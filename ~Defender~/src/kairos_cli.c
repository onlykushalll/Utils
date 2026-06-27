/* kairos_cli.c — the `kairos` shell command (investigate|explain|status).
 *
 * This is the user-facing entry point. It:
 *   1. Loads instruction.md as the system prompt
 *   2. Calls kairos_loader to spin up Qwythos-9B (or Qwen2.5-1.5B fallback)
 *   3. Calls kairos_agent to run the agent loop (act → verify → confirm)
 *   4. Prints the structured output
 *   5. Spins the model down (RAM returns to baseline)
 *
 * Usage:
 *   kairos investigate <event_id>
 *   kairos explain <question>
 *   kairos status
 */
#include "guardian.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define KAIROS_INSTRUCTION_PATH "/etc/wlt/guardian/instruction.md"
#define KAIROS_FALLBACK_INSTRUCTION "./kairos/instruction.md"
#define KAIROS_PORT 8080  /* llama.cpp llama-server port */
#define QWYTHOS_MODEL_PATH "/usr/local/share/models/qwythos-9b.gguf"
#define QWEN_FALLBACK_PATH "/usr/local/share/models/qwen2.5-1.5b.gguf"

static int load_instruction(char *out, size_t sz) {
    const char *paths[] = {KAIROS_INSTRUCTION_PATH, KAIROS_FALLBACK_INSTRUCTION, NULL};
    for (int i = 0; paths[i]; i++) {
        FILE *f = fopen(paths[i], "r");
        if (f) {
            size_t n = fread(out, 1, sz-1, f);
            out[n] = 0;
            fclose(f);
            return 0;
        }
    }
    return -ENOENT;
}

/* detect RAM and pick the model */
static const char *pick_model(void) {
    long ram_mb = 0;
    FILE *f = fopen("/proc/meminfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (!strncmp(line, "MemTotal:", 9)) {
                sscanf(line+9, "%ld", &ram_mb);
                ram_mb /= 1024;
                break;
            }
        }
        fclose(f);
    }
    if (ram_mb < 4096) return NULL;  /* no consultant on <4GB */
    if (ram_mb < 8192) return QWEN_FALLBACK_PATH;
    return QWYTHOS_MODEL_PATH;
}

/* kairos_loader: spin up llama-server on port 8080 with the model */
static pid_t g_llama_pid = 0;

static int loader_start(const char *model_path) {
    if (access(model_path, R_OK) != 0) {
        fprintf(stderr, "[kairos] model not found at %s\n", model_path);
        return -ENOENT;
    }
    pid_t pid = fork();
    if (pid < 0) return -errno;
    if (pid == 0) {
        /* child: exec llama-server */
        char port[16]; snprintf(port, sizeof(port), "%d", KAIROS_PORT);
        execlp("llama-server", "llama-server",
               "-m", model_path,
               "--port", port,
               "-c", "8192",       /* context size (1M for Qwythos, but start small) */
               "-t", "4",          /* threads */
               "-ngl", "0",        /* GPU layers (0 = CPU only — WLTIOS targets have no GPU) */
               "--no-webui",
               NULL);
        perror("exec llama-server");
        _exit(127);
    }
    g_llama_pid = pid;
    printf("[kairos] llama-server started (pid=%d, model=%s, port=%d)\n",
           pid, model_path, KAIROS_PORT);
    /* wait for server to be ready (poll the port) */
    for (int i = 0; i < 30; i++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s >= 0) {
            struct sockaddr_in addr = {0};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(KAIROS_PORT);
            addr.sin_addr.s_addr = htonl(0x7f000001);
            if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                close(s);
                printf("[kairos] model ready (waited %d retries)\n", i);
                return 0;
            }
            close(s);
        }
        usleep(500000);
    }
    fprintf(stderr, "[kairos] llama-server failed to become ready\n");
    return -ETIMEDOUT;
}

static void loader_stop(void) {
    if (g_llama_pid > 0) {
        kill(g_llama_pid, SIGTERM);
        int status; waitpid(g_llama_pid, &status, 0);
        printf("[kairos] llama-server stopped (ram freed)\n");
        g_llama_pid = 0;
    }
}

/* call the model's chat completion endpoint with a system+user message.
 * Returns the assistant's response text. */
static int call_model(const char *system_prompt, const char *user_msg,
                      char *out, size_t out_sz) {
    /* build JSON request to llama-server /v1/chat/completions */
    char sys_esc[16384], user_esc[8192];
    /* simple JSON escape */
    size_t si = 0, ui = 0;
    for (const char *p = system_prompt; *p && si < sizeof(sys_esc)-8; p++) {
        if (*p=='"') { sys_esc[si++]='\\'; sys_esc[si++]='"'; }
        else if (*p=='\\') { sys_esc[si++]='\\'; sys_esc[si++]='\\'; }
        else if (*p=='\n') { sys_esc[si++]='\\'; sys_esc[si++]='n'; }
        else sys_esc[si++] = *p;
    }
    sys_esc[si] = 0;
    for (const char *p = user_msg; *p && ui < sizeof(user_esc)-8; p++) {
        if (*p=='"') { user_esc[ui++]='\\'; user_esc[ui++]='"'; }
        else if (*p=='\\') { user_esc[ui++]='\\'; user_esc[ui++]='\\'; }
        else if (*p=='\n') { user_esc[ui++]='\\'; user_esc[ui++]='n'; }
        else user_esc[ui++] = *p;
    }
    user_esc[ui] = 0;

    char body[32768];
    int n = snprintf(body, sizeof(body),
        "{\"messages\":[{\"role\":\"system\",\"content\":\"%s\"},"
        "{\"role\":\"user\",\"content\":\"%s\"}],\"temperature\":0.3,\"max_tokens\":2000}",
        sys_esc, user_esc);
    if (n < 0 || n >= (int)sizeof(body)) return -ENAMETOOLONG;

    /* POST to localhost:8080/v1/chat/completions via curl */
    char cmd[34816];
    snprintf(cmd, sizeof(cmd),
        "curl -s -X POST http://127.0.0.1:%d/v1/chat/completions "
        "-H 'Content-Type: application/json' -d '%s' 2>/dev/null", KAIROS_PORT, body);
    FILE *p = popen(cmd, "r");
    if (!p) return -errno;
    char resp[32768] = {0}; size_t off = 0;
    while (off < sizeof(resp)-1) {
        size_t got = fread(resp+off, 1, sizeof(resp)-1-off, p);
        if (got == 0) break;
        off += got;
    }
    pclose(p);

    /* extract content from JSON response: ...{"content":"..."}... */
    char *c = strstr(resp, "\"content\"");
    if (c) {
        c = strchr(c, ':'); if (c) {
            c++; while (*c==' '||*c=='"') c++;
            size_t oi = 0;
            while (*c && *c != '"' && oi < out_sz-1) {
                if (*c == '\\' && c[1]) {
                    if (c[1]=='n') out[oi++]='\n';
                    else if (c[1]=='"') out[oi++]='"';
                    else if (c[1]=='\\') out[oi++]='\\';
                    else out[oi++]=c[1];
                    c += 2;
                } else {
                    out[oi++] = *c++;
                }
            }
            out[oi] = 0;
            return 0;
        }
    }
    g_strlcpy(out, "(no response from model)", out_sz);
    return -EIO;
}

/* ---- agent loop (act → verify → confirm → self-correct) ---- */
static int run_agent(const char *system_prompt, const char *user_msg,
                     char *out, size_t out_sz) {
    /* v1: single-shot call. Full agent loop (multi-turn with tool calls)
     * would parse the model's requested tool calls, execute them via the MCP
     * socket, feed results back, and iterate. That's kairos_agent.c's job. */
    return call_model(system_prompt, user_msg, out, out_sz);
}

/* ---- subcommands ---- */

static int cmd_investigate(const char *event_id) {
    char instruction[16384];
    if (load_instruction(instruction, sizeof(instruction)) != 0) {
        fprintf(stderr, "[kairos] could not load instruction.md\n");
        return 1;
    }
    const char *model = pick_model();
    if (!model) {
        fprintf(stderr, "[kairos] insufficient RAM for consultant (need >= 4GB)\n");
        return 1;
    }
    if (loader_start(model) != 0) return 1;

    char user_msg[512];
    snprintf(user_msg, sizeof(user_msg),
        "Investigate Guardian event %s. Start by calling guardian_forensics(%s), "
        "then guardian_history, then inspect the offending process/file. "
        "Report findings with cited evidence, hypotheses with confidence, "
        "and recommended actions. Do not execute any irreversible action without my confirmation.",
        event_id, event_id);

    char response[8192];
    int rc = run_agent(instruction, user_msg, response, sizeof(response));
    loader_stop();
    if (rc != 0) {
        fprintf(stderr, "[kairos] agent call failed: %d\n", rc);
        return 1;
    }
    printf("%s\n", response);
    return 0;
}

static int cmd_explain(const char *question) {
    char instruction[16384];
    if (load_instruction(instruction, sizeof(instruction)) != 0) {
        fprintf(stderr, "[kairos] could not load instruction.md\n");
        return 1;
    }
    const char *model = pick_model();
    if (!model) {
        fprintf(stderr, "[kairos] insufficient RAM for consultant\n");
        return 1;
    }
    if (loader_start(model) != 0) return 1;

    char user_msg[2048];
    snprintf(user_msg, sizeof(user_msg),
        "Explain: %s\n\nUse guardian_status and relevant inspect tools to gather evidence. "
        "Start with a 2-3 sentence plain-language summary, then structured findings.",
        question);

    char response[8192];
    int rc = run_agent(instruction, user_msg, response, sizeof(response));
    loader_stop();
    if (rc != 0) { fprintf(stderr, "[kairos] failed: %d\n", rc); return 1; }
    printf("%s\n", response);
    return 0;
}

static int cmd_status(void) {
    /* no model needed — just query the guardian API socket */
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 1; }
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    g_strlcpy(addr.sun_path, G_SOCKET_PATH, sizeof(addr.sun_path));
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "[kairos] guardian not running (connect %s: %s)\n",
                G_SOCKET_PATH, strerror(errno));
        close(s);
        return 1;
    }
    char buf[4096] = {0};
    ssize_t n = read(s, buf, sizeof(buf)-1);
    close(s);
    if (n > 0) {
        printf("Guardian status: %s\n", buf);
        return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: kairos <investigate|explain|status> [args]\n");
        fprintf(stderr, "  kairos investigate <event_id>\n");
        fprintf(stderr, "  kairos explain <question>\n");
        fprintf(stderr, "  kairos status\n");
        return 1;
    }
    if (!strcmp(argv[1], "investigate") && argc > 2) return cmd_investigate(argv[2]);
    if (!strcmp(argv[1], "explain") && argc > 2)      return cmd_explain(argv[2]);
    if (!strcmp(argv[1], "status"))                    return cmd_status();
    fprintf(stderr, "unknown command: %s\n", argv[1]);
    return 1;
}

/* Stub for event bus publish (needed by forensic_log.o when linked into utilities) */
int g_bus_publish(const g_event_t *ev) {
    (void)ev;
    return 0;
}
