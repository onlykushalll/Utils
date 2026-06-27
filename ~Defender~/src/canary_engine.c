/* canary_engine.c — Phase 2.1: Ransomware canary file engine.
 *
 * Creates bait files in locations ransomware encrypts first (alphabetically
 * early names so mass-encryptors hit them first). Any access or modification
 * = immediate CRITICAL alert + freeze. Zero false positives by construction:
 * no legitimate process touches "!GUARDIAN_CANARY_*" files.
 *
 * The BPF LSM file_open hook (Phase 4.1) will inline-kill openers; until then
 * the userspace verify loop catches deletion/modification within 30s.
 */
#include "guardian.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <openssl/rand.h>

#define G_CANARY_NAME "!GUARDIAN_CANARY_DO_NOT_TOUCH.bin"
#define G_CANARY_SIZE 1024
#define G_MAX_CANARIES 8

struct g_canary {
    char path[G_PATH_MAX];
    uint8_t hash[32];   /* expected SHA-256 of canary contents */
    int present;
};

struct g_canary_engine {
    struct g_canary canaries[G_MAX_CANARIES];
    int n;
};

/* placement dirs — ransomware hits these first */
static const char *g_canary_dirs[] = {
    "/tmp", "/var/tmp", "/etc", "/root", "/home",
    NULL
};

static void canary_hash(const uint8_t *data, size_t len, uint8_t out[32]) {
    g_sha256(data, len, out);
}

g_canary_engine_t *g_canary_init(void) {
    g_canary_engine_t *ce = calloc(1, sizeof(*ce));
    if (!ce) return NULL;

    for (int i = 0; g_canary_dirs[i] && ce->n < G_MAX_CANARIES; i++) {
        const char *dir = g_canary_dirs[i];
        /* skip dirs we can't write to (non-root in dev sandbox) */
        if (access(dir, W_OK) != 0) continue;
        struct g_canary *c = &ce->canaries[ce->n];
        snprintf(c->path, sizeof(c->path), "%s/%s", dir, G_CANARY_NAME);

        /* generate 1KB random content */
        uint8_t buf[G_CANARY_SIZE];
        if (RAND_bytes(buf, sizeof(buf)) != 1) {
            /* fall back to urandom if RAND_bytes unavailable */
            FILE *f = fopen("/dev/urandom", "rb");
            if (!f || fread(buf, 1, sizeof(buf), f) != sizeof(buf)) {
                if (f) fclose(f);
                continue;
            }
            fclose(f);
        }
        canary_hash(buf, sizeof(buf), c->hash);

        /* write atomically: O_CREAT|O_EXCL prevents racing a pre-existing file */
        int fd = open(c->path, O_WRONLY | O_CREAT | O_EXCL, 0400);
        if (fd < 0) {
            /* BUG 2 fix: already exists (re-run) — READ + HASH it so verify
             * works. Old code set present=1 but left c->hash all-zero, so
             * every restart triggered RANSOMWARE_CANARY_ENCRYPTED false positives. */
            struct stat st;
            if (stat(c->path, &st) == 0 && st.st_size == G_CANARY_SIZE) {
                int rfd = open(c->path, O_RDONLY);
                if (rfd >= 0) {
                    uint8_t rbuf[G_CANARY_SIZE];
                    if (read(rfd, rbuf, sizeof(rbuf)) == G_CANARY_SIZE) {
                        canary_hash(rbuf, sizeof(rbuf), c->hash);
                        c->present = 1;
                        ce->n++;
                    }
                    close(rfd);
                }
            }
            continue;
        }
        ssize_t w = write(fd, buf, sizeof(buf));
        close(fd);
        if (w == sizeof(buf)) {
            c->present = 1;
            ce->n++;
            printf("[canary] placed %s\n", c->path);
        } else {
            unlink(c->path);
        }
    }
    printf("[canary] %d canary files placed\n", ce->n);
    return ce;
}

void g_canary_free(g_canary_engine_t *ce) {
    if (!ce) return;
    /* NOTE: we do NOT delete canary files on shutdown — they must persist
     * across daemon restarts so a ransomware attack between runs is detected. */
    free(ce);
}

/* Verify all canaries: check existence + content hash.
 * Returns number of missing/tampered canaries (0 = all intact). */
int g_canary_verify_all(g_canary_engine_t *ce) {
    if (!ce) return 0;
    int n_bad = 0;
    for (int i = 0; i < ce->n; i++) {
        struct g_canary *c = &ce->canaries[i];
        struct stat st;
        if (stat(c->path, &st) != 0) {
            /* canary deleted — ransomware indicator */
            n_bad++;
            g_event_t ev = {0};
            g_strlcpy(ev.source, "canary", sizeof(ev.source));
            g_strlcpy(ev.rule_id, "RANSOMWARE_CANARY_DELETED", sizeof(ev.rule_id));
            g_strlcpy(ev.path, c->path, sizeof(ev.path));
            ev.severity = G_SEV_CRITICAL;
            ev.verdict = G_VERDICT_MALICIOUS;
            ev.action_taken = G_ACT_FREEZE;  /* policy may upgrade to kill switch */
            ev.ts_ns = (uint64_t)time(NULL) * 1000000000ULL;
            ev.seq = g_bus_next_seq();
            snprintf(ev.detail, sizeof(ev.detail),
                     "Canary file %s deleted — likely ransomware mass-delete/encrypt",
                     c->path);
            g_bus_publish(&ev);
            c->present = 0;
            continue;
        }
        /* check size + hash */
        if (st.st_size != G_CANARY_SIZE) {
            n_bad++;
            g_event_t ev = {0};
            g_strlcpy(ev.source, "canary", sizeof(ev.source));
            g_strlcpy(ev.rule_id, "RANSOMWARE_CANARY_MODIFIED", sizeof(ev.rule_id));
            g_strlcpy(ev.path, c->path, sizeof(ev.path));
            ev.severity = G_SEV_CRITICAL;
            ev.verdict = G_VERDICT_MALICIOUS;
            ev.action_taken = G_ACT_FREEZE;
            ev.ts_ns = (uint64_t)time(NULL) * 1000000000ULL;
            ev.seq = g_bus_next_seq();
            snprintf(ev.detail, sizeof(ev.detail),
                     "Canary file %s size changed (%ld != %d) — tampering",
                     c->path, (long)st.st_size, G_CANARY_SIZE);
            g_bus_publish(&ev);
            continue;
        }
        /* full content hash check */
        int fd = open(c->path, O_RDONLY);
        if (fd < 0) continue;
        uint8_t buf[G_CANARY_SIZE];
        ssize_t r = read(fd, buf, sizeof(buf));
        close(fd);
        if (r != G_CANARY_SIZE) continue;
        uint8_t h[32];
        canary_hash(buf, r, h);
        if (memcmp(h, c->hash, 32) != 0) {
            n_bad++;
            g_event_t ev = {0};
            g_strlcpy(ev.source, "canary", sizeof(ev.source));
            g_strlcpy(ev.rule_id, "RANSOMWARE_CANARY_ENCRYPTED", sizeof(ev.rule_id));
            g_strlcpy(ev.path, c->path, sizeof(ev.path));
            ev.severity = G_SEV_CRITICAL;
            ev.verdict = G_VERDICT_MALICIOUS;
            ev.action_taken = G_ACT_KILL_SWITCH;
            ev.ts_ns = (uint64_t)time(NULL) * 1000000000ULL;
            ev.seq = g_bus_next_seq();
            snprintf(ev.detail, sizeof(ev.detail),
                     "Canary file %s content hash mismatch — encryption detected, activating kill switch",
                     c->path);
            g_bus_publish(&ev);
        }
    }
    return n_bad;
}
