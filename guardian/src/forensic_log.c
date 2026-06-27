/* forensic_log.c — tamper-evident, encrypted append-only forensic log.
 *
 * Each entry is JSON. Each entry's hash chains to the previous entry:
 *   entry_hash(n) = SHA-256(seq(n) || ts(n) || prev_hash(n) || event_json(n))
 * Modifying any past entry breaks the chain at that point.
 *
 * Encryption: AES-256-GCM. The log file is a sequence of encrypted records:
 *   [iv_len:1][iv:12][cipher_len:4][cipher:N][tag:16]
 * The plaintext inside is the JSON+chain-hash. Key is per-boot (derived from
 * /dev/urandom at daemon start, stored in kernel keyring if available, lost
 * on reboot — acceptable for amnesic mode).
 *
 * Verification: g_log_verify() walks the chain and reports the first break.
 */
#include "guardian.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define G_LOG_IV_LEN   12
#define G_LOG_TAG_LEN  16
#define G_LOG_MAX_REC  (sizeof(g_event_t) + 256)

/* C4 fix: escape quotes and backslashes for safe JSON string embedding */
static void escape_json_field(const char *src, char *dst, size_t dst_sz) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 2 < dst_sz; i++) {
        if (src[i] == '"' || src[i] == '\\') {
            dst[j++] = '\\';
        }
        dst[j++] = src[i];
    }
    dst[j] = '\0';
}

struct g_log {
    FILE    *fp;
    uint8_t  key[32];
    uint8_t  prev_hash[32];   /* rolling chain */
    uint8_t  genesis_hash[32]; /* Bug 4 fix: stored at log creation for verify */
    uint64_t seq;
    pthread_mutex_t lock;
};

/* ---- global singleton ---- */
static g_log_t *g_log_global = NULL;

int g_log_init_global(const char *path, const uint8_t key[32]) {
    if (g_log_global) g_log_close_global();
    g_log_global = g_log_open(path, key);
    return g_log_global ? 0 : -EIO;
}

int g_log_append_global(const g_event_t *ev) {
    return g_log_global ? g_log_append(g_log_global, ev) : -ENODEV;
}

void g_log_close_global(void) {
    if (g_log_global) { g_log_close(g_log_global); g_log_global = NULL; }
}

/* ---- AES-256-GCM (openssl) ---- */
int g_aes_gcm_encrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                      const uint8_t *plain, size_t plain_len,
                      const uint8_t *aad, size_t aad_len,
                      uint8_t *cipher, uint8_t tag[16]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -ENOMEM;
    int rc = -EIO, len;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1) goto out;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto out;
    if (aad_len && EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) goto out;
    if (EVP_EncryptUpdate(ctx, cipher, &len, plain, plain_len) != 1) goto out;
    int total = len;
    if (EVP_EncryptFinal_ex(ctx, cipher + len, &len) != 1) goto out;
    total += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) goto out;
    rc = total;
out:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

int g_aes_gcm_decrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                      const uint8_t *cipher, size_t cipher_len,
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t tag[16], uint8_t *plain) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -ENOMEM;
    int rc = -EIO, len;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1) goto out;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto out;
    if (aad_len && EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) goto out;
    if (EVP_DecryptUpdate(ctx, plain, &len, cipher, cipher_len) != 1) goto out;
    int total = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) goto out;
    if (EVP_DecryptFinal_ex(ctx, plain + len, &len) != 1) goto out;  /* auth fail */
    total += len;
    rc = total;
out:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

/* ---- SHA-256 (openssl, but with internal fallback interface) ---- */
void g_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    /* C5 fix: NULL check — EVP_MD_CTX_new can fail under OOM */
    if (!ctx) { memset(out, 0, 32); return; }
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    unsigned int L = 32;
    EVP_DigestFinal_ex(ctx, out, &L);
    EVP_MD_CTX_free(ctx);
}

void g_sha256_hex(const uint8_t *data, size_t len, char out[65]) {
    uint8_t h[32];
    g_sha256(data, len, h);
    static const char *hex = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { out[i*2]=hex[h[i]>>4]; out[i*2+1]=hex[h[i]&0xf]; }
    out[64] = 0;
}

/* streaming ctx (openssl EVP wrapped) */
void g_sha256_init_ctx(void *ctx) {
    EVP_MD_CTX **pp = (EVP_MD_CTX**)ctx;
    if (!*pp) *pp = EVP_MD_CTX_new();
    EVP_DigestInit_ex(*pp, EVP_sha256(), NULL);
}
void g_sha256_update_ctx(void *ctx, const uint8_t *data, size_t len) {
    EVP_MD_CTX **pp = (EVP_MD_CTX**)ctx;
    EVP_DigestUpdate(*pp, data, len);
}
void g_sha256_final_ctx(void *ctx, uint8_t out[32]) {
    EVP_MD_CTX **pp = (EVP_MD_CTX**)ctx;
    unsigned int L = 32;
    EVP_DigestFinal_ex(*pp, out, &L);
}

size_t g_strlcpy(char *dst, const char *src, size_t sz) {
    size_t L = strlen(src);
    if (sz) { size_t c = (L < sz) ? L : sz - 1; memcpy(dst, src, c); dst[c] = 0; }
    return L;
}

/* ---- log open/append/close ---- */

g_log_t *g_log_open(const char *path, const uint8_t key[32]) {
    g_log_t *log = calloc(1, sizeof(*log));
    if (!log) return NULL;
    log->fp = fopen(path, "ab+");
    if (!log->fp) { free(log); return NULL; }
    setvbuf(log->fp, NULL, _IONBF, 0);
    memcpy(log->key, key, 32);
    pthread_mutex_init(&log->lock, NULL);
    /* seed prev_hash from /dev/urandom so each boot starts a fresh chain */
    if (RAND_bytes(log->prev_hash, 32) != 1) {
        memset(log->prev_hash, 0x42, 32);
    }
    /* Bug 4 fix: store genesis hash = the initial prev_hash, so verify can
     * walk forward from the true beginning. */
    memcpy(log->genesis_hash, log->prev_hash, 32);
    log->seq = 0;
    return log;
}

/* serialize event + chain to JSON, encrypt, write */
int g_log_append(g_log_t *log, const g_event_t *ev) {
    if (!log || !ev) return -EINVAL;
    pthread_mutex_lock(&log->lock);

    /* Vuln 10: check log quota limit (10MB) */
    struct stat st;
    if (fstat(fileno(log->fp), &st) == 0 && st.st_size >= 10 * 1024 * 1024) {
        static bool g_quota_warning_emitted = false;
        time_t now = time(NULL);
        if (!g_quota_warning_emitted) {
            g_quota_warning_emitted = true;
            pthread_mutex_unlock(&log->lock);

            /* Publish alert event to notify user / compositor */
            g_event_t alert = {0};
            struct timespec ts;
            clock_gettime(CLOCK_BOOTTIME, &ts);
            alert.ts_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
            alert.seq = ev->seq;
            alert.pid = getpid();
            g_strlcpy(alert.comm, "guardian", sizeof(alert.comm));
            g_strlcpy(alert.source, "policy", sizeof(alert.source));
            g_strlcpy(alert.rule_id, "LOG_QUOTA_EXCEEDED", sizeof(alert.rule_id));
            alert.severity = G_SEV_CRITICAL;
            alert.verdict = G_VERDICT_SUSPICIOUS;
            alert.action_taken = G_ACT_LOG;
            g_strlcpy(alert.detail, "Forensic log has exceeded 10MB quota. Operating in overflow plaintext mode.", sizeof(alert.detail));
            g_bus_publish(&alert);

            pthread_mutex_lock(&log->lock);
        }

        /* Spillover: write to plaintext JSON overflow file */
        const char *overflow_path = "/var/log/guardian.overflow";
        FILE *of = fopen(overflow_path, "a");
        if (!of) {
            of = fopen("./guardian.overflow", "a");
        }
        if (of) {
            char ts_overflow[32];
            strftime(ts_overflow, sizeof(ts_overflow), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
            /* C4 fix: escape user-controlled strings before JSON embedding */
            char esc_comm[128], esc_path[G_PATH_MAX * 2], esc_detail[512];
            escape_json_field(ev->comm, esc_comm, sizeof(esc_comm));
            escape_json_field(ev->path, esc_path, sizeof(esc_path));
            escape_json_field(ev->detail, esc_detail, sizeof(esc_detail));
            fprintf(of, "{\"seq\":%llu,\"ts\":\"%s\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,"
                        "\"comm\":\"%s\",\"src\":\"%s\",\"rule\":\"%s\",\"sev\":%d,"
                        "\"verdict\":%d,\"action\":%d,\"path\":\"%s\",\"detail\":\"%s\"}\n",
                    (unsigned long long)log->seq, ts_overflow, ev->pid, ev->ppid, ev->uid,
                    esc_comm, ev->source, ev->rule_id, ev->severity, ev->verdict,
                    ev->action_taken, esc_path, esc_detail);
            fclose(of);
        }
        pthread_mutex_unlock(&log->lock);
        return 0;
    }

    log->seq++;
    char ts[32];
    time_t now = time(NULL);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    /* compute prev_hash for this entry = current rolling hash */
    char prev_hex[65];
    g_sha256_hex(log->prev_hash, 32, prev_hex);

    /* build JSON (the plaintext) */
    char json[G_LOG_MAX_REC];
    int jlen = snprintf(json, sizeof(json),
        "{\"seq\":%llu,\"ts\":\"%s\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,"
        "\"comm\":\"%s\",\"src\":\"%s\",\"rule\":\"%s\",\"sev\":%d,"
        "\"verdict\":%d,\"action\":%d,\"path\":\"%s\",\"detail\":\"%s\","
        "\"prev_hash\":\"%s\"}",
        (unsigned long long)log->seq, ts, ev->pid, ev->ppid, ev->uid,
        ev->comm, ev->source, ev->rule_id, ev->severity, ev->verdict,
        ev->action_taken, ev->path, ev->detail, prev_hex);

    if (jlen < 0 || jlen >= (int)sizeof(json)) {
        pthread_mutex_unlock(&log->lock);
        return -ENAMETOOLONG;
    }

    /* entry_hash = SHA-256(json) — this becomes the next prev_hash */
    uint8_t entry_hash[32];
    g_sha256((const uint8_t*)json, jlen, entry_hash);

    /* encrypt: AES-256-GCM. AAD = seq (binds seq to ciphertext). */
    uint8_t iv[G_LOG_IV_LEN];
    if (RAND_bytes(iv, G_LOG_IV_LEN) != 1) {
        pthread_mutex_unlock(&log->lock);
        return -EIO;
    }
    uint8_t cipher[G_LOG_MAX_REC];
    uint8_t tag[G_LOG_TAG_LEN];
    uint8_t aad[8];
    uint64_t seq_be = htobe64(log->seq);
    memcpy(aad, &seq_be, 8);

    int clen = g_aes_gcm_encrypt(log->key, iv, G_LOG_IV_LEN,
                                  (const uint8_t*)json, jlen,
                                  aad, 8, cipher, tag);
    if (clen < 0) {
        pthread_mutex_unlock(&log->lock);
        return clen;
    }

    /* write record: [iv:12][clen:4][cipher:N][tag:16] */
    unsigned char hdr[1 + 4];
    hdr[0] = (unsigned char)G_LOG_IV_LEN;
    uint32_t clen_n = htonl((uint32_t)clen);
    memcpy(hdr+1, &clen_n, 4);

    /* record format: [ivlen:1][iv:12][clen:4 BE][cipher:N][tag:16] */
    /* M8 fix: check every fwrite return value — partial writes corrupt the log */
    if (fwrite(hdr, 1, 5, log->fp) != 5 ||
        fwrite(iv, 1, G_LOG_IV_LEN, log->fp) != G_LOG_IV_LEN ||
        fwrite(cipher, 1, clen, log->fp) != (size_t)clen ||
        fwrite(tag, 1, G_LOG_TAG_LEN, log->fp) != G_LOG_TAG_LEN) {
        pthread_mutex_unlock(&log->lock);
        return -EIO;
    }
    fflush(log->fp);

    /* advance the chain */
    memcpy(log->prev_hash, entry_hash, 32);

    pthread_mutex_unlock(&log->lock);
    return 0;
}

int g_log_verify(g_log_t *log, char *out_break_at, size_t out_sz) {
    if (!log) return -EINVAL;
    /* Bug 3+4 fix: proper AAD (seq in big-endian, matching append) and
     * actual chain hash comparison against the genesis hash. */
    fseek(log->fp, 0, SEEK_SET);

    /* start from genesis hash */
    uint8_t expected_prev[32];
    memcpy(expected_prev, log->genesis_hash, 32);

    int n = 0;
    uint64_t verify_seq = 0;  /* local seq counter for AAD */
    unsigned char hdr[5];
    while (fread(hdr, 1, 5, log->fp) == 5) {
        int ivlen = hdr[0];
        uint32_t clen;
        memcpy(&clen, hdr+1, 4);
        clen = ntohl(clen);
        if (ivlen > 32 || clen > 1<<20) break;
        uint8_t iv[32]; if (fread(iv, 1, ivlen, log->fp) != (size_t)ivlen) break;
        uint8_t *cipher = malloc(clen);
        if (fread(cipher, 1, clen, log->fp) != clen) { free(cipher); break; }
        uint8_t tag[16]; if (fread(tag, 1, 16, log->fp) != 16) { free(cipher); break; }

        verify_seq++;
        /* Bug 3 fix: pass the correct AAD (seq in big-endian, same as append) */
        uint8_t aad[8];
        uint64_t seq_be = htobe64(verify_seq);
        memcpy(aad, &seq_be, 8);

        uint8_t *plain = malloc(clen + 1);
        int plen = g_aes_gcm_decrypt(log->key, iv, ivlen, cipher, clen,
                                     aad, 8, tag, plain);
        free(cipher);
        if (plen < 0) {
            if (out_break_at) snprintf(out_break_at, out_sz,
                "record %d (GCM auth fail — tampered or wrong key)", n);
            free(plain);
            fseek(log->fp, 0, SEEK_END);
            return n;
        }
        plain[plen] = 0;

        /* Bug 4 fix: verify the chain. The plaintext JSON contains a
         * "prev_hash" field (hex). Extract it and compare to expected_prev.
         * This catches tampering that GCM alone wouldn't (e.g. if an attacker
         * has the key, they can forge valid GCM tags but can't maintain the
         * hash chain without knowing the genesis hash). */
        char expected_hex[65];
        static const char *hex = "0123456789abcdef";
        for (int i = 0; i < 32; i++) {
            expected_hex[i*2] = hex[expected_prev[i] >> 4];
            expected_hex[i*2+1] = hex[expected_prev[i] & 0xf];
        }
        expected_hex[64] = 0;

        /* find "prev_hash":" in plaintext */
        char *ph = strstr((char*)plain, "\"prev_hash\":\"");
        if (!ph) {
            if (out_break_at) snprintf(out_break_at, out_sz,
                "record %d (no prev_hash field)", n);
            free(plain);
            fseek(log->fp, 0, SEEK_END);
            return n;
        }
        ph += 13;  /* skip "prev_hash":" */
        if (strncmp(ph, expected_hex, 64) != 0) {
            if (out_break_at) snprintf(out_break_at, out_sz,
                "record %d (chain hash mismatch — tampered entry)", n);
            free(plain);
            fseek(log->fp, 0, SEEK_END);
            return n;
        }

        /* advance: entry_hash(n) = SHA256(plaintext(n)) = expected_prev for n+1 */
        g_sha256(plain, plen, expected_prev);
        free(plain);
        n++;
    }
    fseek(log->fp, 0, SEEK_END);
    return n;  /* number of valid records */
}

void g_log_close(g_log_t *log) {
    if (!log) return;
    if (log->fp) fclose(log->fp);
    pthread_mutex_destroy(&log->lock);
    free(log);
}
