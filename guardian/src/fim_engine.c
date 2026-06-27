
/* fim_engine.c — Layer 3: File Integrity Monitor (custom, replaces AIDE).
 *
 * SQLite3 DB stores: path, sha256, mtime, size, mode, uid, gid.
 * Baseline built at build time (or first run). Periodic scan compares live
 * files to baseline; on mismatch, emits event + restores from baseline copy.
 *
 * Uses the bundled SHA-256 impl (from forensic_log.c via g_sha256). No
 * external crypto dep needed.
 */
#include "guardian.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/inotify.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

struct __attribute__((packed)) g_fim_metadata {
    char sha256[65];
    int64_t mtime;
    int64_t size;
    int mode;
    int uid;
    int gid;
};

struct g_fim_engine {
    sqlite3 *db;
    int inotify_fd;
    uint8_t key[32];
    bool encrypt_enabled;
    /* Phase 1.1: map inotify watch descriptor -> watched directory path.
     * inotify_event.name is the basename only; we need the full path.
     * Cap at 64 watched directories (sufficient for /etc, /bin, /usr/bin, etc.). */
    int   wd_used[64];
    char  wd_dirs[64][G_PATH_MAX];
};

static int hash_file(const char *path, uint8_t out[32]) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -errno;
    FILE *f = fdopen(fd, "rb");
    if (!f) { close(fd); return -errno; }
    /* use the streaming SHA-256 from forensic_log.c */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    uint8_t buf[65536]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        EVP_DigestUpdate(ctx, buf, n);
    }
    unsigned int L = 32;
    EVP_DigestFinal_ex(ctx, out, &L);
    EVP_MD_CTX_free(ctx);
    fclose(f);
    return 0;
}

static void hash_to_hex(const uint8_t in[32], char out[65]) {
    static const char *hex = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { out[i*2]=hex[in[i]>>4]; out[i*2+1]=hex[in[i]&0xf]; }
    out[64] = 0;
}

g_fim_engine_t *g_fim_init(const char *db_path, const uint8_t key[32], bool encrypt_enabled) {
    g_fim_engine_t *fe = calloc(1, sizeof(*fe));
    if (!fe) return NULL;
    fe->encrypt_enabled = encrypt_enabled;
    if (key) memcpy(fe->key, key, 32);

    if (sqlite3_open(db_path, &fe->db) != SQLITE_OK) {
        fprintf(stderr, "[fim] open db %s: %s\n", db_path, sqlite3_errmsg(fe->db));
        free(fe); return NULL;
    }

    if (encrypt_enabled) {
        /* Schema check: detect old plaintext columns */
        sqlite3_stmt *stmt;
        int check_rc = sqlite3_prepare_v2(fe->db, "PRAGMA table_info(baseline);", -1, &stmt, NULL);
        if (check_rc == SQLITE_OK) {
            bool has_sha256 = false;
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char *col_name = (const char *)sqlite3_column_text(stmt, 1);
                if (col_name && strcmp(col_name, "sha256") == 0) {
                    has_sha256 = true;
                }
            }
            sqlite3_finalize(stmt);
            if (has_sha256) {
                fprintf(stderr, "[fim] ERROR: FIM schema outdated — run guardian --rebuild-fim\n");
                sqlite3_close(fe->db);
                free(fe);
                return NULL;
            }
        }
        
        sqlite3_exec(fe->db,
            "CREATE TABLE IF NOT EXISTS baseline("
            "  path TEXT PRIMARY KEY, iv BLOB, tag BLOB, ciphertext BLOB);",
            NULL, NULL, NULL);
    } else {
        sqlite3_exec(fe->db,
            "CREATE TABLE IF NOT EXISTS baseline("
            "  path TEXT PRIMARY KEY, sha256 TEXT, mtime INTEGER, size INTEGER, "
            "  mode INTEGER, uid INTEGER, gid INTEGER);",
            NULL, NULL, NULL);
    }

    fe->inotify_fd = inotify_init1(IN_NONBLOCK);
    printf("[fim] initialized (db=%s, encrypted=%d)\n", db_path, encrypt_enabled);
    return fe;
}

void g_fim_free(g_fim_engine_t *fe) {
    if (!fe) return;
    if (fe->db) sqlite3_close(fe->db);
    if (fe->inotify_fd >= 0) close(fe->inotify_fd);
    free(fe);
}

int g_fim_add_watch(g_fim_engine_t *fe, const char *path) {
    if (!fe || !path) return -EINVAL;
    uint8_t h[32];
    if (hash_file(path, h) != 0) return -errno;
    char hex[65]; hash_to_hex(h, hex);
    struct stat st; if (stat(path, &st) != 0) return -errno;

    int rc_db = -EIO;
    if (fe->encrypt_enabled) {
        struct g_fim_metadata meta;
        g_strlcpy(meta.sha256, hex, sizeof(meta.sha256));
        meta.mtime = st.st_mtime;
        meta.size = st.st_size;
        meta.mode = st.st_mode;
        meta.uid = st.st_uid;
        meta.gid = st.st_gid;

        uint8_t iv[12];
        /* L5 fix: NEVER fall back to rand() — predictable IVs break GCM.
         * If the system has no entropy, refuse to encrypt. */
        if (RAND_bytes(iv, sizeof(iv)) != 1) {
            return -EIO;
        }

        uint8_t tag[16];
        size_t cipher_len = sizeof(meta);
        uint8_t *ciphertext = malloc(cipher_len);
        if (!ciphertext) return -ENOMEM;

        int rc_enc = g_aes_gcm_encrypt(fe->key, iv, sizeof(iv), (const uint8_t *)&meta, cipher_len, (const uint8_t *)path, strlen(path), ciphertext, tag);
        if (rc_enc < 0) {
            free(ciphertext);
            return rc_enc;
        }

        sqlite3_stmt *s;
        sqlite3_prepare_v2(fe->db,
            "INSERT OR REPLACE INTO baseline(path,iv,tag,ciphertext) VALUES(?,?,?,?)", -1, &s, NULL);
        sqlite3_bind_text(s, 1, path, -1, SQLITE_STATIC);
        sqlite3_bind_blob(s, 2, iv, sizeof(iv), SQLITE_STATIC);
        sqlite3_bind_blob(s, 3, tag, sizeof(tag), SQLITE_STATIC);
        sqlite3_bind_blob(s, 4, ciphertext, cipher_len, SQLITE_STATIC);
        int step_rc = sqlite3_step(s);
        sqlite3_finalize(s);
        free(ciphertext);
        if (step_rc == SQLITE_DONE) rc_db = 0;
    } else {
        sqlite3_stmt *s;
        sqlite3_prepare_v2(fe->db,
            "INSERT OR REPLACE INTO baseline(path,sha256,mtime,size,mode,uid,gid) "
            "VALUES(?,?,?,?,?,?,?)", -1, &s, NULL);
        sqlite3_bind_text(s, 1, path, -1, SQLITE_STATIC);
        sqlite3_bind_text(s, 2, hex, -1, SQLITE_STATIC);
        sqlite3_bind_int64(s, 3, st.st_mtime);
        sqlite3_bind_int64(s, 4, st.st_size);
        sqlite3_bind_int(s, 5, st.st_mode);
        sqlite3_bind_int(s, 6, st.st_uid);
        sqlite3_bind_int(s, 7, st.st_gid);
        int step_rc = sqlite3_step(s);
        sqlite3_finalize(s);
        if (step_rc == SQLITE_DONE) rc_db = 0;
    }

    /* also add inotify watch if possible */
    if (fe->inotify_fd >= 0) {
        int wd = inotify_add_watch(fe->inotify_fd, path, IN_MODIFY|IN_DELETE|IN_MOVE);
        /* Phase 1.1: store wd -> directory path so inotify events can be
         * attributed to the correct full path. When watching a file (not a
         * dir), store the file's own path so ie->len==0 events map back. */
        if (wd >= 0 && wd < 64) {
            fe->wd_used[wd] = 1;
            g_strlcpy(fe->wd_dirs[wd], path, sizeof(fe->wd_dirs[wd]));
        }
    }
    return rc_db;
}

int g_fim_build_baseline(g_fim_engine_t *fe, const char *paths_file) {
    if (!fe || !paths_file) return -EINVAL;
    FILE *f = fopen(paths_file, "r");
    if (!f) return -errno;
    char line[G_PATH_MAX];
    int n = 0;
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n'); if (nl) *nl = 0;
        if (!line[0] || line[0] == '#') continue;
        if (g_fim_add_watch(fe, line) == 0) n++;
    }
    fclose(f);
    printf("[fim] baseline built: %d paths\n", n);
    return n;
}

int g_fim_check_path(g_fim_engine_t *fe, const char *path, g_event_t *out) {
    if (!fe || !path || !out) return -EINVAL;
    memset(out, 0, sizeof(*out));
    g_strlcpy(out->source, "fim", sizeof(out->source));
    g_strlcpy(out->path, path, sizeof(out->path));
    out->ts_ns = (uint64_t)time(NULL) * 1000000000ULL;
    out->seq = g_bus_next_seq();

    char baseline[65] = {0};

    if (fe->encrypt_enabled) {
        sqlite3_stmt *s;
        sqlite3_prepare_v2(fe->db, "SELECT iv, tag, ciphertext FROM baseline WHERE path=?", -1, &s, NULL);
        sqlite3_bind_text(s, 1, path, -1, SQLITE_STATIC);
        if (sqlite3_step(s) != SQLITE_ROW) {
            sqlite3_finalize(s);
            return -ENOENT;
        }
        int iv_len = sqlite3_column_bytes(s, 0);
        int tag_len = sqlite3_column_bytes(s, 1);
        int cipher_len = sqlite3_column_bytes(s, 2);
        const uint8_t *iv = sqlite3_column_blob(s, 0);
        const uint8_t *tag = sqlite3_column_blob(s, 1);
        const uint8_t *ciphertext = sqlite3_column_blob(s, 2);

        struct g_fim_metadata meta;
        if (cipher_len != sizeof(meta)) {
            sqlite3_finalize(s);
            goto tampered;
        }

        int rc_dec = g_aes_gcm_decrypt(fe->key, iv, iv_len, ciphertext, cipher_len, (const uint8_t *)path, strlen(path), tag, (uint8_t *)&meta);
        sqlite3_finalize(s);
        if (rc_dec < 0) {
            goto tampered;
        }
        g_strlcpy(baseline, meta.sha256, sizeof(baseline));
    } else {
        sqlite3_stmt *s;
        sqlite3_prepare_v2(fe->db, "SELECT sha256 FROM baseline WHERE path=?", -1, &s, NULL);
        sqlite3_bind_text(s, 1, path, -1, SQLITE_STATIC);
        if (sqlite3_step(s) != SQLITE_ROW) {
            sqlite3_finalize(s);
            return -ENOENT;  /* not watched */
        }
        g_strlcpy(baseline, (const char*)sqlite3_column_text(s, 0), sizeof(baseline));
        sqlite3_finalize(s);
    }

    uint8_t h[32];
    if (hash_file(path, h) != 0) {
        out->verdict = G_VERDICT_UNKNOWN;
        g_strlcpy(out->rule_id, "FIM_FILE_MISSING", sizeof(out->rule_id));
        out->severity = G_SEV_HIGH;
        g_bus_publish(out);
        return 1;
    }
    char now[65]; hash_to_hex(h, now);
    if (strcmp(baseline, now) != 0) {
        out->verdict = G_VERDICT_SUSPICIOUS;
        out->severity = G_SEV_HIGH;
        out->action_taken = G_ACT_LOG;  /* policy engine upgrades critical paths */
        snprintf(out->detail, sizeof(out->detail),
                 "INTEGRITY VIOLATION: %s changed (was %.12s... now %.12s...)",
                 path, baseline, now);
        g_strlcpy(out->rule_id, "FIM_INTEGRITY_DELTA", sizeof(out->rule_id));
        g_bus_publish(out);
        return 1;
    }
    out->verdict = G_VERDICT_CLEAN;
    return 0;

tampered:
    out->verdict = G_VERDICT_MALICIOUS;
    out->severity = G_SEV_CRITICAL;
    g_strlcpy(out->rule_id, "FIM_DATABASE_TAMPERED", sizeof(out->rule_id));
    snprintf(out->detail, sizeof(out->detail),
             "CRITICAL: FIM database tampered for path %s (GCM auth failed)", path);
    g_bus_publish(out);
    return 1;
}

int g_fim_scan_all(g_fim_engine_t *fe, int (*cb)(const g_event_t*, void*), void *ud) {
    if (!fe) return -EINVAL;
    sqlite3_stmt *s;
    sqlite3_prepare_v2(fe->db, "SELECT path FROM baseline", -1, &s, NULL);
    int n_violations = 0;
    while (sqlite3_step(s) == SQLITE_ROW) {
        const char *path = (const char*)sqlite3_column_text(s, 0);
        g_event_t ev;
        if (g_fim_check_path(fe, path, &ev) > 0) {
            n_violations++;
            if (cb) cb(&ev, ud);
        }
    }
    sqlite3_finalize(s);
    return n_violations;
}

int g_fim_restore(g_fim_engine_t *fe, const char *path) {
    /* BUG 8 fix: delegate to g_action_restore_file (Phase 1.3) which checks
     * the baseline directory first, then quarantine. Old code returned -ENOSYS
     * (stub) while action_engine.c had the real implementation — two divergent
     * restore paths. Now there's one authority. */
    (void)fe;
    return g_action_restore_file(path);
}

int g_fim_watch_inotify(g_fim_engine_t *fe, int timeout_ms,
                        int (*cb)(const g_event_t*, void*), void *ud) {
    if (!fe || fe->inotify_fd < 0) return -EINVAL;
    fd_set fds; FD_ZERO(&fds); FD_SET(fe->inotify_fd, &fds);
    struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    int rc = select(fe->inotify_fd + 1, &fds, NULL, NULL, &tv);
    if (rc <= 0) return 0;
    char buf[8192] __attribute__((aligned(8)));
    ssize_t n = read(fe->inotify_fd, buf, sizeof(buf));
    if (n <= 0) return 0;
    int count = 0;
    for (char *p = buf; p < buf + n; ) {
        struct inotify_event *ie = (struct inotify_event*)p;
        /* Bug 10 fix: check for inotify queue overflow */
        if (ie->wd == -1 && (ie->mask & IN_Q_OVERFLOW)) {
            printf("[fim] inotify queue overflow — triggering full scan\n");
            g_fim_scan_all(fe, cb, ud);
            p += sizeof(struct inotify_event) + ie->len;
            continue;
        }
        if (ie->len > 0) {
            g_event_t ev = {0};
            /* Phase 1.1 fix: ie->name is the basename only. Reconstruct the
             * full path using the wd->dir map populated in g_fim_add_watch.
             * Old code produced "/passwd" instead of "/etc/passwd". */
            const char *dir = (ie->wd >= 0 && ie->wd < 64 && fe->wd_used[ie->wd])
                              ? fe->wd_dirs[ie->wd] : "";
            if (dir[0]) {
                snprintf(ev.path, sizeof(ev.path), "%s/%s", dir, ie->name);
            } else {
                snprintf(ev.path, sizeof(ev.path), "/%s", ie->name);
            }
            g_strlcpy(ev.source, "fim", sizeof(ev.source));
            g_strlcpy(ev.rule_id, "FIM_INOTIFY_EVENT", sizeof(ev.rule_id));
            ev.severity = G_SEV_LOW;
            ev.action_taken = G_ACT_LOG;
            if (cb) cb(&ev, ud);
            count++;
        }
        p += sizeof(struct inotify_event) + ie->len;
    }
    return count;
}

int g_fim_test_has_ciphertext(g_fim_engine_t *fe, const char *path) {
    if (!fe || !fe->db || !path) return 0;
    sqlite3_stmt *stmt;
    int found = 0;
    if (sqlite3_prepare_v2(fe->db, "SELECT ciphertext FROM baseline WHERE path=?;", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            if (sqlite3_column_bytes(stmt, 0) > 0) {
                found = 1;
            }
        }
        sqlite3_finalize(stmt);
    }
    return found;
}

int g_fim_test_tamper_tag(g_fim_engine_t *fe, const char *path) {
    if (!fe || !fe->db || !path) return -EINVAL;
    sqlite3_stmt *stmt;
    int rc = -1;
    if (sqlite3_prepare_v2(fe->db, "UPDATE baseline SET tag = x'00000000000000000000000000000000' WHERE path=?;", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, path, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_DONE) {
            rc = 0;
        }
        sqlite3_finalize(stmt);
    }
    return rc;
}

