# Phase 5.1: TPM Key Sealing for Forensic Log

## Goal
Derive the forensic log AES-256-GCM key from TPM PCR values instead of
/dev/urandom, so the key is bound to the platform's measured boot state.
A different boot state (e.g., attacker boots a modified kernel) produces
a different key, making the log unreadable to an attacker who reseats
the disk.

## Approach

### On a system with TPM (most x86 since ~2015):
1. At image build time, generate a 32-byte log key.
2. Seal it to PCR values using `tpm2_create` (seals to current boot state).
3. At guardian startup, `tpm2_unseal` retrieves the key (only works if
   PCRs match — i.e., same boot state).
4. If unseal fails (modified boot), fall back to a fresh urandom key +
   emit a TPM_UNSEAL_FAILED alert (log is unreadable across this reboot).

### On a system without TPM (QEMU without --tpmdev):
- Fall back to /dev/urandom (current behavior).
- Emit a warning that TPM is unavailable.
- This is the current dev-sandbox behavior.

## Implementation status

The forensic_log.c `g_get_log_key()` function currently uses /dev/urandom.
The TPM path is documented here but NOT yet implemented because:
- QEMU TPM emulation (`--tpmdev passthrough` or swtpm) is not configured
  in the current WLTIOS build.
- tpm2-tss + tpm2-tools are not in the initramfs.

## Implementation sketch (for when TPM is available)

```c
static int derive_key_from_tpm(uint8_t key[32]) {
    /* Try tpm2_unseal via subprocess (simpler than linking tpm2-tss) */
    pid_t pid = fork();
    if (pid == 0) {
        /* child: tpm2_unseal -c key.ctx -o /tmp/key.bin */
        execlp("tpm2_unseal", "tpm2_unseal", "-c", "/etc/wlt/guardian/log.key.ctx",
               "-o", "/tmp/logkey.bin", NULL);
        _exit(127);
    }
    int status; waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return -1;
    int fd = open("/tmp/logkey.bin", O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, key, 32);
    close(fd); unlink("/tmp/logkey.bin");
    return (n == 32) ? 0 : -1;
}

void g_get_log_key(uint8_t key[32]) {
    if (derive_key_from_tpm(key) == 0) {
        printf("[log] key derived from TPM (bound to boot state)\n");
        return;
    }
    /* fallback: urandom (amnesic mode — key changes each boot) */
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { fread(key, 1, 32, f); fclose(f); }
    printf("[log] WARNING: TPM unavailable, using urandom key (amnesic mode)\n");
}
```

## Sealing at build time

```bash
# Generate the key
openssl rand -out log.key 32
# Seal to current PCR state (requires tpm2-tools + a TPM)
tpm2_createprimary -C o -c primary.ctx
tpm2_create -C primary.ctx -i log.key -u key.pub -r key.priv
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
# Store key.ctx in /etc/wlt/guardian/ at image build time
```

## Recommendation

Implement the TPM path once WLTIOS QEMU is configured with swtpm
(`-tpmdev emulator,... -device tpc-tis,tpmdev=...`). Until then, the
urandom fallback is acceptable for the dev sandbox (amnesic mode is
the documented behavior for <TPM targets).
