# Guardian Privacy Document

## What Guardian collects

**Guardian does NOT collect telemetry.** There is no cloud, no phone-home, no
automatic reporting. All detection and enforcement happens locally.

## What Guardian stores locally

### Forensic log (`/var/log/guardian.log`)
- AES-256-GCM encrypted
- SHA-256 hash-chained (tamper-evident)
- Contains: event timestamps, process info (pid, comm, ppid), rule matches,
  actions taken, evidence hashes
- **Amnesic mode**: the encryption key is derived from /dev/urandom on each
  boot. On reboot, the key is wiped and the log becomes unreadable. This is
  the default behavior on systems without a TPM.
- **TPM mode** (future): the key is sealed to TPM PCR values, binding log
  readability to the platform's measured boot state.

### FIM database (`/etc/wlt/guardian/fim.db`)
- SQLite3, optionally AES-256-GCM encrypted
- Contains: file paths, SHA-256 hashes, metadata (mtime, size, mode, uid, gid)
- Used to detect file tampering

### Baseline copies (`/etc/wlt/guardian/baseline/`)
- Clean original copies of watched files
- Used to restore files after tampering
- Built at image-creation time, not at runtime

## What Guardian transmits

### Signature updates (opt-in, over Tor)
- Guardian fetches YARA signature updates from a Tor .onion URL (if configured)
- Updates are Ed25519-signed and verified before applying
- The update URL and public key are in `wlt-integration/guardian.conf`
- **No telemetry is sent** — Guardian only downloads; it never uploads data

### Network connections
- Guardian's own network activity: Tor SOCKS proxy (localhost:9050) for updates
- All other network egress by non-Tor processes is KILLED by the eBPF connect hook
- The kill switch deletes the default route on detection of non-Tor egress

## Process data accessed

Guardian reads `/proc` to collect per-process features for anomaly detection:
- `/proc/<pid>/status` (memory usage)
- `/proc/<pid>/stat` (CPU usage)
- `/proc/<pid>/maps` + `/proc/<pid>/mem` (memory scanning for YARA signatures)
- `/proc/<pid>/cmdline` (command line for signature scanning)
- `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` (network leak detection)

**This data is processed in-memory and is NOT persisted** unless a detection
triggers a forensic log entry (which is encrypted).

## Canary files

Guardian places bait files (`!GUARDIAN_CANARY_DO_NOT_TOUCH.bin`) in `/tmp`,
`/var/tmp`, `/etc`, `/root`, `/home`. These contain 1KB of random data. Their
purpose is ransomware detection — any access or modification triggers an alert.

**These files persist across daemon restarts** by design (so attacks between
runs are detected). They can be safely deleted manually if Guardian is uninstalled.

## Data retention

- Forensic log: rotated when it exceeds 10MB (overflow spills to plaintext JSON)
- FIM database: regenerated at each baseline build (image creation time)
- No historical data is retained across reboots in amnesic mode

## User control

- All logging can be disabled in `guardian.conf`
- The kill switch is one-way (cannot be cleared by userspace once activated) —
  this is a security feature, not a privacy concern
- Signature updates are disabled by default (empty `update_url` in config)
