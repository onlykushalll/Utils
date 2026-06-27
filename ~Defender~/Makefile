# WLTIOS Guardian — Makefile
# Builds the defender daemon, eBPF programs, and ML assets.
# Requires: `source activate.sh` first.
#
# Targets:
#   make bpf       - compile eBPF programs to .o (build/bpf/*.bpf.o)
#   make guardian  - build the guardian daemon (build/guardian)
#   make ml        - train the anomaly model (ml/anomaly.pkl)
#   make sigs      - compile YARA rules (signatures/guardian.yarc)
#   make all       - all of the above
#   make test      - run unit tests
#   make clean     - remove build artifacts

GUARDIAN_ROOT := $(shell pwd)
GUARDIAN_PREFIX ?= $(GUARDIAN_ROOT)/local-deps/usr
BUILD         := $(GUARDIAN_ROOT)/build
BPF_BUILD     := $(BUILD)/bpf
SRC           := $(GUARDIAN_ROOT)/src
BPF_SRC       := $(GUARDIAN_ROOT)/bpf

# eBPF compiler: conda clang -target bpf. -nostdinc keeps glibc headers out.
BPF_CC := $(GUARDIAN_PREFIX)/bin/clang-18
BPF_CFLAGS := -g -O2 -target bpf -nostdinc -D__TARGET_ARCH_x86 -D__x86_64__ \
	      -I$(GUARDIAN_ROOT)/include \
	      -I$(GUARDIAN_PREFIX)/include-linux \
	      -I$(GUARDIAN_PREFIX)/include-linux/linux \
	      -I$(GUARDIAN_PREFIX)/include-linux/asm-generic \
	      -I$(GUARDIAN_PREFIX)/include

# Daemon compiler: SYSTEM gcc (avoids conda sysroot/glibc header conflicts).
# Links against conda static libs (libyara.a, libbpf.a, libelf.a, libz.a) and
# conda dynamic libcrypto/libsqlite3, with rpath so they resolve at runtime.
# -DG_HAVE_LIBBPF enables the libbpf loader code in ebpf_engine.c.
DAEMON_CC := gcc
DAEMON_CFLAGS := -O2 -g -Wall -Wno-unused-function -Wno-unused-variable \
	         -DG_HAVE_LIBBPF \
	         -I$(GUARDIAN_ROOT)/include -I$(GUARDIAN_PREFIX)/include -I$(GUARDIAN_PREFIX)/include/x86_64-linux-gnu
DAEMON_LDFLAGS := -L$(GUARDIAN_PREFIX)/lib -L$(GUARDIAN_PREFIX)/lib64 -L$(GUARDIAN_PREFIX)/lib/x86_64-linux-gnu \
	          -Wl,-rpath,$(GUARDIAN_PREFIX)/lib -Wl,-rpath,$(GUARDIAN_PREFIX)/lib64 -Wl,-rpath,$(GUARDIAN_PREFIX)/lib/x86_64-linux-gnu \
	          -lyara -lbpf -lelf -lcrypto -lzstd -ljitterentropy -lz -lsqlite3 -lpthread -lm -ldl

BPF_PROGS := $(patsubst $(BPF_SRC)/%.bpf.c,$(BPF_BUILD)/%.bpf.o,$(wildcard $(BPF_SRC)/*.bpf.c))
# daemon = all C files EXCEPT mcp_server.c, kairos_cli.c and watchdog.c (they have their own mains)
DAEMON_SRCS := $(filter-out $(SRC)/mcp_server.c $(SRC)/kairos_cli.c $(SRC)/watchdog.c,$(wildcard $(SRC)/*.c))
DAEMON_OBJS := $(patsubst $(SRC)/%.c,$(BUILD)/%.o,$(DAEMON_SRCS))

.PHONY: all bpf guardian mcp kairos watchdog ml sigs test clean help keys
all: bpf sigs guardian mcp kairos watchdog ml

help:
	@echo "WLTIOS Guardian build targets:"
	@echo "  make bpf      - compile eBPF programs"
	@echo "  make guardian - build the daemon"
	@echo "  make ml       - train anomaly model"
	@echo "  make sigs     - compile YARA rules"
	@echo "  make all      - everything"
	@echo "  make test     - unit tests"
	@echo "  make clean    - remove build/"

# --- eBPF programs ---
$(BPF_BUILD)/%.bpf.o: $(BPF_SRC)/%.bpf.c | $(BPF_BUILD)
	@echo "[BPF] $<"
	LD_LIBRARY_PATH=$(GUARDIAN_PREFIX)/lib/x86_64-linux-gnu $(BPF_CC) $(BPF_CFLAGS) -c $< -o $@

bpf: $(BPF_PROGS)

# --- daemon ---
$(BUILD)/%.o: $(SRC)/%.c | $(BUILD)
	@echo "[CC]  $<"
	$(DAEMON_CC) $(DAEMON_CFLAGS) -c $< -o $@

guardian: $(DAEMON_OBJS)
	@echo "[LD]  guardian"
	$(DAEMON_CC) $(DAEMON_OBJS) -o $(BUILD)/guardian $(DAEMON_LDFLAGS)

# --- MCP server (C, ~32 tools, JSON-RPC over Unix socket) ---
MCP_LDFLAGS := $(DAEMON_LDFLAGS)  # same libs (crypto, etc.)
mcp: $(BUILD)/mcp_server.o $(BUILD)/action_engine.o $(BUILD)/forensic_log.o
	@echo "[LD]  mcp_server"
	$(DAEMON_CC) $(BUILD)/mcp_server.o $(BUILD)/action_engine.o $(BUILD)/forensic_log.o \
	    -o $(BUILD)/mcp_server $(MCP_LDFLAGS)

# --- Kairos CLI (loads/unloads Qwythos, calls MCP) ---
kairos: $(BUILD)/kairos_cli.o $(BUILD)/forensic_log.o
	@echo "[LD]  kairos"
	$(DAEMON_CC) $(BUILD)/kairos_cli.o $(BUILD)/forensic_log.o -o $(BUILD)/kairos $(DAEMON_LDFLAGS)

# --- Watchdog (monitors daemon PID and heartbeat, triggers kill switch) ---
watchdog: $(BUILD)/watchdog.o
	@echo "[LD]  watchdog"
	$(DAEMON_CC) $(BUILD)/watchdog.o -o $(BUILD)/guardian_watchdog

# --- YARA signatures ---
sigs: rules/guardian.yar
	@echo "[YARA] compile rules"
	yarac rules/guardian.yar signatures/guardian.yarc

keys:
	@echo "[KEYS] generating Ed25519 keypair"
	openssl genpkey -algorithm ed25519 -out update_signing.key
	openssl pkey -in update_signing.key -pubout -out update_pubkey.pem

# --- anomaly ML ---
ml: ml/anomaly.py
	@echo "[ML]  train anomaly model"
	python3 ml/anomaly.py --train --out ml/anomaly.pkl
	python3 -c "import hashlib; h=hashlib.sha256(open('ml/anomaly.pkl','rb').read()).hexdigest(); open('ml/anomaly.pkl.sha256','w').write(h + '  ml/anomaly.pkl\n')"

# --- tests ---
test: guardian
	@echo "[TEST] running unit tests"
	$(BUILD)/guardian --self-test || true

# --- dirs ---
$(BPF_BUILD) $(BUILD):
	mkdir -p $@

clean:
	rm -rf $(BUILD)
	rm -f signatures/guardian.yarc
	rm -f ml/anomaly.pkl
