# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# Out-of-tree bpftime virtual-patch build — SELF-CONTAINED (verified aarch64 + x86_64).
# Needs NO bpftime source tree. Uses only:
#   - /usr/local/bpftool/bpftool                 (codegen)
#   - /usr/local/bpftool/libbpf/include + libbpf.a (headers + link)
#   - the running kernel's BTF (/sys/kernel/btf/vmlinux) to generate vmlinux.h
#   - the system uapi headers (/usr/include/linux/bpf.h)
# Produces: patch.bpf.o, patch.skel.h, patch_loader.
BPFTOOL    ?= /usr/local/bpftool/bpftool
LIBBPF_INC ?= /usr/local/bpftool/libbpf/include
LIBBPF_A   ?= /usr/local/bpftool/libbpf/libbpf.a
KERNEL_BTF ?= /sys/kernel/btf/vmlinux
CLANG      ?= clang
OUT        := .output

# The patch technique (see patch.bpf.c). Set ONCE here (or `make PATCH_TECHNIQUE=3`)
# and it is passed to BOTH the eBPF object and the loader, so they always agree on
# whether to use the override attach (1/2/4/5) or a plain uprobe (3).
PATCH_TECHNIQUE ?= 1

# PATCH_MODE: `enforce` (default — override/probe_write/clamp) or `observe` (log-only: staged
# rollout + non-crashing detection). Accepts the words or 0/1. Threaded (-D) to BOTH compile units.
PATCH_MODE ?= enforce
# Map explicitly and ERROR on anything else — do NOT silently fall through to enforce (the
# state-mutating mode): a typo like `PATCH_MODE=observ` by someone intending a cautious observe
# rollout must not ship the acting patch.
PATCH_MODE_VAL := $(if $(filter observe 0,$(PATCH_MODE)),0,$(if $(filter enforce 1,$(PATCH_MODE)),1,$(error PATCH_MODE must be observe|enforce (or 0|1), got '$(PATCH_MODE)')))

# uname -m -> __TARGET_ARCH_ suffix. Order matters: 'arm.*' must run BEFORE
# 'aarch64' (aarch64 has no "arm" substring, so arm.* leaves it alone, then it
# maps to arm64). Reversing them would turn arm64 back into arm.
ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/arm.*/arm/;s/aarch64/arm64/;s/ppc64le/powerpc/;s/mips.*/mips/;s/riscv64/riscv/;s/loongarch64/loongarch/')

BPF_INCLUDES    := -I$(OUT) -I$(LIBBPF_INC)
LOADER_INCLUDES := -I$(OUT) -I$(LIBBPF_INC)
# clang's per-arch system headers (asm/types.h etc.) — required for -target bpf
CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

.PHONY: all clean FORCE
all: patch_loader

$(OUT):
	mkdir -p $(OUT)

# PATCH_TECHNIQUE must be a REBUILD DEPENDENCY, not just a -D value. make decides what to
# rebuild from file timestamps and ignores command-line variable changes, so after a plain
# `make` (technique 1) a later `make PATCH_TECHNIQUE=3` on unchanged sources would rebuild
# NOTHING and silently ship the wrong technique (override attach running the no-op tech-1
# program). This stamp file changes mtime only when the value actually changes, and both
# compile units depend on it, so switching the technique forces the correct rebuild.
$(OUT)/.technique.stamp: FORCE | $(OUT)
	@echo '$(PATCH_TECHNIQUE)' | cmp -s - $@ 2>/dev/null || echo '$(PATCH_TECHNIQUE)' > $@

# Same rebuild-dependency treatment for PATCH_MODE (observe vs enforce): switching mode on the
# command line must force a recompile of both units, or you'd ship the wrong mode silently.
$(OUT)/.mode.stamp: FORCE | $(OUT)
	@echo '$(PATCH_MODE_VAL)' | cmp -s - $@ 2>/dev/null || echo '$(PATCH_MODE_VAL)' > $@

# Generate vmlinux.h from the running kernel's BTF (CO-RE). No bpftime source needed.
$(OUT)/vmlinux.h: | $(OUT)
	@test -r $(KERNEL_BTF) || { echo "ERROR: $(KERNEL_BTF) not readable — need a BTF-enabled kernel (CONFIG_DEBUG_INFO_BTF) to generate vmlinux.h"; exit 1; }
	$(BPFTOOL) btf dump file $(KERNEL_BTF) format c > $@

$(OUT)/patch.bpf.o: patch.bpf.c ufunc.bpf.h patch_event.h $(OUT)/vmlinux.h $(OUT)/.technique.stamp $(OUT)/.mode.stamp
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -DPATCH_TECHNIQUE=$(PATCH_TECHNIQUE) -DPATCH_MODE=$(PATCH_MODE_VAL) \
		-Wno-missing-declarations \
		$(BPF_INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		-c patch.bpf.c -o $(OUT)/patch.tmp.bpf.o
	$(BPFTOOL) gen object $@ $(OUT)/patch.tmp.bpf.o

patch.skel.h: $(OUT)/patch.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

patch_loader: patch_loader.c attach_override.h patch_event.h patch.skel.h $(OUT)/.technique.stamp $(OUT)/.mode.stamp | $(OUT)
	$(CLANG) -g -Wall -DPATCH_TECHNIQUE=$(PATCH_TECHNIQUE) -DPATCH_MODE=$(PATCH_MODE_VAL) $(LOADER_INCLUDES) -c patch_loader.c -o $(OUT)/patch_loader.o
	$(CLANG) $(OUT)/patch_loader.o $(LIBBPF_A) -lelf -lz -o $@

clean:
	rm -rf $(OUT) patch.skel.h patch_loader
