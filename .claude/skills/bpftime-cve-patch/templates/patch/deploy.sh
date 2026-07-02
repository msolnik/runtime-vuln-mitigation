#!/usr/bin/env bash
# Deploy / remove the bpftime virtual patch. Verified end-to-end on aarch64.
#
# CRITICAL (learned empirically): bpftime shares ONE global shm
# (/dev/shm/bpftime_maps_shm). A stale loader/agent or leftover shm makes the
# override attach fail (bpf_prog_attach -> EBADF) or collide. ALWAYS start from
# clean shm — this script does that in `clean`.
#
# Also: bpftime's syscall-tracepoint hooking is x86_64-ONLY (the aarch64 syscall
# trampoline is an unimplemented stub). On aarch64 you MUST use a uprobe-override
# patch (this template), not a syscall filter. This script warns if it detects a
# syscall-mode patch on aarch64.
#
# Usage:
#   ./deploy.sh preload   ./target [args...]   # load loader + run target with the agent
#   ./deploy.sh attach    <pid>                # inject into an already-running pid (needs sudo)
#   ./deploy.sh clean                          # kill loaders + wipe bpftime shm
#
# ASan / library-order note (verified): `preload` runs the target via explicit LD_PRELOAD
# (NOT `bpftime start`) so you can control order. If the target is ASan-instrumented, set
#   EXTRA_PRELOAD=$(gcc -print-file-name=libasan.so)
# so libasan is loaded BEFORE the agent — otherwise the sanitizer aborts ("ASan runtime does
# not come first"). The loader's TARGET_BINARY must be the EXACT path of the target you run
# here (bpftime keys the uprobe on that path). For a SERVER, background the target and drive
# it with the PoC (see run_server.sh) instead of the foreground run below.
set -u
BPFTIME_BIN="${BPFTIME_BIN:-/usr/local/bin/bpftime}"
INSTALL="${INSTALL:--i /usr/local/bin}"    # where libbpftime-*.so live (default $HOME/.bpftime does NOT exist here)
AGENT_SO="${AGENT_SO:-/usr/local/bin/libbpftime-agent.so}"
EXTRA_PRELOAD="${EXTRA_PRELOAD:-}"         # e.g. libasan.so for an ASan target — MUST precede the agent
LOADER="${LOADER:-./patch_loader}"

clean(){
	for p in patch_loader bpftime bpftimetool; do pkill -9 -x "$p" 2>/dev/null; done
	/usr/local/bin/bpftimetool remove >/dev/null 2>&1 || true
	rm -f /dev/shm/bpftime_maps_shm 2>/dev/null || true
	sleep 1
}

arch_check(){
	if [ "$(uname -m)" = "aarch64" ] && grep -qsE 'tracepoint/syscalls|sys_enter|sys_exit' patch.bpf.c; then
		echo "WARNING: this looks like a syscall-tracepoint patch, which does NOT work on aarch64." >&2
		echo "         Rewrite it as a uprobe-override on the vulnerable function." >&2
	fi
}

case "${1:-}" in
  preload)
	shift; arch_check; clean
	echo "[deploy] loader: $BPFTIME_BIN $INSTALL load $LOADER"
	$BPFTIME_BIN $INSTALL load "$LOADER" & LP=$!
	sleep 3
	kill -0 $LP 2>/dev/null || { echo "[deploy] loader died — attach failed (check clean shm / symbol / arch)"; exit 1; }
	# Explicit LD_PRELOAD (not `bpftime start`) so EXTRA_PRELOAD (e.g. libasan) precedes the agent:
	PRELOAD="${EXTRA_PRELOAD:+$EXTRA_PRELOAD:}$AGENT_SO"
	echo "[deploy] target: LD_PRELOAD=$PRELOAD $*"
	LD_PRELOAD="$PRELOAD" "$@"
	kill $LP 2>/dev/null; clean ;;
  attach)
	shift; arch_check; clean
	$BPFTIME_BIN $INSTALL load "$LOADER" & sleep 3
	echo "[deploy] injecting into pid $1 (needs root/CAP_SYS_PTRACE)"
	sudo $BPFTIME_BIN $INSTALL attach "$1" ;;
  clean) clean; echo "[deploy] shm + loaders cleared" ;;
  *) echo "usage: $0 {preload ./target [args]|attach <pid>|clean}"; exit 2 ;;
esac
