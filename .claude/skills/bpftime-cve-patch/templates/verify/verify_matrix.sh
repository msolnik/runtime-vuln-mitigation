#!/usr/bin/env bash
# Phase 5 verification matrix for a FILE / CLI target (`./target input`). Runs the
# A/B/C+control cells and gates on all green. Reuses poc/run.sh (the ONE oracle)
# unchanged for A and B — the ONLY A-vs-B difference is the bpftime agent on the
# oracle's target process. Each cell starts from CLEAN bpftime shm.
#
# CRITICAL (the bug this shape fixes): a bpftime patch is per-process — it only applies
# to a process that runs with the agent preloaded AND a live loader. So the PATCHED cells
# must (a) keep the loader alive in the BACKGROUND and (b) run the SAME oracle with
# AGENT_PRELOAD set, so run.sh's own target is the hooked process. Deploying a throwaway
# target and then measuring a different, unhooked one (an easy mistake) makes Cell B measure
# an UNPATCHED process — it can never legitimately pass.
#
# Fill in the CONFIG block, then: bash verify_matrix.sh   (server target? use verify_matrix_server.sh)
set -u
N="${N:-20}"
ROOT="${ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"     # work/<CVE-ID>
POC_DIR="${POC_DIR:-$ROOT/poc}"
PATCH_DIR="${PATCH_DIR:-$ROOT/patch}"
AGENT="${AGENT:-/usr/local/bin/libbpftime-agent.so}"
LOADER_LOG="${LOADER_LOG:-/tmp/verify_loader.log}"

# ==== fill these in per CVE ==================================================
TARGET="$ROOT/target/noasan/target_app"   # the NON-ASan -g build (all four cells; agent clashes with ASan).
                                            # MUST be byte-identical to poc/run.sh's TARGET — bpftime keys the
                                            # uprobe on the path (perf config1); a mismatch protects nothing.
FUNC="<sink_function>"                      # symbol the loader hooks (research/root-cause.md)
# EXTRA_PRELOAD="$(gcc -print-file-name=libasan.so)"   # ONLY if you must verify on an ASan build (libasan first)
run_benign_suite(){ ( cd "$(dirname "$0")" && ./benign_suite.sh ); }   # exit 0 = benign OK
export TARGET                               # run.sh honors $TARGET — keep the oracle + loader hook on ONE binary
# ============================================================================

clean(){ for p in patch_loader bpftime bpftimetool "$(basename "$TARGET")"; do pkill -9 -x "$p" 2>/dev/null; done
	/usr/local/bin/bpftimetool remove >/dev/null 2>&1; rm -f /dev/shm/bpftime_maps_shm 2>/dev/null; sleep 1; }

# Start the patch loader in the background; it stays alive polling the ring buffer. Return 0
# once it reports the hook installed. Sets $LOADER_PID.
start_loader(){ : > "$LOADER_LOG"
	BPFTIME_LOG_OUTPUT=console /usr/local/bin/bpftime -i /usr/local/bin load \
		"$PATCH_DIR/patch_loader" "$TARGET" "$FUNC" > "$LOADER_LOG" 2>&1 &
	LOADER_PID=$!
	for _ in $(seq 1 40); do
		grep -q 'patch loaded: hooking' "$LOADER_LOG" && return 0
		kill -0 "$LOADER_PID" 2>/dev/null || return 1; sleep 0.3
	done; return 1; }
stop_loader(){ [ -n "${LOADER_PID:-}" ] && kill "$LOADER_PID" 2>/dev/null; LOADER_PID=""; }
# The agent preload the oracle uses in patched cells (libasan first if verifying on ASan):
AGENT_PRELOAD_VAL="${EXTRA_PRELOAD:+$EXTRA_PRELOAD:}$AGENT"

pass=1; note(){ echo "[$1] $2"; }

echo "== Cell A: UNPATCHED + PoC (expect exploited x$N) =="
clean
( cd "$POC_DIR" && ./run_n.sh "$N" all ) && note A "exploited (bug real)" || { note A "FAIL — bug not reliably reproduced"; pass=0; }
# Sweep sanity: every declared variant must ALSO exploit the UNPATCHED build, else "blocked in
# Cell B" proves nothing (a variant that never exploited can't demonstrate the patch stopped it).
if [ "${SWEEP:-1}" = 1 ]; then
  for v in $(cd "$POC_DIR" && python3 exploit.py variants); do
    ( cd "$POC_DIR" && VARIANT="$v" ./run.sh >/dev/null 2>&1 ) \
      && note "A:$v" "variant exploits unpatched" || { note "A:$v" "FAIL — variant does NOT exploit unpatched (sweep would be vacuous)"; pass=0; }
  done
fi

echo "== Control: UNPATCHED + benign (record baseline) =="
clean
run_benign_suite && note CTL "benign baseline OK" || { note CTL "FAIL — pre-existing benign failure"; pass=0; }

echo "== Cell B: PATCHED + PoC (+variants) (expect blocked x$N) =="
clean
if ! start_loader; then echo "  loader/attach failed"; tail -5 "$LOADER_LOG"; note B "FAIL — attach failed"; pass=0
else
  ( cd "$POC_DIR" && AGENT_PRELOAD="$AGENT_PRELOAD_VAL" ./run_n.sh "$N" none ) \
    && note B "blocked (exploit neutralized)" || { note B "FAIL — exploit still succeeds"; pass=0; }
  # Anti-overfitting sweep (CONDITIONAL-GUARD patches only — see references/patch-verification.md;
  # an unconditional state-reset patch reads no payload and cannot overfit: set SWEEP=0 and make
  # the structural argument instead). The variant list comes from the ONE driver, so it can never
  # drift from the exploit — no separate variant tool.
  if [ "${SWEEP:-1}" = 1 ]; then
    for v in $(cd "$POC_DIR" && python3 exploit.py variants); do
      ( cd "$POC_DIR" && VARIANT="$v" AGENT_PRELOAD="$AGENT_PRELOAD_VAL" ./run_n.sh "$N" none ) \
        && note "B:$v" "variant blocked" || { note "B:$v" "FAIL — variant still exploits"; pass=0; }
    done
  fi
  # Gate on a FIRED event (patch-verification.md step 8): a "blocked" with ZERO fires may be
  # blocked-by-luck (agent perturbed the heap) or a half-attach — NOT proof the hook neutralized it.
  # (Skip for an unconditional-sanitize patch only if you've argued it structurally; here we require
  # at least one fire on the malicious path, matching the server matrix's per-request FIRED gate.)
  fired=$(grep -c '\[patch\] FIRED' "$LOADER_LOG" 2>/dev/null || true)
  echo "  loader FIRED events: ${fired:-0}"
  [ "${fired:-0}" -ge 1 ] || { note B "FAIL — blocked but the hook never FIRED (blocked by luck / half-attach?)"; pass=0; }
  stop_loader
fi

echo "== Cell C: PATCHED + benign (must match baseline, no false positives) =="
clean
if ! start_loader; then echo "  loader/attach failed"; note C "FAIL — attach failed"; pass=0
else
  ( cd "$(dirname "$0")" && AGENT_PRELOAD="$AGENT_PRELOAD_VAL" ./benign_suite.sh ) \
    && note C "benign still works" || { note C "FAIL — over-blocking (false positive)"; pass=0; }
  stop_loader
fi

clean
echo "================ GATE ================"
[ "$pass" -eq 1 ] && { echo "PASS: A=exploited, B=blocked, C=works, control=stable"; exit 0; } \
                  || { echo "FAIL: at least one cell red — do not claim success (escalate)"; exit 1; }
