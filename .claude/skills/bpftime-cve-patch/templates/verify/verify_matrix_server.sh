#!/usr/bin/env bash
# Phase 5 verification matrix for a SERVER / DAEMON target (web server, database,
# broker, ...). Use this instead of verify_matrix.sh when the target is a
# long-running process driven over a socket/protocol, not a `./target input` CLI.
#
# Shape (validated end-to-end):
#   - runs every cell on the NON-ASan `-g` build (target/noasan/...): the bpftime
#     agent's LD_PRELOAD clashes with the ASan runtime. Crash oracle = MALLOC_CHECK_=3,
#     which turns heap corruption into a deterministic SIGABRT (signal 6).
#   - PATCHED cells: start the patch loader in the BACKGROUND under `bpftime load`
#     (it stays alive polling the ring buffer), THEN start the server in the
#     foreground with LD_PRELOAD=<agent> so the agent injects the hook in-process.
#   - FIRED evidence is per-request DELTA-counted from the loader log (total_fired
#     is cumulative and also advanced by the readiness probe + benign warm-up).
#
# Fill in the hooks in the CONFIG block, then: bash verify_matrix_server.sh
set -u
N="${N:-10}"
ROOT="${ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"        # work/<CVE-ID>
AGENT="${AGENT:-/usr/local/bin/libbpftime-agent.so}"
LOADER_LOG="${LOADER_LOG:-/tmp/verify_loader.log}"
SRV_OUT="${SRV_OUT:-/tmp/verify_server.out}"

# ==== fill these in per CVE (generic placeholders) ===========================
TARGET="$ROOT/target/noasan/<server>"     # the NON-ASan -g build (patch attaches here)
FUNC="<sink_function>"                     # symbol the loader hooks (root-cause.md)
PATCHDIR="$ROOT/patch"                     # built patch_loader lives here

# Start the server in the FOREGROUND, single worker, no daemonize, under the patch oracle.
# $1 = with_agent (0/1). Foreground/single-process VARIES per server — a flag (apache `-X`,
# some `--foreground`) or a CONFIG directive (nginx: `daemon off; master_process off;`). Set
# SRV_FLAGS for YOUR server (below). ALSO: CONF must be ABSOLUTE — many servers join a relative
# -c to a `-p`/prefix dir, so a relative path silently loads the wrong (default) config and
# leaves the vuln path OFF; if your server needs a prefix, pass it here too (e.g. nginx `-p`).
CONF="$ROOT/poc/target.conf"               # ABSOLUTE path — see note above
SRV_FLAGS=( -c "$CONF" )                    # e.g. nginx: ( -c "$CONF" -p "$ROOT/poc/run" ); apache: ( -X -f "$CONF" )
start_server(){ : > "$SRV_OUT"
  if [ "$1" = 1 ]; then
    MALLOC_CHECK_=3 LD_PRELOAD="$AGENT" BPFTIME_LOG_OUTPUT=console \
      "$TARGET" "${SRV_FLAGS[@]}" > "$SRV_OUT" 2>&1 &
  else
    MALLOC_CHECK_=3 "$TARGET" "${SRV_FLAGS[@]}" > "$SRV_OUT" 2>&1 &
  fi
  SRV=$!; }

# Readiness: return 0 once the server accepts a benign probe; return 1 if it dies
# at startup (so we report STARTUP_FAIL instead of hanging).
wait_ready(){ for i in $(seq 1 120); do
    send_benign "$PROBE" >/dev/null 2>&1 && return 0
    kill -0 "${SRV:-0}" 2>/dev/null || return 1; sleep 0.2; done; return 1; }

# Send one attack for a named variant, via the SINGLE-SOURCE driver (raw socket, EXACT wire
# bytes — NOT curl, which percent-encodes the path and masks escape-expansion bugs).
send_attack(){ python3 "$ROOT/poc/exploit.py" send --variant "${1:-canonical}" >/dev/null 2>&1; }
# Send one benign request; echo a comparable result token (status/body) for baselining.
# Benign paths are app-legit URLs (no exact-byte requirement), so curl is fine here.
send_benign(){ curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:8080/$1"; }

PROBE="ready"                                        # a cheap benign readiness request
BENIGN=(normal "users/list" "v1/data.json" ready)    # Cell C / control suite
# Anti-overfitting sweep (CONDITIONAL-guard patches only — see patch-verification.md step 10).
# The variant list comes from the ONE driver (exploit.py), so it can NEVER drift from the
# exploit and there is no second variant tool. VARIANTS[0] ("canonical") is the main attack.
# For an UNCONDITIONAL sanitize/state-reset patch, set SWEEP=0 and make the structural
# argument instead (it reads no payload, so a byte sweep proves nothing).
mapfile -t VARIANTS < <(python3 "$ROOT/poc/exploit.py" variants)
[ "${#VARIANTS[@]}" -gt 0 ] || VARIANTS=(canonical)
# =============================================================================

SRV=""; pass=1
clean_shm(){ for p in patch_loader bpftime bpftimetool "$(basename "$TARGET")"; do pkill -9 -x "$p" 2>/dev/null; done
  /usr/local/bin/bpftimetool remove >/dev/null 2>&1; rm -f /dev/shm/bpftime_maps_shm 2>/dev/null; sleep 1; }
stop_server(){ [ -n "$SRV" ] && kill "$SRV" 2>/dev/null; pkill -9 -x "$(basename "$TARGET")" 2>/dev/null; SRV=""; }
alive(){ kill -0 "${SRV:-0}" 2>/dev/null; }
fired_total(){ grep -c '\[patch\] FIRED' "$LOADER_LOG" 2>/dev/null || true; }

# Start the patch loader in the background; wait until it reports the hook installed.
start_loader(){ : > "$LOADER_LOG"
  BPFTIME_LOG_OUTPUT=console /usr/local/bin/bpftime -i /usr/local/bin load \
    "$PATCHDIR/patch_loader" "$TARGET" "$FUNC" > "$LOADER_LOG" 2>&1 &
  LOADER_PID=$!
  for i in $(seq 1 40); do
    grep -q 'patch loaded: hooking' "$LOADER_LOG" && return 0
    kill -0 "$LOADER_PID" 2>/dev/null || return 1; sleep 0.3
  done; return 1; }

note(){ echo "  [$1] $2"; }
echo "== server verification matrix (N=$N, non-ASan build, oracle=MALLOC_CHECK_=3->SIGABRT) =="

# ---- Cell A: unpatched + attack, expect SIGABRT every run -------------------
echo; echo "== Cell A: UNPATCHED + attack x$N (expect crash every run) =="
a_crash=0
for run in $(seq 1 "$N"); do
  clean_shm >/dev/null 2>&1; start_server 0
  if ! wait_ready; then echo "  run $run: STARTUP_FAIL"; stop_server; continue; fi
  send_attack "${VARIANTS[0]}" >/dev/null 2>&1 || true; sleep 0.4
  if alive; then echo "  run $run: SURVIVED — UNEXPECTED"
  else wait "$SRV" 2>/dev/null; rc=$?; sig=$((rc>128?rc-128:0)); echo "  run $run: CRASH sig=$sig"
       # count any fatal crash signal the confirmed oracle produces: SIGABRT(6, MALLOC_CHECK_),
       # SIGBUS(7, aarch64), SIGSEGV(11). Hardcoding sig==6 would FAIL a real SIGSEGV overflow.
       case "$sig" in 6|7|11) a_crash=$((a_crash+1));; esac; fi
  stop_server
done
echo "  Cell A: $a_crash/$N crashed"; [ "$a_crash" -eq "$N" ] && note A "exploited (bug real)" || { note A FAIL; pass=0; }

# ---- Control: unpatched + benign, record baseline ---------------------------
echo; echo "== Control: UNPATCHED + benign (record baseline) =="
clean_shm >/dev/null 2>&1; start_server 0; ctl_ok=1
if wait_ready; then
  for b in "${BENIGN[@]}"; do r=$(send_benign "$b"); echo "  baseline $b -> $r"; done
  alive && echo "  server ALIVE after benign suite" || { echo "  DIED on benign"; ctl_ok=0; }
else echo "  STARTUP_FAIL"; ctl_ok=0; fi
stop_server
[ "$ctl_ok" = 1 ] && note CTL "baseline recorded" || { note CTL FAIL; pass=0; }

# ---- Cell B: patched + attack (+sweep), expect SURVIVE + FIRED delta --------
echo; echo "== Cell B: PATCHED + attack x$N + sweep (expect survive + FIRED) =="
clean_shm >/dev/null 2>&1
if ! start_loader; then echo "  loader/attach failed"; tail -5 "$LOADER_LOG"; note B FAIL; pass=0
else
  start_server 1
  if ! wait_ready; then echo "  server under agent never served"; tail -3 "$SRV_OUT"; note B FAIL; pass=0; stop_server
  else
    grep -q 'Attach successfully' "$SRV_OUT" && echo "  agent: Attach successfully"
    b_ok=1; prev=$(fired_total)
    for run in $(seq 1 "$N"); do
      send_attack "${VARIANTS[0]}" >/dev/null 2>&1; sleep 0.3
      now=$(fired_total); d=$((now-prev)); prev=$now
      if alive && [ "$d" -ge 1 ]; then echo "  run $run: SURVIVED  FIRED+=$d (total=$now)"
      else echo "  run $run: FAIL alive=$(alive&&echo y||echo n) FIRED+=$d"; b_ok=0; fi
    done
    if [ "${SWEEP:-1}" = 1 ]; then
      echo "  -- anti-overfitting sweep (set SWEEP=0 for unconditional-sanitize patches) --"
      for v in "${VARIANTS[@]}"; do
        prev=$(fired_total); send_attack "$v"; sleep 0.3
        now=$(fired_total); d=$((now-prev))
        if alive && [ "$d" -ge 1 ]; then echo "  variant [$v]: SURVIVED FIRED+=$d"
        else echo "  variant [$v]: FAIL alive=$(alive&&echo y||echo n) FIRED+=$d"; b_ok=0; fi
      done
    else echo "  -- sweep skipped (SWEEP=0): unconditional-sanitize patch, structural argument in results.md --"; fi
    stop_server
    [ "$b_ok" = 1 ] && note B "blocked (survived + FIRED)" || { note B FAIL; pass=0; }
  fi
fi

# ---- Cell C: patched + benign, must match baseline --------------------------
echo; echo "== Cell C: PATCHED + benign (must match baseline, no false block) =="
clean_shm >/dev/null 2>&1
if ! start_loader; then echo "  loader failed"; note C FAIL; pass=0
else
  start_server 1; c_ok=1
  if wait_ready; then
    for b in "${BENIGN[@]}"; do r=$(send_benign "$b"); echo "  patched benign $b -> $r"; done
    alive && echo "  server ALIVE (patched)" || { echo "  DIED"; c_ok=0; }
    echo "  (an UNCONDITIONAL sanitize patch also FIREs on benign, harmlessly — total_fired=$(fired_total);"
    echo "   'no false block' is proven by matching the baseline above, NOT by an ALLOWED event)"
  else echo "  STARTUP_FAIL"; c_ok=0; fi
  stop_server
  [ "$c_ok" = 1 ] && note C "benign matches baseline" || { note C "FAIL — over-blocking"; pass=0; }
fi

clean_shm >/dev/null 2>&1
echo; echo "==================== GATE ===================="
[ "$pass" = 1 ] && { echo "PASS: A=exploited, B=blocked(incl sweep,+FIRED), C=matches baseline, control=stable"; exit 0; } \
                || { echo "FAIL: at least one cell red — do NOT claim success (escalate)"; exit 1; }
