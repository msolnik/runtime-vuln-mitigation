#!/usr/bin/env bash
# PoC oracle for a SERVER / DAEMON target (web server, database, ...), where the crash is
# in a worker/child, not your foreground shell. exit 0 = exploited, 1 = not,
# 2 = INCONCLUSIVE, 3 = harness error. Reuse UNCHANGED across verify cells A and B.
#
# SINGLE SOURCE OF TRUTH: the payload and its delivery live in exploit.py — this script
# NEVER embeds payload bytes and NEVER uses curl (curl percent-encodes the path, masking
# escape-expansion bugs). It starts the server, calls `exploit.py send` to deliver the exact
# wire bytes, and detects the worker crash. The Phase-5 variant sweep just passes --variant.
#
#   ./run_server.sh                      # canonical exploit  -> expect exit 0
#   ./run_server.sh --variant benign     # negative control   -> expect exit 1
#   ./run_server.sh --variant amp        # a sweep variant    -> expect exit 0 (unpatched)
#   VARIANT=amp ./run_server.sh          # same, via env (what run_n.sh / the matrix set)
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"

# ---- set these per CVE (from research/root-cause.md) ------------------------
PORT=8080
# Start the server IN THE FOREGROUND, single worker, no daemonize, under target.conf, so the
# crash is catchable and workers inherit ASAN_OPTIONS. Foreground/single-process is usually a
# CONFIG directive or a flag that VARIES per server (nginx: `daemon off; master_process off;`
# in the conf; apache: `-X`; others: `--foreground`) — set it correctly for YOUR server.
# Use an ABSOLUTE config path — many servers resolve a relative -c against a prefix/working dir.
CONF="$HERE/target.conf"                                                        # ABSOLUTE (HERE is absolute)
# SERVER_BIN defaults to the ASan build (this oracle is the Phase-3 reproduction check); the
# Phase-5 matrix overrides it to the non-ASan build via `SERVER_BIN=.../noasan/... run_server.sh`.
SERVER_BIN="${SERVER_BIN:-$HERE/../target/asan/<server>}"
START_SERVER() { "$SERVER_BIN" -c "$CONF" & }                                   # keep PID in $SRV; add the per-server foreground flag if needed
SANITIZER_RE='AddressSanitizer: heap-buffer-overflow'
CRASH_LOG='error.log'          # server's error/log file; leave empty to skip the log fallback
CRASH_RE='(worker|child) .*(exited on signal|crash|SIGSEGV|SIGABRT)'   # tune to the server's log format
# -----------------------------------------------------------------------------

# Variant selection: --variant V, or $VARIANT, default canonical. All other args pass through
# to `exploit.py send` (e.g. --filler/--count) so the ONE driver stays the source of truth.
VARIANT="${VARIANT:-canonical}"
PASS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --variant) VARIANT="$2"; shift 2 ;;
        --variant=*) VARIANT="${1#*=}"; shift ;;
        *) PASS+=("$1"); shift ;;
    esac
done

logdir="$(mktemp -d "${TMPDIR:-/tmp}/poc-asan.XXXXXX")" || exit 3
export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:symbolize=1:log_path=$logdir/asan"
export MALLOC_CHECK_=3   # non-ASan build: glibc turns heap corruption into SIGABRT (patch-verify oracle)
export TZ=UTC LC_ALL=C
: > "$HERE/$CRASH_LOG" 2>/dev/null || true

SRV=""
cleanup() { [ -n "$SRV" ] && kill "$SRV" 2>/dev/null; pkill -P "${SRV:-0}" 2>/dev/null; rm -rf "$logdir"; }
trap cleanup EXIT

START_SERVER; SRV=$!

# Readiness with liveness: a server that dies at startup -> INCONCLUSIVE, not a 5s hang.
ready=1
for _ in $(seq 1 50); do
    kill -0 "$SRV" 2>/dev/null || { echo "INCONCLUSIVE: server exited before ready"; exit 2; }
    (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null && { ready=0; break; }
    sleep 0.1
done
[ "$ready" -eq 0 ] || { echo "INCONCLUSIVE: server never came up"; exit 2; }

# Deliver the EXACT wire bytes via the single-source driver (raw socket, no curl re-encoding).
status="$(python3 "$HERE/exploit.py" send --variant "$VARIANT" --port "$PORT" "${PASS[@]}")"
echo "variant=$VARIANT  server-status=$status"
sleep 1                        # let the worker crash + ASan flush its report

shopt -s nullglob
report="$(cat "$logdir"/asan.* 2>/dev/null)"
elog="$(cat "$HERE/$CRASH_LOG" 2>/dev/null)"
shopt -u nullglob

if printf '%s' "$report" | grep -qE "$SANITIZER_RE"; then
    echo "REPRODUCED (worker sanitizer report)"; exit 0
fi
# The SERVER PROCESS ITSELF died. For a single-process server (nginx `master_process off`)
# or a non-ASan build under MALLOC_CHECK_=3, the foreground process just aborts (SIGABRT) with
# NO ASan log and NO worker-crash line — so this liveness check is the PRIMARY detector there.
# We have not killed it yet (cleanup runs on EXIT), so a dead $SRV = a crash. Count only fatal
# crash signals (6 SIGABRT / 7 SIGBUS / 11 SIGSEGV), not a clean exit.
if ! kill -0 "$SRV" 2>/dev/null; then
    wait "$SRV" 2>/dev/null; rc=$?; sig=$(( rc>128 ? rc-128 : 0 ))
    case "$sig" in 6|7|11) echo "REPRODUCED (server process crashed, signal $sig)"; exit 0 ;; esac
fi
# Fallback: a worker/child died (a master+worker server usually survives + respawns), so check
# the server's own log for a crash line (format varies per server — tune CRASH_RE).
if [ -n "$CRASH_LOG" ] && [ -f "$HERE/$CRASH_LOG" ] && grep -qE "$CRASH_RE" "$HERE/$CRASH_LOG"; then
    echo "REPRODUCED (worker/child crashed)"; exit 0
fi
echo NOT_REPRODUCED; exit 1
