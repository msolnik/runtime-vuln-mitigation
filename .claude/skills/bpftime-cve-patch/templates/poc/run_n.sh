#!/usr/bin/env bash
# Run the oracle N times and enforce a consistency threshold. Use for the
# exploit (require ALL N reproduce) and for every control (require 0 of N).
# Verified: heap-layout/race bugs are flaky — a single run is not enough.
#
#   ./run_n.sh 20 all                    # PoC: exit 0 only if all 20 report REPRODUCED
#   ./run_n.sh 20 none                   # control: exit 0 only if 0 of 20 report REPRODUCED
#   ./run_n.sh 20 all --variant amp      # a sweep variant, ALL N must reproduce (unpatched)
#   ORACLE=./run_server.sh ./run_n.sh 10 all   # server target (default oracle is ./run.sh)
#
# The variant / extra args are forwarded to the ONE oracle (run.sh or run_server.sh), which
# forwards them to exploit.py — a single source of truth, no per-phase payload tooling.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ORACLE="${ORACLE:-$HERE/run.sh}"
N="${1:-20}"; WANT="${2:-all}"                                # remaining args -> oracle (e.g. --variant amp)
# shift up to 2 safely: `shift 2` with <2 positionals is a no-op that would LEAK N/WANT into "$@".
[ $# -ge 1 ] && shift; [ $# -ge 1 ] && shift
repro=0 incon=0
for _ in $(seq 1 "$N"); do
	"$ORACLE" "$@" >/dev/null 2>&1; rc=$?
	case "$rc" in 0) repro=$((repro+1));; 2|3) incon=$((incon+1));; esac
done
echo "reproduced $repro/$N (inconclusive $incon)  [oracle=$(basename "$ORACLE") args=$*]"
[ "$incon" -gt 0 ] && { echo "FAIL: $incon inconclusive runs — fix the harness first"; exit 2; }
case "$WANT" in
	all)  [ "$repro" -eq "$N" ] && { echo "PASS (all reproduced)"; exit 0; } || { echo "FAIL: only $repro/$N"; exit 1; } ;;
	none) [ "$repro" -eq 0 ]   && { echo "PASS (none reproduced)"; exit 0; } || { echo "FAIL: $repro/$N reproduced"; exit 1; } ;;
	*) echo "usage: run_n.sh N [all|none] [--variant V ...]"; exit 3 ;;
esac
