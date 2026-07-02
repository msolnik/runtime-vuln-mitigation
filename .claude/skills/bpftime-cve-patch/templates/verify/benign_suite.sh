#!/usr/bin/env bash
# Cell C / control: exercise the target's LEGITIMATE behavior on the hooked code
# path, under the SAME config as the exploit run. exit 0 = benign behavior OK.
#
# Use the app's own smoke/regression tests plus representative real workloads that hit the
# patched function with benign inputs. Compare outputs/exit codes (and, for hot paths,
# latency) to the unpatched baseline — any deviation UNDER THE PATCH is a false positive.
#
# Patched (Cell C) vs unpatched (Control) is expressed the SAME way as the oracle: the
# matrix exports AGENT_PRELOAD for the patched run, so the exact process here is the hooked
# one. Benign input comes from the ONE driver (`exploit.py --variant benign`) so it stays a
# true negative control of the same code path — add the app's real smoke tests alongside.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET="${TARGET:-$HERE/../target/noasan/target_app}"   # NON-ASan build (matches the matrix)
POC_DIR="${POC_DIR:-$HERE/../poc}"

# Representative benign input on the hooked path (single-source driver).
python3 "$POC_DIR/exploit.py" gen --variant benign --out "$POC_DIR/benign.bin" 2>/dev/null || true

# Run it under the agent when the matrix asks (patched cell), else bare (control baseline).
if [ -n "${AGENT_PRELOAD:-}" ]; then
	env LD_PRELOAD="$AGENT_PRELOAD" "$TARGET" "$POC_DIR/benign.bin" > benign.out 2>&1
else
	"$TARGET" "$POC_DIR/benign.bin" > benign.out 2>&1
fi
rc=$?

# TODO: replace/extend with the app's real smoke tests + expected-output assertion.
if [ "$rc" -eq 0 ] && grep -q "EXPECTED_OK_MARKER" benign.out; then
	echo "benign OK"; exit 0
else
	echo "benign BROKEN (rc=$rc) — patch is over-blocking (or fix the EXPECTED_OK_MARKER assertion)"; exit 1
fi
