#!/usr/bin/env bash
# State preconditions to make the vulnerable path reachable (see Phase 3 step 2).
# Some sinks need prior state (e.g. the Redis xgroup bug needs a non-stream key
# to exist first). Script that here so the PoC and the negative control run
# against identical state. Runs before the oracle. No-op by default.
set -eu

# Example: seed a config-selected feature / create prerequisite state.
#   cp target.conf ../target/run.conf
#   ../target/target_app --config ../target/run.conf --create-object foo
:
