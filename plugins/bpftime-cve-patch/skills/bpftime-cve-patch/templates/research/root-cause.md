# Root cause — <CVE-ID>

*Phase 2 output. Drives the PoC (Phase 3) and the patch (Phase 4).*

## Sink
- **File:function:** `<path/file.c>:<function>`  (the enclosing function of the removed/pre-image lines in the fix diff)
- **Built target binary path:** `target/<...>/<binary>`  ← the loader's `TARGET_BINARY`/`TARGET_FUNC` and the Phase 5 deploy MUST use this exact binary (the patch uses a bare `SEC("uprobe")`; the loader picks the target)
- Vulnerable function signature: `<ret> <function>(<args>)`  ← match this in `patch.bpf.c` `BPF_UPROBE(patch_entry, ...)`

## Bug class
- CWE-<XXX>: <name>. The fix ADDS: <bounds check | overflow-safe multiply | NULL/type check | realpath/'..' reject | ...>

## Invariant (what the patch enforces)
- The exploit violates: **<the exact condition the guard checks>**.
- The patch fires (skips/replaces the call) iff: `<condition on args / target memory>`.

## Reachability
- Entry point (attacker-controlled): `<public API / parser / network / CLI / env>` → ... → sink.
- Configuration gating: <build flag / config directive / runtime mode required — see findings.md>

## Detector for the PoC (Phase 3)
- MODE: <crash | dos | sentinel | instrument>; exact signal/ASan class, sentinel token, or (instrument, for NON-CRASHING corruption) the observe-probe would-block verdict: `<...>`
