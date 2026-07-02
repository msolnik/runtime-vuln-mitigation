# bpftime virtual patch — <CVE-ID>

## Summary
- Vulnerability: <CVE-ID>, <product> <affected range>, <CWE / bug class>.
- Mitigation: a bpftime uprobe-override patch on `<binary>:<function>` that <blocks/short-circuits the exploit condition>.
- Status: **verified** — exploit blocked, benign behavior intact (see Verification).

## Root cause
- Sink: `<file:function>`; invariant the exploit violates: `<...>`.
- Fixing commit: <repo>@<sha>. Introduced-in: <sha>.
- Required configuration to reach the path: <...>.

## Proof-of-concept & exploitation method
- Build: <exact vulnerable version + sanitizer/detector>. Config: `poc/target.conf` (the enabling
  config was learned from the public PoC/advisory; the exploit itself was derived from the fix diff).
- **Exploit mechanism** (`poc/exploit.py explain` verbatim): <how the guarded quantity is violated —
  the causal chain from attacker input to the sink; e.g. length/copy desync where escaped bytes
  expand past a raw-sized buffer>.
- **PoC driver:** `poc/exploit.py` is the single source of truth — `gen` emits the payload, `send`
  delivers exact wire bytes over a raw socket, `variants` lists the root-cause-equivalent triggers.
- Reproduce: `cd poc && ./run.sh` (file/CLI) or `./run_server.sh` (server) — exit 0 = exploited.
  Negative control (`--variant benign`, same build + config) reports not-exploited.
- **Anti-overfitting variants** (all hit the same invariant): <list from `exploit.py variants`, with
  the one-line reason each is root-cause-equivalent>.

## The bpftime patch
- Technique: <conditional override(1) | replace(2) | state-mutation/sanitize(3) | ufunc-backed(4) | detect-and-neutralize bounds(5)>; mode: <enforce | observe>.
- Hook: `SEC("uprobe")` on `<binary>:<function>`, attached with the OVERRIDE type (1008); `bpf_override_return` skips the vulnerable path when `<invariant>`.
- Build & deploy: `cd patch && make && ./deploy.sh preload <target>` (details in patch/).

## Verification (A/B/C + control)
*(quote verify/results.md)*
- A unpatched+PoC: exploited. Control unpatched+benign: baseline.
- B patched+PoC (+variants): blocked. C patched+benign: matches baseline.

## Assumptions & residual risk
- **Binary-layout coupling:** the patch reads args/offsets of the specific build; a recompile/upgrade can break it — re-validate on the target build.
- **Process-scoped:** bpftime patches a userspace process (LD_PRELOAD/inject), not kernel-wide; must be injected into every target instance.
- **Arch:** uprobe-override works on x86_64 and aarch64. (bpftime syscall-tracepoint filtering is x86_64-only.)
- **TOCTOU:** in multithreaded targets, an argument can change between the check and use.
- **bpftime is pre-1.0** — treat as a mitigation. The durable fix is upgrading to the patched version (<fixed>).
