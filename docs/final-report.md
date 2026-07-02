# Final report — autonomous runtime-mitigation framework

**One-page report.** For the system design see [design.md](design.md); for
architecture and the environment see [architecture.md](architecture.md) and
[devcontainer.md](devcontainer.md).

## Motivation for the project

Automated tooling — LLMs above all — now finds and analyzes vulnerabilities faster
than fixes reach the machines that run the code. A flaw can be public knowledge
while an installable update is still weeks or months out: upstream patch →
maintainer release → distro packaging → deployment.
[CVE-2026-31431](https://copy.fail/) ("Copy Fail") is a recent case: the mainline
fix landed within days of the report, but rolling an installable update across
every affected distro and kernel is the slow, still-trailing tail.

**The thesis:** an autonomous agent can take a vulnerability all the way to a
*proven* runtime mitigation, fast enough to matter in that window. Given a CVE (or a
write-up, advisory, or scanner output), the agent builds a PoC that reproduces the
flaw, then a bpftime patch that provably blocks it, with no rebuild or restart. That
patch is a bridge you could push across a fleet to hold the line until the upstream
fix ships. Proving it works is the hard part, and the whole point: without a bug you
can reproduce on demand, there is no way to know a runtime patch does anything at
all. That is why verification is wired into every step (see below).

Why these choices: bringing eBPF-style runtime patching to **userspace** is the
whole angle, and **bpftime** is the mature way to do it — its hooking suite
(override, replace, ufunc, probe-write) makes in-process enforcement practical
without hand-building injection machinery. Userland is the demo target because it's
trivial to sandbox in Docker; neither choice is fundamental, and the approach isn't
userland-specific.

## Approach to testing & validation

The central risk is a patch nobody proved works, so validation is baked into the
pipeline rather than bolted on:

- **Objective reproduction oracle.** The vulnerable target is built with ASan/UBSan
  (`-fno-sanitize-recover=all`), so a sanitizer report at the sink is ground truth;
  a second non-ASan build (the one the patch attaches to) stays deterministic via
  `MALLOC_CHECK_=3` → `SIGABRT`. `run.sh` exits 0 = exploited, keyed on the
  *specific* sanitizer class at the sink.
- **Negative control.** The identical harness must report *not* exploited on benign
  input. That proves the oracle keys on the trigger, not the harness or config, so
  no separate "fixed" build is needed to establish falsifiability.
- **A/B/C + control matrix (the gate).** A: unpatched + PoC → exploited every run.
  Control: unpatched + benign → golden baseline. B: patched + PoC (plus variants) →
  blocked every run. C: patched + benign → matches baseline exactly. The run passes
  only if every cell is green; a patch that blocks the PoC but fails Cell C or a
  variant gets kicked back, not shipped.
- **Anti-overfitting sweep.** A conditional guard is re-tested against root-cause
  *variants*, all driven through the one `exploit.py`, so it can't degrade into a
  signature for the sample bytes.
- **Pre-flight + end-to-end.** `smoke.sh` checks shell syntax, `exploit.py`
  subcommands, and patch builds across technique × mode (including observe ≠
  enforce). Attach success is asserted explicitly (bpftime returns a positive fd),
  since a silent attach failure leaves the app exposed while benign tests still
  pass. The full pipeline was validated end-to-end primarily on **CVE-2026-42945**
  (nginx, "rift") — the main real-CVE run given time constraints — plus a synthetic
  non-crashing harness; see [example-cve-2026-42945.md](example-cve-2026-42945.md)
  to reproduce it.

## Areas for improvement (more time / compute)

- **Broader CVE coverage.** Validation centered on one real CVE (CVE-2026-42945)
  due to time. Exercising more bug classes, more targets, and the full technique
  taxonomy is the highest-value next test.
- **Kernel-space targets** via kernel eBPF/LSM — the natural next step beyond the
  userland demo.
- **More advanced patching.** The framework handles fairly simple vulns today. It
  should grow to cover harder bug classes: multi-condition logic, multithreaded and
  race bugs, and vulns whose fix isn't a single localized change.
- **Broader oracle library.** Lean on bpf itself to instrument the binary further
  and catch non-memory bugs beyond the ASan/malloc default.
- **Better PoC generation.** The PoC logic is pretty basic right now, just enough
  to demonstrate the verification loop. Ideally a more advanced agent would replace it.
- **Fleet-wide deployment.** In the future this could push hot-patches to thousands
  of machines in near real time.

## Commentary on the building process

- **bpftime is fragile and load-bearing.** Success is a *positive* fd (0 is not
  failure), stale `/dev/shm` state fails the attach with `EBADF`, and small rewrites
  of the loader/build broke attachment in testing. That's why the scaffold is a
  verified template the agent fills in rather than hand-rolls.
- **Upstream patches are messy.** They span multiple commits and are often poorly
  documented, so pinning down exactly what "the fix" is took real digging.
- **Reproducing the target config was the real headache.** Automatically standing up
  the vulnerable configuration so the PoCs could run against it caused most of the
  pain in the whole pipeline.
