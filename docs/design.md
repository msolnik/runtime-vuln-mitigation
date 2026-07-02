# Design doc — autonomous runtime-mitigation framework

**One-page design rationale: how the system is built and why.** Component-level
detail is in [architecture.md](architecture.md), the runtime is in
[devcontainer.md](devcontainer.md), and the motivation for the project plus how it
was validated are in [final-report.md](final-report.md).

## Overview

The system takes a known userspace vulnerability (a CVE, a bug write-up, an
advisory, or scanner output) and produces a tested bpftime runtime mitigation. It
works in two verified steps. First it builds a PoC that objectively reproduces the
flaw on the unpatched app. Only then does it write the mitigation (an eBPF program
injected into the running process that enforces the upstream fix's invariant) and
confirm that the same PoC no longer fires while benign behavior stays intact. No
rebuild, no restart. The verified PoC is what makes the patch trustworthy: without
a bug you can reproduce on demand, a runtime patch is just a guess. Together they
cover the window between public disclosure and an installable downstream fix.

The project is also a bet on the agent itself. The goal is to show an autonomous
agent can own that whole arc, from a CVE to a validated PoC to a runtime patch,
and hand back a mitigation you could push across a fleet to hold the line until
the upstream fix ships. What follows is how it's built and why.

## Architecture at a glance

Three shipped pieces, one flow: a marketplace ships one plugin (a single skill)
that runs inside a devcontainer and writes all its artifacts under `work/<CVE-ID>/`.

```
6-phase pipeline: research → root-cause → reproduce (PoC) → patch → verify → report
```

A main orchestrator agent drives the pipeline and owns the pass/fail gate. It hands
the noisy, failure-prone phases to a fixed number of isolated subagents (3 for
research, 1 for the PoC, 1 for the patch). The counts are fixed on purpose:
isolation keeps the heavy build and debug churn out of the orchestrator's context,
and a fixed shape keeps runs deterministic and reproducible instead of ballooning
with the size of the target. The devcontainer prebuilds the bpftime toolchain into
fixed paths, so there's zero per-run setup.

Splitting the work across distinct agents is a modularity choice, not just a
context one. Each phase is a self-contained agent with a defined input/output
contract: research hands root-cause facts to the PoC agent, the PoC agent hands a
verified reproducer to the patch agent, and so on down the line. Because the seams
are explicit, any single stage can be upgraded or replaced on its own without
rewiring the pipeline (see Scope & extensibility).

## Key design decisions

Two problems sit at the center: prove the bug is real, and generate a patch that
neutralizes it. The rest is the verification that keeps both steps honest.

### Proving the bug (reproduction & the ASan oracle)

1. **Reproduce before you patch.** No patch gets written until a PoC objectively
   fails on the unpatched app and a benign control passes. A patch you can't
   falsify is worthless; this is the step that turns "looks fixed" into "proven
   fixed."
2. **Build the target twice.** Both builds use the same vulnerable version and config
   but do different jobs. The ASan/UBSan build is the reproduction oracle, since a
   sanitizer report at the sink is ground truth. A plain `-g` build is what the patch
   attaches to, because bpftime's injected agent (`LD_PRELOAD`) clashes with the ASan
   runtime; on that build the oracle stays deterministic through `MALLOC_CHECK_=3` →
   `SIGABRT`. The oracle itself is a drop-in slot (sanitizer, sentinel, timeout, or
   observe-probe, depending on the bug class), but ASan and malloc guards are the
   default because they're objective.
3. **Tie the oracle to the bug, not just any crash.** `run.sh` reports the exploit
   as reproduced (exit 0) only when it sees the *specific* sanitizer class at the
   sink, so a stray crash or a flaky harness doesn't count. The benign negative
   control on the same build is the proof: it has to come back clean, which shows the
   signal tracks the vulnerability itself and not the test setup. Because the oracle
   is that precise, no separate "fixed" build is needed to establish falsifiability.
4. **Derive the exploit from the fix diff, not a public PoC.** The PoC is the
   minimal input that violates the quantity the upstream fix guards. Understanding
   the mechanism, rather than copying weaponized bytes, is what later makes
   root-cause variants possible for anti-overfitting.

### Generating the patch

5. **Patch the invariant, not the bytes.** The guard mirrors the condition the
   upstream fix adds, not the sample exploit, and a variant sweep proves trivial
   mutations don't slip past it. Where it can, it re-runs the app's own validator
   instead of re-implementing the check.
6. **Match the patch to the fix's shape.** A small technique taxonomy maps each fix
   pattern to a mechanism: conditional **override** (skip the call on a bad
   condition), full **replace** (synthesize a safe return), **state-reset** (write a
   struct field at a pahole-derived offset, mirroring a one-line fix), **ufunc**
   (call the app's own validator), and **detect-and-neutralize bounds** (compute
   need against capacity, then override or clamp when it's out of range).
7. **Design within bpftime's real constraints.** In-process eBPF can skip or replace
   a call and mutate memory that a pointer argument points to. It cannot rewrite a
   scalar/register argument (pt_regs is a copy), and it's process-scoped, never
   kernel-wide. So the technique follows from what's actually possible at the hook,
   not from whatever the source fix happens to look like.
8. **Observe or enforce from one program.** A single build flag flips the same
   invariant between a log-only detector (for staged rollout, and the only way to
   catch non-crashing corruption before it happens) and active neutralization.
   Detection and enforcement can't drift apart, because they're the same code.

### Keeping it honest (verification)

9. **One exploit, reused everywhere.** A single parametrized `exploit.py` (payload,
   raw-socket delivery, variant registry) is the source of truth across reproduce,
   patch, and verify. This closed a real regression where duplicate scripts and a
   URL-encoding curl sender quietly masked the trigger.
10. **Fail loud, never fake green.** The fragile phases retry within a bounded,
    compaction-safe budget and then escalate. A patch that doesn't verifiably block
    the PoC across variants, with benign behavior intact, is never reported as done.

**Engineering guardrails.** The plugin ships its own devcontainer, with the bpftime
toolchain pinned at fixed paths, so it's portable and reproducible with zero per-run
setup. The brittle bpftime build/attach path is a template verified on x86_64 and
aarch64 that agents fill in rather than hand-roll.

## Scope & extensibility

- **Userland first, by choice.** It's easy to sandbox and demo in Docker. The
  reproduce → patch → verify loop isn't userland-specific, though; kernel targets
  via kernel eBPF are the obvious next step.
- **Swappable stages.** Because each phase is a separate agent behind a fixed
  contract, pieces upgrade independently: a more advanced PoC generator, an input
  front-end that takes scanner output or a raw write-up instead of a CVE id, or new
  patch techniques, none of which touch the rest of the pipeline.
- **bpftime as the substrate.** This is a deliberate bet, not just convenience: the
  whole angle is bringing eBPF-style runtime patching to userspace, and bpftime is
  the mature way to do it. Its hooking suite (override, replace, ufunc, probe-write)
  is what makes the techniques above practical without us building the injection
  machinery from scratch.
