# Plugin architecture — `runtime-vuln-mitigation`

How the plugin is built: its components, the agent-orchestration model, the data
that flows between phases, the patch mechanism, and the verification model that
lets it claim a patch actually works. For *why* it is shaped this way, see
[design.md](design.md); for the environment it runs in, see
[devcontainer.md](devcontainer.md).

The plugin turns a **userspace CVE or bug write-up** into a **tested bpftime
virtual patch**: it researches the flaw, reproduces it with a proof-of-concept,
authors an eBPF program that neutralizes it in-process, and verifies the exploit
is blocked without breaking the app — autonomously, inside the devcontainer.

---

## 1. System context

Four layers, from outermost in:

```
┌─ marketplace  (.claude-plugin/marketplace.json — "msolnik-tools")
│  └─ plugin    (plugins/runtime-vuln-mitigation/.claude-plugin/plugin.json)
│     └─ skill  (skills/runtime-vuln-mitigation/SKILL.md + references + templates + tests)
│        └─ runs inside → devcontainer  (prebuilt bpftime toolchain, fixed paths)
└─ produces → work/<CVE-ID>/  (all artifacts, in the user's project dir, git-ignored)
```

- The **marketplace** is a thin manifest that lists one installable plugin.
- The **plugin** is a manifest + a single skill. It carries no hooks, commands,
  agents, or MCP servers — all behavior lives in the skill.
- The **skill** is the engine: a `SKILL.md` procedure plus progressive-disclosure
  `references/`, copy-and-fill `templates/`, and a `tests/smoke.sh` guardrail.
- The **devcontainer** is a hard runtime dependency: it installs the bpftime
  toolchain into the exact fixed paths the skill's templates hard-code, so the
  pipeline needs no per-run environment setup and no bpftime source tree.

## 2. Component layout

```
plugins/runtime-vuln-mitigation/
├── .claude-plugin/plugin.json          # manifest: name, description, keywords
├── README.md                           # user-facing overview
└── skills/runtime-vuln-mitigation/
    ├── SKILL.md                        # the procedure: principles + 6-phase pipeline
    ├── references/                     # progressive disclosure — loaded on demand
    │   ├── vulnerability-research.md   #   sources, fixing-commit convergence, bug-class heuristics
    │   ├── poc-reproduction.md         #   pinning, sanitizers, the boolean oracle, negative control
    │   ├── bpftime-patch-cookbook.md   #   attach types, technique taxonomy, build/deploy
    │   └── patch-verification.md       #   A/B/C+control matrix, anti-overfitting, CI gate
    ├── templates/                      # copy-and-fill scaffolds (copied INTO work/, never edited in place)
    │   ├── research/  poc/  patch/  verify/  report/
    └── tests/smoke.sh                  # fast pre-flight: syntax + technique×mode builds
```

**Design of the skill body.** `SKILL.md` states seven load-bearing principles up
front, then a table-driven 6-phase pipeline, then a large
"rationalizations to reject" table that pre-empts the specific shortcuts that
have historically produced false results. The references are deliberately *not*
inlined — they load only when a phase reaches for them, keeping the
orchestrator's context lean. Templates are the verified, load-bearing artifacts;
the skill's stance is **copy the scaffold and fill the TODOs, never hand-roll**
(small rewrites of the attach/build path broke attachment in testing).

## 3. Orchestration model

The skill runs as a **main orchestrator agent** that delegates the expensive or
noisy phases to **subagents with fixed counts** — the fan-out never scales with
the size of the target codebase.

```
main orchestrator (holds pipeline state, owns the decision gate)
│
├─ Phase 1  → 3 parallel subagents  (advisory · fix-commit · reachability/config)
├─ Phase 3  → 1 isolated subagent   (build + PoC + negative control)
├─ Phase 4  → 1 isolated subagent   (author + build + attach + first block-check)
└─ Phase 5  → (optional) 1 isolated subagent runs the matrix; the GATE stays on main
```

Two reasons for this split:

- **Context hygiene** — Phases 3/4 generate heavy build/debug churn. Running them
  in isolated subagents keeps that out of the orchestrator, which only receives a
  structured pass/fail summary plus artifact paths.
- **Determinism** — fixed subagent counts (exactly 3 research, 1 PoC, 1 patch)
  mean orchestration cost is bounded regardless of target.

Every subagent gets a specific target, an explicit task, the agent type
(`general-purpose`), and a **structured return contract** — e.g. the PoC subagent
must return `{asan_bin, noasan_bin, run_sh_mode, reproduces, control_passes,
artifact_paths[], …}`. The decision gate (Phase 5) is never delegated: only the
main agent decides pass/fail.

## 4. The pipeline and its data flow

Six phases run in order; each reads and writes known locations under
`work/<CVE-ID>/` so subagents, the negative control, and the verification runs
all agree on where source, binaries, and configs live.

| Phase | Reads | Produces | Runs as |
|-------|-------|----------|---------|
| 0 · Intake & Setup | CVE id / write-up | work dir, normalized id, toolchain check | main |
| 1 · Research | CVE id | `research/findings.md` (advisory + fix diff) | 3 parallel subagents |
| 2 · Root-Cause | findings + fix diff | `research/root-cause.md` (sink, CWE, invariant, config, target binary path) | main |
| 3 · Reproduce | root-cause | `poc/` (`exploit.py`, `run.sh` oracle, `target.conf`), `target/{asan,noasan}/` | isolated subagent, loop ≤3 |
| 4 · Patch | root-cause + PoC | `patch/` (`patch.bpf.c`, loader, Makefile, deploy) | isolated subagent, loop ≤3 |
| 5 · Verify | patch + PoC | `verify/results.md` (A/B/C + control matrix) | main (mechanics optionally delegated) |
| 6 · Report | everything | `work/<CVE-ID>/REPORT.md` | main |

The artifact tree is the integration contract between phases:

```
work/<CVE-ID>/
├── research/   findings.md, root-cause.md
├── target/     asan/  (PoC reproduction oracle)   noasan/  (patch attach + verify)
├── poc/        exploit.py (single source of truth), run.sh / run_server.sh oracle, target.conf
├── patch/      patch.bpf.c, patch_loader.c, attach_override.h, ufunc.bpf.h, Makefile, deploy.sh
├── verify/     verify_matrix.sh, benign_suite.sh, results.md
└── REPORT.md
```

## 5. Working-directory contract

Two roots that must never be confused:

- **`{baseDir}`** — the skill's own directory. When installed as a plugin this is
  `${CLAUDE_PLUGIN_ROOT}/skills/runtime-vuln-mitigation`, which is **read-only and
  shared across projects**. Templates are copied *out of* it; nothing is ever
  written *into* it.
- **`work/<CVE-ID>/`** — every generated artifact, created under the user's
  current project directory (git-ignored). Nothing the skill produces is ever
  written under `{baseDir}` or any `.claude/` directory.

This separation is what makes the plugin safe to install once and run against
many CVEs from many projects without cross-contamination.

## 6. The two-build model

Phase 3 builds the **same vulnerable version + config twice**:

- **`target/asan/`** — `-fsanitize=address,undefined -fno-sanitize-recover=all -g`,
  used as the **PoC reproduction oracle** (a sanitizer report at the sink is
  ground truth that the bug fired).
- **`target/noasan/`** — a plain `-g` build, used for **patch attach and
  verification**, because the bpftime agent's `LD_PRELOAD` clashes with the ASan
  runtime. On this build the crash oracle is signal-based (`MALLOC_CHECK_=3`
  turns heap corruption into a deterministic `SIGABRT`).

The loader's `TARGET_BINARY` must reference the exact `noasan` binary the PoC
exercised — a patch attached to a different build silently protects nothing.

## 7. The patch model

bpftime injects an eBPF program into the target process (`LD_PRELOAD` at start,
or Frida into a running PID) so it runs **in-process** on the target's own calls
and syscalls.

```
        target process (unmodified binary)
   call vuln_fn(args) ──▶ [bpftime uprobe/override hook]
                              │  read args + target memory (in-process)
                              │  optionally call the app's own validator via ufunc
                              ├─ invariant holds  ──▶ run original function (benign)
                              └─ invariant violated ─▶ bpf_override_return(safe) — original SKIPPED
```

**Attach types** (from the cookbook): `UPROBE_OVERRIDE` (perf type **1008**) is
the primary mechanism — the program runs before the function and, if it calls
`bpf_override_return`, the original is skipped. `UREPLACE` (1009) always replaces.
A bare `SEC("uprobe")` string is used; the override behavior comes from the
loader's attach, not the SEC name.

**Technique taxonomy** — set via `PATCH_TECHNIQUE` in the Makefile, threaded to
both `patch.bpf.c` and `patch_loader.c` so the eBPF side and the attach path
always agree on override-vs-plain-uprobe:

| Technique | Fix shape it mirrors | Mechanism |
|-----------|----------------------|-----------|
| 1 — conditional override | skip/deny a call on bad input | `bpf_override_return` under 1008 |
| 2 — full replace | always return a synthesized safe value | `ureplace` (1009) |
| 3 — state reset | one-liner that clears a flag / fixes a size | `bpf_probe_write_user` at a pahole offset, **plain uprobe** |
| 4 — ufunc-backed | re-run the app's own validator | `ufunc` call by name |
| 5 — detect-and-neutralize | bounds check / non-crashing OOB | compute `need` vs `capacity`; override when OOB, or clamp a memory-backed size |
| (syscall) | deny a dangerous syscall | syscall tracepoint + override — **x86_64 only** |

**Hard constraints** the patch is designed around: you *cannot* rewrite a
scalar/register argument (pt_regs is a copy — you can only skip/replace the call
or mutate memory a pointer arg points to), and enforcement is *process-scoped*,
never kernel-wide. On aarch64, syscall-tracepoint hooking is unavailable, so a
uprobe-override on the function is mandatory.

**`PATCH_MODE` — observe vs enforce.** The *same* program builds two ways.
`observe` evaluates the invariant, emits a `would-block` ring-buffer verdict, and
does **not** act — used for staged rollout and, crucially, as a **detector for
non-crashing corruption** (the verdict is the oracle in Phase 3's
`MODE=instrument`). `enforce` runs the same invariant but acts. Both emit the rich
event (`invariant_id/verdict/observed/bound`), so a single build flag flips
detect ↔ neutralize. The Makefile treats the mode as a rebuild dependency and
**errors** on a typo rather than silently falling through to `enforce`.

## 8. Verification model

A patch is only "done" when four cells are green, run against the `noasan` build,
all reusing the **one** exploit oracle from `poc/run.sh`:

| Cell | Setup | Required result |
|------|-------|-----------------|
| A | unpatched + PoC (×N) | exploited every run |
| Control | unpatched + benign suite | golden baseline recorded |
| B | patched + PoC (×N + variants) | blocked every run; block logged |
| C | patched + benign suite | matches baseline exactly (no false positives) |

Two integrity properties are enforced structurally:

- **Single source of truth for the exploit.** `poc/exploit.py` owns payload
  generation, wire delivery (raw socket, not curl), and a **variant registry**.
  Phases 4 and 5 reuse it unchanged — no phase writes a second payload generator
  or sender. This killed a real regression where one bug grew three overlapping
  payload scripts and a curl sender that URL-encoded the trigger away.
- **Anti-overfitting by patch shape.** A *conditional guard* (technique 1/2/5)
  gets the full variant sweep — the same root-cause-equivalent triggers already
  declared in `exploit.py`, run through the same oracle — so it can't overfit to
  the literal exploit bytes. An *unconditional* sanitize/state-reset (technique 3,
  reads no input) can't overfit by construction, so it makes a structural argument
  instead of a fuzz sweep.

The decision gate stays with the main agent: pass only if A=exploited,
B=blocked (incl. variants), C=matches baseline, control=stable.

## 9. Reliability mechanisms

- **Bounded retry + escalation.** Phases 3 and 4 are the fragile ones. Phase 3
  retries ≤3. Phase 4 shares **one** budget of 3 attempts with the Phase-4↔5
  kickback loop, tracked by a named `patch_attempt` counter persisted via
  `TaskUpdate` so a mid-loop context compaction can't lose the count. On
  exhaustion the skill **stops and escalates** via `AskUserQuestion` (continue
  best-effort / abort / take guidance).
- **No faked greens.** A patch that does not verifiably block the PoC is never
  reported as done — escalate instead. This is the skill's central integrity rule.
- **Attach assertion.** bpftime returns a *positive fd* on successful attach (not
  0), and a silent attach failure leaves the app exposed while benign tests still
  pass — so attachment is asserted explicitly, not inferred from Cell C.
- **Verify-before-trust research.** Recent-CVE research can be wrong or
  hallucinated; the fixing commit is confirmed by fetching the `.patch` directly,
  with 3-subagent convergence as the corroboration bar.
- **Smoke guardrail.** `tests/smoke.sh` is the cheap pre-flight after any template
  edit: shell syntax, `exploit.py` subcommands, patch builds across
  technique × mode, and a check that `observe` produces a *different* object than
  `enforce` (and that a bad `PATCH_MODE` fails safe).

## 10. Runtime environment dependency

The skill's templates hard-code the devcontainer's fixed install paths — `bpftime`
and the injectable libs in `/usr/local/bin`, `bpftool` + prebuilt libbpf under
`/usr/local/bpftool/`, and kernel BTF at `/sys/kernel/btf/vmlinux` (the Makefile
generates `vmlinux.h` from it). This is a deliberate coupling: no bpftime source
tree is needed at runtime, and the pipeline works with zero per-run setup. Running
the plugin outside this environment requires reproducing those paths. See
[devcontainer.md](devcontainer.md).

## 11. Trust boundaries & scope

- The patch runs **in-process, inside the target's address space** — full trust
  within that process, no privilege boundary crossed beyond what injection
  requires (`NET_ADMIN`/`NET_RAW` caps are for server targets and raw-socket PoC
  delivery, not for the patch itself).
- Patches are **mitigations, not fixes**: coupled to the target's binary layout
  and offsets, on a pre-1.0 runtime. Every `REPORT.md` documents binary-layout
  coupling, TOCTOU exposure, and residual risk, and recommends the upstream fix
  as the durable remedy.
- **Out of scope** (enforced by the skill's "When NOT to use"): kernel-space CVEs,
  producing an upstream source fix/PR, general eBPF tracing, and discovering
  unknown bugs.
