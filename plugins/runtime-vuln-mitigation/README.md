# runtime-vuln-mitigation

> Turn a userspace CVE into a **tested [bpftime](https://github.com/eunomia-bpf/bpftime) runtime mitigation** — researched, reproduced, patched, and verified end to end.

A Claude Code plugin that packages the [`runtime-vuln-mitigation` skill](skills/runtime-vuln-mitigation/SKILL.md). Give it a CVE id or a bug write-up for a **userspace** program or library and it produces a **virtual patch**: an eBPF program that bpftime injects into the target process to enforce, at runtime, the same invariant the upstream fix adds — proving the exploit is blocked while benign behavior stays intact.

## When it triggers

Invoke it when you want a **verified** runtime mitigation for a *known* userspace vulnerability:

- You have a CVE id (e.g. `CVE-2019-12735`) or a bug write-up for a userspace app/library.
- The vulnerable path is reachable at a userspace function or a syscall the target makes (memory corruption, logic, type confusion, injection, traversal, DoS).
- You need it *verified* — exploit blocked **and** benign behavior intact — not just written.

**Not for:** kernel-space CVEs · producing the upstream source fix / a PR · general eBPF tracing or observability · discovering unknown bugs (fuzzing). See [SKILL.md → When NOT to Use](skills/runtime-vuln-mitigation/SKILL.md#when-not-to-use).

## Example

```
> Build a bpftime virtual patch for CVE-2019-12735.
```

Claude runs the pipeline autonomously and reports back with a summary and the artifact location (`work/CVE-2019-12735/`), including a self-contained `REPORT.md`.

## The pipeline

Six phases, run in order. The fragile phases (reproduce, patch) retry with a bounded budget and then escalate rather than fake a result.

| Phase | Produces | Runs as |
|-------|----------|---------|
| 0 · Intake & Setup | work dir, normalized target id, toolchain check | main agent |
| 1 · Research | authoritative advisory data + the fixing commit/diff | 3 parallel subagents |
| 2 · Root-Cause | sink `file:function`, bug class (CWE), trigger invariant | main agent |
| 3 · Reproduce (PoC) | `run.sh` where exit 0 = exploited, + a negative control | isolated subagent |
| 4 · Patch | `patch.bpf.c` + loader that attaches cleanly and blocks the PoC | isolated subagent |
| 5 · Verify | A/B/C + control matrix, all green (incl. anti-overfitting variants) | main agent |
| 6 · Report | `REPORT.md` deliverable with assumptions & residual risk | main agent |

## How a patch neutralizes a vulnerability

bpftime injects an eBPF program into the target **in-process** (via `LD_PRELOAD` at start, or Frida into a running PID). The patch hooks the narrowest point where the vulnerability's precondition is decidable, checks the invariant, and short-circuits the dangerous path:

```
        target process (unmodified binary)
   call vuln_fn(args) ──▶ [bpftime uprobe/override hook]
                              │  read args + target memory (in-process)
                              │  optionally call the app's own validator via ufunc
                              ├─ invariant holds  ──▶ run original function (benign)
                              └─ invariant violated ─▶ bpf_override_return(safe) — original SKIPPED
```

**What a patch can and cannot do:**

| Capability | Mechanism |
|-----------|-----------|
| Skip / short-circuit the call | `bpf_override_return(ctx, rc)` |
| Replace the function entirely | `ureplace` |
| Mutate memory an arg points to | `bpf_probe_write_user(dst,src,len)` |
| Call the app's own functions | `ufunc` |
| Observe without acting (staged rollout / non-crashing bug detection) | `PATCH_MODE=observe` ring-buffer verdict |
| Rewrite scalar/register arg values | **not possible** (pt_regs is a copy) |
| Enforce kernel-wide | **not possible** (process-scoped) |

## Output layout

Everything lands under `work/<CVE-ID>/` in your project directory (git-ignored) — never inside the plugin:

```
work/<CVE-ID>/
├── research/     # findings.md (advisory + fix diff), root-cause.md (sink, CWE, invariant)
├── target/       # vulnerable source, built asan/ (PoC oracle) + noasan/ (patch attach/verify)
├── poc/          # exploit.py (single source of truth), run.sh oracle, target.conf
├── patch/        # patch.bpf.c, patch_loader.c, Makefile, deploy.sh (verified scaffold)
├── verify/       # verify_matrix.sh, benign_suite.sh, results.md
└── REPORT.md     # the deliverable
```

## Requirements

Designed to run inside the repo's devcontainer, which ships the bpftime toolchain in the fixed locations the skill expects (`bpftime` in `/usr/local/bin`, `bpftool` + libbpf under `/usr/local/bpftool/`, `clang`/`llvm`, `pahole`, kernel BTF). See the [repo README](../../README.md#quick-start) for setup.

## Learn more

| Doc | Content |
|-----|---------|
| [SKILL.md](skills/runtime-vuln-mitigation/SKILL.md) | The full pipeline, principles, and rationalizations-to-reject |
| [references/vulnerability-research.md](skills/runtime-vuln-mitigation/references/vulnerability-research.md) | CVE root-cause methodology |
| [references/poc-reproduction.md](skills/runtime-vuln-mitigation/references/poc-reproduction.md) | Building an objective, reproducible PoC |
| [references/bpftime-patch-cookbook.md](skills/runtime-vuln-mitigation/references/bpftime-patch-cookbook.md) | Authoring/building/deploying a bpftime patch |
| [references/patch-verification.md](skills/runtime-vuln-mitigation/references/patch-verification.md) | The A/B/C + control verification matrix |
| [templates/](skills/runtime-vuln-mitigation/templates/) | Copy-and-fill scaffolds (patch build verified on x86_64 + aarch64) |
