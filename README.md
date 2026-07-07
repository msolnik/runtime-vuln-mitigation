# runtime-vuln-mitigation

A local [Claude Code plugin marketplace](https://docs.claude.com/en/docs/claude-code/plugins) that ships one plugin — [`runtime-vuln-mitigation`](plugins/runtime-vuln-mitigation/) — together with a devcontainer that pre-builds the entire [bpftime](https://github.com/eunomia-bpf/bpftime) userspace-eBPF toolchain it depends on.

The plugin turns a **userspace CVE or bug write-up** into a **tested bpftime runtime mitigation** (a "virtual patch"): it researches the flaw, reproduces it with a proof-of-concept, authors an eBPF program that neutralizes it in-process, and verifies the exploit is blocked without breaking the app — end to end, autonomously.

> Virtual patch = a hook injected into the running process that enforces the same invariant the upstream fix adds, *without* recompiling or restarting the target. It is a **mitigation**, not a replacement for the upstream fix.

> **Testing status:** This is a prototype. It has been exercised end-to-end **primarily** against a single target — **nginx / [CVE-2026-42945](docs/example-cve-2026-42945.md)** ("rift"). Other CVEs, bug classes, and targets are expected to work but are much less exercised; treat anything beyond that primary case as experimental.



## What's in this repo


| Path                                                                   | Purpose                                                                                            |
| ---------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| [`.claude-plugin/marketplace.json`](.claude-plugin/marketplace.json)   | Marketplace manifest (`msolnik-tools`) listing the plugin                                          |
| [`plugins/runtime-vuln-mitigation/`](plugins/runtime-vuln-mitigation/) | The plugin — see its [README](plugins/runtime-vuln-mitigation/README.md)                           |
| [`.devcontainer/`](.devcontainer/)                                     | Devcontainer that builds & installs the bpftime toolchain — [full setup doc](docs/devcontainer.md) |
| `work/<CVE-ID>/`                                                       | Where the plugin writes all its artifacts (git-ignored)                                            |




## Quick start



### 1. Bring up the devcontainer

The plugin runs its whole pipeline (build, PoC, deploy, verify) *inside* a container that already has the toolchain. It is based on Trail of Bits' [`claude-code-devcontainer`](https://github.com/trailofbits/claude-code-devcontainer) (`devc`):

```sh
devc up       # start the devcontainer
devc shell    # open a shell inside it
```

(Or use the raw devcontainer CLI: `devcontainer up --workspace-folder .`.)

The container is launched with `--cap-add=NET_ADMIN --cap-add=NET_RAW` (needed for server/daemon targets) and installs, into fixed locations the plugin relies on (full breakdown in [docs/devcontainer.md](docs/devcontainer.md)):

- `bpftime`, `bpftimetool`, `libbpftime-*.so` in `/usr/local/bin`
- `bpftool` + prebuilt libbpf (`include/`, `libbpf.a`) under `/usr/local/bpftool/`
- `clang` / `llvm`, and `dwarves` (`pahole`, for struct-field offsets)
- kernel BTF at `/sys/kernel/btf/vmlinux` (used to generate `vmlinux.h`)

No bpftime *source tree* is needed at runtime — the plugin uses the installed binaries and prebuilt libbpf.

### 2. Install the plugin

From inside a Claude Code session in this repo:

```
/plugin marketplace add .
/plugin install runtime-vuln-mitigation@msolnik-tools
```



### 3. Use it

Give Claude a CVE id or a userspace bug write-up:

```
Build a bpftime virtual patch for CVE-2026-42945.
```

The plugin runs the 6-phase pipeline and drops every artifact — research, PoC, patch, verification, and a `REPORT.md` — under `work/<CVE-ID>/`.

See the [plugin README](plugins/runtime-vuln-mitigation/README.md) for the pipeline, capabilities, and scope (what it does **not** do — e.g. kernel-space CVEs).

For a step-by-step run, see the worked example: [docs/example-cve-2026-42945.md](docs/example-cve-2026-42945.md).

