# Devcontainer & environment setup

The environment the [`runtime-vuln-mitigation`](../plugins/runtime-vuln-mitigation/) plugin runs inside. It pre-builds the entire [bpftime](https://github.com/eunomia-bpf/bpftime) userspace-eBPF toolchain and installs everything into the **fixed locations the skill relies on**, so the plugin's pipeline (build → PoC → deploy → verify) works with no per-run setup.

Base image: `mcr.microsoft.com/devcontainers/base:ubuntu24.04`. Definition lives in [`.devcontainer/`](../.devcontainer/).

## Bringing it up from scratch

You need a container runtime (Docker / Podman / OrbStack) and either VS Code or the devcontainer CLI.

This devcontainer is based on Trail of Bits' [`claude-code-devcontainer`](https://github.com/trailofbits/claude-code-devcontainer) (`devc`), so the quickest path is `devc up` then `devc shell` (equivalent to the VS Code / `devcontainer` CLI steps below).

**VS Code:** open the repo and run **Dev Containers: Reopen in Container**.

**CLI:**

```sh
npm install -g @devcontainers/cli   # if not already installed
devcontainer up --workspace-folder .
devcontainer exec --workspace-folder . bash
```

The first build compiles bpftime from source, so expect a few minutes on a cold build; it's cached afterward.

### Authentication

Claude Code auth is passed through from the host environment (see `remoteEnv` in [`.devcontainer/devcontainer.json`](../.devcontainer/devcontainer.json)). Set **one** of these on the host before launching:

```sh
export CLAUDE_CODE_OAUTH_TOKEN=...   # preferred; enables the onboarding bypass
# or
export ANTHROPIC_API_KEY=...
```

With `CLAUDE_CODE_OAUTH_TOKEN` set, [`post_install.py`](../.devcontainer/post_install.py) seeds the auth state and skips the interactive onboarding wizard.

## What gets installed (and why the plugin needs it)

### bpftime toolchain — the load-bearing part

Built from source ([`Dockerfile`](../.devcontainer/Dockerfile) `make release`) and placed where the skill's templates expect it:

| Location | Contents |
|----------|----------|
| `/usr/local/bin/` | `bpftime`, `bpftimetool`, `libbpftime-*.so` |
| `/usr/local/bpftool/` | `bpftool` + prebuilt libbpf (`include/`, `libbpf.a`) — the bootstrap build |
| `/sys/kernel/btf/vmlinux` | kernel BTF (the patch Makefile generates `vmlinux.h` from it) |

> No bpftime *source tree* is needed at runtime. The plugin's patch Makefile links the prebuilt `/usr/local/bpftool/libbpf/libbpf.a` and calls the installed `bpftime`/`bpftool` binaries. The CLI default `~/.bpftime` does **not** exist — the skill always passes `-i /usr/local/bin`.

### Build & analysis tooling

`clang`, `llvm`/`llvm-dev`, `build-essential`, `cmake`, `pkg-config`, `binutils-dev`, and **`dwarves`** (provides `pahole`, used by `find_offsets.sh` to extract struct-field offsets for technique-3/5 memory-write patches). Headers: `libelf-dev`, `zlib1g-dev`, `libboost-all-dev`, `libyaml-cpp-dev`.

### Common target dependencies

So a checked-out vulnerable app builds and runs without hunting for libs: `libpcre3`/`libpcre2`, `libssl3`, `libxml2`, `libcurl4`, `libevent`, `libsqlite3`, `libjemalloc2`, plus the usual runtime libs.

### Network capability

The container runs with `--cap-add=NET_ADMIN --cap-add=NET_RAW` and ships `iptables`, `ipset`, `iproute2`, `dnsutils`, `netcat-openbsd` — needed for server/daemon targets and the raw-socket exploit delivery (`exploit.py send`).

### Claude Code + dev ergonomics

Claude Code is installed natively, with these marketplaces pre-added: `anthropics/skills`, `trailofbits/skills`, `trailofbits/skills-curated`. Python 3.13 (via `uv`), `ast-grep`, `ripgrep`, `fd-find`, `fzf`, `git-delta`, `tmux`.

## Persistence & config

Named volumes survive rebuilds (see `mounts` in [`.devcontainer/devcontainer.json`](../.devcontainer/devcontainer.json)):

- shell history (`/commandhistory`)
- Claude config (`/home/vscode/.claude`, also `CLAUDE_CONFIG_DIR`)
- `gh` CLI config

[`post_install.py`](../.devcontainer/post_install.py) runs on create to bypass onboarding (when a token is present), set `bypassPermissions` mode, configure tmux (200k history, mouse), and fix ownership on the mounted volumes.

> Note: `.devcontainer/` is bind-mounted **read-only** inside the container, so edit those files from the host, not from within a running container.

## Files

| File | Purpose |
|------|---------|
| [`.devcontainer/devcontainer.json`](../.devcontainer/devcontainer.json) | Container definition — build, mounts, caps, env, `postCreateCommand` |
| [`.devcontainer/Dockerfile`](../.devcontainer/Dockerfile) | Image build, including the bpftime source build |
| [`.devcontainer/post_install.py`](../.devcontainer/post_install.py) | On-create configuration (auth, permissions, tmux, ownership) |
| `.devcontainer/.zshrc` | Shell config (currently not sourced — zsh setup is commented out in the Dockerfile) |
