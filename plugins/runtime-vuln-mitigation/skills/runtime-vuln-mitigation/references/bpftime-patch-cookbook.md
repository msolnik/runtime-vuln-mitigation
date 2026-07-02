# bpftime Patch Cookbook

How to author, build, deploy, and debug a bpftime eBPF program that acts as a runtime
"virtual patch" for a userspace vulnerability. The facts below were derived by reading the
bpftime **core source** (attach/ + runtime/) and verified end-to-end on this container; the
build itself needs **no bpftime source tree** (see §2/§6).

> **Use the templates.** `{baseDir}/templates/patch/` is a verified (x86_64 + aarch64)
> scaffold — copy it into `work/<CVE>/patch/` and fill the TODOs rather than hand-rolling.
> This reference explains what it does and why. The bpftime `example/hotpatch/*` demos (and
> `example/minimal` / `error-inject`) are **thought-input only** — their loaders are stale
> (attach commented out / removed `bpftime-cli` JSON flow); trust the core API below.

## Verified facts (empirically confirmed on this container — aarch64, HEAD 6bd5319; the template scaffold also builds+attaches on x86_64, see the arch matrix)

- **Attach types:** `ATTACH_UPROBE=6`, `ATTACH_URETPROBE=7`, `ATTACH_UPROBE_OVERRIDE=1008`,
  `ATTACH_UREPLACE=1009`, `ATTACH_SYSCALL_TRACE=2`. There is **no separate "filter" type** —
  "filter" == uprobe-override (1008).
- **Override mechanism:** the loader opens a perf event with `attr.type = 1008` and links the
  prog with `bpf_prog_attach(..., BPF_MODIFY_RETURN, 0)` (the flag is *ignored*; the type 1008
  is what matters). `bpf_override_return` (helper **58**) then skips the original;
  `bpf_set_retval` (helper **187**) sets the return. Under a plain uprobe they throw.
- **Success return convention:** under bpftime, `bpf_prog_attach` returns a **positive fd on
  success** (NOT 0). Only a negative result is a failure. (This bit me — the template
  `attach_override.h` normalizes it to 0.)
- **Arch matrix:** uprobe / uretprobe / uprobe-override / ureplace work on **x86_64 AND
  aarch64** (Frida-based, full arm64 register support). **Syscall-tracepoint hooking is
  x86_64-ONLY** — the aarch64 syscall trampoline (text_segment_transformer) is an
  unimplemented stub. On aarch64 you MUST use uprobe-override, never a syscall filter.
- **You cannot rewrite scalar/register args** (no write-back in the frida path). Only skip/
  replace the call (`bpf_override_return`/ureplace) or mutate pointed-to memory
  (`bpf_probe_write_user`, helper 36). The override handler forwards only **arg0–arg4** to
  the original — 6+ register-arg functions may misbehave if you don't override.
- **ufunc** (call the target's own functions by name): dispatcher helper **1000**, find-id
  **1001**; on by default. `bpf_get_func_arg`/`get_func_ret`/`get_retval` are provided only by
  the frida attach impl's custom helpers under a uprobe attach — prefer `BPF_UPROBE`/`PT_REGS_PARM*`.
- **Build:** the container's prebuilt libbpf (`/usr/local/bpftool/libbpf/libbpf.a`) + installed
  `bpftool` work fine (verified) — the libbpf version is NOT the issue. (An earlier "must use
  vendored libbpf / else EBADF" was a **misdiagnosis** of the positive-fd return above.) Use
  `-I/usr/local/bpftool/libbpf/include` for `<bpf/...>`, generate `vmlinux.h` from
  `/sys/kernel/btf/vmlinux`, pass `-D__TARGET_ARCH_<arch>`; `{baseDir}/templates/patch/Makefile` does it.
- **Deploy needs clean shm:** all agents share `/dev/shm/bpftime_maps_shm`; a stale loader/
  agent makes attach fail (EBADF). Clean it (`bpftimetool remove` + `rm`) before every deploy.

---

## 1. Mental Model

bpftime is a **userspace** eBPF runtime. It loads a standard, clang-built eBPF object and
runs it **in-process inside the target application** via Frida-gum binary rewriting — no
kernel, no source change, no recompile of the target. Because the program executes in the
target's address space, a hook can read the target's memory directly and actively change
control flow.

Two processes are involved:
- **Loader / syscall-server** (`bpftime load ./loader`, or `LD_PRELOAD` of
  `libbpftime-syscall-server.so`): owns the eBPF program and the maps (in shared memory).
  Keep it alive for the lifetime of the patch — killing it evicts the program.
- **Agent / target** (`bpftime start ./target`, or `LD_PRELOAD` of `libbpftime-agent.so`,
  or `bpftime attach <pid>`): the process being patched; the agent runs the eBPF program
  in-process on the hooked functions/syscalls.

---

## 2. This Container's Install (important)

| Thing | Path |
|-------|------|
| CLI + tools | `/usr/local/bin/{bpftime,bpftime-aot,bpftime_daemon,bpftimetool,bpftime-vm}` |
| Injectable libs | `/usr/local/bin/libbpftime-{agent,agent-transformer,syscall-server}.so` |
| bpftool | `/usr/local/bpftool/bpftool` |
| libbpf headers + lib | `/usr/local/bpftool/libbpf/include/` and `.../libbpf/libbpf.a` |
| vmlinux.h source | generated at build from `/sys/kernel/btf/vmlinux` (kernel BTF) |
| uapi headers | system `/usr/include/linux/bpf.h` |

**No bpftime source tree is required** — the build is self-contained on the above (the
skill's `{baseDir}/templates/patch/Makefile` does it). **Gotcha:** the CLI default `--install-location`
is `~/.bpftime`, which does **not** exist here. Always pass `-i /usr/local/bin`, or use
`LD_PRELOAD` with the explicit `/usr/local/bin/libbpftime-*.so` paths.

---

## 3. Attach Types

| Type | Value | Behavior | Use for a patch |
|------|-------|----------|-----------------|
| uprobe | 6 | Observe on function entry | Detection/logging only |
| uretprobe | 7 | Observe on function return | Inspect/observe return |
| **UPROBE_OVERRIDE** | **1008** | Run before the fn; if the program calls `bpf_override_return`, the original is **skipped** | **Primary patch mechanism** |
| **UREPLACE** | **1009** | Original **always** replaced; program's return becomes the fn's return | Synthesize a safe return value |
| syscall tracepoint | — | Hook syscalls the target makes; `bpf_override_return` in `sys_enter` skips the syscall | Filter/deny a dangerous syscall |

**Two ways the target is chosen — do not confuse them:**
- **Manual OVERRIDE (the patch path, what the templates use):** the program is **bare
  `SEC("uprobe")`**; the target `binary:function` is supplied by the *loader* (perf event
  type 1008, `config1`=binary, `config2`=offset — see `attach_override.h`). The SEC string
  does NOT carry the target here.
- **libbpf auto-attach (plain *observe* uprobe only — cannot override):** the target lives in
  the SEC string and `skel__attach()` wires it. Forms:
  - `SEC("uprobe/./target_app:vuln_fn")` — function in the main binary (`module:function`)
  - `SEC("uprobe/libc.so.6:malloc")` — function in a shared library
  - `SEC("tracepoint/syscalls/sys_enter_write")` — a syscall (x86_64 only; enable with `-s`)
  - `SEC("usdt")` with `BPF_USDT(...)` — a USDT probe point

---

## 4. Authoring the Patch (`patch.bpf.c`)

### Reading arguments and memory
Uprobe handlers receive `struct pt_regs *ctx`. Read args with the typed macro or raw:
```c
// typed: names the args by type
int BPF_UPROBE(patch_handle, client *c, int len) { ... }
// raw:
int handler(struct pt_regs *ctx) { long a1 = PT_REGS_PARM1(ctx); ... }
```
Because the program runs in-process you can dereference pointer args directly
(`c->argc`), but for untrusted addresses prefer `bpf_probe_read_user(dst, sz, src)` — it
installs a SIGSEGV guard so a bad pointer returns an error instead of crashing the target.

### Enforcing the invariant (the actual patch)
Evaluate the **root-cause invariant** (from Phase 2), and only short-circuit when it is
violated:
```c
SEC("uprobe")                                 // bare — the loader picks the target (override attach)
int BPF_UPROBE(patch_vuln_fn, char *buf, int len) {
    if (len > MAX_SAFE_LEN) {                 // the exact condition the upstream fix guards
        bpf_printk("virtual patch fired: len=%d", len);
        bpf_override_return(ctx, -1);         // original NOT executed; returns -1
    }
    return 0;                                 // invariant holds -> original runs (benign)
}
char LICENSE[] SEC("license") = "GPL";
```

### Reusing the app's own validators (`ufunc`)
The strongest patches call the target's real functions instead of re-implementing logic
(as the Redis demo re-uses `lookupKeyWrite`/`checkType`). Use the bundled
`ufunc.bpf.h` (in `{baseDir}/templates/patch/`):
```c
#include "ufunc.bpf.h"                        // defines ufunc_call(1000), ufunc_find_func_id(1001)
robj *o = (robj *)UFUNC_CALL_NAME_2("lookupKeyWrite", c->db, c->argv[2]);
if (!o || checkType(c, o, OBJ_STREAM)) { bpf_override_return(NULL, 0); return 0; }
```
Register the ufunc symbol→address mapping in the loader/CLI JSON. Requires correct
symbol names and matching ABI — a wrong signature silently corrupts the target.

### Replicating a state-change fix (mutate a struct field / flag) — technique 3

**Not every fix skips a call.** Many upstream fixes just **reset internal state** — clear a
flag, zero a length, correct a size. When the fix is a one-line state change like
`obj->flag = 0;` inside `some_fn(struct T *obj)`, you cannot change a scalar *argument*, but you
CAN write through a POINTER argument into the target's own memory: hook `some_fn` and write the
same field the fix writes. This is the shape of many "leaked/stale flag" bugs.

**Step 1 — get the field offset from the binary YOU built.** Phase 3 builds the target with
`-g`, so its DWARF has every struct layout. Use `pahole` (installed via `dwarves`) — never guess:
```bash
pahole -C <struct_name> target/<path>/<binary>          # fields with byte offsets + bitfield bit positions
# helper: {baseDir}/templates/patch/find_offsets.sh target/<path>/<binary> <struct_name> <field>
```
For a **bitfield**, pahole prints the containing-unit byte offset AND the bit position/width,
e.g. `unsigned int <field>:1; /* 64: 3 4 */` → storage-unit byte offset `64`, bit `3`.
Check the sink symbol's scope with `nm <binary> | grep <fn>`: `T` = global (attachable by
name), `t` = local/`static` (needs an unstripped `-g` build). Build `-g` and **not stripped**
either way. (`file` may be absent in-container; use `readelf -S`/`nm` to check for `.symtab`.)

**Step 2 — write the field with `bpf_probe_write_user`.** For a whole field, memcpy the value.
For a single **bitfield bit**, read-modify-write its byte so you don't clobber neighbours:
```c
#define FIELD_OFF N        /* byte offset from pahole */
#define FIELD_BIT B        /* bit within that byte */
SEC("uprobe")              /* PLAIN uprobe on the sink fn — NOT override */
int BPF_UPROBE(patch_entry, void *obj) {        /* arg0 = pointer to the struct the fix mutates */
    __u8 b = 0;
    bpf_probe_read_user(&b, 1, (char *)obj + FIELD_OFF);
    b &= ~(1u << FIELD_BIT);                    /* clear the flag (the fix's state reset) */
    bpf_probe_write_user((char *)obj + FIELD_OFF, &b, 1);
    return 0;
}
```
This is a **plain uprobe**, NOT the override attach — you are not skipping the function, only
fixing its state. Selecting `PATCH_TECHNIQUE 3` (below) makes both `patch.bpf.c` and
`patch_loader.c` use the plain-uprobe attach automatically. In Phase 5, assert the byte actually
changed and the exploit no longer triggers.

You can also just **clamp/rewrite a buffer** a pointer arg points to the same way:
`bpf_probe_write_user((void *)ptr, &safe_bytes, len);` (in-place memcpy, same address space).

### Key helpers available
`bpf_probe_read(_user/_kernel/_str)`, `bpf_probe_write_user`, `bpf_override_return`,
`bpf_get_func_arg`, map helpers, `bpf_ringbuf_output`/`bpf_perf_event_output`,
`bpf_printk`, `bpf_get_current_pid_tgid`, `bpf_ktime_get_ns`. ~35 kernel-compatible
helpers total.

---

## 5. Which Technique to Use

Copy `{baseDir}/templates/patch/` and set `PATCH_TECHNIQUE` in the Makefile (`PATCH_TECHNIQUE ?=
N`, or `make PATCH_TECHNIQUE=N`) — it is passed to BOTH `patch.bpf.c` and `patch_loader.c` so the
eBPF side and the attach path always agree (1/2/4/5 = override attach; 3 = plain uprobe):

| Situation | Technique |
|-----------|-----------|
| Skip/deny a function on a bad-input condition | 1 — conditional override (`bpf_override_return`) |
| Always return a synthesized safe value | 2 — full replace |
| Replicate a fix that RESETS STATE (clear a flag/bitfield, fix a size) | 3 — memory write: pahole offset + `bpf_probe_write_user` (plain uprobe, NOT override) |
| Sanitize a buffer a pointer arg points to | 3 — observe/sanitize (`bpf_probe_write_user`) |
| Re-run the app's own validator to mirror the upstream fix | 4 — ufunc-backed (`UFUNC_CALL_NAME_*`) |
| **Bounds bug / NON-CRASHING OOB** (over-read/over-write, index past a length) | **5 — detect-and-neutralize**: compute `need` vs `capacity`, override when out of bounds (or clamp a memory-backed size) |
| Deny a dangerous **syscall** (x86_64 only) | syscall tracepoint + override |

### `PATCH_MODE` — observe vs enforce (one program, build flag)

Orthogonal to the technique: `make PATCH_MODE=observe` builds the SAME program to **log only** —
it evaluates the invariant and emits a `would-block` verdict over the ring buffer but does NOT act
(no override, no `probe_write`). `PATCH_MODE=enforce` (default) acts. Threaded via the Makefile
(`-DPATCH_MODE` + a `.mode.stamp` rebuild dep, exactly like `PATCH_TECHNIQUE`) to both units.
Two uses:
- **Detect non-crashing corruption** — observe mode is the oracle for a bug that never crashes: the
  hook computes the unsafe condition before any corruption. `run.sh MODE=instrument` reads the
  verdict. Trust it only with the vulnerable-vs-fixed/benign **differential** (see
  `references/poc-reproduction.md` "Grounding a non-crashing oracle" — the guard must be SILENT on
  the fixed build, or it is circular).
- **Staged rollout** — ship observe first in production to measure real would-block rate (zero false
  positives), then rebuild `enforce`.
Observe mode is safe under an override attach: not calling `bpf_override_return` lets the original
run normally (same as technique 1's ALLOW path). The rich event
(`invariant_id/verdict/observed/bound/arg0`) is the "improved patch info/tracing".

### Technique 5 detail — detect-and-neutralize bounds

Read the sink args, **compute** the required size/index (`need`, the "observed") and the available
capacity (`cap`, the "bound") from the invariant, and compare. On `need > cap`:
- **enforce (default): `bpf_override_return(safe)`** — skip the unsafe call. Needs the override
  attach (technique 5 uses it, like 1/2/4).
- **clamp variant:** if `cap`/the size lives in MEMORY the sink dereferences (a struct size field),
  `bpf_probe_write_user` it down to `cap` — but then switch the loader to a PLAIN uprobe (like
  technique 3), since a clamp needs no override. **You cannot clamp a bare scalar/register arg**
  (no write-back) — fall back to override there.
It reads input to decide → a **conditional guard** → Phase 5 gives it the full variant sweep.

(If the bpftime source happens to be present, `example/hotpatch/{redis,vim}` and
`example/minimal/uprobe-override` are illustrative — but their loaders are stale; the
templates are the working, verified starting point.)

---

## 6. Building (self-contained — use `templates/patch/Makefile`)

`make` in the copied `patch/` dir does all of this (verified on aarch64 + x86_64); the steps,
for reference:
```bash
BT=/usr/local/bpftool
# 1. generate vmlinux.h from the running kernel's BTF (no bpftime source):
$BT/bpftool btf dump file /sys/kernel/btf/vmlinux format c > .output/vmlinux.h
# 2. compile the eBPF object (ARCH auto-detected: arm64 on aarch64, x86 on x86_64):
clang -g -O2 -target bpf -D__TARGET_ARCH_$ARCH -Wno-missing-declarations \
  -I.output -I$BT/libbpf/include $CLANG_BPF_SYS_INCLUDES -c patch.bpf.c -o .output/patch.tmp.bpf.o
$BT/bpftool gen object .output/patch.bpf.o .output/patch.tmp.bpf.o
$BT/bpftool gen skeleton .output/patch.bpf.o > patch.skel.h
# 3. loader (uapi <linux/bpf.h> from the system; link the prebuilt libbpf.a):
clang -g -Wall -I.output -I$BT/libbpf/include -c patch_loader.c -o .output/patch_loader.o
clang .output/patch_loader.o $BT/libbpf/libbpf.a -lelf -lz -o patch_loader
```
The **loader** drives the generated skeleton (`patch_bpf__open`/`__load`/`__destroy`) and
attaches with `attach_override.h`: perf event `attr.type = 1008` (`BPF_TYPE_UPROBE_OVERRIDE`),
`attr.config1 = binary path`, `attr.config2 = function offset`, then
`bpf_prog_attach(prog_fd, pfd, BPF_MODIFY_RETURN, 0)` — which **returns a positive fd on
success** (normalize to 0). `attach_override.h`/`ufunc.bpf.h` are bundled in the templates.

Optional AOT (deploy without a JIT at runtime): `bpftime-vm build patch.bpf.o -o out_dir`.

---

## 7. Deploying

**Mode A — preload at start (most deterministic):**
```bash
bpftime -i /usr/local/bin load  ./patch_loader     # terminal 1: holds program + maps
bpftime -i /usr/local/bin start ./target_app       # terminal 2: target with agent injected
# add -s to `start` to enable syscall-tracepoint hooks (x86)
```
Equivalent via preload (what `deploy.sh` uses):
`LD_PRELOAD=/usr/local/bin/libbpftime-syscall-server.so ./patch_loader` (loader) and
`LD_PRELOAD=/usr/local/bin/libbpftime-agent.so ./target_app` (target).
- **Library order matters for a sanitizer-instrumented target:** its runtime MUST load before the
  agent — `LD_PRELOAD="$(gcc -print-file-name=libasan.so):/usr/local/bin/libbpftime-agent.so" ./target_app`
  — else it aborts ("ASan runtime does not come first"). `bpftime start` can't control this order; use
  the explicit `LD_PRELOAD` form (deploy.sh's `EXTRA_PRELOAD` does exactly this).
- **Path identity:** the loader's `TARGET_BINARY` must be the EXACT path you run the target as — bpftime
  keys the uprobe on that path, so a mismatch silently attaches to nothing.

**Mode B — late attach to an already-running process (no restart):**
```bash
bpftime -i /usr/local/bin load ./patch_loader &    # loader stays running
./target_app & VICTIM=$!
sudo bpftime -i /usr/local/bin attach "$VICTIM"     # Frida-injects the agent into the PID
# or by name with auto-refresh of late links:
sudo bpftime -i /usr/local/bin trace --pidof target_app --auto-refresh-ms 500 ./patch_loader
sudo bpftime -i /usr/local/bin detach               # remove the patch
```
Late attach needs privileges (root or `CAP_SYS_PTRACE` and a permissive
`/proc/sys/kernel/yama/ptrace_scope`).

**Assert it attached.** A silent attach/verifier failure leaves the app unprotected. Check
the loader output for a successful load + "attached" message; raise verbosity if unsure.

---

## 8. Logging & Debugging

**Recommended patch logging: a ring buffer, not `bpf_printk`.** The templates log each decision as a
`struct patch_event` (shared header `patch_event.h`: `invariant_id`, `verdict` ALLOW/WOULD_BLOCK/
BLOCKED, `observed`, `bound`, `arg0`) through a `BPF_MAP_TYPE_RINGBUF`; the LOADER runs
`ring_buffer__poll` and prints `[patch] FIRED invariant=… verdict=… observed=… bound=…` (ALLOW is
counted, not printed). Verified: `ring_buffer__poll`
works over bpftime's shm ringbuf loader-side (one event per hit, no loss). This is robust
(the loader owns the output — no target-stderr buffering, nothing lost on kill), structured, and
the stream of `FIRED` events IS your Phase-5 "the filter fired on the malicious path" evidence.
Use it via the template's `patch_report()` (patch.bpf.c) + the loader's poll loop (patch_loader.c).

`bpf_printk` is only for quick ad-hoc debug — and under the agent its output goes to the
**target's stderr** (NOT `~/.bpftime/runtime.log`, NOT the kernel `trace_pipe`) and is
buffering-sensitive: run the target with `BPFTIME_LOG_OUTPUT=console` and `stdbuf -oL` (or capture
its stderr) or you may lose it on kill.

```bash
SPDLOG_LEVEL=debug BPFTIME_LOG_OUTPUT=console \
  LD_PRELOAD=/usr/local/bin/libbpftime-syscall-server.so ./patch_loader
``` The loader/syscall-server's own logs go to
`~/.bpftime/runtime.log` (created lazily) or the console with `BPFTIME_LOG_OUTPUT=console`. Inspect
shared-memory program/map state with `bpftimetool export /tmp/state.json`. To force the kernel
verifier for extra safety before shipping: `BPFTIME_RUN_WITH_KERNEL=true` on the loader.

---

## 9. Constraints & Pitfalls

- **Cannot rewrite scalar/register argument values.** The `pt_regs` handed to the program
  is a copy with no write-back. Change behavior via `bpf_override_return` (skip/replace) or
  `bpf_probe_write_user` (mutate pointed-to memory) — never by editing `PT_REGS_PARMn`.
- **Same for syscall args:** you can block/fail the syscall or edit a pointed-to buffer, but
  cannot redirect it by changing argument values (e.g. can't repoint `open()` to another path).
- **`bpf_override_return` needs an OVERRIDE/UREPLACE or syscall attach.** On a plain
  observe uprobe it errors/throws.
- **One override/replace per function address** (`-EEXIST` otherwise). Plain observers can
  coexist.
- **Binary-layout coupling.** Patches that read struct fields at fixed offsets or fixed
  symbol addresses break on recompile / different arch / app update. Pin the build;
  regenerate offsets from BTF (`bpftool btf dump`) / `pahole`; resolve symbols with `nm`.
- **In-process crash risk.** A fault or infinite loop in the handler can take down the
  target. Prefer `bpf_probe_read_user` over raw deref for untrusted pointers.
- **TOCTOU.** In a multithreaded target, another thread can mutate an argument between your
  check and the app's use. Account for this when arguing the filter is sound.
- **Frida may reject tiny/inlined functions** (`GUM_ATTACH_WRONG_SIGNATURE`) — hook a
  larger wrapper or a caller instead.
- **Syscall-tracepoint interception is x86_64-ONLY** — the aarch64 trampoline is an
  unimplemented stub, so on aarch64 you MUST hook the function (uprobe-override), not the syscall.
- **Pre-1.0.** bpftime's own docs say it is not production-ready. Treat patches as
  mitigations and validate heavily (Phase 5).

---

## 10. Choosing the Hook

1. Prefer a **uprobe OVERRIDE on the vulnerable function** when a clean symbol exists and
   the invariant is decidable from its args/memory — closest to the upstream fix.
2. Use **UREPLACE** when the function must return a synthesized valid object (not just an
   error) on the safe path.
3. Use a **syscall tracepoint** when the danger is best expressed as a syscall the target
   makes (e.g. an unexpected `execve`, a write outside an allowed path) and you want to
   deny it regardless of which internal function initiated it.
4. Hook the **narrowest point where the invariant is decidable** — deeper hooks reduce
   false positives; wrapper hooks help when the true sink is inlined.
