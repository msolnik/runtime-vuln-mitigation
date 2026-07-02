/* SPDX-License-Identifier: MIT
 *
 * bpftime virtual-patch — eBPF side (runs IN-PROCESS inside the target).
 *
 * Grounded in the bpftime core API (verified against attach/ + runtime/):
 *   - bpf_override_return  = helper id 58 (runtime/src/bpf_helper.cpp)
 *   - it only takes effect under an OVERRIDE (1008) or UREPLACE (1009) attach;
 *     the loader (patch_loader.c + attach_override.h) selects that. Under a
 *     plain uprobe (type 6) it THROWS — no control-flow change.
 *   - ufunc dispatcher=1000 / find-id=1001 (runtime/extension/extension_helper.cpp)
 *   - BPF_UPROBE / PT_REGS_PARM* read args on BOTH x86_64 (rdi,rsi,...) and
 *     aarch64 (x0-x7) via libbpf bpf_tracing.h — arch-portable.
 *
 * HARD CONSTRAINT (verified: no register write-back in the frida attach path):
 *   You canNOT rewrite a scalar/register argument value. You can only
 *   (a) skip/replace the call via bpf_override_return, or
 *   (b) mutate memory a POINTER argument points to via bpf_probe_write_user.
 *
 * Fill in the two things from research/root-cause.md:
 *   1. the vulnerable function's signature  -> BPF_UPROBE(patch_entry, <args>)
 *   2. the root-cause INVARIANT              -> the `if (...)` condition below
 */
#define BPF_NO_GLOBAL_DATA
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * PATCH_MODE — observe vs enforce, ONE program (set via the Makefile: `make PATCH_MODE=observe`
 * or `PATCH_MODE=enforce`, threaded as -DPATCH_MODE to both this file and patch_loader.c).
 *   observe (0): evaluate the invariant and LOG the verdict, but DO NOT change behavior (no
 *                override, no probe_write). Two uses: (a) staged rollout / shadow mode, and
 *                (b) a DETECTOR for NON-CRASHING memory corruption — the hook computes the
 *                unsafe condition (e.g. need > capacity) and reports it BEFORE any corruption,
 *                so you get evidence even when nothing crashes. (See references/poc-reproduction.md
 *                "Grounding a non-crashing oracle": a would-block verdict is only trustworthy as an
 *                oracle with the vulnerable-vs-fixed/benign DIFFERENTIAL — it must be silent on the
 *                fixed build and on benign input, else the guard is circular.)
 *   enforce (1): same invariant, but ACT (override / probe_write / clamp). [default]
 * The verdict is emitted either way, so a single build flag flips detect ↔ neutralize.
 */
#define PATCH_MODE_OBSERVE 0
#define PATCH_MODE_ENFORCE 1
#ifndef PATCH_MODE
#define PATCH_MODE PATCH_MODE_ENFORCE
#endif
#define PATCH_OBSERVE (PATCH_MODE == PATCH_MODE_OBSERVE)

/*
 * Structured patch logging via a RING BUFFER (verified to work under bpftime: the loader's
 * ring_buffer__poll streams these events over the shm ringbuf). Preferred over bpf_printk —
 * whose output goes to the target's stderr and is buffering-sensitive/lost-on-kill. The loader
 * (patch_loader.c) prints + flushes these; a verdict >= WOULD_BLOCK is your "the filter fired"
 * evidence (Phase 5) AND, in observe mode, your non-crashing detection signal (Phase 3).
 *
 *   verdict: ALLOW=0 (invariant held) · WOULD_BLOCK=1 (violated, observe mode: logged not acted)
 *            · BLOCKED=2 (violated, enforce mode: neutralized).
 *   invariant_id: which check fired (a patch may have several).
 *   observed/bound: the offending quantity and the safe bound it exceeded (e.g. need vs capacity,
 *                   index vs length) — the heart of "improved patch info/tracing".
 *   arg0: a correlating arg (object/pointer) so events can be tied to a request.
 */
#include "patch_event.h"   /* enum patch_verdict + struct patch_event — shared with patch_loader.c */
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 16); } patch_log SEC(".maps");
static __always_inline void patch_report(__u32 invariant_id, __u32 verdict,
					 __u64 observed, __u64 bound, __u64 arg0)
{
	struct patch_event *e = bpf_ringbuf_reserve(&patch_log, sizeof(*e), 0);
	if (e) {
		e->invariant_id = invariant_id; e->verdict = verdict;
		e->observed = observed; e->bound = bound; e->arg0 = arg0;
		bpf_ringbuf_submit(e, 0);
	}
}
/* The verdict a violated invariant gets, given the build mode (compile-time constant). */
#define VIOLATION_VERDICT (PATCH_OBSERVE ? PATCH_WOULD_BLOCK : PATCH_BLOCKED)

/*
 * Pick the technique that matches the vulnerability (see references/bpftime-patch-cookbook.md):
 *   1 = conditional override  — skip the original when the invariant is violated   [default]
 *   2 = full replace          — original never runs; return a synthesized safe value
 *   3 = state-mutation/sanitize — plain uprobe; write a struct field/buffer via
 *       bpf_probe_write_user (offset from find_offsets.sh) — e.g. replicate a fix that clears a flag
 *   4 = ufunc-backed fix       — call the target's own validators to mirror the upstream fix
 *   5 = detect-and-neutralize bounds — read args, COMPUTE the safe bound, and enforce it
 *       (conditional override when out of bounds; or clamp a memory-backed size via
 *       probe_write). The canonical patch for NON-CRASHING OOB (over-read/over-write). It is a
 *       CONDITIONAL GUARD (reads input to decide) → full anti-overfitting variant sweep in Phase 5.
 * Techniques 1, 2, 4, 5 require the override/replace attach; technique 3 is a plain uprobe. Set
 * this via the Makefile (`PATCH_TECHNIQUE ?= 1`, or `make PATCH_TECHNIQUE=3`) so patch.bpf.c AND
 * patch_loader.c pick the same attach path; the define below is only the fallback without -D.
 */
#ifndef PATCH_TECHNIQUE
#define PATCH_TECHNIQUE 1
#endif

#if PATCH_TECHNIQUE == 1
/* CONDITIONAL OVERRIDE. Match the arg list to the real function signature.
 * Return the SAME value the upstream-fixed code returns on the rejected path. */
SEC("uprobe")
int BPF_UPROBE(patch_entry /* , TYPE arg1, TYPE arg2 ... */)
{
	/* TODO: read args (arg1, ...) and/or target memory via
	 * bpf_probe_read_user(&tmp, sizeof(tmp), ptr). Then test the invariant: */
	if (/* ROOT-CAUSE INVARIANT IS VIOLATED — replace this */ 0) {
		patch_report(1, VIOLATION_VERDICT, 0 /* observed, e.g. len */, 0 /* bound */, 0 /* arg0 */);
#if !PATCH_OBSERVE
		bpf_override_return(ctx, -1); /* skip original; return safe error (enforce only) */
#endif
		return 0;
	}
	patch_report(1, PATCH_ALLOW, 0, 0, 0); /* optional — drop on hot paths */
	return 0; /* invariant holds -> original runs unchanged (benign) */
}

#elif PATCH_TECHNIQUE == 2
/* FULL REPLACE — original never runs; the value below is always returned (enforce). In observe
 * mode it is logged but NOT replaced (the original still runs). */
SEC("uprobe")
int BPF_UPROBE(patch_entry)
{
	patch_report(2, VIOLATION_VERDICT, 0, 0, 0);
#if !PATCH_OBSERVE
	bpf_override_return(ctx, 0 /* synthesized safe return value */);
#endif
	return 0;
}

#elif PATCH_TECHNIQUE == 3
/* STATE-MUTATION / SANITIZE (plain uprobe — NOT override). Replicate a fix that resets internal
 * state or sanitizes a buffer by writing through a POINTER arg with bpf_probe_write_user. You may
 * NOT change scalar arg values.
 *   Get FIELD_OFF/FIELD_BIT from the binary you built:
 *     ./find_offsets.sh ../target/<binary> <struct_name> <field>
 * Building with PATCH_TECHNIQUE=3 makes patch_loader.c attach a PLAIN uprobe (not override).
 * observe mode logs the byte it WOULD clear without writing (a shadow of the state reset). */
#define FIELD_OFF 0   /* TODO: byte offset of the field from find_offsets.sh */
#define FIELD_BIT 0   /* TODO: bit position (bitfield); ignore for a whole field */
SEC("uprobe")
int BPF_UPROBE(patch_entry, void *obj)   /* arg0 = pointer to the struct the fix mutates */
{
	__u8 b = 0;                                        /* read-modify-write one byte so */
	bpf_probe_read_user(&b, 1, (char *)obj + FIELD_OFF);  /* neighbouring bits survive */
	patch_report(3, VIOLATION_VERDICT, b, 0, (__u64)obj);
#if !PATCH_OBSERVE
	b &= ~(1u << FIELD_BIT);                           /* clear the flag (the fix's state reset) */
	bpf_probe_write_user((char *)obj + FIELD_OFF, &b, 1);
	/* Buffer-clamp variant: bpf_probe_write_user((void *)ptr, &safe_bytes, len); */
#endif
	return 0;
}

#elif PATCH_TECHNIQUE == 4
/* UFUNC-BACKED FIX — call the target's OWN functions by name to mirror the
 * upstream fix faithfully. Requires the `ufunc` helper group (on by default). */
#include "ufunc.bpf.h"
SEC("uprobe")
int BPF_UPROBE(patch_entry /* , TYPE arg1 ... */)
{
	/* long ok = UFUNC_CALL_NAME_1("target_validator", arg1); */
	long ok = 1; /* TODO: replace with the real validator call */
	if (!ok) {
		patch_report(4, VIOLATION_VERDICT, 0, 0, 0);
#if !PATCH_OBSERVE
		bpf_override_return(ctx, -1);
#endif
		return 0;
	}
	patch_report(4, PATCH_ALLOW, 0, 0, 0);
	return 0;
}

#elif PATCH_TECHNIQUE == 5
/* DETECT-AND-NEUTRALIZE BOUNDS — the canonical patch for NON-CRASHING OOB (silent over-read /
 * over-write, index past a length). READ the args, COMPUTE the safe bound from the invariant,
 * and compare. This is a CONDITIONAL GUARD (reads input) → Phase 5 gives it the full variant sweep.
 *
 * Fill compute_need()/compute_cap() from the sink's semantics (root-cause.md). Example shapes:
 *   - length/copy desync: need = escaped_len(src, srclen); cap = alloc_size (a struct field).
 *   - index bug:          need = index + 1;                cap = array_count.
 * Read the quantities from memory (bpf_probe_read_user) or scalar args (PT_REGS_PARM via BPF_UPROBE).
 *
 * ENFORCEMENT (enforce mode): default = conditional OVERRIDE (skip the unsafe call) — needs the
 * override attach (this technique uses it). If instead the bound lives in MEMORY the sink
 * dereferences (a size field / capacity), you can CLAMP it in place with bpf_probe_write_user
 * INSTEAD of the override (see the commented line) — this works AS-IS under technique 5's override
 * attach: just don't also call bpf_override_return, so the original runs on with the corrected
 * size. You CANNOT clamp a bare scalar/register arg (no write-back) — override there.
 * observe mode: reports observed/bound but neither overrides nor clamps. */
SEC("uprobe")
int BPF_UPROBE(patch_entry, void *arg0 /* , TYPE arg1 ... — match the sink */)
{
	__u64 need = 0;   /* TODO: compute the required size/index from the args (the "observed") */
	__u64 cap  = 0;   /* TODO: compute the available capacity/bound */
	/* e.g.:
	 *   struct rec r; bpf_probe_read_user(&r, sizeof(r), arg0);
	 *   need = r.escaped_len; cap = r.alloc_size;
	 */
	if (need > cap) {                     /* OUT OF BOUNDS — the corruption condition */
		patch_report(5, VIOLATION_VERDICT, need, cap, (__u64)arg0);
#if !PATCH_OBSERVE
		bpf_override_return(ctx, -1);  /* neutralize: skip the unsafe call (safe error) */
		/* clamp variant (INSTEAD of the override above; works under this same override attach,
		 * memory-backed size only): __u64 clamped = cap;
		 *   bpf_probe_write_user((char *)arg0 + SIZE_OFF, &clamped, sizeof(clamped)); return 0; */
#endif
		return 0;
	}
	patch_report(5, PATCH_ALLOW, need, cap, (__u64)arg0);
	return 0;                             /* in bounds -> original runs unchanged */
}

#else
#error "PATCH_TECHNIQUE must be 1, 2, 3, 4 or 5"
#endif

char LICENSE[] SEC("license") = "GPL";
