/* SPDX-License-Identifier: MIT
 *
 * Shared ring-buffer event layout — the ONE definition, included by BOTH sides:
 *   - patch.bpf.c   (eBPF; gets __u32/__u64 from vmlinux.h, included before this)
 *   - patch_loader.c (loader; gets them from <linux/types.h>, included before this)
 * The loader decodes raw ring-buffer bytes with this struct, so the two sides MUST agree
 * byte-for-byte. Defining it once here removes the hand-synced duplicate and the silent
 * mis-decode hazard if a field is ever added/reordered.
 */
#ifndef PATCH_EVENT_H
#define PATCH_EVENT_H

enum patch_verdict { PATCH_ALLOW = 0, PATCH_WOULD_BLOCK = 1, PATCH_BLOCKED = 2 };

struct patch_event {
	__u32 invariant_id;   /* which check fired (a patch may have several) */
	__u32 verdict;        /* enum patch_verdict */
	__u64 observed;       /* the offending quantity (need / index / freed-ptr / read-len) */
	__u64 bound;          /* the safe bound it exceeded (capacity / length) */
	__u64 arg0;           /* a correlating arg (object/pointer) */
};

#endif /* PATCH_EVENT_H */
