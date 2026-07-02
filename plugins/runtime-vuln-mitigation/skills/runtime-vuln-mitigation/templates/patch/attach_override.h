/* SPDX-License-Identifier: MIT
 *
 * Attach an eBPF program to a userspace function with bpftime's OVERRIDE (1008)
 * or REPLACE (1009) attach type — the thing that makes bpf_override_return() /
 * bpf_set_retval() actually skip or replace the original function.
 *
 * Verified against bpftime core:
 *   - The bpftime syscall-server intercepts perf_event_open and keys off
 *     attr.type == 1008 / 1009 (runtime/syscall-server/syscall_context.cpp),
 *     mapping it to add_uprobe_override / ureplace. The BPF_MODIFY_RETURN flag
 *     passed to bpf_prog_attach is IGNORED by bpftime — only the perf type and
 *     the prog->perf_event link matter.
 *   - config1 = uprobe binary path, config2 = function offset.
 *   - elf_find_func_offset_from_file() is a libbpf symbol (present in the
 *     linked libbpf.a) that resolves the function offset in the target ELF.
 *   - Works on x86_64 and aarch64 (frida-based; no arch-specific asm here).
 */
#ifndef BPFTIME_OVERRIDE_ATTACH_H
#define BPFTIME_OVERRIDE_ATTACH_H

#include <unistd.h>
#include <syscall.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

/* libbpf-provided: resolve a function's uprobe offset within an ELF file. */
long elf_find_func_offset_from_file(const char *binary_path, const char *name);

#define BPF_TYPE_UPROBE_OVERRIDE 1008 /* conditional skip via bpf_override_return */
#define BPF_TYPE_UREPLACE        1009 /* always replace; program's retval is used */

static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64)(unsigned long)ptr;
}

/* Open a bpftime override/replace perf event for binary_path:offset. */
static int bpftime_perf_event_open_override(const char *binary_path,
					    uint64_t offset, int pid, int type)
{
	struct perf_event_attr attr;
	int pfd;

	memset(&attr, 0, sizeof(attr));
	attr.size = sizeof(attr);
	attr.type = type;                       /* 1008 or 1009 -> bpftime */
	attr.config1 = ptr_to_u64(binary_path); /* uprobe_path */
	attr.config2 = offset;                  /* probe_offset */

	pfd = syscall(__NR_perf_event_open, &attr, pid < 0 ? -1 : pid,
		      pid == -1 ? 0 : -1, -1, PERF_FLAG_FD_CLOEXEC);
	return pfd >= 0 ? pfd : -errno;
}

/* Attach prog_fd to binary_path:name with the given bpftime attach `type`. */
static int bpf_prog_attach_with_type(int prog_fd, const char *binary_path,
				     const char *name, int type)
{
	long offset = elf_find_func_offset_from_file(binary_path, name);
	if (offset < 0) {
		fprintf(stderr, "could not resolve %s in %s (err=%ld)\n", name,
			binary_path, offset);
		return (int)offset;
	}
	int pfd = bpftime_perf_event_open_override(binary_path, offset, -1, type);
	if (pfd < 0) {
		fprintf(stderr, "perf_event_open(type=%d) failed: %d\n", type, pfd);
		return pfd;
	}
	/* BPF_MODIFY_RETURN here is ignored by bpftime; it only links prog<->event.
	 * NOTE: under bpftime's syscall-server, bpf_prog_attach returns a POSITIVE
	 * fd on success (not 0 like kernel libbpf). Normalize to 0 so callers can
	 * use `if (err)`; only a negative result is a real failure. */
	int res = bpf_prog_attach(prog_fd, pfd, BPF_MODIFY_RETURN, 0);
	if (res < 0) {
		fprintf(stderr, "bpf_prog_attach failed: %d\n", res);
		return res;
	}
	return 0;
}

/* Conditional override (skip original when bpf_override_return is called). */
static int bpf_prog_attach_uprobe_with_override(int prog_fd,
						const char *binary_path,
						const char *name)
{
	return bpf_prog_attach_with_type(prog_fd, binary_path, name,
					 BPF_TYPE_UPROBE_OVERRIDE);
}

/* Full replace (original never runs; program's return value is always used). */
__attribute__((unused)) static int bpf_prog_attach_uprobe_with_replace(int prog_fd,
					       const char *binary_path,
					       const char *name)
{
	return bpf_prog_attach_with_type(prog_fd, binary_path, name,
					 BPF_TYPE_UREPLACE);
}

#endif /* BPFTIME_OVERRIDE_ATTACH_H */
