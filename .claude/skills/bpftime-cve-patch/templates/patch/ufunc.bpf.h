/* SPDX-License-Identifier: MIT
 *
 * ufunc: call the TARGET process's own functions BY NAME from inside an eBPF
 * patch — used to recreate an upstream fix faithfully when the correct behavior
 * needs the application's own helpers (as the real Redis xgroup fix calls
 * lookupKeyWrite/checkType).
 *
 * Verified against bpftime core:
 *   - dispatcher helper id = 1000, find-id helper id = 1001
 *     (runtime/src/bpftime_internal.h, registered in
 *      runtime/extension/extension_helper.cpp).
 *   - The `ufunc` helper group is ON by default. If you set BPFTIME_HELPER_GROUPS
 *     you MUST include `ufunc`, e.g. BPFTIME_HELPER_GROUPS=ufunc,kernel,shm_map
 *   - Up to 6 args are marshalled (runtime/src/ufunc.cpp).
 *   - The loader/host side must register the symbol->address mapping (dlsym-based
 *     resolver) so find-id can resolve the name.
 */
#ifndef BPFTIME_UFUNC_BPF_H
#define BPFTIME_UFUNC_BPF_H

typedef unsigned long long __ufunc_u64;

struct arg_list {
	__ufunc_u64 args[6];
};

#define UFUNC_HELPER_ID_DISPATCHER 1000
#define UFUNC_HELPER_ID_FIND_ID 1001

static __ufunc_u64 (*ufunc_call)(__ufunc_u64 id, __ufunc_u64 arg_list) =
	(void *)UFUNC_HELPER_ID_DISPATCHER;
static __ufunc_u64 (*ufunc_find_func_id)(const char *func_name) =
	(void *)UFUNC_HELPER_ID_FIND_ID;

#define UFUNC_CALL_0(func)                                                     \
	({                                                                     \
		struct arg_list _a = { 0 };                                    \
		ufunc_call((func), (__ufunc_u64)&_a);                          \
	})
#define UFUNC_CALL_1(func, a1)                                                 \
	({                                                                     \
		struct arg_list _a = { 0 };                                    \
		_a.args[0] = (__ufunc_u64)(a1);                                \
		ufunc_call((func), (__ufunc_u64)&_a);                          \
	})
#define UFUNC_CALL_2(func, a1, a2)                                             \
	({                                                                     \
		struct arg_list _a = { 0 };                                    \
		_a.args[0] = (__ufunc_u64)(a1);                                \
		_a.args[1] = (__ufunc_u64)(a2);                                \
		ufunc_call((func), (__ufunc_u64)&_a);                          \
	})
#define UFUNC_CALL_3(func, a1, a2, a3)                                         \
	({                                                                     \
		struct arg_list _a = { 0 };                                    \
		_a.args[0] = (__ufunc_u64)(a1);                                \
		_a.args[1] = (__ufunc_u64)(a2);                                \
		_a.args[2] = (__ufunc_u64)(a3);                                \
		ufunc_call((func), (__ufunc_u64)&_a);                          \
	})

#define UFUNC_CALL_NAME_0(name)                                                \
	({                                                                     \
		char _n[] = name;                                              \
		UFUNC_CALL_0(ufunc_find_func_id(_n));                          \
	})
#define UFUNC_CALL_NAME_1(name, a1)                                            \
	({                                                                     \
		char _n[] = name;                                              \
		UFUNC_CALL_1(ufunc_find_func_id(_n), a1);                      \
	})
#define UFUNC_CALL_NAME_2(name, a1, a2)                                        \
	({                                                                     \
		char _n[] = name;                                              \
		UFUNC_CALL_2(ufunc_find_func_id(_n), a1, a2);                  \
	})
#define UFUNC_CALL_NAME_3(name, a1, a2, a3)                                    \
	({                                                                     \
		char _n[] = name;                                              \
		UFUNC_CALL_3(ufunc_find_func_id(_n), a1, a2, a3);              \
	})

#endif /* BPFTIME_UFUNC_BPF_H */
