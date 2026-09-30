// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2016  David Lamparter, for NetDEF, Inc.
 */

#ifndef _FRR_HOOK_H
#define _FRR_HOOK_H

#include <stdbool.h>

#include "module.h"
#include "memory.h"

#ifdef __cplusplus
extern "C" {
#endif

/* type-safe subscribable hook points
 *
 * where "type-safe" applies to the function pointers used for subscriptions
 *
 * overall usage:
 * - to create a hook:
 *
 *   mydaemon.h:
 *     #include "hook.h"
 *     DECLARE_HOOK (some_update_event, (struct eventinfo *info), (info));
 *
 *   mydaemon.c:
 *     DEFINE_HOOK (some_update_event, (struct eventinfo *info), (info));
 *     ...
 *     hook_call (some_update_event, info)
 *
 * Note:  the second and third macro args must be the hook function's
 * parameter list, with the same names for each parameter.  The second
 * macro arg is with types (used for defining things), the third arg is
 * just the names (used for passing along parameters).
 *
 * Do not use parameter names starting with "hook", these can collide with
 * names used by the hook code itself.
 *
 * The return value is always "int" for now;  hook_call will sum up the
 * return values from each registered user.  Default is 0.
 *
 * There are no pre-defined semantics for the value, in most cases it is
 * ignored.  For success/failure indication, 0 should be success, and
 * handlers should make sure to only return 0 or 1 (not -1 or other values).
 *
 *
 * - to use a hook / create a handler:
 *
 *     #include "mydaemon.h"
 *     int event_handler (struct eventinfo *info) { ... }
 *     hook_register (some_update_event, event_handler);
 *
 *   or, if you need an argument to be passed along (addonptr will be added
 *   as first argument when calling the handler):
 *
 *     #include "mydaemon.h"
 *     int event_handler (void *addonptr, struct eventinfo *info) { ... }
 *     hook_register_arg (some_update_event, event_handler, addonptr);
 *
 *   (addonptr isn't typesafe, but that should be manageable.)
 *
 * Hooks also support a "priority" value for ordering registered calls
 * relative to each other.  The priority is a signed integer where lower
 * values are called earlier.  There is also "Koohs", which is hooks with
 * reverse priority ordering (for cleanup/deinit hooks, so you can use the
 * same priority value).
 *
 * Recommended priority value ranges are:
 *
 *  -999 ...     0 ...  999 - main executable / daemon, or library
 * -1999 ... -1000          - modules registering calls that should run before
 *                            the daemon's bits
 *            1000 ... 1999 - modules calls that should run after daemon's
 *
 * Note: the default value is 1000, based on the following 2 expectations:
 * - most hook_register() usage will be in loadable modules
 * - usage of hook_register() in the daemon itself may need relative ordering
 *   to itself, making an explicit value the expected case
 *
 * The priority value is passed as extra argument on hook_register_prio() /
 * hook_register_arg_prio().  Whether a hook runs in reverse is determined
 * solely by the code defining / calling the hook.  (DECLARE_KOOH is actually
 * the same thing as DECLARE_HOOK, it's just there to make it obvious.)
 */

/* TODO:
 * - hook_unregister_all_module()
 * - introspection / CLI / debug
 * - testcases ;)
 *
 * For loadable modules, the idea is that hooks could be automatically
 * unregistered when a module is unloaded.
 *
 * It's also possible to add a constructor (MTYPE style) to DEFINE_HOOK,
 * which would make it possible for the CLI to show all hooks and all
 * registered handlers.
 */

struct hookent {
	struct hookent *next;
	void *hookfn; /* actually a function pointer */
	void *hookarg;
	bool has_arg : 1;
	bool ent_on_heap : 1;
	bool ent_used : 1;
	int priority;
	struct frrmod_runtime *module;
	const char *fnname;
};

struct hook {
	const char *name;
	struct hookent *entries;
	bool reverse;
};

#define HOOK_DEFAULT_PRIORITY 1000

/* subscribe/add callback function to a hook
 *
 * always use hook_register(), which uses the static inline helper from
 * DECLARE_HOOK in order to get type safety
 */
extern void _hook_register(struct hook *hook, struct hookent *stackent,
			   void *funcptr, void *arg, bool has_arg,
			   struct frrmod_runtime *module,
			   const char *funcname, int priority);

/* most hook_register calls are not in a loop or similar and can use a
 * statically allocated "struct hookent" from the data segment
 */
#define _hook_reg_svar(hook, funcptr, arg, has_arg, module, funcname, prio)    \
	do {                                                                   \
		static struct hookent stack_hookent = {};                      \
		_hook_register(hook, &stack_hookent, funcptr, arg, has_arg,    \
			       module, funcname, prio);                        \
	} while (0)

#define hook_register(hookname, func)                                          \
	_hook_reg_svar(&_hook_##hookname, _hook_typecheck_##hookname(func),    \
		       NULL, false, THIS_MODULE, #func, HOOK_DEFAULT_PRIORITY)
#define hook_register_arg(hookname, func, arg)                                 \
	_hook_reg_svar(&_hook_##hookname,                                      \
		       _hook_typecheck_arg_##hookname(func), arg, true,        \
		       THIS_MODULE, #func, HOOK_DEFAULT_PRIORITY)
#define hook_register_prio(hookname, prio, func)                               \
	_hook_reg_svar(&_hook_##hookname, _hook_typecheck_##hookname(func),    \
		       NULL, false, THIS_MODULE, #func, prio)
#define hook_register_arg_prio(hookname, prio, func, arg)                      \
	_hook_reg_svar(&_hook_##hookname,                                      \
		       _hook_typecheck_arg_##hookname(func), arg, true,        \
		       THIS_MODULE, #func, prio)

extern void _hook_unregister(struct hook *hook, void *funcptr, void *arg,
			     bool has_arg);
#define hook_unregister(hookname, func)                                        \
	_hook_unregister(&_hook_##hookname, _hook_typecheck_##hookname(func),  \
			 NULL, false)
#define hook_unregister_arg(hookname, func, arg)                               \
	_hook_unregister(&_hook_##hookname,                                    \
			 _hook_typecheck_arg_##hookname(func), arg, true)

#define hook_have_hooks(hookname) (_hook_##hookname.entries != NULL)

/* invoke hooks
 * this is private (static) to the file that has the DEFINE_HOOK statement
 */
#define hook_call(hookname, ...) hook_call_##hookname(__VA_ARGS__)

/* helpers to add the void * arg */
#define _HOOK_COMMA_ARGNAME(decl, name, ...) , name
#define _HOOK_COMMA_ARGDECL(decl, name, ...) , decl name

#define _HOOK_JOIN_(NAME, ...) _MACRO_REPEAT0(_EMPTY, NAME, MACRO_APPLY, ##__VA_ARGS__)
#define _HOOK_JOIN(...)	       _HOOK_JOIN_(__VA_ARGS__)
#define HOOK_ADDARG(...)       (hookarg _HOOK_JOIN(_HOOK_COMMA_ARGNAME, ##__VA_ARGS__))
#define HOOK_ADDDEF(...)       (void *hookarg _HOOK_JOIN(_HOOK_COMMA_ARGDECL, ##__VA_ARGS__))

/* and another helper to convert () into (void) to get a proper prototype */
#define _SKIP_10(x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, ret, ...) ret
#define _MAKE_VOID(...) _SKIP_10(, ##__VA_ARGS__, , , , , , , , , , void)

#define _HOOK_ARGNAME(decl, name, ...) name
#define _HOOK_ARGDECL(decl, name, ...) decl name

#define _HOOK_COMMA_JOIN_(NAME, ...) _MACRO_REPEAT0(_COMMA, NAME, MACRO_APPLY, ##__VA_ARGS__)
#define _HOOK_COMMA_JOIN(...)	     _HOOK_COMMA_JOIN_(__VA_ARGS__)

#define HOOK_PASSARG(...) (_HOOK_COMMA_JOIN(_HOOK_ARGNAME, ##__VA_ARGS__))
#define HOOK_VOIDIFY(...) (_MAKE_VOID(__VA_ARGS__) _HOOK_COMMA_JOIN(_HOOK_ARGDECL, ##__VA_ARGS__))

/* use in header file - declares the hook and its arguments
 * usage:  DECLARE_HOOK(my_hook, (int arg1, struct foo *arg2), (arg1, arg2));
 * as above, "passlist" must use the same order and same names as "arglist"
 *
 * theoretically passlist is not necessary, but let's keep things simple and
 * use exact same args on DECLARE and DEFINE.
 */
#define DECLARE_HOOK(hookname, ...)                                                               \
	extern struct hook _hook_##hookname;                                                      \
	__attribute__((unused)) static inline void *_hook_typecheck_##hookname(                   \
		int(*funcptr) HOOK_VOIDIFY(__VA_ARGS__))                                          \
	{                                                                                         \
		return (void *)funcptr;                                                           \
	}                                                                                         \
	__attribute__((unused)) static inline void *_hook_typecheck_arg_##hookname(               \
		int(*funcptr) HOOK_ADDDEF(__VA_ARGS__))                                           \
	{                                                                                         \
		return (void *)funcptr;                                                           \
	}                                                                                         \
	MACRO_REQUIRE_SEMICOLON() /* end */

#define DECLARE_KOOH(hookname, ...) DECLARE_HOOK(hookname, ##__VA_ARGS__)

/* use in source file - contains hook-related definitions.
 */
#define DEFINE_HOOK_INT(hookname, arglist, rev)                                                   \
	struct hook _hook_##hookname = {                                                          \
		.name = #hookname,                                                                \
		.entries = NULL,                                                                  \
		.reverse = rev,                                                                   \
	};                                                                                        \
	static int hook_call_##hookname HOOK_VOIDIFY arglist                                      \
	{                                                                                         \
		int hooksum = 0;                                                                  \
		struct hookent *he = _hook_##hookname.entries;                                    \
		void *hookarg;                                                                    \
		union {                                                                           \
			void *voidptr;                                                            \
			int(*fptr) HOOK_VOIDIFY arglist;                                          \
			int(*farg) HOOK_ADDDEF arglist;                                           \
		} hookp;                                                                          \
		for (; he; he = he->next) {                                                       \
			hookarg = he->hookarg;                                                    \
			hookp.voidptr = he->hookfn;                                               \
			if (!he->has_arg)                                                         \
				hooksum += hookp.fptr HOOK_PASSARG arglist;                       \
			else                                                                      \
				hooksum += hookp.farg HOOK_ADDARG arglist;                        \
		}                                                                                 \
		return hooksum;                                                                   \
	}                                                                                         \
	MACRO_REQUIRE_SEMICOLON() /* end */

#define DEFINE_HOOK(hookname, ...) DEFINE_HOOK_INT(hookname, (__VA_ARGS__), false)
#define DEFINE_KOOH(hookname, ...) DEFINE_HOOK_INT(hookname, (__VA_ARGS__), true)

#ifdef __cplusplus
}
#endif

#endif /* _FRR_HOOK_H */
