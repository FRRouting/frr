/*
 * Copyright (c) 2016  David Lamparter, for NetDEF, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef _FRR_HOOK_H
#define _FRR_HOOK_H

#include <stdbool.h>

#include "module.h"
#include "memory.h"

/* type-safe subscribable hook points
 *
 * where "type-safe" applies to the function pointers used for subscriptions
 *
 * overall usage:
 * - to create a hook:
 *
 *   mydaemon.h:
 *     #include "hook.h"
 *     DECLARE_HOOK (some_update_event, (struct eventinfo *info), (info))
 *
 *   mydaemon.c:
 *     DEFINE_HOOK (some_update_event, (struct eventinfo *info), (info))
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
	bool has_arg;
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
extern void _hook_register(struct hook *hook, void *funcptr, void *arg,
			   bool has_arg, struct frrmod_runtime *module,
			   const char *funcname, int priority);
#define hook_register(hookname, func)                                          \
	_hook_register(&_hook_##hookname, _hook_typecheck_##hookname(func),    \
		       NULL, false, THIS_MODULE, #func, HOOK_DEFAULT_PRIORITY)
#define hook_register_arg(hookname, func, arg)                                 \
	_hook_register(&_hook_##hookname,                                      \
		       _hook_typecheck_arg_##hookname(func), arg, true,        \
		       THIS_MODULE, #func, HOOK_DEFAULT_PRIORITY)
#define hook_register_prio(hookname, prio, func)                               \
	_hook_register(&_hook_##hookname, _hook_typecheck_##hookname(func),    \
		       NULL, false, THIS_MODULE, #func, prio)
#define hook_register_arg_prio(hookname, prio, func, arg)                      \
	_hook_register(&_hook_##hookname,                                      \
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

/* invoke hooks
 * this is private (static) to the file that has the DEFINE_HOOK statement
 */
#define hook_call(hookname, ...) hook_call_##hookname(__VA_ARGS__)

/* helpers to add the void * arg */
#define HOOK_ADDDEF(...) (void *hookarg , ## __VA_ARGS__)
#define HOOK_ADDARG(...) (hookarg , ## __VA_ARGS__)

/* use in header file - declares the hook and its arguments
 * usage:  DECLARE_HOOK(my_hook, (int arg1, struct foo *arg2), (arg1, arg2))
 * as above, "passlist" must use the same order and same names as "arglist"
 *
 * theoretically passlist is not neccessary, but let's keep things simple and
 * use exact same args on DECLARE and DEFINE.
 */
#define DECLARE_HOOK(hookname, arglist, passlist)                              \
	extern struct hook _hook_##hookname;                                   \
	__attribute__((unused)) static void *_hook_typecheck_##hookname(       \
		int(*funcptr) arglist)                                         \
	{                                                                      \
		return (void *)funcptr;                                        \
	}                                                                      \
	__attribute__((unused)) static void *_hook_typecheck_arg_##hookname(   \
		int(*funcptr) HOOK_ADDDEF arglist)                             \
	{                                                                      \
		return (void *)funcptr;                                        \
	}
#define DECLARE_KOOH(hookname, arglist, passlist)                              \
	DECLARE_HOOK(hookname, arglist, passlist)

/* use in source file - contains hook-related definitions.
 */
#define DEFINE_HOOK_INT(hookname, arglist, passlist, rev)                      \
	struct hook _hook_##hookname = {                                       \
		.name = #hookname, .entries = NULL, .reverse = rev,            \
	};                                                                     \
	static int hook_call_##hookname arglist                                \
	{                                                                      \
		int hooksum = 0;                                               \
		struct hookent *he = _hook_##hookname.entries;                 \
		void *hookarg;                                                 \
		union {                                                        \
			void *voidptr;                                         \
			int(*fptr) arglist;                                    \
			int(*farg) HOOK_ADDDEF arglist;                        \
		} hookp;                                                       \
		for (; he; he = he->next) {                                    \
			hookarg = he->hookarg;                                 \
			hookp.voidptr = he->hookfn;                            \
			if (!he->has_arg)                                      \
				hooksum += hookp.fptr passlist;                \
			else                                                   \
				hooksum += hookp.farg HOOK_ADDARG passlist;    \
		}                                                              \
		return hooksum;                                                \
	}

#define DEFINE_HOOK(hookname, arglist, passlist)                               \
	DEFINE_HOOK_INT(hookname, arglist, passlist, false)
#define DEFINE_KOOH(hookname, arglist, passlist)                               \
	DEFINE_HOOK_INT(hookname, arglist, passlist, true)

#endif /* _FRR_HOOK_H */
