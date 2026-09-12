// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2016  David Lamparter, for NetDEF, Inc.
 */

/* Header intended to be included multiple times - no include guard! */
#ifdef DO_HOOK
#error Definitions from previous hooks_begin.h around - forgot hooks_end.h somewhere?
#endif

/* DO => DECLARE */
#if defined(HOOKS_DECLARE)
#define DO_HOOK DECLARE_HOOK
#define DO_KOOH DECLARE_KOOH

/* DO => DEFINE */
#elif defined(HOOKS_DEFINE)
#define DO_HOOK DEFINE_HOOK
#define DO_KOOH DEFINE_KOOH

/* DO => LUA */
#elif defined(HOOKS_LUA)
#define DO_HOOK LUA_HOOK
#define DO_KOOH LUA_HOOK

#else
#error No operation requested, define one of HOOKS_DECLARE, HOOKS_DEFINE or HOOKS_LUA!
#endif
