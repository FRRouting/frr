// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2016  David Lamparter, for NetDEF, Inc.
 */

/* Header intended to be included multiple times - no include guard! */
#ifndef DO_HOOK
#error No hook definitions active - hooks_end.h without hooks_begin.h?
#endif

#undef DO_HOOK
#undef DO_KOOH

#ifdef HOOKS_DECLARE
#undef HOOKS_DECLARE
#endif
#ifdef HOOKS_DEFINE
#undef HOOKS_DEFINE
#endif
#ifdef HOOKS_LUA
#undef HOOKS_LUA
#endif
