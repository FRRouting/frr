// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2017-20  David Lamparter, for NetDEF, Inc.
 */

#ifndef _FRR_XREF_H
#define _FRR_XREF_H

#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include "compiler.h"
#include "typesafe.h"

#ifdef __cplusplus
extern "C" {
#endif

enum xref_type {
	XREFT_NONE = 0,

	XREFT_EVENTSCHED = 0x100,

	XREFT_LOGMSG = 0x200,
	XREFT_ASSERT = 0x280,

	XREFT_DEFUN = 0x300,
	XREFT_INSTALL_ELEMENT = 0x301,
};

/* struct xref is the "const" part;  struct xrefdata is the writable part. */
struct xref;
struct xrefdata;

struct xref {
	/* this may be NULL, depending on the type of the xref.
	 * if it is NULL, the xref has no unique ID and cannot be accessed
	 * through that mechanism.
	 */
	struct xrefdata *xrefdata;

	/* type isn't generally needed at runtime */
	enum xref_type type;

	/* code location */
	int line;
	const char *file;
	const char *func;

	/* -- 32 bytes (on 64bit) -- */

	/* type-specific bits appended by embedding this struct */
};

PREDECL_RBTREE_UNIQ(xrefdata_uid);

struct xrefdata {
	/* pointer back to the const part;  this will be initialized at
	 * program startup by xref_block_add().  (Creating structs with
	 * cyclic pointers to each other is not easily possible for
	 * function-scoped static variables.)
	 *
	 * There is no xrefdata w/o xref, but there are xref w/o xrefdata.
	 */
	const struct xref *xref;

	/* base32(crockford) of unique ID.  not all bytes are used, but
	 * let's pad to 16 for simplicity
	 */
	char uid[16];

	/* hash/uid input
	 * if hashstr is NULL, no UID is assigned/calculated.  Use macro
	 * string concatenation if multiple values need to be fed in.
	 * (This is here to not make the UID calculation independent of
	 * xref type.)
	 */
	const char *hashstr;
	uint32_t hashu32[2];

	/* -- 32 bytes (on 64bit) -- */
	struct xrefdata_uid_item xui;
};

static inline int xrefdata_uid_cmp(const struct xrefdata *a,
				   const struct xrefdata *b)
{
	return strcmp(a->uid, b->uid);
}

DECLARE_RBTREE_UNIQ(xrefdata_uid, struct xrefdata, xui, xrefdata_uid_cmp);
extern struct xrefdata_uid_head xrefdata_uid;

/* linker "magic" is used to create an array of pointers to struct xref.
 * the result is a contiguous block of pointers, each pointing to an xref
 * somewhere in the code.  The linker gives us start and end pointers, we
 * stuff those into the struct below and hook up a constructor to run at
 * program startup with the struct passed.
 *
 * Placing the xrefs themselves into an array doesn't work because they'd
 * need to be constant size, but we're embedding struct xref into other
 * container structs with extra data.  Also this means that external code
 * (like the python xref dumper) can safely ignore extra data at the end of
 * xrefs without needing to account for size in iterating the array.
 *
 * If you're curious, this is also how __attribute__((constructor)) (and
 * destructor) are implemented - there are 2 arrays, ".init_array" and
 * ".fini_array", containing function pointers.  The magic turns out to be
 * quite mundane, actually ;)
 *
 * The slightly tricky bit is that this is a per-object (i.e. per shared
 * library & daemon) thing and we need a bit of help (in XREF_SETUP) to
 * initialize correctly.
 */

struct xref_block {
	struct xref_block *next;
	const struct xref * const *start;
	const struct xref * const *stop;
};

extern struct xref_block *xref_blocks;
extern void xref_block_add(struct xref_block *block);
extern void xref_gcc_workaround(const struct xref *xref);

#ifndef HAVE_SECTION_SYMS
/* we have a build system patch to use GNU ld on Solaris;  if that doesn't
 * work we end up on Solaris ld which doesn't support the section start/end
 * symbols.
 */
#define XREF_SETUP() \
	CPP_NOTICE("Missing linker support for section arrays.  Solaris ld?")
#else
/* the actual symbols that the linker provides for us.  Note these are
 * _symbols_ referring to the actual section start/end, i.e. they are very
 * much NOT _pointers_, rather the symbol *value* is the pointer.  Declaring
 * them as size-1 arrays is the "best" / "right" thing.
 */
extern const struct xref * const __start_xref_array[1] DSO_LOCAL;
extern const struct xref * const __stop_xref_array[1] DSO_LOCAL;

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
/* no redzone around each of the xref_p please, we're building an array out
 * of variables here.  kinda breaks things if there's redzones between each
 * array item.
 */
#define xref_array_attr used, section("xref_array"), no_sanitize("address")
#endif
#endif
#ifndef xref_array_attr
#define xref_array_attr used, section("xref_array")
#endif

/* this macro is invoked once for each standalone DSO through
 *   FRR_MODULE_SETUP  \
 *                      }-> FRR_COREMOD_SETUP -> XREF_SETUP
 *   FRR_DAEMON_INFO   /
 */
#define XREF_SETUP()                                                           \
	static const struct xref _dummy_xref = {                               \
			/* .xrefdata = */ NULL,                                \
			/* .type = */ XREFT_NONE,                              \
			/* .line = */ __LINE__,                                \
			/* .file = */ __FILE__,                                \
			/* .func = */ "dummy",                                 \
	};                                                                     \
	static const struct xref * const _dummy_xref_p                         \
			__attribute__((xref_array_attr)) = &_dummy_xref;       \
	static void __attribute__((used, _CONSTRUCTOR(1100)))                  \
			_xref_init(void) {                                     \
		static struct xref_block _xref_block = {                       \
			.next = NULL,                                          \
			.start = __start_xref_array,                           \
			.stop = __stop_xref_array,                             \
		};                                                             \
		xref_block_add(&_xref_block);                                  \
	}                                                                      \
	asm(XREF_NOTE);                                                        \
	MACRO_REQUIRE_SEMICOLON() /* end */

/* the following blurb emits an ELF note indicating start and end of the xref
 * array in the binary.  This is technically the "correct" entry point for
 * external tools reading xrefs out of an ELF shared library or executable.
 *
 * right now, the extraction tools use the section header for "xref_array"
 * instead; however, section headers are technically not necessarily preserved
 * for fully linked libraries or executables.  (In practice they are only
 * stripped by obfuscation tools.)
 *
 * conversely, for reading xrefs out of a single relocatable object file (e.g.
 * bar.o), section headers are the right thing to look at since the note is
 * only emitted for the final binary once.
 *
 * FRR itself does not need this note to operate correctly, so if you have
 * some build issue with it just add -DFRR_XREF_NO_NOTE to your build flags
 * to disable it.
 */
#if defined(FRR_XREF_NO_NOTE) || defined(__mips64)
#define XREF_NOTE ""

/* mips64 note:  MIPS64 (regardless of endianness, both mips64 & mips64el)
 * does not have a 64-bit PC-relative relocation type.  Unfortunately, a
 * 64-bit PC-relative relocation is exactly what the below asm magic emits.
 * Therefore, the xref ELF note is permanently disabled on MIPS64.
 *
 * For some context, refer to https://reviews.llvm.org/D80390
 *
 * As noted above, xref extraction still works through the section header
 * path, so no functionality is lost.
 */
#else

#if __SIZEOF_POINTER__ == 4
#define _NOTE_2PTRSIZE	"8"
#define _NOTE_PTR	".long"
#elif __SIZEOF_POINTER__ == 8
#define _NOTE_2PTRSIZE	"16"
#define _NOTE_PTR	".quad"
#else
#error unsupported pointer size
#endif

#ifdef __arm__
# define asmspecial "%"
#else
# define asmspecial "@"
#endif

#define XREF_NOTE                                                              \
	""                                                                 "\n"\
	"	.type _frr_xref_note," asmspecial "object"                 "\n"\
	"	.pushsection .note.FRR,\"a\"," asmspecial "note"           "\n"\
	"	.p2align 2"                                                "\n"\
	"_frr_xref_note:"                                                  "\n"\
	"	.long	9"                                                 "\n"\
	"	.long	" _NOTE_2PTRSIZE                                   "\n"\
	"	.ascii	\"XREF\""                                          "\n"\
	"	.ascii	\"FRRouting\\0\\0\\0\""                            "\n"\
	"	" _NOTE_PTR "	__start_xref_array-."                      "\n"\
	"	" _NOTE_PTR "	__stop_xref_array-."                       "\n"\
	"	.size _frr_xref_note, .-_frr_xref_note"                    "\n"\
	"	.popsection"                                               "\n"\
	""                                                                 "\n"\
	/* end */
#endif

#endif /* HAVE_SECTION_SYMS */

/* emit the array entry / pointer to xref */
#if defined(__clang__) || !defined(__cplusplus)
#define XREF_LINK(dst)                                                         \
	static const struct xref * const NAMECTR(xref_p_)                      \
			__attribute__((xref_array_attr))                       \
		= &(dst)                                                       \
	/* end */

#else /* GCC && C++ */
/* workaround for GCC bug 41091 (dated 2009), added in 2021...
 *
 * this breaks extraction of xrefs with xrelfo.py (because the xref_array
 * entry will be missing), but provides full runtime functionality.  To get
 * the proper list of xrefs from C++ code, build with clang...
 */
struct _xref_p {
	const struct xref * const ptr;

	_xref_p(const struct xref *_ptr) : ptr(_ptr)
	{
		xref_gcc_workaround(_ptr);
	}
};

#define XREF_LINK(dst)                                                         \
	static const struct _xref_p __attribute__((used))                      \
			NAMECTR(xref_p_)(&(dst))                               \
	/* end */
#endif

/* initializer for a "struct xref" */
#define XREF_INIT(type_, xrefdata_, func_)                                     \
	{                                                                      \
		/* .xrefdata = */ (xrefdata_),                                 \
		/* .type = */ (type_),                                         \
		/* .line = */ __LINE__,                                        \
		/* .file = */ __FILE__,                                        \
		/* .func = */ func_,                                           \
	}                                                                      \
	/* end */

/* use with XREF_INIT when outside of a function, i.e. no __func__ */
#define XREF_NO_FUNC	"<global>"

#ifdef __cplusplus
}
#endif

#endif /* _FRR_XREF_H */
