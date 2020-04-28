/*
 * Copyright (c) 2017-20  David Lamparter, for NetDEF, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _FRR_XREF_H
#define _FRR_XREF_H

#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include "compiler.h"

enum xref_type {
	XREFT_NONE = 0,

	XREFT_THREADSCHED,

	XREFT_threadsched = XREFT_THREADSCHED,
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
	char prefix[16];

	/* hash/uid input
	 * if hashstr is NULL, no UID is assigned/calculated.  Use macro
	 * string concatenation if multiple values need to be fed in.
	 * (This is here to not make the UID calculation independent of
	 * xref type.)
	 */
	const char *hashstr;
	uint32_t hashu32[2];

	/* -- 32 bytes (on 64bit) -- */
};

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
	const struct xref * const * start;
	const struct xref * const * stop;
};

extern struct xref_block *xref_blocks;
extern void xref_block_add(struct xref_block *block);

#ifndef HAVE_SECTION_SYMS
/* we have a build system patch to use GNU ld on Solaris;  if that doesn't
 * work we end up on Solaris ld which doesn't support the section start/end
 * symbols.
 */
#define XREF_SETUP() \
	CPP_NOTICE("Missing linker support for section arrays.  Solaris linker?")
#else
/* the actual symbols that the linker provides for us.  Note these are
 * _symbols_ referring to the actual section start/end, i.e. they are very
 * much NOT _pointers_, rather the symbol *value* is the pointer.  Declaring
 * them as size-1 arrays is the "best" / "right" thing.
 */
extern const struct xref * const __start_xref_array[1] DSO_LOCAL;
extern const struct xref * const __stop_xref_array[1] DSO_LOCAL;

/* this macro is invoked once for each standalone DSO through
 *   FRR_MODULE_SETUP  \
 *                      }-> FRR_COREMOD_SETUP -> XREF_SETUP
 *   FRR_DAEMON_INFO   /
 */
#define XREF_SETUP()                                                           \
	static const struct xref _dummy_xref = {                               \
			.file = __FILE__, .line = __LINE__, .func = "dummy",   \
			.type = XREFT_NONE,                                    \
	};                                                                     \
	static const struct xref * const _dummy_xref_p                         \
			__attribute__((used, section("xref_array")))           \
			= &_dummy_xref;                                        \
	static void __attribute__((used, _CONSTRUCTOR(1100)))                  \
			_xref_init(void) {                                     \
		static struct xref_block _xref_block = {                       \
			.start = __start_xref_array,                           \
			.stop = __stop_xref_array,                             \
		};                                                             \
		xref_block_add(&_xref_block);                                  \
	}                                                                      \
	asm(XREF_NOTE);                                                        \
	/* end */

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
#ifdef FRR_XREF_NO_NOTE
#define XREF_NOTE ""
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
#define XREF_ARRAYENT(dst)                                                     \
	static const struct xref * const NAMECTR(xref_p_)                      \
			__attribute__((used, section("xref_array")))           \
		= &(dst)                                                       \
	/* end */

/* initializer for a "struct xref" */
#define XREF_INIT(type_, xrefdata_, func_)                                     \
	{                                                                      \
		.type = (type_), .xrefdata = (xrefdata_),                      \
		.file = __FILE__, .line = __LINE__, .func = func_,             \
	}                                                                      \
	/* end */

#define DEFINE_XREF(name, type_, xrefdata_, ...)                               \
	static const struct xref_ ## type_ name __attribute__((used)) = {      \
		.xref = XREF_INIT(XREFT_ ## type_, xrefdata_, __func__),       \
		__VA_ARGS__                                                    \
	};                                                                     \
	XREF_ARRAYENT(name.xref)                                               \
	/* end */

/* same as above, but without __func__ (which raises an error on file scope) */
#define DEFINE_XREF_NOFN(name, type_, xrefdata_, ...)                          \
	static const struct xref_ ## type_ name __attribute__((used)) = {      \
		.xref = XREF_INIT(XREFT_ ## type_, xrefdata_, "<global>"),     \
		__VA_ARGS__                                                    \
	};                                                                     \
	XREF_ARRAYENT(name.xref)                                               \
	/* end */

#ifdef __cplusplus
}
#endif

#endif /* _FRR_XREF_H */
