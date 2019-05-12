/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 *
 * Copyright (c) 2011 The FreeBSD Foundation
 * All rights reserved.
 * Portions of this software were developed by David Chisnall
 * under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

/*
 * Actual printf innards.
 *
 * This code is large and complicated...
 */

#include <sys/types.h>
#include <sys/uio.h>

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include <stdarg.h>

#include "printflocal.h"

#define	CHAR	char
#include "printfcommon.h"

#ifdef WCHAR_SUPPORT
/*
 * Convert a wide character string argument for the %ls format to a multibyte
 * string representation. If not -1, prec specifies the maximum number of
 * bytes to output, and also means that we can't assume that the wide char.
 * string ends is null-terminated.
 */
static char *
__wcsconv(wchar_t *wcsarg, int prec)
{
	static const mbstate_t initial;
	mbstate_t mbs;
	char buf[MB_LEN_MAX];
	wchar_t *p;
	char *convbuf;
	size_t clen, nbytes;

	/* Allocate space for the maximum number of bytes we could output. */
	if (prec < 0) {
		p = wcsarg;
		mbs = initial;
		nbytes = wcsrtombs(NULL, (const wchar_t **)&p, 0, &mbs);
		if (nbytes == (size_t)-1)
			return (NULL);
	} else {
		/*
		 * Optimisation: if the output precision is small enough,
		 * just allocate enough memory for the maximum instead of
		 * scanning the string.
		 */
		if (prec < 128)
			nbytes = prec;
		else {
			nbytes = 0;
			p = wcsarg;
			mbs = initial;
			for (;;) {
				clen = wcrtomb(buf, *p++, &mbs);
				if (clen == 0 || clen == (size_t)-1 ||
				    nbytes + clen > (size_t)prec)
					break;
				nbytes += clen;
			}
		}
	}
	if ((convbuf = malloc(nbytes + 1)) == NULL)
		return (NULL);

	/* Fill the output buffer. */
	p = wcsarg;
	mbs = initial;
	if ((nbytes = wcsrtombs(convbuf, (const wchar_t **)&p,
	    nbytes, &mbs)) == (size_t)-1) {
		free(convbuf);
		return (NULL);
	}
	convbuf[nbytes] = '\0';
	return (convbuf);
}
#endif /* WCHAR_SUPPORT */

/*
 * The size of the buffer we use as scratch space for integer
 * conversions, among other things.  We need enough space to
 * write a uintmax_t in octal (plus one byte).
 */
#if UINTMAX_MAX <= UINT64_MAX
#define	BUF	64
#else
#error "BUF must be large enough to format a uintmax_t"
#endif

/*
 * Non-MT-safe version
 */
ssize_t
vbprintfrr(struct fbuf *cb, const char *fmt0, va_list ap)
{
	const char *fmt;	/* format string */
	int ch;			/* character from fmt */
	int n, n2;		/* handy integer (short term usage) */
	const char *cp;		/* handy char pointer (short term usage) */
	int flags;		/* flags as above */
	int ret;		/* return value accumulator */
	int width;		/* width from format (%8d), or 0 */
	int prec;		/* precision from format; <0 for N/A */
	int saved_errno;
	char sign;		/* sign prefix (' ', '+', '-', or \0) */

	u_long	ulval = 0;	/* integer arguments %[diouxX] */
	uintmax_t ujval = 0;	/* %j, %ll, %q, %t, %z integers */
	void *ptrval;		/* %p */
	int base;		/* base for [diouxX] conversion */
	int dprec;		/* a copy of prec if [diouxX], 0 otherwise */
	int realsz;		/* field size expanded by dprec, sign, etc */
	int size;		/* size of converted field or string */
	int prsize;             /* max size of printed field */
	const char *xdigs;     	/* digits for %[xX] conversion */
	struct io_state io;	/* I/O buffering state */
	char buf[BUF];		/* buffer with space for digits of uintmax_t */
	char ox[2];		/* space for 0x; ox[1] is either x, X, or \0 */
	union arg *argtable;    /* args, built due to positional arg */
	union arg statargtable [STATIC_ARG_TBL_SIZE];
	int nextarg;            /* 1-based argument index */
	va_list orgap;          /* original argument pointer */
	char *convbuf;		/* wide to multibyte conversion result */

	static const char xdigs_lower[16] = "0123456789abcdef";
	static const char xdigs_upper[16] = "0123456789ABCDEF";

	/* BEWARE, these `goto error' on error. */
#define	PRINT(ptr, len) { \
	if (io_print(&io, (ptr), (len)))	\
		goto error; \
}
#define	PAD(howmany, with) { \
	if (io_pad(&io, (howmany), (with))) \
		goto error; \
}
#define	PRINTANDPAD(p, ep, len, with) {	\
	if (io_printandpad(&io, (p), (ep), (len), (with))) \
		goto error; \
}
#define	FLUSH() do { } while (0)

	/*
	 * Get the argument indexed by nextarg.   If the argument table is
	 * built, use it to get the argument.  If its not, get the next
	 * argument (and arguments must be gotten sequentially).
	 */
#define GETARG(type) \
	((argtable != NULL) ? *((type*)(&argtable[nextarg++])) : \
	    (nextarg++, va_arg(ap, type)))

	/*
	 * To extend shorts properly, we need both signed and unsigned
	 * argument extraction methods.
	 */
#define	SARG() \
	(flags&LONGINT ? GETARG(long) : \
	    flags&SHORTINT ? (long)(short)GETARG(int) : \
	    flags&CHARINT ? (long)(signed char)GETARG(int) : \
	    (long)GETARG(int))
#define	UARG() \
	(flags&LONGINT ? GETARG(u_long) : \
	    flags&SHORTINT ? (u_long)(u_short)GETARG(int) : \
	    flags&CHARINT ? (u_long)(u_char)GETARG(int) : \
	    (u_long)GETARG(u_int))
#define	INTMAX_SIZE	(INTMAXT|SIZET|PTRDIFFT|LLONGINT|LONGDBL)
#define SJARG() \
	(flags&LONGDBL ? GETARG(int64_t) : \
	    flags&INTMAXT ? GETARG(intmax_t) : \
	    flags&SIZET ? (intmax_t)GETARG(ssize_t) : \
	    flags&PTRDIFFT ? (intmax_t)GETARG(ptrdiff_t) : \
	    (intmax_t)GETARG(long long))
#define	UJARG() \
	(flags&LONGDBL ? GETARG(uint64_t) : \
	    flags&INTMAXT ? GETARG(uintmax_t) : \
	    flags&SIZET ? (uintmax_t)GETARG(size_t) : \
	    flags&PTRDIFFT ? (uintmax_t)GETARG(ptrdiff_t) : \
	    (uintmax_t)GETARG(unsigned long long))

	/*
	 * Get * arguments, including the form *nn$.  Preserve the nextarg
	 * that the argument can be gotten once the type is determined.
	 */
#define GETASTER(val) \
	n2 = 0; \
	cp = fmt; \
	while (is_digit(*cp)) { \
		n2 = 10 * n2 + to_digit(*cp); \
		cp++; \
	} \
	if (*cp == '$') { \
		int hold = nextarg; \
		if (argtable == NULL) { \
			argtable = statargtable; \
			if (_frr_find_arguments (fmt0, orgap, &argtable)) { \
				ret = EOF; \
				goto error; \
			} \
		} \
		nextarg = n2; \
		val = GETARG (int); \
		nextarg = hold; \
		fmt = ++cp; \
	} else { \
		val = GETARG (int); \
	}

	xdigs = xdigs_lower;
	saved_errno = errno;
	convbuf = NULL;
	fmt = (char *)fmt0;
	argtable = NULL;
	nextarg = 1;
	va_copy(orgap, ap);
	io_init(&io, cb);
	ret = 0;

	/*
	 * Scan the format for conversions (`%' character).
	 */
	for (;;) {
		for (cp = fmt; (ch = *fmt) != '\0' && ch != '%'; fmt++)
			/* void */;
		if ((n = fmt - cp) != 0) {
			if ((unsigned)ret + n > INT_MAX) {
				ret = EOF;
				errno = EOVERFLOW;
				goto error;
			}
			PRINT(cp, n);
			ret += n;
		}
		if (ch == '\0')
			goto done;
		fmt++;		/* skip over '%' */

		flags = 0;
		dprec = 0;
		width = 0;
		prec = -1;
		sign = '\0';
		ox[1] = '\0';

rflag:		ch = *fmt++;
reswitch:	switch (ch) {
		case ' ':
			/*-
			 * ``If the space and + flags both appear, the space
			 * flag will be ignored.''
			 *	-- ANSI X3J11
			 */
			if (!sign)
				sign = ' ';
			goto rflag;
		case '#':
			flags |= ALT;
			goto rflag;
		case '*':
			/*-
			 * ``A negative field width argument is taken as a
			 * - flag followed by a positive field width.''
			 *	-- ANSI X3J11
			 * They don't exclude field widths read from args.
			 */
			GETASTER (width);
			if (width >= 0)
				goto rflag;
			width = -width;
			/* FALLTHROUGH */
		case '-':
			flags |= LADJUST;
			goto rflag;
		case '+':
			sign = '+';
			goto rflag;
		case '\'':
			flags |= GROUPING;
			goto rflag;
		case '.':
			if ((ch = *fmt++) == '*') {
				GETASTER (prec);
				goto rflag;
			}
			prec = 0;
			while (is_digit(ch)) {
				prec = 10 * prec + to_digit(ch);
				ch = *fmt++;
			}
			goto reswitch;
		case '0':
			/*-
			 * ``Note that 0 is taken as a flag, not as the
			 * beginning of a field width.''
			 *	-- ANSI X3J11
			 */
			flags |= ZEROPAD;
			goto rflag;
		case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			n = 0;
			do {
				n = 10 * n + to_digit(ch);
				ch = *fmt++;
			} while (is_digit(ch));
			if (ch == '$') {
				nextarg = n;
				if (argtable == NULL) {
					argtable = statargtable;
					if (_frr_find_arguments (fmt0, orgap,
							      &argtable)) {
						ret = EOF;
						goto error;
					}
				}
				goto rflag;
			}
			width = n;
			goto reswitch;
		case 'L':
			flags |= LONGDBL;
			goto rflag;
		case 'h':
			if (flags & SHORTINT) {
				flags &= ~SHORTINT;
				flags |= CHARINT;
			} else
				flags |= SHORTINT;
			goto rflag;
		case 'j':
			flags |= INTMAXT;
			goto rflag;
		case 'l':
			if (flags & LONGINT) {
				flags &= ~LONGINT;
				flags |= LLONGINT;
			} else
				flags |= LONGINT;
			goto rflag;
		case 'q':
			flags |= LLONGINT;	/* not necessarily */
			goto rflag;
		case 't':
			flags |= PTRDIFFT;
			goto rflag;
		case 'z':
			flags |= SIZET;
			goto rflag;
		case 'C':
			flags |= LONGINT;
			/*FALLTHROUGH*/
		case 'c':
#ifdef WCHAR_SUPPORT
			if (flags & LONGINT) {
				static const mbstate_t initial;
				mbstate_t mbs;
				size_t mbseqlen;

				mbs = initial;
				mbseqlen = wcrtomb(cp = buf,
				    (wchar_t)GETARG(wint_t), &mbs);
				if (mbseqlen == (size_t)-1) {
					goto error;
				}
				size = (int)mbseqlen;
			} else
#endif /* WCHAR_SUPPORT */
			{
				buf[0] = GETARG(int);
				cp = buf;
				size = 1;
			}
			sign = '\0';
			break;
		case 'D':
			flags |= LONGINT;
			/*FALLTHROUGH*/
		case 'd':
		case 'i':
			if (flags & INTMAX_SIZE)
				ujval = SJARG();
			else
				ulval = SARG();

			if (printfrr_ext_char(fmt[0])) {
				n2 = printfrr_exti(buf, sizeof(buf), fmt, prec,
						(flags & INTMAX_SIZE) ? ujval
						: (uintmax_t)ulval);
				if (n2 > 0) {
					fmt += n2;
					cp = buf;
					size = strlen(cp);
					sign = '\0';
					break;
				}
			}
			if (flags & INTMAX_SIZE) {
				if ((intmax_t)ujval < 0) {
					ujval = -ujval;
					sign = '-';
				}
			} else {
				if ((long)ulval < 0) {
					ulval = -ulval;
					sign = '-';
				}
			}
			base = 10;
			goto number;
#ifndef NO_FLOATING_POINT
		case 'a':
		case 'A':
		case 'e':
		case 'E':
		case 'f':
		case 'F':
		case 'g':
		case 'G':
			if (flags & LONGDBL) {
				long double arg = GETARG(long double);
				char fmt[6] = "%.*L";
				fmt[4] = ch;
				fmt[5] = '\0';

				snprintf(buf, sizeof(buf), fmt, prec, arg);
			} else {
				double arg = GETARG(double);
				char fmt[5] = "%.*";
				fmt[3] = ch;
				fmt[4] = '\0';

				snprintf(buf, sizeof(buf), fmt, prec, arg);
			}
			cp = buf;
			/* for proper padding */
			if (*cp == '-') {
				cp++;
				sign = '-';
			}
			/* "inf" */
			if (!is_digit(*cp) && *cp != '.')
				flags &= ~ZEROPAD;
			size = strlen(buf);
			break;
#endif
		case 'm':
			cp = strerror(saved_errno);
			size = (prec >= 0) ? strnlen(cp, prec) : strlen(cp);
			sign = '\0';
			break;
		case 'n':
			/*
			 * Assignment-like behavior is specified if the
			 * value overflows or is otherwise unrepresentable.
			 * C99 says to use `signed char' for %hhn conversions.
			 */
			if (flags & LLONGINT)
				*GETARG(long long *) = ret;
			else if (flags & SIZET)
				*GETARG(ssize_t *) = (ssize_t)ret;
			else if (flags & PTRDIFFT)
				*GETARG(ptrdiff_t *) = ret;
			else if (flags & INTMAXT)
				*GETARG(intmax_t *) = ret;
			else if (flags & LONGINT)
				*GETARG(long *) = ret;
			else if (flags & SHORTINT)
				*GETARG(short *) = ret;
			else if (flags & CHARINT)
				*GETARG(signed char *) = ret;
			else
				*GETARG(int *) = ret;
			continue;	/* no output */
		case 'O':
			flags |= LONGINT;
			/*FALLTHROUGH*/
		case 'o':
			if (flags & INTMAX_SIZE)
				ujval = UJARG();
			else
				ulval = UARG();
			base = 8;
			goto nosign;
		case 'p':
			/*-
			 * ``The argument shall be a pointer to void.  The
			 * value of the pointer is converted to a sequence
			 * of printable characters, in an implementation-
			 * defined manner.''
			 *	-- ANSI X3J11
			 */
			ptrval = GETARG(void *);
			if (printfrr_ext_char(fmt[0]) &&
					(n2 = printfrr_extp(buf, sizeof(buf),
						fmt, prec, ptrval)) > 0) {
				fmt += n2;
				cp = buf;
				size = strlen(cp);
				sign = '\0';
				break;
			}
			ujval = (uintmax_t)(uintptr_t)ptrval;
			base = 16;
			xdigs = xdigs_lower;
			flags = flags | INTMAXT;
			ox[1] = 'x';
			goto nosign;
		case 'S':
			flags |= LONGINT;
			/*FALLTHROUGH*/
		case 's':
#ifdef WCHAR_SUPPORT
			if (flags & LONGINT) {
				wchar_t *wcp;

				if (convbuf != NULL)
					free(convbuf);
				if ((wcp = GETARG(wchar_t *)) == NULL)
					cp = "(null)";
				else {
					convbuf = __wcsconv(wcp, prec);
					if (convbuf == NULL) {
						goto error;
					}
					cp = convbuf;
				}
			} else
#endif
			if ((cp = GETARG(char *)) == NULL)
				cp = "(null)";
			size = (prec >= 0) ? strnlen(cp, prec) : strlen(cp);
			sign = '\0';
			break;
		case 'U':
			flags |= LONGINT;
			/*FALLTHROUGH*/
		case 'u':
			if (flags & INTMAX_SIZE)
				ujval = UJARG();
			else
				ulval = UARG();
			base = 10;
			goto nosign;
		case 'X':
			xdigs = xdigs_upper;
			goto hex;
		case 'x':
			xdigs = xdigs_lower;
hex:
			if (flags & INTMAX_SIZE)
				ujval = UJARG();
			else
				ulval = UARG();
			base = 16;
			/* leading 0x/X only if non-zero */
			if (flags & ALT &&
			    (flags & INTMAX_SIZE ? ujval != 0 : ulval != 0))
				ox[1] = ch;

			flags &= ~GROUPING;
			/* unsigned conversions */
nosign:			sign = '\0';
			/*-
			 * ``... diouXx conversions ... if a precision is
			 * specified, the 0 flag will be ignored.''
			 *	-- ANSI X3J11
			 */
number:			if ((dprec = prec) >= 0)
				flags &= ~ZEROPAD;

			/*-
			 * ``The result of converting a zero value with an
			 * explicit precision of zero is no characters.''
			 *	-- ANSI X3J11
			 *
			 * ``The C Standard is clear enough as is.  The call
			 * printf("%#.0o", 0) should print 0.''
			 *	-- Defect Report #151
			 */
			cp = buf + BUF;
			if (flags & INTMAX_SIZE) {
				if (ujval != 0 || prec != 0 ||
				    (flags & ALT && base == 8))
					cp = __ujtoa(ujval, buf + BUF, base,
					    flags & ALT, xdigs);
			} else {
				if (ulval != 0 || prec != 0 ||
				    (flags & ALT && base == 8))
					cp = __ultoa(ulval, buf + BUF, base,
					    flags & ALT, xdigs);
			}
			size = buf + BUF - cp;
			if (size > BUF)	/* should never happen */
				abort();
			break;
		default:	/* "%?" prints ?, unless ? is NUL */
			if (ch == '\0')
				goto done;
			/* pretend it was %c with argument ch */
			buf[0] = ch;
			cp = buf;
			size = 1;
			sign = '\0';
			break;
		}

		/*
		 * All reasonable formats wind up here.  At this point, `cp'
		 * points to a string which (if not flags&LADJUST) should be
		 * padded out to `width' places.  If flags&ZEROPAD, it should
		 * first be prefixed by any sign or other prefix; otherwise,
		 * it should be blank padded before the prefix is emitted.
		 * After any left-hand padding and prefixing, emit zeroes
		 * required by a decimal [diouxX] precision, then print the
		 * string proper, then emit zeroes required by any leftover
		 * floating precision; finally, if LADJUST, pad with blanks.
		 *
		 * Compute actual size, so we know how much to pad.
		 * size excludes decimal prec; realsz includes it.
		 */
		realsz = dprec > size ? dprec : size;
		if (sign)
			realsz++;
		if (ox[1])
			realsz += 2;

		prsize = width > realsz ? width : realsz;
		if ((unsigned)ret + prsize > INT_MAX) {
			ret = EOF;
			errno = EOVERFLOW;
			goto error;
		}

		/* right-adjusting blank padding */
		if ((flags & (LADJUST|ZEROPAD)) == 0)
			PAD(width - realsz, blanks);

		/* prefix */
		if (sign)
			PRINT(&sign, 1);

		if (ox[1]) {	/* ox[1] is either x, X, or \0 */
			ox[0] = '0';
			PRINT(ox, 2);
		}

		/* right-adjusting zero padding */
		if ((flags & (LADJUST|ZEROPAD)) == ZEROPAD)
			PAD(width - realsz, zeroes);

		/* the string or number proper */
		/* leading zeroes from decimal precision */
		PAD(dprec - size, zeroes);
		PRINT(cp, size);
		/* left-adjusting padding (always blank) */
		if (flags & LADJUST)
			PAD(width - realsz, blanks);

		/* finally, adjust ret */
		ret += prsize;

		FLUSH();	/* copy out the I/O vectors */
	}
done:
	FLUSH();
error:
	va_end(orgap);
	if (convbuf != NULL)
		free(convbuf);
	if ((argtable != NULL) && (argtable != statargtable))
		free (argtable);
	return (ret);
	/* NOTREACHED */
}

