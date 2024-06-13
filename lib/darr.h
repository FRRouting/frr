// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * June 23 2023, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 */
#ifndef _FRR_DARR_H_
#define _FRR_DARR_H_

/*
 * API functions:
 * ==============
 *  - darr_append
 *  - darr_append_mt
 *  - darr_append_n
 *  - darr_append_n_mt
 *  - darr_append_nz
 *  - darr_append_nz_mt
 *  - darr_cap
 *  - darr_ensure_avail
 *  - darr_ensure_avail_mt
 *  - darr_ensure_cap
 *  - darr_ensure_cap_mt
 *  - darr_ensure_i
 *  - darr_ensure_i_mt
 *  - darr_free
 *  - darr_free_free
 *  - darr_free_func
 *  - darr_insert
 *  - darr_insert_mt
 *  - darr_insertz
 *  - darr_insertz_mt
 *  - darr_insert_n
 *  - darr_insert_n_mt
 *  - darr_insert_nz
 *  - darr_insert_nz_mt
 *  - darr_last
 *  - darr_lasti
 *  - darr_len
 *  - darr_maxi
 *  - darr_pop
 *  - darr_push
 *  - darr_pushz
 *  - darr_remove
 *  - darr_remove_n
 *  - darr_reset
 *  - darr_setlen
 *
 * Iteration
 * ---------
 *  - darr_foreach_i
 *  - darr_foreach_p
 *
 * String Utilities
 * ----------------
 *  - darr_in_strcat_tail
 *  - darr_in_strcatf, darr_in_vstrcatf
 *  - darr_in_strdup
 *  - darr_in_strdup_cap
 *  - darr_in_sprintf, darr_in_vsprintf
 *  - darr_set_strlen
 *  - darr_strdup
 *  - darr_strdup_cap
 *  - darr_strlen
 *  - darr_strnul
 *  - darr_sprintf, darr_vsprintf
 */
/*
 * A few assured items
 *
 * - DAs will never have capacity 0 unless they are NULL pointers.
 */

/*
 * NOTE: valgrind by default enables a "length64" heuristic (among others) which
 * identifies "interior-pointer" 8 bytes forward of a "start-pointer" as a
 * "start-pointer". This should cause what normally would be "possibly-lost"
 * errors to instead be definite for dynamic arrays. This is b/c the header is 8 bytes
 */

#include <zebra.h>
#include <limits.h>
#include "memory.h"

DECLARE_MTYPE(DARR);
DECLARE_MTYPE(DARR_STR);

struct darr_metadata {
	uint32_t len;
	uint32_t cap;
	struct memtype *mtype;
};

void *__darr_insert_n(void *a, uint at, uint count, size_t esize, bool zero,
		      struct memtype *mt);
char *__darr_in_sprintf(char **sp, bool concat, const char *fmt, ...)
	PRINTFRR(3, 4);
char *__darr_in_vsprintf(char **sp, bool concat, const char *fmt, va_list ap)
	PRINTFRR(3, 0);
void *__darr_resize(void *a, uint count, size_t esize, struct memtype *mt);


#define _darr_esize(A) sizeof((A)[0])
#define darr_esize(A)  sizeof((A)[0])
#define _darr_len(A)   _darr_meta(A)->len
#define _darr_meta(A)  (((struct darr_metadata *)(A)) - 1)
#define _darr_resize_mt(A, C, MT)                                              \
	({ (A) = __darr_resize(A, C, _darr_esize(A), MT); })
#define _darr_resize(A, C) _darr_resize_mt(A, C, MTYPE_DARR)

/* Get the current capacity of the array */
#define darr_cap(A) (((A) == NULL) ? 0 : _darr_meta(A)->cap)

/* Get the current available expansion space */
#define darr_avail(A) (((A) == NULL) ? 0 : (darr_cap(A) - darr_len(A)))

/* Get the largest possible index one can `darr_ensure_i` w/o resizing */
#define darr_maxi(A) ((int)darr_cap(A) - 1)

/**
 * darr_len() - Get the current length of the array as a unsigned int.
 * darr_ilen() - Get the current length of the array as an int.
 *
 * Args:
 *	A: The dynamic array, can be NULL.
 *
 * Return:
 *      The current length of the array.
 */
#define darr_len(A)  (((A) == NULL) ? 0 : _darr_meta(A)->len)
#define darr_ilen(A) (((A) == NULL) ? 0 : (ssize_t)_darr_meta(A)->len)

/**
 * darr_lasti() - Get the last element's index.
 *
 * Args:
 *	A: The dynamic array, can be NULL.
 *
 * Return:
 *      The current last element index, or -1 for none.
 */
#define darr_lasti(A) (darr_ilen(A) - 1)

/**
 * Set the current length of the array `A` to 0.
 *
 * Args:
 *	A: The dynamic array, can be NULL.
 */
#define darr_reset(A)                                                          \
	do {                                                                   \
		if ((A))                                                       \
			_darr_len(A) = 0;                                      \
	} while (0)

/**
 * Set the current length of the array `A` to `L`.
 *
 * This function does *not* guarantee the memory is valid to L,
 * use `darr_ensure` or `darr_ensure_cap` for that.
 *
 * Args:
 *	A: The dynamic array, can only be NULL if (L) == 0.
 *      L: The new length of the array.
 */
#define darr_setlen(A, L)                                                      \
	do {                                                                   \
		assert((A) || !(L));                                           \
		if ((A)) {                                                     \
			/* have to cast to avoid compiler warning for "0" */   \
			assert((long long)darr_cap(A) >= (long long)(L));      \
			_darr_len(A) = (L);                                    \
		}                                                              \
	} while (0)

/**
 * Set the string length of the array `S` to `L`, and NUL
 * terminate the string at L. The dynamic array length will be `L` + 1.
 *
 * Thus after calling:
 *
 *    darr_len(S) == L + 1
 *    darr_strlen(S) == L
 *    S[L] == 0
 *
 * This function does *not* guarantee the `L` + 1 memory is allocated to
 * the array, use `darr_ensure` or `*_cap` functions for that.
 *
 * Args:
 *	S: The dynamic array, cannot be NULL.
 *      L: The new str length of the array, will set
 *
 * Return:
 *      A pointer to the end of S (i.e., pointing to the NUL byte).
 */
#define darr_set_strlen(S, L)                                                  \
	({                                                                     \
		assert((S));                                                   \
		/* have to cast to avoid compiler warning for "0" */           \
		assert((long long)darr_cap(S) >= (long long)(L));              \
		_darr_len(S) = (L) + 1;                                        \
		*darr_last(S) = 0;                                             \
		darr_last(S);                                                  \
	})

/**
 * Free memory allocated for the dynamic array `A`
 *
 * Args:
 *	A: The dynamic array, can be NULL.
 */

#define darr_free(A)                                                           \
	do {                                                                   \
		if ((A)) {                                                     \
			struct darr_metadata *__meta = _darr_meta(A);          \
			XFREE(__meta->mtype, __meta);                          \
			(A) = NULL;                                            \
		}                                                              \
	} while (0)

/**
 * Free memory allocated for the dynamic array `A`, calling `darr_free` for
 * each element of the array first.
 *
 * Args:
 *	A: The dynamic array, can be NULL.
 */
#define darr_free_free(A)                                                      \
	do {                                                                   \
		for (uint __i = 0; __i < darr_len(A); __i++)                   \
			if ((A)[__i]) {                                        \
				struct darr_metadata *__meta =                 \
					_darr_meta((A)[__i]);                  \
				XFREE(__meta->mtype, __meta);                  \
			}                                                      \
		darr_free(A);                                                  \
	} while (0)

/**
 * Free memory allocated for the dynamic array `A`, calling `F` routine
 * for each element of the array first.
 *
 * Args:
 *	A: The dynamic array, can be NULL.
 *	F: The function to call for each element.
 */

#define darr_free_func(A, F)                                                   \
	do {                                                                   \
		for (uint __i = 0; __i < darr_len(A); __i++) {                 \
			F((A)[__i]);                                           \
		}                                                              \
		darr_free(A);                                                  \
	} while (0)

/**
 * Make sure that there is room in the dynamic array `A` to add `C` elements.
 *
 * Available space is `darr_cap(a) - darr_len(a)`.
 *
 * The value `A` may be changed as a result of this call in which case any
 * pointers into the previous memory block are no longer valid. The `A` value
 * is guaranteed not to change if there is sufficient capacity in the array.
 *
 * Args:
 *	A: (IN/OUT) the dynamic array, can be NULL.
 *	S: Amount of free space to guarantee.
 *
 * Return:
 *      A pointer to the (possibly moved) array.
 */
#define darr_ensure_avail_mt(A, S, MT)                                         \
	({                                                                     \
		ssize_t need = (ssize_t)(S) -                                  \
			       (ssize_t)(darr_cap(A) - darr_len(A));           \
		if (need > 0)                                                  \
			_darr_resize_mt((A), darr_cap(A) + need, MT);          \
		(A);                                                           \
	})
#define darr_ensure_avail(A, S) darr_ensure_avail_mt(A, S, MTYPE_DARR)

/**
 * Make sure that there is room in the dynamic array `A` for `C` elements.
 *
 * The value `A` may be changed as a result of this call in which case any
 * pointers into the previous memory block are no longer valid. The `A` value
 * is guaranteed not to change if there is sufficient capacity in the array.
 *
 * The exception to the no-change rule is if @C is passed as 0, it will be
 * considered 1 so that an array is always allocated if currently NULL,
 * i.e., @A will never be NULL after a call to darr_ensure_cap_mt()
 *
 * Args:
 *	A: (IN/OUT) the dynamic array, can be NULL.
 *	C: Total capacity to guarantee.
 *
 * Return:
 *      A pointer to the (possibly moved) array.
 */
#define darr_ensure_cap_mt(A, C, MT)                                           \
	({                                                                     \
		/* Cast to avoid warning when C == 0 */                        \
		uint _c = (C) > 0 ? (C) : 1;                                   \
		if ((size_t)darr_cap(A) < _c)                                  \
			_darr_resize_mt((A), _c, MT);                          \
		(A);                                                           \
	})
#define darr_ensure_cap(A, C) darr_ensure_cap_mt(A, C, MTYPE_DARR)

/**
 * Return a pointer to the (I)th element of array `A`, making sure there is
 * room for the element.
 *
 * If the array length is less than `I + 1` then the length is set to `I + 1`.
 *
 * The value `A` may be changed as a result of this call in which case any
 * pointers into the previous memory block are no longer valid. The `A` value
 * is guaranteed not to change if there is sufficient capacity in the array.
 *
 * Args:
 *
 *	A: (IN/OUT) the dynamic array, can be NULL.
 *	I: the index to guarantee memory exists for
 *
 * Return:
 *      A pointer to the (I)th element in `A`
 */
#define darr_ensure_i_mt(A, I, MT)                                             \
	({                                                                     \
		assert((int)(I) >= 0 && (uint)(I) <= INT_MAX);                 \
		int _i = (int)(I);                                             \
		if (_i > darr_maxi(A))                                         \
			_darr_resize_mt((A), _i + 1, MT);                      \
		assert((A) != NULL);                                           \
		if ((uint)_i + 1 > _darr_len(A))                               \
			_darr_len(A) = _i + 1;                                 \
		&(A)[_i];                                                      \
	})
#define darr_ensure_i(A, I) darr_ensure_i_mt(A, I, MTYPE_DARR)

#define _darr_insert_n(A, I, N, Z, MT)                                         \
	({                                                                     \
		(A) = __darr_insert_n(A, I, N, _darr_esize(A), Z, MT);         \
		&(A)[I];                                                       \
	})
/**
 * Insert N uninitialized elements in the array at index `I`.
 *
 * Previous elements from `I` are shifted right by `N`. Array length is
 * increased by `N`.
 *
 * The value `A` may be changed as a result of this call in which case any
 * pointers into the previous memory block are no longer valid. The `A` value
 * is guaranteed not to change if there is sufficient capacity in the array.
 *
 * The `z` variant zeros new elements.
 *
 * Args:
 *	A: The dynamic array, can be NULL.
 *
 * Return:
 *      A pointer to the first inserted element in the array.
 */
#define darr_insert_n(A, I, N)	   _darr_insert_n(A, I, N, false, MTYPE_DARR)
#define darr_insert_n_mt(A, I, N)  _darr_insert_n(A, I, N, false, MT)
#define darr_insert_nz(A, I, N)	   _darr_insert_n(A, I, N, true, MTYPE_DARR)
#define darr_insert_nz_mt(A, I, N) _darr_insert_n(A, I, N, true, MT)

/**
 * Insert an uninitialized element in the array at index `I`.
 *
 * Previous elements from `I` are shifted right by 1. Array length is
 * increased by 1.
 *
 * The value `A` may be changed as a result of this call in which case any
 * pointers into the previous memory block are no longer valid. The `A` value
 * is guaranteed not to change if there is sufficient capacity in the array.
 *
 * The `z` variant zeros the new element.
 *
 * Args:
 *	A: The dynamic array, can be NULL.
 *
 * Return:
 *      A pointer to the element in the array.
 */
#define darr_insert(A, I)     _darr_insert_n(A, I, 1, false, MTYPE_DARR)
#define darr_insert_mt(A, I)  _darr_insert_n(A, I, 1, false, MT)
#define darr_insertz(A, I)    _darr_insert_n(A, I, 1, true, MTYPE_DARR)
#define darr_insertz_mt(A, I) _darr_insert_n(A, I, 1, true, MT)

/**
 * Remove `N` elements from the array starting at index `I`.
 *
 * Elements from `I` + `N` are shifted left by `N`. Array length is reduced by
 * `N`.
 *
 * Args:
 *	A: The dynamic array, can be NULL.
 */
#define darr_remove_n(A, I, N)                                                 \
	do {                                                                   \
		uint __i = (I);                                                \
		uint __n = (N);                                                \
		uint __len = darr_len(A);                                      \
		if (!__len)                                                    \
			break;                                                 \
		else if (__i + __n < __len) {                                  \
			memmove(&(A)[__i], &(A)[__i + __n],                    \
				_darr_esize(A) * (__len - (__i + __n)));       \
			_darr_len(A) = __len - __n;                            \
		} else                                                         \
			_darr_len(A) = __i;                                    \
	} while (0)

/**
 * Remove the `I`th element from the array.
 *
 * Previous elements from `I` + 1 are shifted left by 1, Array length is reduced
 * by 1.
 *
 * Args:
 *	A: The dynamic array, can be NULL.
 */
#define darr_remove(A, I) darr_remove_n(A, I, 1)


#define _darr_append_n(A, N, Z, MT)                                            \
	({                                                                     \
		uint __len = darr_len(A);                                      \
		darr_ensure_cap_mt(A, __len + (N), MT);                        \
		_darr_len(A) = __len + (N);                                    \
		if (Z)                                                         \
			memset(&(A)[__len], 0, (N)*_darr_esize(A));            \
		&(A)[__len];                                                   \
	})
/**
 * Extending the array's length by N.
 *
 * Args:
 *	A: The dynamic array, can be NULL.
 *
 * The `z` variant zeros new elements.
 *
 * Return:
 *	A pointer to the first of the added elements at the end of the array.
 */
#define darr_append_n(A, N)	    _darr_append_n(A, N, false, MTYPE_DARR)
#define darr_append_n_mt(A, N, MT)  _darr_append_n(A, N, false, MT)
#define darr_append_nz(A, N)	    _darr_append_n(A, N, true, MTYPE_DARR)
#define darr_append_nz_mt(A, N, MT) _darr_append_n(A, N, true, MT)

/**
 * Extending the array's length by 1.
 *
 * Args:
 *	A: The dynamic array, can be NULL.
 *
 * The `z` variant zeros the new element.
 *
 * Return:
 *	A pointer to the new element at the end of the array.
 */
#define darr_append(A)	       _darr_append_n(A, 1, false, MTYPE_DARR)
#define darr_append_mt(A, MT)  _darr_append_n(A, 1, false, MT)
#define darr_appendz(A)	       _darr_append_n(A, 1, true, MTYPE_DARR)
#define darr_appendz_mt(A, MT) _darr_append_n(A, 1, true, MT)

/**
 * Append an element `E` onto the array `A`, extending it's length by 1.
 *
 * The `z` variant zeros the new element.
 *
 * Args:
 *	A: The dynamic array, can be NULL.
 *
 * Return:
 *	A pointer to the element in the array.
 */
#define darr_push(A, E)	       (*darr_append(A) = (E))
#define darr_push_mt(A, E, MT) (*darr_append_mt(A, MT) = (E))
#define darr_pushz(A)	       (darr_appendz(A))
#define darr_pushz_mt(A, MT)   (darr_appendz_mt(A, MT))


/**
 * Pop the last `N` elements from the array decrementing the length by `N`.
 *
 * Args:
 *	A: The dynamic array, can be NULL.
 */
#define darr_pop_n(A, N)                                                       \
	do {                                                                   \
		if ((A) && (N) >= _darr_len(A))                                \
			darr_reset(A);                                         \
		else                                                           \
			_darr_len(A) -= (N);                                   \
	} while (0)


/**
 * Pop the last element from the array decrementing the length by 1.
 *
 * Args:
 *	A: The dynamic array, can be NULL.
 *
 * Return:
 *      The element just popped.
 */
#define darr_pop(A)                                                            \
	({                                                                     \
		uint __len = _darr_len(A);                                     \
		assert(__len);                                                 \
		darr_remove(A, __len - 1);                                     \
		/* count on fact that we don't resize */                       \
		(A)[__len - 1];                                                \
	})

/**
 * Return the address at the end of the array -- useful for iterating
 *
 * Args:
 *	A: The dynamic array, can be NULL.
 *
 * Return:
 *	The address of the end of the array (past the last elment) or NULL
 *	if `A` is NULL.
 */
#define darr_end(A) ((A) + darr_len(A))

/**
 * darr_last() - Get a pointer to the last element of the array.
 * darr_strnul() - Get a pointer to the NUL byte of the darr string or NULL.
 *
 * Args:
 *	A: The dynamic array, can be NULL.
 *
 * Return:
 *      A pointer to the last element of the array or NULL if the array is
 *      empty.
 */
#define darr_last(A)                                                           \
	({                                                                     \
		uint __len = darr_len(A);                                      \
		((__len > 0) ? &(A)[__len - 1] : NULL);                        \
	})
#define darr_strnul(S) darr_last(S)

/**
 * darr_in_sprintf() - sprintf into D.
 *
 * Args:
 *      D: The destination darr, D's value may be NULL.
 *      F: The format string
 *      ...: variable arguments for format string.
 *
 * Return:
 *	The dynamic_array D with the new string content.
 */
#define darr_in_sprintf(D, F, ...) __darr_in_sprintf(&(D), 0, F, __VA_ARGS__)


/**
 * darr_in_strcat() - concat a string into a darr string.
 *
 * Args:
 *      D: The destination darr, D's value may be NULL.
 *      S: The string to concat onto D.
 *
 * Return:
 *	The dynamic_array D with the new string content.
 */
#define darr_in_strcat(D, S)                                                   \
	({                                                                     \
		uint __dlen = darr_strlen(D);                                  \
		uint __slen = strlen(S);                                       \
		darr_ensure_cap_mt(D, __dlen + __slen + 1, MTYPE_DARR_STR);    \
		if (darr_len(D) == 0)                                          \
			*darr_append(D) = 0;                                   \
		memcpy(darr_last(D), (S), __slen + 1);                         \
		_darr_len(D) += __slen;                                        \
		D;                                                             \
	})

/**
 * darr_in_strcatf() - concat a formatted string into a darr string.
 *
 * Args:
 *      D: The destination darr, D's value may be NULL.
 *      F: The format string to concat onto D after adding arguments.
 *    ...: The arguments for the format string.
 * Return:
 *	The dynamic_array D with the new string content.
 */
#define darr_in_strcatf(D, F, ...)                                             \
	__darr_in_sprintf(&(D), true, (F), __VA_ARGS__)

/**
 * darr_in_strcat_tail() - copies end of one darr str to another.
 *
 * This is a rather specialized function, it takes 2 darr's, a destination and a
 * source. If the source is not longer than the destination nothing is done.
 * Otherwise the characters in the source that lie beyond the length of the dest
 * are added to the dest. No checking is done to make sure the common prefix
 * matches. For example:
 *
 *     D: "/foo"
 *     S: "/foo/bar"
 *  -> D: "/foo/bar"
 *
 *     perhaps surprising results:
 *     D: "/foo"
 *     S: "/zoo/bar"
 *  -> D: "/foo/bar"
 *
 * Args:
 *      D: The destination darr, D's value may be NULL.
 *      S: The string to copy the tail from.
 *
 * Return:
 *	The dynamic_array D with the extended string content.
 */
#define darr_in_strcat_tail(D, S)                                              \
	({                                                                     \
		int __dsize, __ssize, __extra;                                 \
									       \
		if (darr_len(D) == 0)                                          \
			*darr_append(D) = 0;                                   \
		__dsize = darr_ilen(D);                                        \
		__ssize = darr_ilen(S);                                        \
		__extra = __ssize - __dsize;                                   \
		if (__extra > 0) {                                             \
			darr_ensure_cap_mt(D, (uint)__ssize, MTYPE_DARR_STR);  \
			memcpy(darr_last(D), (S) + __dsize - 1, __extra + 1);  \
			_darr_len(D) += __extra;                               \
		}                                                              \
		D;                                                             \
	})

/**
 * darr_in_strdup_cap() - duplicate the string into a darr reserving capacity.
 * darr_in_strdup() - duplicate the string into a darr.
 *
 * Args:
 *      D: The destination darr, D's value may be NULL.
 *      S: The string to duplicate.
 *      C: The capacity to reserve.
 *
 * Return:
 *	The dynamic_array D with the duplicated string.
 */
#define darr_in_strdup_cap(D, S, C)                                            \
	({                                                                     \
		size_t __size = strlen(S) + 1;                                 \
		darr_reset(D);                                                 \
		darr_ensure_cap_mt(D,                                          \
				   ((size_t)(C) > __size) ? (size_t)(C)        \
							  : __size,            \
				   MTYPE_DARR_STR);                            \
		strlcpy(D, (S), darr_cap(D));                                  \
		darr_setlen((D), (size_t)__size);                              \
		D;                                                             \
	})
#define darr_in_strdup(D, S) darr_in_strdup_cap(D, S, 1)

/**
 * darr_in_vsprintf() - vsprintf into D.
 *
 * Args:
 *      D: The destination darr, D's value may be NULL.
 *      F: The format string
 *      A: Varargs
 *
 * Return:
 *	The dynamic_array D with the new string content.
 */
#define darr_in_vsprintf(D, F, A) __darr_in_vsprintf(&(D), 0, F, A)

/**
 * darr_in_vstrcatf() - concat a formatted string into a darr string.
 *
 * Args:
 *      D: The destination darr, D's value may be NULL.
 *      F: The format string to concat onto D after adding arguments.
 *      A: Varargs
 *
 * Return:
 *	The dynamic_array D with the new string content.
 */
#define darr_in_vstrcatf(D, F, A) __darr_in_vsprintf(&(D), true, (F), (A))

/**
 * darr_sprintf() - sprintf into a new dynamic array.
 *
 * Args:
 *      F: The format string
 *      ...: variable arguments for format string.
 *
 * Return:
 *	A char * dynamic_array with the new string content.
 */
#define darr_sprintf(F, ...)                                                   \
	({                                                                     \
		char *d = NULL;                                                \
		__darr_in_sprintf(&d, false, F, __VA_ARGS__);                  \
		d;                                                             \
	})

/**
 * darr_strdup_cap() - duplicate the string reserving capacity.
 * darr_strdup() - duplicate the string into a dynamic array.
 *
 * Args:
 *      S: The string to duplicate.
 *      C: The capacity to reserve.
 *
 * Return:
 *	The dynamic_array with the duplicated string.
 */
#define darr_strdup_cap(S, C)                                                  \
	({                                                                     \
		size_t __size = strlen(S) + 1;                                 \
		char *__s = NULL;                                              \
		/* Cast to ssize_t to avoid warning when C == 0 */             \
		darr_ensure_cap_mt(__s,                                        \
				   ((ssize_t)(C) > (ssize_t)__size)            \
					   ? (size_t)(C)                       \
					   : __size,                           \
				   MTYPE_DARR_STR);                            \
		strlcpy(__s, (S), darr_cap(__s));                              \
		darr_setlen(__s, (size_t)__size);                              \
		__s;                                                           \
	})
#define darr_strdup(S) darr_strdup_cap(S, 0)

/**
 * darr_strlen() - get the length of the NUL terminated string in a darr.
 *
 * Args:
 *      S: The string to measure, value may be NULL.
 *
 * Return:
 *	The length of the NUL terminated string in @S
 */
#define darr_strlen(S)                                                         \
	({                                                                     \
		uint __size = darr_len(S);                                     \
		if (__size)                                                    \
			__size -= 1;                                           \
		assert(!(S) || ((char *)(S))[__size] == 0);                    \
		__size;                                                        \
	})

/**
 * darr_vsprintf() - vsprintf into a new dynamic array.
 *
 * Args:
 *      F: The format string
 *      A: Varargs
 *
 * Return:
 *	The dynamic_array D with the new string content.
 */
#define darr_vsprintf(F, A)                                                    \
	({                                                                     \
		char *d = NULL;                                                \
		darr_in_vsprintf(d, F, A);                                     \
		d;                                                             \
	})

/**
 * Iterate over array `A` using a pointer to each element in `P`.
 *
 * Args:
 *	A: The dynamic array, can be NULL.
 *	P: A variable with the same type as A used as the iterator.
 */
#define darr_foreach_p(A, P) for ((P) = (A); (P) < darr_end(A); (P)++)

/**
 * Iterate over array `A`s indices.
 *
 * Args:
 *	A: The dynamic array, can be NULL.
 *	I: A uint variable to store the current element index in.
 */
#define darr_foreach_i(A, I) for ((I) = 0; (I) < darr_len(A); (I)++)

#endif /* _FRR_DARR_H_ */
