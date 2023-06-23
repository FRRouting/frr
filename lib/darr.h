// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * June 23 2023, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 *
 * API functions:
 * ==============
 *  - darr_append
 *  - darr_append_n
 *  - darr_append_nz
 *  - darr_cap
 *  - darr_ensure_cap
 *  - darr_ensure_i
 *  - darr_foreach_i
 *  - darr_foreach_p
 *  - darr_free
 *  - darr_insert
 *  - darr_insertz
 *  - darr_insert_n
 *  - darr_insert_nz
 *  - darr_len
 *  - darr_maxi
 *  - darr_pop
 *  - darr_push
 *  - darr_pushz
 *  - darr_remove
 *  - darr_remove_n
 *  - darr_reset
 *  - darr_setlen
 */
/*
 * A few assured items
 *
 * - DAs will never have capacity 0 unless they are NULL pointers.
 */
#include <zebra.h>

struct darr_metadata {
	uint len;
	uint cap;
};
void *__darr_insert_n(void *a, uint at, uint count, size_t esize, bool zero);
void *__darr_resize(void *a, uint count, size_t esize);

#define _darr_esize(A)	   sizeof((A)[0])
#define darr_esize(A)	   sizeof((A)[0])
#define _darr_len(A)	   _darr_meta(A)->len
#define _darr_meta(A)	   (((struct darr_metadata *)(A)) - 1)
#define _darr_resize(A, C) ({ (A) = __darr_resize((A), C, _darr_esize(A)); })

/* Get the current capacity of the array */
#define darr_cap(A) (((A) == NULL) ? 0 : _darr_meta(A)->cap)

/* Get the largest possible index one can `darr_ensure_i` w/o resizing */
#define darr_maxi(A) ((int)darr_cap(A) - 1)

/**
 * Get the current length of the array.
 *
 * As long as `A` is non-NULL, this macro may be used as an L-value to modify
 * the length of the array.
 *
 * Args:
 *	A: The dynamic array, can be NULL.
 *
 * Return:
 *      The current length of the array.
 */
#define darr_len(A) (((A) == NULL) ? 0 : _darr_meta(A)->len)

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
			assert((long long)darr_cap(A) >= (L));                 \
			_darr_len(A) = (L);                                    \
		}                                                              \
	} while (0)

/**
 * Free memory allocated for the dynamic array `A`
 *
 * Args:
 *	A: The dynamic array, can be NULL.
 */

#define darr_free(A)                                                           \
	do {                                                                   \
		if ((A)) {                                                     \
			free(_darr_meta(A));                                   \
			(A) = NULL;                                            \
		}                                                              \
	} while (0)

/**
 * Make sure that there is room in the dynamic array `A` for `C` elements.
 *
 * The value `A` may be changed as a result of this call in which case any
 * pointers into the previous memory block are no longer valid. The `A` value
 * is guaranteed not to change if there is sufficient capacity in the array.
 *
 * Args:
 *	A: (IN/OUT) the dynamic array, can be NULL.
 *	I: the index to guarantee memory exists for
 *
 * Return:
 *      A pointer to the (possibly moved) array.
 */
#define darr_ensure_cap(A, C)                                                  \
	({                                                                     \
		if (darr_cap(A) < (C))                                         \
			_darr_resize((A), (C));                                \
		(A);                                                           \
	})

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
#define darr_ensure_i(A, I)                                                    \
	({                                                                     \
		if ((int)(I) > darr_maxi(A))                                   \
			_darr_resize((A), (I) + 1);                            \
		if ((I) + 1 > _darr_len(A))                                    \
			_darr_len(A) = (I) + 1;                                \
		&(A)[I];                                                       \
	})

#define _darr_insert_n(A, I, N, Z)                                             \
	({                                                                     \
		(A) = __darr_insert_n(A, I, N, _darr_esize(A), Z);             \
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
#define darr_insert_n(A, I, N)	_darr_insert_n(A, I, N, false)
#define darr_insert_nz(A, I, N) _darr_insert_n(A, I, N, true)

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
#define darr_insert(A, I)  _darr_insert_n(A, I, 1, false)
#define darr_insertz(A, I) _darr_insert_n(A, I, 1, true)

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


#define _darr_append_n(A, N, Z)                                                \
	({                                                                     \
		uint __len = darr_len(A);                                      \
		darr_ensure_cap(A, __len + (N));                               \
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
#define darr_append_n(A, N)  _darr_append_n(A, N, false)
#define darr_append_nz(A, N) _darr_append_n(A, N, true)

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
#define darr_append(A)	_darr_append_n(A, 1, false)
#define darr_appendz(A) _darr_append_n(A, 1, true)

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
#define darr_push(A, E) (*darr_append(A) = (E))
#define darr_pushz(A)	(darr_appendz(A))


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
