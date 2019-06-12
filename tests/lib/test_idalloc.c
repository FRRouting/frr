#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "id_alloc.h"

#include <inttypes.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#define IDS_PER_PAGE (1<<(IDALLOC_OFFSET_BITS + IDALLOC_WORD_BITS))
char allocated_markers[IDS_PER_PAGE*3];

int main(int argc, char **argv)
{
	int i, val;
	uint32_t pg;
	struct id_alloc *a;

	/* 1. Rattle test, shake it a little and make sure it doesn't make any
	 * noise :)
	 */
	a = idalloc_new("Rattle test");
	for (i = 0; i < 1000000; i++)
		assert(idalloc_allocate(a) != 0);

	idalloc_destroy(a);

	/* 2. Reserve a few low IDs, make sure they are skipped by normal
	 * allocation.
	 */
	a = idalloc_new("Low Reservations");
	assert(idalloc_reserve(a, 1) == 1);
	assert(idalloc_reserve(a, 3) == 3);
	assert(idalloc_reserve(a, 5) == 5);
	for (i = 0; i < 100; i++) {
		val = idalloc_allocate(a);
		assert(val != 1 && val != 3 && val != 5);
	}
	idalloc_destroy(a);

	/* 3. Single page testing. Check that IDs are kept unique, and all IDs
	 * in the existing page are allocated before a new page is added.
	 */
	memset(allocated_markers, 0, sizeof(allocated_markers));
	allocated_markers[IDALLOC_INVALID] = 1;

	a = idalloc_new("Single Page");

	/* reserve the rest of the first page */
	for (i = 0; i < IDS_PER_PAGE - 1; i++) {
		val = idalloc_allocate(a);
		assert(val < IDS_PER_PAGE);
		assert(allocated_markers[val] == 0);
		assert(a->capacity == IDS_PER_PAGE);
		allocated_markers[val] = 1;
	}
	/* Check that the count is right */
	assert(a->allocated == IDS_PER_PAGE);

	/* Free some IDs out of the middle. */
	idalloc_free(a, 300);
	allocated_markers[300] = 0;
	idalloc_free(a, 400);
	allocated_markers[400] = 0;
	idalloc_free(a, 500);
	allocated_markers[500] = 0;

	assert(a->allocated == IDS_PER_PAGE-3);

	/* Allocate the three IDs back and make sure they are pulled from the
	 * set just freed
	 */
	for (i = 0; i < 3; i++) {
		val = idalloc_allocate(a);
		assert(val < IDS_PER_PAGE);
		assert(allocated_markers[val] == 0);
		assert(a->capacity == IDS_PER_PAGE);
		allocated_markers[val] = 1;
	}
	idalloc_destroy(a);

	/* 4. Multi-page testing. */
	memset(allocated_markers, 0, sizeof(allocated_markers));
	allocated_markers[IDALLOC_INVALID] = 1;

	a = idalloc_new("Multi-page");

	/* reserve the rest of the first page and all of the second and third */
	for (i = 0; i < 3 * IDS_PER_PAGE - 1; i++) {
		val = idalloc_allocate(a);
		assert(val < 3*IDS_PER_PAGE);
		assert(allocated_markers[val] == 0);
		allocated_markers[val] = 1;
	}
	assert(a->capacity == 3*IDS_PER_PAGE);
	assert(a->allocated == 3*IDS_PER_PAGE);

	/* Free two IDs from each page. */
	for (i = 0; i < 3; i++) {
		idalloc_free(a, 7 + i*IDS_PER_PAGE);
		allocated_markers[7 + i*IDS_PER_PAGE] = 0;

		idalloc_free(a, 4 + i*IDS_PER_PAGE);
		allocated_markers[4 + i*IDS_PER_PAGE] = 0;
	}

	assert(a->allocated == 3*IDS_PER_PAGE - 6);

	/* Allocate the six IDs back and make sure they are pulled from the set
	 * just freed.
	 */
	for (i = 0; i < 6; i++) {
		val = idalloc_allocate(a);
		assert(val < 3*IDS_PER_PAGE);
		assert(allocated_markers[val] == 0);
		assert(a->capacity == 3*IDS_PER_PAGE);
		allocated_markers[val] = 1;
	}

	assert(a->capacity == 3*IDS_PER_PAGE);
	assert(a->allocated == 3*IDS_PER_PAGE);

	/* Walk each allocated ID. Free it, then re-allocate it back. */
	for (i = 1; i < 3 * IDS_PER_PAGE - 1; i++) {
		idalloc_free(a, i);
		val = idalloc_allocate(a);
		assert(val == i);
		assert(a->capacity == 3*IDS_PER_PAGE);
		assert(a->allocated == 3*IDS_PER_PAGE);
	}
	idalloc_destroy(a);

	/* 5. Weird Reservations
	 * idalloc_reserve exists primarily to black out low numbered IDs that
	 * are reserved for special cases. However, we will test it for more
	 * complex use cases to avoid unpleasant surprises.
	 */

	memset(allocated_markers, 0, sizeof(allocated_markers));
	allocated_markers[IDALLOC_INVALID] = 1;

	a = idalloc_new("Weird Reservations");

	/* Start with 3 pages fully allocated. */
	for (i = 0; i < 3 * IDS_PER_PAGE - 1; i++) {
		val = idalloc_allocate(a);
		assert(val < 3*IDS_PER_PAGE);
		assert(allocated_markers[val] == 0);
		allocated_markers[val] = 1;
	}
	assert(a->capacity == 3*IDS_PER_PAGE);
	assert(a->allocated == 3*IDS_PER_PAGE);

	/* Free a bit out of each of the three pages. Then reserve one of the
	 * three freed IDs. Finally, allocate the other two freed IDs. Do this
	 * each of three ways. (Reserve out of the first, seconds then third
	 * page.)
	 * The intent here is to exercise the rare cases on reserve_bit's
	 * linked-list removal in the case that it is not removing the first
	 * page with a free bit in its list of pages with free bits.
	 */

	for (pg = 0; pg < 3; pg++) {
		/* free a bit out of each of the three pages */
		for (i = 0; i < 3; i++) {
			idalloc_free(a, i*IDS_PER_PAGE + 17);
			allocated_markers[i*IDS_PER_PAGE + 17] = 0;
		}

		assert(a->capacity == 3*IDS_PER_PAGE);
		assert(a->allocated == 3*IDS_PER_PAGE-3);

		/* Reserve one of the freed IDs */
		assert(idalloc_reserve(a, pg*IDS_PER_PAGE + 17) ==
		       pg*IDS_PER_PAGE + 17);
		allocated_markers[pg*IDS_PER_PAGE + 17] = 1;

		assert(a->capacity == 3*IDS_PER_PAGE);
		assert(a->allocated == 3*IDS_PER_PAGE-2);

		/* Allocate the other two back */
		for (i = 0; i < 2; i++) {
			val = idalloc_allocate(a);
			assert(val < 3*IDS_PER_PAGE);
			assert(allocated_markers[val] == 0);
			allocated_markers[val] = 1;
		}
		assert(a->capacity == 3*IDS_PER_PAGE);
		assert(a->allocated == 3*IDS_PER_PAGE);
	}
	idalloc_destroy(a);

	puts("ID Allocator test successful.\n");
	return 0;
}
