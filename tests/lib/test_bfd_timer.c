// SPDX-License-Identifier: GPL-2.0-or-later
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "bfdd/bfd_timer.h"

int main(void)
{
	static const uint32_t intervals[] = { 0,	 50000,		 100000,
					      1000000,	 UINT32_MAX / 3, UINT32_MAX / 3 + 1,
					      UINT32_MAX };
	static const uint8_t multipliers[] = { 1, 3, 7, UINT8_MAX };
	unsigned int checks = 0;

	for (unsigned int m = 0; m < sizeof(multipliers) / sizeof(multipliers[0]); m++) {
		for (unsigned int a = 0; a < sizeof(intervals) / sizeof(intervals[0]); a++) {
			for (unsigned int b = 0; b < sizeof(intervals) / sizeof(intervals[0]);
			     b++) {
				uint64_t interval = intervals[a] > intervals[b] ? intervals[a]
										: intervals[b];
				/* Independent reference by repeated addition, not multiplication. */
				uint64_t expected = 0;
				for (unsigned int n = 0; n < multipliers[m]; n++)
					expected += interval;
				uint64_t actual = bfd_detection_timeout_us(multipliers[m],
									   intervals[a],
									   intervals[b]);
				assert(actual == expected);
				struct timeval tv = bfd_detection_timeout_tv(actual);
				assert(tv.tv_usec >= 0 && tv.tv_usec < 1000000);
				assert((uint64_t)tv.tv_sec * 1000000 + tv.tv_usec == expected);
				/* The greatest legal product's normalized parts fit signed 32 bits. */
				assert(tv.tv_sec <= INT32_MAX && tv.tv_usec <= INT32_MAX);
				checks++;
			}
		}
	}
	assert(checks == 196);
	puts("BFD detection-time arithmetic and normalized timer conversion passed.");
	return 0;
}
