// SPDX-License-Identifier: GPL-2.0-or-later
/* Typed policy checks; no packet generation or network access. */
#include <zebra.h>
#include "bgpd/bgpd.h"
#include "bgpd/bgp_packet.h"

int main(void)
{
	assert(bgp_refresh_min_payload(false) == 4);
	assert(bgp_refresh_min_payload(true) == 3);
	/* Both thresholds protect the AFI and subtype reads; the legacy
	 * threshold additionally guarantees the complete fixed body.
	 */
	for (unsigned int enhanced = 0; enhanced < 2; enhanced++) {
		for (size_t length = 0; length <= UINT16_MAX; length++) {
			bool admitted = length >= bgp_refresh_min_payload(enhanced);

			if (admitted)
				assert(length >= 3);
			if (!enhanced && admitted)
				assert(length >= 4);
		}
	}
	puts("refresh preflight read bounds OK");
	/* Diagnostic accounting cannot exceed either buffer, with or without
	 * Hard Reset encapsulation. These are sizes, not encoded messages.
	 */
	for (unsigned int wrapper = 0; wrapper < 2; wrapper++) {
		size_t overhead = BGP_MSG_NOTIFY_MIN_SIZE + 2 * wrapper;
		const size_t limits[] = {0, 1, 21, 22, 23, 4096, 65535};

		for (size_t i = 0; i < array_size(limits); i++) {
			size_t maximum = limits[i];

			for (size_t size = 0; size <= UINT16_MAX; size++) {
				size_t available = size / 2;
				size_t n = bgp_refresh_error_data_size(size, available,
								     maximum, wrapper);

				assert(n <= size && n <= available);
				if (maximum <= overhead)
					assert(n == 0);
				else
					assert(n + overhead <= maximum);
			}
		}
		assert(bgp_refresh_error_data_size(24, 24, 4096, wrapper) == 24);
		assert(bgp_refresh_error_data_size(4096, 4096, 4096, wrapper) ==
		       4096 - overhead);
		assert(bgp_refresh_error_data_size(65535, 65535, 65535, wrapper) ==
		       65535 - overhead);
	}
	puts("diagnostic buffer bounds OK");
	return 0;
}
