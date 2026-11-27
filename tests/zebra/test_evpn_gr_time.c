// SPDX-License-Identifier: GPL-2.0-or-later

#include <zebra.h>

#include "zebra/zebra_evpn.h"

int main(void)
{
	const struct timeval cleanup_time = { .tv_sec = 100, .tv_usec = 800000 };
	const struct timeval later_same_second = { .tv_sec = 100, .tv_usec = 800001 };
	const struct timeval earlier_same_second = { .tv_sec = 100, .tv_usec = 799999 };
	const struct timeval same_time = { .tv_sec = 100, .tv_usec = 800000 };
	const struct timeval next_second = { .tv_sec = 101, .tv_usec = 0 };

	if (!zebra_evpn_vtep_gr_imet_refreshed_after(&later_same_second, &cleanup_time))
		return 1;
	puts("same-second RT-3 refresh after cutoff: fresh");

	if (zebra_evpn_vtep_gr_imet_refreshed_after(&earlier_same_second, &cleanup_time))
		return 1;
	puts("same-second RT-3 refresh before cutoff: stale");

	if (zebra_evpn_vtep_gr_imet_refreshed_after(&same_time, &cleanup_time))
		return 1;
	puts("RT-3 refresh equal to cutoff: stale");

	if (!zebra_evpn_vtep_gr_imet_refreshed_after(&next_second, &cleanup_time))
		return 1;
	puts("later-second RT-3 refresh: fresh");

	return 0;
}
