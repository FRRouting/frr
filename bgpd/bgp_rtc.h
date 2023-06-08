// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP RTC - Constrained Route Distribution
 * Constrained Route Distribution - RFC 4684
 * Copyright (C) 2023 Alexander Sohn
 */

#ifndef BGP_RTC_H
#define BGP_RTC_H

#include <zebra.h>
#include "bgpd.h"
#include "bgp_attr.h"

extern int bgp_nlri_parse_rtc(struct peer *peer, struct attr *attr, struct bgp_nlri *packet,
			      bool withdraw);

#endif /* BGP_RTC_H */
