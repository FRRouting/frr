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
#include "vty.h"
#include "bgp_nht.h"

extern int bgp_nlri_parse_rtc(struct peer *peer, struct attr *attr, struct bgp_nlri *packet,
			      bool withdraw);
extern void bgp_rtc_add_ecommunity_val_dynamic(struct bgp *bgp, struct ecommunity_val *eval);
extern void bgp_rtc_remove_ecommunity_val_dynamic(struct bgp *bgp, struct ecommunity_val *eval);
extern void bgp_rtc_update_vpn_policy_ecommunity_dynamic(struct bgp *bgp, afi_t afi,
							 struct ecommunity *old_ecom,
							 struct ecommunity *new_ecom);

extern int bgp_rtc_static_from_str(struct vty *vty, struct bgp *bgp, const char *str, bool add);

extern char *bgp_rtc_prefix_display(char *buf, size_t size, uint16_t prefix_len,
				    const struct rtc_info *rtc_info);
extern void bgp_rtc_init(void);
#endif /* BGP_RTC_H */
