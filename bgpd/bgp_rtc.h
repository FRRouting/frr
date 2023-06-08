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


enum rtc_prefix_list_type {
	RTC_PREFIX_DENY = 0,
	RTC_PREFIX_PERMIT,
};

struct bgp_rtc_plist_entry {
	struct list *origin_as;
	uint8_t route_target[8];
	uint8_t prefixlen;
};

struct bgp_rtc_plist {
	struct list *entries;
	struct in_addr router_id;
};

extern int bgp_nlri_parse_rtc(struct peer *peer, struct attr *attr, struct bgp_nlri *packet,
			      bool withdraw);

extern enum rtc_prefix_list_type bgp_rtc_filter(struct peer *peer, struct ecommunity *ecom);

extern void bgp_rtc_add_ecommunity_val_dynamic(struct bgp *bgp, struct ecommunity_val *eval);
extern void bgp_rtc_remove_ecommunity_val_dynamic(struct bgp *bgp, struct ecommunity_val *eval);
extern void bgp_rtc_update_vpn_policy_ecommunity_dynamic(struct bgp *bgp, afi_t afi,
							 struct ecommunity *old_ecom,
							 struct ecommunity *new_ecom);

extern int bgp_rtc_static_from_str(struct vty *vty, struct bgp *bgp, const char *str, bool add);

extern char *bgp_rtc_prefix_display(char *buf, size_t size, uint16_t prefix_len,
				    const struct rtc_info *rtc_info);

extern void bgp_rtc_plist_free(void *arg);
extern struct bgp_rtc_plist *bgp_peer_get_rtc_plist(struct peer *peer);
extern int bgp_rtc_plist_entry_set(struct peer *peer, struct prefix *p, bool add);
extern void bgp_show_rtc_plist(struct vty *vty, struct bgp_rtc_plist *rtc_plist, bool json);

extern void bgp_rtc_init(void);
#endif /* BGP_RTC_H */
