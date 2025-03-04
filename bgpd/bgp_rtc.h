// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Route-target constrain feature
 * Copyright (C) 2025 Cisco Systems Inc.
 */

#ifndef _BGP_RTC_H
#define _BGP_RTC_H 1

#include "lib/zebra.h"
#include "bgpd.h"

/* Max prefixlen for an RTC "prefix", formed from an RT */
#define BGP_RTC_PREFIX_MAXLEN 96

/* Init, deinit peer's RTC data */
void bgp_rtc_peer_init(struct peer *peer);
void bgp_rtc_peer_delete(struct peer *peer);
/* RTC import list change: may be "remove imports", or "add/change imports" */
int bgp_rtc_import_update(struct bgp *bgp, const struct ecommunity *oldcomm,
			  const struct ecommunity *newcomm, bool update);
/* RTC peer activate/deactivate change */
int bgp_rtc_peer_update(struct peer *peer, afi_t afi, safi_t safi, bool active);
/* Finer-grained RT change for RTC: add or remove one RT */
struct ecommunity_val; /* Forward ref */
int bgp_rtc_import_change(struct bgp *bgp, const struct ecommunity_val *eval,
			  bool add_p);
/* RTC prefix advertisement update */
int bgp_rtc_prefix_update(struct bgp_dest *dest, struct bgp_path_info *oldpi,
			  struct bgp_path_info *newpi);
/* Special handling for peer advertising the RTC default prefix */
int bgp_rtc_default_update(struct peer *peer, const struct prefix *p,
			   bool add_p);
/* Check peer's outbound RTC filter. */
bool bgp_rtc_peer_filter_check(struct peer *peer, const struct attr *attr,
			       afi_t afi, safi_t safi);
/* Show output helper */
void bgp_rtc_show_peer(const struct peer *peer, struct vty *vty,
		       json_object *jneigh);

#endif /* _BGP_RTC_H */
