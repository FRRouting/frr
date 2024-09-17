#ifndef BGP_RTC_H
#define BGP_RTC_H
#include <zebra.h>
#include <stdbool.h>
#include <stdint.h>
#include "bgpd.h"
#include "bgp_attr.h"
#include "bgp_ecommunity.h"
#include "vty.h"
#include "lib/prefix.h"

#define BGP_RTC_MAX_PREFIXLEN 96

extern int bgp_nlri_parse_rtc(struct peer *peer, struct attr *attr,
			      struct bgp_nlri *packet, bool withdraw);
extern int bgp_rtc_filter(struct peer *peer, struct attr *attr, const struct prefix *p);
extern void bgp_rtc_add_static(struct bgp *bgp, struct ecommunity_val *eval,
			       uint32_t prefixlen);
extern void bgp_rtc_remove_static(struct bgp *bgp, struct ecommunity_val *eval,
				  uint32_t prefixlen);
int bgp_rtc_static_from_str(struct vty *vty, struct bgp *bgp, const char *str,
			    bool add);
#endif /* BGP_RTC_H */