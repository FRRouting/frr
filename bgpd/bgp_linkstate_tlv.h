// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Link-State TLV Serializer/Deserializer header
 * Copyright 2023 6WIND S.A.
 */

#ifndef BGP_LINKSTATE_TLV_H
#define BGP_LINKSTATE_TLV_H

extern int bgp_nlri_parse_linkstate(struct peer *peer, struct attr *attr,
				    struct bgp_nlri *packet, int withdraw);
extern void bgp_nlri_encode_linkstate(struct stream *s, const struct prefix *p);

#endif /* BGP_LINKSTATE_TLV_H */
