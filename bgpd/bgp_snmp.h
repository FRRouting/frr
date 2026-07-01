// SPDX-License-Identifier: GPL-2.0-or-later
/* Common header file for BGP SNMP implementation.
 *
 * Copyright (C) 2022 Donatas Abraitis <donatas@opensourcerouting.org>
 */

#ifndef _FRR_BGP_SNMP_H_
#define _FRR_BGP_SNMP_H_

/* SNMP value hack. */
#define INTEGER ASN_INTEGER
#define INTEGER32 ASN_INTEGER
#define COUNTER32 ASN_COUNTER
#define OCTET_STRING ASN_OCTET_STR
#define IPADDRESS ASN_IPADDRESS
#define GAUGE32 ASN_UNSIGNED

extern struct peer *bgp_snmp_lookup_peer(vrf_id_t vrf_id, const struct ipaddr *addr);
extern struct peer *bgp_snmp_get_first_peer(bool all_vrfs, sa_family_t family);
extern struct peer *bgp_snmp_get_next_peer(bool all_vrfs, vrf_id_t peer_vrf_id, sa_family_t family,
					   const struct ipaddr *addr);
extern struct peer_af *bgp_snmp_peer_af_next(struct peer *peer, afi_t afi, safi_t safi);

/*
 * Workaround for net-snmp 5.7.3: OID array items are uninitialized
 * and contain random values. Zero them out to ensure correct behavior.
 * This issue is fixed in net-snmp 5.8+.
 */
static inline void bgp_snmp_index_init(oid *index, size_t max_len)
{
	memset(index, 0, max_len * sizeof(oid));
}

#endif /* _FRR_BGP_SNMP_H_ */
