// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * iana_afi and safi definitions.
 * Copyright (C) 2018-2019 Cumulus Networks, Inc.
 * Donald Sharp
 */
#ifndef __IANA_AFI_H__

#include <prefix.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The above AFI and SAFI definitions are for internal use. The protocol
 * definitions (IANA values) as for example used in BGP protocol packets
 * are defined below and these will get mapped to/from the internal values
 * in the appropriate places.
 * The rationale is that the protocol (IANA) values may be sparse and are
 * not optimal for use in data-structure sizing.
 * Note: Only useful (i.e., supported) values are defined below.
 */
typedef enum {
	IANA_AFI_RESERVED = 0,
	IANA_AFI_IPV4 = 1,
	IANA_AFI_IPV6 = 2,
	IANA_AFI_L2VPN = 25,
} iana_afi_t;

typedef enum {
	IANA_SAFI_RESERVED = 0,
	IANA_SAFI_UNICAST = 1,
	IANA_SAFI_MULTICAST = 2,
	IANA_SAFI_LABELED_UNICAST = 4,
	IANA_SAFI_ENCAP = 7,
	IANA_SAFI_EVPN = 70,
	IANA_SAFI_MPLS_VPN = 128,
	IANA_SAFI_FLOWSPEC = 133
} iana_safi_t;

static inline afi_t afi_iana2int(iana_afi_t afi)
{
	switch (afi) {
	case IANA_AFI_IPV4:
		return AFI_IP;
	case IANA_AFI_IPV6:
		return AFI_IP6;
	case IANA_AFI_L2VPN:
		return AFI_L2VPN;
	case IANA_AFI_RESERVED:
		return AFI_MAX;
	}

	return AFI_MAX;
}

static inline iana_afi_t afi_int2iana(afi_t afi)
{
	switch (afi) {
	case AFI_IP:
		return IANA_AFI_IPV4;
	case AFI_IP6:
		return IANA_AFI_IPV6;
	case AFI_L2VPN:
		return IANA_AFI_L2VPN;
	case AFI_UNSPEC:
	case AFI_MAX:
		return IANA_AFI_RESERVED;
	}

	return IANA_AFI_RESERVED;
}

static inline const char *iana_afi2str(iana_afi_t afi)
{
	return afi2str(afi_iana2int(afi));
}

static inline safi_t safi_iana2int(iana_safi_t safi)
{
	switch (safi) {
	case IANA_SAFI_UNICAST:
		return SAFI_UNICAST;
	case IANA_SAFI_MULTICAST:
		return SAFI_MULTICAST;
	case IANA_SAFI_MPLS_VPN:
		return SAFI_MPLS_VPN;
	case IANA_SAFI_ENCAP:
		return SAFI_ENCAP;
	case IANA_SAFI_EVPN:
		return SAFI_EVPN;
	case IANA_SAFI_LABELED_UNICAST:
		return SAFI_LABELED_UNICAST;
	case IANA_SAFI_FLOWSPEC:
		return SAFI_FLOWSPEC;
	case IANA_SAFI_RESERVED:
		return SAFI_MAX;
	}

	return SAFI_MAX;
}

static inline iana_safi_t safi_int2iana(safi_t safi)
{
	switch (safi) {
	case SAFI_UNICAST:
		return IANA_SAFI_UNICAST;
	case SAFI_MULTICAST:
		return IANA_SAFI_MULTICAST;
	case SAFI_MPLS_VPN:
		return IANA_SAFI_MPLS_VPN;
	case SAFI_ENCAP:
		return IANA_SAFI_ENCAP;
	case SAFI_EVPN:
		return IANA_SAFI_EVPN;
	case SAFI_LABELED_UNICAST:
		return IANA_SAFI_LABELED_UNICAST;
	case SAFI_FLOWSPEC:
		return IANA_SAFI_FLOWSPEC;
	case SAFI_UNSPEC:
	case SAFI_MAX:
		return IANA_SAFI_RESERVED;
	}

	return IANA_SAFI_RESERVED;
}

static inline const char *iana_safi2str(iana_safi_t safi)
{
	return safi2str(safi_iana2int(safi));
}

#ifdef __cplusplus
}
#endif

#endif
