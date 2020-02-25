
/* Interface function header.
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_INTERFACE_H
#define _ZEBRA_INTERFACE_H

#include "redistribute.h"
#include "vrf.h"
#include "hook.h"

#include "zebra/zebra_l2.h"
#include "zebra/zebra_nhg_private.h"

#ifdef __cplusplus
extern "C" {
#endif

/* For interface multicast configuration. */
#define IF_ZEBRA_MULTICAST_UNSPEC 0
#define IF_ZEBRA_MULTICAST_ON     1
#define IF_ZEBRA_MULTICAST_OFF    2

/* For interface shutdown configuration. */
#define IF_ZEBRA_SHUTDOWN_OFF    0
#define IF_ZEBRA_SHUTDOWN_ON     1

#if defined(HAVE_RTADV)
/* Router advertisement parameter.  From RFC4861, RFC6275 and RFC4191. */
struct rtadvconf {
	/* A flag indicating whether or not the router sends periodic Router
	   Advertisements and responds to Router Solicitations.
	   Default: false */
	int AdvSendAdvertisements;

	/* The maximum time allowed between sending unsolicited multicast
	   Router Advertisements from the interface, in milliseconds.
	   MUST be no less than 70 ms [RFC6275 7.5] and no greater
	   than 1800000 ms [RFC4861 6.2.1].

	   Default: 600000 milliseconds */
	int MaxRtrAdvInterval;
#define RTADV_MAX_RTR_ADV_INTERVAL 600000

	/* The minimum time allowed between sending unsolicited multicast
	   Router Advertisements from the interface, in milliseconds.
	   MUST be no less than 30 ms [RFC6275 7.5].
	   MUST be no greater than .75 * MaxRtrAdvInterval.

	   Default: 0.33 * MaxRtrAdvInterval */
	int MinRtrAdvInterval; /* This field is currently unused. */
#define RTADV_MIN_RTR_ADV_INTERVAL (0.33 * RTADV_MAX_RTR_ADV_INTERVAL)

	/* Unsolicited Router Advertisements' interval timer. */
	int AdvIntervalTimer;

	/* The true/false value to be placed in the "Managed address
	   configuration" flag field in the Router Advertisement.  See
	   [ADDRCONF].

	   Default: false */
	int AdvManagedFlag;


	/* The true/false value to be placed in the "Other stateful
	   configuration" flag field in the Router Advertisement.  See
	   [ADDRCONF].

	   Default: false */
	int AdvOtherConfigFlag;

	/* The value to be placed in MTU options sent by the router.  A
	   value of zero indicates that no MTU options are sent.

	   Default: 0 */
	int AdvLinkMTU;


	/* The value to be placed in the Reachable Time field in the Router
	   Advertisement messages sent by the router.  The value zero means
	   unspecified (by this router).  MUST be no greater than 3,600,000
	   milliseconds (1 hour).

	   Default: 0 */
	uint32_t AdvReachableTime;
#define RTADV_MAX_REACHABLE_TIME 3600000

	/* The value to be placed in the Retrans Timer field in the Router
	   Advertisement messages sent by the router.  The value zero means
	   unspecified (by this router).

	   Default: 0 */
	int AdvRetransTimer;

	/* The default value to be placed in the Cur Hop Limit field in the
	   Router Advertisement messages sent by the router.  The value
	   should be set to that current diameter of the Internet.  The
	   value zero means unspecified (by this router).

	   Default: The value specified in the "Assigned Numbers" RFC
	   [ASSIGNED] that was in effect at the time of implementation. */
	int AdvCurHopLimit;

	/* The value to be placed in the Router Lifetime field of Router
	   Advertisements sent from the interface, in seconds.  MUST be
	   either zero or between MaxRtrAdvInterval and 9000 seconds.  A
	   value of zero indicates that the router is not to be used as a
	   default router.

	   Default: 3 * MaxRtrAdvInterval */
	int AdvDefaultLifetime;
#define RTADV_MAX_RTRLIFETIME 9000 /* 2.5 hours */

	/* A list of prefixes to be placed in Prefix Information options in
	   Router Advertisement messages sent from the interface.

	   Default: all prefixes that the router advertises via routing
	   protocols as being on-link for the interface from which the
	   advertisement is sent. The link-local prefix SHOULD NOT be
	   included in the list of advertised prefixes. */
	struct list *AdvPrefixList;

	/* The true/false value to be placed in the "Home agent"
	   flag field in the Router Advertisement.  See [RFC6275 7.1].

	   Default: false */
	int AdvHomeAgentFlag;
#ifndef ND_RA_FLAG_HOME_AGENT
#define ND_RA_FLAG_HOME_AGENT 	0x20
#endif

	/* The value to be placed in Home Agent Information option if Home
	   Flag is set.
	   Default: 0 */
	int HomeAgentPreference;

	/* The value to be placed in Home Agent Information option if Home
	   Flag is set. Lifetime (seconds) MUST not be greater than 18.2
	   hours.
	   The value 0 has special meaning: use of AdvDefaultLifetime value.

	   Default: 0 */
	int HomeAgentLifetime;
#define RTADV_MAX_HALIFETIME 65520 /* 18.2 hours */

	/* The true/false value to insert or not an Advertisement Interval
	   option. See [RFC 6275 7.3]

	   Default: false */
	int AdvIntervalOption;

	/* The value to be placed in the Default Router Preference field of
	   a router advertisement. See [RFC 4191 2.1 & 2.2]

	   Default: 0 (medium) */
	int DefaultPreference;
#define RTADV_PREF_MEDIUM 0x0 /* Per RFC4191. */

	/*
	 * List of recursive DNS servers to include in the RDNSS option.
	 * See [RFC8106 5.1]
	 *
	 * Default: empty list; do not emit RDNSS option
	 */
	struct list *AdvRDNSSList;

	/*
	 * List of DNS search domains to include in the DNSSL option.
	 * See [RFC8106 5.2]
	 *
	 * Default: empty list; do not emit DNSSL option
	 */
	struct list *AdvDNSSLList;

	/*
	 * rfc4861 states RAs must be sent at least 3 seconds apart.
	 * We allow faster retransmits to speed up convergence but can
	 * turn that capability off to meet the rfc if needed.
	 */
	bool UseFastRexmit; /* True if fast rexmits are enabled */

	uint8_t inFastRexmit; /* True if we're rexmits faster than usual */

	/* Track if RA was configured by BGP or by the Operator or both */
	uint8_t ra_configured;    /* Was RA configured? */
#define BGP_RA_CONFIGURED (1<<0)  /* BGP configured RA? */
#define VTY_RA_CONFIGURED (1<<1)  /* Operator configured RA? */
#define VTY_RA_INTERVAL_CONFIGURED (1<<2)  /* Operator configured RA interval */
	int NumFastReXmitsRemain; /* Loaded first with number of fast
				     rexmits to do */

#define RTADV_FAST_REXMIT_PERIOD 1 /* 1 sec */
#define RTADV_NUM_FAST_REXMITS   4 /* Fast Rexmit RA 4 times on certain events */
};

struct rtadv_rdnss {
	/* Address of recursive DNS server to advertise */
	struct in6_addr addr;

	/*
	 * Lifetime in seconds; all-ones means infinity, zero
	 * stop using it.
	 */
	uint32_t lifetime;

	/* If lifetime not set, use a default of 3*MaxRtrAdvInterval */
	int lifetime_set;
};

/*
 * [RFC1035 2.3.4] sets the maximum length of a domain name (a sequence of
 * labels, each prefixed by a length octet) at 255 octets.
 */
#define RTADV_MAX_ENCODED_DOMAIN_NAME 255

struct rtadv_dnssl {
	/* Domain name without trailing root zone dot (NUL-terminated) */
	char name[RTADV_MAX_ENCODED_DOMAIN_NAME - 1];

	/* Name encoded as in [RFC1035 3.1] */
	uint8_t encoded_name[RTADV_MAX_ENCODED_DOMAIN_NAME];

	/* Actual length of encoded_name */
	size_t encoded_len;

	/* Lifetime as for RDNSS */
	uint32_t lifetime;
	int lifetime_set;
};

#endif /* HAVE_RTADV */

/* Zebra interface type - ones of interest. */
typedef enum {
	ZEBRA_IF_OTHER = 0, /* Anything else */
	ZEBRA_IF_VXLAN,     /* VxLAN interface */
	ZEBRA_IF_VRF,       /* VRF device */
	ZEBRA_IF_BRIDGE,    /* bridge device */
	ZEBRA_IF_VLAN,      /* VLAN sub-interface */
	ZEBRA_IF_MACVLAN,   /* MAC VLAN interface*/
	ZEBRA_IF_VETH,      /* VETH interface*/
	ZEBRA_IF_BOND,	    /* Bond */
	ZEBRA_IF_BOND_SLAVE,	    /* Bond */
} zebra_iftype_t;

/* Zebra "slave" interface type */
typedef enum {
	ZEBRA_IF_SLAVE_NONE,   /* Not a slave */
	ZEBRA_IF_SLAVE_VRF,    /* Member of a VRF */
	ZEBRA_IF_SLAVE_BRIDGE, /* Member of a bridge */
	ZEBRA_IF_SLAVE_BOND,   /* Bond member */
	ZEBRA_IF_SLAVE_OTHER,  /* Something else - e.g., bond slave */
} zebra_slave_iftype_t;

struct irdp_interface;

/* `zebra' daemon local interface structure. */
struct zebra_if {
	/* Shutdown configuration. */
	uint8_t shutdown;

	/* Multicast configuration. */
	uint8_t multicast;

	/* Router advertise configuration. */
	uint8_t rtadv_enable;

	/* Installed addresses chains tree. */
	struct route_table *ipv4_subnets;

	/* Nexthops pointing to this interface */
	/**
	 * Any nexthop that we get should have an
	 * interface. When an interface goes down,
	 * we will use this list to update the nexthops
	 * pointing to it with that info.
	 */
	struct nhg_connected_tree_head nhg_dependents;

	/* Information about up/down changes */
	unsigned int up_count;
	char up_last[QUAGGA_TIMESTAMP_LEN];
	unsigned int down_count;
	char down_last[QUAGGA_TIMESTAMP_LEN];

#if defined(HAVE_RTADV)
	struct rtadvconf rtadv;
	unsigned int ra_sent, ra_rcvd;
#endif /* HAVE_RTADV */

	struct irdp_interface *irdp;

#ifdef HAVE_STRUCT_SOCKADDR_DL
	union {
		/* note that sdl_storage is never accessed, it only exists to
		 * make space.
		 * all actual uses refer to sdl - but use sizeof(sdl_storage)!
		 * this fits
		 * best with C aliasing rules. */
		struct sockaddr_dl sdl;
		struct sockaddr_storage sdl_storage;
	};
#endif

#ifdef SUNOS_5
	/* the real IFF_UP state of the primary interface.
	 * need this to differentiate between all interfaces being
	 * down (but primary still plumbed) and primary having gone
	 * ~IFF_UP, and all addresses gone.
	 */
	uint8_t primary_state;
#endif /* SUNOS_5 */

	/* ptm enable configuration */
	uint8_t ptm_enable;

	/* Zebra interface and "slave" interface type */
	zebra_iftype_t zif_type;
	zebra_slave_iftype_t zif_slave_type;

	/* Additional L2 info, depends on zif_type */
	union zebra_l2if_info l2info;

	/* For members of a bridge, link to bridge. */
	/* Note: If additional fields become necessary, this can be modified to
	 * be a pointer to a dynamically allocd struct.
	 */
	struct zebra_l2info_brslave brslave_info;

	struct zebra_l2info_bondslave bondslave_info;

	/* Link fields - for sub-interfaces. */
	ifindex_t link_ifindex;
	struct interface *link;

	struct thread *speed_update;

	/*
	 * Does this interface have a v6 to v4 ll neighbor entry
	 * for bgp unnumbered?
	 */
	bool v6_2_v4_ll_neigh_entry;
	char neigh_mac[6];
	struct in6_addr v6_2_v4_ll_addr6;

	/* The description of the interface */
	char *desc;
};

DECLARE_HOOK(zebra_if_extra_info, (struct vty * vty, struct interface *ifp),
	     (vty, ifp))
DECLARE_HOOK(zebra_if_config_wr, (struct vty * vty, struct interface *ifp),
	     (vty, ifp))

static inline void zebra_if_set_ziftype(struct interface *ifp,
					zebra_iftype_t zif_type,
					zebra_slave_iftype_t zif_slave_type)
{
	struct zebra_if *zif;

	zif = (struct zebra_if *)ifp->info;
	zif->zif_type = zif_type;
	zif->zif_slave_type = zif_slave_type;
}

#define IS_ZEBRA_IF_VRF(ifp)                                                   \
	(((struct zebra_if *)(ifp->info))->zif_type == ZEBRA_IF_VRF)

#define IS_ZEBRA_IF_BRIDGE(ifp)                                                \
	(((struct zebra_if *)(ifp->info))->zif_type == ZEBRA_IF_BRIDGE)

#define IS_ZEBRA_IF_VLAN(ifp)                                                  \
	(((struct zebra_if *)(ifp->info))->zif_type == ZEBRA_IF_VLAN)

#define IS_ZEBRA_IF_VXLAN(ifp)                                                 \
	(((struct zebra_if *)(ifp->info))->zif_type == ZEBRA_IF_VXLAN)

#define IS_ZEBRA_IF_MACVLAN(ifp)                                               \
	(((struct zebra_if *)(ifp->info))->zif_type == ZEBRA_IF_MACVLAN)

#define IS_ZEBRA_IF_VETH(ifp)                                               \
	(((struct zebra_if *)(ifp->info))->zif_type == ZEBRA_IF_VETH)

#define IS_ZEBRA_IF_BRIDGE_SLAVE(ifp)					\
	(((struct zebra_if *)(ifp->info))->zif_slave_type                      \
	 == ZEBRA_IF_SLAVE_BRIDGE)

#define IS_ZEBRA_IF_VRF_SLAVE(ifp)                                             \
	(((struct zebra_if *)(ifp->info))->zif_slave_type == ZEBRA_IF_SLAVE_VRF)

#define IS_ZEBRA_IF_BOND_SLAVE(ifp)					\
	(((struct zebra_if *)(ifp->info))->zif_slave_type                      \
	 == ZEBRA_IF_SLAVE_BOND)

extern void zebra_if_init(void);

extern struct interface *if_lookup_by_index_per_ns(struct zebra_ns *, uint32_t);
extern struct interface *if_lookup_by_name_per_ns(struct zebra_ns *,
						  const char *);
extern struct interface *if_link_per_ns(struct zebra_ns *, struct interface *);
extern const char *ifindex2ifname_per_ns(struct zebra_ns *, unsigned int);

extern void if_unlink_per_ns(struct interface *);
extern void if_nbr_mac_to_ipv4ll_neigh_update(struct interface *fip,
					      char mac[6],
					      struct in6_addr *address,
					      int add);
extern void if_nbr_ipv6ll_to_ipv4ll_neigh_update(struct interface *ifp,
						 struct in6_addr *address,
						 int add);
extern void if_nbr_ipv6ll_to_ipv4ll_neigh_del_all(struct interface *ifp);
extern void if_delete_update(struct interface *ifp);
extern void if_add_update(struct interface *ifp);
extern void if_up(struct interface *);
extern void if_down(struct interface *);
extern void if_refresh(struct interface *);
extern void if_flags_update(struct interface *, uint64_t);
extern int if_subnet_add(struct interface *, struct connected *);
extern int if_subnet_delete(struct interface *, struct connected *);
extern int ipv6_address_configured(struct interface *ifp);
extern void if_handle_vrf_change(struct interface *ifp, vrf_id_t vrf_id);
extern void zebra_if_update_link(struct interface *ifp, ifindex_t link_ifindex,
				 ns_id_t ns_id);
extern void zebra_if_update_all_links(void);
extern void zebra_if_set_protodown(struct interface *ifp, bool down);

/* Nexthop group connected functions */
extern void if_nhg_dependents_add(struct interface *ifp,
				  struct nhg_hash_entry *nhe);
extern void if_nhg_dependents_del(struct interface *ifp,
				  struct nhg_hash_entry *nhe);
extern unsigned int if_nhg_dependents_count(const struct interface *ifp);
extern bool if_nhg_dependents_is_empty(const struct interface *ifp);

extern void vrf_add_update(struct vrf *vrfp);

#ifdef HAVE_PROC_NET_DEV
extern void ifstat_update_proc(void);
#endif /* HAVE_PROC_NET_DEV */
#ifdef HAVE_NET_RT_IFLIST
extern void ifstat_update_sysctl(void);

#endif /* HAVE_NET_RT_IFLIST */
#ifdef HAVE_PROC_NET_DEV
extern int interface_list_proc(void);
#endif /* HAVE_PROC_NET_DEV */
#ifdef HAVE_PROC_NET_IF_INET6
extern int ifaddr_proc_ipv6(void);
#endif /* HAVE_PROC_NET_IF_INET6 */

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_INTERFACE_H */
