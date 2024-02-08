// SPDX-License-Identifier: GPL-2.0-or-later

/* Interface function header.
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_INTERFACE_H
#define _ZEBRA_INTERFACE_H

#include "redistribute.h"
#include "vrf.h"
#include "hook.h"
#include "bitfield.h"

#include "zebra/zebra_l2.h"
#include "zebra/zebra_l2_bridge_if.h"
#include "zebra/zebra_nhg_private.h"
#include "zebra/zebra_router.h"
#include "zebra/rtadv.h"

#ifdef __cplusplus
extern "C" {
#endif

/* For interface configuration. */
#define IF_ZEBRA_DATA_UNSPEC 0
#define IF_ZEBRA_DATA_ON 1
#define IF_ZEBRA_DATA_OFF 2

#define IF_VLAN_BITMAP_MAX 4096

/* Zebra interface type - ones of interest. */
enum zebra_iftype {
	ZEBRA_IF_OTHER = 0, /* Anything else */
	ZEBRA_IF_VXLAN,     /* VxLAN interface */
	ZEBRA_IF_VRF,       /* VRF device */
	ZEBRA_IF_BRIDGE,    /* bridge device */
	ZEBRA_IF_VLAN,      /* VLAN sub-interface */
	ZEBRA_IF_MACVLAN,   /* MAC VLAN interface*/
	ZEBRA_IF_VETH,      /* VETH interface*/
	ZEBRA_IF_BOND,	    /* Bond */
	ZEBRA_IF_GRE,      /* GRE interface */
};

/* Zebra "slave" interface type */
enum zebra_slave_iftype {
	ZEBRA_IF_SLAVE_NONE,   /* Not a slave */
	ZEBRA_IF_SLAVE_VRF,    /* Member of a VRF */
	ZEBRA_IF_SLAVE_BRIDGE, /* Member of a bridge */
	ZEBRA_IF_SLAVE_BOND,   /* Bond member */
	ZEBRA_IF_SLAVE_OTHER,  /* Something else - e.g., bond slave */
};

struct irdp_interface;

/* Ethernet segment info used for setting up EVPN multihoming */
struct zebra_evpn_es;
struct zebra_es_if_info {
	/* type-3 esi config */
	struct ethaddr sysmac;
	uint32_t lid; /* local-id; has to be unique per-ES-sysmac */

	esi_t esi;

	uint16_t df_pref;
	uint8_t flags;
#define ZIF_CFG_ES_FLAG_BYPASS (1 << 0)

	struct zebra_evpn_es *es; /* local ES */
};

enum zebra_if_flags {
	/* device has been configured as an uplink for
	 * EVPN multihoming
	 */
	ZIF_FLAG_EVPN_MH_UPLINK = (1 << 0),
	ZIF_FLAG_EVPN_MH_UPLINK_OPER_UP = (1 << 1),

	/* Dataplane protodown-on */
	ZIF_FLAG_PROTODOWN = (1 << 2),
	/* Dataplane protodown-on Queued to the dplane */
	ZIF_FLAG_SET_PROTODOWN = (1 << 3),
	/* Dataplane protodown-off Queued to the dplane */
	ZIF_FLAG_UNSET_PROTODOWN = (1 << 4),

	/* LACP bypass state is set by the dataplane on a bond member
	 * and inherited by the bond (if one or more bond members are in
	 * a bypass state the bond is placed in a bypass state)
	 */
	ZIF_FLAG_LACP_BYPASS = (1 << 5)
};

#define ZEBRA_IF_IS_PROTODOWN(zif) ((zif)->flags & ZIF_FLAG_PROTODOWN)
#define ZEBRA_IF_IS_PROTODOWN_ONLY_EXTERNAL(zif)                               \
	((zif)->protodown_rc == ZEBRA_PROTODOWN_EXTERNAL)

/* Mem type for zif desc */
DECLARE_MTYPE(ZIF_DESC);

/* `zebra' daemon local interface structure. */
struct zebra_if {
	/* back pointer to the interface */
	struct interface *ifp;

	enum zebra_if_flags flags;

	/* Shutdown configuration. */
	uint8_t shutdown;

	/* Multicast configuration. */
	uint8_t multicast;

	/* MPLS status. */
	bool mpls;

	/* MPLS configuration */
	uint8_t mpls_config;

	/* Linkdown status */
	bool linkdown, linkdownv6;

	/* Is Multicast Forwarding on? */
	bool v4mcast_on, v6mcast_on;

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
	char up_last[FRR_TIMESTAMP_LEN];
	unsigned int down_count;
	char down_last[FRR_TIMESTAMP_LEN];

	struct rtadvconf rtadv;
	unsigned int ra_sent, ra_rcvd;

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

	/* ptm enable configuration */
	uint8_t ptm_enable;

	/* Zebra interface and "slave" interface type */
	enum zebra_iftype zif_type;
	enum zebra_slave_iftype zif_slave_type;

	/* Additional L2 info, depends on zif_type */
	union zebra_l2if_info l2info;

	/* For members of a bridge, link to bridge. */
	/* Note: If additional fields become necessary, this can be modified to
	 * be a pointer to a dynamically allocd struct.
	 */
	struct zebra_l2info_brslave brslave_info;

	struct zebra_l2info_bondslave bondslave_info;
	struct zebra_l2info_bond bond_info;

	/* ethernet segment */
	struct zebra_es_if_info es_info;

	/* bitmap of vlans associated with this interface */
	bitfield_t vlan_bitmap;

	/* An interface can be error-disabled if a protocol (such as EVPN or
	 * VRRP) detects a problem with keeping it operationally-up.
	 * If any of the protodown bits are set protodown-on is programmed
	 * in the dataplane. This results in a carrier/L1 down on the
	 * physical device.
	 */
	uint32_t protodown_rc;

	/* list of zebra_mac entries using this interface as destination */
	struct list *mac_list;

	/* Link fields - for sub-interfaces. */
	ns_id_t link_nsid;
	ifindex_t link_ifindex;
	struct interface *link;

#define INTERFACE_SPEED_ERROR_READ    -1
#define INTERFACE_SPEED_ERROR_UNKNOWN -2

	uint8_t speed_update_count;
	struct event *speed_update;

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
	     (vty, ifp));

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

#define IS_ZEBRA_IF_BOND(ifp)                                                  \
	(((struct zebra_if *)(ifp->info))->zif_type == ZEBRA_IF_BOND)

#define IS_ZEBRA_IF_GRE(ifp)                                               \
	(((struct zebra_if *)(ifp->info))->zif_type == ZEBRA_IF_GRE)

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
extern struct interface *if_lookup_by_index_per_nsid(ns_id_t nsid,
						     uint32_t ifindex);
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
extern void if_delete_update(struct interface **ifp);
extern void if_add_update(struct interface *ifp);
extern void if_up(struct interface *ifp, bool install_connected);
extern void if_down(struct interface *);
extern void if_refresh(struct interface *);
extern void if_flags_update(struct interface *, uint64_t);
extern int if_subnet_add(struct interface *, struct connected *);
extern int if_subnet_delete(struct interface *, struct connected *);
extern void if_handle_vrf_change(struct interface *ifp, vrf_id_t vrf_id);
extern void zebra_if_update_link(struct interface *ifp, ifindex_t link_ifindex,
				 ns_id_t ns_id);
extern void zebra_if_update_all_links(struct zebra_ns *zns);
/**
 * Directly update entire protodown & reason code bitfield.
 */
extern int zebra_if_update_protodown_rc(struct interface *ifp, bool new_down,
					uint32_t new_protodown_rc);

extern void cli_show_legacy_admin_group(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults);
extern void cli_show_affinity_mode(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults);
extern void cli_show_affinity(struct vty *vty, const struct lyd_node *dnode,
			      bool show_defaults);

/**
 * Set protodown with single reason.
 */
extern int zebra_if_set_protodown(struct interface *ifp, bool down,
				  enum protodown_reasons new_reason);
extern void if_ip_address_install(struct interface *ifp, struct prefix *prefix,
				  const char *label, struct prefix *pp);
extern void if_ip_address_uninstall(struct interface *ifp,
				    struct prefix *prefix, struct prefix *pp);
extern void if_ipv6_address_install(struct interface *ifp,
				    struct prefix *prefix);
extern void if_ipv6_address_uninstall(struct interface *ifp,
				      struct prefix *prefix);
extern int if_shutdown(struct interface *ifp);
extern int if_no_shutdown(struct interface *ifp);
extern void if_arp(struct interface *ifp, bool enable);
extern int if_multicast_set(struct interface *ifp);
extern int if_multicast_unset(struct interface *ifp);
extern int if_linkdetect(struct interface *ifp, bool detect);
extern void if_addr_wakeup(struct interface *ifp);

void link_param_cmd_set_uint32(struct interface *ifp, uint32_t *field,
			       uint32_t type, uint32_t value);
void link_param_cmd_set_float(struct interface *ifp, float *field,
			      uint32_t type, float value);
void link_param_cmd_unset(struct interface *ifp, uint32_t type);

/* Nexthop group connected functions */
extern bool if_nhg_dependents_is_empty(const struct interface *ifp);

extern void vrf_add_update(struct vrf *vrfp);
extern void zebra_l2_map_slave_to_bond(struct zebra_if *zif, vrf_id_t vrf);
extern void zebra_l2_unmap_slave_from_bond(struct zebra_if *zif);
extern const char *zebra_protodown_rc_str(uint32_t protodown_rc, char *pd_buf,
					  uint32_t pd_buf_len);
void zebra_if_dplane_result(struct zebra_dplane_ctx *ctx);

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
