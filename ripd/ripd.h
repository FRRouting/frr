/* RIP related values and structures.
 * Copyright (C) 1997, 1998, 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
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

#ifndef _ZEBRA_RIP_H
#define _ZEBRA_RIP_H

#include "hook.h"
#include "nexthop.h"
#include "distribute.h"
#include "memory.h"

/* RIP version number. */
#define RIPv1                            1
#define RIPv2                            2
/* N.B. stuff will break if
	(RIPv1 != RI_RIP_VERSION_1) || (RIPv2 != RI_RIP_VERSION_2) */


/* RIP command list. */
#define RIP_REQUEST                      1
#define RIP_RESPONSE                     2
#define RIP_TRACEON                      3	/* Obsolete */
#define RIP_TRACEOFF                     4	/* Obsolete */
#define RIP_POLL                         5
#define RIP_POLL_ENTRY                   6
#define RIP_COMMAND_MAX                  7

/* RIP metric infinity value.*/
#define RIP_METRIC_INFINITY             16

/* Normal RIP packet min and max size. */
#define RIP_PACKET_MINSIZ                4
#define RIP_PACKET_MAXSIZ              512

#define RIP_HEADER_SIZE                  4
#define RIP_RTE_SIZE                    20

/* Max count of routing table entry in one rip packet. */
#define RIP_MAX_RTE   ((RIP_PACKET_MAXSIZ - RIP_HEADER_SIZE) / RIP_RTE_SIZE)

/* RIP version 2 multicast address. */
#ifndef INADDR_RIP_GROUP
#define INADDR_RIP_GROUP        0xe0000009    /* 224.0.0.9 */
#endif

/* RIP peer timeout value. */
#define RIP_PEER_TIMER_DEFAULT         180

/* RIP port number. */
#define RIP_PORT_DEFAULT               520
#define RIP_VTY_PORT                  2602

/* Default configuration file name. */
#define RIPD_DEFAULT_CONFIG    "ripd.conf"

/* RIP route types. */
#define RIP_ROUTE_RTE                    0
#define RIP_ROUTE_STATIC                 1
#define RIP_ROUTE_DEFAULT                2
#define RIP_ROUTE_REDISTRIBUTE           3
#define RIP_ROUTE_INTERFACE              4

/* RIPv2 special RTE family types */
#define RIP_FAMILY_AUTH                  0xffff

/* RIPv2 authentication types, for RIP_FAMILY_AUTH RTE's */
#define RIP_NO_AUTH                0
#define RIP_AUTH_DATA              1
#define RIP_AUTH_SIMPLE_PASSWORD   2
#define RIP_AUTH_MD5               3

/* RIPv2 Simple authentication */
#define RIP_AUTH_SIMPLE_SIZE		16

/* RIPv2 MD5 authentication. */
#define RIP_AUTH_MD5_SIZE               16
#define RIP_AUTH_MD5_COMPAT_SIZE        RIP_RTE_SIZE

/* YANG paths */
#define RIP_INSTANCE	"/frr-ripd:ripd/instance"
#define RIP_IFACE	"/frr-interface:lib/interface/frr-ripd:rip"

DECLARE_MGROUP(RIPD)

/* RIP structure. */
struct rip {
	RB_ENTRY(rip) entry;

	/* VRF this routing instance is associated with. */
	char *vrf_name;

	/* VRF backpointer (might be NULL if the VRF doesn't exist). */
	struct vrf *vrf;

	/* Status of the routing instance. */
	bool enabled;

	/* RIP socket. */
	int sock;

	/* Default version of rip instance. */
	int version_send; /* version 1 or 2 (but not both) */
	int version_recv; /* version 1 or 2 or both */

	/* Output buffer of RIP. */
	struct stream *obuf;

	/* RIP routing information base. */
	struct route_table *table;

	/* RIP static neighbors. */
	struct route_table *neighbor;

	/* Linked list of RIP peers. */
	struct list *peer_list;

	/* RIP threads. */
	struct thread *t_read;

	/* Update and garbage timer. */
	struct thread *t_update;

	/* Triggered update hack. */
	int trigger;
	struct thread *t_triggered_update;
	struct thread *t_triggered_interval;

	/* RIP timer values. */
	uint32_t update_time;
	uint32_t timeout_time;
	uint32_t garbage_time;

	/* RIP default metric. */
	uint8_t default_metric;

	/* RIP default distance. */
	uint8_t distance;
	struct route_table *distance_table;

	/* RIP ECMP flag */
	bool ecmp;

	/* Are we in passive-interface default mode? */
	bool passive_default;

	/* RIP enabled interfaces. */
	vector enable_interface;

	/* RIP enabled networks. */
	struct route_table *enable_network;

	/* Vector to store passive-interface name. */
	vector passive_nondefault;

	/* RIP offset-lists. */
	struct list *offset_list_master;

	/* RIP redistribute configuration. */
	struct {
		bool enabled;
		struct {
			char *name;
			struct route_map *map;
		} route_map;
		bool metric_config;
		uint8_t metric;
	} redist[ZEBRA_ROUTE_MAX];

	/* For distribute-list container */
	struct distribute_ctx *distribute_ctx;

	/* For if_rmap container */
	struct if_rmap_ctx *if_rmap_ctx;

	/* Counters for SNMP. */
	struct {
		/* RIP route changes. */
		long route_changes;

		/* RIP queries. */
		long queries;
	} counters;
};
RB_HEAD(rip_instance_head, rip);
RB_PROTOTYPE(rip_instance_head, rip, entry, rip_instance_compare)

/* RIP routing table entry which belong to rip_packet. */
struct rte {
	uint16_t family;	/* Address family of this route. */
	uint16_t tag;		/* Route Tag which included in RIP2 packet. */
	struct in_addr prefix;  /* Prefix of rip route. */
	struct in_addr mask;    /* Netmask of rip route. */
	struct in_addr nexthop; /* Next hop of rip route. */
	uint32_t metric;	/* Metric value of rip route. */
};

/* RIP packet structure. */
struct rip_packet {
	unsigned char command; /* Command type of RIP packet. */
	unsigned char version; /* RIP version which coming from peer. */
	unsigned char pad1;    /* Padding of RIP packet header. */
	unsigned char pad2;    /* Same as above. */
	struct rte rte[1];     /* Address structure. */
};

/* Buffer to read RIP packet. */
union rip_buf {
	struct rip_packet rip_packet;
	char buf[RIP_PACKET_MAXSIZ];
};

/* RIP route information. */
struct rip_info {
	/* This route's type. */
	int type;

	/* Sub type. */
	int sub_type;

	/* RIP nexthop. */
	struct nexthop nh;
	struct in_addr from;

	/* Metric of this route. */
	uint32_t metric;

	/* External metric of this route.
	   if learnt from an externalm proto */
	uint32_t external_metric;

	/* Tag information of this route. */
	uint16_t tag;

/* Flags of RIP route. */
#define RIP_RTF_FIB      1
#define RIP_RTF_CHANGED  2
	uint8_t flags;

	/* Garbage collect timer. */
	struct thread *t_timeout;
	struct thread *t_garbage_collect;

	/* Route-map futures - this variables can be changed. */
	struct in_addr nexthop_out;
	uint8_t metric_set;
	uint32_t metric_out;
	uint16_t tag_out;
	ifindex_t ifindex_out;

	struct route_node *rp;

	uint8_t distance;
};

typedef enum {
	RIP_NO_SPLIT_HORIZON = 0,
	RIP_SPLIT_HORIZON,
	RIP_SPLIT_HORIZON_POISONED_REVERSE
} split_horizon_policy_t;

/* RIP specific interface configuration. */
struct rip_interface {
	/* Parent routing instance. */
	struct rip *rip;

	/* RIP is enabled on this interface. */
	int enable_network;
	int enable_interface;

	/* RIP is running on this interface. */
	int running;

	/* RIP version control. */
	int ri_send;
	int ri_receive;

	/* RIPv2 broadcast mode */
	bool v2_broadcast;

	/* RIPv2 authentication type. */
	int auth_type;

	/* RIPv2 authentication string. */
	char *auth_str;

	/* RIPv2 authentication key chain. */
	char *key_chain;

	/* value to use for md5->auth_len */
	int md5_auth_len;

	/* Split horizon flag. */
	split_horizon_policy_t split_horizon;

/* For filter type slot. */
#define RIP_FILTER_IN  0
#define RIP_FILTER_OUT 1
#define RIP_FILTER_MAX 2

	/* Access-list. */
	struct access_list *list[RIP_FILTER_MAX];

	/* Prefix-list. */
	struct prefix_list *prefix[RIP_FILTER_MAX];

	/* Route-map. */
	struct route_map *routemap[RIP_FILTER_MAX];

	/* Wake up thread. */
	struct thread *t_wakeup;

	/* Interface statistics. */
	int recv_badpackets;
	int recv_badroutes;
	int sent_updates;

	/* Passive interface. */
	int passive;
};

/* RIP peer information. */
struct rip_peer {
	/* Parent routing instance. */
	struct rip *rip;

	/* Peer address. */
	struct in_addr addr;

	/* Peer RIP tag value. */
	int domain;

	/* Last update time. */
	time_t uptime;

	/* Peer RIP version. */
	uint8_t version;

	/* Statistics. */
	int recv_badpackets;
	int recv_badroutes;

	/* Timeout thread. */
	struct thread *t_timeout;
};

struct rip_distance {
	/* Distance value for the IP source prefix. */
	uint8_t distance;

	/* Name of the access-list to be matched. */
	char *access_list;
};

struct rip_md5_info {
	uint16_t family;
	uint16_t type;
	uint16_t packet_len;
	uint8_t keyid;
	uint8_t auth_len;
	uint32_t sequence;
	uint32_t reserv1;
	uint32_t reserv2;
};

struct rip_md5_data {
	uint16_t family;
	uint16_t type;
	uint8_t digest[16];
};

/* RIP accepet/announce methods. */
#define RI_RIP_UNSPEC                      0
#define RI_RIP_VERSION_1                   1
#define RI_RIP_VERSION_2                   2
#define RI_RIP_VERSION_1_AND_2             3
#define RI_RIP_VERSION_NONE                4
/* N.B. stuff will break if
	(RIPv1 != RI_RIP_VERSION_1) || (RIPv2 != RI_RIP_VERSION_2) */

/* RIP event. */
enum rip_event {
	RIP_READ,
	RIP_UPDATE_EVENT,
	RIP_TRIGGERED_UPDATE,
};

/* Macro for timer turn on. */
#define RIP_TIMER_ON(T,F,V) thread_add_timer (master, (F), rinfo, (V), &(T))

/* Macro for timer turn off. */
#define RIP_TIMER_OFF(X) THREAD_TIMER_OFF(X)

#define RIP_OFFSET_LIST_IN  0
#define RIP_OFFSET_LIST_OUT 1
#define RIP_OFFSET_LIST_MAX 2

struct rip_offset_list {
	/* Parent routing instance. */
	struct rip *rip;

	char *ifname;

	struct {
		char *alist_name;
		/* struct access_list *alist; */
		uint8_t metric;
	} direct[RIP_OFFSET_LIST_MAX];
};

/* Prototypes. */
extern void rip_init(void);
extern void rip_clean(struct rip *rip);
extern void rip_clean_network(struct rip *rip);
extern void rip_interfaces_clean(struct rip *rip);
extern int rip_passive_nondefault_set(struct rip *rip, const char *ifname);
extern int rip_passive_nondefault_unset(struct rip *rip, const char *ifname);
extern void rip_passive_nondefault_clean(struct rip *rip);
extern void rip_if_init(void);
extern void rip_route_map_init(void);
extern void rip_zebra_vrf_register(struct vrf *vrf);
extern void rip_zebra_vrf_deregister(struct vrf *vrf);
extern void rip_zclient_init(struct thread_master *);
extern void rip_zclient_stop(void);
extern int if_check_address(struct rip *rip, struct in_addr addr);
extern struct rip *rip_lookup_by_vrf_id(vrf_id_t vrf_id);
extern struct rip *rip_lookup_by_vrf_name(const char *vrf_name);
extern struct rip *rip_create(const char *vrf_name, struct vrf *vrf,
			      int socket);

extern int rip_request_send(struct sockaddr_in *, struct interface *, uint8_t,
			    struct connected *);
extern int rip_neighbor_lookup(struct rip *rip, struct sockaddr_in *from);
extern int rip_neighbor_add(struct rip *rip, struct prefix_ipv4 *p);
extern int rip_neighbor_delete(struct rip *rip, struct prefix_ipv4 *p);

extern int rip_enable_network_add(struct rip *rip, struct prefix *p);
extern int rip_enable_network_delete(struct rip *rip, struct prefix *p);
extern int rip_enable_if_add(struct rip *rip, const char *ifname);
extern int rip_enable_if_delete(struct rip *rip, const char *ifname);

extern void rip_event(struct rip *rip, enum rip_event event, int sock);
extern void rip_ecmp_disable(struct rip *rip);

extern int rip_create_socket(struct vrf *vrf);

extern int rip_redistribute_check(struct rip *rip, int type);
extern void rip_redistribute_conf_update(struct rip *rip, int type);
extern void rip_redistribute_conf_delete(struct rip *rip, int type);
extern void rip_redistribute_add(struct rip *rip, int type, int sub_type,
				 struct prefix_ipv4 *p, struct nexthop *nh,
				 unsigned int metric, unsigned char distance,
				 route_tag_t tag);
extern void rip_redistribute_delete(struct rip *rip, int type, int sub_type,
				    struct prefix_ipv4 *p, ifindex_t ifindex);
extern void rip_redistribute_withdraw(struct rip *rip, int type);
extern void rip_zebra_ipv4_add(struct rip *rip, struct route_node *rp);
extern void rip_zebra_ipv4_delete(struct rip *rip, struct route_node *rp);
extern void rip_interface_multicast_set(int, struct connected *);
extern void rip_distribute_update_interface(struct interface *);
extern void rip_if_rmap_update_interface(struct interface *ifp);

extern int rip_show_network_config(struct vty *vty, struct rip *rip);
extern void rip_show_redistribute_config(struct vty *vty, struct rip *rip);

extern void rip_peer_update(struct rip *rip, struct sockaddr_in *from,
			    uint8_t version);
extern void rip_peer_bad_route(struct rip *rip, struct sockaddr_in *from);
extern void rip_peer_bad_packet(struct rip *rip, struct sockaddr_in *from);
extern void rip_peer_display(struct vty *vty, struct rip *rip);
extern struct rip_peer *rip_peer_lookup(struct rip *rip, struct in_addr *addr);
extern struct rip_peer *rip_peer_lookup_next(struct rip *rip,
					     struct in_addr *addr);
extern int rip_peer_list_cmp(struct rip_peer *p1, struct rip_peer *p2);
extern void rip_peer_list_del(void *arg);

extern void rip_info_free(struct rip_info *);
extern struct rip *rip_info_get_instance(const struct rip_info *rinfo);
extern struct rip_distance *rip_distance_new(void);
extern void rip_distance_free(struct rip_distance *rdistance);
extern uint8_t rip_distance_apply(struct rip *rip, struct rip_info *rinfo);
extern void rip_redistribute_enable(struct rip *rip);
extern void rip_redistribute_disable(struct rip *rip);

extern int rip_route_rte(struct rip_info *rinfo);
extern struct rip_info *rip_ecmp_add(struct rip *rip,
				     struct rip_info *rinfo_new);
extern struct rip_info *rip_ecmp_replace(struct rip *rip,
					 struct rip_info *rinfo_new);
extern struct rip_info *rip_ecmp_delete(struct rip *rip,
					struct rip_info *rinfo);

extern struct rip_offset_list *rip_offset_list_new(struct rip *rip,
						   const char *ifname);
extern void offset_list_del(struct rip_offset_list *offset);
extern void offset_list_free(struct rip_offset_list *offset);
extern struct rip_offset_list *rip_offset_list_lookup(struct rip *rip,
						      const char *ifname);
extern int rip_offset_list_apply_in(struct prefix_ipv4 *, struct interface *,
				    uint32_t *);
extern int rip_offset_list_apply_out(struct prefix_ipv4 *, struct interface *,
				     uint32_t *);
extern int offset_list_cmp(struct rip_offset_list *o1,
			   struct rip_offset_list *o2);

extern void rip_vrf_init(void);
extern void rip_vrf_terminate(void);
extern void rip_cli_init(void);

extern struct zebra_privs_t ripd_privs;
extern struct rip_instance_head rip_instances;

/* Master thread strucutre. */
extern struct thread_master *master;

DECLARE_HOOK(rip_ifaddr_add, (struct connected * ifc), (ifc))
DECLARE_HOOK(rip_ifaddr_del, (struct connected * ifc), (ifc))

#endif /* _ZEBRA_RIP_H */
