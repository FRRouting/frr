/*
 * RIPng related value and structure.
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#ifndef _ZEBRA_RIPNG_RIPNGD_H
#define _ZEBRA_RIPNG_RIPNGD_H

#include <zclient.h>
#include <vty.h>
#include <distribute.h>
#include <vector.h>
#include <memory.h>

/* RIPng version and port number. */
#define RIPNG_V1                         1
#define RIPNG_PORT_DEFAULT             521
#define RIPNG_VTY_PORT                2603
#define RIPNG_MAX_PACKET_SIZE         1500
#define RIPNG_PRIORITY_DEFAULT           0

/* RIPng commands. */
#define RIPNG_REQUEST                    1
#define RIPNG_RESPONSE                   2

/* RIPng metric and multicast group address. */
#define RIPNG_METRIC_INFINITY           16
#define RIPNG_METRIC_NEXTHOP          0xff
#define RIPNG_GROUP              "ff02::9"

/* RIPng peer timeout value. */
#define RIPNG_PEER_TIMER_DEFAULT       180

/* Default config file name. */
#define RIPNG_DEFAULT_CONFIG "ripngd.conf"

/* RIPng route types. */
#define RIPNG_ROUTE_RTE                  0
#define RIPNG_ROUTE_STATIC               1
#define RIPNG_ROUTE_DEFAULT              2
#define RIPNG_ROUTE_REDISTRIBUTE         3
#define RIPNG_ROUTE_INTERFACE            4
#define RIPNG_ROUTE_AGGREGATE            5

/* Interface send/receive configuration. */
#define RIPNG_SEND_UNSPEC                0
#define RIPNG_SEND_OFF                   1
#define RIPNG_RECEIVE_UNSPEC             0
#define RIPNG_RECEIVE_OFF                1

/* RIP default route's accept/announce methods. */
#define RIPNG_DEFAULT_ADVERTISE_UNSPEC   0
#define RIPNG_DEFAULT_ADVERTISE_NONE     1
#define RIPNG_DEFAULT_ADVERTISE          2

#define RIPNG_DEFAULT_ACCEPT_UNSPEC      0
#define RIPNG_DEFAULT_ACCEPT_NONE        1
#define RIPNG_DEFAULT_ACCEPT             2

/* For max RTE calculation. */
#ifndef IPV6_HDRLEN
#define IPV6_HDRLEN 40
#endif /* IPV6_HDRLEN */

#ifndef IFMINMTU
#define IFMINMTU    576
#endif /* IFMINMTU */

/* YANG paths */
#define RIPNG_INSTANCE	"/frr-ripngd:ripngd/instance"
#define RIPNG_IFACE	"/frr-interface:lib/interface/frr-ripngd:ripng"

DECLARE_MGROUP(RIPNGD)

/* RIPng structure. */
struct ripng {
	RB_ENTRY(ripng) entry;

	/* VRF this routing instance is associated with. */
	char *vrf_name;

	/* VRF backpointer (might be NULL if the VRF doesn't exist). */
	struct vrf *vrf;

	/* Status of the routing instance. */
	bool enabled;

	/* RIPng socket. */
	int sock;

	/* RIPng Parameters.*/
	uint8_t command;
	uint8_t version;
	uint16_t update_time;
	uint16_t timeout_time;
	uint16_t garbage_time;
	int max_mtu;
	uint8_t default_metric;

	/* Input/output buffer of RIPng. */
	struct stream *ibuf;
	struct stream *obuf;

	/* RIPng routing information base. */
	struct agg_table *table;

	/* Linked list of RIPng peers. */
	struct list *peer_list;

	/* RIPng enabled interfaces. */
	vector enable_if;

	/* RIPng enabled networks. */
	struct agg_table *enable_network;

	/* Vector to store passive-interface name. */
	vector passive_interface;

	/* RIPng offset-lists. */
	struct list *offset_list_master;

	/* RIPng threads. */
	struct thread *t_read;
	struct thread *t_write;
	struct thread *t_update;
	struct thread *t_garbage;
	struct thread *t_zebra;

	/* Triggered update hack. */
	int trigger;
	struct thread *t_triggered_update;
	struct thread *t_triggered_interval;

	/* RIPng ECMP flag */
	bool ecmp;

	/* RIPng redistribute configuration. */
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
};
RB_HEAD(ripng_instance_head, ripng);
RB_PROTOTYPE(ripng_instance_head, ripng, entry, ripng_instance_compare)

/* Routing table entry. */
struct rte {
	struct in6_addr addr; /* RIPng destination prefix */
	uint16_t tag;	 /* RIPng tag */
	uint8_t prefixlen;    /* Length of the RIPng prefix */
	uint8_t metric;       /* Metric of the RIPng route */
			      /* The nexthop is stored by the structure
			       * ripng_nexthop within ripngd.c */
};

/* RIPNG send packet. */
struct ripng_packet {
	uint8_t command;
	uint8_t version;
	uint16_t zero;
	struct rte rte[1];
};

/* Each route's information. */
struct ripng_info {
	/* This route's type.  Static, ripng or aggregate. */
	uint8_t type;

	/* Sub type for static route. */
	uint8_t sub_type;

	/* RIPng specific information */
	struct in6_addr nexthop;
	struct in6_addr from;

	/* Which interface does this route come from. */
	ifindex_t ifindex;

	/* Metric of this route.  */
	uint8_t metric;

	/* Tag field of RIPng packet.*/
	uint16_t tag;

	/* For aggregation. */
	unsigned int suppress;

/* Flags of RIPng route. */
#define RIPNG_RTF_FIB      1
#define RIPNG_RTF_CHANGED  2
	uint8_t flags;

	/* Garbage collect timer. */
	struct thread *t_timeout;
	struct thread *t_garbage_collect;

	/* Route-map features - this variables can be changed. */
	struct in6_addr nexthop_out;
	uint8_t metric_set;
	uint8_t metric_out;
	uint16_t tag_out;

	struct agg_node *rp;
};

#ifdef notyet
#if 0
/* RIPng tag structure. */
struct ripng_tag
{
  /* Tag value. */
  uint16_t tag;

  /* Port. */
  uint16_t port;

  /* Multicast group. */
  struct in6_addr maddr;

  /* Table number. */
  int table;

  /* Distance. */
  int distance;

  /* Split horizon. */
  uint8_t split_horizon;

  /* Poison reverse. */
  uint8_t poison_reverse;
};
#endif /* 0 */
#endif /* not yet */

typedef enum {
	RIPNG_NO_SPLIT_HORIZON = 0,
	RIPNG_SPLIT_HORIZON,
	RIPNG_SPLIT_HORIZON_POISONED_REVERSE
} split_horizon_policy_t;

/* RIPng specific interface configuration. */
struct ripng_interface {
	/* Parent routing instance. */
	struct ripng *ripng;

	/* RIPng is enabled on this interface. */
	int enable_network;
	int enable_interface;

	/* RIPng is running on this interface. */
	int running;

	/* Split horizon flag. */
	split_horizon_policy_t split_horizon;

/* For filter type slot. */
#define RIPNG_FILTER_IN  0
#define RIPNG_FILTER_OUT 1
#define RIPNG_FILTER_MAX 2

	/* Access-list. */
	struct access_list *list[RIPNG_FILTER_MAX];

	/* Prefix-list. */
	struct prefix_list *prefix[RIPNG_FILTER_MAX];

	/* Route-map. */
	struct route_map *routemap[RIPNG_FILTER_MAX];

#ifdef notyet
#if 0
  /* RIPng tag configuration. */
  struct ripng_tag *rtag;
#endif /* 0 */
#endif /* notyet */

	/* Default information originate. */
	uint8_t default_originate;

	/* Default information only. */
	uint8_t default_only;

	/* Wake up thread. */
	struct thread *t_wakeup;

	/* Passive interface. */
	int passive;
};

/* RIPng peer information. */
struct ripng_peer {
	/* Parent routing instance. */
	struct ripng *ripng;

	/* Peer address. */
	struct in6_addr addr;

	/* Peer RIPng tag value. */
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

/* All RIPng events. */
enum ripng_event {
	RIPNG_READ,
	RIPNG_ZEBRA,
	RIPNG_REQUEST_EVENT,
	RIPNG_UPDATE_EVENT,
	RIPNG_TRIGGERED_UPDATE,
};

/* RIPng timer on/off macro. */
#define RIPNG_TIMER_ON(T,F,V) thread_add_timer (master, (F), rinfo, (V), &(T))

#define RIPNG_TIMER_OFF(T)                                                     \
	do {                                                                   \
		if (T) {                                                       \
			thread_cancel(T);                                      \
			(T) = NULL;                                            \
		}                                                              \
	} while (0)

#define RIPNG_OFFSET_LIST_IN  0
#define RIPNG_OFFSET_LIST_OUT 1
#define RIPNG_OFFSET_LIST_MAX 2

struct ripng_offset_list {
	/* Parent routing instance. */
	struct ripng *ripng;

	char *ifname;

	struct {
		char *alist_name;
		/* struct access_list *alist; */
		uint8_t metric;
	} direct[RIPNG_OFFSET_LIST_MAX];
};

/* Extern variables. */
extern struct zebra_privs_t ripngd_privs;
extern struct thread_master *master;
extern struct ripng_instance_head ripng_instances;

/* Prototypes. */
extern void ripng_init(void);
extern void ripng_clean(struct ripng *ripng);
extern void ripng_clean_network(struct ripng *ripng);
extern void ripng_interface_clean(struct ripng *ripng);
extern int ripng_enable_network_add(struct ripng *ripng, struct prefix *p);
extern int ripng_enable_network_delete(struct ripng *ripng, struct prefix *p);
extern int ripng_enable_if_add(struct ripng *ripng, const char *ifname);
extern int ripng_enable_if_delete(struct ripng *ripng, const char *ifname);
extern int ripng_passive_interface_set(struct ripng *ripng, const char *ifname);
extern int ripng_passive_interface_unset(struct ripng *ripng,
					 const char *ifname);
extern void ripng_passive_interface_clean(struct ripng *ripng);
extern void ripng_if_init(void);
extern void ripng_route_map_init(void);
extern void ripng_zebra_vrf_register(struct vrf *vrf);
extern void ripng_zebra_vrf_deregister(struct vrf *vrf);
extern void ripng_terminate(void);
/* zclient_init() is done by ripng_zebra.c:zebra_init() */
extern void zebra_init(struct thread_master *);
extern void ripng_zebra_stop(void);
extern void ripng_redistribute_conf_update(struct ripng *ripng, int type);
extern void ripng_redistribute_conf_delete(struct ripng *ripng, int type);

extern void ripng_peer_update(struct ripng *ripng, struct sockaddr_in6 *from,
			      uint8_t version);
extern void ripng_peer_bad_route(struct ripng *ripng,
				 struct sockaddr_in6 *from);
extern void ripng_peer_bad_packet(struct ripng *ripng,
				  struct sockaddr_in6 *from);
extern void ripng_peer_display(struct vty *vty, struct ripng *ripng);
extern struct ripng_peer *ripng_peer_lookup(struct ripng *ripng,
					    struct in6_addr *addr);
extern struct ripng_peer *ripng_peer_lookup_next(struct ripng *ripng,
						 struct in6_addr *addr);
extern int ripng_peer_list_cmp(struct ripng_peer *p1, struct ripng_peer *p2);
extern void ripng_peer_list_del(void *arg);

extern struct ripng_offset_list *ripng_offset_list_new(struct ripng *ripng,
						       const char *ifname);
extern void ripng_offset_list_del(struct ripng_offset_list *offset);
extern void ripng_offset_list_free(struct ripng_offset_list *offset);
extern struct ripng_offset_list *ripng_offset_list_lookup(struct ripng *ripng,
							  const char *ifname);
extern int ripng_offset_list_apply_in(struct ripng *ripng,
				      struct prefix_ipv6 *p,
				      struct interface *ifp, uint8_t *metric);
extern int ripng_offset_list_apply_out(struct ripng *ripng,
				       struct prefix_ipv6 *p,
				       struct interface *ifp, uint8_t *metric);
extern int offset_list_cmp(struct ripng_offset_list *o1,
			   struct ripng_offset_list *o2);

extern int ripng_route_rte(struct ripng_info *rinfo);
extern struct ripng_info *ripng_info_new(void);
extern void ripng_info_free(struct ripng_info *rinfo);
extern struct ripng *ripng_info_get_instance(const struct ripng_info *rinfo);
extern void ripng_event(struct ripng *ripng, enum ripng_event event, int sock);
extern int ripng_request(struct interface *ifp);
extern void ripng_redistribute_add(struct ripng *ripng, int type, int sub_type,
				   struct prefix_ipv6 *p, ifindex_t ifindex,
				   struct in6_addr *nexthop, route_tag_t tag);
extern void ripng_redistribute_delete(struct ripng *ripng, int type,
				      int sub_type, struct prefix_ipv6 *p,
				      ifindex_t ifindex);
extern void ripng_redistribute_withdraw(struct ripng *ripng, int type);

extern void ripng_ecmp_disable(struct ripng *ripng);
extern void ripng_distribute_update_interface(struct interface *);
extern void ripng_if_rmap_update_interface(struct interface *);

extern void ripng_zebra_ipv6_add(struct ripng *ripng, struct agg_node *node);
extern void ripng_zebra_ipv6_delete(struct ripng *ripng, struct agg_node *node);

extern void ripng_redistribute_enable(struct ripng *ripng);
extern void ripng_redistribute_disable(struct ripng *ripng);
extern int ripng_redistribute_check(struct ripng *ripng, int type);
extern void ripng_redistribute_write(struct vty *vty, struct ripng *ripng);

extern int ripng_write_rte(int num, struct stream *s, struct prefix_ipv6 *p,
			   struct in6_addr *nexthop, uint16_t tag,
			   uint8_t metric);
extern int ripng_send_packet(caddr_t buf, int bufsize, struct sockaddr_in6 *to,
			     struct interface *ifp);

extern void ripng_packet_dump(struct ripng_packet *packet, int size,
			      const char *sndrcv);

extern int ripng_interface_up(ZAPI_CALLBACK_ARGS);
extern int ripng_interface_down(ZAPI_CALLBACK_ARGS);
extern int ripng_interface_add(ZAPI_CALLBACK_ARGS);
extern int ripng_interface_delete(ZAPI_CALLBACK_ARGS);
extern int ripng_interface_address_add(ZAPI_CALLBACK_ARGS);
extern int ripng_interface_address_delete(ZAPI_CALLBACK_ARGS);
extern int ripng_interface_vrf_update(ZAPI_CALLBACK_ARGS);
extern void ripng_interface_sync(struct interface *ifp);

extern struct ripng *ripng_lookup_by_vrf_id(vrf_id_t vrf_id);
extern struct ripng *ripng_lookup_by_vrf_name(const char *vrf_name);
extern struct ripng *ripng_create(const char *vrf_name, struct vrf *vrf,
				  int socket);
extern int ripng_make_socket(struct vrf *vrf);
extern int ripng_network_write(struct vty *vty, struct ripng *ripng);

extern struct ripng_info *ripng_ecmp_add(struct ripng *ripng,
					 struct ripng_info *rinfo);
extern struct ripng_info *ripng_ecmp_replace(struct ripng *ripng,
					     struct ripng_info *rinfo);
extern struct ripng_info *ripng_ecmp_delete(struct ripng *ripng,
					    struct ripng_info *rinfo);

extern void ripng_vrf_init(void);
extern void ripng_vrf_terminate(void);
extern void ripng_cli_init(void);

#endif /* _ZEBRA_RIPNG_RIPNGD_H */
