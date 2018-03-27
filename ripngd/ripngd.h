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

#include "ripng_memory.h"

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

/* RIPng timers. */
#define RIPNG_UPDATE_TIMER_DEFAULT      30
#define RIPNG_TIMEOUT_TIMER_DEFAULT    180
#define RIPNG_GARBAGE_TIMER_DEFAULT    120

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

/* Default value for "default-metric" command. */
#define RIPNG_DEFAULT_METRIC_DEFAULT     1

/* For max RTE calculation. */
#ifndef IPV6_HDRLEN
#define IPV6_HDRLEN 40
#endif /* IPV6_HDRLEN */

#ifndef IFMINMTU
#define IFMINMTU    576
#endif /* IFMINMTU */

/* RIPng structure. */
struct ripng {
	/* RIPng socket. */
	int sock;

	/* RIPng Parameters.*/
	uint8_t command;
	uint8_t version;
	unsigned long update_time;
	unsigned long timeout_time;
	unsigned long garbage_time;
	int max_mtu;
	int default_metric;
	int default_information;

	/* Input/output buffer of RIPng. */
	struct stream *ibuf;
	struct stream *obuf;

	/* RIPng routing information base. */
	struct route_table *table;

	/* RIPng only static route information. */
	struct route_table *route;

	/* RIPng aggregate route information. */
	struct route_table *aggregate;

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
	unsigned int ecmp;

	/* For redistribute route map. */
	struct {
		char *name;
		struct route_map *map;
		int metric_config;
		uint32_t metric;
	} route_map[ZEBRA_ROUTE_MAX];
};

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

	struct route_node *rp;
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
	/* RIPng is enabled on this interface. */
	int enable_network;
	int enable_interface;

	/* RIPng is running on this interface. */
	int running;

	/* Split horizon flag. */
	split_horizon_policy_t split_horizon;
	split_horizon_policy_t split_horizon_default;

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

/* Extern variables. */
extern struct ripng *ripng;
extern struct zebra_privs_t ripngd_privs;
extern struct thread_master *master;

/* Prototypes. */
extern void ripng_init(void);
extern void ripng_reset(void);
extern void ripng_clean(void);
extern void ripng_clean_network(void);
extern void ripng_interface_clean(void);
extern void ripng_interface_reset(void);
extern void ripng_passive_interface_clean(void);
extern void ripng_if_init(void);
extern void ripng_route_map_init(void);
extern void ripng_route_map_reset(void);
extern void ripng_terminate(void);
/* zclient_init() is done by ripng_zebra.c:zebra_init() */
extern void zebra_init(struct thread_master *);
extern void ripng_zebra_stop(void);
extern void ripng_zclient_reset(void);
extern void ripng_offset_init(void);

extern int config_write_ripng_offset_list(struct vty *);

extern void ripng_peer_init(void);
extern void ripng_peer_update(struct sockaddr_in6 *, uint8_t);
extern void ripng_peer_bad_route(struct sockaddr_in6 *);
extern void ripng_peer_bad_packet(struct sockaddr_in6 *);
extern void ripng_peer_display(struct vty *);
extern struct ripng_peer *ripng_peer_lookup(struct in6_addr *);
extern struct ripng_peer *ripng_peer_lookup_next(struct in6_addr *);

extern int ripng_offset_list_apply_in(struct prefix_ipv6 *, struct interface *,
				      uint8_t *);
extern int ripng_offset_list_apply_out(struct prefix_ipv6 *, struct interface *,
				       uint8_t *);
extern void ripng_offset_clean(void);

extern struct ripng_info *ripng_info_new(void);
extern void ripng_info_free(struct ripng_info *rinfo);
extern void ripng_event(enum ripng_event, int);
extern int ripng_request(struct interface *ifp);
extern void ripng_redistribute_add(int, int, struct prefix_ipv6 *, ifindex_t,
				   struct in6_addr *, route_tag_t);
extern void ripng_redistribute_delete(int, int, struct prefix_ipv6 *,
				      ifindex_t);
extern void ripng_redistribute_withdraw(int type);

extern void ripng_distribute_update_interface(struct interface *);
extern void ripng_if_rmap_update_interface(struct interface *);

extern void ripng_zebra_ipv6_add(struct route_node *);
extern void ripng_zebra_ipv6_delete(struct route_node *);

extern void ripng_redistribute_clean(void);
extern int ripng_redistribute_check(int);
extern void ripng_redistribute_write(struct vty *, int);

extern int ripng_write_rte(int num, struct stream *s, struct prefix_ipv6 *p,
			   struct in6_addr *nexthop, uint16_t tag,
			   uint8_t metric);
extern int ripng_send_packet(caddr_t buf, int bufsize, struct sockaddr_in6 *to,
			     struct interface *ifp);

extern void ripng_packet_dump(struct ripng_packet *packet, int size,
			      const char *sndrcv);

extern int ripng_interface_up(int command, struct zclient *, zebra_size_t,
			      vrf_id_t);
extern int ripng_interface_down(int command, struct zclient *, zebra_size_t,
				vrf_id_t);
extern int ripng_interface_add(int command, struct zclient *, zebra_size_t,
			       vrf_id_t);
extern int ripng_interface_delete(int command, struct zclient *, zebra_size_t,
				  vrf_id_t);
extern int ripng_interface_address_add(int command, struct zclient *,
				       zebra_size_t, vrf_id_t);
extern int ripng_interface_address_delete(int command, struct zclient *,
					  zebra_size_t, vrf_id_t);

extern int ripng_network_write(struct vty *, int);

extern struct ripng_info *ripng_ecmp_add(struct ripng_info *);
extern struct ripng_info *ripng_ecmp_replace(struct ripng_info *);
extern struct ripng_info *ripng_ecmp_delete(struct ripng_info *);

#endif /* _ZEBRA_RIPNG_RIPNGD_H */
