/*
 * EIGRP Definition of Data Structures.
 * Copyright (C) 2013-2016
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
 *   Frantisek Gazo
 *   Tomas Hvorkovy
 *   Martin Kontsek
 *   Lukas Koribsky
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

#ifndef _ZEBRA_EIGRP_STRUCTS_H_
#define _ZEBRA_EIGRP_STRUCTS_H_

#include "filter.h"

#include "eigrpd/eigrp_const.h"
#include "eigrpd/eigrp_macros.h"

/* EIGRP master for system wide configuration and variables. */
struct eigrp_master {
	/* EIGRP instance. */
	struct list *eigrp;

	/* EIGRP thread master. */
	struct thread_master *master;

	/* Zebra interface list. */
	struct list *iflist;

	/* EIGRP start time. */
	time_t start_time;

	/* Various EIGRP global configuration. */
	unsigned char options;

#define EIGRP_MASTER_SHUTDOWN (1 << 0) /* deferred-shutdown */
};

struct eigrp_metrics {
	uint32_t delay;
	uint32_t bandwidth;
	unsigned char mtu[3];
	unsigned char hop_count;
	unsigned char reliability;
	unsigned char load;
	unsigned char tag;
	unsigned char flags;
};

struct eigrp {
	uint16_t AS;		   /* Autonomous system number */
	uint16_t vrid;		   /* Virtual Router ID */
	unsigned char k_values[6]; /*Array for K values configuration*/
	unsigned char variance;    /*Metric variance multiplier*/
	unsigned char max_paths;   /*Maximum allowed paths for 1 prefix*/

	/*Name of this EIGRP instance*/
	char *name;

	/* EIGRP Router ID. */
	uint32_t router_id;	/* Configured automatically. */
	uint32_t router_id_static; /* Configured manually. */

	struct list *eiflist;		  /* eigrp interfaces */
	unsigned char passive_interface_default; /* passive-interface default */

	unsigned int fd;
	unsigned int maxsndbuflen;

	uint32_t sequence_number; /*Global EIGRP sequence number*/

	struct stream *ibuf;
	struct list *oi_write_q;

	/*Threads*/
	struct thread *t_write;
	struct thread *t_read;
	struct thread *t_distribute; /* timer for distribute list */

	struct route_table *networks; /* EIGRP config networks. */

	struct list *topology_table;

	uint64_t serno; /* Global serial number counter for topology entry
			   changes*/
	uint64_t
		serno_last_update; /* Highest serial number of information send
				      by last update*/
	struct list *topology_changes_internalIPV4;
	struct list *topology_changes_externalIPV4;

	/*Neighbor self*/
	struct eigrp_neighbor *neighbor_self;

	/*Configured metric for redistributed routes*/
	struct eigrp_metrics dmetric[ZEBRA_ROUTE_MAX + 1];
	int redistribute; /* Num of redistributed protocols. */

	/* Access-list. */
	struct access_list *list[EIGRP_FILTER_MAX];
	/* Prefix-list. */
	struct prefix_list *prefix[EIGRP_FILTER_MAX];
	/* Route-map. */
	struct route_map *routemap[EIGRP_FILTER_MAX];

	/* For redistribute route map. */
	struct {
		char *name;
		struct route_map *map;
		int metric_config;
		uint32_t metric;
	} route_map[ZEBRA_ROUTE_MAX];

	QOBJ_FIELDS
};
DECLARE_QOBJ_TYPE(eigrp)
//------------------------------------------------------------------------------------------------------------------------------------------

/*EIGRP interface structure*/
struct eigrp_interface {
	/* This interface's parent eigrp instance. */
	struct eigrp *eigrp;

	/* Interface data from zebra. */
	struct interface *ifp;

	/* Packet send buffer. */
	struct eigrp_fifo *obuf; /* Output queue */

	/* To which multicast groups do we currently belong? */

	/* Configured varables. */
	struct eigrp_if_params *params;

	unsigned char multicast_memberships;

	/* EIGRP Network Type. */
	unsigned char type;

	struct prefix *address;      /* Interface prefix */
	struct connected *connected; /* Pointer to connected */

	/* Neighbor information. */
	struct list *nbrs; /* EIGRP Neighbor List */

	/* Threads. */
	struct thread *t_hello;      /* timer */
	struct thread *t_distribute; /* timer for distribute list */

	int on_write_q;

	/* Statistics fields. */
	uint32_t hello_in;   /* Hello message input count. */
	uint32_t update_in;  /* Update message input count. */
	uint32_t query_in;   /* Querry message input count. */
	uint32_t reply_in;   /* Reply message input count. */
	uint32_t hello_out;  /* Hello message output count. */
	uint32_t update_out; /* Update message output count. */
	uint32_t query_out;  /* Query message output count. */
	uint32_t reply_out;  /* Reply message output count. */
	uint32_t siaQuery_in;
	uint32_t siaQuery_out;
	uint32_t siaReply_in;
	uint32_t siaReply_out;
	uint32_t ack_out;
	uint32_t ack_in;

	uint32_t crypt_seqnum; /* Cryptographic Sequence Number */

	/* Access-list. */
	struct access_list *list[EIGRP_FILTER_MAX];
	/* Prefix-list. */
	struct prefix_list *prefix[EIGRP_FILTER_MAX];
	/* Route-map. */
	struct route_map *routemap[EIGRP_FILTER_MAX];
};

struct eigrp_if_params {
	DECLARE_IF_PARAM(unsigned char,
			 passive_interface);   /* EIGRP Interface is
					   passive: no sending or
					   receiving (no need to
					   join multicast groups)
					   */
	DECLARE_IF_PARAM(uint32_t, v_hello);   /* Hello Interval */
	DECLARE_IF_PARAM(uint16_t, v_wait);    /* Router Hold Time Interval */
	DECLARE_IF_PARAM(unsigned char, type); /* type of interface */
	DECLARE_IF_PARAM(uint32_t, bandwidth);
	DECLARE_IF_PARAM(uint32_t, delay);
	DECLARE_IF_PARAM(unsigned char, reliability);
	DECLARE_IF_PARAM(unsigned char, load);

	DECLARE_IF_PARAM(char *,
			 auth_keychain); /* Associated keychain with interface*/
	DECLARE_IF_PARAM(int, auth_type); /* EIGRP authentication type */
};

enum { MEMBER_ALLROUTERS = 0,
       MEMBER_MAX,
};

struct eigrp_if_info {
	struct eigrp_if_params *def_params;
	struct route_table *params;
	struct route_table *eifs;
	unsigned int
		membership_counts[MEMBER_MAX]; /* multicast group refcnts */
};

//------------------------------------------------------------------------------------------------------------------------------------------

/* Determines if it is first or last packet
 * when packet consists of multiple packet
 * chunks because of many route TLV
 * (all won't fit into one packet) */
enum Packet_part_type {
	EIGRP_PACKET_PART_NA,
	EIGRP_PACKET_PART_FIRST,
	EIGRP_PACKET_PART_LAST
};

/* Neighbor Data Structure */
struct eigrp_neighbor {
	/* This neighbor's parent eigrp interface. */
	struct eigrp_interface *ei;

	/* EIGRP neighbor Information */
	unsigned char state; /* neigbor status. */

	uint32_t recv_sequence_number; /* Last received sequence Number. */
	uint32_t init_sequence_number;

	/*If packet is unacknowledged, we try to send it again 16 times*/
	unsigned char retrans_counter;

	struct in_addr src; /* Neighbor Src address. */

	unsigned char os_rel_major;  // system version - just for show
	unsigned char os_rel_minor;  // system version - just for show
	unsigned char tlv_rel_major; // eigrp version - tells us what TLV format
				     // to use
	unsigned char tlv_rel_minor; // eigrp version - tells us what TLV format
				     // to use

	unsigned char K1;
	unsigned char K2;
	unsigned char K3;
	unsigned char K4;
	unsigned char K5;
	unsigned char K6;

	/* Timer values. */
	uint16_t v_holddown;

	/* Threads. */
	struct thread *t_holddown;
	struct thread *t_nbr_send_gr; /* thread for sending multiple GR packet
					 chunks */

	struct eigrp_fifo *retrans_queue;
	struct eigrp_fifo *multicast_queue;

	uint32_t crypt_seqnum; /* Cryptographic Sequence Number. */

	/* prefixes not received from neighbor during Graceful restart */
	struct list *nbr_gr_prefixes;
	/* prefixes not yet send to neighbor during Graceful restart */
	struct list *nbr_gr_prefixes_send;
	/* if packet is first or last during Graceful restart */
	enum Packet_part_type nbr_gr_packet_type;
};

//---------------------------------------------------------------------------------------------------------------------------------------------


struct eigrp_packet {
	struct eigrp_packet *next;
	struct eigrp_packet *previous;

	/* Pointer to data stream. */
	struct stream *s;

	/* IP destination address. */
	struct in_addr dst;

	/*Packet retransmission thread*/
	struct thread *t_retrans_timer;

	/*Packet retransmission counter*/
	unsigned char retrans_counter;

	uint32_t sequence_number;

	/* EIGRP packet length. */
	uint16_t length;

	struct eigrp_neighbor *nbr;
};

struct eigrp_fifo {
	struct eigrp_packet *head;
	struct eigrp_packet *tail;

	unsigned long count;
};

struct eigrp_header {
	unsigned char version;
	unsigned char opcode;
	uint16_t checksum;
	uint32_t flags;
	uint32_t sequence;
	uint32_t ack;
	uint16_t vrid;
	uint16_t ASNumber;
	char *tlv[0];

} __attribute__((packed));


/**
 * Generic TLV type used for packet decoding.
 *
 *      +-----+------------------+
 *      |     |     |            |
 *      | Type| Len |    Vector  |
 *      |     |     |            |
 *      +-----+------------------+
 */
struct eigrp_tlv_hdr_type {
	uint16_t type;
	uint16_t length;
	uint8_t value[0];
} __attribute__((packed));

struct TLV_Parameter_Type {
	uint16_t type;
	uint16_t length;
	unsigned char K1;
	unsigned char K2;
	unsigned char K3;
	unsigned char K4;
	unsigned char K5;
	unsigned char K6;
	uint16_t hold_time;
} __attribute__((packed));

struct TLV_MD5_Authentication_Type {
	uint16_t type;
	uint16_t length;
	uint16_t auth_type;
	uint16_t auth_length;
	uint32_t key_id;
	uint32_t key_sequence;
	unsigned char Nullpad[8];
	unsigned char digest[EIGRP_AUTH_TYPE_MD5_LEN];

} __attribute__((packed));

struct TLV_SHA256_Authentication_Type {
	uint16_t type;
	uint16_t length;
	uint16_t auth_type;
	uint16_t auth_length;
	uint32_t key_id;
	uint32_t key_sequence;
	unsigned char Nullpad[8];
	unsigned char digest[EIGRP_AUTH_TYPE_SHA256_LEN];

} __attribute__((packed));

struct TLV_Sequence_Type {
	uint16_t type;
	uint16_t length;
	unsigned char addr_length;
	struct in_addr *addresses;
} __attribute__((packed));

struct TLV_Next_Multicast_Sequence {
	uint16_t type;
	uint16_t length;
	uint32_t multicast_sequence;
} __attribute__((packed));

struct TLV_Software_Type {
	uint16_t type;
	uint16_t length;
	unsigned char vender_major;
	unsigned char vender_minor;
	unsigned char eigrp_major;
	unsigned char eigrp_minor;
} __attribute__((packed));

struct TLV_IPv4_Internal_type {
	uint16_t type;
	uint16_t length;
	struct in_addr forward;

	/*Metrics*/
	struct eigrp_metrics metric;

	unsigned char prefix_length;

	unsigned char destination_part[4];
	struct in_addr destination;
} __attribute__((packed));

struct TLV_IPv4_External_type {
	uint16_t type;
	uint16_t length;
	struct in_addr next_hop;
	struct in_addr originating_router;
	uint32_t originating_as;
	uint32_t administrative_tag;
	uint32_t external_metric;
	uint16_t reserved;
	unsigned char external_protocol;
	unsigned char external_flags;

	/*Metrics*/
	struct eigrp_metrics metric;

	unsigned char prefix_length;
	unsigned char destination_part[4];
	struct in_addr destination;
} __attribute__((packed));

/* EIGRP Peer Termination TLV - used for hard restart */
struct TLV_Peer_Termination_type {
	uint16_t type;
	uint16_t length;
	unsigned char unknown;
	uint32_t neighbor_ip;
} __attribute__((packed));

/* Who executed Graceful restart */
enum GR_type { EIGRP_GR_MANUAL, EIGRP_GR_FILTER };

//---------------------------------------------------------------------------------------------------------------------------------------------

/* EIGRP Topology table node structure */
struct eigrp_prefix_entry {
	struct list *entries, *rij;
	uint32_t fdistance;		      // FD
	uint32_t rdistance;		      // RD
	uint32_t distance;		      // D
	struct eigrp_metrics reported_metric; // RD for sending

	unsigned char nt;	 // network type
	unsigned char state;      // route fsm state
	unsigned char af;	 // address family
	unsigned char req_action; // required action

	struct prefix *destination;

	// If network type is REMOTE_EXTERNAL, pointer will have reference to
	// its external TLV
	struct TLV_IPv4_External_type *extTLV;

	uint64_t serno; /*Serial number for this entry. Increased with each
			   change of entry*/
};

/* EIGRP Topology table record structure */
struct eigrp_nexthop_entry {
	struct eigrp_prefix_entry *prefix;
	uint32_t reported_distance; // distance reported by neighbor
	uint32_t distance;	  // sum of reported distance and link cost to
				    // advertised neighbor

	struct eigrp_metrics reported_metric;
	struct eigrp_metrics total_metric;

	struct eigrp_neighbor *adv_router; // ip address of advertising neighbor
	unsigned char flags;		   // used for marking successor and FS

	struct eigrp_interface *ei; // pointer for case of connected entry
};

//---------------------------------------------------------------------------------------------------------------------------------------------
typedef enum {
	EIGRP_CONNECTED,
	EIGRP_INT,
	EIGRP_EXT,
} msg_data_t;

/* EIGRP Finite State Machine */

struct eigrp_fsm_action_message {
	unsigned char packet_type;	 // UPDATE, QUERY, SIAQUERY, SIAREPLY
	struct eigrp *eigrp;		   // which thread sent mesg
	struct eigrp_neighbor *adv_router; // advertising neighbor
	struct eigrp_nexthop_entry *entry;
	struct eigrp_prefix_entry *prefix;
	msg_data_t data_type; // internal or external tlv type
	struct eigrp_metrics metrics;
};

#endif /* _ZEBRA_EIGRP_STRUCTURES_H_ */
