// SPDX-License-Identifier: GPL-2.0-or-later
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
 */

#ifndef _ZEBRA_EIGRP_STRUCTS_H_
#define _ZEBRA_EIGRP_STRUCTS_H_

#include "filter.h"

#include "eigrpd/eigrp_const.h"
#include "eigrpd/eigrp_macros.h"

struct eigrp_metrics {
	uint32_t delay;
	uint32_t bandwidth;
	uint8_t mtu[3];
	uint8_t hop_count;
	uint8_t reliability;
	uint8_t load;
	uint8_t tag;
	uint8_t flags;
};

struct eigrp_extdata {
	uint32_t orig;
	uint32_t as;
	uint32_t tag;
	uint32_t metric;
	uint16_t reserved;
	uint8_t protocol;
	uint8_t flags;
};

PREDECL_HASH(eigrp_interface_hash);
PREDECL_HASH(eigrp_master_hash);
struct eigrp {
	struct eigrp_master_hash_item eigrp_item;

	vrf_id_t vrf_id;

	uint16_t AS;	 /* Autonomous system number */
	uint16_t vrid;       /* Virtual Router ID */
	uint8_t k_values[6]; /*Array for K values configuration*/
	uint8_t variance;    /*Metric variance multiplier*/
	uint8_t max_paths;   /*Maximum allowed paths for 1 prefix*/

	/*Name of this EIGRP instance*/
	char *name;

	/* EIGRP Router ID. */
	struct in_addr router_id;	/* Configured automatically. */
	struct in_addr router_id_static; /* Configured manually. */

	struct eigrp_interface_hash_head eifs;
	uint8_t passive_interface_default; /* passive-interface default */

	int fd;
	unsigned int maxsndbuflen;

	uint32_t sequence_number; /*Global EIGRP sequence number*/

	struct stream *ibuf;
	struct list *oi_write_q;

	/*Threads*/
	struct event *t_write;
	struct event *t_read;
	struct event *t_distribute; /* timer for distribute list */

	struct route_table *networks; /* EIGRP config networks. */

	struct route_table *topology_table;

	uint64_t serno; /* Global serial number counter for topology entry
			   changes*/
	uint64_t serno_last_update; /* Highest serial number of information send
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

	/* distribute_ctx */
	struct distribute_ctx *distribute_ctx;

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(eigrp);

struct eigrp_if_params {
	uint8_t passive_interface;
	uint32_t v_hello;
	uint16_t v_wait;
	uint8_t type; /* type of interface */
	uint32_t bandwidth;
	uint32_t delay;
	uint8_t reliability;
	uint8_t load;

	char *auth_keychain; /* Associated keychain with interface*/
	int auth_type;       /* EIGRP authentication type */
};

/*
 * Per-interface EIGRP data, attached to ifp->info.
 *
 * Historically a bare "struct eigrp_interface" is hung off ifp->info, and it
 * is only allocated once a `network` statement matches a connected prefix (see
 * eigrp_network_run_interface()).  That single object conflates three
 * independent concerns:
 *
 *   1. interface *configuration* (struct eigrp_if_params: delay, bandwidth,
 *      hello-interval, hold-time, passive, authentication);
 *   2. a *single* connected prefix (struct prefix address); and
 *   3. running *protocol state* (neighbors, output buffer, timers, stats).
 *
 * Because the object is prefix-derived it cannot exist before the protocol is
 * active, so per-interface configuration entered before a `network` statement
 * is rejected with NB_ERR_INCONSISTENCY (issue #11301), and an interface can
 * only ever run EIGRP on one connected prefix.
 *
 * struct eigrp_if_info splits interface *configuration*, which must be
 * available as soon as the interface exists, from the running per-address
 * interface instances.  This mirrors ospfd's struct ospf_if_info and is the
 * separation requested in the reviews of #14765 and #18307.
 */
struct eigrp_if_info {
	/* Interface-wide parameters.  Allocated as soon as the interface
	 * exists and independent of whether EIGRP runs on it, which is what
	 * allows configuration to be accepted before a `network` statement.
	 *
	 * Unlike ospfd there is no per-address parameter table here:
	 * frr-eigrpd.yang has no per-address interface configuration (the
	 * interface leaves are per-interface, and the `instance` list is
	 * keyed by ASN), so a route_table of overrides would be dead code.
	 */
	struct eigrp_if_params *def_params;

	/* Running struct eigrp_interface instances, keyed by connected
	 * address.  A single interface may run EIGRP on several prefixes.
	 */
	struct route_table *eifs;
};

enum { MEMBER_ALLROUTERS = 0,
       MEMBER_MAX,
};

PREDECL_HASH(eigrp_nbr_hash);

/*EIGRP interface structure*/
struct eigrp_interface {
	struct eigrp_interface_hash_item eif_item;

	/* Interface configuration.  Points at the owning interface's
	 * eigrp_if_info->def_params, which is allocated when the interface
	 * appears and outlives this (prefix-derived) object.  Configuration
	 * therefore survives EIGRP being started and stopped.
	 */
	struct eigrp_if_params *params;

	/*multicast group refcnts */
	bool member_allrouters;

	/* This interface's parent eigrp instance. */
	struct eigrp *eigrp;

	/* Interface data from zebra. */
	struct interface *ifp;

	/* Packet send buffer. */
	struct eigrp_fifo *obuf; /* Output queue */

	/* To which multicast groups do we currently belong? */

	uint32_t curr_bandwidth;
	uint32_t curr_mtu;

	uint8_t multicast_memberships;

	/* EIGRP Network Type. */
	uint8_t type;

	struct prefix address;      /* Interface prefix */

	/* Neighbor information. */
	struct eigrp_nbr_hash_head nbr_hash_head;

	/* Threads. */
	struct event *t_hello;	    /* timer */
	struct event *t_distribute; /* timer for distribute list */

	int on_write_q;

	/* Statistics fields. */
	uint32_t hello_in;   /* Hello message input count. */
	uint32_t update_in;  /* Update message input count. */
	uint32_t query_in;   /* Query message input count. */
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
	struct eigrp_nbr_hash_item nbr_hash_item;

	/* This neighbor's parent eigrp interface. */
	struct eigrp_interface *ei;

	/* EIGRP neighbor Information */
	uint8_t state; /* neighbor status. */

	uint32_t recv_sequence_number; /* Last received sequence Number. */
	uint32_t init_sequence_number;

	/*If packet is unacknowledged, we try to send it again 16 times*/
	uint8_t retrans_counter;

	struct in_addr src; /* Neighbor Src address. */

	uint8_t os_rel_major;  // system version - just for show
	uint8_t os_rel_minor;  // system version - just for show
	uint8_t tlv_rel_major; // eigrp version - tells us what TLV format to
			       // use
	uint8_t tlv_rel_minor; // eigrp version - tells us what TLV format to
			       // use

	uint8_t K1;
	uint8_t K2;
	uint8_t K3;
	uint8_t K4;
	uint8_t K5;
	uint8_t K6;

	/* Timer values. */
	uint16_t v_holddown;

	/* Threads. */
	struct event *t_holddown;
	struct event *t_nbr_send_gr; /* thread for sending multiple GR packet
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
	struct event *t_retrans_timer;

	/*Packet retransmission counter*/
	uint8_t retrans_counter;

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
	uint8_t version;
	uint8_t opcode;
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
	uint8_t K1;
	uint8_t K2;
	uint8_t K3;
	uint8_t K4;
	uint8_t K5;
	uint8_t K6;
	uint16_t hold_time;
} __attribute__((packed));

struct TLV_MD5_Authentication_Type {
	uint16_t type;
	uint16_t length;
	uint16_t auth_type;
	uint16_t auth_length;
	uint32_t key_id;
	uint32_t key_sequence;
	uint8_t Nullpad[8];
	uint8_t digest[EIGRP_AUTH_TYPE_MD5_LEN];

} __attribute__((packed));

struct TLV_SHA256_Authentication_Type {
	uint16_t type;
	uint16_t length;
	uint16_t auth_type;
	uint16_t auth_length;
	uint32_t key_id;
	uint32_t key_sequence;
	uint8_t Nullpad[8];
	uint8_t digest[EIGRP_AUTH_TYPE_SHA256_LEN];

} __attribute__((packed));

struct TLV_Sequence_Type {
	uint16_t type;
	uint16_t length;
	uint8_t addr_length;
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
	uint8_t vender_major;
	uint8_t vender_minor;
	uint8_t eigrp_major;
	uint8_t eigrp_minor;
} __attribute__((packed));

struct TLV_IPv4_Internal_type {
	uint16_t type;
	uint16_t length;
	struct in_addr forward;

	/*Metrics*/
	struct eigrp_metrics metric;

	uint8_t prefix_length;

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
	uint8_t external_protocol;
	uint8_t external_flags;

	/*Metrics*/
	struct eigrp_metrics metric;

	uint8_t prefix_length;
	unsigned char destination_part[4];
	struct in_addr destination;
} __attribute__((packed));

/* EIGRP Peer Termination TLV - used for hard restart */
struct TLV_Peer_Termination_type {
	uint16_t type;
	uint16_t length;
	uint8_t unknown;
	uint32_t neighbor_ip;
} __attribute__((packed));

/* Who executed Graceful restart */
enum GR_type { EIGRP_GR_MANUAL, EIGRP_GR_FILTER };

//---------------------------------------------------------------------------------------------------------------------------------------------

/* EIGRP Topology table node structure */
struct eigrp_prefix_descriptor {
	struct list *entries, *rij;
	uint32_t fdistance;		      // FD
	uint32_t rdistance;		      // RD
	uint32_t distance;		      // D
	struct eigrp_metrics reported_metric; // RD for sending

	uint8_t nt;	 // network type
	uint8_t state;      // route fsm state
	uint8_t af;	 // address family
	uint8_t req_action; // required action

	struct prefix destination;

	// If network type is REMOTE_EXTERNAL, pointer will have reference to
	// its external TLV
	struct TLV_IPv4_External_type *extTLV;

	uint64_t serno; /*Serial number for this entry. Increased with each
			   change of entry*/
};

/* EIGRP Topology table record structure */
struct eigrp_route_descriptor {
	uint16_t type;
	uint16_t afi;

	struct eigrp_prefix_descriptor *prefix;
	struct eigrp_neighbor *adv_router;
	struct in_addr nexthop;

	uint32_t reported_distance; // distance reported by neighbor
	uint32_t distance;	  // sum of reported distance and link cost to
				    // advertised neighbor

	struct eigrp_metrics reported_metric;
	struct eigrp_metrics total_metric;

	struct eigrp_metrics metric;
	struct eigrp_extdata extdata;

	uint8_t flags;			   // used for marking successor and FS

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
	uint8_t packet_type;		   // UPDATE, QUERY, SIAQUERY, SIAREPLY
	struct eigrp *eigrp;		   // which thread sent mesg
	struct eigrp_neighbor *adv_router; // advertising neighbor
	struct eigrp_route_descriptor *entry;
	struct eigrp_prefix_descriptor *prefix;
	msg_data_t data_type; // internal or external tlv type
	struct eigrp_metrics metrics;
	enum metric_change change;
};

#endif /* _ZEBRA_EIGRP_STRUCTURES_H_ */
