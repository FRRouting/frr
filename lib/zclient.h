// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra's client header.
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_ZCLIENT_H
#define _ZEBRA_ZCLIENT_H

struct zclient;

/* For struct zapi_route. */
#include "prefix.h"
#include "ipaddr.h"

/* For struct interface and struct connected. */
#include "if.h"

/* For vrf_bitmap_t. */
#include "vrf.h"

/* For union g_addr */
#include "nexthop.h"
/* For resilience */
#include "nexthop_group.h"

/* For union pw_protocol_fields */
#include "pw.h"

#include "mlag.h"
#include "srte.h"
#include "srv6.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Zebra types. Used in Zserv message header. */
typedef uint16_t zebra_size_t;

/* Marker value used in new Zserv, in the byte location corresponding
 * the command value in the old zserv header. To allow old and new
 * Zserv headers to be distinguished from each other.
 */
#define ZEBRA_HEADER_MARKER              254

/* For input/output buffer to zebra. */
#define ZEBRA_MAX_PACKET_SIZ          16384U
#define ZEBRA_SMALL_PACKET_SIZE       200U

/* Zebra header size. */
#define ZEBRA_HEADER_SIZE             10

/* special socket path name to use TCP
 * @ is used as first character because that's abstract socket names on Linux
 */
#define ZAPI_TCP_PATHNAME             "@tcp"

/* IPset size name stands for the name of the ipset entry
 * that can be created by using some zapi interfaces
 */
#define ZEBRA_IPSET_NAME_SIZE   32

/* IPTable action is defined by two values: either
 * forward or drop
 */
#define ZEBRA_IPTABLES_FORWARD 0
#define ZEBRA_IPTABLES_DROP    1

/* Zebra FEC register command flags. */
#define ZEBRA_FEC_REGISTER_LABEL          0x1
#define ZEBRA_FEC_REGISTER_LABEL_INDEX    0x2

/* Client capabilities */
enum zserv_client_capabilities {
	ZEBRA_CLIENT_GR_CAPABILITIES = 1,
	ZEBRA_CLIENT_ROUTE_UPDATE_COMPLETE = 2,
	ZEBRA_CLIENT_ROUTE_UPDATE_PENDING = 3,
	ZEBRA_CLIENT_GR_DISABLE = 4,
	ZEBRA_CLIENT_RIB_STALE_TIME
};

/* Macro to check if there GR enabled. */
#define ZEBRA_CLIENT_GR_ENABLED(X) (X == ZEBRA_CLIENT_GR_CAPABILITIES)

#define ZEBRA_SR_POLICY_NAME_MAX_LENGTH 100

extern struct sockaddr_storage zclient_addr;
extern socklen_t zclient_addr_len;

/* Zebra message types. Please update the corresponding
 * command_types array with any changes!
 */
typedef enum {
	ZEBRA_INTERFACE_ADD,
	ZEBRA_INTERFACE_DELETE,
	ZEBRA_INTERFACE_ADDRESS_ADD,
	ZEBRA_INTERFACE_ADDRESS_DELETE,
	ZEBRA_INTERFACE_UP,
	ZEBRA_INTERFACE_DOWN,
	ZEBRA_INTERFACE_SET_MASTER,
	ZEBRA_INTERFACE_SET_ARP,
	ZEBRA_INTERFACE_SET_PROTODOWN,
	ZEBRA_ROUTE_ADD,
	ZEBRA_ROUTE_DELETE,
	ZEBRA_ROUTE_NOTIFY_OWNER,
	ZEBRA_REDISTRIBUTE_ADD,
	ZEBRA_REDISTRIBUTE_DELETE,
	ZEBRA_REDISTRIBUTE_DEFAULT_ADD,
	ZEBRA_REDISTRIBUTE_DEFAULT_DELETE,
	ZEBRA_ROUTER_ID_ADD,
	ZEBRA_ROUTER_ID_DELETE,
	ZEBRA_ROUTER_ID_UPDATE,
	ZEBRA_HELLO,
	ZEBRA_CAPABILITIES,
	ZEBRA_NEXTHOP_REGISTER,
	ZEBRA_NEXTHOP_UNREGISTER,
	ZEBRA_NEXTHOP_UPDATE,
	ZEBRA_INTERFACE_NBR_ADDRESS_ADD,
	ZEBRA_INTERFACE_NBR_ADDRESS_DELETE,
	ZEBRA_INTERFACE_BFD_DEST_UPDATE,
	ZEBRA_BFD_DEST_REGISTER,
	ZEBRA_BFD_DEST_DEREGISTER,
	ZEBRA_BFD_DEST_UPDATE,
	ZEBRA_BFD_DEST_REPLAY,
	ZEBRA_REDISTRIBUTE_ROUTE_ADD,
	ZEBRA_REDISTRIBUTE_ROUTE_DEL,
	ZEBRA_VRF_ADD,
	ZEBRA_VRF_DELETE,
	ZEBRA_VRF_LABEL,
	ZEBRA_BFD_CLIENT_REGISTER,
	ZEBRA_BFD_CLIENT_DEREGISTER,
	ZEBRA_INTERFACE_ENABLE_RADV,
	ZEBRA_INTERFACE_DISABLE_RADV,
	ZEBRA_NEXTHOP_LOOKUP_MRIB,
	ZEBRA_INTERFACE_LINK_PARAMS,
	ZEBRA_MPLS_LABELS_ADD,
	ZEBRA_MPLS_LABELS_DELETE,
	ZEBRA_MPLS_LABELS_REPLACE,
	ZEBRA_SR_POLICY_SET,
	ZEBRA_SR_POLICY_DELETE,
	ZEBRA_SR_POLICY_NOTIFY_STATUS,
	ZEBRA_IPMR_ROUTE_STATS,
	ZEBRA_LABEL_MANAGER_CONNECT,
	ZEBRA_LABEL_MANAGER_CONNECT_ASYNC,
	ZEBRA_GET_LABEL_CHUNK,
	ZEBRA_RELEASE_LABEL_CHUNK,
	ZEBRA_FEC_REGISTER,
	ZEBRA_FEC_UNREGISTER,
	ZEBRA_FEC_UPDATE,
	ZEBRA_ADVERTISE_DEFAULT_GW,
	ZEBRA_ADVERTISE_SVI_MACIP,
	ZEBRA_ADVERTISE_SUBNET,
	ZEBRA_ADVERTISE_ALL_VNI,
	ZEBRA_LOCAL_ES_ADD,
	ZEBRA_LOCAL_ES_DEL,
	ZEBRA_REMOTE_ES_VTEP_ADD,
	ZEBRA_REMOTE_ES_VTEP_DEL,
	ZEBRA_LOCAL_ES_EVI_ADD,
	ZEBRA_LOCAL_ES_EVI_DEL,
	ZEBRA_VNI_ADD,
	ZEBRA_VNI_DEL,
	ZEBRA_L3VNI_ADD,
	ZEBRA_L3VNI_DEL,
	ZEBRA_REMOTE_VTEP_ADD,
	ZEBRA_REMOTE_VTEP_DEL,
	ZEBRA_MACIP_ADD,
	ZEBRA_MACIP_DEL,
	ZEBRA_IP_PREFIX_ROUTE_ADD,
	ZEBRA_IP_PREFIX_ROUTE_DEL,
	ZEBRA_REMOTE_MACIP_ADD,
	ZEBRA_REMOTE_MACIP_DEL,
	ZEBRA_DUPLICATE_ADDR_DETECTION,
	ZEBRA_PW_ADD,
	ZEBRA_PW_DELETE,
	ZEBRA_PW_SET,
	ZEBRA_PW_UNSET,
	ZEBRA_PW_STATUS_UPDATE,
	ZEBRA_RULE_ADD,
	ZEBRA_RULE_DELETE,
	ZEBRA_RULE_NOTIFY_OWNER,
	ZEBRA_TABLE_MANAGER_CONNECT,
	ZEBRA_GET_TABLE_CHUNK,
	ZEBRA_RELEASE_TABLE_CHUNK,
	ZEBRA_IPSET_CREATE,
	ZEBRA_IPSET_DESTROY,
	ZEBRA_IPSET_ENTRY_ADD,
	ZEBRA_IPSET_ENTRY_DELETE,
	ZEBRA_IPSET_NOTIFY_OWNER,
	ZEBRA_IPSET_ENTRY_NOTIFY_OWNER,
	ZEBRA_IPTABLE_ADD,
	ZEBRA_IPTABLE_DELETE,
	ZEBRA_IPTABLE_NOTIFY_OWNER,
	ZEBRA_VXLAN_FLOOD_CONTROL,
	ZEBRA_VXLAN_SG_ADD,
	ZEBRA_VXLAN_SG_DEL,
	ZEBRA_VXLAN_SG_REPLAY,
	ZEBRA_MLAG_PROCESS_UP,
	ZEBRA_MLAG_PROCESS_DOWN,
	ZEBRA_MLAG_CLIENT_REGISTER,
	ZEBRA_MLAG_CLIENT_UNREGISTER,
	ZEBRA_MLAG_FORWARD_MSG,
	ZEBRA_NHG_ADD,
	ZEBRA_NHG_DEL,
	ZEBRA_NHG_NOTIFY_OWNER,
	ZEBRA_EVPN_REMOTE_NH_ADD,
	ZEBRA_EVPN_REMOTE_NH_DEL,
	ZEBRA_SRV6_LOCATOR_ADD,
	ZEBRA_SRV6_LOCATOR_DELETE,
	ZEBRA_SRV6_MANAGER_GET_LOCATOR_CHUNK,
	ZEBRA_SRV6_MANAGER_RELEASE_LOCATOR_CHUNK,
	ZEBRA_SRV6_MANAGER_GET_LOCATOR,
	ZEBRA_SRV6_MANAGER_GET_SRV6_SID,
	ZEBRA_SRV6_MANAGER_RELEASE_SRV6_SID,
	ZEBRA_SRV6_MANAGER_GET_LOCATOR_SID,
	ZEBRA_SRV6_MANAGER_RELEASE_LOCATOR_SID,
	ZEBRA_SRV6_MANAGER_GET_LOCATOR_ALL,
	ZEBRA_ERROR,
	ZEBRA_CLIENT_CAPABILITIES,
	ZEBRA_OPAQUE_MESSAGE,
	ZEBRA_OPAQUE_REGISTER,
	ZEBRA_OPAQUE_UNREGISTER,
	ZEBRA_NEIGH_DISCOVER,
	ZEBRA_ROUTE_NOTIFY_REQUEST,
	ZEBRA_CLIENT_CLOSE_NOTIFY,
	ZEBRA_NEIGH_ADDED,
	ZEBRA_NEIGH_REMOVED,
	ZEBRA_NEIGH_GET,
	ZEBRA_NEIGH_REGISTER,
	ZEBRA_NEIGH_UNREGISTER,
	ZEBRA_NEIGH_IP_ADD,
	ZEBRA_NEIGH_IP_DEL,
	ZEBRA_CONFIGURE_ARP,
	ZEBRA_GRE_GET,
	ZEBRA_GRE_UPDATE,
	ZEBRA_GRE_SOURCE_SET,
	ZEBRA_TC_QDISC_INSTALL,
	ZEBRA_TC_QDISC_UNINSTALL,
	ZEBRA_TC_CLASS_ADD,
	ZEBRA_TC_CLASS_DELETE,
	ZEBRA_TC_FILTER_ADD,
	ZEBRA_TC_FILTER_DELETE,
	ZEBRA_OPAQUE_NOTIFY,
	ZEBRA_SRV6_SID_NOTIFY,
} zebra_message_types_t;
/* Zebra message types. Please update the corresponding
 * command_types array with any changes!
 */

enum zebra_error_types {
	ZEBRA_UNKNOWN_ERROR,    /* Error of unknown type */
	ZEBRA_NO_VRF,		/* Vrf in header was not found */
	ZEBRA_INVALID_MSG_TYPE, /* No handler found for msg type */
};

static inline const char *zebra_error_type2str(enum zebra_error_types type)
{
	switch (type) {
	case ZEBRA_UNKNOWN_ERROR:
		return "ZEBRA_UNKNOWN_ERROR";
	case ZEBRA_NO_VRF:
		return "ZEBRA_NO_VRF";
	case ZEBRA_INVALID_MSG_TYPE:
		return "ZEBRA_INVALID_MSG_TYPE";
	}

	return "UNKNOWN";
}

struct redist_proto {
	uint8_t enabled;
	struct list *instances;
};

struct zclient_capabilities {
	uint32_t ecmp;
	bool mpls_enabled;
	enum mlag_role role;
	bool v6_with_v4_nexthop;
};

/* Graceful Restart Capabilities message */
struct zapi_cap {
	enum zserv_client_capabilities cap;
	uint32_t stale_removal_time;
	afi_t afi;
	safi_t safi;
	vrf_id_t vrf_id;
};

/* clang-format off */
#define ZAPI_CALLBACK_ARGS                                                     \
	int cmd, struct zclient *zclient, uint16_t length, vrf_id_t vrf_id

/* function-type typedef (pointer not included) */
typedef int (zclient_handler)(ZAPI_CALLBACK_ARGS);
/* clang-format on */

struct zapi_route;

/* Structure for the zebra client. */
struct zclient {
	/* The thread master we schedule ourselves on */
	struct event_loop *master;

	/* Privileges to change socket values */
	struct zebra_privs_t *privs;

	/* Is this a synchronous client? */
	bool synchronous;

	/* Auxiliary clients don't execute standard library handlers
	 * (which otherwise would duplicate VRF/interface add/delete/etc.
	 */
	bool auxiliary;

	/* BFD enabled with bfd_protocol_integration_init() */
	bool bfd_integration;

	/* Session id (optional) to support clients with multiple sessions */
	uint32_t session_id;

	/* Socket to zebra daemon. */
	int sock;

	/* Connection failure count. */
	int fail;

	/* Input buffer for zebra message. */
	struct stream *ibuf;

	/* Output buffer for zebra message. */
	struct stream *obuf;

	/* Buffer of data waiting to be written to zebra. */
	struct buffer *wb;

	/* Read and connect thread. */
	struct event *t_read;
	struct event *t_connect;

	/* Thread to write buffered data to zebra. */
	struct event *t_write;

	/* Redistribute information. */
	uint8_t redist_default; /* clients protocol */
	unsigned short instance;
	struct redist_proto mi_redist[AFI_MAX][ZEBRA_ROUTE_MAX];
	vrf_bitmap_t redist[AFI_MAX][ZEBRA_ROUTE_MAX];

	/* Redistribute default. */
	vrf_bitmap_t default_information[AFI_MAX];

	/* Pointer to the callback functions. */
	void (*zebra_connected)(struct zclient *);
	void (*zebra_capabilities)(struct zclient_capabilities *cap);

	/*
	 * match -> is the prefix that the calling daemon asked to be matched
	 * against.
	 * nhr->prefix -> is the actual prefix that was matched against in the
	 * rib itself.
	 *
	 * This distinction is made because a LPM can be made if there is a
	 * covering route.  This way the upper level protocol can make a
	 * decision point about whether or not it wants to use the match or not.
	 */
	void (*nexthop_update)(struct vrf *vrf, struct prefix *match,
			       struct zapi_route *nhr);

	int (*handle_error)(enum zebra_error_types error);

	/*
	 * When the zclient attempts to write the stream data to
	 * it's named pipe to/from zebra, we may have a situation
	 * where the other daemon has not fully drained the data
	 * from the socket.  In this case provide a mechanism
	 * where we will *still* buffer the data to be sent
	 * and also provide a callback mechanism to the appropriate
	 * place where we can signal that we're ready to receive
	 * more data.
	 */
	void (*zebra_buffer_write_ready)(void);

	zclient_handler *const *handlers;
	size_t n_handlers;
};

/* lib handlers added in bfd.c */
extern int zclient_bfd_session_replay(ZAPI_CALLBACK_ARGS);
extern int zclient_bfd_session_update(ZAPI_CALLBACK_ARGS);

/* Zebra API message flag. */
#define ZAPI_MESSAGE_NEXTHOP  0x01
#define ZAPI_MESSAGE_DISTANCE 0x02
#define ZAPI_MESSAGE_METRIC   0x04
#define ZAPI_MESSAGE_TAG      0x08
#define ZAPI_MESSAGE_MTU      0x10
#define ZAPI_MESSAGE_SRCPFX   0x20
/* Backup nexthops are present */
#define ZAPI_MESSAGE_BACKUP_NEXTHOPS 0x40
#define ZAPI_MESSAGE_NHG 0x80
/*
 * This should only be used by a DAEMON that needs to communicate
 * the table being used is not in the VRF.  You must pass the
 * default vrf, else this will be ignored.
 */
#define ZAPI_MESSAGE_TABLEID 0x0100
#define ZAPI_MESSAGE_SRTE 0x0200
#define ZAPI_MESSAGE_OPAQUE 0x0400

#define ZSERV_VERSION 6
/* Zserv protocol message header */
struct zmsghdr {
	uint16_t length;
	/* Always set to 255 in new zserv */
	uint8_t marker;
	uint8_t version;
	vrf_id_t vrf_id;
	uint16_t command;
} __attribute__((packed));
#define ZAPI_HEADER_CMD_LOCATION offsetof(struct zmsghdr, command)

/*
 * ZAPI nexthop. Note that these are sorted when associated with ZAPI routes,
 * and that sorting must be aligned with the sorting of nexthops in
 * lib/nexthop.c. Any new fields must be accounted for in zapi_nexthop_cmp().
 */
struct zapi_nexthop {
	enum nexthop_types_t type;
	vrf_id_t vrf_id;
	ifindex_t ifindex;
	uint8_t flags;
	union {
		union g_addr gate;
		enum blackhole_type bh_type;
	};

	/* MPLS labels for BGP-LU or Segment Routing */
	uint8_t label_num;
	enum lsp_types_t label_type;
	mpls_label_t labels[MPLS_MAX_LABELS];

	struct ethaddr rmac;

	uint64_t weight;

	/* Backup nexthops, for IP-FRR, TI-LFA, etc */
	uint8_t backup_num;
	uint8_t backup_idx[NEXTHOP_MAX_BACKUPS];

	/* SR-TE color. */
	uint32_t srte_color;

	/* SRv6 localsid info for Endpoint-behaviour */
	uint32_t seg6local_action;
	struct seg6local_context seg6local_ctx;

	/* SRv6 Headend-behaviour */
	int seg_num;
	struct in6_addr seg6_segs[SRV6_MAX_SEGS];
};

/*
 * ZAPI nexthop flags values - we're encoding a single octet
 * initially, so ensure that the on-the-wire encoding continues
 * to match the number of valid flags.
 */

#define ZAPI_NEXTHOP_FLAG_ONLINK	0x01
#define ZAPI_NEXTHOP_FLAG_LABEL		0x02
#define ZAPI_NEXTHOP_FLAG_WEIGHT	0x04
#define ZAPI_NEXTHOP_FLAG_HAS_BACKUP	0x08 /* Nexthop has a backup */
#define ZAPI_NEXTHOP_FLAG_SEG6		0x10
#define ZAPI_NEXTHOP_FLAG_SEG6LOCAL	0x20
#define ZAPI_NEXTHOP_FLAG_EVPN		0x40

/*
 * ZAPI Nexthop Group. For use with protocol creation of nexthop groups.
 */
struct zapi_nhg {
	uint16_t proto;
	uint32_t id;

	struct nhg_resilience resilience;

	uint16_t nexthop_num;
	struct zapi_nexthop nexthops[MULTIPATH_NUM];

	uint16_t backup_nexthop_num;
	struct zapi_nexthop backup_nexthops[MULTIPATH_NUM];
};

/*
 * Some of these data structures do not map easily to
 * a actual data structure size giving different compilers
 * and systems.  For those data structures we need
 * to use the smallest available stream_getX/putX functions
 * to encode/decode.
 */
struct zapi_route {
	uint8_t type;
	unsigned short instance;

	/* If you add flags, update zclient_dump_route_flags */
	uint32_t flags;
/*
 * Cause Zebra to consider this routes nexthops recursively
 */
#define ZEBRA_FLAG_ALLOW_RECURSION    0x01
/*
 * This is a route that is read in on startup that was left around
 * from a previous run of FRR
 */
#define ZEBRA_FLAG_SELFROUTE          0x02
/*
 * This flag is used to tell Zebra that the BGP route being passed
 * down is a IBGP route
 */
#define ZEBRA_FLAG_IBGP               0x04
/*
 * This is a route that has been selected for FIB installation.
 * This flag is set in zebra and can be passed up to routing daemons
 */
#define ZEBRA_FLAG_SELECTED           0x08
/*
 * This is a route that we are telling Zebra that this route *must*
 * win and will be installed even over ZEBRA_FLAG_SELECTED
 */
#define ZEBRA_FLAG_FIB_OVERRIDE       0x10
/*
 * This flag tells Zebra that the route is a EVPN route and should
 * be treated specially
 */
#define ZEBRA_FLAG_EVPN_ROUTE         0x20
/*
 * This flag tells Zebra that it should treat the distance passed
 * down as an additional discriminator for route selection of the
 * route entry.  This mainly is used for backup static routes.
 */
#define ZEBRA_FLAG_RR_USE_DISTANCE    0x40
/*
 * This flag tells everyone that the route was intentionally
 * not offloaded and the route will be sent to the cpu for
 * forwarding.  This flag makes no sense unless you are in
 * an asic offload situation
 */
#define ZEBRA_FLAG_TRAPPED            0x80
/*
 * This flag tells everyone that the route has been
 * successfully offloaded to an asic for forwarding.
 * This flag makes no sense unless you are in an asic
 * offload situation.
 */
#define ZEBRA_FLAG_OFFLOADED          0x100
/*
 * This flag tells everyone that the route has
 * failed offloading.
 * This flag makes no sense unless you are in an asic
 * offload situation.
 */
#define ZEBRA_FLAG_OFFLOAD_FAILED     0x200

/*
 * This flag lets us know that we think the route entry
 * received has caused us to be out of sync with the
 * kernel (NLM_F_APPEND at the very least )
 */
#define ZEBRA_FLAG_OUTOFSYNC          0x400

	/* The older XXX_MESSAGE flags live here */
	uint32_t message;

	/*
	 * This is an enum but we are going to treat it as a uint8_t
	 * for purpose of encoding/decoding
	 */
	safi_t safi;

	struct prefix prefix;
	struct prefix_ipv6 src_prefix;

	uint16_t nexthop_num;
	struct zapi_nexthop nexthops[MULTIPATH_NUM];

	/* Support backup routes for IP FRR, TI-LFA, traffic engineering */
	uint16_t backup_nexthop_num;
	struct zapi_nexthop backup_nexthops[MULTIPATH_NUM];

	uint32_t nhgid;

	uint8_t distance;

	uint32_t metric;

	route_tag_t tag;

	uint32_t mtu;

	vrf_id_t vrf_id;

	uint32_t tableid;

	/* SR-TE color (used for nexthop updates only). */
	uint32_t srte_color;

#define ZAPI_MESSAGE_OPAQUE_LENGTH 1024
	struct {
		uint16_t length;
		uint8_t data[ZAPI_MESSAGE_OPAQUE_LENGTH];
	} opaque;
};

extern char *zclient_dump_route_flags(uint32_t flags, char *buf, size_t len);

struct zapi_labels {
	uint8_t message;
#define ZAPI_LABELS_FTN           0x01
#define ZAPI_LABELS_HAS_BACKUPS   0x02
	enum lsp_types_t type;
	mpls_label_t local_label;
	struct {
		struct prefix prefix;
		uint8_t type;
		unsigned short instance;
	} route;

	uint16_t nexthop_num;
	struct zapi_nexthop nexthops[MULTIPATH_NUM];

	/* Backup nexthops, if present */
	uint16_t backup_nexthop_num;
	struct zapi_nexthop backup_nexthops[MULTIPATH_NUM];
};

struct zapi_srte_tunnel {
	enum lsp_types_t type;
	mpls_label_t local_label;
	uint8_t label_num;
	mpls_label_t labels[MPLS_MAX_LABELS];
};

struct zapi_sr_policy {
	uint32_t color;
	struct ipaddr endpoint;
	char name[SRTE_POLICY_NAME_MAX_LENGTH];
	struct zapi_srte_tunnel segment_list;
	int status;
};

struct zapi_pw {
	char ifname[IFNAMSIZ];
	ifindex_t ifindex;
	int type;
	int af;
	union g_addr nexthop;
	uint32_t local_label;
	uint32_t remote_label;
	uint8_t flags;
	union pw_protocol_fields data;
	uint8_t protocol;
};

struct zapi_pw_status {
	char ifname[IFNAMSIZ];
	ifindex_t ifindex;
	uint32_t status;
};

/* IGP instance data associated to a RLFA. */
struct zapi_rlfa_igp {
	vrf_id_t vrf_id;
	int protocol;
	union {
		struct {
			char area_tag[32];
			struct {
				int tree_id;
				int level;
				unsigned int run_id;
			} spf;
		} isis;
	};
};

/* IGP -> LDP RLFA (un)registration message. */
struct zapi_rlfa_request {
	/* IGP instance data. */
	struct zapi_rlfa_igp igp;

	/* Destination prefix. */
	struct prefix destination;

	/* PQ node address. */
	struct in_addr pq_address;
};

/* LDP -> IGP RLFA label update. */
struct zapi_rlfa_response {
	/* IGP instance data. */
	struct zapi_rlfa_igp igp;

	/* Destination prefix. */
	struct prefix destination;

	/* Resolved LDP labels. */
	mpls_label_t pq_label;
	uint16_t nexthop_num;
	struct {
		int family;
		union g_addr gate;
		mpls_label_t label;
	} nexthops[MULTIPATH_NUM];
};

enum zapi_route_notify_owner {
	ZAPI_ROUTE_FAIL_INSTALL,
	ZAPI_ROUTE_BETTER_ADMIN_WON,
	ZAPI_ROUTE_INSTALLED,
	ZAPI_ROUTE_REMOVED,
	ZAPI_ROUTE_REMOVE_FAIL,
};

enum zapi_nhg_notify_owner {
	ZAPI_NHG_FAIL_INSTALL,
	ZAPI_NHG_INSTALLED,
	ZAPI_NHG_REMOVED,
	ZAPI_NHG_REMOVE_FAIL,
};

enum zapi_rule_notify_owner {
	ZAPI_RULE_FAIL_INSTALL,
	ZAPI_RULE_INSTALLED,
	ZAPI_RULE_REMOVED,
	ZAPI_RULE_FAIL_REMOVE,
};

enum ipset_type {
	IPSET_NET_NET = 1,
	IPSET_NET_PORT_NET,
	IPSET_NET_PORT,
	IPSET_NET
};

enum zapi_ipset_notify_owner {
	ZAPI_IPSET_FAIL_INSTALL = 0,
	ZAPI_IPSET_INSTALLED,
	ZAPI_IPSET_REMOVED,
	ZAPI_IPSET_FAIL_REMOVE,
};

enum zapi_ipset_entry_notify_owner {
	ZAPI_IPSET_ENTRY_FAIL_INSTALL = 0,
	ZAPI_IPSET_ENTRY_INSTALLED,
	ZAPI_IPSET_ENTRY_REMOVED,
	ZAPI_IPSET_ENTRY_FAIL_REMOVE,
};

enum zapi_iptable_notify_owner {
	ZAPI_IPTABLE_FAIL_INSTALL = 0,
	ZAPI_IPTABLE_INSTALLED,
	ZAPI_IPTABLE_REMOVED,
	ZAPI_IPTABLE_FAIL_REMOVE,
};

enum zapi_srv6_sid_notify {
	ZAPI_SRV6_SID_FAIL_ALLOC = 0,
	ZAPI_SRV6_SID_ALLOCATED,
	ZAPI_SRV6_SID_RELEASED,
	ZAPI_SRV6_SID_FAIL_RELEASE,
};

enum zclient_send_status {
	ZCLIENT_SEND_FAILURE = -1,
	ZCLIENT_SEND_SUCCESS = 0,
	ZCLIENT_SEND_BUFFERED = 1
};

static inline const char *
zapi_nhg_notify_owner2str(enum zapi_nhg_notify_owner note)
{
	switch (note) {
	case ZAPI_NHG_FAIL_INSTALL:
		return "ZAPI_NHG_FAIL_INSTALL";
	case ZAPI_NHG_INSTALLED:
		return "ZAPI_NHG_INSTALLED";
	case ZAPI_NHG_REMOVE_FAIL:
		return "ZAPI_NHG_REMOVE_FAIL";
	case ZAPI_NHG_REMOVED:
		return "ZAPI_NHG_REMOVED";
	}

	return "UNKNOWN";
}

static inline const char *
zapi_rule_notify_owner2str(enum zapi_rule_notify_owner note)
{
	switch (note) {
	case ZAPI_RULE_FAIL_INSTALL:
		return "ZAPI_RULE_FAIL_INSTALL";
	case ZAPI_RULE_INSTALLED:
		return "ZAPI_RULE_INSTALLED";
	case ZAPI_RULE_FAIL_REMOVE:
		return "ZAPI_RULE_FAIL_REMOVE";
	case ZAPI_RULE_REMOVED:
		return "ZAPI_RULE_REMOVED";
	}

	return "UNKNOWN";
}

static inline const char *zapi_srv6_sid_notify2str(enum zapi_srv6_sid_notify note)
{
	switch (note) {
	case ZAPI_SRV6_SID_FAIL_ALLOC:
		return "ZAPI_SRV6_SID_FAIL_ALLOC";
	case ZAPI_SRV6_SID_ALLOCATED:
		return "ZAPI_SRV6_SID_ALLOCATED";
	case ZAPI_SRV6_SID_FAIL_RELEASE:
		return "ZAPI_SRV6_SID_FAIL_RELEASE";
	case ZAPI_SRV6_SID_RELEASED:
		return "ZAPI_SRV6_SID_RELEASED";
	}

	return "UNKNOWN";
}

/* Zebra MAC types */
#define ZEBRA_MACIP_TYPE_STICKY                0x01 /* Sticky MAC*/
#define ZEBRA_MACIP_TYPE_GW                    0x02 /* gateway (SVI) mac*/
#define ZEBRA_MACIP_TYPE_ROUTER_FLAG           0x04 /* Router Flag - proxy NA */
#define ZEBRA_MACIP_TYPE_OVERRIDE_FLAG         0x08 /* Override Flag */
#define ZEBRA_MACIP_TYPE_SVI_IP                0x10 /* SVI MAC-IP */
#define ZEBRA_MACIP_TYPE_PROXY_ADVERT          0x20 /* Not locally active */
#define ZEBRA_MACIP_TYPE_SYNC_PATH             0x40 /* sync path */
/* XXX - flags is an u8; that needs to be changed to u32 if you need
 * to allocate past 0x80.  Additionally touch zclient_evpn_dump_macip_flags
 */
#define MACIP_BUF_SIZE 128
extern char *zclient_evpn_dump_macip_flags(uint8_t flags, char *buf,
					   size_t len);

/* Zebra ES VTEP flags (ZEBRA_REMOTE_ES_VTEP_ADD) */
/* ESR has been rxed from the VTEP. Only VTEPs that have advertised the
 * Type-4 route can participate in DF election.
 */
#define ZAPI_ES_VTEP_FLAG_ESR_RXED (1 << 0)

enum zebra_neigh_state { ZEBRA_NEIGH_INACTIVE = 0, ZEBRA_NEIGH_ACTIVE = 1 };

struct zclient_options {
	bool synchronous;

	/* auxiliary = don't call common lib/ handlers that manage bits.
	 * Those should only run once, on the "main" zclient, which this is
	 * not.  (This is also set for synchronous clients.)
	 */
	bool auxiliary;
};

extern const struct zclient_options zclient_options_default;
extern const struct zclient_options zclient_options_sync;
extern const struct zclient_options zclient_options_auxiliary;

/* link layer representation for GRE like interfaces
 * ip_in is the underlay IP, ip_out is the tunnel dest
 * index stands for the index of the interface
 * ndm state stands for the NDM value in netlink
 * (see linux/neighbour.h)
 */
#define ZEBRA_NEIGH_STATE_INCOMPLETE (0x01)
#define ZEBRA_NEIGH_STATE_REACHABLE (0x02)
#define ZEBRA_NEIGH_STATE_STALE (0x04)
#define ZEBRA_NEIGH_STATE_DELAY (0x08)
#define ZEBRA_NEIGH_STATE_PROBE (0x10)
#define ZEBRA_NEIGH_STATE_FAILED (0x20)
#define ZEBRA_NEIGH_STATE_NOARP (0x40)
#define ZEBRA_NEIGH_STATE_PERMANENT (0x80)
#define ZEBRA_NEIGH_STATE_NONE (0x00)

struct zapi_neigh_ip {
	int cmd;
	int ip_len;
	struct ipaddr ip_in;
	struct ipaddr ip_out;
	ifindex_t index;
	uint32_t ndm_state;
};
int zclient_neigh_ip_decode(struct stream *s, struct zapi_neigh_ip *api);
int zclient_neigh_ip_encode(struct stream *s, uint16_t cmd, union sockunion *in,
			    union sockunion *out, struct interface *ifp,
			    int ndm_state, int ip_len);

/*
 * We reserve the top 4 bits for l2-NHG, everything else
 * is for zebra/proto l3-NHG.
 *
 * Each client is going to get it's own nexthop group space
 * and we'll separate them, we'll figure out where to start based upon
 * the route_types.h
 */
#define ZEBRA_NHG_PROTO_UPPER                                                  \
	((uint32_t)250000000) /* Bottom 28 bits then rounded down */
#define ZEBRA_NHG_PROTO_SPACING (ZEBRA_NHG_PROTO_UPPER / ZEBRA_ROUTE_MAX)
#define ZEBRA_NHG_PROTO_LOWER                                                  \
	(ZEBRA_NHG_PROTO_SPACING * (ZEBRA_ROUTE_LOCAL + 1))

extern uint32_t zclient_get_nhg_start(uint32_t proto);

extern struct zclient *zclient_new(struct event_loop *m,
				   const struct zclient_options *opt,
				   zclient_handler *const *handlers,
				   size_t n_handlers);

extern void zclient_init(struct zclient *, int, unsigned short,
			 struct zebra_privs_t *privs);
extern int zclient_start(struct zclient *);
extern void zclient_stop(struct zclient *);
extern void zclient_reset(struct zclient *);
extern void zclient_free(struct zclient *);

extern int zclient_socket_connect(struct zclient *);

extern unsigned short *redist_check_instance(struct redist_proto *,
					     unsigned short);
extern void redist_add_instance(struct redist_proto *, unsigned short);
extern void redist_del_instance(struct redist_proto *, unsigned short);
extern void redist_del_all_instances(struct redist_proto *red);

/*
 * Send to zebra that the specified vrf is using label to resolve
 * itself for L3VPN's.  Repeated calls of this function with
 * different labels will cause an effective update of the
 * label for lookup.  If you pass in MPLS_LABEL_NONE
 * we will cause a delete action and remove this label pop
 * operation.
 *
 * The underlying AF_MPLS doesn't care about afi's
 * but we can make the zebra_vrf keep track of what
 * we have installed and play some special games
 * to get them both installed.
 */
extern enum zclient_send_status
zclient_send_vrf_label(struct zclient *zclient, vrf_id_t vrf_id, afi_t afi,
		       mpls_label_t label, enum lsp_types_t ltype);

extern enum zclient_send_status
zclient_send_localsid(struct zclient *zclient, const struct in6_addr *sid,
		      vrf_id_t vrf_id, enum seg6local_action_t action,
		      const struct seg6local_context *context);

extern void zclient_send_reg_requests(struct zclient *, vrf_id_t);
extern void zclient_send_dereg_requests(struct zclient *, vrf_id_t);
extern enum zclient_send_status
zclient_send_router_id_update(struct zclient *zclient,
			      zebra_message_types_t type, afi_t afi,
			      vrf_id_t vrf_id);

extern enum zclient_send_status
zclient_send_interface_radv_req(struct zclient *zclient, vrf_id_t vrf_id,
				struct interface *ifp, int enable,
				uint32_t ra_interval);
extern enum zclient_send_status
zclient_send_interface_protodown(struct zclient *zclient, vrf_id_t vrf_id,
				 struct interface *ifp, bool down);

/* Send redistribute command to zebra daemon. Do not update zclient state. */
extern enum zclient_send_status
zebra_redistribute_send(int command, struct zclient *, afi_t, int type,
			unsigned short instance, vrf_id_t vrf_id);

extern enum zclient_send_status
zebra_redistribute_default_send(int command, struct zclient *zclient, afi_t afi,
				vrf_id_t vrf_id);

/* Send route notify request to zebra */
extern int zebra_route_notify_send(int command, struct zclient *zclient,
				   bool set);

/* If state has changed, update state and call zebra_redistribute_send. */
extern void zclient_redistribute(int command, struct zclient *, afi_t, int type,
				 unsigned short instance, vrf_id_t vrf_id);

/* If state has changed, update state and send the command to zebra. */
extern void zclient_redistribute_default(int command, struct zclient *,
					 afi_t, vrf_id_t vrf_id);

/*
 * Send the message in zclient->obuf to the zebra daemon (or enqueue it).
 * Returns:
 * -1 on a I/O error
 *  0 data was successfully sent
 *  1 data was buffered for future usage
 */
extern enum zclient_send_status zclient_send_message(struct zclient *);

/* create header for command, length to be filled in by user later */
extern void zclient_create_header(struct stream *, uint16_t, vrf_id_t);
/*
 * Read sizeof(struct zmsghdr) bytes from the provided socket and parse the
 * received data into the specified fields. If this is successful, read the
 * rest of the packet into the provided stream.
 *
 * s
 *    The stream to read into
 *
 * sock
 *    The socket to read from
 *
 * size
 *    Parsed message size will be placed in the pointed-at integer
 *
 * marker
 *    Parsed marker will be placed in the pointed-at byte
 *
 * version
 *    Parsed version will be placed in the pointed-at byte
 *
 * vrf_id
 *    Parsed VRF ID will be placed in the pointed-at vrf_id_t
 *
 * cmd
 *    Parsed command number will be placed in the pointed-at integer
 *
 * Returns:
 *    -1 if:
 *    - insufficient data for header was read
 *    - a version mismatch was detected
 *    - a marker mismatch was detected
 *    - header size field specified more data than could be read
 */
extern int zclient_read_header(struct stream *s, int sock, uint16_t *size,
			       uint8_t *marker, uint8_t *version,
			       vrf_id_t *vrf_id, uint16_t *cmd);
/*
 * Parse header from ZAPI message stream into struct zmsghdr.
 * This function assumes the stream getp points at the first byte of the header.
 * If the function is successful then the stream getp will point to the byte
 * immediately after the last byte of the header.
 *
 * zmsg
 *    The stream containing the header
 *
 * hdr
 *    The header struct to parse into.
 *
 * Returns:
 *    true if parsing succeeded, false otherwise
 */
extern bool zapi_parse_header(struct stream *zmsg, struct zmsghdr *hdr);

extern enum zclient_send_status zclient_interface_set_arp(struct zclient *client,
							  struct interface *ifp,
							  bool arp_enable);
extern enum zclient_send_status
zclient_interface_set_master(struct zclient *client, struct interface *master,
			     struct interface *slave);
extern struct interface *zebra_interface_state_read(struct stream *s, vrf_id_t);
extern struct connected *zebra_interface_address_read(int, struct stream *,
						      vrf_id_t);
extern struct nbr_connected *
zebra_interface_nbr_address_read(int, struct stream *, vrf_id_t);
extern int zebra_router_id_update_read(struct stream *s, struct prefix *rid);

extern struct interface *zebra_interface_link_params_read(struct stream *s,
							  vrf_id_t vrf_id,
							  bool *changed);
extern size_t zebra_interface_link_params_write(struct stream *,
						struct interface *);

extern int zapi_srv6_locator_sid_encode(struct stream *s, struct srv6_locator *loc);
extern enum zclient_send_status
zclient_send_get_label_chunk(struct zclient *zclient, uint8_t keep,
			     uint32_t chunk_size, uint32_t base);

extern int lm_label_manager_connect(struct zclient *zclient, int async);
extern int lm_get_label_chunk(struct zclient *zclient, uint8_t keep,
			      uint32_t base, uint32_t chunk_size,
			      uint32_t *start, uint32_t *end);
extern int lm_release_label_chunk(struct zclient *zclient, uint32_t start,
				  uint32_t end);
extern int tm_table_manager_connect(struct zclient *zclient);
extern int tm_get_table_chunk(struct zclient *zclient, uint32_t chunk_size,
			      uint32_t *start, uint32_t *end);
extern int tm_release_table_chunk(struct zclient *zclient, uint32_t start,
				  uint32_t end);

/* Zebra SRv6 Manager flags */
#define ZAPI_SRV6_MANAGER_SID_FLAG_HAS_SID_VALUE 0x01
#define ZAPI_SRV6_MANAGER_SID_FLAG_HAS_LOCATOR	 0x02

extern int srv6_manager_get_locator_chunk(struct zclient *zclient,
					  const char *locator_name);
extern int srv6_manager_release_locator_chunk(struct zclient *zclient,
					      const char *locator_name);
extern int srv6_manager_get_locator(struct zclient *zclient,
				    const char *locator_name);
extern int srv6_manager_get_sid(struct zclient *zclient,
				const struct srv6_sid_ctx *ctx,
				struct in6_addr *sid_value,
				const char *locator_name, uint32_t *sid_func);
extern int srv6_manager_release_sid(struct zclient *zclient,
				    const struct srv6_sid_ctx *ctx);

extern enum zclient_send_status zebra_send_sr_policy(struct zclient *zclient,
						     int cmd,
						     struct zapi_sr_policy *zp);
extern int zapi_sr_policy_encode(struct stream *s, int cmd,
				 struct zapi_sr_policy *zp);
extern int zapi_sr_policy_decode(struct stream *s, struct zapi_sr_policy *zp);
extern int zapi_sr_policy_notify_status_decode(struct stream *s,
					       struct zapi_sr_policy *zp);

extern enum zclient_send_status zebra_send_mpls_labels(struct zclient *zclient,
						       int cmd,
						       struct zapi_labels *zl);
extern int zapi_labels_encode(struct stream *s, int cmd,
			      struct zapi_labels *zl);
extern int zapi_labels_decode(struct stream *s, struct zapi_labels *zl);

extern int zapi_srv6_locator_encode(struct stream *s,
				    const struct srv6_locator *l);
extern int zapi_srv6_locator_decode(struct stream *s, struct srv6_locator *l);
extern int zapi_srv6_locator_chunk_encode(struct stream *s,
					  const struct srv6_locator_chunk *c);
extern int zapi_srv6_locator_chunk_decode(struct stream *s,
					  struct srv6_locator_chunk *c);

extern enum zclient_send_status zebra_send_pw(struct zclient *zclient,
					      int command, struct zapi_pw *pw);
extern int zebra_read_pw_status_update(ZAPI_CALLBACK_ARGS,
				       struct zapi_pw_status *pw);

extern enum zclient_send_status zclient_route_send(uint8_t, struct zclient *,
						   struct zapi_route *);
extern enum zclient_send_status
zclient_send_rnh(struct zclient *zclient, int command, const struct prefix *p,
		 safi_t safi, bool connected, bool resolve_via_default,
		 vrf_id_t vrf_id);
int zapi_nexthop_encode(struct stream *s, const struct zapi_nexthop *api_nh,
			uint32_t api_flags, uint32_t api_message);
extern int zapi_route_encode(uint8_t, struct stream *, struct zapi_route *);
extern int zapi_route_decode(struct stream *s, struct zapi_route *api);
extern int zapi_nexthop_decode(struct stream *s, struct zapi_nexthop *api_nh,
			       uint32_t api_flags, uint32_t api_message);
bool zapi_nhg_notify_decode(struct stream *s, uint32_t *id,
			    enum zapi_nhg_notify_owner *note);
bool zapi_route_notify_decode(struct stream *s, struct prefix *p,
			      uint32_t *tableid,
			      enum zapi_route_notify_owner *note,
			      afi_t *afi, safi_t *safi);
bool zapi_rule_notify_decode(struct stream *s, uint32_t *seqno,
			     uint32_t *priority, uint32_t *unique, char *ifname,
			     enum zapi_rule_notify_owner *note);
bool zapi_ipset_notify_decode(struct stream *s,
			      uint32_t *unique,
			     enum zapi_ipset_notify_owner *note);
bool zapi_srv6_sid_notify_decode(struct stream *s, struct srv6_sid_ctx *ctx,
				 struct in6_addr *sid_value, uint32_t *func,
				 uint32_t *wide_func,
				 enum zapi_srv6_sid_notify *note,
				 char **locator_name);

/* Nexthop-group message apis */
extern enum zclient_send_status
zclient_nhg_send(struct zclient *zclient, int cmd, struct zapi_nhg *api_nhg);

#define ZEBRA_IPSET_NAME_SIZE   32

bool zapi_ipset_entry_notify_decode(struct stream *s,
	    uint32_t *unique,
	    char *ipset_name,
	    enum zapi_ipset_entry_notify_owner *note);
bool zapi_iptable_notify_decode(struct stream *s,
		uint32_t *unique,
		enum zapi_iptable_notify_owner *note);

extern struct nexthop *
nexthop_from_zapi_nexthop(const struct zapi_nexthop *znh);
int zapi_nexthop_from_nexthop(struct zapi_nexthop *znh,
			      const struct nexthop *nh);
int zapi_backup_nexthop_from_nexthop(struct zapi_nexthop *znh,
				     const struct nexthop *nh);
const char *zapi_nexthop2str(const struct zapi_nexthop *znh, char *buf,
			     int bufsize);

/* Decode the zebra error message */
extern bool zapi_error_decode(struct stream *s, enum zebra_error_types *error);

/* Encode and decode restart capabilities */
extern enum zclient_send_status
zclient_capabilities_send(uint32_t cmd, struct zclient *zclient,
			  struct zapi_cap *api);
extern int32_t zapi_capabilities_decode(struct stream *s, struct zapi_cap *api);

static inline void zapi_route_set_blackhole(struct zapi_route *api,
					    enum blackhole_type bh_type)
{
	api->nexthop_num = 1;
	api->nexthops[0].type = NEXTHOP_TYPE_BLACKHOLE;
	api->nexthops[0].vrf_id = VRF_DEFAULT;
	api->nexthops[0].bh_type = bh_type;
	SET_FLAG(api->message, ZAPI_MESSAGE_NEXTHOP);
};

static inline void zapi_route_set_nhg_id(struct zapi_route *api,
					 uint32_t *nhg_id)
{
	api->nexthop_num = 0;
	api->nhgid = *nhg_id;
	if (api->nhgid)
		SET_FLAG(api->message, ZAPI_MESSAGE_NHG);
};

extern enum zclient_send_status
zclient_send_mlag_register(struct zclient *client, uint32_t bit_map);
extern enum zclient_send_status
zclient_send_mlag_deregister(struct zclient *client);

extern enum zclient_send_status zclient_send_mlag_data(struct zclient *client,
						       struct stream *client_s);

/*
 * Send an OPAQUE message, contents opaque to zebra - but note that
 * the length of the payload is restricted by the zclient's
 * outgoing message buffer.
 * The message header is a message subtype; please use the registry
 * below to avoid sub-type collisions. Clients use the registration
 * apis to manage the specific opaque subtypes they want to receive.
 */
enum zclient_send_status zclient_send_opaque(struct zclient *zclient,
					     uint32_t type, const uint8_t *data,
					     size_t datasize);

enum zclient_send_status
zclient_send_opaque_unicast(struct zclient *zclient, uint32_t type,
			    uint8_t proto, uint16_t instance,
			    uint32_t session_id, const uint8_t *data,
			    size_t datasize);

/* Init functions also provided for clients who want to encode their
 * data inline into the zclient's stream buffer. Please use these instead
 * of hand-encoding the header info, since that may change over time.
 * Note that these will reset the zclient's outbound stream before encoding.
 */
enum zclient_send_status zapi_opaque_init(struct zclient *zclient,
					  uint32_t type, uint16_t flags);

enum zclient_send_status
zapi_opaque_unicast_init(struct zclient *zclient, uint32_t type, uint16_t flags,
			 uint8_t proto, uint16_t instance, uint32_t session_id);

/* Struct representing the decoded opaque header info */
struct zapi_opaque_msg {
	uint32_t type; /* Subtype */
	uint16_t len;  /* len after zapi header and this info */
	uint16_t flags;

	/* Sending client info */
	uint8_t src_proto;
	uint16_t src_instance;
	uint32_t src_session_id;

	/* Destination client info - *if* UNICAST flag is set */
	uint8_t dest_proto;
	uint16_t dest_instance;
	uint32_t dest_session_id;
};

#define ZAPI_OPAQUE_FLAG_UNICAST   0x01

/* Simple struct to convey registration/unreg requests */
struct zapi_opaque_reg_info {
	/* Message subtype */
	uint32_t type;

	/* Client session tuple */
	uint8_t proto;
	uint16_t instance;
	uint32_t session_id;
};

/* Simple struct conveying information about opaque notifications.
 * Daemons can request notifications about the status of registration for
 * opaque message types. For example, a client daemon can request notification
 * when a server registers to receive a certain message code. Or a server can
 * request notification when a subscriber registers for its output.
 */
struct zapi_opaque_notif_info {
	bool request;	   /* Request to register, or notification from zebra */
	bool reg;	   /* Register or unregister */
	uint32_t msg_type; /* Target message code */

	/* For notif registration, zapi info for the client.
	 * For notifications, zapi info for the message's server/registrant.
	 * For notification that there is no server/registrant, not present.
	 */
	uint8_t proto;
	uint16_t instance;
	uint32_t session_id;
};

/* The same ZAPI message is used for daemon->zebra requests, and for
 * zebra->daemon notifications.
 * Daemons send 'request' true, and 'reg' true or false.
 * Zebra sends 'request' false, 'reg' set if the notification is a
 * server/receiver registration for the message type, and false if the event
 * is the end of registrations.
 */

/* Decode incoming opaque */
int zclient_opaque_decode(struct stream *msg, struct zapi_opaque_msg *info);

enum zclient_send_status zclient_register_opaque(struct zclient *zclient,
						 uint32_t type);
enum zclient_send_status zclient_unregister_opaque(struct zclient *zclient,
						   uint32_t type);
int zapi_opaque_reg_decode(struct stream *msg,
			   struct zapi_opaque_reg_info *info);

/* Opaque notification features */
enum zclient_send_status zclient_opaque_request_notify(struct zclient *zclient,
						       uint32_t msgtype);
enum zclient_send_status zclient_opaque_drop_notify(struct zclient *zclient,
						    uint32_t msgtype);

/* Encode, decode an incoming zapi opaque notification */
int zclient_opaque_notif_encode(struct stream *s, uint32_t msg_type,
				bool reg /* register or unreg*/, uint8_t proto,
				uint16_t instance, uint32_t session_id);
int zclient_opaque_notif_decode(struct stream *s,
				struct zapi_opaque_notif_info *info);

/*
 * Registry of opaque message types. Please do not reuse an in-use
 * type code; some daemons are likely relying on it.
 */
enum zapi_opaque_registry {
	/* Request link-state database dump, at restart for example */
	LINK_STATE_SYNC = 1,
	/* Update containing link-state db info */
	LINK_STATE_UPDATE = 2,
	/* Request LDP-SYNC state from LDP */
	LDP_IGP_SYNC_IF_STATE_REQUEST = 3,
	/* Update containing LDP IGP Sync State info */
	LDP_IGP_SYNC_IF_STATE_UPDATE = 4,
	/* Announce that LDP is up  */
	LDP_IGP_SYNC_ANNOUNCE_UPDATE = 5,
	/* Register RLFA with LDP */
	LDP_RLFA_REGISTER = 7,
	/* Unregister all RLFAs with LDP */
	LDP_RLFA_UNREGISTER_ALL = 8,
	/* Announce LDP labels associated to a previously registered RLFA */
	LDP_RLFA_LABELS = 9,
};

/* Send the hello message.
 * Returns 0 for success or -1 on an I/O error.
 */
extern enum zclient_send_status zclient_send_hello(struct zclient *client);

extern void zclient_register_neigh(struct zclient *zclient, vrf_id_t vrf_id,
				   afi_t afi, bool reg);

extern enum zclient_send_status
zclient_send_neigh_discovery_req(struct zclient *zclient,
				 const struct interface *ifp,
				 const struct prefix *p);

struct zapi_client_close_info {
	/* Client session tuple */
	uint8_t proto;
	uint16_t instance;
	uint32_t session_id;
};

/* Decode incoming client close notify */
extern int zapi_client_close_notify_decode(struct stream *s,
					   struct zapi_client_close_info *info);

extern int zclient_send_zebra_gre_request(struct zclient *client,
					  struct interface *ifp);
#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_ZCLIENT_H */
