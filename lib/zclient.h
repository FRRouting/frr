/* Zebra's client header.
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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

#ifndef _ZEBRA_ZCLIENT_H
#define _ZEBRA_ZCLIENT_H

/* For struct zapi_route. */
#include "prefix.h"

/* For struct interface and struct connected. */
#include "if.h"

/* For vrf_bitmap_t. */
#include "vrf.h"

/* For union g_addr */
#include "nexthop.h"

/* For union pw_protocol_fields */
#include "pw.h"

#include "mlag.h"

/* Zebra types. Used in Zserv message header. */
typedef uint16_t zebra_size_t;

/* Marker value used in new Zserv, in the byte location corresponding
 * the command value in the old zserv header. To allow old and new
 * Zserv headers to be distinguished from each other.
 */
#define ZEBRA_HEADER_MARKER              254

/* For input/output buffer to zebra. */
#define ZEBRA_MAX_PACKET_SIZ          16384U

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

extern struct sockaddr_storage zclient_addr;
extern socklen_t zclient_addr_len;

/* Zebra message types. */
typedef enum {
	ZEBRA_INTERFACE_ADD,
	ZEBRA_INTERFACE_DELETE,
	ZEBRA_INTERFACE_ADDRESS_ADD,
	ZEBRA_INTERFACE_ADDRESS_DELETE,
	ZEBRA_INTERFACE_UP,
	ZEBRA_INTERFACE_DOWN,
	ZEBRA_INTERFACE_SET_MASTER,
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
	ZEBRA_IMPORT_ROUTE_REGISTER,
	ZEBRA_IMPORT_ROUTE_UNREGISTER,
	ZEBRA_IMPORT_CHECK_UPDATE,
	ZEBRA_BFD_DEST_REGISTER,
	ZEBRA_BFD_DEST_DEREGISTER,
	ZEBRA_BFD_DEST_UPDATE,
	ZEBRA_BFD_DEST_REPLAY,
	ZEBRA_REDISTRIBUTE_ROUTE_ADD,
	ZEBRA_REDISTRIBUTE_ROUTE_DEL,
	ZEBRA_VRF_UNREGISTER,
	ZEBRA_VRF_ADD,
	ZEBRA_VRF_DELETE,
	ZEBRA_VRF_LABEL,
	ZEBRA_INTERFACE_VRF_UPDATE,
	ZEBRA_BFD_CLIENT_REGISTER,
	ZEBRA_BFD_CLIENT_DEREGISTER,
	ZEBRA_INTERFACE_ENABLE_RADV,
	ZEBRA_INTERFACE_DISABLE_RADV,
	ZEBRA_IPV4_NEXTHOP_LOOKUP_MRIB,
	ZEBRA_INTERFACE_LINK_PARAMS,
	ZEBRA_MPLS_LABELS_ADD,
	ZEBRA_MPLS_LABELS_DELETE,
	ZEBRA_MPLS_LABELS_REPLACE,
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
} zebra_message_types_t;

struct redist_proto {
	uint8_t enabled;
	struct list *instances;
};

struct zclient_capabilities {
	uint32_t ecmp;
	bool mpls_enabled;
	enum mlag_role role;
};

/* Structure for the zebra client. */
struct zclient {
	/* The thread master we schedule ourselves on */
	struct thread_master *master;

	/* Priviledges to change socket values */
	struct zebra_privs_t *privs;

	/* Do we care about failure events for route install? */
	bool receive_notify;

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
	struct thread *t_read;
	struct thread *t_connect;

	/* Thread to write buffered data to zebra. */
	struct thread *t_write;

	/* Redistribute information. */
	uint8_t redist_default; /* clients protocol */
	unsigned short instance;
	struct redist_proto mi_redist[AFI_MAX][ZEBRA_ROUTE_MAX];
	vrf_bitmap_t redist[AFI_MAX][ZEBRA_ROUTE_MAX];

	/* Redistribute defauilt. */
	vrf_bitmap_t default_information[AFI_MAX];

#define ZAPI_CALLBACK_ARGS                                                     \
	int cmd, struct zclient *zclient, uint16_t length, vrf_id_t vrf_id

	/* Pointer to the callback functions. */
	void (*zebra_connected)(struct zclient *);
	void (*zebra_capabilities)(struct zclient_capabilities *cap);
	int (*router_id_update)(ZAPI_CALLBACK_ARGS);
	int (*interface_address_add)(ZAPI_CALLBACK_ARGS);
	int (*interface_address_delete)(ZAPI_CALLBACK_ARGS);
	int (*interface_link_params)(ZAPI_CALLBACK_ARGS);
	int (*interface_bfd_dest_update)(ZAPI_CALLBACK_ARGS);
	int (*interface_nbr_address_add)(ZAPI_CALLBACK_ARGS);
	int (*interface_nbr_address_delete)(ZAPI_CALLBACK_ARGS);
	int (*interface_vrf_update)(ZAPI_CALLBACK_ARGS);
	int (*nexthop_update)(ZAPI_CALLBACK_ARGS);
	int (*import_check_update)(ZAPI_CALLBACK_ARGS);
	int (*bfd_dest_replay)(ZAPI_CALLBACK_ARGS);
	int (*redistribute_route_add)(ZAPI_CALLBACK_ARGS);
	int (*redistribute_route_del)(ZAPI_CALLBACK_ARGS);
	int (*fec_update)(int, struct zclient *, uint16_t);
	int (*local_es_add)(ZAPI_CALLBACK_ARGS);
	int (*local_es_del)(ZAPI_CALLBACK_ARGS);
	int (*local_vni_add)(ZAPI_CALLBACK_ARGS);
	int (*local_vni_del)(ZAPI_CALLBACK_ARGS);
	int (*local_l3vni_add)(ZAPI_CALLBACK_ARGS);
	int (*local_l3vni_del)(ZAPI_CALLBACK_ARGS);
	void (*local_ip_prefix_add)(ZAPI_CALLBACK_ARGS);
	void (*local_ip_prefix_del)(ZAPI_CALLBACK_ARGS);
	int (*local_macip_add)(ZAPI_CALLBACK_ARGS);
	int (*local_macip_del)(ZAPI_CALLBACK_ARGS);
	int (*pw_status_update)(ZAPI_CALLBACK_ARGS);
	int (*route_notify_owner)(ZAPI_CALLBACK_ARGS);
	int (*rule_notify_owner)(ZAPI_CALLBACK_ARGS);
	void (*label_chunk)(ZAPI_CALLBACK_ARGS);
	int (*ipset_notify_owner)(ZAPI_CALLBACK_ARGS);
	int (*ipset_entry_notify_owner)(ZAPI_CALLBACK_ARGS);
	int (*iptable_notify_owner)(ZAPI_CALLBACK_ARGS);
	int (*vxlan_sg_add)(ZAPI_CALLBACK_ARGS);
	int (*vxlan_sg_del)(ZAPI_CALLBACK_ARGS);
};

/* Zebra API message flag. */
#define ZAPI_MESSAGE_NEXTHOP  0x01
#define ZAPI_MESSAGE_DISTANCE 0x02
#define ZAPI_MESSAGE_METRIC   0x04
#define ZAPI_MESSAGE_TAG      0x08
#define ZAPI_MESSAGE_MTU      0x10
#define ZAPI_MESSAGE_SRCPFX   0x20
#define ZAPI_MESSAGE_LABEL    0x40
/*
 * This should only be used by a DAEMON that needs to communicate
 * the table being used is not in the VRF.  You must pass the
 * default vrf, else this will be ignored.
 */
#define ZAPI_MESSAGE_TABLEID  0x80

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

struct zapi_nexthop {
	enum nexthop_types_t type;
	vrf_id_t vrf_id;
	ifindex_t ifindex;
	bool onlink;
	union {
		union g_addr gate;
		enum blackhole_type bh_type;
	};

	/* MPLS labels for BGP-LU or Segment Routing */
	uint8_t label_num;
	mpls_label_t labels[MPLS_MAX_LABELS];

	struct ethaddr rmac;
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

	uint8_t message;

	/*
	 * This is an enum but we are going to treat it as a uint8_t
	 * for purpose of encoding/decoding
	 */
	safi_t safi;

	struct prefix prefix;
	struct prefix_ipv6 src_prefix;

	uint16_t nexthop_num;
	struct zapi_nexthop nexthops[MULTIPATH_NUM];

	uint8_t distance;

	uint32_t metric;

	route_tag_t tag;

	uint32_t mtu;

	vrf_id_t vrf_id;

	uint32_t tableid;
};

struct zapi_nexthop_label {
	enum nexthop_types_t type;
	int family;
	union g_addr address;
	ifindex_t ifindex;
	mpls_label_t label;
};

struct zapi_labels {
	uint8_t message;
#define ZAPI_LABELS_FTN      0x01
	enum lsp_types_t type;
	mpls_label_t local_label;
	struct {
		struct prefix prefix;
		uint8_t type;
		unsigned short instance;
	} route;
	uint16_t nexthop_num;
	struct zapi_nexthop_label nexthops[MULTIPATH_NUM];
};

struct zapi_pw {
	char ifname[IF_NAMESIZE];
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
	char ifname[IF_NAMESIZE];
	ifindex_t ifindex;
	uint32_t status;
};

enum zapi_route_notify_owner {
	ZAPI_ROUTE_FAIL_INSTALL,
	ZAPI_ROUTE_BETTER_ADMIN_WON,
	ZAPI_ROUTE_INSTALLED,
	ZAPI_ROUTE_REMOVED,
	ZAPI_ROUTE_REMOVE_FAIL,
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
	ZAPI_IPSET_FAIL_INSTALL,
	ZAPI_IPSET_INSTALLED,
	ZAPI_IPSET_REMOVED,
	ZAPI_IPSET_FAIL_REMOVE,
};

enum zapi_ipset_entry_notify_owner {
	ZAPI_IPSET_ENTRY_FAIL_INSTALL,
	ZAPI_IPSET_ENTRY_INSTALLED,
	ZAPI_IPSET_ENTRY_REMOVED,
	ZAPI_IPSET_ENTRY_FAIL_REMOVE,
};

enum zapi_iptable_notify_owner {
	ZAPI_IPTABLE_FAIL_INSTALL,
	ZAPI_IPTABLE_INSTALLED,
	ZAPI_IPTABLE_REMOVED,
	ZAPI_IPTABLE_FAIL_REMOVE,
};

/* Zebra MAC types */
#define ZEBRA_MACIP_TYPE_STICKY                0x01 /* Sticky MAC*/
#define ZEBRA_MACIP_TYPE_GW                    0x02 /* gateway (SVI) mac*/
#define ZEBRA_MACIP_TYPE_ROUTER_FLAG           0x04 /* Router Flag - proxy NA */
#define ZEBRA_MACIP_TYPE_OVERRIDE_FLAG         0x08 /* Override Flag */

enum zebra_neigh_state { ZEBRA_NEIGH_INACTIVE = 0, ZEBRA_NEIGH_ACTIVE = 1 };

struct zclient_options {
	bool receive_notify;
};

extern struct zclient_options zclient_options_default;

extern struct zclient *zclient_new(struct thread_master *m,
				   struct zclient_options *opt);

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
extern void zclient_send_vrf_label(struct zclient *zclient, vrf_id_t vrf_id,
				   afi_t afi, mpls_label_t label,
				   enum lsp_types_t ltype);

extern void zclient_send_reg_requests(struct zclient *, vrf_id_t);
extern void zclient_send_dereg_requests(struct zclient *, vrf_id_t);

extern void zclient_send_interface_radv_req(struct zclient *zclient,
					    vrf_id_t vrf_id,
					    struct interface *ifp, int enable,
					    int ra_interval);
extern int zclient_send_interface_protodown(struct zclient *zclient,
					    vrf_id_t vrf_id,
					    struct interface *ifp, bool down);

/* Send redistribute command to zebra daemon. Do not update zclient state. */
extern int zebra_redistribute_send(int command, struct zclient *, afi_t,
				   int type, unsigned short instance,
				   vrf_id_t vrf_id);

extern int zebra_redistribute_default_send(int command, struct zclient *zclient,
					   afi_t afi, vrf_id_t vrf_id);

/* If state has changed, update state and call zebra_redistribute_send. */
extern void zclient_redistribute(int command, struct zclient *, afi_t, int type,
				 unsigned short instance, vrf_id_t vrf_id);

/* If state has changed, update state and send the command to zebra. */
extern void zclient_redistribute_default(int command, struct zclient *,
					 afi_t, vrf_id_t vrf_id);

/* Send the message in zclient->obuf to the zebra daemon (or enqueue it).
   Returns 0 for success or -1 on an I/O error. */
extern int zclient_send_message(struct zclient *);

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

extern void zclient_interface_set_master(struct zclient *client,
					 struct interface *master,
					 struct interface *slave);
extern struct interface *zebra_interface_state_read(struct stream *s, vrf_id_t);
extern struct connected *zebra_interface_address_read(int, struct stream *,
						      vrf_id_t);
extern struct nbr_connected *
zebra_interface_nbr_address_read(int, struct stream *, vrf_id_t);
extern struct interface *zebra_interface_vrf_update_read(struct stream *s,
							 vrf_id_t vrf_id,
							 vrf_id_t *new_vrf_id);
extern void zebra_router_id_update_read(struct stream *s, struct prefix *rid);

extern struct interface *zebra_interface_link_params_read(struct stream *s,
							  vrf_id_t vrf_id);
extern size_t zebra_interface_link_params_write(struct stream *,
						struct interface *);
extern int zclient_send_get_label_chunk(struct zclient *zclient, uint8_t keep,
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

extern int zebra_send_mpls_labels(struct zclient *zclient, int cmd,
				  struct zapi_labels *zl);
extern int zapi_labels_encode(struct stream *s, int cmd,
			      struct zapi_labels *zl);
extern int zapi_labels_decode(struct stream *s, struct zapi_labels *zl);

extern int zebra_send_pw(struct zclient *zclient, int command,
			 struct zapi_pw *pw);
extern void zebra_read_pw_status_update(ZAPI_CALLBACK_ARGS, struct zapi_pw_status *pw);

extern int zclient_route_send(uint8_t, struct zclient *, struct zapi_route *);
extern int zclient_send_rnh(struct zclient *zclient, int command,
			    struct prefix *p, bool exact_match,
			    vrf_id_t vrf_id);
extern int zapi_route_encode(uint8_t, struct stream *, struct zapi_route *);
extern int zapi_route_decode(struct stream *, struct zapi_route *);
bool zapi_route_notify_decode(struct stream *s, struct prefix *p,
			      uint32_t *tableid,
			      enum zapi_route_notify_owner *note);
bool zapi_rule_notify_decode(struct stream *s, uint32_t *seqno,
			     uint32_t *priority, uint32_t *unique,
			     ifindex_t *ifindex,
			     enum zapi_rule_notify_owner *note);
bool zapi_ipset_notify_decode(struct stream *s,
			      uint32_t *unique,
			     enum zapi_ipset_notify_owner *note);

#define ZEBRA_IPSET_NAME_SIZE   32

bool zapi_ipset_entry_notify_decode(struct stream *s,
	    uint32_t *unique,
	    char *ipset_name,
	    enum zapi_ipset_entry_notify_owner *note);
bool zapi_iptable_notify_decode(struct stream *s,
		uint32_t *unique,
		enum zapi_iptable_notify_owner *note);

extern struct nexthop *nexthop_from_zapi_nexthop(struct zapi_nexthop *znh);
extern bool zapi_nexthop_update_decode(struct stream *s,
				       struct zapi_route *nhr);

static inline void zapi_route_set_blackhole(struct zapi_route *api,
					    enum blackhole_type bh_type)
{
	api->nexthop_num = 1;
	api->nexthops[0].type = NEXTHOP_TYPE_BLACKHOLE;
	api->nexthops[0].vrf_id = VRF_DEFAULT;
	api->nexthops[0].bh_type = bh_type;
	SET_FLAG(api->message, ZAPI_MESSAGE_NEXTHOP);
};


#endif /* _ZEBRA_ZCLIENT_H */
