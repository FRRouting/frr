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

/* For struct zapi_ipv{4,6}. */
#include "prefix.h"

/* For struct interface and struct connected. */
#include "if.h"

/* For vrf_bitmap_t. */
#include "vrf.h"

/* For input/output buffer to zebra. */
#define ZEBRA_MAX_PACKET_SIZ          4096

/* Zebra header size. */
#define ZEBRA_HEADER_SIZE             8

/* Zebra message types. */
typedef enum {
  ZEBRA_INTERFACE_ADD,
  ZEBRA_INTERFACE_DELETE,
  ZEBRA_INTERFACE_ADDRESS_ADD,
  ZEBRA_INTERFACE_ADDRESS_DELETE,
  ZEBRA_INTERFACE_UP,
  ZEBRA_INTERFACE_DOWN,
  ZEBRA_IPV4_ROUTE_ADD,
  ZEBRA_IPV4_ROUTE_DELETE,
  ZEBRA_IPV6_ROUTE_ADD,
  ZEBRA_IPV6_ROUTE_DELETE,
  ZEBRA_REDISTRIBUTE_ADD,
  ZEBRA_REDISTRIBUTE_DELETE,
  ZEBRA_REDISTRIBUTE_DEFAULT_ADD,
  ZEBRA_REDISTRIBUTE_DEFAULT_DELETE,
  ZEBRA_ROUTER_ID_ADD,
  ZEBRA_ROUTER_ID_DELETE,
  ZEBRA_ROUTER_ID_UPDATE,
  ZEBRA_HELLO,
  ZEBRA_NEXTHOP_REGISTER,
  ZEBRA_NEXTHOP_UNREGISTER,
  ZEBRA_NEXTHOP_UPDATE,
  ZEBRA_INTERFACE_NBR_ADDRESS_ADD,
  ZEBRA_INTERFACE_NBR_ADDRESS_DELETE,
  ZEBRA_INTERFACE_BFD_DEST_UPDATE,
  ZEBRA_IMPORT_ROUTE_REGISTER,
  ZEBRA_IMPORT_ROUTE_UNREGISTER,
  ZEBRA_IMPORT_CHECK_UPDATE,
  ZEBRA_IPV4_ROUTE_IPV6_NEXTHOP_ADD,
  ZEBRA_BFD_DEST_REGISTER,
  ZEBRA_BFD_DEST_DEREGISTER,
  ZEBRA_BFD_DEST_UPDATE,
  ZEBRA_BFD_DEST_REPLAY,
  ZEBRA_REDISTRIBUTE_IPV4_ADD,
  ZEBRA_REDISTRIBUTE_IPV4_DEL,
  ZEBRA_REDISTRIBUTE_IPV6_ADD,
  ZEBRA_REDISTRIBUTE_IPV6_DEL,
  ZEBRA_VRF_UNREGISTER,
  ZEBRA_VRF_ADD,
  ZEBRA_VRF_DELETE,
  ZEBRA_INTERFACE_VRF_UPDATE,
  ZEBRA_BFD_CLIENT_REGISTER,
  ZEBRA_INTERFACE_ENABLE_RADV,
  ZEBRA_INTERFACE_DISABLE_RADV,
  ZEBRA_IPV4_NEXTHOP_LOOKUP_MRIB,
  ZEBRA_INTERFACE_LINK_PARAMS,
  ZEBRA_MPLS_LABELS_ADD,
  ZEBRA_MPLS_LABELS_DELETE,
  ZEBRA_IPV4_NEXTHOP_ADD,
  ZEBRA_IPV4_NEXTHOP_DELETE,
  ZEBRA_IPV6_NEXTHOP_ADD,
  ZEBRA_IPV6_NEXTHOP_DELETE,
  ZEBRA_IPMR_ROUTE_STATS,
  ZEBRA_LABEL_MANAGER_CONNECT,
  ZEBRA_GET_LABEL_CHUNK,
  ZEBRA_RELEASE_LABEL_CHUNK,
  ZEBRA_FEC_REGISTER,
  ZEBRA_FEC_UNREGISTER,
  ZEBRA_FEC_UPDATE,
  ZEBRA_ADVERTISE_ALL_VNI,
  ZEBRA_VNI_ADD,
  ZEBRA_VNI_DEL,
  ZEBRA_REMOTE_VTEP_ADD,
  ZEBRA_REMOTE_VTEP_DEL,
  ZEBRA_MACIP_ADD,
  ZEBRA_MACIP_DEL,
  ZEBRA_REMOTE_MACIP_ADD,
  ZEBRA_REMOTE_MACIP_DEL,
} zebra_message_types_t;

struct redist_proto
{
  u_char enabled;
  struct list *instances;
};

/* Structure for the zebra client. */
struct zclient
{
  /* The thread master we schedule ourselves on */
  struct thread_master *master;

  /* Socket to zebra daemon. */
  int sock;

  /* Flag of communication to zebra is enabled or not.  Default is on.
     This flag is disabled by `no router zebra' statement. */
  int enable;

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
  u_char redist_default; /* clients protocol */
  u_short instance;
  struct redist_proto mi_redist[AFI_MAX][ZEBRA_ROUTE_MAX];
  vrf_bitmap_t redist[AFI_MAX][ZEBRA_ROUTE_MAX];

  /* Redistribute defauilt. */
  vrf_bitmap_t default_information;

  /* Pointer to the callback functions. */
  void (*zebra_connected) (struct zclient *);
  int (*router_id_update) (int, struct zclient *, uint16_t, vrf_id_t);
  int (*interface_add) (int, struct zclient *, uint16_t, vrf_id_t);
  int (*interface_delete) (int, struct zclient *, uint16_t, vrf_id_t);
  int (*interface_up) (int, struct zclient *, uint16_t, vrf_id_t);
  int (*interface_down) (int, struct zclient *, uint16_t, vrf_id_t);
  int (*interface_address_add) (int, struct zclient *, uint16_t, vrf_id_t);
  int (*interface_address_delete) (int, struct zclient *, uint16_t, vrf_id_t);
  int (*interface_link_params) (int, struct zclient *, uint16_t);
  int (*interface_bfd_dest_update) (int, struct zclient *, uint16_t, vrf_id_t);
  int (*interface_nbr_address_add) (int, struct zclient *, uint16_t, vrf_id_t);
  int (*interface_nbr_address_delete) (int, struct zclient *, uint16_t, vrf_id_t);
  int (*interface_vrf_update) (int, struct zclient *, uint16_t, vrf_id_t);
  int (*nexthop_update) (int, struct zclient *, uint16_t, vrf_id_t);
  int (*import_check_update) (int, struct zclient *, uint16_t, vrf_id_t);
  int (*bfd_dest_replay) (int, struct zclient *, uint16_t, vrf_id_t);
  int (*redistribute_route_ipv4_add) (int, struct zclient *, uint16_t, vrf_id_t);
  int (*redistribute_route_ipv4_del) (int, struct zclient *, uint16_t, vrf_id_t);
  int (*redistribute_route_ipv6_add) (int, struct zclient *, uint16_t, vrf_id_t);
  int (*redistribute_route_ipv6_del) (int, struct zclient *, uint16_t, vrf_id_t);
  int (*fec_update) (int, struct zclient *, uint16_t);
  int (*local_vni_add) (int, struct zclient *, uint16_t, vrf_id_t);
  int (*local_vni_del) (int, struct zclient *, uint16_t, vrf_id_t);
  int (*local_macip_add) (int, struct zclient *, uint16_t, vrf_id_t);
  int (*local_macip_del) (int, struct zclient *, uint16_t, vrf_id_t);
};

/* Zebra API message flag. */
#define ZAPI_MESSAGE_NEXTHOP  0x01
#define ZAPI_MESSAGE_IFINDEX  0x02
#define ZAPI_MESSAGE_DISTANCE 0x04
#define ZAPI_MESSAGE_METRIC   0x08
#define ZAPI_MESSAGE_TAG      0x10
#define ZAPI_MESSAGE_MTU      0x20
#define ZAPI_MESSAGE_SRCPFX   0x40
#define ZAPI_MESSAGE_LABEL    0x80

/* Zserv protocol message header */
struct zserv_header
{
  uint16_t length;
  uint8_t marker;	/* corresponds to command field in old zserv
                         * always set to 255 in new zserv.
                         */
  uint8_t version;
#define ZSERV_VERSION	4
  vrf_id_t vrf_id;
  uint16_t command;
};

struct zapi_route
{
  u_char type;
  u_short instance;

  u_int32_t flags;

  u_char message;

  safi_t safi;

  u_char nexthop_num;
  struct nexthop **nexthop;

  u_char distance;

  u_int32_t metric;

  route_tag_t tag;

  u_int32_t mtu;

  vrf_id_t vrf_id;
};

/* Zebra IPv4 route message API. */
struct zapi_ipv4
{
  u_char type;
  u_short instance;

  u_int32_t flags;

  u_char message;

  safi_t safi;

  u_char nexthop_num;
  struct in_addr **nexthop;

  u_char ifindex_num;
  ifindex_t *ifindex;

  u_char label_num;
  unsigned int *label;

  u_char distance;

  u_int32_t metric;

  route_tag_t tag;

  u_int32_t mtu;

  vrf_id_t vrf_id;
};

/* Prototypes of zebra client service functions. */
extern struct zclient *zclient_new (struct thread_master *);
extern void zclient_init (struct zclient *, int, u_short);
extern int zclient_start (struct zclient *);
extern void zclient_stop (struct zclient *);
extern void zclient_reset (struct zclient *);
extern void zclient_free (struct zclient *);

extern int  zclient_socket_connect (struct zclient *);
extern void zclient_serv_path_set  (char *path);
extern const char *zclient_serv_path_get (void);

extern u_short *redist_check_instance (struct redist_proto *, u_short);
extern void redist_add_instance (struct redist_proto *, u_short);
extern void redist_del_instance (struct redist_proto *, u_short);

extern void zclient_send_reg_requests (struct zclient *, vrf_id_t);
extern void zclient_send_dereg_requests (struct zclient *, vrf_id_t);

extern void zclient_send_interface_radv_req (struct zclient *zclient, vrf_id_t vrf_id,
                                 struct interface *ifp, int enable, int ra_interval);

/* Send redistribute command to zebra daemon. Do not update zclient state. */
extern int zebra_redistribute_send (int command, struct zclient *, afi_t, int type, u_short instance, vrf_id_t vrf_id);

/* If state has changed, update state and call zebra_redistribute_send. */
extern void zclient_redistribute (int command, struct zclient *, afi_t, int type,
                                  u_short instance, vrf_id_t vrf_id);

/* If state has changed, update state and send the command to zebra. */
extern void zclient_redistribute_default (int command, struct zclient *,
    vrf_id_t vrf_id);

/* Send the message in zclient->obuf to the zebra daemon (or enqueue it).
   Returns 0 for success or -1 on an I/O error. */
extern int zclient_send_message(struct zclient *);

/* create header for command, length to be filled in by user later */
extern void zclient_create_header (struct stream *, uint16_t, vrf_id_t);
extern int zclient_read_header (struct stream *s, int sock, u_int16_t *size,
				u_char *marker, u_char *version,
				vrf_id_t *vrf_id, u_int16_t *cmd);

extern struct interface *zebra_interface_add_read (struct stream *, vrf_id_t);
extern struct interface *zebra_interface_state_read (struct stream *s, vrf_id_t);
extern struct connected *zebra_interface_address_read (int, struct stream *, vrf_id_t);
extern struct nbr_connected *zebra_interface_nbr_address_read (int, struct stream *, vrf_id_t);
extern struct interface * zebra_interface_vrf_update_read (struct stream *s, vrf_id_t vrf_id,
                            vrf_id_t *new_vrf_id);
extern void zebra_interface_if_set_value (struct stream *, struct interface *);
extern void zebra_router_id_update_read (struct stream *s, struct prefix *rid);
extern int zapi_ipv4_route (u_char, struct zclient *, struct prefix_ipv4 *, 
                            struct zapi_ipv4 *);

extern struct interface *zebra_interface_link_params_read (struct stream *);
extern size_t zebra_interface_link_params_write (struct stream *,
                                                 struct interface *);
extern int lm_label_manager_connect (struct zclient *zclient);
extern int lm_get_label_chunk (struct zclient *zclient, u_char keep,
                               uint32_t chunk_size, uint32_t *start, uint32_t *end);
extern int lm_release_label_chunk (struct zclient *zclient, uint32_t start, uint32_t end);
/* IPv6 prefix add and delete function prototype. */

struct zapi_ipv6
{
  u_char type;
  u_short instance;

  u_int32_t flags;

  u_char message;

  safi_t safi;

  u_char nexthop_num;
  struct in6_addr **nexthop;

  u_char ifindex_num;
  ifindex_t *ifindex;

  u_char label_num;
  unsigned int *label;

  u_char distance;

  u_int32_t metric;

  route_tag_t tag;

  u_int32_t mtu;

  vrf_id_t vrf_id;
};

extern int zapi_ipv6_route (u_char cmd, struct zclient *zclient, 
                     struct prefix_ipv6 *p, struct prefix_ipv6 *src_p,
                     struct zapi_ipv6 *api);
extern int zapi_ipv4_route_ipv6_nexthop (u_char, struct zclient *,
                                         struct prefix_ipv4 *, struct zapi_ipv6 *);
extern int zapi_route (u_char cmd, struct zclient *zclient,
                       struct prefix *p, struct prefix_ipv6 *src_p,
                       struct zapi_route *api);

#endif /* _ZEBRA_ZCLIENT_H */
