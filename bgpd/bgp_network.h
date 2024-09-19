// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP network related header
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _QUAGGA_BGP_NETWORK_H
#define _QUAGGA_BGP_NETWORK_H

#define BGP_SOCKET_SNDBUF_SIZE 65536

struct bgp_listener {
	int fd;
	union sockunion su;
	struct event *thread;
	struct bgp *bgp;
	char *name;
};

extern void bgp_dump_listener_info(struct vty *vty);
extern int bgp_socket(struct bgp *bgp, unsigned short port,
		      const char *address);
extern void bgp_close_vrf_socket(struct bgp *bgp);
extern void bgp_close(void);
extern int bgp_connect(struct peer_connection *connection);
extern int bgp_getsockname(struct peer *peer);
extern void bgp_updatesockname(struct peer *peer);

extern int bgp_md5_set_prefix(struct bgp *bgp, struct prefix *p,
			      const char *password);
extern int bgp_md5_unset_prefix(struct bgp *bgp, struct prefix *p);
extern int bgp_md5_set(struct peer_connection *connection);
extern int bgp_md5_unset(struct peer_connection *connection);
extern int bgp_set_socket_ttl(struct peer_connection *connection);
extern int bgp_tcp_mss_set(struct peer *peer);
extern int bgp_update_address(struct interface *ifp, const union sockunion *dst,
			      union sockunion *addr);

#endif /* _QUAGGA_BGP_NETWORK_H */
