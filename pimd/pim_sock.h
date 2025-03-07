// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#ifndef PIM_SOCK_H
#define PIM_SOCK_H

#include <netinet/in.h>

#define PIM_SOCK_ERR_NONE    (0)  /* No error */
#define PIM_SOCK_ERR_SOCKET  (-1) /* socket() */
#define PIM_SOCK_ERR_RA      (-2) /* Router Alert option */
#define PIM_SOCK_ERR_REUSE   (-3) /* Reuse option */
#define PIM_SOCK_ERR_TTL     (-4) /* TTL option */
#define PIM_SOCK_ERR_LOOP    (-5) /* Loopback option */
#define PIM_SOCK_ERR_IFACE   (-6) /* Outgoing interface option */
#define PIM_SOCK_ERR_DSTADDR (-7) /* Outgoing interface option */
#define PIM_SOCK_ERR_NONBLOCK_GETFL (-8) /* Get O_NONBLOCK */
#define PIM_SOCK_ERR_NONBLOCK_SETFL (-9) /* Set O_NONBLOCK */
#define PIM_SOCK_ERR_NAME    (-10) /* Socket name (getsockname) */
#define PIM_SOCK_ERR_BIND    (-11) /* Can't bind to interface */

struct pim_instance;

int pim_socket_bind(int fd, struct interface *ifp);
void pim_socket_ip_hdr(int fd);
int pim_setsockopt_packetinfo(int fd);
int pim_socket_raw(int protocol);
int pim_socket_mcast(int protocol, pim_addr ifaddr, struct interface *ifp,
		     uint8_t loop);
int pim_socket_join(int fd, pim_addr group, pim_addr ifaddr, ifindex_t ifindex,
		    struct pim_interface *pim_ifp);
int pim_socket_leave(int fd, pim_addr group, pim_addr ifaddr, ifindex_t ifindex,
		     struct pim_interface *pim_ifp);
int pim_socket_recvfromto(int fd, uint8_t *buf, size_t len,
			  struct sockaddr_storage *from, socklen_t *fromlen,
			  struct sockaddr_storage *to, socklen_t *tolen,
			  ifindex_t *ifindex);

int pim_socket_getsockname(int fd, struct sockaddr *name, socklen_t *namelen);

int pim_reg_sock(void);

#endif /* PIM_SOCK_H */
