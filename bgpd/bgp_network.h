/* BGP network related header
 * Copyright (C) 1999 Kunihiro Ishiguro
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

#ifndef _QUAGGA_BGP_NETWORK_H
#define _QUAGGA_BGP_NETWORK_H

#define BGP_SOCKET_SNDBUF_SIZE 65536

extern int bgp_socket(struct bgp *bgp, unsigned short port,
		      const char *address);
extern void bgp_close_vrf_socket(struct bgp *bgp);
extern void bgp_close(void);
extern int bgp_connect(struct peer *);
extern int bgp_getsockname(struct peer *);

extern int bgp_md5_set(struct peer *);
extern int bgp_md5_unset(struct peer *);
extern int bgp_set_socket_ttl(struct peer *, int fd);

#endif /* _QUAGGA_BGP_NETWORK_H */
