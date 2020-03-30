// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra NHRP library
 * Copyright (C)2024 6WIND S.A.
 */

#ifndef _ZEBRA_NHRP_H
#define _ZEBRA_NHRP_H

#ifdef __cplusplus
extern "C" {
#endif

#define ZEBRA_GRE_NHRP_6WIND_RCV_BUF 500

extern int zebra_nhrp_6wind_fd;
extern bool zebra_nhrp_fastpath_configured;
extern struct event *zebra_nhrp_log_event;

extern int zebra_nhrp_6wind_configure_listen_port(uint16_t port);
extern int zebra_nhrp_6wind_access(int *fd_fp, int *fd_orig);
extern int zebra_nhrp_netlink_fastpath_parse(int fd, int orig_fd, int *status);
extern void zebra_nhrp_6wind_log_recv(struct event *t);

extern void zebra_nhrp_interface_configure(struct interface *ifp,
					   bool nhrp_6wind, afi_t afi,
					   bool enabled);
extern void zebra_nhrp_6wind_connection(bool on, uint16_t port);

extern void zebra_nhrp_6wind_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_NHRP_H */
