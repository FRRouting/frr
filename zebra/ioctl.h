/*
 * Common ioctl functions.
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

#ifndef _ZEBRA_IOCTL_H
#define _ZEBRA_IOCTL_H

#ifdef __cplusplus
extern "C" {
#endif

/* Prototypes. */
extern void ifreq_set_name(struct ifreq *, struct interface *);
extern int if_ioctl(unsigned long, caddr_t);
extern int vrf_if_ioctl(unsigned long request, caddr_t buffer, vrf_id_t vrf_id);

extern int if_set_flags(struct interface *, uint64_t);
extern int if_unset_flags(struct interface *, uint64_t);
extern void if_get_flags(struct interface *);

extern void if_get_metric(struct interface *);
extern void if_get_mtu(struct interface *);

#ifdef SOLARIS_IPV6
extern int if_ioctl_ipv6(unsigned long, caddr_t);
extern struct connected *if_lookup_linklocal(struct interface *);

#define AF_IOCTL(af, request, buffer)                                          \
	((af) == AF_INET ? if_ioctl(request, buffer)                           \
			 : if_ioctl_ipv6(request, buffer))
#else  /* SOLARIS_IPV6 */

#define AF_IOCTL(af, request, buffer)  if_ioctl(request, buffer)

#endif /* SOLARIS_IPV6 */

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_IOCTL_H */
