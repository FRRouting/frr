// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Common ioctl functions.
 * Copyright (C) 1998 Kunihiro Ishiguro
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

#define AF_IOCTL(af, request, buffer)  if_ioctl(request, buffer)

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_IOCTL_H */
