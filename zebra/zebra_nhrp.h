// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra NHRP library
 * Copyright (C)2024 6WIND S.A.
 */

#ifndef _ZEBRA_NHRP_H
#define _ZEBRA_NHRP_H

#ifdef __cplusplus
extern "C" {
#endif

extern void zebra_nhrp_interface_configure(struct interface *ifp,
					   bool nhrp_6wind, afi_t afi,
					   bool enabled);
extern void zebra_nhrp_6wind_connection(bool on, uint16_t port);

extern void zebra_nhrp_6wind_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_NHRP_H */
