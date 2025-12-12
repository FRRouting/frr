// SPDX-License-Identifier: GPL-2.0-or-later
/* RIP interface routines
 *
 * This file is part of Quagga
 */

#ifndef _QUAGGA_RIP_INTERFACE_H
#define _QUAGGA_RIP_INTERFACE_H

#include "memory.h"
#include "zclient.h"

DECLARE_MTYPE(RIP_INTERFACE_STRING);

extern int rip_interface_down(int cmd, struct zclient *zclient, zebra_size_t length,
			      vrf_id_t vrf_id);
extern int rip_interface_up(int cmd, struct zclient *zclient, zebra_size_t length, vrf_id_t vrf_id);
extern int rip_interface_add(int cmd, struct zclient *zclient, zebra_size_t length,
			     vrf_id_t vrf_id);
extern int rip_interface_delete(int cmd, struct zclient *zclient, zebra_size_t length,
				vrf_id_t vrf_id);
extern int rip_interface_address_add(int cmd, struct zclient *zclient, zebra_size_t length,
				     vrf_id_t vrf_id);
extern int rip_interface_address_delete(int cmd, struct zclient *zclient, zebra_size_t length,
					vrf_id_t vrf_id);
extern int rip_interface_vrf_update(ZAPI_CALLBACK_ARGS);
extern void rip_interface_sync(struct interface *ifp);
extern int rip_enable_network_lookup2(struct connected *connected);

#endif /* _QUAGGA_RIP_INTERFACE_H */
