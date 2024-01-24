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

extern void rip_interface_down(ZAPI_CALLBACK_ARGS);
extern void rip_interface_up(ZAPI_CALLBACK_ARGS);
extern void rip_interface_add(ZAPI_CALLBACK_ARGS);
extern void rip_interface_delete(ZAPI_CALLBACK_ARGS);
extern void rip_interface_address_add(ZAPI_CALLBACK_ARGS);
extern void rip_interface_address_delete(ZAPI_CALLBACK_ARGS);
extern void rip_interface_vrf_update(ZAPI_CALLBACK_ARGS);
extern void rip_interface_sync(struct interface *ifp);

#endif /* _QUAGGA_RIP_INTERFACE_H */
