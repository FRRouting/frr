// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright 2015-2016, LabN Consulting, L.L.C.
 */

#ifndef _QUAGGA_BGP_VNC_TYPES_H
#define _QUAGGA_BGP_VNC_TYPES_H

#ifdef ENABLE_BGP_VNC
typedef enum {
	BGP_VNC_SUBTLV_TYPE_LIFETIME = 1,
	BGP_VNC_SUBTLV_TYPE_RFPOPTION = 2, /* deprecated */
} bgp_vnc_subtlv_types;

#endif /* ENABLE_BGP_VNC */
#endif /* _QUAGGA_BGP_VNC_TYPES_H */
