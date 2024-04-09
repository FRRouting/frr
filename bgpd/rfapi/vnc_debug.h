// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Copyright 2016, LabN Consulting, L.L.C.
 */

#ifndef _QUAGGA_BGP_VNC_DEBUG_H
#define _QUAGGA_BGP_VNC_DEBUG_H

#ifdef ENABLE_BGP_VNC

/*
 * debug state storage
 */
extern unsigned long conf_vnc_debug;
extern unsigned long term_vnc_debug;

/*
 * debug flag bits
 */
#define VNC_DEBUG_RFAPI_QUERY		0x00000001
#define VNC_DEBUG_IMPORT_BI_ATTACH	0x00000002
#define VNC_DEBUG_IMPORT_DEL_REMOTE	0x00000004
#define VNC_DEBUG_EXPORT_BGP_GETCE	0x00000008
#define VNC_DEBUG_EXPORT_BGP_DIRECT_ADD	0x00000010
#define VNC_DEBUG_IMPORT_BGP_ADD_ROUTE	0x00000020
#define VNC_DEBUG_VERBOSE       	0x00000040
#define VNC_DEBUG_ANY                   0xFFFFFFFF

#define VNC_DEBUG(bit)          (term_vnc_debug & (VNC_DEBUG_ ## bit))
#define vnc_zlog_debug_verbose  if (VNC_DEBUG(VERBOSE)) zlog_debug
#define vnc_zlog_debug_any      if (VNC_DEBUG(ANY)) zlog_debug

extern void vnc_debug_init(void);

#endif /* ENABLE_BGP_VNC */

#endif /* _QUAGGA_BGP_VNC_DEBUG_H */
