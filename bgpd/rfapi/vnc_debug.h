/*
 *
 * Copyright 2016, LabN Consulting, L.L.C.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_BGP_VNC_DEBUG_H
#define _QUAGGA_BGP_VNC_DEBUG_H

#if ENABLE_BGP_VNC

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
