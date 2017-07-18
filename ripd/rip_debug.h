/* RIP debug routines
 * Copyright (C) 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
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

#ifndef _ZEBRA_RIP_DEBUG_H
#define _ZEBRA_RIP_DEBUG_H

/* RIP debug event flags. */
#define RIP_DEBUG_EVENT   0x01

/* RIP debug packet flags. */
#define RIP_DEBUG_PACKET  0x01
#define RIP_DEBUG_SEND    0x20
#define RIP_DEBUG_RECV    0x40
#define RIP_DEBUG_DETAIL  0x80

/* RIP debug zebra flags. */
#define RIP_DEBUG_ZEBRA   0x01

/* Debug related macro. */
#define IS_RIP_DEBUG_EVENT  (rip_debug_event & RIP_DEBUG_EVENT)

#define IS_RIP_DEBUG_PACKET (rip_debug_packet & RIP_DEBUG_PACKET)
#define IS_RIP_DEBUG_SEND   (rip_debug_packet & RIP_DEBUG_SEND)
#define IS_RIP_DEBUG_RECV   (rip_debug_packet & RIP_DEBUG_RECV)

#define IS_RIP_DEBUG_ZEBRA  (rip_debug_zebra & RIP_DEBUG_ZEBRA)

extern unsigned long rip_debug_event;
extern unsigned long rip_debug_packet;
extern unsigned long rip_debug_zebra;

extern void rip_debug_init(void);
extern void rip_debug_reset(void);

#endif /* _ZEBRA_RIP_DEBUG_H */
