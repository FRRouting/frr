// SPDX-License-Identifier: GPL-2.0-or-later
/* RIP debug routines
 * Copyright (C) 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
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

#endif /* _ZEBRA_RIP_DEBUG_H */
