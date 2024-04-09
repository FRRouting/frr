// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RIPng debug output routines
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_RIPNG_DEBUG_H
#define _ZEBRA_RIPNG_DEBUG_H

/* Debug flags. */
#define RIPNG_DEBUG_EVENT   0x01

#define RIPNG_DEBUG_PACKET  0x01
#define RIPNG_DEBUG_SEND    0x20
#define RIPNG_DEBUG_RECV    0x40

#define RIPNG_DEBUG_ZEBRA   0x01

/* Debug related macro. */
#define IS_RIPNG_DEBUG_EVENT  (ripng_debug_event & RIPNG_DEBUG_EVENT)

#define IS_RIPNG_DEBUG_PACKET (ripng_debug_packet & RIPNG_DEBUG_PACKET)
#define IS_RIPNG_DEBUG_SEND   (ripng_debug_packet & RIPNG_DEBUG_SEND)
#define IS_RIPNG_DEBUG_RECV   (ripng_debug_packet & RIPNG_DEBUG_RECV)

#define IS_RIPNG_DEBUG_ZEBRA  (ripng_debug_zebra & RIPNG_DEBUG_ZEBRA)

extern unsigned long ripng_debug_event;
extern unsigned long ripng_debug_packet;
extern unsigned long ripng_debug_zebra;

extern void ripng_debug_init(void);

#endif /* _ZEBRA_RIPNG_DEBUG_H */
