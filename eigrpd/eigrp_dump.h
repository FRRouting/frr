// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * EIGRP Dump Functions and Debbuging.
 * Copyright (C) 2013-2014
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
 */

#ifndef _ZEBRA_EIGRPD_DUMP_H_
#define _ZEBRA_EIGRPD_DUMP_H_

#define EIGRP_TIME_DUMP_SIZE		16

/* general debug flags */
extern unsigned long term_debug_eigrp;
#define EIGRP_DEBUG_EVENT		0x01
#define EIGRP_DEBUG_DETAIL		0x02
#define EIGRP_DEBUG_TIMERS		0x04

/* neighbor debug flags */
extern unsigned long term_debug_eigrp_nei;
#define EIGRP_DEBUG_NEI				0x01

/* packet debug flags */
extern unsigned long term_debug_eigrp_packet[];
#define EIGRP_DEBUG_UPDATE			0x01
#define EIGRP_DEBUG_REQUEST			0x02
#define EIGRP_DEBUG_QUERY			0x04
#define EIGRP_DEBUG_REPLY			0x08
#define EIGRP_DEBUG_HELLO			0x10
#define EIGRP_DEBUG_PROBE			0x40
#define EIGRP_DEBUG_ACK 			0x80
#define EIGRP_DEBUG_SIAQUERY	    0x200
#define EIGRP_DEBUG_SIAREPLY	    0x400
#define EIGRP_DEBUG_STUB 			0x800
#define EIGRP_DEBUG_PACKETS_ALL     0xfff

extern unsigned long term_debug_eigrp_transmit;
#define EIGRP_DEBUG_SEND			0x01
#define EIGRP_DEBUG_RECV			0x02
#define EIGRP_DEBUG_SEND_RECV		0x03
#define EIGRP_DEBUG_PACKET_DETAIL	0x04

/* zebra debug flags */
extern unsigned long term_debug_eigrp_zebra;
#define EIGRP_DEBUG_ZEBRA_INTERFACE	0x01
#define EIGRP_DEBUG_ZEBRA_REDISTRIBUTE	0x02
#define EIGRP_DEBUG_ZEBRA		0x03

/* Macro for setting debug option. */
#define CONF_DEBUG_NEI_ON(a, b)		conf_debug_eigrp_nei[a] |= (b)
#define CONF_DEBUG_NEI_OFF(a, b)	conf_debug_eigrp_nei[a] &= ~(b)
#define TERM_DEBUG_NEI_ON(a, b)		term_debug_eigrp_nei[a] |= (b)
#define TERM_DEBUG_NEI_OFF(a, b)	term_debug_eigrp_nei[a] &= ~(b)
#define DEBUG_NEI_ON(a, b)                                                     \
	do {                                                                   \
		CONF_DEBUG_NEI_ON(a, b);                                       \
		TERM_DEBUG_NEI_ON(a, b);                                       \
	} while (0)
#define DEBUG_NEI_OFF(a, b)                                                    \
	do {                                                                   \
		CONF_DEBUG_NEI_OFF(a, b);                                      \
		TERM_DEBUG_NEI_OFF(a, b);                                      \
	} while (0)

#define CONF_DEBUG_PACKET_ON(a, b)	conf_debug_eigrp_packet[a] |= (b)
#define CONF_DEBUG_PACKET_OFF(a, b)	conf_debug_eigrp_packet[a] &= ~(b)
#define TERM_DEBUG_PACKET_ON(a, b)	term_debug_eigrp_packet[a] |= (b)
#define TERM_DEBUG_PACKET_OFF(a, b)	term_debug_eigrp_packet[a] &= ~(b)
#define DEBUG_PACKET_ON(a, b)                                                  \
	do {                                                                   \
		CONF_DEBUG_PACKET_ON(a, b);                                    \
		TERM_DEBUG_PACKET_ON(a, b);                                    \
	} while (0)
#define DEBUG_PACKET_OFF(a, b)                                                 \
	do {                                                                   \
		CONF_DEBUG_PACKET_OFF(a, b);                                   \
		TERM_DEBUG_PACKET_OFF(a, b);                                   \
	} while (0)

#define CONF_DEBUG_TRANSMIT_ON(a, b)	conf_debug_eigrp_transmit |= (b)
#define CONF_DEBUG_TRANSMIT_OFF(a, b)	conf_debug_eigrp_transmit &= ~(b)
#define TERM_DEBUG_TRANSMIT_ON(a, b)	term_debug_eigrp_transmit |= (b)
#define TERM_DEBUG_TRANSMIT_OFF(a, b)	term_debug_eigrp_transmit &= ~(b)
#define DEBUG_TRANSMIT_ON(a, b)                                                \
	do {                                                                   \
		CONF_DEBUG_TRANSMIT_ON(a, b);                                  \
		TERM_DEBUG_TRANSMIT_ON(a, b);                                  \
	} while (0)
#define DEBUG_TRANSMIT_OFF(a, b)                                               \
	do {                                                                   \
		CONF_DEBUG_TRANSMIT_OFF(a, b);                                 \
		TERM_DEBUG_TRANSMIT_OFF(a, b);                                 \
	} while (0)

#define CONF_DEBUG_ON(a, b)		conf_debug_eigrp_ ## a |= (EIGRP_DEBUG_ ## b)
#define CONF_DEBUG_OFF(a, b)		conf_debug_eigrp_ ## a &= ~(EIGRP_DEBUG_ ## b)
#define TERM_DEBUG_ON(a, b)		term_debug_eigrp_ ## a |= (EIGRP_DEBUG_ ## b)
#define TERM_DEBUG_OFF(a, b)		term_debug_eigrp_ ## a &= ~(EIGRP_DEBUG_ ## b)
#define DEBUG_ON(a, b)                                                         \
	do {                                                                   \
		CONF_DEBUG_ON(a, b);                                           \
		TERM_DEBUG_ON(a, b);                                           \
	} while (0)
#define DEBUG_OFF(a, b)                                                        \
	do {                                                                   \
		CONF_DEBUG_OFF(a, b);                                          \
		TERM_DEBUG_OFF(a, b);                                          \
	} while (0)

/* Macro for checking debug option. */
#define IS_DEBUG_EIGRP_PACKET(a, b)                                            \
	(term_debug_eigrp_packet[a] & EIGRP_DEBUG_##b)
#define IS_DEBUG_EIGRP_TRANSMIT(a, b)                                          \
	(term_debug_eigrp_transmit & EIGRP_DEBUG_##b)
#define IS_DEBUG_EIGRP_NEI(a, b) (term_debug_eigrp_nei & EIGRP_DEBUG_##b)
#define IS_DEBUG_EIGRP(a, b) (term_debug_eigrp & EIGRP_DEBUG_##b)
#define IS_DEBUG_EIGRP_EVENT IS_DEBUG_EIGRP(event, EVENT)

/* Prototypes. */
extern const char *eigrp_if_name_string(struct eigrp_interface *);

extern void eigrp_ip_header_dump(struct ip *);
extern void eigrp_header_dump(struct eigrp_header *);

extern void show_ip_eigrp_interface_header(struct vty *, struct eigrp *);
extern void show_ip_eigrp_neighbor_header(struct vty *, struct eigrp *);
extern void show_ip_eigrp_topology_header(struct vty *, struct eigrp *);
extern void show_ip_eigrp_interface_detail(struct vty *, struct eigrp *,
					   struct eigrp_interface *);
extern void show_ip_eigrp_interface_sub(struct vty *, struct eigrp *,
					struct eigrp_interface *);
extern void show_ip_eigrp_neighbor_sub(struct vty *, struct eigrp_neighbor *,
				       int);
extern void show_ip_eigrp_prefix_descriptor(struct vty *vty,
					    struct eigrp_prefix_descriptor *tn);
extern void show_ip_eigrp_route_descriptor(struct vty *vty, struct eigrp *eigrp,
					   struct eigrp_route_descriptor *ne,
					   bool *first);

extern void eigrp_debug_init(void);

#endif /* _ZEBRA_EIGRPD_DUMP_H_ */
