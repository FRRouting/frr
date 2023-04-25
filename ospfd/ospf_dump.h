// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFd dump routine.
 * Copyright (C) 1999 Toshiaki Takada
 */

#ifndef _ZEBRA_OSPF_DUMP_H
#define _ZEBRA_OSPF_DUMP_H

/* Debug Flags. */
#define OSPF_DEBUG_HELLO	0x01
#define OSPF_DEBUG_DB_DESC	0x02
#define OSPF_DEBUG_LS_REQ	0x04
#define OSPF_DEBUG_LS_UPD	0x08
#define OSPF_DEBUG_LS_ACK	0x10
#define OSPF_DEBUG_ALL		0x1f

#define OSPF_DEBUG_SEND		0x01
#define OSPF_DEBUG_RECV		0x02
#define OSPF_DEBUG_SEND_RECV    0x03
#define OSPF_DEBUG_DETAIL	0x04

#define OSPF_DEBUG_ISM_STATUS	0x01
#define OSPF_DEBUG_ISM_EVENTS	0x02
#define OSPF_DEBUG_ISM_TIMERS	0x04
#define OSPF_DEBUG_ISM		0x07
#define OSPF_DEBUG_NSM_STATUS	0x01
#define OSPF_DEBUG_NSM_EVENTS	0x02
#define OSPF_DEBUG_NSM_TIMERS   0x04
#define OSPF_DEBUG_NSM		0x07

#define OSPF_DEBUG_LSA_GENERATE 0x01
#define OSPF_DEBUG_LSA_FLOODING	0x02
#define OSPF_DEBUG_LSA_INSTALL  0x04
#define OSPF_DEBUG_LSA_REFRESH  0x08
#define OSPF_DEBUG_LSA		0x0F
#define OSPF_DEBUG_EXTNL_LSA_AGGR 0x10

#define OSPF_DEBUG_ZEBRA_INTERFACE     0x01
#define OSPF_DEBUG_ZEBRA_REDISTRIBUTE  0x02
#define OSPF_DEBUG_ZEBRA	       0x03

#define OSPF_DEBUG_EVENT        0x01
#define OSPF_DEBUG_NSSA		0x02
#define OSPF_DEBUG_TE          0x04
#define OSPF_DEBUG_EXT         0x08
#define OSPF_DEBUG_SR          0x10
#define OSPF_DEBUG_TI_LFA 0x11
#define OSPF_DEBUG_DEFAULTINFO 0x20
#define OSPF_DEBUG_LDP_SYNC 0x40

#define OSPF_DEBUG_GR 0x01

#define OSPF_DEBUG_BFD_LIB 0x01

#define OSPF_DEBUG_CLIENT_API 0x01

/* Macro for setting debug option. */
#define CONF_DEBUG_PACKET_ON(a, b)	    conf_debug_ospf_packet[a] |= (b)
#define CONF_DEBUG_PACKET_OFF(a, b)	    conf_debug_ospf_packet[a] &= ~(b)
#define TERM_DEBUG_PACKET_ON(a, b)	    term_debug_ospf_packet[a] |= (b)
#define TERM_DEBUG_PACKET_OFF(a, b)	    term_debug_ospf_packet[a] &= ~(b)
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

#define CONF_DEBUG_ON(a, b)	 conf_debug_ospf_ ## a |= (OSPF_DEBUG_ ## b)
#define CONF_DEBUG_OFF(a, b)	 conf_debug_ospf_ ## a &= ~(OSPF_DEBUG_ ## b)
#define TERM_DEBUG_ON(a, b)	 term_debug_ospf_ ## a |= (OSPF_DEBUG_ ## b)
#define TERM_DEBUG_OFF(a, b)	 term_debug_ospf_ ## a &= ~(OSPF_DEBUG_ ## b)
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
#define IS_DEBUG_OSPF_PACKET(a, b) (term_debug_ospf_packet[a] & OSPF_DEBUG_##b)
#define IS_DEBUG_OSPF(a, b) (term_debug_ospf_##a & OSPF_DEBUG_##b)
#define IS_DEBUG_OSPF_EVENT IS_DEBUG_OSPF(event, EVENT)

#define IS_DEBUG_OSPF_NSSA  IS_DEBUG_OSPF(nssa, NSSA)

#define IS_DEBUG_OSPF_TE  IS_DEBUG_OSPF(te, TE)

#define IS_DEBUG_OSPF_EXT  IS_DEBUG_OSPF(ext, EXT)

#define IS_DEBUG_OSPF_SR  IS_DEBUG_OSPF(sr, SR)

#define IS_DEBUG_OSPF_TI_LFA IS_DEBUG_OSPF(ti_lfa, TI_LFA)

#define IS_DEBUG_OSPF_DEFAULT_INFO IS_DEBUG_OSPF(defaultinfo, DEFAULTINFO)

#define IS_DEBUG_OSPF_LDP_SYNC IS_DEBUG_OSPF(ldp_sync, LDP_SYNC)
#define IS_DEBUG_OSPF_GR IS_DEBUG_OSPF(gr, GR)
#define IS_DEBUG_OSPF_CLIENT_API IS_DEBUG_OSPF(client_api, CLIENT_API)

#define IS_CONF_DEBUG_OSPF_PACKET(a, b)                                        \
	(conf_debug_ospf_packet[a] & OSPF_DEBUG_##b)
#define IS_CONF_DEBUG_OSPF(a, b) (conf_debug_ospf_##a & OSPF_DEBUG_##b)

#define AREA_NAME(A)    ospf_area_name_string ((A))
#define IF_NAME(I)      ospf_if_name_string ((I))

/* Extern debug flag. */
extern unsigned long term_debug_ospf_packet[];
extern unsigned long term_debug_ospf_event;
extern unsigned long term_debug_ospf_ism;
extern unsigned long term_debug_ospf_nsm;
extern unsigned long term_debug_ospf_lsa;
extern unsigned long term_debug_ospf_zebra;
extern unsigned long term_debug_ospf_nssa;
extern unsigned long term_debug_ospf_te;
extern unsigned long term_debug_ospf_ext;
extern unsigned long term_debug_ospf_sr;
extern unsigned long term_debug_ospf_ti_lfa;
extern unsigned long term_debug_ospf_defaultinfo;
extern unsigned long term_debug_ospf_ldp_sync;
extern unsigned long term_debug_ospf_gr;
extern unsigned long term_debug_ospf_bfd;
extern unsigned long term_debug_ospf_client_api;

/* Message Strings. */
extern char *ospf_lsa_type_str[];

/* Prototypes. */
extern const char *ospf_area_name_string(struct ospf_area *area);
extern const char *ospf_area_desc_string(struct ospf_area *area);
extern const char *ospf_if_name_string(struct ospf_interface *oip);
extern int ospf_nbr_ism_state(struct ospf_neighbor *nbr);
extern void ospf_nbr_ism_state_message(struct ospf_neighbor *nbr, char *buf,
				       size_t size);
extern const char *ospf_timer_dump(struct event *e, char *buf, size_t size);
extern const char *ospf_timeval_dump(struct timeval *t, char *buf, size_t size);
extern void ospf_packet_dump(struct stream *s);
extern void ospf_debug_init(void);

/* Appropriate buffer size to use with ospf_timer_dump and ospf_timeval_dump: */
#define OSPF_TIME_DUMP_SIZE	16

#endif /* _ZEBRA_OSPF_DUMP_H */
