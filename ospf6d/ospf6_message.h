/*
 * Copyright (C) 1999-2003 Yasuhiro Ohara
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

#ifndef OSPF6_MESSAGE_H
#define OSPF6_MESSAGE_H

#define OSPF6_MESSAGE_BUFSIZ  4096

/* Debug option */
extern unsigned char conf_debug_ospf6_message[];
#define OSPF6_DEBUG_MESSAGE_SEND 0x01
#define OSPF6_DEBUG_MESSAGE_RECV 0x02
#define OSPF6_DEBUG_MESSAGE_ON(type, level)                                    \
	(conf_debug_ospf6_message[type] |= (level))
#define OSPF6_DEBUG_MESSAGE_OFF(type, level)                                   \
	(conf_debug_ospf6_message[type] &= ~(level))
#define IS_OSPF6_DEBUG_MESSAGE(t, e)                                           \
	(conf_debug_ospf6_message[t] & OSPF6_DEBUG_MESSAGE_##e)

/* Type */
#define OSPF6_MESSAGE_TYPE_UNKNOWN  0x0
#define OSPF6_MESSAGE_TYPE_HELLO    0x1  /* Discover/maintain neighbors */
#define OSPF6_MESSAGE_TYPE_DBDESC   0x2  /* Summarize database contents */
#define OSPF6_MESSAGE_TYPE_LSREQ    0x3  /* Database download request */
#define OSPF6_MESSAGE_TYPE_LSUPDATE 0x4  /* Database update */
#define OSPF6_MESSAGE_TYPE_LSACK    0x5  /* Flooding acknowledgment */
#define OSPF6_MESSAGE_TYPE_ALL      0x6  /* For debug option */

/* OSPFv3 packet header */
#define OSPF6_HEADER_SIZE                     16U
struct ospf6_header {
	uint8_t version;
	uint8_t type;
	uint16_t length;
	uint32_t router_id;
	uint32_t area_id;
	uint16_t checksum;
	uint8_t instance_id;
	uint8_t reserved;
};

#define OSPF6_MESSAGE_END(H) ((caddr_t) (H) + ntohs ((H)->length))

/* Hello */
#define OSPF6_HELLO_MIN_SIZE                  20U
struct ospf6_hello {
	ifindex_t interface_id;
	uint8_t priority;
	uint8_t options[3];
	uint16_t hello_interval;
	uint16_t dead_interval;
	uint32_t drouter;
	uint32_t bdrouter;
	/* Followed by Router-IDs */
};

/* Database Description */
#define OSPF6_DB_DESC_MIN_SIZE                12U
struct ospf6_dbdesc {
	uint8_t reserved1;
	uint8_t options[3];
	uint16_t ifmtu;
	uint8_t reserved2;
	uint8_t bits;
	uint32_t seqnum;
	/* Followed by LSA Headers */
};

#define OSPF6_DBDESC_MSBIT (0x01) /* master/slave bit */
#define OSPF6_DBDESC_MBIT  (0x02) /* more bit */
#define OSPF6_DBDESC_IBIT  (0x04) /* initial bit */

/* Link State Request */
#define OSPF6_LS_REQ_MIN_SIZE                  0U
/* It is just a sequence of entries below */
#define OSPF6_LSREQ_LSDESC_FIX_SIZE           12U
struct ospf6_lsreq_entry {
	uint16_t reserved;   /* Must Be Zero */
	uint16_t type;       /* LS type */
	uint32_t id;	 /* Link State ID */
	uint32_t adv_router; /* Advertising Router */
};

/* Link State Update */
#define OSPF6_LS_UPD_MIN_SIZE                  4U
struct ospf6_lsupdate {
	uint32_t lsa_number;
	/* Followed by LSAs */
};

/* Link State Acknowledgement */
#define OSPF6_LS_ACK_MIN_SIZE                  0U
/* It is just a sequence of LSA Headers */

/* Function definition */
extern void ospf6_hello_print(struct ospf6_header *);
extern void ospf6_dbdesc_print(struct ospf6_header *);
extern void ospf6_lsreq_print(struct ospf6_header *);
extern void ospf6_lsupdate_print(struct ospf6_header *);
extern void ospf6_lsack_print(struct ospf6_header *);

extern int ospf6_iobuf_size(unsigned int size);
extern void ospf6_message_terminate(void);
extern int ospf6_receive(struct thread *thread);

extern int ospf6_hello_send(struct thread *thread);
extern int ospf6_dbdesc_send(struct thread *thread);
extern int ospf6_dbdesc_send_newone(struct thread *thread);
extern int ospf6_lsreq_send(struct thread *thread);
extern int ospf6_lsupdate_send_interface(struct thread *thread);
extern int ospf6_lsupdate_send_neighbor(struct thread *thread);
extern int ospf6_lsack_send_interface(struct thread *thread);
extern int ospf6_lsack_send_neighbor(struct thread *thread);

extern int config_write_ospf6_debug_message(struct vty *);
extern void install_element_ospf6_debug_message(void);

#endif /* OSPF6_MESSAGE_H */
