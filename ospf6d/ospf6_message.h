// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 1999-2003 Yasuhiro Ohara
 */

#ifndef OSPF6_MESSAGE_H
#define OSPF6_MESSAGE_H

#define OSPF6_MESSAGE_BUFSIZ  4096

/* Debug option */
extern unsigned char conf_debug_ospf6_message[];

#define OSPF6_ACTION_SEND 0x01
#define OSPF6_ACTION_RECV 0x02
#define OSPF6_DEBUG_MESSAGE_SEND 0x01
#define OSPF6_DEBUG_MESSAGE_RECV 0x02
#define OSPF6_DEBUG_MESSAGE_SEND_HDR 0x04
#define OSPF6_DEBUG_MESSAGE_RECV_HDR 0x08
#define OSPF6_DEBUG_MESSAGE_SEND_BOTH                                          \
	OSPF6_DEBUG_MESSAGE_SEND | OSPF6_DEBUG_MESSAGE_SEND_HDR
#define OSPF6_DEBUG_MESSAGE_RECV_BOTH                                          \
	OSPF6_DEBUG_MESSAGE_RECV | OSPF6_DEBUG_MESSAGE_RECV_HDR

#define OSPF6_DEBUG_MESSAGE_ON(type, level)                                    \
	(conf_debug_ospf6_message[type] |= (level))
#define OSPF6_DEBUG_MESSAGE_OFF(type, level)                                   \
	(conf_debug_ospf6_message[type] &= ~(level))

#define IS_OSPF6_DEBUG_MESSAGE(t, e)                                           \
	(((OSPF6_DEBUG_MESSAGE_##e) == OSPF6_DEBUG_MESSAGE_RECV_HDR)           \
		? (conf_debug_ospf6_message[t]                                 \
		   & (OSPF6_DEBUG_MESSAGE_RECV_BOTH))                          \
		: (((OSPF6_DEBUG_MESSAGE_##e) == OSPF6_DEBUG_MESSAGE_SEND_HDR) \
			   ? (conf_debug_ospf6_message[t]                      \
			      & (OSPF6_DEBUG_MESSAGE_SEND_BOTH))               \
			   : (conf_debug_ospf6_message[t]                      \
			      & (OSPF6_DEBUG_MESSAGE_##e))))

#define IS_OSPF6_DEBUG_MESSAGE_ENABLED(type, e)                                \
	(conf_debug_ospf6_message[type] & (OSPF6_DEBUG_MESSAGE_##e))

/* Type */
#define OSPF6_MESSAGE_TYPE_UNKNOWN  0x0
#define OSPF6_MESSAGE_TYPE_HELLO    0x1  /* Discover/maintain neighbors */
#define OSPF6_MESSAGE_TYPE_DBDESC   0x2  /* Summarize database contents */
#define OSPF6_MESSAGE_TYPE_LSREQ    0x3  /* Database download request */
#define OSPF6_MESSAGE_TYPE_LSUPDATE 0x4  /* Database update */
#define OSPF6_MESSAGE_TYPE_LSACK    0x5  /* Flooding acknowledgment */
#define OSPF6_MESSAGE_TYPE_ALL      0x6  /* For debug option */
#define OSPF6_MESSAGE_TYPE_MAX 0x6       /* same as OSPF6_MESSAGE_TYPE_ALL */

struct ospf6_interface;

struct ospf6_packet {
	struct ospf6_packet *next;

	/* Pointer to data stream. */
	struct stream *s;

	/* IP destination address. */
	struct in6_addr dst;

	/* OSPF6 packet length. */
	uint16_t length;
};

/* OSPF packet queue structure. */
struct ospf6_fifo {
	unsigned long count;

	struct ospf6_packet *head;
	struct ospf6_packet *tail;
};

/* OSPFv3 packet header */
#define OSPF6_HEADER_SIZE                     16U
struct ospf6_header {
	uint8_t version;
	uint8_t type;
	uint16_t length;
	in_addr_t router_id;
	in_addr_t area_id;
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
	in_addr_t drouter;
	in_addr_t bdrouter;
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
	in_addr_t id;	 /* Link State ID */
	in_addr_t adv_router; /* Advertising Router */
};

/* Link State Update */
#define OSPF6_LS_UPD_MIN_SIZE                  4U
struct ospf6_lsupdate {
	uint32_t lsa_number;
	/* Followed by LSAs */
};

/* LLS is not supported, but used to derive
 * offset of Auth_trailer
 */
struct ospf6_lls_hdr {
	uint16_t checksum;
	uint16_t length;
};

/* Link State Acknowledgement */
#define OSPF6_LS_ACK_MIN_SIZE 0U
/* It is just a sequence of LSA Headers */

/* Function definition */
extern void ospf6_hello_print(struct ospf6_header *, int action);
extern void ospf6_dbdesc_print(struct ospf6_header *, int action);
extern void ospf6_lsreq_print(struct ospf6_header *, int action);
extern void ospf6_lsupdate_print(struct ospf6_header *, int action);
extern void ospf6_lsack_print(struct ospf6_header *, int action);

extern struct ospf6_fifo *ospf6_fifo_new(void);
extern void ospf6_fifo_flush(struct ospf6_fifo *fifo);
extern void ospf6_fifo_free(struct ospf6_fifo *fifo);

extern int ospf6_iobuf_size(unsigned int size);
extern void ospf6_message_terminate(void);
extern void ospf6_receive(struct event *thread);

extern void ospf6_hello_send(struct event *thread);
extern void ospf6_dbdesc_send(struct event *thread);
extern void ospf6_dbdesc_send_newone(struct event *thread);
extern void ospf6_lsreq_send(struct event *thread);
extern void ospf6_lsupdate_send_interface(struct event *thread);
extern void ospf6_lsupdate_send_neighbor(struct event *thread);
extern void ospf6_lsack_send_interface(struct event *thread);
extern void ospf6_lsack_send_neighbor(struct event *thread);

extern void ospf6_hello_send_addr(struct ospf6_interface *oi,
				  const struct in6_addr *addr);

extern int config_write_ospf6_debug_message(struct vty *);
extern void install_element_ospf6_debug_message(void);
extern const char *ospf6_message_type(int type);
#endif /* OSPF6_MESSAGE_H */
