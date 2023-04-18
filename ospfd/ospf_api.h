// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * API message handling module for OSPF daemon and client.
 * Copyright (C) 2001, 2002 Ralph Keller
 * Copyright (c) 2022, LabN Consulting, L.L.C.
 */


/* This file is used both by the OSPFd and client applications to
   define message formats used for communication. */

#ifndef _OSPF_API_H
#define _OSPF_API_H

#include <zebra.h>
#include "ospf_lsa.h"

#define OSPF_API_VERSION           1

/* MTYPE definition is not reflected to "memory.h". */
#define MTYPE_OSPF_API_MSG      MTYPE_TMP
#define MTYPE_OSPF_API_FIFO     MTYPE_TMP

/* Default API server port to accept connection request from client-side. */
/* This value could be overridden by "ospfapi" entry in "/etc/services". */
#define OSPF_API_SYNC_PORT      2607

/* -----------------------------------------------------------
 * Generic messages
 * -----------------------------------------------------------
 */

/* Message header structure, fields are in network byte order and
   aligned to four octets. */
struct apimsghdr {
	uint8_t version; /* OSPF API protocol version */
	uint8_t msgtype; /* Type of message */
	uint16_t msglen; /* Length of message w/o header */
	uint32_t msgseq; /* Sequence number */
};

/* Message representation with header and body */
struct msg {
	struct msg *next; /* to link into fifo */

	/* Message header */
	struct apimsghdr hdr;

	/* Message body */
	struct stream *s;
};

/* Prototypes for generic messages. */
extern struct msg *msg_new(uint8_t msgtype, void *msgbody, uint32_t seqnum,
			   uint16_t msglen);
extern struct msg *msg_dup(struct msg *msg);
extern void msg_print(struct msg *msg); /* XXX debug only */
extern void msg_free(struct msg *msg);
struct msg *msg_read(int fd);
extern int msg_write(int fd, struct msg *msg);

/* For requests, the message sequence number is between MIN_SEQ and
   MAX_SEQ. For notifications, the sequence number is 0. */

#define MIN_SEQ          1
#define MAX_SEQ 2147483647

extern void msg_set_seq(struct msg *msg, uint32_t seqnr);
extern uint32_t msg_get_seq(struct msg *msg);

/* -----------------------------------------------------------
 * Message fifo queues
 * -----------------------------------------------------------
 */

/* Message queue structure. */
struct msg_fifo {
	unsigned long count;

	struct msg *head;
	struct msg *tail;
};

/* Prototype for message fifo queues. */
extern struct msg_fifo *msg_fifo_new(void);
extern void msg_fifo_push(struct msg_fifo *, struct msg *msg);
extern struct msg *msg_fifo_pop(struct msg_fifo *fifo);
extern struct msg *msg_fifo_head(struct msg_fifo *fifo);
extern void msg_fifo_flush(struct msg_fifo *fifo);
extern void msg_fifo_free(struct msg_fifo *fifo);

/* -----------------------------------------------------------
 * Specific message type and format definitions
 * -----------------------------------------------------------
 */

/* Messages to OSPF daemon. */
#define MSG_REGISTER_OPAQUETYPE   1
#define MSG_UNREGISTER_OPAQUETYPE 2
#define MSG_REGISTER_EVENT        3
#define MSG_SYNC_LSDB             4
#define MSG_ORIGINATE_REQUEST     5
#define MSG_DELETE_REQUEST        6
#define MSG_SYNC_REACHABLE        7
#define MSG_SYNC_ISM              8
#define MSG_SYNC_NSM              9
#define MSG_SYNC_ROUTER_ID        19

/* Messages from OSPF daemon. */
#define MSG_REPLY                10
#define MSG_READY_NOTIFY         11
#define MSG_LSA_UPDATE_NOTIFY    12
#define MSG_LSA_DELETE_NOTIFY    13
#define MSG_NEW_IF               14
#define MSG_DEL_IF               15
#define MSG_ISM_CHANGE           16
#define MSG_NSM_CHANGE           17
#define MSG_REACHABLE_CHANGE     18
#define MSG_ROUTER_ID_CHANGE     20

struct msg_register_opaque_type {
	uint8_t lsatype;
	uint8_t opaquetype;
	uint8_t pad[2]; /* padding */
};

struct msg_unregister_opaque_type {
	uint8_t lsatype;
	uint8_t opaquetype;
	uint8_t pad[2]; /* padding */
};

/* Power2 is needed to convert LSA types into bit positions,
 * see typemask below. Type definition starts at 1, so
 * Power2[0] is not used. */


static const uint16_t Power2[] = {
	0,	 (1 << 0),  (1 << 1),  (1 << 2),  (1 << 3), (1 << 4),
	(1 << 5),  (1 << 6),  (1 << 7),  (1 << 8),  (1 << 9), (1 << 10),
	(1 << 11), (1 << 12), (1 << 13), (1 << 14), (1 << 15)};

struct lsa_filter_type {
	uint16_t typemask; /* bitmask for selecting LSA types (1..16) */
	uint8_t origin;    /* selects according to origin. */
#define NON_SELF_ORIGINATED	0
#define	SELF_ORIGINATED  (OSPF_LSA_SELF)
#define	ANY_ORIGIN 2

	uint8_t num_areas; /* number of areas in the filter. */
			   /* areas, if any, go here. */
};

struct msg_register_event {
	struct lsa_filter_type filter;
};

struct msg_sync_lsdb {
	struct lsa_filter_type filter;
};

struct msg_originate_request {
	/* Used for LSA type 9 otherwise ignored */
	struct in_addr ifaddr;

	/* Used for LSA type 10 otherwise ignored */
	struct in_addr area_id;

	/* LSA header and LSA-specific part */
	struct lsa_header data;
};


/* OSPF API MSG Delete Flag. */
#define OSPF_API_DEL_ZERO_LEN_LSA 0x01 /* send withdrawal with no LSA data */

#define IS_DEL_ZERO_LEN_LSA(x) ((x)->flags & OSPF_API_DEL_ZERO_LEN_LSA)

struct msg_delete_request {
	struct in_addr addr; /* intf IP for link local, area for type 10,
				"0.0.0.0" for AS-external */
	uint8_t lsa_type;
	uint8_t opaque_type;
	uint8_t pad;   /* padding */
	uint8_t flags; /* delete flags */
	uint32_t opaque_id;
};

struct msg_reply {
	signed char errcode;
#define OSPF_API_OK                         0
#define OSPF_API_NOSUCHINTERFACE          (-1)
#define OSPF_API_NOSUCHAREA               (-2)
#define OSPF_API_NOSUCHLSA                (-3)
#define OSPF_API_ILLEGALLSATYPE           (-4)
#define OSPF_API_OPAQUETYPEINUSE          (-5)
#define OSPF_API_OPAQUETYPENOTREGISTERED  (-6)
#define OSPF_API_NOTREADY                 (-7)
#define OSPF_API_NOMEMORY                 (-8)
#define OSPF_API_ERROR                    (-9)
#define OSPF_API_UNDEF                   (-10)
	uint8_t pad[3]; /* padding to four byte alignment */
};

/* Message to tell client application that it ospf daemon is
 * ready to accept opaque LSAs for a given interface or area. */

struct msg_ready_notify {
	uint8_t lsa_type;
	uint8_t opaque_type;
	uint8_t pad[2];      /* padding */
	struct in_addr addr; /* interface address or area address */
};

/* These messages have a dynamic length depending on the embodied LSA.
   They are aligned to four octets. msg_lsa_change_notify is used for
   both LSA update and LSAs delete. */

struct msg_lsa_change_notify {
	/* Used for LSA type 9 otherwise ignored */
	struct in_addr ifaddr;
	/* Area ID. Not valid for AS-External and Opaque11 LSAs. */
	struct in_addr area_id;
	uint8_t is_self_originated; /* 1 if self originated. */
	uint8_t pad[3];
	struct lsa_header data;
};

struct msg_new_if {
	struct in_addr ifaddr;  /* interface IP address */
	struct in_addr area_id; /* area this interface belongs to */
};

struct msg_del_if {
	struct in_addr ifaddr; /* interface IP address */
};

struct msg_ism_change {
	struct in_addr ifaddr;  /* interface IP address */
	struct in_addr area_id; /* area this interface belongs to */
	uint8_t status;		/* interface status (up/down) */
	uint8_t pad[3];		/* not used */
};

struct msg_nsm_change {
	struct in_addr ifaddr;    /* attached interface */
	struct in_addr nbraddr;   /* Neighbor interface address */
	struct in_addr router_id; /* Router ID of neighbor */
	uint8_t status;		  /* NSM status */
	uint8_t pad[3];
};

struct msg_reachable_change {
	uint16_t nadd;
	uint16_t nremove;
	struct in_addr router_ids[]; /* add followed by remove */
};

struct msg_router_id_change {
	struct in_addr router_id; /* this systems router id */
};

/* We make use of a union to define a structure that covers all
   possible API messages. This allows us to find out how much memory
   needs to be reserved for the largest API message. */
struct apimsg {
	struct apimsghdr hdr;
	union {
		struct msg_register_opaque_type register_opaque_type;
		struct msg_register_event register_event;
		struct msg_sync_lsdb sync_lsdb;
		struct msg_originate_request originate_request;
		struct msg_delete_request delete_request;
		struct msg_reply reply;
		struct msg_ready_notify ready_notify;
		struct msg_new_if new_if;
		struct msg_del_if del_if;
		struct msg_ism_change ism_change;
		struct msg_nsm_change nsm_change;
		struct msg_lsa_change_notify lsa_change_notify;
		struct msg_reachable_change reachable_change;
		struct msg_router_id_change router_id_change;
	} u;
};

#define OSPF_API_MAX_MSG_SIZE (sizeof(struct apimsg) + OSPF_MAX_PACKET_SIZE)

/* -----------------------------------------------------------
 * Prototypes for specific messages
 * -----------------------------------------------------------
 */

/* For debugging only. */
extern void api_opaque_lsa_print(struct ospf_lsa *lsa);

/* Messages sent by client */
extern struct msg *new_msg_register_opaque_type(uint32_t seqnum, uint8_t ltype,
						uint8_t otype);
extern struct msg *new_msg_register_event(uint32_t seqnum,
					  struct lsa_filter_type *filter);
extern struct msg *new_msg_sync_lsdb(uint32_t seqnum,
				     struct lsa_filter_type *filter);
extern struct msg *new_msg_originate_request(uint32_t seqnum,
					     struct in_addr ifaddr,
					     struct in_addr area_id,
					     struct lsa_header *data);
extern struct msg *new_msg_delete_request(uint32_t seqnum, struct in_addr addr,
					  uint8_t lsa_type, uint8_t opaque_type,
					  uint32_t opaque_id, uint8_t flags);

/* Messages sent by OSPF daemon */
extern struct msg *new_msg_reply(uint32_t seqnum, uint8_t rc);

extern struct msg *new_msg_ready_notify(uint32_t seqnr, uint8_t lsa_type,
					uint8_t opaque_type,
					struct in_addr addr);

extern struct msg *new_msg_new_if(uint32_t seqnr, struct in_addr ifaddr,
				  struct in_addr area);

extern struct msg *new_msg_del_if(uint32_t seqnr, struct in_addr ifaddr);

extern struct msg *new_msg_ism_change(uint32_t seqnr, struct in_addr ifaddr,
				      struct in_addr area, uint8_t status);

extern struct msg *new_msg_nsm_change(uint32_t seqnr, struct in_addr ifaddr,
				      struct in_addr nbraddr,
				      struct in_addr router_id, uint8_t status);

/* msgtype is MSG_LSA_UPDATE_NOTIFY or MSG_LSA_DELETE_NOTIFY */
extern struct msg *new_msg_lsa_change_notify(uint8_t msgtype, uint32_t seqnum,
					     struct in_addr ifaddr,
					     struct in_addr area_id,
					     uint8_t is_self_originated,
					     struct lsa_header *data);

extern struct msg *new_msg_reachable_change(uint32_t seqnum, uint16_t nadd,
					    struct in_addr *add,
					    uint16_t nremove,
					    struct in_addr *remove);

extern struct msg *new_msg_router_id_change(uint32_t seqnr,
					    struct in_addr router_id);
/* string printing functions */
extern const char *ospf_api_errname(int errcode);
extern const char *ospf_api_typename(int msgtype);

#endif /* _OSPF_API_H */
