// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * API message handling module for OSPF daemon and client.
 * Copyright (C) 2001, 2002 Ralph Keller
 * Copyright (c) 2022, LabN Consulting, L.L.C.
 */

#include <zebra.h>

#ifdef SUPPORT_OSPF_API

#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "memory.h"
#include "command.h"
#include "vty.h"
#include "stream.h"
#include "log.h"
#include "frrevent.h"
#include "hash.h"
#include "sockunion.h" /* for inet_aton() */
#include "buffer.h"
#include "network.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_ase.h"
#include "ospfd/ospf_zebra.h"

#include "ospfd/ospf_api.h"


/* For debugging only, will be removed */
void api_opaque_lsa_print(struct ospf_lsa *lsa)
{
	struct opaque_lsa {
		struct lsa_header header;
		uint8_t mydata[];
	};

	struct opaque_lsa *olsa;
	int opaquelen;
	int i;

	ospf_lsa_header_dump(lsa->data);

	olsa = (struct opaque_lsa *)lsa->data;

	opaquelen = lsa->size - OSPF_LSA_HEADER_SIZE;
	zlog_debug("apiserver_lsa_print: opaquelen=%d", opaquelen);

	for (i = 0; i < opaquelen; i++) {
		zlog_debug("0x%x ", olsa->mydata[i]);
	}
	zlog_debug(" ");
}

/* -----------------------------------------------------------
 * Generic messages
 * -----------------------------------------------------------
 */

struct msg *msg_new(uint8_t msgtype, void *msgbody, uint32_t seqnum,
		    uint16_t msglen)
{
	struct msg *new;

	new = XCALLOC(MTYPE_OSPF_API_MSG, sizeof(struct msg));

	new->hdr.version = OSPF_API_VERSION;
	new->hdr.msgtype = msgtype;
	new->hdr.msglen = htons(msglen);
	new->hdr.msgseq = htonl(seqnum);

	new->s = stream_new(msglen);
	assert(new->s);
	stream_put(new->s, msgbody, msglen);

	return new;
}


/* Duplicate a message by copying content. */
struct msg *msg_dup(struct msg *msg)
{
	struct msg *new;
	size_t size;

	assert(msg);

	size = ntohs(msg->hdr.msglen);
	if (size > OSPF_MAX_LSA_SIZE)
		return NULL;

	new = msg_new(msg->hdr.msgtype, STREAM_DATA(msg->s),
		      ntohl(msg->hdr.msgseq), size);
	return new;
}


/* XXX only for testing, will be removed */

struct nametab {
	int value;
	const char *name;
};

const char *ospf_api_typename(int msgtype)
{
	struct nametab NameTab[] = {
		{
			MSG_REGISTER_OPAQUETYPE, "Register opaque-type",
		},
		{
			MSG_UNREGISTER_OPAQUETYPE, "Unregister opaque-type",
		},
		{
			MSG_REGISTER_EVENT, "Register event",
		},
		{
			MSG_SYNC_LSDB, "Sync LSDB",
		},
		{
			MSG_ORIGINATE_REQUEST, "Originate request",
		},
		{
			MSG_DELETE_REQUEST, "Delete request",
		},
		{
			MSG_REPLY, "Reply",
		},
		{
			MSG_READY_NOTIFY, "Ready notify",
		},
		{
			MSG_LSA_UPDATE_NOTIFY, "LSA update notify",
		},
		{
			MSG_LSA_DELETE_NOTIFY, "LSA delete notify",
		},
		{
			MSG_NEW_IF, "New interface",
		},
		{
			MSG_DEL_IF, "Del interface",
		},
		{
			MSG_ISM_CHANGE, "ISM change",
		},
		{
			MSG_NSM_CHANGE, "NSM change",
		},
		{
			MSG_REACHABLE_CHANGE,
			"Reachable change",
		},
	};

	int i, n = array_size(NameTab);
	const char *name = NULL;

	for (i = 0; i < n; i++) {
		if (NameTab[i].value == msgtype) {
			name = NameTab[i].name;
			break;
		}
	}

	return name ? name : "?";
}

const char *ospf_api_errname(int errcode)
{
	struct nametab NameTab[] = {
		{
			OSPF_API_OK, "OK",
		},
		{
			OSPF_API_NOSUCHINTERFACE, "No such interface",
		},
		{
			OSPF_API_NOSUCHAREA, "No such area",
		},
		{
			OSPF_API_NOSUCHLSA, "No such LSA",
		},
		{
			OSPF_API_ILLEGALLSATYPE, "Illegal LSA type",
		},
		{
			OSPF_API_OPAQUETYPEINUSE, "Opaque type in use",
		},
		{
			OSPF_API_OPAQUETYPENOTREGISTERED,
			"Opaque type not registered",
		},
		{
			OSPF_API_NOTREADY, "Not ready",
		},
		{
			OSPF_API_NOMEMORY, "No memory",
		},
		{
			OSPF_API_ERROR, "Other error",
		},
		{
			OSPF_API_UNDEF, "Undefined",
		},
	};

	int i, n = array_size(NameTab);
	const char *name = NULL;

	for (i = 0; i < n; i++) {
		if (NameTab[i].value == errcode) {
			name = NameTab[i].name;
			break;
		}
	}

	return name ? name : "?";
}

void msg_print(struct msg *msg)
{
	if (!msg) {
		zlog_debug("msg_print msg=NULL!");
		return;
	}

	/* API message common header part. */
	zlog_debug("API-msg [%s]: type(%d),len(%d),seq(%lu),data(%p),size(%zd)",
		   ospf_api_typename(msg->hdr.msgtype), msg->hdr.msgtype,
		   ntohs(msg->hdr.msglen),
		   (unsigned long)ntohl(msg->hdr.msgseq), STREAM_DATA(msg->s),
		   STREAM_SIZE(msg->s));

	return;
}

void msg_free(struct msg *msg)
{
	if (msg->s)
		stream_free(msg->s);

	XFREE(MTYPE_OSPF_API_MSG, msg);
}


/* Set sequence number of message */
void msg_set_seq(struct msg *msg, uint32_t seqnr)
{
	assert(msg);
	msg->hdr.msgseq = htonl(seqnr);
}

/* Get sequence number of message */
uint32_t msg_get_seq(struct msg *msg)
{
	assert(msg);
	return ntohl(msg->hdr.msgseq);
}

/* -----------------------------------------------------------
 * Message fifo queues
 * -----------------------------------------------------------
 */

struct msg_fifo *msg_fifo_new(void)
{
	return XCALLOC(MTYPE_OSPF_API_FIFO, sizeof(struct msg_fifo));
}

/* Add new message to fifo. */
void msg_fifo_push(struct msg_fifo *fifo, struct msg *msg)
{
	if (fifo->tail)
		fifo->tail->next = msg;
	else
		fifo->head = msg;

	fifo->tail = msg;
	fifo->count++;
}


/* Remove first message from fifo. */
struct msg *msg_fifo_pop(struct msg_fifo *fifo)
{
	struct msg *msg;

	msg = fifo->head;
	if (msg) {
		fifo->head = msg->next;

		if (fifo->head == NULL)
			fifo->tail = NULL;

		fifo->count--;
	}
	return msg;
}

/* Return first fifo entry but do not remove it. */
struct msg *msg_fifo_head(struct msg_fifo *fifo)
{
	return fifo->head;
}

/* Flush message fifo. */
void msg_fifo_flush(struct msg_fifo *fifo)
{
	struct msg *op;
	struct msg *next;

	for (op = fifo->head; op; op = next) {
		next = op->next;
		msg_free(op);
	}

	fifo->head = fifo->tail = NULL;
	fifo->count = 0;
}

/* Free API message fifo. */
void msg_fifo_free(struct msg_fifo *fifo)
{
	msg_fifo_flush(fifo);

	XFREE(MTYPE_OSPF_API_FIFO, fifo);
}

struct msg *msg_read(int fd)
{
	struct msg *msg;
	struct apimsghdr hdr;
	uint8_t buf[OSPF_API_MAX_MSG_SIZE];
	ssize_t bodylen;
	ssize_t rlen;

	/* Read message header */
	rlen = readn(fd, (uint8_t *)&hdr, sizeof(struct apimsghdr));

	if (rlen < 0) {
		zlog_warn("msg_read: readn %s", safe_strerror(errno));
		return NULL;
	} else if (rlen == 0) {
		zlog_warn("msg_read: Connection closed by peer");
		return NULL;
	} else if (rlen != sizeof(struct apimsghdr)) {
		zlog_warn("msg_read: Cannot read message header!");
		return NULL;
	}

	/* Check version of API protocol */
	if (hdr.version != OSPF_API_VERSION) {
		zlog_warn("msg_read: OSPF API protocol version mismatch");
		return NULL;
	}

	/* Determine body length. */
	bodylen = ntohs(hdr.msglen);
	if (bodylen > (ssize_t)sizeof(buf)) {
		zlog_warn("%s: Body Length of message greater than what we can read",
			  __func__);
		return NULL;
	}

	if (bodylen > 0) {
		/* Read message body */
		rlen = readn(fd, buf, bodylen);
		if (rlen < 0) {
			zlog_warn("msg_read: readn %s", safe_strerror(errno));
			return NULL;
		} else if (rlen == 0) {
			zlog_warn("msg_read: Connection closed by peer");
			return NULL;
		} else if (rlen != bodylen) {
			zlog_warn("msg_read: Cannot read message body!");
			return NULL;
		}
	}

	/* Allocate new message */
	msg = msg_new(hdr.msgtype, buf, ntohl(hdr.msgseq), bodylen);

	return msg;
}

int msg_write(int fd, struct msg *msg)
{
	uint8_t buf[OSPF_API_MAX_MSG_SIZE];
	uint16_t l;
	int wlen;

	assert(msg);
	assert(msg->s);

	/* Length of OSPF LSA payload */
	l = ntohs(msg->hdr.msglen);
	if (l > OSPF_MAX_LSA_SIZE) {
		zlog_warn("%s: wrong LSA size %d", __func__, l);
		return -1;
	}

	/* Make contiguous memory buffer for message */
	memcpy(buf, &msg->hdr, sizeof(struct apimsghdr));
	memcpy(buf + sizeof(struct apimsghdr), STREAM_DATA(msg->s), l);

	/* Total length of OSPF API Message */
	l += sizeof(struct apimsghdr);
	wlen = writen(fd, buf, l);
	if (wlen < 0) {
		zlog_warn("%s: writen %s", __func__, safe_strerror(errno));
		return -1;
	} else if (wlen == 0) {
		zlog_warn("%s: Connection closed by peer", __func__);
		return -1;
	} else if (wlen != l) {
		zlog_warn("%s: Cannot write API message", __func__);
		return -1;
	}
	return 0;
}

/* -----------------------------------------------------------
 * Specific messages
 * -----------------------------------------------------------
 */

struct msg *new_msg_register_opaque_type(uint32_t seqnum, uint8_t ltype,
					 uint8_t otype)
{
	struct msg_register_opaque_type rmsg;

	rmsg.lsatype = ltype;
	rmsg.opaquetype = otype;
	memset(&rmsg.pad, 0, sizeof(rmsg.pad));

	return msg_new(MSG_REGISTER_OPAQUETYPE, &rmsg, seqnum,
		       sizeof(struct msg_register_opaque_type));
}

struct msg *new_msg_register_event(uint32_t seqnum,
				   struct lsa_filter_type *filter)
{
	uint8_t buf[OSPF_API_MAX_MSG_SIZE];
	struct msg_register_event *emsg;
	unsigned int len;

	emsg = (struct msg_register_event *)buf;
	len = sizeof(struct msg_register_event)
	      + filter->num_areas * sizeof(struct in_addr);
	emsg->filter.typemask = htons(filter->typemask);
	emsg->filter.origin = filter->origin;
	emsg->filter.num_areas = filter->num_areas;
	if (len > sizeof(buf))
		len = sizeof(buf);
	/* API broken - missing memcpy to fill data */
	return msg_new(MSG_REGISTER_EVENT, emsg, seqnum, len);
}

struct msg *new_msg_sync_lsdb(uint32_t seqnum, struct lsa_filter_type *filter)
{
	uint8_t buf[OSPF_API_MAX_MSG_SIZE];
	struct msg_sync_lsdb *smsg;
	unsigned int len;

	smsg = (struct msg_sync_lsdb *)buf;
	len = sizeof(struct msg_sync_lsdb)
	      + filter->num_areas * sizeof(struct in_addr);
	smsg->filter.typemask = htons(filter->typemask);
	smsg->filter.origin = filter->origin;
	smsg->filter.num_areas = filter->num_areas;
	if (len > sizeof(buf))
		len = sizeof(buf);
	/* API broken - missing memcpy to fill data */
	return msg_new(MSG_SYNC_LSDB, smsg, seqnum, len);
}


struct msg *new_msg_originate_request(uint32_t seqnum, struct in_addr ifaddr,
				      struct in_addr area_id,
				      struct lsa_header *data)
{
	struct msg_originate_request *omsg;
	unsigned int omsglen;
	char buf[OSPF_API_MAX_MSG_SIZE];
	size_t off_data = offsetof(struct msg_originate_request, data);
	size_t data_maxs = sizeof(buf) - off_data;
	struct lsa_header *omsg_data = (struct lsa_header *)&buf[off_data];

	omsg = (struct msg_originate_request *)buf;
	omsg->ifaddr = ifaddr;
	omsg->area_id = area_id;

	omsglen = ntohs(data->length);
	if (omsglen > data_maxs)
		omsglen = data_maxs;
	memcpy(omsg_data, data, omsglen);
	omsglen += sizeof(struct msg_originate_request)
		   - sizeof(struct lsa_header);

	return msg_new(MSG_ORIGINATE_REQUEST, omsg, seqnum, omsglen);
}

struct msg *new_msg_delete_request(uint32_t seqnum, struct in_addr addr,
				   uint8_t lsa_type, uint8_t opaque_type,
				   uint32_t opaque_id, uint8_t flags)
{
	struct msg_delete_request dmsg;
	dmsg.addr = addr;
	dmsg.lsa_type = lsa_type;
	dmsg.opaque_type = opaque_type;
	dmsg.opaque_id = htonl(opaque_id);
	memset(&dmsg.pad, 0, sizeof(dmsg.pad));
	dmsg.flags = flags;

	return msg_new(MSG_DELETE_REQUEST, &dmsg, seqnum,
		       sizeof(struct msg_delete_request));
}


struct msg *new_msg_reply(uint32_t seqnr, uint8_t rc)
{
	struct msg *msg;
	struct msg_reply rmsg;

	/* Set return code */
	rmsg.errcode = rc;
	memset(&rmsg.pad, 0, sizeof(rmsg.pad));

	msg = msg_new(MSG_REPLY, &rmsg, seqnr, sizeof(struct msg_reply));

	return msg;
}

struct msg *new_msg_ready_notify(uint32_t seqnr, uint8_t lsa_type,
				 uint8_t opaque_type, struct in_addr addr)
{
	struct msg_ready_notify rmsg;

	rmsg.lsa_type = lsa_type;
	rmsg.opaque_type = opaque_type;
	memset(&rmsg.pad, 0, sizeof(rmsg.pad));
	rmsg.addr = addr;

	return msg_new(MSG_READY_NOTIFY, &rmsg, seqnr,
		       sizeof(struct msg_ready_notify));
}

struct msg *new_msg_new_if(uint32_t seqnr, struct in_addr ifaddr,
			   struct in_addr area_id)
{
	struct msg_new_if nmsg;

	nmsg.ifaddr = ifaddr;
	nmsg.area_id = area_id;

	return msg_new(MSG_NEW_IF, &nmsg, seqnr, sizeof(struct msg_new_if));
}

struct msg *new_msg_del_if(uint32_t seqnr, struct in_addr ifaddr)
{
	struct msg_del_if dmsg;

	dmsg.ifaddr = ifaddr;

	return msg_new(MSG_DEL_IF, &dmsg, seqnr, sizeof(struct msg_del_if));
}

struct msg *new_msg_ism_change(uint32_t seqnr, struct in_addr ifaddr,
			       struct in_addr area_id, uint8_t status)
{
	struct msg_ism_change imsg;

	imsg.ifaddr = ifaddr;
	imsg.area_id = area_id;
	imsg.status = status;
	memset(&imsg.pad, 0, sizeof(imsg.pad));

	return msg_new(MSG_ISM_CHANGE, &imsg, seqnr,
		       sizeof(struct msg_ism_change));
}

struct msg *new_msg_nsm_change(uint32_t seqnr, struct in_addr ifaddr,
			       struct in_addr nbraddr, struct in_addr router_id,
			       uint8_t status)
{
	struct msg_nsm_change nmsg;

	nmsg.ifaddr = ifaddr;
	nmsg.nbraddr = nbraddr;
	nmsg.router_id = router_id;
	nmsg.status = status;
	memset(&nmsg.pad, 0, sizeof(nmsg.pad));

	return msg_new(MSG_NSM_CHANGE, &nmsg, seqnr,
		       sizeof(struct msg_nsm_change));
}

struct msg *new_msg_lsa_change_notify(uint8_t msgtype, uint32_t seqnum,
				      struct in_addr ifaddr,
				      struct in_addr area_id,
				      uint8_t is_self_originated,
				      struct lsa_header *data)
{
	uint8_t buf[OSPF_API_MAX_MSG_SIZE];
	struct msg_lsa_change_notify *nmsg;
	unsigned int len;
	size_t off_data = offsetof(struct msg_lsa_change_notify, data);
	size_t data_maxs = sizeof(buf) - off_data;
	struct lsa_header *nmsg_data = (struct lsa_header *)&buf[off_data];

	assert(data);

	nmsg = (struct msg_lsa_change_notify *)buf;
	nmsg->ifaddr = ifaddr;
	nmsg->area_id = area_id;
	nmsg->is_self_originated = is_self_originated;
	memset(&nmsg->pad, 0, sizeof(nmsg->pad));

	len = ntohs(data->length);
	if (len > data_maxs)
		len = data_maxs;
	memcpy(nmsg_data, data, len);
	len += sizeof(struct msg_lsa_change_notify) - sizeof(struct lsa_header);

	return msg_new(msgtype, nmsg, seqnum, len);
}

struct msg *new_msg_reachable_change(uint32_t seqnum, uint16_t nadd,
				     struct in_addr *add, uint16_t nremove,
				     struct in_addr *remove)
{
	uint8_t buf[OSPF_API_MAX_MSG_SIZE];
	struct msg_reachable_change *nmsg = (void *)buf;
	const uint insz = sizeof(*nmsg->router_ids);
	const uint nmax = (sizeof(buf) - sizeof(*nmsg)) / insz;
	uint len;

	if (nadd > nmax)
		nadd = nmax;
	if (nremove > (nmax - nadd))
		nremove = (nmax - nadd);

	if (nadd)
		memcpy(nmsg->router_ids, add, nadd * insz);
	if (nremove)
		memcpy(&nmsg->router_ids[nadd], remove, nremove * insz);

	nmsg->nadd = htons(nadd);
	nmsg->nremove = htons(nremove);
	len = sizeof(*nmsg) + insz * (nadd + nremove);

	return msg_new(MSG_REACHABLE_CHANGE, nmsg, seqnum, len);
}

struct msg *new_msg_router_id_change(uint32_t seqnum, struct in_addr router_id)
{
	struct msg_router_id_change rmsg = {.router_id = router_id};

	return msg_new(MSG_ROUTER_ID_CHANGE, &rmsg, seqnum,
		       sizeof(struct msg_router_id_change));
}

#endif /* SUPPORT_OSPF_API */
