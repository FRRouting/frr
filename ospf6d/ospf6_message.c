// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#include <zebra.h>

#include "memory.h"
#include "log.h"
#include "vty.h"
#include "command.h"
#include "frrevent.h"
#include "linklist.h"
#include "lib_errors.h"
#include "checksum.h"
#include "network.h"

#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_top.h"
#include "ospf6_network.h"
#include "ospf6_message.h"

#include "ospf6_area.h"
#include "ospf6_neighbor.h"
#include "ospf6_interface.h"

/* for structures and macros ospf6_lsa_examin() needs */
#include "ospf6_abr.h"
#include "ospf6_asbr.h"
#include "ospf6_intra.h"

#include "ospf6_flood.h"
#include "ospf6d.h"
#include "ospf6_gr.h"
#include <netinet/ip6.h>
#include "lib/libospf.h"
#include "lib/keychain.h"
#include "ospf6_auth_trailer.h"

DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_MESSAGE, "OSPF6 message");
DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_PACKET, "OSPF6 packet");
DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_FIFO, "OSPF6  FIFO queue");

unsigned char conf_debug_ospf6_message[6] = {0x03, 0, 0, 0, 0, 0};

const char *ospf6_message_type(int type)
{
	switch (type) {
	case OSPF6_MESSAGE_TYPE_HELLO:
		return "Hello";
	case OSPF6_MESSAGE_TYPE_DBDESC:
		return "DbDesc";
	case OSPF6_MESSAGE_TYPE_LSREQ:
		return "LSReq";
	case OSPF6_MESSAGE_TYPE_LSUPDATE:
		return "LSUpdate";
	case OSPF6_MESSAGE_TYPE_LSACK:
		return "LSAck";
	case OSPF6_MESSAGE_TYPE_UNKNOWN:
	default:
		return "unknown";
	}
}

/* Minimum (besides the standard OSPF packet header) lengths for OSPF
   packets of particular types, offset is the "type" field. */
const uint16_t ospf6_packet_minlen[OSPF6_MESSAGE_TYPE_ALL] = {
	0,
	OSPF6_HELLO_MIN_SIZE,
	OSPF6_DB_DESC_MIN_SIZE,
	OSPF6_LS_REQ_MIN_SIZE,
	OSPF6_LS_UPD_MIN_SIZE,
	OSPF6_LS_ACK_MIN_SIZE};

/* Minimum (besides the standard LSA header) lengths for LSAs of particular
   types, offset is the "LSA function code" portion of "LSA type" field. */
const uint16_t ospf6_lsa_minlen[OSPF6_LSTYPE_SIZE] = {
	0,
	/* 0x2001 */ OSPF6_ROUTER_LSA_MIN_SIZE,
	/* 0x2002 */ OSPF6_NETWORK_LSA_MIN_SIZE,
	/* 0x2003 */ OSPF6_INTER_PREFIX_LSA_MIN_SIZE,
	/* 0x2004 */ OSPF6_INTER_ROUTER_LSA_FIX_SIZE,
	/* 0x4005 */ OSPF6_AS_EXTERNAL_LSA_MIN_SIZE,
	/* 0x2006 */ 0,
	/* 0x2007 */ OSPF6_AS_EXTERNAL_LSA_MIN_SIZE,
	/* 0x0008 */ OSPF6_LINK_LSA_MIN_SIZE,
	/* 0x2009 */ OSPF6_INTRA_PREFIX_LSA_MIN_SIZE,
	/* 0x200a */ 0,
	/* 0x000b */ OSPF6_GRACE_LSA_MIN_SIZE};

/* print functions */

static void ospf6_header_print(struct ospf6_header *oh)
{
	zlog_debug("    OSPFv%d Type:%d Len:%hu Router-ID:%pI4", oh->version,
		   oh->type, ntohs(oh->length), &oh->router_id);
	zlog_debug("    Area-ID:%pI4 Cksum:%hx Instance-ID:%d", &oh->area_id,
		   ntohs(oh->checksum), oh->instance_id);
}

void ospf6_hello_print(struct ospf6_header *oh, int action)
{
	struct ospf6_hello *hello;
	char options[32];
	char *p;

	ospf6_header_print(oh);
	assert(oh->type == OSPF6_MESSAGE_TYPE_HELLO);

	hello = (struct ospf6_hello *)((caddr_t)oh
				       + sizeof(struct ospf6_header));

	ospf6_options_printbuf(hello->options, options, sizeof(options));

	zlog_debug("    I/F-Id:%ld Priority:%d Option:%s",
		   (unsigned long)ntohl(hello->interface_id), hello->priority,
		   options);
	zlog_debug("    HelloInterval:%hu DeadInterval:%hu",
		   ntohs(hello->hello_interval), ntohs(hello->dead_interval));
	zlog_debug("    DR:%pI4 BDR:%pI4", &hello->drouter, &hello->bdrouter);

	if ((IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV)
	     && action == OSPF6_ACTION_RECV)
	    || (IS_OSPF6_DEBUG_MESSAGE(oh->type, SEND)
		&& action == OSPF6_ACTION_SEND)) {

		for (p = (char *)((caddr_t)hello + sizeof(struct ospf6_hello));
		     p + sizeof(uint32_t) <= OSPF6_MESSAGE_END(oh);
		     p += sizeof(uint32_t))
			zlog_debug("    Neighbor: %pI4", (in_addr_t *)p);

		assert(p == OSPF6_MESSAGE_END(oh));
	}
}

void ospf6_dbdesc_print(struct ospf6_header *oh, int action)
{
	struct ospf6_dbdesc *dbdesc;
	char options[32];
	char *p;

	ospf6_header_print(oh);
	assert(oh->type == OSPF6_MESSAGE_TYPE_DBDESC);

	dbdesc = (struct ospf6_dbdesc *)((caddr_t)oh
					 + sizeof(struct ospf6_header));

	ospf6_options_printbuf(dbdesc->options, options, sizeof(options));

	zlog_debug("    MBZ: %#x Option: %s IfMTU: %hu", dbdesc->reserved1,
		   options, ntohs(dbdesc->ifmtu));
	zlog_debug("    MBZ: %#x Bits: %s%s%s SeqNum: %#lx", dbdesc->reserved2,
		   (CHECK_FLAG(dbdesc->bits, OSPF6_DBDESC_IBIT) ? "I" : "-"),
		   (CHECK_FLAG(dbdesc->bits, OSPF6_DBDESC_MBIT) ? "M" : "-"),
		   (CHECK_FLAG(dbdesc->bits, OSPF6_DBDESC_MSBIT) ? "m" : "s"),
		   (unsigned long)ntohl(dbdesc->seqnum));

	if ((IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV)
	     && action == OSPF6_ACTION_RECV)
	    || (IS_OSPF6_DEBUG_MESSAGE(oh->type, SEND)
		&& action == OSPF6_ACTION_SEND)) {

		for (p = (char *)((caddr_t)dbdesc
				  + sizeof(struct ospf6_dbdesc));
		     p + sizeof(struct ospf6_lsa_header)
		     <= OSPF6_MESSAGE_END(oh);
		     p += sizeof(struct ospf6_lsa_header))
			ospf6_lsa_header_print_raw(
				(struct ospf6_lsa_header *)p);

		assert(p == OSPF6_MESSAGE_END(oh));
	}
}

void ospf6_lsreq_print(struct ospf6_header *oh, int action)
{
	char *p;

	ospf6_header_print(oh);
	assert(oh->type == OSPF6_MESSAGE_TYPE_LSREQ);

	if ((IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV)
	     && action == OSPF6_ACTION_RECV)
	    || (IS_OSPF6_DEBUG_MESSAGE(oh->type, SEND)
		&& action == OSPF6_ACTION_SEND)) {

		for (p = (char *)((caddr_t)oh + sizeof(struct ospf6_header));
		     p + sizeof(struct ospf6_lsreq_entry)
		     <= OSPF6_MESSAGE_END(oh);
		     p += sizeof(struct ospf6_lsreq_entry)) {
			struct ospf6_lsreq_entry *e =
				(struct ospf6_lsreq_entry *)p;

			zlog_debug("    [%s Id:%pI4 Adv:%pI4]",
				   ospf6_lstype_name(e->type), &e->id,
				   &e->adv_router);
		}

		assert(p == OSPF6_MESSAGE_END(oh));
	}
}

void ospf6_lsupdate_print(struct ospf6_header *oh, int action)
{
	struct ospf6_lsupdate *lsupdate;
	unsigned long num;
	char *p;

	ospf6_header_print(oh);
	assert(oh->type == OSPF6_MESSAGE_TYPE_LSUPDATE);

	lsupdate = (struct ospf6_lsupdate *)((caddr_t)oh
					     + sizeof(struct ospf6_header));

	num = ntohl(lsupdate->lsa_number);
	zlog_debug("    Number of LSA: %ld", num);

	if ((IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV)
	     && action == OSPF6_ACTION_RECV)
	    || (IS_OSPF6_DEBUG_MESSAGE(oh->type, SEND)
		&& action == OSPF6_ACTION_SEND)) {

		for (p = (char *)((caddr_t)lsupdate
				  + sizeof(struct ospf6_lsupdate));
		     p < OSPF6_MESSAGE_END(oh)
		     && p + OSPF6_LSA_SIZE(p) <= OSPF6_MESSAGE_END(oh);
		     p += OSPF6_LSA_SIZE(p)) {
			ospf6_lsa_header_print_raw(
				(struct ospf6_lsa_header *)p);
		}

		assert(p == OSPF6_MESSAGE_END(oh));
	}
}

void ospf6_lsack_print(struct ospf6_header *oh, int action)
{
	char *p;

	ospf6_header_print(oh);
	assert(oh->type == OSPF6_MESSAGE_TYPE_LSACK);

	if ((IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV)
	     && action == OSPF6_ACTION_RECV)
	    || (IS_OSPF6_DEBUG_MESSAGE(oh->type, SEND)
		&& action == OSPF6_ACTION_SEND)) {

		for (p = (char *)((caddr_t)oh + sizeof(struct ospf6_header));
		     p + sizeof(struct ospf6_lsa_header)
		     <= OSPF6_MESSAGE_END(oh);
		     p += sizeof(struct ospf6_lsa_header))
			ospf6_lsa_header_print_raw(
				(struct ospf6_lsa_header *)p);

		assert(p == OSPF6_MESSAGE_END(oh));
	}
}

static struct ospf6_packet *ospf6_packet_new(size_t size)
{
	struct ospf6_packet *new;

	new = XCALLOC(MTYPE_OSPF6_PACKET, sizeof(struct ospf6_packet));
	new->s = stream_new(size);

	return new;
}

static struct ospf6_packet *ospf6_packet_dup(struct ospf6_packet *old)
{
	struct ospf6_packet *new;

	new = XCALLOC(MTYPE_OSPF6_PACKET, sizeof(struct ospf6_packet));
	new->s = stream_dup(old->s);
	new->dst = old->dst;
	new->length = old->length;

	return new;
}

static void ospf6_packet_free(struct ospf6_packet *op)
{
	if (op->s)
		stream_free(op->s);

	XFREE(MTYPE_OSPF6_PACKET, op);
}

struct ospf6_fifo *ospf6_fifo_new(void)
{
	struct ospf6_fifo *new;

	new = XCALLOC(MTYPE_OSPF6_FIFO, sizeof(struct ospf6_fifo));
	return new;
}

/* Add new packet to fifo. */
static void ospf6_fifo_push(struct ospf6_fifo *fifo, struct ospf6_packet *op)
{
	if (fifo->tail)
		fifo->tail->next = op;
	else
		fifo->head = op;

	fifo->tail = op;

	fifo->count++;
}

/* Add new packet to head of fifo. */
static void ospf6_fifo_push_head(struct ospf6_fifo *fifo,
				 struct ospf6_packet *op)
{
	op->next = fifo->head;

	if (fifo->tail == NULL)
		fifo->tail = op;

	fifo->head = op;

	fifo->count++;
}

/* Delete first packet from fifo. */
static struct ospf6_packet *ospf6_fifo_pop(struct ospf6_fifo *fifo)
{
	struct ospf6_packet *op;

	op = fifo->head;

	if (op) {
		fifo->head = op->next;

		if (fifo->head == NULL)
			fifo->tail = NULL;

		fifo->count--;
	}

	return op;
}

/* Return first fifo entry. */
static struct ospf6_packet *ospf6_fifo_head(struct ospf6_fifo *fifo)
{
	return fifo->head;
}

/* Flush ospf packet fifo. */
void ospf6_fifo_flush(struct ospf6_fifo *fifo)
{
	struct ospf6_packet *op;
	struct ospf6_packet *next;

	for (op = fifo->head; op; op = next) {
		next = op->next;
		ospf6_packet_free(op);
	}
	fifo->head = fifo->tail = NULL;
	fifo->count = 0;
}

/* Free ospf packet fifo. */
void ospf6_fifo_free(struct ospf6_fifo *fifo)
{
	ospf6_fifo_flush(fifo);

	XFREE(MTYPE_OSPF6_FIFO, fifo);
}

static void ospf6_packet_add(struct ospf6_interface *oi,
			     struct ospf6_packet *op)
{
	/* Add packet to end of queue. */
	ospf6_fifo_push(oi->obuf, op);

	/* Debug of packet fifo*/
	/* ospf_fifo_debug (oi->obuf); */
}

static void ospf6_packet_add_top(struct ospf6_interface *oi,
				 struct ospf6_packet *op)
{
	/* Add packet to head of queue. */
	ospf6_fifo_push_head(oi->obuf, op);

	/* Debug of packet fifo*/
	/* ospf_fifo_debug (oi->obuf); */
}

static void ospf6_packet_delete(struct ospf6_interface *oi)
{
	struct ospf6_packet *op;

	op = ospf6_fifo_pop(oi->obuf);

	if (op)
		ospf6_packet_free(op);
}


static void ospf6_hello_recv(struct in6_addr *src, struct in6_addr *dst,
			     struct ospf6_interface *oi,
			     struct ospf6_header *oh)
{
	struct ospf6_hello *hello;
	struct ospf6_neighbor *on;
	char *p;
	int twoway = 0;
	int neighborchange = 0;
	int neighbor_ifindex_change = 0;
	int backupseen = 0;
	int64_t latency = 0;
	struct timeval timestamp;

	monotime(&timestamp);
	hello = (struct ospf6_hello *)((caddr_t)oh
				       + sizeof(struct ospf6_header));

	if ((oi->state == OSPF6_INTERFACE_POINTTOPOINT
	     || oi->state == OSPF6_INTERFACE_POINTTOMULTIPOINT)
	    && oi->p2xp_only_cfg_neigh) {
		/* NEVER, never, ever, do this on broadcast (or NBMA)!
		 * DR/BDR election requires everyone to talk to everyone else
		 * only for PtP/PtMP we can be selective in adjacencies!
		 */
		struct ospf6_if_p2xp_neighcfg *p2xp_cfg;

		p2xp_cfg = ospf6_if_p2xp_find(oi, src);
		if (!p2xp_cfg) {
			if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV_HDR))
				zlog_debug(
					"ignoring PtP/PtMP hello from %pI6, neighbor not configured",
					src);
			return;
		}
	}

	/* HelloInterval check */
	if (ntohs(hello->hello_interval) != oi->hello_interval) {
		zlog_warn(
			"VRF %s: I/F %s HelloInterval mismatch from %pI6 (%pI4): (my %d, rcvd %d)",
			oi->interface->vrf->name, oi->interface->name, src,
			&oh->router_id, oi->hello_interval,
			ntohs(hello->hello_interval));
		return;
	}

	/* RouterDeadInterval check */
	if (ntohs(hello->dead_interval) != oi->dead_interval) {
		zlog_warn(
			"VRF %s: I/F %s DeadInterval mismatch from %pI6 (%pI4): (my %d, rcvd %d)",
			oi->interface->vrf->name, oi->interface->name, src,
			&oh->router_id, oi->dead_interval,
			ntohs(hello->dead_interval));
		return;
	}

	/* E-bit check */
	if (OSPF6_OPT_ISSET(hello->options, OSPF6_OPT_E) !=
	    OSPF6_OPT_ISSET(oi->area->options, OSPF6_OPT_E)) {
		zlog_warn("VRF %s: IF %s E-bit mismatch from %pI6 (%pI4)",
			  oi->interface->vrf->name, oi->interface->name, src,
			  &oh->router_id);
		return;
	}

	/* N-bit check */
	if (OSPF6_OPT_ISSET(hello->options, OSPF6_OPT_N)
	    != OSPF6_OPT_ISSET(oi->area->options, OSPF6_OPT_N)) {
		zlog_warn("VRF %s: IF %s N-bit mismatch",
			  oi->interface->vrf->name, oi->interface->name);
		return;
	}

	if (((OSPF6_OPT_ISSET_EXT(hello->options, OSPF6_OPT_AT) ==
	      OSPF6_OPT_AT) &&
	     (oi->at_data.flags == 0)) ||
	    ((OSPF6_OPT_ISSET_EXT(hello->options, OSPF6_OPT_AT) !=
	      OSPF6_OPT_AT) &&
	     (oi->at_data.flags != 0))) {
		if (IS_OSPF6_DEBUG_AUTH_RX)
			zlog_warn(
				"VRF %s: IF %s AT-bit mismatch in hello packet",
				oi->interface->vrf->name, oi->interface->name);
		oi->at_data.rx_drop++;
		return;
	}

	/* Find neighbor, create if not exist */
	on = ospf6_neighbor_lookup(oh->router_id, oi);
	if (on == NULL) {
		on = ospf6_neighbor_create(oh->router_id, oi);
		on->prev_drouter = on->drouter = hello->drouter;
		on->prev_bdrouter = on->bdrouter = hello->bdrouter;
		on->priority = hello->priority;
	}

	/* check latency against hello period */
	if (on->hello_in)
		latency = monotime_since(&on->last_hello, NULL)
			  - ((int64_t)oi->hello_interval * 1000000);
	/* log if latency exceeds the hello period */
	if (latency > ((int64_t)oi->hello_interval * 1000000))
		zlog_warn("%s RX %pI4 high latency %" PRId64 "us.", __func__,
			  &on->router_id, latency);
	on->last_hello = timestamp;
	on->hello_in++;

	/* Always override neighbor's source address */
	ospf6_neighbor_lladdr_set(on, src);

	/* Neighbor ifindex check */
	if (on->ifindex != (ifindex_t)ntohl(hello->interface_id)) {
		on->ifindex = ntohl(hello->interface_id);
		neighbor_ifindex_change++;
	}

	/* TwoWay check */
	for (p = (char *)((caddr_t)hello + sizeof(struct ospf6_hello));
	     p + sizeof(uint32_t) <= OSPF6_MESSAGE_END(oh);
	     p += sizeof(uint32_t)) {
		uint32_t *router_id = (uint32_t *)p;

		if (*router_id == oi->area->ospf6->router_id)
			twoway++;
	}

	assert(p == OSPF6_MESSAGE_END(oh));

	/* RouterPriority check */
	if (on->priority != hello->priority) {
		on->priority = hello->priority;
		neighborchange++;
	}

	/* DR check */
	if (on->drouter != hello->drouter) {
		on->prev_drouter = on->drouter;
		on->drouter = hello->drouter;
		if (on->prev_drouter == on->router_id
		    || on->drouter == on->router_id)
			neighborchange++;
	}

	/* BDR check */
	if (on->bdrouter != hello->bdrouter) {
		on->prev_bdrouter = on->bdrouter;
		on->bdrouter = hello->bdrouter;
		if (on->prev_bdrouter == on->router_id
		    || on->bdrouter == on->router_id)
			neighborchange++;
	}

	/* BackupSeen check */
	if (oi->state == OSPF6_INTERFACE_WAITING) {
		if (hello->bdrouter == on->router_id)
			backupseen++;
		else if (hello->drouter == on->router_id
			 && hello->bdrouter == htonl(0))
			backupseen++;
	}

	oi->hello_in++;

	/* Execute neighbor events */
	event_execute(master, hello_received, on, 0, NULL);
	if (twoway)
		event_execute(master, twoway_received, on, 0, NULL);
	else {
		if (OSPF6_GR_IS_ACTIVE_HELPER(on)) {
			if (IS_DEBUG_OSPF6_GR)
				zlog_debug(
					"%s, Received oneway hello from RESTARTER so ignore here.",
					__PRETTY_FUNCTION__);
		} else {
			/* If the router is DR_OTHER, RESTARTER will not wait
			 * until it receives the hello from it if it receives
			 * from DR and BDR.
			 * So, helper might receives ONE_WAY hello from
			 * RESTARTER. So not allowing to change the state if it
			 * receives one_way hellow when it acts as HELPER for
			 * that specific neighbor.
			 */
			event_execute(master, oneway_received, on, 0, NULL);
		}
	}

	if (OSPF6_GR_IS_ACTIVE_HELPER(on)) {
		/* As per the GR Conformance Test Case 7.2. Section 3
		 * "Also, if X was the Designated Router on network segment S
		 * when the helping relationship began, Y maintains X as the
		 * Designated Router until the helping relationship is
		 * terminated."
		 * When it is a helper for this neighbor, It should not trigger
		 * the ISM Events. Also Intentionally not setting the priority
		 * and other fields so that when the neighbor exits the Grace
		 * period, it can handle if there is any change before GR and
		 * after GR.
		 */
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug(
				"%s, Neighbor is under GR Restart, hence ignoring the ISM Events",
				__PRETTY_FUNCTION__);

		return;
	}

	/*
	 * RFC 3623 - Section 2:
	 * "If the restarting router determines that it was the Designated
	 * Router on a given segment prior to the restart, it elects
	 * itself as the Designated Router again.  The restarting router
	 * knows that it was the Designated Router if, while the
	 * associated interface is in Waiting state, a Hello packet is
	 * received from a neighbor listing the router as the Designated
	 * Router".
	 */
	if (oi->area->ospf6->gr_info.restart_in_progress
	    && oi->state == OSPF6_INTERFACE_WAITING
	    && hello->drouter == oi->area->ospf6->router_id)
		oi->drouter = hello->drouter;

	/* Schedule interface events */
	if (backupseen)
		event_add_event(master, backup_seen, oi, 0, NULL);
	if (neighborchange)
		event_add_event(master, neighbor_change, oi, 0, NULL);

	if (neighbor_ifindex_change && on->state == OSPF6_NEIGHBOR_FULL)
		OSPF6_ROUTER_LSA_SCHEDULE(oi->area);
}

static void ospf6_dbdesc_recv_master(struct ospf6_header *oh,
				     struct ospf6_neighbor *on)
{
	struct ospf6_dbdesc *dbdesc;
	char *p;

	dbdesc = (struct ospf6_dbdesc *)((caddr_t)oh
					 + sizeof(struct ospf6_header));

	if (on->state < OSPF6_NEIGHBOR_INIT) {
		if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV_HDR))
			zlog_debug("Neighbor state less than Init, ignore");
		return;
	}

	switch (on->state) {
	case OSPF6_NEIGHBOR_TWOWAY:
		if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV_HDR))
			zlog_debug("Neighbor state is 2-Way, ignore");
		return;

	case OSPF6_NEIGHBOR_INIT:
		event_execute(master, twoway_received, on, 0, NULL);
		if (on->state != OSPF6_NEIGHBOR_EXSTART) {
			if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV_HDR))
				zlog_debug(
					"Neighbor state is not ExStart, ignore");
			return;
		}
		/* else fall through to ExStart */
		fallthrough;
	case OSPF6_NEIGHBOR_EXSTART:
		/* if neighbor obeys us as our slave, schedule negotiation_done
		   and process LSA Headers. Otherwise, ignore this message */
		if (!CHECK_FLAG(dbdesc->bits, OSPF6_DBDESC_MSBIT)
		    && !CHECK_FLAG(dbdesc->bits, OSPF6_DBDESC_IBIT)
		    && ntohl(dbdesc->seqnum) == on->dbdesc_seqnum) {
			/* execute NegotiationDone */
			event_execute(master, negotiation_done, on, 0, NULL);

			/* Record neighbor options */
			memcpy(on->options, dbdesc->options,
			       sizeof(on->options));
		} else {
			zlog_warn("VRF %s: Nbr %s: Negotiation failed",
				  on->ospf6_if->interface->vrf->name, on->name);
			return;
		}
		/* fall through to exchange */
		fallthrough;
	case OSPF6_NEIGHBOR_EXCHANGE:
		if (!memcmp(dbdesc, &on->dbdesc_last,
			    sizeof(struct ospf6_dbdesc))) {
			/* Duplicated DatabaseDescription is dropped by master
			 */
			if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV_HDR))
				zlog_debug(
					"Duplicated dbdesc discarded by Master, ignore");
			return;
		}

		if (CHECK_FLAG(dbdesc->bits, OSPF6_DBDESC_MSBIT)) {
			zlog_warn(
				"DbDesc recv: Master/Slave bit mismatch Nbr %s",
				on->name);
			event_add_event(master, seqnumber_mismatch, on, 0,
					NULL);
			return;
		}

		if (CHECK_FLAG(dbdesc->bits, OSPF6_DBDESC_IBIT)) {
			zlog_warn("DbDesc recv: Initialize bit mismatch Nbr %s",
				  on->name);
			event_add_event(master, seqnumber_mismatch, on, 0,
					NULL);
			return;
		}

		if (memcmp(on->options, dbdesc->options, sizeof(on->options))) {
			zlog_warn("DbDesc recv: Option field mismatch Nbr %s",
				  on->name);
			event_add_event(master, seqnumber_mismatch, on, 0,
					NULL);
			return;
		}

		if (ntohl(dbdesc->seqnum) != on->dbdesc_seqnum) {
			zlog_warn(
				"DbDesc recv: Sequence number mismatch Nbr %s (received %#lx, %#lx expected)",
				on->name, (unsigned long)ntohl(dbdesc->seqnum),
				(unsigned long)on->dbdesc_seqnum);
			event_add_event(master, seqnumber_mismatch, on, 0,
					 NULL);
			return;
		}
		break;

	case OSPF6_NEIGHBOR_LOADING:
	case OSPF6_NEIGHBOR_FULL:
		if (!memcmp(dbdesc, &on->dbdesc_last,
			    sizeof(struct ospf6_dbdesc))) {
			/* Duplicated DatabaseDescription is dropped by master
			 */
			if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV_HDR))
				zlog_debug(
					"Duplicated dbdesc discarded by Master, ignore");
			return;
		}

		zlog_warn(
			"DbDesc recv: Not duplicate dbdesc in state %s Nbr %s",
			ospf6_neighbor_state_str[on->state], on->name);
		event_add_event(master, seqnumber_mismatch, on, 0, NULL);
		return;

	default:
		assert(0);
		break;
	}

	/* Process LSA headers */
	for (p = (char *)((caddr_t)dbdesc + sizeof(struct ospf6_dbdesc));
	     p + sizeof(struct ospf6_lsa_header) <= OSPF6_MESSAGE_END(oh);
	     p += sizeof(struct ospf6_lsa_header)) {
		struct ospf6_lsa *his, *mine;
		struct ospf6_lsdb *lsdb = NULL;

		his = ospf6_lsa_create_headeronly((struct ospf6_lsa_header *)p);

		if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV))
			zlog_debug("%s", his->name);

		switch (OSPF6_LSA_SCOPE(his->header->type)) {
		case OSPF6_SCOPE_LINKLOCAL:
			lsdb = on->ospf6_if->lsdb;
			break;
		case OSPF6_SCOPE_AREA:
			lsdb = on->ospf6_if->area->lsdb;
			break;
		case OSPF6_SCOPE_AS:
			lsdb = on->ospf6_if->area->ospf6->lsdb;
			break;
		case OSPF6_SCOPE_RESERVED:
			if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV))
				zlog_debug("Ignoring LSA of reserved scope");
			ospf6_lsa_delete(his);
			continue;
		}

		if (ntohs(his->header->type) == OSPF6_LSTYPE_AS_EXTERNAL
		    && (IS_AREA_STUB(on->ospf6_if->area)
			|| IS_AREA_NSSA(on->ospf6_if->area))) {
			if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV))
				zlog_debug(
					"SeqNumMismatch (E-bit mismatch), discard");
			ospf6_lsa_delete(his);
			event_add_event(master, seqnumber_mismatch, on, 0,
					NULL);
			return;
		}

		mine = ospf6_lsdb_lookup(his->header->type, his->header->id,
					 his->header->adv_router, lsdb);
		if (mine == NULL) {
			if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV))
				zlog_debug("Add request (No database copy)");
			ospf6_lsdb_add(ospf6_lsa_copy(his), on->request_list);
		} else if (ospf6_lsa_compare(his, mine) < 0) {
			if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV))
				zlog_debug("Add request (Received MoreRecent)");
			ospf6_lsdb_add(ospf6_lsa_copy(his), on->request_list);
		} else {
			if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV))
				zlog_debug("Discard (Existing MoreRecent)");
		}
		ospf6_lsa_delete(his);
	}

	assert(p == OSPF6_MESSAGE_END(oh));

	/* Increment sequence number */
	on->dbdesc_seqnum++;

	/* schedule send lsreq */
	if (on->request_list->count)
		event_add_event(master, ospf6_lsreq_send, on, 0,
				&on->thread_send_lsreq);

	EVENT_OFF(on->thread_send_dbdesc);

	/* More bit check */
	if (!CHECK_FLAG(dbdesc->bits, OSPF6_DBDESC_MBIT)
	    && !CHECK_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MBIT))
		event_add_event(master, exchange_done, on, 0,
				&on->thread_exchange_done);
	else {
		event_add_event(master, ospf6_dbdesc_send_newone, on, 0,
				&on->thread_send_dbdesc);
	}

	/* save last received dbdesc */
	memcpy(&on->dbdesc_last, dbdesc, sizeof(struct ospf6_dbdesc));
}

static void ospf6_dbdesc_recv_slave(struct ospf6_header *oh,
				    struct ospf6_neighbor *on)
{
	struct ospf6_dbdesc *dbdesc;
	char *p;

	dbdesc = (struct ospf6_dbdesc *)((caddr_t)oh
					 + sizeof(struct ospf6_header));

	if (on->state < OSPF6_NEIGHBOR_INIT) {
		if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV_HDR))
			zlog_debug("Neighbor state less than Init, ignore");
		return;
	}

	switch (on->state) {
	case OSPF6_NEIGHBOR_TWOWAY:
		if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV_HDR))
			zlog_debug("Neighbor state is 2-Way, ignore");
		return;

	case OSPF6_NEIGHBOR_INIT:
		event_execute(master, twoway_received, on, 0, NULL);
		if (on->state != OSPF6_NEIGHBOR_EXSTART) {
			if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV_HDR))
				zlog_debug(
					"Neighbor state is not ExStart, ignore");
			return;
		}
		/* else fall through to ExStart */
		fallthrough;
	case OSPF6_NEIGHBOR_EXSTART:
		/* If the neighbor is Master, act as Slave. Schedule
		   negotiation_done
		   and process LSA Headers. Otherwise, ignore this message */
		if (CHECK_FLAG(dbdesc->bits, OSPF6_DBDESC_IBIT)
		    && CHECK_FLAG(dbdesc->bits, OSPF6_DBDESC_MBIT)
		    && CHECK_FLAG(dbdesc->bits, OSPF6_DBDESC_MSBIT)
		    && ntohs(oh->length)
			       == sizeof(struct ospf6_header)
					  + sizeof(struct ospf6_dbdesc)) {
			/* set the master/slave bit to slave */
			UNSET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MSBIT);

			/* set the DD sequence number to one specified by master
			 */
			on->dbdesc_seqnum = ntohl(dbdesc->seqnum);

			/* schedule NegotiationDone */
			event_execute(master, negotiation_done, on, 0, NULL);

			/* Record neighbor options */
			memcpy(on->options, dbdesc->options,
			       sizeof(on->options));
		} else {
			zlog_warn("VRF %s: Nbr %s Negotiation failed",
				  on->ospf6_if->interface->vrf->name, on->name);
			return;
		}
		break;

	case OSPF6_NEIGHBOR_EXCHANGE:
		if (!memcmp(dbdesc, &on->dbdesc_last,
			    sizeof(struct ospf6_dbdesc))) {
			/* Duplicated DatabaseDescription causes slave to
			 * retransmit */
			if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV_HDR))
				zlog_debug(
					"Duplicated dbdesc causes retransmit");
			EVENT_OFF(on->thread_send_dbdesc);
			event_add_event(master, ospf6_dbdesc_send, on, 0,
					&on->thread_send_dbdesc);
			return;
		}

		if (!CHECK_FLAG(dbdesc->bits, OSPF6_DBDESC_MSBIT)) {
			zlog_warn(
				"DbDesc slave recv: Master/Slave bit mismatch Nbr %s",
				on->name);
			event_add_event(master, seqnumber_mismatch, on, 0,
					NULL);
			return;
		}

		if (CHECK_FLAG(dbdesc->bits, OSPF6_DBDESC_IBIT)) {
			zlog_warn(
				"DbDesc slave recv: Initialize bit mismatch Nbr %s",
				on->name);
			event_add_event(master, seqnumber_mismatch, on, 0,
					NULL);
			return;
		}

		if (memcmp(on->options, dbdesc->options, sizeof(on->options))) {
			zlog_warn(
				"DbDesc slave recv: Option field mismatch Nbr %s",
				on->name);
			event_add_event(master, seqnumber_mismatch, on, 0,
					NULL);
			return;
		}

		if (ntohl(dbdesc->seqnum) != on->dbdesc_seqnum + 1) {
			zlog_warn(
				"DbDesc slave recv: Sequence number mismatch Nbr %s (received %#lx, %#lx expected)",
				on->name, (unsigned long)ntohl(dbdesc->seqnum),
				(unsigned long)on->dbdesc_seqnum + 1);
			event_add_event(master, seqnumber_mismatch, on, 0,
					 NULL);
			return;
		}
		break;

	case OSPF6_NEIGHBOR_LOADING:
	case OSPF6_NEIGHBOR_FULL:
		if (!memcmp(dbdesc, &on->dbdesc_last,
			    sizeof(struct ospf6_dbdesc))) {
			/* Duplicated DatabaseDescription causes slave to
			 * retransmit */
			if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV_HDR))
				zlog_debug(
					"Duplicated dbdesc causes retransmit");
			EVENT_OFF(on->thread_send_dbdesc);
			event_add_event(master, ospf6_dbdesc_send, on, 0,
					&on->thread_send_dbdesc);
			return;
		}

		zlog_warn(
			"DbDesc slave recv: Not duplicate dbdesc in state %s Nbr %s",
			ospf6_neighbor_state_str[on->state], on->name);
		event_add_event(master, seqnumber_mismatch, on, 0, NULL);
		return;

	default:
		assert(0);
		break;
	}

	/* Process LSA headers */
	for (p = (char *)((caddr_t)dbdesc + sizeof(struct ospf6_dbdesc));
	     p + sizeof(struct ospf6_lsa_header) <= OSPF6_MESSAGE_END(oh);
	     p += sizeof(struct ospf6_lsa_header)) {
		struct ospf6_lsa *his, *mine;
		struct ospf6_lsdb *lsdb = NULL;

		his = ospf6_lsa_create_headeronly((struct ospf6_lsa_header *)p);

		switch (OSPF6_LSA_SCOPE(his->header->type)) {
		case OSPF6_SCOPE_LINKLOCAL:
			lsdb = on->ospf6_if->lsdb;
			break;
		case OSPF6_SCOPE_AREA:
			lsdb = on->ospf6_if->area->lsdb;
			break;
		case OSPF6_SCOPE_AS:
			lsdb = on->ospf6_if->area->ospf6->lsdb;
			break;
		case OSPF6_SCOPE_RESERVED:
			if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV))
				zlog_debug("Ignoring LSA of reserved scope");
			ospf6_lsa_delete(his);
			continue;
		}

		if (OSPF6_LSA_SCOPE(his->header->type) == OSPF6_SCOPE_AS
		    && (IS_AREA_STUB(on->ospf6_if->area)
			|| IS_AREA_NSSA(on->ospf6_if->area))) {
			if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV))
				zlog_debug("E-bit mismatch with LSA Headers");
			ospf6_lsa_delete(his);
			event_add_event(master, seqnumber_mismatch, on, 0,
					NULL);
			return;
		}

		mine = ospf6_lsdb_lookup(his->header->type, his->header->id,
					 his->header->adv_router, lsdb);
		if (mine == NULL || ospf6_lsa_compare(his, mine) < 0) {
			if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV))
				zlog_debug("Add request-list: %s", his->name);
			ospf6_lsdb_add(ospf6_lsa_copy(his), on->request_list);
		}
		ospf6_lsa_delete(his);
	}

	assert(p == OSPF6_MESSAGE_END(oh));

	/* Set sequence number to Master's */
	on->dbdesc_seqnum = ntohl(dbdesc->seqnum);

	/* schedule send lsreq */
	if (on->request_list->count)
		event_add_event(master, ospf6_lsreq_send, on, 0,
				&on->thread_send_lsreq);

	EVENT_OFF(on->thread_send_dbdesc);
	event_add_event(master, ospf6_dbdesc_send_newone, on, 0,
			&on->thread_send_dbdesc);

	/* save last received dbdesc */
	memcpy(&on->dbdesc_last, dbdesc, sizeof(struct ospf6_dbdesc));
}

static void ospf6_dbdesc_recv(struct in6_addr *src, struct in6_addr *dst,
			      struct ospf6_interface *oi,
			      struct ospf6_header *oh)
{
	struct ospf6_neighbor *on;
	struct ospf6_dbdesc *dbdesc;

	on = ospf6_neighbor_lookup(oh->router_id, oi);
	if (on == NULL) {
		if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV_HDR))
			zlog_debug("Neighbor not found, ignore");
		return;
	}

	dbdesc = (struct ospf6_dbdesc *)((caddr_t)oh
					 + sizeof(struct ospf6_header));

	if (((OSPF6_OPT_ISSET_EXT(dbdesc->options, OSPF6_OPT_AT) ==
	      OSPF6_OPT_AT) &&
	     (oi->at_data.flags == 0)) ||
	    ((OSPF6_OPT_ISSET_EXT(dbdesc->options, OSPF6_OPT_AT) !=
	      OSPF6_OPT_AT) &&
	     (oi->at_data.flags != 0))) {
		if (IS_OSPF6_DEBUG_AUTH_RX)
			zlog_warn(
				"VRF %s: IF %s AT-bit mismatch in dbdesc packet",
				oi->interface->vrf->name, oi->interface->name);
		oi->at_data.rx_drop++;
		return;
	}

	/* Interface MTU check */
	if (!oi->mtu_ignore && ntohs(dbdesc->ifmtu) != oi->ifmtu) {
		zlog_warn("VRF %s: I/F %s MTU mismatch (my %d rcvd %d)",
			  oi->interface->vrf->name, oi->interface->name,
			  oi->ifmtu, ntohs(dbdesc->ifmtu));
		return;
	}

	if (dbdesc->reserved1 || dbdesc->reserved2) {
		if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV_HDR))
			zlog_debug(
				"Non-0 reserved field in %s's DbDesc, correct",
				on->name);
		dbdesc->reserved1 = 0;
		dbdesc->reserved2 = 0;
	}

	oi->db_desc_in++;

	if (ntohl(oh->router_id) < ntohl(oi->area->ospf6->router_id))
		ospf6_dbdesc_recv_master(oh, on);
	else if (ntohl(oi->area->ospf6->router_id) < ntohl(oh->router_id))
		ospf6_dbdesc_recv_slave(oh, on);
	else {
		if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV_HDR))
			zlog_debug("Can't decide which is master, ignore");
	}
}

static void ospf6_lsreq_recv(struct in6_addr *src, struct in6_addr *dst,
			     struct ospf6_interface *oi,
			     struct ospf6_header *oh)
{
	struct ospf6_neighbor *on;
	char *p;
	struct ospf6_lsreq_entry *e;
	struct ospf6_lsdb *lsdb = NULL;
	struct ospf6_lsa *lsa;

	on = ospf6_neighbor_lookup(oh->router_id, oi);
	if (on == NULL) {
		if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV_HDR))
			zlog_debug("Neighbor not found, ignore");
		return;
	}

	if (on->state != OSPF6_NEIGHBOR_EXCHANGE
	    && on->state != OSPF6_NEIGHBOR_LOADING
	    && on->state != OSPF6_NEIGHBOR_FULL) {
		if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV_HDR))
			zlog_debug("Neighbor state less than Exchange, ignore");
		return;
	}

	oi->ls_req_in++;

	/* Process each request */
	for (p = (char *)((caddr_t)oh + sizeof(struct ospf6_header));
	     p + sizeof(struct ospf6_lsreq_entry) <= OSPF6_MESSAGE_END(oh);
	     p += sizeof(struct ospf6_lsreq_entry)) {
		e = (struct ospf6_lsreq_entry *)p;

		switch (OSPF6_LSA_SCOPE(e->type)) {
		case OSPF6_SCOPE_LINKLOCAL:
			lsdb = on->ospf6_if->lsdb;
			break;
		case OSPF6_SCOPE_AREA:
			lsdb = on->ospf6_if->area->lsdb;
			break;
		case OSPF6_SCOPE_AS:
			lsdb = on->ospf6_if->area->ospf6->lsdb;
			break;
		default:
			if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV))
				zlog_debug("Ignoring LSA of reserved scope");
			continue;
		}

		/* Find database copy */
		lsa = ospf6_lsdb_lookup(e->type, e->id, e->adv_router, lsdb);
		if (lsa == NULL) {
			zlog_warn(
				"Can't find requested lsa [%s Id:%pI4 Adv:%pI4] send badLSReq",
				ospf6_lstype_name(e->type), &e->id,
				&e->adv_router);
			event_add_event(master, bad_lsreq, on, 0, NULL);
			return;
		}

		ospf6_lsdb_add(ospf6_lsa_copy(lsa), on->lsupdate_list);
	}

	assert(p == OSPF6_MESSAGE_END(oh));

	/* schedule send lsupdate */
	EVENT_OFF(on->thread_send_lsupdate);
	event_add_event(master, ospf6_lsupdate_send_neighbor, on, 0,
			&on->thread_send_lsupdate);
}

/* Verify, that the specified memory area contains exactly N valid IPv6
   prefixes as specified by RFC5340, A.4.1. */
static unsigned ospf6_prefixes_examin(
	struct ospf6_prefix *current, /* start of buffer    */
	unsigned length,
	const uint32_t req_num_pfxs /* always compared with the actual number
					of prefixes */
)
{
	uint8_t requested_pfx_bytes;
	uint32_t real_num_pfxs = 0;

	while (length) {
		if (length < OSPF6_PREFIX_MIN_SIZE) {
			zlog_warn("%s: undersized IPv6 prefix header",
				  __func__);
			return MSG_NG;
		}
		/* safe to look deeper */
		if (current->prefix_length > IPV6_MAX_BITLEN) {
			zlog_warn("%s: invalid PrefixLength (%u bits)",
				  __func__, current->prefix_length);
			return MSG_NG;
		}
		/* covers both fixed- and variable-sized fields */
		requested_pfx_bytes =
			OSPF6_PREFIX_MIN_SIZE
			+ OSPF6_PREFIX_SPACE(current->prefix_length);
		if (requested_pfx_bytes > length) {
			zlog_warn("%s: undersized IPv6 prefix", __func__);
			return MSG_NG;
		}
		/* next prefix */
		length -= requested_pfx_bytes;
		current = (struct ospf6_prefix *)((caddr_t)current
						  + requested_pfx_bytes);
		real_num_pfxs++;
	}
	if (real_num_pfxs != req_num_pfxs) {
		zlog_warn(
			"%s: IPv6 prefix number mismatch (%u required, %u real)",
			__func__, req_num_pfxs, real_num_pfxs);
		return MSG_NG;
	}
	return MSG_OK;
}

/* Verify an LSA to have a valid length and dispatch further (where
   appropriate) to check if the contents, including nested IPv6 prefixes,
   is properly sized/aligned within the LSA. Note that this function gets
   LSA type in network byte order, uses in host byte order and passes to
   ospf6_lstype_name() in network byte order again. */
static unsigned ospf6_lsa_examin(struct ospf6_lsa_header *lsah,
				 const uint16_t lsalen,
				 const uint8_t headeronly)
{
	struct ospf6_intra_prefix_lsa *intra_prefix_lsa;
	struct ospf6_as_external_lsa *as_external_lsa;
	struct ospf6_link_lsa *link_lsa;
	unsigned exp_length;
	uint8_t ltindex;
	uint16_t lsatype;

	/* In case an additional minimum length constraint is defined for
	   current
	   LSA type, make sure that this constraint is met. */
	lsatype = ntohs(lsah->type);
	ltindex = lsatype & OSPF6_LSTYPE_FCODE_MASK;
	if (ltindex < OSPF6_LSTYPE_SIZE && ospf6_lsa_minlen[ltindex]
	    && lsalen < ospf6_lsa_minlen[ltindex] + OSPF6_LSA_HEADER_SIZE) {
		zlog_warn("%s: undersized (%u B) LSA", __func__, lsalen);
		return MSG_NG;
	}
	switch (lsatype) {
	case OSPF6_LSTYPE_ROUTER:
		/* RFC5340 A.4.3, LSA header + OSPF6_ROUTER_LSA_MIN_SIZE bytes
		   followed
		   by N>=0 interface descriptions. */
		if ((lsalen - OSPF6_LSA_HEADER_SIZE - OSPF6_ROUTER_LSA_MIN_SIZE)
		    % OSPF6_ROUTER_LSDESC_FIX_SIZE) {
			zlog_warn(
				"%s: Router LSA interface description alignment error",
				__func__);
			return MSG_NG;
		}
		break;
	case OSPF6_LSTYPE_NETWORK:
		/* RFC5340 A.4.4, LSA header + OSPF6_NETWORK_LSA_MIN_SIZE bytes
		   followed by N>=0 attached router descriptions. */
		if ((lsalen - OSPF6_LSA_HEADER_SIZE
		     - OSPF6_NETWORK_LSA_MIN_SIZE)
		    % OSPF6_NETWORK_LSDESC_FIX_SIZE) {
			zlog_warn(
				"%s: Network LSA router description alignment error",
				__func__);
			return MSG_NG;
		}
		break;
	case OSPF6_LSTYPE_INTER_PREFIX:
		/* RFC5340 A.4.5, LSA header + OSPF6_INTER_PREFIX_LSA_MIN_SIZE
		   bytes
		   followed by 3-4 fields of a single IPv6 prefix. */
		if (headeronly)
			break;
		return ospf6_prefixes_examin(
			(struct ospf6_prefix
				 *)((caddr_t)lsah + OSPF6_LSA_HEADER_SIZE
				    + OSPF6_INTER_PREFIX_LSA_MIN_SIZE),
			lsalen - OSPF6_LSA_HEADER_SIZE
				- OSPF6_INTER_PREFIX_LSA_MIN_SIZE,
			1);
	case OSPF6_LSTYPE_INTER_ROUTER:
		/* RFC5340 A.4.6, fixed-size LSA. */
		if (lsalen
		    > OSPF6_LSA_HEADER_SIZE + OSPF6_INTER_ROUTER_LSA_FIX_SIZE) {
			zlog_warn("%s: Inter Router LSA oversized (%u B) LSA",
				  __func__, lsalen);
			return MSG_NG;
		}
		break;
	case OSPF6_LSTYPE_AS_EXTERNAL: /* RFC5340 A.4.7, same as A.4.8. */
	case OSPF6_LSTYPE_TYPE_7:
		/* RFC5340 A.4.8, LSA header + OSPF6_AS_EXTERNAL_LSA_MIN_SIZE
		   bytes
		   followed by 3-4 fields of IPv6 prefix and 3 conditional LSA
		   fields:
		   16 bytes of forwarding address, 4 bytes of external route
		   tag,
		   4 bytes of referenced link state ID. */
		if (headeronly)
			break;
		as_external_lsa =
			(struct ospf6_as_external_lsa
				 *)((caddr_t)lsah + OSPF6_LSA_HEADER_SIZE);
		exp_length =
			OSPF6_LSA_HEADER_SIZE + OSPF6_AS_EXTERNAL_LSA_MIN_SIZE;
		/* To find out if the last optional field (Referenced Link State
		   ID) is
		   assumed in this LSA, we need to access fixed fields of the
		   IPv6
		   prefix before ospf6_prefix_examin() confirms its sizing. */
		if (exp_length + OSPF6_PREFIX_MIN_SIZE > lsalen) {
			zlog_warn(
				"%s: AS External undersized (%u B) LSA header",
				__func__, lsalen);
			return MSG_NG;
		}
		/* forwarding address */
		if (CHECK_FLAG(as_external_lsa->bits_metric, OSPF6_ASBR_BIT_F))
			exp_length += 16;
		/* external route tag */
		if (CHECK_FLAG(as_external_lsa->bits_metric, OSPF6_ASBR_BIT_T))
			exp_length += 4;
		/* referenced link state ID */
		if (as_external_lsa->prefix.u._prefix_referenced_lstype)
			exp_length += 4;
		/* All the fixed-size fields (mandatory and optional) must fit.
		   I.e.,
		   this check does not include any IPv6 prefix fields. */
		if (exp_length > lsalen) {
			zlog_warn(
				"%s: AS External undersized (%u B) LSA header",
				__func__, lsalen);
			return MSG_NG;
		}
		/* The last call completely covers the remainder (IPv6 prefix).
		 */
		return ospf6_prefixes_examin(
			(struct ospf6_prefix
				 *)((caddr_t)as_external_lsa
				    + OSPF6_AS_EXTERNAL_LSA_MIN_SIZE),
			lsalen - exp_length, 1);
	case OSPF6_LSTYPE_LINK:
		/* RFC5340 A.4.9, LSA header + OSPF6_LINK_LSA_MIN_SIZE bytes
		   followed
		   by N>=0 IPv6 prefix blocks (with N declared beforehand). */
		if (headeronly)
			break;
		link_lsa = (struct ospf6_link_lsa *)((caddr_t)lsah
						     + OSPF6_LSA_HEADER_SIZE);
		return ospf6_prefixes_examin(
			(struct ospf6_prefix *)((caddr_t)link_lsa
						+ OSPF6_LINK_LSA_MIN_SIZE),
			lsalen - OSPF6_LSA_HEADER_SIZE
				- OSPF6_LINK_LSA_MIN_SIZE,
			ntohl(link_lsa->prefix_num) /* 32 bits */
			);
	case OSPF6_LSTYPE_INTRA_PREFIX:
		/* RFC5340 A.4.10, LSA header + OSPF6_INTRA_PREFIX_LSA_MIN_SIZE
		   bytes
		   followed by N>=0 IPv6 prefixes (with N declared beforehand).
		   */
		if (headeronly)
			break;
		intra_prefix_lsa =
			(struct ospf6_intra_prefix_lsa
				 *)((caddr_t)lsah + OSPF6_LSA_HEADER_SIZE);
		return ospf6_prefixes_examin(
			(struct ospf6_prefix
				 *)((caddr_t)intra_prefix_lsa
				    + OSPF6_INTRA_PREFIX_LSA_MIN_SIZE),
			lsalen - OSPF6_LSA_HEADER_SIZE
				- OSPF6_INTRA_PREFIX_LSA_MIN_SIZE,
			ntohs(intra_prefix_lsa->prefix_num) /* 16 bits */
		);
	case OSPF6_LSTYPE_GRACE_LSA:
		if (lsalen < OSPF6_LSA_HEADER_SIZE + GRACE_PERIOD_TLV_SIZE
				     + GRACE_RESTART_REASON_TLV_SIZE) {
			if (IS_DEBUG_OSPF6_GR)
				zlog_debug("%s: Undersized GraceLSA.",
					   __func__);
			return MSG_NG;
		}
	}
	/* No additional validation is possible for unknown LSA types, which are
	   themselves valid in OPSFv3, hence the default decision is to accept.
	   */
	return MSG_OK;
}

/* Verify if the provided input buffer is a valid sequence of LSAs. This
   includes verification of LSA blocks length/alignment and dispatching
   of deeper-level checks. */
static unsigned
ospf6_lsaseq_examin(struct ospf6_lsa_header *lsah, /* start of buffered data */
		    size_t length, const uint8_t headeronly,
		    /* When declared_num_lsas is not 0, compare it to the real
		       number of LSAs
		       and treat the difference as an error. */
		    const uint32_t declared_num_lsas)
{
	uint32_t counted_lsas = 0;

	while (length) {
		uint16_t lsalen;
		if (length < OSPF6_LSA_HEADER_SIZE) {
			zlog_warn(
				"%s: undersized (%zu B) trailing (#%u) LSA header",
				__func__, length, counted_lsas);
			return MSG_NG;
		}
		/* save on ntohs() calls here and in the LSA validator */
		lsalen = OSPF6_LSA_SIZE(lsah);
		if (lsalen < OSPF6_LSA_HEADER_SIZE) {
			zlog_warn(
				"%s: malformed LSA header #%u, declared length is %u B",
				__func__, counted_lsas, lsalen);
			return MSG_NG;
		}
		if (headeronly) {
			/* less checks here and in ospf6_lsa_examin() */
			if (MSG_OK != ospf6_lsa_examin(lsah, lsalen, 1)) {
				zlog_warn(
					"%s: anomaly in header-only %s LSA #%u",
					__func__, ospf6_lstype_name(lsah->type),
					counted_lsas);
				return MSG_NG;
			}
			lsah = (struct ospf6_lsa_header
					*)((caddr_t)lsah
					   + OSPF6_LSA_HEADER_SIZE);
			length -= OSPF6_LSA_HEADER_SIZE;
		} else {
			/* make sure the input buffer is deep enough before
			 * further checks */
			if (lsalen > length) {
				zlog_warn(
					"%s: anomaly in %s LSA #%u: declared length is %u B, buffered length is %zu B",
					__func__, ospf6_lstype_name(lsah->type),
					counted_lsas, lsalen, length);
				return MSG_NG;
			}
			if (MSG_OK != ospf6_lsa_examin(lsah, lsalen, 0)) {
				zlog_warn("%s: anomaly in %s LSA #%u", __func__,
					  ospf6_lstype_name(lsah->type),
					  counted_lsas);
				return MSG_NG;
			}
			lsah = (struct ospf6_lsa_header *)((caddr_t)lsah
							   + lsalen);
			length -= lsalen;
		}
		counted_lsas++;
	}

	if (declared_num_lsas && counted_lsas != declared_num_lsas) {
		zlog_warn("%s: #LSAs declared (%u) does not match actual (%u)",
			  __func__, declared_num_lsas, counted_lsas);
		return MSG_NG;
	}
	return MSG_OK;
}

/* Verify a complete OSPF packet for proper sizing/alignment. */
static unsigned ospf6_packet_examin(struct ospf6_header *oh,
				    const unsigned bytesonwire)
{
	struct ospf6_lsupdate *lsupd;
	unsigned test;

	/* length, 1st approximation */
	if (bytesonwire < OSPF6_HEADER_SIZE) {
		zlog_warn("%s: undersized (%u B) packet", __func__,
			  bytesonwire);
		return MSG_NG;
	}

	/* Now it is safe to access header fields. */
	if (bytesonwire != ntohs(oh->length)) {
		zlog_warn("%s: %s packet length error (%u real, %u declared)",
			  __func__, ospf6_message_type(oh->type), bytesonwire,
			  ntohs(oh->length));
		return MSG_NG;
	}

	/* version check */
	if (oh->version != OSPFV3_VERSION) {
		zlog_warn("%s: invalid (%u) protocol version", __func__,
			  oh->version);
		return MSG_NG;
	}
	/* length, 2nd approximation */
	if (oh->type < OSPF6_MESSAGE_TYPE_ALL && ospf6_packet_minlen[oh->type]
	    && bytesonwire
		       < OSPF6_HEADER_SIZE + ospf6_packet_minlen[oh->type]) {
		zlog_warn("%s: undersized (%u B) %s packet", __func__,
			  bytesonwire, ospf6_message_type(oh->type));
		return MSG_NG;
	}
	/* type-specific deeper validation */
	switch (oh->type) {
	case OSPF6_MESSAGE_TYPE_HELLO:
		/* RFC5340 A.3.2, packet header + OSPF6_HELLO_MIN_SIZE bytes
		   followed
		   by N>=0 router-IDs. */
		if (0
		    == (bytesonwire - OSPF6_HEADER_SIZE - OSPF6_HELLO_MIN_SIZE)
			       % 4)
			return MSG_OK;
		zlog_warn("%s: alignment error in %s packet", __func__,
			  ospf6_message_type(oh->type));
		return MSG_NG;
	case OSPF6_MESSAGE_TYPE_DBDESC:
		/* RFC5340 A.3.3, packet header + OSPF6_DB_DESC_MIN_SIZE bytes
		   followed
		   by N>=0 header-only LSAs. */
		test = ospf6_lsaseq_examin(
			(struct ospf6_lsa_header *)((caddr_t)oh
						    + OSPF6_HEADER_SIZE
						    + OSPF6_DB_DESC_MIN_SIZE),
			bytesonwire - OSPF6_HEADER_SIZE
				- OSPF6_DB_DESC_MIN_SIZE,
			1, 0);
		break;
	case OSPF6_MESSAGE_TYPE_LSREQ:
		/* RFC5340 A.3.4, packet header + N>=0 LS description blocks. */
		if (0
		    == (bytesonwire - OSPF6_HEADER_SIZE - OSPF6_LS_REQ_MIN_SIZE)
			       % OSPF6_LSREQ_LSDESC_FIX_SIZE)
			return MSG_OK;
		zlog_warn("%s: alignment error in %s packet", __func__,
			  ospf6_message_type(oh->type));
		return MSG_NG;
	case OSPF6_MESSAGE_TYPE_LSUPDATE:
		/* RFC5340 A.3.5, packet header + OSPF6_LS_UPD_MIN_SIZE bytes
		   followed
		   by N>=0 full LSAs (with N declared beforehand). */
		lsupd = (struct ospf6_lsupdate *)((caddr_t)oh
						  + OSPF6_HEADER_SIZE);
		test = ospf6_lsaseq_examin(
			(struct ospf6_lsa_header *)((caddr_t)lsupd
						    + OSPF6_LS_UPD_MIN_SIZE),
			bytesonwire - OSPF6_HEADER_SIZE - OSPF6_LS_UPD_MIN_SIZE,
			0, ntohl(lsupd->lsa_number) /* 32 bits */
			);
		break;
	case OSPF6_MESSAGE_TYPE_LSACK:
		/* RFC5340 A.3.6, packet header + N>=0 header-only LSAs. */
		test = ospf6_lsaseq_examin(
			(struct ospf6_lsa_header *)((caddr_t)oh
						    + OSPF6_HEADER_SIZE
						    + OSPF6_LS_ACK_MIN_SIZE),
			bytesonwire - OSPF6_HEADER_SIZE - OSPF6_LS_ACK_MIN_SIZE,
			1, 0);
		break;
	default:
		zlog_warn("%s: invalid (%u) message type", __func__, oh->type);
		return MSG_NG;
	}
	if (test != MSG_OK)
		zlog_warn("%s: anomaly in %s packet", __func__,
			  ospf6_message_type(oh->type));
	return test;
}

/* Verify particular fields of otherwise correct received OSPF packet to
   meet the requirements of RFC. */
static int ospf6_rxpacket_examin(struct ospf6_interface *oi,
				 struct ospf6_header *oh,
				 const unsigned bytesonwire)
{
	struct ospf6_neighbor *on;

	if (MSG_OK != ospf6_packet_examin(oh, bytesonwire))
		return MSG_NG;

	on = ospf6_neighbor_lookup(oh->router_id, oi);

	/* Area-ID check */
	if (oh->area_id != oi->area->area_id) {
		if (oh->area_id == OSPF_AREA_BACKBONE)
			zlog_warn(
				"VRF %s: I/F %s (%s, Router-ID: %pI4) Message may be via Virtual Link: not supported",
				oi->interface->vrf->name, oi->interface->name,
				on ? on->name : "null", &oh->router_id);
		else
			zlog_warn(
				"VRF %s: I/F %s (%s, Router-ID: %pI4) Area-ID mismatch (my %pI4, rcvd %pI4)",
				oi->interface->vrf->name, oi->interface->name,
				on ? on->name : "null", &oh->router_id,
				&oi->area->area_id, &oh->area_id);
		return MSG_NG;
	}

	/* Instance-ID check */
	if (oh->instance_id != oi->instance_id) {
		zlog_warn(
			"VRF %s: I/F %s (%s, Router-ID: %pI4) Instance-ID mismatch (my %u, rcvd %u)",
			oi->interface->vrf->name, oi->interface->name,
			on ? on->name : "null", &oh->router_id, oi->instance_id,
			oh->instance_id);
		return MSG_NG;
	}

	/* Router-ID check */
	if (oh->router_id == oi->area->ospf6->router_id) {
		zlog_warn("VRF %s: I/F %s Duplicate Router-ID (%pI4)",
			  oi->interface->vrf->name, oi->interface->name,
			  &oh->router_id);
		return MSG_NG;
	}
	return MSG_OK;
}

static void ospf6_lsupdate_recv(struct in6_addr *src, struct in6_addr *dst,
				struct ospf6_interface *oi,
				struct ospf6_header *oh)
{
	struct ospf6_neighbor *on;
	struct ospf6_lsupdate *lsupdate;
	char *p;

	on = ospf6_neighbor_lookup(oh->router_id, oi);
	if (on == NULL) {
		if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV_HDR))
			zlog_debug("Neighbor not found, ignore");
		return;
	}

	if (on->state != OSPF6_NEIGHBOR_EXCHANGE
	    && on->state != OSPF6_NEIGHBOR_LOADING
	    && on->state != OSPF6_NEIGHBOR_FULL) {
		if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV_HDR))
			zlog_debug("Neighbor state less than Exchange, ignore");
		return;
	}

	lsupdate = (struct ospf6_lsupdate *)((caddr_t)oh
					     + sizeof(struct ospf6_header));

	oi->ls_upd_in++;

	/* Process LSAs */
	for (p = (char *)((caddr_t)lsupdate + sizeof(struct ospf6_lsupdate));
	     p < OSPF6_MESSAGE_END(oh)
	     && p + OSPF6_LSA_SIZE(p) <= OSPF6_MESSAGE_END(oh);
	     p += OSPF6_LSA_SIZE(p)) {
		ospf6_receive_lsa(on, (struct ospf6_lsa_header *)p);
	}

	assert(p == OSPF6_MESSAGE_END(oh));
}

static void ospf6_lsack_recv(struct in6_addr *src, struct in6_addr *dst,
			     struct ospf6_interface *oi,
			     struct ospf6_header *oh)
{
	struct ospf6_neighbor *on;
	char *p;
	struct ospf6_lsa *his, *mine;
	struct ospf6_lsdb *lsdb = NULL;

	assert(oh->type == OSPF6_MESSAGE_TYPE_LSACK);

	on = ospf6_neighbor_lookup(oh->router_id, oi);
	if (on == NULL) {
		if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV_HDR))
			zlog_debug("Neighbor not found, ignore");
		return;
	}

	if (on->state != OSPF6_NEIGHBOR_EXCHANGE
	    && on->state != OSPF6_NEIGHBOR_LOADING
	    && on->state != OSPF6_NEIGHBOR_FULL) {
		if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV_HDR))
			zlog_debug("Neighbor state less than Exchange, ignore");
		return;
	}

	oi->ls_ack_in++;

	for (p = (char *)((caddr_t)oh + sizeof(struct ospf6_header));
	     p + sizeof(struct ospf6_lsa_header) <= OSPF6_MESSAGE_END(oh);
	     p += sizeof(struct ospf6_lsa_header)) {
		his = ospf6_lsa_create_headeronly((struct ospf6_lsa_header *)p);

		switch (OSPF6_LSA_SCOPE(his->header->type)) {
		case OSPF6_SCOPE_LINKLOCAL:
			lsdb = on->ospf6_if->lsdb;
			break;
		case OSPF6_SCOPE_AREA:
			lsdb = on->ospf6_if->area->lsdb;
			break;
		case OSPF6_SCOPE_AS:
			lsdb = on->ospf6_if->area->ospf6->lsdb;
			break;
		case OSPF6_SCOPE_RESERVED:
			if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV))
				zlog_debug("Ignoring LSA of reserved scope");
			ospf6_lsa_delete(his);
			continue;
		}

		if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV))
			zlog_debug("%s acknowledged by %s", his->name,
				   on->name);

		/* Find database copy */
		mine = ospf6_lsdb_lookup(his->header->type, his->header->id,
					 his->header->adv_router, lsdb);
		if (mine == NULL) {
			if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV))
				zlog_debug("No database copy");
			ospf6_lsa_delete(his);
			continue;
		}

		/* Check if the LSA is on his retrans-list */
		mine = ospf6_lsdb_lookup(his->header->type, his->header->id,
					 his->header->adv_router,
					 on->retrans_list);
		if (mine == NULL) {
			if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV))
				zlog_debug("Not on %s's retrans-list",
					   on->name);
			ospf6_lsa_delete(his);
			continue;
		}

		if (ospf6_lsa_compare(his, mine) != 0) {
			/* Log this questionable acknowledgement,
			   and examine the next one. */
			if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV))
				zlog_debug("Questionable acknowledgement");
			ospf6_lsa_delete(his);
			continue;
		}

		if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV))
			zlog_debug(
				"Acknowledged, remove from %s's retrans-list",
				on->name);

		ospf6_decrement_retrans_count(mine);
		if (OSPF6_LSA_IS_MAXAGE(mine))
			ospf6_maxage_remove(on->ospf6_if->area->ospf6);
		ospf6_lsdb_remove(mine, on->retrans_list);
		ospf6_lsa_delete(his);
	}

	assert(p == OSPF6_MESSAGE_END(oh));
}

static uint8_t *recvbuf = NULL;
static uint8_t *sendbuf = NULL;
static unsigned int iobuflen = 0;

int ospf6_iobuf_size(unsigned int size)
{
	/* NB: there was previously code here that tried to dynamically size
	 * the buffer for whatever we see in MTU on interfaces.  Which is
	 * _unconditionally wrong_ - we can always receive fragmented IPv6
	 * up to the regular 64k length limit.  (No jumbograms, thankfully.)
	 */

	if (!iobuflen) {
		/* the + 128 is to have some runway at the end */
		size_t alloc_size = 65536 + 128;

		assert(!recvbuf && !sendbuf);

		recvbuf = XMALLOC(MTYPE_OSPF6_MESSAGE, alloc_size);
		sendbuf = XMALLOC(MTYPE_OSPF6_MESSAGE, alloc_size);
		iobuflen = alloc_size;
	}

	return iobuflen;
}

void ospf6_message_terminate(void)
{
	XFREE(MTYPE_OSPF6_MESSAGE, recvbuf);
	XFREE(MTYPE_OSPF6_MESSAGE, sendbuf);

	iobuflen = 0;
}

enum ospf6_read_return_enum {
	OSPF6_READ_ERROR,
	OSPF6_READ_CONTINUE,
};

static int ospf6_read_helper(int sockfd, struct ospf6 *ospf6)
{
	int len;
	struct in6_addr src, dst;
	ifindex_t ifindex;
	struct iovec iovector[2];
	struct ospf6_interface *oi;
	struct ospf6_header *oh;
	enum ospf6_auth_err ret = OSPF6_AUTH_PROCESS_NORMAL;
	uint32_t at_len = 0;
	uint32_t lls_len = 0;

	/* initialize */
	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	ifindex = 0;
	iovector[0].iov_base = recvbuf;
	iovector[0].iov_len = iobuflen;
	iovector[1].iov_base = NULL;
	iovector[1].iov_len = 0;

	/* receive message */
	len = ospf6_recvmsg(&src, &dst, &ifindex, iovector, sockfd);
	if (len < 0)
		return OSPF6_READ_ERROR;

	if ((uint)len > iobuflen) {
		flog_err(EC_LIB_DEVELOPMENT, "Excess message read");
		return OSPF6_READ_ERROR;
	}

	/* ensure some zeroes past the end, just as a security precaution */
	memset(recvbuf + len, 0, MIN(128, iobuflen - len));

	oi = ospf6_interface_lookup_by_ifindex(ifindex, ospf6->vrf_id);
	if (oi == NULL || oi->area == NULL
	    || CHECK_FLAG(oi->flag, OSPF6_INTERFACE_DISABLE)) {
		if (IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_UNKNOWN,
					   RECV_HDR))
			zlog_debug("Message received on disabled interface");
		return OSPF6_READ_CONTINUE;
	}
	if (CHECK_FLAG(oi->flag, OSPF6_INTERFACE_PASSIVE)) {
		if (IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_UNKNOWN,
					   RECV_HDR))
			zlog_debug("%s: Ignore message on passive interface %s",
				   __func__, oi->interface->name);
		return OSPF6_READ_CONTINUE;
	}

	/*
	 * Drop packet destined to another VRF.
	 * This happens when raw_l3mdev_accept is set to 1.
	 */
	if (ospf6->vrf_id != oi->interface->vrf->vrf_id)
		return OSPF6_READ_CONTINUE;

	oh = (struct ospf6_header *)recvbuf;
	ret = ospf6_auth_validate_pkt(oi, (uint32_t *)&len, oh, &at_len,
				      &lls_len);
	if (ret == OSPF6_AUTH_VALIDATE_SUCCESS) {
		ret = ospf6_auth_check_digest(oh, oi, &src, lls_len);
		if (ret == OSPF6_AUTH_VALIDATE_FAILURE) {
			if (IS_OSPF6_DEBUG_AUTH_RX)
				zlog_err(
					"RECV[%s]: OSPF packet auth digest miss-match on %s",
					oi->interface->name,
					ospf6_message_type(oh->type));
			oi->at_data.rx_drop++;
			return OSPF6_READ_CONTINUE;
		}
	} else if (ret == OSPF6_AUTH_VALIDATE_FAILURE) {
		oi->at_data.rx_drop++;
		return OSPF6_READ_CONTINUE;
	}

	if (ospf6_rxpacket_examin(oi, oh, len) != MSG_OK)
		return OSPF6_READ_CONTINUE;

	/* Being here means, that no sizing/alignment issues were detected in
	   the input packet. This renders the additional checks performed below
	   and also in the type-specific dispatching functions a dead code,
	   which can be dismissed in a cleanup-focused review round later. */

	/* Log */
	if (IS_OSPF6_DEBUG_MESSAGE(oh->type, RECV_HDR)) {
		zlog_debug("%s received on %s", ospf6_message_type(oh->type),
			   oi->interface->name);
		zlog_debug("    src: %pI6", &src);
		zlog_debug("    dst: %pI6", &dst);

		switch (oh->type) {
		case OSPF6_MESSAGE_TYPE_HELLO:
			ospf6_hello_print(oh, OSPF6_ACTION_RECV);
			break;
		case OSPF6_MESSAGE_TYPE_DBDESC:
			ospf6_dbdesc_print(oh, OSPF6_ACTION_RECV);
			break;
		case OSPF6_MESSAGE_TYPE_LSREQ:
			ospf6_lsreq_print(oh, OSPF6_ACTION_RECV);
			break;
		case OSPF6_MESSAGE_TYPE_LSUPDATE:
			ospf6_lsupdate_print(oh, OSPF6_ACTION_RECV);
			break;
		case OSPF6_MESSAGE_TYPE_LSACK:
			ospf6_lsack_print(oh, OSPF6_ACTION_RECV);
			break;
		default:
			assert(0);
		}

		if ((at_len != 0) && IS_OSPF6_DEBUG_AUTH_RX)
			ospf6_auth_hdr_dump_recv(oh, (len + at_len + lls_len),
						 lls_len);
	}

	switch (oh->type) {
	case OSPF6_MESSAGE_TYPE_HELLO:
		ospf6_hello_recv(&src, &dst, oi, oh);
		break;

	case OSPF6_MESSAGE_TYPE_DBDESC:
		ospf6_dbdesc_recv(&src, &dst, oi, oh);
		break;

	case OSPF6_MESSAGE_TYPE_LSREQ:
		ospf6_lsreq_recv(&src, &dst, oi, oh);
		break;

	case OSPF6_MESSAGE_TYPE_LSUPDATE:
		ospf6_lsupdate_recv(&src, &dst, oi, oh);
		break;

	case OSPF6_MESSAGE_TYPE_LSACK:
		ospf6_lsack_recv(&src, &dst, oi, oh);
		break;

	default:
		assert(0);
	}

	return OSPF6_READ_CONTINUE;
}

void ospf6_receive(struct event *thread)
{
	int sockfd;
	struct ospf6 *ospf6;
	int count = 0;

	/* add next read thread */
	ospf6 = EVENT_ARG(thread);
	sockfd = EVENT_FD(thread);

	event_add_read(master, ospf6_receive, ospf6, ospf6->fd,
		       &ospf6->t_ospf6_receive);

	while (count < ospf6->write_oi_count) {
		count++;
		switch (ospf6_read_helper(sockfd, ospf6)) {
		case OSPF6_READ_ERROR:
			return;
		case OSPF6_READ_CONTINUE:
			break;
		}
	}
}

static void ospf6_fill_hdr_checksum(struct ospf6_interface *oi,
				    struct ospf6_packet *op)
{
	struct ipv6_ph ph = {};
	struct ospf6_header *oh;
	void *offset = NULL;

	if (oi->at_data.flags != 0)
		return;

	memcpy(&ph.src, oi->linklocal_addr, sizeof(struct in6_addr));
	memcpy(&ph.dst, &op->dst, sizeof(struct in6_addr));
	ph.ulpl = htonl(op->length);
	ph.next_hdr = IPPROTO_OSPFIGP;

	/* Suppress static analysis warnings about accessing icmp6 oob */
	oh = (struct ospf6_header *)STREAM_DATA(op->s);
	offset = oh;
	oh->checksum = in_cksum_with_ph6(&ph, offset, op->length);
}

static void ospf6_make_header(uint8_t type, struct ospf6_interface *oi,
			      struct stream *s)
{
	struct ospf6_header *oh;

	oh = (struct ospf6_header *)STREAM_DATA(s);

	oh->version = (uint8_t)OSPFV3_VERSION;
	oh->type = type;
	oh->length = 0;

	oh->router_id = oi->area->ospf6->router_id;
	oh->area_id = oi->area->area_id;
	oh->checksum = 0;
	oh->instance_id = oi->instance_id;
	oh->reserved = 0;

	stream_forward_endp(s, OSPF6_HEADER_SIZE);
}

static void ospf6_fill_header(struct ospf6_interface *oi, struct stream *s,
			      uint16_t length)
{
	struct ospf6_header *oh;

	oh = (struct ospf6_header *)STREAM_DATA(s);

	oh->length = htons(length);
}

static void ospf6_fill_lsupdate_header(struct stream *s, uint32_t lsa_num)
{
	struct ospf6_header *oh;
	struct ospf6_lsupdate *lsu;

	oh = (struct ospf6_header *)STREAM_DATA(s);

	lsu = (struct ospf6_lsupdate *)((caddr_t)oh
					+ sizeof(struct ospf6_header));
	lsu->lsa_number = htonl(lsa_num);
}

static void ospf6_auth_trailer_copy_keychain_key(struct ospf6_interface *oi)
{
	char *keychain_name = NULL;
	struct keychain *keychain = NULL;
	struct key *key = NULL;

	keychain_name = oi->at_data.keychain;
	keychain = keychain_lookup(keychain_name);
	if (keychain) {
		key = key_lookup_for_send(keychain);
		if (key && key->string &&
		    key->hash_algo != KEYCHAIN_ALGO_NULL) {
			/* storing the values so that further
			 * lookup can be avoided. after
			 * processing the digest need to reset
			 * these values
			 */
			oi->at_data.hash_algo = key->hash_algo;
			if (oi->at_data.auth_key)
				XFREE(MTYPE_OSPF6_AUTH_MANUAL_KEY,
				      oi->at_data.auth_key);
			oi->at_data.auth_key = XSTRDUP(
				MTYPE_OSPF6_AUTH_MANUAL_KEY, key->string);
			oi->at_data.key_id = key->index;
			SET_FLAG(oi->at_data.flags,
				 OSPF6_AUTH_TRAILER_KEYCHAIN_VALID);
		}
	}
}

static uint16_t ospf6_packet_max(struct ospf6_interface *oi)
{
	uint16_t at_len = 0;

	assert(oi->ifmtu > sizeof(struct ip6_hdr));

	if (oi->at_data.flags != 0) {
		if (CHECK_FLAG(oi->at_data.flags, OSPF6_AUTH_TRAILER_KEYCHAIN))
			ospf6_auth_trailer_copy_keychain_key(oi);

		at_len += OSPF6_AUTH_HDR_MIN_SIZE;
		at_len += keychain_get_hash_len(oi->at_data.hash_algo);
		return oi->ifmtu - (sizeof(struct ip6_hdr)) - at_len;
	}

	return oi->ifmtu - (sizeof(struct ip6_hdr));
}

static uint16_t ospf6_make_hello(struct ospf6_interface *oi, struct stream *s)
{
	struct listnode *node, *nnode;
	struct ospf6_neighbor *on;
	uint16_t length = OSPF6_HELLO_MIN_SIZE;
	uint8_t options1 = oi->area->options[1];

	if (oi->at_data.flags != 0)
		options1 |= OSPF6_OPT_AT;

	stream_putl(s, oi->interface->ifindex);
	stream_putc(s, oi->priority);
	stream_putc(s, oi->area->options[0]);
	stream_putc(s, options1);
	stream_putc(s, oi->area->options[2]);
	stream_putw(s, oi->hello_interval);
	stream_putw(s, oi->dead_interval);
	stream_put_ipv4(s, oi->drouter);
	stream_put_ipv4(s, oi->bdrouter);

	for (ALL_LIST_ELEMENTS(oi->neighbor_list, node, nnode, on)) {
		if (on->state < OSPF6_NEIGHBOR_INIT)
			continue;

		if ((length + sizeof(uint32_t) + OSPF6_HEADER_SIZE)
		    > ospf6_packet_max(oi)) {
			if (IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_HELLO,
						   SEND))
				zlog_debug(
					"sending Hello message: exceeds I/F MTU");
			break;
		}

		stream_put_ipv4(s, on->router_id);
		length += sizeof(uint32_t);
	}

	return length;
}

static void ospf6_write(struct event *thread)
{
	struct ospf6 *ospf6 = EVENT_ARG(thread);
	struct ospf6_interface *oi;
	struct ospf6_header *oh;
	struct ospf6_packet *op;
	struct listnode *node;
	struct iovec iovector[2];
	int pkt_count = 0;
	int len;
	int64_t latency = 0;
	struct timeval timestamp;
	uint16_t at_len = 0;

	if (ospf6->fd < 0) {
		zlog_warn("ospf6_write failed to send, fd %d", ospf6->fd);
		return;
	}

	node = listhead(ospf6->oi_write_q);
	assert(node);
	oi = listgetdata(node);

	while ((pkt_count < ospf6->write_oi_count) && oi) {
		op = ospf6_fifo_head(oi->obuf);
		assert(op);
		assert(op->length >= OSPF6_HEADER_SIZE);

		iovector[0].iov_base = (caddr_t)stream_pnt(op->s);
		iovector[0].iov_len = op->length;
		iovector[1].iov_base = NULL;
		iovector[1].iov_len = 0;

		oh = (struct ospf6_header *)STREAM_DATA(op->s);

		if (oi->at_data.flags != 0) {
			at_len = ospf6_auth_len_get(oi);
			if (at_len) {
				iovector[0].iov_len =
					ntohs(oh->length) + at_len;
				ospf6_auth_digest_send(oi->linklocal_addr, oi,
						       oh, at_len,
						       iovector[0].iov_len);
			} else {
				iovector[0].iov_len = ntohs(oh->length);
			}
		} else {
			iovector[0].iov_len = ntohs(oh->length);
		}

		len = ospf6_sendmsg(oi->linklocal_addr, &op->dst,
				    oi->interface->ifindex, iovector,
				    ospf6->fd);

		if (len != (op->length + (int)at_len))
			flog_err(EC_LIB_DEVELOPMENT,
				 "Could not send entire message");

		if (IS_OSPF6_DEBUG_MESSAGE(oh->type, SEND_HDR)) {
			zlog_debug("%s send on %s",
				   ospf6_message_type(oh->type),
				   oi->interface->name);
			zlog_debug("    src: %pI6", oi->linklocal_addr);
			zlog_debug("    dst: %pI6", &op->dst);
			switch (oh->type) {
			case OSPF6_MESSAGE_TYPE_HELLO:
				ospf6_hello_print(oh, OSPF6_ACTION_SEND);
				break;
			case OSPF6_MESSAGE_TYPE_DBDESC:
				ospf6_dbdesc_print(oh, OSPF6_ACTION_SEND);
				break;
			case OSPF6_MESSAGE_TYPE_LSREQ:
				ospf6_lsreq_print(oh, OSPF6_ACTION_SEND);
				break;
			case OSPF6_MESSAGE_TYPE_LSUPDATE:
				ospf6_lsupdate_print(oh, OSPF6_ACTION_SEND);
				break;
			case OSPF6_MESSAGE_TYPE_LSACK:
				ospf6_lsack_print(oh, OSPF6_ACTION_SEND);
				break;
			default:
				zlog_debug("Unknown message");
				assert(0);
				break;
			}
		}
		switch (oh->type) {
		case OSPF6_MESSAGE_TYPE_HELLO:
			monotime(&timestamp);
			if (oi->hello_out)
				latency = monotime_since(&oi->last_hello, NULL)
					  - ((int64_t)oi->hello_interval
					     * 1000000);

			/* log if latency exceeds the hello period */
			if (latency > ((int64_t)oi->hello_interval * 1000000))
				zlog_warn("%s hello TX high latency %" PRId64
					  "us.",
					  __func__, latency);
			oi->last_hello = timestamp;
			oi->hello_out++;
			break;
		case OSPF6_MESSAGE_TYPE_DBDESC:
			oi->db_desc_out++;
			break;
		case OSPF6_MESSAGE_TYPE_LSREQ:
			oi->ls_req_out++;
			break;
		case OSPF6_MESSAGE_TYPE_LSUPDATE:
			oi->ls_upd_out++;
			break;
		case OSPF6_MESSAGE_TYPE_LSACK:
			oi->ls_ack_out++;
			break;
		default:
			zlog_debug("Unknown message");
			assert(0);
			break;
		}

		if ((oi->at_data.flags != 0) &&
		    (IS_OSPF6_DEBUG_MESSAGE(oh->type, SEND_HDR)) &&
		    (IS_OSPF6_DEBUG_AUTH_TX))
			ospf6_auth_hdr_dump_send(oh, iovector[0].iov_len);

		/* initialize at_len to 0 for next packet */
		at_len = 0;

		/* Now delete packet from queue. */
		ospf6_packet_delete(oi);

		/* Move this interface to the tail of write_q to
		       serve everyone in a round robin fashion */
		list_delete_node(ospf6->oi_write_q, node);
		if (ospf6_fifo_head(oi->obuf) == NULL) {
			oi->on_write_q = 0;
			oi = NULL;
		} else {
			listnode_add(ospf6->oi_write_q, oi);
		}

		/* Setup to service from the head of the queue again */
		if (!list_isempty(ospf6->oi_write_q)) {
			node = listhead(ospf6->oi_write_q);
			oi = listgetdata(node);
		}
	}

	/* If packets still remain in queue, call write thread. */
	if (!list_isempty(ospf6->oi_write_q))
		event_add_write(master, ospf6_write, ospf6, ospf6->fd,
				&ospf6->t_write);
}

void ospf6_hello_send(struct event *thread)
{
	struct ospf6_interface *oi;

	oi = (struct ospf6_interface *)EVENT_ARG(thread);

	/* Check if the GR hello-delay is active. */
	if (oi->gr.hello_delay.t_grace_send)
		return;

	/* Check if config is still being processed */
	if (event_is_scheduled(t_ospf6_cfg)) {
		if (IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_HELLO, SEND))
			zlog_debug(
				"Suppressing Hello on interface %s during config load",
				oi->interface->name);
		event_add_timer(master, ospf6_hello_send, oi,
				oi->hello_interval, &oi->thread_send_hello);
		return;
	}

	if (oi->state <= OSPF6_INTERFACE_DOWN) {
		if (IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_HELLO, SEND_HDR))
			zlog_debug("Unable to send Hello on down interface %s",
				   oi->interface->name);
		return;
	}

	event_add_timer(master, ospf6_hello_send, oi, oi->hello_interval,
			 &oi->thread_send_hello);

	ospf6_hello_send_addr(oi, NULL);
}

/* used to send polls for PtP/PtMP too */
void ospf6_hello_send_addr(struct ospf6_interface *oi,
			   const struct in6_addr *addr)
{
	struct ospf6_packet *op;
	uint16_t length = OSPF6_HEADER_SIZE;
	bool anything = false;

	op = ospf6_packet_new(oi->ifmtu);

	ospf6_make_header(OSPF6_MESSAGE_TYPE_HELLO, oi, op->s);

	/* Prepare OSPF Hello body */
	length += ospf6_make_hello(oi, op->s);
	if (length == OSPF6_HEADER_SIZE) {
		/* Hello overshooting MTU */
		ospf6_packet_free(op);
		return;
	}

	/* Fill OSPF header. */
	ospf6_fill_header(oi, op->s, length);

	/* Set packet length. */
	op->length = length;

	if ((oi->state == OSPF6_INTERFACE_POINTTOPOINT
	     || oi->state == OSPF6_INTERFACE_POINTTOMULTIPOINT)
	    && !addr && oi->p2xp_no_multicast_hello) {
		struct listnode *node;
		struct ospf6_neighbor *on;
		struct ospf6_packet *opdup;

		for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, node, on)) {
			if (on->state < OSPF6_NEIGHBOR_INIT)
				/* poll-interval for these */
				continue;

			opdup = ospf6_packet_dup(op);
			opdup->dst = on->linklocal_addr;
			ospf6_fill_hdr_checksum(oi, opdup);
			ospf6_packet_add_top(oi, opdup);
			anything = true;
		}

		ospf6_packet_free(op);
	} else {
		op->dst = addr ? *addr : allspfrouters6;

		/* Add packet to the top of the interface output queue, so that
		 * they can't get delayed by things like long queues of LS
		 * Update packets
		 */
		ospf6_fill_hdr_checksum(oi, op);
		ospf6_packet_add_top(oi, op);
		anything = true;
	}

	if (anything)
		OSPF6_MESSAGE_WRITE_ON(oi);
}

static uint16_t ospf6_make_dbdesc(struct ospf6_neighbor *on, struct stream *s)
{
	uint16_t length = OSPF6_DB_DESC_MIN_SIZE;
	struct ospf6_lsa *lsa, *lsanext;
	uint8_t options1 = on->ospf6_if->area->options[1];

	if (on->ospf6_if->at_data.flags != 0)
		options1 |= OSPF6_OPT_AT;

	/* if this is initial one, initialize sequence number for DbDesc */
	if (CHECK_FLAG(on->dbdesc_bits, OSPF6_DBDESC_IBIT)
	    && (on->dbdesc_seqnum == 0)) {
		on->dbdesc_seqnum = frr_sequence32_next();
	}

	/* reserved */
	stream_putc(s, 0); /* reserved 1 */
	stream_putc(s, on->ospf6_if->area->options[0]);
	stream_putc(s, options1);
	stream_putc(s, on->ospf6_if->area->options[2]);
	stream_putw(s, on->ospf6_if->ifmtu);
	stream_putc(s, 0); /* reserved 2 */
	stream_putc(s, on->dbdesc_bits);
	stream_putl(s, on->dbdesc_seqnum);

	/* if this is not initial one, set LSA headers in dbdesc */
	if (!CHECK_FLAG(on->dbdesc_bits, OSPF6_DBDESC_IBIT)) {
		for (ALL_LSDB(on->dbdesc_list, lsa, lsanext)) {
			ospf6_lsa_age_update_to_send(lsa,
						     on->ospf6_if->transdelay);

			/* MTU check */
			if ((length + sizeof(struct ospf6_lsa_header)
			     + OSPF6_HEADER_SIZE)
			    > ospf6_packet_max(on->ospf6_if)) {
				ospf6_lsa_unlock(&lsa);
				if (lsanext)
					ospf6_lsa_unlock(&lsanext);
				break;
			}
			stream_put(s, lsa->header,
				   sizeof(struct ospf6_lsa_header));
			length += sizeof(struct ospf6_lsa_header);
		}
	}
	return length;
}

void ospf6_dbdesc_send(struct event *thread)
{
	struct ospf6_neighbor *on;
	uint16_t length = OSPF6_HEADER_SIZE;
	struct ospf6_packet *op;

	on = (struct ospf6_neighbor *)EVENT_ARG(thread);

	if (on->state < OSPF6_NEIGHBOR_EXSTART) {
		if (IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_DBDESC, SEND))
			zlog_debug(
				"Quit to send DbDesc to neighbor %s state %s",
				on->name, ospf6_neighbor_state_str[on->state]);
		return;
	}

	/* set next thread if master */
	if (CHECK_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MSBIT))
		event_add_timer(master, ospf6_dbdesc_send, on,
				on->ospf6_if->rxmt_interval,
				&on->thread_send_dbdesc);

	op = ospf6_packet_new(on->ospf6_if->ifmtu);
	ospf6_make_header(OSPF6_MESSAGE_TYPE_DBDESC, on->ospf6_if, op->s);

	length += ospf6_make_dbdesc(on, op->s);
	ospf6_fill_header(on->ospf6_if, op->s, length);

	/* Set packet length. */
	op->length = length;

	if (on->ospf6_if->state == OSPF6_INTERFACE_POINTTOPOINT)
		op->dst = allspfrouters6;
	else
		op->dst = on->linklocal_addr;

	ospf6_fill_hdr_checksum(on->ospf6_if, op);

	ospf6_packet_add(on->ospf6_if, op);

	OSPF6_MESSAGE_WRITE_ON(on->ospf6_if);
}

void ospf6_dbdesc_send_newone(struct event *thread)
{
	struct ospf6_neighbor *on;
	struct ospf6_lsa *lsa, *lsanext;
	unsigned int size = 0;

	on = (struct ospf6_neighbor *)EVENT_ARG(thread);
	ospf6_lsdb_remove_all(on->dbdesc_list);

	/* move LSAs from summary_list to dbdesc_list (within neighbor
	   structure)
	   so that ospf6_send_dbdesc () can send those LSAs */
	size = sizeof(struct ospf6_lsa_header) + sizeof(struct ospf6_dbdesc);
	for (ALL_LSDB(on->summary_list, lsa, lsanext)) {
		/* if stub area then don't advertise AS-External LSAs */
		if ((IS_AREA_STUB(on->ospf6_if->area)
		     || IS_AREA_NSSA(on->ospf6_if->area))
		    && ntohs(lsa->header->type) == OSPF6_LSTYPE_AS_EXTERNAL) {
			ospf6_lsdb_remove(lsa, on->summary_list);
			continue;
		}

		if (size + sizeof(struct ospf6_lsa_header)
		    > ospf6_packet_max(on->ospf6_if)) {
			ospf6_lsa_unlock(&lsa);
			if (lsanext)
				ospf6_lsa_unlock(&lsanext);
			break;
		}

		ospf6_lsdb_add(ospf6_lsa_copy(lsa), on->dbdesc_list);
		ospf6_lsdb_remove(lsa, on->summary_list);
		size += sizeof(struct ospf6_lsa_header);
	}

	if (on->summary_list->count == 0)
		UNSET_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MBIT);

	/* If slave, More bit check must be done here */
	if (!CHECK_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MSBIT) && /* Slave */
	    !CHECK_FLAG(on->dbdesc_last.bits, OSPF6_DBDESC_MBIT)
	    && !CHECK_FLAG(on->dbdesc_bits, OSPF6_DBDESC_MBIT))
		event_add_event(master, exchange_done, on, 0,
				&on->thread_exchange_done);

	event_execute(master, ospf6_dbdesc_send, on, 0, NULL);
}

static uint16_t ospf6_make_lsreq(struct ospf6_neighbor *on, struct stream *s)
{
	uint16_t length = 0;
	struct ospf6_lsa *lsa, *lsanext, *last_req = NULL;

	for (ALL_LSDB(on->request_list, lsa, lsanext)) {
		if ((length + OSPF6_HEADER_SIZE)
		    > ospf6_packet_max(on->ospf6_if)) {
			ospf6_lsa_unlock(&lsa);
			if (lsanext)
				ospf6_lsa_unlock(&lsanext);
			break;
		}
		stream_putw(s, 0); /* reserved */
		stream_putw(s, ntohs(lsa->header->type));
		stream_putl(s, ntohl(lsa->header->id));
		stream_putl(s, ntohl(lsa->header->adv_router));
		length += sizeof(struct ospf6_lsreq_entry);
		last_req = lsa;
	}

	if (last_req != NULL) {
		if (on->last_ls_req != NULL)
			ospf6_lsa_unlock(&on->last_ls_req);

		ospf6_lsa_lock(last_req);
		on->last_ls_req = last_req;
	}

	return length;
}

static uint16_t ospf6_make_lsack_neighbor(struct ospf6_neighbor *on,
					  struct ospf6_packet **op)
{
	uint16_t length = 0;
	struct ospf6_lsa *lsa, *lsanext;
	int lsa_cnt = 0;

	for (ALL_LSDB(on->lsack_list, lsa, lsanext)) {
		if ((length + sizeof(struct ospf6_lsa_header)
		     + OSPF6_HEADER_SIZE)
		    > ospf6_packet_max(on->ospf6_if)) {
			/* if we run out of packet size/space here,
			   better to try again soon. */
			if (lsa_cnt) {
				ospf6_fill_header(on->ospf6_if, (*op)->s,
						  length + OSPF6_HEADER_SIZE);

				(*op)->length = length + OSPF6_HEADER_SIZE;
				(*op)->dst = on->linklocal_addr;
				ospf6_fill_hdr_checksum(on->ospf6_if, *op);
				ospf6_packet_add(on->ospf6_if, *op);
				OSPF6_MESSAGE_WRITE_ON(on->ospf6_if);
				/* new packet */
				*op = ospf6_packet_new(on->ospf6_if->ifmtu);
				ospf6_make_header(OSPF6_MESSAGE_TYPE_LSACK,
						  on->ospf6_if, (*op)->s);
				length = 0;
				lsa_cnt = 0;
			}
		}
		ospf6_lsa_age_update_to_send(lsa, on->ospf6_if->transdelay);
		stream_put((*op)->s, lsa->header,
			   sizeof(struct ospf6_lsa_header));
		length += sizeof(struct ospf6_lsa_header);

		assert(lsa->lock == 2);
		ospf6_lsdb_remove(lsa, on->lsack_list);
		lsa_cnt++;
	}
	return length;
}

void ospf6_lsreq_send(struct event *thread)
{
	struct ospf6_neighbor *on;
	struct ospf6_packet *op;
	uint16_t length = OSPF6_HEADER_SIZE;

	on = (struct ospf6_neighbor *)EVENT_ARG(thread);

	/* LSReq will be sent only in ExStart or Loading */
	if (on->state != OSPF6_NEIGHBOR_EXCHANGE
	    && on->state != OSPF6_NEIGHBOR_LOADING) {
		if (IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_LSREQ, SEND_HDR))
			zlog_debug("Quit to send LSReq to neighbor %s state %s",
				   on->name,
				   ospf6_neighbor_state_str[on->state]);
		return;
	}

	/* schedule loading_done if request list is empty */
	if (on->request_list->count == 0) {
		event_add_event(master, loading_done, on, 0,
				&on->event_loading_done);
		return;
	}

	op = ospf6_packet_new(on->ospf6_if->ifmtu);
	ospf6_make_header(OSPF6_MESSAGE_TYPE_LSREQ, on->ospf6_if, op->s);

	length += ospf6_make_lsreq(on, op->s);

	if (length == OSPF6_HEADER_SIZE) {
		/* Hello overshooting MTU */
		ospf6_packet_free(op);
		return;
	}

	/* Fill OSPF header. */
	ospf6_fill_header(on->ospf6_if, op->s, length);

	/* Set packet length */
	op->length = length;

	if (on->ospf6_if->state == OSPF6_INTERFACE_POINTTOPOINT)
		op->dst = allspfrouters6;
	else
		op->dst = on->linklocal_addr;

	ospf6_fill_hdr_checksum(on->ospf6_if, op);
	ospf6_packet_add(on->ospf6_if, op);

	OSPF6_MESSAGE_WRITE_ON(on->ospf6_if);

	/* set next thread */
	if (on->request_list->count != 0) {
		event_add_timer(master, ospf6_lsreq_send, on,
				on->ospf6_if->rxmt_interval,
				&on->thread_send_lsreq);
	}
}

static void ospf6_send_lsupdate(struct ospf6_neighbor *on,
				struct ospf6_interface *oi,
				struct ospf6_packet *op)
{
	if (on) {
		if ((on->ospf6_if->state == OSPF6_INTERFACE_POINTTOPOINT)
		    || (on->ospf6_if->state == OSPF6_INTERFACE_DR)
		    || (on->ospf6_if->state == OSPF6_INTERFACE_BDR))
			op->dst = allspfrouters6;
		else
			op->dst = on->linklocal_addr;
		oi = on->ospf6_if;
	} else if (oi) {
		if ((oi->state == OSPF6_INTERFACE_POINTTOPOINT)
		    || (oi->state == OSPF6_INTERFACE_DR)
		    || (oi->state == OSPF6_INTERFACE_BDR))
			op->dst = allspfrouters6;
		else
			op->dst = alldrouters6;
	}
	if (oi) {
		struct ospf6 *ospf6;

		ospf6_fill_hdr_checksum(oi, op);
		ospf6_packet_add(oi, op);
		/* If ospf instance is being deleted, send the packet
		 * immediately
		 */
		if ((oi->area == NULL) || (oi->area->ospf6 == NULL))
			return;

		ospf6 = oi->area->ospf6;
		if (ospf6->inst_shutdown) {
			if (oi->on_write_q == 0) {
				listnode_add(ospf6->oi_write_q, oi);
				oi->on_write_q = 1;
			}
			/*
			 * When ospf6d immediately calls event_execute
			 * for items in the oi_write_q.  The event_execute
			 * will call ospf6_write and cause the oi_write_q
			 * to be emptied.  *IF* there is already an event
			 * scheduled for the oi_write_q by something else
			 * then when it wakes up in the future and attempts
			 * to cycle through items in the queue it will
			 * assert.  Let's stop the t_write event and
			 * if ospf6_write doesn't finish up the work
			 * it will schedule itself again.
			 */
			event_cancel(&ospf6->t_write);
			event_execute(master, ospf6_write, ospf6, 0, NULL);
		} else
			OSPF6_MESSAGE_WRITE_ON(oi);
	}
}

static uint16_t ospf6_make_lsupdate_list(struct ospf6_neighbor *on,
					 struct ospf6_packet **op, int *lsa_cnt)
{
	uint16_t length = OSPF6_LS_UPD_MIN_SIZE;
	struct ospf6_lsa *lsa, *lsanext;

	/* skip over fixed header */
	stream_forward_endp((*op)->s, OSPF6_LS_UPD_MIN_SIZE);

	for (ALL_LSDB(on->lsupdate_list, lsa, lsanext)) {
		if ((length + OSPF6_LSA_SIZE(lsa->header) + OSPF6_HEADER_SIZE) >
		    ospf6_packet_max(on->ospf6_if)) {
			ospf6_fill_header(on->ospf6_if, (*op)->s,
					  length + OSPF6_HEADER_SIZE);
			(*op)->length = length + OSPF6_HEADER_SIZE;
			ospf6_fill_lsupdate_header((*op)->s, *lsa_cnt);
			ospf6_send_lsupdate(on, NULL, *op);

			/* refresh packet */
			*op = ospf6_packet_new(on->ospf6_if->ifmtu);
			length = OSPF6_LS_UPD_MIN_SIZE;
			*lsa_cnt = 0;
			ospf6_make_header(OSPF6_MESSAGE_TYPE_LSUPDATE,
					  on->ospf6_if, (*op)->s);
			stream_forward_endp((*op)->s, OSPF6_LS_UPD_MIN_SIZE);
		}
		ospf6_lsa_age_update_to_send(lsa, on->ospf6_if->transdelay);
		stream_put((*op)->s, lsa->header, OSPF6_LSA_SIZE(lsa->header));
		(*lsa_cnt)++;
		length += OSPF6_LSA_SIZE(lsa->header);
		assert(lsa->lock == 2);
		ospf6_lsdb_remove(lsa, on->lsupdate_list);
	}
	return length;
}

static uint16_t ospf6_make_ls_retrans_list(struct ospf6_neighbor *on,
					   struct ospf6_packet **op,
					   int *lsa_cnt)
{
	uint16_t length = OSPF6_LS_UPD_MIN_SIZE;
	struct ospf6_lsa *lsa, *lsanext;

	/* skip over fixed header */
	stream_forward_endp((*op)->s, OSPF6_LS_UPD_MIN_SIZE);

	for (ALL_LSDB(on->retrans_list, lsa, lsanext)) {
		if ((length + OSPF6_LSA_SIZE(lsa->header) + OSPF6_HEADER_SIZE) >
		    ospf6_packet_max(on->ospf6_if)) {
			ospf6_fill_header(on->ospf6_if, (*op)->s,
					  length + OSPF6_HEADER_SIZE);
			(*op)->length = length + OSPF6_HEADER_SIZE;
			ospf6_fill_lsupdate_header((*op)->s, *lsa_cnt);
			if (on->ospf6_if->state == OSPF6_INTERFACE_POINTTOPOINT)
				(*op)->dst = allspfrouters6;
			else
				(*op)->dst = on->linklocal_addr;

			ospf6_fill_hdr_checksum(on->ospf6_if, *op);
			ospf6_packet_add(on->ospf6_if, *op);
			OSPF6_MESSAGE_WRITE_ON(on->ospf6_if);

			/* refresh packet */
			*op = ospf6_packet_new(on->ospf6_if->ifmtu);
			length = OSPF6_LS_UPD_MIN_SIZE;
			*lsa_cnt = 0;
			ospf6_make_header(OSPF6_MESSAGE_TYPE_LSUPDATE,
					  on->ospf6_if, (*op)->s);
			stream_forward_endp((*op)->s, OSPF6_LS_UPD_MIN_SIZE);
		}
		ospf6_lsa_age_update_to_send(lsa, on->ospf6_if->transdelay);
		stream_put((*op)->s, lsa->header, OSPF6_LSA_SIZE(lsa->header));
		(*lsa_cnt)++;
		length += OSPF6_LSA_SIZE(lsa->header);
	}
	return length;
}

void ospf6_lsupdate_send_neighbor(struct event *thread)
{
	struct ospf6_neighbor *on;
	struct ospf6_packet *op;
	uint16_t length = OSPF6_HEADER_SIZE;
	int lsa_cnt = 0;

	on = (struct ospf6_neighbor *)EVENT_ARG(thread);

	if (IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_LSUPDATE, SEND_HDR))
		zlog_debug("LSUpdate to neighbor %s", on->name);

	if (on->state < OSPF6_NEIGHBOR_EXCHANGE) {
		if (IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_LSUPDATE,
					   SEND_HDR))
			zlog_debug("Quit to send (neighbor state %s)",
				   ospf6_neighbor_state_str[on->state]);
		return;
	}

	/* first do lsupdate_list */
	op = ospf6_packet_new(on->ospf6_if->ifmtu);
	ospf6_make_header(OSPF6_MESSAGE_TYPE_LSUPDATE, on->ospf6_if, op->s);
	length += ospf6_make_lsupdate_list(on, &op, &lsa_cnt);
	if (lsa_cnt) {
		/* Fill OSPF header. */
		ospf6_fill_header(on->ospf6_if, op->s, length);
		ospf6_fill_lsupdate_header(op->s, lsa_cnt);
		op->length = length;
		ospf6_send_lsupdate(on, NULL, op);

		/* prepare new packet */
		op = ospf6_packet_new(on->ospf6_if->ifmtu);
		length = OSPF6_HEADER_SIZE;
		lsa_cnt = 0;
	} else {
		stream_reset(op->s);
		length = OSPF6_HEADER_SIZE;
	}

	ospf6_make_header(OSPF6_MESSAGE_TYPE_LSUPDATE, on->ospf6_if, op->s);
	/* now do retransmit list */
	length += ospf6_make_ls_retrans_list(on, &op, &lsa_cnt);
	if (lsa_cnt) {
		ospf6_fill_header(on->ospf6_if, op->s, length);
		ospf6_fill_lsupdate_header(op->s, lsa_cnt);
		op->length = length;
		if (on->ospf6_if->state == OSPF6_INTERFACE_POINTTOPOINT)
			op->dst = allspfrouters6;
		else
			op->dst = on->linklocal_addr;
		ospf6_fill_hdr_checksum(on->ospf6_if, op);
		ospf6_packet_add(on->ospf6_if, op);
		OSPF6_MESSAGE_WRITE_ON(on->ospf6_if);
	} else
		ospf6_packet_free(op);

	if (on->lsupdate_list->count != 0) {
		event_add_event(master, ospf6_lsupdate_send_neighbor, on, 0,
				&on->thread_send_lsupdate);
	} else if (on->retrans_list->count != 0) {
		event_add_timer(master, ospf6_lsupdate_send_neighbor, on,
				on->ospf6_if->rxmt_interval,
				&on->thread_send_lsupdate);
	}
}

int ospf6_lsupdate_send_neighbor_now(struct ospf6_neighbor *on,
				     struct ospf6_lsa *lsa)
{
	struct ospf6_packet *op;
	uint16_t length = OSPF6_HEADER_SIZE;

	op = ospf6_packet_new(on->ospf6_if->ifmtu);
	ospf6_make_header(OSPF6_MESSAGE_TYPE_LSUPDATE, on->ospf6_if, op->s);

	/* skip over fixed header */
	stream_forward_endp(op->s, OSPF6_LS_UPD_MIN_SIZE);
	ospf6_lsa_age_update_to_send(lsa, on->ospf6_if->transdelay);
	stream_put(op->s, lsa->header, OSPF6_LSA_SIZE(lsa->header));
	length = OSPF6_HEADER_SIZE + OSPF6_LS_UPD_MIN_SIZE
		 + OSPF6_LSA_SIZE(lsa->header);
	ospf6_fill_header(on->ospf6_if, op->s, length);
	ospf6_fill_lsupdate_header(op->s, 1);
	op->length = length;

	if (IS_OSPF6_DEBUG_FLOODING
	    || IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_LSUPDATE, SEND_HDR))
		zlog_debug("%s: Send lsupdate with lsa %s (age %u)", __func__,
			   lsa->name, ntohs(lsa->header->age));

	ospf6_send_lsupdate(on, NULL, op);

	return 0;
}

static uint16_t ospf6_make_lsupdate_interface(struct ospf6_interface *oi,
					      struct ospf6_packet **op,
					      int *lsa_cnt)
{
	uint16_t length = OSPF6_LS_UPD_MIN_SIZE;
	struct ospf6_lsa *lsa, *lsanext;

	/* skip over fixed header */
	stream_forward_endp((*op)->s, OSPF6_LS_UPD_MIN_SIZE);

	for (ALL_LSDB(oi->lsupdate_list, lsa, lsanext)) {
		if (length + OSPF6_LSA_SIZE(lsa->header) + OSPF6_HEADER_SIZE >
		    ospf6_packet_max(oi)) {
			ospf6_fill_header(oi, (*op)->s,
					  length + OSPF6_HEADER_SIZE);
			(*op)->length = length + OSPF6_HEADER_SIZE;
			ospf6_fill_lsupdate_header((*op)->s, *lsa_cnt);
			ospf6_send_lsupdate(NULL, oi, *op);

			/* refresh packet */
			*op = ospf6_packet_new(oi->ifmtu);
			length = OSPF6_LS_UPD_MIN_SIZE;
			*lsa_cnt = 0;
			ospf6_make_header(OSPF6_MESSAGE_TYPE_LSUPDATE, oi,
					  (*op)->s);
			stream_forward_endp((*op)->s, OSPF6_LS_UPD_MIN_SIZE);
		}

		ospf6_lsa_age_update_to_send(lsa, oi->transdelay);
		stream_put((*op)->s, lsa->header, OSPF6_LSA_SIZE(lsa->header));
		(*lsa_cnt)++;
		length += OSPF6_LSA_SIZE(lsa->header);

		assert(lsa->lock == 2);
		ospf6_lsdb_remove(lsa, oi->lsupdate_list);
	}
	return length;
}

void ospf6_lsupdate_send_interface(struct event *thread)
{
	struct ospf6_interface *oi;
	struct ospf6_packet *op;
	uint16_t length = OSPF6_HEADER_SIZE;
	int lsa_cnt = 0;

	oi = (struct ospf6_interface *)EVENT_ARG(thread);

	if (oi->state <= OSPF6_INTERFACE_WAITING) {
		if (IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_LSUPDATE,
					   SEND_HDR))
			zlog_debug(
				"Quit to send LSUpdate to interface %s state %s",
				oi->interface->name,
				ospf6_interface_state_str[oi->state]);
		return;
	}

	/* if we have nothing to send, return */
	if (oi->lsupdate_list->count == 0)
		return;

	op = ospf6_packet_new(oi->ifmtu);
	ospf6_make_header(OSPF6_MESSAGE_TYPE_LSUPDATE, oi, op->s);
	length += ospf6_make_lsupdate_interface(oi, &op, &lsa_cnt);
	if (lsa_cnt) {
		/* Fill OSPF header. */
		ospf6_fill_header(oi, op->s, length);
		ospf6_fill_lsupdate_header(op->s, lsa_cnt);
		op->length = length;
		ospf6_send_lsupdate(NULL, oi, op);
	} else
		ospf6_packet_free(op);

	if (oi->lsupdate_list->count > 0) {
		event_add_event(master, ospf6_lsupdate_send_interface, oi, 0,
				&oi->thread_send_lsupdate);
	}
}

void ospf6_lsack_send_neighbor(struct event *thread)
{
	struct ospf6_neighbor *on;
	struct ospf6_packet *op;
	uint16_t length = OSPF6_HEADER_SIZE;

	on = (struct ospf6_neighbor *)EVENT_ARG(thread);

	if (on->state < OSPF6_NEIGHBOR_EXCHANGE) {
		if (IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_LSACK, SEND_HDR))
			zlog_debug("Quit to send LSAck to neighbor %s state %s",
				   on->name,
				   ospf6_neighbor_state_str[on->state]);
		return;
	}

	/* if we have nothing to send, return */
	if (on->lsack_list->count == 0)
		return;

	op = ospf6_packet_new(on->ospf6_if->ifmtu);
	ospf6_make_header(OSPF6_MESSAGE_TYPE_LSACK, on->ospf6_if, op->s);

	length += ospf6_make_lsack_neighbor(on, &op);

	if (length == OSPF6_HEADER_SIZE) {
		ospf6_packet_free(op);
		return;
	}

	/* Fill OSPF header. */
	ospf6_fill_header(on->ospf6_if, op->s, length);

	/* Set packet length, dst and queue to FIFO. */
	op->length = length;
	op->dst = on->linklocal_addr;
	ospf6_fill_hdr_checksum(on->ospf6_if, op);
	ospf6_packet_add(on->ospf6_if, op);
	OSPF6_MESSAGE_WRITE_ON(on->ospf6_if);

	if (on->lsack_list->count > 0)
		event_add_event(master, ospf6_lsack_send_neighbor, on, 0,
				&on->thread_send_lsack);
}

static uint16_t ospf6_make_lsack_interface(struct ospf6_interface *oi,
					   struct ospf6_packet *op)
{
	uint16_t length = 0;
	struct ospf6_lsa *lsa, *lsanext;

	for (ALL_LSDB(oi->lsack_list, lsa, lsanext)) {
		if ((length + sizeof(struct ospf6_lsa_header)
		     + OSPF6_HEADER_SIZE)
		    > ospf6_packet_max(oi)) {
			/* if we run out of packet size/space here,
			   better to try again soon. */
			EVENT_OFF(oi->thread_send_lsack);
			event_add_event(master, ospf6_lsack_send_interface, oi,
					0, &oi->thread_send_lsack);

			ospf6_lsa_unlock(&lsa);
			if (lsanext)
				ospf6_lsa_unlock(&lsanext);
			break;
		}
		ospf6_lsa_age_update_to_send(lsa, oi->transdelay);
		stream_put(op->s, lsa->header, sizeof(struct ospf6_lsa_header));
		length += sizeof(struct ospf6_lsa_header);

		assert(lsa->lock == 2);
		ospf6_lsdb_remove(lsa, oi->lsack_list);
	}
	return length;
}

void ospf6_lsack_send_interface(struct event *thread)
{
	struct ospf6_interface *oi;
	struct ospf6_packet *op;
	uint16_t length = OSPF6_HEADER_SIZE;

	oi = (struct ospf6_interface *)EVENT_ARG(thread);

	if (oi->state <= OSPF6_INTERFACE_WAITING) {
		if (IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_LSACK, SEND_HDR))
			zlog_debug(
				"Quit to send LSAck to interface %s state %s",
				oi->interface->name,
				ospf6_interface_state_str[oi->state]);
		return;
	}

	/* if we have nothing to send, return */
	if (oi->lsack_list->count == 0)
		return;

	op = ospf6_packet_new(oi->ifmtu);
	ospf6_make_header(OSPF6_MESSAGE_TYPE_LSACK, oi, op->s);

	length += ospf6_make_lsack_interface(oi, op);

	if (length == OSPF6_HEADER_SIZE) {
		ospf6_packet_free(op);
		return;
	}
	/* Fill OSPF header. */
	ospf6_fill_header(oi, op->s, length);

	/* Set packet length, dst and queue to FIFO. */
	op->length = length;
	if ((oi->state == OSPF6_INTERFACE_POINTTOPOINT)
	    || (oi->state == OSPF6_INTERFACE_DR)
	    || (oi->state == OSPF6_INTERFACE_BDR))
		op->dst = allspfrouters6;
	else
		op->dst = alldrouters6;

	ospf6_fill_hdr_checksum(oi, op);
	ospf6_packet_add(oi, op);
	OSPF6_MESSAGE_WRITE_ON(oi);

	if (oi->lsack_list->count > 0)
		event_add_event(master, ospf6_lsack_send_interface, oi, 0,
				&oi->thread_send_lsack);
}

/* Commands */
DEFUN(debug_ospf6_message, debug_ospf6_message_cmd,
      "debug ospf6 message <unknown|hello|dbdesc|lsreq|lsupdate|lsack|all> [<send|recv|send-hdr|recv-hdr>]",
      DEBUG_STR OSPF6_STR
      "Debug OSPFv3 message\n"
      "Debug Unknown message\n"
      "Debug Hello message\n"
      "Debug Database Description message\n"
      "Debug Link State Request message\n"
      "Debug Link State Update message\n"
      "Debug Link State Acknowledgement message\n"
      "Debug All message\n"
      "Debug only sending message, entire packet\n"
      "Debug only receiving message, entire packet\n"
      "Debug only sending message, header only\n"
      "Debug only receiving message, header only\n")
{
	int idx_packet = 3;
	int idx_send_recv = 4;
	unsigned char level = 0;
	int type = 0;
	int i;

	/* check type */
	if (!strncmp(argv[idx_packet]->arg, "u", 1))
		type = OSPF6_MESSAGE_TYPE_UNKNOWN;
	else if (!strncmp(argv[idx_packet]->arg, "h", 1))
		type = OSPF6_MESSAGE_TYPE_HELLO;
	else if (!strncmp(argv[idx_packet]->arg, "d", 1))
		type = OSPF6_MESSAGE_TYPE_DBDESC;
	else if (!strncmp(argv[idx_packet]->arg, "lsr", 3))
		type = OSPF6_MESSAGE_TYPE_LSREQ;
	else if (!strncmp(argv[idx_packet]->arg, "lsu", 3))
		type = OSPF6_MESSAGE_TYPE_LSUPDATE;
	else if (!strncmp(argv[idx_packet]->arg, "lsa", 3))
		type = OSPF6_MESSAGE_TYPE_LSACK;
	else if (!strncmp(argv[idx_packet]->arg, "a", 1))
		type = OSPF6_MESSAGE_TYPE_ALL;

	if (argc == 4)
		level = OSPF6_DEBUG_MESSAGE_SEND | OSPF6_DEBUG_MESSAGE_RECV;
	else if (!strncmp(argv[idx_send_recv]->arg, "send-h", 6))
		level = OSPF6_DEBUG_MESSAGE_SEND_HDR;
	else if (!strncmp(argv[idx_send_recv]->arg, "s", 1))
		level = OSPF6_DEBUG_MESSAGE_SEND;
	else if (!strncmp(argv[idx_send_recv]->arg, "recv-h", 6))
		level = OSPF6_DEBUG_MESSAGE_RECV_HDR;
	else if (!strncmp(argv[idx_send_recv]->arg, "r", 1))
		level = OSPF6_DEBUG_MESSAGE_RECV;

	if (type == OSPF6_MESSAGE_TYPE_ALL) {
		for (i = 0; i < 6; i++)
			OSPF6_DEBUG_MESSAGE_ON(i, level);
	} else
		OSPF6_DEBUG_MESSAGE_ON(type, level);

	return CMD_SUCCESS;
}

DEFUN(no_debug_ospf6_message, no_debug_ospf6_message_cmd,
      "no debug ospf6 message <unknown|hello|dbdesc|lsreq|lsupdate|lsack|all> [<send|recv|send-hdr|recv-hdr>]",
      NO_STR DEBUG_STR OSPF6_STR
      "Debug OSPFv3 message\n"
      "Debug Unknown message\n"
      "Debug Hello message\n"
      "Debug Database Description message\n"
      "Debug Link State Request message\n"
      "Debug Link State Update message\n"
      "Debug Link State Acknowledgement message\n"
      "Debug All message\n"
      "Debug only sending message, entire pkt\n"
      "Debug only receiving message, entire pkt\n"
      "Debug only sending message, header only\n"
      "Debug only receiving message, header only\n")
{
	int idx_packet = 4;
	int idx_send_recv = 5;
	unsigned char level = 0;
	int type = 0;
	int i;

	/* check type */
	if (!strncmp(argv[idx_packet]->arg, "u", 1))
		type = OSPF6_MESSAGE_TYPE_UNKNOWN;
	else if (!strncmp(argv[idx_packet]->arg, "h", 1))
		type = OSPF6_MESSAGE_TYPE_HELLO;
	else if (!strncmp(argv[idx_packet]->arg, "d", 1))
		type = OSPF6_MESSAGE_TYPE_DBDESC;
	else if (!strncmp(argv[idx_packet]->arg, "lsr", 3))
		type = OSPF6_MESSAGE_TYPE_LSREQ;
	else if (!strncmp(argv[idx_packet]->arg, "lsu", 3))
		type = OSPF6_MESSAGE_TYPE_LSUPDATE;
	else if (!strncmp(argv[idx_packet]->arg, "lsa", 3))
		type = OSPF6_MESSAGE_TYPE_LSACK;
	else if (!strncmp(argv[idx_packet]->arg, "a", 1))
		type = OSPF6_MESSAGE_TYPE_ALL;

	if (argc == 5)
		level = OSPF6_DEBUG_MESSAGE_SEND | OSPF6_DEBUG_MESSAGE_RECV
			| OSPF6_DEBUG_MESSAGE_SEND_HDR
			| OSPF6_DEBUG_MESSAGE_RECV_HDR;
	else if (!strncmp(argv[idx_send_recv]->arg, "send-h", 6))
		level = OSPF6_DEBUG_MESSAGE_SEND_HDR;
	else if (!strncmp(argv[idx_send_recv]->arg, "s", 1))
		level = OSPF6_DEBUG_MESSAGE_SEND;
	else if (!strncmp(argv[idx_send_recv]->arg, "recv-h", 6))
		level = OSPF6_DEBUG_MESSAGE_RECV_HDR;
	else if (!strncmp(argv[idx_send_recv]->arg, "r", 1))
		level = OSPF6_DEBUG_MESSAGE_RECV;

	if (type == OSPF6_MESSAGE_TYPE_ALL) {
		for (i = 0; i < 6; i++)
			OSPF6_DEBUG_MESSAGE_OFF(i, level);
	} else
		OSPF6_DEBUG_MESSAGE_OFF(type, level);

	return CMD_SUCCESS;
}


int config_write_ospf6_debug_message(struct vty *vty)
{
	const char *type_str[] = {"unknown", "hello",    "dbdesc",
				  "lsreq",   "lsupdate", "lsack"};
	unsigned char s = 0, r = 0, sh = 0, rh = 0;
	int i;

	for (i = 0; i < 6; i++) {
		if (IS_OSPF6_DEBUG_MESSAGE_ENABLED(i, SEND))
			s |= 1 << i;
		if (IS_OSPF6_DEBUG_MESSAGE_ENABLED(i, RECV))
			r |= 1 << i;
	}

	for (i = 0; i < 6; i++) {
		if (IS_OSPF6_DEBUG_MESSAGE_ENABLED(i, SEND_HDR))
			sh |= 1 << i;
		if (IS_OSPF6_DEBUG_MESSAGE_ENABLED(i, RECV_HDR))
			rh |= 1 << i;
	}

	if (s == 0x3f && r == 0x3f) {
		vty_out(vty, "debug ospf6 message all\n");
		return 0;
	}

	if (s == 0x3f && r == 0) {
		vty_out(vty, "debug ospf6 message all send\n");
		return 0;
	} else if (s == 0 && r == 0x3f) {
		vty_out(vty, "debug ospf6 message all recv\n");
		return 0;
	}

	if (sh == 0x3f && rh == 0) {
		vty_out(vty, "debug ospf6 message all send-hdr\n");
		return 0;
	} else if (sh == 0 && rh == 0x3f) {
		vty_out(vty, "debug ospf6 message all recv-hdr\n");
		return 0;
	}

	/* Unknown message is logged by default */
	if (!IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_UNKNOWN, SEND)
	    && !IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_UNKNOWN, RECV))
		vty_out(vty, "no debug ospf6 message unknown\n");
	else if (!IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_UNKNOWN, SEND))
		vty_out(vty, "no debug ospf6 message unknown send\n");
	else if (!IS_OSPF6_DEBUG_MESSAGE(OSPF6_MESSAGE_TYPE_UNKNOWN, RECV))
		vty_out(vty, "no debug ospf6 message unknown recv\n");

	for (i = 1; i < 6; i++) {
		if (IS_OSPF6_DEBUG_MESSAGE_ENABLED(i, SEND)
		    && IS_OSPF6_DEBUG_MESSAGE_ENABLED(i, RECV)) {
			vty_out(vty, "debug ospf6 message %s\n", type_str[i]);
			continue;
		}

		if (IS_OSPF6_DEBUG_MESSAGE_ENABLED(i, SEND))
			vty_out(vty, "debug ospf6 message %s send\n",
				type_str[i]);
		else if (IS_OSPF6_DEBUG_MESSAGE_ENABLED(i, SEND_HDR))
			vty_out(vty, "debug ospf6 message %s send-hdr\n",
				type_str[i]);

		if (IS_OSPF6_DEBUG_MESSAGE_ENABLED(i, RECV))
			vty_out(vty, "debug ospf6 message %s recv\n",
				type_str[i]);
		else if (IS_OSPF6_DEBUG_MESSAGE_ENABLED(i, RECV_HDR))
			vty_out(vty, "debug ospf6 message %s recv-hdr\n",
				type_str[i]);
	}

	return 0;
}

void install_element_ospf6_debug_message(void)
{
	install_element(ENABLE_NODE, &debug_ospf6_message_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf6_message_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_message_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf6_message_cmd);
}
