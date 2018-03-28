/*
 * Copyright (C) 2003 Yasuhiro Ohara
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

#include <zebra.h>

/* Include other stuffs */
#include "log.h"
#include "linklist.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "memory.h"
#include "thread.h"
#include "checksum.h"

#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_message.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"

#include "ospf6_flood.h"
#include "ospf6d.h"

vector ospf6_lsa_handler_vector;

static int ospf6_unknown_lsa_show(struct vty *vty, struct ospf6_lsa *lsa)
{
	uint8_t *start, *end, *current;
	char byte[4];

	start = (uint8_t *)lsa->header + sizeof(struct ospf6_lsa_header);
	end = (uint8_t *)lsa->header + ntohs(lsa->header->length);

	vty_out(vty, "        Unknown contents:\n");
	for (current = start; current < end; current++) {
		if ((current - start) % 16 == 0)
			vty_out(vty, "\n        ");
		else if ((current - start) % 4 == 0)
			vty_out(vty, " ");

		snprintf(byte, sizeof(byte), "%02x", *current);
		vty_out(vty, "%s", byte);
	}

	vty_out(vty, "\n\n");
	return 0;
}

static struct ospf6_lsa_handler unknown_handler = {
	.lh_type = OSPF6_LSTYPE_UNKNOWN,
	.lh_name = "Unknown",
	.lh_short_name = "Unk",
	.lh_show = ospf6_unknown_lsa_show,
	.lh_get_prefix_str = NULL,
	.lh_debug = 0 /* No default debug */
};

void ospf6_install_lsa_handler(const struct ospf6_lsa_handler *handler)
{
	/* type in handler is host byte order */
	int index = handler->lh_type & OSPF6_LSTYPE_FCODE_MASK;
	vector_set_index(ospf6_lsa_handler_vector, index, (void *)handler);
}

const struct ospf6_lsa_handler *ospf6_get_lsa_handler(uint16_t type)
{
	const struct ospf6_lsa_handler *handler = NULL;
	unsigned int index = ntohs(type) & OSPF6_LSTYPE_FCODE_MASK;

	if (index >= vector_active(ospf6_lsa_handler_vector))
		handler = &unknown_handler;
	else
		handler = vector_slot(ospf6_lsa_handler_vector, index);

	if (handler == NULL)
		handler = &unknown_handler;

	return handler;
}

const char *ospf6_lstype_name(uint16_t type)
{
	static char buf[8];
	const struct ospf6_lsa_handler *handler;

	handler = ospf6_get_lsa_handler(type);
	if (handler && handler != &unknown_handler)
		return handler->lh_name;

	snprintf(buf, sizeof(buf), "0x%04hx", ntohs(type));
	return buf;
}

const char *ospf6_lstype_short_name(uint16_t type)
{
	static char buf[8];
	const struct ospf6_lsa_handler *handler;

	handler = ospf6_get_lsa_handler(type);
	if (handler && handler != &unknown_handler)
		return handler->lh_short_name;

	snprintf(buf, sizeof(buf), "0x%04hx", ntohs(type));
	return buf;
}

uint8_t ospf6_lstype_debug(uint16_t type)
{
	const struct ospf6_lsa_handler *handler;
	handler = ospf6_get_lsa_handler(type);
	return handler->debug;
}

/* RFC2328: Section 13.2 */
int ospf6_lsa_is_differ(struct ospf6_lsa *lsa1, struct ospf6_lsa *lsa2)
{
	int len;

	assert(OSPF6_LSA_IS_SAME(lsa1, lsa2));

	/* XXX, Options ??? */

	ospf6_lsa_age_current(lsa1);
	ospf6_lsa_age_current(lsa2);
	if (ntohs(lsa1->header->age) == OSPF_LSA_MAXAGE
	    && ntohs(lsa2->header->age) != OSPF_LSA_MAXAGE)
		return 1;
	if (ntohs(lsa1->header->age) != OSPF_LSA_MAXAGE
	    && ntohs(lsa2->header->age) == OSPF_LSA_MAXAGE)
		return 1;

	/* compare body */
	if (ntohs(lsa1->header->length) != ntohs(lsa2->header->length))
		return 1;

	len = ntohs(lsa1->header->length) - sizeof(struct ospf6_lsa_header);
	return memcmp(lsa1->header + 1, lsa2->header + 1, len);
}

int ospf6_lsa_is_changed(struct ospf6_lsa *lsa1, struct ospf6_lsa *lsa2)
{
	int length;

	if (OSPF6_LSA_IS_MAXAGE(lsa1) ^ OSPF6_LSA_IS_MAXAGE(lsa2))
		return 1;
	if (ntohs(lsa1->header->length) != ntohs(lsa2->header->length))
		return 1;
	/* Going beyond LSA headers to compare the payload only makes sense,
	 * when both LSAs aren't header-only. */
	if (CHECK_FLAG(lsa1->flag, OSPF6_LSA_HEADERONLY)
	    != CHECK_FLAG(lsa2->flag, OSPF6_LSA_HEADERONLY)) {
		zlog_warn(
			"%s: only one of two (%s, %s) LSAs compared is header-only",
			__func__, lsa1->name, lsa2->name);
		return 1;
	}
	if (CHECK_FLAG(lsa1->flag, OSPF6_LSA_HEADERONLY))
		return 0;

	length = OSPF6_LSA_SIZE(lsa1->header) - sizeof(struct ospf6_lsa_header);
	/* Once upper layer verifies LSAs received, length underrun should
	 * become a warning. */
	if (length <= 0)
		return 0;

	return memcmp(OSPF6_LSA_HEADER_END(lsa1->header),
		      OSPF6_LSA_HEADER_END(lsa2->header), length);
}

/* ospf6 age functions */
/* calculate birth */
void ospf6_lsa_age_set(struct ospf6_lsa *lsa)
{
	struct timeval now;

	assert(lsa && lsa->header);

	monotime(&now);

	lsa->birth.tv_sec = now.tv_sec - ntohs(lsa->header->age);
	lsa->birth.tv_usec = now.tv_usec;

	return;
}

/* this function calculates current age from its birth,
   then update age field of LSA header. return value is current age */
uint16_t ospf6_lsa_age_current(struct ospf6_lsa *lsa)
{
	struct timeval now;
	uint32_t ulage;
	uint16_t age;

	assert(lsa);
	assert(lsa->header);

	/* current time */
	monotime(&now);

	if (ntohs(lsa->header->age) >= OSPF_LSA_MAXAGE) {
		/* ospf6_lsa_premature_aging () sets age to MAXAGE; when using
		   relative time, we cannot compare against lsa birth time, so
		   we catch this special case here. */
		lsa->header->age = htons(OSPF_LSA_MAXAGE);
		return OSPF_LSA_MAXAGE;
	}
	/* calculate age */
	ulage = now.tv_sec - lsa->birth.tv_sec;

	/* if over MAXAGE, set to it */
	age = (ulage > OSPF_LSA_MAXAGE ? OSPF_LSA_MAXAGE : ulage);

	lsa->header->age = htons(age);
	return age;
}

/* update age field of LSA header with adding InfTransDelay */
void ospf6_lsa_age_update_to_send(struct ospf6_lsa *lsa, uint32_t transdelay)
{
	unsigned short age;

	age = ospf6_lsa_age_current(lsa) + transdelay;
	if (age > OSPF_LSA_MAXAGE)
		age = OSPF_LSA_MAXAGE;
	lsa->header->age = htons(age);
}

void ospf6_lsa_premature_aging(struct ospf6_lsa *lsa)
{
	/* log */
	if (IS_OSPF6_DEBUG_LSA_TYPE(lsa->header->type))
		zlog_debug("LSA: Premature aging: %s", lsa->name);

	THREAD_OFF(lsa->expire);
	THREAD_OFF(lsa->refresh);

	/*
	 * We clear the LSA from the neighbor retx lists now because it
	 * will not get deleted later. Essentially, changing the age to
	 * MaxAge will prevent this LSA from being matched with its
	 * existing entries in the retx list thereby causing those entries
	 * to be silently replaced with its MaxAged version, but with ever
	 * increasing retx count causing this LSA to remain forever and
	 * for the MaxAge remover thread to be called forever too.
	 *
	 * The reason the previous entry silently disappears is that when
	 * entry is added to a neighbor's retx list, it replaces the existing
	 * entry. But since the ospf6_lsdb_add() routine is generic and not
	 * aware
	 * of the special semantics of retx count, the retx count is not
	 * decremented when its replaced. Attempting to add the incr and decr
	 * retx count routines as the hook_add and hook_remove for the retx
	 * lists
	 * have a problem because the hook_remove routine is called for MaxAge
	 * entries (as will be the case in a traditional LSDB, unlike in this
	 * case
	 * where an LSDB is used as an efficient tree structure to store all
	 * kinds
	 * of data) that are added instead of calling the hook_add routine.
	 */

	ospf6_flood_clear(lsa);

	lsa->header->age = htons(OSPF_LSA_MAXAGE);
	thread_execute(master, ospf6_lsa_expire, lsa, 0);
}

/* check which is more recent. if a is more recent, return -1;
   if the same, return 0; otherwise(b is more recent), return 1 */
int ospf6_lsa_compare(struct ospf6_lsa *a, struct ospf6_lsa *b)
{
	int32_t seqnuma, seqnumb;
	uint16_t cksuma, cksumb;
	uint16_t agea, ageb;

	assert(a && a->header);
	assert(b && b->header);
	assert(OSPF6_LSA_IS_SAME(a, b));

	seqnuma = (int32_t)ntohl(a->header->seqnum);
	seqnumb = (int32_t)ntohl(b->header->seqnum);

	/* compare by sequence number */
	if (seqnuma > seqnumb)
		return -1;
	if (seqnuma < seqnumb)
		return 1;

	/* Checksum */
	cksuma = ntohs(a->header->checksum);
	cksumb = ntohs(b->header->checksum);
	if (cksuma > cksumb)
		return -1;
	if (cksuma < cksumb)
		return 0;

	/* Update Age */
	agea = ospf6_lsa_age_current(a);
	ageb = ospf6_lsa_age_current(b);

	/* MaxAge check */
	if (agea == OSPF_LSA_MAXAGE && ageb != OSPF_LSA_MAXAGE)
		return -1;
	else if (agea != OSPF_LSA_MAXAGE && ageb == OSPF_LSA_MAXAGE)
		return 1;

	/* Age check */
	if (agea > ageb && agea - ageb >= OSPF_LSA_MAXAGE_DIFF)
		return 1;
	else if (agea < ageb && ageb - agea >= OSPF_LSA_MAXAGE_DIFF)
		return -1;

	/* neither recent */
	return 0;
}

char *ospf6_lsa_printbuf(struct ospf6_lsa *lsa, char *buf, int size)
{
	char id[16], adv_router[16];
	inet_ntop(AF_INET, &lsa->header->id, id, sizeof(id));
	inet_ntop(AF_INET, &lsa->header->adv_router, adv_router,
		  sizeof(adv_router));
	snprintf(buf, size, "[%s Id:%s Adv:%s]",
		 ospf6_lstype_name(lsa->header->type), id, adv_router);
	return buf;
}

void ospf6_lsa_header_print_raw(struct ospf6_lsa_header *header)
{
	char id[16], adv_router[16];
	inet_ntop(AF_INET, &header->id, id, sizeof(id));
	inet_ntop(AF_INET, &header->adv_router, adv_router, sizeof(adv_router));
	zlog_debug("    [%s Id:%s Adv:%s]", ospf6_lstype_name(header->type), id,
		   adv_router);
	zlog_debug("    Age: %4hu SeqNum: %#08lx Cksum: %04hx Len: %d",
		   ntohs(header->age), (unsigned long)ntohl(header->seqnum),
		   ntohs(header->checksum), ntohs(header->length));
}

void ospf6_lsa_header_print(struct ospf6_lsa *lsa)
{
	ospf6_lsa_age_current(lsa);
	ospf6_lsa_header_print_raw(lsa->header);
}

void ospf6_lsa_show_summary_header(struct vty *vty)
{
	vty_out(vty, "%-4s %-15s%-15s%4s %8s %30s\n", "Type", "LSId",
		"AdvRouter", "Age", "SeqNum", "Payload");
}

void ospf6_lsa_show_summary(struct vty *vty, struct ospf6_lsa *lsa)
{
	char adv_router[16], id[16];
	int type;
	const struct ospf6_lsa_handler *handler;
	char buf[64], tmpbuf[80];
	int cnt = 0;

	assert(lsa);
	assert(lsa->header);

	inet_ntop(AF_INET, &lsa->header->id, id, sizeof(id));
	inet_ntop(AF_INET, &lsa->header->adv_router, adv_router,
		  sizeof(adv_router));

	type = ntohs(lsa->header->type);
	handler = ospf6_get_lsa_handler(lsa->header->type);
	if ((type == OSPF6_LSTYPE_INTER_PREFIX)
	    || (type == OSPF6_LSTYPE_INTER_ROUTER)
	    || (type == OSPF6_LSTYPE_AS_EXTERNAL)) {
		vty_out(vty, "%-4s %-15s%-15s%4hu %8lx %30s\n",
			ospf6_lstype_short_name(lsa->header->type), id,
			adv_router, ospf6_lsa_age_current(lsa),
			(unsigned long)ntohl(lsa->header->seqnum),
			handler->lh_get_prefix_str(lsa, buf, sizeof(buf), 0));
	} else if (type != OSPF6_LSTYPE_UNKNOWN) {
		sprintf(tmpbuf, "%-4s %-15s%-15s%4hu %8lx",
			ospf6_lstype_short_name(lsa->header->type), id,
			adv_router, ospf6_lsa_age_current(lsa),
			(unsigned long)ntohl(lsa->header->seqnum));

		while (handler->lh_get_prefix_str(lsa, buf, sizeof(buf), cnt)
		       != NULL) {
			vty_out(vty, "%s %30s\n", tmpbuf, buf);
			cnt++;
		}
	} else {
		vty_out(vty, "%-4s %-15s%-15s%4hu %8lx\n",
			ospf6_lstype_short_name(lsa->header->type), id,
			adv_router, ospf6_lsa_age_current(lsa),
			(unsigned long)ntohl(lsa->header->seqnum));
	}
}

void ospf6_lsa_show_dump(struct vty *vty, struct ospf6_lsa *lsa)
{
	uint8_t *start, *end, *current;
	char byte[4];

	start = (uint8_t *)lsa->header;
	end = (uint8_t *)lsa->header + ntohs(lsa->header->length);

	vty_out(vty, "\n");
	vty_out(vty, "%s:\n", lsa->name);

	for (current = start; current < end; current++) {
		if ((current - start) % 16 == 0)
			vty_out(vty, "\n        ");
		else if ((current - start) % 4 == 0)
			vty_out(vty, " ");

		snprintf(byte, sizeof(byte), "%02x", *current);
		vty_out(vty, "%s", byte);
	}

	vty_out(vty, "\n\n");
	return;
}

void ospf6_lsa_show_internal(struct vty *vty, struct ospf6_lsa *lsa)
{
	char adv_router[64], id[64];

	assert(lsa && lsa->header);

	inet_ntop(AF_INET, &lsa->header->id, id, sizeof(id));
	inet_ntop(AF_INET, &lsa->header->adv_router, adv_router,
		  sizeof(adv_router));

	vty_out(vty, "\n");
	vty_out(vty, "Age: %4hu Type: %s\n", ospf6_lsa_age_current(lsa),
		ospf6_lstype_name(lsa->header->type));
	vty_out(vty, "Link State ID: %s\n", id);
	vty_out(vty, "Advertising Router: %s\n", adv_router);
	vty_out(vty, "LS Sequence Number: %#010lx\n",
		(unsigned long)ntohl(lsa->header->seqnum));
	vty_out(vty, "CheckSum: %#06hx Length: %hu\n",
		ntohs(lsa->header->checksum), ntohs(lsa->header->length));
	vty_out(vty, "Flag: %x \n", lsa->flag);
	vty_out(vty, "Lock: %d \n", lsa->lock);
	vty_out(vty, "ReTx Count: %d\n", lsa->retrans_count);
	vty_out(vty, "Threads: Expire: 0x%p, Refresh: 0x%p \n",
		(void *)lsa->expire, (void *)lsa->refresh);
	vty_out(vty, "\n");
	return;
}

void ospf6_lsa_show(struct vty *vty, struct ospf6_lsa *lsa)
{
	char adv_router[64], id[64];
	const struct ospf6_lsa_handler *handler;
	struct timeval now, res;
	char duration[64];

	assert(lsa && lsa->header);

	inet_ntop(AF_INET, &lsa->header->id, id, sizeof(id));
	inet_ntop(AF_INET, &lsa->header->adv_router, adv_router,
		  sizeof(adv_router));

	monotime(&now);
	timersub(&now, &lsa->installed, &res);
	timerstring(&res, duration, sizeof(duration));

	vty_out(vty, "Age: %4hu Type: %s\n", ospf6_lsa_age_current(lsa),
		ospf6_lstype_name(lsa->header->type));
	vty_out(vty, "Link State ID: %s\n", id);
	vty_out(vty, "Advertising Router: %s\n", adv_router);
	vty_out(vty, "LS Sequence Number: %#010lx\n",
		(unsigned long)ntohl(lsa->header->seqnum));
	vty_out(vty, "CheckSum: %#06hx Length: %hu\n",
		ntohs(lsa->header->checksum), ntohs(lsa->header->length));
	vty_out(vty, "Duration: %s\n", duration);

	handler = ospf6_get_lsa_handler(lsa->header->type);

	if (handler->lh_show != NULL)
		handler->lh_show(vty, lsa);
	else {
		assert(unknown_handler.lh_show != NULL);
		unknown_handler.lh_show(vty, lsa);
	}

	vty_out(vty, "\n");
}

/* OSPFv3 LSA creation/deletion function */
struct ospf6_lsa *ospf6_lsa_create(struct ospf6_lsa_header *header)
{
	struct ospf6_lsa *lsa = NULL;
	struct ospf6_lsa_header *new_header = NULL;
	uint16_t lsa_size = 0;

	/* size of the entire LSA */
	lsa_size = ntohs(header->length); /* XXX vulnerable */

	/* allocate memory for this LSA */
	new_header = (struct ospf6_lsa_header *)XMALLOC(MTYPE_OSPF6_LSA_HEADER,
							lsa_size);

	/* copy LSA from original header */
	memcpy(new_header, header, lsa_size);

	/* LSA information structure */
	/* allocate memory */
	lsa = (struct ospf6_lsa *)XCALLOC(MTYPE_OSPF6_LSA,
					  sizeof(struct ospf6_lsa));

	lsa->header = (struct ospf6_lsa_header *)new_header;

	/* dump string */
	ospf6_lsa_printbuf(lsa, lsa->name, sizeof(lsa->name));

	/* calculate birth of this lsa */
	ospf6_lsa_age_set(lsa);

	return lsa;
}

struct ospf6_lsa *ospf6_lsa_create_headeronly(struct ospf6_lsa_header *header)
{
	struct ospf6_lsa *lsa = NULL;
	struct ospf6_lsa_header *new_header = NULL;

	/* allocate memory for this LSA */
	new_header = (struct ospf6_lsa_header *)XMALLOC(
		MTYPE_OSPF6_LSA_HEADER, sizeof(struct ospf6_lsa_header));

	/* copy LSA from original header */
	memcpy(new_header, header, sizeof(struct ospf6_lsa_header));

	/* LSA information structure */
	/* allocate memory */
	lsa = (struct ospf6_lsa *)XCALLOC(MTYPE_OSPF6_LSA,
					  sizeof(struct ospf6_lsa));

	lsa->header = (struct ospf6_lsa_header *)new_header;
	SET_FLAG(lsa->flag, OSPF6_LSA_HEADERONLY);

	/* dump string */
	ospf6_lsa_printbuf(lsa, lsa->name, sizeof(lsa->name));

	/* calculate birth of this lsa */
	ospf6_lsa_age_set(lsa);

	return lsa;
}

void ospf6_lsa_delete(struct ospf6_lsa *lsa)
{
	assert(lsa->lock == 0);

	/* cancel threads */
	THREAD_OFF(lsa->expire);
	THREAD_OFF(lsa->refresh);

	/* do free */
	XFREE(MTYPE_OSPF6_LSA_HEADER, lsa->header);
	XFREE(MTYPE_OSPF6_LSA, lsa);
}

struct ospf6_lsa *ospf6_lsa_copy(struct ospf6_lsa *lsa)
{
	struct ospf6_lsa *copy = NULL;

	ospf6_lsa_age_current(lsa);
	if (CHECK_FLAG(lsa->flag, OSPF6_LSA_HEADERONLY))
		copy = ospf6_lsa_create_headeronly(lsa->header);
	else
		copy = ospf6_lsa_create(lsa->header);
	assert(copy->lock == 0);

	copy->birth = lsa->birth;
	copy->originated = lsa->originated;
	copy->received = lsa->received;
	copy->installed = lsa->installed;
	copy->lsdb = lsa->lsdb;
	copy->rn = NULL;

	return copy;
}

/* increment reference counter of struct ospf6_lsa */
void ospf6_lsa_lock(struct ospf6_lsa *lsa)
{
	lsa->lock++;
	return;
}

/* decrement reference counter of struct ospf6_lsa */
void ospf6_lsa_unlock(struct ospf6_lsa *lsa)
{
	/* decrement reference counter */
	assert(lsa->lock > 0);
	lsa->lock--;

	if (lsa->lock != 0)
		return;

	ospf6_lsa_delete(lsa);
}


/* ospf6 lsa expiry */
int ospf6_lsa_expire(struct thread *thread)
{
	struct ospf6_lsa *lsa;

	lsa = (struct ospf6_lsa *)THREAD_ARG(thread);

	assert(lsa && lsa->header);
	assert(OSPF6_LSA_IS_MAXAGE(lsa));
	assert(!lsa->refresh);

	lsa->expire = (struct thread *)NULL;

	if (IS_OSPF6_DEBUG_LSA_TYPE(lsa->header->type)) {
		zlog_debug("LSA Expire:");
		ospf6_lsa_header_print(lsa);
	}

	if (CHECK_FLAG(lsa->flag, OSPF6_LSA_HEADERONLY))
		return 0; /* dbexchange will do something ... */

	/* reinstall lsa */
	ospf6_install_lsa(lsa);

	/* reflood lsa */
	ospf6_flood(NULL, lsa);

	/* schedule maxage remover */
	ospf6_maxage_remove(ospf6);

	return 0;
}

int ospf6_lsa_refresh(struct thread *thread)
{
	struct ospf6_lsa *old, *self, *new;
	struct ospf6_lsdb *lsdb_self;

	old = (struct ospf6_lsa *)THREAD_ARG(thread);
	assert(old && old->header);

	old->refresh = (struct thread *)NULL;

	lsdb_self = ospf6_get_scoped_lsdb_self(old);
	self = ospf6_lsdb_lookup(old->header->type, old->header->id,
				 old->header->adv_router, lsdb_self);
	if (self == NULL) {
		if (IS_OSPF6_DEBUG_LSA_TYPE(old->header->type))
			zlog_debug("Refresh: could not find self LSA, flush %s",
				   old->name);
		ospf6_lsa_premature_aging(old);
		return 0;
	}

	/* Reset age, increment LS sequence number. */
	self->header->age = htons(0);
	self->header->seqnum =
		ospf6_new_ls_seqnum(self->header->type, self->header->id,
				    self->header->adv_router, old->lsdb);
	ospf6_lsa_checksum(self->header);

	new = ospf6_lsa_create(self->header);
	new->lsdb = old->lsdb;
	new->refresh = NULL;
	thread_add_timer(master, ospf6_lsa_refresh, new, OSPF_LS_REFRESH_TIME,
			 &new->refresh);

	/* store it in the LSDB for self-originated LSAs */
	ospf6_lsdb_add(ospf6_lsa_copy(new), lsdb_self);

	if (IS_OSPF6_DEBUG_LSA_TYPE(new->header->type)) {
		zlog_debug("LSA Refresh:");
		ospf6_lsa_header_print(new);
	}

	ospf6_install_lsa(new);
	ospf6_flood(NULL, new);

	return 0;
}

void ospf6_flush_self_originated_lsas_now(void)
{
	struct listnode *node;
	struct ospf6_area *oa;
	struct ospf6_lsa *lsa;
	const struct route_node *end = NULL;
	uint32_t type, adv_router;

	ospf6->inst_shutdown = 1;

	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, node, oa)) {
		end = ospf6_lsdb_head(oa->lsdb_self, 0, 0, ospf6->router_id,
				      &lsa);
		while (lsa) {
			/* RFC 2328 (14.1):  Set MAXAGE */
			lsa->header->age = htons(OSPF_LSA_MAXAGE);
			/* Flood MAXAGE LSA*/
			ospf6_flood(NULL, lsa);

			lsa = ospf6_lsdb_next(end, lsa);
		}
	}

	type = htons(OSPF6_LSTYPE_AS_EXTERNAL);
	adv_router = ospf6->router_id;
	for (ALL_LSDB_TYPED_ADVRTR(ospf6->lsdb, type, adv_router, lsa)) {
		/* RFC 2328 (14.1):  Set MAXAGE */
		lsa->header->age = htons(OSPF_LSA_MAXAGE);
		ospf6_flood(NULL, lsa);
	}
}

/* Fletcher Checksum -- Refer to RFC1008. */

/* All the offsets are zero-based. The offsets in the RFC1008 are
   one-based. */
unsigned short ospf6_lsa_checksum(struct ospf6_lsa_header *lsa_header)
{
	uint8_t *buffer = (uint8_t *)&lsa_header->type;
	int type_offset =
		buffer - (uint8_t *)&lsa_header->age; /* should be 2 */

	/* Skip the AGE field */
	uint16_t len = ntohs(lsa_header->length) - type_offset;

	/* Checksum offset starts from "type" field, not the beginning of the
	   lsa_header struct. The offset is 14, rather than 16. */
	int checksum_offset = (uint8_t *)&lsa_header->checksum - buffer;

	return (unsigned short)fletcher_checksum(buffer, len, checksum_offset);
}

int ospf6_lsa_checksum_valid(struct ospf6_lsa_header *lsa_header)
{
	uint8_t *buffer = (uint8_t *)&lsa_header->type;
	int type_offset =
		buffer - (uint8_t *)&lsa_header->age; /* should be 2 */

	/* Skip the AGE field */
	uint16_t len = ntohs(lsa_header->length) - type_offset;

	return (fletcher_checksum(buffer, len, FLETCHER_CHECKSUM_VALIDATE)
		== 0);
}

void ospf6_lsa_init(void)
{
	ospf6_lsa_handler_vector = vector_init(0);
	ospf6_install_lsa_handler(&unknown_handler);
}

void ospf6_lsa_terminate(void)
{
	vector_free(ospf6_lsa_handler_vector);
}

static char *ospf6_lsa_handler_name(const struct ospf6_lsa_handler *h)
{
	static char buf[64];
	unsigned int i;
	unsigned int size = strlen(h->lh_name);

	if (!strcmp(h->lh_name, "unknown")
	    && h->lh_type != OSPF6_LSTYPE_UNKNOWN) {
		snprintf(buf, sizeof(buf), "%#04hx", h->lh_type);
		return buf;
	}

	for (i = 0; i < MIN(size, sizeof(buf)); i++) {
		if (!islower((unsigned char)h->lh_name[i]))
			buf[i] = tolower((unsigned char)h->lh_name[i]);
		else
			buf[i] = h->lh_name[i];
	}
	buf[size] = '\0';
	return buf;
}

DEFUN (debug_ospf6_lsa_type,
       debug_ospf6_lsa_hex_cmd,
       "debug ospf6 lsa <router|network|inter-prefix|inter-router|as-external|link|intra-prefix|unknown> [<originate|examine|flooding>]",
       DEBUG_STR
       OSPF6_STR
       "Debug Link State Advertisements (LSAs)\n"
       "Display Router LSAs\n"
       "Display Network LSAs\n"
       "Display Inter-Area-Prefix LSAs\n"
       "Display Inter-Router LSAs\n"
       "Display As-External LSAs\n"
       "Display Link LSAs\n"
       "Display Intra-Area-Prefix LSAs\n"
       "Display LSAs of unknown origin\n"
       "Display details of LSAs\n"
       "Dump LSAs\n"
       "Display LSA's internal information\n")
{
	int idx_lsa = 3;
	int idx_type = 4;
	unsigned int i;
	struct ospf6_lsa_handler *handler = NULL;

	for (i = 0; i < vector_active(ospf6_lsa_handler_vector); i++) {
		handler = vector_slot(ospf6_lsa_handler_vector, i);
		if (handler == NULL)
			continue;
		if (strncmp(argv[idx_lsa]->arg, ospf6_lsa_handler_name(handler),
			    strlen(argv[idx_lsa]->arg))
		    == 0)
			break;
		if (!strcasecmp(argv[idx_lsa]->arg, handler->lh_name))
			break;
		handler = NULL;
	}

	if (handler == NULL)
		handler = &unknown_handler;

	if (argc == 5) {
		if (strmatch(argv[idx_type]->text, "originate"))
			SET_FLAG(handler->debug, OSPF6_LSA_DEBUG_ORIGINATE);
		else if (strmatch(argv[idx_type]->text, "examine"))
			SET_FLAG(handler->debug, OSPF6_LSA_DEBUG_EXAMIN);
		else if (strmatch(argv[idx_type]->text, "flooding"))
			SET_FLAG(handler->debug, OSPF6_LSA_DEBUG_FLOOD);
	} else
		SET_FLAG(handler->debug, OSPF6_LSA_DEBUG);

	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_lsa_type,
       no_debug_ospf6_lsa_hex_cmd,
       "no debug ospf6 lsa <router|network|inter-prefix|inter-router|as-external|link|intra-prefix|unknown> [<originate|examine|flooding>]",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug Link State Advertisements (LSAs)\n"
       "Display Router LSAs\n"
       "Display Network LSAs\n"
       "Display Inter-Area-Prefix LSAs\n"
       "Display Inter-Router LSAs\n"
       "Display As-External LSAs\n"
       "Display Link LSAs\n"
       "Display Intra-Area-Prefix LSAs\n"
       "Display LSAs of unknown origin\n"
       "Display details of LSAs\n"
       "Dump LSAs\n"
       "Display LSA's internal information\n")
{
	int idx_lsa = 4;
	int idx_type = 5;
	unsigned int i;
	struct ospf6_lsa_handler *handler = NULL;

	for (i = 0; i < vector_active(ospf6_lsa_handler_vector); i++) {
		handler = vector_slot(ospf6_lsa_handler_vector, i);
		if (handler == NULL)
			continue;
		if (strncmp(argv[idx_lsa]->arg, ospf6_lsa_handler_name(handler),
			    strlen(argv[idx_lsa]->arg))
		    == 0)
			break;
		if (!strcasecmp(argv[idx_lsa]->arg, handler->lh_name))
			break;
	}

	if (handler == NULL)
		return CMD_SUCCESS;

	if (argc == 6) {
		if (strmatch(argv[idx_type]->text, "originate"))
			UNSET_FLAG(handler->debug, OSPF6_LSA_DEBUG_ORIGINATE);
		if (strmatch(argv[idx_type]->text, "examine"))
			UNSET_FLAG(handler->debug, OSPF6_LSA_DEBUG_EXAMIN);
		if (strmatch(argv[idx_type]->text, "flooding"))
			UNSET_FLAG(handler->debug, OSPF6_LSA_DEBUG_FLOOD);
	} else
		UNSET_FLAG(handler->debug, OSPF6_LSA_DEBUG);

	return CMD_SUCCESS;
}

void install_element_ospf6_debug_lsa(void)
{
	install_element(ENABLE_NODE, &debug_ospf6_lsa_hex_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf6_lsa_hex_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_lsa_hex_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf6_lsa_hex_cmd);
}

int config_write_ospf6_debug_lsa(struct vty *vty)
{
	unsigned int i;
	const struct ospf6_lsa_handler *handler;

	for (i = 0; i < vector_active(ospf6_lsa_handler_vector); i++) {
		handler = vector_slot(ospf6_lsa_handler_vector, i);
		if (handler == NULL)
			continue;
		if (CHECK_FLAG(handler->debug, OSPF6_LSA_DEBUG))
			vty_out(vty, "debug ospf6 lsa %s\n",
				ospf6_lsa_handler_name(handler));
		if (CHECK_FLAG(handler->debug, OSPF6_LSA_DEBUG_ORIGINATE))
			vty_out(vty, "debug ospf6 lsa %s originate\n",
				ospf6_lsa_handler_name(handler));
		if (CHECK_FLAG(handler->debug, OSPF6_LSA_DEBUG_EXAMIN))
			vty_out(vty, "debug ospf6 lsa %s examine\n",
				ospf6_lsa_handler_name(handler));
		if (CHECK_FLAG(handler->debug, OSPF6_LSA_DEBUG_FLOOD))
			vty_out(vty, "debug ospf6 lsa %s flooding\n",
				ospf6_lsa_handler_name(handler));
	}

	return 0;
}
