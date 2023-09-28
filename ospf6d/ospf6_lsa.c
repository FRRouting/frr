// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#include <zebra.h>

/* Include other stuffs */
#include "log.h"
#include "linklist.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "memory.h"
#include "frrevent.h"
#include "checksum.h"
#include "frrstr.h"

#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_message.h"
#include "ospf6_asbr.h"
#include "ospf6_zebra.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"

#include "ospf6_flood.h"
#include "ospf6d.h"

#include "ospf6d/ospf6_lsa_clippy.c"

DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_LSA,         "OSPF6 LSA");
DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_LSA_HEADER,  "OSPF6 LSA header");
DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_LSA_SUMMARY, "OSPF6 LSA summary");

static struct ospf6_lsa_handler *lsa_handlers[OSPF6_LSTYPE_SIZE];

struct ospf6 *ospf6_get_by_lsdb(struct ospf6_lsa *lsa)
{
	struct ospf6 *ospf6 = NULL;

	switch (OSPF6_LSA_SCOPE(lsa->header->type)) {
	case OSPF6_SCOPE_LINKLOCAL:
		ospf6 = OSPF6_INTERFACE(lsa->lsdb->data)->area->ospf6;
		break;
	case OSPF6_SCOPE_AREA:
		ospf6 = OSPF6_AREA(lsa->lsdb->data)->ospf6;
		break;
	case OSPF6_SCOPE_AS:
		ospf6 = OSPF6_PROCESS(lsa->lsdb->data);
		break;
	default:
		assert(0);
		break;
	}
	return ospf6;
}

static int ospf6_unknown_lsa_show(struct vty *vty, struct ospf6_lsa *lsa,
				  json_object *json_obj, bool use_json)
{
	uint8_t *start, *end, *current;

	start = (uint8_t *)lsa->header + sizeof(struct ospf6_lsa_header);
	end = (uint8_t *)lsa->header + ntohs(lsa->header->length);

	if (use_json) {
		json_object_string_add(json_obj, "lsaType", "unknown");
	} else {
		vty_out(vty, "        Unknown contents:\n");
		for (current = start; current < end; current++) {
			if ((current - start) % 16 == 0)
				vty_out(vty, "\n        ");
			else if ((current - start) % 4 == 0)
				vty_out(vty, " ");

			vty_out(vty, "%02x", *current);
		}

		vty_out(vty, "\n\n");
	}
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

void ospf6_install_lsa_handler(struct ospf6_lsa_handler *handler)
{
	/* type in handler is host byte order */
	unsigned int index = handler->lh_type & OSPF6_LSTYPE_FCODE_MASK;

	assertf(index < array_size(lsa_handlers), "index=%x", index);
	assertf(lsa_handlers[index] == NULL, "old=%s, new=%s",
		lsa_handlers[index]->lh_name, handler->lh_name);

	lsa_handlers[index] = handler;
}

struct ospf6_lsa_handler *ospf6_get_lsa_handler(uint16_t type)
{
	struct ospf6_lsa_handler *handler = NULL;
	unsigned int index = ntohs(type) & OSPF6_LSTYPE_FCODE_MASK;

	if (index < array_size(lsa_handlers))
		handler = lsa_handlers[index];

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
	if (handler)
		return handler->lh_short_name;

	snprintf(buf, sizeof(buf), "0x%04hx", ntohs(type));
	return buf;
}

uint8_t ospf6_lstype_debug(uint16_t type)
{
	const struct ospf6_lsa_handler *handler;
	handler = ospf6_get_lsa_handler(type);
	return handler->lh_debug;
}

int metric_type(struct ospf6 *ospf6, int type, uint8_t instance)
{
	struct ospf6_redist *red;

	red = ospf6_redist_lookup(ospf6, type, instance);

	return ((!red || red->dmetric.type < 0) ? DEFAULT_METRIC_TYPE
						: red->dmetric.type);
}

int metric_value(struct ospf6 *ospf6, int type, uint8_t instance)
{
	struct ospf6_redist *red;

	red = ospf6_redist_lookup(ospf6, type, instance);
	if (!red || red->dmetric.value < 0) {
		if (type == DEFAULT_ROUTE) {
			if (ospf6->default_originate == DEFAULT_ORIGINATE_ZEBRA)
				return DEFAULT_DEFAULT_ORIGINATE_METRIC;
			else
				return DEFAULT_DEFAULT_ALWAYS_METRIC;
		} else
			return DEFAULT_DEFAULT_METRIC;
	}

	return red->dmetric.value;
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

	EVENT_OFF(lsa->expire);
	EVENT_OFF(lsa->refresh);

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
	event_execute(master, ospf6_lsa_expire, lsa, 0, NULL);
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

void ospf6_lsa_show_summary(struct vty *vty, struct ospf6_lsa *lsa,
			    json_object *json_array, bool use_json)
{
	char adv_router[16], id[16];
	int type;
	const struct ospf6_lsa_handler *handler;
	char buf[64];
	int cnt = 0;
	json_object *json_obj = NULL;

	assert(lsa);
	assert(lsa->header);

	inet_ntop(AF_INET, &lsa->header->id, id, sizeof(id));
	inet_ntop(AF_INET, &lsa->header->adv_router, adv_router,
		  sizeof(adv_router));

	type = ntohs(lsa->header->type);
	handler = ospf6_get_lsa_handler(lsa->header->type);

	if (use_json)
		json_obj = json_object_new_object();

	switch (type) {
	case OSPF6_LSTYPE_INTER_PREFIX:
	case OSPF6_LSTYPE_INTER_ROUTER:
	case OSPF6_LSTYPE_AS_EXTERNAL:
	case OSPF6_LSTYPE_TYPE_7:
		if (use_json) {
			json_object_string_add(
				json_obj, "type",
				ospf6_lstype_short_name(lsa->header->type));
			json_object_string_add(json_obj, "lsId", id);
			json_object_string_add(json_obj, "advRouter",
					       adv_router);
			json_object_int_add(json_obj, "age",
					    ospf6_lsa_age_current(lsa));
			json_object_int_add(
				json_obj, "seqNum",
				(unsigned long)ntohl(lsa->header->seqnum));
			json_object_string_add(
				json_obj, "payload",
				handler->lh_get_prefix_str(lsa, buf,
							   sizeof(buf), 0));
			json_object_array_add(json_array, json_obj);
		} else
			vty_out(vty, "%-4s %-15s%-15s%4hu %8lx %30s\n",
				ospf6_lstype_short_name(lsa->header->type), id,
				adv_router, ospf6_lsa_age_current(lsa),
				(unsigned long)ntohl(lsa->header->seqnum),
				handler->lh_get_prefix_str(lsa, buf,
							   sizeof(buf), 0));
		break;
	case OSPF6_LSTYPE_ROUTER:
	case OSPF6_LSTYPE_NETWORK:
	case OSPF6_LSTYPE_GROUP_MEMBERSHIP:
	case OSPF6_LSTYPE_LINK:
	case OSPF6_LSTYPE_INTRA_PREFIX:
		while (handler->lh_get_prefix_str(lsa, buf, sizeof(buf), cnt)
		       != NULL) {
			if (use_json) {
				json_object_string_add(
					json_obj, "type",
					ospf6_lstype_short_name(
						lsa->header->type));
				json_object_string_add(json_obj, "lsId", id);
				json_object_string_add(json_obj, "advRouter",
						       adv_router);
				json_object_int_add(json_obj, "age",
						    ospf6_lsa_age_current(lsa));
				json_object_int_add(
					json_obj, "seqNum",
					(unsigned long)ntohl(
						lsa->header->seqnum));
				json_object_string_add(json_obj, "payload",
						       buf);
				json_object_array_add(json_array, json_obj);
				json_obj = json_object_new_object();
			} else
				vty_out(vty, "%-4s %-15s%-15s%4hu %8lx %30s\n",
					ospf6_lstype_short_name(
						lsa->header->type),
					id, adv_router,
					ospf6_lsa_age_current(lsa),
					(unsigned long)ntohl(
						lsa->header->seqnum),
					buf);
			cnt++;
		}
		if (use_json)
			json_object_free(json_obj);
		break;
	default:
		if (use_json) {
			json_object_string_add(
				json_obj, "type",
				ospf6_lstype_short_name(lsa->header->type));
			json_object_string_add(json_obj, "lsId", id);
			json_object_string_add(json_obj, "advRouter",
					       adv_router);
			json_object_int_add(json_obj, "age",
					    ospf6_lsa_age_current(lsa));
			json_object_int_add(
				json_obj, "seqNum",
				(unsigned long)ntohl(lsa->header->seqnum));
			json_object_array_add(json_array, json_obj);
		} else
			vty_out(vty, "%-4s %-15s%-15s%4hu %8lx\n",
				ospf6_lstype_short_name(lsa->header->type), id,
				adv_router, ospf6_lsa_age_current(lsa),
				(unsigned long)ntohl(lsa->header->seqnum));
		break;
	}
}

void ospf6_lsa_show_dump(struct vty *vty, struct ospf6_lsa *lsa,
			 json_object *json_array, bool use_json)
{
	uint8_t *start = NULL;
	uint8_t *end = NULL;
	uint8_t *current = NULL;
	char byte[4];
	char *header_str = NULL;
	char adv_router[INET6_ADDRSTRLEN];
	char id[INET6_ADDRSTRLEN];
	json_object *json = NULL;

	start = (uint8_t *)lsa->header;
	end = (uint8_t *)lsa->header + ntohs(lsa->header->length);

	if (use_json) {
		json = json_object_new_object();
		size_t header_str_sz = (2 * (end - start)) + 1;

		header_str = XMALLOC(MTYPE_OSPF6_LSA_HEADER, header_str_sz);

		inet_ntop(AF_INET, &lsa->header->id, id, sizeof(id));
		inet_ntop(AF_INET, &lsa->header->adv_router, adv_router,
			  sizeof(adv_router));

		frrstr_hex(header_str, header_str_sz, start, end - start);

		json_object_string_add(json, "linkStateId", id);
		json_object_string_add(json, "advertisingRouter", adv_router);
		json_object_string_add(json, "header", header_str);
		json_object_array_add(json_array, json);

		XFREE(MTYPE_OSPF6_LSA_HEADER, header_str);
	} else {
		vty_out(vty, "\n%s:\n", lsa->name);

		for (current = start; current < end; current++) {
			if ((current - start) % 16 == 0)
				vty_out(vty, "\n        ");
			else if ((current - start) % 4 == 0)
				vty_out(vty, " ");

			snprintf(byte, sizeof(byte), "%02x", *current);
			vty_out(vty, "%s", byte);
		}

		vty_out(vty, "\n\n");
	}

	return;
}

void ospf6_lsa_show_internal(struct vty *vty, struct ospf6_lsa *lsa,
			     json_object *json_array, bool use_json)
{
	char adv_router[64], id[64];
	json_object *json_obj;

	assert(lsa && lsa->header);

	inet_ntop(AF_INET, &lsa->header->id, id, sizeof(id));
	inet_ntop(AF_INET, &lsa->header->adv_router, adv_router,
		  sizeof(adv_router));

	if (use_json) {
		json_obj = json_object_new_object();
		json_object_int_add(json_obj, "age",
				    ospf6_lsa_age_current(lsa));
		json_object_string_add(json_obj, "type",
				       ospf6_lstype_name(lsa->header->type));
		json_object_string_add(json_obj, "linkStateId", id);
		json_object_string_add(json_obj, "advertisingRouter",
				       adv_router);
		json_object_int_add(json_obj, "lsSequenceNumber",
				    (unsigned long)ntohl(lsa->header->seqnum));
		json_object_int_add(json_obj, "checksum",
				    ntohs(lsa->header->checksum));
		json_object_int_add(json_obj, "length",
				    ntohs(lsa->header->length));
		json_object_int_add(json_obj, "flag", lsa->flag);
		json_object_int_add(json_obj, "lock", lsa->lock);
		json_object_int_add(json_obj, "reTxCount", lsa->retrans_count);

		/* Threads Data not added */
		json_object_array_add(json_array, json_obj);
	} else {
		vty_out(vty, "\n");
		vty_out(vty, "Age: %4hu Type: %s\n", ospf6_lsa_age_current(lsa),
			ospf6_lstype_name(lsa->header->type));
		vty_out(vty, "Link State ID: %s\n", id);
		vty_out(vty, "Advertising Router: %s\n", adv_router);
		vty_out(vty, "LS Sequence Number: %#010lx\n",
			(unsigned long)ntohl(lsa->header->seqnum));
		vty_out(vty, "CheckSum: %#06hx Length: %hu\n",
			ntohs(lsa->header->checksum),
			ntohs(lsa->header->length));
		vty_out(vty, "Flag: %x \n", lsa->flag);
		vty_out(vty, "Lock: %d \n", lsa->lock);
		vty_out(vty, "ReTx Count: %d\n", lsa->retrans_count);
		vty_out(vty, "Threads: Expire: %p, Refresh: %p\n", lsa->expire,
			lsa->refresh);
		vty_out(vty, "\n");
	}
	return;
}

void ospf6_lsa_show(struct vty *vty, struct ospf6_lsa *lsa,
		    json_object *json_array, bool use_json)
{
	char adv_router[64], id[64];
	const struct ospf6_lsa_handler *handler;
	struct timeval now, res;
	char duration[64];
	json_object *json_obj = NULL;

	assert(lsa && lsa->header);

	inet_ntop(AF_INET, &lsa->header->id, id, sizeof(id));
	inet_ntop(AF_INET, &lsa->header->adv_router, adv_router,
		  sizeof(adv_router));

	monotime(&now);
	timersub(&now, &lsa->installed, &res);
	timerstring(&res, duration, sizeof(duration));
	if (use_json) {
		json_obj = json_object_new_object();
		json_object_int_add(json_obj, "age",
				    ospf6_lsa_age_current(lsa));
		json_object_string_add(json_obj, "type",
				       ospf6_lstype_name(lsa->header->type));
		json_object_string_add(json_obj, "linkStateId", id);
		json_object_string_add(json_obj, "advertisingRouter",
				       adv_router);
		json_object_int_add(json_obj, "lsSequenceNumber",
				    (unsigned long)ntohl(lsa->header->seqnum));
		json_object_int_add(json_obj, "checksum",
				    ntohs(lsa->header->checksum));
		json_object_int_add(json_obj, "length",
				    ntohs(lsa->header->length));
		json_object_string_add(json_obj, "duration", duration);
	} else {
		vty_out(vty, "Age: %4hu Type: %s\n", ospf6_lsa_age_current(lsa),
			ospf6_lstype_name(lsa->header->type));
		vty_out(vty, "Link State ID: %s\n", id);
		vty_out(vty, "Advertising Router: %s\n", adv_router);
		vty_out(vty, "LS Sequence Number: %#010lx\n",
			(unsigned long)ntohl(lsa->header->seqnum));
		vty_out(vty, "CheckSum: %#06hx Length: %hu\n",
			ntohs(lsa->header->checksum),
			ntohs(lsa->header->length));
		vty_out(vty, "Duration: %s\n", duration);
	}

	handler = ospf6_get_lsa_handler(lsa->header->type);

	if (handler->lh_show != NULL)
		handler->lh_show(vty, lsa, json_obj, use_json);
	else {
		assert(unknown_handler.lh_show != NULL);
		unknown_handler.lh_show(vty, lsa, json_obj, use_json);
	}

	if (use_json)
		json_object_array_add(json_array, json_obj);
	else
		vty_out(vty, "\n");
}

struct ospf6_lsa *ospf6_lsa_alloc(size_t lsa_length)
{
	struct ospf6_lsa *lsa;

	lsa = XCALLOC(MTYPE_OSPF6_LSA, sizeof(struct ospf6_lsa));
	lsa->header = XMALLOC(MTYPE_OSPF6_LSA_HEADER, lsa_length);

	return lsa;
}

/* OSPFv3 LSA creation/deletion function */
struct ospf6_lsa *ospf6_lsa_create(struct ospf6_lsa_header *header)
{
	struct ospf6_lsa *lsa = NULL;
	uint16_t lsa_size = 0;

	/* size of the entire LSA */
	lsa_size = ntohs(header->length); /* XXX vulnerable */

	lsa = ospf6_lsa_alloc(lsa_size);

	/* copy LSA from original header */
	memcpy(lsa->header, header, lsa_size);

	/* dump string */
	ospf6_lsa_printbuf(lsa, lsa->name, sizeof(lsa->name));

	/* calculate birth of this lsa */
	ospf6_lsa_age_set(lsa);

	return lsa;
}

struct ospf6_lsa *ospf6_lsa_create_headeronly(struct ospf6_lsa_header *header)
{
	struct ospf6_lsa *lsa = NULL;

	lsa = ospf6_lsa_alloc(sizeof(struct ospf6_lsa_header));

	memcpy(lsa->header, header, sizeof(struct ospf6_lsa_header));

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
	EVENT_OFF(lsa->expire);
	EVENT_OFF(lsa->refresh);

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
struct ospf6_lsa *ospf6_lsa_lock(struct ospf6_lsa *lsa)
{
	lsa->lock++;
	return lsa;
}

/* decrement reference counter of struct ospf6_lsa */
void ospf6_lsa_unlock(struct ospf6_lsa **lsa)
{
	/* decrement reference counter */
	assert((*lsa)->lock > 0);
	(*lsa)->lock--;

	if ((*lsa)->lock != 0)
		return;

	ospf6_lsa_delete(*lsa);
	*lsa = NULL;
}


/* ospf6 lsa expiry */
void ospf6_lsa_expire(struct event *thread)
{
	struct ospf6_lsa *lsa;
	struct ospf6 *ospf6;

	lsa = (struct ospf6_lsa *)EVENT_ARG(thread);

	assert(lsa && lsa->header);
	assert(OSPF6_LSA_IS_MAXAGE(lsa));
	assert(!lsa->refresh);

	lsa->expire = (struct event *)NULL;

	if (IS_OSPF6_DEBUG_LSA_TYPE(lsa->header->type)) {
		zlog_debug("LSA Expire:");
		ospf6_lsa_header_print(lsa);
	}

	if (CHECK_FLAG(lsa->flag, OSPF6_LSA_HEADERONLY))
		return; /* dbexchange will do something ... */
	ospf6 = ospf6_get_by_lsdb(lsa);
	assert(ospf6);

	/* reinstall lsa */
	ospf6_install_lsa(lsa);

	/* reflood lsa */
	ospf6_flood(NULL, lsa);

	/* schedule maxage remover */
	ospf6_maxage_remove(ospf6);
}

void ospf6_lsa_refresh(struct event *thread)
{
	struct ospf6_lsa *old, *self, *new;
	struct ospf6_lsdb *lsdb_self;

	old = (struct ospf6_lsa *)EVENT_ARG(thread);
	assert(old && old->header);

	old->refresh = (struct event *)NULL;

	lsdb_self = ospf6_get_scoped_lsdb_self(old);
	self = ospf6_lsdb_lookup(old->header->type, old->header->id,
				 old->header->adv_router, lsdb_self);
	if (self == NULL) {
		if (IS_OSPF6_DEBUG_LSA_TYPE(old->header->type))
			zlog_debug("Refresh: could not find self LSA, flush %s",
				   old->name);
		ospf6_lsa_premature_aging(old);
		return;
	}

	/* Reset age, increment LS sequence number. */
	self->header->age = htons(0);
	self->header->seqnum =
		ospf6_new_ls_seqnum(self->header->type, self->header->id,
				    self->header->adv_router, old->lsdb);
	ospf6_lsa_checksum(self->header);

	new = ospf6_lsa_create(self->header);
	new->lsdb = old->lsdb;
	event_add_timer(master, ospf6_lsa_refresh, new, OSPF_LS_REFRESH_TIME,
			&new->refresh);

	/* store it in the LSDB for self-originated LSAs */
	ospf6_lsdb_add(ospf6_lsa_copy(new), lsdb_self);

	if (IS_OSPF6_DEBUG_LSA_TYPE(new->header->type)) {
		zlog_debug("LSA Refresh:");
		ospf6_lsa_header_print(new);
	}

	ospf6_install_lsa(new);
	ospf6_flood(NULL, new);
}

void ospf6_flush_self_originated_lsas_now(struct ospf6 *ospf6)
{
	struct listnode *node, *nnode;
	struct ospf6_area *oa;
	struct ospf6_lsa *lsa;
	const struct route_node *end = NULL;
	uint32_t type, adv_router;
	struct ospf6_interface *oi;

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

		for (ALL_LIST_ELEMENTS(oa->if_list, node, nnode, oi)) {
			end = ospf6_lsdb_head(oi->lsdb_self, 0, 0,
					      ospf6->router_id, &lsa);
			while (lsa) {
				/* RFC 2328 (14.1):  Set MAXAGE */
				lsa->header->age = htons(OSPF_LSA_MAXAGE);
				/* Flood MAXAGE LSA*/
				ospf6_flood(NULL, lsa);

				lsa = ospf6_lsdb_next(end, lsa);
			}
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
	ospf6_install_lsa_handler(&unknown_handler);
}

void ospf6_lsa_terminate(void)
{
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

void ospf6_lsa_debug_set_all(bool val)
{
	unsigned int i;
	struct ospf6_lsa_handler *handler = NULL;

	for (i = 0; i < array_size(lsa_handlers); i++) {
		handler = lsa_handlers[i];
		if (handler == NULL)
			continue;
		if (val)
			SET_FLAG(handler->lh_debug, OSPF6_LSA_DEBUG_ALL);
		else
			UNSET_FLAG(handler->lh_debug, OSPF6_LSA_DEBUG_ALL);
	}
}

DEFPY (debug_ospf6_lsa_all,
       debug_ospf6_lsa_all_cmd,
       "[no$no] debug ospf6 lsa all",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug Link State Advertisements (LSAs)\n"
       "Display for all types of LSAs\n")
{
	ospf6_lsa_debug_set_all(!no);
	return CMD_SUCCESS;
}

DEFPY (debug_ospf6_lsa_aggregation,
       debug_ospf6_lsa_aggregation_cmd,
       "[no] debug ospf6 lsa aggregation",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug Link State Advertisements (LSAs)\n"
       "External LSA Aggregation\n")
{

	struct ospf6_lsa_handler *handler;

	handler = ospf6_get_lsa_handler(OSPF6_LSTYPE_AS_EXTERNAL);
	if (handler == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	if (no)
		UNSET_FLAG(handler->lh_debug, OSPF6_LSA_DEBUG_AGGR);
	else
		SET_FLAG(handler->lh_debug, OSPF6_LSA_DEBUG_AGGR);

	return CMD_SUCCESS;
}

DEFUN (debug_ospf6_lsa_type,
       debug_ospf6_lsa_hex_cmd,
       "debug ospf6 lsa <router|network|inter-prefix|inter-router|as-external|nssa|link|intra-prefix|unknown> [<originate|examine|flooding>]",
       DEBUG_STR
       OSPF6_STR
       "Debug Link State Advertisements (LSAs)\n"
       "Display Router LSAs\n"
       "Display Network LSAs\n"
       "Display Inter-Area-Prefix LSAs\n"
       "Display Inter-Router LSAs\n"
       "Display As-External LSAs\n"
       "Display NSSA LSAs\n"
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

	for (i = 0; i < array_size(lsa_handlers); i++) {
		handler = lsa_handlers[i];
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
			SET_FLAG(handler->lh_debug, OSPF6_LSA_DEBUG_ORIGINATE);
		else if (strmatch(argv[idx_type]->text, "examine"))
			SET_FLAG(handler->lh_debug, OSPF6_LSA_DEBUG_EXAMIN);
		else if (strmatch(argv[idx_type]->text, "flooding"))
			SET_FLAG(handler->lh_debug, OSPF6_LSA_DEBUG_FLOOD);
	} else
		SET_FLAG(handler->lh_debug, OSPF6_LSA_DEBUG);

	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_lsa_type,
       no_debug_ospf6_lsa_hex_cmd,
       "no debug ospf6 lsa <router|network|inter-prefix|inter-router|as-external|nssa|link|intra-prefix|unknown> [<originate|examine|flooding>]",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug Link State Advertisements (LSAs)\n"
       "Display Router LSAs\n"
       "Display Network LSAs\n"
       "Display Inter-Area-Prefix LSAs\n"
       "Display Inter-Router LSAs\n"
       "Display As-External LSAs\n"
       "Display NSSA LSAs\n"
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

	for (i = 0; i < array_size(lsa_handlers); i++) {
		handler = lsa_handlers[i];
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
			UNSET_FLAG(handler->lh_debug,
				   OSPF6_LSA_DEBUG_ORIGINATE);
		if (strmatch(argv[idx_type]->text, "examine"))
			UNSET_FLAG(handler->lh_debug, OSPF6_LSA_DEBUG_EXAMIN);
		if (strmatch(argv[idx_type]->text, "flooding"))
			UNSET_FLAG(handler->lh_debug, OSPF6_LSA_DEBUG_FLOOD);
	} else
		UNSET_FLAG(handler->lh_debug, OSPF6_LSA_DEBUG);

	return CMD_SUCCESS;
}

void install_element_ospf6_debug_lsa(void)
{
	install_element(ENABLE_NODE, &debug_ospf6_lsa_all_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_lsa_all_cmd);
	install_element(ENABLE_NODE, &debug_ospf6_lsa_hex_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf6_lsa_hex_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_lsa_hex_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf6_lsa_hex_cmd);

	install_element(ENABLE_NODE, &debug_ospf6_lsa_aggregation_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_lsa_aggregation_cmd);
}

int config_write_ospf6_debug_lsa(struct vty *vty)
{
	unsigned int i;
	const struct ospf6_lsa_handler *handler;
	bool debug_all = true;

	for (i = 0; i < array_size(lsa_handlers); i++) {
		handler = lsa_handlers[i];
		if (handler == NULL)
			continue;
		if (CHECK_FLAG(handler->lh_debug, OSPF6_LSA_DEBUG_ALL)
		    < OSPF6_LSA_DEBUG_ALL) {
			debug_all = false;
			break;
		}
	}

	if (debug_all) {
		vty_out(vty, "debug ospf6 lsa all\n");
		return 0;
	}

	for (i = 0; i < array_size(lsa_handlers); i++) {
		handler = lsa_handlers[i];
		if (handler == NULL)
			continue;
		if (CHECK_FLAG(handler->lh_debug, OSPF6_LSA_DEBUG))
			vty_out(vty, "debug ospf6 lsa %s\n",
				ospf6_lsa_handler_name(handler));
		if (CHECK_FLAG(handler->lh_debug, OSPF6_LSA_DEBUG_ORIGINATE))
			vty_out(vty, "debug ospf6 lsa %s originate\n",
				ospf6_lsa_handler_name(handler));
		if (CHECK_FLAG(handler->lh_debug, OSPF6_LSA_DEBUG_EXAMIN))
			vty_out(vty, "debug ospf6 lsa %s examine\n",
				ospf6_lsa_handler_name(handler));
		if (CHECK_FLAG(handler->lh_debug, OSPF6_LSA_DEBUG_FLOOD))
			vty_out(vty, "debug ospf6 lsa %s flooding\n",
				ospf6_lsa_handler_name(handler));
		if (CHECK_FLAG(handler->lh_debug, OSPF6_LSA_DEBUG_AGGR))
			vty_out(vty, "debug ospf6 lsa aggregation\n");
	}

	return 0;
}
