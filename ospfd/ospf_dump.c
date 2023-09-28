// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFd dump routine.
 * Copyright (C) 1999, 2000 Toshiaki Takada
 */

#include <zebra.h>

#include "lib/bfd.h"
#include "monotime.h"
#include "linklist.h"
#include "frrevent.h"
#include "prefix.h"
#include "command.h"
#include "stream.h"
#include "log.h"
#include "sockopt.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_dump_clippy.c"

/* Configuration debug option variables. */
unsigned long conf_debug_ospf_packet[5] = {0, 0, 0, 0, 0};
unsigned long conf_debug_ospf_event = 0;
unsigned long conf_debug_ospf_ism = 0;
unsigned long conf_debug_ospf_nsm = 0;
unsigned long conf_debug_ospf_lsa = 0;
unsigned long conf_debug_ospf_zebra = 0;
unsigned long conf_debug_ospf_nssa = 0;
unsigned long conf_debug_ospf_te;
unsigned long conf_debug_ospf_ext = 0;
unsigned long conf_debug_ospf_sr;
unsigned long conf_debug_ospf_ti_lfa;
unsigned long conf_debug_ospf_defaultinfo;
unsigned long conf_debug_ospf_ldp_sync;
unsigned long conf_debug_ospf_gr;
unsigned long conf_debug_ospf_bfd;
unsigned long conf_debug_ospf_client_api;

/* Enable debug option variables -- valid only session. */
unsigned long term_debug_ospf_packet[5] = {0, 0, 0, 0, 0};
unsigned long term_debug_ospf_event;
unsigned long term_debug_ospf_ism = 0;
unsigned long term_debug_ospf_nsm = 0;
unsigned long term_debug_ospf_lsa = 0;
unsigned long term_debug_ospf_zebra = 0;
unsigned long term_debug_ospf_nssa = 0;
unsigned long term_debug_ospf_te;
unsigned long term_debug_ospf_ext = 0;
unsigned long term_debug_ospf_sr;
unsigned long term_debug_ospf_ti_lfa;
unsigned long term_debug_ospf_defaultinfo;
unsigned long term_debug_ospf_ldp_sync;
unsigned long term_debug_ospf_gr;
unsigned long term_debug_ospf_bfd;
unsigned long term_debug_ospf_client_api;

const char *ospf_redist_string(unsigned int route_type)
{
	return (route_type == ZEBRA_ROUTE_MAX) ? "Default"
					       : zebra_route_string(route_type);
}

#define OSPF_AREA_STRING_MAXLEN  16
const char *ospf_area_name_string(struct ospf_area *area)
{
	static char buf[OSPF_AREA_STRING_MAXLEN] = "";
	uint32_t area_id;

	if (!area)
		return "-";

	area_id = ntohl(area->area_id.s_addr);
	snprintf(buf, sizeof(buf), "%d.%d.%d.%d", (area_id >> 24) & 0xff,
		 (area_id >> 16) & 0xff, (area_id >> 8) & 0xff, area_id & 0xff);
	return buf;
}

#define OSPF_AREA_DESC_STRING_MAXLEN  23
const char *ospf_area_desc_string(struct ospf_area *area)
{
	static char buf[OSPF_AREA_DESC_STRING_MAXLEN] = "";
	uint8_t type;

	if (!area)
		return "(incomplete)";

	type = area->external_routing;
	switch (type) {
	case OSPF_AREA_NSSA:
		snprintf(buf, sizeof(buf), "%s [NSSA]",
			 ospf_area_name_string(area));
		break;
	case OSPF_AREA_STUB:
		snprintf(buf, sizeof(buf), "%s [Stub]",
			 ospf_area_name_string(area));
		break;
	default:
		return ospf_area_name_string(area);
	}

	return buf;
}

#define OSPF_IF_STRING_MAXLEN 40

/* Display both nbr and ism state of the ospf neighbor.*/
const char *ospf_if_name_string(struct ospf_interface *oi)
{
	static char buf[OSPF_IF_STRING_MAXLEN] = "";
	uint32_t ifaddr;

	if (!oi || !oi->address)
		return "inactive";

	if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
		return oi->ifp->name;

	ifaddr = ntohl(oi->address->u.prefix4.s_addr);
	snprintf(buf, sizeof(buf), "%s:%d.%d.%d.%d", oi->ifp->name,
		 (ifaddr >> 24) & 0xff, (ifaddr >> 16) & 0xff,
		 (ifaddr >> 8) & 0xff, ifaddr & 0xff);
	return buf;
}

int ospf_nbr_ism_state(struct ospf_neighbor *nbr)
{
	int state;
	struct ospf_interface *oi = nbr->oi;

	if (IPV4_ADDR_SAME(&DR(oi), &nbr->address.u.prefix4))
		state = ISM_DR;
	else if (IPV4_ADDR_SAME(&BDR(oi), &nbr->address.u.prefix4))
		state = ISM_Backup;
	else
		state = ISM_DROther;

	return state;
}

void ospf_nbr_ism_state_message(struct ospf_neighbor *nbr, char *buf,
				size_t size)
{
	int state;
	struct ospf_interface *oi = nbr->oi;

	if (!oi)
		return;

	/* network type is point-to-point */
	if (oi->type == OSPF_IFTYPE_POINTOPOINT) {
		snprintf(buf, size, "%s/-",
			 lookup_msg(ospf_nsm_state_msg, nbr->state, NULL));
		return;
	}

	state = ospf_nbr_ism_state(nbr);

	snprintf(buf, size, "%s/%s",
		 lookup_msg(ospf_nsm_state_msg, nbr->state, NULL),
		 lookup_msg(ospf_ism_state_msg, state, NULL));
}

const char *ospf_timeval_dump(struct timeval *t, char *buf, size_t size)
{
/* Making formatted timer strings. */
#define MINUTE_IN_SECONDS	60
#define HOUR_IN_SECONDS		(60*MINUTE_IN_SECONDS)

	unsigned long w, d, h, m, ms, us;

	if (!t)
		return "inactive";

	w = d = h = m = ms = 0;
	memset(buf, 0, size);

	us = t->tv_usec;
	if (us >= 1000) {
		ms = us / 1000;
		us %= 1000;
		(void)us; /* unused */
	}

	if (ms >= 1000) {
		t->tv_sec += ms / 1000;
		ms %= 1000;
	}

	if (t->tv_sec > ONE_WEEK_SECOND) {
		w = t->tv_sec / ONE_WEEK_SECOND;
		t->tv_sec -= w * ONE_WEEK_SECOND;
	}

	if (t->tv_sec > ONE_DAY_SECOND) {
		d = t->tv_sec / ONE_DAY_SECOND;
		t->tv_sec -= d * ONE_DAY_SECOND;
	}

	if (t->tv_sec >= HOUR_IN_SECONDS) {
		h = t->tv_sec / HOUR_IN_SECONDS;
		t->tv_sec -= h * HOUR_IN_SECONDS;
	}

	if (t->tv_sec >= MINUTE_IN_SECONDS) {
		m = t->tv_sec / MINUTE_IN_SECONDS;
		t->tv_sec -= m * MINUTE_IN_SECONDS;
	}

	if (w > 99)
		snprintf(buf, size, "%luw%1lud", w, d);
	else if (w)
		snprintf(buf, size, "%luw%1lud%02luh", w, d, h);
	else if (d)
		snprintf(buf, size, "%1lud%02luh%02lum", d, h, m);
	else if (h)
		snprintf(buf, size, "%luh%02lum%02lds", h, m, (long)t->tv_sec);
	else if (m)
		snprintf(buf, size, "%lum%02lds", m, (long)t->tv_sec);
	else if (t->tv_sec > 0 || ms > 0)
		snprintf(buf, size, "%ld.%03lus", (long)t->tv_sec, ms);
	else
		snprintf(buf, size, "%ld usecs", (long)t->tv_usec);

	return buf;
}

const char *ospf_timer_dump(struct event *t, char *buf, size_t size)
{
	struct timeval result;
	if (!t)
		return "inactive";

	monotime_until(&t->u.sands, &result);
	return ospf_timeval_dump(&result, buf, size);
}

static void ospf_packet_hello_dump(struct stream *s, uint16_t length)
{
	struct ospf_hello *hello;
	int i, len;

	hello = (struct ospf_hello *)stream_pnt(s);

	zlog_debug("Hello");
	zlog_debug("  NetworkMask %pI4", &hello->network_mask);
	zlog_debug("  HelloInterval %d", ntohs(hello->hello_interval));
	zlog_debug("  Options %d (%s)", hello->options,
		   ospf_options_dump(hello->options));
	zlog_debug("  RtrPriority %d", hello->priority);
	zlog_debug("  RtrDeadInterval %ld",
		   (unsigned long)ntohl(hello->dead_interval));
	zlog_debug("  DRouter %pI4", &hello->d_router);
	zlog_debug("  BDRouter %pI4", &hello->bd_router);

	len = length - OSPF_HEADER_SIZE - OSPF_HELLO_MIN_SIZE;
	zlog_debug("  # Neighbors %d", len / 4);
	for (i = 0; len > 0; i++, len -= sizeof(struct in_addr))
		zlog_debug("    Neighbor %pI4", &hello->neighbors[i]);
}

static char *ospf_dd_flags_dump(uint8_t flags, char *buf, size_t size)
{
	snprintf(buf, size, "%s|%s|%s", (flags & OSPF_DD_FLAG_I) ? "I" : "-",
		 (flags & OSPF_DD_FLAG_M) ? "M" : "-",
		 (flags & OSPF_DD_FLAG_MS) ? "MS" : "-");

	return buf;
}

static char *ospf_router_lsa_flags_dump(uint8_t flags, char *buf, size_t size)
{
	snprintf(buf, size, "%s|%s|%s",
		 (flags & ROUTER_LSA_VIRTUAL) ? "V" : "-",
		 (flags & ROUTER_LSA_EXTERNAL) ? "E" : "-",
		 (flags & ROUTER_LSA_BORDER) ? "B" : "-");

	return buf;
}

static void ospf_router_lsa_dump(struct stream *s, uint16_t length)
{
	char buf[BUFSIZ];
	struct router_lsa *rl;
	struct router_link *rlnk;
	int i, len, sum;

	rl = (struct router_lsa *)stream_pnt(s);

	zlog_debug("  Router-LSA");
	zlog_debug("    flags %s",
		   ospf_router_lsa_flags_dump(rl->flags, buf, BUFSIZ));
	zlog_debug("    # links %d", ntohs(rl->links));

	len = length - OSPF_LSA_HEADER_SIZE - 4;
	rlnk = &rl->link[0];
	sum = 0;
	for (i = 0; sum < len && rlnk; sum += 12, rlnk = &rl->link[++i]) {
		zlog_debug("    Link ID %pI4", &rlnk->link_id);
		zlog_debug("    Link Data %pI4", &rlnk->link_data);
		zlog_debug("    Type %d", (uint8_t)rlnk->type);
		zlog_debug("    TOS %d", (uint8_t)rlnk->tos);
		zlog_debug("    metric %d", ntohs(rlnk->metric));
	}
}

static void ospf_network_lsa_dump(struct stream *s, uint16_t length)
{
	struct network_lsa *nl;
	int i, cnt;

	zlog_debug("  Network-LSA");

	nl = (struct network_lsa *)stream_pnt(s);
	cnt = (length - (OSPF_LSA_HEADER_SIZE + 4)) / 4;

	/*
	zlog_debug ("LSA total size %d", ntohs (nl->header.length));
	zlog_debug ("Network-LSA size %d",
	ntohs (nl->header.length) - OSPF_LSA_HEADER_SIZE);
	*/
	zlog_debug("    Network Mask %pI4", &nl->mask);
	zlog_debug("    # Attached Routers %d", cnt);
	for (i = 0; i < cnt; i++)
		zlog_debug("      Attached Router %pI4",
			   &nl->routers[i]);
}

static void ospf_summary_lsa_dump(struct stream *s, uint16_t length)
{
	struct summary_lsa *sl;

	sl = (struct summary_lsa *)stream_pnt(s);

	zlog_debug("  Summary-LSA");
	zlog_debug("    Network Mask %pI4", &sl->mask);
	zlog_debug("    TOS=%d metric %d", sl->tos, GET_METRIC(sl->metric));
}

static void ospf_as_external_lsa_dump(struct stream *s, uint16_t length)
{
	struct as_external_lsa *al;
	struct as_route *asr;
	int size, sum;
	int i;

	al = (struct as_external_lsa *)stream_pnt(s);
	zlog_debug("  %s", ospf_lsa_type_msg[al->header.type].str);
	zlog_debug("    Network Mask %pI4", &al->mask);

	size = length - OSPF_LSA_HEADER_SIZE - 4;
	asr = &al->e[0];
	sum = 0;
	for (i = 0; sum < size && asr; sum += 12, asr = &al->e[++i]) {
		zlog_debug("    bit %s TOS=%d metric %d",
			   IS_EXTERNAL_METRIC(asr->tos) ? "E" : "-",
			   asr->tos & 0x7f, GET_METRIC(asr->metric));
		zlog_debug("    Forwarding address %pI4", &asr->fwd_addr);
		zlog_debug("    External Route Tag %" ROUTE_TAG_PRI,
			   ntohl(asr->route_tag));
	}
}

static void ospf_lsa_header_list_dump(struct stream *s, uint16_t length)
{
	struct lsa_header *lsa;
	int len;

	zlog_debug("  # LSA Headers %d", length / OSPF_LSA_HEADER_SIZE);

	/* LSA Headers. */
	len = length;
	while (len > 0) {
		lsa = (struct lsa_header *)stream_pnt(s);
		ospf_lsa_header_dump(lsa);

		stream_forward_getp(s, OSPF_LSA_HEADER_SIZE);
		len -= OSPF_LSA_HEADER_SIZE;
	}
}

static void ospf_packet_db_desc_dump(struct stream *s, uint16_t length)
{
	struct ospf_db_desc *dd;
	char dd_flags[8];

	uint32_t gp;

	gp = stream_get_getp(s);
	dd = (struct ospf_db_desc *)stream_pnt(s);

	zlog_debug("Database Description");
	zlog_debug("  Interface MTU %d", ntohs(dd->mtu));
	zlog_debug("  Options %d (%s)", dd->options,
		   ospf_options_dump(dd->options));
	zlog_debug("  Flags %d (%s)", dd->flags,
		   ospf_dd_flags_dump(dd->flags, dd_flags, sizeof(dd_flags)));
	zlog_debug("  Sequence Number 0x%08lx",
		   (unsigned long)ntohl(dd->dd_seqnum));

	length -= OSPF_HEADER_SIZE + OSPF_DB_DESC_MIN_SIZE;

	stream_forward_getp(s, OSPF_DB_DESC_MIN_SIZE);

	ospf_lsa_header_list_dump(s, length);

	stream_set_getp(s, gp);
}

static void ospf_packet_ls_req_dump(struct stream *s, uint16_t length)
{
	uint32_t sp;
	uint32_t ls_type;
	struct in_addr ls_id;
	struct in_addr adv_router;
	int sum;

	sp = stream_get_getp(s);

	length -= OSPF_HEADER_SIZE;

	zlog_debug("Link State Request");
	zlog_debug("  # Requests %d", length / 12);

	sum = 0;
	for (; sum < length; sum += 12) {
		ls_type = stream_getl(s);
		ls_id.s_addr = stream_get_ipv4(s);
		adv_router.s_addr = stream_get_ipv4(s);

		zlog_debug("  LS type %d", ls_type);
		zlog_debug("  Link State ID %pI4", &ls_id);
		zlog_debug("  Advertising Router %pI4", &adv_router);
	}

	stream_set_getp(s, sp);
}

static void ospf_packet_ls_upd_dump(struct stream *s, uint16_t length)
{
	uint32_t sp;
	struct lsa_header *lsa;
	int lsa_len, len;
	uint32_t count;

	len = length - OSPF_HEADER_SIZE;

	sp = stream_get_getp(s);

	count = stream_getl(s);
	len -= 4;

	zlog_debug("Link State Update");
	zlog_debug("  # LSAs %d", count);

	while (len > 0 && count > 0) {
		if ((uint16_t)len < OSPF_LSA_HEADER_SIZE || len % 4 != 0) {
			zlog_debug("  Remaining %d bytes; Incorrect length.",
				   len);
			break;
		}

		lsa = (struct lsa_header *)stream_pnt(s);
		lsa_len = ntohs(lsa->length);
		ospf_lsa_header_dump(lsa);

		/* Check that LSA length is valid */
		if (lsa_len > len || lsa_len % 4 != 0) {
			zlog_debug("  LSA length %d is incorrect!", lsa_len);
			break;
		}
		switch (lsa->type) {
		case OSPF_ROUTER_LSA:
			ospf_router_lsa_dump(s, lsa_len);
			break;
		case OSPF_NETWORK_LSA:
			ospf_network_lsa_dump(s, lsa_len);
			break;
		case OSPF_SUMMARY_LSA:
		case OSPF_ASBR_SUMMARY_LSA:
			ospf_summary_lsa_dump(s, lsa_len);
			break;
		case OSPF_AS_EXTERNAL_LSA:
			ospf_as_external_lsa_dump(s, lsa_len);
			break;
		case OSPF_AS_NSSA_LSA:
			ospf_as_external_lsa_dump(s, lsa_len);
			break;
		case OSPF_OPAQUE_LINK_LSA:
		case OSPF_OPAQUE_AREA_LSA:
		case OSPF_OPAQUE_AS_LSA:
			ospf_opaque_lsa_dump(s, lsa_len);
			break;
		default:
			break;
		}

		stream_forward_getp(s, lsa_len);
		len -= lsa_len;
		count--;
	}

	stream_set_getp(s, sp);
}

static void ospf_packet_ls_ack_dump(struct stream *s, uint16_t length)
{
	uint32_t sp;

	length -= OSPF_HEADER_SIZE;
	sp = stream_get_getp(s);

	zlog_debug("Link State Acknowledgment");
	ospf_lsa_header_list_dump(s, length);

	stream_set_getp(s, sp);
}

static void ospf_header_dump(struct ospf_header *ospfh)
{
	char buf[9];
	uint16_t auth_type = ntohs(ospfh->auth_type);

	zlog_debug("Header");
	zlog_debug("  Version %d", ospfh->version);
	zlog_debug("  Type %d (%s)", ospfh->type,
		   lookup_msg(ospf_packet_type_str, ospfh->type, NULL));
	zlog_debug("  Packet Len %d", ntohs(ospfh->length));
	zlog_debug("  Router ID %pI4", &ospfh->router_id);
	zlog_debug("  Area ID %pI4", &ospfh->area_id);
	zlog_debug("  Checksum 0x%x", ntohs(ospfh->checksum));
	zlog_debug("  AuType %s",
		   lookup_msg(ospf_auth_type_str, auth_type, NULL));

	switch (auth_type) {
	case OSPF_AUTH_NULL:
		break;
	case OSPF_AUTH_SIMPLE:
		strlcpy(buf, (char *)ospfh->u.auth_data, sizeof(buf));
		zlog_debug("  Simple Password %s", buf);
		break;
	case OSPF_AUTH_CRYPTOGRAPHIC:
		zlog_debug("  Cryptographic Authentication");
		zlog_debug("  Key ID %d", ospfh->u.crypt.key_id);
		zlog_debug("  Auth Data Len %d", ospfh->u.crypt.auth_data_len);
		zlog_debug("  Sequence number %ld",
			   (unsigned long)ntohl(ospfh->u.crypt.crypt_seqnum));
		break;
	default:
		zlog_debug("* This is not supported authentication type");
		break;
	}
}

void ospf_packet_dump(struct stream *s)
{
	struct ospf_header *ospfh;
	unsigned long gp;

	/* Preserve pointer. */
	gp = stream_get_getp(s);

	/* OSPF Header dump. */
	ospfh = (struct ospf_header *)stream_pnt(s);

	/* Until detail flag is set, return. */
	if (!(term_debug_ospf_packet[ospfh->type - 1] & OSPF_DEBUG_DETAIL))
		return;

	/* Show OSPF header detail. */
	ospf_header_dump(ospfh);
	stream_forward_getp(s, OSPF_HEADER_SIZE);

	switch (ospfh->type) {
	case OSPF_MSG_HELLO:
		ospf_packet_hello_dump(s, ntohs(ospfh->length));
		break;
	case OSPF_MSG_DB_DESC:
		ospf_packet_db_desc_dump(s, ntohs(ospfh->length));
		break;
	case OSPF_MSG_LS_REQ:
		ospf_packet_ls_req_dump(s, ntohs(ospfh->length));
		break;
	case OSPF_MSG_LS_UPD:
		ospf_packet_ls_upd_dump(s, ntohs(ospfh->length));
		break;
	case OSPF_MSG_LS_ACK:
		ospf_packet_ls_ack_dump(s, ntohs(ospfh->length));
		break;
	default:
		break;
	}

	stream_set_getp(s, gp);
}

DEFPY (debug_ospf_packet,
       debug_ospf_packet_cmd,
       "[no$no] debug ospf [(1-65535)$inst] packet <hello|dd|ls-request|ls-update|ls-ack|all>$packet [<send$send [detail$detail]|recv$recv [detail$detail]|detail$detail>]",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF packets\n"
       "OSPF Hello\n"
       "OSPF Database Description\n"
       "OSPF Link State Request\n"
       "OSPF Link State Update\n"
       "OSPF Link State Acknowledgment\n"
       "OSPF all packets\n"
       "Packet sent\n"
       "Detail Information\n"
       "Packet received\n"
       "Detail Information\n"
       "Detail Information\n")
{
	int type = 0;
	int flag = 0;
	int i;

	if (inst && inst != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	/* Check packet type. */
	if (strmatch(packet, "hello"))
		type = OSPF_DEBUG_HELLO;
	else if (strmatch(packet, "dd"))
		type = OSPF_DEBUG_DB_DESC;
	else if (strmatch(packet, "ls-request"))
		type = OSPF_DEBUG_LS_REQ;
	else if (strmatch(packet, "ls-update"))
		type = OSPF_DEBUG_LS_UPD;
	else if (strmatch(packet, "ls-ack"))
		type = OSPF_DEBUG_LS_ACK;
	else if (strmatch(packet, "all"))
		type = OSPF_DEBUG_ALL;

	/* Cases:
	 * (none)      = send + recv
	 * detail      = send + recv + detail
	 * recv        = recv
	 * send        = send
	 * recv detail = recv + detail
	 * send detail = send + detail
	 */
	if (!send && !recv) {
		flag |= OSPF_DEBUG_SEND;
		flag |= OSPF_DEBUG_RECV;
	}

	flag |= (send) ? OSPF_DEBUG_SEND : 0;
	flag |= (recv) ? OSPF_DEBUG_RECV : 0;
	flag |= (detail) ? OSPF_DEBUG_DETAIL : 0;

	for (i = 0; i < 5; i++)
		if (type & (0x01 << i)) {
			if (vty->node == CONFIG_NODE) {
				if (no)
					DEBUG_PACKET_OFF(i, flag);
				else
					DEBUG_PACKET_ON(i, flag);
			} else {
				if (no)
					TERM_DEBUG_PACKET_OFF(i, flag);
				else
					TERM_DEBUG_PACKET_ON(i, flag);
			}
		}

#ifdef DEBUG
/*
for (i = 0; i < 5; i++)
  zlog_debug ("flag[%d] = %d", i, ospf_debug_packet[i]);
*/
#endif /* DEBUG */

	return CMD_SUCCESS;
}

DEFUN (debug_ospf_ism,
       debug_ospf_ism_cmd,
       "debug ospf [(1-65535)] ism [<status|events|timers>]",
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF Interface State Machine\n"
       "ISM Status Information\n"
       "ISM Event Information\n"
       "ISM TImer Information\n")
{
	int inst = (argv[2]->type == RANGE_TKN);
	char *dbgparam = (argc == 4 + inst) ? argv[argc - 1]->text : NULL;

	if (inst) // user passed instance ID
	{
		if (inst != ospf_instance)
			return CMD_NOT_MY_INSTANCE;
	}

	if (vty->node == CONFIG_NODE) {
		if (!dbgparam)
			DEBUG_ON(ism, ISM);
		else {
			if (strmatch(dbgparam, "status"))
				DEBUG_ON(ism, ISM_STATUS);
			else if (strmatch(dbgparam, "events"))
				DEBUG_ON(ism, ISM_EVENTS);
			else if (strmatch(dbgparam, "timers"))
				DEBUG_ON(ism, ISM_TIMERS);
		}

		return CMD_SUCCESS;
	}

	/* ENABLE_NODE. */
	if (!dbgparam)
		TERM_DEBUG_ON(ism, ISM);
	else {
		if (strmatch(dbgparam, "status"))
			TERM_DEBUG_ON(ism, ISM_STATUS);
		else if (strmatch(dbgparam, "events"))
			TERM_DEBUG_ON(ism, ISM_EVENTS);
		else if (strmatch(dbgparam, "timers"))
			TERM_DEBUG_ON(ism, ISM_TIMERS);
	}

	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf_ism,
       no_debug_ospf_ism_cmd,
       "no debug ospf [(1-65535)] ism [<status|events|timers>]",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF Interface State Machine\n"
       "ISM Status Information\n"
       "ISM Event Information\n"
       "ISM TImer Information\n")
{
	int inst = (argv[3]->type == RANGE_TKN);
	char *dbgparam = (argc == 5 + inst) ? argv[argc - 1]->text : NULL;

	if (inst) // user passed instance ID
	{
		if (inst != ospf_instance)
			return CMD_NOT_MY_INSTANCE;
	}

	if (vty->node == CONFIG_NODE) {
		if (!dbgparam)
			DEBUG_OFF(ism, ISM);
		else {
			if (strmatch(dbgparam, "status"))
				DEBUG_OFF(ism, ISM_STATUS);
			else if (strmatch(dbgparam, "events"))
				DEBUG_OFF(ism, ISM_EVENTS);
			else if (strmatch(dbgparam, "timers"))
				DEBUG_OFF(ism, ISM_TIMERS);
		}

		return CMD_SUCCESS;
	}

	/* ENABLE_NODE. */
	if (!dbgparam)
		TERM_DEBUG_OFF(ism, ISM);
	else {
		if (strmatch(dbgparam, "status"))
			TERM_DEBUG_OFF(ism, ISM_STATUS);
		else if (strmatch(dbgparam, "events"))
			TERM_DEBUG_OFF(ism, ISM_EVENTS);
		else if (strmatch(dbgparam, "timers"))
			TERM_DEBUG_OFF(ism, ISM_TIMERS);
	}

	return CMD_SUCCESS;
}

static int debug_ospf_nsm_common(struct vty *vty, int arg_base, int argc,
				 struct cmd_token **argv)
{
	if (vty->node == CONFIG_NODE) {
		if (argc == arg_base + 0)
			DEBUG_ON(nsm, NSM);
		else if (argc == arg_base + 1) {
			if (strmatch(argv[arg_base]->text, "status"))
				DEBUG_ON(nsm, NSM_STATUS);
			else if (strmatch(argv[arg_base]->text, "events"))
				DEBUG_ON(nsm, NSM_EVENTS);
			else if (strmatch(argv[arg_base]->text, "timers"))
				DEBUG_ON(nsm, NSM_TIMERS);
		}

		return CMD_SUCCESS;
	}

	/* ENABLE_NODE. */
	if (argc == arg_base + 0)
		TERM_DEBUG_ON(nsm, NSM);
	else if (argc == arg_base + 1) {
		if (strmatch(argv[arg_base]->text, "status"))
			TERM_DEBUG_ON(nsm, NSM_STATUS);
		else if (strmatch(argv[arg_base]->text, "events"))
			TERM_DEBUG_ON(nsm, NSM_EVENTS);
		else if (strmatch(argv[arg_base]->text, "timers"))
			TERM_DEBUG_ON(nsm, NSM_TIMERS);
	}

	return CMD_SUCCESS;
}

DEFUN (debug_ospf_nsm,
       debug_ospf_nsm_cmd,
       "debug ospf nsm [<status|events|timers>]",
       DEBUG_STR
       OSPF_STR
       "OSPF Neighbor State Machine\n"
       "NSM Status Information\n"
       "NSM Event Information\n"
       "NSM Timer Information\n")
{
	return debug_ospf_nsm_common(vty, 3, argc, argv);
}

DEFUN (debug_ospf_instance_nsm,
       debug_ospf_instance_nsm_cmd,
       "debug ospf (1-65535) nsm [<status|events|timers>]",
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF Neighbor State Machine\n"
       "NSM Status Information\n"
       "NSM Event Information\n"
       "NSM Timer Information\n")
{
	int idx_number = 2;
	unsigned short instance = 0;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	return debug_ospf_nsm_common(vty, 4, argc, argv);
}


static int no_debug_ospf_nsm_common(struct vty *vty, int arg_base, int argc,
				    struct cmd_token **argv)
{
	/* XXX qlyoung */
	if (vty->node == CONFIG_NODE) {
		if (argc == arg_base + 0)
			DEBUG_OFF(nsm, NSM);
		else if (argc == arg_base + 1) {
			if (strmatch(argv[arg_base]->text, "status"))
				DEBUG_OFF(nsm, NSM_STATUS);
			else if (strmatch(argv[arg_base]->text, "events"))
				DEBUG_OFF(nsm, NSM_EVENTS);
			else if (strmatch(argv[arg_base]->text, "timers"))
				DEBUG_OFF(nsm, NSM_TIMERS);
		}

		return CMD_SUCCESS;
	}

	/* ENABLE_NODE. */
	if (argc == arg_base + 0)
		TERM_DEBUG_OFF(nsm, NSM);
	else if (argc == arg_base + 1) {
		if (strmatch(argv[arg_base]->text, "status"))
			TERM_DEBUG_OFF(nsm, NSM_STATUS);
		else if (strmatch(argv[arg_base]->text, "events"))
			TERM_DEBUG_OFF(nsm, NSM_EVENTS);
		else if (strmatch(argv[arg_base]->text, "timers"))
			TERM_DEBUG_OFF(nsm, NSM_TIMERS);
	}

	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf_nsm,
       no_debug_ospf_nsm_cmd,
       "no debug ospf nsm [<status|events|timers>]",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF Neighbor State Machine\n"
       "NSM Status Information\n"
       "NSM Event Information\n"
       "NSM Timer Information\n")
{
	return no_debug_ospf_nsm_common(vty, 4, argc, argv);
}


DEFUN (no_debug_ospf_instance_nsm,
       no_debug_ospf_instance_nsm_cmd,
       "no debug ospf (1-65535) nsm [<status|events|timers>]",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF Neighbor State Machine\n"
       "NSM Status Information\n"
       "NSM Event Information\n"
       "NSM Timer Information\n")
{
	int idx_number = 3;
	unsigned short instance = 0;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	return no_debug_ospf_nsm_common(vty, 5, argc, argv);
}


static int debug_ospf_lsa_common(struct vty *vty, int arg_base, int argc,
				 struct cmd_token **argv)
{
	if (vty->node == CONFIG_NODE) {
		if (argc == arg_base + 0)
			DEBUG_ON(lsa, LSA);
		else if (argc == arg_base + 1) {
			if (strmatch(argv[arg_base]->text, "generate"))
				DEBUG_ON(lsa, LSA_GENERATE);
			else if (strmatch(argv[arg_base]->text, "flooding"))
				DEBUG_ON(lsa, LSA_FLOODING);
			else if (strmatch(argv[arg_base]->text, "install"))
				DEBUG_ON(lsa, LSA_INSTALL);
			else if (strmatch(argv[arg_base]->text, "refresh"))
				DEBUG_ON(lsa, LSA_REFRESH);
			else if (strmatch(argv[arg_base]->text, "aggregate"))
				DEBUG_ON(lsa, EXTNL_LSA_AGGR);
		}

		return CMD_SUCCESS;
	}

	/* ENABLE_NODE. */
	if (argc == arg_base + 0)
		TERM_DEBUG_ON(lsa, LSA);
	else if (argc == arg_base + 1) {
		if (strmatch(argv[arg_base]->text, "generate"))
			TERM_DEBUG_ON(lsa, LSA_GENERATE);
		else if (strmatch(argv[arg_base]->text, "flooding"))
			TERM_DEBUG_ON(lsa, LSA_FLOODING);
		else if (strmatch(argv[arg_base]->text, "install"))
			TERM_DEBUG_ON(lsa, LSA_INSTALL);
		else if (strmatch(argv[arg_base]->text, "refresh"))
			TERM_DEBUG_ON(lsa, LSA_REFRESH);
		else if (strmatch(argv[arg_base]->text, "aggregate"))
			TERM_DEBUG_ON(lsa, EXTNL_LSA_AGGR);
	}

	return CMD_SUCCESS;
}

DEFUN (debug_ospf_lsa,
       debug_ospf_lsa_cmd,
       "debug ospf lsa [<generate|flooding|install|refresh|aggregate>]",
       DEBUG_STR
       OSPF_STR
       "OSPF Link State Advertisement\n"
       "LSA Generation\n"
       "LSA Flooding\n"
       "LSA Install/Delete\n"
       "LSA Refresh\n"
       "External LSA Aggregation\n")
{
	return debug_ospf_lsa_common(vty, 3, argc, argv);
}

DEFUN (debug_ospf_instance_lsa,
       debug_ospf_instance_lsa_cmd,
       "debug ospf (1-65535) lsa "
       "[<generate|flooding|install|refresh|aggregate>]",
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF Link State Advertisement\n"
       "LSA Generation\n"
       "LSA Flooding\n"
       "LSA Install/Delete\n"
       "LSA Refresh\n"
       "External LSA Aggregation\n")
{
	int idx_number = 2;
	unsigned short instance = 0;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	return debug_ospf_lsa_common(vty, 4, argc, argv);
}


static int no_debug_ospf_lsa_common(struct vty *vty, int arg_base, int argc,
				    struct cmd_token **argv)
{
	if (vty->node == CONFIG_NODE) {
		if (argc == arg_base + 0)
			DEBUG_OFF(lsa, LSA);
		else if (argc == arg_base + 1) {
			if (strmatch(argv[arg_base]->text, "generate"))
				DEBUG_OFF(lsa, LSA_GENERATE);
			else if (strmatch(argv[arg_base]->text, "flooding"))
				DEBUG_OFF(lsa, LSA_FLOODING);
			else if (strmatch(argv[arg_base]->text, "install"))
				DEBUG_OFF(lsa, LSA_INSTALL);
			else if (strmatch(argv[arg_base]->text, "refresh"))
				DEBUG_OFF(lsa, LSA_REFRESH);
			else if (strmatch(argv[arg_base]->text, "aggregate"))
				DEBUG_OFF(lsa, EXTNL_LSA_AGGR);
		}

		return CMD_SUCCESS;
	}

	/* ENABLE_NODE. */
	if (argc == arg_base + 0)
		TERM_DEBUG_OFF(lsa, LSA);
	else if (argc == arg_base + 1) {
		if (strmatch(argv[arg_base]->text, "generate"))
			TERM_DEBUG_OFF(lsa, LSA_GENERATE);
		else if (strmatch(argv[arg_base]->text, "flooding"))
			TERM_DEBUG_OFF(lsa, LSA_FLOODING);
		else if (strmatch(argv[arg_base]->text, "install"))
			TERM_DEBUG_OFF(lsa, LSA_INSTALL);
		else if (strmatch(argv[arg_base]->text, "refresh"))
			TERM_DEBUG_OFF(lsa, LSA_REFRESH);
		else if (strmatch(argv[arg_base]->text, "aggregate"))
			TERM_DEBUG_OFF(lsa, EXTNL_LSA_AGGR);
	}

	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf_lsa,
       no_debug_ospf_lsa_cmd,
       "no debug ospf lsa [<generate|flooding|install|refresh|aggregate>]",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF Link State Advertisement\n"
       "LSA Generation\n"
       "LSA Flooding\n"
       "LSA Install/Delete\n"
       "LSA Refres\n"
       "External LSA Aggregation\n")
{
	return no_debug_ospf_lsa_common(vty, 4, argc, argv);
}

DEFUN (no_debug_ospf_instance_lsa,
       no_debug_ospf_instance_lsa_cmd,
       "no debug ospf (1-65535) lsa "
       "[<generate|flooding|install|refresh|aggregate>]",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF Link State Advertisement\n"
       "LSA Generation\n"
       "LSA Flooding\n"
       "LSA Install/Delete\n"
       "LSA Refres\n"
       "External LSA Aggregation\n")
{
	int idx_number = 3;
	unsigned short instance = 0;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	return no_debug_ospf_lsa_common(vty, 5, argc, argv);
}


static int debug_ospf_zebra_common(struct vty *vty, int arg_base, int argc,
				   struct cmd_token **argv)
{
	if (vty->node == CONFIG_NODE) {
		if (argc == arg_base + 0)
			DEBUG_ON(zebra, ZEBRA);
		else if (argc == arg_base + 1) {
			if (strmatch(argv[arg_base]->text, "interface"))
				DEBUG_ON(zebra, ZEBRA_INTERFACE);
			else if (strmatch(argv[arg_base]->text, "redistribute"))
				DEBUG_ON(zebra, ZEBRA_REDISTRIBUTE);
		}

		return CMD_SUCCESS;
	}

	/* ENABLE_NODE. */
	if (argc == arg_base + 0)
		TERM_DEBUG_ON(zebra, ZEBRA);
	else if (argc == arg_base + 1) {
		if (strmatch(argv[arg_base]->text, "interface"))
			TERM_DEBUG_ON(zebra, ZEBRA_INTERFACE);
		else if (strmatch(argv[arg_base]->text, "redistribute"))
			TERM_DEBUG_ON(zebra, ZEBRA_REDISTRIBUTE);
	}

	return CMD_SUCCESS;
}

DEFUN (debug_ospf_zebra,
       debug_ospf_zebra_cmd,
       "debug ospf zebra [<interface|redistribute>]",
       DEBUG_STR
       OSPF_STR
       ZEBRA_STR
       "Zebra interface\n"
       "Zebra redistribute\n")
{
	return debug_ospf_zebra_common(vty, 3, argc, argv);
}

DEFUN (debug_ospf_instance_zebra,
       debug_ospf_instance_zebra_cmd,
       "debug ospf (1-65535) zebra [<interface|redistribute>]",
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       ZEBRA_STR
       "Zebra interface\n"
       "Zebra redistribute\n")
{
	int idx_number = 2;
	unsigned short instance = 0;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	return debug_ospf_zebra_common(vty, 4, argc, argv);
}


static int no_debug_ospf_zebra_common(struct vty *vty, int arg_base, int argc,
				      struct cmd_token **argv)
{
	if (vty->node == CONFIG_NODE) {
		if (argc == arg_base + 0)
			DEBUG_OFF(zebra, ZEBRA);
		else if (argc == arg_base + 1) {
			if (strmatch(argv[arg_base]->text, "interface"))
				DEBUG_OFF(zebra, ZEBRA_INTERFACE);
			else if (strmatch(argv[arg_base]->text, "redistribute"))
				DEBUG_OFF(zebra, ZEBRA_REDISTRIBUTE);
		}

		return CMD_SUCCESS;
	}

	/* ENABLE_NODE. */
	if (argc == arg_base + 0)
		TERM_DEBUG_OFF(zebra, ZEBRA);
	else if (argc == arg_base + 1) {
		if (strmatch(argv[arg_base]->text, "interface"))
			TERM_DEBUG_OFF(zebra, ZEBRA_INTERFACE);
		else if (strmatch(argv[arg_base]->text, "redistribute"))
			TERM_DEBUG_OFF(zebra, ZEBRA_REDISTRIBUTE);
	}

	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf_zebra,
       no_debug_ospf_zebra_cmd,
       "no debug ospf zebra [<interface|redistribute>]",
       NO_STR
       DEBUG_STR
       OSPF_STR
       ZEBRA_STR
       "Zebra interface\n"
       "Zebra redistribute\n")
{
	return no_debug_ospf_zebra_common(vty, 4, argc, argv);
}

DEFUN (no_debug_ospf_instance_zebra,
       no_debug_ospf_instance_zebra_cmd,
       "no debug ospf (1-65535) zebra [<interface|redistribute>]",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       ZEBRA_STR
       "Zebra interface\n"
       "Zebra redistribute\n")
{
	int idx_number = 3;
	unsigned short instance = 0;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	return no_debug_ospf_zebra_common(vty, 5, argc, argv);
}


DEFUN (debug_ospf_event,
       debug_ospf_event_cmd,
       "debug ospf event",
       DEBUG_STR
       OSPF_STR
       "OSPF event information\n")
{
	if (vty->node == CONFIG_NODE)
		CONF_DEBUG_ON(event, EVENT);
	TERM_DEBUG_ON(event, EVENT);
	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf_event,
       no_debug_ospf_event_cmd,
       "no debug ospf event",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF event information\n")
{
	if (vty->node == CONFIG_NODE)
		CONF_DEBUG_OFF(event, EVENT);
	TERM_DEBUG_OFF(event, EVENT);
	return CMD_SUCCESS;
}

DEFUN (debug_ospf_instance_event,
       debug_ospf_instance_event_cmd,
       "debug ospf (1-65535) event",
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF event information\n")
{
	int idx_number = 2;
	unsigned short instance = 0;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	if (vty->node == CONFIG_NODE)
		CONF_DEBUG_ON(event, EVENT);
	TERM_DEBUG_ON(event, EVENT);
	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf_instance_event,
       no_debug_ospf_instance_event_cmd,
       "no debug ospf (1-65535) event",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF event information\n")
{
	int idx_number = 3;
	unsigned short instance = 0;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	if (vty->node == CONFIG_NODE)
		CONF_DEBUG_OFF(event, EVENT);
	TERM_DEBUG_OFF(event, EVENT);
	return CMD_SUCCESS;
}

DEFUN (debug_ospf_nssa,
       debug_ospf_nssa_cmd,
       "debug ospf nssa",
       DEBUG_STR
       OSPF_STR
       "OSPF nssa information\n")
{
	if (vty->node == CONFIG_NODE)
		CONF_DEBUG_ON(nssa, NSSA);
	TERM_DEBUG_ON(nssa, NSSA);
	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf_nssa,
       no_debug_ospf_nssa_cmd,
       "no debug ospf nssa",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF nssa information\n")
{
	if (vty->node == CONFIG_NODE)
		CONF_DEBUG_OFF(nssa, NSSA);
	TERM_DEBUG_OFF(nssa, NSSA);
	return CMD_SUCCESS;
}

DEFUN (debug_ospf_instance_nssa,
       debug_ospf_instance_nssa_cmd,
       "debug ospf (1-65535) nssa",
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF nssa information\n")
{
	int idx_number = 2;
	unsigned short instance = 0;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	if (vty->node == CONFIG_NODE)
		CONF_DEBUG_ON(nssa, NSSA);
	TERM_DEBUG_ON(nssa, NSSA);
	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf_instance_nssa,
       no_debug_ospf_instance_nssa_cmd,
       "no debug ospf (1-65535) nssa",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF nssa information\n")
{
	int idx_number = 3;
	unsigned short instance = 0;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	if (vty->node == CONFIG_NODE)
		CONF_DEBUG_OFF(nssa, NSSA);
	TERM_DEBUG_OFF(nssa, NSSA);
	return CMD_SUCCESS;
}

DEFPY (debug_ospf_te,
       debug_ospf_te_cmd,
       "[no$no] debug ospf [(1-65535)$instance] te",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF-TE information\n")
{
	if (instance && instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	if (vty->node == CONFIG_NODE) {
		if (no)
			DEBUG_OFF(te, TE);
		else
			DEBUG_ON(te, TE);
	} else {
		if (no)
			TERM_DEBUG_OFF(te, TE);
		else
			TERM_DEBUG_ON(te, TE);
	}

	return CMD_SUCCESS;
}

DEFPY (debug_ospf_sr,
       debug_ospf_sr_cmd,
       "[no$no] debug ospf [(1-65535)$instance] sr",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF-SR information\n")
{
	if (instance && instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	if (vty->node == CONFIG_NODE) {
		if (no)
			DEBUG_OFF(sr, SR);
		else
			DEBUG_ON(sr, SR);
	} else {
		if (no)
			TERM_DEBUG_OFF(sr, SR);
		else
			TERM_DEBUG_ON(sr, SR);
	}

	return CMD_SUCCESS;
}

DEFPY (debug_ospf_ti_lfa,
       debug_ospf_ti_lfa_cmd,
       "[no$no] debug ospf [(1-65535)$instance] ti-lfa",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF-SR TI-LFA information\n")
{
	if (instance && instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	if (vty->node == CONFIG_NODE) {
		if (no)
			DEBUG_OFF(ti_lfa, TI_LFA);
		else
			DEBUG_ON(ti_lfa, TI_LFA);
	} else {
		if (no)
			TERM_DEBUG_OFF(ti_lfa, TI_LFA);
		else
			TERM_DEBUG_ON(ti_lfa, TI_LFA);
	}

	return CMD_SUCCESS;
}

DEFPY (debug_ospf_default_info,
       debug_ospf_default_info_cmd,
       "[no$no] debug ospf [(1-65535)$instance] default-information",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF default information\n")
{
	if (instance && instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	if (vty->node == CONFIG_NODE) {
		if (no)
			DEBUG_OFF(defaultinfo, DEFAULTINFO);
		else
			DEBUG_ON(defaultinfo, DEFAULTINFO);
	} else {
		if (no)
			TERM_DEBUG_OFF(defaultinfo, DEFAULTINFO);
		else
			TERM_DEBUG_ON(defaultinfo, DEFAULTINFO);
	}

	return CMD_SUCCESS;
}

DEFPY (debug_ospf_ldp_sync,
       debug_ospf_ldp_sync_cmd,
       "[no$no] debug ospf [(1-65535)$instance] ldp-sync",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF LDP-Sync information\n")
{
	if (instance && instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	if (vty->node == CONFIG_NODE) {
		if (no)
			DEBUG_OFF(ldp_sync, LDP_SYNC);
		else
			DEBUG_ON(ldp_sync, LDP_SYNC);
	} else {
		if (no)
			TERM_DEBUG_OFF(ldp_sync, LDP_SYNC);
		else
			TERM_DEBUG_ON(ldp_sync, LDP_SYNC);
	}

	return CMD_SUCCESS;
}

DEFPY (debug_ospf_gr,
       debug_ospf_gr_cmd,
       "[no$no] debug ospf [(1-65535)$instance] graceful-restart",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF Graceful Restart\n")
{
	if (instance && instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	if (vty->node == CONFIG_NODE) {
		if (no)
			CONF_DEBUG_OFF(gr, GR);
		else
			CONF_DEBUG_ON(gr, GR);
	}

	if (no)
		TERM_DEBUG_OFF(gr, GR);
	else
		TERM_DEBUG_ON(gr, GR);

	return CMD_SUCCESS;
}

DEFPY (debug_ospf_bfd,
       debug_ospf_bfd_cmd,
       "[no] debug ospf [(1-65535)$instance] bfd",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "Bidirection Forwarding Detection\n")
{
	if (instance && instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	if (vty->node == CONFIG_NODE) {
		if (no) {
			bfd_protocol_integration_set_debug(false);
			DEBUG_OFF(bfd, BFD_LIB);
		} else {
			bfd_protocol_integration_set_debug(true);
			DEBUG_ON(bfd, BFD_LIB);
		}
	} else {
		if (no)
			TERM_DEBUG_OFF(bfd, BFD_LIB);
		else
			TERM_DEBUG_ON(bfd, BFD_LIB);
	}

	return CMD_SUCCESS;
}

DEFPY (debug_ospf_client_api,
       debug_ospf_client_api_cmd,
       "[no$no] debug ospf [(1-65535)$instance] client-api",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF client API information\n")
{
	if (instance && instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	if (vty->node == CONFIG_NODE) {
		if (no)
			DEBUG_OFF(client_api, CLIENT_API);
		else
			DEBUG_ON(client_api, CLIENT_API);
	} else {
		if (no)
			TERM_DEBUG_OFF(client_api, CLIENT_API);
		else
			TERM_DEBUG_ON(client_api, CLIENT_API);
	}

	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf,
       no_debug_ospf_cmd,
       "no debug ospf",
       NO_STR
       DEBUG_STR
       OSPF_STR)
{
	int flag = OSPF_DEBUG_SEND | OSPF_DEBUG_RECV | OSPF_DEBUG_DETAIL;
	int i;

	if (vty->node == CONFIG_NODE) {
		CONF_DEBUG_OFF(event, EVENT);
		CONF_DEBUG_OFF(nssa, NSSA);
		DEBUG_OFF(ism, ISM_EVENTS);
		DEBUG_OFF(ism, ISM_STATUS);
		DEBUG_OFF(ism, ISM_TIMERS);
		DEBUG_OFF(lsa, LSA);
		DEBUG_OFF(lsa, LSA_FLOODING);
		DEBUG_OFF(lsa, LSA_GENERATE);
		DEBUG_OFF(lsa, LSA_INSTALL);
		DEBUG_OFF(lsa, LSA_REFRESH);
		DEBUG_OFF(nsm, NSM);
		DEBUG_OFF(nsm, NSM_EVENTS);
		DEBUG_OFF(nsm, NSM_STATUS);
		DEBUG_OFF(nsm, NSM_TIMERS);
		DEBUG_OFF(event, EVENT);
		DEBUG_OFF(zebra, ZEBRA);
		DEBUG_OFF(zebra, ZEBRA_INTERFACE);
		DEBUG_OFF(zebra, ZEBRA_REDISTRIBUTE);
		DEBUG_OFF(defaultinfo, DEFAULTINFO);
		DEBUG_OFF(ldp_sync, LDP_SYNC);
		DEBUG_OFF(te, TE);
		DEBUG_OFF(sr, SR);
		DEBUG_OFF(ti_lfa, TI_LFA);
		DEBUG_OFF(client_api, CLIENT_API);

		/* BFD debugging is two parts: OSPF and library. */
		DEBUG_OFF(bfd, BFD_LIB);
		bfd_protocol_integration_set_debug(false);

		for (i = 0; i < 5; i++)
			DEBUG_PACKET_OFF(i, flag);
	}

	for (i = 0; i < 5; i++)
		TERM_DEBUG_PACKET_OFF(i, flag);

	TERM_DEBUG_OFF(event, EVENT);
	TERM_DEBUG_OFF(ism, ISM);
	TERM_DEBUG_OFF(ism, ISM_EVENTS);
	TERM_DEBUG_OFF(ism, ISM_STATUS);
	TERM_DEBUG_OFF(ism, ISM_TIMERS);
	TERM_DEBUG_OFF(lsa, LSA);
	TERM_DEBUG_OFF(lsa, LSA_FLOODING);
	TERM_DEBUG_OFF(lsa, LSA_GENERATE);
	TERM_DEBUG_OFF(lsa, LSA_INSTALL);
	TERM_DEBUG_OFF(lsa, LSA_REFRESH);
	TERM_DEBUG_OFF(nsm, NSM);
	TERM_DEBUG_OFF(nsm, NSM_EVENTS);
	TERM_DEBUG_OFF(nsm, NSM_STATUS);
	TERM_DEBUG_OFF(nsm, NSM_TIMERS);
	TERM_DEBUG_OFF(nssa, NSSA);
	TERM_DEBUG_OFF(zebra, ZEBRA);
	TERM_DEBUG_OFF(zebra, ZEBRA_INTERFACE);
	TERM_DEBUG_OFF(zebra, ZEBRA_REDISTRIBUTE);
	TERM_DEBUG_OFF(defaultinfo, DEFAULTINFO);
	TERM_DEBUG_OFF(ldp_sync, LDP_SYNC);
	TERM_DEBUG_OFF(te, TE);
	TERM_DEBUG_OFF(sr, SR);
	TERM_DEBUG_OFF(ti_lfa, TI_LFA);
	TERM_DEBUG_OFF(bfd, BFD_LIB);
	TERM_DEBUG_OFF(client_api, CLIENT_API);

	return CMD_SUCCESS;
}

static int show_debugging_ospf_common(struct vty *vty)
{
	int i;

	if (ospf_instance)
		vty_out(vty, "\nOSPF Instance: %d\n\n", ospf_instance);

	vty_out(vty, "OSPF debugging status:\n");

	/* Show debug status for events. */
	if (IS_DEBUG_OSPF(event, EVENT))
		vty_out(vty, "  OSPF event debugging is on\n");

	/* Show debug status for ISM. */
	if (IS_DEBUG_OSPF(ism, ISM) == OSPF_DEBUG_ISM)
		vty_out(vty, "  OSPF ISM debugging is on\n");
	else {
		if (IS_DEBUG_OSPF(ism, ISM_STATUS))
			vty_out(vty, "  OSPF ISM status debugging is on\n");
		if (IS_DEBUG_OSPF(ism, ISM_EVENTS))
			vty_out(vty, "  OSPF ISM event debugging is on\n");
		if (IS_DEBUG_OSPF(ism, ISM_TIMERS))
			vty_out(vty, "  OSPF ISM timer debugging is on\n");
	}

	/* Show debug status for NSM. */
	if (IS_DEBUG_OSPF(nsm, NSM) == OSPF_DEBUG_NSM)
		vty_out(vty, "  OSPF NSM debugging is on\n");
	else {
		if (IS_DEBUG_OSPF(nsm, NSM_STATUS))
			vty_out(vty, "  OSPF NSM status debugging is on\n");
		if (IS_DEBUG_OSPF(nsm, NSM_EVENTS))
			vty_out(vty, "  OSPF NSM event debugging is on\n");
		if (IS_DEBUG_OSPF(nsm, NSM_TIMERS))
			vty_out(vty, "  OSPF NSM timer debugging is on\n");
	}

	/* Show debug status for OSPF Packets. */
	for (i = 0; i < 5; i++)
		if (IS_DEBUG_OSPF_PACKET(i, SEND)
		    && IS_DEBUG_OSPF_PACKET(i, RECV)) {
			vty_out(vty, "  OSPF packet %s%s debugging is on\n",
				lookup_msg(ospf_packet_type_str, i + 1, NULL),
				IS_DEBUG_OSPF_PACKET(i, DETAIL) ? " detail"
								: "");
		} else {
			if (IS_DEBUG_OSPF_PACKET(i, SEND))
				vty_out(vty,
					"  OSPF packet %s send%s debugging is on\n",
					lookup_msg(ospf_packet_type_str, i + 1,
						   NULL),
					IS_DEBUG_OSPF_PACKET(i, DETAIL)
						? " detail"
						: "");
			if (IS_DEBUG_OSPF_PACKET(i, RECV))
				vty_out(vty,
					"  OSPF packet %s receive%s debugging is on\n",
					lookup_msg(ospf_packet_type_str, i + 1,
						   NULL),
					IS_DEBUG_OSPF_PACKET(i, DETAIL)
						? " detail"
						: "");
		}

	/* Show debug status for OSPF LSAs. */
	if (IS_DEBUG_OSPF(lsa, LSA) == OSPF_DEBUG_LSA)
		vty_out(vty, "  OSPF LSA debugging is on\n");
	else {
		if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
			vty_out(vty, "  OSPF LSA generation debugging is on\n");
		if (IS_DEBUG_OSPF(lsa, LSA_FLOODING))
			vty_out(vty, "  OSPF LSA flooding debugging is on\n");
		if (IS_DEBUG_OSPF(lsa, LSA_INSTALL))
			vty_out(vty, "  OSPF LSA install debugging is on\n");
		if (IS_DEBUG_OSPF(lsa, LSA_REFRESH))
			vty_out(vty, "  OSPF LSA refresh debugging is on\n");
	}

	/* Show debug status for Zebra. */
	if (IS_DEBUG_OSPF(zebra, ZEBRA) == OSPF_DEBUG_ZEBRA)
		vty_out(vty, "  OSPF Zebra debugging is on\n");
	else {
		if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
			vty_out(vty,
				"  OSPF Zebra interface debugging is on\n");
		if (IS_DEBUG_OSPF(zebra, ZEBRA_REDISTRIBUTE))
			vty_out(vty,
				"  OSPF Zebra redistribute debugging is on\n");
	}

	if (IS_DEBUG_OSPF(defaultinfo, DEFAULTINFO) == OSPF_DEBUG_DEFAULTINFO)
		vty_out(vty, "  OSPF default information is on\n");

	/* Show debug status for NSSA. */
	if (IS_DEBUG_OSPF(nssa, NSSA) == OSPF_DEBUG_NSSA)
		vty_out(vty, "  OSPF NSSA debugging is on\n");

	/* Show debug status for LDP-SYNC. */
	if (IS_DEBUG_OSPF(ldp_sync, LDP_SYNC) == OSPF_DEBUG_LDP_SYNC)
		vty_out(vty, "  OSPF ldp-sync debugging is on\n");

	/* Show debug status for GR. */
	if (IS_DEBUG_OSPF(gr, GR) == OSPF_DEBUG_GR)
		vty_out(vty, "  OSPF Graceful Restart debugging is on\n");

	/* Show debug status for TE */
	if (IS_DEBUG_OSPF(te, TE) == OSPF_DEBUG_TE)
		vty_out(vty, "  OSPF TE debugging is on\n");

	/* Show debug status for SR */
	if (IS_DEBUG_OSPF(sr, SR) == OSPF_DEBUG_SR)
		vty_out(vty, "  OSPF SR debugging is on\n");

	/* Show debug status for TI-LFA */
	if (IS_DEBUG_OSPF(ti_lfa, TI_LFA) == OSPF_DEBUG_TI_LFA)
		vty_out(vty, "  OSPF TI-LFA debugging is on\n");

	if (IS_DEBUG_OSPF(bfd, BFD_LIB) == OSPF_DEBUG_BFD_LIB)
		vty_out(vty,
			"  OSPF BFD integration library debugging is on\n");

	/* Show debug status for LDP-SYNC. */
	if (IS_DEBUG_OSPF(client_api, CLIENT_API) == OSPF_DEBUG_CLIENT_API)
		vty_out(vty, "  OSPF client-api debugging is on\n");

	return CMD_SUCCESS;
}

DEFUN_NOSH (show_debugging_ospf,
	    show_debugging_ospf_cmd,
	    "show debugging [ospf]",
	    SHOW_STR
	    DEBUG_STR
	    OSPF_STR)
{
	show_debugging_ospf_common(vty);

	cmd_show_lib_debugs(vty);

	return CMD_SUCCESS;
}

DEFUN_NOSH (show_debugging_ospf_instance,
	    show_debugging_ospf_instance_cmd,
	    "show debugging ospf (1-65535)",
	    SHOW_STR
	    DEBUG_STR
	    OSPF_STR
	    "Instance ID\n")
{
	int idx_number = 3;
	unsigned short instance = 0;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	show_debugging_ospf_common(vty);

	cmd_show_lib_debugs(vty);

	return CMD_SUCCESS;
}

static int config_write_debug(struct vty *vty);
/* Debug node. */
static struct cmd_node debug_node = {
	.name = "debug",
	.node = DEBUG_NODE,
	.prompt = "",
	.config_write = config_write_debug,
};

static int config_write_debug(struct vty *vty)
{
	int write = 0;
	int i, r;

	const char *type_str[] = {"hello", "dd", "ls-request", "ls-update",
				  "ls-ack"};
	const char *detail_str[] = {
		"",	" send",	" recv",	"",
		" detail", " send detail", " recv detail", " detail"};

	char str[16];
	memset(str, 0, 16);

	if (ospf_instance)
		snprintf(str, sizeof(str), " %u", ospf_instance);

	/* debug ospf ism (status|events|timers). */
	if (IS_CONF_DEBUG_OSPF(ism, ISM) == OSPF_DEBUG_ISM)
		vty_out(vty, "debug ospf%s ism\n", str);
	else {
		if (IS_CONF_DEBUG_OSPF(ism, ISM_STATUS))
			vty_out(vty, "debug ospf%s ism status\n", str);
		if (IS_CONF_DEBUG_OSPF(ism, ISM_EVENTS))
			vty_out(vty, "debug ospf%s ism event\n", str);
		if (IS_CONF_DEBUG_OSPF(ism, ISM_TIMERS))
			vty_out(vty, "debug ospf%s ism timer\n", str);
	}

	/* debug ospf nsm (status|events|timers). */
	if (IS_CONF_DEBUG_OSPF(nsm, NSM) == OSPF_DEBUG_NSM)
		vty_out(vty, "debug ospf%s nsm\n", str);
	else {
		if (IS_CONF_DEBUG_OSPF(nsm, NSM_STATUS))
			vty_out(vty, "debug ospf%s nsm status\n", str);
		if (IS_CONF_DEBUG_OSPF(nsm, NSM_EVENTS))
			vty_out(vty, "debug ospf%s nsm event\n", str);
		if (IS_CONF_DEBUG_OSPF(nsm, NSM_TIMERS))
			vty_out(vty, "debug ospf%s nsm timer\n", str);
	}

	/* debug ospf lsa (generate|flooding|install|refresh). */
	if (IS_CONF_DEBUG_OSPF(lsa, LSA) == OSPF_DEBUG_LSA)
		vty_out(vty, "debug ospf%s lsa\n", str);
	else {
		if (IS_CONF_DEBUG_OSPF(lsa, LSA_GENERATE))
			vty_out(vty, "debug ospf%s lsa generate\n", str);
		if (IS_CONF_DEBUG_OSPF(lsa, LSA_FLOODING))
			vty_out(vty, "debug ospf%s lsa flooding\n", str);
		if (IS_CONF_DEBUG_OSPF(lsa, LSA_INSTALL))
			vty_out(vty, "debug ospf%s lsa install\n", str);
		if (IS_CONF_DEBUG_OSPF(lsa, LSA_REFRESH))
			vty_out(vty, "debug ospf%s lsa refresh\n", str);

		write = 1;
	}

	/* debug ospf zebra (interface|redistribute). */
	if (IS_CONF_DEBUG_OSPF(zebra, ZEBRA) == OSPF_DEBUG_ZEBRA)
		vty_out(vty, "debug ospf%s zebra\n", str);
	else {
		if (IS_CONF_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
			vty_out(vty, "debug ospf%s zebra interface\n", str);
		if (IS_CONF_DEBUG_OSPF(zebra, ZEBRA_REDISTRIBUTE))
			vty_out(vty, "debug ospf%s zebra redistribute\n", str);

		write = 1;
	}

	/* debug ospf event. */
	if (IS_CONF_DEBUG_OSPF(event, EVENT) == OSPF_DEBUG_EVENT) {
		vty_out(vty, "debug ospf%s event\n", str);
		write = 1;
	}

	/* debug ospf nssa. */
	if (IS_CONF_DEBUG_OSPF(nssa, NSSA) == OSPF_DEBUG_NSSA) {
		vty_out(vty, "debug ospf%s nssa\n", str);
		write = 1;
	}

	/* debug ospf packet all detail. */
	r = OSPF_DEBUG_SEND_RECV | OSPF_DEBUG_DETAIL;
	for (i = 0; i < 5; i++)
		r &= conf_debug_ospf_packet[i]
		     & (OSPF_DEBUG_SEND_RECV | OSPF_DEBUG_DETAIL);
	if (r == (OSPF_DEBUG_SEND_RECV | OSPF_DEBUG_DETAIL)) {
		vty_out(vty, "debug ospf%s packet all detail\n", str);
		write = 1;
	}

	/* debug ospf packet all. */
	r = OSPF_DEBUG_SEND_RECV;
	for (i = 0; i < 5; i++)
		r &= conf_debug_ospf_packet[i] & OSPF_DEBUG_SEND_RECV;
	if (r == OSPF_DEBUG_SEND_RECV) {
		vty_out(vty, "debug ospf%s packet all\n", str);
		for (i = 0; i < 5; i++)
			if (conf_debug_ospf_packet[i] & OSPF_DEBUG_DETAIL)
				vty_out(vty, "debug ospf%s packet %s detail\n",
					str, type_str[i]);
		write = 1;
	}

	/* debug ospf packet (hello|dd|ls-request|ls-update|ls-ack)
	   (send|recv) (detail). */
	for (i = 0; i < 5; i++) {
		if (conf_debug_ospf_packet[i] == 0)
			continue;

		vty_out(vty, "debug ospf%s packet %s%s\n", str, type_str[i],
			detail_str[conf_debug_ospf_packet[i]]);
		write = 1;
	}

	/* debug ospf te */
	if (IS_CONF_DEBUG_OSPF(te, TE) == OSPF_DEBUG_TE) {
		vty_out(vty, "debug ospf%s te\n", str);
		write = 1;
	}

	/* debug ospf sr */
	if (IS_CONF_DEBUG_OSPF(sr, SR) == OSPF_DEBUG_SR) {
		vty_out(vty, "debug ospf%s sr\n", str);
		write = 1;
	}

	/* debug ospf sr ti-lfa */
	if (IS_CONF_DEBUG_OSPF(ti_lfa, TI_LFA) == OSPF_DEBUG_TI_LFA) {
		vty_out(vty, "debug ospf%s ti-lfa\n", str);
		write = 1;
	}

	/* debug ospf ldp-sync */
	if (IS_CONF_DEBUG_OSPF(ldp_sync, LDP_SYNC) == OSPF_DEBUG_LDP_SYNC) {
		vty_out(vty, "debug ospf%s ldp-sync\n", str);
		write = 1;
	}

	/* debug ospf gr */
	if (IS_CONF_DEBUG_OSPF(gr, GR) == OSPF_DEBUG_GR) {
		vty_out(vty, "debug ospf%s graceful-restart\n", str);
		write = 1;
	}

	if (IS_CONF_DEBUG_OSPF(bfd, BFD_LIB) == OSPF_DEBUG_BFD_LIB) {
		vty_out(vty, "debug ospf%s bfd\n", str);
		write = 1;
	}

	/* debug ospf client-api */
	if (IS_CONF_DEBUG_OSPF(client_api, CLIENT_API) ==
	    OSPF_DEBUG_CLIENT_API) {
		vty_out(vty, "debug ospf%s client-api\n", str);
		write = 1;
	}

	/* debug ospf default-information */
	if (IS_CONF_DEBUG_OSPF(defaultinfo, DEFAULTINFO) ==
	    OSPF_DEBUG_DEFAULTINFO) {
		vty_out(vty, "debug ospf%s default-information\n", str);
		write = 1;
	}

	return write;
}

/* Initialize debug commands. */
void ospf_debug_init(void)
{
	install_node(&debug_node);

	install_element(ENABLE_NODE, &show_debugging_ospf_cmd);
	install_element(ENABLE_NODE, &debug_ospf_ism_cmd);
	install_element(ENABLE_NODE, &debug_ospf_nsm_cmd);
	install_element(ENABLE_NODE, &debug_ospf_lsa_cmd);
	install_element(ENABLE_NODE, &debug_ospf_zebra_cmd);
	install_element(ENABLE_NODE, &debug_ospf_event_cmd);
	install_element(ENABLE_NODE, &debug_ospf_nssa_cmd);
	install_element(ENABLE_NODE, &debug_ospf_te_cmd);
	install_element(ENABLE_NODE, &debug_ospf_sr_cmd);
	install_element(ENABLE_NODE, &debug_ospf_ti_lfa_cmd);
	install_element(ENABLE_NODE, &debug_ospf_default_info_cmd);
	install_element(ENABLE_NODE, &debug_ospf_ldp_sync_cmd);
	install_element(ENABLE_NODE, &debug_ospf_client_api_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf_ism_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf_nsm_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf_lsa_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf_zebra_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf_event_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf_nssa_cmd);
	install_element(ENABLE_NODE, &debug_ospf_gr_cmd);
	install_element(ENABLE_NODE, &debug_ospf_bfd_cmd);

	install_element(ENABLE_NODE, &show_debugging_ospf_instance_cmd);
	install_element(ENABLE_NODE, &debug_ospf_packet_cmd);

	install_element(ENABLE_NODE, &debug_ospf_instance_nsm_cmd);
	install_element(ENABLE_NODE, &debug_ospf_instance_lsa_cmd);
	install_element(ENABLE_NODE, &debug_ospf_instance_zebra_cmd);
	install_element(ENABLE_NODE, &debug_ospf_instance_event_cmd);
	install_element(ENABLE_NODE, &debug_ospf_instance_nssa_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf_instance_nsm_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf_instance_lsa_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf_instance_zebra_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf_instance_event_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf_instance_nssa_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf_cmd);

	install_element(CONFIG_NODE, &debug_ospf_packet_cmd);
	install_element(CONFIG_NODE, &debug_ospf_ism_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf_ism_cmd);

	install_element(CONFIG_NODE, &debug_ospf_nsm_cmd);
	install_element(CONFIG_NODE, &debug_ospf_lsa_cmd);
	install_element(CONFIG_NODE, &debug_ospf_zebra_cmd);
	install_element(CONFIG_NODE, &debug_ospf_event_cmd);
	install_element(CONFIG_NODE, &debug_ospf_nssa_cmd);
	install_element(CONFIG_NODE, &debug_ospf_te_cmd);
	install_element(CONFIG_NODE, &debug_ospf_sr_cmd);
	install_element(CONFIG_NODE, &debug_ospf_ti_lfa_cmd);
	install_element(CONFIG_NODE, &debug_ospf_default_info_cmd);
	install_element(CONFIG_NODE, &debug_ospf_ldp_sync_cmd);
	install_element(CONFIG_NODE, &debug_ospf_client_api_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf_nsm_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf_lsa_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf_zebra_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf_event_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf_nssa_cmd);
	install_element(CONFIG_NODE, &debug_ospf_gr_cmd);
	install_element(CONFIG_NODE, &debug_ospf_bfd_cmd);

	install_element(CONFIG_NODE, &debug_ospf_instance_nsm_cmd);
	install_element(CONFIG_NODE, &debug_ospf_instance_lsa_cmd);
	install_element(CONFIG_NODE, &debug_ospf_instance_zebra_cmd);
	install_element(CONFIG_NODE, &debug_ospf_instance_event_cmd);
	install_element(CONFIG_NODE, &debug_ospf_instance_nssa_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf_instance_nsm_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf_instance_lsa_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf_instance_zebra_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf_instance_event_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf_instance_nssa_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf_cmd);
}
