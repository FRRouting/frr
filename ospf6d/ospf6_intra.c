// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#include <zebra.h>

#include "log.h"
#include "linklist.h"
#include "frrevent.h"
#include "memory.h"
#include "if.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "command.h"
#include "vrf.h"

#include "ospf6_proto.h"
#include "ospf6_message.h"
#include "ospf6_route.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"
#include "ospf6_intra.h"
#include "ospf6_asbr.h"
#include "ospf6_abr.h"
#include "ospf6_flood.h"
#include "ospf6d.h"
#include "ospf6_spf.h"
#include "ospf6_tlv.h"
#include "ospf6_gr.h"

unsigned char conf_debug_ospf6_brouter = 0;
uint32_t conf_debug_ospf6_brouter_specific_router_id;
uint32_t conf_debug_ospf6_brouter_specific_area_id;

#define MAX_LSA_PAYLOAD   (1024 + 256)
/******************************/
/* RFC2740 3.4.3.1 Router-LSA */
/******************************/

/* OSPF6_LSTYPE_ROUTER */
static char *ospf6_router_lsa_get_nbr_id(struct ospf6_lsa *lsa, char *buf,
					 int buflen, int pos)
{
	char buf1[INET_ADDRSTRLEN], buf2[INET_ADDRSTRLEN];
	struct ospf6_router_lsdesc *lsdesc = nth_lsdesc(lsa->header, pos);

	if (!lsdesc || !buf || buflen < (2 + 2 * INET_ADDRSTRLEN))
		return NULL;

	inet_ntop(AF_INET, &lsdesc->neighbor_interface_id, buf1, sizeof(buf1));
	inet_ntop(AF_INET, &lsdesc->neighbor_router_id, buf2, sizeof(buf2));
	snprintf(buf, buflen, "%s/%s", buf2, buf1);
	return buf;
}

static int ospf6_router_lsa_show(struct vty *vty, struct ospf6_lsa *lsa,
				 json_object *json_obj, bool use_json)
{
	char *start, *end, *current;
	char buf[32], name[32], bits[16], options[32];
	struct ospf6_router_lsa *router_lsa;
	struct ospf6_router_lsdesc *lsdesc;
	json_object *json_arr = NULL;
	json_object *json_loop;

	router_lsa =
		(struct ospf6_router_lsa *)((char *)lsa->header
					    + sizeof(struct ospf6_lsa_header));

	ospf6_capability_printbuf(router_lsa->bits, bits, sizeof(bits));
	ospf6_options_printbuf(router_lsa->options, options, sizeof(options));
	if (use_json) {
		json_object_string_add(json_obj, "bits", bits);
		json_object_string_add(json_obj, "options", options);
		json_arr = json_object_new_array();
	} else
		vty_out(vty, "    Bits: %s Options: %s\n", bits, options);

	start = (char *)router_lsa + sizeof(struct ospf6_router_lsa);
	end = (char *)lsa->header + ntohs(lsa->header->length);
	for (current = start;
	     current + sizeof(struct ospf6_router_lsdesc) <= end;
	     current += sizeof(struct ospf6_router_lsdesc)) {
		lsdesc = (struct ospf6_router_lsdesc *)current;

		if (lsdesc->type == OSPF6_ROUTER_LSDESC_POINTTOPOINT)
			snprintf(name, sizeof(name), "Point-To-Point");
		else if (lsdesc->type == OSPF6_ROUTER_LSDESC_TRANSIT_NETWORK)
			snprintf(name, sizeof(name), "Transit-Network");
		else if (lsdesc->type == OSPF6_ROUTER_LSDESC_STUB_NETWORK)
			snprintf(name, sizeof(name), "Stub-Network");
		else if (lsdesc->type == OSPF6_ROUTER_LSDESC_VIRTUAL_LINK)
			snprintf(name, sizeof(name), "Virtual-Link");
		else
			snprintf(name, sizeof(name), "Unknown (%#x)",
				 lsdesc->type);

		if (use_json) {
			json_loop = json_object_new_object();
			json_object_string_add(json_loop, "type", name);
			json_object_int_add(json_loop, "metric",
					    ntohs(lsdesc->metric));
			json_object_string_addf(
				json_loop, "interfaceId", "%pI4",
				(in_addr_t *)&lsdesc->interface_id);
			json_object_string_addf(
				json_loop, "neighborInterfaceId", "%pI4",
				(in_addr_t *)&lsdesc->neighbor_interface_id);
			json_object_string_addf(json_loop, "neighborRouterId",
						"%pI4",
						&lsdesc->neighbor_router_id);
			json_object_array_add(json_arr, json_loop);
		} else {
			vty_out(vty, "    Type: %s Metric: %d\n", name,
				ntohs(lsdesc->metric));
			vty_out(vty, "    Interface ID: %s\n",
				inet_ntop(AF_INET, &lsdesc->interface_id, buf,
					  sizeof(buf)));
			vty_out(vty, "    Neighbor Interface ID: %s\n",
				inet_ntop(AF_INET,
					  &lsdesc->neighbor_interface_id, buf,
					  sizeof(buf)));
			vty_out(vty, "    Neighbor Router ID: %s\n",
				inet_ntop(AF_INET, &lsdesc->neighbor_router_id,
					  buf, sizeof(buf)));
		}
	}
	if (use_json)
		json_object_object_add(json_obj, "lsaDescription", json_arr);

	return 0;
}

static void ospf6_router_lsa_options_set(struct ospf6_area *oa,
					 struct ospf6_router_lsa *router_lsa)
{
	OSPF6_OPT_CLEAR_ALL(router_lsa->options);
	memcpy(router_lsa->options, oa->options, 3);

	if (ospf6_check_and_set_router_abr(oa->ospf6))
		SET_FLAG(router_lsa->bits, OSPF6_ROUTER_BIT_B);
	else
		UNSET_FLAG(router_lsa->bits, OSPF6_ROUTER_BIT_B);

	if (!IS_AREA_STUB(oa) && ospf6_asbr_is_asbr(oa->ospf6)) {
		SET_FLAG(router_lsa->bits, OSPF6_ROUTER_BIT_E);
	} else {
		UNSET_FLAG(router_lsa->bits, OSPF6_ROUTER_BIT_E);
	}

	/* If the router is ASBR and the area-type is NSSA set the
	 * translate bit in router LSA.
	 */
	if (IS_AREA_NSSA(oa)
	    && (ospf6_asbr_is_asbr(oa->ospf6) || IS_OSPF6_ABR(oa->ospf6))) {
		if (oa->NSSATranslatorRole == OSPF6_NSSA_ROLE_ALWAYS)
			SET_FLAG(router_lsa->bits, OSPF6_ROUTER_BIT_NT);
	} else {
		UNSET_FLAG(router_lsa->bits, OSPF6_ROUTER_BIT_NT);
	}

	UNSET_FLAG(router_lsa->bits, OSPF6_ROUTER_BIT_V);
	UNSET_FLAG(router_lsa->bits, OSPF6_ROUTER_BIT_W);
}

int ospf6_router_is_stub_router(struct ospf6_lsa *lsa)
{
	struct ospf6_router_lsa *rtr_lsa;

	if (lsa != NULL && OSPF6_LSA_IS_TYPE(ROUTER, lsa)) {
		rtr_lsa = lsa_after_header(lsa->header);

		if (!OSPF6_OPT_ISSET(rtr_lsa->options, OSPF6_OPT_R)) {
			return OSPF6_IS_STUB_ROUTER;
		} else if (!OSPF6_OPT_ISSET(rtr_lsa->options, OSPF6_OPT_V6)) {
			return OSPF6_IS_STUB_ROUTER_V6;
		}
	}

	return OSPF6_NOT_STUB_ROUTER;
}

void ospf6_router_lsa_originate(struct event *thread)
{
	struct ospf6_area *oa;

	char buffer[OSPF6_MAX_LSASIZE];
	struct ospf6_lsa_header *lsa_header;
	struct ospf6_lsa *lsa;

	uint32_t link_state_id = 0;
	struct listnode *node, *nnode;
	struct listnode *j;
	struct ospf6_interface *oi;
	struct ospf6_neighbor *on, *drouter = NULL;
	struct ospf6_router_lsa *router_lsa;
	struct ospf6_router_lsdesc *lsdesc;
	uint16_t type;
	uint32_t router;
	int count;

	oa = (struct ospf6_area *)EVENT_ARG(thread);

	if (oa->ospf6->gr_info.restart_in_progress) {
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug(
				"Graceful Restart in progress, don't originate LSA");
		return;
	}

	if (IS_OSPF6_DEBUG_ORIGINATE(ROUTER))
		zlog_debug("Originate Router-LSA for Area %s", oa->name);

	memset(buffer, 0, sizeof(buffer));
	lsa_header = (struct ospf6_lsa_header *)buffer;
	router_lsa = lsa_after_header(lsa_header);

	ospf6_router_lsa_options_set(oa, router_lsa);

	/* describe links for each interfaces */
	lsdesc = lsdesc_start_lsa_type(lsa_header, OSPF6_LSTYPE_ROUTER);

	for (ALL_LIST_ELEMENTS(oa->if_list, node, nnode, oi)) {
		/* Interfaces in state Down or Loopback are not described */
		if (oi->state == OSPF6_INTERFACE_DOWN
		    || oi->state == OSPF6_INTERFACE_LOOPBACK)
			continue;

		/* Nor are interfaces without any full adjacencies described */
		count = 0;
		for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, j, on))
			if (on->state == OSPF6_NEIGHBOR_FULL)
				count++;

		if (count == 0)
			continue;

		/* Multiple Router-LSA instance according to size limit setting
		 */
		if ((oa->router_lsa_size_limit != 0)
		    && ((size_t)((char *)lsdesc - buffer)
				+ sizeof(struct ospf6_router_lsdesc)
			> oa->router_lsa_size_limit)) {
			if (lsdesc ==
			    lsdesc_start_lsa_type(lsa_header,
						  OSPF6_LSTYPE_ROUTER)) {
				zlog_warn(
					"Size limit setting for Router-LSA too short");
				return;
			}

			/* Fill LSA Header */
			lsa_header->age = 0;
			lsa_header->type = htons(OSPF6_LSTYPE_ROUTER);
			lsa_header->id = htonl(link_state_id);
			lsa_header->adv_router = oa->ospf6->router_id;
			lsa_header->seqnum = ospf6_new_ls_seqnum(
				lsa_header->type, lsa_header->id,
				lsa_header->adv_router, oa->lsdb);
			lsa_header->length =
				htons((caddr_t)lsdesc - (caddr_t)buffer);

			/* LSA checksum */
			ospf6_lsa_checksum(lsa_header);

			/* create LSA */
			lsa = ospf6_lsa_create(lsa_header);

			/* Originate */
			ospf6_lsa_originate_area(lsa, oa);

			/* Reset Buffer to fill next Router LSA */
			memset(buffer, 0, sizeof(buffer));
			lsa_header = (struct ospf6_lsa_header *)buffer;
			router_lsa = lsa_after_header(lsa_header);

			ospf6_router_lsa_options_set(oa, router_lsa);

			/* describe links for each interfaces */
			lsdesc = lsdesc_start_lsa_type(lsa_header,
						       OSPF6_LSTYPE_ROUTER);

			link_state_id++;
		}

		/* Point-to-Point interfaces */
		if (oi->type == OSPF_IFTYPE_POINTOPOINT
		    || oi->type == OSPF_IFTYPE_POINTOMULTIPOINT) {
			for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, j, on)) {
				if (on->state != OSPF6_NEIGHBOR_FULL)
					continue;

				lsdesc->type = OSPF6_ROUTER_LSDESC_POINTTOPOINT;
				lsdesc->metric = htons(ospf6_neighbor_cost(on));
				lsdesc->interface_id =
					htonl(oi->interface->ifindex);
				lsdesc->neighbor_interface_id =
					htonl(on->ifindex);
				lsdesc->neighbor_router_id = on->router_id;

				lsdesc++;
			}
		}

		/* Broadcast and NBMA interfaces */
		else if (oi->type == OSPF_IFTYPE_BROADCAST) {
			/* If this router is not DR,
			   and If this router not fully adjacent with DR,
			   this interface is not transit yet: ignore. */
			if (oi->state != OSPF6_INTERFACE_DR) {
				drouter =
					ospf6_neighbor_lookup(oi->drouter, oi);
				if (drouter == NULL
				    || drouter->state != OSPF6_NEIGHBOR_FULL)
					continue;
			}

			lsdesc->type = OSPF6_ROUTER_LSDESC_TRANSIT_NETWORK;
			lsdesc->metric = htons(oi->cost);
			lsdesc->interface_id = htonl(oi->interface->ifindex);
			if (oi->state != OSPF6_INTERFACE_DR) {
				lsdesc->neighbor_interface_id =
					htonl(drouter->ifindex);
				lsdesc->neighbor_router_id = drouter->router_id;
			} else {
				lsdesc->neighbor_interface_id =
					htonl(oi->interface->ifindex);
				lsdesc->neighbor_router_id =
					oi->area->ospf6->router_id;
			}

			lsdesc++;
		} else {
			assert(0); /* Unknown interface type */
		}

		/* Virtual links */
		/* xxx */
		/* Point-to-Multipoint interfaces */
		/* xxx */
	}

	/* Fill LSA Header */
	lsa_header->age = 0;
	lsa_header->type = htons(OSPF6_LSTYPE_ROUTER);
	lsa_header->id = htonl(link_state_id);
	lsa_header->adv_router = oa->ospf6->router_id;
	lsa_header->seqnum =
		ospf6_new_ls_seqnum(lsa_header->type, lsa_header->id,
				    lsa_header->adv_router, oa->lsdb);
	lsa_header->length = htons((caddr_t)lsdesc - (caddr_t)buffer);

	/* LSA checksum */
	ospf6_lsa_checksum(lsa_header);

	/* create LSA */
	lsa = ospf6_lsa_create(lsa_header);

	/* Originate */
	ospf6_lsa_originate_area(lsa, oa);

	link_state_id++;

	/* Do premature-aging of rest, undesired Router-LSAs */
	type = ntohs(OSPF6_LSTYPE_ROUTER);
	router = oa->ospf6->router_id;
	count = 0;
	for (ALL_LSDB_TYPED_ADVRTR(oa->lsdb, type, router, lsa)) {
		if (ntohl(lsa->header->id) < link_state_id)
			continue;
		ospf6_lsa_purge(lsa);
		count++;
	}

	/*
	 * Waiting till the LSA is actually removed from the database to trigger
	 * SPF delays network convergence. Unlike IPv4, for an ABR, when all
	 * interfaces associated with an area are gone, triggering an SPF right
	 * away
	 * helps convergence with inter-area routes.
	 */
	if (count && !link_state_id)
		ospf6_spf_schedule(oa->ospf6,
				   OSPF6_SPF_FLAGS_ROUTER_LSA_ORIGINATED);
}

/*******************************/
/* RFC2740 3.4.3.2 Network-LSA */
/*******************************/

static char *ospf6_network_lsa_get_ar_id(struct ospf6_lsa *lsa, char *buf,
					 int buflen, int pos)
{
	struct ospf6_network_lsdesc *lsdesc = nth_lsdesc(lsa->header, pos);

	if (!lsdesc || !buf || buflen < (1 + INET_ADDRSTRLEN))
		return NULL;

	inet_ntop(AF_INET, &lsdesc->router_id, buf, buflen);
	return buf;
}

static int ospf6_network_lsa_show(struct vty *vty, struct ospf6_lsa *lsa,
				  json_object *json_obj, bool use_json)
{
	char *start, *end, *current;
	struct ospf6_network_lsa *network_lsa;
	struct ospf6_network_lsdesc *lsdesc;
	char buf[128], options[32];
	json_object *json_arr = NULL;

	network_lsa = lsa_after_header(lsa->header);

	ospf6_options_printbuf(network_lsa->options, options, sizeof(options));
	if (use_json)
		json_object_string_add(json_obj, "options", options);
	else
		vty_out(vty, "     Options: %s\n", options);

	start = (char *)network_lsa + sizeof(struct ospf6_network_lsa);
	end = (char *)lsa->header + ntohs(lsa->header->length);
	if (use_json)
		json_arr = json_object_new_array();

	for (current = start;
	     current + sizeof(struct ospf6_network_lsdesc) <= end;
	     current += sizeof(struct ospf6_network_lsdesc)) {
		lsdesc = (struct ospf6_network_lsdesc *)current;
		inet_ntop(AF_INET, &lsdesc->router_id, buf, sizeof(buf));
		if (use_json)
			json_object_array_add(json_arr,
					      json_object_new_string(buf));
		else
			vty_out(vty, "     Attached Router: %s\n", buf);
	}
	if (use_json)
		json_object_object_add(json_obj, "attachedRouter", json_arr);

	return 0;
}

void ospf6_network_lsa_originate(struct event *thread)
{
	struct ospf6_interface *oi;

	char buffer[OSPF6_MAX_LSASIZE];
	struct ospf6_lsa_header *lsa_header;

	int count;
	struct ospf6_lsa *old, *lsa;
	struct ospf6_network_lsa *network_lsa;
	struct ospf6_network_lsdesc *lsdesc;
	struct ospf6_neighbor *on;
	struct ospf6_link_lsa *link_lsa;
	struct listnode *i;
	uint16_t type;

	oi = (struct ospf6_interface *)EVENT_ARG(thread);

	/* The interface must be enabled until here. A Network-LSA of a
	   disabled interface (but was once enabled) should be flushed
	   by ospf6_lsa_refresh (), and does not come here. */
	assert(oi->area);

	if (oi->area->ospf6->gr_info.restart_in_progress) {
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug(
				"Graceful Restart in progress, don't originate LSA");
		return;
	}

	old = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_NETWORK),
				htonl(oi->interface->ifindex),
				oi->area->ospf6->router_id, oi->area->lsdb);

	/* Do not originate Network-LSA if not DR */
	if (oi->state != OSPF6_INTERFACE_DR) {
		if (old) {
			ospf6_lsa_purge(old);
			/*
			 * Waiting till the LSA is actually removed from the
			 * database to
			 * trigger SPF delays network convergence.
			 */
			ospf6_spf_schedule(
				oi->area->ospf6,
				OSPF6_SPF_FLAGS_NETWORK_LSA_ORIGINATED);
		}
		return;
	}

	if (IS_OSPF6_DEBUG_ORIGINATE(NETWORK))
		zlog_debug("Originate Network-LSA for Interface %s",
			   oi->interface->name);

	/* If none of neighbor is adjacent to us */
	count = 0;

	for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, i, on))
		if (on->state == OSPF6_NEIGHBOR_FULL)
			count++;

	if (count == 0) {
		if (IS_OSPF6_DEBUG_ORIGINATE(NETWORK))
			zlog_debug("Interface stub, ignore");
		if (old)
			ospf6_lsa_purge(old);
		return;
	}

	/* prepare buffer */
	memset(buffer, 0, sizeof(buffer));
	lsa_header = (struct ospf6_lsa_header *)buffer;
	network_lsa = lsa_after_header(lsa_header);

	/* Collect the interface's Link-LSAs to describe
	   network's optional capabilities */
	type = htons(OSPF6_LSTYPE_LINK);
	for (ALL_LSDB_TYPED(oi->lsdb, type, lsa)) {
		link_lsa = lsa_after_header(lsa->header);
		network_lsa->options[0] |= link_lsa->options[0];
		network_lsa->options[1] |= link_lsa->options[1];
		network_lsa->options[2] |= link_lsa->options[2];
	}

	lsdesc = lsdesc_start_lsa_type(lsa_header, OSPF6_LSTYPE_NETWORK);

	/* set Link Description to the router itself */
	lsdesc->router_id = oi->area->ospf6->router_id;
	lsdesc++;

	/* Walk through the neighbors */
	for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, i, on)) {
		if (on->state != OSPF6_NEIGHBOR_FULL)
			continue;

		/* set this neighbor's Router-ID to LSA */
		lsdesc->router_id = on->router_id;
		lsdesc++;
	}

	/* Fill LSA Header */
	lsa_header->age = 0;
	lsa_header->type = htons(OSPF6_LSTYPE_NETWORK);
	lsa_header->id = htonl(oi->interface->ifindex);
	lsa_header->adv_router = oi->area->ospf6->router_id;
	lsa_header->seqnum =
		ospf6_new_ls_seqnum(lsa_header->type, lsa_header->id,
				    lsa_header->adv_router, oi->area->lsdb);
	lsa_header->length = htons((caddr_t)lsdesc - (caddr_t)buffer);

	/* LSA checksum */
	ospf6_lsa_checksum(lsa_header);

	/* create LSA */
	lsa = ospf6_lsa_create(lsa_header);

	/* Originate */
	ospf6_lsa_originate_area(lsa, oi->area);
}


/****************************/
/* RFC2740 3.4.3.6 Link-LSA */
/****************************/

static char *ospf6_link_lsa_get_prefix_str(struct ospf6_lsa *lsa, char *buf,
					   int buflen, int pos)
{
	struct ospf6_link_lsa *link_lsa = lsa_after_header(lsa->header);
	struct ospf6_prefix *prefix = nth_prefix(lsa->header, pos);
	struct in6_addr in6 = { 0 };

	if (!prefix || !buf || buflen < (1 + INET6_ADDRSTRLEN))
		return NULL;

	/* position zero is used for the lladdr in the body of the LSA */
	if (pos == 0) {
		inet_ntop(AF_INET6, &link_lsa->linklocal_addr, buf, buflen);
		return buf;
	}

	memcpy(&in6, OSPF6_PREFIX_BODY(prefix),
	       OSPF6_PREFIX_SPACE(prefix->prefix_length));
	inet_ntop(AF_INET6, &in6, buf, buflen);

	return buf;
}

static int ospf6_link_lsa_show(struct vty *vty, struct ospf6_lsa *lsa,
			       json_object *json_obj, bool use_json)
{
	char *start, *end, *current;
	struct ospf6_link_lsa *link_lsa;
	int prefixnum;
	char buf[128], options[32];
	struct ospf6_prefix *prefix;
	struct in6_addr in6;
	json_object *json_loop;
	json_object *json_arr = NULL;
	char prefix_string[133];

	link_lsa = lsa_after_header(lsa->header);

	ospf6_options_printbuf(link_lsa->options, options, sizeof(options));
	inet_ntop(AF_INET6, &link_lsa->linklocal_addr, buf, sizeof(buf));
	prefixnum = ntohl(link_lsa->prefix_num);

	if (use_json) {
		json_arr = json_object_new_array();
		json_object_int_add(json_obj, "priority", link_lsa->priority);
		json_object_string_add(json_obj, "options", options);
		json_object_string_add(json_obj, "linkLocalAddress", buf);
		json_object_int_add(json_obj, "numberOfPrefix", prefixnum);
	} else {
		vty_out(vty, "     Priority: %d Options: %s\n",
			link_lsa->priority, options);
		vty_out(vty, "     LinkLocal Address: %s\n", buf);
		vty_out(vty, "     Number of Prefix: %d\n", prefixnum);
	}

	start = (char *)link_lsa + sizeof(struct ospf6_link_lsa);
	end = ospf6_lsa_end(lsa->header);

	for (current = start; current < end;
	     current += OSPF6_PREFIX_SIZE(prefix)) {
		prefix = (struct ospf6_prefix *)current;
		if (prefix->prefix_length == 0
		    || current + OSPF6_PREFIX_SIZE(prefix) > end)
			break;

		ospf6_prefix_options_printbuf(prefix->prefix_options, buf,
					      sizeof(buf));
		if (use_json) {
			json_loop = json_object_new_object();
			json_object_string_add(json_loop, "prefixOption", buf);
		} else
			vty_out(vty, "     Prefix Options: %s\n", buf);

		memset(&in6, 0, sizeof(in6));
		memcpy(&in6, OSPF6_PREFIX_BODY(prefix),
		       OSPF6_PREFIX_SPACE(prefix->prefix_length));
		inet_ntop(AF_INET6, &in6, buf, sizeof(buf));
		if (use_json) {
			snprintf(prefix_string, sizeof(prefix_string), "%s/%d",
				 buf, prefix->prefix_length);
			json_object_string_add(json_loop, "prefix",
					       prefix_string);
			json_object_array_add(json_arr, json_loop);
		} else
			vty_out(vty, "     Prefix: %s/%d\n", buf,
				prefix->prefix_length);
	}
	if (use_json)
		json_object_object_add(json_obj, "prefix", json_arr);

	return 0;
}

void ospf6_link_lsa_originate(struct event *thread)
{
	struct ospf6_interface *oi;

	char buffer[OSPF6_MAX_LSASIZE];
	struct ospf6_lsa_header *lsa_header;
	struct ospf6_lsa *old, *lsa;

	struct ospf6_link_lsa *link_lsa;
	struct ospf6_route *route;
	struct ospf6_prefix *op;

	oi = (struct ospf6_interface *)EVENT_ARG(thread);

	assert(oi->area);

	if (oi->area->ospf6->gr_info.restart_in_progress) {
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug(
				"Graceful Restart in progress, don't originate LSA");
		return;
	}


	/* find previous LSA */
	old = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_LINK),
				htonl(oi->interface->ifindex),
				oi->area->ospf6->router_id, oi->lsdb);

	if (CHECK_FLAG(oi->flag, OSPF6_INTERFACE_DISABLE)) {
		if (old)
			ospf6_lsa_purge(old);
		return;
	}

	if (IS_OSPF6_DEBUG_ORIGINATE(LINK))
		zlog_debug("Originate Link-LSA for Interface %s",
			   oi->interface->name);

	/* can't make Link-LSA if linklocal address not set */
	if (oi->linklocal_addr == NULL) {
		if (IS_OSPF6_DEBUG_ORIGINATE(LINK))
			zlog_debug(
				"No Linklocal address on %s, defer originating",
				oi->interface->name);
		if (old)
			ospf6_lsa_purge(old);
		return;
	}

	/* prepare buffer */
	memset(buffer, 0, sizeof(buffer));
	lsa_header = (struct ospf6_lsa_header *)buffer;
	link_lsa = lsa_after_header(lsa_header);

	/* Fill Link-LSA */
	link_lsa->priority = oi->priority;
	memcpy(link_lsa->options, oi->area->options, 3);
	memcpy(&link_lsa->linklocal_addr, oi->linklocal_addr,
	       sizeof(struct in6_addr));
	link_lsa->prefix_num = htonl(oi->route_connected->count);

	op = lsdesc_start_lsa_type(lsa_header, OSPF6_LSTYPE_LINK);

	/* connected prefix to advertise */
	for (route = ospf6_route_head(oi->route_connected); route;
	     route = ospf6_route_next(route)) {
		op->prefix_length = route->prefix.prefixlen;
		op->prefix_options = route->prefix_options;
		op->prefix_metric = htons(0);
		memcpy(OSPF6_PREFIX_BODY(op), &route->prefix.u.prefix6,
		       OSPF6_PREFIX_SPACE(op->prefix_length));
		op = OSPF6_PREFIX_NEXT(op);
	}

	/* Fill LSA Header */
	lsa_header->age = 0;
	lsa_header->type = htons(OSPF6_LSTYPE_LINK);
	lsa_header->id = htonl(oi->interface->ifindex);
	lsa_header->adv_router = oi->area->ospf6->router_id;
	lsa_header->seqnum =
		ospf6_new_ls_seqnum(lsa_header->type, lsa_header->id,
				    lsa_header->adv_router, oi->lsdb);
	lsa_header->length = htons((caddr_t)op - (caddr_t)buffer);

	/* LSA checksum */
	ospf6_lsa_checksum(lsa_header);

	/* create LSA */
	lsa = ospf6_lsa_create(lsa_header);

	/* Originate */
	ospf6_lsa_originate_interface(lsa, oi);
}


/*****************************************/
/* RFC2740 3.4.3.7 Intra-Area-Prefix-LSA */
/*****************************************/
static char *ospf6_intra_prefix_lsa_get_prefix_str(struct ospf6_lsa *lsa,
						   char *buf, int buflen,
						   int pos)
{
	struct ospf6_prefix *prefix = nth_prefix(lsa->header, pos);
	struct in6_addr in6 = { 0 };
	char tbuf[16];

	/* ensure buflen >= INET6_ADDRSTRLEN + '/128\0' */
	if (!prefix || !buf || buflen < (5 + INET6_ADDRSTRLEN))
		return NULL;

	memcpy(&in6, OSPF6_PREFIX_BODY(prefix),
	       OSPF6_PREFIX_SPACE(prefix->prefix_length));
	inet_ntop(AF_INET6, &in6, buf, buflen);

	snprintf(tbuf, sizeof(tbuf), "/%d", prefix->prefix_length);
	strlcat(buf, tbuf, buflen);

	return buf;
}

static int ospf6_intra_prefix_lsa_show(struct vty *vty, struct ospf6_lsa *lsa,
				       json_object *json_obj, bool use_json)
{
	char *start, *end, *current;
	struct ospf6_intra_prefix_lsa *intra_prefix_lsa;
	int prefixnum;
	char buf[128];
	struct ospf6_prefix *prefix;
	char id[16], adv_router[16];
	struct in6_addr in6;
	json_object *json_loop;
	json_object *json_arr = NULL;
	char prefix_string[133];

	intra_prefix_lsa = lsa_after_header(lsa->header);

	prefixnum = ntohs(intra_prefix_lsa->prefix_num);

	if (use_json) {
		json_arr = json_object_new_array();
		json_object_int_add(json_obj, "numberOfPrefix", prefixnum);
	} else
		vty_out(vty, "     Number of Prefix: %d\n", prefixnum);

	inet_ntop(AF_INET, &intra_prefix_lsa->ref_id, id, sizeof(id));
	inet_ntop(AF_INET, &intra_prefix_lsa->ref_adv_router, adv_router,
		  sizeof(adv_router));
	if (use_json) {
		json_object_string_add(
			json_obj, "reference",
			ospf6_lstype_name(intra_prefix_lsa->ref_type));
		json_object_string_add(json_obj, "referenceId", id);
		json_object_string_add(json_obj, "referenceAdv", adv_router);
	} else
		vty_out(vty, "     Reference: %s Id: %s Adv: %s\n",
			ospf6_lstype_name(intra_prefix_lsa->ref_type), id,
			adv_router);

	start = (char *)intra_prefix_lsa
		+ sizeof(struct ospf6_intra_prefix_lsa);
	end = ospf6_lsa_end(lsa->header);

	for (current = start; current < end;
	     current += OSPF6_PREFIX_SIZE(prefix)) {
		prefix = (struct ospf6_prefix *)current;
		if (prefix->prefix_length == 0
		    || current + OSPF6_PREFIX_SIZE(prefix) > end)
			break;

		ospf6_prefix_options_printbuf(prefix->prefix_options, buf,
					      sizeof(buf));
		if (use_json) {
			json_loop = json_object_new_object();
			json_object_string_add(json_loop, "prefixOption", buf);
		} else
			vty_out(vty, "     Prefix Options: %s\n", buf);

		memset(&in6, 0, sizeof(in6));
		memcpy(&in6, OSPF6_PREFIX_BODY(prefix),
		       OSPF6_PREFIX_SPACE(prefix->prefix_length));
		inet_ntop(AF_INET6, &in6, buf, sizeof(buf));
		if (use_json) {
			snprintf(prefix_string, sizeof(prefix_string), "%s/%d",
				 buf, prefix->prefix_length);
			json_object_string_add(json_loop, "prefix",
					       prefix_string);
			json_object_int_add(json_loop, "metric",
					    ntohs(prefix->prefix_metric));
			json_object_array_add(json_arr, json_loop);
		} else {
			vty_out(vty, "     Prefix: %s/%d\n", buf,
				prefix->prefix_length);
			vty_out(vty, "     Metric: %d\n",
				ntohs(prefix->prefix_metric));
		}
	}
	if (use_json)
		json_object_object_add(json_obj, "prefix", json_arr);

	return 0;
}

void ospf6_intra_prefix_lsa_originate_stub(struct event *thread)
{
	struct ospf6_area *oa;

	char buffer[OSPF6_MAX_LSASIZE];
	struct ospf6_lsa_header *lsa_header;
	struct ospf6_lsa *old, *lsa, *old_next = NULL;

	struct ospf6_intra_prefix_lsa *intra_prefix_lsa;
	struct ospf6_interface *oi;
	struct ospf6_neighbor *on;
	struct ospf6_route *route;
	struct ospf6_prefix *op;
	struct listnode *i, *j;
	int full_count = 0;
	unsigned short prefix_num = 0;
	struct ospf6_route_table *route_advertise;
	int ls_id = 0;

	oa = (struct ospf6_area *)EVENT_ARG(thread);

	if (oa->ospf6->gr_info.restart_in_progress) {
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug(
				"Graceful Restart in progress, don't originate LSA");
		return;
	}

	/* find previous LSA */
	old = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_INTRA_PREFIX), htonl(0),
				oa->ospf6->router_id, oa->lsdb);

	if (!IS_AREA_ENABLED(oa)) {
		if (old) {
			ospf6_lsa_purge(old);
			/* find previous LSA */
			old_next = ospf6_lsdb_lookup(
				htons(OSPF6_LSTYPE_INTRA_PREFIX),
				htonl(++ls_id), oa->ospf6->router_id, oa->lsdb);

			while (old_next) {
				ospf6_lsa_purge(old_next);
				old_next = ospf6_lsdb_lookup(
					htons(OSPF6_LSTYPE_INTRA_PREFIX),
					htonl(++ls_id), oa->ospf6->router_id,
					oa->lsdb);
			}
		}
		return;
	}

	if (IS_OSPF6_DEBUG_ORIGINATE(INTRA_PREFIX))
		zlog_debug(
			"Originate Intra-Area-Prefix-LSA for area %s's stub prefix",
			oa->name);

	/* prepare buffer */
	memset(buffer, 0, sizeof(buffer));
	lsa_header = (struct ospf6_lsa_header *)buffer;
	intra_prefix_lsa = lsa_after_header(lsa_header);

	/* Fill Intra-Area-Prefix-LSA */
	intra_prefix_lsa->ref_type = htons(OSPF6_LSTYPE_ROUTER);
	intra_prefix_lsa->ref_id = htonl(0);
	intra_prefix_lsa->ref_adv_router = oa->ospf6->router_id;

	route_advertise = ospf6_route_table_create(0, 0);

	for (ALL_LIST_ELEMENTS_RO(oa->if_list, i, oi)) {
		if (oi->state == OSPF6_INTERFACE_DOWN) {
			if (IS_OSPF6_DEBUG_ORIGINATE(INTRA_PREFIX))
				zlog_debug("  Interface %s is down, ignore",
					   oi->interface->name);
			continue;
		}

		full_count = 0;

		for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, j, on))
			if (on->state == OSPF6_NEIGHBOR_FULL)
				full_count++;

		if (oi->state != OSPF6_INTERFACE_LOOPBACK
		    && oi->state != OSPF6_INTERFACE_POINTTOPOINT
		    && oi->state != OSPF6_INTERFACE_POINTTOMULTIPOINT
		    && full_count != 0) {
			if (IS_OSPF6_DEBUG_ORIGINATE(INTRA_PREFIX))
				zlog_debug("  Interface %s is not stub, ignore",
					   oi->interface->name);
			continue;
		}

		if (IS_OSPF6_DEBUG_ORIGINATE(INTRA_PREFIX))
			zlog_debug("  Interface %s:", oi->interface->name);

		/* connected prefix to advertise */
		for (route = ospf6_route_head(oi->route_connected); route;
		     route = ospf6_route_best_next(route)) {
			if (IS_OSPF6_DEBUG_ORIGINATE(INTRA_PREFIX))
				zlog_debug("    include %pFX", &route->prefix);
			ospf6_route_add(ospf6_route_copy(route),
					route_advertise);
		}
	}

	if (route_advertise->count == 0) {
		if (old) {
			ls_id = 0;
			ospf6_lsa_purge(old);
			/* find previous LSA */
			old_next = ospf6_lsdb_lookup(
				htons(OSPF6_LSTYPE_INTRA_PREFIX),
				htonl(++ls_id), oa->ospf6->router_id, oa->lsdb);

			while (old_next) {
				ospf6_lsa_purge(old_next);
				old_next = ospf6_lsdb_lookup(
					htons(OSPF6_LSTYPE_INTRA_PREFIX),
					htonl(++ls_id), oa->ospf6->router_id,
					oa->lsdb);
			}
		}
		ospf6_route_table_delete(route_advertise);
		return;
	}

	/* Neighbor change to FULL, if INTRA-AREA-PREFIX LSA
	 * has not change, Flush old LSA and Re-Originate INP,
	 * as ospf6_flood() checks if LSA is same as DB,
	 * it won't be updated to neighbor's DB.
	 */
	if (oa->intra_prefix_originate) {
		if (IS_OSPF6_DEBUG_ORIGINATE(INTRA_PREFIX))
			zlog_debug(
				"%s: Re-originate intra prefix LSA, Current full nbrs %u",
				__func__, oa->full_nbrs);
		if (old)
			ospf6_lsa_purge_multi_ls_id(oa, old);
		oa->intra_prefix_originate = 0;
	}

	/* put prefixes to advertise */
	prefix_num = 0;
	op = lsdesc_start_lsa_type(lsa_header, OSPF6_LSTYPE_INTRA_PREFIX);
	for (route = ospf6_route_head(route_advertise); route;
	     route = ospf6_route_best_next(route)) {
		if (((caddr_t)op - (caddr_t)lsa_header) > MAX_LSA_PAYLOAD) {
			intra_prefix_lsa->prefix_num = htons(prefix_num);

			/* Fill LSA Header */
			lsa_header->age = 0;
			lsa_header->type = htons(OSPF6_LSTYPE_INTRA_PREFIX);
			lsa_header->id = htonl(ls_id++);
			lsa_header->adv_router = oa->ospf6->router_id;
			lsa_header->seqnum = ospf6_new_ls_seqnum(
				lsa_header->type, lsa_header->id,
				lsa_header->adv_router, oa->lsdb);
			lsa_header->length =
				htons((caddr_t)op - (caddr_t)lsa_header);

			/* LSA checksum */
			ospf6_lsa_checksum(lsa_header);

			/* Create LSA */
			lsa = ospf6_lsa_create(lsa_header);

			/* Originate */
			ospf6_lsa_originate_area(lsa, oa);

			/* Prepare next buffer */
			memset(buffer, 0, sizeof(buffer));
			lsa_header = (struct ospf6_lsa_header *)buffer;
			intra_prefix_lsa = lsa_after_header(lsa_header);

			/* Fill Intra-Area-Prefix-LSA */
			intra_prefix_lsa->ref_type = htons(OSPF6_LSTYPE_ROUTER);
			intra_prefix_lsa->ref_id = htonl(0);
			intra_prefix_lsa->ref_adv_router = oa->ospf6->router_id;

			/* Put next set of prefixes to advertise */
			prefix_num = 0;
			op = lsdesc_start_lsa_type(lsa_header,
						   OSPF6_LSTYPE_INTRA_PREFIX);
		}

		op->prefix_length = route->prefix.prefixlen;
		op->prefix_options = route->prefix_options;
		op->prefix_metric = htons(route->path.cost);
		memcpy(OSPF6_PREFIX_BODY(op), &route->prefix.u.prefix6,
		       OSPF6_PREFIX_SPACE(op->prefix_length));
		prefix_num++;

		op = OSPF6_PREFIX_NEXT(op);
	}

	ospf6_route_table_delete(route_advertise);

	if (prefix_num == 0) {
		if (IS_OSPF6_DEBUG_ORIGINATE(INTRA_PREFIX))
			zlog_debug(
				"Quit to Advertise Intra-Prefix: no route to advertise");
		return;
	}

	intra_prefix_lsa->prefix_num = htons(prefix_num);

	/* Fill LSA Header */
	lsa_header->age = 0;
	lsa_header->type = htons(OSPF6_LSTYPE_INTRA_PREFIX);
	lsa_header->id = htonl(ls_id++);
	lsa_header->adv_router = oa->ospf6->router_id;
	lsa_header->seqnum =
		ospf6_new_ls_seqnum(lsa_header->type, lsa_header->id,
				    lsa_header->adv_router, oa->lsdb);
	lsa_header->length = htons((caddr_t)op - (caddr_t)lsa_header);

	/* LSA checksum */
	ospf6_lsa_checksum(lsa_header);

	/* create LSA */
	lsa = ospf6_lsa_create(lsa_header);

	/* Originate */
	ospf6_lsa_originate_area(lsa, oa);
}


void ospf6_intra_prefix_lsa_originate_transit(struct event *thread)
{
	struct ospf6_interface *oi;

	char buffer[OSPF6_MAX_LSASIZE];
	struct ospf6_lsa_header *lsa_header;
	struct ospf6_lsa *old, *lsa;

	struct ospf6_intra_prefix_lsa *intra_prefix_lsa;
	struct ospf6_neighbor *on;
	struct ospf6_route *route;
	struct ospf6_prefix *op;
	struct listnode *i;
	int full_count = 0;
	unsigned short prefix_num = 0;
	struct ospf6_route_table *route_advertise;
	struct ospf6_link_lsa *link_lsa;
	char *start, *end, *current;
	uint16_t type;

	oi = (struct ospf6_interface *)EVENT_ARG(thread);

	assert(oi->area);

	if (oi->area->ospf6->gr_info.restart_in_progress) {
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug(
				"Graceful Restart in progress, don't originate LSA");
		return;
	}

	/* find previous LSA */
	old = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_INTRA_PREFIX),
				htonl(oi->interface->ifindex),
				oi->area->ospf6->router_id, oi->area->lsdb);

	if (CHECK_FLAG(oi->flag, OSPF6_INTERFACE_DISABLE)) {
		if (old)
			ospf6_lsa_purge(old);
		return;
	}

	if (IS_OSPF6_DEBUG_ORIGINATE(INTRA_PREFIX))
		zlog_debug(
			"Originate Intra-Area-Prefix-LSA for interface %s's prefix",
			oi->interface->name);

	/* prepare buffer */
	memset(buffer, 0, sizeof(buffer));
	lsa_header = (struct ospf6_lsa_header *)buffer;
	intra_prefix_lsa = lsa_after_header(lsa_header);

	/* Fill Intra-Area-Prefix-LSA */
	intra_prefix_lsa->ref_type = htons(OSPF6_LSTYPE_NETWORK);
	intra_prefix_lsa->ref_id = htonl(oi->interface->ifindex);
	intra_prefix_lsa->ref_adv_router = oi->area->ospf6->router_id;

	if (oi->state != OSPF6_INTERFACE_DR) {
		if (IS_OSPF6_DEBUG_ORIGINATE(INTRA_PREFIX))
			zlog_debug("  Interface is not DR");
		if (old)
			ospf6_lsa_purge(old);
		return;
	}

	full_count = 0;
	for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, i, on))
		if (on->state == OSPF6_NEIGHBOR_FULL)
			full_count++;

	if (full_count == 0) {
		if (IS_OSPF6_DEBUG_ORIGINATE(INTRA_PREFIX))
			zlog_debug("  Interface is stub");
		if (old)
			ospf6_lsa_purge(old);
		return;
	}

	/* connected prefix to advertise */
	route_advertise = ospf6_route_table_create(0, 0);

	type = ntohs(OSPF6_LSTYPE_LINK);
	for (ALL_LSDB_TYPED(oi->lsdb, type, lsa)) {
		if (OSPF6_LSA_IS_MAXAGE(lsa))
			continue;

		if (IS_OSPF6_DEBUG_ORIGINATE(INTRA_PREFIX))
			zlog_debug("  include prefix from %s", lsa->name);

		if (lsa->header->adv_router != oi->area->ospf6->router_id) {
			on = ospf6_neighbor_lookup(lsa->header->adv_router, oi);
			if (on == NULL || on->state != OSPF6_NEIGHBOR_FULL) {
				if (IS_OSPF6_DEBUG_ORIGINATE(INTRA_PREFIX))
					zlog_debug(
						"    Neighbor not found or not Full, ignore");
				continue;
			}
		}

		link_lsa = lsa_after_header(lsa->header);

		prefix_num = (unsigned short)ntohl(link_lsa->prefix_num);
		start = (char *)link_lsa + sizeof(struct ospf6_link_lsa);
		end = ospf6_lsa_end(lsa->header);

		for (current = start; current < end && prefix_num;
		     current += OSPF6_PREFIX_SIZE(op)) {
			op = (struct ospf6_prefix *)current;
			if (op->prefix_length == 0
			    || current + OSPF6_PREFIX_SIZE(op) > end)
				break;

			route = ospf6_route_create(oi->area->ospf6);

			route->type = OSPF6_DEST_TYPE_NETWORK;
			route->prefix.family = AF_INET6;
			route->prefix.prefixlen = op->prefix_length;
			memset(&route->prefix.u.prefix6, 0,
			       sizeof(struct in6_addr));
			memcpy(&route->prefix.u.prefix6, OSPF6_PREFIX_BODY(op),
			       OSPF6_PREFIX_SPACE(op->prefix_length));
			route->prefix_options = op->prefix_options;

			route->path.origin.type = lsa->header->type;
			route->path.origin.id = lsa->header->id;
			route->path.origin.adv_router = lsa->header->adv_router;
			route->path.options[0] = link_lsa->options[0];
			route->path.options[1] = link_lsa->options[1];
			route->path.options[2] = link_lsa->options[2];
			route->path.area_id = oi->area->area_id;
			route->path.type = OSPF6_PATH_TYPE_INTRA;

			if (IS_OSPF6_DEBUG_ORIGINATE(INTRA_PREFIX))
				zlog_debug("    include %pFX", &route->prefix);

			ospf6_route_add(route, route_advertise);
			prefix_num--;
		}
		if (current != end && IS_OSPF6_DEBUG_ORIGINATE(INTRA_PREFIX))
			zlog_debug("Trailing garbage in %s", lsa->name);
	}

	op = lsdesc_start_lsa_type(lsa_header, OSPF6_LSTYPE_INTRA_PREFIX);

	prefix_num = 0;
	for (route = ospf6_route_head(route_advertise); route;
	     route = ospf6_route_best_next(route)) {
		op->prefix_length = route->prefix.prefixlen;
		op->prefix_options = route->prefix_options;
		op->prefix_metric = htons(0);
		memcpy(OSPF6_PREFIX_BODY(op), &route->prefix.u.prefix6,
		       OSPF6_PREFIX_SPACE(op->prefix_length));
		op = OSPF6_PREFIX_NEXT(op);
		prefix_num++;
	}

	ospf6_route_table_delete(route_advertise);

	if (prefix_num == 0) {
		if (IS_OSPF6_DEBUG_ORIGINATE(INTRA_PREFIX))
			zlog_debug(
				"Quit to Advertise Intra-Prefix: no route to advertise");
		return;
	}

	intra_prefix_lsa->prefix_num = htons(prefix_num);

	/* Fill LSA Header */
	lsa_header->age = 0;
	lsa_header->type = htons(OSPF6_LSTYPE_INTRA_PREFIX);
	lsa_header->id = htonl(oi->interface->ifindex);
	lsa_header->adv_router = oi->area->ospf6->router_id;
	lsa_header->seqnum =
		ospf6_new_ls_seqnum(lsa_header->type, lsa_header->id,
				    lsa_header->adv_router, oi->area->lsdb);
	lsa_header->length = htons((caddr_t)op - (caddr_t)lsa_header);

	/* LSA checksum */
	ospf6_lsa_checksum(lsa_header);

	/* create LSA */
	lsa = ospf6_lsa_create(lsa_header);

	/* Originate */
	ospf6_lsa_originate_area(lsa, oi->area);
}

static void ospf6_intra_prefix_update_route_origin(struct ospf6_route *oa_route,
						   struct ospf6 *ospf6)
{
	struct ospf6_path *h_path;
	struct ospf6_route *g_route, *nroute;

	/* Update Global ospf6 route path */
	g_route = ospf6_route_lookup(&oa_route->prefix, ospf6->route_table);

	assert(g_route);

	for (ospf6_route_lock(g_route); g_route &&
	     ospf6_route_is_prefix(&oa_route->prefix, g_route);
	     g_route = nroute) {
		nroute = ospf6_route_next(g_route);
		if (g_route->type != oa_route->type)
			continue;
		if (g_route->path.area_id != oa_route->path.area_id)
			continue;
		if (g_route->path.type != OSPF6_PATH_TYPE_INTRA)
			continue;
		if (g_route->path.cost != oa_route->path.cost)
			continue;

		if (ospf6_route_is_same_origin(g_route, oa_route)) {
			h_path = (struct ospf6_path *)listgetdata(
				listhead(g_route->paths));
			g_route->path.origin.type = h_path->origin.type;
			g_route->path.origin.id = h_path->origin.id;
			g_route->path.origin.adv_router =
				h_path->origin.adv_router;
			if (nroute)
				ospf6_route_unlock(nroute);
			break;
		}
	}

	h_path = (struct ospf6_path *)listgetdata(
				listhead(oa_route->paths));
	oa_route->path.origin.type = h_path->origin.type;
	oa_route->path.origin.id = h_path->origin.id;
	oa_route->path.origin.adv_router = h_path->origin.adv_router;
}

void ospf6_intra_prefix_route_ecmp_path(struct ospf6_area *oa,
					struct ospf6_route *old,
					struct ospf6_route *route)
{
	struct ospf6_route *old_route, *ls_entry;
	struct ospf6_path *ecmp_path, *o_path = NULL;
	struct listnode *anode, *anext;
	struct listnode *nnode, *rnode, *rnext;
	struct ospf6_nexthop *nh, *rnh;
	bool route_found = false;
	struct interface *ifp = NULL;
	struct ospf6_lsa *lsa;
	struct ospf6_intra_prefix_lsa *intra_prefix_lsa;

	/* check for old entry match with new route origin,
	 * delete old entry.
	 */
	for (old_route = old; old_route; old_route = old_route->next) {
		bool route_updated = false;

		/* The route linked-list is grouped in batches of prefix.
		 * If the new prefix is not the same as the one of interest
		 * then we have walked over the end of the batch and so we
		 * should break rather than continuing unnecessarily.
		 */
		if (!ospf6_route_is_same(old_route, route))
			break;
		if (old_route->path.type != route->path.type)
			continue;

		/* Current and New route has same origin,
		 * delete old entry.
		 */
		for (ALL_LIST_ELEMENTS(old_route->paths, anode, anext,
						  o_path)) {
			/* Check old route path and route has same
			 * origin.
			 */
			if (o_path->area_id != route->path.area_id
			    || !ospf6_ls_origin_same(o_path, &route->path))
				continue;

			/* Cost is not same then delete current path */
			if (o_path->cost == route->path.cost)
				continue;

			if (IS_OSPF6_DEBUG_EXAMIN(INTRA_PREFIX)) {
				zlog_debug(
					"%s: route %pFX cost old %u new %u is not same, replace route",
					__func__, &old_route->prefix, o_path->cost,
					route->path.cost);
			}

			/* Remove selected current path's nh from
			 * effective nh list.
			 */
			for (ALL_LIST_ELEMENTS_RO(o_path->nh_list, nnode, nh)) {
				for (ALL_LIST_ELEMENTS(old_route->nh_list,
							rnode, rnext, rnh)) {
					if (!ospf6_nexthop_is_same(rnh, nh))
						continue;
					listnode_delete(old_route->nh_list,
								rnh);
					ospf6_nexthop_delete(rnh);
					route_updated = true;
				}
			}

			listnode_delete(old_route->paths, o_path);
			ospf6_path_free(o_path);

			/* Current route's path (adv_router info) is similar
			 * to route being added.
			 * Replace current route's path with paths list head.
			 * Update FIB with effective NHs.
			 */
			if (listcount(old_route->paths)) {
				if (route_updated) {
					for (ALL_LIST_ELEMENTS(old_route->paths,
							anode, anext, o_path)) {
						ospf6_merge_nexthops(
							old_route->nh_list,
							o_path->nh_list);
					}
					/* Update ospf6 route table and
					 * RIB/FIB with effective
					 * nh_list
					 */
					if (oa->route_table->hook_add)
						(*oa->route_table->hook_add)(
							old_route);

					if (old_route->path.origin.id ==
					route->path.origin.id &&
					old_route->path.origin.adv_router ==
						route->path.origin.adv_router) {
						ospf6_intra_prefix_update_route_origin(
							old_route, oa->ospf6);
					}
					break;
				}
			} else {
				if (IS_OSPF6_DEBUG_EXAMIN(INTRA_PREFIX)) {
					zlog_debug(
						"%s: route %pFX old cost %u new cost %u, delete old entry.",
						__func__, &old_route->prefix,
						old_route->path.cost,
						route->path.cost);
				}
				if (oa->route_table->hook_remove)
					ospf6_route_remove(old_route,
							   oa->route_table);
				else
					SET_FLAG(old_route->flag,
						 OSPF6_ROUTE_REMOVE);
				break;
			}
		}
		if (route_updated)
			break;
	}

	for (old_route = old; old_route; old_route = old_route->next) {

		/* The route linked-list is grouped in batches of prefix.
		 * If the new prefix is not the same as the one of interest
		 * then we have walked over the end of the batch and so we
		 * should break rather than continuing unnecessarily.
		 */
		if (!ospf6_route_is_same(old_route, route))
			break;
		if (old_route->path.type != route->path.type)
			continue;

		/* Old Route and New Route have Equal Cost, Merge NHs */
		if (old_route->path.cost == route->path.cost) {
			route_found = true;

			/* check if this path exists already in
			 * route->paths list, if so, replace nh_list.
			 */
			for (ALL_LIST_ELEMENTS_RO(old_route->paths, anode,
						  o_path)) {
				if (o_path->area_id == route->path.area_id
				    && ospf6_ls_origin_same(o_path, &route->path))
					break;
			}
			/* If path is not found in old_route paths's list,
			 * add a new path to route paths list and merge
			 * nexthops in route->path->nh_list.
			 * Otherwise replace existing path's nh_list.
			 */
			if (o_path == NULL) {
				ecmp_path = ospf6_path_dup(&route->path);

				/* Add a nh_list to new ecmp path */
				ospf6_copy_nexthops(ecmp_path->nh_list,
						    route->nh_list);
				/* Add the new path to route's path list */
				listnode_add_sort(old_route->paths, ecmp_path);

				if (IS_OSPF6_DEBUG_EXAMIN(INTRA_PREFIX)) {
					zlog_debug(
						"%s: route %pFX %p another path added with nh %u, effective paths %u nh %u",
						__func__, &route->prefix,
						(void *)old_route,
						listcount(ecmp_path->nh_list),
						old_route->paths ? listcount(
							old_route->paths)
								 : 0,
						listcount(old_route->nh_list));
				}
			} else {
				list_delete_all_node(o_path->nh_list);
				ospf6_copy_nexthops(o_path->nh_list,
					    route->nh_list);

			}

			list_delete_all_node(old_route->nh_list);

			for (ALL_LIST_ELEMENTS_RO(old_route->paths, anode,
						  o_path)) {
				ls_entry = ospf6_route_lookup(
							&o_path->ls_prefix,
							oa->spf_table);
				if (ls_entry == NULL) {
					if (IS_OSPF6_DEBUG_EXAMIN(INTRA_PREFIX))
						zlog_debug(
							"%s: ls_prfix %pFX ls_entry not found.",
							__func__,
							&o_path->ls_prefix);
					continue;
				}
				lsa = ospf6_lsdb_lookup(o_path->origin.type,
						o_path->origin.id,
						o_path->origin.adv_router,
						oa->lsdb);
				if (lsa == NULL) {
					if (IS_OSPF6_DEBUG_EXAMIN(
								INTRA_PREFIX)) {
						struct prefix adv_prefix;

						ospf6_linkstate_prefix(
						o_path->origin.adv_router,
						o_path->origin.id, &adv_prefix);
						zlog_debug(
							"%s: adv_router %pFX lsa not found",
							__func__, &adv_prefix);
					}
					continue;
				}
				intra_prefix_lsa = lsa_after_header(lsa->header);

				if (intra_prefix_lsa->ref_adv_router
				     == oa->ospf6->router_id) {
					ifp = if_lookup_prefix(
						&old_route->prefix,
						oa->ospf6->vrf_id);
				}

				if (ifp) {
					/* Nexthop interface found */
					ospf6_route_add_nexthop(old_route,
								ifp->ifindex,
								NULL);
				} else {
					/* The connected interfaces between
					 * routers can be in different networks.
					 * In this case the matching interface
					 * is not found. Copy nexthops from the
					 * link state entry
					 */
					ospf6_route_merge_nexthops(old_route,
								   ls_entry);
				}
			}

			if (IS_OSPF6_DEBUG_EXAMIN(INTRA_PREFIX))
				zlog_debug(
					"%s: route %pFX %p with final effective paths %u nh %u",
					__func__, &route->prefix,
					(void *)old_route,
					old_route->paths
						? listcount(old_route->paths)
						: 0,
					listcount(old_route->nh_list));

			/* used in intra_route_calculation() to add to
			 * global ospf6 route table.
			 */
			UNSET_FLAG(old_route->flag, OSPF6_ROUTE_REMOVE);
			SET_FLAG(old_route->flag, OSPF6_ROUTE_ADD);
			/* Update ospf6 route table and RIB/FIB */
			if (oa->route_table->hook_add)
				(*oa->route_table->hook_add)(old_route);
			/* Delete the new route its info added to existing
			 * route.
			 */
			ospf6_route_delete(route);

			break;
		}
	}

	if (!route_found) {
		/* Add new route to existing node in ospf6 route table. */
		ospf6_route_add(route, oa->route_table);
	}
}

void ospf6_intra_prefix_lsa_add(struct ospf6_lsa *lsa)
{
	struct ospf6_area *oa;
	struct ospf6_intra_prefix_lsa *intra_prefix_lsa;
	struct prefix ls_prefix;
	struct ospf6_route *route, *ls_entry, *old;
	int prefix_num;
	struct ospf6_prefix *op;
	char *start, *current, *end;
	char buf[PREFIX2STR_BUFFER];
	struct interface *ifp = NULL;
	int direct_connect = 0;
	struct ospf6_path *path;

	if (OSPF6_LSA_IS_MAXAGE(lsa))
		return;

	if (IS_OSPF6_DEBUG_EXAMIN(INTRA_PREFIX))
		zlog_debug("%s: LSA %s found", __func__, lsa->name);

	oa = OSPF6_AREA(lsa->lsdb->data);

	intra_prefix_lsa = lsa_after_header(lsa->header);
	if (intra_prefix_lsa->ref_type == htons(OSPF6_LSTYPE_ROUTER) ||
	    intra_prefix_lsa->ref_type == htons(OSPF6_LSTYPE_NETWORK))
		ospf6_linkstate_prefix(intra_prefix_lsa->ref_adv_router,
				       intra_prefix_lsa->ref_id, &ls_prefix);
	else {
		if (IS_OSPF6_DEBUG_EXAMIN(INTRA_PREFIX))
			zlog_debug("Unknown reference LS-type: %#hx",
				   ntohs(intra_prefix_lsa->ref_type));
		return;
	}

	ls_entry = ospf6_route_lookup(&ls_prefix, oa->spf_table);
	if (ls_entry == NULL) {
		if (IS_OSPF6_DEBUG_EXAMIN(INTRA_PREFIX)) {
			ospf6_linkstate_prefix2str(&ls_prefix, buf,
						   sizeof(buf));
			zlog_debug("LS entry does not exist: %s", buf);
		}
		return;
	}

	if (intra_prefix_lsa->ref_adv_router == oa->ospf6->router_id) {
		/* the intra-prefix are directly connected */
		direct_connect = 1;
	}

	prefix_num = ntohs(intra_prefix_lsa->prefix_num);
	start = (caddr_t)intra_prefix_lsa
		+ sizeof(struct ospf6_intra_prefix_lsa);
	end = ospf6_lsa_end(lsa->header);
	for (current = start; current < end; current += OSPF6_PREFIX_SIZE(op)) {
		op = (struct ospf6_prefix *)current;
		if (prefix_num == 0)
			break;
		if (end < current + OSPF6_PREFIX_SIZE(op))
			break;

		/* Appendix A.4.1.1 */
		if (CHECK_FLAG(op->prefix_options, OSPF6_PREFIX_OPTION_NU)) {
			if (IS_OSPF6_DEBUG_EXAMIN(INTRA_PREFIX)) {
				ospf6_linkstate_prefix2str(
					(struct prefix *)OSPF6_PREFIX_BODY(op),
					buf, sizeof(buf));
				zlog_debug(
					"%s: Skipping Prefix %s has NU option set",
					__func__, buf);
			}
			continue;
		}

		route = ospf6_route_create(oa->ospf6);

		memset(&route->prefix, 0, sizeof(struct prefix));
		route->prefix.family = AF_INET6;
		route->prefix.prefixlen = op->prefix_length;
		ospf6_prefix_in6_addr(&route->prefix.u.prefix6,
				      intra_prefix_lsa, op);
		route->prefix_options = op->prefix_options;

		route->type = OSPF6_DEST_TYPE_NETWORK;
		route->path.origin.type = lsa->header->type;
		route->path.origin.id = lsa->header->id;
		route->path.origin.adv_router = lsa->header->adv_router;
		route->path.area_id = oa->area_id;
		route->path.type = OSPF6_PATH_TYPE_INTRA;
		route->path.metric_type = 1;
		route->path.cost =
			ls_entry->path.cost + ntohs(op->prefix_metric);
		memcpy(&route->path.ls_prefix, &ls_prefix,
		       sizeof(struct prefix));
		if (direct_connect) {
			ifp = if_lookup_prefix(&route->prefix,
					       oa->ospf6->vrf_id);
		}

		if (ifp) {
			/* Nexthop interface found */
			ospf6_route_add_nexthop(route, ifp->ifindex, NULL);
		} else {
			/* The connected interfaces between routers can be in
			 * different networks. In this case the matching
			 * interface is not found. Copy nexthops from the
			 * link state entry
			 */
			ospf6_route_copy_nexthops(route, ls_entry);
		}

		path = ospf6_path_dup(&route->path);
		ospf6_copy_nexthops(path->nh_list, route->path.nh_list);
		listnode_add_sort(route->paths, path);

		old = ospf6_route_lookup(&route->prefix, oa->route_table);
		if (old) {
			if (IS_OSPF6_DEBUG_EXAMIN(INTRA_PREFIX)) {
				prefix2str(&route->prefix, buf, sizeof(buf));
				zlog_debug(
					"%s Update route: %s old cost %u new cost %u paths %u nh %u",
					__func__, buf, old->path.cost,
					route->path.cost,
					listcount(route->paths),
					listcount(route->nh_list));
			}
			ospf6_intra_prefix_route_ecmp_path(oa, old, route);
		} else {
			if (IS_OSPF6_DEBUG_EXAMIN(INTRA_PREFIX)) {
				prefix2str(&route->prefix, buf, sizeof(buf));
				zlog_debug(
					"%s route %s add with cost %u paths %u nh %u",
					__func__, buf, route->path.cost,
					listcount(route->paths),
					listcount(route->nh_list));
			}
			ospf6_route_add(route, oa->route_table);
		}
		prefix_num--;
	}

	if (current != end && IS_OSPF6_DEBUG_EXAMIN(INTRA_PREFIX))
		zlog_debug("Trailing garbage ignored");
}

static void ospf6_intra_prefix_lsa_remove_update_route(struct ospf6_lsa *lsa,
						  struct ospf6_area *oa,
						  struct ospf6_route *route)
{
	struct listnode *anode, *anext;
	struct listnode *nnode, *rnode, *rnext;
	struct ospf6_nexthop *nh, *rnh;
	struct ospf6_path *o_path;
	bool nh_updated = false;
	char buf[PREFIX2STR_BUFFER];

	/* Iterate all paths of route to find maching
	 * with LSA remove info.
	 * If route->path is same, replace
	 * from paths list.
	 */
	for (ALL_LIST_ELEMENTS(route->paths, anode, anext, o_path)) {
		if ((o_path->origin.type != lsa->header->type) ||
		    (o_path->origin.adv_router != lsa->header->adv_router) ||
		    (o_path->origin.id != lsa->header->id))
			continue;

		if (IS_OSPF6_DEBUG_EXAMIN(INTRA_PREFIX)) {
			prefix2str(&route->prefix, buf, sizeof(buf));
			zlog_debug(
				"%s: route %s path found with cost %u nh %u to remove.",
				__func__, buf, o_path->cost,
				listcount(o_path->nh_list));
		}

		/* Remove found path's nh_list from
		 * the route's nh_list.
		 */
		for (ALL_LIST_ELEMENTS_RO(o_path->nh_list, nnode, nh)) {
			for (ALL_LIST_ELEMENTS(route->nh_list, rnode,
					       rnext, rnh)) {
				if (!ospf6_nexthop_is_same(rnh, nh))
					continue;
				listnode_delete(route->nh_list, rnh);
				ospf6_nexthop_delete(rnh);
			}
		}
		/* Delete the path from route's
		 * path list
		 */
		listnode_delete(route->paths, o_path);
		ospf6_path_free(o_path);
		nh_updated = true;
		break;
	}

	if (nh_updated) {
		/* Iterate all paths and merge nexthop,
		 * unlesss any of the nexthop similar to
		 * ones deleted as part of path deletion.
		 */
		for (ALL_LIST_ELEMENTS(route->paths, anode, anext, o_path))
			ospf6_merge_nexthops(route->nh_list, o_path->nh_list);


		if (IS_OSPF6_DEBUG_EXAMIN(INTRA_PREFIX)) {
			prefix2str(&route->prefix, buf, sizeof(buf));
			zlog_debug(
				"%s: route %s update paths %u nh %u", __func__,
				buf, route->paths ? listcount(route->paths) : 0,
				route->nh_list ? listcount(route->nh_list) : 0);
		}

		/* Update Global Route table and
		 * RIB/FIB with effective
		 * nh_list
		 */
		if (oa->route_table->hook_add)
			(*oa->route_table->hook_add)(route);

		/* route's primary path is similar
		 * to LSA, replace route's primary
		 * path with route's paths list
		 * head.
		 */
		if ((route->path.origin.id == lsa->header->id) &&
		    (route->path.origin.adv_router ==
				lsa->header->adv_router)) {
			ospf6_intra_prefix_update_route_origin(route,
							       oa->ospf6);
		}
	}

}

void ospf6_intra_prefix_lsa_remove(struct ospf6_lsa *lsa)
{
	struct ospf6_area *oa;
	struct ospf6_intra_prefix_lsa *intra_prefix_lsa;
	struct prefix prefix;
	struct ospf6_route *route, *nroute;
	int prefix_num;
	struct ospf6_prefix *op;
	char *start, *current, *end;
	char buf[PREFIX2STR_BUFFER];

	if (IS_OSPF6_DEBUG_EXAMIN(INTRA_PREFIX))
		zlog_debug("%s: %s disappearing", __func__, lsa->name);

	oa = OSPF6_AREA(lsa->lsdb->data);

	intra_prefix_lsa = lsa_after_header(lsa->header);

	prefix_num = ntohs(intra_prefix_lsa->prefix_num);
	start = (caddr_t)intra_prefix_lsa
		+ sizeof(struct ospf6_intra_prefix_lsa);
	end = ospf6_lsa_end(lsa->header);
	for (current = start; current < end; current += OSPF6_PREFIX_SIZE(op)) {
		op = (struct ospf6_prefix *)current;
		if (prefix_num == 0)
			break;
		if (end < current + OSPF6_PREFIX_SIZE(op))
			break;
		prefix_num--;

		memset(&prefix, 0, sizeof(prefix));
		prefix.family = AF_INET6;
		prefix.prefixlen = op->prefix_length;
		ospf6_prefix_in6_addr(&prefix.u.prefix6, intra_prefix_lsa, op);

		route = ospf6_route_lookup(&prefix, oa->route_table);
		if (route == NULL)
			continue;

		for (ospf6_route_lock(route);
		     route && ospf6_route_is_prefix(&prefix, route);
		     route = nroute) {
			nroute = ospf6_route_next(route);
			if (route->type != OSPF6_DEST_TYPE_NETWORK)
				continue;
			if (route->path.area_id != oa->area_id)
				continue;
			if (route->path.type != OSPF6_PATH_TYPE_INTRA)
				continue;
			/* Route has multiple ECMP paths, remove matching
			 * path. Update current route's effective nh list
			 * after removal of one of the path.
			 */
			if (listcount(route->paths) > 1) {
				ospf6_intra_prefix_lsa_remove_update_route(
							lsa, oa, route);
			} else {

				if (route->path.origin.type != lsa->header->type
				    || route->path.origin.id != lsa->header->id
				    || route->path.origin.adv_router
				    != lsa->header->adv_router)
					continue;

				if (IS_OSPF6_DEBUG_EXAMIN(INTRA_PREFIX)) {
					prefix2str(&route->prefix, buf,
						   sizeof(buf));
					zlog_debug(
						"%s: route remove %s with path type %u cost %u paths %u nh %u",
						__func__, buf, route->path.type,
						route->path.cost,
						listcount(route->paths),
						listcount(route->nh_list));
				}
				ospf6_route_remove(route, oa->route_table);
			}
		}
		if (route)
			ospf6_route_unlock(route);
	}

	if (current != end && IS_OSPF6_DEBUG_EXAMIN(INTRA_PREFIX))
		zlog_debug("Trailing garbage ignored");
}

void ospf6_intra_route_calculation(struct ospf6_area *oa)
{
	struct ospf6_route *route, *nroute;
	uint16_t type;
	struct ospf6_lsa *lsa;
	void (*hook_add)(struct ospf6_route *) = NULL;
	void (*hook_remove)(struct ospf6_route *) = NULL;
	char buf[PREFIX2STR_BUFFER];

	if (IS_OSPF6_DEBUG_EXAMIN(INTRA_PREFIX))
		zlog_debug("Re-examin intra-routes for area %s", oa->name);

	hook_add = oa->route_table->hook_add;
	hook_remove = oa->route_table->hook_remove;
	oa->route_table->hook_add = NULL;
	oa->route_table->hook_remove = NULL;

	for (route = ospf6_route_head(oa->route_table); route;
	     route = ospf6_route_next(route))
		route->flag = OSPF6_ROUTE_REMOVE;

	type = htons(OSPF6_LSTYPE_INTRA_PREFIX);
	for (ALL_LSDB_TYPED(oa->lsdb, type, lsa))
		ospf6_intra_prefix_lsa_add(lsa);

	oa->route_table->hook_add = hook_add;
	oa->route_table->hook_remove = hook_remove;

	for (route = ospf6_route_head(oa->route_table); route; route = nroute) {
		if (IS_OSPF6_DEBUG_EXAMIN(INTRA_PREFIX)) {
			prefix2str(&route->prefix, buf, sizeof(buf));
			zlog_debug("%s: route %s, flag 0x%x", __func__, buf,
				   route->flag);
		}

		nroute = ospf6_route_next(route);
		if (CHECK_FLAG(route->flag, OSPF6_ROUTE_REMOVE)
		    && CHECK_FLAG(route->flag, OSPF6_ROUTE_ADD)) {
			UNSET_FLAG(route->flag, OSPF6_ROUTE_REMOVE);
			UNSET_FLAG(route->flag, OSPF6_ROUTE_ADD);
		}

		if (CHECK_FLAG(route->flag, OSPF6_ROUTE_REMOVE))
			ospf6_route_remove(route, oa->route_table);
		else if (CHECK_FLAG(route->flag, OSPF6_ROUTE_ADD)
			 || CHECK_FLAG(route->flag, OSPF6_ROUTE_CHANGE)) {
			if (hook_add)
				(*hook_add)(route);
			route->flag = 0;
		} else {
			/* Redo the summaries as things might have changed */
			if (IS_OSPF6_DEBUG_EXAMIN(INTRA_PREFIX))
				zlog_debug("%s: Originate summary for route %s",
					   __func__, buf);
			ospf6_abr_originate_summary(route, oa->ospf6);
			route->flag = 0;
		}
	}

	if (IS_OSPF6_DEBUG_EXAMIN(INTRA_PREFIX))
		zlog_debug("Re-examin intra-routes for area %s: Done",
			   oa->name);
}

static void ospf6_brouter_debug_print(struct ospf6_route *brouter)
{
	uint32_t brouter_id;
	char brouter_name[16];
	char area_name[16];
	char destination[64];
	char installed[64], changed[64];
	struct timeval now, res;
	char id[16], adv_router[16];
	char capa[16], options[32];

	brouter_id = ADV_ROUTER_IN_PREFIX(&brouter->prefix);
	inet_ntop(AF_INET, &brouter_id, brouter_name, sizeof(brouter_name));
	inet_ntop(AF_INET, &brouter->path.area_id, area_name,
		  sizeof(area_name));
	ospf6_linkstate_prefix2str(&brouter->prefix, destination,
				   sizeof(destination));

	monotime(&now);
	timersub(&now, &brouter->installed, &res);
	timerstring(&res, installed, sizeof(installed));

	monotime(&now);
	timersub(&now, &brouter->changed, &res);
	timerstring(&res, changed, sizeof(changed));

	inet_ntop(AF_INET, &brouter->path.origin.id, id, sizeof(id));
	inet_ntop(AF_INET, &brouter->path.origin.adv_router, adv_router,
		  sizeof(adv_router));

	ospf6_options_printbuf(brouter->path.options, options, sizeof(options));
	ospf6_capability_printbuf(brouter->path.router_bits, capa,
				  sizeof(capa));

	zlog_info("Brouter: %s via area %s", brouter_name, area_name);
	zlog_info("  memory: prev: %p this: %p next: %p parent rnode: %p",
		  (void *)brouter->prev, (void *)brouter, (void *)brouter->next,
		  (void *)brouter->rnode);
	zlog_info("  type: %d prefix: %s installed: %s changed: %s",
		  brouter->type, destination, installed, changed);
	zlog_info("  lock: %d flags: %s%s%s%s", brouter->lock,
		  (CHECK_FLAG(brouter->flag, OSPF6_ROUTE_BEST) ? "B" : "-"),
		  (CHECK_FLAG(brouter->flag, OSPF6_ROUTE_ADD) ? "A" : "-"),
		  (CHECK_FLAG(brouter->flag, OSPF6_ROUTE_REMOVE) ? "R" : "-"),
		  (CHECK_FLAG(brouter->flag, OSPF6_ROUTE_CHANGE) ? "C" : "-"));
	zlog_info("  path type: %s ls-origin %s id: %s adv-router %s",
		  OSPF6_PATH_TYPE_NAME(brouter->path.type),
		  ospf6_lstype_name(brouter->path.origin.type), id, adv_router);
	zlog_info("  options: %s router-bits: %s metric-type: %d metric: %d/%d",
		  options, capa, brouter->path.metric_type, brouter->path.cost,
		  brouter->path.u.cost_e2);
	zlog_info(" paths %u nh %u", listcount(brouter->paths),
		   listcount(brouter->nh_list));
}

void ospf6_intra_brouter_calculation(struct ospf6_area *oa)
{
	struct ospf6_route *brouter, *nbrouter, *copy;
	void (*hook_add)(struct ospf6_route *) = NULL;
	void (*hook_remove)(struct ospf6_route *) = NULL;
	uint32_t brouter_id;
	char brouter_name[16];

	if (IS_OSPF6_DEBUG_BROUTER_SPECIFIC_AREA_ID(oa->area_id) ||
	    IS_OSPF6_DEBUG_ROUTE(MEMORY))
		zlog_debug("%s: border-router calculation for area %s",
			   __func__, oa->name);

	hook_add = oa->ospf6->brouter_table->hook_add;
	hook_remove = oa->ospf6->brouter_table->hook_remove;
	oa->ospf6->brouter_table->hook_add = NULL;
	oa->ospf6->brouter_table->hook_remove = NULL;

	/* withdraw the previous router entries for the area */
	for (brouter = ospf6_route_head(oa->ospf6->brouter_table); brouter;
	     brouter = ospf6_route_next(brouter)) {
		brouter_id = ADV_ROUTER_IN_PREFIX(&brouter->prefix);
		inet_ntop(AF_INET, &brouter_id, brouter_name,
			  sizeof(brouter_name));

		if (brouter->path.area_id != oa->area_id)
			continue;

		SET_FLAG(brouter->flag, OSPF6_ROUTE_REMOVE);

		if (IS_OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER_ID(brouter_id)
		    || IS_OSPF6_DEBUG_ROUTE(MEMORY)) {
			zlog_debug("%p: mark as removing: area %s brouter %s",
				   (void *)brouter, oa->name, brouter_name);
			ospf6_brouter_debug_print(brouter);
		}
	}

	for (brouter = ospf6_route_head(oa->spf_table); brouter;
	     brouter = ospf6_route_next(brouter)) {
		brouter_id = ADV_ROUTER_IN_PREFIX(&brouter->prefix);
		inet_ntop(AF_INET, &brouter_id, brouter_name,
			  sizeof(brouter_name));

		if (brouter->type != OSPF6_DEST_TYPE_LINKSTATE)
			continue;

		if (ospf6_linkstate_prefix_id(&brouter->prefix) != htonl(0))
			continue;

		if (!CHECK_FLAG(brouter->path.router_bits, OSPF6_ROUTER_BIT_E)
		    && !CHECK_FLAG(brouter->path.router_bits,
				   OSPF6_ROUTER_BIT_B))
			continue;

		if (!OSPF6_OPT_ISSET(brouter->path.options, OSPF6_OPT_V6)
		    || !OSPF6_OPT_ISSET(brouter->path.options, OSPF6_OPT_R))
			continue;

		copy = ospf6_route_copy(brouter);
		copy->type = OSPF6_DEST_TYPE_ROUTER;
		copy->path.area_id = oa->area_id;
		ospf6_route_add(copy, oa->ospf6->brouter_table);

		if (IS_OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER_ID(brouter_id)
		    || IS_OSPF6_DEBUG_ROUTE(MEMORY)) {
			zlog_debug("%p: transfer: area %s brouter %s",
				   (void *)brouter, oa->name, brouter_name);
			ospf6_brouter_debug_print(brouter);
		}
	}

	oa->ospf6->brouter_table->hook_add = hook_add;
	oa->ospf6->brouter_table->hook_remove = hook_remove;

	for (brouter = ospf6_route_head(oa->ospf6->brouter_table); brouter;
	     brouter = nbrouter) {

		/*
		 * brouter may have been "deleted" in the last loop iteration.
		 * If this is the case there is still 1 final refcount lock
		 * taken by ospf6_route_next, that will be released by the same
		 * call and result in deletion. To avoid heap UAF we must then
		 * skip processing the deleted route.
		 */
		if (brouter->lock == 1) {
			if (IS_OSPF6_DEBUG_ROUTE(MEMORY))
				ospf6_brouter_debug_print(brouter);
			nbrouter = ospf6_route_next(brouter);
			continue;
		} else {
			nbrouter = ospf6_route_next(brouter);
		}

		brouter_id = ADV_ROUTER_IN_PREFIX(&brouter->prefix);
		inet_ntop(AF_INET, &brouter_id, brouter_name,
			  sizeof(brouter_name));

		if (brouter->path.area_id != oa->area_id)
			continue;

		if (CHECK_FLAG(brouter->flag, OSPF6_ROUTE_WAS_REMOVED))
			continue;

		/* After iterating spf_table for all routers including
		 * intra brouter, clear mark for remove flag for
		 * inter border router if its adv router present in
		 * SPF table.
		 */
		if (brouter->path.type == OSPF6_PATH_TYPE_INTER) {
			struct prefix adv_prefix;

			ospf6_linkstate_prefix(brouter->path.origin.adv_router,
					       htonl(0), &adv_prefix);

			if (ospf6_route_lookup(&adv_prefix, oa->spf_table)) {
				if (IS_OSPF6_DEBUG_BROUTER) {
					zlog_debug(
						"%s: keep inter brouter %s as adv router 0x%x found in spf",
						__func__, brouter_name,
						brouter->path.origin
							.adv_router);
					ospf6_brouter_debug_print(brouter);
				}
				UNSET_FLAG(brouter->flag, OSPF6_ROUTE_REMOVE);
			}
		}

		if (CHECK_FLAG(brouter->flag, OSPF6_ROUTE_REMOVE)
		    && CHECK_FLAG(brouter->flag, OSPF6_ROUTE_ADD)) {
			UNSET_FLAG(brouter->flag, OSPF6_ROUTE_REMOVE);
			UNSET_FLAG(brouter->flag, OSPF6_ROUTE_ADD);
		}

		if (CHECK_FLAG(brouter->flag, OSPF6_ROUTE_REMOVE)) {
			if (IS_OSPF6_DEBUG_BROUTER
			    || IS_OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER_ID(
				       brouter_id)
			    || IS_OSPF6_DEBUG_BROUTER_SPECIFIC_AREA_ID(
				       oa->area_id))
				zlog_debug(
					"%s: brouter %s disappears via area %s",
					__func__, brouter_name, oa->name);
			/* This is used to protect nbrouter from removed from
			 * the table. For an example, ospf6_abr_examin_summary,
			 * removes brouters which are marked for remove.
			 */
			oa->intra_brouter_calc = true;
			ospf6_route_remove(brouter, oa->ospf6->brouter_table);
			brouter = NULL;
		} else if (CHECK_FLAG(brouter->flag, OSPF6_ROUTE_ADD)
			   || CHECK_FLAG(brouter->flag, OSPF6_ROUTE_CHANGE)) {
			if (IS_OSPF6_DEBUG_BROUTER
			    || IS_OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER_ID(
				       brouter_id)
			    || IS_OSPF6_DEBUG_BROUTER_SPECIFIC_AREA_ID(
				       oa->area_id))
				zlog_info("%s: brouter %s appears via area %s",
					  __func__, brouter_name, oa->name);

			/* newly added */
			if (hook_add)
				(*hook_add)(brouter);
		} else {
			if (IS_OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER_ID(
				    brouter_id)
			    || IS_OSPF6_DEBUG_BROUTER_SPECIFIC_AREA_ID(
				       oa->area_id))
				zlog_debug(
					"brouter %s still exists via area %s",
					brouter_name, oa->name);
			/* But re-originate summaries */
			ospf6_abr_originate_summary(brouter, oa->ospf6);
		}

		if (brouter) {
			UNSET_FLAG(brouter->flag, OSPF6_ROUTE_ADD);
			UNSET_FLAG(brouter->flag, OSPF6_ROUTE_CHANGE);
		}
		/* Reset for nbrouter */
		oa->intra_brouter_calc = false;
	}

	if (IS_OSPF6_DEBUG_BROUTER_SPECIFIC_AREA_ID(oa->area_id) ||
	    IS_OSPF6_DEBUG_ROUTE(MEMORY))
		zlog_debug("%s: border-router calculation for area %s: done",
			   __func__, oa->name);
}

static struct ospf6_lsa_handler router_handler = {
	.lh_type = OSPF6_LSTYPE_ROUTER,
	.lh_name = "Router",
	.lh_short_name = "Rtr",
	.lh_show = ospf6_router_lsa_show,
	.lh_get_prefix_str = ospf6_router_lsa_get_nbr_id,
	.lh_debug = 0};

static struct ospf6_lsa_handler network_handler = {
	.lh_type = OSPF6_LSTYPE_NETWORK,
	.lh_name = "Network",
	.lh_short_name = "Net",
	.lh_show = ospf6_network_lsa_show,
	.lh_get_prefix_str = ospf6_network_lsa_get_ar_id,
	.lh_debug = 0};

static struct ospf6_lsa_handler link_handler = {
	.lh_type = OSPF6_LSTYPE_LINK,
	.lh_name = "Link",
	.lh_short_name = "Lnk",
	.lh_show = ospf6_link_lsa_show,
	.lh_get_prefix_str = ospf6_link_lsa_get_prefix_str,
	.lh_debug = 0};

static struct ospf6_lsa_handler intra_prefix_handler = {
	.lh_type = OSPF6_LSTYPE_INTRA_PREFIX,
	.lh_name = "Intra-Prefix",
	.lh_short_name = "INP",
	.lh_show = ospf6_intra_prefix_lsa_show,
	.lh_get_prefix_str = ospf6_intra_prefix_lsa_get_prefix_str,
	.lh_debug = 0};

void ospf6_intra_init(void)
{
	ospf6_install_lsa_handler(&router_handler);
	ospf6_install_lsa_handler(&network_handler);
	ospf6_install_lsa_handler(&link_handler);
	ospf6_install_lsa_handler(&intra_prefix_handler);
}

DEFUN (debug_ospf6_brouter,
       debug_ospf6_brouter_cmd,
       "debug ospf6 border-routers",
       DEBUG_STR
       OSPF6_STR
       "Debug border router\n"
      )
{
	OSPF6_DEBUG_BROUTER_ON();
	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_brouter,
       no_debug_ospf6_brouter_cmd,
       "no debug ospf6 border-routers",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug border router\n"
      )
{
	OSPF6_DEBUG_BROUTER_OFF();
	return CMD_SUCCESS;
}

DEFUN (debug_ospf6_brouter_router,
       debug_ospf6_brouter_router_cmd,
       "debug ospf6 border-routers router-id A.B.C.D",
       DEBUG_STR
       OSPF6_STR
       "Debug border router\n"
       "Debug specific border router\n"
       "Specify border-router's router-id\n"
      )
{
	int idx_ipv4 = 4;
	uint32_t router_id;
	inet_pton(AF_INET, argv[idx_ipv4]->arg, &router_id);
	OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER_ON(router_id);
	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_brouter_router,
       no_debug_ospf6_brouter_router_cmd,
       "no debug ospf6 border-routers router-id [A.B.C.D]",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug border router\n"
       "Debug specific border router\n"
       "Specify border-router's router-id\n"
      )
{
	OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER_OFF();
	return CMD_SUCCESS;
}

DEFUN (debug_ospf6_brouter_area,
       debug_ospf6_brouter_area_cmd,
       "debug ospf6 border-routers area-id A.B.C.D",
       DEBUG_STR
       OSPF6_STR
       "Debug border router\n"
       "Debug border routers in specific Area\n"
       "Specify Area-ID\n"
      )
{
	int idx_ipv4 = 4;
	uint32_t area_id;
	inet_pton(AF_INET, argv[idx_ipv4]->arg, &area_id);
	OSPF6_DEBUG_BROUTER_SPECIFIC_AREA_ON(area_id);
	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_brouter_area,
       no_debug_ospf6_brouter_area_cmd,
       "no debug ospf6 border-routers area-id [A.B.C.D]",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug border router\n"
       "Debug border routers in specific Area\n"
       "Specify Area-ID\n"
      )
{
	OSPF6_DEBUG_BROUTER_SPECIFIC_AREA_OFF();
	return CMD_SUCCESS;
}

int config_write_ospf6_debug_brouter(struct vty *vty)
{
	char buf[16];
	if (IS_OSPF6_DEBUG_BROUTER)
		vty_out(vty, "debug ospf6 border-routers\n");
	if (IS_OSPF6_DEBUG_BROUTER_SPECIFIC_ROUTER) {
		inet_ntop(AF_INET, &conf_debug_ospf6_brouter_specific_router_id,
			  buf, sizeof(buf));
		vty_out(vty, "debug ospf6 border-routers router-id %s\n", buf);
	}
	if (IS_OSPF6_DEBUG_BROUTER_SPECIFIC_AREA) {
		inet_ntop(AF_INET, &conf_debug_ospf6_brouter_specific_area_id,
			  buf, sizeof(buf));
		vty_out(vty, "debug ospf6 border-routers area-id %s\n", buf);
	}
	return 0;
}

void install_element_ospf6_debug_brouter(void)
{
	install_element(ENABLE_NODE, &debug_ospf6_brouter_cmd);
	install_element(ENABLE_NODE, &debug_ospf6_brouter_router_cmd);
	install_element(ENABLE_NODE, &debug_ospf6_brouter_area_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf6_brouter_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf6_brouter_router_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf6_brouter_area_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_brouter_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_brouter_router_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_brouter_area_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf6_brouter_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf6_brouter_router_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf6_brouter_area_cmd);
}
