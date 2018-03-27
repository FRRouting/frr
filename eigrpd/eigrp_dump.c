/*
 * EIGRP Dump Functions and Debugging.
 * Copyright (C) 2013-2014
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
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

#include "linklist.h"
#include "thread.h"
#include "prefix.h"
#include "command.h"
#include "stream.h"
#include "log.h"
#include "sockopt.h"
#include "table.h"
#include "keychain.h"

#include "eigrpd/eigrp_structs.h"
#include "eigrpd/eigrpd.h"
#include "eigrpd/eigrp_interface.h"
#include "eigrpd/eigrp_neighbor.h"
#include "eigrpd/eigrp_packet.h"
#include "eigrpd/eigrp_zebra.h"
#include "eigrpd/eigrp_vty.h"
#include "eigrpd/eigrp_network.h"
#include "eigrpd/eigrp_dump.h"
#include "eigrpd/eigrp_topology.h"

/* Enable debug option variables -- valid only session. */
unsigned long term_debug_eigrp = 0;
unsigned long term_debug_eigrp_nei = 0;
unsigned long term_debug_eigrp_packet[11] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
unsigned long term_debug_eigrp_zebra = 6;
unsigned long term_debug_eigrp_transmit = 0;

/* Configuration debug option variables. */
unsigned long conf_debug_eigrp = 0;
unsigned long conf_debug_eigrp_nei = 0;
unsigned long conf_debug_eigrp_packet[11] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
unsigned long conf_debug_eigrp_zebra = 0;
unsigned long conf_debug_eigrp_transmit = 0;


static int config_write_debug(struct vty *vty)
{
	int write = 0;
	int i;

	const char *type_str[] = {"update", "request",   "query",     "reply",
				  "hello",  "",		 "probe",     "ack",
				  "",       "SIA query", "SIA reply", "stub",
				  "all"};
	const char *detail_str[] = {
		"",	" send",	" recv",	"",
		" detail", " send detail", " recv detail", " detail"};


	/* debug eigrp event. */

	/* debug eigrp packet */
	for (i = 0; i < 10; i++) {
		if (conf_debug_eigrp_packet[i] == 0
		    && term_debug_eigrp_packet[i] == 0)
			continue;

		vty_out(vty, "debug eigrp packet %s%s\n", type_str[i],
			detail_str[conf_debug_eigrp_packet[i]]);
		write = 1;
	}

	return write;
}

static int eigrp_neighbor_packet_queue_sum(struct eigrp_interface *ei)
{
	struct eigrp_neighbor *nbr;
	struct listnode *node, *nnode;
	int sum;
	sum = 0;

	for (ALL_LIST_ELEMENTS(ei->nbrs, node, nnode, nbr)) {
		sum += nbr->retrans_queue->count;
	}

	return sum;
}

/*
 * Expects header to be in host order
 */
void eigrp_ip_header_dump(struct ip *iph)
{
	/* IP Header dump. */
	zlog_debug("ip_v %u", iph->ip_v);
	zlog_debug("ip_hl %u", iph->ip_hl);
	zlog_debug("ip_tos %u", iph->ip_tos);
	zlog_debug("ip_len %u", iph->ip_len);
	zlog_debug("ip_id %u", (uint32_t)iph->ip_id);
	zlog_debug("ip_off %u", (uint32_t)iph->ip_off);
	zlog_debug("ip_ttl %u", iph->ip_ttl);
	zlog_debug("ip_p %u", iph->ip_p);
	zlog_debug("ip_sum 0x%x", (uint32_t)iph->ip_sum);
	zlog_debug("ip_src %s", inet_ntoa(iph->ip_src));
	zlog_debug("ip_dst %s", inet_ntoa(iph->ip_dst));
}

/*
 * Expects header to be in host order
 */
void eigrp_header_dump(struct eigrp_header *eigrph)
{
	/* EIGRP Header dump. */
	zlog_debug("eigrp_version %u", eigrph->version);
	zlog_debug("eigrp_opcode %u", eigrph->opcode);
	zlog_debug("eigrp_checksum 0x%x", ntohs(eigrph->checksum));
	zlog_debug("eigrp_flags 0x%x", ntohl(eigrph->flags));
	zlog_debug("eigrp_sequence %u", ntohl(eigrph->sequence));
	zlog_debug("eigrp_ack %u", ntohl(eigrph->ack));
	zlog_debug("eigrp_vrid %u", ntohs(eigrph->vrid));
	zlog_debug("eigrp_AS %u", ntohs(eigrph->ASNumber));
}

const char *eigrp_if_name_string(struct eigrp_interface *ei)
{
	static char buf[EIGRP_IF_STRING_MAXLEN] = "";

	if (!ei)
		return "inactive";

	snprintf(buf, EIGRP_IF_STRING_MAXLEN, "%s", ei->ifp->name);
	return buf;
}

const char *eigrp_topology_ip_string(struct eigrp_prefix_entry *tn)
{
	static char buf[EIGRP_IF_STRING_MAXLEN] = "";
	uint32_t ifaddr;

	ifaddr = ntohl(tn->destination->u.prefix4.s_addr);
	snprintf(buf, EIGRP_IF_STRING_MAXLEN, "%u.%u.%u.%u",
		 (ifaddr >> 24) & 0xff, (ifaddr >> 16) & 0xff,
		 (ifaddr >> 8) & 0xff, ifaddr & 0xff);
	return buf;
}


const char *eigrp_if_ip_string(struct eigrp_interface *ei)
{
	static char buf[EIGRP_IF_STRING_MAXLEN] = "";
	uint32_t ifaddr;

	if (!ei)
		return "inactive";

	ifaddr = ntohl(ei->address->u.prefix4.s_addr);
	snprintf(buf, EIGRP_IF_STRING_MAXLEN, "%u.%u.%u.%u",
		 (ifaddr >> 24) & 0xff, (ifaddr >> 16) & 0xff,
		 (ifaddr >> 8) & 0xff, ifaddr & 0xff);

	return buf;
}

const char *eigrp_neigh_ip_string(struct eigrp_neighbor *nbr)
{
	static char buf[EIGRP_IF_STRING_MAXLEN] = "";
	uint32_t ifaddr;

	ifaddr = ntohl(nbr->src.s_addr);
	snprintf(buf, EIGRP_IF_STRING_MAXLEN, "%u.%u.%u.%u",
		 (ifaddr >> 24) & 0xff, (ifaddr >> 16) & 0xff,
		 (ifaddr >> 8) & 0xff, ifaddr & 0xff);

	return buf;
}

void show_ip_eigrp_interface_header(struct vty *vty, struct eigrp *eigrp)
{

	vty_out(vty,
		"\nEIGRP interfaces for AS(%d)\n\n %-10s %-10s %-10s %-6s %-12s %-7s %-14s %-12s %-8s %-8s %-8s\n %-39s %-12s %-7s %-14s %-12s %-8s\n",
		eigrp->AS, "Interface", "Bandwidth", "Delay", "Peers",
		"Xmit Queue", "Mean", "Pacing Time", "Multicast", "Pending",
		"Hello", "Holdtime", "", "Un/Reliable", "SRTT", "Un/Reliable",
		"Flow Timer", "Routes");
}

void show_ip_eigrp_interface_sub(struct vty *vty, struct eigrp *eigrp,
				 struct eigrp_interface *ei)
{
	vty_out(vty, "%-11s ", eigrp_if_name_string(ei));
	vty_out(vty, "%-11u", ei->params.bandwidth);
	vty_out(vty, "%-11u", ei->params.delay);
	vty_out(vty, "%-7u", ei->nbrs->count);
	vty_out(vty, "%u %c %-10u", 0, '/',
		eigrp_neighbor_packet_queue_sum(ei));
	vty_out(vty, "%-7u %-14u %-12u %-8u", 0, 0, 0, 0);
	vty_out(vty, "%-8u %-8u \n", ei->params.v_hello, ei->params.v_wait);
}

void show_ip_eigrp_interface_detail(struct vty *vty, struct eigrp *eigrp,
				    struct eigrp_interface *ei)
{
	vty_out(vty, "%-2s %s %d %-3s \n", "", "Hello interval is ", 0, " sec");
	vty_out(vty, "%-2s %s %s \n", "", "Next xmit serial", "<none>");
	vty_out(vty, "%-2s %s %d %s %d %s %d %s %d \n", "",
		"Un/reliable mcasts: ", 0, "/", 0, "Un/reliable ucasts: ", 0,
		"/", 0);
	vty_out(vty, "%-2s %s %d %s %d %s %d \n", "", "Mcast exceptions: ", 0,
		"  CR packets: ", 0, "  ACKs supressed: ", 0);
	vty_out(vty, "%-2s %s %d %s %d \n", "", "Retransmissions sent: ", 0,
		"Out-of-sequence rcvd: ", 0);
	vty_out(vty, "%-2s %s %s %s \n", "", "Authentication mode is ", "not",
		"set");
	vty_out(vty, "%-2s %s \n", "", "Use multicast");
}

void show_ip_eigrp_neighbor_header(struct vty *vty, struct eigrp *eigrp)
{
	vty_out(vty,
		"\nEIGRP neighbors for AS(%d)\n\n%-3s %-17s %-20s %-6s %-8s %-6s %-5s %-5s %-5s\n %-41s %-6s %-8s %-6s %-4s %-6s %-5s \n",
		eigrp->AS, "H", "Address", "Interface", "Hold", "Uptime",
		"SRTT", "RTO", "Q", "Seq", "", "(sec)", "", "(ms)", "", "Cnt",
		"Num");
}

void show_ip_eigrp_neighbor_sub(struct vty *vty, struct eigrp_neighbor *nbr,
				int detail)
{

	vty_out(vty, "%-3u %-17s %-21s", 0, eigrp_neigh_ip_string(nbr),
		eigrp_if_name_string(nbr->ei));
	if (nbr->t_holddown)
		vty_out(vty, "%-7lu",
			thread_timer_remain_second(nbr->t_holddown));
	else
		vty_out(vty, "-      ");
	vty_out(vty, "%-8u %-6u %-5u", 0, 0, EIGRP_PACKET_RETRANS_TIME);
	vty_out(vty, "%-7lu", nbr->retrans_queue->count);
	vty_out(vty, "%u\n", nbr->recv_sequence_number);


	if (detail) {
		vty_out(vty, "    Version %u.%u/%u.%u", nbr->os_rel_major,
			nbr->os_rel_minor, nbr->tlv_rel_major,
			nbr->tlv_rel_minor);
		vty_out(vty, ", Retrans: %lu, Retries: %lu",
			nbr->retrans_queue->count, 0UL);
		vty_out(vty, ", %s\n", eigrp_nbr_state_str(nbr));
	}
}

/*
 * Print standard header for show EIGRP topology output
 */
void show_ip_eigrp_topology_header(struct vty *vty, struct eigrp *eigrp)
{
	struct in_addr router_id;
	router_id.s_addr = eigrp->router_id;

	vty_out(vty, "\nEIGRP Topology Table for AS(%d)/ID(%s)\n\n", eigrp->AS,
		inet_ntoa(router_id));
	vty_out(vty,
		"Codes: P - Passive, A - Active, U - Update, Q - Query, "
		"R - Reply\n       r - reply Status, s - sia Status\n\n");
}

void show_ip_eigrp_prefix_entry(struct vty *vty, struct eigrp_prefix_entry *tn)
{
	struct list *successors = eigrp_topology_get_successor(tn);
	char buffer[PREFIX_STRLEN];

	vty_out(vty, "%-3c", (tn->state > 0) ? 'A' : 'P');

	vty_out(vty, "%s, ",
		prefix2str(tn->destination, buffer, PREFIX_STRLEN));
	vty_out(vty, "%u successors, ", (successors) ? successors->count : 0);
	vty_out(vty, "FD is %u, serno: %" PRIu64 " \n", tn->fdistance,
		tn->serno);

	if (successors)
		list_delete_and_null(&successors);
}

void show_ip_eigrp_nexthop_entry(struct vty *vty, struct eigrp *eigrp,
				 struct eigrp_nexthop_entry *te, int *first)
{
	if (te->reported_distance == EIGRP_MAX_METRIC)
		return;

	if (*first) {
		show_ip_eigrp_prefix_entry(vty, te->prefix);
		*first = 0;
	}

	if (te->adv_router == eigrp->neighbor_self)
		vty_out(vty, "%-7s%s, %s\n", " ", "via Connected",
			eigrp_if_name_string(te->ei));
	else {
		vty_out(vty, "%-7s%s%s (%u/%u), %s\n", " ", "via ",
			inet_ntoa(te->adv_router->src), te->distance,
			te->reported_distance, eigrp_if_name_string(te->ei));
	}
}


DEFUN_NOSH (show_debugging_eigrp,
	    show_debugging_eigrp_cmd,
	    "show debugging [eigrp]",
	    SHOW_STR
	    DEBUG_STR
	    EIGRP_STR)
{
	int i;

	vty_out(vty, "EIGRP debugging status:\n");

	/* Show debug status for events. */
	if (IS_DEBUG_EIGRP(event, EVENT))
		vty_out(vty, "  EIGRP event debugging is on\n");

	/* Show debug status for EIGRP Packets. */
	for (i = 0; i < 11; i++) {
		if (i == 8)
			continue;

		if (IS_DEBUG_EIGRP_PACKET(i, SEND)
		    && IS_DEBUG_EIGRP_PACKET(i, RECV)) {
			vty_out(vty, "  EIGRP packet %s%s debugging is on\n",
				lookup_msg(eigrp_packet_type_str, i + 1, NULL),
				IS_DEBUG_EIGRP_PACKET(i, PACKET_DETAIL)
					? " detail"
					: "");
		} else {
			if (IS_DEBUG_EIGRP_PACKET(i, SEND))
				vty_out(vty,
					"  EIGRP packet %s send%s debugging is on\n",
					lookup_msg(eigrp_packet_type_str, i + 1,
						   NULL),
					IS_DEBUG_EIGRP_PACKET(i, PACKET_DETAIL)
						? " detail"
						: "");
			if (IS_DEBUG_EIGRP_PACKET(i, RECV))
				vty_out(vty,
					"  EIGRP packet %s receive%s debugging is on\n",
					lookup_msg(eigrp_packet_type_str, i + 1,
						   NULL),
					IS_DEBUG_EIGRP_PACKET(i, PACKET_DETAIL)
						? " detail"
						: "");
		}
	}

	return CMD_SUCCESS;
}


/*
  [no] debug eigrp packet (hello|dd|ls-request|ls-update|ls-ack|all)
  [send|recv [detail]]
*/

DEFUN (debug_eigrp_transmit,
       debug_eigrp_transmit_cmd,
       "debug eigrp transmit <send|recv|all> [detail]",
       DEBUG_STR
       EIGRP_STR
       "EIGRP transmission events\n"
       "packet sent\n"
       "packet received\n"
       "all packets\n"
       "Detailed Information\n")
{
	int flag = 0;
	int idx = 2;

	/* send or recv. */
	if (argv_find(argv, argc, "send", &idx))
		flag = EIGRP_DEBUG_SEND;
	else if (argv_find(argv, argc, "recv", &idx))
		flag = EIGRP_DEBUG_RECV;
	else if (argv_find(argv, argc, "all", &idx))
		flag = EIGRP_DEBUG_SEND_RECV;

	/* detail option */
	if (argv_find(argv, argc, "detail", &idx))
		flag = EIGRP_DEBUG_PACKET_DETAIL;

	if (vty->node == CONFIG_NODE)
		DEBUG_TRANSMIT_ON(0, flag);
	else
		TERM_DEBUG_TRANSMIT_ON(0, flag);

	return CMD_SUCCESS;
}

DEFUN (no_debug_eigrp_transmit,
       no_debug_eigrp_transmit_cmd,
       "no debug eigrp transmit <send|recv|all> [detail]",
       NO_STR
       UNDEBUG_STR
       EIGRP_STR
       "EIGRP transmission events\n"
       "packet sent\n"
       "packet received\n"
       "all packets\n"
       "Detailed Information\n")
{
	int flag = 0;
	int idx = 3;

	/* send or recv. */
	if (argv_find(argv, argc, "send", &idx))
		flag = EIGRP_DEBUG_SEND;
	else if (argv_find(argv, argc, "recv", &idx))
		flag = EIGRP_DEBUG_RECV;
	else if (argv_find(argv, argc, "all", &idx))
		flag = EIGRP_DEBUG_SEND_RECV;

	/* detail option */
	if (argv_find(argv, argc, "detail", &idx))
		flag = EIGRP_DEBUG_PACKET_DETAIL;

	if (vty->node == CONFIG_NODE)
		DEBUG_TRANSMIT_OFF(0, flag);
	else
		TERM_DEBUG_TRANSMIT_OFF(0, flag);

	return CMD_SUCCESS;
}

DEFUN (debug_eigrp_packets,
       debug_eigrp_packets_all_cmd,
       "debug eigrp packets <siaquery|siareply|ack|hello|probe|query|reply|request|retry|stub|terse|update|all> [send|receive] [detail]",
       DEBUG_STR
       EIGRP_STR
       "EIGRP packets\n"
       "EIGRP SIA-Query packets\n"
       "EIGRP SIA-Reply packets\n"
       "EIGRP ack packets\n"
       "EIGRP hello packets\n"
       "EIGRP probe packets\n"
       "EIGRP query packets\n"
       "EIGRP reply packets\n"
       "EIGRP request packets\n"
       "EIGRP retransmissions\n"
       "EIGRP stub packets\n"
       "Display all EIGRP packets except Hellos\n"
       "EIGRP update packets\n"
       "Display all EIGRP packets\n"
       "Send Packets\n"
       "Receive Packets\n"
       "Detail Information\n")
{
	int type = 0;
	int flag = 0;
	int i;
	int idx = 0;

	/* Check packet type. */
	if (argv_find(argv, argc, "hello", &idx))
		type = EIGRP_DEBUG_HELLO;
	if (argv_find(argv, argc, "update", &idx))
		type = EIGRP_DEBUG_UPDATE;
	if (argv_find(argv, argc, "query", &idx))
		type = EIGRP_DEBUG_QUERY;
	if (argv_find(argv, argc, "ack", &idx))
		type = EIGRP_DEBUG_ACK;
	if (argv_find(argv, argc, "probe", &idx))
		type = EIGRP_DEBUG_PROBE;
	if (argv_find(argv, argc, "stub", &idx))
		type = EIGRP_DEBUG_STUB;
	if (argv_find(argv, argc, "reply", &idx))
		type = EIGRP_DEBUG_REPLY;
	if (argv_find(argv, argc, "request", &idx))
		type = EIGRP_DEBUG_REQUEST;
	if (argv_find(argv, argc, "siaquery", &idx))
		type = EIGRP_DEBUG_SIAQUERY;
	if (argv_find(argv, argc, "siareply", &idx))
		type = EIGRP_DEBUG_SIAREPLY;
	if (argv_find(argv, argc, "all", &idx))
		type = EIGRP_DEBUG_PACKETS_ALL;


	/* All packet types, both send and recv. */
	flag = EIGRP_DEBUG_SEND_RECV;

	/* send or recv. */
	if (argv_find(argv, argc, "s", &idx))
		flag = EIGRP_DEBUG_SEND;
	else if (argv_find(argv, argc, "r", &idx))
		flag = EIGRP_DEBUG_RECV;

	/* detail. */
	if (argv_find(argv, argc, "detail", &idx))
		flag |= EIGRP_DEBUG_PACKET_DETAIL;

	for (i = 0; i < 11; i++)
		if (type & (0x01 << i)) {
			if (vty->node == CONFIG_NODE)
				DEBUG_PACKET_ON(i, flag);
			else
				TERM_DEBUG_PACKET_ON(i, flag);
		}

	return CMD_SUCCESS;
}

DEFUN (no_debug_eigrp_packets,
       no_debug_eigrp_packets_all_cmd,
       "no debug eigrp packets <siaquery|siareply|ack|hello|probe|query|reply|request|retry|stub|terse|update|all> [send|receive] [detail]",
       NO_STR
       UNDEBUG_STR
       EIGRP_STR
       "EIGRP packets\n"
       "EIGRP SIA-Query packets\n"
       "EIGRP SIA-Reply packets\n"
       "EIGRP ack packets\n"
       "EIGRP hello packets\n"
       "EIGRP probe packets\n"
       "EIGRP query packets\n"
       "EIGRP reply packets\n"
       "EIGRP request packets\n"
       "EIGRP retransmissions\n"
       "EIGRP stub packets\n"
       "Display all EIGRP packets except Hellos\n"
       "EIGRP update packets\n"
       "Display all EIGRP packets\n"
       "Send Packets\n"
       "Receive Packets\n"
       "Detailed Information\n")
{
	int type = 0;
	int flag = 0;
	int i;
	int idx = 0;

	/* Check packet type. */
	if (argv_find(argv, argc, "hello", &idx))
		type = EIGRP_DEBUG_HELLO;
	if (argv_find(argv, argc, "update", &idx))
		type = EIGRP_DEBUG_UPDATE;
	if (argv_find(argv, argc, "query", &idx))
		type = EIGRP_DEBUG_QUERY;
	if (argv_find(argv, argc, "ack", &idx))
		type = EIGRP_DEBUG_ACK;
	if (argv_find(argv, argc, "probe", &idx))
		type = EIGRP_DEBUG_PROBE;
	if (argv_find(argv, argc, "stub", &idx))
		type = EIGRP_DEBUG_STUB;
	if (argv_find(argv, argc, "reply", &idx))
		type = EIGRP_DEBUG_REPLY;
	if (argv_find(argv, argc, "request", &idx))
		type = EIGRP_DEBUG_REQUEST;
	if (argv_find(argv, argc, "siaquery", &idx))
		type = EIGRP_DEBUG_SIAQUERY;
	if (argv_find(argv, argc, "siareply", &idx))
		type = EIGRP_DEBUG_SIAREPLY;

	/* Default, both send and recv. */
	flag = EIGRP_DEBUG_SEND_RECV;

	/* send or recv. */
	if (argv_find(argv, argc, "send", &idx))
		flag = EIGRP_DEBUG_SEND;
	else if (argv_find(argv, argc, "reply", &idx))
		flag = EIGRP_DEBUG_RECV;

	/* detail. */
	if (argv_find(argv, argc, "detail", &idx))
		flag |= EIGRP_DEBUG_PACKET_DETAIL;

	for (i = 0; i < 11; i++)
		if (type & (0x01 << i)) {
			if (vty->node == CONFIG_NODE)
				DEBUG_PACKET_OFF(i, flag);
			else
				TERM_DEBUG_PACKET_OFF(i, flag);
		}

	return CMD_SUCCESS;
}

/* Debug node. */
static struct cmd_node eigrp_debug_node = {
	DEBUG_NODE, "", 1 /* VTYSH */
};

/* Initialize debug commands. */
void eigrp_debug_init()
{
	install_node(&eigrp_debug_node, config_write_debug);

	install_element(ENABLE_NODE, &show_debugging_eigrp_cmd);
	install_element(ENABLE_NODE, &debug_eigrp_packets_all_cmd);
	install_element(ENABLE_NODE, &no_debug_eigrp_packets_all_cmd);
	install_element(ENABLE_NODE, &debug_eigrp_transmit_cmd);
	install_element(ENABLE_NODE, &no_debug_eigrp_transmit_cmd);

	install_element(CONFIG_NODE, &show_debugging_eigrp_cmd);
	install_element(CONFIG_NODE, &debug_eigrp_packets_all_cmd);
	install_element(CONFIG_NODE, &no_debug_eigrp_packets_all_cmd);
	install_element(CONFIG_NODE, &debug_eigrp_transmit_cmd);
	install_element(CONFIG_NODE, &no_debug_eigrp_transmit_cmd);
}
