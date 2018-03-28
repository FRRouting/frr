/*
 * OSPFd dump routine (parts used by ospfclient).
 * Copyright (C) 1999, 2000 Toshiaki Takada
 *
 * This file is part of FRRouting (FRR).
 *
 * FRR is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2, or (at your option) any later version.
 *
 * FRR is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "log.h"
#include "prefix.h"

#include "ospf_dump_api.h"
#include "ospfd.h"
#include "ospf_asbr.h"
#include "ospf_lsa.h"
#include "ospf_nsm.h"
#include "ospf_ism.h"

const struct message ospf_ism_state_msg[] = {
	{ISM_DependUpon, "DependUpon"},
	{ISM_Down, "Down"},
	{ISM_Loopback, "Loopback"},
	{ISM_Waiting, "Waiting"},
	{ISM_PointToPoint, "Point-To-Point"},
	{ISM_DROther, "DROther"},
	{ISM_Backup, "Backup"},
	{ISM_DR, "DR"},
	{0}};

const struct message ospf_nsm_state_msg[] = {{NSM_DependUpon, "DependUpon"},
					     {NSM_Deleted, "Deleted"},
					     {NSM_Down, "Down"},
					     {NSM_Attempt, "Attempt"},
					     {NSM_Init, "Init"},
					     {NSM_TwoWay, "2-Way"},
					     {NSM_ExStart, "ExStart"},
					     {NSM_Exchange, "Exchange"},
					     {NSM_Loading, "Loading"},
					     {NSM_Full, "Full"},
					     {0}};

const struct message ospf_lsa_type_msg[] = {
	{OSPF_UNKNOWN_LSA, "unknown"},
	{OSPF_ROUTER_LSA, "router-LSA"},
	{OSPF_NETWORK_LSA, "network-LSA"},
	{OSPF_SUMMARY_LSA, "summary-LSA"},
	{OSPF_ASBR_SUMMARY_LSA, "summary-LSA"},
	{OSPF_AS_EXTERNAL_LSA, "AS-external-LSA"},
	{OSPF_GROUP_MEMBER_LSA, "GROUP MEMBER LSA"},
	{OSPF_AS_NSSA_LSA, "NSSA-LSA"},
	{8, "Type-8 LSA"},
	{OSPF_OPAQUE_LINK_LSA, "Link-Local Opaque-LSA"},
	{OSPF_OPAQUE_AREA_LSA, "Area-Local Opaque-LSA"},
	{OSPF_OPAQUE_AS_LSA, "AS-external Opaque-LSA"},
	{0}};

const struct message ospf_link_state_id_type_msg[] = {
	{OSPF_UNKNOWN_LSA, "(unknown)"},
	{OSPF_ROUTER_LSA, ""},
	{OSPF_NETWORK_LSA, "(address of Designated Router)"},
	{OSPF_SUMMARY_LSA, "(summary Network Number)"},
	{OSPF_ASBR_SUMMARY_LSA, "(AS Boundary Router address)"},
	{OSPF_AS_EXTERNAL_LSA, "(External Network Number)"},
	{OSPF_GROUP_MEMBER_LSA, "(Group membership information)"},
	{OSPF_AS_NSSA_LSA, "(External Network Number for NSSA)"},
	{8, "(Type-8 LSID)"},
	{OSPF_OPAQUE_LINK_LSA, "(Link-Local Opaque-Type/ID)"},
	{OSPF_OPAQUE_AREA_LSA, "(Area-Local Opaque-Type/ID)"},
	{OSPF_OPAQUE_AS_LSA, "(AS-external Opaque-Type/ID)"},
	{0}};

const struct message ospf_network_type_msg[] = {
	{OSPF_IFTYPE_NONE, "NONE"},
	{OSPF_IFTYPE_POINTOPOINT, "Point-to-Point"},
	{OSPF_IFTYPE_BROADCAST, "Broadcast"},
	{OSPF_IFTYPE_NBMA, "NBMA"},
	{OSPF_IFTYPE_POINTOMULTIPOINT, "Point-to-MultiPoint"},
	{OSPF_IFTYPE_VIRTUALLINK, "Virtual-Link"},
	{0}};

/* AuType */
const struct message ospf_auth_type_str[] = {
	{OSPF_AUTH_NULL, "Null"},
	{OSPF_AUTH_SIMPLE, "Simple"},
	{OSPF_AUTH_CRYPTOGRAPHIC, "Cryptographic"},
	{0}};

#define OSPF_OPTION_STR_MAXLEN		24

char *ospf_options_dump(uint8_t options)
{
	static char buf[OSPF_OPTION_STR_MAXLEN];

	snprintf(buf, OSPF_OPTION_STR_MAXLEN, "*|%s|%s|%s|%s|%s|%s|%s",
		 (options & OSPF_OPTION_O) ? "O" : "-",
		 (options & OSPF_OPTION_DC) ? "DC" : "-",
		 (options & OSPF_OPTION_EA) ? "EA" : "-",
		 (options & OSPF_OPTION_NP) ? "N/P" : "-",
		 (options & OSPF_OPTION_MC) ? "MC" : "-",
		 (options & OSPF_OPTION_E) ? "E" : "-",
		 (options & OSPF_OPTION_MT) ? "M/T" : "-");

	return buf;
}

void ospf_lsa_header_dump(struct lsa_header *lsah)
{
	const char *lsah_type = lookup_msg(ospf_lsa_type_msg, lsah->type, NULL);

	zlog_debug("  LSA Header");
	zlog_debug("    LS age %d", ntohs(lsah->ls_age));
	zlog_debug("    Options %d (%s)", lsah->options,
		   ospf_options_dump(lsah->options));
	zlog_debug("    LS type %d (%s)", lsah->type,
		   (lsah->type ? lsah_type : "unknown type"));
	zlog_debug("    Link State ID %s", inet_ntoa(lsah->id));
	zlog_debug("    Advertising Router %s", inet_ntoa(lsah->adv_router));
	zlog_debug("    LS sequence number 0x%lx",
		   (unsigned long)ntohl(lsah->ls_seqnum));
	zlog_debug("    LS checksum 0x%x", ntohs(lsah->checksum));
	zlog_debug("    length %d", ntohs(lsah->length));
}
