/* BGP open message handling
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
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
#include "prefix.h"
#include "stream.h"
#include "thread.h"
#include "log.h"
#include "command.h"
#include "memory.h"
#include "queue.h"
#include "filter.h"

#include "lib/json.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_memory.h"

/* BGP-4 Multiprotocol Extentions lead us to the complex world. We can
   negotiate remote peer supports extentions or not. But if
   remote-peer doesn't supports negotiation process itself.  We would
   like to do manual configuration.

   So there is many configurable point.  First of all we want set each
   peer whether we send capability negotiation to the peer or not.
   Next, if we send capability to the peer we want to set my capabilty
   inforation at each peer. */

void bgp_capability_vty_out(struct vty *vty, struct peer *peer,
			    uint8_t use_json, json_object *json_neigh)
{
	char *pnt;
	char *end;
	struct capability_mp_data mpc;
	struct capability_header *hdr;
	json_object *json_cap = NULL;

	if (use_json)
		json_cap = json_object_new_object();

	pnt = peer->notify.data;
	end = pnt + peer->notify.length;

	while (pnt < end) {
		if (pnt + sizeof(struct capability_mp_data) + 2 > end)
			return;

		hdr = (struct capability_header *)pnt;
		if (pnt + hdr->length + 2 > end)
			return;

		memcpy(&mpc, pnt + 2, sizeof(struct capability_mp_data));

		if (hdr->code == CAPABILITY_CODE_MP) {
			afi_t afi;
			safi_t safi;

			(void)bgp_map_afi_safi_iana2int(ntohs(mpc.afi),
							mpc.safi, &afi, &safi);

			if (use_json) {
				switch (afi) {
				case AFI_IP:
					json_object_string_add(
						json_cap,
						"capabilityErrorMultiProtocolAfi",
						"IPv4");
					break;
				case AFI_IP6:
					json_object_string_add(
						json_cap,
						"capabilityErrorMultiProtocolAfi",
						"IPv6");
					break;
				case AFI_L2VPN:
					json_object_string_add(
						json_cap,
						"capabilityErrorMultiProtocolAfi",
						"L2VPN");
					break;
				default:
					json_object_int_add(
						json_cap,
						"capabilityErrorMultiProtocolAfiUnknown",
						ntohs(mpc.afi));
					break;
				}
				switch (safi) {
				case SAFI_UNICAST:
					json_object_string_add(
						json_cap,
						"capabilityErrorMultiProtocolSafi",
						"unicast");
					break;
				case SAFI_MULTICAST:
					json_object_string_add(
						json_cap,
						"capabilityErrorMultiProtocolSafi",
						"multicast");
					break;
				case SAFI_LABELED_UNICAST:
					json_object_string_add(
						json_cap,
						"capabilityErrorMultiProtocolSafi",
						"labeled-unicast");
					break;
				case SAFI_MPLS_VPN:
					json_object_string_add(
						json_cap,
						"capabilityErrorMultiProtocolSafi",
						"MPLS-labeled VPN");
					break;
				case SAFI_ENCAP:
					json_object_string_add(
						json_cap,
						"capabilityErrorMultiProtocolSafi",
						"encap");
					break;
				case SAFI_EVPN:
					json_object_string_add(
						json_cap,
						"capabilityErrorMultiProtocolSafi",
						"EVPN");
					break;
				case SAFI_FLOWSPEC:
					json_object_string_add(
						json_cap,
						"capabilityErrorMultiProtocolSafi",
						"flowspec");
					break;
				default:
					json_object_int_add(
						json_cap,
						"capabilityErrorMultiProtocolSafiUnknown",
						mpc.safi);
					break;
				}
			} else {
				vty_out(vty,
					"  Capability error for: Multi protocol ");
				switch (afi) {
				case AFI_IP:
					vty_out(vty, "AFI IPv4, ");
					break;
				case AFI_IP6:
					vty_out(vty, "AFI IPv6, ");
					break;
				case AFI_L2VPN:
					vty_out(vty, "AFI L2VPN, ");
					break;
				default:
					vty_out(vty, "AFI Unknown %d, ",
						ntohs(mpc.afi));
					break;
				}
				switch (safi) {
				case SAFI_UNICAST:
					vty_out(vty, "SAFI Unicast");
					break;
				case SAFI_MULTICAST:
					vty_out(vty, "SAFI Multicast");
					break;
				case SAFI_LABELED_UNICAST:
					vty_out(vty, "SAFI Labeled-unicast");
					break;
				case SAFI_MPLS_VPN:
					vty_out(vty, "SAFI MPLS-labeled VPN");
					break;
				case SAFI_ENCAP:
					vty_out(vty, "SAFI ENCAP");
					break;
				case SAFI_FLOWSPEC:
					vty_out(vty, "SAFI FLOWSPEC");
					break;
				case SAFI_EVPN:
					vty_out(vty, "SAFI EVPN");
					break;
				default:
					vty_out(vty, "SAFI Unknown %d ",
						mpc.safi);
					break;
				}
				vty_out(vty, "\n");
			}
		} else if (hdr->code >= 128) {
			if (use_json)
				json_object_int_add(
					json_cap,
					"capabilityErrorVendorSpecificCapabilityCode",
					hdr->code);
			else
				vty_out(vty,
					"  Capability error: vendor specific capability code %d",
					hdr->code);
		} else {
			if (use_json)
				json_object_int_add(
					json_cap,
					"capabilityErrorUnknownCapabilityCode",
					hdr->code);
			else
				vty_out(vty,
					"  Capability error: unknown capability code %d",
					hdr->code);
		}
		pnt += hdr->length + 2;
	}
	if (use_json)
		json_object_object_add(json_neigh, "capabilityErrors",
				       json_cap);
}

static void bgp_capability_mp_data(struct stream *s,
				   struct capability_mp_data *mpc)
{
	mpc->afi = stream_getw(s);
	mpc->reserved = stream_getc(s);
	mpc->safi = stream_getc(s);
}

/* Set negotiated capability value. */
static int bgp_capability_mp(struct peer *peer, struct capability_header *hdr)
{
	struct capability_mp_data mpc;
	struct stream *s = BGP_INPUT(peer);
	afi_t afi;
	safi_t safi;

	/* Verify length is 4 */
	if (hdr->length != 4) {
		zlog_warn(
			"MP Cap: Received invalid length %d, non-multiple of 4",
			hdr->length);
		return -1;
	}

	bgp_capability_mp_data(s, &mpc);

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s OPEN has MP_EXT CAP for afi/safi: %u/%u",
			   peer->host, mpc.afi, mpc.safi);

	/* Convert AFI, SAFI to internal values, check. */
	if (bgp_map_afi_safi_iana2int(mpc.afi, mpc.safi, &afi, &safi))
		return -1;

	/* Now safi remapped, and afi/safi are valid array indices */
	peer->afc_recv[afi][safi] = 1;

	if (peer->afc[afi][safi])
		peer->afc_nego[afi][safi] = 1;
	else
		return -1;

	return 0;
}

static void bgp_capability_orf_not_support(struct peer *peer, iana_afi_t afi,
					   iana_safi_t safi, uint8_t type,
					   uint8_t mode)
{
	if (bgp_debug_neighbor_events(peer))
		zlog_debug(
			"%s Addr-family %d/%d has ORF type/mode %d/%d not supported",
			peer->host, afi, safi, type, mode);
}

static const struct message orf_type_str[] = {
	{ORF_TYPE_PREFIX, "Prefixlist"},
	{ORF_TYPE_PREFIX_OLD, "Prefixlist (old)"},
	{0}};

static const struct message orf_mode_str[] = {{ORF_MODE_RECEIVE, "Receive"},
					      {ORF_MODE_SEND, "Send"},
					      {ORF_MODE_BOTH, "Both"},
					      {0}};

static int bgp_capability_orf_entry(struct peer *peer,
				    struct capability_header *hdr)
{
	struct stream *s = BGP_INPUT(peer);
	struct capability_mp_data mpc;
	uint8_t num;
	iana_afi_t pkt_afi;
	afi_t afi;
	iana_safi_t pkt_safi;
	safi_t safi;
	uint8_t type;
	uint8_t mode;
	uint16_t sm_cap = 0; /* capability send-mode receive */
	uint16_t rm_cap = 0; /* capability receive-mode receive */
	int i;

	/* ORF Entry header */
	bgp_capability_mp_data(s, &mpc);
	num = stream_getc(s);
	pkt_afi = mpc.afi;
	pkt_safi = mpc.safi;

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s ORF Cap entry for afi/safi: %u/%u", peer->host,
			   mpc.afi, mpc.safi);

	/* Convert AFI, SAFI to internal values, check. */
	if (bgp_map_afi_safi_iana2int(pkt_afi, pkt_safi, &afi, &safi)) {
		zlog_info(
			"%s Addr-family %d/%d not supported."
			" Ignoring the ORF capability",
			peer->host, pkt_afi, pkt_safi);
		return 0;
	}

	mpc.afi = pkt_afi;
	mpc.safi = safi;

	/* validate number field */
	if (CAPABILITY_CODE_ORF_LEN + (num * 2) > hdr->length) {
		zlog_info(
			"%s ORF Capability entry length error,"
			" Cap length %u, num %u",
			peer->host, hdr->length, num);
		bgp_notify_send(peer, BGP_NOTIFY_OPEN_ERR,
				BGP_NOTIFY_OPEN_MALFORMED_ATTR);
		return -1;
	}

	for (i = 0; i < num; i++) {
		type = stream_getc(s);
		mode = stream_getc(s);

		/* ORF Mode error check */
		switch (mode) {
		case ORF_MODE_BOTH:
		case ORF_MODE_SEND:
		case ORF_MODE_RECEIVE:
			break;
		default:
			bgp_capability_orf_not_support(peer, pkt_afi, pkt_safi,
						       type, mode);
			continue;
		}
		/* ORF Type and afi/safi error checks */
		/* capcode versus type */
		switch (hdr->code) {
		case CAPABILITY_CODE_ORF:
			switch (type) {
			case ORF_TYPE_PREFIX:
				break;
			default:
				bgp_capability_orf_not_support(
					peer, pkt_afi, pkt_safi, type, mode);
				continue;
			}
			break;
		case CAPABILITY_CODE_ORF_OLD:
			switch (type) {
			case ORF_TYPE_PREFIX_OLD:
				break;
			default:
				bgp_capability_orf_not_support(
					peer, pkt_afi, pkt_safi, type, mode);
				continue;
			}
			break;
		default:
			bgp_capability_orf_not_support(peer, pkt_afi, pkt_safi,
						       type, mode);
			continue;
		}

		/* AFI vs SAFI */
		if (!((afi == AFI_IP && safi == SAFI_UNICAST)
		      || (afi == AFI_IP && safi == SAFI_MULTICAST)
		      || (afi == AFI_IP6 && safi == SAFI_UNICAST))) {
			bgp_capability_orf_not_support(peer, pkt_afi, pkt_safi,
						       type, mode);
			continue;
		}

		if (bgp_debug_neighbor_events(peer))
			zlog_debug(
				"%s OPEN has %s ORF capability"
				" as %s for afi/safi: %d/%d",
				peer->host,
				lookup_msg(orf_type_str, type, NULL),
				lookup_msg(orf_mode_str, mode, NULL), pkt_afi,
				pkt_safi);

		if (hdr->code == CAPABILITY_CODE_ORF) {
			sm_cap = PEER_CAP_ORF_PREFIX_SM_RCV;
			rm_cap = PEER_CAP_ORF_PREFIX_RM_RCV;
		} else if (hdr->code == CAPABILITY_CODE_ORF_OLD) {
			sm_cap = PEER_CAP_ORF_PREFIX_SM_OLD_RCV;
			rm_cap = PEER_CAP_ORF_PREFIX_RM_OLD_RCV;
		} else {
			bgp_capability_orf_not_support(peer, pkt_afi, pkt_safi,
						       type, mode);
			continue;
		}

		switch (mode) {
		case ORF_MODE_BOTH:
			SET_FLAG(peer->af_cap[afi][safi], sm_cap);
			SET_FLAG(peer->af_cap[afi][safi], rm_cap);
			break;
		case ORF_MODE_SEND:
			SET_FLAG(peer->af_cap[afi][safi], sm_cap);
			break;
		case ORF_MODE_RECEIVE:
			SET_FLAG(peer->af_cap[afi][safi], rm_cap);
			break;
		}
	}
	return 0;
}

static int bgp_capability_restart(struct peer *peer,
				  struct capability_header *caphdr)
{
	struct stream *s = BGP_INPUT(peer);
	uint16_t restart_flag_time;
	size_t end = stream_get_getp(s) + caphdr->length;

	/* Verify length is a multiple of 4 */
	if ((caphdr->length - 2) % 4) {
		zlog_warn(
			"Restart Cap: Received invalid length %d, non-multiple of 4",
			caphdr->length);
		return -1;
	}

	SET_FLAG(peer->cap, PEER_CAP_RESTART_RCV);
	restart_flag_time = stream_getw(s);
	if (CHECK_FLAG(restart_flag_time, RESTART_R_BIT))
		SET_FLAG(peer->cap, PEER_CAP_RESTART_BIT_RCV);

	UNSET_FLAG(restart_flag_time, 0xF000);
	peer->v_gr_restart = restart_flag_time;

	if (bgp_debug_neighbor_events(peer)) {
		zlog_debug("%s OPEN has Graceful Restart capability",
			   peer->host);
		zlog_debug("%s Peer has%srestarted. Restart Time : %d",
			   peer->host,
			   CHECK_FLAG(peer->cap, PEER_CAP_RESTART_BIT_RCV)
				   ? " "
				   : " not ",
			   peer->v_gr_restart);
	}

	while (stream_get_getp(s) + 4 <= end) {
		afi_t afi;
		safi_t safi;
		iana_afi_t pkt_afi = stream_getw(s);
		iana_safi_t pkt_safi = stream_getc(s);
		uint8_t flag = stream_getc(s);

		/* Convert AFI, SAFI to internal values, check. */
		if (bgp_map_afi_safi_iana2int(pkt_afi, pkt_safi, &afi, &safi)) {
			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%s Addr-family %d/%d(afi/safi) not supported."
					" Ignore the Graceful Restart capability for this AFI/SAFI",
					peer->host, pkt_afi, pkt_safi);
		} else if (!peer->afc[afi][safi]) {
			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%s Addr-family %d/%d(afi/safi) not enabled."
					" Ignore the Graceful Restart capability",
					peer->host, pkt_afi, pkt_safi);
		} else {
			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%s Address family %s is%spreserved",
					peer->host, afi_safi_print(afi, safi),
					CHECK_FLAG(
						peer->af_cap[afi][safi],
						PEER_CAP_RESTART_AF_PRESERVE_RCV)
						? " "
						: " not ");

			SET_FLAG(peer->af_cap[afi][safi],
				 PEER_CAP_RESTART_AF_RCV);
			if (CHECK_FLAG(flag, RESTART_F_BIT))
				SET_FLAG(peer->af_cap[afi][safi],
					 PEER_CAP_RESTART_AF_PRESERVE_RCV);
		}
	}
	return 0;
}

/* Unlike other capability parsing routines, this one returns 0 on error */
static as_t bgp_capability_as4(struct peer *peer, struct capability_header *hdr)
{
	SET_FLAG(peer->cap, PEER_CAP_AS4_RCV);

	if (hdr->length != CAPABILITY_CODE_AS4_LEN) {
		zlog_err("%s AS4 capability has incorrect data length %d",
			 peer->host, hdr->length);
		return 0;
	}

	as_t as4 = stream_getl(BGP_INPUT(peer));

	if (BGP_DEBUG(as4, AS4))
		zlog_debug(
			"%s [AS4] about to set cap PEER_CAP_AS4_RCV, got as4 %u",
			peer->host, as4);
	return as4;
}

static int bgp_capability_addpath(struct peer *peer,
				  struct capability_header *hdr)
{
	struct stream *s = BGP_INPUT(peer);
	size_t end = stream_get_getp(s) + hdr->length;

	SET_FLAG(peer->cap, PEER_CAP_ADDPATH_RCV);

	/* Verify length is a multiple of 4 */
	if (hdr->length % 4) {
		zlog_warn(
			"Add Path: Received invalid length %d, non-multiple of 4",
			hdr->length);
		return -1;
	}

	while (stream_get_getp(s) + 4 <= end) {
		afi_t afi;
		safi_t safi;
		iana_afi_t pkt_afi = stream_getw(s);
		iana_safi_t pkt_safi = stream_getc(s);
		uint8_t send_receive = stream_getc(s);

		if (bgp_debug_neighbor_events(peer))
			zlog_debug(
				"%s OPEN has AddPath CAP for afi/safi: %u/%u%s%s",
				peer->host, pkt_afi, pkt_safi,
				(send_receive & BGP_ADDPATH_RX) ? ", receive"
								: "",
				(send_receive & BGP_ADDPATH_TX) ? ", transmit"
								: "");

		/* Convert AFI, SAFI to internal values, check. */
		if (bgp_map_afi_safi_iana2int(pkt_afi, pkt_safi, &afi, &safi)) {
			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%s Addr-family %d/%d(afi/safi) not supported."
					" Ignore the Addpath Attribute for this AFI/SAFI",
					peer->host, pkt_afi, pkt_safi);
			continue;
		} else if (!peer->afc[afi][safi]) {
			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%s Addr-family %d/%d(afi/safi) not enabled."
					" Ignore the AddPath capability for this AFI/SAFI",
					peer->host, pkt_afi, pkt_safi);
			continue;
		}

		if (send_receive & BGP_ADDPATH_RX)
			SET_FLAG(peer->af_cap[afi][safi],
				 PEER_CAP_ADDPATH_AF_RX_RCV);

		if (send_receive & BGP_ADDPATH_TX)
			SET_FLAG(peer->af_cap[afi][safi],
				 PEER_CAP_ADDPATH_AF_TX_RCV);
	}

	return 0;
}

static int bgp_capability_enhe(struct peer *peer, struct capability_header *hdr)
{
	struct stream *s = BGP_INPUT(peer);
	size_t end = stream_get_getp(s) + hdr->length;

	/* Verify length is a multiple of 4 */
	if (hdr->length % 6) {
		zlog_warn(
			"Extended NH: Received invalid length %d, non-multiple of 6",
			hdr->length);
		return -1;
	}

	while (stream_get_getp(s) + 6 <= end) {
		iana_afi_t pkt_afi = stream_getw(s);
		afi_t afi;
		iana_safi_t pkt_safi = stream_getw(s);
		safi_t safi;
		iana_afi_t pkt_nh_afi = stream_getw(s);
		afi_t nh_afi;

		if (bgp_debug_neighbor_events(peer))
			zlog_debug(
				"%s Received with afi/safi/next-hop afi: %u/%u/%u",
				peer->host, pkt_afi, pkt_safi, pkt_nh_afi);

		/* Convert AFI, SAFI to internal values, check. */
		if (bgp_map_afi_safi_iana2int(pkt_afi, pkt_safi, &afi, &safi)) {
			if (bgp_debug_neighbor_events(peer))
				zlog_debug(
					"%s Addr-family %d/%d(afi/safi) not supported."
					" Ignore the ENHE Attribute for this AFI/SAFI",
					peer->host, pkt_afi, pkt_safi);
			continue;
		}

		/* RFC 5549 specifies use of this capability only for IPv4 AFI,
		 * with
		 * the Nexthop AFI being IPv6. A future spec may introduce other
		 * possibilities, so we ignore other values with a log. Also,
		 * only
		 * SAFI_UNICAST and SAFI_LABELED_UNICAST are currently supported
		 * (and expected).
		 */
		nh_afi = afi_iana2int(pkt_nh_afi);

		if (afi != AFI_IP || nh_afi != AFI_IP6
		    || !(safi == SAFI_UNICAST
			 || safi == SAFI_LABELED_UNICAST)) {
			zlog_warn(
				"%s Unexpected afi/safi/next-hop afi: %u/%u/%u "
				"in Extended Next-hop capability, ignoring",
				peer->host, pkt_afi, pkt_safi, pkt_nh_afi);
			continue;
		}

		SET_FLAG(peer->af_cap[afi][safi], PEER_CAP_ENHE_AF_RCV);

		if (CHECK_FLAG(peer->af_cap[afi][safi], PEER_CAP_ENHE_AF_ADV))
			SET_FLAG(peer->af_cap[afi][safi],
				 PEER_CAP_ENHE_AF_NEGO);
	}

	SET_FLAG(peer->cap, PEER_CAP_ENHE_RCV);

	return 0;
}

static int bgp_capability_hostname(struct peer *peer,
				   struct capability_header *hdr)
{
	struct stream *s = BGP_INPUT(peer);
	char str[BGP_MAX_HOSTNAME + 1];
	size_t end = stream_get_getp(s) + hdr->length;
	uint8_t len;

	SET_FLAG(peer->cap, PEER_CAP_HOSTNAME_RCV);

	len = stream_getc(s);
	if (stream_get_getp(s) + len > end) {
		zlog_warn(
			"%s: Received malformed hostname capability from peer %s",
			__FUNCTION__, peer->host);
		return -1;
	}

	if (len > BGP_MAX_HOSTNAME) {
		stream_get(str, s, BGP_MAX_HOSTNAME);
		stream_forward_getp(s, len - BGP_MAX_HOSTNAME);
		len = BGP_MAX_HOSTNAME; /* to set the '\0' below */
	} else if (len)
		stream_get(str, s, len);

	if (len) {
		str[len] = '\0';

		if (peer->hostname != NULL) {
			XFREE(MTYPE_BGP_PEER_HOST, peer->hostname);
			peer->hostname = NULL;
		}

		if (peer->domainname != NULL) {
			XFREE(MTYPE_BGP_PEER_HOST, peer->domainname);
			peer->domainname = NULL;
		}

		peer->hostname = XSTRDUP(MTYPE_BGP_PEER_HOST, str);
	}

	if (stream_get_getp(s) + 1 > end) {
		zlog_warn(
			"%s: Received invalid domain name len (hostname capability) from peer %s",
			__FUNCTION__, peer->host);
		return -1;
	}

	len = stream_getc(s);
	if (stream_get_getp(s) + len > end) {
		zlog_warn(
			"%s: Received runt domain name (hostname capability) from peer %s",
			__FUNCTION__, peer->host);
		return -1;
	}

	if (len > BGP_MAX_HOSTNAME) {
		stream_get(str, s, BGP_MAX_HOSTNAME);
		stream_forward_getp(s, len - BGP_MAX_HOSTNAME);
		len = BGP_MAX_HOSTNAME; /* to set the '\0' below */
	} else if (len)
		stream_get(str, s, len);

	if (len) {
		str[len] = '\0';
		peer->domainname = XSTRDUP(MTYPE_BGP_PEER_HOST, str);
	}

	if (bgp_debug_neighbor_events(peer)) {
		zlog_debug("%s received hostname %s, domainname %s", peer->host,
			   peer->hostname, peer->domainname);
	}

	return 0;
}

static const struct message capcode_str[] = {
	{CAPABILITY_CODE_MP, "MultiProtocol Extensions"},
	{CAPABILITY_CODE_REFRESH, "Route Refresh"},
	{CAPABILITY_CODE_ORF, "Cooperative Route Filtering"},
	{CAPABILITY_CODE_RESTART, "Graceful Restart"},
	{CAPABILITY_CODE_AS4, "4-octet AS number"},
	{CAPABILITY_CODE_ADDPATH, "AddPath"},
	{CAPABILITY_CODE_DYNAMIC, "Dynamic"},
	{CAPABILITY_CODE_ENHE, "Extended Next Hop Encoding"},
	{CAPABILITY_CODE_DYNAMIC_OLD, "Dynamic (Old)"},
	{CAPABILITY_CODE_REFRESH_OLD, "Route Refresh (Old)"},
	{CAPABILITY_CODE_ORF_OLD, "ORF (Old)"},
	{CAPABILITY_CODE_FQDN, "FQDN"},
	{0}};

/* Minimum sizes for length field of each cap (so not inc. the header) */
static const size_t cap_minsizes[] = {
		[CAPABILITY_CODE_MP] = CAPABILITY_CODE_MP_LEN,
		[CAPABILITY_CODE_REFRESH] = CAPABILITY_CODE_REFRESH_LEN,
		[CAPABILITY_CODE_ORF] = CAPABILITY_CODE_ORF_LEN,
		[CAPABILITY_CODE_RESTART] = CAPABILITY_CODE_RESTART_LEN,
		[CAPABILITY_CODE_AS4] = CAPABILITY_CODE_AS4_LEN,
		[CAPABILITY_CODE_ADDPATH] = CAPABILITY_CODE_ADDPATH_LEN,
		[CAPABILITY_CODE_DYNAMIC] = CAPABILITY_CODE_DYNAMIC_LEN,
		[CAPABILITY_CODE_DYNAMIC_OLD] = CAPABILITY_CODE_DYNAMIC_LEN,
		[CAPABILITY_CODE_ENHE] = CAPABILITY_CODE_ENHE_LEN,
		[CAPABILITY_CODE_REFRESH_OLD] = CAPABILITY_CODE_REFRESH_LEN,
		[CAPABILITY_CODE_ORF_OLD] = CAPABILITY_CODE_ORF_LEN,
		[CAPABILITY_CODE_FQDN] = CAPABILITY_CODE_MIN_FQDN_LEN,
};

/* value the capability must be a multiple of.
 * 0-data capabilities won't be checked against this.
 * Other capabilities whose data doesn't fall on convenient boundaries for this
 * table should be set to 1.
 */
static const size_t cap_modsizes[] = {
		[CAPABILITY_CODE_MP] = 4,
		[CAPABILITY_CODE_REFRESH] = 1,
		[CAPABILITY_CODE_ORF] = 1,
		[CAPABILITY_CODE_RESTART] = 1,
		[CAPABILITY_CODE_AS4] = 4,
		[CAPABILITY_CODE_ADDPATH] = 4,
		[CAPABILITY_CODE_DYNAMIC] = 1,
		[CAPABILITY_CODE_DYNAMIC_OLD] = 1,
		[CAPABILITY_CODE_ENHE] = 6,
		[CAPABILITY_CODE_REFRESH_OLD] = 1,
		[CAPABILITY_CODE_ORF_OLD] = 1,
		[CAPABILITY_CODE_FQDN] = 1,
};

/**
 * Parse given capability.
 * XXX: This is reading into a stream, but not using stream API
 *
 * @param[out] mp_capability Set to 1 on return iff one or more Multiprotocol
 *                           capabilities were encountered.
 */
static int bgp_capability_parse(struct peer *peer, size_t length,
				int *mp_capability, uint8_t **error)
{
	int ret;
	struct stream *s = BGP_INPUT(peer);
	size_t end = stream_get_getp(s) + length;

	assert(STREAM_READABLE(s) >= length);

	while (stream_get_getp(s) < end) {
		size_t start;
		uint8_t *sp = stream_pnt(s);
		struct capability_header caphdr;

		ret = 0;
		/* We need at least capability code and capability length. */
		if (stream_get_getp(s) + 2 > end) {
			zlog_info("%s Capability length error (< header)",
				  peer->host);
			bgp_notify_send(peer, BGP_NOTIFY_OPEN_ERR,
					BGP_NOTIFY_OPEN_MALFORMED_ATTR);
			return -1;
		}

		caphdr.code = stream_getc(s);
		caphdr.length = stream_getc(s);
		start = stream_get_getp(s);

		/* Capability length check sanity check. */
		if (start + caphdr.length > end) {
			zlog_info("%s Capability length error (< length)",
				  peer->host);
			bgp_notify_send(peer, BGP_NOTIFY_OPEN_ERR,
					BGP_NOTIFY_OPEN_MALFORMED_ATTR);
			return -1;
		}

		if (bgp_debug_neighbor_events(peer))
			zlog_debug("%s OPEN has %s capability (%u), length %u",
				   peer->host,
				   lookup_msg(capcode_str, caphdr.code, NULL),
				   caphdr.code, caphdr.length);

		/* Length sanity check, type-specific, for known capabilities */
		switch (caphdr.code) {
		case CAPABILITY_CODE_MP:
		case CAPABILITY_CODE_REFRESH:
		case CAPABILITY_CODE_REFRESH_OLD:
		case CAPABILITY_CODE_ORF:
		case CAPABILITY_CODE_ORF_OLD:
		case CAPABILITY_CODE_RESTART:
		case CAPABILITY_CODE_AS4:
		case CAPABILITY_CODE_ADDPATH:
		case CAPABILITY_CODE_DYNAMIC:
		case CAPABILITY_CODE_DYNAMIC_OLD:
		case CAPABILITY_CODE_ENHE:
		case CAPABILITY_CODE_FQDN:
			/* Check length. */
			if (caphdr.length < cap_minsizes[caphdr.code]) {
				zlog_info(
					"%s %s Capability length error: got %u,"
					" expected at least %u",
					peer->host,
					lookup_msg(capcode_str, caphdr.code,
						   NULL),
					caphdr.length,
					(unsigned)cap_minsizes[caphdr.code]);
				bgp_notify_send(peer, BGP_NOTIFY_OPEN_ERR,
						BGP_NOTIFY_OPEN_MALFORMED_ATTR);
				return -1;
			}
			if (caphdr.length
			    && caphdr.length % cap_modsizes[caphdr.code] != 0) {
				zlog_info(
					"%s %s Capability length error: got %u,"
					" expected a multiple of %u",
					peer->host,
					lookup_msg(capcode_str, caphdr.code,
						   NULL),
					caphdr.length,
					(unsigned)cap_modsizes[caphdr.code]);
				bgp_notify_send(peer, BGP_NOTIFY_OPEN_ERR,
						BGP_NOTIFY_OPEN_MALFORMED_ATTR);
				return -1;
			}
		/* we deliberately ignore unknown codes, see below */
		default:
			break;
		}

		switch (caphdr.code) {
		case CAPABILITY_CODE_MP: {
			*mp_capability = 1;

			/* Ignore capability when override-capability is set. */
			if (!CHECK_FLAG(peer->flags,
					PEER_FLAG_OVERRIDE_CAPABILITY)) {
				/* Set negotiated value. */
				ret = bgp_capability_mp(peer, &caphdr);

				/* Unsupported Capability. */
				if (ret < 0) {
					/* Store return data. */
					memcpy(*error, sp, caphdr.length + 2);
					*error += caphdr.length + 2;
				}
				ret = 0; /* Don't return error for this */
			}
		} break;
		case CAPABILITY_CODE_REFRESH:
		case CAPABILITY_CODE_REFRESH_OLD: {
			/* BGP refresh capability */
			if (caphdr.code == CAPABILITY_CODE_REFRESH_OLD)
				SET_FLAG(peer->cap, PEER_CAP_REFRESH_OLD_RCV);
			else
				SET_FLAG(peer->cap, PEER_CAP_REFRESH_NEW_RCV);
		} break;
		case CAPABILITY_CODE_ORF:
		case CAPABILITY_CODE_ORF_OLD:
			ret = bgp_capability_orf_entry(peer, &caphdr);
			break;
		case CAPABILITY_CODE_RESTART:
			ret = bgp_capability_restart(peer, &caphdr);
			break;
		case CAPABILITY_CODE_DYNAMIC:
		case CAPABILITY_CODE_DYNAMIC_OLD:
			SET_FLAG(peer->cap, PEER_CAP_DYNAMIC_RCV);
			break;
		case CAPABILITY_CODE_AS4:
			/* Already handled as a special-case parsing of the
			 * capabilities
			 * at the beginning of OPEN processing. So we care not a
			 * jot
			 * for the value really, only error case.
			 */
			if (!bgp_capability_as4(peer, &caphdr))
				ret = -1;
			break;
		case CAPABILITY_CODE_ADDPATH:
			ret = bgp_capability_addpath(peer, &caphdr);
			break;
		case CAPABILITY_CODE_ENHE:
			ret = bgp_capability_enhe(peer, &caphdr);
			break;
		case CAPABILITY_CODE_FQDN:
			ret = bgp_capability_hostname(peer, &caphdr);
			break;
		default:
			if (caphdr.code > 128) {
				/* We don't send Notification for unknown vendor
				   specific
				   capabilities.  It seems reasonable for now...
				   */
				zlog_warn("%s Vendor specific capability %d",
					  peer->host, caphdr.code);
			} else {
				zlog_warn(
					"%s unrecognized capability code: %d - ignored",
					peer->host, caphdr.code);
				memcpy(*error, sp, caphdr.length + 2);
				*error += caphdr.length + 2;
			}
		}

		if (ret < 0) {
			bgp_notify_send(peer, BGP_NOTIFY_OPEN_ERR,
					BGP_NOTIFY_OPEN_MALFORMED_ATTR);
			return -1;
		}
		if (stream_get_getp(s) != (start + caphdr.length)) {
			if (stream_get_getp(s) > (start + caphdr.length))
				zlog_warn(
					"%s Cap-parser for %s read past cap-length, %u!",
					peer->host,
					lookup_msg(capcode_str, caphdr.code,
						   NULL),
					caphdr.length);
			stream_set_getp(s, start + caphdr.length);
		}
	}
	return 0;
}

static int bgp_auth_parse(struct peer *peer, size_t length)
{
	bgp_notify_send(peer, BGP_NOTIFY_OPEN_ERR,
			BGP_NOTIFY_OPEN_AUTH_FAILURE);
	return -1;
}

static int strict_capability_same(struct peer *peer)
{
	int i, j;

	for (i = AFI_IP; i < AFI_MAX; i++)
		for (j = SAFI_UNICAST; j < SAFI_MAX; j++)
			if (peer->afc[i][j] != peer->afc_nego[i][j])
				return 0;
	return 1;
}

/* peek into option, stores ASN to *as4 if the AS4 capability was found.
 * Returns  0 if no as4 found, as4cap value otherwise.
 */
as_t peek_for_as4_capability(struct peer *peer, uint8_t length)
{
	struct stream *s = BGP_INPUT(peer);
	size_t orig_getp = stream_get_getp(s);
	size_t end = orig_getp + length;
	as_t as4 = 0;

	if (BGP_DEBUG(as4, AS4))
		zlog_info(
			"%s [AS4] rcv OPEN w/ OPTION parameter len: %u,"
			" peeking for as4",
			peer->host, length);
	/* the error cases we DONT handle, we ONLY try to read as4 out of
	 * correctly formatted options.
	 */
	while (stream_get_getp(s) < end) {
		uint8_t opt_type;
		uint8_t opt_length;

		/* Check the length. */
		if (stream_get_getp(s) + 2 > end)
			goto end;

		/* Fetch option type and length. */
		opt_type = stream_getc(s);
		opt_length = stream_getc(s);

		/* Option length check. */
		if (stream_get_getp(s) + opt_length > end)
			goto end;

		if (opt_type == BGP_OPEN_OPT_CAP) {
			unsigned long capd_start = stream_get_getp(s);
			unsigned long capd_end = capd_start + opt_length;

			assert(capd_end <= end);

			while (stream_get_getp(s) < capd_end) {
				struct capability_header hdr;

				if (stream_get_getp(s) + 2 > capd_end)
					goto end;

				hdr.code = stream_getc(s);
				hdr.length = stream_getc(s);

				if ((stream_get_getp(s) + hdr.length)
				    > capd_end)
					goto end;

				if (hdr.code == CAPABILITY_CODE_AS4) {
					if (BGP_DEBUG(as4, AS4))
						zlog_info(
							"[AS4] found AS4 capability, about to parse");
					as4 = bgp_capability_as4(peer, &hdr);

					goto end;
				}
				stream_forward_getp(s, hdr.length);
			}
		}
	}

end:
	stream_set_getp(s, orig_getp);
	return as4;
}

/**
 * Parse open option.
 *
 * @param[out] mp_capability @see bgp_capability_parse() for semantics.
 */
int bgp_open_option_parse(struct peer *peer, uint8_t length, int *mp_capability)
{
	int ret = 0;
	uint8_t *error;
	uint8_t error_data[BGP_MAX_PACKET_SIZE];
	struct stream *s = BGP_INPUT(peer);
	size_t end = stream_get_getp(s) + length;

	error = error_data;

	if (bgp_debug_neighbor_events(peer))
		zlog_debug("%s rcv OPEN w/ OPTION parameter len: %u",
			   peer->host, length);

	while (stream_get_getp(s) < end) {
		uint8_t opt_type;
		uint8_t opt_length;

		/* Must have at least an OPEN option header */
		if (STREAM_READABLE(s) < 2) {
			zlog_info("%s Option length error", peer->host);
			bgp_notify_send(peer, BGP_NOTIFY_OPEN_ERR,
					BGP_NOTIFY_OPEN_MALFORMED_ATTR);
			return -1;
		}

		/* Fetch option type and length. */
		opt_type = stream_getc(s);
		opt_length = stream_getc(s);

		/* Option length check. */
		if (STREAM_READABLE(s) < opt_length) {
			zlog_info("%s Option length error", peer->host);
			bgp_notify_send(peer, BGP_NOTIFY_OPEN_ERR,
					BGP_NOTIFY_OPEN_MALFORMED_ATTR);
			return -1;
		}

		if (bgp_debug_neighbor_events(peer))
			zlog_debug(
				"%s rcvd OPEN w/ optional parameter type %u (%s) len %u",
				peer->host, opt_type,
				opt_type == BGP_OPEN_OPT_AUTH
					? "Authentication"
					: opt_type == BGP_OPEN_OPT_CAP
						  ? "Capability"
						  : "Unknown",
				opt_length);

		switch (opt_type) {
		case BGP_OPEN_OPT_AUTH:
			ret = bgp_auth_parse(peer, opt_length);
			break;
		case BGP_OPEN_OPT_CAP:
			ret = bgp_capability_parse(peer, opt_length,
						   mp_capability, &error);
			break;
		default:
			bgp_notify_send(peer, BGP_NOTIFY_OPEN_ERR,
					BGP_NOTIFY_OPEN_UNSUP_PARAM);
			ret = -1;
			break;
		}

		/* Parse error.  To accumulate all unsupported capability codes,
		   bgp_capability_parse does not return -1 when encounter
		   unsupported capability code.  To detect that, please check
		   error and erro_data pointer, like below.  */
		if (ret < 0)
			return -1;
	}

	/* All OPEN option is parsed.  Check capability when strict compare
	   flag is enabled.*/
	if (CHECK_FLAG(peer->flags, PEER_FLAG_STRICT_CAP_MATCH)) {
		/* If Unsupported Capability exists. */
		if (error != error_data) {
			bgp_notify_send_with_data(peer, BGP_NOTIFY_OPEN_ERR,
						  BGP_NOTIFY_OPEN_UNSUP_CAPBL,
						  error_data,
						  error - error_data);
			return -1;
		}

		/* Check local capability does not negotiated with remote
		   peer. */
		if (!strict_capability_same(peer)) {
			bgp_notify_send(peer, BGP_NOTIFY_OPEN_ERR,
					BGP_NOTIFY_OPEN_UNSUP_CAPBL);
			return -1;
		}
	}

	/* Check there are no common AFI/SAFIs and send Unsupported Capability
	   error. */
	if (*mp_capability
	    && !CHECK_FLAG(peer->flags, PEER_FLAG_OVERRIDE_CAPABILITY)) {
		if (!peer->afc_nego[AFI_IP][SAFI_UNICAST]
		    && !peer->afc_nego[AFI_IP][SAFI_MULTICAST]
		    && !peer->afc_nego[AFI_IP][SAFI_LABELED_UNICAST]
		    && !peer->afc_nego[AFI_IP][SAFI_MPLS_VPN]
		    && !peer->afc_nego[AFI_IP][SAFI_ENCAP]
		    && !peer->afc_nego[AFI_IP][SAFI_FLOWSPEC]
		    && !peer->afc_nego[AFI_IP6][SAFI_UNICAST]
		    && !peer->afc_nego[AFI_IP6][SAFI_MULTICAST]
		    && !peer->afc_nego[AFI_IP6][SAFI_LABELED_UNICAST]
		    && !peer->afc_nego[AFI_IP6][SAFI_MPLS_VPN]
		    && !peer->afc_nego[AFI_IP6][SAFI_ENCAP]
		    && !peer->afc_nego[AFI_IP6][SAFI_FLOWSPEC]
		    && !peer->afc_nego[AFI_L2VPN][SAFI_EVPN]) {
			zlog_err(
				"%s [Error] Configured AFI/SAFIs do not "
				"overlap with received MP capabilities",
				peer->host);

			if (error != error_data)
				bgp_notify_send_with_data(
					peer, BGP_NOTIFY_OPEN_ERR,
					BGP_NOTIFY_OPEN_UNSUP_CAPBL, error_data,
					error - error_data);
			else
				bgp_notify_send(peer, BGP_NOTIFY_OPEN_ERR,
						BGP_NOTIFY_OPEN_UNSUP_CAPBL);
			return -1;
		}
	}
	return 0;
}

static void bgp_open_capability_orf(struct stream *s, struct peer *peer,
				    afi_t afi, safi_t safi, uint8_t code)
{
	uint8_t cap_len;
	uint8_t orf_len;
	unsigned long capp;
	unsigned long orfp;
	unsigned long numberp;
	int number_of_orfs = 0;
	iana_afi_t pkt_afi;
	iana_safi_t pkt_safi;

	/* Convert AFI, SAFI to values for packet. */
	bgp_map_afi_safi_int2iana(afi, safi, &pkt_afi, &pkt_safi);

	stream_putc(s, BGP_OPEN_OPT_CAP);
	capp = stream_get_endp(s); /* Set Capability Len Pointer */
	stream_putc(s, 0);	 /* Capability Length */
	stream_putc(s, code);      /* Capability Code */
	orfp = stream_get_endp(s); /* Set ORF Len Pointer */
	stream_putc(s, 0);	 /* ORF Length */
	stream_putw(s, pkt_afi);
	stream_putc(s, 0);
	stream_putc(s, pkt_safi);
	numberp = stream_get_endp(s); /* Set Number Pointer */
	stream_putc(s, 0);	    /* Number of ORFs */

	/* Address Prefix ORF */
	if (CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_ORF_PREFIX_SM)
	    || CHECK_FLAG(peer->af_flags[afi][safi], PEER_FLAG_ORF_PREFIX_RM)) {
		stream_putc(s, (code == CAPABILITY_CODE_ORF
					? ORF_TYPE_PREFIX
					: ORF_TYPE_PREFIX_OLD));

		if (CHECK_FLAG(peer->af_flags[afi][safi],
			       PEER_FLAG_ORF_PREFIX_SM)
		    && CHECK_FLAG(peer->af_flags[afi][safi],
				  PEER_FLAG_ORF_PREFIX_RM)) {
			SET_FLAG(peer->af_cap[afi][safi],
				 PEER_CAP_ORF_PREFIX_SM_ADV);
			SET_FLAG(peer->af_cap[afi][safi],
				 PEER_CAP_ORF_PREFIX_RM_ADV);
			stream_putc(s, ORF_MODE_BOTH);
		} else if (CHECK_FLAG(peer->af_flags[afi][safi],
				      PEER_FLAG_ORF_PREFIX_SM)) {
			SET_FLAG(peer->af_cap[afi][safi],
				 PEER_CAP_ORF_PREFIX_SM_ADV);
			stream_putc(s, ORF_MODE_SEND);
		} else {
			SET_FLAG(peer->af_cap[afi][safi],
				 PEER_CAP_ORF_PREFIX_RM_ADV);
			stream_putc(s, ORF_MODE_RECEIVE);
		}
		number_of_orfs++;
	}

	/* Total Number of ORFs. */
	stream_putc_at(s, numberp, number_of_orfs);

	/* Total ORF Len. */
	orf_len = stream_get_endp(s) - orfp - 1;
	stream_putc_at(s, orfp, orf_len);

	/* Total Capability Len. */
	cap_len = stream_get_endp(s) - capp - 1;
	stream_putc_at(s, capp, cap_len);
}

/* Fill in capability open option to the packet. */
void bgp_open_capability(struct stream *s, struct peer *peer)
{
	uint8_t len;
	unsigned long cp, capp, rcapp;
	iana_afi_t pkt_afi;
	afi_t afi;
	safi_t safi;
	iana_safi_t pkt_safi;
	as_t local_as;
	uint32_t restart_time;
	uint8_t afi_safi_count = 0;
	int adv_addpath_tx = 0;

	/* Remember current pointer for Opt Parm Len. */
	cp = stream_get_endp(s);

	/* Opt Parm Len. */
	stream_putc(s, 0);

	/* Do not send capability. */
	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_CAPABILITY_OPEN)
	    || CHECK_FLAG(peer->flags, PEER_FLAG_DONT_CAPABILITY))
		return;

	/* MP capability for configured AFI, SAFI */
	FOREACH_AFI_SAFI (afi, safi) {
		if (peer->afc[afi][safi]) {
			/* Convert AFI, SAFI to values for packet. */
			bgp_map_afi_safi_int2iana(afi, safi, &pkt_afi,
						  &pkt_safi);

			peer->afc_adv[afi][safi] = 1;
			stream_putc(s, BGP_OPEN_OPT_CAP);
			stream_putc(s, CAPABILITY_CODE_MP_LEN + 2);
			stream_putc(s, CAPABILITY_CODE_MP);
			stream_putc(s, CAPABILITY_CODE_MP_LEN);
			stream_putw(s, pkt_afi);
			stream_putc(s, 0);
			stream_putc(s, pkt_safi);

			/* Extended nexthop capability - currently
			 * supporting RFC-5549 for
			 * Link-Local peering only
			 */
			if (CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_ENHE)
			    && peer->su.sa.sa_family == AF_INET6
			    && IN6_IS_ADDR_LINKLOCAL(&peer->su.sin6.sin6_addr)
			    && afi == AFI_IP
			    && (safi == SAFI_UNICAST
				|| safi == SAFI_LABELED_UNICAST)) {
				/* RFC 5549 Extended Next Hop Encoding
				 */
				SET_FLAG(peer->cap, PEER_CAP_ENHE_ADV);
				stream_putc(s, BGP_OPEN_OPT_CAP);
				stream_putc(s, CAPABILITY_CODE_ENHE_LEN + 2);
				stream_putc(s, CAPABILITY_CODE_ENHE);
				stream_putc(s, CAPABILITY_CODE_ENHE_LEN);

				SET_FLAG(peer->af_cap[AFI_IP][safi],
					 PEER_CAP_ENHE_AF_ADV);
				stream_putw(s, pkt_afi);
				stream_putw(s, pkt_safi);
				stream_putw(s, afi_int2iana(AFI_IP6));

				if (CHECK_FLAG(peer->af_cap[afi][safi],
					       PEER_CAP_ENHE_AF_RCV))
					SET_FLAG(peer->af_cap[afi][safi],
						 PEER_CAP_ENHE_AF_NEGO);
			}
		}
	}

	/* Route refresh. */
	SET_FLAG(peer->cap, PEER_CAP_REFRESH_ADV);
	stream_putc(s, BGP_OPEN_OPT_CAP);
	stream_putc(s, CAPABILITY_CODE_REFRESH_LEN + 2);
	stream_putc(s, CAPABILITY_CODE_REFRESH_OLD);
	stream_putc(s, CAPABILITY_CODE_REFRESH_LEN);
	stream_putc(s, BGP_OPEN_OPT_CAP);
	stream_putc(s, CAPABILITY_CODE_REFRESH_LEN + 2);
	stream_putc(s, CAPABILITY_CODE_REFRESH);
	stream_putc(s, CAPABILITY_CODE_REFRESH_LEN);

	/* AS4 */
	SET_FLAG(peer->cap, PEER_CAP_AS4_ADV);
	stream_putc(s, BGP_OPEN_OPT_CAP);
	stream_putc(s, CAPABILITY_CODE_AS4_LEN + 2);
	stream_putc(s, CAPABILITY_CODE_AS4);
	stream_putc(s, CAPABILITY_CODE_AS4_LEN);
	if (peer->change_local_as)
		local_as = peer->change_local_as;
	else
		local_as = peer->local_as;
	stream_putl(s, local_as);

	/* AddPath */
	FOREACH_AFI_SAFI (afi, safi) {
		if (peer->afc[afi][safi]) {
			afi_safi_count++;

			/* Only advertise addpath TX if a feature that
			 * will use it is
			 * configured */
			if (CHECK_FLAG(peer->af_flags[afi][safi],
				       PEER_FLAG_ADDPATH_TX_ALL_PATHS)
			    || CHECK_FLAG(peer->af_flags[afi][safi],
					  PEER_FLAG_ADDPATH_TX_BESTPATH_PER_AS))
				adv_addpath_tx = 1;
		}
	}

	SET_FLAG(peer->cap, PEER_CAP_ADDPATH_ADV);
	stream_putc(s, BGP_OPEN_OPT_CAP);
	stream_putc(s, (CAPABILITY_CODE_ADDPATH_LEN * afi_safi_count) + 2);
	stream_putc(s, CAPABILITY_CODE_ADDPATH);
	stream_putc(s, CAPABILITY_CODE_ADDPATH_LEN * afi_safi_count);

	FOREACH_AFI_SAFI (afi, safi) {
		if (peer->afc[afi][safi]) {
			/* Convert AFI, SAFI to values for packet. */
			bgp_map_afi_safi_int2iana(afi, safi, &pkt_afi,
						  &pkt_safi);

			stream_putw(s, pkt_afi);
			stream_putc(s, pkt_safi);

			if (adv_addpath_tx) {
				stream_putc(s, BGP_ADDPATH_RX | BGP_ADDPATH_TX);
				SET_FLAG(peer->af_cap[afi][safi],
					 PEER_CAP_ADDPATH_AF_RX_ADV);
				SET_FLAG(peer->af_cap[afi][safi],
					 PEER_CAP_ADDPATH_AF_TX_ADV);
			} else {
				stream_putc(s, BGP_ADDPATH_RX);
				SET_FLAG(peer->af_cap[afi][safi],
					 PEER_CAP_ADDPATH_AF_RX_ADV);
				UNSET_FLAG(peer->af_cap[afi][safi],
					   PEER_CAP_ADDPATH_AF_TX_ADV);
			}
		}
	}

	/* ORF capability. */
	FOREACH_AFI_SAFI (afi, safi) {
		if (CHECK_FLAG(peer->af_flags[afi][safi],
			       PEER_FLAG_ORF_PREFIX_SM)
		    || CHECK_FLAG(peer->af_flags[afi][safi],
				  PEER_FLAG_ORF_PREFIX_RM)) {
			bgp_open_capability_orf(s, peer, afi, safi,
						CAPABILITY_CODE_ORF_OLD);
			bgp_open_capability_orf(s, peer, afi, safi,
						CAPABILITY_CODE_ORF);
		}
	}

	/* Dynamic capability. */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_DYNAMIC_CAPABILITY)) {
		SET_FLAG(peer->cap, PEER_CAP_DYNAMIC_ADV);
		stream_putc(s, BGP_OPEN_OPT_CAP);
		stream_putc(s, CAPABILITY_CODE_DYNAMIC_LEN + 2);
		stream_putc(s, CAPABILITY_CODE_DYNAMIC_OLD);
		stream_putc(s, CAPABILITY_CODE_DYNAMIC_LEN);
		stream_putc(s, BGP_OPEN_OPT_CAP);
		stream_putc(s, CAPABILITY_CODE_DYNAMIC_LEN + 2);
		stream_putc(s, CAPABILITY_CODE_DYNAMIC);
		stream_putc(s, CAPABILITY_CODE_DYNAMIC_LEN);
	}

	/* Hostname capability */
	if (cmd_hostname_get()) {
		SET_FLAG(peer->cap, PEER_CAP_HOSTNAME_ADV);
		stream_putc(s, BGP_OPEN_OPT_CAP);
		rcapp = stream_get_endp(s); /* Ptr to length placeholder */
		stream_putc(s, 0);	  /* dummy len for now */
		stream_putc(s, CAPABILITY_CODE_FQDN);
		capp = stream_get_endp(s);
		stream_putc(s, 0); /* dummy len for now */
		len = strlen(cmd_hostname_get());
		if (len > BGP_MAX_HOSTNAME)
			len = BGP_MAX_HOSTNAME;

		stream_putc(s, len);
		stream_put(s, cmd_hostname_get(), len);
		if (cmd_domainname_get()) {
			len = strlen(cmd_domainname_get());
			if (len > BGP_MAX_HOSTNAME)
				len = BGP_MAX_HOSTNAME;

			stream_putc(s, len);
			stream_put(s, cmd_domainname_get(), len);
		} else
			stream_putc(s, 0); /* 0 length */

		/* Set the lengths straight */
		len = stream_get_endp(s) - rcapp - 1;
		stream_putc_at(s, rcapp, len);
		len = stream_get_endp(s) - capp - 1;
		stream_putc_at(s, capp, len);

		if (bgp_debug_neighbor_events(peer))
			zlog_debug(
				"%s Sending hostname cap with hn = %s, dn = %s",
				peer->host, cmd_hostname_get(),
				cmd_domainname_get());
	}

	/* Sending base graceful-restart capability irrespective of the config
	 */
	SET_FLAG(peer->cap, PEER_CAP_RESTART_ADV);
	stream_putc(s, BGP_OPEN_OPT_CAP);
	capp = stream_get_endp(s); /* Set Capability Len Pointer */
	stream_putc(s, 0);	 /* Capability Length */
	stream_putc(s, CAPABILITY_CODE_RESTART);
	rcapp = stream_get_endp(s); /* Set Restart Capability Len Pointer */
	stream_putc(s, 0);
	restart_time = peer->bgp->restart_time;
	if (peer->bgp->t_startup) {
		SET_FLAG(restart_time, RESTART_R_BIT);
		SET_FLAG(peer->cap, PEER_CAP_RESTART_BIT_ADV);
	}
	stream_putw(s, restart_time);

	/* Send address-family specific graceful-restart capability only when GR
	   config
	   is present */
	if (bgp_flag_check(peer->bgp, BGP_FLAG_GRACEFUL_RESTART)) {
		FOREACH_AFI_SAFI (afi, safi) {
			if (peer->afc[afi][safi]) {
				/* Convert AFI, SAFI to values for
				 * packet. */
				bgp_map_afi_safi_int2iana(afi, safi, &pkt_afi,
							  &pkt_safi);
				stream_putw(s, pkt_afi);
				stream_putc(s, pkt_safi);
				if (bgp_flag_check(peer->bgp,
						   BGP_FLAG_GR_PRESERVE_FWD))
					stream_putc(s, RESTART_F_BIT);
				else
					stream_putc(s, 0);
			}
		}
	}

	/* Total Graceful restart capability Len. */
	len = stream_get_endp(s) - rcapp - 1;
	stream_putc_at(s, rcapp, len);

	/* Total Capability Len. */
	len = stream_get_endp(s) - capp - 1;
	stream_putc_at(s, capp, len);

	/* Total Opt Parm Len. */
	len = stream_get_endp(s) - cp - 1;
	stream_putc_at(s, cp, len);
}
