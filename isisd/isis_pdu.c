/*
 * IS-IS Rout(e)ing protocol - isis_pdu.c
 *                             PDU processing
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "memory.h"
#include "thread.h"
#include "linklist.h"
#include "log.h"
#include "stream.h"
#include "vty.h"
#include "hash.h"
#include "prefix.h"
#include "if.h"
#include "checksum.h"
#include "md5.h"

#include "isisd/dict.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_network.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_dr.h"
#include "isisd/isisd.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_pdu.h"
#include "isisd/iso_checksum.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_events.h"
#include "isisd/isis_te.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_tlvs.h"

static int ack_lsp(struct isis_lsp_hdr *hdr, struct isis_circuit *circuit,
		   int level)
{
	unsigned long lenp;
	int retval;
	uint16_t length;
	uint8_t pdu_type =
		(level == IS_LEVEL_1) ? L1_PARTIAL_SEQ_NUM : L2_PARTIAL_SEQ_NUM;

	isis_circuit_stream(circuit, &circuit->snd_stream);

	fill_fixed_hdr(pdu_type, circuit->snd_stream);

	lenp = stream_get_endp(circuit->snd_stream);
	stream_putw(circuit->snd_stream, 0); /* PDU length  */
	stream_put(circuit->snd_stream, isis->sysid, ISIS_SYS_ID_LEN);
	stream_putc(circuit->snd_stream, circuit->idx);
	stream_putc(circuit->snd_stream, 9);  /* code */
	stream_putc(circuit->snd_stream, 16); /* len */

	stream_putw(circuit->snd_stream, hdr->rem_lifetime);
	stream_put(circuit->snd_stream, hdr->lsp_id, ISIS_SYS_ID_LEN + 2);
	stream_putl(circuit->snd_stream, hdr->seqno);
	stream_putw(circuit->snd_stream, hdr->checksum);

	length = (uint16_t)stream_get_endp(circuit->snd_stream);
	/* Update PDU length */
	stream_putw_at(circuit->snd_stream, lenp, length);

	retval = circuit->tx(circuit, level);
	if (retval != ISIS_OK)
		zlog_err("ISIS-Upd (%s): Send L%d LSP PSNP on %s failed",
			 circuit->area->area_tag, level,
			 circuit->interface->name);

	return retval;
}

/*
 *  RECEIVE SIDE
 */

struct iih_info {
	struct isis_circuit *circuit;
	uint8_t *ssnpa;
	int level;

	uint8_t circ_type;
	uint8_t sys_id[ISIS_SYS_ID_LEN];
	uint16_t holdtime;
	uint16_t pdu_len;

	uint8_t circuit_id;

	uint8_t priority;
	uint8_t dis[ISIS_SYS_ID_LEN + 1];

	bool v4_usable;
	bool v6_usable;

	struct isis_tlvs *tlvs;
};

static int process_p2p_hello(struct iih_info *iih)
{
	struct isis_threeway_adj *tw_adj = iih->tlvs->threeway_adj;
	if (tw_adj) {
		if (tw_adj->state > ISIS_THREEWAY_DOWN) {
			if (isis->debugs & DEBUG_ADJ_PACKETS) {
				zlog_debug("ISIS-Adj (%s): Rcvd P2P IIH from (%s) with invalid three-way state: %d\n",
					   iih->circuit->area->area_tag,
					   iih->circuit->interface->name,
					   tw_adj->state);
			}
			return ISIS_WARNING;
		}

		if (tw_adj->neighbor_set
		    && (memcmp(tw_adj->neighbor_id, isis->sysid, ISIS_SYS_ID_LEN)
			|| tw_adj->neighbor_circuit_id != (uint32_t) iih->circuit->idx)) {

			if (isis->debugs & DEBUG_ADJ_PACKETS) {
				zlog_debug("ISIS-Adj (%s): Rcvd P2P IIH from (%s) which lists IS/Circuit different from us as neighbor.\n",
					   iih->circuit->area->area_tag,
					   iih->circuit->interface->name);
			}

			return ISIS_WARNING;
		}
	}

	/*
	 * My interpertation of the ISO, if no adj exists we will create one for
	 * the circuit
	 */
	struct isis_adjacency *adj = iih->circuit->u.p2p.neighbor;
	/* If an adjacency exists, check it is with the source of the hello
	 * packets */
	if (adj) {
		if (memcmp(iih->sys_id, adj->sysid, ISIS_SYS_ID_LEN)) {
			zlog_debug(
				"hello source and adjacency do not match, set adj down\n");
			isis_adj_state_change(adj, ISIS_ADJ_DOWN,
					      "adj do not exist");
			return ISIS_OK;
		}
	}
	if (!adj || adj->level != iih->circ_type) {
		if (!adj) {
			adj = isis_new_adj(iih->sys_id, NULL, iih->circ_type,
					   iih->circuit);
		} else {
			adj->level = iih->circ_type;
		}
		iih->circuit->u.p2p.neighbor = adj;
		/* Build lsp with the new neighbor entry when a new
		 * adjacency is formed. Set adjacency circuit type to
		 * IIH PDU header circuit type before lsp is regenerated
		 * when an adjacency is up. This will result in the new
		 * adjacency entry getting added to the lsp tlv neighbor list.
		 */
		adj->circuit_t = iih->circ_type;
		isis_adj_state_change(adj, ISIS_ADJ_INITIALIZING, NULL);
		adj->sys_type = ISIS_SYSTYPE_UNKNOWN;
	}

	if (tw_adj && adj->threeway_state == ISIS_THREEWAY_DOWN)
		adj->ext_circuit_id = tw_adj->local_circuit_id;

	/* 8.2.6 Monitoring point-to-point adjacencies */
	adj->hold_time = iih->holdtime;
	adj->last_upd = time(NULL);

	bool changed;
	isis_tlvs_to_adj(iih->tlvs, adj, &changed);
	changed |= tlvs_to_adj_mt_set(iih->tlvs, iih->v4_usable, iih->v6_usable,
				      adj);

	/* Update MPLS TE Remote IP address parameter if possible */
	if (IS_MPLS_TE(isisMplsTE) && iih->circuit->mtc
	    && IS_CIRCUIT_TE(iih->circuit->mtc) && adj->ipv4_address_count)
		set_circuitparams_rmt_ipaddr(iih->circuit->mtc,
					     adj->ipv4_addresses[0]);

	/* lets take care of the expiry */
	THREAD_TIMER_OFF(adj->t_expire);
	thread_add_timer(master, isis_adj_expire, adj, (long)adj->hold_time,
			 &adj->t_expire);

	/* 8.2.5.2 a) a match was detected */
	if (isis_tlvs_area_addresses_match(iih->tlvs,
					   iih->circuit->area->area_addrs)) {
		/* 8.2.5.2 a) 2) If the system is L1 - table 5 */
		if (iih->circuit->area->is_type == IS_LEVEL_1) {
			switch (iih->circ_type) {
			case IS_LEVEL_1:
			case IS_LEVEL_1_AND_2:
				if (adj->adj_state != ISIS_ADJ_UP
				    || adj->adj_usage == ISIS_ADJ_LEVEL1) {
					isis_adj_process_threeway(adj, tw_adj,
								  ISIS_ADJ_LEVEL1);
				}
				break;
			case IS_LEVEL_2:
				if (adj->adj_state != ISIS_ADJ_UP) {
					/* (7) reject - wrong system type event
					 */
					zlog_warn("wrongSystemType");
					return ISIS_WARNING;
				} else if (adj->adj_usage == ISIS_ADJ_LEVEL1) {
					/* (6) down - wrong system */
					isis_adj_state_change(adj,
							      ISIS_ADJ_DOWN,
							      "Wrong System");
				}
				break;
			}
		}

		/* 8.2.5.2 a) 3) If the system is L1L2 - table 6 */
		if (iih->circuit->area->is_type == IS_LEVEL_1_AND_2) {
			switch (iih->circ_type) {
			case IS_LEVEL_1:
				if (adj->adj_state != ISIS_ADJ_UP
				    || adj->adj_usage == ISIS_ADJ_LEVEL1) {
					isis_adj_process_threeway(adj, tw_adj,
								  ISIS_ADJ_LEVEL1);
				} else if ((adj->adj_usage
					    == ISIS_ADJ_LEVEL1AND2)
					   || (adj->adj_usage
					       == ISIS_ADJ_LEVEL2)) {
					/* (8) down - wrong system */
					isis_adj_state_change(adj,
							      ISIS_ADJ_DOWN,
							      "Wrong System");
				}
				break;
			case IS_LEVEL_2:
				if (adj->adj_state != ISIS_ADJ_UP
				    || adj->adj_usage == ISIS_ADJ_LEVEL2) {
					isis_adj_process_threeway(adj, tw_adj,
								  ISIS_ADJ_LEVEL2);
				} else if ((adj->adj_usage == ISIS_ADJ_LEVEL1)
					   || (adj->adj_usage
					       == ISIS_ADJ_LEVEL1AND2)) {
					/* (8) down - wrong system */
					isis_adj_state_change(adj,
							      ISIS_ADJ_DOWN,
							      "Wrong System");
				}
				break;
			case IS_LEVEL_1_AND_2:
				if (adj->adj_state != ISIS_ADJ_UP
				    || adj->adj_usage == ISIS_ADJ_LEVEL1AND2) {
					isis_adj_process_threeway(adj, tw_adj,
								  ISIS_ADJ_LEVEL1AND2);
				} else if ((adj->adj_usage == ISIS_ADJ_LEVEL1)
					   || (adj->adj_usage
					       == ISIS_ADJ_LEVEL2)) {
					/* (8) down - wrong system */
					isis_adj_state_change(adj,
							      ISIS_ADJ_DOWN,
							      "Wrong System");
				}
				break;
			}
		}

		/* 8.2.5.2 a) 4) If the system is L2 - table 7 */
		if (iih->circuit->area->is_type == IS_LEVEL_2) {
			switch (iih->circ_type) {
			case IS_LEVEL_1:
				if (adj->adj_state != ISIS_ADJ_UP) {
					/* (5) reject - wrong system type event
					 */
					zlog_warn("wrongSystemType");
					return ISIS_WARNING;
				} else if ((adj->adj_usage
					    == ISIS_ADJ_LEVEL1AND2)
					   || (adj->adj_usage
					       == ISIS_ADJ_LEVEL2)) {
					/* (6) down - wrong system */
					isis_adj_state_change(adj,
							      ISIS_ADJ_DOWN,
							      "Wrong System");
				}
				break;
			case IS_LEVEL_1_AND_2:
			case IS_LEVEL_2:
				if (adj->adj_state != ISIS_ADJ_UP
				    || adj->adj_usage == ISIS_ADJ_LEVEL2) {
					isis_adj_process_threeway(adj, tw_adj,
								  ISIS_ADJ_LEVEL2);
				} else if (adj->adj_usage
					   == ISIS_ADJ_LEVEL1AND2) {
					/* (6) down - wrong system */
					isis_adj_state_change(adj,
							      ISIS_ADJ_DOWN,
							      "Wrong System");
				}
				break;
			}
		}
	}
	/* 8.2.5.2 b) if no match was detected */
	else if (listcount(iih->circuit->area->area_addrs) > 0) {
		if (iih->circuit->area->is_type == IS_LEVEL_1) {
			/* 8.2.5.2 b) 1) is_type L1 and adj is not up */
			if (adj->adj_state != ISIS_ADJ_UP) {
				isis_adj_state_change(adj, ISIS_ADJ_DOWN,
						      "Area Mismatch");
				/* 8.2.5.2 b) 2)is_type L1 and adj is up */
			} else {
				isis_adj_state_change(adj, ISIS_ADJ_DOWN,
						      "Down - Area Mismatch");
			}
		}
		/* 8.2.5.2 b 3 If the system is L2 or L1L2 - table 8 */
		else {
			switch (iih->circ_type) {
			case IS_LEVEL_1:
				if (adj->adj_state != ISIS_ADJ_UP) {
					/* (6) reject - Area Mismatch event */
					zlog_warn("AreaMismatch");
					return ISIS_WARNING;
				} else if (adj->adj_usage == ISIS_ADJ_LEVEL1) {
					/* (7) down - area mismatch */
					isis_adj_state_change(adj,
							      ISIS_ADJ_DOWN,
							      "Area Mismatch");

				} else if ((adj->adj_usage
					    == ISIS_ADJ_LEVEL1AND2)
					   || (adj->adj_usage
					       == ISIS_ADJ_LEVEL2)) {
					/* (7) down - wrong system */
					isis_adj_state_change(adj,
							      ISIS_ADJ_DOWN,
							      "Wrong System");
				}
				break;
			case IS_LEVEL_1_AND_2:
			case IS_LEVEL_2:
				if (adj->adj_state != ISIS_ADJ_UP
				    || adj->adj_usage == ISIS_ADJ_LEVEL2) {
					isis_adj_process_threeway(adj, tw_adj,
								  ISIS_ADJ_LEVEL2);
				} else if (adj->adj_usage == ISIS_ADJ_LEVEL1) {
					/* (7) down - wrong system */
					isis_adj_state_change(adj,
							      ISIS_ADJ_DOWN,
							      "Wrong System");
				} else if (adj->adj_usage
					   == ISIS_ADJ_LEVEL1AND2) {
					if (iih->circ_type == IS_LEVEL_2) {
						/* (7) down - wrong system */
						isis_adj_state_change(
							adj, ISIS_ADJ_DOWN,
							"Wrong System");
					} else {
						/* (7) down - area mismatch */
						isis_adj_state_change(
							adj, ISIS_ADJ_DOWN,
							"Area Mismatch");
					}
				}
				break;
			}
		}
	} else {
		/* down - area mismatch */
		isis_adj_state_change(adj, ISIS_ADJ_DOWN, "Area Mismatch");
	}

	if (adj->adj_state == ISIS_ADJ_UP && changed) {
		lsp_regenerate_schedule(adj->circuit->area,
					isis_adj_usage2levels(adj->adj_usage),
					0);
	}

	/* 8.2.5.2 c) if the action was up - comparing circuit IDs */
	/* FIXME - Missing parts */

	/* some of my own understanding of the ISO, why the heck does
	 * it not say what should I change the system_type to...
	 */
	switch (adj->adj_usage) {
	case ISIS_ADJ_LEVEL1:
		adj->sys_type = ISIS_SYSTYPE_L1_IS;
		break;
	case ISIS_ADJ_LEVEL2:
		adj->sys_type = ISIS_SYSTYPE_L2_IS;
		break;
	case ISIS_ADJ_LEVEL1AND2:
		adj->sys_type = ISIS_SYSTYPE_L2_IS;
		break;
	case ISIS_ADJ_NONE:
		adj->sys_type = ISIS_SYSTYPE_UNKNOWN;
		break;
	}

	if (isis->debugs & DEBUG_ADJ_PACKETS) {
		zlog_debug(
			"ISIS-Adj (%s): Rcvd P2P IIH from (%s), cir type %s,"
			" cir id %hhu, length %" PRIu16,
			iih->circuit->area->area_tag,
			iih->circuit->interface->name,
			circuit_t2string(iih->circuit->is_type),
			iih->circuit->circuit_id, iih->pdu_len);
	}

	return ISIS_OK;
}

static int process_lan_hello(struct iih_info *iih)
{
	struct isis_adjacency *adj;
	adj = isis_adj_lookup(iih->sys_id,
			      iih->circuit->u.bc.adjdb[iih->level - 1]);
	if ((adj == NULL) || (memcmp(adj->snpa, iih->ssnpa, ETH_ALEN))
	    || (adj->level != iih->level)) {
		if (!adj) {
			/* Do as in 8.4.2.5 */
			adj = isis_new_adj(iih->sys_id, iih->ssnpa, iih->level,
					   iih->circuit);
		} else {
			if (iih->ssnpa) {
				memcpy(adj->snpa, iih->ssnpa, 6);
			} else {
				memset(adj->snpa, ' ', 6);
			}
			adj->level = iih->level;
		}
		isis_adj_state_change(adj, ISIS_ADJ_INITIALIZING, NULL);

		if (iih->level == IS_LEVEL_1)
			adj->sys_type = ISIS_SYSTYPE_L1_IS;
		else
			adj->sys_type = ISIS_SYSTYPE_L2_IS;
		list_delete_all_node(
			iih->circuit->u.bc.lan_neighs[iih->level - 1]);
		isis_adj_build_neigh_list(
			iih->circuit->u.bc.adjdb[iih->level - 1],
			iih->circuit->u.bc.lan_neighs[iih->level - 1]);
	}

	if (adj->dis_record[iih->level - 1].dis == ISIS_IS_DIS) {
		uint8_t *dis = (iih->level == 1)
				       ? iih->circuit->u.bc.l1_desig_is
				       : iih->circuit->u.bc.l2_desig_is;

		if (memcmp(dis, iih->dis, ISIS_SYS_ID_LEN + 1)) {
			thread_add_event(master, isis_event_dis_status_change,
					 iih->circuit, 0, NULL);
			memcpy(dis, iih->dis, ISIS_SYS_ID_LEN + 1);
		}
	}

	adj->circuit_t = iih->circ_type;
	adj->hold_time = iih->holdtime;
	adj->last_upd = time(NULL);
	adj->prio[iih->level - 1] = iih->priority;
	memcpy(adj->lanid, iih->dis, ISIS_SYS_ID_LEN + 1);

	bool changed;
	isis_tlvs_to_adj(iih->tlvs, adj, &changed);
	changed |= tlvs_to_adj_mt_set(iih->tlvs, iih->v4_usable, iih->v6_usable,
				      adj);

	/* lets take care of the expiry */
	THREAD_TIMER_OFF(adj->t_expire);
	thread_add_timer(master, isis_adj_expire, adj, (long)adj->hold_time,
			 &adj->t_expire);

	/*
	 * If the snpa for this circuit is found from LAN Neighbours TLV
	 * we have two-way communication -> adjacency can be put to state "up"
	 */
	bool own_snpa_found =
		isis_tlvs_own_snpa_found(iih->tlvs, iih->circuit->u.bc.snpa);

	if (adj->adj_state != ISIS_ADJ_UP) {
		if (own_snpa_found) {
			isis_adj_state_change(
				adj, ISIS_ADJ_UP,
				"own SNPA found in LAN Neighbours TLV");
		}
	} else {
		if (!own_snpa_found) {
			isis_adj_state_change(
				adj, ISIS_ADJ_INITIALIZING,
				"own SNPA not found in LAN Neighbours TLV");
		}
	}

	if (adj->adj_state == ISIS_ADJ_UP && changed)
		lsp_regenerate_schedule(adj->circuit->area, iih->level, 0);

	if (isis->debugs & DEBUG_ADJ_PACKETS) {
		zlog_debug(
			"ISIS-Adj (%s): Rcvd L%d LAN IIH from %s on %s, cirType %s, cirID %u, length %zd",
			iih->circuit->area->area_tag, iih->level,
			snpa_print(iih->ssnpa), iih->circuit->interface->name,
			circuit_t2string(iih->circuit->is_type),
			iih->circuit->circuit_id,
			stream_get_endp(iih->circuit->rcv_stream));
	}
	return ISIS_OK;
}

static int pdu_len_validate(uint16_t pdu_len, struct isis_circuit *circuit)
{
	if (pdu_len < stream_get_getp(circuit->rcv_stream)
	    || pdu_len > ISO_MTU(circuit)
	    || pdu_len > stream_get_endp(circuit->rcv_stream))
		return 1;

	if (pdu_len < stream_get_endp(circuit->rcv_stream))
		stream_set_endp(circuit->rcv_stream, pdu_len);
	return 0;
}

static int process_hello(uint8_t pdu_type, struct isis_circuit *circuit,
			 uint8_t *ssnpa)
{
	bool p2p_hello = (pdu_type == P2P_HELLO);
	int level = p2p_hello ? 0
			      : (pdu_type == L1_LAN_HELLO) ? ISIS_LEVEL1
							   : ISIS_LEVEL2;
	const char *pdu_name =
		p2p_hello
			? "P2P IIH"
			: (level == ISIS_LEVEL1) ? "L1 LAN IIH" : "L2 LAN IIH";

	if (isis->debugs & DEBUG_ADJ_PACKETS) {
		zlog_debug("ISIS-Adj (%s): Rcvd %s on %s, cirType %s, cirID %u",
			   circuit->area->area_tag, pdu_name,
			   circuit->interface->name,
			   circuit_t2string(circuit->is_type),
			   circuit->circuit_id);
		if (isis->debugs & DEBUG_PACKET_DUMP)
			zlog_dump_data(STREAM_DATA(circuit->rcv_stream),
				       stream_get_endp(circuit->rcv_stream));
	}

	if (p2p_hello) {
		if (circuit->circ_type != CIRCUIT_T_P2P) {
			zlog_warn("p2p hello on non p2p circuit");
			return ISIS_WARNING;
		}
	} else {
		if (circuit->circ_type != CIRCUIT_T_BROADCAST) {
			zlog_warn("lan hello on non broadcast circuit");
			return ISIS_WARNING;
		}

		if (circuit->ext_domain) {
			zlog_debug(
				"level %d LAN Hello received over circuit with externalDomain = true",
				level);
			return ISIS_WARNING;
		}

		if (!(circuit->is_type & level)) {
			if (isis->debugs & DEBUG_ADJ_PACKETS) {
				zlog_debug(
					"ISIS-Adj (%s): Interface level mismatch, %s",
					circuit->area->area_tag,
					circuit->interface->name);
			}
			return ISIS_WARNING;
		}
	}

	struct iih_info iih = {
		.circuit = circuit, .ssnpa = ssnpa, .level = level};

	/* Generic IIH Header */
	iih.circ_type = stream_getc(circuit->rcv_stream) & 0x03;
	stream_get(iih.sys_id, circuit->rcv_stream, ISIS_SYS_ID_LEN);
	iih.holdtime = stream_getw(circuit->rcv_stream);
	iih.pdu_len = stream_getw(circuit->rcv_stream);

	if (p2p_hello) {
		iih.circuit_id = stream_getc(circuit->rcv_stream);
	} else {
		iih.priority = stream_getc(circuit->rcv_stream);
		stream_get(iih.dis, circuit->rcv_stream, ISIS_SYS_ID_LEN + 1);
	}

	if (pdu_len_validate(iih.pdu_len, circuit)) {
		zlog_warn(
			"ISIS-Adj (%s): Rcvd %s from (%s) with invalid pdu length %" PRIu16,
			circuit->area->area_tag, pdu_name,
			circuit->interface->name, iih.pdu_len);
		return ISIS_WARNING;
	}

	if (!p2p_hello && !(level & iih.circ_type)) {
		zlog_err("Level %d LAN Hello with Circuit Type %d", level,
			 iih.circ_type);
		return ISIS_ERROR;
	}

	const char *error_log;
	int retval = ISIS_WARNING;

	if (isis_unpack_tlvs(STREAM_READABLE(circuit->rcv_stream),
			     circuit->rcv_stream, &iih.tlvs, &error_log)) {
		zlog_warn("isis_unpack_tlvs() failed: %s", error_log);
		goto out;
	}

	if (!iih.tlvs->area_addresses.count) {
		zlog_warn("No Area addresses TLV in %s", pdu_name);
		goto out;
	}

	if (!iih.tlvs->protocols_supported.count) {
		zlog_warn("No supported protocols TLV in %s", pdu_name);
		goto out;
	}

	if (!isis_tlvs_auth_is_valid(iih.tlvs, &circuit->passwd,
				     circuit->rcv_stream, false)) {
		isis_event_auth_failure(circuit->area->area_tag,
					"IIH authentication failure",
					iih.sys_id);
		goto out;
	}

	if (!memcmp(iih.sys_id, isis->sysid, ISIS_SYS_ID_LEN)) {
		zlog_warn(
			"ISIS-Adj (%s): Received IIH with own sysid - discard",
			circuit->area->area_tag);
		goto out;
	}

	if (!p2p_hello
	    && (listcount(circuit->area->area_addrs) == 0
		|| (level == ISIS_LEVEL1
		    && !isis_tlvs_area_addresses_match(
			       iih.tlvs, circuit->area->area_addrs)))) {
		if (isis->debugs & DEBUG_ADJ_PACKETS) {
			zlog_debug(
				"ISIS-Adj (%s): Area mismatch, level %d IIH on %s",
				circuit->area->area_tag, level,
				circuit->interface->name);
		}
		goto out;
	}

	iih.v4_usable = (circuit->ip_addrs && listcount(circuit->ip_addrs)
			 && iih.tlvs->ipv4_address.count);

	iih.v6_usable = (circuit->ipv6_link && listcount(circuit->ipv6_link)
			 && iih.tlvs->ipv6_address.count);

	if (!iih.v4_usable && !iih.v6_usable)
		goto out;

	retval = p2p_hello ? process_p2p_hello(&iih) : process_lan_hello(&iih);
out:
	isis_free_tlvs(iih.tlvs);

	return retval;
}

/*
 * Process Level 1/2 Link State
 * ISO - 10589
 * Section 7.3.15.1 - Action on receipt of a link state PDU
 */
static int process_lsp(uint8_t pdu_type, struct isis_circuit *circuit,
		       const uint8_t *ssnpa)
{
	int level = (pdu_type == L1_LINK_STATE) ? ISIS_LEVEL1 : ISIS_LEVEL2;

	if (isis->debugs & DEBUG_UPDATE_PACKETS) {
		zlog_debug(
			"ISIS-Upd (%s): Rcvd L%d LSP on %s, cirType %s, cirID %u",
			circuit->area->area_tag, level,
			circuit->interface->name,
			circuit_t2string(circuit->is_type),
			circuit->circuit_id);
		if (isis->debugs & DEBUG_PACKET_DUMP)
			zlog_dump_data(STREAM_DATA(circuit->rcv_stream),
				       stream_get_endp(circuit->rcv_stream));
	}

	struct isis_lsp_hdr hdr = {};

	hdr.pdu_len = stream_getw(circuit->rcv_stream);
	hdr.rem_lifetime = stream_getw(circuit->rcv_stream);
	stream_get(hdr.lsp_id, circuit->rcv_stream, sizeof(hdr.lsp_id));
	hdr.seqno = stream_getl(circuit->rcv_stream);
	hdr.checksum = stream_getw(circuit->rcv_stream);
	hdr.lsp_bits = stream_getc(circuit->rcv_stream);

	if (pdu_len_validate(hdr.pdu_len, circuit)) {
		zlog_debug("ISIS-Upd (%s): LSP %s invalid LSP length %" PRIu16,
			   circuit->area->area_tag, rawlspid_print(hdr.lsp_id),
			   hdr.pdu_len);
		return ISIS_WARNING;
	}

	if (isis->debugs & DEBUG_UPDATE_PACKETS) {
		zlog_debug("ISIS-Upd (%s): Rcvd L%d LSP %s, seq 0x%08" PRIx32
			   ", cksum 0x%04" PRIx16 ", lifetime %" PRIu16
			   "s, len %" PRIu16 ", on %s",
			   circuit->area->area_tag, level,
			   rawlspid_print(hdr.lsp_id), hdr.seqno, hdr.checksum,
			   hdr.rem_lifetime, hdr.pdu_len,
			   circuit->interface->name);
	}

	/* lsp is_type check */
	if ((hdr.lsp_bits & IS_LEVEL_1) != IS_LEVEL_1) {
		zlog_debug(
			"ISIS-Upd (%s): LSP %s invalid LSP is type 0x%" PRIx8,
			circuit->area->area_tag, rawlspid_print(hdr.lsp_id),
			hdr.lsp_bits & IS_LEVEL_1_AND_2);
		/* continue as per RFC1122 Be liberal in what you accept, and
		 * conservative in what you send */
	}

	/* Checksum sanity check - FIXME: move to correct place */
	/* 12 = sysid+pdu+remtime */
	if (iso_csum_verify(STREAM_DATA(circuit->rcv_stream) + 12,
			    hdr.pdu_len - 12, hdr.checksum, 12)) {
		zlog_debug(
			"ISIS-Upd (%s): LSP %s invalid LSP checksum 0x%04" PRIx16,
			circuit->area->area_tag, rawlspid_print(hdr.lsp_id),
			hdr.checksum);
		return ISIS_WARNING;
	}

	/* 7.3.15.1 a) 1 - external domain circuit will discard lsps */
	if (circuit->ext_domain) {
		zlog_debug(
			"ISIS-Upd (%s): LSP %s received at level %d over circuit with "
			"externalDomain = true",
			circuit->area->area_tag, rawlspid_print(hdr.lsp_id),
			level);
		return ISIS_WARNING;
	}

	/* 7.3.15.1 a) 2,3 - manualL2OnlyMode not implemented */
	if (!(circuit->is_type & level)) {
		zlog_debug(
			"ISIS-Upd (%s): LSP %s received at level %d over circuit of"
			" type %s",
			circuit->area->area_tag, rawlspid_print(hdr.lsp_id),
			level, circuit_t2string(circuit->is_type));
		return ISIS_WARNING;
	}

	struct isis_tlvs *tlvs = NULL;
	int retval = ISIS_WARNING;
	const char *error_log;

	if (isis_unpack_tlvs(STREAM_READABLE(circuit->rcv_stream),
			     circuit->rcv_stream, &tlvs, &error_log)) {
		zlog_warn("Something went wrong unpacking the LSP: %s",
			  error_log);
		goto out;
	}

	/* 7.3.15.1 a) 4 - need to make sure IDLength matches */

	/* 7.3.15.1 a) 5 - maximum area match, can be ommited since we only use
	 * 3 */

	/* 7.3.15.1 a) 7 - password check */
	struct isis_passwd *passwd = (level == ISIS_LEVEL1)
					     ? &circuit->area->area_passwd
					     : &circuit->area->domain_passwd;
	if (!isis_tlvs_auth_is_valid(tlvs, passwd, circuit->rcv_stream, true)) {
		isis_event_auth_failure(circuit->area->area_tag,
					"LSP authentication failure",
					hdr.lsp_id);
		goto out;
	}

	/* Find the LSP in our database and compare it to this Link State header
	 */
	struct isis_lsp *lsp =
		lsp_search(hdr.lsp_id, circuit->area->lspdb[level - 1]);
	int comp = 0;
	if (lsp)
		comp = lsp_compare(circuit->area->area_tag, lsp, hdr.seqno,
				   hdr.checksum, hdr.rem_lifetime);
	if (lsp && (lsp->own_lsp))
		goto dontcheckadj;

	/* 7.3.15.1 a) 6 - Must check that we have an adjacency of the same
	 * level  */
	/* for broadcast circuits, snpa should be compared */

	if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
		if (!isis_adj_lookup_snpa(ssnpa,
					  circuit->u.bc.adjdb[level - 1])) {
			zlog_debug("(%s): DS ======= LSP %s, seq 0x%08" PRIx32
				   ", cksum 0x%04" PRIx16 ", lifetime %" PRIu16
				   "s on %s",
				   circuit->area->area_tag,
				   rawlspid_print(hdr.lsp_id), hdr.seqno,
				   hdr.checksum, hdr.rem_lifetime,
				   circuit->interface->name);
			goto out; /* Silently discard */
		}
	}
	/* for non broadcast, we just need to find same level adj */
	else {
		/* If no adj, or no sharing of level */
		if (!circuit->u.p2p.neighbor) {
			retval = ISIS_OK;
			goto out;
		} else {
			if (((level == IS_LEVEL_1)
			     && (circuit->u.p2p.neighbor->adj_usage
				 == ISIS_ADJ_LEVEL2))
			    || ((level == IS_LEVEL_2)
				&& (circuit->u.p2p.neighbor->adj_usage
				    == ISIS_ADJ_LEVEL1)))
				goto out;
		}
	}

	bool lsp_confusion;

dontcheckadj:
	/* 7.3.15.1 a) 7 - Passwords for level 1 - not implemented  */

	/* 7.3.15.1 a) 8 - Passwords for level 2 - not implemented  */

	/* 7.3.15.1 a) 9 - OriginatingLSPBufferSize - not implemented  FIXME: do
	 * it */

	/* 7.3.16.2 - If this is an LSP from another IS with identical seq_num
	 * but
	 *            wrong checksum, initiate a purge. */
	if (lsp && (lsp->hdr.seqno == hdr.seqno)
	    && (lsp->hdr.checksum != hdr.checksum)) {
		zlog_warn("ISIS-Upd (%s): LSP %s seq 0x%08" PRIx32
			  " with confused checksum received.",
			  circuit->area->area_tag, rawlspid_print(hdr.lsp_id),
			  hdr.seqno);
		hdr.rem_lifetime = 0;
		lsp_confusion = true;
	} else
		lsp_confusion = false;

	/* 7.3.15.1 b) - If the remaining life time is 0, we perform 7.3.16.4 */
	if (hdr.rem_lifetime == 0) {
		if (!lsp) {
			/* 7.3.16.4 a) 1) No LSP in db -> send an ack, but don't
			 * save */
			/* only needed on explicit update, eg - p2p */
			if (circuit->circ_type == CIRCUIT_T_P2P)
				ack_lsp(&hdr, circuit, level);
			goto out; /* FIXME: do we need a purge? */
		} else {
			if (memcmp(hdr.lsp_id, isis->sysid, ISIS_SYS_ID_LEN)) {
				/* LSP by some other system -> do 7.3.16.4 b) */
				/* 7.3.16.4 b) 1)  */
				if (comp == LSP_NEWER) {
					lsp_update(lsp, &hdr, tlvs,
						   circuit->rcv_stream,
						   circuit->area, level,
						   lsp_confusion);
					tlvs = NULL;
					/* ii */
					lsp_set_all_srmflags(lsp);
					/* v */
					ISIS_FLAGS_CLEAR_ALL(
						lsp->SSNflags); /* FIXME:
								   OTHER
								   than c
								   */

					/* For the case of lsp confusion, flood
					 * the purge back to its
					 * originator so that it can react.
					 * Otherwise, don't reflood
					 * through incoming circuit as usual */
					if (!lsp_confusion) {
						/* iii */
						ISIS_CLEAR_FLAG(lsp->SRMflags,
								circuit);
						/* iv */
						if (circuit->circ_type
						    != CIRCUIT_T_BROADCAST)
							ISIS_SET_FLAG(
								lsp->SSNflags,
								circuit);
					}
				} /* 7.3.16.4 b) 2) */
				else if (comp == LSP_EQUAL) {
					/* i */
					ISIS_CLEAR_FLAG(lsp->SRMflags, circuit);
					/* ii */
					if (circuit->circ_type
					    != CIRCUIT_T_BROADCAST)
						ISIS_SET_FLAG(lsp->SSNflags,
							      circuit);
				} /* 7.3.16.4 b) 3) */
				else {
					ISIS_SET_FLAG(lsp->SRMflags, circuit);
					ISIS_CLEAR_FLAG(lsp->SSNflags, circuit);
				}
			} else if (lsp->hdr.rem_lifetime != 0) {
				/* our own LSP -> 7.3.16.4 c) */
				if (comp == LSP_NEWER) {
					lsp_inc_seqno(lsp, hdr.seqno);
					lsp_set_all_srmflags(lsp);
				} else {
					ISIS_SET_FLAG(lsp->SRMflags, circuit);
					ISIS_CLEAR_FLAG(lsp->SSNflags, circuit);
				}
				if (isis->debugs & DEBUG_UPDATE_PACKETS)
					zlog_debug(
						"ISIS-Upd (%s): (1) re-originating LSP %s new seq 0x%08" PRIx32,
						circuit->area->area_tag,
						rawlspid_print(hdr.lsp_id),
						lsp->hdr.seqno);
			}
		}
		goto out;
	}
	/* 7.3.15.1 c) - If this is our own lsp and we don't have it initiate a
	 * purge */
	if (memcmp(hdr.lsp_id, isis->sysid, ISIS_SYS_ID_LEN) == 0) {
		if (!lsp) {
			/* 7.3.16.4: initiate a purge */
			lsp_purge_non_exist(level, &hdr, circuit->area);
			retval = ISIS_OK;
			goto out;
		}
		/* 7.3.15.1 d) - If this is our own lsp and we have it */

		/* In 7.3.16.1, If an Intermediate system R somewhere in the
		 * domain
		 * has information that the current sequence number for source S
		 * is
		 * "greater" than that held by S, ... */

		if (hdr.seqno > lsp->hdr.seqno) {
			/* 7.3.16.1  */
			lsp_inc_seqno(lsp, hdr.seqno);
			if (isis->debugs & DEBUG_UPDATE_PACKETS)
				zlog_debug(
					"ISIS-Upd (%s): (2) re-originating LSP %s new seq 0x%08" PRIx32,
					circuit->area->area_tag,
					rawlspid_print(hdr.lsp_id),
					lsp->hdr.seqno);
		}
		/* If the received LSP is older or equal,
		 * resend the LSP which will act as ACK */
		lsp_set_all_srmflags(lsp);
	} else {
		/* 7.3.15.1 e) - This lsp originated on another system */

		/* 7.3.15.1 e) 1) LSP newer than the one in db or no LSP in db
		 */
		if ((!lsp || comp == LSP_NEWER)) {
			/*
			 * If this lsp is a frag, need to see if we have zero
			 * lsp present
			 */
			struct isis_lsp *lsp0 = NULL;
			if (LSP_FRAGMENT(hdr.lsp_id) != 0) {
				uint8_t lspid[ISIS_SYS_ID_LEN + 2];
				memcpy(lspid, hdr.lsp_id, ISIS_SYS_ID_LEN + 1);
				LSP_FRAGMENT(lspid) = 0;
				lsp0 = lsp_search(
					lspid, circuit->area->lspdb[level - 1]);
				if (!lsp0) {
					zlog_debug(
						"Got lsp frag, while zero lsp not in database");
					return ISIS_OK;
				}
			}
			/* i */
			if (!lsp) {
				lsp = lsp_new_from_recv(
					&hdr, tlvs, circuit->rcv_stream, lsp0,
					circuit->area, level);
				tlvs = NULL;
				lsp_insert(lsp,
					   circuit->area->lspdb[level - 1]);
			} else /* exists, so we overwrite */
			{
				lsp_update(lsp, &hdr, tlvs, circuit->rcv_stream,
					   circuit->area, level, false);
				tlvs = NULL;
			}
			/* ii */
			lsp_set_all_srmflags(lsp);
			/* iii */
			ISIS_CLEAR_FLAG(lsp->SRMflags, circuit);

			/* iv */
			if (circuit->circ_type != CIRCUIT_T_BROADCAST)
				ISIS_SET_FLAG(lsp->SSNflags, circuit);
			/* FIXME: v) */
		}
		/* 7.3.15.1 e) 2) LSP equal to the one in db */
		else if (comp == LSP_EQUAL) {
			ISIS_CLEAR_FLAG(lsp->SRMflags, circuit);
			lsp_update(lsp, &hdr, tlvs, circuit->rcv_stream,
				   circuit->area, level, false);
			tlvs = NULL;
			if (circuit->circ_type != CIRCUIT_T_BROADCAST)
				ISIS_SET_FLAG(lsp->SSNflags, circuit);
		}
		/* 7.3.15.1 e) 3) LSP older than the one in db */
		else {
			ISIS_SET_FLAG(lsp->SRMflags, circuit);
			ISIS_CLEAR_FLAG(lsp->SSNflags, circuit);
		}
	}

	retval = ISIS_OK;

out:
	isis_free_tlvs(tlvs);
	return retval;
}

/*
 * Process Sequence Numbers
 * ISO - 10589
 * Section 7.3.15.2 - Action on receipt of a sequence numbers PDU
 */

static int process_snp(uint8_t pdu_type, struct isis_circuit *circuit,
		       const uint8_t *ssnpa)
{
	bool is_csnp = (pdu_type == L1_COMPLETE_SEQ_NUM
			|| pdu_type == L2_COMPLETE_SEQ_NUM);
	char typechar = is_csnp ? 'C' : 'P';
	int level = (pdu_type == L1_COMPLETE_SEQ_NUM
		     || pdu_type == L1_PARTIAL_SEQ_NUM)
			    ? ISIS_LEVEL1
			    : ISIS_LEVEL2;

	uint16_t pdu_len = stream_getw(circuit->rcv_stream);
	uint8_t rem_sys_id[ISIS_SYS_ID_LEN];
	stream_get(rem_sys_id, circuit->rcv_stream, ISIS_SYS_ID_LEN);
	stream_forward_getp(circuit->rcv_stream, 1); /* Circuit ID - unused */

	uint8_t start_lsp_id[ISIS_SYS_ID_LEN + 2] = {};
	uint8_t stop_lsp_id[ISIS_SYS_ID_LEN + 2] = {};

	if (is_csnp) {
		stream_get(start_lsp_id, circuit->rcv_stream,
			   ISIS_SYS_ID_LEN + 2);
		stream_get(stop_lsp_id, circuit->rcv_stream,
			   ISIS_SYS_ID_LEN + 2);
	}

	if (pdu_len_validate(pdu_len, circuit)) {
		zlog_warn("Received a CSNP with bogus length %d", pdu_len);
		return ISIS_WARNING;
	}

	if (isis->debugs & DEBUG_SNP_PACKETS) {
		zlog_debug(
			"ISIS-Snp (%s): Rcvd L%d %cSNP on %s, cirType %s, cirID %u",
			circuit->area->area_tag, level, typechar,
			circuit->interface->name,
			circuit_t2string(circuit->is_type),
			circuit->circuit_id);
		if (isis->debugs & DEBUG_PACKET_DUMP)
			zlog_dump_data(STREAM_DATA(circuit->rcv_stream),
				       stream_get_endp(circuit->rcv_stream));
	}

	/* 7.3.15.2 a) 1 - external domain circuit will discard snp pdu */
	if (circuit->ext_domain) {

		zlog_debug(
			"ISIS-Snp (%s): Rcvd L%d %cSNP on %s, "
			"skipping: circuit externalDomain = true",
			circuit->area->area_tag, level, typechar,
			circuit->interface->name);

		return ISIS_OK;
	}

	/* 7.3.15.2 a) 2,3 - manualL2OnlyMode not implemented */
	if (!(circuit->is_type & level)) {
		zlog_debug(
			"ISIS-Snp (%s): Rcvd L%d %cSNP on %s, "
			"skipping: circuit type %s does not match level %d",
			circuit->area->area_tag, level, typechar,
			circuit->interface->name,
			circuit_t2string(circuit->is_type), level);

		return ISIS_OK;
	}

	/* 7.3.15.2 a) 4 - not applicable for CSNP  only PSNPs on broadcast */
	if (!is_csnp && (circuit->circ_type == CIRCUIT_T_BROADCAST)
	    && !circuit->u.bc.is_dr[level - 1]) {
		zlog_debug(
			"ISIS-Snp (%s): Rcvd L%d %cSNP from %s on %s, "
			"skipping: we are not the DIS",
			circuit->area->area_tag, level, typechar,
			snpa_print(ssnpa), circuit->interface->name);

		return ISIS_OK;
	}

	/* 7.3.15.2 a) 5 - need to make sure IDLength matches - already checked
	 */

	/* 7.3.15.2 a) 6 - maximum area match, can be ommited since we only use
	 * 3
	 * - already checked */

	/* 7.3.15.2 a) 7 - Must check that we have an adjacency of the same
	 * level  */
	/* for broadcast circuits, snpa should be compared */
	/* FIXME : Do we need to check SNPA? */
	if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
		if (!isis_adj_lookup(rem_sys_id,
				     circuit->u.bc.adjdb[level - 1]))
			return ISIS_OK; /* Silently discard */
	} else {
		if (!circuit->u.p2p.neighbor) {
			zlog_warn("no p2p neighbor on circuit %s",
				  circuit->interface->name);
			return ISIS_OK; /* Silently discard */
		}
	}

	struct isis_tlvs *tlvs;
	int retval = ISIS_WARNING;
	const char *error_log;

	if (isis_unpack_tlvs(STREAM_READABLE(circuit->rcv_stream),
			     circuit->rcv_stream, &tlvs, &error_log)) {
		zlog_warn("Something went wrong unpacking the SNP: %s",
			  error_log);
		goto out;
	}

	struct isis_passwd *passwd = (level == IS_LEVEL_1)
					     ? &circuit->area->area_passwd
					     : &circuit->area->domain_passwd;
	if (CHECK_FLAG(passwd->snp_auth, SNP_AUTH_RECV)
	    && !isis_tlvs_auth_is_valid(tlvs, passwd, circuit->rcv_stream,
					false)) {
		isis_event_auth_failure(circuit->area->area_tag,
					"SNP authentication failure",
					rem_sys_id);
		goto out;
	}

	struct isis_lsp_entry *entry_head =
		(struct isis_lsp_entry *)tlvs->lsp_entries.head;

	/* debug isis snp-packets */
	if (isis->debugs & DEBUG_SNP_PACKETS) {
		zlog_debug("ISIS-Snp (%s): Rcvd L%d %cSNP from %s on %s",
			   circuit->area->area_tag, level, typechar,
			   snpa_print(ssnpa), circuit->interface->name);
		for (struct isis_lsp_entry *entry = entry_head; entry;
		     entry = entry->next) {
			zlog_debug(
				"ISIS-Snp (%s):         %cSNP entry %s, seq 0x%08" PRIx32
				", cksum 0x%04" PRIx16 ", lifetime %" PRIu16 "s",
				circuit->area->area_tag, typechar,
				rawlspid_print(entry->id), entry->seqno,
				entry->checksum, entry->rem_lifetime);
		}
	}

	/* 7.3.15.2 b) Actions on LSP_ENTRIES reported */
	for (struct isis_lsp_entry *entry = entry_head; entry;
	     entry = entry->next) {
		struct isis_lsp *lsp =
			lsp_search(entry->id, circuit->area->lspdb[level - 1]);
		bool own_lsp = !memcmp(entry->id, isis->sysid, ISIS_SYS_ID_LEN);
		if (lsp) {
			/* 7.3.15.2 b) 1) is this LSP newer */
			int cmp = lsp_compare(circuit->area->area_tag, lsp,
					      entry->seqno, entry->checksum,
					      entry->rem_lifetime);
			/* 7.3.15.2 b) 2) if it equals, clear SRM on p2p */
			if (cmp == LSP_EQUAL) {
				/* if (circuit->circ_type !=
				 * CIRCUIT_T_BROADCAST) */
				ISIS_CLEAR_FLAG(lsp->SRMflags, circuit);
			}
			/* 7.3.15.2 b) 3) if it is older, clear SSN and set SRM
			   */
			else if (cmp == LSP_OLDER) {
				ISIS_CLEAR_FLAG(lsp->SSNflags, circuit);
				ISIS_SET_FLAG(lsp->SRMflags, circuit);
			}
			/* 7.3.15.2 b) 4) if it is newer, set SSN and clear SRM
			   on p2p */
			else {
				if (own_lsp) {
					lsp_inc_seqno(lsp, entry->seqno);
					ISIS_SET_FLAG(lsp->SRMflags, circuit);
				} else {
					ISIS_SET_FLAG(lsp->SSNflags, circuit);
					/* if (circuit->circ_type !=
					 * CIRCUIT_T_BROADCAST) */
					ISIS_CLEAR_FLAG(lsp->SRMflags, circuit);
				}
			}
		} else {
			/* 7.3.15.2 b) 5) if it was not found, and all of those
			 * are not 0,
			 * insert it and set SSN on it */
			if (entry->rem_lifetime && entry->checksum
			    && entry->seqno && memcmp(entry->id, isis->sysid,
						      ISIS_SYS_ID_LEN)) {
				struct isis_lsp *lsp0 = NULL;

				if (LSP_FRAGMENT(entry->id)) {
					uint8_t lspid[ISIS_SYS_ID_LEN + 2];

					memcpy(lspid, entry->id,
					       ISIS_SYS_ID_LEN + 1);
					LSP_FRAGMENT(lspid) = 0;
					lsp0 = lsp_search(
						  lspid,
						  circuit->area->lspdb[level - 1]);
					if (!lsp0) {
						zlog_debug("Got lsp frag in snp, while zero not in database");
						continue;
					}
				}
				struct isis_lsp *lsp =
					lsp_new(circuit->area, entry->id,
						entry->rem_lifetime, 0, 0,
						entry->checksum, lsp0, level);
				lsp_insert(lsp,
					   circuit->area->lspdb[level - 1]);
				ISIS_FLAGS_CLEAR_ALL(lsp->SRMflags);
				ISIS_SET_FLAG(lsp->SSNflags, circuit);
			}
		}
	}

	/* 7.3.15.2 c) on CSNP set SRM for all in range which were not reported
	 */
	if (is_csnp) {
		/*
		 * Build a list from our own LSP db bounded with
		 * start_lsp_id and stop_lsp_id
		 */
		struct list *lsp_list = list_new();
		lsp_build_list_nonzero_ht(start_lsp_id, stop_lsp_id, lsp_list,
					  circuit->area->lspdb[level - 1]);

		/* Fixme: Find a better solution */
		struct listnode *node, *nnode;
		struct isis_lsp *lsp;
		for (struct isis_lsp_entry *entry = entry_head; entry;
		     entry = entry->next) {
			for (ALL_LIST_ELEMENTS(lsp_list, node, nnode, lsp)) {
				if (lsp_id_cmp(lsp->hdr.lsp_id, entry->id)
				    == 0) {
					list_delete_node(lsp_list, node);
					break;
				}
			}
		}

		/* on remaining LSPs we set SRM (neighbor knew not of) */
		for (ALL_LIST_ELEMENTS_RO(lsp_list, node, lsp))
			ISIS_SET_FLAG(lsp->SRMflags, circuit);
		/* lets free it */
		list_delete_and_null(&lsp_list);
	}

	retval = ISIS_OK;
out:
	isis_free_tlvs(tlvs);
	return retval;
}

static int pdu_size(uint8_t pdu_type, uint8_t *size)
{
	switch (pdu_type) {
	case L1_LAN_HELLO:
	case L2_LAN_HELLO:
		*size = ISIS_LANHELLO_HDRLEN;
		break;
	case P2P_HELLO:
		*size = ISIS_P2PHELLO_HDRLEN;
		break;
	case L1_LINK_STATE:
	case L2_LINK_STATE:
		*size = ISIS_LSP_HDR_LEN;
		break;
	case L1_COMPLETE_SEQ_NUM:
	case L2_COMPLETE_SEQ_NUM:
		*size = ISIS_CSNP_HDRLEN;
		break;
	case L1_PARTIAL_SEQ_NUM:
	case L2_PARTIAL_SEQ_NUM:
		*size = ISIS_PSNP_HDRLEN;
		break;
	default:
		return 1;
	}
	*size += ISIS_FIXED_HDR_LEN;
	return 0;
}

/*
 * PDU Dispatcher
 */

int isis_handle_pdu(struct isis_circuit *circuit, uint8_t *ssnpa)
{
	int retval = ISIS_OK;

	/* Verify that at least the 8 bytes fixed header have been received */
	if (stream_get_endp(circuit->rcv_stream) < ISIS_FIXED_HDR_LEN) {
		zlog_err("PDU is too short to be IS-IS.");
		return ISIS_ERROR;
	}

	uint8_t idrp = stream_getc(circuit->rcv_stream);
	uint8_t length = stream_getc(circuit->rcv_stream);
	uint8_t version1 = stream_getc(circuit->rcv_stream);
	uint8_t id_len = stream_getc(circuit->rcv_stream);
	uint8_t pdu_type = stream_getc(circuit->rcv_stream)
			   & 0x1f; /* bits 6-8 are reserved */
	uint8_t version2 = stream_getc(circuit->rcv_stream);
	stream_forward_getp(circuit->rcv_stream, 1); /* reserved */
	uint8_t max_area_addrs = stream_getc(circuit->rcv_stream);

	if (idrp == ISO9542_ESIS) {
		zlog_err("No support for ES-IS packet IDRP=%" PRIx8, idrp);
		return ISIS_ERROR;
	}

	if (idrp != ISO10589_ISIS) {
		zlog_err("Not an IS-IS packet IDRP=%" PRIx8, idrp);
		return ISIS_ERROR;
	}

	if (version1 != 1) {
		zlog_warn("Unsupported ISIS version %" PRIu8, version1);
		return ISIS_WARNING;
	}

	if (id_len != 0 && id_len != ISIS_SYS_ID_LEN) {
		zlog_err(
			"IDFieldLengthMismatch: ID Length field in a received PDU  %" PRIu8
			", while the parameter for this IS is %u",
			id_len, ISIS_SYS_ID_LEN);
		return ISIS_ERROR;
	}

	uint8_t expected_length;
	if (pdu_size(pdu_type, &expected_length)) {
		zlog_warn("Unsupported ISIS PDU %" PRIu8, pdu_type);
		return ISIS_WARNING;
	}

	if (length != expected_length) {
		zlog_err("Exepected fixed header length = %" PRIu8
			 " but got %" PRIu8,
			 expected_length, length);
		return ISIS_ERROR;
	}

	if (stream_get_endp(circuit->rcv_stream) < length) {
		zlog_err(
			"PDU is too short to contain fixed header of given PDU type.");
		return ISIS_ERROR;
	}

	if (version2 != 1) {
		zlog_warn("Unsupported ISIS PDU version %" PRIu8, version2);
		return ISIS_WARNING;
	}

	if (circuit->is_passive) {
		zlog_warn("Received ISIS PDU on passive circuit %s",
			  circuit->interface->name);
		return ISIS_WARNING;
	}

	/* either 3 or 0 */
	if (max_area_addrs != 0 && max_area_addrs != isis->max_area_addrs) {
		zlog_err(
			"maximumAreaAddressesMismatch: maximumAreaAdresses in a received PDU %" PRIu8
			" while the parameter for this IS is %u",
			max_area_addrs, isis->max_area_addrs);
		return ISIS_ERROR;
	}

	switch (pdu_type) {
	case L1_LAN_HELLO:
	case L2_LAN_HELLO:
	case P2P_HELLO:
		retval = process_hello(pdu_type, circuit, ssnpa);
		break;
	case L1_LINK_STATE:
	case L2_LINK_STATE:
		retval = process_lsp(pdu_type, circuit, ssnpa);
		break;
	case L1_COMPLETE_SEQ_NUM:
	case L2_COMPLETE_SEQ_NUM:
	case L1_PARTIAL_SEQ_NUM:
	case L2_PARTIAL_SEQ_NUM:
		retval = process_snp(pdu_type, circuit, ssnpa);
		break;
	default:
		return ISIS_ERROR;
	}

	return retval;
}

int isis_receive(struct thread *thread)
{
	struct isis_circuit *circuit;
	uint8_t ssnpa[ETH_ALEN];
	int retval;

	/*
	 * Get the circuit
	 */
	circuit = THREAD_ARG(thread);
	assert(circuit);

	circuit->t_read = NULL;

	isis_circuit_stream(circuit, &circuit->rcv_stream);

	retval = circuit->rx(circuit, ssnpa);

#if ISIS_METHOD != ISIS_METHOD_BPF
	if (retval == ISIS_OK)
		retval = isis_handle_pdu(circuit, ssnpa);
#endif //ISIS_METHOD != ISIS_METHOD_BPF

	/*
	 * prepare for next packet.
	 */
	if (!circuit->is_passive)
		isis_circuit_prepare(circuit);

	return retval;
}

/*
 * SEND SIDE
 */
void fill_fixed_hdr(uint8_t pdu_type, struct stream *stream)
{
	uint8_t length;

	if (pdu_size(pdu_type, &length))
		assert(!"Unknown PDU Type");

	stream_putc(stream, ISO10589_ISIS); /* IDRP */
	stream_putc(stream, length);	/* Length of fixed header */
	stream_putc(stream, 1); /* Version/Protocol ID Extension 1 */
	stream_putc(stream, 0); /* ID Length, 0 => 6 */
	stream_putc(stream, pdu_type);
	stream_putc(stream, 1); /* Subversion */
	stream_putc(stream, 0); /* Reserved */
	stream_putc(stream, 0); /* Max Area Addresses 0 => 3 */
}

static void put_hello_hdr(struct isis_circuit *circuit, int level,
			  size_t *len_pointer)
{
	uint8_t pdu_type;

	if (circuit->circ_type == CIRCUIT_T_BROADCAST)
		pdu_type = (level == IS_LEVEL_1) ? L1_LAN_HELLO : L2_LAN_HELLO;
	else
		pdu_type = P2P_HELLO;

	isis_circuit_stream(circuit, &circuit->snd_stream);
	fill_fixed_hdr(pdu_type, circuit->snd_stream);

	stream_putc(circuit->snd_stream, circuit->is_type);
	stream_put(circuit->snd_stream, circuit->area->isis->sysid,
		   ISIS_SYS_ID_LEN);

	uint32_t holdtime = circuit->hello_multiplier[level - 1]
			    * circuit->hello_interval[level - 1];

	if (holdtime > 0xffff)
		holdtime = 0xffff;

	stream_putw(circuit->snd_stream, holdtime);
	*len_pointer = stream_get_endp(circuit->snd_stream);
	stream_putw(circuit->snd_stream, 0); /* length is filled in later */

	if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
		uint8_t *desig_is = (level == IS_LEVEL_1)
					    ? circuit->u.bc.l1_desig_is
					    : circuit->u.bc.l2_desig_is;
		stream_putc(circuit->snd_stream, circuit->priority[level - 1]);
		stream_put(circuit->snd_stream, desig_is, ISIS_SYS_ID_LEN + 1);
	} else {
		stream_putc(circuit->snd_stream, circuit->circuit_id);
	}
}

int send_hello(struct isis_circuit *circuit, int level)
{
	size_t len_pointer;
	int retval;

	if (circuit->is_passive)
		return ISIS_OK;

	if (circuit->interface->mtu == 0) {
		zlog_warn("circuit has zero MTU");
		return ISIS_WARNING;
	}

	put_hello_hdr(circuit, level, &len_pointer);

	struct isis_tlvs *tlvs = isis_alloc_tlvs();

	isis_tlvs_add_auth(tlvs, &circuit->passwd);

	if (!listcount(circuit->area->area_addrs)) {
		isis_free_tlvs(tlvs);
		return ISIS_WARNING;
	}

	isis_tlvs_add_area_addresses(tlvs, circuit->area->area_addrs);

	if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
		isis_tlvs_add_lan_neighbors(
			tlvs, circuit->u.bc.lan_neighs[level - 1]);
	} else if (circuit->circ_type == CIRCUIT_T_P2P
		   && !circuit->disable_threeway_adj) {
		uint32_t ext_circuit_id = circuit->idx;
		if (circuit->u.p2p.neighbor) {
			isis_tlvs_add_threeway_adj(tlvs,
					circuit->u.p2p.neighbor->threeway_state,
					ext_circuit_id,
					circuit->u.p2p.neighbor->sysid,
					circuit->u.p2p.neighbor->ext_circuit_id);
		} else {
			isis_tlvs_add_threeway_adj(tlvs,
					ISIS_THREEWAY_DOWN,
					ext_circuit_id,
					NULL, 0);
		}
	}

	isis_tlvs_set_protocols_supported(tlvs, &circuit->nlpids);

	/*
	 * MT Supported TLV
	 *
	 * TLV gets included if no topology is enabled on the interface,
	 * if one topology other than #0 is enabled, or if multiple topologies
	 * are enabled.
	 */
	struct isis_circuit_mt_setting **mt_settings;
	unsigned int mt_count;

	mt_settings = circuit_mt_settings(circuit, &mt_count);
	if (mt_count == 0 && area_is_mt(circuit->area)) {
		tlvs->mt_router_info_empty = true;
	} else if ((mt_count == 1
		    && mt_settings[0]->mtid != ISIS_MT_IPV4_UNICAST)
		   || (mt_count > 1)) {
		for (unsigned int i = 0; i < mt_count; i++)
			isis_tlvs_add_mt_router_info(tlvs, mt_settings[i]->mtid,
						     false, false);
	}

	if (circuit->ip_router && circuit->ip_addrs)
		isis_tlvs_add_ipv4_addresses(tlvs, circuit->ip_addrs);

	if (circuit->ipv6_router && circuit->ipv6_link)
		isis_tlvs_add_ipv6_addresses(tlvs, circuit->ipv6_link);

	if (isis_pack_tlvs(tlvs, circuit->snd_stream, len_pointer,
			   circuit->pad_hellos, false)) {
		isis_free_tlvs(tlvs);
		return ISIS_WARNING; /* XXX: Maybe Log TLV structure? */
	}

	if (isis->debugs & DEBUG_ADJ_PACKETS) {
		if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
			zlog_debug(
				"ISIS-Adj (%s): Sending L%d LAN IIH on %s, length %zd",
				circuit->area->area_tag, level,
				circuit->interface->name,
				stream_get_endp(circuit->snd_stream));
		} else {
			zlog_debug(
				"ISIS-Adj (%s): Sending P2P IIH on %s, length %zd",
				circuit->area->area_tag,
				circuit->interface->name,
				stream_get_endp(circuit->snd_stream));
		}
		if (isis->debugs & DEBUG_PACKET_DUMP)
			zlog_dump_data(STREAM_DATA(circuit->snd_stream),
				       stream_get_endp(circuit->snd_stream));
	}

	isis_free_tlvs(tlvs);

	retval = circuit->tx(circuit, level);
	if (retval != ISIS_OK)
		zlog_err("ISIS-Adj (%s): Send L%d IIH on %s failed",
			 circuit->area->area_tag, level,
			 circuit->interface->name);

	return retval;
}

int send_lan_l1_hello(struct thread *thread)
{
	struct isis_circuit *circuit;
	int retval;

	circuit = THREAD_ARG(thread);
	assert(circuit);
	circuit->u.bc.t_send_lan_hello[0] = NULL;

	if (!(circuit->area->is_type & IS_LEVEL_1)) {
		zlog_warn(
			"ISIS-Hello (%s): Trying to send L1 IIH in L2-only area",
			circuit->area->area_tag);
		return 1;
	}

	if (circuit->u.bc.run_dr_elect[0])
		isis_dr_elect(circuit, 1);

	retval = send_hello(circuit, 1);

	/* set next timer thread */
	thread_add_timer(master, send_lan_l1_hello, circuit,
			 isis_jitter(circuit->hello_interval[0], IIH_JITTER),
			 &circuit->u.bc.t_send_lan_hello[0]);

	return retval;
}

int send_lan_l2_hello(struct thread *thread)
{
	struct isis_circuit *circuit;
	int retval;

	circuit = THREAD_ARG(thread);
	assert(circuit);
	circuit->u.bc.t_send_lan_hello[1] = NULL;

	if (!(circuit->area->is_type & IS_LEVEL_2)) {
		zlog_warn("ISIS-Hello (%s): Trying to send L2 IIH in L1 area",
			  circuit->area->area_tag);
		return 1;
	}

	if (circuit->u.bc.run_dr_elect[1])
		isis_dr_elect(circuit, 2);

	retval = send_hello(circuit, 2);

	/* set next timer thread */
	thread_add_timer(master, send_lan_l2_hello, circuit,
			 isis_jitter(circuit->hello_interval[1], IIH_JITTER),
			 &circuit->u.bc.t_send_lan_hello[1]);

	return retval;
}

int send_p2p_hello(struct thread *thread)
{
	struct isis_circuit *circuit;

	circuit = THREAD_ARG(thread);
	assert(circuit);
	circuit->u.p2p.t_send_p2p_hello = NULL;

	send_hello(circuit, 1);

	/* set next timer thread */
	thread_add_timer(master, send_p2p_hello, circuit,
			 isis_jitter(circuit->hello_interval[1], IIH_JITTER),
			 &circuit->u.p2p.t_send_p2p_hello);

	return ISIS_OK;
}

/*
 * Count the maximum number of lsps that can be accomodated by a given size.
 */
#define LSP_ENTRIES_LEN (10 + ISIS_SYS_ID_LEN)
static uint16_t get_max_lsp_count(uint16_t size)
{
	uint16_t tlv_count;
	uint16_t lsp_count;
	uint16_t remaining_size;

	/* First count the full size TLVs */
	tlv_count = size / MAX_LSP_ENTRIES_TLV_SIZE;
	lsp_count = tlv_count * (MAX_LSP_ENTRIES_TLV_SIZE / LSP_ENTRIES_LEN);

	/* The last TLV, if any */
	remaining_size = size % MAX_LSP_ENTRIES_TLV_SIZE;
	if (remaining_size - 2 >= LSP_ENTRIES_LEN)
		lsp_count += (remaining_size - 2) / LSP_ENTRIES_LEN;

	return lsp_count;
}

int send_csnp(struct isis_circuit *circuit, int level)
{
	if (circuit->area->lspdb[level - 1] == NULL
	    || dict_count(circuit->area->lspdb[level - 1]) == 0)
		return ISIS_OK;

	isis_circuit_stream(circuit, &circuit->snd_stream);
	fill_fixed_hdr((level == ISIS_LEVEL1) ? L1_COMPLETE_SEQ_NUM
					      : L2_COMPLETE_SEQ_NUM,
		       circuit->snd_stream);

	size_t len_pointer = stream_get_endp(circuit->snd_stream);
	stream_putw(circuit->snd_stream, 0);
	stream_put(circuit->snd_stream, isis->sysid, ISIS_SYS_ID_LEN);
	/* with zero circuit id - ref 9.10, 9.11 */
	stream_putc(circuit->snd_stream, 0);

	size_t start_pointer = stream_get_endp(circuit->snd_stream);
	stream_put(circuit->snd_stream, 0, ISIS_SYS_ID_LEN + 2);
	size_t end_pointer = stream_get_endp(circuit->snd_stream);
	stream_put(circuit->snd_stream, 0, ISIS_SYS_ID_LEN + 2);

	struct isis_passwd *passwd = (level == ISIS_LEVEL1)
					     ? &circuit->area->area_passwd
					     : &circuit->area->domain_passwd;

	struct isis_tlvs *tlvs = isis_alloc_tlvs();

	if (CHECK_FLAG(passwd->snp_auth, SNP_AUTH_SEND))
		isis_tlvs_add_auth(tlvs, passwd);

	size_t tlv_start = stream_get_endp(circuit->snd_stream);
	if (isis_pack_tlvs(tlvs, circuit->snd_stream, len_pointer, false,
			   false)) {
		isis_free_tlvs(tlvs);
		return ISIS_WARNING;
	}
	isis_free_tlvs(tlvs);

	uint16_t num_lsps =
		get_max_lsp_count(STREAM_WRITEABLE(circuit->snd_stream));

	uint8_t start[ISIS_SYS_ID_LEN + 2];
	memset(start, 0x00, ISIS_SYS_ID_LEN + 2);
	uint8_t stop[ISIS_SYS_ID_LEN + 2];
	memset(stop, 0xff, ISIS_SYS_ID_LEN + 2);

	bool loop = true;
	while (loop) {
		tlvs = isis_alloc_tlvs();
		if (CHECK_FLAG(passwd->snp_auth, SNP_AUTH_SEND))
			isis_tlvs_add_auth(tlvs, passwd);

		struct isis_lsp *last_lsp;
		isis_tlvs_add_csnp_entries(tlvs, start, stop, num_lsps,
					   circuit->area->lspdb[level - 1],
					   &last_lsp);
		/*
		 * Update the stop lsp_id before encoding this CSNP.
		 */
		if (tlvs->lsp_entries.count < num_lsps) {
			memset(stop, 0xff, ISIS_SYS_ID_LEN + 2);
		} else {
			memcpy(stop, last_lsp->hdr.lsp_id, sizeof(stop));
		}

		memcpy(STREAM_DATA(circuit->snd_stream) + start_pointer, start,
		       ISIS_SYS_ID_LEN + 2);
		memcpy(STREAM_DATA(circuit->snd_stream) + end_pointer, stop,
		       ISIS_SYS_ID_LEN + 2);
		stream_set_endp(circuit->snd_stream, tlv_start);
		if (isis_pack_tlvs(tlvs, circuit->snd_stream, len_pointer,
				   false, false)) {
			isis_free_tlvs(tlvs);
			return ISIS_WARNING;
		}

		if (isis->debugs & DEBUG_SNP_PACKETS) {
			zlog_debug(
				"ISIS-Snp (%s): Sending L%d CSNP on %s, length %zd",
				circuit->area->area_tag, level,
				circuit->interface->name,
				stream_get_endp(circuit->snd_stream));
			log_multiline(LOG_DEBUG, "              ", "%s",
				      isis_format_tlvs(tlvs));
			if (isis->debugs & DEBUG_PACKET_DUMP)
				zlog_dump_data(
					STREAM_DATA(circuit->snd_stream),
					stream_get_endp(circuit->snd_stream));
		}

		int retval = circuit->tx(circuit, level);
		if (retval != ISIS_OK) {
			zlog_err("ISIS-Snp (%s): Send L%d CSNP on %s failed",
				 circuit->area->area_tag, level,
				 circuit->interface->name);
			isis_free_tlvs(tlvs);
			return retval;
		}

		/*
		 * Start lsp_id of the next CSNP should be one plus the
		 * stop lsp_id in this current CSNP.
		 */
		memcpy(start, stop, ISIS_SYS_ID_LEN + 2);
		loop = 0;
		for (int i = ISIS_SYS_ID_LEN + 1; i >= 0; --i) {
			if (start[i] < (uint8_t)0xff) {
				start[i] += 1;
				loop = 1;
				break;
			}
		}
		memset(stop, 0xff, ISIS_SYS_ID_LEN + 2);
		isis_free_tlvs(tlvs);
	}

	return ISIS_OK;
}

int send_l1_csnp(struct thread *thread)
{
	struct isis_circuit *circuit;
	int retval = ISIS_OK;

	circuit = THREAD_ARG(thread);
	assert(circuit);

	circuit->t_send_csnp[0] = NULL;

	if (circuit->circ_type == CIRCUIT_T_BROADCAST
	    && circuit->u.bc.is_dr[0]) {
		send_csnp(circuit, 1);
	}
	/* set next timer thread */
	thread_add_timer(master, send_l1_csnp, circuit,
			 isis_jitter(circuit->csnp_interval[0], CSNP_JITTER),
			 &circuit->t_send_csnp[0]);

	return retval;
}

int send_l2_csnp(struct thread *thread)
{
	struct isis_circuit *circuit;
	int retval = ISIS_OK;

	circuit = THREAD_ARG(thread);
	assert(circuit);

	circuit->t_send_csnp[1] = NULL;

	if (circuit->circ_type == CIRCUIT_T_BROADCAST
	    && circuit->u.bc.is_dr[1]) {
		send_csnp(circuit, 2);
	}
	/* set next timer thread */
	thread_add_timer(master, send_l2_csnp, circuit,
			 isis_jitter(circuit->csnp_interval[1], CSNP_JITTER),
			 &circuit->t_send_csnp[1]);

	return retval;
}

/*
 *  7.3.15.4 action on expiration of partial SNP interval
 *  level 1
 */
static int send_psnp(int level, struct isis_circuit *circuit)
{
	if (circuit->circ_type == CIRCUIT_T_BROADCAST
	    && circuit->u.bc.is_dr[level - 1])
		return ISIS_OK;

	if (circuit->area->lspdb[level - 1] == NULL
	    || dict_count(circuit->area->lspdb[level - 1]) == 0)
		return ISIS_OK;

	if (!circuit->snd_stream)
		return ISIS_ERROR;

	isis_circuit_stream(circuit, &circuit->snd_stream);
	fill_fixed_hdr((level == ISIS_LEVEL1) ? L1_PARTIAL_SEQ_NUM
					      : L2_PARTIAL_SEQ_NUM,
		       circuit->snd_stream);

	size_t len_pointer = stream_get_endp(circuit->snd_stream);
	stream_putw(circuit->snd_stream, 0); /* length is filled in later */
	stream_put(circuit->snd_stream, isis->sysid, ISIS_SYS_ID_LEN);
	stream_putc(circuit->snd_stream, circuit->idx);

	struct isis_passwd *passwd = (level == ISIS_LEVEL1)
					     ? &circuit->area->area_passwd
					     : &circuit->area->domain_passwd;

	struct isis_tlvs *tlvs = isis_alloc_tlvs();

	if (CHECK_FLAG(passwd->snp_auth, SNP_AUTH_SEND))
		isis_tlvs_add_auth(tlvs, passwd);

	size_t tlv_start = stream_get_endp(circuit->snd_stream);
	if (isis_pack_tlvs(tlvs, circuit->snd_stream, len_pointer, false,
			   false)) {
		isis_free_tlvs(tlvs);
		return ISIS_WARNING;
	}
	isis_free_tlvs(tlvs);

	uint16_t num_lsps =
		get_max_lsp_count(STREAM_WRITEABLE(circuit->snd_stream));

	while (1) {
		tlvs = isis_alloc_tlvs();
		if (CHECK_FLAG(passwd->snp_auth, SNP_AUTH_SEND))
			isis_tlvs_add_auth(tlvs, passwd);

		for (dnode_t *dnode =
			     dict_first(circuit->area->lspdb[level - 1]);
		     dnode; dnode = dict_next(circuit->area->lspdb[level - 1],
					      dnode)) {
			struct isis_lsp *lsp = dnode_get(dnode);

			if (ISIS_CHECK_FLAG(lsp->SSNflags, circuit))
				isis_tlvs_add_lsp_entry(tlvs, lsp);

			if (tlvs->lsp_entries.count == num_lsps)
				break;
		}

		if (!tlvs->lsp_entries.count) {
			isis_free_tlvs(tlvs);
			return ISIS_OK;
		}

		stream_set_endp(circuit->snd_stream, tlv_start);
		if (isis_pack_tlvs(tlvs, circuit->snd_stream, len_pointer,
				   false, false)) {
			isis_free_tlvs(tlvs);
			return ISIS_WARNING;
		}

		if (isis->debugs & DEBUG_SNP_PACKETS) {
			zlog_debug(
				"ISIS-Snp (%s): Sending L%d PSNP on %s, length %zd",
				circuit->area->area_tag, level,
				circuit->interface->name,
				stream_get_endp(circuit->snd_stream));
			log_multiline(LOG_DEBUG, "              ", "%s",
				      isis_format_tlvs(tlvs));
			if (isis->debugs & DEBUG_PACKET_DUMP)
				zlog_dump_data(
					STREAM_DATA(circuit->snd_stream),
					stream_get_endp(circuit->snd_stream));
		}

		int retval = circuit->tx(circuit, level);
		if (retval != ISIS_OK) {
			zlog_err("ISIS-Snp (%s): Send L%d PSNP on %s failed",
				 circuit->area->area_tag, level,
				 circuit->interface->name);
			isis_free_tlvs(tlvs);
			return retval;
		}

		/*
		 * sending succeeded, we can clear SSN flags of this circuit
		 * for the LSPs in list
		 */
		struct isis_lsp_entry *entry_head;
		entry_head = (struct isis_lsp_entry *)tlvs->lsp_entries.head;
		for (struct isis_lsp_entry *entry = entry_head; entry;
		     entry = entry->next)
			ISIS_CLEAR_FLAG(entry->lsp->SSNflags, circuit);
		isis_free_tlvs(tlvs);
	}

	return ISIS_OK;
}

int send_l1_psnp(struct thread *thread)
{

	struct isis_circuit *circuit;
	int retval = ISIS_OK;

	circuit = THREAD_ARG(thread);
	assert(circuit);

	circuit->t_send_psnp[0] = NULL;

	send_psnp(1, circuit);
	/* set next timer thread */
	thread_add_timer(master, send_l1_psnp, circuit,
			 isis_jitter(circuit->psnp_interval[0], PSNP_JITTER),
			 &circuit->t_send_psnp[0]);

	return retval;
}

/*
 *  7.3.15.4 action on expiration of partial SNP interval
 *  level 2
 */
int send_l2_psnp(struct thread *thread)
{
	struct isis_circuit *circuit;
	int retval = ISIS_OK;

	circuit = THREAD_ARG(thread);
	assert(circuit);

	circuit->t_send_psnp[1] = NULL;

	send_psnp(2, circuit);

	/* set next timer thread */
	thread_add_timer(master, send_l2_psnp, circuit,
			 isis_jitter(circuit->psnp_interval[1], PSNP_JITTER),
			 &circuit->t_send_psnp[1]);

	return retval;
}

/*
 * ISO 10589 - 7.3.14.3
 */
int send_lsp(struct thread *thread)
{
	struct isis_circuit *circuit;
	struct isis_lsp *lsp;
	int clear_srm = 1;
	int retval = ISIS_OK;

	circuit = THREAD_ARG(thread);
	assert(circuit);
	circuit->t_send_lsp = NULL;

	lsp = isis_circuit_lsp_queue_pop(circuit);
	if (!lsp)
		return ISIS_OK;

	if (!list_isempty(circuit->lsp_queue)) {
		isis_circuit_schedule_lsp_send(circuit);
	}

	if (circuit->state != C_STATE_UP || circuit->is_passive == 1)
		goto out;

	/*
	 * Do not send if levels do not match
	 */
	if (!(lsp->level & circuit->is_type))
		goto out;

	/*
	 * Do not send if we do not have adjacencies in state up on the circuit
	 */
	if (circuit->upadjcount[lsp->level - 1] == 0)
		goto out;

	/* stream_copy will assert and stop program execution if LSP is larger
	 * than
	 * the circuit's MTU. So handle and log this case here. */
	if (stream_get_endp(lsp->pdu) > stream_get_size(circuit->snd_stream)) {
		zlog_err(
			"ISIS-Upd (%s): Can't send L%d LSP %s, seq 0x%08" PRIx32
			", cksum 0x%04" PRIx16 ", lifetime %" PRIu16
			"s on %s. LSP Size is %zu while interface stream size is %zu.",
			circuit->area->area_tag, lsp->level,
			rawlspid_print(lsp->hdr.lsp_id), lsp->hdr.seqno,
			lsp->hdr.checksum, lsp->hdr.rem_lifetime,
			circuit->interface->name, stream_get_endp(lsp->pdu),
			stream_get_size(circuit->snd_stream));
		if (isis->debugs & DEBUG_PACKET_DUMP)
			zlog_dump_data(STREAM_DATA(lsp->pdu),
				       stream_get_endp(lsp->pdu));
		retval = ISIS_ERROR;
		goto out;
	}

	/* copy our lsp to the send buffer */
	stream_copy(circuit->snd_stream, lsp->pdu);

	if (isis->debugs & DEBUG_UPDATE_PACKETS) {
		zlog_debug("ISIS-Upd (%s): Sending L%d LSP %s, seq 0x%08" PRIx32
			   ", cksum 0x%04" PRIx16 ", lifetime %" PRIu16
			   "s on %s",
			   circuit->area->area_tag, lsp->level,
			   rawlspid_print(lsp->hdr.lsp_id), lsp->hdr.seqno,
			   lsp->hdr.checksum, lsp->hdr.rem_lifetime,
			   circuit->interface->name);
		if (isis->debugs & DEBUG_PACKET_DUMP)
			zlog_dump_data(STREAM_DATA(circuit->snd_stream),
				       stream_get_endp(circuit->snd_stream));
	}

	clear_srm = 0;
	retval = circuit->tx(circuit, lsp->level);
	if (retval != ISIS_OK) {
		zlog_err("ISIS-Upd (%s): Send L%d LSP on %s failed %s",
			 circuit->area->area_tag, lsp->level,
			 circuit->interface->name,
			 (retval == ISIS_WARNING) ? "temporarily"
						  : "permanently");
	}

out:
	if (clear_srm
	    || (retval == ISIS_OK && circuit->circ_type == CIRCUIT_T_BROADCAST)
	    || (retval != ISIS_OK && retval != ISIS_WARNING)) {
		/* SRM flag will trigger retransmission. We will not retransmit
		 * if we
		 * encountered a fatal error.
		 * On success, they should only be cleared if it's a broadcast
		 * circuit.
		 * On a P2P circuit, we will wait for the ack from the neighbor
		 * to clear
		 * the fag.
		 */
		ISIS_CLEAR_FLAG(lsp->SRMflags, circuit);
	}

	return retval;
}
