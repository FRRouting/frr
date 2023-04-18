// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_pdu.c
 *                             PDU processing
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */

#include <zebra.h>

#include "memory.h"
#include "frrevent.h"
#include "linklist.h"
#include "log.h"
#include "stream.h"
#include "vty.h"
#include "hash.h"
#include "prefix.h"
#include "if.h"
#include "checksum.h"
#include "md5.h"
#include "lib_errors.h"

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
#include "isisd/isis_errors.h"
#include "isisd/fabricd.h"
#include "isisd/isis_tx_queue.h"
#include "isisd/isis_pdu_counter.h"
#include "isisd/isis_nb.h"

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
	stream_put(circuit->snd_stream, circuit->isis->sysid, ISIS_SYS_ID_LEN);
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

	pdu_counter_count(circuit->area->pdu_tx_counters, pdu_type);
	retval = circuit->tx(circuit, level);
	if (retval != ISIS_OK)
		flog_err(EC_ISIS_PACKET,
			 "ISIS-Upd (%s): Send L%d LSP PSNP on %s failed",
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
			if (IS_DEBUG_ADJ_PACKETS) {
				zlog_debug("ISIS-Adj (%s): Rcvd P2P IIH from (%s) with invalid three-way state: %d",
					   iih->circuit->area->area_tag,
					   iih->circuit->interface->name,
					   tw_adj->state);
			}
			return ISIS_WARNING;
		}

		if (tw_adj->neighbor_set
		    && (memcmp(tw_adj->neighbor_id, iih->circuit->isis->sysid,
			       ISIS_SYS_ID_LEN)
			|| tw_adj->neighbor_circuit_id
				   != (uint32_t)iih->circuit->idx)) {

			if (IS_DEBUG_ADJ_PACKETS) {
				zlog_debug("ISIS-Adj (%s): Rcvd P2P IIH from (%s) which lists IS/Circuit different from us as neighbor.",
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
				"hello source and adjacency do not match, set adj down");
			isis_adj_state_change(&adj, ISIS_ADJ_DOWN,
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
		isis_adj_state_change(&adj, ISIS_ADJ_INITIALIZING, NULL);
		adj->sys_type = ISIS_SYSTYPE_UNKNOWN;
	}

	if (tw_adj)
		adj->ext_circuit_id = tw_adj->local_circuit_id;

	/* 8.2.6 Monitoring point-to-point adjacencies */
	adj->hold_time = iih->holdtime;
	adj->last_upd = time(NULL);

	bool changed;
	isis_tlvs_to_adj(iih->tlvs, adj, &changed);
	changed |= tlvs_to_adj_mt_set(iih->tlvs, iih->v4_usable, iih->v6_usable,
				      adj);

	/* lets take care of the expiry */
	EVENT_OFF(adj->t_expire);
	event_add_timer(master, isis_adj_expire, adj, (long)adj->hold_time,
			&adj->t_expire);

	/* While fabricds initial sync is in progress, ignore hellos from other
	 * interfaces than the one we are performing the initial sync on. */
	if (fabricd_initial_sync_is_in_progress(iih->circuit->area)
	    && fabricd_initial_sync_circuit(iih->circuit->area) != iih->circuit)
		return ISIS_OK;

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
					isis_adj_state_change(&adj,
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
					isis_adj_state_change(&adj,
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
					isis_adj_state_change(&adj,
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
					isis_adj_state_change(&adj,
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
					isis_adj_state_change(&adj,
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
					isis_adj_state_change(&adj,
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
				isis_adj_state_change(&adj, ISIS_ADJ_DOWN,
						      "Area Mismatch");
				/* 8.2.5.2 b) 2)is_type L1 and adj is up */
			} else {
				isis_adj_state_change(&adj, ISIS_ADJ_DOWN,
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
					isis_adj_state_change(&adj,
							      ISIS_ADJ_DOWN,
							      "Area Mismatch");

				} else if ((adj->adj_usage
					    == ISIS_ADJ_LEVEL1AND2)
					   || (adj->adj_usage
					       == ISIS_ADJ_LEVEL2)) {
					/* (7) down - wrong system */
					isis_adj_state_change(&adj,
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
					isis_adj_state_change(&adj,
							      ISIS_ADJ_DOWN,
							      "Wrong System");
				} else if (adj->adj_usage
					   == ISIS_ADJ_LEVEL1AND2) {
					if (iih->circ_type == IS_LEVEL_2) {
						/* (7) down - wrong system */
						isis_adj_state_change(
							&adj, ISIS_ADJ_DOWN,
							"Wrong System");
					} else {
						/* (7) down - area mismatch */
						isis_adj_state_change(
							&adj, ISIS_ADJ_DOWN,
							"Area Mismatch");
					}
				}
				break;
			}
		}
	} else {
		/* down - area mismatch */
		isis_adj_state_change(&adj, ISIS_ADJ_DOWN, "Area Mismatch");
	}

	if (adj) {
		if (adj->adj_state == ISIS_ADJ_UP && changed) {
			lsp_regenerate_schedule(
				adj->circuit->area,
				isis_adj_usage2levels(adj->adj_usage), 0);
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
	}

	if (IS_DEBUG_ADJ_PACKETS) {
		zlog_debug(
			"ISIS-Adj (%s): Rcvd P2P IIH from (%s), cir type %s, cir id %hhu, length %hu",
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
		isis_adj_state_change(&adj, ISIS_ADJ_INITIALIZING, NULL);

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
			event_add_event(master, isis_event_dis_status_change,
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
	EVENT_OFF(adj->t_expire);
	event_add_timer(master, isis_adj_expire, adj, (long)adj->hold_time,
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
				&adj, ISIS_ADJ_UP,
				"own SNPA found in LAN Neighbours TLV");
		}
	} else {
		if (!own_snpa_found) {
			isis_adj_state_change(
				&adj, ISIS_ADJ_INITIALIZING,
				"own SNPA not found in LAN Neighbours TLV");
		}
	}

	if (adj->adj_state == ISIS_ADJ_UP && changed)
		lsp_regenerate_schedule(adj->circuit->area, iih->level, 0);

	if (IS_DEBUG_ADJ_PACKETS) {
		zlog_debug(
			"ISIS-Adj (%s): Rcvd L%d LAN IIH from %pSY on %s, cirType %s, cirID %u, length %zd",
			iih->circuit->area->area_tag, iih->level, iih->ssnpa,
			iih->circuit->interface->name,
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

static void update_rej_adj_count(struct isis_circuit *circuit)
{
	circuit->rej_adjacencies++;
	if (circuit->is_type == IS_LEVEL_1)
		circuit->area->rej_adjacencies[0]++;
	else if (circuit->is_type == IS_LEVEL_2)
		circuit->area->rej_adjacencies[1]++;
	else {
		circuit->area->rej_adjacencies[0]++;
		circuit->area->rej_adjacencies[1]++;
	}
}

static int process_hello(uint8_t pdu_type, struct isis_circuit *circuit,
			 uint8_t *ssnpa)
{
	/* keep a copy of the raw pdu for NB notifications */
	size_t pdu_start = stream_get_getp(circuit->rcv_stream);
	size_t pdu_end = stream_get_endp(circuit->rcv_stream);
	char raw_pdu[pdu_end - pdu_start];
	bool p2p_hello = (pdu_type == P2P_HELLO);
	int level = p2p_hello ? 0
			      : (pdu_type == L1_LAN_HELLO) ? ISIS_LEVEL1
							   : ISIS_LEVEL2;
	const char *pdu_name =
		p2p_hello
			? "P2P IIH"
			: (level == ISIS_LEVEL1) ? "L1 LAN IIH" : "L2 LAN IIH";

	stream_get_from(raw_pdu, circuit->rcv_stream, pdu_start,
			pdu_end - pdu_start);
	if (IS_DEBUG_ADJ_PACKETS) {
		zlog_debug("ISIS-Adj (%s): Rcvd %s on %s, cirType %s, cirID %u",
			   circuit->area->area_tag, pdu_name,
			   circuit->interface->name,
			   circuit_t2string(circuit->is_type),
			   circuit->circuit_id);
		if (IS_DEBUG_PACKET_DUMP)
			zlog_dump_data(STREAM_DATA(circuit->rcv_stream),
				       stream_get_endp(circuit->rcv_stream));
	}

	if (p2p_hello) {
		if (circuit->circ_type != CIRCUIT_T_P2P) {
			zlog_warn("p2p hello on non p2p circuit");
			update_rej_adj_count(circuit);
#ifndef FABRICD
			isis_notif_reject_adjacency(
				circuit, "p2p hello on non p2p circuit",
				raw_pdu, sizeof(raw_pdu));
#endif /* ifndef FABRICD */
			return ISIS_WARNING;
		}
	} else {
		if (circuit->circ_type != CIRCUIT_T_BROADCAST) {
			zlog_warn("lan hello on non broadcast circuit");
			update_rej_adj_count(circuit);
#ifndef FABRICD
			isis_notif_reject_adjacency(
				circuit, "lan hello on non broadcast circuit",
				raw_pdu, sizeof(raw_pdu));
#endif /* ifndef FABRICD */
			return ISIS_WARNING;
		}

		if (circuit->ext_domain) {
			zlog_debug(
				"level %d LAN Hello received over circuit with externalDomain = true",
				level);
			update_rej_adj_count(circuit);
#ifndef FABRICD
			isis_notif_reject_adjacency(
				circuit,
				"LAN Hello received over circuit with externalDomain = true",
				raw_pdu, sizeof(raw_pdu));
#endif /* ifndef FABRICD */
			return ISIS_WARNING;
		}

		if (!(circuit->is_type & level)) {
			if (IS_DEBUG_ADJ_PACKETS) {
				zlog_debug(
					"ISIS-Adj (%s): Interface level mismatch, %s",
					circuit->area->area_tag,
					circuit->interface->name);
			}
			update_rej_adj_count(circuit);
#ifndef FABRICD
			isis_notif_reject_adjacency(circuit,
						    "Interface level mismatch",
						    raw_pdu, sizeof(raw_pdu));
#endif /* ifndef FABRICD */
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
			"ISIS-Adj (%s): Rcvd %s from (%s) with invalid pdu length %hu",
			circuit->area->area_tag, pdu_name,
			circuit->interface->name, iih.pdu_len);
		update_rej_adj_count(circuit);
#ifndef FABRICD
		isis_notif_reject_adjacency(circuit, "Invalid PDU length",
					    raw_pdu, sizeof(raw_pdu));
#endif /* ifndef FABRICD */
		return ISIS_WARNING;
	}

	if (!p2p_hello && !(level & iih.circ_type)) {
		flog_err(EC_ISIS_PACKET,
			 "Level %d LAN Hello with Circuit Type %d", level,
			 iih.circ_type);
		update_rej_adj_count(circuit);
#ifndef FABRICD
		isis_notif_reject_adjacency(circuit,
					    "LAN Hello with wrong IS-level",
					    raw_pdu, sizeof(raw_pdu));
#endif /* ifndef FABRICD */
		return ISIS_ERROR;
	}

	const char *error_log;
	int retval = ISIS_WARNING;

	if (isis_unpack_tlvs(STREAM_READABLE(circuit->rcv_stream),
			     circuit->rcv_stream, &iih.tlvs, &error_log)) {
		zlog_warn("isis_unpack_tlvs() failed: %s", error_log);
		update_rej_adj_count(circuit);
#ifndef FABRICD
		isis_notif_reject_adjacency(circuit, "Failed to unpack TLVs",
					    raw_pdu, sizeof(raw_pdu));
#endif /* ifndef FABRICD */
		goto out;
	}

	if (!iih.tlvs->area_addresses.count) {
		zlog_warn("No Area addresses TLV in %s", pdu_name);
#ifndef FABRICD
		/* send northbound notification */
		isis_notif_area_mismatch(circuit, raw_pdu, sizeof(raw_pdu));
#endif /* ifndef FABRICD */
		goto out;
	}

	if (!iih.tlvs->protocols_supported.count) {
		zlog_warn("No supported protocols TLV in %s", pdu_name);
		update_rej_adj_count(circuit);
#ifndef FABRICD
		isis_notif_reject_adjacency(circuit,
					    "No supported protocols TLV",
					    raw_pdu, sizeof(raw_pdu));
#endif /* ifndef FABRICD */
		goto out;
	}

	int auth_code = isis_tlvs_auth_is_valid(iih.tlvs, &circuit->passwd,
						circuit->rcv_stream, false);
	if (auth_code != ISIS_AUTH_OK) {
		isis_event_auth_failure(circuit->area->area_tag,
					"IIH authentication failure",
					iih.sys_id);
#ifndef FABRICD
		/* send northbound notification */
		stream_get_from(raw_pdu, circuit->rcv_stream, pdu_start,
				pdu_end - pdu_start);
		if (auth_code == ISIS_AUTH_FAILURE) {
			update_rej_adj_count(circuit);
			isis_notif_authentication_failure(circuit, raw_pdu,
							  sizeof(raw_pdu));
		} else { /* AUTH_TYPE_FAILURE or NO_VALIDATOR */
			update_rej_adj_count(circuit);
			isis_notif_authentication_type_failure(circuit, raw_pdu,
							       sizeof(raw_pdu));
		}
#endif /* ifndef FABRICD */
		goto out;
	}

	if (!memcmp(iih.sys_id, circuit->isis->sysid, ISIS_SYS_ID_LEN)) {
		zlog_warn(
			"ISIS-Adj (%s): Received IIH with own sysid on %s - discard",
			circuit->area->area_tag, circuit->interface->name);
		update_rej_adj_count(circuit);
#ifndef FABRICD
		isis_notif_reject_adjacency(circuit,
					    "Received IIH with our own sysid",
					    raw_pdu, sizeof(raw_pdu));
#endif /* ifndef FABRICD */
		goto out;
	}

	if (!p2p_hello
	    && (listcount(circuit->area->area_addrs) == 0
		|| (level == ISIS_LEVEL1
		    && !isis_tlvs_area_addresses_match(
			       iih.tlvs, circuit->area->area_addrs)))) {
		if (IS_DEBUG_ADJ_PACKETS) {
			zlog_debug(
				"ISIS-Adj (%s): Area mismatch, level %d IIH on %s",
				circuit->area->area_tag, level,
				circuit->interface->name);
		}
#ifndef FABRICD
		/* send northbound notification */
		isis_notif_area_mismatch(circuit, raw_pdu, sizeof(raw_pdu));
#endif /* ifndef FABRICD */
		goto out;
	}

	iih.v4_usable = (fabricd_ip_addrs(circuit)
			 && iih.tlvs->ipv4_address.count);

	iih.v6_usable =
		(listcount(circuit->ipv6_link) && iih.tlvs->ipv6_address.count);

	if (!iih.v4_usable && !iih.v6_usable) {
		if (IS_DEBUG_ADJ_PACKETS) {
			zlog_warn(
				"ISIS-Adj (%s): Neither IPv4 nor IPv6 considered usable. Ignoring IIH",
				circuit->area->area_tag);
		}
		update_rej_adj_count(circuit);
#ifndef FABRICD
		isis_notif_reject_adjacency(
			circuit, "Neither IPv4 not IPv6 considered usable",
			raw_pdu, sizeof(raw_pdu));
#endif /* ifndef FABRICD */
		goto out;
	}

	retval = p2p_hello ? process_p2p_hello(&iih) : process_lan_hello(&iih);
out:
	isis_free_tlvs(iih.tlvs);

	return retval;
}

static void lsp_flood_or_update(struct isis_lsp *lsp,
				struct isis_circuit *circuit,
				bool circuit_scoped)
{
	if (!circuit_scoped)
		lsp_flood(lsp, circuit);
	else
		fabricd_update_lsp_no_flood(lsp, circuit);
}

/*
 * Process Level 1/2 Link State
 * ISO - 10589
 * Section 7.3.15.1 - Action on receipt of a link state PDU
 */
static int process_lsp(uint8_t pdu_type, struct isis_circuit *circuit,
		       const uint8_t *ssnpa, uint8_t max_area_addrs)
{
	int level;
	bool circuit_scoped;
	size_t pdu_start = stream_get_getp(circuit->rcv_stream);
	size_t pdu_end = stream_get_endp(circuit->rcv_stream);
	char raw_pdu[pdu_end - pdu_start];

	stream_get_from(raw_pdu, circuit->rcv_stream, pdu_start,
			pdu_end - pdu_start);

	if (pdu_type == FS_LINK_STATE) {
		if (!fabricd)
			return ISIS_ERROR;
		if (max_area_addrs != L2_CIRCUIT_FLOODING_SCOPE)
			return ISIS_ERROR;
		level = ISIS_LEVEL2;
		circuit_scoped = true;

		/* The stream is used verbatim for sending out new LSPDUs.
		 * So make sure we store it as an L2 LSPDU internally.
		 * (compare for the reverse in `send_lsp`) */
		stream_putc_at(circuit->rcv_stream, 4, L2_LINK_STATE);
		stream_putc_at(circuit->rcv_stream, 7, 0);
	} else {
		if (pdu_type == L1_LINK_STATE)
			level = ISIS_LEVEL1;
		else
			level = ISIS_LEVEL2;
		circuit_scoped = false;
	}

	if (IS_DEBUG_UPDATE_PACKETS) {
		zlog_debug(
			"ISIS-Upd (%s): Rcvd %sL%d LSP on %s, cirType %s, cirID %u",
			circuit->area->area_tag,
			circuit_scoped ? "Circuit scoped " : "", level,
			circuit->interface->name,
			circuit_t2string(circuit->is_type),
			circuit->circuit_id);
		if (IS_DEBUG_PACKET_DUMP)
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

#ifndef FABRICD
	/* send northbound notification */
	char buf[ISO_SYSID_STRLEN];

	snprintfrr(buf, ISO_SYSID_STRLEN, "%pSY", hdr.lsp_id);
	isis_notif_lsp_received(circuit, hdr.lsp_id, hdr.seqno, time(NULL),
				buf);
#endif /* ifndef FABRICD */

	if (pdu_len_validate(hdr.pdu_len, circuit)) {
		zlog_debug("ISIS-Upd (%s): LSP %pLS invalid LSP length %hu",
			   circuit->area->area_tag, hdr.lsp_id, hdr.pdu_len);
		return ISIS_WARNING;
	}

	if (IS_DEBUG_UPDATE_PACKETS) {
		zlog_debug(
			"ISIS-Upd (%s): Rcvd L%d LSP %pLS, seq 0x%08x, cksum 0x%04hx, lifetime %hus, len %hu, on %s",
			circuit->area->area_tag, level, hdr.lsp_id, hdr.seqno,
			hdr.checksum, hdr.rem_lifetime, hdr.pdu_len,
			circuit->interface->name);
	}

	/* lsp is_type check */
	if ((hdr.lsp_bits & IS_LEVEL_1) != IS_LEVEL_1) {
		zlog_debug("ISIS-Upd (%s): LSP %pLS invalid LSP is type 0x%x",
			   circuit->area->area_tag, hdr.lsp_id,
			   hdr.lsp_bits & IS_LEVEL_1_AND_2);
		/* continue as per RFC1122 Be liberal in what you accept, and
		 * conservative in what you send */
	}

	/* Checksum sanity check - FIXME: move to correct place */
	/* 12 = sysid+pdu+remtime */
	if (iso_csum_verify(STREAM_DATA(circuit->rcv_stream) + 12,
			    hdr.pdu_len - 12, hdr.checksum, 12)) {
		zlog_debug(
			"ISIS-Upd (%s): LSP %pLS invalid LSP checksum 0x%04hx",
			circuit->area->area_tag, hdr.lsp_id, hdr.checksum);
		return ISIS_WARNING;
	}

	/* 7.3.15.1 a) 1 - external domain circuit will discard lsps */
	if (circuit->ext_domain) {
		zlog_debug(
			"ISIS-Upd (%s): LSP %pLS received at level %d over circuit with externalDomain = true",
			circuit->area->area_tag, hdr.lsp_id, level);
		return ISIS_WARNING;
	}

	/* 7.3.15.1 a) 2,3 - manualL2OnlyMode not implemented */
	if (!(circuit->is_type & level)) {
		zlog_debug(
			"ISIS-Upd (%s): LSP %pLS received at level %d over circuit of type %s",
			circuit->area->area_tag, hdr.lsp_id, level,
			circuit_t2string(circuit->is_type));
		return ISIS_WARNING;
	}

	struct isis_tlvs *tlvs = NULL;
	int retval = ISIS_WARNING;
	const char *error_log;

	if (isis_unpack_tlvs(STREAM_READABLE(circuit->rcv_stream),
			     circuit->rcv_stream, &tlvs, &error_log)) {
		zlog_warn("Something went wrong unpacking the LSP: %s",
			  error_log);
#ifndef FABRICD
		/* send northbound notification. Note that the tlv-type and
		 * offset cannot correctly be set here as they are not returned
		 * by isis_unpack_tlvs, but in there I cannot fire a
		 * notification because I have no circuit information. So until
		 * we change the code above to return those extra fields, we
		 * will send dummy values which are ignored in the callback
		 */
		circuit->lsp_error_counter++;
		if (circuit->is_type == IS_LEVEL_1) {
			circuit->area->lsp_error_counter[0]++;
		} else if (circuit->is_type == IS_LEVEL_2) {
			circuit->area->lsp_error_counter[1]++;
		} else {
			circuit->area->lsp_error_counter[0]++;
			circuit->area->lsp_error_counter[1]++;
		}

		isis_notif_lsp_error(circuit, hdr.lsp_id, raw_pdu,
				     sizeof(raw_pdu), 0, 0);
#endif /* ifndef FABRICD */
		goto out;
	}

	/* 7.3.15.1 a) 4 - need to make sure IDLength matches */

	/* 7.3.15.1 a) 5 - maximum area match, can be ommited since we only use
	 * 3 */

	/* 7.3.15.1 a) 7 - password check */
	struct isis_passwd *passwd = (level == ISIS_LEVEL1)
					     ? &circuit->area->area_passwd
					     : &circuit->area->domain_passwd;
	int auth_code = isis_tlvs_auth_is_valid(tlvs, passwd,
						circuit->rcv_stream, true);
	if (auth_code != ISIS_AUTH_OK) {
		isis_event_auth_failure(circuit->area->area_tag,
					"LSP authentication failure",
					hdr.lsp_id);
#ifndef FABRICD
		/* send northbound notification */
		if (auth_code == ISIS_AUTH_FAILURE) {
			circuit->auth_failures++;
			if (circuit->is_type == IS_LEVEL_1) {
				circuit->area->auth_failures[0]++;
			} else if (circuit->is_type == IS_LEVEL_2) {
				circuit->area->auth_failures[1]++;
			} else {
				circuit->area->auth_failures[0]++;
				circuit->area->auth_failures[1]++;
			}
			isis_notif_authentication_failure(circuit, raw_pdu,
							  sizeof(raw_pdu));
		} else { /* AUTH_TYPE_FAILURE or NO_VALIDATOR */
			circuit->auth_type_failures++;
			if (circuit->is_type == IS_LEVEL_1) {
				circuit->area->auth_type_failures[0]++;
			} else if (circuit->is_type == IS_LEVEL_2) {
				circuit->area->auth_type_failures[1]++;
			} else {
				circuit->area->auth_type_failures[0]++;
				circuit->area->auth_type_failures[1]++;
			}
			isis_notif_authentication_type_failure(circuit, raw_pdu,
							       sizeof(raw_pdu));
		}
#endif /* ifndef FABRICD */
		goto out;
	}

	/* Find the LSP in our database and compare it to this Link State header
	 */
	struct isis_lsp *lsp =
		lsp_search(&circuit->area->lspdb[level - 1], hdr.lsp_id);
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
			zlog_debug(
				"(%s): DS ======= LSP %pLS, seq 0x%08x, cksum 0x%04hx, lifetime %hus on %s",
				circuit->area->area_tag, hdr.lsp_id, hdr.seqno,
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
	    && (lsp->hdr.checksum != hdr.checksum)
	    && hdr.rem_lifetime) {
		zlog_warn(
			"ISIS-Upd (%s): LSP %pLS seq 0x%08x with confused checksum received.",
			circuit->area->area_tag, hdr.lsp_id, hdr.seqno);
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
			if (memcmp(hdr.lsp_id, circuit->isis->sysid,
				   ISIS_SYS_ID_LEN)) {
				/* LSP by some other system -> do 7.3.16.4 b) */
				/* 7.3.16.4 b) 1)  */
				if (comp == LSP_NEWER) {
					lsp_update(lsp, &hdr, tlvs,
						   circuit->rcv_stream,
						   circuit->area, level,
						   lsp_confusion);
					if (lsp_confusion)
						isis_free_tlvs(tlvs);
					tlvs = NULL;
					/* ii */
					lsp_flood_or_update(lsp, NULL,
							    circuit_scoped);
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
						isis_tx_queue_del(
							circuit->tx_queue,
							lsp);

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
					isis_tx_queue_del(circuit->tx_queue,
							  lsp);
					/* ii */
					if (circuit->circ_type
					    != CIRCUIT_T_BROADCAST)
						ISIS_SET_FLAG(lsp->SSNflags,
							      circuit);
				} /* 7.3.16.4 b) 3) */
				else {
					isis_tx_queue_add(circuit->tx_queue,
							  lsp, TX_LSP_NORMAL);
					ISIS_CLEAR_FLAG(lsp->SSNflags, circuit);
				}
			} else if (lsp->hdr.rem_lifetime != 0) {
				/* our own LSP -> 7.3.16.4 c) */
				if (comp == LSP_NEWER) {
#ifndef FABRICD
					if (lsp->hdr.seqno < hdr.seqno) {
						/* send northbound
						 * notification */
						circuit->area
							->lsp_seqno_skipped_counter++;
						isis_notif_seqno_skipped(
							circuit, hdr.lsp_id);
					}
#endif /* ifndef FABRICD */
					lsp_inc_seqno(lsp, hdr.seqno);
					lsp_flood_or_update(lsp, NULL,
							    circuit_scoped);
				} else {
					isis_tx_queue_add(circuit->tx_queue,
							  lsp, TX_LSP_NORMAL);
					ISIS_CLEAR_FLAG(lsp->SSNflags, circuit);
				}
				if (IS_DEBUG_UPDATE_PACKETS)
					zlog_debug(
						"ISIS-Upd (%s): (1) re-originating LSP %pLS new seq 0x%08x",
						circuit->area->area_tag,
						hdr.lsp_id, lsp->hdr.seqno);
			} else {
				/* our own LSP with 0 remaining life time */
#ifndef FABRICD
				/* send northbound notification */
				isis_notif_own_lsp_purge(circuit, hdr.lsp_id);
#endif /* ifndef FABRICD */
			}
		}
		goto out;
	}
	/* 7.3.15.1 c) - If this is our own lsp and we don't have it initiate a
	 * purge */
	if (memcmp(hdr.lsp_id, circuit->isis->sysid, ISIS_SYS_ID_LEN) == 0) {
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

		if (comp == LSP_NEWER) {
			/* 7.3.16.1  */
			lsp_inc_seqno(lsp, hdr.seqno);
#ifndef FABRICD
			/* send northbound notification */
			circuit->area->lsp_seqno_skipped_counter++;
			isis_notif_seqno_skipped(circuit, hdr.lsp_id);
#endif /* ifndef FABRICD */
			if (IS_DEBUG_UPDATE_PACKETS) {
				zlog_debug(
					"ISIS-Upd (%s): (2) re-originating LSP %pLS new seq 0x%08x",
					circuit->area->area_tag, hdr.lsp_id,
					lsp->hdr.seqno);
			}
			lsp_flood(lsp, NULL);
		} else if (comp == LSP_EQUAL) {
			isis_tx_queue_del(circuit->tx_queue, lsp);
			if (circuit->circ_type != CIRCUIT_T_BROADCAST)
				ISIS_SET_FLAG(lsp->SSNflags, circuit);
		} else {
			isis_tx_queue_add(circuit->tx_queue, lsp,
					  TX_LSP_NORMAL);
			ISIS_CLEAR_FLAG(lsp->SSNflags, circuit);
		}
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
					&circuit->area->lspdb[level - 1], lspid);
				if (!lsp0) {
					zlog_debug(
						"Got lsp frag, while zero lsp not in database");
					goto out;
				}
			}
			/* i */
			if (!lsp) {
				lsp = lsp_new_from_recv(
					&hdr, tlvs, circuit->rcv_stream, lsp0,
					circuit->area, level);
				tlvs = NULL;
				lsp_insert(&circuit->area->lspdb[level - 1],
					   lsp);
			} else /* exists, so we overwrite */
			{
				lsp_update(lsp, &hdr, tlvs, circuit->rcv_stream,
					   circuit->area, level, false);
				tlvs = NULL;
			}
			lsp_flood_or_update(lsp, circuit, circuit_scoped);

			/* iv */
			if (circuit->circ_type != CIRCUIT_T_BROADCAST)
				ISIS_SET_FLAG(lsp->SSNflags, circuit);
			/* FIXME: v) */
		}
		/* 7.3.15.1 e) 2) LSP equal to the one in db */
		else if (comp == LSP_EQUAL) {
			isis_tx_queue_del(circuit->tx_queue, lsp);
			lsp_update(lsp, &hdr, tlvs, circuit->rcv_stream,
				   circuit->area, level, false);
			tlvs = NULL;
			if (circuit->circ_type != CIRCUIT_T_BROADCAST)
				ISIS_SET_FLAG(lsp->SSNflags, circuit);
		}
		/* 7.3.15.1 e) 3) LSP older than the one in db */
		else {
			isis_tx_queue_add(circuit->tx_queue, lsp,
					  TX_LSP_NORMAL);
			ISIS_CLEAR_FLAG(lsp->SSNflags, circuit);
		}
	}

	retval = ISIS_OK;

out:
	fabricd_trigger_csnp(circuit->area, circuit_scoped);

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
#ifndef FABRICD
	size_t pdu_start = stream_get_getp(circuit->rcv_stream);
	size_t pdu_end = stream_get_endp(circuit->rcv_stream);
	char raw_pdu[pdu_end - pdu_start];
#endif /* ifndef FABRICD */

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

	if (IS_DEBUG_SNP_PACKETS) {
		zlog_debug(
			"ISIS-Snp (%s): Rcvd L%d %cSNP on %s, cirType %s, cirID %u",
			circuit->area->area_tag, level, typechar,
			circuit->interface->name,
			circuit_t2string(circuit->is_type),
			circuit->circuit_id);
		if (IS_DEBUG_PACKET_DUMP)
			zlog_dump_data(STREAM_DATA(circuit->rcv_stream),
				       stream_get_endp(circuit->rcv_stream));
	}

	/* 7.3.15.2 a) 1 - external domain circuit will discard snp pdu */
	if (circuit->ext_domain) {

		zlog_debug(
			"ISIS-Snp (%s): Rcvd L%d %cSNP on %s, skipping: circuit externalDomain = true",
			circuit->area->area_tag, level, typechar,
			circuit->interface->name);

		return ISIS_OK;
	}

	/* 7.3.15.2 a) 2,3 - manualL2OnlyMode not implemented */
	if (!(circuit->is_type & level)) {
		zlog_debug(
			"ISIS-Snp (%s): Rcvd L%d %cSNP on %s, skipping: circuit type %s does not match level %d",
			circuit->area->area_tag, level, typechar,
			circuit->interface->name,
			circuit_t2string(circuit->is_type), level);

		return ISIS_OK;
	}

	/* 7.3.15.2 a) 4 - not applicable for CSNP  only PSNPs on broadcast */
	if (!is_csnp && (circuit->circ_type == CIRCUIT_T_BROADCAST)
	    && !circuit->u.bc.is_dr[level - 1]) {
		zlog_debug(
			"ISIS-Snp (%s): Rcvd L%d %cSNP from %pSY on %s, skipping: we are not the DIS",
			circuit->area->area_tag, level, typechar, ssnpa,
			circuit->interface->name);

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
		if (!fabricd && !circuit->u.p2p.neighbor) {
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

	if (CHECK_FLAG(passwd->snp_auth, SNP_AUTH_RECV)) {
		int auth_code = isis_tlvs_auth_is_valid(
			tlvs, passwd, circuit->rcv_stream, false);
		if (auth_code != ISIS_AUTH_OK) {
			isis_event_auth_failure(circuit->area->area_tag,
						"SNP authentication failure",
						rem_sys_id);
#ifndef FABRICD
			/* send northbound notification */
			stream_get_from(raw_pdu, circuit->rcv_stream, pdu_start,
					pdu_end - pdu_start);
			if (auth_code == ISIS_AUTH_FAILURE) {
				circuit->auth_failures++;
				if (circuit->is_type == IS_LEVEL_1) {
					circuit->area->auth_failures[0]++;
				} else if (circuit->is_type == IS_LEVEL_2) {
					circuit->area->auth_failures[1]++;
				} else {
					circuit->area->auth_failures[0]++;
					circuit->area->auth_failures[1]++;
				}
				isis_notif_authentication_failure(
					circuit, raw_pdu, sizeof(raw_pdu));
			} else { /* AUTH_TYPE_FAILURE or NO_VALIDATOR */
				circuit->auth_type_failures++;
				if (circuit->is_type == IS_LEVEL_1) {
					circuit->area->auth_type_failures[0]++;
				} else if (circuit->is_type == IS_LEVEL_2) {
					circuit->area->auth_type_failures[1]++;
				} else {
					circuit->area->auth_type_failures[0]++;
					circuit->area->auth_type_failures[1]++;
				}
				isis_notif_authentication_type_failure(
					circuit, raw_pdu, sizeof(raw_pdu));
			}
#endif /* ifndef FABRICD */
			goto out;
		}
	}

	struct isis_lsp_entry *entry_head =
		(struct isis_lsp_entry *)tlvs->lsp_entries.head;

	/* debug isis snp-packets */
	if (IS_DEBUG_SNP_PACKETS) {
		zlog_debug("ISIS-Snp (%s): Rcvd L%d %cSNP from %pSY on %s",
			   circuit->area->area_tag, level, typechar, ssnpa,
			   circuit->interface->name);
		for (struct isis_lsp_entry *entry = entry_head; entry;
		     entry = entry->next) {
			zlog_debug(
				"ISIS-Snp (%s):         %cSNP entry %pLS, seq 0x%08x, cksum 0x%04hx, lifetime %hus",
				circuit->area->area_tag, typechar, entry->id,
				entry->seqno, entry->checksum,
				entry->rem_lifetime);
		}
	}

	bool resync_needed = false;

	/* 7.3.15.2 b) Actions on LSP_ENTRIES reported */
	for (struct isis_lsp_entry *entry = entry_head; entry;
	     entry = entry->next) {
		struct isis_lsp *lsp =
			lsp_search(&circuit->area->lspdb[level - 1], entry->id);
		bool own_lsp = !memcmp(entry->id, circuit->isis->sysid,
				       ISIS_SYS_ID_LEN);
		if (lsp) {
			/* 7.3.15.2 b) 1) is this LSP newer */
			int cmp = lsp_compare(circuit->area->area_tag, lsp,
					      entry->seqno, entry->checksum,
					      entry->rem_lifetime);
			/* 7.3.15.2 b) 2) if it equals, clear SRM on p2p */
			if (cmp == LSP_EQUAL) {
				/* if (circuit->circ_type !=
				 * CIRCUIT_T_BROADCAST) */
				isis_tx_queue_del(circuit->tx_queue, lsp);
			}
			/* 7.3.15.2 b) 3) if it is older, clear SSN and set SRM
			   */
			else if (cmp == LSP_OLDER) {
				ISIS_CLEAR_FLAG(lsp->SSNflags, circuit);
				isis_tx_queue_add(circuit->tx_queue, lsp,
						  TX_LSP_NORMAL);
			}
			/* 7.3.15.2 b) 4) if it is newer, set SSN and clear SRM
			   on p2p */
			else {
				if (own_lsp) {
					lsp_inc_seqno(lsp, entry->seqno);
					isis_tx_queue_add(circuit->tx_queue, lsp,
							TX_LSP_NORMAL);
				} else {
					ISIS_SET_FLAG(lsp->SSNflags, circuit);
					/* if (circuit->circ_type !=
					 * CIRCUIT_T_BROADCAST) */
					isis_tx_queue_del(circuit->tx_queue, lsp);
					resync_needed = true;
				}
			}
		} else {
			/* 7.3.15.2 b) 5) if it was not found, and all of those
			 * are not 0,
			 * insert it and set SSN on it */
			if (entry->rem_lifetime && entry->checksum
			    && entry->seqno
			    && memcmp(entry->id, circuit->isis->sysid,
				      ISIS_SYS_ID_LEN)) {
				struct isis_lsp *lsp0 = NULL;

				if (LSP_FRAGMENT(entry->id)) {
					uint8_t lspid[ISIS_SYS_ID_LEN + 2];

					memcpy(lspid, entry->id,
					       ISIS_SYS_ID_LEN + 1);
					LSP_FRAGMENT(lspid) = 0;
					lsp0 = lsp_search(
						  &circuit->area->lspdb[level - 1],
						  lspid);
					if (!lsp0) {
						zlog_debug("Got lsp frag in snp, while zero not in database");
						continue;
					}
				}
				lsp = lsp_new(circuit->area, entry->id,
						entry->rem_lifetime, 0, 0,
						entry->checksum, lsp0, level);
				lsp_insert(&circuit->area->lspdb[level - 1],
					   lsp);

				lsp_set_all_srmflags(lsp, false);
				ISIS_SET_FLAG(lsp->SSNflags, circuit);
				resync_needed = true;
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
		lsp_build_list_nonzero_ht(&circuit->area->lspdb[level - 1],
					  start_lsp_id, stop_lsp_id, lsp_list);

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
		for (ALL_LIST_ELEMENTS_RO(lsp_list, node, lsp)) {
			isis_tx_queue_add(circuit->tx_queue, lsp, TX_LSP_NORMAL);
			resync_needed = true;
		}

		/* lets free it */
		list_delete(&lsp_list);
	}

	if (fabricd_initial_sync_is_complete(circuit->area) && resync_needed)
		zlog_warn("OpenFabric: Needed to resync LSPDB using CSNP!");

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
	case FS_LINK_STATE:
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
	size_t pdu_start = stream_get_getp(circuit->rcv_stream);
	size_t pdu_end = stream_get_endp(circuit->rcv_stream);
	char raw_pdu[pdu_end - pdu_start];

	stream_get_from(raw_pdu, circuit->rcv_stream, pdu_start,
			pdu_end - pdu_start);

	/* Verify that at least the 8 bytes fixed header have been received */
	if (stream_get_endp(circuit->rcv_stream) < ISIS_FIXED_HDR_LEN) {
		flog_err(EC_ISIS_PACKET, "PDU is too short to be IS-IS.");
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

	pdu_counter_count(circuit->area->pdu_rx_counters, pdu_type);

	if (idrp == ISO9542_ESIS) {
		flog_err(EC_LIB_DEVELOPMENT,
			 "No support for ES-IS packet IDRP=%hhx", idrp);
		pdu_counter_count_drop(circuit->area, pdu_type);
		return ISIS_ERROR;
	}

	if (idrp != ISO10589_ISIS) {
		flog_err(EC_ISIS_PACKET, "Not an IS-IS packet IDRP=%hhx",
			 idrp);
		pdu_counter_count_drop(circuit->area, pdu_type);
		return ISIS_ERROR;
	}

	if (version1 != 1) {
		zlog_warn("Unsupported ISIS version %hhu", version1);
#ifndef FABRICD
		/* send northbound notification */
		isis_notif_version_skew(circuit, version1, raw_pdu,
					sizeof(raw_pdu));
#endif /* ifndef FABRICD */
		pdu_counter_count_drop(circuit->area, pdu_type);
		return ISIS_WARNING;
	}

	if (id_len != 0 && id_len != ISIS_SYS_ID_LEN) {
		flog_err(
			EC_ISIS_PACKET,
			"IDFieldLengthMismatch: ID Length field in a received PDU  %hhu, while the parameter for this IS is %u",
			id_len, ISIS_SYS_ID_LEN);
		circuit->id_len_mismatches++;
		if (circuit->is_type == IS_LEVEL_1) {
			circuit->area->id_len_mismatches[0]++;
		} else if (circuit->is_type == IS_LEVEL_2) {
			circuit->area->id_len_mismatches[1]++;
		} else {
			circuit->area->id_len_mismatches[0]++;
			circuit->area->id_len_mismatches[1]++;
		}

#ifndef FABRICD
		/* send northbound notification */
		isis_notif_id_len_mismatch(circuit, id_len, raw_pdu,
					   sizeof(raw_pdu));
#endif /* ifndef FABRICD */
		pdu_counter_count_drop(circuit->area, pdu_type);
		return ISIS_ERROR;
	}

	uint8_t expected_length;
	if (pdu_size(pdu_type, &expected_length)) {
		zlog_warn("Unsupported ISIS PDU %hhu", pdu_type);
		pdu_counter_count_drop(circuit->area, pdu_type);
		return ISIS_WARNING;
	}

	if (length != expected_length) {
		flog_err(EC_ISIS_PACKET,
			 "Expected fixed header length = %hhu but got %hhu",
			 expected_length, length);
		pdu_counter_count_drop(circuit->area, pdu_type);
		return ISIS_ERROR;
	}

	if (stream_get_endp(circuit->rcv_stream) < length) {
		flog_err(
			EC_ISIS_PACKET,
			"PDU is too short to contain fixed header of given PDU type.");
		pdu_counter_count_drop(circuit->area, pdu_type);
		return ISIS_ERROR;
	}

	if (version2 != 1) {
		zlog_warn("Unsupported ISIS PDU version %hhu", version2);
#ifndef FABRICD
		/* send northbound notification */
		isis_notif_version_skew(circuit, version2, raw_pdu,
					sizeof(raw_pdu));
#endif /* ifndef FABRICD */
		pdu_counter_count_drop(circuit->area, pdu_type);
		return ISIS_WARNING;
	}

	if (circuit->is_passive) {
		zlog_warn("Received ISIS PDU on passive circuit %s",
			  circuit->interface->name);
		pdu_counter_count_drop(circuit->area, pdu_type);
		return ISIS_WARNING;
	}

	/* either 3 or 0 */
	if (pdu_type != FS_LINK_STATE /* FS PDU doesn't contain max area addr
					 field */
	    && max_area_addrs != 0
	    && max_area_addrs != circuit->isis->max_area_addrs) {
		flog_err(
			EC_ISIS_PACKET,
			"maximumAreaAddressesMismatch: maximumAreaAdresses in a received PDU %hhu while the parameter for this IS is %u",
			max_area_addrs, circuit->isis->max_area_addrs);
		circuit->max_area_addr_mismatches++;
#ifndef FABRICD
		/* send northbound notification */
		isis_notif_max_area_addr_mismatch(circuit, max_area_addrs,
						  raw_pdu, sizeof(raw_pdu));
#endif /* ifndef FABRICD */
		pdu_counter_count_drop(circuit->area, pdu_type);
		return ISIS_ERROR;
	}

	switch (pdu_type) {
	case L1_LAN_HELLO:
	case L2_LAN_HELLO:
	case P2P_HELLO:
		if (fabricd && pdu_type != P2P_HELLO) {
			pdu_counter_count_drop(circuit->area, pdu_type);
			return ISIS_ERROR;
		}

		retval = process_hello(pdu_type, circuit, ssnpa);
		break;
	case L1_LINK_STATE:
	case L2_LINK_STATE:
	case FS_LINK_STATE:
		if (fabricd && pdu_type != L2_LINK_STATE &&
		    pdu_type != FS_LINK_STATE) {
			pdu_counter_count_drop(circuit->area, pdu_type);
			return ISIS_ERROR;
		}

		retval = process_lsp(pdu_type, circuit, ssnpa, max_area_addrs);
		break;
	case L1_COMPLETE_SEQ_NUM:
	case L2_COMPLETE_SEQ_NUM:
	case L1_PARTIAL_SEQ_NUM:
	case L2_PARTIAL_SEQ_NUM:
		retval = process_snp(pdu_type, circuit, ssnpa);
		break;
	default:
		pdu_counter_count_drop(circuit->area, pdu_type);
		return ISIS_ERROR;
	}

	if (retval != ISIS_OK)
		pdu_counter_count_drop(circuit->area, pdu_type);

	return retval;
}

void isis_receive(struct event *thread)
{
	struct isis_circuit *circuit;
	uint8_t ssnpa[ETH_ALEN];

	/*
	 * Get the circuit
	 */
	circuit = EVENT_ARG(thread);
	assert(circuit);

	circuit->t_read = NULL;

	isis_circuit_stream(circuit, &circuit->rcv_stream);

#if ISIS_METHOD != ISIS_METHOD_BPF
	int retval;

	retval = circuit->rx(circuit, ssnpa);

	if (retval == ISIS_OK)
		isis_handle_pdu(circuit, ssnpa);
#else // ISIS_METHOD != ISIS_METHOD_BPF
	circuit->rx(circuit, ssnpa);
#endif

	/*
	 * prepare for next packet.
	 */
	if (!circuit->is_passive)
		isis_circuit_prepare(circuit);
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

static uint8_t hello_pdu_type(struct isis_circuit *circuit, int level)
{
	if (circuit->circ_type == CIRCUIT_T_BROADCAST)
		return (level == IS_LEVEL_1) ? L1_LAN_HELLO : L2_LAN_HELLO;
	else
		return P2P_HELLO;
}

static void put_hello_hdr(struct isis_circuit *circuit, int level,
			  size_t *len_pointer)
{
	uint8_t pdu_type = hello_pdu_type(circuit, level);

	isis_circuit_stream(circuit, &circuit->snd_stream);
	fill_fixed_hdr(pdu_type, circuit->snd_stream);

	stream_putc(circuit->snd_stream, circuit->is_type);
	stream_put(circuit->snd_stream, circuit->isis->sysid, ISIS_SYS_ID_LEN);

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
			uint8_t threeway_state;

			if (fabricd_initial_sync_is_in_progress(circuit->area)
			    && fabricd_initial_sync_circuit(circuit->area) != circuit)
				threeway_state = ISIS_THREEWAY_DOWN;
			else
				threeway_state = circuit->u.p2p.neighbor->threeway_state;
			isis_tlvs_add_threeway_adj(tlvs,
					threeway_state,
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

	if (circuit->ip_router) {
		struct list *circuit_ip_addrs = fabricd_ip_addrs(circuit);

		if (circuit_ip_addrs)
			isis_tlvs_add_ipv4_addresses(tlvs, circuit_ip_addrs);
	}

	if (circuit->ipv6_router)
		isis_tlvs_add_ipv6_addresses(tlvs, circuit->ipv6_link);

	/* RFC6119 section 4 define TLV 233 to provide Global IPv6 address */
	if (circuit->ipv6_router)
		isis_tlvs_add_global_ipv6_addresses(tlvs,
						    circuit->ipv6_non_link);

	bool should_pad_hello =
		circuit->pad_hellos == ISIS_HELLO_PADDING_ALWAYS ||
		(circuit->pad_hellos ==
			 ISIS_HELLO_PADDING_DURING_ADJACENCY_FORMATION &&
		 circuit->upadjcount[0] + circuit->upadjcount[1] == 0);

	if (isis_pack_tlvs(tlvs, circuit->snd_stream, len_pointer,
			   should_pad_hello, false)) {
		isis_free_tlvs(tlvs);
		return ISIS_WARNING; /* XXX: Maybe Log TLV structure? */
	}

	if (IS_DEBUG_ADJ_PACKETS) {
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
		if (IS_DEBUG_PACKET_DUMP)
			zlog_dump_data(STREAM_DATA(circuit->snd_stream),
				       stream_get_endp(circuit->snd_stream));
	}

	isis_free_tlvs(tlvs);

	pdu_counter_count(circuit->area->pdu_tx_counters,
			  hello_pdu_type(circuit, level));
	retval = circuit->tx(circuit, level);
	if (retval != ISIS_OK)
		flog_err(EC_ISIS_PACKET,
			 "ISIS-Adj (%s): Send L%d IIH on %s failed",
			 circuit->area->area_tag, level,
			 circuit->interface->name);

	return retval;
}

static void send_hello_cb(struct event *thread)
{
	struct isis_circuit_arg *arg = EVENT_ARG(thread);
	assert(arg);

	struct isis_circuit *circuit = arg->circuit;
	int level = arg->level;

	assert(circuit);

	if (circuit->circ_type == CIRCUIT_T_P2P) {
		circuit->u.p2p.t_send_p2p_hello = NULL;
		send_hello(circuit, 1);
		send_hello_sched(circuit, ISIS_LEVEL1,
				 1000 * circuit->hello_interval[1]);
		return;
	}

	if (circuit->circ_type != CIRCUIT_T_BROADCAST) {
		zlog_warn("ISIS-Hello (%s): Trying to send hello on unknown circuit type %d",
			  circuit->area->area_tag, circuit->circ_type);
		return;
	}

	circuit->u.bc.t_send_lan_hello[level - 1] = NULL;
	if (!(circuit->is_type & level)) {
		zlog_warn("ISIS-Hello (%s): Trying to send L%d IIH in L%d-only circuit",
			  circuit->area->area_tag, level, 3 - level);
		return;
	}

	if (circuit->u.bc.run_dr_elect[level - 1])
		isis_dr_elect(circuit, level);

	send_hello(circuit, level);

	/* set next timer thread */
	send_hello_sched(circuit, level, 1000 * circuit->hello_interval[level - 1]);
}

static void _send_hello_sched(struct isis_circuit *circuit,
			      struct event **threadp, int level, long delay)
{
	if (*threadp) {
		if (event_timer_remain_msec(*threadp) < (unsigned long)delay)
			return;

		EVENT_OFF(*threadp);
	}

	event_add_timer_msec(master, send_hello_cb,
			     &circuit->level_arg[level - 1],
			     isis_jitter(delay, IIH_JITTER), threadp);
}

void send_hello_sched(struct isis_circuit *circuit, int level, long delay)
{
	if (circuit->circ_type == CIRCUIT_T_P2P) {
		_send_hello_sched(circuit, &circuit->u.p2p.t_send_p2p_hello,
				  ISIS_LEVEL1, delay);
		return;
	}

	if (circuit->circ_type != CIRCUIT_T_BROADCAST) {
		zlog_warn("%s: encountered unknown circuit type %d on %s",
			  __func__, circuit->circ_type,
			  circuit->interface->name);
		return;
	}

	for (int loop_level = ISIS_LEVEL1; loop_level <= ISIS_LEVEL2; loop_level++) {
		if (!(loop_level & level))
			continue;

		_send_hello_sched(
			circuit,
			&circuit->u.bc.t_send_lan_hello[loop_level - 1],
			loop_level,
			delay
		);
	}
}


/*
 * Count the maximum number of lsps that can be accommodated by a given size.
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
	if (lspdb_count(&circuit->area->lspdb[level - 1]) == 0)
		return ISIS_OK;

	uint8_t pdu_type = (level == ISIS_LEVEL1) ? L1_COMPLETE_SEQ_NUM
						  : L2_COMPLETE_SEQ_NUM;

	isis_circuit_stream(circuit, &circuit->snd_stream);
	fill_fixed_hdr(pdu_type, circuit->snd_stream);

	size_t len_pointer = stream_get_endp(circuit->snd_stream);

	stream_putw(circuit->snd_stream, 0);
	stream_put(circuit->snd_stream, circuit->isis->sysid, ISIS_SYS_ID_LEN);
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
					   &circuit->area->lspdb[level - 1],
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

		if (IS_DEBUG_SNP_PACKETS) {
			zlog_debug(
				"ISIS-Snp (%s): Sending L%d CSNP on %s, length %zd",
				circuit->area->area_tag, level,
				circuit->interface->name,
				stream_get_endp(circuit->snd_stream));
			log_multiline(LOG_DEBUG, "              ", "%s",
				      isis_format_tlvs(tlvs, NULL));
			if (IS_DEBUG_PACKET_DUMP)
				zlog_dump_data(
					STREAM_DATA(circuit->snd_stream),
					stream_get_endp(circuit->snd_stream));
		}

		pdu_counter_count(circuit->area->pdu_tx_counters, pdu_type);
		int retval = circuit->tx(circuit, level);
		if (retval != ISIS_OK) {
			flog_err(EC_ISIS_PACKET,
				 "ISIS-Snp (%s): Send L%d CSNP on %s failed",
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
		loop = false;
		for (int i = ISIS_SYS_ID_LEN + 1; i >= 0; --i) {
			if (start[i] < (uint8_t)0xff) {
				start[i] += 1;
				loop = true;
				break;
			}
		}
		memset(stop, 0xff, ISIS_SYS_ID_LEN + 2);
		isis_free_tlvs(tlvs);
	}

	return ISIS_OK;
}

void send_l1_csnp(struct event *thread)
{
	struct isis_circuit *circuit;

	circuit = EVENT_ARG(thread);
	assert(circuit);

	circuit->t_send_csnp[0] = NULL;

	if ((circuit->circ_type == CIRCUIT_T_BROADCAST
	     && circuit->u.bc.is_dr[0])
	     || circuit->circ_type == CIRCUIT_T_P2P) {
		send_csnp(circuit, 1);
	}
	/* set next timer thread */
	event_add_timer(master, send_l1_csnp, circuit,
			isis_jitter(circuit->csnp_interval[0], CSNP_JITTER),
			&circuit->t_send_csnp[0]);
}

void send_l2_csnp(struct event *thread)
{
	struct isis_circuit *circuit;

	circuit = EVENT_ARG(thread);
	assert(circuit);

	circuit->t_send_csnp[1] = NULL;

	if ((circuit->circ_type == CIRCUIT_T_BROADCAST
	     && circuit->u.bc.is_dr[1])
             || circuit->circ_type == CIRCUIT_T_P2P) {
		send_csnp(circuit, 2);
	}
	/* set next timer thread */
	event_add_timer(master, send_l2_csnp, circuit,
			isis_jitter(circuit->csnp_interval[1], CSNP_JITTER),
			&circuit->t_send_csnp[1]);
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

	if (lspdb_count(&circuit->area->lspdb[level - 1]) == 0)
		return ISIS_OK;

	if (!circuit->snd_stream)
		return ISIS_ERROR;

	uint8_t pdu_type = (level == ISIS_LEVEL1) ? L1_PARTIAL_SEQ_NUM
						  : L2_PARTIAL_SEQ_NUM;

	isis_circuit_stream(circuit, &circuit->snd_stream);
	fill_fixed_hdr(pdu_type, circuit->snd_stream);

	size_t len_pointer = stream_get_endp(circuit->snd_stream);
	stream_putw(circuit->snd_stream, 0); /* length is filled in later */
	stream_put(circuit->snd_stream, circuit->isis->sysid, ISIS_SYS_ID_LEN);
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
		struct isis_lsp *lsp;

		tlvs = isis_alloc_tlvs();
		if (CHECK_FLAG(passwd->snp_auth, SNP_AUTH_SEND))
			isis_tlvs_add_auth(tlvs, passwd);

		frr_each (lspdb, &circuit->area->lspdb[level - 1], lsp) {
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

		if (IS_DEBUG_SNP_PACKETS) {
			zlog_debug(
				"ISIS-Snp (%s): Sending L%d PSNP on %s, length %zd",
				circuit->area->area_tag, level,
				circuit->interface->name,
				stream_get_endp(circuit->snd_stream));
			log_multiline(LOG_DEBUG, "              ", "%s",
				      isis_format_tlvs(tlvs, NULL));
			if (IS_DEBUG_PACKET_DUMP)
				zlog_dump_data(
					STREAM_DATA(circuit->snd_stream),
					stream_get_endp(circuit->snd_stream));
		}

		pdu_counter_count(circuit->area->pdu_tx_counters, pdu_type);
		int retval = circuit->tx(circuit, level);
		if (retval != ISIS_OK) {
			flog_err(EC_ISIS_PACKET,
				 "ISIS-Snp (%s): Send L%d PSNP on %s failed",
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

void send_l1_psnp(struct event *thread)
{

	struct isis_circuit *circuit;

	circuit = EVENT_ARG(thread);
	assert(circuit);

	circuit->t_send_psnp[0] = NULL;

	send_psnp(1, circuit);
	/* set next timer thread */
	event_add_timer(master, send_l1_psnp, circuit,
			isis_jitter(circuit->psnp_interval[0], PSNP_JITTER),
			&circuit->t_send_psnp[0]);
}

/*
 *  7.3.15.4 action on expiration of partial SNP interval
 *  level 2
 */
void send_l2_psnp(struct event *thread)
{
	struct isis_circuit *circuit;

	circuit = EVENT_ARG(thread);
	assert(circuit);

	circuit->t_send_psnp[1] = NULL;

	send_psnp(2, circuit);

	/* set next timer thread */
	event_add_timer(master, send_l2_psnp, circuit,
			isis_jitter(circuit->psnp_interval[1], PSNP_JITTER),
			&circuit->t_send_psnp[1]);
}

/*
 * ISO 10589 - 7.3.14.3
 */
void send_lsp(struct isis_circuit *circuit, struct isis_lsp *lsp,
	      enum isis_tx_type tx_type)
{
	int clear_srm = 1;
	int retval = ISIS_OK;

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
		flog_err(
			EC_ISIS_PACKET,
			"ISIS-Upd (%s): Can't send L%d LSP %pLS, seq 0x%08x, cksum 0x%04hx, lifetime %hus on %s. LSP Size is %zu while interface stream size is %zu.",
			circuit->area->area_tag, lsp->level, lsp->hdr.lsp_id,
			lsp->hdr.seqno, lsp->hdr.checksum,
			lsp->hdr.rem_lifetime, circuit->interface->name,
			stream_get_endp(lsp->pdu),
			stream_get_size(circuit->snd_stream));
#ifndef FABRICD
		/* send a northbound notification */
		isis_notif_lsp_too_large(circuit, stream_get_endp(lsp->pdu),
					 lsp->hdr.lsp_id);
#endif /* ifndef FABRICD */
		if (IS_DEBUG_PACKET_DUMP)
			zlog_dump_data(STREAM_DATA(lsp->pdu),
				       stream_get_endp(lsp->pdu));
		retval = ISIS_ERROR;
		goto out;
	}

	/* copy our lsp to the send buffer */
	stream_copy(circuit->snd_stream, lsp->pdu);

	if (tx_type == TX_LSP_CIRCUIT_SCOPED) {
		stream_putc_at(circuit->snd_stream, 4, FS_LINK_STATE);
		stream_putc_at(circuit->snd_stream, 7,
			       L2_CIRCUIT_FLOODING_SCOPE);
	}

	if (IS_DEBUG_UPDATE_PACKETS) {
		zlog_debug(
			"ISIS-Upd (%s): Sending %sL%d LSP %pLS, seq 0x%08x, cksum 0x%04hx, lifetime %hus on %s",
			circuit->area->area_tag,
			(tx_type == TX_LSP_CIRCUIT_SCOPED) ? "Circuit scoped "
							   : "",
			lsp->level, lsp->hdr.lsp_id, lsp->hdr.seqno,
			lsp->hdr.checksum, lsp->hdr.rem_lifetime,
			circuit->interface->name);
		if (IS_DEBUG_PACKET_DUMP)
			zlog_dump_data(STREAM_DATA(circuit->snd_stream),
				       stream_get_endp(circuit->snd_stream));
	}

	uint8_t pdu_type = (tx_type == TX_LSP_CIRCUIT_SCOPED) ? FS_LINK_STATE
			 : (lsp->level == ISIS_LEVEL1) ? L1_LINK_STATE
						       : L2_LINK_STATE;

	clear_srm = 0;
	pdu_counter_count(circuit->area->pdu_tx_counters, pdu_type);
	retval = circuit->tx(circuit, lsp->level);
	if (retval != ISIS_OK) {
		flog_err(EC_ISIS_PACKET,
			 "ISIS-Upd (%s): Send L%d LSP on %s failed %s",
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
		isis_tx_queue_del(circuit->tx_queue, lsp);
	}
}

void isis_log_pdu_drops(struct isis_area *area, const char *pdu_type)
{
	uint64_t total_drops = 0;

	for (int i = 0; i < PDU_COUNTER_SIZE; i++) {
		if (!area->pdu_drop_counters[i])
			continue;
		total_drops += area->pdu_drop_counters[i];
	}

	zlog_info("PDU drop detected of type: %s. %" PRIu64
		  " Total Drops; %" PRIu64 " L1 IIH drops;  %" PRIu64
		  " L2 IIH drops; %" PRIu64 " P2P IIH drops; %" PRIu64
		  " L1 LSP drops; %" PRIu64 " L2 LSP drops; %" PRIu64
		  " FS LSP drops; %" PRIu64 " L1 CSNP drops; %" PRIu64
		  " L2 CSNP drops; %" PRIu64 " L1 PSNP drops; %" PRIu64
		  " L2 PSNP drops.",
		  pdu_type, total_drops,
		  pdu_counter_get_count(area->pdu_drop_counters, L1_LAN_HELLO),
		  pdu_counter_get_count(area->pdu_drop_counters, L2_LAN_HELLO),
		  pdu_counter_get_count(area->pdu_drop_counters, P2P_HELLO),
		  pdu_counter_get_count(area->pdu_drop_counters, L1_LINK_STATE),
		  pdu_counter_get_count(area->pdu_drop_counters, L2_LINK_STATE),
		  pdu_counter_get_count(area->pdu_drop_counters, FS_LINK_STATE),
		  pdu_counter_get_count(area->pdu_drop_counters,
					L1_COMPLETE_SEQ_NUM),
		  pdu_counter_get_count(area->pdu_drop_counters,
					L2_COMPLETE_SEQ_NUM),
		  pdu_counter_get_count(area->pdu_drop_counters,
					L1_PARTIAL_SEQ_NUM),
		  pdu_counter_get_count(area->pdu_drop_counters,
					L2_PARTIAL_SEQ_NUM));
}
