/*
 * IS-IS Rout(e)ing protocol - isis_te.c
 *
 * This is an implementation of RFC5305 & RFC 7810
 *
 *      Copyright (C) 2014 Orange Labs
 *      http://www.orange.com
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
#include <math.h>

#include "linklist.h"
#include "thread.h"
#include "vty.h"
#include "stream.h"
#include "memory.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "hash.h"
#include "if.h"
#include "vrf.h"
#include "checksum.h"
#include "md5.h"
#include "sockunion.h"
#include "network.h"
#include "sbuf.h"

#include "isisd/dict.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isisd.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_te.h"

/* Global varial for MPLS TE management */
struct isis_mpls_te isisMplsTE;

const char *mode2text[] = {"Disable", "Area", "AS", "Emulate"};

/*------------------------------------------------------------------------*
 * Followings are control functions for MPLS-TE parameters management.
 *------------------------------------------------------------------------*/

/* Search MPLS TE Circuit context from Interface */
static struct mpls_te_circuit *lookup_mpls_params_by_ifp(struct interface *ifp)
{
	struct isis_circuit *circuit;

	if ((circuit = circuit_scan_by_ifp(ifp)) == NULL)
		return NULL;

	return circuit->mtc;
}

/* Create new MPLS TE Circuit context */
struct mpls_te_circuit *mpls_te_circuit_new()
{
	struct mpls_te_circuit *mtc;

	zlog_debug("ISIS MPLS-TE: Create new MPLS TE Circuit context");

	mtc = XCALLOC(MTYPE_ISIS_MPLS_TE, sizeof(struct mpls_te_circuit));

	if (mtc == NULL)
		return NULL;

	mtc->status = disable;
	mtc->type = STD_TE;
	mtc->length = 0;

	return mtc;
}

/* Copy SUB TLVs parameters into a buffer - No space verification are performed
 */
/* Caller must verify before that there is enough free space in the buffer */
uint8_t add_te_subtlvs(uint8_t *buf, struct mpls_te_circuit *mtc)
{
	uint8_t size, *tlvs = buf;

	zlog_debug("ISIS MPLS-TE: Add TE Sub TLVs to buffer");

	if (mtc == NULL) {
		zlog_debug(
			"ISIS MPLS-TE: Abort! No MPLS TE Circuit available has been specified");
		return 0;
	}

	/* Create buffer if not provided */
	if (buf == NULL) {
		zlog_debug("ISIS MPLS-TE: Abort! No Buffer has been specified");
		return 0;
	}

	/* TE_SUBTLV_ADMIN_GRP */
	if (SUBTLV_TYPE(mtc->admin_grp) != 0) {
		size = SUBTLV_SIZE(&(mtc->admin_grp.header));
		memcpy(tlvs, &(mtc->admin_grp), size);
		tlvs += size;
	}

	/* TE_SUBTLV_LLRI */
	if (SUBTLV_TYPE(mtc->llri) != 0) {
		size = SUBTLV_SIZE(&(mtc->llri.header));
		memcpy(tlvs, &(mtc->llri), size);
		tlvs += size;
	}

	/* TE_SUBTLV_LCLIF_IPADDR */
	if (SUBTLV_TYPE(mtc->local_ipaddr) != 0) {
		size = SUBTLV_SIZE(&(mtc->local_ipaddr.header));
		memcpy(tlvs, &(mtc->local_ipaddr), size);
		tlvs += size;
	}

	/* TE_SUBTLV_RMTIF_IPADDR */
	if (SUBTLV_TYPE(mtc->rmt_ipaddr) != 0) {
		size = SUBTLV_SIZE(&(mtc->rmt_ipaddr.header));
		memcpy(tlvs, &(mtc->rmt_ipaddr), size);
		tlvs += size;
	}

	/* TE_SUBTLV_MAX_BW */
	if (SUBTLV_TYPE(mtc->max_bw) != 0) {
		size = SUBTLV_SIZE(&(mtc->max_bw.header));
		memcpy(tlvs, &(mtc->max_bw), size);
		tlvs += size;
	}

	/* TE_SUBTLV_MAX_RSV_BW */
	if (SUBTLV_TYPE(mtc->max_rsv_bw) != 0) {
		size = SUBTLV_SIZE(&(mtc->max_rsv_bw.header));
		memcpy(tlvs, &(mtc->max_rsv_bw), size);
		tlvs += size;
	}

	/* TE_SUBTLV_UNRSV_BW */
	if (SUBTLV_TYPE(mtc->unrsv_bw) != 0) {
		size = SUBTLV_SIZE(&(mtc->unrsv_bw.header));
		memcpy(tlvs, &(mtc->unrsv_bw), size);
		tlvs += size;
	}

	/* TE_SUBTLV_TE_METRIC */
	if (SUBTLV_TYPE(mtc->te_metric) != 0) {
		size = SUBTLV_SIZE(&(mtc->te_metric.header));
		memcpy(tlvs, &(mtc->te_metric), size);
		tlvs += size;
	}

	/* TE_SUBTLV_AV_DELAY */
	if (SUBTLV_TYPE(mtc->av_delay) != 0) {
		size = SUBTLV_SIZE(&(mtc->av_delay.header));
		memcpy(tlvs, &(mtc->av_delay), size);
		tlvs += size;
	}

	/* TE_SUBTLV_MM_DELAY */
	if (SUBTLV_TYPE(mtc->mm_delay) != 0) {
		size = SUBTLV_SIZE(&(mtc->mm_delay.header));
		memcpy(tlvs, &(mtc->mm_delay), size);
		tlvs += size;
	}

	/* TE_SUBTLV_DELAY_VAR */
	if (SUBTLV_TYPE(mtc->delay_var) != 0) {
		size = SUBTLV_SIZE(&(mtc->delay_var.header));
		memcpy(tlvs, &(mtc->delay_var), size);
		tlvs += size;
	}

	/* TE_SUBTLV_PKT_LOSS */
	if (SUBTLV_TYPE(mtc->pkt_loss) != 0) {
		size = SUBTLV_SIZE(&(mtc->pkt_loss.header));
		memcpy(tlvs, &(mtc->pkt_loss), size);
		tlvs += size;
	}

	/* TE_SUBTLV_RES_BW */
	if (SUBTLV_TYPE(mtc->res_bw) != 0) {
		size = SUBTLV_SIZE(&(mtc->res_bw.header));
		memcpy(tlvs, &(mtc->res_bw), size);
		tlvs += size;
	}

	/* TE_SUBTLV_AVA_BW */
	if (SUBTLV_TYPE(mtc->ava_bw) != 0) {
		size = SUBTLV_SIZE(&(mtc->ava_bw.header));
		memcpy(tlvs, &(mtc->ava_bw), size);
		tlvs += size;
	}

	/* TE_SUBTLV_USE_BW */
	if (SUBTLV_TYPE(mtc->use_bw) != 0) {
		size = SUBTLV_SIZE(&(mtc->use_bw.header));
		memcpy(tlvs, &(mtc->use_bw), size);
		tlvs += size;
	}

	/* Add before this line any other parsing of TLV */
	(void)tlvs;

	/* Update SubTLVs length */
	mtc->length = subtlvs_len(mtc);

	zlog_debug("ISIS MPLS-TE: Add %d bytes length SubTLVs", mtc->length);

	return mtc->length;
}

/* Compute total Sub-TLVs size */
uint8_t subtlvs_len(struct mpls_te_circuit *mtc)
{
	int length = 0;

	/* Sanity Check */
	if (mtc == NULL)
		return 0;

	/* TE_SUBTLV_ADMIN_GRP */
	if (SUBTLV_TYPE(mtc->admin_grp) != 0)
		length += SUBTLV_SIZE(&(mtc->admin_grp.header));

	/* TE_SUBTLV_LLRI */
	if (SUBTLV_TYPE(mtc->llri) != 0)
		length += SUBTLV_SIZE(&mtc->llri.header);

	/* TE_SUBTLV_LCLIF_IPADDR */
	if (SUBTLV_TYPE(mtc->local_ipaddr) != 0)
		length += SUBTLV_SIZE(&mtc->local_ipaddr.header);

	/* TE_SUBTLV_RMTIF_IPADDR */
	if (SUBTLV_TYPE(mtc->rmt_ipaddr) != 0)
		length += SUBTLV_SIZE(&mtc->rmt_ipaddr.header);

	/* TE_SUBTLV_MAX_BW */
	if (SUBTLV_TYPE(mtc->max_bw) != 0)
		length += SUBTLV_SIZE(&mtc->max_bw.header);

	/* TE_SUBTLV_MAX_RSV_BW */
	if (SUBTLV_TYPE(mtc->max_rsv_bw) != 0)
		length += SUBTLV_SIZE(&mtc->max_rsv_bw.header);

	/* TE_SUBTLV_UNRSV_BW */
	if (SUBTLV_TYPE(mtc->unrsv_bw) != 0)
		length += SUBTLV_SIZE(&mtc->unrsv_bw.header);

	/* TE_SUBTLV_TE_METRIC */
	if (SUBTLV_TYPE(mtc->te_metric) != 0)
		length += SUBTLV_SIZE(&mtc->te_metric.header);

	/* TE_SUBTLV_AV_DELAY */
	if (SUBTLV_TYPE(mtc->av_delay) != 0)
		length += SUBTLV_SIZE(&mtc->av_delay.header);

	/* TE_SUBTLV_MM_DELAY */
	if (SUBTLV_TYPE(mtc->mm_delay) != 0)
		length += SUBTLV_SIZE(&mtc->mm_delay.header);

	/* TE_SUBTLV_DELAY_VAR */
	if (SUBTLV_TYPE(mtc->delay_var) != 0)
		length += SUBTLV_SIZE(&mtc->delay_var.header);

	/* TE_SUBTLV_PKT_LOSS */
	if (SUBTLV_TYPE(mtc->pkt_loss) != 0)
		length += SUBTLV_SIZE(&mtc->pkt_loss.header);

	/* TE_SUBTLV_RES_BW */
	if (SUBTLV_TYPE(mtc->res_bw) != 0)
		length += SUBTLV_SIZE(&mtc->res_bw.header);

	/* TE_SUBTLV_AVA_BW */
	if (SUBTLV_TYPE(mtc->ava_bw) != 0)
		length += SUBTLV_SIZE(&mtc->ava_bw.header);

	/* TE_SUBTLV_USE_BW */
	if (SUBTLV_TYPE(mtc->use_bw) != 0)
		length += SUBTLV_SIZE(&mtc->use_bw.header);

	/* Check that length is lower than the MAXIMUM SUBTLV size i.e. 256 */
	if (length > MAX_SUBTLV_SIZE) {
		mtc->length = 0;
		return 0;
	}

	mtc->length = (uint8_t)length;

	return mtc->length;
}

/* Following are various functions to set MPLS TE parameters */
static void set_circuitparams_admin_grp(struct mpls_te_circuit *mtc,
					uint32_t admingrp)
{
	SUBTLV_TYPE(mtc->admin_grp) = TE_SUBTLV_ADMIN_GRP;
	SUBTLV_LEN(mtc->admin_grp) = SUBTLV_DEF_SIZE;
	mtc->admin_grp.value = htonl(admingrp);
	return;
}

static void __attribute__((unused))
set_circuitparams_llri(struct mpls_te_circuit *mtc, uint32_t local,
		       uint32_t remote)
{
	SUBTLV_TYPE(mtc->llri) = TE_SUBTLV_LLRI;
	SUBTLV_LEN(mtc->llri) = TE_SUBTLV_LLRI_SIZE;
	mtc->llri.local = htonl(local);
	mtc->llri.remote = htonl(remote);
}

void set_circuitparams_local_ipaddr(struct mpls_te_circuit *mtc,
				    struct in_addr addr)
{

	SUBTLV_TYPE(mtc->local_ipaddr) = TE_SUBTLV_LOCAL_IPADDR;
	SUBTLV_LEN(mtc->local_ipaddr) = SUBTLV_DEF_SIZE;
	mtc->local_ipaddr.value.s_addr = addr.s_addr;
	return;
}

void set_circuitparams_rmt_ipaddr(struct mpls_te_circuit *mtc,
				  struct in_addr addr)
{

	SUBTLV_TYPE(mtc->rmt_ipaddr) = TE_SUBTLV_RMT_IPADDR;
	SUBTLV_LEN(mtc->rmt_ipaddr) = SUBTLV_DEF_SIZE;
	mtc->rmt_ipaddr.value.s_addr = addr.s_addr;
	return;
}

static void set_circuitparams_max_bw(struct mpls_te_circuit *mtc, float fp)
{
	SUBTLV_TYPE(mtc->max_bw) = TE_SUBTLV_MAX_BW;
	SUBTLV_LEN(mtc->max_bw) = SUBTLV_DEF_SIZE;
	mtc->max_bw.value = htonf(fp);
	return;
}

static void set_circuitparams_max_rsv_bw(struct mpls_te_circuit *mtc, float fp)
{
	SUBTLV_TYPE(mtc->max_rsv_bw) = TE_SUBTLV_MAX_RSV_BW;
	SUBTLV_LEN(mtc->max_rsv_bw) = SUBTLV_DEF_SIZE;
	mtc->max_rsv_bw.value = htonf(fp);
	return;
}

static void set_circuitparams_unrsv_bw(struct mpls_te_circuit *mtc,
				       int priority, float fp)
{
	/* Note that TLV-length field is the size of array. */
	SUBTLV_TYPE(mtc->unrsv_bw) = TE_SUBTLV_UNRSV_BW;
	SUBTLV_LEN(mtc->unrsv_bw) = TE_SUBTLV_UNRSV_SIZE;
	mtc->unrsv_bw.value[priority] = htonf(fp);
	return;
}

static void set_circuitparams_te_metric(struct mpls_te_circuit *mtc,
					uint32_t te_metric)
{
	SUBTLV_TYPE(mtc->te_metric) = TE_SUBTLV_TE_METRIC;
	SUBTLV_LEN(mtc->te_metric) = TE_SUBTLV_TE_METRIC_SIZE;
	mtc->te_metric.value[0] = (te_metric >> 16) & 0xFF;
	mtc->te_metric.value[1] = (te_metric >> 8) & 0xFF;
	mtc->te_metric.value[2] = te_metric & 0xFF;
	return;
}

static void set_circuitparams_inter_as(struct mpls_te_circuit *mtc,
				       struct in_addr addr, uint32_t as)
{

	/* Set the Remote ASBR IP address and then the associated AS number */
	SUBTLV_TYPE(mtc->rip) = TE_SUBTLV_RIP;
	SUBTLV_LEN(mtc->rip) = SUBTLV_DEF_SIZE;
	mtc->rip.value.s_addr = addr.s_addr;

	SUBTLV_TYPE(mtc->ras) = TE_SUBTLV_RAS;
	SUBTLV_LEN(mtc->ras) = SUBTLV_DEF_SIZE;
	mtc->ras.value = htonl(as);
}

static void unset_circuitparams_inter_as(struct mpls_te_circuit *mtc)
{

	/* Reset the Remote ASBR IP address and then the associated AS number */
	SUBTLV_TYPE(mtc->rip) = 0;
	SUBTLV_LEN(mtc->rip) = 0;
	mtc->rip.value.s_addr = 0;

	SUBTLV_TYPE(mtc->ras) = 0;
	SUBTLV_LEN(mtc->ras) = 0;
	mtc->ras.value = 0;
}

static void set_circuitparams_av_delay(struct mpls_te_circuit *mtc,
				       uint32_t delay, uint8_t anormal)
{
	uint32_t tmp;
	/* Note that TLV-length field is the size of array. */
	SUBTLV_TYPE(mtc->av_delay) = TE_SUBTLV_AV_DELAY;
	SUBTLV_LEN(mtc->av_delay) = SUBTLV_DEF_SIZE;
	tmp = delay & TE_EXT_MASK;
	if (anormal)
		tmp |= TE_EXT_ANORMAL;
	mtc->av_delay.value = htonl(tmp);
	return;
}

static void set_circuitparams_mm_delay(struct mpls_te_circuit *mtc,
				       uint32_t low, uint32_t high,
				       uint8_t anormal)
{
	uint32_t tmp;
	/* Note that TLV-length field is the size of array. */
	SUBTLV_TYPE(mtc->mm_delay) = TE_SUBTLV_MM_DELAY;
	SUBTLV_LEN(mtc->mm_delay) = TE_SUBTLV_MM_DELAY_SIZE;
	tmp = low & TE_EXT_MASK;
	if (anormal)
		tmp |= TE_EXT_ANORMAL;
	mtc->mm_delay.low = htonl(tmp);
	mtc->mm_delay.high = htonl(high);
	return;
}

static void set_circuitparams_delay_var(struct mpls_te_circuit *mtc,
					uint32_t jitter)
{
	/* Note that TLV-length field is the size of array. */
	SUBTLV_TYPE(mtc->delay_var) = TE_SUBTLV_DELAY_VAR;
	SUBTLV_LEN(mtc->delay_var) = SUBTLV_DEF_SIZE;
	mtc->delay_var.value = htonl(jitter & TE_EXT_MASK);
	return;
}

static void set_circuitparams_pkt_loss(struct mpls_te_circuit *mtc,
				       uint32_t loss, uint8_t anormal)
{
	uint32_t tmp;
	/* Note that TLV-length field is the size of array. */
	SUBTLV_TYPE(mtc->pkt_loss) = TE_SUBTLV_PKT_LOSS;
	SUBTLV_LEN(mtc->pkt_loss) = SUBTLV_DEF_SIZE;
	tmp = loss & TE_EXT_MASK;
	if (anormal)
		tmp |= TE_EXT_ANORMAL;
	mtc->pkt_loss.value = htonl(tmp);
	return;
}

static void set_circuitparams_res_bw(struct mpls_te_circuit *mtc, float fp)
{
	/* Note that TLV-length field is the size of array. */
	SUBTLV_TYPE(mtc->res_bw) = TE_SUBTLV_RES_BW;
	SUBTLV_LEN(mtc->res_bw) = SUBTLV_DEF_SIZE;
	mtc->res_bw.value = htonf(fp);
	return;
}

static void set_circuitparams_ava_bw(struct mpls_te_circuit *mtc, float fp)
{
	/* Note that TLV-length field is the size of array. */
	SUBTLV_TYPE(mtc->ava_bw) = TE_SUBTLV_AVA_BW;
	SUBTLV_LEN(mtc->ava_bw) = SUBTLV_DEF_SIZE;
	mtc->ava_bw.value = htonf(fp);
	return;
}

static void set_circuitparams_use_bw(struct mpls_te_circuit *mtc, float fp)
{
	/* Note that TLV-length field is the size of array. */
	SUBTLV_TYPE(mtc->use_bw) = TE_SUBTLV_USE_BW;
	SUBTLV_LEN(mtc->use_bw) = SUBTLV_DEF_SIZE;
	mtc->use_bw.value = htonf(fp);
	return;
}

/* Main initialization / update function of the MPLS TE Circuit context */
/* Call when interface TE Link parameters are modified */
void isis_link_params_update(struct isis_circuit *circuit,
			     struct interface *ifp)
{
	int i;
	struct prefix_ipv4 *addr;
	struct mpls_te_circuit *mtc;

	/* Sanity Check */
	if ((circuit == NULL) || (ifp == NULL))
		return;

	zlog_info("MPLS-TE: Initialize circuit parameters for interface %s",
		  ifp->name);

	/* Check if MPLS TE Circuit context has not been already created */
	if (circuit->mtc == NULL)
		circuit->mtc = mpls_te_circuit_new();

	mtc = circuit->mtc;

	/* Fulfil MTC TLV from ifp TE Link parameters */
	if (HAS_LINK_PARAMS(ifp)) {
		mtc->status = enable;
		/* STD_TE metrics */
		if (IS_PARAM_SET(ifp->link_params, LP_ADM_GRP))
			set_circuitparams_admin_grp(
				mtc, ifp->link_params->admin_grp);
		else
			SUBTLV_TYPE(mtc->admin_grp) = 0;

		/* If not already set, register local IP addr from ip_addr list
		 * if it exists */
		if (SUBTLV_TYPE(mtc->local_ipaddr) == 0) {
			if (circuit->ip_addrs != NULL
			    && listcount(circuit->ip_addrs) != 0) {
				addr = (struct prefix_ipv4 *)listgetdata(
					(struct listnode *)listhead(
						circuit->ip_addrs));
				set_circuitparams_local_ipaddr(mtc,
							       addr->prefix);
			}
		}

		/* If not already set, try to determine Remote IP addr if
		 * circuit is P2P */
		if ((SUBTLV_TYPE(mtc->rmt_ipaddr) == 0)
		    && (circuit->circ_type == CIRCUIT_T_P2P)) {
			struct isis_adjacency *adj = circuit->u.p2p.neighbor;
			if (adj && adj->adj_state == ISIS_ADJ_UP
			    && adj->ipv4_address_count) {
				set_circuitparams_rmt_ipaddr(
					mtc, adj->ipv4_addresses[0]);
			}
		}

		if (IS_PARAM_SET(ifp->link_params, LP_MAX_BW))
			set_circuitparams_max_bw(mtc, ifp->link_params->max_bw);
		else
			SUBTLV_TYPE(mtc->max_bw) = 0;

		if (IS_PARAM_SET(ifp->link_params, LP_MAX_RSV_BW))
			set_circuitparams_max_rsv_bw(
				mtc, ifp->link_params->max_rsv_bw);
		else
			SUBTLV_TYPE(mtc->max_rsv_bw) = 0;

		if (IS_PARAM_SET(ifp->link_params, LP_UNRSV_BW))
			for (i = 0; i < MAX_CLASS_TYPE; i++)
				set_circuitparams_unrsv_bw(
					mtc, i, ifp->link_params->unrsv_bw[i]);
		else
			SUBTLV_TYPE(mtc->unrsv_bw) = 0;

		if (IS_PARAM_SET(ifp->link_params, LP_TE_METRIC))
			set_circuitparams_te_metric(
				mtc, ifp->link_params->te_metric);
		else
			SUBTLV_TYPE(mtc->te_metric) = 0;

		/* TE metric Extensions */
		if (IS_PARAM_SET(ifp->link_params, LP_DELAY))
			set_circuitparams_av_delay(
				mtc, ifp->link_params->av_delay, 0);
		else
			SUBTLV_TYPE(mtc->av_delay) = 0;

		if (IS_PARAM_SET(ifp->link_params, LP_MM_DELAY))
			set_circuitparams_mm_delay(
				mtc, ifp->link_params->min_delay,
				ifp->link_params->max_delay, 0);
		else
			SUBTLV_TYPE(mtc->mm_delay) = 0;

		if (IS_PARAM_SET(ifp->link_params, LP_DELAY_VAR))
			set_circuitparams_delay_var(
				mtc, ifp->link_params->delay_var);
		else
			SUBTLV_TYPE(mtc->delay_var) = 0;

		if (IS_PARAM_SET(ifp->link_params, LP_PKT_LOSS))
			set_circuitparams_pkt_loss(
				mtc, ifp->link_params->pkt_loss, 0);
		else
			SUBTLV_TYPE(mtc->pkt_loss) = 0;

		if (IS_PARAM_SET(ifp->link_params, LP_RES_BW))
			set_circuitparams_res_bw(mtc, ifp->link_params->res_bw);
		else
			SUBTLV_TYPE(mtc->res_bw) = 0;

		if (IS_PARAM_SET(ifp->link_params, LP_AVA_BW))
			set_circuitparams_ava_bw(mtc, ifp->link_params->ava_bw);
		else
			SUBTLV_TYPE(mtc->ava_bw) = 0;

		if (IS_PARAM_SET(ifp->link_params, LP_USE_BW))
			set_circuitparams_use_bw(mtc, ifp->link_params->use_bw);
		else
			SUBTLV_TYPE(mtc->use_bw) = 0;

		/* INTER_AS */
		if (IS_PARAM_SET(ifp->link_params, LP_RMT_AS))
			set_circuitparams_inter_as(mtc,
						   ifp->link_params->rmt_ip,
						   ifp->link_params->rmt_as);
		else
			/* reset inter-as TE params */
			unset_circuitparams_inter_as(mtc);

		/* Compute total length of SUB TLVs */
		mtc->length = subtlvs_len(mtc);

	} else
		mtc->status = disable;

/* Finally Update LSP */
#if 0
  if (IS_MPLS_TE(isisMplsTE) && circuit->area)
       lsp_regenerate_schedule (circuit->area, circuit->is_type, 0);
#endif
	return;
}

void isis_mpls_te_update(struct interface *ifp)
{
	struct isis_circuit *circuit;

	/* Sanity Check */
	if (ifp == NULL)
		return;

	/* Get circuit context from interface */
	if ((circuit = circuit_scan_by_ifp(ifp)) == NULL)
		return;

	/* Update TE TLVs ... */
	isis_link_params_update(circuit, ifp);

	/* ... and LSP */
	if (IS_MPLS_TE(isisMplsTE) && circuit->area)
		lsp_regenerate_schedule(circuit->area, circuit->is_type, 0);

	return;
}

/*------------------------------------------------------------------------*
 * Followings are vty session control functions.
 *------------------------------------------------------------------------*/

static uint8_t print_subtlv_admin_grp(struct sbuf *buf, int indent,
				      struct te_subtlv_admin_grp *tlv)
{
	sbuf_push(buf, indent, "Administrative Group: 0x%" PRIx32 "\n",
		  ntohl(tlv->value));
	return (SUBTLV_HDR_SIZE + SUBTLV_DEF_SIZE);
}

static uint8_t print_subtlv_llri(struct sbuf *buf, int indent,
				 struct te_subtlv_llri *tlv)
{
	sbuf_push(buf, indent, "Link Local  ID: %" PRIu32 "\n",
		  ntohl(tlv->local));
	sbuf_push(buf, indent, "Link Remote ID: %" PRIu32 "\n",
		  ntohl(tlv->remote));

	return (SUBTLV_HDR_SIZE + TE_SUBTLV_LLRI_SIZE);
}

static uint8_t print_subtlv_local_ipaddr(struct sbuf *buf, int indent,
					 struct te_subtlv_local_ipaddr *tlv)
{
	sbuf_push(buf, indent, "Local Interface IP Address(es): %s\n",
		  inet_ntoa(tlv->value));

	return (SUBTLV_HDR_SIZE + SUBTLV_DEF_SIZE);
}

static uint8_t print_subtlv_rmt_ipaddr(struct sbuf *buf, int indent,
				       struct te_subtlv_rmt_ipaddr *tlv)
{
	sbuf_push(buf, indent, "Remote Interface IP Address(es): %s\n",
		  inet_ntoa(tlv->value));

	return (SUBTLV_HDR_SIZE + SUBTLV_DEF_SIZE);
}

static uint8_t print_subtlv_max_bw(struct sbuf *buf, int indent,
				   struct te_subtlv_max_bw *tlv)
{
	float fval;

	fval = ntohf(tlv->value);

	sbuf_push(buf, indent, "Maximum Bandwidth: %g (Bytes/sec)\n", fval);

	return (SUBTLV_HDR_SIZE + SUBTLV_DEF_SIZE);
}

static uint8_t print_subtlv_max_rsv_bw(struct sbuf *buf, int indent,
				       struct te_subtlv_max_rsv_bw *tlv)
{
	float fval;

	fval = ntohf(tlv->value);

	sbuf_push(buf, indent, "Maximum Reservable Bandwidth: %g (Bytes/sec)\n",
		  fval);

	return (SUBTLV_HDR_SIZE + SUBTLV_DEF_SIZE);
}

static uint8_t print_subtlv_unrsv_bw(struct sbuf *buf, int indent,
				     struct te_subtlv_unrsv_bw *tlv)
{
	float fval1, fval2;
	int i;

	sbuf_push(buf, indent, "Unreserved Bandwidth:\n");

	for (i = 0; i < MAX_CLASS_TYPE; i += 2) {
		fval1 = ntohf(tlv->value[i]);
		fval2 = ntohf(tlv->value[i + 1]);
		sbuf_push(buf, indent + 2,
			  "[%d]: %g (Bytes/sec),\t[%d]: %g (Bytes/sec)\n", i,
			  fval1, i + 1, fval2);
	}

	return (SUBTLV_HDR_SIZE + TE_SUBTLV_UNRSV_SIZE);
}

static uint8_t print_subtlv_te_metric(struct sbuf *buf, int indent,
				      struct te_subtlv_te_metric *tlv)
{
	uint32_t te_metric;

	te_metric = tlv->value[2] | tlv->value[1] << 8 | tlv->value[0] << 16;
	sbuf_push(buf, indent, "Traffic Engineering Metric: %u\n", te_metric);

	return (SUBTLV_HDR_SIZE + SUBTLV_DEF_SIZE);
}

static uint8_t print_subtlv_ras(struct sbuf *buf, int indent,
				struct te_subtlv_ras *tlv)
{
	sbuf_push(buf, indent, "Inter-AS TE Remote AS number: %" PRIu32 "\n",
		  ntohl(tlv->value));

	return (SUBTLV_HDR_SIZE + SUBTLV_DEF_SIZE);
}

static uint8_t print_subtlv_rip(struct sbuf *buf, int indent,
				struct te_subtlv_rip *tlv)
{
	sbuf_push(buf, indent, "Inter-AS TE Remote ASBR IP address: %s\n",
		  inet_ntoa(tlv->value));

	return (SUBTLV_HDR_SIZE + SUBTLV_DEF_SIZE);
}

static uint8_t print_subtlv_av_delay(struct sbuf *buf, int indent,
				     struct te_subtlv_av_delay *tlv)
{
	uint32_t delay;
	uint32_t A;

	delay = (uint32_t)ntohl(tlv->value) & TE_EXT_MASK;
	A = (uint32_t)ntohl(tlv->value) & TE_EXT_ANORMAL;

	sbuf_push(buf, indent,
		  "%s Average Link Delay: %" PRIu32 " (micro-sec)\n",
		  A ? "Anomalous" : "Normal", delay);

	return (SUBTLV_HDR_SIZE + SUBTLV_DEF_SIZE);
}

static uint8_t print_subtlv_mm_delay(struct sbuf *buf, int indent,
				     struct te_subtlv_mm_delay *tlv)
{
	uint32_t low, high;
	uint32_t A;

	low = (uint32_t)ntohl(tlv->low) & TE_EXT_MASK;
	A = (uint32_t)ntohl(tlv->low) & TE_EXT_ANORMAL;
	high = (uint32_t)ntohl(tlv->high) & TE_EXT_MASK;

	sbuf_push(buf, indent, "%s Min/Max Link Delay: %" PRIu32 " / %" PRIu32 " (micro-sec)\n",
		  A ? "Anomalous" : "Normal", low, high);

	return (SUBTLV_HDR_SIZE + SUBTLV_DEF_SIZE);
}

static uint8_t print_subtlv_delay_var(struct sbuf *buf, int indent,
				      struct te_subtlv_delay_var *tlv)
{
	uint32_t jitter;

	jitter = (uint32_t)ntohl(tlv->value) & TE_EXT_MASK;

	sbuf_push(buf, indent, "Delay Variation: %" PRIu32 " (micro-sec)\n",
		  jitter);

	return (SUBTLV_HDR_SIZE + SUBTLV_DEF_SIZE);
}

static uint8_t print_subtlv_pkt_loss(struct sbuf *buf, int indent,
				     struct te_subtlv_pkt_loss *tlv)
{
	uint32_t loss;
	uint32_t A;
	float fval;

	loss = (uint32_t)ntohl(tlv->value) & TE_EXT_MASK;
	fval = (float)(loss * LOSS_PRECISION);
	A = (uint32_t)ntohl(tlv->value) & TE_EXT_ANORMAL;

	sbuf_push(buf, indent, "%s Link Packet Loss: %g (%%)\n",
		  A ? "Anomalous" : "Normal", fval);

	return (SUBTLV_HDR_SIZE + SUBTLV_DEF_SIZE);
}

static uint8_t print_subtlv_res_bw(struct sbuf *buf, int indent,
				   struct te_subtlv_res_bw *tlv)
{
	float fval;

	fval = ntohf(tlv->value);

	sbuf_push(buf, indent,
		  "Unidirectional Residual Bandwidth: %g (Bytes/sec)\n", fval);

	return (SUBTLV_HDR_SIZE + SUBTLV_DEF_SIZE);
}

static uint8_t print_subtlv_ava_bw(struct sbuf *buf, int indent,
				   struct te_subtlv_ava_bw *tlv)
{
	float fval;

	fval = ntohf(tlv->value);

	sbuf_push(buf, indent,
		  "Unidirectional Available Bandwidth: %g (Bytes/sec)\n", fval);

	return (SUBTLV_HDR_SIZE + SUBTLV_DEF_SIZE);
}

static uint8_t print_subtlv_use_bw(struct sbuf *buf, int indent,
				   struct te_subtlv_use_bw *tlv)
{
	float fval;

	fval = ntohf(tlv->value);

	sbuf_push(buf, indent,
		  "Unidirectional Utilized Bandwidth: %g (Bytes/sec)\n", fval);

	return (SUBTLV_HDR_SIZE + SUBTLV_DEF_SIZE);
}

static uint8_t print_unknown_tlv(struct sbuf *buf, int indent,
				 struct subtlv_header *tlvh)
{
	int i, rtn;
	uint8_t *v = (uint8_t *)tlvh;

	if (tlvh->length != 0) {
		sbuf_push(buf, indent,
			  "Unknown TLV: [type(%#.2x), length(%#.2x)]\n",
			  tlvh->type, tlvh->length);
		sbuf_push(buf, indent + 2, "Dump: [00]");
		rtn = 1; /* initialize end of line counter */
		for (i = 0; i < tlvh->length; i++) {
			sbuf_push(buf, 0, " %#.2x", v[i]);
			if (rtn == 8) {
				sbuf_push(buf, 0, "\n");
				sbuf_push(buf, indent + 8, "[%.2x]", i + 1);
				rtn = 1;
			} else
				rtn++;
		}
		sbuf_push(buf, 0, "\n");
	} else {
		sbuf_push(buf, indent,
			  "Unknown TLV: [type(%#.2x), length(%#.2x)]\n",
			  tlvh->type, tlvh->length);
	}

	return SUBTLV_SIZE(tlvh);
}

/* Main Show function */
void mpls_te_print_detail(struct sbuf *buf, int indent,
			  uint8_t *subtlvs, uint8_t subtlv_len)
{
	struct subtlv_header *tlvh = (struct subtlv_header *)subtlvs;
	uint16_t sum = 0;

	for (; sum < subtlv_len;
	     tlvh = (struct subtlv_header *)(subtlvs + sum)) {
		if (subtlv_len - sum < SUBTLV_SIZE(tlvh)) {
			sbuf_push(buf, indent, "Available data %" PRIu8 " is less than TLV size %u!\n",
				  subtlv_len - sum, SUBTLV_SIZE(tlvh));
			return;
		}

		switch (tlvh->type) {
		case TE_SUBTLV_ADMIN_GRP:
			if (tlvh->length != SUBTLV_DEF_SIZE) {
				sbuf_push(buf, indent, "TLV size does not match expected size for Administrative Group!\n");
				return;
			}
			sum += print_subtlv_admin_grp(buf, indent,
				(struct te_subtlv_admin_grp *)tlvh);
			break;
		case TE_SUBTLV_LLRI:
			if (tlvh->length != TE_SUBTLV_LLRI_SIZE) {
				sbuf_push(buf, indent, "TLV size does not match expected size for Link ID!\n");
				return;
			}
			sum += print_subtlv_llri(buf, indent,
						 (struct te_subtlv_llri *)tlvh);
			break;
		case TE_SUBTLV_LOCAL_IPADDR:
			if (tlvh->length != SUBTLV_DEF_SIZE) {
				sbuf_push(buf, indent, "TLV size does not match expected size for Local IP address!\n");
				return;
			}
			sum += print_subtlv_local_ipaddr(buf, indent,
				(struct te_subtlv_local_ipaddr *)tlvh);
			break;
		case TE_SUBTLV_RMT_IPADDR:
			if (tlvh->length != SUBTLV_DEF_SIZE) {
				sbuf_push(buf, indent, "TLV size does not match expected size for Remote Interface address!\n");
				return;
			}
			sum += print_subtlv_rmt_ipaddr(buf, indent,
				(struct te_subtlv_rmt_ipaddr *)tlvh);
			break;
		case TE_SUBTLV_MAX_BW:
			if (tlvh->length != SUBTLV_DEF_SIZE) {
				sbuf_push(buf, indent, "TLV size does not match expected size for Maximum Bandwidth!\n");
				return;
			}
			sum += print_subtlv_max_bw(buf, indent,
				(struct te_subtlv_max_bw *)tlvh);
			break;
		case TE_SUBTLV_MAX_RSV_BW:
			if (tlvh->length != SUBTLV_DEF_SIZE) {
				sbuf_push(buf, indent, "TLV size does not match expected size for Maximum Reservable Bandwidth!\n");
				return;
			}
			sum += print_subtlv_max_rsv_bw(buf, indent,
				(struct te_subtlv_max_rsv_bw *)tlvh);
			break;
		case TE_SUBTLV_UNRSV_BW:
			if (tlvh->length != TE_SUBTLV_UNRSV_SIZE) {
				sbuf_push(buf, indent, "TLV size does not match expected size for Unreserved Bandwidth!\n");
				return;
			}
			sum += print_subtlv_unrsv_bw(buf, indent,
				(struct te_subtlv_unrsv_bw *)tlvh);
			break;
		case TE_SUBTLV_TE_METRIC:
			if (tlvh->length != SUBTLV_DEF_SIZE) {
				sbuf_push(buf, indent, "TLV size does not match expected size for Traffic Engineering Metric!\n");
				return;
			}
			sum += print_subtlv_te_metric(buf, indent,
				(struct te_subtlv_te_metric *)tlvh);
			break;
		case TE_SUBTLV_RAS:
			if (tlvh->length != SUBTLV_DEF_SIZE) {
				sbuf_push(buf, indent, "TLV size does not match expected size for Remote AS number!\n");
				return;
			}
			sum += print_subtlv_ras(buf, indent,
						(struct te_subtlv_ras *)tlvh);
			break;
		case TE_SUBTLV_RIP:
			if (tlvh->length != SUBTLV_DEF_SIZE) {
				sbuf_push(buf, indent, "TLV size does not match expected size for Remote ASBR IP Address!\n");
				return;
			}
			sum += print_subtlv_rip(buf, indent,
						(struct te_subtlv_rip *)tlvh);
			break;
		case TE_SUBTLV_AV_DELAY:
			if (tlvh->length != SUBTLV_DEF_SIZE) {
				sbuf_push(buf, indent, "TLV size does not match expected size for Average Link Delay!\n");
				return;
			}
			sum += print_subtlv_av_delay(buf, indent,
				(struct te_subtlv_av_delay *)tlvh);
			break;
		case TE_SUBTLV_MM_DELAY:
			if (tlvh->length != SUBTLV_DEF_SIZE) {
				sbuf_push(buf, indent, "TLV size does not match expected size for Min/Max Link Delay!\n");
				return;
			}
			sum += print_subtlv_mm_delay(buf, indent,
				(struct te_subtlv_mm_delay *)tlvh);
			break;
		case TE_SUBTLV_DELAY_VAR:
			if (tlvh->length != SUBTLV_DEF_SIZE) {
				sbuf_push(buf, indent, "TLV size does not match expected size for Delay Variation!\n");
				return;
			}
			sum += print_subtlv_delay_var(buf, indent,
				(struct te_subtlv_delay_var *)tlvh);
			break;
		case TE_SUBTLV_PKT_LOSS:
			if (tlvh->length != SUBTLV_DEF_SIZE) {
				sbuf_push(buf, indent, "TLV size does not match expected size for Link Packet Loss!\n");
				return;
			}
			sum += print_subtlv_pkt_loss(buf, indent,
				(struct te_subtlv_pkt_loss *)tlvh);
			break;
		case TE_SUBTLV_RES_BW:
			if (tlvh->length != SUBTLV_DEF_SIZE) {
				sbuf_push(buf, indent, "TLV size does not match expected size for Unidirectional Residual Bandwidth!\n");
				return;
			}
			sum += print_subtlv_res_bw(buf, indent,
				(struct te_subtlv_res_bw *)tlvh);
			break;
		case TE_SUBTLV_AVA_BW:
			if (tlvh->length != SUBTLV_DEF_SIZE) {
				sbuf_push(buf, indent, "TLV size does not match expected size for Unidirectional Available Bandwidth!\n");
				return;
			}
			sum += print_subtlv_ava_bw(buf, indent,
				(struct te_subtlv_ava_bw *)tlvh);
			break;
		case TE_SUBTLV_USE_BW:
			if (tlvh->length != SUBTLV_DEF_SIZE) {
				sbuf_push(buf, indent, "TLV size does not match expected size for Unidirectional Utilized Bandwidth!\n");
				return;
			}
			sum += print_subtlv_use_bw(buf, indent,
				(struct te_subtlv_use_bw *)tlvh);
			break;
		default:
			sum += print_unknown_tlv(buf, indent, tlvh);
			break;
		}
	}
	return;
}

/* Specific MPLS TE router parameters write function */
void isis_mpls_te_config_write_router(struct vty *vty)
{
	if (IS_MPLS_TE(isisMplsTE)) {
		vty_out(vty, "  mpls-te on\n");
		vty_out(vty, "  mpls-te router-address %s\n",
			inet_ntoa(isisMplsTE.router_id));
	}

	return;
}


/*------------------------------------------------------------------------*
 * Followings are vty command functions.
 *------------------------------------------------------------------------*/

DEFUN (isis_mpls_te_on,
       isis_mpls_te_on_cmd,
       "mpls-te on",
       MPLS_TE_STR
       "Enable MPLS-TE functionality\n")
{
	struct listnode *node;
	struct isis_circuit *circuit;

	if (IS_MPLS_TE(isisMplsTE))
		return CMD_SUCCESS;

	if (IS_DEBUG_ISIS(DEBUG_TE))
		zlog_debug("ISIS MPLS-TE: OFF -> ON");

	isisMplsTE.status = enable;

	/*
	 * Following code is intended to handle two cases;
	 *
	 * 1) MPLS-TE was disabled at startup time, but now become enabled.
	 * In this case, we must enable MPLS-TE Circuit regarding interface
	 * MPLS_TE flag
	 * 2) MPLS-TE was once enabled then disabled, and now enabled again.
	 */
	for (ALL_LIST_ELEMENTS_RO(isisMplsTE.cir_list, node, circuit)) {
		if (circuit->mtc == NULL || IS_FLOOD_AS(circuit->mtc->type))
			continue;

		if ((circuit->mtc->status == disable)
		    && HAS_LINK_PARAMS(circuit->interface))
			circuit->mtc->status = enable;
		else
			continue;

		/* Reoriginate STD_TE & GMPLS circuits */
		if (circuit->area)
			lsp_regenerate_schedule(circuit->area, circuit->is_type,
						0);
	}

	return CMD_SUCCESS;
}

DEFUN (no_isis_mpls_te_on,
       no_isis_mpls_te_on_cmd,
       "no mpls-te",
       NO_STR
       "Disable the MPLS-TE functionality\n")
{
	struct listnode *node;
	struct isis_circuit *circuit;

	if (isisMplsTE.status == disable)
		return CMD_SUCCESS;

	if (IS_DEBUG_ISIS(DEBUG_TE))
		zlog_debug("ISIS MPLS-TE: ON -> OFF");

	isisMplsTE.status = disable;

	/* Flush LSP if circuit engage */
	for (ALL_LIST_ELEMENTS_RO(isisMplsTE.cir_list, node, circuit)) {
		if (circuit->mtc == NULL || (circuit->mtc->status == disable))
			continue;

		/* disable MPLS_TE Circuit */
		circuit->mtc->status = disable;

		/* Re-originate circuit without STD_TE & GMPLS parameters */
		if (circuit->area)
			lsp_regenerate_schedule(circuit->area, circuit->is_type,
						0);
	}

	return CMD_SUCCESS;
}

DEFUN (isis_mpls_te_router_addr,
       isis_mpls_te_router_addr_cmd,
       "mpls-te router-address A.B.C.D",
       MPLS_TE_STR
       "Stable IP address of the advertising router\n"
       "MPLS-TE router address in IPv4 address format\n")
{
	int idx_ipv4 = 2;
	struct in_addr value;
	struct listnode *node;
	struct isis_area *area;

	if (!inet_aton(argv[idx_ipv4]->arg, &value)) {
		vty_out(vty, "Please specify Router-Addr by A.B.C.D\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	isisMplsTE.router_id.s_addr = value.s_addr;

	if (isisMplsTE.status == disable)
		return CMD_SUCCESS;

	/* Update main Router ID in isis global structure */
	isis->router_id = value.s_addr;
	/* And re-schedule LSP update */
	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area))
		if (listcount(area->area_addrs) > 0)
			lsp_regenerate_schedule(area, area->is_type, 0);

	return CMD_SUCCESS;
}

DEFUN (isis_mpls_te_inter_as,
       isis_mpls_te_inter_as_cmd,
       "mpls-te inter-as <level-1|level-1-2|level-2-only>",
       MPLS_TE_STR
       "Configure MPLS-TE Inter-AS support\n"
       "AREA native mode self originate INTER-AS LSP with L1 only flooding scope)\n"
       "AREA native mode self originate INTER-AS LSP with L1 and L2 flooding scope)\n"
       "AS native mode self originate INTER-AS LSP with L2 only flooding scope\n")
{
	vty_out(vty, "Not yet supported\n");
	return CMD_SUCCESS;
}

DEFUN (no_isis_mpls_te_inter_as,
       no_isis_mpls_te_inter_as_cmd,
       "no mpls-te inter-as",
       NO_STR
       "Disable the MPLS-TE functionality\n"
       "Disable MPLS-TE Inter-AS support\n")
{

	vty_out(vty, "Not yet supported\n");
	return CMD_SUCCESS;
}

DEFUN (show_isis_mpls_te_router,
       show_isis_mpls_te_router_cmd,
       "show isis mpls-te router",
       SHOW_STR
       ISIS_STR
       MPLS_TE_STR
       "Router information\n")
{
	if (IS_MPLS_TE(isisMplsTE)) {
		vty_out(vty, "--- MPLS-TE router parameters ---\n");

		if (ntohs(isisMplsTE.router_id.s_addr) != 0)
			vty_out(vty, "  Router-Address: %s\n",
				inet_ntoa(isisMplsTE.router_id));
		else
			vty_out(vty, "  N/A\n");
	} else
		vty_out(vty, "  MPLS-TE is disable on this router\n");

	return CMD_SUCCESS;
}

static void show_mpls_te_sub(struct vty *vty, struct interface *ifp)
{
	struct mpls_te_circuit *mtc;
	struct sbuf buf;

	sbuf_init(&buf, NULL, 0);

	if ((IS_MPLS_TE(isisMplsTE))
	    && ((mtc = lookup_mpls_params_by_ifp(ifp)) != NULL)) {
		/* Continue only if interface is not passive or support Inter-AS
		 * TEv2 */
		if (mtc->status != enable) {
			if (IS_INTER_AS(mtc->type)) {
				vty_out(vty,
					"-- Inter-AS TEv2 link parameters for %s --\n",
					ifp->name);
			} else {
				/* MPLS-TE is not activate on this interface */
				/* or this interface is passive and Inter-AS
				 * TEv2 is not activate */
				vty_out(vty,
					"  %s: MPLS-TE is disabled on this interface\n",
					ifp->name);
				return;
			}
		} else {
			vty_out(vty, "-- MPLS-TE link parameters for %s --\n",
				ifp->name);
		}

		sbuf_reset(&buf);
		print_subtlv_admin_grp(&buf, 4, &mtc->admin_grp);

		if (SUBTLV_TYPE(mtc->local_ipaddr) != 0)
			print_subtlv_local_ipaddr(&buf, 4, &mtc->local_ipaddr);
		if (SUBTLV_TYPE(mtc->rmt_ipaddr) != 0)
			print_subtlv_rmt_ipaddr(&buf, 4, &mtc->rmt_ipaddr);

		print_subtlv_max_bw(&buf, 4, &mtc->max_bw);
		print_subtlv_max_rsv_bw(&buf, 4, &mtc->max_rsv_bw);
		print_subtlv_unrsv_bw(&buf, 4, &mtc->unrsv_bw);
		print_subtlv_te_metric(&buf, 4, &mtc->te_metric);

		if (IS_INTER_AS(mtc->type)) {
			if (SUBTLV_TYPE(mtc->ras) != 0)
				print_subtlv_ras(&buf, 4, &mtc->ras);
			if (SUBTLV_TYPE(mtc->rip) != 0)
				print_subtlv_rip(&buf, 4, &mtc->rip);
		}

		print_subtlv_av_delay(&buf, 4, &mtc->av_delay);
		print_subtlv_mm_delay(&buf, 4, &mtc->mm_delay);
		print_subtlv_delay_var(&buf, 4, &mtc->delay_var);
		print_subtlv_pkt_loss(&buf, 4, &mtc->pkt_loss);
		print_subtlv_res_bw(&buf, 4, &mtc->res_bw);
		print_subtlv_ava_bw(&buf, 4, &mtc->ava_bw);
		print_subtlv_use_bw(&buf, 4, &mtc->use_bw);

		vty_multiline(vty, "", "%s", sbuf_buf(&buf));
		vty_out(vty, "---------------\n\n");
	} else {
		vty_out(vty, "  %s: MPLS-TE is disabled on this interface\n",
			ifp->name);
	}

	sbuf_free(&buf);
	return;
}

DEFUN (show_isis_mpls_te_interface,
       show_isis_mpls_te_interface_cmd,
       "show isis mpls-te interface [INTERFACE]",
       SHOW_STR
       ISIS_STR
       MPLS_TE_STR
       "Interface information\n"
       "Interface name\n")
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	int idx_interface = 4;
	struct interface *ifp;

	/* Show All Interfaces. */
	if (argc == 4) {
		FOR_ALL_INTERFACES (vrf, ifp)
			show_mpls_te_sub(vty, ifp);
	}
	/* Interface name is specified. */
	else {
		if ((ifp = if_lookup_by_name(argv[idx_interface]->arg,
					     VRF_DEFAULT))
		    == NULL)
			vty_out(vty, "No such interface name\n");
		else
			show_mpls_te_sub(vty, ifp);
	}

	return CMD_SUCCESS;
}

/* Initialize MPLS_TE */
void isis_mpls_te_init(void)
{

	zlog_debug("ISIS MPLS-TE: Initialize");

	/* Initialize MPLS_TE structure */
	isisMplsTE.status = disable;
	isisMplsTE.level = 0;
	isisMplsTE.inter_as = off;
	isisMplsTE.interas_areaid.s_addr = 0;
	isisMplsTE.cir_list = list_new();
	isisMplsTE.router_id.s_addr = 0;

	/* Register new VTY commands */
	install_element(VIEW_NODE, &show_isis_mpls_te_router_cmd);
	install_element(VIEW_NODE, &show_isis_mpls_te_interface_cmd);

	install_element(ISIS_NODE, &isis_mpls_te_on_cmd);
	install_element(ISIS_NODE, &no_isis_mpls_te_on_cmd);
	install_element(ISIS_NODE, &isis_mpls_te_router_addr_cmd);
	install_element(ISIS_NODE, &isis_mpls_te_inter_as_cmd);
	install_element(ISIS_NODE, &no_isis_mpls_te_inter_as_cmd);

	return;
}
