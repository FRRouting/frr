/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "if.h"
#include "log.h"
#include "prefix.h"
#include "vty.h"
#include "plist.h"

#include "pimd.h"
#include "pim_vty.h"
#include "pim_pim.h"
#include "pim_msg.h"
#include "pim_util.h"
#include "pim_str.h"
#include "pim_iface.h"
#include "pim_rp.h"
#include "pim_rpf.h"
#include "pim_register.h"
#include "pim_jp_agg.h"
#include "pim_oil.h"

void pim_msg_build_header(uint8_t *pim_msg, size_t pim_msg_size,
			  uint8_t pim_msg_type)
{
	struct pim_msg_header *header = (struct pim_msg_header *)pim_msg;

	/*
	 * Write header
	 */
	header->ver = PIM_PROTO_VERSION;
	header->type = pim_msg_type;
	header->reserved = 0;


	header->checksum = 0;
	/*
	 * The checksum for Registers is done only on the first 8 bytes of the
	 * packet,
	 * including the PIM header and the next 4 bytes, excluding the data
	 * packet portion
	 */
	if (pim_msg_type == PIM_MSG_TYPE_REGISTER)
		header->checksum = in_cksum(pim_msg, PIM_MSG_REGISTER_LEN);
	else
		header->checksum = in_cksum(pim_msg, pim_msg_size);
}

uint8_t *pim_msg_addr_encode_ipv4_ucast(uint8_t *buf, struct in_addr addr)
{
	buf[0] = PIM_MSG_ADDRESS_FAMILY_IPV4; /* addr family */
	buf[1] = '\0';			      /* native encoding */
	memcpy(buf + 2, &addr, sizeof(struct in_addr));

	return buf + PIM_ENCODED_IPV4_UCAST_SIZE;
}

uint8_t *pim_msg_addr_encode_ipv4_group(uint8_t *buf, struct in_addr addr)
{
	buf[0] = PIM_MSG_ADDRESS_FAMILY_IPV4; /* addr family */
	buf[1] = '\0';			      /* native encoding */
	buf[2] = '\0';			      /* reserved */
	buf[3] = 32;			      /* mask len */
	memcpy(buf + 4, &addr, sizeof(struct in_addr));

	return buf + PIM_ENCODED_IPV4_GROUP_SIZE;
}

uint8_t *pim_msg_addr_encode_ipv4_source(uint8_t *buf, struct in_addr addr,
					 uint8_t bits)
{
	buf[0] = PIM_MSG_ADDRESS_FAMILY_IPV4; /* addr family */
	buf[1] = '\0';			      /* native encoding */
	buf[2] = bits;
	buf[3] = 32; /* mask len */
	memcpy(buf + 4, &addr, sizeof(struct in_addr));

	return buf + PIM_ENCODED_IPV4_SOURCE_SIZE;
}

/*
 * For the given 'struct pim_jp_sources' list
 * determine the size_t it would take up.
 */
size_t pim_msg_get_jp_group_size(struct list *sources)
{
	struct pim_jp_sources *js;
	size_t size = 0;

	if (!sources)
		return 0;

	size += sizeof(struct pim_encoded_group_ipv4);
	size += 4; // Joined sources (2) + Pruned Sources (2)

	size += sizeof(struct pim_encoded_source_ipv4) * sources->count;

	js = listgetdata(listhead(sources));
	if (js && js->up->sg.src.s_addr == INADDR_ANY) {
		struct pim_upstream *child, *up;
		struct listnode *up_node;

		up = js->up;
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug(
				"%s: Considering (%s) children for (S,G,rpt) prune",
				__PRETTY_FUNCTION__, up->sg_str);

		for (ALL_LIST_ELEMENTS_RO(up->sources, up_node, child)) {
			if (child->sptbit == PIM_UPSTREAM_SPTBIT_TRUE) {
				if (!pim_rpf_is_same(&up->rpf, &child->rpf)) {
					size += sizeof(
						struct pim_encoded_source_ipv4);
					PIM_UPSTREAM_FLAG_SET_SEND_SG_RPT_PRUNE(
						child->flags);
					if (PIM_DEBUG_PIM_PACKETS)
						zlog_debug(
							"%s: SPT Bit and RPF'(%s) != RPF'(S,G): Add Prune (%s,rpt) to compound message",
							__PRETTY_FUNCTION__,
							up->sg_str,
							child->sg_str);
				} else if (PIM_DEBUG_PIM_PACKETS)
					zlog_debug(
						"%s: SPT Bit and RPF'(%s) == RPF'(S,G): Not adding Prune for (%s,rpt)",
						__PRETTY_FUNCTION__, up->sg_str,
						child->sg_str);
			} else if (pim_upstream_is_sg_rpt(child)) {
				if (pim_upstream_empty_inherited_olist(child)) {
					size += sizeof(
						struct pim_encoded_source_ipv4);
					PIM_UPSTREAM_FLAG_SET_SEND_SG_RPT_PRUNE(
						child->flags);
					if (PIM_DEBUG_PIM_PACKETS)
						zlog_debug(
							"%s: inherited_olist(%s,rpt) is NULL, Add Prune to compound message",
							__PRETTY_FUNCTION__,
							child->sg_str);
				} else if (!pim_rpf_is_same(&up->rpf,
							    &child->rpf)) {
					size += sizeof(
						struct pim_encoded_source_ipv4);
					PIM_UPSTREAM_FLAG_SET_SEND_SG_RPT_PRUNE(
						child->flags);
					if (PIM_DEBUG_PIM_PACKETS)
						zlog_debug(
							"%s: RPF'(%s) != RPF'(%s,rpt), Add Prune to compound message",
							__PRETTY_FUNCTION__,
							up->sg_str,
							child->sg_str);
				} else if (PIM_DEBUG_PIM_PACKETS)
					zlog_debug(
						"%s: RPF'(%s) == RPF'(%s,rpt), Do not add Prune to compound message",
						__PRETTY_FUNCTION__, up->sg_str,
						child->sg_str);
			} else if (PIM_DEBUG_PIM_PACKETS)
				zlog_debug("%s: SPT bit is not set for (%s)",
					   __PRETTY_FUNCTION__, child->sg_str);
		}
	}
	return size;
}

size_t pim_msg_build_jp_groups(struct pim_jp_groups *grp,
			       struct pim_jp_agg_group *sgs, size_t size)
{
	struct listnode *node, *nnode;
	struct pim_jp_sources *source;
	struct pim_upstream *up = NULL;
	struct in_addr stosend;
	uint8_t bits;
	uint8_t tgroups = 0;

	memset(grp, 0, size);
	pim_msg_addr_encode_ipv4_group((uint8_t *)&grp->g, sgs->group);

	for (ALL_LIST_ELEMENTS(sgs->sources, node, nnode, source)) {
		/* number of joined/pruned sources */
		if (source->is_join)
			grp->joins++;
		else
			grp->prunes++;

		if (source->up->sg.src.s_addr == INADDR_ANY) {
			struct pim_instance *pim = source->up->channel_oil->pim;
			struct pim_rpf *rpf = pim_rp_g(pim, source->up->sg.grp);
			bits = PIM_ENCODE_SPARSE_BIT | PIM_ENCODE_WC_BIT
			       | PIM_ENCODE_RPT_BIT;
			stosend = rpf->rpf_addr.u.prefix4;
			/* Only Send SGRpt in case of *,G Join */
			if (source->is_join)
				up = source->up;
		} else {
			bits = PIM_ENCODE_SPARSE_BIT;
			stosend = source->up->sg.src;
		}

		pim_msg_addr_encode_ipv4_source((uint8_t *)&grp->s[tgroups],
						stosend, bits);
		tgroups++;
	}

	if (up) {
		struct pim_upstream *child;

		for (ALL_LIST_ELEMENTS(up->sources, node, nnode, child)) {
			if (PIM_UPSTREAM_FLAG_TEST_SEND_SG_RPT_PRUNE(
				    child->flags)) {
				pim_msg_addr_encode_ipv4_source(
					(uint8_t *)&grp->s[tgroups],
					child->sg.src,
					PIM_ENCODE_SPARSE_BIT
						| PIM_ENCODE_RPT_BIT);
				tgroups++;
				PIM_UPSTREAM_FLAG_UNSET_SEND_SG_RPT_PRUNE(
					child->flags);
				grp->prunes++;
			}
		}
	}

	grp->joins = htons(grp->joins);
	grp->prunes = htons(grp->prunes);

	return size;
}
