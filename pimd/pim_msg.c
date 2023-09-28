// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#include <zebra.h>

#include "if.h"
#include "log.h"
#include "prefix.h"
#include "vty.h"
#include "plist.h"

#include "pimd.h"
#include "pim_instance.h"
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

void pim_msg_build_header(pim_addr src, pim_addr dst, uint8_t *pim_msg,
			  size_t pim_msg_size, uint8_t pim_msg_type,
			  bool no_fwd)
{
	struct pim_msg_header *header = (struct pim_msg_header *)pim_msg;
	struct iovec iov[2], *iovp = iov;

	/*
	 * The checksum for Registers is done only on the first 8 bytes of the
	 * packet, including the PIM header and the next 4 bytes, excluding the
	 * data packet portion
	 *
	 * for IPv6, the pseudoheader upper-level protocol length is also
	 * truncated, so let's just set it here before everything else.
	 */
	if (pim_msg_type == PIM_MSG_TYPE_REGISTER)
		pim_msg_size = PIM_MSG_REGISTER_LEN;

#if PIM_IPV == 6
	struct ipv6_ph phdr = {
		.src = src,
		.dst = dst,
		.ulpl = htonl(pim_msg_size),
		.next_hdr = IPPROTO_PIM,
	};

	iovp->iov_base = &phdr;
	iovp->iov_len = sizeof(phdr);
	iovp++;
#endif

	/*
	 * Write header
	 */
	header->ver = PIM_PROTO_VERSION;
	header->type = pim_msg_type;
	header->Nbit = no_fwd;
	header->reserved = 0;

	header->checksum = 0;
	iovp->iov_base = header;
	iovp->iov_len = pim_msg_size;
	iovp++;

	header->checksum = in_cksumv(iov, iovp - iov);
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

uint8_t *pim_msg_addr_encode_ipv6_source(uint8_t *buf, struct in6_addr addr,
					 uint8_t bits)
{
	buf[0] = PIM_MSG_ADDRESS_FAMILY_IPV6; /* addr family */
	buf[1] = '\0';			      /* native encoding */
	buf[2] = bits;
	buf[3] = 128; /* mask len */
	buf += 4;

	memcpy(buf, &addr, sizeof(addr));
	buf += sizeof(addr);

	return buf;
}

uint8_t *pim_msg_addr_encode_ipv6_ucast(uint8_t *buf, struct in6_addr addr)
{
	buf[0] = PIM_MSG_ADDRESS_FAMILY_IPV6; /* addr family */
	buf[1] = '\0';			      /* native encoding */
	buf += 2;

	memcpy(buf, &addr, sizeof(addr));
	buf += sizeof(addr);

	return buf;
}

uint8_t *pim_msg_addr_encode_ipv6_group(uint8_t *buf, struct in6_addr addr)
{
	buf[0] = PIM_MSG_ADDRESS_FAMILY_IPV6; /* addr family */
	buf[1] = '\0';			      /* native encoding */
	buf[2] = '\0';			      /* reserved */
	buf[3] = 128;			      /* mask len */
	buf += 4;

	memcpy(buf, &addr, sizeof(addr));
	buf += sizeof(addr);

	return buf;
}

#if PIM_IPV == 4
#define pim_msg_addr_encode(what) pim_msg_addr_encode_ipv4_##what
#else
#define pim_msg_addr_encode(what) pim_msg_addr_encode_ipv6_##what
#endif

uint8_t *pim_msg_addr_encode_ucast(uint8_t *buf, pim_addr addr)
{
	return pim_msg_addr_encode(ucast)(buf, addr);
}

uint8_t *pim_msg_addr_encode_group(uint8_t *buf, pim_addr addr)
{
	return pim_msg_addr_encode(group)(buf, addr);
}

uint8_t *pim_msg_addr_encode_source(uint8_t *buf, pim_addr addr, uint8_t bits)
{
	return pim_msg_addr_encode(source)(buf, addr, bits);
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

	size += sizeof(pim_encoded_group);
	size += 4; // Joined sources (2) + Pruned Sources (2)

	size += sizeof(pim_encoded_source) * sources->count;

	js = listgetdata(listhead(sources));
	if (js && pim_addr_is_any(js->up->sg.src) && js->is_join) {
		struct pim_upstream *child, *up;
		struct listnode *up_node;

		up = js->up;
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug(
				"%s: Considering (%s) children for (S,G,rpt) prune",
				__func__, up->sg_str);

		for (ALL_LIST_ELEMENTS_RO(up->sources, up_node, child)) {
			/*
			 * PIM VXLAN is weird
			 * It auto creates the S,G and populates a bunch
			 * of flags that make it look like a SPT prune should
			 * be sent.  But this regularly scheduled join
			 * for the *,G in the VXLAN setup can happen at
			 * scheduled times *before* the null register
			 * is received by the RP to cause it to initiate
			 * the S,G joins toward the source.  Let's just
			 * assume that if this is a SRC VXLAN ORIG route
			 * and no actual ifchannels( joins ) have been
			 * created then do not send the embedded prune
			 * Why you may ask?  Well if the prune is S,G
			 * RPT Prune is received *before* the join
			 * from the RP( if it flows to this routers
			 * upstream interface ) then we'll just wisely
			 * create a mroute with an empty oil on
			 * the upstream intermediate router preventing
			 * packets from flowing to the RP
			 */
			if (PIM_UPSTREAM_FLAG_TEST_SRC_VXLAN_ORIG(child->flags) &&
			    listcount(child->ifchannels) == 0) {
				if (PIM_DEBUG_PIM_PACKETS)
					zlog_debug("%s: %s Vxlan originated S,G route with no ifchannels, not adding prune to compound message",
						   __func__, child->sg_str);
			} else if (!PIM_UPSTREAM_FLAG_TEST_USE_RPT(child->flags)) {
				/* If we are using SPT and the SPT and RPT IIFs
				 * are different we can prune the source off
				 * of the RPT.
				 * If RPF_interface(S) is not resolved hold
				 * decision to prune as SPT may end up on the
				 * same IIF as RPF_interface(RP).
				 */
				if (child->rpf.source_nexthop.interface &&
					!pim_rpf_is_same(&up->rpf,
						&child->rpf)) {
					size += sizeof(pim_encoded_source);
					PIM_UPSTREAM_FLAG_SET_SEND_SG_RPT_PRUNE(
						child->flags);
					if (PIM_DEBUG_PIM_PACKETS)
						zlog_debug(
							"%s: SPT Bit and RPF'(%s) != RPF'(S,G): Add Prune (%s,rpt) to compound message",
							__func__, up->sg_str,
							child->sg_str);
				} else if (PIM_DEBUG_PIM_PACKETS)
					zlog_debug(
						"%s: SPT Bit and RPF'(%s) == RPF'(S,G): Not adding Prune for (%s,rpt)",
						__func__, up->sg_str,
						child->sg_str);
			} else if (pim_upstream_empty_inherited_olist(child)) {
				/* S is supposed to be forwarded along the RPT
				 * but it's inherited OIL is empty. So just
				 * prune it off.
				 */
				size += sizeof(pim_encoded_source);
				PIM_UPSTREAM_FLAG_SET_SEND_SG_RPT_PRUNE(
						child->flags);
				if (PIM_DEBUG_PIM_PACKETS)
					zlog_debug(
						"%s: inherited_olist(%s,rpt) is NULL, Add Prune to compound message",
						__func__, child->sg_str);
			} else if (PIM_DEBUG_PIM_PACKETS)
				zlog_debug(
					"%s: Do not add Prune %s to compound message %s",
					__func__, child->sg_str, up->sg_str);
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
	pim_addr stosend;
	uint8_t bits;
	uint8_t tgroups = 0;

	memset(grp, 0, size);
	pim_msg_addr_encode_group((uint8_t *)&grp->g, sgs->group);

	for (ALL_LIST_ELEMENTS(sgs->sources, node, nnode, source)) {
		/* number of joined/pruned sources */
		if (source->is_join)
			grp->joins++;
		else
			grp->prunes++;

		if (pim_addr_is_any(source->up->sg.src)) {
			struct pim_instance *pim = source->up->channel_oil->pim;
			struct pim_rpf *rpf = pim_rp_g(pim, source->up->sg.grp);
			bits = PIM_ENCODE_SPARSE_BIT | PIM_ENCODE_WC_BIT
			       | PIM_ENCODE_RPT_BIT;
			stosend = rpf->rpf_addr;
			/* Only Send SGRpt in case of *,G Join */
			if (source->is_join)
				up = source->up;
		} else {
			bits = PIM_ENCODE_SPARSE_BIT;
			stosend = source->up->sg.src;
		}

		pim_msg_addr_encode_source((uint8_t *)&grp->s[tgroups], stosend,
					   bits);
		tgroups++;
	}

	if (up) {
		struct pim_upstream *child;

		for (ALL_LIST_ELEMENTS(up->sources, node, nnode, child)) {
			if (PIM_UPSTREAM_FLAG_TEST_SEND_SG_RPT_PRUNE(
				    child->flags)) {
				pim_msg_addr_encode_source(
					(uint8_t *)&grp->s[tgroups],
					child->sg.src,
					PIM_ENCODE_SPARSE_BIT |
						PIM_ENCODE_RPT_BIT);
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
