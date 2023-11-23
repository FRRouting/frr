// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#include <zebra.h>

#include "log.h"
#include "if.h"

#include "pimd.h"
#include "pim_instance.h"
#include "pim_pim.h"
#include "pim_str.h"
#include "pim_tlv.h"
#include "pim_util.h"
#include "pim_hello.h"
#include "pim_iface.h"
#include "pim_neighbor.h"
#include "pim_upstream.h"
#include "pim_bsm.h"

static void on_trace(const char *label, struct interface *ifp, pim_addr src)
{
	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("%s: from %pPAs on %s", label, &src, ifp->name);
}

static void tlv_trace_bool(const char *label, const char *tlv_name,
			   const char *ifname, pim_addr src_addr, int isset,
			   int value)
{
	if (isset)
		zlog_debug(
			"%s: PIM hello option from %pPAs on interface %s: %s=%d",
			label, &src_addr, ifname, tlv_name, value);
}

static void tlv_trace_uint16(const char *label, const char *tlv_name,
			     const char *ifname, pim_addr src_addr, int isset,
			     uint16_t value)
{
	if (isset)
		zlog_debug(
			"%s: PIM hello option from %pPAs on interface %s: %s=%u",
			label, &src_addr, ifname, tlv_name, value);
}

static void tlv_trace_uint32(const char *label, const char *tlv_name,
			     const char *ifname, pim_addr src_addr, int isset,
			     uint32_t value)
{
	if (isset)
		zlog_debug(
			"%s: PIM hello option from %pPAs on interface %s: %s=%u",
			label, &src_addr, ifname, tlv_name, value);
}

static void tlv_trace_uint32_hex(const char *label, const char *tlv_name,
				 const char *ifname, pim_addr src_addr,
				 int isset, uint32_t value)
{
	if (isset)
		zlog_debug(
			"%s: PIM hello option from %pPAs on interface %s: %s=%08x",
			label, &src_addr, ifname, tlv_name, value);
}

static void tlv_trace_list(const char *label, const char *tlv_name,
			   const char *ifname, pim_addr src_addr, int isset,
			   struct list *addr_list)
{
	if (isset)
		zlog_debug(
			"%s: PIM hello option from %pPAs on interface %s: %s size=%d list=%p",
			label, &src_addr, ifname, tlv_name,
			addr_list ? ((int)listcount(addr_list)) : -1,
			(void *)addr_list);
}

#define FREE_ADDR_LIST                                                         \
	if (hello_option_addr_list) {                                          \
		list_delete(&hello_option_addr_list);                          \
	}

#define FREE_ADDR_LIST_THEN_RETURN(code)                                       \
	{                                                                      \
		FREE_ADDR_LIST                                                 \
		return (code);                                                 \
	}

int pim_hello_recv(struct interface *ifp, pim_addr src_addr, uint8_t *tlv_buf,
		   int tlv_buf_size)
{
	struct pim_interface *pim_ifp;
	struct pim_neighbor *neigh;
	uint8_t *tlv_curr;
	uint8_t *tlv_pastend;
	pim_hello_options hello_options =
		0; /* bit array recording options found */
	uint16_t hello_option_holdtime = 0;
	uint16_t hello_option_propagation_delay = 0;
	uint16_t hello_option_override_interval = 0;
	uint32_t hello_option_dr_priority = 0;
	uint32_t hello_option_generation_id = 0;
	struct list *hello_option_addr_list = 0;

	if (PIM_DEBUG_PIM_HELLO)
		on_trace(__func__, ifp, src_addr);

	pim_ifp = ifp->info;
	assert(pim_ifp);

	if (pim_ifp->pim_passive_enable) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug(
				"skip receiving PIM message on passive interface %s",
				ifp->name);
		return 0;
	}

	++pim_ifp->pim_ifstat_hello_recv;

	/*
	  Parse PIM hello TLVs
	 */
	assert(tlv_buf_size >= 0);
	tlv_curr = tlv_buf;
	tlv_pastend = tlv_buf + tlv_buf_size;

	while (tlv_curr < tlv_pastend) {
		uint16_t option_type;
		uint16_t option_len;
		int remain = tlv_pastend - tlv_curr;

		if (remain < PIM_TLV_MIN_SIZE) {
			if (PIM_DEBUG_PIM_HELLO)
				zlog_debug(
					"%s: short PIM hello TLV size=%d < min=%d from %pPAs on interface %s",
					__func__, remain, PIM_TLV_MIN_SIZE,
					&src_addr, ifp->name);
			FREE_ADDR_LIST_THEN_RETURN(-1);
		}

		option_type = PIM_TLV_GET_TYPE(tlv_curr);
		tlv_curr += PIM_TLV_TYPE_SIZE;
		option_len = PIM_TLV_GET_LENGTH(tlv_curr);
		tlv_curr += PIM_TLV_LENGTH_SIZE;

		if ((tlv_curr + option_len) > tlv_pastend) {
			if (PIM_DEBUG_PIM_HELLO)
				zlog_debug(
					"%s: long PIM hello TLV type=%d length=%d > left=%td from %pPAs on interface %s",
					__func__, option_type, option_len,
					tlv_pastend - tlv_curr, &src_addr,
					ifp->name);
			FREE_ADDR_LIST_THEN_RETURN(-2);
		}

		if (PIM_DEBUG_PIM_HELLO)
			zlog_debug(
				"%s: parse left_size=%d: PIM hello TLV type=%d length=%d from %pPAs on %s",
				__func__, remain, option_type, option_len,
				&src_addr, ifp->name);

		switch (option_type) {
		case PIM_MSG_OPTION_TYPE_HOLDTIME:
			if (pim_tlv_parse_holdtime(ifp->name, src_addr,
						   &hello_options,
						   &hello_option_holdtime,
						   option_len, tlv_curr)) {
				FREE_ADDR_LIST_THEN_RETURN(-3);
			}
			break;
		case PIM_MSG_OPTION_TYPE_LAN_PRUNE_DELAY:
			if (pim_tlv_parse_lan_prune_delay(
				    ifp->name, src_addr, &hello_options,
				    &hello_option_propagation_delay,
				    &hello_option_override_interval, option_len,
				    tlv_curr)) {
				FREE_ADDR_LIST_THEN_RETURN(-4);
			}
			break;
		case PIM_MSG_OPTION_TYPE_DR_PRIORITY:
			if (pim_tlv_parse_dr_priority(ifp->name, src_addr,
						      &hello_options,
						      &hello_option_dr_priority,
						      option_len, tlv_curr)) {
				FREE_ADDR_LIST_THEN_RETURN(-5);
			}
			break;
		case PIM_MSG_OPTION_TYPE_GENERATION_ID:
			if (pim_tlv_parse_generation_id(
				    ifp->name, src_addr, &hello_options,
				    &hello_option_generation_id, option_len,
				    tlv_curr)) {
				FREE_ADDR_LIST_THEN_RETURN(-6);
			}
			break;
		case PIM_MSG_OPTION_TYPE_ADDRESS_LIST:
			if (pim_tlv_parse_addr_list(ifp->name, src_addr,
						    &hello_options,
						    &hello_option_addr_list,
						    option_len, tlv_curr)) {
				return -7;
			}
			break;
		case PIM_MSG_OPTION_TYPE_DM_STATE_REFRESH:
			if (PIM_DEBUG_PIM_HELLO)
				zlog_debug(
					"%s: ignoring PIM hello dense-mode state refresh TLV option type=%d length=%d from %pPAs on interface %s",
					__func__, option_type, option_len,
					&src_addr, ifp->name);
			break;
		default:
			if (PIM_DEBUG_PIM_HELLO)
				zlog_debug(
					"%s: ignoring unknown PIM hello TLV type=%d length=%d from %pPAs on interface %s",
					__func__, option_type, option_len,
					&src_addr, ifp->name);
		}

		tlv_curr += option_len;
	}

	/*
	  Check received PIM hello options
	*/

	if (PIM_DEBUG_PIM_HELLO) {
		tlv_trace_uint16(__func__, "holdtime", ifp->name, src_addr,
				 PIM_OPTION_IS_SET(hello_options,
						   PIM_OPTION_MASK_HOLDTIME),
				 hello_option_holdtime);
		tlv_trace_uint16(
			__func__, "propagation_delay", ifp->name, src_addr,
			PIM_OPTION_IS_SET(hello_options,
					  PIM_OPTION_MASK_LAN_PRUNE_DELAY),
			hello_option_propagation_delay);
		tlv_trace_uint16(
			__func__, "override_interval", ifp->name, src_addr,
			PIM_OPTION_IS_SET(hello_options,
					  PIM_OPTION_MASK_LAN_PRUNE_DELAY),
			hello_option_override_interval);
		tlv_trace_bool(
			__func__, "can_disable_join_suppression", ifp->name,
			src_addr,
			PIM_OPTION_IS_SET(hello_options,
					  PIM_OPTION_MASK_LAN_PRUNE_DELAY),
			PIM_OPTION_IS_SET(
				hello_options,
				PIM_OPTION_MASK_CAN_DISABLE_JOIN_SUPPRESSION));
		tlv_trace_uint32(__func__, "dr_priority", ifp->name, src_addr,
				 PIM_OPTION_IS_SET(hello_options,
						   PIM_OPTION_MASK_DR_PRIORITY),
				 hello_option_dr_priority);
		tlv_trace_uint32_hex(
			__func__, "generation_id", ifp->name, src_addr,
			PIM_OPTION_IS_SET(hello_options,
					  PIM_OPTION_MASK_GENERATION_ID),
			hello_option_generation_id);
		tlv_trace_list(__func__, "address_list", ifp->name, src_addr,
			       PIM_OPTION_IS_SET(hello_options,
						 PIM_OPTION_MASK_ADDRESS_LIST),
			       hello_option_addr_list);
	}

	if (!PIM_OPTION_IS_SET(hello_options, PIM_OPTION_MASK_HOLDTIME)) {
		if (PIM_DEBUG_PIM_HELLO)
			zlog_debug(
				"%s: PIM hello missing holdtime from %pPAs on interface %s",
				__func__, &src_addr, ifp->name);
	}

	/*
	  New neighbor?
	*/

	neigh = pim_neighbor_find(ifp, src_addr, false);
	if (!neigh) {
		/* Add as new neighbor */

		neigh = pim_neighbor_add(
			ifp, src_addr, hello_options, hello_option_holdtime,
			hello_option_propagation_delay,
			hello_option_override_interval,
			hello_option_dr_priority, hello_option_generation_id,
			hello_option_addr_list, PIM_NEIGHBOR_SEND_DELAY);
		if (!neigh) {
			if (PIM_DEBUG_PIM_HELLO)
				zlog_warn(
					"%s: failure creating PIM neighbor %pPAs on interface %s",
					__func__, &src_addr, ifp->name);
			FREE_ADDR_LIST_THEN_RETURN(-8);
		}
		/* Forward BSM if required */
		if (!pim_bsm_new_nbr_fwd(neigh, ifp)) {
			if (PIM_DEBUG_PIM_HELLO)
				zlog_debug(
					"%s: forwarding bsm to new nbr failed",
					__func__);
		}

		/* actual addr list has been saved under neighbor */
		return 0;
	}

	/*
	  Received generation ID ?
	*/

	if (PIM_OPTION_IS_SET(hello_options, PIM_OPTION_MASK_GENERATION_ID)) {
		/* GenID mismatch ? */
		if (!PIM_OPTION_IS_SET(neigh->hello_options,
				       PIM_OPTION_MASK_GENERATION_ID)
		    || (hello_option_generation_id != neigh->generation_id)) {
			/* GenID mismatch, then replace neighbor */

			if (PIM_DEBUG_PIM_HELLO)
				zlog_debug(
					"%s: GenId mismatch new=%08x old=%08x: replacing neighbor %pPAs on %s",
					__func__, hello_option_generation_id,
					neigh->generation_id, &src_addr,
					ifp->name);

			pim_upstream_rpf_genid_changed(pim_ifp->pim,
						       neigh->source_addr);

			pim_neighbor_delete(ifp, neigh, "GenID mismatch");
			neigh = pim_neighbor_add(ifp, src_addr, hello_options,
						 hello_option_holdtime,
						 hello_option_propagation_delay,
						 hello_option_override_interval,
						 hello_option_dr_priority,
						 hello_option_generation_id,
						 hello_option_addr_list,
						 PIM_NEIGHBOR_SEND_NOW);
			if (!neigh) {
				if (PIM_DEBUG_PIM_HELLO)
					zlog_debug(
						"%s: failure re-creating PIM neighbor %pPAs on interface %s",
						__func__, &src_addr, ifp->name);
				FREE_ADDR_LIST_THEN_RETURN(-9);
			}
			/* Forward BSM if required */
			if (!pim_bsm_new_nbr_fwd(neigh, ifp)) {
				if (PIM_DEBUG_PIM_HELLO)
					zlog_debug(
						"%s: forwarding bsm to new nbr failed",
						__func__);
			}
			/* actual addr list is saved under neighbor */
			return 0;

		} /* GenId mismatch: replace neighbor */

	} /* GenId received */

	/*
	  Update existing neighbor
	*/

	pim_neighbor_update(neigh, hello_options, hello_option_holdtime,
			    hello_option_dr_priority, hello_option_addr_list);
	/* actual addr list is saved under neighbor */
	return 0;
}

int pim_hello_build_tlv(struct interface *ifp, uint8_t *tlv_buf,
			int tlv_buf_size, uint16_t holdtime,
			uint32_t dr_priority, uint32_t generation_id,
			uint16_t propagation_delay, uint16_t override_interval,
			int can_disable_join_suppression)
{
	uint8_t *curr = tlv_buf;
	uint8_t *pastend = tlv_buf + tlv_buf_size;
	uint8_t *tmp;
#if PIM_IPV == 4
	struct pim_interface *pim_ifp = ifp->info;
	struct pim_instance *pim = pim_ifp->pim;
#endif

	/*
	 * Append options
	 */

	/* Holdtime */
	curr = pim_tlv_append_uint16(curr, pastend,
				     PIM_MSG_OPTION_TYPE_HOLDTIME, holdtime);
	if (!curr) {
		if (PIM_DEBUG_PIM_HELLO) {
			zlog_debug(
				"%s: could not set PIM hello Holdtime option for interface %s",
				__func__, ifp->name);
		}
		return -1;
	}

	/* LAN Prune Delay */
	tmp = pim_tlv_append_2uint16(curr, pastend,
				     PIM_MSG_OPTION_TYPE_LAN_PRUNE_DELAY,
				     propagation_delay, override_interval);
	if (!tmp) {
		if (PIM_DEBUG_PIM_HELLO) {
			zlog_debug(
				"%s: could not set PIM LAN Prune Delay option for interface %s",
				__func__, ifp->name);
		}
		return -1;
	}
	if (can_disable_join_suppression) {
		*(curr + 4) |= 0x80; /* enable T bit */
	}
	curr = tmp;

	/* DR Priority */
	curr = pim_tlv_append_uint32(
		curr, pastend, PIM_MSG_OPTION_TYPE_DR_PRIORITY, dr_priority);
	if (!curr) {
		if (PIM_DEBUG_PIM_HELLO) {
			zlog_debug(
				"%s: could not set PIM hello DR Priority option for interface %s",
				__func__, ifp->name);
		}
		return -2;
	}

	/* Generation ID */
	curr = pim_tlv_append_uint32(curr, pastend,
				     PIM_MSG_OPTION_TYPE_GENERATION_ID,
				     generation_id);
	if (!curr) {
		if (PIM_DEBUG_PIM_HELLO) {
			zlog_debug(
				"%s: could not set PIM hello Generation ID option for interface %s",
				__func__, ifp->name);
		}
		return -3;
	}

	/* Secondary Address List */
	if (if_connected_count(ifp->connected)) {
		curr = pim_tlv_append_addrlist_ucast(curr, pastend, ifp,
						     PIM_AF);
		if (!curr) {
			if (PIM_DEBUG_PIM_HELLO) {
				zlog_debug(
					"%s: could not set PIM hello %s Secondary Address List option for interface %s",
					__func__, PIM_AF_NAME, ifp->name);
			}
			return -4;
		}
#if PIM_IPV == 4
		if (pim->send_v6_secondary) {
			curr = pim_tlv_append_addrlist_ucast(curr, pastend, ifp,
							     AF_INET6);
			if (!curr) {
				if (PIM_DEBUG_PIM_HELLO) {
					zlog_debug(
						"%s: could not sent PIM hello v6 secondary Address List option for interface %s",
						__func__, ifp->name);
				}
				return -4;
			}
		}
#endif
	}

	return curr - tlv_buf;
}

/*
  RFC 4601: 4.3.1.  Sending Hello Messages

  Thus, if a router needs to send a Join/Prune or Assert message on an
  interface on which it has not yet sent a Hello message with the
  currently configured IP address, then it MUST immediately send the
  relevant Hello message without waiting for the Hello Timer to
  expire, followed by the Join/Prune or Assert message.
*/
void pim_hello_require(struct interface *ifp)
{
	struct pim_interface *pim_ifp;

	assert(ifp);

	pim_ifp = ifp->info;

	assert(pim_ifp);

	if (PIM_IF_FLAG_TEST_HELLO_SENT(pim_ifp->flags))
		return;

	pim_hello_restart_now(ifp); /* Send hello and restart timer */
}
