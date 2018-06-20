/* BGP FlowSpec Utilities
 * Portions:
 *     Copyright (C) 2017 ChinaTelecom SDN Group
 *     Copyright (C) 2018 6WIND
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "zebra.h"

#include "prefix.h"

#include "bgp_table.h"
#include "bgp_flowspec_util.h"
#include "bgp_flowspec_private.h"
#include "bgp_pbr.h"

static void hex2bin(uint8_t *hex, int *bin)
{
	int remainder = *hex;
	int i = 0;

	while (remainder >= 1 && i < 8) {
		bin[7-i] = remainder % 2;
		remainder = remainder / 2;
		i++;
	}
	for (; i < 8; i++)
		bin[7-i] = 0;
}

static int hexstr2num(uint8_t *hexstr, int len)
{
	int i = 0;
	int num = 0;

	for (i = 0; i < len; i++)
		num = hexstr[i] + 16*16*num;
	return num;
}

/* call bgp_flowspec_op_decode
 * returns offset
 */
static int bgp_flowspec_call_non_opaque_decode(uint8_t *nlri_content, int len,
					       struct bgp_pbr_match_val *mval,
					       uint8_t *match_num, int *error)
{
	int ret;

	ret = bgp_flowspec_op_decode(
			     BGP_FLOWSPEC_CONVERT_TO_NON_OPAQUE,
			     nlri_content,
			     len,
			     mval, error);
	if (*error < 0)
		zlog_err("%s: flowspec_op_decode error %d",
			 __func__, *error);
	else
		*match_num = *error;
	return ret;
}

static bool bgp_flowspec_contains_prefix(struct prefix *pfs,
					 struct prefix *input,
					 int prefix_check)
{
	uint32_t offset = 0;
	int type;
	int ret = 0, error = 0;
	uint8_t *nlri_content = (uint8_t *)pfs->u.prefix_flowspec.ptr;
	size_t len = pfs->u.prefix_flowspec.prefixlen;
	struct prefix compare;

	error = 0;
	while (offset < len-1 && error >= 0) {
		type = nlri_content[offset];
		offset++;
		switch (type) {
		case FLOWSPEC_DEST_PREFIX:
		case FLOWSPEC_SRC_PREFIX:
			memset(&compare, 0, sizeof(struct prefix));
			ret = bgp_flowspec_ip_address(
					BGP_FLOWSPEC_CONVERT_TO_NON_OPAQUE,
					nlri_content+offset,
					len - offset,
					&compare, &error);
			if (ret <= 0)
				break;
			if (prefix_check &&
			    compare.prefixlen != input->prefixlen)
				break;
			if (compare.family != input->family)
				break;
			if ((input->family == AF_INET) &&
			    IPV4_ADDR_SAME(&input->u.prefix4,
					   &compare.u.prefix4))
				return true;
			if ((input->family == AF_INET6) &&
			    IPV6_ADDR_SAME(&input->u.prefix6.s6_addr,
					   &compare.u.prefix6.s6_addr))
				return true;
			break;
		case FLOWSPEC_IP_PROTOCOL:
		case FLOWSPEC_PORT:
		case FLOWSPEC_DEST_PORT:
		case FLOWSPEC_SRC_PORT:
		case FLOWSPEC_ICMP_TYPE:
		case FLOWSPEC_ICMP_CODE:
			ret = bgp_flowspec_op_decode(BGP_FLOWSPEC_VALIDATE_ONLY,
						     nlri_content+offset,
						     len - offset,
						     NULL, &error);
			break;
		case FLOWSPEC_FRAGMENT:
		case FLOWSPEC_TCP_FLAGS:
			ret = bgp_flowspec_bitmask_decode(
						BGP_FLOWSPEC_VALIDATE_ONLY,
						nlri_content+offset,
						len - offset,
						NULL, &error);
			break;
		case FLOWSPEC_PKT_LEN:
		case FLOWSPEC_DSCP:
			ret = bgp_flowspec_op_decode(
						BGP_FLOWSPEC_VALIDATE_ONLY,
						nlri_content + offset,
						len - offset, NULL,
						&error);
			break;
		default:
			error = -1;
			break;
		}
		offset += ret;
	}
	return false;
}

/*
 * handle the flowspec address src/dst or generic address NLRI
 * return number of bytes analysed ( >= 0).
 */
int bgp_flowspec_ip_address(enum bgp_flowspec_util_nlri_t type,
			    uint8_t *nlri_ptr,
			    uint32_t max_len,
			    void *result, int *error)
{
	char *display = (char *)result; /* for return_string */
	struct prefix *prefix = (struct prefix *)result;
	uint32_t offset = 0;
	struct prefix prefix_local;
	int psize;

	*error = 0;
	memset(&prefix_local, 0, sizeof(struct prefix));
	/* read the prefix length */
	prefix_local.prefixlen = nlri_ptr[offset];
	psize = PSIZE(prefix_local.prefixlen);
	offset++;
	/* TODO Flowspec IPv6 Support */
	prefix_local.family = AF_INET;
	/* Prefix length check. */
	if (prefix_local.prefixlen > prefix_blen(&prefix_local) * 8)
		*error = -1;
	/* When packet overflow occur return immediately. */
	if (psize + offset > max_len)
		*error = -1;
	/* Defensive coding, double-check
	 * the psize fits in a struct prefix
	 */
	if (psize > (ssize_t)sizeof(prefix_local.u))
		*error = -1;
	memcpy(&prefix_local.u.prefix, &nlri_ptr[offset], psize);
	offset += psize;
	switch (type) {
	case BGP_FLOWSPEC_RETURN_STRING:
		prefix2str(&prefix_local, display,
			   BGP_FLOWSPEC_STRING_DISPLAY_MAX);
		break;
	case BGP_FLOWSPEC_CONVERT_TO_NON_OPAQUE:
		PREFIX_COPY_IPV4(prefix, &prefix_local)
		break;
	case BGP_FLOWSPEC_VALIDATE_ONLY:
	default:
		break;
	}
	return offset;
}

/*
 * handle the flowspec operator NLRI
 * return number of bytes analysed
 * if there is an error, the passed error param is used to give error:
 * -1 if decoding error,
 * if result is a string, its assumed length
 *  is BGP_FLOWSPEC_STRING_DISPLAY_MAX
 */
int bgp_flowspec_op_decode(enum bgp_flowspec_util_nlri_t type,
			   uint8_t *nlri_ptr,
			   uint32_t max_len,
			   void *result, int *error)
{
	int op[8];
	int len, value, value_size;
	int loop = 0;
	char *ptr = (char *)result; /* for return_string */
	uint32_t offset = 0;
	int len_string = BGP_FLOWSPEC_STRING_DISPLAY_MAX;
	int len_written;
	struct bgp_pbr_match_val *mval = (struct bgp_pbr_match_val *)result;

	*error = 0;
	do {
		if (loop > BGP_PBR_MATCH_VAL_MAX)
			*error = -2;
		hex2bin(&nlri_ptr[offset], op);
		offset++;
		len = 2*op[2]+op[3];
		value_size = 1 << len;
		value = hexstr2num(&nlri_ptr[offset], value_size);
		/* can not be < and > at the same time */
		if (op[5] == 1 && op[6] == 1)
			*error = -1;
		/* if first element, AND bit can not be set */
		if (op[1] == 1 && loop == 0)
			*error = -1;
		switch (type) {
		case BGP_FLOWSPEC_RETURN_STRING:
			if (loop) {
				len_written = snprintf(ptr, len_string,
						      ", ");
				len_string -= len_written;
				ptr += len_written;
			}
			if (op[5] == 1) {
				len_written = snprintf(ptr, len_string,
						       "<");
				len_string -= len_written;
				ptr += len_written;
			}
			if (op[6] == 1) {
				len_written = snprintf(ptr, len_string,
						      ">");
				len_string -= len_written;
				ptr += len_written;
			}
			if (op[7] == 1) {
				len_written = snprintf(ptr, len_string,
						       "=");
				len_string -= len_written;
				ptr += len_written;
			}
			len_written = snprintf(ptr, len_string,
					       " %d ", value);
			len_string -= len_written;
			ptr += len_written;
			break;
		case BGP_FLOWSPEC_CONVERT_TO_NON_OPAQUE:
			/* limitation: stop converting */
			if (*error == -2)
				break;
			mval->value = value;
			if (op[5] == 1)
				mval->compare_operator |=
					OPERATOR_COMPARE_LESS_THAN;
			if (op[6] == 1)
				mval->compare_operator |=
					OPERATOR_COMPARE_GREATER_THAN;
			if (op[7] == 1)
				mval->compare_operator |=
					OPERATOR_COMPARE_EQUAL_TO;
			if (op[1] == 1)
				mval->unary_operator = OPERATOR_UNARY_AND;
			else
				mval->unary_operator = OPERATOR_UNARY_OR;
			mval++;
			break;
		case BGP_FLOWSPEC_VALIDATE_ONLY:
		default:
			/* no action */
			break;
		}
		offset += value_size;
		loop++;
	} while (op[0] == 0 && offset < max_len - 1);
	if (offset > max_len)
		*error = -1;
	/* use error parameter to count the number of entries */
	if (*error == 0)
		*error = loop;
	return offset;
}


/*
 * handle the flowspec tcpflags or fragment field
 * return number of bytes analysed
 * if there is an error, the passed error param is used to give error:
 * -1 if decoding error,
 * if result is a string, its assumed length
 *  is BGP_FLOWSPEC_STRING_DISPLAY_MAX
 */
int bgp_flowspec_bitmask_decode(enum bgp_flowspec_util_nlri_t type,
				 uint8_t *nlri_ptr,
				 uint32_t max_len,
				 void *result, int *error)
{
	int op[8];
	int len, value_size, loop = 0, value;
	char *ptr = (char *)result; /* for return_string */
	struct bgp_pbr_match_val *mval = (struct bgp_pbr_match_val *)result;
	uint32_t offset = 0;
	int len_string = BGP_FLOWSPEC_STRING_DISPLAY_MAX;
	int len_written;

	*error = 0;
	do {
		if (loop > BGP_PBR_MATCH_VAL_MAX)
			*error = -2;
		hex2bin(&nlri_ptr[offset], op);
		/* if first element, AND bit can not be set */
		if (op[1] == 1 && loop == 0)
			*error = -1;
		offset++;
		len = 2 * op[2] + op[3];
		value_size = 1 << len;
		value = hexstr2num(&nlri_ptr[offset], value_size);
		switch (type) {
		case BGP_FLOWSPEC_RETURN_STRING:
			if (op[1] == 1 && loop != 0) {
				len_written = snprintf(ptr, len_string,
						       ",&");
				len_string -= len_written;
				ptr += len_written;
			} else if (op[1] == 0 && loop != 0) {
				len_written = snprintf(ptr, len_string,
						      ",|");
				len_string -= len_written;
				ptr += len_written;
			}
			if (op[7] == 1) {
				len_written = snprintf(ptr, len_string,
					       "= ");
				len_string -= len_written;
				ptr += len_written;
			} else {
				len_written = snprintf(ptr, len_string,
						       "∋ ");
				len_string -= len_written;
				ptr += len_written;
			}
			if (op[6] == 1) {
				len_written = snprintf(ptr, len_string,
					       "! ");
				len_string -= len_written;
				ptr += len_written;
			}
			len_written = snprintf(ptr, len_string,
				       "%d", value);
			len_string -= len_written;
			ptr += len_written;
			break;
		case BGP_FLOWSPEC_CONVERT_TO_NON_OPAQUE:
			/* limitation: stop converting */
			if (*error == -2)
				break;
			mval->value = value;
			if (op[6] == 1) {
				/* different from */
				mval->compare_operator |=
					OPERATOR_COMPARE_LESS_THAN;
				mval->compare_operator |=
					OPERATOR_COMPARE_GREATER_THAN;
			} else
				mval->compare_operator |=
					OPERATOR_COMPARE_EQUAL_TO;
			if (op[7] == 1)
				mval->compare_operator |=
					OPERATOR_COMPARE_EXACT_MATCH;
			if (op[1] == 1)
				mval->unary_operator =
					OPERATOR_UNARY_AND;
			else
				mval->unary_operator =
					OPERATOR_UNARY_OR;
			mval++;
			break;
		case BGP_FLOWSPEC_VALIDATE_ONLY:
		default:
			/* no action */
			break;
		}
		offset += value_size;
		loop++;
	} while (op[0] == 0 && offset < max_len - 1);
	if (offset > max_len)
		*error = -1;
	/* use error parameter to count the number of entries */
	if (*error == 0)
		*error = loop;
	return offset;
}

int bgp_flowspec_match_rules_fill(uint8_t *nlri_content, int len,
				  struct bgp_pbr_entry_main *bpem)
{
	int offset = 0, error = 0;
	struct prefix *prefix;
	struct bgp_pbr_match_val *mval;
	uint8_t *match_num;
	uint8_t bitmask = 0;
	int ret = 0, type;

	while (offset < len - 1 && error >= 0) {
		type = nlri_content[offset];
		offset++;
		switch (type) {
		case FLOWSPEC_DEST_PREFIX:
		case FLOWSPEC_SRC_PREFIX:
			bitmask = 0;
			if (type == FLOWSPEC_DEST_PREFIX) {
				bitmask |= PREFIX_DST_PRESENT;
				prefix = &bpem->dst_prefix;
			} else {
				bitmask |= PREFIX_SRC_PRESENT;
				prefix = &bpem->src_prefix;
			}
			ret = bgp_flowspec_ip_address(
					BGP_FLOWSPEC_CONVERT_TO_NON_OPAQUE,
					nlri_content + offset,
					len - offset,
					prefix, &error);
			if (error < 0)
				zlog_err("%s: flowspec_ip_address error %d",
					 __func__, error);
			else
				bpem->match_bitmask |= bitmask;
			offset += ret;
			break;
		case FLOWSPEC_IP_PROTOCOL:
			match_num = &(bpem->match_protocol_num);
			mval = (struct bgp_pbr_match_val *)
				&(bpem->protocol);
			offset += bgp_flowspec_call_non_opaque_decode(
							nlri_content + offset,
							len - offset,
							mval, match_num,
							&error);
			break;
		case FLOWSPEC_PORT:
			match_num = &(bpem->match_port_num);
			mval = (struct bgp_pbr_match_val *)
				&(bpem->port);
			offset += bgp_flowspec_call_non_opaque_decode(
							nlri_content + offset,
							len - offset,
							mval, match_num,
							&error);
			break;
		case FLOWSPEC_DEST_PORT:
			match_num = &(bpem->match_dst_port_num);
			mval = (struct bgp_pbr_match_val *)
				&(bpem->dst_port);
			offset += bgp_flowspec_call_non_opaque_decode(
							nlri_content + offset,
							len - offset,
							mval, match_num,
							&error);
			break;
		case FLOWSPEC_SRC_PORT:
			match_num = &(bpem->match_src_port_num);
			mval = (struct bgp_pbr_match_val *)
				&(bpem->src_port);
			offset += bgp_flowspec_call_non_opaque_decode(
							nlri_content + offset,
							len - offset,
							mval, match_num,
							&error);
			break;
		case FLOWSPEC_ICMP_TYPE:
			match_num = &(bpem->match_icmp_type_num);
			mval = (struct bgp_pbr_match_val *)
				&(bpem->icmp_type);
			offset += bgp_flowspec_call_non_opaque_decode(
							nlri_content + offset,
							len - offset,
							mval, match_num,
							&error);
			break;
		case FLOWSPEC_ICMP_CODE:
			match_num = &(bpem->match_icmp_code_num);
			mval = (struct bgp_pbr_match_val *)
				&(bpem->icmp_code);
			offset += bgp_flowspec_call_non_opaque_decode(
							nlri_content + offset,
							len - offset,
							mval, match_num,
							&error);
			break;
		case FLOWSPEC_PKT_LEN:
			match_num =
				&(bpem->match_packet_length_num);
			mval = (struct bgp_pbr_match_val *)
				&(bpem->packet_length);
			offset += bgp_flowspec_call_non_opaque_decode(
							nlri_content + offset,
							len - offset,
							mval, match_num,
							&error);
			break;
		case FLOWSPEC_DSCP:
			match_num = &(bpem->match_dscp_num);
			mval = (struct bgp_pbr_match_val *)
				&(bpem->dscp);
			offset += bgp_flowspec_call_non_opaque_decode(
							nlri_content + offset,
							len - offset,
							mval, match_num,
							&error);
			break;
		case FLOWSPEC_TCP_FLAGS:
			ret = bgp_flowspec_bitmask_decode(
					BGP_FLOWSPEC_CONVERT_TO_NON_OPAQUE,
					nlri_content + offset,
					len - offset,
					&bpem->tcpflags, &error);
			if (error < 0)
				zlog_err("%s: flowspec_tcpflags_decode error %d",
					 __func__, error);
			else
				bpem->match_tcpflags_num = error;
			/* contains the number of slots used */
			offset += ret;
			break;
		case FLOWSPEC_FRAGMENT:
			ret = bgp_flowspec_bitmask_decode(
					BGP_FLOWSPEC_CONVERT_TO_NON_OPAQUE,
					nlri_content + offset,
					len - offset, &bpem->fragment,
					&error);
			if (error < 0)
				zlog_err("%s: flowspec_fragment_type_decode error %d",
					 __func__, error);
			else
				bpem->match_fragment_num = error;
			offset += ret;
			break;
		default:
			zlog_err("%s: unknown type %d\n", __func__, type);
		}
	}
	return error;
}


struct bgp_node *bgp_flowspec_get_match_per_ip(afi_t afi,
					       struct bgp_table *rib,
					       struct prefix *match,
					       int prefix_check)
{
	struct bgp_node *rn;
	struct prefix *prefix;

	for (rn = bgp_table_top(rib); rn; rn = bgp_route_next(rn)) {
		prefix = &rn->p;

		if (prefix->family != AF_FLOWSPEC)
			continue;

		if (bgp_flowspec_contains_prefix(prefix, match, prefix_check))
			return rn;
	}
	return NULL;
}
