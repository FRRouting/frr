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
#include "bgp_flowspec_util.h"

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

	*error = 0;
	do {
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
			if (loop)
				ptr += sprintf(ptr, ", ");
			if (op[5] == 1)
				ptr += sprintf(ptr, "<");
			if (op[6] == 1)
				ptr += sprintf(ptr, ">");
			if (op[7] == 1)
				ptr += sprintf(ptr, "=");
			ptr += sprintf(ptr, " %d ", value);
			break;
		case BGP_FLOWSPEC_CONVERT_TO_NON_OPAQUE:
			/* TODO : FS OPAQUE */
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
 * handle the flowspec tcpflags field
 * return number of bytes analysed
 * if there is an error, the passed error param is used to give error:
 * -1 if decoding error,
 */
int bgp_flowspec_tcpflags_decode(enum bgp_flowspec_util_nlri_t type,
				 uint8_t *nlri_ptr,
				 uint32_t max_len,
				 void *result, int *error)
{
	int op[8];
	int len, value_size, loop = 0, value;
	char *ptr = (char *)result; /* for return_string */
	uint32_t offset = 0;

	*error = 0;
	do {
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
			if (op[1] == 1 && loop != 0)
				ptr += sprintf(ptr, ", and ");
			else if (op[1] == 0 && loop != 0)
				ptr += sprintf(ptr, ", or ");
			ptr += sprintf(ptr, "tcp flags is ");
			if (op[6] == 1)
				ptr += sprintf(ptr, "not ");
			if (op[7] == 1)
				ptr += sprintf(ptr, "exactly match ");
			ptr += sprintf(ptr, "%d", value);
			break;
		case BGP_FLOWSPEC_CONVERT_TO_NON_OPAQUE:
			/* TODO : FS OPAQUE */
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
 * handle the flowspec fragment type field
 * return error (returned values are invalid) or number of bytes analysed
 * -1 if error in decoding
 * >= 0 : number of bytes analysed (ok).
 */
int bgp_flowspec_fragment_type_decode(enum bgp_flowspec_util_nlri_t type,
				      uint8_t *nlri_ptr,
				      uint32_t max_len,
				      void *result, int *error)
{
	int op[8];
	int len, value, value_size, loop = 0;
	char *ptr = (char *)result; /* for return_string */
	uint32_t offset = 0;

	*error = 0;
	do {
		hex2bin(&nlri_ptr[offset], op);
		offset++;
		len = 2 * op[2] + op[3];
		value_size = 1 << len;
		value = hexstr2num(&nlri_ptr[offset], value_size);
		if (value != 1 && value != 2 && value != 4 && value != 8)
			*error = -1;
		offset += value_size;
		/* TODO : as per RFC5574 : first Fragment bits are Reserved
		 * does that mean that it is not possible
		 * to handle multiple occurences ?
		 * as of today, we only grab the first TCP fragment
		 */
		if (loop) {
			*error = -2;
			loop++;
			continue;
		}
		switch (type) {
		case BGP_FLOWSPEC_RETURN_STRING:
			switch (value) {
			case 1:
				ptr += sprintf(ptr, "dont-fragment");
				break;
			case 2:
				ptr += sprintf(ptr, "is-fragment");
				break;
			case 4:
				ptr += sprintf(ptr, "first-fragment");
				break;
			case 8:
				ptr += sprintf(ptr, "last-fragment");
				break;
			default:
				{}
			}
			break;
		case BGP_FLOWSPEC_CONVERT_TO_NON_OPAQUE:
			/* TODO : FS OPAQUE */
			break;
		case BGP_FLOWSPEC_VALIDATE_ONLY:
		default:
			/* no action */
			break;
		}
		loop++;
	} while (op[0] == 0 && offset < max_len - 1);
	if (offset > max_len)
		*error = -1;
	return offset;
}
