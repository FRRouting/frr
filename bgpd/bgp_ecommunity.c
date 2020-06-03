/* BGP Extended Communities Attribute
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
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

#include "hash.h"
#include "memory.h"
#include "prefix.h"
#include "command.h"
#include "queue.h"
#include "filter.h"
#include "jhash.h"
#include "stream.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_flowspec_private.h"
#include "bgpd/bgp_pbr.h"

/* struct used to dump the rate contained in FS set traffic-rate EC */
union traffic_rate {
	float rate_float;
	uint8_t rate_byte[4];
};

/* Hash of community attribute. */
static struct hash *ecomhash;

/* Allocate a new ecommunities.  */
struct ecommunity *ecommunity_new(void)
{
	return XCALLOC(MTYPE_ECOMMUNITY, sizeof(struct ecommunity));
}

void ecommunity_strfree(char **s)
{
	XFREE(MTYPE_ECOMMUNITY_STR, *s);
}

/* Allocate ecommunities.  */
void ecommunity_free(struct ecommunity **ecom)
{
	if (!(*ecom))
		return;

	XFREE(MTYPE_ECOMMUNITY_VAL, (*ecom)->val);
	XFREE(MTYPE_ECOMMUNITY_STR, (*ecom)->str);
	XFREE(MTYPE_ECOMMUNITY, *ecom);
}

static void ecommunity_hash_free(struct ecommunity *ecom)
{
	ecommunity_free(&ecom);
}


/* Add a new Extended Communities value to Extended Communities
   Attribute structure.  When the value is already exists in the
   structure, we don't add the value.  Newly added value is sorted by
   numerical order.  When the value is added to the structure return 1
   else return 0.
   The additional parameters 'unique' and 'overwrite' ensure a particular
   extended community (based on type and sub-type) is present only
   once and whether the new value should replace what is existing or
   not.
*/
bool ecommunity_add_val(struct ecommunity *ecom, struct ecommunity_val *eval,
			bool unique, bool overwrite)
{
	int c, ins_idx;

	/* When this is fist value, just add it. */
	if (ecom->val == NULL) {
		ecom->size = 1;
		ecom->val = XCALLOC(MTYPE_ECOMMUNITY_VAL, ECOMMUNITY_SIZE);
		memcpy(ecom->val, eval->val, ECOMMUNITY_SIZE);
		return true;
	}

	/* If the value already exists in the structure return 0.  */
	/* check also if the extended community itself exists. */
	c = 0;
	ins_idx = -1;
	for (uint8_t *p = ecom->val; c < ecom->size;
	     p += ECOMMUNITY_SIZE, c++) {
		if (unique) {
			if (p[0] == eval->val[0] &&
			    p[1] == eval->val[1]) {
				if (overwrite) {
					memcpy(p, eval->val, ECOMMUNITY_SIZE);
					return 1;
				}
				return 0;
			}
		}
		int ret = memcmp(p, eval->val, ECOMMUNITY_SIZE);
		if (ret == 0)
			return 0;
		if (ret > 0) {
			if (!unique)
				break;
			if (ins_idx == -1)
				ins_idx = c;
		}
	}

	if (ins_idx == -1)
		ins_idx = c;

	/* Add the value to the structure with numerical sorting.  */
	ecom->size++;
	ecom->val = XREALLOC(MTYPE_ECOMMUNITY_VAL, ecom->val,
			     ecom->size * ECOMMUNITY_SIZE);

	memmove(ecom->val + ((ins_idx + 1) * ECOMMUNITY_SIZE),
		ecom->val + (ins_idx * ECOMMUNITY_SIZE),
		(ecom->size - 1 - ins_idx) * ECOMMUNITY_SIZE);
	memcpy(ecom->val + (ins_idx * ECOMMUNITY_SIZE),
	       eval->val, ECOMMUNITY_SIZE);

	return true;
}

/* This function takes pointer to Extended Communites strucutre then
   create a new Extended Communities structure by uniq and sort each
   Extended Communities value.  */
struct ecommunity *ecommunity_uniq_sort(struct ecommunity *ecom)
{
	int i;
	struct ecommunity *new;
	struct ecommunity_val *eval;

	if (!ecom)
		return NULL;

	new = ecommunity_new();

	for (i = 0; i < ecom->size; i++) {
		eval = (struct ecommunity_val *)(ecom->val
						 + (i * ECOMMUNITY_SIZE));
		ecommunity_add_val(new, eval, false, false);
	}
	return new;
}

/* Parse Extended Communites Attribute in BGP packet.  */
struct ecommunity *ecommunity_parse(uint8_t *pnt, unsigned short length)
{
	struct ecommunity tmp;
	struct ecommunity *new;

	/* Length check.  */
	if (length % ECOMMUNITY_SIZE)
		return NULL;

	/* Prepare tmporary structure for making a new Extended Communities
	   Attribute.  */
	tmp.size = length / ECOMMUNITY_SIZE;
	tmp.val = pnt;

	/* Create a new Extended Communities Attribute by uniq and sort each
	   Extended Communities value  */
	new = ecommunity_uniq_sort(&tmp);

	return ecommunity_intern(new);
}

/* Duplicate the Extended Communities Attribute structure.  */
struct ecommunity *ecommunity_dup(struct ecommunity *ecom)
{
	struct ecommunity *new;

	new = XCALLOC(MTYPE_ECOMMUNITY, sizeof(struct ecommunity));
	new->size = ecom->size;
	if (new->size) {
		new->val = XMALLOC(MTYPE_ECOMMUNITY_VAL,
				   ecom->size * ECOMMUNITY_SIZE);
		memcpy(new->val, ecom->val, ecom->size * ECOMMUNITY_SIZE);
	} else
		new->val = NULL;
	return new;
}

/* Retrun string representation of communities attribute. */
char *ecommunity_str(struct ecommunity *ecom)
{
	if (!ecom->str)
		ecom->str =
			ecommunity_ecom2str(ecom, ECOMMUNITY_FORMAT_DISPLAY, 0);
	return ecom->str;
}

/* Merge two Extended Communities Attribute structure.  */
struct ecommunity *ecommunity_merge(struct ecommunity *ecom1,
				    struct ecommunity *ecom2)
{
	if (ecom1->val)
		ecom1->val =
			XREALLOC(MTYPE_ECOMMUNITY_VAL, ecom1->val,
				 (ecom1->size + ecom2->size) * ECOMMUNITY_SIZE);
	else
		ecom1->val =
			XMALLOC(MTYPE_ECOMMUNITY_VAL,
				(ecom1->size + ecom2->size) * ECOMMUNITY_SIZE);

	memcpy(ecom1->val + (ecom1->size * ECOMMUNITY_SIZE), ecom2->val,
	       ecom2->size * ECOMMUNITY_SIZE);
	ecom1->size += ecom2->size;

	return ecom1;
}

/* Intern Extended Communities Attribute.  */
struct ecommunity *ecommunity_intern(struct ecommunity *ecom)
{
	struct ecommunity *find;

	assert(ecom->refcnt == 0);

	find = (struct ecommunity *)hash_get(ecomhash, ecom, hash_alloc_intern);

	if (find != ecom)
		ecommunity_free(&ecom);

	find->refcnt++;

	if (!find->str)
		find->str =
			ecommunity_ecom2str(find, ECOMMUNITY_FORMAT_DISPLAY, 0);

	return find;
}

/* Unintern Extended Communities Attribute.  */
void ecommunity_unintern(struct ecommunity **ecom)
{
	struct ecommunity *ret;

	if ((*ecom)->refcnt)
		(*ecom)->refcnt--;

	/* Pull off from hash.  */
	if ((*ecom)->refcnt == 0) {
		/* Extended community must be in the hash.  */
		ret = (struct ecommunity *)hash_release(ecomhash, *ecom);
		assert(ret != NULL);

		ecommunity_free(ecom);
	}
}

/* Utinity function to make hash key.  */
unsigned int ecommunity_hash_make(const void *arg)
{
	const struct ecommunity *ecom = arg;
	int size = ecom->size * ECOMMUNITY_SIZE;

	return jhash(ecom->val, size, 0x564321ab);
}

/* Compare two Extended Communities Attribute structure.  */
bool ecommunity_cmp(const void *arg1, const void *arg2)
{
	const struct ecommunity *ecom1 = arg1;
	const struct ecommunity *ecom2 = arg2;

	if (ecom1 == NULL && ecom2 == NULL)
		return true;

	if (ecom1 == NULL || ecom2 == NULL)
		return false;

	return (ecom1->size == ecom2->size
		&& memcmp(ecom1->val, ecom2->val, ecom1->size * ECOMMUNITY_SIZE)
			   == 0);
}

/* Initialize Extended Comminities related hash. */
void ecommunity_init(void)
{
	ecomhash = hash_create(ecommunity_hash_make, ecommunity_cmp,
			       "BGP ecommunity hash");
}

void ecommunity_finish(void)
{
	hash_clean(ecomhash, (void (*)(void *))ecommunity_hash_free);
	hash_free(ecomhash);
	ecomhash = NULL;
}

/* Extended Communities token enum. */
enum ecommunity_token {
	ecommunity_token_unknown = 0,
	ecommunity_token_rt,
	ecommunity_token_soo,
	ecommunity_token_val,
};

/*
 * Encode BGP extended community from passed values. Supports types
 * defined in RFC 4360 and well-known sub-types.
 */
static int ecommunity_encode(uint8_t type, uint8_t sub_type, int trans, as_t as,
			     struct in_addr ip, uint32_t val,
			     struct ecommunity_val *eval)
{
	assert(eval);
	if (type == ECOMMUNITY_ENCODE_AS) {
		if (as > BGP_AS_MAX)
			return -1;
	} else if (type == ECOMMUNITY_ENCODE_IP
		   || type == ECOMMUNITY_ENCODE_AS4) {
		if (val > UINT16_MAX)
			return -1;
	}

	/* Fill in the values. */
	eval->val[0] = type;
	if (!trans)
		eval->val[0] |= ECOMMUNITY_FLAG_NON_TRANSITIVE;
	eval->val[1] = sub_type;
	if (type == ECOMMUNITY_ENCODE_AS) {
		eval->val[2] = (as >> 8) & 0xff;
		eval->val[3] = as & 0xff;
		eval->val[4] = (val >> 24) & 0xff;
		eval->val[5] = (val >> 16) & 0xff;
		eval->val[6] = (val >> 8) & 0xff;
		eval->val[7] = val & 0xff;
	} else if (type == ECOMMUNITY_ENCODE_IP) {
		memcpy(&eval->val[2], &ip, sizeof(struct in_addr));
		eval->val[6] = (val >> 8) & 0xff;
		eval->val[7] = val & 0xff;
	} else {
		eval->val[2] = (as >> 24) & 0xff;
		eval->val[3] = (as >> 16) & 0xff;
		eval->val[4] = (as >> 8) & 0xff;
		eval->val[5] = as & 0xff;
		eval->val[6] = (val >> 8) & 0xff;
		eval->val[7] = val & 0xff;
	}

	return 0;
}

/* Get next Extended Communities token from the string. */
static const char *ecommunity_gettoken(const char *str,
				       struct ecommunity_val *eval,
				       enum ecommunity_token *token)
{
	int ret;
	int dot = 0;
	int digit = 0;
	int separator = 0;
	const char *p = str;
	char *endptr;
	struct in_addr ip;
	as_t as = 0;
	uint32_t val = 0;
	uint8_t ecomm_type;
	char buf[INET_ADDRSTRLEN + 1];

	/* Skip white space. */
	while (isspace((unsigned char)*p)) {
		p++;
		str++;
	}

	/* Check the end of the line. */
	if (*p == '\0')
		return NULL;

	/* "rt" and "soo" keyword parse. */
	if (!isdigit((unsigned char)*p)) {
		/* "rt" match check.  */
		if (tolower((unsigned char)*p) == 'r') {
			p++;
			if (tolower((unsigned char)*p) == 't') {
				p++;
				*token = ecommunity_token_rt;
				return p;
			}
			if (isspace((unsigned char)*p) || *p == '\0') {
				*token = ecommunity_token_rt;
				return p;
			}
			goto error;
		}
		/* "soo" match check.  */
		else if (tolower((unsigned char)*p) == 's') {
			p++;
			if (tolower((unsigned char)*p) == 'o') {
				p++;
				if (tolower((unsigned char)*p) == 'o') {
					p++;
					*token = ecommunity_token_soo;
					return p;
				}
				if (isspace((unsigned char)*p) || *p == '\0') {
					*token = ecommunity_token_soo;
					return p;
				}
				goto error;
			}
			if (isspace((unsigned char)*p) || *p == '\0') {
				*token = ecommunity_token_soo;
				return p;
			}
			goto error;
		}
		goto error;
	}

	/* What a mess, there are several possibilities:
	 *
	 * a) A.B.C.D:MN
	 * b) EF:OPQR
	 * c) GHJK:MN
	 *
	 * A.B.C.D: Four Byte IP
	 * EF:      Two byte ASN
	 * GHJK:    Four-byte ASN
	 * MN:      Two byte value
	 * OPQR:    Four byte value
	 *
	 */
	while (isdigit((unsigned char)*p) || *p == ':' || *p == '.') {
		if (*p == ':') {
			if (separator)
				goto error;

			separator = 1;
			digit = 0;

			if ((p - str) > INET_ADDRSTRLEN)
				goto error;
			memset(buf, 0, INET_ADDRSTRLEN + 1);
			memcpy(buf, str, p - str);

			if (dot) {
				/* Parsing A.B.C.D in:
				 * A.B.C.D:MN
				 */
				ret = inet_aton(buf, &ip);
				if (ret == 0)
					goto error;
			} else {
				/* ASN */
				as = strtoul(buf, &endptr, 10);
				if (*endptr != '\0' || as == BGP_AS4_MAX)
					goto error;
			}
		} else if (*p == '.') {
			if (separator)
				goto error;
			dot++;
			if (dot > 4)
				goto error;
		} else {
			digit = 1;

			/* We're past the IP/ASN part */
			if (separator) {
				val *= 10;
				val += (*p - '0');
			}
		}
		p++;
	}

	/* Low digit part must be there. */
	if (!digit || !separator)
		goto error;

	/* Encode result into extended community.  */
	if (dot)
		ecomm_type = ECOMMUNITY_ENCODE_IP;
	else if (as > BGP_AS_MAX)
		ecomm_type = ECOMMUNITY_ENCODE_AS4;
	else
		ecomm_type = ECOMMUNITY_ENCODE_AS;
	if (ecommunity_encode(ecomm_type, 0, 1, as, ip, val, eval))
		goto error;
	*token = ecommunity_token_val;
	return p;

error:
	*token = ecommunity_token_unknown;
	return p;
}

/* Convert string to extended community attribute.

   When type is already known, please specify both str and type.  str
   should not include keyword such as "rt" and "soo".  Type is
   ECOMMUNITY_ROUTE_TARGET or ECOMMUNITY_SITE_ORIGIN.
   keyword_included should be zero.

   For example route-map's "set extcommunity" command case:

   "rt 100:1 100:2 100:3"        -> str = "100:1 100:2 100:3"
				    type = ECOMMUNITY_ROUTE_TARGET
				    keyword_included = 0

   "soo 100:1"                   -> str = "100:1"
				    type = ECOMMUNITY_SITE_ORIGIN
				    keyword_included = 0

   When string includes keyword for each extended community value.
   Please specify keyword_included as non-zero value.

   For example standard extcommunity-list case:

   "rt 100:1 rt 100:2 soo 100:1" -> str = "rt 100:1 rt 100:2 soo 100:1"
				    type = 0
				    keyword_include = 1
*/
struct ecommunity *ecommunity_str2com(const char *str, int type,
				      int keyword_included)
{
	struct ecommunity *ecom = NULL;
	enum ecommunity_token token = ecommunity_token_unknown;
	struct ecommunity_val eval;
	int keyword = 0;

	while ((str = ecommunity_gettoken(str, &eval, &token))) {
		switch (token) {
		case ecommunity_token_rt:
		case ecommunity_token_soo:
			if (!keyword_included || keyword) {
				if (ecom)
					ecommunity_free(&ecom);
				return NULL;
			}
			keyword = 1;

			if (token == ecommunity_token_rt) {
				type = ECOMMUNITY_ROUTE_TARGET;
			}
			if (token == ecommunity_token_soo) {
				type = ECOMMUNITY_SITE_ORIGIN;
			}
			break;
		case ecommunity_token_val:
			if (keyword_included) {
				if (!keyword) {
					if (ecom)
						ecommunity_free(&ecom);
					return NULL;
				}
				keyword = 0;
			}
			if (ecom == NULL)
				ecom = ecommunity_new();
			eval.val[1] = type;
			ecommunity_add_val(ecom, &eval, false, false);
			break;
		case ecommunity_token_unknown:
		default:
			if (ecom)
				ecommunity_free(&ecom);
			return NULL;
		}
	}
	return ecom;
}

static int ecommunity_rt_soo_str(char *buf, size_t bufsz, const uint8_t *pnt,
				 int type, int sub_type, int format)
{
	int len = 0;
	const char *prefix;

	/* For parse Extended Community attribute tupple. */
	struct ecommunity_as eas;
	struct ecommunity_ip eip;


	/* Determine prefix for string, if any. */
	switch (format) {
	case ECOMMUNITY_FORMAT_COMMUNITY_LIST:
		prefix = (sub_type == ECOMMUNITY_ROUTE_TARGET ? "rt " : "soo ");
		break;
	case ECOMMUNITY_FORMAT_DISPLAY:
		prefix = (sub_type == ECOMMUNITY_ROUTE_TARGET ? "RT:" : "SoO:");
		break;
	case ECOMMUNITY_FORMAT_ROUTE_MAP:
		prefix = "";
		break;
	default:
		prefix = "";
		break;
	}

	/* Put string into buffer.  */
	if (type == ECOMMUNITY_ENCODE_AS4) {
		pnt = ptr_get_be32(pnt, &eas.as);
		eas.val = (*pnt++ << 8);
		eas.val |= (*pnt++);

		len = snprintf(buf, bufsz, "%s%u:%u", prefix, eas.as, eas.val);
	} else if (type == ECOMMUNITY_ENCODE_AS) {
		eas.as = (*pnt++ << 8);
		eas.as |= (*pnt++);
		pnt = ptr_get_be32(pnt, &eas.val);

		len = snprintf(buf, bufsz, "%s%u:%u", prefix, eas.as, eas.val);
	} else if (type == ECOMMUNITY_ENCODE_IP) {
		memcpy(&eip.ip, pnt, 4);
		pnt += 4;
		eip.val = (*pnt++ << 8);
		eip.val |= (*pnt++);

		len = snprintf(buf, bufsz, "%s%s:%u", prefix, inet_ntoa(eip.ip),
			       eip.val);
	}

	/* consume value */
	(void)pnt;

	return len;
}

static int ecommunity_lb_str(char *buf, size_t bufsz, const uint8_t *pnt)
{
	int len = 0;
	as_t as;
	uint32_t bw;
	char bps_buf[20] = {0};

#define ONE_GBPS_BYTES (1000 * 1000 * 1000 / 8)
#define ONE_MBPS_BYTES (1000 * 1000 / 8)
#define ONE_KBPS_BYTES (1000 / 8)

	as = (*pnt++ << 8);
	as |= (*pnt++);
	(void)ptr_get_be32(pnt, &bw);
	if (bw >= ONE_GBPS_BYTES)
		snprintf(bps_buf, sizeof(bps_buf), "%.3f Gbps",
			 (float)(bw / ONE_GBPS_BYTES));
	else if (bw >= ONE_MBPS_BYTES)
		snprintf(bps_buf, sizeof(bps_buf), "%.3f Mbps",
			 (float)(bw / ONE_MBPS_BYTES));
	else if (bw >= ONE_KBPS_BYTES)
		snprintf(bps_buf, sizeof(bps_buf), "%.3f Kbps",
			 (float)(bw / ONE_KBPS_BYTES));
	else
		snprintf(bps_buf, sizeof(bps_buf), "%u bps", bw * 8);

	len = snprintf(buf, bufsz, "LB:%u:%u (%s)", as, bw, bps_buf);
	return len;
}

/* Convert extended community attribute to string.

   Due to historical reason of industry standard implementation, there
   are three types of format.

   route-map set extcommunity format
	"rt 100:1 100:2"
	"soo 100:3"

   extcommunity-list
	"rt 100:1 rt 100:2 soo 100:3"

   "show [ip] bgp" and extcommunity-list regular expression matching
	"RT:100:1 RT:100:2 SoO:100:3"

   For each formath please use below definition for format:

   ECOMMUNITY_FORMAT_ROUTE_MAP
   ECOMMUNITY_FORMAT_COMMUNITY_LIST
   ECOMMUNITY_FORMAT_DISPLAY

   Filter is added to display only ECOMMUNITY_ROUTE_TARGET in some cases.
   0 value displays all
*/
char *ecommunity_ecom2str(struct ecommunity *ecom, int format, int filter)
{
	int i;
	uint8_t *pnt;
	uint8_t type = 0;
	uint8_t sub_type = 0;
#define ECOMMUNITY_STRLEN 64
	int str_size;
	char *str_buf;

	if (ecom->size == 0)
		return XCALLOC(MTYPE_ECOMMUNITY_STR, 1);

	/* ecom strlen + space + null term */
	str_size = (ecom->size * (ECOMMUNITY_STRLEN + 1)) + 1;
	str_buf = XCALLOC(MTYPE_ECOMMUNITY_STR, str_size);

	char encbuf[128];

	for (i = 0; i < ecom->size; i++) {
		int unk_ecom = 0;
		memset(encbuf, 0x00, sizeof(encbuf));

		/* Space between each value.  */
		if (i > 0)
			strlcat(str_buf, " ", str_size);

		/* Retrieve value field */
		pnt = ecom->val + (i * 8);

		/* High-order octet is the type */
		type = *pnt++;

		if (type == ECOMMUNITY_ENCODE_AS || type == ECOMMUNITY_ENCODE_IP
		    || type == ECOMMUNITY_ENCODE_AS4) {
			/* Low-order octet of type. */
			sub_type = *pnt++;
			if (sub_type != ECOMMUNITY_ROUTE_TARGET
			    && sub_type != ECOMMUNITY_SITE_ORIGIN) {
				if (sub_type ==
				    ECOMMUNITY_FLOWSPEC_REDIRECT_IPV4 &&
				    type == ECOMMUNITY_ENCODE_IP) {
					struct in_addr *ipv4 =
						(struct in_addr *)pnt;
					char ipv4str[INET_ADDRSTRLEN];

					inet_ntop(AF_INET, ipv4,
						  ipv4str,
						  INET_ADDRSTRLEN);
					snprintf(encbuf, sizeof(encbuf),
						 "NH:%s:%d", ipv4str, pnt[5]);
				} else if (sub_type ==
					   ECOMMUNITY_LINK_BANDWIDTH &&
					   type == ECOMMUNITY_ENCODE_AS) {
					ecommunity_lb_str(encbuf,
						sizeof(encbuf), pnt);
				} else
					unk_ecom = 1;
			} else {
				ecommunity_rt_soo_str(encbuf, sizeof(encbuf),
						      pnt, type, sub_type,
						      format);
			}
		} else if (type == ECOMMUNITY_ENCODE_OPAQUE) {
			if (filter == ECOMMUNITY_ROUTE_TARGET)
				continue;
			if (*pnt == ECOMMUNITY_OPAQUE_SUBTYPE_ENCAP) {
				uint16_t tunneltype;
				memcpy(&tunneltype, pnt + 5, 2);
				tunneltype = ntohs(tunneltype);

				snprintf(encbuf, sizeof(encbuf), "ET:%d",
					 tunneltype);
			} else if (*pnt == ECOMMUNITY_EVPN_SUBTYPE_DEF_GW) {
				strlcpy(encbuf, "Default Gateway",
					sizeof(encbuf));
			} else {
				unk_ecom = 1;
			}
		} else if (type == ECOMMUNITY_ENCODE_EVPN) {
			if (filter == ECOMMUNITY_ROUTE_TARGET)
				continue;
			if (*pnt == ECOMMUNITY_EVPN_SUBTYPE_ROUTERMAC) {
				struct ethaddr rmac;
				pnt++;
				memcpy(&rmac, pnt, ETH_ALEN);

				snprintf(encbuf, sizeof(encbuf),
					 "Rmac:%02x:%02x:%02x:%02x:%02x:%02x",
					 (uint8_t)rmac.octet[0],
					 (uint8_t)rmac.octet[1],
					 (uint8_t)rmac.octet[2],
					 (uint8_t)rmac.octet[3],
					 (uint8_t)rmac.octet[4],
					 (uint8_t)rmac.octet[5]);
			} else if (*pnt
				   == ECOMMUNITY_EVPN_SUBTYPE_MACMOBILITY) {
				uint32_t seqnum;
				uint8_t flags = *++pnt;

				memcpy(&seqnum, pnt + 2, 4);
				seqnum = ntohl(seqnum);

				snprintf(encbuf, sizeof(encbuf), "MM:%u",
					 seqnum);

				if (CHECK_FLAG(
					    flags,
					    ECOMMUNITY_EVPN_SUBTYPE_MACMOBILITY_FLAG_STICKY))
					strlcat(encbuf, ", sticky MAC",
						sizeof(encbuf));
			} else if (*pnt == ECOMMUNITY_EVPN_SUBTYPE_ND) {
				uint8_t flags = *++pnt;

				if (CHECK_FLAG(
					    flags,
					    ECOMMUNITY_EVPN_SUBTYPE_ND_ROUTER_FLAG))
					strlcpy(encbuf, "ND:Router Flag",
						sizeof(encbuf));
				if (CHECK_FLAG(
					    flags,
					    ECOMMUNITY_EVPN_SUBTYPE_PROXY_FLAG))
					strlcpy(encbuf, "ND:Proxy",
						sizeof(encbuf));
			} else if (*pnt
				   == ECOMMUNITY_EVPN_SUBTYPE_ES_IMPORT_RT) {
				struct ethaddr mac;

				pnt++;
				memcpy(&mac, pnt, ETH_ALEN);
				snprintf(encbuf,
					sizeof(encbuf),
					"ES-Import-Rt:%02x:%02x:%02x:%02x:%02x:%02x",
					(uint8_t)mac.octet[0],
					(uint8_t)mac.octet[1],
					(uint8_t)mac.octet[2],
					(uint8_t)mac.octet[3],
					(uint8_t)mac.octet[4],
					(uint8_t)mac.octet[5]);
			} else if (*pnt
				   == ECOMMUNITY_EVPN_SUBTYPE_ESI_LABEL) {
				uint8_t flags = *++pnt;

				snprintf(encbuf,
					sizeof(encbuf), "ESI-label-Rt:%s",
					(flags &
					 ECOMMUNITY_EVPN_SUBTYPE_ESI_SA_FLAG) ?
					"SA":"AA");
			} else if (*pnt
				   == ECOMMUNITY_EVPN_SUBTYPE_DF_ELECTION) {
				uint8_t alg;
				uint16_t pref;
				uint16_t bmap;

				alg = *(pnt + 1);
				memcpy(&bmap, pnt + 2, 2);
				bmap = ntohs(bmap);
				memcpy(&pref, pnt + 5, 2);
				pref = ntohs(pref);

				if (bmap)
					snprintf(encbuf, sizeof(encbuf),
						"DF: (alg: %u, bmap: 0x%x pref: %u)",
						alg, bmap, pref);
				else
					snprintf(encbuf, sizeof(encbuf),
						"DF: (alg: %u, pref: %u)",
						alg, pref);
			} else
				unk_ecom = 1;
		} else if (type == ECOMMUNITY_ENCODE_REDIRECT_IP_NH) {
			sub_type = *pnt++;
			if (sub_type == ECOMMUNITY_REDIRECT_IP_NH) {
				snprintf(encbuf, sizeof(encbuf),
					 "FS:redirect IP 0x%x", *(pnt + 5));
			} else
				unk_ecom = 1;
		} else if (type == ECOMMUNITY_ENCODE_TRANS_EXP ||
			   type == ECOMMUNITY_EXTENDED_COMMUNITY_PART_2 ||
			   type == ECOMMUNITY_EXTENDED_COMMUNITY_PART_3) {
			sub_type = *pnt++;
			if (sub_type == ECOMMUNITY_REDIRECT_VRF) {
				char buf[16] = {};
				ecommunity_rt_soo_str(
					buf, sizeof(buf), pnt,
					type & ~ECOMMUNITY_ENCODE_TRANS_EXP,
					ECOMMUNITY_ROUTE_TARGET,
					ECOMMUNITY_FORMAT_DISPLAY);
				snprintf(encbuf, sizeof(encbuf),
					 "FS:redirect VRF %s", buf);
			} else if (type != ECOMMUNITY_ENCODE_TRANS_EXP)
				unk_ecom = 1;
			else if (sub_type == ECOMMUNITY_TRAFFIC_ACTION) {
				char action[64];

				if (*(pnt+3) ==
				    1 << FLOWSPEC_TRAFFIC_ACTION_TERMINAL)
					strlcpy(action, "terminate (apply)",
						sizeof(action));
				else
					strlcpy(action, "eval stops",
						sizeof(action));

				if (*(pnt+3) ==
				    1 << FLOWSPEC_TRAFFIC_ACTION_SAMPLE)
					strlcat(action, ", sample",
						sizeof(action));


				snprintf(encbuf, sizeof(encbuf), "FS:action %s",
					 action);
			} else if (sub_type == ECOMMUNITY_TRAFFIC_RATE) {
				union traffic_rate data;

				data.rate_byte[3] = *(pnt+2);
				data.rate_byte[2] = *(pnt+3);
				data.rate_byte[1] = *(pnt+4);
				data.rate_byte[0] = *(pnt+5);
				snprintf(encbuf, sizeof(encbuf), "FS:rate %f",
					 data.rate_float);
			} else if (sub_type == ECOMMUNITY_TRAFFIC_MARKING) {
				snprintf(encbuf, sizeof(encbuf),
					 "FS:marking %u", *(pnt + 5));
			} else
				unk_ecom = 1;
		} else if (type == ECOMMUNITY_ENCODE_AS_NON_TRANS) {
			sub_type = *pnt++;
			if (sub_type == ECOMMUNITY_LINK_BANDWIDTH)
				ecommunity_lb_str(encbuf, sizeof(encbuf), pnt);
			else
				unk_ecom = 1;
		} else {
			sub_type = *pnt++;
			unk_ecom = 1;
		}

		if (unk_ecom)
			snprintf(encbuf, sizeof(encbuf), "UNK:%d, %d", type,
				 sub_type);

		int r = strlcat(str_buf, encbuf, str_size);
		assert(r < str_size);
	}

	return str_buf;
}

bool ecommunity_match(const struct ecommunity *ecom1,
		      const struct ecommunity *ecom2)
{
	int i = 0;
	int j = 0;

	if (ecom1 == NULL && ecom2 == NULL)
		return true;

	if (ecom1 == NULL || ecom2 == NULL)
		return false;

	if (ecom1->size < ecom2->size)
		return false;

	/* Every community on com2 needs to be on com1 for this to match */
	while (i < ecom1->size && j < ecom2->size) {
		if (memcmp(ecom1->val + i * ECOMMUNITY_SIZE,
			   ecom2->val + j * ECOMMUNITY_SIZE, ECOMMUNITY_SIZE)
		    == 0)
			j++;
		i++;
	}

	if (j == ecom2->size)
		return true;
	else
		return false;
}

/* return first occurence of type */
extern struct ecommunity_val *ecommunity_lookup(const struct ecommunity *ecom,
						uint8_t type, uint8_t subtype)
{
	uint8_t *p;
	int c;

	/* If the value already exists in the structure return 0.  */
	c = 0;
	for (p = ecom->val; c < ecom->size; p += ECOMMUNITY_SIZE, c++) {
		if (p == NULL) {
			continue;
		}
		if (p[0] == type && p[1] == subtype)
			return (struct ecommunity_val *)p;
	}
	return NULL;
}

/* remove ext. community matching type and subtype
 * return 1 on success ( removed ), 0 otherwise (not present)
 */
bool ecommunity_strip(struct ecommunity *ecom, uint8_t type,
		      uint8_t subtype)
{
	uint8_t *p, *q, *new;
	int c, found = 0;
	/* When this is fist value, just add it.  */
	if (ecom == NULL || ecom->val == NULL)
		return false;

	/* Check if any existing ext community matches. */
	/* Certain extended communities like the Route Target can be present
	 * multiple times, handle that.
	 */
	c = 0;
	for (p = ecom->val; c < ecom->size; p += ECOMMUNITY_SIZE, c++) {
		if (p[0] == type && p[1] == subtype)
			found++;
	}
	/* If no matching ext community exists, return. */
	if (found == 0)
		return false;

	/* Handle the case where everything needs to be stripped. */
	if (found == ecom->size) {
		XFREE(MTYPE_ECOMMUNITY_VAL, ecom->val);
		ecom->size = 0;
		return true;
	}

	/* Strip matching ext community(ies). */
	new = XMALLOC(MTYPE_ECOMMUNITY_VAL,
		      (ecom->size - found) * ECOMMUNITY_SIZE);
	q = new;
	for (c = 0, p = ecom->val; c < ecom->size; c++, p += ECOMMUNITY_SIZE) {
		if (!(p[0] == type && p[1] == subtype)) {
			memcpy(q, p, ECOMMUNITY_SIZE);
			q += ECOMMUNITY_SIZE;
		}
	}
	XFREE(MTYPE_ECOMMUNITY_VAL, ecom->val);
	ecom->val = new;
	ecom->size -= found;
	return true;
}

/*
 * Remove specified extended community value from extended community.
 * Returns 1 if value was present (and hence, removed), 0 otherwise.
 */
bool ecommunity_del_val(struct ecommunity *ecom, struct ecommunity_val *eval)
{
	uint8_t *p;
	int c, found = 0;

	/* Make sure specified value exists. */
	if (ecom == NULL || ecom->val == NULL)
		return false;
	c = 0;
	for (p = ecom->val; c < ecom->size; p += ECOMMUNITY_SIZE, c++) {
		if (!memcmp(p, eval->val, ECOMMUNITY_SIZE)) {
			found = 1;
			break;
		}
	}
	if (found == 0)
		return false;

	/* Delete the selected value */
	ecom->size--;
	p = XMALLOC(MTYPE_ECOMMUNITY_VAL, ecom->size * ECOMMUNITY_SIZE);
	if (c != 0)
		memcpy(p, ecom->val, c * ECOMMUNITY_SIZE);
	if ((ecom->size - c) != 0)
		memcpy(p + (c)*ECOMMUNITY_SIZE,
		       ecom->val + (c + 1) * ECOMMUNITY_SIZE,
		       (ecom->size - c) * ECOMMUNITY_SIZE);
	XFREE(MTYPE_ECOMMUNITY_VAL, ecom->val);
	ecom->val = p;
	return true;
}

int ecommunity_fill_pbr_action(struct ecommunity_val *ecom_eval,
			       struct bgp_pbr_entry_action *api)
{
	if (ecom_eval->val[1] == ECOMMUNITY_TRAFFIC_RATE) {
		api->action = ACTION_TRAFFICRATE;
		api->u.r.rate_info[3] = ecom_eval->val[4];
		api->u.r.rate_info[2] = ecom_eval->val[5];
		api->u.r.rate_info[1] = ecom_eval->val[6];
		api->u.r.rate_info[0] = ecom_eval->val[7];
	} else if (ecom_eval->val[1] == ECOMMUNITY_TRAFFIC_ACTION) {
		api->action = ACTION_TRAFFIC_ACTION;
		/* else distribute code is set by default */
		if (ecom_eval->val[5] & (1 << FLOWSPEC_TRAFFIC_ACTION_TERMINAL))
			api->u.za.filter |= TRAFFIC_ACTION_TERMINATE;
		else
			api->u.za.filter |= TRAFFIC_ACTION_DISTRIBUTE;
		if (ecom_eval->val[5] == 1 << FLOWSPEC_TRAFFIC_ACTION_SAMPLE)
			api->u.za.filter |= TRAFFIC_ACTION_SAMPLE;

	} else if (ecom_eval->val[1] == ECOMMUNITY_TRAFFIC_MARKING) {
		api->action = ACTION_MARKING;
		api->u.marking_dscp = ecom_eval->val[7];
	} else if (ecom_eval->val[1] == ECOMMUNITY_REDIRECT_VRF) {
		/* must use external function */
		return 0;
	} else if (ecom_eval->val[1] == ECOMMUNITY_REDIRECT_IP_NH) {
		/* see draft-ietf-idr-flowspec-redirect-ip-02
		 * Q1: how come a ext. community can host ipv6 address
		 * Q2 : from cisco documentation:
		 * Announces the reachability of one or more flowspec NLRI.
		 * When a BGP speaker receives an UPDATE message with the
		 * redirect-to-IP extended community, it is expected to
		 * create a traffic filtering rule for every flow-spec
		 * NLRI in the message that has this path as its best
		 * path. The filter entry matches the IP packets
		 * described in the NLRI field and redirects them or
		 * copies them towards the IPv4 or IPv6 address specified
		 * in the 'Network Address of Next- Hop'
		 * field of the associated MP_REACH_NLRI.
		 */
		struct ecommunity_ip *ip_ecom = (struct ecommunity_ip *)
			ecom_eval + 2;

		api->u.zr.redirect_ip_v4 = ip_ecom->ip;
	} else
		return -1;
	return 0;
}

static struct ecommunity *bgp_aggr_ecommunity_lookup(
						struct bgp_aggregate *aggregate,
						struct ecommunity *ecommunity)
{
	return hash_lookup(aggregate->ecommunity_hash, ecommunity);
}

static void *bgp_aggr_ecommunty_hash_alloc(void *p)
{
	struct ecommunity *ref = (struct ecommunity *)p;
	struct ecommunity *ecommunity = NULL;

	ecommunity = ecommunity_dup(ref);
	return ecommunity;
}

static void bgp_aggr_ecommunity_prepare(struct hash_bucket *hb, void *arg)
{
	struct ecommunity *hb_ecommunity = hb->data;
	struct ecommunity **aggr_ecommunity = arg;

	if (*aggr_ecommunity)
		*aggr_ecommunity = ecommunity_merge(*aggr_ecommunity,
						    hb_ecommunity);
	else
		*aggr_ecommunity = ecommunity_dup(hb_ecommunity);
}

void bgp_aggr_ecommunity_remove(void *arg)
{
	struct ecommunity *ecommunity = arg;

	ecommunity_free(&ecommunity);
}

void bgp_compute_aggregate_ecommunity(struct bgp_aggregate *aggregate,
				      struct ecommunity *ecommunity)
{
	bgp_compute_aggregate_ecommunity_hash(aggregate, ecommunity);
	bgp_compute_aggregate_ecommunity_val(aggregate);
}


void bgp_compute_aggregate_ecommunity_hash(struct bgp_aggregate *aggregate,
					   struct ecommunity *ecommunity)
{
	struct ecommunity *aggr_ecommunity = NULL;

	if ((aggregate == NULL) || (ecommunity == NULL))
		return;

	/* Create hash if not already created.
	 */
	if (aggregate->ecommunity_hash == NULL)
		aggregate->ecommunity_hash = hash_create(
					ecommunity_hash_make, ecommunity_cmp,
					"BGP Aggregator ecommunity hash");

	aggr_ecommunity = bgp_aggr_ecommunity_lookup(aggregate, ecommunity);
	if (aggr_ecommunity == NULL) {
		/* Insert ecommunity into hash.
		 */
		aggr_ecommunity = hash_get(aggregate->ecommunity_hash,
					   ecommunity,
					   bgp_aggr_ecommunty_hash_alloc);
	}

	/* Increment reference counter.
	 */
	aggr_ecommunity->refcnt++;
}

void bgp_compute_aggregate_ecommunity_val(struct bgp_aggregate *aggregate)
{
	struct ecommunity *ecommerge = NULL;

	if (aggregate == NULL)
		return;

	/* Re-compute aggregate's ecommunity.
	 */
	if (aggregate->ecommunity)
		ecommunity_free(&aggregate->ecommunity);
	if (aggregate->ecommunity_hash
	    && aggregate->ecommunity_hash->count) {
		hash_iterate(aggregate->ecommunity_hash,
			     bgp_aggr_ecommunity_prepare,
			     &aggregate->ecommunity);
		ecommerge = aggregate->ecommunity;
		aggregate->ecommunity = ecommunity_uniq_sort(ecommerge);
		if (ecommerge)
			ecommunity_free(&ecommerge);
	}
}

void bgp_remove_ecommunity_from_aggregate(struct bgp_aggregate *aggregate,
					  struct ecommunity *ecommunity)
{
	struct ecommunity *aggr_ecommunity = NULL;
	struct ecommunity *ret_ecomm = NULL;

	if ((!aggregate)
	    || (!aggregate->ecommunity_hash)
	    || (!ecommunity))
		return;

	/* Look-up the ecommunity in the hash.
	 */
	aggr_ecommunity = bgp_aggr_ecommunity_lookup(aggregate, ecommunity);
	if (aggr_ecommunity) {
		aggr_ecommunity->refcnt--;

		if (aggr_ecommunity->refcnt == 0) {
			ret_ecomm = hash_release(aggregate->ecommunity_hash,
						 aggr_ecommunity);
			ecommunity_free(&ret_ecomm);
			bgp_compute_aggregate_ecommunity_val(aggregate);
		}
	}
}

void bgp_remove_ecomm_from_aggregate_hash(struct bgp_aggregate *aggregate,
					  struct ecommunity *ecommunity)
{

	struct ecommunity *aggr_ecommunity = NULL;
	struct ecommunity *ret_ecomm = NULL;

	if ((!aggregate)
	    || (!aggregate->ecommunity_hash)
	    || (!ecommunity))
		return;

	/* Look-up the ecommunity in the hash.
	 */
	aggr_ecommunity = bgp_aggr_ecommunity_lookup(aggregate, ecommunity);
	if (aggr_ecommunity) {
		aggr_ecommunity->refcnt--;

		if (aggr_ecommunity->refcnt == 0) {
			ret_ecomm = hash_release(aggregate->ecommunity_hash,
						 aggr_ecommunity);
			ecommunity_free(&ret_ecomm);
		}
	}
}

/*
 * return the BGP link bandwidth extended community, if present;
 * the actual bandwidth is returned via param
 */
const uint8_t *ecommunity_linkbw_present(struct ecommunity *ecom, uint32_t *bw)
{
	const uint8_t *eval;
	int i;

	if (bw)
		*bw = 0;

	if (!ecom || !ecom->size)
		return NULL;

	for (i = 0; i < ecom->size; i++) {
		const uint8_t *pnt;
		uint8_t type, sub_type;
		uint32_t bwval;

		eval = pnt = (ecom->val + (i * ECOMMUNITY_SIZE));
		type = *pnt++;
		sub_type = *pnt++;

		if ((type == ECOMMUNITY_ENCODE_AS ||
		     type == ECOMMUNITY_ENCODE_AS_NON_TRANS) &&
		    sub_type == ECOMMUNITY_LINK_BANDWIDTH) {
			pnt += 2; /* bandwidth is encoded as AS:val */
			pnt = ptr_get_be32(pnt, &bwval);
			(void)pnt; /* consume value */
			if (bw)
				*bw = bwval;
			return eval;
		}
	}

	return NULL;
}


struct ecommunity *ecommunity_replace_linkbw(as_t as,
					     struct ecommunity *ecom,
					     uint64_t cum_bw)
{
	struct ecommunity *new;
	struct ecommunity_val lb_eval;
	const uint8_t *eval;
	uint8_t type;
	uint32_t cur_bw;

	/* Nothing to replace if link-bandwidth doesn't exist or
	 * is non-transitive - just return existing extcommunity.
	 */
	new = ecom;
	if (!ecom || !ecom->size)
		return new;

	eval = ecommunity_linkbw_present(ecom, &cur_bw);
	if (!eval)
		return new;

	type = *eval;
	if (type & ECOMMUNITY_FLAG_NON_TRANSITIVE)
		return new;

	/* Transitive link-bandwidth exists, replace with the passed
	 * (cumulative) bandwidth value. We need to create a new
	 * extcommunity for this - refer to AS-Path replace function
	 * for reference.
	 */
	if (cum_bw > 0xFFFFFFFF)
		cum_bw = 0xFFFFFFFF;
	encode_lb_extcomm(as > BGP_AS_MAX ? BGP_AS_TRANS : as, cum_bw,
			  false, &lb_eval);
	new = ecommunity_dup(ecom);
	ecommunity_add_val(new, &lb_eval, true, true);

	return new;
}
