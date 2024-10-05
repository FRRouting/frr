// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Extended Communities Attribute
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
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

#include "lib/printfrr.h"

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
	struct ecommunity *ecom;

	ecom = (struct ecommunity *)XCALLOC(MTYPE_ECOMMUNITY,
					    sizeof(struct ecommunity));
	ecom->unit_size = ECOMMUNITY_SIZE;
	return ecom;
}

void ecommunity_strfree(char **s)
{
	XFREE(MTYPE_ECOMMUNITY_STR, *s);
}

/* Free ecommunities.  */
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
static bool ecommunity_add_val_internal(struct ecommunity *ecom,
					const void *eval,
					bool unique, bool overwrite,
					uint8_t ecom_size)
{
	uint32_t c, ins_idx;
	const struct ecommunity_val *eval4 = (struct ecommunity_val *)eval;
	const struct ecommunity_val_ipv6 *eval6 =
		(struct ecommunity_val_ipv6 *)eval;

	/* When this is fist value, just add it. */
	if (ecom->val == NULL) {
		ecom->size = 1;
		ecom->val = XMALLOC(MTYPE_ECOMMUNITY_VAL,
				    ecom_length_size(ecom, ecom_size));
		memcpy(ecom->val, eval, ecom_size);
		return true;
	}

	/* If the value already exists in the structure return 0.  */
	/* check also if the extended community itself exists. */
	c = 0;

	ins_idx = UINT32_MAX;
	for (uint8_t *p = ecom->val; c < ecom->size;
	     p += ecom_size, c++) {
		if (unique) {
			if (ecom_size == ECOMMUNITY_SIZE) {
				if (p[0] == eval4->val[0] &&
				    p[1] == eval4->val[1]) {
					if (overwrite) {
						memcpy(p, eval4->val,
						       ecom_size);
						return true;
					}
					return false;
				}
			} else {
				if (p[0] == eval6->val[0] &&
				    p[1] == eval6->val[1]) {
					if (overwrite) {
						memcpy(p, eval6->val,
						       ecom_size);
						return true;
					}
					return false;
				}
			}
		}
		int ret = memcmp(p, eval, ecom_size);
		if (ret == 0)
			return false;
		if (ret > 0) {
			if (!unique)
				break;
			if (ins_idx == UINT32_MAX)
				ins_idx = c;
		}
	}

	if (ins_idx == UINT32_MAX)
		ins_idx = c;

	/* Add the value to the structure with numerical sorting.  */
	ecom->size++;
	ecom->val = XREALLOC(MTYPE_ECOMMUNITY_VAL, ecom->val,
			 ecom_length_size(ecom, ecom_size));

	memmove(ecom->val + ((ins_idx + 1) * ecom_size),
		ecom->val + (ins_idx * ecom_size),
		(ecom->size - 1 - ins_idx) * ecom_size);
	memcpy(ecom->val + (ins_idx * ecom_size),
	       eval, ecom_size);

	return true;
}

/* Add a new Extended Communities value to Extended Communities
 * Attribute structure.  When the value is already exists in the
 * structure, we don't add the value.  Newly added value is sorted by
 * numerical order.  When the value is added to the structure return 1
 * else return 0.
 */
bool ecommunity_add_val(struct ecommunity *ecom, struct ecommunity_val *eval,
		       bool unique, bool overwrite)
{
	return ecommunity_add_val_internal(ecom, (const void *)eval, unique,
					   overwrite, ECOMMUNITY_SIZE);
}

bool ecommunity_add_val_ipv6(struct ecommunity *ecom,
			     struct ecommunity_val_ipv6 *eval,
			     bool unique, bool overwrite)
{
	return ecommunity_add_val_internal(ecom, (const void *)eval, unique,
					   overwrite, IPV6_ECOMMUNITY_SIZE);
}

static struct ecommunity *
ecommunity_uniq_sort_internal(struct ecommunity *ecom,
			      unsigned short ecom_size)
{
	uint32_t i;
	struct ecommunity *new;
	const void *eval;

	if (!ecom)
		return NULL;

	new = ecommunity_new();
	new->unit_size = ecom_size;
	new->disable_ieee_floating = ecom->disable_ieee_floating;

	for (i = 0; i < ecom->size; i++) {
		eval = (void *)(ecom->val + (i * ecom_size));
		ecommunity_add_val_internal(new, eval, false, false, ecom_size);
	}
	return new;
}

/* This function takes pointer to Extended Communites structure then
 * create a new Extended Communities structure by uniq and sort each
 * Extended Communities value.
 */
struct ecommunity *ecommunity_uniq_sort(struct ecommunity *ecom)
{
	return ecommunity_uniq_sort_internal(ecom, ECOMMUNITY_SIZE);
}

/* Parse Extended Communites Attribute in BGP packet.  */
static struct ecommunity *ecommunity_parse_internal(uint8_t *pnt,
						    unsigned short length,
						    unsigned short size_ecom,
						    bool disable_ieee_floating)
{
	struct ecommunity tmp;
	struct ecommunity *new;

	/* Length check.  */
	if (length % size_ecom)
		return NULL;

	/* Prepare tmporary structure for making a new Extended Communities
	   Attribute.  */
	tmp.size = length / size_ecom;
	tmp.val = pnt;
	tmp.disable_ieee_floating = disable_ieee_floating;

	/* Create a new Extended Communities Attribute by uniq and sort each
	   Extended Communities value  */
	new = ecommunity_uniq_sort_internal(&tmp, size_ecom);

	return ecommunity_intern(new);
}

struct ecommunity *ecommunity_parse(uint8_t *pnt, unsigned short length,
				    bool disable_ieee_floating)
{
	return ecommunity_parse_internal(pnt, length, ECOMMUNITY_SIZE,
					 disable_ieee_floating);
}

struct ecommunity *ecommunity_parse_ipv6(uint8_t *pnt, unsigned short length)
{
	return ecommunity_parse_internal(pnt, length, IPV6_ECOMMUNITY_SIZE,
					 false);
}

/* Duplicate the Extended Communities Attribute structure.  */
struct ecommunity *ecommunity_dup(struct ecommunity *ecom)
{
	struct ecommunity *new;

	new = XCALLOC(MTYPE_ECOMMUNITY, sizeof(struct ecommunity));
	new->size = ecom->size;
	new->unit_size = ecom->unit_size;
	if (new->size) {
		new->val = XMALLOC(MTYPE_ECOMMUNITY_VAL,
				   ecom->size * ecom->unit_size);
		memcpy(new->val, ecom->val,
		       (size_t)ecom->size * (size_t)ecom->unit_size);
	} else
		new->val = NULL;
	return new;
}

/* Return string representation of ecommunities attribute. */
const char *ecommunity_str(struct ecommunity *ecom)
{
	if (!ecom)
		return "(null)";

	if (!ecom->str)
		ecom->str =
			ecommunity_ecom2str(ecom, ECOMMUNITY_FORMAT_DISPLAY, 0);
	return ecom->str;
}

/* Merge two Extended Communities Attribute structure.  */
struct ecommunity *ecommunity_merge(struct ecommunity *ecom1,
				    struct ecommunity *ecom2)
{
	ecom1->val = XREALLOC(MTYPE_ECOMMUNITY_VAL, ecom1->val,
			      (size_t)(ecom1->size + ecom2->size)
				      * (size_t)ecom1->unit_size);

	memcpy(ecom1->val + (ecom1->size * ecom1->unit_size), ecom2->val,
	       (size_t)ecom2->size * (size_t)ecom1->unit_size);
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

	if (!*ecom)
		return;

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
	int size = ecom->size * ecom->unit_size;

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

	if (ecom1->unit_size != ecom2->unit_size)
		return false;

	return (ecom1->size == ecom2->size
		&& memcmp(ecom1->val, ecom2->val, ecom1->size *
			  ecom1->unit_size) == 0);
}

static void ecommunity_color_str(char *buf, size_t bufsz, uint8_t *ptr)
{
	/*
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *  | 0x03         | Sub-Type(0x0b) |    Flags                      |
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *  |                          Color Value                          |
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	uint32_t colorid;

	memcpy(&colorid, ptr + 3, 4);
	colorid = ntohl(colorid);
	snprintf(buf, bufsz, "Color:%d", colorid);
}

/* Initialize Extended Comminities related hash. */
void ecommunity_init(void)
{
	ecomhash = hash_create(ecommunity_hash_make, ecommunity_cmp,
			       "BGP ecommunity hash");
}

void ecommunity_finish(void)
{
	hash_clean_and_free(&ecomhash, (void (*)(void *))ecommunity_hash_free);
}

/* Extended Communities token enum. */
enum ecommunity_token {
	ecommunity_token_unknown = 0,
	ecommunity_token_rt,
	ecommunity_token_nt,
	ecommunity_token_soo,
	ecommunity_token_color,
	ecommunity_token_val,
	ecommunity_token_rt6,
	ecommunity_token_val6,
};

static const char *ecommunity_origin_validation_state2str(
	enum ecommunity_origin_validation_states state)
{
	switch (state) {
	case ECOMMUNITY_ORIGIN_VALIDATION_STATE_VALID:
		return "valid";
	case ECOMMUNITY_ORIGIN_VALIDATION_STATE_NOTFOUND:
		return "not-found";
	case ECOMMUNITY_ORIGIN_VALIDATION_STATE_INVALID:
		return "invalid";
	case ECOMMUNITY_ORIGIN_VALIDATION_STATE_NOTUSED:
		return "not-used";
	}

	return "ERROR";
}

static void ecommunity_origin_validation_state_str(char *buf, size_t bufsz,
						   uint8_t *ptr)
{
	/* Origin Validation State is encoded in the last octet
	 *
	 * 0                   1                   2                   3
	 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |       0x43    |      0x00     |             Reserved          |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |                    Reserved                   |validationstate|
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	uint8_t state = *(ptr + ECOMMUNITY_SIZE - 3);

	snprintf(buf, bufsz, "OVS:%s",
		 ecommunity_origin_validation_state2str(state));

	(void)ptr; /* consume value */
}

bool ecommunity_node_target_match(struct ecommunity *ecom,
				  struct in_addr *local_id)
{
	uint32_t i;
	bool match = false;

	if (!ecom || !ecom->size)
		return NULL;

	for (i = 0; i < ecom->size; i++) {
		const uint8_t *pnt;
		uint8_t type, sub_type;

		pnt = (ecom->val + (i * ECOMMUNITY_SIZE));
		type = *pnt++;
		sub_type = *pnt++;

		if (type == ECOMMUNITY_ENCODE_IP &&
		    sub_type == ECOMMUNITY_NODE_TARGET) {
			/* Node Target ID is encoded as A.B.C.D:0 */
			if (IPV4_ADDR_SAME((struct in_addr *)pnt, local_id))
				match = true;
			(void)pnt;
		}
	}

	return match;
}

static void ecommunity_node_target_str(char *buf, size_t bufsz, uint8_t *ptr,
				       int format)
{
	/*
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *  | 0x01 or 0x41 | Sub-Type(0x09) |    Target BGP Identifier      |
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *  | Target BGP Identifier (cont.) |           Reserved            |
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	struct in_addr node_id = {};

	IPV4_ADDR_COPY(&node_id, (struct in_addr *)ptr);


	snprintfrr(buf, bufsz, "%s%pI4%s",
		   format == ECOMMUNITY_FORMAT_COMMUNITY_LIST ? "nt " : "NT:",
		   &node_id,
		   format == ECOMMUNITY_FORMAT_COMMUNITY_LIST ? ":0" : "");

	(void)ptr; /* consume value */
}

static int ecommunity_encode_internal(uint8_t type, uint8_t sub_type,
				      int trans, as_t as,
				      struct in_addr *ip,
				      struct in6_addr *ip6,
				      uint32_t val,
				      void *eval_ptr)
{
	struct ecommunity_val *eval = (struct ecommunity_val *)eval_ptr;
	struct ecommunity_val_ipv6 *eval6 =
		(struct ecommunity_val_ipv6 *)eval_ptr;

	assert(eval);
	if (type == ECOMMUNITY_ENCODE_AS) {
		if (as > BGP_AS_MAX)
			return -1;
	} else if (type == ECOMMUNITY_ENCODE_IP
		   || type == ECOMMUNITY_ENCODE_AS4) {
		if (val > UINT16_MAX)
			return -1;
	} else if (type == ECOMMUNITY_ENCODE_TRANS_EXP &&
		   sub_type == ECOMMUNITY_FLOWSPEC_REDIRECT_IPV6 &&
		   (!ip6 || val > UINT16_MAX)) {
		return -1;
	}

	/* Fill in the values. */
	eval->val[0] = type;
	if (!trans)
		SET_FLAG(eval->val[0], ECOMMUNITY_FLAG_NON_TRANSITIVE);
	eval->val[1] = sub_type;
	if (type == ECOMMUNITY_ENCODE_AS) {
		encode_route_target_as(as, val, eval, trans);
	} else if (type == ECOMMUNITY_ENCODE_IP) {
		if (sub_type == ECOMMUNITY_NODE_TARGET)
			encode_node_target(ip, eval, trans);
		else
			encode_route_target_ip(ip, val, eval, trans);
	} else if (type == ECOMMUNITY_ENCODE_TRANS_EXP &&
		   sub_type == ECOMMUNITY_FLOWSPEC_REDIRECT_IPV6) {
		memcpy(&eval6->val[2], ip6, sizeof(struct in6_addr));
		eval6->val[18] = (val >> 8) & 0xff;
		eval6->val[19] = val & 0xff;
	} else if (type == ECOMMUNITY_ENCODE_OPAQUE &&
		   sub_type == ECOMMUNITY_COLOR) {
		encode_color(val, eval);
	} else {
		encode_route_target_as4(as, val, eval, trans);
	}

	return 0;
}

/*
 * Encode BGP extended community from passed values. Supports types
 * defined in RFC 4360 and well-known sub-types.
 */
static int ecommunity_encode(uint8_t type, uint8_t sub_type, int trans, as_t as,
			     struct in_addr ip, uint32_t val,
			     struct ecommunity_val *eval)
{
	return ecommunity_encode_internal(type, sub_type, trans, as,
					  &ip, NULL, val, (void *)eval);
}

/* Get next Extended Communities token from the string. */
static const char *ecommunity_gettoken(const char *str, void *eval_ptr,
				       enum ecommunity_token *token, int type)
{
	int ret;
	int dot = 0;
	int digit = 0;
	int separator = 0;
	const char *p = str;
	char *endptr;
	struct in_addr ip;
	struct in6_addr ip6;
	as_t as = 0;
	uint32_t val = 0;
	uint32_t val_color = 0;
	uint8_t ecomm_type = 0;
	uint8_t sub_type = 0;
	char buf[INET_ADDRSTRLEN + 1];
	struct ecommunity_val *eval = (struct ecommunity_val *)eval_ptr;
	uint64_t tmp_as = 0;
	static const char str_color[5] = "color";
	const char *ptr_color;
	bool val_color_set = false;

	/* Skip white space. */
	while (isspace((unsigned char)*p)) {
		p++;
		str++;
	}

	/* Check the end of the line. */
	if (*p == '\0')
		return NULL;

	/* "rt", "nt", "soo", and "color" keyword parse. */
	/* "rt" */
	if (tolower((unsigned char)*p) == 'r') {
		p++;
		if (tolower((unsigned char)*p) == 't') {
			p++;
			if (*p != '\0' && tolower((int)*p) == '6')
				*token = ecommunity_token_rt6;
			else
				*token = ecommunity_token_rt;
			return p;
		}
		if (isspace((unsigned char)*p) || *p == '\0') {
			*token = ecommunity_token_rt;
			return p;
		}
		goto error;
	}

	/* "nt" */
	if (tolower((unsigned char)*p) == 'n') {
		p++;
		if (tolower((unsigned char)*p) == 't') {
			p++;
			*token = ecommunity_token_nt;
			return p;
		}
		if (isspace((unsigned char)*p) || *p == '\0') {
			*token = ecommunity_token_nt;
			return p;
		}
		goto error;
	}

	/* "soo" */
	if (tolower((unsigned char)*p) == 's') {
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

	/* "color" */
	if (tolower((unsigned char)*p) == 'c') {
		ptr_color = &str_color[0];
		for (unsigned int i = 0; i < 5; i++) {
			if (tolower((unsigned char)*p) != *ptr_color)
				break;

			p++;
			ptr_color++;
		}
		if (isspace((unsigned char)*p) || *p == '\0') {
			*token = ecommunity_token_color;
			return p;
		}
		goto error;
	}
	/* What a mess, there are several possibilities:
	 *
	 * a) A.B.C.D:MN
	 * b) EF:OPQR
	 * c) GHJK:MN
	 * d) <IPV6>:MN (only with rt6)
	 *
	 * A.B.C.D: Four Byte IP
	 * EF:      Two byte ASN
	 * GHJK:    Four-byte ASN
	 * MN:      Two byte value
	 * OPQR:    Four byte value
	 *
	 */
	/* IPv6 case : look for last ':' */
	if (*token == ecommunity_token_rt6 ||
	    *token == ecommunity_token_val6) {
		char *limit;

		limit = endptr = strrchr(p, ':');
		if (!endptr)
			goto error;

		endptr++;
		errno = 0;
		tmp_as = strtoul(endptr, &endptr, 10);
		/* 'unsigned long' is a uint64 on 64-bit
		 * systems, and uint32 on 32-bit systems. So for
		 * 64-bit we can just directly check the value
		 * against BGP_AS4_MAX/UINT32_MAX, and for
		 * 32-bit we can check for errno (set to ERANGE
		 * upon overflow).
		 */
		if (*endptr != '\0' || tmp_as == BGP_AS4_MAX || errno)
			goto error;
		as = (as_t)tmp_as;

		memcpy(buf, p, (limit - p));
		buf[limit - p] = '\0';
		ret = inet_pton(AF_INET6, buf, &ip6);
		if (ret == 0)
			goto error;

		ecomm_type = ECOMMUNITY_ENCODE_TRANS_EXP;
		if (ecommunity_encode_internal(ecomm_type,
					ECOMMUNITY_FLOWSPEC_REDIRECT_IPV6,
					1, 0, NULL, &ip6, as, eval_ptr))
			goto error;

		*token = ecommunity_token_val6;
		while (isdigit((int)*p) || *p == ':' || *p == '.') {
			p++;
		}
		return p;
	}
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

			if (dot == 3) {
				/* Parsing A.B.C.D in:
				 * A.B.C.D:MN
				 */
				ret = inet_aton(buf, &ip);
				if (ret == 0)
					goto error;
			} else if (dot == 1) {
				/* Parsing A.B AS number in:
				 * A.B:MN
				 */
				if (!asn_str2asn(buf, &as))
					goto error;
			} else {
				/* Parsing A AS number in A:MN */
				errno = 0;
				tmp_as = strtoul(buf, &endptr, 10);
				/* 'unsigned long' is a uint64 on 64-bit
				 * systems, and uint32 on 32-bit systems. So for
				 * 64-bit we can just directly check the value
				 * against BGP_AS4_MAX/UINT32_MAX, and for
				 * 32-bit we can check for errno (set to ERANGE
				 * upon overflow).
				 */
				if (*endptr != '\0' || tmp_as > BGP_AS4_MAX ||
				    errno)
					goto error;
				as = (as_t)tmp_as;
			}
		} else if (*p == '.') {
			if (separator)
				goto error;
			/* either IP or AS format */
			dot++;
			if (dot > 1)
				ecomm_type = ECOMMUNITY_ENCODE_IP;
			if (dot >= 4)
				goto error;
		} else {
			digit = 1;

			/* We're past the IP/ASN part,
			 * or we have a color
			 */
			if (separator) {
				val *= 10;
				val += (*p - '0');
				val_color_set = false;
			} else {
				val_color *= 10;
				val_color += (*p - '0');
				val_color_set = true;
			}
		}
		p++;
	}

	/* Low digit part must be there. */
	if (!digit && (!separator || !val_color_set))
		goto error;

	if (ecomm_type != ECOMMUNITY_ENCODE_IP) {
		/* Encode result into extended community for AS format or color.  */
		if (as > BGP_AS_MAX)
			ecomm_type = ECOMMUNITY_ENCODE_AS4;
		else if (as > 0)
			ecomm_type = ECOMMUNITY_ENCODE_AS;
		else if (val_color) {
			ecomm_type = ECOMMUNITY_ENCODE_OPAQUE;
			sub_type = ECOMMUNITY_COLOR;
			val = val_color;
		}
	}
	if (ecommunity_encode(ecomm_type, sub_type, 1, as, ip, val, eval))
		goto error;
	*token = ecommunity_token_val;
	return p;

error:
	*token = ecommunity_token_unknown;
	return p;
}

static struct ecommunity *ecommunity_str2com_internal(const char *str, int type,
						      int keyword_included,
						      bool is_ipv6_extcomm)
{
	struct ecommunity *ecom = NULL;
	enum ecommunity_token token = ecommunity_token_unknown;
	struct ecommunity_val_ipv6 eval;
	int keyword = 0;

	if (is_ipv6_extcomm)
		token = ecommunity_token_rt6;
	while ((str = ecommunity_gettoken(str, (void *)&eval, &token, type))) {
		switch (token) {
		case ecommunity_token_rt:
		case ecommunity_token_nt:
		case ecommunity_token_rt6:
		case ecommunity_token_soo:
		case ecommunity_token_color:
			if (!keyword_included || keyword) {
				if (ecom)
					ecommunity_free(&ecom);
				return NULL;
			}
			keyword = 1;

			if (token == ecommunity_token_rt ||
			    token == ecommunity_token_rt6)
				type = ECOMMUNITY_ROUTE_TARGET;
			if (token == ecommunity_token_soo)
				type = ECOMMUNITY_SITE_ORIGIN;
			if (token == ecommunity_token_nt)
				type = ECOMMUNITY_NODE_TARGET;
			if (token == ecommunity_token_color)
				type = ECOMMUNITY_COLOR;
			break;
		case ecommunity_token_val:
			if (keyword_included) {
				if (!keyword) {
					ecommunity_free(&ecom);
					return NULL;
				}
				keyword = 0;
			}
			if (ecom == NULL)
				ecom = ecommunity_new();
			eval.val[1] = type;
			ecommunity_add_val_internal(ecom, (void *)&eval,
						    false, false,
						    ecom->unit_size);
			break;
		case ecommunity_token_val6:
			if (keyword_included) {
				if (!keyword) {
					ecommunity_free(&ecom);
					return NULL;
				}
				keyword = 0;
			}
			if (ecom == NULL)
				ecom = ecommunity_new();
			ecom->unit_size = IPV6_ECOMMUNITY_SIZE;
			eval.val[1] = type;
			ecommunity_add_val_internal(ecom, (void *)&eval, false, false,
						    ecom->unit_size);
			break;
		case ecommunity_token_unknown:
			if (ecom)
				ecommunity_free(&ecom);
			return NULL;
		}
	}
	return ecom;
}

/* Convert string to extended community attribute.
 *
 * When type is already known, please specify both str and type.  str
 * should not include keyword such as "rt" and "soo".  Type is
 * ECOMMUNITY_ROUTE_TARGET or ECOMMUNITY_SITE_ORIGIN.
 * keyword_included should be zero.
 *
 * For example route-map's "set extcommunity" command case:
 *
 * "rt 100:1 100:2 100:3"        -> str = "100:1 100:2 100:3"
 *				    type = ECOMMUNITY_ROUTE_TARGET
 *				    keyword_included = 0
 *
 * "soo 100:1"                   -> str = "100:1"
 *				    type = ECOMMUNITY_SITE_ORIGIN
 *				    keyword_included = 0
 *
 * When string includes keyword for each extended community value.
 * Please specify keyword_included as non-zero value.
 *
 * For example standard extcommunity-list case:
 *
 * "rt 100:1 rt 100:2 soo 100:1" -> str = "rt 100:1 rt 100:2 soo 100:1"
 *				    type = 0
 *				    keyword_include = 1
 */
struct ecommunity *ecommunity_str2com(const char *str, int type,
				      int keyword_included)
{
	return ecommunity_str2com_internal(str, type,
					   keyword_included, false);
}

struct ecommunity *ecommunity_str2com_ipv6(const char *str, int type,
					   int keyword_included)
{
	return ecommunity_str2com_internal(str, type,
					   keyword_included, true);
}

static int ecommunity_rt_soo_str_internal(char *buf, size_t bufsz,
					  const uint8_t *pnt, int type,
					  int sub_type, int format,
					  unsigned short ecom_size)
{
	int len = 0;
	const char *prefix;
	char buf_local[INET6_ADDRSTRLEN];

	/* For parse Extended Community attribute tupple. */
	struct ecommunity_as eas;
	struct ecommunity_ip eip;
	struct ecommunity_ip6 eip6;

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
		if (ecom_size == ECOMMUNITY_SIZE) {
			eas.as = (*pnt++ << 8);
			eas.as |= (*pnt++);
			pnt = ptr_get_be32(pnt, &eas.val);

			len = snprintf(buf, bufsz, "%s%u:%u", prefix, eas.as,
				       eas.val);
		} else {
			/* this is an IPv6 ext community
			 * first 16 bytes stands for IPv6 addres
			 */
			memcpy(&eip6.ip, pnt, 16);
			pnt += 16;
			eip6.val = (*pnt++ << 8);
			eip6.val |= (*pnt++);

			inet_ntop(AF_INET6, &eip6.ip, buf_local,
				  sizeof(buf_local));
			len = snprintf(buf, bufsz, "%s%s:%u", prefix,
				       buf_local, eip6.val);
		}
	} else if (type == ECOMMUNITY_ENCODE_IP) {
		memcpy(&eip.ip, pnt, 4);
		pnt += 4;
		eip.val = (*pnt++ << 8);
		eip.val |= (*pnt++);

		len = snprintfrr(buf, bufsz, "%s%pI4:%u", prefix, &eip.ip,
				 eip.val);
	}

	/* consume value */
	(void)pnt;

	return len;
}

static int ecommunity_rt_soo_str(char *buf, size_t bufsz, const uint8_t *pnt,
				 int type, int sub_type, int format)
{
	return ecommunity_rt_soo_str_internal(buf, bufsz, pnt, type,
					      sub_type, format,
					      ECOMMUNITY_SIZE);
}

/* Helper function to convert IEEE-754 Floating Point to uint32 */
static uint32_t ieee_float_uint32_to_uint32(uint32_t u)
{
	union {
		float r;
		uint32_t d;
	} f = {.d = u};

	return (uint32_t)f.r;
}

static int ecommunity_lb_str(char *buf, size_t bufsz, const uint8_t *pnt,
			     bool disable_ieee_floating)
{
	int len = 0;
	as_t as;
	uint32_t bw_tmp, bw;
	char bps_buf[20] = {0};

	as = (*pnt++ << 8);
	as |= (*pnt++);
	(void)ptr_get_be32(pnt, &bw_tmp);

	bw = disable_ieee_floating ? bw_tmp
				   : ieee_float_uint32_to_uint32(bw_tmp);

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

static int ipv6_ecommunity_lb_str(char *buf, size_t bufsz, const uint8_t *pnt,
				  size_t length)
{
	int len = 0;
	as_t as = 0;
	uint64_t bw = 0;
	char bps_buf[20] = { 0 };

	if (length < IPV6_ECOMMUNITY_SIZE)
		goto done;

	pnt += 2; /* Reserved */
	pnt = ptr_get_be64(pnt, &bw);
	(void)ptr_get_be32(pnt, &as);

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
		snprintfrr(bps_buf, sizeof(bps_buf), "%" PRIu64 " bps", bw * 8);

done:
	len = snprintfrr(buf, bufsz, "LB:%u:%" PRIu64 " (%s)", as, bw, bps_buf);
	return len;
}

bool ecommunity_has_route_target(struct ecommunity *ecom)
{
	uint32_t i;
	uint8_t *pnt;
	uint8_t type = 0;
	uint8_t sub_type = 0;

	if (!ecom)
		return false;
	for (i = 0; i < ecom->size; i++) {
		/* Retrieve value field */
		pnt = ecom->val + (i * ecom->unit_size);

		/* High-order octet is the type */
		type = *pnt++;

		if (type == ECOMMUNITY_ENCODE_AS ||
		    type == ECOMMUNITY_ENCODE_IP ||
		    type == ECOMMUNITY_ENCODE_AS4) {
			/* Low-order octet of type. */
			sub_type = *pnt++;
			if (sub_type == ECOMMUNITY_ROUTE_TARGET)
				return true;
		}
	}
	return false;
}

/* Convert extended community attribute to string.
 * Due to historical reason of industry standard implementation, there
 * are three types of format:
 *
 * route-map set extcommunity format:
 *     "rt 100:1 100:2soo 100:3"
 *
 * extcommunity-list:
 *     "rt 100:1 rt 100:2 soo 100:3"
 *
 * show bgp:
 *     "RT:100:1 RT:100:2 SoO:100:3"
 *
 * For each format please use below definition for format:
 *     ECOMMUNITY_FORMAT_ROUTE_MAP
 *     ECOMMUNITY_FORMAT_COMMUNITY_LIST
 *     ECOMMUNITY_FORMAT_DISPLAY
 *
 * Filter is added to display only ECOMMUNITY_ROUTE_TARGET in some cases.
 * 0 value displays all.
 */
char *ecommunity_ecom2str(struct ecommunity *ecom, int format, int filter)
{
	uint32_t i;
	uint8_t *pnt;
	uint8_t type = 0;
	uint8_t sub_type = 0;
	int str_size;
	char *str_buf;

	if (!ecom || ecom->size == 0)
		return XCALLOC(MTYPE_ECOMMUNITY_STR, 1);

	/* ecom strlen + space + null term */
	str_size = (ecom->size * (ECOMMUNITY_STRLEN + 1)) + 1;
	str_buf = XCALLOC(MTYPE_ECOMMUNITY_STR, str_size);

	char encbuf[128];

	for (i = 0; i < ecom->size; i++) {
		bool unk_ecom = false;
		memset(encbuf, 0x00, sizeof(encbuf));

		/* Space between each value.  */
		if (i > 0)
			strlcat(str_buf, " ", str_size);

		/* Retrieve value field */
		pnt = ecom->val + (i * ecom->unit_size);

		uint8_t *data = pnt;
		uint8_t *end = data + ecom->unit_size;
		size_t len = end - data;

		/* Sanity check for extended communities lenght, to avoid
		 * overrun when dealing with bits, e.g. ptr_get_be64().
		 */
		if (len < ecom->unit_size) {
			unk_ecom = true;
			goto unknown;
		}

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
					snprintfrr(encbuf, sizeof(encbuf),
						   "NH:%pI4:%d", ipv4, pnt[5]);
				} else if (sub_type ==
					   ECOMMUNITY_LINK_BANDWIDTH &&
					   type == ECOMMUNITY_ENCODE_AS) {
					ecommunity_lb_str(
						encbuf, sizeof(encbuf), pnt,
						ecom->disable_ieee_floating);
				} else if (sub_type ==
						   ECOMMUNITY_EXTENDED_LINK_BANDWIDTH &&
					   type == ECOMMUNITY_ENCODE_AS4) {
					ipv6_ecommunity_lb_str(encbuf,
							       sizeof(encbuf),
							       pnt, len);
				} else if (sub_type == ECOMMUNITY_NODE_TARGET &&
					   type == ECOMMUNITY_ENCODE_IP) {
					ecommunity_node_target_str(
						encbuf, sizeof(encbuf), pnt,
						format);
				} else
					unk_ecom = true;
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
			} else if (*pnt == ECOMMUNITY_COLOR) {
				ecommunity_color_str(encbuf, sizeof(encbuf),
						     pnt);
			} else {
				unk_ecom = true;
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

				snprintf(encbuf, sizeof(encbuf),
					 "ESI-label-Rt:%s",
					 CHECK_FLAG(flags,
						    ECOMMUNITY_EVPN_SUBTYPE_ESI_SA_FLAG)
						 ? "SA"
						 : "AA");
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
					snprintf(
						encbuf, sizeof(encbuf),
						"DF: (alg: %u, bmap: 0x%x pref: %u)",
						alg, bmap, pref);
				else
					snprintf(encbuf, sizeof(encbuf),
						 "DF: (alg: %u, pref: %u)", alg,
						 pref);
			} else
				unk_ecom = true;
		} else if (type == ECOMMUNITY_ENCODE_REDIRECT_IP_NH) {
			sub_type = *pnt++;
			if (sub_type == ECOMMUNITY_REDIRECT_IP_NH) {
				snprintf(encbuf, sizeof(encbuf),
					 "FS:redirect IP 0x%x", *(pnt + 5));
			} else
				unk_ecom = true;
		} else if (type == ECOMMUNITY_ENCODE_TRANS_EXP ||
			   type == ECOMMUNITY_EXTENDED_COMMUNITY_PART_2 ||
			   type == ECOMMUNITY_EXTENDED_COMMUNITY_PART_3) {
			sub_type = *pnt++;

			if (sub_type == ECOMMUNITY_ROUTE_TARGET) {
				char buf[ECOMMUNITY_STRLEN];

				memset(buf, 0, sizeof(buf));
				ecommunity_rt_soo_str_internal(
					buf, sizeof(buf), (const uint8_t *)pnt,
					CHECK_FLAG(type,
						   ~ECOMMUNITY_ENCODE_TRANS_EXP),
					ECOMMUNITY_ROUTE_TARGET, format,
					ecom->unit_size);
				snprintf(encbuf, sizeof(encbuf), "%s", buf);
			} else if (sub_type ==
				   ECOMMUNITY_FLOWSPEC_REDIRECT_IPV6) {
				char buf[64];

				memset(buf, 0, sizeof(buf));
				ecommunity_rt_soo_str_internal(
					buf, sizeof(buf), (const uint8_t *)pnt,
					CHECK_FLAG(type,
						   ~ECOMMUNITY_ENCODE_TRANS_EXP),
					ECOMMUNITY_ROUTE_TARGET,
					ECOMMUNITY_FORMAT_DISPLAY,
					ecom->unit_size);
				snprintf(encbuf, sizeof(encbuf),
					 "FS:redirect VRF %s", buf);
			} else if (sub_type == ECOMMUNITY_REDIRECT_VRF) {
				char buf[16];

				memset(buf, 0, sizeof(buf));
				ecommunity_rt_soo_str(
					buf, sizeof(buf), (const uint8_t *)pnt,
					CHECK_FLAG(type,
						   ~ECOMMUNITY_ENCODE_TRANS_EXP),
					ECOMMUNITY_ROUTE_TARGET,
					ECOMMUNITY_FORMAT_DISPLAY);
				snprintf(encbuf, sizeof(encbuf),
					 "FS:redirect VRF %s", buf);
				snprintf(encbuf, sizeof(encbuf),
					 "FS:redirect VRF %s", buf);
			} else if (type != ECOMMUNITY_ENCODE_TRANS_EXP)
				unk_ecom = true;
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
				unk_ecom = true;
		} else if (type == ECOMMUNITY_ENCODE_AS_NON_TRANS) {
			sub_type = *pnt++;
			if (sub_type == ECOMMUNITY_LINK_BANDWIDTH)
				ecommunity_lb_str(encbuf, sizeof(encbuf), pnt,
						  ecom->disable_ieee_floating);
			else if (sub_type == ECOMMUNITY_EXTENDED_LINK_BANDWIDTH)
				ipv6_ecommunity_lb_str(encbuf, sizeof(encbuf),
						       pnt, len);
			else
				unk_ecom = true;
		} else if (type == ECOMMUNITY_ENCODE_IP_NON_TRANS) {
			sub_type = *pnt++;
			if (sub_type == ECOMMUNITY_NODE_TARGET)
				ecommunity_node_target_str(
					encbuf, sizeof(encbuf), pnt, format);
			else
				unk_ecom = true;
		} else if (type == ECOMMUNITY_ENCODE_OPAQUE_NON_TRANS) {
			sub_type = *pnt++;
			if (sub_type == ECOMMUNITY_ORIGIN_VALIDATION_STATE)
				ecommunity_origin_validation_state_str(
					encbuf, sizeof(encbuf), pnt);
			else
				unk_ecom = true;
		} else {
			sub_type = *pnt++;
			unk_ecom = true;
		}

unknown:
		if (unk_ecom)
			snprintf(encbuf, sizeof(encbuf), "UNK:%d, %d", type,
				 sub_type);

		int r = strlcat(str_buf, encbuf, str_size);
		assert(r < str_size);
	}

	return str_buf;
}

bool ecommunity_include(struct ecommunity *e1, struct ecommunity *e2)
{
	uint32_t i, j;

	if (!e1 || !e2)
		return false;
	for (i = 0; i < e1->size; ++i) {
		for (j = 0; j < e2->size; ++j) {
			if (!memcmp(e1->val + (i * e1->unit_size),
				    e2->val + (j * e2->unit_size),
				    e1->unit_size))
				return true;
		}
	}
	return false;
}

bool ecommunity_match(const struct ecommunity *ecom1,
		      const struct ecommunity *ecom2)
{
	uint32_t i = 0;
	uint32_t j = 0;

	if (ecom1 == NULL && ecom2 == NULL)
		return true;

	if (ecom1 == NULL || ecom2 == NULL)
		return false;

	if (ecom1->size < ecom2->size)
		return false;

	/* Every community on com2 needs to be on com1 for this to match */
	while (i < ecom1->size && j < ecom2->size) {
		if (memcmp(ecom1->val + i * ecom1->unit_size,
			   ecom2->val + j * ecom2->unit_size,
			   ecom2->unit_size)
		    == 0)
			j++;
		i++;
	}

	if (j == ecom2->size)
		return true;
	else
		return false;
}

/* return last occurence of color */
/* it will be the greatest color value */
extern uint32_t ecommunity_select_color(const struct ecommunity *ecom)
{

	uint32_t aux_color = 0;
	uint8_t *p;
	uint32_t c = 0;

	/* If the value already exists in the structure return 0.  */

	for (p = ecom->val; c < ecom->size; p += ecom->unit_size, c++) {
		if (p == NULL)
			break;

		if (p[0] == ECOMMUNITY_ENCODE_OPAQUE &&
		    p[1] == ECOMMUNITY_COLOR)
			ptr_get_be32((const uint8_t *)&p[4], &aux_color);
	}
	return aux_color;
}


/* return first occurence of type */
extern struct ecommunity_val *ecommunity_lookup(const struct ecommunity *ecom,
						uint8_t type, uint8_t subtype)
{
	uint8_t *p;
	uint32_t c;

	/* If the value already exists in the structure return 0.  */
	c = 0;
	for (p = ecom->val; c < ecom->size; p += ecom->unit_size, c++) {
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
	uint32_t c, found = 0;
	/* When this is fist value, just add it.  */
	if (ecom == NULL || ecom->val == NULL)
		return false;

	/* Check if any existing ext community matches. */
	/* Certain extended communities like the Route Target can be present
	 * multiple times, handle that.
	 */
	c = 0;
	for (p = ecom->val; c < ecom->size; p += ecom->unit_size, c++) {
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
		      (ecom->size - found) * ecom->unit_size);
	q = new;
	for (c = 0, p = ecom->val; c < ecom->size; c++, p += ecom->unit_size) {
		if (!(p[0] == type && p[1] == subtype)) {
			memcpy(q, p, ecom->unit_size);
			q += ecom->unit_size;
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
	uint32_t c, found = 0;

	/* Make sure specified value exists. */
	if (ecom == NULL || ecom->val == NULL)
		return false;
	c = 0;
	for (p = ecom->val; c < ecom->size; p += ecom->unit_size, c++) {
		if (!memcmp(p, eval->val, ecom->unit_size)) {
			found = 1;
			break;
		}
	}
	if (found == 0)
		return false;

	/* Delete the selected value */
	ecom->size--;
	if (ecom->size) {
		p = XMALLOC(MTYPE_ECOMMUNITY_VAL, ecom->size * ecom->unit_size);
		if (c != 0)
			memcpy(p, ecom->val, c * ecom->unit_size);
		if ((ecom->size - c) != 0)
			memcpy(p + (c)*ecom->unit_size,
			       ecom->val + (c + 1) * ecom->unit_size,
			       (ecom->size - c) * ecom->unit_size);
		XFREE(MTYPE_ECOMMUNITY_VAL, ecom->val);
		ecom->val = p;
	} else
		XFREE(MTYPE_ECOMMUNITY_VAL, ecom->val);

	return true;
}

int ecommunity_fill_pbr_action(struct ecommunity_val *ecom_eval,
			       struct bgp_pbr_entry_action *api,
			       afi_t afi)
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
		if (CHECK_FLAG(ecom_eval->val[5],
			       (1 << FLOWSPEC_TRAFFIC_ACTION_TERMINAL)))
			SET_FLAG(api->u.za.filter, TRAFFIC_ACTION_TERMINATE);
		else
			SET_FLAG(api->u.za.filter, TRAFFIC_ACTION_DISTRIBUTE);
		if (ecom_eval->val[5] == 1 << FLOWSPEC_TRAFFIC_ACTION_SAMPLE)
			SET_FLAG(api->u.za.filter, TRAFFIC_ACTION_SAMPLE);

	} else if (ecom_eval->val[1] == ECOMMUNITY_TRAFFIC_MARKING) {
		api->action = ACTION_MARKING;
		api->u.marking_dscp = ecom_eval->val[7];
	} else if (ecom_eval->val[1] == ECOMMUNITY_REDIRECT_VRF) {
		/* must use external function */
		return 0;
	} else if (ecom_eval->val[1] == ECOMMUNITY_REDIRECT_IP_NH &&
		   afi == AFI_IP) {
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
		struct ecommunity_ip *ip_ecom =
			(struct ecommunity_ip *)&ecom_eval->val[2];

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

struct ecommunity *
ecommunity_add_origin_validation_state(enum rpki_states rpki_state,
				       struct ecommunity *old)
{
	struct ecommunity *new = NULL;
	struct ecommunity ovs_ecomm = {0};
	struct ecommunity_val ovs_eval;

	encode_origin_validation_state(rpki_state, &ovs_eval);

	if (old) {
		new = ecommunity_dup(old);
		ecommunity_add_val(new, &ovs_eval, true, true);
		if (!old->refcnt)
			ecommunity_free(&old);
	} else {
		ovs_ecomm.size = 1;
		ovs_ecomm.unit_size = ECOMMUNITY_SIZE;
		ovs_ecomm.val = (uint8_t *)&ovs_eval.val;
		new = ecommunity_dup(&ovs_ecomm);
	}

	return new;
}

/*
 * return the BGP link bandwidth extended community, if present;
 * the actual bandwidth is returned via param
 */
const uint8_t *ecommunity_linkbw_present(struct ecommunity *ecom, uint64_t *bw)
{
	const uint8_t *data;
	uint32_t i;

	if (bw)
		*bw = 0;

	if (!ecom || !ecom->size)
		return NULL;

	for (i = 0; i < ecom->size; i++) {
		const uint8_t *pnt;
		uint8_t type, sub_type;

		data = pnt = (ecom->val + (i * ecom->unit_size));
		type = *pnt++;
		sub_type = *pnt++;

		const uint8_t *end = data + ecom->unit_size;
		size_t len = end - data;

		/* Sanity check for extended communities lenght, to avoid
		 * overrun when dealing with bits, e.g. ptr_get_be64().
		 */
		if (len < ecom->unit_size)
			return NULL;

		if ((type == ECOMMUNITY_ENCODE_AS ||
		     type == ECOMMUNITY_ENCODE_AS_NON_TRANS) &&
		    sub_type == ECOMMUNITY_LINK_BANDWIDTH) {
			uint32_t bwval;

			pnt += 2; /* bandwidth is encoded as AS:val */
			pnt = ptr_get_be32(pnt, &bwval);
			(void)pnt; /* consume value */
			if (bw)
				*bw = (uint64_t)(ecom->disable_ieee_floating
							 ? bwval
							 : ieee_float_uint32_to_uint32(
								   bwval));
			return data;
		} else if (type == ECOMMUNITY_ENCODE_AS4 &&
			   sub_type == ECOMMUNITY_EXTENDED_LINK_BANDWIDTH) {
			uint64_t bwval;

			if (len < IPV6_ECOMMUNITY_SIZE)
				return NULL;

			pnt += 2; /* Reserved */
			pnt = ptr_get_be64(pnt, &bwval);
			(void)pnt;

			if (bw)
				*bw = bwval;

			return data;
		}
	}

	return NULL;
}


struct ecommunity *ecommunity_replace_linkbw(as_t as, struct ecommunity *ecom,
					     uint64_t cum_bw,
					     bool disable_ieee_floating,
					     bool extended)
{
	struct ecommunity *new;
	const uint8_t *eval;
	uint8_t type;
	uint64_t cur_bw;

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
	if (CHECK_FLAG(type, ECOMMUNITY_FLAG_NON_TRANSITIVE))
		return new;

	/* Transitive link-bandwidth exists, replace with the passed
	 * (cumulative) bandwidth value. We need to create a new
	 * extcommunity for this - refer to AS-Path replace function
	 * for reference.
	 */
	if (cum_bw > 0xFFFFFFFF)
		cum_bw = 0xFFFFFFFF;

	if (extended) {
		struct ecommunity_val_ipv6 lb_eval;

		encode_lb_extended_extcomm(as, cum_bw, false, &lb_eval);
		new = ecommunity_dup(ecom);
		ecommunity_add_val_ipv6(new, &lb_eval, true, true);
	} else {
		struct ecommunity_val lb_eval;

		encode_lb_extcomm(as > BGP_AS_MAX ? BGP_AS_TRANS : as, cum_bw,
				  false, &lb_eval, disable_ieee_floating);
		new = ecommunity_dup(ecom);
		ecommunity_add_val(new, &lb_eval, true, true);
	}

	return new;
}

bool soo_in_ecom(struct ecommunity *ecom, struct ecommunity *soo)
{
	if (ecom && soo) {
		if ((ecommunity_lookup(ecom, ECOMMUNITY_ENCODE_AS,
				       ECOMMUNITY_SITE_ORIGIN) ||
		     ecommunity_lookup(ecom, ECOMMUNITY_ENCODE_AS4,
				       ECOMMUNITY_SITE_ORIGIN) ||
		     ecommunity_lookup(ecom, ECOMMUNITY_ENCODE_IP,
				       ECOMMUNITY_SITE_ORIGIN)) &&
		    ecommunity_include(ecom, soo))
			return true;
	}
	return false;
}
