/* Community attribute related functions.
 * Copyright (C) 1998, 2001 Kunihiro Ishiguro
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

#include "command.h"
#include "hash.h"
#include "memory.h"
#include "jhash.h"

#include "bgpd/bgp_memory.h"
#include "bgpd/bgp_community.h"

/* Hash of community attribute. */
static struct hash *comhash;

/* Allocate a new communities value.  */
static struct community *community_new(void)
{
	return XCALLOC(MTYPE_COMMUNITY, sizeof(struct community));
}

/* Free communities value.  */
void community_free(struct community **com)
{
	XFREE(MTYPE_COMMUNITY_VAL, (*com)->val);
	XFREE(MTYPE_COMMUNITY_STR, (*com)->str);

	if ((*com)->json) {
		json_object_free((*com)->json);
		(*com)->json = NULL;
	}

	XFREE(MTYPE_COMMUNITY, (*com));
}

/* Add one community value to the community. */
static void community_add_val(struct community *com, uint32_t val)
{
	com->size++;
	if (com->val)
		com->val = XREALLOC(MTYPE_COMMUNITY_VAL, com->val,
				    com_length(com));
	else
		com->val = XMALLOC(MTYPE_COMMUNITY_VAL, com_length(com));

	val = htonl(val);
	memcpy(com_lastval(com), &val, sizeof(uint32_t));
}

/* Delete one community. */
void community_del_val(struct community *com, uint32_t *val)
{
	int i = 0;
	int c = 0;

	if (!com->val)
		return;

	while (i < com->size) {
		if (memcmp(com->val + i, val, sizeof(uint32_t)) == 0) {
			c = com->size - i - 1;

			if (c > 0)
				memmove(com->val + i, com->val + (i + 1),
					c * sizeof(*val));

			com->size--;

			if (com->size > 0)
				com->val = XREALLOC(MTYPE_COMMUNITY_VAL,
						    com->val, com_length(com));
			else {
				XFREE(MTYPE_COMMUNITY_VAL, com->val);
				com->val = NULL;
			}
			return;
		}
		i++;
	}
}

/* Delete all communities listed in com2 from com1 */
struct community *community_delete(struct community *com1,
				   struct community *com2)
{
	int i = 0;

	while (i < com2->size) {
		community_del_val(com1, com2->val + i);
		i++;
	}

	return com1;
}

/* Callback function from qsort(). */
static int community_compare(const void *a1, const void *a2)
{
	uint32_t v1;
	uint32_t v2;

	memcpy(&v1, a1, sizeof(uint32_t));
	memcpy(&v2, a2, sizeof(uint32_t));
	v1 = ntohl(v1);
	v2 = ntohl(v2);

	if (v1 < v2)
		return -1;
	if (v1 > v2)
		return 1;
	return 0;
}

int community_include(struct community *com, uint32_t val)
{
	int i;

	val = htonl(val);

	for (i = 0; i < com->size; i++)
		if (memcmp(&val, com_nthval(com, i), sizeof(uint32_t)) == 0)
			return 1;

	return 0;
}

uint32_t community_val_get(struct community *com, int i)
{
	uint8_t *p;
	uint32_t val;

	p = (uint8_t *)com->val;
	p += (i * 4);

	memcpy(&val, p, sizeof(uint32_t));

	return ntohl(val);
}

/* Sort and uniq given community. */
struct community *community_uniq_sort(struct community *com)
{
	int i;
	struct community *new;
	uint32_t val;

	if (!com)
		return NULL;

	new = community_new();
	new->json = NULL;

	for (i = 0; i < com->size; i++) {
		val = community_val_get(com, i);

		if (!community_include(new, val))
			community_add_val(new, val);
	}

	qsort(new->val, new->size, sizeof(uint32_t), community_compare);

	return new;
}

/* Convert communities attribute to string.

   For Well-known communities value, below keyword is used.

   0x0             "internet"
   0xFFFF0000      "graceful-shutdown"
   0xFFFF0001      "accept-own"
   0xFFFF0002      "route-filter-translated-v4"
   0xFFFF0003      "route-filter-v4"
   0xFFFF0004      "route-filter-translated-v6"
   0xFFFF0005      "route-filter-v6"
   0xFFFF0006      "llgr-stale"
   0xFFFF0007      "no-llgr"
   0xFFFF0008      "accept-own-nexthop"
   0xFFFF029A      "blackhole"
   0xFFFFFF01      "no-export"
   0xFFFFFF02      "no-advertise"
   0xFFFFFF03      "local-AS"
   0xFFFFFF04      "no-peer"

   For other values, "AS:VAL" format is used.  */
static void set_community_string(struct community *com, bool make_json)
{
	int i;
	char *str;
	int len;
	int first;
	uint32_t comval;
	uint16_t as;
	uint16_t val;
	json_object *json_community_list = NULL;
	json_object *json_string = NULL;

	if (!com)
		return;

	if (make_json) {
		com->json = json_object_new_object();
		json_community_list = json_object_new_array();
	}

	/* When communities attribute is empty.  */
	if (com->size == 0) {
		str = XMALLOC(MTYPE_COMMUNITY_STR, 1);
		str[0] = '\0';

		if (make_json) {
			json_object_string_add(com->json, "string", "");
			json_object_object_add(com->json, "list",
					       json_community_list);
		}
		com->str = str;
		return;
	}

	/* Memory allocation is time consuming work.  So we calculate
	   required string length first.  */
	len = 0;

	for (i = 0; i < com->size; i++) {
		memcpy(&comval, com_nthval(com, i), sizeof(uint32_t));
		comval = ntohl(comval);

		switch (comval) {
		case COMMUNITY_INTERNET:
			len += strlen(" internet");
			break;
		case COMMUNITY_GSHUT:
			len += strlen(" graceful-shutdown");
			break;
		case COMMUNITY_ACCEPT_OWN:
			len += strlen(" accept-own");
			break;
		case COMMUNITY_ROUTE_FILTER_TRANSLATED_v4:
			len += strlen(" route-filter-translated-v4");
			break;
		case COMMUNITY_ROUTE_FILTER_v4:
			len += strlen(" route-filter-v4");
			break;
		case COMMUNITY_ROUTE_FILTER_TRANSLATED_v6:
			len += strlen(" route-filter-translated-v6");
			break;
		case COMMUNITY_ROUTE_FILTER_v6:
			len += strlen(" route-filter-v6");
			break;
		case COMMUNITY_LLGR_STALE:
			len += strlen(" llgr-stale");
			break;
		case COMMUNITY_NO_LLGR:
			len += strlen(" no-llgr");
			break;
		case COMMUNITY_ACCEPT_OWN_NEXTHOP:
			len += strlen(" accept-own-nexthop");
			break;
		case COMMUNITY_BLACKHOLE:
			len += strlen(" blackhole");
			break;
		case COMMUNITY_NO_EXPORT:
			len += strlen(" no-export");
			break;
		case COMMUNITY_NO_ADVERTISE:
			len += strlen(" no-advertise");
			break;
		case COMMUNITY_LOCAL_AS:
			len += strlen(" local-AS");
			break;
		case COMMUNITY_NO_PEER:
			len += strlen(" no-peer");
			break;
		default:
			len += strlen(" 65536:65535");
			break;
		}
	}

	/* Allocate memory.  */
	str = XCALLOC(MTYPE_COMMUNITY_STR, len);
	first = 1;

	/* Fill in string.  */
	for (i = 0; i < com->size; i++) {
		memcpy(&comval, com_nthval(com, i), sizeof(uint32_t));
		comval = ntohl(comval);

		if (first)
			first = 0;
		else
			strlcat(str, " ", len);

		switch (comval) {
		case COMMUNITY_INTERNET:
			strlcat(str, "internet", len);
			if (make_json) {
				json_string =
					json_object_new_string("internet");
				json_object_array_add(json_community_list,
						      json_string);
			}
			break;
		case COMMUNITY_GSHUT:
			strlcat(str, "graceful-shutdown", len);
			if (make_json) {
				json_string = json_object_new_string(
					"gracefulShutdown");
				json_object_array_add(json_community_list,
						      json_string);
			}
			break;
		case COMMUNITY_ACCEPT_OWN:
			strlcat(str, "accept-own", len);
			if (make_json) {
				json_string = json_object_new_string(
					"acceptown");
				json_object_array_add(json_community_list,
						      json_string);
			}
			break;
		case COMMUNITY_ROUTE_FILTER_TRANSLATED_v4:
			strlcat(str, "route-filter-translated-v4", len);
			if (make_json) {
				json_string = json_object_new_string(
					"routeFilterTranslatedV4");
				json_object_array_add(json_community_list,
						      json_string);
			}
			break;
		case COMMUNITY_ROUTE_FILTER_v4:
			strlcat(str, "route-filter-v4", len);
			if (make_json) {
				json_string = json_object_new_string(
					"routeFilterV4");
				json_object_array_add(json_community_list,
						      json_string);
			}
			break;
		case COMMUNITY_ROUTE_FILTER_TRANSLATED_v6:
			strlcat(str, "route-filter-translated-v6", len);
			if (make_json) {
				json_string = json_object_new_string(
					"routeFilterTranslatedV6");
				json_object_array_add(json_community_list,
						      json_string);
			}
			break;
		case COMMUNITY_ROUTE_FILTER_v6:
			strlcat(str, "route-filter-v6", len);
			if (make_json) {
				json_string = json_object_new_string(
					"routeFilterV6");
				json_object_array_add(json_community_list,
						      json_string);
			}
			break;
		case COMMUNITY_LLGR_STALE:
			strlcat(str, "llgr-stale", len);
			if (make_json) {
				json_string = json_object_new_string(
					"llgrStale");
				json_object_array_add(json_community_list,
						      json_string);
			}
			break;
		case COMMUNITY_NO_LLGR:
			strlcat(str, "no-llgr", len);
			if (make_json) {
				json_string = json_object_new_string(
					"noLlgr");
				json_object_array_add(json_community_list,
						      json_string);
			}
			break;
		case COMMUNITY_ACCEPT_OWN_NEXTHOP:
			strlcat(str, "accept-own-nexthop", len);
			if (make_json) {
				json_string = json_object_new_string(
					"acceptownnexthop");
				json_object_array_add(json_community_list,
						      json_string);
			}
			break;
		case COMMUNITY_BLACKHOLE:
			strlcat(str, "blackhole", len);
			if (make_json) {
				json_string = json_object_new_string(
					"blackhole");
				json_object_array_add(json_community_list,
						      json_string);
			}
			break;
		case COMMUNITY_NO_EXPORT:
			strlcat(str, "no-export", len);
			if (make_json) {
				json_string =
					json_object_new_string("noExport");
				json_object_array_add(json_community_list,
						      json_string);
			}
			break;
		case COMMUNITY_NO_ADVERTISE:
			strlcat(str, "no-advertise", len);
			if (make_json) {
				json_string =
					json_object_new_string("noAdvertise");
				json_object_array_add(json_community_list,
						      json_string);
			}
			break;
		case COMMUNITY_LOCAL_AS:
			strlcat(str, "local-AS", len);
			if (make_json) {
				json_string = json_object_new_string("localAs");
				json_object_array_add(json_community_list,
						      json_string);
			}
			break;
		case COMMUNITY_NO_PEER:
			strlcat(str, "no-peer", len);
			if (make_json) {
				json_string = json_object_new_string("noPeer");
				json_object_array_add(json_community_list,
						      json_string);
			}
			break;
		default:
			as = (comval >> 16) & 0xFFFF;
			val = comval & 0xFFFF;
			char buf[32];
			snprintf(buf, sizeof(buf), "%u:%d", as, val);
			strlcat(str, buf, len);
			if (make_json) {
				json_string = json_object_new_string(buf);
				json_object_array_add(json_community_list,
						      json_string);
			}
			break;
		}
	}

	if (make_json) {
		json_object_string_add(com->json, "string", str);
		json_object_object_add(com->json, "list", json_community_list);
	}
	com->str = str;
}

/* Intern communities attribute.  */
struct community *community_intern(struct community *com)
{
	struct community *find;

	/* Assert this community structure is not interned. */
	assert(com->refcnt == 0);

	/* Lookup community hash. */
	find = (struct community *)hash_get(comhash, com, hash_alloc_intern);

	/* Arguemnt com is allocated temporary.  So when it is not used in
	   hash, it should be freed.  */
	if (find != com)
		community_free(&com);

	/* Increment refrence counter.  */
	find->refcnt++;

	/* Make string.  */
	if (!find->str)
		set_community_string(find, false);

	return find;
}

/* Free community attribute. */
void community_unintern(struct community **com)
{
	struct community *ret;

	if ((*com)->refcnt)
		(*com)->refcnt--;

	/* Pull off from hash.  */
	if ((*com)->refcnt == 0) {
		/* Community value com must exist in hash. */
		ret = (struct community *)hash_release(comhash, *com);
		assert(ret != NULL);

		community_free(com);
	}
}

/* Create new community attribute. */
struct community *community_parse(uint32_t *pnt, unsigned short length)
{
	struct community tmp;
	struct community *new;

	/* If length is malformed return NULL. */
	if (length % 4)
		return NULL;

	/* Make temporary community for hash look up. */
	tmp.size = length / 4;
	tmp.val = pnt;

	new = community_uniq_sort(&tmp);

	return community_intern(new);
}

struct community *community_dup(struct community *com)
{
	struct community *new;

	new = XCALLOC(MTYPE_COMMUNITY, sizeof(struct community));
	new->size = com->size;
	if (new->size) {
		new->val = XMALLOC(MTYPE_COMMUNITY_VAL, com->size * 4);
		memcpy(new->val, com->val, com->size * 4);
	} else
		new->val = NULL;
	return new;
}

/* Retrun string representation of communities attribute. */
char *community_str(struct community *com, bool make_json)
{
	if (!com)
		return NULL;

	if (make_json && !com->json && com->str)
		XFREE(MTYPE_COMMUNITY_STR, com->str);

	if (!com->str)
		set_community_string(com, make_json);
	return com->str;
}

/* Make hash value of community attribute. This function is used by
   hash package.*/
unsigned int community_hash_make(const struct community *com)
{
	uint32_t *pnt = (uint32_t *)com->val;

	return jhash2(pnt, com->size, 0x43ea96c1);
}

int community_match(const struct community *com1, const struct community *com2)
{
	int i = 0;
	int j = 0;

	if (com1 == NULL && com2 == NULL)
		return 1;

	if (com1 == NULL || com2 == NULL)
		return 0;

	if (com1->size < com2->size)
		return 0;

	/* Every community on com2 needs to be on com1 for this to match */
	while (i < com1->size && j < com2->size) {
		if (memcmp(com1->val + i, com2->val + j, sizeof(uint32_t)) == 0)
			j++;
		i++;
	}

	if (j == com2->size)
		return 1;
	else
		return 0;
}

/* If two aspath have same value then return 1 else return 0. This
   function is used by hash package. */
bool community_cmp(const struct community *com1, const struct community *com2)
{
	if (com1 == NULL && com2 == NULL)
		return true;
	if (com1 == NULL || com2 == NULL)
		return false;

	if (com1->size == com2->size)
		if (memcmp(com1->val, com2->val, com1->size * 4) == 0)
			return true;
	return false;
}

/* Add com2 to the end of com1. */
struct community *community_merge(struct community *com1,
				  struct community *com2)
{
	if (com1->val)
		com1->val = XREALLOC(MTYPE_COMMUNITY_VAL, com1->val,
				     (com1->size + com2->size) * 4);
	else
		com1->val = XMALLOC(MTYPE_COMMUNITY_VAL,
				    (com1->size + com2->size) * 4);

	memcpy(com1->val + com1->size, com2->val, com2->size * 4);
	com1->size += com2->size;

	return com1;
}

/* Community token enum. */
enum community_token {
	community_token_val,
	community_token_gshut,
	community_token_accept_own,
	community_token_route_filter_translated_v4,
	community_token_route_filter_v4,
	community_token_route_filter_translated_v6,
	community_token_route_filter_v6,
	community_token_llgr_stale,
	community_token_no_llgr,
	community_token_accept_own_nexthop,
	community_token_blackhole,
	community_token_no_export,
	community_token_no_advertise,
	community_token_local_as,
	community_token_no_peer,
	community_token_unknown
};

/* Get next community token from string. */
static const char *
community_gettoken(const char *buf, enum community_token *token, uint32_t *val)
{
	const char *p = buf;

	/* Skip white space. */
	while (isspace((unsigned char)*p))
		p++;

	/* Check the end of the line. */
	if (*p == '\0')
		return NULL;

	/* Well known community string check. */
	if (isalpha((unsigned char)*p)) {
		if (strncmp(p, "internet", strlen("internet")) == 0) {
			*val = COMMUNITY_INTERNET;
			*token = community_token_no_export;
			p += strlen("internet");
			return p;
		}
		if (strncmp(p, "graceful-shutdown", strlen("graceful-shutdown"))
		    == 0) {
			*val = COMMUNITY_GSHUT;
			*token = community_token_gshut;
			p += strlen("graceful-shutdown");
			return p;
		}
		if (strncmp(p, "accept-own", strlen("accept-own"))
		    == 0) {
			*val = COMMUNITY_ACCEPT_OWN;
			*token = community_token_accept_own;
			p += strlen("accept-own");
			return p;
		}
		if (strncmp(p, "route-filter-translated-v4",
			strlen("route-filter-translated-v4"))
		    == 0) {
			*val = COMMUNITY_ROUTE_FILTER_TRANSLATED_v4;
			*token = community_token_route_filter_translated_v4;
			p += strlen("route-filter-translated-v4");
			return p;
		}
		if (strncmp(p, "route-filter-v4", strlen("route-filter-v4"))
		    == 0) {
			*val = COMMUNITY_ROUTE_FILTER_v4;
			*token = community_token_route_filter_v4;
			p += strlen("route-filter-v4");
			return p;
		}
		if (strncmp(p, "route-filter-translated-v6",
			strlen("route-filter-translated-v6"))
		    == 0) {
			*val = COMMUNITY_ROUTE_FILTER_TRANSLATED_v6;
			*token = community_token_route_filter_translated_v6;
			p += strlen("route-filter-translated-v6");
			return p;
		}
		if (strncmp(p, "route-filter-v6", strlen("route-filter-v6"))
		    == 0) {
			*val = COMMUNITY_ROUTE_FILTER_v6;
			*token = community_token_route_filter_v6;
			p += strlen("route-filter-v6");
			return p;
		}
		if (strncmp(p, "llgr-stale", strlen("llgr-stale"))
		    == 0) {
			*val = COMMUNITY_LLGR_STALE;
			*token = community_token_llgr_stale;
			p += strlen("llgr-stale");
			return p;
		}
		if (strncmp(p, "no-llgr", strlen("no-llgr"))
		    == 0) {
			*val = COMMUNITY_NO_LLGR;
			*token = community_token_no_llgr;
			p += strlen("no-llgr");
			return p;
		}
		if (strncmp(p, "accept-own-nexthop",
			strlen("accept-own-nexthop"))
		    == 0) {
			*val = COMMUNITY_ACCEPT_OWN_NEXTHOP;
			*token = community_token_accept_own_nexthop;
			p += strlen("accept-own-nexthop");
			return p;
		}
		if (strncmp(p, "blackhole", strlen("blackhole"))
		    == 0) {
			*val = COMMUNITY_BLACKHOLE;
			*token = community_token_blackhole;
			p += strlen("blackhole");
			return p;
		}
		if (strncmp(p, "no-export", strlen("no-export")) == 0) {
			*val = COMMUNITY_NO_EXPORT;
			*token = community_token_no_export;
			p += strlen("no-export");
			return p;
		}
		if (strncmp(p, "no-advertise", strlen("no-advertise")) == 0) {
			*val = COMMUNITY_NO_ADVERTISE;
			*token = community_token_no_advertise;
			p += strlen("no-advertise");
			return p;
		}
		if (strncmp(p, "local-AS", strlen("local-AS")) == 0) {
			*val = COMMUNITY_LOCAL_AS;
			*token = community_token_local_as;
			p += strlen("local-AS");
			return p;
		}
		if (strncmp(p, "no-peer", strlen("no-peer")) == 0) {
			*val = COMMUNITY_NO_PEER;
			*token = community_token_no_peer;
			p += strlen("no-peer");
			return p;
		}

		/* Unknown string. */
		*token = community_token_unknown;
		return NULL;
	}

	/* Community value. */
	if (isdigit((unsigned char)*p)) {
		int separator = 0;
		int digit = 0;
		uint32_t community_low = 0;
		uint32_t community_high = 0;

		while (isdigit((unsigned char)*p) || *p == ':') {
			if (*p == ':') {
				if (separator) {
					*token = community_token_unknown;
					return NULL;
				} else {
					separator = 1;
					digit = 0;

					if (community_low > UINT16_MAX) {
						*token =
							community_token_unknown;
						return NULL;
					}

					community_high = community_low << 16;
					community_low = 0;
				}
			} else {
				digit = 1;
				community_low *= 10;
				community_low += (*p - '0');
			}
			p++;
		}
		if (!digit) {
			*token = community_token_unknown;
			return NULL;
		}

		if (community_low > UINT16_MAX) {
			*token = community_token_unknown;
			return NULL;
		}

		*val = community_high + community_low;
		*token = community_token_val;
		return p;
	}
	*token = community_token_unknown;
	return NULL;
}

/* convert string to community structure */
struct community *community_str2com(const char *str)
{
	struct community *com = NULL;
	struct community *com_sort = NULL;
	uint32_t val = 0;
	enum community_token token = community_token_unknown;

	do {
		str = community_gettoken(str, &token, &val);

		switch (token) {
		case community_token_val:
		case community_token_gshut:
		case community_token_accept_own:
		case community_token_route_filter_translated_v4:
		case community_token_route_filter_v4:
		case community_token_route_filter_translated_v6:
		case community_token_route_filter_v6:
		case community_token_llgr_stale:
		case community_token_no_llgr:
		case community_token_accept_own_nexthop:
		case community_token_blackhole:
		case community_token_no_export:
		case community_token_no_advertise:
		case community_token_local_as:
		case community_token_no_peer:
			if (com == NULL) {
				com = community_new();
				com->json = NULL;
			}
			community_add_val(com, val);
			break;
		case community_token_unknown:
			if (com)
				community_free(&com);
			return NULL;
		}
	} while (str);

	com_sort = community_uniq_sort(com);
	community_free(&com);

	return com_sort;
}

/* Return communities hash entry count.  */
unsigned long community_count(void)
{
	return comhash->count;
}

/* Return communities hash.  */
struct hash *community_hash(void)
{
	return comhash;
}

/* Initialize comminity related hash. */
void community_init(void)
{
	comhash =
		hash_create((unsigned int (*)(const void *))community_hash_make,
			    (bool (*)(const void *, const void *))community_cmp,
			    "BGP Community Hash");
}

void community_finish(void)
{
	hash_free(comhash);
	comhash = NULL;
}

static struct community *bgp_aggr_community_lookup(
						struct bgp_aggregate *aggregate,
						struct community *community)
{
	return hash_lookup(aggregate->community_hash, community);
}

static void *bgp_aggr_communty_hash_alloc(void *p)
{
	struct community *ref = (struct community *)p;
	struct community *community = NULL;

	community = community_dup(ref);
	return community;
}

static void bgp_aggr_community_prepare(struct hash_backet *hb, void *arg)
{
	struct community *hb_community = hb->data;
	struct community **aggr_community = arg;

	if (*aggr_community)
		*aggr_community = community_merge(*aggr_community,
						  hb_community);
	else
		*aggr_community = community_dup(hb_community);
}

void bgp_aggr_community_remove(void *arg)
{
	struct community *community = arg;

	community_free(&community);
}

void bgp_compute_aggregate_community(struct bgp_aggregate *aggregate,
				     struct community *community)
{
	bgp_compute_aggregate_community_hash(aggregate, community);
	bgp_compute_aggregate_community_val(aggregate);
}


void bgp_compute_aggregate_community_hash(struct bgp_aggregate *aggregate,
					  struct community *community)
{
	struct community *aggr_community = NULL;

	if ((aggregate == NULL) || (community == NULL))
		return;

	/* Create hash if not already created.
	 */
	if (aggregate->community_hash == NULL)
		aggregate->community_hash = hash_create(
			(unsigned int (*)(const void *))community_hash_make,
			(bool (*)(const void *, const void *))community_cmp,
			"BGP Aggregator community hash");

	aggr_community = bgp_aggr_community_lookup(aggregate, community);
	if (aggr_community == NULL) {
		/* Insert community into hash.
		 */
		aggr_community = hash_get(aggregate->community_hash, community,
					  bgp_aggr_communty_hash_alloc);
	}

	/* Increment reference counter.
	 */
	aggr_community->refcnt++;
}

void bgp_compute_aggregate_community_val(struct bgp_aggregate *aggregate)
{
	struct community *commerge = NULL;

	if (aggregate == NULL)
		return;

	/* Re-compute aggregate's community.
	 */
	if (aggregate->community)
		community_free(&aggregate->community);
	if (aggregate->community_hash &&
	    aggregate->community_hash->count) {
		hash_iterate(aggregate->community_hash,
			     bgp_aggr_community_prepare,
			     &aggregate->community);
		commerge = aggregate->community;
		aggregate->community = community_uniq_sort(commerge);
		if (commerge)
			community_free(&commerge);
	}
}



void bgp_remove_community_from_aggregate(struct bgp_aggregate *aggregate,
					 struct community *community)
{
	struct community *aggr_community = NULL;
	struct community *ret_comm = NULL;

	if ((!aggregate)
	    || (!aggregate->community_hash)
	    || (!community))
		return;

	/* Look-up the community in the hash.
	 */
	aggr_community = bgp_aggr_community_lookup(aggregate, community);
	if (aggr_community) {
		aggr_community->refcnt--;

		if (aggr_community->refcnt == 0) {
			ret_comm = hash_release(aggregate->community_hash,
						aggr_community);
			community_free(&ret_comm);

			bgp_compute_aggregate_community_val(aggregate);
		}
	}
}

void bgp_remove_comm_from_aggregate_hash(struct bgp_aggregate *aggregate,
		struct community *community)
{

	struct community *aggr_community = NULL;
	struct community *ret_comm = NULL;

	if ((!aggregate)
	    || (!aggregate->community_hash)
	    || (!community))
		return;

	/* Look-up the community in the hash.
	 */
	aggr_community = bgp_aggr_community_lookup(aggregate, community);
	if (aggr_community) {
		aggr_community->refcnt--;

		if (aggr_community->refcnt == 0) {
			ret_comm = hash_release(aggregate->community_hash,
						aggr_community);
			community_free(&ret_comm);
		}
	}
}
