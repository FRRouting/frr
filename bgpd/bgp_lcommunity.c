/* BGP Large Communities Attribute
 *
 * Copyright (C) 2016 Keyur Patel <keyur@arrcus.com>
 *
 * This file is part of FRRouting (FRR).
 *
 * FRR is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2, or (at your option) any later version.
 *
 * FRR is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
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
#include "filter.h"
#include "jhash.h"
#include "stream.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_community_alias.h"
#include "bgpd/bgp_aspath.h"

/* Hash of community attribute. */
static struct hash *lcomhash;

/* Allocate a new lcommunities.  */
static struct lcommunity *lcommunity_new(void)
{
	return XCALLOC(MTYPE_LCOMMUNITY, sizeof(struct lcommunity));
}

/* Allocate lcommunities.  */
void lcommunity_free(struct lcommunity **lcom)
{
	if (!(*lcom))
		return;

	XFREE(MTYPE_LCOMMUNITY_VAL, (*lcom)->val);
	XFREE(MTYPE_LCOMMUNITY_STR, (*lcom)->str);
	if ((*lcom)->json)
		json_object_free((*lcom)->json);
	XFREE(MTYPE_LCOMMUNITY, *lcom);
}

static void lcommunity_hash_free(struct lcommunity *lcom)
{
	lcommunity_free(&lcom);
}

/* Add a new Large Communities value to Large Communities
   Attribute structure.  When the value is already exists in the
   structure, we don't add the value.  Newly added value is sorted by
   numerical order.  When the value is added to the structure return 1
   else return 0.  */
static bool lcommunity_add_val(struct lcommunity *lcom,
			       struct lcommunity_val *lval)
{
	uint8_t *p;
	int ret;
	int c;

	/* When this is fist value, just add it.  */
	if (lcom->val == NULL) {
		lcom->size++;
		lcom->val = XMALLOC(MTYPE_LCOMMUNITY_VAL, lcom_length(lcom));
		memcpy(lcom->val, lval->val, LCOMMUNITY_SIZE);
		return true;
	}

	/* If the value already exists in the structure return 0.  */
	c = 0;
	for (p = lcom->val; c < lcom->size; p += LCOMMUNITY_SIZE, c++) {
		ret = memcmp(p, lval->val, LCOMMUNITY_SIZE);
		if (ret == 0)
			return false;
		if (ret > 0)
			break;
	}

	/* Add the value to the structure with numerical sorting.  */
	lcom->size++;
	lcom->val =
		XREALLOC(MTYPE_LCOMMUNITY_VAL, lcom->val, lcom_length(lcom));

	memmove(lcom->val + (c + 1) * LCOMMUNITY_SIZE,
		lcom->val + c * LCOMMUNITY_SIZE,
		(lcom->size - 1 - c) * LCOMMUNITY_SIZE);
	memcpy(lcom->val + c * LCOMMUNITY_SIZE, lval->val, LCOMMUNITY_SIZE);

	return true;
}

/* This function takes pointer to Large Communites strucutre then
   create a new Large Communities structure by uniq and sort each
   Large Communities value.  */
struct lcommunity *lcommunity_uniq_sort(struct lcommunity *lcom)
{
	int i;
	struct lcommunity *new;
	struct lcommunity_val *lval;

	if (!lcom)
		return NULL;

	new = lcommunity_new();

	for (i = 0; i < lcom->size; i++) {
		lval = (struct lcommunity_val *)(lcom->val
						 + (i * LCOMMUNITY_SIZE));
		lcommunity_add_val(new, lval);
	}
	return new;
}

/* Parse Large Communites Attribute in BGP packet.  */
struct lcommunity *lcommunity_parse(uint8_t *pnt, unsigned short length)
{
	struct lcommunity tmp;
	struct lcommunity *new;

	/* Length check.  */
	if (length % LCOMMUNITY_SIZE)
		return NULL;

	/* Prepare tmporary structure for making a new Large Communities
	   Attribute.  */
	tmp.size = length / LCOMMUNITY_SIZE;
	tmp.val = pnt;

	/* Create a new Large Communities Attribute by uniq and sort each
	   Large Communities value  */
	new = lcommunity_uniq_sort(&tmp);

	return lcommunity_intern(new);
}

/* Duplicate the Large Communities Attribute structure.  */
struct lcommunity *lcommunity_dup(struct lcommunity *lcom)
{
	struct lcommunity *new;

	new = lcommunity_new();
	new->size = lcom->size;
	if (new->size) {
		new->val = XMALLOC(MTYPE_LCOMMUNITY_VAL, lcom_length(lcom));
		memcpy(new->val, lcom->val, lcom_length(lcom));
	} else
		new->val = NULL;
	return new;
}

/* Merge two Large Communities Attribute structure.  */
struct lcommunity *lcommunity_merge(struct lcommunity *lcom1,
				    struct lcommunity *lcom2)
{
	if (lcom1->val)
		lcom1->val = XREALLOC(MTYPE_LCOMMUNITY_VAL, lcom1->val,
				      lcom_length(lcom1) + lcom_length(lcom2));
	else
		lcom1->val = XMALLOC(MTYPE_LCOMMUNITY_VAL,
				     lcom_length(lcom1) + lcom_length(lcom2));

	memcpy(lcom1->val + lcom_length(lcom1), lcom2->val, lcom_length(lcom2));
	lcom1->size += lcom2->size;

	return lcom1;
}

static void set_lcommunity_string(struct lcommunity *lcom, bool make_json)
{
	int i;
	int len;
	char *str_buf;
	const uint8_t *pnt;
	uint32_t global, local1, local2;
	json_object *json_lcommunity_list = NULL;
	json_object *json_string = NULL;

	/* 3 32-bit integers, 2 colons, and a space */
#define LCOMMUNITY_STRLEN (10 * 3 + 2 + 1)

	if (!lcom)
		return;

	if (make_json) {
		lcom->json = json_object_new_object();
		json_lcommunity_list = json_object_new_array();
	}

	if (lcom->size == 0) {
		str_buf = XCALLOC(MTYPE_LCOMMUNITY_STR, 1);

		if (make_json) {
			json_object_string_add(lcom->json, "string", "");
			json_object_object_add(lcom->json, "list",
					       json_lcommunity_list);
		}

		lcom->str = str_buf;
		return;
	}

	/* 1 space + lcom->size lcom strings + null terminator */
	size_t str_buf_sz = BUFSIZ;
	str_buf = XCALLOC(MTYPE_LCOMMUNITY_STR, str_buf_sz);

	for (i = 0; i < lcom->size; i++) {
		if (i > 0)
			strlcat(str_buf, " ", str_buf_sz);

		pnt = lcom->val + (i * LCOMMUNITY_SIZE);
		pnt = ptr_get_be32(pnt, &global);
		pnt = ptr_get_be32(pnt, &local1);
		pnt = ptr_get_be32(pnt, &local2);
		(void)pnt;

		char lcsb[LCOMMUNITY_STRLEN + 1];

		snprintf(lcsb, sizeof(lcsb), "%u:%u:%u", global, local1,
			 local2);

		len = strlcat(str_buf, bgp_community2alias(lcsb), str_buf_sz);
		assert((unsigned int)len < str_buf_sz);

		if (make_json) {
			json_string = json_object_new_string(lcsb);
			json_object_array_add(json_lcommunity_list,
					      json_string);
		}
	}

	if (make_json) {
		json_object_string_add(lcom->json, "string", str_buf);
		json_object_object_add(lcom->json, "list",
				       json_lcommunity_list);
	}

	lcom->str = str_buf;
}

/* Intern Large Communities Attribute.  */
struct lcommunity *lcommunity_intern(struct lcommunity *lcom)
{
	struct lcommunity *find;

	assert(lcom->refcnt == 0);

	find = (struct lcommunity *)hash_get(lcomhash, lcom, hash_alloc_intern);

	if (find != lcom)
		lcommunity_free(&lcom);

	find->refcnt++;

	if (!find->str)
		set_lcommunity_string(find, false);

	return find;
}

/* Unintern Large Communities Attribute.  */
void lcommunity_unintern(struct lcommunity **lcom)
{
	struct lcommunity *ret;

	if ((*lcom)->refcnt)
		(*lcom)->refcnt--;

	/* Pull off from hash.  */
	if ((*lcom)->refcnt == 0) {
		/* Large community must be in the hash.  */
		ret = (struct lcommunity *)hash_release(lcomhash, *lcom);
		assert(ret != NULL);

		lcommunity_free(lcom);
	}
}

/* Retrun string representation of communities attribute. */
char *lcommunity_str(struct lcommunity *lcom, bool make_json)
{
	if (!lcom)
		return NULL;

	if (make_json && !lcom->json && lcom->str)
		XFREE(MTYPE_LCOMMUNITY_STR, lcom->str);

	if (!lcom->str)
		set_lcommunity_string(lcom, make_json);

	return lcom->str;
}

/* Utility function to make hash key.  */
unsigned int lcommunity_hash_make(const void *arg)
{
	const struct lcommunity *lcom = arg;
	int size = lcom_length(lcom);

	return jhash(lcom->val, size, 0xab125423);
}

/* Compare two Large Communities Attribute structure.  */
bool lcommunity_cmp(const void *arg1, const void *arg2)
{
	const struct lcommunity *lcom1 = arg1;
	const struct lcommunity *lcom2 = arg2;

	if (lcom1 == NULL && lcom2 == NULL)
		return true;

	if (lcom1 == NULL || lcom2 == NULL)
		return false;

	return (lcom1->size == lcom2->size
		&& memcmp(lcom1->val, lcom2->val, lcom_length(lcom1)) == 0);
}

/* Return communities hash.  */
struct hash *lcommunity_hash(void)
{
	return lcomhash;
}

/* Initialize Large Comminities related hash. */
void lcommunity_init(void)
{
	lcomhash = hash_create(lcommunity_hash_make, lcommunity_cmp,
			       "BGP lcommunity hash");
}

void lcommunity_finish(void)
{
	hash_clean(lcomhash, (void (*)(void *))lcommunity_hash_free);
	hash_free(lcomhash);
	lcomhash = NULL;
}

/* Get next Large Communities token from the string.
 * Assumes str is space-delimeted and describes 0 or more
 * valid large communities
 */
static const char *lcommunity_gettoken(const char *str,
				       struct lcommunity_val *lval)
{
	const char *p = str;

	/* Skip white space. */
	while (isspace((unsigned char)*p)) {
		p++;
		str++;
	}

	/* Check the end of the line. */
	if (*p == '\0')
		return NULL;

	/* Community value. */
	int separator = 0;
	int digit = 0;
	uint32_t globaladmin = 0;
	uint32_t localdata1 = 0;
	uint32_t localdata2 = 0;

	while (*p && *p != ' ') {
		/* large community valid chars */
		assert(isdigit((unsigned char)*p) || *p == ':');

		if (*p == ':') {
			separator++;
			digit = 0;
			if (separator == 1) {
				globaladmin = localdata2;
			} else {
				localdata1 = localdata2;
			}
			localdata2 = 0;
		} else {
			digit = 1;
			/* left shift the accumulated value and add current
			 * digit
			 */
			localdata2 *= 10;
			localdata2 += (*p - '0');
		}
		p++;
	}

	/* Assert str was a valid large community */
	assert(separator == 2 && digit == 1);

	/*
	 * Copy the large comm.
	 */
	lval->val[0] = (globaladmin >> 24) & 0xff;
	lval->val[1] = (globaladmin >> 16) & 0xff;
	lval->val[2] = (globaladmin >> 8) & 0xff;
	lval->val[3] = globaladmin & 0xff;
	lval->val[4] = (localdata1 >> 24) & 0xff;
	lval->val[5] = (localdata1 >> 16) & 0xff;
	lval->val[6] = (localdata1 >> 8) & 0xff;
	lval->val[7] = localdata1 & 0xff;
	lval->val[8] = (localdata2 >> 24) & 0xff;
	lval->val[9] = (localdata2 >> 16) & 0xff;
	lval->val[10] = (localdata2 >> 8) & 0xff;
	lval->val[11] = localdata2 & 0xff;

	return p;
}

/*
  Convert string to large community attribute.
  When type is already known, please specify both str and type.

  When string includes keyword for each large community value.
  Please specify keyword_included as non-zero value.
*/
struct lcommunity *lcommunity_str2com(const char *str)
{
	struct lcommunity *lcom = NULL;
	struct lcommunity_val lval;

	if (!lcommunity_list_valid(str, LARGE_COMMUNITY_LIST_STANDARD))
		return NULL;

	do {
		str = lcommunity_gettoken(str, &lval);
		if (lcom == NULL)
			lcom = lcommunity_new();
		lcommunity_add_val(lcom, &lval);
	} while (str);

	return lcom;
}

bool lcommunity_include(struct lcommunity *lcom, uint8_t *ptr)
{
	int i;
	uint8_t *lcom_ptr;

	for (i = 0; i < lcom->size; i++) {
		lcom_ptr = lcom->val + (i * LCOMMUNITY_SIZE);
		if (memcmp(ptr, lcom_ptr, LCOMMUNITY_SIZE) == 0)
			return true;
	}
	return false;
}

bool lcommunity_match(const struct lcommunity *lcom1,
		      const struct lcommunity *lcom2)
{
	int i = 0;
	int j = 0;

	if (lcom1 == NULL && lcom2 == NULL)
		return true;

	if (lcom1 == NULL || lcom2 == NULL)
		return false;

	if (lcom1->size < lcom2->size)
		return false;

	/* Every community on com2 needs to be on com1 for this to match */
	while (i < lcom1->size && j < lcom2->size) {
		if (memcmp(lcom1->val + (i * LCOMMUNITY_SIZE),
			   lcom2->val + (j * LCOMMUNITY_SIZE), LCOMMUNITY_SIZE)
		    == 0)
			j++;
		i++;
	}

	if (j == lcom2->size)
		return true;
	else
		return false;
}

/* Delete one lcommunity. */
void lcommunity_del_val(struct lcommunity *lcom, uint8_t *ptr)
{
	int i = 0;
	int c = 0;

	if (!lcom->val)
		return;

	while (i < lcom->size) {
		if (memcmp(lcom->val + i * LCOMMUNITY_SIZE, ptr,
			   LCOMMUNITY_SIZE)
		    == 0) {
			c = lcom->size - i - 1;

			if (c > 0)
				memmove(lcom->val + i * LCOMMUNITY_SIZE,
					lcom->val + (i + 1) * LCOMMUNITY_SIZE,
					c * LCOMMUNITY_SIZE);

			lcom->size--;

			if (lcom->size > 0)
				lcom->val =
					XREALLOC(MTYPE_LCOMMUNITY_VAL,
						 lcom->val, lcom_length(lcom));
			else {
				XFREE(MTYPE_LCOMMUNITY_VAL, lcom->val);
			}
			return;
		}
		i++;
	}
}

static struct lcommunity *bgp_aggr_lcommunity_lookup(
						struct bgp_aggregate *aggregate,
						struct lcommunity *lcommunity)
{
	return hash_lookup(aggregate->lcommunity_hash, lcommunity);
}

static void *bgp_aggr_lcommunty_hash_alloc(void *p)
{
	struct lcommunity *ref = (struct lcommunity *)p;
	struct lcommunity *lcommunity = NULL;

	lcommunity = lcommunity_dup(ref);
	return lcommunity;
}

static void bgp_aggr_lcommunity_prepare(struct hash_bucket *hb, void *arg)
{
	struct lcommunity *hb_lcommunity = hb->data;
	struct lcommunity **aggr_lcommunity = arg;

	if (*aggr_lcommunity)
		*aggr_lcommunity = lcommunity_merge(*aggr_lcommunity,
						    hb_lcommunity);
	else
		*aggr_lcommunity = lcommunity_dup(hb_lcommunity);
}

void bgp_aggr_lcommunity_remove(void *arg)
{
	struct lcommunity *lcommunity = arg;

	lcommunity_free(&lcommunity);
}

void bgp_compute_aggregate_lcommunity(struct bgp_aggregate *aggregate,
				      struct lcommunity *lcommunity)
{

	bgp_compute_aggregate_lcommunity_hash(aggregate, lcommunity);
	bgp_compute_aggregate_lcommunity_val(aggregate);
}

void bgp_compute_aggregate_lcommunity_hash(struct bgp_aggregate *aggregate,
					   struct lcommunity *lcommunity)
{

	struct lcommunity *aggr_lcommunity = NULL;

	if ((aggregate == NULL) || (lcommunity == NULL))
		return;

	/* Create hash if not already created.
	 */
	if (aggregate->lcommunity_hash == NULL)
		aggregate->lcommunity_hash = hash_create(
					lcommunity_hash_make, lcommunity_cmp,
					"BGP Aggregator lcommunity hash");

	aggr_lcommunity = bgp_aggr_lcommunity_lookup(aggregate, lcommunity);
	if (aggr_lcommunity == NULL) {
		/* Insert lcommunity into hash.
		 */
		aggr_lcommunity = hash_get(aggregate->lcommunity_hash,
					   lcommunity,
					   bgp_aggr_lcommunty_hash_alloc);
	}

	/* Increment reference counter.
	 */
	aggr_lcommunity->refcnt++;
}

void bgp_compute_aggregate_lcommunity_val(struct bgp_aggregate *aggregate)
{
	struct lcommunity *lcommerge = NULL;

	if (aggregate == NULL)
		return;

	/* Re-compute aggregate's lcommunity.
	 */
	if (aggregate->lcommunity)
		lcommunity_free(&aggregate->lcommunity);
	if (aggregate->lcommunity_hash &&
	    aggregate->lcommunity_hash->count) {
		hash_iterate(aggregate->lcommunity_hash,
			     bgp_aggr_lcommunity_prepare,
			     &aggregate->lcommunity);
		lcommerge = aggregate->lcommunity;
		aggregate->lcommunity = lcommunity_uniq_sort(lcommerge);
		if (lcommerge)
			lcommunity_free(&lcommerge);
	}
}

void bgp_remove_lcommunity_from_aggregate(struct bgp_aggregate *aggregate,
					  struct lcommunity *lcommunity)
{
	struct lcommunity *aggr_lcommunity = NULL;
	struct lcommunity *ret_lcomm = NULL;

	if ((!aggregate)
	    || (!aggregate->lcommunity_hash)
	    || (!lcommunity))
		return;

	/* Look-up the lcommunity in the hash.
	 */
	aggr_lcommunity = bgp_aggr_lcommunity_lookup(aggregate, lcommunity);
	if (aggr_lcommunity) {
		aggr_lcommunity->refcnt--;

		if (aggr_lcommunity->refcnt == 0) {
			ret_lcomm = hash_release(aggregate->lcommunity_hash,
						 aggr_lcommunity);
			lcommunity_free(&ret_lcomm);

			bgp_compute_aggregate_lcommunity_val(aggregate);

		}
	}
}

void bgp_remove_lcomm_from_aggregate_hash(struct bgp_aggregate *aggregate,
					  struct lcommunity *lcommunity)
{
	struct lcommunity *aggr_lcommunity = NULL;
	struct lcommunity *ret_lcomm = NULL;

	if ((!aggregate)
	    || (!aggregate->lcommunity_hash)
	    || (!lcommunity))
		return;

	/* Look-up the lcommunity in the hash.
	 */
	aggr_lcommunity = bgp_aggr_lcommunity_lookup(aggregate, lcommunity);
	if (aggr_lcommunity) {
		aggr_lcommunity->refcnt--;

		if (aggr_lcommunity->refcnt == 0) {
			ret_lcomm = hash_release(aggregate->lcommunity_hash,
						 aggr_lcommunity);
			lcommunity_free(&ret_lcomm);
		}
	}
}
