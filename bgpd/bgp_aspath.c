// SPDX-License-Identifier: GPL-2.0-or-later
/* AS path management routines.
 * Copyright (C) 1996, 97, 98, 99 Kunihiro Ishiguro
 * Copyright (C) 2005 Sun Microsystems, Inc.
 */

#include <zebra.h>

#include "hash.h"
#include "memory.h"
#include "vector.h"
#include "log.h"
#include "stream.h"
#include "command.h"
#include "jhash.h"
#include "queue.h"
#include "filter.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_filter.h"

/* Attr. Flags and Attr. Type Code. */
#define AS_HEADER_SIZE 2

/* Now FOUR octets are used for AS value. */
#define AS_VALUE_SIZE         sizeof(as_t)
/* This is the old one */
#define AS16_VALUE_SIZE	      sizeof(as16_t)

/* Maximum protocol segment length value */
#define AS_SEGMENT_MAX		255

/* The following length and size macros relate specifically to Quagga's
 * internal representation of AS-Segments, not per se to the on-wire
 * sizes and lengths.  At present (200508) they sort of match, however
 * the ONLY functions which should now about the on-wire syntax are
 * aspath_put, assegment_put and assegment_parse.
 *
 * aspath_put returns bytes written, the only definitive record of
 * size of wire-format attribute..
 */

/* Calculated size in bytes of ASN segment data to hold N ASN's */
#define ASSEGMENT_DATA_SIZE(N, S)                                              \
	((N) * ((S) ? AS_VALUE_SIZE : AS16_VALUE_SIZE))

/* Calculated size of segment struct to hold N ASN's */
#define ASSEGMENT_SIZE(N,S)  (AS_HEADER_SIZE + ASSEGMENT_DATA_SIZE (N,S))

/* AS segment octet length. */
#define ASSEGMENT_LEN(X,S) ASSEGMENT_SIZE((X)->length,S)

/* AS_SEQUENCE segments can be packed together */
/* Can the types of X and Y be considered for packing? */
#define ASSEGMENT_TYPES_PACKABLE(X, Y)                                         \
	(((X)->type == (Y)->type) && ((X)->type == AS_SEQUENCE))
/* Types and length of X,Y suitable for packing? */
#define ASSEGMENTS_PACKABLE(X, Y)                                              \
	(ASSEGMENT_TYPES_PACKABLE((X), (Y))                                    \
	 && (((X)->length + (Y)->length) <= AS_SEGMENT_MAX))

/* As segment header - the on-wire representation
 * NOT the internal representation!
 */
struct assegment_header {
	uint8_t type;
	uint8_t length;
};

/* Hash for aspath.  This is the top level structure of AS path. */
static struct hash *ashash;

/* Stream for SNMP. See aspath_snmp_pathseg */
static struct stream *snmp_stream;

/* as-path orphan exclude list */
static struct as_list_list_head as_exclude_list_orphan;

/* Callers are required to initialize the memory */
static as_t *assegment_data_new(int num)
{
	return (XMALLOC(MTYPE_AS_SEG_DATA, ASSEGMENT_DATA_SIZE(num, 1)));
}

static void assegment_data_free(as_t *asdata)
{
	XFREE(MTYPE_AS_SEG_DATA, asdata);
}

const char *const aspath_segment_type_str[] = {
	"as-invalid", "as-set", "as-sequence", "as-confed-sequence",
	"as-confed-set"
};

/* Get a new segment. Note that 0 is an allowed length,
 * and will result in a segment with no allocated data segment.
 * the caller should immediately assign data to the segment, as the segment
 * otherwise is not generally valid
 */
static struct assegment *assegment_new(uint8_t type, unsigned short length)
{
	struct assegment *new;

	new = XCALLOC(MTYPE_AS_SEG, sizeof(struct assegment));

	if (length)
		new->as = assegment_data_new(length);

	new->length = length;
	new->type = type;

	return new;
}

static void assegment_free(struct assegment *seg)
{
	if (!seg)
		return;

	assegment_data_free(seg->as);
	memset(seg, 0xfe, sizeof(struct assegment));
	XFREE(MTYPE_AS_SEG, seg);

	return;
}

/* free entire chain of segments */
static void assegment_free_all(struct assegment *seg)
{
	struct assegment *prev;

	while (seg) {
		prev = seg;
		seg = seg->next;
		assegment_free(prev);
	}
}

/* Duplicate just the given assegment and its data */
static struct assegment *assegment_dup(struct assegment *seg)
{
	struct assegment *new;

	new = assegment_new(seg->type, seg->length);
	memcpy(new->as, seg->as, ASSEGMENT_DATA_SIZE(new->length, 1));

	return new;
}

/* Duplicate entire chain of assegments, return the head */
static struct assegment *assegment_dup_all(struct assegment *seg)
{
	struct assegment *new = NULL;
	struct assegment *head = NULL;

	while (seg) {
		if (head) {
			new->next = assegment_dup(seg);
			new = new->next;
		} else
			head = new = assegment_dup(seg);

		seg = seg->next;
	}
	return head;
}

/* prepend the as number to given segment, given num of times */
static struct assegment *assegment_prepend_asns(struct assegment *seg,
						as_t asnum, int num)
{
	as_t *newas;
	int i;

	if (!num)
		return seg;

	if (num >= AS_SEGMENT_MAX)
		return seg; /* we don't do huge prepends */

	newas = assegment_data_new(seg->length + num);
	if (newas == NULL)
		return seg;

	for (i = 0; i < num; i++)
		newas[i] = asnum;

	memcpy(newas + num, seg->as, ASSEGMENT_DATA_SIZE(seg->length, 1));
	assegment_data_free(seg->as);
	seg->as = newas;
	seg->length += num;

	return seg;
}

/* append given array of as numbers to the segment */
static struct assegment *assegment_append_asns(struct assegment *seg,
					       as_t *asnos, int num)
{
	as_t *newas;

	if (!seg)
		return seg;

	newas = XREALLOC(MTYPE_AS_SEG_DATA, seg->as,
			 ASSEGMENT_DATA_SIZE(seg->length + num, 1));

	seg->as = newas;
	memcpy(seg->as + seg->length, asnos,
	       ASSEGMENT_DATA_SIZE(num, 1));
	seg->length += num;
	return seg;
}

static int int_cmp(const void *p1, const void *p2)
{
	const as_t *as1 = p1;
	const as_t *as2 = p2;

	return (*as1 == *as2) ? 0 : ((*as1 > *as2) ? 1 : -1);
}

/* normalise the segment.
 * In particular, merge runs of AS_SEQUENCEs into one segment
 * Internally, we do not care about the wire segment length limit, and
 * we want each distinct AS_PATHs to have the exact same internal
 * representation - eg, so that our hashing actually works..
 */
static struct assegment *assegment_normalise(struct assegment *head)
{
	struct assegment *seg = head, *pin;
	struct assegment *tmp;

	if (!head)
		return head;

	while (seg) {
		pin = seg;

		/* Sort values SET segments, for determinism in paths to aid
		 * creation of hash values / path comparisons
		 * and because it helps other lesser implementations ;)
		 */
		if (seg->type == AS_SET || seg->type == AS_CONFED_SET) {
			int tail = 0;
			int i;

			qsort(seg->as, seg->length, sizeof(as_t), int_cmp);

			/* weed out dupes */
			for (i = 1; i < seg->length; i++) {
				if (seg->as[tail] == seg->as[i])
					continue;

				tail++;
				if (tail < i)
					seg->as[tail] = seg->as[i];
			}
			/* seg->length can be 0.. */
			if (seg->length)
				seg->length = tail + 1;
		}

		/* read ahead from the current, pinned segment while the
		 * segments
		 * are packable/mergeable. Append all following packable
		 * segments
		 * to the segment we have pinned and remove these appended
		 * segments.
		 */
		while (pin->next && ASSEGMENT_TYPES_PACKABLE(pin, pin->next)) {
			tmp = pin->next;
			seg = pin->next;

			/* append the next sequence to the pinned sequence */
			pin = assegment_append_asns(pin, seg->as, seg->length);

			/* bypass the next sequence */
			pin->next = seg->next;

			/* get rid of the now referenceless segment */
			assegment_free(tmp);
		}

		seg = pin->next;
	}
	return head;
}

static struct aspath *aspath_new(enum asnotation_mode asnotation)
{
	struct aspath *as;

	as = XCALLOC(MTYPE_AS_PATH, sizeof(struct aspath));
	as->asnotation = asnotation;
	return as;
}

/* Free AS path structure. */
void aspath_free(struct aspath *aspath)
{
	if (!aspath)
		return;
	if (aspath->segments)
		assegment_free_all(aspath->segments);
	XFREE(MTYPE_AS_STR, aspath->str);

	if (aspath->json) {
		json_object_free(aspath->json);
		aspath->json = NULL;
	}

	XFREE(MTYPE_AS_PATH, aspath);
}

/* Unintern aspath from AS path bucket. */
void aspath_unintern(struct aspath **aspath)
{
	struct aspath *ret;
	struct aspath *asp;

	if (!*aspath)
		return;

	asp = *aspath;

	if (asp->refcnt)
		asp->refcnt--;

	if (asp->refcnt == 0) {
		/* This aspath must exist in aspath hash table. */
		ret = hash_release(ashash, asp);
		assert(ret != NULL);
		aspath_free(asp);
		*aspath = NULL;
	}
}

/* Return the start or end delimiters for a particular Segment type */
#define AS_SEG_START 0
#define AS_SEG_END 1
static char aspath_delimiter_char(uint8_t type, uint8_t which)
{
	int i;
	struct {
		int type;
		char start;
		char end;
	} aspath_delim_char[] = {{AS_SET, '{', '}'},
				 {AS_CONFED_SET, '[', ']'},
				 {AS_CONFED_SEQUENCE, '(', ')'},
				 {0}};

	for (i = 0; aspath_delim_char[i].type != 0; i++) {
		if (aspath_delim_char[i].type == type) {
			if (which == AS_SEG_START)
				return aspath_delim_char[i].start;
			else if (which == AS_SEG_END)
				return aspath_delim_char[i].end;
		}
	}
	return ' ';
}

/* countup asns from this segment and index onward */
static int assegment_count_asns(struct assegment *seg, int from)
{
	int count = 0;
	while (seg) {
		if (!from)
			count += seg->length;
		else {
			count += (seg->length - from);
			from = 0;
		}
		seg = seg->next;
	}
	return count;
}

unsigned int aspath_count_confeds(struct aspath *aspath)
{
	int count = 0;
	struct assegment *seg = aspath->segments;

	while (seg) {
		if (seg->type == AS_CONFED_SEQUENCE)
			count += seg->length;
		else if (seg->type == AS_CONFED_SET)
			count++;

		seg = seg->next;
	}
	return count;
}

unsigned int aspath_count_hops(const struct aspath *aspath)
{
	int count = 0;
	struct assegment *seg = aspath->segments;

	while (seg) {
		if (seg->type == AS_SEQUENCE)
			count += seg->length;
		else if (seg->type == AS_SET)
			count++;

		seg = seg->next;
	}
	return count;
}

/* Check if aspath has AS_SET or AS_CONFED_SET */
bool aspath_check_as_sets(struct aspath *aspath)
{
	struct assegment *seg = aspath->segments;

	while (seg) {
		if (seg->type == AS_SET || seg->type == AS_CONFED_SET)
			return true;
		seg = seg->next;
	}
	return false;
}

/* Check if aspath has BGP_AS_ZERO */
bool aspath_check_as_zero(struct aspath *aspath)
{
	struct assegment *seg = aspath->segments;
	unsigned int i;

	while (seg) {
		for (i = 0; i < seg->length; i++)
			if (seg->as[i] == BGP_AS_ZERO)
				return true;
		seg = seg->next;
	}

	return false;
}

/* Estimate size aspath /might/ take if encoded into an
 * ASPATH attribute.
 *
 * This is a quick estimate, not definitive! aspath_put()
 * may return a different number!!
 */
unsigned int aspath_size(struct aspath *aspath)
{
	int size = 0;
	struct assegment *seg = aspath->segments;

	while (seg) {
		size += ASSEGMENT_SIZE(seg->length, 1);
		seg = seg->next;
	}
	return size;
}

/* Return highest public ASN in path */
as_t aspath_highest(struct aspath *aspath)
{
	struct assegment *seg = aspath->segments;
	as_t highest = 0;
	unsigned int i;

	while (seg) {
		for (i = 0; i < seg->length; i++)
			if (seg->as[i] > highest
			    && !BGP_AS_IS_PRIVATE(seg->as[i]))
				highest = seg->as[i];
		seg = seg->next;
	}
	return highest;
}

/* Return the left-most ASN in path */
as_t aspath_leftmost(struct aspath *aspath)
{
	struct assegment *seg = aspath->segments;
	as_t leftmost = 0;

	if (seg && seg->length && seg->type == AS_SEQUENCE)
		leftmost = seg->as[0];

	return leftmost;
}

/* Return 1 if there are any 4-byte ASes in the path */
bool aspath_has_as4(struct aspath *aspath)
{
	struct assegment *seg = aspath->segments;
	unsigned int i;

	while (seg) {
		for (i = 0; i < seg->length; i++)
			if (seg->as[i] > BGP_AS_MAX)
				return true;
		seg = seg->next;
	}
	return false;
}

/* Convert aspath structure to string expression. */
static void aspath_make_str_count(struct aspath *as, bool make_json)
{
	struct assegment *seg;
	int str_size;
	int len = 0;
	char *str_buf;
	json_object *jaspath_segments = NULL;
	json_object *jseg = NULL;
	json_object *jseg_list = NULL;

	if (make_json) {
		as->json = json_object_new_object();
		jaspath_segments = json_object_new_array();
	}

	/* Empty aspath. */
	if (!as->segments) {
		if (make_json) {
			json_object_string_add(as->json, "string", "Local");
			json_object_object_add(as->json, "segments",
					       jaspath_segments);
			json_object_int_add(as->json, "length", 0);
		}
		as->str = XMALLOC(MTYPE_AS_STR, 1);
		as->str[0] = '\0';
		as->str_len = 0;
		return;
	}

	seg = as->segments;

/* ASN takes 5 to 10 chars plus separator, see below.
 * If there is one differing segment type, we need an additional
 * 2 chars for segment delimiters, and the final '\0'.
 * Hopefully this is large enough to avoid hitting the realloc
 * code below for most common sequences.
 *
 * This was changed to 10 after the well-known BGP assertion, which
 * had hit some parts of the Internet in May of 2009.
 * plain format : '4294967295 ' : 10 + 1
 * astod format : '65535.65535 ': 11 + 1
 */
#define ASN_STR_LEN (11 + 1)
	str_size = MAX(assegment_count_asns(seg, 0) * ASN_STR_LEN + 2 + 1,
		       ASPATH_STR_DEFAULT_LEN);
	str_buf = XMALLOC(MTYPE_AS_STR, str_size);

	while (seg) {
		int i;
		char separator;

		/* Check AS type validity. Set separator for segment */
		switch (seg->type) {
		case AS_SET:
		case AS_CONFED_SET:
			separator = ',';
			break;
		case AS_SEQUENCE:
		case AS_CONFED_SEQUENCE:
			separator = ' ';
			break;
		default:
			XFREE(MTYPE_AS_STR, str_buf);
			as->str = NULL;
			as->str_len = 0;
			json_object_free(as->json);
			as->json = NULL;

			return;
		}

/* We might need to increase str_buf, particularly if path has
 * differing segments types, our initial guesstimate above will
 * have been wrong. Need 11 chars for ASN, a separator each and
 * potentially two segment delimiters, plus a space between each
 * segment and trailing zero.
 *
 * This definitely didn't work with the value of 5 bytes and
 * 32-bit ASNs.
 */
#define SEGMENT_STR_LEN(X) (((X)->length * ASN_STR_LEN) + 2 + 1 + 1)
		if ((len + SEGMENT_STR_LEN(seg)) > str_size) {
			str_size = len + SEGMENT_STR_LEN(seg);
			str_buf = XREALLOC(MTYPE_AS_STR, str_buf, str_size);
		}
#undef ASN_STR_LEN
#undef SEGMENT_STR_LEN

		if (seg->type != AS_SEQUENCE)
			len += snprintf(
				str_buf + len, str_size - len, "%c",
				aspath_delimiter_char(seg->type, AS_SEG_START));

		if (make_json)
			jseg_list = json_object_new_array();

		/* write out the ASNs, with their separators, bar the last one*/
		for (i = 0; i < seg->length; i++) {
			if (make_json)
				asn_asn2json_array(jseg_list, seg->as[i],
						   as->asnotation);
			len += snprintfrr(str_buf + len, str_size - len,
					  ASN_FORMAT(as->asnotation),
					  &seg->as[i]);

			if (i < (seg->length - 1))
				len += snprintf(str_buf + len, str_size - len,
						"%c", separator);
		}

		if (make_json) {
			jseg = json_object_new_object();
			json_object_string_add(
				jseg, "type",
				aspath_segment_type_str[seg->type]);
			json_object_object_add(jseg, "list", jseg_list);
			json_object_array_add(jaspath_segments, jseg);
		}

		if (seg->type != AS_SEQUENCE)
			len += snprintf(
				str_buf + len, str_size - len, "%c",
				aspath_delimiter_char(seg->type, AS_SEG_END));
		if (seg->next)
			len += snprintf(str_buf + len, str_size - len, " ");

		seg = seg->next;
	}

	assert(len < str_size);

	str_buf[len] = '\0';
	as->str = str_buf;
	as->str_len = len;

	if (make_json) {
		json_object_string_add(as->json, "string", str_buf);
		json_object_object_add(as->json, "segments", jaspath_segments);
		json_object_int_add(as->json, "length", aspath_count_hops(as));
	}

	return;
}

void aspath_str_update(struct aspath *as, bool make_json)
{
	XFREE(MTYPE_AS_STR, as->str);

	if (as->json) {
		json_object_free(as->json);
		as->json = NULL;
	}

	aspath_make_str_count(as, make_json);
}

/* Intern allocated AS path. */
struct aspath *aspath_intern(struct aspath *aspath)
{
	struct aspath *find;

	/* Assert this AS path structure is not interned and has the string
	   representation built. */
	assert(aspath->refcnt == 0);
	assert(aspath->str);

	/* Check AS path hash. */
	find = hash_get(ashash, aspath, hash_alloc_intern);
	if (find != aspath)
		aspath_free(aspath);

	find->refcnt++;

	return find;
}

/* Duplicate aspath structure.  Created same aspath structure but
   reference count and AS path string is cleared. */
struct aspath *aspath_dup(struct aspath *aspath)
{
	unsigned short buflen = aspath->str_len + 1;
	struct aspath *new;

	new = XCALLOC(MTYPE_AS_PATH, sizeof(struct aspath));
	new->json = NULL;

	if (aspath->segments)
		new->segments = assegment_dup_all(aspath->segments);

	if (!aspath->str)
		return new;

	new->str = XMALLOC(MTYPE_AS_STR, buflen);
	new->str_len = aspath->str_len;
	new->asnotation = aspath->asnotation;

	/* copy the string data */
	if (aspath->str_len > 0)
		memcpy(new->str, aspath->str, buflen);
	else
		new->str[0] = '\0';

	return new;
}

static void *aspath_hash_alloc(void *arg)
{
	const struct aspath *aspath = arg;
	struct aspath *new;

	/* Malformed AS path value. */
	assert(aspath->str);

	/* New aspath structure is needed. */
	new = XMALLOC(MTYPE_AS_PATH, sizeof(struct aspath));

	/* Reuse segments and string representation */
	new->refcnt = 0;
	new->segments = aspath->segments;
	new->str = aspath->str;
	new->str_len = aspath->str_len;
	new->json = aspath->json;
	new->asnotation = aspath->asnotation;

	return new;
}

/* parse as-segment byte stream in struct assegment */
static int assegments_parse(struct stream *s, size_t length,
			    struct assegment **result, int use32bit)
{
	struct assegment_header segh;
	struct assegment *seg, *prev = NULL, *head = NULL;
	size_t bytes = 0;

	/* empty aspath (ie iBGP or somesuch) */
	if (length == 0)
		return 0;

	if (BGP_DEBUG(as4, AS4_SEGMENT))
		zlog_debug(
			"[AS4SEG] Parse aspath segment: got total byte length %lu",
			(unsigned long)length);
	/* basic checks */
	if ((STREAM_READABLE(s) < length)
	    || (STREAM_READABLE(s) < AS_HEADER_SIZE)
	    || (length % AS16_VALUE_SIZE))
		return -1;

	while (bytes < length) {
		int i;
		size_t seg_size;

		if ((length - bytes) <= AS_HEADER_SIZE) {
			if (head)
				assegment_free_all(head);
			return -1;
		}

		/* softly softly, get the header first on its own */
		segh.type = stream_getc(s);
		segh.length = stream_getc(s);

		seg_size = ASSEGMENT_SIZE(segh.length, use32bit);

		if (BGP_DEBUG(as4, AS4_SEGMENT))
			zlog_debug(
				"[AS4SEG] Parse aspath segment: got type %d, length %d",
				segh.type, segh.length);

		/* check it.. */
		if (((bytes + seg_size) > length)
		    /* 1771bis 4.3b: seg length contains one or more */
		    || (segh.length == 0)
		    /* Paranoia in case someone changes type of segment length.
		     * Shift both values by 0x10 to make the comparison operate
		     * on more, than 8 bits (otherwise it's a warning, bug
		     * #564).
		     */
		    || ((sizeof(segh.length) > 1)
			&& (0x10 + segh.length > 0x10 + AS_SEGMENT_MAX))) {
			if (head)
				assegment_free_all(head);
			return -1;
		}

		switch (segh.type) {
		case AS_SEQUENCE:
		case AS_SET:
		case AS_CONFED_SEQUENCE:
		case AS_CONFED_SET:
			break;
		default:
			if (head)
				assegment_free_all(head);
			return -1;
		}

		/* now its safe to trust lengths */
		seg = assegment_new(segh.type, segh.length);

		if (head)
			prev->next = seg;
		else /* it's the first segment */
			head = seg;

		for (i = 0; i < segh.length; i++)
			seg->as[i] =
				(use32bit) ? stream_getl(s) : stream_getw(s);

		bytes += seg_size;

		if (BGP_DEBUG(as4, AS4_SEGMENT))
			zlog_debug(
				"[AS4SEG] Parse aspath segment: Bytes now: %lu",
				(unsigned long)bytes);

		prev = seg;
	}

	*result = assegment_normalise(head);
	return 0;
}

/* AS path parse function.  pnt is a pointer to byte stream and length
   is length of byte stream.  If there is same AS path in the the AS
   path hash then return it else make new AS path structure.

   On error NULL is returned.
 */
struct aspath *aspath_parse(struct stream *s, size_t length, int use32bit,
			    enum asnotation_mode asnotation)
{
	struct aspath as;
	struct aspath *find;

	/* If length is odd it's malformed AS path. */
	/* Nit-picking: if (use32bit == 0) it is malformed if odd,
	 * otherwise its malformed when length is larger than 2 and (length-2)
	 * is not dividable by 4.
	 * But... this time we're lazy
	 */
	if (length % AS16_VALUE_SIZE)
		return NULL;

	memset(&as, 0, sizeof(as));
	as.asnotation = asnotation;
	if (assegments_parse(s, length, &as.segments, use32bit) < 0)
		return NULL;

	/* If already same aspath exist then return it. */
	find = hash_get(ashash, &as, aspath_hash_alloc);

	/* if the aspath was already hashed free temporary memory. */
	if (find->refcnt) {
		assegment_free_all(as.segments);
		/* aspath_key_make() always updates the string */
		XFREE(MTYPE_AS_STR, as.str);
		if (as.json) {
			json_object_free(as.json);
			as.json = NULL;
		}
	}

	find->refcnt++;

	return find;
}

static void assegment_data_put(struct stream *s, as_t *as, int num,
			       int use32bit)
{
	int i;
	assert(num <= AS_SEGMENT_MAX);

	for (i = 0; i < num; i++)
		if (use32bit)
			stream_putl(s, as[i]);
		else {
			if (as[i] <= BGP_AS_MAX)
				stream_putw(s, as[i]);
			else
				stream_putw(s, BGP_AS_TRANS);
		}
}

static size_t assegment_header_put(struct stream *s, uint8_t type, int length)
{
	size_t lenp;
	assert(length <= AS_SEGMENT_MAX);
	stream_putc(s, type);
	lenp = stream_get_endp(s);
	stream_putc(s, length);
	return lenp;
}

/* write aspath data to stream */
size_t aspath_put(struct stream *s, struct aspath *as, int use32bit)
{
	struct assegment *seg = as->segments;
	size_t bytes = 0;

	if (!seg || seg->length == 0)
		return 0;

	/*
	 * Hey, what do we do when we have > STREAM_WRITABLE(s) here?
	 * At the moment, we would write out a partial aspath, and our
	 * peer
	 * will complain and drop the session :-/
	 *
	 * The general assumption here is that many things tested will
	 * never happen.  And, in real live, up to now, they have not.
	 */
	while (seg && (ASSEGMENT_LEN(seg, use32bit) <= STREAM_WRITEABLE(s))) {
		struct assegment *next = seg->next;
		int written = 0;
		int asns_packed = 0;
		size_t lenp;

		/* Overlength segments have to be split up */
		while ((seg->length - written) > AS_SEGMENT_MAX) {
			assegment_header_put(s, seg->type, AS_SEGMENT_MAX);
			assegment_data_put(s, (seg->as + written),
					   AS_SEGMENT_MAX, use32bit);
			written += AS_SEGMENT_MAX;
			bytes += ASSEGMENT_SIZE(AS_SEGMENT_MAX, use32bit);
		}

		/* write the final segment, probably is also the first
		 */
		lenp = assegment_header_put(s, seg->type,
					    seg->length - written);
		assegment_data_put(s, (seg->as + written),
				   seg->length - written, use32bit);

		/* Sequence-type segments can be 'packed' together
		 * Case of a segment which was overlength and split up
		 * will be missed here, but that doesn't matter.
		 */
		while (next && ASSEGMENTS_PACKABLE(seg, next)) {
			/* NB: We should never normally get here given
			 * we
			 * normalise aspath data when parse them.
			 * However, better
			 * safe than sorry. We potentially could call
			 * assegment_normalise here instead, but it's
			 * cheaper and
			 * easier to do it on the fly here rather than
			 * go through
			 * the segment list twice every time we write
			 * out
			 * aspath's.
			 */

			/* Next segment's data can fit in this one */
			assegment_data_put(s, next->as, next->length, use32bit);

			/* update the length of the segment header */
			stream_putc_at(s, lenp,
				       seg->length - written + next->length);
			asns_packed += next->length;

			next = next->next;
		}

		bytes += ASSEGMENT_SIZE(seg->length - written + asns_packed,
					use32bit);
		seg = next;
	}
	return bytes;
}

/* This is for SNMP BGP4PATHATTRASPATHSEGMENT
 * We have no way to manage the storage, so we use a static stream
 * wrapper around aspath_put.
 */
uint8_t *aspath_snmp_pathseg(struct aspath *as, size_t *varlen)
{
#define SNMP_PATHSEG_MAX 1024

	if (!snmp_stream)
		snmp_stream = stream_new(SNMP_PATHSEG_MAX);
	else
		stream_reset(snmp_stream);

	if (!as) {
		*varlen = 0;
		return NULL;
	}
	aspath_put(snmp_stream, as, 0); /* use 16 bit for now here */

	*varlen = stream_get_endp(snmp_stream);
	return stream_pnt(snmp_stream);
}

static struct assegment *aspath_aggregate_as_set_add(struct aspath *aspath,
						     struct assegment *asset,
						     as_t as)
{
	int i;

	/* If this is first AS set member, create new as-set segment. */
	if (asset == NULL) {
		asset = assegment_new(AS_SET, 1);
		if (!aspath->segments)
			aspath->segments = asset;
		else {
			struct assegment *seg = aspath->segments;
			while (seg->next)
				seg = seg->next;
			seg->next = asset;
		}
		asset->as[0] = as;
	} else {
		/* Check this AS value already exists or not. */
		for (i = 0; i < asset->length; i++)
			if (asset->as[i] == as)
				return asset;

		asset->length++;
		asset->as = XREALLOC(MTYPE_AS_SEG_DATA, asset->as,
				     asset->length * AS_VALUE_SIZE);
		asset->as[asset->length - 1] = as;
	}


	return asset;
}

/* Modify as1 using as2 for aggregation. */
struct aspath *aspath_aggregate(struct aspath *as1, struct aspath *as2)
{
	int i;
	int minlen = 0;
	int match = 0;
	int from;
	struct assegment *seg1 = as1->segments;
	struct assegment *seg2 = as2->segments;
	struct aspath *aspath = NULL;
	struct assegment *asset = NULL;
	struct assegment *prevseg = NULL;

	/* First of all check common leading sequence. */
	while (seg1 && seg2) {
		/* Check segment type. */
		if (seg1->type != seg2->type)
			break;

		/* Minimum segment length. */
		minlen = MIN(seg1->length, seg2->length);

		for (match = 0; match < minlen; match++)
			if (seg1->as[match] != seg2->as[match])
				break;

		if (match) {
			struct assegment *seg = assegment_new(seg1->type, 0);

			seg = assegment_append_asns(seg, seg1->as, match);

			if (!aspath) {
				aspath = aspath_new(as1->asnotation);
				aspath->segments = seg;
			} else
				prevseg->next = seg;

			prevseg = seg;
		}

		if (match != minlen || match != seg1->length
		    || seg1->length != seg2->length)
			break;
		/* We are moving on to the next segment to reset match */
		else
			match = 0;

		seg1 = seg1->next;
		seg2 = seg2->next;
	}

	if (!aspath)
		aspath = aspath_new(as1->asnotation);

	/* Make as-set using rest of all information. */
	from = match;
	while (seg1) {
		for (i = from; i < seg1->length; i++)
			asset = aspath_aggregate_as_set_add(aspath, asset,
							    seg1->as[i]);

		from = 0;
		seg1 = seg1->next;
	}

	from = match;
	while (seg2) {
		for (i = from; i < seg2->length; i++)
			asset = aspath_aggregate_as_set_add(aspath, asset,
							    seg2->as[i]);

		from = 0;
		seg2 = seg2->next;
	}

	assegment_normalise(aspath->segments);
	aspath_str_update(aspath, false);
	return aspath;
}

/* When a BGP router receives an UPDATE with an MP_REACH_NLRI
   attribute, check the leftmost AS number in the AS_PATH attribute is
   or not the peer's AS number. */
bool aspath_firstas_check(struct aspath *aspath, as_t asno)
{
	if ((aspath == NULL) || (aspath->segments == NULL))
		return false;

	if (aspath->segments && (aspath->segments->type == AS_SEQUENCE)
	    && (aspath->segments->as[0] == asno))
		return true;

	return false;
}

unsigned int aspath_get_first_as(struct aspath *aspath)
{
	if (aspath == NULL || aspath->segments == NULL)
		return 0;

	return aspath->segments->as[0];
}

unsigned int aspath_get_last_as(struct aspath *aspath)
{
	int i;
	unsigned int last_as = 0;
	const struct assegment *seg;

	if (aspath == NULL || aspath->segments == NULL)
		return last_as;

	seg = aspath->segments;

	while (seg) {
		if (seg->type == AS_SEQUENCE || seg->type == AS_CONFED_SEQUENCE)
			for (i = 0; i < seg->length; i++)
				last_as = seg->as[i];
		seg = seg->next;
	}

	return last_as;
}

/* AS path loop check.  If aspath contains asno then return >= 1. */
int aspath_loop_check(struct aspath *aspath, as_t asno)
{
	struct assegment *seg;
	int count = 0;

	if ((aspath == NULL) || (aspath->segments == NULL))
		return 0;

	seg = aspath->segments;

	while (seg) {
		int i;

		for (i = 0; i < seg->length; i++)
			if (seg->as[i] == asno)
				count++;

		seg = seg->next;
	}
	return count;
}

/* AS path loop check.  If aspath contains asno
 * that is a confed id then return >= 1.
 */
int aspath_loop_check_confed(struct aspath *aspath, as_t asno)
{
	struct assegment *seg;
	int count = 0;

	if (aspath == NULL || aspath->segments == NULL)
		return 0;

	seg = aspath->segments;

	while (seg) {
		unsigned int i;

		for (i = 0; i < seg->length; i++)
			if (seg->type != AS_CONFED_SEQUENCE &&
			    seg->type != AS_CONFED_SET && seg->as[i] == asno)
				count++;

		seg = seg->next;
	}
	return count;
}


/* When all of AS path is private AS return 1.  */
bool aspath_private_as_check(struct aspath *aspath)
{
	struct assegment *seg;

	if (!(aspath && aspath->segments))
		return false;

	seg = aspath->segments;

	while (seg) {
		int i;

		for (i = 0; i < seg->length; i++) {
			if (!BGP_AS_IS_PRIVATE(seg->as[i]))
				return false;
		}
		seg = seg->next;
	}
	return true;
}

/* Replace all ASN instances of the regex rule with our own ASN  */
struct aspath *aspath_replace_regex_asn(struct aspath *aspath,
					struct as_list *acl_list, as_t our_asn)
{
	struct aspath *new;
	struct assegment *cur_seg;
	struct as_list *cur_as_list;
	struct as_filter *cur_as_filter;
	char str_buf[ASPATH_STR_DEFAULT_LEN];
	uint32_t i;

	new = aspath_dup(aspath);
	cur_seg = new->segments;

	while (cur_seg) {
		cur_as_list = acl_list;
		while (cur_as_list) {
			cur_as_filter = cur_as_list->head;
			while (cur_as_filter) {
				for (i = 0; i < cur_seg->length; i++) {
					snprintfrr(str_buf,
						   ASPATH_STR_DEFAULT_LEN,
						   ASN_FORMAT(new->asnotation),
						   &cur_seg->as[i]);
					if (!regexec(cur_as_filter->reg,
						     str_buf, 0, NULL, 0))
						cur_seg->as[i] = our_asn;
				}
				cur_as_filter = cur_as_filter->next;
			}
			cur_as_list = cur_as_list->next;
		}
		cur_seg = cur_seg->next;
	}

	aspath_str_update(new, false);
	return new;
}


/* Replace all instances of the target ASN with our own ASN */
struct aspath *aspath_replace_specific_asn(struct aspath *aspath,
					   as_t target_asn, as_t our_asn)
{
	struct aspath *new;
	struct assegment *seg;

	new = aspath_dup(aspath);
	seg = new->segments;

	while (seg) {
		int i;

		for (i = 0; i < seg->length; i++) {
			if (seg->as[i] == target_asn)
				seg->as[i] = our_asn;
		}
		seg = seg->next;
	}

	aspath_str_update(new, false);
	return new;
}

/* Replace all ASNs with our own ASN */
struct aspath *aspath_replace_all_asn(struct aspath *aspath, as_t our_asn)
{
	struct aspath *new;
	struct assegment *seg;

	new = aspath_dup(aspath);
	seg = new->segments;

	while (seg) {
		int i;

		for (i = 0; i < seg->length; i++)
			seg->as[i] = our_asn;

		seg = seg->next;
	}

	aspath_str_update(new, false);
	return new;
}

/* Replace all private ASNs with our own ASN */
struct aspath *aspath_replace_private_asns(struct aspath *aspath, as_t asn,
					   as_t peer_asn)
{
	struct aspath *new;
	struct assegment *seg;

	new = aspath_dup(aspath);
	seg = new->segments;

	while (seg) {
		int i;

		for (i = 0; i < seg->length; i++) {
			/* Don't replace if public ASN or peer's ASN */
			if (BGP_AS_IS_PRIVATE(seg->as[i])
			    && (seg->as[i] != peer_asn))
				seg->as[i] = asn;
		}
		seg = seg->next;
	}

	aspath_str_update(new, false);
	return new;
}

/* Remove all private ASNs */
struct aspath *aspath_remove_private_asns(struct aspath *aspath, as_t peer_asn)
{
	struct aspath *new;
	struct assegment *seg;
	struct assegment *new_seg;
	struct assegment *last_new_seg;
	int i;
	int j;
	int public = 0;
	int peer = 0;

	new = XCALLOC(MTYPE_AS_PATH, sizeof(struct aspath));

	new->json = NULL;
	new_seg = NULL;
	last_new_seg = NULL;
	seg = aspath->segments;
	while (seg) {
		public = 0;
		peer = 0;
		for (i = 0; i < seg->length; i++) {
			// ASN is public
			if (!BGP_AS_IS_PRIVATE(seg->as[i]))
				public++;
			/* ASN matches peer's.
			 * Don't double-count if peer_asn is public.
			 */
			else if (seg->as[i] == peer_asn)
				peer++;
		}

		// The entire segment is public so copy it
		if (public == seg->length)
			new_seg = assegment_dup(seg);

		// The segment is a mix of public and private ASNs. Copy as many
		// spots as
		// there are public ASNs then come back and fill in only the
		// public ASNs.
		else {
			/* length needs to account for all retained ASNs
			 * (public or peer_asn), not just public
			 */
			new_seg = assegment_new(seg->type, (public + peer));
			j = 0;
			for (i = 0; i < seg->length; i++) {
				// keep ASN if public or matches peer's ASN
				if (!BGP_AS_IS_PRIVATE(seg->as[i])
				    || (seg->as[i] == peer_asn)) {
					new_seg->as[j] = seg->as[i];
					j++;
				}
			}
		}

		// This is the first segment so set the aspath segments pointer
		// to this one
		if (!last_new_seg)
			new->segments = new_seg;
		else
			last_new_seg->next = new_seg;

		last_new_seg = new_seg;
		seg = seg->next;
	}
	if (!aspath->refcnt)
		aspath_free(aspath);
	aspath_str_update(new, false);
	return new;
}

/* AS path confed check.  If aspath contains confed set or sequence then return
 * 1. */
bool aspath_confed_check(struct aspath *aspath)
{
	struct assegment *seg;

	if (!(aspath && aspath->segments))
		return false;

	seg = aspath->segments;

	while (seg) {
		if (seg->type == AS_CONFED_SET
		    || seg->type == AS_CONFED_SEQUENCE)
			return true;
		seg = seg->next;
	}
	return false;
}

/* Leftmost AS path segment confed check.  If leftmost AS segment is of type
  AS_CONFED_SEQUENCE or AS_CONFED_SET then return 1.  */
bool aspath_left_confed_check(struct aspath *aspath)
{

	if (!(aspath && aspath->segments))
		return false;

	if ((aspath->segments->type == AS_CONFED_SEQUENCE)
	    || (aspath->segments->type == AS_CONFED_SET))
		return true;

	return false;
}

/* Merge as1 to as2.  as2 should be uninterned aspath. */
static struct aspath *aspath_merge(struct aspath *as1, struct aspath *as2)
{
	struct assegment *last, *new;

	if (!as1 || !as2)
		return NULL;

	last = new = assegment_dup_all(as1->segments);

	/* find the last valid segment */
	while (last && last->next)
		last = last->next;

	if (last)
		last->next = as2->segments;
	as2->segments = new;
	aspath_str_update(as2, false);
	return as2;
}

/* Prepend as1 to as2.  as2 should be uninterned aspath. */
struct aspath *aspath_prepend(struct aspath *as1, struct aspath *as2)
{
	struct assegment *as1segtail;
	struct assegment *as2segtail;
	struct assegment *as2seghead;

	if (!as1 || !as2)
		return NULL;

	/* If as2 is empty, only need to dupe as1's chain onto as2 */
	if (as2->segments == NULL) {
		as2->segments = assegment_dup_all(as1->segments);
		aspath_str_update(as2, false);
		return as2;
	}

	/* If as1 is empty AS, no prepending to do. */
	if (as1->segments == NULL)
		return as2;

	/* find the tail as1's segment chain. */
	as1segtail = as1->segments;
	while (as1segtail && as1segtail->next)
		as1segtail = as1segtail->next;

	/* Delete any AS_CONFED_SEQUENCE segment from as2. */
	if (as1segtail->type == AS_SEQUENCE
	    && as2->segments->type == AS_CONFED_SEQUENCE)
		as2 = aspath_delete_confed_seq(as2);

	if (!as2->segments) {
		as2->segments = assegment_dup_all(as1->segments);
		aspath_str_update(as2, false);
		return as2;
	}

	/* Compare last segment type of as1 and first segment type of as2. */
	if (as1segtail->type != as2->segments->type)
		return aspath_merge(as1, as2);

	if (as1segtail->type == AS_SEQUENCE) {
		/* We have two chains of segments, as1->segments and seg2,
		 * and we have to attach them together, merging the attaching
		 * segments together into one.
		 *
		 * 1. dupe as1->segments onto head of as2
		 * 2. merge seg2's asns onto last segment of this new chain
		 * 3. attach chain after seg2
		 */

		/* save as2 head */
		as2seghead = as2->segments;

		/* dupe as1 onto as2's head */
		as2segtail = as2->segments = assegment_dup_all(as1->segments);

		/* refind the tail of as2 */
		while (as2segtail && as2segtail->next)
			as2segtail = as2segtail->next;

		/* merge the old head, seg2, into tail, seg1 */
		assegment_append_asns(as2segtail, as2seghead->as,
				      as2seghead->length);

		/*
		 * bypass the merged seg2, and attach any chain after it
		 * to chain descending from as2's head
		 */
		if (as2segtail)
			as2segtail->next = as2seghead->next;

		/* as2->segments is now referenceless and useless */
		assegment_free(as2seghead);

		/* we've now prepended as1's segment chain to as2, merging
		 * the inbetween AS_SEQUENCE of seg2 in the process
		 */
		aspath_str_update(as2, false);
		return as2;
	} else {
		/* AS_SET merge code is needed at here. */
		return aspath_merge(as1, as2);
	}
	/* XXX: Ermmm, what if as1 has multiple segments?? */

	/* Not reached */
}

/* insert aspath exclude in head of orphan exclude list*/
void as_exclude_set_orphan(struct aspath_exclude *ase)
{
	ase->exclude_aspath_acl = NULL;
	as_list_list_add_head(&as_exclude_list_orphan, ase);
}

void as_exclude_remove_orphan(struct aspath_exclude *ase)
{
	if (as_list_list_count(&as_exclude_list_orphan))
		as_list_list_del(&as_exclude_list_orphan, ase);
}

/* currently provide only one exclude, not a list */
struct aspath_exclude *as_exclude_lookup_orphan(const char *acl_name)
{
	struct aspath_exclude *ase = NULL;
	char *name = NULL;

	frr_each (as_list_list, &as_exclude_list_orphan, ase) {
		if (ase->exclude_aspath_acl_name) {
			name = ase->exclude_aspath_acl_name;
			if (!strcmp(name, acl_name))
				break;
		}
	}
	if (ase)
		as_exclude_remove_orphan(ase);

	return ase;
}

/* Iterate over AS_PATH segments and wipe all occurrences of the
 * listed AS numbers. Hence some segments may lose some or even
 * all data on the way, the operation is implemented as a smarter
 * version of aspath_dup(), which allocates memory to hold the new
 * data, not the original. The new AS path is returned.
 */
struct aspath *aspath_filter_exclude(struct aspath *source,
				     struct aspath *exclude_list)
{
	struct assegment *srcseg, *exclseg, *lastseg;
	struct aspath *newpath;

	newpath = aspath_new(source->asnotation);
	lastseg = NULL;

	for (srcseg = source->segments; srcseg; srcseg = srcseg->next) {
		unsigned i, y, newlen = 0, done = 0, skip_as;
		struct assegment *newseg;

		/* Find out, how much ASns are we going to pick from this
		 * segment.
		 * We can't perform filtering right inline, because the size of
		 * the new segment isn't known at the moment yet.
		 */
		for (i = 0; i < srcseg->length; i++) {
			skip_as = 0;
			for (exclseg = exclude_list->segments;
			     exclseg && !skip_as; exclseg = exclseg->next)
				for (y = 0; y < exclseg->length; y++)
					if (srcseg->as[i] == exclseg->as[y]) {
						skip_as = 1;
						// There's no sense in testing
						// the rest of exclusion list,
						// bail out.
						break;
					}
			if (!skip_as)
				newlen++;
		}
		/* newlen is now the number of ASns to copy */
		if (!newlen)
			continue;

		/* Actual copying. Allocate memory and iterate once more,
		 * performing filtering. */
		newseg = assegment_new(srcseg->type, newlen);
		for (i = 0; i < srcseg->length; i++) {
			skip_as = 0;
			for (exclseg = exclude_list->segments;
			     exclseg && !skip_as; exclseg = exclseg->next)
				for (y = 0; y < exclseg->length; y++)
					if (srcseg->as[i] == exclseg->as[y]) {
						skip_as = 1;
						break;
					}
			if (skip_as)
				continue;
			newseg->as[done++] = srcseg->as[i];
		}
		/* At his point newlen must be equal to done, and both must be
		 * positive. Append
		 * the filtered segment to the gross result. */
		if (!lastseg)
			newpath->segments = newseg;
		else
			lastseg->next = newseg;
		lastseg = newseg;
	}
	aspath_str_update(newpath, false);
	/* We are happy returning even an empty AS_PATH, because the
	 * administrator
	 * might expect this very behaviour. There's a mean to avoid this, if
	 * necessary,
	 * by having a match rule against certain AS_PATH regexps in the
	 * route-map index.
	 */
	aspath_free(source);
	return newpath;
}

struct aspath *aspath_filter_exclude_all(struct aspath *source)
{
	struct aspath *newpath;

	newpath = aspath_new(source->asnotation);

	aspath_str_update(newpath, false);
	/* We are happy returning even an empty AS_PATH, because the
	 * administrator
	 * might expect this very behaviour. There's a mean to avoid this, if
	 * necessary,
	 * by having a match rule against certain AS_PATH regexps in the
	 * route-map index.
	 */
	aspath_free(source);
	return newpath;
}

struct aspath *aspath_filter_exclude_acl(struct aspath *source,
					 struct as_list *acl_list)
{
	struct assegment *cur_seg, *new_seg, *prev_seg, *next_seg;
	struct as_list *cur_as_list;
	struct as_filter *cur_as_filter;
	char str_buf[ASPATH_STR_DEFAULT_LEN];
	uint32_t nb_as_del;
	uint32_t i, j;

	cur_seg = source->segments;
	prev_seg = NULL;
	/* segments from source aspath */
	while (cur_seg) {
		next_seg = cur_seg->next;
		cur_as_list = acl_list;
		nb_as_del = 0;
		/* aspath filter list from acl_list */
		while (cur_as_list) {
			cur_as_filter = cur_as_list->head;
			while (cur_as_filter) {
				for (i = 0; i < cur_seg->length; i++) {
					if (cur_seg->as[i] == 0)
						continue;

					snprintfrr(str_buf,
						   ASPATH_STR_DEFAULT_LEN,
						   ASN_FORMAT(source->asnotation),
						   &cur_seg->as[i]);
					if (!regexec(cur_as_filter->reg,
						     str_buf, 0, NULL, 0)) {
						cur_seg->as[i] = 0;
						nb_as_del++;
					}
				}

				cur_as_filter = cur_as_filter->next;
			}

			cur_as_list = cur_as_list->next;
		}
		/* full segment is excluded remove it */
		if (nb_as_del == cur_seg->length) {
			if (cur_seg == source->segments)
				/* first segment */
				source->segments = cur_seg->next;
			else if (prev_seg)
				prev_seg->next = cur_seg->next;
			assegment_free(cur_seg);
		}
		/* change in segment size -> new allocation and replace segment*/
		else if (nb_as_del) {
			new_seg = assegment_new(cur_seg->type,
						cur_seg->length - nb_as_del);
			j = 0;
			for (i = 0; i < cur_seg->length; i++) {
				if (cur_seg->as[i] == 0)
					continue;
				new_seg->as[j] = cur_seg->as[i];
				j++;
			}
			new_seg->next = next_seg;
			if (cur_seg == source->segments)
				/* first segment */
				source->segments = new_seg;
			else if (prev_seg)
				prev_seg->next = new_seg;
			assegment_free(cur_seg);
			prev_seg = new_seg;
		} else
			prev_seg = cur_seg;
		cur_seg = next_seg;
	}


	aspath_str_update(source, false);
	/* We are happy returning even an empty AS_PATH, because the
	 * administrator
	 * might expect this very behaviour. There's a mean to avoid this, if
	 * necessary,
	 * by having a match rule against certain AS_PATH regexps in the
	 * route-map index.
	 */
	return source;
}


/* Add specified AS to the leftmost of aspath. */
static struct aspath *aspath_add_asns(struct aspath *aspath, as_t asno,
				      uint8_t type, unsigned num)
{
	struct assegment *assegment = aspath->segments;
	unsigned i;

	if (assegment && assegment->type == type) {
		/* extend existing segment */
		aspath->segments =
			assegment_prepend_asns(aspath->segments, asno, num);
	} else {
		/* prepend with new segment */
		struct assegment *newsegment = assegment_new(type, num);
		for (i = 0; i < num; i++)
			newsegment->as[i] = asno;

		/* insert potentially replacing empty segment */
		if (assegment && assegment->length == 0) {
			newsegment->next = assegment->next;
			assegment_free(assegment);
		} else
			newsegment->next = assegment;
		aspath->segments = newsegment;
	}

	aspath_str_update(aspath, false);
	return aspath;
}

/* Add specified AS to the leftmost of aspath num times. */
struct aspath *aspath_add_seq_n(struct aspath *aspath, as_t asno, unsigned num)
{
	return aspath_add_asns(aspath, asno, AS_SEQUENCE, num);
}

/* Add specified AS to the leftmost of aspath. */
struct aspath *aspath_add_seq(struct aspath *aspath, as_t asno)
{
	return aspath_add_asns(aspath, asno, AS_SEQUENCE, 1);
}

/* Compare leftmost AS value for MED check.  If as1's leftmost AS and
   as2's leftmost AS is same return 1. */
bool aspath_cmp_left(const struct aspath *aspath1, const struct aspath *aspath2)
{
	const struct assegment *seg1;
	const struct assegment *seg2;

	if (!(aspath1 && aspath2))
		return false;

	seg1 = aspath1->segments;
	seg2 = aspath2->segments;

	/* If both paths are originated in this AS then we do want to compare
	 * MED */
	if (!seg1 && !seg2)
		return true;

	/* find first non-confed segments for each */
	while (seg1 && ((seg1->type == AS_CONFED_SEQUENCE)
			|| (seg1->type == AS_CONFED_SET)))
		seg1 = seg1->next;

	while (seg2 && ((seg2->type == AS_CONFED_SEQUENCE)
			|| (seg2->type == AS_CONFED_SET)))
		seg2 = seg2->next;

	/* Check as1's */
	if (!(seg1 && seg2 && (seg1->type == AS_SEQUENCE)
	      && (seg2->type == AS_SEQUENCE)))
		return false;

	if (seg1->as[0] == seg2->as[0])
		return true;

	return false;
}

/* Truncate an aspath after a number of hops, and put the hops remaining
 * at the front of another aspath.  Needed for AS4 compat.
 *
 * Returned aspath is a /new/ aspath, which should either by free'd or
 * interned by the caller, as desired.
 */
struct aspath *aspath_reconcile_as4(struct aspath *aspath,
				    struct aspath *as4path)
{
	struct assegment *seg, *newseg, *prevseg = NULL;
	struct aspath *newpath = NULL, *mergedpath;
	int hops, cpasns = 0;

	if (!aspath || !as4path)
		return NULL;

	seg = aspath->segments;

	/* CONFEDs should get reconciled too.. */
	hops = (aspath_count_hops(aspath) + aspath_count_confeds(aspath))
	       - aspath_count_hops(as4path);

	if (hops < 0) {
		if (BGP_DEBUG(as4, AS4))
			flog_warn(
				EC_BGP_ASPATH_FEWER_HOPS,
				"[AS4] Fewer hops in AS_PATH than NEW_AS_PATH");
		/* Something's gone wrong. The RFC says we should now ignore
		 * AS4_PATH,
		 * which is daft behaviour - it contains vital loop-detection
		 * information which must have been removed from AS_PATH.
		 */
		hops = aspath_count_hops(aspath);
	}

	if (!hops) {
		newpath = aspath_dup(as4path);
		aspath_str_update(newpath, false);
		return newpath;
	}

	if (BGP_DEBUG(as4, AS4))
		zlog_debug(
			"[AS4] got AS_PATH %s and AS4_PATH %s synthesizing now",
			aspath->str, as4path->str);

	while (seg && hops > 0) {
		switch (seg->type) {
		case AS_SET:
		case AS_CONFED_SET:
			hops--;
			cpasns = seg->length;
			break;
		case AS_CONFED_SEQUENCE:
			/* Should never split a confed-sequence, if hop-count
			 * suggests we must then something's gone wrong
			 * somewhere.
			 *
			 * Most important goal is to preserve AS_PATHs prime
			 * function
			 * as loop-detector, so we fudge the numbers so that the
			 * entire
			 * confed-sequence is merged in.
			 */
			if (hops < seg->length) {
				if (BGP_DEBUG(as4, AS4))
					zlog_debug(
						"[AS4] AS4PATHmangle: AS_CONFED_SEQUENCE falls across 2/4 ASN boundary somewhere, broken..");
				hops = seg->length;
			}
			fallthrough;
		case AS_SEQUENCE:
			cpasns = MIN(seg->length, hops);
			hops -= seg->length;
		}

		assert(cpasns <= seg->length);

		newseg = assegment_new(seg->type, 0);
		newseg = assegment_append_asns(newseg, seg->as, cpasns);

		if (!newpath) {
			newpath = aspath_new(aspath->asnotation);
			newpath->segments = newseg;
		} else
			prevseg->next = newseg;

		prevseg = newseg;
		seg = seg->next;
	}

	/* We may be able to join some segments here, and we must
	 * do this because... we want normalised aspaths in out hash
	 * and we do not want to stumble in aspath_put.
	 */
	mergedpath = aspath_merge(newpath, aspath_dup(as4path));
	aspath_free(newpath);
	mergedpath->segments = assegment_normalise(mergedpath->segments);
	aspath_str_update(mergedpath, false);

	if (BGP_DEBUG(as4, AS4))
		zlog_debug("[AS4] result of synthesizing is %s",
			   mergedpath->str);

	return mergedpath;
}

/* Compare leftmost AS value for MED check.  If as1's leftmost AS and
   as2's leftmost AS is same return 1. (confederation as-path
   only).  */
bool aspath_cmp_left_confed(const struct aspath *aspath1,
			    const struct aspath *aspath2)
{
	if (!(aspath1 && aspath2))
		return false;

	if (!(aspath1->segments && aspath2->segments))
		return false;

	if ((aspath1->segments->type != AS_CONFED_SEQUENCE)
	    || (aspath2->segments->type != AS_CONFED_SEQUENCE))
		return false;

	if (aspath1->segments->as[0] == aspath2->segments->as[0])
		return true;

	return false;
}

/* Delete all AS_CONFED_SEQUENCE/SET segments from aspath.
 * RFC 5065 section 4.1.c.1
 *
 * 1) if any path segments of the AS_PATH are of the type
 *    AS_CONFED_SEQUENCE or AS_CONFED_SET, those segments MUST be
 *    removed from the AS_PATH attribute, leaving the sanitized
 *    AS_PATH attribute to be operated on by steps 2, 3 or 4.
 */
struct aspath *aspath_delete_confed_seq(struct aspath *aspath)
{
	struct assegment *seg, *prev, *next;
	char removed_confed_segment;

	if (!(aspath && aspath->segments))
		return aspath;

	seg = aspath->segments;
	removed_confed_segment = 0;
	next = NULL;
	prev = NULL;

	while (seg) {
		next = seg->next;

		if (seg->type == AS_CONFED_SEQUENCE
		    || seg->type == AS_CONFED_SET) {
			/* This is the first segment in the aspath */
			if (aspath->segments == seg)
				aspath->segments = seg->next;
			else
				prev->next = seg->next;

			assegment_free(seg);
			removed_confed_segment = 1;
		} else
			prev = seg;

		seg = next;
	}

	if (removed_confed_segment)
		aspath_str_update(aspath, false);

	return aspath;
}

/* Add new AS number to the leftmost part of the aspath as
   AS_CONFED_SEQUENCE.  */
struct aspath *aspath_add_confed_seq(struct aspath *aspath, as_t asno)
{
	return aspath_add_asns(aspath, asno, AS_CONFED_SEQUENCE, 1);
}

/* Add new as value to as path structure. */
static void aspath_as_add(struct aspath *as, as_t asno)
{
	struct assegment *seg = as->segments;

	if (!seg)
		return;

	/* Last segment search procedure. */
	while (seg->next)
		seg = seg->next;

	assegment_append_asns(seg, &asno, 1);
}

/* Add new as segment to the as path. */
static void aspath_segment_add(struct aspath *as, int type)
{
	struct assegment *seg = as->segments;
	struct assegment *new = assegment_new(type, 0);

	if (seg) {
		while (seg->next)
			seg = seg->next;
		seg->next = new;
	} else
		as->segments = new;
}

struct aspath *aspath_empty(enum asnotation_mode asnotation)
{
	return aspath_parse(NULL, 0, 1, asnotation); /* 32Bit ;-) */
}

struct aspath *aspath_empty_get(void)
{
	struct aspath *aspath;

	aspath = aspath_new(bgp_get_asnotation(NULL));
	aspath_make_str_count(aspath, false);
	return aspath;
}

unsigned long aspath_count(void)
{
	return ashash->count;
}

/*
   Theoretically, one as path can have:

   One BGP packet size should be less than 4096.
   One BGP attribute size should be less than 4096 - BGP header size.
   One BGP aspath size should be less than 4096 - BGP header size -
       BGP mandantry attribute size.
*/

/* AS path string lexical token enum. */
enum as_token {
	as_token_asval,
	as_token_set_start,
	as_token_set_end,
	as_token_confed_seq_start,
	as_token_confed_seq_end,
	as_token_confed_set_start,
	as_token_confed_set_end,
	as_token_unknown
};

/* Return next token and point for string parse. */
static const char *aspath_gettoken(const char *buf, enum as_token *token,
				   unsigned long *asno)
{
	const char *p = buf;
	as_t asval;
	bool found = false;

	/* Skip separators (space for sequences, ',' for sets). */
	while (isspace((unsigned char)*p) || *p == ',')
		p++;

	/* Check the end of the string and type specify characters
	   (e.g. {}()). */
	switch (*p) {
	case '\0':
		return NULL;
	case '{':
		*token = as_token_set_start;
		p++;
		return p;
	case '}':
		*token = as_token_set_end;
		p++;
		return p;
	case '(':
		*token = as_token_confed_seq_start;
		p++;
		return p;
	case ')':
		*token = as_token_confed_seq_end;
		p++;
		return p;
	case '[':
		*token = as_token_confed_set_start;
		p++;
		return p;
	case ']':
		*token = as_token_confed_set_end;
		p++;
		return p;
	}

	asval = 0;
	p = asn_str2asn_parse(p, &asval, &found);
	if (found) {
		*asno = asval;
		*token = as_token_asval;
	} else
		*token = as_token_unknown;
	return p;
}

struct aspath *aspath_str2aspath(const char *str,
				 enum asnotation_mode asnotation)
{
	enum as_token token = as_token_unknown;
	unsigned short as_type;
	unsigned long asno = 0;
	struct aspath *aspath;
	int needtype;

	aspath = aspath_new(asnotation);

	/* We start default type as AS_SEQUENCE. */
	as_type = AS_SEQUENCE;
	needtype = 1;

	while ((str = aspath_gettoken(str, &token, &asno)) != NULL) {
		switch (token) {
		case as_token_asval:
			if (needtype) {
				aspath_segment_add(aspath, as_type);
				needtype = 0;
			}
			aspath_as_add(aspath, asno);
			break;
		case as_token_set_start:
			as_type = AS_SET;
			aspath_segment_add(aspath, as_type);
			needtype = 0;
			break;
		case as_token_set_end:
			as_type = AS_SEQUENCE;
			needtype = 1;
			break;
		case as_token_confed_seq_start:
			as_type = AS_CONFED_SEQUENCE;
			aspath_segment_add(aspath, as_type);
			needtype = 0;
			break;
		case as_token_confed_seq_end:
			as_type = AS_SEQUENCE;
			needtype = 1;
			break;
		case as_token_confed_set_start:
			as_type = AS_CONFED_SET;
			aspath_segment_add(aspath, as_type);
			needtype = 0;
			break;
		case as_token_confed_set_end:
			as_type = AS_SEQUENCE;
			needtype = 1;
			break;
		case as_token_unknown:
		default:
			aspath_free(aspath);
			return NULL;
		}
	}

	aspath_make_str_count(aspath, false);

	return aspath;
}

/* Make hash value by raw aspath data. */
unsigned int aspath_key_make(const void *p)
{
	const struct aspath *aspath = p;
	unsigned int key = 0;

	if (!aspath->str)
		aspath_str_update((struct aspath *)aspath, false);

	key = jhash(aspath->str, aspath->str_len, 2334325);

	return key;
}

/* If two aspath have same value then return 1 else return 0 */
bool aspath_cmp(const void *arg1, const void *arg2)
{
	const struct assegment *seg1 = ((const struct aspath *)arg1)->segments;
	const struct assegment *seg2 = ((const struct aspath *)arg2)->segments;

	if (((const struct aspath *)arg1)->asnotation !=
	    ((const struct aspath *)arg2)->asnotation)
		return false;

	while (seg1 || seg2) {
		int i;
		if ((!seg1 && seg2) || (seg1 && !seg2))
			return false;
		if (seg1->type != seg2->type)
			return false;
		if (seg1->length != seg2->length)
			return false;
		for (i = 0; i < seg1->length; i++)
			if (seg1->as[i] != seg2->as[i])
				return false;
		seg1 = seg1->next;
		seg2 = seg2->next;
	}
	return true;
}

/* AS path hash initialize. */
void aspath_init(void)
{
	ashash = hash_create_size(32768, aspath_key_make, aspath_cmp,
				  "BGP AS Path");

	as_list_list_init(&as_exclude_list_orphan);
}

void aspath_finish(void)
{
	struct aspath_exclude *ase;

	hash_clean_and_free(&ashash, (void (*)(void *))aspath_free);

	if (snmp_stream)
		stream_free(snmp_stream);

	while ((ase = as_list_list_pop(&as_exclude_list_orphan))) {
		aspath_free(ase->aspath);
		if (ase->exclude_aspath_acl_name)
			XFREE(MTYPE_TMP, ase->exclude_aspath_acl_name);
		XFREE(MTYPE_ROUTE_MAP_COMPILED, ase);
	}
	as_list_list_fini(&as_exclude_list_orphan);
}

/* return and as path value */
const char *aspath_print(struct aspath *as)
{
	return as ? as->str : "(null)";
}

/* Printing functions */
/* Feed the AS_PATH to the vty; the space suffix follows it only in case
 * AS_PATH wasn't empty.
 */
void aspath_print_vty(struct vty *vty, struct aspath *as)
{
	vty_out(vty, "%s%s", as->str, as->str_len ? " " : "");
}

static void aspath_show_all_iterator(struct hash_bucket *bucket,
				     struct vty *vty)
{
	struct aspath *as;

	as = (struct aspath *)bucket->data;

	vty_out(vty, "[%p:%u] (%ld) ", (void *)bucket, bucket->key, as->refcnt);
	vty_out(vty, "%s\n", as->str);
}

/* Print all aspath and hash information.  This function is used from
   `show [ip] bgp paths' command. */
void aspath_print_all_vty(struct vty *vty)
{
	hash_iterate(ashash, (void (*)(struct hash_bucket *,
				       void *))aspath_show_all_iterator,
		     vty);
}

static struct aspath *bgp_aggr_aspath_lookup(struct bgp_aggregate *aggregate,
					     struct aspath *aspath)
{
	return hash_lookup(aggregate->aspath_hash, aspath);
}

static void *bgp_aggr_aspath_hash_alloc(void *p)
{
	struct aspath *ref = (struct aspath *)p;
	struct aspath *aspath = NULL;

	aspath = aspath_dup(ref);
	return aspath;
}

static void bgp_aggr_aspath_prepare(struct hash_bucket *hb, void *arg)
{
	struct aspath *hb_aspath = hb->data;
	struct aspath **aggr_aspath = arg;
	struct aspath *aspath = NULL;

	if (*aggr_aspath) {
		aspath = aspath_aggregate(*aggr_aspath, hb_aspath);
		aspath_free(*aggr_aspath);
		*aggr_aspath = aspath;
	} else {
		*aggr_aspath = aspath_dup(hb_aspath);
	}
}

void bgp_aggr_aspath_remove(void *arg)
{
	struct aspath *aspath = arg;

	aspath_free(aspath);
}

void bgp_compute_aggregate_aspath(struct bgp_aggregate *aggregate,
				  struct aspath *aspath)
{
	bgp_compute_aggregate_aspath_hash(aggregate, aspath);

	bgp_compute_aggregate_aspath_val(aggregate);

}

void bgp_compute_aggregate_aspath_hash(struct bgp_aggregate *aggregate,
				       struct aspath *aspath)
{
	struct aspath *aggr_aspath = NULL;

	if ((aggregate == NULL) || (aspath == NULL))
		return;

	/* Create hash if not already created.
	 */
	if (aggregate->aspath_hash == NULL)
		aggregate->aspath_hash = hash_create(
					aspath_key_make, aspath_cmp,
					"BGP Aggregator as-path hash");

	aggr_aspath = bgp_aggr_aspath_lookup(aggregate, aspath);
	if (aggr_aspath == NULL) {
		/* Insert as-path into hash.
		 */
		aggr_aspath = hash_get(aggregate->aspath_hash, aspath,
				       bgp_aggr_aspath_hash_alloc);
	}

	/* Increment reference counter.
	 */
	aggr_aspath->refcnt++;
}

void bgp_compute_aggregate_aspath_val(struct bgp_aggregate *aggregate)
{
	if (aggregate == NULL)
		return;
	/* Re-compute aggregate's as-path.
	 */
	if (aggregate->aspath) {
		aspath_free(aggregate->aspath);
		aggregate->aspath = NULL;
	}
	if (aggregate->aspath_hash
	    && aggregate->aspath_hash->count) {
		hash_iterate(aggregate->aspath_hash,
			     bgp_aggr_aspath_prepare,
			     &aggregate->aspath);
	}
}

void bgp_remove_aspath_from_aggregate(struct bgp_aggregate *aggregate,
				      struct aspath *aspath)
{
	struct aspath *aggr_aspath = NULL;
	struct aspath *ret_aspath = NULL;

	if ((!aggregate)
	    || (!aggregate->aspath_hash)
	    || (!aspath))
		return;

	/* Look-up the aspath in the hash.
	 */
	aggr_aspath = bgp_aggr_aspath_lookup(aggregate, aspath);
	if (aggr_aspath) {
		aggr_aspath->refcnt--;

		if (aggr_aspath->refcnt == 0) {
			ret_aspath = hash_release(aggregate->aspath_hash,
						  aggr_aspath);
			aspath_free(ret_aspath);
			ret_aspath = NULL;

			/* Remove aggregate's old as-path.
			 */
			aspath_free(aggregate->aspath);
			aggregate->aspath = NULL;

			bgp_compute_aggregate_aspath_val(aggregate);
		}
	}
}

void bgp_remove_aspath_from_aggregate_hash(struct bgp_aggregate *aggregate,
					   struct aspath *aspath)
{
	struct aspath *aggr_aspath = NULL;
	struct aspath *ret_aspath = NULL;

	if ((!aggregate)
	    || (!aggregate->aspath_hash)
	    || (!aspath))
		return;

	/* Look-up the aspath in the hash.
	 */
	aggr_aspath = bgp_aggr_aspath_lookup(aggregate, aspath);
	if (aggr_aspath) {
		aggr_aspath->refcnt--;

		if (aggr_aspath->refcnt == 0) {
			ret_aspath = hash_release(aggregate->aspath_hash,
						  aggr_aspath);
			aspath_free(ret_aspath);
			ret_aspath = NULL;
		}
	}
}

