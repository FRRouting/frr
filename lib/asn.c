/*
 * ASN functions
 *
 * Copyright 2022 6WIND
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>
#include "log.h"
#include "asn.h"

static bool relax_as_zero;

static const struct message asnotation_mode_msg[] = {
	{ASNOTATION_PLAIN, "plain"},
	{ASNOTATION_DOT, "dot"},
	{ASNOTATION_DOTPLUS, "dot+"},
	{ASNOTATION_UNDEFINED, "undefined"},
	{0}
};

/* converts a string into an Autonomous system number
 * "1.1" => 65536
 * "65500" => 65500
 */
static bool asn_str2asn_internal(const char *asstring, as_t *asn,
				 const char **next, bool *partial,
				 enum asnotation_mode *mode)
{
	uint32_t high = 0, low = 0;
	uint64_t temp_val;
	const char *p = asstring;
	bool ret = false;
	uint32_t digit;
	enum asnotation_mode val = ASNOTATION_PLAIN;

	if (!asstring)
		goto end;

	if  (!isdigit((unsigned char)*p))
		goto end;

	/* leading zero is forbidden */
	if (*p == '0' && isdigit((unsigned char)*(p + 1)))
		goto end;

	temp_val = 0;
	while (isdigit((unsigned char)*p)) {
		digit = (*p) - '0';
		temp_val *= 10;
		temp_val += digit;
		if (temp_val > UINT32_MAX)
			/* overflow */
			goto end;
		p++;
	}
	high = (uint32_t)temp_val;
	if (*p == '.') { /* dot format */
		p++;

		if (*p == '\0' && partial) {
			*partial = true;
			goto end;
		}

		/* leading zero is forbidden */
		if (*p == '0' && isdigit((unsigned char)*(p + 1)))
			goto end;

		temp_val = 0;
		while (isdigit((unsigned char)*p)) {
			digit = (*p) - '0';
			temp_val *= 10;
			temp_val += digit;
			if (temp_val > UINT16_MAX)
				/* overflow */
				goto end;
			p++;
		}
		low = (uint32_t)temp_val;

		if (!next && *p != '\0' && !isdigit((unsigned char)*p))
			goto end;
		/* AS <AS4B>.<AS4B> is forbidden */
		if (high > UINT16_MAX)
			goto end;
		/* AS 0.0 is authorised for some case only */
		if (!relax_as_zero && high == 0 && low == 0) {
			if (partial)
				*partial = true;
			goto end;
		}
		if (asn)
			*asn = (high << 16) + low;
		ret = true;
		if (high == 0)
			val = ASNOTATION_DOTPLUS;
		else
			val = ASNOTATION_DOT;
		goto end;
	}
	/* AS 0 is forbidden */
	if (!relax_as_zero && high == 0)
		goto end;
	if (!asn) {
		ret = true;
		goto end;
	}
	*asn = high;
	ret = true;
 end:
	if (next)
		*next = p;
	if (mode)
		*mode = val;
	return ret;
}

static void asn_asn2asdot(as_t asn, char *asstring, size_t len)
{
	uint16_t low, high;

	high = (asn >> 16) & 0xffff;
	low = asn & 0xffff;
	snprintf(asstring, len, "%hu.%hu", high, low);
}

bool asn_str2asn(const char *asstring, as_t *asn)
{
	return asn_str2asn_internal(asstring, asn, NULL, NULL, NULL);
}

const char *asn_asn2asplain(as_t asn)
{
	static char buf[ASN_STRING_MAX_SIZE];

	snprintf(buf, sizeof(buf), "%u", asn);
	return buf;
}

const char *asn_str2asn_parse(const char *asstring, as_t *asn, bool *found_ptr)
{
	const char *p = NULL;
	const char **next = &p;
	bool found;

	found = asn_str2asn_internal(asstring, asn, next, NULL, NULL);
	if (found_ptr)
		*found_ptr = found;
	return *next;
}

void asn_relax_as_zero(bool relax)
{
	relax_as_zero = relax;
}

enum match_type asn_str2asn_match(const char *str)
{
	bool found, partial = false;

	found = asn_str2asn_internal(str, NULL, NULL, &partial, NULL);
	if (found && !partial)
		return exact_match;

	if (partial)
		return partly_match;

	return no_match;
}

bool asn_str2asn_notation(const char *asstring, as_t *asn,
			  enum asnotation_mode *asnotation)
{
	return asn_str2asn_internal(asstring, asn, NULL, NULL, asnotation);
}

const char *asn_mode2str(enum asnotation_mode asnotation)
{
	return lookup_msg(asnotation_mode_msg, asnotation,
			  "Unrecognized AS notation mode");
}

void asn_asn2json(json_object *json, const char *attr,
		  as_t asn, enum asnotation_mode asnotation)
{
	static char as_str[ASN_STRING_MAX_SIZE];

	if ((asnotation == ASNOTATION_PLAIN) ||
	    ((asnotation == ASNOTATION_DOT) && asn < UINT16_MAX))
		json_object_int_add(json, attr, asn);
	else {
		asn_asn2asdot(asn, as_str, sizeof(as_str));
		json_object_string_add(json, attr, as_str);
	}
}

void asn_asn2json_array(json_object *jseg_list, as_t asn,
			enum asnotation_mode asnotation)
{
	static char as_str[ASN_STRING_MAX_SIZE];

	if ((asnotation == ASNOTATION_PLAIN) ||
	    ((asnotation == ASNOTATION_DOT) && asn < UINT16_MAX))
		json_object_array_add(jseg_list,
				      json_object_new_int64(asn));
	else {
		asn_asn2asdot(asn, as_str, sizeof(as_str));
		json_array_string_add(jseg_list, as_str);
	}
}

char *asn_asn2string(const as_t *asn, char *buf, size_t len,
		     enum asnotation_mode asnotation)
{
	if ((asnotation == ASNOTATION_PLAIN) ||
	    ((asnotation == ASNOTATION_DOT) && *asn < UINT16_MAX))
		snprintf(buf, len, "%u", *asn);
	else
		asn_asn2asdot(*asn, buf, len);
	return buf;
}

static ssize_t printfrr_asnotation(struct fbuf *buf, struct printfrr_eargs *ea,
				   const void *ptr,
				   enum asnotation_mode asnotation)
{
	/* for alignemnt up to 33 chars - %33pASD for instance - */
	char as_str[ASN_STRING_MAX_SIZE*3];
	const as_t *asn;

	if (!ptr)
		return bputs(buf, "(null)");
	asn = ptr;
	asn_asn2string(asn, as_str, sizeof(as_str), asnotation);
	return bputs(buf, as_str);
}

printfrr_ext_autoreg_p("ASP", printfrr_asplain);
static ssize_t printfrr_asplain(struct fbuf *buf, struct printfrr_eargs *ea,
				const void *ptr)
{
	return printfrr_asnotation(buf, ea, ptr, ASNOTATION_PLAIN);
}

printfrr_ext_autoreg_p("ASD", printfrr_asdot);
static ssize_t printfrr_asdot(struct fbuf *buf, struct printfrr_eargs *ea,
				const void *ptr)
{
	return printfrr_asnotation(buf, ea, ptr, ASNOTATION_DOT);
}

printfrr_ext_autoreg_p("ASE", printfrr_asdotplus);
static ssize_t printfrr_asdotplus(struct fbuf *buf, struct printfrr_eargs *ea,
				  const void *ptr)
{
	return printfrr_asnotation(buf, ea, ptr, ASNOTATION_DOTPLUS);
}
