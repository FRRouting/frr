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

/* converts a string into an Autonomous system number
 * "1.1" => 65536
 * "65500" => 65500
 */
static bool asn_str2asn_internal(const char *asstring, as_t *asn,
				 const char **next, bool *partial)
{
	uint32_t high = 0, low = 0;
	uint64_t temp_val;
	const char *p = asstring;
	bool ret = false;
	uint32_t digit;

	if (!asstring)
		goto end;

	if  (!isdigit((unsigned char)*p))
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
		temp_val = 0;
		if (*p == '\0' && partial) {
			*partial = true;
			goto end;
		}
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
		if (!asn) {
			ret = true;
			goto end;
		}
		*asn = (high << 16) + low;
		ret = true;
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
	return ret;
}

bool asn_str2asn(const char *asstring, as_t *asn)
{
	return asn_str2asn_internal(asstring, asn, NULL, NULL);
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

	found = asn_str2asn_internal(asstring, asn, next, NULL);
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

	found = asn_str2asn_internal(str, NULL, NULL, &partial);
	if (found && !partial)
		return exact_match;

	if (partial)
		return partly_match;

	return no_match;
}
