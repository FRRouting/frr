/*
 * Administrative-group library (RFC3630, RFC5305, RFC5329, RFC7308)
 *
 * Copyright 2022 Hiroki Shirokura, LINE Corporation
 * Copyright 2022 Masakazu Asama
 * Copyright 2022 6WIND S.A.
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

#include "admin_group.h"
#include "bitfield.h"

char *admin_group_string(char *out, size_t sz, int indent,
			 const struct admin_group *ag)
{
	bool printed = false;
	size_t index = 2;
	int nb_print = 0;

	if (sz < index)
		return out;

	if (admin_group_explicit_zero(ag)) {
		snprintf(out, sz, "0x00000000");
		return out;
	}

	if (admin_group_zero(ag)) {
		snprintf(out, sz, "not-set");
		return out;
	}

	snprintf(out, sz, "0x");
	for (ssize_t i = ag->bitmap.m - 1; i >= 0; i--) {
		if (sz - index <= 0)
			break;
		if (ag->bitmap.data[i] == 0 && !printed)
			continue;
		if (nb_print != 0 && (nb_print % 4) == 0) {
			snprintf(&out[index], sz - index, "\n%*s", indent, "");
			index += indent + 1;
			snprintf(&out[index], sz - index, "0x%08x ",
				 ag->bitmap.data[i]);
			index += 2;
		} else
			snprintf(&out[index], sz - index, "%08x ",
				 ag->bitmap.data[i]);
		index += 9;
		nb_print++;
		printed = true;
	}
	return out;
}

char *admin_group_standard_print(char *out, int indent, uint32_t bitmap)
{
	bool first = true;
	int bit, i;
	size_t ret, line_sz = 0, line_max_sz;

	out[0] = '\0';

	if (bitmap == 0) {
		snprintf(out, ADMIN_GROUP_PRINT_MAX_SIZE, "not-set");
		return out;
	}

	line_max_sz = strlen("0xffffffff ffffffff ffffffff ffffffff");

	for (i = 0; i < 32; i++) {
		bit = bitmap >> i & 1;
		if (bit == 0)
			continue;
		if (!first) {
			ret = snprintf(&out[strlen(out)],
				       ADMIN_GROUP_PRINT_MAX_SIZE - strlen(out),
				       ", ");
			line_sz += ret;
		}
		if (line_sz >= line_max_sz) {
			snprintf(&out[strlen(out)],
				 ADMIN_GROUP_PRINT_MAX_SIZE - strlen(out),
				 "\n%*s", indent, "");

			line_sz = 0;
		}
		ret = snprintf(&out[strlen(out)],
			       ADMIN_GROUP_PRINT_MAX_SIZE - strlen(out), "%d",
			       i);
		line_sz += ret;
		first = false;
	}

	return out;
}

char *admin_group_print(char *out, int indent, const struct admin_group *ag)
{
	bool first = true;
	uint32_t i;
	size_t ret, line_sz = 0, line_max_sz;

	out[0] = '\0';

	if (admin_group_size(ag) == 0) {
		snprintf(out, ADMIN_GROUP_PRINT_MAX_SIZE, "not-set");
		return out;
	}

	line_max_sz = strlen("0xffffffff ffffffff ffffffff ffffffff");

	for (i = 0; i < (admin_group_size(ag) * WORD_SIZE); i++) {
		if (!admin_group_get(ag, i))
			continue;
		if (!first) {
			ret = snprintf(&out[strlen(out)],
				       ADMIN_GROUP_PRINT_MAX_SIZE - strlen(out),
				       ", ");
			line_sz += ret;
		}
		if (line_sz >= line_max_sz) {
			snprintf(&out[strlen(out)],
				 ADMIN_GROUP_PRINT_MAX_SIZE - strlen(out),
				 "\n%*s", indent, "");

			line_sz = 0;
		}
		ret = snprintf(&out[strlen(out)],
			       ADMIN_GROUP_PRINT_MAX_SIZE - strlen(out), "%d",
			       i);
		line_sz += ret;
		if (ret >= (ADMIN_GROUP_PRINT_MAX_SIZE - strlen(out))) {
			out[0] = '\0';
			return out;
		}
		first = false;
	}

	return out;
}

bool admin_group_cmp(const struct admin_group *ag1,
		     const struct admin_group *ag2)
{
	size_t i;

	for (i = 0; i < ag1->bitmap.m || i < ag2->bitmap.m; i++) {
		if (i >= ag1->bitmap.m) {
			if (ag2->bitmap.data[i] != 0)
				return false;
		} else if (i >= ag2->bitmap.m) {
			if (ag1->bitmap.data[i] != 0)
				return false;
		} else if (memcmp(&ag1->bitmap.data[i], &ag2->bitmap.data[i],
				  sizeof(word_t)) != 0)
			return false;
	}

	return true;
}

void admin_group_copy(struct admin_group *dst, const struct admin_group *src)
{
	assert(bf_is_inited(src->bitmap));
	if (bf_is_inited(dst->bitmap))
		bf_free(dst->bitmap);
	dst->bitmap = bf_copy(src->bitmap);
}

void admin_group_init(struct admin_group *ag)
{
	assert(!bf_is_inited(ag->bitmap));
	bf_init(ag->bitmap, WORD_SIZE);
}

void admin_group_term(struct admin_group *ag)
{
	assert(bf_is_inited(ag->bitmap));
	bf_free(ag->bitmap);
}

word_t admin_group_get_offset(const struct admin_group *ag, size_t oct_offset)
{
	assert(bf_is_inited(ag->bitmap));
	if (ag->bitmap.m < oct_offset)
		return 0;
	return ag->bitmap.data[oct_offset];
}

static void admin_group_extend(struct admin_group *ag, size_t idx)
{
	size_t old_m, m;

	old_m = ag->bitmap.m;
	m = idx + 1;
	ag->bitmap.m = m;
	ag->bitmap.data =
		XREALLOC(MTYPE_BITFIELD, ag->bitmap.data, m * sizeof(word_t));
	memset(&ag->bitmap.data[old_m], 0, (m - old_m) * sizeof(word_t));
}

void admin_group_set(struct admin_group *ag, size_t pos)
{
	size_t idx = bf_index(pos);

	if (idx >= ag->bitmap.m)
		admin_group_extend(ag, idx);

	ag->bitmap.data[idx] |= 1 << (bf_offset(pos));

	if (idx >= ag->bitmap.n)
		ag->bitmap.n = idx + 1;
}

void admin_group_unset(struct admin_group *ag, size_t pos)
{
	if (bf_index(pos) > (ag->bitmap.m - 1))
		return;
	bf_release_index(ag->bitmap, pos);
	ag->bitmap.n = admin_group_size(ag);
}

int admin_group_get(const struct admin_group *ag, size_t pos)
{
	size_t admin_group_length = admin_group_size(ag);
	uint32_t oct_offset;
	size_t idx;

	if (admin_group_length == 0)
		return 0;

	idx = bf_index(pos);

	if (idx >= admin_group_length)
		return 0;

	oct_offset = admin_group_get_offset(ag, idx);
	return oct_offset >> pos & 1;
}

void admin_group_bulk_set(struct admin_group *ag, uint32_t bitmap,
			  size_t oct_offset)
{

	if (bitmap == 0 && oct_offset == 0) {
		admin_group_allow_explicit_zero(ag);
		return;
	}

	if (oct_offset >= ag->bitmap.m)
		admin_group_extend(ag, oct_offset);

	ag->bitmap.data[oct_offset] = bitmap;

	if (oct_offset >= ag->bitmap.n)
		ag->bitmap.n = oct_offset + 1;
}

size_t admin_group_size(const struct admin_group *ag)
{
	size_t size = 0;

	for (size_t i = 0; i < ag->bitmap.m; i++)
		if (ag->bitmap.data[i] != 0)
			size = i + 1;
	return size;
}

size_t admin_group_nb_words(const struct admin_group *ag)
{
	return ag->bitmap.n;
}

void admin_group_clear(struct admin_group *ag)
{
	for (size_t i = 0; i < ag->bitmap.m; i++)
		ag->bitmap.data[i] = 0;
	ag->bitmap.n = 0;
}

bool admin_group_zero(const struct admin_group *ag)
{
	for (size_t i = 0; i < ag->bitmap.m; i++)
		if (ag->bitmap.data[i] != 0)
			return false;
	return true;
}


bool admin_group_explicit_zero(const struct admin_group *ag)
{
	return ag->bitmap.n == 1 && ag->bitmap.data[0] == 0;
}

void admin_group_allow_explicit_zero(struct admin_group *ag)
{
	if (admin_group_zero(ag))
		ag->bitmap.n = 1;
}

void admin_group_disallow_explicit_zero(struct admin_group *ag)
{
	if (admin_group_zero(ag))
		ag->bitmap.n = 0;
}

/* link_std_ag: admin-group in the RFC5305 section 3.1 format
 * link_ext_ag: admin-group in the RFC7308 format
 * RFC7308 specifies in section 2.3.1 that:
 * "If both an AG and EAG are present, a receiving node MUST use the AG
 * as the first 32 bits (0-31) of administrative color and use the EAG
 * for bits 32 and higher, if present."
 */
bool admin_group_match_any(const struct admin_group *fad_ag,
			   const uint32_t *link_std_ag,
			   const struct admin_group *link_ext_ag)
{
	size_t fad_ag_sz, link_ag_sz, i;
	uint32_t link_ag_bitmap, fad_ag_bitmap;

	assert(fad_ag);

	/* get the size of admin-groups: i.e. number of used words */
	fad_ag_sz = admin_group_size(fad_ag);
	if (link_std_ag && link_ext_ag) {
		link_ag_sz = admin_group_size(link_ext_ag);
		if (link_ag_sz == 0)
			link_ag_sz = 1;
	} else if (link_std_ag && !link_ext_ag)
		link_ag_sz = 1;
	else if (!link_std_ag && link_ext_ag)
		link_ag_sz = admin_group_size(link_ext_ag);
	else
		link_ag_sz = 0;

	for (i = 0; i < fad_ag_sz && i < link_ag_sz; i++) {
		fad_ag_bitmap = fad_ag->bitmap.data[i];
		if (i == 0 && link_std_ag)
			link_ag_bitmap = *link_std_ag;
		else
			link_ag_bitmap = link_ext_ag->bitmap.data[i];

		if (fad_ag_bitmap & link_ag_bitmap)
			return true;
	}
	return false;
}

/* same comments as admin_group_match_any() */
bool admin_group_match_all(const struct admin_group *fad_ag,
			   const uint32_t *link_std_ag,
			   const struct admin_group *link_ext_ag)
{
	size_t fad_ag_sz, link_ag_sz, i;
	uint32_t link_ag_bitmap, fad_ag_bitmap;

	assert(fad_ag);

	/* get the size of admin-groups: i.e. number of used words */
	fad_ag_sz = admin_group_size(fad_ag);
	if (link_std_ag && link_ext_ag) {
		link_ag_sz = admin_group_size(link_ext_ag);
		if (link_ag_sz == 0)
			link_ag_sz = 1;
	} else if (link_std_ag && !link_ext_ag)
		link_ag_sz = 1;
	else if (!link_std_ag && link_ext_ag)
		link_ag_sz = admin_group_size(link_ext_ag);
	else
		link_ag_sz = 0;

	if (fad_ag_sz > link_ag_sz)
		return false;

	for (i = 0; i < fad_ag_sz; i++) {
		fad_ag_bitmap = fad_ag->bitmap.data[i];
		if (fad_ag_bitmap == 0)
			continue;

		if (i == 0 && link_std_ag)
			link_ag_bitmap = *link_std_ag;
		else
			link_ag_bitmap = link_ext_ag->bitmap.data[i];

		if ((fad_ag_bitmap & link_ag_bitmap) != fad_ag_bitmap)
			return false;
	}
	return true;
}
