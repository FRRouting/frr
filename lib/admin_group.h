// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Administrative-group library (RFC3630, RFC5305, RFC5329, RFC7308)
 *
 * Copyright 2022 Hiroki Shirokura, LINE Corporation
 * Copyright 2022 Masakazu Asama
 * Copyright 2022 6WIND S.A.
 */

#ifndef _FRR_ADMIN_GROUP_H
#define _FRR_ADMIN_GROUP_H

#include "zebra.h"
#include "memory.h"
#include "bitfield.h"

#define ADMIN_GROUP_PRINT_MAX_SIZE 2048
#define EXT_ADMIN_GROUP_MAX_POSITIONS 1024

struct admin_group {
	bitfield_t bitmap;
};

char *admin_group_string(char *out, size_t sz, int indent,
			 const struct admin_group *ag);
char *admin_group_standard_print(char *out, int indent, uint32_t bitmap);
char *admin_group_print(char *out, int indent, const struct admin_group *ag);
bool admin_group_cmp(const struct admin_group *ag1,
		     const struct admin_group *ag2);
void admin_group_copy(struct admin_group *dst, const struct admin_group *src);
void admin_group_init(struct admin_group *ag);
void admin_group_term(struct admin_group *ag);
uint32_t admin_group_get_offset(const struct admin_group *ag,
				size_t oct_offset);
void admin_group_set(struct admin_group *ag, size_t pos);
void admin_group_unset(struct admin_group *ag, size_t pos);
int admin_group_get(const struct admin_group *ag, size_t pos);
void admin_group_bulk_set(struct admin_group *ag, uint32_t bitmap,
			  size_t oct_offset);
size_t admin_group_size(const struct admin_group *ag);
size_t admin_group_nb_words(const struct admin_group *ag);
void admin_group_clear(struct admin_group *ag);
bool admin_group_zero(const struct admin_group *ag);
bool admin_group_explicit_zero(const struct admin_group *ag);
void admin_group_allow_explicit_zero(struct admin_group *ag);
void admin_group_disallow_explicit_zero(struct admin_group *ag);

bool admin_group_match_any(const struct admin_group *fad_ag,
			   const uint32_t *link_std_ag,
			   const struct admin_group *link_ag);
bool admin_group_match_all(const struct admin_group *fad_ag,
			   const uint32_t *link_std_ag,
			   const struct admin_group *link_ag);

#endif /* _FRR_ADMIN_GROUP_H */
