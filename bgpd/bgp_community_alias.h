/* BGP community, large-community aliasing.
 *
 * Copyright (C) 2021 Donatas Abraitis <donatas.abraitis@gmail.com>
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

#include "bgpd/bgp_lcommunity.h"

#ifndef FRR_BGP_COMMUNITY_ALIAS_H
#define FRR_BGP_COMMUNITY_ALIAS_H

struct community_alias {
	/* Human readable community string */
	char community[LCOMMUNITY_SIZE * 3];

	/* Human readable community alias */
	char alias[BUFSIZ];
};

extern void bgp_community_alias_init(void);
extern void bgp_community_alias_finish(void);
extern struct community_alias *bgp_ca_alias_lookup(struct community_alias *ca);
extern struct community_alias *
bgp_ca_community_lookup(struct community_alias *ca);
extern void bgp_ca_community_insert(struct community_alias *ca);
extern void bgp_ca_alias_insert(struct community_alias *ca);
extern void bgp_ca_community_delete(struct community_alias *ca);
extern void bgp_ca_alias_delete(struct community_alias *ca);
extern int bgp_community_alias_write(struct vty *vty);
extern const char *bgp_community2alias(char *community);
extern const char *bgp_alias2community(char *alias);
extern char *bgp_alias2community_str(const char *str);
extern void bgp_community_alias_command_completion_setup(void);

#endif /* FRR_BGP_COMMUNITY_ALIAS_H */
