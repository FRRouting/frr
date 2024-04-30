// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP community, large-community aliasing.
 *
 * Copyright (C) 2021 Donatas Abraitis <donatas.abraitis@gmail.com>
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
