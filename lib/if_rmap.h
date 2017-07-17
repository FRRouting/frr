/* route-map for interface.
 * Copyright (C) 1999 Kunihiro Ishiguro
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

#ifndef _ZEBRA_IF_RMAP_H
#define _ZEBRA_IF_RMAP_H

enum if_rmap_type { IF_RMAP_IN, IF_RMAP_OUT, IF_RMAP_MAX };

struct if_rmap {
	/* Name of the interface. */
	char *ifname;

	char *routemap[IF_RMAP_MAX];
};

extern void if_rmap_init(int);
extern void if_rmap_reset(void);
extern void if_rmap_hook_add(void (*)(struct if_rmap *));
extern void if_rmap_hook_delete(void (*)(struct if_rmap *));
extern struct if_rmap *if_rmap_lookup(const char *);
extern int config_write_if_rmap(struct vty *);

#endif /* _ZEBRA_IF_RMAP_H */
