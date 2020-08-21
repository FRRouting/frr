/*
 * IS-IS Rout(e)ing protocol - isis_spf.h
 *                             IS-IS Shortest Path First algorithm
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_ISIS_SPF_H
#define _ZEBRA_ISIS_SPF_H

struct isis_spftree;

struct isis_spftree *isis_spftree_new(struct isis_area *area);
void isis_spf_invalidate_routes(struct isis_spftree *tree);
void isis_spf_verify_routes(struct isis_area *area,
			    struct isis_spftree **trees);
void isis_spftree_del(struct isis_spftree *spftree);
void spftree_area_init(struct isis_area *area);
void spftree_area_del(struct isis_area *area);
#define isis_spf_schedule(area, level) \
	_isis_spf_schedule((area), (level), __func__, \
			   __FILE__, __LINE__)
int _isis_spf_schedule(struct isis_area *area, int level,
		       const char *func, const char *file, int line);
void isis_spf_init(void);
void isis_spf_print(struct isis_spftree *spftree, struct vty *vty);
struct isis_spftree *isis_run_hopcount_spf(struct isis_area *area,
					   uint8_t *sysid,
					   struct isis_spftree *spftree);
#endif /* _ZEBRA_ISIS_SPF_H */
