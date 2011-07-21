/* $QuaggaId: Format:%an, %ai, %h$ $
 *
 * BGP Multipath
 * Copyright (C) 2010 Google Inc.
 *
 * This file is part of Quagga
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _QUAGGA_BGP_MPATH_H
#define _QUAGGA_BGP_MPATH_H

/* BGP default maximum-paths */
#define BGP_DEFAULT_MAXPATHS 1

/* Functions to support maximum-paths configuration */
extern int bgp_maximum_paths_set (struct bgp *, afi_t, safi_t, int, u_int16_t);
extern int bgp_maximum_paths_unset (struct bgp *, afi_t, safi_t, int);

/* Functions used by bgp_best_selection to record current
 * multipath selections
 */
extern void bgp_mp_list_init (struct list *);
extern void bgp_mp_list_clear (struct list *);
extern void bgp_mp_list_add (struct list *, struct bgp_info *);

#endif /* _QUAGGA_BGP_MPATH_H */
