/* BGP Flowspec header for packet handling
 * Copyright (C) 2018 6WIND
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FRR_BGP_FLOWSPEC_H
#define _FRR_BGP_FLOWSPEC_H

#define NLRI_STRING_FORMAT_LARGE        0
#define NLRI_STRING_FORMAT_DEBUG        1
#define NLRI_STRING_FORMAT_MIN          2
#define NLRI_STRING_FORMAT_JSON         3
#define NLRI_STRING_FORMAT_JSON_SIMPLE  4

#define BGP_FLOWSPEC_NLRI_STRING_MAX 512

extern int bgp_nlri_parse_flowspec(struct peer *peer, struct attr *attr,
				   struct bgp_nlri *packet, int withdraw);

extern void bgp_flowspec_vty_init(void);

extern int bgp_show_table_flowspec(struct vty *vty, struct bgp *bgp, afi_t afi,
				   struct bgp_table *table,
				   enum bgp_show_type type,
				   void *output_arg, uint8_t use_json,
				   int is_last,
				   unsigned long *output_cum,
				   unsigned long *total_cum);

extern void bgp_fs_nlri_get_string(unsigned char *nlri_content, size_t len,
				   char *return_string, int format,
				   json_object *json_path);

extern void route_vty_out_flowspec(struct vty *vty, struct prefix *p,
				   struct bgp_info *binfo,
				   int display, json_object *json_paths);
extern int bgp_fs_config_write_pbr(struct vty *vty, struct bgp *bgp,
				   afi_t afi, safi_t safi);

#endif /* _FRR_BGP_FLOWSPEC_H */
