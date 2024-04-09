// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Flowspec header for packet handling
 * Copyright (C) 2018 6WIND
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
				   struct bgp_nlri *packet, bool withdraw);

extern void bgp_flowspec_vty_init(void);

extern int bgp_show_table_flowspec(struct vty *vty, struct bgp *bgp, afi_t afi,
				   struct bgp_table *table,
				   enum bgp_show_type type, void *output_arg,
				   bool use_json, int is_last,
				   unsigned long *output_cum,
				   unsigned long *total_cum);

extern void bgp_fs_nlri_get_string(unsigned char *nlri_content, size_t len,
				   char *return_string, int format,
				   json_object *json_path,
				   afi_t afi);

extern void route_vty_out_flowspec(struct vty *vty, const struct prefix *p,
				   struct bgp_path_info *path, int display,
				   json_object *json_paths);
extern int bgp_fs_config_write_pbr(struct vty *vty, struct bgp *bgp,
				   afi_t afi, safi_t safi);

extern int bgp_flowspec_display_match_per_ip(afi_t afi, struct bgp_table *rib,
					     struct prefix *match,
					     int prefix_check, struct vty *vty,
					     bool use_json,
					     json_object *json_paths);

#endif /* _FRR_BGP_FLOWSPEC_H */
