/* BGP VTY interface.
 * Copyright (C) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro
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

#ifndef _QUAGGA_BGP_VTY_H
#define _QUAGGA_BGP_VTY_H

struct bgp;

#define BGP_INSTANCE_HELP_STR "BGP view\nBGP VRF\nView/VRF name\n"
#define BGP_INSTANCE_ALL_HELP_STR "BGP view\nBGP VRF\nAll Views/VRFs\n"

#define BGP_AFI_CMD_STR         "<ipv4|ipv6>"
#define BGP_AFI_HELP_STR        "Address Family\nAddress Family\n"
#define BGP_SAFI_CMD_STR        "<unicast|multicast|vpn>"
#define BGP_SAFI_HELP_STR                                                      \
	"Address Family modifier\n"                                            \
	"Address Family modifier\n"                                            \
	"Address Family modifier\n"
#define BGP_AFI_SAFI_CMD_STR    BGP_AFI_CMD_STR" "BGP_SAFI_CMD_STR
#define BGP_AFI_SAFI_HELP_STR   BGP_AFI_HELP_STR BGP_SAFI_HELP_STR

#define BGP_SAFI_WITH_LABEL_CMD_STR  "<unicast|multicast|vpn|labeled-unicast|flowspec>"
#define BGP_SAFI_WITH_LABEL_HELP_STR                                           \
	"Address Family modifier\n"                                            \
	"Address Family modifier\n"                                            \
	"Address Family modifier\n"                                            \
	"Address Family modifier\n"                                            \
	"Address Family modifier\n"

extern void bgp_vty_init(void);
extern const char *afi_safi_print(afi_t afi, safi_t safi);
extern const char *afi_safi_json(afi_t afi, safi_t safi);
extern void bgp_config_write_update_delay(struct vty *vty, struct bgp *bgp);
extern void bgp_config_write_wpkt_quanta(struct vty *vty, struct bgp *bgp);
extern void bgp_config_write_rpkt_quanta(struct vty *vty, struct bgp *bgp);
extern void bgp_config_write_listen(struct vty *vty, struct bgp *bgp);
extern void bgp_config_write_coalesce_time(struct vty *vty, struct bgp *bgp);
extern int bgp_vty_return(struct vty *vty, int ret);
extern struct peer *peer_and_group_lookup_vty(struct vty *vty,
					      const char *peer_str);

extern afi_t bgp_vty_afi_from_str(const char *afi_str);

extern safi_t bgp_vty_safi_from_str(const char *safi_str);

extern int argv_find_and_parse_afi(struct cmd_token **argv, int argc,
				   int *index, afi_t *afi);

extern int argv_find_and_parse_safi(struct cmd_token **argv, int argc,
				    int *index, safi_t *safi);

extern int bgp_vty_find_and_parse_afi_safi_bgp(struct vty *vty,
					       struct cmd_token **argv,
					       int argc, int *idx, afi_t *afi,
					       safi_t *safi, struct bgp **bgp);
extern int bgp_show_summary_vty(struct vty *vty, const char *name, afi_t afi,
				safi_t safi, uint8_t use_json);
extern void bgp_vpn_policy_config_write_afi(struct vty *vty, struct bgp *bgp,
					    afi_t afi);
#endif /* _QUAGGA_BGP_VTY_H */
