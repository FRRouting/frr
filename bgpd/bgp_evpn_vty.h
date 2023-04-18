// SPDX-License-Identifier: GPL-2.0-or-later
/* EVPN VTY functions to EVPN
 * Copyright (C) 2017 6WIND
 */

#ifndef _FRR_BGP_EVPN_VTY_H
#define _FRR_BGP_EVPN_VTY_H

extern void bgp_config_write_evpn_info(struct vty *vty, struct bgp *bgp,
				       afi_t afi, safi_t safi);
extern void bgp_ethernetvpn_init(void);

#define L2VPN_HELP_STR        "Layer 2 Virtual Private Network\n"
#define EVPN_HELP_STR        "Ethernet Virtual Private Network\n"
#define VNI_HELP_STR "VXLAN Network Identifier\n"
#define VNI_NUM_HELP_STR "VNI number\n"
#define VNI_ALL_HELP_STR "All VNIs\n"
#define DETAIL_HELP_STR "Print Detailed Output\n"
#define VTEP_HELP_STR "Remote VTEP\n"
#define VTEP_IP_HELP_STR "Remote VTEP IP address\n"

extern int argv_find_and_parse_oly_idx(struct cmd_token **argv, int argc,
				       int *oly_idx,
				       enum overlay_index_type *oly);

/* Parse type from "type <ead|1|...>", return -1 on failure */
extern int bgp_evpn_cli_parse_type(int *type, struct cmd_token **argv,
				   int argc);

extern int bgp_evpn_show_all_routes(struct vty *vty, struct bgp *bgp, int type,
				    bool use_json, int detail);

#endif /* _QUAGGA_BGP_EVPN_VTY_H */
