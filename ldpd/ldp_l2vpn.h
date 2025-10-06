// SPDX-License-Identifier: GPL-2.0-or-later
/* Route map function.
 * Copyright (C) 1998 Kunihiro Ishiguro
 */

#ifndef _LDP_L2VPN_H
#define _LDP_L2VPN_H

#ifdef __cplusplus
extern "C" {
#endif

extern const struct frr_yang_module_info frr_ldp_l2vpn;
extern const struct frr_yang_module_info frr_ldp_l2vpn_cli_info;

extern void ldp_l2vpn_cli_init(void);
extern void ldp_l2vpn_init(void);

struct l2vpn;
struct l2vpn_pw;

struct l2vpn_pw *l2vpn_pw_find(struct l2vpn *l2vpn, const char *ifname);
struct l2vpn_if *l2vpn_if_find(struct l2vpn *l2vpn, const char *ifname);

struct l2vpn_lib_register {
	void (*add_hook)(const char *name);
	void (*del_hook)(const char *name);
	void (*event_hook)(const char *name);
	bool (*iface_ok_for_l2vpn)(const char *ifname);
};

extern struct l2vpn_lib_register l2vpn_lib_master;

int l2vpn_iface_is_configured(const char *ifname);

void l2vpn_register_hook(void (*func_add)(const char *), void (*func_del)(const char *),
			 void (*func_event)(const char *),
			 bool (*func_iface_ok_for_l2vpn)(const char *));

#ifdef __cplusplus
}
#endif

#endif /* _LDP_L2VPN_H */
