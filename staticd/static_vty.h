// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * STATICd - vty header
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */
#ifndef __STATIC_VTY_H__
#define __STATIC_VTY_H__

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(HAVE_STATICD_MGMTD) && defined(HAVE_STATICD_NB)
void static_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void static_cli_show_end(struct vty *vty, const struct lyd_node *dnode);
void static_nexthop_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void static_src_nexthop_cli_show(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
int static_nexthop_cli_cmp(const struct lyd_node *dnode1, const struct lyd_node *dnode2);
int static_route_list_cli_cmp(const struct lyd_node *dnode1, const struct lyd_node *dnode2);
int static_src_list_cli_cmp(const struct lyd_node *dnode1, const struct lyd_node *dnode2);
int static_path_list_cli_cmp(const struct lyd_node *dnode1, const struct lyd_node *dnode2);
#endif /* !defined(HAVE_STATICD_MGMTD) && defined(HAVE_STATICD_NB) */

#ifndef HAVE_STATICD_NB
PREDECL_DLIST(static_route_args_list);
#endif /* !HAVE_STATICD_NB */

/** All possible route parameters available in CLI. */
struct static_route_args {
#ifndef HAVE_STATICD_NB
	struct static_route_args_list_item list;
#endif /* !HAVE_STATICD_NB */

	/** "no" command? */
	bool is_delete;
	/** Is VRF obtained from XPath? */
	bool xpath_vrf;

	bool onlink;
	afi_t afi;
	safi_t safi;

	const char *vrf;
	const char *nexthop_vrf;
	const char *prefix;
	const char *prefix_mask;
	const char *source;
	const char *gateway;
	const char *interface_name;
	const char *segs;
	const char *flag;
	const char *tag;
	const char *distance;
	const char *label;
	const char *table;
	const char *color;

	bool bfd;
	bool bfd_multi_hop;
	const char *bfd_source;
	const char *bfd_profile;

	bool bfd_auto_hop;
	bool pm;

#ifndef HAVE_STATICD_NB
	struct prefix p;

	/* Store installed data */
	struct static_nexthop *nh;
#endif /* !HAVE_STATICD_NB */

	const char *srv6_encap_behavior;
};

#ifndef HAVE_STATICD_NB
void static_args_free(struct static_route_args *args);
#endif /* !HAVE_STATICD_NB */

void static_vty_init(void);

#ifdef __cplusplus
}
#endif

#endif
