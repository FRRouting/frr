/*
 * March 15 2025, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2025, LabN Consulting, L.L.C.
 *
 */
#include <zebra.h>
#include "ospf_nb.h"
#include "ospfd/ospf_cli_clippy.c"

/*
 * XXX Add YANG based CLI config writing functions here.
 */

#if 0
static void lib_interface_ospf_interface_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static void ospf_instance_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}

static void ospf_instance_areas_area_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */
}
#endif

/* clang-format off */
const struct frr_yang_module_info frr_ospfd_lite_cli_info = {
        .name = "frr-ospfd-lite",
	.ignore_cfg_cbs = true,
        .nodes = {
#if 0
                {
                        .xpath = "/frr-interface:lib/interface/frr-ospfd-lite:ospf-interface",
                        .cbs = {
                                .cli_show = lib_interface_ospf_interface_cli_write,
                        }
                },
                {
                        .xpath = "/frr-ospfd-lite:ospf/instance",
                        .cbs = {
                                .cli_show = ospf_instance_cli_write,
                        }
                },
                {
                        .xpath = "/frr-ospfd-lite:ospf/instance/areas/area",
                        .cbs = {
                                .cli_show = ospf_instance_areas_area_cli_write,
                        }
                },
#endif
                {
                        .xpath = NULL,
                },
        }
};
/* clang-format on */
