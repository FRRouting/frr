// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP BMP northbound — loadable-module ops table.
 * Copyright (C) 2026 FRRouting
 *
 * bgpd_bmp.so assigns bmp_nb_cb at module init.  Without the module, NB
 * APPLY writes to bmp-config are silent no-ops.  Core bgpd must not call
 * into bmp_* symbols; VALIDATE/cli_show stay YANG-only in bgp_nb_config.c.
 */

#ifndef _FRR_BGP_BMP_NB_H_
#define _FRR_BGP_BMP_NB_H_

#include <stdbool.h>
#include <stdint.h>

struct bgp;

/*
 * Opaque bmp_targets handle — only meaningful when bgpd_bmp.so is loaded.
 * Core passes it through nb_running_* without including bgp_bmp.h.
 */
struct bmp_nb_ops {
	int (*mirror_buffer_limit_set)(struct bgp *bgp, uint32_t limit);
	int (*mirror_buffer_limit_unset)(struct bgp *bgp);

	void *(*target_get)(struct bgp *bgp, const char *name);
	void (*target_put)(void *bt);

	void (*target_mirror_set)(void *bt, bool enable);
	void (*target_stats_set)(void *bt, uint32_t msec);
	void (*target_stats_experimental_set)(void *bt, bool enable);
	void (*target_acl_set)(void *bt, bool ipv6, const char *access_list);
};

extern struct bmp_nb_ops *bmp_nb_cb;

#endif /* _FRR_BGP_BMP_NB_H_ */
