// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * September 9 2024, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2024, LabN Consulting, L.L.C.
 */

#include <lib/libfrr.h>
#include <lib/zebra.h>
#include <lib/privs.h>
#include <lib/version.h>

zebra_capabilities_t _caps_p[] = {ZCAP_NET_RAW, ZCAP_BIND, ZCAP_SYS_ADMIN};

struct zebra_privs_t rustbind_privs = {
#if defined(FRR_USER)
	.user = FRR_USER,
#endif
#if defined FRR_GROUP
	.group = FRR_GROUP,
#endif
#ifdef VTY_GROUP
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0
};


static const struct frr_yang_module_info *const rustbind_yang_modules[] = {};

/* clang-format off */
FRR_DAEMON_INFO(rustbind, RUST,
		.vty_port = RUSTBIND_VTY_PORT,
		.proghelp = "Implementation of the RUST daemon template.",

		.privs = &rustbind_privs,

		.yang_modules = rustbind_yang_modules,
		.n_yang_modules = array_size(rustbind_yang_modules),

		/* mgmtd will load the per-daemon config file now */
		.flags = FRR_NO_SPLIT_CONFIG,
	);
/* clang-format on */

extern struct frr_daemon_info *rust_get_daemon_info(void);

struct frr_daemon_info *rust_get_daemon_info(void)
{
	return &rustbind_di;
}
