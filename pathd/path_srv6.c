// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright 2025 6WIND S.A.
 */

#include "zebra.h"
#include "srv6.h"
#include "pathd.h"

void path_srv6_init(void)
{
	srv6_use_sid_manager = false;
}

void path_srv6_destroy(void)
{
}

void path_srv6_show_running(struct vty *vty)
{
	if (srv6_use_sid_manager)
		vty_out(vty, "  use-srv6-sid-manager\n");
}
