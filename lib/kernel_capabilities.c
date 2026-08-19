// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Kernel capabilities
 * Copyright 2026 6WIND S.A.
 */

#include "zebra.h"
#include "kernel_capabilities.h"

static bool seg6_encap_source;
static bool seg6_encap_lookup;

bool kernel_capabilities_has_seg6_encap_source(void)
{
	return seg6_encap_source;
}

bool kernel_capabilities_has_seg6_encap_lookup(void)
{
	return seg6_encap_lookup;
}

void kernel_capabilities_set_seg6_encap_source(bool enabled)
{
	seg6_encap_source = enabled;
}

void kernel_capabilities_set_seg6_encap_lookup(bool enabled)
{
	seg6_encap_lookup = enabled;
}
