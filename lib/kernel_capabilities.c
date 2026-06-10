// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Kernel capabilities
 * Copyright 2026 6WIND S.A.
 */

#include "zebra.h"
#include "kernel_capabilities.h"

static bool check_srv6_seg6local_dt6_vrftable_attr_supported;
static bool check_srv6_seg6_source_encap_attr_supported;

bool kernel_capabilities_is_srv6_seg6local_dt6_vrftable_attr_supported(void)
{
	return check_srv6_seg6local_dt6_vrftable_attr_supported;
}

bool kernel_capabilities_is_srv6_seg6_source_encap_attr_supported(void)
{
	return check_srv6_seg6_source_encap_attr_supported;
}

void kernel_capabilities_set_srv6_seg6local_dt6_vrftable_attr_supported(bool enabled)
{
	check_srv6_seg6local_dt6_vrftable_attr_supported = enabled;
}

void kernel_capabilities_set_srv6_seg6_source_encap_attr_supported(bool enabled)
{
	check_srv6_seg6_source_encap_attr_supported = enabled;
}
