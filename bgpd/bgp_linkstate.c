// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Link-State
 * Copyright 2023 6WIND S.A.
 */

#include <zebra.h>

#include "prefix.h"
#include "lib_errors.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_linkstate.h"
#include "bgpd/bgp_linkstate_tlv.h"


DEFINE_MTYPE_STATIC(BGPD, PTR_LINKSTATE, "Link-State Prefix Pointer");

uintptr_t bgp_linkstate_ptr_new(uint8_t *pnt, uint16_t length)
{
	void *ptr = XCALLOC(MTYPE_PTR_LINKSTATE, length);

	memcpy(ptr, pnt, length);

	return (uintptr_t)ptr;
}

void bgp_linkstate_ptr_free(uintptr_t ptr)
{
	void *tmp;

	tmp = (void *)ptr;

	XFREE(MTYPE_PTR_LINKSTATE, tmp);
}

void bgp_linkstate_init(void)
{
	prefix_set_linkstate_display_hook(bgp_linkstate_nlri_prefix_display);
}
