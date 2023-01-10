// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Link-State VTY
 * Copyright 2023 6WIND S.A.
 */

#include <zebra.h>
#include "command.h"
#include "prefix.h"
#include "lib/json.h"
#include "lib/printfrr.h"
#include "stream.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_linkstate_vty.h"
#include "bgpd/bgp_linkstate.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_debug.h"

#include "bgpd/bgp_linkstate_vty_clippy.c"


DEFPY (debug_bgp_linkstate,
       debug_bgp_linkstate_cmd,
       "[no] debug bgp linkstate",
       NO_STR
       DEBUG_STR
       BGP_STR
       "BGP allow linkstate debugging entries\n")
{
	if (vty->node == CONFIG_NODE) {
		if (no)
			DEBUG_OFF(linkstate, LINKSTATE);
		else
			DEBUG_ON(linkstate, LINKSTATE);
	} else {
		if (no)
			TERM_DEBUG_OFF(linkstate, LINKSTATE);
		else
			TERM_DEBUG_ON(linkstate, LINKSTATE);
		vty_out(vty, "BGP linkstate debugging is %s\n",
			no ? "off" : "on");
	}

	return CMD_SUCCESS;
}


void bgp_linkstate_vty_init(void)
{
	install_element(ENABLE_NODE, &debug_bgp_linkstate_cmd);
	install_element(CONFIG_NODE, &debug_bgp_linkstate_cmd);
}
