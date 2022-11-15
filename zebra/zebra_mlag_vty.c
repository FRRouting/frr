/* Zebra Mlag vty Code.
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *                    Donald Sharp
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include <zebra.h>

#include "vty.h"
#include "command.h"

#include "zebra_router.h"
#include "zebra_mlag_vty.h"
#include "debug.h"
#include "zapi_msg.h"

#include "zebra/zebra_mlag_vty_clippy.c"

DEFUN_HIDDEN (show_mlag,
	      show_mlag_cmd,
	      "show zebra mlag",
	      SHOW_STR
	      ZEBRA_STR
	      "The mlag role on this machine\n")
{
	char buf[MLAG_ROLE_STRSIZE];

	vty_out(vty, "MLag is configured to: %s\n",
		mlag_role2str(zrouter.mlag_info.role, buf, sizeof(buf)));

	return CMD_SUCCESS;
}

DEFPY_HIDDEN(test_mlag, test_mlag_cmd,
	     "test zebra mlag <none$none|primary$primary|secondary$secondary>",
	     "Test code\n"
	     ZEBRA_STR
	     "Modify the Mlag state\n"
	     "Mlag is not setup on the machine\n"
	     "Mlag is setup to be primary\n"
	     "Mlag is setup to be the secondary\n")
{
	return zebra_mlag_test_mlag_internal(none, primary, secondary);
}

void zebra_mlag_vty_init(void)
{
	install_element(VIEW_NODE, &show_mlag_cmd);
	install_element(ENABLE_NODE, &test_mlag_cmd);
}
