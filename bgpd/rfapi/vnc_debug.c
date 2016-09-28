/* 
 *
 * Copyright 2016, LabN Consulting, L.L.C.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#include "lib/zebra.h"

#include <lib/version.h>
#include "lib/prefix.h"
#include "lib/linklist.h"
#include "lib/stream.h"
#include "lib/command.h"
#include "lib/str.h"
#include "lib/log.h"
#include "bgpd/rfapi/vnc_debug.h"

/*
 * debug state storage
 */
unsigned long conf_vnc_debug;
unsigned long term_vnc_debug;

struct vnc_debug {
    unsigned long	bit;
    const char		*name;
};

struct vnc_debug	vncdebug[] =
{
    {VNC_DEBUG_RFAPI_QUERY,		"rfapi-query"},
    {VNC_DEBUG_IMPORT_BI_ATTACH,	"import-bi-attach"},
    {VNC_DEBUG_IMPORT_DEL_REMOTE,	"import-del-remote"},
    {VNC_DEBUG_EXPORT_BGP_GETCE,	"export-bgp-getce"},
    {VNC_DEBUG_EXPORT_BGP_DIRECT_ADD,	"export-bgp-direct-add"},
    {VNC_DEBUG_IMPORT_BGP_ADD_ROUTE,	"import-bgp-add-route"},
};

#define VNC_STR "VNC information\n"

/***********************************************************************
 *	debug bgp vnc <foo>
 ***********************************************************************/
DEFUN (debug_bgp_vnc,
       debug_bgp_vnc_cmd,
       "debug bgp vnc (rfapi-query|import-bi-attach|import-del-remote)",
       DEBUG_STR
       BGP_STR
       VNC_STR
       "rfapi query handling\n"
       "import BI atachment\n"
       "import delete remote routes\n")
{
  size_t	i;

  for (i = 0; i < (sizeof(vncdebug) / sizeof(struct vnc_debug)); ++i)
    {
      if (!strcmp(argv[0], vncdebug[i].name))
	{
	  if (vty->node == CONFIG_NODE)
	    {
	      conf_vnc_debug |= vncdebug[i].bit;
	      term_vnc_debug |= vncdebug[i].bit;
	    }
	  else
	    {
	      term_vnc_debug |= vncdebug[i].bit;
	      vty_out (vty, "BGP vnc %s debugging is on%s",
		vncdebug[i].name, VTY_NEWLINE);
	    }
	  return CMD_SUCCESS;
	}
    }
  vty_out (vty, "Unknown debug flag: %s%s", argv[0], VTY_NEWLINE);
  return CMD_WARNING;
}

DEFUN (no_debug_bgp_vnc,
       no_debug_bgp_vnc_cmd,
       "no debug bgp vnc (rfapi-query|import-bi-attach|import-del-remote)",
       NO_STR
       DEBUG_STR
       BGP_STR
       VNC_STR
       "rfapi query handling\n"
       "import BI atachment\n"
       "import delete remote routes\n")
{
  size_t	i;

  for (i = 0; i < (sizeof(vncdebug) / sizeof(struct vnc_debug)); ++i)
    {
      if (!strcmp(argv[0], vncdebug[i].name))
	{
	  if (vty->node == CONFIG_NODE)
	    {
	      conf_vnc_debug &= ~vncdebug[i].bit;
	      term_vnc_debug &= ~vncdebug[i].bit;
	    }
	  else
	    {
	      term_vnc_debug &= ~vncdebug[i].bit;
	      vty_out (vty, "BGP vnc %s debugging is off%s",
		vncdebug[i].name, VTY_NEWLINE);
	    }
	  return CMD_SUCCESS;
	}
    }
  vty_out (vty, "Unknown debug flag: %s%s", argv[0], VTY_NEWLINE);
  return CMD_WARNING;
}

ALIAS (no_debug_bgp_vnc,
       undebug_bgp_vnc_cmd,
       "undebug bgp vnc (rfapi-query|import-bi-attach|import-del-remote)",
       UNDEBUG_STR
       BGP_STR
       VNC_STR
       "rfapi query handling\n"
       "import BI atachment\n"
       "import delete remote routes\n")


/***********************************************************************
 *	no debug bgp vnc all
 ***********************************************************************/

DEFUN (no_debug_bgp_vnc_all,
       no_debug_bgp_vnc_all_cmd,
       "no debug all bgp vnc",
       NO_STR
       DEBUG_STR
       "Disable all VNC debugging\n"
       BGP_STR
       VNC_STR)
{
  term_vnc_debug = 0;
  vty_out (vty, "All possible VNC debugging has been turned off%s", VTY_NEWLINE);
      
  return CMD_SUCCESS;
}

ALIAS (no_debug_bgp_vnc_all,
       undebug_bgp_vnc_all_cmd,
       "undebug all bgp vnc",
       UNDEBUG_STR
       "Disable all VNC debugging\n"
       BGP_STR
       VNC_STR)

/***********************************************************************
 *	show/save
 ***********************************************************************/

DEFUN (show_debugging_bgp_vnc,
       show_debugging_bgp_vnc_cmd,
       "show debugging bgp vnc",
       SHOW_STR
       DEBUG_STR
       BGP_STR
       VNC_STR)
{
  size_t	i;

  vty_out (vty, "BGP VNC debugging status:%s", VTY_NEWLINE);

  for (i = 0; i < (sizeof(vncdebug) / sizeof(struct vnc_debug)); ++i)
    {
      if (term_vnc_debug & vncdebug[i].bit)
	{
	  vty_out (vty, "  BGP VNC %s debugging is on%s",
	    vncdebug[i].name, VTY_NEWLINE);
	}
    }
  vty_out (vty, "%s", VTY_NEWLINE);
  return CMD_SUCCESS;
}

static int
bgp_vnc_config_write_debug (struct vty *vty)
{
  int write = 0;
  size_t	i;

  for (i = 0; i < (sizeof(vncdebug) / sizeof(struct vnc_debug)); ++i)
    {
      if (conf_vnc_debug & vncdebug[i].bit)
	{
	  vty_out (vty, "debug bgp vnc %s%s", vncdebug[i].name, VTY_NEWLINE);
	  write++;
	}
    }
  return write;
}

static struct cmd_node debug_node =
{
  DEBUG_VNC_NODE,
  "",
  1
};

void
vnc_debug_init (void)
{
  install_node (&debug_node, bgp_vnc_config_write_debug);
  install_element (ENABLE_NODE, &show_debugging_bgp_vnc_cmd);

  install_element (ENABLE_NODE, &debug_bgp_vnc_cmd);
  install_element (CONFIG_NODE, &debug_bgp_vnc_cmd);
  install_element (ENABLE_NODE, &no_debug_bgp_vnc_cmd);
  install_element (ENABLE_NODE, &undebug_bgp_vnc_cmd);

  install_element (ENABLE_NODE, &no_debug_bgp_vnc_all_cmd);
  install_element (ENABLE_NODE, &undebug_bgp_vnc_all_cmd);
}
