// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Copyright 2016, LabN Consulting, L.L.C.
 */

#include "lib/zebra.h"

#include "lib/prefix.h"
#include "lib/linklist.h"
#include "lib/stream.h"
#include "lib/command.h"
#include "lib/log.h"
#include "bgpd/rfapi/vnc_debug.h"

/*
 * debug state storage
 */
unsigned long conf_vnc_debug;
unsigned long term_vnc_debug;

struct vnc_debug {
	unsigned long bit;
	const char *name;
};

static const struct vnc_debug vncdebug[] = {
	{VNC_DEBUG_RFAPI_QUERY, "rfapi-query"},
	{VNC_DEBUG_IMPORT_BI_ATTACH, "import-bi-attach"},
	{VNC_DEBUG_IMPORT_DEL_REMOTE, "import-del-remote"},
	{VNC_DEBUG_EXPORT_BGP_GETCE, "export-bgp-getce"},
	{VNC_DEBUG_EXPORT_BGP_DIRECT_ADD, "export-bgp-direct-add"},
	{VNC_DEBUG_IMPORT_BGP_ADD_ROUTE, "import-bgp-add-route"},
	{VNC_DEBUG_VERBOSE, "verbose"},
};

#define VNC_STR "VNC information\n"

/***********************************************************************
 *	debug bgp vnc <foo>
 ***********************************************************************/
DEFUN (debug_bgp_vnc,
       debug_bgp_vnc_cmd,
       "debug bgp vnc <rfapi-query|import-bi-attach|import-del-remote|verbose>",
       DEBUG_STR
       BGP_STR
       VNC_STR
       "rfapi query handling\n"
       "import BI atachment\n"
       "import delete remote routes\n"
       "verbose logging\n")
{
	size_t i;

	for (i = 0; i < (sizeof(vncdebug) / sizeof(struct vnc_debug)); ++i) {
		if (strmatch(argv[3]->text, vncdebug[i].name)) {
			if (vty->node == CONFIG_NODE) {
				conf_vnc_debug |= vncdebug[i].bit;
				term_vnc_debug |= vncdebug[i].bit;
			} else {
				term_vnc_debug |= vncdebug[i].bit;
				vty_out(vty, "BGP vnc %s debugging is on\n",
					vncdebug[i].name);
			}
			return CMD_SUCCESS;
		}
	}
	vty_out(vty, "Unknown debug flag: %s\n", argv[3]->arg);
	return CMD_WARNING_CONFIG_FAILED;
}

DEFUN (no_debug_bgp_vnc,
       no_debug_bgp_vnc_cmd,
       "no debug bgp vnc <rfapi-query|import-bi-attach|import-del-remote|verbose>",
       NO_STR
       DEBUG_STR
       BGP_STR
       VNC_STR
       "rfapi query handling\n"
       "import BI atachment\n"
       "import delete remote routes\n"
       "verbose logging\n")
{
	size_t i;

	for (i = 0; i < (sizeof(vncdebug) / sizeof(struct vnc_debug)); ++i) {
		if (strmatch(argv[argc - 1]->text, vncdebug[i].name)) {
			if (vty->node == CONFIG_NODE) {
				conf_vnc_debug &= ~vncdebug[i].bit;
				term_vnc_debug &= ~vncdebug[i].bit;
			} else {
				term_vnc_debug &= ~vncdebug[i].bit;
				vty_out(vty, "BGP vnc %s debugging is off\n",
					vncdebug[i].name);
			}
			return CMD_SUCCESS;
		}
	}
	vty_out(vty, "Unknown debug flag: %s\n", argv[3]->arg);
	return CMD_WARNING_CONFIG_FAILED;
}

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
	vty_out(vty, "All possible VNC debugging has been turned off\n");

	return CMD_SUCCESS;
}

/***********************************************************************
 *	show/save
 ***********************************************************************/

DEFUN_NOSH (show_debugging_bgp_vnc,
	    show_debugging_bgp_vnc_cmd,
	    "show debugging bgp vnc",
	    SHOW_STR
	    DEBUG_STR
	    BGP_STR
	    VNC_STR)
{
	size_t i;

	vty_out(vty, "BGP VNC debugging status:\n");

	for (i = 0; i < (sizeof(vncdebug) / sizeof(struct vnc_debug)); ++i) {
		if (term_vnc_debug & vncdebug[i].bit) {
			vty_out(vty, "  BGP VNC %s debugging is on\n",
				vncdebug[i].name);
		}
	}
	vty_out(vty, "\n");
	return CMD_SUCCESS;
}

static int bgp_vnc_config_write_debug(struct vty *vty)
{
	int write = 0;
	size_t i;

	for (i = 0; i < array_size(vncdebug); ++i) {
		if (conf_vnc_debug & vncdebug[i].bit) {
			vty_out(vty, "debug bgp vnc %s\n", vncdebug[i].name);
			write++;
		}
	}
	return write;
}

static int bgp_vnc_config_write_debug(struct vty *vty);
static struct cmd_node debug_node = {
	.name = "vnc debug",
	.node = DEBUG_VNC_NODE,
	.prompt = "",
	.config_write = bgp_vnc_config_write_debug,
};

void vnc_debug_init(void)
{
	install_node(&debug_node);
	install_element(ENABLE_NODE, &show_debugging_bgp_vnc_cmd);

	install_element(ENABLE_NODE, &debug_bgp_vnc_cmd);
	install_element(CONFIG_NODE, &debug_bgp_vnc_cmd);
	install_element(ENABLE_NODE, &no_debug_bgp_vnc_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_vnc_cmd);

	install_element(ENABLE_NODE, &no_debug_bgp_vnc_all_cmd);
	install_element(CONFIG_NODE, &no_debug_bgp_vnc_all_cmd);
}
