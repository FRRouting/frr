/*
 * RIPng debug output routines
 * Copyright (C) 1998 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include "command.h"
#include "ripngd/ripng_debug.h"

/* For debug statement. */
unsigned long ripng_debug_event = 0;
unsigned long ripng_debug_packet = 0;
unsigned long ripng_debug_zebra = 0;

DEFUN (show_debugging_ripng,
       show_debugging_ripng_cmd,
       "show debugging ripng",
       SHOW_STR
       DEBUG_STR
       "RIPng configuration\n")
{
  vty_outln (vty, "RIPng debugging status:");

  if (IS_RIPNG_DEBUG_EVENT)
    vty_outln (vty, "  RIPng event debugging is on");

  if (IS_RIPNG_DEBUG_PACKET)
    {
      if (IS_RIPNG_DEBUG_SEND && IS_RIPNG_DEBUG_RECV)
	{
	  vty_outln (vty,"  RIPng packet debugging is on");
	}
      else
	{
	  if (IS_RIPNG_DEBUG_SEND)
	    vty_outln (vty,"  RIPng packet send debugging is on");
	  else
	    vty_outln (vty,"  RIPng packet receive debugging is on");
	}
    }

  if (IS_RIPNG_DEBUG_ZEBRA)
    vty_outln (vty, "  RIPng zebra debugging is on");

  return CMD_SUCCESS;
}

DEFUN (debug_ripng_events,
       debug_ripng_events_cmd,
       "debug ripng events",
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng events\n")
{
  ripng_debug_event = RIPNG_DEBUG_EVENT;
  return CMD_WARNING_CONFIG_FAILED;
}

DEFUN (debug_ripng_packet,
       debug_ripng_packet_cmd,
       "debug ripng packet",
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng packet\n")
{
  ripng_debug_packet = RIPNG_DEBUG_PACKET;
  ripng_debug_packet |= RIPNG_DEBUG_SEND;
  ripng_debug_packet |= RIPNG_DEBUG_RECV;
  return CMD_SUCCESS;
}

DEFUN (debug_ripng_packet_direct,
       debug_ripng_packet_direct_cmd,
       "debug ripng packet <recv|send>",
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng packet\n"
       "Debug option set for receive packet\n"
       "Debug option set for send packet\n")
{
  int idx_recv_send = 3;
  ripng_debug_packet |= RIPNG_DEBUG_PACKET;
  if (strncmp ("send", argv[idx_recv_send]->arg, strlen (argv[idx_recv_send]->arg)) == 0)
    ripng_debug_packet |= RIPNG_DEBUG_SEND;
  if (strncmp ("recv", argv[idx_recv_send]->arg, strlen (argv[idx_recv_send]->arg)) == 0)
    ripng_debug_packet |= RIPNG_DEBUG_RECV;

  return CMD_SUCCESS;
}

DEFUN (debug_ripng_zebra,
       debug_ripng_zebra_cmd,
       "debug ripng zebra",
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng and zebra communication\n")
{
  ripng_debug_zebra = RIPNG_DEBUG_ZEBRA;
  return CMD_WARNING_CONFIG_FAILED;
}

DEFUN (no_debug_ripng_events,
       no_debug_ripng_events_cmd,
       "no debug ripng events",
       NO_STR
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng events\n")
{
  ripng_debug_event = 0;
  return CMD_SUCCESS;
}

DEFUN (no_debug_ripng_packet,
       no_debug_ripng_packet_cmd,
       "no debug ripng packet",
       NO_STR
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng packet\n")
{
  ripng_debug_packet = 0;
  return CMD_SUCCESS;
}

DEFUN (no_debug_ripng_packet_direct,
       no_debug_ripng_packet_direct_cmd,
       "no debug ripng packet <recv|send>",
       NO_STR
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng packet\n"
       "Debug option set for receive packet\n"
       "Debug option set for send packet\n")
{
  int idx_recv_send = 4;
  if (strncmp ("send", argv[idx_recv_send]->arg, strlen (argv[idx_recv_send]->arg)) == 0)
    {
      if (IS_RIPNG_DEBUG_RECV)
       ripng_debug_packet &= ~RIPNG_DEBUG_SEND;
      else
       ripng_debug_packet = 0;
    }
  else if (strncmp ("recv", argv[idx_recv_send]->arg, strlen (argv[idx_recv_send]->arg)) == 0)
    {
      if (IS_RIPNG_DEBUG_SEND)
       ripng_debug_packet &= ~RIPNG_DEBUG_RECV;
      else
       ripng_debug_packet = 0;
    }
  return CMD_SUCCESS;
}

DEFUN (no_debug_ripng_zebra,
       no_debug_ripng_zebra_cmd,
       "no debug ripng zebra",
       NO_STR
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng and zebra communication\n")
{
  ripng_debug_zebra = 0;
  return CMD_WARNING_CONFIG_FAILED;
}

/* Debug node. */
static struct cmd_node debug_node =
{
  DEBUG_NODE,
  "",				/* Debug node has no interface. */
  1 /* VTYSH */
};

static int
config_write_debug (struct vty *vty)
{
  int write = 0;

  if (IS_RIPNG_DEBUG_EVENT)
    {
      vty_outln (vty, "debug ripng events");
      write++;
    }
  if (IS_RIPNG_DEBUG_PACKET)
    {
      if (IS_RIPNG_DEBUG_SEND && IS_RIPNG_DEBUG_RECV)
	{
	  vty_outln (vty,"debug ripng packet");
	  write++;
	}
      else
	{
	  if (IS_RIPNG_DEBUG_SEND)
	    vty_outln (vty,"debug ripng packet send");
	  else
	    vty_outln (vty,"debug ripng packet recv");
	  write++;
	}
    }
  if (IS_RIPNG_DEBUG_ZEBRA)
    {
      vty_outln (vty, "debug ripng zebra");
      write++;
    }
  return write;
}

void
ripng_debug_reset ()
{
  ripng_debug_event = 0;
  ripng_debug_packet = 0;
  ripng_debug_zebra = 0;
}

void
ripng_debug_init ()
{
  ripng_debug_event = 0;
  ripng_debug_packet = 0;
  ripng_debug_zebra = 0;

  install_node (&debug_node, config_write_debug);

  install_element (VIEW_NODE, &show_debugging_ripng_cmd);

  install_element (ENABLE_NODE, &debug_ripng_events_cmd);
  install_element (ENABLE_NODE, &debug_ripng_packet_cmd);
  install_element (ENABLE_NODE, &debug_ripng_packet_direct_cmd);
  install_element (ENABLE_NODE, &debug_ripng_zebra_cmd);
  install_element (ENABLE_NODE, &no_debug_ripng_events_cmd);
  install_element (ENABLE_NODE, &no_debug_ripng_packet_cmd);
  install_element (ENABLE_NODE, &no_debug_ripng_packet_direct_cmd);
  install_element (ENABLE_NODE, &no_debug_ripng_zebra_cmd);

  install_element (CONFIG_NODE, &debug_ripng_events_cmd);
  install_element (CONFIG_NODE, &debug_ripng_packet_cmd);
  install_element (CONFIG_NODE, &debug_ripng_packet_direct_cmd);
  install_element (CONFIG_NODE, &debug_ripng_zebra_cmd);
  install_element (CONFIG_NODE, &no_debug_ripng_events_cmd);
  install_element (CONFIG_NODE, &no_debug_ripng_packet_cmd);
  install_element (CONFIG_NODE, &no_debug_ripng_packet_direct_cmd);
  install_element (CONFIG_NODE, &no_debug_ripng_zebra_cmd);
}
