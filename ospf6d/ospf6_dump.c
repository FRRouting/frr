/*
 * Logging function
 * Copyright (C) 1999-2002 Yasuhiro Ohara
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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the 
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 * Boston, MA 02111-1307, USA.  
 */

#include <zebra.h>

/* Include other stuffs */
#include "log.h"
#include "command.h"
#include "ospf6_dump.h"

#define CMD_SHOW    0
#define CMD_ENABLE  1
#define CMD_DISABLE 2
#define CMD_MAX     3

struct ospf6_dump
{
  struct cmd_element cmd[CMD_MAX];
  char *name;
  int config;
};

#define DUMP_MAX 512
struct ospf6_dump *ospf6_dump[DUMP_MAX];
unsigned int dump_size = 0;

static int
ospf6_dump_index (struct cmd_element *cmd, int command)
{
  int i;

  for (i = 0; i < DUMP_MAX; i++)
    {
      if (cmd != &ospf6_dump[i]->cmd[command])
        continue;
      break;
    }

  if (i == DUMP_MAX)
    return -1;
  return i;
}

int
ospf6_dump_is_on (int index)
{
  if (ospf6_dump[index] == NULL)
    return 0;

  return ospf6_dump[index]->config;
}

int
ospf6_dump_show (struct cmd_element *cmd,
                 struct vty *vty, int argc, char **argv)
{
  int index;

  index = ospf6_dump_index (cmd, CMD_SHOW);
  assert (index != -1);

  vty_out (vty, "  %-16s: %s%s", ospf6_dump[index]->name,
           (ospf6_dump[index]->config ? "on" : "off"),
           VTY_NEWLINE);
  return CMD_SUCCESS;
}

int
ospf6_dump_enable (struct cmd_element *cmd,
                   struct vty *vty, int argc, char **argv)
{
  int index;

  index = ospf6_dump_index (cmd, CMD_ENABLE);
  assert (index != -1);

  ospf6_dump[index]->config = 1;
  return CMD_SUCCESS;
}

int
ospf6_dump_disable (struct cmd_element *cmd,
                    struct vty *vty, int argc, char **argv)
{
  int index;

  index = ospf6_dump_index (cmd, CMD_DISABLE);
  assert (index != -1);

  ospf6_dump[index]->config = 0;
  return CMD_SUCCESS;
}

int
ospf6_dump_install (char *name, char *help)
{
  struct cmd_element *cmd;
  char string[256];
  char helpstring[256];

  if (dump_size + 1 >= DUMP_MAX)
    return -1;

  ospf6_dump[dump_size] = malloc (sizeof (struct ospf6_dump));
  if (ospf6_dump[dump_size] == NULL)
    return -1;
  memset (ospf6_dump[dump_size], 0, sizeof (struct ospf6_dump));

  ospf6_dump[dump_size]->name = strdup (name);

  cmd = &ospf6_dump[dump_size]->cmd[CMD_SHOW];
  snprintf (string, sizeof (string), "show debugging ospf6 %s", name);
  snprintf (helpstring, sizeof (helpstring), "%s%s%s%s",
            SHOW_STR, DEBUG_STR, OSPF6_STR, help);
  memset (cmd, 0, sizeof (struct cmd_element));
  cmd->string = strdup (string);
  cmd->func = ospf6_dump_show;
  cmd->doc = strdup (helpstring);
  install_element (VIEW_NODE, cmd);
  install_element (ENABLE_NODE, cmd);

  cmd = &ospf6_dump[dump_size]->cmd[CMD_ENABLE];
  snprintf (string, sizeof (string), "debug ospf6 %s", name);
  snprintf (helpstring, sizeof (helpstring), "%s%s%s",
            DEBUG_STR, OSPF6_STR, help);
  memset (cmd, 0, sizeof (struct cmd_element));
  cmd->string = strdup (string);
  cmd->func = ospf6_dump_enable;
  cmd->doc = strdup (helpstring);
  install_element (CONFIG_NODE, cmd);

  cmd = &ospf6_dump[dump_size]->cmd[CMD_DISABLE];
  snprintf (string, sizeof (string), "no debug ospf6 %s", name);
  snprintf (helpstring, sizeof (helpstring), "%s%s%s%s",
            NO_STR, DEBUG_STR, OSPF6_STR, help);
  memset (cmd, 0, sizeof (struct cmd_element));
  cmd->string = strdup (string);
  cmd->func = ospf6_dump_disable;
  cmd->doc = strdup (helpstring);
  install_element (CONFIG_NODE, cmd);

  return dump_size++;
}

DEFUN(show_debug_ospf6,
      show_debug_ospf6_cmd,
      "show debugging ospf6",
      SHOW_STR
      DEBUG_STR
      OSPF6_STR)
{
  int i;

  vty_out (vty, "OSPF6 debugging status:%s", VTY_NEWLINE);

  for (i = 0; i < DUMP_MAX; i++)
    {
      if (ospf6_dump[i] == NULL)
        continue;
      ospf6_dump_show (&ospf6_dump[i]->cmd[CMD_SHOW], vty, 0, NULL);
    }

  return CMD_SUCCESS;
}

DEFUN (debug_ospf6_all,
       debug_ospf6_all_cmd,
       "debug ospf6 all",
       DEBUG_STR
       OSPF6_STR
       "Turn on ALL OSPFv3 debugging\n")
{
  int i;

  for (i = 0; i < DUMP_MAX; i++)
    {
      if (ospf6_dump[i] == NULL)
        continue;
      ospf6_dump_enable (&ospf6_dump[i]->cmd[CMD_ENABLE], vty, 0, NULL);
    }

  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_all,
       no_debug_ospf6_all_cmd,
       "no debug ospf6 all",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Turn off ALL OSPFv3 debugging\n")
{
  int i;

  for (i = 0; i < DUMP_MAX; i++)
    {
      if (ospf6_dump[i] == NULL)
        continue;
      ospf6_dump_disable (&ospf6_dump[i]->cmd[CMD_DISABLE], vty, 0, NULL);
    }

  return CMD_SUCCESS;
}

struct cmd_node debug_node =
{
  DEBUG_NODE,
  ""
};

int
ospf6_dump_config_write (struct vty *vty)
{
  int i;

  for (i = 0; i < dump_size; i++)
    {
      if (ospf6_dump[i] == NULL)
        continue;

      if (ospf6_dump[i]->config == 0)
        continue;

      vty_out (vty, "debug ospf6 %s%s", ospf6_dump[i]->name, VTY_NEWLINE);
    }

  vty_out (vty, "!%s", VTY_NEWLINE);
  return 0;
}

char dump_index[OSPF6_DUMP_MAX];

void
ospf6_dump_init ()
{
  memset (ospf6_dump, 0, sizeof (ospf6_dump));

  install_node (&debug_node, ospf6_dump_config_write);

  install_element (VIEW_NODE,   &show_debug_ospf6_cmd);
  install_element (ENABLE_NODE, &show_debug_ospf6_cmd);

  install_element (CONFIG_NODE, &debug_ospf6_all_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_all_cmd);

  /* bellow is for backward compatibility
     should be moved to each modules */

#define MESSAGE_STR "OSPFv3 Messages\n"

  dump_index[OSPF6_DUMP_HELLO] =
    ospf6_dump_install ("message hello",
                        MESSAGE_STR "Hello\n");
  dump_index[OSPF6_DUMP_DBDESC] =
    ospf6_dump_install ("message dbdesc",
                        MESSAGE_STR "Database Description\n");
  dump_index[OSPF6_DUMP_LSREQ] =
    ospf6_dump_install ("message lsreq",
                        MESSAGE_STR "Link State Request\n");
  dump_index[OSPF6_DUMP_LSUPDATE] =
    ospf6_dump_install ("message lsupdate",
                        MESSAGE_STR "Link State Update\n");
  dump_index[OSPF6_DUMP_LSACK] =
    ospf6_dump_install ("message lsack",
                        MESSAGE_STR "Link State Acknowledge\n");
  dump_index[OSPF6_DUMP_NEIGHBOR] =
    ospf6_dump_install ("neighbor", "Neighbors\n");
  dump_index[OSPF6_DUMP_INTERFACE] =
    ospf6_dump_install ("interface", "Interfaces\n");
  dump_index[OSPF6_DUMP_LSA] =
    ospf6_dump_install ("lsa", "Link State Advertisement\n");
  dump_index[OSPF6_DUMP_ZEBRA] =
    ospf6_dump_install ("zebra", "Communication with zebra\n");
  dump_index[OSPF6_DUMP_CONFIG] =
    ospf6_dump_install ("config", "Configuration Changes\n");
  dump_index[OSPF6_DUMP_DBEX] =
    ospf6_dump_install ("dbex", "Database Exchange/Flooding\n");
  dump_index[OSPF6_DUMP_SPF] =
    ospf6_dump_install ("spf", "SPF Calculation\n");
  dump_index[OSPF6_DUMP_ROUTE] =
    ospf6_dump_install ("route", "Route Calculation\n");
  dump_index[OSPF6_DUMP_LSDB] =
    ospf6_dump_install ("lsdb", "Link State Database\n");
  dump_index[OSPF6_DUMP_REDISTRIBUTE] =
    ospf6_dump_install ("redistribute",
                        "Route Exchange with other protocols\n");
  dump_index[OSPF6_DUMP_HOOK] =
    ospf6_dump_install ("hook", "Hooks\n");
  dump_index[OSPF6_DUMP_ASBR] =
    ospf6_dump_install ("asbr", "AS Boundary Router function\n");
  dump_index[OSPF6_DUMP_PREFIX] =
    ospf6_dump_install ("prefix", "Prefix\n");
}


