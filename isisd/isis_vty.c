/*
 * IS-IS Rout(e)ing protocol - isis_circuit.h
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology      
 *                           Institute of Communications Engineering
 * Copyright (C) 2016        David Lamparter, for NetDEF, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public Licenseas published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.

 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <zebra.h>
#include <command.h>

#include "isis_circuit.h"
#include "isis_csm.h"
#include "isis_misc.h"
#include "isisd.h"

static struct isis_circuit *
isis_circuit_lookup (struct vty *vty)
{
  struct interface *ifp;
  struct isis_circuit *circuit;

  ifp = (struct interface *) vty->index;
  if (!ifp)
    {
      vty_out (vty, "Invalid interface %s", VTY_NEWLINE);
      return NULL;
    }

  circuit = circuit_scan_by_ifp (ifp);
  if (!circuit)
    {
      vty_out (vty, "ISIS is not enabled on circuit %s%s",
               ifp->name, VTY_NEWLINE);
      return NULL;
    }

  return circuit;
}

DEFUN (ip_router_isis,
       ip_router_isis_cmd,
       "(ip|ipv6) router isis WORD",
       "Interface Internet Protocol config commands\n"
       "IP router interface commands\n"
       "IS-IS Routing for IP\n"
       "Routing process tag\n")
{
  struct interface *ifp;
  struct isis_circuit *circuit;
  struct isis_area *area;
  const char *af = argv[0];
  const char *area_tag = argv[1];

  ifp = (struct interface *) vty->index;
  assert (ifp);

  /* Prevent more than one area per circuit */
  circuit = circuit_scan_by_ifp (ifp);
  if (circuit)
    {
      if (circuit->ip_router == 1)
        {
          if (strcmp (circuit->area->area_tag, area_tag))
            {
              vty_out (vty, "ISIS circuit is already defined on %s%s",
                       circuit->area->area_tag, VTY_NEWLINE);
              return CMD_ERR_NOTHING_TODO;
            }
          return CMD_SUCCESS;
        }
    }

  area = isis_area_lookup (area_tag);
  if (!area)
    area = isis_area_create (area_tag);

  if (!circuit)
    circuit = isis_circuit_create (area, ifp);

  bool ip = circuit->ip_router, ipv6 = circuit->ipv6_router;
  if (af[2] != '\0')
    ipv6 = true;
  else
    ip = true;

  isis_circuit_af_set (circuit, ip, ipv6);
  return CMD_SUCCESS;
}

DEFUN (no_ip_router_isis,
       no_ip_router_isis_cmd,
       "no (ip|ipv6) router isis WORD",
       NO_STR
       "Interface Internet Protocol config commands\n"
       "IP router interface commands\n"
       "IS-IS Routing for IP\n"
       "Routing process tag\n")
{
  struct interface *ifp;
  struct isis_area *area;
  struct isis_circuit *circuit;
  const char *af = argv[0];
  const char *area_tag = argv[1];

  ifp = (struct interface *) vty->index;
  if (!ifp)
    {
      vty_out (vty, "Invalid interface %s", VTY_NEWLINE);
      return CMD_ERR_NO_MATCH;
    }

  area = isis_area_lookup (area_tag);
  if (!area)
    {
      vty_out (vty, "Can't find ISIS instance %s%s",
               argv[0], VTY_NEWLINE);
      return CMD_ERR_NO_MATCH;
    }

  circuit = circuit_lookup_by_ifp (ifp, area->circuit_list);
  if (!circuit)
    {
      vty_out (vty, "ISIS is not enabled on circuit %s%s",
               ifp->name, VTY_NEWLINE);
      return CMD_ERR_NO_MATCH;
    }

  bool ip = circuit->ip_router, ipv6 = circuit->ipv6_router;
  if (af[2] != '\0')
    ipv6 = false;
  else
    ip = false;

  isis_circuit_af_set (circuit, ip, ipv6);
  return CMD_SUCCESS;
}

DEFUN (isis_passive,
       isis_passive_cmd,
       "isis passive",
       "IS-IS commands\n"
       "Configure the passive mode for interface\n")
{
  struct isis_circuit *circuit = isis_circuit_lookup (vty);
  if (!circuit)
    return CMD_ERR_NO_MATCH;

  isis_circuit_passive_set (circuit, 1);
  return CMD_SUCCESS;
}

DEFUN (no_isis_passive,
       no_isis_passive_cmd,
       "no isis passive",
       NO_STR
       "IS-IS commands\n"
       "Configure the passive mode for interface\n")
{
  struct isis_circuit *circuit = isis_circuit_lookup (vty);
  if (!circuit)
    return CMD_ERR_NO_MATCH;

  if (if_is_loopback (circuit->interface))
    {
      vty_out (vty, "Can't set no passive for loopback interface%s",
               VTY_NEWLINE);
      return CMD_ERR_AMBIGUOUS;
    }

  isis_circuit_passive_set (circuit, 0);
  return CMD_SUCCESS;
}

DEFUN (isis_circuit_type,
       isis_circuit_type_cmd,
       "isis circuit-type (level-1|level-1-2|level-2-only)",
       "IS-IS commands\n"
       "Configure circuit type for interface\n"
       "Level-1 only adjacencies are formed\n"
       "Level-1-2 adjacencies are formed\n"
       "Level-2 only adjacencies are formed\n")
{
  int is_type;
  struct isis_circuit *circuit = isis_circuit_lookup (vty);
  if (!circuit)
    return CMD_ERR_NO_MATCH;

  is_type = string2circuit_t (argv[0]);
  if (!is_type)
    {
      vty_out (vty, "Unknown circuit-type %s", VTY_NEWLINE);
      return CMD_ERR_AMBIGUOUS;
    }

  if (circuit->state == C_STATE_UP &&
      circuit->area->is_type != IS_LEVEL_1_AND_2 &&
      circuit->area->is_type != is_type)
    {
      vty_out (vty, "Invalid circuit level for area %s.%s",
               circuit->area->area_tag, VTY_NEWLINE);
      return CMD_ERR_AMBIGUOUS;
    }
  isis_circuit_is_type_set (circuit, is_type);

  return CMD_SUCCESS;
}

DEFUN (no_isis_circuit_type,
       no_isis_circuit_type_cmd,
       "no isis circuit-type (level-1|level-1-2|level-2-only)",
       NO_STR
       "IS-IS commands\n"
       "Configure circuit type for interface\n"
       "Level-1 only adjacencies are formed\n"
       "Level-1-2 adjacencies are formed\n"
       "Level-2 only adjacencies are formed\n")
{
  int is_type;
  struct isis_circuit *circuit = isis_circuit_lookup (vty);
  if (!circuit)
    return CMD_ERR_NO_MATCH;

  /*
   * Set the circuits level to its default value
   */
  if (circuit->state == C_STATE_UP)
    is_type = circuit->area->is_type;
  else
    is_type = IS_LEVEL_1_AND_2;
  isis_circuit_is_type_set (circuit, is_type);

  return CMD_SUCCESS;
}

DEFUN (isis_network,
       isis_network_cmd,
       "isis network point-to-point",
       "IS-IS commands\n"
       "Set network type\n"
       "point-to-point network type\n")
{
  struct isis_circuit *circuit = isis_circuit_lookup (vty);
  if (!circuit)
    return CMD_ERR_NO_MATCH;

  if (!isis_circuit_circ_type_set(circuit, CIRCUIT_T_P2P))
    {
      vty_out (vty, "isis network point-to-point "
               "is valid only on broadcast interfaces%s",
               VTY_NEWLINE);
      return CMD_ERR_AMBIGUOUS;
    }

  return CMD_SUCCESS;
}

DEFUN (no_isis_network,
       no_isis_network_cmd,
       "no isis network point-to-point",
       NO_STR
       "IS-IS commands\n"
       "Set network type for circuit\n"
       "point-to-point network type\n")
{
  struct isis_circuit *circuit = isis_circuit_lookup (vty);
  if (!circuit)
    return CMD_ERR_NO_MATCH;

  if (!isis_circuit_circ_type_set(circuit, CIRCUIT_T_BROADCAST))
    {
      vty_out (vty, "isis network point-to-point "
               "is valid only on broadcast interfaces%s",
               VTY_NEWLINE);
      return CMD_ERR_AMBIGUOUS;
    }

  return CMD_SUCCESS;
}

DEFUN (isis_priority,
       isis_priority_cmd,
       "isis priority <0-127>",
       "IS-IS commands\n"
       "Set priority for Designated Router election\n"
       "Priority value\n")
{
  int prio;
  struct isis_circuit *circuit = isis_circuit_lookup (vty);
  if (!circuit)
    return CMD_ERR_NO_MATCH;

  prio = atoi (argv[0]);
  if (prio < MIN_PRIORITY || prio > MAX_PRIORITY)
    {
      vty_out (vty, "Invalid priority %d - should be <0-127>%s",
               prio, VTY_NEWLINE);
      return CMD_ERR_AMBIGUOUS;
    }

  circuit->priority[0] = prio;
  circuit->priority[1] = prio;

  return CMD_SUCCESS;
}

DEFUN (no_isis_priority,
       no_isis_priority_cmd,
       "no isis priority",
       NO_STR
       "IS-IS commands\n"
       "Set priority for Designated Router election\n")
{
  struct isis_circuit *circuit = isis_circuit_lookup (vty);
  if (!circuit)
    return CMD_ERR_NO_MATCH;

  circuit->priority[0] = DEFAULT_PRIORITY;
  circuit->priority[1] = DEFAULT_PRIORITY;

  return CMD_SUCCESS;
}

ALIAS (no_isis_priority,
       no_isis_priority_arg_cmd,
       "no isis priority <0-127>",
       NO_STR
       "IS-IS commands\n"
       "Set priority for Designated Router election\n"
       "Priority value\n")

DEFUN (isis_priority_l1,
       isis_priority_l1_cmd,
       "isis priority <0-127> level-1",
       "IS-IS commands\n"
       "Set priority for Designated Router election\n"
       "Priority value\n"
       "Specify priority for level-1 routing\n")
{
  int prio;
  struct isis_circuit *circuit = isis_circuit_lookup (vty);
  if (!circuit)
    return CMD_ERR_NO_MATCH;

  prio = atoi (argv[0]);
  if (prio < MIN_PRIORITY || prio > MAX_PRIORITY)
    {
      vty_out (vty, "Invalid priority %d - should be <0-127>%s",
               prio, VTY_NEWLINE);
      return CMD_ERR_AMBIGUOUS;
    }

  circuit->priority[0] = prio;

  return CMD_SUCCESS;
}

DEFUN (no_isis_priority_l1,
       no_isis_priority_l1_cmd,
       "no isis priority level-1",
       NO_STR
       "IS-IS commands\n"
       "Set priority for Designated Router election\n"
       "Specify priority for level-1 routing\n")
{
  struct isis_circuit *circuit = isis_circuit_lookup (vty);
  if (!circuit)
    return CMD_ERR_NO_MATCH;

  circuit->priority[0] = DEFAULT_PRIORITY;

  return CMD_SUCCESS;
}

ALIAS (no_isis_priority_l1,
       no_isis_priority_l1_arg_cmd,
       "no isis priority <0-127> level-1",
       NO_STR
       "IS-IS commands\n"
       "Set priority for Designated Router election\n"
       "Priority value\n"
       "Specify priority for level-1 routing\n")

DEFUN (isis_priority_l2,
       isis_priority_l2_cmd,
       "isis priority <0-127> level-2",
       "IS-IS commands\n"
       "Set priority for Designated Router election\n"
       "Priority value\n"
       "Specify priority for level-2 routing\n")
{
  int prio;
  struct isis_circuit *circuit = isis_circuit_lookup (vty);
  if (!circuit)
    return CMD_ERR_NO_MATCH;

  prio = atoi (argv[0]);
  if (prio < MIN_PRIORITY || prio > MAX_PRIORITY)
    {
      vty_out (vty, "Invalid priority %d - should be <0-127>%s",
               prio, VTY_NEWLINE);
      return CMD_ERR_AMBIGUOUS;
    }

  circuit->priority[1] = prio;

  return CMD_SUCCESS;
}

DEFUN (no_isis_priority_l2,
       no_isis_priority_l2_cmd,
       "no isis priority level-2",
       NO_STR
       "IS-IS commands\n"
       "Set priority for Designated Router election\n"
       "Specify priority for level-2 routing\n")
{
  struct isis_circuit *circuit = isis_circuit_lookup (vty);
  if (!circuit)
    return CMD_ERR_NO_MATCH;

  circuit->priority[1] = DEFAULT_PRIORITY;

  return CMD_SUCCESS;
}

ALIAS (no_isis_priority_l2,
       no_isis_priority_l2_arg_cmd,
       "no isis priority <0-127> level-2",
       NO_STR
       "IS-IS commands\n"
       "Set priority for Designated Router election\n"
       "Priority value\n"
       "Specify priority for level-2 routing\n")

/* Metric command */
DEFUN (isis_metric,
       isis_metric_cmd,
       "isis metric <0-16777215>",
       "IS-IS commands\n"
       "Set default metric for circuit\n"
       "Default metric value\n")
{
  int met;
  struct isis_circuit *circuit = isis_circuit_lookup (vty);
  if (!circuit)
    return CMD_ERR_NO_MATCH;

  met = atoi (argv[0]);

  /* RFC3787 section 5.1 */
  if (circuit->area && circuit->area->oldmetric == 1 &&
      met > MAX_NARROW_LINK_METRIC)
    {
      vty_out (vty, "Invalid metric %d - should be <0-63> "
               "when narrow metric type enabled%s",
               met, VTY_NEWLINE);
      return CMD_ERR_AMBIGUOUS;
    }

  /* RFC4444 */
  if (circuit->area && circuit->area->newmetric == 1 &&
      met > MAX_WIDE_LINK_METRIC)
    {
      vty_out (vty, "Invalid metric %d - should be <0-16777215> "
               "when wide metric type enabled%s",
               met, VTY_NEWLINE);
      return CMD_ERR_AMBIGUOUS;
    }

  isis_circuit_metric_set (circuit, IS_LEVEL_1, met);
  isis_circuit_metric_set (circuit, IS_LEVEL_2, met);
  return CMD_SUCCESS;
}

DEFUN (no_isis_metric,
       no_isis_metric_cmd,
       "no isis metric",
       NO_STR
       "IS-IS commands\n"
       "Set default metric for circuit\n")
{
  struct isis_circuit *circuit = isis_circuit_lookup (vty);
  if (!circuit)
    return CMD_ERR_NO_MATCH;

  isis_circuit_metric_set (circuit, IS_LEVEL_1, DEFAULT_CIRCUIT_METRIC);
  isis_circuit_metric_set (circuit, IS_LEVEL_2, DEFAULT_CIRCUIT_METRIC);
  return CMD_SUCCESS;
}

ALIAS (no_isis_metric,
       no_isis_metric_arg_cmd,
       "no isis metric <0-16777215>",
       NO_STR
       "IS-IS commands\n"
       "Set default metric for circuit\n"
       "Default metric value\n")

DEFUN (isis_metric_l1,
       isis_metric_l1_cmd,
       "isis metric <0-16777215> level-1",
       "IS-IS commands\n"
       "Set default metric for circuit\n"
       "Default metric value\n"
       "Specify metric for level-1 routing\n")
{
  int met;
  struct isis_circuit *circuit = isis_circuit_lookup (vty);
  if (!circuit)
    return CMD_ERR_NO_MATCH;

  met = atoi (argv[0]);

  /* RFC3787 section 5.1 */
  if (circuit->area && circuit->area->oldmetric == 1 &&
      met > MAX_NARROW_LINK_METRIC)
    {
      vty_out (vty, "Invalid metric %d - should be <0-63> "
               "when narrow metric type enabled%s",
               met, VTY_NEWLINE);
      return CMD_ERR_AMBIGUOUS;
    }

  /* RFC4444 */
  if (circuit->area && circuit->area->newmetric == 1 &&
      met > MAX_WIDE_LINK_METRIC)
    {
      vty_out (vty, "Invalid metric %d - should be <0-16777215> "
               "when wide metric type enabled%s",
               met, VTY_NEWLINE);
      return CMD_ERR_AMBIGUOUS;
    }

  isis_circuit_metric_set (circuit, IS_LEVEL_1, met);
  return CMD_SUCCESS;
}

DEFUN (no_isis_metric_l1,
       no_isis_metric_l1_cmd,
       "no isis metric level-1",
       NO_STR
       "IS-IS commands\n"
       "Set default metric for circuit\n"
       "Specify metric for level-1 routing\n")
{
  struct isis_circuit *circuit = isis_circuit_lookup (vty);
  if (!circuit)
    return CMD_ERR_NO_MATCH;

  isis_circuit_metric_set (circuit, IS_LEVEL_1, DEFAULT_CIRCUIT_METRIC);
  return CMD_SUCCESS;
}

ALIAS (no_isis_metric_l1,
       no_isis_metric_l1_arg_cmd,
       "no isis metric <0-16777215> level-1",
       NO_STR
       "IS-IS commands\n"
       "Set default metric for circuit\n"
       "Default metric value\n"
       "Specify metric for level-1 routing\n")

DEFUN (isis_metric_l2,
       isis_metric_l2_cmd,
       "isis metric <0-16777215> level-2",
       "IS-IS commands\n"
       "Set default metric for circuit\n"
       "Default metric value\n"
       "Specify metric for level-2 routing\n")
{
  int met;
  struct isis_circuit *circuit = isis_circuit_lookup (vty);
  if (!circuit)
    return CMD_ERR_NO_MATCH;

  met = atoi (argv[0]);

  /* RFC3787 section 5.1 */
  if (circuit->area && circuit->area->oldmetric == 1 &&
      met > MAX_NARROW_LINK_METRIC)
    {
      vty_out (vty, "Invalid metric %d - should be <0-63> "
               "when narrow metric type enabled%s",
               met, VTY_NEWLINE);
      return CMD_ERR_AMBIGUOUS;
    }

  /* RFC4444 */
  if (circuit->area && circuit->area->newmetric == 1 &&
      met > MAX_WIDE_LINK_METRIC)
    {
      vty_out (vty, "Invalid metric %d - should be <0-16777215> "
               "when wide metric type enabled%s",
               met, VTY_NEWLINE);
      return CMD_ERR_AMBIGUOUS;
    }

  isis_circuit_metric_set (circuit, IS_LEVEL_2, met);
  return CMD_SUCCESS;
}

DEFUN (no_isis_metric_l2,
       no_isis_metric_l2_cmd,
       "no isis metric level-2",
       NO_STR
       "IS-IS commands\n"
       "Set default metric for circuit\n"
       "Specify metric for level-2 routing\n")
{
  struct isis_circuit *circuit = isis_circuit_lookup (vty);
  if (!circuit)
    return CMD_ERR_NO_MATCH;

  isis_circuit_metric_set (circuit, IS_LEVEL_2, DEFAULT_CIRCUIT_METRIC);
  return CMD_SUCCESS;
}

ALIAS (no_isis_metric_l2,
       no_isis_metric_l2_arg_cmd,
       "no isis metric <0-16777215> level-2",
       NO_STR
       "IS-IS commands\n"
       "Set default metric for circuit\n"
       "Default metric value\n"
       "Specify metric for level-2 routing\n")
/* end of metrics */

void
isis_vty_init (void)
{
  install_element (INTERFACE_NODE, &ip_router_isis_cmd);
  install_element (INTERFACE_NODE, &no_ip_router_isis_cmd);

  install_element (INTERFACE_NODE, &isis_passive_cmd);
  install_element (INTERFACE_NODE, &no_isis_passive_cmd);

  install_element (INTERFACE_NODE, &isis_circuit_type_cmd);
  install_element (INTERFACE_NODE, &no_isis_circuit_type_cmd);

  install_element (INTERFACE_NODE, &isis_network_cmd);
  install_element (INTERFACE_NODE, &no_isis_network_cmd);

  install_element (INTERFACE_NODE, &isis_priority_cmd);
  install_element (INTERFACE_NODE, &no_isis_priority_cmd);
  install_element (INTERFACE_NODE, &no_isis_priority_arg_cmd);
  install_element (INTERFACE_NODE, &isis_priority_l1_cmd);
  install_element (INTERFACE_NODE, &no_isis_priority_l1_cmd);
  install_element (INTERFACE_NODE, &no_isis_priority_l1_arg_cmd);
  install_element (INTERFACE_NODE, &isis_priority_l2_cmd);
  install_element (INTERFACE_NODE, &no_isis_priority_l2_cmd);
  install_element (INTERFACE_NODE, &no_isis_priority_l2_arg_cmd);

  install_element (INTERFACE_NODE, &isis_metric_cmd);
  install_element (INTERFACE_NODE, &no_isis_metric_cmd);
  install_element (INTERFACE_NODE, &no_isis_metric_arg_cmd);
  install_element (INTERFACE_NODE, &isis_metric_l1_cmd);
  install_element (INTERFACE_NODE, &no_isis_metric_l1_cmd);
  install_element (INTERFACE_NODE, &no_isis_metric_l1_arg_cmd);
  install_element (INTERFACE_NODE, &isis_metric_l2_cmd);
  install_element (INTERFACE_NODE, &no_isis_metric_l2_cmd);
  install_element (INTERFACE_NODE, &no_isis_metric_l2_arg_cmd);
}
