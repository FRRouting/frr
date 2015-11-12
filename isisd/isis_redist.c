/*
 * IS-IS Rout(e)ing protocol - isis_redist.c
 *
 * Copyright (C) 2013-2015 Christian Franke <chris@opensourcerouting.org>
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public License as published by the Free 
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

#include "command.h"
#include "if.h"
#include "linklist.h"
#include "memory.h"
#include "memtypes.h"
#include "prefix.h"
#include "routemap.h"
#include "stream.h"
#include "table.h"
#include "vty.h"

#include "isisd/dict.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_tlv.h"
#include "isisd/isisd.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_route.h"
#include "isisd/isis_zebra.h"

static int
redist_protocol(int family)
{
  if (family == AF_INET)
    return 0;
  if (family == AF_INET6)
    return 1;

  assert(!"Unsupported address family!");
}

static int
is_default(struct prefix *p)
{
  if (p->family == AF_INET)
    if (p->u.prefix4.s_addr == 0 && p->prefixlen == 0)
      return 1;
  if (p->family == AF_INET6)
    if (IN6_IS_ADDR_UNSPECIFIED(&p->u.prefix6) && p->prefixlen == 0)
      return 1;
  return 0;
}

static struct route_table*
get_ext_info(struct isis *i, int family)
{
  int protocol = redist_protocol(family);

  return i->ext_info[protocol];
}

static struct isis_redist*
get_redist_settings(struct isis_area *area, int family, int type, int level)
{
  int protocol = redist_protocol(family);

  return &area->redist_settings[protocol][type][level-1];
}

struct route_table*
get_ext_reach(struct isis_area *area, int family, int level)
{
  int protocol = redist_protocol(family);

  return area->ext_reach[protocol][level-1];
}

static struct route_node *
isis_redist_route_node_create(route_table_delegate_t *delegate,
                              struct route_table *table)
{
  struct route_node *node;
  node = XCALLOC(MTYPE_ROUTE_NODE, sizeof(*node));
  return node;
}

static void
isis_redist_route_node_destroy(route_table_delegate_t *delegate,
                               struct route_table *table,
                               struct route_node *node)
{
  if (node->info)
    XFREE(MTYPE_ISIS, node->info);
  XFREE (MTYPE_ROUTE_NODE, node);
}

static route_table_delegate_t isis_redist_rt_delegate = {
  .create_node = isis_redist_route_node_create,
  .destroy_node = isis_redist_route_node_destroy
};

/* Install external reachability information into a
 * specific area for a specific level.
 * Schedule an lsp regenerate if necessary */
static void
isis_redist_install(struct isis_area *area, int level,
                    struct prefix *p, struct isis_ext_info *info)
{
  int family = p->family;
  struct route_table *er_table = get_ext_reach(area, family, level);
  struct route_node *er_node;

  if (!er_table)
    {
      zlog_warn("%s: External reachability table of area %s"
                " is not initialized.", __func__, area->area_tag);
      return;
    }

  er_node = route_node_get(er_table, p);
  if (er_node->info)
    {
      route_unlock_node(er_node);

      /* Don't update/reschedule lsp generation if nothing changed. */
      if (!memcmp(er_node->info, info, sizeof(*info)))
        return;
    }
  else
    {
      er_node->info = XMALLOC(MTYPE_ISIS, sizeof(*info));
    }

  memcpy(er_node->info, info, sizeof(*info));
  lsp_regenerate_schedule(area, level, 0);
}

/* Remove external reachability information from a
 * specific area for a specific level.
 * Schedule an lsp regenerate if necessary. */
static void
isis_redist_uninstall(struct isis_area *area, int level, struct prefix *p)
{
  int family = p->family;
  struct route_table *er_table = get_ext_reach(area, family, level);
  struct route_node *er_node;

  if (!er_table)
    {
      zlog_warn("%s: External reachability table of area %s"
                " is not initialized.", __func__, area->area_tag);
      return;
    }

  er_node = route_node_lookup(er_table, p);
  if (!er_node)
    return;
  else
    route_unlock_node(er_node);

  if (!er_node->info)
    return;

  route_unlock_node(er_node);
  lsp_regenerate_schedule(area, level, 0);
}

/* Update external reachability info of area for a given level
 * and prefix, using the given redistribution settings. */
static void
isis_redist_update_ext_reach(struct isis_area *area, int level,
                             struct isis_redist *redist, struct prefix *p,
                             struct isis_ext_info *info)
{
  struct isis_ext_info area_info;
  route_map_result_t map_ret;

  memcpy(&area_info, info, sizeof(area_info));
  if (redist->metric != 0xffffffff)
    area_info.metric = redist->metric;

  if (redist->map_name)
    {
      map_ret = route_map_apply(redist->map, p, RMAP_ISIS, &area_info);
      if (map_ret == RMAP_DENYMATCH)
        area_info.distance = 255;
    }

  /* Allow synthesized default routes only on always orignate */
  if (area_info.origin == DEFAULT_ROUTE
      && redist->redist != DEFAULT_ORIGINATE_ALWAYS)
    area_info.distance = 255;

  if (area_info.distance < 255)
    isis_redist_install(area, level, p, &area_info);
  else
    isis_redist_uninstall(area, level, p);
}

static void
isis_redist_ensure_default(struct isis *isis, int family)
{
  struct prefix p;
  struct route_table *ei_table = get_ext_info(isis, family);
  struct route_node *ei_node;
  struct isis_ext_info *info;

  if (family == AF_INET)
    {
      p.family = AF_INET;
      p.prefixlen = 0;
      memset(&p.u.prefix4, 0, sizeof(p.u.prefix4));
    }
  else if (family == AF_INET6)
    {
      p.family = AF_INET6;
      p.prefixlen = 0;
      memset(&p.u.prefix6, 0, sizeof(p.u.prefix6));
    }
  else
    assert(!"Unknown family!");

  ei_node = route_node_get(ei_table, &p);
  if (ei_node->info)
    {
      route_unlock_node(ei_node);
      return;
    }

  ei_node->info = XCALLOC(MTYPE_ISIS, sizeof(struct isis_ext_info));

  info = ei_node->info;
  info->origin = DEFAULT_ROUTE;
  info->distance = 254;
  info->metric = MAX_WIDE_PATH_METRIC;
}

/* Handle notification about route being added */
void
isis_redist_add(int type, struct prefix *p, u_char distance, uint32_t metric)
{
  int family = p->family;
  struct route_table *ei_table = get_ext_info(isis, family);
  struct route_node *ei_node;
  struct isis_ext_info *info;
  struct listnode *node;
  struct isis_area *area;
  int level;
  struct isis_redist *redist;

  char debug_buf[BUFSIZ];
  prefix2str(p, debug_buf, sizeof(debug_buf));

  zlog_debug("%s: New route %s from %s.", __func__, debug_buf,
             zebra_route_string(type));

  if (!ei_table)
    {
      zlog_warn("%s: External information table not initialized.",
                __func__);
      return;
    }

  ei_node = route_node_get(ei_table, p);
  if (ei_node->info)
    route_unlock_node(ei_node);
  else
    ei_node->info = XCALLOC(MTYPE_ISIS, sizeof(struct isis_ext_info));

  info = ei_node->info;
  info->origin = type;
  info->distance = distance;
  info->metric = metric;

  if (is_default(p))
    type = DEFAULT_ROUTE;

  for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area))
    for (level = 1; level <= ISIS_LEVELS; level++)
      {
        redist = get_redist_settings(area, family, type, level);
        if (!redist->redist)
          continue;

        isis_redist_update_ext_reach(area, level, redist, p, info);
      }
}

void
isis_redist_delete(int type, struct prefix *p)
{
  int family = p->family;
  struct route_table *ei_table = get_ext_info(isis, family);
  struct route_node *ei_node;
  struct listnode *node;
  struct isis_area *area;
  int level;
  struct isis_redist *redist;

  char debug_buf[BUFSIZ];
  prefix2str(p, debug_buf, sizeof(debug_buf));

  zlog_debug("%s: Removing route %s from %s.", __func__, debug_buf,
             zebra_route_string(type));

  if (is_default(p))
    {
      /* Don't remove default route but add synthetic route for use
       * by "default-information originate always". Areas without the
       * "always" setting will ignore routes with origin DEFAULT_ROUTE. */
      isis_redist_add(DEFAULT_ROUTE, p, 254, MAX_WIDE_PATH_METRIC);
      return;
    }

  if (!ei_table)
    {
      zlog_warn("%s: External information table not initialized.",
                __func__);
      return;
    }

  ei_node = route_node_lookup(ei_table, p);
  if (!ei_node || !ei_node->info)
    {
      char buf[BUFSIZ];
      prefix2str(p, buf, sizeof(buf));
      zlog_warn("%s: Got a delete for %s route %s, but that route"
                " was never added.", __func__, zebra_route_string(type),
                buf);
      if (ei_node)
        route_unlock_node(ei_node);
      return;
    }
  route_unlock_node(ei_node);

  for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area))
    for (level = 1; level < ISIS_LEVELS; level++)
      {
        redist = get_redist_settings(area, family, type, level);
        if (!redist->redist)
          continue;

        isis_redist_uninstall(area, level, p);
      }

  route_unlock_node(ei_node);
}

static void
isis_redist_routemap_set(struct isis_redist *redist, const char *routemap)
{
  if (redist->map_name) {
    XFREE(MTYPE_ISIS, redist->map_name);
    redist->map = NULL;
  }

  if (routemap && strlen(routemap)) {
    redist->map_name = XSTRDUP(MTYPE_ISIS, routemap);
    redist->map = route_map_lookup_by_name(routemap);
  }
}

static void
isis_redist_update_zebra_subscriptions(struct isis *isis)
{
  struct listnode *node;
  struct isis_area *area;
  int type;
  int level;
  int protocol;

  char do_subscribe[ZEBRA_ROUTE_MAX + 1];

  memset(do_subscribe, 0, sizeof(do_subscribe));

  for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area))
    for (protocol = 0; protocol < REDIST_PROTOCOL_COUNT; protocol++)
      for (type = 0; type < ZEBRA_ROUTE_MAX + 1; type++)
        for (level = 0; level < ISIS_LEVELS; level++)
          if (area->redist_settings[protocol][type][level].redist)
            do_subscribe[type] = 1;

  for (type = 0; type < ZEBRA_ROUTE_MAX + 1; type++)
    {
      /* This field is actually controlling transmission of the IS-IS
       * routes to Zebra and has nothing to do with redistribution,
       * so skip it. */
      if (type == ZEBRA_ROUTE_ISIS)
        continue;

      if (do_subscribe[type])
        isis_zebra_redistribute_set(type);
      else
        isis_zebra_redistribute_unset(type);
    }
}

static void
isis_redist_set(struct isis_area *area, int level,
                int family, int type, uint32_t metric,
                const char *routemap, int originate_type)
{
  int protocol = redist_protocol(family);
  struct isis_redist *redist = get_redist_settings(area, family, type, level);
  int i;
  struct route_table *ei_table;
  struct route_node *rn;
  struct isis_ext_info *info;

  redist->redist = (type == DEFAULT_ROUTE) ? originate_type : 1;
  redist->metric = metric;
  isis_redist_routemap_set(redist, routemap);

  if (!area->ext_reach[protocol][level-1])
    {
      area->ext_reach[protocol][level-1] =
          route_table_init_with_delegate(&isis_redist_rt_delegate);
    }

  for (i = 0; i < REDIST_PROTOCOL_COUNT; i++)
    if (!area->isis->ext_info[i])
      {
        area->isis->ext_info[i] =
            route_table_init_with_delegate(&isis_redist_rt_delegate);
      }

  isis_redist_update_zebra_subscriptions(area->isis);

  if (type == DEFAULT_ROUTE && originate_type == DEFAULT_ORIGINATE_ALWAYS)
    isis_redist_ensure_default(area->isis, family);

  ei_table = get_ext_info(area->isis, family);
  for (rn = route_top(ei_table); rn; rn = route_next(rn))
    {
      if (!rn->info)
        continue;
      info = rn->info;

      if (type == DEFAULT_ROUTE)
        {
          if (!is_default(&rn->p))
            continue;
        }
      else
        {
          if (info->origin != type)
            continue;
        }

      isis_redist_update_ext_reach(area, level, redist, &rn->p, info);
    }
}

static void
isis_redist_unset(struct isis_area *area, int level,
                  int family, int type)
{
  struct isis_redist *redist = get_redist_settings(area, family, type, level);
  struct route_table *er_table = get_ext_reach(area, family, level);
  struct route_node *rn;
  struct isis_ext_info *info;

  if (!redist->redist)
    return;

  redist->redist = 0;
  if (!er_table)
    {
      zlog_warn("%s: External reachability table uninitialized.", __func__);
      return;
    }

  for (rn = route_top(er_table); rn; rn = route_next(rn))
    {
      if (!rn->info)
        continue;
      info = rn->info;

      if (type == DEFAULT_ROUTE)
        {
          if (!is_default(&rn->p))
            continue;
        }
      else
        {
          if (info->origin != type)
            continue;
        }

      route_unlock_node(rn);
    }

  lsp_regenerate_schedule(area, level, 0);
  isis_redist_update_zebra_subscriptions(area->isis);
}

void
isis_redist_area_finish(struct isis_area *area)
{
  int protocol;
  int level;
  int type;

  for (protocol = 0; protocol < REDIST_PROTOCOL_COUNT; protocol++)
    for (level = 0; level < ISIS_LEVELS; level++)
      {
        for (type = 0; type < ZEBRA_ROUTE_MAX + 1; type++)
          {
            struct isis_redist *redist;

            redist = &area->redist_settings[protocol][type][level];
            redist->redist = 0;
            if (redist->map_name)
              XFREE(MTYPE_ISIS, redist->map_name);
          }
        route_table_finish(area->ext_reach[protocol][level]);
      }

  isis_redist_update_zebra_subscriptions(area->isis);
}

DEFUN(isis_redistribute,
      isis_redistribute_cmd,
      "redistribute (ipv4|ipv6) " QUAGGA_REDIST_STR_ISISD
      " (level-1|level-2) {metric <0-16777215>|route-map WORD}",
      REDIST_STR
      "Redistribute IPv4 routes\n"
      "Redistribute IPv6 routes\n"
      QUAGGA_REDIST_HELP_STR_ISISD
      "Redistribute into level-1\n"
      "Redistribute into level-2\n"
      "Metric for redistributed routes\n"
      "ISIS default metric\n"
      "Route map reference\n"
      "Pointer to route-map entries\n")
{
  struct isis_area *area = vty->index;
  int family;
  int afi;
  int type;
  int level;
  unsigned long metric;
  const char *routemap;

  if (argc < 5)
    return CMD_WARNING;

  family = str2family(argv[0]);
  if (family < 0)
    return CMD_WARNING;

  afi = family2afi(family);
  if (!afi)
    return CMD_WARNING;

  type = proto_redistnum(afi, argv[1]);
  if (type < 0 || type == ZEBRA_ROUTE_ISIS)
    return CMD_WARNING;

  if (!strcmp("level-1", argv[2]))
    level = 1;
  else if (!strcmp("level-2", argv[2]))
    level = 2;
  else
    return CMD_WARNING;

  if ((area->is_type & level) != level)
    {
      vty_out(vty, "Node is not a level-%d IS%s", level, VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (argv[3])
    {
      char *endp;
      metric = strtoul(argv[3], &endp, 10);
      if (argv[3][0] == '\0' || *endp != '\0')
        return CMD_WARNING;
    }
  else
    {
      metric = 0xffffffff;
    }

  routemap = argv[4];

  isis_redist_set(area, level, family, type, metric, routemap, 0);
  return 0;
}

DEFUN(no_isis_redistribute,
      no_isis_redistribute_cmd,
      "no redistribute (ipv4|ipv6) " QUAGGA_REDIST_STR_ISISD
      " (level-1|level-2)",
      NO_STR
      REDIST_STR
      "Redistribute IPv4 routes\n"
      "Redistribute IPv6 routes\n"
      QUAGGA_REDIST_HELP_STR_ISISD
      "Redistribute into level-1\n"
      "Redistribute into level-2\n")
{
  struct isis_area *area = vty->index;
  int type;
  int level;
  int family;
  int afi;

  if (argc < 3)
    return CMD_WARNING;

  family = str2family(argv[0]);
  if (family < 0)
    return CMD_WARNING;

  afi = family2afi(family);
  if (!afi)
    return CMD_WARNING;

  type = proto_redistnum(afi, argv[1]);
  if (type < 0 || type == ZEBRA_ROUTE_ISIS)
    return CMD_WARNING;

  if (!strcmp("level-1", argv[2]))
    level = 1;
  else if (!strcmp("level-2", argv[2]))
    level = 2;
  else
    return CMD_WARNING;

  isis_redist_unset(area, level, family, type);
  return 0;
}

DEFUN(isis_default_originate,
      isis_default_originate_cmd,
      "default-information originate (ipv4|ipv6) (level-1|level-2) "
        "{always|metric <0-16777215>|route-map WORD}",
      "Control distribution of default information\n"
      "Distribute a default route\n"
      "Distribute default route for IPv4\n"
      "Distribute default route for IPv6\n"
      "Distribute default route into level-1\n"
      "Distribute default route into level-2\n"
      "Always advertise default route\n"
      "Metric for default route\n"
      "ISIS default metric\n"
      "Route map reference\n"
      "Pointer to route-map entries\n")
{
  struct isis_area *area = vty->index;
  int family;
  int originate_type;
  int level;
  unsigned long metric;
  const char *routemap;

  if (argc < 5)
    return CMD_WARNING;

  family = str2family(argv[0]);
  if (family < 0)
    return CMD_WARNING;

  if (!strcmp("level-1", argv[1]))
    level = 1;
  else if (!strcmp("level-2", argv[1]))
    level = 2;
  else
    return CMD_WARNING;

  if ((area->is_type & level) != level)
    {
      vty_out(vty, "Node is not a level-%d IS%s", level, VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (argv[2] && *argv[2] != '\0')
    originate_type = DEFAULT_ORIGINATE_ALWAYS;
  else
    originate_type = DEFAULT_ORIGINATE;

  if (family == AF_INET6 && originate_type != DEFAULT_ORIGINATE_ALWAYS)
    {
      vty_out(vty, "Zebra doesn't implement default-originate for IPv6 yet%s", VTY_NEWLINE);
      vty_out(vty, "so use with care or use default-originate always.%s", VTY_NEWLINE);
    }

  if (argv[3])
    {
      char *endp;
      metric = strtoul(argv[3], &endp, 10);
      if (argv[3][0] == '\0' || *endp != '\0')
        return CMD_WARNING;
    }
  else
    {
      metric = 0xffffffff;
    }

  routemap = argv[4];

  isis_redist_set(area, level, family, DEFAULT_ROUTE, metric, routemap, originate_type);
  return 0;
}

DEFUN(no_isis_default_originate,
      no_isis_default_originate_cmd,
      "no default-information originate (ipv4|ipv6) (level-1|level-2)",
      NO_STR
      "Control distribution of default information\n"
      "Distribute a default route\n"
      "Distribute default route for IPv4\n"
      "Distribute default route for IPv6\n"
      "Distribute default route into level-1\n"
      "Distribute default route into level-2\n")
{
  struct isis_area *area = vty->index;

  int family;
  int level;

  if (argc < 2)
    return CMD_WARNING;

  family = str2family(argv[0]);
  if (family < 0)
    return CMD_WARNING;

  if (!strcmp("level-1", argv[1]))
    level = 1;
  else if (!strcmp("level-2", argv[1]))
    level = 2;
  else
    return CMD_WARNING;

  isis_redist_unset(area, level, family, DEFAULT_ROUTE);
  return 0;
}

int
isis_redist_config_write(struct vty *vty, struct isis_area *area,
                         int family)
{
  int type;
  int level;
  int write = 0;
  struct isis_redist *redist;
  const char *family_str;

  if (family == AF_INET)
    family_str = "ipv4";
  else if (family == AF_INET6)
    family_str = "ipv6";
  else
    return 0;

  for (type = 0; type < ZEBRA_ROUTE_MAX; type++)
    {
      if (type == ZEBRA_ROUTE_ISIS)
        continue;

      for (level = 1; level <= ISIS_LEVELS; level++)
        {
          redist = get_redist_settings(area, family, type, level);
          if (!redist->redist)
            continue;
          vty_out(vty, " redistribute %s %s level-%d",
                  family_str, zebra_route_string(type), level);
          if (redist->metric != 0xffffffff)
            vty_out(vty, " metric %u", redist->metric);
          if (redist->map_name)
            vty_out(vty, " route-map %s", redist->map_name);
          vty_out(vty, "%s", VTY_NEWLINE);
          write++;
        }
    }

  for (level = 1; level <= ISIS_LEVELS; level++)
    {
      redist = get_redist_settings(area, family, DEFAULT_ROUTE, level);
      if (!redist->redist)
        continue;
      vty_out(vty, " default-information originate %s level-%d",
              family_str, level);
      if (redist->redist == DEFAULT_ORIGINATE_ALWAYS)
        vty_out(vty, " always");
      if (redist->metric != 0xffffffff)
        vty_out(vty, " metric %u", redist->metric);
      if (redist->map_name)
        vty_out(vty, " route-map %s", redist->map_name);
      vty_out(vty, "%s", VTY_NEWLINE);
      write++;
    }

  return write;
}

void
isis_redist_init(void)
{
  install_element(ISIS_NODE, &isis_redistribute_cmd);
  install_element(ISIS_NODE, &no_isis_redistribute_cmd);
  install_element(ISIS_NODE, &isis_default_originate_cmd);
  install_element(ISIS_NODE, &no_isis_default_originate_cmd);
}
