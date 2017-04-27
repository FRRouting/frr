/*
 * IS-IS Rout(e)ing protocol - Multi Topology Support
 *
 * Copyright (C) 2017 Christian Franke
 *
 * This file is part of FreeRangeRouting (FRR)
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
#include "isisd/isisd.h"
#include "isisd/isis_memory.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_mt.h"

DEFINE_MTYPE_STATIC(ISISD, MT_AREA_SETTING, "ISIS MT Area Setting")
DEFINE_MTYPE_STATIC(ISISD, MT_CIRCUIT_SETTING, "ISIS MT Circuit Setting")

/* MT naming api */
const char *isis_mtid2str(uint16_t mtid)
{
  switch(mtid)
    {
      case ISIS_MT_IPV4_UNICAST:
        return "ipv4-unicast";
      case ISIS_MT_IPV4_MGMT:
        return "ipv4-mgmt";
      case ISIS_MT_IPV6_UNICAST:
        return "ipv6-unicast";
      case ISIS_MT_IPV4_MULTICAST:
        return "ipv4-multicast";
      case ISIS_MT_IPV6_MULTICAST:
        return "ipv6-multicast";
      case ISIS_MT_IPV6_MGMT:
        return "ipv6-mgmt";
      default:
        return NULL;
    }
}

uint16_t isis_str2mtid(const char *name)
{
  if (!strcmp(name,"ipv4-unicast"))
    return ISIS_MT_IPV4_UNICAST;
  if (!strcmp(name,"ipv4-mgmt"))
    return ISIS_MT_IPV4_MGMT;
  if (!strcmp(name,"ipv6-unicast"))
    return ISIS_MT_IPV6_UNICAST;
  if (!strcmp(name,"ipv4-multicast"))
    return ISIS_MT_IPV4_MULTICAST;
  if (!strcmp(name,"ipv6-multicast"))
    return ISIS_MT_IPV6_MULTICAST;
  if (!strcmp(name,"ipv6-mgmt"))
    return ISIS_MT_IPV6_MGMT;
  return -1;
}

/* General MT settings api */

struct mt_setting {
	ISIS_MT_INFO_FIELDS;
};

static void *
lookup_mt_setting(struct list *mt_list, uint16_t mtid)
{
  struct listnode *node;
  struct mt_setting *setting;

  for (ALL_LIST_ELEMENTS_RO(mt_list, node, setting))
    {
      if (setting->mtid == mtid)
        return setting;
    }
  return NULL;
}

static void
add_mt_setting(struct list **mt_list, void *setting)
{
  if (!*mt_list)
    *mt_list = list_new();
  listnode_add(*mt_list, setting);
}

/* Area specific MT settings api */

struct isis_area_mt_setting*
area_lookup_mt_setting(struct isis_area *area, uint16_t mtid)
{
  return lookup_mt_setting(area->mt_settings, mtid);
}

struct isis_area_mt_setting*
area_new_mt_setting(struct isis_area *area, uint16_t mtid)
{
  struct isis_area_mt_setting *setting;

  setting = XCALLOC(MTYPE_MT_AREA_SETTING, sizeof(*setting));
  setting->mtid = mtid;
  return setting;
}

static void
area_free_mt_setting(void *setting)
{
  XFREE(MTYPE_MT_AREA_SETTING, setting);
}

void
area_add_mt_setting(struct isis_area *area, struct isis_area_mt_setting *setting)
{
  add_mt_setting(&area->mt_settings, setting);
}

void
area_mt_init(struct isis_area *area)
{
  struct isis_area_mt_setting *v4_unicast_setting;

  /* MTID 0 is always enabled */
  v4_unicast_setting = area_new_mt_setting(area, ISIS_MT_IPV4_UNICAST);
  v4_unicast_setting->enabled = true;
  add_mt_setting(&area->mt_settings, v4_unicast_setting);
  area->mt_settings->del = area_free_mt_setting;
}

void
area_mt_finish(struct isis_area *area)
{
  list_delete(area->mt_settings);
  area->mt_settings = NULL;
}

struct isis_area_mt_setting *
area_get_mt_setting(struct isis_area *area, uint16_t mtid)
{
  struct isis_area_mt_setting *setting;

  setting = area_lookup_mt_setting(area, mtid);
  if (!setting)
    {
      setting = area_new_mt_setting(area, mtid);
      area_add_mt_setting(area, setting);
    }
  return setting;
}

int
area_write_mt_settings(struct isis_area *area, struct vty *vty)
{
  int written = 0;
  struct listnode *node;
  struct isis_area_mt_setting *setting;

  for (ALL_LIST_ELEMENTS_RO(area->mt_settings, node, setting))
    {
      const char *name = isis_mtid2str(setting->mtid);
      if (name && setting->enabled)
        {
          if (setting->mtid == ISIS_MT_IPV4_UNICAST)
            continue; /* always enabled, no need to write out config */
          vty_out (vty, " topology %s%s%s", name,
                   setting->overload ? " overload" : "",
                   VTY_NEWLINE);
          written++;
        }
    }
  return written;
}

/* Circuit specific MT settings api */

struct isis_circuit_mt_setting*
circuit_lookup_mt_setting(struct isis_circuit *circuit, uint16_t mtid)
{
  return lookup_mt_setting(circuit->mt_settings, mtid);
}

struct isis_circuit_mt_setting*
circuit_new_mt_setting(struct isis_circuit *circuit, uint16_t mtid)
{
  struct isis_circuit_mt_setting *setting;

  setting = XCALLOC(MTYPE_MT_CIRCUIT_SETTING, sizeof(*setting));
  setting->mtid = mtid;
  setting->enabled = true; /* Enabled is default for circuit */
  return setting;
}

static void
circuit_free_mt_setting(void *setting)
{
  XFREE(MTYPE_MT_CIRCUIT_SETTING, setting);
}

void
circuit_add_mt_setting(struct isis_circuit *circuit,
                       struct isis_circuit_mt_setting *setting)
{
  add_mt_setting(&circuit->mt_settings, setting);
}

void
circuit_mt_init(struct isis_circuit *circuit)
{
  circuit->mt_settings = list_new();
  circuit->mt_settings->del = circuit_free_mt_setting;
}

void
circuit_mt_finish(struct isis_circuit *circuit)
{
  list_delete(circuit->mt_settings);
  circuit->mt_settings = NULL;
}

struct isis_circuit_mt_setting*
circuit_get_mt_setting(struct isis_circuit *circuit, uint16_t mtid)
{
  struct isis_circuit_mt_setting *setting;

  setting = circuit_lookup_mt_setting(circuit, mtid);
  if (!setting)
    {
      setting = circuit_new_mt_setting(circuit, mtid);
      circuit_add_mt_setting(circuit, setting);
    }
  return setting;
}

int
circuit_write_mt_settings(struct isis_circuit *circuit, struct vty *vty)
{
  int written = 0;
  struct listnode *node;
  struct isis_circuit_mt_setting *setting;

  for (ALL_LIST_ELEMENTS_RO (circuit->mt_settings, node, setting))
    {
      const char *name = isis_mtid2str(setting->mtid);
      if (name && !setting->enabled)
        {
          vty_out (vty, " no isis topology %s%s", name, VTY_NEWLINE);
          written++;
        }
    }
  return written;
}
