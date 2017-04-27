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
#ifndef ISIS_MT_H
#define ISIS_MT_H

#define ISIS_MT_IPV4_UNICAST   0
#define ISIS_MT_IPV4_MGMT      1
#define ISIS_MT_IPV6_UNICAST   2
#define ISIS_MT_IPV4_MULTICAST 3
#define ISIS_MT_IPV6_MULTICAST 4
#define ISIS_MT_IPV6_MGMT      5

#define ISIS_MT_NAMES \
    "<ipv4-unicast" \
    "|ipv4-mgmt" \
    "|ipv6-unicast" \
    "|ipv4-multicast" \
    "|ipv6-multicast" \
    "|ipv6-mgmt" \
    ">"

#define ISIS_MT_DESCRIPTIONS \
    "IPv4 unicast topology\n" \
    "IPv4 management topology\n" \
    "IPv6 unicast topology\n" \
    "IPv4 multicast topology\n" \
    "IPv6 multicast topology\n" \
    "IPv6 management topology\n"

#define ISIS_MT_INFO_FIELDS \
  uint16_t mtid;

struct isis_area_mt_setting {
  ISIS_MT_INFO_FIELDS
  bool enabled;
  bool overload;
};

struct isis_circuit_mt_setting {
  ISIS_MT_INFO_FIELDS
  bool enabled;
};

const char *isis_mtid2str(uint16_t mtid);
uint16_t isis_str2mtid(const char *name);

struct isis_area;
struct isis_circuit;

struct isis_area_mt_setting* area_lookup_mt_setting(struct isis_area *area,
                                                    uint16_t mtid);
struct isis_area_mt_setting* area_new_mt_setting(struct isis_area *area,
                                                 uint16_t mtid);
void area_add_mt_setting(struct isis_area *area,
                         struct isis_area_mt_setting *setting);

void area_mt_init(struct isis_area *area);
void area_mt_finish(struct isis_area *area);
struct isis_area_mt_setting* area_get_mt_setting(struct isis_area *area,
                                                 uint16_t mtid);
int area_write_mt_settings(struct isis_area *area, struct vty *vty);

struct isis_circuit_mt_setting* circuit_lookup_mt_setting(
                                                struct isis_circuit *circuit,
                                                uint16_t mtid);
struct isis_circuit_mt_setting* circuit_new_mt_setting(
                                                struct isis_circuit *circuit,
                                                uint16_t mtid);
void circuit_add_mt_setting(struct isis_circuit *circuit,
                            struct isis_circuit_mt_setting *setting);
void circuit_mt_init(struct isis_circuit *circuit);
void circuit_mt_finish(struct isis_circuit *circuit);
struct isis_circuit_mt_setting* circuit_get_mt_setting(
                                                struct isis_circuit *circuit,
                                                uint16_t mtid);
int circuit_write_mt_settings(struct isis_circuit *circuit, struct vty *vty);
#endif
