/*
 * PIM for Quagga
 * Copyright (C) 2016 Cumulus Networks, Inc.
 * Donald Sharp
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */
#ifndef PIM_MSDP_H
#define PIM_MSDP_H

enum pim_msdp_states_t
  {
    PIM_MSDP_DISABLED,
    PIM_MSDP_INACTIVE,
    PIM_MSDP_LISTEN,
    PIM_MSDP_CONNECTING,
    PIM_MSDP_ESTABLISHED
  };

enum pim_msdp_tlv_t
  {
    PIM_MSDP_V4_SOURCE_ACTIVE = 1,
    PIM_MSDP_V4_SOURCE_ACTIVE_REQUEST,
    PIM_MSDP_V4_SOURCE_ACTIVE_RESPONSE,
    PIM_MSDP_KEEPALIVE,
    PIM_MSDP_RESERVED,
    PIM_MSDP_TRACEROUTE_PROGRESS,
    PIM_MSDP_TRACEROUTE_REPLY,
  };

struct pim_msdp_t
{
  enum pim_msdp_states_t  state;

  struct prefix peer;

  struct thread *cr_timer;  // 5.6
  struct thread *h_timer;   // 5.4
  struct thread *ka_timer;  // 5.5

};

void pim_msdp_init (void);
#endif
