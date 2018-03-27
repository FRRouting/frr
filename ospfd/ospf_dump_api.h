/*
 * OSPFd dump routine (parts used by ospfclient).
 * Copyright (C) 1999 Toshiaki Takada
 *
 * This file is part of FRRouting (FRR).
 *
 * FRR is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2, or (at your option) any later version.
 *
 * FRR is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_OSPF_DUMP_API_H
#define _ZEBRA_OSPF_DUMP_API_H

#include "log.h"
struct lsa_header;

extern const struct message ospf_ism_state_msg[];
extern const struct message ospf_nsm_state_msg[];
extern const struct message ospf_lsa_type_msg[];
extern const struct message ospf_link_state_id_type_msg[];
extern const struct message ospf_network_type_msg[];
extern const struct message ospf_auth_type_str[];
extern const int ospf_ism_state_msg_max;
extern const int ospf_nsm_state_msg_max;
extern const int ospf_lsa_type_msg_max;
extern const int ospf_link_state_id_type_msg_max;
extern const int ospf_network_type_msg_max;
extern const size_t ospf_auth_type_str_max;

extern char *ospf_options_dump(uint8_t);
extern void ospf_lsa_header_dump(struct lsa_header *);

#endif /* _ZEBRA_OSPF_DUMP_API_H */
