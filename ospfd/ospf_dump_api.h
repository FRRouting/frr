// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFd dump routine (parts used by ospfclient).
 * Copyright (C) 1999 Toshiaki Takada
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
