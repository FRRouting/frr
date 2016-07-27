/*
  PIM for Quagga
  Copyright (C) 2008  Everton da Silva Marques

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program; see the file COPYING; if not, write to the
  Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
  MA 02110-1301 USA
  
*/

#ifndef PIM_MSG_H
#define PIM_MSG_H

#include <netinet/in.h>

/*
  Number       Description       
  ----------   ------------------
  0            Reserved
  1            IP (IP version 4)
  2            IP6 (IP version 6)

  From:
  http://www.iana.org/assignments/address-family-numbers
*/
#define PIM_MSG_ADDRESS_FAMILY_IPV4 (1)

void pim_msg_build_header(uint8_t *pim_msg, int pim_msg_size,
			  uint8_t pim_msg_type);
uint8_t *pim_msg_addr_encode_ipv4_ucast(uint8_t *buf,
					int buf_size,
					struct in_addr addr);
uint8_t *pim_msg_addr_encode_ipv4_group(uint8_t *buf,
					int buf_size,
					struct in_addr addr);

#define PIM_ENCODE_SPARSE_BIT      0x04
#define PIM_ENCODE_WC_BIT          0x02
#define PIM_ENCODE_RPT_BIT         0x01
uint8_t *pim_msg_addr_encode_ipv4_source(uint8_t *buf,
					 int buf_size,
					 struct in_addr addr,
					 uint8_t bits);


int pim_msg_join_prune_encode (uint8_t *buf, int buf_size, int is_join,
			       struct in_addr source, struct in_addr group,
			       struct in_addr upstream, int holdtime);
#endif /* PIM_MSG_H */
