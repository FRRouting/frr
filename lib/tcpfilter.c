/* Route filtering function for TCP and UDP.
 * Copyright (C) 2000 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
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

#include "command.h"
#include "prefix.h"

#define FILTER_TYPE_IP   1
#define FILTER_TYPE_TCP  2
#define FILTER_TYPE_UDP  3

DEFUN (al_tcp_filter,
       al_tcp_filter_cmd,
       "access-list WORD (deny|permit) tcp (A.B.C.D/M|any) (A.B.C.D/M|any)",
       "Add an access list entry\n"
       "Access-list name\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Transmission Control Protocol\n"
       "Source address prefix\n"
       "Any source host\n"
       "Destination address prefix\n"
       "Any destination host\n")
{
  return CMD_SUCCESS;
}

DEFUN (al_tcp_filter_eq,
       al_tcp_filter_eq_cmd,
       "access-list WORD (deny|permit) tcp (A.B.C.D/M|any) (A.B.C.D/M|any) eq <0-65535>",
       "Add an access list entry\n"
       "Access-list name\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "Transmission Control Protocol\n"
       "Source address prefix\n"
       "Any source host\n"
       "Destination address prefix\n"
       "Any destination host\n"
       "Port number\n")
{
  return CMD_SUCCESS;
}

void
tcpfilter_init ()
{
  install_element (CONFIG_NODE, &al_tcp_filter_cmd);
  install_element (CONFIG_NODE, &al_tcp_filter_eq_cmd);
}
