/*
 * Copyright (C) 1999 Yasuhiro Ohara
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

#include "ospf6_proto.h"

char *
ospf6_options_string (u_char opt_capability[3], char *buffer, int size)
{
  char *dc, *r, *n, *mc, *e, *v6;

  dc = (OSPF6_OPT_ISSET (opt_capability, OSPF6_OPT_DC) ? "DC" : "--");
  r  = (OSPF6_OPT_ISSET (opt_capability, OSPF6_OPT_R) ? "R" : "-");
  n  = (OSPF6_OPT_ISSET (opt_capability, OSPF6_OPT_N) ? "N" : "-");
  mc = (OSPF6_OPT_ISSET (opt_capability, OSPF6_OPT_MC) ? "MC" : "--");
  e  = (OSPF6_OPT_ISSET (opt_capability, OSPF6_OPT_E) ? "E" : "-");
  v6 = (OSPF6_OPT_ISSET (opt_capability, OSPF6_OPT_V6) ? "V6" : "--");
  snprintf (buffer, size, "%s|%s|%s|%s|%s|%s", dc, r, n, mc, e, v6);
  return buffer;
}

