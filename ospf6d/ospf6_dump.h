/*
 * Logging function
 * Copyright (C) 1999-2002 Yasuhiro Ohara
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

#ifndef OSPF6_DUMP_H
#define OSPF6_DUMP_H

enum ospf6_dump_type
{
  OSPF6_DUMP_HELLO,
  OSPF6_DUMP_DBDESC,
  OSPF6_DUMP_LSREQ,
  OSPF6_DUMP_LSUPDATE,
  OSPF6_DUMP_LSACK,
  OSPF6_DUMP_NEIGHBOR,
  OSPF6_DUMP_INTERFACE,
  OSPF6_DUMP_AREA,
  OSPF6_DUMP_LSA,
  OSPF6_DUMP_ZEBRA,
  OSPF6_DUMP_CONFIG,
  OSPF6_DUMP_DBEX,
  OSPF6_DUMP_SPF,
  OSPF6_DUMP_ROUTE,
  OSPF6_DUMP_LSDB,
  OSPF6_DUMP_REDISTRIBUTE,
  OSPF6_DUMP_HOOK,
  OSPF6_DUMP_ASBR,
  OSPF6_DUMP_PREFIX,
  OSPF6_DUMP_ABR,
  OSPF6_DUMP_MAX
};

#define IS_OSPF6_DUMP_HELLO \
  (ospf6_dump_is_on (dump_index[OSPF6_DUMP_HELLO]))
#define IS_OSPF6_DUMP_DBDESC \
  (ospf6_dump_is_on (dump_index[OSPF6_DUMP_DBDESC]))
#define IS_OSPF6_DUMP_LSREQ \
  (ospf6_dump_is_on (dump_index[OSPF6_DUMP_LSREQ]))
#define IS_OSPF6_DUMP_LSUPDATE \
  (ospf6_dump_is_on (dump_index[OSPF6_DUMP_LSUPDATE]))
#define IS_OSPF6_DUMP_LSACK \
  (ospf6_dump_is_on (dump_index[OSPF6_DUMP_LSACK]))
#define IS_OSPF6_DUMP_NEIGHBOR \
  (ospf6_dump_is_on (dump_index[OSPF6_DUMP_NEIGHBOR]))
#define IS_OSPF6_DUMP_INTERFACE \
  (ospf6_dump_is_on (dump_index[OSPF6_DUMP_INTERFACE]))
#define IS_OSPF6_DUMP_LSA \
  (ospf6_dump_is_on (dump_index[OSPF6_DUMP_LSA]))
#define IS_OSPF6_DUMP_ZEBRA \
  (ospf6_dump_is_on (dump_index[OSPF6_DUMP_ZEBRA]))
#define IS_OSPF6_DUMP_CONFIG \
  (ospf6_dump_is_on (dump_index[OSPF6_DUMP_CONFIG]))
#define IS_OSPF6_DUMP_DBEX \
  (ospf6_dump_is_on (dump_index[OSPF6_DUMP_DBEX]))
#define IS_OSPF6_DUMP_SPF \
  (ospf6_dump_is_on (dump_index[OSPF6_DUMP_SPF]))
#define IS_OSPF6_DUMP_ROUTE \
  (ospf6_dump_is_on (dump_index[OSPF6_DUMP_ROUTE]))
#define IS_OSPF6_DUMP_LSDB \
  (ospf6_dump_is_on (dump_index[OSPF6_DUMP_LSDB]))
#define IS_OSPF6_DUMP_REDISTRIBUTE \
  (ospf6_dump_is_on (dump_index[OSPF6_DUMP_REDISTRIBUTE]))
#define IS_OSPF6_DUMP_HOOK \
  (ospf6_dump_is_on (dump_index[OSPF6_DUMP_HOOK]))
#define IS_OSPF6_DUMP_ASBR \
  (ospf6_dump_is_on (dump_index[OSPF6_DUMP_ASBR]))
#define IS_OSPF6_DUMP_PREFIX \
  (ospf6_dump_is_on (dump_index[OSPF6_DUMP_PREFIX]))

extern char dump_index[OSPF6_DUMP_MAX];

void ospf6_dump_init ();
int ospf6_dump_is_on (int index);
int ospf6_dump_install (char *name, char *help);

#endif /* OSPF6_DUMP_H */

