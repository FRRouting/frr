/*
 * Zebra NS header
 * Copyright (C) 2016 Cumulus Networks, Inc.
 *                    Donald Sharp
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#if !defined(__ZEBRA_NS_H__)
#define __ZEBRA_NS_H__

#ifdef HAVE_NETLINK
/* Socket interface to kernel */
struct nlsock
{
  int sock;
  int seq;
  struct sockaddr_nl snl;
  const char *name;
};
#endif

/* NetNS ID type. */
typedef u_int16_t ns_id_t;

struct zebra_ns
{
  /* net-ns name.  */
  char name[VRF_NAMSIZ];

  /* Identifier. */
  ns_id_t ns_id;

#ifdef HAVE_NETLINK
  struct nlsock netlink;     /* kernel messages */
  struct nlsock netlink_cmd; /* command channel */
  struct thread *t_netlink;
#endif

  struct route_table *if_table;

#if defined (HAVE_RTADV)
  struct rtadv rtadv;
#endif /* HAVE_RTADV */
};

#define NS_DEFAULT 0
#define NS_UNKNOWN UINT16_MAX

struct zebra_ns *zebra_ns_lookup (ns_id_t ns_id);

int zebra_ns_init (void);
int zebra_ns_enable (ns_id_t ns_id, void **info);
int zebra_ns_disable (ns_id_t ns_id, void **info);
#endif
