/*
 * Zebra VxLAN (EVPN) Data structures and definitions
 * These are "internal" to this function.
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
 *
 * This file is part of FRR.
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

#ifndef _ZEBRA_VXLAN_PRIVATE_H
#define _ZEBRA_VXLAN_PRIVATE_H

#include <zebra.h>

#include <zebra.h>

#include "if.h"
#include "linklist.h"

/* definitions */
typedef struct zebra_vni_t_ zebra_vni_t;
typedef struct zebra_vtep_t_ zebra_vtep_t;

/*
 * VTEP info
 *
 * Right now, this just has each remote VTEP's IP address.
 */
struct zebra_vtep_t_
{
  /* Remote IP. */
  /* NOTE: Can only be IPv4 right now. */
  struct in_addr vtep_ip;

  /* Links. */
  struct zebra_vtep_t_ *next;
  struct zebra_vtep_t_ *prev;
};


/*
 * VNI hash table
 *
 * Contains information pertaining to a VNI:
 * - the list of remote VTEPs (with this VNI)
 */
struct zebra_vni_t_
{
  /* VNI - key */
  vni_t vni;

  /* Corresponding VxLAN interface. */
  struct interface *vxlan_if;

  /* List of remote VTEPs */
  zebra_vtep_t *vteps;

  /* Local IP */
  struct in_addr local_vtep_ip;
};

#endif /* _ZEBRA_VXLAN_PRIVATE_H */
