/* BGP open message handling
   Copyright (C) 1999 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

/* MP Capability information. */
struct capability_mp
{
  u_int16_t afi;
  u_char reserved;
  u_char safi;
};

/* BGP open message capability. */
struct capability
{
  u_char code;
  u_char length;
  struct capability_mp mpc;
};

/* Multiprotocol Extensions capabilities. */
#define CAPABILITY_CODE_MP              1
#define CAPABILITY_CODE_MP_LEN          4

/* Route refresh capabilities. */
#define CAPABILITY_CODE_REFRESH         2
#define CAPABILITY_CODE_REFRESH_OLD   128
#define CAPABILITY_CODE_REFRESH_LEN     0

/* Cooperative Route Filtering Capability.  */
#define CAPABILITY_CODE_ORF             3 
#define CAPABILITY_CODE_ORF_OLD       130

/* ORF Type.  */
#define ORF_TYPE_PREFIX                64 
#define ORF_TYPE_PREFIX_OLD           128

/* ORF Mode.  */
#define ORF_MODE_RECEIVE                1 
#define ORF_MODE_SEND                   2 
#define ORF_MODE_BOTH                   3 

/* Dynamic capability.  */
#define CAPABILITY_CODE_DYNAMIC        66
#define CAPABILITY_CODE_DYNAMIC_LEN     0

/* Capability Message Action.  */
#define CAPABILITY_ACTION_SET           0
#define CAPABILITY_ACTION_UNSET         1

int bgp_open_option_parse (struct peer *, u_char, int *);
void bgp_open_capability (struct stream *, struct peer *);
void bgp_capability_vty_out (struct vty *, struct peer *);
