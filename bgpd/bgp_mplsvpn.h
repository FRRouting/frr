/* MPLS-VPN
   Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>

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

#ifndef _QUAGGA_BGP_MPLSVPN_H
#define _QUAGGA_BGP_MPLSVPN_H

#define RD_TYPE_AS      0
#define RD_TYPE_IP      1
#define RD_TYPE_AS4     2
#if ENABLE_BGP_VNC
#define RD_TYPE_VNC_ETH	0xff00  /* VNC L2VPN */
#endif

#define RD_ADDRSTRLEN  28

typedef enum {
    MPLS_LABEL_IPV4_EXPLICIT_NULL = 0,  /* [RFC3032] */
    MPLS_LABEL_ROUTER_ALERT       = 1,  /* [RFC3032] */
    MPLS_LABEL_IPV6_EXPLICIT_NULL = 2,  /* [RFC3032] */
    MPLS_LABEL_IMPLICIT_NULL      = 3,  /* [RFC3032] */
    MPLS_LABEL_UNASSIGNED4        = 4,
    MPLS_LABEL_UNASSIGNED5        = 5,
    MPLS_LABEL_UNASSIGNED6        = 6,
    MPLS_LABEL_ELI                = 7,  /* Entropy Indicator [RFC6790] */
    MPLS_LABEL_UNASSIGNED8        = 8,
    MPLS_LABEL_UNASSIGNED9        = 9,
    MPLS_LABEL_UNASSIGNED10       = 10,
    MPLS_LABEL_UNASSIGNED11       = 11,
    MPLS_LABEL_GAL                = 13, /* [RFC5586] */
    MPLS_LABEL_OAM_ALERT          = 14, /* [RFC3429] */
    MPLS_LABEL_EXTENSION          = 15  /* [RFC7274] */
} mpls_special_label_t;

#define MPLS_LABEL_IS_SPECIAL(label)             \
    ((label) <= MPLS_LABEL_EXTENSION)
#define MPLS_LABEL_IS_NULL(label)                \
    ((label) == MPLS_LABEL_IPV4_EXPLICIT_NULL || \
     (label) == MPLS_LABEL_IPV6_EXPLICIT_NULL || \
     (label) == MPLS_LABEL_IMPLICIT_NULL)

struct rd_as
{
  u_int16_t type;
  as_t as;
  u_int32_t val;
};

struct rd_ip
{
  u_int16_t type;
  struct in_addr ip;
  u_int16_t val;
};

#if ENABLE_BGP_VNC
struct rd_vnc_eth
{
  u_int16_t type;
  uint8_t local_nve_id;
  struct ethaddr macaddr;
};
#endif

extern u_int16_t decode_rd_type (u_char *);
extern void encode_rd_type (u_int16_t, u_char *);
extern void bgp_mplsvpn_init (void);
extern int bgp_nlri_parse_vpn (struct peer *, struct attr *, struct bgp_nlri *);
extern u_int32_t decode_label (u_char *);
extern void encode_label(u_int32_t, u_char *);
extern void decode_rd_as (u_char *, struct rd_as *);
extern void decode_rd_as4 (u_char *, struct rd_as *);
extern void decode_rd_ip (u_char *, struct rd_ip *);
#if ENABLE_BGP_VNC
extern void decode_vnc_eth (u_char *, struct rd_vnc_eth *);
#endif
extern int str2prefix_rd (const char *, struct prefix_rd *);
extern int str2tag (const char *, u_char *);
extern char *prefix_rd2str (struct prefix_rd *, char *, size_t);

#endif /* _QUAGGA_BGP_MPLSVPN_H */
