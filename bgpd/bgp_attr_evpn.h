/* E-VPN attribute handling structure file
   Copyright (C) 2016 6WIND

This file is part of Free Range Routing.

Free Range Routing is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

Free Range Routing is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with Free Range Routing; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#ifndef _QUAGGA_BGP_ATTR_EVPN_H
#define _QUAGGA_BGP_ATTR_EVPN_H

/* value of first byte of ESI */
#define ESI_TYPE_ARBITRARY 0 /* */
#define ESI_TYPE_LACP      1 /* <> */
#define ESI_TYPE_BRIDGE    2 /* <Root bridge Mac-6B>:<Root Br Priority-2B>:00 */
#define ESI_TYPE_MAC       3 /* <Syst Mac Add-6B>:<Local Discriminator Value-3B> */
#define ESI_TYPE_ROUTER    4 /* <RouterId-4B>:<Local Discriminator Value-4B> */
#define ESI_TYPE_AS        5 /* <AS-4B>:<Local Discriminator Value-4B> */
#define MAX_ESI {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff}
#define ESI_LEN 10

#define MAX_ET 0xffffffff
u_long eth_tag_id;

struct eth_segment_id
{
  u_char val[ESI_LEN];
};

#define MAC_LEN 6

union gw_addr {
  struct in_addr ipv4;
  struct in6_addr ipv6;
};

struct bgp_route_evpn
{
  struct eth_segment_id eth_s_id;
  union gw_addr gw_ip;
};

extern int str2esi (const char *str, struct eth_segment_id *id);
extern int str2mac (const char *str, char *mac);
extern char *esi2str (struct eth_segment_id *id);
extern char *mac2str (char *mac);
extern char *ecom_mac2str(char *ecom_mac);

#endif /* _QUAGGA_BGP_ATTR_EVPN_H */
