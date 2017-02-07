/*
 * OSPFd dump routine.
 * Copyright (C) 1999, 2000 Toshiaki Takada
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

#include "linklist.h"
#include "thread.h"
#include "prefix.h"
#include "command.h"
#include "stream.h"
#include "log.h"
#include "sockopt.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_network.h"

/* Configuration debug option variables. */
unsigned long conf_debug_ospf_packet[5] = {0, 0, 0, 0, 0};
unsigned long conf_debug_ospf_event = 0;
unsigned long conf_debug_ospf_ism = 0;
unsigned long conf_debug_ospf_nsm = 0;
unsigned long conf_debug_ospf_lsa = 0;
unsigned long conf_debug_ospf_zebra = 0;
unsigned long conf_debug_ospf_nssa = 0;
unsigned long conf_debug_ospf_te = 0;

/* Enable debug option variables -- valid only session. */
unsigned long term_debug_ospf_packet[5] = {0, 0, 0, 0, 0};
unsigned long term_debug_ospf_event = 0;
unsigned long term_debug_ospf_ism = 0;
unsigned long term_debug_ospf_nsm = 0;
unsigned long term_debug_ospf_lsa = 0;
unsigned long term_debug_ospf_zebra = 0;
unsigned long term_debug_ospf_nssa = 0;
unsigned long term_debug_ospf_te = 0;


const char *
ospf_redist_string(u_int route_type)
{
  return (route_type == ZEBRA_ROUTE_MAX) ?
  	 "Default" : zebra_route_string(route_type);
}

#define OSPF_AREA_STRING_MAXLEN  16
const char *
ospf_area_name_string (struct ospf_area *area)
{
  static char buf[OSPF_AREA_STRING_MAXLEN] = "";
  u_int32_t area_id;

  if (!area)
    return "-";

  area_id = ntohl (area->area_id.s_addr);
  snprintf (buf, OSPF_AREA_STRING_MAXLEN, "%d.%d.%d.%d",
            (area_id >> 24) & 0xff, (area_id >> 16) & 0xff,
            (area_id >> 8) & 0xff, area_id & 0xff);
  return buf;
}

#define OSPF_AREA_DESC_STRING_MAXLEN  23
const char *
ospf_area_desc_string (struct ospf_area *area)
{
  static char buf[OSPF_AREA_DESC_STRING_MAXLEN] = "";
  u_char type;

  if (!area)
    return "(incomplete)";

  type = area->external_routing;
  switch (type)
    {
    case OSPF_AREA_NSSA:
      snprintf (buf, OSPF_AREA_DESC_STRING_MAXLEN, "%s [NSSA]",
                ospf_area_name_string (area));
      break;
    case OSPF_AREA_STUB:
      snprintf (buf, OSPF_AREA_DESC_STRING_MAXLEN, "%s [Stub]",
                ospf_area_name_string (area));
      break;
    default:
      return ospf_area_name_string (area);
    }

  return buf;
}

#define OSPF_IF_STRING_MAXLEN  40
const char *
ospf_if_name_string (struct ospf_interface *oi)
{
  static char buf[OSPF_IF_STRING_MAXLEN] = "";
  u_int32_t ifaddr;

  if (!oi || !oi->address)
    return "inactive";

  if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
    return oi->ifp->name;

  ifaddr = ntohl (oi->address->u.prefix4.s_addr);
  snprintf (buf, OSPF_IF_STRING_MAXLEN,
            "%s:%d.%d.%d.%d", oi->ifp->name,
            (ifaddr >> 24) & 0xff, (ifaddr >> 16) & 0xff,
            (ifaddr >> 8) & 0xff, ifaddr & 0xff);
  return buf;
}


void
ospf_nbr_state_message (struct ospf_neighbor *nbr, char *buf, size_t size)
{
  int state;
  struct ospf_interface *oi = nbr->oi;

  if (IPV4_ADDR_SAME (&DR (oi), &nbr->address.u.prefix4))
    state = ISM_DR;
  else if (IPV4_ADDR_SAME (&BDR (oi), &nbr->address.u.prefix4))
    state = ISM_Backup;
  else
    state = ISM_DROther;

  memset (buf, 0, size);

  snprintf (buf, size, "%s/%s",
	    LOOKUP (ospf_nsm_state_msg, nbr->state),
	    LOOKUP (ospf_ism_state_msg, state));
}

const char *
ospf_timeval_dump (struct timeval *t, char *buf, size_t size)
{
  /* Making formatted timer strings. */
#define MINUTE_IN_SECONDS	60
#define HOUR_IN_SECONDS		(60*MINUTE_IN_SECONDS)
#define DAY_IN_SECONDS		(24*HOUR_IN_SECONDS)
#define WEEK_IN_SECONDS		(7*DAY_IN_SECONDS)
  unsigned long w, d, h, m, s, ms, us;
  
  if (!t)
    return "inactive";
  
  w = d = h = m = s = ms = us = 0;
  memset (buf, 0, size);

  us = t->tv_usec;
  if (us >= 1000)
    {
      ms = us / 1000;
      us %= 1000;
    }

  if (ms >= 1000)
    {
      t->tv_sec += ms / 1000;
      ms %= 1000;
    }
  
  if (t->tv_sec > WEEK_IN_SECONDS)
    {
      w = t->tv_sec / WEEK_IN_SECONDS;
      t->tv_sec -= w * WEEK_IN_SECONDS;
    }
  
  if (t->tv_sec > DAY_IN_SECONDS)
    {
      d = t->tv_sec / DAY_IN_SECONDS;
      t->tv_sec -= d * DAY_IN_SECONDS;
    }
  
  if (t->tv_sec >= HOUR_IN_SECONDS)
    {
      h = t->tv_sec / HOUR_IN_SECONDS;
      t->tv_sec -= h * HOUR_IN_SECONDS;
    }
  
  if (t->tv_sec >= MINUTE_IN_SECONDS)
    {
      m = t->tv_sec / MINUTE_IN_SECONDS;
      t->tv_sec -= m * MINUTE_IN_SECONDS;
    }
  
  if (w > 99)
    snprintf (buf, size, "%ldw%1ldd", w, d);
  else if (w)
    snprintf (buf, size, "%ldw%1ldd%02ldh", w, d, h);
  else if (d)
    snprintf (buf, size, "%1ldd%02ldh%02ldm", d, h, m);
  else if (h)
    snprintf (buf, size, "%ldh%02ldm%02lds", h, m, (long)t->tv_sec);
  else if (m)
    snprintf (buf, size, "%ldm%02lds", m, (long)t->tv_sec);
  else if (ms)
    snprintf (buf, size, "%ld.%03lds", (long)t->tv_sec, ms);
  else
    snprintf (buf, size, "%ld usecs", (long)t->tv_usec);

  return buf;
}

const char *
ospf_timer_dump (struct thread *t, char *buf, size_t size)
{
  struct timeval result;
  if (!t)
    return "inactive";
  
  result = tv_sub (t->u.sands, recent_relative_time());
  return ospf_timeval_dump (&result, buf, size);
}

static void
ospf_packet_hello_dump (struct stream *s, u_int16_t length)
{
  struct ospf_hello *hello;
  int i;

  hello = (struct ospf_hello *) STREAM_PNT (s);

  zlog_debug ("Hello");
  zlog_debug ("  NetworkMask %s", inet_ntoa (hello->network_mask));
  zlog_debug ("  HelloInterval %d", ntohs (hello->hello_interval));
  zlog_debug ("  Options %d (%s)", hello->options,
	     ospf_options_dump (hello->options));
  zlog_debug ("  RtrPriority %d", hello->priority);
  zlog_debug ("  RtrDeadInterval %ld", (u_long)ntohl (hello->dead_interval));
  zlog_debug ("  DRouter %s", inet_ntoa (hello->d_router));
  zlog_debug ("  BDRouter %s", inet_ntoa (hello->bd_router));

  length -= OSPF_HEADER_SIZE + OSPF_HELLO_MIN_SIZE;
  zlog_debug ("  # Neighbors %d", length / 4);
  for (i = 0; length > 0; i++, length -= sizeof (struct in_addr))
    zlog_debug ("    Neighbor %s", inet_ntoa (hello->neighbors[i]));
}

static char *
ospf_dd_flags_dump (u_char flags, char *buf, size_t size)
{
  memset (buf, 0, size);

  snprintf (buf, size, "%s|%s|%s",
	    (flags & OSPF_DD_FLAG_I) ? "I" : "-",
	    (flags & OSPF_DD_FLAG_M) ? "M" : "-",
	    (flags & OSPF_DD_FLAG_MS) ? "MS" : "-");

  return buf;
}

static char *
ospf_router_lsa_flags_dump (u_char flags, char *buf, size_t size)
{
  memset (buf, 0, size);

  snprintf (buf, size, "%s|%s|%s",
	    (flags & ROUTER_LSA_VIRTUAL) ? "V" : "-",
	    (flags & ROUTER_LSA_EXTERNAL) ? "E" : "-",
	    (flags & ROUTER_LSA_BORDER) ? "B" : "-");

  return buf;
}

static void
ospf_router_lsa_dump (struct stream *s, u_int16_t length)
{
  char buf[BUFSIZ];
  struct router_lsa *rl;
  int i, len;

  rl = (struct router_lsa *) STREAM_PNT (s);

  zlog_debug ("  Router-LSA");
  zlog_debug ("    flags %s", 
	     ospf_router_lsa_flags_dump (rl->flags, buf, BUFSIZ));
  zlog_debug ("    # links %d", ntohs (rl->links));

  len = ntohs (rl->header.length) - OSPF_LSA_HEADER_SIZE - 4;
  for (i = 0; len > 0; i++)
    {
      zlog_debug ("    Link ID %s", inet_ntoa (rl->link[i].link_id));
      zlog_debug ("    Link Data %s", inet_ntoa (rl->link[i].link_data));
      zlog_debug ("    Type %d", (u_char) rl->link[i].type);
      zlog_debug ("    TOS %d", (u_char) rl->link[i].tos);
      zlog_debug ("    metric %d", ntohs (rl->link[i].metric));

      len -= 12;
    }
}

static void
ospf_network_lsa_dump (struct stream *s, u_int16_t length)
{
  struct network_lsa *nl;
  int i, cnt;

  nl = (struct network_lsa *) STREAM_PNT (s);
  cnt = (ntohs (nl->header.length) - (OSPF_LSA_HEADER_SIZE + 4)) / 4;
  
  zlog_debug ("  Network-LSA");
  /*
  zlog_debug ("LSA total size %d", ntohs (nl->header.length));
  zlog_debug ("Network-LSA size %d", 
  ntohs (nl->header.length) - OSPF_LSA_HEADER_SIZE);
  */
  zlog_debug ("    Network Mask %s", inet_ntoa (nl->mask));
  zlog_debug ("    # Attached Routers %d", cnt);
  for (i = 0; i < cnt; i++)
    zlog_debug ("      Attached Router %s", inet_ntoa (nl->routers[i]));
}

static void
ospf_summary_lsa_dump (struct stream *s, u_int16_t length)
{
  struct summary_lsa *sl;
  int size;
  int i;

  sl = (struct summary_lsa *) STREAM_PNT (s);

  zlog_debug ("  Summary-LSA");
  zlog_debug ("    Network Mask %s", inet_ntoa (sl->mask));

  size = ntohs (sl->header.length) - OSPF_LSA_HEADER_SIZE - 4;
  for (i = 0; size > 0; size -= 4, i++)
    zlog_debug ("    TOS=%d metric %d", sl->tos,
	       GET_METRIC (sl->metric));
}

static void
ospf_as_external_lsa_dump (struct stream *s, u_int16_t length)
{
  struct as_external_lsa *al;
  int size;
  int i;

  al = (struct as_external_lsa *) STREAM_PNT (s);
  zlog_debug ("  %s", ospf_lsa_type_msg[al->header.type].str);
  zlog_debug ("    Network Mask %s", inet_ntoa (al->mask));

  size = ntohs (al->header.length) - OSPF_LSA_HEADER_SIZE -4;
  for (i = 0; size > 0; size -= 12, i++)
    {
      zlog_debug ("    bit %s TOS=%d metric %d",
		 IS_EXTERNAL_METRIC (al->e[i].tos) ? "E" : "-",
		 al->e[i].tos & 0x7f, GET_METRIC (al->e[i].metric));
      zlog_debug ("    Forwarding address %s", inet_ntoa (al->e[i].fwd_addr));
      zlog_debug ("    External Route Tag %"ROUTE_TAG_PRI, al->e[i].route_tag);
    }
}

static void
ospf_lsa_header_list_dump (struct stream *s, u_int16_t length)
{
  struct lsa_header *lsa;

  zlog_debug ("  # LSA Headers %d", length / OSPF_LSA_HEADER_SIZE);

  /* LSA Headers. */
  while (length > 0)
    {
      lsa = (struct lsa_header *) STREAM_PNT (s);
      ospf_lsa_header_dump (lsa);

      stream_forward_getp (s, OSPF_LSA_HEADER_SIZE);
      length -= OSPF_LSA_HEADER_SIZE;
    }
}

static void
ospf_packet_db_desc_dump (struct stream *s, u_int16_t length)
{
  struct ospf_db_desc *dd;
  char dd_flags[8];

  u_int32_t gp;

  gp = stream_get_getp (s);
  dd = (struct ospf_db_desc *) STREAM_PNT (s);

  zlog_debug ("Database Description");
  zlog_debug ("  Interface MTU %d", ntohs (dd->mtu));
  zlog_debug ("  Options %d (%s)", dd->options,
	     ospf_options_dump (dd->options));
  zlog_debug ("  Flags %d (%s)", dd->flags,
	     ospf_dd_flags_dump (dd->flags, dd_flags, sizeof dd_flags));
  zlog_debug ("  Sequence Number 0x%08lx", (u_long)ntohl (dd->dd_seqnum));

  length -= OSPF_HEADER_SIZE + OSPF_DB_DESC_MIN_SIZE;

  stream_forward_getp (s, OSPF_DB_DESC_MIN_SIZE);

  ospf_lsa_header_list_dump (s, length);

  stream_set_getp (s, gp);
}

static void
ospf_packet_ls_req_dump (struct stream *s, u_int16_t length)
{
  u_int32_t sp;
  u_int32_t ls_type;
  struct in_addr ls_id;
  struct in_addr adv_router;

  sp = stream_get_getp (s);

  length -= OSPF_HEADER_SIZE;

  zlog_debug ("Link State Request");
  zlog_debug ("  # Requests %d", length / 12);

  for (; length > 0; length -= 12)
    {
      ls_type = stream_getl (s);
      ls_id.s_addr = stream_get_ipv4 (s);
      adv_router.s_addr = stream_get_ipv4 (s);

      zlog_debug ("  LS type %d", ls_type);
      zlog_debug ("  Link State ID %s", inet_ntoa (ls_id));
      zlog_debug ("  Advertising Router %s",
		 inet_ntoa (adv_router));
    }

  stream_set_getp (s, sp);
}

static void
ospf_packet_ls_upd_dump (struct stream *s, u_int16_t length)
{
  u_int32_t sp;
  struct lsa_header *lsa;
  int lsa_len;
  u_int32_t count;

  length -= OSPF_HEADER_SIZE;

  sp = stream_get_getp (s);

  count = stream_getl (s);
  length -= 4;

  zlog_debug ("Link State Update");
  zlog_debug ("  # LSAs %d", count);

  while (length > 0 && count > 0)
    {
      if (length < OSPF_HEADER_SIZE || length % 4 != 0)
	{
          zlog_debug ("  Remaining %d bytes; Incorrect length.", length);
	  break;
	}

      lsa = (struct lsa_header *) STREAM_PNT (s);
      lsa_len = ntohs (lsa->length);
      ospf_lsa_header_dump (lsa);

      switch (lsa->type)
	{
	case OSPF_ROUTER_LSA:
	  ospf_router_lsa_dump (s, length);
	  break;
	case OSPF_NETWORK_LSA:
	  ospf_network_lsa_dump (s, length);
	  break;
	case OSPF_SUMMARY_LSA:
	case OSPF_ASBR_SUMMARY_LSA:
	  ospf_summary_lsa_dump (s, length);
	  break;
	case OSPF_AS_EXTERNAL_LSA:
	  ospf_as_external_lsa_dump (s, length);
	  break;
	case OSPF_AS_NSSA_LSA:
	  ospf_as_external_lsa_dump (s, length);
	  break;
	case OSPF_OPAQUE_LINK_LSA:
	case OSPF_OPAQUE_AREA_LSA:
	case OSPF_OPAQUE_AS_LSA:
	  ospf_opaque_lsa_dump (s, length);
	  break;
	default:
	  break;
	}

      stream_forward_getp (s, lsa_len);
      length -= lsa_len;
      count--;
    }

  stream_set_getp (s, sp);
}

static void
ospf_packet_ls_ack_dump (struct stream *s, u_int16_t length)
{
  u_int32_t sp;

  length -= OSPF_HEADER_SIZE;
  sp = stream_get_getp (s);

  zlog_debug ("Link State Acknowledgment");
  ospf_lsa_header_list_dump (s, length);

  stream_set_getp (s, sp);
}

/* Expects header to be in host order */
void
ospf_ip_header_dump (struct ip *iph)
{
  /* IP Header dump. */
  zlog_debug ("ip_v %d", iph->ip_v);
  zlog_debug ("ip_hl %d", iph->ip_hl);
  zlog_debug ("ip_tos %d", iph->ip_tos);
  zlog_debug ("ip_len %d", iph->ip_len);
  zlog_debug ("ip_id %u", (u_int32_t) iph->ip_id);
  zlog_debug ("ip_off %u", (u_int32_t) iph->ip_off);
  zlog_debug ("ip_ttl %d", iph->ip_ttl);
  zlog_debug ("ip_p %d", iph->ip_p);
  zlog_debug ("ip_sum 0x%x", (u_int32_t) iph->ip_sum);
  zlog_debug ("ip_src %s",  inet_ntoa (iph->ip_src));
  zlog_debug ("ip_dst %s", inet_ntoa (iph->ip_dst));
}

static void
ospf_header_dump (struct ospf_header *ospfh)
{
  char buf[9];
  u_int16_t auth_type = ntohs (ospfh->auth_type);

  zlog_debug ("Header");
  zlog_debug ("  Version %d", ospfh->version);
  zlog_debug ("  Type %d (%s)", ospfh->type,
	     LOOKUP (ospf_packet_type_str, ospfh->type));
  zlog_debug ("  Packet Len %d", ntohs (ospfh->length));
  zlog_debug ("  Router ID %s", inet_ntoa (ospfh->router_id));
  zlog_debug ("  Area ID %s", inet_ntoa (ospfh->area_id));
  zlog_debug ("  Checksum 0x%x", ntohs (ospfh->checksum));
  zlog_debug ("  AuType %s", LOOKUP (ospf_auth_type_str, auth_type));

  switch (auth_type)
    {
    case OSPF_AUTH_NULL:
      break;
    case OSPF_AUTH_SIMPLE:
      memset (buf, 0, 9);
      strncpy (buf, (char *) ospfh->u.auth_data, 8);
      zlog_debug ("  Simple Password %s", buf);
      break;
    case OSPF_AUTH_CRYPTOGRAPHIC:
      zlog_debug ("  Cryptographic Authentication");
      zlog_debug ("  Key ID %d", ospfh->u.crypt.key_id);
      zlog_debug ("  Auth Data Len %d", ospfh->u.crypt.auth_data_len);
      zlog_debug ("  Sequence number %ld",
		 (u_long)ntohl (ospfh->u.crypt.crypt_seqnum));
      break;
    default:
      zlog_debug ("* This is not supported authentication type");
      break;
    }
    
}

void
ospf_packet_dump (struct stream *s)
{
  struct ospf_header *ospfh;
  unsigned long gp;

  /* Preserve pointer. */
  gp = stream_get_getp (s);

  /* OSPF Header dump. */
  ospfh = (struct ospf_header *) STREAM_PNT (s);

  /* Until detail flag is set, return. */
  if (!(term_debug_ospf_packet[ospfh->type - 1] & OSPF_DEBUG_DETAIL))
    return;

  /* Show OSPF header detail. */
  ospf_header_dump (ospfh);
  stream_forward_getp (s, OSPF_HEADER_SIZE);

  switch (ospfh->type)
    {
    case OSPF_MSG_HELLO:
      ospf_packet_hello_dump (s, ntohs (ospfh->length));
      break;
    case OSPF_MSG_DB_DESC:
      ospf_packet_db_desc_dump (s, ntohs (ospfh->length));
      break;
    case OSPF_MSG_LS_REQ:
      ospf_packet_ls_req_dump (s, ntohs (ospfh->length));
      break;
    case OSPF_MSG_LS_UPD:
      ospf_packet_ls_upd_dump (s, ntohs (ospfh->length));
      break;
    case OSPF_MSG_LS_ACK:
      ospf_packet_ls_ack_dump (s, ntohs (ospfh->length));
      break;
    default:
      break;
    }

  stream_set_getp (s, gp);
}


/*
   [no] debug ospf [<1-65535>] packet (hello|dd|ls-request|ls-update|ls-ack|all)
                          [send|recv [detail]]
*/
static int
debug_ospf_packet_common (struct vty *vty, int arg_base, int argc,
                          const char **argv)
{
  int type = 0;
  int flag = 0;
  int i;

  assert (argc > arg_base + 0);

  /* Check packet type. */
  if (strncmp (argv[arg_base + 0], "h", 1) == 0)
    type = OSPF_DEBUG_HELLO;
  else if (strncmp (argv[arg_base + 0], "d", 1) == 0)
    type = OSPF_DEBUG_DB_DESC;
  else if (strncmp (argv[arg_base + 0], "ls-r", 4) == 0)
    type = OSPF_DEBUG_LS_REQ;
  else if (strncmp (argv[arg_base + 0], "ls-u", 4) == 0)
    type = OSPF_DEBUG_LS_UPD;
  else if (strncmp (argv[arg_base + 0], "ls-a", 4) == 0)
    type = OSPF_DEBUG_LS_ACK;
  else if (strncmp (argv[arg_base + 0], "a", 1) == 0)
    type = OSPF_DEBUG_ALL;

  /* Default, both send and recv. */
  if (argc == arg_base + 1)
    flag = OSPF_DEBUG_SEND | OSPF_DEBUG_RECV;

  /* send or recv. */
  if (argc >= arg_base + 2)
    {
      if (strncmp (argv[arg_base + 1], "s", 1) == 0)
	flag = OSPF_DEBUG_SEND;
      else if (strncmp (argv[arg_base + 1], "r", 1) == 0)
	flag = OSPF_DEBUG_RECV;
      else if (strncmp (argv[arg_base + 1], "d", 1) == 0)
	flag = OSPF_DEBUG_SEND | OSPF_DEBUG_RECV | OSPF_DEBUG_DETAIL;
    }

  /* detail. */
  if (argc == arg_base + 3)
    if (strncmp (argv[arg_base + 2], "d", 1) == 0)
      flag |= OSPF_DEBUG_DETAIL;

  for (i = 0; i < 5; i++)
    if (type & (0x01 << i))
      {
	if (vty->node == CONFIG_NODE)
	  DEBUG_PACKET_ON (i, flag);
	else
	  TERM_DEBUG_PACKET_ON (i, flag);
      }

  return CMD_SUCCESS;
}

DEFUN (debug_ospf_packet,
       debug_ospf_packet_all_cmd,
       "debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all)",
       DEBUG_STR
       OSPF_STR
       "OSPF packets\n"
       "OSPF Hello\n"
       "OSPF Database Description\n"
       "OSPF Link State Request\n"
       "OSPF Link State Update\n"
       "OSPF Link State Acknowledgment\n"
       "OSPF all packets\n")
{
  return (debug_ospf_packet_common(vty, 0, argc, argv));
}

ALIAS (debug_ospf_packet,
       debug_ospf_packet_send_recv_cmd,
       "debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv|detail)",
       "Debugging functions\n"
       "OSPF information\n"
       "OSPF packets\n"
       "OSPF Hello\n"
       "OSPF Database Description\n"
       "OSPF Link State Request\n"
       "OSPF Link State Update\n"
       "OSPF Link State Acknowledgment\n"
       "OSPF all packets\n"
       "Packet sent\n"
       "Packet received\n"
       "Detail information\n")

ALIAS (debug_ospf_packet,
       debug_ospf_packet_send_recv_detail_cmd,
       "debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv) (detail|)",
       "Debugging functions\n"
       "OSPF information\n"
       "OSPF packets\n"
       "OSPF Hello\n"
       "OSPF Database Description\n"
       "OSPF Link State Request\n"
       "OSPF Link State Update\n"
       "OSPF Link State Acknowledgment\n"
       "OSPF all packets\n"
       "Packet sent\n"
       "Packet received\n"
       "Detail Information\n")
       
DEFUN (debug_ospf_instance_packet,
       debug_ospf_instance_packet_all_cmd,
       "debug ospf <1-65535> packet (hello|dd|ls-request|ls-update|ls-ack|all)",
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF packets\n"
       "OSPF Hello\n"
       "OSPF Database Description\n"
       "OSPF Link State Request\n"
       "OSPF Link State Update\n"
       "OSPF Link State Acknowledgment\n"
       "OSPF all packets\n")
{
  u_short instance = 0;

  VTY_GET_INTEGER ("Instance", instance, argv[0]);
  if (!ospf_lookup_instance (instance))
    return CMD_SUCCESS;

  return (debug_ospf_packet_common(vty, 1, argc, argv));
}

ALIAS (debug_ospf_instance_packet,
       debug_ospf_instance_packet_send_recv_cmd,
       "debug ospf <1-65535> packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv|detail)",
       "Debugging functions\n"
       "OSPF information\n"
       "Instance ID\n"
       "OSPF packets\n"
       "OSPF Hello\n"
       "OSPF Database Description\n"
       "OSPF Link State Request\n"
       "OSPF Link State Update\n"
       "OSPF Link State Acknowledgment\n"
       "OSPF all packets\n"
       "Packet sent\n"
       "Packet received\n"
       "Detail information\n")

ALIAS (debug_ospf_instance_packet,
       debug_ospf_instance_packet_send_recv_detail_cmd,
       "debug ospf <1-65535> packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv) (detail|)",
       "Debugging functions\n"
       "OSPF information\n"
       "Instance ID\n"
       "OSPF packets\n"
       "OSPF Hello\n"
       "OSPF Database Description\n"
       "OSPF Link State Request\n"
       "OSPF Link State Update\n"
       "OSPF Link State Acknowledgment\n"
       "OSPF all packets\n"
       "Packet sent\n"
       "Packet received\n"
       "Detail Information\n")

static int
no_debug_ospf_packet_common (struct vty *vty, int arg_base, int argc,
                             const char **argv)
{
  int type = 0;
  int flag = 0;
  int i;

  assert (argc > arg_base + 0);

  /* Check packet type. */
  if (strncmp (argv[arg_base + 0], "h", 1) == 0)
    type = OSPF_DEBUG_HELLO;
  else if (strncmp (argv[arg_base + 0], "d", 1) == 0)
    type = OSPF_DEBUG_DB_DESC;
  else if (strncmp (argv[arg_base + 0], "ls-r", 4) == 0)
    type = OSPF_DEBUG_LS_REQ;
  else if (strncmp (argv[arg_base + 0], "ls-u", 4) == 0)
    type = OSPF_DEBUG_LS_UPD;
  else if (strncmp (argv[arg_base + 0], "ls-a", 4) == 0)
    type = OSPF_DEBUG_LS_ACK;
  else if (strncmp (argv[arg_base + 0], "a", 1) == 0)
    type = OSPF_DEBUG_ALL;

  /* Default, both send and recv. */
  if (argc == arg_base + 1)
    flag = OSPF_DEBUG_SEND | OSPF_DEBUG_RECV | OSPF_DEBUG_DETAIL ;

  /* send or recv. */
  if (argc == arg_base + 2)
    {
      if (strncmp (argv[arg_base + 1], "s", 1) == 0)
	flag = OSPF_DEBUG_SEND | OSPF_DEBUG_DETAIL;
      else if (strncmp (argv[arg_base + 1], "r", 1) == 0)
	flag = OSPF_DEBUG_RECV | OSPF_DEBUG_DETAIL;
      else if (strncmp (argv[arg_base + 1], "d", 1) == 0)
	flag = OSPF_DEBUG_DETAIL | OSPF_DEBUG_RECV | OSPF_DEBUG_DETAIL;
    }

  /* detail. */
  if (argc == arg_base + 3)
    if (strncmp (argv[arg_base + 2], "d", 1) == 0)
      flag = OSPF_DEBUG_DETAIL;

  for (i = 0; i < 5; i++)
    if (type & (0x01 << i))
      {
	if (vty->node == CONFIG_NODE)
	  DEBUG_PACKET_OFF (i, flag);
	else
	  TERM_DEBUG_PACKET_OFF (i, flag);
      }

#ifdef DEBUG
  /*
  for (i = 0; i < 5; i++)
    zlog_debug ("flag[%d] = %d", i, ospf_debug_packet[i]);
  */
#endif /* DEBUG */

  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf_packet,
       no_debug_ospf_packet_all_cmd,
       "no debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all)",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF packets\n"
       "OSPF Hello\n"
       "OSPF Database Description\n"
       "OSPF Link State Request\n"
       "OSPF Link State Update\n"
       "OSPF Link State Acknowledgment\n"
       "OSPF all packets\n")
{
  return no_debug_ospf_packet_common(vty, 0, argc, argv);
}

ALIAS (no_debug_ospf_packet,
       no_debug_ospf_packet_send_recv_cmd,
       "no debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv|detail)",
       NO_STR
       "Debugging functions\n"
       "OSPF information\n"
       "OSPF packets\n"
       "OSPF Hello\n"
       "OSPF Database Description\n"
       "OSPF Link State Request\n"
       "OSPF Link State Update\n"
       "OSPF Link State Acknowledgment\n"
       "OSPF all packets\n"
       "Packet sent\n"
       "Packet received\n"
       "Detail Information\n")

ALIAS (no_debug_ospf_packet,
       no_debug_ospf_packet_send_recv_detail_cmd,
       "no debug ospf packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv) (detail|)",
       NO_STR
       "Debugging functions\n"
       "OSPF information\n"
       "OSPF packets\n"
       "OSPF Hello\n"
       "OSPF Database Description\n"
       "OSPF Link State Request\n"
       "OSPF Link State Update\n"
       "OSPF Link State Acknowledgment\n"
       "OSPF all packets\n"
       "Packet sent\n"
       "Packet received\n"
       "Detail Information\n")

DEFUN (no_debug_ospf_instance_packet,
       no_debug_ospf_instance_packet_all_cmd,
       "no debug ospf <1-65535> packet (hello|dd|ls-request|ls-update|ls-ack|all)",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF packets\n"
       "OSPF Hello\n"
       "OSPF Database Description\n"
       "OSPF Link State Request\n"
       "OSPF Link State Update\n"
       "OSPF Link State Acknowledgment\n"
       "OSPF all packets\n")
{
  u_short instance = 0;

  VTY_GET_INTEGER ("Instance", instance, argv[0]);
  if (!ospf_lookup_instance (instance))
    return CMD_SUCCESS;

  return (no_debug_ospf_packet_common(vty, 1, argc, argv));
}

ALIAS (no_debug_ospf_instance_packet,
       no_debug_ospf_instance_packet_send_recv_cmd,
       "no debug ospf <1-65535> packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv|detail)",
       NO_STR
       "Debugging functions\n"
       "OSPF information\n"
       "Instance ID\n"
       "OSPF packets\n"
       "OSPF Hello\n"
       "OSPF Database Description\n"
       "OSPF Link State Request\n"
       "OSPF Link State Update\n"
       "OSPF Link State Acknowledgment\n"
       "OSPF all packets\n"
       "Packet sent\n"
       "Packet received\n"
       "Detail Information\n")

ALIAS (no_debug_ospf_instance_packet,
       no_debug_ospf_instance_packet_send_recv_detail_cmd,
       "no debug ospf <1-65535> packet (hello|dd|ls-request|ls-update|ls-ack|all) (send|recv) (detail|)",
       NO_STR
       "Debugging functions\n"
       "OSPF information\n"
       "Instance ID\n"
       "OSPF packets\n"
       "OSPF Hello\n"
       "OSPF Database Description\n"
       "OSPF Link State Request\n"
       "OSPF Link State Update\n"
       "OSPF Link State Acknowledgment\n"
       "OSPF all packets\n"
       "Packet sent\n"
       "Packet received\n"
       "Detail Information\n")


static int
debug_ospf_ism_common (struct vty *vty, int arg_base, int argc, const char **argv)
{
  if (vty->node == CONFIG_NODE)
    {
      if (argc == arg_base + 0)
	DEBUG_ON (ism, ISM);
      else if (argc == arg_base + 1)
	{
	  if (strncmp (argv[arg_base + 0], "s", 1) == 0)
	    DEBUG_ON (ism, ISM_STATUS);
	  else if (strncmp (argv[arg_base + 0], "e", 1) == 0)
	    DEBUG_ON (ism, ISM_EVENTS);
	  else if (strncmp (argv[arg_base + 0], "t", 1) == 0)
	    DEBUG_ON (ism, ISM_TIMERS);
	}

      return CMD_SUCCESS;
    }

  /* ENABLE_NODE. */
  if (argc == arg_base + 0)
    TERM_DEBUG_ON (ism, ISM);
  else if (argc == arg_base + 1)
    {
      if (strncmp (argv[arg_base + 0], "s", 1) == 0)
	TERM_DEBUG_ON (ism, ISM_STATUS);
      else if (strncmp (argv[arg_base + 0], "e", 1) == 0)
	TERM_DEBUG_ON (ism, ISM_EVENTS);
      else if (strncmp (argv[arg_base + 0], "t", 1) == 0)
	TERM_DEBUG_ON (ism, ISM_TIMERS);
    }

  return CMD_SUCCESS;
}

DEFUN (debug_ospf_ism,
       debug_ospf_ism_cmd,
       "debug ospf ism",
       DEBUG_STR
       OSPF_STR
       "OSPF Interface State Machine\n")
{
  return debug_ospf_ism_common(vty, 0, argc, argv);
}

ALIAS (debug_ospf_ism,
       debug_ospf_ism_sub_cmd,
       "debug ospf ism (status|events|timers)",
       DEBUG_STR
       OSPF_STR
       "OSPF Interface State Machine\n"
       "ISM Status Information\n"
       "ISM Event Information\n"
       "ISM TImer Information\n")

DEFUN (debug_ospf_instance_ism,
       debug_ospf_instance_ism_cmd,
       "debug ospf <1-65535> ism",
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF Interface State Machine\n")
{
  u_short instance = 0;

  VTY_GET_INTEGER ("Instance", instance, argv[0]);
  if (!ospf_lookup_instance (instance))
    return CMD_SUCCESS;

  return debug_ospf_ism_common(vty, 1, argc, argv);
}

ALIAS (debug_ospf_instance_ism,
       debug_ospf_instance_ism_sub_cmd,
       "debug ospf <1-65535> ism (status|events|timers)",
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF Interface State Machine\n"
       "ISM Status Information\n"
       "ISM Event Information\n"
       "ISM TImer Information\n")

static int
no_debug_ospf_ism_common(struct vty *vty, int arg_base, int argc,
                         const char **argv)
{
  if (vty->node == CONFIG_NODE)
    {
      if (argc == arg_base + 0)
	DEBUG_OFF (ism, ISM);
      else if (argc == arg_base + 1)
	{
	  if (strncmp (argv[arg_base + 0], "s", 1) == 0)
	    DEBUG_OFF (ism, ISM_STATUS);
	  else if (strncmp (argv[arg_base + 0], "e", 1) == 0)
	    DEBUG_OFF (ism, ISM_EVENTS);
	  else if (strncmp (argv[arg_base + 0], "t", 1) == 0)
	    DEBUG_OFF (ism, ISM_TIMERS);
	}
      return CMD_SUCCESS;
    }

  /* ENABLE_NODE. */
  if (argc == arg_base + 0)
    TERM_DEBUG_OFF (ism, ISM);
  else if (argc == arg_base + 1)
    {
      if (strncmp (argv[arg_base + 0], "s", 1) == 0)
	TERM_DEBUG_OFF (ism, ISM_STATUS);
      else if (strncmp (argv[arg_base + 0], "e", 1) == 0)
	TERM_DEBUG_OFF (ism, ISM_EVENTS);
      else if (strncmp (argv[arg_base + 0], "t", 1) == 0)
	TERM_DEBUG_OFF (ism, ISM_TIMERS);
    }

  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf_ism,
       no_debug_ospf_ism_cmd,
       "no debug ospf ism",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF Interface State Machine")
{
  return no_debug_ospf_ism_common(vty, 0, argc, argv);
}

ALIAS (no_debug_ospf_ism,
       no_debug_ospf_ism_sub_cmd,
       "no debug ospf ism (status|events|timers)",
       NO_STR
       "Debugging functions\n"
       "OSPF information\n"
       "OSPF Interface State Machine\n"
       "ISM Status Information\n"
       "ISM Event Information\n"
       "ISM Timer Information\n")

DEFUN (no_debug_ospf_instance_ism,
       no_debug_ospf_instance_ism_cmd,
       "no debug ospf <1-65535> ism",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF Interface State Machine")
{
  u_short instance = 0;

  VTY_GET_INTEGER ("Instance", instance, argv[0]);
  if (!ospf_lookup_instance (instance))
    return CMD_SUCCESS;

  return no_debug_ospf_ism_common(vty, 1, argc, argv);
}

ALIAS (no_debug_ospf_instance_ism,
       no_debug_ospf_instance_ism_sub_cmd,
       "no debug ospf <1-65535> ism (status|events|timers)",
       NO_STR
       "Debugging functions\n"
       "OSPF information\n"
       "Instance ID\n"
       "OSPF Interface State Machine\n"
       "ISM Status Information\n"
       "ISM Event Information\n"
       "ISM Timer Information\n")

static int
debug_ospf_nsm_common (struct vty *vty, int arg_base, int argc, const char **argv)
{
  if (vty->node == CONFIG_NODE)
    {
      if (argc == arg_base + 0)
	DEBUG_ON (nsm, NSM);
      else if (argc == arg_base + 1)
	{
	  if (strncmp (argv[arg_base + 0], "s", 1) == 0)
	    DEBUG_ON (nsm, NSM_STATUS);
	  else if (strncmp (argv[arg_base + 0], "e", 1) == 0)
	    DEBUG_ON (nsm, NSM_EVENTS);
	  else if (strncmp (argv[arg_base + 0], "t", 1) == 0)
	    DEBUG_ON (nsm, NSM_TIMERS);
	}

      return CMD_SUCCESS;
    }

  /* ENABLE_NODE. */
  if (argc == arg_base + 0)
    TERM_DEBUG_ON (nsm, NSM);
  else if (argc == arg_base + 1)
    {
      if (strncmp (argv[arg_base + 0], "s", 1) == 0)
	TERM_DEBUG_ON (nsm, NSM_STATUS);
      else if (strncmp (argv[arg_base + 0], "e", 1) == 0)
	TERM_DEBUG_ON (nsm, NSM_EVENTS);
      else if (strncmp (argv[arg_base + 0], "t", 1) == 0)
	TERM_DEBUG_ON (nsm, NSM_TIMERS);
    }

  return CMD_SUCCESS;
}

DEFUN (debug_ospf_nsm,
       debug_ospf_nsm_cmd,
       "debug ospf nsm",
       DEBUG_STR
       OSPF_STR
       "OSPF Neighbor State Machine\n")
{
  return debug_ospf_nsm_common (vty, 0, argc, argv);
}

ALIAS (debug_ospf_nsm,
       debug_ospf_nsm_sub_cmd,
       "debug ospf nsm (status|events|timers)",
       DEBUG_STR
       OSPF_STR
       "OSPF Neighbor State Machine\n"
       "NSM Status Information\n"
       "NSM Event Information\n"
       "NSM Timer Information\n")

DEFUN (debug_ospf_instance_nsm,
       debug_ospf_instance_nsm_cmd,
       "debug ospf <1-65535> nsm",
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF Neighbor State Machine\n")
{
  u_short instance = 0;

  VTY_GET_INTEGER ("Instance", instance, argv[0]);
  if (!ospf_lookup_instance (instance))
    return CMD_SUCCESS;

  return debug_ospf_nsm_common (vty, 1, argc, argv);
}

ALIAS (debug_ospf_instance_nsm,
       debug_ospf_instance_nsm_sub_cmd,
       "debug ospf <1-65535> nsm (status|events|timers)",
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF Neighbor State Machine\n"
       "NSM Status Information\n"
       "NSM Event Information\n"
       "NSM Timer Information\n")

static int
no_debug_ospf_nsm_common (struct vty *vty, int arg_base, int argc, const char **argv)
{
  if (vty->node == CONFIG_NODE)
    {
      if (argc == arg_base + 0)
	DEBUG_OFF (nsm, NSM);
      else if (argc == arg_base + 1)
	{
	  if (strncmp (argv[arg_base + 0], "s", 1) == 0)
	    DEBUG_OFF (nsm, NSM_STATUS);
	  else if (strncmp (argv[arg_base + 0], "e", 1) == 0)
	    DEBUG_OFF (nsm, NSM_EVENTS);
	  else if (strncmp (argv[arg_base + 0], "t", 1) == 0)
	    DEBUG_OFF (nsm, NSM_TIMERS);
	}

      return CMD_SUCCESS;
    }

  /* ENABLE_NODE. */
  if (argc == arg_base + 0)
    TERM_DEBUG_OFF (nsm, NSM);
  else if (argc == arg_base + 1)
    {
      if (strncmp (argv[arg_base + 0], "s", 1) == 0)
	TERM_DEBUG_OFF (nsm, NSM_STATUS);
      else if (strncmp (argv[arg_base + 0], "e", 1) == 0)
	TERM_DEBUG_OFF (nsm, NSM_EVENTS);
      else if (strncmp (argv[arg_base + 0], "t", 1) == 0)
	TERM_DEBUG_OFF (nsm, NSM_TIMERS);
    }

  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf_nsm,
       no_debug_ospf_nsm_cmd,
       "no debug ospf nsm",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF Neighbor State Machine")
{
  return no_debug_ospf_nsm_common(vty, 0, argc, argv);
}

ALIAS (no_debug_ospf_nsm,
       no_debug_ospf_nsm_sub_cmd,
       "no debug ospf nsm (status|events|timers)",
       NO_STR
       "Debugging functions\n"
       "OSPF information\n"
       "OSPF Interface State Machine\n"
       "NSM Status Information\n"
       "NSM Event Information\n"
       "NSM Timer Information\n")

DEFUN (no_debug_ospf_instance_nsm,
       no_debug_ospf_instance_nsm_cmd,
       "no debug ospf <1-65535> nsm",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF Neighbor State Machine")
{
  u_short instance = 0;

  VTY_GET_INTEGER ("Instance", instance, argv[0]);
  if (!ospf_lookup_instance (instance))
    return CMD_SUCCESS;

  return no_debug_ospf_nsm_common(vty, 1, argc, argv);
}

ALIAS (no_debug_ospf_instance_nsm,
       no_debug_ospf_instance_nsm_sub_cmd,
       "no debug ospf <1-65535> nsm (status|events|timers)",
       NO_STR
       "Debugging functions\n"
       "OSPF information\n"
       "Instance ID\n"
       "OSPF Interface State Machine\n"
       "NSM Status Information\n"
       "NSM Event Information\n"
       "NSM Timer Information\n")


static int
debug_ospf_lsa_common (struct vty *vty, int arg_base, int argc, const char **argv)
{
  if (vty->node == CONFIG_NODE)
    {
      if (argc == arg_base + 0)
	DEBUG_ON (lsa, LSA);
      else if (argc == arg_base + 1)
	{
	  if (strncmp (argv[arg_base + 0], "g", 1) == 0)
	    DEBUG_ON (lsa, LSA_GENERATE);
	  else if (strncmp (argv[arg_base + 0], "f", 1) == 0)
	    DEBUG_ON (lsa, LSA_FLOODING);
	  else if (strncmp (argv[arg_base + 0], "i", 1) == 0)
	    DEBUG_ON (lsa, LSA_INSTALL);
	  else if (strncmp (argv[arg_base + 0], "r", 1) == 0)
	    DEBUG_ON (lsa, LSA_REFRESH);
	}

      return CMD_SUCCESS;
    }

  /* ENABLE_NODE. */
  if (argc == arg_base + 0)
    TERM_DEBUG_ON (lsa, LSA);
  else if (argc == arg_base + 1)
    {
      if (strncmp (argv[arg_base + 0], "g", 1) == 0)
	TERM_DEBUG_ON (lsa, LSA_GENERATE);
      else if (strncmp (argv[arg_base + 0], "f", 1) == 0)
	TERM_DEBUG_ON (lsa, LSA_FLOODING);
      else if (strncmp (argv[arg_base + 0], "i", 1) == 0)
	TERM_DEBUG_ON (lsa, LSA_INSTALL);
      else if (strncmp (argv[arg_base + 0], "r", 1) == 0)
	TERM_DEBUG_ON (lsa, LSA_REFRESH);
    }

  return CMD_SUCCESS;
}

DEFUN (debug_ospf_lsa,
       debug_ospf_lsa_cmd,
       "debug ospf lsa",
       DEBUG_STR
       OSPF_STR
       "OSPF Link State Advertisement\n")
{
  return debug_ospf_lsa_common(vty, 0, argc, argv);
}

ALIAS (debug_ospf_lsa,
       debug_ospf_lsa_sub_cmd,
       "debug ospf lsa (generate|flooding|install|refresh)",
       DEBUG_STR
       OSPF_STR
       "OSPF Link State Advertisement\n"
       "LSA Generation\n"
       "LSA Flooding\n"
       "LSA Install/Delete\n"
       "LSA Refresh\n")

DEFUN (debug_ospf_instance_lsa,
       debug_ospf_instance_lsa_cmd,
       "debug ospf <1-65535> lsa",
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF Link State Advertisement\n")
{
  u_short instance = 0;

  VTY_GET_INTEGER ("Instance", instance, argv[0]);
  if (!ospf_lookup_instance (instance))
    return CMD_SUCCESS;

  return debug_ospf_lsa_common(vty, 1, argc, argv);
}

ALIAS (debug_ospf_instance_lsa,
       debug_ospf_instance_lsa_sub_cmd,
       "debug ospf <1-65535> lsa (generate|flooding|install|refresh)",
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF Link State Advertisement\n"
       "LSA Generation\n"
       "LSA Flooding\n"
       "LSA Install/Delete\n"
       "LSA Refresh\n")

static int
no_debug_ospf_lsa_common (struct vty *vty, int arg_base, int argc, const char **argv)
{
  if (vty->node == CONFIG_NODE)
    {
      if (argc == arg_base + 0)
	DEBUG_OFF (lsa, LSA);
      else if (argc == arg_base + 1)
	{
	  if (strncmp (argv[arg_base + 0], "g", 1) == 0)
	    DEBUG_OFF (lsa, LSA_GENERATE);
	  else if (strncmp (argv[arg_base + 0], "f", 1) == 0)
	    DEBUG_OFF (lsa, LSA_FLOODING);
	  else if (strncmp (argv[arg_base + 0], "i", 1) == 0)
	    DEBUG_OFF (lsa, LSA_INSTALL);
	  else if (strncmp (argv[arg_base + 0], "r", 1) == 0)
	    DEBUG_OFF (lsa, LSA_REFRESH);
	}

      return CMD_SUCCESS;
    }

  /* ENABLE_NODE. */
  if (argc == arg_base + 0)
    TERM_DEBUG_OFF (lsa, LSA);
  else if (argc == arg_base + 1)
    {
      if (strncmp (argv[arg_base + 0], "g", 1) == 0)
	TERM_DEBUG_OFF (lsa, LSA_GENERATE);
      else if (strncmp (argv[arg_base + 0], "f", 1) == 0)
	TERM_DEBUG_OFF (lsa, LSA_FLOODING);
      else if (strncmp (argv[arg_base + 0], "i", 1) == 0)
	TERM_DEBUG_OFF (lsa, LSA_INSTALL);
      else if (strncmp (argv[arg_base + 0], "r", 1) == 0)
	TERM_DEBUG_OFF (lsa, LSA_REFRESH);
    }

  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf_lsa,
       no_debug_ospf_lsa_cmd,
       "no debug ospf lsa",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF Link State Advertisement\n")
{
  return no_debug_ospf_lsa_common (vty, 0, argc, argv);
}

ALIAS (no_debug_ospf_lsa,
       no_debug_ospf_lsa_sub_cmd,
       "no debug ospf lsa (generate|flooding|install|refresh)",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF Link State Advertisement\n"
       "LSA Generation\n"
       "LSA Flooding\n"
       "LSA Install/Delete\n"
       "LSA Refres\n")

DEFUN (no_debug_ospf_instance_lsa,
       no_debug_ospf_instance_lsa_cmd,
       "no debug ospf <1-65535> lsa",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF Link State Advertisement\n")
{
  u_short instance = 0;

  VTY_GET_INTEGER ("Instance", instance, argv[0]);
  if (!ospf_lookup_instance (instance))
    return CMD_SUCCESS;

  return no_debug_ospf_lsa_common (vty, 1, argc, argv);
}

ALIAS (no_debug_ospf_instance_lsa,
       no_debug_ospf_instance_lsa_sub_cmd,
       "no debug ospf <1-65535> lsa (generate|flooding|install|refresh)",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF Link State Advertisement\n"
       "LSA Generation\n"
       "LSA Flooding\n"
       "LSA Install/Delete\n"
       "LSA Refres\n")


static int
debug_ospf_zebra_common (struct vty *vty, int arg_base, int argc, const char **argv)
{
  if (vty->node == CONFIG_NODE)
    {
      if (argc == arg_base + 0)
	DEBUG_ON (zebra, ZEBRA);
      else if (argc == arg_base + 1)
	{
	  if (strncmp (argv[arg_base + 0], "i", 1) == 0)
	    DEBUG_ON (zebra, ZEBRA_INTERFACE);
	  else if (strncmp (argv[arg_base + 0], "r", 1) == 0)
	    DEBUG_ON (zebra, ZEBRA_REDISTRIBUTE);
	}

      return CMD_SUCCESS;
    }

  /* ENABLE_NODE. */
  if (argc == arg_base + 0)
    TERM_DEBUG_ON (zebra, ZEBRA);
  else if (argc == arg_base + 1)
    {
      if (strncmp (argv[arg_base + 0], "i", 1) == 0)
	TERM_DEBUG_ON (zebra, ZEBRA_INTERFACE);
      else if (strncmp (argv[arg_base + 0], "r", 1) == 0)
	TERM_DEBUG_ON (zebra, ZEBRA_REDISTRIBUTE);
    }

  return CMD_SUCCESS;
}

DEFUN (debug_ospf_zebra,
       debug_ospf_zebra_cmd,
       "debug ospf zebra",
       DEBUG_STR
       OSPF_STR
       "OSPF Zebra information\n")
{
  return debug_ospf_zebra_common(vty, 0, argc, argv);
}

ALIAS (debug_ospf_zebra,
       debug_ospf_zebra_sub_cmd,
       "debug ospf zebra (interface|redistribute)",
       DEBUG_STR
       OSPF_STR
       "OSPF Zebra information\n"
       "Zebra interface\n"
       "Zebra redistribute\n")

DEFUN (debug_ospf_instance_zebra,
       debug_ospf_instance_zebra_cmd,
       "debug ospf <1-65535> zebra",
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF Zebra information\n")
{
  u_short instance = 0;

  VTY_GET_INTEGER ("Instance", instance, argv[0]);
  if (!ospf_lookup_instance (instance))
    return CMD_SUCCESS;

  return debug_ospf_zebra_common(vty, 1, argc, argv);
}

ALIAS (debug_ospf_instance_zebra,
       debug_ospf_instance_zebra_sub_cmd,
       "debug ospf <1-65535> zebra (interface|redistribute)",
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF Zebra information\n"
       "Zebra interface\n"
       "Zebra redistribute\n")

static int
no_debug_ospf_zebra_common(struct vty *vty, int arg_base, int argc,
                           const char **argv)
{
  if (vty->node == CONFIG_NODE)
    {
      if (argc == arg_base + 0)
	DEBUG_OFF (zebra, ZEBRA);
      else if (argc == arg_base + 1)
	{
	  if (strncmp (argv[arg_base + 0], "i", 1) == 0)
	    DEBUG_OFF (zebra, ZEBRA_INTERFACE);
	  else if (strncmp (argv[arg_base + 0], "r", 1) == 0)
	    DEBUG_OFF (zebra, ZEBRA_REDISTRIBUTE);
	}

      return CMD_SUCCESS;
    }

  /* ENABLE_NODE. */
  if (argc == arg_base + 0)
    TERM_DEBUG_OFF (zebra, ZEBRA);
  else if (argc == arg_base + 1)
    {
      if (strncmp (argv[arg_base + 0], "i", 1) == 0)
	TERM_DEBUG_OFF (zebra, ZEBRA_INTERFACE);
      else if (strncmp (argv[arg_base + 0], "r", 1) == 0)
	TERM_DEBUG_OFF (zebra, ZEBRA_REDISTRIBUTE);
    }

  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf_zebra,
       no_debug_ospf_zebra_cmd,
       "no debug ospf zebra",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF Zebra information\n")
{
  return no_debug_ospf_zebra_common(vty, 0, argc, argv);
}

ALIAS (no_debug_ospf_zebra,
       no_debug_ospf_zebra_sub_cmd,
       "no debug ospf zebra (interface|redistribute)",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF Zebra information\n"
       "Zebra interface\n"
       "Zebra redistribute\n")

DEFUN (no_debug_ospf_instance_zebra,
       no_debug_ospf_instance_zebra_cmd,
       "no debug ospf <1-65535> zebra",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF Zebra information\n")
{
  u_short instance = 0;

  VTY_GET_INTEGER ("Instance", instance, argv[0]);
  if (!ospf_lookup_instance (instance))
    return CMD_SUCCESS;

  return no_debug_ospf_zebra_common(vty, 1, argc, argv);
}

ALIAS (no_debug_ospf_instance_zebra,
       no_debug_ospf_instance_zebra_sub_cmd,
       "no debug ospf <1-65535> zebra (interface|redistribute)",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF Zebra information\n"
       "Zebra interface\n"
       "Zebra redistribute\n")


DEFUN (debug_ospf_event,
       debug_ospf_event_cmd,
       "debug ospf event",
       DEBUG_STR
       OSPF_STR
       "OSPF event information\n")
{
  if (vty->node == CONFIG_NODE)
    CONF_DEBUG_ON (event, EVENT);
  TERM_DEBUG_ON (event, EVENT);
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf_event,
       no_debug_ospf_event_cmd,
       "no debug ospf event",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF event information\n")
{
  if (vty->node == CONFIG_NODE)
    CONF_DEBUG_OFF (event, EVENT);
  TERM_DEBUG_OFF (event, EVENT);
  return CMD_SUCCESS;
}

DEFUN (debug_ospf_instance_event,
       debug_ospf_instance_event_cmd,
       "debug ospf <1-65535> event",
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF event information\n")
{
  u_short instance = 0;

  VTY_GET_INTEGER ("Instance", instance, argv[0]);
  if (!ospf_lookup_instance (instance))
    return CMD_SUCCESS;

  if (vty->node == CONFIG_NODE)
    CONF_DEBUG_ON (event, EVENT);
  TERM_DEBUG_ON (event, EVENT);
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf_instance_event,
       no_debug_ospf_instance_event_cmd,
       "no debug ospf <1-65535> event",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF event information\n")
{
  u_short instance = 0;

  VTY_GET_INTEGER ("Instance", instance, argv[0]);
  if (!ospf_lookup_instance (instance))
    return CMD_SUCCESS;

  if (vty->node == CONFIG_NODE)
    CONF_DEBUG_OFF (event, EVENT);
  TERM_DEBUG_OFF (event, EVENT);
  return CMD_SUCCESS;
}

DEFUN (debug_ospf_nssa,
       debug_ospf_nssa_cmd,
       "debug ospf nssa",
       DEBUG_STR
       OSPF_STR
       "OSPF nssa information\n")
{
  if (vty->node == CONFIG_NODE)
    CONF_DEBUG_ON (nssa, NSSA);
  TERM_DEBUG_ON (nssa, NSSA);
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf_nssa,
       no_debug_ospf_nssa_cmd,
       "no debug ospf nssa",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF nssa information\n")
{
  if (vty->node == CONFIG_NODE)
    CONF_DEBUG_OFF (nssa, NSSA);
  TERM_DEBUG_OFF (nssa, NSSA);
  return CMD_SUCCESS;
}

DEFUN (debug_ospf_instance_nssa,
       debug_ospf_instance_nssa_cmd,
       "debug ospf <1-65535> nssa",
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF nssa information\n")
{
  u_short instance = 0;

  VTY_GET_INTEGER ("Instance", instance, argv[0]);
  if (!ospf_lookup_instance (instance))
    return CMD_SUCCESS;

  if (vty->node == CONFIG_NODE)
    CONF_DEBUG_ON (nssa, NSSA);
  TERM_DEBUG_ON (nssa, NSSA);
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf_instance_nssa,
       no_debug_ospf_instance_nssa_cmd,
       "no debug ospf <1-65535> nssa",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n"
       "OSPF nssa information\n")
{
  u_short instance = 0;

  VTY_GET_INTEGER ("Instance", instance, argv[0]);
  if (!ospf_lookup_instance (instance))
    return CMD_SUCCESS;

  if (vty->node == CONFIG_NODE)
    CONF_DEBUG_OFF (nssa, NSSA);
  TERM_DEBUG_OFF (nssa, NSSA);
  return CMD_SUCCESS;
}

DEFUN (debug_ospf_te,
       debug_ospf_te_cmd,
       "debug ospf te",
       DEBUG_STR
       OSPF_STR
       "OSPF-TE information\n")
{
  if (vty->node == CONFIG_NODE)
    CONF_DEBUG_ON (te, TE);
  TERM_DEBUG_ON (te, TE);
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf_te,
       no_debug_ospf_te_cmd,
       "no debug ospf te",
       NO_STR
       DEBUG_STR
       OSPF_STR
       "OSPF-TE information\n")
{
  if (vty->node == CONFIG_NODE)
    CONF_DEBUG_OFF (te, TE);
  TERM_DEBUG_OFF (te, TE);
  return CMD_SUCCESS;
}

DEFUN (no_debug_ospf,
       no_debug_ospf_cmd,
       "no debug ospf",
       NO_STR
       DEBUG_STR
       OSPF_STR)
{
  int flag = OSPF_DEBUG_SEND | OSPF_DEBUG_RECV | OSPF_DEBUG_DETAIL;
  int i;

  if (vty->node == CONFIG_NODE)
    {
      CONF_DEBUG_OFF (event, EVENT);
      CONF_DEBUG_OFF (nssa, NSSA);
      DEBUG_OFF (ism, ISM_EVENTS);
      DEBUG_OFF (ism, ISM_STATUS);
      DEBUG_OFF (ism, ISM_TIMERS);
      DEBUG_OFF (lsa, LSA);
      DEBUG_OFF (lsa, LSA_FLOODING);
      DEBUG_OFF (lsa, LSA_GENERATE);
      DEBUG_OFF (lsa, LSA_INSTALL);
      DEBUG_OFF (lsa, LSA_REFRESH);
      DEBUG_OFF (nsm, NSM);
      DEBUG_OFF (nsm, NSM_EVENTS);
      DEBUG_OFF (nsm, NSM_STATUS);
      DEBUG_OFF (nsm, NSM_TIMERS);
      DEBUG_OFF (zebra, ZEBRA);
      DEBUG_OFF (zebra, ZEBRA_INTERFACE);
      DEBUG_OFF (zebra, ZEBRA_REDISTRIBUTE);

      for (i = 0; i < 5; i++)
        DEBUG_PACKET_OFF (i, flag);
    }

  for (i = 0; i < 5; i++)
    TERM_DEBUG_PACKET_OFF (i, flag);

  TERM_DEBUG_OFF (event, EVENT);
  TERM_DEBUG_OFF (ism, ISM);
  TERM_DEBUG_OFF (ism, ISM_EVENTS);
  TERM_DEBUG_OFF (ism, ISM_STATUS);
  TERM_DEBUG_OFF (ism, ISM_TIMERS);
  TERM_DEBUG_OFF (lsa, LSA);
  TERM_DEBUG_OFF (lsa, LSA_FLOODING);
  TERM_DEBUG_OFF (lsa, LSA_GENERATE);
  TERM_DEBUG_OFF (lsa, LSA_INSTALL);
  TERM_DEBUG_OFF (lsa, LSA_REFRESH);
  TERM_DEBUG_OFF (nsm, NSM);
  TERM_DEBUG_OFF (nsm, NSM_EVENTS);
  TERM_DEBUG_OFF (nsm, NSM_STATUS);
  TERM_DEBUG_OFF (nsm, NSM_TIMERS);
  TERM_DEBUG_OFF (nssa, NSSA);
  TERM_DEBUG_OFF (zebra, ZEBRA);
  TERM_DEBUG_OFF (zebra, ZEBRA_INTERFACE);
  TERM_DEBUG_OFF (zebra, ZEBRA_REDISTRIBUTE);

  return CMD_SUCCESS;
}

static int
show_debugging_ospf_common (struct vty *vty, struct ospf *ospf)
{
  int i;

  if (ospf->instance)
    vty_out (vty, "%sOSPF Instance: %d%s%s", VTY_NEWLINE, ospf->instance,
             VTY_NEWLINE, VTY_NEWLINE);

  vty_out (vty, "OSPF debugging status:%s", VTY_NEWLINE);

  /* Show debug status for events. */
  if (IS_DEBUG_OSPF(event,EVENT))
    vty_out (vty, "  OSPF event debugging is on%s", VTY_NEWLINE);

  /* Show debug status for ISM. */
  if (IS_DEBUG_OSPF (ism, ISM) == OSPF_DEBUG_ISM)
    vty_out (vty, "  OSPF ISM debugging is on%s", VTY_NEWLINE);
  else
    {
      if (IS_DEBUG_OSPF (ism, ISM_STATUS))
	vty_out (vty, "  OSPF ISM status debugging is on%s", VTY_NEWLINE);
      if (IS_DEBUG_OSPF (ism, ISM_EVENTS))
	vty_out (vty, "  OSPF ISM event debugging is on%s", VTY_NEWLINE);
      if (IS_DEBUG_OSPF (ism, ISM_TIMERS))
	vty_out (vty, "  OSPF ISM timer debugging is on%s", VTY_NEWLINE);
    }

  /* Show debug status for NSM. */
  if (IS_DEBUG_OSPF (nsm, NSM) == OSPF_DEBUG_NSM)
    vty_out (vty, "  OSPF NSM debugging is on%s", VTY_NEWLINE);
  else
    {
      if (IS_DEBUG_OSPF (nsm, NSM_STATUS))
	vty_out (vty, "  OSPF NSM status debugging is on%s", VTY_NEWLINE);
      if (IS_DEBUG_OSPF (nsm, NSM_EVENTS))
	vty_out (vty, "  OSPF NSM event debugging is on%s", VTY_NEWLINE);
      if (IS_DEBUG_OSPF (nsm, NSM_TIMERS))
	vty_out (vty, "  OSPF NSM timer debugging is on%s", VTY_NEWLINE);
    }

  /* Show debug status for OSPF Packets. */
  for (i = 0; i < 5; i++)
    if (IS_DEBUG_OSPF_PACKET (i, SEND) && IS_DEBUG_OSPF_PACKET (i, RECV))
      {
	vty_out (vty, "  OSPF packet %s%s debugging is on%s",
		 LOOKUP (ospf_packet_type_str, i + 1),
		 IS_DEBUG_OSPF_PACKET (i, DETAIL) ? " detail" : "",
		 VTY_NEWLINE);
      }
    else
      {
	if (IS_DEBUG_OSPF_PACKET (i, SEND))
	  vty_out (vty, "  OSPF packet %s send%s debugging is on%s",
		   LOOKUP (ospf_packet_type_str, i + 1),
		   IS_DEBUG_OSPF_PACKET (i, DETAIL) ? " detail" : "",
		   VTY_NEWLINE);
	if (IS_DEBUG_OSPF_PACKET (i, RECV))
	  vty_out (vty, "  OSPF packet %s receive%s debugging is on%s",
		   LOOKUP (ospf_packet_type_str, i + 1),
		   IS_DEBUG_OSPF_PACKET (i, DETAIL) ? " detail" : "",
		   VTY_NEWLINE);
      }

  /* Show debug status for OSPF LSAs. */
  if (IS_DEBUG_OSPF (lsa, LSA) == OSPF_DEBUG_LSA)
    vty_out (vty, "  OSPF LSA debugging is on%s", VTY_NEWLINE);
  else
    {
      if (IS_DEBUG_OSPF (lsa, LSA_GENERATE))
	vty_out (vty, "  OSPF LSA generation debugging is on%s", VTY_NEWLINE);
      if (IS_DEBUG_OSPF (lsa, LSA_FLOODING))
	vty_out (vty, "  OSPF LSA flooding debugging is on%s", VTY_NEWLINE);
      if (IS_DEBUG_OSPF (lsa, LSA_INSTALL))
	vty_out (vty, "  OSPF LSA install debugging is on%s", VTY_NEWLINE);
      if (IS_DEBUG_OSPF (lsa, LSA_REFRESH))
	vty_out (vty, "  OSPF LSA refresh debugging is on%s", VTY_NEWLINE);
    }

  /* Show debug status for Zebra. */
  if (IS_DEBUG_OSPF (zebra, ZEBRA) == OSPF_DEBUG_ZEBRA)
    vty_out (vty, "  OSPF Zebra debugging is on%s", VTY_NEWLINE);
  else
    {
      if (IS_DEBUG_OSPF (zebra, ZEBRA_INTERFACE))
	vty_out (vty, "  OSPF Zebra interface debugging is on%s", VTY_NEWLINE);
      if (IS_DEBUG_OSPF (zebra, ZEBRA_REDISTRIBUTE))
	vty_out (vty, "  OSPF Zebra redistribute debugging is on%s", VTY_NEWLINE);
    }

  /* Show debug status for NSSA. */
  if (IS_DEBUG_OSPF (nssa, NSSA) == OSPF_DEBUG_NSSA)
    vty_out (vty, "  OSPF NSSA debugging is on%s", VTY_NEWLINE);

  vty_out (vty, "%s", VTY_NEWLINE);

  return CMD_SUCCESS;
}

DEFUN (show_debugging_ospf,
       show_debugging_ospf_cmd,
       "show debugging ospf",
       SHOW_STR
       DEBUG_STR
       OSPF_STR)
{
  struct ospf *ospf;

  if ((ospf = ospf_lookup()) == NULL)
    return CMD_SUCCESS;

  return show_debugging_ospf_common(vty, ospf);
}

DEFUN (show_debugging_ospf_instance,
       show_debugging_ospf_instance_cmd,
       "show debugging ospf <1-65535>",
       SHOW_STR
       DEBUG_STR
       OSPF_STR
       "Instance ID\n")
{
  struct ospf *ospf;
  u_short instance = 0;

  VTY_GET_INTEGER ("Instance", instance, argv[0]);
  if ((ospf = ospf_lookup_instance (instance)) == NULL )
    return CMD_SUCCESS;

  return show_debugging_ospf_common(vty, ospf);
}

/* Debug node. */
static struct cmd_node debug_node =
{
  DEBUG_NODE,
  "",
  1 /* VTYSH */
};

static int
config_write_debug (struct vty *vty)
{
  int write = 0;
  int i, r;

  const char *type_str[] = {"hello", "dd", "ls-request", "ls-update", "ls-ack"};
  const char *detail_str[] = {"", " send", " recv", "", " detail",
			" send detail", " recv detail", " detail"};

  struct ospf *ospf;
  char str[16];
  memset (str, 0, 16);

  if ((ospf = ospf_lookup()) == NULL)
    return CMD_SUCCESS;

  if (ospf->instance)
    sprintf(str, " %d", ospf->instance);

  /* debug ospf ism (status|events|timers). */
  if (IS_CONF_DEBUG_OSPF (ism, ISM) == OSPF_DEBUG_ISM)
    vty_out (vty, "debug ospf%s ism%s", str, VTY_NEWLINE);
  else
    {
      if (IS_CONF_DEBUG_OSPF (ism, ISM_STATUS))
	vty_out (vty, "debug ospf%s ism status%s", str, VTY_NEWLINE);
      if (IS_CONF_DEBUG_OSPF (ism, ISM_EVENTS))
	vty_out (vty, "debug ospf%s ism event%s", str, VTY_NEWLINE);
      if (IS_CONF_DEBUG_OSPF (ism, ISM_TIMERS))
	vty_out (vty, "debug ospf%s ism timer%s", str, VTY_NEWLINE);
    }

  /* debug ospf nsm (status|events|timers). */
  if (IS_CONF_DEBUG_OSPF (nsm, NSM) == OSPF_DEBUG_NSM)
    vty_out (vty, "debug ospf%s nsm%s", str, VTY_NEWLINE);
  else
    {
      if (IS_CONF_DEBUG_OSPF (nsm, NSM_STATUS))
	vty_out (vty, "debug ospf%s nsm status%s", str, VTY_NEWLINE);
      if (IS_CONF_DEBUG_OSPF (nsm, NSM_EVENTS))
	vty_out (vty, "debug ospf%s nsm event%s", str, VTY_NEWLINE);
      if (IS_CONF_DEBUG_OSPF (nsm, NSM_TIMERS))
	vty_out (vty, "debug ospf%s nsm timer%s", str, VTY_NEWLINE);
    }

  /* debug ospf lsa (generate|flooding|install|refresh). */
  if (IS_CONF_DEBUG_OSPF (lsa, LSA) == OSPF_DEBUG_LSA)
    vty_out (vty, "debug ospf%s lsa%s", str, VTY_NEWLINE);
  else
    {
      if (IS_CONF_DEBUG_OSPF (lsa, LSA_GENERATE))
	vty_out (vty, "debug ospf%s lsa generate%s", str, VTY_NEWLINE);
      if (IS_CONF_DEBUG_OSPF (lsa, LSA_FLOODING))
	vty_out (vty, "debug ospf%s lsa flooding%s", str, VTY_NEWLINE);
      if (IS_CONF_DEBUG_OSPF (lsa, LSA_INSTALL))
	vty_out (vty, "debug ospf%s lsa install%s", str, VTY_NEWLINE);
      if (IS_CONF_DEBUG_OSPF (lsa, LSA_REFRESH))
	vty_out (vty, "debug ospf%s lsa refresh%s", str, VTY_NEWLINE);

      write = 1;
    }

  /* debug ospf zebra (interface|redistribute). */
  if (IS_CONF_DEBUG_OSPF (zebra, ZEBRA) == OSPF_DEBUG_ZEBRA)
    vty_out (vty, "debug ospf%s zebra%s", str, VTY_NEWLINE);
  else
    {
      if (IS_CONF_DEBUG_OSPF (zebra, ZEBRA_INTERFACE))
	vty_out (vty, "debug ospf%s zebra interface%s", str, VTY_NEWLINE);
      if (IS_CONF_DEBUG_OSPF (zebra, ZEBRA_REDISTRIBUTE))
	vty_out (vty, "debug ospf%s zebra redistribute%s", str, VTY_NEWLINE);

      write = 1;
    }

  /* debug ospf event. */
  if (IS_CONF_DEBUG_OSPF (event, EVENT) == OSPF_DEBUG_EVENT)
    {
      vty_out (vty, "debug ospf%s event%s", str, VTY_NEWLINE);
      write = 1;
    }

  /* debug ospf nssa. */
  if (IS_CONF_DEBUG_OSPF (nssa, NSSA) == OSPF_DEBUG_NSSA)
    {
      vty_out (vty, "debug ospf%s nssa%s", str, VTY_NEWLINE);
      write = 1;
    }
  
  /* debug ospf packet all detail. */
  r = OSPF_DEBUG_SEND_RECV|OSPF_DEBUG_DETAIL;
  for (i = 0; i < 5; i++)
    r &= conf_debug_ospf_packet[i] & (OSPF_DEBUG_SEND_RECV|OSPF_DEBUG_DETAIL);
  if (r == (OSPF_DEBUG_SEND_RECV|OSPF_DEBUG_DETAIL))
    {
      vty_out (vty, "debug ospf%s packet all detail%s", str, VTY_NEWLINE);
      return 1;
    }

  /* debug ospf packet all. */
  r = OSPF_DEBUG_SEND_RECV;
  for (i = 0; i < 5; i++)
    r &= conf_debug_ospf_packet[i] & OSPF_DEBUG_SEND_RECV;
  if (r == OSPF_DEBUG_SEND_RECV)
    {
      vty_out (vty, "debug ospf%s packet all%s", str, VTY_NEWLINE);
      for (i = 0; i < 5; i++)
	if (conf_debug_ospf_packet[i] & OSPF_DEBUG_DETAIL)
	  vty_out (vty, "debug ospf%s packet %s detail%s", str,
		   type_str[i],
		   VTY_NEWLINE);
      return 1;
    }

  /* debug ospf packet (hello|dd|ls-request|ls-update|ls-ack)
     (send|recv) (detail). */
  for (i = 0; i < 5; i++)
    {
      if (conf_debug_ospf_packet[i] == 0)
	continue;
      
      vty_out (vty, "debug ospf%s packet %s%s%s", str,
	       type_str[i], detail_str[conf_debug_ospf_packet[i]],
	       VTY_NEWLINE);
      write = 1;
    }

  return write;
}

/* Initialize debug commands. */
void
debug_init ()
{
  install_node (&debug_node, config_write_debug);

  install_element (ENABLE_NODE, &show_debugging_ospf_cmd);
  install_element (ENABLE_NODE, &debug_ospf_packet_send_recv_detail_cmd);
  install_element (ENABLE_NODE, &debug_ospf_packet_send_recv_cmd);
  install_element (ENABLE_NODE, &debug_ospf_packet_all_cmd);
  install_element (ENABLE_NODE, &debug_ospf_ism_sub_cmd);
  install_element (ENABLE_NODE, &debug_ospf_ism_cmd);
  install_element (ENABLE_NODE, &debug_ospf_nsm_sub_cmd);
  install_element (ENABLE_NODE, &debug_ospf_nsm_cmd);
  install_element (ENABLE_NODE, &debug_ospf_lsa_sub_cmd);
  install_element (ENABLE_NODE, &debug_ospf_lsa_cmd);
  install_element (ENABLE_NODE, &debug_ospf_zebra_sub_cmd);
  install_element (ENABLE_NODE, &debug_ospf_zebra_cmd);
  install_element (ENABLE_NODE, &debug_ospf_event_cmd);
  install_element (ENABLE_NODE, &debug_ospf_nssa_cmd);
  install_element (ENABLE_NODE, &debug_ospf_te_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_packet_send_recv_detail_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_packet_send_recv_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_packet_all_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_ism_sub_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_ism_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_nsm_sub_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_nsm_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_lsa_sub_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_lsa_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_zebra_sub_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_zebra_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_event_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_nssa_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_te_cmd);

  install_element (ENABLE_NODE, &show_debugging_ospf_instance_cmd);
  install_element (ENABLE_NODE, &debug_ospf_instance_packet_send_recv_detail_cmd);
  install_element (ENABLE_NODE, &debug_ospf_instance_packet_send_recv_cmd);
  install_element (ENABLE_NODE, &debug_ospf_instance_packet_all_cmd);
  install_element (ENABLE_NODE, &debug_ospf_instance_ism_sub_cmd);
  install_element (ENABLE_NODE, &debug_ospf_instance_ism_cmd);
  install_element (ENABLE_NODE, &debug_ospf_instance_nsm_sub_cmd);
  install_element (ENABLE_NODE, &debug_ospf_instance_nsm_cmd);
  install_element (ENABLE_NODE, &debug_ospf_instance_lsa_sub_cmd);
  install_element (ENABLE_NODE, &debug_ospf_instance_lsa_cmd);
  install_element (ENABLE_NODE, &debug_ospf_instance_zebra_sub_cmd);
  install_element (ENABLE_NODE, &debug_ospf_instance_zebra_cmd);
  install_element (ENABLE_NODE, &debug_ospf_instance_event_cmd);
  install_element (ENABLE_NODE, &debug_ospf_instance_nssa_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_instance_packet_send_recv_detail_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_instance_packet_send_recv_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_instance_packet_all_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_instance_ism_sub_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_instance_ism_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_instance_nsm_sub_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_instance_nsm_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_instance_lsa_sub_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_instance_lsa_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_instance_zebra_sub_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_instance_zebra_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_instance_event_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_instance_nssa_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf_cmd);

  install_element (CONFIG_NODE, &debug_ospf_packet_send_recv_detail_cmd);
  install_element (CONFIG_NODE, &debug_ospf_packet_send_recv_cmd);
  install_element (CONFIG_NODE, &debug_ospf_packet_all_cmd);
  install_element (CONFIG_NODE, &debug_ospf_ism_sub_cmd);
  install_element (CONFIG_NODE, &debug_ospf_ism_cmd);
  install_element (CONFIG_NODE, &debug_ospf_nsm_sub_cmd);
  install_element (CONFIG_NODE, &debug_ospf_nsm_cmd);
  install_element (CONFIG_NODE, &debug_ospf_lsa_sub_cmd);
  install_element (CONFIG_NODE, &debug_ospf_lsa_cmd);
  install_element (CONFIG_NODE, &debug_ospf_zebra_sub_cmd);
  install_element (CONFIG_NODE, &debug_ospf_zebra_cmd);
  install_element (CONFIG_NODE, &debug_ospf_event_cmd);
  install_element (CONFIG_NODE, &debug_ospf_nssa_cmd);
  install_element (CONFIG_NODE, &debug_ospf_te_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_packet_send_recv_detail_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_packet_send_recv_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_packet_all_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_ism_sub_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_ism_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_nsm_sub_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_nsm_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_lsa_sub_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_lsa_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_zebra_sub_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_zebra_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_event_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_nssa_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_te_cmd);

  install_element (CONFIG_NODE, &debug_ospf_instance_packet_send_recv_detail_cmd);
  install_element (CONFIG_NODE, &debug_ospf_instance_packet_send_recv_cmd);
  install_element (CONFIG_NODE, &debug_ospf_instance_packet_all_cmd);
  install_element (CONFIG_NODE, &debug_ospf_instance_ism_sub_cmd);
  install_element (CONFIG_NODE, &debug_ospf_instance_ism_cmd);
  install_element (CONFIG_NODE, &debug_ospf_instance_nsm_sub_cmd);
  install_element (CONFIG_NODE, &debug_ospf_instance_nsm_cmd);
  install_element (CONFIG_NODE, &debug_ospf_instance_lsa_sub_cmd);
  install_element (CONFIG_NODE, &debug_ospf_instance_lsa_cmd);
  install_element (CONFIG_NODE, &debug_ospf_instance_zebra_sub_cmd);
  install_element (CONFIG_NODE, &debug_ospf_instance_zebra_cmd);
  install_element (CONFIG_NODE, &debug_ospf_instance_event_cmd);
  install_element (CONFIG_NODE, &debug_ospf_instance_nssa_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_instance_packet_send_recv_detail_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_instance_packet_send_recv_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_instance_packet_all_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_instance_ism_sub_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_instance_ism_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_instance_nsm_sub_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_instance_nsm_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_instance_lsa_sub_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_instance_lsa_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_instance_zebra_sub_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_instance_zebra_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_instance_event_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_instance_nssa_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf_cmd);
}
