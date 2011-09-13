/*
 * IS-IS Rout(e)ing protocol - isis_pdu.c   
 *                             PDU processing
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology      
 *                           Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public Licenseas published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.

 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <zebra.h>

#include "memory.h"
#include "thread.h"
#include "linklist.h"
#include "log.h"
#include "stream.h"
#include "vty.h"
#include "hash.h"
#include "prefix.h"
#include "if.h"
#include "checksum.h"

#include "isisd/dict.h"
#include "isisd/include-netbsd/iso.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_network.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_dr.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_tlv.h"
#include "isisd/isisd.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_pdu.h"
#include "isisd/iso_checksum.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_events.h"

extern struct thread_master *master;
extern struct isis *isis;

#define ISIS_MINIMUM_FIXED_HDR_LEN 15
#define ISIS_MIN_PDU_LEN           13	/* partial seqnum pdu with id_len=2 */

#ifndef PNBBY
#define PNBBY 8
#endif /* PNBBY */

/* Utility mask array. */
static const u_char maskbit[] = {
  0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff
};

/*
 * HELPER FUNCS
 */

/*
 * Compares two sets of area addresses
 */
static int
area_match (struct list *left, struct list *right)
{
  struct area_addr *addr1, *addr2;
  struct listnode *node1, *node2;

  for (ALL_LIST_ELEMENTS_RO (left, node1, addr1))
  {
    for (ALL_LIST_ELEMENTS_RO (right, node2, addr2))
    {
      if (addr1->addr_len == addr2->addr_len &&
	  !memcmp (addr1->area_addr, addr2->area_addr, (int) addr1->addr_len))
	return 1;		/* match */
    }
  }

  return 0;			/* mismatch */
}

/*
 * Check if ip2 is in the ip1's network (function like Prefix.h:prefix_match() )
 * param ip1            the IS interface ip address structure
 * param ip2            the IIH's ip address
 * return  0            the IIH's IP is not in the IS's subnetwork
 *         1            the IIH's IP is in the IS's subnetwork
 */
static int
ip_same_subnet (struct prefix_ipv4 *ip1, struct in_addr *ip2)
{
  u_char *addr1, *addr2;
  int shift, offset, offsetloop;
  int len;

  addr1 = (u_char *) & ip1->prefix.s_addr;
  addr2 = (u_char *) & ip2->s_addr;
  len = ip1->prefixlen;

  shift = len % PNBBY;
  offsetloop = offset = len / PNBBY;

  while (offsetloop--)
    if (addr1[offsetloop] != addr2[offsetloop])
      return 0;

  if (shift)
    if (maskbit[shift] & (addr1[offset] ^ addr2[offset]))
      return 0;

  return 1;			/* match  */
}

/*
 * Compares two set of ip addresses
 * param left     the local interface's ip addresses
 * param right    the iih interface's ip address
 * return         0   no match;
 *                1   match;
 */
static int
ip_match (struct list *left, struct list *right)
{
  struct prefix_ipv4 *ip1;
  struct in_addr *ip2;
  struct listnode *node1, *node2;

  if ((left == NULL) || (right == NULL))
    return 0;
  
  for (ALL_LIST_ELEMENTS_RO (left, node1, ip1))
  {
    for (ALL_LIST_ELEMENTS_RO (right, node2, ip2))
    {
      if (ip_same_subnet (ip1, ip2))
	{
	  return 1;		/* match */
	}
    }

  }
  return 0;
}

/*
 * Checks whether we should accept a PDU of given level 
 */
static int
accept_level (int level, int circuit_t)
{
  int retval = ((circuit_t & level) == level);	/* simple approach */

  return retval;
}

int
authentication_check (struct isis_passwd *one, struct isis_passwd *theother)
{
  if (one->type != theother->type)
    {
      zlog_warn ("Unsupported authentication type %d", theother->type);
      return 1;			/* Auth fail (different authentication types) */
    }
  switch (one->type)
    {
    case ISIS_PASSWD_TYPE_CLEARTXT:
      if (one->len != theother->len)
	return 1;		/* Auth fail () - passwd len mismatch */
      return memcmp (one->passwd, theother->passwd, one->len);
      break;
    default:
      zlog_warn ("Unsupported authentication type");
      break;
    }
  return 0;			/* Auth pass */
}

/*
 * Processing helper functions
 */
static void
tlvs_to_adj_nlpids (struct tlvs *tlvs, struct isis_adjacency *adj)
{
  int i;
  struct nlpids *tlv_nlpids;

  if (tlvs->nlpids)
    {

      tlv_nlpids = tlvs->nlpids;

      adj->nlpids.count = tlv_nlpids->count;

      for (i = 0; i < tlv_nlpids->count; i++)
	{
	  adj->nlpids.nlpids[i] = tlv_nlpids->nlpids[i];
	}
    }
}

static void
del_ip_addr (void *val)
{
  XFREE (MTYPE_ISIS_TMP, val);
}

static void
tlvs_to_adj_ipv4_addrs (struct tlvs *tlvs, struct isis_adjacency *adj)
{
  struct listnode *node;
  struct in_addr *ipv4_addr, *malloced;

  if (adj->ipv4_addrs)
    {
      adj->ipv4_addrs->del = del_ip_addr;
      list_delete (adj->ipv4_addrs);
    }
  adj->ipv4_addrs = list_new ();
  if (tlvs->ipv4_addrs)
    {
      for (ALL_LIST_ELEMENTS_RO (tlvs->ipv4_addrs, node, ipv4_addr))
      {
	malloced = XMALLOC (MTYPE_ISIS_TMP, sizeof (struct in_addr));
	memcpy (malloced, ipv4_addr, sizeof (struct in_addr));
	listnode_add (adj->ipv4_addrs, malloced);
      }
    }
}

#ifdef HAVE_IPV6
static void
tlvs_to_adj_ipv6_addrs (struct tlvs *tlvs, struct isis_adjacency *adj)
{
  struct listnode *node;
  struct in6_addr *ipv6_addr, *malloced;

  if (adj->ipv6_addrs)
    {
      adj->ipv6_addrs->del = del_ip_addr;
      list_delete (adj->ipv6_addrs);
    }
  adj->ipv6_addrs = list_new ();
  if (tlvs->ipv6_addrs)
    {
      for (ALL_LIST_ELEMENTS_RO (tlvs->ipv6_addrs, node, ipv6_addr))
      {
	malloced = XMALLOC (MTYPE_ISIS_TMP, sizeof (struct in6_addr));
	memcpy (malloced, ipv6_addr, sizeof (struct in6_addr));
	listnode_add (adj->ipv6_addrs, malloced);
      }
    }

}
#endif /* HAVE_IPV6 */

/*
 *  RECEIVE SIDE                           
 */

/*
 * Process P2P IIH
 * ISO - 10589
 * Section 8.2.5 - Receiving point-to-point IIH PDUs
 *
 */
static int
process_p2p_hello (struct isis_circuit *circuit)
{
  int retval = ISIS_OK;
  struct isis_p2p_hello_hdr *hdr;
  struct isis_adjacency *adj;
  u_int32_t expected = 0, found;
  struct tlvs tlvs;

  if ((stream_get_endp (circuit->rcv_stream) -
       stream_get_getp (circuit->rcv_stream)) < ISIS_P2PHELLO_HDRLEN)
    {
      zlog_warn ("Packet too short");
      return ISIS_WARNING;
    }

  /* 8.2.5.1 PDU acceptance tests */

  /* 8.2.5.1 a) external domain untrue */
  /* FIXME: not useful at all?         */

  /* 8.2.5.1 b) ID Length mismatch */
  /* checked at the handle_pdu     */

  /* 8.2.5.2 IIH PDU Processing */

  /* 8.2.5.2 a) 1) Maximum Area Addresses */
  /* Already checked, and can also be ommited */

  /*
   * Get the header
   */
  hdr = (struct isis_p2p_hello_hdr *) STREAM_PNT (circuit->rcv_stream);
  circuit->rcv_stream->getp += ISIS_P2PHELLO_HDRLEN;

  /*  hdr.circuit_t = stream_getc (stream);
     stream_get (hdr.source_id, stream, ISIS_SYS_ID_LEN);
     hdr.hold_time = stream_getw (stream);
     hdr.pdu_len   = stream_getw (stream);
     hdr.local_id  = stream_getc (stream); */

  /*
   * My interpertation of the ISO, if no adj exists we will create one for 
   * the circuit
   */

  if (isis->debugs & DEBUG_ADJ_PACKETS)
    {
      zlog_debug ("ISIS-Adj (%s): Rcvd P2P IIH from (%s), cir type %s,"
		  " cir id %02d, length %d",
		  circuit->area->area_tag, circuit->interface->name,
		  circuit_t2string (circuit->circuit_is_type),
		  circuit->circuit_id, ntohs (hdr->pdu_len));
    }

  adj = circuit->u.p2p.neighbor;
  if (!adj)
    {
      adj = isis_new_adj (hdr->source_id, NULL, 0, circuit);
      if (adj == NULL)
	return ISIS_ERROR;
      circuit->u.p2p.neighbor = adj;
      isis_adj_state_change (adj, ISIS_ADJ_INITIALIZING, NULL);
      adj->sys_type = ISIS_SYSTYPE_UNKNOWN;
    }

  /* 8.2.6 Monitoring point-to-point adjacencies */
  adj->hold_time = ntohs (hdr->hold_time);
  adj->last_upd = time (NULL);

  /*
   * Lets get the TLVS now
   */
  expected |= TLVFLAG_AREA_ADDRS;
  expected |= TLVFLAG_AUTH_INFO;
  expected |= TLVFLAG_NLPID;
  expected |= TLVFLAG_IPV4_ADDR;
  expected |= TLVFLAG_IPV6_ADDR;

  retval = parse_tlvs (circuit->area->area_tag,
		       STREAM_PNT (circuit->rcv_stream),
		       ntohs (hdr->pdu_len) - ISIS_P2PHELLO_HDRLEN
		       - ISIS_FIXED_HDR_LEN, &expected, &found, &tlvs);

  if (retval > ISIS_WARNING)
    {
      free_tlvs (&tlvs);
      return retval;
    };

  /* 8.2.5.1 c) Authentication */
  if (circuit->passwd.type)
    {
      if (!(found & TLVFLAG_AUTH_INFO) ||
	  authentication_check (&circuit->passwd, &tlvs.auth_info))
	{
	  isis_event_auth_failure (circuit->area->area_tag,
				   "P2P hello authentication failure",
				   hdr->source_id);
	  return ISIS_OK;
	}
    }

  /* we do this now because the adj may not survive till the end... */

  /* we need to copy addresses to the adj */
  tlvs_to_adj_ipv4_addrs (&tlvs, adj);

#ifdef HAVE_IPV6
  tlvs_to_adj_ipv6_addrs (&tlvs, adj);
#endif /* HAVE_IPV6 */

  /* lets take care of the expiry */
  THREAD_TIMER_OFF (adj->t_expire);
  THREAD_TIMER_ON (master, adj->t_expire, isis_adj_expire, adj,
		   (long) adj->hold_time);

  /* 8.2.5.2 a) a match was detected */
  if (area_match (circuit->area->area_addrs, tlvs.area_addrs))
    {
      /* 8.2.5.2 a) 2) If the system is L1 - table 5 */
      if (circuit->area->is_type == IS_LEVEL_1)
	{
	  switch (hdr->circuit_t)
	    {
	    case IS_LEVEL_1:
	    case IS_LEVEL_1_AND_2:
	      if (adj->adj_state != ISIS_ADJ_UP)
		{
		  /* (4) adj state up */
		  isis_adj_state_change (adj, ISIS_ADJ_UP, NULL);
		  /* (5) adj usage level 1 */
		  adj->adj_usage = ISIS_ADJ_LEVEL1;
		}
	      else if (adj->adj_usage == ISIS_ADJ_LEVEL1)
		{
		  ;		/* accept */
		}
	      break;
	    case IS_LEVEL_2:
	      if (adj->adj_state != ISIS_ADJ_UP)
		{
		  /* (7) reject - wrong system type event */
		  zlog_warn ("wrongSystemType");
		  return ISIS_WARNING;	/* Reject */
		}
	      else if (adj->adj_usage == ISIS_ADJ_LEVEL1)
		{
		  /* (6) down - wrong system */
		  isis_adj_state_change (adj, ISIS_ADJ_DOWN, "Wrong System");
		}
	      break;
	    }
	}

      /* 8.2.5.2 a) 3) If the system is L1L2 - table 6 */
      if (circuit->area->is_type == IS_LEVEL_1_AND_2)
	{
	  switch (hdr->circuit_t)
	    {
	    case IS_LEVEL_1:
	      if (adj->adj_state != ISIS_ADJ_UP)
		{
		  /* (6) adj state up */
		  isis_adj_state_change (adj, ISIS_ADJ_UP, NULL);
		  /* (7) adj usage level 1 */
		  adj->adj_usage = ISIS_ADJ_LEVEL1;
		}
	      else if (adj->adj_usage == ISIS_ADJ_LEVEL1)
		{
		  ;		/* accept */
		}
	      else if ((adj->adj_usage == ISIS_ADJ_LEVEL1AND2) ||
		       (adj->adj_usage == ISIS_ADJ_LEVEL2))
		{
		  /* (8) down - wrong system */
		  isis_adj_state_change (adj, ISIS_ADJ_DOWN, "Wrong System");
		}
	      break;
	    case IS_LEVEL_2:
	      if (adj->adj_state != ISIS_ADJ_UP)
		{
		  /* (6) adj state up */
		  isis_adj_state_change (adj, ISIS_ADJ_UP, NULL);
		  /* (9) adj usage level 2 */
		  adj->adj_usage = ISIS_ADJ_LEVEL2;
		}
	      else if ((adj->adj_usage == ISIS_ADJ_LEVEL1) ||
		       (adj->adj_usage == ISIS_ADJ_LEVEL1AND2))
		{
		  /* (8) down - wrong system */
		  isis_adj_state_change (adj, ISIS_ADJ_DOWN, "Wrong System");
		}
	      else if (adj->adj_usage == ISIS_ADJ_LEVEL2)
		{
		  ;		/* Accept */
		}
	      break;
	    case IS_LEVEL_1_AND_2:
	      if (adj->adj_state != ISIS_ADJ_UP)
		{
		  /* (6) adj state up */
		  isis_adj_state_change (adj, ISIS_ADJ_UP, NULL);
		  /* (10) adj usage level 1 */
		  adj->adj_usage = ISIS_ADJ_LEVEL1AND2;
		}
	      else if ((adj->adj_usage == ISIS_ADJ_LEVEL1) ||
		       (adj->adj_usage == ISIS_ADJ_LEVEL2))
		{
		  /* (8) down - wrong system */
		  isis_adj_state_change (adj, ISIS_ADJ_DOWN, "Wrong System");
		}
	      else if (adj->adj_usage == ISIS_ADJ_LEVEL1AND2)
		{
		  ;		/* Accept */
		}
	      break;
	    }
	}

      /* 8.2.5.2 a) 4) If the system is L2 - table 7 */
      if (circuit->area->is_type == IS_LEVEL_2)
	{
	  switch (hdr->circuit_t)
	    {
	    case IS_LEVEL_1:
	      if (adj->adj_state != ISIS_ADJ_UP)
		{
		  /* (5) reject - wrong system type event */
		  zlog_warn ("wrongSystemType");
		  return ISIS_WARNING;	/* Reject */
		}
	      else if ((adj->adj_usage == ISIS_ADJ_LEVEL1AND2) ||
		       (adj->adj_usage == ISIS_ADJ_LEVEL2))
		{
		  /* (6) down - wrong system */
		  isis_adj_state_change (adj, ISIS_ADJ_DOWN, "Wrong System");
		}
	      break;
	    case IS_LEVEL_1_AND_2:
	    case IS_LEVEL_2:
	      if (adj->adj_state != ISIS_ADJ_UP)
		{
		  /* (7) adj state up */
		  isis_adj_state_change (adj, ISIS_ADJ_UP, NULL);
		  /* (8) adj usage level 2 */
		  adj->adj_usage = ISIS_ADJ_LEVEL2;
		}
	      else if (adj->adj_usage == ISIS_ADJ_LEVEL1AND2)
		{
		  /* (6) down - wrong system */
		  isis_adj_state_change (adj, ISIS_ADJ_DOWN, "Wrong System");
		}
	      else if (adj->adj_usage == ISIS_ADJ_LEVEL2)
		{
		  ;		/* Accept */
		}
	      break;
	    }
	}
    }
  /* 8.2.5.2 b) if no match was detected */
  else
    {
      if (circuit->area->is_type == IS_LEVEL_1)
	{
	  /* 8.2.5.2 b) 1) is_type L1 and adj is not up */
	  if (adj->adj_state != ISIS_ADJ_UP)
	    {
	      isis_adj_state_change (adj, ISIS_ADJ_DOWN, "Area Mismatch");
	      /* 8.2.5.2 b) 2)is_type L1 and adj is up */
	    }
	  else
	    {
	      isis_adj_state_change (adj, ISIS_ADJ_DOWN,
				     "Down - Area Mismatch");
	    }
	}
      /* 8.2.5.2 b 3 If the system is L2 or L1L2 - table 8 */
      else
	{
	  switch (hdr->circuit_t)
	    {
	    case IS_LEVEL_1:
	      if (adj->adj_state != ISIS_ADJ_UP)
		{
		  /* (6) reject - Area Mismatch event */
		  zlog_warn ("AreaMismatch");
		  return ISIS_WARNING;	/* Reject */
		}
	      else if (adj->adj_usage == ISIS_ADJ_LEVEL1)
		{
		  /* (7) down - area mismatch */
		  isis_adj_state_change (adj, ISIS_ADJ_DOWN, "Area Mismatch");

		}
	      else if ((adj->adj_usage == ISIS_ADJ_LEVEL1AND2) ||
		       (adj->adj_usage == ISIS_ADJ_LEVEL2))
		{
		  /* (7) down - wrong system */
		  isis_adj_state_change (adj, ISIS_ADJ_DOWN, "Wrong System");
		}
	      break;
	    case IS_LEVEL_1_AND_2:
	    case IS_LEVEL_2:
	      if (adj->adj_state != ISIS_ADJ_UP)
		{
		  /* (8) adj state up */
		  isis_adj_state_change (adj, ISIS_ADJ_UP, NULL);
		  /* (9) adj usage level 2 */
		  adj->adj_usage = ISIS_ADJ_LEVEL2;
		}
	      else if (adj->adj_usage == ISIS_ADJ_LEVEL1)
		{
		  /* (7) down - wrong system */
		  isis_adj_state_change (adj, ISIS_ADJ_DOWN, "Wrong System");
		}
	      else if (adj->adj_usage == ISIS_ADJ_LEVEL1AND2)
		{
		  if (hdr->circuit_t == IS_LEVEL_2)
		    {
		      /* (7) down - wrong system */
		      isis_adj_state_change (adj, ISIS_ADJ_DOWN,
					     "Wrong System");
		    }
		  else
		    {
		      /* (7) down - area mismatch */
		      isis_adj_state_change (adj, ISIS_ADJ_DOWN,
					     "Area Mismatch");
		    }
		}
	      else if (adj->adj_usage == ISIS_ADJ_LEVEL2)
		{
		  ;		/* Accept */
		}
	      break;
	    }
	}
    }
  /* 8.2.5.2 c) if the action was up - comparing circuit IDs */
  /* FIXME - Missing parts */

  /* some of my own understanding of the ISO, why the heck does
   * it not say what should I change the system_type to...
   */
  switch (adj->adj_usage)
    {
    case ISIS_ADJ_LEVEL1:
      adj->sys_type = ISIS_SYSTYPE_L1_IS;
      break;
    case ISIS_ADJ_LEVEL2:
      adj->sys_type = ISIS_SYSTYPE_L2_IS;
      break;
    case ISIS_ADJ_LEVEL1AND2:
      adj->sys_type = ISIS_SYSTYPE_L2_IS;
      break;
    case ISIS_ADJ_NONE:
      adj->sys_type = ISIS_SYSTYPE_UNKNOWN;
      break;
    }

  adj->circuit_t = hdr->circuit_t;
  adj->level = hdr->circuit_t;

  free_tlvs (&tlvs);

  return retval;
}

/*
 * Process IS-IS LAN Level 1/2 Hello PDU
 */
static int
process_lan_hello (int level, struct isis_circuit *circuit, u_char * ssnpa)
{
  int retval = ISIS_OK;
  struct isis_lan_hello_hdr hdr;
  struct isis_adjacency *adj;
  u_int32_t expected = 0, found;
  struct tlvs tlvs;
  u_char *snpa;
  struct listnode *node;

  if ((stream_get_endp (circuit->rcv_stream) -
       stream_get_getp (circuit->rcv_stream)) < ISIS_LANHELLO_HDRLEN)
    {
      zlog_warn ("Packet too short");
      return ISIS_WARNING;
    }

  if (circuit->ext_domain)
    {
      zlog_debug ("level %d LAN Hello received over circuit with "
		  "externalDomain = true", level);
      return ISIS_WARNING;
    }

  if (!accept_level (level, circuit->circuit_is_type))
    {
      if (isis->debugs & DEBUG_ADJ_PACKETS)
	{
	  zlog_debug ("ISIS-Adj (%s): Interface level mismatch, %s",
		      circuit->area->area_tag, circuit->interface->name);
	}
      return ISIS_WARNING;
    }

#if 0
  /* Cisco's debug message compatability */
  if (!accept_level (level, circuit->area->is_type))
    {
      if (isis->debugs & DEBUG_ADJ_PACKETS)
	{
	  zlog_debug ("ISIS-Adj (%s): is type mismatch",
		      circuit->area->area_tag);
	}
      return ISIS_WARNING;
    }
#endif
  /*
   * Fill the header
   */
  hdr.circuit_t = stream_getc (circuit->rcv_stream);
  stream_get (hdr.source_id, circuit->rcv_stream, ISIS_SYS_ID_LEN);
  hdr.hold_time = stream_getw (circuit->rcv_stream);
  hdr.pdu_len = stream_getw (circuit->rcv_stream);
  hdr.prio = stream_getc (circuit->rcv_stream);
  stream_get (hdr.lan_id, circuit->rcv_stream, ISIS_SYS_ID_LEN + 1);

  if (hdr.circuit_t != IS_LEVEL_1 && hdr.circuit_t != IS_LEVEL_2 &&
      hdr.circuit_t != IS_LEVEL_1_AND_2)
    {
      zlog_warn ("Level %d LAN Hello with Circuit Type %d", level,
		 hdr.circuit_t);
      return ISIS_ERROR;
    }
  /*
   * Then get the tlvs
   */
  expected |= TLVFLAG_AUTH_INFO;
  expected |= TLVFLAG_AREA_ADDRS;
  expected |= TLVFLAG_LAN_NEIGHS;
  expected |= TLVFLAG_NLPID;
  expected |= TLVFLAG_IPV4_ADDR;
  expected |= TLVFLAG_IPV6_ADDR;

  retval = parse_tlvs (circuit->area->area_tag,
		       STREAM_PNT (circuit->rcv_stream),
		       hdr.pdu_len - ISIS_LANHELLO_HDRLEN -
		       ISIS_FIXED_HDR_LEN, &expected, &found, &tlvs);

  if (retval > ISIS_WARNING)
    {
      zlog_warn ("parse_tlvs() failed");
      goto out;
    }

  if (!(found & TLVFLAG_AREA_ADDRS))
    {
      zlog_warn ("No Area addresses TLV in Level %d LAN IS to IS hello",
		 level);
      retval = ISIS_WARNING;
      goto out;
    }

  if (circuit->passwd.type)
    {
      if (!(found & TLVFLAG_AUTH_INFO) ||
	  authentication_check (&circuit->passwd, &tlvs.auth_info))
	{
	  isis_event_auth_failure (circuit->area->area_tag,
				   "LAN hello authentication failure",
				   hdr.source_id);
	  retval = ISIS_WARNING;
	  goto out;
	}
    }

  /*
   * Accept the level 1 adjacency only if a match between local and
   * remote area addresses is found
   */
  if (level == 1 && !area_match (circuit->area->area_addrs, tlvs.area_addrs))
    {
      if (isis->debugs & DEBUG_ADJ_PACKETS)
	{
	  zlog_debug ("ISIS-Adj (%s): Area mismatch, level %d IIH on %s",
		      circuit->area->area_tag, level,
		      circuit->interface->name);
	}
      retval = ISIS_OK;
      goto out;
    }

  /* 
   * it's own IIH PDU - discard silently 
   */
  if (!memcmp (circuit->u.bc.snpa, ssnpa, ETH_ALEN))
    {
      zlog_debug ("ISIS-Adj (%s): it's own IIH PDU - discarded",
		  circuit->area->area_tag);

      retval = ISIS_OK;
      goto out;
    }

  /*
   * check if it's own interface ip match iih ip addrs
   */
  if (!(found & TLVFLAG_IPV4_ADDR)
      || !ip_match (circuit->ip_addrs, tlvs.ipv4_addrs))
    {
      zlog_debug
	("ISIS-Adj: No usable IP interface addresses in LAN IIH from %s\n",
	 circuit->interface->name);
      retval = ISIS_WARNING;
      goto out;
    }

  adj = isis_adj_lookup (hdr.source_id, circuit->u.bc.adjdb[level - 1]);
  if (!adj)
    {
      /*
       * Do as in 8.4.2.5
       */
      adj = isis_new_adj (hdr.source_id, ssnpa, level, circuit);
      if (adj == NULL)
	{
	  retval = ISIS_ERROR;
	  goto out;
	}

      adj->level = level;
      isis_adj_state_change (adj, ISIS_ADJ_INITIALIZING, NULL);

      if (level == 1)
	{
	  adj->sys_type = ISIS_SYSTYPE_L1_IS;
	}
      else
	{
	  adj->sys_type = ISIS_SYSTYPE_L2_IS;
	}
      list_delete_all_node (circuit->u.bc.lan_neighs[level - 1]);
      isis_adj_build_neigh_list (circuit->u.bc.adjdb[level - 1],
				 circuit->u.bc.lan_neighs[level - 1]);
    }

  if(adj->dis_record[level-1].dis==ISIS_IS_DIS)
    switch (level)
      {
      case 1:
	if (memcmp (circuit->u.bc.l1_desig_is, hdr.lan_id, ISIS_SYS_ID_LEN + 1))
	  {
	    thread_add_event (master, isis_event_dis_status_change, circuit, 0);
	    memcpy (&circuit->u.bc.l1_desig_is, hdr.lan_id,
		    ISIS_SYS_ID_LEN + 1);
	  }
	break;
      case 2:
	if (memcmp (circuit->u.bc.l2_desig_is, hdr.lan_id, ISIS_SYS_ID_LEN + 1))
	  {
	    thread_add_event (master, isis_event_dis_status_change, circuit, 0);
	    memcpy (&circuit->u.bc.l2_desig_is, hdr.lan_id,
		    ISIS_SYS_ID_LEN + 1);
	  }
	break;
      }

  adj->hold_time = hdr.hold_time;
  adj->last_upd = time (NULL);
  adj->prio[level - 1] = hdr.prio;

  memcpy (adj->lanid, hdr.lan_id, ISIS_SYS_ID_LEN + 1);

  /* which protocol are spoken ??? */
  if (found & TLVFLAG_NLPID)
    tlvs_to_adj_nlpids (&tlvs, adj);

  /* we need to copy addresses to the adj */
  if (found & TLVFLAG_IPV4_ADDR)
    tlvs_to_adj_ipv4_addrs (&tlvs, adj);

#ifdef HAVE_IPV6
  if (found & TLVFLAG_IPV6_ADDR)
    tlvs_to_adj_ipv6_addrs (&tlvs, adj);
#endif /* HAVE_IPV6 */

  adj->circuit_t = hdr.circuit_t;

  /* lets take care of the expiry */
  THREAD_TIMER_OFF (adj->t_expire);
  THREAD_TIMER_ON (master, adj->t_expire, isis_adj_expire, adj,
		   (long) adj->hold_time);

  /*
   * If the snpa for this circuit is found from LAN Neighbours TLV
   * we have two-way communication -> adjacency can be put to state "up"
   */

  if (found & TLVFLAG_LAN_NEIGHS)
    {
      if (adj->adj_state != ISIS_ADJ_UP)
	{
	  for (ALL_LIST_ELEMENTS_RO (tlvs.lan_neighs, node, snpa))
	    if (!memcmp (snpa, circuit->u.bc.snpa, ETH_ALEN))
	    {
	      isis_adj_state_change (adj, ISIS_ADJ_UP,
				     "own SNPA found in LAN Neighbours TLV");
	    }
	}
    }

out:
  /* DEBUG_ADJ_PACKETS */
  if (isis->debugs & DEBUG_ADJ_PACKETS)
    {
      /* FIXME: is this place right? fix missing info */
      zlog_debug ("ISIS-Adj (%s): Rcvd L%d LAN IIH from %s on %s, cirType %s, "
		  "cirID %u, length %ld",
		  circuit->area->area_tag,
		  level, snpa_print (ssnpa), circuit->interface->name,
		  circuit_t2string (circuit->circuit_is_type),
		  circuit->circuit_id,
		  /* FIXME: use %z when we stop supporting old compilers. */
		  (unsigned long) stream_get_endp (circuit->rcv_stream));
    }

  free_tlvs (&tlvs);

  return retval;
}

/*
 * Process Level 1/2 Link State
 * ISO - 10589
 * Section 7.3.15.1 - Action on receipt of a link state PDU
 */
static int
process_lsp (int level, struct isis_circuit *circuit, u_char * ssnpa)
{
  struct isis_link_state_hdr *hdr;
  struct isis_adjacency *adj = NULL;
  struct isis_lsp *lsp, *lsp0 = NULL;
  int retval = ISIS_OK, comp = 0;
  u_char lspid[ISIS_SYS_ID_LEN + 2];
  struct isis_passwd *passwd;

  /* Sanity check - FIXME: move to correct place */
  if ((stream_get_endp (circuit->rcv_stream) -
       stream_get_getp (circuit->rcv_stream)) < ISIS_LSP_HDR_LEN)
    {
      zlog_warn ("Packet too short");
      return ISIS_WARNING;
    }

  /* Reference the header   */
  hdr = (struct isis_link_state_hdr *) STREAM_PNT (circuit->rcv_stream);

  if (isis->debugs & DEBUG_UPDATE_PACKETS)
    {
      zlog_debug ("ISIS-Upd (%s): Rcvd L%d LSP %s, seq 0x%08x, cksum 0x%04x, "
		  "lifetime %us, len %lu, on %s",
		  circuit->area->area_tag,
		  level,
		  rawlspid_print (hdr->lsp_id),
		  ntohl (hdr->seq_num),
		  ntohs (hdr->checksum),
		  ntohs (hdr->rem_lifetime),
		  /* FIXME: use %z when we stop supporting old compilers. */
		  (unsigned long) stream_get_endp (circuit->rcv_stream), 
		  circuit->interface->name);
    }

  assert (ntohs (hdr->pdu_len) > ISIS_LSP_HDR_LEN);

  /* Checksum sanity check - FIXME: move to correct place */
  /* 12 = sysid+pdu+remtime */
  if (iso_csum_verify (STREAM_PNT (circuit->rcv_stream) + 4,
		       ntohs (hdr->pdu_len) - 12, &hdr->checksum))
    {
      zlog_debug ("ISIS-Upd (%s): LSP %s invalid LSP checksum 0x%04x",
		  circuit->area->area_tag,
		  rawlspid_print (hdr->lsp_id), ntohs (hdr->checksum));

      return ISIS_WARNING;
    }

  /* 7.3.15.1 a) 1 - external domain circuit will discard lsps */
  if (circuit->ext_domain)
    {
      zlog_debug
	("ISIS-Upd (%s): LSP %s received at level %d over circuit with "
	 "externalDomain = true", circuit->area->area_tag,
	 rawlspid_print (hdr->lsp_id), level);

      return ISIS_WARNING;
    }

  /* 7.3.15.1 a) 2,3 - manualL2OnlyMode not implemented */
  if (!accept_level (level, circuit->circuit_is_type))
    {
      zlog_debug ("ISIS-Upd (%s): LSP %s received at level %d over circuit of"
		  " type %s",
		  circuit->area->area_tag,
		  rawlspid_print (hdr->lsp_id),
		  level, circuit_t2string (circuit->circuit_is_type));

      return ISIS_WARNING;
    }

  /* 7.3.15.1 a) 4 - need to make sure IDLength matches */

  /* 7.3.15.1 a) 5 - maximum area match, can be ommited since we only use 3 */

  /* 7.3.15.1 a) 7 - password check */
  (level == ISIS_LEVEL1) ? (passwd = &circuit->area->area_passwd) :
    (passwd = &circuit->area->domain_passwd);
  if (passwd->type)
    {
      if (isis_lsp_authinfo_check (circuit->rcv_stream, circuit->area,
				   ntohs (hdr->pdu_len), passwd))
	{
	  isis_event_auth_failure (circuit->area->area_tag,
				   "LSP authentication failure", hdr->lsp_id);
	  return ISIS_WARNING;
	}
    }
  /* Find the LSP in our database and compare it to this Link State header */
  lsp = lsp_search (hdr->lsp_id, circuit->area->lspdb[level - 1]);
  if (lsp)
    comp = lsp_compare (circuit->area->area_tag, lsp, hdr->seq_num,
			hdr->checksum, hdr->rem_lifetime);
  if (lsp && (lsp->own_lsp
#ifdef TOPOLOGY_GENERATE
	      || lsp->from_topology
#endif /* TOPOLOGY_GENERATE */
      ))
    goto dontcheckadj;

  /* 7.3.15.1 a) 6 - Must check that we have an adjacency of the same level  */
  /* for broadcast circuits, snpa should be compared */
  /* FIXME : Point To Point */

  if (circuit->circ_type == CIRCUIT_T_BROADCAST)
    {
      adj = isis_adj_lookup_snpa (ssnpa, circuit->u.bc.adjdb[level - 1]);
      if (!adj)
	{
	  zlog_debug ("(%s): DS ======= LSP %s, seq 0x%08x, cksum 0x%04x, "
		      "lifetime %us on %s",
		      circuit->area->area_tag,
		      rawlspid_print (hdr->lsp_id),
		      ntohl (hdr->seq_num),
		      ntohs (hdr->checksum),
		      ntohs (hdr->rem_lifetime), circuit->interface->name);
	  return ISIS_WARNING;	/* Silently discard */
	}
    }

  /* for non broadcast, we just need to find same level adj */
  else
    {
      /* If no adj, or no sharing of level */
      if (!circuit->u.p2p.neighbor)
	{
	  return ISIS_OK;	/* Silently discard */
	}
      else
	{
	  if (((level == 1) &&
	       (circuit->u.p2p.neighbor->adj_usage == ISIS_ADJ_LEVEL2)) ||
	      ((level == 2) &&
	       (circuit->u.p2p.neighbor->adj_usage == ISIS_ADJ_LEVEL1)))
	    return ISIS_WARNING;	/* Silently discard */
	}
    }
dontcheckadj:
  /* 7.3.15.1 a) 7 - Passwords for level 1 - not implemented  */

  /* 7.3.15.1 a) 8 - Passwords for level 2 - not implemented  */

  /* 7.3.15.1 a) 9 - OriginatingLSPBufferSize - not implemented  FIXME: do it */

  /* 7.3.15.1 b) - If the remaining life time is 0, we perform 7.3.16.4 */
  if (hdr->rem_lifetime == 0)
    {
      if (!lsp)
	{
	  /* 7.3.16.4 a) 1) No LSP in db -> send an ack, but don't save */
	  /* only needed on explicit update, eg - p2p */
	  if (circuit->circ_type == CIRCUIT_T_P2P)
	    ack_lsp (hdr, circuit, level);
	  return retval;	/* FIXME: do we need a purge? */
	}
      else
	{
	  if (memcmp (hdr->lsp_id, isis->sysid, ISIS_SYS_ID_LEN))
	    {
	      /* LSP by some other system -> do 7.3.16.4 b) */
	      /* 7.3.16.4 b) 1)  */
	      if (comp == LSP_NEWER)
		{
		  lsp_update (lsp, hdr, circuit->rcv_stream, circuit->area,
			      level);
		  /* ii */
		  ISIS_FLAGS_SET_ALL (lsp->SRMflags);
		  /* iii */
		  ISIS_CLEAR_FLAG (lsp->SRMflags, circuit);
		  /* v */
		  ISIS_FLAGS_CLEAR_ALL (lsp->SSNflags);	/* FIXME: OTHER than c */
		  /* iv */
		  if (circuit->circ_type != CIRCUIT_T_BROADCAST)
		    ISIS_SET_FLAG (lsp->SSNflags, circuit);

		}		/* 7.3.16.4 b) 2) */
	      else if (comp == LSP_EQUAL)
		{
		  /* i */
		  ISIS_CLEAR_FLAG (lsp->SRMflags, circuit);
		  /* ii */
		  if (circuit->circ_type != CIRCUIT_T_BROADCAST)
		    ISIS_SET_FLAG (lsp->SSNflags, circuit);
		}		/* 7.3.16.4 b) 3) */
	      else
		{
		  ISIS_SET_FLAG (lsp->SRMflags, circuit);
		  ISIS_CLEAR_FLAG (lsp->SSNflags, circuit);
		}
	    }
	  else
	    {
	      /* our own LSP -> 7.3.16.4 c) */
	      if (LSP_PSEUDO_ID (lsp->lsp_header->lsp_id) !=
		  circuit->circuit_id
		  || (LSP_PSEUDO_ID (lsp->lsp_header->lsp_id) ==
		      circuit->circuit_id
		      && circuit->u.bc.is_dr[level - 1] == 1))
		{
		  lsp->lsp_header->seq_num = htonl (ntohl (hdr->seq_num) + 1);
		  if (isis->debugs & DEBUG_UPDATE_PACKETS)
		    zlog_debug ("LSP LEN: %d",
				ntohs (lsp->lsp_header->pdu_len));
		  fletcher_checksum (STREAM_DATA (lsp->pdu) + 12,
				   ntohs (lsp->lsp_header->pdu_len) - 12, 12);
		  ISIS_FLAGS_SET_ALL (lsp->SRMflags);
		  if (isis->debugs & DEBUG_UPDATE_PACKETS)
		    zlog_debug ("ISIS-Upd (%s): (1) re-originating LSP %s new "
				"seq 0x%08x", circuit->area->area_tag,
				rawlspid_print (hdr->lsp_id),
				ntohl (lsp->lsp_header->seq_num));
		  lsp->lsp_header->rem_lifetime =
		    htons (isis_jitter
			   (circuit->area->max_lsp_lifetime[level - 1],
			    MAX_AGE_JITTER));
		}
	      else
		{
		  /* Got purge for own pseudo-lsp, and we are not DR  */
		  lsp_purge_dr (lsp->lsp_header->lsp_id, circuit, level);
		}
	    }
	}
      return retval;
    }
  /* 7.3.15.1 c) - If this is our own lsp and we don't have it initiate a 
   * purge */
  if (memcmp (hdr->lsp_id, isis->sysid, ISIS_SYS_ID_LEN) == 0)
    {
      if (!lsp)
	{
	  /* 7.3.16.4: initiate a purge */
	  lsp_purge_non_exist (hdr, circuit->area);
	  return ISIS_OK;
	}
      /* 7.3.15.1 d) - If this is our own lsp and we have it */

      /* In 7.3.16.1, If an Intermediate system R somewhere in the domain
       * has information that the current sequence number for source S is
       * "greater" than that held by S, ... */

      else if (ntohl (hdr->seq_num) > ntohl (lsp->lsp_header->seq_num))
	{
	  /* 7.3.16.1  */
	  lsp->lsp_header->seq_num = htonl (ntohl (hdr->seq_num) + 1);

	  fletcher_checksum (STREAM_DATA (lsp->pdu) + 12,
			   ntohs (lsp->lsp_header->pdu_len) - 12, 12);

	  ISIS_FLAGS_SET_ALL (lsp->SRMflags);
	  if (isis->debugs & DEBUG_UPDATE_PACKETS)
	    zlog_debug ("ISIS-Upd (%s): (2) re-originating LSP %s new seq "
			"0x%08x", circuit->area->area_tag,
			rawlspid_print (hdr->lsp_id),
			ntohl (lsp->lsp_header->seq_num));
	  lsp->lsp_header->rem_lifetime =
	    htons (isis_jitter
		   (circuit->area->max_lsp_lifetime[level - 1],
		    MAX_AGE_JITTER));
	}
    }
  else
    {
      /* 7.3.15.1 e) - This lsp originated on another system */

      /* 7.3.15.1 e) 1) LSP newer than the one in db or no LSP in db */
      if ((!lsp || comp == LSP_NEWER))
	{
	  /* i */
	  if (lsp)
	    {
#ifdef EXTREME_DEBUG
	      zlog_debug ("level %d number is - %ld", level,
			  circuit->area->lspdb[level - 1]->dict_nodecount);
#endif /* EXTREME DEBUG */
	      lsp_search_and_destroy (hdr->lsp_id,
				      circuit->area->lspdb[level - 1]);
	      /* exists, so we overwrite */
#ifdef EXTREME_DEBUG
	      zlog_debug ("level %d number is - %ld", level,
			  circuit->area->lspdb[level - 1]->dict_nodecount);
#endif /* EXTREME DEBUG */
	    }
	  /*
	   * If this lsp is a frag, need to see if we have zero lsp present
	   */
	  if (LSP_FRAGMENT (hdr->lsp_id) != 0)
	    {
	      memcpy (lspid, hdr->lsp_id, ISIS_SYS_ID_LEN + 1);
	      LSP_FRAGMENT (lspid) = 0;
	      lsp0 = lsp_search (lspid, circuit->area->lspdb[level - 1]);
	      if (!lsp0)
		{
		  zlog_debug ("Got lsp frag, while zero lsp not database");
		  return ISIS_OK;
		}
	    }
	  lsp =
	    lsp_new_from_stream_ptr (circuit->rcv_stream,
				     ntohs (hdr->pdu_len), lsp0,
				     circuit->area);
	  lsp->level = level;
	  lsp->adj = adj;
	  lsp_insert (lsp, circuit->area->lspdb[level - 1]);
	  /* ii */
	  ISIS_FLAGS_SET_ALL (lsp->SRMflags);
	  /* iii */
	  ISIS_CLEAR_FLAG (lsp->SRMflags, circuit);

	  /* iv */
	  if (circuit->circ_type != CIRCUIT_T_BROADCAST)
	    ISIS_SET_FLAG (lsp->SSNflags, circuit);
	  /* FIXME: v) */
	}
      /* 7.3.15.1 e) 2) LSP equal to the one in db */
      else if (comp == LSP_EQUAL)
	{
	  ISIS_CLEAR_FLAG (lsp->SRMflags, circuit);
	  lsp_update (lsp, hdr, circuit->rcv_stream, circuit->area, level);
	  if (circuit->circ_type != CIRCUIT_T_BROADCAST)
	    {
	      ISIS_SET_FLAG (lsp->SSNflags, circuit);
	    }
	}
      /* 7.3.15.1 e) 3) LSP older than the one in db */
      else
	{
	  ISIS_SET_FLAG (lsp->SRMflags, circuit);
	  ISIS_CLEAR_FLAG (lsp->SSNflags, circuit);
	}
    }
  if (lsp)
    lsp->adj = adj;
  return retval;
}

/*
 * Process Sequence Numbers
 * ISO - 10589
 * Section 7.3.15.2 - Action on receipt of a sequence numbers PDU
 */

static int
process_snp (int snp_type, int level, struct isis_circuit *circuit,
	     u_char * ssnpa)
{
  int retval = ISIS_OK;
  int cmp, own_lsp;
  char typechar = ' ';
  int len;
  struct isis_adjacency *adj;
  struct isis_complete_seqnum_hdr *chdr = NULL;
  struct isis_partial_seqnum_hdr *phdr = NULL;
  uint32_t found = 0, expected = 0;
  struct isis_lsp *lsp;
  struct lsp_entry *entry;
  struct listnode *node, *nnode;
  struct listnode *node2, *nnode2;
  struct tlvs tlvs;
  struct list *lsp_list = NULL;
  struct isis_passwd *passwd;

  if (snp_type == ISIS_SNP_CSNP_FLAG)
    {
      /* getting the header info */
      typechar = 'C';
      chdr =
	(struct isis_complete_seqnum_hdr *) STREAM_PNT (circuit->rcv_stream);
      circuit->rcv_stream->getp += ISIS_CSNP_HDRLEN;
      len = ntohs (chdr->pdu_len);
      if (len < ISIS_CSNP_HDRLEN)
	{
	  zlog_warn ("Received a CSNP with bogus length!");
	  return ISIS_OK;
	}
    }
  else
    {
      typechar = 'P';
      phdr =
	(struct isis_partial_seqnum_hdr *) STREAM_PNT (circuit->rcv_stream);
      circuit->rcv_stream->getp += ISIS_PSNP_HDRLEN;
      len = ntohs (phdr->pdu_len);
      if (len < ISIS_PSNP_HDRLEN)
	{
	  zlog_warn ("Received a CSNP with bogus length!");
	  return ISIS_OK;
	}
    }

  /* 7.3.15.2 a) 1 - external domain circuit will discard snp pdu */
  if (circuit->ext_domain)
    {

      zlog_debug ("ISIS-Snp (%s): Rcvd L%d %cSNP on %s, "
		  "skipping: circuit externalDomain = true",
		  circuit->area->area_tag,
		  level, typechar, circuit->interface->name);

      return ISIS_OK;
    }

  /* 7.3.15.2 a) 2,3 - manualL2OnlyMode not implemented */
  if (!accept_level (level, circuit->circuit_is_type))
    {

      zlog_debug ("ISIS-Snp (%s): Rcvd L%d %cSNP on %s, "
		  "skipping: circuit type %s does not match level %d",
		  circuit->area->area_tag,
		  level,
		  typechar,
		  circuit->interface->name,
		  circuit_t2string (circuit->circuit_is_type), level);

      return ISIS_OK;
    }

  /* 7.3.15.2 a) 4 - not applicable for CSNP  only PSNPs on broadcast */
  if ((snp_type == ISIS_SNP_PSNP_FLAG) &&
      (circuit->circ_type == CIRCUIT_T_BROADCAST))
    {
      if (!circuit->u.bc.is_dr[level - 1])
	{

	  zlog_debug ("ISIS-Snp (%s): Rcvd L%d %cSNP from %s on %s, "
		      "skipping: we are not the DIS",
		      circuit->area->area_tag,
		      level,
		      typechar, snpa_print (ssnpa), circuit->interface->name);

	  return ISIS_OK;
	}
    }

  /* 7.3.15.2 a) 5 - need to make sure IDLength matches - already checked */

  /* 7.3.15.2 a) 6 - maximum area match, can be ommited since we only use 3
   * - already checked */

  /* 7.3.15.2 a) 7 - Must check that we have an adjacency of the same level  */
  /* for broadcast circuits, snpa should be compared */
  /* FIXME : Do we need to check SNPA? */
  if (circuit->circ_type == CIRCUIT_T_BROADCAST)
    {
      if (snp_type == ISIS_SNP_CSNP_FLAG)
	{
	  adj =
	    isis_adj_lookup (chdr->source_id, circuit->u.bc.adjdb[level - 1]);
	}
      else
	{
	  /* a psnp on a broadcast, how lovely of Juniper :) */
	  adj =
	    isis_adj_lookup (phdr->source_id, circuit->u.bc.adjdb[level - 1]);
	}
      if (!adj)
	return ISIS_OK;		/* Silently discard */
    }
  else
    {
      if (!circuit->u.p2p.neighbor)
	return ISIS_OK;		/* Silently discard */
    }

  /* 7.3.15.2 a) 8 - Passwords for level 1 - not implemented  */

  /* 7.3.15.2 a) 9 - Passwords for level 2 - not implemented  */

  memset (&tlvs, 0, sizeof (struct tlvs));

  /* parse the SNP */
  expected |= TLVFLAG_LSP_ENTRIES;
  expected |= TLVFLAG_AUTH_INFO;
  retval = parse_tlvs (circuit->area->area_tag,
		       STREAM_PNT (circuit->rcv_stream),
		       len - circuit->rcv_stream->getp,
		       &expected, &found, &tlvs);

  if (retval > ISIS_WARNING)
    {
      zlog_warn ("something went very wrong processing SNP");
      free_tlvs (&tlvs);
      return retval;
    }

  if (level == 1)
    passwd = &circuit->area->area_passwd;
  else
    passwd = &circuit->area->domain_passwd;

  if (CHECK_FLAG(passwd->snp_auth, SNP_AUTH_RECV))
    {
      if (passwd->type)
	{
	  if (!(found & TLVFLAG_AUTH_INFO) ||
	      authentication_check (passwd, &tlvs.auth_info))
	    {
	      isis_event_auth_failure (circuit->area->area_tag,
				       "SNP authentication" " failure",
				       phdr ? phdr->source_id : chdr->source_id);
	      return ISIS_OK;
	    }
	}
    }

  /* debug isis snp-packets */
  if (isis->debugs & DEBUG_SNP_PACKETS)
    {
      zlog_debug ("ISIS-Snp (%s): Rcvd L%d %cSNP from %s on %s",
		  circuit->area->area_tag,
		  level,
		  typechar, snpa_print (ssnpa), circuit->interface->name);
      if (tlvs.lsp_entries)
	{
	  for (ALL_LIST_ELEMENTS_RO (tlvs.lsp_entries, node, entry))
	  {
	    zlog_debug ("ISIS-Snp (%s):         %cSNP entry %s, seq 0x%08x,"
			" cksum 0x%04x, lifetime %us",
			circuit->area->area_tag,
			typechar,
			rawlspid_print (entry->lsp_id),
			ntohl (entry->seq_num),
			ntohs (entry->checksum), ntohs (entry->rem_lifetime));
	  }
	}
    }

  /* 7.3.15.2 b) Actions on LSP_ENTRIES reported */
  if (tlvs.lsp_entries)
    {
      for (ALL_LIST_ELEMENTS_RO (tlvs.lsp_entries, node, entry))
      {
	lsp = lsp_search (entry->lsp_id, circuit->area->lspdb[level - 1]);
	own_lsp = !memcmp (entry->lsp_id, isis->sysid, ISIS_SYS_ID_LEN);
	if (lsp)
	  {
	    /* 7.3.15.2 b) 1) is this LSP newer */
	    cmp = lsp_compare (circuit->area->area_tag, lsp, entry->seq_num,
			       entry->checksum, entry->rem_lifetime);
	    /* 7.3.15.2 b) 2) if it equals, clear SRM on p2p */
	    if (cmp == LSP_EQUAL)
	      {
		if (circuit->circ_type != CIRCUIT_T_BROADCAST)
		  ISIS_CLEAR_FLAG (lsp->SRMflags, circuit);
		/* 7.3.15.2 b) 3) if it is older, clear SSN and set SRM */
	      }
	    else if (cmp == LSP_OLDER)
	      {
		ISIS_CLEAR_FLAG (lsp->SSNflags, circuit);
		ISIS_SET_FLAG (lsp->SRMflags, circuit);
	      }
	    else
	      {
		/* 7.3.15.2 b) 4) if it is newer, set SSN and clear SRM
		 * on p2p */
		if (own_lsp)
		  {
		    lsp_inc_seqnum (lsp, ntohl (entry->seq_num));
		    ISIS_SET_FLAG (lsp->SRMflags, circuit);
		  }
		else
		  {
		    ISIS_SET_FLAG (lsp->SSNflags, circuit);
		    if (circuit->circ_type != CIRCUIT_T_BROADCAST)
		      ISIS_CLEAR_FLAG (lsp->SRMflags, circuit);
		  }
	      }
	  }
	else
	  {
	    /* 7.3.15.2 b) 5) if it was not found, and all of those are not 0, 
	     * insert it and set SSN on it */
	    if (entry->rem_lifetime && entry->checksum && entry->seq_num &&
		memcmp (entry->lsp_id, isis->sysid, ISIS_SYS_ID_LEN))
	      {
		lsp = lsp_new (entry->lsp_id, ntohs (entry->rem_lifetime),
			       0, 0, entry->checksum, level);
		lsp_insert (lsp, circuit->area->lspdb[level - 1]);
		ISIS_SET_FLAG (lsp->SSNflags, circuit);
	      }
	  }
      }
    }

  /* 7.3.15.2 c) on CSNP set SRM for all in range which were not reported */
  if (snp_type == ISIS_SNP_CSNP_FLAG)
    {
      /*
       * Build a list from our own LSP db bounded with start_ and stop_lsp_id
       */
      lsp_list = list_new ();
      lsp_build_list_nonzero_ht (chdr->start_lsp_id, chdr->stop_lsp_id,
				 lsp_list, circuit->area->lspdb[level - 1]);

      /* Fixme: Find a better solution */
      if (tlvs.lsp_entries)
	{
	  for (ALL_LIST_ELEMENTS (tlvs.lsp_entries, node, nnode, entry))
	  {
	    for (ALL_LIST_ELEMENTS (lsp_list, node2, nnode2, lsp))
	    {
	      if (lsp_id_cmp (lsp->lsp_header->lsp_id, entry->lsp_id) == 0)
		{
		  list_delete_node (lsp_list, node2);
		  break;
		}
	    }
	  }
	}
      /* on remaining LSPs we set SRM (neighbor knew not of) */
      for (ALL_LIST_ELEMENTS_RO (lsp_list, node, lsp))
      {
	ISIS_SET_FLAG (lsp->SRMflags, circuit);
      }
      /* lets free it */
      list_free (lsp_list);
    }

  free_tlvs (&tlvs);
  return retval;
}

static int
process_csnp (int level, struct isis_circuit *circuit, u_char * ssnpa)
{
  /* Sanity check - FIXME: move to correct place */
  if ((stream_get_endp (circuit->rcv_stream) -
       stream_get_getp (circuit->rcv_stream)) < ISIS_CSNP_HDRLEN)
    {
      zlog_warn ("Packet too short ( < %d)", ISIS_CSNP_HDRLEN);
      return ISIS_WARNING;
    }

  return process_snp (ISIS_SNP_CSNP_FLAG, level, circuit, ssnpa);
}

static int
process_psnp (int level, struct isis_circuit *circuit, u_char * ssnpa)
{
  if ((stream_get_endp (circuit->rcv_stream) -
       stream_get_getp (circuit->rcv_stream)) < ISIS_PSNP_HDRLEN)
    {
      zlog_warn ("Packet too short");
      return ISIS_WARNING;
    }

  return process_snp (ISIS_SNP_PSNP_FLAG, level, circuit, ssnpa);
}

/*
 * Process ISH
 * ISO - 10589
 * Section 8.2.2 - Receiving ISH PDUs by an intermediate system
 * FIXME: sample packet dump, need to figure 0x81 - looks like NLPid
 *           0x82	0x15	0x01	0x00	0x04	0x01	0x2c	0x59
 *           0x38	0x08	0x47	0x00	0x01	0x00	0x02	0x00
 *           0x03	0x00	0x81	0x01	0xcc
 */
static int
process_is_hello (struct isis_circuit *circuit)
{
  struct isis_adjacency *adj;
  int retval = ISIS_OK;
  u_char neigh_len;
  u_char *sysid;

  /* In this point in time we are not yet able to handle is_hellos
   * on lan - Sorry juniper...
   */
  if (circuit->circ_type == CIRCUIT_T_BROADCAST)
    return retval;

  neigh_len = stream_getc (circuit->rcv_stream);
  sysid = STREAM_PNT (circuit->rcv_stream) + neigh_len - 1 - ISIS_SYS_ID_LEN;
  adj = circuit->u.p2p.neighbor;
  if (!adj)
    {
      /* 8.2.2 */
      adj = isis_new_adj (sysid, NULL, 0, circuit);
      if (adj == NULL)
	return ISIS_ERROR;

      isis_adj_state_change (adj, ISIS_ADJ_INITIALIZING, NULL);
      adj->sys_type = ISIS_SYSTYPE_UNKNOWN;
      circuit->u.p2p.neighbor = adj;
    }
  /* 8.2.2 a) */
  if ((adj->adj_state == ISIS_ADJ_UP) && memcmp (adj->sysid, sysid,
						 ISIS_SYS_ID_LEN))
    {
      /* 8.2.2 a) 1) FIXME: adjStateChange(down) event */
      /* 8.2.2 a) 2) delete the adj */
      XFREE (MTYPE_ISIS_ADJACENCY, adj);
      /* 8.2.2 a) 3) create a new adj */
      adj = isis_new_adj (sysid, NULL, 0, circuit);
      if (adj == NULL)
	return ISIS_ERROR;

      /* 8.2.2 a) 3) i */
      isis_adj_state_change (adj, ISIS_ADJ_INITIALIZING, NULL);
      /* 8.2.2 a) 3) ii */
      adj->sys_type = ISIS_SYSTYPE_UNKNOWN;
      /* 8.2.2 a) 4) quite meaningless */
    }
  /* 8.2.2 b) ignore on condition */
  if ((adj->adj_state == ISIS_ADJ_INITIALIZING) &&
      (adj->sys_type == ISIS_SYSTYPE_IS))
    {
      /* do nothing */
    }
  else
    {
      /* 8.2.2 c) respond with a p2p IIH */
      send_hello (circuit, 1);
    }
  /* 8.2.2 d) type is IS */
  adj->sys_type = ISIS_SYSTYPE_IS;
  /* 8.2.2 e) FIXME: Circuit type of? */

  return retval;
}

/*
 * PDU Dispatcher
 */

static int
isis_handle_pdu (struct isis_circuit *circuit, u_char * ssnpa)
{
  struct isis_fixed_hdr *hdr;
  struct esis_fixed_hdr *esis_hdr;

  int retval = ISIS_OK;

  /*
   * Let's first read data from stream to the header
   */
  hdr = (struct isis_fixed_hdr *) STREAM_DATA (circuit->rcv_stream);

  if ((hdr->idrp != ISO10589_ISIS) && (hdr->idrp != ISO9542_ESIS))
    {
      zlog_warn ("Not an IS-IS or ES-IS packet IDRP=%02x", hdr->idrp);
      return ISIS_ERROR;
    }

  /* now we need to know if this is an ISO 9542 packet and
   * take real good care of it, waaa!
   */
  if (hdr->idrp == ISO9542_ESIS)
    {
      esis_hdr = (struct esis_fixed_hdr *) STREAM_DATA (circuit->rcv_stream);
      stream_set_getp (circuit->rcv_stream, ESIS_FIXED_HDR_LEN);
      /* FIXME: Need to do some acceptence tests */
      /* example length... */
      switch (esis_hdr->pdu_type)
	{
	case ESH_PDU:
	  /* FIXME */
	  break;
	case ISH_PDU:
	  zlog_debug ("AN ISH PDU!!");
	  retval = process_is_hello (circuit);
	  break;
	default:
	  return ISIS_ERROR;
	}
      return retval;
    }
  else
    {
      stream_set_getp (circuit->rcv_stream, ISIS_FIXED_HDR_LEN);
    }
  /*
   * and then process it
   */

  if (hdr->length < ISIS_MINIMUM_FIXED_HDR_LEN)
    {
      zlog_err ("Fixed header length = %d", hdr->length);
      return ISIS_ERROR;
    }

  if (hdr->version1 != 1)
    {
      zlog_warn ("Unsupported ISIS version %u", hdr->version1);
      return ISIS_WARNING;
    }
  /* either 6 or 0 */
  if ((hdr->id_len != 0) && (hdr->id_len != ISIS_SYS_ID_LEN))
    {
      zlog_err
	("IDFieldLengthMismatch: ID Length field in a received PDU  %u, "
	 "while the parameter for this IS is %u", hdr->id_len,
	 ISIS_SYS_ID_LEN);
      return ISIS_ERROR;
    }

  if (hdr->version2 != 1)
    {
      zlog_warn ("Unsupported ISIS version %u", hdr->version2);
      return ISIS_WARNING;
    }
  /* either 3 or 0 */
  if ((hdr->max_area_addrs != 0)
      && (hdr->max_area_addrs != isis->max_area_addrs))
    {
      zlog_err ("maximumAreaAddressesMismatch: maximumAreaAdresses in a "
		"received PDU %u while the parameter for this IS is %u",
		hdr->max_area_addrs, isis->max_area_addrs);
      return ISIS_ERROR;
    }

  switch (hdr->pdu_type)
    {
    case L1_LAN_HELLO:
      retval = process_lan_hello (ISIS_LEVEL1, circuit, ssnpa);
      break;
    case L2_LAN_HELLO:
      retval = process_lan_hello (ISIS_LEVEL2, circuit, ssnpa);
      break;
    case P2P_HELLO:
      retval = process_p2p_hello (circuit);
      break;
    case L1_LINK_STATE:
      retval = process_lsp (ISIS_LEVEL1, circuit, ssnpa);
      break;
    case L2_LINK_STATE:
      retval = process_lsp (ISIS_LEVEL2, circuit, ssnpa);
      break;
    case L1_COMPLETE_SEQ_NUM:
      retval = process_csnp (ISIS_LEVEL1, circuit, ssnpa);
      break;
    case L2_COMPLETE_SEQ_NUM:
      retval = process_csnp (ISIS_LEVEL2, circuit, ssnpa);
      break;
    case L1_PARTIAL_SEQ_NUM:
      retval = process_psnp (ISIS_LEVEL1, circuit, ssnpa);
      break;
    case L2_PARTIAL_SEQ_NUM:
      retval = process_psnp (ISIS_LEVEL2, circuit, ssnpa);
      break;
    default:
      return ISIS_ERROR;
    }

  return retval;
}

#ifdef GNU_LINUX
int
isis_receive (struct thread *thread)
{
  struct isis_circuit *circuit;
  u_char ssnpa[ETH_ALEN];
  int retval;

  /*
   * Get the circuit 
   */
  circuit = THREAD_ARG (thread);
  assert (circuit);

  if (!circuit->area)
    return ISIS_OK;

  if (circuit->rcv_stream == NULL)
    circuit->rcv_stream = stream_new (ISO_MTU (circuit));
  else
    stream_reset (circuit->rcv_stream);

  retval = circuit->rx (circuit, ssnpa);
  circuit->t_read = NULL;

  if (retval == ISIS_OK)
    retval = isis_handle_pdu (circuit, ssnpa);

  /* 
   * prepare for next packet. 
   */
  THREAD_READ_ON (master, circuit->t_read, isis_receive, circuit,
		  circuit->fd);

  return retval;
}

#else
int
isis_receive (struct thread *thread)
{
  struct isis_circuit *circuit;
  u_char ssnpa[ETH_ALEN];
  int retval;

  /*
   * Get the circuit 
   */
  circuit = THREAD_ARG (thread);
  assert (circuit);

  circuit->t_read = NULL;

  if (circuit->rcv_stream == NULL)
    circuit->rcv_stream = stream_new (ISO_MTU (circuit));
  else
    stream_reset (circuit->rcv_stream);

  retval = circuit->rx (circuit, ssnpa);

  if (retval == ISIS_OK)
    retval = isis_handle_pdu (circuit, ssnpa);

  /* 
   * prepare for next packet. 
   */
  circuit->t_read = thread_add_timer_msec (master, isis_receive, circuit,
					   listcount
					   (circuit->area->circuit_list) *
					   100);

  return retval;
}

#endif

 /* filling of the fixed isis header */
void
fill_fixed_hdr (struct isis_fixed_hdr *hdr, u_char pdu_type)
{
  memset (hdr, 0, sizeof (struct isis_fixed_hdr));

  hdr->idrp = ISO10589_ISIS;

  switch (pdu_type)
    {
    case L1_LAN_HELLO:
    case L2_LAN_HELLO:
      hdr->length = ISIS_LANHELLO_HDRLEN;
      break;
    case P2P_HELLO:
      hdr->length = ISIS_P2PHELLO_HDRLEN;
      break;
    case L1_LINK_STATE:
    case L2_LINK_STATE:
      hdr->length = ISIS_LSP_HDR_LEN;
      break;
    case L1_COMPLETE_SEQ_NUM:
    case L2_COMPLETE_SEQ_NUM:
      hdr->length = ISIS_CSNP_HDRLEN;
      break;
    case L1_PARTIAL_SEQ_NUM:
    case L2_PARTIAL_SEQ_NUM:
      hdr->length = ISIS_PSNP_HDRLEN;
      break;
    default:
      zlog_warn ("fill_fixed_hdr(): unknown pdu type %d", pdu_type);
      return;
    }
  hdr->length += ISIS_FIXED_HDR_LEN;
  hdr->pdu_type = pdu_type;
  hdr->version1 = 1;
  hdr->id_len = 0;		/* ISIS_SYS_ID_LEN -  0==6 */
  hdr->version2 = 1;
  hdr->max_area_addrs = 0;	/* isis->max_area_addrs -  0==3 */
}

/*
 * SEND SIDE                             
 */
static void
fill_fixed_hdr_andstream (struct isis_fixed_hdr *hdr, u_char pdu_type,
			  struct stream *stream)
{
  fill_fixed_hdr (hdr, pdu_type);

  stream_putc (stream, hdr->idrp);
  stream_putc (stream, hdr->length);
  stream_putc (stream, hdr->version1);
  stream_putc (stream, hdr->id_len);
  stream_putc (stream, hdr->pdu_type);
  stream_putc (stream, hdr->version2);
  stream_putc (stream, hdr->reserved);
  stream_putc (stream, hdr->max_area_addrs);

  return;
}

int
send_hello (struct isis_circuit *circuit, int level)
{
  struct isis_fixed_hdr fixed_hdr;
  struct isis_lan_hello_hdr hello_hdr;
  struct isis_p2p_hello_hdr p2p_hello_hdr;

  u_int32_t interval;
  unsigned long len_pointer, length;
  int retval;

  if (circuit->interface->mtu == 0)
    {
      zlog_warn ("circuit has zero MTU");
      return ISIS_WARNING;
    }

  if (!circuit->snd_stream)
    circuit->snd_stream = stream_new (ISO_MTU (circuit));
  else
    stream_reset (circuit->snd_stream);

  if (circuit->circ_type == CIRCUIT_T_BROADCAST)
    if (level == 1)
      fill_fixed_hdr_andstream (&fixed_hdr, L1_LAN_HELLO,
				circuit->snd_stream);
    else
      fill_fixed_hdr_andstream (&fixed_hdr, L2_LAN_HELLO,
				circuit->snd_stream);
  else
    fill_fixed_hdr_andstream (&fixed_hdr, P2P_HELLO, circuit->snd_stream);

  /*
   * Fill LAN Level 1 or 2 Hello PDU header
   */
  memset (&hello_hdr, 0, sizeof (struct isis_lan_hello_hdr));
  interval = circuit->hello_multiplier[level - 1] *
    circuit->hello_interval[level - 1];
  /* If we are the DIS then hello interval is divided by three, as is the hold-timer */
  if (circuit->u.bc.is_dr[level - 1])
    interval=interval/3;
  if (interval > USHRT_MAX)
    interval = USHRT_MAX;
  hello_hdr.circuit_t = circuit->circuit_is_type;
  memcpy (hello_hdr.source_id, isis->sysid, ISIS_SYS_ID_LEN);
  hello_hdr.hold_time = htons ((u_int16_t) interval);

  hello_hdr.pdu_len = 0;	/* Update the PDU Length later */
  len_pointer = stream_get_endp (circuit->snd_stream) + 3 + ISIS_SYS_ID_LEN;

  /* copy the shared part of the hello to the p2p hello if needed */
  if (circuit->circ_type == CIRCUIT_T_P2P)
    {
      memcpy (&p2p_hello_hdr, &hello_hdr, 5 + ISIS_SYS_ID_LEN);
      p2p_hello_hdr.local_id = circuit->circuit_id;
      /* FIXME: need better understanding */
      stream_put (circuit->snd_stream, &p2p_hello_hdr, ISIS_P2PHELLO_HDRLEN);
    }
  else
    {
      hello_hdr.prio = circuit->u.bc.priority[level - 1];
      if (level == 1 && circuit->u.bc.l1_desig_is)
	{
	  memcpy (hello_hdr.lan_id, circuit->u.bc.l1_desig_is,
		  ISIS_SYS_ID_LEN + 1);
	}
      else if (level == 2 && circuit->u.bc.l2_desig_is)
	{
	  memcpy (hello_hdr.lan_id, circuit->u.bc.l2_desig_is,
		  ISIS_SYS_ID_LEN + 1);
	}
      stream_put (circuit->snd_stream, &hello_hdr, ISIS_LANHELLO_HDRLEN);
    }

  /*
   * Then the variable length part 
   */
  /* add circuit password */
  if (circuit->passwd.type)
    if (tlv_add_authinfo (circuit->passwd.type, circuit->passwd.len,
			  circuit->passwd.passwd, circuit->snd_stream))
      return ISIS_WARNING;
  /*  Area Addresses TLV */
  assert (circuit->area);
  if (circuit->area->area_addrs && circuit->area->area_addrs->count > 0)
    if (tlv_add_area_addrs (circuit->area->area_addrs, circuit->snd_stream))
      return ISIS_WARNING;

  /*  LAN Neighbors TLV */
  if (circuit->circ_type == CIRCUIT_T_BROADCAST)
    {
      if (level == 1 && circuit->u.bc.lan_neighs[0]->count > 0)
	if (tlv_add_lan_neighs (circuit->u.bc.lan_neighs[0],
				circuit->snd_stream))
	  return ISIS_WARNING;
      if (level == 2 && circuit->u.bc.lan_neighs[1]->count > 0)
	if (tlv_add_lan_neighs (circuit->u.bc.lan_neighs[1],
				circuit->snd_stream))
	  return ISIS_WARNING;
    }

  /* Protocols Supported TLV */
  if (circuit->nlpids.count > 0)
    if (tlv_add_nlpid (&circuit->nlpids, circuit->snd_stream))
      return ISIS_WARNING;
  /* IP interface Address TLV */
  if (circuit->ip_router && circuit->ip_addrs && circuit->ip_addrs->count > 0)
    if (tlv_add_ip_addrs (circuit->ip_addrs, circuit->snd_stream))
      return ISIS_WARNING;

#ifdef HAVE_IPV6
  /* IPv6 Interface Address TLV */
  if (circuit->ipv6_router && circuit->ipv6_link &&
      circuit->ipv6_link->count > 0)
    if (tlv_add_ipv6_addrs (circuit->ipv6_link, circuit->snd_stream))
      return ISIS_WARNING;
#endif /* HAVE_IPV6 */

  if (circuit->u.bc.pad_hellos)
    if (tlv_add_padding (circuit->snd_stream))
      return ISIS_WARNING;

  length = stream_get_endp (circuit->snd_stream);
  /* Update PDU length */
  stream_putw_at (circuit->snd_stream, len_pointer, (u_int16_t) length);

  retval = circuit->tx (circuit, level);
  if (retval)
    zlog_warn ("sending of LAN Level %d Hello failed", level);

  /* DEBUG_ADJ_PACKETS */
  if (isis->debugs & DEBUG_ADJ_PACKETS)
    {
      if (circuit->circ_type == CIRCUIT_T_BROADCAST)
	{
	  zlog_debug ("ISIS-Adj (%s): Sent L%d LAN IIH on %s, length %ld",
		      circuit->area->area_tag, level, circuit->interface->name,
		      /* FIXME: use %z when we stop supporting old compilers. */
		      (unsigned long) STREAM_SIZE (circuit->snd_stream));
	}
      else
	{
	  zlog_debug ("ISIS-Adj (%s): Sent P2P IIH on %s, length %ld",
		      circuit->area->area_tag, circuit->interface->name,
		      /* FIXME: use %z when we stop supporting old compilers. */
		      (unsigned long) STREAM_SIZE (circuit->snd_stream));
	}
    }

  return retval;
}

static int
send_lan_hello (struct isis_circuit *circuit, int level)
{
  return send_hello (circuit, level);
}

int
send_lan_l1_hello (struct thread *thread)
{
  struct isis_circuit *circuit;
  int retval;
  unsigned long next_hello;

  circuit = THREAD_ARG (thread);
  assert (circuit);

  if (!circuit->area) {
    return ISIS_OK;
  }

  /* Pseudonode sends hellos three times more than the other nodes */
  if (circuit->u.bc.is_dr[0])
    next_hello=circuit->hello_interval[0]/3+1;
  else
    next_hello=circuit->hello_interval[0];

  circuit->u.bc.t_send_lan_hello[0] = NULL;

  if (circuit->u.bc.run_dr_elect[0])
    retval = isis_dr_elect (circuit, 1);

  retval = send_lan_hello (circuit, 1);

  /* set next timer thread */
  THREAD_TIMER_ON (master, circuit->u.bc.t_send_lan_hello[0],
		   send_lan_l1_hello, circuit,
                  isis_jitter (next_hello, IIH_JITTER));

  return retval;
}

int
send_lan_l2_hello (struct thread *thread)
{
  struct isis_circuit *circuit;
  int retval;
  unsigned long next_hello;

  circuit = THREAD_ARG (thread);
  assert (circuit);

  if (!circuit->area) {
    return ISIS_OK;
  }

  /* Pseudonode sends hellos three times more than the other nodes */
  if (circuit->u.bc.is_dr[1])
    next_hello=circuit->hello_interval[1]/3+1;
  else
    next_hello=circuit->hello_interval[1];

  circuit->u.bc.t_send_lan_hello[1] = NULL;

  if (circuit->u.bc.run_dr_elect[1])
    retval = isis_dr_elect (circuit, 2);

  retval = send_lan_hello (circuit, 2);

  /* set next timer thread */
  THREAD_TIMER_ON (master, circuit->u.bc.t_send_lan_hello[1],
		   send_lan_l2_hello, circuit,
                  isis_jitter (next_hello, IIH_JITTER));

  return retval;
}

int
send_p2p_hello (struct thread *thread)
{
  struct isis_circuit *circuit;

  circuit = THREAD_ARG (thread);
  assert (circuit);
  circuit->u.p2p.t_send_p2p_hello = NULL;

  send_hello (circuit, 1);

  /* set next timer thread */
  THREAD_TIMER_ON (master, circuit->u.p2p.t_send_p2p_hello, send_p2p_hello,
		   circuit, isis_jitter (circuit->hello_interval[1],
					 IIH_JITTER));

  return ISIS_OK;
}

static int
build_csnp (int level, u_char * start, u_char * stop, struct list *lsps,
	    struct isis_circuit *circuit)
{
  struct isis_fixed_hdr fixed_hdr;
  struct isis_passwd *passwd;
  int retval = ISIS_OK;
  unsigned long lenp;
  u_int16_t length;

  if (level == 1)
    fill_fixed_hdr_andstream (&fixed_hdr, L1_COMPLETE_SEQ_NUM,
			      circuit->snd_stream);
  else
    fill_fixed_hdr_andstream (&fixed_hdr, L2_COMPLETE_SEQ_NUM,
			      circuit->snd_stream);

  /*
   * Fill Level 1 or 2 Complete Sequence Numbers header
   */

  lenp = stream_get_endp (circuit->snd_stream);
  stream_putw (circuit->snd_stream, 0);	/* PDU length - when we know it */
  /* no need to send the source here, it is always us if we csnp */
  stream_put (circuit->snd_stream, isis->sysid, ISIS_SYS_ID_LEN);
  /* with zero circuit id - ref 9.10, 9.11 */
  stream_putc (circuit->snd_stream, 0x00);

  stream_put (circuit->snd_stream, start, ISIS_SYS_ID_LEN + 2);
  stream_put (circuit->snd_stream, stop, ISIS_SYS_ID_LEN + 2);

  /*
   * And TLVs
   */
  if (level == 1)
    passwd = &circuit->area->area_passwd;
  else
    passwd = &circuit->area->domain_passwd;

  if (CHECK_FLAG(passwd->snp_auth, SNP_AUTH_SEND))
    if (passwd->type)
      retval = tlv_add_authinfo (passwd->type, passwd->len,
				 passwd->passwd, circuit->snd_stream);

  if (!retval && lsps)
    {
      retval = tlv_add_lsp_entries (lsps, circuit->snd_stream);
    }
  length = (u_int16_t) stream_get_endp (circuit->snd_stream);
  assert (length >= ISIS_CSNP_HDRLEN);
  /* Update PU length */
  stream_putw_at (circuit->snd_stream, lenp, length);

  return retval;
}

/*
 * FIXME: support multiple CSNPs
 */

int
send_csnp (struct isis_circuit *circuit, int level)
{
  int retval = ISIS_OK;
  u_char start[ISIS_SYS_ID_LEN + 2];
  u_char stop[ISIS_SYS_ID_LEN + 2];
  struct list *list = NULL;
  struct listnode *node;
  struct isis_lsp *lsp;

  memset (start, 0x00, ISIS_SYS_ID_LEN + 2);
  memset (stop, 0xff, ISIS_SYS_ID_LEN + 2);

  if (circuit->area->lspdb[level - 1] &&
      dict_count (circuit->area->lspdb[level - 1]) > 0)
    {
      list = list_new ();
      lsp_build_list (start, stop, list, circuit->area->lspdb[level - 1]);

      if (circuit->snd_stream == NULL)
	circuit->snd_stream = stream_new (ISO_MTU (circuit));
      else
	stream_reset (circuit->snd_stream);

      retval = build_csnp (level, start, stop, list, circuit);

      if (isis->debugs & DEBUG_SNP_PACKETS)
	{
	  zlog_debug ("ISIS-Snp (%s): Sent L%d CSNP on %s, length %ld",
		     circuit->area->area_tag, level, circuit->interface->name,
		     /* FIXME: use %z when we stop supporting old compilers. */
		     (unsigned long) STREAM_SIZE (circuit->snd_stream));
	  for (ALL_LIST_ELEMENTS_RO (list, node, lsp))
	  {
	    zlog_debug ("ISIS-Snp (%s):         CSNP entry %s, seq 0x%08x,"
			" cksum 0x%04x, lifetime %us",
			circuit->area->area_tag,
			rawlspid_print (lsp->lsp_header->lsp_id),
			ntohl (lsp->lsp_header->seq_num),
			ntohs (lsp->lsp_header->checksum),
			ntohs (lsp->lsp_header->rem_lifetime));
	  }
	}

      list_delete (list);

      if (retval == ISIS_OK)
	retval = circuit->tx (circuit, level);
    }
  return retval;
}

int
send_l1_csnp (struct thread *thread)
{
  struct isis_circuit *circuit;
  int retval = ISIS_OK;

  circuit = THREAD_ARG (thread);
  assert (circuit);

  circuit->t_send_csnp[0] = NULL;

  if (circuit->circ_type == CIRCUIT_T_BROADCAST && circuit->u.bc.is_dr[0])
    {
      send_csnp (circuit, 1);
    }
  /* set next timer thread */
  THREAD_TIMER_ON (master, circuit->t_send_csnp[0], send_l1_csnp, circuit,
		   isis_jitter (circuit->csnp_interval[0], CSNP_JITTER));

  return retval;
}

int
send_l2_csnp (struct thread *thread)
{
  struct isis_circuit *circuit;
  int retval = ISIS_OK;

  circuit = THREAD_ARG (thread);
  assert (circuit);

  circuit->t_send_csnp[1] = NULL;

  if (circuit->circ_type == CIRCUIT_T_BROADCAST && circuit->u.bc.is_dr[1])
    {
      send_csnp (circuit, 2);
    }
  /* set next timer thread */
  THREAD_TIMER_ON (master, circuit->t_send_csnp[1], send_l2_csnp, circuit,
		   isis_jitter (circuit->csnp_interval[1], CSNP_JITTER));

  return retval;
}

static int
build_psnp (int level, struct isis_circuit *circuit, struct list *lsps)
{
  struct isis_fixed_hdr fixed_hdr;
  unsigned long lenp;
  u_int16_t length;
  int retval = 0;
  struct isis_lsp *lsp;
  struct isis_passwd *passwd;
  struct listnode *node;

  if (level == 1)
    fill_fixed_hdr_andstream (&fixed_hdr, L1_PARTIAL_SEQ_NUM,
			      circuit->snd_stream);
  else
    fill_fixed_hdr_andstream (&fixed_hdr, L2_PARTIAL_SEQ_NUM,
			      circuit->snd_stream);

  /*
   * Fill Level 1 or 2 Partial Sequence Numbers header
   */
  lenp = stream_get_endp (circuit->snd_stream);
  stream_putw (circuit->snd_stream, 0);	/* PDU length - when we know it */
  stream_put (circuit->snd_stream, isis->sysid, ISIS_SYS_ID_LEN);
  stream_putc (circuit->snd_stream, circuit->idx);

  /*
   * And TLVs
   */

  if (level == 1)
    passwd = &circuit->area->area_passwd;
  else
    passwd = &circuit->area->domain_passwd;

  if (CHECK_FLAG(passwd->snp_auth, SNP_AUTH_SEND))
    if (passwd->type)
      retval = tlv_add_authinfo (passwd->type, passwd->len,
				 passwd->passwd, circuit->snd_stream);

  if (!retval && lsps)
    {
      retval = tlv_add_lsp_entries (lsps, circuit->snd_stream);
    }

  if (isis->debugs & DEBUG_SNP_PACKETS)
    {
      for (ALL_LIST_ELEMENTS_RO (lsps, node, lsp))
      {
	zlog_debug ("ISIS-Snp (%s):         PSNP entry %s, seq 0x%08x,"
		    " cksum 0x%04x, lifetime %us",
		    circuit->area->area_tag,
		    rawlspid_print (lsp->lsp_header->lsp_id),
		    ntohl (lsp->lsp_header->seq_num),
		    ntohs (lsp->lsp_header->checksum),
		    ntohs (lsp->lsp_header->rem_lifetime));
      }
    }

  length = (u_int16_t) stream_get_endp (circuit->snd_stream);
  assert (length >= ISIS_PSNP_HDRLEN);
  /* Update PDU length */
  stream_putw_at (circuit->snd_stream, lenp, length);

  return ISIS_OK;
}

/*
 *  7.3.15.4 action on expiration of partial SNP interval
 *  level 1
 */
static int
send_psnp (int level, struct isis_circuit *circuit)
{
  int retval = ISIS_OK;
  struct isis_lsp *lsp;
  struct list *list = NULL;
  struct listnode *node;

  if ((circuit->circ_type == CIRCUIT_T_BROADCAST &&
       !circuit->u.bc.is_dr[level - 1]) ||
      circuit->circ_type != CIRCUIT_T_BROADCAST)
    {

      if (circuit->area->lspdb[level - 1] &&
	  dict_count (circuit->area->lspdb[level - 1]) > 0)
	{
	  list = list_new ();
	  lsp_build_list_ssn (circuit, list, circuit->area->lspdb[level - 1]);

	  if (listcount (list) > 0)
	    {
	      if (circuit->snd_stream == NULL)
		circuit->snd_stream = stream_new (ISO_MTU (circuit));
	      else
		stream_reset (circuit->snd_stream);


	      if (isis->debugs & DEBUG_SNP_PACKETS)
		zlog_debug ("ISIS-Snp (%s): Sent L%d PSNP on %s, length %ld",
			    circuit->area->area_tag, level,
			    circuit->interface->name,
			    /* FIXME: use %z when we stop supporting old
			     * compilers. */
			    (unsigned long) STREAM_SIZE (circuit->snd_stream));

	      retval = build_psnp (level, circuit, list);
	      if (retval == ISIS_OK)
		retval = circuit->tx (circuit, level);

	      if (retval == ISIS_OK)
		{
		  /*
		   * sending succeeded, we can clear SSN flags of this circuit
		   * for the LSPs in list
		   */
		  for (ALL_LIST_ELEMENTS_RO (list, node, lsp))
                    ISIS_CLEAR_FLAG (lsp->SSNflags, circuit);
		}
	    }
	  list_delete (list);
	}
    }

  return retval;
}

int
send_l1_psnp (struct thread *thread)
{

  struct isis_circuit *circuit;
  int retval = ISIS_OK;

  circuit = THREAD_ARG (thread);
  assert (circuit);

  circuit->t_send_psnp[0] = NULL;

  send_psnp (1, circuit);
  /* set next timer thread */
  THREAD_TIMER_ON (master, circuit->t_send_psnp[0], send_l1_psnp, circuit,
		   isis_jitter (circuit->psnp_interval[0], PSNP_JITTER));

  return retval;
}

/*
 *  7.3.15.4 action on expiration of partial SNP interval
 *  level 2
 */
int
send_l2_psnp (struct thread *thread)
{
  struct isis_circuit *circuit;
  int retval = ISIS_OK;

  circuit = THREAD_ARG (thread);
  assert (circuit);

  circuit->t_send_psnp[1] = NULL;

  send_psnp (2, circuit);

  /* set next timer thread */
  THREAD_TIMER_ON (master, circuit->t_send_psnp[1], send_l2_psnp, circuit,
		   isis_jitter (circuit->psnp_interval[1], PSNP_JITTER));

  return retval;
}

/*
 * ISO 10589 - 7.3.14.3
 */
int
send_lsp (struct thread *thread)
{
  struct isis_circuit *circuit;
  struct isis_lsp *lsp;
  struct listnode *node;
  int retval = 0;

  circuit = THREAD_ARG (thread);
  assert (circuit);

  if (circuit->state == C_STATE_UP)
    {
      lsp = listgetdata ((node = listhead (circuit->lsp_queue)));

      /*
       * Do not send if levels do not match
       */
      if (!(lsp->level & circuit->circuit_is_type))
	goto dontsend;

      /*
       * Do not send if we do not have adjacencies in state up on the circuit
       */
      if (circuit->upadjcount[lsp->level - 1] == 0)
	goto dontsend;
      /* only send if it needs sending */
      if ((time (NULL) - lsp->last_sent) >=
	  circuit->area->lsp_gen_interval[lsp->level - 1])
	{

	  if (isis->debugs & DEBUG_UPDATE_PACKETS)
	    {
	      zlog_debug
		("ISIS-Upd (%s): Sent L%d LSP %s, seq 0x%08x, cksum 0x%04x,"
		 " lifetime %us on %s", circuit->area->area_tag, lsp->level,
		 rawlspid_print (lsp->lsp_header->lsp_id),
		 ntohl (lsp->lsp_header->seq_num),
		 ntohs (lsp->lsp_header->checksum),
		 ntohs (lsp->lsp_header->rem_lifetime),
		 circuit->interface->name);
	    }
	  /* copy our lsp to the send buffer */
	  stream_copy (circuit->snd_stream, lsp->pdu);

	  retval = circuit->tx (circuit, lsp->level);

	  /*
	   * If the sending succeeded, we can del the lsp from circuits
	   * lsp_queue
	   */
	  if (retval == ISIS_OK)
	    {
	      list_delete_node (circuit->lsp_queue, node);

	      /*
	       * On broadcast circuits also the SRMflag can be cleared
	       */
	      if (circuit->circ_type == CIRCUIT_T_BROADCAST)
		ISIS_CLEAR_FLAG (lsp->SRMflags, circuit);

	      if (flags_any_set (lsp->SRMflags) == 0)
		{
		  /*
		   * need to remember when we were last sent
		   */
		  lsp->last_sent = time (NULL);
		}
	    }
	  else
	    {
	      zlog_debug ("sending of level %d link state failed", lsp->level);
	    }
	}
      else
	{
	  /* my belief is that if it wasn't his time, the lsp can be removed
	   * from the queue
	   */
	dontsend:
	  list_delete_node (circuit->lsp_queue, node);
	}
#if 0
      /*
       * If there are still LSPs send next one after lsp-interval (33 msecs)
       */
      if (listcount (circuit->lsp_queue) > 0)
	thread_add_timer (master, send_lsp, circuit, 1);
#endif
    }

  return retval;
}

int
ack_lsp (struct isis_link_state_hdr *hdr, struct isis_circuit *circuit,
	 int level)
{
  unsigned long lenp;
  int retval;
  u_int16_t length;
  struct isis_fixed_hdr fixed_hdr;

  if (!circuit->snd_stream)
    circuit->snd_stream = stream_new (ISO_MTU (circuit));
  else
    stream_reset (circuit->snd_stream);

//  fill_llc_hdr (stream);
  if (level == 1)
    fill_fixed_hdr_andstream (&fixed_hdr, L1_PARTIAL_SEQ_NUM,
			      circuit->snd_stream);
  else
    fill_fixed_hdr_andstream (&fixed_hdr, L2_PARTIAL_SEQ_NUM,
			      circuit->snd_stream);


  lenp = stream_get_endp (circuit->snd_stream);
  stream_putw (circuit->snd_stream, 0);	/* PDU length  */
  stream_put (circuit->snd_stream, isis->sysid, ISIS_SYS_ID_LEN);
  stream_putc (circuit->snd_stream, circuit->idx);
  stream_putc (circuit->snd_stream, 9);	/* code */
  stream_putc (circuit->snd_stream, 16);	/* len */

  stream_putw (circuit->snd_stream, ntohs (hdr->rem_lifetime));
  stream_put (circuit->snd_stream, hdr->lsp_id, ISIS_SYS_ID_LEN + 2);
  stream_putl (circuit->snd_stream, ntohl (hdr->seq_num));
  stream_putw (circuit->snd_stream, ntohs (hdr->checksum));

  length = (u_int16_t) stream_get_endp (circuit->snd_stream);
  /* Update PDU length */
  stream_putw_at (circuit->snd_stream, lenp, length);

  retval = circuit->tx (circuit, level);

  return retval;
}

