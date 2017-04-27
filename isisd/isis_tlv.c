/*
 * IS-IS Rout(e)ing protocol - isis_tlv.c
 *                             IS-IS TLV related routines
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

#include "log.h"
#include "linklist.h"
#include "stream.h"
#include "memory.h"
#include "prefix.h"
#include "vty.h"
#include "if.h"

#include "isisd/dict.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_tlv.h"
#include "isisd/isisd.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_te.h"
#include "isisd/isis_mt.h"

void
free_tlv (void *val)
{
  XFREE (MTYPE_ISIS_TLV, val);

  return;
}

/*
 * Called after parsing of a PDU. There shouldn't be any tlv's left, so this
 * is only a caution to avoid memory leaks
 */
void
free_tlvs (struct tlvs *tlvs)
{
  if (tlvs->area_addrs)
    list_delete (tlvs->area_addrs);
  if (tlvs->mt_router_info)
    list_delete (tlvs->mt_router_info);
  if (tlvs->is_neighs)
    list_delete (tlvs->is_neighs);
  if (tlvs->te_is_neighs)
    list_delete (tlvs->te_is_neighs);
  if (tlvs->mt_is_neighs)
    list_delete (tlvs->mt_is_neighs);
  if (tlvs->es_neighs)
    list_delete (tlvs->es_neighs);
  if (tlvs->lsp_entries)
    list_delete (tlvs->lsp_entries);
  if (tlvs->prefix_neighs)
    list_delete (tlvs->prefix_neighs);
  if (tlvs->lan_neighs)
    list_delete (tlvs->lan_neighs);
  if (tlvs->ipv4_addrs)
    list_delete (tlvs->ipv4_addrs);
  if (tlvs->ipv4_int_reachs)
    list_delete (tlvs->ipv4_int_reachs);
  if (tlvs->ipv4_ext_reachs)
    list_delete (tlvs->ipv4_ext_reachs);
  if (tlvs->te_ipv4_reachs)
    list_delete (tlvs->te_ipv4_reachs);
  if (tlvs->mt_ipv4_reachs)
    list_delete (tlvs->mt_ipv4_reachs);
  if (tlvs->ipv6_addrs)
    list_delete (tlvs->ipv6_addrs);
  if (tlvs->ipv6_reachs)
    list_delete (tlvs->ipv6_reachs);
  if (tlvs->mt_ipv6_reachs)
    list_delete (tlvs->mt_ipv6_reachs);

  memset (tlvs, 0, sizeof (struct tlvs));

  return;
}

static int
parse_mtid(uint16_t *mtid, bool read_mtid,
           unsigned int *length, u_char **pnt)
{
  if (!read_mtid)
    {
      *mtid = ISIS_MT_IPV4_UNICAST;
      return ISIS_OK;
    }

  uint16_t mtid_buf;

  if (*length < sizeof(mtid_buf))
    {
      zlog_warn("ISIS-TLV: mt tlv too short to contain MT id");
      return ISIS_WARNING;
    }

  memcpy(&mtid_buf, *pnt, sizeof(mtid_buf));
  *pnt += sizeof(mtid_buf);
  *length -= sizeof(mtid_buf);

  *mtid = ntohs(mtid_buf) & ISIS_MT_MASK;
  return ISIS_OK;
}

static int
parse_mt_is_neighs(struct tlvs *tlvs, bool read_mtid,
                   unsigned int length, u_char *pnt)
{
  struct list *neigh_list;
  uint16_t mtid;
  int rv;

  rv = parse_mtid(&mtid, read_mtid, &length, &pnt);
  if (rv != ISIS_OK)
    return rv;

  if (mtid == ISIS_MT_IPV4_UNICAST)
    {
      if (!tlvs->te_is_neighs)
        {
          tlvs->te_is_neighs = list_new();
          tlvs->te_is_neighs->del = free_tlv;
        }
      neigh_list = tlvs->te_is_neighs;
    }
  else
    {
      struct tlv_mt_neighbors *neighbors;

      neighbors = tlvs_get_mt_neighbors(tlvs, mtid);
      neighbors->list->del = free_tlv;
      neigh_list = neighbors->list;
    }

  while (length >= IS_NEIGHBOURS_LEN)
    {
      struct te_is_neigh *neigh = XCALLOC(MTYPE_ISIS_TLV, sizeof(*neigh));

      memcpy(neigh, pnt, IS_NEIGHBOURS_LEN);
      pnt += IS_NEIGHBOURS_LEN;
      length -= IS_NEIGHBOURS_LEN;

      if (neigh->sub_tlvs_length > length)
        {
          zlog_warn("ISIS-TLV: neighbor subtlv length exceeds TLV size");
          XFREE(MTYPE_ISIS_TLV, neigh);
          return ISIS_WARNING;
        }

      memcpy(neigh->sub_tlvs, pnt, neigh->sub_tlvs_length);
      pnt += neigh->sub_tlvs_length;
      length -= neigh->sub_tlvs_length;

      listnode_add(neigh_list, neigh);
    }

  if (length)
    {
      zlog_warn("ISIS-TLV: TE/MT neighor TLV has trailing data");
      return ISIS_WARNING;
    }

  return ISIS_OK;
}

static int
parse_mt_ipv4_reachs(struct tlvs *tlvs, bool read_mtid,
                     unsigned int length, u_char *pnt)
{
  struct list *reach_list;
  uint16_t mtid;
  int rv;

  rv = parse_mtid(&mtid, read_mtid, &length, &pnt);
  if (rv != ISIS_OK)
    return rv;

  if (mtid == ISIS_MT_IPV4_UNICAST)
    {
      if (!tlvs->te_ipv4_reachs)
        {
          tlvs->te_ipv4_reachs = list_new();
          tlvs->te_ipv4_reachs->del = free_tlv;
        }
      reach_list = tlvs->te_ipv4_reachs;
    }
  else
    {
      struct tlv_mt_ipv4_reachs *reachs;

      reachs = tlvs_get_mt_ipv4_reachs(tlvs, mtid);
      reachs->list->del = free_tlv;
      reach_list = reachs->list;
    }

  while (length >= 5) /* Metric + Control */
    {
      struct te_ipv4_reachability *reach = XCALLOC(MTYPE_ISIS_TLV, TE_IPV4_REACH_LEN);

      memcpy(reach, pnt, 5); /* Metric + Control */
      pnt += 5;
      length -= 5;

      unsigned char prefixlen = reach->control & 0x3F;

      if (prefixlen > IPV4_MAX_BITLEN)
        {
          zlog_warn("ISIS-TLV: invalid IPv4 extended reachability prefix length %d", prefixlen);
          XFREE(MTYPE_ISIS_TLV, reach);
          return ISIS_WARNING;
        }

      if (length < (unsigned int)PSIZE(prefixlen))
        {
          zlog_warn("ISIS-TLV: invalid IPv4 extended reachability prefix too long for tlv");
          XFREE(MTYPE_ISIS_TLV, reach);
          return ISIS_WARNING;
        }

      memcpy(&reach->prefix_start, pnt, PSIZE(prefixlen));
      pnt += PSIZE(prefixlen);
      length -= PSIZE(prefixlen);

      if (reach->control & TE_IPV4_HAS_SUBTLV)
        {
          if (length < 1)
            {
              zlog_warn("ISIS-TLV: invalid IPv4 extended reachability SubTLV missing");
              XFREE(MTYPE_ISIS_TLV, reach);
              return ISIS_WARNING;
            }

          u_char subtlv_len = *pnt;
          pnt++;
          length--;

          if (length < subtlv_len)
            {
              zlog_warn("ISIS-TLV: invalid IPv4 extended reachability SubTLVs have oversize");
              XFREE(MTYPE_ISIS_TLV, reach);
              return ISIS_WARNING;
            }

          /* Skip Sub-TLVs for now */
          pnt += subtlv_len;
          length -= subtlv_len;
        }
      listnode_add(reach_list, reach);
    }

  if (length)
    {
      zlog_warn("ISIS-TLV: TE/MT ipv4 reachability TLV has trailing data");
      return ISIS_WARNING;
    }

  return ISIS_OK;
}

static int
parse_mt_ipv6_reachs(struct tlvs *tlvs, bool read_mtid,
                     unsigned int length, u_char *pnt)
{
  struct list *reach_list;
  uint16_t mtid;
  int rv;

  rv = parse_mtid(&mtid, read_mtid, &length, &pnt);
  if (rv != ISIS_OK)
    return rv;

  if (mtid == ISIS_MT_IPV4_UNICAST)
    {
      if (!tlvs->ipv6_reachs)
        {
          tlvs->ipv6_reachs = list_new();
          tlvs->ipv6_reachs->del = free_tlv;
        }
      reach_list = tlvs->ipv6_reachs;
    }
  else
    {
      struct tlv_mt_ipv6_reachs *reachs;

      reachs = tlvs_get_mt_ipv6_reachs(tlvs, mtid);
      reachs->list->del = free_tlv;
      reach_list = reachs->list;
    }

  while (length >= 6) /* Metric + Control + Prefixlen */
    {
      struct ipv6_reachability *reach = XCALLOC(MTYPE_ISIS_TLV, sizeof(*reach));

      memcpy(reach, pnt, 6); /* Metric + Control + Prefixlen */
      pnt += 6;
      length -= 6;

      if (reach->prefix_len > IPV6_MAX_BITLEN)
        {
          zlog_warn("ISIS-TLV: invalid IPv6 reachability prefix length %d", reach->prefix_len);
          XFREE(MTYPE_ISIS_TLV, reach);
          return ISIS_WARNING;
        }

      if (length < (unsigned int)PSIZE(reach->prefix_len))
        {
          zlog_warn("ISIS-TLV: invalid IPv6 reachability prefix too long for tlv");
          XFREE(MTYPE_ISIS_TLV, reach);
          return ISIS_WARNING;
        }

      memcpy(&reach->prefix, pnt, PSIZE(reach->prefix_len));
      pnt += PSIZE(reach->prefix_len);
      length -= PSIZE(reach->prefix_len);

      if (reach->control_info & CTRL_INFO_SUBTLVS)
        {
          if (length < 1)
            {
              zlog_warn("ISIS-TLV: invalid IPv6 reachability SubTLV missing");
              XFREE(MTYPE_ISIS_TLV, reach);
              return ISIS_WARNING;
            }

          u_char subtlv_len = *pnt;
          pnt++;
          length--;

          if (length < subtlv_len)
            {
              zlog_warn("ISIS-TLV: invalid IPv6 reachability SubTLVs have oversize");
              XFREE(MTYPE_ISIS_TLV, reach);
              return ISIS_WARNING;
            }

          /* Skip Sub-TLVs for now */
          pnt += subtlv_len;
          length -= subtlv_len;
        }
      listnode_add(reach_list, reach);
    }

  if (length)
    {
      zlog_warn("ISIS-TLV: (MT) IPv6 reachability TLV has trailing data");
      return ISIS_WARNING;
    }

  return ISIS_OK;
}

/*
 * Parses the tlvs found in the variant length part of the PDU.
 * Caller tells with flags in "expected" which TLV's it is interested in.
 */
int
parse_tlvs (char *areatag, u_char * stream, int size, u_int32_t * expected,
	    u_int32_t * found, struct tlvs *tlvs, u_int32_t *auth_tlv_offset)
{
  u_char type, length;
  struct lan_neigh *lan_nei;
  struct area_addr *area_addr;
  struct is_neigh *is_nei;
  struct es_neigh *es_nei;
  struct lsp_entry *lsp_entry;
  struct in_addr *ipv4_addr;
  struct ipv4_reachability *ipv4_reach;
  struct in6_addr *ipv6_addr;
  int value_len, retval = ISIS_OK;
  u_char *start = stream, *pnt = stream;

  *found = 0;
  memset (tlvs, 0, sizeof (struct tlvs));

  while (pnt < stream + size - 2)
    {
      type = *pnt;
      length = *(pnt + 1);
      pnt += 2;
      value_len = 0;
      if (pnt + length > stream + size)
	{
	  zlog_warn ("ISIS-TLV (%s): TLV (type %d, length %d) exceeds packet "
		     "boundaries", areatag, type, length);
	  retval = ISIS_WARNING;
	  break;
	}
      switch (type)
	{
	case AREA_ADDRESSES:
	  /* +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |                        Address Length                         | 
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |                         Area Address                          | 
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * :                                                               :
	   */
	  *found |= TLVFLAG_AREA_ADDRS;
#ifdef EXTREME_TLV_DEBUG
	  zlog_debug ("TLV Area Adresses len %d", length);
#endif /* EXTREME_TLV_DEBUG */
	  if (*expected & TLVFLAG_AREA_ADDRS)
	    {
	      while (length > value_len)
		{
		  area_addr = (struct area_addr *) pnt;
		  value_len += area_addr->addr_len + 1;
		  pnt += area_addr->addr_len + 1;
		  if (!tlvs->area_addrs)
		    tlvs->area_addrs = list_new ();
		  listnode_add (tlvs->area_addrs, area_addr);
		}
	    }
	  else
	    {
	      pnt += length;
	    }
	  break;

	case IS_NEIGHBOURS:
	  *found |= TLVFLAG_IS_NEIGHS;
#ifdef EXTREME_TLV_DEBUG
	  zlog_debug ("ISIS-TLV (%s): IS Neighbours length %d",
		      areatag, length);
#endif /* EXTREME_TLV_DEBUG */
	  if (TLVFLAG_IS_NEIGHS & *expected)
	    {
	      /* +-------+-------+-------+-------+-------+-------+-------+-------+
	       * |                        Virtual Flag                           | 
	       * +-------+-------+-------+-------+-------+-------+-------+-------+
	       */
	      pnt++;
	      value_len++;
	      /* +-------+-------+-------+-------+-------+-------+-------+-------+
	       * |   0   |  I/E  |               Default Metric                  | 
	       * +-------+-------+-------+-------+-------+-------+-------+-------+
	       * |   S   |  I/E  |               Delay Metric                    |
	       * +-------+-------+-------+-------+-------+-------+-------+-------+
	       * |   S   |  I/E  |               Expense Metric                  |
	       * +-------+-------+-------+-------+-------+-------+-------+-------+
	       * |   S   |  I/E  |               Error Metric                    |
	       * +-------+-------+-------+-------+-------+-------+-------+-------+
	       * |                        Neighbour ID                           |
	       * +---------------------------------------------------------------+
	       * :                                                               :
	       */
	      while (length > value_len)
		{
		  is_nei = (struct is_neigh *) pnt;
		  value_len += 4 + ISIS_SYS_ID_LEN + 1;
		  pnt += 4 + ISIS_SYS_ID_LEN + 1;
		  if (!tlvs->is_neighs)
		    tlvs->is_neighs = list_new ();
		  listnode_add (tlvs->is_neighs, is_nei);
		}
	    }
	  else
	    {
	      pnt += length;
	    }
	  break;

	case TE_IS_NEIGHBOURS:
	  *found |= TLVFLAG_TE_IS_NEIGHS;
#ifdef EXTREME_TLV_DEBUG
	  zlog_debug ("ISIS-TLV (%s): Extended IS Neighbours length %d",
		     areatag, length);
#endif /* EXTREME_TLV_DEBUG */
	  if (TLVFLAG_TE_IS_NEIGHS & *expected)
	    retval = parse_mt_is_neighs(tlvs, false, length, pnt);
	  pnt += length;
	  break;

	case MT_IS_NEIGHBOURS:
	  *found |= TLVFLAG_TE_IS_NEIGHS;
#ifdef EXTREME_TLV_DEBUG
	  zlog_debug ("ISIS-TLV (%s): MT IS Neighbours length %d",
	              areatag, length);
#endif
	  if (TLVFLAG_TE_IS_NEIGHS & *expected)
	    retval = parse_mt_is_neighs(tlvs, true, length, pnt);
	  pnt += length;
	  break;

	case ES_NEIGHBOURS:
	  /* +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |   0   |  I/E  |               Default Metric                  | 
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |   S   |  I/E  |               Delay Metric                    |
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |   S   |  I/E  |               Expense Metric                  |
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |   S   |  I/E  |               Error Metric                    |
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |                        Neighbour ID                           |
	   * +---------------------------------------------------------------+
	   * |                        Neighbour ID                           |
	   * +---------------------------------------------------------------+
	   * :                                                               :
	   */
#ifdef EXTREME_TLV_DEBUG
	  zlog_debug ("ISIS-TLV (%s): ES Neighbours length %d",
		     areatag, length);
#endif /* EXTREME_TLV_DEBUG */
	  *found |= TLVFLAG_ES_NEIGHS;
	  if (*expected & TLVFLAG_ES_NEIGHS)
	    {
	      es_nei = (struct es_neigh *) pnt;
	      value_len += 4;
	      pnt += 4;
	      while (length > value_len)
		{
		  /* FIXME FIXME FIXME - add to the list */
		  /*          sys_id->id = pnt; */
		  value_len += ISIS_SYS_ID_LEN;
		  pnt += ISIS_SYS_ID_LEN;
		  /*  if (!es_nei->neigh_ids) es_nei->neigh_ids = sysid; */
		}
	      if (!tlvs->es_neighs)
		tlvs->es_neighs = list_new ();
	      listnode_add (tlvs->es_neighs, es_nei);
	    }
	  else
	    {
	      pnt += length;
	    }
	  break;

	case LAN_NEIGHBOURS:
	  /* +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |                        LAN Address                            | 
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * :                                                               :
	   */
	  *found |= TLVFLAG_LAN_NEIGHS;
#ifdef EXTREME_TLV_DEBUG
	  zlog_debug ("ISIS-TLV (%s): LAN Neigbours length %d",
		      areatag, length);
#endif /* EXTREME_TLV_DEBUG */
	  if (TLVFLAG_LAN_NEIGHS & *expected)
	    {
	      while (length > value_len)
		{
		  lan_nei = (struct lan_neigh *) pnt;
		  if (!tlvs->lan_neighs)
		    tlvs->lan_neighs = list_new ();
		  listnode_add (tlvs->lan_neighs, lan_nei);
		  value_len += ETH_ALEN;
		  pnt += ETH_ALEN;
		}
	    }
	  else
	    {
	      pnt += length;
	    }
	  break;

	case PADDING:
#ifdef EXTREME_TLV_DEBUG
	  zlog_debug ("TLV padding %d", length);
#endif /* EXTREME_TLV_DEBUG */
	  pnt += length;
	  break;

	case LSP_ENTRIES:
	  /* +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |                     Remaining Lifetime                        | 2
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |                         LSP ID                                | id+2
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |                   LSP Sequence Number                         | 4
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |                        Checksum                               | 2
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   */
#ifdef EXTREME_TLV_DEBUG
	  zlog_debug ("ISIS-TLV (%s): LSP Entries length %d", areatag, length);
#endif /* EXTREME_TLV_DEBUG */
	  *found |= TLVFLAG_LSP_ENTRIES;
	  if (TLVFLAG_LSP_ENTRIES & *expected)
	    {
	      while (length > value_len)
		{
		  lsp_entry = (struct lsp_entry *) pnt;
		  value_len += 10 + ISIS_SYS_ID_LEN;
		  pnt += 10 + ISIS_SYS_ID_LEN;
		  if (!tlvs->lsp_entries)
		    tlvs->lsp_entries = list_new ();
		  listnode_add (tlvs->lsp_entries, lsp_entry);
		}
	    }
	  else
	    {
	      pnt += length;
	    }
	  break;

	case CHECKSUM:
	  /* +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |                   16 bit fletcher CHECKSUM                    |
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * :                                                               :
	   */
	  *found |= TLVFLAG_CHECKSUM;
#ifdef EXTREME_TLV_DEBUG
	  zlog_debug ("ISIS-TLV (%s): Checksum length %d", areatag, length);
#endif /* EXTREME_TLV_DEBUG */
	  if (*expected & TLVFLAG_CHECKSUM)
	    {
	      tlvs->checksum = (struct checksum *) pnt;
	    }
	  pnt += length;
	  break;

	case PROTOCOLS_SUPPORTED:
	  /* +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |                       NLPID                                   |
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * :                                                               :
	   */
	  *found |= TLVFLAG_NLPID;
#ifdef EXTREME_TLV_DEBUG
	  zlog_debug ("ISIS-TLV (%s): Protocols Supported length %d",
		      areatag, length);
#endif /* EXTREME_TLV_DEBUG */
	  if (*expected & TLVFLAG_NLPID)
	    {
	      tlvs->nlpids = (struct nlpids *) (pnt - 1);
	    }
	  pnt += length;
	  break;

	case IPV4_ADDR:
	  /* +-------+-------+-------+-------+-------+-------+-------+-------+
	   * +                 IP version 4 address                          + 4
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * :                                                               :
	   */
	  *found |= TLVFLAG_IPV4_ADDR;
#ifdef EXTREME_TLV_DEBUG
	  zlog_debug ("ISIS-TLV (%s): IPv4 Address length %d",
		      areatag, length);
#endif /* EXTREME_TLV_DEBUG */
	  if (*expected & TLVFLAG_IPV4_ADDR)
	    {
	      while (length > value_len)
		{
		  ipv4_addr = (struct in_addr *) pnt;
#ifdef EXTREME_TLV_DEBUG
		  zlog_debug ("ISIS-TLV (%s) : IP ADDR %s, pnt %p", areatag,
			      inet_ntoa (*ipv4_addr), pnt);
#endif /* EXTREME_TLV_DEBUG */
		  if (!tlvs->ipv4_addrs)
		    tlvs->ipv4_addrs = list_new ();
		  listnode_add (tlvs->ipv4_addrs, ipv4_addr);
		  value_len += 4;
		  pnt += 4;
		}
	    }
	  else
	    {
	      pnt += length;
	    }
	  break;

	case AUTH_INFO:
	  *found |= TLVFLAG_AUTH_INFO;
#ifdef EXTREME_TLV_DEBUG
	  zlog_debug ("ISIS-TLV (%s): IS-IS Authentication Information",
		      areatag);
#endif
	  if (*expected & TLVFLAG_AUTH_INFO)
	    {
	      tlvs->auth_info.type = *pnt;
              if (length == 0)
                {
                  zlog_warn ("ISIS-TLV (%s): TLV (type %d, length %d) "
                             "incorrect.", areatag, type, length);
                  return ISIS_WARNING;
                }
              --length;
	      tlvs->auth_info.len = length;
	      pnt++;
	      memcpy (tlvs->auth_info.passwd, pnt, length);
              /* Return the authentication tlv pos for later computation
               * of MD5 (RFC 5304, 2)
               */
              if (auth_tlv_offset)
                *auth_tlv_offset += (pnt - start - 3);
              pnt += length;
	    }
	  else
	    {
	      pnt += length;
	    }
	  break;

	case DYNAMIC_HOSTNAME:
	  *found |= TLVFLAG_DYN_HOSTNAME;
#ifdef EXTREME_TLV_DEBUG
	  zlog_debug ("ISIS-TLV (%s): Dynamic Hostname length %d",
		      areatag, length);
#endif /* EXTREME_TLV_DEBUG */
	  if (*expected & TLVFLAG_DYN_HOSTNAME)
	    {
	      /* the length is also included in the pointed struct */
	      tlvs->hostname = (struct hostname *) (pnt - 1);
	    }
	  pnt += length;
	  break;

	case TE_ROUTER_ID:
	  /* +---------------------------------------------------------------+
	   * +                         Router ID                             + 4
	   * +---------------------------------------------------------------+
	   */
	  *found |= TLVFLAG_TE_ROUTER_ID;
#ifdef EXTREME_TLV_DEBUG
	  zlog_debug ("ISIS-TLV (%s): TE Router ID %d", areatag, length);
#endif /* EXTREME_TLV_DEBUG */
	  if (*expected & TLVFLAG_TE_ROUTER_ID)
	    tlvs->router_id = (struct te_router_id *) (pnt);
	  pnt += length;
	  break;

	case IPV4_INT_REACHABILITY:
	  /* +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |   0   |  I/E  |               Default Metric                  | 1
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |   S   |  I/E  |               Delay Metric                    | 1
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |   S   |  I/E  |               Expense Metric                  | 1
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |   S   |  I/E  |               Error Metric                    | 1
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |                        ip address                             | 4
	   * +---------------------------------------------------------------+
	   * |                        address mask                           | 4
	   * +---------------------------------------------------------------+
	   * :                                                               :
	   */
	  *found |= TLVFLAG_IPV4_INT_REACHABILITY;
#ifdef EXTREME_TLV_DEBUG
	  zlog_debug ("ISIS-TLV (%s): IPv4 internal Reachability length %d",
		      areatag, length);
#endif /* EXTREME_TLV_DEBUG */
	  if (*expected & TLVFLAG_IPV4_INT_REACHABILITY)
	    {
	      while (length > value_len)
		{
		  ipv4_reach = (struct ipv4_reachability *) pnt;
		  if (!tlvs->ipv4_int_reachs)
		    tlvs->ipv4_int_reachs = list_new ();
		  listnode_add (tlvs->ipv4_int_reachs, ipv4_reach);
		  value_len += 12;
		  pnt += 12;
		}
	    }
	  else
	    {
	      pnt += length;
	    }
	  break;

	case IPV4_EXT_REACHABILITY:
	  /* +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |   0   |  I/E  |               Default Metric                  | 1
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |   S   |  I/E  |               Delay Metric                    | 1
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |   S   |  I/E  |               Expense Metric                  | 1
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |   S   |  I/E  |               Error Metric                    | 1
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |                        ip address                             | 4
	   * +---------------------------------------------------------------+
	   * |                        address mask                           | 4
	   * +---------------------------------------------------------------+
	   * :                                                               :
	   */
	  *found |= TLVFLAG_IPV4_EXT_REACHABILITY;
#ifdef EXTREME_TLV_DEBUG
	  zlog_debug ("ISIS-TLV (%s): IPv4 external Reachability length %d",
		      areatag, length);
#endif /* EXTREME_TLV_DEBUG */
	  if (*expected & TLVFLAG_IPV4_EXT_REACHABILITY)
	    {
	      while (length > value_len)
		{
		  ipv4_reach = (struct ipv4_reachability *) pnt;
		  if (!tlvs->ipv4_ext_reachs)
		    tlvs->ipv4_ext_reachs = list_new ();
		  listnode_add (tlvs->ipv4_ext_reachs, ipv4_reach);
		  value_len += 12;
		  pnt += 12;
		}
	    }
	  else
	    {
	      pnt += length;
	    }
	  break;

	case TE_IPV4_REACHABILITY:
	  *found |= TLVFLAG_TE_IPV4_REACHABILITY;
#ifdef EXTREME_TLV_DEBUG
	  zlog_debug ("ISIS-TLV (%s): IPv4 extended Reachability length %d",
	              areatag, length);
#endif /* EXTREME_TLV_DEBUG */
	  if (*expected & TLVFLAG_TE_IPV4_REACHABILITY)
	    retval = parse_mt_ipv4_reachs(tlvs, false, length, pnt);
	  pnt += length;
	  break;
	case MT_IPV4_REACHABILITY:
	  *found |= TLVFLAG_TE_IPV4_REACHABILITY;
#ifdef EXTREME_TLV_DEBUG
	  zlog_debug ("ISIS-TLV (%s): IPv4 MT Reachability length %d",
	              areatag, length);
#endif /* EXTREME_TLV_DEBUG */
	  if (*expected & TLVFLAG_TE_IPV4_REACHABILITY)
	    retval = parse_mt_ipv4_reachs(tlvs, true, length, pnt);
	  pnt += length;
	  break;
	case IPV6_ADDR:
	  /* +-------+-------+-------+-------+-------+-------+-------+-------+
	   * +                 IP version 6 address                          + 16
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * :                                                               :
	   */
	  *found |= TLVFLAG_IPV6_ADDR;
#ifdef EXTREME_TLV_DEBUG
	  zlog_debug ("ISIS-TLV (%s): IPv6 Address length %d",
		      areatag, length);
#endif /* EXTREME_TLV_DEBUG */
	  if (*expected & TLVFLAG_IPV6_ADDR)
	    {
	      while (length > value_len)
		{
		  ipv6_addr = (struct in6_addr *) pnt;
		  if (!tlvs->ipv6_addrs)
		    tlvs->ipv6_addrs = list_new ();
		  listnode_add (tlvs->ipv6_addrs, ipv6_addr);
		  value_len += 16;
		  pnt += 16;
		}
	    }
	  else
	    {
	      pnt += length;
	    }
	  break;

	case IPV6_REACHABILITY:
	  *found |= TLVFLAG_IPV6_REACHABILITY;
#ifdef EXTREME_TLV_DEBUG
	  zlog_debug ("ISIS-TLV (%s): IPv6 Reachability length %d",
	              areatag, length);
#endif /* EXTREME_TLV_DEBUG */
	  if (*expected & TLVFLAG_IPV6_REACHABILITY)
	    retval = parse_mt_ipv6_reachs(tlvs, false, length, pnt);
	  pnt += length;
	  break;
	case MT_IPV6_REACHABILITY:
	  *found |= TLVFLAG_IPV6_REACHABILITY;
#ifdef EXTREME_TLV_DEBUG
	  zlog_debug ("ISIS-TLV (%s): IPv6 Reachability length %d",
	              areatag, length);
#endif /* EXTREME_TLV_DEBUG */
	  if (*expected & TLVFLAG_IPV6_REACHABILITY)
	    retval = parse_mt_ipv6_reachs(tlvs, true, length, pnt);
	  pnt += length;
	  break;
	case WAY3_HELLO:
	  /* +---------------------------------------------------------------+
	   * |                  Adjacency state                              | 1
	   * +---------------------------------------------------------------+
	   * |                  Extended Local Circuit ID                    | 4
	   * +---------------------------------------------------------------+
	   * |                  Neighbor System ID (If known)                | 0-8
	   *                                      (probably 6)
	   * +---------------------------------------------------------------+
	   * |                  Neighbor Local Circuit ID (If known)         | 4
	   * +---------------------------------------------------------------+
	   */
	  *found |= TLVFLAG_3WAY_HELLO;
	  if (*expected & TLVFLAG_3WAY_HELLO)
	    {
	      while (length > value_len)
		{
		  /* FIXME: make this work */
/*           Adjacency State (one octet):
              0 = Up
              1 = Initializing
              2 = Down
            Extended Local Circuit ID (four octets)
            Neighbor System ID if known (zero to eight octets)
            Neighbor Extended Local Circuit ID (four octets, if Neighbor
              System ID is present) */
		  pnt += length;
		  value_len += length;
		}
	    }
	  else
	    {
	      pnt += length;
	    }

	  break;
	case GRACEFUL_RESTART:
	  /* +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |         Reserved                      |  SA   |  RA   |  RR   | 1
	   * +-------+-------+-------+-------+-------+-------+-------+-------+
	   * |                          Remaining Time                       | 2
	   * +---------------------------------------------------------------+
	   * |                Restarting Neighbor ID (If known)              | 0-8
	   * +---------------------------------------------------------------+
	   */
	  *found |= TLVFLAG_GRACEFUL_RESTART;
	  if (*expected & TLVFLAG_GRACEFUL_RESTART)
	    {
	      /* FIXME: make this work */
	    }
	  pnt += length;
	  break;

	case MT_ROUTER_INFORMATION:
	  *found |= TLVFLAG_MT_ROUTER_INFORMATION;
	  if (*expected & TLVFLAG_MT_ROUTER_INFORMATION)
	    {
	      if (!tlvs->mt_router_info)
	        {
	          tlvs->mt_router_info = list_new();
	          tlvs->mt_router_info->del = free_tlv;
	        }
	      while (length > value_len)
	        {
	          uint16_t mt_info;
	          struct mt_router_info *info;

	          if (value_len + sizeof(mt_info) > length) {
	            zlog_warn("ISIS-TLV (%s): TLV 229 is truncated.", areatag);
	            pnt += length - value_len;
	            break;
	          }

	          memcpy(&mt_info, pnt, sizeof(mt_info));
	          pnt += sizeof(mt_info);
	          value_len += sizeof(mt_info);

	          mt_info = ntohs(mt_info);
	          info = XCALLOC(MTYPE_ISIS_TLV, sizeof(*info));
	          info->mtid = mt_info & ISIS_MT_MASK;
	          info->overload = mt_info & ISIS_MT_OL_MASK;
	          listnode_add(tlvs->mt_router_info, info);
	        }
	    }
	  else
	    {
	      pnt += length;
	    }
	  break;
	default:
	  zlog_warn ("ISIS-TLV (%s): unsupported TLV type %d, length %d",
		     areatag, type, length);

	  pnt += length;
	  break;
	}
      /* Abort Parsing if error occured */
      if (retval != ISIS_OK)
	return retval;
    }

  return retval;
}

int
add_tlv (u_char tag, u_char len, u_char * value, struct stream *stream)
{
  if ((stream_get_size (stream) - stream_get_endp (stream)) <
      (((unsigned)len) + 2))
    {
      zlog_warn ("No room for TLV of type %d "
                 "(total size %d available %d required %d)",
                 tag, (int)stream_get_size (stream),
                 (int)(stream_get_size (stream) - stream_get_endp (stream)),
                 len+2);
      return ISIS_WARNING;
    }

  stream_putc (stream, tag);	/* TAG */
  stream_putc (stream, len);	/* LENGTH */
  stream_put (stream, value, (int) len);	/* VALUE */

#ifdef EXTREME_DEBUG
  zlog_debug ("Added TLV %d len %d", tag, len);
#endif /* EXTREME DEBUG */
  return ISIS_OK;
}

int
tlv_add_mt_router_info (struct list *mt_router_info, struct stream *stream)
{
  struct listnode *node;
  struct mt_router_info *info;

  uint16_t value[127];
  uint16_t *pos = value;

  for (ALL_LIST_ELEMENTS_RO(mt_router_info, node, info))
    {
      uint16_t mt_info;

      mt_info = info->mtid;
      if (info->overload)
        mt_info |= ISIS_MT_OL_MASK;

      *pos = htons(mt_info);
      pos++;
    }

  return add_tlv(MT_ROUTER_INFORMATION, (pos - value) * sizeof(*pos),
                 (u_char*)value, stream);
}

int
tlv_add_area_addrs (struct list *area_addrs, struct stream *stream)
{
  struct listnode *node;
  struct area_addr *area_addr;

  u_char value[255];
  u_char *pos = value;

  for (ALL_LIST_ELEMENTS_RO (area_addrs, node, area_addr))
    {
      if (pos - value + area_addr->addr_len > 255)
	goto err;
      *pos = area_addr->addr_len;
      pos++;
      memcpy (pos, area_addr->area_addr, (int) area_addr->addr_len);
      pos += area_addr->addr_len;
    }

  return add_tlv (AREA_ADDRESSES, pos - value, value, stream);

err:
  zlog_warn ("tlv_add_area_addrs(): TLV longer than 255");
  return ISIS_WARNING;
}

int
tlv_add_is_neighs (struct list *is_neighs, struct stream *stream)
{
  struct listnode *node;
  struct is_neigh *is_neigh;
  u_char value[255];
  u_char *pos = value;
  int retval;

  *pos = 0;			/*is_neigh->virtual; */
  pos++;

  for (ALL_LIST_ELEMENTS_RO (is_neighs, node, is_neigh))
    {
      if (pos - value + IS_NEIGHBOURS_LEN > 255)
	{
	  retval = add_tlv (IS_NEIGHBOURS, pos - value, value, stream);
	  if (retval != ISIS_OK)
	    return retval;
	  pos = value;
	}
      *pos = is_neigh->metrics.metric_default;
      pos++;
      *pos = is_neigh->metrics.metric_delay;
      pos++;
      *pos = is_neigh->metrics.metric_expense;
      pos++;
      *pos = is_neigh->metrics.metric_error;
      pos++;
      memcpy (pos, is_neigh->neigh_id, ISIS_SYS_ID_LEN + 1);
      pos += ISIS_SYS_ID_LEN + 1;
    }

  return add_tlv (IS_NEIGHBOURS, pos - value, value, stream);
}

static size_t
max_tlv_size(struct stream *stream)
{
  size_t avail = stream_get_size (stream) - stream_get_endp(stream);

  if (avail < 2)
    return 0;

  if (avail < 257)
    return avail - 2;

  return 255;
}

unsigned int
tlv_add_te_is_neighs (struct list *te_is_neighs, struct stream *stream, void *arg)
{
  struct listnode *node;
  struct te_is_neigh *te_is_neigh;
  u_char value[255];
  u_char *pos = value;
  uint16_t mtid = arg ? *(uint16_t*)arg : ISIS_MT_IPV4_UNICAST;
  unsigned int consumed = 0;
  size_t max_size = max_tlv_size(stream);

  if (mtid != ISIS_MT_IPV4_UNICAST)
    {
      uint16_t mtid_conversion = ntohs(mtid);
      memcpy(pos, &mtid_conversion, sizeof(mtid_conversion));
      pos += sizeof(mtid_conversion);
    }

  for (ALL_LIST_ELEMENTS_RO (te_is_neighs, node, te_is_neigh))
    {
      /* FIXME: Check if Total SubTLVs size doesn't exceed 255 */
      if ((size_t)(pos - value) + IS_NEIGHBOURS_LEN + te_is_neigh->sub_tlvs_length > max_size)
        break;

      memcpy (pos, te_is_neigh->neigh_id, ISIS_SYS_ID_LEN + 1);
      pos += ISIS_SYS_ID_LEN + 1;
      memcpy (pos, te_is_neigh->te_metric, 3);
      pos += 3;
      /* Set the total size of Sub TLVs */
      *pos = te_is_neigh->sub_tlvs_length;
      pos++;
      /* Copy Sub TLVs if any */
      if (te_is_neigh->sub_tlvs_length > 0)
        {
          memcpy (pos, te_is_neigh->sub_tlvs, te_is_neigh->sub_tlvs_length);
          pos += te_is_neigh->sub_tlvs_length;
        }
      consumed++;
    }

  if (consumed)
    {
      int rv = add_tlv ((mtid != ISIS_MT_IPV4_UNICAST) ? MT_IS_NEIGHBOURS
                                                       : TE_IS_NEIGHBOURS,
                        pos - value, value, stream);
      assert(rv == ISIS_OK);
    }
  return consumed;
}

int
tlv_add_lan_neighs (struct list *lan_neighs, struct stream *stream)
{
  struct listnode *node;
  u_char *snpa;
  u_char value[255];
  u_char *pos = value;
  int retval;

  for (ALL_LIST_ELEMENTS_RO (lan_neighs, node, snpa))
    {
      if (pos - value + ETH_ALEN > 255)
	{
	  retval = add_tlv (LAN_NEIGHBOURS, pos - value, value, stream);
	  if (retval != ISIS_OK)
	    return retval;
	  pos = value;
	}
      memcpy (pos, snpa, ETH_ALEN);
      pos += ETH_ALEN;
    }

  return add_tlv (LAN_NEIGHBOURS, pos - value, value, stream);
}

int
tlv_add_nlpid (struct nlpids *nlpids, struct stream *stream)
{
  return add_tlv (PROTOCOLS_SUPPORTED, nlpids->count, nlpids->nlpids, stream);
}

int
tlv_add_authinfo (u_char auth_type, u_char auth_len, u_char *auth_value,
		  struct stream *stream)
{
  u_char value[255];
  u_char *pos = value;
  *pos++ = auth_type;
  memcpy (pos, auth_value, auth_len);

  return add_tlv (AUTH_INFO, auth_len + 1, value, stream);
}

int
tlv_add_checksum (struct checksum *checksum, struct stream *stream)
{
  u_char value[255];
  u_char *pos = value;
  return add_tlv (CHECKSUM, pos - value, value, stream);
}

int
tlv_add_ip_addrs (struct list *ip_addrs, struct stream *stream)
{
  struct listnode *node;
  struct prefix_ipv4 *ipv4;
  u_char value[255];
  u_char *pos = value;

  for (ALL_LIST_ELEMENTS_RO (ip_addrs, node, ipv4))
    {
      if (pos - value + IPV4_MAX_BYTELEN > 255)
	{
	  /* RFC 1195 s4.2: only one tuple of 63 allowed. */
	  zlog_warn ("tlv_add_ip_addrs(): cutting off at 63 IP addresses");
	  break;
	}
      *(u_int32_t *) pos = ipv4->prefix.s_addr;
      pos += IPV4_MAX_BYTELEN;
    }

  return add_tlv (IPV4_ADDR, pos - value, value, stream);
}

/* Used to add TLV containing just one IPv4 address - either IPv4 address TLV
 * (in case of LSP) or TE router ID TLV. */
int
tlv_add_in_addr (struct in_addr *addr, struct stream *stream, u_char tag)
{
  u_char value[255];
  u_char *pos = value;
  
  memcpy (pos, addr, IPV4_MAX_BYTELEN);
  pos += IPV4_MAX_BYTELEN;

  return add_tlv (tag, pos - value, value, stream);
}

int
tlv_add_dynamic_hostname (struct hostname *hostname, struct stream *stream)
{
  return add_tlv (DYNAMIC_HOSTNAME, hostname->namelen, hostname->name,
		  stream);
}

int
tlv_add_lsp_entries (struct list *lsps, struct stream *stream)
{
  struct listnode *node;
  struct isis_lsp *lsp;
  u_char value[255];
  u_char *pos = value;
  int retval;

  for (ALL_LIST_ELEMENTS_RO (lsps, node, lsp))
    {
      if (pos - value + LSP_ENTRIES_LEN > 255)
	{
	  retval = add_tlv (LSP_ENTRIES, pos - value, value, stream);
	  if (retval != ISIS_OK)
	    return retval;
	  pos = value;
	}
      *((u_int16_t *) pos) = lsp->lsp_header->rem_lifetime;
      pos += 2;
      memcpy (pos, lsp->lsp_header->lsp_id, ISIS_SYS_ID_LEN + 2);
      pos += ISIS_SYS_ID_LEN + 2;
      *((u_int32_t *) pos) = lsp->lsp_header->seq_num;
      pos += 4;
      *((u_int16_t *) pos) = lsp->lsp_header->checksum;
      pos += 2;
    }

  return add_tlv (LSP_ENTRIES, pos - value, value, stream);
}

static int
tlv_add_ipv4_reachs (u_char tag, struct list *ipv4_reachs, struct stream *stream)
{
  struct listnode *node;
  struct ipv4_reachability *reach;
  u_char value[255];
  u_char *pos = value;
  int retval;

  for (ALL_LIST_ELEMENTS_RO (ipv4_reachs, node, reach))
    {
      if (pos - value + IPV4_REACH_LEN > 255)
	{
	  retval =
	    add_tlv (tag, pos - value, value, stream);
	  if (retval != ISIS_OK)
	    return retval;
	  pos = value;
	}
      *pos = reach->metrics.metric_default;
      pos++;
      *pos = reach->metrics.metric_delay;
      pos++;
      *pos = reach->metrics.metric_expense;
      pos++;
      *pos = reach->metrics.metric_error;
      pos++;
      *(u_int32_t *) pos = reach->prefix.s_addr;
      pos += IPV4_MAX_BYTELEN;
      *(u_int32_t *) pos = reach->mask.s_addr;
      pos += IPV4_MAX_BYTELEN;
    }

  return add_tlv (tag, pos - value, value, stream);
}

int
tlv_add_ipv4_int_reachs (struct list *ipv4_reachs, struct stream *stream)
{
  return tlv_add_ipv4_reachs(IPV4_INT_REACHABILITY, ipv4_reachs, stream);
}

int
tlv_add_ipv4_ext_reachs (struct list *ipv4_reachs, struct stream *stream)
{
  return tlv_add_ipv4_reachs(IPV4_EXT_REACHABILITY, ipv4_reachs, stream);
}


unsigned int
tlv_add_te_ipv4_reachs (struct list *te_ipv4_reachs, struct stream *stream, void *arg)
{
  struct listnode *node;
  struct te_ipv4_reachability *te_reach;
  u_char value[255];
  u_char *pos = value;
  uint16_t mtid = arg ? *(uint16_t*)arg : ISIS_MT_IPV4_UNICAST;
  unsigned int consumed = 0;
  size_t max_size = max_tlv_size(stream);

  if (mtid != ISIS_MT_IPV4_UNICAST)
    {
      uint16_t mtid_conversion = ntohs(mtid);
      memcpy(pos, &mtid_conversion, sizeof(mtid_conversion));
      pos += sizeof(mtid_conversion);
    }

  for (ALL_LIST_ELEMENTS_RO (te_ipv4_reachs, node, te_reach))
    {
      unsigned char prefixlen = te_reach->control & 0x3F;

      if ((size_t)(pos - value) + 5 + PSIZE(prefixlen) > max_size)
        break;

      *(u_int32_t *) pos = te_reach->te_metric;
      pos += 4;
      *pos = te_reach->control;
      pos++;
      memcpy (pos, &te_reach->prefix_start, PSIZE(prefixlen));
      pos += PSIZE(prefixlen);
      consumed++;
    }

  if (consumed)
    {
      int rv = add_tlv ((mtid != ISIS_MT_IPV4_UNICAST) ? MT_IPV4_REACHABILITY
                                                       : TE_IPV4_REACHABILITY,
                        pos - value, value, stream);
      assert(rv == ISIS_OK);
    }

  return consumed;
}

int
tlv_add_ipv6_addrs (struct list *ipv6_addrs, struct stream *stream)
{
  struct listnode *node;
  struct prefix_ipv6 *ipv6;
  u_char value[255];
  u_char *pos = value;
  int retval;

  for (ALL_LIST_ELEMENTS_RO (ipv6_addrs, node, ipv6))
    {
      if (pos - value + IPV6_MAX_BYTELEN > 255)
	{
	  retval = add_tlv (IPV6_ADDR, pos - value, value, stream);
	  if (retval != ISIS_OK)
	    return retval;
	  pos = value;
	}
      memcpy (pos, ipv6->prefix.s6_addr, IPV6_MAX_BYTELEN);
      pos += IPV6_MAX_BYTELEN;
    }

  return add_tlv (IPV6_ADDR, pos - value, value, stream);
}

unsigned int
tlv_add_ipv6_reachs (struct list *ipv6_reachs, struct stream *stream, void *arg)
{
  struct listnode *node;
  struct ipv6_reachability *ip6reach;
  u_char value[255];
  u_char *pos = value;
  uint16_t mtid = arg ? *(uint16_t*)arg : ISIS_MT_IPV4_UNICAST;
  unsigned int consumed = 0;
  size_t max_size = max_tlv_size(stream);

  if (mtid != ISIS_MT_IPV4_UNICAST)
    {
      uint16_t mtid_conversion = ntohs(mtid);
      memcpy(pos, &mtid_conversion, sizeof(mtid_conversion));
      pos += sizeof(mtid_conversion);
    }

  for (ALL_LIST_ELEMENTS_RO (ipv6_reachs, node, ip6reach))
    {
      if ((size_t)(pos - value) + 6 + PSIZE(ip6reach->prefix_len) > max_size)
        break;

      *(uint32_t *)pos = ip6reach->metric;
      pos += 4;
      *pos = ip6reach->control_info;
      pos++;
      *pos = ip6reach->prefix_len;
      pos++;
      memcpy (pos, ip6reach->prefix, PSIZE(ip6reach->prefix_len));
      pos += PSIZE(ip6reach->prefix_len);
      consumed++;
    }

  if (consumed)
    {
      int rv = add_tlv ((mtid != ISIS_MT_IPV4_UNICAST) ? MT_IPV6_REACHABILITY
                                                       : IPV6_REACHABILITY,
                        pos - value, value, stream);
      assert(rv == ISIS_OK);
    }

  return consumed;
}

int
tlv_add_padding (struct stream *stream)
{
  int fullpads, i, left;

  /*
   * How many times can we add full padding ?
   */
  fullpads = (stream_get_size (stream) - stream_get_endp (stream)) / 257;
  for (i = 0; i < fullpads; i++)
    {
      if (!stream_putc (stream, (u_char) PADDING))	/* TAG */
	goto err;
      if (!stream_putc (stream, (u_char) 255))	/* LENGHT */
	goto err;
      stream_put (stream, NULL, 255);		/* zero padding */
    }

  left = stream_get_size (stream) - stream_get_endp (stream);

  if (left < 2)
    return ISIS_OK;

  if (left == 2)
    {
      stream_putc (stream, PADDING);
      stream_putc (stream, 0);
      return ISIS_OK;
    }

  stream_putc (stream, PADDING);
  stream_putc (stream, left - 2);
  stream_put (stream, NULL, left-2);

  return ISIS_OK;

err:
  zlog_warn ("tlv_add_padding(): no room for tlv");
  return ISIS_WARNING;
}
