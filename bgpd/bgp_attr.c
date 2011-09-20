/* BGP attributes management routines.
   Copyright (C) 1996, 97, 98, 1999 Kunihiro Ishiguro

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

#include <zebra.h>

#include "linklist.h"
#include "prefix.h"
#include "memory.h"
#include "vector.h"
#include "vty.h"
#include "stream.h"
#include "log.h"
#include "hash.h"
#include "jhash.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_ecommunity.h"

/* Attribute strings for logging. */
static const struct message attr_str [] = 
{
  { BGP_ATTR_ORIGIN,           "ORIGIN" }, 
  { BGP_ATTR_AS_PATH,          "AS_PATH" }, 
  { BGP_ATTR_NEXT_HOP,         "NEXT_HOP" }, 
  { BGP_ATTR_MULTI_EXIT_DISC,  "MULTI_EXIT_DISC" }, 
  { BGP_ATTR_LOCAL_PREF,       "LOCAL_PREF" }, 
  { BGP_ATTR_ATOMIC_AGGREGATE, "ATOMIC_AGGREGATE" }, 
  { BGP_ATTR_AGGREGATOR,       "AGGREGATOR" }, 
  { BGP_ATTR_COMMUNITIES,      "COMMUNITY" }, 
  { BGP_ATTR_ORIGINATOR_ID,    "ORIGINATOR_ID" },
  { BGP_ATTR_CLUSTER_LIST,     "CLUSTERLIST" }, 
  { BGP_ATTR_DPA,              "DPA" },
  { BGP_ATTR_ADVERTISER,       "ADVERTISER"} ,
  { BGP_ATTR_RCID_PATH,        "RCID_PATH" },
  { BGP_ATTR_MP_REACH_NLRI,    "MP_REACH_NLRI" },
  { BGP_ATTR_MP_UNREACH_NLRI,  "MP_UNREACH_NLRI" },
  { BGP_ATTR_EXT_COMMUNITIES,  "EXT_COMMUNITIES" },
  { BGP_ATTR_AS4_PATH,         "AS4_PATH" }, 
  { BGP_ATTR_AS4_AGGREGATOR,   "AS4_AGGREGATOR" }, 
  { BGP_ATTR_AS_PATHLIMIT,     "AS_PATHLIMIT" },
};
static const int attr_str_max = sizeof(attr_str)/sizeof(attr_str[0]);

static struct hash *cluster_hash;

static void *
cluster_hash_alloc (void *p)
{
  struct cluster_list * val = (struct cluster_list *) p;
  struct cluster_list *cluster;

  cluster = XMALLOC (MTYPE_CLUSTER, sizeof (struct cluster_list));
  cluster->length = val->length;

  if (cluster->length)
    {
      cluster->list = XMALLOC (MTYPE_CLUSTER_VAL, val->length);
      memcpy (cluster->list, val->list, val->length);
    }
  else
    cluster->list = NULL;

  cluster->refcnt = 0;

  return cluster;
}

/* Cluster list related functions. */
static struct cluster_list *
cluster_parse (struct in_addr * pnt, int length)
{
  struct cluster_list tmp;
  struct cluster_list *cluster;

  tmp.length = length;
  tmp.list = pnt;

  cluster = hash_get (cluster_hash, &tmp, cluster_hash_alloc);
  cluster->refcnt++;
  return cluster;
}

int
cluster_loop_check (struct cluster_list *cluster, struct in_addr originator)
{
  int i;
    
  for (i = 0; i < cluster->length / 4; i++)
    if (cluster->list[i].s_addr == originator.s_addr)
      return 1;
  return 0;
}

static unsigned int
cluster_hash_key_make (void *p)
{
  const struct cluster_list *cluster = p;

  return jhash(cluster->list, cluster->length, 0);
}

static int
cluster_hash_cmp (const void *p1, const void *p2)
{
  const struct cluster_list * cluster1 = p1;
  const struct cluster_list * cluster2 = p2;

  return (cluster1->length == cluster2->length &&
	  memcmp (cluster1->list, cluster2->list, cluster1->length) == 0);
}

static void
cluster_free (struct cluster_list *cluster)
{
  if (cluster->list)
    XFREE (MTYPE_CLUSTER_VAL, cluster->list);
  XFREE (MTYPE_CLUSTER, cluster);
}

#if 0
static struct cluster_list *
cluster_dup (struct cluster_list *cluster)
{
  struct cluster_list *new;

  new = XCALLOC (MTYPE_CLUSTER, sizeof (struct cluster_list));
  new->length = cluster->length;

  if (cluster->length)
    {
      new->list = XMALLOC (MTYPE_CLUSTER_VAL, cluster->length);
      memcpy (new->list, cluster->list, cluster->length);
    }
  else
    new->list = NULL;
  
  return new;
}
#endif

static struct cluster_list *
cluster_intern (struct cluster_list *cluster)
{
  struct cluster_list *find;

  find = hash_get (cluster_hash, cluster, cluster_hash_alloc);
  find->refcnt++;

  return find;
}

void
cluster_unintern (struct cluster_list *cluster)
{
  struct cluster_list *ret;

  if (cluster->refcnt)
    cluster->refcnt--;

  if (cluster->refcnt == 0)
    {
      ret = hash_release (cluster_hash, cluster);
      cluster_free (cluster);
    }
}

static void
cluster_init (void)
{
  cluster_hash = hash_create (cluster_hash_key_make, cluster_hash_cmp);
}

static void
cluster_finish (void)
{
  hash_free (cluster_hash);
  cluster_hash = NULL;
}

/* Unknown transit attribute. */
static struct hash *transit_hash;

static void
transit_free (struct transit *transit)
{
  if (transit->val)
    XFREE (MTYPE_TRANSIT_VAL, transit->val);
  XFREE (MTYPE_TRANSIT, transit);
}


static void *
transit_hash_alloc (void *p)
{
  /* Transit structure is already allocated.  */
  return p;
}

static struct transit *
transit_intern (struct transit *transit)
{
  struct transit *find;

  find = hash_get (transit_hash, transit, transit_hash_alloc);
  if (find != transit)
    transit_free (transit);
  find->refcnt++;

  return find;
}

void
transit_unintern (struct transit *transit)
{
  struct transit *ret;

  if (transit->refcnt)
    transit->refcnt--;

  if (transit->refcnt == 0)
    {
      ret = hash_release (transit_hash, transit);
      transit_free (transit);
    }
}

static unsigned int
transit_hash_key_make (void *p)
{
  const struct transit * transit = p;

  return jhash(transit->val, transit->length, 0);
}

static int
transit_hash_cmp (const void *p1, const void *p2)
{
  const struct transit * transit1 = p1;
  const struct transit * transit2 = p2;

  return (transit1->length == transit2->length &&
	  memcmp (transit1->val, transit2->val, transit1->length) == 0);
}

static void
transit_init (void)
{
  transit_hash = hash_create (transit_hash_key_make, transit_hash_cmp);
}

static void
transit_finish (void)
{
  hash_free (transit_hash);
  transit_hash = NULL;
}

/* Attribute hash routines. */
static struct hash *attrhash;

static struct attr_extra *
bgp_attr_extra_new (void)
{
  return XCALLOC (MTYPE_ATTR_EXTRA, sizeof (struct attr_extra));
}

void
bgp_attr_extra_free (struct attr *attr)
{
  if (attr->extra)
    {
      XFREE (MTYPE_ATTR_EXTRA, attr->extra);
      attr->extra = NULL;
    }
}

struct attr_extra *
bgp_attr_extra_get (struct attr *attr)
{
  if (!attr->extra)
    attr->extra = bgp_attr_extra_new();
  return attr->extra;
}

/* Shallow copy of an attribute
 * Though, not so shallow that it doesn't copy the contents
 * of the attr_extra pointed to by 'extra'
 */
void
bgp_attr_dup (struct attr *new, struct attr *orig)
{
  *new = *orig;
  if (orig->extra)
    {
      new->extra = bgp_attr_extra_new();
      *new->extra = *orig->extra;
    }
}

unsigned long int
attr_count (void)
{
  return attrhash->count;
}

unsigned long int
attr_unknown_count (void)
{
  return transit_hash->count;
}

unsigned int
attrhash_key_make (void *p)
{
  const struct attr * attr = (struct attr *) p;
  uint32_t key = 0;
#define MIX(val)	key = jhash_1word(val, key)

  MIX(attr->origin);
  MIX(attr->nexthop.s_addr);
  MIX(attr->med);
  MIX(attr->local_pref);

  key += attr->origin;
  key += attr->nexthop.s_addr;
  key += attr->med;
  key += attr->local_pref;
  
  if (attr->extra)
    {
      MIX(attr->extra->aggregator_as);
      MIX(attr->extra->aggregator_addr.s_addr);
      MIX(attr->extra->weight);
      MIX(attr->extra->mp_nexthop_global_in.s_addr);
    }
  
  if (attr->aspath)
    MIX(aspath_key_make (attr->aspath));
  if (attr->community)
    MIX(community_hash_make (attr->community));
  
  if (attr->extra)
    {
      if (attr->extra->ecommunity)
        MIX(ecommunity_hash_make (attr->extra->ecommunity));
      if (attr->extra->cluster)
        MIX(cluster_hash_key_make (attr->extra->cluster));
      if (attr->extra->transit)
        MIX(transit_hash_key_make (attr->extra->transit));

#ifdef HAVE_IPV6
      MIX(attr->extra->mp_nexthop_len);
      key = jhash(attr->extra->mp_nexthop_global.s6_addr, 16, key);
      key = jhash(attr->extra->mp_nexthop_local.s6_addr, 16, key);
#endif /* HAVE_IPV6 */
    }

  return key;
}

int
attrhash_cmp (const void *p1, const void *p2)
{
  const struct attr * attr1 = p1;
  const struct attr * attr2 = p2;

  if (attr1->flag == attr2->flag
      && attr1->origin == attr2->origin
      && attr1->nexthop.s_addr == attr2->nexthop.s_addr
      && attr1->aspath == attr2->aspath
      && attr1->community == attr2->community
      && attr1->med == attr2->med
      && attr1->local_pref == attr2->local_pref)
    {
      const struct attr_extra *ae1 = attr1->extra;
      const struct attr_extra *ae2 = attr2->extra;
      
      if (ae1 && ae2
          && ae1->aggregator_as == ae2->aggregator_as
          && ae1->aggregator_addr.s_addr == ae2->aggregator_addr.s_addr
          && ae1->weight == ae2->weight
#ifdef HAVE_IPV6
          && ae1->mp_nexthop_len == ae2->mp_nexthop_len
          && IPV6_ADDR_SAME (&ae1->mp_nexthop_global, &ae2->mp_nexthop_global)
          && IPV6_ADDR_SAME (&ae1->mp_nexthop_local, &ae2->mp_nexthop_local)
#endif /* HAVE_IPV6 */
          && IPV4_ADDR_SAME (&ae1->mp_nexthop_global_in, &ae2->mp_nexthop_global_in)
          && ae1->ecommunity == ae2->ecommunity
          && ae1->cluster == ae2->cluster
          && ae1->transit == ae2->transit)
        return 1;
      else if (ae1 || ae2)
        return 0;
      /* neither attribute has extra attributes, so they're same */
      return 1;
    }
  else
    return 0;
}

static void
attrhash_init (void)
{
  attrhash = hash_create (attrhash_key_make, attrhash_cmp);
}

static void
attrhash_finish (void)
{
  hash_free (attrhash);
  attrhash = NULL;
}

static void
attr_show_all_iterator (struct hash_backet *backet, struct vty *vty)
{
  struct attr *attr = backet->data;

  vty_out (vty, "attr[%ld] nexthop %s%s", attr->refcnt, 
	   inet_ntoa (attr->nexthop), VTY_NEWLINE);
}

void
attr_show_all (struct vty *vty)
{
  hash_iterate (attrhash, 
		(void (*)(struct hash_backet *, void *))
		attr_show_all_iterator,
		vty);
}

static void *
bgp_attr_hash_alloc (void *p)
{
  struct attr * val = (struct attr *) p;
  struct attr *attr;

  attr = XMALLOC (MTYPE_ATTR, sizeof (struct attr));
  *attr = *val;
  if (val->extra)
    {
      attr->extra = bgp_attr_extra_new ();
      *attr->extra = *val->extra;
    }
  attr->refcnt = 0;
  return attr;
}

/* Internet argument attribute. */
struct attr *
bgp_attr_intern (struct attr *attr)
{
  struct attr *find;

  /* Intern referenced strucutre. */
  if (attr->aspath)
    {
      if (! attr->aspath->refcnt)
	attr->aspath = aspath_intern (attr->aspath);
      else
	attr->aspath->refcnt++;
    }
  if (attr->community)
    {
      if (! attr->community->refcnt)
	attr->community = community_intern (attr->community);
      else
	attr->community->refcnt++;
    }
  if (attr->extra)
    {
      struct attr_extra *attre = attr->extra;
      
      if (attre->ecommunity)
        {
          if (! attre->ecommunity->refcnt)
            attre->ecommunity = ecommunity_intern (attre->ecommunity);
          else
            attre->ecommunity->refcnt++;
          
        }
      if (attre->cluster)
        {
          if (! attre->cluster->refcnt)
            attre->cluster = cluster_intern (attre->cluster);
          else
            attre->cluster->refcnt++;
        }
      if (attre->transit)
        {
          if (! attre->transit->refcnt)
            attre->transit = transit_intern (attre->transit);
          else
            attre->transit->refcnt++;
        }
    }
  
  find = (struct attr *) hash_get (attrhash, attr, bgp_attr_hash_alloc);
  find->refcnt++;
  
  return find;
}


/* Make network statement's attribute. */
struct attr *
bgp_attr_default_set (struct attr *attr, u_char origin)
{
  memset (attr, 0, sizeof (struct attr));
  bgp_attr_extra_get (attr);
  
  attr->origin = origin;
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_ORIGIN);
  attr->aspath = aspath_empty ();
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_AS_PATH);
  attr->extra->weight = BGP_ATTR_DEFAULT_WEIGHT;
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_NEXT_HOP);
#ifdef HAVE_IPV6
  attr->extra->mp_nexthop_len = IPV6_MAX_BYTELEN;
#endif

  return attr;
}


/* Make network statement's attribute. */
struct attr *
bgp_attr_default_intern (u_char origin)
{
  struct attr attr;
  struct attr *new;
  struct attr_extra *attre;
  
  memset (&attr, 0, sizeof (struct attr));
  attre = bgp_attr_extra_get (&attr);
  
  bgp_attr_default_set(&attr, origin);

  new = bgp_attr_intern (&attr);
  bgp_attr_extra_free (&attr);
  
  aspath_unintern (&new->aspath);
  return new;
}

struct attr *
bgp_attr_aggregate_intern (struct bgp *bgp, u_char origin,
			   struct aspath *aspath,
			   struct community *community, int as_set)
{
  struct attr attr;
  struct attr *new;
  struct attr_extra *attre;

  memset (&attr, 0, sizeof (struct attr));
  attre = bgp_attr_extra_get (&attr);
  
  /* Origin attribute. */
  attr.origin = origin;
  attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_ORIGIN);

  /* AS path attribute. */
  if (aspath)
    attr.aspath = aspath_intern (aspath);
  else
    attr.aspath = aspath_empty ();
  attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_AS_PATH);

  /* Next hop attribute.  */
  attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_NEXT_HOP);

  if (community)
    {
      attr.community = community;
      attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_COMMUNITIES);
    }

  attre->weight = BGP_ATTR_DEFAULT_WEIGHT;
#ifdef HAVE_IPV6
  attre->mp_nexthop_len = IPV6_MAX_BYTELEN;
#endif
  if (! as_set)
    attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE);
  attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR);
  if (CHECK_FLAG (bgp->config, BGP_CONFIG_CONFEDERATION))
    attre->aggregator_as = bgp->confed_id;
  else
    attre->aggregator_as = bgp->as;
  attre->aggregator_addr = bgp->router_id;

  new = bgp_attr_intern (&attr);
  bgp_attr_extra_free (&attr);
  
  aspath_unintern (&new->aspath);
  return new;
}

/* Unintern just the sub-components of the attr, but not the attr */
void
bgp_attr_unintern_sub (struct attr *attr)
{
  /* aspath refcount shoud be decrement. */
  if (attr->aspath)
    aspath_unintern (&attr->aspath);
  UNSET_FLAG(attr->flag, BGP_ATTR_AS_PATH);
  
  if (attr->community)
    community_unintern (&attr->community);
  UNSET_FLAG(attr->flag, BGP_ATTR_COMMUNITIES);
  
  if (attr->extra)
    {
      if (attr->extra->ecommunity)
        ecommunity_unintern (&attr->extra->ecommunity);
      UNSET_FLAG(attr->flag, BGP_ATTR_EXT_COMMUNITIES);
      
      if (attr->extra->cluster)
        cluster_unintern (attr->extra->cluster);
      UNSET_FLAG(attr->flag, BGP_ATTR_CLUSTER_LIST);
      
      if (attr->extra->transit)
        transit_unintern (attr->extra->transit);
    }
}

/* Free bgp attribute and aspath. */
void
bgp_attr_unintern (struct attr **attr)
{
  struct attr *ret;
  struct attr tmp;
  
  /* Decrement attribute reference. */
  (*attr)->refcnt--;
  
  tmp = *(*attr);
  
  if ((*attr)->extra)
    {
      tmp.extra = bgp_attr_extra_new ();
      memcpy (tmp.extra, (*attr)->extra, sizeof (struct attr_extra));
    }
  
  /* If reference becomes zero then free attribute object. */
  if ((*attr)->refcnt == 0)
    {    
      ret = hash_release (attrhash, *attr);
      assert (ret != NULL);
      bgp_attr_extra_free (*attr);
      XFREE (MTYPE_ATTR, *attr);
      *attr = NULL;
    }

  bgp_attr_unintern_sub (&tmp);
}

void
bgp_attr_flush (struct attr *attr)
{
  if (attr->aspath && ! attr->aspath->refcnt)
    aspath_free (attr->aspath);
  if (attr->community && ! attr->community->refcnt)
    community_free (attr->community);
  if (attr->extra)
    {
      struct attr_extra *attre = attr->extra;

      if (attre->ecommunity && ! attre->ecommunity->refcnt)
        ecommunity_free (&attre->ecommunity);
      if (attre->cluster && ! attre->cluster->refcnt)
        cluster_free (attre->cluster);
      if (attre->transit && ! attre->transit->refcnt)
        transit_free (attre->transit);
    }
}

/* Implement draft-scudder-idr-optional-transitive behaviour and
 * avoid resetting sessions for malformed attributes which are
 * are partial/optional and hence where the error likely was not
 * introduced by the sending neighbour.
 */
static bgp_attr_parse_ret_t
bgp_attr_malformed (struct peer *peer, u_char type, u_char flag,
                    u_char subcode, u_char *startp, bgp_size_t length)
{
  /* Only relax error handling for eBGP peers */
  if (peer_sort (peer) != BGP_PEER_EBGP)
    {
      bgp_notify_send_with_data (peer, BGP_NOTIFY_UPDATE_ERR, subcode,
                                 startp, length);
      return BGP_ATTR_PARSE_ERROR;

    }
  
  switch (type) {
    /* where an optional attribute is inconsequential, e.g. it does not affect
     * route selection, and can be safely ignored then any such attributes
     * which are malformed should just be ignored and the route processed as
     * normal.
     */
    case BGP_ATTR_AS4_AGGREGATOR:
    case BGP_ATTR_AGGREGATOR:
    case BGP_ATTR_ATOMIC_AGGREGATE:
      return BGP_ATTR_PARSE_PROCEED;
    
    /* Core attributes, particularly ones which may influence route
     * selection should always cause session resets
     */
    case BGP_ATTR_ORIGIN:
    case BGP_ATTR_AS_PATH:
    case BGP_ATTR_NEXT_HOP:
    case BGP_ATTR_MULTI_EXIT_DISC:
    case BGP_ATTR_LOCAL_PREF:
    case BGP_ATTR_COMMUNITIES:
    case BGP_ATTR_ORIGINATOR_ID:
    case BGP_ATTR_CLUSTER_LIST:
    case BGP_ATTR_MP_REACH_NLRI:
    case BGP_ATTR_MP_UNREACH_NLRI:
    case BGP_ATTR_EXT_COMMUNITIES:
      bgp_notify_send_with_data (peer, BGP_NOTIFY_UPDATE_ERR, subcode,
                                 startp, length);
      return BGP_ATTR_PARSE_ERROR;
  }
  
  /* Partial optional attributes that are malformed should not cause
   * the whole session to be reset. Instead treat it as a withdrawal
   * of the routes, if possible.
   */
  if (CHECK_FLAG (flag, BGP_ATTR_FLAG_TRANS)
      && CHECK_FLAG (flag, BGP_ATTR_FLAG_OPTIONAL)
      && CHECK_FLAG (flag, BGP_ATTR_FLAG_PARTIAL))
    return BGP_ATTR_PARSE_WITHDRAW;
  
  /* default to reset */
  return BGP_ATTR_PARSE_ERROR;
}

/* Get origin attribute of the update message. */
static bgp_attr_parse_ret_t
bgp_attr_origin (struct peer *peer, bgp_size_t length, 
		 struct attr *attr, u_char flag, u_char *startp)
{
  bgp_size_t total;

  /* total is entire attribute length include Attribute Flags (1),
     Attribute Type code (1) and Attribute length (1 or 2).  */
  total = length + (CHECK_FLAG (flag, BGP_ATTR_FLAG_EXTLEN) ? 4 : 3);

  /* If any recognized attribute has Attribute Flags that conflict
     with the Attribute Type Code, then the Error Subcode is set to
     Attribute Flags Error.  The Data field contains the erroneous
     attribute (type, length and value). */
  if (flag != BGP_ATTR_FLAG_TRANS)
    {
      zlog (peer->log, LOG_ERR, 
	    "Origin attribute flag isn't transitive %d", flag);
      return bgp_attr_malformed (peer, BGP_ATTR_ORIGIN, flag,
                                 BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR,
                                 startp, total);
    }

  /* If any recognized attribute has Attribute Length that conflicts
     with the expected length (based on the attribute type code), then
     the Error Subcode is set to Attribute Length Error.  The Data
     field contains the erroneous attribute (type, length and
     value). */
  if (length != 1)
    {
      zlog (peer->log, LOG_ERR, "Origin attribute length is not one %d",
	    length);
      return bgp_attr_malformed (peer, BGP_ATTR_ORIGIN, flag,
                                 BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
                                 startp, total);
    }

  /* Fetch origin attribute. */
  attr->origin = stream_getc (BGP_INPUT (peer));

  /* If the ORIGIN attribute has an undefined value, then the Error
     Subcode is set to Invalid Origin Attribute.  The Data field
     contains the unrecognized attribute (type, length and value). */
  if ((attr->origin != BGP_ORIGIN_IGP)
      && (attr->origin != BGP_ORIGIN_EGP)
      && (attr->origin != BGP_ORIGIN_INCOMPLETE))
    {
      zlog (peer->log, LOG_ERR, "Origin attribute value is invalid %d",
	      attr->origin);
      return bgp_attr_malformed (peer, BGP_ATTR_ORIGIN, flag,
                                 BGP_NOTIFY_UPDATE_INVAL_ORIGIN,
                                 startp, total);
    }

  /* Set oring attribute flag. */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_ORIGIN);

  return 0;
}

/* Parse AS path information.  This function is wrapper of
   aspath_parse. */
static int
bgp_attr_aspath (struct peer *peer, bgp_size_t length, 
		 struct attr *attr, u_char flag, u_char *startp)
{
  bgp_size_t total;

  total = length + (CHECK_FLAG (flag, BGP_ATTR_FLAG_EXTLEN) ? 4 : 3);

  /* Flag check. */
  if (CHECK_FLAG (flag, BGP_ATTR_FLAG_OPTIONAL)
      || ! CHECK_FLAG (flag, BGP_ATTR_FLAG_TRANS))
    {
      zlog (peer->log, LOG_ERR, 
	    "As-Path attribute flag isn't transitive %d", flag);
      return bgp_attr_malformed (peer, BGP_ATTR_AS_PATH, flag,
                                 BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR,
                                 startp, total);
    }

  /*
   * peer with AS4 => will get 4Byte ASnums
   * otherwise, will get 16 Bit
   */
  attr->aspath = aspath_parse (peer->ibuf, length, 
                               CHECK_FLAG (peer->cap, PEER_CAP_AS4_RCV));

  /* In case of IBGP, length will be zero. */
  if (! attr->aspath)
    {
      zlog (peer->log, LOG_ERR,
            "Malformed AS path from %s, length is %d",
            peer->host, length);
      return bgp_attr_malformed (peer, BGP_ATTR_AS_PATH, flag,
                                 BGP_NOTIFY_UPDATE_MAL_AS_PATH,
                                 NULL, 0);
    }

  /* Set aspath attribute flag. */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_AS_PATH);

  return BGP_ATTR_PARSE_PROCEED;
}

static bgp_attr_parse_ret_t
bgp_attr_aspath_check (struct peer *peer, struct attr *attr, u_char flag)
{
  /* These checks were part of bgp_attr_aspath, but with
   * as4 we should to check aspath things when
   * aspath synthesizing with as4_path has already taken place.
   * Otherwise we check ASPATH and use the synthesized thing, and that is
   * not right.
   * So do the checks later, i.e. here
   */
  struct bgp *bgp = peer->bgp;
  struct aspath *aspath;

  bgp = peer->bgp;
    
  /* Confederation sanity check. */
  if ((peer_sort (peer) == BGP_PEER_CONFED && ! aspath_left_confed_check (attr->aspath)) ||
     (peer_sort (peer) == BGP_PEER_EBGP && aspath_confed_check (attr->aspath)))
    {
      zlog (peer->log, LOG_ERR, "Malformed AS path from %s", peer->host);
      return bgp_attr_malformed (peer, BGP_ATTR_AS_PATH, flag,
                                 BGP_NOTIFY_UPDATE_MAL_AS_PATH,
                                 NULL, 0);
    }

  /* First AS check for EBGP. */
  if (bgp != NULL && bgp_flag_check (bgp, BGP_FLAG_ENFORCE_FIRST_AS))
    {
      if (peer_sort (peer) == BGP_PEER_EBGP 
	  && ! aspath_firstas_check (attr->aspath, peer->as))
 	{
 	  zlog (peer->log, LOG_ERR,
 		"%s incorrect first AS (must be %u)", peer->host, peer->as);
          return bgp_attr_malformed (peer, BGP_ATTR_AS_PATH, flag,
                                     BGP_NOTIFY_UPDATE_MAL_AS_PATH,
                                     NULL, 0);
 	}
    }

  /* local-as prepend */
  if (peer->change_local_as &&
      ! CHECK_FLAG (peer->flags, PEER_FLAG_LOCAL_AS_NO_PREPEND))
    {
      aspath = aspath_dup (attr->aspath);
      aspath = aspath_add_seq (aspath, peer->change_local_as);
      aspath_unintern (&attr->aspath);
      attr->aspath = aspath_intern (aspath);
    }

  return BGP_ATTR_PARSE_PROCEED;
}

/* Parse AS4 path information.  This function is another wrapper of
   aspath_parse. */
static int
bgp_attr_as4_path (struct peer *peer, bgp_size_t length,
		 struct attr *attr, u_char flag, u_char *startp,
		 struct aspath **as4_path)
{
  bgp_size_t total;

  total = length + (CHECK_FLAG (flag, BGP_ATTR_FLAG_EXTLEN) ? 4 : 3);

  /* Flag check. */
  if (!CHECK_FLAG (flag, BGP_ATTR_FLAG_OPTIONAL)
      || !CHECK_FLAG (flag, BGP_ATTR_FLAG_TRANS))
    {
      zlog (peer->log, LOG_ERR, 
	    "As4-Path attribute flag isn't optional/transitive %d", flag);
      return bgp_attr_malformed (peer, BGP_ATTR_AS_PATH, flag,
                                 BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR,
                                 startp, total);
    }

  *as4_path = aspath_parse (peer->ibuf, length, 1);

  /* In case of IBGP, length will be zero. */
  if (!*as4_path)
    {
      zlog (peer->log, LOG_ERR,
            "Malformed AS4 path from %s, length is %d",
            peer->host, length);
      return bgp_attr_malformed (peer, BGP_ATTR_AS4_PATH, flag,
                                 BGP_NOTIFY_UPDATE_MAL_AS_PATH,
                                 NULL, 0);
    }

  /* Set aspath attribute flag. */
  if (as4_path)
    attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_AS4_PATH);

  return BGP_ATTR_PARSE_PROCEED;
}

/* Nexthop attribute. */
static bgp_attr_parse_ret_t
bgp_attr_nexthop (struct peer *peer, bgp_size_t length, 
		  struct attr *attr, u_char flag, u_char *startp)
{
  bgp_size_t total;

  total = length + (CHECK_FLAG (flag, BGP_ATTR_FLAG_EXTLEN) ? 4 : 3);

  /* Flag check. */
  if (CHECK_FLAG (flag, BGP_ATTR_FLAG_OPTIONAL)
      || ! CHECK_FLAG (flag, BGP_ATTR_FLAG_TRANS))
    {
      zlog (peer->log, LOG_ERR, 
	    "Origin attribute flag isn't transitive %d", flag);
      return bgp_attr_malformed (peer, BGP_ATTR_NEXT_HOP, flag,
                                 BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR,
                                 startp, total);
    }

  /* Check nexthop attribute length. */
  if (length != 4)
    {
      zlog (peer->log, LOG_ERR, "Nexthop attribute length isn't four [%d]",
	      length);

      return bgp_attr_malformed (peer, BGP_ATTR_NEXT_HOP, flag,
                                 BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
                                 startp, total);
    }

  attr->nexthop.s_addr = stream_get_ipv4 (peer->ibuf);
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_NEXT_HOP);

  return BGP_ATTR_PARSE_PROCEED;
}

/* MED atrribute. */
static bgp_attr_parse_ret_t
bgp_attr_med (struct peer *peer, bgp_size_t length, 
	      struct attr *attr, u_char flag, u_char *startp)
{
  bgp_size_t total;

  total = length + (CHECK_FLAG (flag, BGP_ATTR_FLAG_EXTLEN) ? 4 : 3);

  /* Flag checks. */
  if (! CHECK_FLAG (flag, BGP_ATTR_FLAG_OPTIONAL))
    {
      zlog (peer->log, LOG_ERR,
	    "MULTI_EXIT_DISC attribute must be flagged as \"optional\" (%u)", flag);
      bgp_notify_send_with_data (peer,
				 BGP_NOTIFY_UPDATE_ERR,
				 BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR,
				 startp, total);
      return -1;
    }
  if (CHECK_FLAG (flag, BGP_ATTR_FLAG_TRANS))
    {
      zlog (peer->log, LOG_ERR,
	    "MULTI_EXIT_DISC attribute must not be flagged as \"transitive\" (%u)", flag);
      bgp_notify_send_with_data (peer,
				 BGP_NOTIFY_UPDATE_ERR,
				 BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR,
				 startp, total);
      return -1;
    }
  if (CHECK_FLAG (flag, BGP_ATTR_FLAG_PARTIAL))
    {
      zlog (peer->log, LOG_ERR,
	    "MULTI_EXIT_DISC attribute must not be flagged as \"partial\" (%u)", flag);
      bgp_notify_send_with_data (peer,
				 BGP_NOTIFY_UPDATE_ERR,
				 BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR,
				 startp, total);
      return -1;
    }

  /* Length check. */
  if (length != 4)
    {
      zlog (peer->log, LOG_ERR, 
	    "MED attribute length isn't four [%d]", length);

      return bgp_attr_malformed (peer, BGP_ATTR_MULTI_EXIT_DISC, flag,
                                 BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
                                 startp, total);
    }

  attr->med = stream_getl (peer->ibuf);

  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC);

  return BGP_ATTR_PARSE_PROCEED;
}

/* Local preference attribute. */
static bgp_attr_parse_ret_t
bgp_attr_local_pref (struct peer *peer, bgp_size_t length, 
		     struct attr *attr, u_char flag, u_char *startp)
{
  bgp_size_t total;

  total = length + (CHECK_FLAG (flag, BGP_ATTR_FLAG_EXTLEN) ? 4 : 3);
  /* Flag checks. */
  if (CHECK_FLAG (flag, BGP_ATTR_FLAG_OPTIONAL))
    {
      zlog (peer->log, LOG_ERR,
	    "LOCAL_PREF attribute must be flagged as \"well-known\" (%u)", flag);
      bgp_notify_send_with_data (peer,
				 BGP_NOTIFY_UPDATE_ERR,
				 BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR,
				 startp, total);
      return -1;
    }
  if (! CHECK_FLAG (flag, BGP_ATTR_FLAG_TRANS))
    {
      zlog (peer->log, LOG_ERR,
	    "LOCAL_PREF attribute must be flagged as \"transitive\" (%u)", flag);
      bgp_notify_send_with_data (peer,
				 BGP_NOTIFY_UPDATE_ERR,
				 BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR,
				 startp, total);
      return -1;
    }

  /* If it is contained in an UPDATE message that is received from an
     external peer, then this attribute MUST be ignored by the
     receiving speaker. */
  if (peer_sort (peer) == BGP_PEER_EBGP)
    {
      stream_forward_getp (peer->ibuf, length);
      return BGP_ATTR_PARSE_PROCEED;
    }

  if (length == 4) 
    attr->local_pref = stream_getl (peer->ibuf);
  else 
    attr->local_pref = 0;

  /* Set atomic aggregate flag. */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF);

  return BGP_ATTR_PARSE_PROCEED;
}

/* Atomic aggregate. */
static int
bgp_attr_atomic (struct peer *peer, bgp_size_t length, 
		 struct attr *attr, u_char flag, u_char *startp)
{
  bgp_size_t total;

  total = length + (CHECK_FLAG (flag, BGP_ATTR_FLAG_EXTLEN) ? 4 : 3);
  /* Flag checks. */
  if (CHECK_FLAG (flag, BGP_ATTR_FLAG_OPTIONAL))
    {
      zlog (peer->log, LOG_ERR,
	    "ATOMIC_AGGREGATE attribute must not be flagged as \"optional\" (%u)", flag);
      bgp_notify_send_with_data (peer,
				 BGP_NOTIFY_UPDATE_ERR,
				 BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR,
				 startp, total);
      return -1;
    }
  if (! CHECK_FLAG (flag, BGP_ATTR_FLAG_TRANS))
    {
      zlog (peer->log, LOG_ERR,
	    "ATOMIC_AGGREGATE attribute must be flagged as \"transitive\" (%u)", flag);
      bgp_notify_send_with_data (peer,
				 BGP_NOTIFY_UPDATE_ERR,
				 BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR,
				 startp, total);
      return -1;
    }
  if (CHECK_FLAG (flag, BGP_ATTR_FLAG_PARTIAL))
    {
      zlog (peer->log, LOG_ERR,
	    "ATOMIC_AGGREGATE attribute must not be flagged as \"partial\" (%u)", flag);
      bgp_notify_send_with_data (peer,
				 BGP_NOTIFY_UPDATE_ERR,
				 BGP_NOTIFY_UPDATE_ATTR_FLAG_ERR,
				 startp, total);
      return -1;
    }

  /* Length check. */
  if (length != 0)
    {
      zlog (peer->log, LOG_ERR, "Bad atomic aggregate length %d", length);

      return bgp_attr_malformed (peer, BGP_ATTR_ATOMIC_AGGREGATE, flag,
                                 BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
                                 NULL, 0);
    }

  /* Set atomic aggregate flag. */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE);

  return BGP_ATTR_PARSE_PROCEED;
}

/* Aggregator attribute */
static int
bgp_attr_aggregator (struct peer *peer, bgp_size_t length,
		     struct attr *attr, u_char flag)
{
  int wantedlen = 6;
  struct attr_extra *attre = bgp_attr_extra_get (attr);
  
  /* peer with AS4 will send 4 Byte AS, peer without will send 2 Byte */
  if (CHECK_FLAG (peer->cap, PEER_CAP_AS4_RCV))
    wantedlen = 8;
  
  if (length != wantedlen)
    {
      zlog (peer->log, LOG_ERR, "Aggregator length is not %d [%d]", wantedlen, length);

      return bgp_attr_malformed (peer, BGP_ATTR_AGGREGATOR, flag,
                                 BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
                                 NULL, 0);
    }
  
  if ( CHECK_FLAG (peer->cap, PEER_CAP_AS4_RCV ) )
    attre->aggregator_as = stream_getl (peer->ibuf);
  else
    attre->aggregator_as = stream_getw (peer->ibuf);
  attre->aggregator_addr.s_addr = stream_get_ipv4 (peer->ibuf);

  /* Set atomic aggregate flag. */
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR);

  return BGP_ATTR_PARSE_PROCEED;
}

/* New Aggregator attribute */
static bgp_attr_parse_ret_t
bgp_attr_as4_aggregator (struct peer *peer, bgp_size_t length,
		     struct attr *attr, u_char flag, 
		     as_t *as4_aggregator_as,
		     struct in_addr *as4_aggregator_addr)
{
  if (length != 8)
    {
      zlog (peer->log, LOG_ERR, "New Aggregator length is not 8 [%d]", length);
      return bgp_attr_malformed (peer, BGP_ATTR_AS4_AGGREGATOR, flag,
                                 BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
                                 NULL, 0);
    }
  *as4_aggregator_as = stream_getl (peer->ibuf);
  as4_aggregator_addr->s_addr = stream_get_ipv4 (peer->ibuf);

  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_AS4_AGGREGATOR);

  return BGP_ATTR_PARSE_PROCEED;
}

/* Munge Aggregator and New-Aggregator, AS_PATH and NEW_AS_PATH.
 */
static bgp_attr_parse_ret_t
bgp_attr_munge_as4_attrs (struct peer *peer, struct attr *attr, u_char flag,
                          struct aspath *as4_path, as_t as4_aggregator,
                          struct in_addr *as4_aggregator_addr)
{
  int ignore_as4_path = 0;
  struct aspath *newpath;
  struct attr_extra *attre = attr->extra;
    
  if (CHECK_FLAG (peer->cap, PEER_CAP_AS4_RCV))
    {
      /* peer can do AS4, so we ignore AS4_PATH and AS4_AGGREGATOR
       * if given.
       * It is worth a warning though, because the peer really
       * should not send them
       */
      if (BGP_DEBUG(as4, AS4))
        {
          if (attr->flag & (ATTR_FLAG_BIT(BGP_ATTR_AS4_PATH)))
            zlog_debug ("[AS4] %s %s AS4_PATH",
                        peer->host, "AS4 capable peer, yet it sent");
          
          if (attr->flag & (ATTR_FLAG_BIT(BGP_ATTR_AS4_AGGREGATOR)))
            zlog_debug ("[AS4] %s %s AS4_AGGREGATOR",
                        peer->host, "AS4 capable peer, yet it sent");
        }
      
      return BGP_ATTR_PARSE_PROCEED;
    }
  
  if (attr->flag & (ATTR_FLAG_BIT (BGP_ATTR_AS4_PATH))
      && !(attr->flag & (ATTR_FLAG_BIT (BGP_ATTR_AS_PATH))))
    {
      /* Hu? This is not supposed to happen at all!
       * got as4_path and no aspath,
       *   This should already
       *   have been handled by 'well known attributes missing'
       *   But... yeah, paranoia
       * Take this as a "malformed attribute"
       */
      zlog (peer->log, LOG_ERR, 
            "%s BGP not AS4 capable peer sent AS4_PATH but"
            " no AS_PATH, cant do anything here", peer->host);
      return bgp_attr_malformed (peer, BGP_ATTR_AS_PATH, flag,
                                 BGP_NOTIFY_UPDATE_MAL_ATTR,
                                 NULL, 0);
    }

  /* We have a asn16 peer.  First, look for AS4_AGGREGATOR
   * because that may override AS4_PATH
   */
  if (attr->flag & (ATTR_FLAG_BIT (BGP_ATTR_AS4_AGGREGATOR) ) )
    {
      if (attr->flag & (ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR) ) )
        {
          assert (attre);
          
          /* received both.
           * if the as_number in aggregator is not AS_TRANS,
           *  then AS4_AGGREGATOR and AS4_PATH shall be ignored
           *        and the Aggregator shall be taken as 
           *        info on the aggregating node, and the AS_PATH
           *        shall be taken as the AS_PATH
           *  otherwise
           *        the Aggregator shall be ignored and the
           *        AS4_AGGREGATOR shall be taken as the
           *        Aggregating node and the AS_PATH is to be
           *        constructed "as in all other cases"
           */
          if (attre->aggregator_as != BGP_AS_TRANS)
            {
              /* ignore */
              if ( BGP_DEBUG(as4, AS4))
                zlog_debug ("[AS4] %s BGP not AS4 capable peer" 
                            " send AGGREGATOR != AS_TRANS and"
                            " AS4_AGGREGATOR, so ignore"
                            " AS4_AGGREGATOR and AS4_PATH", peer->host);
              ignore_as4_path = 1;
            }
          else
            {
              /* "New_aggregator shall be taken as aggregator" */
              attre->aggregator_as = as4_aggregator;
              attre->aggregator_addr.s_addr = as4_aggregator_addr->s_addr;
            }
        }
      else
        {
          /* We received a AS4_AGGREGATOR but no AGGREGATOR.
           * That is bogus - but reading the conditions
           * we have to handle AS4_AGGREGATOR as if it were
           * AGGREGATOR in that case
           */
          if ( BGP_DEBUG(as4, AS4))
            zlog_debug ("[AS4] %s BGP not AS4 capable peer send"
                        " AS4_AGGREGATOR but no AGGREGATOR, will take"
                        " it as if AGGREGATOR with AS_TRANS had been there", peer->host);
          (attre = bgp_attr_extra_get (attr))->aggregator_as = as4_aggregator;
          /* sweep it under the carpet and simulate a "good" AGGREGATOR */
          attr->flag |= (ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR));
        }
    }

  /* need to reconcile NEW_AS_PATH and AS_PATH */
  if (!ignore_as4_path && (attr->flag & (ATTR_FLAG_BIT( BGP_ATTR_AS4_PATH))))
    {
       newpath = aspath_reconcile_as4 (attr->aspath, as4_path);
       aspath_unintern (&attr->aspath);
       attr->aspath = aspath_intern (newpath);
    }
  return BGP_ATTR_PARSE_PROCEED;
}

/* Community attribute. */
static bgp_attr_parse_ret_t
bgp_attr_community (struct peer *peer, bgp_size_t length, 
		    struct attr *attr, u_char flag, u_char *startp)
{
  bgp_size_t total
    = length + (CHECK_FLAG (flag, BGP_ATTR_FLAG_EXTLEN) ? 4 : 3);
  
  if (length == 0)
    {
      attr->community = NULL;
      return BGP_ATTR_PARSE_PROCEED;
    }
  
  attr->community =
    community_parse ((u_int32_t *)stream_pnt (peer->ibuf), length);
  
  /* XXX: fix community_parse to use stream API and remove this */
  stream_forward_getp (peer->ibuf, length);

  if (!attr->community)
    return bgp_attr_malformed (peer, BGP_ATTR_COMMUNITIES, flag,
                               BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
                               startp, total);
  
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_COMMUNITIES);

  return BGP_ATTR_PARSE_PROCEED;
}

/* Originator ID attribute. */
static bgp_attr_parse_ret_t
bgp_attr_originator_id (struct peer *peer, bgp_size_t length, 
			struct attr *attr, u_char flag)
{
  if (length != 4)
    {
      zlog (peer->log, LOG_ERR, "Bad originator ID length %d", length);

      return bgp_attr_malformed (peer, BGP_ATTR_ORIGINATOR_ID, flag,
                                 BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
                                 NULL, 0);
    }

  (bgp_attr_extra_get (attr))->originator_id.s_addr 
    = stream_get_ipv4 (peer->ibuf);

  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_ORIGINATOR_ID);

  return BGP_ATTR_PARSE_PROCEED;
}

/* Cluster list attribute. */
static bgp_attr_parse_ret_t
bgp_attr_cluster_list (struct peer *peer, bgp_size_t length, 
		       struct attr *attr, u_char flag)
{
  /* Check length. */
  if (length % 4)
    {
      zlog (peer->log, LOG_ERR, "Bad cluster list length %d", length);

      return bgp_attr_malformed (peer, BGP_ATTR_CLUSTER_LIST, flag,
                                 BGP_NOTIFY_UPDATE_ATTR_LENG_ERR,
                                 NULL, 0);
    }

  (bgp_attr_extra_get (attr))->cluster 
    = cluster_parse ((struct in_addr *)stream_pnt (peer->ibuf), length);
  
  /* XXX: Fix cluster_parse to use stream API and then remove this */
  stream_forward_getp (peer->ibuf, length);

  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_CLUSTER_LIST);

  return BGP_ATTR_PARSE_PROCEED;
}

/* Multiprotocol reachability information parse. */
int
bgp_mp_reach_parse (struct peer *peer, bgp_size_t length, struct attr *attr,
		    struct bgp_nlri *mp_update)
{
  afi_t afi;
  safi_t safi;
  bgp_size_t nlri_len;
  size_t start;
  int ret;
  struct stream *s;
  struct attr_extra *attre = bgp_attr_extra_get(attr);
  
  /* Set end of packet. */
  s = BGP_INPUT(peer);
  start = stream_get_getp(s);
  
  /* safe to read statically sized header? */
#define BGP_MP_REACH_MIN_SIZE 5
#define LEN_LEFT	(length - (stream_get_getp(s) - start))
  if ((length > STREAM_READABLE(s)) || (length < BGP_MP_REACH_MIN_SIZE))
    {
      zlog_info ("%s: %s sent invalid length, %lu", 
		 __func__, peer->host, (unsigned long)length);
      return BGP_ATTR_PARSE_ERROR;
    }
  
  /* Load AFI, SAFI. */
  afi = stream_getw (s);
  safi = stream_getc (s);

  /* Get nexthop length. */
  attre->mp_nexthop_len = stream_getc (s);
  
  if (LEN_LEFT < attre->mp_nexthop_len)
    {
      zlog_info ("%s: %s, MP nexthop length, %u, goes past end of attribute", 
		 __func__, peer->host, attre->mp_nexthop_len);
      return BGP_ATTR_PARSE_ERROR;
    }
  
  /* Nexthop length check. */
  switch (attre->mp_nexthop_len)
    {
    case 4:
      stream_get (&attre->mp_nexthop_global_in, s, 4);
      /* Probably needed for RFC 2283 */
      if (attr->nexthop.s_addr == 0)
        memcpy(&attr->nexthop.s_addr, &attre->mp_nexthop_global_in, 4);
      break;
    case 12:
      {
	u_int32_t rd_high;
	u_int32_t rd_low;

	rd_high = stream_getl (s);
	rd_low = stream_getl (s);
	stream_get (&attre->mp_nexthop_global_in, s, 4);
      }
      break;
#ifdef HAVE_IPV6
    case 16:
      stream_get (&attre->mp_nexthop_global, s, 16);
      break;
    case 32:
      stream_get (&attre->mp_nexthop_global, s, 16);
      stream_get (&attre->mp_nexthop_local, s, 16);
      if (! IN6_IS_ADDR_LINKLOCAL (&attre->mp_nexthop_local))
	{
	  char buf1[INET6_ADDRSTRLEN];
	  char buf2[INET6_ADDRSTRLEN];

	  if (BGP_DEBUG (update, UPDATE_IN))
	    zlog_debug ("%s got two nexthop %s %s but second one is not a link-local nexthop", peer->host,
		       inet_ntop (AF_INET6, &attre->mp_nexthop_global,
				  buf1, INET6_ADDRSTRLEN),
		       inet_ntop (AF_INET6, &attre->mp_nexthop_local,
				  buf2, INET6_ADDRSTRLEN));

	  attre->mp_nexthop_len = 16;
	}
      break;
#endif /* HAVE_IPV6 */
    default:
      zlog_info ("%s: (%s) Wrong multiprotocol next hop length: %d", 
		 __func__, peer->host, attre->mp_nexthop_len);
      return BGP_ATTR_PARSE_ERROR;
    }

  if (!LEN_LEFT)
    {
      zlog_info ("%s: (%s) Failed to read SNPA and NLRI(s)",
                 __func__, peer->host);
      return BGP_ATTR_PARSE_ERROR;
    }
  
  {
    u_char val; 
    if ((val = stream_getc (s)))
    zlog_warn ("%s sent non-zero value, %u, for defunct SNPA-length field",
                peer->host, val);
  }
  
  /* must have nrli_len, what is left of the attribute */
  nlri_len = LEN_LEFT;
  if ((!nlri_len) || (nlri_len > STREAM_READABLE(s)))
    {
      zlog_info ("%s: (%s) Failed to read NLRI",
                 __func__, peer->host);
      return BGP_ATTR_PARSE_ERROR;
    }
 
  if (safi != BGP_SAFI_VPNV4)
    {
      ret = bgp_nlri_sanity_check (peer, afi, stream_pnt (s), nlri_len);
      if (ret < 0) 
        {
          zlog_info ("%s: (%s) NLRI doesn't pass sanity check",
                     __func__, peer->host);
	  return BGP_ATTR_PARSE_ERROR;
	}
    }

  mp_update->afi = afi;
  mp_update->safi = safi;
  mp_update->nlri = stream_pnt (s);
  mp_update->length = nlri_len;

  stream_forward_getp (s, nlri_len);

  return BGP_ATTR_PARSE_PROCEED;
#undef LEN_LEFT
}

/* Multiprotocol unreachable parse */
int
bgp_mp_unreach_parse (struct peer *peer, bgp_size_t length, 
		      struct bgp_nlri *mp_withdraw)
{
  struct stream *s;
  afi_t afi;
  safi_t safi;
  u_int16_t withdraw_len;
  int ret;

  s = peer->ibuf;
  
#define BGP_MP_UNREACH_MIN_SIZE 3
  if ((length > STREAM_READABLE(s)) || (length <  BGP_MP_UNREACH_MIN_SIZE))
    return BGP_ATTR_PARSE_ERROR;
  
  afi = stream_getw (s);
  safi = stream_getc (s);
  
  withdraw_len = length - BGP_MP_UNREACH_MIN_SIZE;

  if (safi != BGP_SAFI_VPNV4)
    {
      ret = bgp_nlri_sanity_check (peer, afi, stream_pnt (s), withdraw_len);
      if (ret < 0)
	return BGP_ATTR_PARSE_ERROR;
    }

  mp_withdraw->afi = afi;
  mp_withdraw->safi = safi;
  mp_withdraw->nlri = stream_pnt (s);
  mp_withdraw->length = withdraw_len;

  stream_forward_getp (s, withdraw_len);

  return BGP_ATTR_PARSE_PROCEED;
}

/* Extended Community attribute. */
static bgp_attr_parse_ret_t
bgp_attr_ext_communities (struct peer *peer, bgp_size_t length, 
			  struct attr *attr, u_char flag, u_char *startp)
{
  bgp_size_t total
    = length + (CHECK_FLAG (flag, BGP_ATTR_FLAG_EXTLEN) ? 4 : 3);
  
  if (length == 0)
    {
      if (attr->extra)
        attr->extra->ecommunity = NULL;
      /* Empty extcomm doesn't seem to be invalid per se */
      return BGP_ATTR_PARSE_PROCEED;
    }

  (bgp_attr_extra_get (attr))->ecommunity =
    ecommunity_parse ((u_int8_t *)stream_pnt (peer->ibuf), length);
  /* XXX: fix ecommunity_parse to use stream API */
  stream_forward_getp (peer->ibuf, length);
  
  if (!attr->extra->ecommunity)
    return bgp_attr_malformed (peer, BGP_ATTR_EXT_COMMUNITIES,
                               flag, BGP_NOTIFY_UPDATE_OPT_ATTR_ERR,
                               startp, total);
  
  attr->flag |= ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES);

  return BGP_ATTR_PARSE_PROCEED;
}

/* BGP unknown attribute treatment. */
static bgp_attr_parse_ret_t
bgp_attr_unknown (struct peer *peer, struct attr *attr, u_char flag,
		  u_char type, bgp_size_t length, u_char *startp)
{
  bgp_size_t total;
  struct transit *transit;
  struct attr_extra *attre;

  if (BGP_DEBUG (normal, NORMAL))
  zlog_debug ("%s Unknown attribute is received (type %d, length %d)",
	      peer->host, type, length);
  
  if (BGP_DEBUG (events, EVENTS))
    zlog (peer->log, LOG_DEBUG, 
	  "Unknown attribute type %d length %d is received", type, length);

  /* Forward read pointer of input stream. */
  stream_forward_getp (peer->ibuf, length);

  /* Adjest total length to include type and length. */
  total = length + (CHECK_FLAG (flag, BGP_ATTR_FLAG_EXTLEN) ? 4 : 3);

  /* If any of the mandatory well-known attributes are not recognized,
     then the Error Subcode is set to Unrecognized Well-known
     Attribute.  The Data field contains the unrecognized attribute
     (type, length and value). */
  if (!CHECK_FLAG (flag, BGP_ATTR_FLAG_OPTIONAL))
    {
      return bgp_attr_malformed (peer, type, flag,
                                 BGP_NOTIFY_UPDATE_UNREC_ATTR,
                                 startp, total);
    }

  /* Unrecognized non-transitive optional attributes must be quietly
     ignored and not passed along to other BGP peers. */
  if (! CHECK_FLAG (flag, BGP_ATTR_FLAG_TRANS))
    return BGP_ATTR_PARSE_PROCEED;

  /* If a path with recognized transitive optional attribute is
     accepted and passed along to other BGP peers and the Partial bit
     in the Attribute Flags octet is set to 1 by some previous AS, it
     is not set back to 0 by the current AS. */
  SET_FLAG (*startp, BGP_ATTR_FLAG_PARTIAL);

  /* Store transitive attribute to the end of attr->transit. */
  if (! ((attre = bgp_attr_extra_get(attr))->transit) )
      attre->transit = XCALLOC (MTYPE_TRANSIT, sizeof (struct transit));

  transit = attre->transit;

  if (transit->val)
    transit->val = XREALLOC (MTYPE_TRANSIT_VAL, transit->val, 
			     transit->length + total);
  else
    transit->val = XMALLOC (MTYPE_TRANSIT_VAL, total);

  memcpy (transit->val + transit->length, startp, total);
  transit->length += total;

  return BGP_ATTR_PARSE_PROCEED;
}

/* Read attribute of update packet.  This function is called from
   bgp_update() in bgpd.c.  */
bgp_attr_parse_ret_t
bgp_attr_parse (struct peer *peer, struct attr *attr, bgp_size_t size,
		struct bgp_nlri *mp_update, struct bgp_nlri *mp_withdraw)
{
  int ret;
  u_char flag = 0;
  u_char type = 0;
  bgp_size_t length;
  u_char *startp, *endp;
  u_char *attr_endp;
  u_char seen[BGP_ATTR_BITMAP_SIZE];
  /* we need the as4_path only until we have synthesized the as_path with it */
  /* same goes for as4_aggregator */
  struct aspath *as4_path = NULL;
  as_t as4_aggregator = 0;
  struct in_addr as4_aggregator_addr = { 0 };

  /* Initialize bitmap. */
  memset (seen, 0, BGP_ATTR_BITMAP_SIZE);

  /* End pointer of BGP attribute. */
  endp = BGP_INPUT_PNT (peer) + size;
  
  /* Get attributes to the end of attribute length. */
  while (BGP_INPUT_PNT (peer) < endp)
    {
      /* Check remaining length check.*/
      if (endp - BGP_INPUT_PNT (peer) < BGP_ATTR_MIN_LEN)
	{
	  /* XXX warning: long int format, int arg (arg 5) */
	  zlog (peer->log, LOG_WARNING, 
		"%s: error BGP attribute length %lu is smaller than min len",
		peer->host,
		(unsigned long) (endp - STREAM_PNT (BGP_INPUT (peer))));

	  bgp_notify_send (peer, 
			   BGP_NOTIFY_UPDATE_ERR, 
			   BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
	  return BGP_ATTR_PARSE_ERROR;
	}

      /* Fetch attribute flag and type. */
      startp = BGP_INPUT_PNT (peer);
      flag = stream_getc (BGP_INPUT (peer));
      type = stream_getc (BGP_INPUT (peer));

      /* Check whether Extended-Length applies and is in bounds */
      if (CHECK_FLAG (flag, BGP_ATTR_FLAG_EXTLEN)
          && ((endp - startp) < (BGP_ATTR_MIN_LEN + 1)))
	{
	  zlog (peer->log, LOG_WARNING, 
		"%s: Extended length set, but just %lu bytes of attr header",
		peer->host,
		(unsigned long) (endp - STREAM_PNT (BGP_INPUT (peer))));

	  bgp_notify_send (peer, 
			   BGP_NOTIFY_UPDATE_ERR, 
			   BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
	  return BGP_ATTR_PARSE_ERROR;
	}

      /* Check extended attribue length bit. */
      if (CHECK_FLAG (flag, BGP_ATTR_FLAG_EXTLEN))
	length = stream_getw (BGP_INPUT (peer));
      else
	length = stream_getc (BGP_INPUT (peer));
      
      /* If any attribute appears more than once in the UPDATE
	 message, then the Error Subcode is set to Malformed Attribute
	 List. */

      if (CHECK_BITMAP (seen, type))
	{
	  zlog (peer->log, LOG_WARNING,
		"%s: error BGP attribute type %d appears twice in a message",
		peer->host, type);

	  bgp_notify_send (peer, 
			   BGP_NOTIFY_UPDATE_ERR, 
			   BGP_NOTIFY_UPDATE_MAL_ATTR);
	  return BGP_ATTR_PARSE_ERROR;
	}

      /* Set type to bitmap to check duplicate attribute.  `type' is
	 unsigned char so it never overflow bitmap range. */

      SET_BITMAP (seen, type);

      /* Overflow check. */
      attr_endp =  BGP_INPUT_PNT (peer) + length;

      if (attr_endp > endp)
	{
	  zlog (peer->log, LOG_WARNING, 
		"%s: BGP type %d length %d is too large, attribute total length is %d.  attr_endp is %p.  endp is %p", peer->host, type, length, size, attr_endp, endp);
	  bgp_notify_send (peer, 
			   BGP_NOTIFY_UPDATE_ERR, 
			   BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
	  return BGP_ATTR_PARSE_ERROR;
	}

      /* OK check attribute and store it's value. */
      switch (type)
	{
	case BGP_ATTR_ORIGIN:
	  ret = bgp_attr_origin (peer, length, attr, flag, startp);
	  break;
	case BGP_ATTR_AS_PATH:
	  ret = bgp_attr_aspath (peer, length, attr, flag, startp);
	  break;
	case BGP_ATTR_AS4_PATH:
	  ret = bgp_attr_as4_path (peer, length, attr, flag, startp, &as4_path);
	  break;
	case BGP_ATTR_NEXT_HOP:	
	  ret = bgp_attr_nexthop (peer, length, attr, flag, startp);
	  break;
	case BGP_ATTR_MULTI_EXIT_DISC:
	  ret = bgp_attr_med (peer, length, attr, flag, startp);
	  break;
	case BGP_ATTR_LOCAL_PREF:
	  ret = bgp_attr_local_pref (peer, length, attr, flag, startp);
	  break;
	case BGP_ATTR_ATOMIC_AGGREGATE:
	  ret = bgp_attr_atomic (peer, length, attr, flag, startp);
	  break;
	case BGP_ATTR_AGGREGATOR:
	  ret = bgp_attr_aggregator (peer, length, attr, flag);
	  break;
	case BGP_ATTR_AS4_AGGREGATOR:
	  ret = bgp_attr_as4_aggregator (peer, length, attr, flag,
	                                 &as4_aggregator, 
	                                 &as4_aggregator_addr);
	  break;
	case BGP_ATTR_COMMUNITIES:
	  ret = bgp_attr_community (peer, length, attr, flag, startp);
	  break;
	case BGP_ATTR_ORIGINATOR_ID:
	  ret = bgp_attr_originator_id (peer, length, attr, flag);
	  break;
	case BGP_ATTR_CLUSTER_LIST:
	  ret = bgp_attr_cluster_list (peer, length, attr, flag);
	  break;
	case BGP_ATTR_MP_REACH_NLRI:
	  ret = bgp_mp_reach_parse (peer, length, attr, mp_update);
	  break;
	case BGP_ATTR_MP_UNREACH_NLRI:
	  ret = bgp_mp_unreach_parse (peer, length, mp_withdraw);
	  break;
	case BGP_ATTR_EXT_COMMUNITIES:
	  ret = bgp_attr_ext_communities (peer, length, attr, flag, startp);
	  break;
	default:
	  ret = bgp_attr_unknown (peer, attr, flag, type, length, startp);
	  break;
	}
      
      /* If hard error occured immediately return to the caller. */
      if (ret == BGP_ATTR_PARSE_ERROR)
        {
          zlog (peer->log, LOG_WARNING,
                "%s: Attribute %s, parse error", 
                peer->host, 
                LOOKUP (attr_str, type));
          bgp_notify_send (peer, 
                           BGP_NOTIFY_UPDATE_ERR,
                           BGP_NOTIFY_UPDATE_MAL_ATTR);
          if (as4_path)
            aspath_unintern (&as4_path);
          return ret;
        }
      if (ret == BGP_ATTR_PARSE_WITHDRAW)
        {
          
          zlog (peer->log, LOG_WARNING,
                "%s: Attribute %s, parse error - treating as withdrawal",
                peer->host,
                LOOKUP (attr_str, type));
          if (as4_path)
            aspath_unintern (&as4_path);
          return ret;
        }
      
      /* Check the fetched length. */
      if (BGP_INPUT_PNT (peer) != attr_endp)
	{
	  zlog (peer->log, LOG_WARNING, 
		"%s: BGP attribute %s, fetch error", 
                peer->host, LOOKUP (attr_str, type));
	  bgp_notify_send (peer, 
			   BGP_NOTIFY_UPDATE_ERR, 
			   BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
          if (as4_path)
            aspath_unintern (&as4_path);
	  return BGP_ATTR_PARSE_ERROR;
	}
    }

  /* Check final read pointer is same as end pointer. */
  if (BGP_INPUT_PNT (peer) != endp)
    {
      zlog (peer->log, LOG_WARNING, 
	    "%s: BGP attribute %s, length mismatch",
	    peer->host, LOOKUP (attr_str, type));
      bgp_notify_send (peer, 
		       BGP_NOTIFY_UPDATE_ERR, 
		       BGP_NOTIFY_UPDATE_ATTR_LENG_ERR);
      if (as4_path)
        aspath_unintern (&as4_path);
      return BGP_ATTR_PARSE_ERROR;
    }

  /* 
   * At this place we can see whether we got AS4_PATH and/or
   * AS4_AGGREGATOR from a 16Bit peer and act accordingly.
   * We can not do this before we've read all attributes because
   * the as4 handling does not say whether AS4_PATH has to be sent
   * after AS_PATH or not - and when AS4_AGGREGATOR will be send
   * in relationship to AGGREGATOR.
   * So, to be defensive, we are not relying on any order and read
   * all attributes first, including these 32bit ones, and now,
   * afterwards, we look what and if something is to be done for as4.
   */
  if (bgp_attr_munge_as4_attrs (peer, attr, flag, as4_path,
                                as4_aggregator, &as4_aggregator_addr))
    {
      if (as4_path)
        aspath_unintern (&as4_path);
      return BGP_ATTR_PARSE_ERROR;
    }

  /* At this stage, we have done all fiddling with as4, and the
   * resulting info is in attr->aggregator resp. attr->aspath
   * so we can chuck as4_aggregator and as4_path alltogether in
   * order to save memory
   */
  if (as4_path)
    {
      aspath_unintern (&as4_path); /* unintern - it is in the hash */
      /* The flag that we got this is still there, but that does not
       * do any trouble
       */
    }
  /*
   * The "rest" of the code does nothing with as4_aggregator.
   * there is no memory attached specifically which is not part
   * of the attr.
   * so ignoring just means do nothing.
   */
  /*
   * Finally do the checks on the aspath we did not do yet
   * because we waited for a potentially synthesized aspath.
   */
  if (attr->flag & (ATTR_FLAG_BIT(BGP_ATTR_AS_PATH)))
    {
      ret = bgp_attr_aspath_check (peer, attr, flag);
      if (ret != BGP_ATTR_PARSE_PROCEED)
	return ret;
    }

  /* Finally intern unknown attribute. */
  if (attr->extra && attr->extra->transit)
    attr->extra->transit = transit_intern (attr->extra->transit);

  return BGP_ATTR_PARSE_PROCEED;
}

/* Well-known attribute check. */
int
bgp_attr_check (struct peer *peer, struct attr *attr)
{
  u_char type = 0;
  
  if (! CHECK_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_ORIGIN)))
    type = BGP_ATTR_ORIGIN;

  if (! CHECK_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_AS_PATH)))
    type = BGP_ATTR_AS_PATH;

  if (! CHECK_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_NEXT_HOP)))
    type = BGP_ATTR_NEXT_HOP;

  if (peer_sort (peer) == BGP_PEER_IBGP
      && ! CHECK_FLAG (attr->flag, ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF)))
    type = BGP_ATTR_LOCAL_PREF;

  if (type)
    {
      zlog (peer->log, LOG_WARNING, 
	    "%s Missing well-known attribute %d.",
	    peer->host, type);
      bgp_notify_send_with_data (peer, 
				 BGP_NOTIFY_UPDATE_ERR, 
				 BGP_NOTIFY_UPDATE_MISS_ATTR,
				 &type, 1);
      return BGP_ATTR_PARSE_ERROR;
    }
  return BGP_ATTR_PARSE_PROCEED;
}

int stream_put_prefix (struct stream *, struct prefix *);

/* Make attribute packet. */
bgp_size_t
bgp_packet_attribute (struct bgp *bgp, struct peer *peer,
		      struct stream *s, struct attr *attr, struct prefix *p,
		      afi_t afi, safi_t safi, struct peer *from,
		      struct prefix_rd *prd, u_char *tag)
{
  size_t cp;
  size_t aspath_sizep;
  struct aspath *aspath;
  int send_as4_path = 0;
  int send_as4_aggregator = 0;
  int use32bit = (CHECK_FLAG (peer->cap, PEER_CAP_AS4_RCV)) ? 1 : 0;

  if (! bgp)
    bgp = bgp_get_default ();

  /* Remember current pointer. */
  cp = stream_get_endp (s);

  /* Origin attribute. */
  stream_putc (s, BGP_ATTR_FLAG_TRANS);
  stream_putc (s, BGP_ATTR_ORIGIN);
  stream_putc (s, 1);
  stream_putc (s, attr->origin);

  /* AS path attribute. */

  /* If remote-peer is EBGP */
  if (peer_sort (peer) == BGP_PEER_EBGP
      && (! CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_AS_PATH_UNCHANGED)
	  || attr->aspath->segments == NULL)
      && (! CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_RSERVER_CLIENT)))
    {    
      aspath = aspath_dup (attr->aspath);

      if (CHECK_FLAG(bgp->config, BGP_CONFIG_CONFEDERATION))
	{
	  /* Strip the confed info, and then stuff our path CONFED_ID
	     on the front */
	  aspath = aspath_delete_confed_seq (aspath);
	  aspath = aspath_add_seq (aspath, bgp->confed_id);
	}
      else
	{
	  aspath = aspath_add_seq (aspath, peer->local_as);
	  if (peer->change_local_as)
	    aspath = aspath_add_seq (aspath, peer->change_local_as);
	}
    }
  else if (peer_sort (peer) == BGP_PEER_CONFED)
    {
      /* A confed member, so we need to do the AS_CONFED_SEQUENCE thing */
      aspath = aspath_dup (attr->aspath);
      aspath = aspath_add_confed_seq (aspath, peer->local_as);
    }
  else
    aspath = attr->aspath;

  /* If peer is not AS4 capable, then:
   * - send the created AS_PATH out as AS4_PATH (optional, transitive),
   *   but ensure that no AS_CONFED_SEQUENCE and AS_CONFED_SET path segment
   *   types are in it (i.e. exclude them if they are there)
   *   AND do this only if there is at least one asnum > 65535 in the path!
   * - send an AS_PATH out, but put 16Bit ASnums in it, not 32bit, and change
   *   all ASnums > 65535 to BGP_AS_TRANS
   */

  stream_putc (s, BGP_ATTR_FLAG_TRANS|BGP_ATTR_FLAG_EXTLEN);
  stream_putc (s, BGP_ATTR_AS_PATH);
  aspath_sizep = stream_get_endp (s);
  stream_putw (s, 0);
  stream_putw_at (s, aspath_sizep, aspath_put (s, aspath, use32bit));
  
  /* OLD session may need NEW_AS_PATH sent, if there are 4-byte ASNs 
   * in the path
   */
  if (!use32bit && aspath_has_as4 (aspath))
      send_as4_path = 1; /* we'll do this later, at the correct place */
  
  /* Nexthop attribute. */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_NEXT_HOP) && afi == AFI_IP)
    {
      stream_putc (s, BGP_ATTR_FLAG_TRANS);
      stream_putc (s, BGP_ATTR_NEXT_HOP);
      stream_putc (s, 4);
      if (safi == SAFI_MPLS_VPN)
	{
	  if (attr->nexthop.s_addr == 0)
	    stream_put_ipv4 (s, peer->nexthop.v4.s_addr);
	  else
	    stream_put_ipv4 (s, attr->nexthop.s_addr);
	}
      else
	stream_put_ipv4 (s, attr->nexthop.s_addr);
    }

  /* MED attribute. */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
    {
      stream_putc (s, BGP_ATTR_FLAG_OPTIONAL);
      stream_putc (s, BGP_ATTR_MULTI_EXIT_DISC);
      stream_putc (s, 4);
      stream_putl (s, attr->med);
    }

  /* Local preference. */
  if (peer_sort (peer) == BGP_PEER_IBGP ||
      peer_sort (peer) == BGP_PEER_CONFED)
    {
      stream_putc (s, BGP_ATTR_FLAG_TRANS);
      stream_putc (s, BGP_ATTR_LOCAL_PREF);
      stream_putc (s, 4);
      stream_putl (s, attr->local_pref);
    }

  /* Atomic aggregate. */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE))
    {
      stream_putc (s, BGP_ATTR_FLAG_TRANS);
      stream_putc (s, BGP_ATTR_ATOMIC_AGGREGATE);
      stream_putc (s, 0);
    }

  /* Aggregator. */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR))
    {
      assert (attr->extra);
      
      /* Common to BGP_ATTR_AGGREGATOR, regardless of ASN size */
      stream_putc (s, BGP_ATTR_FLAG_OPTIONAL|BGP_ATTR_FLAG_TRANS);
      stream_putc (s, BGP_ATTR_AGGREGATOR);
      
      if (use32bit)
        {
          /* AS4 capable peer */
          stream_putc (s, 8);
          stream_putl (s, attr->extra->aggregator_as);
        }
      else
        {
          /* 2-byte AS peer */
          stream_putc (s, 6);
          
          /* Is ASN representable in 2-bytes? Or must AS_TRANS be used? */
          if ( attr->extra->aggregator_as > 65535 )
            {
              stream_putw (s, BGP_AS_TRANS);
              
              /* we have to send AS4_AGGREGATOR, too.
               * we'll do that later in order to send attributes in ascending
               * order.
               */
              send_as4_aggregator = 1;
            }
          else
            stream_putw (s, (u_int16_t) attr->extra->aggregator_as);
        }
      stream_put_ipv4 (s, attr->extra->aggregator_addr.s_addr);
    }

  /* Community attribute. */
  if (CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_SEND_COMMUNITY) 
      && (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_COMMUNITIES)))
    {
      if (attr->community->size * 4 > 255)
	{
	  stream_putc (s, BGP_ATTR_FLAG_OPTIONAL|BGP_ATTR_FLAG_TRANS|BGP_ATTR_FLAG_EXTLEN);
	  stream_putc (s, BGP_ATTR_COMMUNITIES);
	  stream_putw (s, attr->community->size * 4);
	}
      else
	{
	  stream_putc (s, BGP_ATTR_FLAG_OPTIONAL|BGP_ATTR_FLAG_TRANS);
	  stream_putc (s, BGP_ATTR_COMMUNITIES);
	  stream_putc (s, attr->community->size * 4);
	}
      stream_put (s, attr->community->val, attr->community->size * 4);
    }

  /* Route Reflector. */
  if (peer_sort (peer) == BGP_PEER_IBGP
      && from
      && peer_sort (from) == BGP_PEER_IBGP)
    {
      /* Originator ID. */
      stream_putc (s, BGP_ATTR_FLAG_OPTIONAL);
      stream_putc (s, BGP_ATTR_ORIGINATOR_ID);
      stream_putc (s, 4);

      if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID))
	stream_put_in_addr (s, &attr->extra->originator_id);
      else 
        stream_put_in_addr (s, &from->remote_id);

      /* Cluster list. */
      stream_putc (s, BGP_ATTR_FLAG_OPTIONAL);
      stream_putc (s, BGP_ATTR_CLUSTER_LIST);
      
      if (attr->extra && attr->extra->cluster)
	{
	  stream_putc (s, attr->extra->cluster->length + 4);
	  /* If this peer configuration's parent BGP has cluster_id. */
	  if (bgp->config & BGP_CONFIG_CLUSTER_ID)
	    stream_put_in_addr (s, &bgp->cluster_id);
	  else
	    stream_put_in_addr (s, &bgp->router_id);
	  stream_put (s, attr->extra->cluster->list, 
	              attr->extra->cluster->length);
	}
      else
	{
	  stream_putc (s, 4);
	  /* If this peer configuration's parent BGP has cluster_id. */
	  if (bgp->config & BGP_CONFIG_CLUSTER_ID)
	    stream_put_in_addr (s, &bgp->cluster_id);
	  else
	    stream_put_in_addr (s, &bgp->router_id);
	}
    }

#ifdef HAVE_IPV6
  /* If p is IPv6 address put it into attribute. */
  if (p->family == AF_INET6)
    {
      unsigned long sizep;
      struct attr_extra *attre = attr->extra;
      
      assert (attr->extra);
      
      stream_putc (s, BGP_ATTR_FLAG_OPTIONAL);
      stream_putc (s, BGP_ATTR_MP_REACH_NLRI);
      sizep = stream_get_endp (s);
      stream_putc (s, 0);	/* Marker: Attribute length. */
      stream_putw (s, AFI_IP6);	/* AFI */
      stream_putc (s, safi);	/* SAFI */

      stream_putc (s, attre->mp_nexthop_len);

      if (attre->mp_nexthop_len == 16)
	stream_put (s, &attre->mp_nexthop_global, 16);
      else if (attre->mp_nexthop_len == 32)
	{
	  stream_put (s, &attre->mp_nexthop_global, 16);
	  stream_put (s, &attre->mp_nexthop_local, 16);
	}
      
      /* SNPA */
      stream_putc (s, 0);

      /* Prefix write. */
      stream_put_prefix (s, p);

      /* Set MP attribute length. */
      stream_putc_at (s, sizep, (stream_get_endp (s) - sizep) - 1);
    }
#endif /* HAVE_IPV6 */

  if (p->family == AF_INET && safi == SAFI_MULTICAST)
    {
      unsigned long sizep;

      stream_putc (s, BGP_ATTR_FLAG_OPTIONAL);
      stream_putc (s, BGP_ATTR_MP_REACH_NLRI);
      sizep = stream_get_endp (s);
      stream_putc (s, 0);	/* Marker: Attribute Length. */
      stream_putw (s, AFI_IP);	/* AFI */
      stream_putc (s, SAFI_MULTICAST);	/* SAFI */

      stream_putc (s, 4);
      stream_put_ipv4 (s, attr->nexthop.s_addr);

      /* SNPA */
      stream_putc (s, 0);

      /* Prefix write. */
      stream_put_prefix (s, p);

      /* Set MP attribute length. */
      stream_putc_at (s, sizep, (stream_get_endp (s) - sizep) - 1);
    }

  if (p->family == AF_INET && safi == SAFI_MPLS_VPN)
    {
      unsigned long sizep;

      stream_putc (s, BGP_ATTR_FLAG_OPTIONAL);
      stream_putc (s, BGP_ATTR_MP_REACH_NLRI);
      sizep = stream_get_endp (s);
      stream_putc (s, 0);	/* Length of this attribute. */
      stream_putw (s, AFI_IP);	/* AFI */
      stream_putc (s, BGP_SAFI_VPNV4);	/* SAFI */

      stream_putc (s, 12);
      stream_putl (s, 0);
      stream_putl (s, 0);
      stream_put (s, &attr->extra->mp_nexthop_global_in, 4);

      /* SNPA */
      stream_putc (s, 0);

      /* Tag, RD, Prefix write. */
      stream_putc (s, p->prefixlen + 88);
      stream_put (s, tag, 3);
      stream_put (s, prd->val, 8);
      stream_put (s, &p->u.prefix, PSIZE (p->prefixlen));

      /* Set MP attribute length. */
      stream_putc_at (s, sizep, (stream_get_endp (s) - sizep) - 1);
    }

  /* Extended Communities attribute. */
  if (CHECK_FLAG (peer->af_flags[afi][safi], PEER_FLAG_SEND_EXT_COMMUNITY) 
      && (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES)))
    {
      struct attr_extra *attre = attr->extra;
      
      assert (attre);
      
      if (peer_sort (peer) == BGP_PEER_IBGP 
          || peer_sort (peer) == BGP_PEER_CONFED)
	{
	  if (attre->ecommunity->size * 8 > 255)
	    {
	      stream_putc (s, BGP_ATTR_FLAG_OPTIONAL|BGP_ATTR_FLAG_TRANS|BGP_ATTR_FLAG_EXTLEN);
	      stream_putc (s, BGP_ATTR_EXT_COMMUNITIES);
	      stream_putw (s, attre->ecommunity->size * 8);
	    }
	  else
	    {
	      stream_putc (s, BGP_ATTR_FLAG_OPTIONAL|BGP_ATTR_FLAG_TRANS);
	      stream_putc (s, BGP_ATTR_EXT_COMMUNITIES);
	      stream_putc (s, attre->ecommunity->size * 8);
	    }
	  stream_put (s, attre->ecommunity->val, attre->ecommunity->size * 8);
	}
      else
	{
	  u_int8_t *pnt;
	  int tbit;
	  int ecom_tr_size = 0;
	  int i;

	  for (i = 0; i < attre->ecommunity->size; i++)
	    {
	      pnt = attre->ecommunity->val + (i * 8);
	      tbit = *pnt;

	      if (CHECK_FLAG (tbit, ECOMMUNITY_FLAG_NON_TRANSITIVE))
		continue;

	      ecom_tr_size++;
	    }

	  if (ecom_tr_size)
	    {
	      if (ecom_tr_size * 8 > 255)
		{
		  stream_putc (s, BGP_ATTR_FLAG_OPTIONAL|BGP_ATTR_FLAG_TRANS|BGP_ATTR_FLAG_EXTLEN);
		  stream_putc (s, BGP_ATTR_EXT_COMMUNITIES);
		  stream_putw (s, ecom_tr_size * 8);
		}
	      else
		{
		  stream_putc (s, BGP_ATTR_FLAG_OPTIONAL|BGP_ATTR_FLAG_TRANS);
		  stream_putc (s, BGP_ATTR_EXT_COMMUNITIES);
		  stream_putc (s, ecom_tr_size * 8);
		}

	      for (i = 0; i < attre->ecommunity->size; i++)
		{
		  pnt = attre->ecommunity->val + (i * 8);
		  tbit = *pnt;

		  if (CHECK_FLAG (tbit, ECOMMUNITY_FLAG_NON_TRANSITIVE))
		    continue;

		  stream_put (s, pnt, 8);
		}
	    }
	}
    }

  if ( send_as4_path )
    {
      /* If the peer is NOT As4 capable, AND */
      /* there are ASnums > 65535 in path  THEN
       * give out AS4_PATH */

      /* Get rid of all AS_CONFED_SEQUENCE and AS_CONFED_SET
       * path segments!
       * Hm, I wonder...  confederation things *should* only be at
       * the beginning of an aspath, right?  Then we should use
       * aspath_delete_confed_seq for this, because it is already
       * there! (JK) 
       * Folks, talk to me: what is reasonable here!?
       */
      aspath = aspath_delete_confed_seq (aspath);

      stream_putc (s, BGP_ATTR_FLAG_TRANS|BGP_ATTR_FLAG_OPTIONAL|BGP_ATTR_FLAG_EXTLEN);
      stream_putc (s, BGP_ATTR_AS4_PATH);
      aspath_sizep = stream_get_endp (s);
      stream_putw (s, 0);
      stream_putw_at (s, aspath_sizep, aspath_put (s, aspath, 1));
    }

  if (aspath != attr->aspath)
    aspath_free (aspath);

  if ( send_as4_aggregator ) 
    {
      assert (attr->extra);

      /* send AS4_AGGREGATOR, at this place */
      /* this section of code moved here in order to ensure the correct
       * *ascending* order of attributes
       */
      stream_putc (s, BGP_ATTR_FLAG_OPTIONAL|BGP_ATTR_FLAG_TRANS);
      stream_putc (s, BGP_ATTR_AS4_AGGREGATOR);
      stream_putc (s, 8);
      stream_putl (s, attr->extra->aggregator_as);
      stream_put_ipv4 (s, attr->extra->aggregator_addr.s_addr);
    }
  
  /* Unknown transit attribute. */
  if (attr->extra && attr->extra->transit)
    stream_put (s, attr->extra->transit->val, attr->extra->transit->length);

  /* Return total size of attribute. */
  return stream_get_endp (s) - cp;
}

bgp_size_t
bgp_packet_withdraw (struct peer *peer, struct stream *s, struct prefix *p,
		     afi_t afi, safi_t safi, struct prefix_rd *prd,
		     u_char *tag)
{
  unsigned long cp;
  unsigned long attrlen_pnt;
  bgp_size_t size;

  cp = stream_get_endp (s);

  stream_putc (s, BGP_ATTR_FLAG_OPTIONAL);
  stream_putc (s, BGP_ATTR_MP_UNREACH_NLRI);

  attrlen_pnt = stream_get_endp (s);
  stream_putc (s, 0);		/* Length of this attribute. */

  stream_putw (s, family2afi (p->family));

  if (safi == SAFI_MPLS_VPN)
    {
      /* SAFI */
      stream_putc (s, BGP_SAFI_VPNV4);

      /* prefix. */
      stream_putc (s, p->prefixlen + 88);
      stream_put (s, tag, 3);
      stream_put (s, prd->val, 8);
      stream_put (s, &p->u.prefix, PSIZE (p->prefixlen));
    }
  else
    {
      /* SAFI */
      stream_putc (s, safi);

      /* prefix */
      stream_put_prefix (s, p);
    }

  /* Set MP attribute length. */
  size = stream_get_endp (s) - attrlen_pnt - 1;
  stream_putc_at (s, attrlen_pnt, size);

  return stream_get_endp (s) - cp;
}

/* Initialization of attribute. */
void
bgp_attr_init (void)
{
  aspath_init ();
  attrhash_init ();
  community_init ();
  ecommunity_init ();
  cluster_init ();
  transit_init ();
}

void
bgp_attr_finish (void)
{
  aspath_finish ();
  attrhash_finish ();
  community_finish ();
  ecommunity_finish ();
  cluster_finish ();
  transit_finish ();
}

/* Make attribute packet. */
void
bgp_dump_routes_attr (struct stream *s, struct attr *attr, 
                      struct prefix *prefix)
{
  unsigned long cp;
  unsigned long len;
  size_t aspath_lenp;
  struct aspath *aspath;

  /* Remember current pointer. */
  cp = stream_get_endp (s);

  /* Place holder of length. */
  stream_putw (s, 0);

  /* Origin attribute. */
  stream_putc (s, BGP_ATTR_FLAG_TRANS);
  stream_putc (s, BGP_ATTR_ORIGIN);
  stream_putc (s, 1);
  stream_putc (s, attr->origin);

  aspath = attr->aspath;
  
  stream_putc (s, BGP_ATTR_FLAG_TRANS|BGP_ATTR_FLAG_EXTLEN);
  stream_putc (s, BGP_ATTR_AS_PATH);
  aspath_lenp = stream_get_endp (s);
  stream_putw (s, 0);
  
  stream_putw_at (s, aspath_lenp, aspath_put (s, aspath, 1));

  /* Nexthop attribute. */
  /* If it's an IPv6 prefix, don't dump the IPv4 nexthop to save space */
  if(prefix != NULL
#ifdef HAVE_IPV6
     && prefix->family != AF_INET6
#endif /* HAVE_IPV6 */
     )
    {
      stream_putc (s, BGP_ATTR_FLAG_TRANS);
      stream_putc (s, BGP_ATTR_NEXT_HOP);
      stream_putc (s, 4);
      stream_put_ipv4 (s, attr->nexthop.s_addr);
    }

  /* MED attribute. */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_MULTI_EXIT_DISC))
    {
      stream_putc (s, BGP_ATTR_FLAG_OPTIONAL);
      stream_putc (s, BGP_ATTR_MULTI_EXIT_DISC);
      stream_putc (s, 4);
      stream_putl (s, attr->med);
    }

  /* Local preference. */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_LOCAL_PREF))
    {
      stream_putc (s, BGP_ATTR_FLAG_TRANS);
      stream_putc (s, BGP_ATTR_LOCAL_PREF);
      stream_putc (s, 4);
      stream_putl (s, attr->local_pref);
    }

  /* Atomic aggregate. */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_ATOMIC_AGGREGATE))
    {
      stream_putc (s, BGP_ATTR_FLAG_TRANS);
      stream_putc (s, BGP_ATTR_ATOMIC_AGGREGATE);
      stream_putc (s, 0);
    }

  /* Aggregator. */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_AGGREGATOR))
    {
      assert (attr->extra);
      stream_putc (s, BGP_ATTR_FLAG_OPTIONAL|BGP_ATTR_FLAG_TRANS);
      stream_putc (s, BGP_ATTR_AGGREGATOR);
      stream_putc (s, 8);
      stream_putl (s, attr->extra->aggregator_as);
      stream_put_ipv4 (s, attr->extra->aggregator_addr.s_addr);
    }

  /* Community attribute. */
  if (attr->flag & ATTR_FLAG_BIT (BGP_ATTR_COMMUNITIES))
    {
      if (attr->community->size * 4 > 255)
	{
	  stream_putc (s, BGP_ATTR_FLAG_OPTIONAL|BGP_ATTR_FLAG_TRANS|BGP_ATTR_FLAG_EXTLEN);
	  stream_putc (s, BGP_ATTR_COMMUNITIES);
	  stream_putw (s, attr->community->size * 4);
	}
      else
	{
	  stream_putc (s, BGP_ATTR_FLAG_OPTIONAL|BGP_ATTR_FLAG_TRANS);
	  stream_putc (s, BGP_ATTR_COMMUNITIES);
	  stream_putc (s, attr->community->size * 4);
	}
      stream_put (s, attr->community->val, attr->community->size * 4);
    }

#ifdef HAVE_IPV6
  /* Add a MP_NLRI attribute to dump the IPv6 next hop */
  if (prefix != NULL && prefix->family == AF_INET6 && attr->extra &&
     (attr->extra->mp_nexthop_len == 16 || attr->extra->mp_nexthop_len == 32) )
    {
      int sizep;
      struct attr_extra *attre = attr->extra;
      
      stream_putc(s, BGP_ATTR_FLAG_OPTIONAL);
      stream_putc(s, BGP_ATTR_MP_REACH_NLRI);
      sizep = stream_get_endp (s);

      /* MP header */
      stream_putc (s, 0);		/* Marker: Attribute length. */
      stream_putw(s, AFI_IP6);		/* AFI */
      stream_putc(s, SAFI_UNICAST);	/* SAFI */

      /* Next hop */
      stream_putc(s, attre->mp_nexthop_len);
      stream_put(s, &attre->mp_nexthop_global, 16);
      if (attre->mp_nexthop_len == 32)
        stream_put(s, &attre->mp_nexthop_local, 16);

      /* SNPA */
      stream_putc(s, 0);

      /* Prefix */
      stream_put_prefix(s, prefix);

      /* Set MP attribute length. */
      stream_putc_at (s, sizep, (stream_get_endp (s) - sizep) - 1);
    }
#endif /* HAVE_IPV6 */

  /* Return total size of attribute. */
  len = stream_get_endp (s) - cp - 2;
  stream_putw_at (s, cp, len);
}
