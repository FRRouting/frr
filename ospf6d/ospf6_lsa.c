/*
 * LSA function
 * Copyright (C) 1999 Yasuhiro Ohara
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

/* Include other stuffs */
#include "version.h"
#include "log.h"
#include "getopt.h"
#include "linklist.h"
#include "thread.h"
#include "command.h"
#include "memory.h"
#include "sockunion.h"
#include "if.h"
#include "prefix.h"
#include "stream.h"
#include "thread.h"
#include "filter.h"
#include "zclient.h"
#include "table.h"
#include "plist.h"

#include "ospf6_proto.h"
#include "ospf6_prefix.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_message.h"
#include "ospf6_dump.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"
#include "ospf6_ism.h"
#include "ospf6_nsm.h"
#include "ospf6_dbex.h"

#define HEADER_DEPENDENCY
#include "ospf6d.h"
#undef HEADER_DEPENDENCY

/* test LSAs identity */
static int
ospf6_lsa_issame (struct ospf6_lsa_header__ *lsh1,
                  struct ospf6_lsa_header__ *lsh2)
{
  assert (lsh1 && lsh2);

  if (lsh1->adv_router != lsh2->adv_router)
    return 0;

  if (lsh1->id != lsh2->id)
    return 0;

  if (lsh1->type != lsh2->type)
    return 0;

  return 1;
}

/* RFC2328: Section 13.2 */
int
ospf6_lsa_differ (struct ospf6_lsa *lsa1,
                  struct ospf6_lsa *lsa2)
{
  int diff, cmplen;

  if (! ospf6_lsa_issame (lsa1->header, lsa2->header))
    return 1;

  /* check Options field */
  /* xxx */

  ospf6_lsa_age_current (lsa1);
  ospf6_lsa_age_current (lsa2);
  if (ntohs (lsa1->header->age) == MAXAGE &&
      ntohs (lsa2->header->age) != MAXAGE)
    return 1;
  if (ntohs (lsa1->header->age) != MAXAGE &&
      ntohs (lsa2->header->age) == MAXAGE)
    return 1;

  /* compare body */
  if (ntohs (lsa1->header->length) != ntohs (lsa2->header->length))
    return 1;

  cmplen = ntohs (lsa1->header->length) - sizeof (struct ospf6_lsa_header);
  diff = memcmp (lsa1->header + 1, lsa2->header + 1, cmplen);

  return diff;
}

int
ospf6_lsa_match (u_int16_t type, u_int32_t id, u_int32_t adv_router,
                 struct ospf6_lsa_header *lsh)
{
  if (lsh->advrtr != adv_router)
    return 0;

  if (lsh->ls_id != id)
    return 0;

  if (lsh->type != type)
    return 0;

  return 1;
}

/* ospf6 age functions */
/* calculate birth and set expire timer */
static void
ospf6_lsa_age_set (struct ospf6_lsa *lsa)
{
  struct timeval now;

  assert (lsa && lsa->header);

  if (gettimeofday (&now, (struct timezone *)NULL) < 0)
    zlog_warn ("LSA: gettimeofday failed, may fail LSA AGEs: %s",
               strerror (errno));

  lsa->birth.tv_sec = now.tv_sec - ntohs (lsa->header->age);
  lsa->birth.tv_usec = now.tv_usec;
  if (ntohs (lsa->header->age) != MAXAGE)
    lsa->expire = thread_add_timer (master, ospf6_lsa_expire, lsa,
                                    lsa->birth.tv_sec + MAXAGE - now.tv_sec);
  else
    lsa->expire = NULL;
  return;
}

/* this function calculates current age from its birth,
   then update age field of LSA header. return value is current age */
u_int16_t
ospf6_lsa_age_current (struct ospf6_lsa *lsa)
{
  struct timeval now;
  u_int32_t ulage;
  u_int16_t age;

  assert (lsa);
  assert (lsa->header);

  /* current time */
  if (gettimeofday (&now, (struct timezone *)NULL) < 0)
    zlog_warn ("LSA: gettimeofday failed, may fail ages: %s",
               strerror (errno));

  /* calculate age */
  ulage = now.tv_sec - lsa->birth.tv_sec;

  /* if over MAXAGE, set to it */
  if (ulage > MAXAGE)
    age = MAXAGE;
  else
    age = ulage;

  lsa->header->age = htons (age);
  return age;
}

/* update age field of LSA header with adding InfTransDelay */
void
ospf6_lsa_age_update_to_send (struct ospf6_lsa *lsa, u_int32_t transdelay)
{
  unsigned short age;

  age = ospf6_lsa_age_current (lsa) + transdelay;
  if (age > MAXAGE)
    age = MAXAGE;
  lsa->header->age = htons (age);
  return;
}

void
ospf6_lsa_premature_aging (struct ospf6_lsa *lsa)
{
  /* log */
  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("LSA: Premature aging: %s", lsa->str);

  if (lsa->expire)
    thread_cancel (lsa->expire);
  lsa->expire = (struct thread *) NULL;
  if (lsa->refresh)
    thread_cancel (lsa->refresh);
  lsa->refresh = (struct thread *) NULL;

  memset (&lsa->birth, 0, sizeof (struct timeval));
  thread_execute (master, ospf6_lsa_expire, lsa, 0);
}

/* check which is more recent. if a is more recent, return -1;
   if the same, return 0; otherwise(b is more recent), return 1 */
int
ospf6_lsa_check_recent (struct ospf6_lsa *a, struct ospf6_lsa *b)
{
  signed long seqnuma, seqnumb;
  u_int16_t cksuma, cksumb;
  u_int16_t agea, ageb;

  assert (a && a->header);
  assert (b && b->header);
  assert (ospf6_lsa_issame (a->header, b->header));

  seqnuma = ((signed long) ntohl (a->header->seqnum))
             - (signed long) INITIAL_SEQUENCE_NUMBER;
  seqnumb = ((signed long) ntohl (b->header->seqnum))
             - (signed long) INITIAL_SEQUENCE_NUMBER;

  /* compare by sequence number */
    /* xxx, care about LS sequence number wrapping */
  recent_reason = "seqnum";
  if (seqnuma > seqnumb)
    return -1;
  else if (seqnuma < seqnumb)
    return 1;

  /* Checksum */
  cksuma = ntohs (a->header->checksum);
  cksumb = ntohs (b->header->checksum);
  if (cksuma > cksumb)
    return -1;
  if (cksuma < cksumb)
    return 0;

  /* Age check */
  agea = ospf6_lsa_age_current (a);
  ageb = ospf6_lsa_age_current (b);

    /* MaxAge check */
  recent_reason = "max age";
  if (agea == OSPF6_LSA_MAXAGE && ageb != OSPF6_LSA_MAXAGE)
    return -1;
  else if (agea != OSPF6_LSA_MAXAGE && ageb == OSPF6_LSA_MAXAGE)
    return 1;

  recent_reason = "age differ";
  if (agea > ageb && agea - ageb >= OSPF6_LSA_MAXAGEDIFF)
    return 1;
  else if (agea < ageb && ageb - agea >= OSPF6_LSA_MAXAGEDIFF)
    return -1;

  /* neither recent */
  recent_reason = "the same instance";
  return 0;
}

int
ospf6_lsa_lsd_num (struct ospf6_lsa_header *lsa_header)
{
  int ldnum = 0;
  u_int16_t len;

  len = ntohs (lsa_header->length);
  len -= sizeof (struct ospf6_lsa_header);
  if (lsa_header->type == htons (OSPF6_LSA_TYPE_ROUTER))
    {
      len -= sizeof (struct ospf6_router_lsa);
      ldnum = len / sizeof (struct ospf6_router_lsd);
    }
  else /* (lsa_header->type == htons (OSPF6_LSA_TYPE_NETWORK)) */
    {
      len -= sizeof (struct ospf6_network_lsa);
      ldnum = len / sizeof (u_int32_t);
    }

  return ldnum;
}

void *
ospf6_lsa_lsd_get (int index, struct ospf6_lsa_header *lsa_header)
{
  void *p;
  struct ospf6_router_lsa *router_lsa;
  struct ospf6_router_lsd *router_lsd;
  struct ospf6_network_lsa *network_lsa;
  struct ospf6_network_lsd *network_lsd;

  if (lsa_header->type == htons (OSPF6_LSA_TYPE_ROUTER))
    {
      router_lsa = (struct ospf6_router_lsa *) (lsa_header + 1);
      router_lsd = (struct ospf6_router_lsd *) (router_lsa + 1);
      router_lsd += index;
      p = (void *) router_lsd;
    }
  else if (lsa_header->type == htons (OSPF6_LSA_TYPE_NETWORK))
    {
      network_lsa = (struct ospf6_network_lsa *) (lsa_header + 1);
      network_lsd = (struct ospf6_network_lsd *) (network_lsa + 1);
      network_lsd += index;
      p = (void *) network_lsd;
    }
  else
    {
      p = (void *) NULL;
    }

  return p;
}

/* network_lsd <-> router_lsd */
static int
ospf6_lsa_lsd_network_reference_match (struct ospf6_network_lsd *network_lsd1,
                                       struct ospf6_lsa_header *lsa_header1,
                                       struct ospf6_router_lsd *router_lsd2,
                                       struct ospf6_lsa_header *lsa_header2)
{
  if (network_lsd1->adv_router != lsa_header2->advrtr)
    return 0;
  if (router_lsd2->type != OSPF6_ROUTER_LSD_TYPE_TRANSIT_NETWORK)
    return 0;
  if (router_lsd2->neighbor_router_id != lsa_header1->advrtr)
    return 0;
  if (router_lsd2->neighbor_interface_id != lsa_header1->ls_id)
    return 0;
  return 1;
}

/* router_lsd <-> router_lsd */
static int
ospf6_lsa_lsd_router_reference_match (struct ospf6_router_lsd *router_lsd1,
                                      struct ospf6_lsa_header *lsa_header1,
                                      struct ospf6_router_lsd *router_lsd2,
                                      struct ospf6_lsa_header *lsa_header2)
{
  if (router_lsd1->type != OSPF6_ROUTER_LSD_TYPE_POINTTOPOINT)
    return 0;
  if (router_lsd2->type != OSPF6_ROUTER_LSD_TYPE_POINTTOPOINT)
    return 0;
  if (router_lsd1->neighbor_router_id != lsa_header2->advrtr)
    return 0;
  if (router_lsd2->neighbor_router_id != lsa_header1->advrtr)
    return 0;
  if (router_lsd1->neighbor_interface_id != router_lsd2->interface_id)
    return 0;
  if (router_lsd2->neighbor_interface_id != router_lsd1->interface_id)
    return 0;
  return 1;
}

int
ospf6_lsa_lsd_is_refer_ok (int index1, struct ospf6_lsa_header *lsa_header1,
                           int index2, struct ospf6_lsa_header *lsa_header2)
{
  struct ospf6_router_lsd *r1, *r2;
  struct ospf6_network_lsd *n;

  r1 = (struct ospf6_router_lsd *) NULL;
  r2 = (struct ospf6_router_lsd *) NULL;
  n = (struct ospf6_network_lsd *) NULL;
  if (lsa_header1->type == htons (OSPF6_LSA_TYPE_ROUTER))
    r1 = (struct ospf6_router_lsd *) ospf6_lsa_lsd_get (index1, lsa_header1);
  else
    n = (struct ospf6_network_lsd *) ospf6_lsa_lsd_get (index1, lsa_header1);

  if (lsa_header2->type == htons (OSPF6_LSA_TYPE_ROUTER))
    r2 = (struct ospf6_router_lsd *) ospf6_lsa_lsd_get (index2, lsa_header2);
  else
    n = (struct ospf6_network_lsd *) ospf6_lsa_lsd_get (index2, lsa_header2);

  if (r1 && r2)
    return ospf6_lsa_lsd_router_reference_match (r1, lsa_header1,
                                                 r2, lsa_header2);
  else if (r1 && n)
    return ospf6_lsa_lsd_network_reference_match (n, lsa_header2,
                                                  r1, lsa_header1);
  else if (n && r2)
    return ospf6_lsa_lsd_network_reference_match (n, lsa_header1,
                                                 r2, lsa_header2);
  return 0;
}

void
ospf6_lsa_show (struct vty *vty, struct ospf6_lsa *lsa)
{
  char adv_router[64], id[64], type[32];

  assert (lsa);
  assert (lsa->header);

  ospf6_lsa_type_string (lsa->header->type, type, sizeof (type));
  inet_ntop (AF_INET, &lsa->header->id, id, sizeof (id));
  inet_ntop (AF_INET, &lsa->header->adv_router,
             adv_router, sizeof (adv_router));

  vty_out (vty, "%s", VTY_NEWLINE);
  vty_out (vty, "Age: %4hu Type: %s%s", ospf6_lsa_age_current (lsa),
           type, VTY_NEWLINE);
  vty_out (vty, "Link State ID: %s%s", id, VTY_NEWLINE);
  vty_out (vty, "Advertising Router: %s%s", adv_router, VTY_NEWLINE);
  vty_out (vty, "LS Sequence Number: %#lx%s", (u_long)ntohl (lsa->header->seqnum),
           VTY_NEWLINE);
  vty_out (vty, "CheckSum: %#hx Length: %hu%s", ntohs (lsa->header->checksum),
           ntohs (lsa->header->length), VTY_NEWLINE);

  {
    struct ospf6_lsa_slot *slot;
    slot = ospf6_lsa_slot_get (lsa->header->type);
    if (slot)
      {
        (*slot->func_show) (vty, lsa);
        vty_out (vty, "%s", VTY_NEWLINE);
        return;
      }
  }

  vty_out (vty, "%sUnknown LSA type ...%s", VTY_NEWLINE, VTY_NEWLINE);
}

void
ospf6_lsa_show_summary_header (struct vty *vty)
{
  vty_out (vty, "%-12s %-15s %-15s %4s %8s %4s %4s %-8s%s",
           "Type", "LSId", "AdvRouter", "Age", "SeqNum",
           "Cksm", "Len", "Duration", VTY_NEWLINE);
}

void
ospf6_lsa_show_summary (struct vty *vty, struct ospf6_lsa *lsa)
{
  char adv_router[16], id[16], type[16];
  struct timeval now, res;
  char duration[16];

  assert (lsa);
  assert (lsa->header);

  memset (type, 0, sizeof (type));
  ospf6_lsa_type_string (lsa->header->type, type, 13);
  inet_ntop (AF_INET, &lsa->header->id, id, sizeof (id));
  inet_ntop (AF_INET, &lsa->header->adv_router, adv_router,
             sizeof (adv_router));

  gettimeofday (&now, NULL);
  ospf6_timeval_sub (&now, &lsa->installed, &res);
  ospf6_timeval_string_summary (&res, duration, sizeof (duration));

  vty_out (vty, "%-12s %-15s %-15s %4hu %8lx %04hx %4hu %8s%s",
           type, id, adv_router, ospf6_lsa_age_current (lsa),
           (u_long) ntohl (lsa->header->seqnum),
           ntohs (lsa->header->checksum), ntohs (lsa->header->length),
           duration, VTY_NEWLINE);
}

void
ospf6_lsa_show_dump (struct vty *vty, struct ospf6_lsa *lsa)
{
  u_char *start, *end, *current;
  char byte[4];

  start = (char *) lsa->header;
  end = (char *) lsa->header + ntohs (lsa->header->length);

  vty_out (vty, "%s", VTY_NEWLINE);
  vty_out (vty, "%s:%s", lsa->str, VTY_NEWLINE);

  for (current = start; current < end; current ++)
    {
      if ((current - start) % 16 == 0)
        vty_out (vty, "%s        ", VTY_NEWLINE);
      else if ((current - start) % 4 == 0)
        vty_out (vty, " ");

      snprintf (byte, sizeof (byte), "%02x", *current);
      vty_out (vty, "%s", byte);
    }

  vty_out (vty, "%s%s", VTY_NEWLINE, VTY_NEWLINE);
}

/* OSPFv3 LSA creation/deletion function */

/* calculate LS sequence number for my new LSA.
   return value is network byte order */
static signed long
ospf6_lsa_seqnum_new (u_int16_t type, u_int32_t id, u_int32_t adv_router,
                      void *scope)
{
  struct ospf6_lsa *lsa;
  signed long seqnum;

  /* get current database copy */
  lsa = ospf6_lsdb_lookup (type, id, adv_router, scope);

  /* if current database copy not found, return InitialSequenceNumber */
  if (!lsa)
    seqnum = INITIAL_SEQUENCE_NUMBER;
  else
    seqnum = (signed long) ntohl (lsa->header->seqnum) + 1;

  return (htonl (seqnum));
}

#if 0
static void
ospf6_lsa_header_set (u_int16_t type, u_int32_t ls_id, u_int32_t advrtr,
                      struct ospf6_lsa_header *lsa_header, int bodysize)
{
  /* fill LSA header */
  lsa_header->age = 0;
  lsa_header->type = type;
  lsa_header->ls_id = ls_id;
  lsa_header->advrtr = advrtr;
  lsa_header->seqnum =
    ospf6_lsa_seqnum_new (lsa_header->type, lsa_header->ls_id,
                          lsa_header->advrtr);
  lsa_header->length = htons (sizeof (struct ospf6_lsa_header) + bodysize);

  /* LSA checksum */
  ospf6_lsa_checksum (lsa_header);
}
#endif /*0*/

struct ospf6_lsa *
ospf6_lsa_create (struct ospf6_lsa_header *source)
{
  struct ospf6_lsa *lsa = NULL;
  struct ospf6_lsa_header *lsa_header = NULL;
  u_int16_t lsa_size = 0;
  char buf_router[16], buf_id[16], typebuf[32];

  /* whole length of this LSA */
  lsa_size = ntohs (source->length);

  /* allocate memory for this LSA */
  lsa_header = (struct ospf6_lsa_header *)
    XMALLOC (MTYPE_OSPF6_LSA, lsa_size);
  if (! lsa_header)
    {
      zlog_err ("Can't allocate memory for LSA Header");
      return (struct ospf6_lsa *) NULL;
    }
  memset (lsa_header, 0, lsa_size);

  /* copy LSA from source */
  memcpy (lsa_header, source, lsa_size);

  /* LSA information structure */
  /* allocate memory */
  lsa = (struct ospf6_lsa *)
          XMALLOC (MTYPE_OSPF6_LSA, sizeof (struct ospf6_lsa));
  memset (lsa, 0, sizeof (struct ospf6_lsa));

  lsa->lsa_hdr = (struct ospf6_lsa_hdr *) lsa_header;
  lsa->header = (struct ospf6_lsa_header__ *) lsa_header;

  lsa->summary = 0; /* this is not LSA summary */

  /* dump string */
  inet_ntop (AF_INET, &lsa->header->id, buf_id, sizeof (buf_id));
  inet_ntop (AF_INET, &lsa->header->adv_router, buf_router,
             sizeof (buf_router));
  snprintf (lsa->str, sizeof (lsa->str), "[%s ID=%s Adv=%s]",
            ospf6_lsa_type_string (lsa_header->type, typebuf,
                                   sizeof (typebuf)),
            buf_id, buf_router);

  /* calculate birth, expire and refresh of this lsa */
  ospf6_lsa_age_set (lsa);

#ifdef DEBUG
  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("Create: %s (%p/%p)", lsa->str, lsa, lsa->header);
#endif /*DEBUG*/

  return lsa;
}

struct ospf6_lsa *
ospf6_lsa_summary_create (struct ospf6_lsa_header__ *source)
{
  struct ospf6_lsa *lsa = NULL;
  struct ospf6_lsa_header *lsa_header = NULL;
  u_int16_t lsa_size = 0;
  char buf_router[16], buf_id[16], typebuf[16];

  /* LSA summary contains LSA Header only */
  lsa_size = sizeof (struct ospf6_lsa_header);

  /* allocate memory for this LSA */
  lsa_header = (struct ospf6_lsa_header *)
    XMALLOC (MTYPE_OSPF6_LSA_SUMMARY, lsa_size);
  memset (lsa_header, 0, lsa_size);

  /* copy LSA from source */
  memcpy (lsa_header, source, lsa_size);

  /* LSA information structure */
  /* allocate memory */
  lsa = (struct ospf6_lsa *)
          XMALLOC (MTYPE_OSPF6_LSA_SUMMARY, sizeof (struct ospf6_lsa));
  memset (lsa, 0, sizeof (struct ospf6_lsa));

  lsa->lsa_hdr = (struct ospf6_lsa_hdr *) lsa_header;
  lsa->header = (struct ospf6_lsa_header__ *) lsa_header;
  lsa->summary = 1; /* this is LSA summary */

  /* dump string */
  inet_ntop (AF_INET, &lsa->header->id, buf_id, sizeof (buf_id));
  inet_ntop (AF_INET, &lsa->header->adv_router, buf_router,
             sizeof (buf_router));
  snprintf (lsa->str, sizeof (lsa->str), "[%s Summary ID=%s Adv=%s]",
            ospf6_lsa_type_string (lsa->header->type, typebuf,
                                   sizeof (typebuf)),
            buf_id, buf_router);

  /* calculate birth, expire and refresh of this lsa */
  ospf6_lsa_age_set (lsa);

#ifdef DEBUG
  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("Create: %s (%p/%p)", lsa->str, lsa, lsa->header);
#endif /*DEBUG*/

  return lsa;
}

void
ospf6_lsa_delete (struct ospf6_lsa *lsa)
{
  /* just to make sure */
  if (lsa->lock != 0)
    {
      zlog_err ("Can't delete %s: lock: %ld", lsa->str, lsa->lock);
      return;
    }

  /* cancel threads */
  if (lsa->expire)
    thread_cancel (lsa->expire);
  lsa->expire = (struct thread *) NULL;
  if (lsa->refresh)
    thread_cancel (lsa->refresh);
  lsa->refresh = (struct thread *) NULL;

#ifdef DEBUG
  if (IS_OSPF6_DUMP_LSA)
      zlog_info ("Delete %s (%p/%p)", lsa->str, lsa, lsa->header);
#endif /*DEBUG*/

  /* do free */
  if (lsa->summary)
    XFREE (MTYPE_OSPF6_LSA_SUMMARY, lsa->header);
  else
    XFREE (MTYPE_OSPF6_LSA, lsa->header);
  lsa->header = NULL;

  if (lsa->summary)
    XFREE (MTYPE_OSPF6_LSA_SUMMARY, lsa);
  else
    XFREE (MTYPE_OSPF6_LSA, lsa);
}

/* increment reference counter of  struct ospf6_lsa */
void
ospf6_lsa_lock (struct ospf6_lsa *lsa)
{
  lsa->lock++;
  return;
}

/* decrement reference counter of  struct ospf6_lsa */
void
ospf6_lsa_unlock (struct ospf6_lsa *lsa)
{
  /* decrement reference counter */
  if (lsa->lock > 0)
    lsa->lock--;
  else
    zlog_warn ("Can't unlock %s: already no lock", lsa->str);

  if (lsa->lock == 0)
    ospf6_lsa_delete (lsa);
}

void
ospf6_lsa_originate (u_int16_t type, u_int32_t id, u_int32_t adv_router,
                     char *data, int data_len, void *scope)
{
  char buffer[MAXLSASIZE];
  struct ospf6_lsa_header *lsa_header;
  struct ospf6_lsa *lsa;
  struct ospf6_lsa *old;

  assert (data_len <= sizeof (buffer) - sizeof (struct ospf6_lsa_header));

  lsa_header = (struct ospf6_lsa_header *) buffer;

  /* Copy LSA Body */
  memcpy (buffer + sizeof (struct ospf6_lsa_header), data, data_len);

  /* Fill LSA Header */
  lsa_header->age = 0;
  lsa_header->type = type;
  lsa_header->ls_id = id;
  lsa_header->advrtr = adv_router;
  lsa_header->seqnum =
    ospf6_lsa_seqnum_new (lsa_header->type, lsa_header->ls_id,
                          lsa_header->advrtr, scope);
  lsa_header->length = htons (sizeof (struct ospf6_lsa_header) + data_len);

  /* LSA checksum */
  ospf6_lsa_checksum (lsa_header);

  /* create LSA */
  lsa = ospf6_lsa_create ((struct ospf6_lsa_header *) buffer);
  lsa->scope = scope;

  /* find previous LSA */
  old = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                           lsa->header->adv_router, lsa->scope);
  if (old)
    {
      /* Check if this is neither different instance nor refresh, return */
      if (! CHECK_FLAG (old->flag, OSPF6_LSA_FLAG_REFRESH) &&
          ! ospf6_lsa_differ (lsa, old))
        {
          if (IS_OSPF6_DUMP_LSA)
            zlog_info ("LSA: Suppress updating %s", lsa->str);
          ospf6_lsa_delete (lsa);
          return;
        }
    }

  lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh, lsa,
                                   OSPF6_LS_REFRESH_TIME);
  gettimeofday (&lsa->originated, NULL);

  //if (IS_OSPF6_DUMP_LSA)
    zlog_info ("LSA: originate %s seq: %#x age: %hu %ld.%06ld",
               lsa->str, ntohl (lsa->header->seqnum),
               ospf6_lsa_age_current (lsa),
               lsa->originated.tv_sec, lsa->originated.tv_usec);

  ospf6_dbex_remove_from_all_retrans_list (lsa);
  ospf6_dbex_flood (lsa, NULL);
  ospf6_lsdb_install (lsa);
}


/* ospf6_lsa expired */
int
ospf6_lsa_expire (struct thread *thread)
{
  struct ospf6_lsa *lsa;
  struct ospf6_lsdb *lsdb = NULL;
  void (*hook) (struct ospf6_lsa *, struct ospf6_lsa *);

  lsa = (struct ospf6_lsa *) THREAD_ARG (thread);
  assert (lsa && lsa->lsa_hdr);

  /* assertion */
  assert (IS_LSA_MAXAGE (lsa));
  assert (!lsa->refresh);

  lsa->expire = (struct thread *) NULL;

  /* log */
  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("LSA: Expire: %s", lsa->str);

  if (!lsa->summary)
    {
      /* reflood lsa */
      ospf6_dbex_flood (lsa, NULL);

      /* get scoped lsdb, call remove hook */
      if (OSPF6_LSA_IS_SCOPE_LINKLOCAL (ntohs (lsa->header->type)))
        lsdb = ((struct ospf6_interface *) lsa->scope)->lsdb;
      else if (OSPF6_LSA_IS_SCOPE_AREA (ntohs (lsa->header->type)))
        lsdb = ((struct ospf6_area *) lsa->scope)->lsdb;
      else if (OSPF6_LSA_IS_SCOPE_AS (ntohs (lsa->header->type)))
        lsdb = ((struct ospf6 *) lsa->scope)->lsdb;
      else
        assert (0);

      /* call LSDB hook to re-process LSA */
      hook = ospf6_lsdb_hook[ntohs (lsa->header->type) &
                             OSPF6_LSTYPE_CODE_MASK].hook;
      if (hook)
        (*hook) (NULL, lsa);

      /* do not free LSA, and do nothing about lslists.
         wait event (ospf6_lsdb_check_maxage) */
    }

  return 0;
}

int
ospf6_lsa_refresh (struct thread *thread)
{
  struct ospf6_lsa *lsa;
  struct ospf6_lsa_slot *slot;

  assert (thread);
  lsa = (struct ospf6_lsa *) THREAD_ARG  (thread);
  assert (lsa && lsa->lsa_hdr);

  /* this will be used later as flag to decide really originate */
  lsa->refresh = (struct thread *) NULL;
  SET_FLAG (lsa->flag, OSPF6_LSA_FLAG_REFRESH);

  /* log */
  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("LSA Refresh: %s", lsa->str);

  slot = ospf6_lsa_slot_get (lsa->header->type);
  if (slot)
    {
      zlog_info ("LSA Refresh: %s", slot->name);
      (*slot->func_refresh) (lsa);
      return 0;
    }

  zlog_warn ("Can't Refresh LSA: Unknown type: %#x",
             ntohs (lsa->header->type));
  return 1;
}



/* enhanced Fletcher checksum algorithm, RFC1008 7.2 */
#define MODX                4102
#define LSA_CHECKSUM_OFFSET   15

unsigned short
ospf6_lsa_checksum (struct ospf6_lsa_header *lsa_header)
{
  u_char *sp, *ep, *p, *q;
  int c0 = 0, c1 = 0;
  int x, y;
  u_int16_t length;

  lsa_header->checksum = 0;
  length = ntohs (lsa_header->length) - 2;
  sp = (char *) &lsa_header->type;

  for (ep = sp + length; sp < ep; sp = q)
    {
      q = sp + MODX;
      if (q > ep)
        q = ep;
      for (p = sp; p < q; p++)
        {
          c0 += *p;
          c1 += c0;
        }
      c0 %= 255;
      c1 %= 255;
    }

  /* r = (c1 << 8) + c0; */
  x = ((length - LSA_CHECKSUM_OFFSET) * c0 - c1) % 255;
  if (x <= 0)
    x += 255;
  y = 510 - c0 - x;
  if (y > 255)
    y -= 255;

  lsa_header->checksum = htons ((x << 8) + y);

  return (lsa_header->checksum);
}

int
ospf6_lsa_is_known_type (struct ospf6_lsa_header *lsa_header)
{
  struct ospf6_lsa_slot *slot;

  slot = ospf6_lsa_slot_get (lsa_header->type);
  if (slot)
    return 1;
  return 0;
}

struct ospf6_lsa_slot *slot_head = NULL;

struct ospf6_lsa_slot *
ospf6_lsa_slot_get (u_int16_t type)
{
  struct ospf6_lsa_slot *slot;

  for (slot = slot_head; slot; slot = slot->next)
    {
      if (slot->type == type)
        return slot;
    }

  return NULL;
}

int
ospf6_lsa_slot_register (struct ospf6_lsa_slot *src)
{
  struct ospf6_lsa_slot *new, *slot;

  slot = ospf6_lsa_slot_get (src->type);
  if (slot)
    {
      if (IS_OSPF6_DUMP_LSA)
        zlog_info ("LSA: Slot register: already exists: %#x %s",
                   slot->type, slot->name);
      return -1;
    }

  new = (struct ospf6_lsa_slot *)
    XMALLOC (MTYPE_OSPF6_LSA, sizeof (struct ospf6_lsa_slot));
  if (! new)
    {
      zlog_err ("Can't allocate memory for LSA slot: %s", strerror (errno));
      return -1;
    }
  memset (new, 0, sizeof (struct ospf6_lsa_slot));
  memcpy (new, src, sizeof (struct ospf6_lsa_slot));

  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("LSA: Slot register: %#x %s", slot->type, slot->name);

  if (slot_head == NULL)
    {
      new->prev = NULL;
      new->next = NULL;
      slot_head = new;
      return 0;
    }

  slot = slot_head;
  while (slot->next)
    slot = slot->next;

  slot->next = new;
  new->prev = slot;

  return 0;
}

int
ospf6_lsa_slot_unregister (u_int16_t type)
{
  struct ospf6_lsa_slot *slot;

  slot = ospf6_lsa_slot_get (type);
  if (slot == NULL)
    {
      if (IS_OSPF6_DUMP_LSA)
        zlog_info ("Registering LSA slot: no such slot: %#x", type);
      return -1;
    }

  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("Unregistering LSA Slot: %#x %s", slot->type, slot->name);

  if (slot->prev)
    slot->prev->next = slot->next;
  if (slot->next)
    slot->next->prev = slot->prev;

  if (slot_head == slot)
    slot_head = slot->next;

  XFREE (MTYPE_OSPF6_LSA, slot);
  return 0;
}

char *
ospf6_lsa_type_string (u_int16_t type, char *buf, int bufsize)
{
  struct ospf6_lsa_slot *slot;

  slot = ospf6_lsa_slot_get (type);
  if (slot)
    snprintf (buf, bufsize, "%s", slot->name);
  else
    snprintf (buf, bufsize, "Type=0x%04x", ntohs (type));

  return buf;
}


/*******************/
/* LSA Origination */
/*******************/

#define CONTINUE_IF_ADDRESS_LINKLOCAL(addr)\
  if (IN6_IS_ADDR_LINKLOCAL (&(addr)->u.prefix6))\
    {\
      char buf[64];\
      prefix2str (addr, buf, sizeof (buf));\
      if (IS_OSPF6_DUMP_LSA)\
        zlog_info ("  Filter out Linklocal: %s", buf);\
      continue;\
    }

#define CONTINUE_IF_ADDRESS_UNSPECIFIED(addr)\
  if (IN6_IS_ADDR_UNSPECIFIED (&(addr)->u.prefix6))\
    {\
      char buf[64];\
      prefix2str (addr, buf, sizeof (buf));\
      if (IS_OSPF6_DUMP_LSA)\
        zlog_info ("  Filter out Unspecified: %s", buf);\
      continue;\
    }

#define CONTINUE_IF_ADDRESS_LOOPBACK(addr)\
  if (IN6_IS_ADDR_LOOPBACK (&(addr)->u.prefix6))\
    {\
      char buf[64];\
      prefix2str (addr, buf, sizeof (buf));\
      if (IS_OSPF6_DUMP_LSA)\
        zlog_info ("  Filter out Loopback: %s", buf);\
      continue;\
    }

#define CONTINUE_IF_ADDRESS_V4COMPAT(addr)\
  if (IN6_IS_ADDR_V4COMPAT (&(addr)->u.prefix6))\
    {\
      char buf[64];\
      prefix2str (addr, buf, sizeof (buf));\
      if (IS_OSPF6_DUMP_LSA)\
        zlog_info ("  Filter out V4Compat: %s", buf);\
      continue;\
    }

#define CONTINUE_IF_ADDRESS_V4MAPPED(addr)\
  if (IN6_IS_ADDR_V4MAPPED (&(addr)->u.prefix6))\
    {\
      char buf[64];\
      prefix2str (addr, buf, sizeof (buf));\
      if (IS_OSPF6_DUMP_LSA)\
        zlog_info ("  Filter out V4Mapped: %s", buf);\
      continue;\
    }

/******************************/
/* RFC2740 3.4.3.1 Router-LSA */
/******************************/

char *
ospf6_lsa_router_bits_string (u_char router_bits, char *buf, int size)
{
  char w, v, e, b;

  w = (router_bits & OSPF6_ROUTER_LSA_BIT_W ? 'W' : '-');
  v = (router_bits & OSPF6_ROUTER_LSA_BIT_V ? 'V' : '-');
  e = (router_bits & OSPF6_ROUTER_LSA_BIT_E ? 'E' : '-');
  b = (router_bits & OSPF6_ROUTER_LSA_BIT_B ? 'B' : '-');
  snprintf (buf, size, "----%c%c%c%c", w, v, e, b);
  return buf;
}

int
ospf6_lsa_router_show (struct vty *vty, struct ospf6_lsa *lsa)
{
  char *start, *end, *current;
  char buf[32], name[32], bits[32], options[32];
  struct ospf6_router_lsa *router_lsa;
  struct ospf6_router_lsd *lsdesc;

  assert (lsa->header);

  router_lsa = (struct ospf6_router_lsa *)
    ((char *) lsa->header + sizeof (struct ospf6_lsa_header));

  ospf6_lsa_router_bits_string (router_lsa->bits, bits, sizeof (bits));
  ospf6_options_string (router_lsa->options, options, sizeof (options));
  vty_out (vty, "    Bits: %s Options: %s%s", bits, options, VTY_NEWLINE);

  start = (char *) router_lsa + sizeof (struct ospf6_router_lsa);
  end = (char *) lsa->header + ntohs (lsa->header->length);
  for (current = start; current + sizeof (struct ospf6_router_lsd) <= end;
       current += sizeof (struct ospf6_router_lsd))
    {
      lsdesc = (struct ospf6_router_lsd *) current;

      if (lsdesc->type == OSPF6_ROUTER_LSD_TYPE_POINTTOPOINT)
        snprintf (name, sizeof (name), "Point-To-Point");
      else if (lsdesc->type == OSPF6_ROUTER_LSD_TYPE_TRANSIT_NETWORK)
        snprintf (name, sizeof (name), "Transit-Network");
      else if (lsdesc->type == OSPF6_ROUTER_LSD_TYPE_STUB_NETWORK)
        snprintf (name, sizeof (name), "Stub-Network");
      else if (lsdesc->type == OSPF6_ROUTER_LSD_TYPE_VIRTUAL_LINK)
        snprintf (name, sizeof (name), "Virtual-Link");
      else
        snprintf (name, sizeof (name), "Unknown (%#x)", lsdesc->type);

      vty_out (vty, "    Type: %s Metric: %d%s",
               name, ntohs (lsdesc->metric), VTY_NEWLINE);
      vty_out (vty, "    Interface ID: %s%s",
               inet_ntop (AF_INET, &lsdesc->interface_id,
                          buf, sizeof (buf)), VTY_NEWLINE);
      vty_out (vty, "    Neighbor Interface ID: %s%s",
               inet_ntop (AF_INET, &lsdesc->neighbor_interface_id,
                          buf, sizeof (buf)), VTY_NEWLINE);
      vty_out (vty, "    Neighbor Router ID: %s%s",
               inet_ntop (AF_INET, &lsdesc->neighbor_router_id,
                          buf, sizeof (buf)), VTY_NEWLINE);
    }
  return 0;
}

u_long
ospf6_lsa_has_elasped (u_int16_t type, u_int32_t id,
                       u_int32_t adv_router, void *scope)
{
  struct ospf6_lsa *old;
  struct timeval now;

  if (adv_router != ospf6->router_id)
    zlog_info ("LSA: Router-ID changed ?");

  old = ospf6_lsdb_lookup (type, id, adv_router, scope);
  if (! old)
    return OSPF6_LSA_MAXAGE;

  gettimeofday (&now, NULL);
  return ((u_long) SEC_TVDIFF (&now, &old->originated));
}

int
ospf6_lsa_originate_router (struct thread *thread)
{
  char buffer [MAXLSASIZE];
  u_int16_t size;
  struct ospf6_area *o6a;
  int count;
  u_int32_t area_id;

  struct ospf6_router_lsa *router_lsa;
  struct ospf6_router_lsd *router_lsd;
  listnode i;
  struct ospf6_interface *o6i;
  struct ospf6_neighbor *o6n = NULL;

  area_id = (u_int32_t) THREAD_ARG (thread);

  o6a = ospf6_area_lookup (area_id, ospf6);
  if (! o6a)
    {
      inet_ntop (AF_INET, &area_id, buffer, sizeof (buffer));
      if (IS_OSPF6_DUMP_LSA)
        zlog_info ("LSA: Update Router-LSA: No such area: %s", buffer);
      return 0;
    }

  /* clear thread */
  o6a->thread_router_lsa = NULL;

  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("LSA: originate Router-LSA for Area %s", o6a->str);

  size = sizeof (struct ospf6_router_lsa);
  memset (buffer, 0, sizeof (buffer));
  router_lsa = (struct ospf6_router_lsa *) buffer;

  OSPF6_OPT_CLEAR_ALL (router_lsa->options);
  OSPF6_OPT_SET (router_lsa->options, OSPF6_OPT_V6);
  OSPF6_OPT_SET (router_lsa->options, OSPF6_OPT_E);
  OSPF6_OPT_CLEAR (router_lsa->options, OSPF6_OPT_MC);
  OSPF6_OPT_CLEAR (router_lsa->options, OSPF6_OPT_N);
  OSPF6_OPT_SET (router_lsa->options, OSPF6_OPT_R);
  OSPF6_OPT_CLEAR (router_lsa->options, OSPF6_OPT_DC);

  OSPF6_ROUTER_LSA_CLEAR_ALL_BITS (router_lsa);
  OSPF6_ROUTER_LSA_CLEAR (router_lsa, OSPF6_ROUTER_LSA_BIT_B);

  if (ospf6_is_asbr (o6a->ospf6))
    OSPF6_ROUTER_LSA_SET (router_lsa, OSPF6_ROUTER_LSA_BIT_E);
  else
    OSPF6_ROUTER_LSA_CLEAR (router_lsa, OSPF6_ROUTER_LSA_BIT_E);

  OSPF6_ROUTER_LSA_CLEAR (router_lsa, OSPF6_ROUTER_LSA_BIT_V);
  OSPF6_ROUTER_LSA_CLEAR (router_lsa, OSPF6_ROUTER_LSA_BIT_W);

  /* describe links for each interfaces */
  router_lsd = (struct ospf6_router_lsd *) (router_lsa + 1);
  for (i = listhead (o6a->if_list); i; nextnode (i))
    {
      o6i = (struct ospf6_interface *) getdata (i);
      assert (o6i);

      /* Interfaces in state Down or Loopback are not described */
      if (o6i->state == IFS_DOWN || o6i->state == IFS_LOOPBACK)
        continue;

      /* Nor are interfaces without any full adjacencies described */
      count = 0;
      o6i->foreach_nei (o6i, &count, NBS_FULL, ospf6_count_state);
      if (count == 0)
        continue;

      /* Point-to-Point interfaces */
      if (if_is_pointopoint (o6i->interface))
        {
          if (listcount (o6i->neighbor_list) == 0)
            continue;

          if (listcount (o6i->neighbor_list) != 1)
            zlog_warn ("LSA: Multiple neighbors on PoinToPoint: %s",
                       o6i->interface->name);

          o6n = (struct ospf6_neighbor *)
                   getdata (listhead (o6i->neighbor_list));
          assert (o6n);

          router_lsd->type = OSPF6_ROUTER_LSD_TYPE_POINTTOPOINT;
          router_lsd->metric = htons (o6i->cost);
          router_lsd->interface_id = htonl (o6i->if_id);
          router_lsd->neighbor_interface_id = htonl (o6n->ifid);
          router_lsd->neighbor_router_id = o6n->router_id;

          size += sizeof (struct ospf6_router_lsd);
          router_lsd ++;

          continue;
        }

      /* Broadcast and NBMA interfaces */
      if (if_is_broadcast (o6i->interface))
        {
          /* If this router is not DR,
             and If this router not fully adjacent with DR,
             this interface is not transit yet: ignore. */
          if (o6i->state != IFS_DR)
            {
              o6n = ospf6_neighbor_lookup (o6i->dr, o6i); /* find DR */
              if (o6n == NULL || o6n->state != NBS_FULL)
                continue;
            }
          else
            {
              count = 0;
              o6i->foreach_nei (o6i, &count, NBS_FULL, ospf6_count_state);
              if (count == 0)
                continue;
            }

          router_lsd->type = OSPF6_ROUTER_LSD_TYPE_TRANSIT_NETWORK;
          router_lsd->metric = htons (o6i->cost);
          router_lsd->interface_id = htonl (o6i->if_id);
          if (o6i->state != IFS_DR)
            {
              router_lsd->neighbor_interface_id = htonl (o6n->ifid);
              router_lsd->neighbor_router_id = o6n->router_id;
            }
          else
            {
              router_lsd->neighbor_interface_id = htonl (o6i->if_id);
              router_lsd->neighbor_router_id = o6i->area->ospf6->router_id;
            }

          size += sizeof (struct ospf6_router_lsd);
          router_lsd ++;

          continue;
        }

      /* Virtual links */
        /* xxx */
      /* Point-to-Multipoint interfaces */
        /* xxx */
    }

  ospf6_lsa_originate (htons (OSPF6_LSA_TYPE_ROUTER),
                       htonl (0), o6a->ospf6->router_id,
                       (char *) router_lsa, size, o6a);
  return 0;
}

void
ospf6_lsa_schedule_router (struct ospf6_area *area)
{
  u_long elasped_time, time = 0;

  if (area->thread_router_lsa)
    {
      if (IS_OSPF6_DUMP_LSA)
        zlog_info ("LSA: schedule: Router-LSA for Area %s: another thread",
                   area->str);
      return;
    }

  elasped_time =
    ospf6_lsa_has_elasped (htons (OSPF6_LSA_TYPE_ROUTER), htonl (0),
                           area->ospf6->router_id, area);
  if (elasped_time < OSPF6_MIN_LS_INTERVAL)
    time = (u_long) (OSPF6_MIN_LS_INTERVAL - elasped_time);
  else
    time = 0;

  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("LSA: schedule: Router-LSA for Area %s after %lu sec",
               area->str, time);

  if (time)
    area->thread_router_lsa =
      thread_add_timer (master, ospf6_lsa_originate_router,
                        (void *) area->area_id, time);
  else
    area->thread_router_lsa =
      thread_add_event (master, ospf6_lsa_originate_router,
                        (void *) area->area_id, 0);
}

int
ospf6_lsa_router_hook_neighbor (void *neighbor)
{
  struct ospf6_neighbor *o6n = neighbor;
  if (o6n->ospf6_interface->area)
    ospf6_lsa_schedule_router (o6n->ospf6_interface->area);
  return 0;
}

int
ospf6_lsa_router_hook_interface (void *interface)
{
  struct ospf6_interface *o6i = interface;
  if (o6i->area)
    ospf6_lsa_schedule_router (o6i->area);
  return 0;
}

int
ospf6_lsa_router_hook_area (void *area)
{
  struct ospf6_area *o6a = area;
  ospf6_lsa_schedule_router (o6a);
  return 0;
}

int
ospf6_lsa_router_hook_top (void *ospf6)
{
  struct ospf6 *o6 = ospf6;
  struct ospf6_area *o6a;
  listnode node;

  for (node = listhead (o6->area_list); node; nextnode (node))
    {
      o6a = getdata (node);
      ospf6_lsa_schedule_router (o6a);
    }
  return 0;
}

int
ospf6_lsa_router_refresh (void *old)
{
  struct ospf6_lsa *lsa = old;
  struct ospf6_area *o6a;

  o6a = lsa->scope;
  ospf6_lsa_schedule_router (o6a);
  return 0;
}

void
ospf6_lsa_slot_register_router ()
{
  struct ospf6_lsa_slot slot;
  struct ospf6_hook hook;

  memset (&slot, 0, sizeof (struct ospf6_lsa_slot));
  slot.type              = htons (OSPF6_LSA_TYPE_ROUTER);
  slot.name              = "Router";
  slot.func_show         = ospf6_lsa_router_show;
  slot.func_refresh      = ospf6_lsa_router_refresh;
  ospf6_lsa_slot_register (&slot);

  ospf6_lsdb_hook[OSPF6_LSA_TYPE_ROUTER & OSPF6_LSTYPE_CODE_MASK].hook = 
    ospf6_spf_database_hook;

  memset (&hook, 0, sizeof (hook));
  hook.name = "OriginateRouter";
  hook.hook_change  = ospf6_lsa_router_hook_neighbor;
  ospf6_hook_register (&hook, &neighbor_hook);

  memset (&hook, 0, sizeof (hook));
  hook.name = "OriginateRouter";
  hook.hook_change = ospf6_lsa_router_hook_interface;
  ospf6_hook_register (&hook, &interface_hook);

  memset (&hook, 0, sizeof (hook));
  hook.name = "OriginateRouter";
  hook.hook_change      = ospf6_lsa_router_hook_area;
  ospf6_hook_register (&hook, &area_hook);

  memset (&hook, 0, sizeof (hook));
  hook.name = "OriginateRouter";
  hook.hook_change       = ospf6_lsa_router_hook_top;
  ospf6_hook_register (&hook, &top_hook);
}

/*******************************/
/* RFC2740 3.4.3.2 Network-LSA */
/*******************************/

int
ospf6_lsa_network_show (struct vty *vty, struct ospf6_lsa *lsa)
{
  char *start, *end, *current;
  struct ospf6_network_lsa *network_lsa;
  u_int32_t *router_id;
  char buf[128], options[32];

  assert (lsa->header);
  network_lsa = (struct ospf6_network_lsa *) (lsa->header + 1);
  router_id = (u_int32_t *)(network_lsa + 1);

  ospf6_options_string (network_lsa->options, options, sizeof (options));
  vty_out (vty, "     Options: %s%s", options, VTY_NEWLINE);

  start = (char *) network_lsa + sizeof (struct ospf6_network_lsa);
  end = (char *) lsa->header + ntohs (lsa->header->length);
  for (current = start; current + sizeof (u_int32_t) <= end;
       current += sizeof (u_int32_t))
    {
      router_id = (u_int32_t *) current;
      inet_ntop (AF_INET, router_id, buf, sizeof (buf));
      vty_out (vty, "     Attached Router: %s%s", buf, VTY_NEWLINE);
    }
  return 0;
}

void
ospf6_lsa_network_update (char *ifname)
{
  char buffer [MAXLSASIZE];
  u_int16_t size;
  struct ospf6_lsa *old;
  struct interface *ifp;
  struct ospf6_interface *o6i;
  int count;

  struct ospf6_network_lsa *network_lsa;
  struct ospf6_neighbor *o6n;
  u_int32_t *router_id;
  listnode node;

  ifp = if_lookup_by_name (ifname);
  if (! ifp)
    {
      if (IS_OSPF6_DUMP_LSA)
        zlog_warn ("Update Network: No such Interface: %s", ifname);
      return;
    }

  o6i = (struct ospf6_interface *) ifp->info;
  if (! o6i || ! o6i->area)
    {
      if (IS_OSPF6_DUMP_LSA)
        zlog_warn ("Update Network: Interface not enabled: %s", ifname);
      return;
    }

  /* find previous LSA */
  old = ospf6_lsdb_lookup (htons (OSPF6_LSA_TYPE_NETWORK),
                           htonl (o6i->if_id),
                           o6i->area->ospf6->router_id, o6i->area);

  /* Don't originate Network-LSA if not DR */
  if (o6i->state != IFS_DR)
    {
      if (IS_OSPF6_DUMP_LSA)
        zlog_info ("Update Network: Interface %s is not DR",
                   o6i->interface->name);
      if (old)
        ospf6_lsa_premature_aging (old);
      return;
    }

  /* If none of neighbor is adjacent to us */
  count = 0;
  o6i->foreach_nei (o6i, &count, NBS_FULL, ospf6_count_state);
  if (count == 0)
    {
      if (IS_OSPF6_DUMP_LSA)
        zlog_info ("Update Network: Interface %s is Stub",
                   o6i->interface->name);
      if (old)
        ospf6_lsa_premature_aging (old);
      return;
    }

  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("Update Network: Interface %s", o6i->interface->name);

  /* prepare buffer */
  memset (buffer, 0, sizeof (buffer));
  size = sizeof (struct ospf6_network_lsa);
  network_lsa = (struct ospf6_network_lsa *) buffer;
  router_id = (u_int32_t *)(network_lsa + 1);

  /* set fields of myself */
  *router_id++ = o6i->area->ospf6->router_id;
  size += sizeof (u_int32_t);
  network_lsa->options[0] |= o6i->area->options[0];
  network_lsa->options[1] |= o6i->area->options[1];
  network_lsa->options[2] |= o6i->area->options[2];

  /* Walk through neighbors */
  for (node = listhead (o6i->neighbor_list); node; nextnode (node))
    {
      o6n = (struct ospf6_neighbor *) getdata (node);

      if (o6n->state != NBS_FULL)
        continue;

      /* set this neighbor's Router-ID to LSA */
      *router_id++ = o6n->router_id;
      size += sizeof (u_int32_t);

      /* options field is logical OR */
      network_lsa->options[0] |= o6n->options[0];
      network_lsa->options[1] |= o6n->options[1];
      network_lsa->options[2] |= o6n->options[2];
    }

  ospf6_lsa_originate (htons (OSPF6_LSA_TYPE_NETWORK),
                       htonl (o6i->if_id), o6i->area->ospf6->router_id,
                       (char *) network_lsa, size, o6i->area);
}

int
ospf6_lsa_network_hook_neighbor (void *neighbor)
{
  struct ospf6_neighbor *o6n = neighbor;
  ospf6_lsa_network_update (o6n->ospf6_interface->interface->name);
  return 0;
}

int
ospf6_lsa_network_hook_interface (void *interface)
{
  struct ospf6_interface *o6i = interface;
  if (o6i->area)
    ospf6_lsa_network_update (o6i->interface->name);
  return 0;
}

int
ospf6_lsa_network_refresh (void *old)
{
  struct ospf6_lsa *lsa = old;
  struct interface *ifp;

  ifp = if_lookup_by_index (ntohl (lsa->header->id));
  if (! ifp)
    ospf6_lsa_premature_aging (old);
  else
    ospf6_lsa_network_update (ifp->name);

  return 0;
}

void
ospf6_lsa_slot_register_network ()
{
  struct ospf6_lsa_slot slot;
  struct ospf6_hook hook;

  memset (&slot, 0, sizeof (struct ospf6_lsa_slot));
  slot.type              = htons (OSPF6_LSA_TYPE_NETWORK);
  slot.name              = "Network";
  slot.func_show         = ospf6_lsa_network_show;
  slot.func_refresh      = ospf6_lsa_network_refresh;
  ospf6_lsa_slot_register (&slot);

  ospf6_lsdb_hook[OSPF6_LSA_TYPE_NETWORK & OSPF6_LSTYPE_CODE_MASK].hook = 
    ospf6_spf_database_hook;

  memset (&hook, 0, sizeof (hook));
  hook.name  = "OriginateNetwork";
  hook.hook_change  = ospf6_lsa_network_hook_neighbor;
  ospf6_hook_register (&hook, &neighbor_hook);

  memset (&hook, 0, sizeof (hook));
  hook.name  = "OriginateNetwork";
  hook.hook_change = ospf6_lsa_network_hook_interface;
  ospf6_hook_register (&hook, &interface_hook);
}

/****************************/
/* RFC2740 3.4.3.6 Link-LSA */
/****************************/

int
ospf6_lsa_link_show (struct vty *vty, struct ospf6_lsa *lsa)
{
  char *start, *end, *current;
  struct ospf6_link_lsa *link_lsa;
  int prefixnum;
  struct ospf6_prefix *prefix;
  char buf[128];
  struct in6_addr in6;

  assert (lsa->header);

  link_lsa = (struct ospf6_link_lsa *) (lsa->header + 1);
  prefixnum = ntohl (link_lsa->llsa_prefix_num);

  inet_ntop (AF_INET6, (void *)&link_lsa->llsa_linklocal, buf, sizeof (buf));
  vty_out (vty, "     LinkLocal Address: %s%s", buf, VTY_NEWLINE);
  vty_out (vty, "     Number of Prefix: %d%s", prefixnum, VTY_NEWLINE);

  start = (char *) link_lsa + sizeof (struct ospf6_link_lsa);
  end = (char *) lsa->header + ntohs (lsa->header->length); 
  for (current = start; current < end; current += OSPF6_PREFIX_SIZE (prefix))
    {
      prefix = (struct ospf6_prefix *) current;
      if (current + OSPF6_PREFIX_SIZE (prefix) > end)
        {
          vty_out (vty, "    Trailing %d byte garbage ... Malformed%s",
                   end - current, VTY_NEWLINE);
          return -1;
        }

      ospf6_prefix_options_str (prefix->prefix_options, buf, sizeof (buf));
      vty_out (vty, "     Prefix Options: %s%s", buf, VTY_NEWLINE);
      ospf6_prefix_in6_addr (prefix, &in6);
      inet_ntop (AF_INET6, &in6, buf, sizeof (buf));
      vty_out (vty, "     Prefix: %s/%d%s",
               buf, prefix->prefix_length, VTY_NEWLINE);
    }

  return 0;
}


void
ospf6_lsa_link_update (char *ifname)
{
  char *cp, buffer [MAXLSASIZE], buf[32];
  u_int16_t size;
  struct ospf6_lsa *old;
  struct interface *ifp;
  struct ospf6_interface *o6i;

  struct ospf6_link_lsa *link_lsa;
  struct ospf6_prefix *p;
  list prefix_connected;
  listnode node;
  struct connected *c;

  ifp = if_lookup_by_name (ifname);
  if (! ifp)
    {
      if (IS_OSPF6_DUMP_LSA)
        zlog_info ("Update Link: No such Interface: %s", ifname);
      return;
    }

  o6i = (struct ospf6_interface *) ifp->info;
  if (! o6i || ! o6i->area)
    {
      if (IS_OSPF6_DUMP_LSA)
        zlog_info ("Update Link: Interface not enabled: %s", ifname);
      return;
    }

#if 0
  /* Link-LSA is on Broadcast or NBMA */
  if (! if_is_broadcast (o6i->interface) /* && ! NBMA xxx */)
    {
      return;
    }
#endif /*0*/

  /* find previous LSA */
  old = ospf6_lsdb_lookup (htons (OSPF6_LSA_TYPE_LINK), htonl (o6i->if_id),
                           ospf6->router_id, o6i->area);

  /* can't make Link-LSA if linklocal address not set */
  if (! o6i->lladdr)
    {
      if (IS_OSPF6_DUMP_LSA)
        zlog_warn ("Update Link: No Linklocal Address: %s",
                   o6i->interface->name);
      if (old)
        ospf6_lsa_premature_aging (old);
      return;
    }

  if (IS_OSPF6_DUMP_LSA)
    zlog_info ("Update Link: Interface %s", o6i->interface->name);

  if (! ospf6_interface_is_enabled (o6i->interface->ifindex))
    {
      if (IS_OSPF6_DUMP_LSA)
        zlog_info ("  Interface %s not enabled", o6i->interface->name);
      if (old)
        ospf6_lsa_premature_aging (old);
      return;
    }

  /* check connected prefix */
  prefix_connected = list_new ();
  for (node = listhead (o6i->interface->connected); node; nextnode (node))
    {
      c = (struct connected *) getdata (node);

      /* filter prefix not IPv6 */
      if (c->address->family != AF_INET6)
        continue;

      /* for log */
      prefix2str (c->address, buf, sizeof (buf));

      CONTINUE_IF_ADDRESS_LINKLOCAL (c->address);
      CONTINUE_IF_ADDRESS_UNSPECIFIED (c->address);
      CONTINUE_IF_ADDRESS_LOOPBACK (c->address);
      CONTINUE_IF_ADDRESS_V4COMPAT (c->address);
      CONTINUE_IF_ADDRESS_V4MAPPED (c->address);

      /* filter prefix specified by configuration */
      if (o6i->plist_name)
        {
          struct prefix_list *plist;
          enum prefix_list_type result = PREFIX_PERMIT;

          plist = prefix_list_lookup (AFI_IP6, o6i->plist_name);
          if (plist)
            result = prefix_list_apply (plist, c->address);
          else if (IS_OSPF6_DUMP_LSA)
            zlog_warn ("Update Intra-Prefix (Stub): "
                       "Prefix list \"%s\" not found", o6i->plist_name);

          if (result == PREFIX_DENY)
            {
              if (IS_OSPF6_DUMP_LSA)
                zlog_info ("  Filter out Prefix-list %s: %s",
                           o6i->plist_name, buf);
              continue;
            }
        }

      if (IS_OSPF6_DUMP_LSA)
        zlog_info ("    Advertise %s", buf);

      /* hold prefix in list. duplicate is filtered in ospf6_prefix_add() */
      p = ospf6_prefix_create (0, 0, (struct prefix_ipv6 *) c->address);
      ospf6_prefix_add (prefix_connected, p);
    }

  /* Note: even if no prefix configured, still we have to create Link-LSA
     for next-hop resolution */

  memset (buffer, 0, sizeof (buffer));
  size = sizeof (struct ospf6_link_lsa);
  link_lsa = (struct ospf6_link_lsa *) buffer;

  /* fill Link LSA and calculate size */
  link_lsa->llsa_rtr_pri = o6i->priority;
  link_lsa->llsa_options[0] = o6i->area->options[0];
  link_lsa->llsa_options[1] = o6i->area->options[1];
  link_lsa->llsa_options[2] = o6i->area->options[2];

  /* linklocal address */
  memcpy (&link_lsa->llsa_linklocal, o6i->lladdr, sizeof (struct in6_addr));

#ifdef KAME /* clear ifindex */
  if (link_lsa->llsa_linklocal.s6_addr[3] & 0x0f)
    link_lsa->llsa_linklocal.s6_addr[3] &= ~((char)0x0f);
#endif /* KAME */

  link_lsa->llsa_prefix_num = htonl (listcount (prefix_connected));
  cp = (char *)(link_lsa + 1);
  for (node = listhead (prefix_connected); node; nextnode (node))
    {
      p = (struct ospf6_prefix *) getdata (node);
      size += OSPF6_PREFIX_SIZE (p);
      memcpy (cp, p, OSPF6_PREFIX_SIZE (p));
      cp += OSPF6_PREFIX_SIZE (p);
    }

  for (node = listhead (prefix_connected); node; nextnode (node))
    {
      p = (struct ospf6_prefix *) getdata (node);
      ospf6_prefix_delete (p);
    }
  list_delete (prefix_connected);

  ospf6_lsa_originate (htons (OSPF6_LSA_TYPE_LINK),
                       htonl (o6i->if_id), o6i->area->ospf6->router_id,
                       (char *) link_lsa, size, o6i);
}

int
ospf6_lsa_link_hook_interface (void *interface)
{
  struct ospf6_interface *o6i = interface;
  if (o6i->area)
    ospf6_lsa_link_update (o6i->interface->name);
  return 0;
}

int
ospf6_lsa_link_refresh (void *old)
{
  struct ospf6_lsa *lsa = old;
  struct interface *ifp;

  ifp = if_lookup_by_index (ntohl (lsa->header->id));
  if (! ifp)
    ospf6_lsa_premature_aging (old);
  else
    ospf6_lsa_link_update (ifp->name);

  return 0;
}

void
ospf6_lsa_slot_register_link ()
{
  struct ospf6_lsa_slot slot;

  memset (&slot, 0, sizeof (struct ospf6_lsa_slot));
  slot.type              = htons (OSPF6_LSA_TYPE_LINK);
  slot.name              = "Link";
  slot.func_show         = ospf6_lsa_link_show;
  slot.func_refresh      = ospf6_lsa_link_refresh;
  slot.hook_interface.name = "OriginateLink";
  slot.hook_interface.hook_change = ospf6_lsa_link_hook_interface;
  ospf6_lsa_slot_register (&slot);

  /*
   * Link LSA handling will be shift in ospf6_intra.c
   * Currently, only database hook only moved to ospf6_intra.c
   */
#if 0
  ospf6_lsdb_hook[OSPF6_LSA_TYPE_LINK & OSPF6_LSTYPE_CODE_MASK].hook = 
    ospf6_spf_database_hook;
#endif /*0*/
}

int
ospf6_lsa_add_hook (void *data)
{
  struct ospf6_lsa *lsa = data;
  struct ospf6_lsa_slot *sp;

  sp = ospf6_lsa_slot_get (lsa->header->type);
  if (sp)
    {
      CALL_CHANGE_HOOK (&sp->database_hook, lsa);
    }
  else
    zlog_warn ("Unknown LSA added to database: %s", lsa->str);
  return 0;
}

int
ospf6_lsa_change_hook (void *data)
{
  struct ospf6_lsa *lsa = data;
  struct ospf6_lsa_slot *sp;

  sp = ospf6_lsa_slot_get (lsa->header->type);
  if (sp)
    {
      CALL_CHANGE_HOOK (&sp->database_hook, lsa);
    }
  else
    zlog_warn ("Unknown LSA changed in database: %s", lsa->str);
  return 0;
}

int
ospf6_lsa_remove_hook (void *data)
{
  struct ospf6_lsa *lsa = data;
  struct ospf6_lsa_slot *sp;

  sp = ospf6_lsa_slot_get (lsa->header->type);
  if (sp)
    {
      CALL_REMOVE_HOOK (&sp->database_hook, lsa);
    }
  else
    zlog_warn ("Unknown LSA removed from database: %s", lsa->str);
  return 0;
}

/* Initialize LSA slots */
void
ospf6_lsa_init ()
{
  struct ospf6_hook hook;

  slot_head = NULL;
  ospf6_lsa_slot_register_router ();
  ospf6_lsa_slot_register_network ();
  ospf6_lsa_slot_register_link ();
#if 0
  ospf6_lsa_slot_register_intra_prefix ();
  ospf6_lsa_slot_register_as_external ();
#endif /*0*/

  hook.name = "LSADatabaseHook";
  hook.hook_add = ospf6_lsa_add_hook;
  hook.hook_change = ospf6_lsa_change_hook;
  hook.hook_remove = ospf6_lsa_remove_hook;
  ospf6_hook_register (&hook, &database_hook);
}

