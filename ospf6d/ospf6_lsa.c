/*
 * Copyright (C) 2003 Yasuhiro Ohara
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
#include "log.h"
#include "linklist.h"
#include "command.h"
#include "memory.h"
#include "thread.h"

#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_message.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"

#include "ospf6_flood.h"
#include "ospf6d.h"

unsigned char conf_debug_ospf6_lsa = 0;

struct ospf6_lstype ospf6_lstype[OSPF6_LSTYPE_SIZE];

char *ospf6_lstype_str[OSPF6_LSTYPE_SIZE] =
  {"Unknown", "Router", "Network", "Inter-Prefix", "Inter-Router",
   "AS-External", "Group-Membership", "Type-7", "Link", "Intra-Prefix"};

char *
ospf6_lstype_name (u_int16_t type)
{
  static char buf[8];
  int index = ntohs (type) & OSPF6_LSTYPE_FCODE_MASK;

  if (index < OSPF6_LSTYPE_SIZE && ospf6_lstype_str[index])
    return ospf6_lstype_str[index];

  snprintf (buf, sizeof (buf), "0x%04hx", ntohs (type));
  return buf;
}

/* RFC2328: Section 13.2 */
int
ospf6_lsa_is_differ (struct ospf6_lsa *lsa1,
                     struct ospf6_lsa *lsa2)
{
  int len;

  assert (OSPF6_LSA_IS_SAME (lsa1, lsa2));

  /* XXX, Options ??? */

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

  len = ntohs (lsa1->header->length) - sizeof (struct ospf6_lsa_header);
  return memcmp (lsa1->header + 1, lsa2->header + 1, len);
}

int
ospf6_lsa_is_changed (struct ospf6_lsa *lsa1,
                      struct ospf6_lsa *lsa2)
{
  int length;

  if (OSPF6_LSA_IS_MAXAGE (lsa1) ^ OSPF6_LSA_IS_MAXAGE (lsa2))
    return 1;
  if (ntohs (lsa1->header->length) != ntohs (lsa2->header->length))
    return 1;

  length = OSPF6_LSA_SIZE (lsa1->header) - sizeof (struct ospf6_lsa_header);
  assert (length > 0);

  return memcmp (OSPF6_LSA_HEADER_END (lsa1->header),
                 OSPF6_LSA_HEADER_END (lsa2->header), length);
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
                                    MAXAGE + lsa->birth.tv_sec
                                    - now.tv_sec);
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
    zlog_warn ("LSA: gettimeofday failed, may fail LSA AGEs: %s",
               strerror (errno));

  /* calculate age */
  ulage = now.tv_sec - lsa->birth.tv_sec;

  /* if over MAXAGE, set to it */
  age = (ulage > MAXAGE ? MAXAGE : ulage);

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
}

void
ospf6_lsa_premature_aging (struct ospf6_lsa *lsa)
{
  /* log */
  if (IS_OSPF6_DEBUG_LSA (ORIGINATE))
    zlog_info ("LSA: Premature aging: %s", lsa->name);

  THREAD_OFF (lsa->expire);
  THREAD_OFF (lsa->refresh);

  memset (&lsa->birth, 0, sizeof (struct timeval));
  thread_execute (master, ospf6_lsa_expire, lsa, 0);
}

/* check which is more recent. if a is more recent, return -1;
   if the same, return 0; otherwise(b is more recent), return 1 */
int
ospf6_lsa_compare (struct ospf6_lsa *a, struct ospf6_lsa *b)
{
  signed long seqnuma, seqnumb;
  u_int16_t cksuma, cksumb;
  u_int16_t agea, ageb;

  assert (a && a->header);
  assert (b && b->header);
  assert (OSPF6_LSA_IS_SAME (a, b));

  seqnuma = ((signed long) ntohl (a->header->seqnum))
             - (signed long) INITIAL_SEQUENCE_NUMBER;
  seqnumb = ((signed long) ntohl (b->header->seqnum))
             - (signed long) INITIAL_SEQUENCE_NUMBER;

  /* compare by sequence number */
  /* XXX, LS sequence number wrapping */
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

  /* Update Age */
  agea = ospf6_lsa_age_current (a);
  ageb = ospf6_lsa_age_current (b);

  /* MaxAge check */
  if (agea == MAXAGE && ageb != MAXAGE)
    return -1;
  else if (agea != MAXAGE && ageb == MAXAGE)
    return 1;

  /* Age check */
  if (agea > ageb && agea - ageb >= MAX_AGE_DIFF)
    return 1;
  else if (agea < ageb && ageb - agea >= MAX_AGE_DIFF)
    return -1;

  /* neither recent */
  return 0;
}

char *
ospf6_lsa_printbuf (struct ospf6_lsa *lsa, char *buf, int size)
{
  char id[16], adv_router[16];
  inet_ntop (AF_INET, &lsa->header->id, id, sizeof (id));
  inet_ntop (AF_INET, &lsa->header->adv_router, adv_router,
             sizeof (adv_router));
  snprintf (buf, size, "[%s Id:%s Adv:%s]",
            OSPF6_LSTYPE_NAME (lsa->header->type), id, adv_router);
  return buf;
}

void
ospf6_lsa_header_print_raw (struct ospf6_lsa_header *header)
{
  char id[16], adv_router[16];
  inet_ntop (AF_INET, &header->id, id, sizeof (id));
  inet_ntop (AF_INET, &header->adv_router, adv_router,
             sizeof (adv_router));
  zlog_info ("    [%s Id:%s Adv:%s]",
             OSPF6_LSTYPE_NAME (header->type), id, adv_router);
  zlog_info ("    Age: %4hu SeqNum: %#08lx Cksum: %04hx Len: %d",
             ntohs (header->age), (u_long) ntohl (header->seqnum),
             ntohs (header->checksum), ntohs (header->length));
}

void
ospf6_lsa_header_print (struct ospf6_lsa *lsa)
{
  ospf6_lsa_age_current (lsa);
  ospf6_lsa_header_print_raw (lsa->header);
}

void
ospf6_lsa_show (struct vty *vty, struct ospf6_lsa *lsa)
{
  char adv_router[64], id[64];
  int index;

  assert (lsa && lsa->header);

  inet_ntop (AF_INET, &lsa->header->id, id, sizeof (id));
  inet_ntop (AF_INET, &lsa->header->adv_router,
             adv_router, sizeof (adv_router));

  vty_out (vty, "Age: %4hu Type: %s%s", ospf6_lsa_age_current (lsa),
           OSPF6_LSTYPE_NAME (lsa->header->type), VNL);
  vty_out (vty, "Link State ID: %s%s", id, VNL);
  vty_out (vty, "Advertising Router: %s%s", adv_router, VNL);
  vty_out (vty, "LS Sequence Number: %#010lx%s",
           (u_long) ntohl (lsa->header->seqnum), VNL);
  vty_out (vty, "CheckSum: %#06hx Length: %hu%s",
           ntohs (lsa->header->checksum),
           ntohs (lsa->header->length), VNL);

  index = OSPF6_LSTYPE_INDEX (ntohs (lsa->header->type));
  if (ospf6_lstype[index].show)
    (*ospf6_lstype[index].show) (vty, lsa);
  else
    vty_out (vty, "%sUnknown LSA type ...%s", VNL, VNL);

  vty_out (vty, "%s", VNL);
}

void
ospf6_lsa_show_summary_header (struct vty *vty)
{
  vty_out (vty, "%-12s %-15s %-15s %4s %8s %4s %4s %-8s%s",
           "Type", "LSId", "AdvRouter", "Age", "SeqNum",
           "Cksm", "Len", "Duration", VNL);
}

void
ospf6_lsa_show_summary (struct vty *vty, struct ospf6_lsa *lsa)
{
  char adv_router[16], id[16];
  struct timeval now, res;
  char duration[16];

  assert (lsa);
  assert (lsa->header);

  inet_ntop (AF_INET, &lsa->header->id, id, sizeof (id));
  inet_ntop (AF_INET, &lsa->header->adv_router, adv_router,
             sizeof (adv_router));

  gettimeofday (&now, NULL);
  timersub (&now, &lsa->installed, &res);
  timerstring (&res, duration, sizeof (duration));

  vty_out (vty, "%-12s %-15s %-15s %4hu %8lx %04hx %4hu %8s%s",
           OSPF6_LSTYPE_NAME (lsa->header->type),
           id, adv_router, ospf6_lsa_age_current (lsa),
           (u_long) ntohl (lsa->header->seqnum),
           ntohs (lsa->header->checksum), ntohs (lsa->header->length),
           duration, VNL);
}

void
ospf6_lsa_show_dump (struct vty *vty, struct ospf6_lsa *lsa)
{
  u_char *start, *end, *current;
  char byte[4];

  start = (char *) lsa->header;
  end = (char *) lsa->header + ntohs (lsa->header->length);

  vty_out (vty, "%s", VNL);
  vty_out (vty, "%s:%s", lsa->name, VNL);

  for (current = start; current < end; current ++)
    {
      if ((current - start) % 16 == 0)
        vty_out (vty, "%s        ", VNL);
      else if ((current - start) % 4 == 0)
        vty_out (vty, " ");

      snprintf (byte, sizeof (byte), "%02x", *current);
      vty_out (vty, "%s", byte);
    }

  vty_out (vty, "%s%s", VNL, VNL);
}

void
ospf6_lsa_show_internal (struct vty *vty, struct ospf6_lsa *lsa)
{
  char adv_router[64], id[64];

  assert (lsa && lsa->header);

  inet_ntop (AF_INET, &lsa->header->id, id, sizeof (id));
  inet_ntop (AF_INET, &lsa->header->adv_router,
             adv_router, sizeof (adv_router));

  vty_out (vty, "%s", VNL);
  vty_out (vty, "Age: %4hu Type: %s%s", ospf6_lsa_age_current (lsa),
           OSPF6_LSTYPE_NAME (lsa->header->type), VNL);
  vty_out (vty, "Link State ID: %s%s", id, VNL);
  vty_out (vty, "Advertising Router: %s%s", adv_router, VNL);
  vty_out (vty, "LS Sequence Number: %#010lx%s",
           (u_long) ntohl (lsa->header->seqnum), VNL);
  vty_out (vty, "CheckSum: %#06hx Length: %hu%s",
           ntohs (lsa->header->checksum),
           ntohs (lsa->header->length), VNL);
  vty_out (vty, "    Prev: %p This: %p Next: %p%s",
           lsa->prev, lsa, lsa->next, VNL);
  vty_out (vty, "%s", VNL);
}

/* OSPFv3 LSA creation/deletion function */

struct ospf6_lsa *
ospf6_lsa_create (struct ospf6_lsa_header *header)
{
  struct ospf6_lsa *lsa = NULL;
  struct ospf6_lsa_header *new_header = NULL;
  u_int16_t lsa_size = 0;

  /* size of the entire LSA */
  lsa_size = ntohs (header->length);   /* XXX vulnerable */

  /* allocate memory for this LSA */
  new_header = (struct ospf6_lsa_header *)
    XMALLOC (MTYPE_OSPF6_LSA, lsa_size);

  /* copy LSA from original header */
  memcpy (new_header, header, lsa_size);

  /* LSA information structure */
  /* allocate memory */
  lsa = (struct ospf6_lsa *)
    XMALLOC (MTYPE_OSPF6_LSA, sizeof (struct ospf6_lsa));
  memset (lsa, 0, sizeof (struct ospf6_lsa));

  lsa->header = (struct ospf6_lsa_header *) new_header;
  lsa->headeronly = 0; /* this is not header only */

  /* dump string */
  ospf6_lsa_printbuf (lsa, lsa->name, sizeof (lsa->name));

  /* calculate birth, expire and refresh of this lsa */
  ospf6_lsa_age_set (lsa);

  if (IS_OSPF6_DEBUG_LSA (MEMORY))
    zlog_info ("Create LSA Memory: %s (%p/%p)",
               lsa->name, lsa, lsa->header);

  return lsa;
}

struct ospf6_lsa *
ospf6_lsa_create_headeronly (struct ospf6_lsa_header *header)
{
  struct ospf6_lsa *lsa = NULL;
  struct ospf6_lsa_header *new_header = NULL;

  /* allocate memory for this LSA */
  new_header = (struct ospf6_lsa_header *)
    XMALLOC (MTYPE_OSPF6_LSA, sizeof (struct ospf6_lsa_header));

  /* copy LSA from original header */
  memcpy (new_header, header, sizeof (struct ospf6_lsa_header));

  /* LSA information structure */
  /* allocate memory */
  lsa = (struct ospf6_lsa *)
    XMALLOC (MTYPE_OSPF6_LSA, sizeof (struct ospf6_lsa));
  memset (lsa, 0, sizeof (struct ospf6_lsa));

  lsa->header = (struct ospf6_lsa_header *) new_header;
  lsa->headeronly = 1; /* this is header only */

  /* dump string */
  ospf6_lsa_printbuf (lsa, lsa->name, sizeof (lsa->name));

  /* calculate birth, expire and refresh of this lsa */
  ospf6_lsa_age_set (lsa);

  if (IS_OSPF6_DEBUG_LSA (MEMORY))
    zlog_info ("Create LSA (Header-only) Memory: %s (%p/%p)",
               lsa->name, lsa, lsa->header);

  return lsa;
}

void
ospf6_lsa_delete (struct ospf6_lsa *lsa)
{
  assert (lsa->lock == 0);

  /* cancel threads */
  THREAD_OFF (lsa->expire);
  THREAD_OFF (lsa->refresh);

  if (IS_OSPF6_DEBUG_LSA (MEMORY))
    zlog_info ("Delete LSA %s Memory: %s (%p/%p)",
               (lsa->headeronly ? "(Header-only) " : ""),
               lsa->name, lsa, lsa->header);

  /* do free */
  XFREE (MTYPE_OSPF6_LSA, lsa->header);
  XFREE (MTYPE_OSPF6_LSA, lsa);
}

struct ospf6_lsa *
ospf6_lsa_copy (struct ospf6_lsa *lsa)
{
  struct ospf6_lsa *copy = NULL;

  if (IS_OSPF6_DEBUG_LSA (MEMORY))
    zlog_info ("Create LSA Copy from %s", lsa->name);

  ospf6_lsa_age_current (lsa);
  if (lsa->headeronly)
    copy = ospf6_lsa_create_headeronly (lsa->header);
  else
    copy = ospf6_lsa_create (lsa->header);
  assert (copy->lock == 0);

  copy->installed = lsa->installed;
  copy->originated = lsa->originated;
  copy->scope = lsa->scope;

  return copy;
}

/* increment reference counter of struct ospf6_lsa */
void
ospf6_lsa_lock (struct ospf6_lsa *lsa)
{
  lsa->lock++;
  return;
}

/* decrement reference counter of struct ospf6_lsa */
void
ospf6_lsa_unlock (struct ospf6_lsa *lsa)
{
  /* decrement reference counter */
  assert (lsa->lock > 0);
  lsa->lock--;

  if (lsa->lock != 0)
    return;

  ospf6_lsa_delete (lsa);
}

void
ospf6_lsa_originate (struct ospf6_lsa *lsa)
{
  struct ospf6_lsa *old;
  struct ospf6_lsdb *lsdb = NULL;

  /* find previous LSA */
  lsdb = ospf6_get_scoped_lsdb (lsa->header->type, lsa->scope);
  if (lsdb == NULL)
    {
      zlog_warn ("Can't decide scoped LSDB");
      ospf6_lsa_delete (lsa);
      return;
    }

  old = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                           lsa->header->adv_router, lsdb);
  if (old)
    {
      /* If this origination is neither different instance nor refresh,
         suppress this origination */
      if (! CHECK_FLAG (old->flag, OSPF6_LSA_REFRESH) &&
          ! OSPF6_LSA_IS_DIFFER (lsa, old))
        {
          if (IS_OSPF6_DEBUG_LSA (ORIGINATE))
            zlog_info ("Suppress updating LSA: %s", lsa->name);
          ospf6_lsa_delete (lsa);
          return;
        }
    }

  lsa->refresh = thread_add_timer (master, ospf6_lsa_refresh, lsa,
                                   LS_REFRESH_TIME);

  if (IS_OSPF6_DEBUG_LSA (ORIGINATE))
    {
      zlog_info ("LSA Originate:");
      ospf6_lsa_header_print (lsa);
    }

  if (old)
    ospf6_flood_clear (old);
  ospf6_flood_lsa (lsa, NULL);
  ospf6_install_lsa (lsa, lsdb);
}

void
ospf6_lsa_re_originate (struct ospf6_lsa *lsa)
{
  u_int16_t index;

  if (IS_OSPF6_DEBUG_LSA (ORIGINATE))
    {
      zlog_info ("LSA Reoriginate:");
      ospf6_lsa_header_print (lsa);
    }

  index = OSPF6_LSTYPE_INDEX (ntohs (lsa->header->type));
  if (ospf6_lstype[index].reoriginate)
    (*ospf6_lstype[index].reoriginate) (lsa);
  else
    ospf6_lsa_premature_aging (lsa);
}


/* ospf6 lsa expiry */
int
ospf6_lsa_expire (struct thread *thread)
{
  struct ospf6_lsa *lsa;
  struct ospf6_lsdb *lsdb = NULL;

  lsa = (struct ospf6_lsa *) THREAD_ARG (thread);

  assert (lsa && lsa->header);
  assert (OSPF6_LSA_IS_MAXAGE (lsa));
  assert (! lsa->refresh);

  lsa->expire = (struct thread *) NULL;

  if (IS_OSPF6_DEBUG_LSA (TIMER))
    {
      zlog_info ("LSA Expire:");
      ospf6_lsa_header_print (lsa);
    }

  if (lsa->headeronly)
    return 0;    /* dbexchange will do something ... */

  /* reflood lsa */
  ospf6_flood_lsa (lsa, NULL);

  /* reinstall lsa */
  lsdb = ospf6_get_scoped_lsdb (lsa->header->type, lsa->scope);
  if (lsdb == NULL)
    {
      zlog_warn ("Can't decide scoped LSDB: %s", lsa->name);
      return 0;
    }
  if (IS_OSPF6_DEBUG_LSA (DATABASE))
    zlog_info ("Reinstall MaxAge %s", lsa->name);
  ospf6_lsdb_add (lsa, lsdb);

  /* schedule maxage remover */
  ospf6_maxage_remove (ospf6);

  return 0;
}

/* Below will become dummy thread.
   refresh function must be set individually per each LSAs */
int
ospf6_lsa_refresh (struct thread *thread)
{
  struct ospf6_lsa *lsa;

  assert (thread);
  lsa = (struct ospf6_lsa *) THREAD_ARG (thread);
  assert (lsa && lsa->header);

  lsa->refresh = (struct thread *) NULL;

  /* this will be used later to decide really originate or not */
  SET_FLAG (lsa->flag, OSPF6_LSA_REFRESH);

  if (IS_OSPF6_DEBUG_LSA (ORIGINATE))
    {
      zlog_info ("LSA Refresh:");
      ospf6_lsa_header_print (lsa);
    }

  ospf6_lsa_re_originate (lsa);
  return 0;
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
ospf6_unknown_reoriginate (struct ospf6_lsa *lsa)
{
  ospf6_lsa_premature_aging (lsa);
  return 0;
}

int
ospf6_unknown_show (struct vty *vty, struct ospf6_lsa *lsa)
{
  u_char *start, *end, *current;
  char byte[4];

  start = (char *) lsa->header + sizeof (struct ospf6_lsa_header);
  end = (char *) lsa->header + ntohs (lsa->header->length);

  vty_out (vty, "        Unknown contents:%s", VNL);
  for (current = start; current < end; current ++)
    {
      if ((current - start) % 16 == 0)
        vty_out (vty, "%s        ", VNL);
      else if ((current - start) % 4 == 0)
        vty_out (vty, " ");

      snprintf (byte, sizeof (byte), "%02x", *current);
      vty_out (vty, "%s", byte);
    }

  vty_out (vty, "%s%s", VNL, VNL);
  return 0;
}

void
ospf6_lsa_init ()
{
  memset (ospf6_lstype, 0, sizeof (ospf6_lstype));

  ospf6_lstype[0].name = "Unknown";
  ospf6_lstype[0].reoriginate = ospf6_unknown_reoriginate;
  ospf6_lstype[0].show = ospf6_unknown_show;
}



DEFUN (debug_ospf6_lsa_sendrecv,
       debug_ospf6_lsa_sendrecv_cmd,
       "debug ospf6 lsa (send|recv|originate|timer|database|memory|all)",
       DEBUG_STR
       OSPF6_STR
       "Debug Link State Advertisements (LSAs)\n"
       "Debug Sending LSAs\n"
       "Debug Receiving LSAs\n"
       "Debug Originating LSAs\n"
       "Debug Timer Event of LSAs\n"
       "Debug LSA Database\n"
       "Debug Memory of LSAs\n"
       "Debug LSAs all\n"
      )
{
  unsigned char level = 0;

  if (argc)
    {
      if (! strncmp (argv[0], "s", 1))
        level = OSPF6_DEBUG_LSA_SEND;
      else if (! strncmp (argv[0], "r", 1))
        level = OSPF6_DEBUG_LSA_RECV;
      else if (! strncmp (argv[0], "o", 1))
        level = OSPF6_DEBUG_LSA_ORIGINATE;
      else if (! strncmp (argv[0], "t", 1))
        level = OSPF6_DEBUG_LSA_TIMER;
      else if (! strncmp (argv[0], "d", 1))
        level = OSPF6_DEBUG_LSA_DATABASE;
      else if (! strncmp (argv[0], "m", 1))
        level = OSPF6_DEBUG_LSA_MEMORY;
      else if (! strncmp (argv[0], "a", 1))
        {
          level = OSPF6_DEBUG_LSA_SEND | OSPF6_DEBUG_LSA_RECV |
                  OSPF6_DEBUG_LSA_ORIGINATE | OSPF6_DEBUG_LSA_TIMER |
                  OSPF6_DEBUG_LSA_DATABASE | OSPF6_DEBUG_LSA_MEMORY;
        }
    }
  else
    {
      level = OSPF6_DEBUG_LSA_SEND | OSPF6_DEBUG_LSA_RECV |
              OSPF6_DEBUG_LSA_ORIGINATE | OSPF6_DEBUG_LSA_TIMER;
    }

  OSPF6_DEBUG_LSA_ON (level);
  return CMD_SUCCESS;
}

ALIAS (debug_ospf6_lsa_sendrecv,
       debug_ospf6_lsa_cmd,
       "debug ospf6 lsa",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug Link State Advertisements (LSAs)\n"
      );

DEFUN (no_debug_ospf6_lsa_sendrecv,
       no_debug_ospf6_lsa_sendrecv_cmd,
       "no debug ospf6 lsa (send|recv|originate|timer|database|memory|all)",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug Link State Advertisements (LSAs)\n"
       "Debug Sending LSAs\n"
       "Debug Receiving LSAs\n"
       "Debug Originating LSAs\n"
       "Debug Timer Event of LSAs\n"
       "Debug LSA Database\n"
       "Debug Memory of LSAs\n"
       "Debug LSAs all\n"
      )
{
  unsigned char level = 0;

  if (argc)
    {
      if (! strncmp (argv[0], "s", 1))
        level = OSPF6_DEBUG_LSA_SEND;
      else if (! strncmp (argv[0], "r", 1))
        level = OSPF6_DEBUG_LSA_RECV;
      else if (! strncmp (argv[0], "o", 1))
        level = OSPF6_DEBUG_LSA_ORIGINATE;
      else if (! strncmp (argv[0], "t", 1))
        level = OSPF6_DEBUG_LSA_TIMER;
      else if (! strncmp (argv[0], "d", 1))
        level = OSPF6_DEBUG_LSA_DATABASE;
      else if (! strncmp (argv[0], "m", 1))
        level = OSPF6_DEBUG_LSA_MEMORY;
      else if (! strncmp (argv[0], "a", 1))
        {
          level = OSPF6_DEBUG_LSA_SEND | OSPF6_DEBUG_LSA_RECV |
                  OSPF6_DEBUG_LSA_ORIGINATE | OSPF6_DEBUG_LSA_TIMER |
                  OSPF6_DEBUG_LSA_DATABASE | OSPF6_DEBUG_LSA_MEMORY;
        }
    }
  else
    {
      level = OSPF6_DEBUG_LSA_SEND | OSPF6_DEBUG_LSA_RECV |
              OSPF6_DEBUG_LSA_ORIGINATE | OSPF6_DEBUG_LSA_TIMER;
    }

  OSPF6_DEBUG_LSA_OFF (level);
  return CMD_SUCCESS;
}

ALIAS (no_debug_ospf6_lsa_sendrecv,
       no_debug_ospf6_lsa_cmd,
       "no debug ospf6 lsa",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug Link State Advertisements (LSAs)\n"
      );

int
config_write_ospf6_debug_lsa (struct vty *vty)
{
  if (conf_debug_ospf6_lsa == OSPF6_DEBUG_LSA_ALL)
    vty_out (vty, "debug ospf6 lsa all%s", VNL);
  else
    {
      if (conf_debug_ospf6_lsa == OSPF6_DEBUG_LSA_DEFAULT)
        vty_out (vty, "debug ospf6 lsa%s", VNL);
      else
        {
          if (IS_OSPF6_DEBUG_LSA (SEND))
            vty_out (vty, "debug ospf6 lsa send%s", VNL);
          if (IS_OSPF6_DEBUG_LSA (RECV))
            vty_out (vty, "debug ospf6 lsa recv%s", VNL);
          if (IS_OSPF6_DEBUG_LSA (ORIGINATE))
            vty_out (vty, "debug ospf6 lsa originate%s", VNL);
          if (IS_OSPF6_DEBUG_LSA (TIMER))
            vty_out (vty, "debug ospf6 lsa timer%s", VNL);
        }

      if (IS_OSPF6_DEBUG_LSA (DATABASE))
        vty_out (vty, "debug ospf6 lsa database%s", VNL);
      if (IS_OSPF6_DEBUG_LSA (MEMORY))
        vty_out (vty, "debug ospf6 lsa memory%s", VNL);
    }

  return 0;
}

void
install_element_ospf6_debug_lsa ()
{
  install_element (ENABLE_NODE, &debug_ospf6_lsa_cmd);
  install_element (ENABLE_NODE, &debug_ospf6_lsa_sendrecv_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf6_lsa_cmd);
  install_element (ENABLE_NODE, &no_debug_ospf6_lsa_sendrecv_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_lsa_cmd);
  install_element (CONFIG_NODE, &debug_ospf6_lsa_sendrecv_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_lsa_cmd);
  install_element (CONFIG_NODE, &no_debug_ospf6_lsa_sendrecv_cmd);
}


