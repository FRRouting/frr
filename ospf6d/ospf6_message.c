/*
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

#include "ospf6d.h"

int
is_ospf6_message_dump (u_char type)
{
  if (type > OSPF6_MESSAGE_TYPE_LSACK)
    type = OSPF6_MESSAGE_TYPE_UNKNOWN;

  switch (type)
    {
      case OSPF6_MESSAGE_TYPE_UNKNOWN:
          return 1;
        break;
      case OSPF6_MESSAGE_TYPE_HELLO:
        if (IS_OSPF6_DUMP_HELLO)
          return 1;
        break;
      case OSPF6_MESSAGE_TYPE_DBDESC:
        if (IS_OSPF6_DUMP_DBDESC)
          return 1;
        break;
      case OSPF6_MESSAGE_TYPE_LSREQ:
        if (IS_OSPF6_DUMP_LSREQ)
          return 1;
        break;
      case OSPF6_MESSAGE_TYPE_LSUPDATE:
        if (IS_OSPF6_DUMP_LSUPDATE)
          return 1;
        break;
      case OSPF6_MESSAGE_TYPE_LSACK:
        if (IS_OSPF6_DUMP_LSACK)
          return 1;
        break;
      default:
        break;
    }
  return 0;
}
#define IS_OSPF6_DUMP_MESSAGE(x) (is_ospf6_message_dump(x))

char *ospf6_message_type_string[] =
{
  "Unknown", "Hello", "DbDesc", "LSReq", "LSUpdate", "LSAck", NULL
};

void
ospf6_message_log_lsa_header (struct ospf6_lsa_header *lsa_header)
{
  char buf_id[16], buf_router[16], typebuf[32];

  inet_ntop (AF_INET, &lsa_header->advrtr, buf_router, sizeof (buf_router));
  inet_ntop (AF_INET, &lsa_header->ls_id, buf_id, sizeof (buf_id));
  zlog_info ("   [%s ID=%s Adv=%s]",
             ospf6_lsa_type_string (lsa_header->type, typebuf,
                                    sizeof (typebuf)),
             buf_id, buf_router);
  zlog_info ("    Age=%hu SeqNum=%#lx Cksum=%#hx Len=%hu",
             ntohs (lsa_header->age), (u_long)ntohl (lsa_header->seqnum),
             ntohs (lsa_header->checksum), ntohs (lsa_header->length));
}

static void
ospf6_message_log_unknown (struct iovec *message)
{
  zlog_info ("Message:  Unknown");
}

static void
ospf6_message_log_hello (struct iovec *message)
{
  struct ospf6_header *ospf6_header;
  u_int16_t length_left;
  struct ospf6_hello *hello;
  char dr_str[16], bdr_str[16];
  char *start, *end, *current;

  /* calculate length */
  ospf6_header = (struct ospf6_header *) message[0].iov_base;
  length_left = ntohs (ospf6_header->len) - sizeof (struct ospf6_header);
  length_left = (length_left < iov_totallen (message) - sizeof (struct ospf6_header) ?
                 length_left : iov_totallen (message) - sizeof (struct ospf6_header));

  hello = (struct ospf6_hello *) message[1].iov_base;

  inet_ntop (AF_INET, &hello->dr, dr_str, sizeof (dr_str));
  inet_ntop (AF_INET, &hello->bdr, bdr_str, sizeof (bdr_str));

  zlog_info ("    IFID:%ld Priority:%d Option:%s",
             (u_long)ntohl (hello->interface_id), hello->rtr_pri, "xxx");
  zlog_info ("    HelloInterval:%hu Deadinterval:%hu",
             ntohs (hello->hello_interval),
             ntohs (hello->router_dead_interval));
  zlog_info ("    DR:%s BDR:%s", dr_str, bdr_str);

  start = (char *) (hello + 1);
  if (start >= (char *) message[1].iov_base + message[1].iov_len)
    start = message[2].iov_base;
  end = (char *) start + (length_left - sizeof (struct ospf6_hello));

  for (current = start; current < end; current += sizeof (u_int32_t))
    {
      char neighbor[16];
      inet_ntop (AF_INET, current, neighbor, sizeof (neighbor));
      zlog_info ("    Neighbor: %s", neighbor);
    }
}

static void
ospf6_message_log_dbdesc (struct iovec *message)
{
  struct ospf6_header *ospf6_header;
  u_int16_t length_left;
  struct ospf6_dbdesc *dbdesc;
  int i;
  char buffer[16];
  struct ospf6_lsa_header *lsa_header;

  /* calculate length */
  ospf6_header = (struct ospf6_header *) message[0].iov_base;
  length_left = ntohs (ospf6_header->len) - sizeof (struct ospf6_header);
  length_left = (length_left < iov_totallen (message) - sizeof (struct ospf6_header) ?
                 length_left : iov_totallen (message) - sizeof (struct ospf6_header));

  dbdesc = (struct ospf6_dbdesc *) message[1].iov_base;
  ospf6_options_string (dbdesc->options, buffer, sizeof (buffer));

  zlog_info ("    Option:%s IFMTU:%hu", buffer, ntohs (dbdesc->ifmtu));
  zlog_info ("    Bits:%s%s%s SeqNum:%#lx",
             (DD_IS_IBIT_SET (dbdesc->bits) ? "I" : "-"),
             (DD_IS_MBIT_SET (dbdesc->bits) ? "M" : "-"),
             (DD_IS_MSBIT_SET (dbdesc->bits) ? "m" : "s"),
             (u_long)ntohl (dbdesc->seqnum));

  for (lsa_header = (struct ospf6_lsa_header *) (dbdesc + 1);
       (char *)(lsa_header + 1) <= (char *)(message[1].iov_base + message[1].iov_len) &&
       (char *)(lsa_header + 1) <= (char *)dbdesc + length_left;
       lsa_header++)
    ospf6_message_log_lsa_header (lsa_header);

  length_left -= message[1].iov_len;
  for (i = 2; message[i].iov_base; i++)
    {
      for (lsa_header = (struct ospf6_lsa_header *) message[i].iov_base;
           (char *)(lsa_header + 1) <= (char *) (message[i].iov_base +
                                                 message[i].iov_len) &&
           (char *)(lsa_header + 1) <= (char *) (message[i].iov_base + length_left);
           lsa_header++)
        ospf6_message_log_lsa_header (lsa_header);
      length_left -= message[i].iov_len;
    }
}

static void
ospf6_message_log_lsreq (struct iovec *message)
{
  struct ospf6_header *ospf6_header;
  u_int16_t length_left;
  int i;
  struct ospf6_lsreq *lsreq;
  char buf_router[16], buf_id[16], buf_type[16];

  /* calculate length */
  ospf6_header = (struct ospf6_header *) message[0].iov_base;
  length_left = ntohs (ospf6_header->len) - sizeof (struct ospf6_header);
  length_left = (length_left < iov_totallen (message) - sizeof (struct ospf6_header) ?
                 length_left : iov_totallen (message) - sizeof (struct ospf6_header));

  for (i = 1; message[i].iov_base; i++)
    {
      for (lsreq = (struct ospf6_lsreq *) message[i].iov_base;
           (char *)(lsreq + 1) <= (char *) (message[i].iov_base + message[i].iov_len) &&
           (char *)(lsreq + 1) <= (char *) (message[i].iov_base + length_left);
           lsreq++)
        {
          inet_ntop (AF_INET, &lsreq->adv_router, buf_router, sizeof (buf_router));
          inet_ntop (AF_INET, &lsreq->id, buf_id, sizeof (buf_id));
          zlog_info ("    [%s ID=%s Adv=%s]",
                     ospf6_lsa_type_string (lsreq->type, buf_type,
                                            sizeof (buf_type)),
                     buf_id, buf_router);
        }
      length_left -= message[i].iov_len;
    }
}

static void
ospf6_message_log_lsupdate (struct iovec *message)
{
  struct ospf6_header *ospf6_header;
  u_int16_t length_left;
  int i, lsanum;
  struct ospf6_lsupdate *lsupdate;
  struct ospf6_lsa_header *lsa_header;

  /* calculate length */
  ospf6_header = (struct ospf6_header *) message[0].iov_base;
  length_left = ntohs (ospf6_header->len) - sizeof (struct ospf6_header);
  length_left = (length_left < iov_totallen (message) - sizeof (struct ospf6_header) ?
                 length_left : iov_totallen (message) - sizeof (struct ospf6_header));

  lsupdate = (struct ospf6_lsupdate *) message[1].iov_base;
  lsanum = ntohl (lsupdate->lsupdate_num);

  zlog_info ("    Number of LSA: #%d", lsanum);

  for (lsa_header = (struct ospf6_lsa_header *) (lsupdate + 1);
       (char *)lsa_header < (char *)(message[1].iov_base + message[1].iov_len) &&
       (char *)lsa_header < (char *)(message[1].iov_base + length_left);
       lsa_header = OSPF6_LSA_NEXT (lsa_header))
    ospf6_message_log_lsa_header (lsa_header);
  length_left -= message[1].iov_len;

  for (i = 2; message[i].iov_base; i++)
    {

      for (lsa_header = (struct ospf6_lsa_header *) message[i].iov_base;
           (char *)lsa_header < (char *) (message[i].iov_base + message[i].iov_len) &&
           (char *)lsa_header < (char *) (message[i].iov_base + length_left);
           lsa_header = OSPF6_LSA_NEXT (lsa_header))
        ospf6_message_log_lsa_header (lsa_header);
      length_left -= message[i].iov_len;
    }
}

static void
ospf6_message_log_lsack (struct iovec *message)
{
  struct ospf6_header *ospf6_header;
  u_int16_t length_left;
  struct ospf6_lsa_header *lsa_header;
  int i;

  /* calculate length */
  ospf6_header = (struct ospf6_header *) message[0].iov_base;
  length_left = ntohs (ospf6_header->len) - sizeof (struct ospf6_header);
  length_left = (length_left < iov_totallen (message) - sizeof (struct ospf6_header) ?
                 length_left : iov_totallen (message) - sizeof (struct ospf6_header));

  for (i = 1; message[i].iov_base; i++)
    {
      for (lsa_header = (struct ospf6_lsa_header *) message[i].iov_base;
           (char *)(lsa_header + 1) <= (char *) (message[i].iov_base +
                                                 message[i].iov_len) &&
           (char *)(lsa_header + 1) <= (char *) (message[i].iov_base + length_left);
           lsa_header++)
        ospf6_message_log_lsa_header (lsa_header);
      length_left -= message[i].iov_len;
    }
}

struct {
  void (*message_log) (struct iovec *);
} ospf6_message_log_body [] =
{
  {ospf6_message_log_unknown},
  {ospf6_message_log_hello},
  {ospf6_message_log_dbdesc},
  {ospf6_message_log_lsreq},
  {ospf6_message_log_lsupdate},
  {ospf6_message_log_lsack},
};

static void
ospf6_message_log (struct iovec *message)
{
  struct ospf6_header *o6h;
  char router_id[16], area_id[16];
  u_char type;

  assert (message[0].iov_len == sizeof (struct ospf6_header));
  o6h = (struct ospf6_header *) message[0].iov_base;

  inet_ntop (AF_INET, &o6h->router_id, router_id, sizeof (router_id));
  inet_ntop (AF_INET, &o6h->area_id, area_id, sizeof (area_id));

  zlog_info ("    OSPFv%d Type:%d Len:%hu RouterID:%s",
             o6h->version, o6h->type, ntohs (o6h->len), router_id);
  zlog_info ("    AreaID:%s Cksum:%hx InstanceID:%d",
             area_id, ntohs (o6h->cksum), o6h->instance_id);

  type = (OSPF6_MESSAGE_TYPE_UNKNOWN < o6h->type &&
          o6h->type <= OSPF6_MESSAGE_TYPE_LSACK ?
          o6h->type : OSPF6_MESSAGE_TYPE_UNKNOWN);
  (* ospf6_message_log_body[type].message_log) (&message[0]);
}

int
ospf6_opt_is_mismatch (unsigned char opt, char *options1, char *options2)
{
  return (OSPF6_OPT_ISSET (options1, opt) ^ OSPF6_OPT_ISSET (options2, opt));
}


void
ospf6_process_unknown (struct iovec *message,
                       struct in6_addr *src,
                       struct in6_addr *dst,
                       struct ospf6_interface *o6i,
                       u_int32_t router_id)
{
  zlog_warn ("unknown message type, drop");
}

void
ospf6_process_hello (struct iovec *message,
                     struct in6_addr *src,
                     struct in6_addr *dst,
                     struct ospf6_interface *o6i,
                     u_int32_t router_id)
{
  struct ospf6_header *ospf6_header;
  u_int16_t length;
  struct ospf6_hello *hello;
  char changes = 0;
#define CHANGE_RTRPRI (1 << 0)
#define CHANGE_DR     (1 << 1)
#define CHANGE_BDR    (1 << 2)
  int twoway = 0, backupseen = 0, nbchange = 0;
  u_int32_t *router_id_ptr;
  int i, seenrtrnum = 0, router_id_space = 0;
  char strbuf[64];
  struct ospf6_neighbor *o6n = NULL;

  /* assert interface */
  assert (o6i);

  /* caluculate length */
  ospf6_header = (struct ospf6_header *) message[0].iov_base;
  length = ntohs (ospf6_header->len) - sizeof (struct ospf6_header);
  length = (length < message[1].iov_len ? length : message[1].iov_len);

  /* set hello pointer */
  hello = (struct ospf6_hello *) message[1].iov_base;

  /* find neighbor. if cannot be found, create */
  o6n = ospf6_neighbor_lookup (router_id, o6i);
  if (!o6n)
    {
      o6n = ospf6_neighbor_create (router_id, o6i);
      o6n->ifid = ntohl (hello->interface_id);
      o6n->prevdr = o6n->dr = hello->dr;
      o6n->prevbdr = o6n->bdr = hello->bdr;
      o6n->priority = hello->rtr_pri;
      memcpy (&o6n->hisaddr, src, sizeof (struct in6_addr));
    }

  /* HelloInterval check */
  if (ntohs (hello->hello_interval) != o6i->hello_interval)
    {
      zlog_warn ("HelloInterval mismatch with %s", o6n->str);
      return;
    }

  /* RouterDeadInterval check */
  if (ntohs (hello->router_dead_interval)
      != o6i->dead_interval)
    {
      zlog_warn ("RouterDeadInterval mismatch with %s", o6n->str);
      return;
    }

  /* check options */
  /* Ebit */
  if (ospf6_opt_is_mismatch (OSPF6_OPT_E, hello->options, o6i->area->options))
    {
      zlog_warn ("Ebit mismatch with %s", o6n->str);
      return;
    }

  /* RouterPriority set */
  if (o6n->priority != hello->rtr_pri)
    {
      o6n->priority = hello->rtr_pri;
      if (IS_OSPF6_DUMP_HELLO)
        zlog_info ("%s: RouterPriority changed", o6n->str);
      changes |= CHANGE_RTRPRI;
    }

  /* DR set */
  if (o6n->dr != hello->dr)
    {
      /* save previous dr, set current */
      o6n->prevdr = o6n->dr;
      o6n->dr = hello->dr;
      inet_ntop (AF_INET, &o6n->dr, strbuf, sizeof (strbuf));
      if (IS_OSPF6_DUMP_HELLO)
        zlog_info ("%s declare %s as DR", o6n->str, strbuf);
      changes |= CHANGE_DR;
    }

  /* BDR set */
  if (o6n->bdr != hello->bdr)
    {
      /* save previous bdr, set current */
      o6n->prevbdr = o6n->bdr;
      o6n->bdr = hello->bdr;
      inet_ntop (AF_INET, &o6n->bdr, strbuf, sizeof (strbuf));
      if (IS_OSPF6_DUMP_HELLO)
        zlog_info ("%s declare %s as BDR", o6n->str, strbuf);
      changes |= CHANGE_BDR;
    }

  /* TwoWay check */
  router_id_space = length - sizeof (struct ospf6_hello);
  seenrtrnum = router_id_space / sizeof (u_int32_t);
  router_id_ptr = (u_int32_t *) (hello + 1);
  for (i = 0; i < seenrtrnum; i++)
    {
      if (*router_id_ptr == o6i->area->ospf6->router_id)
        twoway++;
      router_id_ptr++;
    }

  /* execute neighbor events */
  thread_execute (master, hello_received, o6n, 0);
  if (twoway)
    thread_execute (master, twoway_received, o6n, 0);
  else
    thread_execute (master, oneway_received, o6n, 0);

  /* BackupSeen check */
  if (o6i->state == IFS_WAITING)
    {
      if (hello->dr == hello->bdr &&
          hello->dr == o6n->router_id)
        zlog_warn ("*** DR Election of %s is illegal", o6n->str);

      if (hello->bdr == o6n->router_id)
        backupseen++;
      else if (hello->dr == o6n->router_id && hello->bdr == 0)
        backupseen++;
    }

  /* NeighborChange check */
  if (changes & CHANGE_RTRPRI)
    nbchange++;
  if (changes & CHANGE_DR)
    if (o6n->prevdr == o6n->router_id || o6n->dr == o6n->router_id)
      nbchange++;
  if (changes & CHANGE_BDR)
    if (o6n->prevbdr == o6n->router_id || o6n->bdr == o6n->router_id)
      nbchange++;

  /* schedule interface events */
  if (backupseen)
    thread_add_event (master, backup_seen, o6i, 0);
  if (nbchange)
    thread_add_event (master, neighbor_change, o6i, 0);

  return;
}

int
ospf6_dbdesc_is_master (struct ospf6_neighbor *o6n)
{
  char buf[128];

  if (o6n->router_id == ospf6->router_id)
    {
      inet_ntop (AF_INET6, &o6n->hisaddr, buf, sizeof (buf));
      zlog_warn ("Message: Neighbor router-id conflicts: %s: %s",
                 o6n->str, buf);
      return -1;
    }
  else if (ntohl (o6n->router_id) > ntohl (ospf6->router_id))
    return 0;
  return 1;
}

int
ospf6_dbdesc_is_duplicate (struct ospf6_dbdesc *received,
                           struct ospf6_dbdesc *last_received)
{
  if (memcmp (received->options, last_received->options, 3) != 0)
    return 0;
  if (received->ifmtu != last_received->ifmtu)
    return 0;
  if (received->bits != last_received->bits)
    return 0;
  if (received->seqnum != last_received->seqnum)
    return 0;
  return 1;
}

void
ospf6_process_dbdesc_master (struct iovec *message, struct ospf6_neighbor *o6n)
{
  struct ospf6_header *ospf6_header;
  u_int16_t length, lsa_count;
  struct ospf6_dbdesc *dbdesc;
  struct ospf6_lsa_header *lsa_header;

  /* caluculate length */
  ospf6_header = (struct ospf6_header *) message[0].iov_base;
  length = ntohs (ospf6_header->len) - sizeof (struct ospf6_header);
  length = (length < message[1].iov_len ? length : message[1].iov_len);

  /* set database description pointer */
  dbdesc = (struct ospf6_dbdesc *) message[1].iov_base;

  switch (o6n->state)
    {
      case NBS_DOWN:
      case NBS_ATTEMPT:
      case NBS_TWOWAY:
        if (IS_OSPF6_DUMP_DBDESC)
          zlog_info ("DbDesc from %s Ignored: state less than Init",
                     o6n->str);
        return;

      case NBS_INIT:
        thread_execute (master, twoway_received, o6n, 0);
        if (o6n->state != NBS_EXSTART)
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("DbDesc from %s Ignored: state less than ExStart",
                         o6n->str);
            return;
          }
        /* else fall through to ExStart */
      case NBS_EXSTART:
        if (DDBIT_IS_SLAVE (dbdesc->bits) &&
            !DDBIT_IS_INITIAL (dbdesc->bits) &&
            ntohl (dbdesc->seqnum) == o6n->dbdesc_seqnum)
          {
            ospf6_neighbor_dbex_init (o6n);

            if (o6n->thread_rxmt_dbdesc)
              thread_cancel (o6n->thread_rxmt_dbdesc);
            o6n->thread_rxmt_dbdesc = (struct thread *) NULL;

            thread_add_event (master, negotiation_done, o6n, 0);
          }
        else
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("  negotiation failed with %s", o6n->str);
            return;
          }
        break;

      case NBS_EXCHANGE:
        /* duplicate dbdesc dropped by master */
        if (!memcmp (dbdesc, &o6n->last_dd,
                     sizeof (struct ospf6_dbdesc)))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("  duplicate dbdesc, drop");
            return;
          }

        /* check Initialize bit and Master/Slave bit */
        if (DDBIT_IS_INITIAL (dbdesc->bits))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("Initialize bit mismatch");
            thread_add_event (master, seqnumber_mismatch, o6n, 0);
            return;
          }
        if (DDBIT_IS_MASTER (dbdesc->bits))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("Master/Slave bit mismatch");
            thread_add_event (master, seqnumber_mismatch, o6n, 0);
            return;
          }

        /* dbdesc option check */
        if (memcmp (dbdesc->options, o6n->last_dd.options,
                    sizeof (dbdesc->options)))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("dbdesc option field changed");
            thread_add_event (master, seqnumber_mismatch, o6n, 0);
            return;
          }

        /* dbdesc sequence number check */
        if (ntohl (dbdesc->seqnum) != o6n->dbdesc_seqnum)
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_warn ("*** dbdesc seqnumber mismatch: %d expected",
                         o6n->dbdesc_seqnum);
            thread_add_event (master, seqnumber_mismatch, o6n, 0);
            return;
          }
        break;

      case NBS_LOADING:
      case NBS_FULL:
        /* duplicate dbdesc dropped by master */
        if (ospf6_dbdesc_is_duplicate (dbdesc, &o6n->last_dd))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("  duplicate dbdesc, drop");
            return;
          }
        else
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("  not duplicate dbdesc in state %s",
                         ospf6_neighbor_state_string[o6n->state]);
            thread_add_event (master, seqnumber_mismatch, o6n, 0);
            return;
          }
        break; /* not reached */

      default:
        assert (0);
        break; /* not reached */
    }

  /* process LSA headers */
  lsa_count = 0;
  for (lsa_header = (struct ospf6_lsa_header *) (dbdesc + 1);
       (char *)(lsa_header + 1) <= (char *)dbdesc + length;
       lsa_header++)
    {
      if (ospf6_dbex_check_dbdesc_lsa_header (lsa_header, o6n) < 0)
        {
          thread_add_event (master, seqnumber_mismatch, o6n, 0);
          return;
        }
      lsa_count ++;
    }

  /* increment dbdesc seqnum */
  o6n->dbdesc_seqnum++;

  /* cancel transmission/retransmission thread */
  if (o6n->thread_send_dbdesc)
    thread_cancel (o6n->thread_send_dbdesc);
  o6n->thread_send_dbdesc = (struct thread *) NULL;
  if (o6n->thread_rxmt_dbdesc)
    thread_cancel (o6n->thread_rxmt_dbdesc);
  o6n->thread_rxmt_dbdesc = (struct thread *) NULL;

  /* more bit check */
  if (!DD_IS_MBIT_SET (dbdesc->bits) && !DD_IS_MBIT_SET (o6n->dbdesc_bits))
    thread_add_event (master, exchange_done, o6n, 0);
  else
    o6n->thread_send_dbdesc =
      thread_add_event (master, ospf6_send_dbdesc, o6n, 0);

  /* save last received dbdesc */
  memcpy (&o6n->last_dd, dbdesc, sizeof (struct ospf6_dbdesc));

  /* statistics */
  o6n->lsa_receive[OSPF6_MESSAGE_TYPE_DBDESC] += lsa_count;

  return;
}

void
ospf6_process_dbdesc_slave (struct iovec *message, struct ospf6_neighbor *o6n)
{
  struct ospf6_header *ospf6_header;
  u_int16_t length, lsa_count;
  struct ospf6_dbdesc *dbdesc;
  struct ospf6_lsa_header *lsa_header;

  /* caluculate length */
  ospf6_header = (struct ospf6_header *) message[0].iov_base;
  length = ntohs (ospf6_header->len) - sizeof (struct ospf6_header);
  length = (length < message[1].iov_len ? length : message[1].iov_len);

  /* set database description pointer */
  dbdesc = (struct ospf6_dbdesc *) message[1].iov_base;

  switch (o6n->state)
    {
      case NBS_DOWN:
      case NBS_ATTEMPT:
      case NBS_TWOWAY:
        return;
      case NBS_INIT:
        thread_execute (master, twoway_received, o6n, 0);
        if (o6n->state != NBS_EXSTART)
          {
            return;
          }
        /* else fall through to ExStart */
      case NBS_EXSTART:
        if (DD_IS_IBIT_SET (dbdesc->bits) &&
            DD_IS_MBIT_SET (dbdesc->bits) &&
            DD_IS_MSBIT_SET (dbdesc->bits))
          {
            /* Master/Slave bit set to slave */
            DD_MSBIT_CLEAR (o6n->dbdesc_bits);
            /* Initialize bit clear */
            DD_IBIT_CLEAR (o6n->dbdesc_bits);
            /* sequence number set to master's */
            o6n->dbdesc_seqnum = ntohl (dbdesc->seqnum);
            ospf6_neighbor_dbex_init (o6n);

            if (o6n->thread_rxmt_dbdesc)
              thread_cancel (o6n->thread_rxmt_dbdesc);
            o6n->thread_rxmt_dbdesc = (struct thread *) NULL;

            thread_add_event (master, negotiation_done, o6n, 0);
          }
        else
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("negotiation failed");
            return;
          }
        break;

      case NBS_EXCHANGE:
        /* duplicate dbdesc dropped by master */
        if (!memcmp (dbdesc, &o6n->last_dd,
                     sizeof (struct ospf6_dbdesc)))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("  duplicate dbdesc, retransmit dbdesc");

            if (o6n->thread_rxmt_dbdesc)
              thread_cancel (o6n->thread_rxmt_dbdesc);
            o6n->thread_rxmt_dbdesc =
              thread_add_event (master, ospf6_send_dbdesc_rxmt, o6n, 0);

            return;
          }

        /* check Initialize bit and Master/Slave bit */
        if (DDBIT_IS_INITIAL (dbdesc->bits))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("Initialize bit mismatch");
            thread_add_event (master, seqnumber_mismatch, o6n, 0);
            return;
          }
        if (DDBIT_IS_SLAVE (dbdesc->bits))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("Master/Slave bit mismatch");
            thread_add_event (master, seqnumber_mismatch, o6n, 0);
            return;
          }

        /* dbdesc option check */
        if (memcmp (dbdesc->options, o6n->last_dd.options,
                    sizeof (dbdesc->options)))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("dbdesc option field changed");
            thread_add_event (master, seqnumber_mismatch, o6n, 0);
            return;
          }

        /* dbdesc sequence number check */
        if (ntohl (dbdesc->seqnum) != o6n->dbdesc_seqnum + 1)
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_warn ("*** dbdesc seqnumber mismatch: %d expected",
                         o6n->dbdesc_seqnum + 1);
            thread_add_event (master, seqnumber_mismatch, o6n, 0);
            return;
          }
        break;

      case NBS_LOADING:
      case NBS_FULL:
        /* duplicate dbdesc cause slave to retransmit */
        if (ospf6_dbdesc_is_duplicate (dbdesc, &o6n->last_dd))
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("  duplicate dbdesc, retransmit");

            if (o6n->thread_rxmt_dbdesc)
              thread_cancel (o6n->thread_rxmt_dbdesc);
            o6n->thread_rxmt_dbdesc =
              thread_add_event (master, ospf6_send_dbdesc_rxmt, o6n, 0);

            return;
          }
        else
          {
            if (IS_OSPF6_DUMP_DBDESC)
              zlog_info ("  not duplicate dbdesc in state %s",
                         ospf6_neighbor_state_string[o6n->state]);
            thread_add_event (master, seqnumber_mismatch, o6n, 0);
            return;
          }
        break; /* not reached */

      default:
        assert (0);
        break; /* not reached */
    }

  /* process LSA headers */
  lsa_count = 0;
  for (lsa_header = (struct ospf6_lsa_header *) (dbdesc + 1);
       (char *)(lsa_header + 1) <= (char *)dbdesc + length;
       lsa_header++)
    {
      if (ospf6_dbex_check_dbdesc_lsa_header (lsa_header, o6n) < 0)
        {
          thread_add_event (master, seqnumber_mismatch, o6n, 0);
          return;
        }
      lsa_count ++;
    }

  /* set dbdesc seqnum to master's */
  o6n->dbdesc_seqnum = ntohl (dbdesc->seqnum);

  if (o6n->thread_send_dbdesc)
    thread_cancel (o6n->thread_send_dbdesc);
  o6n->thread_send_dbdesc =
    thread_add_event (master, ospf6_send_dbdesc, o6n, 0);

  /* save last received dbdesc */
  memcpy (&o6n->last_dd, dbdesc, sizeof (struct ospf6_dbdesc));

  /* statistics */
  o6n->lsa_receive[OSPF6_MESSAGE_TYPE_DBDESC] += lsa_count;

  return;
}

void
ospf6_process_dbdesc (struct iovec *message,
                      struct in6_addr *src,
                      struct in6_addr *dst,
                      struct ospf6_interface *o6i,
                      u_int32_t router_id)
{
  struct ospf6_header *ospf6_header;
  u_int16_t length;
  struct ospf6_neighbor *o6n;
  struct ospf6_dbdesc *dbdesc;
  int Im_master = 0;

  /* assert interface */
  assert (o6i);

  /* caluculate length */
  ospf6_header = (struct ospf6_header *) message[0].iov_base;
  length = ntohs (ospf6_header->len) - sizeof (struct ospf6_header);
  length = (length < message[1].iov_len ? length : message[1].iov_len);

  /* set database description pointer */
  dbdesc = (struct ospf6_dbdesc *) message[1].iov_base;

  /* find neighbor. if cannot be found, reject this message */
  o6n = ospf6_neighbor_lookup (router_id, o6i);
  if (!o6n)
    {
      if (IS_OSPF6_DUMP_DBDESC)
        zlog_info ("neighbor not found, reject");
      return;
    }

  if (memcmp (src, &o6n->hisaddr, sizeof (struct in6_addr)))
    {
      if (IS_OSPF6_DUMP_MESSAGE (ospf6_header->type))
        zlog_info ("From Secondary I/F of the neighbor: ignore");
      return;
    }

  /* interface mtu check */
    /* xxx */

  /* check am I master */
  Im_master = ospf6_dbdesc_is_master (o6n);
  if (Im_master < 0)
    {
      return; /* can't decide which is master, return */
    }

  if (Im_master)
    ospf6_process_dbdesc_master (message, o6n);
  else
    ospf6_process_dbdesc_slave (message, o6n);

  return;
}

void
ospf6_process_lsreq (struct iovec *message,
                     struct in6_addr *src,
                     struct in6_addr *dst,
                     struct ospf6_interface *o6i,
                     u_int32_t router_id)
{
  struct ospf6_header *ospf6_header;
  u_int16_t length;
  struct ospf6_neighbor *o6n;
  struct ospf6_lsreq *lsreq;
  struct iovec response[OSPF6_MESSAGE_IOVEC_SIZE];
  struct ospf6_lsa *lsa;
  unsigned long lsanum = 0;
  struct ospf6_lsupdate lsupdate;
  char buf_id[16], buf_router[16], buf_type[16];

  /* assert interface */
  assert (o6i);

  /* caluculate length */
  ospf6_header = (struct ospf6_header *) message[0].iov_base;
  length = ntohs (ospf6_header->len) - sizeof (struct ospf6_header);
  length = (length < message[1].iov_len ? length : message[1].iov_len);

  /* find neighbor. if cannot be found, reject this message */
  o6n = ospf6_neighbor_lookup (router_id, o6i);
  if (!o6n)
    {
      if (IS_OSPF6_DUMP_LSREQ)
        zlog_info ("  neighbor not found, reject");
      return;
    }

  if (memcmp (src, &o6n->hisaddr, sizeof (struct in6_addr)))
    {
      if (IS_OSPF6_DUMP_MESSAGE (ospf6_header->type))
        zlog_info ("From Secondary I/F of the neighbor: ignore");
      return;
    }

  /* In states other than ExChange, Loading, or Full, the packet
     should be ignored. */
  if (o6n->state != NBS_EXCHANGE && o6n->state != NBS_LOADING
      && o6n->state != NBS_FULL)
    {
      if (IS_OSPF6_DUMP_LSREQ)
        zlog_info ("  neighbor state less than Exchange, reject");
      return;
    }

  /* Initialize response LSUpdate packet */
  OSPF6_MESSAGE_CLEAR (response);
  memset (&lsupdate, 0, sizeof (struct ospf6_lsupdate));
  OSPF6_MESSAGE_ATTACH (response, &lsupdate, sizeof (struct ospf6_lsupdate));

  /* process each request */
  lsanum = 0;
  for (lsreq = (struct ospf6_lsreq *) message[1].iov_base;
       (char *)(lsreq + 1) <= (char *)(message[1].iov_base + length);
       lsreq++)
    {
      inet_ntop (AF_INET, &lsreq->adv_router, buf_router, sizeof (buf_router));
      inet_ntop (AF_INET, &lsreq->id, buf_id, sizeof (buf_id));

      /* find instance of database copy */
      lsa = ospf6_lsdb_lookup (lsreq->type, lsreq->id, lsreq->adv_router,
                               ospf6_lsa_get_scope (lsreq->type, o6i));

      if (!lsa)
        {
          if (IS_OSPF6_DUMP_LSREQ)
            zlog_info ("BadLSReq: %s requests [%s ID=%s Adv=%s] not found",
                       o6n->str, ospf6_lsa_type_string (lsreq->type, buf_type,
                                                        sizeof (buf_type)),
                       buf_id, buf_router);
          thread_add_event (master, bad_lsreq, o6n, 0);
          return;
        }

      /* I/F MTU check */
      if (sizeof (struct ospf6_header) + sizeof (struct ospf6_lsupdate)
          + iov_totallen (response) + ntohs (lsa->header->length)
          > o6i->ifmtu)
        break;

      OSPF6_MESSAGE_ATTACH (response, lsa->header, ntohs (lsa->header->length));
      lsanum++;
    }

  /* send response LSUpdate to this request */
  if (lsanum)
    {
      lsupdate.lsupdate_num = htonl (lsanum);

      ospf6_message_send (OSPF6_MESSAGE_TYPE_LSUPDATE, response,
                          &o6n->hisaddr, o6i->if_id);
    }

  /* statistics */
  o6n->lsa_receive[OSPF6_MESSAGE_TYPE_LSREQ]
    += length / sizeof (struct ospf6_lsreq);
}

void
ospf6_process_lsupdate (struct iovec *message,
                        struct in6_addr *src,
                        struct in6_addr *dst,
                        struct ospf6_interface *o6i,
                        u_int32_t router_id)
{
  struct ospf6_header *ospf6_header;
  u_int16_t length;
  struct ospf6_lsupdate *lsupdate;
  struct ospf6_neighbor *o6n;
  unsigned long lsanum;
  struct ospf6_lsa_header *lsa_header;

  /* assert interface */
  assert (o6i);

  /* caluculate length */
  ospf6_header = (struct ospf6_header *) message[0].iov_base;
  length = ntohs (ospf6_header->len) - sizeof (struct ospf6_header);
  length = (length < message[1].iov_len ? length : message[1].iov_len);

  /* find neighbor. if cannot be found, reject this message */
  o6n = ospf6_neighbor_lookup (router_id, o6i);
  if (! o6n)
    {
      if (IS_OSPF6_DUMP_LSUPDATE)
        zlog_info ("  neighbor not found, reject");
      return;
    }

  if (memcmp (src, &o6n->hisaddr, sizeof (struct in6_addr)))
    {
      if (IS_OSPF6_DUMP_MESSAGE (ospf6_header->type))
        zlog_info ("From Secondary I/F of the neighbor: ignore");
      return;
    }

  /* if neighbor state less than ExChange, reject this message */
  if (o6n->state < NBS_EXCHANGE)
    {
      if (IS_OSPF6_DUMP_LSUPDATE)
        zlog_info ("  neighbor state less than Exchange, reject");
      return;
    }

  /* set linkstate update pointer */
  lsupdate = (struct ospf6_lsupdate *) message[1].iov_base;

  /* save linkstate update info */
  lsanum = ntohl (lsupdate->lsupdate_num);

  /* statistics */
  o6n->ospf6_stat_received_lsa += lsanum;
  o6n->ospf6_stat_received_lsupdate++;

  /* RFC2328 Section 10.9: When the neighbor responds to these requests
     with the proper Link State Update packet(s), the Link state request
     list is truncated and a new Link State Request packet is sent. */

  /* process LSAs */
  for (lsa_header = (struct ospf6_lsa_header *) (lsupdate + 1);
       lsanum && (char *)lsa_header < (char *)lsupdate + length;
       lsanum--)
    {
      ospf6_dbex_receive_lsa (lsa_header, o6n);
      lsa_header = OSPF6_LSA_NEXT (lsa_header);
    }

  /* send new Link State Request packet if this LS Update packet
     can be recognized as a response to our previous LS request */
  if (! IN6_IS_ADDR_MULTICAST(dst) &&
      (o6n->state == NBS_EXCHANGE || o6n->state == NBS_LOADING))
    thread_add_event (master, ospf6_send_lsreq, o6n, 0);

  return;
}

void
ospf6_process_lsack (struct iovec *message,
                     struct in6_addr *src,
                     struct in6_addr *dst,
                     struct ospf6_interface *o6i,
                     u_int32_t router_id)
{
  struct ospf6_header *ospf6_header;
  u_int16_t length;
  struct ospf6_neighbor *o6n;
  struct ospf6_lsa_header *lsa_header;
  struct ospf6_lsa *lsa, *copy, *rem;

  /* assert interface */
  assert (o6i);

  /* caluculate length */
  ospf6_header = (struct ospf6_header *) message[0].iov_base;
  length = ntohs (ospf6_header->len) - sizeof (struct ospf6_header);
  length = (length < message[1].iov_len ? length : message[1].iov_len);

  /* find neighbor. if cannot be found, reject this message */
  o6n = ospf6_neighbor_lookup (router_id, o6i);
  if (!o6n)
    {
      if (IS_OSPF6_DUMP_LSACK)
        zlog_info ("LSACK: neighbor not found, reject");
      return;
    }

  if (memcmp (src, &o6n->hisaddr, sizeof (struct in6_addr)))
    {
      if (IS_OSPF6_DUMP_LSACK)
        zlog_info ("LSACK: From Secondary I/F of the neighbor: ignore");
      return;
    }

  /* if neighbor state less than ExChange, reject this message */
  if (o6n->state < NBS_EXCHANGE)
    {
      if (IS_OSPF6_DUMP_LSACK)
        zlog_info ("LSACK: neighbor state less than Exchange, reject");
      return;
    }

  /* process each LSA header */
  for (lsa_header = (struct ospf6_lsa_header *) message[1].iov_base;
       (char *)(lsa_header + 1) <= (char *)(message[1].iov_base + length);
       lsa_header++)
    {
      /* find database copy */
      copy = ospf6_lsdb_lookup (lsa_header->type, lsa_header->ls_id,
                                lsa_header->advrtr,
                                ospf6_lsa_get_scope (lsa_header->type, o6i));

      /* if no database copy */
      if (!copy)
        {
          if (IS_OSPF6_DUMP_LSACK)
            zlog_info ("LSACK: no database copy, ignore");
          continue;
        }

      /* if not on his retrans list */
      rem = ospf6_lsdb_lookup_lsdb (copy->header->type, copy->header->id,
                                    copy->header->adv_router,
                                    o6n->retrans_list);
      if (rem == NULL)
        {
          if (IS_OSPF6_DUMP_LSACK)
            zlog_info ("LSACK: not on %s's retranslist, ignore", o6n->str);
          continue;
        }

      /* create temporary LSA from Ack message */
      lsa = ospf6_lsa_summary_create ((struct ospf6_lsa_header__ *) lsa_header);

      /* if the same instance, remove from retrans list.
         else, log and ignore */
      if (ospf6_lsa_check_recent (lsa, copy) == 0)
        ospf6_neighbor_retrans_remove (rem, o6n);
      else
        {
          /* Log the questionable acknowledgement,
             and examine the next one. */
          zlog_info ("LSACK: questionable acknowledge: %s", copy->str);
          zlog_info ("LSACK:   received: seq: %#x age: %hu",
                     ntohl (lsa->header->seqnum),
                     ntohs (lsa->header->age));
          zlog_info ("LSACK:   instance: seq: %#x age: %hu",
                     ntohl (copy->header->seqnum),
                     ospf6_lsa_age_current (copy));
        }

      /* release temporary LSA from Ack message */
      ospf6_lsa_delete (lsa);
    }

  ospf6_maxage_remover ();
  return;
}

struct {
  void (*process) (struct iovec *, struct in6_addr *, struct in6_addr *,
                   struct ospf6_interface *, u_int32_t);
} ospf6_message_process_type [] =
{
  {ospf6_process_unknown},
  {ospf6_process_hello},
  {ospf6_process_dbdesc},
  {ospf6_process_lsreq},
  {ospf6_process_lsupdate},
  {ospf6_process_lsack}
};

/* process ospf6 protocol header. then, call next process function
   for each message type */
static void 
ospf6_message_process (struct iovec *message,
                       struct in6_addr *src,
                       struct in6_addr *dst,
                       struct ospf6_interface *o6i)
{
  struct ospf6_header *ospf6_header = NULL;
  u_char type;
  u_int32_t router_id;
  char srcname[64];

  assert (o6i);
  assert (src);
  assert (dst);

  /* set ospf6_hdr pointer to head of buffer */
  ospf6_header = (struct ospf6_header *) message[0].iov_base;

  /* version check */
  if (ospf6_header->version != OSPF6_VERSION)
    {
      if (IS_OSPF6_DUMP_MESSAGE (ospf6_header->type))
        zlog_info ("version mismatch, drop");
      return;
    }

  /* area id check */
  if (ospf6_header->area_id != o6i->area->area_id)
    {
      if (ospf6_header->area_id == 0)
        {
          if (IS_OSPF6_DUMP_MESSAGE (ospf6_header->type))
            zlog_info ("virtual link not yet, drop");
          return;
        }

      if (IS_OSPF6_DUMP_MESSAGE (ospf6_header->type))
        zlog_info ("area id mismatch, drop");
      return;
    }

  /* instance id check */
  if (ospf6_header->instance_id != o6i->instance_id)
    {
      if (IS_OSPF6_DUMP_MESSAGE (ospf6_header->type))
        zlog_info ("instance id mismatch, drop");
      return;
    }

  /* message type check */
  type = (ospf6_header->type >= OSPF6_MESSAGE_TYPE_MAX ?
          OSPF6_MESSAGE_TYPE_UNKNOWN : ospf6_header->type);

  /* log */
  if (IS_OSPF6_DUMP_MESSAGE (type))
    {
      char srcname[64], dstname[64];
      inet_ntop (AF_INET6, dst, dstname, sizeof (dstname));
      inet_ntop (AF_INET6, src, srcname, sizeof (srcname));
      zlog_info ("Receive %s on %s",
                 ospf6_message_type_string[type], o6i->interface->name);
      zlog_info ("    %s -> %s", srcname, dstname);
      ospf6_message_log (message);
    }

  /* router id check */
  router_id = ospf6_header->router_id;
  if (ospf6_header->router_id == o6i->area->ospf6->router_id)
    {
      inet_ntop (AF_INET6, src, srcname, sizeof (srcname));
      zlog_warn ("*** Router-ID mismatch: from %s on %s",
                 srcname, o6i->interface->name);
      return;
    }

  /* octet statistics relies on some asumption:
       on ethernet, no IPv6 Extention header, etc */
#define OSPF6_IP6_HEADER_SIZE   40
#define OSPF6_ETHER_HEADER_SIZE 14
  o6i->message_stat[type].recv++;
  o6i->message_stat[type].recv_octet += ntohs (ospf6_header->len)
    + OSPF6_IP6_HEADER_SIZE + OSPF6_ETHER_HEADER_SIZE;

  /* futher process */
  (*ospf6_message_process_type[type].process) (&message[0], src, dst, o6i, router_id);

  return;
}

int
ospf6_receive (struct thread *thread)
{
  int sockfd;
  struct in6_addr src, dst;
  unsigned int ifindex;
  struct iovec message[OSPF6_MESSAGE_IOVEC_SIZE];
  struct ospf6_header ospf6_header;
  char buffer[OSPF6_MESSAGE_RECEIVE_BUFSIZE];
  struct ospf6_interface *o6i;
  unsigned char type;

  /* get socket */
  sockfd = THREAD_FD (thread);

  /* add next read thread */
  thread_add_read (master, ospf6_receive, NULL, sockfd);

  /* initialize */
  OSPF6_MESSAGE_CLEAR (message);
  memset (&ospf6_header, 0, sizeof (struct ospf6_header));

  OSPF6_MESSAGE_ATTACH (message, &ospf6_header, sizeof (struct ospf6_header));
  OSPF6_MESSAGE_ATTACH (message, buffer, OSPF6_MESSAGE_RECEIVE_BUFSIZE);

  /* receive message */
  ospf6_recvmsg (&src, &dst, &ifindex, message);

  type = (OSPF6_MESSAGE_TYPE_UNKNOWN < ospf6_header.type &&
          ospf6_header.type <= OSPF6_MESSAGE_TYPE_LSACK ?
          ospf6_header.type : OSPF6_MESSAGE_TYPE_UNKNOWN);
  o6i = ospf6_interface_lookup_by_index (ifindex);
  if (!o6i || !o6i->area)
    {
      //zlog_warn ("*** received interface ospf6 disabled");
      return 0;
    }

  /* if not passive, process message */
  if (! CHECK_FLAG (o6i->flag, OSPF6_INTERFACE_FLAG_PASSIVE))
    ospf6_message_process (message, &src, &dst, o6i);
  else if (IS_OSPF6_DUMP_MESSAGE (type))
    zlog_info ("Ignore message on passive interface %s",
               o6i->interface->name);

  return 0;
}


/* send section */
int
ospf6_message_length (struct iovec *message)
{
  int i, length = 0;
  for (i = 0; i < OSPF6_MESSAGE_IOVEC_SIZE; i++)
    {
      if (message[i].iov_base == NULL && message[i].iov_len == 0)
        break;
      length += message[i].iov_len;
    }
  return length;
}
#define OSPF6_MESSAGE_LENGTH(msg) \
(ospf6_message_length (msg))

void
ospf6_message_send (unsigned char type, struct iovec *msg,
                    struct in6_addr *dst, u_int ifindex)
{
  struct ospf6_interface *o6i;
  struct ospf6_header ospf6_header;
  char dst_name[64], src_name[64];
  struct iovec message[OSPF6_MESSAGE_IOVEC_SIZE];
  int msg_len;

  /* ospf6 interface lookup */
  o6i = ospf6_interface_lookup_by_index (ifindex);
  assert (o6i);

  msg_len = OSPF6_MESSAGE_LENGTH (msg);

  /* I/F MTU check */
#if 0
  if (msg_len + sizeof (struct ospf6_header) >= o6i->interface->mtu)
#else
  if (msg_len + sizeof (struct ospf6_header) >= o6i->ifmtu)
#endif
    {
      /* If Interface MTU is 0, save the case
         since zebra had been failed to get MTU from Kernel */
      if (o6i->interface->mtu != 0)
        {
          zlog_warn ("Message: Send failed on %s: exceeds I/F MTU",
                     o6i->interface->name);
          zlog_warn ("Message:   while sending %s: Len:%d MTU:%d",
                     ospf6_message_type_string[type],
                     msg_len + sizeof (struct ospf6_header),
                     o6i->ifmtu);
          return;
        }
      else
        {
          zlog_warn ("Message: I/F MTU check ignored on %s",
                     o6i->interface->name);
        }
    }

  /* Initialize */
  OSPF6_MESSAGE_CLEAR (message);

  /* set OSPF header */
  memset (&ospf6_header, 0, sizeof (ospf6_header));
  ospf6_header.version = OSPF6_VERSION;
  ospf6_header.type = type;
  ospf6_header.len = htons (msg_len + sizeof (struct ospf6_header));
  ospf6_header.router_id = ospf6->router_id;
  ospf6_header.area_id = o6i->area->area_id;
  /* checksum is calculated by kernel */
  ospf6_header.instance_id = o6i->instance_id;
  ospf6_header.reserved = 0;
  OSPF6_MESSAGE_ATTACH (message, &ospf6_header, sizeof (struct ospf6_header));

  /* Attach rest to message */
  OSPF6_MESSAGE_JOIN (message, msg);

  /* statistics */
  if (type >= OSPF6_MESSAGE_TYPE_MAX)
    type = OSPF6_MESSAGE_TYPE_UNKNOWN;
  o6i->message_stat[type].send++;
  o6i->message_stat[type].send_octet += ntohs (ospf6_header.len);

  /* log */
  if (IS_OSPF6_DUMP_MESSAGE (type))
    {
      inet_ntop (AF_INET6, dst, dst_name, sizeof (dst_name));
      if (o6i->lladdr)
        inet_ntop (AF_INET6, o6i->lladdr, src_name, sizeof (src_name));
      else
        strcpy (src_name, "Unknown");
      zlog_info ("Send %s on %s",
                 ospf6_message_type_string[type], o6i->interface->name);
      zlog_info ("    %s -> %s", src_name, dst_name);
      ospf6_message_log (message);
    }

  /* send message */
  ospf6_sendmsg (o6i->lladdr, dst, &ifindex, message);
}


int
ospf6_send_hello (struct thread *thread)
{
  listnode n;
  struct ospf6_interface *o6i;
  struct ospf6_neighbor *o6n;
  struct in6_addr dst;
  struct iovec message[OSPF6_MESSAGE_IOVEC_SIZE];
  struct ospf6_hello hello;
  char router_buffer[1024]; /* xxx */
  u_int router_size;

  /* which ospf6 interface to send */
  o6i = (struct ospf6_interface *) THREAD_ARG (thread);
  o6i->thread_send_hello = (struct thread *) NULL;

  /* assure interface is up */
  if (o6i->state <= IFS_DOWN)
    {
      if (IS_OSPF6_DUMP_HELLO)
        zlog_warn ("Send HELLO Failed: Interface not enabled: %s",
                   o6i->interface->name);
      return 0;
    }

  /* clear message buffer */
  OSPF6_MESSAGE_CLEAR (message);

  /* set Hello fields */
  hello.interface_id = htonl (o6i->if_id);
  hello.rtr_pri = o6i->priority;
  memcpy (hello.options, o6i->area->options, sizeof (hello.options));
  hello.hello_interval = htons (o6i->hello_interval);
  hello.router_dead_interval = htons (o6i->dead_interval);
  hello.dr = o6i->dr;
  hello.bdr = o6i->bdr;
  OSPF6_MESSAGE_ATTACH (message, &hello, sizeof (struct ospf6_hello));

  /* set neighbor router id */
  router_size = 0;
  for (n = listhead (o6i->neighbor_list); n; nextnode (n))
    {
      o6n = (struct ospf6_neighbor *) getdata (n);

      if (o6n->state < NBS_INIT)
        continue;

      if (router_size + sizeof (o6n->router_id) > sizeof (router_buffer))
        {
          zlog_warn ("Send HELLO: Buffer shortage on %s",
                     o6i->interface->name);
          break;
        }

      /* Copy Router-ID to Buffer */
      memcpy (router_buffer + router_size, &o6n->router_id,
              sizeof (o6n->router_id));
      router_size += sizeof (o6n->router_id);
    }
  OSPF6_MESSAGE_ATTACH (message, router_buffer, router_size);

  /* set destionation */
  inet_pton (AF_INET6, ALLSPFROUTERS6, &dst);

  /* send hello */
  ospf6_message_send (OSPF6_MESSAGE_TYPE_HELLO, message, &dst,
                      o6i->interface->ifindex);

  /* set next timer thread */
  o6i->thread_send_hello = thread_add_timer (master, ospf6_send_hello,
                                             o6i, o6i->hello_interval);

  return 0;
}

void
ospf6_dbdesc_seqnum_init (struct ospf6_neighbor *o6n)
{
  struct timeval tv;

  if (gettimeofday (&tv, (struct timezone *) NULL) < 0)
    tv.tv_sec = 1;

  o6n->dbdesc_seqnum = tv.tv_sec;

  if (IS_OSPF6_DUMP_DBDESC)
    zlog_info ("set dbdesc seqnum %d for %s", o6n->dbdesc_seqnum, o6n->str);
}

int
ospf6_send_dbdesc_rxmt (struct thread *thread)
{
  struct ospf6_lsdb_node node;
  struct ospf6_neighbor *o6n;
  struct iovec message[OSPF6_MESSAGE_IOVEC_SIZE];
  struct ospf6_lsa *lsa;
  struct ospf6_lsa_header *lsa_header;
  struct ospf6_dbdesc dbdesc;

  o6n = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (o6n);

  /* clear thread */
  o6n->thread_rxmt_dbdesc = (struct thread *) NULL;

  /* if state less than ExStart, do nothing */
  if (o6n->state < NBS_EXSTART)
    return 0;

  OSPF6_MESSAGE_CLEAR (message);

  /* set dbdesc */
  memcpy (dbdesc.options, o6n->ospf6_interface->area->options,
          sizeof (dbdesc.options));
  dbdesc.ifmtu = htons (o6n->ospf6_interface->interface->mtu);
  dbdesc.bits = o6n->dbdesc_bits;
  dbdesc.seqnum = htonl (o6n->dbdesc_seqnum);
  OSPF6_MESSAGE_ATTACH (message, &dbdesc, sizeof (struct ospf6_dbdesc));

  /* if this is not initial, set LSA summary to dbdesc */
  if (! DD_IS_IBIT_SET (o6n->dbdesc_bits))
    {
      for (ospf6_lsdb_head (&node, o6n->dbdesc_list);
           ! ospf6_lsdb_is_end (&node); ospf6_lsdb_next (&node))
        {
          lsa = node.lsa;

          /* xxx, no MTU check: no support for Dynamic MTU change */

          /* set age and add InfTransDelay */
          ospf6_lsa_age_update_to_send (lsa, o6n->ospf6_interface->transdelay);

          /* set LSA summary to send buffer */
          lsa_header = (struct ospf6_lsa_header *) lsa->lsa_hdr;
          OSPF6_MESSAGE_ATTACH (message, lsa_header,
                                sizeof (struct ospf6_lsa_header));
        }
    }

  /* send dbdesc */
  ospf6_message_send (OSPF6_MESSAGE_TYPE_DBDESC, message, &o6n->hisaddr,
                      o6n->ospf6_interface->interface->ifindex);

  /* if master, set futher retransmission */
  if (DD_IS_MSBIT_SET (o6n->dbdesc_bits))
    o6n->thread_rxmt_dbdesc =
      thread_add_timer (master, ospf6_send_dbdesc_rxmt,
                        o6n, o6n->ospf6_interface->rxmt_interval);

  /* statistics */
  o6n->ospf6_stat_retrans_dbdesc++;

  return 0;
}

int
ospf6_send_dbdesc (struct thread *thread)
{
  struct ospf6_neighbor *o6n;
  struct ospf6_lsa *lsa;
  struct iovec message[OSPF6_MESSAGE_IOVEC_SIZE];
  struct ospf6_dbdesc dbdesc;
  struct ospf6_lsdb_node node;

  o6n = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (o6n);

  /* clear thread */
  o6n->thread_send_dbdesc = (struct thread *) NULL;
  if (o6n->thread_rxmt_dbdesc)
    thread_cancel (o6n->thread_rxmt_dbdesc);
  o6n->thread_rxmt_dbdesc = (struct thread *) NULL;

  /* if state less than ExStart, do nothing */
  if (o6n->state < NBS_EXSTART)
    return 0;

  OSPF6_MESSAGE_CLEAR (message);
  OSPF6_MESSAGE_ATTACH (message, &dbdesc, sizeof (struct ospf6_dbdesc));

  /* clear previous LSA summary sent */
  ospf6_lsdb_remove_all (o6n->dbdesc_list);
  assert (o6n->dbdesc_list->count == 0);

  /* if this is not initial, set LSA summary to dbdesc */
  if (! DD_IS_IBIT_SET (o6n->dbdesc_bits))
    {
      for (ospf6_lsdb_head (&node, o6n->summary_list);
           ! ospf6_lsdb_is_end (&node);
           ospf6_lsdb_next (&node))
        {
          lsa = node.lsa;

          /* MTU check */
          if (OSPF6_MESSAGE_LENGTH (message)
              + sizeof (struct ospf6_lsa_header)
              + sizeof (struct ospf6_header)
              > o6n->ospf6_interface->ifmtu)
            break;

          /* debug */
          if (IS_OSPF6_DUMP_DBDESC)
            zlog_info ("Include DbDesc: %s", lsa->str);

          /* attach to dbdesclist */
          ospf6_neighbor_dbdesc_add (lsa, o6n);
          /* detach from summarylist */
          ospf6_neighbor_summary_remove (lsa, o6n);

          /* set age and add InfTransDelay */
          ospf6_lsa_age_update_to_send (lsa, o6n->ospf6_interface->transdelay);

          /* set LSA summary to send buffer */
          OSPF6_MESSAGE_ATTACH (message, lsa->header,
                                sizeof (struct ospf6_lsa_header));
        }

      if (o6n->summary_list->count == 0)
        {
          /* Clear more bit */
          DD_MBIT_CLEAR (o6n->dbdesc_bits);

          /* slave must schedule ExchangeDone on sending, here */
          if (! DD_IS_MSBIT_SET (o6n->dbdesc_bits))
            {
              if (! DD_IS_MBIT_SET (o6n->dbdesc_bits) &&
                  ! DD_IS_MBIT_SET (o6n->last_dd.bits))
                thread_add_event (master, exchange_done, o6n, 0);
            }
        }
    }

  /* if this is initial, set seqnum */
  if (DDBIT_IS_INITIAL (o6n->dbdesc_bits))
    ospf6_dbdesc_seqnum_init (o6n);

  /* set dbdesc */
  memcpy (dbdesc.options, o6n->ospf6_interface->area->options,
          sizeof (dbdesc.options));
  dbdesc.ifmtu = htons (o6n->ospf6_interface->interface->mtu);
  dbdesc.bits = o6n->dbdesc_bits;
  dbdesc.seqnum = htonl (o6n->dbdesc_seqnum);

  /* send dbdesc */
  ospf6_message_send (OSPF6_MESSAGE_TYPE_DBDESC, message, &o6n->hisaddr,
                      o6n->ospf6_interface->interface->ifindex);

  /* if master, set retransmission */
  if (DD_IS_MSBIT_SET (o6n->dbdesc_bits))
    o6n->thread_rxmt_dbdesc =
      thread_add_timer (master, ospf6_send_dbdesc_rxmt,
                          o6n, o6n->ospf6_interface->rxmt_interval);

  /* statistics */
  o6n->lsa_send[OSPF6_MESSAGE_TYPE_DBDESC] += o6n->dbdesc_list->count;

  return 0;
}

int
ospf6_send_lsreq_rxmt (struct thread *thread)
{
  struct ospf6_neighbor *o6n;

  o6n = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (o6n);

  o6n->thread_rxmt_lsreq = (struct thread *) NULL;
  o6n->thread_send_lsreq = thread_add_event (master, ospf6_send_lsreq, o6n, 0);
  return 0;
}

int
ospf6_send_lsreq (struct thread *thread)
{
  struct ospf6_neighbor *o6n;
  struct iovec message[OSPF6_MESSAGE_IOVEC_SIZE];
  struct ospf6_lsreq lsreq[OSPF6_MESSAGE_IOVEC_SIZE];
  struct ospf6_lsa *lsa;
  struct ospf6_lsdb_node node;
  int i;

  o6n = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (o6n);

  /* LSReq will be send only in ExStart or Loading */
  if (o6n->state != NBS_EXCHANGE && o6n->state != NBS_LOADING)
    return 0;

  /* clear thread */
  o6n->thread_send_lsreq = (struct thread *) NULL;
  if (o6n->thread_rxmt_lsreq)
    thread_cancel (o6n->thread_rxmt_lsreq);
  o6n->thread_rxmt_lsreq = (struct thread *) NULL;

  /* schedule loading_done if request list is empty */
  if (o6n->request_list->count == 0)
    {
      thread_add_event (master, loading_done, o6n, 0);
      return 0;
    }

  /* clear message buffer */
  OSPF6_MESSAGE_CLEAR (message);

  i = 0;
  for (ospf6_lsdb_head (&node, o6n->request_list);
       ! ospf6_lsdb_is_end (&node); ospf6_lsdb_next (&node))
    {
      lsa = node.lsa;

      /* Buffer Overflow */
      if (i >= OSPF6_MESSAGE_IOVEC_SIZE)
        break;

      /* I/F MTU check */
      if (OSPF6_MESSAGE_LENGTH (message)
          + sizeof (struct ospf6_lsreq)
          + sizeof (struct ospf6_header)
          > o6n->ospf6_interface->ifmtu)
        break;

      lsreq[i].mbz = 0;
      lsreq[i].type = lsa->header->type;
      lsreq[i].id = lsa->header->id;
      lsreq[i].adv_router = lsa->header->adv_router;

      OSPF6_MESSAGE_ATTACH (message, &lsreq[i], sizeof (struct ospf6_lsreq));
      i++;
    }

  ospf6_message_send (OSPF6_MESSAGE_TYPE_LSREQ, message, &o6n->hisaddr,
                      o6n->ospf6_interface->interface->ifindex);

  /* set retransmit thread */
  o6n->thread_rxmt_lsreq =
    thread_add_timer (master, ospf6_send_lsreq_rxmt,
                      o6n, o6n->ospf6_interface->rxmt_interval);

  /* statistics */
  o6n->lsa_send[OSPF6_MESSAGE_TYPE_LSREQ] += i;

  return 0;
}

/* Send LSUpdate directly to the neighbor, from his retransmission list */
int
ospf6_send_lsupdate_rxmt (struct thread *thread)
{
  struct ospf6_neighbor *o6n;
  struct iovec message[OSPF6_MESSAGE_IOVEC_SIZE];
  struct ospf6_lsupdate lsupdate;
  struct ospf6_lsa *lsa;
  struct ospf6_lsdb_node node;

  o6n = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (o6n);

  o6n->send_update = (struct thread *) NULL;

  if (o6n->ospf6_interface->state <= IFS_WAITING)
    return -1;

  /* clear message buffer */
  OSPF6_MESSAGE_CLEAR (message);

  /* set lsupdate header */
  lsupdate.lsupdate_num = 0; /* set gradually */
  OSPF6_MESSAGE_ATTACH (message, &lsupdate, sizeof (struct ospf6_lsupdate));

  /* for each LSA listed on retransmission-list */
  for (ospf6_lsdb_head (&node, o6n->retrans_list);
       ! ospf6_lsdb_is_end (&node);
       ospf6_lsdb_next (&node))
    {
      lsa = node.lsa;

      /* I/F MTU check */
      if (OSPF6_MESSAGE_LENGTH (message)
          + sizeof (struct ospf6_lsupdate)
          + sizeof (struct ospf6_header)
          + ntohs (lsa->header->length)
          > o6n->ospf6_interface->ifmtu)
        break;

      ospf6_lsa_age_update_to_send (lsa, o6n->ospf6_interface->transdelay);
      OSPF6_MESSAGE_ATTACH (message, lsa->header, ntohs (lsa->header->length));
      lsupdate.lsupdate_num++;
    }

  /* check and correct lsupdate */
  if (lsupdate.lsupdate_num == 0)
    return 0;
  lsupdate.lsupdate_num = htonl (lsupdate.lsupdate_num);

  if (IS_OSPF6_DUMP_LSUPDATE)
    zlog_info ("MESSAGE: retrsnsmit LSUpdate to %s", o6n->str);

  /* statistics */
  o6n->ospf6_stat_retrans_lsupdate++;

  ospf6_message_send (OSPF6_MESSAGE_TYPE_LSUPDATE, message,
                      &o6n->hisaddr, o6n->ospf6_interface->if_id);

  o6n->send_update = thread_add_timer (master, ospf6_send_lsupdate_rxmt, o6n,
                                       o6n->ospf6_interface->rxmt_interval);
  return 0;
}

/* Send LSUpdate containing one LSA directly to the neighbor.
   This is "implied acknowledgement" */
void
ospf6_send_lsupdate_direct (struct ospf6_lsa *lsa, struct ospf6_neighbor *o6n)
{
  struct iovec message[OSPF6_MESSAGE_IOVEC_SIZE];
  struct ospf6_lsupdate lsupdate;
  int lsa_len;

  /* clear message buffer */
  OSPF6_MESSAGE_CLEAR (message);

  /* set lsupdate header */
  lsupdate.lsupdate_num = ntohl (1);
  OSPF6_MESSAGE_ATTACH (message, &lsupdate, sizeof (struct ospf6_lsupdate));

  /* set one LSA */
  lsa_len = ntohs (lsa->lsa_hdr->lsh_len);
  ospf6_lsa_age_update_to_send (lsa, o6n->ospf6_interface->transdelay);
  OSPF6_MESSAGE_ATTACH (message, lsa->lsa_hdr, lsa_len);

  ospf6_message_send (OSPF6_MESSAGE_TYPE_LSUPDATE, message, &o6n->hisaddr,
                      o6n->ospf6_interface->if_id);
}

/* Send LSUpdate containing one LSA by multicast.
   On non-broadcast link, send it to each neighbor by unicast.
   This is ordinary flooding */
void
ospf6_send_lsupdate_flood (struct ospf6_lsa *lsa, struct ospf6_interface *o6i)
{
  struct iovec message[OSPF6_MESSAGE_IOVEC_SIZE];
  struct ospf6_lsupdate lsupdate;
  struct in6_addr dst;
  int lsa_len;

  /* clear message buffer */
  OSPF6_MESSAGE_CLEAR (message);

  /* set lsupdate header */
  lsupdate.lsupdate_num = ntohl (1);
  OSPF6_MESSAGE_ATTACH (message, &lsupdate, sizeof (struct ospf6_lsupdate));

  /* set one LSA */
  lsa_len = ntohs (lsa->lsa_hdr->lsh_len);
  ospf6_lsa_age_update_to_send (lsa, o6i->transdelay);
  OSPF6_MESSAGE_ATTACH (message, lsa->lsa_hdr, lsa_len);

  if (if_is_broadcast (o6i->interface))
    {
      /* set destination */
      if (o6i->state == IFS_DR || o6i->state == IFS_BDR)
        inet_pton (AF_INET6, ALLSPFROUTERS6, &dst);
      else
        inet_pton (AF_INET6, ALLDROUTERS6, &dst);
    }
  else
    {
      /* IPv6 relies on link local multicast */
      inet_pton (AF_INET6, ALLSPFROUTERS6, &dst);
    }

  ospf6_message_send (OSPF6_MESSAGE_TYPE_LSUPDATE, message, &dst,
                      o6i->if_id);
}

int
ospf6_send_lsack_delayed (struct thread *thread)
{
  struct ospf6_interface *o6i;
  struct iovec message[MAXIOVLIST];
  struct ospf6_lsa *lsa;
  struct ospf6_lsdb_node node;

  o6i = THREAD_ARG (thread);
  assert (o6i);

  if (IS_OSPF6_DUMP_LSACK)
    zlog_info ("LSACK: Delayed LSAck for %s\n", o6i->interface->name);

  o6i->thread_send_lsack_delayed = (struct thread *) NULL;

  if (o6i->state <= IFS_WAITING)
    return 0;

  if (o6i->ack_list->count == 0)
    return 0;

  iov_clear (message, MAXIOVLIST);

  for (ospf6_lsdb_head (&node, o6i->ack_list);
       ! ospf6_lsdb_is_end (&node);
       ospf6_lsdb_next (&node))
    {
      lsa = node.lsa;
      if (IS_OVER_MTU (message, o6i->ifmtu, sizeof (struct ospf6_lsa_hdr)))
        break;

      OSPF6_MESSAGE_ATTACH (message, lsa->header,
                            sizeof (struct ospf6_lsa_header));
      ospf6_interface_delayed_ack_remove (lsa, o6i);
    }

  /* statistics */
  o6i->ospf6_stat_delayed_lsack++;

  switch (o6i->state)
    {
    case IFS_DR:
    case IFS_BDR:
      ospf6_message_send (OSPF6_MESSAGE_TYPE_LSACK, message,
                          &allspfrouters6.sin6_addr, o6i->if_id);
      break;
    default:
      ospf6_message_send (OSPF6_MESSAGE_TYPE_LSACK, message,
                          &alldrouters6.sin6_addr, o6i->if_id);
      break;
    }

  iov_clear (message, MAXIOVLIST);
  return 0;
}

