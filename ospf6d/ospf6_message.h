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

#ifndef OSPF6_MESSAGE_H
#define OSPF6_MESSAGE_H

#include "ospf6_prefix.h"
#include "ospf6_lsa.h"

/* Type */
#define OSPF6_MESSAGE_TYPE_NONE     0x0
#define OSPF6_MESSAGE_TYPE_UNKNOWN  0x0
#define OSPF6_MESSAGE_TYPE_HELLO    0x1  /* Discover/maintain neighbors */
#define OSPF6_MESSAGE_TYPE_DBDESC   0x2  /* Summarize database contents */
#define OSPF6_MESSAGE_TYPE_LSREQ    0x3  /* Database download */
#define OSPF6_MESSAGE_TYPE_LSUPDATE 0x4  /* Database update */
#define OSPF6_MESSAGE_TYPE_LSACK    0x5  /* Flooding acknowledgment */
#define OSPF6_MESSAGE_TYPE_MAX      0x6

/* OSPFv3 packet header */
struct ospf6_header
{
  u_char    version;
  u_char    type;
  u_int16_t len;
  u_int32_t router_id;
  u_int32_t area_id;
  u_int16_t cksum;
  u_char    instance_id;
  u_char    reserved;
};

/* Hello */
#define MAXLISTEDNBR     64
struct ospf6_hello
{
  u_int32_t interface_id;
  u_char    rtr_pri;
  u_char    options[3];
  u_int16_t hello_interval;
  u_int16_t router_dead_interval;
  u_int32_t dr;
  u_int32_t bdr;
};

/* Database Description */
struct ospf6_dbdesc
{
  u_char    mbz1;
  u_char    options[3];
  u_int16_t ifmtu;
  u_char    mbz2;
  u_char    bits;
  u_int32_t seqnum;
  /* Followed by LSAs */
};
#define DEFAULT_INTERFACE_MTU 1500

#define DD_IS_MSBIT_SET(x) ((x) & (1 << 0))
#define DD_MSBIT_SET(x) ((x) |= (1 << 0))
#define DD_MSBIT_CLEAR(x) ((x) &= ~(1 << 0))
#define DD_IS_MBIT_SET(x) ((x) & (1 << 1))
#define DD_MBIT_SET(x) ((x) |= (1 << 1))
#define DD_MBIT_CLEAR(x) ((x) &= ~(1 << 1))
#define DD_IS_IBIT_SET(x) ((x) & (1 << 2))
#define DD_IBIT_SET(x) ((x) |= (1 << 2))
#define DD_IBIT_CLEAR(x) ((x) &= ~(1 << 2))

#define DDBIT_IS_MASTER(x)   ((x) &   (1 << 0))
#define DDBIT_IS_SLAVE(x)  (!((x) &   (1 << 0)))
#define DDBIT_SET_MASTER(x)  ((x) |=  (1 << 0))
#define DDBIT_SET_SLAVE(x)   ((x) |= ~(1 << 0))
#define DDBIT_IS_MORE(x)     ((x) &   (1 << 1))
#define DDBIT_SET_MORE(x)    ((x) |=  (1 << 1))
#define DDBIT_CLR_MORE(x)    ((x) |= ~(1 << 1))
#define DDBIT_IS_INITIAL(x)  ((x) &   (1 << 2))
#define DDBIT_SET_INITIAL(x) ((x) |=  (1 << 2))
#define DDBIT_CLR_INITIAL(x) ((x) |= ~(1 << 2))

#define OSPF6_DBDESC_BIT_MASTER  0x01
#define OSPF6_DBDESC_BIT_MORE    0x02
#define OSPF6_DBDESC_BIT_INITIAL 0x04

/* Link State Request */
struct ospf6_lsreq
{
  u_int16_t mbz;          /* Must Be Zero */
  u_int16_t type;         /* LS type */
  u_int32_t id;           /* Link State ID */
  u_int32_t adv_router;   /* Advertising Router */
};

/* Link State Update */
struct ospf6_lsupdate
{
  u_int32_t lsupdate_num;
};

/* Link State Acknowledgement */
  /* no need for structure,
     it will include only LSA header in the packet body.*/

/* definition for ospf6_message.c */
#define OSPF6_MESSAGE_RECEIVE_BUFSIZE 5120
#define OSPF6_MESSAGE_IOVEC_END       1024

#define IS_OVER_MTU(message,mtu,addsize) \
          (iov_totallen(message)+(addsize) >= \
            (mtu)-sizeof(struct ospf6_header))

#define OSPF6_MESSAGE_IOVEC_SIZE  1024
#define OSPF6_MESSAGE_CLEAR(msg) \
do { \
  int x; \
  for (x = 0; x < OSPF6_MESSAGE_IOVEC_SIZE; x++) \
    { \
      (msg)[x].iov_base = NULL; \
      (msg)[x].iov_len = 0; \
    } \
} while (0)

#define OSPF6_MESSAGE_ATTACH(msg,buf,bufsize) \
do { \
  int x; \
  for (x = 0; x < OSPF6_MESSAGE_IOVEC_SIZE; x++) \
    if ((msg)[x].iov_base == (void *)NULL && (msg)[x].iov_len == 0) \
      break; \
  if (x < OSPF6_MESSAGE_IOVEC_SIZE - 1) \
    { \
      (msg)[x].iov_base = (void *)(buf); \
      (msg)[x].iov_len = (bufsize); \
    } \
} while (0)

#define OSPF6_MESSAGE_JOIN(msg,join) \
do { \
  int x,y; \
  for (x = 0; x < OSPF6_MESSAGE_IOVEC_SIZE; x++) \
    if ((msg)[x].iov_base == NULL && (msg)[x].iov_len == 0) \
      break; \
  for (y = x; y < OSPF6_MESSAGE_IOVEC_SIZE; y++) \
    { \
      (msg)[y].iov_base = (join)[y - x].iov_base; \
      (msg)[y].iov_len = (join)[y - x].iov_len; \
    } \
} while (0)


/* Statistics */
struct ospf6_message_stat
{
  u_int32_t send;
  u_int32_t send_octet;
  u_int32_t recv;
  u_int32_t recv_octet;
};

/* Type string */
extern char *ospf6_message_type_string[];

/* Function Prototypes */
int ospf6_receive (struct thread *);

int ospf6_send_hello (struct thread *);
int ospf6_send_dbdesc_rxmt (struct thread *);
int ospf6_send_dbdesc (struct thread *);
int ospf6_send_lsreq (struct thread *);

struct ospf6_neighbor;
struct ospf6_interface;
int
ospf6_send_lsupdate_rxmt (struct thread *);
void
ospf6_send_lsupdate_direct (struct ospf6_lsa *, struct ospf6_neighbor *);
void
ospf6_send_lsupdate_flood (struct ospf6_lsa *, struct ospf6_interface *);

int ospf6_send_lsack_delayed (struct thread *);
int ospf6_send_lsack_direct (struct thread *);

void ospf6_message_send (u_char, struct iovec *, struct in6_addr *, u_int);

#endif /* OSPF6_MESSAGE_H */

