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

#ifndef OSPF6_LSA_H
#define OSPF6_LSA_H

#include "ospf6_hook.h"

#define ONESECOND_USEC  1000000
#define USEC_TVDIFF(tv2,tv1) \
  (((tv2)->tv_sec - (tv1)->tv_sec) * ONESECOND_USEC \
   + ((tv2)->tv_usec - (tv1)->tv_usec))
#define SEC_TVDIFF(tv2,tv1) \
  (USEC_TVDIFF((tv2),(tv1)) / ONESECOND_USEC)

/* LSA definition */

#define MAXLSASIZE   1024

#define OSPF6_LSA_MAXAGE           3600    /* 1 hour */
#define OSPF6_LSA_CHECKAGE         300     /* 5 min */
#define OSPF6_LSA_MAXAGEDIFF       900     /* 15 min */

/* Type */
#define OSPF6_LSA_TYPE_NONE             0x0000
#define OSPF6_LSA_TYPE_ROUTER           0x2001
#define OSPF6_LSA_TYPE_NETWORK          0x2002
#define OSPF6_LSA_TYPE_INTER_PREFIX     0x2003
#define OSPF6_LSA_TYPE_INTER_ROUTER     0x2004
#define OSPF6_LSA_TYPE_AS_EXTERNAL      0x4005
#define OSPF6_LSA_TYPE_GROUP_MEMBERSHIP 0x2006
#define OSPF6_LSA_TYPE_TYPE_7           0x2007
#define OSPF6_LSA_TYPE_LINK             0x0008
#define OSPF6_LSA_TYPE_INTRA_PREFIX     0x2009
#define OSPF6_LSA_TYPE_MAX              0x000a
#define OSPF6_LSA_TYPE_SIZE             0x000b

/* Masks for LS Type : RFC 2740 A.4.2.1 "LS type" */
#define OSPF6_LSTYPE_UBIT_MASK        0x8000
#define OSPF6_LSTYPE_SCOPE_MASK       0x6000
#define OSPF6_LSTYPE_CODE_MASK        0x1fff

#define OSPF6_LSA_TYPESW_MASK         OSPF6_LSTYPE_CODE_MASK
#define OSPF6_LSA_TYPESW(x) (ntohs((x)) & OSPF6_LSA_TYPESW_MASK)
#define OSPF6_LSA_TYPESW_ISKNOWN(x) (OSPF6_LSA_TYPESW(x) < OSPF6_LSA_TYPE_MAX)

/* lsa scope */
#define OSPF6_LSA_SCOPE_LINKLOCAL  0x0000
#define OSPF6_LSA_SCOPE_AREA       0x2000
#define OSPF6_LSA_SCOPE_AS         0x4000
#define OSPF6_LSA_SCOPE_RESERVED   0x6000
#define OSPF6_LSA_IS_SCOPE_LINKLOCAL(x) \
  (((x) & OSPF6_LSTYPE_SCOPE_MASK) == OSPF6_LSA_SCOPE_LINKLOCAL)
#define OSPF6_LSA_IS_SCOPE_AREA(x) \
  (((x) & OSPF6_LSTYPE_SCOPE_MASK) == OSPF6_LSA_SCOPE_AREA)
#define OSPF6_LSA_IS_SCOPE_AS(x) \
  (((x) & OSPF6_LSTYPE_SCOPE_MASK) == OSPF6_LSA_SCOPE_AS)

/* NOTE that all LSAs are kept NETWORK BYTE ORDER */

/* Router-LSA */
struct ospf6_router_lsa
{
  u_char bits;
  u_char options[3];
  /* followed by ospf6_router_lsd(s) */
};

#define OSPF6_ROUTER_LSA_BIT_B     (1 << 0)
#define OSPF6_ROUTER_LSA_BIT_E     (1 << 1)
#define OSPF6_ROUTER_LSA_BIT_V     (1 << 2)
#define OSPF6_ROUTER_LSA_BIT_W     (1 << 3)

#define OSPF6_ROUTER_LSA_SET(x,y)    ((x)->bits |=  (y))
#define OSPF6_ROUTER_LSA_ISSET(x,y)  ((x)->bits &   (y))
#define OSPF6_ROUTER_LSA_CLEAR(x,y)  ((x)->bits &= ~(y))
#define OSPF6_ROUTER_LSA_CLEAR_ALL_BITS(x)  ((x)->bits = 0)

/* Link State Description in Router-LSA */
struct ospf6_router_lsd
{
  u_char    type;
  u_char    reserved;
  u_int16_t metric;                /* output cost */
  u_int32_t interface_id;
  u_int32_t neighbor_interface_id;
  u_int32_t neighbor_router_id;
};

#define OSPF6_ROUTER_LSD_TYPE_POINTTOPOINT       1
#define OSPF6_ROUTER_LSD_TYPE_TRANSIT_NETWORK    2
#define OSPF6_ROUTER_LSD_TYPE_STUB_NETWORK       3
#define OSPF6_ROUTER_LSD_TYPE_VIRTUAL_LINK       4

/* Network-LSA */
struct ospf6_network_lsa
{
  u_char reserved;
  u_char options[3];
  /* followed by ospf6_netowrk_lsd(s) */
};

/* Link State Description in Router-LSA */
struct ospf6_network_lsd
{
  u_int32_t adv_router;
};

/* Link-LSA */
struct ospf6_link_lsa
{
  u_char          llsa_rtr_pri;
  u_char          llsa_options[3];
  struct in6_addr llsa_linklocal;
  u_int32_t       llsa_prefix_num;
  /* followed by prefix(es) */
};

/* Intra-Area-Prefix-LSA */
struct ospf6_intra_area_prefix_lsa
{
  u_int16_t prefix_number;
  u_int16_t refer_lstype;
  u_int32_t refer_lsid;
  u_int32_t refer_advrtr;
};

/* AS-External-LSA */
struct ospf6_as_external_lsa
{
  u_char    ase_bits;
  u_char    ase_pre_metric; /* 1st byte of metric */
  u_int16_t ase_metric;     /* 2nd, 3rd byte of metric */
#if 1
  struct ospf6_prefix ospf6_prefix;
#else
  u_char    ase_prefix_len;
  u_char    ase_prefix_opt;
  u_int16_t ase_refer_lstype;
  /* followed by one address prefix */
#endif
  /* followed by none or one forwarding address */
  /* followed by none or one external route tag */
  /* followed by none or one referenced LS-ID */
};
#define ASE_LSA_BIT_T     (1 << 0)
#define ASE_LSA_BIT_F     (1 << 1)
#define ASE_LSA_BIT_E     (1 << 2)

#define ASE_LSA_SET(x,y)    ((x)->ase_bits |=  (y))
#define ASE_LSA_ISSET(x,y)  ((x)->ase_bits &   (y))
#define ASE_LSA_CLEAR(x,y)  ((x)->ase_bits &= ~(y))

/* LSA Header */
struct ospf6_lsa_hdr
{
  u_int16_t lsh_age;      /* LS age */
  u_int16_t lsh_type;     /* LS type */
  u_int32_t lsh_id;       /* Link State ID */
  u_int32_t lsh_advrtr;   /* Advertising Router */
  u_int32_t lsh_seqnum;   /* LS sequence number */
  u_int16_t lsh_cksum;    /* LS checksum */
  u_int16_t lsh_len;      /* length */
};
struct ospf6_lsa_header
{
  u_int16_t age;       /* LS age */
  u_int16_t type;      /* LS type */
  u_int32_t ls_id;     /* Link State ID */
  u_int32_t advrtr;    /* Advertising Router */
  u_int32_t seqnum;    /* LS sequence number */
  u_int16_t checksum;  /* LS checksum */
  u_int16_t length;    /* LSA length */
};
struct ospf6_lsa_header__
{
  u_int16_t age;        /* LS age */
  u_int16_t type;       /* LS type */
  u_int32_t id;         /* Link State ID */
  u_int32_t adv_router; /* Advertising Router */
  u_int32_t seqnum;     /* LS sequence number */
  u_int16_t checksum;   /* LS checksum */
  u_int16_t length;     /* LSA length */
};

#define OSPF6_LSA_NEXT(x) ((struct ospf6_lsa_header *) \
                             ((char *)(x) + ntohs ((x)->length)))

#define OSPF6_LSA_HEADER_END(header) \
  ((void *)((char *)(header) + sizeof (struct ospf6_lsa_header)))

struct ospf6_lsa
{
  char                   str[256];  /* dump string */

  u_long                 lock;      /* reference counter */
  int                    summary;   /* indicate this is LS header only */
  void                  *scope;     /* pointer of scoped data structure */
  unsigned char          flag;      /* to decide ack type and refresh */
  struct timeval         birth;     /* tv_sec when LS age 0 */
  struct timeval         installed; /* installed time */
  struct timeval         originated; /* installed time */
  struct thread         *expire;
  struct thread         *refresh;   /* For self-originated LSA */
  u_int32_t              from;      /* from which neighbor */

  /* lsa instance */
  struct ospf6_lsa_hdr  *lsa_hdr;
  struct ospf6_lsa_header__ *header;

  /* statistics */
  u_long turnover_num;
  u_long turnover_total;
  u_long turnover_min;
  u_long turnover_max;
};

struct ospf6_lsa_slot
{
  struct ospf6_lsa_slot *prev;
  struct ospf6_lsa_slot *next;

  u_int16_t  type;
  char      *name;

  int (*func_print)        (struct ospf6_lsa *lsa);
  int (*func_show)         (struct vty *vty, struct ospf6_lsa *lsa);
  int (*func_refresh)      (void *lsa);

  int (*database_add)      (void *lsa);
  int (*database_remove)   (void *lsa);

  struct ospf6_hook_master database_hook;

  struct ospf6_hook hook_neighbor;
  struct ospf6_hook hook_interface;
  struct ospf6_hook hook_area;
  struct ospf6_hook hook_top;
  struct ospf6_hook hook_database;
  struct ospf6_hook hook_route;
};

#define OSPF6_LSA_FLAG_FLOODBACK  0x01
#define OSPF6_LSA_FLAG_DUPLICATE  0x02
#define OSPF6_LSA_FLAG_IMPLIEDACK 0x04
#define OSPF6_LSA_FLAG_REFRESH    0x08

/* Back pointer check, Is X's reference field bound to Y ? */
#define x_ipl(x) ((struct intra_area_prefix_lsa *)LSH_NEXT((x)->lsa_hdr))
#define is_reference_network_ok(x,y) \
          ((x_ipl(x))->intra_prefix_refer_lstype == (y)->lsa_hdr->lsh_type &&\
           (x_ipl(x))->intra_prefix_refer_lsid == (y)->lsa_hdr->lsh_id &&\
           (x_ipl(x))->intra_prefix_refer_advrtr == (y)->lsa_hdr->lsh_advrtr)
  /* referencing router's ifid must be 0,
     see draft-ietf-ospf-ospfv6-06.txt */
#define is_reference_router_ok(x,y) \
          ((x_ipl(x))->intra_prefix_refer_lstype == (y)->lsa_hdr->lsh_type &&\
           (x_ipl(x))->intra_prefix_refer_lsid == htonl (0) &&\
           (x_ipl(x))->intra_prefix_refer_advrtr == (y)->lsa_hdr->lsh_advrtr)

/* MaxAge check.  */
/* ospf6_lsa_is_maxage (struct ospf6_lsa *lsa) */
#define IS_LSA_MAXAGE(L)      (ospf6_lsa_age_current (L) == OSPF6_LSA_MAXAGE)

struct ospf6_lsa_slot *ospf6_lsa_slot_get (u_int16_t type);
int ospf6_lsa_slot_register (struct ospf6_lsa_slot *src);
int ospf6_lsa_slot_unregister (u_int16_t type);

extern struct ospf6_lsa_slot *slot_head;
#define CALL_FOREACH_LSA_HOOK(hook,func,data) \
  if (ospf6)\
    {\
      struct ospf6_lsa_slot *slot;\
      for (slot = slot_head; slot; slot = slot->next)\
        {\
          if (slot->hook.func)\
            (*slot->hook.func) (data);\
        }\
    }
#define CALL_LSA_FUNC(type,func,data) \
  if (ospf6)\
    {\
      struct ospf6_lsa_slot *slot;\
      slot = ospf6_lsa_slot_get (type);\
      if (slot && slot->func)\
        {\
          (*slot->func) (data);\
        }\
      else\
        {\
          zlog_warn ("LSA: No slot for type %#x: %s line:%d",\
                     ntohs (type), __FILE__, __LINE__);\
        }\
    }

#define CALL_LSA_DATABASE_ADD(type,data) \
  if (ospf6)\
    {\
      struct ospf6_lsa_slot *slot;\
      slot = ospf6_lsa_slot_get (type);\
      if (slot)\
        {\
          CALL_ADD_HOOK (&slot->database_hook, data);\
        }\
      else\
        {\
          zlog_warn ("LSA: No slot for type %#x: %s line:%d",\
                     ntohs (type), __FILE__, __LINE__);\
        }\
    }
#define CALL_LSA_DATABASE_CHANGE(type,data) \
  if (ospf6)\
    {\
      struct ospf6_lsa_slot *slot;\
      slot = ospf6_lsa_slot_get (type);\
      if (slot)\
        {\
          CALL_CHANGE_HOOK (&slot->database_hook, data);\
        }\
      else\
        {\
          zlog_warn ("LSA: No slot for type %#x: %s line:%d",\
                     ntohs (type), __FILE__, __LINE__);\
        }\
    }
#define CALL_LSA_DATABASE_REMOVE(type,data) \
  if (ospf6)\
    {\
      struct ospf6_lsa_slot *slot;\
      slot = ospf6_lsa_slot_get (type);\
      if (slot)\
        {\
          CALL_REMOVE_HOOK (&slot->database_hook, data);\
        }\
      else\
        {\
          zlog_warn ("LSA: No slot for type %#x: %s line:%d",\
                     ntohs (type), __FILE__, __LINE__);\
        }\
    }

void ospf6_lsa_init ();

/* Function Prototypes */

struct router_lsd *
get_router_lsd (u_int32_t, struct ospf6_lsa *);
unsigned long get_ifindex_to_router (u_int32_t, struct ospf6_lsa *);

int ospf6_lsa_differ (struct ospf6_lsa *lsa1, struct ospf6_lsa *lsa2);
int ospf6_lsa_match (u_int16_t, u_int32_t, u_int32_t,
                     struct ospf6_lsa_header *);

void ospf6_lsa_show (struct vty *, struct ospf6_lsa *);
void ospf6_lsa_show_dump (struct vty *, struct ospf6_lsa *);
void ospf6_lsa_show_summary (struct vty *, struct ospf6_lsa *);
void ospf6_lsa_show_summary_header (struct vty *);

struct ospf6_lsa *
ospf6_lsa_create (struct ospf6_lsa_header *);
struct ospf6_lsa *
ospf6_lsa_summary_create (struct ospf6_lsa_header__ *);
void
ospf6_lsa_delete (struct ospf6_lsa *);

void ospf6_lsa_lock (struct ospf6_lsa *);
void ospf6_lsa_unlock (struct ospf6_lsa *);

unsigned short ospf6_lsa_age_current (struct ospf6_lsa *);
int ospf6_lsa_is_maxage (struct ospf6_lsa *);
void ospf6_lsa_age_update_to_send (struct ospf6_lsa *, u_int32_t);
void ospf6_lsa_premature_aging (struct ospf6_lsa *);

int ospf6_lsa_check_recent (struct ospf6_lsa *, struct ospf6_lsa *);

int
ospf6_lsa_lsd_num (struct ospf6_lsa_header *lsa_header);
void *
ospf6_lsa_lsd_get (int index, struct ospf6_lsa_header *lsa_header);
int
ospf6_lsa_lsd_is_refer_ok (int index1, struct ospf6_lsa_header *lsa_header1,
                           int index2, struct ospf6_lsa_header *lsa_header2);

int ospf6_lsa_expire (struct thread *);
int ospf6_lsa_refresh (struct thread *);

u_short ospf6_lsa_checksum (struct ospf6_lsa_header *);

void ospf6_lsa_update_network (char *ifname);
void ospf6_lsa_update_link (char *ifname);
void ospf6_lsa_update_as_external (u_int32_t ls_id);
void ospf6_lsa_update_intra_prefix_transit (char *ifname);
void ospf6_lsa_update_intra_prefix_stub (u_int32_t area_id);

u_int16_t ospf6_lsa_get_scope_type (u_int16_t);
int ospf6_lsa_is_known_type (struct ospf6_lsa_header *lsa_header);

char *ospf6_lsa_type_string (u_int16_t type, char *buf, int bufsize);
char *ospf6_lsa_router_bits_string (u_char router_bits, char *buf, int size);

u_long
ospf6_lsa_has_elasped (u_int16_t, u_int32_t, u_int32_t, void *);
void
ospf6_lsa_originate (u_int16_t, u_int32_t, u_int32_t, char *, int, void *);

#endif /* OSPF6_LSA_H */

