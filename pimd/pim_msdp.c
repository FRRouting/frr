/*
 * IP MSDP for Quagga
 * Copyright (C) 2016 Cumulus Networks, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

#include <zebra.h>

#include <lib/hash.h>
#include <lib/jhash.h>
#include <lib/log.h>
#include <lib/sockunion.h>
#include <lib/stream.h>
#include <lib/thread.h>

#include "pimd.h"
#include "pim_cmd.h"
#include "pim_memory.h"
#include "pim_str.h"
#include "pim_time.h"

#include "pim_msdp.h"
#include "pim_msdp_packet.h"
#include "pim_msdp_socket.h"

struct pim_msdp pim_msdp, *msdp = &pim_msdp;

static void pim_msdp_peer_listen(struct pim_msdp_peer *mp);
static void pim_msdp_peer_cr_timer_setup(struct pim_msdp_peer *mp, bool start);
static void pim_msdp_peer_ka_timer_setup(struct pim_msdp_peer *mp, bool start);
static void pim_msdp_peer_hold_timer_setup(struct pim_msdp_peer *mp, bool start);
static void pim_msdp_peer_free(struct pim_msdp_peer *mp);

char *
pim_msdp_state_dump(enum pim_msdp_peer_state state, char *buf, int buf_size)
{
  switch (state) {
    case PIM_MSDP_DISABLED:
      snprintf(buf, buf_size, "%s", "disabled");
      break;
    case PIM_MSDP_INACTIVE:
      snprintf(buf, buf_size, "%s", "inactive");
      break;
    case PIM_MSDP_LISTEN:
      snprintf(buf, buf_size, "%s", "listen");
      break;
    case PIM_MSDP_CONNECTING:
      snprintf(buf, buf_size, "%s", "connecting");
      break;
    case PIM_MSDP_ESTABLISHED:
      snprintf(buf, buf_size, "%s", "established");
      break;
    default:
      snprintf(buf, buf_size, "unk-%d", state);
  }
  return buf;
}

char *
pim_msdp_peer_key_dump(struct pim_msdp_peer *mp, char *buf, int buf_size, bool long_format)
{
  char peer_str[INET_ADDRSTRLEN];
  char local_str[INET_ADDRSTRLEN];

  pim_inet4_dump("<peer?>", mp->peer, peer_str, sizeof(peer_str));
  if (long_format) {
    pim_inet4_dump("<local?>", mp->local, local_str, sizeof(local_str));
    snprintf(buf, buf_size, "MSDP peer %s local %s mg %s",
        peer_str, local_str, mp->mesh_group_name);
  } else {
    snprintf(buf, buf_size, "MSDP peer %s", peer_str);
  }

  return buf;
}

static void
pim_msdp_peer_state_chg_log(struct pim_msdp_peer *mp)
{
  char state_str[PIM_MSDP_STATE_STRLEN];
  char key_str[PIM_MSDP_PEER_KEY_STRLEN];

  pim_msdp_state_dump(mp->state, state_str, sizeof(state_str));
  pim_msdp_peer_key_dump(mp, key_str, sizeof(key_str), false);
  zlog_debug("%s state chg to %s", key_str, state_str);
}

/* MSDP Connection State Machine actions (defined in RFC-3618:Sec-11.2) */
/* 11.2.A2: active peer - start connect retry timer; when the timer fires
 * a tcp connection will be made */
static void
pim_msdp_peer_connect(struct pim_msdp_peer *mp)
{
  mp->state = PIM_MSDP_CONNECTING;
  if (PIM_DEBUG_MSDP_EVENTS) {
    pim_msdp_peer_state_chg_log(mp);
  }

  pim_msdp_peer_cr_timer_setup(mp, true /* start */);
}

/* 11.2.A3: passive peer - just listen for connections */
static void
pim_msdp_peer_listen(struct pim_msdp_peer *mp)
{
  mp->state = PIM_MSDP_LISTEN;
  if (PIM_DEBUG_MSDP_EVENTS) {
    pim_msdp_peer_state_chg_log(mp);
  }

  /* this is interntionally asymmetric i.e. we set up listen-socket when the
  * first listening peer is configured; but don't bother tearing it down when
  * all the peers go down */
  pim_msdp_sock_listen();
}

/* 11.2.A4 and 11.2.A5: transition active or passive peer to
 * established state */
void
pim_msdp_peer_established(struct pim_msdp_peer *mp)
{
  mp->state = PIM_MSDP_ESTABLISHED;
  mp->uptime = pim_time_monotonic_sec();

  if (PIM_DEBUG_MSDP_EVENTS) {
    pim_msdp_peer_state_chg_log(mp);
  }

  /* stop retry timer on active peers */
  pim_msdp_peer_cr_timer_setup(mp, false /* start */);

  /* send KA; start KA and hold timers */
  pim_msdp_pkt_ka_tx(mp);
  pim_msdp_peer_ka_timer_setup(mp, true /* start */);
  pim_msdp_peer_hold_timer_setup(mp, true /* start */);

  PIM_MSDP_PEER_WRITE_ON(mp);
  PIM_MSDP_PEER_READ_ON(mp);
}

/* 11.2.A6, 11.2.A7 and 11.2.A8: shutdown the peer tcp connection */
void
pim_msdp_peer_stop_tcp_conn(struct pim_msdp_peer *mp, bool chg_state)
{
  if (chg_state) {
    mp->state = PIM_MSDP_INACTIVE;
    if (PIM_DEBUG_MSDP_EVENTS) {
      pim_msdp_peer_state_chg_log(mp);
    }
  }

  /* stop read and write threads */
  PIM_MSDP_PEER_READ_OFF(mp);
  PIM_MSDP_PEER_WRITE_OFF(mp);

  /* reset buffers */
  if (mp->ibuf)
    stream_reset(mp->ibuf);
  if (mp->obuf)
    stream_fifo_clean(mp->obuf);

  /* stop all peer timers */
  pim_msdp_peer_ka_timer_setup(mp, false /* start */);
  pim_msdp_peer_cr_timer_setup(mp, false /* start */);
  pim_msdp_peer_hold_timer_setup(mp, false /* start */);

  /* close connection */
  if (mp->fd >= 0) {
    close(mp->fd);
    mp->fd = -1;
  }
}

/* RFC-3618:Sec-5.6 - stop the peer tcp connection and startover */
void
pim_msdp_peer_reset_tcp_conn(struct pim_msdp_peer *mp, const char *rc_str)
{
  if (PIM_DEBUG_EVENTS) {
    char key_str[PIM_MSDP_PEER_KEY_STRLEN];

    pim_msdp_peer_key_dump(mp, key_str, sizeof(key_str), false);
    zlog_debug("%s tcp reset %s", key_str, rc_str);
  }

  /* close the connection and transition to listening or connecting */
  pim_msdp_peer_stop_tcp_conn(mp, true /* chg_state */);
  if (PIM_MSDP_PEER_IS_LISTENER(mp)) {
    pim_msdp_peer_listen(mp);
  } else {
    pim_msdp_peer_connect(mp);
  }
}

static void
pim_msdp_peer_timer_expiry_log(struct pim_msdp_peer *mp, const char *timer_str)
{
  char key_str[PIM_MSDP_PEER_KEY_STRLEN];

  pim_msdp_peer_key_dump(mp, key_str, sizeof(key_str), false);
  zlog_debug("%s timer %s expired", key_str, timer_str);
}

/* RFC-3618:Sec-5.4 - peer hold timer */
static int
pim_msdp_peer_hold_timer_cb(struct thread *t)
{
  struct pim_msdp_peer *mp;

  zassert(t);
  mp = THREAD_ARG(t);
  zassert(mp);

  if (PIM_DEBUG_MSDP_EVENTS) {
    pim_msdp_peer_timer_expiry_log(mp, "hold");
  }

  if (mp->state != PIM_MSDP_ESTABLISHED) {
    return 0;
  }

  if (PIM_DEBUG_MSDP_EVENTS) {
    pim_msdp_peer_state_chg_log(mp);
  }
  pim_msdp_peer_reset_tcp_conn(mp, "ht-expired");
  return 0;
}
static void
pim_msdp_peer_hold_timer_setup(struct pim_msdp_peer *mp, bool start)
{
  THREAD_OFF(mp->hold_timer);
  if (start) {
    THREAD_TIMER_ON(msdp->master, mp->hold_timer,
        pim_msdp_peer_hold_timer_cb, mp, PIM_MSDP_PEER_HOLD_TIME);
  }
}


/* RFC-3618:Sec-5.5 - peer keepalive timer */
static int
pim_msdp_peer_ka_timer_cb(struct thread *t)
{
  struct pim_msdp_peer *mp;

  zassert(t);
  mp = THREAD_ARG(t);
  zassert(mp);

  if (PIM_DEBUG_MSDP_EVENTS) {
    pim_msdp_peer_timer_expiry_log(mp, "ka");
  }

  if (mp->state != PIM_MSDP_ESTABLISHED) {
    return 0;
  }

  pim_msdp_pkt_ka_tx(mp);
  pim_msdp_peer_ka_timer_setup(mp, true /* start */);
  return 0;
}
/* XXX: reset this anytime a message is sent to the peer */
static void
pim_msdp_peer_ka_timer_setup(struct pim_msdp_peer *mp, bool start)
{
  THREAD_OFF(mp->ka_timer);
  if (start) {
    THREAD_TIMER_ON(msdp->master, mp->ka_timer,
        pim_msdp_peer_ka_timer_cb, mp, PIM_MSDP_PEER_KA_TIME);
  }
}

static void
pim_msdp_peer_active_connect(struct pim_msdp_peer *mp)
{
  int rc;
  rc = pim_msdp_sock_connect(mp);

  if (PIM_DEBUG_MSDP_INTERNAL) {
    char key_str[PIM_MSDP_PEER_KEY_STRLEN];

    pim_msdp_peer_key_dump(mp, key_str, sizeof(key_str), false);
    zlog_debug("%s pim_msdp_peer_active_connect: %d", key_str, rc);
  }

  switch (rc) {
    case connect_error:
      /* connect failed restart the connect-retry timer */
      pim_msdp_peer_cr_timer_setup(mp, true /* start */);
      break;

    case connect_success:
      /* connect was sucessful move to established */
      pim_msdp_peer_established(mp);
      break;

    case connect_in_progress:
      /* for NB content we need to wait till sock is readable or
       * writeable */
      PIM_MSDP_PEER_WRITE_ON(mp);
      PIM_MSDP_PEER_READ_ON(mp);
      /* also restart connect-retry timer to reset the socket if connect is
       * not sucessful */
      pim_msdp_peer_cr_timer_setup(mp, true /* start */);
      break;
  }
}

/* RFC-3618:Sec-5.6 - connection retry on active peer */
static int
pim_msdp_peer_cr_timer_cb(struct thread *t)
{
  struct pim_msdp_peer *mp;

  zassert(t);
  mp = THREAD_ARG(t);
  zassert(mp);

  if (PIM_DEBUG_MSDP_EVENTS) {
    pim_msdp_peer_timer_expiry_log(mp, "connect-retry");
  }

  if (mp->state != PIM_MSDP_CONNECTING || PIM_MSDP_PEER_IS_LISTENER(mp)) {
    return 0;
  }

  pim_msdp_peer_active_connect(mp);
  return 0;
}
static void
pim_msdp_peer_cr_timer_setup(struct pim_msdp_peer *mp, bool start)
{
  THREAD_OFF(mp->cr_timer);
  if (start) {
    THREAD_TIMER_ON(msdp->master, mp->cr_timer,
        pim_msdp_peer_cr_timer_cb, mp, PIM_MSDP_PEER_CONNECT_RETRY_TIME);
  }
}

/* if a valid packet is rxed from the peer we can restart hold timer */
void
pim_msdp_peer_pkt_rxed(struct pim_msdp_peer *mp)
{
  if (mp->state == PIM_MSDP_ESTABLISHED) {
    pim_msdp_peer_hold_timer_setup(mp, true /* start */);
  }
}

static void pim_msdp_addr2su(union sockunion *su, struct in_addr addr)
{
  sockunion_init(su);
  su->sin.sin_addr = addr;
  su->sin.sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
  su->sin.sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
}

/* 11.2.A1: create a new peer and transition state to listen or connecting */
static enum pim_msdp_err
pim_msdp_peer_new(struct in_addr peer_addr, struct in_addr local_addr,
                     const char *mesh_group_name)
{
  struct pim_msdp_peer *mp;

  mp = XCALLOC(MTYPE_PIM_MSDP_PEER, sizeof(*mp));
  if (!mp) {
    zlog_err("%s: PIM XCALLOC(%zu) failure",
             __PRETTY_FUNCTION__, sizeof(*mp));
    return PIM_MSDP_ERR_OOM;
  }

  mp->peer = peer_addr;
  pim_msdp_addr2su(&mp->su_peer, mp->peer);
  mp->local = local_addr;
  pim_msdp_addr2su(&mp->su_local, mp->local);
  mp->mesh_group_name = XSTRDUP(MTYPE_PIM_MSDP_PEER_MG_NAME, mesh_group_name);
  mp->state = PIM_MSDP_INACTIVE;
  mp->fd = -1;
  /* higher IP address is listener */
  if (ntohl(mp->local.s_addr) > ntohl(mp->peer.s_addr)) {
    mp->flags |= PIM_MSDP_PEERF_LISTENER;
  }

  if (PIM_DEBUG_MSDP_EVENTS) {
    char key_str[PIM_MSDP_PEER_KEY_STRLEN];

    pim_msdp_peer_key_dump(mp, key_str, sizeof(key_str), true);
    zlog_debug("%s created", key_str);
  }

  /* setup packet buffers */
  mp->ibuf = stream_new(PIM_MSDP_MAX_PACKET_SIZE);
  mp->obuf = stream_fifo_new();

  /* insert into misc tables for easy access */
  mp = hash_get(msdp->peer_hash, mp, hash_alloc_intern);
  if (!mp) {
    zlog_err("%s: PIM hash get failure", __PRETTY_FUNCTION__);
    pim_msdp_peer_free(mp);
    return PIM_MSDP_ERR_OOM;
  }
  listnode_add_sort(msdp->peer_list, mp);

  if (PIM_DEBUG_MSDP_EVENTS) {
    pim_msdp_peer_state_chg_log(mp);
  }
  /* fireup the connect state machine */
  if (PIM_MSDP_PEER_IS_LISTENER(mp)) {
    pim_msdp_peer_listen(mp);
  } else {
    pim_msdp_peer_connect(mp);
  }
  return PIM_MSDP_ERR_NONE;
}

struct pim_msdp_peer *
pim_msdp_peer_find(struct in_addr peer_addr)
{
  struct pim_msdp_peer lookup;

  lookup.peer = peer_addr;
  return hash_lookup(msdp->peer_hash, &lookup);
}

/* add peer configuration if it doesn't already exist */
enum pim_msdp_err
pim_msdp_peer_add(struct in_addr peer_addr, struct in_addr local_addr,
                  const char *mesh_group_name)
{
  struct pim_msdp_peer *mp;

  mp = pim_msdp_peer_find(peer_addr);
  if (mp) {
    return PIM_MSDP_ERR_PEER_EXISTS;
  }

  return pim_msdp_peer_new(peer_addr, local_addr, mesh_group_name);
}

/* release all mem associated with a peer */
static void
pim_msdp_peer_free(struct pim_msdp_peer *mp)
{
  if (mp->ibuf) {
    stream_free(mp->ibuf);
  }

  if (mp->obuf) {
    stream_fifo_free(mp->obuf);
  }

  if (mp->mesh_group_name) {
    XFREE(MTYPE_PIM_MSDP_PEER_MG_NAME, mp->mesh_group_name);
  }
  XFREE(MTYPE_PIM_MSDP_PEER, mp);
}

/* delete the peer config */
enum pim_msdp_err
pim_msdp_peer_del(struct in_addr peer_addr)
{
  struct pim_msdp_peer *mp;

  mp = pim_msdp_peer_find(peer_addr);
  if (!mp) {
    return PIM_MSDP_ERR_NO_PEER;
  }

  /* stop the tcp connection and shutdown all timers */
  pim_msdp_peer_stop_tcp_conn(mp, true /* chg_state */);

  /* remove the session from various tables */
  listnode_delete(msdp->peer_list, mp);
  hash_release(msdp->peer_hash, mp);

  if (PIM_DEBUG_MSDP_EVENTS) {
    char key_str[PIM_MSDP_PEER_KEY_STRLEN];

    pim_msdp_peer_key_dump(mp, key_str, sizeof(key_str), true);
    zlog_debug("%s deleted", key_str);
  }

  /* free up any associated memory */
  pim_msdp_peer_free(mp);

  return PIM_MSDP_ERR_NONE;
}

/* peer hash and peer list helpers */
static unsigned int
pim_msdp_peer_hash_key_make(void *p)
{
  struct pim_msdp_peer *mp = p;
  return (jhash_1word(mp->peer.s_addr, 0));
}

static int
pim_msdp_peer_hash_eq(const void *p1, const void *p2)
{
  const struct pim_msdp_peer *mp1 = p1;
  const struct pim_msdp_peer *mp2 = p2;

  return (mp1->peer.s_addr == mp2->peer.s_addr);
}

static int
pim_msdp_peer_comp(const void *p1, const void *p2)
{
  const struct pim_msdp_peer *mp1 = p1;
  const struct pim_msdp_peer *mp2 = p2;

  if (ntohl(mp1->peer.s_addr) < ntohl(mp2->peer.s_addr))
    return -1;

  if (ntohl(mp1->peer.s_addr) > ntohl(mp2->peer.s_addr))
    return 1;

  return 0;
}

/* MSDP init */
void
pim_msdp_init(struct thread_master *master)
{
  /* XXX: temporarily enable noisy logs; will be disabled once dev is
   * complete */
  PIM_DO_DEBUG_MSDP_INTERNAL;

  msdp->peer_hash = hash_create(pim_msdp_peer_hash_key_make,
                                 pim_msdp_peer_hash_eq);
  msdp->peer_list = list_new();
  msdp->peer_list->del = (void (*)(void *))pim_msdp_peer_free;
  msdp->peer_list->cmp = (int (*)(void *, void *))pim_msdp_peer_comp;
  msdp->master = master;
}

/* counterpart to MSDP init; XXX: unused currently */
void
pim_msdp_exit(void)
{
  /* XXX: stop listener and delete all peer sessions */

  if (msdp->peer_hash) {
    hash_free(msdp->peer_hash);
    msdp->peer_hash = NULL;
  }

  if (msdp->peer_list) {
    list_free(msdp->peer_list);
    msdp->peer_list = NULL;
  }
}
