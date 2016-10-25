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
#ifndef PIM_MSDP_H
#define PIM_MSDP_H

enum pim_msdp_peer_state {
  PIM_MSDP_DISABLED,
  PIM_MSDP_INACTIVE,
  PIM_MSDP_LISTEN,
  PIM_MSDP_CONNECTING,
  PIM_MSDP_ESTABLISHED
};

/* SA and KA TLVs are processed; rest ignored */
enum pim_msdp_tlv {
  PIM_MSDP_V4_SOURCE_ACTIVE = 1,
  PIM_MSDP_V4_SOURCE_ACTIVE_REQUEST,
  PIM_MSDP_V4_SOURCE_ACTIVE_RESPONSE,
  PIM_MSDP_KEEPALIVE,
  PIM_MSDP_RESERVED,
  PIM_MSDP_TRACEROUTE_PROGRESS,
  PIM_MSDP_TRACEROUTE_REPLY,
};

/* MSDP error codes */
enum pim_msdp_err {
  PIM_MSDP_ERR_NONE = 0,
  PIM_MSDP_ERR_OOM = -1,
  PIM_MSDP_ERR_PEER_EXISTS = -2,
  PIM_MSDP_ERR_MAX_MESH_GROUPS = -3,
  PIM_MSDP_ERR_NO_PEER = -4,
};

#define PIM_MSDP_STATE_STRLEN 16
#define PIM_MSDP_PEER_KEY_STRLEN 80
#define PIM_MSDP_UPTIME_STRLEN 80
#define PIM_MSDP_TCP_PORT 639
#define PIM_MSDP_SOCKET_SNDBUF_SIZE 65536

#define PIM_MSDP_PEER_IS_LISTENER(mp) (mp->flags & PIM_MSDP_PEERF_LISTENER)
enum pim_msdp_peer_flags {
  PIM_MSDP_PEERF_NONE = 0,
  PIM_MSDP_PEERF_LISTENER = (1 << 0)
};

struct pim_msdp_peer {
  /* configuration */
  struct in_addr local;
  struct in_addr peer;
  char *mesh_group_name;

  /* state */
  enum pim_msdp_peer_state state;
  enum pim_msdp_peer_flags flags;

  /* TCP socket info */
  union sockunion su_local;
  union sockunion su_peer;
  int fd;

  /* protocol timers */
#define PIM_MSDP_PEER_HOLD_TIME 75
  struct thread *hold_timer;   // 5.4
#define PIM_MSDP_PEER_KA_TIME 60
  struct thread *ka_timer;  // 5.5
#define PIM_MSDP_PEER_CONNECT_RETRY_TIME 30
  struct thread *cr_timer;  // 5.6

  /* packet thread and buffers */
  struct stream *ibuf;
  struct stream_fifo *obuf;
  struct thread *t_read;
  struct thread *t_write;

  /* stats */
  uint32_t ka_tx_cnt;
  uint32_t sa_tx_cnt;
  uint32_t ka_rx_cnt;
  uint32_t sa_rx_cnt;
  uint32_t unk_rx_cnt;

  /* timestamps */
  int64_t uptime;
};

enum pim_msdp_flags {
  PIM_MSDPF_NONE = 0,
  PIM_MSDPF_LISTENER = (1 << 0)
};

struct pim_msdp_listener {
  int fd;
  union sockunion su;
  struct thread *thread;
};

struct pim_msdp {
  enum pim_msdp_flags flags;
  struct hash *peer_hash;
  struct list *peer_list;
  struct pim_msdp_listener listener;
  struct thread_master *master;
  uint32_t rejected_accepts;
};

#define PIM_MSDP_PEER_READ_ON(mp) THREAD_READ_ON(msdp->master, mp->t_read, pim_msdp_read, mp, mp->fd);
#define PIM_MSDP_PEER_WRITE_ON(mp) THREAD_WRITE_ON(msdp->master, mp->t_write, pim_msdp_write, mp, mp->fd);

#define PIM_MSDP_PEER_READ_OFF(mp) THREAD_READ_OFF(mp->t_read)
#define PIM_MSDP_PEER_WRITE_OFF(mp) THREAD_WRITE_OFF(mp->t_write)

extern struct pim_msdp *msdp;
void pim_msdp_init(struct thread_master *master);
void pim_msdp_exit(void);
enum pim_msdp_err pim_msdp_peer_add(struct in_addr peer, struct in_addr local, const char *mesh_group_name);
enum pim_msdp_err pim_msdp_peer_del(struct in_addr peer_addr);
char *pim_msdp_state_dump(enum pim_msdp_peer_state state, char *buf, int buf_size);
struct pim_msdp_peer *pim_msdp_peer_find(struct in_addr peer_addr);
void pim_msdp_peer_established(struct pim_msdp_peer *mp);
void pim_msdp_peer_pkt_rxed(struct pim_msdp_peer *mp);
void pim_msdp_peer_stop_tcp_conn(struct pim_msdp_peer *mp, bool chg_state);
void pim_msdp_peer_reset_tcp_conn(struct pim_msdp_peer *mp, const char *rc_str);
int pim_msdp_write(struct thread *thread);
char *pim_msdp_peer_key_dump(struct pim_msdp_peer *mp, char *buf, int buf_size, bool long_format);

#endif
