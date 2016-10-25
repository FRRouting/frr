/*
 * IP MSDP packet helper
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

#include <lib/log.h>
#include <lib/network.h>
#include <lib/stream.h>
#include <lib/thread.h>

#include "pimd.h"
#include "pim_str.h"

#include "pim_msdp.h"
#include "pim_msdp_packet.h"
#include "pim_msdp_socket.h"

static char *
pim_msdp_pkt_type_dump(enum pim_msdp_tlv type, char *buf, int buf_size)
{
  switch (type) {
    case PIM_MSDP_V4_SOURCE_ACTIVE:
      snprintf(buf, buf_size, "%s", "SA");
      break;
    case PIM_MSDP_V4_SOURCE_ACTIVE_REQUEST:
      snprintf(buf, buf_size, "%s", "SA_REQ");
      break;
    case PIM_MSDP_V4_SOURCE_ACTIVE_RESPONSE:
      snprintf(buf, buf_size, "%s", "SA_RESP");
      break;
    case PIM_MSDP_KEEPALIVE:
      snprintf(buf, buf_size, "%s", "KA");
      break;
    case PIM_MSDP_RESERVED:
      snprintf(buf, buf_size, "%s", "RSVD");
      break;
    case PIM_MSDP_TRACEROUTE_PROGRESS:
      snprintf(buf, buf_size, "%s", "TRACE_PROG");
      break;
    case PIM_MSDP_TRACEROUTE_REPLY:
      snprintf(buf, buf_size, "%s", "TRACE_REPLY");
      break;
    default:
      snprintf(buf, buf_size, "UNK-%d", type);
  }
  return buf;
}

static void
pim_msdp_pkt_dump(struct pim_msdp_peer *mp, int type, int len, bool rx)
{
  char key_str[PIM_MSDP_PEER_KEY_STRLEN];
  char type_str[PIM_MSDP_PKT_TYPE_STRLEN];

  pim_msdp_peer_key_dump(mp, key_str, sizeof(key_str), false);
  pim_msdp_pkt_type_dump(type, type_str, sizeof(type_str));

  zlog_debug("%s pkt %s type %s len %d",
      key_str, rx?"rx":"tx", type_str, len);
  /* XXX: dump actual data */
}

/* Check file descriptor whether connect is established. */
static void
pim_msdp_connect_check(struct pim_msdp_peer *mp)
{
  int status;
  socklen_t slen;
  int ret;

  if (mp->state != PIM_MSDP_CONNECTING) {
    /* if we are here it means we are not in a connecting or established state
     * for now treat this as a fatal error */
    /* XXX:revisit; reset TCP connection */
    pim_msdp_peer_reset_tcp_conn(mp, "invalid-state");
    return;
  }

  PIM_MSDP_PEER_READ_OFF(mp);
  PIM_MSDP_PEER_WRITE_OFF(mp);

  /* Check file descriptor. */
  slen = sizeof(status);
  ret = getsockopt(mp->fd, SOL_SOCKET, SO_ERROR, (void *)&status, &slen);

  /* If getsockopt is fail, this is fatal error. */
  if (ret < 0) {
    zlog_err("can't get sockopt for nonblocking connect");
    /* XXX:revisit; reset TCP connection */
    pim_msdp_peer_reset_tcp_conn(mp, "connect-failed");
    return;
  }

  /* When status is 0 then TCP connection is established. */
  if (PIM_DEBUG_MSDP_INTERNAL) {
    char key_str[PIM_MSDP_PEER_KEY_STRLEN];

    pim_msdp_peer_key_dump(mp, key_str, sizeof(key_str), false);
    zlog_debug("%s pim_connect_check %s", key_str, status?"fail":"success");
  }
  if (status == 0) {
    pim_msdp_peer_established(mp);
  } else {
    /* XXX:revisit; reset TCP connection */
    pim_msdp_peer_reset_tcp_conn(mp, "connect-failed");
  }
}

static void
pim_msdp_pkt_delete(struct pim_msdp_peer *mp)
{
  stream_free(stream_fifo_pop(mp->obuf));
}

static void
pim_msdp_write_proceed_actions(struct pim_msdp_peer *mp)
{
  if (stream_fifo_head(mp->obuf)) {
    PIM_MSDP_PEER_WRITE_ON(mp);
  }
}

int
pim_msdp_write(struct thread *thread)
{
  struct pim_msdp_peer *mp;
  struct stream *s;
  int num;
  enum pim_msdp_tlv type;

  mp = THREAD_ARG(thread);
  mp->t_write = NULL;

  if (PIM_DEBUG_MSDP_INTERNAL) {
    char key_str[PIM_MSDP_PEER_KEY_STRLEN];

    pim_msdp_peer_key_dump(mp, key_str, sizeof(key_str), false);
    zlog_debug("%s pim_msdp_write", key_str);
  }
  if (mp->fd < 0) {
    return -1;
  }

  /* check if TCP connection is established */
  if (mp->state != PIM_MSDP_ESTABLISHED) {
    pim_msdp_connect_check(mp);
    return 0;
  }

  s = stream_fifo_head(mp->obuf);
  if (!s) {
    pim_msdp_write_proceed_actions(mp);
    return 0;
  }

  sockopt_cork (mp->fd, 1);

  /* Nonblocking write until TCP output buffer is full  */
  do
  {
    int writenum;

    /* Number of bytes to be sent */
    writenum = stream_get_endp(s) - stream_get_getp(s);

    /* Call write() system call */
    num = write(mp->fd, STREAM_PNT(s), writenum);
    if (num < 0) {
      /* write failed either retry needed or error */
      if (ERRNO_IO_RETRY(errno))
        break;

      /* XXX:revisit; reset TCP connection */
      pim_msdp_peer_reset_tcp_conn(mp, "pkt-tx-failed");
      return 0;
    }

    if (num != writenum) {
      /* Partial write */
      stream_forward_getp(s, num);
      break;
    }

    /* Retrieve msdp packet type. */
    type = stream_getc(s);
    switch (type)
    {
      case PIM_MSDP_KEEPALIVE:
        mp->ka_tx_cnt++;
        break;
      case PIM_MSDP_V4_SOURCE_ACTIVE:
        mp->sa_tx_cnt++;
        break;
      default:;
    }
    if (PIM_DEBUG_MSDP_PACKETS) {
      pim_msdp_pkt_dump(mp, type, writenum, false /*rx*/);
    }

    /* packet sent delete it. */
    pim_msdp_pkt_delete(mp);

    /* XXX - may need to pause if we have done too much work in this
     * loop */
  } while ((s = stream_fifo_head(mp->obuf)) != NULL);
  pim_msdp_write_proceed_actions(mp);

  sockopt_cork (mp->fd, 0);

  return 0;
}

static void
pim_msdp_pkt_send(struct pim_msdp_peer *mp, struct stream *s)
{
  /* Add packet to the end of list. */
  stream_fifo_push(mp->obuf, s);

  PIM_MSDP_PEER_WRITE_ON(mp);
}

/* Make keepalive packet and send it to the peer
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       4      |              3                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
void
pim_msdp_pkt_ka_tx(struct pim_msdp_peer *mp)
{
  struct stream *s;

  s = stream_new(PIM_MSDP_KA_TLV_MAX_SIZE);
  stream_putc(s, PIM_MSDP_KEEPALIVE);
  stream_putw(s, PIM_MSDP_KA_TLV_MAX_SIZE);

  pim_msdp_pkt_send(mp, s);
}

static void
pim_msdp_pkt_rxed_with_fatal_error(struct pim_msdp_peer *mp)
{
  /* XXX:revisit; reset TCP connection */
  pim_msdp_peer_reset_tcp_conn(mp, "invalid-pkt-rx");
}

static void
pim_msdp_pkt_ka_rx(struct pim_msdp_peer *mp, int len)
{
  mp->ka_rx_cnt++;
  if (len !=  PIM_MSDP_KA_TLV_MAX_SIZE) {
    pim_msdp_pkt_rxed_with_fatal_error(mp);
    return;
  }
  pim_msdp_peer_pkt_rxed(mp);
}

static void
pim_msdp_pkt_sa_rx(struct pim_msdp_peer *mp, int len)
{
  mp->sa_rx_cnt++;
  /* XXX: proc SA ... */
  pim_msdp_peer_pkt_rxed(mp);
}

/* Theoretically you could have different tlv types in the same message.
 * For the time being I am assuming one; will revisit before 3.2 - XXX */
static void
pim_msdp_pkt_rx(struct pim_msdp_peer *mp, int nbytes)
{
  enum pim_msdp_tlv type;
  int len;

  type = stream_getc(mp->ibuf);
  len = stream_getw(mp->ibuf);
  if (len <  PIM_MSDP_HEADER_SIZE) {
    pim_msdp_pkt_rxed_with_fatal_error(mp);
    return;
  }

  if (len > PIM_MSDP_SA_TLV_MAX_SIZE) {
    /* if tlv size if greater than max just ignore the tlv */
    return;
  }

  if (len > nbytes) {
    /* we got a partial read or the packet is malformed */
    pim_msdp_pkt_rxed_with_fatal_error(mp);
    return;
  }

  if (PIM_DEBUG_MSDP_PACKETS) {
    pim_msdp_pkt_dump(mp, type, len, true /*rx*/);
  }

  switch(type) {
      case PIM_MSDP_KEEPALIVE:
        pim_msdp_pkt_ka_rx(mp, len);
        break;
      case PIM_MSDP_V4_SOURCE_ACTIVE:
        mp->sa_rx_cnt++;
        pim_msdp_pkt_sa_rx(mp, len);
        break;
      default:
        mp->unk_rx_cnt++;
  }
  /* XXX: process next tlv*/
}

/* pim msdp read utility function. */
static int
pim_msdp_read_packet(struct pim_msdp_peer *mp)
{
  int nbytes;
  /* Read packet from fd. */
  nbytes = stream_read_try(mp->ibuf, mp->fd, PIM_MSDP_MAX_PACKET_SIZE);
  if (nbytes < PIM_MSDP_HEADER_SIZE) {
    if (nbytes == -2) {
      /* transient error retry */
      return -1;
    }
    pim_msdp_pkt_rxed_with_fatal_error(mp);
    return -1;
  }
  return nbytes;
}

int
pim_msdp_read(struct thread *thread)
{
  struct pim_msdp_peer *mp;
  int rc;

  mp = THREAD_ARG(thread);
  mp->t_read = NULL;

  if (PIM_DEBUG_MSDP_INTERNAL) {
    char key_str[PIM_MSDP_PEER_KEY_STRLEN];

    pim_msdp_peer_key_dump(mp, key_str, sizeof(key_str), false);
    zlog_debug("%s pim_msdp_read", key_str);
  }

  if (mp->fd < 0) {
    return -1;
  }

  /* check if TCP connection is established */
  if (mp->state != PIM_MSDP_ESTABLISHED) {
    pim_msdp_connect_check(mp);
    return 0;
  }

  THREAD_READ_ON(msdp->master, mp->t_read, pim_msdp_read, mp, mp->fd);

  rc = pim_msdp_read_packet(mp);
  if (rc > 0) {
    pim_msdp_pkt_rx(mp, rc);
  }

  stream_reset(mp->ibuf);
  return 0;
}
