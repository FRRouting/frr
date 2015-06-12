/* Kernel routing table updates using netlink over GNU/Linux system.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>
#include <sys/un.h>		/* for sockaddr_un */
#include <net/if.h>
#include "zebra/zserv.h"
#include "zebra/interface.h"
#include "zebra/debug.h"
#include "zebra/zebra_ptm.h"
#include "if.h"
#include "command.h"
#include "stream.h"
#include "ptm_lib.h"
#include "zebra/zebra_ptm_redistribute.h"

#define ZEBRA_PTM_RECONNECT_TIME_INITIAL 1 /* initial reconnect is 1s */
#define ZEBRA_PTM_RECONNECT_TIME_MAX     300

#define PTM_MSG_LEN     4
#define PTM_HEADER_LEN  37

const char ZEBRA_PTM_GET_STATUS_CMD[] = "get-status";
const char ZEBRA_PTM_BFD_START_CMD[] = "start-bfd-sess";
const char ZEBRA_PTM_BFD_STOP_CMD[] = "stop-bfd-sess";

const char ZEBRA_PTM_PORT_STR[] = "port";
const char ZEBRA_PTM_CBL_STR[] = "cbl status";
const char ZEBRA_PTM_PASS_STR[] = "pass";
const char ZEBRA_PTM_FAIL_STR[] = "fail";
const char ZEBRA_PTM_BFDSTATUS_STR[] = "state";
const char ZEBRA_PTM_BFDSTATUS_UP_STR[] = "Up";
const char ZEBRA_PTM_BFDSTATUS_DOWN_STR[] = "Down";
const char ZEBRA_PTM_BFDDEST_STR[] = "peer";
const char ZEBRA_PTM_BFDSRC_STR[] = "local";
const char ZEBRA_PTM_INVALID_PORT_NAME[] = "N/A";
const char ZEBRA_PTM_INVALID_SRC_IP[] = "N/A";

const char ZEBRA_PTM_BFD_DST_IP_FIELD[] = "dstIPaddr";
const char ZEBRA_PTM_BFD_SRC_IP_FIELD[] = "srcIPaddr";
const char ZEBRA_PTM_BFD_MIN_RX_FIELD[] = "requiredMinRx";
const char ZEBRA_PTM_BFD_MIN_TX_FIELD[] = "upMinTx";
const char ZEBRA_PTM_BFD_DETECT_MULT_FIELD[] = "detectMult";
const char ZEBRA_PTM_BFD_MULTI_HOP_FIELD[] = "multiHop";
const char ZEBRA_PTM_BFD_CLIENT_FIELD[] = "client";
const char ZEBRA_PTM_BFD_SEQID_FIELD[] = "seqid";
const char ZEBRA_PTM_BFD_IFNAME_FIELD[] = "ifName";
const char ZEBRA_PTM_BFD_MAX_HOP_CNT_FIELD[] = "maxHopCnt";

extern struct zebra_t zebrad;
int ptm_enable;

int zebra_ptm_sock = -1;
struct thread *zebra_ptm_thread = NULL;

static int zebra_ptm_reconnect_time = ZEBRA_PTM_RECONNECT_TIME_INITIAL;
int zebra_ptm_pid = 0;
static ptm_lib_handle_t *ptm_hdl;

static int zebra_ptm_socket_init(void);
int zebra_ptm_sock_read(struct thread *);
int zebra_ptm_sock_write(struct thread *);
static void zebra_ptm_install_commands (void);
static int zebra_ptm_handle_cbl_msg(void *arg, void *in_ctxt);
static int zebra_ptm_handle_bfd_msg(void *arg, void *in_ctxt);
void zebra_bfd_peer_replay_req (void);

const char ZEBRA_PTM_SOCK_NAME[] = "\0/var/run/ptmd.socket";

void
zebra_ptm_init (void)
{
  char buf[64];

  zebra_ptm_pid = getpid();
  zebra_ptm_install_commands();

  sprintf(buf, "%s", "quagga");
  ptm_hdl = ptm_lib_register(buf, NULL, zebra_ptm_handle_bfd_msg,
                                    zebra_ptm_handle_cbl_msg);
}

int
zebra_ptm_connect (struct thread *t)
{
  int init = 0;
  char *data;
  void *out_ctxt;
  int len = ZEBRA_PTM_SEND_MAX_SOCKBUF;

  if (zebra_ptm_sock == -1) {
    zebra_ptm_socket_init();
    init = 1;
  }

  if (zebra_ptm_sock != -1) {
    if (init) {
      zebra_bfd_peer_replay_req();
    }

    if (ptm_enable) {
      data = calloc(1, len);
      if (!data) {
          zlog_debug("%s: Allocation of send data failed", __func__);
          return -1;
        }
      ptm_lib_init_msg(ptm_hdl, 0, PTMLIB_MSG_TYPE_CMD, NULL, &out_ctxt);
      ptm_lib_append_msg(ptm_hdl, out_ctxt, "cmd", ZEBRA_PTM_GET_STATUS_CMD);
      ptm_lib_complete_msg(ptm_hdl, out_ctxt, data, &len);

      zebra_ptm_thread = thread_add_write (zebrad.master, zebra_ptm_sock_write,
                                         data, zebra_ptm_sock);
    }
    zebra_ptm_reconnect_time = ZEBRA_PTM_RECONNECT_TIME_INITIAL;
  } else {
    zebra_ptm_reconnect_time *= 2;
    if (zebra_ptm_reconnect_time > ZEBRA_PTM_RECONNECT_TIME_MAX)
      zebra_ptm_reconnect_time = ZEBRA_PTM_RECONNECT_TIME_MAX;

    zebra_ptm_thread = thread_add_timer (zebrad.master, zebra_ptm_connect, NULL,
					 zebra_ptm_reconnect_time);
  }

  return(errno);
}

DEFUN (zebra_ptm_enable,
       zebra_ptm_enable_cmd,
       "ptm-enable",
       "Enable neighbor check with specified topology\n")
{
  struct listnode *i;
  struct interface *ifp;

  ptm_enable = 1;

  for (ALL_LIST_ELEMENTS_RO (iflist, i, ifp))
    if (!ifp->ptm_enable)
      {
	ifp->ptm_enable = 1;
	ifp->ptm_status = 1;	/* to bring down ports that may fail check */
      }

  zebra_ptm_connect(NULL);

  return CMD_SUCCESS;
}

DEFUN (no_zebra_ptm_enable,
       no_zebra_ptm_enable_cmd,
       "no ptm-enable",
       NO_STR
       "Enable neighbor check with specified topology\n")
{
  struct listnode *i;
  struct interface *ifp;
  int send_linkup;

  ptm_enable = 0;
  for (ALL_LIST_ELEMENTS_RO (iflist, i, ifp))
    {
      if (ifp->ptm_enable)
	{
	  if (!if_is_operative(ifp))
	    send_linkup = 1;

	  ifp->ptm_enable = 0;
	  if (if_is_operative (ifp) && send_linkup) {
	    zlog_debug ("%s: Bringing up interface %s", __func__,
			ifp->name);
	    if_up (ifp);
	  }
	}
    }

  return CMD_SUCCESS;
}

void
zebra_ptm_write (struct vty *vty)
{
  if (ptm_enable)
    vty_out (vty, "ptm-enable%s", VTY_NEWLINE);

  return;
}

static int
zebra_ptm_socket_init (void)
{
  int ret;
  int sock;
  struct sockaddr_un addr;

  zebra_ptm_sock = -1;

  sock = socket (PF_UNIX, (SOCK_STREAM | SOCK_NONBLOCK), 0);
  if (sock < 0)
    return -1;

  /* Make server socket. */
  memset (&addr, 0, sizeof (struct sockaddr_un));
  addr.sun_family = AF_UNIX;
  memcpy (&addr.sun_path, ZEBRA_PTM_SOCK_NAME,
	  sizeof(ZEBRA_PTM_SOCK_NAME));

  ret = connect(sock, (struct sockaddr *) &addr,
                sizeof (addr.sun_family)+sizeof (ZEBRA_PTM_SOCK_NAME)-1);
  if (ret < 0)
    {
      zlog_warn("%s: Unable to connect to socket %s [%s]",
	              __func__, ZEBRA_PTM_SOCK_NAME, safe_strerror(errno));
      close (sock);
      return -1;
    }
  zlog_debug ("%s: connection to ptm socket %s succeeded",
	      __func__, ZEBRA_PTM_SOCK_NAME);
  zebra_ptm_sock = sock;
  return sock;
}

static void
zebra_ptm_install_commands (void)
{
  install_element (CONFIG_NODE, &zebra_ptm_enable_cmd);
  install_element (CONFIG_NODE, &no_zebra_ptm_enable_cmd);
}

/* BFD session goes down, send message to the protocols. */
void
if_bfd_session_down (struct interface *ifp, struct prefix *dp, struct prefix *sp)
{
  if (IS_ZEBRA_DEBUG_EVENT)
    {
      char buf[2][INET6_ADDRSTRLEN];

      if (ifp)
        {
          zlog_debug ("MESSAGE: ZEBRA_INTERFACE_BFD_DEST_DOWN %s/%d on %s",
                  inet_ntop (dp->family, &dp->u.prefix, buf, INET6_ADDRSTRLEN),
                  dp->prefixlen, ifp->name);
        }
      else
        {
          zlog_debug ("MESSAGE: ZEBRA_INTERFACE_BFD_DEST_DOWN %s/%d "
                      "with src %s/%d",
                  inet_ntop (dp->family, &dp->u.prefix, buf[0], INET6_ADDRSTRLEN),
                  dp->prefixlen,
                  inet_ntop (sp->family, &sp->u.prefix, buf[1], INET6_ADDRSTRLEN),
                  sp->prefixlen);
        }
    }

  zebra_interface_bfd_update (ifp, dp, sp);
}

static int
zebra_ptm_handle_bfd_msg(void *arg, void *in_ctxt)
{
  struct interface *ifp = NULL;
  char port_str[128];
  char bfdst_str[32];
  char dest_str[64];
  char src_str[64];
  struct prefix dest_prefix;
  struct prefix src_prefix;

  ptm_lib_find_key_in_msg(in_ctxt, ZEBRA_PTM_PORT_STR, port_str);

  if (port_str[0] == '\0') {
    zlog_debug("%s: Key %s not found in PTM msg", __func__,
               ZEBRA_PTM_PORT_STR);
    return -1;
  }

  if (strcmp(ZEBRA_PTM_INVALID_PORT_NAME, port_str)) {
    ifp = if_lookup_by_name(port_str);

    if (!ifp) {
      zlog_err("%s: %s not found in interface list", __func__, port_str);
          return -1;
    }
  }

  ptm_lib_find_key_in_msg(in_ctxt, ZEBRA_PTM_BFDSTATUS_STR, bfdst_str);

  if (bfdst_str[0] == '\0') {
    zlog_debug("%s: Key %s not found in PTM msg", __func__,
               ZEBRA_PTM_BFDSTATUS_STR);
    return -1;
  }

  ptm_lib_find_key_in_msg(in_ctxt, ZEBRA_PTM_BFDDEST_STR, dest_str);

  if (dest_str[0] == '\0') {
    zlog_debug("%s: Key %s not found in PTM msg", __func__,
               ZEBRA_PTM_BFDDEST_STR);
    return -1;
  }

  ptm_lib_find_key_in_msg(in_ctxt, ZEBRA_PTM_BFDSRC_STR, src_str);

  if (src_str[0] == '\0') {
    zlog_debug("%s: Key %s not found in PTM msg", __func__,
               ZEBRA_PTM_BFDSRC_STR);
    return -1;
  }

  zlog_debug("%s: Recv Port [%s] bfd status [%s] peer [%s] local [%s]",
              __func__, port_str, bfdst_str, dest_str, src_str);

  /* we only care if bfd session goes down */
  if (!strcmp (bfdst_str, ZEBRA_PTM_BFDSTATUS_DOWN_STR)) {
    if (inet_pton(AF_INET, dest_str, &dest_prefix.u.prefix4) > 0) {
      dest_prefix.family = AF_INET;
      dest_prefix.prefixlen = IPV4_MAX_PREFIXLEN;
    }
#ifdef HAVE_IPV6
    else if (inet_pton(AF_INET6, dest_str, &dest_prefix.u.prefix6) > 0) {
      dest_prefix.family = AF_INET6;
      dest_prefix.prefixlen = IPV6_MAX_PREFIXLEN;
    }
#endif /* HAVE_IPV6 */
    else {
        zlog_err("%s: Peer addr %s not found", __func__,
           dest_str);
        return -1;
    }

    memset(&src_prefix, 0, sizeof(struct prefix));
    if (strcmp(ZEBRA_PTM_INVALID_SRC_IP, src_str)) {
      if (inet_pton(AF_INET, src_str, &src_prefix.u.prefix4) > 0) {
        src_prefix.family = AF_INET;
        src_prefix.prefixlen = IPV4_MAX_PREFIXLEN;
      }
#ifdef HAVE_IPV6
      else if (inet_pton(AF_INET6, src_str, &src_prefix.u.prefix6) > 0) {
        src_prefix.family = AF_INET6;
        src_prefix.prefixlen = IPV6_MAX_PREFIXLEN;
      }
#endif /* HAVE_IPV6 */
      else {
          zlog_err("%s: Local addr %s not found", __func__,
             src_str);
          return -1;
      }
    }

    if_bfd_session_down(ifp, &dest_prefix, &src_prefix);
  }

  return 0;
}

static int
zebra_ptm_handle_cbl_msg(void *arg, void *in_ctxt)
{
  struct interface *ifp;
  char cbl_str[32];
  char port_str[128];

  ptm_lib_find_key_in_msg(in_ctxt, ZEBRA_PTM_PORT_STR, port_str);

  if (port_str[0] == '\0') {
    zlog_debug("%s: Key %s not found in PTM msg", __func__,
               ZEBRA_PTM_PORT_STR);
    return 0;
  }

  ptm_lib_find_key_in_msg(in_ctxt, ZEBRA_PTM_CBL_STR, cbl_str);

  if (cbl_str[0] == '\0') {
    zlog_debug("%s: Key %s not found in PTM msg", __func__,
               ZEBRA_PTM_CBL_STR);
    return 0;
  }

  zlog_debug("%s: Recv Port [%s] cbl status [%s]", __func__,
             port_str, cbl_str);

  ifp = if_lookup_by_name(port_str);

  if (!ifp) {
    zlog_err("%s: %s not found in interface list", __func__, port_str);
	return -1;
  }

  if (!strcmp(cbl_str, ZEBRA_PTM_PASS_STR) && (!ifp->ptm_status)) {
	  ifp->ptm_status = 1;
	  if (ifp->ptm_enable && if_is_no_ptm_operative (ifp))
	    if_up (ifp);
  } else if (!strcmp (cbl_str, ZEBRA_PTM_FAIL_STR) && (ifp->ptm_status)) {
	  ifp->ptm_status = 0;
	  if (ifp->ptm_enable && if_is_no_ptm_operative (ifp))
	    if_down (ifp);
  }

  return 0;
}

int
zebra_ptm_sock_write (struct thread *thread)
{
  int sock;
  int nbytes;
  char *data;

  sock = THREAD_FD (thread);
  data = THREAD_ARG (thread);

  if (sock == -1)
    return -1;

  errno = 0;

  nbytes = send(sock, data, strlen(data), 0);

  if (nbytes <= 0) {
    if (errno && errno != EWOULDBLOCK && errno != EAGAIN) {
        zlog_warn ("%s routing socket error: %s", __func__,
                      safe_strerror (errno));
        zebra_ptm_sock = -1;
        zebra_ptm_thread = thread_add_timer (zebrad.master, zebra_ptm_connect,
                                              NULL, zebra_ptm_reconnect_time);
        return (-1);
    }
  }

  zlog_debug ("%s: Sent message (%d) %s", __func__, strlen(data), data);
  zebra_ptm_thread = thread_add_read (zebrad.master, zebra_ptm_sock_read,
                                      NULL, sock);
  free (data);
  return(0);
}

int
zebra_ptm_sock_read (struct thread *thread)
{
  int sock, done = 0;
  int rc;
  char  *rcvptr;

  errno = 0;
  sock = THREAD_FD (thread);

  if (sock == -1)
    return -1;

  /* PTM communicates in CSV format */
  while(!done) {
    rcvptr = calloc(1, ZEBRA_PTM_MAX_SOCKBUF);

    rc = ptm_lib_process_msg(ptm_hdl, sock, rcvptr, ZEBRA_PTM_MAX_SOCKBUF,
                                NULL);
    if (rc <= 0)
      break;
  }

  if (rc <= 0) {
    if (((rc == 0) && !errno) || (errno  && (errno != EWOULDBLOCK) && (errno != EAGAIN))) {
      zlog_warn ("%s routing socket error: %s(%d) bytes %d", __func__,
                    safe_strerror (errno), errno, rc);

      close (zebra_ptm_sock);
      zebra_ptm_sock = -1;
      zebra_ptm_thread = thread_add_timer (zebrad.master, zebra_ptm_connect,
                                         NULL, zebra_ptm_reconnect_time);
      return (-1);
    }
  }

  free(rcvptr);
  zebra_ptm_thread = thread_add_read (zebrad.master, zebra_ptm_sock_read,
                                      NULL, sock);

  return 0;
}

/* BFD peer/dst register/update */
int
zebra_ptm_bfd_dst_register (struct zserv *client, int sock, u_short length,
                              int command)
{
  char *data;
  struct stream *s;
  struct prefix src_p;
  struct prefix dst_p;
  u_char multi_hop;
  u_char multi_hop_cnt;
  u_char detect_mul;
  unsigned int min_rx_timer;
  unsigned int min_tx_timer;
  char if_name[INTERFACE_NAMSIZ];
  u_char len;
  void *out_ctxt;
  char buf[INET6_ADDRSTRLEN];
  char tmp_buf[64];
  int data_len = ZEBRA_PTM_SEND_MAX_SOCKBUF;

  if (command == ZEBRA_BFD_DEST_UPDATE)
    client->bfd_peer_upd8_cnt++;
  else
    client->bfd_peer_add_cnt++;

  zlog_debug("bfd_dst_register msg from client %s: length=%d",
     zebra_route_string(client->proto), length);

  if (zebra_ptm_sock == -1)
    {
      zebra_ptm_thread = thread_add_timer (zebrad.master, zebra_ptm_connect,
                                             NULL, zebra_ptm_reconnect_time);
      return -1;
    }

  data = calloc(1, data_len);
  if (!data)
    {
      zlog_debug("%s: Allocation of send data failed", __func__);
      return -1;
    }

  ptm_lib_init_msg(ptm_hdl, 0, PTMLIB_MSG_TYPE_CMD, NULL, &out_ctxt);
  sprintf(tmp_buf, "%s", ZEBRA_PTM_BFD_START_CMD);
  ptm_lib_append_msg(ptm_hdl, out_ctxt, "cmd", tmp_buf);
  sprintf(tmp_buf, "quagga");
  ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_CLIENT_FIELD,
                      tmp_buf);
  sprintf(tmp_buf, "%d", zebra_ptm_pid);
  ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_SEQID_FIELD,
                      tmp_buf);

  s = client->ibuf;

  dst_p.family = stream_getw(s);

  if (dst_p.family == AF_INET)
    dst_p.prefixlen = IPV4_MAX_BYTELEN;
  else
    dst_p.prefixlen = IPV6_MAX_BYTELEN;

  stream_get(&dst_p.u.prefix, s, dst_p.prefixlen);
  if (dst_p.family == AF_INET)
    {
      inet_ntop(AF_INET, &dst_p.u.prefix4, buf, sizeof(buf));
      ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_DST_IP_FIELD, buf);
    }
#ifdef HAVE_IPV6
  else
    {
      inet_ntop(AF_INET6, &dst_p.u.prefix6, buf, sizeof(buf));
      ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_DST_IP_FIELD, buf);
    }
#endif /* HAVE_IPV6 */

  min_rx_timer = stream_getl(s);
  sprintf(tmp_buf, "%d", min_rx_timer);
  ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_MIN_RX_FIELD,
                      tmp_buf);
  min_tx_timer = stream_getl(s);
  sprintf(tmp_buf, "%d", min_tx_timer);
  ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_MIN_TX_FIELD,
                      tmp_buf);
  detect_mul = stream_getc(s);
  sprintf(tmp_buf, "%d", detect_mul);
  ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_DETECT_MULT_FIELD,
                      tmp_buf);

  multi_hop = stream_getc(s);
  if (multi_hop)
    {
      sprintf(tmp_buf, "%d", 1);
      ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_MULTI_HOP_FIELD,
                          tmp_buf);
      src_p.family = stream_getw(s);

      if (src_p.family == AF_INET)
        src_p.prefixlen = IPV4_MAX_BYTELEN;
      else
        src_p.prefixlen = IPV6_MAX_BYTELEN;

      stream_get(&src_p.u.prefix, s, src_p.prefixlen);
      if (src_p.family == AF_INET)
        {
          inet_ntop(AF_INET, &src_p.u.prefix4, buf, sizeof(buf));
          ptm_lib_append_msg(ptm_hdl, out_ctxt,
                              ZEBRA_PTM_BFD_SRC_IP_FIELD, buf);
        }
#ifdef HAVE_IPV6
      else
        {
          inet_ntop(AF_INET6, &src_p.u.prefix6, buf, sizeof(buf));
          ptm_lib_append_msg(ptm_hdl, out_ctxt,
                              ZEBRA_PTM_BFD_SRC_IP_FIELD, buf);
        }
#endif /* HAVE_IPV6 */

      multi_hop_cnt = stream_getc(s);
      sprintf(tmp_buf, "%d", multi_hop_cnt);
      ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_MAX_HOP_CNT_FIELD,
                          tmp_buf);
    }
  else
    {
#ifdef HAVE_IPV6
      if (dst_p.family == AF_INET6)
        {
          src_p.family = stream_getw(s);

          if (src_p.family == AF_INET)
            src_p.prefixlen = IPV4_MAX_BYTELEN;
          else
            src_p.prefixlen = IPV6_MAX_BYTELEN;

          stream_get(&src_p.u.prefix, s, src_p.prefixlen);
          if (src_p.family == AF_INET)
            {
              inet_ntop(AF_INET, &src_p.u.prefix4, buf, sizeof(buf));
              ptm_lib_append_msg(ptm_hdl, out_ctxt,
                                  ZEBRA_PTM_BFD_SRC_IP_FIELD, buf);
            }
          else
            {
              inet_ntop(AF_INET6, &src_p.u.prefix6, buf, sizeof(buf));
              ptm_lib_append_msg(ptm_hdl, out_ctxt,
                                  ZEBRA_PTM_BFD_SRC_IP_FIELD, buf);
            }
        }
#endif /* HAVE_IPV6 */
      len = stream_getc(s);
      stream_get(if_name, s, len);
      if_name[len] = '\0';

      ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_IFNAME_FIELD,
                          if_name);
    }

  ptm_lib_complete_msg(ptm_hdl, out_ctxt, data, &data_len);
  zebra_ptm_thread = thread_add_write (zebrad.master, zebra_ptm_sock_write,
                                         data, zebra_ptm_sock);
  return 0;
}

/* BFD peer/dst deregister */
int
zebra_ptm_bfd_dst_deregister (struct zserv *client, int sock, u_short length)
{
  char *data;
  struct stream *s;
  struct prefix src_p;
  struct prefix dst_p;
  u_char multi_hop;
  char if_name[INTERFACE_NAMSIZ];
  u_char len;
  char buf[INET6_ADDRSTRLEN];
  char tmp_buf[64];
  int data_len = ZEBRA_PTM_SEND_MAX_SOCKBUF;
  void *out_ctxt;

  client->bfd_peer_del_cnt++;

  zlog_debug("bfd_dst_deregister msg from client %s: length=%d",
       zebra_route_string(client->proto), length);

  if (zebra_ptm_sock == -1)
    {
      zebra_ptm_thread = thread_add_timer (zebrad.master, zebra_ptm_connect,
                                             NULL, zebra_ptm_reconnect_time);
      return -1;
    }

  data = calloc(1, data_len);
  if (!data)
    {
      zlog_debug("%s: Allocation of send data failed", __func__);
      return -1;
    }

  ptm_lib_init_msg(ptm_hdl, 0, PTMLIB_MSG_TYPE_CMD, NULL, &out_ctxt);

  sprintf(tmp_buf, "%s", ZEBRA_PTM_BFD_STOP_CMD);
  ptm_lib_append_msg(ptm_hdl, out_ctxt, "cmd", tmp_buf);

  sprintf(tmp_buf, "%s", "quagga");
  ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_CLIENT_FIELD,
                      tmp_buf);

  sprintf(tmp_buf, "%d", zebra_ptm_pid);
  ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_SEQID_FIELD,
                      tmp_buf);

  s = client->ibuf;

  dst_p.family = stream_getw(s);

  if (dst_p.family == AF_INET)
    dst_p.prefixlen = IPV4_MAX_BYTELEN;
  else
    dst_p.prefixlen = IPV6_MAX_BYTELEN;

  stream_get(&dst_p.u.prefix, s, dst_p.prefixlen);
  if (dst_p.family == AF_INET)
    {
      inet_ntop(AF_INET, &dst_p.u.prefix4, buf, sizeof(buf));
      ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_DST_IP_FIELD, buf);
    }
#ifdef HAVE_IPV6
  else
    {
      inet_ntop(AF_INET6, &dst_p.u.prefix6, buf, sizeof(buf));
      ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_DST_IP_FIELD, buf);
    }
#endif /* HAVE_IPV6 */

  multi_hop = stream_getc(s);
  if (multi_hop)
    {
      sprintf(tmp_buf, "%d", 1);
      ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_MULTI_HOP_FIELD,
                          tmp_buf);

      src_p.family = stream_getw(s);

      if (src_p.family == AF_INET)
        src_p.prefixlen = IPV4_MAX_BYTELEN;
      else
        src_p.prefixlen = IPV6_MAX_BYTELEN;

      stream_get(&src_p.u.prefix, s, src_p.prefixlen);
      if (src_p.family == AF_INET)
        {
          inet_ntop(AF_INET, &src_p.u.prefix4, buf, sizeof(buf));
          ptm_lib_append_msg(ptm_hdl, out_ctxt,
                              ZEBRA_PTM_BFD_SRC_IP_FIELD, buf);
        }
#ifdef HAVE_IPV6
      else
        {
          inet_ntop(AF_INET6, &src_p.u.prefix6, buf, sizeof(buf));
          ptm_lib_append_msg(ptm_hdl, out_ctxt,
                              ZEBRA_PTM_BFD_SRC_IP_FIELD, buf);
        }
#endif /* HAVE_IPV6 */
    }
  else
    {
#ifdef HAVE_IPV6
      if (dst_p.family == AF_INET6)
        {
          src_p.family = stream_getw(s);

          if (src_p.family == AF_INET)
            src_p.prefixlen = IPV4_MAX_BYTELEN;
          else
            src_p.prefixlen = IPV6_MAX_BYTELEN;

          stream_get(&src_p.u.prefix, s, src_p.prefixlen);
          if (src_p.family == AF_INET)
            {
              inet_ntop(AF_INET, &src_p.u.prefix4, buf, sizeof(buf));
              ptm_lib_append_msg(ptm_hdl, out_ctxt,
                                  ZEBRA_PTM_BFD_SRC_IP_FIELD, buf);
            }
          else
            {
              inet_ntop(AF_INET6, &src_p.u.prefix6, buf, sizeof(buf));
              ptm_lib_append_msg(ptm_hdl, out_ctxt,
                                  ZEBRA_PTM_BFD_SRC_IP_FIELD, buf);
            }
        }
#endif /* HAVE_IPV6 */

      len = stream_getc(s);
      stream_get(if_name, s, len);
      if_name[len] = '\0';

      ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_IFNAME_FIELD,
                          if_name);
    }

  ptm_lib_complete_msg(ptm_hdl, out_ctxt, data, &data_len);
  zebra_ptm_thread = thread_add_write (zebrad.master, zebra_ptm_sock_write,
                                         data, zebra_ptm_sock);
  return 0;
}
