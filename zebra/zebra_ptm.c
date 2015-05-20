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

#define ZEBRA_PTM_RECONNECT_TIME_INITIAL 1 /* initial reconnect is 1s */
#define ZEBRA_PTM_RECONNECT_TIME_MAX     300

#define PTM_MSG_LEN     4
#define PTM_HEADER_LEN  37
char *ZEBRA_PTM_GET_STATUS_CMD = "get-status";
char *ZEBRA_PTM_PORT_STR = "port";
char *ZEBRA_PTM_CBL_STR = "cbl status";
char *ZEBRA_PTM_PASS_STR = "pass";
char *ZEBRA_PTM_FAIL_STR = "fail";
char *ZEBRA_PTM_BFDSTATUS_STR = "BFD status";
char *ZEBRA_PTM_BFDDEST_STR = "BFD peer";

extern struct zebra_t zebrad;
int ptm_enable;

int zebra_ptm_sock = -1;
struct thread *zebra_ptm_thread = NULL;

static int zebra_ptm_reconnect_time = ZEBRA_PTM_RECONNECT_TIME_INITIAL;

static void zebra_ptm_finish(void);
static int zebra_ptm_socket_init(void);
int zebra_ptm_sock_read(struct thread *);
int zebra_ptm_sock_write(struct thread *);
static void zebra_ptm_install_commands (void);

const char ZEBRA_PTM_SOCK_NAME[] = "\0/var/run/ptmd.socket";

void
zebra_ptm_init (void)
{
  zebra_ptm_install_commands();
}

int
zebra_ptm_connect (struct thread *t)
{
  zebra_ptm_socket_init();

  if (zebra_ptm_sock != -1) {
    zebra_ptm_thread = thread_add_write (zebrad.master, zebra_ptm_sock_write,
                                         NULL, zebra_ptm_sock);
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

static void
zebra_ptm_finish (void)
{
  if (zebra_ptm_sock != -1)
    {
      if (zebra_ptm_thread != NULL)
	{
	  thread_cancel(zebra_ptm_thread);
	  zebra_ptm_thread = NULL;
	}
      close (zebra_ptm_sock);
      zebra_ptm_sock = -1;
    }
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
	    zlog_debug ("%s: Bringing up interface %s\n", __func__,
			ifp->name);
	    if_up (ifp);
	  }
	}
    }
  zebra_ptm_finish();

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
      zlog_debug("%s: Unable to connect to socket %s [%s]\n",
	              __func__, ZEBRA_PTM_SOCK_NAME, safe_strerror(errno));
      close (sock);
      return -1;
    }
  zlog_debug ("%s: connection to ptm socket %s succeeded\n",
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

static char *
zebra_ptm_find_key(char *key_arg, char *arg, int arglen)
{
  char buf[ZEBRA_PTM_MAX_SOCKBUF];
  char *data, *hdr, *key, *val;
  char *currd, *currh;
  char *savd, *savh;

  snprintf(buf, sizeof(buf), "%s", arg);
  /* split up row header and data */
  hdr = buf;
  data = strstr(hdr, "\n");
  if (!data)
    return NULL;
  *data = '\0';
  data++;

  currh = strtok_r(hdr, ",\n\0", &savh);
  currd = strtok_r(data, ",\n\0", &savd);
  while(currh && currd) {
    key = currh;
    val = currd;
    if (!strcmp(key, key_arg)) {
        /* found the value */
        return val;
    }
    currh = strtok_r(NULL, ",\n\0", &savh);
    currd = strtok_r(NULL, ",\n\0", &savd);
  }

  return NULL;
}

static  void
zebra_ptm_handle_bfd_msg(char *buf, int buflen)
{
  struct interface *ifp;
  char *port_str, *bfdst_str, *dest_str;
  struct in_addr dest_addr;
  struct prefix dest_prefix;

  port_str = zebra_ptm_find_key(ZEBRA_PTM_PORT_STR, buf, buflen);

  if (!port_str) {
    zlog_debug("%s: Key %s not found in PTM msg\n", __func__,
               ZEBRA_PTM_PORT_STR);
    return;
  }

  ifp = if_lookup_by_name(port_str);

  if (!ifp) {
    zlog_err("%s: %s not found in interface list\n", __func__, port_str);
	return;
  }

  bfdst_str = zebra_ptm_find_key(ZEBRA_PTM_BFDSTATUS_STR, buf, buflen);

  if (!bfdst_str) {
    zlog_debug("%s: Key %s not found in PTM msg\n", __func__,
               ZEBRA_PTM_BFDSTATUS_STR);
    return;
  }

  dest_str = zebra_ptm_find_key(ZEBRA_PTM_BFDDEST_STR, buf, buflen);

  if (!dest_str) {
    zlog_debug("%s: Key %s not found in PTM msg\n", __func__,
               ZEBRA_PTM_BFDDEST_STR);
    return;
  }

  zlog_debug("%s: Recv Port [%s] bfd status [%s] peer [%s]\n", __func__,
             port_str, bfdst_str, dest_str);

  /* if ptm cbl checks fail then no more processing required */
  if (!ifp->ptm_status) {
    return;
  }

  /* we only care if bfd session goes down */
  if (!strcmp (bfdst_str, ZEBRA_PTM_FAIL_STR)) {
	  if (ifp->ptm_enable && if_is_no_ptm_operative (ifp)) {
        if (inet_pton(AF_INET, dest_str, &dest_addr) <= 0) {
            zlog_err("%s: Peer addr not found\n", __func__,
               dest_str);
            return;
        }
        dest_prefix.family = AF_INET;
        dest_prefix.u.prefix4 = dest_addr;
        dest_prefix.prefixlen = IPV4_MAX_PREFIXLEN;

        zlog_debug("%s: bfd session down [%s]\n", __func__, dest_str);
        if_bfd_session_down(ifp, &dest_prefix);
      }
  }
}

static void
zebra_ptm_handle_cbl_msg(char *buf, int buflen)
{
  struct interface *ifp;
  char *cbl_str, *port_str;

  port_str = zebra_ptm_find_key(ZEBRA_PTM_PORT_STR, buf, buflen);

  if (!port_str) {
    zlog_debug("%s: Key %s not found in PTM msg\n", __func__,
               ZEBRA_PTM_PORT_STR);
    return;
  }

  cbl_str = zebra_ptm_find_key(ZEBRA_PTM_CBL_STR, buf, buflen);

  if (!cbl_str) {
    zlog_debug("%s: Key %s not found in PTM msg\n", __func__,
               ZEBRA_PTM_CBL_STR);
    return;
  }

  zlog_debug("%s: Recv Port [%s] cbl status [%s]\n", __func__,
             port_str, cbl_str);

  ifp = if_lookup_by_name(port_str);

  if (!ifp) {
    zlog_err("%s: %s not found in interface list\n", __func__, port_str);
	return;
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
}

static void
zebra_ptm_process_csv (char *buf, int buflen)
{
  /* handle any cbl messages */
  zebra_ptm_handle_cbl_msg(buf, buflen);

  /* handle any bfd messages */
  zebra_ptm_handle_bfd_msg(buf, buflen);

}

int
zebra_ptm_sock_write (struct thread *thread)
{
  int sock;
  int nbytes;

  sock = THREAD_FD (thread);

  if (sock == -1)
    return -1;

  nbytes = send(sock, ZEBRA_PTM_GET_STATUS_CMD,
                strlen(ZEBRA_PTM_GET_STATUS_CMD), 0);

  if (nbytes <= 0)
    {
      if (nbytes < 0 && errno != EWOULDBLOCK && errno != EAGAIN)
	zlog_warn ("routing socket error: %s", safe_strerror (errno));

      zebra_ptm_sock = -1;
      zebra_ptm_thread = thread_add_timer (zebrad.master, zebra_ptm_connect, NULL,
					   zebra_ptm_reconnect_time);
      return (-1);
    }

  zlog_debug ("%s: Sent message %s\n", __func__, ZEBRA_PTM_GET_STATUS_CMD);
  zebra_ptm_thread = thread_add_read (zebrad.master, zebra_ptm_sock_read, NULL, sock);

  return(0);
}

int
zebra_ptm_sock_read (struct thread *thread)
{
  int sock, done = 0;
  char rcvbuf[ZEBRA_PTM_MAX_SOCKBUF];
  int nbytes, msglen;
  char  *rcvptr, *eofptr;
  char msgbuf[ZEBRA_PTM_MAX_SOCKBUF];

  sock = THREAD_FD (thread);

  if (sock == -1)
    return -1;

  /* PTM communicates in CSV format */
  while(!done) {
    rcvptr = rcvbuf;
    /* get PTM header */
    nbytes = recv(sock, rcvptr, PTM_HEADER_LEN, 0);
    if (nbytes <= 0)
        break;
    snprintf(msgbuf, PTM_MSG_LEN+1, "%s", rcvptr);
    msglen = strtol(msgbuf, NULL, 10);

    /* get the PTM message */
    rcvptr = calloc(1, msglen);
    nbytes = recv(sock, rcvptr, msglen, 0);
    if (nbytes <= 0)
        break;
    /* process one PTM message */
    zebra_ptm_process_csv(rcvptr, msglen);
    free(rcvptr);
  }

  if (nbytes <= 0) {
    if (errno  && errno != EWOULDBLOCK && errno != EAGAIN) {
	  zlog_warn ("routing socket error: %s", safe_strerror (errno));

      close (zebra_ptm_sock);
      zebra_ptm_sock = -1;
      zebra_ptm_thread = thread_add_timer (zebrad.master, zebra_ptm_connect,
                                           NULL, zebra_ptm_reconnect_time);
      return (-1);
    }
  }

  zebra_ptm_thread = thread_add_read (zebrad.master, zebra_ptm_sock_read, NULL, sock);

  return 0;
}
