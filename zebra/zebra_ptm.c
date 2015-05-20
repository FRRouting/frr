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
extern struct zebra_t zebrad;
int ptm_enable;

int zebra_ptm_sock = -1;
struct thread *zebra_ptm_thread = NULL;

static int zebra_ptm_reconnect_time = ZEBRA_PTM_RECONNECT_TIME_INITIAL;

static void zebra_ptm_finish(void);
static int zebra_ptm_socket_init(void);
static void zebra_ptm_process_msg(char *msg);
int zebra_ptm_sock_read(struct thread *);
static void zebra_ptm_install_commands (void);

const char ZEBRA_PTM_SOCK_NAME[] = "\0/var/run/ptmd.socket";

typedef enum ptm_msg_type {
    PTM_LLDP = 0,
    PTM_BFD,
    PTM_MAX
} ptm_msg_t;

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
    zebra_ptm_thread = thread_add_read (zebrad.master, zebra_ptm_sock_read, NULL, zebra_ptm_sock);
    zebra_ptm_reconnect_time = ZEBRA_PTM_RECONNECT_TIME_INITIAL;
  } else {
    zlog_err("%s: Socket connect to %s failed with err = %d\n", __func__,
	     ZEBRA_PTM_SOCK_NAME, errno);
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
  sock = socket (PF_UNIX, SOCK_STREAM, 0);
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
      zlog_err("%s: Unable to connect to socket %s, errno=%d\n",
	       __func__, ZEBRA_PTM_SOCK_NAME, errno);
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

static void
zebra_ptm_process_msg (char *buf)
{
  char port_name[IF_NAMESIZE+1];
  char status[8];
  char tgt_ip[12];
  char type[2];
  char byte_len[4];
  struct interface *ifp;
  int scan_count, bytes_read;
  char *pos;
  const char *delim = "\n";
  struct in_addr dest_addr;
  struct prefix dest_prefix;
  ptm_msg_t msg_type;

  /* the messages from the ptm ctl socket are in text only */
  /* with a fixed format:<count> <portname> <type> <pass|fail> */
  pos = strtok(buf, delim);
  while (pos != NULL) {
    if (strstr(pos, "EOF") != NULL)
      break;
    scan_count = sscanf(pos, "%3s %16s %1s %4s %n", byte_len, port_name, type, status, &bytes_read);

    if (scan_count == 4) {

      zlog_debug("%s: %s received new status %s, type %s with scan count = %d\n",
                 __func__, port_name, type, status, scan_count);

      ifp = if_lookup_by_name(port_name);
      if (ifp == NULL) {
	zlog_err("%s: %s not found in interface list\n", __func__, port_name);
	return;
      }

      if (strchr(type, "B") == 0) {
        msg_type = PTM_BFD;
        pos = pos + bytes_read;
        scan_count = sscanf(pos, "%11s", tgt_ip);
      } else {
        msg_type = PTM_LLDP;
      }

      if (strcmp(status, "pass") == 0) {
	if (!ifp->ptm_status) {
	  ifp->ptm_status = 1;
	  if (ifp->ptm_enable && if_is_no_ptm_operative (ifp))
	    if_up (ifp);
	}
      } else if (strcmp (status, "fail") == 0) {
        if (ifp->ptm_status) {
          ifp->ptm_status = 0;
          if (ifp->ptm_enable && if_is_no_ptm_operative (ifp)) {
            if (msg_type == PTM_BFD) {

              if (inet_pton(AF_INET, tgt_ip, &dest_addr) <= 0) {
                  zlog_err ("%s: Not a valid destination address: %s",
                            __func__, tgt_ip);
                  return;
              }
              dest_prefix.family = AF_INET;
              dest_prefix.u.prefix4 = dest_addr;
              dest_prefix.prefixlen = IPV4_MAX_PREFIXLEN;

              /* Send BFD message with ifp and dest_prefix to protocols */
            } else {
              if_down (ifp);
            }
          }
	}
      }
    }
    pos = strtok(NULL, delim);
  }
}

int
zebra_ptm_sock_read (struct thread *thread)
{
  int sock;
  char rcvbuf[ZEBRA_PTM_MAX_SOCKBUF];
  int nbytes;

  sock = THREAD_FD (thread);

  if (sock == -1)
    return -1;

  nbytes = recv(sock, rcvbuf, sizeof(rcvbuf), 0);

  if (nbytes <= 0)
    {
      if (nbytes < 0 && errno != EWOULDBLOCK && errno != EAGAIN)
	zlog_warn ("routing socket error: %s", safe_strerror (errno));

      zebra_ptm_sock = -1;
      zebra_ptm_thread = thread_add_timer (zebrad.master, zebra_ptm_connect, NULL,
					   zebra_ptm_reconnect_time);
      return (-1);
    }

  zlog_debug ("%s: Received message \n%s\n", __func__, rcvbuf);
  zebra_ptm_thread = thread_add_read (zebrad.master, zebra_ptm_sock_read, NULL, sock);

  zebra_ptm_process_msg (rcvbuf);

  return(0);
}
