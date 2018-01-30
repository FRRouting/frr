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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include <sys/un.h> /* for sockaddr_un */
#include <net/if.h>
#include "vty.h"
#include "zebra/zserv.h"
#include "zebra/interface.h"
#include "zebra/debug.h"
#include "zebra/zebra_ptm.h"
#include "if.h"
#include "command.h"
#include "stream.h"
#include "ptm_lib.h"
#include "network.h"
#include "buffer.h"
#include "zebra/zebra_ptm_redistribute.h"
#include "bfd.h"
#include "vrf.h"
#include "rib.h"
#include "zebra_vrf.h"
#include "version.h"

#define ZEBRA_PTM_RECONNECT_TIME_INITIAL 1 /* initial reconnect is 1s */
#define ZEBRA_PTM_RECONNECT_TIME_MAX     300

#define PTM_MSG_LEN     4
#define PTM_HEADER_LEN  37

const char ZEBRA_PTM_GET_STATUS_CMD[] = "get-status";
const char ZEBRA_PTM_BFD_START_CMD[] = "start-bfd-sess";
const char ZEBRA_PTM_BFD_STOP_CMD[] = "stop-bfd-sess";
const char ZEBRA_PTM_BFD_CLIENT_REG_CMD[] = "reg-bfd-client";
const char ZEBRA_PTM_BFD_CLIENT_DEREG_CMD[] = "dereg-bfd-client";

const char ZEBRA_PTM_CMD_STR[] = "cmd";
const char ZEBRA_PTM_CMD_STATUS_STR[] = "cmd_status";
const char ZEBRA_PTM_PORT_STR[] = "port";
const char ZEBRA_PTM_CBL_STR[] = "cbl status";
const char ZEBRA_PTM_PASS_STR[] = "pass";
const char ZEBRA_PTM_FAIL_STR[] = "fail";
const char ZEBRA_PTM_BFDSTATUS_STR[] = "state";
const char ZEBRA_PTM_BFDSTATUS_UP_STR[] = "Up";
const char ZEBRA_PTM_BFDSTATUS_DOWN_STR[] = "Down";
const char ZEBRA_PTM_BFDDEST_STR[] = "peer";
const char ZEBRA_PTM_BFDSRC_STR[] = "local";
const char ZEBRA_PTM_BFDVRF_STR[] = "vrf";
const char ZEBRA_PTM_INVALID_PORT_NAME[] = "N/A";
const char ZEBRA_PTM_INVALID_SRC_IP[] = "N/A";
const char ZEBRA_PTM_INVALID_VRF[] = "N/A";

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
const char ZEBRA_PTM_BFD_SEND_EVENT[] = "sendEvent";
const char ZEBRA_PTM_BFD_VRF_NAME_FIELD[] = "vrfName";

static ptm_lib_handle_t *ptm_hdl;

struct zebra_ptm_cb ptm_cb;

static int zebra_ptm_socket_init(void);
int zebra_ptm_sock_read(struct thread *);
static void zebra_ptm_install_commands(void);
static int zebra_ptm_handle_msg_cb(void *arg, void *in_ctxt);
void zebra_bfd_peer_replay_req(void);
void zebra_ptm_send_status_req(void);
void zebra_ptm_reset_status(int ptm_disable);

const char ZEBRA_PTM_SOCK_NAME[] = "\0/var/run/ptmd.socket";

void zebra_ptm_init(void)
{
	char buf[64];

	memset(&ptm_cb, 0, sizeof(struct zebra_ptm_cb));

	ptm_cb.out_data = calloc(1, ZEBRA_PTM_SEND_MAX_SOCKBUF);
	if (!ptm_cb.out_data) {
		zlog_warn("%s: Allocation of send data failed", __func__);
		return;
	}

	ptm_cb.in_data = calloc(1, ZEBRA_PTM_MAX_SOCKBUF);
	if (!ptm_cb.in_data) {
		zlog_warn("%s: Allocation of recv data failed", __func__);
		free(ptm_cb.out_data);
		return;
	}

	ptm_cb.pid = getpid();
	zebra_ptm_install_commands();

	sprintf(buf, "%s", FRR_PTM_NAME);
	ptm_hdl = ptm_lib_register(buf, NULL, zebra_ptm_handle_msg_cb,
				   zebra_ptm_handle_msg_cb);
	ptm_cb.wb = buffer_new(0);

	ptm_cb.reconnect_time = ZEBRA_PTM_RECONNECT_TIME_INITIAL;

	ptm_cb.ptm_sock = -1;
}

void zebra_ptm_finish(void)
{
	int proto;

	for (proto = 0; proto < ZEBRA_ROUTE_MAX; proto++)
		if (CHECK_FLAG(ptm_cb.client_flags[proto],
			       ZEBRA_PTM_BFD_CLIENT_FLAG_REG))
			zebra_ptm_bfd_client_deregister(proto);

	buffer_flush_all(ptm_cb.wb, ptm_cb.ptm_sock);

	free(ptm_hdl);

	if (ptm_cb.out_data)
		free(ptm_cb.out_data);

	if (ptm_cb.in_data)
		free(ptm_cb.in_data);

	/* Release threads. */
	if (ptm_cb.t_read)
		thread_cancel(ptm_cb.t_read);
	if (ptm_cb.t_write)
		thread_cancel(ptm_cb.t_write);
	if (ptm_cb.t_timer)
		thread_cancel(ptm_cb.t_timer);

	if (ptm_cb.wb)
		buffer_free(ptm_cb.wb);

	if (ptm_cb.ptm_sock >= 0)
		close(ptm_cb.ptm_sock);
}

static int zebra_ptm_flush_messages(struct thread *thread)
{
	ptm_cb.t_write = NULL;

	if (ptm_cb.ptm_sock == -1)
		return -1;

	errno = 0;

	switch (buffer_flush_available(ptm_cb.wb, ptm_cb.ptm_sock)) {
	case BUFFER_ERROR:
		zlog_warn("%s ptm socket error: %s", __func__,
			  safe_strerror(errno));
		close(ptm_cb.ptm_sock);
		ptm_cb.ptm_sock = -1;
		zebra_ptm_reset_status(0);
		ptm_cb.t_timer = NULL;
		thread_add_timer(zebrad.master, zebra_ptm_connect, NULL,
				 ptm_cb.reconnect_time, &ptm_cb.t_timer);
		return (-1);
	case BUFFER_PENDING:
		ptm_cb.t_write = NULL;
		thread_add_write(zebrad.master, zebra_ptm_flush_messages, NULL,
				 ptm_cb.ptm_sock, &ptm_cb.t_write);
		break;
	case BUFFER_EMPTY:
		break;
	}

	return (0);
}

static int zebra_ptm_send_message(char *data, int size)
{
	errno = 0;
	switch (buffer_write(ptm_cb.wb, ptm_cb.ptm_sock, data, size)) {
	case BUFFER_ERROR:
		zlog_warn("%s ptm socket error: %s", __func__,
			  safe_strerror(errno));
		close(ptm_cb.ptm_sock);
		ptm_cb.ptm_sock = -1;
		zebra_ptm_reset_status(0);
		ptm_cb.t_timer = NULL;
		thread_add_timer(zebrad.master, zebra_ptm_connect, NULL,
				 ptm_cb.reconnect_time, &ptm_cb.t_timer);
		return -1;
	case BUFFER_EMPTY:
		THREAD_OFF(ptm_cb.t_write);
		break;
	case BUFFER_PENDING:
		thread_add_write(zebrad.master, zebra_ptm_flush_messages, NULL,
				 ptm_cb.ptm_sock, &ptm_cb.t_write);
		break;
	}

	return 0;
}

int zebra_ptm_connect(struct thread *t)
{
	int init = 0;

	if (ptm_cb.ptm_sock == -1) {
		zebra_ptm_socket_init();
		init = 1;
	}

	if (ptm_cb.ptm_sock != -1) {
		if (init) {
			ptm_cb.t_read = NULL;
			thread_add_read(zebrad.master, zebra_ptm_sock_read,
					NULL, ptm_cb.ptm_sock, &ptm_cb.t_read);
			zebra_bfd_peer_replay_req();
		}
		zebra_ptm_send_status_req();
		ptm_cb.reconnect_time = ZEBRA_PTM_RECONNECT_TIME_INITIAL;
	} else if (ptm_cb.reconnect_time < ZEBRA_PTM_RECONNECT_TIME_MAX) {
		ptm_cb.reconnect_time *= 2;
		if (ptm_cb.reconnect_time > ZEBRA_PTM_RECONNECT_TIME_MAX)
			ptm_cb.reconnect_time = ZEBRA_PTM_RECONNECT_TIME_MAX;

		ptm_cb.t_timer = NULL;
		thread_add_timer(zebrad.master, zebra_ptm_connect, NULL,
				 ptm_cb.reconnect_time, &ptm_cb.t_timer);
	} else if (ptm_cb.reconnect_time >= ZEBRA_PTM_RECONNECT_TIME_MAX) {
		ptm_cb.reconnect_time = ZEBRA_PTM_RECONNECT_TIME_INITIAL;
	}

	return (errno);
}

DEFUN (zebra_ptm_enable,
       zebra_ptm_enable_cmd,
       "ptm-enable",
       "Enable neighbor check with specified topology\n")
{
	struct vrf *vrf;
	struct interface *ifp;
	struct zebra_if *if_data;

	ptm_cb.ptm_enable = ZEBRA_IF_PTM_ENABLE_ON;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name)
		FOR_ALL_INTERFACES (vrf, ifp)
			if (!ifp->ptm_enable) {
				if_data = (struct zebra_if *)ifp->info;
				if (if_data
				    && (if_data->ptm_enable
					== ZEBRA_IF_PTM_ENABLE_UNSPEC)) {
					ifp->ptm_enable =
						ZEBRA_IF_PTM_ENABLE_ON;
				}
				/* Assign a default unknown status */
				ifp->ptm_status = ZEBRA_PTM_STATUS_UNKNOWN;
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
	ptm_cb.ptm_enable = ZEBRA_IF_PTM_ENABLE_OFF;
	zebra_ptm_reset_status(1);
	return CMD_SUCCESS;
}

DEFUN (zebra_ptm_enable_if,
       zebra_ptm_enable_if_cmd,
       "ptm-enable",
       "Enable neighbor check with specified topology\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct zebra_if *if_data;
	int old_ptm_enable;
	int send_linkdown = 0;

	if (ifp->ifindex == IFINDEX_INTERNAL) {
		return CMD_SUCCESS;
	}

	old_ptm_enable = ifp->ptm_enable;
	ifp->ptm_enable = ptm_cb.ptm_enable;

	if (if_is_no_ptm_operative(ifp))
		send_linkdown = 1;

	if (!old_ptm_enable && ptm_cb.ptm_enable) {
		if (!if_is_operative(ifp) && send_linkdown) {
			if (IS_ZEBRA_DEBUG_EVENT)
				zlog_debug("%s: Bringing down interface %s\n",
					   __func__, ifp->name);
			if_down(ifp);
		}
	}

	if_data = ifp->info;
	if_data->ptm_enable = ZEBRA_IF_PTM_ENABLE_UNSPEC;

	return CMD_SUCCESS;
}

DEFUN (no_zebra_ptm_enable_if,
       no_zebra_ptm_enable_if_cmd,
       "no ptm-enable",
       NO_STR
       "Enable neighbor check with specified topology\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int send_linkup = 0;
	struct zebra_if *if_data;

	if ((ifp->ifindex != IFINDEX_INTERNAL) && (ifp->ptm_enable)) {
		if (!if_is_operative(ifp))
			send_linkup = 1;

		ifp->ptm_enable = ZEBRA_IF_PTM_ENABLE_OFF;
		if (if_is_no_ptm_operative(ifp) && send_linkup) {
			if (IS_ZEBRA_DEBUG_EVENT)
				zlog_debug("%s: Bringing up interface %s\n",
					   __func__, ifp->name);
			if_up(ifp);
		}
	}

	if_data = ifp->info;
	if_data->ptm_enable = ZEBRA_IF_PTM_ENABLE_OFF;

	return CMD_SUCCESS;
}


void zebra_ptm_write(struct vty *vty)
{
	if (ptm_cb.ptm_enable)
		vty_out(vty, "ptm-enable\n");

	return;
}

static int zebra_ptm_socket_init(void)
{
	int ret;
	int sock;
	struct sockaddr_un addr;

	ptm_cb.ptm_sock = -1;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;
	if (set_nonblocking(sock) < 0) {
		if (IS_ZEBRA_DEBUG_EVENT)
			zlog_debug("%s: Unable to set socket non blocking[%s]",
				   __PRETTY_FUNCTION__, safe_strerror(errno));
		close(sock);
		return -1;
	}

	/* Make server socket. */
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	memcpy(&addr.sun_path, ZEBRA_PTM_SOCK_NAME,
	       sizeof(ZEBRA_PTM_SOCK_NAME));

	ret = connect(sock, (struct sockaddr *)&addr,
		      sizeof(addr.sun_family) + sizeof(ZEBRA_PTM_SOCK_NAME)
			      - 1);
	if (ret < 0) {
		if (IS_ZEBRA_DEBUG_EVENT)
			zlog_debug("%s: Unable to connect to socket %s [%s]",
				   __func__, ZEBRA_PTM_SOCK_NAME,
				   safe_strerror(errno));
		close(sock);
		return -1;
	}
	ptm_cb.ptm_sock = sock;
	return sock;
}

static void zebra_ptm_install_commands(void)
{
	install_element(CONFIG_NODE, &zebra_ptm_enable_cmd);
	install_element(CONFIG_NODE, &no_zebra_ptm_enable_cmd);
	install_element(INTERFACE_NODE, &zebra_ptm_enable_if_cmd);
	install_element(INTERFACE_NODE, &no_zebra_ptm_enable_if_cmd);
}

/* BFD session goes down, send message to the protocols. */
static void if_bfd_session_update(struct interface *ifp, struct prefix *dp,
				  struct prefix *sp, int status,
				  vrf_id_t vrf_id)
{
	if (IS_ZEBRA_DEBUG_EVENT) {
		char buf[2][INET6_ADDRSTRLEN];

		if (ifp) {
			zlog_debug(
				"MESSAGE: ZEBRA_INTERFACE_BFD_DEST_UPDATE %s/%d on %s"
				" %s event",
				inet_ntop(dp->family, &dp->u.prefix, buf[0],
					  INET6_ADDRSTRLEN),
				dp->prefixlen, ifp->name,
				bfd_get_status_str(status));
		} else {
			zlog_debug(
				"MESSAGE: ZEBRA_INTERFACE_BFD_DEST_UPDATE %s/%d "
				"with src %s/%d and vrf %u %s event",
				inet_ntop(dp->family, &dp->u.prefix, buf[0],
					  INET6_ADDRSTRLEN),
				dp->prefixlen,
				inet_ntop(sp->family, &sp->u.prefix, buf[1],
					  INET6_ADDRSTRLEN),
				sp->prefixlen, vrf_id,
				bfd_get_status_str(status));
		}
	}

	zebra_interface_bfd_update(ifp, dp, sp, status, vrf_id);
}

static int zebra_ptm_handle_bfd_msg(void *arg, void *in_ctxt,
				    struct interface *ifp)
{
	char bfdst_str[32];
	char dest_str[64];
	char src_str[64];
	char vrf_str[64];
	struct prefix dest_prefix;
	struct prefix src_prefix;
	vrf_id_t vrf_id;

	ptm_lib_find_key_in_msg(in_ctxt, ZEBRA_PTM_BFDSTATUS_STR, bfdst_str);

	if (bfdst_str[0] == '\0') {
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

	ptm_lib_find_key_in_msg(in_ctxt, ZEBRA_PTM_BFDVRF_STR, vrf_str);

	if (vrf_str[0] == '\0') {
		zlog_debug("%s: Key %s not found in PTM msg", __func__,
			   ZEBRA_PTM_BFDVRF_STR);
		return -1;
	}

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug(
			"%s: Recv Port [%s] bfd status [%s] vrf [%s]"
			" peer [%s] local [%s]",
			__func__, ifp ? ifp->name : "N/A", bfdst_str, vrf_str,
			dest_str, src_str);

	if (str2prefix(dest_str, &dest_prefix) == 0) {
		zlog_err("%s: Peer addr %s not found", __func__, dest_str);
		return -1;
	}

	memset(&src_prefix, 0, sizeof(struct prefix));
	if (strcmp(ZEBRA_PTM_INVALID_SRC_IP, src_str)) {
		if (str2prefix(src_str, &src_prefix) == 0) {
			zlog_err("%s: Local addr %s not found", __func__,
				 src_str);
			return -1;
		}
	}

	if (!strcmp(ZEBRA_PTM_INVALID_VRF, vrf_str) && ifp) {
		vrf_id = ifp->vrf_id;
	} else {
		vrf_id = vrf_name_to_id(vrf_str);
	}

	if (!strcmp(bfdst_str, ZEBRA_PTM_BFDSTATUS_DOWN_STR)) {
		if_bfd_session_update(ifp, &dest_prefix, &src_prefix,
				      BFD_STATUS_DOWN, vrf_id);
	} else {
		if_bfd_session_update(ifp, &dest_prefix, &src_prefix,
				      BFD_STATUS_UP, vrf_id);
	}

	return 0;
}

static int zebra_ptm_handle_cbl_msg(void *arg, void *in_ctxt,
				    struct interface *ifp, char *cbl_str)
{
	int send_linkup = 0;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("%s: Recv Port [%s] cbl status [%s]", __func__,
			   ifp->name, cbl_str);

	if (!strcmp(cbl_str, ZEBRA_PTM_PASS_STR)
	    && (ifp->ptm_status != ZEBRA_PTM_STATUS_UP)) {

		if (ifp->ptm_status == ZEBRA_PTM_STATUS_DOWN)
			send_linkup = 1;
		ifp->ptm_status = ZEBRA_PTM_STATUS_UP;
		if (ifp->ptm_enable && if_is_no_ptm_operative(ifp)
		    && send_linkup)
			if_up(ifp);
	} else if (!strcmp(cbl_str, ZEBRA_PTM_FAIL_STR)
		   && (ifp->ptm_status != ZEBRA_PTM_STATUS_DOWN)) {
		ifp->ptm_status = ZEBRA_PTM_STATUS_DOWN;
		if (ifp->ptm_enable && if_is_no_ptm_operative(ifp))
			if_down(ifp);
	}

	return 0;
}

/*
 * zebra_ptm_handle_msg_cb - The purpose of this callback function is to handle
 *  all the command responses and notifications received from PTM.
 *
 * Command responses: Upon establishing connection with PTM, Zebra requests
 *  status of all interfaces using 'get-status' command if global ptm-enable
 *  knob is enabled. As a response to the get-status command PTM sends status
 *  of all the interfaces as command responses. All other type of command
 *  responses with cmd_status key word  are dropped. The sole purpose of
 *  registering this function as callback for the command responses is to
 *  handle the responses to get-status command.
 *
 * Notifications: Cable status and BFD session status changes are sent as
 *  notifications by PTM. So, this function is also the callback function for
 *  processing all the notifications from the PTM.
 *
 */
static int zebra_ptm_handle_msg_cb(void *arg, void *in_ctxt)
{
	struct interface *ifp = NULL;
	char port_str[128];
	char cbl_str[32];
	char cmd_status_str[32];

	ptm_lib_find_key_in_msg(in_ctxt, ZEBRA_PTM_CMD_STATUS_STR,
				cmd_status_str);

	/* Drop command response messages */
	if (cmd_status_str[0] != '\0') {
		return 0;
	}

	ptm_lib_find_key_in_msg(in_ctxt, ZEBRA_PTM_PORT_STR, port_str);

	if (port_str[0] == '\0') {
		zlog_debug("%s: Key %s not found in PTM msg", __func__,
			   ZEBRA_PTM_PORT_STR);
		return -1;
	}

	if (strcmp(ZEBRA_PTM_INVALID_PORT_NAME, port_str)) {
		ifp = if_lookup_by_name_all_vrf(port_str);

		if (!ifp) {
			zlog_err("%s: %s not found in interface list", __func__,
				 port_str);
			return -1;
		}
	}

	ptm_lib_find_key_in_msg(in_ctxt, ZEBRA_PTM_CBL_STR, cbl_str);

	if (cbl_str[0] == '\0') {
		return zebra_ptm_handle_bfd_msg(arg, in_ctxt, ifp);
	} else {
		if (ifp) {
			return zebra_ptm_handle_cbl_msg(arg, in_ctxt, ifp,
							cbl_str);
		} else {
			return -1;
		}
	}
}

int zebra_ptm_sock_read(struct thread *thread)
{
	int sock, done = 0;
	int rc;

	errno = 0;
	sock = THREAD_FD(thread);

	if (sock == -1)
		return -1;

	/* PTM communicates in CSV format */
	while (!done) {
		rc = ptm_lib_process_msg(ptm_hdl, sock, ptm_cb.in_data,
					 ZEBRA_PTM_MAX_SOCKBUF, NULL);
		if (rc <= 0)
			break;
	}

	if (rc <= 0) {
		if (((rc == 0) && !errno)
		    || (errno && (errno != EWOULDBLOCK) && (errno != EAGAIN))) {
			zlog_warn("%s routing socket error: %s(%d) bytes %d",
				  __func__, safe_strerror(errno), errno, rc);

			close(ptm_cb.ptm_sock);
			ptm_cb.ptm_sock = -1;
			zebra_ptm_reset_status(0);
			ptm_cb.t_timer = NULL;
			thread_add_timer(zebrad.master, zebra_ptm_connect, NULL,
					 ptm_cb.reconnect_time,
					 &ptm_cb.t_timer);
			return (-1);
		}
	}

	ptm_cb.t_read = NULL;
	thread_add_read(zebrad.master, zebra_ptm_sock_read, NULL,
			ptm_cb.ptm_sock, &ptm_cb.t_read);

	return 0;
}

/* BFD peer/dst register/update */
int zebra_ptm_bfd_dst_register(struct zserv *client, u_short length,
			       int command, struct zebra_vrf *zvrf)
{
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
	unsigned int pid;

	if (command == ZEBRA_BFD_DEST_UPDATE)
		client->bfd_peer_upd8_cnt++;
	else
		client->bfd_peer_add_cnt++;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("bfd_dst_register msg from client %s: length=%d",
			   zebra_route_string(client->proto), length);

	if (ptm_cb.ptm_sock == -1) {
		ptm_cb.t_timer = NULL;
		thread_add_timer(zebrad.master, zebra_ptm_connect, NULL,
				 ptm_cb.reconnect_time, &ptm_cb.t_timer);
		return -1;
	}

	ptm_lib_init_msg(ptm_hdl, 0, PTMLIB_MSG_TYPE_CMD, NULL, &out_ctxt);
	sprintf(tmp_buf, "%s", ZEBRA_PTM_BFD_START_CMD);
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_CMD_STR, tmp_buf);
	sprintf(tmp_buf, "%s", zebra_route_string(client->proto));
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_CLIENT_FIELD,
			   tmp_buf);

	s = client->ibuf;

	STREAM_GETL(s, pid);
	sprintf(tmp_buf, "%d", pid);
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_SEQID_FIELD,
			   tmp_buf);

	STREAM_GETW(s, dst_p.family);

	if (dst_p.family == AF_INET)
		dst_p.prefixlen = IPV4_MAX_BYTELEN;
	else
		dst_p.prefixlen = IPV6_MAX_BYTELEN;

	STREAM_GET(&dst_p.u.prefix, s, dst_p.prefixlen);
	if (dst_p.family == AF_INET) {
		inet_ntop(AF_INET, &dst_p.u.prefix4, buf, sizeof(buf));
		ptm_lib_append_msg(ptm_hdl, out_ctxt,
				   ZEBRA_PTM_BFD_DST_IP_FIELD, buf);
	} else {
		inet_ntop(AF_INET6, &dst_p.u.prefix6, buf, sizeof(buf));
		ptm_lib_append_msg(ptm_hdl, out_ctxt,
				   ZEBRA_PTM_BFD_DST_IP_FIELD, buf);
	}

	STREAM_GETL(s, min_rx_timer);
	sprintf(tmp_buf, "%d", min_rx_timer);
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_MIN_RX_FIELD,
			   tmp_buf);
	STREAM_GETL(s, min_tx_timer);
	sprintf(tmp_buf, "%d", min_tx_timer);
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_MIN_TX_FIELD,
			   tmp_buf);
	STREAM_GETC(s, detect_mul);
	sprintf(tmp_buf, "%d", detect_mul);
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_DETECT_MULT_FIELD,
			   tmp_buf);

	STREAM_GETC(s, multi_hop);
	if (multi_hop) {
		sprintf(tmp_buf, "%d", 1);
		ptm_lib_append_msg(ptm_hdl, out_ctxt,
				   ZEBRA_PTM_BFD_MULTI_HOP_FIELD, tmp_buf);
		STREAM_GETW(s, src_p.family);

		if (src_p.family == AF_INET)
			src_p.prefixlen = IPV4_MAX_BYTELEN;
		else
			src_p.prefixlen = IPV6_MAX_BYTELEN;

		STREAM_GET(&src_p.u.prefix, s, src_p.prefixlen);
		if (src_p.family == AF_INET) {
			inet_ntop(AF_INET, &src_p.u.prefix4, buf, sizeof(buf));
			ptm_lib_append_msg(ptm_hdl, out_ctxt,
					   ZEBRA_PTM_BFD_SRC_IP_FIELD, buf);
		} else {
			inet_ntop(AF_INET6, &src_p.u.prefix6, buf, sizeof(buf));
			ptm_lib_append_msg(ptm_hdl, out_ctxt,
					   ZEBRA_PTM_BFD_SRC_IP_FIELD, buf);
		}

		STREAM_GETC(s, multi_hop_cnt);
		sprintf(tmp_buf, "%d", multi_hop_cnt);
		ptm_lib_append_msg(ptm_hdl, out_ctxt,
				   ZEBRA_PTM_BFD_MAX_HOP_CNT_FIELD, tmp_buf);

		if (zvrf_id(zvrf) != VRF_DEFAULT)
			ptm_lib_append_msg(ptm_hdl, out_ctxt,
					   ZEBRA_PTM_BFD_VRF_NAME_FIELD,
					   zvrf_name(zvrf));
	} else {
		if (dst_p.family == AF_INET6) {
			STREAM_GETW(s, src_p.family);

			if (src_p.family == AF_INET)
				src_p.prefixlen = IPV4_MAX_BYTELEN;
			else
				src_p.prefixlen = IPV6_MAX_BYTELEN;

			STREAM_GET(&src_p.u.prefix, s, src_p.prefixlen);
			if (src_p.family == AF_INET) {
				inet_ntop(AF_INET, &src_p.u.prefix4, buf,
					  sizeof(buf));
				ptm_lib_append_msg(ptm_hdl, out_ctxt,
						   ZEBRA_PTM_BFD_SRC_IP_FIELD,
						   buf);
			} else {
				inet_ntop(AF_INET6, &src_p.u.prefix6, buf,
					  sizeof(buf));
				ptm_lib_append_msg(ptm_hdl, out_ctxt,
						   ZEBRA_PTM_BFD_SRC_IP_FIELD,
						   buf);
			}
		}
		STREAM_GETC(s, len);
		STREAM_GET(if_name, s, len);
		if_name[len] = '\0';

		ptm_lib_append_msg(ptm_hdl, out_ctxt,
				   ZEBRA_PTM_BFD_IFNAME_FIELD, if_name);
	}

	sprintf(tmp_buf, "%d", 1);
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_SEND_EVENT,
			   tmp_buf);

	ptm_lib_complete_msg(ptm_hdl, out_ctxt, ptm_cb.out_data, &data_len);

	if (IS_ZEBRA_DEBUG_SEND)
		zlog_debug("%s: Sent message (%d) %s", __func__, data_len,
			   ptm_cb.out_data);
	zebra_ptm_send_message(ptm_cb.out_data, data_len);

	return 0;

stream_failure:
	ptm_lib_cleanup_msg(ptm_hdl, out_ctxt);
	return 0;
}

/* BFD peer/dst deregister */
int zebra_ptm_bfd_dst_deregister(struct zserv *client, u_short length,
				 struct zebra_vrf *zvrf)
{
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
	unsigned int pid;

	client->bfd_peer_del_cnt++;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("bfd_dst_deregister msg from client %s: length=%d",
			   zebra_route_string(client->proto), length);

	if (ptm_cb.ptm_sock == -1) {
		ptm_cb.t_timer = NULL;
		thread_add_timer(zebrad.master, zebra_ptm_connect, NULL,
				 ptm_cb.reconnect_time, &ptm_cb.t_timer);
		return -1;
	}

	ptm_lib_init_msg(ptm_hdl, 0, PTMLIB_MSG_TYPE_CMD, NULL, &out_ctxt);

	sprintf(tmp_buf, "%s", ZEBRA_PTM_BFD_STOP_CMD);
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_CMD_STR, tmp_buf);

	sprintf(tmp_buf, "%s", zebra_route_string(client->proto));
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_CLIENT_FIELD,
			   tmp_buf);

	s = client->ibuf;

	STREAM_GETL(s, pid);
	sprintf(tmp_buf, "%d", pid);
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_SEQID_FIELD,
			   tmp_buf);

	STREAM_GETW(s, dst_p.family);

	if (dst_p.family == AF_INET)
		dst_p.prefixlen = IPV4_MAX_BYTELEN;
	else
		dst_p.prefixlen = IPV6_MAX_BYTELEN;

	STREAM_GET(&dst_p.u.prefix, s, dst_p.prefixlen);
	if (dst_p.family == AF_INET)
		inet_ntop(AF_INET, &dst_p.u.prefix4, buf, sizeof(buf));
	else
		inet_ntop(AF_INET6, &dst_p.u.prefix6, buf, sizeof(buf));
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_DST_IP_FIELD, buf);


	STREAM_GETC(s, multi_hop);
	if (multi_hop) {
		sprintf(tmp_buf, "%d", 1);
		ptm_lib_append_msg(ptm_hdl, out_ctxt,
				   ZEBRA_PTM_BFD_MULTI_HOP_FIELD, tmp_buf);

		STREAM_GETW(s, src_p.family);

		if (src_p.family == AF_INET)
			src_p.prefixlen = IPV4_MAX_BYTELEN;
		else
			src_p.prefixlen = IPV6_MAX_BYTELEN;

		STREAM_GET(&src_p.u.prefix, s, src_p.prefixlen);
		if (src_p.family == AF_INET)
			inet_ntop(AF_INET, &src_p.u.prefix4, buf, sizeof(buf));
		else
			inet_ntop(AF_INET6, &src_p.u.prefix6, buf, sizeof(buf));
		ptm_lib_append_msg(ptm_hdl, out_ctxt,
				   ZEBRA_PTM_BFD_SRC_IP_FIELD, buf);

		if (zvrf_id(zvrf) != VRF_DEFAULT)
			ptm_lib_append_msg(ptm_hdl, out_ctxt,
					   ZEBRA_PTM_BFD_VRF_NAME_FIELD,
					   zvrf_name(zvrf));
	} else {
		if (dst_p.family == AF_INET6) {
			STREAM_GETW(s, src_p.family);

			if (src_p.family == AF_INET)
				src_p.prefixlen = IPV4_MAX_BYTELEN;
			else
				src_p.prefixlen = IPV6_MAX_BYTELEN;

			STREAM_GET(&src_p.u.prefix, s, src_p.prefixlen);
			if (src_p.family == AF_INET) {
				inet_ntop(AF_INET, &src_p.u.prefix4, buf,
					  sizeof(buf));
				ptm_lib_append_msg(ptm_hdl, out_ctxt,
						   ZEBRA_PTM_BFD_SRC_IP_FIELD,
						   buf);
			} else {
				inet_ntop(AF_INET6, &src_p.u.prefix6, buf,
					  sizeof(buf));
				ptm_lib_append_msg(ptm_hdl, out_ctxt,
						   ZEBRA_PTM_BFD_SRC_IP_FIELD,
						   buf);
			}
		}

		STREAM_GETC(s, len);
		STREAM_GET(if_name, s, len);
		if_name[len] = '\0';

		ptm_lib_append_msg(ptm_hdl, out_ctxt,
				   ZEBRA_PTM_BFD_IFNAME_FIELD, if_name);
	}

	ptm_lib_complete_msg(ptm_hdl, out_ctxt, ptm_cb.out_data, &data_len);
	if (IS_ZEBRA_DEBUG_SEND)
		zlog_debug("%s: Sent message (%d) %s", __func__, data_len,
			   ptm_cb.out_data);

	zebra_ptm_send_message(ptm_cb.out_data, data_len);

	return 0;

stream_failure:
	ptm_lib_cleanup_msg(ptm_hdl, out_ctxt);
	return 0;
}

/* BFD client register */
int zebra_ptm_bfd_client_register(struct zserv *client,
				  u_short length)
{
	struct stream *s;
	unsigned int pid;
	void *out_ctxt = NULL;
	char tmp_buf[64];
	int data_len = ZEBRA_PTM_SEND_MAX_SOCKBUF;

	client->bfd_client_reg_cnt++;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("bfd_client_register msg from client %s: length=%d",
			   zebra_route_string(client->proto), length);

	s = client->ibuf;
	STREAM_GETL(s, pid);

	if (ptm_cb.ptm_sock == -1) {
		ptm_cb.t_timer = NULL;
		thread_add_timer(zebrad.master, zebra_ptm_connect, NULL,
				 ptm_cb.reconnect_time, &ptm_cb.t_timer);
		return -1;
	}

	ptm_lib_init_msg(ptm_hdl, 0, PTMLIB_MSG_TYPE_CMD, NULL, &out_ctxt);

	sprintf(tmp_buf, "%s", ZEBRA_PTM_BFD_CLIENT_REG_CMD);
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_CMD_STR, tmp_buf);

	sprintf(tmp_buf, "%s", zebra_route_string(client->proto));
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_CLIENT_FIELD,
			   tmp_buf);

	sprintf(tmp_buf, "%d", pid);
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_SEQID_FIELD,
			   tmp_buf);

	ptm_lib_complete_msg(ptm_hdl, out_ctxt, ptm_cb.out_data, &data_len);

	if (IS_ZEBRA_DEBUG_SEND)
		zlog_debug("%s: Sent message (%d) %s", __func__, data_len,
			   ptm_cb.out_data);
	zebra_ptm_send_message(ptm_cb.out_data, data_len);

	SET_FLAG(ptm_cb.client_flags[client->proto],
		 ZEBRA_PTM_BFD_CLIENT_FLAG_REG);

	return 0;

stream_failure:
	if (out_ctxt)
		ptm_lib_cleanup_msg(ptm_hdl, out_ctxt);
	return 0;
}

/* BFD client deregister */
void zebra_ptm_bfd_client_deregister(int proto)
{
	void *out_ctxt;
	char tmp_buf[64];
	int data_len = ZEBRA_PTM_SEND_MAX_SOCKBUF;

	if (proto != ZEBRA_ROUTE_OSPF && proto != ZEBRA_ROUTE_BGP
	    && proto != ZEBRA_ROUTE_OSPF6 && proto != ZEBRA_ROUTE_PIM)
		return;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_err("bfd_client_deregister msg for client %s",
			 zebra_route_string(proto));

	if (ptm_cb.ptm_sock == -1) {
		ptm_cb.t_timer = NULL;
		thread_add_timer(zebrad.master, zebra_ptm_connect, NULL,
				 ptm_cb.reconnect_time, &ptm_cb.t_timer);
		return;
	}

	ptm_lib_init_msg(ptm_hdl, 0, PTMLIB_MSG_TYPE_CMD, NULL, &out_ctxt);

	sprintf(tmp_buf, "%s", ZEBRA_PTM_BFD_CLIENT_DEREG_CMD);
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_CMD_STR, tmp_buf);

	sprintf(tmp_buf, "%s", zebra_route_string(proto));
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_CLIENT_FIELD,
			   tmp_buf);

	ptm_lib_complete_msg(ptm_hdl, out_ctxt, ptm_cb.out_data, &data_len);

	if (IS_ZEBRA_DEBUG_SEND)
		zlog_debug("%s: Sent message (%d) %s", __func__, data_len,
			   ptm_cb.out_data);

	zebra_ptm_send_message(ptm_cb.out_data, data_len);
	UNSET_FLAG(ptm_cb.client_flags[proto], ZEBRA_PTM_BFD_CLIENT_FLAG_REG);
}

int zebra_ptm_get_enable_state(void)
{
	return ptm_cb.ptm_enable;
}

/*
 * zebra_ptm_get_status_str - Convert status to a display string.
 */
static const char *zebra_ptm_get_status_str(int status)
{
	switch (status) {
	case ZEBRA_PTM_STATUS_DOWN:
		return "fail";
	case ZEBRA_PTM_STATUS_UP:
		return "pass";
	case ZEBRA_PTM_STATUS_UNKNOWN:
	default:
		return "n/a";
	}
}

void zebra_ptm_show_status(struct vty *vty, struct interface *ifp)
{
	vty_out(vty, "  PTM status: ");
	if (ifp->ptm_enable) {
		vty_out(vty, "%s\n", zebra_ptm_get_status_str(ifp->ptm_status));
	} else {
		vty_out(vty, "disabled\n");
	}
}

void zebra_ptm_send_status_req(void)
{
	void *out_ctxt;
	int len = ZEBRA_PTM_SEND_MAX_SOCKBUF;

	if (ptm_cb.ptm_enable) {
		ptm_lib_init_msg(ptm_hdl, 0, PTMLIB_MSG_TYPE_CMD, NULL,
				 &out_ctxt);
		ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_CMD_STR,
				   ZEBRA_PTM_GET_STATUS_CMD);
		ptm_lib_complete_msg(ptm_hdl, out_ctxt, ptm_cb.out_data, &len);

		zebra_ptm_send_message(ptm_cb.out_data, len);
	}
}

void zebra_ptm_reset_status(int ptm_disable)
{
	struct vrf *vrf;
	struct interface *ifp;
	int send_linkup;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id)
		FOR_ALL_INTERFACES (vrf, ifp) {
			send_linkup = 0;
			if (ifp->ptm_enable) {
				if (!if_is_operative(ifp))
					send_linkup = 1;

				if (ptm_disable)
					ifp->ptm_enable =
						ZEBRA_IF_PTM_ENABLE_OFF;
				ifp->ptm_status = ZEBRA_PTM_STATUS_UNKNOWN;

				if (if_is_operative(ifp) && send_linkup) {
					if (IS_ZEBRA_DEBUG_EVENT)
						zlog_debug(
							"%s: Bringing up interface %s",
							__func__, ifp->name);
					if_up(ifp);
				}
			}
		}
}

void zebra_ptm_if_init(struct zebra_if *zebra_ifp)
{
	zebra_ifp->ptm_enable = ZEBRA_IF_PTM_ENABLE_UNSPEC;
}

void zebra_ptm_if_set_ptm_state(struct interface *ifp,
				struct zebra_if *zebra_ifp)
{
	if (zebra_ifp && zebra_ifp->ptm_enable != ZEBRA_IF_PTM_ENABLE_UNSPEC)
		ifp->ptm_enable = zebra_ifp->ptm_enable;
}

void zebra_ptm_if_write(struct vty *vty, struct zebra_if *zebra_ifp)
{
	if (zebra_ifp->ptm_enable == ZEBRA_IF_PTM_ENABLE_OFF)
		vty_out(vty, " no ptm-enable\n");
}
