// SPDX-License-Identifier: GPL-2.0-or-later
/* Kernel routing table updates using netlink over GNU/Linux system.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
 */

#include <zebra.h>

#include <sys/un.h> /* for sockaddr_un */
#include <net/if.h>

#include "bfd.h"
#include "buffer.h"
#include "command.h"
#include "if.h"
#include "network.h"
#include "ptm_lib.h"
#include "rib.h"
#include "stream.h"
#include "lib/version.h"
#include "vrf.h"
#include "vty.h"
#include "lib_errors.h"

#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_ptm.h"
#include "zebra/zebra_ptm_redistribute.h"
#include "zebra/zebra_router.h"
#include "zebra_vrf.h"

/*
 * Choose the BFD implementation that we'll use.
 *
 * There are two implementations:
 * - PTM BFD: which uses an external daemon;
 * - bfdd: FRR's own BFD daemon;
 */
#if HAVE_BFDD == 0

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
const char ZEBRA_PTM_BFD_CBIT_FIELD[] = "bfdcbit";

static ptm_lib_handle_t *ptm_hdl;

struct zebra_ptm_cb ptm_cb;

static int zebra_ptm_socket_init(void);
void zebra_ptm_sock_read(struct event *thread);
static int zebra_ptm_handle_msg_cb(void *arg, void *in_ctxt);
void zebra_bfd_peer_replay_req(void);
void zebra_ptm_send_status_req(void);
void zebra_ptm_reset_status(int ptm_disable);
static int zebra_ptm_bfd_client_deregister(struct zserv *client);

const char ZEBRA_PTM_SOCK_NAME[] = "\0/var/run/ptmd.socket";

void zebra_ptm_init(void)
{
	char buf[64];

	memset(&ptm_cb, 0, sizeof(ptm_cb));

	ptm_cb.out_data = calloc(1, ZEBRA_PTM_SEND_MAX_SOCKBUF);
	if (!ptm_cb.out_data) {
		zlog_debug("%s: Allocation of send data failed", __func__);
		return;
	}

	ptm_cb.in_data = calloc(1, ZEBRA_PTM_MAX_SOCKBUF);
	if (!ptm_cb.in_data) {
		zlog_debug("%s: Allocation of recv data failed", __func__);
		free(ptm_cb.out_data);
		return;
	}

	ptm_cb.pid = getpid();

	snprintf(buf, sizeof(buf), "%s", FRR_PTM_NAME);
	ptm_hdl = ptm_lib_register(buf, NULL, zebra_ptm_handle_msg_cb,
				   zebra_ptm_handle_msg_cb);
	ptm_cb.wb = buffer_new(0);

	ptm_cb.reconnect_time = ZEBRA_PTM_RECONNECT_TIME_INITIAL;

	ptm_cb.ptm_sock = -1;

	hook_register(zserv_client_close, zebra_ptm_bfd_client_deregister);
}

void zebra_ptm_finish(void)
{
	buffer_flush_all(ptm_cb.wb, ptm_cb.ptm_sock);

	free(ptm_hdl);

	if (ptm_cb.out_data)
		free(ptm_cb.out_data);

	if (ptm_cb.in_data)
		free(ptm_cb.in_data);

	/* Cancel events. */
	EVENT_OFF(ptm_cb.t_read);
	EVENT_OFF(ptm_cb.t_write);
	EVENT_OFF(ptm_cb.t_timer);

	if (ptm_cb.wb)
		buffer_free(ptm_cb.wb);

	if (ptm_cb.ptm_sock >= 0)
		close(ptm_cb.ptm_sock);
}

static void zebra_ptm_flush_messages(struct event *thread)
{
	ptm_cb.t_write = NULL;

	if (ptm_cb.ptm_sock == -1)
		return;

	errno = 0;

	switch (buffer_flush_available(ptm_cb.wb, ptm_cb.ptm_sock)) {
	case BUFFER_ERROR:
		flog_err_sys(EC_LIB_SOCKET, "%s ptm socket error: %s", __func__,
			     safe_strerror(errno));
		close(ptm_cb.ptm_sock);
		ptm_cb.ptm_sock = -1;
		zebra_ptm_reset_status(0);
		ptm_cb.t_timer = NULL;
		event_add_timer(zrouter.master, zebra_ptm_connect, NULL,
				ptm_cb.reconnect_time, &ptm_cb.t_timer);
		return;
	case BUFFER_PENDING:
		ptm_cb.t_write = NULL;
		event_add_write(zrouter.master, zebra_ptm_flush_messages, NULL,
				ptm_cb.ptm_sock, &ptm_cb.t_write);
		break;
	case BUFFER_EMPTY:
		break;
	}
}

static int zebra_ptm_send_message(char *data, int size)
{
	errno = 0;
	switch (buffer_write(ptm_cb.wb, ptm_cb.ptm_sock, data, size)) {
	case BUFFER_ERROR:
		flog_err_sys(EC_LIB_SOCKET, "%s ptm socket error: %s", __func__,
			     safe_strerror(errno));
		close(ptm_cb.ptm_sock);
		ptm_cb.ptm_sock = -1;
		zebra_ptm_reset_status(0);
		ptm_cb.t_timer = NULL;
		event_add_timer(zrouter.master, zebra_ptm_connect, NULL,
				ptm_cb.reconnect_time, &ptm_cb.t_timer);
		return -1;
	case BUFFER_EMPTY:
		EVENT_OFF(ptm_cb.t_write);
		break;
	case BUFFER_PENDING:
		event_add_write(zrouter.master, zebra_ptm_flush_messages, NULL,
				ptm_cb.ptm_sock, &ptm_cb.t_write);
		break;
	}

	return 0;
}

void zebra_ptm_connect(struct event *t)
{
	int init = 0;

	if (ptm_cb.ptm_sock == -1) {
		zebra_ptm_socket_init();
		init = 1;
	}

	if (ptm_cb.ptm_sock != -1) {
		if (init) {
			ptm_cb.t_read = NULL;
			event_add_read(zrouter.master, zebra_ptm_sock_read,
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
		event_add_timer(zrouter.master, zebra_ptm_connect, NULL,
				ptm_cb.reconnect_time, &ptm_cb.t_timer);
	} else if (ptm_cb.reconnect_time >= ZEBRA_PTM_RECONNECT_TIME_MAX) {
		ptm_cb.reconnect_time = ZEBRA_PTM_RECONNECT_TIME_INITIAL;
	}
}

void zebra_global_ptm_enable(void)
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
}

void zebra_global_ptm_disable(void)
{
	ptm_cb.ptm_enable = ZEBRA_IF_PTM_ENABLE_OFF;
	zebra_ptm_reset_status(1);
}

void zebra_if_ptm_enable(struct interface *ifp)
{
	struct zebra_if *if_data;
	int old_ptm_enable;
	int send_linkdown = 0;

	if_data = ifp->info;
	if_data->ptm_enable = ZEBRA_IF_PTM_ENABLE_UNSPEC;

	if (ifp->ifindex == IFINDEX_INTERNAL) {
		return;
	}

	old_ptm_enable = ifp->ptm_enable;
	ifp->ptm_enable = ptm_cb.ptm_enable;

	if (if_is_no_ptm_operative(ifp))
		send_linkdown = 1;

	if (!old_ptm_enable && ptm_cb.ptm_enable) {
		if (!if_is_operative(ifp) && send_linkdown) {
			if (IS_ZEBRA_DEBUG_EVENT)
				zlog_debug("%s: Bringing down interface %s",
					   __func__, ifp->name);
			if_down(ifp);
		}
	}
}

void zebra_if_ptm_disable(struct interface *ifp)
{
	struct zebra_if *if_data;
	int send_linkup = 0;

	if ((ifp->ifindex != IFINDEX_INTERNAL) && (ifp->ptm_enable)) {
		if (!if_is_operative(ifp))
			send_linkup = 1;

		ifp->ptm_enable = ZEBRA_IF_PTM_ENABLE_OFF;
		if (if_is_no_ptm_operative(ifp) && send_linkup) {
			if (IS_ZEBRA_DEBUG_EVENT)
				zlog_debug("%s: Bringing up interface %s",
					   __func__, ifp->name);
			if_up(ifp, true);
		}
	}

	if_data = ifp->info;
	if_data->ptm_enable = ZEBRA_IF_PTM_ENABLE_OFF;
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
				   __func__, safe_strerror(errno));
		close(sock);
		return -1;
	}

	/* Make server socket. */
	memset(&addr, 0, sizeof(addr));
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

/* BFD session goes down, send message to the protocols. */
static void if_bfd_session_update(struct interface *ifp, struct prefix *dp,
				  struct prefix *sp, int status,
				  vrf_id_t vrf_id)
{
	if (IS_ZEBRA_DEBUG_EVENT) {
		char buf[2][INET6_ADDRSTRLEN];

		if (ifp) {
			zlog_debug(
				"MESSAGE: ZEBRA_INTERFACE_BFD_DEST_UPDATE %s/%d on %s %s event",
				inet_ntop(dp->family, &dp->u.prefix, buf[0],
					  INET6_ADDRSTRLEN),
				dp->prefixlen, ifp->name,
				bfd_get_status_str(status));
		} else {
			struct vrf *vrf = vrf_lookup_by_id(vrf_id);

			zlog_debug(
				"MESSAGE: ZEBRA_INTERFACE_BFD_DEST_UPDATE %s/%d with src %s/%d and vrf %s(%u) %s event",
				inet_ntop(dp->family, &dp->u.prefix, buf[0],
					  INET6_ADDRSTRLEN),
				dp->prefixlen,
				inet_ntop(sp->family, &sp->u.prefix, buf[1],
					  INET6_ADDRSTRLEN),
				sp->prefixlen, VRF_LOGNAME(vrf), vrf_id,
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
			"%s: Recv Port [%s] bfd status [%s] vrf [%s] peer [%s] local [%s]",
			__func__, ifp ? ifp->name : "N/A", bfdst_str, vrf_str,
			dest_str, src_str);

	if (str2prefix(dest_str, &dest_prefix) == 0) {
		flog_err(EC_ZEBRA_PREFIX_PARSE_ERROR,
			 "%s: Peer addr %s not found", __func__, dest_str);
		return -1;
	}

	memset(&src_prefix, 0, sizeof(src_prefix));
	if (strcmp(ZEBRA_PTM_INVALID_SRC_IP, src_str)) {
		if (str2prefix(src_str, &src_prefix) == 0) {
			flog_err(EC_ZEBRA_PREFIX_PARSE_ERROR,
				 "%s: Local addr %s not found", __func__,
				 src_str);
			return -1;
		}
	}

	if (!strcmp(ZEBRA_PTM_INVALID_VRF, vrf_str) && ifp) {
		vrf_id = ifp->vrf->vrf_id;
	} else {
		struct vrf *pVrf;

		pVrf = vrf_lookup_by_name(vrf_str);
		if (pVrf)
			vrf_id = pVrf->vrf_id;
		else
			vrf_id = VRF_DEFAULT;
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
			if_up(ifp, true);
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
		struct vrf *vrf;
		int count = 0;

		RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
			ifp = if_lookup_by_name_vrf(port_str, vrf);
			if (ifp) {
				count++;
				if (!vrf_is_backend_netns())
					break;
			}
		}

		if (!ifp) {
			flog_warn(EC_ZEBRA_UNKNOWN_INTERFACE,
				  "%s: %s not found in interface list",
				  __func__, port_str);
			return -1;
		}
		if (count > 1) {
			flog_warn(EC_ZEBRA_UNKNOWN_INTERFACE,
				  "%s: multiple interface with name %s",
				  __func__, port_str);
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

void zebra_ptm_sock_read(struct event *thread)
{
	int sock;
	int rc;

	errno = 0;
	sock = EVENT_FD(thread);

	if (sock == -1)
		return;

	/* PTM communicates in CSV format */
	do {
		rc = ptm_lib_process_msg(ptm_hdl, sock, ptm_cb.in_data,
					 ZEBRA_PTM_MAX_SOCKBUF, NULL);
	} while (rc > 0);

	if (((rc == 0) && !errno)
	    || (errno && (errno != EWOULDBLOCK) && (errno != EAGAIN))) {
		flog_err_sys(EC_LIB_SOCKET,
			     "%s routing socket error: %s(%d) bytes %d",
			     __func__, safe_strerror(errno), errno, rc);

		close(ptm_cb.ptm_sock);
		ptm_cb.ptm_sock = -1;
		zebra_ptm_reset_status(0);
		ptm_cb.t_timer = NULL;
		event_add_timer(zrouter.master, zebra_ptm_connect, NULL,
				ptm_cb.reconnect_time, &ptm_cb.t_timer);
		return;
	}

	ptm_cb.t_read = NULL;
	event_add_read(zrouter.master, zebra_ptm_sock_read, NULL,
		       ptm_cb.ptm_sock, &ptm_cb.t_read);
}

/* BFD peer/dst register/update */
void zebra_ptm_bfd_dst_register(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	struct prefix src_p;
	struct prefix dst_p;
	uint8_t multi_hop;
	uint8_t multi_hop_cnt;
	uint8_t detect_mul;
	unsigned int min_rx_timer;
	unsigned int min_tx_timer;
	char if_name[IFNAMSIZ];
	uint8_t len;
	void *out_ctxt;
	char buf[INET6_ADDRSTRLEN];
	char tmp_buf[64];
	int data_len = ZEBRA_PTM_SEND_MAX_SOCKBUF;
	unsigned int pid;
	uint8_t cbit_set;

	if (hdr->command == ZEBRA_BFD_DEST_UPDATE)
		client->bfd_peer_upd8_cnt++;
	else
		client->bfd_peer_add_cnt++;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("bfd_dst_register msg from client %s: length=%d",
			   zebra_route_string(client->proto), hdr->length);

	if (ptm_cb.ptm_sock == -1) {
		ptm_cb.t_timer = NULL;
		event_add_timer(zrouter.master, zebra_ptm_connect, NULL,
				ptm_cb.reconnect_time, &ptm_cb.t_timer);
		return;
	}

	ptm_lib_init_msg(ptm_hdl, 0, PTMLIB_MSG_TYPE_CMD, NULL, &out_ctxt);
	snprintf(tmp_buf, sizeof(tmp_buf), "%s", ZEBRA_PTM_BFD_START_CMD);
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_CMD_STR, tmp_buf);
	snprintf(tmp_buf, sizeof(tmp_buf), "%s",
		 zebra_route_string(client->proto));
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_CLIENT_FIELD,
			   tmp_buf);

	s = msg;

	STREAM_GETL(s, pid);
	snprintf(tmp_buf, sizeof(tmp_buf), "%d", pid);
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
	snprintf(tmp_buf, sizeof(tmp_buf), "%d", min_rx_timer);
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_MIN_RX_FIELD,
			   tmp_buf);
	STREAM_GETL(s, min_tx_timer);
	snprintf(tmp_buf, sizeof(tmp_buf), "%d", min_tx_timer);
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_MIN_TX_FIELD,
			   tmp_buf);
	STREAM_GETC(s, detect_mul);
	snprintf(tmp_buf, sizeof(tmp_buf), "%d", detect_mul);
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_DETECT_MULT_FIELD,
			   tmp_buf);

	STREAM_GETC(s, multi_hop);
	if (multi_hop) {
		snprintf(tmp_buf, sizeof(tmp_buf), "%d", 1);
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
		snprintf(tmp_buf, sizeof(tmp_buf), "%d", multi_hop_cnt);
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
	STREAM_GETC(s, cbit_set);
	snprintf(tmp_buf, sizeof(tmp_buf), "%d", cbit_set);
	ptm_lib_append_msg(ptm_hdl, out_ctxt,
			   ZEBRA_PTM_BFD_CBIT_FIELD, tmp_buf);

	snprintf(tmp_buf, sizeof(tmp_buf), "%d", 1);
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_SEND_EVENT,
			   tmp_buf);

	ptm_lib_complete_msg(ptm_hdl, out_ctxt, ptm_cb.out_data, &data_len);

	if (IS_ZEBRA_DEBUG_SEND)
		zlog_debug("%s: Sent message (%d) %s", __func__, data_len,
			   ptm_cb.out_data);
	zebra_ptm_send_message(ptm_cb.out_data, data_len);

	return;

stream_failure:
	ptm_lib_cleanup_msg(ptm_hdl, out_ctxt);
}

/* BFD peer/dst deregister */
void zebra_ptm_bfd_dst_deregister(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	struct prefix src_p;
	struct prefix dst_p;
	uint8_t multi_hop;
	char if_name[IFNAMSIZ];
	uint8_t len;
	char buf[INET6_ADDRSTRLEN];
	char tmp_buf[64];
	int data_len = ZEBRA_PTM_SEND_MAX_SOCKBUF;
	void *out_ctxt;
	unsigned int pid;

	client->bfd_peer_del_cnt++;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("bfd_dst_deregister msg from client %s: length=%d",
			   zebra_route_string(client->proto), hdr->length);

	if (ptm_cb.ptm_sock == -1) {
		ptm_cb.t_timer = NULL;
		event_add_timer(zrouter.master, zebra_ptm_connect, NULL,
				ptm_cb.reconnect_time, &ptm_cb.t_timer);
		return;
	}

	ptm_lib_init_msg(ptm_hdl, 0, PTMLIB_MSG_TYPE_CMD, NULL, &out_ctxt);

	snprintf(tmp_buf, sizeof(tmp_buf), "%s", ZEBRA_PTM_BFD_STOP_CMD);
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_CMD_STR, tmp_buf);

	snprintf(tmp_buf, sizeof(tmp_buf), "%s",
		 zebra_route_string(client->proto));
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_CLIENT_FIELD,
			   tmp_buf);

	s = msg;

	STREAM_GETL(s, pid);
	snprintf(tmp_buf, sizeof(tmp_buf), "%d", pid);
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
		snprintf(tmp_buf, sizeof(tmp_buf), "%d", 1);
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

	return;

stream_failure:
	ptm_lib_cleanup_msg(ptm_hdl, out_ctxt);
}

/* BFD client register */
void zebra_ptm_bfd_client_register(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	unsigned int pid;
	void *out_ctxt = NULL;
	char tmp_buf[64];
	int data_len = ZEBRA_PTM_SEND_MAX_SOCKBUF;

	client->bfd_client_reg_cnt++;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("bfd_client_register msg from client %s: length=%d",
			   zebra_route_string(client->proto), hdr->length);

	s = msg;
	STREAM_GETL(s, pid);

	if (ptm_cb.ptm_sock == -1) {
		ptm_cb.t_timer = NULL;
		event_add_timer(zrouter.master, zebra_ptm_connect, NULL,
				ptm_cb.reconnect_time, &ptm_cb.t_timer);
		return;
	}

	ptm_lib_init_msg(ptm_hdl, 0, PTMLIB_MSG_TYPE_CMD, NULL, &out_ctxt);

	snprintf(tmp_buf, sizeof(tmp_buf), "%s", ZEBRA_PTM_BFD_CLIENT_REG_CMD);
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_CMD_STR, tmp_buf);

	snprintf(tmp_buf, sizeof(tmp_buf), "%s",
		 zebra_route_string(client->proto));
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_CLIENT_FIELD,
			   tmp_buf);

	snprintf(tmp_buf, sizeof(tmp_buf), "%d", pid);
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_SEQID_FIELD,
			   tmp_buf);

	ptm_lib_complete_msg(ptm_hdl, out_ctxt, ptm_cb.out_data, &data_len);

	if (IS_ZEBRA_DEBUG_SEND)
		zlog_debug("%s: Sent message (%d) %s", __func__, data_len,
			   ptm_cb.out_data);
	zebra_ptm_send_message(ptm_cb.out_data, data_len);

	SET_FLAG(ptm_cb.client_flags[client->proto],
		 ZEBRA_PTM_BFD_CLIENT_FLAG_REG);

	return;

stream_failure:
	/*
	 * IF we ever add more STREAM_GETXXX functions after the out_ctxt
	 * is allocated then we need to add this code back in
	 *
	 * if (out_ctxt)
	 *	ptm_lib_cleanup_msg(ptm_hdl, out_ctxt);
	 */
	return;
}

/* BFD client deregister */
int zebra_ptm_bfd_client_deregister(struct zserv *client)
{
	uint8_t proto = client->proto;
	void *out_ctxt;
	char tmp_buf[64];
	int data_len = ZEBRA_PTM_SEND_MAX_SOCKBUF;

	if (!IS_BFD_ENABLED_PROTOCOL(proto))
		return 0;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("bfd_client_deregister msg for client %s",
			   zebra_route_string(proto));

	if (ptm_cb.ptm_sock == -1) {
		ptm_cb.t_timer = NULL;
		event_add_timer(zrouter.master, zebra_ptm_connect, NULL,
				ptm_cb.reconnect_time, &ptm_cb.t_timer);
		return 0;
	}

	ptm_lib_init_msg(ptm_hdl, 0, PTMLIB_MSG_TYPE_CMD, NULL, &out_ctxt);

	snprintf(tmp_buf, sizeof(tmp_buf), "%s",
		 ZEBRA_PTM_BFD_CLIENT_DEREG_CMD);
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_CMD_STR, tmp_buf);

	snprintf(tmp_buf, sizeof(tmp_buf), "%s", zebra_route_string(proto));
	ptm_lib_append_msg(ptm_hdl, out_ctxt, ZEBRA_PTM_BFD_CLIENT_FIELD,
			   tmp_buf);

	ptm_lib_complete_msg(ptm_hdl, out_ctxt, ptm_cb.out_data, &data_len);

	if (IS_ZEBRA_DEBUG_SEND)
		zlog_debug("%s: Sent message (%d) %s", __func__, data_len,
			   ptm_cb.out_data);

	zebra_ptm_send_message(ptm_cb.out_data, data_len);
	UNSET_FLAG(ptm_cb.client_flags[proto], ZEBRA_PTM_BFD_CLIENT_FLAG_REG);

	return 0;
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

void zebra_ptm_show_status(struct vty *vty, json_object *json,
			   struct interface *ifp)
{
	const char *status;

	if (ifp->ptm_enable)
		status = zebra_ptm_get_status_str(ifp->ptm_status);
	else
		status = "disabled";

	if (json)
		json_object_string_add(json, "ptmStatus", status);
	else
		vty_out(vty, "  PTM status: %s\n", status);
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
					if_up(ifp, true);
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

#else /* HAVE_BFDD */

/*
 * Data structures.
 */
struct ptm_process {
	struct zserv *pp_zs;
	pid_t pp_pid;

	TAILQ_ENTRY(ptm_process) pp_entry;
};
TAILQ_HEAD(ppqueue, ptm_process) ppqueue;

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_PTM_BFD_PROCESS,
		    "PTM BFD process reg table");

/*
 * Prototypes.
 */
static struct ptm_process *pp_new(pid_t pid, struct zserv *zs);
static struct ptm_process *pp_lookup_byzs(struct zserv *zs);
static void pp_free(struct ptm_process *pp);
static void pp_free_all(void);

static void zebra_ptm_send_bfdd(struct stream *msg);
static void zebra_ptm_send_clients(struct stream *msg);
static int _zebra_ptm_bfd_client_deregister(struct zserv *zs);
static void _zebra_ptm_reroute(struct zserv *zs, struct zebra_vrf *zvrf,
			       struct stream *msg, uint32_t command);


/*
 * Process PID registration.
 */
static struct ptm_process *pp_new(pid_t pid, struct zserv *zs)
{
	struct ptm_process *pp;

#ifdef PTM_DEBUG
	/* Sanity check: more than one client can't have the same PID. */
	TAILQ_FOREACH(pp, &ppqueue, pp_entry) {
		if (pp->pp_pid == pid && pp->pp_zs != zs)
			zlog_err("%s:%d pid and client pointer doesn't match",
				 __FILE__, __LINE__);
	}
#endif /* PTM_DEBUG */

	/* Lookup for duplicates. */
	pp = pp_lookup_byzs(zs);
	if (pp != NULL)
		return pp;

	/* Allocate and register new process. */
	pp = XCALLOC(MTYPE_ZEBRA_PTM_BFD_PROCESS, sizeof(*pp));

	pp->pp_pid = pid;
	pp->pp_zs = zs;
	TAILQ_INSERT_HEAD(&ppqueue, pp, pp_entry);

	return pp;
}

static struct ptm_process *pp_lookup_byzs(struct zserv *zs)
{
	struct ptm_process *pp;

	TAILQ_FOREACH(pp, &ppqueue, pp_entry) {
		if (pp->pp_zs != zs)
			continue;

		break;
	}

	return pp;
}

static void pp_free(struct ptm_process *pp)
{
	if (pp == NULL)
		return;

	TAILQ_REMOVE(&ppqueue, pp, pp_entry);
	XFREE(MTYPE_ZEBRA_PTM_BFD_PROCESS, pp);
}

static void pp_free_all(void)
{
	struct ptm_process *pp;

	while (!TAILQ_EMPTY(&ppqueue)) {
		pp = TAILQ_FIRST(&ppqueue);
		pp_free(pp);
	}
}


/*
 * Use the FRR's internal daemon implementation.
 */
static void zebra_ptm_send_bfdd(struct stream *msg)
{
	struct listnode *node;
	struct zserv *client;
	struct stream *msgc;

	/* Create copy for replication. */
	msgc = stream_dup(msg);

	/* Send message to all running BFDd daemons. */
	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, node, client)) {
		if (client->proto != ZEBRA_ROUTE_BFD)
			continue;

		zserv_send_message(client, msg);

		/* Allocate more messages. */
		msg = stream_dup(msgc);
	}

	stream_free(msgc);
	stream_free(msg);
}

static void zebra_ptm_send_clients(struct stream *msg)
{
	struct listnode *node;
	struct zserv *client;
	struct stream *msgc;

	/* Create copy for replication. */
	msgc = stream_dup(msg);

	/* Send message to all running client daemons. */
	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, node, client)) {
		if (!IS_BFD_ENABLED_PROTOCOL(client->proto))
			continue;

		zserv_send_message(client, msg);

		/* Allocate more messages. */
		msg = stream_dup(msgc);
	}

	stream_free(msgc);
	stream_free(msg);
}

static int _zebra_ptm_bfd_client_deregister(struct zserv *zs)
{
	struct stream *msg;
	struct ptm_process *pp;

	if (!IS_BFD_ENABLED_PROTOCOL(zs->proto))
		return 0;

	/* Find daemon pid by zebra connection pointer. */
	pp = pp_lookup_byzs(zs);
	if (pp == NULL) {
		zlog_err("%s:%d failed to find process pid registration",
			 __FILE__, __LINE__);
		return -1;
	}

	/* Generate, send message and free() daemon related data. */
	msg = stream_new(ZEBRA_MAX_PACKET_SIZ);
	if (msg == NULL) {
		zlog_debug("%s: not enough memory", __func__);
		return 0;
	}

	/*
	 * The message type will be ZEBRA_BFD_DEST_REPLAY so we can use only
	 * one callback at the `bfdd` side, however the real command
	 * number will be included right after the zebra header.
	 */
	zclient_create_header(msg, ZEBRA_BFD_DEST_REPLAY, 0);
	stream_putl(msg, ZEBRA_BFD_CLIENT_DEREGISTER);

	/* Put process PID. */
	stream_putl(msg, pp->pp_pid);

	/* Update the data pointers. */
	stream_putw_at(msg, 0, stream_get_endp(msg));

	zebra_ptm_send_bfdd(msg);

	pp_free(pp);

	return 0;
}

void zebra_ptm_init(void)
{
	/* Initialize the ptm process information list. */
	TAILQ_INIT(&ppqueue);

	/*
	 * Send deregistration messages to BFD daemon when some other
	 * daemon closes. This will help avoid sending daemons
	 * unnecessary notification messages.
	 */
	hook_register(zserv_client_close, _zebra_ptm_bfd_client_deregister);
}

void zebra_ptm_finish(void)
{
	/* Remove the client disconnect hook and free all memory. */
	hook_unregister(zserv_client_close, _zebra_ptm_bfd_client_deregister);
	pp_free_all();
}


/*
 * Message handling.
 */
static void _zebra_ptm_reroute(struct zserv *zs, struct zebra_vrf *zvrf,
			       struct stream *msg, uint32_t command)
{
	struct stream *msgc;
	char buf[ZEBRA_MAX_PACKET_SIZ];
	pid_t ppid;

	/* Create BFD header */
	msgc = stream_new(ZEBRA_MAX_PACKET_SIZ);
	zclient_create_header(msgc, ZEBRA_BFD_DEST_REPLAY, zvrf->vrf->vrf_id);
	stream_putl(msgc, command);

	if (STREAM_READABLE(msg) > STREAM_WRITEABLE(msgc)) {
		zlog_warn("Cannot fit extended BFD header plus original message contents into ZAPI packet; dropping message");
		goto stream_failure;
	}

	/* Copy original message, excluding header, into new message */
	stream_get_from(buf, msg, stream_get_getp(msg), STREAM_READABLE(msg));
	stream_put(msgc, buf, STREAM_READABLE(msg));

	/* Update length field */
	stream_putw_at(msgc, 0, STREAM_READABLE(msgc));

	zebra_ptm_send_bfdd(msgc);
	msgc = NULL;

	/* Registrate process PID for shutdown hook. */
	STREAM_GETL(msg, ppid);
	pp_new(ppid, zs);

	return;

stream_failure:
	if (msgc)
		stream_free(msgc);
	zlog_err("%s:%d failed to registrate client pid", __FILE__, __LINE__);
}

void zebra_ptm_bfd_dst_register(ZAPI_HANDLER_ARGS)
{
	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("bfd_dst_register msg from client %s: length=%d",
			   zebra_route_string(client->proto), hdr->length);

	_zebra_ptm_reroute(client, zvrf, msg, ZEBRA_BFD_DEST_REGISTER);
}

void zebra_ptm_bfd_dst_deregister(ZAPI_HANDLER_ARGS)
{
	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("bfd_dst_deregister msg from client %s: length=%d",
			   zebra_route_string(client->proto), hdr->length);

	_zebra_ptm_reroute(client, zvrf, msg, ZEBRA_BFD_DEST_DEREGISTER);
}

void zebra_ptm_bfd_client_register(ZAPI_HANDLER_ARGS)
{
	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("bfd_client_register msg from client %s: length=%d",
			   zebra_route_string(client->proto), hdr->length);

	_zebra_ptm_reroute(client, zvrf, msg, ZEBRA_BFD_CLIENT_REGISTER);
}

void zebra_ptm_bfd_dst_replay(ZAPI_HANDLER_ARGS)
{
	struct stream *msgc;
	size_t zmsglen, zhdrlen;
	uint32_t cmd;

	/*
	 * NOTE:
	 * Replay messages with HAVE_BFDD are meant to be replayed to
	 * the client daemons. These messages are composed and
	 * originated from the `bfdd` daemon.
	 */
	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("bfd_dst_update msg from client %s: length=%d",
			   zebra_route_string(client->proto), hdr->length);

	/*
	 * Client messages must be re-routed, otherwise do the `bfdd`
	 * special treatment.
	 */
	if (client->proto != ZEBRA_ROUTE_BFD) {
		_zebra_ptm_reroute(client, zvrf, msg, ZEBRA_BFD_DEST_REPLAY);
		return;
	}

	/* Figure out if this is an DEST_UPDATE or DEST_REPLAY. */
	if (stream_getl2(msg, &cmd) == false) {
		zlog_err("%s: expected at least 4 bytes (command)", __func__);
		return;
	}

	/*
	 * Don't modify message in the zebra API. In order to do that we
	 * need to allocate a new message stream and copy the message
	 * provided by zebra.
	 */
	msgc = stream_new(ZEBRA_MAX_PACKET_SIZ);
	if (msgc == NULL) {
		zlog_debug("%s: not enough memory", __func__);
		return;
	}

	/* Calculate our header size plus the message contents. */
	if (cmd != ZEBRA_BFD_DEST_REPLAY) {
		zhdrlen = ZEBRA_HEADER_SIZE;
		zmsglen = msg->endp - msg->getp;
		memcpy(msgc->data + zhdrlen, msg->data + msg->getp, zmsglen);

		zclient_create_header(msgc, cmd, zvrf_id(zvrf));

		msgc->getp = 0;
		msgc->endp = zhdrlen + zmsglen;
	} else
		zclient_create_header(msgc, cmd, zvrf_id(zvrf));

	/* Update the data pointers. */
	stream_putw_at(msgc, 0, stream_get_endp(msgc));

	zebra_ptm_send_clients(msgc);
}

/*
 * Unused functions.
 */
void zebra_ptm_if_init(struct zebra_if *zifp __attribute__((__unused__)))
{
	/* NOTHING */
}

int zebra_ptm_get_enable_state(void)
{
	return 0;
}

void zebra_ptm_show_status(struct vty *vty __attribute__((__unused__)),
			   json_object *json __attribute__((__unused__)),
			   struct interface *ifp __attribute__((__unused__)))
{
	/* NOTHING */
}

void zebra_ptm_if_set_ptm_state(struct interface *i __attribute__((__unused__)),
				struct zebra_if *zi __attribute__((__unused__)))
{
	/* NOTHING */
}

#endif /* HAVE_BFDD */
