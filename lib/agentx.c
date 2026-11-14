// SPDX-License-Identifier: GPL-2.0-or-later
/* SNMP support
 * Copyright (C) 2012 Vincent Bernat <bernat@luffy.cx>
 */

#include <zebra.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#ifdef SNMP_AGENTX
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/snmp_vars.h>
#include <net-snmp/agent/agent_callbacks.h>
#include <net-snmp/agent/ds_agent.h>
#include <net-snmp/library/large_fd_set.h>
#include <net-snmp/library/snmp_transport.h>
#include <net-snmp/library/system.h>

#include "command.h"
#include "smux.h"
#include "memory.h"
#include "linklist.h"
#include "lib/version.h"
#include "lib_errors.h"
#include "hook.h"
#include "libfrr.h"
#include "xref.h"
#include "lib/libagentx.h"
#include "lib/debug.h"
#include "monotime.h"

XREF_SETUP();

DEFINE_HOOK(agentx_enabled, (), ());
DEFINE_MTYPE_STATIC(LIB, AGENTX_TRAP, "AgentX pending SNMP notification");

//bool agentx_enabled = false;

/*
 * Master session is open. INDEX_START sets this, INDEX_STOP clears it.
 * In this net-snmp those fire only for that session, not MIB walks.
 * show agentx status copies the flag and does not probe the socket.
 */
static bool agentx_connected;
/* Session from INDEX_START. Cleared on disconnect. Its socket is the one show reads. */
static netsnmp_session *agentx_master_sess;

static struct event_loop *agentx_tm;
static struct event *timeout_thr = NULL;
static struct list *events = NULL;

static void agentx_events_update(void);

static inline bool agentx_debug(void)
{
	return DEBUG_MODE_CHECK(&agentx_dbg, DEBUG_MODE_ALL);
}

static void agentx_timeout(struct event *t)
{
	snmp_timeout();
	run_alarms();
	netsnmp_check_outstanding_agent_requests();
	agentx_events_update();
}

static void agentx_read(struct event *t)
{
	netsnmp_large_fd_set lfds;
	int flags, new_flags = 0;
	int nonblock = false;
	struct listnode *ln = EVENT_ARG(t);
	struct event **thr = listgetdata(ln);
	XFREE(MTYPE_TMP, thr);
	list_delete_node(events, ln);

	/* fix for non blocking socket */
	flags = fcntl(EVENT_FD(t), F_GETFL, 0);
	if (-1 == flags) {
		/* The session fd is already gone. Logging here repeats once
		 * per read after snmpd drops the AgentX socket.
		 */
		if (errno != EBADF)
			flog_err(EC_LIB_SYSTEM_CALL, "Failed to get FD settings fcntl: %s(%d)",
				 strerror(errno), errno);
		return;
	}

	if (flags & O_NONBLOCK)
		nonblock = true;
	else
		new_flags = fcntl(EVENT_FD(t), F_SETFL, flags | O_NONBLOCK);

	if (new_flags == -1) {
		if (errno == EBADF)
			return;
		flog_err(EC_LIB_SYSTEM_CALL, "Failed to set snmp fd non blocking: %s(%d)",
			 strerror(errno), errno);
	}

	netsnmp_large_fd_set_init(&lfds, FD_SETSIZE);
	netsnmp_large_fd_setfd(t->u.fd, &lfds);
	snmp_read2(&lfds);

	/* Reset the flag. Leave the socket blocking: netsnmp's stream
	 * send treats a short write as success and would split an AgentX
	 * message if the fd stayed O_NONBLOCK.
	 */
	if (!nonblock) {
		new_flags = fcntl(EVENT_FD(t), F_SETFL, flags);

		if (new_flags == -1 && errno != EBADF)
			flog_err(
				EC_LIB_SYSTEM_CALL,
				"Failed to set snmp fd back to original settings: %s(%d)",
				strerror(errno), errno);
	}

	netsnmp_check_outstanding_agent_requests();
	agentx_events_update();
	netsnmp_large_fd_set_cleanup(&lfds);
}

/* Safely cancel an event only if we're in the owner thread.
 * event_cancel() requires owner thread. If not in owner thread,
 * skip cancellation - the event will be cleaned up eventually.
 */
static void agentx_event_cancel_safe(struct event **thr)
{
	if (thr == NULL || *thr == NULL)
		return;

	if (agentx_tm != NULL &&
	    pthread_equal(frr_event_loop_get_pthread_owner(agentx_tm), pthread_self()))
		event_cancel(thr);
}

static void agentx_events_update(void)
{
	int maxfd = 0;
	int block = 1;
	struct timeval timeout = {.tv_sec = 0, .tv_usec = 0};
	netsnmp_large_fd_set lfds;
	struct listnode *ln;
	struct event **thr;
	int fd, thr_fd;

	agentx_event_cancel_safe(&timeout_thr);

	netsnmp_large_fd_set_init(&lfds, FD_SETSIZE);
	snmp_select_info2(&maxfd, &lfds, &timeout, &block);

	if (!block) {
		event_add_timer_tv(agentx_tm, agentx_timeout, NULL, &timeout,
				   &timeout_thr);
	}

	ln = listhead(events);
	thr = ln ? listgetdata(ln) : NULL;
	thr_fd = thr ? EVENT_FD(*thr) : -1;

	/* "two-pointer" / two-list simultaneous iteration
	 * ln/thr/thr_fd point to the next existing event listener to hit while
	 * fd counts to catch up */
	for (fd = 0; fd < maxfd; fd++) {
		/* caught up */
		if (thr_fd == fd) {
			struct listnode *nextln = listnextnode(ln);
			if (!netsnmp_large_fd_is_set(fd, &lfds)) {
				DEBUGD(&agentx_dbg, "AgentX: stop polling fd %d", fd);
				agentx_event_cancel_safe(thr);
				XFREE(MTYPE_TMP, thr);
				list_delete_node(events, ln);
			}
			ln = nextln;
			thr = ln ? listgetdata(ln) : NULL;
			thr_fd = thr ? EVENT_FD(*thr) : -1;
		}
		/* need listener, but haven't hit one where it would be.
		 * The new cell must not be stored in thr: thr is part of the
		 * ln/thr/thr_fd cursor and has to keep describing ln's own
		 * cell, which a later iteration cancels and frees.
		 */
		else if (netsnmp_large_fd_is_set(fd, &lfds)) {
			struct event **newthr;
			struct listnode *newln;

			newthr = XCALLOC(MTYPE_TMP, sizeof(struct event *));
			newln = listnode_add_before(events, ln, newthr);
			event_add_read(agentx_tm, agentx_read, newln, fd, newthr);
			DEBUGD(&agentx_dbg, "AgentX: start polling fd %d", fd);
		}
	}

	/* leftover event listeners at this point have fd > maxfd, delete them
	 */
	while (ln) {
		struct listnode *nextln = listnextnode(ln);
		thr = listgetdata(ln);
		DEBUGD(&agentx_dbg, "AgentX: stop polling fd %d",
		       (thr && *thr) ? EVENT_FD(*thr) : -1);
		agentx_event_cancel_safe(thr);
		XFREE(MTYPE_TMP, thr);
		list_delete_node(events, ln);
		ln = nextln;
	}
	netsnmp_large_fd_set_cleanup(&lfds);
}

/* Logging NetSNMP messages */
static int agentx_log_callback(int major, int minor, void *serverarg,
			       void *clientarg)
{
	struct snmp_log_message *slm = (struct snmp_log_message *)serverarg;
	char *msg;

	if (slm->priority == LOG_DEBUG && !agentx_debug())
		return SNMP_ERR_NOERROR;

	msg = XSTRDUP(MTYPE_TMP, slm->msg);
	if (msg)
		msg[strlen(msg) - 1] = '\0';
	switch (slm->priority) {
	case LOG_EMERG:
		flog_err(EC_LIB_SNMP, "snmp[emerg]: %s", msg ? msg : slm->msg);
		break;
	case LOG_ALERT:
		flog_err(EC_LIB_SNMP, "snmp[alert]: %s", msg ? msg : slm->msg);
		break;
	case LOG_CRIT:
		flog_err(EC_LIB_SNMP, "snmp[crit]: %s", msg ? msg : slm->msg);
		break;
	case LOG_ERR:
		flog_err(EC_LIB_SNMP, "snmp[err]: %s", msg ? msg : slm->msg);
		break;
	case LOG_WARNING:
		flog_warn(EC_LIB_SNMP, "snmp[warning]: %s",
			  msg ? msg : slm->msg);
		break;
	case LOG_NOTICE:
		zlog_notice("snmp[notice]: %s", msg ? msg : slm->msg);
		break;
	case LOG_INFO:
		zlog_info("snmp[info]: %s", msg ? msg : slm->msg);
		break;
	case LOG_DEBUG:
		zlog_debug("snmp[debug]: %s", msg ? msg : slm->msg);
		break;
	}
	XFREE(MTYPE_TMP, msg);
	return SNMP_ERR_NOERROR;
}

static int agentx_cli_on(void)
{
	if (!agentx_enabled) {
		DEBUGD(&agentx_dbg, "AgentX: enable subagent, connecting to master agent");
		init_snmp(FRR_SMUX_NAME);
		events = list_new();
		agentx_events_update();
		agentx_enabled = true;
		hook_call(agentx_enabled);
	}

	return 1;
}

static int agentx_cli_off(void)
{
	if (!agentx_enabled)
		return 1;
	return 0;
}

/*
 * Deferred SNMP notifications.
 *
 * send_v2trap() runs on the calling thread. A mass peer transition would
 * issue thousands of blocking sends, and each one also walks every IPv4
 * address via get_myaddr(). The varbind list is copied by
 * snmp_varlist_add_variable(), so it stays valid after the caller deletes
 * the object that produced it. The drain yields between batches and will
 * not call send_v2trap() unless the AgentX socket has room for a full
 * notification. The socket stays blocking: a non-blocking short write
 * corrupts the AgentX stream.
 */
/*
 * Count, not byte, cap: 65536 copied varbind lists. At the fastest drain
 * rate (16 / 10 ms = 1600 notifications/s), a full queue takes
 * 65536 / 1600 = 40.96 s to empty once socket space returns. There is no
 * finite drain time while snmpd does not consume the socket.
 */
#define AGENTX_TRAP_Q_MAX	     65536
#define AGENTX_TRAP_Q_BATCH	     16
#define AGENTX_TRAP_Q_INTERVAL_MS    10
#define AGENTX_TRAP_DOWN_INTERVAL_MS 1000
#define AGENTX_TRAP_HOLD_MS	     30000
#define AGENTX_TRAP_LOG_INTERVAL_MS  10000
/* Bytes of send-buffer slack required before a blocking send. */
#define AGENTX_TRAP_MIN_SPACE 2048

struct agentx_trap_item {
	netsnmp_variable_list *vars;
	struct agentx_trap_item *next;
};

static struct agentx_trap_item *trap_q_head, *trap_q_tail;
static uint32_t trap_q_len;
static uint64_t trap_q_dropped;
static struct event *trap_q_ev;
static struct timeval trap_q_down_since;
static bool trap_q_down_valid;
static struct timeval trap_q_log_since;
static bool trap_q_log_valid;
static struct timeval trap_q_hold_log_since;
static bool trap_q_hold_log_valid;
static bool trap_addr_cached;

static void agentx_trap_flush(struct event *t);
static void agentx_trap_debug(const char *what, const netsnmp_variable_list *vb);

static void agentx_trap_schedule(long delay_ms)
{
	if (trap_q_ev || !agentx_tm)
		return;
	event_add_timer_msec(agentx_tm, agentx_trap_flush, NULL, delay_ms, &trap_q_ev);
}

static void agentx_trap_log_drop(const char *why, uint32_t queued)
{
	if (trap_q_log_valid &&
	    monotime_since(&trap_q_log_since, NULL) < (int64_t)AGENTX_TRAP_LOG_INTERVAL_MS * 1000)
		return;

	monotime(&trap_q_log_since);
	trap_q_log_valid = true;
	flog_warn(EC_LIB_SNMP,
		  "AgentX: notification backlog %s (%u queued, %" PRIu64
		  " dropped); master agent (snmpd) not consuming traps",
		  why, queued, trap_q_dropped);
}

/* log_drop is false on shutdown: exiting is not a lost notification. */
static void agentx_trap_free_queue(bool log_drop, const char *why)
{
	uint32_t dropped_now = 0;

	while (trap_q_head) {
		struct agentx_trap_item *it = trap_q_head;

		trap_q_head = it->next;
		snmp_free_varbind(it->vars);
		XFREE(MTYPE_AGENTX_TRAP, it);
		dropped_now++;
	}
	trap_q_tail = NULL;
	trap_q_len = 0;

	if (!log_drop || !dropped_now)
		return;

	trap_q_dropped += dropped_now;
	agentx_trap_log_drop(why, dropped_now);
}

static void agentx_trap_quiesce(void)
{
	if (trap_q_len)
		DEBUGD(&agentx_dbg, "AgentX: discard %u queued traps on shutdown", trap_q_len);

	agentx_event_cancel_safe(&trap_q_ev);
	agentx_trap_free_queue(false, NULL);
	trap_q_down_valid = false;
}

/* One SIOCGIFCONF for the life of the process. Later traps resolve the
 * cached literal instead of enumerating every interface address.
 */
static void agentx_cache_trap_addr(void)
{
	in_addr_t addr;
	struct in_addr in;
	char buf[INET_ADDRSTRLEN];

	if (trap_addr_cached)
		return;

	addr = get_myaddr();
	if (addr == 0)
		addr = htonl(INADDR_LOOPBACK);
	in.s_addr = addr;
	if (!inet_ntop(AF_INET, &in, buf, sizeof(buf)))
		return;

	if (netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID, NETSNMP_DS_AGENT_TRAP_ADDR, buf) != 0)
		return;

	trap_addr_cached = true;
}

/* poll() is not enough: POLLOUT is true when a single byte fits, and a
 * blocking send of the rest of the PDU would stall the main loop. Require
 * room for one notification. ioctl failure means this fd is not a stream
 * socket we can measure; ignore it rather than refusing to send forever.
 */
static bool agentx_fd_has_space(int fd)
{
#ifdef TIOCOUTQ
	int queued = 0;
	int sndbuf = 0;
	socklen_t optlen = sizeof(sndbuf);
	int avail;

	if (ioctl(fd, TIOCOUTQ, &queued) < 0)
		return true;
	if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &optlen) < 0 || sndbuf <= 0)
		return true;

	avail = sndbuf / 2 - queued;
	return avail >= AGENTX_TRAP_MIN_SPACE;
#else
	return true;
#endif
}

/*
 * Called from agentx_master_writable() each time the drain cannot send,
 * with why naming the reason: no transport, poll error, not writable,
 * transport error, or send buffer full. Only logs under debug agentx,
 * and rate-limited by AGENTX_TRAP_LOG_INTERVAL_MS, so a busy socket does
 * not flood the log on every 10 ms wake.
 */
static void agentx_trap_debug_hold(const char *why)
{
	if (!agentx_debug())
		return;

	/*
	 * The drain can wake every 10 ms while the socket stays busy.
	 * Log that reason at most once per AGENTX_TRAP_LOG_INTERVAL_MS.
	 * monotime_since() is microseconds, so the interval is scaled.
	 */
	if (trap_q_hold_log_valid && monotime_since(&trap_q_hold_log_since, NULL) <
					     (int64_t)AGENTX_TRAP_LOG_INTERVAL_MS * 1000)
		return;

	monotime(&trap_q_hold_log_since);
	trap_q_hold_log_valid = true;
	DEBUGD(&agentx_dbg, "AgentX: hold trap drain (%s, %u queued)", why, trap_q_len);
}

/* The FRR read-event list is not the AgentX transport. It can be empty
 * while the master session is up, and a descriptor in it that is not
 * writable stops every trap. send_v2trap() uses this session's socket.
 */
static int agentx_master_sock(void)
{
	void *sessp;
	netsnmp_transport *transport;

	if (!agentx_master_sess)
		return -1;

	sessp = snmp_sess_pointer(agentx_master_sess);
	if (!sessp) {
		agentx_master_sess = NULL;
		return -1;
	}

	transport = snmp_sess_transport(sessp);
	if (!transport || transport->sock < 0)
		return -1;
	return transport->sock;
}

/*
 * Same lookup as agentx_master_sock(), without clearing a stale session.
 * "show agentx status" must not change drain state.
 */
static int agentx_master_sock_peek(void)
{
	void *sessp;
	netsnmp_transport *transport;

	if (!agentx_master_sess)
		return -1;

	sessp = snmp_sess_pointer(agentx_master_sess);
	if (!sessp)
		return -1;

	transport = snmp_sess_transport(sessp);
	if (!transport || transport->sock < 0)
		return -1;

	return transport->sock;
}

/*
 * After send_v2trap() the notification is freed, so this backlog is
 * bytes, not a trap count. TIOCOUTQ on a Unix socket is data written
 * and not yet read by snmpd, including per-buffer kernel overhead. On
 * a TCP AgentX socket it is bytes not yet acknowledged, which snmpd
 * may already have received. SO_SNDBUF is the live cap. A failed call
 * leaves the valid flag clear.
 */
static void agentx_read_sendbuf(int fd, struct agentx_cli_status *status)
{
#ifdef TIOCOUTQ
	int queued = 0;
	int sndbuf = 0;
	socklen_t optlen = sizeof(sndbuf);

	if (ioctl(fd, TIOCOUTQ, &queued) == 0 && queued >= 0) {
		status->send_queued = queued;
		status->send_queued_valid = true;
	}

	if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &optlen) == 0 && sndbuf > 0) {
		status->send_maximum = sndbuf;
		status->send_maximum_valid = true;
	}
#else
	(void)fd;
	(void)status;
#endif
}

static bool agentx_master_writable(void)
{
	struct pollfd pfd;
	int fd = agentx_master_sock();
	int ready;

	if (fd < 0) {
		agentx_trap_debug_hold("no AgentX transport");
		return false;
	}

	pfd.fd = fd;
	pfd.events = POLLOUT;
	pfd.revents = 0;
	ready = poll(&pfd, 1, 0);
	if (ready < 0) {
		agentx_trap_debug_hold("poll error");
		return false;
	}
	if (ready == 0) {
		agentx_trap_debug_hold("transport not writable");
		return false;
	}
	if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
		agentx_trap_debug_hold("transport error");
		return false;
	}
	if (!(pfd.revents & POLLOUT)) {
		agentx_trap_debug_hold("transport not writable");
		return false;
	}
	if (!agentx_fd_has_space(fd)) {
		agentx_trap_debug_hold("send buffer full");
		return false;
	}
	return true;
}

static void agentx_trap_enqueue(netsnmp_variable_list *vars)
{
	struct agentx_trap_item *it;

	if (!vars)
		return;

	agentx_cache_trap_addr();

	if (trap_q_len >= AGENTX_TRAP_Q_MAX) {
		snmp_free_varbind(vars);
		trap_q_dropped++;
		agentx_trap_log_drop("full", trap_q_len);
		return;
	}

	it = XCALLOC(MTYPE_AGENTX_TRAP, sizeof(*it));
	it->vars = vars;
	if (trap_q_tail)
		trap_q_tail->next = it;
	else
		trap_q_head = it;
	trap_q_tail = it;
	trap_q_len++;

	if (agentx_debug())
		agentx_trap_debug("queue trap", vars);

	/* First item: timer 0 still polls once before it runs. Further
	 * items keep the timer that is already waiting.
	 */
	if (!trap_q_ev)
		agentx_trap_schedule(0);
}

/*
 * Copy the neighbor into buf for a debug line. RFC 4273 puts it in
 * bgpPeerRemoteAddr, an IpAddress binding, not in the trap OID. The
 * first 4-byte IPv4 binding is that address. buf stays empty when the
 * notification has none.
 */
static void agentx_trap_peer_addr(const netsnmp_variable_list *vb, char *buf, size_t buflen)
{
	buf[0] = '\0';
	for (; vb; vb = vb->next_variable) {
		if (vb->type != ASN_IPADDRESS || !vb->val.string || vb->val_len != 4)
			continue;
		if (!inet_ntop(AF_INET, vb->val.string, buf, buflen))
			buf[0] = '\0';
		return;
	}
}

/* Callers check agentx_debug() first: formatting the OID is not free. */
static void agentx_trap_debug(const char *what, const netsnmp_variable_list *vb)
{
	char oidbuf[512];
	char peerbuf[INET_ADDRSTRLEN];

	oidbuf[0] = '\0';
	/* First binding is snmpTrapOID; its value is the notification. */
	if (vb && vb->type == ASN_OBJECT_ID && vb->val.objid && vb->val_len >= sizeof(oid))
		snprint_objid(oidbuf, sizeof(oidbuf), vb->val.objid, vb->val_len / sizeof(oid));
	agentx_trap_peer_addr(vb, peerbuf, sizeof(peerbuf));
	DEBUGD(&agentx_dbg, "AgentX: %s%s%s%s%s (%u queued)", what, oidbuf[0] ? " " : "", oidbuf,
	       peerbuf[0] ? " neighbor " : "", peerbuf, trap_q_len);
}

static void agentx_trap_flush(struct event *t)
{
	int n = 0;

	if (!agentx_enabled) {
		agentx_trap_free_queue(false, NULL);
		return;
	}

	if (!agentx_connected) {
		if (!trap_q_down_valid) {
			monotime(&trap_q_down_since);
			trap_q_down_valid = true;
		}
		if (monotime_since(&trap_q_down_since, NULL) >=
		    (int64_t)AGENTX_TRAP_HOLD_MS * 1000) {
			agentx_trap_free_queue(true, "master agent down");
			return;
		}
		if (trap_q_head)
			agentx_trap_schedule(AGENTX_TRAP_DOWN_INTERVAL_MS);
		return;
	}

	while (trap_q_head && n < AGENTX_TRAP_Q_BATCH) {
		struct agentx_trap_item *it;

		/* Disconnect can run from inside send_v2trap(). */
		if (!agentx_connected || !agentx_master_writable())
			break;

		it = trap_q_head;
		trap_q_head = it->next;
		if (!trap_q_head)
			trap_q_tail = NULL;
		trap_q_len--;

		if (agentx_debug())
			agentx_trap_debug("send trap to snmpd", it->vars);

		send_v2trap(it->vars);
		snmp_free_varbind(it->vars);
		XFREE(MTYPE_AGENTX_TRAP, it);
		n++;
	}

	if (n)
		agentx_events_update();

	if (!trap_q_head)
		return;

	if (!agentx_connected)
		agentx_trap_schedule(AGENTX_TRAP_DOWN_INTERVAL_MS);
	else
		agentx_trap_schedule(AGENTX_TRAP_Q_INTERVAL_MS);
}

/* INDEX_START: master session opened. show agentx status reports up. */
static int agentx_master_up_cb(int majorID, int minorID, void *serverarg, void *clientarg)
{
	agentx_master_sess = serverarg;
	agentx_connected = true;
	trap_q_down_valid = false;
	DEBUGD(&agentx_dbg, "AgentX: master agent session up (%u traps queued)", trap_q_len);
	if (trap_q_head) {
		agentx_event_cancel_safe(&trap_q_ev);
		agentx_trap_schedule(0);
	}
	return SNMP_ERR_NOERROR;
}

/* INDEX_STOP: that transport dropped. show agentx status reports down. */
static int agentx_master_down_cb(int majorID, int minorID, void *serverarg, void *clientarg)
{
	agentx_master_sess = NULL;
	agentx_connected = false;
	DEBUGD(&agentx_dbg, "AgentX: master agent session down (%u traps queued)", trap_q_len);
	if (!trap_q_down_valid) {
		monotime(&trap_q_down_since);
		trap_q_down_valid = true;
	}
	return SNMP_ERR_NOERROR;
}

static int smux_disable(void)
{
	agentx_enabled = false;
	agentx_connected = false;
	agentx_master_sess = NULL;
	agentx_trap_quiesce();

	return 0;
}

bool smux_enabled(void)
{
	return agentx_enabled;
}

/*
 * pending and dropped are the daemon queue. connected copies
 * agentx_connected. Read the socket only while that is set.
 */
static int agentx_cli_show_cb(struct agentx_cli_status *status)
{
	int fd;

	assert(status);

	status->enabled = agentx_enabled;
	status->connected = agentx_connected;
	status->pending = trap_q_len;
	status->dropped = trap_q_dropped;
	status->send_queued_valid = false;
	status->send_maximum_valid = false;
	status->socket_fd_valid = false;

	if (!agentx_connected)
		return 0;

	fd = agentx_master_sock_peek();
	if (fd < 0)
		return 0;

	status->socket_fd = fd;
	status->socket_fd_valid = true;
	agentx_read_sendbuf(fd, status);

	return 0;
}

void smux_init(struct event_loop *tm)
{
	agentx_tm = tm;

	hook_register(agentx_cli_enabled, agentx_cli_on);
	hook_register(agentx_cli_disabled, agentx_cli_off);
	hook_register(agentx_cli_show, agentx_cli_show_cb);

	netsnmp_enable_subagent();
	snmp_disable_log();
	snmp_enable_calllog();
	snmp_register_callback(SNMP_CALLBACK_LIBRARY, SNMP_CALLBACK_LOGGING,
			       agentx_log_callback, NULL);
	/* Master-session up/down. Registered before init_snmp() opens it. */
	snmp_register_callback(SNMP_CALLBACK_APPLICATION, SNMPD_CALLBACK_INDEX_START,
			       agentx_master_up_cb, NULL);
	snmp_register_callback(SNMP_CALLBACK_APPLICATION, SNMPD_CALLBACK_INDEX_STOP,
			       agentx_master_down_cb, NULL);
	init_agent(FRR_SMUX_NAME);

	hook_register(frr_early_fini, smux_disable);
}

void smux_agentx_enable(void)
{
	if (!agentx_enabled) {
		DEBUGD(&agentx_dbg, "AgentX: enable subagent, connecting to master agent");
		init_snmp(FRR_SMUX_NAME);
		events = list_new();
		agentx_events_update();
		agentx_enabled = true;
	}
}

void smux_register_mib(const char *descr, struct variable *var, size_t width,
		       int num, oid name[], size_t namelen)
{
	register_mib(descr, var, width, num, name, namelen);
}

void smux_trap(struct variable *vp, size_t vp_len, const oid *ename,
	       size_t enamelen, const oid *name, size_t namelen,
	       const oid *iname, size_t inamelen,
	       const struct trap_object *trapobj, size_t trapobjlen,
	       uint8_t sptrap)
{
	struct index_oid trap_index[1];

	/* copy the single index into the multi-index format */
	oid_copy(trap_index[0].indexname, iname, inamelen);
	trap_index[0].indexlen = inamelen;

	smux_trap_multi_index(vp, vp_len, ename, enamelen, name, namelen,
			      trap_index, array_size(trap_index), trapobj,
			      trapobjlen, sptrap);
}

int smux_trap_multi_index(struct variable *vp, size_t vp_len, const oid *ename,
			  size_t enamelen, const oid *name, size_t namelen,
			  struct index_oid *iname, size_t index_len,
			  const struct trap_object *trapobj, size_t trapobjlen,
			  uint8_t sptrap)
{
	oid objid_snmptrap[] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
	size_t objid_snmptrap_len = sizeof(objid_snmptrap) / sizeof(oid);
	oid notification_oid[MAX_OID_LEN];
	size_t notification_oid_len;
	unsigned int i;

	netsnmp_variable_list *notification_vars = NULL;
	if (!agentx_enabled)
		return 0;

	/* snmpTrapOID */
	oid_copy(notification_oid, ename, enamelen);
	notification_oid[enamelen] = sptrap;
	notification_oid_len = enamelen + 1;
	snmp_varlist_add_variable(&notification_vars, objid_snmptrap,
				  objid_snmptrap_len, ASN_OBJECT_ID,
				  (uint8_t *)notification_oid,
				  notification_oid_len * sizeof(oid));

	/* Provided bindings */
	for (i = 0; i < trapobjlen; i++) {
		unsigned int j;
		oid oid[MAX_OID_LEN];
		size_t oid_len, onamelen;
		uint8_t *val;
		size_t val_len;
		WriteMethod *wm = NULL;
		struct variable cvp;
		unsigned int iindex;
		/*
		 * this allows the behaviour of smux_trap with a single index
		 * for all objects to be maintained whilst allowing traps which
		 * have different indices per object to be supported
		 */
		iindex = (index_len == 1) ? 0 : i;

		/* Make OID. */
		if (trapobj[i].namelen > 0) {
			/* Columnar object */
			onamelen = trapobj[i].namelen;
			oid_copy(oid, name, namelen);
			oid_copy(oid + namelen, trapobj[i].name, onamelen);
			oid_copy(oid + namelen + onamelen,
				 iname[iindex].indexname,
				 iname[iindex].indexlen);
			oid_len = namelen + onamelen + iname[iindex].indexlen;
		} else {
			/* Scalar object */
			onamelen = trapobj[i].namelen * (-1);
			oid_copy(oid, name, namelen);
			oid_copy(oid + namelen, trapobj[i].name, onamelen);
			oid[onamelen + namelen] = 0;
			oid_len = namelen + onamelen + 1;
		}

		/* Locate the appropriate function and type in the MIB registry.
		 */
		for (j = 0; j < vp_len; j++) {
			if (oid_compare(trapobj[i].name, onamelen, vp[j].name,
					vp[j].namelen)
			    != 0)
				continue;
			/* We found the appropriate variable in the MIB
			 * registry. */
			oid_copy(cvp.name, name, namelen);
			oid_copy(cvp.name + namelen, vp[j].name, vp[j].namelen);
			cvp.namelen = namelen + vp[j].namelen;
			cvp.type = vp[j].type;
			cvp.magic = vp[j].magic;
			cvp.acl = vp[j].acl;
			cvp.findVar = vp[j].findVar;

			/* Grab the result. */
			val = cvp.findVar(&cvp, oid, &oid_len, 1, &val_len,
					  &wm);
			if (!val)
				break;
			snmp_varlist_add_variable(&notification_vars, oid,
						  oid_len, vp[j].type, val,
						  val_len);
			break;
		}
	}


	/* Ownership of notification_vars moves to the queue. The caller's
	 * object (for example a BGP peer) may be freed as soon as we return.
	 */
	agentx_trap_enqueue(notification_vars);
	return 1;
}

void smux_events_update(void)
{
	agentx_events_update();
}

static void smux_events_delete_thread(void *arg)
{
	XFREE(MTYPE_TMP, arg);
}

void smux_terminate(void)
{
	agentx_trap_quiesce();

	if (events) {
		events->del = smux_events_delete_thread;
		list_delete(&events);
	}
}
#endif /* SNMP_AGENTX */
