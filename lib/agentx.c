// SPDX-License-Identifier: GPL-2.0-or-later
/* SNMP support
 * Copyright (C) 2012 Vincent Bernat <bernat@luffy.cx>
 */

#include <zebra.h>
#include <fcntl.h>

#ifdef SNMP_AGENTX
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/snmp_vars.h>
#include <net-snmp/library/large_fd_set.h>

#include "command.h"
#include "smux.h"
#include "memory.h"
#include "linklist.h"
#include "lib/version.h"
#include "lib_errors.h"
#include "hook.h"
#include "libfrr.h"
#include "xref.h"

XREF_SETUP();

DEFINE_HOOK(agentx_enabled, (), ());

static bool agentx_enabled = false;

static struct event_loop *agentx_tm;
static struct event *timeout_thr = NULL;
static struct list *events = NULL;

static void agentx_events_update(void);

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
		flog_err(EC_LIB_SYSTEM_CALL, "Failed to get FD settings fcntl: %s(%d)",
			 strerror(errno), errno);
		return;
	}

	if (flags & O_NONBLOCK)
		nonblock = true;
	else
		new_flags = fcntl(EVENT_FD(t), F_SETFL, flags | O_NONBLOCK);

	if (new_flags == -1)
		flog_err(EC_LIB_SYSTEM_CALL, "Failed to set snmp fd non blocking: %s(%d)",
			 strerror(errno), errno);

	netsnmp_large_fd_set_init(&lfds, FD_SETSIZE);
	netsnmp_large_fd_setfd(t->u.fd, &lfds);
	snmp_read2(&lfds);

	/* Reset the flag */
	if (!nonblock) {
		new_flags = fcntl(EVENT_FD(t), F_SETFL, flags);

		if (new_flags == -1)
			flog_err(
				EC_LIB_SYSTEM_CALL,
				"Failed to set snmp fd back to original settings: %s(%d)",
				strerror(errno), errno);
	}

	netsnmp_check_outstanding_agent_requests();
	agentx_events_update();
	netsnmp_large_fd_set_cleanup(&lfds);
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

	event_cancel(&timeout_thr);

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
				event_cancel(thr);
				XFREE(MTYPE_TMP, thr);
				list_delete_node(events, ln);
			}
			ln = nextln;
			thr = ln ? listgetdata(ln) : NULL;
			thr_fd = thr ? EVENT_FD(*thr) : -1;
		}
		/* need listener, but haven't hit one where it would be */
		else if (netsnmp_large_fd_is_set(fd, &lfds)) {
			struct listnode *newln;

			thr = XCALLOC(MTYPE_TMP, sizeof(struct event *));
			newln = listnode_add_before(events, ln, thr);
			event_add_read(agentx_tm, agentx_read, newln, fd, thr);
		}
	}

	/* leftover event listeners at this point have fd > maxfd, delete them
	 */
	while (ln) {
		struct listnode *nextln = listnextnode(ln);
		thr = listgetdata(ln);
		event_cancel(thr);
		XFREE(MTYPE_TMP, thr);
		list_delete_node(events, ln);
		ln = nextln;
	}
	netsnmp_large_fd_set_cleanup(&lfds);
}

/* AgentX node. */
static int config_write_agentx(struct vty *vty);
static struct cmd_node agentx_node = {
	.name = "smux",
	.node = SMUX_NODE,
	.prompt = "",
	.config_write = config_write_agentx,
};

/* Logging NetSNMP messages */
static int agentx_log_callback(int major, int minor, void *serverarg,
			       void *clientarg)
{
	struct snmp_log_message *slm = (struct snmp_log_message *)serverarg;
	char *msg = XSTRDUP(MTYPE_TMP, slm->msg);
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

static int config_write_agentx(struct vty *vty)
{
	if (agentx_enabled)
		vty_out(vty, "agentx\n");
	return 1;
}

DEFUN (agentx_enable,
       agentx_enable_cmd,
       "agentx",
       "SNMP AgentX protocol settings\n")
{
	if (!agentx_enabled) {
		init_snmp(FRR_SMUX_NAME);
		events = list_new();
		agentx_events_update();
		agentx_enabled = true;
		hook_call(agentx_enabled);
	}

	return CMD_SUCCESS;
}

DEFUN (no_agentx,
       no_agentx_cmd,
       "no agentx",
       NO_STR
       "SNMP AgentX protocol settings\n")
{
	if (!agentx_enabled)
		return CMD_SUCCESS;
	vty_out(vty, "SNMP AgentX support cannot be disabled once enabled\n");
	return CMD_WARNING_CONFIG_FAILED;
}

static int smux_disable(void)
{
	agentx_enabled = false;

	return 0;
}

bool smux_enabled(void)
{
	return agentx_enabled;
}

void smux_init(struct event_loop *tm)
{
	agentx_tm = tm;

	netsnmp_enable_subagent();
	snmp_disable_log();
	snmp_enable_calllog();
	snmp_register_callback(SNMP_CALLBACK_LIBRARY, SNMP_CALLBACK_LOGGING,
			       agentx_log_callback, NULL);
	init_agent(FRR_SMUX_NAME);

	install_node(&agentx_node);
	install_element(CONFIG_NODE, &agentx_enable_cmd);
	install_element(CONFIG_NODE, &no_agentx_cmd);

	hook_register(frr_early_fini, smux_disable);
}

void smux_agentx_enable(void)
{
	if (!agentx_enabled) {
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
		 * this allows the behaviour of smux_trap with a singe index
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


	send_v2trap(notification_vars);
	snmp_free_varbind(notification_vars);
	agentx_events_update();
	return 1;
}

void smux_events_update(void)
{
	agentx_events_update();
}

#endif /* SNMP_AGENTX */
