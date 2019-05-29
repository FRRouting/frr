/*
 * VTY library for Path Monitoring Daemon
 * Copyright (C) 6WIND 2019
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "vty.h"
#include "command.h"
#include "prefix.h"
#include "sockunion.h"
#include <hash.h>
#include "nexthop.h"
#include "log.h"
#include "vrf.h"
#include "zclient.h"
#include "nexthop_group.h"

#include "pmd/pm_memory.h"
#include "pmd/pm_zebra.h"
#include "pmd/pm_vty.h"
#include "pmd/pm_memory.h"

#include "pmd/pm.h"
#include "pmd/pm_echo.h"

#ifndef VTYSH_EXTRACT_PL
#include "pmd/pm_vty_clippy.c"
#endif

#define SESSION_STR "Configure session\n"
#define SESSION_IPV4_STR "IPv4 peer address\n"
#define SESSION_IPV6_STR "IPv6 peer address\n"
#define REMOTE_STR "Configure remote address\n"
#define LOCAL_STR "Configure local address\n"
#define LOCAL_IPV4_STR "IPv4 local address\n"
#define LOCAL_IPV6_STR "IPv6 local address\n"
#define LOCAL_INTF_STR "Configure local interface name to use\n"
#define VRF_STR "Configure VRF\n"
#define VRF_NAME_STR "Configure VRF name\n"

/*
 * Prototypes
 */
static int pm_write_config(struct vty *vty);
static int pm_session_walk_write_config(struct vty *vty);
static void pm_session_write_config_walker(struct hash_bucket *b, void *data);

static int pm_write_config(struct vty *vty)
{
	vty_out(vty, "pm\n");
	vty_out(vty, "!\n");
	return 0;
}

struct pm_session_walk_ctxt {
	struct vty *vty;
	struct pm_session *pm;
};

static void pm_session_write_config_walker(struct hash_bucket *b, void *data)
{
	struct vty *vty = data;
	char buf[SU_ADDRSTRLEN];
	struct pm_session *pm = (struct pm_session *)b->data;

	if (!PM_CHECK_FLAG(pm->flags, PM_SESS_FLAG_CONFIG))
		return;
	vty_out(vty, " session %s", sockunion2str(&pm->key.peer, buf, sizeof(buf)));
	if (sockunion_family(&pm->key.local) == AF_INET ||
	    sockunion_family(&pm->key.local) == AF_INET6)
		vty_out(vty, " local-address %s",
			sockunion2str(&pm->key.local, buf, sizeof(buf)));
	if (pm->key.ifname[0])
		vty_out(vty, " interface %s", pm->key.ifname);
	if (pm->key.vrfname[0])
		vty_out(vty, " vrf %s", pm->key.vrfname);
	vty_out(vty, "\n");
	if (pm->interval != PM_INTERVAL_DEFAULT)
		vty_out(vty, "  interval %u\n", pm->interval);
	if (pm->tos_val != PM_PACKET_TOS_DEFAULT)
		vty_out(vty, "  packet-tos %u\n", pm->tos_val);
	if (pm->packet_size != pm_get_default_packet_size(pm))
		vty_out(vty, "  packet-size %u\n", pm->packet_size);
	if (pm->timeout != PM_TIMEOUT_DEFAULT)
		vty_out(vty, "  timeout %u\n", pm->timeout);
	if (pm->retries_down != PM_PACKET_RETRIES_DOWN_DEFAULT
	    || pm->retries_up != PM_PACKET_RETRIES_UP_DEFAULT)
		vty_out(vty, "  retries up-count %u down-count %u\n",
			pm->retries_up, pm->retries_down);
	if (pm->flags & PM_SESS_FLAG_SHUTDOWN)
		vty_out(vty, "  shutdown\n");
	else
		vty_out(vty, "  no shutdown\n");
	vty_out(vty, " !\n");
	return;
}

static int pm_session_walk_write_config(struct vty *vty)
{
	if (pm_nht_not_used)
		vty_out(vty, " no nht\n");
	hash_iterate(pm_session_list,
		     pm_session_write_config_walker, (void *)vty);
	return 1;
}

/*
 * Commands definition.
 */
DEFUN_NOSH(pm_enter, pm_enter_cmd, "pm", "Configure Path Monitoring sessions\n")
{
	vty->node = PM_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH(
	pm_peer_enter, pm_peer_enter_cmd,
	"session <A.B.C.D|X:X::X:X> [{local-address <A.B.C.D|X:X::X:X>|interface IFNAME|vrf NAME}]",
	SESSION_STR SESSION_IPV4_STR SESSION_IPV6_STR
	LOCAL_STR LOCAL_IPV4_STR LOCAL_IPV6_STR
	INTERFACE_STR
	LOCAL_INTF_STR
	VRF_STR VRF_NAME_STR)
{
	struct pm_session *pm = NULL;
	const char *peer = argv[1]->arg;
	int idx;
	const char *ifname = NULL, *local = NULL, *vrfname = NULL;
	union sockunion psa;
	char errormsg[128];

	idx = 0;
	if (argv_find(argv, argc, "interface", &idx))
		ifname = argv[idx + 1]->arg;

	idx = 0;
	if (argv_find(argv, argc, "local-address", &idx))
		local = argv[idx + 1]->arg;

	idx = 0;
	if (argv_find(argv, argc, "vrf", &idx))
		vrfname = argv[idx + 1]->arg;

	str2sockunion(peer, &psa);
	pm = pm_lookup_session(&psa, local, ifname, vrfname, false,
			       errormsg, sizeof(errormsg));
	if (pm) {
		if (!PM_CHECK_FLAG(pm->flags, PM_SESS_FLAG_CONFIG)) {
			if (pm->refcount)
				vty_out(vty, "%% session peer is now configurable via pm daemon.\n");
			PM_SET_FLAG(pm->flags, PM_SESS_FLAG_CONFIG);
		}
		VTY_PUSH_CONTEXT(PM_SESSION_NODE, pm);
		return CMD_SUCCESS;
	}
	pm = pm_lookup_session(&psa, local, ifname, vrfname, true,
			       errormsg, sizeof(errormsg));
	if (!pm) {
		vty_out(vty, "%% Invalid session configuration: %s\n",
			errormsg);
		return CMD_WARNING_CONFIG_FAILED;
	}
	pm_initialise(pm, false, errormsg, sizeof(errormsg));
	pm_zebra_nht_register(pm, true, vty);
	VTY_PUSH_CONTEXT(PM_SESSION_NODE, pm);
	return CMD_SUCCESS;
}

DEFPY(
	pm_set_nht, pm_set_nht_cmd,
	"[no$no] nht",
	NO_STR
	"Enable nexthop-tracking\n")
{
	if (no)
		pm_zebra_nht(false);
	else
		pm_zebra_nht(true);
	return CMD_SUCCESS;
}

DEFPY(
	pm_remove_session, pm_remove_session_cmd,
	"no session <A.B.C.D|X:X::X:X>$peer [{local-address <A.B.C.D|X:X::X:X>$local|interface IFNAME$ifname|vrf NAME$vrfname}]",
	NO_STR
	SESSION_STR SESSION_IPV4_STR SESSION_IPV6_STR
	LOCAL_STR LOCAL_IPV4_STR LOCAL_IPV6_STR
	INTERFACE_STR
	LOCAL_INTF_STR
	VRF_STR VRF_NAME_STR)
{
	union sockunion psa;
	struct pm_session *pm = NULL;
	char errormsg[128];

	str2sockunion(peer_str, &psa);
	pm = pm_lookup_session(&psa, local_str, ifname, vrfname, false,
			       errormsg, sizeof(errormsg));
	if (!pm) {
		vty_out(vty, "%% Invalid session configuration: %s\n",
			errormsg);
		return CMD_WARNING_CONFIG_FAILED;
	}
	/* flush session if any */
	pm_echo_stop(pm, errormsg, sizeof(errormsg), false);
	pm_zebra_nht_register(pm, false, vty);

	hash_release(pm_session_list, pm);
	XFREE(MTYPE_PM_SESSION, pm);
	return CMD_SUCCESS;
}

DEFPY(pm_packet_interval, pm_packet_interval_cmd, "[no] interval [(1-65535)$freq]",
      NO_STR
      "Interval between each emission\n"
      "Interval in milliseconds\n")
{
	struct pm_session *pm;

	pm = VTY_GET_CONTEXT(pm_session);

	if (no)
		pm->interval = PM_INTERVAL_DEFAULT;
	else if (freq)
		pm->interval = freq;
	pm_try_run(vty, pm);
	return CMD_SUCCESS;
}

DEFPY(pm_packet_size, pm_packet_size_cmd, "[no] packet-size [(1-65535)$psize]",
      NO_STR "Packet size in bytes\n" "Size of packet to send\n")
{
	struct pm_session *pm;

	pm = VTY_GET_CONTEXT(pm_session);

	if (no)
		pm->packet_size = pm_get_default_packet_size(pm);
	else if (psize)
		pm->packet_size = psize;
	pm_try_run(vty, pm);
	return CMD_SUCCESS;
}

DEFPY(pm_packet_tos, pm_packet_tos_cmd, "[no] packet-tos (1-255)$tosval",
      NO_STR "TOS to apply to packet\n"
      "Packet TOS val in decimal format\n")
{
	struct pm_session *pm;

	pm = VTY_GET_CONTEXT(pm_session);

	if (no)
		pm->tos_val = PM_PACKET_TOS_DEFAULT;
	else if (tosval)
		pm->tos_val = tosval;
	pm_try_run(vty, pm);
	return CMD_SUCCESS;
}

DEFPY(pm_packet_timeout, pm_packet_timeout_cmd, "[no] timeout [(1-65535)$tmo]",
      NO_STR
      "Timeout where response considered as lost\n"
      "Timeout in milliseconds\n")
{
	struct pm_session *pm;

	pm = VTY_GET_CONTEXT(pm_session);

	if (no)
		pm->timeout = PM_TIMEOUT_DEFAULT;
	else if (tmo)
		pm->timeout = tmo;
	pm_try_run(vty, pm);
	return CMD_SUCCESS;
}

DEFPY(pm_packet_retries, pm_packet_retries_cmd,
      "[no] retries [up-count (1-255)$retriesup] [down-count (1-255)$retriesdown]",
      NO_STR
      "Number of consecutive retries where response considered as lost\n"
      "Number of consecutive retries up\n"
      "Retries in number of responses\n"
      "Number of consecutive retries down\n"
      "Retries in number of responses\n")
{
	struct pm_session *pm;

	pm = VTY_GET_CONTEXT(pm_session);

	if (no) {
		pm->retries_up = PM_PACKET_RETRIES_UP_DEFAULT;
		pm->retries_down = PM_PACKET_RETRIES_DOWN_DEFAULT;
	} else {
		if (retriesup)
			pm->retries_up = retriesup;
		if (retriesdown)
			pm->retries_down = retriesdown;
		pm_try_run(vty, pm);
	}
	return CMD_SUCCESS;
}

DEFPY(pm_session_shutdown, pm_session_shutdown_cmd, "[no] shutdown",
      NO_STR "Disable PM session\n")
{
	struct pm_session *pm;
	char errormsg[128];

	pm = VTY_GET_CONTEXT(pm_session);
	if (no) {
		if (!PM_CHECK_FLAG(pm->flags, PM_SESS_FLAG_SHUTDOWN))
			return CMD_SUCCESS;

		PM_UNSET_FLAG(pm->flags, PM_SESS_FLAG_SHUTDOWN);
		pm_try_run(vty, pm);
	} else {
		if (PM_CHECK_FLAG(pm->flags, PM_SESS_FLAG_SHUTDOWN))
			return CMD_SUCCESS;

		/* flush previous context */
		if (pm->oper_ctxt) {
			pm_echo_stop(pm, errormsg, sizeof(errormsg), false);
			PM_UNSET_FLAG(pm->flags, PM_SESS_FLAG_RUN);
		}

		PM_SET_FLAG(pm->flags, PM_SESS_FLAG_SHUTDOWN);

		pm_echo_stop(pm, errormsg, sizeof(errormsg), false);
	}
	return CMD_SUCCESS;
}

DEFUN_NOSH (show_debugging_pmd,
	    show_debugging_pmd_cmd,
	    "show debugging [pm]",
	    SHOW_STR
	    DEBUG_STR
	    "Pm Information\n")
{
	vty_out(vty, "Pm debugging status\n");

	return CMD_SUCCESS;
}

struct pm_session_dump {
	struct vty *vty;
	bool oper;
	char *vrfname;
	union sockunion *psa;
	bool use_json;
	struct json_object *jo;
};

static struct json_object *_session_json_header(struct pm_session *pm)
{
	struct json_object *jo = json_object_new_object();
	char addr_buf[INET6_ADDRSTRLEN];

	sockunion2str(&pm->key.peer, addr_buf, sizeof(addr_buf));
	json_object_string_add(jo, "peer", addr_buf);
	if (sockunion_family(&pm->key.local) == AF_INET ||
	    sockunion_family(&pm->key.local) == AF_INET6) {
		sockunion2str(&pm->key.local, addr_buf, sizeof(addr_buf));
		json_object_string_add(jo, "local", addr_buf);
	}

	if (pm->key.vrfname[0])
		json_object_string_add(jo, "vrf", pm->key.vrfname);
	if (pm->key.ifname[0])
		json_object_string_add(jo, "interface", pm->key.ifname);

	return jo;
}

static struct json_object *__display_session_json(struct pm_session *pm,
						  bool operational)
{
	struct json_object *jo = _session_json_header(pm);
	char buf[256];
	struct pm_echo *pme = pm->oper_ctxt;

	if (operational)
		return jo;
	if (!pme) {
		json_object_int_add(jo, "id", 0);
		if (!PM_CHECK_FLAG(pm->flags, PM_SESS_FLAG_NH_VALID))
			json_object_string_add(jo, "diagnostic",
					       "echo unreachable");
		else
			json_object_string_add(jo, "diagnostic",
					       "echo none");
	} else {
		json_object_int_add(jo, "id", pme->discriminator_id);
		json_object_string_add(jo, "diagnostic",
				       pm_echo_get_alarm_str(pm,
							buf,
							sizeof(buf)));
	}
	json_object_string_add(jo, "status",
			       pm_get_state_str(pm, buf,
						sizeof(buf)));
	if (pm->ses_state == PM_DOWN)
		json_object_int_add(jo, "downtime",
				    monotime(NULL) -
				    monotime(&pm->last_time_change));
	else if (pm->ses_state == PM_UP)
		json_object_int_add(jo, "uptime",
				    monotime(NULL) -
				    monotime(&pm->last_time_change));
	json_object_string_add(jo, "type",
			       pm_get_probe_type(pm, buf,
						 sizeof(buf)));
	json_object_int_add(jo, "interval",
			    pm->interval);
	json_object_int_add(jo, "timeout",
			    pm->timeout);
	json_object_int_add(jo, "retries_up",
			    pm->retries_up);
	json_object_int_add(jo, "retries_down",
			    pm->retries_down);
	json_object_int_add(jo, "tos_val",
			    pm->tos_val);
	json_object_int_add(jo, "packet-size",
			    pm->packet_size);
	return jo;
}

static void pm_session_dump_config_walker(struct hash_bucket *b, void *data)
{
	struct pm_session_dump *psd = data;
	struct vty *vty = psd->vty;
	char buf[SU_ADDRSTRLEN];
	char buf2[256];
	struct pm_session *pm = (struct pm_session *)b->data;
	struct json_object *jo = NULL;

	if (psd->vrfname) {
		if (!pm->key.vrfname[0] ||
		    !strmatch(pm->key.vrfname, psd->vrfname))
			return;
	}
	if (psd->psa) {
		if (!sockunion_same((const union sockunion *)&pm->key.peer,
				    (const union sockunion *)psd->psa))
			return;
	}
	if (psd->use_json) {
		jo = __display_session_json(pm, psd->oper);
		json_object_array_add(psd->jo, jo);
		return;
	}
	vty_out(vty, " session %s", sockunion2str(&pm->key.peer,
						  buf, sizeof(buf)));
	if (sockunion_family(&pm->key.local) == AF_INET ||
	    sockunion_family(&pm->key.local) == AF_INET6)
		vty_out(vty, " local-address %s",
			sockunion2str(&pm->key.local, buf, sizeof(buf)));
	if (pm->key.ifname[0])
		vty_out(vty, " interface %s", pm->key.ifname);
	if (pm->key.vrfname[0])
		vty_out(vty, " vrf %s", pm->key.vrfname);
	vty_out(vty, "\n");

	if (psd->oper) {
		pm_echo_dump(vty, pm);
		return;
	}
	vty_out(vty, "\tpacket-tos %u, packet-size %u",
		pm->tos_val, pm->packet_size);
	vty_out(vty, ", interval %u, timeout %u\n",
		pm->interval, pm->timeout);
	vty_out(vty, "\tretries up-count %u down-count %u\n",
		pm->retries_up, pm->retries_down);
	vty_out(vty, "\tstatus: (0x%x)", pm->flags);
	vty_out(vty, " session admin %s, run %s\n",
		pm->flags & PM_SESS_FLAG_SHUTDOWN ? "down" : "up",
		pm->flags & PM_SESS_FLAG_RUN ? "active" : "stopped");
	vty_out(vty, "\t\t %s (%s)\n",
		pm_get_state_str(pm, buf, sizeof(buf)),
		pm_echo_get_alarm_str(pm, buf2, sizeof(buf2)));
}

DEFPY(show_pmd_sessions,
      show_pmd_sessions_cmd,
      "show pm [vrf <NAME>] sessions [operational] [json]",
      SHOW_STR
      "Path Monitoring\n"
      VRF_CMD_HELP_STR
      "Pm Sessions\n"
      "Operational\n"
      JSON_STR)
{
	struct pm_session_dump psd;
	int oper, idx = 0;
	char *vrfname = NULL;
	int idx_vrf = 0;

	if (argv_find(argv, argc, "vrf", &idx_vrf))
		vrfname = argv[idx_vrf + 1]->arg;

	oper = argv_find(argv, argc, "operational", &idx);

	memset(&psd, 0, sizeof(struct pm_session_dump));
	psd.vty = vty;
	psd.vrfname = vrfname;
	psd.psa = NULL;
	if (oper)
		psd.oper = true;
	else
		psd.oper = false;
	psd.use_json = use_json(argc, argv);
	if (!psd.use_json)
		vty_out(vty, "Pm Sessions status\n");
	else
		psd.jo = json_object_new_array();
	hash_iterate(pm_session_list,
		     pm_session_dump_config_walker, (void *)&psd);
	if (psd.use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(psd.jo, 0));
		json_object_free(psd.jo);
	}
	return CMD_SUCCESS;
}

DEFPY(show_pmd_session,
      show_pmd_session_cmd,
      "show pm [vrf <NAME>] session <A.B.C.D|X:X::X:X>$peer [operational] [json]",
      SHOW_STR
      "Path Monitoring\n"
      VRF_CMD_HELP_STR
      SESSION_STR SESSION_IPV4_STR SESSION_IPV6_STR
      "Operational\n"
      JSON_STR)
{
	struct pm_session_dump psd;
	int oper, idx = 0;
	char *vrfname = NULL;
	int idx_vrf = 0;
	union sockunion psa;

	str2sockunion(peer_str, &psa);

	if (argv_find(argv, argc, "vrf", &idx_vrf))
		vrfname = argv[idx_vrf + 1]->arg;

	oper = argv_find(argv, argc, "operational", &idx);

	memset(&psd, 0, sizeof(struct pm_session_dump));
	psd.vty = vty;
	psd.vrfname = vrfname;
	psd.psa = &psa;
	if (oper)
		psd.oper = true;
	else
		psd.oper = false;
	psd.use_json = use_json(argc, argv);
	if (!psd.use_json)
		vty_out(vty, "Pm Sessions status\n");
	else
		psd.jo = json_object_new_array();
	hash_iterate(pm_session_list,
		     pm_session_dump_config_walker, (void *)&psd);
	if (psd.use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(psd.jo, 0));
		json_object_free(psd.jo);
	}
	return CMD_SUCCESS;
}

struct cmd_node pm_node = {
	.name = "pm",
	.node = PM_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-pm)# ",
	.config_write = pm_write_config
};

struct cmd_node pm_session_node = {
	.name = "pm-session",
	.node = PM_SESSION_NODE,
	.parent_node = PM_NODE,
	.prompt = "%s(config-pm-session)# ",
	.config_write = pm_session_walk_write_config
};

void pm_vty_init(void)
{
	install_element(ENABLE_NODE, &show_debugging_pmd_cmd);
	install_element(ENABLE_NODE, &show_pmd_sessions_cmd);
	install_element(ENABLE_NODE, &show_pmd_session_cmd);
	/* Install PM node and commands. */
	install_element(CONFIG_NODE, &pm_enter_cmd);
	install_node(&pm_node);
	install_default(PM_NODE);
	install_element(PM_NODE, &pm_peer_enter_cmd);
	install_element(PM_NODE, &pm_remove_session_cmd);
	install_element(PM_NODE, &pm_set_nht_cmd);

	/* Install PM session node. */
	install_node(&pm_session_node);
	install_default(PM_SESSION_NODE);

	install_element(PM_SESSION_NODE, &pm_session_shutdown_cmd);
	install_element(PM_SESSION_NODE, &pm_packet_timeout_cmd);
	install_element(PM_SESSION_NODE, &pm_packet_interval_cmd);
	install_element(PM_SESSION_NODE, &pm_packet_retries_cmd);
	install_element(PM_SESSION_NODE, &pm_packet_size_cmd);
	install_element(PM_SESSION_NODE, &pm_packet_tos_cmd);
}
