/*
 * VRRP CLI commands.
 * Copyright (C) 2018-2019 Cumulus Networks, Inc.
 * Quentin Young
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "lib/command.h"
#include "lib/if.h"
#include "lib/ipaddr.h"
#include "lib/json.h"
#include "lib/prefix.h"
#include "lib/termtable.h"
#include "lib/vty.h"

#include "vrrp.h"
#include "vrrp_debug.h"
#include "vrrp_vty.h"
#include "vrrp_zebra.h"
#ifndef VTYSH_EXTRACT_PL
#include "vrrpd/vrrp_vty_clippy.c"
#endif


#define VRRP_STR "Virtual Router Redundancy Protocol\n"
#define VRRP_VRID_STR "Virtual Router ID\n"
#define VRRP_PRIORITY_STR "Virtual Router Priority\n"
#define VRRP_ADVINT_STR "Virtual Router Advertisement Interval\n"
#define VRRP_IP_STR "Virtual Router IPv4 address\n"
#define VRRP_VERSION_STR "VRRP protocol version\n"

#define VROUTER_GET_VTY(_vty, _ifp, _vrid, _vr)                                \
	do {                                                                   \
		_vr = vrrp_lookup(_ifp, _vrid);                                \
		if (!_vr) {                                                    \
			vty_out(_vty,                                          \
				"%% Please configure VRRP instance %u\n",      \
				(unsigned int)_vrid);                          \
			return CMD_WARNING_CONFIG_FAILED;                      \
		}                                                              \
	} while (0)

/* clang-format off */

DEFPY(vrrp_vrid,
      vrrp_vrid_cmd,
      "[no] vrrp (1-255)$vrid [version (2-3)]",
      NO_STR
      VRRP_STR
      VRRP_VRID_STR
      VRRP_VERSION_STR
      VRRP_VERSION_STR)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	struct vrrp_vrouter *vr = vrrp_lookup(ifp, vrid);

	if (version == 0)
		version = 3;

	if (no && vr)
		vrrp_vrouter_destroy(vr);
	else if (no && !vr)
		vty_out(vty, "%% VRRP instance %ld does not exist on %s\n",
			vrid, ifp->name);
	else if (!vr)
		vrrp_vrouter_create(ifp, vrid, version);
	else if (vr)
		vty_out(vty, "%% VRRP instance %ld already exists on %s\n",
			vrid, ifp->name);

	return CMD_SUCCESS;
}

DEFPY(vrrp_shutdown,
      vrrp_shutdown_cmd,
      "[no] vrrp (1-255)$vrid shutdown",
      NO_STR
      VRRP_STR
      VRRP_VRID_STR
      "Force VRRP router into administrative shutdown\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	struct vrrp_vrouter *vr;

	VROUTER_GET_VTY(vty, ifp, vrid, vr);

	if (!no) {
		if (vr->v4->fsm.state != VRRP_STATE_INITIALIZE)
			vrrp_event(vr->v4, VRRP_EVENT_SHUTDOWN);
		if (vr->v6->fsm.state != VRRP_STATE_INITIALIZE)
			vrrp_event(vr->v6, VRRP_EVENT_SHUTDOWN);
		vr->shutdown = true;
	} else {
		vr->shutdown = false;
		vrrp_check_start(vr);
	}

	return CMD_SUCCESS;
}

DEFPY(vrrp_priority,
      vrrp_priority_cmd,
      "[no] vrrp (1-255)$vrid priority (1-254)",
      NO_STR
      VRRP_STR
      VRRP_VRID_STR
      VRRP_PRIORITY_STR
      "Priority value")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	struct vrrp_vrouter *vr;
	uint8_t newprio = no ? vd.priority : priority;

	VROUTER_GET_VTY(vty, ifp, vrid, vr);

	vrrp_set_priority(vr, newprio);

	return CMD_SUCCESS;
}

DEFPY(vrrp_advertisement_interval,
      vrrp_advertisement_interval_cmd,
      "[no] vrrp (1-255)$vrid advertisement-interval (10-40950)",
      NO_STR VRRP_STR VRRP_VRID_STR VRRP_ADVINT_STR
      "Advertisement interval in milliseconds; must be multiple of 10")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	struct vrrp_vrouter *vr;
	uint16_t newadvint =
		no ? vd.advertisement_interval * CS2MS : advertisement_interval;

	if (newadvint % CS2MS != 0) {
		vty_out(vty, "%% Value must be a multiple of %u\n",
			(unsigned int)CS2MS);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* all internal computations are in centiseconds */
	newadvint /= CS2MS;

	VROUTER_GET_VTY(vty, ifp, vrid, vr);
	vrrp_set_advertisement_interval(vr, newadvint);

	return CMD_SUCCESS;
}

DEFPY(vrrp_ip,
      vrrp_ip_cmd,
      "[no] vrrp (1-255)$vrid ip A.B.C.D",
      NO_STR
      VRRP_STR
      VRRP_VRID_STR
      "Add IPv4 address\n"
      VRRP_IP_STR)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	struct vrrp_vrouter *vr;
	bool deactivated = false;
	bool activated = false;
	bool failed = false;
	int ret = CMD_SUCCESS;
	int oldstate;

	VROUTER_GET_VTY(vty, ifp, vrid, vr);

	bool will_activate = (vr->v4->fsm.state == VRRP_STATE_INITIALIZE);

	if (no) {
		oldstate = vr->v4->fsm.state;
		failed = vrrp_del_ipv4(vr, ip);
		vrrp_check_start(vr);
		deactivated = (vr->v4->fsm.state == VRRP_STATE_INITIALIZE
			       && oldstate != VRRP_STATE_INITIALIZE);
	} else {
		oldstate = vr->v4->fsm.state;
		failed = vrrp_add_ipv4(vr, ip);
		vrrp_check_start(vr);
		activated = (vr->v4->fsm.state != VRRP_STATE_INITIALIZE
			     && oldstate == VRRP_STATE_INITIALIZE);
	}

	if (activated)
		vty_out(vty, "%% Activated IPv4 Virtual Router %ld\n", vrid);
	if (deactivated)
		vty_out(vty, "%% Deactivated IPv4 Virtual Router %ld\n", vrid);
	if (failed) {
		vty_out(vty, "%% Failed to %s virtual IP\n",
			no ? "remove" : "add");
		ret = CMD_WARNING_CONFIG_FAILED;
		if (will_activate && !activated) {
			vty_out(vty,
				"%% Failed to activate IPv4 Virtual Router %ld\n",
				vrid);
		}
	}

	return ret;
}

DEFPY(vrrp_ip6,
      vrrp_ip6_cmd,
      "[no] vrrp (1-255)$vrid ipv6 X:X::X:X",
      NO_STR
      VRRP_STR
      VRRP_VRID_STR
      "Add IPv6 address\n"
      VRRP_IP_STR)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	struct vrrp_vrouter *vr;
	bool deactivated = false;
	bool activated = false;
	bool failed = false;
	int ret = CMD_SUCCESS;
	int oldstate;

	VROUTER_GET_VTY(vty, ifp, vrid, vr);

	if (vr->version != 3) {
		vty_out(vty,
			"%% Cannot add IPv6 address to VRRPv2 virtual router\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bool will_activate = (vr->v6->fsm.state == VRRP_STATE_INITIALIZE);

	if (no) {
		oldstate = vr->v6->fsm.state;
		failed = vrrp_del_ipv6(vr, ipv6);
		vrrp_check_start(vr);
		deactivated = (vr->v6->fsm.state == VRRP_STATE_INITIALIZE
			       && oldstate != VRRP_STATE_INITIALIZE);
	} else {
		oldstate = vr->v6->fsm.state;
		failed = vrrp_add_ipv6(vr, ipv6);
		vrrp_check_start(vr);
		activated = (vr->v6->fsm.state != VRRP_STATE_INITIALIZE
			     && oldstate == VRRP_STATE_INITIALIZE);
	}

	if (activated)
		vty_out(vty, "%% Activated IPv6 Virtual Router %ld\n", vrid);
	if (deactivated)
		vty_out(vty, "%% Deactivated IPv6 Virtual Router %ld\n", vrid);
	if (failed) {
		vty_out(vty, "%% Failed to %s virtual IP\n",
			no ? "remove" : "add");
		ret = CMD_WARNING_CONFIG_FAILED;
		if (will_activate && !activated) {
			vty_out(vty,
				"%% Failed to activate IPv6 Virtual Router %ld\n",
				vrid);
		}
	}

	return ret;
}

DEFPY(vrrp_preempt,
      vrrp_preempt_cmd,
      "[no] vrrp (1-255)$vrid preempt",
      NO_STR
      VRRP_STR
      VRRP_VRID_STR
      "Preempt mode\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	struct vrrp_vrouter *vr;

	VROUTER_GET_VTY(vty, ifp, vrid, vr);

	vr->preempt_mode = !no;

	return CMD_SUCCESS;
}

DEFPY(vrrp_autoconfigure,
      vrrp_autoconfigure_cmd,
      "[no] vrrp autoconfigure [version (2-3)]",
      NO_STR
      VRRP_STR
      "Automatically set up VRRP instances on VRRP-compatible interfaces\n"
      "Version for automatically configured instances\n"
      VRRP_VERSION_STR)
{
	version = version ? version : 3;

	if (!no)
		vrrp_autoconfig_on(version);
	else
		vrrp_autoconfig_off();

	return CMD_SUCCESS;
}

DEFPY(vrrp_default,
      vrrp_default_cmd,
      "[no] vrrp default <advertisement-interval$adv (10-40950)$advint|preempt$p|priority$prio (1-254)$prioval|shutdown$s>",
      NO_STR
      VRRP_STR
      "Configure defaults for new VRRP instances\n"
      VRRP_ADVINT_STR
      "Advertisement interval in milliseconds\n"
      "Preempt mode\n"
      VRRP_PRIORITY_STR
      "Priority value\n"
      "Force VRRP router into administrative shutdown\n")
{
	if (adv) {
		if (advint % CS2MS != 0) {
			vty_out(vty, "%% Value must be a multiple of %u\n",
				(unsigned int)CS2MS);
			return CMD_WARNING_CONFIG_FAILED;
		}
		/* all internal computations are in centiseconds */
		advint /= CS2MS;
		vd.advertisement_interval = no ? VRRP_DEFAULT_ADVINT : advint;
	}
	if (p)
		vd.preempt_mode = !no;
	if (prio)
		vd.priority = no ? VRRP_DEFAULT_PRIORITY : prioval;
	if (s)
		vd.shutdown = !no;

	return CMD_SUCCESS;
}

/* clang-format on */

/*
 * Build JSON representation of VRRP instance.
 *
 * vr
 *    VRRP router to build json object from
 *
 * Returns:
 *    JSON representation of VRRP instance. Must be freed by caller.
 */
static struct json_object *vrrp_build_json(struct vrrp_vrouter *vr)
{
	char ethstr4[ETHER_ADDR_STRLEN];
	char ethstr6[ETHER_ADDR_STRLEN];
	char ipstr[INET6_ADDRSTRLEN];
	const char *stastr4 = vrrp_state_names[vr->v4->fsm.state];
	const char *stastr6 = vrrp_state_names[vr->v6->fsm.state];
	char sipstr4[INET6_ADDRSTRLEN] = {};
	char sipstr6[INET6_ADDRSTRLEN] = {};
	struct listnode *ln;
	struct ipaddr *ip;
	struct json_object *j = json_object_new_object();
	struct json_object *v4 = json_object_new_object();
	struct json_object *v4_stats = json_object_new_object();
	struct json_object *v4_addrs = json_object_new_array();
	struct json_object *v6 = json_object_new_object();
	struct json_object *v6_stats = json_object_new_object();
	struct json_object *v6_addrs = json_object_new_array();

	prefix_mac2str(&vr->v4->vmac, ethstr4, sizeof(ethstr4));
	prefix_mac2str(&vr->v6->vmac, ethstr6, sizeof(ethstr6));

	json_object_int_add(j, "vrid", vr->vrid);
	json_object_int_add(j, "version", vr->version);
	json_object_boolean_add(j, "autoconfigured", vr->autoconf);
	json_object_boolean_add(j, "shutdown", vr->shutdown);
	json_object_boolean_add(j, "preemptMode", vr->preempt_mode);
	json_object_boolean_add(j, "acceptMode", vr->accept_mode);
	json_object_string_add(j, "interface", vr->ifp->name);
	json_object_int_add(j, "advertisementInterval",
			    vr->advertisement_interval * CS2MS);
	/* v4 */
	json_object_string_add(v4, "interface",
			       vr->v4->mvl_ifp ? vr->v4->mvl_ifp->name : "");
	json_object_string_add(v4, "vmac", ethstr4);
	ipaddr2str(&vr->v4->src, sipstr4, sizeof(sipstr4));
	json_object_string_add(v4, "primaryAddress", sipstr4);
	json_object_string_add(v4, "status", stastr4);
	json_object_int_add(v4, "effectivePriority", vr->v4->priority);
	json_object_int_add(v4, "masterAdverInterval",
			    vr->v4->master_adver_interval * CS2MS);
	json_object_int_add(v4, "skewTime", vr->v4->skew_time * CS2MS);
	json_object_int_add(v4, "masterDownInterval",
			    vr->v4->master_down_interval * CS2MS);
	/* v4 stats */
	json_object_int_add(v4_stats, "adverTx", vr->v4->stats.adver_tx_cnt);
	json_object_int_add(v4_stats, "adverRx", vr->v4->stats.adver_rx_cnt);
	json_object_int_add(v4_stats, "garpTx", vr->v4->stats.garp_tx_cnt);
	json_object_int_add(v4_stats, "transitions", vr->v4->stats.trans_cnt);
	json_object_object_add(v4, "stats", v4_stats);
	/* v4 addrs */
	if (vr->v4->addrs->count) {
		for (ALL_LIST_ELEMENTS_RO(vr->v4->addrs, ln, ip)) {
			inet_ntop(vr->v4->family, &ip->ipaddr_v4, ipstr,
				  sizeof(ipstr));
			json_object_array_add(v4_addrs,
					      json_object_new_string(ipstr));
		}
	}
	json_object_object_add(v4, "addresses", v4_addrs);
	json_object_object_add(j, "v4", v4);

	/* v6 */
	json_object_string_add(v6, "interface",
			       vr->v6->mvl_ifp ? vr->v6->mvl_ifp->name : "");
	json_object_string_add(v6, "vmac", ethstr6);
	ipaddr2str(&vr->v6->src, sipstr6, sizeof(sipstr6));
	if (strlen(sipstr6) == 0 && vr->v6->src.ip.addr == 0x00)
		strlcat(sipstr6, "::", sizeof(sipstr6));
	json_object_string_add(v6, "primaryAddress", sipstr6);
	json_object_string_add(v6, "status", stastr6);
	json_object_int_add(v6, "effectivePriority", vr->v6->priority);
	json_object_int_add(v6, "masterAdverInterval",
			    vr->v6->master_adver_interval * CS2MS);
	json_object_int_add(v6, "skewTime", vr->v6->skew_time * CS2MS);
	json_object_int_add(v6, "masterDownInterval",
			    vr->v6->master_down_interval * CS2MS);
	/* v6 stats */
	json_object_int_add(v6_stats, "adverTx", vr->v6->stats.adver_tx_cnt);
	json_object_int_add(v6_stats, "adverRx", vr->v6->stats.adver_rx_cnt);
	json_object_int_add(v6_stats, "neighborAdverTx",
			    vr->v6->stats.una_tx_cnt);
	json_object_int_add(v6_stats, "transitions", vr->v6->stats.trans_cnt);
	json_object_object_add(v6, "stats", v6_stats);
	/* v6 addrs */
	if (vr->v6->addrs->count) {
		for (ALL_LIST_ELEMENTS_RO(vr->v6->addrs, ln, ip)) {
			inet_ntop(vr->v6->family, &ip->ipaddr_v6, ipstr,
				  sizeof(ipstr));
			json_object_array_add(v6_addrs,
					      json_object_new_string(ipstr));
		}
	}
	json_object_object_add(v6, "addresses", v6_addrs);
	json_object_object_add(j, "v6", v6);

	return j;
}

/*
 * Dump VRRP instance status to VTY.
 *
 * vty
 *    vty to dump to
 *
 * vr
 *    VRRP router to dump
 */
static void vrrp_show(struct vty *vty, struct vrrp_vrouter *vr)
{
	char ethstr4[ETHER_ADDR_STRLEN];
	char ethstr6[ETHER_ADDR_STRLEN];
	char ipstr[INET6_ADDRSTRLEN];
	const char *stastr4 = vrrp_state_names[vr->v4->fsm.state];
	const char *stastr6 = vrrp_state_names[vr->v6->fsm.state];
	char sipstr4[INET6_ADDRSTRLEN] = {};
	char sipstr6[INET6_ADDRSTRLEN] = {};
	struct listnode *ln;
	struct ipaddr *ip;

	struct ttable *tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);

	ttable_add_row(tt, "%s|%" PRIu32, "Virtual Router ID", vr->vrid);
	ttable_add_row(tt, "%s|%" PRIu8, "Protocol Version", vr->version);
	ttable_add_row(tt, "%s|%s", "Autoconfigured",
		       vr->autoconf ? "Yes" : "No");
	ttable_add_row(tt, "%s|%s", "Shutdown", vr->shutdown ? "Yes" : "No");
	ttable_add_row(tt, "%s|%s", "Interface", vr->ifp->name);
	prefix_mac2str(&vr->v4->vmac, ethstr4, sizeof(ethstr4));
	prefix_mac2str(&vr->v6->vmac, ethstr6, sizeof(ethstr6));
	ttable_add_row(tt, "%s|%s", "VRRP interface (v4)",
		       vr->v4->mvl_ifp ? vr->v4->mvl_ifp->name : "None");
	ttable_add_row(tt, "%s|%s", "VRRP interface (v6)",
		       vr->v6->mvl_ifp ? vr->v6->mvl_ifp->name : "None");
	ipaddr2str(&vr->v4->src, sipstr4, sizeof(sipstr4));
	ipaddr2str(&vr->v6->src, sipstr6, sizeof(sipstr6));
	if (strlen(sipstr6) == 0 && vr->v6->src.ip.addr == 0x00)
		strlcat(sipstr6, "::", sizeof(sipstr6));
	ttable_add_row(tt, "%s|%s", "Primary IP (v4)", sipstr4);
	ttable_add_row(tt, "%s|%s", "Primary IP (v6)", sipstr6);
	ttable_add_row(tt, "%s|%s", "Virtual MAC (v4)", ethstr4);
	ttable_add_row(tt, "%s|%s", "Virtual MAC (v6)", ethstr6);
	ttable_add_row(tt, "%s|%s", "Status (v4)", stastr4);
	ttable_add_row(tt, "%s|%s", "Status (v6)", stastr6);
	ttable_add_row(tt, "%s|%" PRIu8, "Priority", vr->priority);
	ttable_add_row(tt, "%s|%" PRIu8, "Effective Priority (v4)",
		       vr->v4->priority);
	ttable_add_row(tt, "%s|%" PRIu8, "Effective Priority (v6)",
		       vr->v6->priority);
	ttable_add_row(tt, "%s|%s", "Preempt Mode",
		       vr->preempt_mode ? "Yes" : "No");
	ttable_add_row(tt, "%s|%s", "Accept Mode",
		       vr->accept_mode ? "Yes" : "No");
	ttable_add_row(tt, "%s|%d ms", "Advertisement Interval",
		       vr->advertisement_interval * CS2MS);
	ttable_add_row(tt, "%s|%d ms",
		       "Master Advertisement Interval (v4)",
		       vr->v4->master_adver_interval * CS2MS);
	ttable_add_row(tt, "%s|%d ms",
		       "Master Advertisement Interval (v6)",
		       vr->v6->master_adver_interval * CS2MS);
	ttable_add_row(tt, "%s|%" PRIu32, "Advertisements Tx (v4)",
		       vr->v4->stats.adver_tx_cnt);
	ttable_add_row(tt, "%s|%" PRIu32, "Advertisements Tx (v6)",
		       vr->v6->stats.adver_tx_cnt);
	ttable_add_row(tt, "%s|%" PRIu32, "Advertisements Rx (v4)",
		       vr->v4->stats.adver_rx_cnt);
	ttable_add_row(tt, "%s|%" PRIu32, "Advertisements Rx (v6)",
		       vr->v6->stats.adver_rx_cnt);
	ttable_add_row(tt, "%s|%" PRIu32, "Gratuitous ARP Tx (v4)",
		       vr->v4->stats.garp_tx_cnt);
	ttable_add_row(tt, "%s|%" PRIu32, "Neigh. Adverts Tx (v6)",
		       vr->v6->stats.una_tx_cnt);
	ttable_add_row(tt, "%s|%" PRIu32, "State transitions (v4)",
		       vr->v4->stats.trans_cnt);
	ttable_add_row(tt, "%s|%" PRIu32, "State transitions (v6)",
		       vr->v6->stats.trans_cnt);
	ttable_add_row(tt, "%s|%d ms", "Skew Time (v4)",
		       vr->v4->skew_time * CS2MS);
	ttable_add_row(tt, "%s|%d ms", "Skew Time (v6)",
		       vr->v6->skew_time * CS2MS);
	ttable_add_row(tt, "%s|%d ms", "Master Down Interval (v4)",
		       vr->v4->master_down_interval * CS2MS);
	ttable_add_row(tt, "%s|%d ms", "Master Down Interval (v6)",
		       vr->v6->master_down_interval * CS2MS);
	ttable_add_row(tt, "%s|%u", "IPv4 Addresses", vr->v4->addrs->count);

	char fill[35];

	memset(fill, '.', sizeof(fill));
	fill[sizeof(fill) - 1] = 0x00;
	if (vr->v4->addrs->count) {
		for (ALL_LIST_ELEMENTS_RO(vr->v4->addrs, ln, ip)) {
			inet_ntop(vr->v4->family, &ip->ipaddr_v4, ipstr,
				  sizeof(ipstr));
			ttable_add_row(tt, "%s|%s", fill, ipstr);
		}
	}

	ttable_add_row(tt, "%s|%u", "IPv6 Addresses", vr->v6->addrs->count);

	if (vr->v6->addrs->count) {
		for (ALL_LIST_ELEMENTS_RO(vr->v6->addrs, ln, ip)) {
			inet_ntop(vr->v6->family, &ip->ipaddr_v6, ipstr,
				  sizeof(ipstr));
			ttable_add_row(tt, "%s|%s", fill, ipstr);
		}
	}

	char *table = ttable_dump(tt, "\n");

	vty_out(vty, "\n%s\n", table);
	XFREE(MTYPE_TMP, table);
	ttable_del(tt);
}

/*
 * Sort comparator, used when sorting VRRP instances for display purposes.
 *
 * Sorts by interface name first, then by VRID ascending.
 */
static int vrrp_instance_display_sort_cmp(const void **d1, const void **d2)
{
	const struct vrrp_vrouter *vr1 = *d1;
	const struct vrrp_vrouter *vr2 = *d2;
	int result;

	result = strcmp(vr1->ifp->name, vr2->ifp->name);
	result += !result * (vr1->vrid - vr2->vrid);

	return result;
}

/* clang-format off */

DEFPY(vrrp_vrid_show,
      vrrp_vrid_show_cmd,
      "show vrrp [interface INTERFACE$ifn] [(1-255)$vrid] [json$json]",
      SHOW_STR
      VRRP_STR
      INTERFACE_STR
      "Only show VRRP instances on this interface\n"
      VRRP_VRID_STR
      JSON_STR)
{
	struct vrrp_vrouter *vr;
	struct listnode *ln;
	struct list *ll = hash_to_list(vrrp_vrouters_hash);
	struct json_object *j = json_object_new_array();

	list_sort(ll, vrrp_instance_display_sort_cmp);

	for (ALL_LIST_ELEMENTS_RO(ll, ln, vr)) {
		if (ifn && !strmatch(ifn, vr->ifp->name))
			continue;
		if (vrid && ((uint8_t) vrid) != vr->vrid)
			continue;

		if (!json)
			vrrp_show(vty, vr);
		else
			json_object_array_add(j, vrrp_build_json(vr));
	}

	if (json)
		vty_out(vty, "%s\n",
			json_object_to_json_string_ext(
				j, JSON_C_TO_STRING_PRETTY));

	json_object_free(j);

	list_delete(&ll);

	return CMD_SUCCESS;
}

DEFPY(vrrp_vrid_show_summary,
      vrrp_vrid_show_summary_cmd,
      "show vrrp [interface INTERFACE$ifn] [(1-255)$vrid] summary",
      SHOW_STR
      VRRP_STR
      INTERFACE_STR
      "Only show VRRP instances on this interface\n"
      VRRP_VRID_STR
      "Summarize all VRRP instances\n")
{
	struct vrrp_vrouter *vr;
	struct listnode *ln;
	struct list *ll = hash_to_list(vrrp_vrouters_hash);

	list_sort(ll, vrrp_instance_display_sort_cmp);

	struct ttable *tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);

	ttable_add_row(
		tt, "Interface|VRID|Priority|IPv4|IPv6|State (v4)|State (v6)");
	ttable_rowseps(tt, 0, BOTTOM, true, '-');

	for (ALL_LIST_ELEMENTS_RO(ll, ln, vr)) {
		if (ifn && !strmatch(ifn, vr->ifp->name))
			continue;
		if (vrid && ((uint8_t)vrid) != vr->vrid)
			continue;

		ttable_add_row(
			tt, "%s|%" PRIu8 "|%" PRIu8 "|%d|%d|%s|%s",
			vr->ifp->name, vr->vrid, vr->priority,
			vr->v4->addrs->count, vr->v6->addrs->count,
			vr->v4->fsm.state == VRRP_STATE_MASTER ? "Master"
							       : "Backup",
			vr->v6->fsm.state == VRRP_STATE_MASTER ? "Master"
							       : "Backup");
	}

	char *table = ttable_dump(tt, "\n");

	vty_out(vty, "\n%s\n", table);
	XFREE(MTYPE_TMP, table);
	ttable_del(tt);

	list_delete(&ll);

	return CMD_SUCCESS;
}


DEFPY(debug_vrrp,
      debug_vrrp_cmd,
      "[no] debug vrrp [{protocol$proto|autoconfigure$ac|packets$pkt|sockets$sock|ndisc$ndisc|arp$arp|zebra$zebra}]",
      NO_STR
      DEBUG_STR
      VRRP_STR
      "Debug protocol state\n"
      "Debug autoconfiguration\n"
      "Debug sent and received packets\n"
      "Debug socket creation and configuration\n"
      "Debug Neighbor Discovery\n"
      "Debug ARP\n"
      "Debug Zebra events\n")
{
	/* If no specific are given on/off them all */
	if (strmatch(argv[argc - 1]->text, "vrrp"))
		vrrp_debug_set(NULL, 0, vty->node, !no, true, true, true, true,
			       true, true, true);
	else
		vrrp_debug_set(NULL, 0, vty->node, !no, !!proto, !!ac, !!pkt,
			       !!sock, !!ndisc, !!arp, !!zebra);

	return CMD_SUCCESS;
}

DEFUN_NOSH (show_debugging_vrrp,
	    show_debugging_vrrp_cmd,
	    "show debugging [vrrp]",
	    SHOW_STR
	    DEBUG_STR
	    "VRRP information\n")
{
	vty_out(vty, "VRRP debugging status:\n");

	vrrp_debug_status_write(vty);

	return CMD_SUCCESS;
}

/* clang-format on */

static struct cmd_node interface_node = {INTERFACE_NODE, "%s(config-if)# ", 1};
static struct cmd_node debug_node = {DEBUG_NODE, "", 1};
static struct cmd_node vrrp_node = {VRRP_NODE, "", 1};

void vrrp_vty_init(void)
{
	install_node(&debug_node, vrrp_config_write_debug);
	install_node(&interface_node, vrrp_config_write_interface);
	install_node(&vrrp_node, vrrp_config_write_global);
	if_cmd_init();

	install_element(VIEW_NODE, &vrrp_vrid_show_cmd);
	install_element(VIEW_NODE, &vrrp_vrid_show_summary_cmd);
	install_element(VIEW_NODE, &show_debugging_vrrp_cmd);
	install_element(VIEW_NODE, &debug_vrrp_cmd);
	install_element(CONFIG_NODE, &debug_vrrp_cmd);
	install_element(CONFIG_NODE, &vrrp_autoconfigure_cmd);
	install_element(CONFIG_NODE, &vrrp_default_cmd);
	install_element(INTERFACE_NODE, &vrrp_vrid_cmd);
	install_element(INTERFACE_NODE, &vrrp_shutdown_cmd);
	install_element(INTERFACE_NODE, &vrrp_priority_cmd);
	install_element(INTERFACE_NODE, &vrrp_advertisement_interval_cmd);
	install_element(INTERFACE_NODE, &vrrp_ip_cmd);
	install_element(INTERFACE_NODE, &vrrp_ip6_cmd);
	install_element(INTERFACE_NODE, &vrrp_preempt_cmd);
}
