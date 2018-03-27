/*
 * IS-IS Rout(e)ing protocol - isis_circuit.h
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 * Copyright (C) 2016        David Lamparter, for NetDEF, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "command.h"
#include "spf_backoff.h"

#include "isis_circuit.h"
#include "isis_csm.h"
#include "isis_misc.h"
#include "isis_mt.h"
#include "isisd.h"

static struct isis_circuit *isis_circuit_lookup(struct vty *vty)
{
	struct interface *ifp = VTY_GET_CONTEXT(interface);
	struct isis_circuit *circuit;

	if (!ifp) {
		vty_out(vty, "Invalid interface \n");
		return NULL;
	}

	circuit = circuit_scan_by_ifp(ifp);
	if (!circuit) {
		vty_out(vty, "ISIS is not enabled on circuit %s\n", ifp->name);
		return NULL;
	}

	return circuit;
}

DEFUN (ip_router_isis,
       ip_router_isis_cmd,
       "ip router isis WORD",
       "Interface Internet Protocol config commands\n"
       "IP router interface commands\n"
       "IS-IS Routing for IP\n"
       "Routing process tag\n")
{
	int idx_afi = 0;
	int idx_word = 3;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct isis_circuit *circuit;
	struct isis_area *area;
	const char *af = argv[idx_afi]->arg;
	const char *area_tag = argv[idx_word]->arg;

	/* Prevent more than one area per circuit */
	circuit = circuit_scan_by_ifp(ifp);
	if (circuit && circuit->area) {
		if (strcmp(circuit->area->area_tag, area_tag)) {
			vty_out(vty, "ISIS circuit is already defined on %s\n",
				circuit->area->area_tag);
			return CMD_ERR_NOTHING_TODO;
		}
	}

	area = isis_area_lookup(area_tag);
	if (!area)
		area = isis_area_create(area_tag);

	if (!circuit || !circuit->area) {
		circuit = isis_circuit_create(area, ifp);

		if (circuit->state != C_STATE_CONF
		    && circuit->state != C_STATE_UP) {
			vty_out(vty,
				"Couldn't bring up interface, please check log.\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	bool ip = circuit->ip_router, ipv6 = circuit->ipv6_router;
	if (af[2] != '\0')
		ipv6 = true;
	else
		ip = true;

	isis_circuit_af_set(circuit, ip, ipv6);
	return CMD_SUCCESS;
}

DEFUN (ip6_router_isis,
       ip6_router_isis_cmd,
       "ipv6 router isis WORD",
       "Interface Internet Protocol config commands\n"
       "IP router interface commands\n"
       "IS-IS Routing for IP\n"
       "Routing process tag\n")
{
	return ip_router_isis(self, vty, argc, argv);
}

DEFUN (no_ip_router_isis,
       no_ip_router_isis_cmd,
       "no <ip|ipv6> router isis WORD",
       NO_STR
       "Interface Internet Protocol config commands\n"
       "IP router interface commands\n"
       "IP router interface commands\n"
       "IS-IS Routing for IP\n"
       "Routing process tag\n")
{
	int idx_afi = 1;
	int idx_word = 4;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct isis_area *area;
	struct isis_circuit *circuit;
	const char *af = argv[idx_afi]->arg;
	const char *area_tag = argv[idx_word]->arg;

	area = isis_area_lookup(area_tag);
	if (!area) {
		vty_out(vty, "Can't find ISIS instance %s\n",
			argv[idx_afi]->arg);
		return CMD_ERR_NO_MATCH;
	}

	circuit = circuit_lookup_by_ifp(ifp, area->circuit_list);
	if (!circuit) {
		vty_out(vty, "ISIS is not enabled on circuit %s\n", ifp->name);
		return CMD_ERR_NO_MATCH;
	}

	bool ip = circuit->ip_router, ipv6 = circuit->ipv6_router;
	if (af[2] != '\0')
		ipv6 = false;
	else
		ip = false;

	isis_circuit_af_set(circuit, ip, ipv6);
	return CMD_SUCCESS;
}

DEFUN (isis_passive,
       isis_passive_cmd,
       "isis passive",
       "IS-IS commands\n"
       "Configure the passive mode for interface\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	CMD_FERR_RETURN(isis_circuit_passive_set(circuit, 1),
			"Cannot set passive: $ERR");
	return CMD_SUCCESS;
}

DEFUN (no_isis_passive,
       no_isis_passive_cmd,
       "no isis passive",
       NO_STR
       "IS-IS commands\n"
       "Configure the passive mode for interface\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	CMD_FERR_RETURN(isis_circuit_passive_set(circuit, 0),
			"Cannot set no passive: $ERR");
	return CMD_SUCCESS;
}

DEFUN (isis_circuit_type,
       isis_circuit_type_cmd,
       "isis circuit-type <level-1|level-1-2|level-2-only>",
       "IS-IS commands\n"
       "Configure circuit type for interface\n"
       "Level-1 only adjacencies are formed\n"
       "Level-1-2 adjacencies are formed\n"
       "Level-2 only adjacencies are formed\n")
{
	int idx_level = 2;
	int is_type;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	is_type = string2circuit_t(argv[idx_level]->arg);
	if (!is_type) {
		vty_out(vty, "Unknown circuit-type \n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (circuit->state == C_STATE_UP
	    && circuit->area->is_type != IS_LEVEL_1_AND_2
	    && circuit->area->is_type != is_type) {
		vty_out(vty, "Invalid circuit level for area %s.\n",
			circuit->area->area_tag);
		return CMD_WARNING_CONFIG_FAILED;
	}
	isis_circuit_is_type_set(circuit, is_type);

	return CMD_SUCCESS;
}

DEFUN (no_isis_circuit_type,
       no_isis_circuit_type_cmd,
       "no isis circuit-type <level-1|level-1-2|level-2-only>",
       NO_STR
       "IS-IS commands\n"
       "Configure circuit type for interface\n"
       "Level-1 only adjacencies are formed\n"
       "Level-1-2 adjacencies are formed\n"
       "Level-2 only adjacencies are formed\n")
{
	int is_type;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	/*
	 * Set the circuits level to its default value
	 */
	if (circuit->state == C_STATE_UP)
		is_type = circuit->area->is_type;
	else
		is_type = IS_LEVEL_1_AND_2;
	isis_circuit_is_type_set(circuit, is_type);

	return CMD_SUCCESS;
}

DEFUN (isis_network,
       isis_network_cmd,
       "isis network point-to-point",
       "IS-IS commands\n"
       "Set network type\n"
       "point-to-point network type\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	if (isis_circuit_circ_type_set(circuit, CIRCUIT_T_P2P)) {
		vty_out(vty,
			"isis network point-to-point is valid only on broadcast interfaces\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (no_isis_network,
       no_isis_network_cmd,
       "no isis network point-to-point",
       NO_STR
       "IS-IS commands\n"
       "Set network type for circuit\n"
       "point-to-point network type\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	if (isis_circuit_circ_type_set(circuit, CIRCUIT_T_BROADCAST)) {
		vty_out(vty,
			"isis network point-to-point is valid only on broadcast interfaces\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (isis_passwd,
       isis_passwd_cmd,
       "isis password <md5|clear> WORD",
       "IS-IS commands\n"
       "Configure the authentication password for a circuit\n"
       "HMAC-MD5 authentication\n"
       "Cleartext password\n"
       "Circuit password\n")
{
	int idx_encryption = 2;
	int idx_word = 3;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	ferr_r rv;

	if (!circuit)
		return CMD_ERR_NO_MATCH;

	if (argv[idx_encryption]->arg[0] == 'm')
		rv = isis_circuit_passwd_hmac_md5_set(circuit,
						      argv[idx_word]->arg);
	else
		rv = isis_circuit_passwd_cleartext_set(circuit,
						       argv[idx_word]->arg);

	CMD_FERR_RETURN(rv, "Failed to set circuit password: $ERR");
	return CMD_SUCCESS;
}

DEFUN (no_isis_passwd,
       no_isis_passwd_cmd,
       "no isis password [<md5|clear> WORD]",
       NO_STR
       "IS-IS commands\n"
       "Configure the authentication password for a circuit\n"
       "HMAC-MD5 authentication\n"
       "Cleartext password\n"
       "Circuit password\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	CMD_FERR_RETURN(isis_circuit_passwd_unset(circuit),
			"Failed to unset circuit password: $ERR");
	return CMD_SUCCESS;
}


DEFUN (isis_priority,
       isis_priority_cmd,
       "isis priority (0-127)",
       "IS-IS commands\n"
       "Set priority for Designated Router election\n"
       "Priority value\n")
{
	int idx_number = 2;
	int prio;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	prio = atoi(argv[idx_number]->arg);
	if (prio < MIN_PRIORITY || prio > MAX_PRIORITY) {
		vty_out(vty, "Invalid priority %d - should be <0-127>\n", prio);
		return CMD_WARNING_CONFIG_FAILED;
	}

	circuit->priority[0] = prio;
	circuit->priority[1] = prio;

	return CMD_SUCCESS;
}

DEFUN (no_isis_priority,
       no_isis_priority_cmd,
       "no isis priority [(0-127)]",
       NO_STR
       "IS-IS commands\n"
       "Set priority for Designated Router election\n"
       "Priority value\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->priority[0] = DEFAULT_PRIORITY;
	circuit->priority[1] = DEFAULT_PRIORITY;

	return CMD_SUCCESS;
}


DEFUN (isis_priority_l1,
       isis_priority_l1_cmd,
       "isis priority (0-127) level-1",
       "IS-IS commands\n"
       "Set priority for Designated Router election\n"
       "Priority value\n"
       "Specify priority for level-1 routing\n")
{
	int idx_number = 2;
	int prio;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	prio = atoi(argv[idx_number]->arg);
	if (prio < MIN_PRIORITY || prio > MAX_PRIORITY) {
		vty_out(vty, "Invalid priority %d - should be <0-127>\n", prio);
		return CMD_WARNING_CONFIG_FAILED;
	}

	circuit->priority[0] = prio;

	return CMD_SUCCESS;
}

DEFUN (no_isis_priority_l1,
       no_isis_priority_l1_cmd,
       "no isis priority [(0-127)] level-1",
       NO_STR
       "IS-IS commands\n"
       "Set priority for Designated Router election\n"
       "Priority value\n"
       "Specify priority for level-1 routing\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->priority[0] = DEFAULT_PRIORITY;

	return CMD_SUCCESS;
}


DEFUN (isis_priority_l2,
       isis_priority_l2_cmd,
       "isis priority (0-127) level-2",
       "IS-IS commands\n"
       "Set priority for Designated Router election\n"
       "Priority value\n"
       "Specify priority for level-2 routing\n")
{
	int idx_number = 2;
	int prio;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	prio = atoi(argv[idx_number]->arg);
	if (prio < MIN_PRIORITY || prio > MAX_PRIORITY) {
		vty_out(vty, "Invalid priority %d - should be <0-127>\n", prio);
		return CMD_WARNING_CONFIG_FAILED;
	}

	circuit->priority[1] = prio;

	return CMD_SUCCESS;
}

DEFUN (no_isis_priority_l2,
       no_isis_priority_l2_cmd,
       "no isis priority [(0-127)] level-2",
       NO_STR
       "IS-IS commands\n"
       "Set priority for Designated Router election\n"
       "Priority value\n"
       "Specify priority for level-2 routing\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->priority[1] = DEFAULT_PRIORITY;

	return CMD_SUCCESS;
}


/* Metric command */
DEFUN (isis_metric,
       isis_metric_cmd,
       "isis metric (0-16777215)",
       "IS-IS commands\n"
       "Set default metric for circuit\n"
       "Default metric value\n")
{
	int idx_number = 2;
	int met;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	met = atoi(argv[idx_number]->arg);

	/* RFC3787 section 5.1 */
	if (circuit->area && circuit->area->oldmetric == 1
	    && met > MAX_NARROW_LINK_METRIC) {
		vty_out(vty,
			"Invalid metric %d - should be <0-63> "
			"when narrow metric type enabled\n",
			met);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* RFC4444 */
	if (circuit->area && circuit->area->newmetric == 1
	    && met > MAX_WIDE_LINK_METRIC) {
		vty_out(vty,
			"Invalid metric %d - should be <0-16777215> "
			"when wide metric type enabled\n",
			met);
		return CMD_WARNING_CONFIG_FAILED;
	}

	CMD_FERR_RETURN(isis_circuit_metric_set(circuit, IS_LEVEL_1, met),
			"Failed to set L1 metric: $ERR");
	CMD_FERR_RETURN(isis_circuit_metric_set(circuit, IS_LEVEL_2, met),
			"Failed to set L2 metric: $ERR");
	return CMD_SUCCESS;
}


DEFUN (no_isis_metric,
       no_isis_metric_cmd,
       "no isis metric [(0-16777215)]",
       NO_STR
       "IS-IS commands\n"
       "Set default metric for circuit\n"
       "Default metric value\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	CMD_FERR_RETURN(isis_circuit_metric_set(circuit, IS_LEVEL_1,
						DEFAULT_CIRCUIT_METRIC),
			"Failed to set L1 metric: $ERR");
	CMD_FERR_RETURN(isis_circuit_metric_set(circuit, IS_LEVEL_2,
						DEFAULT_CIRCUIT_METRIC),
			"Failed to set L2 metric: $ERR");
	return CMD_SUCCESS;
}


DEFUN (isis_metric_l1,
       isis_metric_l1_cmd,
       "isis metric (0-16777215) level-1",
       "IS-IS commands\n"
       "Set default metric for circuit\n"
       "Default metric value\n"
       "Specify metric for level-1 routing\n")
{
	int idx_number = 2;
	int met;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	met = atoi(argv[idx_number]->arg);
	CMD_FERR_RETURN(isis_circuit_metric_set(circuit, IS_LEVEL_1, met),
			"Failed to set L1 metric: $ERR");
	return CMD_SUCCESS;
}


DEFUN (no_isis_metric_l1,
       no_isis_metric_l1_cmd,
       "no isis metric [(0-16777215)] level-1",
       NO_STR
       "IS-IS commands\n"
       "Set default metric for circuit\n"
       "Default metric value\n"
       "Specify metric for level-1 routing\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	CMD_FERR_RETURN(isis_circuit_metric_set(circuit, IS_LEVEL_1,
						DEFAULT_CIRCUIT_METRIC),
			"Failed to set L1 metric: $ERR");
	return CMD_SUCCESS;
}


DEFUN (isis_metric_l2,
       isis_metric_l2_cmd,
       "isis metric (0-16777215) level-2",
       "IS-IS commands\n"
       "Set default metric for circuit\n"
       "Default metric value\n"
       "Specify metric for level-2 routing\n")
{
	int idx_number = 2;
	int met;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	met = atoi(argv[idx_number]->arg);
	CMD_FERR_RETURN(isis_circuit_metric_set(circuit, IS_LEVEL_2, met),
			"Failed to set L2 metric: $ERR");
	return CMD_SUCCESS;
}


DEFUN (no_isis_metric_l2,
       no_isis_metric_l2_cmd,
       "no isis metric [(0-16777215)] level-2",
       NO_STR
       "IS-IS commands\n"
       "Set default metric for circuit\n"
       "Default metric value\n"
       "Specify metric for level-2 routing\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	CMD_FERR_RETURN(isis_circuit_metric_set(circuit, IS_LEVEL_2,
						DEFAULT_CIRCUIT_METRIC),
			"Failed to set L2 metric: $ERR");
	return CMD_SUCCESS;
}

/* end of metrics */

DEFUN (isis_hello_interval,
       isis_hello_interval_cmd,
       "isis hello-interval (1-600)",
       "IS-IS commands\n"
       "Set Hello interval\n"
       "Holdtime 1 seconds, interval depends on multiplier\n")
{
	int idx_number = 2;
	int interval;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	interval = atoi(argv[idx_number]->arg);
	if (interval < MIN_HELLO_INTERVAL || interval > MAX_HELLO_INTERVAL) {
		vty_out(vty, "Invalid hello-interval %d - should be <1-600>\n",
			interval);
		return CMD_WARNING_CONFIG_FAILED;
	}

	circuit->hello_interval[0] = (uint16_t)interval;
	circuit->hello_interval[1] = (uint16_t)interval;

	return CMD_SUCCESS;
}


DEFUN (no_isis_hello_interval,
       no_isis_hello_interval_cmd,
       "no isis hello-interval [(1-600)]",
       NO_STR
       "IS-IS commands\n"
       "Set Hello interval\n"
       "Holdtime 1 second, interval depends on multiplier\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->hello_interval[0] = DEFAULT_HELLO_INTERVAL;
	circuit->hello_interval[1] = DEFAULT_HELLO_INTERVAL;

	return CMD_SUCCESS;
}


DEFUN (isis_hello_interval_l1,
       isis_hello_interval_l1_cmd,
       "isis hello-interval (1-600) level-1",
       "IS-IS commands\n"
       "Set Hello interval\n"
       "Holdtime 1 second, interval depends on multiplier\n"
       "Specify hello-interval for level-1 IIHs\n")
{
	int idx_number = 2;
	long interval;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	interval = atoi(argv[idx_number]->arg);
	if (interval < MIN_HELLO_INTERVAL || interval > MAX_HELLO_INTERVAL) {
		vty_out(vty, "Invalid hello-interval %ld - should be <1-600>\n",
			interval);
		return CMD_WARNING_CONFIG_FAILED;
	}

	circuit->hello_interval[0] = (uint16_t)interval;

	return CMD_SUCCESS;
}


DEFUN (no_isis_hello_interval_l1,
       no_isis_hello_interval_l1_cmd,
       "no isis hello-interval [(1-600)] level-1",
       NO_STR
       "IS-IS commands\n"
       "Set Hello interval\n"
       "Holdtime 1 second, interval depends on multiplier\n"
       "Specify hello-interval for level-1 IIHs\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->hello_interval[0] = DEFAULT_HELLO_INTERVAL;

	return CMD_SUCCESS;
}


DEFUN (isis_hello_interval_l2,
       isis_hello_interval_l2_cmd,
       "isis hello-interval (1-600) level-2",
       "IS-IS commands\n"
       "Set Hello interval\n"
       "Holdtime 1 second, interval depends on multiplier\n"
       "Specify hello-interval for level-2 IIHs\n")
{
	int idx_number = 2;
	long interval;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	interval = atoi(argv[idx_number]->arg);
	if (interval < MIN_HELLO_INTERVAL || interval > MAX_HELLO_INTERVAL) {
		vty_out(vty, "Invalid hello-interval %ld - should be <1-600>\n",
			interval);
		return CMD_WARNING_CONFIG_FAILED;
	}

	circuit->hello_interval[1] = (uint16_t)interval;

	return CMD_SUCCESS;
}


DEFUN (no_isis_hello_interval_l2,
       no_isis_hello_interval_l2_cmd,
       "no isis hello-interval [(1-600)] level-2",
       NO_STR
       "IS-IS commands\n"
       "Set Hello interval\n"
       "Holdtime 1 second, interval depends on multiplier\n"
       "Specify hello-interval for level-2 IIHs\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->hello_interval[1] = DEFAULT_HELLO_INTERVAL;

	return CMD_SUCCESS;
}


DEFUN (isis_hello_multiplier,
       isis_hello_multiplier_cmd,
       "isis hello-multiplier (2-100)",
       "IS-IS commands\n"
       "Set multiplier for Hello holding time\n"
       "Hello multiplier value\n")
{
	int idx_number = 2;
	int mult;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	mult = atoi(argv[idx_number]->arg);
	if (mult < MIN_HELLO_MULTIPLIER || mult > MAX_HELLO_MULTIPLIER) {
		vty_out(vty,
			"Invalid hello-multiplier %d - should be <2-100>\n",
			mult);
		return CMD_WARNING_CONFIG_FAILED;
	}

	circuit->hello_multiplier[0] = (uint16_t)mult;
	circuit->hello_multiplier[1] = (uint16_t)mult;

	return CMD_SUCCESS;
}


DEFUN (no_isis_hello_multiplier,
       no_isis_hello_multiplier_cmd,
       "no isis hello-multiplier [(2-100)]",
       NO_STR
       "IS-IS commands\n"
       "Set multiplier for Hello holding time\n"
       "Hello multiplier value\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->hello_multiplier[0] = DEFAULT_HELLO_MULTIPLIER;
	circuit->hello_multiplier[1] = DEFAULT_HELLO_MULTIPLIER;

	return CMD_SUCCESS;
}


DEFUN (isis_hello_multiplier_l1,
       isis_hello_multiplier_l1_cmd,
       "isis hello-multiplier (2-100) level-1",
       "IS-IS commands\n"
       "Set multiplier for Hello holding time\n"
       "Hello multiplier value\n"
       "Specify hello multiplier for level-1 IIHs\n")
{
	int idx_number = 2;
	int mult;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	mult = atoi(argv[idx_number]->arg);
	if (mult < MIN_HELLO_MULTIPLIER || mult > MAX_HELLO_MULTIPLIER) {
		vty_out(vty,
			"Invalid hello-multiplier %d - should be <2-100>\n",
			mult);
		return CMD_WARNING_CONFIG_FAILED;
	}

	circuit->hello_multiplier[0] = (uint16_t)mult;

	return CMD_SUCCESS;
}


DEFUN (no_isis_hello_multiplier_l1,
       no_isis_hello_multiplier_l1_cmd,
       "no isis hello-multiplier [(2-100)] level-1",
       NO_STR
       "IS-IS commands\n"
       "Set multiplier for Hello holding time\n"
       "Hello multiplier value\n"
       "Specify hello multiplier for level-1 IIHs\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->hello_multiplier[0] = DEFAULT_HELLO_MULTIPLIER;

	return CMD_SUCCESS;
}


DEFUN (isis_hello_multiplier_l2,
       isis_hello_multiplier_l2_cmd,
       "isis hello-multiplier (2-100) level-2",
       "IS-IS commands\n"
       "Set multiplier for Hello holding time\n"
       "Hello multiplier value\n"
       "Specify hello multiplier for level-2 IIHs\n")
{
	int idx_number = 2;
	int mult;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	mult = atoi(argv[idx_number]->arg);
	if (mult < MIN_HELLO_MULTIPLIER || mult > MAX_HELLO_MULTIPLIER) {
		vty_out(vty,
			"Invalid hello-multiplier %d - should be <2-100>\n",
			mult);
		return CMD_WARNING_CONFIG_FAILED;
	}

	circuit->hello_multiplier[1] = (uint16_t)mult;

	return CMD_SUCCESS;
}


DEFUN (no_isis_hello_multiplier_l2,
       no_isis_hello_multiplier_l2_cmd,
       "no isis hello-multiplier [(2-100)] level-2",
       NO_STR
       "IS-IS commands\n"
       "Set multiplier for Hello holding time\n"
       "Hello multiplier value\n"
       "Specify hello multiplier for level-2 IIHs\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->hello_multiplier[1] = DEFAULT_HELLO_MULTIPLIER;

	return CMD_SUCCESS;
}


DEFUN (isis_hello_padding,
       isis_hello_padding_cmd,
       "isis hello padding",
       "IS-IS commands\n"
       "Add padding to IS-IS hello packets\n"
       "Pad hello packets\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->pad_hellos = 1;

	return CMD_SUCCESS;
}

DEFUN (no_isis_hello_padding,
       no_isis_hello_padding_cmd,
       "no isis hello padding",
       NO_STR
       "IS-IS commands\n"
       "Add padding to IS-IS hello packets\n"
       "Pad hello packets\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->pad_hellos = 0;

	return CMD_SUCCESS;
}

DEFUN (isis_threeway_adj,
       isis_threeway_adj_cmd,
       "[no] isis three-way-handshake",
       NO_STR
       "IS-IS commands\n"
       "Enable/Disable three-way handshake\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->disable_threeway_adj = !strcmp(argv[0]->text, "no");
	return CMD_SUCCESS;
}

DEFUN (csnp_interval,
       csnp_interval_cmd,
       "isis csnp-interval (1-600)",
       "IS-IS commands\n"
       "Set CSNP interval in seconds\n"
       "CSNP interval value\n")
{
	int idx_number = 2;
	unsigned long interval;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	interval = atol(argv[idx_number]->arg);
	if (interval < MIN_CSNP_INTERVAL || interval > MAX_CSNP_INTERVAL) {
		vty_out(vty, "Invalid csnp-interval %lu - should be <1-600>\n",
			interval);
		return CMD_WARNING_CONFIG_FAILED;
	}

	circuit->csnp_interval[0] = (uint16_t)interval;
	circuit->csnp_interval[1] = (uint16_t)interval;

	return CMD_SUCCESS;
}


DEFUN (no_csnp_interval,
       no_csnp_interval_cmd,
       "no isis csnp-interval [(1-600)]",
       NO_STR
       "IS-IS commands\n"
       "Set CSNP interval in seconds\n"
       "CSNP interval value\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->csnp_interval[0] = DEFAULT_CSNP_INTERVAL;
	circuit->csnp_interval[1] = DEFAULT_CSNP_INTERVAL;

	return CMD_SUCCESS;
}


DEFUN (csnp_interval_l1,
       csnp_interval_l1_cmd,
       "isis csnp-interval (1-600) level-1",
       "IS-IS commands\n"
       "Set CSNP interval in seconds\n"
       "CSNP interval value\n"
       "Specify interval for level-1 CSNPs\n")
{
	int idx_number = 2;
	unsigned long interval;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	interval = atol(argv[idx_number]->arg);
	if (interval < MIN_CSNP_INTERVAL || interval > MAX_CSNP_INTERVAL) {
		vty_out(vty, "Invalid csnp-interval %lu - should be <1-600>\n",
			interval);
		return CMD_WARNING_CONFIG_FAILED;
	}

	circuit->csnp_interval[0] = (uint16_t)interval;

	return CMD_SUCCESS;
}


DEFUN (no_csnp_interval_l1,
       no_csnp_interval_l1_cmd,
       "no isis csnp-interval [(1-600)] level-1",
       NO_STR
       "IS-IS commands\n"
       "Set CSNP interval in seconds\n"
       "CSNP interval value\n"
       "Specify interval for level-1 CSNPs\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->csnp_interval[0] = DEFAULT_CSNP_INTERVAL;

	return CMD_SUCCESS;
}


DEFUN (csnp_interval_l2,
       csnp_interval_l2_cmd,
       "isis csnp-interval (1-600) level-2",
       "IS-IS commands\n"
       "Set CSNP interval in seconds\n"
       "CSNP interval value\n"
       "Specify interval for level-2 CSNPs\n")
{
	int idx_number = 2;
	unsigned long interval;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	interval = atol(argv[idx_number]->arg);
	if (interval < MIN_CSNP_INTERVAL || interval > MAX_CSNP_INTERVAL) {
		vty_out(vty, "Invalid csnp-interval %lu - should be <1-600>\n",
			interval);
		return CMD_WARNING_CONFIG_FAILED;
	}

	circuit->csnp_interval[1] = (uint16_t)interval;

	return CMD_SUCCESS;
}


DEFUN (no_csnp_interval_l2,
       no_csnp_interval_l2_cmd,
       "no isis csnp-interval [(1-600)] level-2",
       NO_STR
       "IS-IS commands\n"
       "Set CSNP interval in seconds\n"
       "CSNP interval value\n"
       "Specify interval for level-2 CSNPs\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->csnp_interval[1] = DEFAULT_CSNP_INTERVAL;

	return CMD_SUCCESS;
}


DEFUN (psnp_interval,
       psnp_interval_cmd,
       "isis psnp-interval (1-120)",
       "IS-IS commands\n"
       "Set PSNP interval in seconds\n"
       "PSNP interval value\n")
{
	int idx_number = 2;
	unsigned long interval;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	interval = atol(argv[idx_number]->arg);
	if (interval < MIN_PSNP_INTERVAL || interval > MAX_PSNP_INTERVAL) {
		vty_out(vty, "Invalid psnp-interval %lu - should be <1-120>\n",
			interval);
		return CMD_WARNING_CONFIG_FAILED;
	}

	circuit->psnp_interval[0] = (uint16_t)interval;
	circuit->psnp_interval[1] = (uint16_t)interval;

	return CMD_SUCCESS;
}


DEFUN (no_psnp_interval,
       no_psnp_interval_cmd,
       "no isis psnp-interval [(1-120)]",
       NO_STR
       "IS-IS commands\n"
       "Set PSNP interval in seconds\n"
       "PSNP interval value\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->psnp_interval[0] = DEFAULT_PSNP_INTERVAL;
	circuit->psnp_interval[1] = DEFAULT_PSNP_INTERVAL;

	return CMD_SUCCESS;
}


DEFUN (psnp_interval_l1,
       psnp_interval_l1_cmd,
       "isis psnp-interval (1-120) level-1",
       "IS-IS commands\n"
       "Set PSNP interval in seconds\n"
       "PSNP interval value\n"
       "Specify interval for level-1 PSNPs\n")
{
	int idx_number = 2;
	unsigned long interval;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	interval = atol(argv[idx_number]->arg);
	if (interval < MIN_PSNP_INTERVAL || interval > MAX_PSNP_INTERVAL) {
		vty_out(vty, "Invalid psnp-interval %lu - should be <1-120>\n",
			interval);
		return CMD_WARNING_CONFIG_FAILED;
	}

	circuit->psnp_interval[0] = (uint16_t)interval;

	return CMD_SUCCESS;
}


DEFUN (no_psnp_interval_l1,
       no_psnp_interval_l1_cmd,
       "no isis psnp-interval [(1-120)] level-1",
       NO_STR
       "IS-IS commands\n"
       "Set PSNP interval in seconds\n"
       "PSNP interval value\n"
       "Specify interval for level-1 PSNPs\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->psnp_interval[0] = DEFAULT_PSNP_INTERVAL;

	return CMD_SUCCESS;
}


DEFUN (psnp_interval_l2,
       psnp_interval_l2_cmd,
       "isis psnp-interval (1-120) level-2",
       "IS-IS commands\n"
       "Set PSNP interval in seconds\n"
       "PSNP interval value\n"
       "Specify interval for level-2 PSNPs\n")
{
	int idx_number = 2;
	unsigned long interval;
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	interval = atol(argv[idx_number]->arg);
	if (interval < MIN_PSNP_INTERVAL || interval > MAX_PSNP_INTERVAL) {
		vty_out(vty, "Invalid psnp-interval %lu - should be <1-120>\n",
			interval);
		return CMD_WARNING_CONFIG_FAILED;
	}

	circuit->psnp_interval[1] = (uint16_t)interval;

	return CMD_SUCCESS;
}


DEFUN (no_psnp_interval_l2,
       no_psnp_interval_l2_cmd,
       "no isis psnp-interval [(1-120)] level-2",
       NO_STR
       "IS-IS commands\n"
       "Set PSNP interval in seconds\n"
       "PSNP interval value\n"
       "Specify interval for level-2 PSNPs\n")
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;

	circuit->psnp_interval[1] = DEFAULT_PSNP_INTERVAL;

	return CMD_SUCCESS;
}

DEFUN (circuit_topology,
       circuit_topology_cmd,
       "isis topology " ISIS_MT_NAMES,
       "IS-IS commands\n"
       "Configure interface IS-IS topologies\n"
       ISIS_MT_DESCRIPTIONS)
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;
	const char *arg = argv[2]->arg;
	uint16_t mtid = isis_str2mtid(arg);

	if (circuit->area && circuit->area->oldmetric) {
		vty_out(vty,
			"Multi topology IS-IS can only be used with wide metrics\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (mtid == (uint16_t)-1) {
		vty_out(vty, "Don't know topology '%s'\n", arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return isis_circuit_mt_enabled_set(circuit, mtid, true);
}

DEFUN (no_circuit_topology,
       no_circuit_topology_cmd,
       "no isis topology " ISIS_MT_NAMES,
       NO_STR
       "IS-IS commands\n"
       "Configure interface IS-IS topologies\n"
       ISIS_MT_DESCRIPTIONS)
{
	struct isis_circuit *circuit = isis_circuit_lookup(vty);
	if (!circuit)
		return CMD_ERR_NO_MATCH;
	const char *arg = argv[3]->arg;
	uint16_t mtid = isis_str2mtid(arg);

	if (circuit->area && circuit->area->oldmetric) {
		vty_out(vty,
			"Multi topology IS-IS can only be used with wide metrics\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (mtid == (uint16_t)-1) {
		vty_out(vty, "Don't know topology '%s'\n", arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return isis_circuit_mt_enabled_set(circuit, mtid, false);
}

static int validate_metric_style_narrow(struct vty *vty, struct isis_area *area)
{
	struct isis_circuit *circuit;
	struct listnode *node;

	if (!vty)
		return CMD_WARNING_CONFIG_FAILED;

	if (!area) {
		vty_out(vty, "ISIS area is invalid\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit)) {
		if ((area->is_type & IS_LEVEL_1)
		    && (circuit->is_type & IS_LEVEL_1)
		    && (circuit->te_metric[0] > MAX_NARROW_LINK_METRIC)) {
			vty_out(vty, "ISIS circuit %s metric is invalid\n",
				circuit->interface->name);
			return CMD_WARNING_CONFIG_FAILED;
		}
		if ((area->is_type & IS_LEVEL_2)
		    && (circuit->is_type & IS_LEVEL_2)
		    && (circuit->te_metric[1] > MAX_NARROW_LINK_METRIC)) {
			vty_out(vty, "ISIS circuit %s metric is invalid\n",
				circuit->interface->name);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	return CMD_SUCCESS;
}

DEFUN (metric_style,
       metric_style_cmd,
       "metric-style <narrow|transition|wide>",
       "Use old-style (ISO 10589) or new-style packet formats\n"
       "Use old style of TLVs with narrow metric\n"
       "Send and accept both styles of TLVs during transition\n"
       "Use new style of TLVs to carry wider metric\n")
{
	int idx_metric_style = 1;
	VTY_DECLVAR_CONTEXT(isis_area, area);
	int ret;

	if (strncmp(argv[idx_metric_style]->arg, "w", 1) == 0) {
		isis_area_metricstyle_set(area, false, true);
		return CMD_SUCCESS;
	}

	if (area_is_mt(area)) {
		vty_out(vty,
			"Narrow metrics cannot be used while multi topology IS-IS is active\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = validate_metric_style_narrow(vty, area);
	if (ret != CMD_SUCCESS)
		return ret;

	if (strncmp(argv[idx_metric_style]->arg, "t", 1) == 0)
		isis_area_metricstyle_set(area, true, true);
	else if (strncmp(argv[idx_metric_style]->arg, "n", 1) == 0)
		isis_area_metricstyle_set(area, true, false);
	return CMD_SUCCESS;

	return CMD_SUCCESS;
}

DEFUN (no_metric_style,
       no_metric_style_cmd,
       "no metric-style",
       NO_STR
       "Use old-style (ISO 10589) or new-style packet formats\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);
	int ret;

	if (area_is_mt(area)) {
		vty_out(vty,
			"Narrow metrics cannot be used while multi topology IS-IS is active\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = validate_metric_style_narrow(vty, area);
	if (ret != CMD_SUCCESS)
		return ret;

	isis_area_metricstyle_set(area, true, false);
	return CMD_SUCCESS;
}

DEFUN (set_overload_bit,
       set_overload_bit_cmd,
       "set-overload-bit",
       "Set overload bit to avoid any transit traffic\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	isis_area_overload_bit_set(area, true);
	return CMD_SUCCESS;
}

DEFUN (no_set_overload_bit,
       no_set_overload_bit_cmd,
       "no set-overload-bit",
       "Reset overload bit to accept transit traffic\n"
       "Reset overload bit\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	isis_area_overload_bit_set(area, false);
	return CMD_SUCCESS;
}

DEFUN (set_attached_bit,
       set_attached_bit_cmd,
       "set-attached-bit",
       "Set attached bit to identify as L1/L2 router for inter-area traffic\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	isis_area_attached_bit_set(area, true);
	return CMD_SUCCESS;
}

DEFUN (no_set_attached_bit,
       no_set_attached_bit_cmd,
       "no set-attached-bit",
       NO_STR
       "Reset attached bit\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	isis_area_attached_bit_set(area, false);
	return CMD_SUCCESS;
}

DEFUN (dynamic_hostname,
       dynamic_hostname_cmd,
       "hostname dynamic",
       "Dynamic hostname for IS-IS\n"
       "Dynamic hostname\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	isis_area_dynhostname_set(area, true);
	return CMD_SUCCESS;
}

DEFUN (no_dynamic_hostname,
       no_dynamic_hostname_cmd,
       "no hostname dynamic",
       NO_STR
       "Dynamic hostname for IS-IS\n"
       "Dynamic hostname\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	isis_area_dynhostname_set(area, false);
	return CMD_SUCCESS;
}

static int area_lsp_mtu_set(struct vty *vty, unsigned int lsp_mtu)
{
	VTY_DECLVAR_CONTEXT(isis_area, area);
	struct listnode *node;
	struct isis_circuit *circuit;

	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit)) {
		if (circuit->state != C_STATE_INIT
		    && circuit->state != C_STATE_UP)
			continue;
		if (lsp_mtu > isis_circuit_pdu_size(circuit)) {
			vty_out(vty,
				"ISIS area contains circuit %s, which has a maximum PDU size of %zu.\n",
				circuit->interface->name,
				isis_circuit_pdu_size(circuit));
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	isis_area_lsp_mtu_set(area, lsp_mtu);
	return CMD_SUCCESS;
}

DEFUN (area_lsp_mtu,
       area_lsp_mtu_cmd,
       "lsp-mtu (128-4352)",
       "Configure the maximum size of generated LSPs\n"
       "Maximum size of generated LSPs\n")
{
	int idx_number = 1;
	unsigned int lsp_mtu;

	lsp_mtu = strtoul(argv[idx_number]->arg, NULL, 10);

	return area_lsp_mtu_set(vty, lsp_mtu);
}


DEFUN (no_area_lsp_mtu,
       no_area_lsp_mtu_cmd,
       "no lsp-mtu [(128-4352)]",
       NO_STR
       "Configure the maximum size of generated LSPs\n"
       "Maximum size of generated LSPs\n")
{
	return area_lsp_mtu_set(vty, DEFAULT_LSP_MTU);
}


DEFUN (is_type,
       is_type_cmd,
       "is-type <level-1|level-1-2|level-2-only>",
       "IS Level for this routing process (OSI only)\n"
       "Act as a station router only\n"
       "Act as both a station router and an area router\n"
       "Act as an area router only\n")
{
	int idx_level = 1;
	VTY_DECLVAR_CONTEXT(isis_area, area);
	int type;

	type = string2circuit_t(argv[idx_level]->arg);
	if (!type) {
		vty_out(vty, "Unknown IS level \n");
		return CMD_SUCCESS;
	}

	isis_area_is_type_set(area, type);

	return CMD_SUCCESS;
}

DEFUN (no_is_type,
       no_is_type_cmd,
       "no is-type <level-1|level-1-2|level-2-only>",
       NO_STR
       "IS Level for this routing process (OSI only)\n"
       "Act as a station router only\n"
       "Act as both a station router and an area router\n"
       "Act as an area router only\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);
	int type;

	/*
	 * Put the is-type back to defaults:
	 * - level-1-2 on first area
	 * - level-1 for the rest
	 */
	if (listgetdata(listhead(isis->area_list)) == area)
		type = IS_LEVEL_1_AND_2;
	else
		type = IS_LEVEL_1;

	isis_area_is_type_set(area, type);

	return CMD_SUCCESS;
}

static int set_lsp_gen_interval(struct vty *vty, struct isis_area *area,
				uint16_t interval, int level)
{
	int lvl;

	for (lvl = IS_LEVEL_1; lvl <= IS_LEVEL_2; ++lvl) {
		if (!(lvl & level))
			continue;

		if (interval >= area->lsp_refresh[lvl - 1]) {
			vty_out(vty,
				"LSP gen interval %us must be less than "
				"the LSP refresh interval %us\n",
				interval, area->lsp_refresh[lvl - 1]);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	for (lvl = IS_LEVEL_1; lvl <= IS_LEVEL_2; ++lvl) {
		if (!(lvl & level))
			continue;
		area->lsp_gen_interval[lvl - 1] = interval;
	}

	return CMD_SUCCESS;
}

DEFUN (lsp_gen_interval,
       lsp_gen_interval_cmd,
       "lsp-gen-interval [<level-1|level-2>] (1-120)",
       "Minimum interval between regenerating same LSP\n"
       "Set interval for level 1 only\n"
       "Set interval for level 2 only\n"
       "Minimum interval in seconds\n")
{
	int idx = 0;
	VTY_DECLVAR_CONTEXT(isis_area, area);
	uint16_t interval;
	int level;

	level = 0;
	level |= argv_find(argv, argc, "level-1", &idx) ? IS_LEVEL_1 : 0;
	level |= argv_find(argv, argc, "level-2", &idx) ? IS_LEVEL_2 : 0;
	if (!level)
		level = IS_LEVEL_1 | IS_LEVEL_2;

	argv_find(argv, argc, "(1-120)", &idx);

	interval = atoi(argv[idx]->arg);
	return set_lsp_gen_interval(vty, area, interval, level);
}

DEFUN (no_lsp_gen_interval,
       no_lsp_gen_interval_cmd,
       "no lsp-gen-interval [<level-1|level-2>] [(1-120)]",
       NO_STR
       "Minimum interval between regenerating same LSP\n"
       "Set interval for level 1 only\n"
       "Set interval for level 2 only\n"
       "Minimum interval in seconds\n")
{
	int idx = 0;
	VTY_DECLVAR_CONTEXT(isis_area, area);
	uint16_t interval;
	int level;

	level = 0;
	level |= argv_find(argv, argc, "level-1", &idx) ? IS_LEVEL_1 : 0;
	level |= argv_find(argv, argc, "level-2", &idx) ? IS_LEVEL_2 : 0;
	if (!level)
		level = IS_LEVEL_1 | IS_LEVEL_2;

	interval = DEFAULT_MIN_LSP_GEN_INTERVAL;
	return set_lsp_gen_interval(vty, area, interval, level);
}

DEFUN (spf_interval,
       spf_interval_cmd,
       "spf-interval (1-120)",
       "Minimum interval between SPF calculations\n"
       "Minimum interval between consecutive SPFs in seconds\n")
{
	int idx_number = 1;
	VTY_DECLVAR_CONTEXT(isis_area, area);
	uint16_t interval;

	interval = atoi(argv[idx_number]->arg);
	area->min_spf_interval[0] = interval;
	area->min_spf_interval[1] = interval;

	return CMD_SUCCESS;
}


DEFUN (no_spf_interval,
       no_spf_interval_cmd,
       "no spf-interval [[<level-1|level-2>] (1-120)]",
       NO_STR
       "Minimum interval between SPF calculations\n"
       "Set interval for level 1 only\n"
       "Set interval for level 2 only\n"
       "Minimum interval between consecutive SPFs in seconds\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	area->min_spf_interval[0] = MINIMUM_SPF_INTERVAL;
	area->min_spf_interval[1] = MINIMUM_SPF_INTERVAL;

	return CMD_SUCCESS;
}


DEFUN (spf_interval_l1,
       spf_interval_l1_cmd,
       "spf-interval level-1 (1-120)",
       "Minimum interval between SPF calculations\n"
       "Set interval for level 1 only\n"
       "Minimum interval between consecutive SPFs in seconds\n")
{
	int idx_number = 2;
	VTY_DECLVAR_CONTEXT(isis_area, area);
	uint16_t interval;

	interval = atoi(argv[idx_number]->arg);
	area->min_spf_interval[0] = interval;

	return CMD_SUCCESS;
}

DEFUN (no_spf_interval_l1,
       no_spf_interval_l1_cmd,
       "no spf-interval level-1",
       NO_STR
       "Minimum interval between SPF calculations\n"
       "Set interval for level 1 only\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	area->min_spf_interval[0] = MINIMUM_SPF_INTERVAL;

	return CMD_SUCCESS;
}


DEFUN (spf_interval_l2,
       spf_interval_l2_cmd,
       "spf-interval level-2 (1-120)",
       "Minimum interval between SPF calculations\n"
       "Set interval for level 2 only\n"
       "Minimum interval between consecutive SPFs in seconds\n")
{
	int idx_number = 2;
	VTY_DECLVAR_CONTEXT(isis_area, area);
	uint16_t interval;

	interval = atoi(argv[idx_number]->arg);
	area->min_spf_interval[1] = interval;

	return CMD_SUCCESS;
}

DEFUN (no_spf_interval_l2,
       no_spf_interval_l2_cmd,
       "no spf-interval level-2",
       NO_STR
       "Minimum interval between SPF calculations\n"
       "Set interval for level 2 only\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	area->min_spf_interval[1] = MINIMUM_SPF_INTERVAL;

	return CMD_SUCCESS;
}

DEFUN (no_spf_delay_ietf,
       no_spf_delay_ietf_cmd,
       "no spf-delay-ietf",
       NO_STR
       "IETF SPF delay algorithm\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	spf_backoff_free(area->spf_delay_ietf[0]);
	spf_backoff_free(area->spf_delay_ietf[1]);
	area->spf_delay_ietf[0] = NULL;
	area->spf_delay_ietf[1] = NULL;

	return CMD_SUCCESS;
}

DEFUN (spf_delay_ietf,
       spf_delay_ietf_cmd,
       "spf-delay-ietf init-delay (0-60000) short-delay (0-60000) long-delay (0-60000) holddown (0-60000) time-to-learn (0-60000)",
       "IETF SPF delay algorithm\n"
       "Delay used while in QUIET state\n"
       "Delay used while in QUIET state in milliseconds\n"
       "Delay used while in SHORT_WAIT state\n"
       "Delay used while in SHORT_WAIT state in milliseconds\n"
       "Delay used while in LONG_WAIT\n"
       "Delay used while in LONG_WAIT state in milliseconds\n"
       "Time with no received IGP events before considering IGP stable\n"
       "Time with no received IGP events before considering IGP stable (in milliseconds)\n"
       "Maximum duration needed to learn all the events related to a single failure\n"
       "Maximum duration needed to learn all the events related to a single failure (in milliseconds)\n")
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	long init_delay = atol(argv[2]->arg);
	long short_delay = atol(argv[4]->arg);
	long long_delay = atol(argv[6]->arg);
	long holddown = atol(argv[8]->arg);
	long timetolearn = atol(argv[10]->arg);

	size_t bufsiz = strlen(area->area_tag) + sizeof("IS-IS  Lx");
	char *buf = XCALLOC(MTYPE_TMP, bufsiz);

	snprintf(buf, bufsiz, "IS-IS %s L1", area->area_tag);
	spf_backoff_free(area->spf_delay_ietf[0]);
	area->spf_delay_ietf[0] =
		spf_backoff_new(master, buf, init_delay, short_delay,
				long_delay, holddown, timetolearn);

	snprintf(buf, bufsiz, "IS-IS %s L2", area->area_tag);
	spf_backoff_free(area->spf_delay_ietf[1]);
	area->spf_delay_ietf[1] =
		spf_backoff_new(master, buf, init_delay, short_delay,
				long_delay, holddown, timetolearn);

	XFREE(MTYPE_TMP, buf);
	return CMD_SUCCESS;
}

static int area_max_lsp_lifetime_set(struct vty *vty, int level,
				     uint16_t interval)
{
	VTY_DECLVAR_CONTEXT(isis_area, area);
	int lvl;
	uint16_t refresh_interval = interval - 300;
	int set_refresh_interval[ISIS_LEVELS] = {0, 0};

	for (lvl = IS_LEVEL_1; lvl <= IS_LEVEL_2; lvl++) {
		if (!(lvl & level))
			continue;

		if (refresh_interval < area->lsp_refresh[lvl - 1]) {
			vty_out(vty,
				"Level %d Max LSP lifetime %us must be 300s greater than "
				"the configured LSP refresh interval %us\n",
				lvl, interval, area->lsp_refresh[lvl - 1]);
			vty_out(vty,
				"Automatically reducing level %d LSP refresh interval "
				"to %us\n",
				lvl, refresh_interval);
			set_refresh_interval[lvl - 1] = 1;

			if (refresh_interval
			    <= area->lsp_gen_interval[lvl - 1]) {
				vty_out(vty,
					"LSP refresh interval %us must be greater than "
					"the configured LSP gen interval %us\n",
					refresh_interval,
					area->lsp_gen_interval[lvl - 1]);
				return CMD_WARNING_CONFIG_FAILED;
			}
		}
	}

	for (lvl = IS_LEVEL_1; lvl <= IS_LEVEL_2; lvl++) {
		if (!(lvl & level))
			continue;
		isis_area_max_lsp_lifetime_set(area, lvl, interval);
		if (set_refresh_interval[lvl - 1])
			isis_area_lsp_refresh_set(area, lvl, refresh_interval);
	}

	return CMD_SUCCESS;
}

DEFUN (max_lsp_lifetime,
       max_lsp_lifetime_cmd,
       "max-lsp-lifetime [<level-1|level-2>] (350-65535)",
       "Maximum LSP lifetime\n"
       "Maximum LSP lifetime for Level 1 only\n"
       "Maximum LSP lifetime for Level 2 only\n"
       "LSP lifetime in seconds\n")
{
	int idx = 0;
	unsigned int level = IS_LEVEL_1_AND_2;

	if (argv_find(argv, argc, "level-1", &idx))
		level = IS_LEVEL_1;
	else if (argv_find(argv, argc, "level-2", &idx))
		level = IS_LEVEL_2;

	argv_find(argv, argc, "(350-65535)", &idx);
	int lifetime = atoi(argv[idx]->arg);

	return area_max_lsp_lifetime_set(vty, level, lifetime);
}


DEFUN (no_max_lsp_lifetime,
       no_max_lsp_lifetime_cmd,
       "no max-lsp-lifetime [<level-1|level-2>] [(350-65535)]",
       NO_STR
       "Maximum LSP lifetime\n"
       "Maximum LSP lifetime for Level 1 only\n"
       "Maximum LSP lifetime for Level 2 only\n"
       "LSP lifetime in seconds\n")
{
	int idx = 0;
	unsigned int level = IS_LEVEL_1_AND_2;

	if (argv_find(argv, argc, "level-1", &idx))
		level = IS_LEVEL_1;
	else if (argv_find(argv, argc, "level-2", &idx))
		level = IS_LEVEL_2;

	return area_max_lsp_lifetime_set(vty, level, DEFAULT_LSP_LIFETIME);
}

static int area_lsp_refresh_interval_set(struct vty *vty, int level,
					 uint16_t interval)
{
	VTY_DECLVAR_CONTEXT(isis_area, area);
	int lvl;

	for (lvl = IS_LEVEL_1; lvl <= IS_LEVEL_2; ++lvl) {
		if (!(lvl & level))
			continue;
		if (interval <= area->lsp_gen_interval[lvl - 1]) {
			vty_out(vty,
				"LSP refresh interval %us must be greater than "
				"the configured LSP gen interval %us\n",
				interval, area->lsp_gen_interval[lvl - 1]);
			return CMD_WARNING_CONFIG_FAILED;
		}
		if (interval > (area->max_lsp_lifetime[lvl - 1] - 300)) {
			vty_out(vty,
				"LSP refresh interval %us must be less than "
				"the configured LSP lifetime %us less 300\n",
				interval, area->max_lsp_lifetime[lvl - 1]);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	for (lvl = IS_LEVEL_1; lvl <= IS_LEVEL_2; ++lvl) {
		if (!(lvl & level))
			continue;
		isis_area_lsp_refresh_set(area, lvl, interval);
	}

	return CMD_SUCCESS;
}

DEFUN (lsp_refresh_interval,
       lsp_refresh_interval_cmd,
       "lsp-refresh-interval [<level-1|level-2>] (1-65235)",
       "LSP refresh interval\n"
       "LSP refresh interval for Level 1 only\n"
       "LSP refresh interval for Level 2 only\n"
       "LSP refresh interval in seconds\n")
{
	int idx = 0;
	unsigned int level = IS_LEVEL_1_AND_2;
	unsigned int interval = 0;

	if (argv_find(argv, argc, "level-1", &idx))
		level = IS_LEVEL_1;
	else if (argv_find(argv, argc, "level-2", &idx))
		level = IS_LEVEL_2;

	interval = atoi(argv[argc - 1]->arg);
	return area_lsp_refresh_interval_set(vty, level, interval);
}

DEFUN (no_lsp_refresh_interval,
       no_lsp_refresh_interval_cmd,
       "no lsp-refresh-interval [<level-1|level-2>] [(1-65235)]",
       NO_STR
       "LSP refresh interval\n"
       "LSP refresh interval for Level 1 only\n"
       "LSP refresh interval for Level 2 only\n"
       "LSP refresh interval in seconds\n")
{
	int idx = 0;
	unsigned int level = IS_LEVEL_1_AND_2;

	if (argv_find(argv, argc, "level-1", &idx))
		level = IS_LEVEL_1;
	else if (argv_find(argv, argc, "level-2", &idx))
		level = IS_LEVEL_2;

	return area_lsp_refresh_interval_set(vty, level,
					     DEFAULT_MAX_LSP_GEN_INTERVAL);
}

static int area_passwd_set(struct vty *vty, int level,
			   int (*type_set)(struct isis_area *area, int level,
					   const char *passwd,
					   uint8_t snp_auth),
			   const char *passwd, uint8_t snp_auth)
{
	VTY_DECLVAR_CONTEXT(isis_area, area);

	if (passwd && strlen(passwd) > 254) {
		vty_out(vty, "Too long area password (>254)\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	type_set(area, level, passwd, snp_auth);
	return CMD_SUCCESS;
}


DEFUN (area_passwd_md5,
       area_passwd_md5_cmd,
       "area-password md5 WORD [authenticate snp <send-only|validate>]",
       "Configure the authentication password for an area\n"
       "Authentication type\n"
       "Level-wide password\n"
       "Authentication\n"
       "SNP PDUs\n"
       "Send but do not check PDUs on receiving\n"
       "Send and check PDUs on receiving\n")
{
	int idx_password = 0;
	int idx_word = 2;
	int idx_type = 5;
	uint8_t snp_auth = 0;
	int level = strmatch(argv[idx_password]->text, "domain-password")
			    ? IS_LEVEL_2
			    : IS_LEVEL_1;

	if (argc > 3) {
		snp_auth = SNP_AUTH_SEND;
		if (strmatch(argv[idx_type]->text, "validate"))
			snp_auth |= SNP_AUTH_RECV;
	}

	return area_passwd_set(vty, level, isis_area_passwd_hmac_md5_set,
			       argv[idx_word]->arg, snp_auth);
}

DEFUN (domain_passwd_md5,
       domain_passwd_md5_cmd,
       "domain-password md5 WORD [authenticate snp <send-only|validate>]",
       "Set the authentication password for a routing domain\n"
       "Authentication type\n"
       "Level-wide password\n"
       "Authentication\n"
       "SNP PDUs\n"
       "Send but do not check PDUs on receiving\n"
       "Send and check PDUs on receiving\n")
{
	return area_passwd_md5(self, vty, argc, argv);
}

DEFUN (area_passwd_clear,
       area_passwd_clear_cmd,
       "area-password clear WORD [authenticate snp <send-only|validate>]",
       "Configure the authentication password for an area\n"
       "Authentication type\n"
       "Area password\n"
       "Authentication\n"
       "SNP PDUs\n"
       "Send but do not check PDUs on receiving\n"
       "Send and check PDUs on receiving\n")
{
	int idx_password = 0;
	int idx_word = 2;
	int idx_type = 5;
	uint8_t snp_auth = 0;
	int level = strmatch(argv[idx_password]->text, "domain-password")
			    ? IS_LEVEL_2
			    : IS_LEVEL_1;

	if (argc > 3) {
		snp_auth = SNP_AUTH_SEND;
		if (strmatch(argv[idx_type]->text, "validate"))
			snp_auth |= SNP_AUTH_RECV;
	}

	return area_passwd_set(vty, level, isis_area_passwd_cleartext_set,
			       argv[idx_word]->arg, snp_auth);
}

DEFUN (domain_passwd_clear,
       domain_passwd_clear_cmd,
       "domain-password clear WORD [authenticate snp <send-only|validate>]",
       "Set the authentication password for a routing domain\n"
       "Authentication type\n"
       "Area password\n"
       "Authentication\n"
       "SNP PDUs\n"
       "Send but do not check PDUs on receiving\n"
       "Send and check PDUs on receiving\n")
{
	return area_passwd_clear(self, vty, argc, argv);
}

DEFUN (no_area_passwd,
       no_area_passwd_cmd,
       "no <area-password|domain-password>",
       NO_STR
       "Configure the authentication password for an area\n"
       "Set the authentication password for a routing domain\n")
{
	int idx_password = 1;
	int level = strmatch(argv[idx_password]->text, "domain-password")
			    ? IS_LEVEL_2
			    : IS_LEVEL_1;
	VTY_DECLVAR_CONTEXT(isis_area, area);

	return isis_area_passwd_unset(area, level);
}

void isis_vty_init(void)
{
	install_element(INTERFACE_NODE, &ip_router_isis_cmd);
	install_element(INTERFACE_NODE, &ip6_router_isis_cmd);
	install_element(INTERFACE_NODE, &no_ip_router_isis_cmd);

	install_element(INTERFACE_NODE, &isis_passive_cmd);
	install_element(INTERFACE_NODE, &no_isis_passive_cmd);

	install_element(INTERFACE_NODE, &isis_circuit_type_cmd);
	install_element(INTERFACE_NODE, &no_isis_circuit_type_cmd);

	install_element(INTERFACE_NODE, &isis_network_cmd);
	install_element(INTERFACE_NODE, &no_isis_network_cmd);

	install_element(INTERFACE_NODE, &isis_passwd_cmd);
	install_element(INTERFACE_NODE, &no_isis_passwd_cmd);

	install_element(INTERFACE_NODE, &isis_priority_cmd);
	install_element(INTERFACE_NODE, &no_isis_priority_cmd);
	install_element(INTERFACE_NODE, &isis_priority_l1_cmd);
	install_element(INTERFACE_NODE, &no_isis_priority_l1_cmd);
	install_element(INTERFACE_NODE, &isis_priority_l2_cmd);
	install_element(INTERFACE_NODE, &no_isis_priority_l2_cmd);

	install_element(INTERFACE_NODE, &isis_metric_cmd);
	install_element(INTERFACE_NODE, &no_isis_metric_cmd);
	install_element(INTERFACE_NODE, &isis_metric_l1_cmd);
	install_element(INTERFACE_NODE, &no_isis_metric_l1_cmd);
	install_element(INTERFACE_NODE, &isis_metric_l2_cmd);
	install_element(INTERFACE_NODE, &no_isis_metric_l2_cmd);

	install_element(INTERFACE_NODE, &isis_hello_interval_cmd);
	install_element(INTERFACE_NODE, &no_isis_hello_interval_cmd);
	install_element(INTERFACE_NODE, &isis_hello_interval_l1_cmd);
	install_element(INTERFACE_NODE, &no_isis_hello_interval_l1_cmd);
	install_element(INTERFACE_NODE, &isis_hello_interval_l2_cmd);
	install_element(INTERFACE_NODE, &no_isis_hello_interval_l2_cmd);

	install_element(INTERFACE_NODE, &isis_hello_multiplier_cmd);
	install_element(INTERFACE_NODE, &no_isis_hello_multiplier_cmd);
	install_element(INTERFACE_NODE, &isis_hello_multiplier_l1_cmd);
	install_element(INTERFACE_NODE, &no_isis_hello_multiplier_l1_cmd);
	install_element(INTERFACE_NODE, &isis_hello_multiplier_l2_cmd);
	install_element(INTERFACE_NODE, &no_isis_hello_multiplier_l2_cmd);

	install_element(INTERFACE_NODE, &isis_hello_padding_cmd);
	install_element(INTERFACE_NODE, &no_isis_hello_padding_cmd);

	install_element(INTERFACE_NODE, &isis_threeway_adj_cmd);

	install_element(INTERFACE_NODE, &csnp_interval_cmd);
	install_element(INTERFACE_NODE, &no_csnp_interval_cmd);
	install_element(INTERFACE_NODE, &csnp_interval_l1_cmd);
	install_element(INTERFACE_NODE, &no_csnp_interval_l1_cmd);
	install_element(INTERFACE_NODE, &csnp_interval_l2_cmd);
	install_element(INTERFACE_NODE, &no_csnp_interval_l2_cmd);

	install_element(INTERFACE_NODE, &psnp_interval_cmd);
	install_element(INTERFACE_NODE, &no_psnp_interval_cmd);
	install_element(INTERFACE_NODE, &psnp_interval_l1_cmd);
	install_element(INTERFACE_NODE, &no_psnp_interval_l1_cmd);
	install_element(INTERFACE_NODE, &psnp_interval_l2_cmd);
	install_element(INTERFACE_NODE, &no_psnp_interval_l2_cmd);

	install_element(INTERFACE_NODE, &circuit_topology_cmd);
	install_element(INTERFACE_NODE, &no_circuit_topology_cmd);

	install_element(ISIS_NODE, &metric_style_cmd);
	install_element(ISIS_NODE, &no_metric_style_cmd);

	install_element(ISIS_NODE, &set_overload_bit_cmd);
	install_element(ISIS_NODE, &no_set_overload_bit_cmd);

	install_element(ISIS_NODE, &set_attached_bit_cmd);
	install_element(ISIS_NODE, &no_set_attached_bit_cmd);

	install_element(ISIS_NODE, &dynamic_hostname_cmd);
	install_element(ISIS_NODE, &no_dynamic_hostname_cmd);

	install_element(ISIS_NODE, &area_lsp_mtu_cmd);
	install_element(ISIS_NODE, &no_area_lsp_mtu_cmd);

	install_element(ISIS_NODE, &is_type_cmd);
	install_element(ISIS_NODE, &no_is_type_cmd);

	install_element(ISIS_NODE, &lsp_gen_interval_cmd);
	install_element(ISIS_NODE, &no_lsp_gen_interval_cmd);

	install_element(ISIS_NODE, &spf_interval_cmd);
	install_element(ISIS_NODE, &no_spf_interval_cmd);
	install_element(ISIS_NODE, &spf_interval_l1_cmd);
	install_element(ISIS_NODE, &no_spf_interval_l1_cmd);
	install_element(ISIS_NODE, &spf_interval_l2_cmd);
	install_element(ISIS_NODE, &no_spf_interval_l2_cmd);

	install_element(ISIS_NODE, &max_lsp_lifetime_cmd);
	install_element(ISIS_NODE, &no_max_lsp_lifetime_cmd);

	install_element(ISIS_NODE, &lsp_refresh_interval_cmd);
	install_element(ISIS_NODE, &no_lsp_refresh_interval_cmd);

	install_element(ISIS_NODE, &area_passwd_md5_cmd);
	install_element(ISIS_NODE, &area_passwd_clear_cmd);
	install_element(ISIS_NODE, &domain_passwd_md5_cmd);
	install_element(ISIS_NODE, &domain_passwd_clear_cmd);
	install_element(ISIS_NODE, &no_area_passwd_cmd);

	install_element(ISIS_NODE, &spf_delay_ietf_cmd);
	install_element(ISIS_NODE, &no_spf_delay_ietf_cmd);
}
