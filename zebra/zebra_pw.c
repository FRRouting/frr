// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra PW code
 * Copyright (C) 2016 Volta Networks, Inc.
 */

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "frrevent.h"
#include "command.h"
#include "vrf.h"
#include "lib/json.h"
#include "printfrr.h"

#include "zebra/debug.h"
#include "zebra/rib.h"
#include "zebra/zebra_router.h"
#include "zebra/zapi_msg.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_pw.h"

DEFINE_MTYPE_STATIC(LIB, PW, "Pseudowire");

DEFINE_QOBJ_TYPE(zebra_pw);

DEFINE_HOOK(pw_install, (struct zebra_pw * pw), (pw));
DEFINE_HOOK(pw_uninstall, (struct zebra_pw * pw), (pw));

#define MPLS_NO_LABEL MPLS_INVALID_LABEL

static int zebra_pw_enabled(struct zebra_pw *);
static void zebra_pw_install(struct zebra_pw *);
static void zebra_pw_uninstall(struct zebra_pw *);
static void zebra_pw_install_retry(struct event *thread);
static int zebra_pw_check_reachability(const struct zebra_pw *);
static void zebra_pw_update_status(struct zebra_pw *, int);

static inline int zebra_pw_compare(const struct zebra_pw *a,
				   const struct zebra_pw *b)
{
	return (strcmp(a->ifname, b->ifname));
}

RB_GENERATE(zebra_pw_head, zebra_pw, pw_entry, zebra_pw_compare)
RB_GENERATE(zebra_static_pw_head, zebra_pw, static_pw_entry, zebra_pw_compare)

struct zebra_pw *zebra_pw_add(struct zebra_vrf *zvrf, const char *ifname,
			      uint8_t protocol, struct zserv *client)
{
	struct zebra_pw *pw;

	if (IS_ZEBRA_DEBUG_PW)
		zlog_debug("%u: adding pseudowire %s protocol %s",
			   zvrf_id(zvrf), ifname, zebra_route_string(protocol));

	pw = XCALLOC(MTYPE_PW, sizeof(*pw));
	strlcpy(pw->ifname, ifname, sizeof(pw->ifname));
	pw->protocol = protocol;
	pw->vrf_id = zvrf_id(zvrf);
	pw->client = client;
	pw->status = PW_NOT_FORWARDING;
	pw->local_label = MPLS_NO_LABEL;
	pw->remote_label = MPLS_NO_LABEL;
	pw->flags = F_PSEUDOWIRE_CWORD;

	RB_INSERT(zebra_pw_head, &zvrf->pseudowires, pw);
	if (pw->protocol == ZEBRA_ROUTE_STATIC) {
		RB_INSERT(zebra_static_pw_head, &zvrf->static_pseudowires, pw);
		QOBJ_REG(pw, zebra_pw);
	}

	return pw;
}

void zebra_pw_del(struct zebra_vrf *zvrf, struct zebra_pw *pw)
{
	if (IS_ZEBRA_DEBUG_PW)
		zlog_debug("%u: deleting pseudowire %s protocol %s", pw->vrf_id,
			   pw->ifname, zebra_route_string(pw->protocol));

	/* remove nexthop tracking */
	zebra_deregister_rnh_pseudowire(pw->vrf_id, pw);

	/* uninstall */
	if (pw->status == PW_FORWARDING) {
		hook_call(pw_uninstall, pw);
		dplane_pw_uninstall(pw);
	}

	EVENT_OFF(pw->install_retry_timer);

	/* unlink and release memory */
	RB_REMOVE(zebra_pw_head, &zvrf->pseudowires, pw);
	if (pw->protocol == ZEBRA_ROUTE_STATIC)
		RB_REMOVE(zebra_static_pw_head, &zvrf->static_pseudowires, pw);

	XFREE(MTYPE_PW, pw);
}

void zebra_pw_change(struct zebra_pw *pw, ifindex_t ifindex, int type, int af,
		     union g_addr *nexthop, uint32_t local_label,
		     uint32_t remote_label, uint8_t flags,
		     union pw_protocol_fields *data)
{
	pw->ifindex = ifindex;
	pw->type = type;
	pw->af = af;
	pw->nexthop = *nexthop;
	pw->local_label = local_label;
	pw->remote_label = remote_label;
	pw->flags = flags;
	pw->data = *data;

	if (zebra_pw_enabled(pw)) {
		bool nht_exists;
		zebra_register_rnh_pseudowire(pw->vrf_id, pw, &nht_exists);
		if (nht_exists)
			zebra_pw_update(pw);
	} else {
		if (pw->protocol == ZEBRA_ROUTE_STATIC)
			zebra_deregister_rnh_pseudowire(pw->vrf_id, pw);
		zebra_pw_uninstall(pw);
	}
}

struct zebra_pw *zebra_pw_find(struct zebra_vrf *zvrf, const char *ifname)
{
	struct zebra_pw pw;
	strlcpy(pw.ifname, ifname, sizeof(pw.ifname));
	return (RB_FIND(zebra_pw_head, &zvrf->pseudowires, &pw));
}

static int zebra_pw_enabled(struct zebra_pw *pw)
{
	if (pw->protocol == ZEBRA_ROUTE_STATIC) {
		if (pw->local_label == MPLS_NO_LABEL
		    || pw->remote_label == MPLS_NO_LABEL || pw->af == AF_UNSPEC)
			return 0;
		return 1;
	} else
		return pw->enabled;
}

void zebra_pw_update(struct zebra_pw *pw)
{
	if (zebra_pw_check_reachability(pw) < 0) {
		zebra_pw_uninstall(pw);
		zebra_pw_install_failure(pw, PW_NOT_FORWARDING);
		/* wait for NHT and try again later */
	} else {
		/*
		 * Install or reinstall the pseudowire (e.g. to update
		 * parameters like the nexthop or the use of the control word).
		 */
		zebra_pw_install(pw);
	}
}

static void zebra_pw_install(struct zebra_pw *pw)
{
	if (IS_ZEBRA_DEBUG_PW)
		zlog_debug("%u: installing pseudowire %s protocol %s",
			   pw->vrf_id, pw->ifname,
			   zebra_route_string(pw->protocol));

	hook_call(pw_install, pw);
	if (dplane_pw_install(pw) == ZEBRA_DPLANE_REQUEST_FAILURE) {
		zebra_pw_install_failure(pw, PW_NOT_FORWARDING);
		return;
	}

	if (pw->status != PW_FORWARDING)
		zebra_pw_update_status(pw, PW_FORWARDING);
}

static void zebra_pw_uninstall(struct zebra_pw *pw)
{
	if (pw->status != PW_FORWARDING)
		return;

	if (IS_ZEBRA_DEBUG_PW)
		zlog_debug("%u: uninstalling pseudowire %s protocol %s",
			   pw->vrf_id, pw->ifname,
			   zebra_route_string(pw->protocol));

	/* ignore any possible error */
	hook_call(pw_uninstall, pw);
	dplane_pw_uninstall(pw);

	if (zebra_pw_enabled(pw))
		zebra_pw_update_status(pw, PW_NOT_FORWARDING);
}

/*
 * Installation of the pseudowire in the kernel or hardware has failed. This
 * function will notify the pseudowire client about the failure and schedule
 * to retry the installation later. This function can be called by an external
 * agent that performs the pseudowire installation in an asynchronous way.
 */
void zebra_pw_install_failure(struct zebra_pw *pw, int pwstatus)
{
	if (IS_ZEBRA_DEBUG_PW)
		zlog_debug(
			"%u: failed installing pseudowire %s, scheduling retry in %u seconds",
			pw->vrf_id, pw->ifname, PW_INSTALL_RETRY_INTERVAL);

	/* schedule to retry later */
	EVENT_OFF(pw->install_retry_timer);
	event_add_timer(zrouter.master, zebra_pw_install_retry, pw,
			PW_INSTALL_RETRY_INTERVAL, &pw->install_retry_timer);

	zebra_pw_update_status(pw, pwstatus);
}

static void zebra_pw_install_retry(struct event *thread)
{
	struct zebra_pw *pw = EVENT_ARG(thread);

	zebra_pw_install(pw);
}

static void zebra_pw_update_status(struct zebra_pw *pw, int status)
{
	pw->status = status;
	if (pw->client)
		zsend_pw_update(pw->client, pw);
}

static int zebra_pw_check_reachability_strict(const struct zebra_pw *pw,
					      struct route_entry *re)
{
	const struct nexthop *nexthop;
	const struct nexthop_group *nhg;
	bool found_p = false;
	bool fail_p = false;

	/* TODO: consider GRE/L2TPv3 tunnels in addition to MPLS LSPs */

	/* All active nexthops must be labelled; look at
	 * primary and backup fib lists, in case there's been
	 * a backup nexthop activation.
	 */
	nhg = rib_get_fib_nhg(re);
	if (nhg && nhg->nexthop) {
		for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
				continue;

			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE)) {
				if (nexthop->nh_label != NULL)
					found_p = true;
				else {
					fail_p = true;
					break;
				}
			}
		}
	}

	if (fail_p)
		goto done;

	nhg = rib_get_fib_backup_nhg(re);
	if (nhg && nhg->nexthop) {
		for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
				continue;

			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE)) {
				if (nexthop->nh_label != NULL)
					found_p = true;
				else {
					fail_p = true;
					break;
				}
			}
		}
	}

done:

	if (fail_p || !found_p) {
		if (IS_ZEBRA_DEBUG_PW)
			zlog_debug("%s: unlabeled route for %s",
				   __func__, pw->ifname);
		return -1;
	}

	return 0;
}

static int zebra_pw_check_reachability(const struct zebra_pw *pw)
{
	struct route_entry *re;
	const struct nexthop *nexthop;
	const struct nexthop_group *nhg;
	bool found_p = false;

	/* TODO: consider GRE/L2TPv3 tunnels in addition to MPLS LSPs */

	/* Find route to the remote end of the pseudowire */
	re = rib_match(family2afi(pw->af), SAFI_UNICAST, pw->vrf_id,
		       &pw->nexthop, NULL);
	if (!re) {
		if (IS_ZEBRA_DEBUG_PW)
			zlog_debug("%s: no route found for %s", __func__,
				   pw->ifname);
		return -1;
	}

	/* Stricter checking for some OSes (OBSD, e.g.) */
	if (mpls_pw_reach_strict)
		return zebra_pw_check_reachability_strict(pw, re);

	/* There must be at least one installed labelled nexthop;
	 * look at primary and backup fib lists, in case there's been
	 * a backup nexthop activation.
	 */
	nhg = rib_get_fib_nhg(re);
	if (nhg && nhg->nexthop) {
		for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
				continue;

			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE) &&
			    nexthop->nh_label != NULL) {
				found_p = true;
				break;
			}
		}
	}

	if (found_p)
		return 0;

	nhg = rib_get_fib_backup_nhg(re);
	if (nhg && nhg->nexthop) {
		for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
				continue;

			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE) &&
			    nexthop->nh_label != NULL) {
				found_p = true;
				break;
			}
		}
	}

	if (!found_p) {
		if (IS_ZEBRA_DEBUG_PW)
			zlog_debug("%s: unlabeled route for %s",
				   __func__, pw->ifname);
		return -1;
	}

	return 0;
}

static int zebra_pw_client_close(struct zserv *client)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;
	struct zebra_pw *pw, *tmp;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		zvrf = vrf->info;
		RB_FOREACH_SAFE (pw, zebra_pw_head, &zvrf->pseudowires, tmp) {
			if (pw->client != client)
				continue;
			zebra_pw_del(zvrf, pw);
		}
	}

	return 0;
}

void zebra_pw_init(struct zebra_vrf *zvrf)
{
	RB_INIT(zebra_pw_head, &zvrf->pseudowires);
	RB_INIT(zebra_static_pw_head, &zvrf->static_pseudowires);

	hook_register(zserv_client_close, zebra_pw_client_close);
}

void zebra_pw_exit(struct zebra_vrf *zvrf)
{
	struct zebra_pw *pw;

	while (!RB_EMPTY(zebra_pw_head, &zvrf->pseudowires)) {
		pw = RB_ROOT(zebra_pw_head, &zvrf->pseudowires);

		zebra_pw_del(zvrf, pw);
	}
}

DEFUN_NOSH (pseudowire_if,
	    pseudowire_if_cmd,
	    "pseudowire IFNAME",
	    "Static pseudowire configuration\n"
	    "Pseudowire name\n")
{
	struct zebra_vrf *zvrf;
	struct zebra_pw *pw;
	const char *ifname;
	int idx = 0;

	zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);

	argv_find(argv, argc, "IFNAME", &idx);
	ifname = argv[idx]->arg;

	pw = zebra_pw_find(zvrf, ifname);
	if (pw && pw->protocol != ZEBRA_ROUTE_STATIC) {
		vty_out(vty, "%% Pseudowire is not static\n");
		return CMD_WARNING;
	}

	if (!pw)
		pw = zebra_pw_add(zvrf, ifname, ZEBRA_ROUTE_STATIC, NULL);
	VTY_PUSH_CONTEXT(PW_NODE, pw);

	return CMD_SUCCESS;
}

DEFUN (no_pseudowire_if,
       no_pseudowire_if_cmd,
       "no pseudowire IFNAME",
       NO_STR
       "Static pseudowire configuration\n"
       "Pseudowire name\n")
{
	struct zebra_vrf *zvrf;
	struct zebra_pw *pw;
	const char *ifname;
	int idx = 0;

	zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);

	argv_find(argv, argc, "IFNAME", &idx);
	ifname = argv[idx]->arg;

	pw = zebra_pw_find(zvrf, ifname);
	if (pw) {
		if (pw->protocol != ZEBRA_ROUTE_STATIC) {
			vty_out(vty, "%% Pseudowire is not static\n");
			return CMD_WARNING;
		}
		zebra_pw_del(zvrf, pw);
	}

	return CMD_SUCCESS;
}

DEFUN (pseudowire_labels,
       pseudowire_labels_cmd,
       "[no] mpls label local (16-1048575) remote (16-1048575)",
       NO_STR
       "MPLS L2VPN PW command\n"
       "MPLS L2VPN static labels\n"
       "Local pseudowire label\n"
       "Local pseudowire label\n"
       "Remote pseudowire label\n"
       "Remote pseudowire label\n")
{
	VTY_DECLVAR_CONTEXT(zebra_pw, pw);
	int idx = 0;
	mpls_label_t local_label, remote_label;

	if (argv_find(argv, argc, "no", &idx)) {
		local_label = MPLS_NO_LABEL;
		remote_label = MPLS_NO_LABEL;
	} else {
		argv_find(argv, argc, "local", &idx);
		local_label = atoi(argv[idx + 1]->arg);
		argv_find(argv, argc, "remote", &idx);
		remote_label = atoi(argv[idx + 1]->arg);
	}

	zebra_pw_change(pw, pw->ifindex, pw->type, pw->af, &pw->nexthop,
			local_label, remote_label, pw->flags, &pw->data);

	return CMD_SUCCESS;
}

DEFUN (pseudowire_neighbor,
       pseudowire_neighbor_cmd,
       "[no] neighbor <A.B.C.D|X:X::X:X>",
       NO_STR
       "Specify the IPv4 or IPv6 address of the remote endpoint\n"
       "IPv4 address\n"
       "IPv6 address\n")
{
	VTY_DECLVAR_CONTEXT(zebra_pw, pw);
	int idx = 0;
	const char *address;
	int af;
	union g_addr nexthop;

	af = AF_UNSPEC;
	memset(&nexthop, 0, sizeof(nexthop));

	if (!argv_find(argv, argc, "no", &idx)) {
		argv_find(argv, argc, "neighbor", &idx);
		address = argv[idx + 1]->arg;

		if (inet_pton(AF_INET, address, &nexthop.ipv4) == 1)
			af = AF_INET;
		else if (inet_pton(AF_INET6, address, &nexthop.ipv6) == 1)
			af = AF_INET6;
		else {
			vty_out(vty, "%% Malformed address\n");
			return CMD_WARNING;
		}
	}

	zebra_pw_change(pw, pw->ifindex, pw->type, af, &nexthop,
			pw->local_label, pw->remote_label, pw->flags,
			&pw->data);

	return CMD_SUCCESS;
}

DEFUN (pseudowire_control_word,
       pseudowire_control_word_cmd,
       "[no] control-word <exclude|include>",
       NO_STR
       "Control-word options\n"
       "Exclude control-word in pseudowire packets\n"
       "Include control-word in pseudowire packets\n")
{
	VTY_DECLVAR_CONTEXT(zebra_pw, pw);
	int idx = 0;
	uint8_t flags = 0;

	if (argv_find(argv, argc, "no", &idx))
		flags = F_PSEUDOWIRE_CWORD;
	else {
		argv_find(argv, argc, "control-word", &idx);
		if (argv[idx + 1]->text[0] == 'i')
			flags = F_PSEUDOWIRE_CWORD;
	}

	zebra_pw_change(pw, pw->ifindex, pw->type, pw->af, &pw->nexthop,
			pw->local_label, pw->remote_label, flags, &pw->data);

	return CMD_SUCCESS;
}

DEFUN (show_pseudowires,
       show_pseudowires_cmd,
       "show mpls pseudowires",
       SHOW_STR
       MPLS_STR
       "Pseudowires\n")
{
	struct zebra_vrf *zvrf;
	struct zebra_pw *pw;

	zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);

	vty_out(vty, "%-16s %-24s %-12s %-8s %-10s\n", "Interface", "Neighbor",
		"Labels", "Protocol", "Status");

	RB_FOREACH (pw, zebra_pw_head, &zvrf->pseudowires) {
		char buf_nbr[INET6_ADDRSTRLEN];
		char buf_labels[64];

		inet_ntop(pw->af, &pw->nexthop, buf_nbr, sizeof(buf_nbr));

		if (pw->local_label != MPLS_NO_LABEL
		    && pw->remote_label != MPLS_NO_LABEL)
			snprintf(buf_labels, sizeof(buf_labels), "%u/%u",
				 pw->local_label, pw->remote_label);
		else
			snprintf(buf_labels, sizeof(buf_labels), "-");

		vty_out(vty, "%-16s %-24s %-12s %-8s %-10s\n", pw->ifname,
			(pw->af != AF_UNSPEC) ? buf_nbr : "-", buf_labels,
			zebra_route_string(pw->protocol),
			(zebra_pw_enabled(pw) && pw->status == PW_FORWARDING)
				? "UP"
				: "DOWN");
	}

	return CMD_SUCCESS;
}

static void vty_show_mpls_pseudowire_detail(struct vty *vty)
{
	struct zebra_vrf *zvrf;
	struct zebra_pw *pw;
	struct route_entry *re;
	struct nexthop *nexthop;
	struct nexthop_group *nhg;

	zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);

	RB_FOREACH (pw, zebra_pw_head, &zvrf->pseudowires) {
		char buf_nbr[INET6_ADDRSTRLEN];
		char buf_nh[100];

		vty_out(vty, "Interface: %s\n", pw->ifname);
		inet_ntop(pw->af, &pw->nexthop, buf_nbr, sizeof(buf_nbr));
		vty_out(vty, "  Neighbor: %s\n",
			(pw->af != AF_UNSPEC) ? buf_nbr : "-");
		if (pw->local_label != MPLS_NO_LABEL)
			vty_out(vty, "  Local Label: %u\n", pw->local_label);
		else
			vty_out(vty, "  Local Label: %s\n", "-");
		if (pw->remote_label != MPLS_NO_LABEL)
			vty_out(vty, "  Remote Label: %u\n", pw->remote_label);
		else
			vty_out(vty, "  Remote Label: %s\n", "-");
		vty_out(vty, "  Protocol: %s\n",
			zebra_route_string(pw->protocol));
		if (pw->protocol == ZEBRA_ROUTE_LDP)
			vty_out(vty, "  VC-ID: %u\n", pw->data.ldp.pwid);
		vty_out(vty, "  Status: %s \n",
			(zebra_pw_enabled(pw) && pw->status == PW_FORWARDING)
			? "Up"
			: "Down");
		re = rib_match(family2afi(pw->af), SAFI_UNICAST, pw->vrf_id,
			       &pw->nexthop, NULL);
		if (re == NULL)
			continue;

		nhg = rib_get_fib_nhg(re);
		for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
			snprintfrr(buf_nh, sizeof(buf_nh), "%pNHv",
				   nexthop);
			vty_out(vty, "  Next Hop: %s\n", buf_nh);
			if (nexthop->nh_label)
				vty_out(vty, "  Next Hop label: %u\n",
					nexthop->nh_label->label[0]);
			else
				vty_out(vty, "  Next Hop label: %s\n",
					"-");
		}

		/* Include any installed backups */
		nhg = rib_get_fib_backup_nhg(re);
		if (nhg == NULL)
			continue;

		for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
			snprintfrr(buf_nh, sizeof(buf_nh), "%pNHv",
				   nexthop);
			vty_out(vty, "  Next Hop: %s\n", buf_nh);
			if (nexthop->nh_label)
				vty_out(vty, "  Next Hop label: %u\n",
					nexthop->nh_label->label[0]);
			else
				vty_out(vty, "  Next Hop label: %s\n",
					"-");
		}
	}
}

static void vty_show_mpls_pseudowire(struct zebra_pw *pw, json_object *json_pws)
{
	struct route_entry *re;
	struct nexthop *nexthop;
	struct nexthop_group *nhg;
	char buf_nbr[INET6_ADDRSTRLEN];
	char buf_nh[100];
	json_object *json_pw = NULL;
	json_object *json_nexthop = NULL;
	json_object *json_nexthops = NULL;

	json_nexthops = json_object_new_array();
	json_pw = json_object_new_object();

	json_object_string_add(json_pw, "interface", pw->ifname);
	if (pw->af == AF_UNSPEC)
		json_object_string_add(json_pw, "neighbor", "-");
	else {
		inet_ntop(pw->af, &pw->nexthop, buf_nbr, sizeof(buf_nbr));
		json_object_string_add(json_pw, "neighbor", buf_nbr);
	}
	if (pw->local_label != MPLS_NO_LABEL)
		json_object_int_add(json_pw, "localLabel", pw->local_label);
	else
		json_object_string_add(json_pw, "localLabel", "-");
	if (pw->remote_label != MPLS_NO_LABEL)
		json_object_int_add(json_pw, "remoteLabel", pw->remote_label);
	else
		json_object_string_add(json_pw, "remoteLabel", "-");
	json_object_string_add(json_pw, "protocol",
			       zebra_route_string(pw->protocol));
	if (pw->protocol == ZEBRA_ROUTE_LDP)
		json_object_int_add(json_pw, "vcId", pw->data.ldp.pwid);
	json_object_string_add(
		json_pw, "Status",
		(zebra_pw_enabled(pw) && pw->status == PW_FORWARDING) ? "Up"
								      : "Down");
	re = rib_match(family2afi(pw->af), SAFI_UNICAST, pw->vrf_id,
		       &pw->nexthop, NULL);
	if (re == NULL)
		goto done;

	nhg = rib_get_fib_nhg(re);
	for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
		json_nexthop = json_object_new_object();
		snprintfrr(buf_nh, sizeof(buf_nh), "%pNHv", nexthop);
		json_object_string_add(json_nexthop, "nexthop", buf_nh);
		if (nexthop->nh_label)
			json_object_int_add(
				json_nexthop, "nhLabel",
				nexthop->nh_label->label[0]);
		else
			json_object_string_add(json_nexthop, "nhLabel",
					       "-");

		json_object_array_add(json_nexthops, json_nexthop);
	}

	/* Include installed backup nexthops also */
	nhg = rib_get_fib_backup_nhg(re);
	if (nhg == NULL)
		goto done;

	for (ALL_NEXTHOPS_PTR(nhg, nexthop)) {
		json_nexthop = json_object_new_object();
		snprintfrr(buf_nh, sizeof(buf_nh), "%pNHv", nexthop);
		json_object_string_add(json_nexthop, "nexthop", buf_nh);
		if (nexthop->nh_label)
			json_object_int_add(
				json_nexthop, "nhLabel",
				nexthop->nh_label->label[0]);
		else
			json_object_string_add(json_nexthop, "nhLabel",
					       "-");

		json_object_array_add(json_nexthops, json_nexthop);
	}

done:

	json_object_object_add(json_pw, "nexthops", json_nexthops);
	json_object_array_add(json_pws, json_pw);
}

static void vty_show_mpls_pseudowire_detail_json(struct vty *vty)
{
	json_object *json = NULL;
	json_object *json_pws = NULL;
	struct zebra_vrf *zvrf;
	struct zebra_pw *pw;

	zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);

	json = json_object_new_object();
	json_pws = json_object_new_array();
	RB_FOREACH (pw, zebra_pw_head, &zvrf->pseudowires) {
		vty_show_mpls_pseudowire(pw, json_pws);
	}
	json_object_object_add(json, "pw", json_pws);
	vty_json(vty, json);
}

DEFUN(show_pseudowires_detail, show_pseudowires_detail_cmd,
      "show mpls pseudowires detail [json]$json",
      SHOW_STR MPLS_STR
      "Pseudowires\n"
      "Detailed output\n" JSON_STR)
{
	bool uj = use_json(argc, argv);

	if (uj)
		vty_show_mpls_pseudowire_detail_json(vty);
	else
		vty_show_mpls_pseudowire_detail(vty);

	return CMD_SUCCESS;
}

/* Pseudowire configuration write function. */
static int zebra_pw_config(struct vty *vty)
{
	int write = 0;
	struct zebra_vrf *zvrf;
	struct zebra_pw *pw;

	zvrf = zebra_vrf_lookup_by_id(VRF_DEFAULT);

	RB_FOREACH (pw, zebra_static_pw_head, &zvrf->static_pseudowires) {
		vty_out(vty, "pseudowire %s\n", pw->ifname);
		if (pw->local_label != MPLS_NO_LABEL
		    && pw->remote_label != MPLS_NO_LABEL)
			vty_out(vty, " mpls label local %u remote %u\n",
				pw->local_label, pw->remote_label);
		else
			vty_out(vty,
				" ! Incomplete config, specify the static MPLS labels\n");

		if (pw->af != AF_UNSPEC) {
			char buf[INET6_ADDRSTRLEN];
			inet_ntop(pw->af, &pw->nexthop, buf, sizeof(buf));
			vty_out(vty, " neighbor %s\n", buf);
		} else
			vty_out(vty,
				" ! Incomplete config, specify a neighbor address\n");

		if (!(pw->flags & F_PSEUDOWIRE_CWORD))
			vty_out(vty, " control-word exclude\n");

		vty_out(vty, "exit\n");
		vty_out(vty, "!\n");
		write = 1;
	}

	return write;
}

static int zebra_pw_config(struct vty *vty);
static struct cmd_node pw_node = {
	.name = "pw",
	.node = PW_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-pw)# ",
	.config_write = zebra_pw_config,
};

void zebra_pw_vty_init(void)
{
	install_node(&pw_node);
	install_default(PW_NODE);

	install_element(CONFIG_NODE, &pseudowire_if_cmd);
	install_element(CONFIG_NODE, &no_pseudowire_if_cmd);
	install_element(PW_NODE, &pseudowire_labels_cmd);
	install_element(PW_NODE, &pseudowire_neighbor_cmd);
	install_element(PW_NODE, &pseudowire_control_word_cmd);

	install_element(VIEW_NODE, &show_pseudowires_cmd);
	install_element(VIEW_NODE, &show_pseudowires_detail_cmd);
}
