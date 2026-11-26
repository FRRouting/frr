// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Cisco Systems, Inc. */

#include <zebra.h>
#include <sys/ioctl.h>

#include "command.h"
#include "module.h"
#include "zebra/interface.h"
#include "zebra/ioctl.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_evpn.h"
#include "zebra/zebra_evpn_mh.h"
#include "zebra/zebra_evpn_neigh.h"
#include "zebra/zebra_neigh.h"
#include "zebra/zebra_vxlan.h"

struct delete_gate {
	struct zebra_dplane_provider *provider;
	struct zebra_dplane_ctx *held;
	struct zebra_dplane_ctx *repin;
	struct ipaddr ip;
	struct ethaddr mac;
	enum dplane_op_e op;
	bool armed;
};

static struct delete_gate before_kernel;
static struct delete_gate after_kernel;
static pthread_mutex_t gate_lock = PTHREAD_MUTEX_INITIALIZER;

static int gate_process(struct zebra_dplane_provider *provider)
{
	struct delete_gate *gate = dplane_provider_get_data(provider);
	struct zebra_dplane_ctx *ctx;
	int limit = dplane_provider_get_work_limit(provider);

	while (limit-- > 0 && (ctx = dplane_provider_dequeue_in_ctx(provider))) {
		bool hold;

		pthread_mutex_lock(&gate_lock);
		hold = gate->armed && dplane_ctx_get_op(ctx) == gate->op &&
		       (gate->op == DPLANE_OP_MAC_DELETE
				? !memcmp(&gate->mac, dplane_ctx_mac_get_addr(ctx), ETH_ALEN)
				: !ipaddr_cmp(&gate->ip, dplane_ctx_neigh_get_ipaddr(ctx)));
		if (hold) {
			gate->held = ctx;
			gate->armed = false;
		} else if (gate == &before_kernel && gate->held && !gate->repin &&
			   gate->op == DPLANE_OP_MAC_DELETE &&
			   dplane_ctx_get_op(ctx) == DPLANE_OP_MAC_INSTALL &&
			   !memcmp(&gate->mac, dplane_ctx_mac_get_addr(ctx), ETH_ALEN)) {
			/* Keep the matching add behind the queued delete. */
			gate->repin = ctx;
			hold = true;
		}
		pthread_mutex_unlock(&gate_lock);
		if (!hold)
			dplane_provider_enqueue_out_ctx(provider, ctx);
	}
	return 0;
}

static int gate_finish(struct zebra_dplane_provider *provider, bool early)
{
	struct delete_gate *gate = dplane_provider_get_data(provider);

	if (!early && gate->held)
		dplane_ctx_fini(&gate->held);
	if (!early && gate->repin)
		dplane_ctx_fini(&gate->repin);
	return 0;
}

DEFUN(l3mh_test_arm, l3mh_test_arm_cmd,
      "show l3mh-test arm <before-delete|after-delete|before-mac|after-mac|before-repair> WORD",
      SHOW_STR "L3MH test controls\n" "Arm a delete gate\n" "Before neighbor delete\n"
      "After neighbor delete\n" "Before MAC delete\n" "After MAC delete\n"
      "Before neighbor install\n" "IP or MAC to match\n")
{
	const char *mode = argv[3]->text;
	struct delete_gate *gate = !strncmp(mode, "before-", 7) ? &before_kernel : &after_kernel;
	bool mac = !strcmp(mode, "after-mac") || !strcmp(mode, "before-mac");
	bool repair = !strcmp(mode, "before-repair");
	struct ethaddr addr = {};
	struct ipaddr ip = {};

	if (mac ? !prefix_str2mac(argv[4]->arg, &addr) : str2ipaddr(argv[4]->arg, &ip))
		return CMD_WARNING;
	pthread_mutex_lock(&gate_lock);
	if (gate->held || gate->armed) {
		pthread_mutex_unlock(&gate_lock);
		return CMD_WARNING;
	}
	gate->op = DPLANE_OP_NEIGH_DELETE;
	if (mac)
		gate->op = DPLANE_OP_MAC_DELETE;
	if (repair)
		gate->op = DPLANE_OP_NEIGH_INSTALL;
	gate->ip = ip;
	gate->mac = addr;
	gate->armed = true;
	pthread_mutex_unlock(&gate_lock);
	return CMD_SUCCESS;
}

DEFUN(l3mh_test_gate, l3mh_test_gate_cmd,
      "show l3mh-test <held|held-install|held-create-only|release|fail> <before|after>",
      SHOW_STR "L3MH test controls\n" "Check for a held delete\n" "Check for a queued MAC add\n"
      "Check for a create-only neighbor install\n" "Release the context\n"
      "Return a failed delete result\n" "Before kernel\n" "After kernel\n")
{
	const char *action = argv[2]->text;
	struct delete_gate *gate = !strcmp(argv[3]->text, "before") ? &before_kernel
								    : &after_kernel;
	struct zebra_dplane_ctx *ctx;
	struct zebra_dplane_ctx *repin = NULL;
	bool check = !strncmp(action, "held", 4);

	pthread_mutex_lock(&gate_lock);
	ctx = !strcmp(action, "held-install") ? gate->repin : gate->held;
	if (ctx && !check) {
		gate->held = NULL;
		repin = gate->repin;
		gate->repin = NULL;
	}
	pthread_mutex_unlock(&gate_lock);
	if (!ctx)
		return CMD_WARNING;
	if (!strcmp(action, "held-create-only"))
		return dplane_ctx_get_op(ctx) == DPLANE_OP_NEIGH_INSTALL &&
				       CHECK_FLAG(dplane_ctx_neigh_get_update_flags(ctx),
						  DPLANE_NEIGH_CREATE_ONLY)
			       ? CMD_SUCCESS
			       : CMD_WARNING;
	if (check)
		return CMD_SUCCESS;
	if (!strcmp(action, "fail")) {
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_FAILURE);
		dplane_provider_enqueue_to_zebra(ctx);
	} else {
		dplane_provider_enqueue_out_ctx(gate->provider, ctx);
	}
	if (repin)
		dplane_provider_enqueue_out_ctx(gate->provider, repin);
	dplane_provider_work_ready();
	return CMD_SUCCESS;
}

DEFUN(l3mh_test_expiry, l3mh_test_expiry_cmd, "show l3mh-test immediate-expiry [A.B.C.D]",
      SHOW_STR "L3MH test controls\n" "Expire a hold on its next dispatch\n" "Neighbor IP\n")
{
	struct zebra_evpn *zevpn;
	struct zebra_neigh *n;
	struct event_loop *master;
	void (*expire)(struct event *event);
	struct ipaddr ip;

	if (argc == 3) {
		zmh_info->l3_neigh_down_peering_time = 0;
		return CMD_SUCCESS;
	}
	zevpn = zebra_evpn_l3_neigh_sync_lookup(4000);
	if (!zevpn || str2ipaddr(argv[3]->arg, &ip))
		return CMD_WARNING;
	n = zebra_evpn_neigh_lookup(zevpn, &ip);
	if (!n || !n->l3mh_down_timer)
		return CMD_WARNING;
	master = n->l3mh_down_timer->master;
	expire = n->l3mh_down_timer->func;
	event_cancel(&n->l3mh_down_timer);
	event_add_timer(master, expire, n, 0, &n->l3mh_down_timer);
	return CMD_SUCCESS;
}

DEFUN(l3mh_test_event, l3mh_test_event_cmd,
      "show l3mh-test <early-fdb|old-arp|old-withdraw|replacement-loss> A.B.C.D [A.B.C.D]",
      SHOW_STR "L3MH test controls\n" "Deliver FDB delete before link event\n"
      "Deliver a stale ARP learn\n" "Withdraw RT-2 during the old probe\n"
      "Replace RT-2 and lose its RT-1 during the old probe\n" "Neighbor IP\n" "Replacement origin\n")
{
	const char *action = argv[2]->text;
	struct zebra_evpn *zevpn = zebra_evpn_l3_neigh_sync_lookup(4000);
	struct ipaddr ip, origin;
	struct interface *ifp;
	struct zebra_neigh *n;
	struct ethaddr mac;
	esi_t esi;
	vlanid_t vid;
	uint32_t seq;

	if (!zevpn || str2ipaddr(argv[3]->arg, &ip))
		return CMD_WARNING;
	n = zebra_evpn_neigh_lookup(zevpn, &ip);
	if (!n)
		return CMD_WARNING;
	mac = n->emac;
	vid = n->eth_tag;
	if (!strcmp(action, "early-fdb")) {
		struct ifreq ifr = {};
		struct zebra_if *zif;

		ifp = if_lookup_by_index_per_nsid(NS_DEFAULT, n->l3mh_expected_ifindex);
		if (!ifp || !ifp->info)
			return CMD_WARNING;
		zif = ifp->info;
		ifreq_set_name(&ifr, ifp);
		if (vrf_if_ioctl(SIOCGIFFLAGS, (caddr_t)&ifr, VRF_DEFAULT) < 0)
			return CMD_WARNING;
		UNSET_FLAG(ifr.ifr_flags, IFF_UP);
		if (vrf_if_ioctl(SIOCSIFFLAGS, (caddr_t)&ifr, VRF_DEFAULT) < 0 ||
		    !CHECK_FLAG(zif->es_info.es->flags, ZEBRA_EVPNES_OPER_UP))
			return CMD_WARNING;
		zebra_evpn_l3vni_local_mac_update(ifp, zif->brslave_info.br_if, &mac, vid, false);
		return n->l3mh_state == ZEBRA_L3MH_NEIGH_HANDOFF_WAIT ? CMD_SUCCESS : CMD_WARNING;
	}
	if (!strcmp(action, "old-arp")) {
		ifp = if_lookup_by_index_per_nsid(NS_DEFAULT, n->ifindex);
		if (!ifp || !ifp->info)
			return CMD_WARNING;
		zebra_evpn_l3vni_local_neigh_update(ifp, ((struct zebra_if *)ifp->info)->link, &ip,
						    &mac, ZEBRA_NEIGH_STATE_REACHABLE, false,
						    false);
		return CMD_SUCCESS;
	}

	esi = n->rem_esi;
	origin = n->l3mh_peer_origin;
	zebra_evpn_l3vni_peer_backing_invalidate(zevpn->vni, &esi, &origin);
	if (!zebra_evpn_l3mh_probe_current(n))
		return CMD_WARNING;
	seq = n->l3mh_probe_seq;
	if (!strcmp(action, "old-withdraw")) {
		zebra_evpn_l3vni_remote_neigh_del(zevpn, &ip, &mac, vid);
		return n->l3mh_probe_seq == seq ? CMD_SUCCESS : CMD_WARNING;
	}
	if (argc != 5 || str2ipaddr(argv[4]->arg, &origin))
		return CMD_WARNING;
	zebra_evpn_l3vni_remote_neigh_add(zevpn->vni, &ip, &mac, vid, 0, &esi, &origin, 0);
	zebra_evpn_l3vni_peer_backing_invalidate(zevpn->vni, &esi, &origin);
	return n->l3mh_probe_seq == seq && n->l3mh_peer_rt1_lost &&
			       !zebra_evpn_l3mh_probe_current(n)
		       ? CMD_SUCCESS
		       : CMD_WARNING;
}

DEFUN(l3mh_test_stale_neigh, l3mh_test_stale_neigh_cmd,
      "show l3mh-test <stale-failed|stale-gc> A.B.C.D",
      SHOW_STR "L3MH test controls\n" "Deliver old probe failure\n"
      "Deliver old neighbor garbage collection\n" "Neighbor IP\n")
{
	struct zebra_evpn *zevpn = zebra_evpn_l3_neigh_sync_lookup(4000);
	struct zebra_dplane_ctx *ctx;
	struct zebra_neigh *n;
	struct ipaddr ip;
	bool gc = !strcmp(argv[2]->text, "stale-gc");

	if (!zevpn || str2ipaddr(argv[3]->arg, &ip))
		return CMD_WARNING;
	n = zebra_evpn_neigh_lookup(zevpn, &ip);
	if (!n)
		return CMD_WARNING;
	ctx = dplane_ctx_alloc();
	dplane_ctx_set_op(ctx, gc ? DPLANE_OP_NEIGH_IP_DELETE : DPLANE_OP_NEIGH_IP_INSTALL);
	dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_QUEUED);
	dplane_ctx_set_ifindex(ctx, n->ifindex);
	dplane_ctx_set_ns_id(ctx, NS_DEFAULT);
	dplane_ctx_neigh_set_ipaddr(ctx, &ip);
	dplane_ctx_neigh_set_ndm_family(ctx, AF_INET);
	dplane_ctx_neigh_set_ndm_state(ctx, ZEBRA_NEIGH_STATE_FAILED);
	zebra_neigh_dplane_update(ctx);
	dplane_ctx_fini(&ctx);
	return CMD_SUCCESS;
}

static int l3mh_test_init_vty(struct event_loop *loop)
{
	install_element(VIEW_NODE, &l3mh_test_arm_cmd);
	install_element(VIEW_NODE, &l3mh_test_gate_cmd);
	install_element(VIEW_NODE, &l3mh_test_expiry_cmd);
	install_element(VIEW_NODE, &l3mh_test_event_cmd);
	install_element(VIEW_NODE, &l3mh_test_stale_neigh_cmd);

	if (dplane_provider_register("L3MH test before kernel", DPLANE_PRIO_PRE_KERNEL,
				     DPLANE_PROV_FLAGS_DEFAULT, NULL, gate_process, gate_finish,
				     &before_kernel, &before_kernel.provider))
		return 1;
	return dplane_provider_register("L3MH test after kernel", DPLANE_PRIO_POSTPROCESS,
					DPLANE_PROV_FLAGS_DEFAULT, NULL, gate_process, gate_finish,
					&after_kernel, &after_kernel.provider);
}

static int l3mh_test_init(void)
{
	hook_register(frr_late_init, l3mh_test_init_vty);
	return 0;
}

FRR_MODULE_SETUP(.name = "l3mh_test", .version = "1", .init = l3mh_test_init);
