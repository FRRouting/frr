/*
 * Zebra dataplane plugin for DPDK based hw offload
 *
 * Copyright (C) 2021 Nvidia
 * Anuradha Karuppiah
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h" /* Include this explicitly */
#endif

#include "lib/libfrr.h"

#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/zebra_dplane.h"
#include "zebra/debug.h"
#include "zebra/zebra_pbr.h"

#include "zebra/dpdk/zebra_dplane_dpdk_private.h"

static const char *plugin_name = "zebra_dplane_dpdk";

extern struct zebra_privs_t zserv_privs;

static struct zd_dpdk_ctx dpdk_ctx_buf, *dpdk_ctx = &dpdk_ctx_buf;
#define dpdk_stat (&dpdk_ctx->stats)


void zd_dpdk_stat_show(struct vty *vty)
{
	uint32_t tmp_cnt;

	vty_out(vty, "%30s\n%30s\n", "Dataplane DPDK counters",
		"=======================");

#define ZD_DPDK_SHOW_COUNTER(label, counter)                                   \
	do {                                                                   \
		tmp_cnt =                                                      \
			atomic_load_explicit(&counter, memory_order_relaxed);  \
		vty_out(vty, "%28s: %u\n", (label), (tmp_cnt));                \
	} while (0);

	ZD_DPDK_SHOW_COUNTER("PBR rule adds", dpdk_stat->rule_adds);
	ZD_DPDK_SHOW_COUNTER("PBR rule dels", dpdk_stat->rule_dels);
	ZD_DPDK_SHOW_COUNTER("Ignored updates", dpdk_stat->ignored_updates);
}


static void zd_dpdk_rule_add(struct zebra_dplane_ctx *ctx)
{
	/* XXX - place holder */
}


static void zd_dpdk_rule_del(const char *ifname, int in_ifindex,
			     intptr_t dp_flow_ptr)
{

	/* XXX - place holder */
}


static void zd_dpdk_rule_update(struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op;
	int in_ifindex;
	intptr_t dp_flow_ptr;

	if (IS_ZEBRA_DEBUG_DPLANE_DPDK_DETAIL) {
		zlog_debug("Dplane %s", dplane_op2str(dplane_ctx_get_op(ctx)));
	}

	op = dplane_ctx_get_op(ctx);
	switch (op) {
	case DPLANE_OP_RULE_ADD:
		atomic_fetch_add_explicit(&dpdk_stat->rule_adds, 1,
					  memory_order_relaxed);
		zd_dpdk_rule_add(ctx);
		break;

	case DPLANE_OP_RULE_UPDATE:
		/* delete old rule and install new one */
		atomic_fetch_add_explicit(&dpdk_stat->rule_adds, 1,
					  memory_order_relaxed);
		in_ifindex = dplane_ctx_get_ifindex(ctx);
		dp_flow_ptr = dplane_ctx_rule_get_old_dp_flow_ptr(ctx);
		zd_dpdk_rule_del(dplane_ctx_rule_get_ifname(ctx), in_ifindex,
				 dp_flow_ptr);
		zd_dpdk_rule_add(ctx);
		break;

	case DPLANE_OP_RULE_DELETE:
		atomic_fetch_add_explicit(&dpdk_stat->rule_dels, 1,
					  memory_order_relaxed);
		in_ifindex = dplane_ctx_get_ifindex(ctx);
		dp_flow_ptr = dplane_ctx_rule_get_dp_flow_ptr(ctx);
		zd_dpdk_rule_del(dplane_ctx_rule_get_ifname(ctx), in_ifindex,
				 dp_flow_ptr);
		break;

	default:;
	}
}


/* DPDK provider callback.
 */
static void zd_dpdk_process_update(struct zebra_dplane_ctx *ctx)
{
	switch (dplane_ctx_get_op(ctx)) {

	case DPLANE_OP_RULE_ADD:
	case DPLANE_OP_RULE_UPDATE:
	case DPLANE_OP_RULE_DELETE:
		zd_dpdk_rule_update(ctx);
		break;

	default:
		atomic_fetch_add_explicit(&dpdk_stat->ignored_updates, 1,
					  memory_order_relaxed);

		break;
	}
}


static int zd_dpdk_process(struct zebra_dplane_provider *prov)
{
	struct zebra_dplane_ctx *ctx;
	int counter, limit;

	if (IS_ZEBRA_DEBUG_DPLANE_DPDK_DETAIL)
		zlog_debug("processing %s", dplane_provider_get_name(prov));

	limit = dplane_provider_get_work_limit(prov);
	for (counter = 0; counter < limit; counter++) {
		ctx = dplane_provider_dequeue_in_ctx(prov);
		if (!ctx)
			break;

		zd_dpdk_process_update(ctx);
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_SUCCESS);
		dplane_provider_enqueue_out_ctx(prov, ctx);
	}

	return 0;
}

static int zd_dpdk_init(void)
{
	int rc;
	char *argv[] = {(char *)"/usr/lib/frr/zebra", (char *)"--"};

	zd_dpdk_vty_init();

	frr_with_privs (&zserv_privs) {
		rc = rte_eal_init(sizeof(argv) / sizeof(argv[0]), argv);
	}
	if (rc < 0) {
		zlog_warn("EAL init failed %s", rte_strerror(rte_errno));
		return -1;
	}

	return 0;
}

static int zd_dpdk_start(struct zebra_dplane_provider *prov)
{
	if (IS_ZEBRA_DEBUG_DPLANE_DPDK)
		zlog_debug("%s start", dplane_provider_get_name(prov));

	return zd_dpdk_init();
}


static int zd_dpdk_finish(struct zebra_dplane_provider *prov, bool early)
{
	int rc;

	if (early) {
		if (IS_ZEBRA_DEBUG_DPLANE_DPDK)
			zlog_debug("%s early finish",
				   dplane_provider_get_name(prov));

		return 0;
	}

	if (IS_ZEBRA_DEBUG_DPLANE_DPDK)
		zlog_debug("%s finish", dplane_provider_get_name(prov));


	frr_with_privs (&zserv_privs) {
		rc = rte_eal_cleanup();
	}
	if (rc < 0)
		zlog_warn("EAL cleanup failed %s", rte_strerror(rte_errno));

	return 0;
}


static int zd_dpdk_plugin_init(struct thread_master *tm)
{
	int ret;

	ret = dplane_provider_register(
		plugin_name, DPLANE_PRIO_KERNEL, DPLANE_PROV_FLAGS_DEFAULT,
		zd_dpdk_start, zd_dpdk_process, zd_dpdk_finish, dpdk_ctx, NULL);

	if (IS_ZEBRA_DEBUG_DPLANE_DPDK)
		zlog_debug("%s register status %d", plugin_name, ret);

	return 0;
}


static int zd_dpdk_module_init(void)
{
	hook_register(frr_late_init, zd_dpdk_plugin_init);
	return 0;
}

FRR_MODULE_SETUP(.name = "dplane_dpdk", .version = "0.0.1",
		 .description = "Data plane plugin using dpdk for hw offload",
		 .init = zd_dpdk_module_init, );
