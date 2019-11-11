/*
 * Sample plugin for the FRR zebra dataplane.
 *
 * Copyright (c) 2019 Volta Networks, Inc.
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

/*
 * Should be possible to build this plugin using this sort of command:
 *
 *    gcc -I ~/work/frr/ -I ~/work/frr/lib -I ~/work/frr/zebra \
 *        -g -O0 -o sample_plugin.so -shared -fPIC sample_plugin.c
 *
 * where 'frr' is a configured and built frr sandbox.
 *
 * Run zebra with '-M /path/to/sample_plugin.so' to load the module.
 */

#include "config.h" /* Include this explicitly */
#include "lib/zebra.h"
#include "lib/libfrr.h"
#include "zebra/zebra_dplane.h"
#include "zebra/debug.h"

static const char *plugin_name = "SAMPLE";

static struct zebra_dplane_provider *prov_p;

/*
 * Startup/init callback, called from the dataplane.
 */
static int sample_start(struct zebra_dplane_provider *prov)
{
	/* Nothing special to do - we don't allocate anything. */
	return 0;
}


/*
 * Shutdown/cleanup callback, called from the dataplane pthread.
 */
static int sample_fini(struct zebra_dplane_provider *prov, bool early)
{
	/* Nothing special to do. */
	return 0;
}

/*
 * Callback from the dataplane to process incoming work; this runs in the
 * dplane pthread.
 */
static int sample_process(struct zebra_dplane_provider *prov)
{
	int counter, limit;
	struct zebra_dplane_ctx *ctx;

	limit = dplane_provider_get_work_limit(prov_p);

	/* Respect the configured limit on the amount of work to do in
	 * any one call.
	 */
	for (counter = 0; counter < limit; counter++) {
		ctx = dplane_provider_dequeue_in_ctx(prov_p);
		if (!ctx)
			break;

		/* Just set 'success' status and return to the dataplane */
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_SUCCESS);
		dplane_provider_enqueue_out_ctx(prov_p, ctx);
	}

	return 0;
}

/*
 * Init entry point called during zebra startup. This is registered during
 * module init.
 */
static int init_sample_plugin(struct thread_master *tm)
{
	int ret;
	struct zebra_dplane_provider *prov = NULL;

	/* Note that we don't use or store the thread_master 'tm'. We
	 * don't use the zebra main pthread: our plugin code will run in
	 * the zebra dataplane pthread context.
	 */

	/* Register the plugin with the dataplane infrastructure. We
	 * register to be called before the kernel, and we register
	 * our init, process work, and shutdown callbacks.
	 */
	ret = dplane_provider_register(plugin_name, DPLANE_PRIO_PRE_KERNEL,
				       DPLANE_PROV_FLAGS_DEFAULT,
				       sample_start,
				       sample_process,
				       sample_fini,
				       NULL,
				       &prov_p);

	if (IS_ZEBRA_DEBUG_DPLANE)
		zlog_debug("sample plugin register => %d", ret);

	return 0;
}

/*
 * Base FRR loadable module info: basic info including module entry-point.
 */
static int module_init(void)
{
	hook_register(frr_late_init, init_sample_plugin);
	return 0;
}

FRR_MODULE_SETUP(
	.name = "dplane_sample",
	.version = "0.0.1",
	.description = "Dataplane Sample Plugin",
	.init = module_init,
	)
