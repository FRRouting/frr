/* Main routine of bgpd.
 * Copyright (C) 1996, 97, 98, 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include <pthread.h>
#include "vector.h"
#include "command.h"
#include "getopt.h"
#include "thread.h"
#include <lib/version.h>
#include "memory.h"
#include "memory_vty.h"
#include "prefix.h"
#include "log.h"
#include "privs.h"
#include "sigevent.h"
#include "zclient.h"
#include "routemap.h"
#include "filter.h"
#include "plist.h"
#include "stream.h"
#include "queue.h"
#include "vrf.h"
#include "bfd.h"
#include "libfrr.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_keepalives.h"

#ifdef ENABLE_BGP_VNC
#include "bgpd/rfapi/rfapi_backend.h"
#endif

/* bgpd options, we use GNU getopt library. */
static const struct option longopts[] = {
	{"bgp_port", required_argument, NULL, 'p'},
	{"listenon", required_argument, NULL, 'l'},
	{"retain", no_argument, NULL, 'r'},
	{"no_kernel", no_argument, NULL, 'n'},
	{"skip_runas", no_argument, NULL, 'S'},
	{"ecmp", required_argument, NULL, 'e'},
	{0}};

/* signal definitions */
void sighup(void);
void sigint(void);
void sigusr1(void);

static void bgp_exit(int);
static void bgp_vrf_terminate(void);

static struct quagga_signal_t bgp_signals[] = {
	{
		.signal = SIGHUP,
		.handler = &sighup,
	},
	{
		.signal = SIGUSR1,
		.handler = &sigusr1,
	},
	{
		.signal = SIGINT,
		.handler = &sigint,
	},
	{
		.signal = SIGTERM,
		.handler = &sigint,
	},
};

/* Route retain mode flag. */
static int retain_mode = 0;

/* privileges */
static zebra_capabilities_t _caps_p[] = {
	ZCAP_BIND, ZCAP_NET_RAW, ZCAP_NET_ADMIN,
};

struct zebra_privs_t bgpd_privs = {
#if defined(FRR_USER) && defined(FRR_GROUP)
	.user = FRR_USER,
	.group = FRR_GROUP,
#endif
#ifdef VTY_GROUP
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0,
};

static struct frr_daemon_info bgpd_di;

/* SIGHUP handler. */
void sighup(void)
{
	zlog_info("SIGHUP received");

	/* Terminate all thread. */
	bgp_terminate();
	bgp_reset();
	zlog_info("bgpd restarting!");

	/* Reload config file. */
	vty_read_config(bgpd_di.config_file, config_default);

	/* Try to return to normal operation. */
}

/* SIGINT handler. */
__attribute__((__noreturn__)) void sigint(void)
{
	zlog_notice("Terminating on signal");

	if (!retain_mode)
		bgp_terminate();

	bgp_exit(0);

	exit(0);
}

/* SIGUSR1 handler. */
void sigusr1(void)
{
	zlog_rotate();
}

/*
  Try to free up allocations we know about so that diagnostic tools such as
  valgrind are able to better illuminate leaks.

  Zebra route removal and protocol teardown are not meant to be done here.
  For example, "retain_mode" may be set.
*/
static __attribute__((__noreturn__)) void bgp_exit(int status)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;

	/* it only makes sense for this to be called on a clean exit */
	assert(status == 0);

	frr_early_fini();

	bfd_gbl_exit();

	bgp_close();

	/* reverse bgp_master_init */
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp_delete(bgp);

	/* reverse bgp_dump_init */
	bgp_dump_finish();

	/* reverse bgp_route_init */
	bgp_route_finish();

	/* cleanup route maps */
	bgp_route_map_terminate();

	/* reverse bgp_attr_init */
	bgp_attr_finish();

	/* stop pthreads */
	bgp_pthreads_finish();

	/* reverse access_list_init */
	access_list_add_hook(NULL);
	access_list_delete_hook(NULL);
	access_list_reset();

	/* reverse bgp_filter_init */
	as_list_add_hook(NULL);
	as_list_delete_hook(NULL);
	bgp_filter_reset();

	/* reverse prefix_list_init */
	prefix_list_add_hook(NULL);
	prefix_list_delete_hook(NULL);
	prefix_list_reset();

	/* reverse community_list_init */
	community_list_terminate(bgp_clist);

	bgp_vrf_terminate();
#if ENABLE_BGP_VNC
	vnc_zebra_destroy();
#endif
	bgp_zebra_destroy();

	bf_free(bm->rd_idspace);
	list_delete_and_null(&bm->bgp);
	memset(bm, 0, sizeof(*bm));

	frr_fini();
	exit(status);
}

static int bgp_vrf_new(struct vrf *vrf)
{
	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("VRF Created: %s(%u)", vrf->name, vrf->vrf_id);

	return 0;
}

static int bgp_vrf_delete(struct vrf *vrf)
{
	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("VRF Deletion: %s(%u)", vrf->name, vrf->vrf_id);

	return 0;
}

static int bgp_vrf_enable(struct vrf *vrf)
{
	struct bgp *bgp;
	vrf_id_t old_vrf_id;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("VRF enable add %s id %u", vrf->name, vrf->vrf_id);

	bgp = bgp_lookup_by_name(vrf->name);
	if (bgp) {
		old_vrf_id = bgp->vrf_id;
		/* We have instance configured, link to VRF and make it "up". */
		bgp_vrf_link(bgp, vrf);

		/* Update any redistribute vrf bitmaps if the vrf_id changed */
		if (old_vrf_id != bgp->vrf_id)
			bgp_update_redist_vrf_bitmaps(bgp, old_vrf_id);
		bgp_instance_up(bgp);
	}

	return 0;
}

static int bgp_vrf_disable(struct vrf *vrf)
{
	struct bgp *bgp;
	vrf_id_t old_vrf_id;

	if (vrf->vrf_id == VRF_DEFAULT)
		return 0;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("VRF disable %s id %d", vrf->name, vrf->vrf_id);

	bgp = bgp_lookup_by_name(vrf->name);
	if (bgp) {
		old_vrf_id = bgp->vrf_id;
		/* We have instance configured, unlink from VRF and make it
		 * "down". */
		bgp_vrf_unlink(bgp, vrf);
		/* Update any redistribute vrf bitmaps if the vrf_id changed */
		if (old_vrf_id != bgp->vrf_id)
			bgp_update_redist_vrf_bitmaps(bgp, old_vrf_id);
		bgp_instance_down(bgp);
	}

	/* Note: This is a callback, the VRF will be deleted by the caller. */
	return 0;
}

static void bgp_vrf_init(void)
{
	vrf_init(bgp_vrf_new, bgp_vrf_enable, bgp_vrf_disable, bgp_vrf_delete);
}

static void bgp_vrf_terminate(void)
{
	vrf_terminate();
}

FRR_DAEMON_INFO(bgpd, BGP, .vty_port = BGP_VTY_PORT,

		.proghelp = "Implementation of the BGP routing protocol.",

		.signals = bgp_signals, .n_signals = array_size(bgp_signals),

		.privs = &bgpd_privs, )

/* Main routine of bgpd. Treatment of argument and start bgp finite
   state machine is handled at here. */
int main(int argc, char **argv)
{
	int opt;
	int tmp_port;

	int bgp_port = BGP_PORT_DEFAULT;
	char *bgp_address = NULL;
	int no_fib_flag = 0;
	int skip_runas = 0;

	frr_preinit(&bgpd_di, argc, argv);
	frr_opt_add(
		"p:l:rSne:", longopts,
		"  -p, --bgp_port     Set bgp protocol's port number\n"
		"  -l, --listenon     Listen on specified address (implies -n)\n"
		"  -r, --retain       When program terminates, retain added route by bgpd.\n"
		"  -n, --no_kernel    Do not install route to kernel.\n"
		"  -S, --skip_runas   Skip capabilities checks, and changing user and group IDs.\n"
		"  -e, --ecmp         Specify ECMP to use.\n");

	/* Command line argument treatment. */
	while (1) {
		opt = frr_getopt(argc, argv, 0);

		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		case 'p':
			tmp_port = atoi(optarg);
			if (tmp_port <= 0 || tmp_port > 0xffff)
				bgp_port = BGP_PORT_DEFAULT;
			else
				bgp_port = tmp_port;
			break;
		case 'e':
			multipath_num = atoi(optarg);
			if (multipath_num > MULTIPATH_NUM
			    || multipath_num <= 0) {
				zlog_err(
					"Multipath Number specified must be less than %d and greater than 0",
					MULTIPATH_NUM);
				return 1;
			}
			break;
		case 'r':
			retain_mode = 1;
			break;
		case 'l':
			bgp_address = optarg;
		/* listenon implies -n */
		/* fallthru */
		case 'n':
			no_fib_flag = 1;
			break;
		case 'S':
			skip_runas = 1;
			break;
		default:
			frr_help_exit(1);
			break;
		}
	}
	if (skip_runas)
		memset(&bgpd_privs, 0, sizeof(bgpd_privs));

	/* BGP master init. */
	bgp_master_init(frr_init());
	bm->port = bgp_port;
	bm->address = bgp_address;
	if (no_fib_flag)
		bgp_option_set(BGP_OPT_NO_FIB);

	/* Initializations. */
	bgp_vrf_init();

	/* BGP related initialization.  */
	bgp_init();

	snprintf(bgpd_di.startinfo, sizeof(bgpd_di.startinfo), ", bgp@%s:%d",
		 (bm->address ? bm->address : "<all>"), bm->port);

	frr_config_fork();
	/* must be called after fork() */
	bgp_pthreads_run();
	frr_run(bm->master);

	/* Not reached. */
	return (0);
}
