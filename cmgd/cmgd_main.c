/*
 * Main routine of cmgd.
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar
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

#include <pthread.h>
#include "vector.h"
#include "command.h"
#include "getopt.h"
#include "thread.h"
#include <lib/version.h>
#include "memory.h"
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
#include "ns.h"

#include "cmgd/cmgd.h"
#include "cmgd/cmgd_bcknd_adapter.h"

#include "lib/routing_nb.h"
#include "staticd/static_nb.h"

#if 0
#include "cmgd/cmgd_nb.h"
#include "cmgd/cmgd_evpn_mh.h"
#include "cmgd/cmgd_nht.h"

#ifdef ENABLE_CMGD_VNC
#include "cmgd/rfapi/rfapi_backend.h"
#endif
#endif

/* cmgd options, we use GNU getopt library. */
static const struct option longopts[] = {
	{"cmgd_port", required_argument, NULL, 'p'},
	{"listenon", required_argument, NULL, 'l'},
	{"no_kernel", no_argument, NULL, 'n'},
	{"skip_runas", no_argument, NULL, 'S'},
	{"ecmp", required_argument, NULL, 'e'},
	{"int_num", required_argument, NULL, 'I'},
	{"no_zebra", no_argument, NULL, 'Z'},
	{"socket_size", required_argument, NULL, 's'},
	{0}};

/* signal definitions */
void sighup(void);
void sigint(void);
void sigusr1(void);

static void cmgd_exit(int);
static void cmgd_vrf_terminate(void);

static struct quagga_signal_t cmgd_signals[] = {
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

/* privileges */
static zebra_capabilities_t _caps_p[] = {ZCAP_BIND, ZCAP_NET_RAW,
					 ZCAP_NET_ADMIN, ZCAP_SYS_ADMIN};

struct zebra_privs_t cmgd_privs = {
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

static struct frr_daemon_info cmgd_di;

/* SIGHUP handler. */
void sighup(void)
{
	zlog_info("SIGHUP received, ignoring");

	return;

	/*
	 * This is turned off for the moment.  There is all
	 * sorts of config turned off by cmgd_terminate
	 * that is not setup properly again in cmgd_reset.
	 * I see no easy way to do this nor do I see that
	 * this is a desirable way to reload config
	 * given the yang work.
	 */
	/* Terminate all thread. */
	cmgd_terminate();
	
	/*
	 * cmgd_reset();
	 * zlog_info("cmgd restarting!");

	 * Reload config file.
	 * vty_read_config(NULL, cmgd_di.config_file, config_default);
	 */
	/* Try to return to normal operation. */
}

/* SIGINT handler. */
__attribute__((__noreturn__)) void sigint(void)
{
	zlog_notice("Terminating on signal");
	assert(cm->terminating == false);
	cm->terminating = true;	/* global flag that shutting down */

	cmgd_terminate();

	cmgd_exit(0);

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
static __attribute__((__noreturn__)) void cmgd_exit(int status)
{
	// struct cmgd *cmgd, *cmgd_default, *cmgd_evpn;
	// struct listnode *node, *nnode;

	/* it only makes sense for this to be called on a clean exit */
	assert(status == 0);

	frr_early_fini();

#if 0
	bfd_gbl_exit();

	cmgd_close();

	cmgd_default = cmgd_get_default();
	cmgd_evpn = cmgd_get_evpn();

	/* reverse cmgd_master_init */
	for (ALL_LIST_ELEMENTS(cm->cmgd, node, nnode, cmgd)) {
		if (cmgd_default == cmgd || cmgd_evpn == cmgd)
			continue;
		cmgd_delete(cmgd);
	}
	if (cmgd_evpn && cmgd_evpn != cmgd_default)
		cmgd_delete(cmgd_evpn);
	if (cmgd_default)
		cmgd_delete(cmgd_default);

	cmgd_evpn_mh_finish();
	cmgd_l3nhg_finish();

	/* reverse cmgd_dump_init */
	cmgd_dump_finish();

	/* reverse cmgd_route_init */
	cmgd_route_finish();

	/* cleanup route maps */
	cmgd_route_map_terminate();

	/* reverse cmgd_attr_init */
	cmgd_attr_finish();
#endif

	/* stop pthreads */
	cmgd_pthreads_finish();

#if 0
	/* reverse access_list_init */
	access_list_add_hook(NULL);
	access_list_delete_hook(NULL);
	access_list_reset();

	/* reverse cmgd_filter_init */
	as_list_add_hook(NULL);
	as_list_delete_hook(NULL);
	cmgd_filter_reset();

	/* reverse prefix_list_init */
	prefix_list_add_hook(NULL);
	prefix_list_delete_hook(NULL);
	prefix_list_reset();

	/* reverse community_list_init */
	community_list_terminate(cmgd_clist);
#endif
	cmgd_vrf_terminate();
#if 0
#ifdef ENABLE_CMGD_VNC
	vnc_zebra_destroy();
#endif
	cmgd_zebra_destroy();

	bf_free(cm->rd_idspace);
	list_delete(&cm->cmgd);
	list_delete(&cm->addresses);

	cmgd_lp_finish();

	memset(bm, 0, sizeof(*bm));
#endif

	frr_fini();
	exit(status);
}

static int cmgd_vrf_new(struct vrf *vrf)
{
	// if (CMGD_DEBUG(zebra, ZEBRA))
		zlog_debug("VRF Created: %s(%u)", vrf->name, vrf->vrf_id);

	return 0;
}

static int cmgd_vrf_delete(struct vrf *vrf)
{
	// if (CMGD_DEBUG(zebra, ZEBRA))
		zlog_debug("VRF Deletion: %s(%u)", vrf->name, vrf->vrf_id);

	return 0;
}

static int cmgd_vrf_enable(struct vrf *vrf)
{
#if 0
	struct cmgd *cmgd;
	vrf_id_t old_vrf_id;

	if (CMGD_DEBUG(zebra, ZEBRA))
		zlog_debug("VRF enable add %s id %u", vrf->name, vrf->vrf_id);

	cmgd = cmgd_lookup_by_name(vrf->name);
	if (cmgd && cmgd->vrf_id != vrf->vrf_id) {
		if (cmgd->name && strmatch(vrf->name, VRF_DEFAULT_NAME)) {
			XFREE(MTYPE_CMGD, cmgd->name);
			XFREE(MTYPE_CMGD, cmgd->name_pretty);
			cmgd->name_pretty = XSTRDUP(MTYPE_CMGD, "VRF default");
			cmgd->inst_type = CMGD_INSTANCE_TYPE_DEFAULT;
#ifdef ENABLE_CMGD_VNC
			if (!cmgd->rfapi) {
				cmgd->rfapi = cmgd_rfapi_new(cmgd);
				assert(cmgd->rfapi);
				assert(cmgd->rfapi_cfg);
			}
#endif /* ENABLE_CMGD_VNC */
		}
		old_vrf_id = cmgd->vrf_id;
		/* We have instance configured, link to VRF and make it "up". */
		cmgd_vrf_link(cmgd, vrf);

		cmgd_handle_socket(cmgd, vrf, old_vrf_id, true);
		/* Update any redistribution if vrf_id changed */
		if (old_vrf_id != cmgd->vrf_id)
			cmgd_redistribute_redo(cmgd);
		cmgd_instance_up(cmgd);
		vpn_leak_zebra_vrf_label_update(cmgd, AFI_IP);
		vpn_leak_zebra_vrf_label_update(cmgd, AFI_IP6);
		vpn_leak_postchange(CMGD_VPN_POLICY_DIR_TOVPN, AFI_IP,
				    cmgd_get_default(), cmgd);
		vpn_leak_postchange(CMGD_VPN_POLICY_DIR_FROMVPN, AFI_IP,
				    cmgd_get_default(), cmgd);
		vpn_leak_postchange(CMGD_VPN_POLICY_DIR_TOVPN, AFI_IP6,
				    cmgd_get_default(), cmgd);
		vpn_leak_postchange(CMGD_VPN_POLICY_DIR_FROMVPN, AFI_IP6,
				    cmgd_get_default(), cmgd);
	}
#endif

	return 0;
}

static int cmgd_vrf_disable(struct vrf *vrf)
{
#if 0
	struct cmgd *cmgd;
	vrf_id_t old_vrf_id;

	if (vrf->vrf_id == VRF_DEFAULT)
		return 0;

	if (CMGD_DEBUG(zebra, ZEBRA))
		zlog_debug("VRF disable %s id %d", vrf->name, vrf->vrf_id);

	cmgd = cmgd_lookup_by_name(vrf->name);
	if (cmgd) {

		vpn_leak_zebra_vrf_label_withdraw(cmgd, AFI_IP);
		vpn_leak_zebra_vrf_label_withdraw(cmgd, AFI_IP6);
		vpn_leak_prechange(CMGD_VPN_POLICY_DIR_TOVPN, AFI_IP,
				   cmgd_get_default(), cmgd);
		vpn_leak_prechange(CMGD_VPN_POLICY_DIR_FROMVPN, AFI_IP,
				   cmgd_get_default(), cmgd);
		vpn_leak_prechange(CMGD_VPN_POLICY_DIR_TOVPN, AFI_IP6,
				   cmgd_get_default(), cmgd);
		vpn_leak_prechange(CMGD_VPN_POLICY_DIR_FROMVPN, AFI_IP6,
				   cmgd_get_default(), cmgd);

		old_vrf_id = cmgd->vrf_id;
		cmgd_handle_socket(cmgd, vrf, VRF_UNKNOWN, false);
		/* We have instance configured, unlink from VRF and make it
		 * "down". */
		cmgd_vrf_unlink(cmgd, vrf);
		/* Delete any redistribute vrf bitmaps if the vrf_id changed */
		if (old_vrf_id != cmgd->vrf_id)
			cmgd_unset_redist_vrf_bitmaps(cmgd, old_vrf_id);
		cmgd_instance_down(cmgd);
	}
#endif

	/* Note: This is a callback, the VRF will be deleted by the caller. */
	return 0;
}

static int cmgd_vrf_config_write(struct vty *vty)
{
#if 0
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (vrf->vrf_id != VRF_DEFAULT)
			vty_frame(vty, "vrf %s\n", vrf->name);

		static_config(vty, vrf->info, AFI_IP,
			      SAFI_UNICAST, "ip route");
		static_config(vty, vrf->info, AFI_IP,
			      SAFI_MULTICAST, "ip mroute");
		static_config(vty, vrf->info, AFI_IP6,
			      SAFI_UNICAST, "ipv6 route");

		if (vrf->vrf_id != VRF_DEFAULT)
			vty_endframe(vty, " exit-vrf\n!\n");
	}
#endif

	return 0;
}

static void cmgd_vrf_init(void)
{
	vrf_init(cmgd_vrf_new, cmgd_vrf_enable, cmgd_vrf_disable,
		 cmgd_vrf_delete, cmgd_vrf_enable);
	vrf_cmd_init(cmgd_vrf_config_write, &cmgd_privs);
}

static void cmgd_vrf_terminate(void)
{
	vrf_terminate();
}

static const struct frr_yang_module_info *const cmgd_yang_modules[] = {
	// &frr_cmgd_info,
	&frr_filter_info,
	&frr_interface_info,
	&frr_route_map_info,
	&frr_routing_info,
	&frr_vrf_info,
	&frr_staticd_info,
};

FRR_DAEMON_INFO(cmgd, CMGD, .vty_port = CMGD_VTY_PORT,

		.proghelp = "Centralised Management Daemon.",

		.signals = cmgd_signals, .n_signals = array_size(cmgd_signals),

		.privs = &cmgd_privs, .yang_modules = cmgd_yang_modules,
		.n_yang_modules = array_size(cmgd_yang_modules), 
);

#define DEPRECATED_OPTIONS ""

/* Main routine of cmgd. Treatment of argument and start cmgd finite
   state machine is handled at here. */
int main(int argc, char **argv)
{
	int opt;
	int tmp_port;

	int cmgd_port = CMGD_VTY_PORT;
	struct list *addresses = list_new();
	// int no_fib_flag = 0;
	// int no_zebra_flag = 0;
	// int skip_runas = 0;
	// int instance = 0;
	int buffer_size = CMGD_SOCKET_BUF_SIZE;
	// char *address;
	// struct listnode *node;

	addresses->cmp = (int (*)(void *, void *))strcmp;

	frr_preinit(&cmgd_di, argc, argv);
	frr_opt_add(
		"p:l:SnZe:I:s:" DEPRECATED_OPTIONS, longopts,
		"  -p, --cmgd_port     Set CMGD listen port number (0 means do not listen).\n"
		"  -l, --listenon     Listen on specified address (implies -n)\n"
		"  -n, --no_kernel    Do not install route to kernel.\n"
		"  -Z, --no_zebra     Do not communicate with Zebra.\n"
		"  -S, --skip_runas   Skip capabilities checks, and changing user and group IDs.\n"
		"  -e, --ecmp         Specify ECMP to use.\n"
		"  -I, --int_num      Set instance number (label-manager)\n"
		"  -s, --socket_size  Set CMGD peer socket send buffer size\n");

	/* Command line argument treatment. */
	while (1) {
		opt = frr_getopt(argc, argv, 0);

		if (opt && opt < 128 && strchr(DEPRECATED_OPTIONS, opt)) {
			fprintf(stderr,
				"The -%c option no longer exists.\nPlease refer to the manual.\n",
				opt);
			continue;
		}

		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		case 'p':
			tmp_port = atoi(optarg);
			if (tmp_port < 0 || tmp_port > 0xffff)
				cmgd_port = CMGD_VTY_PORT;
			else
				cmgd_port = tmp_port;
			break;
		case 'e': {
#if 0
			unsigned long int parsed_multipath =
				strtoul(optarg, NULL, 10);
			if (parsed_multipath == 0
			    || parsed_multipath > MULTIPATH_NUM
			    || parsed_multipath > UINT_MAX) {
				flog_err(
					EC_CMGD_MULTIPATH,
					"Multipath Number specified must be less than %u and greater than 0",
					MULTIPATH_NUM);
				return 1;
			}
			multipath_num = parsed_multipath;
			break;
#endif
		}
		case 'l':
			listnode_add_sort_nodup(addresses, optarg);
		/* listenon implies -n */
		/* fallthru */
#if 0
		case 'n':
			no_fib_flag = 1;
			break;
		case 'Z':
			no_zebra_flag = 1;
			break;
		case 'S':
			skip_runas = 1;
			break;
		case 'I':
			instance = atoi(optarg);
			if (instance > (unsigned short)-1)
				zlog_err("Instance %i out of range (0..%u)",
					 instance, (unsigned short)-1);
			break;
#endif
		case 's':
			// buffer_size = atoi(optarg);
			break;
		default:
			frr_help_exit(1);
			break;
		}
	}

#if 0
	if (skip_runas)
		memset(&cmgd_privs, 0, sizeof(cmgd_privs));
#endif

	/* CMGD master init. */
	cmgd_master_init(frr_init(), buffer_size, addresses);

#if 0
	cm->port = cmgd_port;
	if (cmgd_port == 0)
		cmgd_option_set(CMGD_OPT_NO_LISTEN);
	if (no_fib_flag || no_zebra_flag)
		cmgd_option_set(CMGD_OPT_NO_FIB);
	if (no_zebra_flag)
		cmgd_option_set(CMGD_OPT_NO_ZEBRA);
	cmgd_error_init();
#endif

	/* Initializations. */
	cmgd_vrf_init();

#if 0
#ifdef HAVE_SCRIPTING
	cmgd_script_init();
#endif

	hook_register(routing_conf_event,
		      routing_control_plane_protocols_name_validate);

#endif

	/* CMGD related initialization.  */
	cmgd_init();

#if 0
	if (list_isempty(cm->addresses)) {
		snprintf(cmgd_di.startinfo, sizeof(cmgd_di.startinfo),
			 ", cmgd@<all>:%d", cm->port);
	} else {
		for (ALL_LIST_ELEMENTS_RO(cm->addresses, node, address))
			snprintf(cmgd_di.startinfo + strlen(cmgd_di.startinfo),
				 sizeof(cmgd_di.startinfo)
					 - strlen(cmgd_di.startinfo),
				 ", cmgd@%s:%d", address, cm->port);
	}
#endif

	frr_config_fork();

#if 0
	/* must be called after fork() */
	cmgd_gr_apply_running_config();
#endif
	cmgd_pthreads_run();

	frr_run(cm->master);

	/* Not reached. */
	return 0;
}
