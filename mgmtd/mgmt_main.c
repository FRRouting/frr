/*
 * Main routine of mgmt.
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

#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_bcknd_adapter.h"

#include "lib/routing_nb.h"

/*
 * NOTE:
 * For each Backend client migrated to MGMTD add the
 * corresponding NB callback modules here.
 */
#include "staticd/static_nb.h"


/* mgmt options, we use GNU getopt library. */
static const struct option longopts[] = {
	{"skip_runas", no_argument, NULL, 'S'},
	{"no_zebra", no_argument, NULL, 'Z'},
	{"socket_size", required_argument, NULL, 's'},
	{0}};

/* signal definitions */
void sighup(void);
void sigint(void);
void sigusr1(void);

static void mgmt_exit(int);
static void mgmt_vrf_terminate(void);

static struct quagga_signal_t mgmt_signals[] = {
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

struct zebra_privs_t mgmt_privs = {
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

static struct frr_daemon_info mgmtd_di;

/* SIGHUP handler. */
void sighup(void)
{
	zlog_info("SIGHUP received, ignoring");

	return;

	/*
	 * This is turned off for the moment.  There is all
	 * sorts of config turned off by mgmt_terminate
	 * that is not setup properly again in mgmt_reset.
	 * I see no easy way to do this nor do I see that
	 * this is a desirable way to reload config
	 * given the yang work.
	 */
	/* Terminate all thread. */
	mgmt_terminate();
	
	/*
	 * mgmt_reset();
	 */
	zlog_info("MGMTD restarting!");

	/*
	 * Reload config file.
	 * vty_read_config(NULL, mgmtd_di.config_file, config_default);
	 */
	/* Try to return to normal operation. */
}

/* SIGINT handler. */
__attribute__((__noreturn__)) void sigint(void)
{
	zlog_notice("Terminating on signal");
	assert(mm->terminating == false);
	mm->terminating = true;	/* global flag that shutting down */

	mgmt_terminate();

	mgmt_exit(0);

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
static __attribute__((__noreturn__)) void mgmt_exit(int status)
{
	// struct mgmt *mgmt, *mgmt_default, *mgmt_evpn;
	// struct listnode *node, *nnode;

	/* it only makes sense for this to be called on a clean exit */
	assert(status == 0);

	frr_early_fini();

#if 0
	bfd_gbl_exit();

	mgmt_close();

	mgmt_default = mgmt_get_default();
	mgmt_evpn = mgmt_get_evpn();

	/* reverse mgmt_master_init */
	for (ALL_LIST_ELEMENTS(mm->mgmt, node, nnode, mgmt)) {
		if (mgmt_default == mgmt || mgmt_evpn == mgmt)
			continue;
		mgmt_delete(mgmt);
	}
	if (mgmt_evpn && mgmt_evpn != mgmt_default)
		mgmt_delete(mgmt_evpn);
	if (mgmt_default)
		mgmt_delete(mgmt_default);

	mgmt_evpn_mh_finish();
	mgmt_l3nhg_finish();

	/* reverse mgmt_dump_init */
	mgmt_dump_finish();

	/* reverse mgmt_route_init */
	mgmt_route_finish();

	/* cleanup route maps */
	mgmt_route_map_terminate();

	/* reverse mgmt_attr_init */
	mgmt_attr_finish();
#endif

	/* stop pthreads */
	mgmt_pthreads_finish();

#if 0
	/* reverse access_list_init */
	access_list_add_hook(NULL);
	access_list_delete_hook(NULL);
	access_list_reset();

	/* reverse mgmt_filter_init */
	as_list_add_hook(NULL);
	as_list_delete_hook(NULL);
	mgmt_filter_reset();

	/* reverse prefix_list_init */
	prefix_list_add_hook(NULL);
	prefix_list_delete_hook(NULL);
	prefix_list_reset();

	/* reverse community_list_init */
	community_list_terminate(mgmt_clist);
#endif
	mgmt_vrf_terminate();
#if 0
#ifdef ENABLE_MGMTD_VNC
	vnc_zebra_destroy();
#endif
	mgmt_zebra_destroy();

	bf_free(mm->rd_idspace);
	list_delete(&mm->mgmt);
	list_delete(&mm->addresses);

	mgmt_lp_finish();

	memset(bm, 0, sizeof(*bm));
#endif

	frr_fini();
	exit(status);
}

static int mgmt_vrf_new(struct vrf *vrf)
{
	// if (MGMTD_DEBUG(zebra, ZEBRA))
		zlog_debug("VRF Created: %s(%u)", vrf->name, vrf->vrf_id);

	return 0;
}

static int mgmt_vrf_delete(struct vrf *vrf)
{
	// if (MGMTD_DEBUG(zebra, ZEBRA))
		zlog_debug("VRF Deletion: %s(%u)", vrf->name, vrf->vrf_id);

	return 0;
}

static int mgmt_vrf_enable(struct vrf *vrf)
{
#if 0
	struct mgmt *mgmt;
	vrf_id_t old_vrf_id;

	if (MGMTD_DEBUG(zebra, ZEBRA))
		zlog_debug("VRF enable add %s id %u", vrf->name, vrf->vrf_id);

	mgmt = mgmt_lookup_by_name(vrf->name);
	if (mgmt && mgmt->vrf_id != vrf->vrf_id) {
		if (mgmt->name && strmatch(vrf->name, VRF_DEFAULT_NAME)) {
			XFREE(MTYPE_MGMTD, mgmt->name);
			XFREE(MTYPE_MGMTD, mgmt->name_pretty);
			mgmt->name_pretty = XSTRDUP(MTYPE_MGMTD, "VRF default");
			mgmt->inst_type = MGMTD_INSTANCE_TYPE_DEFAULT;
#ifdef ENABLE_MGMTD_VNC
			if (!mgmt->rfapi) {
				mgmt->rfapi = mgmt_rfapi_new(mgmt);
				assert(mgmt->rfapi);
				assert(mgmt->rfapi_cfg);
			}
#endif /* ENABLE_MGMTD_VNC */
		}
		old_vrf_id = mgmt->vrf_id;
		/* We have instance configured, link to VRF and make it "up". */
		mgmt_vrf_link(mgmt, vrf);

		mgmt_handle_socket(mgmt, vrf, old_vrf_id, true);
		/* Update any redistribution if vrf_id changed */
		if (old_vrf_id != mgmt->vrf_id)
			mgmt_redistribute_redo(mgmt);
		mgmt_instance_up(mgmt);
		vpn_leak_zebra_vrf_label_update(mgmt, AFI_IP);
		vpn_leak_zebra_vrf_label_update(mgmt, AFI_IP6);
		vpn_leak_postchange(MGMTD_VPN_POLICY_DIR_TOVPN, AFI_IP,
				    mgmt_get_default(), mgmt);
		vpn_leak_postchange(MGMTD_VPN_POLICY_DIR_FROMVPN, AFI_IP,
				    mgmt_get_default(), mgmt);
		vpn_leak_postchange(MGMTD_VPN_POLICY_DIR_TOVPN, AFI_IP6,
				    mgmt_get_default(), mgmt);
		vpn_leak_postchange(MGMTD_VPN_POLICY_DIR_FROMVPN, AFI_IP6,
				    mgmt_get_default(), mgmt);
	}
#endif

	return 0;
}

static int mgmt_vrf_disable(struct vrf *vrf)
{
#if 0
	struct mgmt *mgmt;
	vrf_id_t old_vrf_id;

	if (vrf->vrf_id == VRF_DEFAULT)
		return 0;

	if (MGMTD_DEBUG(zebra, ZEBRA))
		zlog_debug("VRF disable %s id %d", vrf->name, vrf->vrf_id);

	mgmt = mgmt_lookup_by_name(vrf->name);
	if (mgmt) {

		vpn_leak_zebra_vrf_label_withdraw(mgmt, AFI_IP);
		vpn_leak_zebra_vrf_label_withdraw(mgmt, AFI_IP6);
		vpn_leak_prechange(MGMTD_VPN_POLICY_DIR_TOVPN, AFI_IP,
				   mgmt_get_default(), mgmt);
		vpn_leak_prechange(MGMTD_VPN_POLICY_DIR_FROMVPN, AFI_IP,
				   mgmt_get_default(), mgmt);
		vpn_leak_prechange(MGMTD_VPN_POLICY_DIR_TOVPN, AFI_IP6,
				   mgmt_get_default(), mgmt);
		vpn_leak_prechange(MGMTD_VPN_POLICY_DIR_FROMVPN, AFI_IP6,
				   mgmt_get_default(), mgmt);

		old_vrf_id = mgmt->vrf_id;
		mgmt_handle_socket(mgmt, vrf, VRF_UNKNOWN, false);
		/* We have instance configured, unlink from VRF and make it
		 * "down". */
		mgmt_vrf_unlink(mgmt, vrf);
		/* Delete any redistribute vrf bitmaps if the vrf_id changed */
		if (old_vrf_id != mgmt->vrf_id)
			mgmt_unset_redist_vrf_bitmaps(mgmt, old_vrf_id);
		mgmt_instance_down(mgmt);
	}
#endif

	/* Note: This is a callback, the VRF will be deleted by the caller. */
	return 0;
}

static int mgmt_vrf_config_write(struct vty *vty)
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

static void mgmt_vrf_init(void)
{
	vrf_init(mgmt_vrf_new, mgmt_vrf_enable, mgmt_vrf_disable,
		 mgmt_vrf_delete, mgmt_vrf_enable);
	vrf_cmd_init(mgmt_vrf_config_write);
}

static void mgmt_vrf_terminate(void)
{
	vrf_terminate();
}

static const struct frr_yang_module_info *const mgmt_yang_modules[] = {
	// &frr_mgmt_info,
	&frr_filter_info,
	&frr_interface_info,
	&frr_route_map_info,
	&frr_routing_info,
	&frr_vrf_info,
	&frr_staticd_info,
};

FRR_DAEMON_INFO(mgmtd, MGMTD, .vty_port = MGMTD_VTY_PORT,

		.proghelp = "FRR Management Daemon.",

		.signals = mgmt_signals, .n_signals = array_size(mgmt_signals),

		.privs = &mgmt_privs, .yang_modules = mgmt_yang_modules,
		.n_yang_modules = array_size(mgmt_yang_modules), 
);

#define DEPRECATED_OPTIONS ""

/* Main routine of mgmt. Treatment of argument and start mgmt finite
   state machine is handled at here. */
int main(int argc, char **argv)
{
	int opt;
	int tmp_port;

	int mgmt_port = MGMTD_VTY_PORT;
	struct list *addresses = list_new();
	// int no_fib_flag = 0;
	// int no_zebra_flag = 0;
	// int skip_runas = 0;
	// int instance = 0;
	int buffer_size = MGMTD_SOCKET_BUF_SIZE;
	// char *address;
	// struct listnode *node;

	addresses->cmp = (int (*)(void *, void *))strcmp;

	frr_preinit(&mgmtd_di, argc, argv);
	frr_opt_add(
		"p:l:SnZe:I:s:" DEPRECATED_OPTIONS, longopts,
		"  -p, --mgmt_port     Set MGMTD listen port number (0 means do not listen).\n"
		"  -l, --listenon     Listen on specified address (implies -n)\n"
		"  -n, --no_kernel    Do not install route to kernel.\n"
		"  -Z, --no_zebra     Do not communicate with Zebra.\n"
		"  -S, --skip_runas   Skip capabilities checks, and changing user and group IDs.\n"
		"  -e, --ecmp         Specify ECMP to use.\n"
		"  -I, --int_num      Set instance number (label-manager)\n"
		"  -s, --socket_size  Set MGMTD peer socket send buffer size\n");

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
				mgmt_port = MGMTD_VTY_PORT;
			else
				mgmt_port = tmp_port;
			break;
		case 'e': {
#if 0
			unsigned long int parsed_multipath =
				strtoul(optarg, NULL, 10);
			if (parsed_multipath == 0
			    || parsed_multipath > MULTIPATH_NUM
			    || parsed_multipath > UINT_MAX) {
				flog_err(
					EC_MGMTD_MULTIPATH,
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
		memset(&mgmt_privs, 0, sizeof(mgmt_privs));
#endif

	/* MGMTD master init. */
	mgmt_master_init(frr_init(), buffer_size, addresses);

#if 0
	mm->port = mgmt_port;
	if (mgmt_port == 0)
		mgmt_option_set(MGMTD_OPT_NO_LISTEN);
	if (no_fib_flag || no_zebra_flag)
		mgmt_option_set(MGMTD_OPT_NO_FIB);
	if (no_zebra_flag)
		mgmt_option_set(MGMTD_OPT_NO_ZEBRA);
	mgmt_error_init();
#endif

	/* Initializations. */
	mgmt_vrf_init();

#if 0
#ifdef HAVE_SCRIPTING
	mgmt_script_init();
#endif

	hook_register(routing_conf_event,
		      routing_control_plane_protocols_name_validate);

#endif

	/* MGMTD related initialization.  */
	mgmt_init();

#if 0
	if (list_isempty(mm->addresses)) {
		snprintf(mgmtd_di.startinfo, sizeof(mgmtd_di.startinfo),
			 ", mgmt@<all>:%d", mm->port);
	} else {
		for (ALL_LIST_ELEMENTS_RO(mm->addresses, node, address))
			snprintf(mgmtd_di.startinfo + strlen(mgmtd_di.startinfo),
				 sizeof(mgmtd_di.startinfo)
					 - strlen(mgmtd_di.startinfo),
				 ", mgmt@%s:%d", address, mm->port);
	}
#endif

	frr_config_fork();

#if 0
	/* must be called after fork() */
	mgmt_gr_apply_running_config();
#endif
	mgmt_pthreads_run();

	frr_run(mm->master);

	/* Not reached. */
	return 0;
}
