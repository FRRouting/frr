/* NHRP daemon main functions
 * Copyright (c) 2014-2015 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>

#include "zebra.h"
#include "privs.h"
#include "getopt.h"
#include "thread.h"
#include "sigevent.h"
#include "lib/version.h"
#include "log.h"
#include "memory.h"
#include "command.h"
#include "libfrr.h"
#include "filter.h"

#include "nhrpd.h"
#include "nhrp_errors.h"

DEFINE_MGROUP(NHRPD, "NHRP");

unsigned int debug_flags = 0;

struct thread_master *master;
struct timeval current_time;

/* nhrpd options. */
struct option longopts[] = {{0}};

/* nhrpd privileges */
static zebra_capabilities_t _caps_p[] = {
	ZCAP_SYS_ADMIN,
	ZCAP_NET_RAW, ZCAP_NET_ADMIN,
};

struct list *nhrp_vrf_list;
DEFINE_QOBJ_TYPE(nhrp_vrf);

DEFINE_MTYPE_STATIC(NHRPD, NHRP_VRF, "NHRP vrf entry");

struct zebra_privs_t nhrpd_privs = {
#if defined(FRR_USER) && defined(FRR_GROUP)
	.user = FRR_USER,
	.group = FRR_GROUP,
#endif
#ifdef VTY_GROUP
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0
};

static void nhrp_stop_context(struct nhrp_vrf *nhrp_vrf);

static void parse_arguments(int argc, char **argv)
{
	int opt;

	while (1) {
		opt = frr_getopt(argc, argv, 0);
		if (opt < 0)
			break;

		switch (opt) {
		case 0:
			break;
		default:
			frr_help_exit(1);
			break;
		}
	}
}

static void nhrp_sigusr1(void)
{
	zlog_rotate();
}

static void nhrp_request_stop(void)
{
	debugf(NHRP_DEBUG_COMMON, "Exiting...");
	frr_early_fini();

	vrf_terminate();
	nhrp_zebra_terminate_zclient();
	list_delete(&nhrp_vrf_list);
	debugf(NHRP_DEBUG_COMMON, "Done.");
	frr_fini();

	exit(0);
}

static struct quagga_signal_t sighandlers[] = {
	{
		.signal = SIGUSR1,
		.handler = &nhrp_sigusr1,
	},
	{
		.signal = SIGINT,
		.handler = &nhrp_request_stop,
	},
	{
		.signal = SIGTERM,
		.handler = &nhrp_request_stop,
	},
};

static const struct frr_yang_module_info *const nhrpd_yang_modules[] = {
	&frr_filter_info,
	&frr_interface_info,
	&frr_vrf_info,
};

FRR_DAEMON_INFO(nhrpd, NHRP, .vty_port = NHRP_VTY_PORT,

		.proghelp = "Implementation of the NHRP routing protocol.",

		.signals = sighandlers, .n_signals = array_size(sighandlers),

		.privs = &nhrpd_privs, .yang_modules = nhrpd_yang_modules,
		.n_yang_modules = array_size(nhrpd_yang_modules),
);

static void nhrp_start_context(struct nhrp_vrf *nhrp_vrf)
{
	if (nhrp_vrf->vrf_id == VRF_UNKNOWN)
		return;
	nhrp_interface_init_vrf(nhrp_vrf);
	evmgr_init(nhrp_vrf);
	nhrp_vc_init(nhrp_vrf);
	nhrp_packet_init(nhrp_vrf);
	vici_init(nhrp_vrf);
	nhrp_route_init(nhrp_vrf);
	nhrp_nhs_init(nhrp_vrf);
	nhrp_shortcut_init(nhrp_vrf);
}

static void nhrp_stop_context(struct nhrp_vrf *nhrp_vrf)
{
	if (nhrp_vrf->vrf_id == VRF_UNKNOWN)
		return;
	nhrp_shortcut_terminate(nhrp_vrf);
	nhrp_nhs_terminate(nhrp_vrf);
	nhrp_zebra_terminate(nhrp_vrf);
	vici_terminate(nhrp_vrf);
	evmgr_terminate(nhrp_vrf);
	nhrp_vc_terminate(nhrp_vrf);
}

static int nhrp_vrf_new(struct vrf *vrf)
{
	debugf(NHRP_DEBUG_VRF, "VRF Created: %s(%u)", vrf->name, vrf->vrf_id);
	return 0;
}

static int nhrp_vrf_delete(struct vrf *vrf)
{
	debugf(NHRP_DEBUG_VRF, "VRF Deletion: %s(%u)", vrf->name, vrf->vrf_id);
	return 0;
}

static int nhrp_vrf_enable(struct vrf *vrf)
{
	struct nhrp_vrf *nhrp_vrf;

	if (vrf->vrf_id == VRF_DEFAULT)
		return 0;
	debugf(NHRP_DEBUG_VRF, "VRF enable add %s id %u", vrf->name, vrf->vrf_id);
	nhrp_vrf = nhrp_get_context(vrf->name);
	if (nhrp_vrf && nhrp_vrf->vrf_id != vrf->vrf_id) {
		nhrp_vrf->vrf_id = vrf->vrf_id;
		/* start contexts */
		nhrp_start_context(nhrp_vrf);
	}
	return 0;
}

static int nhrp_vrf_disable(struct vrf *vrf)
{
	struct nhrp_vrf *nhrp_vrf;

	debugf(NHRP_DEBUG_VRF, "VRF disable %s id %u", vrf->name, vrf->vrf_id);

	if (vrf->vrf_id == VRF_DEFAULT)
		nhrp_vrf = find_nhrp_vrf(NULL);
	else
		nhrp_vrf = find_nhrp_vrf(vrf->name);

	if (nhrp_vrf && nhrp_vrf->vrf_id != VRF_UNKNOWN) {
		/* stop contexts */
		nhrp_stop_context(nhrp_vrf);
		nhrp_vrf->nhrp_socket_fd = -1;
		nhrp_vrf->vrf_id = VRF_UNKNOWN;
		listnode_delete(nhrp_vrf_list, nhrp_vrf);
		QOBJ_UNREG(nhrp_vrf);
		XFREE(MTYPE_NHRP_VRF, nhrp_vrf);
	}
	return 0;
}

static int nhrp_vrf_config_write(struct vty *vty)
{
	struct vrf *vrf;
	struct nhrp_vrf *nhrp_vrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (vrf->vrf_id == VRF_DEFAULT) {
			vty_out(vty, "!\n");
			continue;
		}
		vty_out(vty, "vrf %s\n", vrf->name);
		nhrp_vrf = find_nhrp_vrf(vrf->name);
		if (nhrp_vrf)
			nhrp_config_write_vrf(vty, nhrp_vrf);
		vty_out(vty, " exit-vrf\n!\n");
	}

	return 0;
}

struct nhrp_vrf *find_nhrp_vrf_id(vrf_id_t vrf_id)
{
	struct listnode *nhrp_vrf_node;
	struct nhrp_vrf *nhrp_vrf;

	if (vrf_id == VRF_UNKNOWN)
		return NULL;
	for (ALL_LIST_ELEMENTS_RO(nhrp_vrf_list, nhrp_vrf_node, nhrp_vrf))
		if (nhrp_vrf->vrf_id == vrf_id)
			return nhrp_vrf;
	return NULL;
}

struct nhrp_vrf *find_nhrp_vrf(const char *vrfname)
{
	struct listnode *nhrp_vrf_node;
	struct nhrp_vrf *nhrp_vrf;

	for (ALL_LIST_ELEMENTS_RO(nhrp_vrf_list, nhrp_vrf_node, nhrp_vrf)) {
		if ((!vrfname && nhrp_vrf->vrfname) ||
		    (vrfname && !nhrp_vrf->vrfname) ||
		    (vrfname && nhrp_vrf->vrfname &&
		     !strmatch(vrfname, nhrp_vrf->vrfname)))
			continue;
		return nhrp_vrf;
	}
	return NULL;
}

struct nhrp_vrf *nhrp_get_context(const char *name)
{
	struct  nhrp_vrf *nhrp_vrf;

	nhrp_vrf = find_nhrp_vrf(name);
	if (!nhrp_vrf) {
		nhrp_vrf = XCALLOC(MTYPE_NHRP_VRF, sizeof(struct nhrp_vrf));
		nhrp_vrf->nhrp_socket_fd = -1;
		QOBJ_REG(nhrp_vrf, nhrp_vrf);
		listnode_add(nhrp_vrf_list, nhrp_vrf);
		nhrp_vrf->vrf_id = VRF_UNKNOWN;
		if (name)
			nhrp_vrf->vrfname = XSTRDUP(MTYPE_NHRP_VRF, name);
		else
			nhrp_vrf->vrf_id = VRF_DEFAULT;
	}
	return nhrp_vrf;
}

int main(int argc, char **argv)
{
	struct nhrp_vrf *nhrp_vrf;

	frr_preinit(&nhrpd_di, argc, argv);
	frr_opt_add("", longopts, "");

	parse_arguments(argc, argv);

	/* Library inits. */
	master = frr_init();
	nhrp_error_init();
	nhrp_vrf_list = list_new();
	vrf_init(nhrp_vrf_new, nhrp_vrf_enable, nhrp_vrf_disable,
		 nhrp_vrf_delete, NULL);
	vrf_cmd_init(nhrp_vrf_config_write, &nhrpd_privs);
	nhrp_interface_init();
	resolver_init(master);

	/*
	 * Run with elevated capabilities, as for all netlink activity
	 * we need privileges anyway.
	 * The assert is for clang SA code where it does
	 * not see the change function being set in lib
	 */
	assert(nhrpd_privs.change);
	nhrpd_privs.change(ZPRIVS_RAISE);

	nhrp_vrf = nhrp_get_context(NULL);
	if_zapi_callbacks(nhrp_ifp_create, nhrp_ifp_up,
			  nhrp_ifp_down, nhrp_ifp_destroy);
	nhrp_start_context(nhrp_vrf);

	nhrp_zebra_init();
	nhrp_config_init();

	frr_config_fork();
	frr_run(master);
	return 0;
}
