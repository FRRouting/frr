// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BFD daemon code
 * Copyright (C) 2018 Network Device Education Foundation, Inc. ("NetDEF")
 */

#include <zebra.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "filter.h"
#include "if.h"
#include "vrf.h"

#include "bfd.h"
#include "bfd_trace.h"
#include "bfdd_nb.h"
#include "bfddp_packet.h"
#include "lib/version.h"
#include "lib/command.h"
#include "lib/plist.h"
#include "lib/hook.h"
#include "lib/keychain.h"
#include "lib/network.h"


/*
 * FRR related code.
 */
DEFINE_MGROUP(BFDD, "Bidirectional Forwarding Detection Daemon");
DEFINE_MTYPE(BFDD, BFDD_CLIENT, "BFD client data");
DEFINE_MTYPE(BFDD, BFDD_CLIENT_NOTIFICATION, "BFD client notification data");

/* Master of threads. */
struct event_loop *master;

/* BFDd privileges */
static zebra_capabilities_t _caps_p[] = {ZCAP_BIND, ZCAP_SYS_ADMIN, ZCAP_NET_RAW};

/* BFD daemon information. */
static struct frr_daemon_info bfdd_di;
static int bfd_process_keychain_remove(const char *keychain_name);

void socket_close(int *s)
{
	if (*s <= 0)
		return;

	if (close(*s) != 0) {
		frrtrace(3, frr_bfd, socket_error, 5, 0, errno);
		zlog_err("%s: close(%d): (%d) %s", __func__, *s, errno,
			 strerror(errno));
	}

	*s = -1;
}

static void sigusr1_handler(void)
{
	zlog_rotate();
}

static FRR_NORETURN void sigterm_handler(void)
{
	bglobal.bg_shutdown = true;

	/* Signalize shutdown. */
	frr_early_fini();

	/* Stop receiving message from zebra. */
	bfdd_zclient_stop();

	keychain_terminate();

	/* Shutdown and free all protocol related memory. */
	bfd_shutdown();

	bfd_vrf_terminate();

	bfdd_zclient_terminate();

	prefix_list_reset();
	access_list_reset();

	/* Terminate and free() FRR related memory. */
	frr_fini();

	exit(0);
}

static void sighup_handler(void)
{
	zlog_info("SIGHUP received");

	/* Reload config file. */
	vty_read_config(NULL, bfdd_di.config_file, config_default);
}

static struct frr_signal_t bfd_signals[] = {
	{
		.signal = SIGUSR1,
		.handler = &sigusr1_handler,
	},
	{
		.signal = SIGTERM,
		.handler = &sigterm_handler,
	},
	{
		.signal = SIGINT,
		.handler = &sigterm_handler,
	},
	{
		.signal = SIGHUP,
		.handler = &sighup_handler,
	},
};

/* clang-format off */

static const struct frr_yang_module_info *const bfdd_yang_modules[] = {
	/* CLI-only filter YANG; do not use frr_filter_info (no filter backend). */
	&frr_filter_cli_info,
	&frr_interface_info,
	&frr_bfdd_info,
	&frr_vrf_info,
	&ietf_key_chain_info,
	&ietf_key_chain_deviation_info,
};

FRR_DAEMON_INFO(bfdd, BFD,
	.vty_port = BFDD_VTY_PORT,
	.proghelp = "Implementation of the BFD protocol.",

	.signals = bfd_signals,
	.n_signals = array_size(bfd_signals),

	.privs = &bglobal.bfdd_privs,

	.yang_modules = bfdd_yang_modules,
	.n_yang_modules = array_size(bfdd_yang_modules),
);

#define OPTION_DPLANEADDR 2000
#define OPTION_VRF_LIST	  20001
static const struct option longopts[] = {
	{ "dplaneaddr", required_argument, NULL, OPTION_DPLANEADDR },
	{ "vrfs", required_argument, NULL, OPTION_VRF_LIST },
	{ 0 }
};
/* clang-format on */

/*
 * BFD daemon related code.
 */
struct bfd_global bglobal;

const struct bfd_diag_str_list diag_list[] = {
	{.str = "control-expired", .type = BD_CONTROL_EXPIRED},
	{.str = "echo-failed", .type = BD_ECHO_FAILED},
	{.str = "neighbor-down", .type = BD_NEIGHBOR_DOWN},
	{.str = "forwarding-reset", .type = BD_FORWARDING_RESET},
	{.str = "path-down", .type = BD_PATH_DOWN},
	{.str = "concatenated-path-down", .type = BD_CONCATPATH_DOWN},
	{.str = "administratively-down", .type = BD_ADMIN_DOWN},
	{.str = "reverse-concat-path-down", .type = BD_REVCONCATPATH_DOWN},
	{.str = NULL},
};

const struct bfd_state_str_list state_list[] = {
	{.str = "admin-down", .type = PTM_BFD_ADM_DOWN},
	{.str = "down", .type = PTM_BFD_DOWN},
	{.str = "init", .type = PTM_BFD_INIT},
	{.str = "up", .type = PTM_BFD_UP},
	{.str = NULL},
};

static void
distributed_bfd_init(const char *arg)
{
	struct network_address address;
	bool is_client;

	if (!network_address_parse(arg, &address, BFD_DATA_PLANE_DEFAULT_PORT)) {
		zlog_err("%s: failed to parse address: %s", __func__, address.error);
		exit(1);
	}

	is_client = !address.listen;

	/* Initialize BFD data plane listening socket. */
	bfd_dplane_init((struct sockaddr *)&address.address, address.address_size, is_client);
}

static void __bfd_process_keychain_updated(const char *keychain_name, bool is_mhop,
					   bool remove_event)
{
	struct bfd_session *bs;
	const struct bfd_session *iter = NULL;
	struct keychain *kc;

	kc = keychain_lookup(keychain_name);

	while ((iter = bfd_session_next(iter, is_mhop, BFD_MODE_TYPE_BFD)) != NULL) {
		bs = (struct bfd_session *)iter;

		if (!bfd_session_auth_config_takes_precedence_over_profile(bs))
			/* Peer-specific config takes precedence */
			continue;

		if (strcmp(keychain_name, bs->peer_profile.auth_config.key_chain_name) != 0)
			/* peer profile keychain name does not match */
			continue;

		if (kc && remove_event == false)
			bs->kc = kc;
		else
			bs->kc = NULL;

		zlog_info("BFD: session [%s], keychain %s %s", bs_to_string(bs), keychain_name,
			  remove_event ? "removed" : "updated");

		bfd_session_apply(bs);
	}
}

static int _bfd_process_keychain_updated(const char *keychain_name, bool remove_event)
{
	struct bfd_profile *bp;

	if (!keychain_name)
		return 0;

	TAILQ_FOREACH (bp, &bplist, entry) {
		if (bp->auth_config.key_chain_name[0] == '\0' ||
		    strcmp(keychain_name, bp->auth_config.key_chain_name) != 0)
			/* profile keychain name does not match */
			continue;

		zlog_info("BFD: profile %s, keychain %s %s", bp->name, keychain_name,
			  remove_event ? "removed" : "updated");

		bfd_profile_update(bp);
	}

	__bfd_process_keychain_updated(keychain_name, false, remove_event);
	__bfd_process_keychain_updated(keychain_name, true, remove_event);
	return 0;
}

static int bfd_process_keychain_remove(const char *keychain_name)
{
	return _bfd_process_keychain_updated(keychain_name, true);
}

static int bfd_process_keychain_update(const char *keychain_name)
{
	return _bfd_process_keychain_updated(keychain_name, false);
}

static void bg_init(void)
{
	struct zebra_privs_t bfdd_privs = {
#if defined(FRR_USER) && defined(FRR_GROUP)
		.user = FRR_USER,
		.group = FRR_GROUP,
#endif
#if defined(VTY_GROUP)
		.vty_group = VTY_GROUP,
#endif
		.caps_p = _caps_p,
		.cap_num_p = array_size(_caps_p),
		.cap_num_i = 0,
	};

	TAILQ_INIT(&bglobal.bg_obslist);

	memcpy(&bglobal.bfdd_privs, &bfdd_privs,
	       sizeof(bfdd_privs));
}

int main(int argc, char *argv[])
{
	char dplane_addr[512];
	char *perm_vrfs = NULL;
	int opt;

	bglobal.bg_use_dplane = false;

	/* Initialize system sockets. */
	bg_init();

	frr_preinit(&bfdd_di, argc, argv);
	frr_opt_add("", longopts,
		    "      --dplaneaddr   Specify BFD data plane address\n"
		    "      ---vrfs <vrf-list>  Comma-separated VRFs to monitor\n");

	while (true) {
		opt = frr_getopt(argc, argv, NULL);
		if (opt == EOF)
			break;

		switch (opt) {
		case OPTION_DPLANEADDR:
			strlcpy(dplane_addr, optarg, sizeof(dplane_addr));
			bglobal.bg_use_dplane = true;
			break;

		case OPTION_VRF_LIST:
			perm_vrfs = XSTRDUP(MTYPE_TMP, optarg);
			break;

		default:
			frr_help_exit(1);
		}
	}

	/* Initialize FRR infrastructure. */
	master = frr_init();

	keychain_init();

	/* Initialize BFD data structures. */
	bfd_initialize();

	bfd_vrf_init(perm_vrfs);

	/* No access_list_init / prefix_list_init (bfdd is not in VTYSH_ACL_CONFIG). */

	/* Initialize zebra connection. */
	bfdd_zclient_init(&bglobal.bfdd_privs);

	/* Install commands. */
	bfdd_vty_init();

	hook_register(keychain_removed, bfd_process_keychain_remove);
	hook_register(keychain_updated, bfd_process_keychain_update);

	/* read configuration file and daemonize  */
	frr_config_fork();

	/* Initialize BFD data plane listening socket. */
	if (bglobal.bg_use_dplane)
		distributed_bfd_init(dplane_addr);

	if (perm_vrfs)
		free(perm_vrfs);

	frr_run(master);
	/* NOTREACHED */

	return 0;
}
