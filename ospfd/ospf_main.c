// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFd main routine.
 *   Copyright (C) 1998, 99 Kunihiro Ishiguro, Toshiaki Takada
 */

#include <zebra.h>

#include <lib/version.h>
#include "bfd.h"
#include "getopt.h"
#include "frrevent.h"
#include "prefix.h"
#include "linklist.h"
#include "if.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "filter.h"
#include "plist.h"
#include "stream.h"
#include "log.h"
#include "memory.h"
#include "privs.h"
#include "sigevent.h"
#include "zclient.h"
#include "vrf.h"
#include "libfrr.h"
#include "routemap.h"
#include "keychain.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_vty.h"
#include "ospfd/ospf_bfd.h"
#include "ospfd/ospf_gr.h"
#include "ospfd/ospf_errors.h"
#include "ospfd/ospf_ldp_sync.h"
#include "ospfd/ospf_routemap_nb.h"

#define OSPFD_STATE_NAME	 "%s/ospfd.json", frr_libstatedir
#define OSPFD_INST_STATE_NAME(i) "%s/ospfd-%d.json", frr_runstatedir, i

/* this one includes the path... because the instance number was in the path
 * before :( ... which totally didn't have a mkdir anywhere.
 */
#define OSPFD_COMPAT_STATE_NAME "%s/ospfd-gr.json", frr_libstatedir
#define OSPFD_COMPAT_INST_STATE_NAME(i)                                        \
	"%s-%d/ospfd-gr.json", frr_runstatedir, i

/* ospfd privileges */
zebra_capabilities_t _caps_p[] = {ZCAP_NET_RAW, ZCAP_BIND, ZCAP_NET_ADMIN,
				  ZCAP_SYS_ADMIN};

struct zebra_privs_t ospfd_privs = {
#if defined(FRR_USER) && defined(FRR_GROUP)
	.user = FRR_USER,
	.group = FRR_GROUP,
#endif
#if defined(VTY_GROUP)
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0};

/* OSPFd options. */
const struct option longopts[] = {
	{"instance", required_argument, NULL, 'n'},
	{"apiserver", no_argument, NULL, 'a'},
	{0}
};

/* OSPFd program name */

/* Master of threads. */
struct event_loop *master;

#ifdef SUPPORT_OSPF_API
extern int ospf_apiserver_enable;
#endif /* SUPPORT_OSPF_API */

/* SIGHUP handler. */
static void sighup(void)
{
	zlog_info("SIGHUP received");
}

/* SIGINT / SIGTERM handler. */
static void sigint(void)
{
	zlog_notice("Terminating on signal");
	bfd_protocol_integration_set_shutdown(true);
	ospf_terminate();

	exit(0);
}

/* SIGUSR1 handler. */
static void sigusr1(void)
{
	zlog_rotate();
}

struct frr_signal_t ospf_signals[] = {
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

static const struct frr_yang_module_info *const ospfd_yang_modules[] = {
	&frr_filter_info,
	&frr_interface_info,
	&frr_route_map_info,
	&frr_vrf_info,
	&frr_ospf_route_map_info,
};

/* actual paths filled in main() */
static char state_path[512];
static char state_compat_path[512];
static char *state_paths[] = {
	state_path,
	state_compat_path,
	NULL,
};

/* clang-format off */
FRR_DAEMON_INFO(ospfd, OSPF,
	.vty_port = OSPF_VTY_PORT,
	.proghelp = "Implementation of the OSPFv2 routing protocol.",

	.signals = ospf_signals,
	.n_signals = array_size(ospf_signals),

	.privs = &ospfd_privs,

	.yang_modules = ospfd_yang_modules,
	.n_yang_modules = array_size(ospfd_yang_modules),

	.state_paths = state_paths,
);
/* clang-format on */

/** Max wait time for config to load before accepting hellos */
#define OSPF_PRE_CONFIG_MAX_WAIT_SECONDS 600

static void ospf_config_finish(struct event *t)
{
	zlog_err("OSPF configuration end timer expired after %d seconds.",
		 OSPF_PRE_CONFIG_MAX_WAIT_SECONDS);
}

static void ospf_config_start(void)
{
	EVENT_OFF(t_ospf_cfg);
	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("ospfd config start callback received.");
	event_add_timer(master, ospf_config_finish, NULL,
			OSPF_PRE_CONFIG_MAX_WAIT_SECONDS, &t_ospf_cfg);
}

static void ospf_config_end(void)
{
	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("ospfd config end callback received.");

	EVENT_OFF(t_ospf_cfg);
}

/* OSPFd main routine. */
int main(int argc, char **argv)
{
#ifdef SUPPORT_OSPF_API
	/* OSPF apiserver is disabled by default. */
	ospf_apiserver_enable = 0;
#endif /* SUPPORT_OSPF_API */

	frr_preinit(&ospfd_di, argc, argv);
	frr_opt_add("n:a", longopts,
		    "  -n, --instance     Set the instance id\n"
		    "  -a, --apiserver    Enable OSPF apiserver\n");

	while (1) {
		int opt;

		opt = frr_getopt(argc, argv, NULL);

		if (opt == EOF)
			break;

		switch (opt) {
		case 'n':
			ospfd_di.instance = ospf_instance = atoi(optarg);
			if (ospf_instance < 1)
				exit(0);
			break;
		case 0:
			break;
#ifdef SUPPORT_OSPF_API
		case 'a':
			ospf_apiserver_enable = 1;
			break;
#endif /* SUPPORT_OSPF_API */
		default:
			frr_help_exit(1);
		}
	}

	/* Invoked by a priviledged user? -- endo. */
	if (geteuid() != 0) {
		errno = EPERM;
		perror(ospfd_di.progname);
		exit(1);
	}

	if (ospf_instance) {
		snprintf(state_path, sizeof(state_path),
			 OSPFD_INST_STATE_NAME(ospf_instance));
		snprintf(state_compat_path, sizeof(state_compat_path),
			 OSPFD_COMPAT_INST_STATE_NAME(ospf_instance));
	} else {
		snprintf(state_path, sizeof(state_path), OSPFD_STATE_NAME);
		snprintf(state_compat_path, sizeof(state_compat_path),
			 OSPFD_COMPAT_STATE_NAME);
	}

	/* OSPF master init. */
	ospf_master_init(frr_init());

	/* Initializations. */
	master = om->master;

	/* Library inits. */
	ospf_debug_init();
	ospf_vrf_init();

	access_list_init();
	prefix_list_init();
	keychain_init();

	/* Configuration processing callback initialization. */
	cmd_init_config_callbacks(ospf_config_start, ospf_config_end);

	/* OSPFd inits. */
	ospf_if_init();
	ospf_zebra_init(master, ospf_instance);

	/* OSPF vty inits. */
	ospf_vty_init();
	ospf_vty_show_init();
	ospf_vty_clear_init();

	/* OSPF BFD init */
	ospf_bfd_init(master);

	/* OSPF LDP IGP Sync init */
	ospf_ldp_sync_init();

	ospf_route_map_init();
	ospf_opaque_init();
	ospf_gr_init();
	ospf_gr_helper_init();

	/* OSPF errors init */
	ospf_error_init();

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	return 0;
}
