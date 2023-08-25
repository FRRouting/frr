// SPDX-License-Identifier: GPL-2.0-or-later
/* Main routine of bgpd.
 * Copyright (C) 1996, 97, 98, 1999 Kunihiro Ishiguro
 */

#include <zebra.h>

#include <pthread.h>
#include "vector.h"
#include "command.h"
#include "getopt.h"
#include "frrevent.h"
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

#include "bgpd/bgpd.h"
#include "bgp_io.h"
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
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_keepalives.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_script.h"
#include "bgpd/bgp_evpn_mh.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_routemap_nb.h"
#include "bgpd/bgp_community_alias.h"

#ifdef ENABLE_BGP_VNC
#include "bgpd/rfapi/rfapi_backend.h"
#endif

/* bgpd options, we use GNU getopt library. */
static const struct option longopts[] = {
	{"bgp_port", required_argument, NULL, 'p'},
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

static void bgp_exit(int);
static void bgp_vrf_terminate(void);

static struct frr_signal_t bgp_signals[] = {
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
	zlog_info("SIGHUP received, ignoring");

	return;

	/*
	 * This is turned off for the moment.  There is all
	 * sorts of config turned off by bgp_terminate
	 * that is not setup properly again in bgp_reset.
	 * I see no easy way to do this nor do I see that
	 * this is a desirable way to reload config
	 * given the yang work.
	 */
	/* Terminate all thread. */
	/*
	 * bgp_terminate();
	 * bgp_reset();
	 * zlog_info("bgpd restarting!");

	 * Reload config file.
	 * vty_read_config(NULL, bgpd_di.config_file, config_default);
	 */
	/* Try to return to normal operation. */
}

/* SIGINT handler. */
__attribute__((__noreturn__)) void sigint(void)
{
	zlog_notice("Terminating on signal");
	assert(bm->terminating == false);
	bm->terminating = true;	/* global flag that shutting down */

	/* Disable BFD events to avoid wasting processing. */
	bfd_protocol_integration_set_shutdown(true);

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
	struct bgp *bgp, *bgp_default, *bgp_evpn;
	struct listnode *node, *nnode;

	/* it only makes sense for this to be called on a clean exit */
	assert(status == 0);

	frr_early_fini();

	bgp_close();

	bgp_default = bgp_get_default();
	bgp_evpn = bgp_get_evpn();

	/* reverse bgp_master_init */
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (bgp_default == bgp || bgp_evpn == bgp)
			continue;
		bgp_delete(bgp);
	}
	if (bgp_evpn && bgp_evpn != bgp_default)
		bgp_delete(bgp_evpn);
	if (bgp_default)
		bgp_delete(bgp_default);

	bgp_evpn_mh_finish();
	bgp_l3nhg_finish();

	/* reverse bgp_dump_init */
	bgp_dump_finish();

	/* BGP community aliases */
	bgp_community_alias_finish();

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
#ifdef ENABLE_BGP_VNC
	vnc_zebra_destroy();
#endif
	bgp_zebra_destroy();

	bf_free(bm->rd_idspace);
	list_delete(&bm->bgp);
	list_delete(&bm->addresses);

	bgp_lp_finish();

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
	if (bgp && bgp->vrf_id != vrf->vrf_id) {
		old_vrf_id = bgp->vrf_id;
		/* We have instance configured, link to VRF and make it "up". */
		bgp_vrf_link(bgp, vrf);

		bgp_handle_socket(bgp, vrf, old_vrf_id, true);
		bgp_instance_up(bgp);
		vpn_leak_zebra_vrf_label_update(bgp, AFI_IP);
		vpn_leak_zebra_vrf_label_update(bgp, AFI_IP6);
		vpn_leak_zebra_vrf_sid_update(bgp, AFI_IP);
		vpn_leak_zebra_vrf_sid_update(bgp, AFI_IP6);
		vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP,
				    bgp_get_default(), bgp);
		vpn_leak_postchange(BGP_VPN_POLICY_DIR_FROMVPN, AFI_IP,
				    bgp_get_default(), bgp);
		vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP6,
				    bgp_get_default(), bgp);
		vpn_leak_postchange(BGP_VPN_POLICY_DIR_FROMVPN, AFI_IP6,
				    bgp_get_default(), bgp);
	}

	return 0;
}

static int bgp_vrf_disable(struct vrf *vrf)
{
	struct bgp *bgp;

	if (vrf->vrf_id == VRF_DEFAULT)
		return 0;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("VRF disable %s id %d", vrf->name, vrf->vrf_id);

	bgp = bgp_lookup_by_name(vrf->name);
	if (bgp) {

		vpn_leak_zebra_vrf_label_withdraw(bgp, AFI_IP);
		vpn_leak_zebra_vrf_label_withdraw(bgp, AFI_IP6);
		vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP,
				   bgp_get_default(), bgp);
		vpn_leak_prechange(BGP_VPN_POLICY_DIR_FROMVPN, AFI_IP,
				   bgp_get_default(), bgp);
		vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP6,
				   bgp_get_default(), bgp);
		vpn_leak_prechange(BGP_VPN_POLICY_DIR_FROMVPN, AFI_IP6,
				   bgp_get_default(), bgp);

		bgp_handle_socket(bgp, vrf, VRF_UNKNOWN, false);
		/* We have instance configured, unlink from VRF and make it
		 * "down". */
		bgp_instance_down(bgp);
		bgp_vrf_unlink(bgp, vrf);
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

static const struct frr_yang_module_info *const bgpd_yang_modules[] = {
	&frr_filter_info,
	&frr_interface_info,
	&frr_route_map_info,
	&frr_vrf_info,
	&frr_bgp_route_map_info,
};

FRR_DAEMON_INFO(bgpd, BGP, .vty_port = BGP_VTY_PORT,

		.proghelp = "Implementation of the BGP routing protocol.",

		.signals = bgp_signals, .n_signals = array_size(bgp_signals),

		.privs = &bgpd_privs, .yang_modules = bgpd_yang_modules,
		.n_yang_modules = array_size(bgpd_yang_modules),
);

#define DEPRECATED_OPTIONS ""

#ifdef FUZZING
#include "lib/ringbuf.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static bool FuzzingInit(void) {
	int bgp_port = BGP_PORT_DEFAULT;
	struct list *addresses = list_new();
	int no_fib_flag = 0;
	int no_zebra_flag = 0;
	int skip_runas = 0;
	int instance = 0;
	int buffer_size = BGP_SOCKET_SNDBUF_SIZE;
	struct listnode *node;

	addresses->cmp = (int (*)(void *, void *))strcmp;

	const char *name[] = { "bgpd" };

	frr_preinit(&bgpd_di, 1, (char **) name);

	/* Initialize basic BGP datastructures */
	bgp_master_init(frr_init_fast(), buffer_size, addresses);
	bm->port = bgp_port;
	bgp_option_set(BGP_OPT_NO_LISTEN);

	bgp_option_set(BGP_OPT_NO_FIB);
	bgp_option_set(BGP_OPT_NO_ZEBRA);
	bgp_error_init();
	// bgp_vrf_init();
	bgp_init((unsigned short)instance);


	/* Create a default instance and peer */
	struct bgp *b;
	as_t as = 65001;
	bgp_get(&b, &as, "default", BGP_INSTANCE_TYPE_DEFAULT, NULL,
		ASNOTATION_UNDEFINED);

	return true;
}

/*
 * Create peer structure that we'll use as the receiver for fuzzed packets.
 *
 * state
 *    BGP FSM state to create the peer in
 */
static struct peer *FuzzingCreatePeer(int state)
{
	union sockunion su;
	sockunion_init(&su);
	inet_pton(AF_INET, "10.1.1.1", &su.sin.sin_addr);
	su.sin.sin_family = AF_INET;
	su.sin.sin_port = 2001;
	struct peer *p = peer_create(&su, NULL, bgp_get_default(), 65000, 65001,
				     AS_UNSPECIFIED, NULL, 1, NULL);
	p->bgp->rpkt_quanta = 1;
	p->status = state;
	p->as_type = AS_EXTERNAL;

	/* set all flags */
	afi_t afi;
	safi_t safi;
	p->cap |= 0xFFFF;
	FOREACH_AFI_SAFI(afi, safi) {
		SET_FLAG(p->af_cap[afi][safi], 0x3FFF);
	}

	peer_activate(p, AFI_L2VPN, SAFI_EVPN);
	peer_activate(p, AFI_IP, SAFI_MPLS_VPN);

	return p;
}

static struct peer *FuzzingPeer;

static bool FuzzingInitialized;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (!FuzzingInitialized) {
		FuzzingInit();
		FuzzingInitialized = true;
		/* See comment below */
		FuzzingPeer = FuzzingCreatePeer(Established);
	}
	//make_route_maps();
	/*
	 * In the AFL standalone case, the peer will already be created for us
	 * before __AFL_INIT() is called to speed things up. We can't pass it
	 * as an argument because the function signature must match libFuzzer's
	 * expectations, so it's saved in a global variable. Even though we'll
	 * be exiting the program after each run, we still destroy the peer
	 * because that increases our coverage and is likely to find memory
	 * leaks when pointers are nulled that would otherwise be "in-use at
	 * exit".
	 *
	 * In the libFuzzer case, we can either create and destroy it each time
	 * to fuzz single packet rx, or we can keep the peer around, which will
	 * fuzz a long lived session. Of course, as state accumulates over
	 * time, memory usage will grow, which imposes some resource
	 * constraints on the fuzzing host. In practice a reasonable server
	 * machine with 64gb of memory or so should be able to fuzz
	 * indefinitely; if bgpd consumes this much memory over time, that
	 * behavior should probably be considered a bug.
	 */
	struct peer *p;
#ifdef FUZZING_LIBFUZZER
	/* For non-persistent mode */
	// p = FuzzingCreatePeer();
	/* For persistent mode */
	p = FuzzingPeer;
#else
	p = FuzzingPeer;
#endif /* FUZZING_LIBFUZZER */

	ringbuf_reset(p->ibuf_work);
	ringbuf_put(p->ibuf_work, data, size);

	int result = 0;
	unsigned char pktbuf[BGP_MAX_PACKET_SIZE];
	uint16_t pktsize = 0;

	/*
	 * Simulate the read process done by bgp_process_reads().
	 *
	 * The actual packet processing code assumes that the size field in the
	 * BGP message is correct, and this check is performed by the i/o code,
	 * so we need to make sure that remains true for fuzzed input.
	 *
	 * Also, validate_header() assumes that there is at least
	 * BGP_HEADER_SIZE bytes in ibuf_work.
	 */
	if ((size < BGP_HEADER_SIZE) || !validate_header(p)) {
		goto done;
	}

	ringbuf_peek(p->ibuf_work, BGP_MARKER_SIZE, &pktsize, sizeof(pktsize));
	pktsize = ntohs(pktsize);

	assert(pktsize <= p->max_packet_size);

	if (ringbuf_remain(p->ibuf_work) >= pktsize) {
		struct stream *pkt = stream_new(pktsize);
		ringbuf_get(p->ibuf_work, pktbuf, pktsize);
		stream_put(pkt, pktbuf, pktsize);
		p->curr = pkt;

		struct event t = {};
		t.arg = p;
		bgp_process_packet(&t);
	}

done:
	//peer_delete(p);

	return 0;
};
#endif /* FUZZING */

#ifndef FUZZING_LIBFUZZER
/* Main routine of bgpd. Treatment of argument and start bgp finite
   state machine is handled at here. */
int main(int argc, char **argv)
{
	int opt;
	int tmp_port;

	int bgp_port = BGP_PORT_DEFAULT;
	struct list *addresses = list_new();
	int no_fib_flag = 0;
	int no_zebra_flag = 0;
	int skip_runas = 0;
	int instance = 0;
	int buffer_size = BGP_SOCKET_SNDBUF_SIZE;
	char *address;
	struct listnode *node;
	//char *bgp_address = NULL;

	//addresses->cmp = (int (*)(void *, void *))strcmp;

	frr_preinit(&bgpd_di, argc, argv);

#ifdef FUZZING
	FuzzingInit();
	FuzzingPeer = FuzzingCreatePeer(Established);
	FuzzingInitialized = true;

#ifdef __AFL_HAVE_MANUAL_CONTROL
	__AFL_INIT();
#endif /* __AFL_HAVE_MANUAL_CONTROL */
	uint8_t *input;
	int r = frrfuzz_read_input(&input);

	if (!input)
		return 0;

	return LLVMFuzzerTestOneInput(input, r);
#endif /* FUZZING */

	frr_opt_add(
		"p:l:SnZe:I:s:" DEPRECATED_OPTIONS, longopts,
		"  -p, --bgp_port     Set BGP listen port number (0 means do not listen).\n"
		"  -l, --listenon     Listen on specified address (implies -n)\n"
		"  -n, --no_kernel    Do not install route to kernel.\n"
		"  -Z, --no_zebra     Do not communicate with Zebra.\n"
		"  -S, --skip_runas   Skip capabilities checks, and changing user and group IDs.\n"
		"  -e, --ecmp         Specify ECMP to use.\n"
		"  -I, --int_num      Set instance number (label-manager)\n"
		"  -s, --socket_size  Set BGP peer socket send buffer size\n");

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
				bgp_port = BGP_PORT_DEFAULT;
			else
				bgp_port = tmp_port;
			break;
		case 'e': {
			unsigned long int parsed_multipath =
				strtoul(optarg, NULL, 10);
			if (parsed_multipath == 0
			    || parsed_multipath > MULTIPATH_NUM
			    || parsed_multipath > UINT_MAX) {
				flog_err(
					EC_BGP_MULTIPATH,
					"Multipath Number specified must be less than %u and greater than 0",
					MULTIPATH_NUM);
				return 1;
			}
			multipath_num = parsed_multipath;
			break;
		}
		case 'l':
			listnode_add_sort_nodup(addresses, optarg);
			break;
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
		case 's':
			buffer_size = atoi(optarg);
			break;
		default:
			frr_help_exit(1);
		}
	}
	if (skip_runas)
		memset(&bgpd_privs, 0, sizeof(bgpd_privs));

	/* BGP master init. */
	bgp_master_init(frr_init(), buffer_size, addresses);
	bm->port = bgp_port;
	if (bgp_port == 0)
		bgp_option_set(BGP_OPT_NO_LISTEN);
	if (no_fib_flag || no_zebra_flag)
		bgp_option_set(BGP_OPT_NO_FIB);
	if (no_zebra_flag)
		bgp_option_set(BGP_OPT_NO_ZEBRA);
	bgp_error_init();
	/* Initializations. */
	bgp_vrf_init();

#ifdef HAVE_SCRIPTING
	bgp_script_init();
#endif

	/* BGP related initialization.  */
	bgp_init((unsigned short)instance);

	if (list_isempty(bm->addresses)) {
		snprintf(bgpd_di.startinfo, sizeof(bgpd_di.startinfo),
			 ", bgp@<all>:%d", bm->port);
	} else {
		for (ALL_LIST_ELEMENTS_RO(bm->addresses, node, address))
			snprintf(bgpd_di.startinfo + strlen(bgpd_di.startinfo),
				 sizeof(bgpd_di.startinfo)
					 - strlen(bgpd_di.startinfo),
				 ", bgp@%s:%d", address, bm->port);
	}

	bgp_if_init();

	frr_config_fork();
	/* must be called after fork() */
	bgp_gr_apply_running_config();
	bgp_pthreads_run();
	frr_run(bm->master);

	/* Not reached. */
	return 0;
}
#endif /* FUZZING_LIBFUZZER */