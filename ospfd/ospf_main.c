/*
 * OSPFd main routine.
 *   Copyright (C) 1998, 99 Kunihiro Ishiguro, Toshiaki Takada
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

#include <lib/version.h>
#include "getopt.h"
#include "thread.h"
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

#ifdef FUZZING
#include "sockopt.h"
#include <netinet/ip.h>
#endif

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
#include "ospfd/ospf_errors.h"

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
struct thread_master *master;

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
	ospf_terminate();
	exit(0);
}

/* SIGUSR1 handler. */
static void sigusr1(void)
{
	zlog_rotate();
}

struct quagga_signal_t ospf_signals[] = {
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
};

FRR_DAEMON_INFO(ospfd, OSPF, .vty_port = OSPF_VTY_PORT,

		.proghelp = "Implementation of the OSPFv2 routing protocol.",

		.signals = ospf_signals, .n_signals = array_size(ospf_signals),

		.privs = &ospfd_privs, .yang_modules = ospfd_yang_modules,
		.n_yang_modules = array_size(ospfd_yang_modules), )

#ifdef FUZZING

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static bool FuzzingInit(void)
{
	unsigned short instance = 0;
	bool created = false;

	const char *name[] = { "ospfd" };

	frr_preinit(&ospfd_di, 1, (char **) &name);


	/* INIT */
	ospf_master_init(frr_init_fast());
	ospf_debug_init();
	ospf_vrf_init();
	access_list_init();
	prefix_list_init();
	ospf_if_init();
	ospf_zebra_init(master, instance);
	ospf_bfd_init();
	ospf_route_map_init();
	ospf_opaque_init();
	ospf_error_init();

	return true;
}

static struct ospf *FuzzingCreateOspf(void)
{
	struct prefix p;
	struct interface *ifp = if_create_ifindex(69, 0);
	ifp->mtu = 68;
	str2prefix("11.0.2.0/24", &p);

	bool created;
	struct ospf *o = ospf_get_instance(0, &created);
	o->fd = 69;

	struct in_addr in;
	inet_pton(AF_INET, "0.0.0.0", &in);
	struct ospf_area *a = ospf_area_new(o, in);

	struct connected *c = connected_add_by_prefix(ifp, &p, NULL);
	add_ospf_interface(c, a);

	struct ospf_interface *oi = listhead(a->oiflist)->data;
	oi->state = 7; // ISM_DR

	o->fuzzing_packet_ifp = ifp;

	return o;
}

static struct ospf *FuzzingOspf;
static bool FuzzingInitialized;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (!FuzzingInitialized) {
		FuzzingInit();
		FuzzingInitialized = true;
		FuzzingOspf = FuzzingCreateOspf();
	}

	struct ospf *o;

#ifdef FUZZING_LIBFUZZER
	o = FuzzingCreateOspf();
#else
	o = FuzzingOspf;
#endif

	/* Simulate the read process done by ospf_recv_packet */
	stream_put(o->ibuf, data, size);
	{
		struct ip *iph;
		unsigned short ip_len = 0;

		if (size < sizeof(struct ip))
			goto done;

		iph = (struct ip *)STREAM_DATA(o->ibuf);
		sockopt_iphdrincl_swab_systoh(iph);
		ip_len = iph->ip_len;

		// skipping platform #ifdefs as I test on linux right now
		// skipping ifindex lookup as it will fail anyway

		if (size != ip_len)
			goto done;
	}

	ospf_read_helper(o);

done:
	stream_reset(o->ibuf);

	return 0;
}
#endif


#ifndef FUZZING_LIBFUZZER
/* OSPFd main routine. */
int main(int argc, char **argv)
{
#ifdef FUZZING

	FuzzingInitialized = FuzzingInit();
	FuzzingOspf = FuzzingCreateOspf();

#ifdef __AFL_HAVE_MANUAL_CONTROL
	__AFL_INIT();
#endif
	uint8_t *input;
	int r = frrfuzz_read_input(&input);

	if (r < 0 || !input)
		goto done;

	LLVMFuzzerTestOneInput(input, r);
done:
	return 0;
#endif

	unsigned short instance = 0;

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
			ospfd_di.instance = instance = atoi(optarg);
			if (instance < 1)
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
			break;
		}
	}

	/* Invoked by a priviledged user? -- endo. */
	if (geteuid() != 0) {
		errno = EPERM;
		perror(ospfd_di.progname);
		exit(1);
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

	/* OSPFd inits. */
	ospf_if_init();
	ospf_zebra_init(master, instance);

	/* OSPF vty inits. */
	ospf_vty_init();
	ospf_vty_show_init();
	ospf_vty_clear_init();

	/* OSPF BFD init */
	ospf_bfd_init();

	ospf_route_map_init();
	ospf_opaque_init();

	/* OSPF errors init */
	ospf_error_init();

	/*
	 * Need to initialize the default ospf structure, so the interface mode
	 * commands can be duly processed if they are received before 'router
	 * ospf',  when ospfd is restarted
	 */
	bool created = false;
	if (instance && !ospf_get_instance(instance, &created)) {
		flog_err(EC_OSPF_INIT_FAIL, "OSPF instance init failed: %s",
			 strerror(errno));
		exit(1);
	}

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	return 0;
}
#endif
