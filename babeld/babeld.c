// SPDX-License-Identifier: MIT
/*
Copyright 2011 by Matthieu Boutier and Juliusz Chroboczek
*/

#include <zebra.h>
#include "command.h"
#include "prefix.h"
#include "memory.h"
#include "table.h"
#include "distribute.h"
#include "prefix.h"
#include "filter.h"
#include "plist.h"
#include "lib_errors.h"
#include "network.h"
#include "if.h"

#include "babel_main.h"
#include "babeld.h"
#include "util.h"
#include "net.h"
#include "kernel.h"
#include "babel_interface.h"
#include "neighbour.h"
#include "route.h"
#include "message.h"
#include "resend.h"
#include "babel_filter.h"
#include "babel_zebra.h"
#include "babel_errors.h"

#ifndef VTYSH_EXTRACT_PL
#include "babeld/babeld_clippy.c"
#endif

DEFINE_MGROUP(BABELD, "babeld");
DEFINE_MTYPE_STATIC(BABELD, BABEL, "Babel Structure");

static void babel_init_routing_process(struct event *thread);
static void babel_get_myid(void);
static void babel_initial_noise(void);
static void babel_read_protocol(struct event *thread);
static void babel_main_loop(struct event *thread);
static void babel_set_timer(struct timeval *timeout);
static void babel_fill_with_next_timeout(struct timeval *tv);
static void
babel_distribute_update (struct distribute_ctx *ctx, struct distribute *dist);

/* Informations relative to the babel running daemon. */
static struct babel *babel_routing_process = NULL;
static unsigned char *receive_buffer = NULL;
static int receive_buffer_size = 0;

/* timeouts */
struct timeval check_neighbours_timeout;
static time_t expiry_time;
static time_t source_expiry_time;

/* Babel node structure. */
static int babel_config_write (struct vty *vty);
static struct cmd_node cmd_babel_node =
{
    .name = "babel",
    .node   = BABEL_NODE,
    .parent_node = CONFIG_NODE,
    .prompt = "%s(config-router)# ",
    .config_write = babel_config_write,
};

/* print current babel configuration on vty */
static int
babel_config_write (struct vty *vty)
{
    int lines = 0;
    int afi;
    int i;

    /* list enabled debug modes */
    lines += debug_babel_config_write (vty);

    if (!babel_routing_process)
        return lines;
    vty_out (vty, "router babel\n");
    if (diversity_kind != DIVERSITY_NONE)
    {
        vty_out (vty, " babel diversity\n");
        lines++;
    }
    if (diversity_factor != BABEL_DEFAULT_DIVERSITY_FACTOR)
    {
        vty_out (vty, " babel diversity-factor %d\n",diversity_factor);
        lines++;
    }
    if (resend_delay != BABEL_DEFAULT_RESEND_DELAY)
    {
        vty_out (vty, " babel resend-delay %u\n", resend_delay);
        lines++;
    }
    if (smoothing_half_life != BABEL_DEFAULT_SMOOTHING_HALF_LIFE)
    {
        vty_out (vty, " babel smoothing-half-life %u\n",
                 smoothing_half_life);
        lines++;
    }
    /* list enabled interfaces */
    lines = 1 + babel_enable_if_config_write (vty);
    /* list redistributed protocols */
    for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
        for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (i != zclient->redist_default &&
		    vrf_bitmap_check(&zclient->redist[afi][i], VRF_DEFAULT)) {
			vty_out(vty, " redistribute %s %s\n",
				(afi == AFI_IP) ? "ipv4" : "ipv6",
				zebra_route_string(i));
			lines++;
		}
	}
    }

    lines += config_write_distribute (vty, babel_routing_process->distribute_ctx);

    vty_out (vty, "exit\n");

    return lines;
}


static int
babel_create_routing_process (void)
{
    assert (babel_routing_process == NULL);

    /* Allocaste Babel instance. */
    babel_routing_process = XCALLOC(MTYPE_BABEL, sizeof(struct babel));

    /* Initialize timeouts */
    gettime(&babel_now);
    expiry_time = babel_now.tv_sec + roughly(30);
    source_expiry_time = babel_now.tv_sec + roughly(300);

    /* Make socket for Babel protocol. */
    protocol_socket = babel_socket(protocol_port);
    if (protocol_socket < 0) {
        flog_err_sys(EC_LIB_SOCKET, "Couldn't create link local socket: %s",
		  safe_strerror(errno));
        goto fail;
    }

    /* Threads. */
    event_add_read(master, babel_read_protocol, NULL, protocol_socket,
		   &babel_routing_process->t_read);
    /* wait a little: zebra will announce interfaces, addresses, routes... */
    event_add_timer_msec(master, babel_init_routing_process, NULL, 200L,
			 &babel_routing_process->t_update);

    /* Distribute list install. */
    babel_routing_process->distribute_ctx = distribute_list_ctx_create (vrf_lookup_by_id(VRF_DEFAULT));
    distribute_list_add_hook (babel_routing_process->distribute_ctx, babel_distribute_update);
    distribute_list_delete_hook (babel_routing_process->distribute_ctx, babel_distribute_update);
    return 0;
fail:
    XFREE(MTYPE_BABEL, babel_routing_process);
    return -1;
}

/* thread reading entries form others babel daemons */
static void babel_read_protocol(struct event *thread)
{
    int rc;
    struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
    struct interface *ifp = NULL;
    struct sockaddr_in6 sin6;

    assert(babel_routing_process != NULL);
    assert(protocol_socket >= 0);

    rc = babel_recv(protocol_socket,
                    receive_buffer, receive_buffer_size,
                    (struct sockaddr*)&sin6, sizeof(sin6));
    if(rc < 0) {
        if(errno != EAGAIN && errno != EINTR) {
            flog_err_sys(EC_LIB_SOCKET, "recv: %s", safe_strerror(errno));
        }
    } else {
        FOR_ALL_INTERFACES(vrf, ifp) {
            if(!if_up(ifp))
                continue;
            if(ifp->ifindex == (ifindex_t)sin6.sin6_scope_id) {
                parse_packet((unsigned char*)&sin6.sin6_addr, ifp,
                             receive_buffer, rc);
                break;
            }
        }
    }

    /* re-add thread */
    event_add_read(master, &babel_read_protocol, NULL, protocol_socket,
		   &babel_routing_process->t_read);
}

/* Zebra will give some information, especially about interfaces. This function
 must be call with a litte timeout wich may give zebra the time to do his job,
 making these inits have sense. */
static void babel_init_routing_process(struct event *thread)
{
    myseqno = (frr_weak_random() & 0xFFFF);
    babel_get_myid();
    babel_load_state_file();
    debugf(BABEL_DEBUG_COMMON, "My ID is : %s.", format_eui64(myid));
    babel_initial_noise();
    babel_main_loop(thread);/* this function self-add to the t_update thread */
}

/* fill "myid" with an unique id (only if myid != {0}). */
static void
babel_get_myid(void)
{
    struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
    struct interface *ifp = NULL;
    int rc;
    int i;

    /* if we already have an id (from state file), we return. */
    if (memcmp(myid, zeroes, 8) != 0) {
        return;
    }

    FOR_ALL_INTERFACES(vrf, ifp) {
        /* ifp->ifindex is not necessarily valid at this point */
        int ifindex = if_nametoindex(ifp->name);
        if(ifindex > 0) {
            unsigned char eui[8];
            rc = if_eui64(ifindex, eui);
            if(rc < 0)
                continue;
            memcpy(myid, eui, 8);
            return;
        }
    }

    /* We failed to get a global EUI64 from the interfaces we were given.
     Let's try to find an interface with a MAC address. */
    for(i = 1; i < 256; i++) {
        char buf[INTERFACE_NAMSIZ], *ifname;
        unsigned char eui[8];
        ifname = if_indextoname(i, buf);
        if(ifname == NULL)
            continue;
        rc = if_eui64(i, eui);
        if(rc < 0)
            continue;
        memcpy(myid, eui, 8);
        return;
    }

    flog_err(EC_BABEL_CONFIG, "Couldn't find router id -- using random value.");

    rc = read_random_bytes(myid, 8);
    if(rc < 0) {
        flog_err(EC_BABEL_CONFIG, "read(random): %s (cannot assign an ID)",
		  safe_strerror(errno));
        exit(1);
    }
    /* Clear group and global bits */
    UNSET_FLAG (myid[0], 3);
}

/* Make some noise so that others notice us, and send retractions in
 case we were restarted recently */
static void
babel_initial_noise(void)
{
    struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
    struct interface *ifp = NULL;

    FOR_ALL_INTERFACES(vrf, ifp) {
        if(!if_up(ifp))
            continue;
        /* Apply jitter before we send the first message. */
        usleep(roughly(10000));
        gettime(&babel_now);
        send_hello(ifp);
        send_wildcard_retraction(ifp);
    }

    FOR_ALL_INTERFACES(vrf, ifp) {
        if(!if_up(ifp))
            continue;
        usleep(roughly(10000));
        gettime(&babel_now);
        send_hello(ifp);
        send_wildcard_retraction(ifp);
        send_self_update(ifp);
        send_request(ifp, NULL, 0);
        flushupdates(ifp);
        flushbuf(ifp);
    }
}

/* Delete all the added babel routes, make babeld only speak to zebra. */
static void
babel_clean_routing_process(void)
{
    flush_all_routes();
    babel_interface_close_all();

    /* cancel events */
    event_cancel(&babel_routing_process->t_read);
    event_cancel(&babel_routing_process->t_update);

    distribute_list_delete(&babel_routing_process->distribute_ctx);
    XFREE(MTYPE_BABEL, babel_routing_process);
}

/* Function used with timeout. */
static void babel_main_loop(struct event *thread)
{
    struct timeval tv;
    struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
    struct interface *ifp = NULL;

    while(1) {
        gettime(&babel_now);

        /* timeouts --------------------------------------------------------- */
        /* get the next timeout */
        babel_fill_with_next_timeout(&tv);
        /* if there is no timeout, we must wait. */
        if(timeval_compare(&tv, &babel_now) > 0) {
            timeval_minus(&tv, &tv, &babel_now);
            debugf(BABEL_DEBUG_TIMEOUT, "babel main loop : timeout: %lld msecs",
                   (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000);
            /* it happens often to have less than 1 ms, it's bad. */
            timeval_add_msec(&tv, &tv, 300);
            babel_set_timer(&tv);
	    return;
	}

        gettime(&babel_now);

        /* update database -------------------------------------------------- */
        if(timeval_compare(&check_neighbours_timeout, &babel_now) < 0) {
            int msecs;
            msecs = check_neighbours();
            /* Multiply by 3/2 to allow neighbours to expire. */
            msecs = MAX(3 * msecs / 2, 10);
            schedule_neighbours_check(msecs, 1);
        }

        if(babel_now.tv_sec >= expiry_time) {
            expire_routes();
            expire_resend();
            expiry_time = babel_now.tv_sec + roughly(30);
        }

        if(babel_now.tv_sec >= source_expiry_time) {
            expire_sources();
            source_expiry_time = babel_now.tv_sec + roughly(300);
        }

        FOR_ALL_INTERFACES(vrf, ifp) {
            babel_interface_nfo *babel_ifp = NULL;
            if(!if_up(ifp))
                continue;
            babel_ifp = babel_get_if_nfo(ifp);
            if(timeval_compare(&babel_now, &babel_ifp->hello_timeout) >= 0)
                send_hello(ifp);
            if(timeval_compare(&babel_now, &babel_ifp->update_timeout) >= 0)
                send_update(ifp, 0, NULL, 0);
            if(timeval_compare(&babel_now,
                               &babel_ifp->update_flush_timeout) >= 0)
                flushupdates(ifp);
        }

        if(resend_time.tv_sec != 0) {
            if(timeval_compare(&babel_now, &resend_time) >= 0)
                do_resend();
        }

        if(unicast_flush_timeout.tv_sec != 0) {
            if(timeval_compare(&babel_now, &unicast_flush_timeout) >= 0)
                flush_unicast(1);
        }

        FOR_ALL_INTERFACES(vrf, ifp) {
            babel_interface_nfo *babel_ifp = NULL;
            if(!if_up(ifp))
                continue;
            babel_ifp = babel_get_if_nfo(ifp);
            if(babel_ifp->flush_timeout.tv_sec != 0) {
                if(timeval_compare(&babel_now, &babel_ifp->flush_timeout) >= 0)
                    flushbuf(ifp);
            }
        }
    }

    assert(0); /* this line should never be reach */
}

static void
printIfMin(struct timeval *tv, int cmd, const char *tag, const char *ifname)
{
    static struct timeval curr_tv;
    static char buffer[200];
    static const char *curr_tag = NULL;

    switch (cmd) {
        case 0: /* reset timeval */
            curr_tv = *tv;
            if(ifname != NULL) {
                snprintf(buffer, 200L, "interface: %s; %s", ifname, tag);
                curr_tag = buffer;
            } else {
                curr_tag = tag;
            }
            break;
        case 1: /* take the min */
            if (tv->tv_sec == 0 && tv->tv_usec == 0) { /* if (tv == ∞) */
                break;
            }
            if (tv->tv_sec < curr_tv.tv_sec ||(tv->tv_sec == curr_tv.tv_sec &&
                                               tv->tv_usec < curr_tv.tv_usec)) {
                curr_tv = *tv;
                if(ifname != NULL) {
                    snprintf(buffer, 200L, "interface: %s; %s", ifname, tag);
                    curr_tag = buffer;
                } else {
                    curr_tag = tag;
                }
            }
            break;
        case 2: /* print message */
            debugf(BABEL_DEBUG_TIMEOUT, "next timeout due to: %s", curr_tag);
            break;
        default:
            break;
    }
}

static void
babel_fill_with_next_timeout(struct timeval *tv)
{
#if (defined NO_DEBUG)
#define printIfMin(a,b,c,d)
#else
#define printIfMin(a, b, c, d)                                                 \
	if (unlikely(debug & BABEL_DEBUG_TIMEOUT)) {                           \
		printIfMin(a, b, c, d);                                        \
	}

	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp = NULL;

	*tv = check_neighbours_timeout;
	printIfMin(tv, 0, "check_neighbours_timeout", NULL);
	timeval_min_sec(tv, expiry_time);
	printIfMin(tv, 1, "expiry_time", NULL);
	timeval_min_sec(tv, source_expiry_time);
	printIfMin(tv, 1, "source_expiry_time", NULL);
	timeval_min(tv, &resend_time);
	printIfMin(tv, 1, "resend_time", NULL);
	FOR_ALL_INTERFACES (vrf, ifp) {
		babel_interface_nfo *babel_ifp = NULL;
		if (!if_up(ifp))
			continue;
		babel_ifp = babel_get_if_nfo(ifp);
		timeval_min(tv, &babel_ifp->flush_timeout);
		printIfMin(tv, 1, "flush_timeout", ifp->name);
		timeval_min(tv, &babel_ifp->hello_timeout);
		printIfMin(tv, 1, "hello_timeout", ifp->name);
		timeval_min(tv, &babel_ifp->update_timeout);
		printIfMin(tv, 1, "update_timeout", ifp->name);
		timeval_min(tv, &babel_ifp->update_flush_timeout);
		printIfMin(tv, 1, "update_flush_timeout", ifp->name);
	}
	timeval_min(tv, &unicast_flush_timeout);
	printIfMin(tv, 1, "unicast_flush_timeout", NULL);
	printIfMin(tv, 2, NULL, NULL);
#undef printIfMin
#endif
}

/* set the t_update thread of the babel routing process to be launch in
 'timeout' (approximate at the milisecond) */
static void
babel_set_timer(struct timeval *timeout)
{
    long msecs = timeout->tv_sec * 1000 + timeout->tv_usec / 1000;
    event_cancel(&(babel_routing_process->t_update));
    event_add_timer_msec(master, babel_main_loop, NULL, msecs,
			 &babel_routing_process->t_update);
}

void
schedule_neighbours_check(int msecs, int override)
{
    struct timeval timeout;

    timeval_add_msec(&timeout, &babel_now, msecs);
    if(override)
        check_neighbours_timeout = timeout;
    else
        timeval_min(&check_neighbours_timeout, &timeout);
}

int
resize_receive_buffer(int size)
{
    if(size <= receive_buffer_size)
        return 0;

    if(receive_buffer == NULL) {
        receive_buffer = malloc(size);
        if(receive_buffer == NULL) {
            flog_err(EC_BABEL_MEMORY, "malloc(receive_buffer): %s",
		      safe_strerror(errno));
            return -1;
        }
        receive_buffer_size = size;
    } else {
        unsigned char *new;
        new = realloc(receive_buffer, size);
        if(new == NULL) {
            flog_err(EC_BABEL_MEMORY, "realloc(receive_buffer): %s",
		      safe_strerror(errno));
            return -1;
        }
        receive_buffer = new;
        receive_buffer_size = size;
    }
    return 1;
}

static void
babel_distribute_update (struct distribute_ctx *ctx, struct distribute *dist)
{
    struct interface *ifp;
    babel_interface_nfo *babel_ifp;
    int type;
    int family;

    if (! dist->ifname)
        return;

    ifp = if_lookup_by_name (dist->ifname, VRF_DEFAULT);
    if (ifp == NULL)
        return;

    babel_ifp = babel_get_if_nfo(ifp);

    for (type = 0; type < DISTRIBUTE_MAX; type++) {
        family = type == DISTRIBUTE_V4_IN || type == DISTRIBUTE_V4_OUT ?
                  AFI_IP : AFI_IP6;
        if (dist->list[type])
            babel_ifp->list[type] = access_list_lookup (family,
                                                        dist->list[type]);
        else
            babel_ifp->list[type] = NULL;
        if (dist->prefix[type])
            babel_ifp->prefix[type] = prefix_list_lookup (family,
                                                          dist->prefix[type]);
        else
            babel_ifp->prefix[type] = NULL;
    }
}

static void
babel_distribute_update_interface (struct interface *ifp)
{
    struct distribute *dist = NULL;

    if (babel_routing_process)
        dist = distribute_lookup(babel_routing_process->distribute_ctx, ifp->name);
    if (dist)
        babel_distribute_update (babel_routing_process->distribute_ctx, dist);
}

/* Update all interface's distribute list. */
static void
babel_distribute_update_all (struct prefix_list *notused)
{
    struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
    struct interface *ifp;

    FOR_ALL_INTERFACES (vrf, ifp)
        babel_distribute_update_interface (ifp);
}

static void
babel_distribute_update_all_wrapper (struct access_list *notused)
{
    babel_distribute_update_all(NULL);
}


/* [Command] */
DEFUN_NOSH (router_babel,
	    router_babel_cmd,
	    "router babel",
	    "Enable a routing process\n"
	    "Make Babel instance command\n")
{
    int ret;

    vty->node = BABEL_NODE;

    if (!babel_routing_process) {
        ret = babel_create_routing_process ();

        /* Notice to user we couldn't create Babel. */
        if (ret < 0) {
            zlog_warn ("can't create Babel");
            return CMD_WARNING;
        }
    }

    return CMD_SUCCESS;
}

/* [Command] */
DEFUN (no_router_babel,
       no_router_babel_cmd,
       "no router babel",
       NO_STR
       "Disable a routing process\n"
       "Remove Babel instance command\n")
{
    if(babel_routing_process)
        babel_clean_routing_process();
    return CMD_SUCCESS;
}

/* [Babel Command] */
DEFUN (babel_diversity,
       babel_diversity_cmd,
       "babel diversity",
       "Babel commands\n"
       "Enable diversity-aware routing.\n")
{
    diversity_kind = DIVERSITY_CHANNEL;
    return CMD_SUCCESS;
}

/* [Babel Command] */
DEFUN (no_babel_diversity,
       no_babel_diversity_cmd,
       "no babel diversity",
       NO_STR
       "Babel commands\n"
       "Disable diversity-aware routing.\n")
{
    diversity_kind = DIVERSITY_NONE;
    return CMD_SUCCESS;
}

/* [Babel Command] */
DEFPY (babel_diversity_factor,
       babel_diversity_factor_cmd,
       "[no] babel diversity-factor (1-256)$factor",
       NO_STR
       "Babel commands\n"
       "Set the diversity factor.\n"
       "Factor in units of 1/256.\n")
{
    diversity_factor = no ? BABEL_DEFAULT_DIVERSITY_FACTOR : factor;
    return CMD_SUCCESS;
}

/* [Babel Command] */
DEFPY (babel_set_resend_delay,
       babel_set_resend_delay_cmd,
       "[no] babel resend-delay (20-655340)$delay",
       NO_STR
       "Babel commands\n"
       "Time before resending a message\n"
       "Milliseconds\n")
{
    resend_delay = no ? BABEL_DEFAULT_RESEND_DELAY : delay;
    return CMD_SUCCESS;
}

/* [Babel Command] */
DEFPY (babel_set_smoothing_half_life,
       babel_set_smoothing_half_life_cmd,
       "[no] babel smoothing-half-life (0-65534)$seconds",
       NO_STR
       "Babel commands\n"
       "Smoothing half-life\n"
       "Seconds (0 to disable)\n")
{
    change_smoothing_half_life(no ? BABEL_DEFAULT_SMOOTHING_HALF_LIFE
        : seconds);
    return CMD_SUCCESS;
}

DEFUN (babel_distribute_list,
       babel_distribute_list_cmd,
       "distribute-list [prefix] ACCESSLIST4_NAME <in|out> [WORD]",
       "Filter networks in routing updates\n"
       "Specify a prefix\n"
       "Access-list name\n"
       "Filter incoming routing updates\n"
       "Filter outgoing routing updates\n"
       "Interface name\n")
{
	const char *ifname = NULL;
	int prefix = (argv[1]->type == WORD_TKN) ? 1 : 0;

	if (argv[argc - 1]->type == VARIABLE_TKN)
		ifname = argv[argc - 1]->arg;

	return distribute_list_parser(prefix, true, argv[2 + prefix]->text,
				      argv[1 + prefix]->arg, ifname);
}

DEFUN (babel_no_distribute_list,
       babel_no_distribute_list_cmd,
       "no distribute-list [prefix] ACCESSLIST4_NAME <in|out> [WORD]",
       NO_STR
       "Filter networks in routing updates\n"
       "Specify a prefix\n"
       "Access-list name\n"
       "Filter incoming routing updates\n"
       "Filter outgoing routing updates\n"
       "Interface name\n")
{
	const char *ifname = NULL;
	int prefix = (argv[2]->type == WORD_TKN) ? 1 : 0;

	if (argv[argc - 1]->type == VARIABLE_TKN)
		ifname = argv[argc - 1]->arg;

	return distribute_list_no_parser(vty, prefix, true,
					 argv[3 + prefix]->text,
					 argv[2 + prefix]->arg, ifname);
}

DEFUN (babel_ipv6_distribute_list,
       babel_ipv6_distribute_list_cmd,
       "ipv6 distribute-list [prefix] ACCESSLIST6_NAME <in|out> [WORD]",
       "IPv6\n"
       "Filter networks in routing updates\n"
       "Specify a prefix\n"
       "Access-list name\n"
       "Filter incoming routing updates\n"
       "Filter outgoing routing updates\n"
       "Interface name\n")
{
	const char *ifname = NULL;
	int prefix = (argv[2]->type == WORD_TKN) ? 1 : 0;

	if (argv[argc - 1]->type == VARIABLE_TKN)
		ifname = argv[argc - 1]->arg;

	return distribute_list_parser(prefix, false, argv[3 + prefix]->text,
				      argv[2 + prefix]->arg, ifname);
}

DEFUN (babel_no_ipv6_distribute_list,
       babel_no_ipv6_distribute_list_cmd,
       "no ipv6 distribute-list [prefix] ACCESSLIST6_NAME <in|out> [WORD]",
       NO_STR
       "IPv6\n"
       "Filter networks in routing updates\n"
       "Specify a prefix\n"
       "Access-list name\n"
       "Filter incoming routing updates\n"
       "Filter outgoing routing updates\n"
       "Interface name\n")
{
	const char *ifname = NULL;
	int prefix = (argv[3]->type == WORD_TKN) ? 1 : 0;

	if (argv[argc - 1]->type == VARIABLE_TKN)
		ifname = argv[argc - 1]->arg;

	return distribute_list_no_parser(vty, prefix, false,
					 argv[4 + prefix]->text,
					 argv[3 + prefix]->arg, ifname);
}

void
babeld_quagga_init(void)
{

    install_node(&cmd_babel_node);

    install_element(CONFIG_NODE, &router_babel_cmd);
    install_element(CONFIG_NODE, &no_router_babel_cmd);

    install_default(BABEL_NODE);
    install_element(BABEL_NODE, &babel_diversity_cmd);
    install_element(BABEL_NODE, &no_babel_diversity_cmd);
    install_element(BABEL_NODE, &babel_diversity_factor_cmd);
    install_element(BABEL_NODE, &babel_set_resend_delay_cmd);
    install_element(BABEL_NODE, &babel_set_smoothing_half_life_cmd);

    install_element(BABEL_NODE, &babel_distribute_list_cmd);
    install_element(BABEL_NODE, &babel_no_distribute_list_cmd);
    install_element(BABEL_NODE, &babel_ipv6_distribute_list_cmd);
    install_element(BABEL_NODE, &babel_no_ipv6_distribute_list_cmd);

    vrf_cmd_init(NULL);

    babel_if_init();

    /* Access list install. */
    access_list_init ();
    access_list_add_hook (babel_distribute_update_all_wrapper);
    access_list_delete_hook (babel_distribute_update_all_wrapper);

    /* Prefix list initialize.*/
    prefix_list_init ();
    prefix_list_add_hook (babel_distribute_update_all);
    prefix_list_delete_hook (babel_distribute_update_all);
}

/* Stubs to adapt Babel's filtering calls to Quagga's infrastructure. */

int
input_filter(const unsigned char *id,
             const unsigned char *prefix, unsigned short plen,
             const unsigned char *neigh, unsigned int ifindex)
{
    return babel_filter(0, prefix, plen, ifindex);
}

int
output_filter(const unsigned char *id, const unsigned char *prefix,
              unsigned short plen, unsigned int ifindex)
{
    return babel_filter(1, prefix, plen, ifindex);
}

/* There's no redistribute filter in Quagga -- the zebra daemon does its
   own filtering. */
int
redistribute_filter(const unsigned char *prefix, unsigned short plen,
                    unsigned int ifindex, int proto)
{
    return 0;
}

struct babel *babel_lookup(void)
{
    return babel_routing_process;
}
