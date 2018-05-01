/*
Copyright 2011 by Matthieu Boutier and Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

/* include zebra library */
#include <zebra.h>
#include "getopt.h"
#include "if.h"
#include "log.h"
#include "thread.h"
#include "privs.h"
#include "sigevent.h"
#include "version.h"
#include "command.h"
#include "vty.h"
#include "memory.h"
#include "libfrr.h"

#include "babel_main.h"
#include "babeld.h"
#include "util.h"
#include "kernel.h"
#include "babel_interface.h"
#include "neighbour.h"
#include "route.h"
#include "xroute.h"
#include "message.h"
#include "resend.h"
#include "babel_zebra.h"

static void babel_fail(void);
static void babel_init_random(void);
static void babel_replace_by_null(int fd);
static void babel_exit_properly(void);
static void babel_save_state_file(void);


struct thread_master *master;     /* quagga's threads handler */
struct timeval babel_now;         /* current time             */

unsigned char myid[8];            /* unique id (mac address of an interface) */
int debug = 0;

int resend_delay = -1;

const unsigned char zeroes[16] = {0};
const unsigned char ones[16] =
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

static const char *state_file = DAEMON_VTY_DIR "/babel-state";

unsigned char protocol_group[16]; /* babel's link-local multicast address */
int protocol_port;                /* babel's port */
int protocol_socket = -1;         /* socket: communicate with others babeld */

static char babel_config_default[] = SYSCONFDIR BABEL_DEFAULT_CONFIG;
static char *babel_vty_addr = NULL;
static int babel_vty_port = BABEL_VTY_PORT;

/* babeld privileges */
static zebra_capabilities_t _caps_p [] =
{
    ZCAP_NET_RAW,
    ZCAP_BIND
};

struct zebra_privs_t babeld_privs =
{
#if defined(FRR_USER)
    .user = FRR_USER,
#endif
#if defined FRR_GROUP
    .group = FRR_GROUP,
#endif
#ifdef VTY_GROUP
    .vty_group = VTY_GROUP,
#endif
    .caps_p = _caps_p,
    .cap_num_p = array_size(_caps_p),
    .cap_num_i = 0
};

static void
babel_sigexit(void)
{
    zlog_notice("Terminating on signal");

    babel_exit_properly();
}

static void
babel_sigusr1 (void)
{
    zlog_rotate ();
}

static struct quagga_signal_t babel_signals[] =
  {
    {
      .signal = SIGUSR1,
      .handler = &babel_sigusr1,
    },
    {
      .signal = SIGINT,
      .handler = &babel_sigexit,
    },
    {
      .signal = SIGTERM,
      .handler = &babel_sigexit,
    },
  };

struct option longopts[] =
  {
    { 0 }
  };

FRR_DAEMON_INFO(babeld, BABELD,
		.vty_port = BABEL_VTY_PORT,
		.proghelp = "Implementation of the BABEL routing protocol.",

		.signals = babel_signals,
		.n_signals = array_size(babel_signals),

		.privs = &babeld_privs,
		)

int
main(int argc, char **argv)
{
    int rc;

    frr_preinit (&babeld_di, argc, argv);
    frr_opt_add ("", longopts, "");
  
    babel_init_random();

    /* set the Babel's default link-local multicast address and Babel's port */
    parse_address("ff02:0:0:0:0:0:1:6", protocol_group, NULL);
    protocol_port = 6696;

    /* get options */
    while(1) {
        int opt;

	opt = frr_getopt (argc, argv, NULL);

	if (opt == EOF)
	  break;

	switch (opt)
	  {
	  case 0:
	    break;
	  default:
	    frr_help_exit (1);
	    break;
	  }
    }

    /* create the threads handler */
    master = frr_init ();

    /* Library inits. */
    zprivs_init (&babeld_privs);
    cmd_init (1);
    vty_init (master);

    resend_delay = BABEL_DEFAULT_RESEND_DELAY;
    change_smoothing_half_life(BABEL_DEFAULT_SMOOTHING_HALF_LIFE);

    babel_replace_by_null(STDIN_FILENO);

    /* init some quagga's dependencies, and babeld's commands */
    babeld_quagga_init();
    /* init zebra client's structure and it's commands */
    /* this replace kernel_setup && kernel_setup_socket */
    babelz_zebra_init ();

    /* Get zebra configuration file. */
    vty_read_config (babeld_di.config_file, babel_config_default);

    /* init buffer */
    rc = resize_receive_buffer(1500);
    if(rc < 0)
        babel_fail();

    schedule_neighbours_check(5000, 1);

    frr_config_fork();
    frr_run(master);

    return 0;
}

static void
babel_fail(void)
{
    exit(1);
}

/* initialize random value, and set 'babel_now' by the way. */
static void
babel_init_random(void)
{
    gettime(&babel_now);
    int rc;
    unsigned int seed;

    rc = read_random_bytes(&seed, sizeof(seed));
    if(rc < 0) {
        zlog_err("read(random): %s", safe_strerror(errno));
        seed = 42;
    }

    seed ^= (babel_now.tv_sec ^ babel_now.tv_usec);
    srandom(seed);
}

/*
 close fd, and replace it by "/dev/null"
 exit if error
 */
static void
babel_replace_by_null(int fd)
{
    int fd_null;
    int rc;

    fd_null = open("/dev/null", O_RDONLY);
    if(fd_null < 0) {
        zlog_err("open(null): %s", safe_strerror(errno));
        exit(1);
    }

    rc = dup2(fd_null, fd);
    if(rc < 0) {
        zlog_err("dup2(null, 0): %s", safe_strerror(errno));
        exit(1);
    }

    close(fd_null);
}

/*
 Load the state file: check last babeld's running state, usefull in case of
 "/etc/init.d/babeld restart"
 */
void
babel_load_state_file(void)
{
    int fd;
    int rc;

    fd = open(state_file, O_RDONLY);
    if(fd < 0 && errno != ENOENT)
        zlog_err("open(babel-state: %s)", safe_strerror(errno));
    rc = unlink(state_file);
    if(fd >= 0 && rc < 0) {
        zlog_err("unlink(babel-state): %s", safe_strerror(errno));
        /* If we couldn't unlink it, it's probably stale. */
        goto fini;
    }
    if(fd >= 0) {
        char buf[100];
        char buf2[100];
        int s;
        long t;
        rc = read(fd, buf, 99);
        if(rc < 0) {
            zlog_err("read(babel-state): %s", safe_strerror(errno));
        } else {
            buf[rc] = '\0';
            rc = sscanf(buf, "%99s %d %ld\n", buf2, &s, &t);
            if(rc == 3 && s >= 0 && s <= 0xFFFF) {
                unsigned char sid[8];
                rc = parse_eui64(buf2, sid);
                if(rc < 0) {
                    zlog_err("Couldn't parse babel-state.");
                } else {
                    struct timeval realnow;
                    debugf(BABEL_DEBUG_COMMON,
                           "Got %s %d %ld from babel-state.",
                           format_eui64(sid), s, t);
                    gettimeofday(&realnow, NULL);
                    if(memcmp(sid, myid, 8) == 0)
                        myseqno = seqno_plus(s, 1);
                    else
                        zlog_err("ID mismatch in babel-state. id=%s; old=%s",
                                 format_eui64(myid),
                                 format_eui64(sid));
                }
            } else {
                zlog_err("Couldn't parse babel-state.");
            }
        }
        goto fini;
    }
fini:
    if (fd >= 0)
        close(fd);
    return ;
}

static void
babel_exit_properly(void)
{
    debugf(BABEL_DEBUG_COMMON, "Exiting...");
    usleep(roughly(10000));
    gettime(&babel_now);

    /* Uninstall and flush all routes. */
    debugf(BABEL_DEBUG_COMMON, "Uninstall routes.");
    flush_all_routes();
    babel_interface_close_all();
    babel_zebra_close_connexion();
    babel_save_state_file();
    debugf(BABEL_DEBUG_COMMON, "Remove pid file.");
    debugf(BABEL_DEBUG_COMMON, "Done.");
    frr_fini();

    exit(0);
}

static void
babel_save_state_file(void)
{
    int fd;
    int rc;

    debugf(BABEL_DEBUG_COMMON, "Save state file.");
    fd = open(state_file, O_WRONLY | O_TRUNC | O_CREAT, 0644);
    if(fd < 0) {
        zlog_err("creat(babel-state): %s", safe_strerror(errno));
        unlink(state_file);
    } else {
        struct timeval realnow;
        char buf[100];
        gettimeofday(&realnow, NULL);
        rc = snprintf(buf, 100, "%s %d %ld\n",
                      format_eui64(myid), (int)myseqno,
                      (long)realnow.tv_sec);
        if(rc < 0 || rc >= 100) {
            zlog_err("write(babel-state): overflow.");
            unlink(state_file);
        } else {
            rc = write(fd, buf, rc);
            if(rc < 0) {
                zlog_err("write(babel-state): %s", safe_strerror(errno));
                unlink(state_file);
            }
            fsync(fd);
        }
        close(fd);
    }
}

void
show_babel_main_configuration (struct vty *vty)
{
    vty_out (vty,
            "state file              = %s\n"
            "configuration file      = %s\n"
            "protocol informations:\n"
            "  multicast address     = %s\n"
            "  port                  = %d\n"
            "vty address             = %s\n"
            "vty port                = %d\n"
            "id                      = %s\n"
            "kernel_metric           = %d\n",
            state_file,
            babeld_di.config_file ? babeld_di.config_file : babel_config_default,
            format_address(protocol_group),
            protocol_port,
            babel_vty_addr ? babel_vty_addr : "None",
            babel_vty_port,
            format_eui64(myid),
            kernel_metric);
}
