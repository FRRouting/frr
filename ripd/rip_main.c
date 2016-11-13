/* RIPd main routine.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro <kunihiro@zebra.org>
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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <zebra.h>

#include <lib/version.h>
#include "getopt.h"
#include "thread.h"
#include "command.h"
#include "memory.h"
#include "memory_vty.h"
#include "prefix.h"
#include "filter.h"
#include "keychain.h"
#include "log.h"
#include "privs.h"
#include "sigevent.h"
#include "zclient.h"
#include "vrf.h"
#include "libfrr.h"

#include "ripd/ripd.h"

/* ripd options. */
static struct option longopts[] = 
{
  { "daemon",      no_argument,       NULL, 'd'},
  { "config_file", required_argument, NULL, 'f'},
  { "pid_file",    required_argument, NULL, 'i'},
  { "socket",      required_argument, NULL, 'z'},
  { "dryrun",      no_argument,       NULL, 'C'},
  { "retain",      no_argument,       NULL, 'r'},
  { 0 }
};

/* ripd privileges */
zebra_capabilities_t _caps_p [] = 
{
  ZCAP_NET_RAW,
  ZCAP_BIND
};

struct zebra_privs_t ripd_privs =
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
  .cap_num_p = 2,
  .cap_num_i = 0
};

/* Configuration file and directory. */
char config_default[] = SYSCONFDIR RIPD_DEFAULT_CONFIG;
char *config_file = NULL;

/* ripd program name */

/* VTY Socket prefix */
char vty_sock_path[MAXPATHLEN] = RIP_VTYSH_PATH;

/* Route retain mode flag. */
int retain_mode = 0;

/* Master of threads. */
struct thread_master *master;

/* Process ID saved for use by init system */
const char *pid_file = PATH_RIPD_PID;

/* SIGHUP handler. */
static void 
sighup (void)
{
  zlog_info ("SIGHUP received");
  rip_clean ();
  rip_reset ();
  zlog_info ("ripd restarting!");

  /* Reload config file. */
  vty_read_config (config_file, config_default);

  /* Try to return to normal operation. */
}

/* SIGINT handler. */
static void
sigint (void)
{
  zlog_notice ("Terminating on signal");

  if (! retain_mode)
    rip_clean ();

  exit (0);
}

/* SIGUSR1 handler. */
static void
sigusr1 (void)
{
  zlog_rotate (NULL);
}

static struct quagga_signal_t ripd_signals[] =
{
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

FRR_DAEMON_INFO(ripd, RIP,
	.vty_port = RIP_VTY_PORT,

	.proghelp = "Implementation of the RIP routing protocol.",

	.signals = ripd_signals,
	.n_signals = array_size(ripd_signals),

	.privs = &ripd_privs,
)

/* Main routine of ripd. */
int
main (int argc, char **argv)
{
  int daemon_mode = 0;
  int dryrun = 0;
  struct thread thread;

  frr_preinit (&ripd_di, argc, argv);
  frr_opt_add ("df:i:z:rC", longopts,
	"  -d, --daemon       Runs in daemon mode\n"
	"  -f, --config_file  Set configuration file name\n"
	"  -i, --pid_file     Set process identifier file name\n"
	"  -z, --socket       Set path of zebra socket\n"
	"  -C, --dryrun       Check configuration for validity and exit\n"
	"  -r, --retain       When program terminates, retain added route by ripd.\n");

  /* Command line option parse. */
  while (1) 
    {
      int opt;

      opt = frr_getopt (argc, argv, NULL);
    
      if (opt == EOF)
	break;

      switch (opt) 
	{
	case 0:
	  break;
	case 'd':
	  daemon_mode = 1;
	  break;
	case 'f':
	  config_file = optarg;
	  break;
        case 'i':
          pid_file = optarg;
          break;
	case 'z':
	  zclient_serv_path_set (optarg);
	  break;
	case 'r':
	  retain_mode = 1;
	  break;
	case 'C':
	  dryrun = 1;
	  break;
	default:
	  frr_help_exit (1);
	  break;
	}
    }

  /* Prepare master thread. */
  master = frr_init ();

  /* Library initialization. */
  keychain_init ();
  vrf_init ();

  /* RIP related initialization. */
  rip_init ();
  rip_if_init ();
  rip_zclient_init(master);
  rip_peer_init ();

  /* Get configuration file. */
  vty_read_config (config_file, config_default);

  /* Start execution only if not in dry-run mode */
  if(dryrun)
    return (0);
  
  /* Change to the daemon program. */
  if (daemon_mode && daemon (0, 0) < 0)
    {
      zlog_err("RIPd daemon failed: %s", strerror(errno));
      exit (1);
    }

  /* Pid file create. */
  pid_output (pid_file);

  /* Create VTY's socket */
  frr_vty_serv (RIP_VTYSH_PATH);

  /* Print banner. */
  zlog_notice ("RIPd %s starting: vty@%d", FRR_VERSION, ripd_di.vty_port);

  /* Execute each thread. */
  while (thread_fetch (master, &thread))
    thread_call (&thread);

  /* Not reached. */
  return (0);
}
