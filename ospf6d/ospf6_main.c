/*
 * Copyright (C) 1999 Yasuhiro Ohara
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the 
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 * Boston, MA 02111-1307, USA.  
 */

#include <zebra.h>
#include <lib/version.h>
#include <stdlib.h>

#include "getopt.h"
#include "thread.h"
#include "log.h"
#include "command.h"
#include "vty.h"
#include "memory.h"
#include "memory_vty.h"
#include "if.h"
#include "filter.h"
#include "prefix.h"
#include "plist.h"
#include "privs.h"
#include "sigevent.h"
#include "zclient.h"
#include "vrf.h"
#include "bfd.h"
#include "libfrr.h"

#include "ospf6d.h"
#include "ospf6_top.h"
#include "ospf6_message.h"
#include "ospf6_asbr.h"
#include "ospf6_lsa.h"
#include "ospf6_interface.h"
#include "ospf6_zebra.h"

/* Default configuration file name for ospf6d. */
#define OSPF6_DEFAULT_CONFIG       "ospf6d.conf"

/* Default port values. */
#define OSPF6_VTY_PORT             2606

/* ospf6d privileges */
zebra_capabilities_t _caps_p [] =
{
  ZCAP_NET_RAW,
  ZCAP_BIND
};

struct zebra_privs_t ospf6d_privs =
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

/* ospf6d options, we use GNU getopt library. */
struct option longopts[] = 
{
  { "daemon",      no_argument,       NULL, 'd'},
  { "config_file", required_argument, NULL, 'f'},
  { "pid_file",    required_argument, NULL, 'i'},
  { "socket",      required_argument, NULL, 'z'},
  { "dryrun",      no_argument,       NULL, 'C'},
  { 0 }
};

/* Configuration file and directory. */
char config_default[] = SYSCONFDIR OSPF6_DEFAULT_CONFIG;

/* is daemon? */
int daemon_mode = 0;

/* Master of threads. */
struct thread_master *master;

/* Process ID saved for use by init system */
const char *pid_file = PATH_OSPF6D_PID;

static void __attribute__ ((noreturn))
ospf6_exit (int status)
{
  struct listnode *node;
  struct interface *ifp;

  if (ospf6)
    ospf6_delete (ospf6);

  bfd_gbl_exit();

  for (ALL_LIST_ELEMENTS_RO (vrf_iflist (VRF_DEFAULT), node, ifp))
    if (ifp->info != NULL)
      ospf6_interface_delete(ifp->info);

  ospf6_message_terminate ();
  ospf6_asbr_terminate ();
  ospf6_lsa_terminate ();

  vrf_terminate ();
  vty_terminate ();
  cmd_terminate ();

  if (zclient)
    zclient_free (zclient);

  if (master)
    thread_master_free (master);

  if (zlog_default)
    closezlog (zlog_default);

  exit (status);
}

/* SIGHUP handler. */
static void 
sighup (void)
{
  zlog_info ("SIGHUP received");
}

/* SIGINT handler. */
static void
sigint (void)
{
  zlog_notice ("Terminating on signal SIGINT");
  ospf6_exit (0);
}

/* SIGTERM handler. */
static void
sigterm (void)
{
  zlog_notice ("Terminating on signal SIGTERM");
  ospf6_clean();
  ospf6_exit (0);
}

/* SIGUSR1 handler. */
static void
sigusr1 (void)
{
  zlog_info ("SIGUSR1 received");
  zlog_rotate (NULL);
}

struct quagga_signal_t ospf6_signals[] =
{
  {
    .signal = SIGHUP,
    .handler = &sighup,
  },
  {
    .signal = SIGINT,
    .handler = &sigint,
  },
  {
    .signal = SIGTERM,
    .handler = &sigterm,
  },
  {
    .signal = SIGUSR1,
    .handler = &sigusr1,
  },
};

FRR_DAEMON_INFO(ospf6d, OSPF6,
	.vty_port = OSPF6_VTY_PORT,

	.proghelp = "Implementation of the OSPFv3 routing protocol.",

	.signals = ospf6_signals,
	.n_signals = array_size(ospf6_signals),

	.privs = &ospf6d_privs,
)

/* Main routine of ospf6d. Treatment of argument and starting ospf finite
   state machine is handled here. */
int
main (int argc, char *argv[], char *envp[])
{
  int opt;
  char *config_file = NULL;
  struct thread thread;
  int dryrun = 0;

  frr_preinit (&ospf6d_di, argc, argv);
  frr_opt_add ("df:i:z:C", longopts,
	"  -d, --daemon       Runs in daemon mode\n"
	"  -f, --config_file  Set configuration file name\n"
	"  -i, --pid_file     Set process identifier file name\n"
	"  -z, --socket       Set path of zebra socket\n"
	"  -C, --dryrun       Check configuration for validity and exit\n");

  /* Command line argument treatment. */
  while (1) 
    {
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
	case 'C':
	  dryrun = 1;
	  break;
        default:
          frr_help_exit (1);
          break;
        }
    }

  if (geteuid () != 0)
    {
      errno = EPERM;
      perror (ospf6d_di.progname);
      exit (1);
    }

  /* thread master */
  master = frr_init ();

  cmd_init (1);
  vty_init (master);
  memory_init ();
  vrf_init ();
  access_list_init ();
  prefix_list_init ();

  /* initialize ospf6 */
  ospf6_init ();

  /* parse config file */
  vty_read_config (config_file, config_default);

  /* Start execution only if not in dry-run mode */
  if (dryrun)
    return(0);
  
  if (daemon_mode && daemon (0, 0) < 0)
    {
      zlog_err("OSPF6d daemon failed: %s", strerror(errno));
      exit (1);
    }

  /* pid file create */
  pid_output (pid_file);

  frr_vty_serv (OSPF6_VTYSH_PATH);

  /* Print start message */
  zlog_notice ("OSPF6d (Quagga-%s ospf6d-%s) starts: vty@%d",
               FRR_VERSION, OSPF6_DAEMON_VERSION, ospf6d_di.vty_port);

  /* Start finite state machine, here we go! */
  while (thread_fetch (master, &thread))
    thread_call (&thread);

  /* Log in case thread failed */
  zlog_warn ("Thread failed");

  /* Not reached. */
  ospf6_exit (0);
}


