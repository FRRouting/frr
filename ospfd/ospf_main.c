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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
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
#include "memory_vty.h"
#include "privs.h"
#include "sigevent.h"
#include "zclient.h"
#include "vrf.h"
#include "libfrr.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_vty.h"
#include "ospfd/ospf_bfd.h"

/* ospfd privileges */
zebra_capabilities_t _caps_p [] = 
{
  ZCAP_NET_RAW,
  ZCAP_BIND,
  ZCAP_NET_ADMIN,
};

struct zebra_privs_t ospfd_privs =
{
#if defined(FRR_USER) && defined(FRR_GROUP)
  .user = FRR_USER,
  .group = FRR_GROUP,
#endif
#if defined(VTY_GROUP)
  .vty_group = VTY_GROUP,
#endif
  .caps_p = _caps_p,
  .cap_num_p = array_size(_caps_p),
  .cap_num_i = 0
};

/* Configuration filename and directory. */
char config_default[100];

/* OSPFd options. */
struct option longopts[] = 
{
  { "daemon",      no_argument,       NULL, 'd'},
  { "instance",    required_argument, NULL, 'n'},
  { "config_file", required_argument, NULL, 'f'},
  { "pid_file",    required_argument, NULL, 'i'},
  { "socket",      required_argument, NULL, 'z'},
  { "dryrun",      no_argument,       NULL, 'C'},
  { "apiserver",   no_argument,       NULL, 'a'},
  { 0 }
};

/* OSPFd program name */

/* Master of threads. */
struct thread_master *master;

/* Process ID saved for use by init system */
char pid_file[100];

#ifdef SUPPORT_OSPF_API
extern int ospf_apiserver_enable;
#endif /* SUPPORT_OSPF_API */

/* Help information display. */
static void __attribute__ ((noreturn))
usage (char *progname, int status)
{
  if (status != 0)
    fprintf (stderr, "Try `%s --help' for more information.\n", progname);
  else
    {    
      printf ("Usage : %s [OPTION...]\n\
\n\
Report bugs to %s\n", progname, FRR_BUG_ADDRESS);
    }
  exit (status);
}

/* SIGHUP handler. */
static void 
sighup (void)
{
  zlog (NULL, LOG_INFO, "SIGHUP received");
}

/* SIGINT / SIGTERM handler. */
static void
sigint (void)
{
  zlog_notice ("Terminating on signal");
  ospf_terminate ();
}

/* SIGUSR1 handler. */
static void
sigusr1 (void)
{
  zlog_rotate (NULL);
}

struct quagga_signal_t ospf_signals[] =
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

FRR_DAEMON_INFO(ospfd, OSPF,
	.vty_port = OSPF_VTY_PORT,

	.proghelp = "Implementation of the OSPFv2 routing protocol.",

	.signals = ospf_signals,
	.n_signals = array_size(ospf_signals),

	.privs = &ospfd_privs,
)

/* OSPFd main routine. */
int
main (int argc, char **argv)
{
  char vty_path[MAXPATHLEN];
  int daemon_mode = 0;
  char *config_file = NULL;
  u_short instance = 0;
  struct thread thread;
  int dryrun = 0;

#ifdef SUPPORT_OSPF_API
  /* OSPF apiserver is disabled by default. */
  ospf_apiserver_enable = 0;
#endif /* SUPPORT_OSPF_API */

  strcpy(pid_file, PATH_OSPFD_PID);

  frr_preinit (&ospfd_di, argc, argv);
  frr_opt_add ("df:i:n:z:aC", longopts,
	"  -d, --daemon       Runs in daemon mode\n"
	"  -n, --instance     Set the instance id\n"
	"  -f, --config_file  Set configuration file name\n"
	"  -i, --pid_file     Set process identifier file name\n"
	"  -z, --socket       Set path of zebra socket\n"
	"  -a. --apiserver    Enable OSPF apiserver\n"
	"  -C, --dryrun       Check configuration for validity and exit\n");

  while (1) 
    {
      int opt;

      opt = frr_getopt (argc, argv, NULL);
    
      if (opt == EOF)
	break;

      switch (opt) 
	{
	case 'n':
          ospfd_di.instance = instance = atoi(optarg);
          if (instance < 1)
            exit(0);
	  break;
	case 0:
	  break;
	case 'd':
	  daemon_mode = 1;
	  break;
	case 'f':
	  config_file = optarg;
	  break;
        case 'i':
          strcpy(pid_file,optarg);
          break;
	case 'z':
	  zclient_serv_path_set (optarg);
	  break;
#ifdef SUPPORT_OSPF_API
	case 'a':
	  ospf_apiserver_enable = 1;
	  break;
#endif /* SUPPORT_OSPF_API */
	case 'C':
	  dryrun = 1;
	  break;
	default:
	  frr_help_exit (1);
	  break;
	}
    }

  /* Invoked by a priviledged user? -- endo. */
  if (geteuid () != 0)
    {
      errno = EPERM;
      perror (ospfd_di.progname);
      exit (1);
    }

  /* OSPF master init. */
  ospf_master_init (frr_init ());

  /* Initializations. */
  master = om->master;

  /* Library inits. */
  cmd_init (1);
  debug_init ();
  vty_init (master);
  memory_init ();
  vrf_init ();

  access_list_init ();
  prefix_list_init ();

  /* OSPFd inits. */
  ospf_if_init ();
  ospf_zebra_init(master, instance);

  /* OSPF vty inits. */
  ospf_vty_init ();
  ospf_vty_show_init ();
  ospf_vty_clear_init ();

  /* OSPF BFD init */
  ospf_bfd_init();

  ospf_route_map_init ();
#ifdef HAVE_SNMP
  ospf_snmp_init ();
#endif /* HAVE_SNMP */
  ospf_opaque_init ();
  
  /* Need to initialize the default ospf structure, so the interface mode
     commands can be duly processed if they are received before 'router ospf',
     when quagga(ospfd) is restarted */
  if (!ospf_get_instance(instance))
    {
      zlog_err("OSPF instance init failed: %s", strerror(errno));
      exit (1);
    }

  /* Get configuration file. */
  if (instance)
    sprintf(config_default, "%sospfd-%d.conf", SYSCONFDIR, instance);
  else
    sprintf(config_default, "%s%s", SYSCONFDIR, OSPF_DEFAULT_CONFIG);
  vty_read_config (config_file, config_default);

  /* Start execution only if not in dry-run mode */
  if (dryrun)
    return(0);
  
  /* Change to the daemon program. */
  if (daemon_mode && daemon (0, 0) < 0)
    {
      zlog_err("OSPFd daemon failed: %s", strerror(errno));
      exit (1);
    }

  /* Create PID file */
  if (instance)
    {
      char pidfile_temp[100];

      /* Override the single file with file including instance
         number in case of multi-instance */
      if (strrchr(pid_file, '/') != NULL)
          /* cut of pid_file at last / char * to get directory */
          *strrchr(pid_file, '/') = '\0';
      else
          /* pid_file contains no directory - should never happen, but deal with it anyway */
          /* throw-away all pid_file and assume it's only the filename */
          pid_file[0] = '\0';

      snprintf(pidfile_temp, sizeof(pidfile_temp), "%s/ospfd-%d.pid", pid_file, instance );
      strlcpy(pid_file, pidfile_temp, sizeof(pid_file));
    }
  /* Process id file create. */
  pid_output (pid_file);

  /* Create VTY socket */
  strlcpy(vty_path, OSPF_VTYSH_PATH, sizeof(vty_path));
  if (instance)
    {
      char *slash = strrchr(vty_path, '/');
      slash = slash ? slash + 1 : vty_path;
      snprintf(slash, vty_path + sizeof(vty_path) - slash, "ospfd-%d.vty",
                      instance);
    }

  frr_vty_serv (vty_path);

  /* Print banner. */
  zlog_notice ("OSPFd %s starting: vty@%d, %s", FRR_VERSION, ospfd_di.vty_port, vty_path);

  /* Fetch next active thread. */
  while (thread_fetch (master, &thread))
    thread_call (&thread);

  /* Not reached. */
  return (0);
}

