/* zebra daemon main routine.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
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
#include "command.h"
#include "thread.h"
#include "filter.h"
#include "memory.h"
#include "zebra_memory.h"
#include "memory_vty.h"
#include "prefix.h"
#include "log.h"
#include "plist.h"
#include "privs.h"
#include "sigevent.h"
#include "vrf.h"

#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/debug.h"
#include "zebra/router-id.h"
#include "zebra/irdp.h"
#include "zebra/rtadv.h"
#include "zebra/zebra_fpm.h"
#include "zebra/zebra_ptm.h"
#include "zebra/zebra_ns.h"
#include "zebra/redistribute.h"
#include "zebra/zebra_mpls.h"

#define ZEBRA_PTM_SUPPORT

/* Zebra instance */
struct zebra_t zebrad =
{
  .rtm_table_default = 0,
};

/* process id. */
pid_t pid;

/* VTY Socket prefix */
char vty_sock_path[MAXPATHLEN] = ZEBRA_VTYSH_PATH;

/* Pacify zclient.o in libzebra, which expects this variable. */
struct thread_master *master;

/* Route retain mode flag. */
int retain_mode = 0;

/* Allow non-quagga entities to delete quagga routes */
int allow_delete = 0;

/* Don't delete kernel route. */
int keep_kernel_mode = 0;

#ifdef HAVE_NETLINK
/* Receive buffer size for netlink socket */
u_int32_t nl_rcvbufsize = 4194304;
#endif /* HAVE_NETLINK */

/* Command line options. */
#define OPTION_VTYSOCK 1000
struct option longopts[] = 
{
  { "batch",        no_argument,       NULL, 'b'},
  { "daemon",       no_argument,       NULL, 'd'},
  { "allow_delete", no_argument,       NULL, 'a'},
  { "keep_kernel",  no_argument,       NULL, 'k'},
  { "fpm_format",   required_argument, NULL, 'F'},
  { "config_file",  required_argument, NULL, 'f'},
  { "pid_file",     required_argument, NULL, 'i'},
  { "socket",       required_argument, NULL, 'z'},
  { "help",         no_argument,       NULL, 'h'},
  { "vty_addr",     required_argument, NULL, 'A'},
  { "vty_port",     required_argument, NULL, 'P'},
  { "vty_socket",   required_argument, NULL, OPTION_VTYSOCK },
  { "retain",       no_argument,       NULL, 'r'},
  { "dryrun",       no_argument,       NULL, 'C'},
#ifdef HAVE_NETLINK
  { "nl-bufsize",   required_argument, NULL, 's'},
#endif /* HAVE_NETLINK */
  { "user",         required_argument, NULL, 'u'},
  { "group",        required_argument, NULL, 'g'},
  { "version",      no_argument,       NULL, 'v'},
  { 0 }
};

zebra_capabilities_t _caps_p [] = 
{
  ZCAP_NET_ADMIN,
  ZCAP_SYS_ADMIN,
  ZCAP_NET_RAW,
};

/* zebra privileges to run with */
struct zebra_privs_t zserv_privs =
{
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

/* Default configuration file path. */
char config_default[] = SYSCONFDIR DEFAULT_CONFIG_FILE;

/* Process ID saved for use by init system */
const char *pid_file = PATH_ZEBRA_PID;

/* Help information display. */
static void
usage (char *progname, int status)
{
  if (status != 0)
    fprintf (stderr, "Try `%s --help' for more information.\n", progname);
  else
    {    
      printf ("Usage : %s [OPTION...]\n\n"\
	      "Daemon which manages kernel routing table management and "\
	      "redistribution between different routing protocols.\n\n"\
	      "-b, --batch        Runs in batch mode\n"\
	      "-d, --daemon       Runs in daemon mode\n"\
	      "-a, --allow_delete Allow other processes to delete Quagga Routes\n" \
	      "-f, --config_file  Set configuration file name\n"\
	      "-F, --fpm_format   Set fpm format to 'netlink' or 'protobuf'\n"\
	      "-i, --pid_file     Set process identifier file name\n"\
	      "-z, --socket       Set path of zebra socket\n"\
	      "-k, --keep_kernel  Don't delete old routes which installed by "\
				  "zebra.\n"\
	      "-C, --dryrun       Check configuration for validity and exit\n"\
	      "-A, --vty_addr     Set vty's bind address\n"\
	      "-P, --vty_port     Set vty's port number\n"\
	      "    --vty_socket   Override vty socket path\n"\
	      "-r, --retain       When program terminates, retain added route "\
				  "by zebra.\n"\
	      "-u, --user         User to run as\n"\
	      "-g, --group        Group to run as\n", progname);
#ifdef HAVE_NETLINK
      printf ("-s, --nl-bufsize   Set netlink receive buffer size\n");
#endif /* HAVE_NETLINK */
      printf ("-v, --version      Print program version\n"\
	      "-h, --help         Display this help and exit\n"\
	      "\n"\
	      "Report bugs to %s\n", FRR_BUG_ADDRESS);
    }

  exit (status);
}

/* SIGHUP handler. */
static void 
sighup (void)
{
  zlog_info ("SIGHUP received");

  /* Reload of config file. */
  ;
}

/* SIGINT handler. */
static void
sigint (void)
{
  struct vrf *vrf;
  struct zebra_vrf *zvrf;
  struct zebra_ns *zns;

  zlog_notice ("Terminating on signal");

#ifdef HAVE_IRDP
  irdp_finish();
#endif

  zebra_ptm_finish();
  list_delete_all_node (zebrad.client_list);

  if (retain_mode)
    RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name)
      {
	zvrf = vrf->info;
	if (zvrf)
	  SET_FLAG (zvrf->flags, ZEBRA_VRF_RETAIN);
      }
  vrf_terminate ();

  zns = zebra_ns_lookup (NS_DEFAULT);
  zebra_ns_disable (0, (void **)&zns);

  access_list_reset ();
  prefix_list_reset ();
  route_map_finish ();
  cmd_terminate ();
  vty_terminate ();
  zprivs_terminate (&zserv_privs);
  list_delete (zebrad.client_list);
  work_queue_free (zebrad.ribq);
  if (zebrad.lsp_process_q)
    work_queue_free (zebrad.lsp_process_q);
  meta_queue_free (zebrad.mq);
  thread_master_free (zebrad.master);
  if (zlog_default)
    closezlog (zlog_default);

  exit (0);
}

/* SIGUSR1 handler. */
static void
sigusr1 (void)
{
  zlog_rotate (NULL);
}

struct quagga_signal_t zebra_signals[] =
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

/* Main startup routine. */
int
main (int argc, char **argv)
{
  char *p;
  char *vty_addr = NULL;
  int vty_port = ZEBRA_VTY_PORT;
  char *vty_sock_name;
  int dryrun = 0;
  int batch_mode = 0;
  int daemon_mode = 0;
  char *config_file = NULL;
  char *progname;
  struct thread thread;
  char *zserv_path = NULL;
  char *fpm_format = NULL;

  /* Set umask before anything for security */
  umask (0027);

  /* preserve my name */
  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  zlog_default = openzlog (progname, ZLOG_ZEBRA, 0,
			   LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);
  zprivs_init (&zserv_privs);
#if defined(HAVE_CUMULUS)
  zlog_set_level (NULL, ZLOG_DEST_SYSLOG, zlog_default->default_lvl);
#endif

  while (1) 
    {
      int opt;
  
#ifdef HAVE_NETLINK  
      opt = getopt_long (argc, argv, "bdakf:F:i:z:hA:P:ru:g:vs:C", longopts, 0);
#else
      opt = getopt_long (argc, argv, "bdakf:F:i:z:hA:P:ru:g:vC", longopts, 0);
#endif /* HAVE_NETLINK */

      if (opt == EOF)
	break;

      switch (opt) 
	{
	case 0:
	  break;
	case 'b':
	  batch_mode = 1;
	case 'd':
	  daemon_mode = 1;
	  break;
	case 'a':
	  allow_delete = 1;
	  break;
	case 'k':
	  keep_kernel_mode = 1;
	  break;
	case 'C':
	  dryrun = 1;
	  break;
	case 'f':
	  config_file = optarg;
	  break;
	case 'F':
	  fpm_format = optarg;
	  break;
	case 'A':
	  vty_addr = optarg;
	  break;
        case 'i':
          pid_file = optarg;
          break;
	case 'z':
	  zserv_path = optarg;
	  break;
	case 'P':
	  /* Deal with atoi() returning 0 on failure, and zebra not
	     listening on zebra port... */
	  if (strcmp(optarg, "0") == 0) 
	    {
	      vty_port = 0;
	      break;
	    } 
	  vty_port = atoi (optarg);
	  if (vty_port <= 0 || vty_port > 0xffff)
	    vty_port = ZEBRA_VTY_PORT;
	  break;
	case OPTION_VTYSOCK:
	  set_socket_path(vty_sock_path, ZEBRA_VTYSH_PATH, optarg, sizeof (vty_sock_path));
	  break;
	case 'r':
	  retain_mode = 1;
	  break;
#ifdef HAVE_NETLINK
	case 's':
	  nl_rcvbufsize = atoi (optarg);
	  break;
#endif /* HAVE_NETLINK */
	case 'u':
	  zserv_privs.user = optarg;
	  break;
	case 'g':
	  zserv_privs.group = optarg;
	  break;
	case 'v':
	  print_version (progname);
	  exit (0);
	  break;
	case 'h':
	  usage (progname, 0);
	  break;
	default:
	  usage (progname, 1);
	  break;
	}
    }

  /* Make master thread emulator. */
  zebrad.master = thread_master_create ();

  /* Vty related initialize. */
  signal_init (zebrad.master, array_size(zebra_signals), zebra_signals);
  cmd_init (1);
  vty_config_lockless ();
  vty_init (zebrad.master);
  memory_init ();

  /* Zebra related initialize. */
  zebra_init ();
  rib_init ();
  zebra_if_init ();
  zebra_debug_init ();
  router_id_cmd_init ();
  zebra_vty_init ();
  access_list_init ();
  prefix_list_init ();
#if defined (HAVE_RTADV)
  rtadv_cmd_init ();
#endif
#ifdef HAVE_IRDP
  irdp_init();
#endif
  /* PTM socket */
#ifdef ZEBRA_PTM_SUPPORT
  zebra_ptm_init();
#endif

  zebra_mpls_init ();
  zebra_mpls_vty_init ();

  /* For debug purpose. */
  /* SET_FLAG (zebra_debug_event, ZEBRA_DEBUG_EVENT); */

  /* Initialize NS( and implicitly the VRF module), and make kernel routing socket. */
  zebra_ns_init ();

#ifdef HAVE_SNMP
  zebra_snmp_init ();
#endif /* HAVE_SNMP */

#ifdef HAVE_FPM
  zfpm_init (zebrad.master, 1, 0, fpm_format);
#else
  zfpm_init (zebrad.master, 0, 0, fpm_format);
#endif

  /* Process the configuration file. Among other configuration
  *  directives we can meet those installing static routes. Such
  *  requests will not be executed immediately, but queued in
  *  zebra->ribq structure until we enter the main execution loop.
  *  The notifications from kernel will show originating PID equal
  *  to that after daemon() completes (if ever called).
  */
  vty_read_config (config_file, config_default);

  /* Don't start execution if we are in dry-run mode */
  if (dryrun)
    return(0);
  
  /* Clean up rib. */
  /* rib_weed_tables (); */

  /* Exit when zebra is working in batch mode. */
  if (batch_mode)
    exit (0);

  /* Daemonize. */
  if (daemon_mode && daemon (0, 0) < 0)
    {
      zlog_err("Zebra daemon failed: %s", strerror(errno));
      exit (1);
    }

  /* Output pid of zebra. */
  pid_output (pid_file);

  /* After we have successfully acquired the pidfile, we can be sure
  *  about being the only copy of zebra process, which is submitting
  *  changes to the FIB.
  *  Clean up zebra-originated routes. The requests will be sent to OS
  *  immediately, so originating PID in notifications from kernel
  *  will be equal to the current getpid(). To know about such routes,
  * we have to have route_read() called before.
  */
  if (! keep_kernel_mode)
    rib_sweep_route ();

  /* Needed for BSD routing socket. */
  pid = getpid ();

  /* This must be done only after locking pidfile (bug #403). */
  zebra_zserv_socket_init (zserv_path);

  /* Make vty server socket. */
  vty_serv_sock (vty_addr, vty_port, vty_sock_path);

  /* Print banner. */
  zlog_notice ("Zebra %s starting: vty@%d", FRR_VERSION, vty_port);

  while (thread_fetch (zebrad.master, &thread))
    thread_call (&thread);

  /* Not reached... */
  return 0;
}
