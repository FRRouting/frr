/*
 * IS-IS Rout(e)ing protocol - isis_main.c
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology      
 *                           Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public Licenseas published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.

 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <zebra.h>

#include "getopt.h"
#include "thread.h"
#include "log.h"
#include <lib/version.h>
#include "command.h"
#include "vty.h"
#include "memory.h"
#include "memory_vty.h"
#include "stream.h"
#include "if.h"
#include "privs.h"
#include "sigevent.h"
#include "filter.h"
#include "plist.h"
#include "zclient.h"
#include "vrf.h"
#include "qobj.h"

#include "isisd/dict.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isisd.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_route.h"
#include "isisd/isis_routemap.h"
#include "isisd/isis_zebra.h"
#include "isisd/isis_tlv.h"
#include "isisd/isis_te.h"

/* Default configuration file name */
#define ISISD_DEFAULT_CONFIG "isisd.conf"
/* Default vty port */
#define ISISD_VTY_PORT       2608

/* isisd privileges */
zebra_capabilities_t _caps_p[] = {
  ZCAP_NET_RAW,
  ZCAP_BIND
};

struct zebra_privs_t isisd_privs = {
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
  .cap_num_p = sizeof (_caps_p) / sizeof (*_caps_p),
  .cap_num_i = 0
};

/* isisd options */
#define OPTION_VTYSOCK 1000
struct option longopts[] = {
  {"daemon",      no_argument,       NULL, 'd'},
  {"config_file", required_argument, NULL, 'f'},
  {"pid_file",    required_argument, NULL, 'i'},
  {"socket",      required_argument, NULL, 'z'},
  {"vty_addr",    required_argument, NULL, 'A'},
  {"vty_port",    required_argument, NULL, 'P'},
  {"vty_socket",  required_argument, NULL, OPTION_VTYSOCK},
  {"user",        required_argument, NULL, 'u'},
  {"group",       required_argument, NULL, 'g'},
  {"version",     no_argument,       NULL, 'v'},
  {"dryrun",      no_argument,       NULL, 'C'},
  {"help",        no_argument,       NULL, 'h'},
  {0}
};

/* Configuration file and directory. */
char config_default[] = SYSCONFDIR ISISD_DEFAULT_CONFIG;
char *config_file = NULL;

/* isisd program name. */
char *progname;

/* VTY Socket prefix */
char vty_sock_path[MAXPATHLEN] = ISIS_VTYSH_PATH;

int daemon_mode = 0;

/* Master of threads. */
struct thread_master *master;

/* Process ID saved for use by init system */
const char *pid_file = PATH_ISISD_PID;

/* for reload */
char _cwd[MAXPATHLEN];
char _progpath[MAXPATHLEN];
int _argc;
char **_argv;
char **_envp;

/*
 * Prototypes.
 */
void reload(void);
void sighup(void);
void sigint(void);
void sigterm(void);
void sigusr1(void);


/* Help information display. */
static void
usage (int status)
{
  if (status != 0)
    fprintf (stderr, "Try `%s --help' for more information.\n", progname);
  else
    {
      printf ("Usage : %s [OPTION...]\n\n\
Daemon which manages IS-IS routing\n\n\
-d, --daemon       Runs in daemon mode\n\
-f, --config_file  Set configuration file name\n\
-i, --pid_file     Set process identifier file name\n\
-z, --socket       Set path of zebra socket\n\
-A, --vty_addr     Set vty's bind address\n\
-P, --vty_port     Set vty's port number\n\
    --vty_socket   Override vty socket path\n\
-u, --user         User to run as\n\
-g, --group        Group to run as\n\
-v, --version      Print program version\n\
-C, --dryrun       Check configuration for validity and exit\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to %s\n", progname, FRR_BUG_ADDRESS);
    }

  exit (status);
}


void
reload ()
{
  zlog_debug ("Reload");
  /* FIXME: Clean up func call here */
  vty_reset ();
  (void) isisd_privs.change (ZPRIVS_RAISE);
  execve (_progpath, _argv, _envp);
  zlog_err ("Reload failed: cannot exec %s: %s", _progpath,
      safe_strerror (errno));
}

static __attribute__((__noreturn__)) void
terminate (int i)
{
  exit (i);
}

/*
 * Signal handlers
 */

void
sighup (void)
{
  zlog_debug ("SIGHUP received");
  reload ();

  return;
}

__attribute__((__noreturn__)) void
sigint (void)
{
  zlog_notice ("Terminating on signal SIGINT");
  terminate (0);
}

__attribute__((__noreturn__)) void
sigterm (void)
{
  zlog_notice ("Terminating on signal SIGTERM");
  terminate (0);
}

void
sigusr1 (void)
{
  zlog_debug ("SIGUSR1 received");
  zlog_rotate (NULL);
}

struct quagga_signal_t isisd_signals[] =
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
   .handler = &sigterm,
   },
};

/*
 * Main routine of isisd. Parse arguments and handle IS-IS state machine.
 */
int
main (int argc, char **argv, char **envp)
{
  char *p;
  int opt, vty_port = ISISD_VTY_PORT;
  struct thread thread;
  char *config_file = NULL;
  char *vty_addr = NULL;
  char *vty_sock_name;
  int dryrun = 0;

  /* Get the programname without the preceding path. */
  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  zlog_default = openzlog (progname, ZLOG_ISIS, 0,
			   LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);
  zprivs_init (&isisd_privs);
#if defined(HAVE_CUMULUS)
  zlog_set_level (NULL, ZLOG_DEST_SYSLOG, zlog_default->default_lvl);
#endif

  /* for reload */
  _argc = argc;
  _argv = argv;
  _envp = envp;
  if (getcwd (_cwd, sizeof (_cwd)) == NULL)
    {
      zlog_err ("ISISd: Unable to determine CWD: %d", errno);
      exit (1);
    }

  if (*argv[0] == '.')
    snprintf (_progpath, sizeof (_progpath), "%s/%s", _cwd, _argv[0]);
  else
    snprintf (_progpath, sizeof (_progpath), "%s", argv[0]);

  /* Command line argument treatment. */
  while (1)
    {
      opt = getopt_long (argc, argv, "df:i:z:hA:p:P:u:g:vC", longopts, 0);

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
	case 'A':
	  vty_addr = optarg;
	  break;
	case 'P':
	  /* Deal with atoi() returning 0 on failure, and isisd not
	     listening on isisd port... */
	  if (strcmp (optarg, "0") == 0)
	    {
	      vty_port = 0;
	      break;
	    }
	  vty_port = atoi (optarg);
	  vty_port = (vty_port ? vty_port : ISISD_VTY_PORT);
	  break;
	case OPTION_VTYSOCK:
	  set_socket_path(vty_sock_path, ISIS_VTYSH_PATH, optarg, sizeof (vty_sock_path));
	  break;
	case 'u':
	  isisd_privs.user = optarg;
	  break;
	case 'g':
	  isisd_privs.group = optarg;
	  break;
	case 'v':
	  printf ("ISISd version %s\n", ISISD_VERSION);
	  printf ("Copyright (c) 2001-2002 Sampo Saaristo,"
		  " Ofer Wald and Hannes Gredler\n");
	  print_version ("Zebra");
	  exit (0);
	  break;
	case 'C':
	  dryrun = 1;
	  break;
	case 'h':
	  usage (0);
	  break;
	default:
	  usage (1);
	  break;
	}
    }

  /* thread master */
  master = thread_master_create ();

  /* random seed from time */
  srandom (time (NULL));

  /*
   *  initializations
   */
  signal_init (master, array_size (isisd_signals), isisd_signals);
  cmd_init (1);
  vty_config_lockless ();
  vty_init (master);
  memory_init ();
  access_list_init();
  vrf_init ();
  prefix_list_init();
  isis_init ();
  isis_circuit_init ();
  isis_spf_cmds_init ();
  isis_redist_init ();
  isis_route_map_init();
  isis_mpls_te_init();

  /* create the global 'isis' instance */
  isis_new (1);

  isis_zebra_init(master);

  /* parse config file */
  /* this is needed three times! because we have interfaces before the areas */
  vty_read_config (config_file, config_default);

  /* Start execution only if not in dry-run mode */
  if (dryrun)
    return(0);
  
  /* demonize */
  if (daemon_mode && daemon (0, 0) < 0)
    {
      zlog_err("ISISd daemon failed: %s", strerror(errno));
      return (1);
    }

  /* Process ID file creation. */
  if (pid_file[0] != '\0')
    pid_output (pid_file);

  /* Make isis vty socket. */
  vty_serv_sock (vty_addr, vty_port, vty_sock_path);

  /* Print banner. */
  zlog_notice ("Quagga-ISISd %s starting: vty@%d", FRR_VERSION, vty_port);

  /* Start finite state machine. */
  while (thread_fetch (master, &thread))
    thread_call (&thread);

  /* Not reached. */
  exit (0);
}
