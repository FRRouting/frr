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

#include <stdio.h>
#include <zebra.h>
#include <net/ethernet.h>

#include "getopt.h"
#include "thread.h"
#include "log.h"
#include "version.h"
#include "command.h"
#include "vty.h"
#include "memory.h"
#include "stream.h"
#include "if.h"
#include "privs.h"

#include "isisd/dict.h"
#include "include-netbsd/iso.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isisd.h"
#include "isisd/isis_dynhn.h"

/* Default configuration file name */
#define ISISD_DEFAULT_CONFIG "isisd.conf"
/* Default vty port */
#define ISISD_VTY_PORT       2608

/* isisd privileges */
zebra_capabilities_t _caps_p [] = 
{
  ZCAP_RAW,
  ZCAP_BIND
};

struct zebra_privs_t isisd_privs =
{
#if defined(QUAGGA_USER)
  .user = QUAGGA_USER,
#endif
#if defined QUAGGA_GROUP
  .group = QUAGGA_GROUP,
#endif
#ifdef VTY_GROUP
  .vty_group = VTY_GROUP,
#endif
  .caps_p = _caps_p,
  .cap_num_p = 2,
  .cap_num_i = 0
};

/* isisd options */
struct option longopts[] = 
{
  { "daemon",      no_argument,       NULL, 'd'},
  { "config_file", required_argument, NULL, 'f'},
  { "vty_port",    required_argument, NULL, 'P'},
  { "user",        required_argument, NULL, 'u'},
  { "version",     no_argument,       NULL, 'v'},
  { "help",        no_argument,       NULL, 'h'},
  { 0 }
};

/* Configuration file and directory. */
char config_current[] = ISISD_DEFAULT_CONFIG;
char config_default[] = SYSCONFDIR ISISD_DEFAULT_CONFIG;
char *config_file = NULL;

/* isisd program name. */
char *progname;

int daemon_mode = 0;

/* Master of threads. */
struct thread_master *master;


/* for reload */
char _cwd[64];
char _progpath[64];
int _argc;
char **_argv;
char **_envp;


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
-P, --vty_port     Set vty's port number\n\
-u, --user         User and group to run as\n\
-v, --version      Print program version\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to sambo@cs.tut.fi\n", progname);
    }

  exit (status);
}


void
reload ()
{
  zlog_info ("Reload");
  /* FIXME: Clean up func call here */
  vty_finish ();
  execve (_progpath, _argv, _envp);
}

void
terminate (int i)
{
  exit (i);
}

/*
 * Signal handlers
 */
void 
sighup (int sig)
{
  zlog_info ("SIGHUP received");
  reload ();

  return;
}

void
sigint (int sig)
{
  zlog_info ("SIGINT received");
  terminate (0);
  
  return;
}

void
sigterm (int sig)
{
  zlog_info ("SIGTERM received");
  terminate (0);
}

void
sigusr1 (int sig)
{
  zlog_info ("SIGUSR1 received");
  zlog_rotate (NULL);
}

/*
 * Signal wrapper. 
 */
RETSIGTYPE *
signal_set (int signo, void (*func)(int))
{
  int ret;
  struct sigaction sig;
  struct sigaction osig;

  sig.sa_handler = func;
  sigemptyset (&sig.sa_mask);
  sig.sa_flags = 0;
#ifdef SA_RESTART
  sig.sa_flags |= SA_RESTART;
#endif /* SA_RESTART */

  ret = sigaction (signo, &sig, &osig);

  if (ret < 0) 
    return (SIG_ERR);
  else
    return (osig.sa_handler);
}

void
signal_init ()
{
  signal_set (SIGHUP, sighup);
  signal_set (SIGINT, sigint);
  signal_set (SIGTERM, sigterm);
  signal_set (SIGPIPE, SIG_IGN);
#ifdef SIGTSTP
  signal_set (SIGTSTP, SIG_IGN);
#endif
#ifdef SIGTTIN
  signal_set (SIGTTIN, SIG_IGN);
#endif
#ifdef SIGTTOU
  signal_set (SIGTTOU, SIG_IGN);
#endif
  signal_set (SIGUSR1, sigusr1);
}

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

  /* Get the programname without the preceding path. */
  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  zlog_default = openzlog (progname, ZLOG_NOLOG, ZLOG_ISIS,
                           LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);

  
  /* for reload */
  _argc = argc;
  _argv = argv;
  _envp = envp;
  getcwd (_cwd, sizeof (_cwd));
  if (*argv[0] == '.')
    snprintf (_progpath, sizeof (_progpath), "%s/%s", _cwd, _argv[0]);
  else
    snprintf (_progpath, sizeof (_progpath), "%s", argv[0]);
  
  /* Command line argument treatment. */
  while (1) 
    {
      opt = getopt_long (argc, argv, "df:hAp:P:u:v", longopts, 0);
    
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
        case 'A':
          vty_addr = optarg;
          break;
        case 'P':
         /* Deal with atoi() returning 0 on failure, and isisd not
             listening on isisd port... */
          if (strcmp(optarg, "0") == 0) 
            {
              vty_port = 0;
              break;
            } 
          vty_port = atoi (optarg);
          vty_port = (vty_port ? vty_port : ISISD_VTY_PORT);
	  break;
        case 'u':
          isisd_privs.user = isisd_privs.group = optarg;
          break;
          break;
        case 'v':
	  printf("ISISd version %s\n", ISISD_VERSION);
	  printf("Copyright (c) 2001-2002 Sampo Saaristo,"
		 " Ofer Wald and Hannes Gredler\n");
          print_version ("Zebra");
          exit (0);
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
  srand(time(NULL));

  /*
   *  initializations
   */
  zprivs_init (&isisd_privs);
  signal_init ();
  cmd_init (1);
  vty_init (master);
  memory_init ();
  isis_init ();
  dyn_cache_init ();
  sort_node ();

  /* parse config file */ 
  /* this is needed three times! because we have interfaces before the areas */
  vty_read_config (config_file, config_current, config_default);
#if 0
  vty_read_config (config_file, config_current, config_default);
  vty_read_config (config_file, config_current, config_default);
#endif
  /* demonize */
  if (daemon_mode)
    daemon (0, 0);

  /* Process ID file creation. */
  pid_output (PATH_ISISD_PID);

  /* Make isis vty socket. */
  vty_serv_sock (vty_addr, vty_port, ISIS_VTYSH_PATH);
  
  /* Print banner. */
#if defined(ZEBRA_VERSION)
  zlog_info ("ISISd %s starting: vty@%d", ZEBRA_VERSION, vty_port);
#elif defined(QUAGGA_VERSION)
  zlog_info ("Quagga-ISISd %s starting: vty@%d", QUAGGA_VERSION, vty_port);
#endif
#ifdef HAVE_IPV6
  zlog_info ("IPv6 enabled");
#endif
  /* Start finite state machine. */
  while (thread_fetch (master, &thread))
    thread_call (&thread);

  /* Not reached. */
  exit (0);
}










