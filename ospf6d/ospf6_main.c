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
#include "getopt.h"
#include "thread.h"
#include "log.h"
#include "version.h"
#include "command.h"
#include "vty.h"
#include "memory.h"
#include "privs.h"

#include "ospf6d.h"
#include "ospf6_network.h"

void ospf6_init ();
void ospf6_terminate ();
void nexthop_init ();
int ospf6_receive (struct thread *);

extern int ospf6_sock;

/* Default configuration file name for ospf6d. */
#define OSPF6_DEFAULT_CONFIG       "ospf6d.conf"
/* Default port values. */
#define OSPF6_VTY_PORT             2606

/* ospf6d privileges */
zebra_capabilities_t _caps_p [] = 
{
  ZCAP_RAW,
  ZCAP_BIND
};

struct zebra_privs_t ospf6d_privs =
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

/* ospf6d options, we use GNU getopt library. */
struct option longopts[] = 
{
  { "daemon",      no_argument,       NULL, 'd'},
  { "config_file", required_argument, NULL, 'f'},
  { "pid_file",    required_argument, NULL, 'i'},
  { "vty_addr",    required_argument, NULL, 'A'},
  { "vty_port",    required_argument, NULL, 'P'},
  { "user",        required_argument, NULL, 'u'},
  { "version",     no_argument,       NULL, 'v'},
  { "help",        no_argument,       NULL, 'h'},
  { 0 }
};

/* Configuration file and directory. */
char config_current[] = OSPF6_DEFAULT_CONFIG;
char config_default[] = SYSCONFDIR OSPF6_DEFAULT_CONFIG;

/* ospf6d program name. */

/* is daemon? */
int daemon_mode = 0;

/* Master of threads. */
struct thread_master *master;

/* Process ID saved for use by init system */
char *pid_file = PATH_OSPF6D_PID;

/* for reload */

#ifdef MAXPATHLEN
char _cwd[MAXPATHLEN];
#else
char _cwd[64];
#endif

char _progpath[64];
int _argc;
char **_argv;
char **_envp;

/* Help information display. */
static void
usage (char *progname, int status)
{
  if (status != 0)
    fprintf (stderr, "Try `%s --help' for more information.\n", progname);
  else
    {    
      printf ("Usage : %s [OPTION...]\n\n\
Daemon which manages OSPF version 3.\n\n\
-d, --daemon       Runs in daemon mode\n\
-f, --config_file  Set configuration file name\n\
-i, --pid_file     Set process identifier file name\n\
-A, --vty_addr     Set vty's bind address\n\
-P, --vty_port     Set vty's port number\n\
-u, --user         User and group to run as\n\
-v, --version      Print program version\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to yasu@sfc.wide.ad.jp\n", progname);
    }

  exit (status);
}


void
_reload ()
{
  zlog_notice ("OSPF6d (Zebra-%s ospf6d-%s) reloaded",
               QUAGGA_VERSION, OSPF6_DAEMON_VERSION);
  ospf6_zebra_finish ();
  vty_finish ();
  execve (_progpath, _argv, _envp);
}

void
terminate (int i)
{
  ospf6_delete (ospf6);
  unlink (PATH_OSPF6D_PID);
  zlog_notice ("OSPF6d (Zebra-%s ospf6d-%s) terminated",
               QUAGGA_VERSION, OSPF6_DAEMON_VERSION);
  exit (i);
}

/* SIGHUP handler. */
void 
sighup (int sig)
{
  zlog_info ("SIGHUP received");
  _reload ();
}

/* SIGINT handler. */
void
sigint (int sig)
{
  zlog_info ("SIGINT received");
  terminate (0);
}

/* SIGTERM handler. */
void
sigterm (int sig)
{
  zlog_info ("SIGTERM received");
  terminate (0);
}

/* SIGUSR1 handler. */
void
sigusr1 (int sig)
{
  zlog_info ("SIGUSR1 received");
  zlog_rotate (NULL);
}

/* Signale wrapper. */
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

/* Initialization of signal handles. */
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

/* Main routine of ospf6d. Treatment of argument and start ospf finite
   state machine is handled here. */
int
main (int argc, char *argv[], char *envp[])
{
  char *p;
  int opt;
  char *vty_addr = NULL;
  int vty_port = OSPF6_VTY_PORT;
  char *config_file = NULL;
  char *progname;
  struct thread thread;
  int flag;

  /* Set umask before anything for security */
  umask (0027);

  /* Preserve name of myself. */
  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

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
      opt = getopt_long (argc, argv, "df:i:hp:A:P:u:v", longopts, 0);
    
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
        case 'i':
          pid_file = optarg;
          break;
        case 'P':
         /* Deal with atoi() returning 0 on failure, and ospf6d not
             listening on ospf6d port... */
          if (strcmp(optarg, "0") == 0) 
            {
              vty_port = 0;
              break;
            } 
          vty_port = atoi (optarg);
          vty_port = (vty_port ? vty_port : OSPF6_VTY_PORT);
	  break;
        case 'u':
          ospf6d_privs.user = ospf6d_privs.group = optarg;
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

  /* thread master */
  master = thread_master_create ();

  /* Initializations. */
  if (! daemon_mode)
    flag = ZLOG_STDOUT;
  else
    flag = ZLOG_NOLOG;

  zlog_default = openzlog (progname, flag, ZLOG_OSPF6,
			   LOG_CONS|LOG_NDELAY|LOG_PID,
			   LOG_DAEMON);
	zprivs_init (&ospf6d_privs);
  signal_init ();
  cmd_init (1);
  vty_init (master);
  ospf6_init ();
  memory_init ();
  sort_node ();

  /* parse config file */
  vty_read_config (config_file, config_current, config_default);

  if (daemon_mode)
    daemon (0, 0);

  /* pid file create */
#if 0
  pid_output_lock (pid_file);
#else
  pid_output (pid_file);
#endif

  /* Make ospf protocol socket. */
  ospf6_serv_sock ();
  thread_add_read (master, ospf6_receive, NULL, ospf6_sock);

  /* Make ospf vty socket. */
  vty_serv_sock (vty_addr, vty_port, OSPF6_VTYSH_PATH);

#ifdef DEBUG
  /* Print start message */
  zlog_notice ("OSPF6d (Zebra-%s ospf6d-%s) starts",
               QUAGGA_VERSION, OSPF6_DAEMON_VERSION);
#endif

  /* Start finite state machine, here we go! */
  while (thread_fetch (master, &thread))
    thread_call (&thread);

  /* Log in case thread failed */
  zlog_warn ("Thread failed");
  terminate (0);

  /* Not reached. */
  exit (0);
}

