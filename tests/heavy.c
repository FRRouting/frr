/*
 * $Id: heavy.c,v 1.2 2005/04/21 16:58:44 paul Exp $
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

/* This programme shows the effects of 'heavy' long-running functions
 * on the cooperative threading model.
 *
 * Run it with a config file containing 'password whatever', telnet to it
 * (it defaults to port 4000) and enter the 'clear foo string' command.
 * then type whatever and observe that the vty interface is unresponsive
 * for quite a period of time, due to the clear_something command
 * taking a very long time to complete.
 */
#include <zebra.h>

#include <lib/version.h>
#include "getopt.h"
#include "thread.h"
#include "vty.h"
#include "command.h"
#include "memory.h"
#include <math.h>

struct thread_master *master;

struct option longopts[] = 
{
  { "daemon",      no_argument,       NULL, 'd'},
  { "config_file", required_argument, NULL, 'f'},
  { "help",        no_argument,       NULL, 'h'},
  { "vty_addr",    required_argument, NULL, 'A'},
  { "vty_port",    required_argument, NULL, 'P'},
  { "version",     no_argument,       NULL, 'v'},
  { 0 }
};

enum
{
  ITERS_FIRST = 0,
  ITERS_ERR = 100,
  ITERS_LATER = 400,
  ITERS_PRINT = 10,
  ITERS_MAX = 1000,
};

static void
slow_func (struct vty *vty, const char *str, const int i)
{
  double x = 1;
  int j;
  
  for (j = 0; j < 300000; j++)
    x += sin(x)*j;
  
  if ((i % ITERS_LATER) == 0)
    printf ("%s: %d, temporary error, save this somehow and do it later..\n", 
            __func__, i);
  
  if ((i % ITERS_ERR) == 0)
    printf ("%s: hard error\n", __func__);
  
  if ((i % ITERS_PRINT) == 0)
    printf ("%s did %d, x = %g%s", str, i, x, VTY_NEWLINE);  
}

static void
clear_something (struct vty *vty, const char *str)
{
  int i;
  
  /* this could be like iterating through 150k of route_table 
   * or worse, iterating through a list of peers, to bgp_stop them with
   * each having 150k route tables to process...
   */
  for (i = ITERS_FIRST; i < ITERS_MAX; i++)
    slow_func (vty, str, i);
}

DEFUN (daemon_exit,
       daemon_exit_cmd,
       "daemon-exit",
       "Make the daemon exit\n")
{
  exit(0);
}

DEFUN (clear_foo,
       clear_foo_cmd,
       "clear foo .LINE",
       "clear command\n"
       "arbitrary string\n")
{
  char *str;
  if (!argc)
    {
      vty_out (vty, "%% string argument required%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  
  str = argv_concat (argv, argc, 0);
  
  clear_something (vty, str);
  XFREE (MTYPE_TMP, str);
  return CMD_SUCCESS;
}

static int timer_count;
int
heavy_timer (struct thread *thread)
{
  int *count = THREAD_ARG(thread);
  
  printf ("run %d of timer\n", (*count)++);
  thread_add_timer (master, heavy_timer, count, 5);
  return 0;
}

static void
heavy_timer_init()
{
  thread_add_timer (master, heavy_timer, &timer_count, 5);
}

static void
slow_vty_init()
{
  install_element (VIEW_NODE, &clear_foo_cmd);
  install_element (VIEW_NODE, &daemon_exit_cmd);
}

/* Help information display. */
static void
usage (char *progname, int status)
{
  if (status != 0)
    fprintf (stderr, "Try `%s --help' for more information.\n", progname);
  else
    {    
      printf ("Usage : %s [OPTION...]\n\
Daemon which does 'slow' things.\n\n\
-d, --daemon       Runs in daemon mode\n\
-f, --config_file  Set configuration file name\n\
-A, --vty_addr     Set vty's bind address\n\
-P, --vty_port     Set vty's port number\n\
-v, --version      Print program version\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to %s\n", progname, ZEBRA_BUG_ADDRESS);
    }
  exit (status);
}


/* main routine. */
int
main (int argc, char **argv)
{
  char *p;
  char *vty_addr = NULL;
  int vty_port = 4000;
  int daemon_mode = 0;
  char *progname;
  struct thread thread;
  char *config_file = NULL;
  
  /* Set umask before anything for security */
  umask (0027);

  /* get program name */
  progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);

  /* master init. */
  master = thread_master_create ();

  while (1) 
    {
      int opt;

      opt = getopt_long (argc, argv, "dhf:A:P:v", longopts, 0);
    
      if (opt == EOF)
	break;

      switch (opt) 
	{
	case 0:
	  break;
        case 'f':
          config_file = optarg;
          break;
	case 'd':
	  daemon_mode = 1;
	  break;
	case 'A':
	  vty_addr = optarg;
	  break;
	case 'P':
          /* Deal with atoi() returning 0 on failure */
          if (strcmp(optarg, "0") == 0)
            {
              vty_port = 0;
              break;
            } 
          vty_port = atoi (optarg);
          vty_port = (vty_port ? vty_port : 4000);
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

  /* Library inits. */
  cmd_init (1);
  vty_init (master);
  memory_init ();

  /* OSPF vty inits. */
  slow_vty_init ();

  sort_node ();

  /* Change to the daemon program. */
  if (daemon_mode)
    daemon (0, 0);

  /* Create VTY socket */
  vty_serv_sock (vty_addr, vty_port, "/tmp/.heavy.sock");
  
  /* Configuration file read*/
  if (!config_file)
    usage (progname, 1);
  vty_read_config (config_file, NULL);
  
  heavy_timer_init();
  
  /* Fetch next active thread. */
  while (thread_fetch (master, &thread))
    thread_call (&thread);

  /* Not reached. */
  exit (0);
}

