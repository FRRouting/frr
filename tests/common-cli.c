/*
 * generic CLI test helper functions
 *
 * Copyright (C) 2015 by David Lamparter,
 *                   for Open Source Routing / NetDEF, Inc.
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

#include <zebra.h>

#include "thread.h"
#include "vty.h"
#include "command.h"
#include "memory.h"
#include "log.h"

#include "common-cli.h"

struct thread_master *master;

int dump_args(struct vty *vty, const char *descr,
              int argc, const char **argv)
{
  int i;
  vty_out (vty, "%s with %d args.%s", descr, argc, VTY_NEWLINE);
  for (i = 0; i < argc; i++)
    {
      vty_out (vty, "[%02d]: %s%s", i, argv[i], VTY_NEWLINE);
    }

  return CMD_SUCCESS;
}

static void vty_do_exit(void)
{
  printf ("\nend.\n");
  exit (0);
}

/* main routine. */
int
main (int argc, char **argv)
{
  struct thread thread;

  /* Set umask before anything for security */
  umask (0027);

  /* master init. */
  master = thread_master_create ();

  zlog_default = openzlog ("common-cli", ZLOG_NONE,
                           LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);
  zlog_set_level (NULL, ZLOG_DEST_SYSLOG, ZLOG_DISABLED);
  zlog_set_level (NULL, ZLOG_DEST_STDOUT, ZLOG_DISABLED);
  zlog_set_level (NULL, ZLOG_DEST_MONITOR, LOG_DEBUG);

  /* Library inits. */
  cmd_init (1);
  host.name = strdup ("test");

  vty_init (master);
  memory_init ();

  test_init ();

  vty_stdio (vty_do_exit);

  /* Fetch next active thread. */
  while (thread_fetch (master, &thread))
    thread_call (&thread);

  /* Not reached. */
  exit (0);
}

