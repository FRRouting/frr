/* Zebra guile interface.
   Copyright (C) 1998, 99 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#include <libguile.h>
#include "zebra-guile.h"

#include "zebra.h"
#include "thread.h"

struct thread *master;

static void
init_libzebra ()
{
  void cmd_init();
  void vty_init();
  void memory_init();

  cmd_init (1);
  vty_init ();
  memory_init ();
}

/* Install scheme procudures. */
void
init_zebra_guile ()
{
  init_libzebra ();

  init_bgp ();

#if 0
  init_zebra ();
  init_rip ();
  init_ospf ();
#endif /* 0 */
}

static void
inner_main (void *closure, int argc, char **argv)
{
  /* Install zebra related scheme procedures. */
  init_zebra_guile ();

  /* Invoke interpreter. */
  scm_shell (argc, argv);
}

int
main (int argc, char **argv)
{
  scm_boot_guile (argc, argv, inner_main, 0);
  return 0;			/* Not reached */
}
