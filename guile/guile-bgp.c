/* Guile bgp interface.
   Copyright (C) 1999 Kunihiro Ishiguro

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

#include <zebra.h>
#include <guile/gh.h>

#include "log.h"
#include "bgpd/bgpd.h"

/* static SCM scm_mark_bgp (SCM obj); */
static size_t scm_free_bgp (SCM vect);
static int scm_print_bgp (SCM vect, SCM port, scm_print_state *pstate);
static SCM scm_equalp_bgp (SCM a, SCM b);

/* Tag of scheme type of bgp. */
long scm_tag_bgp;

static scm_smobfuns bgp_funs =
{
  scm_mark0, scm_free_bgp, scm_print_bgp, scm_equalp_bgp
};

static int
scm_print_bgp (SCM vect, SCM port, scm_print_state *pstate)
{
  unsigned short num;
  struct bgp *bgp;

  num = 0;
  bgp = (struct bgp *) SCM_CDR (vect);
  num = bgp->as;
  scm_puts ("#<bgp ", port);
  scm_intprint (num, 10, port);
  scm_putc ('>', port);
  return 1;
}

static size_t
scm_free_bgp (SCM obj)
{
  /* dummy function. */
  return 10;
}

static SCM
scm_equalp_bgp (SCM a, SCM b)
{
  
  return SCM_BOOL_F;
}

/* Make bgp instance. */
SCM
scm_router_bgp (SCM as_number)
{
  SCM cell;
  long num;
  struct bgp *bgp;
  struct bgp *bgp_create ();

  SCM_ASSERT (SCM_INUMP (as_number), as_number, SCM_ARG1, "router-bgp");

  SCM_DEFER_INTS;

  num = gh_scm2long (as_number);

  /* Make new bgp object. */
  bgp = bgp_create ();
  bgp->as = num;

  SCM_NEWCELL (cell);
  SCM_SETCAR (cell, scm_tag_bgp);
  SCM_SETCDR (cell, bgp);

  SCM_ALLOW_INTS;

  return cell;
}

#if 0
SCM
scm_router_bgp_list ()
{
  return NULL;
}
#endif

void
init_bgp ()
{
  void bgp_init ();

  bgp_init ();

  /* Initi types. */
  scm_tag_bgp  = scm_newsmob (&bgp_funs);

  gh_new_procedure ("router-bgp", scm_router_bgp, 1, 0, 0);
  /* gh_new_procedure ("router-bgp-list", scm_router_bgp_list, 0, 0, 0); */
}
