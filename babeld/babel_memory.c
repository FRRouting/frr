/* babeld memory type definitions
 *
 * Copyright (C) 2017  Donald Sharp
 *
 * This file is part of FRR
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "babel_memory.h"

DEFINE_MGROUP(BABELD, "babeld")
DEFINE_MTYPE(BABELD, BABEL,             "Babel Structure")
DEFINE_MTYPE(BABELD, BABEL_IF,          "Babel Interface")

/* For Emacs:          */
/* Local Variables:    */
/* indent-tabs-mode: t */
/* c-basic-offset: 8   */
/* End:                */
