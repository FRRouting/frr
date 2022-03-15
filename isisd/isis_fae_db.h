/* IS-IS Flex-Algo Endpoint Registration Tracking
 *
 * Copyright 2022 6WIND S.A.
 *
 * This file is part of FRRouting.
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __ISIS_FAE_DB_H
#define __ISIS_FAE_DB_H

#include <zebra.h>
#include "lib/fae_db.h"

struct isis_fae_db {
	struct fae_db_head *active;   /* A route exists for this endpoint */
	struct fae_db_head *inactive; /* No route currently exists for
				       * this endpoint
				       */
};

#endif
