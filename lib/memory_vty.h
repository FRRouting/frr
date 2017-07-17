/* Memory management routine
 * Copyright (C) 1998 Kunihiro Ishiguro
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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_MEMORY_VTY_H
#define _ZEBRA_MEMORY_VTY_H

#include "memory.h"

extern void memory_init(void);

/* Human friendly string for given byte count */
#define MTYPE_MEMSTR_LEN 20
extern const char *mtype_memstr(char *, size_t, unsigned long);
#endif /* _ZEBRA_MEMORY_VTY_H */
