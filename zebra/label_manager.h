/*
 * Label Manager header
 *
 * Copyright (C) 2017 by Bingen Eguzkitza,
 *                       Volta Networks Inc.
 *
 * This file is part of FreeRangeRouting (FRR)
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

#ifndef _LABEL_MANAGER_H
#define _LABEL_MANAGER_H

#include <stdint.h>

#include "lib/linklist.h"
#include "lib/thread.h"

typedef uint32_t label_owner_t;
#define NO_OWNER 0

struct label_manager_chunk {
		label_owner_t owner;
		uint32_t start;
		uint32_t end;
};

struct label_manager {
		struct list *lc_list;
};

bool lm_is_external;

int zread_relay_label_chunk_request (struct stream *src);
void label_manager_init (char *lm_zserv_path, struct thread_master *master);
struct label_manager_chunk *assign_label_chunk (label_owner_t owner, uint32_t size);
int release_label_chunk (label_owner_t owner, uint32_t start, uint32_t end);
void label_manager_close (void);

#endif /* _LABEL_MANAGER_H */
