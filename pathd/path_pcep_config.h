/*
 * Copyright (C) 2020  NetDEF, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _PATH_PCEP_CONFIG_H_
#define _PATH_PCEP_CONFIG_H_

#include <stdbool.h>
#include <debug.h>

#include "pathd/path_pcep.h"

#define PATH_NB_NO_CHANGE 0
#define PATH_NB_OK 1
#define PATH_NB_ERR -1

typedef int (*path_list_cb_t)(struct path *path, void *arg);

/* Lookup the candidate path and fill up the missing path attributes like name
 * and type. Used for path generated from PCEP message received from the PCE
 * so they contains more information about the candidate path. If no matching
 * policy or candidate path is found, nothing is changed.
 * MUST BE CALLED FROM THE MAIN THREAD */
void path_pcep_refine_path(struct path *path);
struct path *path_pcep_config_get_path(struct lsp_nb_key *key);
void path_pcep_config_list_path(path_list_cb_t cb, void *arg);
int path_pcep_config_initiate_path(struct path *path);
int path_pcep_config_update_path(struct path *path);
struct path *candidate_to_path(struct srte_candidate *candidate);


#endif // _PATH_PCEP_CONFIG_H_
