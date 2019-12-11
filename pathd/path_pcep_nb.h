/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Sebastien Merle
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

#ifndef _PATH_PCEP_NB_H_
#define _PATH_PCEP_NB_H_

#include <stdbool.h>
#include <debug.h>

#include "pathd/path_pcep.h"

typedef int (*path_list_cb_t)(path_t *path, void *arg);

void path_nb_list_path(path_list_cb_t cb, void *arg);

int path_nb_commit_candidate_config(struct nb_config *candidate_config,
				    const char *comment);
void path_nb_edit_candidate_config(struct nb_config *candidate_config,
				   const char *xpath,
				   enum nb_operation operation,
				   const char *value);
int path_nb_add_segment_list_segment(const char *segment_list_name,
				     uint32_t index, uint32_t label);
int path_nb_create_segment_list(const char *segment_list_name);
int path_nb_add_candidate_path(uint32_t color, struct ipaddr *endpoint,
			       struct ipaddr *originator,
			       uint32_t discriminator, uint32_t preference,
			       const char *segment_list_name);

#endif // _PATH_PCEP_NB_H_
