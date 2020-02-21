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

#ifndef _PATH_PCEP_LIB_H_
#define _PATH_PCEP_LIB_H_

#include <stdbool.h>
#include <pcep_pcc_api.h>
#include "pathd/path_pcep.h"

int pcep_lib_connect(struct pcc_state *pcc_state);
void pcep_lib_disconnect(struct pcc_state *pcc_state);
double_linked_list *pcep_lib_format_path(struct path *path);
void pcep_lib_parse_capabilities(struct pcc_caps *caps,
				 double_linked_list *objs);
struct path *pcep_lib_parse_path(double_linked_list *objs);
void pcep_lib_free_path(struct path *path);


#endif // _PATH_PCEP_LIB_H_