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

/* Should be in pceplib */
#define GET_SR_ERO_SID_LABEL(SID)   ((SID & 0xfffff000) >> 12)
#define GET_SR_ERO_SID_TC(SID)      ((SID & 0x00000e00) >> 9)
#define GET_SR_ERO_SID_S(SID)       ((SID & 0x00000100) >> 8)
#define GET_SR_ERO_SID_TTL(SID)     ((SID & 0x000000ff))


int pcep_lib_connect(pcc_state_t *pcc_state);
void pcep_lib_disconnect(pcc_state_t *pcc_state);
double_linked_list *pcep_lib_format_path(path_t *path);
path_t *pcep_lib_parse_path(double_linked_list *objs);
void pcep_lib_free_path(path_t *path);


#endif // _PATH_PCEP_LIB_H_