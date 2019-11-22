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

#ifndef _PATH_PCEP_DEBUG_H_
#define _PATH_PCEP_DEBUG_H_

#include <pcep_pcc_api.h>
#include <pcep-objects.h>
#include "pathd/path_pcep.h"

const char *format_pcc_opts(pcc_opts_t *ops);
const char *format_pcc_state(pcc_state_t *state);
const char *format_ctrl_state(ctrl_state_t *state);
const char *format_pcep_event(pcep_event *event);
const char *format_pcep_message(pcep_message *msg);

#endif // _PATH_PCEP_DEBUG_H_