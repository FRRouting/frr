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

#ifndef _PATH_DEBUG_H_
#define _PATH_DEBUG_H_

#include "pathd/pathd.h"

#ifdef __GNUC__
#define THREAD_DATA __thread
#else
#define THREAD_DATA
#endif

#define DEBUG_IDENT_SIZE 4
#define DEBUG_BUFF_SIZE 4096
#define TUP(A, B) ((((uint32_t)(A)) << 16) | ((uint32_t)(B)))
#define PATHD_FORMAT_INIT() _debug_buff[0] = 0
#define PATHD_FORMAT(fmt, ...)                                                 \
	csnprintfrr(_debug_buff, DEBUG_BUFF_SIZE, fmt, ##__VA_ARGS__)
#define PATHD_FORMAT_FINI() _debug_buff

extern THREAD_DATA char _debug_buff[DEBUG_BUFF_SIZE];

const char *srte_protocol_origin_name(enum srte_protocol_origin origin);
const char *srte_candidate_type_name(enum srte_candidate_type type);
const char *objfun_type_name(enum objfun_type type);

#endif // _PATH_DEBUG_H_