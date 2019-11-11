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

#ifndef __PATH_ERRORS_H__
#define __PATH_ERRORS_H__

#include "lib/ferr.h"

enum path_log_refs {
        EC_PATH_PCEP_INIT = PATH_FERR_START,
        EC_PATH_SYSTEM_CALL,
        EC_PATH_PCEP_PCC_INIT,
        EC_PATH_PCEP_PCC_FINI
};

#if 0
extern void path_error_init(void);
#endif

#endif
