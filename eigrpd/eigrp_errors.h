/*
 * eigrp_errors - header for error messages that may occur in the eigrp process
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __EIGRP_ERRORS_H__
#define __EIGRP_ERRORS_H__

#include "ferr.h"
#include "eigrp_errors.h"

enum eigrp_ferr_refs {
	EIGRP_ERR_PACKET = EIGRP_FERR_START,
	EIGRP_ERR_CONFIG,
};

extern void eigrp_error_init(void);

#endif
