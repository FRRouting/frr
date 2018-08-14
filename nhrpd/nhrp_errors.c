/*
 * NHRP-specific error messages.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
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

#include <zebra.h>

#include "lib/ferr.h"
#include "nhrp_errors.h"

DEFINE_LOGCAT(NHRP_ERR_SWAN, ROOT, "NHRP Strong Swan Error",
	.description = "NHRP has detected a error with the Strongswan code",
	.suggestion = "Ensure that StrongSwan is configured correctly.  Restart StrongSwan and FRR",
)
DEFINE_LOGCAT(NHRP_ERR_RESOLVER, ROOT, "NHRP DNS Resolution",
	.description = "NHRP has detected an error in an attempt to resolve a hostname",
	.suggestion = "Ensure that DNS is working properly and the hostname is configured in dns.  If you are still seeing this error, open an issue",
)
