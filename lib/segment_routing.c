/*
 * Flexible Algorithm definitions
 * Copyright (C) 2022  Hiroki Shirokura, LINE Corporation
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
#include "segment_routing.h"

const char *sr_algorithm_string(uint8_t algo)
{
	switch (algo) {
	case SR_ALGORITHM_SPF:
		return "SPF";
	case SR_ALGORITHM_STRICT_SPF:
		return "Strict SPF";
	case SR_ALGORITHM_UNSET:
		return "Unset";
	default:
		return algo >= SR_ALGORITHM_FLEX_MIN ? "Flex-Algo" : "Unknown";
	}
}
