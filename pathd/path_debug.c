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

#include <zebra.h>

#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <libyang/libyang.h>

#include "printfrr.h"
#include "ipaddr.h"

#include "pathd/path_debug.h"

THREAD_DATA char _debug_buff[DEBUG_BUFF_SIZE];

/**
 * Gives the string representation of an srte_protocol_origin enum value.
 *
 * @param origin The enum value to convert to string
 * @return a constant string representation of the enum value
 */
const char *srte_protocol_origin_name(enum srte_protocol_origin origin)
{
	switch (origin) {
	case SRTE_ORIGIN_UNDEFINED:
		return "UNDEFINED";
	case SRTE_ORIGIN_PCEP:
		return "PCEP";
	case SRTE_ORIGIN_BGP:
		return "BGP";
	case SRTE_ORIGIN_LOCAL:
		return "LOCAL";
	default:
		return "UNKNOWN";
	}
}

/**
 * Gives the string representation of an srte_candidate_type enum value.
 *
 * @param origin The enum value to convert to string
 * @return a constant string representation of the enum value
 */
const char *srte_candidate_type_name(enum srte_candidate_type type)
{
	switch (type) {
	case SRTE_CANDIDATE_TYPE_EXPLICIT:
		return "EXPLICIT";
	case SRTE_CANDIDATE_TYPE_DYNAMIC:
		return "DYNAMIC";
	case SRTE_CANDIDATE_TYPE_UNDEFINED:
		return "UNDEFINED";
	default:
		return "UNKNOWN";
	}
}

/**
 * Gives the string representation of an objfun_type enum value.
 *
 * @param origin The enum value to convert to string
 * @return a constant string representation of the enum value
 */
const char *objfun_type_name(enum objfun_type type)
{
	switch (type) {
	case OBJFUN_UNDEFINED:
		return "UNDEFINED";
	case OBJFUN_MCP:
		return "MCP";
	case OBJFUN_MLP:
		return "MLP";
	case OBJFUN_MBP:
		return "MBP";
	case OBJFUN_MBC:
		return "MBC";
	case OBJFUN_MLL:
		return "MLL";
	case OBJFUN_MCC:
		return "MCC";
	case OBJFUN_SPT:
		return "SPT";
	case OBJFUN_MCT:
		return "MCT";
	case OBJFUN_MPLP:
		return "MPLP";
	case OBJFUN_MUP:
		return "MUP";
	case OBJFUN_MRUP:
		return "MRUP";
	case OBJFUN_MTD:
		return "MTD";
	case OBJFUN_MBN:
		return "MBN";
	case OBJFUN_MCTD:
		return "MCTD";
	case OBJFUN_MSL:
		return "MSL";
	case OBJFUN_MSS:
		return "MSS";
	case OBJFUN_MSN:
		return "MSN";
	default:
		return "UNKNOWN";
	}
}
