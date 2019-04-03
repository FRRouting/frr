/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
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

#include "prefix.h"

#include <libyang/user_types.h>

static int ipv4_address_store_clb(const char *type_name, const char *value_str,
				  lyd_val *value, char **err_msg)
{
	value->ptr = malloc(sizeof(struct in_addr));
	if (!value->ptr)
		return 1;

	if (inet_pton(AF_INET, value_str, value->ptr) != 1) {
		free(value->ptr);
		return 1;
	}

	return 0;
}

static int ipv6_address_store_clb(const char *type_name, const char *value_str,
				  lyd_val *value, char **err_msg)
{
	value->ptr = malloc(INET6_ADDRSTRLEN);
	if (!value->ptr)
		return 1;

	if (inet_pton(AF_INET6, value_str, value->ptr) != 1) {
		free(value->ptr);
		return 1;
	}

	return 0;
}

static int ipv4_prefix_store_clb(const char *type_name, const char *value_str,
				 lyd_val *value, char **err_msg)
{
	value->ptr = malloc(sizeof(struct prefix_ipv4));
	if (!value->ptr)
		return 1;

	if (str2prefix_ipv4(value_str, value->ptr) == 0) {
		free(value->ptr);
		return 1;
	}

	return 0;
}

static int ipv6_prefix_store_clb(const char *type_name, const char *value_str,
				 lyd_val *value, char **err_msg)
{
	value->ptr = malloc(sizeof(struct prefix_ipv6));
	if (!value->ptr)
		return 1;

	if (str2prefix_ipv6(value_str, value->ptr) == 0) {
		free(value->ptr);
		return 1;
	}

	return 0;
}

struct lytype_plugin_list frr_user_types[] = {
	{"ietf-inet-types", "2013-07-15", "ipv4-address",
	 ipv4_address_store_clb, free},
	{"ietf-inet-types", "2013-07-15", "ipv4-address-no-zone",
	 ipv4_address_store_clb, free},
	{"ietf-inet-types", "2013-07-15", "ipv6-address",
	 ipv6_address_store_clb, free},
	{"ietf-inet-types", "2013-07-15", "ipv6-address-no-zone",
	 ipv6_address_store_clb, free},
	{"ietf-inet-types", "2013-07-15", "ipv4-prefix", ipv4_prefix_store_clb,
	 free},
	{"ietf-inet-types", "2013-07-15", "ipv6-prefix", ipv6_prefix_store_clb,
	 free},
	{NULL, NULL, NULL, NULL, NULL} /* terminating item */
};
