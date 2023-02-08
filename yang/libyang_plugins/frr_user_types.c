// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 */

#include <zebra.h>

#include "prefix.h"
#include "ipaddr.h"

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

static int ip_address_store_clb(const char *type_name, const char *value_str,
				lyd_val *value, char **err_msg)
{
	value->ptr = malloc(sizeof(struct ipaddr));
	if (!value->ptr)
		return 1;

	if (str2ipaddr(value_str, value->ptr)) {
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

static int ip_prefix_store_clb(const char *type_name, const char *value_str,
			       lyd_val *value, char **err_msg)
{
	value->ptr = malloc(sizeof(struct prefix));
	if (!value->ptr)
		return 1;

	if (str2prefix(value_str, value->ptr) == 0) {
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
	{"ietf-inet-types", "2013-07-15", "ip-address", ip_address_store_clb,
	 free},
	{"ietf-inet-types", "2013-07-15", "ipv4-prefix", ipv4_prefix_store_clb,
	 free},
	{"ietf-inet-types", "2013-07-15", "ipv6-prefix", ipv6_prefix_store_clb,
	 free},
	{"ietf-inet-types", "2013-07-15", "ip-prefix", ip_prefix_store_clb,
	 free},
	{NULL, NULL, NULL, NULL, NULL} /* terminating item */
};
