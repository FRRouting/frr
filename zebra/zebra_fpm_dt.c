/*
 * zebra_fpm_dt.c
 *
 * @copyright Copyright (C) 2016 Sproute Networks, Inc.
 *
 * @author Avneesh Sachdev <avneesh@sproute.com>
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * Developer tests for the zebra code that interfaces with the
 * forwarding plane manager.
 *
 * The functions here are built into developer builds of zebra (when
 * DEV_BUILD is defined), and can be called via the 'invoke' cli
 * command.
 *
 * For example:
 *
 * # invoke zebra function zfpm_dt_benchmark_protobuf_encode 100000
 *
 */

#include <zebra.h>
#include "log.h"
#include "vrf.h"

#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/zebra_vrf.h"

#include "zebra_fpm_private.h"

#include "qpb/qpb_allocator.h"
#include "qpb/linear_allocator.h"

#ifdef HAVE_PROTOBUF
#include "qpb/qpb.h"
#include "fpm/fpm.pb-c.h"
#endif

/*
 * Externs.
 */
extern int zfpm_dt_benchmark_netlink_encode(int argc, const char **argv);
extern int zfpm_dt_benchmark_protobuf_encode(int argc, const char **argv);
extern int zfpm_dt_benchmark_protobuf_decode(int argc, const char **argv);

/*
 * zfpm_dt_find_route
 *
 * Selects a suitable rib destination for fpm interface tests.
 */
static int zfpm_dt_find_route(rib_dest_t **dest_p, struct route_entry **re_p)
{
	struct route_node *rnode;
	route_table_iter_t iter;
	struct route_table *table;
	rib_dest_t *dest;
	struct route_entry *re;
	int ret;

	table = zebra_vrf_table(AFI_IP, SAFI_UNICAST, VRF_DEFAULT);
	if (!table)
		return 0;

	route_table_iter_init(&iter, table);
	while ((rnode = route_table_iter_next(&iter))) {
		dest = rib_dest_from_rnode(rnode);

		if (!dest)
			continue;

		re = zfpm_route_for_update(dest);
		if (!re)
			continue;

		if (re->nexthop_active_num <= 0)
			continue;

		*dest_p = dest;
		*re_p = re;
		ret = 1;
		goto done;
	}

	ret = 0;

done:
	route_table_iter_cleanup(&iter);
	return ret;
}
#ifdef HAVE_NETLINK

/*
 * zfpm_dt_benchmark_netlink_encode
 */
int zfpm_dt_benchmark_netlink_encode(int argc, const char **argv)
{
	int times, i, len;
	rib_dest_t *dest;
	struct route_entry *re;
	char buf[4096];

	times = 100000;
	if (argc > 0) {
		times = atoi(argv[0]);
	}

	if (!zfpm_dt_find_route(&dest, &re)) {
		return 1;
	}

	for (i = 0; i < times; i++) {
		len = zfpm_netlink_encode_route(RTM_NEWROUTE, dest, re, buf,
						sizeof(buf));
		if (len <= 0) {
			return 2;
		}
	}
	return 0;
}

#endif /* HAVE_NETLINK */

#ifdef HAVE_PROTOBUF

/*
 * zfpm_dt_benchmark_protobuf_encode
 */
int zfpm_dt_benchmark_protobuf_encode(int argc, const char **argv)
{
	int times, i, len;
	rib_dest_t *dest;
	struct route_entry *re;
	uint8_t buf[4096];

	times = 100000;
	if (argc > 0) {
		times = atoi(argv[0]);
	}

	if (!zfpm_dt_find_route(&dest, &re)) {
		return 1;
	}

	for (i = 0; i < times; i++) {
		len = zfpm_protobuf_encode_route(dest, re, buf, sizeof(buf));
		if (len <= 0) {
			return 2;
		}
	}
	return 0;
}

/*
 * zfpm_dt_log_fpm_message
 */
static void zfpm_dt_log_fpm_message(Fpm__Message *msg)
{
	Fpm__AddRoute *add_route;
	Fpm__Nexthop *nexthop;
	struct prefix prefix;
	uint8_t family, nh_family;
	uint if_index;
	char *if_name;
	size_t i;
	char buf[INET6_ADDRSTRLEN];
	union g_addr nh_addr;

	if (msg->type != FPM__MESSAGE__TYPE__ADD_ROUTE)
		return;

	zfpm_debug("Add route message");
	add_route = msg->add_route;

	if (!qpb_address_family_get(add_route->address_family, &family))
		return;

	if (!qpb_l3_prefix_get(add_route->key->prefix, family, &prefix))
		return;

	zfpm_debug("Vrf id: %d, Prefix: %s/%d, Metric: %d", add_route->vrf_id,
		   inet_ntop(family, &prefix.u.prefix, buf, sizeof(buf)),
		   prefix.prefixlen, add_route->metric);

	/*
	 * Go over nexthops.
	 */
	for (i = 0; i < add_route->n_nexthops; i++) {
		nexthop = add_route->nexthops[i];
		if (!qpb_if_identifier_get(nexthop->if_id, &if_index, &if_name))
			continue;

		if (nexthop->address)
			qpb_l3_address_get(nexthop->address, &nh_family,
					   &nh_addr);

		zfpm_debug("Nexthop - if_index: %d (%s), gateway: %s, ",
			   if_index, if_name ? if_name : "name not specified",
			   nexthop->address ? inet_ntoa(nh_addr.ipv4) : "None");
	}
}

/*
 * zfpm_dt_benchmark_protobuf_decode
 */
int zfpm_dt_benchmark_protobuf_decode(int argc, const char **argv)
{
	int times, i, len;
	rib_dest_t *dest;
	struct route_entry *re;
	uint8_t msg_buf[4096];
	QPB_DECLARE_STACK_ALLOCATOR(allocator, 8192);
	Fpm__Message *fpm_msg;

	QPB_INIT_STACK_ALLOCATOR(allocator);

	times = 100000;
	if (argc > 0)
		times = atoi(argv[0]);

	if (!zfpm_dt_find_route(&dest, &re))
		return 1;

	/*
	 * Encode the route into the message buffer once only.
	 */
	len = zfpm_protobuf_encode_route(dest, re, msg_buf, sizeof(msg_buf));
	if (len <= 0)
		return 2;

	// Decode once, and display the decoded message
	fpm_msg = fpm__message__unpack(&allocator, len, msg_buf);

	if (fpm_msg) {
		zfpm_dt_log_fpm_message(fpm_msg);
		QPB_RESET_STACK_ALLOCATOR(allocator);
	}

	/*
	 * Decode encoded message the specified number of times.
	 */
	for (i = 0; i < times; i++) {
		fpm_msg = fpm__message__unpack(&allocator, len, msg_buf);

		if (!fpm_msg)
			return 3;

		// fpm__message__free_unpacked(msg, NULL);
		QPB_RESET_STACK_ALLOCATOR(allocator);
	}
	return 0;
}

#endif /* HAVE_PROTOBUF */
