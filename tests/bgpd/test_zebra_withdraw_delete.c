// SPDX-License-Identifier: GPL-2.0-or-later
/* A queued withdrawal must reach Zebra when its BGP instance is deleted. */

#include <zebra.h>

#include "frr_pthread.h"
#include "privs.h"
#include "stream.h"
#include "vrf.h"
#include "zclient.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_zebra.h"

struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

static int check_withdrawal(const char *prefix, bool early, bool reap)
{
	struct bgp *bgp;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct attr attr = {};
	struct prefix p;
	struct zmsghdr hdr;
	struct zapi_route api;
	struct stream *messages = stream_new(65536);
	uint8_t data[65536];
	int sockets[2];
	ssize_t size;
	size_t end;
	unsigned int withdrawals = 0;
	as_t asn = 65000;
	afi_t afi;

	assert(str2prefix(prefix, &p));
	afi = family2afi(p.family);
	assert(bgp_get(&bgp, &asn, NULL, BGP_INSTANCE_TYPE_DEFAULT, NULL, ASNOTATION_PLAIN) >= 0);
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
	bgp_zclient->sock = sockets[0];

	dest = bgp_node_get(bgp->rib[afi][SAFI_UNICAST], &p);
	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);
	pi = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, 0, bgp->peer_self,
		       bgp_attr_intern(&attr), dest);
	bgp_path_info_add(dest, pi);
	if (early)
		SET_FLAG(dest->flags, BGP_NODE_ZEBRA_ANNOUNCE_EARLY);

	/*
	 * Bestpath clears SELECTED before queueing the withdrawal. The old
	 * path can be reaped or retained, for example after nexthop failure.
	 * Delete the instance before the queued withdrawal is dispatched.
	 */
	bgp_zebra_route_install(dest, pi, bgp, false, NULL, false);
	assert(CHECK_FLAG(dest->flags, BGP_NODE_SCHEDULE_FOR_DELETE));
	if (reap) {
		dest = bgp_path_info_reap(dest, pi);
		assert(dest && !bgp_dest_get_bgp_path_info(dest));
	} else {
		assert(bgp_dest_get_bgp_path_info(dest) == pi);
		assert(!CHECK_FLAG(pi->flags, BGP_PATH_SELECTED));
	}
	bgp_dest_unlock_node(dest);
	bgp_delete(bgp);

	while ((size = recv(sockets[1], data, sizeof(data), MSG_DONTWAIT)) > 0)
		stream_put(messages, data, size);
	assert(size == -1 && (errno == EAGAIN || errno == EWOULDBLOCK));

	while (stream_get_getp(messages) < stream_get_endp(messages)) {
		end = stream_get_getp(messages);
		assert(zapi_parse_header(messages, &hdr));
		end += hdr.length;
		assert(end <= stream_get_endp(messages));
		if (hdr.command == ZEBRA_ROUTE_DELETE) {
			assert(zapi_route_decode(messages, &api) == 0);
			if (prefix_same(&api.prefix, &p) && api.safi == SAFI_UNICAST &&
			    api.type == ZEBRA_ROUTE_BGP)
				withdrawals++;
		}
		stream_set_getp(messages, end);
	}

	printf("%s%s %s: %s\n", early ? "early" : "normal", reap ? "" : " retained", prefix,
	       withdrawals == 1 ? "OK" : "failed!");
	stream_free(messages);
	close(sockets[0]);
	close(sockets[1]);
	bgp_zclient->sock = -1;
	return withdrawals != 1;
}

int main(int argc, char **argv)
{
	int failed = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	qobj_init();
	cmd_init(1);
	zlog_aux_init("NONE: ", LOG_ERR);
	master = event_master_create(NULL);
	bgp_master_init(master, BGP_SOCKET_SNDBUF_SIZE, list_new());
	bgp_option_set(BGP_OPT_NO_LISTEN);
	vrf_init(NULL, NULL, NULL, NULL);
	frr_pthread_init();
	bgp_init(0);
	bgp_pthreads_run();

	failed |= check_withdrawal("198.51.100.0/24", false, true);
	failed |= check_withdrawal("2001:db8::/64", false, true);
	failed |= check_withdrawal("198.51.100.0/24", true, true);
	failed |= check_withdrawal("2001:db8::/64", true, true);
	failed |= check_withdrawal("198.51.100.0/24", false, false);

	bgp_pthreads_finish();
	return failed;
}
