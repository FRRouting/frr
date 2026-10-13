// SPDX-License-Identifier: GPL-2.0-or-later
/* Per-family refresh timer ownership and teardown regression. */
#include <zebra.h>
#include "frrevent.h"
#include "privs.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_table.h"

struct zebra_privs_t bgpd_privs;
static unsigned int expired;

static void expired_callback(struct event *event)
{
	struct peer_af *paf = EVENT_ARG(event);

	assert(paf->afi == AFI_IP6);
	assert(paf->t_refresh_stalepath == NULL);
	expired++;
}

static void forbidden_callback(struct event *event)
{
	assert(!"cancelled refresh timer was dispatched");
}

int main(void)
{
	struct event_loop *master = event_master_create("refresh timers");
	struct bgp *bgp = calloc(1, sizeof(*bgp));
	struct peer *peer = calloc(1, sizeof(*peer));
	struct peer_af *ipv4, *ipv6;
	struct event event;

	assert(bgp && peer);
	peer->bgp = bgp;
	ipv4 = peer_af_create(peer, AFI_IP, SAFI_UNICAST);
	ipv6 = peer_af_create(peer, AFI_IP6, SAFI_UNICAST);
	assert(ipv4 && ipv6);
	assert(!peer_refresh_stale_timers_cancel(peer));

	/* Ending one refresh must not cancel another family's deadline. */
	event_add_timer(master, forbidden_callback, ipv4, 60,
			&ipv4->t_refresh_stalepath);
	event_add_timer(master, expired_callback, ipv6, 0,
			&ipv6->t_refresh_stalepath);
	event_cancel(&ipv4->t_refresh_stalepath);
	assert(event_is_scheduled(ipv6->t_refresh_stalepath));
	assert(event_fetch(master, &event));
	event_call(&event);
	assert(expired == 1);
	assert(!peer_refresh_stale_timers_cancel(peer));
	puts("family isolation OK");

	/* Stopping the session cancels every allocated family's timer. */
	event_add_timer(master, forbidden_callback, ipv4, 60,
			&ipv4->t_refresh_stalepath);
	event_add_timer(master, forbidden_callback, ipv6, 60,
			&ipv6->t_refresh_stalepath);
	assert(peer_refresh_stale_timers_cancel(peer));
	assert(!ipv4->t_refresh_stalepath && !ipv6->t_refresh_stalepath);
	assert(!peer_refresh_stale_timers_cancel(peer));
	puts("session cleanup OK");

	/* Exercise the production start transition with real table paths.
	 * A new epoch re-marks a refreshed path, retains the deadline, and
	 * does not mark another peer's path or an unusable path.
	 */
	{
		struct peer other = {0};
		struct bgp_path_info removed = {.peer = peer, .flags = BGP_PATH_REMOVED};
		struct bgp_path_info control = {.peer = &other, .next = &removed};
		struct bgp_path_info target = {.peer = peer, .next = &control};
		struct prefix prefix;
		struct bgp_dest *dest;
		struct event *deadline;

		bgp->rib[AFI_IP][SAFI_UNICAST] = bgp_table_init(bgp, AFI_IP, SAFI_UNICAST);
		assert(str2prefix("192.0.2.0/24", &prefix) > 0);
		dest = bgp_node_get(bgp->rib[AFI_IP][SAFI_UNICAST], &prefix);
		bgp_dest_set_bgp_path_info(dest, &target);
		SET_FLAG(peer->af_sflags[AFI_IP][SAFI_UNICAST], PEER_STATUS_EORR_RECEIVED);
		assert(peer_refresh_stale_start(ipv4));
		assert(CHECK_FLAG(target.flags, BGP_PATH_STALE));
		assert(!CHECK_FLAG(control.flags | removed.flags, BGP_PATH_STALE));
		assert(!CHECK_FLAG(peer->af_sflags[AFI_IP][SAFI_UNICAST],
				   PEER_STATUS_EORR_RECEIVED));
		event_add_timer(master, forbidden_callback, ipv4, 60,
				&ipv4->t_refresh_stalepath);
		deadline = ipv4->t_refresh_stalepath;
		bgp_path_info_unset_flag(dest, &target, BGP_PATH_STALE);
		assert(!peer_refresh_stale_start(ipv4));
		assert(CHECK_FLAG(target.flags, BGP_PATH_STALE));
		assert(!CHECK_FLAG(control.flags | removed.flags, BGP_PATH_STALE));
		assert(ipv4->t_refresh_stalepath == deadline);
		assert(event_is_scheduled(deadline));
		assert(peer_refresh_stale_timers_cancel(peer));
		bgp_dest_set_bgp_path_info(dest, NULL);
		bgp_dest_unlock_node(dest);
		bgp_table_finish(&bgp->rib[AFI_IP][SAFI_UNICAST]);
	}
	puts("repeated refresh state OK");

	/* Deleting an AF must cancel the event before freeing its argument. */
	event_add_timer(master, forbidden_callback, ipv4, 0,
			&ipv4->t_refresh_stalepath);
	event_add_timer(master, expired_callback, ipv6, 0,
			&ipv6->t_refresh_stalepath);
	assert(peer_af_delete(peer, AFI_IP, SAFI_UNICAST) == 0);
	assert(!peer_af_find(peer, AFI_IP, SAFI_UNICAST));
	assert(event_is_scheduled(ipv6->t_refresh_stalepath));
	assert(event_fetch(master, &event));
	event_call(&event);
	assert(expired == 2);
	assert(!bgp->af_peer_count[AFI_IP][SAFI_UNICAST]);
	assert(peer_af_delete(peer, AFI_IP6, SAFI_UNICAST) == 0);
	assert(!peer_refresh_stale_timers_cancel(peer));
	puts("family deletion OK");

	event_master_free(master);
	free(peer);
	free(bgp);
	return 0;
}
