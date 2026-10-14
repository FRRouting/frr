// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Regression test for the use-after-free in the "allowas-in ... route-map"
 * inbound path.
 *
 * bgp_update() runs the allowas-in route-map on a stack copy of the parsed
 * attr and then calls bgp_attr_flush() on that copy. When the copy is made
 * with a plain struct assignment it shares attr->extra with the parsed attr,
 * so the flush frees the extra out from under the parsed attr, and the rest
 * of bgp_update() reads freed memory.
 *
 * The attr below carries COMMUNITIES with the Partial bit set, which is enough
 * to make bgp_attr_parse() allocate attr->extra (partial_attrs). The test
 * drives one UPDATE through bgp_update() and then releases the parsed attr the
 * way bgp_update_receive() does. Under AddressSanitizer this aborts before the
 * fix; after it, it prints OK.
 */

#include <zebra.h>

#include "qobj.h"
#include "vty.h"
#include "stream.h"
#include "privs.h"
#include "routemap.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_community_alias.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_label.h"

/* need these to link in libbgp */
struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

static const uint8_t attrs[] = {
	0x40, 0x01, 0x01, 0x00,				      /* ORIGIN igp */
	0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xe9, /* AS_PATH 65001 */
	0x40, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x02,	      /* NEXT_HOP 10.0.0.2 */
	0xe0, 0x08, 0x04, 0xfd, 0xe9, 0x00, 0x01,	      /* COMMUNITIES, Partial */
};

static struct bgp *bgp;
static as_t asn = 65000;

int main(void)
{
	struct peer *peer;
	struct attr attr = {};
	struct bgp_nlri mp_update = {};
	struct bgp_nlri mp_withdraw = {};
	struct route_map *map;
	struct prefix p;
	enum bgp_attr_parse_ret ret;
	int afi, safi;

	qobj_init();
	cmd_init(0);
	bgp_vty_init();
	master = event_master_create("test allowas rmap");
	bgp_master_init(master, BGP_SOCKET_SNDBUF_SIZE, list_new());
	vrf_init(NULL, NULL, NULL, NULL);
	bgp_option_set(BGP_OPT_NO_LISTEN);
	bgp_attr_init();
	bgp_labels_init();
	bgp_community_alias_init();
	route_map_init();

	if (bgp_get(&bgp, &asn, NULL, BGP_INSTANCE_TYPE_DEFAULT, NULL, ASNOTATION_PLAIN) < 0)
		return 1;

	peer = peer_create_accept(bgp, NULL);
	peer->host = (char *)"foo";
	peer->connection = bgp_peer_connection_new(peer, NULL, UNKNOWN);
	peer->connection->status = Established;
	peer->connection->curr = stream_new(BGP_MAX_PACKET_SIZE);
	peer->sort = BGP_PEER_EBGP;
	peer->as = 65001;
	peer->local_as = 65000;
	peer->as_type = AS_SPECIFIED;
	SET_FLAG(peer->cap, PEER_CAP_AS4_RCV);
	SET_FLAG(peer->cap, PEER_CAP_AS4_ADV);
	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		for (safi = SAFI_UNICAST; safi < SAFI_MAX; safi++) {
			peer->afc[afi][safi] = 1;
			peer->afc_adv[afi][safi] = 1;
			peer->afc_nego[afi][safi] = 1;
		}

	/* neighbor foo allowas-in 3 route-map RM; route-map RM permit 10 */
	map = route_map_get("RM");
	route_map_index_get(map, RMAP_PERMIT, 10);
	SET_FLAG(peer->af_flags[AFI_IP][SAFI_UNICAST], PEER_FLAG_ALLOWAS_IN);
	peer->allowas_in[AFI_IP][SAFI_UNICAST] = 3;
	peer->allowas_in_rmap[AFI_IP][SAFI_UNICAST].name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, "RM");
	peer->allowas_in_rmap[AFI_IP][SAFI_UNICAST].rmap = map;

	stream_reset(peer->connection->curr);
	stream_write(peer->connection->curr, attrs, sizeof(attrs));
	stream_set_getp(peer->connection->curr, 0);
	ret = bgp_attr_parse(peer->connection, &attr, sizeof(attrs), &mp_update, &mp_withdraw,
			     true);
	if (ret != BGP_ATTR_PARSE_PROCEED) {
		printf("allowas-in-rmap-uaf: attr parse failed\nfailed!\n");
		return 1;
	}

	/* as bgp_nlri_parse_ip() does before handing the NLRI to bgp_update() */
	memset(&attr.attr_intern_reuse, 0, sizeof(attr.attr_intern_reuse));
	attr.attr_intern_reuse.parsed_attr = &attr;

	str2prefix("192.0.2.0/24", &p);
	bgp_update(peer, &p, 0, &attr, AFI_IP, SAFI_UNICAST, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
		   NULL, NULL, 0, 0, NULL, NULL);

	bgp_attr_unintern_sub(&attr);

	printf("%s: %s\nOK\n", "allowas-in-rmap-uaf",
	       "UPDATE through allowas-in route-map does not free the parsed attr's extra");
	return 0;
}
