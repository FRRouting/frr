/* SPDX-License-Identifier: GPL-2.0-or-later */
/* This predicate covers the no-work branch of the patched FRR 10.7.1
 * bgp_generate_updgrp_packets, for the single IPv4 unicast lab profile.
 * Unknown families, refresh, pending subgroup work and pending EOR keep
 * their original scheduling event in the journal. */
#include "bgpd/bgp_updgrp.h"

static bool cnlab_idle_update_scan(struct peer_connection *connection)
{
    struct peer *peer=connection->peer;
    bool have_ipv4=false;
    if (!peer_established(connection) ||
        CHECK_FLAG(peer->sflags, PEER_STATUS_COND_ADV_PENDING))
        return false;
    for (enum bgp_af_index i=BGP_AF_START;i<BGP_AF_MAX;i++) {
        struct peer_af *paf=peer->peer_af_array[i];
        if (!paf)
            continue;
        if (paf->afi!=AFI_IP || paf->safi!=SAFI_UNICAST || !paf->subgroup)
            return false;
        struct update_subgroup *group=paf->subgroup;
        if (!advertise_list_is_empty(group) || subgroup_packets_to_build(group) ||
            bpacket_queue_is_full(SUBGRP_INST(group),SUBGRP_PKTQ(group)) ||
            (paf->next_pkt_to_send && paf->next_pkt_to_send->buffer) ||
            event_is_scheduled(group->t_coalesce) ||
            event_is_scheduled(paf->t_announce_route) ||
            CHECK_FLAG(peer->af_sflags[AFI_IP][SAFI_UNICAST],PEER_STATUS_BORR_SEND))
            return false;
        if (!CHECK_FLAG(peer->af_sflags[AFI_IP][SAFI_UNICAST],PEER_STATUS_EOR_SEND) &&
            (BGP_SEND_EOR(peer->bgp,AFI_IP,SAFI_UNICAST) ||
             CHECK_FLAG(peer->cap,PEER_CAP_RESTART_RCV)))
            return false;
        have_ipv4=true;
    }
    return have_ipv4;
}
