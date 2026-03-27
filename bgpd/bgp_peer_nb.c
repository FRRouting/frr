// SPDX-License-Identifier: GPL-2.0-or-later
#include <zebra.h>

#include "bgpd/bgpd.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_updgrp.h"
#include "northbound.h"
#include "bgpd/bgp_peer_nb.h"
#include "lib/vrf.h"

static const char *peer_name_resolve(struct peer *peer, char *buf, size_t buflen)
{
	if (!peer)
		return NULL;

	if (peer->conf_if)
		return peer->conf_if;
	if (peer->host)
		return peer->host;

	if (peer->connection && peer->connection->su.sa.sa_family == AF_INET) {
		inet_ntop(AF_INET, &peer->connection->su.sin.sin_addr, buf, buflen);
		return buf;
	}

	if (peer->connection && peer->connection->su.sa.sa_family == AF_INET6) {
		if (inet_ntop(AF_INET6, &peer->connection->su.sin6.sin6_addr, buf, buflen))
			return buf;
	}

	return NULL;
}

static const char *peer_type_to_str(enum bgp_peer_sort sort)
{
	switch (sort) {
	case BGP_PEER_IBGP:
		return "internal";
	case BGP_PEER_EBGP:
		return "external";
	case BGP_PEER_INTERNAL:
		return "unspecified";
	case BGP_PEER_CONFED:
		return "confederation";
	case BGP_PEER_UNSPECIFIED:
	default:
		return "unspecified";
	}
}

/* XPath: /frr-bgp-peer:lib/vrf */
static const void *lib_vrf_get_next(struct nb_cb_get_next_args *args)
{
	struct vrf *vrfp = (struct vrf *)args->list_entry;

	if (!args->list_entry)
		return RB_MIN(vrf_name_head, &vrfs_by_name);

	return RB_NEXT(vrf_name_head, vrfp);
}

static int lib_vrf_get_keys(struct nb_cb_get_keys_args *args)
{
	struct vrf *vrfp = (struct vrf *)args->list_entry;

	args->keys->num = 1;
	strlcpy(args->keys->key[0], vrfp->name, sizeof(args->keys->key[0]));
	return NB_OK;
}

static const void *lib_vrf_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	return vrf_lookup_by_name(args->keys->key[0]);
}

/* XPath: /frr-bgp-peer:lib/vrf/id */
static struct yang_data *lib_vrf_id_get_elem(struct nb_cb_get_elem_args *args)
{
	struct vrf *vrfp = (struct vrf *)args->list_entry;

	return yang_data_new_uint32(args->xpath, vrfp->vrf_id);
}

/* XPath: /frr-bgp-peer:lib/vrf/peer */
static const void *lib_vrf_peer_get_next(struct nb_cb_get_next_args *args)
{
	struct bgp *bgp;
	struct peer *peer = (struct peer *)args->list_entry;
	struct listnode *node;
	struct peer *it;
	bool return_next = false;
	struct vrf *vrfp = (struct vrf *)args->parent_list_entry;

	if (!vrfp)
		return NULL;

	bgp = vrfp->vrf_id ? bgp_lookup_by_vrf_id(vrfp->vrf_id) : bgp_get_default();
	if (!bgp || !bgp->peer)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, it)) {
		if (!peer)
			return it;

		if (return_next)
			return it;

		if (it == peer)
			return_next = true;
	}

	return NULL;
}

static int lib_vrf_peer_get_keys(struct nb_cb_get_keys_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;
	char addrbuf[INET6_ADDRSTRLEN];
	const char *name;

	args->keys->num = 1;
	name = peer_name_resolve(peer, addrbuf, sizeof(addrbuf));
	strlcpy(args->keys->key[0], name ? name : "", sizeof(args->keys->key[0]));
	return NB_OK;
}

static const void *lib_vrf_peer_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *peer_str = args->keys->key[0];
	struct vrf *vrfp = (struct vrf *)args->parent_list_entry;
	struct bgp *bgp;
	union sockunion su;
	struct peer *peer;
	int ret;

	if (!vrfp)
		return NULL;

	bgp = vrfp->vrf_id ? bgp_lookup_by_vrf_id(vrfp->vrf_id) : bgp_get_default();
	if (!bgp || !bgp->peer)
		return NULL;

	ret = str2sockunion(peer_str, &su);
	if (ret >= 0)
		return peer_lookup(bgp, &su);

	peer = peer_lookup_by_hostname(bgp, peer_str);
	if (!peer)
		peer = peer_lookup_by_conf_if(bgp, peer_str);
	return peer;
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/name */
static struct yang_data *lib_vrf_peer_name_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;
	char addrbuf[INET6_ADDRSTRLEN];
	const char *name = peer_name_resolve(peer, addrbuf, sizeof(addrbuf));

	return yang_data_new_string(args->xpath, name ? name : "");
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/status */
static struct yang_data *lib_vrf_peer_status_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer || !peer->connection)
		return NULL;

	return yang_data_new_string(args->xpath,
				    lookup_msg(bgp_status_msg, peer->connection->status, NULL));
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/local-as */
static struct yang_data *lib_vrf_peer_local_as_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	return peer ? yang_data_new_uint32(args->xpath, peer->local_as) : NULL;
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/peer-as */
static struct yang_data *lib_vrf_peer_as_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	return peer ? yang_data_new_uint32(args->xpath, peer->as) : NULL;
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/description */
static struct yang_data *lib_vrf_peer_description_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	return yang_data_new_string(args->xpath, (peer && peer->desc) ? peer->desc : "");
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/neighbor-address */
static struct yang_data *lib_vrf_peer_neighbor_address_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;
	char addrbuf[INET6_ADDRSTRLEN];
	const char *name = peer_name_resolve(peer, addrbuf, sizeof(addrbuf));

	return yang_data_new_string(args->xpath, name ? name : "");
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/total-msgs-sent */
static struct yang_data *lib_vrf_peer_total_msgs_sent_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	return peer ? yang_data_new_uint32(args->xpath, PEER_TOTAL_TX(peer)) : NULL;
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/total-msgs-recvd */
static struct yang_data *lib_vrf_peer_total_msgs_recvd_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	return peer ? yang_data_new_uint32(args->xpath, PEER_TOTAL_RX(peer)) : NULL;
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/established-transitions */
static struct yang_data *lib_vrf_peer_established_transitions_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	return peer ? yang_data_new_uint32(args->xpath, peer->established) : NULL;
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/in-queue */
static struct yang_data *lib_vrf_peer_in_queue_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer || !peer->connection || !peer->connection->ibuf)
		return NULL;
	return yang_data_new_uint32(args->xpath, peer->connection->ibuf->count);
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/out-queue */
static struct yang_data *lib_vrf_peer_out_queue_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer || !peer->connection || !peer->connection->obuf)
		return NULL;
	return yang_data_new_uint32(args->xpath, peer->connection->obuf->count);
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/last-established */
static struct yang_data *lib_vrf_peer_last_established_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;
	time_t uptime;
	time_t epoch_tbuf;

	if (!peer)
		return NULL;
	uptime = monotime(NULL);
	uptime -= peer->uptime;
	epoch_tbuf = time(NULL) - uptime;
	return yang_data_new_uint64(args->xpath, (uint64_t)epoch_tbuf);
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/peer-group */
static struct yang_data *lib_vrf_peer_group_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;
	return yang_data_new_string(args->xpath,
				    (peer->group && peer->group->name) ? peer->group->name : "");
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/peer-type */
static struct yang_data *lib_vrf_peer_type_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;
	return yang_data_new_string(args->xpath, peer_type_to_str(peer_sort_lookup(peer)));
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/messages/sent/last-notification-error-code */
static struct yang_data *lib_vrf_peer_messages_sent_last_notification_error_code_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer || !peer->notify.code)
		return yang_data_new_string(args->xpath, "");
	return yang_data_new_string(args->xpath, bgp_notify_code_str(peer->notify.code));
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/messages/received/last-notification-error-code */
static struct yang_data *lib_vrf_peer_messages_received_last_notification_error_code_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer || !peer->notify.code)
		return yang_data_new_string(args->xpath, "");
	return yang_data_new_string(args->xpath, bgp_notify_code_str(peer->notify.code));
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/messages/sent/updates */
static struct yang_data *lib_vrf_peer_tx_updates_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;
	int update_out = 0;

	if (!peer)
		return NULL;
	update_out = atomic_load_explicit(&peer->update_out, memory_order_relaxed);
	return yang_data_new_uint32(args->xpath, update_out);
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/messages/received/updates */
static struct yang_data *lib_vrf_peer_rx_updates_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;
	int update_in = 0;

	if (!peer)
		return NULL;
	update_in = atomic_load_explicit(&peer->update_in, memory_order_relaxed);
	return yang_data_new_uint32(args->xpath, update_in);
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/graceful-shutdown */
static struct yang_data *lib_vrf_peer_graceful_shutdown_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer *peer = (struct peer *)args->list_entry;

	if (!peer)
		return NULL;
	return yang_data_new_bool(args->xpath,
				  bgp_in_graceful_shutdown(peer->bgp)
					  || CHECK_FLAG(peer->flags, PEER_FLAG_GRACEFUL_SHUTDOWN));
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/afi-safi */
static const void *lib_vrf_peer_afi_safi_get_next(struct nb_cb_get_next_args *args)
{
	struct peer *peer;
	struct peer_af *paf;
	int idx;

	if (!args || !args->parent_list_entry)
		return NULL;

	peer = (struct peer *)args->parent_list_entry;

	if (!args->list_entry) {
		for (idx = BGP_AF_START; idx < BGP_AF_MAX; idx++) {
			if (peer->peer_af_array[idx])
				return peer->peer_af_array[idx];
		}
		return NULL;
	}

	paf = (struct peer_af *)args->list_entry;
	for (idx = paf->afid + 1; idx < BGP_AF_MAX; idx++) {
		if (peer->peer_af_array[idx])
			return peer->peer_af_array[idx];
	}
	return NULL;
}

static int lib_vrf_peer_afi_safi_get_keys(struct nb_cb_get_keys_args *args)
{
	struct peer_af *paf = (struct peer_af *)args->list_entry;
	const char *id;

	if (!paf)
		return NB_ERR;

	args->keys->num = 1;
	id = yang_afi_safi_value2identity(paf->afi, paf->safi);
	strlcpy(args->keys->key[0], id ? id : "", sizeof(args->keys->key[0]));
	return NB_OK;
}

static const void *lib_vrf_peer_afi_safi_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	struct peer *peer = (struct peer *)args->parent_list_entry;
	int idx;
	const char *name;

	if (!peer)
		return NULL;

	for (idx = BGP_AF_START; idx < BGP_AF_MAX; idx++) {
		if (!peer->peer_af_array[idx])
			continue;
		name = yang_afi_safi_value2identity(peer->peer_af_array[idx]->afi,
						    peer->peer_af_array[idx]->safi);
		if (name && strcmp(name, args->keys->key[0]) == 0)
			return peer->peer_af_array[idx];
	}
	return NULL;
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/afi-safi/afi-safi-name */
static struct yang_data *lib_vrf_peer_afi_safi_name_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer_af *paf = (struct peer_af *)args->list_entry;
	const char *id;

	if (!paf)
		return NULL;
	id = yang_afi_safi_value2identity(paf->afi, paf->safi);
	return yang_data_new_string(args->xpath, id ? id : "");
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/afi-safi/rcvd-pfx */
static struct yang_data *lib_vrf_peer_afi_safi_rcvd_pfx_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer_af *paf = (struct peer_af *)args->list_entry;

	if (!paf || !paf->peer)
		return NULL;
	return yang_data_new_uint32(args->xpath, paf->peer->pcount[paf->afi][paf->safi]);
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/afi-safi/rcvd-pfx-installed */
static struct yang_data *lib_vrf_peer_afi_safi_rcvd_pfx_installed_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct peer_af *paf = (struct peer_af *)args->list_entry;

	if (!paf || !paf->peer)
		return NULL;
	/* Some FRR trees don't keep a separate installed counter. */
	return yang_data_new_uint32(args->xpath, paf->peer->pcount[paf->afi][paf->safi]);
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/afi-safi/pfx-sent */
static struct yang_data *lib_vrf_peer_afi_safi_pfx_sent_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer_af *paf = (struct peer_af *)args->list_entry;

	if (!paf || !PAF_SUBGRP(paf))
		return NULL;
	return yang_data_new_uint32(args->xpath, PAF_SUBGRP(paf)->scount);
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/afi-safi/afi */
static struct yang_data *lib_vrf_peer_afi_safi_afi_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer_af *paf = (struct peer_af *)args->list_entry;

	if (!paf)
		return NULL;
	return yang_data_new_string(args->xpath, afi2str(paf->afi));
}

/* XPath: /frr-bgp-peer:lib/vrf/peer/afi-safi/safi */
static struct yang_data *lib_vrf_peer_afi_safi_safi_get_elem(struct nb_cb_get_elem_args *args)
{
	struct peer_af *paf = (struct peer_af *)args->list_entry;

	if (!paf)
		return NULL;
	return yang_data_new_string(args->xpath, safi2str(paf->safi));
}

/* clang-format off */
const struct frr_yang_module_info frr_bgp_peer_info = {
	.name = "frr-bgp-peer",
	.nodes = {
		{
			.xpath = "/frr-bgp-peer:lib/vrf",
			.cbs = {
				.get_next = lib_vrf_get_next,
				.get_keys = lib_vrf_get_keys,
				.lookup_entry = lib_vrf_lookup_entry,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/id",
			.cbs = {
				.get_elem = lib_vrf_id_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer",
			.cbs = {
				.get_next = lib_vrf_peer_get_next,
				.get_keys = lib_vrf_peer_get_keys,
				.lookup_entry = lib_vrf_peer_lookup_entry,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/name",
			.cbs = {
				.get_elem = lib_vrf_peer_name_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/status",
			.cbs = {
				.get_elem = lib_vrf_peer_status_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/established-transitions",
			.cbs = {
				.get_elem = lib_vrf_peer_established_transitions_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/in-queue",
			.cbs = {
				.get_elem = lib_vrf_peer_in_queue_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/out-queue",
			.cbs = {
				.get_elem = lib_vrf_peer_out_queue_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/local-as",
			.cbs = {
				.get_elem = lib_vrf_peer_local_as_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/peer-as",
			.cbs = {
				.get_elem = lib_vrf_peer_as_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/last-established",
			.cbs = {
				.get_elem = lib_vrf_peer_last_established_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/description",
			.cbs = {
				.get_elem = lib_vrf_peer_description_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/peer-group",
			.cbs = {
				.get_elem = lib_vrf_peer_group_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/peer-type",
			.cbs = {
				.get_elem = lib_vrf_peer_type_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/neighbor-address",
			.cbs = {
				.get_elem = lib_vrf_peer_neighbor_address_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/messages/sent/last-notification-error-code",
			.cbs = {
				.get_elem = lib_vrf_peer_messages_sent_last_notification_error_code_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/messages/sent/updates",
			.cbs = {
				.get_elem = lib_vrf_peer_tx_updates_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/messages/received/last-notification-error-code",
			.cbs = {
				.get_elem = lib_vrf_peer_messages_received_last_notification_error_code_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/messages/received/updates",
			.cbs = {
				.get_elem = lib_vrf_peer_rx_updates_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/afi-safi",
			.cbs = {
				.get_next = lib_vrf_peer_afi_safi_get_next,
				.get_keys = lib_vrf_peer_afi_safi_get_keys,
				.lookup_entry = lib_vrf_peer_afi_safi_lookup_entry,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/afi-safi/afi-safi-name",
			.cbs = {
				.get_elem = lib_vrf_peer_afi_safi_name_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/afi-safi/rcvd-pfx",
			.cbs = {
				.get_elem = lib_vrf_peer_afi_safi_rcvd_pfx_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/afi-safi/rcvd-pfx-installed",
			.cbs = {
				.get_elem = lib_vrf_peer_afi_safi_rcvd_pfx_installed_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/afi-safi/pfx-sent",
			.cbs = {
				.get_elem = lib_vrf_peer_afi_safi_pfx_sent_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/afi-safi/afi",
			.cbs = {
				.get_elem = lib_vrf_peer_afi_safi_afi_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/afi-safi/safi",
			.cbs = {
				.get_elem = lib_vrf_peer_afi_safi_safi_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/graceful-shutdown",
			.cbs = {
				.get_elem = lib_vrf_peer_graceful_shutdown_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/total-msgs-sent",
			.cbs = {
				.get_elem = lib_vrf_peer_total_msgs_sent_get_elem,
			}
		},
		{
			.xpath = "/frr-bgp-peer:lib/vrf/peer/total-msgs-recvd",
			.cbs = {
				.get_elem = lib_vrf_peer_total_msgs_recvd_get_elem,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
/* clang-format on */
