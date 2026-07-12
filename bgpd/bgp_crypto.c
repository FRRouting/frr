// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP crypto-routes experimental AFI/SAFI.
 */

#include <zebra.h>

#include "command.h"
#include "json.h"
#include "memory.h"
#include "prefix.h"
#include "stream.h"
#include "vty.h"

#include "bgpd/bgp_addpath.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_crypto.h"
#include "bgpd/bgp_memory.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_vty.h"

static void bgp_crypto_prefix_make(struct prefix *p, const char *peer_id)
{
	prefix_crypto_set(p, peer_id, strlen(peer_id));
}

static const char *bgp_crypto_prefix_peer_id(const struct prefix *p)
{
	if (!p || p->family != AF_CRYPTO || !p->u.prefix_crypto.ptr)
		return "";

	return (const char *)p->u.prefix_crypto.ptr;
}

static bool bgp_crypto_copy_string(char *dst, size_t dst_len, const char *src)
{
	if (!src || !src[0] || strlen(src) >= dst_len)
		return false;

	strlcpy(dst, src, dst_len);
	return true;
}

static bool bgp_crypto_route_same(const struct bgp_path_info_extra_crypto *a,
				  const struct bgp_path_info_extra_crypto *b)
{
	return a && b && strcmp(a->peer_id, b->peer_id) == 0 &&
	       strcmp(a->algorithm, b->algorithm) == 0 &&
	       strcmp(a->certificate_id, b->certificate_id) == 0 &&
	       strcmp(a->public_key_id, b->public_key_id) == 0 &&
	       a->capability_bitmap == b->capability_bitmap &&
	       a->trust_level == b->trust_level && a->version == b->version;
}

static void bgp_crypto_extra_set(struct bgp_path_info *pi,
				 const struct bgp_path_info_extra_crypto *crypto)
{
	struct bgp_path_info_extra *extra = bgp_path_info_extra_get(pi);

	if (!extra->crypto)
		extra->crypto = XCALLOC(MTYPE_BGP_ROUTE_EXTRA_CRYPTO,
					sizeof(*extra->crypto));

	memcpy(extra->crypto, crypto, sizeof(*extra->crypto));
}

static struct bgp_path_info *
bgp_crypto_path_lookup(struct bgp_dest *dest, struct peer *peer)
{
	struct bgp_path_info *pi;

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == peer)
			return pi;

	return NULL;
}

static void bgp_crypto_attr_default(struct bgp *bgp, struct attr *attr)
{
	bgp_attr_default_set(attr, bgp, BGP_ORIGIN_INCOMPLETE);
	attr->mp_nexthop_len = 0;
}

int bgp_crypto_route_add(struct peer *peer, struct attr *attr,
			 const struct bgp_path_info_extra_crypto *crypto)
{
	struct bgp *bgp;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct bgp_path_info *new;
	struct attr local_attr;
	struct attr *attr_new;
	struct prefix p;
	bool default_attr = false;

	if (!peer || !peer->bgp || !crypto || !crypto->peer_id[0])
		return -1;

	bgp = peer->bgp;

	if (CHECK_FLAG(bgp->flags, BGP_FLAG_DELETE_IN_PROGRESS))
		return 0;

	memset(&p, 0, sizeof(p));
	bgp_crypto_prefix_make(&p, crypto->peer_id);

	dest = bgp_afi_node_get(bgp->rib[AFI_CRYPTO][SAFI_CRYPTO_ROUTES],
				AFI_CRYPTO, SAFI_CRYPTO_ROUTES, &p, NULL);

	if (attr)
		local_attr = *attr;
	else {
		bgp_crypto_attr_default(bgp, &local_attr);
		default_attr = true;
	}
	local_attr.mp_nexthop_len = 0;

	attr_new = bgp_attr_intern(&local_attr);
	if (default_attr)
		aspath_unintern(&local_attr.aspath);

	pi = bgp_crypto_path_lookup(dest, peer);
	if (pi) {
		bool same_attr = !CHECK_FLAG(pi->flags, BGP_PATH_REMOVED) &&
				 attrhash_cmp(pi->attr, attr_new);
		bool same_crypto = pi->extra && pi->extra->crypto &&
				   bgp_crypto_route_same(pi->extra->crypto, crypto);

		if (same_attr && same_crypto) {
			bgp_attr_unintern(&attr_new);
			bgp_dest_unlock_node(dest);
			prefix_crypto_ptr_free(&p);
			return 0;
		}

		bgp_path_info_set_flag(dest, pi, BGP_PATH_ATTR_CHANGED);
		UNSET_FLAG(pi->flags, BGP_PATH_REMOVED);
		SET_FLAG(pi->flags, BGP_PATH_VALID);

		bgp_attr_unintern(&pi->attr);
		pi->attr = attr_new;
		pi->uptime = monotime(NULL);
		bgp_crypto_extra_set(pi, crypto);

		bgp_process(bgp, dest, pi, AFI_CRYPTO, SAFI_CRYPTO_ROUTES);
		bgp_dest_unlock_node(dest);
		prefix_crypto_ptr_free(&p);
		return 0;
	}

	new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, 0, peer, attr_new,
			dest);
	SET_FLAG(new->flags, BGP_PATH_VALID);
	bgp_crypto_extra_set(new, crypto);

	bgp_path_info_add(dest, new);
	bgp_process(bgp, dest, new, AFI_CRYPTO, SAFI_CRYPTO_ROUTES);

	bgp_dest_unlock_node(dest);
	prefix_crypto_ptr_free(&p);
	return 0;
}

int bgp_crypto_route_delete(struct bgp *bgp, struct peer *peer,
			    const char *peer_id)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct prefix p;

	if (!bgp || !peer || !peer_id || !peer_id[0])
		return -1;

	memset(&p, 0, sizeof(p));
	bgp_crypto_prefix_make(&p, peer_id);

	dest = bgp_node_lookup(bgp->rib[AFI_CRYPTO][SAFI_CRYPTO_ROUTES], &p);
	if (!dest) {
		prefix_crypto_ptr_free(&p);
		return 0;
	}

	pi = bgp_crypto_path_lookup(dest, peer);
	if (pi)
		bgp_rib_remove(dest, pi, peer, AFI_CRYPTO,
			       SAFI_CRYPTO_ROUTES);

	bgp_dest_unlock_node(dest);
	prefix_crypto_ptr_free(&p);
	return 0;
}

static int bgp_crypto_parse_tlvs(struct peer *peer, const uint8_t *pnt,
				 const uint8_t *end,
				 struct bgp_path_info_extra_crypto *crypto)
{
	bool have_algorithm = false;
	bool have_certificate_id = false;
	bool have_public_key_id = false;
	bool have_capabilities = false;
	bool have_trust_level = false;

	while (pnt < end) {
		uint16_t type;
		uint16_t len;

		if ((size_t)(end - pnt) < BGP_CRYPTO_TLV_HDR_SIZE)
			return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;

		type = ((uint16_t)pnt[0] << 8) | pnt[1];
		len = ((uint16_t)pnt[2] << 8) | pnt[3];
		pnt += BGP_CRYPTO_TLV_HDR_SIZE;

		if ((size_t)(end - pnt) < len)
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

		switch (type) {
		case BGP_CRYPTO_TLV_ALGORITHM:
			if (!len || len >= sizeof(crypto->algorithm))
				return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
			memcpy(crypto->algorithm, pnt, len);
			crypto->algorithm[len] = '\0';
			have_algorithm = true;
			break;
		case BGP_CRYPTO_TLV_CERTIFICATE_ID:
			if (!len || len >= sizeof(crypto->certificate_id))
				return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
			memcpy(crypto->certificate_id, pnt, len);
			crypto->certificate_id[len] = '\0';
			have_certificate_id = true;
			break;
		case BGP_CRYPTO_TLV_PUBLIC_KEY_ID:
			if (!len || len >= sizeof(crypto->public_key_id))
				return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
			memcpy(crypto->public_key_id, pnt, len);
			crypto->public_key_id[len] = '\0';
			have_public_key_id = true;
			break;
		case BGP_CRYPTO_TLV_CAPABILITY_BITMAP:
			if (len != sizeof(uint64_t))
				return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
			crypto->capability_bitmap =
				((uint64_t)pnt[0] << 56) |
				((uint64_t)pnt[1] << 48) |
				((uint64_t)pnt[2] << 40) |
				((uint64_t)pnt[3] << 32) |
				((uint64_t)pnt[4] << 24) |
				((uint64_t)pnt[5] << 16) |
				((uint64_t)pnt[6] << 8) |
				(uint64_t)pnt[7];
			have_capabilities = true;
			break;
		case BGP_CRYPTO_TLV_TRUST_LEVEL:
			if (len != 1 || pnt[0] > 100)
				return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
			crypto->trust_level = pnt[0];
			have_trust_level = true;
			break;
		default:
			if (bgp_debug_update(peer, NULL, NULL, 1))
				zlog_debug("%pBP crypto-routes unknown TLV type %u length %u ignored",
					   peer, type, len);
			break;
		}

		pnt += len;
	}

	if (!have_algorithm || !have_certificate_id || !have_public_key_id ||
	    !have_capabilities || !have_trust_level)
		return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;

	return 0;
}

int bgp_nlri_parse_crypto(struct peer *peer, struct attr *attr,
			  struct bgp_nlri *packet, bool withdraw)
{
	const uint8_t *pnt = packet->nlri;
	const uint8_t *lim = pnt + packet->length;
	bool addpath_capable;
	uint32_t addpath_id;

	addpath_capable = bgp_addpath_encode_rx(peer, packet->afi, packet->safi);

	while (pnt < lim) {
		struct bgp_path_info_extra_crypto crypto = {};
		const uint8_t *nlri_end;
		uint16_t nlri_len;
		uint16_t version;
		uint8_t route_type;
		uint8_t peer_id_len;

		addpath_id = 0;
		if (addpath_capable) {
			if ((size_t)(lim - pnt) < BGP_ADDPATH_ID_LEN)
				return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
			addpath_id = ((uint32_t)pnt[0] << 24) |
				     ((uint32_t)pnt[1] << 16) |
				     ((uint32_t)pnt[2] << 8) | pnt[3];
			pnt += BGP_ADDPATH_ID_LEN;
		}

		if ((size_t)(lim - pnt) < BGP_CRYPTO_NLRI_LEN_SIZE)
			return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;

		nlri_len = ((uint16_t)pnt[0] << 8) | pnt[1];
		pnt += BGP_CRYPTO_NLRI_LEN_SIZE;

		if (nlri_len > BGP_CRYPTO_NLRI_MAX_SIZE ||
		    (size_t)(lim - pnt) < nlri_len)
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

		if (nlri_len < BGP_CRYPTO_NLRI_FIXED_SIZE)
			return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;

		nlri_end = pnt + nlri_len;

		version = ((uint16_t)pnt[0] << 8) | pnt[1];
		pnt += 2;
		route_type = *pnt++;
		peer_id_len = *pnt++;

		if (version != BGP_CRYPTO_VERSION ||
		    route_type != BGP_CRYPTO_ROUTE_TYPE_PEER_METADATA)
			return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;

		if (!peer_id_len ||
		    peer_id_len >= sizeof(crypto.peer_id) ||
		    (size_t)(nlri_end - pnt) < peer_id_len)
			return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;

		memcpy(crypto.peer_id, pnt, peer_id_len);
		crypto.peer_id[peer_id_len] = '\0';
		crypto.version = version;
		pnt += peer_id_len;

		if (withdraw) {
			bgp_crypto_route_delete(peer->bgp, peer, crypto.peer_id);
			pnt = nlri_end;
			continue;
		}

		if (!attr)
			return BGP_NLRI_PARSE_ERROR;

		if (bgp_crypto_parse_tlvs(peer, pnt, nlri_end, &crypto) < 0)
			return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;

		if (bgp_crypto_route_add(peer, attr, &crypto) < 0)
			return BGP_NLRI_PARSE_ERROR;

		pnt = nlri_end;
		(void)addpath_id;
	}

	return 0;
}

static void bgp_crypto_put_string_tlv(struct stream *s, uint16_t type,
				      const char *value)
{
	size_t len = strlen(value);

	stream_putw(s, type);
	stream_putw(s, len);
	stream_put(s, value, len);
}

void bgp_crypto_encode_nlri(struct stream *s, const struct prefix *p,
			    bool addpath_capable, uint32_t addpath_tx_id,
			    const struct bgp_path_info *path)
{
	const struct bgp_path_info_extra_crypto *crypto = NULL;
	const char *peer_id;
	size_t nlri_len_pos;
	size_t body_start;
	size_t nlri_len;
	uint8_t peer_id_len;

	if (addpath_capable)
		stream_putl(s, addpath_tx_id);

	peer_id = bgp_crypto_prefix_peer_id(p);
	peer_id_len = strlen(peer_id);

	nlri_len_pos = stream_get_endp(s);
	stream_putw(s, 0);
	body_start = stream_get_endp(s);

	stream_putw(s, BGP_CRYPTO_VERSION);
	stream_putc(s, BGP_CRYPTO_ROUTE_TYPE_PEER_METADATA);
	stream_putc(s, peer_id_len);
	stream_put(s, peer_id, peer_id_len);

	if (path && path->extra && path->extra->crypto)
		crypto = path->extra->crypto;

	if (crypto) {
		bgp_crypto_put_string_tlv(s, BGP_CRYPTO_TLV_ALGORITHM,
					  crypto->algorithm);
		bgp_crypto_put_string_tlv(s, BGP_CRYPTO_TLV_CERTIFICATE_ID,
					  crypto->certificate_id);
		bgp_crypto_put_string_tlv(s, BGP_CRYPTO_TLV_PUBLIC_KEY_ID,
					  crypto->public_key_id);
		stream_putw(s, BGP_CRYPTO_TLV_CAPABILITY_BITMAP);
		stream_putw(s, sizeof(uint64_t));
		stream_putq(s, crypto->capability_bitmap);
		stream_putw(s, BGP_CRYPTO_TLV_TRUST_LEVEL);
		stream_putw(s, 1);
		stream_putc(s, crypto->trust_level);
	}

	nlri_len = stream_get_endp(s) - body_start;
	stream_putw_at(s, nlri_len_pos, (uint16_t)nlri_len);
}

size_t bgp_crypto_nlri_size(const struct prefix *p)
{
	/* The update packer needs a conservative maximum before it can see the
	 * path metadata; keep this bound intentionally small and explicit.
	 */
	(void)p;
	return BGP_CRYPTO_NLRI_MAX_SIZE;
}

const char *bgp_crypto_capability_str(uint64_t bitmap, char *buf, size_t len)
{
	bool first = true;

	if (!buf || !len)
		return "";

	buf[0] = '\0';

#define BGP_CRYPTO_APPEND_CAP(_bit, _name)                                    \
	do {                                                                  \
		if (CHECK_FLAG(bitmap, (_bit))) {                             \
			snprintfrr(buf + strlen(buf), len - strlen(buf),      \
				   "%s%s", first ? "" : ",", (_name));     \
			first = false;                                       \
		}                                                             \
	} while (0)

	BGP_CRYPTO_APPEND_CAP(BGP_CRYPTO_CAPABILITY_SIGN, "sign");
	BGP_CRYPTO_APPEND_CAP(BGP_CRYPTO_CAPABILITY_VERIFY, "verify");
	BGP_CRYPTO_APPEND_CAP(BGP_CRYPTO_CAPABILITY_ENCRYPT, "encrypt");

#undef BGP_CRYPTO_APPEND_CAP

	if (first)
		strlcpy(buf, "none", len);

	return buf;
}

static int bgp_crypto_capability_parse(const char *str, uint64_t *bitmap)
{
	uint64_t caps = 0;
	char work[128];
	char *saveptr = NULL;
	char *token;

	if (!str || strlen(str) >= sizeof(work))
		return -1;

	strlcpy(work, str, sizeof(work));
	for (token = strtok_r(work, ",", &saveptr); token;
	     token = strtok_r(NULL, ",", &saveptr)) {
		if (strmatch(token, "sign"))
			SET_FLAG(caps, BGP_CRYPTO_CAPABILITY_SIGN);
		else if (strmatch(token, "verify"))
			SET_FLAG(caps, BGP_CRYPTO_CAPABILITY_VERIFY);
		else if (strmatch(token, "encrypt"))
			SET_FLAG(caps, BGP_CRYPTO_CAPABILITY_ENCRYPT);
		else
			return -1;
	}

	if (!caps)
		return -1;

	*bitmap = caps;
	return 0;
}

static unsigned int bgp_crypto_route_count(struct bgp *bgp)
{
	struct bgp_table *table;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	unsigned int count = 0;

	if (!bgp)
		return 0;

	table = bgp->rib[AFI_CRYPTO][SAFI_CRYPTO_ROUTES];
	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest))
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
			if (pi->extra && pi->extra->crypto &&
			    !CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
				count++;

	return count;
}

static void bgp_crypto_show_one(struct vty *vty, const struct bgp_path_info *pi,
				bool detail, json_object *json_routes)
{
	const struct bgp_path_info_extra_crypto *crypto = pi->extra->crypto;
	char caps[64];

	if (json_routes) {
		json_object *json = json_object_new_object();

		json_object_string_add(json, "peerId", crypto->peer_id);
		json_object_string_add(json, "algorithm", crypto->algorithm);
		json_object_string_add(json, "certificateId",
				       crypto->certificate_id);
		json_object_string_add(json, "publicKeyId",
				       crypto->public_key_id);
		json_object_string_add(json, "capabilities",
				       bgp_crypto_capability_str(
					       crypto->capability_bitmap, caps,
					       sizeof(caps)));
		json_object_int_add(json, "trustLevel", crypto->trust_level);
		json_object_int_add(json, "version", crypto->version);
		json_object_string_add(json, "source",
				       pi->peer ? pi->peer->host : "unknown");
		json_object_boolean_add(json, "valid",
					CHECK_FLAG(pi->flags, BGP_PATH_VALID));
		json_object_boolean_add(json, "best",
					CHECK_FLAG(pi->flags, BGP_PATH_SELECTED));
		json_object_array_add(json_routes, json);
		return;
	}

	vty_out(vty, "%-24s %-12s %-24s %-24s %-14s %3u %s\n",
		crypto->peer_id, crypto->algorithm, crypto->certificate_id,
		crypto->public_key_id,
		bgp_crypto_capability_str(crypto->capability_bitmap, caps,
					  sizeof(caps)),
		crypto->trust_level, pi->peer ? pi->peer->host : "-");
	if (detail) {
		vty_out(vty, "  version %u, valid %s, best %s\n",
			crypto->version,
			CHECK_FLAG(pi->flags, BGP_PATH_VALID) ? "yes" : "no",
			CHECK_FLAG(pi->flags, BGP_PATH_SELECTED) ? "yes" : "no");
	}
}

static int bgp_crypto_show(struct vty *vty, const char *peer_id, bool detail,
			   bool use_json)
{
	struct bgp *bgp = bgp_get_default();
	struct bgp_table *table;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	json_object *json = NULL;
	json_object *json_routes = NULL;
	unsigned int count = 0;

	if (!bgp)
		return CMD_WARNING;

	table = bgp->rib[AFI_CRYPTO][SAFI_CRYPTO_ROUTES];

	if (use_json) {
		json = json_object_new_object();
		json_routes = json_object_new_array();
		json_object_object_add(json, "routes", json_routes);
	} else {
		vty_out(vty, "%-24s %-12s %-24s %-24s %-14s %3s %s\n",
			"Peer-ID", "Algorithm", "Certificate-ID",
			"Public-Key-ID", "Capabilities", "Tr", "Source");
	}

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (!pi->extra || !pi->extra->crypto ||
			    CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
				continue;
			if (peer_id &&
			    !strmatch(peer_id, pi->extra->crypto->peer_id))
				continue;

			bgp_crypto_show_one(vty, pi, detail, json_routes);
			count++;
		}
	}

	if (use_json) {
		json_object_int_add(json, "totalRoutes", count);
		vty_json(vty, json);
	} else {
		vty_out(vty, "\nDisplayed %u crypto route%s\n", count,
			count == 1 ? "" : "s");
	}

	return CMD_SUCCESS;
}

DEFUN (bgp_crypto_peer,
       bgp_crypto_peer_cmd,
       "crypto-peer WORD algorithm WORD certificate-id WORD public-key-id WORD capabilities WORD trust-level (0-100)",
       "Configure a local crypto route\n"
       "Crypto peer identifier\n"
       "Cryptographic algorithm\n"
       "Algorithm name\n"
       "Certificate identifier\n"
       "Certificate identifier\n"
       "Public key identifier\n"
       "Public key identifier\n"
       "Capability list: sign,verify,encrypt or comma-separated values\n"
       "Capabilities\n"
       "Trust level\n"
       "Trust level\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct bgp_path_info_extra_crypto crypto = {};
	unsigned long trust_level;
	uint64_t capabilities;
	int ret;

	if (!bgp->peer_self) {
		vty_out(vty, "%% BGP instance is not ready\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (!bgp_crypto_copy_string(crypto.peer_id, sizeof(crypto.peer_id),
				    argv[1]->arg)) {
		vty_out(vty, "%% Invalid crypto peer-id\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (!bgp_crypto_copy_string(crypto.algorithm, sizeof(crypto.algorithm),
				    argv[3]->arg)) {
		vty_out(vty, "%% Invalid crypto algorithm\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (!bgp_crypto_copy_string(crypto.certificate_id,
				    sizeof(crypto.certificate_id),
				    argv[5]->arg)) {
		vty_out(vty, "%% Invalid certificate-id\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (!bgp_crypto_copy_string(crypto.public_key_id,
				    sizeof(crypto.public_key_id),
				    argv[7]->arg)) {
		vty_out(vty, "%% Invalid public-key-id\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (bgp_crypto_capability_parse(argv[9]->arg, &capabilities) < 0) {
		vty_out(vty, "%% Capabilities must be sign, verify, encrypt, or a comma-separated combination\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	trust_level = strtoul(argv[11]->arg, NULL, 10);
	if (trust_level > 100) {
		vty_out(vty, "%% Trust level must be 0-100\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	crypto.capability_bitmap = capabilities;
	crypto.trust_level = trust_level;
	crypto.version = BGP_CRYPTO_VERSION;

	ret = bgp_crypto_route_add(bgp->peer_self, NULL, &crypto);
	return ret < 0 ? CMD_WARNING_CONFIG_FAILED : CMD_SUCCESS;
}

DEFUN (no_bgp_crypto_peer,
       no_bgp_crypto_peer_cmd,
       "no crypto-peer WORD",
       NO_STR
       "Remove a local crypto route\n"
       "Crypto peer identifier\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);

	if (!bgp->peer_self)
		return CMD_SUCCESS;

	bgp_crypto_route_delete(bgp, bgp->peer_self, argv[2]->arg);
	return CMD_SUCCESS;
}

DEFUN (show_bgp_crypto_routes,
       show_bgp_crypto_routes_cmd,
       "show bgp crypto-routes [json]",
       SHOW_STR
       BGP_STR
       "Crypto metadata routes\n"
       JSON_STR)
{
	bool use_json = false;
	int idx;

	if (argv_find(argv, argc, "json", &idx))
		use_json = true;

	return bgp_crypto_show(vty, NULL, false, use_json);
}

DEFUN (show_bgp_crypto_routes_detail,
       show_bgp_crypto_routes_detail_cmd,
       "show bgp crypto-routes detail [json]",
       SHOW_STR
       BGP_STR
       "Crypto metadata routes\n"
       "Detailed crypto route information\n"
       JSON_STR)
{
	bool use_json = false;
	int idx;

	if (argv_find(argv, argc, "json", &idx))
		use_json = true;

	return bgp_crypto_show(vty, NULL, true, use_json);
}

DEFUN (show_bgp_crypto_routes_peer,
       show_bgp_crypto_routes_peer_cmd,
       "show bgp crypto-routes peer WORD [json]",
       SHOW_STR
       BGP_STR
       "Crypto metadata routes\n"
       "Filter by crypto peer-id\n"
       "Crypto peer identifier\n"
       JSON_STR)
{
	bool use_json = false;
	int idx;

	if (argv_find(argv, argc, "json", &idx))
		use_json = true;

	return bgp_crypto_show(vty, argv[4]->arg, true, use_json);
}

DEFUN (show_bgp_crypto_routes_summary,
       show_bgp_crypto_routes_summary_cmd,
       "show bgp crypto-routes summary [json]",
       SHOW_STR
       BGP_STR
       "Crypto metadata routes\n"
       "Summary of crypto metadata routes\n"
       JSON_STR)
{
	struct bgp *bgp = bgp_get_default();
	bool use_json = false;
	int idx;
	unsigned int local_count = 0;
	unsigned int remote_count = 0;
	unsigned int total;
	struct bgp_table *table;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;

	if (argv_find(argv, argc, "json", &idx))
		use_json = true;

	if (!bgp)
		return CMD_WARNING;

	table = bgp->rib[AFI_CRYPTO][SAFI_CRYPTO_ROUTES];
	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest))
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
			if (pi->extra && pi->extra->crypto &&
			    !CHECK_FLAG(pi->flags, BGP_PATH_REMOVED)) {
				if (pi->peer == bgp->peer_self)
					local_count++;
				else
					remote_count++;
			}

	total = local_count + remote_count;

	if (use_json) {
		json_object *json = json_object_new_object();

		json_object_int_add(json, "totalRoutes", total);
		json_object_int_add(json, "localRoutes", local_count);
		json_object_int_add(json, "remoteRoutes", remote_count);
		vty_json(vty, json);
	} else {
		vty_out(vty, "Total crypto routes: %u\n", total);
		vty_out(vty, "Local crypto routes: %u\n", local_count);
		vty_out(vty, "Remote crypto routes: %u\n", remote_count);
	}

	return CMD_SUCCESS;
}

void bgp_crypto_config_write(struct vty *vty, struct bgp *bgp)
{
	struct bgp_table *table;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;

	if (!bgp)
		return;

	table = bgp->rib[AFI_CRYPTO][SAFI_CRYPTO_ROUTES];
	if (!table || !bgp_crypto_route_count(bgp))
		return;

	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			const struct bgp_path_info_extra_crypto *crypto;
			char caps[64];

			if (pi->peer != bgp->peer_self || !pi->extra ||
			    !pi->extra->crypto ||
			    CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
				continue;

			crypto = pi->extra->crypto;
			vty_out(vty,
				"  crypto-peer %s algorithm %s certificate-id %s public-key-id %s capabilities %s trust-level %u\n",
				crypto->peer_id, crypto->algorithm,
				crypto->certificate_id, crypto->public_key_id,
				bgp_crypto_capability_str(
					crypto->capability_bitmap, caps,
					sizeof(caps)),
				crypto->trust_level);
		}
	}
}

void bgp_crypto_vty_init(void)
{
	install_element(BGP_CRYPTO_ROUTES_NODE, &bgp_crypto_peer_cmd);
	install_element(BGP_CRYPTO_ROUTES_NODE, &no_bgp_crypto_peer_cmd);

	install_element(VIEW_NODE, &show_bgp_crypto_routes_cmd);
	install_element(VIEW_NODE, &show_bgp_crypto_routes_detail_cmd);
	install_element(VIEW_NODE, &show_bgp_crypto_routes_peer_cmd);
	install_element(VIEW_NODE, &show_bgp_crypto_routes_summary_cmd);
	install_element(ENABLE_NODE, &show_bgp_crypto_routes_cmd);
	install_element(ENABLE_NODE, &show_bgp_crypto_routes_detail_cmd);
	install_element(ENABLE_NODE, &show_bgp_crypto_routes_peer_cmd);
	install_element(ENABLE_NODE, &show_bgp_crypto_routes_summary_cmd);
}
