// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS TLV Serializer/Deserializer
 *
 * Copyright (C) 2015,2017 Christian Franke
 *
 * Copyright (C) 2019 Olivier Dugeon - Orange Labs (for TE and SR)
 *
 * Copyright (C) 2023 Carmine Scarpitta - University of Rome Tor Vergata
 * (for IS-IS Extensions to Support SRv6 as per RFC 9352)
 */

#include <zebra.h>
#include <json-c/json_object.h>

#ifdef CRYPTO_OPENSSL
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif

#ifdef CRYPTO_INTERNAL
#include "md5.h"
#endif
#include "memory.h"
#include "stream.h"
#include "sbuf.h"
#include "network.h"

#include "isisd/isisd.h"
#include "isisd/isis_tlvs.h"
#include "isisd/isis_common.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_te.h"
#include "isisd/isis_sr.h"
#include "isisd/isis_flex_algo.h"

#define TLV_SIZE_MISMATCH(log, indent, target)                                 \
	sbuf_push(log, indent,                                                 \
		  "TLV size does not match expected size for " target "!\n")

DEFINE_MTYPE_STATIC(ISISD, ISIS_TLV, "ISIS TLVs");
DEFINE_MTYPE(ISISD, ISIS_SUBTLV, "ISIS Sub-TLVs");
DEFINE_MTYPE(ISISD, ISIS_SUBSUBTLV, "ISIS Sub-Sub-TLVs");
DEFINE_MTYPE_STATIC(ISISD, ISIS_MT_ITEM_LIST, "ISIS MT Item Lists");

typedef int (*unpack_tlv_func)(enum isis_tlv_context context, uint8_t tlv_type,
			       uint8_t tlv_len, struct stream *s,
			       struct sbuf *log, void *dest, int indent);
typedef int (*pack_item_func)(struct isis_item *item, struct stream *s,
			      size_t *min_length);
typedef void (*free_item_func)(struct isis_item *i);
typedef int (*unpack_item_func)(uint16_t mtid, uint8_t len, struct stream *s,
				struct sbuf *log, void *dest, int indent);
typedef void (*format_item_func)(uint16_t mtid, struct isis_item *i,
				 struct sbuf *buf, struct json_object *json,
				 int indent);
typedef struct isis_item *(*copy_item_func)(struct isis_item *i);

struct tlv_ops {
	const char *name;
	unpack_tlv_func unpack;

	pack_item_func pack_item;
	free_item_func free_item;
	unpack_item_func unpack_item;
	format_item_func format_item;
	copy_item_func copy_item;
};

enum how_to_pack {
	ISIS_ITEMS,
	ISIS_MT_ITEMS,
};

struct pack_order_entry {
	enum isis_tlv_context context;
	enum isis_tlv_type type;
	enum how_to_pack how_to_pack;
	size_t what_to_pack;
};
#define PACK_ENTRY(t, h, w)                                                    \
	{                                                                      \
		.context = ISIS_CONTEXT_LSP, .type = ISIS_TLV_##t,             \
		.how_to_pack = (h),                                            \
		.what_to_pack = offsetof(struct isis_tlvs, w),                 \
	}

static const struct pack_order_entry pack_order[] = {
	PACK_ENTRY(OLDSTYLE_REACH, ISIS_ITEMS, oldstyle_reach),
	PACK_ENTRY(LAN_NEIGHBORS, ISIS_ITEMS, lan_neighbor),
	PACK_ENTRY(LSP_ENTRY, ISIS_ITEMS, lsp_entries),
	PACK_ENTRY(EXTENDED_REACH, ISIS_ITEMS, extended_reach),
	PACK_ENTRY(MT_REACH, ISIS_MT_ITEMS, mt_reach),
	PACK_ENTRY(OLDSTYLE_IP_REACH, ISIS_ITEMS, oldstyle_ip_reach),
	PACK_ENTRY(OLDSTYLE_IP_REACH_EXT, ISIS_ITEMS, oldstyle_ip_reach_ext),
	PACK_ENTRY(IPV4_ADDRESS, ISIS_ITEMS, ipv4_address),
	PACK_ENTRY(IPV6_ADDRESS, ISIS_ITEMS, ipv6_address),
	PACK_ENTRY(GLOBAL_IPV6_ADDRESS, ISIS_ITEMS, global_ipv6_address),
	PACK_ENTRY(EXTENDED_IP_REACH, ISIS_ITEMS, extended_ip_reach),
	PACK_ENTRY(MT_IP_REACH, ISIS_MT_ITEMS, mt_ip_reach),
	PACK_ENTRY(IPV6_REACH, ISIS_ITEMS, ipv6_reach),
	PACK_ENTRY(MT_IPV6_REACH, ISIS_MT_ITEMS, mt_ipv6_reach),
	PACK_ENTRY(SRV6_LOCATOR, ISIS_MT_ITEMS, srv6_locator)
};

/* This is a forward definition. The table is actually initialized
 * in at the bottom. */
static const struct tlv_ops *const tlv_table[ISIS_CONTEXT_MAX][ISIS_TLV_MAX];

/* End of _ops forward definition. */

/* Prototypes */
static void append_item(struct isis_item_list *dest, struct isis_item *item);
static void init_item_list(struct isis_item_list *items);

static struct isis_subsubtlvs *
isis_copy_subsubtlvs(struct isis_subsubtlvs *subsubtlvs);
static void isis_format_subsubtlvs(struct isis_subsubtlvs *subsubtlvs,
				   struct sbuf *buf, struct json_object *json,
				   int indent);
static int isis_pack_subsubtlvs(struct isis_subsubtlvs *subsubtlvs,
				struct stream *s);
static int unpack_tlvs(enum isis_tlv_context context, size_t avail_len,
		       struct stream *stream, struct sbuf *log, void *dest,
		       int indent, bool *unpacked_known_tlvs);
static void isis_free_subsubtlvs(struct isis_subsubtlvs *subsubtlvs);

/* For tests/isisd, TLV text requires ipv4-unicast instead of standard */
static const char *isis_mtid2str_fake(uint16_t mtid)
{
	if (mtid == ISIS_MT_STANDARD)
		return "ipv4-unicast";
	return isis_mtid2str(mtid);
}

/* Functions for Extended IS Reachability SubTLVs a.k.a Traffic Engineering */
struct isis_ext_subtlvs *isis_alloc_ext_subtlvs(void)
{
	struct isis_ext_subtlvs *ext;

	ext = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(struct isis_ext_subtlvs));
	init_item_list(&ext->adj_sid);
	init_item_list(&ext->lan_sid);
	ext->aslas = list_new();

	init_item_list(&ext->srv6_endx_sid);
	init_item_list(&ext->srv6_lan_endx_sid);

	admin_group_init(&ext->ext_admin_group);

	return ext;
}

void isis_del_ext_subtlvs(struct isis_ext_subtlvs *ext)
{
	struct isis_item *item, *next_item;
	struct listnode *node, *nnode;
	struct isis_asla_subtlvs *asla;

	if (!ext)
		return;

	/* First, free Adj SID and LAN Adj SID list if needed */
	for (item = ext->adj_sid.head; item; item = next_item) {
		next_item = item->next;
		XFREE(MTYPE_ISIS_SUBTLV, item);
	}
	for (item = ext->lan_sid.head; item; item = next_item) {
		next_item = item->next;
		XFREE(MTYPE_ISIS_SUBTLV, item);
	}

	for (ALL_LIST_ELEMENTS(ext->aslas, node, nnode, asla))
		isis_tlvs_del_asla_flex_algo(ext, asla);

	list_delete(&ext->aslas);

	admin_group_term(&ext->ext_admin_group);

	/* First, free SRv6 End.X SID and SRv6 LAN End.X SID list if needed */
	for (item = ext->srv6_endx_sid.head; item; item = next_item) {
		next_item = item->next;
		isis_free_subsubtlvs(((struct isis_srv6_endx_sid_subtlv *)item)->subsubtlvs);
		XFREE(MTYPE_ISIS_SUBTLV, item);
	}
	for (item = ext->srv6_lan_endx_sid.head; item; item = next_item) {
		next_item = item->next;
		isis_free_subsubtlvs(((struct isis_srv6_lan_endx_sid_subtlv *)item)->subsubtlvs);
		XFREE(MTYPE_ISIS_SUBTLV, item);
	}

	XFREE(MTYPE_ISIS_SUBTLV, ext);
}

/*
 * mtid parameter is used to determine if Adjacency is related to IPv4 or IPv6
 * Multi-Topology. Special 4096 value i.e. first R flag set is used to indicate
 * that MT is disabled i.e. IS-IS is working with a Single Topology.
 */
static struct isis_ext_subtlvs *
copy_item_ext_subtlvs(struct isis_ext_subtlvs *exts, uint16_t mtid)
{
	struct isis_ext_subtlvs *rv = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*rv));
	struct isis_adj_sid *adj;
	struct isis_lan_adj_sid *lan;
	struct listnode *node, *nnode;
	struct isis_asla_subtlvs *new_asla, *asla;
	struct isis_srv6_endx_sid_subtlv *srv6_adj;
	struct isis_srv6_lan_endx_sid_subtlv *srv6_lan;

	/* Copy the Extended IS main part */
	memcpy(rv, exts, sizeof(struct isis_ext_subtlvs));

	/* Disable IPv4 / IPv6 advertisement in function of MTID */
	if (mtid == ISIS_MT_IPV4_UNICAST) {
		UNSET_SUBTLV(rv, EXT_LOCAL_ADDR6);
		UNSET_SUBTLV(rv, EXT_NEIGH_ADDR6);
	}
	if (mtid == ISIS_MT_IPV6_UNICAST) {
		UNSET_SUBTLV(rv, EXT_LOCAL_ADDR);
		UNSET_SUBTLV(rv, EXT_NEIGH_ADDR);
	}

	/* Prepare (LAN)-Adjacency Segment Routing ID*/
	init_item_list(&rv->adj_sid);
	init_item_list(&rv->lan_sid);

	/* Prepare SRv6 (LAN) End.X SID */
	init_item_list(&rv->srv6_endx_sid);
	init_item_list(&rv->srv6_lan_endx_sid);

	UNSET_SUBTLV(rv, EXT_ADJ_SID);
	UNSET_SUBTLV(rv, EXT_LAN_ADJ_SID);

	UNSET_SUBTLV(rv, EXT_SRV6_ENDX_SID);
	UNSET_SUBTLV(rv, EXT_SRV6_LAN_ENDX_SID);

	/* Copy Adj SID list for IPv4 & IPv6 in function of MT ID */
	for (adj = (struct isis_adj_sid *)exts->adj_sid.head; adj != NULL;
	     adj = adj->next) {
		if ((mtid != ISIS_MT_DISABLE)
		    && (((mtid == ISIS_MT_IPV4_UNICAST)
			 && (adj->family != AF_INET))
			|| ((mtid == ISIS_MT_IPV6_UNICAST)
			    && (adj->family != AF_INET6))))
			continue;

		struct isis_adj_sid *new;

		new = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(struct isis_adj_sid));
		new->family = adj->family;
		new->flags = adj->flags;
		new->weight = adj->weight;
		new->sid = adj->sid;
		append_item(&rv->adj_sid, (struct isis_item *)new);
		SET_SUBTLV(rv, EXT_ADJ_SID);
	}

	/* Same for LAN Adj SID */
	for (lan = (struct isis_lan_adj_sid *)exts->lan_sid.head; lan != NULL;
	     lan = lan->next) {
		if ((mtid != ISIS_MT_DISABLE)
		    && (((mtid == ISIS_MT_IPV4_UNICAST)
			 && (lan->family != AF_INET))
			|| ((mtid == ISIS_MT_IPV6_UNICAST)
			    && (lan->family != AF_INET6))))
			continue;

		struct isis_lan_adj_sid *new;

		new = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(struct isis_lan_adj_sid));
		new->family = lan->family;
		new->flags = lan->flags;
		new->weight = lan->weight;
		memcpy(new->neighbor_id, lan->neighbor_id, 6);
		new->sid = lan->sid;
		append_item(&rv->lan_sid, (struct isis_item *)new);
		SET_SUBTLV(rv, EXT_LAN_ADJ_SID);
	}

	/* Copy SRv6 End.X SID list for IPv4 & IPv6 in function of MT ID */
	for (srv6_adj = (struct isis_srv6_endx_sid_subtlv *)
				exts->srv6_endx_sid.head;
	     srv6_adj != NULL; srv6_adj = srv6_adj->next) {
		if ((mtid != 65535) && (mtid != ISIS_MT_DISABLE) &&
		    ((mtid != ISIS_MT_IPV6_UNICAST)))
			continue;

		struct isis_srv6_endx_sid_subtlv *new;

		new = XCALLOC(MTYPE_ISIS_SUBTLV,
			      sizeof(struct isis_srv6_endx_sid_subtlv));
		new->flags = srv6_adj->flags;
		new->algorithm = srv6_adj->algorithm;
		new->weight = srv6_adj->weight;
		new->behavior = srv6_adj->behavior;
		new->sid = srv6_adj->sid;
		new->subsubtlvs = isis_copy_subsubtlvs(srv6_adj->subsubtlvs);
		append_item(&rv->srv6_endx_sid, (struct isis_item *)new);
		SET_SUBTLV(rv, EXT_SRV6_ENDX_SID);
	}
	/* Same for SRv6 LAN End.X SID */
	for (srv6_lan = (struct isis_srv6_lan_endx_sid_subtlv *)
				exts->srv6_lan_endx_sid.head;
	     srv6_lan != NULL; srv6_lan = srv6_lan->next) {
		if ((mtid != 65535) && (mtid != ISIS_MT_DISABLE) &&
		    ((mtid != ISIS_MT_IPV6_UNICAST)))
			continue;

		struct isis_srv6_lan_endx_sid_subtlv *new;

		new = XCALLOC(MTYPE_ISIS_SUBTLV,
			      sizeof(struct isis_srv6_lan_endx_sid_subtlv));
		memcpy(new->neighbor_id, srv6_lan->neighbor_id, 6);
		new->flags = srv6_lan->flags;
		new->algorithm = srv6_lan->algorithm;
		new->weight = srv6_lan->weight;
		new->behavior = srv6_lan->behavior;
		new->sid = srv6_lan->sid;
		new->subsubtlvs = isis_copy_subsubtlvs(srv6_lan->subsubtlvs);
		append_item(&rv->srv6_lan_endx_sid, (struct isis_item *)new);
		SET_SUBTLV(rv, EXT_SRV6_LAN_ENDX_SID);
	}

	rv->aslas = list_new();

	for (ALL_LIST_ELEMENTS(exts->aslas, node, nnode, asla)) {
		new_asla = XCALLOC(MTYPE_ISIS_SUBTLV,
				   sizeof(struct isis_asla_subtlvs));
		memcpy(new_asla, asla, sizeof(struct isis_asla_subtlvs));

		new_asla->ext_admin_group.bitmap.data = NULL;
		admin_group_copy(&new_asla->ext_admin_group,
				 &asla->ext_admin_group);

		listnode_add(rv->aslas, new_asla);
	}

	rv->ext_admin_group.bitmap.data = NULL;
	admin_group_copy(&rv->ext_admin_group, &exts->ext_admin_group);

	return rv;
}

static void format_item_asla_subtlvs(struct isis_asla_subtlvs *asla,
				     struct sbuf *buf, int indent)
{
	char admin_group_buf[ADMIN_GROUP_PRINT_MAX_SIZE];

	sbuf_push(buf, indent, "Application Specific Link Attributes:\n");
	sbuf_push(buf, indent + 2,
		  "L flag: %u, SA-Length: %u, UDA-Length: %u\n", asla->legacy,
		  asla->standard_apps_length, asla->user_def_apps_length);
	sbuf_push(buf, indent + 2, "Standard Applications: 0x%02x",
		  asla->standard_apps);
	if (asla->standard_apps) {
		uint8_t bit = asla->standard_apps;
		if (bit & ISIS_SABM_FLAG_R)
			sbuf_push(buf, 0, " RSVP-TE");
		if (bit & ISIS_SABM_FLAG_S)
			sbuf_push(buf, 0, " SR-Policy");
		if (bit & ISIS_SABM_FLAG_L)
			sbuf_push(buf, 0, " Loop-Free-Alternate");
		if (bit & ISIS_SABM_FLAG_X)
			sbuf_push(buf, 0, " Flex-Algo");
	}
	sbuf_push(buf, 0, "\n");
	sbuf_push(buf, indent + 2, "User Defined Applications: 0x%02x\n",
		  asla->user_def_apps);

	if (IS_SUBTLV(asla, EXT_ADM_GRP)) {
		sbuf_push(buf, indent + 2, "Admin Group: 0x%08x\n",
			  asla->admin_group);
		sbuf_push(buf, indent + 4, "Bit positions: %s\n",
			  admin_group_standard_print(
				  admin_group_buf,
				  indent + 2 + strlen("Admin Group: "),
				  asla->admin_group));
	}
	if (IS_SUBTLV(asla, EXT_EXTEND_ADM_GRP) &&
	    admin_group_nb_words(&asla->ext_admin_group) != 0) {
		sbuf_push(buf, indent + 2, "Ext Admin Group: %s\n",
			  admin_group_string(
				  admin_group_buf, ADMIN_GROUP_PRINT_MAX_SIZE,
				  indent + 2 + strlen("Ext Admin Group: "),
				  &asla->ext_admin_group));
		admin_group_print(admin_group_buf,
				  indent + 2 + strlen("Ext Admin Group: "),
				  &asla->ext_admin_group);
		if (admin_group_buf[0] != '\0' &&
		    (buf->pos + strlen(admin_group_buf) +
		     SBUF_DEFAULT_SIZE / 2) < buf->size)
			sbuf_push(buf, indent + 4, "Bit positions: %s\n",
				  admin_group_buf);
	}
	if (IS_SUBTLV(asla, EXT_MAX_BW))
		sbuf_push(buf, indent + 2,
			  "Maximum Bandwidth: %g (Bytes/sec)\n", asla->max_bw);
	if (IS_SUBTLV(asla, EXT_MAX_RSV_BW))
		sbuf_push(buf, indent + 2,
			  "Maximum Reservable Bandwidth: %g (Bytes/sec)\n",
			  asla->max_rsv_bw);
	if (IS_SUBTLV(asla, EXT_UNRSV_BW)) {
		sbuf_push(buf, indent + 2, "Unreserved Bandwidth:\n");
		for (int j = 0; j < MAX_CLASS_TYPE; j += 2) {
			sbuf_push(
				buf, indent + 2,
				"[%d]: %g (Bytes/sec),\t[%d]: %g (Bytes/sec)\n",
				j, asla->unrsv_bw[j], j + 1,
				asla->unrsv_bw[j + 1]);
		}
	}
	if (IS_SUBTLV(asla, EXT_TE_METRIC))
		sbuf_push(buf, indent + 2, "Traffic Engineering Metric: %u\n",
			  asla->te_metric);
	/* Extended metrics */
	if (IS_SUBTLV(asla, EXT_DELAY))
		sbuf_push(buf, indent + 2,
			  "%s Average Link Delay: %u (micro-sec)\n",
			  IS_ANORMAL(asla->delay) ? "Anomalous" : "Normal",
			  asla->delay);
	if (IS_SUBTLV(asla, EXT_MM_DELAY)) {
		sbuf_push(buf, indent + 2,
			  "%s Min/Max Link Delay: %u / %u (micro-sec)\n",
			  IS_ANORMAL(asla->min_delay) ? "Anomalous" : "Normal",
			  asla->min_delay & TE_EXT_MASK,
			  asla->max_delay & TE_EXT_MASK);
	}
	if (IS_SUBTLV(asla, EXT_DELAY_VAR)) {
		sbuf_push(buf, indent + 2, "Delay Variation: %u (micro-sec)\n",
			  asla->delay_var & TE_EXT_MASK);
	}
	if (IS_SUBTLV(asla, EXT_PKT_LOSS))
		sbuf_push(buf, indent + 2, "%s Link Packet Loss: %g (%%)\n",
			  IS_ANORMAL(asla->pkt_loss) ? "Anomalous" : "Normal",
			  (float)((asla->pkt_loss & TE_EXT_MASK) *
				  LOSS_PRECISION));
	if (IS_SUBTLV(asla, EXT_RES_BW))
		sbuf_push(buf, indent + 2,
			  "Unidir. Residual Bandwidth: %g (Bytes/sec)\n",
			  asla->res_bw);
	if (IS_SUBTLV(asla, EXT_AVA_BW))
		sbuf_push(buf, indent + 2,
			  "Unidir. Available Bandwidth: %g (Bytes/sec)\n",
			  asla->ava_bw);
	if (IS_SUBTLV(asla, EXT_USE_BW))
		sbuf_push(buf, indent + 2,
			  "Unidir. Utilized Bandwidth: %g (Bytes/sec)\n",
			  asla->use_bw);
}

/* mtid parameter is used to manage multi-topology i.e. IPv4 / IPv6 */
static void format_item_ext_subtlvs(struct isis_ext_subtlvs *exts,
				    struct sbuf *buf, struct json_object *json,
				    int indent, uint16_t mtid)
{
	char admin_group_buf[ADMIN_GROUP_PRINT_MAX_SIZE];
	char aux_buf[255];
	char cnt_buf[255];
	struct isis_asla_subtlvs *asla;
	struct listnode *node;

	/* Standard metrics */
	if (IS_SUBTLV(exts, EXT_ADM_GRP)) {
		if (json) {
			snprintfrr(aux_buf, sizeof(aux_buf), "0x%x",
				   exts->adm_group);
			json_object_string_add(json, "adm-group", aux_buf);
		} else {
			sbuf_push(buf, indent, "Admin Group: 0x%08x\n",
				  exts->adm_group);
			sbuf_push(buf, indent + 2, "Bit positions: %s\n",
				  admin_group_standard_print(
					  admin_group_buf,
					  indent + strlen("Admin Group: "),
					  exts->adm_group));
		}
	}

	if (IS_SUBTLV(exts, EXT_EXTEND_ADM_GRP) &&
	    admin_group_nb_words(&exts->ext_admin_group) != 0) {
		if (!json) {
			/* TODO json after fix show database detail json */
			sbuf_push(buf, indent, "Ext Admin Group: %s\n",
				  admin_group_string(
					  admin_group_buf,
					  ADMIN_GROUP_PRINT_MAX_SIZE,
					  indent + strlen("Ext Admin Group: "),
					  &exts->ext_admin_group));
			admin_group_print(admin_group_buf,
					  indent + strlen("Ext Admin Group: "),
					  &exts->ext_admin_group);
			if (admin_group_buf[0] != '\0' &&
			    (buf->pos + strlen(admin_group_buf) +
			     SBUF_DEFAULT_SIZE / 2) < buf->size)
				sbuf_push(buf, indent + 2,
					  "Bit positions: %s\n",
					  admin_group_buf);
		}
	}
	if (IS_SUBTLV(exts, EXT_LLRI)) {
		if (json) {
			json_object_int_add(json, "link-local-id",
					    exts->local_llri);
			json_object_int_add(json, "link-remote-id",
					    exts->remote_llri);
		} else {
			sbuf_push(buf, indent, "Link Local  ID: %u\n",
				  exts->local_llri);
			sbuf_push(buf, indent, "Link Remote ID: %u\n",
				  exts->remote_llri);
		}
	}
	if (IS_SUBTLV(exts, EXT_LOCAL_ADDR)) {
		if (json) {
			inet_ntop(AF_INET, &exts->local_addr, aux_buf,
				  sizeof(aux_buf));
			json_object_string_add(json, "local-iface-ip", aux_buf);
		} else
			sbuf_push(buf, indent,
				  "Local Interface IP Address(es): %pI4\n",
				  &exts->local_addr);
	}
	if (IS_SUBTLV(exts, EXT_NEIGH_ADDR)) {
		if (json) {
			inet_ntop(AF_INET, &exts->neigh_addr, aux_buf,
				  sizeof(aux_buf));
			json_object_string_add(json, "remote-iface-ip",
					       aux_buf);
		} else
			sbuf_push(buf, indent,
				  "Remote Interface IP Address(es): %pI4\n",
				  &exts->neigh_addr);
	}
	if (IS_SUBTLV(exts, EXT_LOCAL_ADDR6)) {
		if (json) {
			inet_ntop(AF_INET6, &exts->local_addr6, aux_buf,
				  sizeof(aux_buf));
			json_object_string_add(json, "local-iface-ipv6",
					       aux_buf);
		} else
			sbuf_push(buf, indent,
				  "Local Interface IPv6 Address(es): %pI6\n",
				  &exts->local_addr6);
	}
	if (IS_SUBTLV(exts, EXT_NEIGH_ADDR6)) {
		if (json) {
			inet_ntop(AF_INET6, &exts->neigh_addr6, aux_buf,
				  sizeof(aux_buf));
			json_object_string_add(json, "remote-iface-ipv6",
					       aux_buf);
		} else
			sbuf_push(buf, indent,
				  "Remote Interface IPv6 Address(es): %pI6\n",
				  &exts->neigh_addr6);
	}
	if (IS_SUBTLV(exts, EXT_MAX_BW)) {
		if (json) {
			snprintfrr(aux_buf, sizeof(aux_buf), "%g",
				   exts->max_bw);
			json_object_string_add(json, "max-bandwith-bytes-sec",
					       aux_buf);
		} else
			sbuf_push(buf, indent,
				  "Maximum Bandwidth: %g (Bytes/sec)\n",
				  exts->max_bw);
	}
	if (IS_SUBTLV(exts, EXT_MAX_RSV_BW)) {
		if (json) {
			snprintfrr(aux_buf, sizeof(aux_buf), "%g",
				   exts->max_rsv_bw);
			json_object_string_add(
				json, "max-res-bandwith-bytes-sec", aux_buf);
		} else
			sbuf_push(
				buf, indent,
				"Maximum Reservable Bandwidth: %g (Bytes/sec)\n",
				exts->max_rsv_bw);
	}
	if (IS_SUBTLV(exts, EXT_UNRSV_BW)) {
		if (json) {
			struct json_object *unrsv_json;
			unrsv_json = json_object_new_object();
			json_object_object_add(json, "unrsv-bandwith-bytes-sec",
					       unrsv_json);
			for (int j = 0; j < MAX_CLASS_TYPE; j += 1) {
				snprintfrr(cnt_buf, sizeof(cnt_buf), "%d", j);
				snprintfrr(aux_buf, sizeof(aux_buf), "%g",
					   exts->unrsv_bw[j]);
				json_object_string_add(unrsv_json, cnt_buf,
						       aux_buf);
			}
		} else {
			sbuf_push(buf, indent, "Unreserved Bandwidth:\n");
			for (int j = 0; j < MAX_CLASS_TYPE; j += 2) {
				sbuf_push(
					buf, indent + 2,
					"[%d]: %g (Bytes/sec),\t[%d]: %g (Bytes/sec)\n",
					j, exts->unrsv_bw[j], j + 1,
					exts->unrsv_bw[j + 1]);
			}
		}
	}
	if (IS_SUBTLV(exts, EXT_TE_METRIC)) {
		if (json) {
			json_object_int_add(json, "te-metric", exts->te_metric);
		} else
			sbuf_push(buf, indent,
				  "Traffic Engineering Metric: %u\n",
				  exts->te_metric);
	}
	if (IS_SUBTLV(exts, EXT_RMT_AS)) {
		if (json) {
			json_object_int_add(json, "inter-as-te-remote-as",
					    exts->remote_as);
		} else
			sbuf_push(buf, indent,
				  "Inter-AS TE Remote AS number: %u\n",
				  exts->remote_as);
	}
	if (IS_SUBTLV(exts, EXT_RMT_IP)) {
		if (json) {
			inet_ntop(AF_INET6, &exts->remote_ip, aux_buf,
				  sizeof(aux_buf));
			json_object_string_add(
				json, "inter-as-te-remote-asbr-ip", aux_buf);
		} else
			sbuf_push(buf, indent,
				  "Inter-AS TE Remote ASBR IP address: %pI4\n",
				  &exts->remote_ip);
	}
	/* Extended metrics */
	if (IS_SUBTLV(exts, EXT_DELAY)) {
		if (json) {
			struct json_object *avg_json;
			avg_json = json_object_new_object();
			json_object_object_add(json, "avg-delay", avg_json);
			json_object_string_add(avg_json, "delay",
					       IS_ANORMAL(exts->delay)
						       ? "Anomalous"
						       : "Normal");
			json_object_int_add(avg_json, "micro-sec", exts->delay);
		} else
			sbuf_push(buf, indent,
				  "%s Average Link Delay: %u (micro-sec)\n",
				  IS_ANORMAL(exts->delay) ? "Anomalous"
							  : "Normal",
				  exts->delay & TE_EXT_MASK);
	}
	if (IS_SUBTLV(exts, EXT_MM_DELAY)) {
		if (json) {
			struct json_object *avg_json;
			avg_json = json_object_new_object();
			json_object_object_add(json, "max-min-delay", avg_json);
			json_object_string_add(avg_json, "delay",
					       IS_ANORMAL(exts->min_delay)
						       ? "Anomalous"
						       : "Normal");
			snprintfrr(aux_buf, sizeof(aux_buf), "%u / %u",
				   exts->min_delay & TE_EXT_MASK,
				   exts->max_delay & TE_EXT_MASK);
			json_object_string_add(avg_json, "micro-sec", aux_buf);

		} else
			sbuf_push(
				buf, indent,
				"%s Min/Max Link Delay: %u / %u (micro-sec)\n",
				IS_ANORMAL(exts->min_delay) ? "Anomalous"
							    : "Normal",
				exts->min_delay & TE_EXT_MASK,
				exts->max_delay & TE_EXT_MASK);
	}
	if (IS_SUBTLV(exts, EXT_DELAY_VAR)) {
		if (json) {
			json_object_int_add(json, "delay-variation-micro-sec",
					    exts->delay_var & TE_EXT_MASK);
		} else
			sbuf_push(buf, indent,
				  "Delay Variation: %u (micro-sec)\n",
				  exts->delay_var & TE_EXT_MASK);
	}
	if (IS_SUBTLV(exts, EXT_PKT_LOSS)) {
		if (json) {
			snprintfrr(aux_buf, sizeof(aux_buf), "%g",
				   (float)((exts->pkt_loss & TE_EXT_MASK) *
					   LOSS_PRECISION));
			struct json_object *link_json;
			link_json = json_object_new_object();
			json_object_object_add(json, "link-packet-loss",
					       link_json);
			json_object_string_add(link_json, "loss",
					       IS_ANORMAL(exts->pkt_loss)
						       ? "Anomalous"
						       : "Normal");
			json_object_string_add(link_json, "percentaje",
					       aux_buf);
		} else
			sbuf_push(buf, indent, "%s Link Packet Loss: %g (%%)\n",
				  IS_ANORMAL(exts->pkt_loss) ? "Anomalous"
							     : "Normal",
				  (float)((exts->pkt_loss & TE_EXT_MASK) *
					  LOSS_PRECISION));
	}
	if (IS_SUBTLV(exts, EXT_RES_BW)) {
		if (json) {
			snprintfrr(aux_buf, sizeof(aux_buf), "%g",
				   (exts->res_bw));
			json_object_string_add(json,
					       "unidir-residual-band-bytes-sec",
					       aux_buf);
		} else
			sbuf_push(
				buf, indent,
				"Unidir. Residual Bandwidth: %g (Bytes/sec)\n",
				exts->res_bw);
	}
	if (IS_SUBTLV(exts, EXT_AVA_BW)) {
		if (json) {
			snprintfrr(aux_buf, sizeof(aux_buf), "%g",
				   (exts->ava_bw));
			json_object_string_add(
				json, "unidir-available-band-bytes-sec",
				aux_buf);
		} else
			sbuf_push(
				buf, indent,
				"Unidir. Available Bandwidth: %g (Bytes/sec)\n",
				exts->ava_bw);
	}
	if (IS_SUBTLV(exts, EXT_USE_BW)) {
		if (json) {
			snprintfrr(aux_buf, sizeof(aux_buf), "%g",
				   (exts->use_bw));
			json_object_string_add(json,
					       "unidir-utilized-band-bytes-sec",
					       aux_buf);
		} else
			sbuf_push(
				buf, indent,
				"Unidir. Utilized Bandwidth: %g (Bytes/sec)\n",
				exts->use_bw);
	}
	/* Segment Routing Adjacency  as per RFC8667 section #2.2.1 */
	if (IS_SUBTLV(exts, EXT_ADJ_SID)) {
		struct isis_adj_sid *adj;

		if (json) {
			struct json_object *arr_adj_json, *flags_json;
			arr_adj_json = json_object_new_array();
			json_object_object_add(json, "adj-sid", arr_adj_json);
			for (adj = (struct isis_adj_sid *)exts->adj_sid.head;
			     adj; adj = adj->next) {
				snprintfrr(cnt_buf, sizeof(cnt_buf), "%d",
					   adj->sid);
				flags_json = json_object_new_object();
				json_object_int_add(flags_json, "sid",
						    adj->sid);
				json_object_int_add(flags_json, "weight",
						    adj->weight);
				json_object_string_add(
					flags_json, "flag-f",
					adj->flags & EXT_SUBTLV_LINK_ADJ_SID_FFLG
						? "1"
						: "0");
				json_object_string_add(
					flags_json, "flag-b",
					adj->flags & EXT_SUBTLV_LINK_ADJ_SID_BFLG
						? "1"
						: "0");
				json_object_string_add(
					flags_json, "flag-v",
					adj->flags & EXT_SUBTLV_LINK_ADJ_SID_VFLG
						? "1"
						: "0");
				json_object_string_add(
					flags_json, "flag-l",
					adj->flags & EXT_SUBTLV_LINK_ADJ_SID_LFLG
						? "1"
						: "0");
				json_object_string_add(
					flags_json, "flag-s",
					adj->flags & EXT_SUBTLV_LINK_ADJ_SID_SFLG
						? "1"
						: "0");
				json_object_string_add(
					flags_json, "flag-p",
					adj->flags & EXT_SUBTLV_LINK_ADJ_SID_PFLG
						? "1"
						: "0");
				json_object_array_add(arr_adj_json, flags_json);
			}
		} else
			for (adj = (struct isis_adj_sid *)exts->adj_sid.head;
			     adj; adj = adj->next) {
				sbuf_push(
					buf, indent,
					"Adjacency-SID: %u, Weight: %hhu, Flags: F:%c B:%c, V:%c, L:%c, S:%c, P:%c\n",
					adj->sid, adj->weight,
					adj->flags & EXT_SUBTLV_LINK_ADJ_SID_FFLG
						? '1'
						: '0',
					adj->flags & EXT_SUBTLV_LINK_ADJ_SID_BFLG
						? '1'
						: '0',
					adj->flags & EXT_SUBTLV_LINK_ADJ_SID_VFLG
						? '1'
						: '0',
					adj->flags & EXT_SUBTLV_LINK_ADJ_SID_LFLG
						? '1'
						: '0',
					adj->flags & EXT_SUBTLV_LINK_ADJ_SID_SFLG
						? '1'
						: '0',
					adj->flags & EXT_SUBTLV_LINK_ADJ_SID_PFLG
						? '1'
						: '0');
			}
	}
	/* Segment Routing LAN-Adjacency as per RFC8667 section #2.2.2 */
	if (IS_SUBTLV(exts, EXT_LAN_ADJ_SID)) {
		struct isis_lan_adj_sid *lan;
		if (json) {
			struct json_object *arr_adj_json, *flags_json;
			arr_adj_json = json_object_new_array();
			json_object_object_add(json, "lan-adj-sid",
					       arr_adj_json);
			for (lan = (struct isis_lan_adj_sid *)
					   exts->adj_sid.head;
			     lan; lan = lan->next) {
				if (((mtid == ISIS_MT_IPV4_UNICAST) &&
				     (lan->family != AF_INET)) ||
				    ((mtid == ISIS_MT_IPV6_UNICAST) &&
				     (lan->family != AF_INET6)))
					continue;
				snprintfrr(cnt_buf, sizeof(cnt_buf), "%d",
					   lan->sid);
				flags_json = json_object_new_object();
				json_object_int_add(flags_json, "sid",
						    lan->sid);
				json_object_int_add(flags_json, "weight",
						    lan->weight);
				json_object_string_add(
					flags_json, "flag-f",
					lan->flags & EXT_SUBTLV_LINK_ADJ_SID_FFLG
						? "1"
						: "0");
				json_object_string_add(
					flags_json, "flag-b",
					lan->flags & EXT_SUBTLV_LINK_ADJ_SID_BFLG
						? "1"
						: "0");
				json_object_string_add(
					flags_json, "flag-v",
					lan->flags & EXT_SUBTLV_LINK_ADJ_SID_VFLG
						? "1"
						: "0");
				json_object_string_add(
					flags_json, "flag-l",
					lan->flags & EXT_SUBTLV_LINK_ADJ_SID_LFLG
						? "1"
						: "0");
				json_object_string_add(
					flags_json, "flag-s",
					lan->flags & EXT_SUBTLV_LINK_ADJ_SID_SFLG
						? "1"
						: "0");
				json_object_string_add(
					flags_json, "flag-p",
					lan->flags & EXT_SUBTLV_LINK_ADJ_SID_PFLG
						? "1"
						: "0");
				json_object_array_add(arr_adj_json, flags_json);
			}
		} else

			for (lan = (struct isis_lan_adj_sid *)
					   exts->lan_sid.head;
			     lan; lan = lan->next) {
				if (((mtid == ISIS_MT_IPV4_UNICAST) &&
				     (lan->family != AF_INET)) ||
				    ((mtid == ISIS_MT_IPV6_UNICAST) &&
				     (lan->family != AF_INET6)))
					continue;
				sbuf_push(
					buf, indent,
					"Lan-Adjacency-SID: %u, Weight: %hhu, Flags: F:%c B:%c, V:%c, L:%c, S:%c, P:%c\n"
					"  Neighbor-ID: %pSY\n",
					lan->sid, lan->weight,
					lan->flags & EXT_SUBTLV_LINK_ADJ_SID_FFLG
						? '1'
						: '0',
					lan->flags & EXT_SUBTLV_LINK_ADJ_SID_BFLG
						? '1'
						: '0',
					lan->flags & EXT_SUBTLV_LINK_ADJ_SID_VFLG
						? '1'
						: '0',
					lan->flags & EXT_SUBTLV_LINK_ADJ_SID_LFLG
						? '1'
						: '0',
					lan->flags & EXT_SUBTLV_LINK_ADJ_SID_SFLG
						? '1'
						: '0',
					lan->flags & EXT_SUBTLV_LINK_ADJ_SID_PFLG
						? '1'
						: '0',
					lan->neighbor_id);
			}
	}
	/* SRv6 End.X SID as per RFC9352 section #8.1 */
	if (IS_SUBTLV(exts, EXT_SRV6_ENDX_SID)) {
		struct isis_srv6_endx_sid_subtlv *adj;

		if (json) {
			struct json_object *arr_adj_json, *flags_json;
			arr_adj_json = json_object_new_array();
			json_object_object_add(json, "srv6-endx-sid",
					       arr_adj_json);
			for (adj = (struct isis_srv6_endx_sid_subtlv *)
					   exts->srv6_endx_sid.head;
			     adj; adj = adj->next) {
				snprintfrr(cnt_buf, sizeof(cnt_buf), "%pI6",
					   &adj->sid);
				flags_json = json_object_new_object();
				json_object_string_addf(flags_json, "sid",
							"%pI6", &adj->sid);
				json_object_string_add(
					flags_json, "algorithm",
					sr_algorithm_string(adj->algorithm));
				json_object_int_add(flags_json, "weight",
						    adj->weight);
				json_object_string_add(
					flags_json, "behavior",
					seg6local_action2str(adj->behavior));
				json_object_string_add(
					flags_json, "flag-b",
					adj->flags & EXT_SUBTLV_LINK_SRV6_ENDX_SID_BFLG
						? "1"
						: "0");
				json_object_string_add(
					flags_json, "flag-s",
					adj->flags & EXT_SUBTLV_LINK_SRV6_ENDX_SID_SFLG
						? "1"
						: "0");
				json_object_string_add(
					flags_json, "flag-p",
					adj->flags & EXT_SUBTLV_LINK_SRV6_ENDX_SID_PFLG
						? "1"
						: "0");
				json_object_array_add(arr_adj_json, flags_json);
				if (adj->subsubtlvs)
					isis_format_subsubtlvs(adj->subsubtlvs,
							       NULL, json,
							       indent + 4);
			}
		} else
			for (adj = (struct isis_srv6_endx_sid_subtlv *)
					   exts->srv6_endx_sid.head;
			     adj; adj = adj->next) {
				sbuf_push(
					buf, indent,
					"SRv6 End.X SID: %pI6, Algorithm: %s, Weight: %hhu, Endpoint Behavior: %s, Flags: B:%c, S:%c, P:%c\n",
					&adj->sid,
					sr_algorithm_string(adj->algorithm),
					adj->weight,
					seg6local_action2str(adj->behavior),
					adj->flags & EXT_SUBTLV_LINK_SRV6_ENDX_SID_BFLG
						? '1'
						: '0',
					adj->flags & EXT_SUBTLV_LINK_SRV6_ENDX_SID_SFLG
						? '1'
						: '0',
					adj->flags & EXT_SUBTLV_LINK_SRV6_ENDX_SID_PFLG
						? '1'
						: '0');
				if (adj->subsubtlvs)
					isis_format_subsubtlvs(adj->subsubtlvs,
							       buf, NULL,
							       indent + 4);
			}
	}
	/* SRv6 LAN End.X SID as per RFC9352 section #8.2 */
	if (IS_SUBTLV(exts, EXT_SRV6_LAN_ENDX_SID)) {
		struct isis_srv6_lan_endx_sid_subtlv *lan;
		if (json) {
			struct json_object *arr_adj_json, *flags_json;
			arr_adj_json = json_object_new_array();
			json_object_object_add(json, "srv6-lan-endx-sid",
					       arr_adj_json);
			for (lan = (struct isis_srv6_lan_endx_sid_subtlv *)
					   exts->srv6_lan_endx_sid.head;
			     lan; lan = lan->next) {
				snprintfrr(cnt_buf, sizeof(cnt_buf), "%pI6",
					   &lan->sid);
				flags_json = json_object_new_object();
				json_object_string_addf(flags_json, "sid",
							"%pI6", &lan->sid);
				json_object_int_add(flags_json, "weight",
						    lan->weight);
				json_object_string_add(
					flags_json, "algorithm",
					sr_algorithm_string(lan->algorithm));
				json_object_int_add(flags_json, "weight",
						    lan->weight);
				json_object_string_add(
					flags_json, "behavior",
					seg6local_action2str(lan->behavior));
				json_object_string_add(
					flags_json, "flag-b",
					lan->flags & EXT_SUBTLV_LINK_SRV6_ENDX_SID_BFLG
						? "1"
						: "0");
				json_object_string_add(
					flags_json, "flag-s",
					lan->flags & EXT_SUBTLV_LINK_SRV6_ENDX_SID_SFLG
						? "1"
						: "0");
				json_object_string_add(
					flags_json, "flag-p",
					lan->flags & EXT_SUBTLV_LINK_SRV6_ENDX_SID_PFLG
						? "1"
						: "0");
				json_object_string_addf(flags_json,
							"neighbor-id", "%pSY",
							lan->neighbor_id);
				json_object_array_add(arr_adj_json, flags_json);
				if (lan->subsubtlvs)
					isis_format_subsubtlvs(lan->subsubtlvs,
							       NULL, json,
							       indent + 4);
			}
		} else
			for (lan = (struct isis_srv6_lan_endx_sid_subtlv *)
					   exts->srv6_lan_endx_sid.head;
			     lan; lan = lan->next) {
				sbuf_push(
					buf, indent,
					"SRv6 Lan End.X SID: %pI6, Algorithm: %s, Weight: %hhu, Endpoint Behavior: %s, Flags: B:%c, S:%c, P:%c "
					"Neighbor-ID: %pSY\n",
					&lan->sid,
					sr_algorithm_string(lan->algorithm),
					lan->weight,
					seg6local_action2str(lan->behavior),
					lan->flags & EXT_SUBTLV_LINK_SRV6_ENDX_SID_BFLG
						? '1'
						: '0',
					lan->flags & EXT_SUBTLV_LINK_SRV6_ENDX_SID_SFLG
						? '1'
						: '0',
					lan->flags & EXT_SUBTLV_LINK_SRV6_ENDX_SID_PFLG
						? '1'
						: '0',
					lan->neighbor_id);
				if (lan->subsubtlvs)
					isis_format_subsubtlvs(lan->subsubtlvs,
							       buf, NULL,
							       indent + 4);
			}
	}
	for (ALL_LIST_ELEMENTS_RO(exts->aslas, node, asla))
		format_item_asla_subtlvs(asla, buf, indent);
}

static void free_item_ext_subtlvs(struct  isis_ext_subtlvs *exts)
{
	isis_del_ext_subtlvs(exts);
}

static int pack_item_ext_subtlv_asla(struct isis_asla_subtlvs *asla,
				     struct stream *s, size_t *min_len)
{
	size_t subtlv_len;
	size_t subtlv_len_pos;

	/* Sub TLV header */
	stream_putc(s, ISIS_SUBTLV_ASLA);

	subtlv_len_pos = stream_get_endp(s);
	stream_putc(s, 0); /* length will be filled later */

	/* SABM Flag/Length */
	if (asla->legacy)
		stream_putc(s, ASLA_LEGACY_FLAG | asla->standard_apps_length);
	else
		stream_putc(s, asla->standard_apps_length);
	stream_putc(s, asla->user_def_apps_length); /* UDABM Flag/Length */
	stream_putc(s, asla->standard_apps);
	stream_putc(s, asla->user_def_apps);

	/* Administrative Group */
	if (IS_SUBTLV(asla, EXT_ADM_GRP)) {
		stream_putc(s, ISIS_SUBTLV_ADMIN_GRP);
		stream_putc(s, ISIS_SUBTLV_DEF_SIZE);
		stream_putl(s, asla->admin_group);
	}

	/* Extended Administrative Group */
	if (IS_SUBTLV(asla, EXT_EXTEND_ADM_GRP) &&
	    admin_group_nb_words(&asla->ext_admin_group) != 0) {
		size_t ag_length;
		size_t ag_length_pos;
		struct admin_group *ag;

		stream_putc(s, ISIS_SUBTLV_EXT_ADMIN_GRP);
		ag_length_pos = stream_get_endp(s);
		stream_putc(s, 0); /* length will be filled later*/

		ag = &asla->ext_admin_group;
		for (size_t i = 0; i < admin_group_nb_words(ag); i++)
			stream_putl(s, ag->bitmap.data[i]);

		ag_length = stream_get_endp(s) - ag_length_pos - 1;
		stream_putc_at(s, ag_length_pos, ag_length);
	}

	if (IS_SUBTLV(asla, EXT_MAX_BW)) {
		stream_putc(s, ISIS_SUBTLV_MAX_BW);
		stream_putc(s, ISIS_SUBTLV_DEF_SIZE);
		stream_putf(s, asla->max_bw);
	}
	if (IS_SUBTLV(asla, EXT_MAX_RSV_BW)) {
		stream_putc(s, ISIS_SUBTLV_MAX_RSV_BW);
		stream_putc(s, ISIS_SUBTLV_DEF_SIZE);
		stream_putf(s, asla->max_rsv_bw);
	}
	if (IS_SUBTLV(asla, EXT_UNRSV_BW)) {
		stream_putc(s, ISIS_SUBTLV_UNRSV_BW);
		stream_putc(s, ISIS_SUBTLV_UNRSV_BW_SIZE);
		for (int j = 0; j < MAX_CLASS_TYPE; j++)
			stream_putf(s, asla->unrsv_bw[j]);
	}
	if (IS_SUBTLV(asla, EXT_TE_METRIC)) {
		stream_putc(s, ISIS_SUBTLV_TE_METRIC);
		stream_putc(s, ISIS_SUBTLV_TE_METRIC_SIZE);
		stream_put3(s, asla->te_metric);
	}
	if (IS_SUBTLV(asla, EXT_DELAY)) {
		stream_putc(s, ISIS_SUBTLV_AV_DELAY);
		stream_putc(s, ISIS_SUBTLV_DEF_SIZE);
		stream_putl(s, asla->delay);
	}
	if (IS_SUBTLV(asla, EXT_MM_DELAY)) {
		stream_putc(s, ISIS_SUBTLV_MM_DELAY);
		stream_putc(s, ISIS_SUBTLV_MM_DELAY_SIZE);
		stream_putl(s, asla->min_delay);
		stream_putl(s, asla->max_delay);
	}
	if (IS_SUBTLV(asla, EXT_DELAY_VAR)) {
		stream_putc(s, ISIS_SUBTLV_DELAY_VAR);
		stream_putc(s, ISIS_SUBTLV_DEF_SIZE);
		stream_putl(s, asla->delay_var);
	}
	if (IS_SUBTLV(asla, EXT_PKT_LOSS)) {
		stream_putc(s, ISIS_SUBTLV_PKT_LOSS);
		stream_putc(s, ISIS_SUBTLV_DEF_SIZE);
		stream_putl(s, asla->pkt_loss);
	}
	if (IS_SUBTLV(asla, EXT_RES_BW)) {
		stream_putc(s, ISIS_SUBTLV_RES_BW);
		stream_putc(s, ISIS_SUBTLV_DEF_SIZE);
		stream_putf(s, asla->res_bw);
	}
	if (IS_SUBTLV(asla, EXT_AVA_BW)) {
		stream_putc(s, ISIS_SUBTLV_AVA_BW);
		stream_putc(s, ISIS_SUBTLV_DEF_SIZE);
		stream_putf(s, asla->ava_bw);
	}
	if (IS_SUBTLV(asla, EXT_USE_BW)) {
		stream_putc(s, ISIS_SUBTLV_USE_BW);
		stream_putc(s, ISIS_SUBTLV_DEF_SIZE);
		stream_putf(s, asla->use_bw);
	}

	subtlv_len = stream_get_endp(s) - subtlv_len_pos - 1;
	stream_putc_at(s, subtlv_len_pos, subtlv_len);

	return 0;
}

static int pack_item_ext_subtlvs(struct isis_ext_subtlvs *exts,
				 struct stream *s, size_t *min_len)
{
	struct isis_asla_subtlvs *asla;
	struct listnode *node;
	uint8_t size;
	int ret;

	if (STREAM_WRITEABLE(s) < ISIS_SUBTLV_MAX_SIZE) {
		*min_len = ISIS_SUBTLV_MAX_SIZE;
		return 1;
	}

	if (IS_SUBTLV(exts, EXT_ADM_GRP)) {
		stream_putc(s, ISIS_SUBTLV_ADMIN_GRP);
		stream_putc(s, ISIS_SUBTLV_DEF_SIZE);
		stream_putl(s, exts->adm_group);
	}
	if (IS_SUBTLV(exts, EXT_EXTEND_ADM_GRP) &&
	    admin_group_nb_words(&exts->ext_admin_group) != 0) {
		/* Extended Administrative Group */
		size_t ag_length;
		size_t ag_length_pos;
		struct admin_group *ag;

		stream_putc(s, ISIS_SUBTLV_EXT_ADMIN_GRP);
		ag_length_pos = stream_get_endp(s);
		stream_putc(s, 0); /* length will be filled later*/

		ag = &exts->ext_admin_group;
		for (size_t i = 0; i < admin_group_nb_words(ag); i++)
			stream_putl(s, ag->bitmap.data[i]);

		ag_length = stream_get_endp(s) - ag_length_pos - 1;
		stream_putc_at(s, ag_length_pos, ag_length);
	}
	if (IS_SUBTLV(exts, EXT_LLRI)) {
		stream_putc(s, ISIS_SUBTLV_LLRI);
		stream_putc(s, ISIS_SUBTLV_LLRI_SIZE);
		stream_putl(s, exts->local_llri);
		stream_putl(s, exts->remote_llri);
	}
	if (IS_SUBTLV(exts, EXT_LOCAL_ADDR)) {
		stream_putc(s, ISIS_SUBTLV_LOCAL_IPADDR);
		stream_putc(s, ISIS_SUBTLV_DEF_SIZE);
		stream_put(s, &exts->local_addr.s_addr, 4);
	}
	if (IS_SUBTLV(exts, EXT_NEIGH_ADDR)) {
		stream_putc(s, ISIS_SUBTLV_RMT_IPADDR);
		stream_putc(s, ISIS_SUBTLV_DEF_SIZE);
		stream_put(s, &exts->neigh_addr.s_addr, 4);
	}
	if (IS_SUBTLV(exts, EXT_LOCAL_ADDR6)) {
		stream_putc(s, ISIS_SUBTLV_LOCAL_IPADDR6);
		stream_putc(s, ISIS_SUBTLV_IPV6_ADDR_SIZE);
		stream_put(s, &exts->local_addr6, 16);
	}
	if (IS_SUBTLV(exts, EXT_NEIGH_ADDR6)) {
		stream_putc(s, ISIS_SUBTLV_RMT_IPADDR6);
		stream_putc(s, ISIS_SUBTLV_IPV6_ADDR_SIZE);
		stream_put(s, &exts->neigh_addr6, 16);
	}
	if (IS_SUBTLV(exts, EXT_MAX_BW)) {
		stream_putc(s, ISIS_SUBTLV_MAX_BW);
		stream_putc(s, ISIS_SUBTLV_DEF_SIZE);
		stream_putf(s, exts->max_bw);
	}
	if (IS_SUBTLV(exts, EXT_MAX_RSV_BW)) {
		stream_putc(s, ISIS_SUBTLV_MAX_RSV_BW);
		stream_putc(s, ISIS_SUBTLV_DEF_SIZE);
		stream_putf(s, exts->max_rsv_bw);
	}
	if (IS_SUBTLV(exts, EXT_UNRSV_BW)) {
		stream_putc(s, ISIS_SUBTLV_UNRSV_BW);
		stream_putc(s, ISIS_SUBTLV_UNRSV_BW_SIZE);
		for (int j = 0; j < MAX_CLASS_TYPE; j++)
			stream_putf(s, exts->unrsv_bw[j]);
	}
	if (IS_SUBTLV(exts, EXT_TE_METRIC)) {
		stream_putc(s, ISIS_SUBTLV_TE_METRIC);
		stream_putc(s, ISIS_SUBTLV_TE_METRIC_SIZE);
		stream_put3(s, exts->te_metric);
	}
	if (IS_SUBTLV(exts, EXT_RMT_AS)) {
		stream_putc(s, ISIS_SUBTLV_RAS);
		stream_putc(s, ISIS_SUBTLV_DEF_SIZE);
		stream_putl(s, exts->remote_as);
	}
	if (IS_SUBTLV(exts, EXT_RMT_IP)) {
		stream_putc(s, ISIS_SUBTLV_RIP);
		stream_putc(s, ISIS_SUBTLV_DEF_SIZE);
		stream_put(s, &exts->remote_ip.s_addr, 4);
	}
	if (IS_SUBTLV(exts, EXT_DELAY)) {
		stream_putc(s, ISIS_SUBTLV_AV_DELAY);
		stream_putc(s, ISIS_SUBTLV_DEF_SIZE);
		stream_putl(s, exts->delay);
	}
	if (IS_SUBTLV(exts, EXT_MM_DELAY)) {
		stream_putc(s, ISIS_SUBTLV_MM_DELAY);
		stream_putc(s, ISIS_SUBTLV_MM_DELAY_SIZE);
		stream_putl(s, exts->min_delay);
		stream_putl(s, exts->max_delay);
	}
	if (IS_SUBTLV(exts, EXT_DELAY_VAR)) {
		stream_putc(s, ISIS_SUBTLV_DELAY_VAR);
		stream_putc(s, ISIS_SUBTLV_DEF_SIZE);
		stream_putl(s, exts->delay_var);
	}
	if (IS_SUBTLV(exts, EXT_PKT_LOSS)) {
		stream_putc(s, ISIS_SUBTLV_PKT_LOSS);
		stream_putc(s, ISIS_SUBTLV_DEF_SIZE);
		stream_putl(s, exts->pkt_loss);
	}
	if (IS_SUBTLV(exts, EXT_RES_BW)) {
		stream_putc(s, ISIS_SUBTLV_RES_BW);
		stream_putc(s, ISIS_SUBTLV_DEF_SIZE);
		stream_putf(s, exts->res_bw);
	}
	if (IS_SUBTLV(exts, EXT_AVA_BW)) {
		stream_putc(s, ISIS_SUBTLV_AVA_BW);
		stream_putc(s, ISIS_SUBTLV_DEF_SIZE);
		stream_putf(s, exts->ava_bw);
	}
	if (IS_SUBTLV(exts, EXT_USE_BW)) {
		stream_putc(s, ISIS_SUBTLV_USE_BW);
		stream_putc(s, ISIS_SUBTLV_DEF_SIZE);
		stream_putf(s, exts->use_bw);
	}
	/* Segment Routing Adjacency as per RFC8667 section #2.2.1 */
	if (IS_SUBTLV(exts, EXT_ADJ_SID)) {
		struct isis_adj_sid *adj;

		for (adj = (struct isis_adj_sid *)exts->adj_sid.head; adj;
		     adj = adj->next) {
			stream_putc(s, ISIS_SUBTLV_ADJ_SID);
			size = ISIS_SUBTLV_ADJ_SID_SIZE;
			if (!(adj->flags & EXT_SUBTLV_LINK_ADJ_SID_VFLG))
				size++;
			stream_putc(s, size);
			stream_putc(s, adj->flags);
			stream_putc(s, adj->weight);
			if (adj->flags & EXT_SUBTLV_LINK_ADJ_SID_VFLG)
				stream_put3(s, adj->sid);
			else
				stream_putl(s, adj->sid);

		}
	}
	/* Segment Routing LAN-Adjacency as per RFC8667 section #2.2.2 */
	if (IS_SUBTLV(exts, EXT_LAN_ADJ_SID)) {
		struct isis_lan_adj_sid *lan;

		for (lan = (struct isis_lan_adj_sid *)exts->lan_sid.head; lan;
		     lan = lan->next) {
			stream_putc(s, ISIS_SUBTLV_LAN_ADJ_SID);
			size = ISIS_SUBTLV_LAN_ADJ_SID_SIZE;
			if (!(lan->flags & EXT_SUBTLV_LINK_ADJ_SID_VFLG))
				size++;
			stream_putc(s, size);
			stream_putc(s, lan->flags);
			stream_putc(s, lan->weight);
			stream_put(s, lan->neighbor_id, 6);
			if (lan->flags & EXT_SUBTLV_LINK_ADJ_SID_VFLG)
				stream_put3(s, lan->sid);
			else
				stream_putl(s, lan->sid);
		}
	}
	/* SRv6 End.X SID as per RFC9352 section #8.1 */
	if (IS_SUBTLV(exts, EXT_SRV6_ENDX_SID)) {
		struct isis_srv6_endx_sid_subtlv *adj;
		size_t subtlv_len;
		size_t subtlv_len_pos;

		for (adj = (struct isis_srv6_endx_sid_subtlv *)
				   exts->srv6_endx_sid.head;
		     adj; adj = adj->next) {
			stream_putc(s, ISIS_SUBTLV_SRV6_ENDX_SID);

			subtlv_len_pos = stream_get_endp(s);
			stream_putc(s, 0); /* length will be filled later */

			stream_putc(s, adj->flags);
			stream_putc(s, adj->algorithm);
			stream_putc(s, adj->weight);
			stream_putw(s, adj->behavior);
			stream_put(s, &adj->sid, IPV6_MAX_BYTELEN);

			if (adj->subsubtlvs) {
				/* Pack Sub-Sub-TLVs */
				if (isis_pack_subsubtlvs(adj->subsubtlvs, s))
					return 1;
			} else {
				/* No Sub-Sub-TLVs */
				if (STREAM_WRITEABLE(s) < 1) {
					*min_len =
						ISIS_SUBTLV_SRV6_ENDX_SID_SIZE;
					return 1;
				}

				/* Put 0 as Sub-Sub-TLV length, because we have
				 * no Sub-Sub-TLVs  */
				stream_putc(s, 0);
			}

			subtlv_len = stream_get_endp(s) - subtlv_len_pos - 1;
			stream_putc_at(s, subtlv_len_pos, subtlv_len);
		}
	}
	/* SRv6 LAN End.X SID as per RFC9352 section #8.2 */
	if (IS_SUBTLV(exts, EXT_SRV6_LAN_ENDX_SID)) {
		struct isis_srv6_lan_endx_sid_subtlv *lan;
		size_t subtlv_len;
		size_t subtlv_len_pos;

		for (lan = (struct isis_srv6_lan_endx_sid_subtlv *)
				   exts->srv6_lan_endx_sid.head;
		     lan; lan = lan->next) {
			stream_putc(s, ISIS_SUBTLV_SRV6_LAN_ENDX_SID);

			subtlv_len_pos = stream_get_endp(s);
			stream_putc(s, 0); /* length will be filled later */

			stream_put(s, lan->neighbor_id, 6);
			stream_putc(s, lan->flags);
			stream_putc(s, lan->algorithm);
			stream_putc(s, lan->weight);
			stream_putw(s, lan->behavior);
			stream_put(s, &lan->sid, IPV6_MAX_BYTELEN);

			if (lan->subsubtlvs) {
				/* Pack Sub-Sub-TLVs */
				if (isis_pack_subsubtlvs(lan->subsubtlvs, s))
					return 1;
			} else {
				/* No Sub-Sub-TLVs */
				if (STREAM_WRITEABLE(s) < 1) {
					*min_len =
						ISIS_SUBTLV_SRV6_LAN_ENDX_SID_SIZE;
					return 1;
				}

				/* Put 0 as Sub-Sub-TLV length, because we have
				 * no Sub-Sub-TLVs  */
				stream_putc(s, 0);
			}

			subtlv_len = stream_get_endp(s) - subtlv_len_pos - 1;
			stream_putc_at(s, subtlv_len_pos, subtlv_len);
		}
	}

	for (ALL_LIST_ELEMENTS_RO(exts->aslas, node, asla)) {
		ret = pack_item_ext_subtlv_asla(asla, s, min_len);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int unpack_item_ext_subtlv_asla(uint16_t mtid, uint8_t subtlv_len,
				       struct stream *s, struct sbuf *log,
				       int indent,
				       struct isis_ext_subtlvs *exts)
{
	/* Standard App Identifier Bit Flags/Length */
	uint8_t sabm_flag_len;
	/* User-defined App Identifier Bit Flags/Length */
	uint8_t uabm_flag_len;
	uint8_t sabm[ASLA_APP_IDENTIFIER_BIT_LENGTH] = {0};
	uint8_t uabm[ASLA_APP_IDENTIFIER_BIT_LENGTH] = {0};
	uint8_t readable = subtlv_len;
	uint8_t subsubtlv_type;
	uint8_t subsubtlv_len;
	size_t nb_groups;
	struct isis_asla_subtlvs *asla;

	if (subtlv_len < ISIS_SUBSUBTLV_HDR_SIZE) {
		TLV_SIZE_MISMATCH(log, indent, "ASLA");
		return -1;
	}


	asla = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*asla));

	admin_group_init(&asla->ext_admin_group);


	sabm_flag_len = stream_getc(s);
	uabm_flag_len = stream_getc(s);
	asla->legacy = CHECK_FLAG(sabm_flag_len, ASLA_LEGACY_FLAG);
	asla->standard_apps_length = ASLA_APPS_LENGTH_MASK & sabm_flag_len;
	asla->user_def_apps_length = ASLA_APPS_LENGTH_MASK & uabm_flag_len;

	readable -= ISIS_SUBSUBTLV_HDR_SIZE;
	if (readable <
	    asla->standard_apps_length + asla->user_def_apps_length) {
		TLV_SIZE_MISMATCH(log, indent, "ASLA");
		return -1;
	}

	for (int i = 0; i < asla->standard_apps_length; i++)
		sabm[i] = stream_getc(s);
	for (int i = 0; i < asla->user_def_apps_length; i++)
		uabm[i] = stream_getc(s);

	readable -= (asla->standard_apps_length + asla->user_def_apps_length);

	asla->standard_apps = sabm[0];
	asla->user_def_apps = uabm[0];

	while (readable > 0) {
		if (readable < ISIS_SUBSUBTLV_HDR_SIZE) {
			TLV_SIZE_MISMATCH(log, indent, "ASLA Sub TLV");
			return -1;
		}

		subsubtlv_type = stream_getc(s);
		subsubtlv_len = stream_getc(s);
		readable -= ISIS_SUBSUBTLV_HDR_SIZE;


		switch (subsubtlv_type) {
		case ISIS_SUBTLV_ADMIN_GRP:
			if (subsubtlv_len != ISIS_SUBTLV_DEF_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "ASLA Adm Group");
				stream_forward_getp(s, subsubtlv_len);
			} else {
				asla->admin_group = stream_getl(s);
				SET_SUBTLV(asla, EXT_ADM_GRP);
			}
			break;

		case ISIS_SUBTLV_EXT_ADMIN_GRP:
			nb_groups = subsubtlv_len / sizeof(uint32_t);
			for (size_t i = 0; i < nb_groups; i++) {
				uint32_t val = stream_getl(s);

				admin_group_bulk_set(&asla->ext_admin_group,
						     val, i);
			}
			SET_SUBTLV(asla, EXT_EXTEND_ADM_GRP);
			break;
		case ISIS_SUBTLV_MAX_BW:
			if (subsubtlv_len != ISIS_SUBTLV_DEF_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "Maximum Bandwidth");
				stream_forward_getp(s, subsubtlv_len);
			} else {
				asla->max_bw = stream_getf(s);
				SET_SUBTLV(asla, EXT_MAX_BW);
			}
			break;
		case ISIS_SUBTLV_MAX_RSV_BW:
			if (subsubtlv_len != ISIS_SUBTLV_DEF_SIZE) {
				TLV_SIZE_MISMATCH(
					log, indent,
					"Maximum Reservable Bandwidth");
				stream_forward_getp(s, subsubtlv_len);
			} else {
				asla->max_rsv_bw = stream_getf(s);
				SET_SUBTLV(asla, EXT_MAX_RSV_BW);
			}
			break;
		case ISIS_SUBTLV_UNRSV_BW:
			if (subsubtlv_len != ISIS_SUBTLV_UNRSV_BW_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "Unreserved Bandwidth");
				stream_forward_getp(s, subsubtlv_len);
			} else {
				for (int i = 0; i < MAX_CLASS_TYPE; i++)
					asla->unrsv_bw[i] = stream_getf(s);
				SET_SUBTLV(asla, EXT_UNRSV_BW);
			}
			break;
		case ISIS_SUBTLV_TE_METRIC:
			if (subsubtlv_len != ISIS_SUBTLV_TE_METRIC_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "Traffic Engineering Metric");
				stream_forward_getp(s, subsubtlv_len);
			} else {
				asla->te_metric = stream_get3(s);
				SET_SUBTLV(asla, EXT_TE_METRIC);
			}
			break;
		/* Extended Metrics as defined in RFC 7810 */
		case ISIS_SUBTLV_AV_DELAY:
			if (subsubtlv_len != ISIS_SUBTLV_DEF_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "Average Link Delay");
				stream_forward_getp(s, subsubtlv_len);
			} else {
				asla->delay = stream_getl(s);
				SET_SUBTLV(asla, EXT_DELAY);
			}
			break;
		case ISIS_SUBTLV_MM_DELAY:
			if (subsubtlv_len != ISIS_SUBTLV_MM_DELAY_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "Min/Max Link Delay");
				stream_forward_getp(s, subsubtlv_len);
			} else {
				asla->min_delay = stream_getl(s);
				asla->max_delay = stream_getl(s);
				SET_SUBTLV(asla, EXT_MM_DELAY);
			}
			break;
		case ISIS_SUBTLV_DELAY_VAR:
			if (subsubtlv_len != ISIS_SUBTLV_DEF_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "Delay Variation");
				stream_forward_getp(s, subsubtlv_len);
			} else {
				asla->delay_var = stream_getl(s);
				SET_SUBTLV(asla, EXT_DELAY_VAR);
			}
			break;
		case ISIS_SUBTLV_PKT_LOSS:
			if (subsubtlv_len != ISIS_SUBTLV_DEF_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "Link Packet Loss");
				stream_forward_getp(s, subsubtlv_len);
			} else {
				asla->pkt_loss = stream_getl(s);
				SET_SUBTLV(asla, EXT_PKT_LOSS);
			}
			break;
		case ISIS_SUBTLV_RES_BW:
			if (subsubtlv_len != ISIS_SUBTLV_DEF_SIZE) {
				TLV_SIZE_MISMATCH(
					log, indent,
					"Unidirectional Residual Bandwidth");
				stream_forward_getp(s, subsubtlv_len);
			} else {
				asla->res_bw = stream_getf(s);
				SET_SUBTLV(asla, EXT_RES_BW);
			}
			break;
		case ISIS_SUBTLV_AVA_BW:
			if (subsubtlv_len != ISIS_SUBTLV_DEF_SIZE) {
				TLV_SIZE_MISMATCH(
					log, indent,
					"Unidirectional Available Bandwidth");
				stream_forward_getp(s, subsubtlv_len);
			} else {
				asla->ava_bw = stream_getf(s);
				SET_SUBTLV(asla, EXT_AVA_BW);
			}
			break;
		case ISIS_SUBTLV_USE_BW:
			if (subsubtlv_len != ISIS_SUBTLV_DEF_SIZE) {
				TLV_SIZE_MISMATCH(
					log, indent,
					"Unidirectional Utilized Bandwidth");
				stream_forward_getp(s, subsubtlv_len);
			} else {
				asla->use_bw = stream_getf(s);
				SET_SUBTLV(asla, EXT_USE_BW);
			}
			break;
		default:
			zlog_debug("unknown (t,l)=(%u,%u)", subsubtlv_type,
				   subsubtlv_len);
			stream_forward_getp(s, subsubtlv_len);
			break;
		}
		readable -= subsubtlv_len;
	}

	listnode_add(exts->aslas, asla);

	return 0;
}

static int unpack_item_ext_subtlvs(uint16_t mtid, uint8_t len, struct stream *s,
				   struct sbuf *log, void *dest, int indent)
{
	uint8_t sum = 0;
	uint8_t subtlv_type;
	uint8_t subtlv_len;
	uint8_t subsubtlv_len;
	size_t nb_groups;
	uint32_t val;

	struct isis_extended_reach *rv = dest;
	struct isis_ext_subtlvs *exts = isis_alloc_ext_subtlvs();

	rv->subtlvs = exts;

	/*
	 * Parse subTLVs until reach subTLV length
	 * Check that it remains at least 2 bytes: subTLV Type & Length
	 */
	while (len > sum + 2) {
		/* Read SubTLV Type and Length */
		subtlv_type = stream_getc(s);
		subtlv_len = stream_getc(s);
		if (subtlv_len > len - sum - ISIS_SUBTLV_HDR_SIZE) {
			sbuf_push(
				log, indent,
				"TLV %hhu: Available data %u is less than TLV size %u !\n",
				subtlv_type, len - sum - ISIS_SUBTLV_HDR_SIZE,
				subtlv_len);
			return 1;
		}

		switch (subtlv_type) {
		/* Standard Metric as defined in RFC5305 */
		case ISIS_SUBTLV_ADMIN_GRP:
			if (subtlv_len != ISIS_SUBTLV_DEF_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "Administrative Group");
				stream_forward_getp(s, subtlv_len);
			} else {
				exts->adm_group = stream_getl(s);
				SET_SUBTLV(exts, EXT_ADM_GRP);
			}
			break;
		case ISIS_SUBTLV_EXT_ADMIN_GRP:
			nb_groups = subtlv_len / sizeof(uint32_t);
			for (size_t i = 0; i < nb_groups; i++) {
				val = stream_getl(s);
				admin_group_bulk_set(&exts->ext_admin_group,
						     val, i);
			}
			SET_SUBTLV(exts, EXT_EXTEND_ADM_GRP);
			break;
		case ISIS_SUBTLV_LLRI:
			if (subtlv_len != ISIS_SUBTLV_LLRI_SIZE) {
				TLV_SIZE_MISMATCH(log, indent, "Link ID");
				stream_forward_getp(s, subtlv_len);
			} else {
				exts->local_llri = stream_getl(s);
				exts->remote_llri = stream_getl(s);
				SET_SUBTLV(exts, EXT_LLRI);
			}
			break;
		case ISIS_SUBTLV_LOCAL_IPADDR:
			if (subtlv_len != ISIS_SUBTLV_DEF_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "Local IP address");
				stream_forward_getp(s, subtlv_len);
			} else {
				stream_get(&exts->local_addr.s_addr, s, 4);
				SET_SUBTLV(exts, EXT_LOCAL_ADDR);
			}
			break;
		case ISIS_SUBTLV_RMT_IPADDR:
			if (subtlv_len != ISIS_SUBTLV_DEF_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "Remote IP address");
				stream_forward_getp(s, subtlv_len);
			} else {
				stream_get(&exts->neigh_addr.s_addr, s, 4);
				SET_SUBTLV(exts, EXT_NEIGH_ADDR);
			}
			break;
		case ISIS_SUBTLV_LOCAL_IPADDR6:
			if (subtlv_len != ISIS_SUBTLV_IPV6_ADDR_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "Local IPv6 address");
				stream_forward_getp(s, subtlv_len);
			} else {
				stream_get(&exts->local_addr6, s, 16);
				SET_SUBTLV(exts, EXT_LOCAL_ADDR6);
			}
			break;
		case ISIS_SUBTLV_RMT_IPADDR6:
			if (subtlv_len != ISIS_SUBTLV_IPV6_ADDR_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "Remote IPv6 address");
				stream_forward_getp(s, subtlv_len);
			} else {
				stream_get(&exts->neigh_addr6, s, 16);
				SET_SUBTLV(exts, EXT_NEIGH_ADDR6);
			}
			break;
		case ISIS_SUBTLV_MAX_BW:
			if (subtlv_len != ISIS_SUBTLV_DEF_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "Maximum Bandwidth");
				stream_forward_getp(s, subtlv_len);
			} else {
				exts->max_bw = stream_getf(s);
				SET_SUBTLV(exts, EXT_MAX_BW);
			}
			break;
		case ISIS_SUBTLV_MAX_RSV_BW:
			if (subtlv_len != ISIS_SUBTLV_DEF_SIZE) {
				TLV_SIZE_MISMATCH(
					log, indent,
					"Maximum Reservable Bandwidth");
				stream_forward_getp(s, subtlv_len);
			} else {
				exts->max_rsv_bw = stream_getf(s);
				SET_SUBTLV(exts, EXT_MAX_RSV_BW);
			}
			break;
		case ISIS_SUBTLV_UNRSV_BW:
			if (subtlv_len != ISIS_SUBTLV_UNRSV_BW_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "Unreserved Bandwidth");
				stream_forward_getp(s, subtlv_len);
			} else {
				for (int i = 0; i < MAX_CLASS_TYPE; i++)
					exts->unrsv_bw[i] = stream_getf(s);
				SET_SUBTLV(exts, EXT_UNRSV_BW);
			}
			break;
		case ISIS_SUBTLV_TE_METRIC:
			if (subtlv_len != ISIS_SUBTLV_TE_METRIC_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "Traffic Engineering Metric");
				stream_forward_getp(s, subtlv_len);
			} else {
				exts->te_metric = stream_get3(s);
				SET_SUBTLV(exts, EXT_TE_METRIC);
			}
			break;
		case ISIS_SUBTLV_RAS:
			if (subtlv_len != ISIS_SUBTLV_DEF_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "Remote AS number");
				stream_forward_getp(s, subtlv_len);
			} else {
				exts->remote_as = stream_getl(s);
				SET_SUBTLV(exts, EXT_RMT_AS);
			}
			break;
		case ISIS_SUBTLV_RIP:
			if (subtlv_len != ISIS_SUBTLV_DEF_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "Remote ASBR IP Address");
				stream_forward_getp(s, subtlv_len);
			} else {
				stream_get(&exts->remote_ip.s_addr, s, 4);
				SET_SUBTLV(exts, EXT_RMT_IP);
			}
			break;
		/* Extended Metrics as defined in RFC 7810 */
		case ISIS_SUBTLV_AV_DELAY:
			if (subtlv_len != ISIS_SUBTLV_DEF_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "Average Link Delay");
				stream_forward_getp(s, subtlv_len);
			} else {
				exts->delay = stream_getl(s);
				SET_SUBTLV(exts, EXT_DELAY);
			}
			break;
		case ISIS_SUBTLV_MM_DELAY:
			if (subtlv_len != ISIS_SUBTLV_MM_DELAY_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "Min/Max Link Delay");
				stream_forward_getp(s, subtlv_len);
			} else {
				exts->min_delay = stream_getl(s);
				exts->max_delay = stream_getl(s);
				SET_SUBTLV(exts, EXT_MM_DELAY);
			}
			break;
		case ISIS_SUBTLV_DELAY_VAR:
			if (subtlv_len != ISIS_SUBTLV_DEF_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "Delay Variation");
				stream_forward_getp(s, subtlv_len);
			} else {
				exts->delay_var = stream_getl(s);
				SET_SUBTLV(exts, EXT_DELAY_VAR);
			}
			break;
		case ISIS_SUBTLV_PKT_LOSS:
			if (subtlv_len != ISIS_SUBTLV_DEF_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "Link Packet Loss");
				stream_forward_getp(s, subtlv_len);
			} else {
				exts->pkt_loss = stream_getl(s);
				SET_SUBTLV(exts, EXT_PKT_LOSS);
			}
			break;
		case ISIS_SUBTLV_RES_BW:
			if (subtlv_len != ISIS_SUBTLV_DEF_SIZE) {
				TLV_SIZE_MISMATCH(
					log, indent,
					"Unidirectional Residual Bandwidth");
				stream_forward_getp(s, subtlv_len);
			} else {
				exts->res_bw = stream_getf(s);
				SET_SUBTLV(exts, EXT_RES_BW);
			}
			break;
		case ISIS_SUBTLV_AVA_BW:
			if (subtlv_len != ISIS_SUBTLV_DEF_SIZE) {
				TLV_SIZE_MISMATCH(
					log, indent,
					"Unidirectional Available Bandwidth");
				stream_forward_getp(s, subtlv_len);
			} else {
				exts->ava_bw = stream_getf(s);
				SET_SUBTLV(exts, EXT_AVA_BW);
			}
			break;
		case ISIS_SUBTLV_USE_BW:
			if (subtlv_len != ISIS_SUBTLV_DEF_SIZE) {
				TLV_SIZE_MISMATCH(
					log, indent,
					"Unidirectional Utilized Bandwidth");
				stream_forward_getp(s, subtlv_len);
			} else {
				exts->use_bw = stream_getf(s);
				SET_SUBTLV(exts, EXT_USE_BW);
			}
			break;
		/* Segment Routing Adjacency as per RFC8667 section #2.2.1 */
		case ISIS_SUBTLV_ADJ_SID:
			if (subtlv_len != ISIS_SUBTLV_ADJ_SID_SIZE
			    && subtlv_len != ISIS_SUBTLV_ADJ_SID_SIZE + 1) {
				TLV_SIZE_MISMATCH(log, indent, "Adjacency SID");
				stream_forward_getp(s, subtlv_len);
			} else {
				struct isis_adj_sid *adj;

				adj = XCALLOC(MTYPE_ISIS_SUBTLV,
					      sizeof(struct isis_adj_sid));
				adj->flags = stream_getc(s);
				adj->weight = stream_getc(s);
				if (adj->flags & EXT_SUBTLV_LINK_ADJ_SID_VFLG
				    && subtlv_len != ISIS_SUBTLV_ADJ_SID_SIZE) {
					TLV_SIZE_MISMATCH(log, indent,
							  "Adjacency SID");
					stream_forward_getp(s, subtlv_len - 2);
					XFREE(MTYPE_ISIS_SUBTLV, adj);
					break;
				}

				if (!(adj->flags & EXT_SUBTLV_LINK_ADJ_SID_VFLG)
				    && subtlv_len
					       != ISIS_SUBTLV_ADJ_SID_SIZE
							  + 1) {
					TLV_SIZE_MISMATCH(log, indent,
							  "Adjacency SID");
					stream_forward_getp(s, subtlv_len - 2);
					XFREE(MTYPE_ISIS_SUBTLV, adj);
					break;
				}

				if (adj->flags & EXT_SUBTLV_LINK_ADJ_SID_VFLG) {
					adj->sid = stream_get3(s);
					adj->sid &= MPLS_LABEL_VALUE_MASK;
				} else {
					adj->sid = stream_getl(s);
				}
				if (mtid == ISIS_MT_IPV4_UNICAST)
					adj->family = AF_INET;
				if (mtid == ISIS_MT_IPV6_UNICAST)
					adj->family = AF_INET6;
				append_item(&exts->adj_sid,
					    (struct isis_item *)adj);
				SET_SUBTLV(exts, EXT_ADJ_SID);
			}
			break;
		/* Segment Routing LAN-Adjacency as per RFC8667 section 2.2.2 */
		case ISIS_SUBTLV_LAN_ADJ_SID:
			if (subtlv_len != ISIS_SUBTLV_LAN_ADJ_SID_SIZE
			    && subtlv_len != ISIS_SUBTLV_LAN_ADJ_SID_SIZE + 1) {
				TLV_SIZE_MISMATCH(log, indent,
						  "LAN-Adjacency SID");
				stream_forward_getp(s, subtlv_len);
			} else {
				struct isis_lan_adj_sid *lan;

				lan = XCALLOC(MTYPE_ISIS_SUBTLV,
					      sizeof(struct isis_lan_adj_sid));
				lan->flags = stream_getc(s);
				lan->weight = stream_getc(s);
				stream_get(&(lan->neighbor_id), s,
					   ISIS_SYS_ID_LEN);

				if (lan->flags & EXT_SUBTLV_LINK_ADJ_SID_VFLG
				    && subtlv_len
					       != ISIS_SUBTLV_LAN_ADJ_SID_SIZE) {
					TLV_SIZE_MISMATCH(log, indent,
							  "LAN-Adjacency SID");
					stream_forward_getp(
						s, subtlv_len - 2
							   - ISIS_SYS_ID_LEN);
					XFREE(MTYPE_ISIS_SUBTLV, lan);
					break;
				}

				if (!(lan->flags & EXT_SUBTLV_LINK_ADJ_SID_VFLG)
				    && subtlv_len
					       != ISIS_SUBTLV_LAN_ADJ_SID_SIZE
							  + 1) {
					TLV_SIZE_MISMATCH(log, indent,
							  "LAN-Adjacency SID");
					stream_forward_getp(
						s, subtlv_len - 2
							   - ISIS_SYS_ID_LEN);
					XFREE(MTYPE_ISIS_SUBTLV, lan);
					break;
				}

				if (lan->flags & EXT_SUBTLV_LINK_ADJ_SID_VFLG) {
					lan->sid = stream_get3(s);
					lan->sid &= MPLS_LABEL_VALUE_MASK;
				} else {
					lan->sid = stream_getl(s);
				}
				if (mtid == ISIS_MT_IPV4_UNICAST)
					lan->family = AF_INET;
				if (mtid == ISIS_MT_IPV6_UNICAST)
					lan->family = AF_INET6;
				append_item(&exts->lan_sid,
					    (struct isis_item *)lan);
				SET_SUBTLV(exts, EXT_LAN_ADJ_SID);
			}
			break;
		/* SRv6 End.X SID as per RFC9352 section #8.1 */
		case ISIS_SUBTLV_SRV6_ENDX_SID:
			if (subtlv_len < ISIS_SUBTLV_SRV6_ENDX_SID_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "SRv6 End.X SID");
				stream_forward_getp(s, subtlv_len);
			} else {
				struct isis_srv6_endx_sid_subtlv *adj;

				adj = XCALLOC(
					MTYPE_ISIS_SUBTLV,
					sizeof(struct
					       isis_srv6_endx_sid_subtlv));
				adj->flags = stream_getc(s);
				adj->algorithm = stream_getc(s);
				adj->weight = stream_getc(s);
				adj->behavior = stream_getw(s);
				stream_get(&adj->sid, s, IPV6_MAX_BYTELEN);
				subsubtlv_len = stream_getc(s);

				adj->subsubtlvs = isis_alloc_subsubtlvs(
					ISIS_CONTEXT_SUBSUBTLV_SRV6_ENDX_SID);

				bool unpacked_known_tlvs = false;
				if (unpack_tlvs(
					    ISIS_CONTEXT_SUBSUBTLV_SRV6_ENDX_SID,
					    subsubtlv_len, s, log,
					    adj->subsubtlvs, indent + 4,
					    &unpacked_known_tlvs)) {
					XFREE(MTYPE_ISIS_SUBTLV, adj);
					break;
				}
				if (!unpacked_known_tlvs) {
					isis_free_subsubtlvs(adj->subsubtlvs);
					adj->subsubtlvs = NULL;
				}

				append_item(&exts->srv6_endx_sid,
					    (struct isis_item *)adj);
				SET_SUBTLV(exts, EXT_SRV6_ENDX_SID);
			}
			break;
		/* SRv6 LAN End.X SID as per RFC9352 section #8.2 */
		case ISIS_SUBTLV_SRV6_LAN_ENDX_SID:
			if (subtlv_len < ISIS_SUBTLV_SRV6_LAN_ENDX_SID_SIZE) {
				TLV_SIZE_MISMATCH(log, indent,
						  "SRv6 LAN End.X SID");
				stream_forward_getp(s, subtlv_len);
			} else {
				struct isis_srv6_lan_endx_sid_subtlv *lan;

				lan = XCALLOC(
					MTYPE_ISIS_SUBTLV,
					sizeof(struct
					       isis_srv6_lan_endx_sid_subtlv));
				stream_get(&(lan->neighbor_id), s,
					   ISIS_SYS_ID_LEN);
				lan->flags = stream_getc(s);
				lan->algorithm = stream_getc(s);
				lan->weight = stream_getc(s);
				lan->behavior = stream_getw(s);
				stream_get(&lan->sid, s, IPV6_MAX_BYTELEN);
				subsubtlv_len = stream_getc(s);

				lan->subsubtlvs = isis_alloc_subsubtlvs(
					ISIS_CONTEXT_SUBSUBTLV_SRV6_ENDX_SID);

				bool unpacked_known_tlvs = false;
				if (unpack_tlvs(
					    ISIS_CONTEXT_SUBSUBTLV_SRV6_ENDX_SID,
					    subsubtlv_len, s, log,
					    lan->subsubtlvs, indent + 4,
					    &unpacked_known_tlvs)) {
					XFREE(MTYPE_ISIS_SUBTLV, lan);
					break;
				}
				if (!unpacked_known_tlvs) {
					isis_free_subsubtlvs(lan->subsubtlvs);
					lan->subsubtlvs = NULL;
				}

				append_item(&exts->srv6_lan_endx_sid,
					    (struct isis_item *)lan);
				SET_SUBTLV(exts, EXT_SRV6_LAN_ENDX_SID);
			}
			break;
		case ISIS_SUBTLV_ASLA:
			if (unpack_item_ext_subtlv_asla(mtid, subtlv_len, s,
							log, indent,
							exts) < 0) {
				sbuf_push(log, indent, "TLV parse error");
			}
			break;
		default:
			/* Skip unknown TLV */
			stream_forward_getp(s, subtlv_len);
			break;
		}
		sum += subtlv_len + ISIS_SUBTLV_HDR_SIZE;
	}

	return 0;
}

/* Functions for Sub-TLV 3 SR Prefix-SID as per RFC8667 section 2.1 */
static struct isis_item *copy_item_prefix_sid(struct isis_item *i)
{
	struct isis_prefix_sid *sid = (struct isis_prefix_sid *)i;
	struct isis_prefix_sid *rv = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*rv));

	rv->flags = sid->flags;
	rv->algorithm = sid->algorithm;
	rv->value = sid->value;
	return (struct isis_item *)rv;
}

static void format_item_prefix_sid(uint16_t mtid, struct isis_item *i,
				   struct sbuf *buf, struct json_object *json,
				   int indent)
{
	struct isis_prefix_sid *sid = (struct isis_prefix_sid *)i;

	if (json) {
		struct json_object *sr_json;
		sr_json = json_object_new_object();
		json_object_object_add(json, "sr", sr_json);
		if (sid->flags & ISIS_PREFIX_SID_VALUE) {
			json_object_int_add(sr_json, "label", sid->value);
		} else {
			json_object_int_add(sr_json, "index", sid->value);
		}
		json_object_int_add(sr_json, "alg", sid->algorithm);
		json_object_string_add(
			sr_json, "readvertised",
			((sid->flags & ISIS_PREFIX_SID_READVERTISED) ? "yes"
								     : ""));
		json_object_string_add(
			sr_json, "node",
			((sid->flags & ISIS_PREFIX_SID_NODE) ? "yes" : ""));
		json_object_string_add(sr_json, "php",
				       ((sid->flags & ISIS_PREFIX_SID_NO_PHP)
						? "no-php"
						: "php"));
		json_object_string_add(
			sr_json, "explicit-null",
			((sid->flags & ISIS_PREFIX_SID_EXPLICIT_NULL) ? "yes"
								      : ""));
		json_object_string_add(
			sr_json, "value",
			((sid->flags & ISIS_PREFIX_SID_VALUE) ? "yes" : ""));
		json_object_string_add(
			sr_json, "local",
			((sid->flags & ISIS_PREFIX_SID_LOCAL) ? "yes" : ""));

	} else {
		sbuf_push(buf, indent, "SR Prefix-SID ");
		if (sid->flags & ISIS_PREFIX_SID_VALUE) {
			sbuf_push(buf, 0, "Label: %u, ", sid->value);
		} else {
			sbuf_push(buf, 0, "Index: %u, ", sid->value);
		}
		sbuf_push(buf, 0, "Algorithm: %hhu, ", sid->algorithm);
		sbuf_push(buf, 0, "Flags:%s%s%s%s%s%s\n",
			  sid->flags & ISIS_PREFIX_SID_READVERTISED
				  ? " READVERTISED"
				  : "",
			  sid->flags & ISIS_PREFIX_SID_NODE ? " NODE" : "",
			  sid->flags & ISIS_PREFIX_SID_NO_PHP ? " NO-PHP"
							      : " PHP",
			  sid->flags & ISIS_PREFIX_SID_EXPLICIT_NULL
				  ? " EXPLICIT-NULL"
				  : "",
			  sid->flags & ISIS_PREFIX_SID_VALUE ? " VALUE" : "",
			  sid->flags & ISIS_PREFIX_SID_LOCAL ? " LOCAL" : "");
	}
}

static void free_item_prefix_sid(struct isis_item *i)
{
	XFREE(MTYPE_ISIS_SUBTLV, i);
}

static int pack_item_prefix_sid(struct isis_item *i, struct stream *s,
				size_t *min_len)
{
	struct isis_prefix_sid *sid = (struct isis_prefix_sid *)i;

	uint8_t size = (sid->flags & ISIS_PREFIX_SID_VALUE) ? 5 : 6;

	if (STREAM_WRITEABLE(s) < size) {
		*min_len = size;
		return 1;
	}

	stream_putc(s, sid->flags);
	stream_putc(s, sid->algorithm);

	if (sid->flags & ISIS_PREFIX_SID_VALUE) {
		stream_put3(s, sid->value);
	} else {
		stream_putl(s, sid->value);
	}

	return 0;
}

static int unpack_item_prefix_sid(uint16_t mtid, uint8_t len, struct stream *s,
				  struct sbuf *log, void *dest, int indent)
{
	struct isis_subtlvs *subtlvs = dest;
	struct isis_prefix_sid sid = {
	};

	sbuf_push(log, indent, "Unpacking SR Prefix-SID...\n");

	if (len < 5) {
		sbuf_push(log, indent,
			  "Not enough data left. (expected 5 or more bytes, got %hhu)\n",
			  len);
		return 1;
	}

	sid.flags = stream_getc(s);
	if (!!(sid.flags & ISIS_PREFIX_SID_VALUE)
	    != !!(sid.flags & ISIS_PREFIX_SID_LOCAL)) {
		sbuf_push(log, indent, "Flags implausible: Local Flag needs to match Value Flag\n");
		return 1;
	}

	sid.algorithm = stream_getc(s);

	uint8_t expected_size = (sid.flags & ISIS_PREFIX_SID_VALUE)
					? ISIS_SUBTLV_PREFIX_SID_SIZE
					: ISIS_SUBTLV_PREFIX_SID_SIZE + 1;
	if (len != expected_size) {
		sbuf_push(log, indent,
			  "TLV size differs from expected size. (expected %u but got %hhu)\n",
			  expected_size, len);
		return 1;
	}

	if (sid.flags & ISIS_PREFIX_SID_VALUE) {
		sid.value = stream_get3(s);
		if (!IS_MPLS_UNRESERVED_LABEL(sid.value)) {
			sbuf_push(log, indent, "Invalid absolute SID %u\n",
				  sid.value);
			return 1;
		}
	} else {
		sid.value = stream_getl(s);
	}

	format_item_prefix_sid(mtid, (struct isis_item *)&sid, log, NULL, indent + 2);
	append_item(&subtlvs->prefix_sids, copy_item_prefix_sid((struct isis_item *)&sid));
	return 0;
}

/* Functions for Sub-TVL ??? IPv6 Source Prefix */

static struct prefix_ipv6 *copy_subtlv_ipv6_source_prefix(struct prefix_ipv6 *p)
{
	if (!p)
		return NULL;

	struct prefix_ipv6 *rv = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*rv));
	rv->family = p->family;
	rv->prefixlen = p->prefixlen;
	memcpy(&rv->prefix, &p->prefix, sizeof(rv->prefix));
	return rv;
}

static void format_subtlv_ipv6_source_prefix(struct prefix_ipv6 *p,
					     struct sbuf *buf,
					     struct json_object *json,
					     int indent)
{
	if (!p)
		return;

	char prefixbuf[PREFIX2STR_BUFFER];
	if (json) {
		prefix2str(p, prefixbuf, sizeof(prefixbuf));
		json_object_string_add(json, "ipv6-src-prefix", prefixbuf);
	} else {
		sbuf_push(buf, indent, "IPv6 Source Prefix: %s\n",
			  prefix2str(p, prefixbuf, sizeof(prefixbuf)));
	}
}

static int pack_subtlv_ipv6_source_prefix(struct prefix_ipv6 *p,
					  struct stream *s)
{
	if (!p)
		return 0;

	if (STREAM_WRITEABLE(s) < 3 + (unsigned)PSIZE(p->prefixlen))
		return 1;

	stream_putc(s, ISIS_SUBTLV_IPV6_SOURCE_PREFIX);
	stream_putc(s, 1 + PSIZE(p->prefixlen));
	stream_putc(s, p->prefixlen);
	stream_put(s, &p->prefix, PSIZE(p->prefixlen));
	return 0;
}

static int unpack_subtlv_ipv6_source_prefix(enum isis_tlv_context context,
					    uint8_t tlv_type, uint8_t tlv_len,
					    struct stream *s, struct sbuf *log,
					    void *dest, int indent)
{
	struct isis_subtlvs *subtlvs = dest;
	struct prefix_ipv6 p = {
		.family = AF_INET6,
	};

	sbuf_push(log, indent, "Unpacking IPv6 Source Prefix Sub-TLV...\n");

	if (tlv_len < 1) {
		sbuf_push(log, indent,
			  "Not enough data left. (expected 1 or more bytes, got %hhu)\n",
			  tlv_len);
		return 1;
	}

	p.prefixlen = stream_getc(s);
	if (p.prefixlen > IPV6_MAX_BITLEN) {
		sbuf_push(log, indent, "Prefixlen %u is implausible for IPv6\n",
			  p.prefixlen);
		return 1;
	}

	if (tlv_len != 1 + PSIZE(p.prefixlen)) {
		sbuf_push(
			log, indent,
			"TLV size differs from expected size for the prefixlen. (expected %u but got %hhu)\n",
			1 + PSIZE(p.prefixlen), tlv_len);
		return 1;
	}

	stream_get(&p.prefix, s, PSIZE(p.prefixlen));

	if (subtlvs->source_prefix) {
		sbuf_push(
			log, indent,
			"WARNING: source prefix Sub-TLV present multiple times.\n");
		/* Ignore all but first occurrence of the source prefix Sub-TLV
		 */
		return 0;
	}

	subtlvs->source_prefix = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(p));
	memcpy(subtlvs->source_prefix, &p, sizeof(p));
	return 0;
}

/* Functions related to Sub-Sub-TLV 1 SRv6 SID Structure
 * as per RFC 9352 section #9 */
static struct isis_srv6_sid_structure_subsubtlv *
copy_subsubtlv_srv6_sid_structure(
	struct isis_srv6_sid_structure_subsubtlv *sid_struct)
{
	if (!sid_struct)
		return NULL;

	struct isis_srv6_sid_structure_subsubtlv *rv =
		XCALLOC(MTYPE_ISIS_SUBSUBTLV, sizeof(*rv));

	rv->loc_block_len = sid_struct->loc_block_len;
	rv->loc_node_len = sid_struct->loc_node_len;
	rv->func_len = sid_struct->func_len;
	rv->arg_len = sid_struct->arg_len;

	return rv;
}

static void format_subsubtlv_srv6_sid_structure(
	struct isis_srv6_sid_structure_subsubtlv *sid_struct, struct sbuf *buf,
	struct json_object *json, int indent)
{
	if (!sid_struct)
		return;

	if (json) {
		struct json_object *sid_struct_json;
		sid_struct_json = json_object_new_object();
		json_object_object_add(json, "srv6-sid-structure",
				       sid_struct_json);
		json_object_int_add(sid_struct_json, "loc-block-len",
				    sid_struct->loc_block_len);
		json_object_int_add(sid_struct_json, "loc-node-len",
				    sid_struct->loc_node_len);
		json_object_int_add(sid_struct_json, "func-len",
				    sid_struct->func_len);
		json_object_int_add(sid_struct_json, "arg-len",
				    sid_struct->arg_len);
	} else {
		sbuf_push(buf, indent, "SRv6 SID Structure ");
		sbuf_push(buf, 0, "Locator Block length: %hhu, ",
			  sid_struct->loc_block_len);
		sbuf_push(buf, 0, "Locator Node length: %hhu, ",
			  sid_struct->loc_node_len);
		sbuf_push(buf, 0, "Function length: %hhu, ",
			  sid_struct->func_len);
		sbuf_push(buf, 0, "Argument length: %hhu, ",
			  sid_struct->arg_len);
		sbuf_push(buf, 0, "\n");
	}
}

static void free_subsubtlv_srv6_sid_structure(
	struct isis_srv6_sid_structure_subsubtlv *sid_struct)
{
	XFREE(MTYPE_ISIS_SUBSUBTLV, sid_struct);
}

static int pack_subsubtlv_srv6_sid_structure(
	struct isis_srv6_sid_structure_subsubtlv *sid_struct, struct stream *s)
{
	if (!sid_struct)
		return 0;

	if (STREAM_WRITEABLE(s) < 6) {
		return 1;
	}

	stream_putc(s, ISIS_SUBSUBTLV_SRV6_SID_STRUCTURE);
	stream_putc(s, 4);
	stream_putc(s, sid_struct->loc_block_len);
	stream_putc(s, sid_struct->loc_node_len);
	stream_putc(s, sid_struct->func_len);
	stream_putc(s, sid_struct->arg_len);

	return 0;
}

static int unpack_subsubtlv_srv6_sid_structure(
	enum isis_tlv_context context, uint8_t tlv_type, uint8_t tlv_len,
	struct stream *s, struct sbuf *log, void *dest, int indent)
{
	struct isis_subsubtlvs *subsubtlvs = dest;
	struct isis_srv6_sid_structure_subsubtlv sid_struct = {};

	sbuf_push(log, indent, "Unpacking SRv6 SID Structure...\n");
	if (tlv_len != 4) {
		sbuf_push(
			log, indent,
			"Invalid SRv6 SID Structure Sub-Sub-TLV size. (Expected 4 bytes, got %hhu)\n",
			tlv_len);
		return 1;
	}

	sid_struct.loc_block_len = stream_getc(s);
	sid_struct.loc_node_len = stream_getc(s);
	sid_struct.func_len = stream_getc(s);
	sid_struct.arg_len = stream_getc(s);

	subsubtlvs->srv6_sid_structure =
		copy_subsubtlv_srv6_sid_structure(&sid_struct);

	return 0;
}

static struct isis_item *copy_item(enum isis_tlv_context context,
				   enum isis_tlv_type type,
				   struct isis_item *item);
static void copy_items(enum isis_tlv_context context, enum isis_tlv_type type,
		       struct isis_item_list *src, struct isis_item_list *dest);
static void format_items_(uint16_t mtid, enum isis_tlv_context context,
			  enum isis_tlv_type type, struct isis_item_list *items,
			  struct sbuf *buf, struct json_object *json,
			  int indent);
#define format_items(...) format_items_(ISIS_MT_IPV4_UNICAST, __VA_ARGS__)
static void free_items(enum isis_tlv_context context, enum isis_tlv_type type,
		       struct isis_item_list *items);
static int pack_items_(uint16_t mtid, enum isis_tlv_context context,
		       enum isis_tlv_type type, struct isis_item_list *items,
		       struct stream *s, struct isis_tlvs **fragment_tlvs,
		       const struct pack_order_entry *pe,
		       struct isis_tlvs *(*new_fragment)(struct list *l),
		       struct list *new_fragment_arg);
#define pack_items(...) pack_items_(ISIS_MT_IPV4_UNICAST, __VA_ARGS__)

/* Functions related to Sub-Sub-TLVs in general */

struct isis_subsubtlvs *isis_alloc_subsubtlvs(enum isis_tlv_context context)
{
	struct isis_subsubtlvs *result;

	result = XCALLOC(MTYPE_ISIS_SUBSUBTLV, sizeof(*result));
	result->context = context;

	return result;
}

static struct isis_subsubtlvs *
isis_copy_subsubtlvs(struct isis_subsubtlvs *subsubtlvs)
{
	if (!subsubtlvs)
		return NULL;

	struct isis_subsubtlvs *rv = XCALLOC(MTYPE_ISIS_SUBSUBTLV, sizeof(*rv));

	rv->context = subsubtlvs->context;

	rv->srv6_sid_structure = copy_subsubtlv_srv6_sid_structure(
		subsubtlvs->srv6_sid_structure);

	return rv;
}

static void isis_format_subsubtlvs(struct isis_subsubtlvs *subsubtlvs,
				   struct sbuf *buf, struct json_object *json,
				   int indent)
{
	format_subsubtlv_srv6_sid_structure(subsubtlvs->srv6_sid_structure, buf,
					    json, indent);
}

static void isis_free_subsubtlvs(struct isis_subsubtlvs *subsubtlvs)
{
	if (!subsubtlvs)
		return;

	free_subsubtlv_srv6_sid_structure(subsubtlvs->srv6_sid_structure);

	XFREE(MTYPE_ISIS_SUBSUBTLV, subsubtlvs);
}

static int isis_pack_subsubtlvs(struct isis_subsubtlvs *subsubtlvs,
				struct stream *s)
{
	int rv;
	size_t subsubtlv_len_pos = stream_get_endp(s);

	if (STREAM_WRITEABLE(s) < 1)
		return 1;

	stream_putc(s, 0); /* Put 0 as Sub-Sub-TLVs length, filled in later */

	rv = pack_subsubtlv_srv6_sid_structure(subsubtlvs->srv6_sid_structure,
					       s);
	if (rv)
		return rv;

	size_t subsubtlv_len = stream_get_endp(s) - subsubtlv_len_pos - 1;
	if (subsubtlv_len > 255)
		return 1;

	stream_putc_at(s, subsubtlv_len_pos, subsubtlv_len);
	return 0;
}

/* Functions related to subtlvs */

static struct isis_subtlvs *isis_alloc_subtlvs(enum isis_tlv_context context)
{
	struct isis_subtlvs *result;

	result = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*result));
	result->context = context;

	init_item_list(&result->prefix_sids);
	init_item_list(&result->srv6_end_sids);

	return result;
}

static struct isis_subtlvs *copy_subtlvs(struct isis_subtlvs *subtlvs)
{
	if (!subtlvs)
		return NULL;

	struct isis_subtlvs *rv = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*rv));

	rv->context = subtlvs->context;

	copy_items(subtlvs->context, ISIS_SUBTLV_PREFIX_SID,
		   &subtlvs->prefix_sids, &rv->prefix_sids);

	rv->source_prefix =
		copy_subtlv_ipv6_source_prefix(subtlvs->source_prefix);

	copy_items(subtlvs->context, ISIS_SUBTLV_SRV6_END_SID,
		   &subtlvs->srv6_end_sids, &rv->srv6_end_sids);

	return rv;
}

static void format_subtlvs(struct isis_subtlvs *subtlvs, struct sbuf *buf,
			   struct json_object *json, int indent)
{
	format_items(subtlvs->context, ISIS_SUBTLV_PREFIX_SID,
		     &subtlvs->prefix_sids, buf, json, indent);

	format_subtlv_ipv6_source_prefix(subtlvs->source_prefix, buf, json, indent);

	format_items(subtlvs->context, ISIS_SUBTLV_SRV6_END_SID,
		     &subtlvs->srv6_end_sids, buf, json, indent);
}

static void isis_free_subtlvs(struct isis_subtlvs *subtlvs)
{
	if (!subtlvs)
		return;

	free_items(subtlvs->context, ISIS_SUBTLV_PREFIX_SID,
		   &subtlvs->prefix_sids);

	XFREE(MTYPE_ISIS_SUBTLV, subtlvs->source_prefix);

	free_items(subtlvs->context, ISIS_SUBTLV_SRV6_END_SID,
		   &subtlvs->srv6_end_sids);

	XFREE(MTYPE_ISIS_SUBTLV, subtlvs);
}

static int pack_subtlvs(struct isis_subtlvs *subtlvs, struct stream *s)
{
	int rv;
	size_t subtlv_len_pos = stream_get_endp(s);

	if (STREAM_WRITEABLE(s) < 1)
		return 1;

	stream_putc(s, 0); /* Put 0 as subtlvs length, filled in later */

	rv = pack_items(subtlvs->context, ISIS_SUBTLV_PREFIX_SID,
			&subtlvs->prefix_sids, s, NULL, NULL, NULL, NULL);
	if (rv)
		return rv;

	rv = pack_subtlv_ipv6_source_prefix(subtlvs->source_prefix, s);
	if (rv)
		return rv;

	rv = pack_items(subtlvs->context, ISIS_SUBTLV_SRV6_END_SID,
			&subtlvs->srv6_end_sids, s, NULL, NULL, NULL, NULL);
	if (rv)
		return rv;

	size_t subtlv_len = stream_get_endp(s) - subtlv_len_pos - 1;
	if (subtlv_len > 255)
		return 1;

	stream_putc_at(s, subtlv_len_pos, subtlv_len);
	return 0;
}

static int unpack_tlvs(enum isis_tlv_context context, size_t avail_len,
		       struct stream *stream, struct sbuf *log, void *dest,
		       int indent, bool *unpacked_known_tlvs);

/* Functions for Sub-TLV 5 SRv6 End SID as per RFC 9352 section #7.2 */
static struct isis_item *copy_item_srv6_end_sid(struct isis_item *i)
{
	struct isis_srv6_end_sid_subtlv *sid =
		(struct isis_srv6_end_sid_subtlv *)i;
	struct isis_srv6_end_sid_subtlv *rv =
		XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*rv));

	rv->behavior = sid->behavior;
	rv->sid = sid->sid;
	rv->subsubtlvs = isis_copy_subsubtlvs(sid->subsubtlvs);

	return (struct isis_item *)rv;
}

static void format_item_srv6_end_sid(uint16_t mtid, struct isis_item *i,
				     struct sbuf *buf, struct json_object *json,
				     int indent)
{
	struct isis_srv6_end_sid_subtlv *sid =
		(struct isis_srv6_end_sid_subtlv *)i;

	if (json) {
		struct json_object *sid_json;
		sid_json = json_object_new_object();
		json_object_object_add(json, "srv6-end-sid", sid_json);
		json_object_string_add(sid_json, "endpoint-behavior",
				       seg6local_action2str(sid->behavior));
		json_object_string_addf(sid_json, "sid-value", "%pI6",
					&sid->sid);
		if (sid->subsubtlvs) {
			struct json_object *subtlvs_json;
			subtlvs_json = json_object_new_object();
			json_object_object_add(sid_json, "subsubtlvs",
					       subtlvs_json);
			isis_format_subsubtlvs(sid->subsubtlvs, NULL,
					       subtlvs_json, 0);
		}
	} else {
		sbuf_push(buf, indent, "SRv6 End SID ");
		sbuf_push(buf, 0, "Endpoint Behavior: %s, ",
			  seg6local_action2str(sid->behavior));
		sbuf_push(buf, 0, "SID value: %pI6\n", &sid->sid);

		if (sid->subsubtlvs) {
			sbuf_push(buf, indent, "  Sub-Sub-TLVs:\n");
			isis_format_subsubtlvs(sid->subsubtlvs, buf, NULL,
					       indent + 4);
		}
	}
}

static void free_item_srv6_end_sid(struct isis_item *i)
{
	struct isis_srv6_end_sid_subtlv *item =
		(struct isis_srv6_end_sid_subtlv *)i;

	isis_free_subsubtlvs(item->subsubtlvs);
	XFREE(MTYPE_ISIS_SUBTLV, i);
}

static int pack_item_srv6_end_sid(struct isis_item *i, struct stream *s,
				  size_t *min_len)
{
	struct isis_srv6_end_sid_subtlv *sid =
		(struct isis_srv6_end_sid_subtlv *)i;

	if (STREAM_WRITEABLE(s) < 19) {
		*min_len = 19;
		return 1;
	}

	stream_putc(s, sid->flags);
	stream_putw(s, sid->behavior);
	stream_put(s, &sid->sid, IPV6_MAX_BYTELEN);

	if (sid->subsubtlvs) {
		/* Pack Sub-Sub-TLVs */
		if (isis_pack_subsubtlvs(sid->subsubtlvs, s))
			return 1;
	} else {
		/* No Sub-Sub-TLVs */
		if (STREAM_WRITEABLE(s) < 1) {
			*min_len = 20;
			return 1;
		}

		/* Put 0 as Sub-Sub-TLV length, because we have no Sub-Sub-TLVs
		 */
		stream_putc(s, 0);
	}

	return 0;
}

static int unpack_item_srv6_end_sid(uint16_t mtid, uint8_t len,
				    struct stream *s, struct sbuf *log,
				    void *dest, int indent)
{
	struct isis_subtlvs *subtlvs = dest;
	struct isis_srv6_end_sid_subtlv *sid = NULL;
	size_t consume;
	uint8_t subsubtlv_len;

	sbuf_push(log, indent, "Unpacking SRv6 End SID...\n");

	consume = 19;
	if (len < consume) {
		sbuf_push(
			log, indent,
			"Not enough data left. (expected 19 or more bytes, got %hhu)\n",
			len);
		goto out;
	}

	sid = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*sid));

	sid->flags = stream_getc(s);
	sid->behavior = stream_getw(s);
	stream_get(&sid->sid, s, IPV6_MAX_BYTELEN);

	format_item_srv6_end_sid(mtid, (struct isis_item *)sid, log, NULL,
				 indent + 2);

	/* Process Sub-Sub-TLVs */
	consume += 1;
	if (len < consume) {
		sbuf_push(
			log, indent,
			"Expected 1 byte of Sub-Sub-TLV len, but no more data persent.\n");
		goto out;
	}
	subsubtlv_len = stream_getc(s);

	consume += subsubtlv_len;
	if (len < consume) {
		sbuf_push(log, indent,
			  "Expected %hhu bytes of Sub-Sub-TLVs, but only %u bytes available.\n",
			  subsubtlv_len, len - ((uint8_t)consume - subsubtlv_len));
		goto out;
	}

	sid->subsubtlvs =
		isis_alloc_subsubtlvs(ISIS_CONTEXT_SUBSUBTLV_SRV6_END_SID);

	bool unpacked_known_tlvs = false;
	if (unpack_tlvs(ISIS_CONTEXT_SUBSUBTLV_SRV6_END_SID, subsubtlv_len, s,
			log, sid->subsubtlvs, indent + 4,
			&unpacked_known_tlvs)) {
		goto out;
	}
	if (!unpacked_known_tlvs) {
		isis_free_subsubtlvs(sid->subsubtlvs);
		sid->subsubtlvs = NULL;
	}

	append_item(&subtlvs->srv6_end_sids, (struct isis_item *)sid);
	return 0;
out:
	if (sid)
		free_item_srv6_end_sid((struct isis_item *)sid);
	return 1;
}

/* Functions related to TLVs 1 Area Addresses */

static struct isis_item *copy_item_area_address(struct isis_item *i)
{
	struct isis_area_address *addr = (struct isis_area_address *)i;
	struct isis_area_address *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->len = addr->len;
	memcpy(rv->addr, addr->addr, addr->len);
	return (struct isis_item *)rv;
}

static void format_item_area_address(uint16_t mtid, struct isis_item *i,
				     struct sbuf *buf, struct json_object *json,
				     int indent)
{
	struct isis_area_address *addr = (struct isis_area_address *)i;
	struct iso_address iso_addr;

	memcpy(iso_addr.area_addr, addr->addr, ISO_ADDR_SIZE);
	iso_addr.addr_len = addr->len;
	if (json)
		json_object_string_addf(json, "area-addr", "%pIS", &iso_addr);
	else
		sbuf_push(buf, indent, "Area Address: %pIS\n", &iso_addr);
}

static void free_item_area_address(struct isis_item *i)
{
	XFREE(MTYPE_ISIS_TLV, i);
}

static int pack_item_area_address(struct isis_item *i, struct stream *s,
				  size_t *min_len)
{
	struct isis_area_address *addr = (struct isis_area_address *)i;

	if (STREAM_WRITEABLE(s) < (unsigned)1 + addr->len) {
		*min_len = (unsigned)1 + addr->len;
		return 1;
	}
	stream_putc(s, addr->len);
	stream_put(s, addr->addr, addr->len);
	return 0;
}

static int unpack_item_area_address(uint16_t mtid, uint8_t len,
				    struct stream *s, struct sbuf *log,
				    void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;
	struct isis_area_address *rv = NULL;

	sbuf_push(log, indent, "Unpack area address...\n");
	if (len < 1) {
		sbuf_push(
			log, indent,
			"Not enough data left. (Expected 1 byte of address length, got %hhu)\n",
			len);
		goto out;
	}

	rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	rv->len = stream_getc(s);

	if (len < 1 + rv->len) {
		sbuf_push(log, indent, "Not enough data left. (Expected %hhu bytes of address, got %u)\n",
			  rv->len, len - 1);
		goto out;
	}

	if (rv->len < 1 || rv->len > 20) {
		sbuf_push(log, indent,
			  "Implausible area address length %hhu\n",
			  rv->len);
		goto out;
	}

	stream_get(rv->addr, s, rv->len);

	format_item_area_address(ISIS_MT_IPV4_UNICAST, (struct isis_item *)rv,
				 log, NULL, indent + 2);
	append_item(&tlvs->area_addresses, (struct isis_item *)rv);
	return 0;
out:
	XFREE(MTYPE_ISIS_TLV, rv);
	return 1;
}

/* Functions related to TLV 2 (Old-Style) IS Reach */
static struct isis_item *copy_item_oldstyle_reach(struct isis_item *i)
{
	struct isis_oldstyle_reach *r = (struct isis_oldstyle_reach *)i;
	struct isis_oldstyle_reach *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	memcpy(rv->id, r->id, 7);
	rv->metric = r->metric;
	return (struct isis_item *)rv;
}

static void format_item_oldstyle_reach(uint16_t mtid, struct isis_item *i,
				       struct sbuf *buf,
				       struct json_object *json, int indent)
{
	struct isis_oldstyle_reach *r = (struct isis_oldstyle_reach *)i;
	char sys_id[ISO_SYSID_STRLEN];

	snprintfrr(sys_id, ISO_SYSID_STRLEN, "%pPN", r->id);
	if (json) {
		struct json_object *old_json;
		old_json = json_object_new_object();
		json_object_object_add(json, "old-reach-style", old_json);
		json_object_string_add(old_json, "is-reach", sys_id);
		json_object_int_add(old_json, "metric", r->metric);
	} else
		sbuf_push(buf, indent, "IS Reachability: %s (Metric: %hhu)\n",
			  sys_id, r->metric);
}

static void free_item_oldstyle_reach(struct isis_item *i)
{
	XFREE(MTYPE_ISIS_TLV, i);
}

static int pack_item_oldstyle_reach(struct isis_item *i, struct stream *s,
				    size_t *min_len)
{
	struct isis_oldstyle_reach *r = (struct isis_oldstyle_reach *)i;

	if (STREAM_WRITEABLE(s) < 11) {
		*min_len = 11;
		return 1;
	}

	stream_putc(s, r->metric);
	stream_putc(s, 0x80); /* delay metric - unsupported */
	stream_putc(s, 0x80); /* expense metric - unsupported */
	stream_putc(s, 0x80); /* error metric - unsupported */
	stream_put(s, r->id, 7);

	return 0;
}

static int unpack_item_oldstyle_reach(uint16_t mtid, uint8_t len,
				      struct stream *s, struct sbuf *log,
				      void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpack oldstyle reach...\n");
	if (len < 11) {
		sbuf_push(
			log, indent,
			"Not enough data left.(Expected 11 bytes of reach information, got %hhu)\n",
			len);
		return 1;
	}

	struct isis_oldstyle_reach *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	rv->metric = stream_getc(s);
	if ((rv->metric & 0x3f) != rv->metric) {
		sbuf_push(log, indent, "Metric has unplausible format\n");
		rv->metric &= 0x3f;
	}
	stream_forward_getp(s, 3); /* Skip other metrics */
	stream_get(rv->id, s, 7);

	format_item_oldstyle_reach(mtid, (struct isis_item *)rv, log, NULL,
				   indent + 2);
	append_item(&tlvs->oldstyle_reach, (struct isis_item *)rv);
	return 0;
}

/* Functions related to TLV 6 LAN Neighbors */
static struct isis_item *copy_item_lan_neighbor(struct isis_item *i)
{
	struct isis_lan_neighbor *n = (struct isis_lan_neighbor *)i;
	struct isis_lan_neighbor *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	memcpy(rv->mac, n->mac, 6);
	return (struct isis_item *)rv;
}

static void format_item_lan_neighbor(uint16_t mtid, struct isis_item *i,
				     struct sbuf *buf, struct json_object *json,
				     int indent)
{
	struct isis_lan_neighbor *n = (struct isis_lan_neighbor *)i;
	char sys_id[ISO_SYSID_STRLEN];

	snprintfrr(sys_id, ISO_SYSID_STRLEN, "%pSY", n->mac);
	if (json)
		json_object_string_add(json, "lan-neighbor", sys_id);
	else
		sbuf_push(buf, indent, "LAN Neighbor: %s\n", sys_id);
}

static void free_item_lan_neighbor(struct isis_item *i)
{
	XFREE(MTYPE_ISIS_TLV, i);
}

static int pack_item_lan_neighbor(struct isis_item *i, struct stream *s,
				  size_t *min_len)
{
	struct isis_lan_neighbor *n = (struct isis_lan_neighbor *)i;

	if (STREAM_WRITEABLE(s) < 6) {
		*min_len = 6;
		return 1;
	}

	stream_put(s, n->mac, 6);

	return 0;
}

static int unpack_item_lan_neighbor(uint16_t mtid, uint8_t len,
				    struct stream *s, struct sbuf *log,
				    void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpack LAN neighbor...\n");
	if (len < 6) {
		sbuf_push(
			log, indent,
			"Not enough data left.(Expected 6 bytes of mac, got %hhu)\n",
			len);
		return 1;
	}

	struct isis_lan_neighbor *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	stream_get(rv->mac, s, 6);

	format_item_lan_neighbor(mtid, (struct isis_item *)rv, log, NULL, indent + 2);
	append_item(&tlvs->lan_neighbor, (struct isis_item *)rv);
	return 0;
}

/* Functions related to TLV 9 LSP Entry */
static struct isis_item *copy_item_lsp_entry(struct isis_item *i)
{
	struct isis_lsp_entry *e = (struct isis_lsp_entry *)i;
	struct isis_lsp_entry *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->rem_lifetime = e->rem_lifetime;
	memcpy(rv->id, e->id, sizeof(rv->id));
	rv->seqno = e->seqno;
	rv->checksum = e->checksum;

	return (struct isis_item *)rv;
}

static void format_item_lsp_entry(uint16_t mtid, struct isis_item *i,
				  struct sbuf *buf, struct json_object *json,
				  int indent)
{
	struct isis_lsp_entry *e = (struct isis_lsp_entry *)i;
	char sys_id[ISO_SYSID_STRLEN];

	snprintfrr(sys_id, ISO_SYSID_STRLEN, "%pLS", e->id);
	if (json) {
		char buf[255];
		struct json_object *lsp_json;
		lsp_json = json_object_new_object();
		json_object_object_add(json, "lsp-entry", lsp_json);
		json_object_string_add(lsp_json, "id", sys_id);
		snprintfrr(buf,sizeof(buf),"0x%08x",e->seqno);
		json_object_string_add(lsp_json, "seq", buf);
		snprintfrr(buf,sizeof(buf),"0x%04hx",e->checksum);
		json_object_string_add(lsp_json, "chksum", buf);
		json_object_int_add(lsp_json, "lifetime", e->checksum);
	} else
		sbuf_push(
			buf, indent,
			"LSP Entry: %s, seq 0x%08x, cksum 0x%04hx, lifetime %hus\n",
			sys_id, e->seqno, e->checksum, e->rem_lifetime);
}

static void free_item_lsp_entry(struct isis_item *i)
{
	XFREE(MTYPE_ISIS_TLV, i);
}

static int pack_item_lsp_entry(struct isis_item *i, struct stream *s,
			       size_t *min_len)
{
	struct isis_lsp_entry *e = (struct isis_lsp_entry *)i;

	if (STREAM_WRITEABLE(s) < 16) {
		*min_len = 16;
		return 1;
	}

	stream_putw(s, e->rem_lifetime);
	stream_put(s, e->id, 8);
	stream_putl(s, e->seqno);
	stream_putw(s, e->checksum);

	return 0;
}

static int unpack_item_lsp_entry(uint16_t mtid, uint8_t len, struct stream *s,
				 struct sbuf *log, void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpack LSP entry...\n");
	if (len < 16) {
		sbuf_push(
			log, indent,
			"Not enough data left. (Expected 16 bytes of LSP info, got %hhu",
			len);
		return 1;
	}

	struct isis_lsp_entry *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	rv->rem_lifetime = stream_getw(s);
	stream_get(rv->id, s, 8);
	rv->seqno = stream_getl(s);
	rv->checksum = stream_getw(s);

	format_item_lsp_entry(mtid, (struct isis_item *)rv, log, NULL, indent + 2);
	append_item(&tlvs->lsp_entries, (struct isis_item *)rv);
	return 0;
}

/* Functions related to TLVs 22/222 Extended Reach/MT Reach */

static struct isis_item *copy_item_extended_reach(struct isis_item *i)
{
	struct isis_extended_reach *r = (struct isis_extended_reach *)i;
	struct isis_extended_reach *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	memcpy(rv->id, r->id, 7);
	rv->metric = r->metric;

	if (r->subtlvs)
		rv->subtlvs = copy_item_ext_subtlvs(r->subtlvs, -1);

	return (struct isis_item *)rv;
}

static void format_item_extended_reach(uint16_t mtid, struct isis_item *i,
				       struct sbuf *buf,
				       struct json_object *json, int indent)
{
	struct isis_extended_reach *r = (struct isis_extended_reach *)i;
	char sys_id[ISO_SYSID_STRLEN];

	snprintfrr(sys_id, ISO_SYSID_STRLEN, "%pPN", r->id);
	if (json) {
		struct json_object *reach_json;
		reach_json = json_object_new_object();
		json_object_object_add(json, "ext-reach", reach_json);
		json_object_string_add(
			reach_json, "mt-id",
			(mtid == ISIS_MT_IPV4_UNICAST) ? "Extended" : "MT");
		json_object_string_add(reach_json, "id", sys_id);
		json_object_int_add(reach_json, "metric", r->metric);
		if (mtid != ISIS_MT_IPV4_UNICAST)
			json_object_string_add(reach_json, "mt-name",
					       isis_mtid2str(mtid));

		if (r->subtlvs)
			format_item_ext_subtlvs(r->subtlvs, NULL, json,
						indent + 2, mtid);
	} else {
		sbuf_push(buf, indent, "%s Reachability: %s (Metric: %u)",
			  (mtid == ISIS_MT_IPV4_UNICAST) ? "Extended" : "MT",
			  sys_id, r->metric);
		if (mtid != ISIS_MT_IPV4_UNICAST)
			sbuf_push(buf, 0, " %s", isis_mtid2str(mtid));
		sbuf_push(buf, 0, "\n");

		if (r->subtlvs)
			format_item_ext_subtlvs(r->subtlvs, buf, NULL,
						indent + 2, mtid);
	}
}

static void free_item_extended_reach(struct isis_item *i)
{
	struct isis_extended_reach *item = (struct isis_extended_reach *)i;

	if (item->subtlvs != NULL)
		free_item_ext_subtlvs(item->subtlvs);
	XFREE(MTYPE_ISIS_TLV, item);
}

static int pack_item_extended_reach(struct isis_item *i, struct stream *s,
				    size_t *min_len)
{
	struct isis_extended_reach *r = (struct isis_extended_reach *)i;
	size_t len;
	size_t len_pos;

	if (STREAM_WRITEABLE(s) < 11 + ISIS_SUBTLV_MAX_SIZE) {
		*min_len = 11 + ISIS_SUBTLV_MAX_SIZE;
		return 1;
	}

	stream_put(s, r->id, sizeof(r->id));
	stream_put3(s, r->metric);
	len_pos = stream_get_endp(s);
	 /* Real length will be adjust after adding subTLVs */
	stream_putc(s, 11);
	if (r->subtlvs)
		pack_item_ext_subtlvs(r->subtlvs, s, min_len);
	/* Adjust length */
	len = stream_get_endp(s) - len_pos - 1;
	stream_putc_at(s, len_pos, len);
	return 0;
}

static int unpack_item_extended_reach(uint16_t mtid, uint8_t len,
				      struct stream *s, struct sbuf *log,
				      void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;
	struct isis_extended_reach *rv = NULL;
	uint8_t subtlv_len;
	struct isis_item_list *items;

	if (mtid == ISIS_MT_IPV4_UNICAST) {
		items = &tlvs->extended_reach;
	} else {
		items = isis_get_mt_items(&tlvs->mt_reach, mtid);
	}

	sbuf_push(log, indent, "Unpacking %s reachability...\n",
		  (mtid == ISIS_MT_IPV4_UNICAST) ? "extended" : "mt");

	if (len < 11) {
		sbuf_push(log, indent,
			  "Not enough data left. (expected 11 or more bytes, got %hhu)\n",
			  len);
		goto out;
	}

	rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	stream_get(rv->id, s, 7);
	rv->metric = stream_get3(s);
	subtlv_len = stream_getc(s);

	if ((size_t)len < ((size_t)11) + subtlv_len) {
		sbuf_push(log, indent,
			  "Not enough data left for subtlv size %hhu, there are only %u bytes left.\n",
			  subtlv_len, len - 11);
		goto out;
	}

	sbuf_push(log, indent, "Storing %hhu bytes of subtlvs\n",
		  subtlv_len);

	if (subtlv_len) {
		if (unpack_item_ext_subtlvs(mtid, subtlv_len, s, log, rv,
					    indent + 4)) {
			goto out;
		}
	}

	format_item_extended_reach(mtid, (struct isis_item *)rv, log, NULL,
				   indent + 2);
	append_item(items, (struct isis_item *)rv);
	return 0;
out:
	if (rv)
		free_item_extended_reach((struct isis_item *)rv);

	return 1;
}

/* Functions related to TLV 128 (Old-Style) IP Reach */
static struct isis_item *copy_item_oldstyle_ip_reach(struct isis_item *i)
{
	struct isis_oldstyle_ip_reach *r = (struct isis_oldstyle_ip_reach *)i;
	struct isis_oldstyle_ip_reach *rv =
		XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->metric = r->metric;
	rv->prefix = r->prefix;
	return (struct isis_item *)rv;
}

static void format_item_oldstyle_ip_reach(uint16_t mtid, struct isis_item *i,
					  struct sbuf *buf,
					  struct json_object *json, int indent)
{
	struct isis_oldstyle_ip_reach *r = (struct isis_oldstyle_ip_reach *)i;
	char prefixbuf[PREFIX2STR_BUFFER];

	if (json) {
		struct json_object *old_json;
		old_json = json_object_new_object();
		json_object_object_add(json, "old-ip-reach-style", old_json);
		json_object_string_add(old_json, "prefix",
				       prefix2str(&r->prefix, prefixbuf, sizeof(prefixbuf)));
		json_object_int_add(old_json, "metric", r->metric);
	} else
	sbuf_push(buf, indent, "IP Reachability: %s (Metric: %hhu)\n",
		  prefix2str(&r->prefix, prefixbuf, sizeof(prefixbuf)),
		  r->metric);
}

static void free_item_oldstyle_ip_reach(struct isis_item *i)
{
	XFREE(MTYPE_ISIS_TLV, i);
}

static int pack_item_oldstyle_ip_reach(struct isis_item *i, struct stream *s,
				       size_t *min_len)
{
	struct isis_oldstyle_ip_reach *r = (struct isis_oldstyle_ip_reach *)i;

	if (STREAM_WRITEABLE(s) < 12) {
		*min_len = 12;
		return 1;
	}

	stream_putc(s, r->metric);
	stream_putc(s, 0x80); /* delay metric - unsupported */
	stream_putc(s, 0x80); /* expense metric - unsupported */
	stream_putc(s, 0x80); /* error metric - unsupported */
	stream_put(s, &r->prefix.prefix, 4);

	struct in_addr mask;
	masklen2ip(r->prefix.prefixlen, &mask);
	stream_put(s, &mask, sizeof(mask));

	return 0;
}

static int unpack_item_oldstyle_ip_reach(uint16_t mtid, uint8_t len,
					 struct stream *s, struct sbuf *log,
					 void *dest, int indent)
{
	sbuf_push(log, indent, "Unpack oldstyle ip reach...\n");
	if (len < 12) {
		sbuf_push(
			log, indent,
			"Not enough data left.(Expected 12 bytes of reach information, got %hhu)\n",
			len);
		return 1;
	}

	struct isis_oldstyle_ip_reach *rv =
		XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	rv->metric = stream_getc(s);
	if ((rv->metric & 0x7f) != rv->metric) {
		sbuf_push(log, indent, "Metric has unplausible format\n");
		rv->metric &= 0x7f;
	}
	stream_forward_getp(s, 3); /* Skip other metrics */
	rv->prefix.family = AF_INET;
	stream_get(&rv->prefix.prefix, s, 4);

	struct in_addr mask;
	stream_get(&mask, s, 4);
	rv->prefix.prefixlen = ip_masklen(mask);

	format_item_oldstyle_ip_reach(mtid, (struct isis_item *)rv, log, NULL,
				      indent + 2);
	append_item(dest, (struct isis_item *)rv);
	return 0;
}


/* Functions related to TLV 129 protocols supported */

static void copy_tlv_protocols_supported(struct isis_protocols_supported *src,
					 struct isis_protocols_supported *dest)
{
	if (!src->protocols || !src->count)
		return;
	dest->count = src->count;
	dest->protocols = XCALLOC(MTYPE_ISIS_TLV, src->count);
	memcpy(dest->protocols, src->protocols, src->count);
}

static void format_tlv_protocols_supported(struct isis_protocols_supported *p,
					   struct sbuf *buf,
					   struct json_object *json, int indent)
{
	if (!p || !p->count || !p->protocols)
		return;

	if (json) {
		struct json_object *protocol_json;
		char buf[255];

		protocol_json = json_object_new_object();
		json_object_object_add(json, "protocols-supported",
				       protocol_json);
		for (uint8_t i = 0; i < p->count; i++) {
			snprintfrr(buf, sizeof(buf), "%d", i);
			json_object_string_add(protocol_json, buf,
					       nlpid2str(p->protocols[i]));
		}
	} else {
		sbuf_push(buf, indent, "Protocols Supported: ");
		for (uint8_t i = 0; i < p->count; i++) {
			sbuf_push(buf, 0, "%s%s", nlpid2str(p->protocols[i]),
				  (i + 1 < p->count) ? ", " : "");
		}
		sbuf_push(buf, 0, "\n");
	}
}

static void free_tlv_protocols_supported(struct isis_protocols_supported *p)
{
	XFREE(MTYPE_ISIS_TLV, p->protocols);
}

static int pack_tlv_protocols_supported(struct isis_protocols_supported *p,
					struct stream *s)
{
	if (!p || !p->count || !p->protocols)
		return 0;

	if (STREAM_WRITEABLE(s) < (unsigned)(p->count + 2))
		return 1;

	stream_putc(s, ISIS_TLV_PROTOCOLS_SUPPORTED);
	stream_putc(s, p->count);
	stream_put(s, p->protocols, p->count);
	return 0;
}

static int unpack_tlv_protocols_supported(enum isis_tlv_context context,
					  uint8_t tlv_type, uint8_t tlv_len,
					  struct stream *s, struct sbuf *log,
					  void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpacking Protocols Supported TLV...\n");
	if (!tlv_len) {
		sbuf_push(log, indent, "WARNING: No protocols included\n");
		return 0;
	}
	if (tlvs->protocols_supported.protocols) {
		sbuf_push(
			log, indent,
			"WARNING: protocols supported TLV present multiple times.\n");
		stream_forward_getp(s, tlv_len);
		return 0;
	}

	tlvs->protocols_supported.count = tlv_len;
	tlvs->protocols_supported.protocols = XCALLOC(MTYPE_ISIS_TLV, tlv_len);
	stream_get(tlvs->protocols_supported.protocols, s, tlv_len);

	format_tlv_protocols_supported(&tlvs->protocols_supported, log, NULL,
				       indent + 2);
	return 0;
}

/* Functions related to TLV 132 IPv4 Interface addresses */
static struct isis_item *copy_item_ipv4_address(struct isis_item *i)
{
	struct isis_ipv4_address *a = (struct isis_ipv4_address *)i;
	struct isis_ipv4_address *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->addr = a->addr;
	return (struct isis_item *)rv;
}

static void format_item_ipv4_address(uint16_t mtid, struct isis_item *i,
				     struct sbuf *buf, struct json_object *json,
				     int indent)
{
	struct isis_ipv4_address *a = (struct isis_ipv4_address *)i;
	char addrbuf[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &a->addr, addrbuf, sizeof(addrbuf));
	if (json) {
		json_object_string_add(json, "ipv4", addrbuf);
	} else {
		sbuf_push(buf, indent, "IPv4 Interface Address: %s\n", addrbuf);
	}
}

static void free_item_ipv4_address(struct isis_item *i)
{
	XFREE(MTYPE_ISIS_TLV, i);
}

static int pack_item_ipv4_address(struct isis_item *i, struct stream *s,
				  size_t *min_len)
{
	struct isis_ipv4_address *a = (struct isis_ipv4_address *)i;

	if (STREAM_WRITEABLE(s) < 4) {
		*min_len = 4;
		return 1;
	}

	stream_put(s, &a->addr, 4);

	return 0;
}

static int unpack_item_ipv4_address(uint16_t mtid, uint8_t len,
				    struct stream *s, struct sbuf *log,
				    void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpack IPv4 Interface address...\n");
	if (len < 4) {
		sbuf_push(
			log, indent,
			"Not enough data left.(Expected 4 bytes of IPv4 address, got %hhu)\n",
			len);
		return 1;
	}

	struct isis_ipv4_address *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	stream_get(&rv->addr, s, 4);

	format_item_ipv4_address(mtid, (struct isis_item *)rv, log, NULL, indent + 2);
	append_item(&tlvs->ipv4_address, (struct isis_item *)rv);
	return 0;
}


/* Functions related to TLV 232 IPv6 Interface addresses */
static struct isis_item *copy_item_ipv6_address(struct isis_item *i)
{
	struct isis_ipv6_address *a = (struct isis_ipv6_address *)i;
	struct isis_ipv6_address *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->addr = a->addr;
	return (struct isis_item *)rv;
}

static void format_item_ipv6_address(uint16_t mtid, struct isis_item *i,
				     struct sbuf *buf, struct json_object *json,
				     int indent)
{
	struct isis_ipv6_address *a = (struct isis_ipv6_address *)i;
	char addrbuf[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &a->addr, addrbuf, sizeof(addrbuf));
	if (json)
		json_object_string_add(json, "ipv6", addrbuf);
	else
		sbuf_push(buf, indent, "IPv6 Interface Address: %s\n", addrbuf);
}

static void free_item_ipv6_address(struct isis_item *i)
{
	XFREE(MTYPE_ISIS_TLV, i);
}

static int pack_item_ipv6_address(struct isis_item *i, struct stream *s,
				  size_t *min_len)
{
	struct isis_ipv6_address *a = (struct isis_ipv6_address *)i;

	if (STREAM_WRITEABLE(s) < IPV6_MAX_BYTELEN) {
		*min_len = IPV6_MAX_BYTELEN;
		return 1;
	}

	stream_put(s, &a->addr, IPV6_MAX_BYTELEN);

	return 0;
}

static int unpack_item_ipv6_address(uint16_t mtid, uint8_t len,
				    struct stream *s, struct sbuf *log,
				    void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpack IPv6 Interface address...\n");
	if (len < 16) {
		sbuf_push(
			log, indent,
			"Not enough data left.(Expected 16 bytes of IPv6 address, got %hhu)\n",
			len);
		return 1;
	}

	struct isis_ipv6_address *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	stream_get(&rv->addr, s, IPV6_MAX_BYTELEN);

	format_item_ipv6_address(mtid, (struct isis_item *)rv, log, NULL, indent + 2);
	append_item(&tlvs->ipv6_address, (struct isis_item *)rv);
	return 0;
}


/* Functions related to TLV 233 Global IPv6 Interface addresses */
static struct isis_item *copy_item_global_ipv6_address(struct isis_item *i)
{
	struct isis_ipv6_address *a = (struct isis_ipv6_address *)i;
	struct isis_ipv6_address *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->addr = a->addr;
	return (struct isis_item *)rv;
}

static void format_item_global_ipv6_address(uint16_t mtid, struct isis_item *i,
					    struct sbuf *buf,
					    struct json_object *json,
					    int indent)
{
	struct isis_ipv6_address *a = (struct isis_ipv6_address *)i;
	char addrbuf[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &a->addr, addrbuf, sizeof(addrbuf));
	if (json)
		json_object_string_add(json, "global-ipv6", addrbuf);
	else
		sbuf_push(buf, indent, "Global IPv6 Interface Address: %s\n",
			  addrbuf);
}

static void free_item_global_ipv6_address(struct isis_item *i)
{
	XFREE(MTYPE_ISIS_TLV, i);
}

static int pack_item_global_ipv6_address(struct isis_item *i, struct stream *s,
					 size_t *min_len)
{
	struct isis_ipv6_address *a = (struct isis_ipv6_address *)i;

	if (STREAM_WRITEABLE(s) < IPV6_MAX_BYTELEN) {
		*min_len = IPV6_MAX_BYTELEN;
		return 1;
	}

	stream_put(s, &a->addr, IPV6_MAX_BYTELEN);

	return 0;
}

static int unpack_item_global_ipv6_address(uint16_t mtid, uint8_t len,
					   struct stream *s, struct sbuf *log,
					   void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpack Global IPv6 Interface address...\n");
	if (len < IPV6_MAX_BYTELEN) {
		sbuf_push(
			log, indent,
			"Not enough data left.(Expected 16 bytes of IPv6 address, got %hhu)\n",
			len);
		return 1;
	}

	struct isis_ipv6_address *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	stream_get(&rv->addr, s, IPV6_MAX_BYTELEN);

	format_item_global_ipv6_address(mtid, (struct isis_item *)rv, log, NULL,
					indent + 2);
	append_item(&tlvs->global_ipv6_address, (struct isis_item *)rv);
	return 0;
}

/* Functions related to TLV 229 MT Router information */
static struct isis_item *copy_item_mt_router_info(struct isis_item *i)
{
	struct isis_mt_router_info *info = (struct isis_mt_router_info *)i;
	struct isis_mt_router_info *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->overload = info->overload;
	rv->attached = info->attached;
	rv->mtid = info->mtid;
	return (struct isis_item *)rv;
}

static void format_item_mt_router_info(uint16_t mtid, struct isis_item *i,
				       struct sbuf *buf,
				       struct json_object *json, int indent)
{
	struct isis_mt_router_info *info = (struct isis_mt_router_info *)i;

	if (json) {
		struct json_object *mt_json;
		mt_json = json_object_new_object();
		json_object_object_add(json, "mt", mt_json);
		json_object_int_add(mt_json, "mtid", info->mtid);
		json_object_string_add(mt_json, "overload", info->overload?"true":"false");
		json_object_string_add(mt_json, "attached", info->attached?"true":"false");
	} else
		sbuf_push(buf, indent, "MT Router Info: %s%s%s\n",
			  isis_mtid2str_fake(info->mtid),
			  info->overload ? " Overload" : "",
			  info->attached ? " Attached" : "");
}

static void free_item_mt_router_info(struct isis_item *i)
{
	XFREE(MTYPE_ISIS_TLV, i);
}

static int pack_item_mt_router_info(struct isis_item *i, struct stream *s,
				    size_t *min_len)
{
	struct isis_mt_router_info *info = (struct isis_mt_router_info *)i;

	if (STREAM_WRITEABLE(s) < 2) {
		*min_len = 2;
		return 1;
	}

	uint16_t entry = info->mtid;

	if (info->overload)
		entry |= ISIS_MT_OL_MASK;
	if (info->attached)
		entry |= ISIS_MT_AT_MASK;

	stream_putw(s, entry);

	return 0;
}

static int unpack_item_mt_router_info(uint16_t mtid, uint8_t len,
				      struct stream *s, struct sbuf *log,
				      void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpack MT Router info...\n");
	if (len < 2) {
		sbuf_push(
			log, indent,
			"Not enough data left.(Expected 2 bytes of MT info, got %hhu)\n",
			len);
		return 1;
	}

	struct isis_mt_router_info *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	uint16_t entry = stream_getw(s);
	rv->overload = entry & ISIS_MT_OL_MASK;
	rv->attached = entry & ISIS_MT_AT_MASK;
	rv->mtid = entry & ISIS_MT_MASK;

	format_item_mt_router_info(mtid, (struct isis_item *)rv, log, NULL,
				   indent + 2);
	append_item(&tlvs->mt_router_info, (struct isis_item *)rv);
	return 0;
}

/* Functions related to TLV 134 TE Router ID */

static struct in_addr *copy_tlv_te_router_id(const struct in_addr *id)
{
	if (!id)
		return NULL;

	struct in_addr *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	memcpy(rv, id, sizeof(*rv));
	return rv;
}

static void format_tlv_te_router_id(const struct in_addr *id, struct sbuf *buf,
				    struct json_object *json, int indent)
{
	if (!id)
		return;

	char addrbuf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, id, addrbuf, sizeof(addrbuf));
	if (json)
		json_object_string_add(json, "te-router-id", addrbuf);
	else
		sbuf_push(buf, indent, "TE Router ID: %s\n", addrbuf);
}

static void free_tlv_te_router_id(struct in_addr *id)
{
	XFREE(MTYPE_ISIS_TLV, id);
}

static int pack_tlv_te_router_id(const struct in_addr *id, struct stream *s)
{
	if (!id)
		return 0;

	if (STREAM_WRITEABLE(s) < (unsigned)(2 + sizeof(*id)))
		return 1;

	stream_putc(s, ISIS_TLV_TE_ROUTER_ID);
	stream_putc(s, 4);
	stream_put(s, id, 4);
	return 0;
}

static int unpack_tlv_te_router_id(enum isis_tlv_context context,
				   uint8_t tlv_type, uint8_t tlv_len,
				   struct stream *s, struct sbuf *log,
				   void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpacking TE Router ID TLV...\n");
	if (tlv_len != 4) {
		sbuf_push(log, indent, "WARNING: Length invalid\n");
		return 1;
	}

	if (tlvs->te_router_id) {
		sbuf_push(log, indent,
			  "WARNING: TE Router ID present multiple times.\n");
		stream_forward_getp(s, tlv_len);
		return 0;
	}

	tlvs->te_router_id = XCALLOC(MTYPE_ISIS_TLV, 4);
	stream_get(tlvs->te_router_id, s, 4);
	format_tlv_te_router_id(tlvs->te_router_id, log, NULL, indent + 2);
	return 0;
}


/* Functions related to TLVs 135/235 extended IP reach/MT IP Reach */

static struct isis_item *copy_item_extended_ip_reach(struct isis_item *i)
{
	struct isis_extended_ip_reach *r = (struct isis_extended_ip_reach *)i;
	struct isis_extended_ip_reach *rv =
		XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->metric = r->metric;
	rv->down = r->down;
	rv->prefix = r->prefix;
	rv->subtlvs = copy_subtlvs(r->subtlvs);

	return (struct isis_item *)rv;
}

static void format_item_extended_ip_reach(uint16_t mtid, struct isis_item *i,
					  struct sbuf *buf,
					  struct json_object *json, int indent)
{
	struct isis_extended_ip_reach *r = (struct isis_extended_ip_reach *)i;
	char prefixbuf[PREFIX2STR_BUFFER];

	if (json) {
		struct json_object *ext_json;
		ext_json = json_object_new_object();
		json_object_object_add(json, "ext-ip-reach", ext_json);
		json_object_string_add(
			json, "mt-id",
			(mtid == ISIS_MT_IPV4_UNICAST) ? "Extended" : "MT");
		json_object_string_add(
			json, "ip-reach",
			prefix2str(&r->prefix, prefixbuf, sizeof(prefixbuf)));
		json_object_int_add(json, "ip-reach-metric", r->metric);
		json_object_string_add(json, "down", r->down ? "yes" : "");
		if (mtid != ISIS_MT_IPV4_UNICAST)
			json_object_string_add(json, "mt-name",
					       isis_mtid2str(mtid));
		if (r->subtlvs) {
			struct json_object *subtlv_json;
			subtlv_json = json_object_new_object();
			json_object_object_add(json, "subtlvs", subtlv_json);
			format_subtlvs(r->subtlvs, NULL, subtlv_json, 0);
		}
	} else {
		sbuf_push(buf, indent, "%s IP Reachability: %s (Metric: %u)%s",
			  (mtid == ISIS_MT_IPV4_UNICAST) ? "Extended" : "MT",
			  prefix2str(&r->prefix, prefixbuf, sizeof(prefixbuf)),
			  r->metric, r->down ? " Down" : "");
		if (mtid != ISIS_MT_IPV4_UNICAST)
			sbuf_push(buf, 0, " %s", isis_mtid2str(mtid));
		sbuf_push(buf, 0, "\n");

		if (r->subtlvs) {
			sbuf_push(buf, indent, "  Subtlvs:\n");
			format_subtlvs(r->subtlvs, buf, NULL, indent + 4);
		}
	}
}

static void free_item_extended_ip_reach(struct isis_item *i)
{
	struct isis_extended_ip_reach *item =
		(struct isis_extended_ip_reach *)i;
	isis_free_subtlvs(item->subtlvs);
	XFREE(MTYPE_ISIS_TLV, item);
}

static int pack_item_extended_ip_reach(struct isis_item *i, struct stream *s,
				       size_t *min_len)
{
	struct isis_extended_ip_reach *r = (struct isis_extended_ip_reach *)i;
	uint8_t control;

	if (STREAM_WRITEABLE(s) < 5) {
		*min_len = 5;
		return 1;
	}
	stream_putl(s, r->metric);

	control = r->down ? ISIS_EXTENDED_IP_REACH_DOWN : 0;
	control |= r->prefix.prefixlen;
	control |= r->subtlvs ? ISIS_EXTENDED_IP_REACH_SUBTLV : 0;

	stream_putc(s, control);

	if (STREAM_WRITEABLE(s) < (unsigned)PSIZE(r->prefix.prefixlen)) {
		*min_len = 5 + (unsigned)PSIZE(r->prefix.prefixlen);
		return 1;
	}
	stream_put(s, &r->prefix.prefix.s_addr, PSIZE(r->prefix.prefixlen));

	if (r->subtlvs)
		return pack_subtlvs(r->subtlvs, s);
	return 0;
}

static int unpack_item_extended_ip_reach(uint16_t mtid, uint8_t len,
					 struct stream *s, struct sbuf *log,
					 void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;
	struct isis_extended_ip_reach *rv = NULL;
	size_t consume;
	uint8_t control, subtlv_len;
	struct isis_item_list *items;

	if (mtid == ISIS_MT_IPV4_UNICAST) {
		items = &tlvs->extended_ip_reach;
	} else {
		items = isis_get_mt_items(&tlvs->mt_ip_reach, mtid);
	}

	sbuf_push(log, indent, "Unpacking %s IPv4 reachability...\n",
		  (mtid == ISIS_MT_IPV4_UNICAST) ? "extended" : "mt");

	consume = 5;
	if (len < consume) {
		sbuf_push(log, indent,
			  "Not enough data left. (expected 5 or more bytes, got %hhu)\n",
			  len);
		goto out;
	}

	rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->metric = stream_getl(s);
	control = stream_getc(s);
	rv->down = (control & ISIS_EXTENDED_IP_REACH_DOWN);
	rv->prefix.family = AF_INET;
	rv->prefix.prefixlen = control & 0x3f;
	if (rv->prefix.prefixlen > IPV4_MAX_BITLEN) {
		sbuf_push(log, indent, "Prefixlen %u is implausible for IPv4\n",
			  rv->prefix.prefixlen);
		goto out;
	}

	consume += PSIZE(rv->prefix.prefixlen);
	if (len < consume) {
		sbuf_push(log, indent,
			  "Expected %u bytes of prefix, but only %u bytes available.\n",
			  PSIZE(rv->prefix.prefixlen), len - 5);
		goto out;
	}
	stream_get(&rv->prefix.prefix.s_addr, s, PSIZE(rv->prefix.prefixlen));
	in_addr_t orig_prefix = rv->prefix.prefix.s_addr;
	apply_mask_ipv4(&rv->prefix);
	if (orig_prefix != rv->prefix.prefix.s_addr)
		sbuf_push(log, indent + 2,
			  "WARNING: Prefix had hostbits set.\n");
	format_item_extended_ip_reach(mtid, (struct isis_item *)rv, log, NULL,
				      indent + 2);

	if (control & ISIS_EXTENDED_IP_REACH_SUBTLV) {
		consume += 1;
		if (len < consume) {
			sbuf_push(log, indent,
				  "Expected 1 byte of subtlv len, but no more data present.\n");
			goto out;
		}
		subtlv_len = stream_getc(s);

		if (!subtlv_len) {
			sbuf_push(log, indent + 2,
				  "  WARNING: subtlv bit is set, but there are no subtlvs.\n");
		}
		consume += subtlv_len;
		if (len < consume) {
			sbuf_push(log, indent,
				  "Expected %hhu bytes of subtlvs, but only %u bytes available.\n",
				  subtlv_len,
				  len - 6 - PSIZE(rv->prefix.prefixlen));
			goto out;
		}

		rv->subtlvs = isis_alloc_subtlvs(ISIS_CONTEXT_SUBTLV_IP_REACH);
		bool unpacked_known_tlvs = false;

		if (unpack_tlvs(ISIS_CONTEXT_SUBTLV_IP_REACH, subtlv_len, s,
				log, rv->subtlvs, indent + 4, &unpacked_known_tlvs)) {
			goto out;
		}
		if (!unpacked_known_tlvs) {
			isis_free_subtlvs(rv->subtlvs);
			rv->subtlvs = NULL;
		}
	}

	append_item(items, (struct isis_item *)rv);
	return 0;
out:
	if (rv)
		free_item_extended_ip_reach((struct isis_item *)rv);
	return 1;
}

/* Functions related to TLV 137 Dynamic Hostname */

static char *copy_tlv_dynamic_hostname(const char *hostname)
{
	if (!hostname)
		return NULL;

	return XSTRDUP(MTYPE_ISIS_TLV, hostname);
}

static void format_tlv_dynamic_hostname(const char *hostname, struct sbuf *buf,
					struct json_object *json, int indent)
{
	if (!hostname)
		return;

	if (json)
		json_object_string_add(json, "hostname", hostname);
	else
		sbuf_push(buf, indent, "Hostname: %s\n", hostname);
}

static void free_tlv_dynamic_hostname(char *hostname)
{
	XFREE(MTYPE_ISIS_TLV, hostname);
}

static int pack_tlv_dynamic_hostname(const char *hostname, struct stream *s)
{
	if (!hostname)
		return 0;

	uint8_t name_len = strlen(hostname);

	if (STREAM_WRITEABLE(s) < (unsigned)(2 + name_len))
		return 1;

	stream_putc(s, ISIS_TLV_DYNAMIC_HOSTNAME);
	stream_putc(s, name_len);
	stream_put(s, hostname, name_len);
	return 0;
}

static int unpack_tlv_dynamic_hostname(enum isis_tlv_context context,
				       uint8_t tlv_type, uint8_t tlv_len,
				       struct stream *s, struct sbuf *log,
				       void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpacking Dynamic Hostname TLV...\n");
	if (!tlv_len) {
		sbuf_push(log, indent, "WARNING: No hostname included\n");
		return 0;
	}

	if (tlvs->hostname) {
		sbuf_push(log, indent,
			  "WARNING: Hostname present multiple times.\n");
		stream_forward_getp(s, tlv_len);
		return 0;
	}

	tlvs->hostname = XCALLOC(MTYPE_ISIS_TLV, tlv_len + 1);
	stream_get(tlvs->hostname, s, tlv_len);
	tlvs->hostname[tlv_len] = '\0';

	bool sane = true;
	for (uint8_t i = 0; i < tlv_len; i++) {
		if ((unsigned char)tlvs->hostname[i] > 127
		    || !isprint((unsigned char)tlvs->hostname[i])) {
			sane = false;
			tlvs->hostname[i] = '?';
		}
	}
	if (!sane) {
		sbuf_push(
			log, indent,
			"WARNING: Hostname contained non-printable/non-ascii characters.\n");
	}

	return 0;
}

/* Functions related to TLV 140 IPv6 TE Router ID */

static struct in6_addr *copy_tlv_te_router_id_ipv6(const struct in6_addr *id)
{
	if (!id)
		return NULL;

	struct in6_addr *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	memcpy(rv, id, sizeof(*rv));
	return rv;
}

static void format_tlv_te_router_id_ipv6(const struct in6_addr *id,
					 struct sbuf *buf,
					 struct json_object *json, int indent)
{
	if (!id)
		return;

	char addrbuf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, id, addrbuf, sizeof(addrbuf));
	if (json)
		json_object_string_add(json, "ipv6-te-router-id", addrbuf);
	else
		sbuf_push(buf, indent, "IPv6 TE Router ID: %s\n", addrbuf);
}

static void free_tlv_te_router_id_ipv6(struct in6_addr *id)
{
	XFREE(MTYPE_ISIS_TLV, id);
}

static int pack_tlv_te_router_id_ipv6(const struct in6_addr *id,
				      struct stream *s)
{
	if (!id)
		return 0;

	if (STREAM_WRITEABLE(s) < (unsigned)(2 + sizeof(*id)))
		return 1;

	stream_putc(s, ISIS_TLV_TE_ROUTER_ID_IPV6);
	stream_putc(s, IPV6_MAX_BYTELEN);
	stream_put(s, id, IPV6_MAX_BYTELEN);
	return 0;
}

static int unpack_tlv_te_router_id_ipv6(enum isis_tlv_context context,
					uint8_t tlv_type, uint8_t tlv_len,
					struct stream *s, struct sbuf *log,
					void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpacking IPv6 TE Router ID TLV...\n");
	if (tlv_len != IPV6_MAX_BYTELEN) {
		sbuf_push(log, indent, "WARNING: Length invalid\n");
		return 1;
	}

	if (tlvs->te_router_id_ipv6) {
		sbuf_push(
			log, indent,
			"WARNING: IPv6 TE Router ID present multiple times.\n");
		stream_forward_getp(s, tlv_len);
		return 0;
	}

	tlvs->te_router_id_ipv6 = XCALLOC(MTYPE_ISIS_TLV, IPV6_MAX_BYTELEN);
	stream_get(tlvs->te_router_id_ipv6, s, IPV6_MAX_BYTELEN);
	format_tlv_te_router_id_ipv6(tlvs->te_router_id_ipv6, log, NULL, indent + 2);
	return 0;
}


/* Functions related to TLV 150 Spine-Leaf-Extension */

static struct isis_spine_leaf *copy_tlv_spine_leaf(
				const struct isis_spine_leaf *spine_leaf)
{
	if (!spine_leaf)
		return NULL;

	struct isis_spine_leaf *rv = XMALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	memcpy(rv, spine_leaf, sizeof(*rv));

	return rv;
}

static void format_tlv_spine_leaf(const struct isis_spine_leaf *spine_leaf,
				  struct sbuf *buf, struct json_object *json,
				  int indent)
{
	if (!spine_leaf)
		return;

	char aux_buf[255];

	if (json) {
		struct json_object *spine_json;
		spine_json = json_object_new_object();
		json_object_object_add(json, "spine-leaf-extension",
				       spine_json);
		if (spine_leaf->has_tier) {
			snprintfrr(aux_buf, sizeof(aux_buf), "%hhu",
				   spine_leaf->tier);
			json_object_string_add(
				spine_json, "tier",
				(spine_leaf->tier == ISIS_TIER_UNDEFINED)
					? "undefined"
					: aux_buf);
		}
		json_object_string_add(spine_json, "flag-leaf",
				       spine_leaf->is_leaf ? "yes" : "");
		json_object_string_add(spine_json, "flag-spine",
				       spine_leaf->is_spine ? "yes" : "");
		json_object_string_add(spine_json, "flag-backup",
				       spine_leaf->is_backup ? "yes" : "");
	} else {
		sbuf_push(buf, indent, "Spine-Leaf-Extension:\n");
		if (spine_leaf->has_tier) {
			if (spine_leaf->tier == ISIS_TIER_UNDEFINED) {
				sbuf_push(buf, indent, "  Tier: undefined\n");
			} else {
				sbuf_push(buf, indent, "  Tier: %hhu\n",
					  spine_leaf->tier);
			}
		}

		sbuf_push(buf, indent, "  Flags:%s%s%s\n",
			  spine_leaf->is_leaf ? " LEAF" : "",
			  spine_leaf->is_spine ? " SPINE" : "",
			  spine_leaf->is_backup ? " BACKUP" : "");
	}
}

static void free_tlv_spine_leaf(struct isis_spine_leaf *spine_leaf)
{
	XFREE(MTYPE_ISIS_TLV, spine_leaf);
}

#define ISIS_SPINE_LEAF_FLAG_TIER 0x08
#define ISIS_SPINE_LEAF_FLAG_BACKUP 0x04
#define ISIS_SPINE_LEAF_FLAG_SPINE 0x02
#define ISIS_SPINE_LEAF_FLAG_LEAF 0x01

static int pack_tlv_spine_leaf(const struct isis_spine_leaf *spine_leaf,
			       struct stream *s)
{
	if (!spine_leaf)
		return 0;

	uint8_t tlv_len = 2;

	if (STREAM_WRITEABLE(s) < (unsigned)(2 + tlv_len))
		return 1;

	stream_putc(s, ISIS_TLV_SPINE_LEAF_EXT);
	stream_putc(s, tlv_len);

	uint16_t spine_leaf_flags = 0;

	if (spine_leaf->has_tier) {
		spine_leaf_flags |= ISIS_SPINE_LEAF_FLAG_TIER;
		spine_leaf_flags |= spine_leaf->tier << 12;
	}

	if (spine_leaf->is_leaf)
		spine_leaf_flags |= ISIS_SPINE_LEAF_FLAG_LEAF;

	if (spine_leaf->is_spine)
		spine_leaf_flags |= ISIS_SPINE_LEAF_FLAG_SPINE;

	if (spine_leaf->is_backup)
		spine_leaf_flags |= ISIS_SPINE_LEAF_FLAG_BACKUP;

	stream_putw(s, spine_leaf_flags);

	return 0;
}

static int unpack_tlv_spine_leaf(enum isis_tlv_context context,
				 uint8_t tlv_type, uint8_t tlv_len,
				 struct stream *s, struct sbuf *log,
				 void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpacking Spine Leaf Extension TLV...\n");
	if (tlv_len < 2) {
		sbuf_push(log, indent, "WARNING: Unexpected TLV size\n");
		stream_forward_getp(s, tlv_len);
		return 0;
	}

	if (tlvs->spine_leaf) {
		sbuf_push(log, indent,
			  "WARNING: Spine Leaf Extension TLV present multiple times.\n");
		stream_forward_getp(s, tlv_len);
		return 0;
	}

	tlvs->spine_leaf = XCALLOC(MTYPE_ISIS_TLV, sizeof(*tlvs->spine_leaf));

	uint16_t spine_leaf_flags = stream_getw(s);

	if (spine_leaf_flags & ISIS_SPINE_LEAF_FLAG_TIER) {
		tlvs->spine_leaf->has_tier = true;
		tlvs->spine_leaf->tier = spine_leaf_flags >> 12;
	}

	tlvs->spine_leaf->is_leaf = spine_leaf_flags & ISIS_SPINE_LEAF_FLAG_LEAF;
	tlvs->spine_leaf->is_spine = spine_leaf_flags & ISIS_SPINE_LEAF_FLAG_SPINE;
	tlvs->spine_leaf->is_backup = spine_leaf_flags & ISIS_SPINE_LEAF_FLAG_BACKUP;

	stream_forward_getp(s, tlv_len - 2);
	return 0;
}

/* Functions related to TLV 240 P2P Three-Way Adjacency */

const char *isis_threeway_state_name(enum isis_threeway_state state)
{
	switch (state) {
	case ISIS_THREEWAY_DOWN:
		return "Down";
	case ISIS_THREEWAY_INITIALIZING:
		return "Initializing";
	case ISIS_THREEWAY_UP:
		return "Up";
	default:
		return "Invalid!";
	}
}

static struct isis_threeway_adj *copy_tlv_threeway_adj(
				const struct isis_threeway_adj *threeway_adj)
{
	if (!threeway_adj)
		return NULL;

	struct isis_threeway_adj *rv = XMALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	memcpy(rv, threeway_adj, sizeof(*rv));

	return rv;
}

static void
format_tlv_threeway_adj(const struct isis_threeway_adj *threeway_adj,
			struct sbuf *buf, struct json_object *json, int indent)
{
	char sys_id[ISO_SYSID_STRLEN];

	if (!threeway_adj)
		return;

	snprintfrr(sys_id, ISO_SYSID_STRLEN, "%pSY", threeway_adj->neighbor_id);
	if (json) {
		struct json_object *three_json;
		three_json = json_object_new_object();
		json_object_object_add(json, "p2p-three-way-adj", three_json);
		json_object_string_add(
			three_json, "state-name",
			isis_threeway_state_name(threeway_adj->state));
		json_object_int_add(three_json, "state", threeway_adj->state);
		json_object_int_add(three_json, "ext-local-circuit-id",
				    threeway_adj->local_circuit_id);
		if (!threeway_adj->neighbor_set)
			return;
		json_object_string_add(three_json, "neigh-system-id", sys_id);
		json_object_int_add(three_json, "neigh-ext-circuit-id",
				    threeway_adj->neighbor_circuit_id);
	} else {
		sbuf_push(buf, indent, "P2P Three-Way Adjacency:\n");
		sbuf_push(buf, indent, "  State: %s (%d)\n",
			  isis_threeway_state_name(threeway_adj->state),
			  threeway_adj->state);
		sbuf_push(buf, indent, "  Extended Local Circuit ID: %u\n",
			  threeway_adj->local_circuit_id);
		if (!threeway_adj->neighbor_set)
			return;

		sbuf_push(buf, indent, "  Neighbor System ID: %s\n", sys_id);
		sbuf_push(buf, indent, "  Neighbor Extended Circuit ID: %u\n",
			  threeway_adj->neighbor_circuit_id);
	}
}

static void free_tlv_threeway_adj(struct isis_threeway_adj *threeway_adj)
{
	XFREE(MTYPE_ISIS_TLV, threeway_adj);
}

static int pack_tlv_threeway_adj(const struct isis_threeway_adj *threeway_adj,
				  struct stream *s)
{
	if (!threeway_adj)
		return 0;

	uint8_t tlv_len = (threeway_adj->neighbor_set) ? 15 : 5;

	if (STREAM_WRITEABLE(s) < (unsigned)(2 + tlv_len))
		return 1;

	stream_putc(s, ISIS_TLV_THREE_WAY_ADJ);
	stream_putc(s, tlv_len);
	stream_putc(s, threeway_adj->state);
	stream_putl(s, threeway_adj->local_circuit_id);

	if (threeway_adj->neighbor_set) {
		stream_put(s, threeway_adj->neighbor_id, 6);
		stream_putl(s, threeway_adj->neighbor_circuit_id);
	}

	return 0;
}

static int unpack_tlv_threeway_adj(enum isis_tlv_context context,
				       uint8_t tlv_type, uint8_t tlv_len,
				       struct stream *s, struct sbuf *log,
				       void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpacking P2P Three-Way Adjacency TLV...\n");
	if (tlv_len != 5 && tlv_len != 15) {
		sbuf_push(log, indent, "WARNING: Unexpected TLV size\n");
		stream_forward_getp(s, tlv_len);
		return 0;
	}

	if (tlvs->threeway_adj) {
		sbuf_push(log, indent,
			  "WARNING: P2P Three-Way Adjacency TLV present multiple times.\n");
		stream_forward_getp(s, tlv_len);
		return 0;
	}

	tlvs->threeway_adj = XCALLOC(MTYPE_ISIS_TLV, sizeof(*tlvs->threeway_adj));

	tlvs->threeway_adj->state = stream_getc(s);
	tlvs->threeway_adj->local_circuit_id = stream_getl(s);

	if (tlv_len == 15) {
		tlvs->threeway_adj->neighbor_set = true;
		stream_get(tlvs->threeway_adj->neighbor_id, s, 6);
		tlvs->threeway_adj->neighbor_circuit_id = stream_getl(s);
	}

	return 0;
}

/* Functions related to TLVs 236/237 IPv6/MT-IPv6 reach */
static struct isis_item *copy_item_ipv6_reach(struct isis_item *i)
{
	struct isis_ipv6_reach *r = (struct isis_ipv6_reach *)i;
	struct isis_ipv6_reach *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->metric = r->metric;
	rv->down = r->down;
	rv->external = r->external;
	rv->prefix = r->prefix;
	rv->subtlvs = copy_subtlvs(r->subtlvs);

	return (struct isis_item *)rv;
}

static void format_item_ipv6_reach(uint16_t mtid, struct isis_item *i,
				   struct sbuf *buf, struct json_object *json,
				   int indent)
{
	struct isis_ipv6_reach *r = (struct isis_ipv6_reach *)i;
	char prefixbuf[PREFIX2STR_BUFFER];

	if (json) {
		struct json_object *reach_json;
		reach_json = json_object_new_object();
		json_object_object_add(json, "ipv6-reach", reach_json);
		json_object_string_add(reach_json, "mt-id",
				       (mtid == ISIS_MT_IPV4_UNICAST) ? ""
								      : "mt");
		json_object_string_add(
			reach_json, "prefix",
			prefix2str(&r->prefix, prefixbuf, sizeof(prefixbuf)));
		json_object_int_add(reach_json, "metric", r->metric);
		json_object_string_add(reach_json, "down",
				       r->down ? "yes" : "");
		json_object_string_add(reach_json, "external",
				       r->external ? "yes" : "");
		if (mtid != ISIS_MT_IPV4_UNICAST)
			json_object_string_add(reach_json, "mt-name",
					       isis_mtid2str(mtid));
		if (r->subtlvs) {
			struct json_object *subtlvs_json;
			subtlvs_json = json_object_new_object();
			json_object_object_add(json, "subtlvs", subtlvs_json);
			format_subtlvs(r->subtlvs, NULL, subtlvs_json, 0);
		}
	} else {
		sbuf_push(buf, indent,
			  "%sIPv6 Reachability: %s (Metric: %u)%s%s",
			  (mtid == ISIS_MT_IPV4_UNICAST) ? "" : "MT ",
			  prefix2str(&r->prefix, prefixbuf, sizeof(prefixbuf)),
			  r->metric, r->down ? " Down" : "",
			  r->external ? " External" : "");
		if (mtid != ISIS_MT_IPV4_UNICAST)
			sbuf_push(buf, 0, " %s", isis_mtid2str(mtid));
		sbuf_push(buf, 0, "\n");

		if (r->subtlvs) {
			sbuf_push(buf, indent, "  Subtlvs:\n");
			format_subtlvs(r->subtlvs, buf, NULL, indent + 4);
		}
	}
}

static void free_item_ipv6_reach(struct isis_item *i)
{
	struct isis_ipv6_reach *item = (struct isis_ipv6_reach *)i;

	isis_free_subtlvs(item->subtlvs);
	XFREE(MTYPE_ISIS_TLV, item);
}

static int pack_item_ipv6_reach(struct isis_item *i, struct stream *s,
				size_t *min_len)
{
	struct isis_ipv6_reach *r = (struct isis_ipv6_reach *)i;
	uint8_t control;

	if (STREAM_WRITEABLE(s) < 6 + (unsigned)PSIZE(r->prefix.prefixlen)) {
		*min_len = 6 + (unsigned)PSIZE(r->prefix.prefixlen);
		return 1;
	}
	stream_putl(s, r->metric);

	control = r->down ? ISIS_IPV6_REACH_DOWN : 0;
	control |= r->external ? ISIS_IPV6_REACH_EXTERNAL : 0;
	control |= r->subtlvs ? ISIS_IPV6_REACH_SUBTLV : 0;

	stream_putc(s, control);
	stream_putc(s, r->prefix.prefixlen);

	stream_put(s, &r->prefix.prefix.s6_addr, PSIZE(r->prefix.prefixlen));

	if (r->subtlvs)
		return pack_subtlvs(r->subtlvs, s);

	return 0;
}

static int unpack_item_ipv6_reach(uint16_t mtid, uint8_t len, struct stream *s,
				  struct sbuf *log, void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;
	struct isis_ipv6_reach *rv = NULL;
	size_t consume;
	uint8_t control, subtlv_len;
	struct isis_item_list *items;

	if (mtid == ISIS_MT_IPV4_UNICAST) {
		items = &tlvs->ipv6_reach;
	} else {
		items = isis_get_mt_items(&tlvs->mt_ipv6_reach, mtid);
	}

	sbuf_push(log, indent, "Unpacking %sIPv6 reachability...\n",
		  (mtid == ISIS_MT_IPV4_UNICAST) ? "" : "mt ");
	consume = 6;
	if (len < consume) {
		sbuf_push(log, indent,
			  "Not enough data left. (expected 6 or more bytes, got %hhu)\n",
			  len);
		goto out;
	}

	rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->metric = stream_getl(s);
	control = stream_getc(s);
	rv->down = (control & ISIS_IPV6_REACH_DOWN);
	rv->external = (control & ISIS_IPV6_REACH_EXTERNAL);

	rv->prefix.family = AF_INET6;
	rv->prefix.prefixlen = stream_getc(s);
	if (rv->prefix.prefixlen > IPV6_MAX_BITLEN) {
		sbuf_push(log, indent, "Prefixlen %u is implausible for IPv6\n",
			  rv->prefix.prefixlen);
		goto out;
	}

	consume += PSIZE(rv->prefix.prefixlen);
	if (len < consume) {
		sbuf_push(log, indent,
			  "Expected %u bytes of prefix, but only %u bytes available.\n",
			  PSIZE(rv->prefix.prefixlen), len - 6);
		goto out;
	}
	stream_get(&rv->prefix.prefix.s6_addr, s, PSIZE(rv->prefix.prefixlen));
	struct in6_addr orig_prefix = rv->prefix.prefix;

	apply_mask_ipv6(&rv->prefix);
	if (memcmp(&orig_prefix, &rv->prefix.prefix, sizeof(orig_prefix)))
		sbuf_push(log, indent + 2,
			  "WARNING: Prefix had hostbits set.\n");
	format_item_ipv6_reach(mtid, (struct isis_item *)rv, log, NULL, indent + 2);

	if (control & ISIS_IPV6_REACH_SUBTLV) {
		consume += 1;
		if (len < consume) {
			sbuf_push(log, indent,
				  "Expected 1 byte of subtlv len, but no more data persent.\n");
			goto out;
		}
		subtlv_len = stream_getc(s);

		if (!subtlv_len) {
			sbuf_push(log, indent + 2,
				  "  WARNING: subtlv bit set, but there are no subtlvs.\n");
		}
		consume += subtlv_len;
		if (len < consume) {
			sbuf_push(log, indent,
				  "Expected %hhu bytes of subtlvs, but only %u bytes available.\n",
				  subtlv_len,
				  len - 6 - PSIZE(rv->prefix.prefixlen));
			goto out;
		}

		rv->subtlvs = isis_alloc_subtlvs(ISIS_CONTEXT_SUBTLV_IPV6_REACH);
		bool unpacked_known_tlvs = false;

		if (unpack_tlvs(ISIS_CONTEXT_SUBTLV_IPV6_REACH, subtlv_len, s,
				log, rv->subtlvs, indent + 4, &unpacked_known_tlvs)) {
			goto out;
		}
		if (!unpacked_known_tlvs) {
			isis_free_subtlvs(rv->subtlvs);
			rv->subtlvs = NULL;
		}
	}

	append_item(items, (struct isis_item *)rv);
	return 0;
out:
	if (rv)
		free_item_ipv6_reach((struct isis_item *)rv);
	return 1;
}

/* Functions related to TLV 242 Router Capability as per RFC7981 */
static struct isis_router_cap *copy_tlv_router_cap(
			       const struct isis_router_cap *router_cap)
{
	struct isis_router_cap *rv;

	if (!router_cap)
		return NULL;

	rv = XMALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	memcpy(rv, router_cap, sizeof(*rv));

#ifndef FABRICD
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++) {
		struct isis_router_cap_fad *sc_fad;
		struct isis_router_cap_fad *rv_fad;

		sc_fad = router_cap->fads[i];
		if (!sc_fad)
			continue;
		rv_fad = XMALLOC(MTYPE_ISIS_TLV,
				 sizeof(struct isis_router_cap_fad));
		*rv_fad = *sc_fad;
		rv_fad->fad.admin_group_exclude_any.bitmap.data = NULL;
		rv_fad->fad.admin_group_include_any.bitmap.data = NULL;
		rv_fad->fad.admin_group_include_all.bitmap.data = NULL;

		assert(bf_is_inited(
			sc_fad->fad.admin_group_exclude_any.bitmap));
		assert(bf_is_inited(
			sc_fad->fad.admin_group_include_any.bitmap));
		assert(bf_is_inited(
			sc_fad->fad.admin_group_include_all.bitmap));

		admin_group_copy(&rv_fad->fad.admin_group_exclude_any,
				 &sc_fad->fad.admin_group_exclude_any);
		admin_group_copy(&rv_fad->fad.admin_group_include_any,
				 &sc_fad->fad.admin_group_include_any);
		admin_group_copy(&rv_fad->fad.admin_group_include_all,
				 &sc_fad->fad.admin_group_include_all);

		rv->fads[i] = rv_fad;
	}
#endif /* ifndef FABRICD */

	return rv;
}

static void format_tlv_router_cap_json(const struct isis_router_cap *router_cap,
				  struct json_object *json)
{
	char addrbuf[INET_ADDRSTRLEN];

	if (!router_cap)
		return;

	/* Router ID and Flags */
	struct json_object *cap_json;
	cap_json = json_object_new_object();
	json_object_object_add(json, "router-capability", cap_json);
	inet_ntop(AF_INET, &router_cap->router_id, addrbuf, sizeof(addrbuf));
	json_object_string_add(cap_json, "id", addrbuf);
	json_object_string_add(
		cap_json, "flag-d",
		router_cap->flags & ISIS_ROUTER_CAP_FLAG_D ? "1" : "0");
	json_object_string_add(
		cap_json, "flag-s",
		router_cap->flags & ISIS_ROUTER_CAP_FLAG_S ? "1" : "0");

	/* Segment Routing Global Block as per RFC8667 section #3.1 */
	if (router_cap->srgb.range_size != 0) {
		struct json_object *gb_json;
		gb_json = json_object_new_object();
		json_object_object_add(json, "segment-routing-gb", gb_json);
		json_object_string_add(gb_json, "ipv4",
				       IS_SR_IPV4(&router_cap->srgb) ? "1"
								     : "0");
		json_object_string_add(gb_json, "ipv6",
				       IS_SR_IPV6(&router_cap->srgb) ? "1"
								     : "0");
		json_object_int_add(gb_json, "global-block-base",
				    router_cap->srgb.lower_bound);
		json_object_int_add(gb_json, "global-block-range",
				    router_cap->srgb.range_size);
	}

	/* Segment Routing Local Block as per RFC8667 section #3.3 */
	if (router_cap->srlb.range_size != 0) {
		struct json_object *lb_json;
		lb_json = json_object_new_object();
		json_object_object_add(json, "segment-routing-lb", lb_json);
		json_object_int_add(lb_json, "global-block-base",
				    router_cap->srlb.lower_bound);
		json_object_int_add(lb_json, "global-block-range",
				    router_cap->srlb.range_size);
	}

	/* Segment Routing Algorithms as per RFC8667 section #3.2 */
	if (router_cap->algo[0] != SR_ALGORITHM_UNSET) {
		char buf[255];
		struct json_object *alg_json;
		alg_json = json_object_new_object();
		json_object_object_add(json, "segment-routing-algorithm",
				       alg_json);
		for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
			if (router_cap->algo[i] != SR_ALGORITHM_UNSET) {
				snprintfrr(buf, sizeof(buf), "%d", i);
				json_object_string_add(alg_json, buf,
						       router_cap->algo[i] == 0
							       ? "SPF"
							       : "Strict SPF");
			}
	}

	/* Segment Routing Node MSD as per RFC8491 section #2 */
	if (router_cap->msd != 0)
		json_object_int_add(json, "msd", router_cap->msd);
}

static void format_tlv_router_cap(const struct isis_router_cap *router_cap,
				  struct sbuf *buf, int indent)
{
	char addrbuf[INET_ADDRSTRLEN];

	if (!router_cap)
		return;

	/* Router ID and Flags */
	inet_ntop(AF_INET, &router_cap->router_id, addrbuf, sizeof(addrbuf));
	sbuf_push(buf, indent, "Router Capability:");
	sbuf_push(buf, indent, " %s , D:%c, S:%c\n", addrbuf,
		  router_cap->flags & ISIS_ROUTER_CAP_FLAG_D ? '1' : '0',
		  router_cap->flags & ISIS_ROUTER_CAP_FLAG_S ? '1' : '0');

	/* Segment Routing Global Block as per RFC8667 section #3.1 */
	if (router_cap->srgb.range_size != 0)
		sbuf_push(
			buf, indent,
			"  Segment Routing: I:%s V:%s, Global Block Base: %u Range: %u\n",
			IS_SR_IPV4(&router_cap->srgb) ? "1" : "0",
			IS_SR_IPV6(&router_cap->srgb) ? "1" : "0",
			router_cap->srgb.lower_bound,
			router_cap->srgb.range_size);

	/* Segment Routing Local Block as per RFC8667 section #3.3 */
	if (router_cap->srlb.range_size != 0)
		sbuf_push(buf, indent, "  SR Local Block Base: %u Range: %u\n",
			  router_cap->srlb.lower_bound,
			  router_cap->srlb.range_size);

	/* Segment Routing Algorithms as per RFC8667 section #3.2 */
	if (router_cap->algo[0] != SR_ALGORITHM_UNSET) {
		sbuf_push(buf, indent, "  SR Algorithm:\n");
		for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
			if (router_cap->algo[i] != SR_ALGORITHM_UNSET)
				sbuf_push(buf, indent, "    %u: %s\n", i,
					  sr_algorithm_string(
						  router_cap->algo[i]));
	}

	/* Segment Routing Node MSD as per RFC8491 section #2 */
	if (router_cap->msd != 0)
		sbuf_push(buf, indent, "  Node Maximum SID Depth: %u\n",
			  router_cap->msd);

#ifndef FABRICD
	/* Flex-Algo */
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++) {
		char admin_group_buf[ADMIN_GROUP_PRINT_MAX_SIZE];
		int indent2;
		struct admin_group *admin_group;
		struct isis_router_cap_fad *fad;

		fad = router_cap->fads[i];
		if (!fad)
			continue;

		sbuf_push(buf, indent, "  Flex-Algo Definition: %d\n",
			  fad->fad.algorithm);
		sbuf_push(buf, indent, "    Metric-Type: %d\n",
			  fad->fad.metric_type);
		sbuf_push(buf, indent, "    Calc-Type: %d\n",
			  fad->fad.calc_type);
		sbuf_push(buf, indent, "    Priority: %d\n", fad->fad.priority);

		indent2 = indent + strlen("    Exclude-Any: ");
		admin_group = &fad->fad.admin_group_exclude_any;
		sbuf_push(buf, indent, "    Exclude-Any: ");
		sbuf_push(buf, 0, "%s\n",
			  admin_group_string(admin_group_buf,
					     ADMIN_GROUP_PRINT_MAX_SIZE,
					     indent2, admin_group));

		indent2 = indent + strlen("    Include-Any: ");
		admin_group = &fad->fad.admin_group_include_any;
		sbuf_push(buf, indent, "    Include-Any: ");
		sbuf_push(buf, 0, "%s\n",
			  admin_group_string(admin_group_buf,
					     ADMIN_GROUP_PRINT_MAX_SIZE,
					     indent2, admin_group));

		indent2 = indent + strlen("    Include-All: ");
		admin_group = &fad->fad.admin_group_include_all;
		sbuf_push(buf, indent, "    Include-All: ");
		sbuf_push(buf, 0, "%s\n",
			  admin_group_string(admin_group_buf,
					     ADMIN_GROUP_PRINT_MAX_SIZE,
					     indent2, admin_group));

		sbuf_push(buf, indent, "    M-Flag: %c\n",
			  CHECK_FLAG(fad->fad.flags, FAD_FLAG_M) ? '1' : '0');

		if (fad->fad.flags != 0 && fad->fad.flags != FAD_FLAG_M)
			sbuf_push(buf, indent, "    Flags: 0x%x\n",
				  fad->fad.flags);
		if (fad->fad.exclude_srlg)
			sbuf_push(buf, indent, "    Exclude SRLG: Enabled\n");
		if (fad->fad.unsupported_subtlv)
			sbuf_push(buf, indent,
				  "    Got an unsupported sub-TLV: Yes\n");
	}
#endif /* ifndef FABRICD */

	/* SRv6 Flags as per RFC 9352 section #2 */
	if (router_cap->srv6_cap.is_srv6_capable)
		sbuf_push(buf, indent, "  SRv6: O:%s\n",
			  SUPPORTS_SRV6_OAM(&router_cap->srv6_cap) ? "1" : "0");
}

static void free_tlv_router_cap(struct isis_router_cap *router_cap)
{
	if (!router_cap)
		return;

#ifndef FABRICD
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++) {
		struct isis_router_cap_fad *fad;

		fad = router_cap->fads[i];
		if (!fad)
			continue;
		admin_group_term(&fad->fad.admin_group_exclude_any);
		admin_group_term(&fad->fad.admin_group_include_any);
		admin_group_term(&fad->fad.admin_group_include_all);
		XFREE(MTYPE_ISIS_TLV, fad);
	}
#endif /* ifndef FABRICD */

	XFREE(MTYPE_ISIS_TLV, router_cap);
}

#ifndef FABRICD
static size_t
isis_router_cap_fad_sub_tlv_len(const struct isis_router_cap_fad *fad)
{
	size_t sz = ISIS_SUBTLV_FAD_MIN_SIZE;
	uint32_t admin_group_length;

	admin_group_length =
		admin_group_nb_words(&fad->fad.admin_group_exclude_any);
	if (admin_group_length)
		sz += sizeof(uint32_t) * admin_group_length + 2;

	admin_group_length =
		admin_group_nb_words(&fad->fad.admin_group_include_any);
	if (admin_group_length)
		sz += sizeof(uint32_t) * admin_group_length + 2;

	admin_group_length =
		admin_group_nb_words(&fad->fad.admin_group_include_all);
	if (admin_group_length)
		sz += sizeof(uint32_t) * admin_group_length + 2;

	if (fad->fad.flags != 0)
		sz += ISIS_SUBTLV_FAD_SUBSUBTLV_FLAGS_SIZE + 2;

	/* TODO: add exclude SRLG sub-sub-TLV length when supported */

	return sz;
}
#endif /* ifndef FABRICD */

static size_t isis_router_cap_tlv_size(const struct isis_router_cap *router_cap)
{
	size_t sz = 2 + ISIS_ROUTER_CAP_SIZE;
#ifndef FABRICD
	size_t fad_sz;
#endif /* ifndef FABRICD */
	int nb_algo, nb_msd;

	if ((router_cap->srgb.range_size != 0) &&
	    (router_cap->srgb.lower_bound != 0)) {
		sz += 2 + ISIS_SUBTLV_SID_LABEL_RANGE_SIZE;
		sz += 2 + ISIS_SUBTLV_SID_LABEL_SIZE;

		nb_algo = isis_tlvs_sr_algo_count(router_cap);
		if (nb_algo != 0)
			sz += 2 + nb_algo;

		if ((router_cap->srlb.range_size != 0) &&
		    (router_cap->srlb.lower_bound != 0)) {
			sz += 2 + ISIS_SUBTLV_SID_LABEL_RANGE_SIZE;
			sz += 2 + ISIS_SUBTLV_SID_LABEL_SIZE;
		}

		if (router_cap->msd != 0)
			sz += 2 + ISIS_SUBTLV_NODE_MSD_SIZE;
	}

#ifndef FABRICD
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++) {
		if (!router_cap->fads[i])
			continue;
		fad_sz = 2 +
			 isis_router_cap_fad_sub_tlv_len(router_cap->fads[i]);
		if (((sz + fad_sz) % 256) < (sz % 256))
			sz += 2 + ISIS_ROUTER_CAP_SIZE + fad_sz;
		else
			sz += fad_sz;
	}
#endif /* ifndef FABRICD */

	if (router_cap->srv6_cap.is_srv6_capable) {
		sz += ISIS_SUBTLV_TYPE_FIELD_SIZE +
		      ISIS_SUBTLV_LENGTH_FIELD_SIZE +
		      ISIS_SUBTLV_SRV6_CAPABILITIES_SIZE;

		nb_algo = isis_tlvs_sr_algo_count(router_cap);
		if (nb_algo != 0)
			sz += ISIS_SUBTLV_TYPE_FIELD_SIZE +
			      ISIS_SUBTLV_LENGTH_FIELD_SIZE + nb_algo;

		nb_msd = router_cap->srv6_msd.max_seg_left_msd +
			 router_cap->srv6_msd.max_end_pop_msd +
			 router_cap->srv6_msd.max_h_encaps_msd +
			 router_cap->srv6_msd.max_end_d_msd;
		if (nb_msd != 0)
			sz += ISIS_SUBTLV_TYPE_FIELD_SIZE +
			      ISIS_SUBTLV_LENGTH_FIELD_SIZE +
			      (ISIS_SUBTLV_NODE_MSD_TYPE_SIZE +
			       ISIS_SUBTLV_NODE_MSD_VALUE_SIZE) *
				      nb_msd;
	}

	return sz;
}

static int pack_tlv_router_cap(const struct isis_router_cap *router_cap,
			       struct stream *s)
{
	size_t tlv_len, len_pos;
	uint8_t nb_algo;
	size_t subtlv_len, subtlv_len_pos;
	bool sr_algo_subtlv_present = false;

	if (!router_cap)
		return 0;

	if (STREAM_WRITEABLE(s) < isis_router_cap_tlv_size(router_cap))
		return 1;

	/* Add Router Capability TLV 242 with Router ID and Flags */
	stream_putc(s, ISIS_TLV_ROUTER_CAPABILITY);
	len_pos = stream_get_endp(s);
	stream_putc(s, 0); /* Real length will be adjusted later */
	stream_put_ipv4(s, router_cap->router_id.s_addr);
	stream_putc(s, router_cap->flags);

	/* Add SRGB if set as per RFC8667 section #3.1 */
	if ((router_cap->srgb.range_size != 0)
	    && (router_cap->srgb.lower_bound != 0)) {
		stream_putc(s, ISIS_SUBTLV_SID_LABEL_RANGE);
		stream_putc(s, ISIS_SUBTLV_SID_LABEL_RANGE_SIZE);
		stream_putc(s, router_cap->srgb.flags);
		stream_put3(s, router_cap->srgb.range_size);
		stream_putc(s, ISIS_SUBTLV_SID_LABEL);
		stream_putc(s, ISIS_SUBTLV_SID_LABEL_SIZE);
		stream_put3(s, router_cap->srgb.lower_bound);

		/* Then SR Algorithm if set as per RFC8667 section #3.2 */
		nb_algo = isis_tlvs_sr_algo_count(router_cap);
		if (nb_algo > 0) {
			stream_putc(s, ISIS_SUBTLV_ALGORITHM);
			stream_putc(s, nb_algo);
			for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
				if (router_cap->algo[i] != SR_ALGORITHM_UNSET)
					stream_putc(s, router_cap->algo[i]);
			sr_algo_subtlv_present = true;
		}

		/* Local Block if defined as per RFC8667 section #3.3 */
		if ((router_cap->srlb.range_size != 0)
		    && (router_cap->srlb.lower_bound != 0)) {
			stream_putc(s, ISIS_SUBTLV_SRLB);
			stream_putc(s, ISIS_SUBTLV_SID_LABEL_RANGE_SIZE);
			/* No Flags are defined for SRLB */
			stream_putc(s, 0);
			stream_put3(s, router_cap->srlb.range_size);
			stream_putc(s, ISIS_SUBTLV_SID_LABEL);
			stream_putc(s, ISIS_SUBTLV_SID_LABEL_SIZE);
			stream_put3(s, router_cap->srlb.lower_bound);
		}

		/* And finish with MSD if set as per RFC8491 section #2 */
		if (router_cap->msd != 0) {
			stream_putc(s, ISIS_SUBTLV_NODE_MSD);
			stream_putc(s, ISIS_SUBTLV_NODE_MSD_SIZE);
			stream_putc(s, MSD_TYPE_BASE_MPLS_IMPOSITION);
			stream_putc(s, router_cap->msd);
		}
	}

#ifndef FABRICD
	/* Flex Algo Definitions */
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++) {
		struct isis_router_cap_fad *fad;
		size_t subtlv_len;
		struct admin_group *ag;
		uint32_t admin_group_length;

		fad = router_cap->fads[i];
		if (!fad)
			continue;

		subtlv_len = isis_router_cap_fad_sub_tlv_len(fad);

		if ((stream_get_endp(s) - len_pos - 1) > 250) {
			/* Adjust TLV length which depends on subTLVs presence
			 */
			tlv_len = stream_get_endp(s) - len_pos - 1;
			stream_putc_at(s, len_pos, tlv_len);

			/* Add Router Capability TLV 242 with Router ID and
			 * Flags
			 */
			stream_putc(s, ISIS_TLV_ROUTER_CAPABILITY);
			/* Real length will be adjusted later */
			len_pos = stream_get_endp(s);
			stream_putc(s, 0);
			stream_put_ipv4(s, router_cap->router_id.s_addr);
			stream_putc(s, router_cap->flags);
		}

		stream_putc(s, ISIS_SUBTLV_FAD);
		stream_putc(s, subtlv_len); /* length will be filled later */

		stream_putc(s, fad->fad.algorithm);
		stream_putc(s, fad->fad.metric_type);
		stream_putc(s, fad->fad.calc_type);
		stream_putc(s, fad->fad.priority);

		ag = &fad->fad.admin_group_exclude_any;
		admin_group_length = admin_group_nb_words(ag);
		if (admin_group_length) {
			stream_putc(s, ISIS_SUBTLV_FAD_SUBSUBTLV_EXCAG);
			stream_putc(s, sizeof(uint32_t) * admin_group_length);
			for (size_t i = 0; i < admin_group_length; i++)
				stream_putl(s, admin_group_get_offset(ag, i));
		}

		ag = &fad->fad.admin_group_include_any;
		admin_group_length = admin_group_nb_words(ag);
		if (admin_group_length) {
			stream_putc(s, ISIS_SUBTLV_FAD_SUBSUBTLV_INCANYAG);
			stream_putc(s, sizeof(uint32_t) * admin_group_length);
			for (size_t i = 0; i < admin_group_length; i++)
				stream_putl(s, admin_group_get_offset(ag, i));
		}

		ag = &fad->fad.admin_group_include_all;
		admin_group_length = admin_group_nb_words(ag);
		if (admin_group_length) {
			stream_putc(s, ISIS_SUBTLV_FAD_SUBSUBTLV_INCALLAG);
			stream_putc(s, sizeof(uint32_t) * admin_group_length);
			for (size_t i = 0; i < admin_group_length; i++)
				stream_putl(s, admin_group_get_offset(ag, i));
		}

		if (fad->fad.flags != 0) {
			stream_putc(s, ISIS_SUBTLV_FAD_SUBSUBTLV_FLAGS);
			stream_putc(s, ISIS_SUBTLV_FAD_SUBSUBTLV_FLAGS_SIZE);
			stream_putc(s, fad->fad.flags);
		}
	}
#endif /* ifndef FABRICD */

	/* Add SRv6 capabilities if set as per RFC 9352 section #2 */
	if (router_cap->srv6_cap.is_srv6_capable) {
		stream_putc(s, ISIS_SUBTLV_SRV6_CAPABILITIES);
		stream_putc(s, ISIS_SUBTLV_SRV6_CAPABILITIES_SIZE);
		stream_putw(s, router_cap->srv6_cap.flags);

		/*
		 * Then add SR Algorithm if set and if we haven't already
		 * added it when we processed SR-MPLS related Sub-TLVs as
		 * per RFC 9352 section #3
		 */
		if (!sr_algo_subtlv_present) {
			nb_algo = isis_tlvs_sr_algo_count(router_cap);
			if (nb_algo > 0) {
				stream_putc(s, ISIS_SUBTLV_ALGORITHM);
				stream_putc(s, nb_algo);
				for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
					if (router_cap->algo[i] !=
					    SR_ALGORITHM_UNSET)
						stream_putc(s,
							    router_cap->algo[i]);
			}
		}

		/* And finish with MSDs if set as per RFC 9352 section #4 */
		if (router_cap->srv6_msd.max_seg_left_msd +
			    router_cap->srv6_msd.max_end_pop_msd +
			    router_cap->srv6_msd.max_h_encaps_msd +
			    router_cap->srv6_msd.max_end_d_msd !=
		    0) {
			stream_putc(s, ISIS_SUBTLV_NODE_MSD);

			subtlv_len_pos = stream_get_endp(s);
			/* Put 0 as Sub-TLV length for now, real length will be
			 * adjusted later */
			stream_putc(s, 0);

			/* RFC 9352 section #4.1 */
			if (router_cap->srv6_msd.max_seg_left_msd != 0) {
				stream_putc(s, ISIS_SUBTLV_SRV6_MAX_SL_MSD);
				stream_putc(
					s,
					router_cap->srv6_msd.max_seg_left_msd);
			}

			/* RFC 9352 section #4.2 */
			if (router_cap->srv6_msd.max_end_pop_msd != 0) {
				stream_putc(s,
					    ISIS_SUBTLV_SRV6_MAX_END_POP_MSD);
				stream_putc(
					s,
					router_cap->srv6_msd.max_end_pop_msd);
			}

			/* RFC 9352 section #4.3 */
			if (router_cap->srv6_msd.max_h_encaps_msd != 0) {
				stream_putc(s,
					    ISIS_SUBTLV_SRV6_MAX_H_ENCAPS_MSD);
				stream_putc(
					s,
					router_cap->srv6_msd.max_h_encaps_msd);
			}

			/* RFC 9352 section #4.4 */
			if (router_cap->srv6_msd.max_end_d_msd != 0) {
				stream_putc(s, ISIS_SUBTLV_SRV6_MAX_END_D_MSD);
				stream_putc(s,
					    router_cap->srv6_msd.max_end_d_msd);
			}

			/* Adjust Node MSD Sub-TLV length which depends on MSDs
			 * presence */
			subtlv_len = stream_get_endp(s) - subtlv_len_pos - 1;
			stream_putc_at(s, subtlv_len_pos, subtlv_len);
		}
	}

	/* Adjust TLV length which depends on subTLVs presence */
	tlv_len = stream_get_endp(s) - len_pos - 1;
	stream_putc_at(s, len_pos, tlv_len);

	return 0;
}

static int unpack_tlv_router_cap(enum isis_tlv_context context,
				 uint8_t tlv_type, uint8_t tlv_len,
				 struct stream *s, struct sbuf *log, void *dest,
				 int indent)
{
	struct isis_tlvs *tlvs = dest;
	struct isis_router_cap *rcap;
	uint8_t type;
	uint8_t length;
	uint8_t subtlv_len;
	uint8_t size;
	int num_msd;

	sbuf_push(log, indent, "Unpacking Router Capability TLV...\n");
	if (tlv_len < ISIS_ROUTER_CAP_SIZE) {
		sbuf_push(log, indent, "WARNING: Unexpected TLV size\n");
		stream_forward_getp(s, tlv_len);
		return 0;
	}

	if (tlvs->router_cap)
		/* Multiple Router Capability found */
		rcap = tlvs->router_cap;
	else {
		/* Allocate router cap structure and initialize SR Algorithms */
		rcap = XCALLOC(MTYPE_ISIS_TLV, sizeof(struct isis_router_cap));
		for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
			rcap->algo[i] = SR_ALGORITHM_UNSET;
	}

	/* Get Router ID and Flags */
	rcap->router_id.s_addr = stream_get_ipv4(s);
	rcap->flags = stream_getc(s);

	/* Parse remaining part of the TLV if present */
	subtlv_len = tlv_len - ISIS_ROUTER_CAP_SIZE;
	while (subtlv_len > 2) {
#ifndef FABRICD
		struct isis_router_cap_fad *fad;
		uint8_t subsubtlvs_len;
#endif /* ifndef FABRICD */
		uint8_t msd_type;

		type = stream_getc(s);
		length = stream_getc(s);

		if (length > STREAM_READABLE(s) || length > subtlv_len - 2) {
			sbuf_push(
				log, indent,
				"WARNING: Router Capability subTLV length too large compared to expected size\n");
			stream_forward_getp(s, STREAM_READABLE(s));
			XFREE(MTYPE_ISIS_TLV, rcap);
			return 0;
		}

		switch (type) {
		case ISIS_SUBTLV_SID_LABEL_RANGE:
			/* Check that SRGB is correctly formated */
			if (length < SUBTLV_RANGE_LABEL_SIZE
			    || length > SUBTLV_RANGE_INDEX_SIZE) {
				stream_forward_getp(s, length);
				break;
			}
			/* Only one SRGB is supported. Skip subsequent one */
			if (rcap->srgb.range_size != 0) {
				stream_forward_getp(s, length);
				break;
			}
			rcap->srgb.flags = stream_getc(s);
			rcap->srgb.range_size = stream_get3(s);
			/* Skip Type and get Length of SID Label */
			stream_getc(s);
			size = stream_getc(s);

			if (size == ISIS_SUBTLV_SID_LABEL_SIZE
			    && length != SUBTLV_RANGE_LABEL_SIZE) {
				stream_forward_getp(s, length - 6);
				break;
			}

			if (size == ISIS_SUBTLV_SID_INDEX_SIZE
			    && length != SUBTLV_RANGE_INDEX_SIZE) {
				stream_forward_getp(s, length - 6);
				break;
			}

			if (size == ISIS_SUBTLV_SID_LABEL_SIZE) {
				rcap->srgb.lower_bound = stream_get3(s);
			} else if (size == ISIS_SUBTLV_SID_INDEX_SIZE) {
				rcap->srgb.lower_bound = stream_getl(s);
			} else {
				stream_forward_getp(s, length - 6);
				break;
			}

			/* SRGB sanity checks. */
			if (rcap->srgb.range_size == 0
			    || (rcap->srgb.lower_bound <= MPLS_LABEL_RESERVED_MAX)
			    || ((rcap->srgb.lower_bound + rcap->srgb.range_size - 1)
				> MPLS_LABEL_UNRESERVED_MAX)) {
				sbuf_push(log, indent, "Invalid label range. Reset SRGB\n");
				rcap->srgb.lower_bound = 0;
				rcap->srgb.range_size = 0;
			}
			/* Only one range is supported. Skip subsequent one */
			size = length - (size + SUBTLV_SR_BLOCK_SIZE);
			if (size > 0)
				stream_forward_getp(s, size);

			break;
		case ISIS_SUBTLV_ALGORITHM:
			if (length == 0)
				break;

			for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
				rcap->algo[i] = SR_ALGORITHM_UNSET;

			for (int i = 0; i < length; i++) {
				uint8_t algo;

				algo = stream_getc(s);
				rcap->algo[algo] = algo;
			}
			break;
		case ISIS_SUBTLV_SRLB:
			/* Check that SRLB is correctly formated */
			if (length < SUBTLV_RANGE_LABEL_SIZE
			    || length > SUBTLV_RANGE_INDEX_SIZE) {
				stream_forward_getp(s, length);
				break;
			}
			/* RFC 8667 section #3.3: Only one SRLB is authorized */
			if (rcap->srlb.range_size != 0) {
				stream_forward_getp(s, length);
				break;
			}
			/* Ignore Flags which are not defined */
			stream_getc(s);
			rcap->srlb.range_size = stream_get3(s);
			/* Skip Type and get Length of SID Label */
			stream_getc(s);
			size = stream_getc(s);

			if (size == ISIS_SUBTLV_SID_LABEL_SIZE
			    && length != SUBTLV_RANGE_LABEL_SIZE) {
				stream_forward_getp(s, length - 6);
				break;
			}

			if (size == ISIS_SUBTLV_SID_INDEX_SIZE
			    && length != SUBTLV_RANGE_INDEX_SIZE) {
				stream_forward_getp(s, length - 6);
				break;
			}

			if (size == ISIS_SUBTLV_SID_LABEL_SIZE) {
				rcap->srlb.lower_bound = stream_get3(s);
			} else if (size == ISIS_SUBTLV_SID_INDEX_SIZE) {
				rcap->srlb.lower_bound = stream_getl(s);
			} else {
				stream_forward_getp(s, length - 6);
				break;
			}

			/* SRLB sanity checks. */
			if (rcap->srlb.range_size == 0
			    || (rcap->srlb.lower_bound <= MPLS_LABEL_RESERVED_MAX)
			    || ((rcap->srlb.lower_bound + rcap->srlb.range_size - 1)
				> MPLS_LABEL_UNRESERVED_MAX)) {
				sbuf_push(log, indent, "Invalid label range. Reset SRLB\n");
				rcap->srlb.lower_bound = 0;
				rcap->srlb.range_size = 0;
			}
			/* Only one range is supported. Skip subsequent one */
			size = length - (size + SUBTLV_SR_BLOCK_SIZE);
			if (size > 0)
				stream_forward_getp(s, size);

			break;
		case ISIS_SUBTLV_NODE_MSD:
			sbuf_push(log, indent,
				  "Unpacking Node MSD sub-TLV...\n");

			/* Check that MSD is correctly formated */
			if (length % 2) {
				sbuf_push(
					log, indent,
					"WARNING: Unexpected MSD sub-TLV length\n");
				stream_forward_getp(s, length);
				break;
			}

			/* Get the number of MSDs carried in the value field of
			 * the Node MSD sub-TLV. The value field consists of one
			 * or more pairs of a 1-octet MSD-Type and 1-octet
			 * MSD-Value */
			num_msd = length / 2;

			/* Unpack MSDs */
			for (int i = 0; i < num_msd; i++) {
				msd_type = stream_getc(s);

				switch (msd_type) {
				case MSD_TYPE_BASE_MPLS_IMPOSITION:
					/* BMI-MSD type as per RFC 8491 */
					rcap->msd = stream_getc(s);
					break;
				case ISIS_SUBTLV_SRV6_MAX_SL_MSD:
					/* SRv6 Maximum Segments Left MSD Type
					 * as per RFC 9352 section #4.1 */
					rcap->srv6_msd.max_seg_left_msd =
						stream_getc(s);
					break;
				case ISIS_SUBTLV_SRV6_MAX_END_POP_MSD:
					/* SRv6 Maximum End Pop MSD Type as per
					 * RFC 9352 section #4.2 */
					rcap->srv6_msd.max_end_pop_msd =
						stream_getc(s);
					break;
				case ISIS_SUBTLV_SRV6_MAX_H_ENCAPS_MSD:
					/* SRv6 Maximum H.Encaps MSD Type as per
					 * RFC 9352 section #4.3 */
					rcap->srv6_msd.max_h_encaps_msd =
						stream_getc(s);
					break;
				case ISIS_SUBTLV_SRV6_MAX_END_D_MSD:
					/* SRv6 Maximum End D MSD Type as per
					 * RFC 9352 section #4.4 */
					rcap->srv6_msd.max_end_d_msd =
						stream_getc(s);
					break;
				default:
					/* Unknown MSD, let's skip it */
					sbuf_push(
						log, indent,
						"WARNING: Skipping unknown MSD Type %hhu (1 byte)\n",
						msd_type);
					stream_forward_getp(s, 1);
				}
			}
			break;
#ifndef FABRICD
		case ISIS_SUBTLV_FAD:
			fad = XCALLOC(MTYPE_ISIS_TLV,
				      sizeof(struct isis_router_cap_fad));
			fad->fad.algorithm = stream_getc(s);
			fad->fad.metric_type = stream_getc(s);
			fad->fad.calc_type = stream_getc(s);
			fad->fad.priority = stream_getc(s);
			rcap->fads[fad->fad.algorithm] = fad;
			admin_group_init(&fad->fad.admin_group_exclude_any);
			admin_group_init(&fad->fad.admin_group_include_any);
			admin_group_init(&fad->fad.admin_group_include_all);

			subsubtlvs_len = length - 4;
			while (subsubtlvs_len > 2) {
				struct admin_group *ag;
				uint8_t subsubtlv_type;
				uint8_t subsubtlv_len;
				uint32_t v;
				int n_ag, i;

				subsubtlv_type = stream_getc(s);
				subsubtlv_len = stream_getc(s);

				switch (subsubtlv_type) {
				case ISIS_SUBTLV_FAD_SUBSUBTLV_EXCAG:
					ag = &fad->fad.admin_group_exclude_any;
					n_ag = subsubtlv_len / sizeof(uint32_t);
					for (i = 0; i < n_ag; i++) {
						v = stream_getl(s);
						admin_group_bulk_set(ag, v, i);
					}
					break;
				case ISIS_SUBTLV_FAD_SUBSUBTLV_INCANYAG:
					ag = &fad->fad.admin_group_include_any;
					n_ag = subsubtlv_len / sizeof(uint32_t);
					for (i = 0; i < n_ag; i++) {
						v = stream_getl(s);
						admin_group_bulk_set(ag, v, i);
					}
					break;
				case ISIS_SUBTLV_FAD_SUBSUBTLV_INCALLAG:
					ag = &fad->fad.admin_group_include_all;
					n_ag = subsubtlv_len / sizeof(uint32_t);
					for (i = 0; i < n_ag; i++) {
						v = stream_getl(s);
						admin_group_bulk_set(ag, v, i);
					}
					break;
				case ISIS_SUBTLV_FAD_SUBSUBTLV_FLAGS:
					if (subsubtlv_len == 0)
						break;

					fad->fad.flags = stream_getc(s);
					for (i = subsubtlv_len - 1; i > 0; --i)
						stream_getc(s);
					break;
				case ISIS_SUBTLV_FAD_SUBSUBTLV_ESRLG:
					fad->fad.exclude_srlg = true;
					stream_forward_getp(s, subsubtlv_len);
					break;
				default:
					sbuf_push(
						log, indent,
						"Received an unsupported Flex-Algo sub-TLV type %u\n",
						subsubtlv_type);
					fad->fad.unsupported_subtlv = true;
					stream_forward_getp(s, subsubtlv_len);
					break;
				}
				subsubtlvs_len -= 2 + subsubtlv_len;
			}
			break;
#endif /* ifndef FABRICD */
		case ISIS_SUBTLV_SRV6_CAPABILITIES:
			sbuf_push(log, indent,
				  "Unpacking SRv6 Capabilities sub-TLV...\n");
			/* Check that SRv6 capabilities sub-TLV is correctly
			 * formated */
			if (length < ISIS_SUBTLV_SRV6_CAPABILITIES_SIZE) {
				sbuf_push(
					log, indent,
					"WARNING: Unexpected SRv6 Capabilities sub-TLV size (expected %d or more bytes, got %hhu)\n",
					ISIS_SUBTLV_SRV6_CAPABILITIES_SIZE,
					length);
				stream_forward_getp(s, length);
				break;
			}
			/* Only one SRv6 capabilities is supported. Skip
			 * subsequent one */
			if (rcap->srv6_cap.is_srv6_capable) {
				sbuf_push(
					log, indent,
					"WARNING: SRv6 Capabilities sub-TLV present multiple times, ignoring.\n");
				stream_forward_getp(s, length);
				break;
			}
			rcap->srv6_cap.is_srv6_capable = true;
			rcap->srv6_cap.flags = stream_getw(s);

			/* The SRv6 Capabilities Sub-TLV may contain optional
			 * Sub-Sub-TLVs, as per RFC 9352 section #2.
			 * Skip any Sub-Sub-TLV contained in the SRv6
			 * Capabilities Sub-TLV that is not currently supported
			 * by IS-IS.
			 */
			if (length > ISIS_SUBTLV_SRV6_CAPABILITIES_SIZE)
				sbuf_push(
					log, indent,
					"Skipping unknown sub-TLV (%hhu bytes)\n",
					length);
			stream_forward_getp(
				s, length - ISIS_SUBTLV_SRV6_CAPABILITIES_SIZE);

			break;
		default:
			stream_forward_getp(s, length);
			break;
		}
		subtlv_len = subtlv_len - length - 2;
	}
	tlvs->router_cap = rcap;
	return 0;
}

/* Functions related to TLV 10 Authentication */
static struct isis_item *copy_item_auth(struct isis_item *i)
{
	struct isis_auth *auth = (struct isis_auth *)i;
	struct isis_auth *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->type = auth->type;
	rv->length = auth->length;
	memcpy(rv->value, auth->value, sizeof(rv->value));
	return (struct isis_item *)rv;
}

static void format_item_auth(uint16_t mtid, struct isis_item *i,
			     struct sbuf *buf, struct json_object *json,
			     int indent)
{
	struct isis_auth *auth = (struct isis_auth *)i;
	char obuf[768];

	if (json)
		json_object_string_add(json, "test-auth", "ok");
	else
		sbuf_push(buf, indent, "Authentication:\n");
	switch (auth->type) {
	case ISIS_PASSWD_TYPE_CLEARTXT:
		zlog_sanitize(obuf, sizeof(obuf), auth->value, auth->length);
		if (json)
			json_object_string_add(json, "auth-pass", obuf);
		else
			sbuf_push(buf, indent, "  Password: %s\n", obuf);
		break;
	case ISIS_PASSWD_TYPE_HMAC_MD5:
		for (unsigned int j = 0; j < 16; j++) {
			snprintf(obuf + 2 * j, sizeof(obuf) - 2 * j, "%02hhx",
				 auth->value[j]);
		}
		if (json)
			json_object_string_add(json, "auth-hmac-md5", obuf);
		else
			sbuf_push(buf, indent, "  HMAC-MD5: %s\n", obuf);
		break;
	default:
		if (json)
			json_object_int_add(json, "auth-unknown", auth->type);
		else
			sbuf_push(buf, indent, "  Unknown (%hhu)\n",
				  auth->type);
		break;
	}
}

static void free_item_auth(struct isis_item *i)
{
	XFREE(MTYPE_ISIS_TLV, i);
}

static int pack_item_auth(struct isis_item *i, struct stream *s,
			  size_t *min_len)
{
	struct isis_auth *auth = (struct isis_auth *)i;

	if (STREAM_WRITEABLE(s) < 1) {
		*min_len = 1;
		return 1;
	}
	stream_putc(s, auth->type);

	switch (auth->type) {
	case ISIS_PASSWD_TYPE_CLEARTXT:
		if (STREAM_WRITEABLE(s) < auth->length) {
			*min_len = 1 + auth->length;
			return 1;
		}
		stream_put(s, auth->passwd, auth->length);
		break;
	case ISIS_PASSWD_TYPE_HMAC_MD5:
		if (STREAM_WRITEABLE(s) < 16) {
			*min_len = 1 + 16;
			return 1;
		}
		auth->offset = stream_get_endp(s);
		stream_put(s, NULL, 16);
		break;
	default:
		return 1;
	}

	return 0;
}

static int unpack_item_auth(uint16_t mtid, uint8_t len, struct stream *s,
			    struct sbuf *log, void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;

	sbuf_push(log, indent, "Unpack Auth TLV...\n");
	if (len < 1) {
		sbuf_push(
			log, indent,
			"Not enough data left.(Expected 1 bytes of auth type, got %hhu)\n",
			len);
		return 1;
	}

	struct isis_auth *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->type = stream_getc(s);
	rv->length = len - 1;

	if (rv->type == ISIS_PASSWD_TYPE_HMAC_MD5 && rv->length != 16) {
		sbuf_push(
			log, indent,
			"Unexpected auth length for HMAC-MD5 (expected 16, got %hhu)\n",
			rv->length);
		XFREE(MTYPE_ISIS_TLV, rv);
		return 1;
	}

	rv->offset = stream_get_getp(s);
	stream_get(rv->value, s, rv->length);
	format_item_auth(mtid, (struct isis_item *)rv, log, NULL, indent + 2);
	append_item(&tlvs->isis_auth, (struct isis_item *)rv);
	return 0;
}

/* Functions related to TLV 13 Purge Originator */

static struct isis_purge_originator *copy_tlv_purge_originator(
					struct isis_purge_originator *poi)
{
	if (!poi)
		return NULL;

	struct isis_purge_originator *rv;

	rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));
	rv->sender_set = poi->sender_set;
	memcpy(rv->generator, poi->generator, sizeof(rv->generator));
	if (poi->sender_set)
		memcpy(rv->sender, poi->sender, sizeof(rv->sender));
	return rv;
}

static void format_tlv_purge_originator(struct isis_purge_originator *poi,
					struct sbuf *buf,
					struct json_object *json, int indent)
{
	char sen_id[ISO_SYSID_STRLEN];
	char gen_id[ISO_SYSID_STRLEN];

	if (!poi)
		return;

	snprintfrr(gen_id, ISO_SYSID_STRLEN, "%pSY", poi->generator);
	if (poi->sender_set)
		snprintfrr(sen_id, ISO_SYSID_STRLEN, "%pSY", poi->sender);

	if (json) {
		struct json_object *purge_json;
		purge_json = json_object_new_object();
		json_object_object_add(json, "purge_originator", purge_json);

		json_object_string_add(purge_json, "id", gen_id);
		if (poi->sender_set)
			json_object_string_add(purge_json, "rec-from", sen_id);
	} else {
		sbuf_push(buf, indent, "Purge Originator Identification:\n");
		sbuf_push(buf, indent, "  Generator: %s\n", gen_id);
		if (poi->sender_set)
			sbuf_push(buf, indent, "  Received-From: %s\n", sen_id);
	}
}

static void free_tlv_purge_originator(struct isis_purge_originator *poi)
{
	XFREE(MTYPE_ISIS_TLV, poi);
}

static int pack_tlv_purge_originator(struct isis_purge_originator *poi,
				     struct stream *s)
{
	if (!poi)
		return 0;

	uint8_t data_len = 1 + sizeof(poi->generator);

	if (poi->sender_set)
		data_len += sizeof(poi->sender);

	if (STREAM_WRITEABLE(s) < (unsigned)(2 + data_len))
		return 1;

	stream_putc(s, ISIS_TLV_PURGE_ORIGINATOR);
	stream_putc(s, data_len);
	stream_putc(s, poi->sender_set ? 2 : 1);
	stream_put(s, poi->generator, sizeof(poi->generator));
	if (poi->sender_set)
		stream_put(s, poi->sender, sizeof(poi->sender));
	return 0;
}

static int unpack_tlv_purge_originator(enum isis_tlv_context context,
				       uint8_t tlv_type, uint8_t tlv_len,
				       struct stream *s, struct sbuf *log,
				       void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;
	struct isis_purge_originator poi = {};

	sbuf_push(log, indent, "Unpacking Purge Originator Identification TLV...\n");
	if (tlv_len < 7) {
		sbuf_push(log, indent, "Not enough data left. (Expected at least 7 bytes, got %hhu)\n", tlv_len);
		return 1;
	}

	uint8_t number_of_ids = stream_getc(s);

	if (number_of_ids == 1) {
		poi.sender_set = false;
	} else if (number_of_ids == 2) {
		poi.sender_set = true;
	} else {
		sbuf_push(log, indent, "Got invalid value for number of system IDs: %hhu)\n", number_of_ids);
		return 1;
	}

	if (tlv_len != 1 + 6 * number_of_ids) {
		sbuf_push(log, indent, "Incorrect tlv len for number of IDs.\n");
		return 1;
	}

	stream_get(poi.generator, s, sizeof(poi.generator));
	if (poi.sender_set)
		stream_get(poi.sender, s, sizeof(poi.sender));

	if (tlvs->purge_originator) {
		sbuf_push(log, indent,
			  "WARNING: Purge originator present multiple times, ignoring.\n");
		return 0;
	}

	tlvs->purge_originator = copy_tlv_purge_originator(&poi);
	return 0;
}


/* Functions relating to item TLVs */

static void init_item_list(struct isis_item_list *items)
{
	items->head = NULL;
	items->tail = &items->head;
	items->count = 0;
}

static struct isis_item *copy_item(enum isis_tlv_context context,
				   enum isis_tlv_type type,
				   struct isis_item *item)
{
	const struct tlv_ops *ops = tlv_table[context][type];

	if (ops && ops->copy_item)
		return ops->copy_item(item);

	assert(!"Unknown item tlv type!");
	return NULL;
}

static void copy_items(enum isis_tlv_context context, enum isis_tlv_type type,
		       struct isis_item_list *src, struct isis_item_list *dest)
{
	struct isis_item *item;

	init_item_list(dest);

	for (item = src->head; item; item = item->next) {
		append_item(dest, copy_item(context, type, item));
	}
}

static void format_item(uint16_t mtid, enum isis_tlv_context context,
			enum isis_tlv_type type, struct isis_item *i,
			struct sbuf *buf, struct json_object *json, int indent)
{
	const struct tlv_ops *ops = tlv_table[context][type];

	if (ops && ops->format_item) {
		ops->format_item(mtid, i, buf, json, indent);
		return;
	}

	assert(!"Unknown item tlv type!");
}

static void format_items_(uint16_t mtid, enum isis_tlv_context context,
			  enum isis_tlv_type type, struct isis_item_list *items,
			  struct sbuf *buf, struct json_object *json,
			  int indent)
{
	struct isis_item *i;

	for (i = items->head; i; i = i->next)
		format_item(mtid, context, type, i, buf, json, indent);
}

static void free_item(enum isis_tlv_context tlv_context,
		      enum isis_tlv_type tlv_type, struct isis_item *item)
{
	const struct tlv_ops *ops = tlv_table[tlv_context][tlv_type];

	if (ops && ops->free_item) {
		ops->free_item(item);
		return;
	}

	assert(!"Unknown item tlv type!");
}

static void free_items(enum isis_tlv_context context, enum isis_tlv_type type,
		       struct isis_item_list *items)
{
	struct isis_item *item, *next_item;

	for (item = items->head; item; item = next_item) {
		next_item = item->next;
		free_item(context, type, item);
	}
}

static int pack_item(enum isis_tlv_context context, enum isis_tlv_type type,
		     struct isis_item *i, struct stream *s, size_t *min_len,
		     struct isis_tlvs **fragment_tlvs,
		     const struct pack_order_entry *pe, uint16_t mtid)
{
	const struct tlv_ops *ops = tlv_table[context][type];

	if (ops && ops->pack_item) {
		return ops->pack_item(i, s, min_len);
	}

	assert(!"Unknown item tlv type!");
	return 1;
}

static void add_item_to_fragment(struct isis_item *i,
				 const struct pack_order_entry *pe,
				 struct isis_tlvs *fragment_tlvs, uint16_t mtid)
{
	struct isis_item_list *l;

	if (pe->how_to_pack == ISIS_ITEMS) {
		l = (struct isis_item_list *)(((char *)fragment_tlvs) + pe->what_to_pack);
	} else {
		struct isis_mt_item_list *m;
		m = (struct isis_mt_item_list *)(((char *)fragment_tlvs) + pe->what_to_pack);
		l = isis_get_mt_items(m, mtid);
	}

	append_item(l, copy_item(pe->context, pe->type, i));
}

static int pack_items_(uint16_t mtid, enum isis_tlv_context context,
		       enum isis_tlv_type type, struct isis_item_list *items,
		       struct stream *s, struct isis_tlvs **fragment_tlvs,
		       const struct pack_order_entry *pe,
		       struct isis_tlvs *(*new_fragment)(struct list *l),
		       struct list *new_fragment_arg)
{
	size_t len_pos, last_len, len;
	struct isis_item *item = NULL;
	int rv;
	size_t min_len = 0;

	if (!items->head)
		return 0;

top:
	if (STREAM_WRITEABLE(s) < 2)
		goto too_long;

	stream_putc(s, type);
	len_pos = stream_get_endp(s);
	stream_putc(s, 0); /* Put 0 as length for now */

	if (context == ISIS_CONTEXT_LSP && IS_COMPAT_MT_TLV(type)
	    && mtid != ISIS_MT_IPV4_UNICAST) {
		if (STREAM_WRITEABLE(s) < 2)
			goto too_long;
		stream_putw(s, mtid);
	}

	/* The SRv6 Locator TLV (RFC 9352 section #7.1) starts with the MTID
	 * field */
	if (context == ISIS_CONTEXT_LSP && type == ISIS_TLV_SRV6_LOCATOR) {
		if (STREAM_WRITEABLE(s) < 2)
			goto too_long;
		stream_putw(s, mtid);
	}

	if (context == ISIS_CONTEXT_LSP && type == ISIS_TLV_OLDSTYLE_REACH) {
		if (STREAM_WRITEABLE(s) < 1)
			goto too_long;
		stream_putc(s, 0); /* Virtual flag is set to 0 */
	}

	last_len = len = 0;
	for (item = item ? item : items->head; item; item = item->next) {
		rv = pack_item(context, type, item, s, &min_len, fragment_tlvs,
			       pe, mtid);
		if (rv)
			goto too_long;

		len = stream_get_endp(s) - len_pos - 1;

		/* Multiple auths don't go into one TLV, so always break */
		if (context == ISIS_CONTEXT_LSP && type == ISIS_TLV_AUTH) {
			item = item->next;
			break;
		}

		/* Multiple prefix-sids don't go into one TLV, so always break */
		if (type == ISIS_SUBTLV_PREFIX_SID
		    && (context == ISIS_CONTEXT_SUBTLV_IP_REACH
			|| context == ISIS_CONTEXT_SUBTLV_IPV6_REACH)) {
			item = item->next;
			break;
		}

		if (len > 255) {
			if (!last_len) /* strange, not a single item fit */
				return 1;
			/* drop last tlv, otherwise, its too long */
			stream_set_endp(s, len_pos + 1 + last_len);
			len = last_len;
			break;
		}

		if (fragment_tlvs)
			add_item_to_fragment(item, pe, *fragment_tlvs, mtid);

		last_len = len;
	}

	stream_putc_at(s, len_pos, len);
	if (item)
		goto top;

	return 0;
too_long:
	if (!fragment_tlvs)
		return 1;
	stream_reset(s);
	if (STREAM_WRITEABLE(s) < min_len)
		return 1;
	*fragment_tlvs = new_fragment(new_fragment_arg);
	goto top;
}
#define pack_items(...) pack_items_(ISIS_MT_IPV4_UNICAST, __VA_ARGS__)

static void append_item(struct isis_item_list *dest, struct isis_item *item)
{
	*dest->tail = item;
	dest->tail = &(*dest->tail)->next;
	dest->count++;
}

static void delete_item(struct isis_item_list *dest, struct isis_item *del)
{
	struct isis_item *item, *prev = NULL, *next;

	/* Sanity Check */
	if ((dest == NULL) || (del == NULL))
		return;

	/*
	 * TODO: delete is tricky because "dest" is a singly linked list.
	 * We need to switch a doubly linked list.
	 */
	for (item = dest->head; item; item = next) {
		if (item->next == del) {
			prev = item;
			break;
		}
		next = item->next;
	}
	if (prev)
		prev->next = del->next;
	if (dest->head == del)
		dest->head = del->next;
	if ((struct isis_item *)dest->tail == del) {
		*dest->tail = prev;
		if (prev)
			dest->tail = &(*dest->tail)->next;
		else
			dest->tail = &dest->head;
	}
	dest->count--;
}

static struct isis_item *last_item(struct isis_item_list *list)
{
	return container_of(list->tail, struct isis_item, next);
}

static int unpack_item(uint16_t mtid, enum isis_tlv_context context,
		       uint8_t tlv_type, uint8_t len, struct stream *s,
		       struct sbuf *log, void *dest, int indent)
{
	const struct tlv_ops *ops = tlv_table[context][tlv_type];

	if (ops && ops->unpack_item)
		return ops->unpack_item(mtid, len, s, log, dest, indent);

	assert(!"Unknown item tlv type!");
	sbuf_push(log, indent, "Unknown item tlv type!\n");
	return 1;
}

static int unpack_tlv_with_items(enum isis_tlv_context context,
				 uint8_t tlv_type, uint8_t tlv_len,
				 struct stream *s, struct sbuf *log, void *dest,
				 int indent)
{
	size_t tlv_start;
	size_t tlv_pos;
	int rv;
	uint16_t mtid;

	tlv_start = stream_get_getp(s);
	tlv_pos = 0;

	if (context == ISIS_CONTEXT_LSP &&
	    (IS_COMPAT_MT_TLV(tlv_type) || tlv_type == ISIS_TLV_SRV6_LOCATOR)) {
		if (tlv_len < 2) {
			sbuf_push(log, indent,
				  "TLV is too short to contain MTID\n");
			return 1;
		}
		mtid = stream_getw(s) & ISIS_MT_MASK;
		tlv_pos += 2;
		sbuf_push(log, indent, "Unpacking as MT %s item TLV...\n",
			  isis_mtid2str_fake(mtid));
	} else {
		sbuf_push(log, indent, "Unpacking as item TLV...\n");
		mtid = ISIS_MT_IPV4_UNICAST;
	}

	if (context == ISIS_CONTEXT_LSP
	    && tlv_type == ISIS_TLV_OLDSTYLE_REACH) {
		if (tlv_len - tlv_pos < 1) {
			sbuf_push(log, indent,
				  "TLV is too short for old style reach\n");
			return 1;
		}
		stream_forward_getp(s, 1);
		tlv_pos += 1;
	}

	if (context == ISIS_CONTEXT_LSP
	    && tlv_type == ISIS_TLV_OLDSTYLE_IP_REACH) {
		struct isis_tlvs *tlvs = dest;
		dest = &tlvs->oldstyle_ip_reach;
	} else if (context == ISIS_CONTEXT_LSP
		   && tlv_type == ISIS_TLV_OLDSTYLE_IP_REACH_EXT) {
		struct isis_tlvs *tlvs = dest;
		dest = &tlvs->oldstyle_ip_reach_ext;
	}

	if (context == ISIS_CONTEXT_LSP
	    && tlv_type == ISIS_TLV_MT_ROUTER_INFO) {
		struct isis_tlvs *tlvs = dest;
		tlvs->mt_router_info_empty = (tlv_pos >= (size_t)tlv_len);
	}

	while (tlv_pos < (size_t)tlv_len) {
		rv = unpack_item(mtid, context, tlv_type, tlv_len - tlv_pos, s,
				 log, dest, indent + 2);
		if (rv)
			return rv;

		tlv_pos = stream_get_getp(s) - tlv_start;
	}

	return 0;
}

/* Functions to manipulate mt_item_lists */

static int isis_mt_item_list_cmp(const struct isis_item_list *a,
				 const struct isis_item_list *b)
{
	if (a->mtid < b->mtid)
		return -1;
	if (a->mtid > b->mtid)
		return 1;
	return 0;
}

RB_PROTOTYPE(isis_mt_item_list, isis_item_list, mt_tree, isis_mt_item_list_cmp);
RB_GENERATE(isis_mt_item_list, isis_item_list, mt_tree, isis_mt_item_list_cmp);

struct isis_item_list *isis_get_mt_items(struct isis_mt_item_list *m,
					 uint16_t mtid)
{
	struct isis_item_list *rv;

	rv = isis_lookup_mt_items(m, mtid);
	if (!rv) {
		rv = XCALLOC(MTYPE_ISIS_MT_ITEM_LIST, sizeof(*rv));
		init_item_list(rv);
		rv->mtid = mtid;
		RB_INSERT(isis_mt_item_list, m, rv);
	}

	return rv;
}

struct isis_item_list *isis_lookup_mt_items(struct isis_mt_item_list *m,
					    uint16_t mtid)
{
	struct isis_item_list key = {.mtid = mtid};

	return RB_FIND(isis_mt_item_list, m, &key);
}

static void free_mt_items(enum isis_tlv_context context,
			  enum isis_tlv_type type, struct isis_mt_item_list *m)
{
	struct isis_item_list *n, *nnext;

	RB_FOREACH_SAFE (n, isis_mt_item_list, m, nnext) {
		free_items(context, type, n);
		RB_REMOVE(isis_mt_item_list, m, n);
		XFREE(MTYPE_ISIS_MT_ITEM_LIST, n);
	}
}

static void format_mt_items(enum isis_tlv_context context,
			    enum isis_tlv_type type,
			    struct isis_mt_item_list *m, struct sbuf *buf,
			    struct json_object *json, int indent)
{
	struct isis_item_list *n;

	RB_FOREACH (n, isis_mt_item_list, m) {
		format_items_(n->mtid, context, type, n, buf, json, indent);
	}
}

static int pack_mt_items(enum isis_tlv_context context, enum isis_tlv_type type,
			 struct isis_mt_item_list *m, struct stream *s,
			 struct isis_tlvs **fragment_tlvs,
			 const struct pack_order_entry *pe,
			 struct isis_tlvs *(*new_fragment)(struct list *l),
			 struct list *new_fragment_arg)
{
	struct isis_item_list *n;

	RB_FOREACH (n, isis_mt_item_list, m) {
		int rv;

		rv = pack_items_(n->mtid, context, type, n, s, fragment_tlvs,
				 pe, new_fragment, new_fragment_arg);
		if (rv)
			return rv;
	}

	return 0;
}

static void copy_mt_items(enum isis_tlv_context context,
			  enum isis_tlv_type type,
			  struct isis_mt_item_list *src,
			  struct isis_mt_item_list *dest)
{
	struct isis_item_list *n;

	RB_INIT(isis_mt_item_list, dest);

	RB_FOREACH (n, isis_mt_item_list, src) {
		copy_items(context, type, n, isis_get_mt_items(dest, n->mtid));
	}
}

/* Functions related to TLV 27 SRv6 Locator as per RFC 9352 section #7.1*/
static struct isis_item *copy_item_srv6_locator(struct isis_item *i)
{
	struct isis_srv6_locator_tlv *loc = (struct isis_srv6_locator_tlv *)i;
	struct isis_srv6_locator_tlv *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->metric = loc->metric;
	rv->flags = loc->flags;
	rv->algorithm = loc->algorithm;
	rv->prefix = loc->prefix;
	rv->subtlvs = copy_subtlvs(loc->subtlvs);

	return (struct isis_item *)rv;
}

static void format_item_srv6_locator(uint16_t mtid, struct isis_item *i,
				     struct sbuf *buf, struct json_object *json,
				     int indent)
{
	struct isis_srv6_locator_tlv *loc = (struct isis_srv6_locator_tlv *)i;

	if (json) {
		struct json_object *loc_json;
		loc_json = json_object_new_object();
		json_object_object_add(json, "srv6-locator", loc_json);
		json_object_int_add(loc_json, "mt-id", mtid);
		json_object_string_addf(loc_json, "prefix", "%pFX",
					&loc->prefix);
		json_object_int_add(loc_json, "metric", loc->metric);
		json_object_string_add(
			loc_json, "d-flag",
			CHECK_FLAG(loc->flags, ISIS_TLV_SRV6_LOCATOR_FLAG_D)
				? "yes"
				: "");
		json_object_int_add(loc_json, "algorithm", loc->algorithm);
		json_object_string_add(loc_json, "mt-name",
				       isis_mtid2str(mtid));
		if (loc->subtlvs) {
			struct json_object *subtlvs_json;
			subtlvs_json = json_object_new_object();
			json_object_object_add(loc_json, "subtlvs",
					       subtlvs_json);
			format_subtlvs(loc->subtlvs, NULL, subtlvs_json, 0);
		}
	} else {
		sbuf_push(buf, indent, "SRv6 Locator: %pFX (Metric: %u)%s",
			  &loc->prefix, loc->metric,
			  CHECK_FLAG(loc->flags, ISIS_TLV_SRV6_LOCATOR_FLAG_D)
				  ? " D-flag"
				  : "");
		sbuf_push(buf, 0, " %s\n", isis_mtid2str(mtid));

		if (loc->subtlvs) {
			sbuf_push(buf, indent, "  Sub-TLVs:\n");
			format_subtlvs(loc->subtlvs, buf, NULL, indent + 4);
		}
	}
}

static void free_item_srv6_locator(struct isis_item *i)
{
	struct isis_srv6_locator_tlv *item = (struct isis_srv6_locator_tlv *)i;

	isis_free_subtlvs(item->subtlvs);
	XFREE(MTYPE_ISIS_TLV, item);
}

static int pack_item_srv6_locator(struct isis_item *i, struct stream *s,
				  size_t *min_len)
{
	struct isis_srv6_locator_tlv *loc = (struct isis_srv6_locator_tlv *)i;

	if (STREAM_WRITEABLE(s) < 7 + (unsigned)PSIZE(loc->prefix.prefixlen)) {
		*min_len = 7 + (unsigned)PSIZE(loc->prefix.prefixlen);
		return 1;
	}

	stream_putl(s, loc->metric);
	stream_putc(s, loc->flags);
	stream_putc(s, loc->algorithm);
	/* Locator size */
	stream_putc(s, loc->prefix.prefixlen);
	/* Locator prefix */
	stream_put(s, &loc->prefix.prefix.s6_addr,
		   PSIZE(loc->prefix.prefixlen));

	if (loc->subtlvs) {
		/* Pack Sub-TLVs */
		if (pack_subtlvs(loc->subtlvs, s))
			return 1;
	} else {
		/* No Sub-TLVs */
		if (STREAM_WRITEABLE(s) < 1) {
			*min_len = 8 + (unsigned)PSIZE(loc->prefix.prefixlen);
			return 1;
		}

		/* Put 0 as Sub-TLV length, because we have no Sub-TLVs  */
		stream_putc(s, 0);
	}

	return 0;
}

static int unpack_item_srv6_locator(uint16_t mtid, uint8_t len,
				    struct stream *s, struct sbuf *log,
				    void *dest, int indent)
{
	struct isis_tlvs *tlvs = dest;
	struct isis_srv6_locator_tlv *rv = NULL;
	size_t consume;
	uint8_t subtlv_len;
	struct isis_item_list *items;

	items = isis_get_mt_items(&tlvs->srv6_locator, mtid);

	sbuf_push(log, indent, "Unpacking SRv6 Locator...\n");
	consume = 7;
	if (len < consume) {
		sbuf_push(
			log, indent,
			"Not enough data left. (expected 7 or more bytes, got %hhu)\n",
			len);
		goto out;
	}

	rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	rv->metric = stream_getl(s);
	rv->flags = stream_getc(s);
	rv->algorithm = stream_getc(s);

	rv->prefix.family = AF_INET6;
	rv->prefix.prefixlen = stream_getc(s);
	if (rv->prefix.prefixlen > IPV6_MAX_BITLEN) {
		sbuf_push(log, indent, "Loc Size %u is implausible for SRv6\n",
			  rv->prefix.prefixlen);
		goto out;
	}

	consume += PSIZE(rv->prefix.prefixlen);
	if (len < consume) {
		sbuf_push(
			log, indent,
			"Expected %u bytes of prefix, but only %u bytes available.\n",
			PSIZE(rv->prefix.prefixlen), len - 7);
		goto out;
	}
	stream_get(&rv->prefix.prefix.s6_addr, s, PSIZE(rv->prefix.prefixlen));

	struct in6_addr orig_locator = rv->prefix.prefix;
	apply_mask_ipv6(&rv->prefix);
	if (memcmp(&orig_locator, &rv->prefix.prefix, sizeof(orig_locator)))
		sbuf_push(log, indent + 2,
			  "WARNING: SRv6 Locator had hostbits set.\n");
	format_item_srv6_locator(mtid, (struct isis_item *)rv, log, NULL,
				 indent + 2);

	consume += 1;
	if (len < consume) {
		sbuf_push(
			log, indent,
			"Expected 1 byte of subtlv len, but no more data persent.\n");
		goto out;
	}
	subtlv_len = stream_getc(s);

	if (subtlv_len) {
		consume += subtlv_len;
		if (len < consume) {
			sbuf_push(
				log, indent,
				"Expected %hhu bytes of subtlvs, but only %u bytes available.\n",
				subtlv_len,
				len - 7 - PSIZE(rv->prefix.prefixlen));
			goto out;
		}

		rv->subtlvs =
			isis_alloc_subtlvs(ISIS_CONTEXT_SUBTLV_SRV6_LOCATOR);

		bool unpacked_known_tlvs = false;
		if (unpack_tlvs(ISIS_CONTEXT_SUBTLV_SRV6_LOCATOR, subtlv_len, s,
				log, rv->subtlvs, indent + 4,
				&unpacked_known_tlvs)) {
			goto out;
		}
		if (!unpacked_known_tlvs) {
			isis_free_subtlvs(rv->subtlvs);
			rv->subtlvs = NULL;
		}
	}

	append_item(items, (struct isis_item *)rv);
	return 0;
out:
	if (rv)
		free_item_srv6_locator((struct isis_item *)rv);
	return 1;
}

/* Functions related to tlvs in general */

struct isis_tlvs *isis_alloc_tlvs(void)
{
	struct isis_tlvs *result;

	result = XCALLOC(MTYPE_ISIS_TLV, sizeof(*result));

	init_item_list(&result->isis_auth);
	init_item_list(&result->area_addresses);
	init_item_list(&result->mt_router_info);
	init_item_list(&result->oldstyle_reach);
	init_item_list(&result->lan_neighbor);
	init_item_list(&result->lsp_entries);
	init_item_list(&result->extended_reach);
	RB_INIT(isis_mt_item_list, &result->mt_reach);
	init_item_list(&result->oldstyle_ip_reach);
	init_item_list(&result->oldstyle_ip_reach_ext);
	init_item_list(&result->ipv4_address);
	init_item_list(&result->ipv6_address);
	init_item_list(&result->global_ipv6_address);
	init_item_list(&result->extended_ip_reach);
	RB_INIT(isis_mt_item_list, &result->mt_ip_reach);
	init_item_list(&result->ipv6_reach);
	RB_INIT(isis_mt_item_list, &result->mt_ipv6_reach);
	RB_INIT(isis_mt_item_list, &result->srv6_locator);

	return result;
}

struct isis_tlvs *isis_copy_tlvs(struct isis_tlvs *tlvs)
{
	struct isis_tlvs *rv = XCALLOC(MTYPE_ISIS_TLV, sizeof(*rv));

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_AUTH, &tlvs->isis_auth,
		   &rv->isis_auth);

	rv->purge_originator =
			copy_tlv_purge_originator(tlvs->purge_originator);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_AREA_ADDRESSES,
		   &tlvs->area_addresses, &rv->area_addresses);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_ROUTER_INFO,
		   &tlvs->mt_router_info, &rv->mt_router_info);

	rv->mt_router_info_empty = tlvs->mt_router_info_empty;

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_OLDSTYLE_REACH,
		   &tlvs->oldstyle_reach, &rv->oldstyle_reach);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_LAN_NEIGHBORS,
		   &tlvs->lan_neighbor, &rv->lan_neighbor);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_LSP_ENTRY, &tlvs->lsp_entries,
		   &rv->lsp_entries);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_REACH,
		   &tlvs->extended_reach, &rv->extended_reach);

	copy_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_REACH, &tlvs->mt_reach,
		      &rv->mt_reach);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_OLDSTYLE_IP_REACH,
		   &tlvs->oldstyle_ip_reach, &rv->oldstyle_ip_reach);

	copy_tlv_protocols_supported(&tlvs->protocols_supported,
				     &rv->protocols_supported);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_OLDSTYLE_IP_REACH_EXT,
		   &tlvs->oldstyle_ip_reach_ext, &rv->oldstyle_ip_reach_ext);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV4_ADDRESS, &tlvs->ipv4_address,
		   &rv->ipv4_address);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV6_ADDRESS, &tlvs->ipv6_address,
		   &rv->ipv6_address);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_GLOBAL_IPV6_ADDRESS,
		   &tlvs->global_ipv6_address, &rv->global_ipv6_address);

	rv->te_router_id = copy_tlv_te_router_id(tlvs->te_router_id);

	rv->te_router_id_ipv6 =
		copy_tlv_te_router_id_ipv6(tlvs->te_router_id_ipv6);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_IP_REACH,
		   &tlvs->extended_ip_reach, &rv->extended_ip_reach);

	copy_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_IP_REACH,
		      &tlvs->mt_ip_reach, &rv->mt_ip_reach);

	rv->hostname = copy_tlv_dynamic_hostname(tlvs->hostname);

	copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV6_REACH, &tlvs->ipv6_reach,
		   &rv->ipv6_reach);

	copy_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_IPV6_REACH,
		      &tlvs->mt_ipv6_reach, &rv->mt_ipv6_reach);

	rv->threeway_adj = copy_tlv_threeway_adj(tlvs->threeway_adj);

	rv->router_cap = copy_tlv_router_cap(tlvs->router_cap);

	rv->spine_leaf = copy_tlv_spine_leaf(tlvs->spine_leaf);

	copy_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_SRV6_LOCATOR,
		      &tlvs->srv6_locator, &rv->srv6_locator);

	return rv;
}

static void format_tlvs(struct isis_tlvs *tlvs, struct sbuf *buf, struct json_object *json, int indent)
{
	format_tlv_protocols_supported(&tlvs->protocols_supported, buf, json,
				       indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_AUTH, &tlvs->isis_auth, buf,
		     json, indent);

	format_tlv_purge_originator(tlvs->purge_originator, buf, json, indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_AREA_ADDRESSES,
		     &tlvs->area_addresses, buf, json, indent);

	if (tlvs->mt_router_info_empty) {
		if (json)
			json_object_string_add(json, "mt-router-info", "none");
		else
			sbuf_push(buf, indent, "MT Router Info: None\n");
	} else {
		format_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_ROUTER_INFO,
			     &tlvs->mt_router_info, buf, json, indent);
	}

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_OLDSTYLE_REACH,
		     &tlvs->oldstyle_reach, buf, json, indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_LAN_NEIGHBORS,
		     &tlvs->lan_neighbor, buf, json, indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_LSP_ENTRY, &tlvs->lsp_entries,
		     buf, json, indent);

	format_tlv_dynamic_hostname(tlvs->hostname, buf, json, indent);
	format_tlv_te_router_id(tlvs->te_router_id, buf, json, indent);
	format_tlv_te_router_id_ipv6(tlvs->te_router_id_ipv6, buf, json,
				     indent);
	if (json)
		format_tlv_router_cap_json(tlvs->router_cap, json);
	else
		format_tlv_router_cap(tlvs->router_cap, buf, indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_REACH,
		     &tlvs->extended_reach, buf, json, indent);

	format_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_REACH, &tlvs->mt_reach,
			buf, json, indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_OLDSTYLE_IP_REACH,
		     &tlvs->oldstyle_ip_reach, buf, json, indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_OLDSTYLE_IP_REACH_EXT,
		     &tlvs->oldstyle_ip_reach_ext, buf, json, indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV4_ADDRESS,
		     &tlvs->ipv4_address, buf, json, indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV6_ADDRESS,
		     &tlvs->ipv6_address, buf, json, indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_GLOBAL_IPV6_ADDRESS,
		     &tlvs->global_ipv6_address, buf, json, indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_IP_REACH,
		     &tlvs->extended_ip_reach, buf, json, indent);

	format_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_IP_REACH,
			&tlvs->mt_ip_reach, buf, json, indent);

	format_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV6_REACH, &tlvs->ipv6_reach,
		     buf, json, indent);

	format_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_IPV6_REACH,
			&tlvs->mt_ipv6_reach, buf, json, indent);

	format_tlv_threeway_adj(tlvs->threeway_adj, buf, json, indent);

	format_tlv_spine_leaf(tlvs->spine_leaf, buf, json, indent);

	format_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_SRV6_LOCATOR,
			&tlvs->srv6_locator, buf, json, indent);
}

const char *isis_format_tlvs(struct isis_tlvs *tlvs, struct json_object *json)
{
	if (json) {
		format_tlvs(tlvs, NULL, json, 0);
		return NULL;
	} else {
		static struct sbuf buf;

		if (!sbuf_buf(&buf))
			sbuf_init(&buf, NULL, 0);

		sbuf_reset(&buf);
		format_tlvs(tlvs, &buf, NULL, 0);
		return sbuf_buf(&buf);
	}
}

void isis_free_tlvs(struct isis_tlvs *tlvs)
{
	if (!tlvs)
		return;

	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_AUTH, &tlvs->isis_auth);
	free_tlv_purge_originator(tlvs->purge_originator);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_AREA_ADDRESSES,
		   &tlvs->area_addresses);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_ROUTER_INFO,
		   &tlvs->mt_router_info);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_OLDSTYLE_REACH,
		   &tlvs->oldstyle_reach);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_LAN_NEIGHBORS,
		   &tlvs->lan_neighbor);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_LSP_ENTRY, &tlvs->lsp_entries);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_REACH,
		   &tlvs->extended_reach);
	free_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_REACH, &tlvs->mt_reach);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_OLDSTYLE_IP_REACH,
		   &tlvs->oldstyle_ip_reach);
	free_tlv_protocols_supported(&tlvs->protocols_supported);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_OLDSTYLE_IP_REACH_EXT,
		   &tlvs->oldstyle_ip_reach_ext);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV4_ADDRESS,
		   &tlvs->ipv4_address);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV6_ADDRESS,
		   &tlvs->ipv6_address);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_GLOBAL_IPV6_ADDRESS,
		   &tlvs->global_ipv6_address);
	free_tlv_te_router_id(tlvs->te_router_id);
	free_tlv_te_router_id_ipv6(tlvs->te_router_id_ipv6);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_EXTENDED_IP_REACH,
		   &tlvs->extended_ip_reach);
	free_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_IP_REACH,
		      &tlvs->mt_ip_reach);
	free_tlv_dynamic_hostname(tlvs->hostname);
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_IPV6_REACH, &tlvs->ipv6_reach);
	free_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_IPV6_REACH,
		      &tlvs->mt_ipv6_reach);
	free_tlv_threeway_adj(tlvs->threeway_adj);
	free_tlv_router_cap(tlvs->router_cap);
	free_tlv_spine_leaf(tlvs->spine_leaf);
	free_mt_items(ISIS_CONTEXT_LSP, ISIS_TLV_SRV6_LOCATOR,
		      &tlvs->srv6_locator);

	XFREE(MTYPE_ISIS_TLV, tlvs);
}

static void add_padding(struct stream *s)
{
	while (STREAM_WRITEABLE(s)) {
		if (STREAM_WRITEABLE(s) == 1)
			break;
		uint32_t padding_len = STREAM_WRITEABLE(s) - 2;

		if (padding_len > 255) {
			if (padding_len == 256)
				padding_len = 254;
			else
				padding_len = 255;
		}

		stream_putc(s, ISIS_TLV_PADDING);
		stream_putc(s, padding_len);
		stream_put(s, NULL, padding_len);
	}
}

#define LSP_REM_LIFETIME_OFF 10
#define LSP_CHECKSUM_OFF 24
static void safe_auth_md5(struct stream *s, uint16_t *checksum,
			  uint16_t *rem_lifetime)
{
	memcpy(rem_lifetime, STREAM_DATA(s) + LSP_REM_LIFETIME_OFF,
	       sizeof(*rem_lifetime));
	memset(STREAM_DATA(s) + LSP_REM_LIFETIME_OFF, 0, sizeof(*rem_lifetime));
	memcpy(checksum, STREAM_DATA(s) + LSP_CHECKSUM_OFF, sizeof(*checksum));
	memset(STREAM_DATA(s) + LSP_CHECKSUM_OFF, 0, sizeof(*checksum));
}

static void restore_auth_md5(struct stream *s, uint16_t checksum,
			     uint16_t rem_lifetime)
{
	memcpy(STREAM_DATA(s) + LSP_REM_LIFETIME_OFF, &rem_lifetime,
	       sizeof(rem_lifetime));
	memcpy(STREAM_DATA(s) + LSP_CHECKSUM_OFF, &checksum, sizeof(checksum));
}

static void update_auth_hmac_md5(struct isis_auth *auth, struct stream *s,
				 bool is_lsp)
{
	uint8_t digest[16];
	uint16_t checksum, rem_lifetime;

	if (is_lsp)
		safe_auth_md5(s, &checksum, &rem_lifetime);

	memset(STREAM_DATA(s) + auth->offset, 0, 16);
#ifdef CRYPTO_OPENSSL
	uint8_t *result = (uint8_t *)HMAC(EVP_md5(), auth->passwd,
					  auth->plength, STREAM_DATA(s),
					  stream_get_endp(s), NULL, NULL);

	memcpy(digest, result, 16);
#elif CRYPTO_INTERNAL
	hmac_md5(STREAM_DATA(s), stream_get_endp(s), auth->passwd,
		 auth->plength, digest);
#endif
	memcpy(auth->value, digest, 16);
	memcpy(STREAM_DATA(s) + auth->offset, digest, 16);

	if (is_lsp)
		restore_auth_md5(s, checksum, rem_lifetime);
}

static void update_auth(struct isis_tlvs *tlvs, struct stream *s, bool is_lsp)
{
	struct isis_auth *auth_head = (struct isis_auth *)tlvs->isis_auth.head;

	for (struct isis_auth *auth = auth_head; auth; auth = auth->next) {
		if (auth->type == ISIS_PASSWD_TYPE_HMAC_MD5)
			update_auth_hmac_md5(auth, s, is_lsp);
	}
}

static int handle_pack_entry(const struct pack_order_entry *pe,
			     struct isis_tlvs *tlvs, struct stream *stream,
			     struct isis_tlvs **fragment_tlvs,
			     struct isis_tlvs *(*new_fragment)(struct list *l),
			     struct list *new_fragment_arg)
{
	int rv;

	if (pe->how_to_pack == ISIS_ITEMS) {
		struct isis_item_list *l;
		l = (struct isis_item_list *)(((char *)tlvs)
					      + pe->what_to_pack);
		rv = pack_items(pe->context, pe->type, l, stream, fragment_tlvs,
				pe, new_fragment, new_fragment_arg);
	} else {
		struct isis_mt_item_list *l;
		l = (struct isis_mt_item_list *)(((char *)tlvs)
						 + pe->what_to_pack);
		rv = pack_mt_items(pe->context, pe->type, l, stream,
				   fragment_tlvs, pe, new_fragment,
				   new_fragment_arg);
	}

	return rv;
}

static int pack_tlvs(struct isis_tlvs *tlvs, struct stream *stream,
		     struct isis_tlvs *fragment_tlvs,
		     struct isis_tlvs *(*new_fragment)(struct list *l),
		     struct list *new_fragment_arg)
{
	int rv;

	/* When fragmenting, don't add auth as it's already accounted for in the
	 * size we are given. */
	if (!fragment_tlvs) {
		rv = pack_items(ISIS_CONTEXT_LSP, ISIS_TLV_AUTH,
				&tlvs->isis_auth, stream, NULL, NULL, NULL,
				NULL);
		if (rv)
			return rv;
	}

	rv = pack_tlv_purge_originator(tlvs->purge_originator, stream);
	if (rv)
		return rv;
	if (fragment_tlvs) {
		fragment_tlvs->purge_originator =
			copy_tlv_purge_originator(tlvs->purge_originator);
	}

	rv = pack_tlv_protocols_supported(&tlvs->protocols_supported, stream);
	if (rv)
		return rv;
	if (fragment_tlvs) {
		copy_tlv_protocols_supported(
			&tlvs->protocols_supported,
			&fragment_tlvs->protocols_supported);
	}

	rv = pack_items(ISIS_CONTEXT_LSP, ISIS_TLV_AREA_ADDRESSES,
			&tlvs->area_addresses, stream, NULL, NULL, NULL, NULL);
	if (rv)
		return rv;
	if (fragment_tlvs) {
		copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_AREA_ADDRESSES,
			   &tlvs->area_addresses,
			   &fragment_tlvs->area_addresses);
	}


	if (tlvs->mt_router_info_empty) {
		if (STREAM_WRITEABLE(stream) < 2)
			return 1;
		stream_putc(stream, ISIS_TLV_MT_ROUTER_INFO);
		stream_putc(stream, 0);
		if (fragment_tlvs)
			fragment_tlvs->mt_router_info_empty = true;
	} else {
		rv = pack_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_ROUTER_INFO,
				&tlvs->mt_router_info, stream, NULL, NULL, NULL,
				NULL);
		if (rv)
			return rv;
		if (fragment_tlvs) {
			copy_items(ISIS_CONTEXT_LSP, ISIS_TLV_MT_ROUTER_INFO,
				   &tlvs->mt_router_info,
				   &fragment_tlvs->mt_router_info);
		}
	}

	rv = pack_tlv_dynamic_hostname(tlvs->hostname, stream);
	if (rv)
		return rv;
	if (fragment_tlvs)
		fragment_tlvs->hostname =
			copy_tlv_dynamic_hostname(tlvs->hostname);

	rv = pack_tlv_router_cap(tlvs->router_cap, stream);
	if (rv)
		return rv;
	if (fragment_tlvs) {
		fragment_tlvs->router_cap =
			copy_tlv_router_cap(tlvs->router_cap);
	}

	rv = pack_tlv_te_router_id(tlvs->te_router_id, stream);
	if (rv)
		return rv;
	if (fragment_tlvs) {
		fragment_tlvs->te_router_id =
			copy_tlv_te_router_id(tlvs->te_router_id);
	}

	rv = pack_tlv_te_router_id_ipv6(tlvs->te_router_id_ipv6, stream);
	if (rv)
		return rv;
	if (fragment_tlvs) {
		fragment_tlvs->te_router_id_ipv6 =
			copy_tlv_te_router_id_ipv6(tlvs->te_router_id_ipv6);
	}

	rv = pack_tlv_threeway_adj(tlvs->threeway_adj, stream);
	if (rv)
		return rv;
	if (fragment_tlvs) {
		fragment_tlvs->threeway_adj =
			copy_tlv_threeway_adj(tlvs->threeway_adj);
	}

	rv = pack_tlv_spine_leaf(tlvs->spine_leaf, stream);
	if (rv)
		return rv;
	if (fragment_tlvs) {
		fragment_tlvs->spine_leaf =
			copy_tlv_spine_leaf(tlvs->spine_leaf);
	}

	for (size_t pack_idx = 0; pack_idx < array_size(pack_order);
	     pack_idx++) {
		rv = handle_pack_entry(&pack_order[pack_idx], tlvs, stream,
				       fragment_tlvs ? &fragment_tlvs : NULL,
				       new_fragment, new_fragment_arg);

		if (rv)
			return rv;
	}

	return 0;
}

int isis_pack_tlvs(struct isis_tlvs *tlvs, struct stream *stream,
		   size_t len_pointer, bool pad, bool is_lsp)
{
	int rv;

	rv = pack_tlvs(tlvs, stream, NULL, NULL, NULL);
	if (rv)
		return rv;

	if (pad)
		add_padding(stream);

	if (len_pointer != (size_t)-1) {
		stream_putw_at(stream, len_pointer, stream_get_endp(stream));
	}

	update_auth(tlvs, stream, is_lsp);

	return 0;
}

static struct isis_tlvs *new_fragment(struct list *l)
{
	struct isis_tlvs *rv = isis_alloc_tlvs();

	listnode_add(l, rv);
	return rv;
}

struct list *isis_fragment_tlvs(struct isis_tlvs *tlvs, size_t size)
{
	struct stream *dummy_stream = stream_new(size);
	struct list *rv = list_new();
	struct isis_tlvs *fragment_tlvs = new_fragment(rv);

	if (pack_tlvs(tlvs, dummy_stream, fragment_tlvs, new_fragment, rv)) {
		struct listnode *node;
		for (ALL_LIST_ELEMENTS_RO(rv, node, fragment_tlvs))
			isis_free_tlvs(fragment_tlvs);
		list_delete(&rv);
	}

	stream_free(dummy_stream);
	return rv;
}

static int unpack_tlv_unknown(enum isis_tlv_context context, uint8_t tlv_type,
			      uint8_t tlv_len, struct stream *s,
			      struct sbuf *log, int indent)
{
	stream_forward_getp(s, tlv_len);
	sbuf_push(log, indent,
		  "Skipping unknown TLV %hhu (%hhu bytes)\n",
		  tlv_type, tlv_len);
	return 0;
}

static int unpack_tlv(enum isis_tlv_context context, size_t avail_len,
		      struct stream *stream, struct sbuf *log, void *dest,
		      int indent, bool *unpacked_known_tlvs)
{
	uint8_t tlv_type, tlv_len;
	const struct tlv_ops *ops;

	sbuf_push(log, indent, "Unpacking TLV...\n");

	if (avail_len < 2) {
		sbuf_push(
			log, indent + 2,
			"Available data %zu too short to contain a TLV header.\n",
			avail_len);
		return 1;
	}

	tlv_type = stream_getc(stream);
	tlv_len = stream_getc(stream);

	sbuf_push(log, indent + 2,
		  "Found TLV of type %hhu and len %hhu.\n",
		  tlv_type, tlv_len);

	if (avail_len < ((size_t)tlv_len) + 2) {
		sbuf_push(log, indent + 2,
			  "Available data %zu too short for claimed TLV len %hhu.\n",
			  avail_len - 2, tlv_len);
		return 1;
	}

	ops = tlv_table[context][tlv_type];
	if (ops && ops->unpack) {
		if (unpacked_known_tlvs)
			*unpacked_known_tlvs = true;
		return ops->unpack(context, tlv_type, tlv_len, stream, log,
				   dest, indent + 2);
	}

	return unpack_tlv_unknown(context, tlv_type, tlv_len, stream, log,
				  indent + 2);
}

static int unpack_tlvs(enum isis_tlv_context context, size_t avail_len,
		       struct stream *stream, struct sbuf *log, void *dest,
		       int indent, bool *unpacked_known_tlvs)
{
	int rv;
	size_t tlv_start, tlv_pos;

	tlv_start = stream_get_getp(stream);
	tlv_pos = 0;

	sbuf_push(log, indent, "Unpacking %zu bytes of %s...\n", avail_len,
		  (context == ISIS_CONTEXT_LSP) ? "TLVs" : "sub-TLVs");

	while (tlv_pos < avail_len) {
		rv = unpack_tlv(context, avail_len - tlv_pos, stream, log, dest,
				indent + 2, unpacked_known_tlvs);
		if (rv)
			return rv;

		tlv_pos = stream_get_getp(stream) - tlv_start;
	}

	return 0;
}

int isis_unpack_tlvs(size_t avail_len, struct stream *stream,
		     struct isis_tlvs **dest, const char **log)
{
	static struct sbuf logbuf;
	int indent = 0;
	int rv;
	struct isis_tlvs *result;

	if (!sbuf_buf(&logbuf))
		sbuf_init(&logbuf, NULL, 0);

	sbuf_reset(&logbuf);
	if (avail_len > STREAM_READABLE(stream)) {
		sbuf_push(&logbuf, indent,
			  "Stream doesn't contain sufficient data. Claimed %zu, available %zu\n",
			  avail_len, STREAM_READABLE(stream));
		return 1;
	}

	result = isis_alloc_tlvs();
	rv = unpack_tlvs(ISIS_CONTEXT_LSP, avail_len, stream, &logbuf, result,
			 indent, NULL);

	*log = sbuf_buf(&logbuf);
	*dest = result;

	return rv;
}

#define TLV_OPS(_name_, _desc_)                                                \
	static const struct tlv_ops tlv_##_name_##_ops = {                     \
		.name = _desc_, .unpack = unpack_tlv_##_name_,                 \
	}

#define ITEM_TLV_OPS(_name_, _desc_)                                           \
	static const struct tlv_ops tlv_##_name_##_ops = {                     \
		.name = _desc_,                                                \
		.unpack = unpack_tlv_with_items,                               \
									       \
		.pack_item = pack_item_##_name_,                               \
		.free_item = free_item_##_name_,                               \
		.unpack_item = unpack_item_##_name_,                           \
		.format_item = format_item_##_name_,                           \
		.copy_item = copy_item_##_name_}

#define SUBTLV_OPS(_name_, _desc_)                                             \
	static const struct tlv_ops subtlv_##_name_##_ops = {                  \
		.name = _desc_, .unpack = unpack_subtlv_##_name_,              \
	}

#define ITEM_SUBTLV_OPS(_name_, _desc_) \
	ITEM_TLV_OPS(_name_, _desc_)

#define SUBSUBTLV_OPS(_name_, _desc_)                                          \
	static const struct tlv_ops subsubtlv_##_name_##_ops = {               \
		.name = _desc_,                                                \
		.unpack = unpack_subsubtlv_##_name_,                           \
	}

#define ITEM_SUBSUBTLV_OPS(_name_, _desc_) \
	ITEM_TLV_OPS(_name_, _desc_)

ITEM_TLV_OPS(area_address, "TLV 1 Area Addresses");
ITEM_TLV_OPS(oldstyle_reach, "TLV 2 IS Reachability");
ITEM_TLV_OPS(lan_neighbor, "TLV 6 LAN Neighbors");
ITEM_TLV_OPS(lsp_entry, "TLV 9 LSP Entries");
ITEM_TLV_OPS(auth, "TLV 10 IS-IS Auth");
TLV_OPS(purge_originator, "TLV 13 Purge Originator Identification");
ITEM_TLV_OPS(extended_reach, "TLV 22 Extended Reachability");
ITEM_TLV_OPS(oldstyle_ip_reach, "TLV 128/130 IP Reachability");
TLV_OPS(protocols_supported, "TLV 129 Protocols Supported");
ITEM_TLV_OPS(ipv4_address, "TLV 132 IPv4 Interface Address");
TLV_OPS(te_router_id, "TLV 134 TE Router ID");
ITEM_TLV_OPS(extended_ip_reach, "TLV 135 Extended IP Reachability");
TLV_OPS(dynamic_hostname, "TLV 137 Dynamic Hostname");
TLV_OPS(te_router_id_ipv6, "TLV 140 IPv6 TE Router ID");
TLV_OPS(spine_leaf, "TLV 150 Spine Leaf Extensions");
ITEM_TLV_OPS(mt_router_info, "TLV 229 MT Router Information");
TLV_OPS(threeway_adj, "TLV 240 P2P Three-Way Adjacency");
ITEM_TLV_OPS(ipv6_address, "TLV 232 IPv6 Interface Address");
ITEM_TLV_OPS(global_ipv6_address, "TLV 233 Global IPv6 Interface Address");
ITEM_TLV_OPS(ipv6_reach, "TLV 236 IPv6 Reachability");
TLV_OPS(router_cap, "TLV 242 Router Capability");

ITEM_SUBTLV_OPS(prefix_sid, "Sub-TLV 3 SR Prefix-SID");
SUBTLV_OPS(ipv6_source_prefix, "Sub-TLV 22 IPv6 Source Prefix");

ITEM_TLV_OPS(srv6_locator, "TLV 27 SRv6 Locator");
ITEM_SUBTLV_OPS(srv6_end_sid, "Sub-TLV 5 SRv6 End SID");
SUBSUBTLV_OPS(srv6_sid_structure, "Sub-Sub-TLV 1 SRv6 SID Structure");

static const struct tlv_ops *const tlv_table[ISIS_CONTEXT_MAX][ISIS_TLV_MAX] = {
	[ISIS_CONTEXT_LSP] = {
		[ISIS_TLV_AREA_ADDRESSES] = &tlv_area_address_ops,
		[ISIS_TLV_OLDSTYLE_REACH] = &tlv_oldstyle_reach_ops,
		[ISIS_TLV_LAN_NEIGHBORS] = &tlv_lan_neighbor_ops,
		[ISIS_TLV_LSP_ENTRY] = &tlv_lsp_entry_ops,
		[ISIS_TLV_AUTH] = &tlv_auth_ops,
		[ISIS_TLV_PURGE_ORIGINATOR] = &tlv_purge_originator_ops,
		[ISIS_TLV_EXTENDED_REACH] = &tlv_extended_reach_ops,
		[ISIS_TLV_OLDSTYLE_IP_REACH] = &tlv_oldstyle_ip_reach_ops,
		[ISIS_TLV_PROTOCOLS_SUPPORTED] = &tlv_protocols_supported_ops,
		[ISIS_TLV_OLDSTYLE_IP_REACH_EXT] = &tlv_oldstyle_ip_reach_ops,
		[ISIS_TLV_IPV4_ADDRESS] = &tlv_ipv4_address_ops,
		[ISIS_TLV_TE_ROUTER_ID] = &tlv_te_router_id_ops,
		[ISIS_TLV_TE_ROUTER_ID_IPV6] = &tlv_te_router_id_ipv6_ops,
		[ISIS_TLV_EXTENDED_IP_REACH] = &tlv_extended_ip_reach_ops,
		[ISIS_TLV_DYNAMIC_HOSTNAME] = &tlv_dynamic_hostname_ops,
		[ISIS_TLV_SPINE_LEAF_EXT] = &tlv_spine_leaf_ops,
		[ISIS_TLV_MT_REACH] = &tlv_extended_reach_ops,
		[ISIS_TLV_MT_ROUTER_INFO] = &tlv_mt_router_info_ops,
		[ISIS_TLV_IPV6_ADDRESS] = &tlv_ipv6_address_ops,
		[ISIS_TLV_GLOBAL_IPV6_ADDRESS] = &tlv_global_ipv6_address_ops,
		[ISIS_TLV_MT_IP_REACH] = &tlv_extended_ip_reach_ops,
		[ISIS_TLV_IPV6_REACH] = &tlv_ipv6_reach_ops,
		[ISIS_TLV_MT_IPV6_REACH] = &tlv_ipv6_reach_ops,
		[ISIS_TLV_THREE_WAY_ADJ] = &tlv_threeway_adj_ops,
		[ISIS_TLV_ROUTER_CAPABILITY] = &tlv_router_cap_ops,
		[ISIS_TLV_SRV6_LOCATOR] = &tlv_srv6_locator_ops,
	},
	[ISIS_CONTEXT_SUBTLV_NE_REACH] = {},
	[ISIS_CONTEXT_SUBTLV_IP_REACH] = {
		[ISIS_SUBTLV_PREFIX_SID] = &tlv_prefix_sid_ops,
	},
	[ISIS_CONTEXT_SUBTLV_IPV6_REACH] = {
		[ISIS_SUBTLV_PREFIX_SID] = &tlv_prefix_sid_ops,
		[ISIS_SUBTLV_IPV6_SOURCE_PREFIX] = &subtlv_ipv6_source_prefix_ops,
	},
	[ISIS_CONTEXT_SUBTLV_SRV6_LOCATOR] = {
		[ISIS_SUBTLV_SRV6_END_SID] = &tlv_srv6_end_sid_ops,
	},
	[ISIS_CONTEXT_SUBSUBTLV_SRV6_END_SID] = {
		[ISIS_SUBSUBTLV_SRV6_SID_STRUCTURE] = &subsubtlv_srv6_sid_structure_ops,
	},
	[ISIS_CONTEXT_SUBSUBTLV_SRV6_ENDX_SID] = {
		[ISIS_SUBSUBTLV_SRV6_SID_STRUCTURE] = &subsubtlv_srv6_sid_structure_ops,
	},
	[ISIS_CONTEXT_SUBSUBTLV_SRV6_LAN_ENDX_SID] = {
		[ISIS_SUBSUBTLV_SRV6_SID_STRUCTURE] = &subsubtlv_srv6_sid_structure_ops,
	}
};

/* Accessor functions */

void isis_tlvs_add_auth(struct isis_tlvs *tlvs, struct isis_passwd *passwd)
{
	free_items(ISIS_CONTEXT_LSP, ISIS_TLV_AUTH, &tlvs->isis_auth);
	init_item_list(&tlvs->isis_auth);

	if (passwd->type == ISIS_PASSWD_TYPE_UNUSED)
		return;

	struct isis_auth *auth = XCALLOC(MTYPE_ISIS_TLV, sizeof(*auth));

	auth->type = passwd->type;

	auth->plength = passwd->len;
	memcpy(auth->passwd, passwd->passwd,
	       MIN(sizeof(auth->passwd), sizeof(passwd->passwd)));

	if (auth->type == ISIS_PASSWD_TYPE_CLEARTXT) {
		auth->length = passwd->len;
		memcpy(auth->value, passwd->passwd,
		       MIN(sizeof(auth->value), sizeof(passwd->passwd)));
	}

	append_item(&tlvs->isis_auth, (struct isis_item *)auth);
}

void isis_tlvs_add_area_addresses(struct isis_tlvs *tlvs,
				  struct list *addresses)
{
	struct listnode *node;
	struct iso_address *area_addr;

	for (ALL_LIST_ELEMENTS_RO(addresses, node, area_addr)) {
		struct isis_area_address *a =
			XCALLOC(MTYPE_ISIS_TLV, sizeof(*a));

		a->len = area_addr->addr_len;
		memcpy(a->addr, area_addr->area_addr, ISO_ADDR_SIZE);
		append_item(&tlvs->area_addresses, (struct isis_item *)a);
	}
}

void isis_tlvs_add_lan_neighbors(struct isis_tlvs *tlvs, struct list *neighbors)
{
	struct listnode *node;
	uint8_t *snpa;

	for (ALL_LIST_ELEMENTS_RO(neighbors, node, snpa)) {
		struct isis_lan_neighbor *n =
			XCALLOC(MTYPE_ISIS_TLV, sizeof(*n));

		memcpy(n->mac, snpa, 6);
		append_item(&tlvs->lan_neighbor, (struct isis_item *)n);
	}
}

void isis_tlvs_set_protocols_supported(struct isis_tlvs *tlvs,
				       struct nlpids *nlpids)
{
	tlvs->protocols_supported.count = nlpids->count;
	XFREE(MTYPE_ISIS_TLV, tlvs->protocols_supported.protocols);
	if (nlpids->count) {
		tlvs->protocols_supported.protocols =
			XCALLOC(MTYPE_ISIS_TLV, nlpids->count);
		memcpy(tlvs->protocols_supported.protocols, nlpids->nlpids,
		       nlpids->count);
	} else {
		tlvs->protocols_supported.protocols = NULL;
	}
}

void isis_tlvs_add_mt_router_info(struct isis_tlvs *tlvs, uint16_t mtid,
				  bool overload, bool attached)
{
	struct isis_mt_router_info *i = XCALLOC(MTYPE_ISIS_TLV, sizeof(*i));

	i->overload = overload;
	i->attached = attached;
	i->mtid = mtid;
	append_item(&tlvs->mt_router_info, (struct isis_item *)i);
}

void isis_tlvs_add_ipv4_address(struct isis_tlvs *tlvs, struct in_addr *addr)
{
	struct isis_ipv4_address *a = XCALLOC(MTYPE_ISIS_TLV, sizeof(*a));
	a->addr = *addr;
	append_item(&tlvs->ipv4_address, (struct isis_item *)a);
}


void isis_tlvs_add_ipv4_addresses(struct isis_tlvs *tlvs,
				  struct list *addresses)
{
	struct listnode *node;
	struct prefix_ipv4 *ip_addr;
	unsigned int addr_count = 0;

	for (ALL_LIST_ELEMENTS_RO(addresses, node, ip_addr)) {
		isis_tlvs_add_ipv4_address(tlvs, &ip_addr->prefix);
		addr_count++;
		if (addr_count >= 63)
			break;
	}
}

void isis_tlvs_add_ipv6_addresses(struct isis_tlvs *tlvs,
				  struct list *addresses)
{
	struct listnode *node;
	struct prefix_ipv6 *ip_addr;
	unsigned int addr_count = 0;

	for (ALL_LIST_ELEMENTS_RO(addresses, node, ip_addr)) {
		if (addr_count >= 15)
			break;

		struct isis_ipv6_address *a =
			XCALLOC(MTYPE_ISIS_TLV, sizeof(*a));

		a->addr = ip_addr->prefix;
		append_item(&tlvs->ipv6_address, (struct isis_item *)a);
		addr_count++;
	}
}

void isis_tlvs_add_global_ipv6_addresses(struct isis_tlvs *tlvs,
					 struct list *addresses)
{
	struct listnode *node;
	struct prefix_ipv6 *ip_addr;
	unsigned int addr_count = 0;

	for (ALL_LIST_ELEMENTS_RO(addresses, node, ip_addr)) {
		if (addr_count >= 15)
			break;

		struct isis_ipv6_address *a =
			XCALLOC(MTYPE_ISIS_TLV, sizeof(*a));

		a->addr = ip_addr->prefix;
		append_item(&tlvs->global_ipv6_address, (struct isis_item *)a);
		addr_count++;
	}
}

typedef bool (*auth_validator_func)(struct isis_passwd *passwd,
				    struct stream *stream,
				    struct isis_auth *auth, bool is_lsp);

static bool auth_validator_cleartxt(struct isis_passwd *passwd,
				    struct stream *stream,
				    struct isis_auth *auth, bool is_lsp)
{
	return (auth->length == passwd->len
		&& !memcmp(auth->value, passwd->passwd, passwd->len));
}

static bool auth_validator_hmac_md5(struct isis_passwd *passwd,
				    struct stream *stream,
				    struct isis_auth *auth, bool is_lsp)
{
	uint8_t digest[16];
	uint16_t checksum;
	uint16_t rem_lifetime;

	if (is_lsp)
		safe_auth_md5(stream, &checksum, &rem_lifetime);

	memset(STREAM_DATA(stream) + auth->offset, 0, 16);
#ifdef CRYPTO_OPENSSL
	uint8_t *result = (uint8_t *)HMAC(EVP_md5(), passwd->passwd,
					  passwd->len, STREAM_DATA(stream),
					  stream_get_endp(stream), NULL, NULL);

	memcpy(digest, result, 16);
#elif CRYPTO_INTERNAL
	hmac_md5(STREAM_DATA(stream), stream_get_endp(stream), passwd->passwd,
		 passwd->len, digest);
#endif
	memcpy(STREAM_DATA(stream) + auth->offset, auth->value, 16);

	bool rv = !memcmp(digest, auth->value, 16);

	if (is_lsp)
		restore_auth_md5(stream, checksum, rem_lifetime);

	return rv;
}

static const auth_validator_func auth_validators[] = {
		[ISIS_PASSWD_TYPE_CLEARTXT] = auth_validator_cleartxt,
		[ISIS_PASSWD_TYPE_HMAC_MD5] = auth_validator_hmac_md5,
};

int isis_tlvs_auth_is_valid(struct isis_tlvs *tlvs, struct isis_passwd *passwd,
			    struct stream *stream, bool is_lsp)
{
	/* If no auth is set, always pass authentication */
	if (!passwd->type)
		return ISIS_AUTH_OK;

	/* If we don't known how to validate the auth, return invalid */
	if (passwd->type >= array_size(auth_validators)
	    || !auth_validators[passwd->type])
		return ISIS_AUTH_NO_VALIDATOR;

	struct isis_auth *auth_head = (struct isis_auth *)tlvs->isis_auth.head;
	struct isis_auth *auth;
	for (auth = auth_head; auth; auth = auth->next) {
		if (auth->type == passwd->type)
			break;
	}

	/* If matching auth TLV could not be found, return invalid */
	if (!auth)
		return ISIS_AUTH_TYPE_FAILURE;


	/* Perform validation and return result */
	if (auth_validators[passwd->type](passwd, stream, auth, is_lsp))
		return ISIS_AUTH_OK;
	else
		return ISIS_AUTH_FAILURE;
}

bool isis_tlvs_area_addresses_match(struct isis_tlvs *tlvs,
				    struct list *addresses)
{
	struct isis_area_address *addr_head;

	addr_head = (struct isis_area_address *)tlvs->area_addresses.head;
	for (struct isis_area_address *addr = addr_head; addr;
	     addr = addr->next) {
		struct listnode *node;
		struct iso_address *a;

		for (ALL_LIST_ELEMENTS_RO(addresses, node, a)) {
			if (a->addr_len == addr->len
			    && !memcmp(a->area_addr, addr->addr, addr->len))
				return true;
		}
	}

	return false;
}

static void tlvs_area_addresses_to_adj(struct isis_tlvs *tlvs,
				       struct isis_adjacency *adj,
				       bool *changed)
{
	if (adj->area_address_count != tlvs->area_addresses.count) {
		uint32_t oc = adj->area_address_count;

		*changed = true;
		adj->area_address_count = tlvs->area_addresses.count;
		adj->area_addresses = XREALLOC(
			MTYPE_ISIS_ADJACENCY_INFO, adj->area_addresses,
			adj->area_address_count * sizeof(*adj->area_addresses));

		for (; oc < adj->area_address_count; oc++) {
			adj->area_addresses[oc].addr_len = 0;
			memset(&adj->area_addresses[oc].area_addr, 0,
			       sizeof(adj->area_addresses[oc].area_addr));
		}
	}

	struct isis_area_address *addr = NULL;
	for (unsigned int i = 0; i < tlvs->area_addresses.count; i++) {
		if (!addr)
			addr = (struct isis_area_address *)
				       tlvs->area_addresses.head;
		else
			addr = addr->next;

		if (adj->area_addresses[i].addr_len == addr->len
		    && !memcmp(adj->area_addresses[i].area_addr, addr->addr,
			       addr->len)) {
			continue;
		}

		*changed = true;
		adj->area_addresses[i].addr_len = addr->len;
		memcpy(adj->area_addresses[i].area_addr, addr->addr, addr->len);
	}
}

static void tlvs_protocols_supported_to_adj(struct isis_tlvs *tlvs,
					    struct isis_adjacency *adj,
					    bool *changed)
{
	bool ipv4_supported = false, ipv6_supported = false;

	for (uint8_t i = 0; i < tlvs->protocols_supported.count; i++) {
		if (tlvs->protocols_supported.protocols[i] == NLPID_IP)
			ipv4_supported = true;
		if (tlvs->protocols_supported.protocols[i] == NLPID_IPV6)
			ipv6_supported = true;
	}

	struct nlpids reduced = {};

	if (ipv4_supported && ipv6_supported) {
		reduced.count = 2;
		reduced.nlpids[0] = NLPID_IP;
		reduced.nlpids[1] = NLPID_IPV6;
	} else if (ipv4_supported) {
		reduced.count = 1;
		reduced.nlpids[0] = NLPID_IP;
	} else if (ipv6_supported) {
		reduced.count = 1;
		reduced.nlpids[0] = NLPID_IPV6;
	} else {
		reduced.count = 0;
	}

	if (adj->nlpids.count == reduced.count
	    && !memcmp(adj->nlpids.nlpids, reduced.nlpids, reduced.count))
		return;

	*changed = true;
	adj->nlpids.count = reduced.count;
	memcpy(adj->nlpids.nlpids, reduced.nlpids, reduced.count);
}

DEFINE_HOOK(isis_adj_ip_enabled_hook,
	    (struct isis_adjacency * adj, int family, bool global),
	    (adj, family, global));
DEFINE_HOOK(isis_adj_ip_disabled_hook,
	    (struct isis_adjacency * adj, int family, bool global),
	    (adj, family, global));

static void tlvs_ipv4_addresses_to_adj(struct isis_tlvs *tlvs,
				       struct isis_adjacency *adj,
				       bool *changed)
{
	bool ipv4_enabled = false;

	if (adj->ipv4_address_count == 0 && tlvs->ipv4_address.count > 0)
		ipv4_enabled = true;
	else if (adj->ipv4_address_count > 0 && tlvs->ipv4_address.count == 0)
		hook_call(isis_adj_ip_disabled_hook, adj, AF_INET, false);

	if (adj->ipv4_address_count != tlvs->ipv4_address.count) {
		uint32_t oc = adj->ipv4_address_count;

		*changed = true;
		adj->ipv4_address_count = tlvs->ipv4_address.count;
		adj->ipv4_addresses = XREALLOC(
			MTYPE_ISIS_ADJACENCY_INFO, adj->ipv4_addresses,
			adj->ipv4_address_count * sizeof(*adj->ipv4_addresses));

		for (; oc < adj->ipv4_address_count; oc++) {
			memset(&adj->ipv4_addresses[oc], 0,
			       sizeof(adj->ipv4_addresses[oc]));
		}
	}

	struct isis_ipv4_address *addr = NULL;
	for (unsigned int i = 0; i < tlvs->ipv4_address.count; i++) {
		if (!addr)
			addr = (struct isis_ipv4_address *)
				       tlvs->ipv4_address.head;
		else
			addr = addr->next;

		if (!memcmp(&adj->ipv4_addresses[i], &addr->addr,
			    sizeof(addr->addr)))
			continue;

		*changed = true;
		adj->ipv4_addresses[i] = addr->addr;
	}

	if (ipv4_enabled)
		hook_call(isis_adj_ip_enabled_hook, adj, AF_INET, false);
}

static void tlvs_ipv6_addresses_to_adj(struct isis_tlvs *tlvs,
				       struct isis_adjacency *adj,
				       bool *changed)
{
	bool ipv6_enabled = false;

	if (adj->ll_ipv6_count == 0 && tlvs->ipv6_address.count > 0)
		ipv6_enabled = true;
	else if (adj->ll_ipv6_count > 0 && tlvs->ipv6_address.count == 0)
		hook_call(isis_adj_ip_disabled_hook, adj, AF_INET6, false);

	if (adj->ll_ipv6_count != tlvs->ipv6_address.count) {
		uint32_t oc = adj->ll_ipv6_count;

		*changed = true;
		adj->ll_ipv6_count = tlvs->ipv6_address.count;
		adj->ll_ipv6_addrs = XREALLOC(
			MTYPE_ISIS_ADJACENCY_INFO, adj->ll_ipv6_addrs,
			adj->ll_ipv6_count * sizeof(*adj->ll_ipv6_addrs));

		for (; oc < adj->ll_ipv6_count; oc++) {
			memset(&adj->ll_ipv6_addrs[oc], 0,
			       sizeof(adj->ll_ipv6_addrs[oc]));
		}
	}

	struct isis_ipv6_address *addr = NULL;
	for (unsigned int i = 0; i < tlvs->ipv6_address.count; i++) {
		if (!addr)
			addr = (struct isis_ipv6_address *)
				       tlvs->ipv6_address.head;
		else
			addr = addr->next;

		if (!memcmp(&adj->ll_ipv6_addrs[i], &addr->addr,
			    sizeof(addr->addr)))
			continue;

		*changed = true;
		adj->ll_ipv6_addrs[i] = addr->addr;
	}

	if (ipv6_enabled)
		hook_call(isis_adj_ip_enabled_hook, adj, AF_INET6, false);
}


static void tlvs_global_ipv6_addresses_to_adj(struct isis_tlvs *tlvs,
					      struct isis_adjacency *adj,
					      bool *changed)
{
	bool global_ipv6_enabled = false;

	if (adj->global_ipv6_count == 0 && tlvs->global_ipv6_address.count > 0)
		global_ipv6_enabled = true;
	else if (adj->global_ipv6_count > 0
		 && tlvs->global_ipv6_address.count == 0)
		hook_call(isis_adj_ip_disabled_hook, adj, AF_INET6, true);

	if (adj->global_ipv6_count != tlvs->global_ipv6_address.count) {
		uint32_t oc = adj->global_ipv6_count;

		*changed = true;
		adj->global_ipv6_count = tlvs->global_ipv6_address.count;
		adj->global_ipv6_addrs = XREALLOC(
			MTYPE_ISIS_ADJACENCY_INFO, adj->global_ipv6_addrs,
			adj->global_ipv6_count
				* sizeof(*adj->global_ipv6_addrs));

		for (; oc < adj->global_ipv6_count; oc++) {
			memset(&adj->global_ipv6_addrs[oc], 0,
			       sizeof(adj->global_ipv6_addrs[oc]));
		}
	}

	struct isis_ipv6_address *addr = NULL;
	for (unsigned int i = 0; i < tlvs->global_ipv6_address.count; i++) {
		if (!addr)
			addr = (struct isis_ipv6_address *)
				       tlvs->global_ipv6_address.head;
		else
			addr = addr->next;

		if (!memcmp(&adj->global_ipv6_addrs[i], &addr->addr,
			    sizeof(addr->addr)))
			continue;

		*changed = true;
		adj->global_ipv6_addrs[i] = addr->addr;
	}

	if (global_ipv6_enabled)
		hook_call(isis_adj_ip_enabled_hook, adj, AF_INET6, true);
}

void isis_tlvs_to_adj(struct isis_tlvs *tlvs, struct isis_adjacency *adj,
		      bool *changed)
{
	*changed = false;

	tlvs_area_addresses_to_adj(tlvs, adj, changed);
	tlvs_protocols_supported_to_adj(tlvs, adj, changed);
	tlvs_ipv4_addresses_to_adj(tlvs, adj, changed);
	tlvs_ipv6_addresses_to_adj(tlvs, adj, changed);
	tlvs_global_ipv6_addresses_to_adj(tlvs, adj, changed);
}

bool isis_tlvs_own_snpa_found(struct isis_tlvs *tlvs, uint8_t *snpa)
{
	struct isis_lan_neighbor *ne_head;

	ne_head = (struct isis_lan_neighbor *)tlvs->lan_neighbor.head;
	for (struct isis_lan_neighbor *ne = ne_head; ne; ne = ne->next) {
		if (!memcmp(ne->mac, snpa, ETH_ALEN))
			return true;
	}

	return false;
}

void isis_tlvs_add_lsp_entry(struct isis_tlvs *tlvs, struct isis_lsp *lsp)
{
	struct isis_lsp_entry *entry = XCALLOC(MTYPE_ISIS_TLV, sizeof(*entry));

	entry->rem_lifetime = lsp->hdr.rem_lifetime;
	memcpy(entry->id, lsp->hdr.lsp_id, ISIS_SYS_ID_LEN + 2);
	entry->checksum = lsp->hdr.checksum;
	entry->seqno = lsp->hdr.seqno;
	entry->lsp = lsp;

	append_item(&tlvs->lsp_entries, (struct isis_item *)entry);
}

void isis_tlvs_add_csnp_entries(struct isis_tlvs *tlvs, uint8_t *start_id,
				uint8_t *stop_id, uint16_t num_lsps,
				struct lspdb_head *head,
				struct isis_lsp **last_lsp)
{
	struct isis_lsp searchfor;
	struct isis_lsp *first, *lsp;

	memcpy(&searchfor.hdr.lsp_id, start_id, sizeof(searchfor.hdr.lsp_id));
	first = lspdb_find_gteq(head, &searchfor);
	if (!first)
		return;

	frr_each_from (lspdb, head, lsp, first) {
		if (memcmp(lsp->hdr.lsp_id, stop_id, sizeof(lsp->hdr.lsp_id))
			> 0 || tlvs->lsp_entries.count == num_lsps)
			break;

		isis_tlvs_add_lsp_entry(tlvs, lsp);
		*last_lsp = lsp;
	}
}

void isis_tlvs_set_dynamic_hostname(struct isis_tlvs *tlvs,
				    const char *hostname)
{
	XFREE(MTYPE_ISIS_TLV, tlvs->hostname);
	if (hostname)
		tlvs->hostname = XSTRDUP(MTYPE_ISIS_TLV, hostname);
}

/* Init Router Capability TLV parameters */
struct isis_router_cap *isis_tlvs_init_router_capability(struct isis_tlvs *tlvs)
{
	tlvs->router_cap = XCALLOC(MTYPE_ISIS_TLV, sizeof(*tlvs->router_cap));

	/* init SR algo list content to the default value */
	for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
		tlvs->router_cap->algo[i] = SR_ALGORITHM_UNSET;

	return tlvs->router_cap;
}

#ifndef FABRICD
void isis_tlvs_set_router_capability_fad(struct isis_tlvs *tlvs,
					 struct flex_algo *fa, int algorithm,
					 uint8_t *sysid)
{
	struct isis_router_cap_fad *rcap_fad;

	assert(tlvs->router_cap);

	rcap_fad = tlvs->router_cap->fads[algorithm];

	if (!rcap_fad)
		rcap_fad = XCALLOC(MTYPE_ISIS_TLV,
				   sizeof(struct isis_router_cap_fad));

	memset(rcap_fad->sysid, 0, ISIS_SYS_ID_LEN + 2);
	memcpy(rcap_fad->sysid, sysid, ISIS_SYS_ID_LEN);

	memcpy(&rcap_fad->fad, fa, sizeof(struct flex_algo));

	rcap_fad->fad.admin_group_exclude_any.bitmap.data = NULL;
	rcap_fad->fad.admin_group_include_any.bitmap.data = NULL;
	rcap_fad->fad.admin_group_include_all.bitmap.data = NULL;

	admin_group_copy(&rcap_fad->fad.admin_group_exclude_any,
			 &fa->admin_group_exclude_any);
	admin_group_copy(&rcap_fad->fad.admin_group_include_any,
			 &fa->admin_group_include_any);
	admin_group_copy(&rcap_fad->fad.admin_group_include_all,
			 &fa->admin_group_include_all);

	tlvs->router_cap->fads[algorithm] = rcap_fad;
}
#endif /* ifndef FABRICD */

int isis_tlvs_sr_algo_count(const struct isis_router_cap *cap)
{
	int count = 0;

	for (int i = 0; i < SR_ALGORITHM_COUNT; i++)
		if (cap->algo[i] != SR_ALGORITHM_UNSET)
			count++;
	return count;
}

void isis_tlvs_set_te_router_id(struct isis_tlvs *tlvs,
				const struct in_addr *id)
{
	XFREE(MTYPE_ISIS_TLV, tlvs->te_router_id);
	if (!id)
		return;
	tlvs->te_router_id = XCALLOC(MTYPE_ISIS_TLV, sizeof(*id));
	memcpy(tlvs->te_router_id, id, sizeof(*id));
}

void isis_tlvs_set_te_router_id_ipv6(struct isis_tlvs *tlvs,
				     const struct in6_addr *id)
{
	XFREE(MTYPE_ISIS_TLV, tlvs->te_router_id_ipv6);
	if (!id)
		return;
	tlvs->te_router_id_ipv6 = XCALLOC(MTYPE_ISIS_TLV, sizeof(*id));
	memcpy(tlvs->te_router_id_ipv6, id, sizeof(*id));
}

void isis_tlvs_add_oldstyle_ip_reach(struct isis_tlvs *tlvs,
				     struct prefix_ipv4 *dest, uint8_t metric)
{
	struct isis_oldstyle_ip_reach *r = XCALLOC(MTYPE_ISIS_TLV, sizeof(*r));

	r->metric = metric;
	memcpy(&r->prefix, dest, sizeof(*dest));
	apply_mask_ipv4(&r->prefix);
	append_item(&tlvs->oldstyle_ip_reach, (struct isis_item *)r);
}

/* Add IS-IS SR Adjacency-SID subTLVs */
void isis_tlvs_add_adj_sid(struct isis_ext_subtlvs *exts,
			   struct isis_adj_sid *adj)
{
	append_item(&exts->adj_sid, (struct isis_item *)adj);
	SET_SUBTLV(exts, EXT_ADJ_SID);
}

/* Delete IS-IS SR Adjacency-SID subTLVs */
void isis_tlvs_del_adj_sid(struct isis_ext_subtlvs *exts,
			   struct isis_adj_sid *adj)
{
	delete_item(&exts->adj_sid, (struct isis_item *)adj);
	XFREE(MTYPE_ISIS_SUBTLV, adj);
	if (exts->adj_sid.count == 0)
		UNSET_SUBTLV(exts, EXT_ADJ_SID);
}

/* Add IS-IS SR LAN-Adjacency-SID subTLVs */
void isis_tlvs_add_lan_adj_sid(struct isis_ext_subtlvs *exts,
			       struct isis_lan_adj_sid *lan)
{
	append_item(&exts->lan_sid, (struct isis_item *)lan);
	SET_SUBTLV(exts, EXT_LAN_ADJ_SID);
}

/* Delete IS-IS SR LAN-Adjacency-SID subTLVs */
void isis_tlvs_del_lan_adj_sid(struct isis_ext_subtlvs *exts,
			       struct isis_lan_adj_sid *lan)
{
	delete_item(&exts->lan_sid, (struct isis_item *)lan);
	XFREE(MTYPE_ISIS_SUBTLV, lan);
	if (exts->lan_sid.count == 0)
		UNSET_SUBTLV(exts, EXT_LAN_ADJ_SID);
}

/* Add IS-IS SRv6 End.X SID subTLVs */
void isis_tlvs_add_srv6_endx_sid(struct isis_ext_subtlvs *exts,
				 struct isis_srv6_endx_sid_subtlv *adj)
{
	append_item(&exts->srv6_endx_sid, (struct isis_item *)adj);
	SET_SUBTLV(exts, EXT_SRV6_ENDX_SID);
}

/* Delete IS-IS SRv6 End.X SID subTLVs */
void isis_tlvs_del_srv6_endx_sid(struct isis_ext_subtlvs *exts,
				 struct isis_srv6_endx_sid_subtlv *adj)
{
	isis_free_subsubtlvs(adj->subsubtlvs);
	delete_item(&exts->srv6_endx_sid, (struct isis_item *)adj);
	XFREE(MTYPE_ISIS_SUBTLV, adj);
	if (exts->srv6_endx_sid.count == 0)
		UNSET_SUBTLV(exts, EXT_SRV6_ENDX_SID);
}

/* Add IS-IS SRv6 LAN End.X SID subTLVs */
void isis_tlvs_add_srv6_lan_endx_sid(struct isis_ext_subtlvs *exts,
				     struct isis_srv6_lan_endx_sid_subtlv *lan)
{
	append_item(&exts->srv6_lan_endx_sid, (struct isis_item *)lan);
	SET_SUBTLV(exts, EXT_SRV6_LAN_ENDX_SID);
}

/* Delete IS-IS SRv6 LAN End.X SID subTLVs */
void isis_tlvs_del_srv6_lan_endx_sid(struct isis_ext_subtlvs *exts,
				     struct isis_srv6_lan_endx_sid_subtlv *lan)
{
	isis_free_subsubtlvs(lan->subsubtlvs);
	delete_item(&exts->srv6_lan_endx_sid, (struct isis_item *)lan);
	XFREE(MTYPE_ISIS_SUBTLV, lan);
	if (exts->srv6_lan_endx_sid.count == 0)
		UNSET_SUBTLV(exts, EXT_SRV6_LAN_ENDX_SID);
}

void isis_tlvs_del_asla_flex_algo(struct isis_ext_subtlvs *ext,
				  struct isis_asla_subtlvs *asla)
{
	admin_group_term(&asla->ext_admin_group);
	listnode_delete(ext->aslas, asla);
	XFREE(MTYPE_ISIS_SUBTLV, asla);
}

struct isis_asla_subtlvs *
isis_tlvs_find_alloc_asla(struct isis_ext_subtlvs *ext, uint8_t standard_apps)
{
	struct isis_asla_subtlvs *asla;
	struct listnode *node;

	if (!list_isempty(ext->aslas)) {
		for (ALL_LIST_ELEMENTS_RO(ext->aslas, node, asla)) {
			if (CHECK_FLAG(asla->standard_apps, standard_apps))
				return asla;
		}
	}

	asla = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(struct isis_asla_subtlvs));
	admin_group_init(&asla->ext_admin_group);
	SET_FLAG(asla->standard_apps, standard_apps);
	SET_FLAG(asla->user_def_apps, standard_apps);
	asla->standard_apps_length = ASLA_APP_IDENTIFIER_BIT_LENGTH;
	asla->user_def_apps_length = ASLA_APP_IDENTIFIER_BIT_LENGTH;

	listnode_add(ext->aslas, asla);
	return asla;
}

void isis_tlvs_free_asla(struct isis_ext_subtlvs *ext, uint8_t standard_apps)
{
	struct isis_asla_subtlvs *asla;
	struct listnode *node;

	if (!ext)
		return;

	for (ALL_LIST_ELEMENTS_RO(ext->aslas, node, asla)) {
		if (!CHECK_FLAG(asla->standard_apps, standard_apps))
			continue;
		isis_tlvs_del_asla_flex_algo(ext, asla);
		break;
	}
}

void isis_tlvs_add_extended_ip_reach(struct isis_tlvs *tlvs,
				     struct prefix_ipv4 *dest, uint32_t metric,
				     bool external,
				     struct sr_prefix_cfg **pcfgs)
{
	struct isis_extended_ip_reach *r = XCALLOC(MTYPE_ISIS_TLV, sizeof(*r));

	r->metric = metric;
	memcpy(&r->prefix, dest, sizeof(*dest));
	apply_mask_ipv4(&r->prefix);

	if (pcfgs) {
		for (int i = 0; i < SR_ALGORITHM_COUNT; i++) {
			struct isis_prefix_sid *psid;
			struct sr_prefix_cfg *pcfg = pcfgs[i];

			if (!pcfg)
				continue;

			psid = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*psid));
			isis_sr_prefix_cfg2subtlv(pcfg, external, psid);

			if (!r->subtlvs)
				r->subtlvs = isis_alloc_subtlvs(
					ISIS_CONTEXT_SUBTLV_IP_REACH);
			append_item(&r->subtlvs->prefix_sids,
				    (struct isis_item *)psid);
		}
	}

	append_item(&tlvs->extended_ip_reach, (struct isis_item *)r);
}

void isis_tlvs_add_ipv6_reach(struct isis_tlvs *tlvs, uint16_t mtid,
			      struct prefix_ipv6 *dest, uint32_t metric,
			      bool external, struct sr_prefix_cfg **pcfgs)
{
	struct isis_ipv6_reach *r = XCALLOC(MTYPE_ISIS_TLV, sizeof(*r));

	r->metric = metric;
	memcpy(&r->prefix, dest, sizeof(*dest));
	apply_mask_ipv6(&r->prefix);
	if (pcfgs) {
		for (int i = 0; i < SR_ALGORITHM_COUNT; i++) {
			struct isis_prefix_sid *psid;
			struct sr_prefix_cfg *pcfg = pcfgs[i];

			if (!pcfg)
				continue;

			psid = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*psid));
			isis_sr_prefix_cfg2subtlv(pcfg, external, psid);

			if (!r->subtlvs)
				r->subtlvs = isis_alloc_subtlvs(
					ISIS_CONTEXT_SUBTLV_IPV6_REACH);
			append_item(&r->subtlvs->prefix_sids,
				    (struct isis_item *)psid);
		}
	}

	struct isis_item_list *l;
	l = (mtid == ISIS_MT_IPV4_UNICAST)
		    ? &tlvs->ipv6_reach
		    : isis_get_mt_items(&tlvs->mt_ipv6_reach, mtid);
	append_item(l, (struct isis_item *)r);
}

void isis_tlvs_add_ipv6_dstsrc_reach(struct isis_tlvs *tlvs, uint16_t mtid,
				     struct prefix_ipv6 *dest,
				     struct prefix_ipv6 *src,
				     uint32_t metric)
{
	isis_tlvs_add_ipv6_reach(tlvs, mtid, dest, metric, false, NULL);
	struct isis_item_list *l = isis_get_mt_items(&tlvs->mt_ipv6_reach,
						     mtid);

	struct isis_ipv6_reach *r = (struct isis_ipv6_reach*)last_item(l);
	r->subtlvs = isis_alloc_subtlvs(ISIS_CONTEXT_SUBTLV_IPV6_REACH);
	r->subtlvs->source_prefix = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*src));
	memcpy(r->subtlvs->source_prefix, src, sizeof(*src));
}

void isis_tlvs_add_oldstyle_reach(struct isis_tlvs *tlvs, uint8_t *id,
				  uint8_t metric)
{
	struct isis_oldstyle_reach *r = XCALLOC(MTYPE_ISIS_TLV, sizeof(*r));

	r->metric = metric;
	memcpy(r->id, id, sizeof(r->id));
	append_item(&tlvs->oldstyle_reach, (struct isis_item *)r);
}

void isis_tlvs_add_extended_reach(struct isis_tlvs *tlvs, uint16_t mtid,
				  uint8_t *id, uint32_t metric,
				  struct isis_ext_subtlvs *exts)
{
	struct isis_extended_reach *r = XCALLOC(MTYPE_ISIS_TLV, sizeof(*r));

	memcpy(r->id, id, sizeof(r->id));
	r->metric = metric;
	if (exts)
		r->subtlvs = copy_item_ext_subtlvs(exts, mtid);

	struct isis_item_list *l;
	if ((mtid == ISIS_MT_IPV4_UNICAST) || (mtid == ISIS_MT_DISABLE))
		l = &tlvs->extended_reach;
	else
		l = isis_get_mt_items(&tlvs->mt_reach, mtid);
	append_item(l, (struct isis_item *)r);
}

void isis_tlvs_add_threeway_adj(struct isis_tlvs *tlvs,
				enum isis_threeway_state state,
				uint32_t local_circuit_id,
				const uint8_t *neighbor_id,
				uint32_t neighbor_circuit_id)
{
	assert(!tlvs->threeway_adj);

	tlvs->threeway_adj = XCALLOC(MTYPE_ISIS_TLV, sizeof(*tlvs->threeway_adj));
	tlvs->threeway_adj->state = state;
	tlvs->threeway_adj->local_circuit_id = local_circuit_id;

	if (neighbor_id) {
		tlvs->threeway_adj->neighbor_set = true;
		memcpy(tlvs->threeway_adj->neighbor_id, neighbor_id, 6);
		tlvs->threeway_adj->neighbor_circuit_id = neighbor_circuit_id;
	}
}

void isis_tlvs_add_spine_leaf(struct isis_tlvs *tlvs, uint8_t tier,
			      bool has_tier, bool is_leaf, bool is_spine,
			      bool is_backup)
{
	assert(!tlvs->spine_leaf);

	tlvs->spine_leaf = XCALLOC(MTYPE_ISIS_TLV, sizeof(*tlvs->spine_leaf));

	if (has_tier) {
		tlvs->spine_leaf->tier = tier;
	}

	tlvs->spine_leaf->has_tier = has_tier;
	tlvs->spine_leaf->is_leaf = is_leaf;
	tlvs->spine_leaf->is_spine = is_spine;
	tlvs->spine_leaf->is_backup = is_backup;
}

struct isis_mt_router_info *
isis_tlvs_lookup_mt_router_info(struct isis_tlvs *tlvs, uint16_t mtid)
{
	if (!tlvs || tlvs->mt_router_info_empty)
		return NULL;

	struct isis_mt_router_info *rv;
	for (rv = (struct isis_mt_router_info *)tlvs->mt_router_info.head; rv;
	     rv = rv->next) {
		if (rv->mtid == mtid)
			return rv;
	}

	return NULL;
}

void isis_tlvs_set_purge_originator(struct isis_tlvs *tlvs,
				    const uint8_t *generator,
				    const uint8_t *sender)
{
	assert(!tlvs->purge_originator);

	tlvs->purge_originator = XCALLOC(MTYPE_ISIS_TLV,
					 sizeof(*tlvs->purge_originator));
	memcpy(tlvs->purge_originator->generator, generator,
	       sizeof(tlvs->purge_originator->generator));
	if (sender) {
		tlvs->purge_originator->sender_set = true;
		memcpy(tlvs->purge_originator->sender, sender,
		       sizeof(tlvs->purge_originator->sender));
	}
}

/* Set SRv6 SID Structure Sub-Sub-TLV parameters */
void isis_subsubtlvs_set_srv6_sid_structure(struct isis_subsubtlvs *subsubtlvs,
					    struct isis_srv6_sid *sid)
{
	assert(!subsubtlvs->srv6_sid_structure);

	subsubtlvs->srv6_sid_structure = XCALLOC(
		MTYPE_ISIS_SUBSUBTLV, sizeof(*subsubtlvs->srv6_sid_structure));

	isis_srv6_sid_structure2subsubtlv(sid, subsubtlvs->srv6_sid_structure);
}

/* Add an SRv6 End SID to the SRv6 End SID Sub-TLV */
void isis_subtlvs_add_srv6_end_sid(struct isis_subtlvs *subtlvs,
				   struct isis_srv6_sid *sid)
{
	struct isis_srv6_end_sid_subtlv *sid_subtlv;

	if (!sid)
		return;

	/* The SRv6 End SID Sub-TLV advertises SRv6 SIDs with Endpoint behaviors
	 * that do not require a particular neighbor in order to be correctly
	 * applied (e.g. End, End.DT6, ...). Before proceeding, let's make sure
	 * we are encoding one of the supported behaviors. */
	if (sid->behavior != SRV6_ENDPOINT_BEHAVIOR_END &&
	    sid->behavior != SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID &&
	    sid->behavior != SRV6_ENDPOINT_BEHAVIOR_END_DT6 &&
	    sid->behavior != SRV6_ENDPOINT_BEHAVIOR_END_DT6_USID &&
	    sid->behavior != SRV6_ENDPOINT_BEHAVIOR_END_DT4 &&
	    sid->behavior != SRV6_ENDPOINT_BEHAVIOR_END_DT4_USID &&
	    sid->behavior != SRV6_ENDPOINT_BEHAVIOR_END_DT46 &&
	    sid->behavior != SRV6_ENDPOINT_BEHAVIOR_END_DT46_USID)
		return;

	/* Allocate memory for the Sub-TLV */
	sid_subtlv = XCALLOC(MTYPE_ISIS_SUBTLV, sizeof(*sid_subtlv));

	/* Fill in the SRv6 End SID Sub-TLV according to the SRv6 SID
	 * configuration */
	isis_srv6_end_sid2subtlv(sid, sid_subtlv);

	/* Add the SRv6 SID Structure Sub-Sub-TLV */
	sid_subtlv->subsubtlvs =
		isis_alloc_subsubtlvs(ISIS_CONTEXT_SUBSUBTLV_SRV6_END_SID);
	isis_subsubtlvs_set_srv6_sid_structure(sid_subtlv->subsubtlvs, sid);

	/* Append the SRv6 End SID Sub-TLV to the Sub-TLVs list */
	append_item(&subtlvs->srv6_end_sids, (struct isis_item *)sid_subtlv);
}

/* Add an SRv6 Locator to the SRv6 Locator TLV */
void isis_tlvs_add_srv6_locator(struct isis_tlvs *tlvs, uint16_t mtid,
				struct isis_srv6_locator *loc)
{
	bool subtlvs_present = false;
	struct listnode *node;
	struct isis_srv6_sid *sid;
	struct isis_srv6_locator_tlv *loc_tlv =
		XCALLOC(MTYPE_ISIS_TLV, sizeof(*loc_tlv));

	/* Fill in the SRv6 Locator TLV according to the SRv6 Locator
	 * configuration */
	isis_srv6_locator2tlv(loc, loc_tlv);

	/* Add the SRv6 End SID Sub-TLVs */
	loc_tlv->subtlvs = isis_alloc_subtlvs(ISIS_CONTEXT_SUBTLV_SRV6_LOCATOR);
	for (ALL_LIST_ELEMENTS_RO(loc->srv6_sid, node, sid)) {
		if (sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END ||
		    sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID ||
		    sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_DT6 ||
		    sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_DT6_USID ||
		    sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_DT4 ||
		    sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_DT4_USID ||
		    sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_DT46 ||
		    sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_DT46_USID) {
			isis_subtlvs_add_srv6_end_sid(loc_tlv->subtlvs, sid);
			subtlvs_present = true;
		}
	}

	if (!subtlvs_present) {
		isis_free_subtlvs(loc_tlv->subtlvs);
		loc_tlv->subtlvs = NULL;
	}

	/* Append the SRv6 Locator TLV to the TLVs list */
	struct isis_item_list *l;
	l = isis_get_mt_items(&tlvs->srv6_locator, mtid);
	append_item(l, (struct isis_item *)loc_tlv);
}
