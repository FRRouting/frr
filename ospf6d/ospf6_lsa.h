// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#ifndef OSPF6_LSA_H
#define OSPF6_LSA_H
#include "ospf6_top.h"
#include "lib/json.h"

/* Debug option */
#define OSPF6_LSA_DEBUG           0x01
#define OSPF6_LSA_DEBUG_ORIGINATE 0x02
#define OSPF6_LSA_DEBUG_EXAMIN    0x04
#define OSPF6_LSA_DEBUG_FLOOD     0x08
#define OSPF6_LSA_DEBUG_ALL                                                    \
	(OSPF6_LSA_DEBUG | OSPF6_LSA_DEBUG_ORIGINATE | OSPF6_LSA_DEBUG_EXAMIN  \
	 | OSPF6_LSA_DEBUG_FLOOD)
#define OSPF6_LSA_DEBUG_AGGR      0x10

/* OSPF LSA Default metric values */
#define DEFAULT_DEFAULT_METRIC 20
#define DEFAULT_DEFAULT_ORIGINATE_METRIC 10
#define DEFAULT_DEFAULT_ALWAYS_METRIC 1
#define DEFAULT_METRIC_TYPE 2

#define IS_OSPF6_DEBUG_LSA(name)                                               \
	(ospf6_lstype_debug(htons(OSPF6_LSTYPE_##name)) & OSPF6_LSA_DEBUG)
#define IS_OSPF6_DEBUG_ORIGINATE(name)                                         \
	(ospf6_lstype_debug(htons(OSPF6_LSTYPE_##name))                        \
	 & OSPF6_LSA_DEBUG_ORIGINATE)
#define IS_OSPF6_DEBUG_EXAMIN(name)                                            \
	(ospf6_lstype_debug(htons(OSPF6_LSTYPE_##name))                        \
	 & OSPF6_LSA_DEBUG_EXAMIN)
#define IS_OSPF6_DEBUG_LSA_TYPE(type)                                          \
	(ospf6_lstype_debug(type) & OSPF6_LSA_DEBUG)
#define IS_OSPF6_DEBUG_ORIGINATE_TYPE(type)                                    \
	(ospf6_lstype_debug(type) & OSPF6_LSA_DEBUG_ORIGINATE)
#define IS_OSPF6_DEBUG_EXAMIN_TYPE(type)                                       \
	(ospf6_lstype_debug(type) & OSPF6_LSA_DEBUG_EXAMIN)
#define IS_OSPF6_DEBUG_FLOOD_TYPE(type)                                        \
	(ospf6_lstype_debug(type) & OSPF6_LSA_DEBUG_FLOOD)
#define IS_OSPF6_DEBUG_AGGR						       \
	(ospf6_lstype_debug(OSPF6_LSTYPE_AS_EXTERNAL) & OSPF6_LSA_DEBUG_AGGR)  \

/* LSA definition */

#define OSPF6_MAX_LSASIZE      4096

/* Type */
#define OSPF6_LSTYPE_UNKNOWN          0x0000
#define OSPF6_LSTYPE_ROUTER           0x2001
#define OSPF6_LSTYPE_NETWORK          0x2002
#define OSPF6_LSTYPE_INTER_PREFIX     0x2003
#define OSPF6_LSTYPE_INTER_ROUTER     0x2004
#define OSPF6_LSTYPE_AS_EXTERNAL      0x4005
#define OSPF6_LSTYPE_GROUP_MEMBERSHIP 0x2006
#define OSPF6_LSTYPE_TYPE_7           0x2007
#define OSPF6_LSTYPE_LINK             0x0008
#define OSPF6_LSTYPE_INTRA_PREFIX     0x2009
#define OSPF6_LSTYPE_GRACE_LSA	      0x000b

/* Extended LSA types from RFC 8362 */
#define OSPF6_LSTYPE_E_ROUTER         (0x20 + OSPF6_LSTYPE_ROUTER)
#define OSPF6_LSTYPE_E_NETWORK        (0x20 + OSPF6_LSTYPE_NETWORK)
#define OSPF6_LSTYPE_E_INTER_PREFIX   (0x20 + OSPF6_LSTYPE_INTER_PREFIX)
#define OSPF6_LSTYPE_E_INTER_ROUTER   (0x20 + OSPF6_LSTYPE_INTER_ROUTER)
#define OSPF6_LSTYPE_E_AS_EXTERNAL    (0x20 + OSPF6_LSTYPE_AS_EXTERNAL)
/* 0x20 + OSPF6_LSTYPE_GROUP_MEMBERSHIP is unused, not to be allocated */
#define OSPF6_LSTYPE_E_TYPE_7         (0x20 + OSPF6_LSTYPE_TYPE_7)
#define OSPF6_LSTYPE_E_LINK           (0x20 + OSPF6_LSTYPE_LINK)
#define OSPF6_LSTYPE_E_INTRA_PREFIX   (0x20 + OSPF6_LSTYPE_INTRA_PREFIX)

#define OSPF6_LSTYPE_SIZE             0x002c /* End of sparse lookup table */

/* Masks for LS Type : RFC 2740 A.4.2.1 "LS type" */
#define OSPF6_LSTYPE_UBIT_MASK        0x8000
#define OSPF6_LSTYPE_SCOPE_MASK       0x6000
#define OSPF6_LSTYPE_FCODE_MASK       0x1fff

/* LSA scope */
#define OSPF6_SCOPE_LINKLOCAL  0x0000
#define OSPF6_SCOPE_AREA       0x2000
#define OSPF6_SCOPE_AS         0x4000
#define OSPF6_SCOPE_RESERVED   0x6000

/* XXX U-bit handling should be treated here */
#define OSPF6_LSA_SCOPE(type) (ntohs(type) & OSPF6_LSTYPE_SCOPE_MASK)

/* LSA Header */
#define OSPF6_LSA_HEADER_SIZE                 20U
struct ospf6_lsa_header {
	uint16_t age;	/* LS age */
	uint16_t type;       /* LS type */
	in_addr_t id;	 /* Link State ID */
	in_addr_t adv_router; /* Advertising Router */
	uint32_t seqnum;     /* LS sequence number */
	uint16_t checksum;   /* LS checksum */
	uint16_t length;     /* LSA length */
};


static inline char *ospf6_lsa_header_end(struct ospf6_lsa_header *header)
{
	return (char *)header + sizeof(struct ospf6_lsa_header);
}

static inline void *lsa_after_header(struct ospf6_lsa_header *header)
{
	return (char *)header + sizeof(struct ospf6_lsa_header);
}

static inline char *ospf6_lsa_end(struct ospf6_lsa_header *header)
{
	return (char *)header + ntohs(header->length);
}

static inline uint16_t ospf6_lsa_size(struct ospf6_lsa_header *header)
{
	return ntohs(header->length);
}

#define OSPF6_LSA_IS_TYPE(t, L)                                                \
	((L)->header->type == htons(OSPF6_LSTYPE_##t) ? 1 : 0)
#define OSPF6_LSA_IS_SAME(L1, L2)                                              \
	((L1)->header->adv_router == (L2)->header->adv_router                  \
	 && (L1)->header->id == (L2)->header->id                               \
	 && (L1)->header->type == (L2)->header->type)
#define OSPF6_LSA_IS_MATCH(t, i, a, L)                                         \
	((L)->header->adv_router == (a) && (L)->header->id == (i)              \
	 && (L)->header->type == (t))
#define OSPF6_LSA_IS_DIFFER(L1, L2)  ospf6_lsa_is_differ (L1, L2)
#define OSPF6_LSA_IS_MAXAGE(L) (ospf6_lsa_age_current (L) == OSPF_LSA_MAXAGE)
#define OSPF6_LSA_IS_CHANGED(L1, L2) ospf6_lsa_is_changed (L1, L2)
#define OSPF6_LSA_IS_SEQWRAP(L) ((L)->header->seqnum == htonl(OSPF_MAX_SEQUENCE_NUMBER + 1))

/* Router-LSA */
#define OSPF6_ROUTER_LSA_MIN_SIZE 4U
struct ospf6_router_lsa {
	uint8_t bits;
	uint8_t options[3];
	/* followed by ospf6_router_lsdesc(s) */
};

/* Extended Router-LSA (RFC 8362)
 * struct ospf6_e_router_lsa is optionally followed by struct tlv_router_link
 * Router-Link TLV (RFC 8362)
 */
#define ospf6_e_router_lsa ospf6_router_lsa

/* Link State Description in Router-LSA */
#define OSPF6_ROUTER_LSDESC_FIX_SIZE 16U
struct ospf6_router_lsdesc {
	uint8_t type;
	uint8_t reserved;
	uint16_t metric; /* output cost */
	uint32_t interface_id;
	uint32_t neighbor_interface_id;
	in_addr_t neighbor_router_id;
};

#define OSPF6_ROUTER_LSDESC_POINTTOPOINT    1
#define OSPF6_ROUTER_LSDESC_TRANSIT_NETWORK 2
#define OSPF6_ROUTER_LSDESC_STUB_NETWORK    3
#define OSPF6_ROUTER_LSDESC_VIRTUAL_LINK    4

/* Network-LSA */
#define OSPF6_NETWORK_LSA_MIN_SIZE 4U
struct ospf6_network_lsa {
	uint8_t reserved;
	uint8_t options[3];
	/* followed by ospf6_network_lsdesc(s) */
};

/* E-Network-LSA (RFC 8362)
 * struct ospf6_e_network_lsa is followed by Attached-Routers TLV.
 * If the TLV is not included in the LSA, the LSA is malformed.
 * If multiple TLVs are included, those subsequent to the first MUST be ignored.
 */
#define ospf6_e_network_lsa ospf6_network_lsa

/* Link State Description in Network-LSA */
#define OSPF6_NETWORK_LSDESC_FIX_SIZE 4U
struct ospf6_network_lsdesc {
	in_addr_t router_id;
};
#define NETWORK_LSDESC_GET_NBR_ROUTERID(x)                                     \
	(((struct ospf6_network_lsdesc *)(x))->router_id)

/* Inter-Area-Prefix-LSA */
#define OSPF6_INTER_PREFIX_LSA_MIN_SIZE 4U /* w/o IPv6 prefix */
struct ospf6_inter_prefix_lsa {
	uint32_t metric;
	struct ospf6_prefix prefix;
};

/* E-Inter-Area-Prefix-LSA (RFC 8362)
 * LSA does not contain any 'body' fields.
 * ospf6_lsa_header MUST be directly followed by a single Inter-Area-Prefix TLV.
 */
#define ospf6_e_inter_prefix_lsa NULL

/* Inter-Area-Router-LSA */
#define OSPF6_INTER_ROUTER_LSA_FIX_SIZE 12U
struct ospf6_inter_router_lsa {
	uint8_t mbz;
	uint8_t options[3];
	uint32_t metric;
	uint32_t router_id;
};

/* E-Inter-Area-Router-LSA
 * LSA does not contain any 'body' fields.
 * ospf6_lsa_header MUST be directly followed by a single Inter-Area-Router TLV.
 */
#define ospf6_e_inter_router_lsa NULL

/* AS-External-LSA */
#define OSPF6_AS_EXTERNAL_LSA_MIN_SIZE 4U /* w/o IPv6 prefix */
struct ospf6_as_external_lsa {
	uint32_t bits_metric;

	struct ospf6_prefix prefix;
	/* followed by none or one forwarding address */
	/* followed by none or one external route tag */
	/* followed by none or one referenced LS-ID */
};

/* E-AS-External-LSA
 * MUST contain a single External-Prefix TLV
 */
#define ospf6_e_as_external_lsa ospf6_as_external_lsa

/* FIXME: move nssa lsa here. */

/* Link-LSA */
#define OSPF6_LINK_LSA_MIN_SIZE 24U /* w/o 1st IPv6 prefix */
struct ospf6_link_lsa {
	uint8_t priority;
	uint8_t options[3];
	struct in6_addr linklocal_addr;
	uint32_t prefix_num;
	/* followed by ospf6 prefix(es) */
};

/* E-Link-LSA
 * struct ospf6_e_link_lsa is followed by any of:
 * Intra-Area-Prefix TLV (zero or many MAY be included),
 * IPv6 Link-Local Address TLV (one SHOULD be included, >1 MUST be ignored),
 * IPv4 Link-Local Address TLV (one SHOULD be included, >1 MUST be ignored),
 * one of IPv4/IPv6 lladdr MUST be included.
 */
#define OSPF6_E_LINK_LSA_MIN_SIZE               4U
struct ospf6_e_link_lsa {
	uint8_t priority;
	uint8_t options[3];
	/* followed by TLVs */
};

/* Intra-Area-Prefix-LSA */
#define OSPF6_INTRA_PREFIX_LSA_MIN_SIZE 12U /* w/o 1st IPv6 prefix */
struct ospf6_intra_prefix_lsa {
	uint16_t prefix_num;
	uint16_t ref_type;
	uint32_t ref_id;
	in_addr_t ref_adv_router;
	/* followed by ospf6 prefix(es) */
};

/* E-Intra-Area-Prefix-LSA
 * Like Intra-Area-Prefix-LSA, except Referenced LS Type MUST be
 * E-Router-LSA (0xA021) or an E-Network-LSA (0xA022)
 */
#define ospf6_e_intra_prefix_lsa ospf6_intra_prefix_lsa

struct ospf6_lsa {
	char name[64]; /* dump string */

	struct route_node *rn;

	unsigned char lock; /* reference counter */
	unsigned char flag; /* special meaning (e.g. floodback) */

	struct timeval birth;      /* tv_sec when LS age 0 */
	struct timeval originated; /* used by MinLSInterval check */
	struct timeval received;   /* used by MinLSArrival check */
	struct timeval installed;

	struct event *expire;
	struct event *refresh; /* For self-originated LSA */

	int retrans_count;

	struct ospf6_lsdb *lsdb;

	in_addr_t external_lsa_id;

	/* lsa instance */
	struct ospf6_lsa_header *header;

	/*For topo chg detection in HELPER role*/
	bool tobe_acknowledged;
};


#define OSPF6_LSA_HEADERONLY 0x01
#define OSPF6_LSA_FLOODBACK  0x02
#define OSPF6_LSA_DUPLICATE  0x04
#define OSPF6_LSA_IMPLIEDACK 0x08
#define OSPF6_LSA_UNAPPROVED 0x10
#define OSPF6_LSA_SEQWRAPPED 0x20
#define OSPF6_LSA_FLUSH      0x40

struct ospf6_lsa_handler {
	uint16_t lh_type; /* host byte order */
	const char *lh_name;
	const char *lh_short_name;
	int (*lh_show)(struct vty *, struct ospf6_lsa *, json_object *json_obj,
		       bool use_json);
	char *(*lh_get_prefix_str)(struct ospf6_lsa *, char *buf, int buflen,
				   int pos);

	uint8_t lh_debug;
};

#define OSPF6_LSA_IS_KNOWN(t)                                                  \
	(ospf6_get_lsa_handler(t)->lh_type != OSPF6_LSTYPE_UNKNOWN ? 1 : 0)

/* Macro for LSA Origination */
/* addr is (struct prefix *) */
#define CONTINUE_IF_ADDRESS_LINKLOCAL(debug, addr)                             \
	if (IN6_IS_ADDR_LINKLOCAL(&(addr)->u.prefix6)) {                       \
		if (debug)                                                     \
			zlog_debug("Filter out Linklocal: %pFX", addr);        \
		continue;                                                      \
	}

#define CONTINUE_IF_ADDRESS_UNSPECIFIED(debug, addr)                           \
	if (IN6_IS_ADDR_UNSPECIFIED(&(addr)->u.prefix6)) {                     \
		if (debug)                                                     \
			zlog_debug("Filter out Unspecified: %pFX", addr);      \
		continue;                                                      \
	}

#define CONTINUE_IF_ADDRESS_LOOPBACK(debug, addr)                              \
	if (IN6_IS_ADDR_LOOPBACK(&(addr)->u.prefix6)) {                        \
		if (debug)                                                     \
			zlog_debug("Filter out Loopback: %pFX", addr);         \
		continue;                                                      \
	}

#define CONTINUE_IF_ADDRESS_V4COMPAT(debug, addr)                              \
	if (IN6_IS_ADDR_V4COMPAT(&(addr)->u.prefix6)) {                        \
		if (debug)                                                     \
			zlog_debug("Filter out V4Compat: %pFX", addr);         \
		continue;                                                      \
	}

#define CONTINUE_IF_ADDRESS_V4MAPPED(debug, addr)                              \
	if (IN6_IS_ADDR_V4MAPPED(&(addr)->u.prefix6)) {                        \
		if (debug)                                                     \
			zlog_debug("Filter out V4Mapped: %pFX", addr);         \
		continue;                                                      \
	}

#define CHECK_LSA_TOPO_CHG_ELIGIBLE(type)                                       \
	((type == OSPF6_LSTYPE_ROUTER) ||                                       \
	 (type == OSPF6_LSTYPE_NETWORK) ||                                      \
	 (type == OSPF6_LSTYPE_INTER_PREFIX) ||                                 \
	 (type == OSPF6_LSTYPE_INTER_ROUTER) ||                                 \
	 (type == OSPF6_LSTYPE_AS_EXTERNAL) ||                                  \
	 (type == OSPF6_LSTYPE_TYPE_7) ||                                       \
	 (type == OSPF6_LSTYPE_INTRA_PREFIX) ||                                 \
	 (type == OSPF6_LSTYPE_E_ROUTER) ||                                     \
	 (type == OSPF6_LSTYPE_E_NETWORK) ||                                    \
	 (type == OSPF6_LSTYPE_E_INTER_PREFIX) ||                               \
	 (type == OSPF6_LSTYPE_E_INTER_ROUTER) ||                               \
	 (type == OSPF6_LSTYPE_E_AS_EXTERNAL) ||                                \
	 (type == OSPF6_LSTYPE_E_TYPE_7) ||                                     \
	 (type == OSPF6_LSTYPE_E_INTRA_PREFIX))


typedef int (*cb_func)(void *desc, void *data);

/*
 * Provides the callback to execute for each lsdesc in an LSA.
 * For classic non-TLV LSAs, tlv_type, *next and *sub_handler are unused.
 * Stores an opaque pointer to the data needed by the callback.
 *
 * For Extended LSAs containing LSAs, the callback is associated with a TLV
 * type and the *next and *sub_handler lists are for handling additional
 * TLV types, and sub-TLVs.
 */
struct tlv_handler {
	int tlv_type;
	const cb_func callback;
	const struct tlv_handler *sub_handler;
};

/* An iterator for handling each descriptor in a classic LSA, or TLV in E-LSA */
#define foreach_lsdesc(lsa_header, handler, cb_data)                           \
	_foreach_lsdesc(lsa_header, handler, cb_data, __func__)

int _foreach_lsdesc(struct ospf6_lsa_header *lsa_header,
		    const struct tlv_handler *handler, void *cb_data,
		    const char *caller);

/* Function Prototypes */
extern const char *ospf6_lstype_name(uint16_t type);
extern const char *ospf6_lstype_short_name(uint16_t type);
extern uint8_t ospf6_lstype_debug(uint16_t type);
extern int metric_type(struct ospf6 *ospf6, int type, uint8_t instance);
extern int metric_value(struct ospf6 *ospf6, int type, uint8_t instance);
extern int ospf6_lsa_is_differ(struct ospf6_lsa *lsa1, struct ospf6_lsa *lsa2);
extern int ospf6_lsa_is_changed(struct ospf6_lsa *lsa1, struct ospf6_lsa *lsa2);
extern uint16_t ospf6_lsa_age_current(struct ospf6_lsa *lsa);
extern void ospf6_lsa_age_update_to_send(struct ospf6_lsa *lsa,
					 uint32_t transdelay);
extern void ospf6_lsa_premature_aging(struct ospf6_lsa *lsa);
extern int ospf6_lsa_compare(struct ospf6_lsa *lsa1, struct ospf6_lsa *lsa2);

extern char *ospf6_lsa_printbuf(struct ospf6_lsa *lsa, char *buf, int size);
extern void ospf6_lsa_header_print_raw(struct ospf6_lsa_header *header);
extern void ospf6_lsa_header_print(struct ospf6_lsa *lsa);
extern void ospf6_lsa_show_summary_header(struct vty *vty);
extern void ospf6_lsa_show_summary(struct vty *vty, struct ospf6_lsa *lsa,
				   json_object *json, bool use_json);
extern void ospf6_lsa_show_dump(struct vty *vty, struct ospf6_lsa *lsa,
				json_object *json, bool use_json);
extern void ospf6_lsa_show_internal(struct vty *vty, struct ospf6_lsa *lsa,
				    json_object *json, bool use_json);
extern void ospf6_lsa_show(struct vty *vty, struct ospf6_lsa *lsa,
			   json_object *json, bool use_json);

extern struct ospf6_lsa *ospf6_lsa_alloc(size_t lsa_length);
extern struct ospf6_lsa *ospf6_lsa_create(struct ospf6_lsa_header *header);
extern struct ospf6_lsa *
ospf6_lsa_create_headeronly(struct ospf6_lsa_header *header);
extern void ospf6_lsa_delete(struct ospf6_lsa *lsa);
extern struct ospf6_lsa *ospf6_lsa_copy(struct ospf6_lsa *lsa);

extern struct ospf6_lsa *ospf6_lsa_lock(struct ospf6_lsa *lsa);
extern void ospf6_lsa_unlock(struct ospf6_lsa **lsa);

extern void ospf6_lsa_expire(struct event *thread);
extern void ospf6_lsa_refresh(struct event *thread);

extern unsigned short ospf6_lsa_checksum(struct ospf6_lsa_header *lsah);
extern int ospf6_lsa_checksum_valid(struct ospf6_lsa_header *lsah);
extern int ospf6_lsa_prohibited_duration(uint16_t type, uint32_t id,
					 uint32_t adv_router, void *scope);

extern void ospf6_install_lsa_handler(struct ospf6_lsa_handler *handler);
extern struct ospf6_lsa_handler *ospf6_get_lsa_handler(uint16_t type);
extern void ospf6_lsa_debug_set_all(bool val);

extern void ospf6_lsa_init(void);
extern void ospf6_lsa_terminate(void);

extern int config_write_ospf6_debug_lsa(struct vty *vty);
extern void install_element_ospf6_debug_lsa(void);
extern void ospf6_lsa_age_set(struct ospf6_lsa *lsa);
extern void ospf6_flush_self_originated_lsas_now(struct ospf6 *ospf6);
extern struct ospf6 *ospf6_get_by_lsdb(struct ospf6_lsa *lsa);
struct ospf6_lsa *ospf6_find_external_lsa(struct ospf6 *ospf6,
					  struct prefix *p);

void *lsdesc_start_lsa_type(struct ospf6_lsa_header *header, int lsa_type);
void *lsdesc_start(struct ospf6_lsa_header *header);

void *nth_lsdesc(struct ospf6_lsa_header *header, int pos);
void *nth_prefix(struct ospf6_lsa_header *header, int pos);
void *nth_tlv(struct ospf6_lsa_header *header, int pos);

#endif /* OSPF6_LSA_H */
