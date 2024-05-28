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
#define OSPF6_LSTYPE_SIZE             0x000c

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

#define CHECK_LSA_TOPO_CHG_ELIGIBLE(type)		\
	((type == OSPF6_LSTYPE_ROUTER)			\
	 || (type == OSPF6_LSTYPE_NETWORK)		\
	 || (type == OSPF6_LSTYPE_INTER_PREFIX)		\
	 || (type == OSPF6_LSTYPE_INTER_ROUTER)		\
	 || (type == OSPF6_LSTYPE_AS_EXTERNAL)		\
	 || (type == OSPF6_LSTYPE_TYPE_7)		\
	 || (type == OSPF6_LSTYPE_INTRA_PREFIX))

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
#endif /* OSPF6_LSA_H */
