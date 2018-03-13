/* NHRP daemon internal structures and function prototypes
 * Copyright (c) 2014-2015 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef NHRPD_H
#define NHRPD_H

#include "list.h"

#include "zbuf.h"
#include "zclient.h"
#include "debug.h"
#include "memory.h"

DECLARE_MGROUP(NHRPD)

#define NHRPD_DEFAULT_HOLDTIME	7200

#define NHRP_VTY_PORT		2610
#define NHRP_DEFAULT_CONFIG	"nhrpd.conf"

extern struct thread_master *master;

enum { NHRP_OK = 0,
       NHRP_ERR_FAIL,
       NHRP_ERR_NO_MEMORY,
       NHRP_ERR_UNSUPPORTED_INTERFACE,
       NHRP_ERR_NHRP_NOT_ENABLED,
       NHRP_ERR_ENTRY_EXISTS,
       NHRP_ERR_ENTRY_NOT_FOUND,
       NHRP_ERR_PROTOCOL_ADDRESS_MISMATCH,
       __NHRP_ERR_MAX };
#define NHRP_ERR_MAX		(__NHRP_ERR_MAX - 1)

struct notifier_block;

typedef void (*notifier_fn_t)(struct notifier_block *, unsigned long);

struct notifier_block {
	struct list_head notifier_entry;
	notifier_fn_t action;
};

struct notifier_list {
	struct list_head notifier_head;
};

#define NOTIFIER_LIST_INITIALIZER(l)                                           \
	{                                                                      \
		.notifier_head = LIST_INITIALIZER((l)->notifier_head)          \
	}

static inline void notifier_init(struct notifier_list *l)
{
	list_init(&l->notifier_head);
}

static inline void notifier_add(struct notifier_block *n,
				struct notifier_list *l, notifier_fn_t action)
{
	n->action = action;
	list_add_tail(&n->notifier_entry, &l->notifier_head);
}

static inline void notifier_del(struct notifier_block *n)
{
	list_del(&n->notifier_entry);
}

static inline void notifier_call(struct notifier_list *l, int cmd)
{
	struct notifier_block *n, *nn;
	list_for_each_entry_safe(n, nn, &l->notifier_head, notifier_entry)
		n->action(n, cmd);
}

static inline int notifier_active(struct notifier_list *l)
{
	return !list_empty(&l->notifier_head);
}

struct resolver_query {
	void (*callback)(struct resolver_query *, int n, union sockunion *);
};

void resolver_init(void);
void resolver_resolve(struct resolver_query *query, int af,
		      const char *hostname, void (*cb)(struct resolver_query *,
						       int, union sockunion *));

void nhrp_zebra_init(void);
void nhrp_zebra_terminate(void);

struct zbuf;
struct nhrp_vc;
struct nhrp_cache;
struct nhrp_nhs;
struct nhrp_interface;

#define MAX_ID_LENGTH			64
#define MAX_CERT_LENGTH			2048

enum nhrp_notify_type {
	NOTIFY_INTERFACE_UP,
	NOTIFY_INTERFACE_DOWN,
	NOTIFY_INTERFACE_CHANGED,
	NOTIFY_INTERFACE_ADDRESS_CHANGED,
	NOTIFY_INTERFACE_NBMA_CHANGED,
	NOTIFY_INTERFACE_MTU_CHANGED,

	NOTIFY_VC_IPSEC_CHANGED,
	NOTIFY_VC_IPSEC_UPDATE_NBMA,

	NOTIFY_PEER_UP,
	NOTIFY_PEER_DOWN,
	NOTIFY_PEER_IFCONFIG_CHANGED,
	NOTIFY_PEER_MTU_CHANGED,
	NOTIFY_PEER_NBMA_CHANGING,

	NOTIFY_CACHE_UP,
	NOTIFY_CACHE_DOWN,
	NOTIFY_CACHE_DELETE,
	NOTIFY_CACHE_USED,
	NOTIFY_CACHE_BINDING_CHANGE,
};

struct nhrp_vc {
	struct notifier_list notifier_list;
	uint8_t ipsec;
	uint8_t updating;
	uint8_t abort_migration;

	struct nhrp_vc_peer {
		union sockunion nbma;
		char id[MAX_ID_LENGTH];
		uint16_t certlen;
		uint8_t cert[MAX_CERT_LENGTH];
	} local, remote;
};

enum nhrp_route_type {
	NHRP_ROUTE_BLACKHOLE,
	NHRP_ROUTE_LOCAL,
	NHRP_ROUTE_NBMA_NEXTHOP,
	NHRP_ROUTE_OFF_NBMA,
};

struct nhrp_peer {
	unsigned int ref;
	unsigned online : 1;
	unsigned requested : 1;
	unsigned fallback_requested : 1;
	unsigned prio : 1;
	struct notifier_list notifier_list;
	struct interface *ifp;
	struct nhrp_vc *vc;
	struct thread *t_fallback;
	struct notifier_block vc_notifier, ifp_notifier;
};

struct nhrp_packet_parser {
	struct interface *ifp;
	struct nhrp_afi_data *if_ad;
	struct nhrp_peer *peer;
	struct zbuf *pkt;
	struct zbuf payload;
	struct zbuf extensions;
	struct nhrp_packet_header *hdr;
	enum nhrp_route_type route_type;
	struct prefix route_prefix;
	union sockunion src_nbma, src_proto, dst_proto;
};

struct nhrp_reqid_pool {
	struct hash *reqid_hash;
	uint32_t next_request_id;
};

struct nhrp_reqid {
	uint32_t request_id;
	void (*cb)(struct nhrp_reqid *, void *);
};

extern struct nhrp_reqid_pool nhrp_packet_reqid;
extern struct nhrp_reqid_pool nhrp_event_reqid;

enum nhrp_cache_type {
	NHRP_CACHE_INVALID = 0,
	NHRP_CACHE_INCOMPLETE,
	NHRP_CACHE_NEGATIVE,
	NHRP_CACHE_CACHED,
	NHRP_CACHE_DYNAMIC,
	NHRP_CACHE_NHS,
	NHRP_CACHE_STATIC,
	NHRP_CACHE_LOCAL,
	NHRP_CACHE_NUM_TYPES
};

extern const char *const nhrp_cache_type_str[];
extern unsigned long nhrp_cache_counts[NHRP_CACHE_NUM_TYPES];

struct nhrp_cache {
	struct interface *ifp;
	union sockunion remote_addr;

	unsigned map : 1;
	unsigned used : 1;
	unsigned route_installed : 1;
	unsigned nhrp_route_installed : 1;

	struct notifier_block peer_notifier;
	struct notifier_block newpeer_notifier;
	struct notifier_list notifier_list;
	struct nhrp_reqid eventid;
	struct thread *t_timeout;
	struct thread *t_auth;

	struct {
		enum nhrp_cache_type type;
		union sockunion remote_nbma_natoa;
		struct nhrp_peer *peer;
		time_t expires;
		uint32_t mtu;
	} cur, new;
};

struct nhrp_shortcut {
	struct prefix *p;
	union sockunion addr;

	struct nhrp_reqid reqid;
	struct thread *t_timer;

	enum nhrp_cache_type type;
	unsigned int holding_time;
	unsigned route_installed : 1;
	unsigned expiring : 1;

	struct nhrp_cache *cache;
	struct notifier_block cache_notifier;
};

struct nhrp_nhs {
	struct interface *ifp;
	struct list_head nhslist_entry;

	unsigned hub : 1;
	afi_t afi;
	union sockunion proto_addr;
	const char *nbma_fqdn; /* IP-address or FQDN */

	struct thread *t_resolve;
	struct resolver_query dns_resolve;
	struct list_head reglist_head;
};

struct nhrp_registration {
	struct list_head reglist_entry;
	struct thread *t_register;
	struct nhrp_nhs *nhs;
	struct nhrp_reqid reqid;
	unsigned int timeout;
	unsigned mark : 1;
	union sockunion proto_addr;
	struct nhrp_peer *peer;
	struct notifier_block peer_notifier;
};

#define NHRP_IFF_SHORTCUT		0x0001
#define NHRP_IFF_REDIRECT		0x0002
#define NHRP_IFF_REG_NO_UNIQUE		0x0100

struct nhrp_interface {
	struct interface *ifp;

	unsigned enabled : 1;

	char *ipsec_profile, *ipsec_fallback_profile, *source;
	union sockunion nbma;
	union sockunion nat_nbma;
	unsigned int linkidx;
	uint32_t grekey;

	struct hash *peer_hash;
	struct hash *cache_hash;

	struct notifier_list notifier_list;

	struct interface *nbmaifp;
	struct notifier_block nbmanifp_notifier;

	struct nhrp_afi_data {
		unsigned flags;
		unsigned short configured : 1;
		union sockunion addr;
		uint32_t network_id;
		short configured_mtu;
		unsigned short mtu;
		unsigned int holdtime;
		struct list_head nhslist_head;
	} afi[AFI_MAX];
};

extern struct zebra_privs_t nhrpd_privs;

int sock_open_unix(const char *path);

void nhrp_interface_init(void);
void nhrp_interface_update(struct interface *ifp);
void nhrp_interface_update_mtu(struct interface *ifp, afi_t afi);

int nhrp_interface_add(int cmd, struct zclient *client, zebra_size_t length,
		       vrf_id_t vrf_id);
int nhrp_interface_delete(int cmd, struct zclient *client, zebra_size_t length,
			  vrf_id_t vrf_id);
int nhrp_interface_up(int cmd, struct zclient *client, zebra_size_t length,
		      vrf_id_t vrf_id);
int nhrp_interface_down(int cmd, struct zclient *client, zebra_size_t length,
			vrf_id_t vrf_id);
int nhrp_interface_address_add(int cmd, struct zclient *client,
			       zebra_size_t length, vrf_id_t vrf_id);
int nhrp_interface_address_delete(int cmd, struct zclient *client,
				  zebra_size_t length, vrf_id_t vrf_id);

void nhrp_interface_notify_add(struct interface *ifp, struct notifier_block *n,
			       notifier_fn_t fn);
void nhrp_interface_notify_del(struct interface *ifp, struct notifier_block *n);
void nhrp_interface_set_protection(struct interface *ifp, const char *profile,
				   const char *fallback_profile);
void nhrp_interface_set_source(struct interface *ifp, const char *ifname);

int nhrp_nhs_add(struct interface *ifp, afi_t afi, union sockunion *proto_addr,
		 const char *nbma_fqdn);
int nhrp_nhs_del(struct interface *ifp, afi_t afi, union sockunion *proto_addr,
		 const char *nbma_fqdn);
int nhrp_nhs_free(struct nhrp_nhs *nhs);
void nhrp_nhs_terminate(void);
void nhrp_nhs_foreach(struct interface *ifp, afi_t afi,
		      void (*cb)(struct nhrp_nhs *, struct nhrp_registration *,
				 void *),
		      void *ctx);

void nhrp_route_update_nhrp(const struct prefix *p, struct interface *ifp);
void nhrp_route_announce(int add, enum nhrp_cache_type type,
			 const struct prefix *p, struct interface *ifp,
			 const union sockunion *nexthop, uint32_t mtu);
int nhrp_route_read(int command, struct zclient *zclient, zebra_size_t length,
		    vrf_id_t vrf_id);
int nhrp_route_get_nexthop(const union sockunion *addr, struct prefix *p,
			   union sockunion *via, struct interface **ifp);
enum nhrp_route_type nhrp_route_address(struct interface *in_ifp,
					union sockunion *addr, struct prefix *p,
					struct nhrp_peer **peer);

void nhrp_config_init(void);

void nhrp_shortcut_init(void);
void nhrp_shortcut_terminate(void);
void nhrp_shortcut_initiate(union sockunion *addr);
void nhrp_shortcut_foreach(afi_t afi,
			   void (*cb)(struct nhrp_shortcut *, void *),
			   void *ctx);
void nhrp_shortcut_purge(struct nhrp_shortcut *s, int force);
void nhrp_shortcut_prefix_change(const struct prefix *p, int deleted);

struct nhrp_cache *nhrp_cache_get(struct interface *ifp,
				  union sockunion *remote_addr, int create);
void nhrp_cache_foreach(struct interface *ifp,
			void (*cb)(struct nhrp_cache *, void *), void *ctx);
void nhrp_cache_set_used(struct nhrp_cache *, int);
int nhrp_cache_update_binding(struct nhrp_cache *, enum nhrp_cache_type type,
			      int holding_time, struct nhrp_peer *p,
			      uint32_t mtu, union sockunion *nbma_natoa);
void nhrp_cache_notify_add(struct nhrp_cache *c, struct notifier_block *,
			   notifier_fn_t);
void nhrp_cache_notify_del(struct nhrp_cache *c, struct notifier_block *);

void nhrp_vc_init(void);
void nhrp_vc_terminate(void);
struct nhrp_vc *nhrp_vc_get(const union sockunion *src,
			    const union sockunion *dst, int create);
int nhrp_vc_ipsec_updown(uint32_t child_id, struct nhrp_vc *vc);
void nhrp_vc_notify_add(struct nhrp_vc *, struct notifier_block *,
			notifier_fn_t);
void nhrp_vc_notify_del(struct nhrp_vc *, struct notifier_block *);
void nhrp_vc_foreach(void (*cb)(struct nhrp_vc *, void *), void *ctx);
void nhrp_vc_reset(void);

void vici_init(void);
void vici_terminate(void);
void vici_request_vc(const char *profile, union sockunion *src,
		     union sockunion *dst, int prio);

extern const char *nhrp_event_socket_path;

void evmgr_init(void);
void evmgr_terminate(void);
void evmgr_set_socket(const char *socket);
void evmgr_notify(const char *name, struct nhrp_cache *c,
		  void (*cb)(struct nhrp_reqid *, void *));

struct nhrp_packet_header *nhrp_packet_push(struct zbuf *zb, uint8_t type,
					    const union sockunion *src_nbma,
					    const union sockunion *src_proto,
					    const union sockunion *dst_proto);
void nhrp_packet_complete(struct zbuf *zb, struct nhrp_packet_header *hdr);
uint16_t nhrp_packet_calculate_checksum(const uint8_t *pdu, uint16_t len);

struct nhrp_packet_header *nhrp_packet_pull(struct zbuf *zb,
					    union sockunion *src_nbma,
					    union sockunion *src_proto,
					    union sockunion *dst_proto);

struct nhrp_cie_header *nhrp_cie_push(struct zbuf *zb, uint8_t code,
				      const union sockunion *nbma,
				      const union sockunion *proto);
struct nhrp_cie_header *nhrp_cie_pull(struct zbuf *zb,
				      struct nhrp_packet_header *hdr,
				      union sockunion *nbma,
				      union sockunion *proto);

struct nhrp_extension_header *
nhrp_ext_push(struct zbuf *zb, struct nhrp_packet_header *hdr, uint16_t type);
void nhrp_ext_complete(struct zbuf *zb, struct nhrp_extension_header *ext);
struct nhrp_extension_header *nhrp_ext_pull(struct zbuf *zb,
					    struct zbuf *payload);
void nhrp_ext_request(struct zbuf *zb, struct nhrp_packet_header *hdr,
		      struct interface *);
int nhrp_ext_reply(struct zbuf *zb, struct nhrp_packet_header *hdr,
		   struct interface *ifp, struct nhrp_extension_header *ext,
		   struct zbuf *extpayload);

uint32_t nhrp_reqid_alloc(struct nhrp_reqid_pool *, struct nhrp_reqid *r,
			  void (*cb)(struct nhrp_reqid *, void *));
void nhrp_reqid_free(struct nhrp_reqid_pool *, struct nhrp_reqid *r);
struct nhrp_reqid *nhrp_reqid_lookup(struct nhrp_reqid_pool *, uint32_t reqid);

int nhrp_packet_init(void);

struct nhrp_peer *nhrp_peer_get(struct interface *ifp,
				const union sockunion *remote_nbma);
struct nhrp_peer *nhrp_peer_ref(struct nhrp_peer *p);
void nhrp_peer_unref(struct nhrp_peer *p);
int nhrp_peer_check(struct nhrp_peer *p, int establish);
void nhrp_peer_notify_add(struct nhrp_peer *p, struct notifier_block *,
			  notifier_fn_t);
void nhrp_peer_notify_del(struct nhrp_peer *p, struct notifier_block *);
void nhrp_peer_recv(struct nhrp_peer *p, struct zbuf *zb);
void nhrp_peer_send(struct nhrp_peer *p, struct zbuf *zb);
void nhrp_peer_send_indication(struct interface *ifp, uint16_t, struct zbuf *);

#endif
