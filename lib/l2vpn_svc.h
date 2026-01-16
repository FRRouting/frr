// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * L2VPN Services (VPWS, VPLS) library
 *
 * Copyright 2026 6WIND S.A.
 */

#ifndef _L2VPN_SVC_H
#define _L2VPN_SVC_H

#ifdef __cplusplus
extern "C" {
#endif

#include "lib/zebra.h"
#include "openbsd-tree.h"
#include "lib/prefix.h"
#include "lib/if.h"
#include "lib/l2vpn.h"
#include "lib/qobj.h"
#include "lib/nexthop.h"

/* clang-format off */

struct l2vpn_if {
	RB_ENTRY(l2vpn_if)	 entry;
	struct l2vpn		*l2vpn;
	char ifname[IFNAMSIZ];
	ifindex_t		 ifindex;
	int			 operative;
	uint8_t			 mac[ETH_ALEN];

	QOBJ_FIELDS;
};
RB_HEAD(l2vpn_if_head, l2vpn_if);
RB_PROTOTYPE(l2vpn_if_head, l2vpn_if, entry, l2vpn_if_compare);
DECLARE_QOBJ_TYPE(l2vpn_if);

struct l2vpn_svc {
	RB_ENTRY(l2vpn_svc) entry;
	struct l2vpn *l2vpn;
	struct in_addr lsr_id;
	int af;
	union g_addr addr;
	union {
		uint32_t pwid;
		uint32_t evi;
	};
	esi_t esi;
	char local_ac[IFNAMSIZ];
	uint32_t local_ac_id;
	uint32_t remote_ac_id;
	vni_t vni;
	char ifname[IFNAMSIZ];
	ifindex_t ifindex;
	bool ignore_mtu_mismatch;
	bool	 enabled;
	uint32_t remote_group;
	uint16_t remote_mtu;
	uint16_t mtu;
	uint32_t local_status;
	uint32_t remote_status;

	/* PW flags */
#define F_PW_STATUSTLV_CONF     (1 << 0) /* status tlv configured */
#define F_PW_STATUSTLV          (1 << 1) /* status tlv negotiated */
#define F_PW_CWORD_CONF         (1 << 2) /* control word configured */
#define F_PW_CWORD              (1 << 3) /* control word negotiated */
#define F_PW_STATIC_NBR_ADDR    (1 << 4) /* static neighbor address configured */
#define F_PW_SEND_REMOTE        (1 << 5) /* send pw message to remote */
	/* EVPN flags */
#define F_EVPN_SEND_REMOTE F_PW_SEND_REMOTE
#define F_EVPN_NBR_ADDR         (1 << 6) /* EVPN neighbor configured */
#define F_EVPN_VNI              (1 << 7) /* EVPN VNI configured */
	uint8_t	 flags;

	/* L2VPN reason code */
#define F_L2VPN_NO_ERR          (1 << 0) /* no error reported */
#define F_L2VPN_LOCAL_NOT_FWD   (1 << 1) /* locally can't forward over PW */
#define F_L2VPN_REMOTE_NOT_FWD  (1 << 2) /* remote end of PW reported fwd error*/
#define F_L2VPN_NO_REMOTE_LABEL (1 << 3) /* have not recvd label from peer */
#define F_L2VPN_MTU_MISMATCH    (1 << 4) /* mtu mismatch between peers */
#define F_L2VPN_NO_REMOTE_AD    (1 << 5) /* have not recvd per-EVI Ethernet A-D route from peer */
#define F_L2VPN_AD_MISMATCH     (1 << 6) /* recvd multiple same EVI Ethernet A-D */
	uint8_t	 reason;

	QOBJ_FIELDS;
};
RB_HEAD(l2vpn_svc_head, l2vpn_svc);
RB_PROTOTYPE(l2vpn_svc_head, l2vpn_svc, entry, l2vpn_svc_compare);
DECLARE_QOBJ_TYPE(l2vpn_svc);


struct l2vpn {
	RB_ENTRY(l2vpn)		 entry;
	char			 name[L2VPN_NAME_LEN];
	int			 type;
	int			 pw_type;
	int			 mtu;
	char br_ifname[IFNAMSIZ];
	ifindex_t		 br_ifindex;
	struct l2vpn_if_head	 if_tree;
	struct l2vpn_svc_head	 svc_tree;
	struct l2vpn_svc_head	 svc_inactive_tree;

	QOBJ_FIELDS;
};
RB_HEAD(l2vpn_head, l2vpn);
RB_PROTOTYPE(l2vpn_head, l2vpn, entry, l2vpn_compare);
DECLARE_QOBJ_TYPE(l2vpn);

/* clang-format on */

extern void l2vpn_init_new(bool in_backend);
extern void l2vpn_init(void);
extern const char *l2vpn_svc_error_code(uint32_t status);

struct l2vpn *l2vpn_new(const char *name);
struct l2vpn *l2vpn_find(struct l2vpn_head *conf, const char *name, int type);
int l2vpn_iface_is_configured(const char *ifname);
void l2vpn_del(struct l2vpn *l2vpn);

struct l2vpn_if *l2vpn_if_new(struct l2vpn *l2vpn, const char *ifname);
struct l2vpn_if *l2vpn_if_find(struct l2vpn *l2vpn, const char *ifname);

struct l2vpn_svc *l2vpn_svc_new(struct l2vpn *l2vpn, const char *ifname);
struct l2vpn_svc *l2vpn_svc_find(struct l2vpn *l2vpn, const char *ifname);
struct l2vpn_svc *l2vpn_svc_find_active(struct l2vpn *l2vpn, const char *ifname);
struct l2vpn_svc *l2vpn_svc_find_inactive(struct l2vpn *l2vpn, const char *ifname);

struct l2vpn_lib_register {
	void (*add_hook)(const char *name);
	void (*del_hook)(const char *name);
	void (*event_hook)(struct l2vpn_svc *l2vpn_svc);
	bool (*iface_ok_for_l2vpn)(const char *ifname);
};

extern struct l2vpn_lib_register l2vpn_lib_master;
extern struct l2vpn_head l2vpn_tree_config;

void l2vpn_register_hook(void (*func_add)(const char *), void (*func_del)(const char *),
			 void (*func_event)(struct l2vpn_svc *),
			 bool (*func_iface_ok_for_l2vpn)(const char *));

#ifdef __cplusplus
}
#endif

#endif /* _L2VPN_SVC_H */
