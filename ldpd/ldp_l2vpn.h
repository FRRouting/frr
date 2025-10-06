// SPDX-License-Identifier: GPL-2.0-or-later
/* Route map function.
 * Copyright (C) 1998 Kunihiro Ishiguro
 */

#ifndef _LDP_L2VPN_H
#define _LDP_L2VPN_H

#ifdef __cplusplus
extern "C" {
#endif

#include "lib/zebra.h"
#include "openbsd-tree.h"
#include "lib/if.h"
#include "lib/pw.h"
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

struct l2vpn_pw {
	RB_ENTRY(l2vpn_pw)	 entry;
	struct l2vpn		*l2vpn;
	struct in_addr		 lsr_id;
	int			 af;
	union g_addr addr;
	uint32_t		 pwid;
	char ifname[IFNAMSIZ];
	ifindex_t		 ifindex;
	bool			 enabled;
	uint32_t		 remote_group;
	uint16_t		 remote_mtu;
	uint32_t		 local_status;
	uint32_t		 remote_status;
	uint8_t			 flags;
	uint8_t			 reason;

	QOBJ_FIELDS;
};
RB_HEAD(l2vpn_pw_head, l2vpn_pw);
RB_PROTOTYPE(l2vpn_pw_head, l2vpn_pw, entry, l2vpn_pw_compare);
DECLARE_QOBJ_TYPE(l2vpn_pw);
#define F_PW_STATUSTLV_CONF	0x01	/* status tlv configured */
#define F_PW_STATUSTLV		0x02	/* status tlv negotiated */
#define F_PW_CWORD_CONF		0x04	/* control word configured */
#define F_PW_CWORD		0x08	/* control word negotiated */
#define F_PW_STATIC_NBR_ADDR	0x10	/* static neighbor address configured */
#define F_PW_SEND_REMOTE	0x20	/* send pw message to remote */


#define F_PW_NO_ERR             0x00	/* no error reported */
#define F_PW_LOCAL_NOT_FWD      0x01	/* locally can't forward over PW */
#define F_PW_REMOTE_NOT_FWD     0x02	/* remote end of PW reported fwd error*/
#define F_PW_NO_REMOTE_LABEL    0x03	/* have not recvd label from peer */
#define F_PW_MTU_MISMATCH       0x04	/* mtu mismatch between peers */

struct l2vpn {
	RB_ENTRY(l2vpn)		 entry;
	char			 name[L2VPN_NAME_LEN];
	int			 type;
	int			 pw_type;
	int			 mtu;
	char br_ifname[IFNAMSIZ];
	ifindex_t		 br_ifindex;
	struct l2vpn_if_head	 if_tree;
	struct l2vpn_pw_head	 pw_tree;
	struct l2vpn_pw_head	 pw_inactive_tree;

	QOBJ_FIELDS;
};
RB_HEAD(l2vpn_head, l2vpn);
RB_PROTOTYPE(l2vpn_head, l2vpn, entry, l2vpn_compare);
DECLARE_QOBJ_TYPE(l2vpn);
#define L2VPN_TYPE_VPWS		1
#define L2VPN_TYPE_VPLS		2

/* clang-format on */

extern const struct frr_yang_module_info frr_ldp_l2vpn;
extern const struct frr_yang_module_info frr_ldp_l2vpn_cli_info;

extern void ldp_l2vpn_cli_init(void);
extern void ldp_l2vpn_init(void);

struct l2vpn *l2vpn_new(const char *name);
struct l2vpn *l2vpn_find(struct l2vpn_head *l2vpn_tree, const char *name);
void l2vpn_del(struct l2vpn *l2vpn);

struct l2vpn_if *l2vpn_if_new(struct l2vpn *l2vpn, const char *ifname);
struct l2vpn_if *l2vpn_if_find(struct l2vpn *l2vpn, const char *ifname);

struct l2vpn_pw *l2vpn_pw_new(struct l2vpn *l2vpn, const char *ifname);
struct l2vpn_pw *l2vpn_pw_find(struct l2vpn *l2vpn, const char *ifname);
struct l2vpn_pw *l2vpn_pw_find_active(struct l2vpn *l2vpn, const char *ifname);
struct l2vpn_pw *l2vpn_pw_find_inactive(struct l2vpn *l2vpn, const char *ifname);

void l2vpn_init(struct l2vpn *l2vpn);

struct l2vpn_lib_register {
	void (*add_hook)(const char *name);
	void (*del_hook)(const char *name);
	void (*event_hook)(const char *name);
	bool (*iface_ok_for_l2vpn)(const char *ifname);
};

extern struct l2vpn_lib_register l2vpn_lib_master;
extern struct l2vpn_head l2vpn_tree_config;

int l2vpn_iface_is_configured(const char *ifname);

void l2vpn_register_hook(void (*func_add)(const char *), void (*func_del)(const char *),
			 void (*func_event)(const char *),
			 bool (*func_iface_ok_for_l2vpn)(const char *));

#ifdef __cplusplus
}
#endif

#endif /* _LDP_L2VPN_H */
