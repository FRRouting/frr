/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * L2VPN Services (VPLS, VPWS) implementation.
 *
 * Copyright 2026 6WIND S.A.
 */

#include <zebra.h>

#include "lib/memory.h"
#include "lib/command.h"
#include "lib/northbound_cli.h"

#include "lib/l2vpn_svc.h"

struct l2vpn_lib_register l2vpn_lib_master = { NULL, NULL, NULL, NULL };
struct l2vpn_head l2vpn_tree_config;

/* clang-format off */

static inline int     l2vpn_compare(const struct l2vpn *, const struct l2vpn *);
static inline int     l2vpn_if_compare(const struct l2vpn_if *, const struct l2vpn_if *);
static inline int     l2vpn_svc_compare(const struct l2vpn_svc *, const struct l2vpn_svc *);

/* clang-format on */

DEFINE_QOBJ_TYPE(l2vpn_if);
DEFINE_QOBJ_TYPE(l2vpn_svc);
DEFINE_QOBJ_TYPE(l2vpn);

DEFINE_MTYPE_STATIC(LIB, L2VPN, "L2VPN entry");
DEFINE_MTYPE_STATIC(LIB, L2VPN_SVC, "L2VPN Service entry");
DEFINE_MTYPE_STATIC(LIB, L2VPN_IF, "L2VPN IF entry");

RB_GENERATE(l2vpn_head, l2vpn, entry, l2vpn_compare)
RB_GENERATE(l2vpn_if_head, l2vpn_if, entry, l2vpn_if_compare)
RB_GENERATE(l2vpn_svc_head, l2vpn_svc, entry, l2vpn_svc_compare)

/* clang-format off */

static inline int
l2vpn_compare(const struct l2vpn *a, const struct l2vpn *b)
{
	return strcmp(a->name, b->name);
}

static inline int l2vpn_svc_compare(const struct l2vpn_svc *a, const struct l2vpn_svc *b)
{
	return if_cmp_name_func(a->ifname, b->ifname);
}

static inline int
l2vpn_if_compare(const struct l2vpn_if *a, const struct l2vpn_if *b)
{
	return if_cmp_name_func(a->ifname, b->ifname);
}

struct l2vpn *
l2vpn_new(const char *name)
{
	struct l2vpn *l2vpn;

	l2vpn = XCALLOC(MTYPE_L2VPN, sizeof(*l2vpn));

	strlcpy(l2vpn->name, name, sizeof(l2vpn->name));

	/* set default values */
	l2vpn->mtu = DEFAULT_L2VPN_MTU;
	l2vpn->pw_type = DEFAULT_PW_TYPE;

	RB_INIT(l2vpn_if_head, &l2vpn->if_tree);
	RB_INIT(l2vpn_svc_head, &l2vpn->svc_tree);
	RB_INIT(l2vpn_svc_head, &l2vpn->svc_inactive_tree);

	return l2vpn;
}


struct l2vpn *
l2vpn_find(struct l2vpn_head *l2vpn_tree, const char *name, int type)
{
	struct l2vpn l2vpn;

	strlcpy(l2vpn.name, name, sizeof(l2vpn.name));
	l2vpn.type = type;
	return RB_FIND(l2vpn_head, l2vpn_tree, &l2vpn);
}

void
l2vpn_del(struct l2vpn *l2vpn)
{
	struct l2vpn_if *lif;
	struct l2vpn_svc *svc;

	while (!RB_EMPTY(l2vpn_if_head, &l2vpn->if_tree)) {
		lif = RB_ROOT(l2vpn_if_head, &l2vpn->if_tree);

		RB_REMOVE(l2vpn_if_head, &l2vpn->if_tree, lif);
		XFREE(MTYPE_L2VPN_IF, lif);
	}
	while (!RB_EMPTY(l2vpn_svc_head, &l2vpn->svc_tree)) {
		svc = RB_ROOT(l2vpn_svc_head, &l2vpn->svc_tree);

		RB_REMOVE(l2vpn_svc_head, &l2vpn->svc_tree, svc);
		XFREE(MTYPE_L2VPN_SVC, svc);
	}
	while (!RB_EMPTY(l2vpn_svc_head, &l2vpn->svc_inactive_tree)) {
		svc = RB_ROOT(l2vpn_svc_head, &l2vpn->svc_inactive_tree);

		RB_REMOVE(l2vpn_svc_head, &l2vpn->svc_inactive_tree, svc);
		XFREE(MTYPE_L2VPN_SVC, svc);
	}

	free(l2vpn);
}

struct l2vpn_svc *
l2vpn_svc_new(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_svc *svc;

	svc = XCALLOC(MTYPE_L2VPN_SVC, sizeof(*svc));

	svc->l2vpn = l2vpn;
	strlcpy(svc->ifname, ifname, sizeof(svc->ifname));

	return svc;
}

struct l2vpn_if *
l2vpn_if_new(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_if *lif;

	lif = XCALLOC(MTYPE_L2VPN_IF, sizeof(*lif));

	lif->l2vpn = l2vpn;
	strlcpy(lif->ifname, ifname, sizeof(lif->ifname));

	return lif;
}

struct l2vpn_svc *
l2vpn_svc_find_active(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_svc s;

	strlcpy(s.ifname, ifname, sizeof(s.ifname));
	return RB_FIND(l2vpn_svc_head, &l2vpn->svc_tree, &s);
}

struct l2vpn_svc *
l2vpn_svc_find_inactive(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_svc s;

	strlcpy(s.ifname, ifname, sizeof(s.ifname));
	return RB_FIND(l2vpn_svc_head, &l2vpn->svc_inactive_tree, &s);
}

/* clang-format on */

struct l2vpn_if *l2vpn_if_find(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_if lif;

	strlcpy(lif.ifname, ifname, sizeof(lif.ifname));
	return RB_FIND(l2vpn_if_head, &l2vpn->if_tree, &lif);
}

struct l2vpn_svc *l2vpn_svc_find(struct l2vpn *l2vpn, const char *ifname)
{
	struct l2vpn_svc *svc;
	struct l2vpn_svc s;

	strlcpy(s.ifname, ifname, sizeof(s.ifname));
	svc = RB_FIND(l2vpn_svc_head, &l2vpn->svc_tree, &s);
	if (svc)
		return svc;
	return RB_FIND(l2vpn_svc_head, &l2vpn->svc_inactive_tree, &s);
}

int l2vpn_iface_is_configured(const char *ifname)
{
	struct l2vpn *l2vpn;

	RB_FOREACH (l2vpn, l2vpn_head, &l2vpn_tree_config) {
		if (l2vpn_if_find(l2vpn, ifname))
			return 1;
		if (l2vpn_svc_find(l2vpn, ifname))
			return 1;
	}

	return 0;
}

void l2vpn_register_hook(void (*func_add)(const char *), void (*func_del)(const char *),
			 void (*func_event)(struct l2vpn_svc *),
			 bool (*func_iface_ok_for_l2vpn)(const char *))
{
	l2vpn_lib_master.add_hook = func_add;
	l2vpn_lib_master.del_hook = func_del;
	l2vpn_lib_master.event_hook = func_event;
	l2vpn_lib_master.iface_ok_for_l2vpn = func_iface_ok_for_l2vpn;
}

void l2vpn_init(void)
{
	RB_INIT(l2vpn_head, &l2vpn_tree_config);
	l2vpn_cli_init();
}

const char *l2vpn_svc_error_code(uint32_t status)
{
	static char buf[16];

	switch (status) {
	case F_L2VPN_NO_ERR:
		return ("No Error");
	case F_L2VPN_LOCAL_NOT_FWD:
		return ("local not forwarding");
	case F_L2VPN_REMOTE_NOT_FWD:
		return ("remote not forwarding");
	case F_L2VPN_NO_REMOTE_LABEL:
		return ("no remote label");
	case F_L2VPN_MTU_MISMATCH:
		return ("mtu mismatch between peers");
	default:
		snprintf(buf, sizeof(buf), "[%0x]", status);
		return buf;
	}
}
