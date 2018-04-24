/*
 * Nexthop Group structure definition.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *                    Donald Sharp
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include <vrf.h>
#include <sockunion.h>
#include <nexthop.h>
#include <nexthop_group.h>
#include <vty.h>
#include <command.h>

#ifndef VTYSH_EXTRACT_PL
#include "lib/nexthop_group_clippy.c"
#endif

DEFINE_MTYPE_STATIC(LIB, NEXTHOP_GROUP, "Nexthop Group")

struct nexthop_group_hooks {
	void (*new)(const char *name);
	void (*add_nexthop)(const struct nexthop_group_cmd *nhg,
			    const struct nexthop *nhop);
	void (*del_nexthop)(const struct nexthop_group_cmd *nhg,
			    const struct nexthop *nhop);
	void (*delete)(const char *name);
};

static struct nexthop_group_hooks nhg_hooks;

static inline int
nexthop_group_cmd_compare(const struct nexthop_group_cmd *nhgc1,
			  const struct nexthop_group_cmd *nhgc2);
RB_GENERATE(nhgc_entry_head, nexthop_group_cmd, nhgc_entry,
	    nexthop_group_cmd_compare)

struct nhgc_entry_head nhgc_entries;

static inline int
nexthop_group_cmd_compare(const struct nexthop_group_cmd *nhgc1,
			  const struct nexthop_group_cmd *nhgc2)
{
	return strcmp(nhgc1->name, nhgc2->name);
}

struct nexthop *nexthop_exists(struct nexthop_group *nhg, struct nexthop *nh)
{
	struct nexthop *nexthop;

	for (nexthop = nhg->nexthop; nexthop; nexthop = nexthop->next) {
		if (nexthop_same(nh, nexthop))
			return nexthop;
	}

	return NULL;
}

struct nexthop_group *nexthop_group_new(void)
{
	return XCALLOC(MTYPE_NEXTHOP_GROUP, sizeof(struct nexthop_group));
}

void nexthop_group_delete(struct nexthop_group **nhg)
{
	XFREE(MTYPE_NEXTHOP_GROUP, *nhg);
}

/* Add nexthop to the end of a nexthop list.  */
void nexthop_add(struct nexthop **target, struct nexthop *nexthop)
{
	struct nexthop *last;

	for (last = *target; last && last->next; last = last->next)
		;
	if (last)
		last->next = nexthop;
	else
		*target = nexthop;
	nexthop->prev = last;
}

/* Delete nexthop from a nexthop list.  */
void nexthop_del(struct nexthop_group *nhg, struct nexthop *nh)
{
	struct nexthop *nexthop;

	for (nexthop = nhg->nexthop; nexthop; nexthop = nexthop->next) {
		if (nexthop_same(nh, nexthop))
			break;
	}

	assert(nexthop);

	if (nexthop->prev)
		nexthop->prev->next = nexthop->next;
	else
		nhg->nexthop = nexthop->next;

	if (nexthop->next)
		nexthop->next->prev = nexthop->prev;

	nh->prev = NULL;
	nh->next = NULL;
}

void copy_nexthops(struct nexthop **tnh, struct nexthop *nh,
		   struct nexthop *rparent)
{
	struct nexthop *nexthop;
	struct nexthop *nh1;

	for (nh1 = nh; nh1; nh1 = nh1->next) {
		nexthop = nexthop_new();
		nexthop->vrf_id = nh1->vrf_id;
		nexthop->ifindex = nh1->ifindex;
		nexthop->type = nh1->type;
		nexthop->flags = nh1->flags;
		memcpy(&nexthop->gate, &nh1->gate, sizeof(nh1->gate));
		memcpy(&nexthop->src, &nh1->src, sizeof(nh1->src));
		memcpy(&nexthop->rmap_src, &nh1->rmap_src,
		       sizeof(nh1->rmap_src));
		nexthop->rparent = rparent;
		if (nh1->nh_label)
			nexthop_add_labels(nexthop, nh1->nh_label_type,
					   nh1->nh_label->num_labels,
					   &nh1->nh_label->label[0]);
		nexthop_add(tnh, nexthop);

		if (CHECK_FLAG(nh1->flags, NEXTHOP_FLAG_RECURSIVE))
			copy_nexthops(&nexthop->resolved, nh1->resolved,
				      nexthop);
	}
}

static void nhgc_delete_nexthops(struct nexthop_group_cmd *nhgc)
{
	struct nexthop *nexthop;

	nexthop = nhgc->nhg.nexthop;
	while (nexthop) {
		struct nexthop *next = nexthop_next(nexthop);

		nexthop_del(&nhgc->nhg, nexthop);
		if (nhg_hooks.del_nexthop)
			nhg_hooks.del_nexthop(nhgc, nexthop);

		nexthop_free(nexthop);

		nexthop = next;
	}
}

struct nexthop_group_cmd *nhgc_find(const char *name)
{
	struct nexthop_group_cmd find;

	strlcpy(find.name, name, sizeof(find.name));

	return RB_FIND(nhgc_entry_head, &nhgc_entries, &find);
}

static int nhgc_cmp_helper(const char *a, const char *b)
{
	if (!a && !b)
		return 0;

	if (a && !b)
		return -1;

	if (!a && b)
		return 1;

	return strcmp(a, b);
}

static int nhgl_cmp(struct nexthop_hold *nh1, struct nexthop_hold *nh2)
{
	int ret;

	ret = sockunion_cmp(&nh1->addr, &nh2->addr);
	if (ret)
		return ret;

	ret = nhgc_cmp_helper(nh1->intf, nh2->intf);
	if (ret)
		return ret;

	return nhgc_cmp_helper(nh1->nhvrf_name, nh2->nhvrf_name);
}

static void nhgl_delete(struct nexthop_hold *nh)
{
	if (nh->intf)
		XFREE(MTYPE_TMP, nh->intf);

	if (nh->nhvrf_name)
		XFREE(MTYPE_TMP, nh->nhvrf_name);

	XFREE(MTYPE_TMP, nh);
}

static struct nexthop_group_cmd *nhgc_get(const char *name)
{
	struct nexthop_group_cmd *nhgc;

	nhgc = nhgc_find(name);
	if (!nhgc) {
		nhgc = XCALLOC(MTYPE_TMP, sizeof(*nhgc));
		strlcpy(nhgc->name, name, sizeof(nhgc->name));

		QOBJ_REG(nhgc, nexthop_group_cmd);
		RB_INSERT(nhgc_entry_head, &nhgc_entries, nhgc);

		nhgc->nhg_list = list_new();
		nhgc->nhg_list->cmp = (int (*)(void *, void *))nhgl_cmp;
		nhgc->nhg_list->del = (void (*)(void *))nhgl_delete;

		if (nhg_hooks.new)
			nhg_hooks.new(name);
	}

	return nhgc;
}

static void nhgc_delete(struct nexthop_group_cmd *nhgc)
{
	nhgc_delete_nexthops(nhgc);

	if (nhg_hooks.delete)
		nhg_hooks.delete(nhgc->name);

	RB_REMOVE(nhgc_entry_head, &nhgc_entries, nhgc);

	list_delete_and_null(&nhgc->nhg_list);

	XFREE(MTYPE_TMP, nhgc);
}

DEFINE_QOBJ_TYPE(nexthop_group_cmd)

DEFUN_NOSH(nexthop_group, nexthop_group_cmd, "nexthop-group NAME",
	   "Enter into the nexthop-group submode\n"
	   "Specify the NAME of the nexthop-group\n")
{
	const char *nhg_name = argv[1]->arg;
	struct nexthop_group_cmd *nhgc = NULL;

	nhgc = nhgc_get(nhg_name);
	VTY_PUSH_CONTEXT(NH_GROUP_NODE, nhgc);

	return CMD_SUCCESS;
}

DEFUN_NOSH(no_nexthop_group, no_nexthop_group_cmd, "no nexthop-group NAME",
	   NO_STR
	   "Delete the nexthop-group\n"
	   "Specify the NAME of the nexthop-group\n")
{
	const char *nhg_name = argv[2]->arg;
	struct nexthop_group_cmd *nhgc = NULL;

	nhgc = nhgc_find(nhg_name);
	if (nhgc)
		nhgc_delete(nhgc);

	return CMD_SUCCESS;
}

static void nexthop_group_save_nhop(struct nexthop_group_cmd *nhgc,
				    const char *nhvrf_name,
				    const union sockunion *addr,
				    const char *intf)
{
	struct nexthop_hold *nh;

	nh = XCALLOC(MTYPE_TMP, sizeof(*nh));

	if (nhvrf_name)
		nh->nhvrf_name = XSTRDUP(MTYPE_TMP, nhvrf_name);
	if (intf)
		nh->intf = XSTRDUP(MTYPE_TMP, intf);

	nh->addr = *addr;

	listnode_add_sort(nhgc->nhg_list, nh);
}

static void nexthop_group_unsave_nhop(struct nexthop_group_cmd *nhgc,
				      const char *nhvrf_name,
				      const union sockunion *addr,
				      const char *intf)
{
	struct nexthop_hold *nh;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(nhgc->nhg_list, node, nh)) {
		if (nhgc_cmp_helper(nhvrf_name, nh->nhvrf_name) == 0 &&
		    sockunion_cmp(addr, &nh->addr) == 0 &&
		    nhgc_cmp_helper(intf, nh->intf) == 0)
			break;
	}

	/*
	 * Something has gone seriously wrong, fail gracefully
	 */
	if (!nh)
		return;

	list_delete_node(nhgc->nhg_list, node);

	if (nh->nhvrf_name)
		XFREE(MTYPE_TMP, nh->nhvrf_name);
	if (nh->intf)
		XFREE(MTYPE_TMP, nh->intf);

	XFREE(MTYPE_TMP, nh);
}

static bool nexthop_group_parse_nexthop(struct nexthop *nhop,
					const union sockunion *addr,
					const char *intf, const char *name)
{
	struct vrf *vrf;

	memset(nhop, 0, sizeof(*nhop));

	if (name)
		vrf = vrf_lookup_by_name(name);
	else
		vrf = vrf_lookup_by_id(VRF_DEFAULT);

	if (!vrf)
		return false;

	nhop->vrf_id = vrf->vrf_id;

	if (addr->sa.sa_family == AF_INET) {
		nhop->gate.ipv4.s_addr = addr->sin.sin_addr.s_addr;
		if (intf) {
			nhop->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			nhop->ifindex = ifname2ifindex(intf, vrf->vrf_id);
			if (nhop->ifindex == IFINDEX_INTERNAL)
				return false;
		} else
			nhop->type = NEXTHOP_TYPE_IPV4;
	} else {
		memcpy(&nhop->gate.ipv6, &addr->sin6.sin6_addr, 16);
		if (intf) {
			nhop->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			nhop->ifindex = ifname2ifindex(intf, vrf->vrf_id);
			if (nhop->ifindex == IFINDEX_INTERNAL)
				return false;
		} else
			nhop->type = NEXTHOP_TYPE_IPV6;
	}

	return true;
}

DEFPY(ecmp_nexthops, ecmp_nexthops_cmd,
      "[no] nexthop <A.B.C.D|X:X::X:X>$addr [INTERFACE]$intf [nexthop-vrf NAME$name]",
      NO_STR
      "Specify one of the nexthops in this ECMP group\n"
      "v4 Address\n"
      "v6 Address\n"
      "Interface to use\n"
      "If the nexthop is in a different vrf tell us\n"
      "The nexthop-vrf Name\n")
{
	VTY_DECLVAR_CONTEXT(nexthop_group_cmd, nhgc);
	struct nexthop nhop;
	struct nexthop *nh;
	bool legal;

	/*
	 * This is impossible to happen as that the cli parser refuses
	 * to let you get here without an addr, but the SA system
	 * does not understand this intricacy
	 */
	assert(addr);

	legal = nexthop_group_parse_nexthop(&nhop, addr, intf, name);

	if (nhop.type == NEXTHOP_TYPE_IPV6
	    && IN6_IS_ADDR_LINKLOCAL(&nhop.gate.ipv6)) {
		vty_out(vty,
			"Specified a v6 LL with no interface, rejecting\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nh = nexthop_exists(&nhgc->nhg, &nhop);

	if (no) {
		nexthop_group_unsave_nhop(nhgc, name, addr, intf);
		if (nh) {
			nexthop_del(&nhgc->nhg, nh);

			if (nhg_hooks.del_nexthop)
				nhg_hooks.del_nexthop(nhgc, nh);

			nexthop_free(nh);
		}
	} else if (!nh) {
		/* must be adding new nexthop since !no and !nexthop_exists */
		if (legal) {
			nh = nexthop_new();

			memcpy(nh, &nhop, sizeof(nhop));
			nexthop_add(&nhgc->nhg.nexthop, nh);
		}

		nexthop_group_save_nhop(nhgc, name, addr, intf);

		if (legal && nhg_hooks.add_nexthop)
			nhg_hooks.add_nexthop(nhgc, nh);
	}

	return CMD_SUCCESS;
}

struct cmd_node nexthop_group_node = {
	NH_GROUP_NODE,
	"%s(config-nh-group)# ",
	1
};

void nexthop_group_write_nexthop(struct vty *vty, struct nexthop *nh)
{
	char buf[100];
	struct vrf *vrf;

	vty_out(vty, "nexthop ");

	switch (nh->type) {
	case NEXTHOP_TYPE_IFINDEX:
		vty_out(vty, "%s", ifindex2ifname(nh->ifindex, nh->vrf_id));
		break;
	case NEXTHOP_TYPE_IPV4:
		vty_out(vty, "%s", inet_ntoa(nh->gate.ipv4));
		break;
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		vty_out(vty, "%s %s", inet_ntoa(nh->gate.ipv4),
			ifindex2ifname(nh->ifindex, nh->vrf_id));
		break;
	case NEXTHOP_TYPE_IPV6:
		vty_out(vty, "%s",
			inet_ntop(AF_INET6, &nh->gate.ipv6, buf, sizeof(buf)));
		break;
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		vty_out(vty, "%s %s",
			inet_ntop(AF_INET6, &nh->gate.ipv6, buf, sizeof(buf)),
			ifindex2ifname(nh->ifindex, nh->vrf_id));
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		break;
	}

	if (nh->vrf_id != VRF_DEFAULT) {
		vrf = vrf_lookup_by_id(nh->vrf_id);
		vty_out(vty, " nexthop-vrf %s", vrf->name);
	}
	vty_out(vty, "\n");
}

static void nexthop_group_write_nexthop_internal(struct vty *vty,
						 struct nexthop_hold *nh)
{
	char buf[100];

	vty_out(vty, "nexthop ");

	vty_out(vty, "%s", sockunion2str(&nh->addr, buf, sizeof(buf)));

	if (nh->intf)
		vty_out(vty, " %s", nh->intf);

	if (nh->nhvrf_name)
		vty_out(vty, " nexthop-vrf %s", nh->nhvrf_name);

	vty_out(vty, "\n");
}

static int nexthop_group_write(struct vty *vty)
{
	struct nexthop_group_cmd *nhgc;
	struct nexthop_hold *nh;

	RB_FOREACH (nhgc, nhgc_entry_head, &nhgc_entries) {
		struct listnode *node;

		vty_out(vty, "nexthop-group %s\n", nhgc->name);

		for (ALL_LIST_ELEMENTS_RO(nhgc->nhg_list, node, nh)) {
			vty_out(vty, "  ");
			nexthop_group_write_nexthop_internal(vty, nh);
		}

		vty_out(vty, "!\n");
	}

	return 1;
}

void nexthop_group_enable_vrf(struct vrf *vrf)
{
	struct nexthop_group_cmd *nhgc;
	struct nexthop_hold *nhh;

	RB_FOREACH (nhgc, nhgc_entry_head, &nhgc_entries) {
		struct listnode *node;

		for (ALL_LIST_ELEMENTS_RO(nhgc->nhg_list, node, nhh)) {
			struct nexthop nhop;
			struct nexthop *nh;

			if (!nexthop_group_parse_nexthop(&nhop, &nhh->addr,
							 nhh->intf,
							 nhh->nhvrf_name))
				continue;

			nh = nexthop_exists(&nhgc->nhg, &nhop);

			if (nh)
				continue;

			if (nhop.vrf_id != vrf->vrf_id)
				continue;

			nh = nexthop_new();

			memcpy(nh, &nhop, sizeof(nhop));
			nexthop_add(&nhgc->nhg.nexthop, nh);

			if (nhg_hooks.add_nexthop)
				nhg_hooks.add_nexthop(nhgc, nh);
		}
	}
}

void nexthop_group_disable_vrf(struct vrf *vrf)
{
	struct nexthop_group_cmd *nhgc;
	struct nexthop_hold *nhh;

	RB_FOREACH (nhgc, nhgc_entry_head, &nhgc_entries) {
		struct listnode *node;

		for (ALL_LIST_ELEMENTS_RO(nhgc->nhg_list, node, nhh)) {
			struct nexthop nhop;
			struct nexthop *nh;

			if (!nexthop_group_parse_nexthop(&nhop, &nhh->addr,
							 nhh->intf,
							 nhh->nhvrf_name))
				continue;

			nh = nexthop_exists(&nhgc->nhg, &nhop);

			if (!nh)
				continue;

			if (nh->vrf_id != vrf->vrf_id)
				continue;

			nexthop_del(&nhgc->nhg, nh);

			if (nhg_hooks.del_nexthop)
				nhg_hooks.del_nexthop(nhgc, nh);

			nexthop_free(nh);
		}
	}
}

void nexthop_group_interface_state_change(struct interface *ifp,
					  ifindex_t oldifindex)
{
	struct nexthop_group_cmd *nhgc;
	struct nexthop_hold *nhh;

	RB_FOREACH (nhgc, nhgc_entry_head, &nhgc_entries) {
		struct listnode *node;
		struct nexthop *nh;

		if (if_is_up(ifp)) {
			for (ALL_LIST_ELEMENTS_RO(nhgc->nhg_list, node, nhh)) {
				struct nexthop nhop;

				if (!nexthop_group_parse_nexthop(
					    &nhop, &nhh->addr, nhh->intf,
					    nhh->nhvrf_name))
					continue;

				switch (nhop.type) {
				case NEXTHOP_TYPE_IPV4:
				case NEXTHOP_TYPE_IPV6:
				case NEXTHOP_TYPE_BLACKHOLE:
					continue;
				case NEXTHOP_TYPE_IFINDEX:
				case NEXTHOP_TYPE_IPV4_IFINDEX:
				case NEXTHOP_TYPE_IPV6_IFINDEX:
					break;
				}
				nh = nexthop_exists(&nhgc->nhg, &nhop);

				if (nh)
					continue;

				if (ifp->ifindex != nhop.ifindex)
					continue;

				nh = nexthop_new();

				memcpy(nh, &nhop, sizeof(nhop));
				nexthop_add(&nhgc->nhg.nexthop, nh);

				if (nhg_hooks.add_nexthop)
					nhg_hooks.add_nexthop(nhgc, nh);
			}
		} else {
			struct nexthop *next_nh;

			for (nh = nhgc->nhg.nexthop; nh; nh = next_nh) {
				next_nh = nh->next;
				switch (nh->type) {
				case NEXTHOP_TYPE_IPV4:
				case NEXTHOP_TYPE_IPV6:
				case NEXTHOP_TYPE_BLACKHOLE:
					continue;
				case NEXTHOP_TYPE_IFINDEX:
				case NEXTHOP_TYPE_IPV4_IFINDEX:
				case NEXTHOP_TYPE_IPV6_IFINDEX:
					break;
				}

				if (oldifindex != nh->ifindex)
					continue;

				nexthop_del(&nhgc->nhg, nh);

				if (nhg_hooks.del_nexthop)
					nhg_hooks.del_nexthop(nhgc, nh);

				nexthop_free(nh);
			}
		}
	}
}

void nexthop_group_init(void (*new)(const char *name),
			void (*add_nexthop)(const struct nexthop_group_cmd *nhg,
					    const struct nexthop *nhop),
			void (*del_nexthop)(const struct nexthop_group_cmd *nhg,
					    const struct nexthop *nhop),
			void (*delete)(const char *name))
{
	RB_INIT(nhgc_entry_head, &nhgc_entries);

	install_node(&nexthop_group_node, nexthop_group_write);
	install_element(CONFIG_NODE, &nexthop_group_cmd);
	install_element(CONFIG_NODE, &no_nexthop_group_cmd);

	install_default(NH_GROUP_NODE);
	install_element(NH_GROUP_NODE, &ecmp_nexthops_cmd);

	memset(&nhg_hooks, 0, sizeof(nhg_hooks));

	if (new)
		nhg_hooks.new = new;
	if (add_nexthop)
		nhg_hooks.add_nexthop = add_nexthop;
	if (del_nexthop)
		nhg_hooks.del_nexthop = del_nexthop;
	if (delete)
		nhg_hooks.delete = delete;
}
