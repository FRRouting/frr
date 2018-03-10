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

static struct nexthop_group_cmd *nhgc_get(const char *name)
{
	struct nexthop_group_cmd *nhgc;

	nhgc = nhgc_find(name);
	if (!nhgc) {
		nhgc = XCALLOC(MTYPE_TMP, sizeof(*nhgc));
		strlcpy(nhgc->name, name, sizeof(nhgc->name));

		QOBJ_REG(nhgc, nexthop_group_cmd);
		RB_INSERT(nhgc_entry_head, &nhgc_entries, nhgc);

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
	struct vrf *vrf;
	struct nexthop nhop;
	struct nexthop *nh;

	if (name)
		vrf = vrf_lookup_by_name(name);
	else
		vrf = vrf_lookup_by_id(VRF_DEFAULT);

	if (!vrf) {
		vty_out(vty, "Specified: %s is non-existent\n", name);
		return CMD_WARNING;
	}

	memset(&nhop, 0, sizeof(nhop));
	nhop.vrf_id = vrf->vrf_id;

	if (addr->sa.sa_family == AF_INET) {
		nhop.gate.ipv4.s_addr = addr->sin.sin_addr.s_addr;
		if (intf) {
			nhop.type = NEXTHOP_TYPE_IPV4_IFINDEX;
			nhop.ifindex = ifname2ifindex(intf, vrf->vrf_id);
			if (nhop.ifindex == IFINDEX_INTERNAL) {
				vty_out(vty,
					"Specified Intf %s does not exist in vrf: %s\n",
					intf, vrf->name);
				return CMD_WARNING;
			}
		} else
			nhop.type = NEXTHOP_TYPE_IPV4;
	} else {
		memcpy(&nhop.gate.ipv6, &addr->sin6.sin6_addr, 16);
		if (intf) {
			nhop.type = NEXTHOP_TYPE_IPV6_IFINDEX;
			nhop.ifindex = ifname2ifindex(intf, vrf->vrf_id);
			if (nhop.ifindex == IFINDEX_INTERNAL) {
				vty_out(vty,
					"Specified Intf %s does not exist in vrf: %s\n",
					intf, vrf->name);
				return CMD_WARNING;
			}
		} else
			nhop.type = NEXTHOP_TYPE_IPV6;
	}

	nh = nexthop_exists(&nhgc->nhg, &nhop);

	if (no) {
		if (nh) {
			nexthop_del(&nhgc->nhg, nh);

			if (nhg_hooks.del_nexthop)
				nhg_hooks.del_nexthop(nhgc, nh);

			nexthop_free(nh);
		}
	} else if (!nh) {
		/* must be adding new nexthop since !no and !nexthop_exists */
		nh = nexthop_new();

		memcpy(nh, &nhop, sizeof(nhop));
		nexthop_add(&nhgc->nhg.nexthop, nh);

		if (nhg_hooks.add_nexthop)
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

	vty_out(vty, "  nexthop ");

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

static int nexthop_group_write(struct vty *vty)
{
	struct nexthop_group_cmd *nhgc;
	struct nexthop *nh;

	RB_FOREACH (nhgc, nhgc_entry_head, &nhgc_entries) {
		vty_out(vty, "nexthop-group %s\n", nhgc->name);

		for (nh = nhgc->nhg.nexthop; nh; nh = nh->next)
			nexthop_group_write_nexthop(vty, nh);

		vty_out(vty, "!\n");
	}

	return 1;
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
