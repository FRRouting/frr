// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra ietf-interfaces northbound interface.
 * Copyright (C) 2026  Eric Parsonage
 */

#include <zebra.h>

#include "if.h"
#include "vrf.h"

#include "zebra/zebra_ietf_interfaces_nb.h"

static struct interface *zebra_ietf_interfaces_lookup(const char *name)
{
	struct vrf *vrf;
	struct interface if_tmp;

	if (vrf_is_backend_netns()) {
		char ifname[XPATH_MAXLEN];
		char vrfname[XPATH_MAXLEN];
		char *separator;

		strlcpy(vrfname, name, sizeof(vrfname));
		separator = strchr(vrfname, ':');
		if (!separator)
			return NULL;

		*separator = '\0';
		strlcpy(ifname, separator + 1, sizeof(ifname));
		vrf = vrf_lookup_by_name(vrfname);
		if (!vrf)
			return NULL;

		strlcpy(if_tmp.name, ifname, sizeof(if_tmp.name));
		return RB_FIND(if_name_head, &vrf->ifaces_by_name, &if_tmp);
	}

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		struct interface *ifp;

		strlcpy(if_tmp.name, name, sizeof(if_tmp.name));
		ifp = RB_FIND(if_name_head, &vrf->ifaces_by_name, &if_tmp);

		if (ifp)
			return ifp;
	}

	return NULL;
}

static void zebra_ietf_interfaces_key(const struct interface *ifp, char *key,
				      size_t key_len)
{
	if (vrf_is_backend_netns())
		snprintf(key, key_len, "%s:%s", ifp->vrf->name, ifp->name);
	else
		snprintf(key, key_len, "%s", ifp->name);
}

/*
 * XPath: /ietf-interfaces:interfaces/interface
 */
static const void *zebra_ietf_interfaces_interface_get_next(struct nb_cb_get_next_args *args)
{
	struct interface *ifp = (struct interface *)args->list_entry;
	struct vrf *vrf;

	if (ifp == NULL) {
		vrf = RB_MIN(vrf_name_head, &vrfs_by_name);
		return vrf ? RB_MIN(if_name_head, &vrf->ifaces_by_name) : NULL;
	}

	vrf = ifp->vrf;
	ifp = RB_NEXT(if_name_head, ifp);

	while (ifp == NULL) {
		vrf = RB_NEXT(vrf_name_head, vrf);
		if (!vrf)
			return NULL;
		ifp = RB_MIN(if_name_head, &vrf->ifaces_by_name);
	}

	return ifp;
}

static int zebra_ietf_interfaces_interface_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct interface *ifp = args->list_entry;

	args->keys->num = 1;
	zebra_ietf_interfaces_key(ifp, args->keys->key[0],
				  sizeof(args->keys->key[0]));

	return NB_OK;
}

static const void *
zebra_ietf_interfaces_interface_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	return zebra_ietf_interfaces_lookup(args->keys->key[0]);
}

/*
 * XPath: /ietf-interfaces:interfaces/interface/name
 */
static struct yang_data *
zebra_ietf_interfaces_interface_name_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct interface *ifp = args->list_entry;
	char name[XPATH_MAXLEN];

	zebra_ietf_interfaces_key(ifp, name, sizeof(name));

	return yang_data_new_string(args->xpath, name);
}

/*
 * XPath: /ietf-interfaces:interfaces/interface/oper-status
 */
static struct yang_data *
zebra_ietf_interfaces_interface_oper_status_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct interface *ifp = args->list_entry;

	return yang_data_new_enum(args->xpath,
				  CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_ACTIVE)
					  ? 1
					  : 2);
}

/*
 * RFC 9129 references ietf-interfaces:interfaces/interface/name from OSPF
 * interface state. Zebra owns FRR's interface table, so it provides the
 * standard interface name list as operational state for those leafrefs.
 */

/* clang-format off */
const struct frr_yang_module_info zebra_ietf_interfaces_info = {
	.name = "ietf-interfaces",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/ietf-interfaces:interfaces/interface",
			.cbs = {
				.get_next = zebra_ietf_interfaces_interface_get_next,
				.get_keys = zebra_ietf_interfaces_interface_get_keys,
				.lookup_entry = zebra_ietf_interfaces_interface_lookup_entry,
			},
		},
		{
			.xpath = "/ietf-interfaces:interfaces/interface/name",
			.cbs = {
				.get_elem = zebra_ietf_interfaces_interface_name_get_elem,
			},
		},
		{
			.xpath = "/ietf-interfaces:interfaces/interface/oper-status",
			.cbs = {
				.get_elem = zebra_ietf_interfaces_interface_oper_status_get_elem,
			},
		},
		{
			.xpath = NULL,
		},
	},
};
/* clang-format on */
