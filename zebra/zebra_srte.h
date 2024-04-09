// SPDX-License-Identifier: GPL-2.0-or-later
/* Zebra's client header.
 * Copyright (C) 2020 Netdef, Inc.
 */

#ifndef _ZEBRA_SRTE_H
#define _ZEBRA_SRTE_H

#include "zebra/zebra_mpls.h"

#include "lib/zclient.h"
#include "lib/srte.h"

#ifdef __cplusplus
extern "C" {
#endif

enum zebra_sr_policy_update_label_mode {
	ZEBRA_SR_POLICY_LABEL_CREATED = 1,
	ZEBRA_SR_POLICY_LABEL_UPDATED = 2,
	ZEBRA_SR_POLICY_LABEL_REMOVED = 3,
};

struct zebra_sr_policy {
	RB_ENTRY(zebra_sr_policy) entry;
	uint32_t color;
	struct ipaddr endpoint;
	char name[SRTE_POLICY_NAME_MAX_LENGTH];
	enum zebra_sr_policy_status status;
	struct zapi_srte_tunnel segment_list;
	struct zebra_lsp *lsp;
	struct zebra_vrf *zvrf;
	int sock;
};
RB_HEAD(zebra_sr_policy_instance_head, zebra_sr_policy);
RB_PROTOTYPE(zebra_sr_policy_instance_head, zebra_sr_policy, entry,
	     zebra_sr_policy_instance_compare)

extern struct zebra_sr_policy_instance_head zebra_sr_policy_instances;

struct zebra_sr_policy *
zebra_sr_policy_add(uint32_t color, struct ipaddr *endpoint, char *name);
void zebra_sr_policy_del(struct zebra_sr_policy *policy);
struct zebra_sr_policy *zebra_sr_policy_find(uint32_t color,
					     struct ipaddr *endpoint);
struct zebra_sr_policy *zebra_sr_policy_find_by_name(char *name);
int zebra_sr_policy_validate(struct zebra_sr_policy *policy,
			     struct zapi_srte_tunnel *new_tunnel);
int zebra_sr_policy_bsid_install(struct zebra_sr_policy *policy);
void zebra_sr_policy_bsid_uninstall(struct zebra_sr_policy *policy,
				    mpls_label_t old_bsid);
void zebra_srte_init(void);
int zebra_sr_policy_label_update(mpls_label_t label,
				 enum zebra_sr_policy_update_label_mode mode);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_SRTE_H */
