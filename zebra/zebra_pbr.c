/* Zebra Policy Based Routing (PBR) main handling.
 * Copyright (C) 2018  Cumulus Networks, Inc.
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#include <jhash.h>
#include <hash.h>

#include "zebra/zebra_pbr.h"
#include "zebra/rt.h"

/* definitions */

/* static function declarations */

/* Private functions */

/* Public functions */
void zebra_pbr_rules_free(void *arg)
{
	struct zebra_pbr_rule *rule;

	rule = (struct zebra_pbr_rule *)arg;

	kernel_del_pbr_rule(rule);
	XFREE(MTYPE_TMP, rule);
}

uint32_t zebra_pbr_rules_hash_key(void *arg)
{
	struct zebra_pbr_rule *rule;
	uint32_t key;

	rule = (struct zebra_pbr_rule *)arg;
	key = jhash_3words(rule->seq, rule->priority, rule->action.table,
			   prefix_hash_key(&rule->filter.src_ip));
	if (rule->ifp)
		key = jhash_1word(rule->ifp->ifindex, key);
	else
		key = jhash_1word(0, key);

	return jhash_3words(rule->filter.src_port, rule->filter.dst_port,
			    prefix_hash_key(&rule->filter.dst_ip),
			    jhash_1word(rule->unique, key));
}

int zebra_pbr_rules_hash_equal(const void *arg1, const void *arg2)
{
	const struct zebra_pbr_rule *r1, *r2;

	r1 = (const struct zebra_pbr_rule *)arg1;
	r2 = (const struct zebra_pbr_rule *)arg2;

	if (r1->seq != r2->seq)
		return 0;

	if (r1->priority != r2->priority)
		return 0;

	if (r1->unique != r2->unique)
		return 0;

	if (r1->action.table != r2->action.table)
		return 0;

	if (r1->filter.src_port != r2->filter.src_port)
		return 0;

	if (r1->filter.dst_port != r2->filter.dst_port)
		return 0;

	if (!prefix_same(&r1->filter.src_ip, &r2->filter.src_ip))
		return 0;

	if (!prefix_same(&r1->filter.dst_ip, &r2->filter.dst_ip))
		return 0;

	if (r1->ifp != r2->ifp)
		return 0;

	return 1;
}

static void *pbr_rule_alloc_intern(void *arg)
{
	struct zebra_pbr_rule *zpr;
	struct zebra_pbr_rule *new;

	zpr = (struct zebra_pbr_rule *)arg;

	new = XCALLOC(MTYPE_TMP, sizeof(*new));

	memcpy(new, zpr, sizeof(*zpr));

	return new;
}

void zebra_pbr_add_rule(struct zebra_ns *zns, struct zebra_pbr_rule *rule)
{
	(void)hash_get(zns->rules_hash, rule, pbr_rule_alloc_intern);
	kernel_add_pbr_rule(rule);
}

void zebra_pbr_del_rule(struct zebra_ns *zns, struct zebra_pbr_rule *rule)
{
	struct zebra_pbr_rule *lookup;

	lookup = hash_lookup(zns->rules_hash, rule);
	kernel_del_pbr_rule(rule);

	if (lookup)
		XFREE(MTYPE_TMP, lookup);
	else
		zlog_warn("%s: Rule being deleted we know nothing about",
			  __PRETTY_FUNCTION__);
}

/*
 * Handle success or failure of rule (un)install in the kernel.
 */
void kernel_pbr_rule_add_del_status(struct zebra_pbr_rule *rule,
				    enum southbound_results res)
{
	switch (res) {
	case SOUTHBOUND_INSTALL_SUCCESS:
		zsend_rule_notify_owner(rule, ZAPI_RULE_INSTALLED);
		break;
	case SOUTHBOUND_INSTALL_FAILURE:
		zsend_rule_notify_owner(rule, ZAPI_RULE_FAIL_INSTALL);
		break;
	case SOUTHBOUND_DELETE_SUCCESS:
		break;
	case SOUTHBOUND_DELETE_FAILURE:
		break;
	}
}

/*
 * Handle rule delete notification from kernel.
 */
int kernel_pbr_rule_del(struct zebra_pbr_rule *rule)
{
	return 0;
}
