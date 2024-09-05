// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SR-TE definitions
 * Copyright 2020 NetDef Inc.
 *                Sascha Kattelmann
 */

#ifndef _FRR_SRTE_H
#define _FRR_SRTE_H

#ifdef __cplusplus
extern "C" {
#endif

#define SRTE_POLICY_NAME_MAX_LENGTH 64

enum zebra_sr_policy_status {
	ZEBRA_SR_POLICY_UP = 0,
	ZEBRA_SR_POLICY_DOWN,
};

/* SR types. */
enum sr_types {
	ZEBRA_SR_LSP_NONE = 0,	/* No LSP. */
	ZEBRA_SR_LSP_SRTE = 1,	/* SR-TE LSP */
	ZEBRA_SR_SRV6_SRTE = 2, /* SRv6 SID List*/
};

static inline enum lsp_types_t lsp_type_from_sr_type(enum sr_types sr_type)
{
	switch (sr_type) {
	case ZEBRA_SR_LSP_SRTE:
		return ZEBRA_LSP_SRTE;
	case ZEBRA_SR_LSP_NONE:
	case ZEBRA_SR_SRV6_SRTE:
	default:
		return ZEBRA_LSP_NONE;
	}
};

static inline int sr_policy_compare(const struct ipaddr *a_endpoint,
				    const struct ipaddr *b_endpoint,
				    uint32_t a_color, uint32_t b_color)
{
	int ret;

	ret = ipaddr_cmp(a_endpoint, b_endpoint);
	if (ret < 0)
		return -1;
	if (ret > 0)
		return 1;

	return a_color - b_color;
}

#ifdef __cplusplus
}
#endif

#endif /* _FRR_SRTE_H */
