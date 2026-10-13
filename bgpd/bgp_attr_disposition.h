// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2026 Qipeng Ding */
#ifndef _FRR_BGP_ATTR_DISPOSITION_H
#define _FRR_BGP_ATTR_DISPOSITION_H

#include "bgpd/bgp_attr.h"

/* Remember withdrawals while bounded validation continues. Fatal outcomes
 * are not deferred: the caller must handle them immediately. A later
 * successful handler cannot erase an earlier withdrawal.
 */
static inline bool bgp_attr_defer_withdraw(enum bgp_attr_parse_ret *pending,
					 enum bgp_attr_parse_ret current)
{
	if (current != BGP_ATTR_PARSE_WITHDRAW && current != BGP_ATTR_PARSE_WITHDRAW_IGNORE)
		return false;
	if (*pending != BGP_ATTR_PARSE_WITHDRAW)
		*pending = current;
	return true;
}

#endif
