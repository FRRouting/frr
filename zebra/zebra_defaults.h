// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra defaults header message
 */

#ifndef _ZEBRA_DEFAULTS_H_
#define _ZEBRA_DEFAULTS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "defaults.h"
#include "zebra/interface.h"

FRR_CFG_DEFAULT_BOOL(ZEBRA_IP_NHT_RESOLVE_VIA_DEFAULT,
		     {
			     .val_bool = true,
			     .match_profile = "traditional",
		     },
		     { .val_bool = false },
		     );

FRR_CFG_DEFAULT_UINT8_T(ZEBRA_MPLS,
			{ .val_uint8_t = IF_ZEBRA_DATA_UNSPEC },
			);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_DEFAULTS_H_ */
