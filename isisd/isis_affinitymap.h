// SPDX-License-Identifier: GPL-2.0-or-later
/* IS-IS  affinity-map header
 * Copyright 2023 6WIND S.A.
 */

#ifndef __ISIS_AFFINITYMAP_H__
#define __ISIS_AFFINITYMAP_H__

#include "lib/affinitymap.h"

#ifndef FABRICD

#ifdef __cplusplus
extern "C" {
#endif

extern void isis_affinity_map_init(void);

#ifdef __cplusplus
}
#endif

#endif /* ifndef FABRICD */

#endif /* __ISIS_AFFINITYMAP_H__ */
