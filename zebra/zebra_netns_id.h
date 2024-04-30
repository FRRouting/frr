// SPDX-License-Identifier: GPL-2.0-or-later
/* zebra NETNS ID handling routines
 * Copyright (C) 2018 6WIND
 */
#if !defined(__ZEBRA_NS_ID_H__)
#define __ZEBRA_NS_ID_H__
#include "zebra.h"
#include "ns.h"

#ifdef __cplusplus
extern "C" {
#endif

extern ns_id_t zebra_ns_id_get(const char *netnspath, int fd);
extern ns_id_t zebra_ns_id_get_default(void);

#ifdef __cplusplus
}
#endif

#endif /* __ZEBRA_NS_ID_H__ */
