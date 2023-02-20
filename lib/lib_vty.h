// SPDX-License-Identifier: GPL-2.0-or-later
/* Memory management routine
 * Copyright (C) 1998 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_LIB_VTY_H
#define _ZEBRA_LIB_VTY_H

#include "memory.h"

#ifdef __cplusplus
extern "C" {
#endif

extern void lib_cmd_init(void);

/* Human friendly string for given byte count */
#define MTYPE_MEMSTR_LEN 20
extern const char *mtype_memstr(char *, size_t, unsigned long);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_LIB_VTY_H */
