// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DSCP manipulation routines header
 * Copyright (C) 2023 VyOS Inc.
 * Volodymyr Huti
 */

#ifndef FRR_DSCP_H
#define FRR_DSCP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <zebra.h>
#include "vty.h"

#define DSFIELD_DSCP (0xfc) /* Upper 6 bits of DS field: DSCP */
#define DSFIELD_ECN (0x03)  /* Lower 2 bits of DS field: BCN */

extern uint8_t dscp_decode_enum(const char *dscp);
extern const char *dscp_enum_str(int dscp);

#ifdef __cplusplus
}
#endif

#endif /* FRR_DSCP_H */
