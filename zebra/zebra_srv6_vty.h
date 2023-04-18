// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra SRv6 VTY functions
 * Copyright (C) 2020  Hiroki Shirokura, LINE Corporation
 */

#ifndef _ZEBRA_SRV6_VTY_H
#define _ZEBRA_SRV6_VTY_H

#define ZEBRA_SRV6_LOCATOR_BLOCK_LENGTH 40
#define ZEBRA_SRV6_LOCATOR_NODE_LENGTH 24
#define ZEBRA_SRV6_FUNCTION_LENGTH 16

extern void zebra_srv6_vty_init(void);

#endif /* _ZEBRA_SRV6_VTY_H */
