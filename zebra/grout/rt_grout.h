// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Grout routing tables
 *
 * Copyright (C) 2025 Free Mobile
 * Maxime Leroy
 */
#ifndef _RT_GROUT_H
#define _RT_GROUT_H

#include <gr_ip4.h>
#include <gr_ip6.h>

#include "zebra/zebra_dplane.h"

void grout_route4_change(bool new, struct gr_ip4_route *gr_r4);
void grout_route6_change(bool new, struct gr_ip6_route *gr_r6);
enum zebra_dplane_result grout_add_del_route(struct zebra_dplane_ctx *ctx);

#endif /* _RT_GROUT_H */
