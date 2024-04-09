// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#ifndef PIM_MACRO_H
#define PIM_MACRO_H

#include <zebra.h>

#include "if.h"

#include "pim_upstream.h"
#include "pim_ifchannel.h"

int pim_macro_ch_lost_assert(const struct pim_ifchannel *ch);
int pim_macro_chisin_joins(const struct pim_ifchannel *ch);
int pim_macro_chisin_pim_include(const struct pim_ifchannel *ch);
int pim_macro_chisin_joins_or_include(const struct pim_ifchannel *ch);
int pim_macro_ch_could_assert_eval(const struct pim_ifchannel *ch);
struct pim_assert_metric pim_macro_spt_assert_metric(const struct pim_rpf *rpf,
						     pim_addr ifaddr);
struct pim_assert_metric
pim_macro_ch_my_assert_metric_eval(const struct pim_ifchannel *ch);
int pim_macro_chisin_oiflist(const struct pim_ifchannel *ch);
int pim_macro_assert_tracking_desired_eval(const struct pim_ifchannel *ch);

#endif /* PIM_MACRO_H */
