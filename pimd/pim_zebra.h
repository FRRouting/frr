// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#ifndef PIM_ZEBRA_H
#define PIM_ZEBRA_H

#include <zebra.h>
#include "zclient.h"

#include "pim_ifchannel.h"

void pim_zebra_init(void);
void pim_zebra_zclient_update(struct vty *vty);

void pim_scan_oil(struct pim_instance *pim_matcher);

void pim_forward_start(struct pim_ifchannel *ch);
void pim_forward_stop(struct pim_ifchannel *ch);

void sched_rpf_cache_refresh(struct pim_instance *pim);
struct zclient *pim_zebra_zclient_get(void);

void pim_zebra_update_all_interfaces(struct pim_instance *pim);
void pim_zebra_upstream_rpf_changed(struct pim_instance *pim,
				    struct pim_upstream *up,
				    struct pim_rpf *old);

void pim_zebra_interface_set_master(struct interface *vrf,
				    struct interface *ifp);
#endif /* PIM_ZEBRA_H */
