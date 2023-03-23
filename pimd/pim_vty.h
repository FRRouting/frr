// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#ifndef PIM_VTY_H
#define PIM_VTY_H

#include "vty.h"

struct pim_instance;

int pim_debug_config_write(struct vty *vty);
int pim_global_config_write_worker(struct pim_instance *pim, struct vty *vty);
int pim_interface_config_write(struct vty *vty);
int pim_config_write(struct vty *vty, int writes, struct interface *ifp,
		     struct pim_instance *pim);
#endif /* PIM_VTY_H */
