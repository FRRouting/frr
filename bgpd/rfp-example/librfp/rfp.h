// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Copyright 2015-2016, LabN Consulting, L.L.C.
 *
 */

/* Sample header file */
#ifndef _RFP_H
#define _RFP_H

#include "bgpd/rfapi/rfapi.h"
extern int bgp_rfp_cfg_write(void *vty, void *bgp);
/* TO BE REMOVED */
void rfp_clear_vnc_nve_all(void);

#endif /* _RFP_H */
