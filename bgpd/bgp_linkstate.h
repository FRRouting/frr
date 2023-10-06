// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Link-State header
 * Copyright 2023 6WIND S.A.
 */

#ifndef _FRR_BGP_LINKSTATE_H
#define _FRR_BGP_LINKSTATE_H

uintptr_t bgp_linkstate_ptr_new(uint8_t *pnt, uint16_t length);
void bgp_linkstate_ptr_free(uintptr_t ptr);

void bgp_linkstate_init(void);
#endif /* _FRR_BGP_LINKSTATE_H */
