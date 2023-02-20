// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#ifndef PIM_INT_H
#define PIM_INT_H

#include <stdint.h>

uint32_t pim_read_uint32_host(const uint8_t *buf);
void pim_write_uint32(uint8_t *buf, uint32_t val_host);

#endif /* PIM_INT_H */
