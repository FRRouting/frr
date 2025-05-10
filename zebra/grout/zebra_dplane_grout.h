// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra dataplane plugin for Grout
 *
 * Copyright (C) 2024 Red Hat
 * Christophe Fontaine
 */

#ifndef _ZEBRA_DPLANE_GROUT_H
#define _ZEBRA_DPLANE_GROUT_H

#include <zebra.h>

int grout_client_send_recv(uint32_t req_type, size_t tx_len, const void *tx_data, void **rx_data);

#endif
