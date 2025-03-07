// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IP MSDP socket management for Quagga
 * Copyright (C) 2016 Cumulus Networks, Inc.
 */
#ifndef PIM_MSDP_SOCKET_H
#define PIM_MSDP_SOCKET_H

struct pim_msdp_peer;

int pim_msdp_sock_auth_listen(struct pim_msdp_peer *mp);
int pim_msdp_sock_listen(struct pim_instance *pim);
int pim_msdp_sock_connect(struct pim_msdp_peer *mp);
#endif
