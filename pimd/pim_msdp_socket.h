// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IP MSDP socket management for Quagga
 * Copyright (C) 2016 Cumulus Networks, Inc.
 */
#ifndef PIM_MSDP_SOCKET_H
#define PIM_MSDP_SOCKET_H

<<<<<<< HEAD
=======
struct pim_msdp_peer;

int pim_msdp_sock_auth_listen(struct pim_msdp_peer *mp);
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
int pim_msdp_sock_listen(struct pim_instance *pim);
int pim_msdp_sock_connect(struct pim_msdp_peer *mp);
#endif
