// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * bgp_rpki code
 * Copyright (C) 2021 NVIDIA Corporation and Mellanox Technologies, LTD
 *                    All Rights Reserved
 *               Donald Sharp
 */
#ifndef __BGP_RPKI_H__
#define __BGP_RPKI_H__

extern struct zebra_privs_t bgpd_privs;

enum rpki_states {
	RPKI_NOT_BEING_USED,
	RPKI_VALID,
	RPKI_NOTFOUND,
	RPKI_INVALID
};

#endif
