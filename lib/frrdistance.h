// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra distance header
 * Copyright (C) 2023 NVIDIA Corporation
 * Donald Sharp
 *
 * Distance related defines.  FRR needs a common set
 * of values for distance.
 */
#ifndef __FRRDISTANCE_H__
#define __FRRDISTANCE_H__

/* Default Administrative Distance of each protocol. */
#define ZEBRA_KERNEL_DISTANCE_DEFAULT       0
#define ZEBRA_CONNECT_DISTANCE_DEFAULT      0
#define ZEBRA_STATIC_DISTANCE_DEFAULT       1
#define ZEBRA_RIP_DISTANCE_DEFAULT        120
#define ZEBRA_RIPNG_DISTANCE_DEFAULT      120
#define ZEBRA_OSPF_DISTANCE_DEFAULT       110
#define ZEBRA_OSPF6_DISTANCE_DEFAULT      110
#define ZEBRA_ISIS_DISTANCE_DEFAULT       115
#define ZEBRA_IBGP_DISTANCE_DEFAULT       200
#define ZEBRA_EBGP_DISTANCE_DEFAULT        20
#define ZEBRA_TABLE_DISTANCE_DEFAULT       15
#define ZEBRA_TABLEDIRECT_DISTANCE_DEFAULT 14
#define ZEBRA_EIGRP_DISTANCE_DEFAULT       90
#define ZEBRA_NHRP_DISTANCE_DEFAULT        10
#define ZEBRA_LDP_DISTANCE_DEFAULT        150
#define ZEBRA_BABEL_DISTANCE_DEFAULT      100
#define ZEBRA_SHARP_DISTANCE_DEFAULT      150
#define ZEBRA_PBR_DISTANCE_DEFAULT        200
#define ZEBRA_OPENFABRIC_DISTANCE_DEFAULT 115
#define ZEBRA_MAX_DISTANCE_DEFAULT        255

#endif
