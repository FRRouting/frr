// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * ISO Network definition - iso_net.h
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 *
 * Copyright (C) 2023 Orange http://www.orange.com
 */

#ifndef LIB_ISO_H_
#define LIB_ISO_H_

#include "compiler.h"
#include "typesafe.h"

/* len of "xx.xxxx.xxxx.xxxx.xxxx.xxxx.xxxx.xxxx.xxxx.xxxx.xx" + '\0' */
#define ISO_ADDR_STRLEN	51
#define ISO_ADDR_MIN	8
#define ISO_ADDR_SIZE	20

/* Predeclare typesafe list for isis_area->area_addrs */
PREDECL_DLIST(iso_address_list);

struct iso_address {
	uint8_t addr_len;
	uint8_t area_addr[ISO_ADDR_SIZE];

	/* Typesafe list linkage for isis_area->area_addrs */
	struct iso_address_list_item item;
};

DECLARE_DLIST(iso_address_list, struct iso_address, item);

/* len of "xxxx.xxxx.xxxx.xx-xx" + '\0' */
#define ISO_SYSID_STRLEN 21

#ifdef _FRR_ATTRIBUTE_PRINTFRR
#pragma FRR printfrr_ext "%pSY" (uint8_t *)
#pragma FRR printfrr_ext "%pPN" (uint8_t *)
#pragma FRR printfrr_ext "%pLS" (uint8_t *)
#pragma FRR printfrr_ext "%pIS" (struct iso_address *)
#endif

#endif /* LIB_ISO_H_ */
