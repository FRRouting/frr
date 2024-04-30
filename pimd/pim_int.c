// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#include <zebra.h>

#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "pim_int.h"

uint32_t pim_read_uint32_host(const uint8_t *buf)
{
	uint32_t val;
	memcpy(&val, buf, sizeof(val));
	/* val is in netorder */
	val = ntohl(val);
	/* val is in hostorder */
	return val;
}

void pim_write_uint32(uint8_t *buf, uint32_t val_host)
{
	/* val_host is in host order */
	val_host = htonl(val_host);
	/* val_host is in netorder */
	memcpy(buf, &val_host, sizeof(val_host));
}
