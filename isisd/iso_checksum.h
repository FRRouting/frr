// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - iso_checksum.c
 *                             ISO checksum related routines
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */
#ifndef _ZEBRA_ISO_CSUM_H
#define _ZEBRA_ISO_CSUM_H

int iso_csum_verify(uint8_t *buffer, int len, uint16_t csum, int offset);

#endif /* _ZEBRA_ISO_CSUM_H */
