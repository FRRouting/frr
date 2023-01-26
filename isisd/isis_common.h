// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_common.h
 *                             some common data structures
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */

#ifndef ISIS_COMMON_H
#define ISIS_COMMON_H

struct isis_passwd {
	uint8_t len;
#define ISIS_PASSWD_TYPE_UNUSED   0
#define ISIS_PASSWD_TYPE_CLEARTXT 1
#define ISIS_PASSWD_TYPE_HMAC_MD5 54
#define ISIS_PASSWD_TYPE_PRIVATE  255
	uint8_t type;
/* Authenticate SNPs? */
#define SNP_AUTH_SEND   0x01
#define SNP_AUTH_RECV   0x02
	uint8_t snp_auth;
	uint8_t passwd[255];
};

/*
 * Supported Protocol IDs
 */
struct nlpids {
	uint8_t count;
	uint8_t nlpids[4]; /* FIXME: enough ? */
};

#endif
