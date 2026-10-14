// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_common.h
 *                             some common data structures
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 * Copyright (C) 2003        Ofer Wald, Hannes Gredler
 */

#ifndef ISIS_COMMON_H
#define ISIS_COMMON_H

struct isis_passwd {
	uint8_t len;
#define ISIS_PASSWD_TYPE_UNUSED   0
#define ISIS_PASSWD_TYPE_CLEARTXT 1
#define ISIS_PASSWD_TYPE_CRYPTO_AUTH 3 /* RFC 5310 */
#define ISIS_PASSWD_TYPE_HMAC_MD5 54
#define ISIS_PASSWD_TYPE_PRIVATE  255
	uint8_t type;
/* Authenticate SNPs? */
#define SNP_AUTH_SEND   0x01
#define SNP_AUTH_RECV   0x02
	uint8_t snp_auth;
	/* The password, or for ISIS_PASSWD_TYPE_CRYPTO_AUTH the key chain name */
	uint8_t passwd[255];
};

/* RFC 7602 Extended Sequence Numbers on a circuit */
enum isis_esn_mode {
	ISIS_ESN_OFF = 0,
	ISIS_ESN_SEND,	 /* add the ESN TLV to IIHs and SNPs */
	ISIS_ESN_VERIFY, /* also discard IIHs and SNPs without a newer one */
};

/*
 * Supported Protocol IDs
 */
struct nlpids {
	uint8_t count;
	uint8_t nlpids[4]; /* FIXME: enough ? */
};

#endif
