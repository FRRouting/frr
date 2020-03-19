/*
 * Copyright 2020, LabN Consulting, L.L.C.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FRR_KEYCRYPT_H
#define _FRR_KEYCRYPT_H

#include <zebra.h>
#include <memory.h>

#undef KEYCRYPT_ENABLED
/* NB HAVE_GNUTLS is ignored because it does not support oaep yet */
/* NB coordinate changes here with CPP logic at start of keycrypt.c */
#if defined HAVE_OPENSSL || defined HAVE_LIBRESSL || defined HAVE_GCRYPT
#define KEYCRYPT_ENABLED 1
#endif

DECLARE_MTYPE(KEYCRYPT_CIPHER_B64)
DECLARE_MTYPE(KEYCRYPT_PLAIN_TEXT)

/*
 * return codes used by some functions
 */
/* clang-format off */
enum keycrypt_err {
	KC_OK = 0,
	KC_ERR_MEMORY,		/* allocation failure */
	KC_ERR_BASE64,		/* base64 encode/decode error */
	KC_ERR_DECRYPT,
	KC_ERR_ENCRYPT,
	KC_ERR_BUILD_NOT_ENABLED,
	KC_ERR_KEYFILE_PATH,	/* can't generate keyfile path */
	KC_ERR_KEYFILE_READ,	/* can't read keyfile */
	KC_ERR_KEYFILE_PARSE,	/* can't parse keyfile */
	KC_ERR_KEYFILE_EXISTS,	/* would overwrite existing keyfile */
	KC_ERR_INTERNAL,	/* unexpected error */
};
/* clang-format on */

const char *keycrypt_strerror(enum keycrypt_err kc_err);

#ifdef KEYCRYPT_ENABLED

extern void keycrypt_base64_encode(const char *pIn, size_t InLen, char **ppOut,
				   size_t *pOutLen);

extern void keycrypt_base64_decode(const char *pIn, size_t InLen, char **ppOut,
				   size_t *pOutLen);

#endif /* KEYCRYPT_ENABLED */

extern void keycrypt_init(void);

typedef void(keycrypt_callback_t)(bool);
struct vty; /* pet compiler for next line */
typedef void(keycrypt_show_callback_t)(struct vty *, const char *);

void keycrypt_register_protocol_callback(keycrypt_callback_t *kcb);

void keycrypt_register_protocol_show_callback(keycrypt_show_callback_t *kcb);

bool keycrypt_is_now_encrypting(void);

void keycrypt_state_change(bool now_encrypting);

extern int keycrypt_encrypt(const char *pPlainText,  /* IN */
			    size_t PlainTextLen,     /* IN */
			    char **ppCipherText,     /* OUT */
			    size_t *pCipherTextLen); /* OUT */

extern int keycrypt_decrypt(struct memtype *mt, /* of PlainText */ /* IN */
			    const char *pCipherText,		   /* IN */
			    size_t CipherTextLen,		   /* IN */
			    char **pPlainText,			   /* OUT */
			    size_t *pPlainTextLen);		   /* OUT */

extern enum keycrypt_err keycrypt_build_passwords(
	const char *password_in,      /* IN */
	bool is_encrypted,	    /* IN */
	struct memtype *mt_plaintext, /* IN */
	char **ppPlainText,	   /* OUT MTYPE_KEY */
	char **ppCryptText);	  /* OUT MTYPE_KEYCRYPT_CIPHER_B64 */

#endif /* _FRR_KEYCRYPT_H */
