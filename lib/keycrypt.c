/*
 * Copyright 2020, LabN Consulting, L.L.C.
 * Copyright (C) 2008 Free Software Foundation, Inc.
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

#include <zebra.h>
#include <sbuf.h>

#include "memory.h"
#include "log.h"
#include "keycrypt.h"
#include "command.h"
#include "keychain.h"
#include "libfrr.h"
#include "lib_errors.h"

DEFINE_MTYPE(LIB, KEYCRYPT_CIPHER_B64, "keycrypt base64 encoded")
DEFINE_MTYPE(LIB, KEYCRYPT_PLAIN_TEXT, "keycrypt plain text")

/* not compatible with oaep padding */
#define KEYCRYPT_ENABLE_PKCS1_PADDING 0

#ifdef KEYCRYPT_ENABLED

/*
 * normalize backend flag names
 */
#if 0 && defined(HAVE_GNUTLS) /* currently has no oaep mode, so disable */
#define KEYCRYPT_HAVE_GNUTLS 1
#endif
#if defined(HAVE_OPENSSL) || defined(HAVE_LIBRESSL)
#define KEYCRYPT_HAVE_OPENSSL 1
#endif
#if defined(HAVE_GCRYPT)
#define KEYCRYPT_HAVE_GCRYPT 1
#endif

#if !defined(KEYCRYPT_HAVE_GNUTLS) && !defined(KEYCRYPT_HAVE_OPENSSL)          \
	&& !defined(KEYCRYPT_HAVE_GCRYPT)
#error "KEYCRYPT_ENABLED defined but no backend defined"
#endif

#endif /* KEYCRYPT_ENABLED */

#ifdef KEYCRYPT_HAVE_GNUTLS
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include <gnutls/abstract.h>
#endif

#ifdef KEYCRYPT_HAVE_OPENSSL
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#endif

#ifdef KEYCRYPT_HAVE_GCRYPT
#include <gcrypt.h>
#endif

/***********************************************************************
 *		KEYCRYPT internal definitions
 ***********************************************************************/

/* #define KEYFILE_NAME_PRIVATE ".ssh/frr" */
#define KEYFILE_NAME_PRIVATE "frr_pk_rsa"
#define PWENT_BUFSIZE 512

DEFINE_MTYPE_STATIC(LIB, KEYCRYPT_KEYFILE_PATH, "keycrypt keyfile path")
DEFINE_MTYPE_STATIC(LIB, KEYCRYPT_CIPHER_TEXT, "keycrypt cipher text")
DEFINE_MTYPE_STATIC(LIB, KEYCRYPT_B64DEC, "keycrypt base64 decoded")

/* don't hit disk more often than this interval: */
#define KEYCRYPT_CHECK_PKEY_SECONDS 10

#ifdef KEYCRYPT_ENABLED
/*
 * Compute path to keyfile
 *
 * Caller must free returned buffer XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, path)
 *
 * Return value is NULL on failure.
 */
static char *keycrypt_keyfile_path(void)
{
	const char *hc;
	const char *config_dir = NULL;
	const char *kf_base = KEYFILE_NAME_PRIVATE;
	char cwd[MAXPATHLEN];
	char *slash;
	char *path;
	int config_dir_len = 0;
	size_t total_length;

	/*
	 * compute config directory
	 */
	hc = host_config_get();
	if (hc) {
		slash = strrchr(hc, '/');
		if (slash) {
			config_dir = hc;
			config_dir_len = slash - hc;
		} else {
			if (getcwd(cwd, MAXPATHLEN) == NULL) {
				flog_err_sys(EC_LIB_SYSTEM_CALL,
					     "%s: getcwd: %s", __func__,
					     strerror(errno));
				return NULL;
			}
			config_dir = cwd;
			config_dir_len = strlen(config_dir);
		}
	} else {
		config_dir = frr_sysconfdir;
		slash = strrchr(config_dir, '/');
		assert(slash);
		config_dir_len = strlen(config_dir);
	}

	total_length = config_dir_len + 1 + strlen(kf_base) + 1;
	path = XMALLOC(MTYPE_KEYCRYPT_KEYFILE_PATH, total_length);
	snprintf(path, total_length, "%.*s/%s", config_dir_len, config_dir,
		 kf_base);

	return path;
}
#endif /* KEYCRYPT_ENABLED */

/* clang-format off */
typedef int be_encrypt_t(
	const char	*pPlainText,
	size_t		PlainTextLen,
	char		**ppCipherTextB64,
	size_t		*pCipherTextB64Len);

typedef int be_decrypt_t(
	struct memtype	*mt,
	const char	*pCipherTextB64,
	size_t		CipherTextB64Len,
	char		**ppPlainText,
	size_t		*pPlainTextLen);

typedef int be_test_cmd_t(
	struct vty	*vty,
	const char	*cleartext);

typedef enum keycrypt_err be_keyfile_read_status_t(
	const char	*keyfile_path,
	const char	**detail);

struct keycrypt_backend {
	const char			*name;
	be_encrypt_t			*f_encrypt;
	be_decrypt_t			*f_decrypt;
	be_test_cmd_t			*f_test_cmd;
	be_keyfile_read_status_t	*f_keyfile_read_status;
	const char			*(*f_be_version_string)(void);
};
/* clang-format on */

/***********************************************************************
 *		openssl-specific functions
 ***********************************************************************/

#ifdef KEYCRYPT_HAVE_OPENSSL

enum keycrypt_openssl_key_format {
	KEYCRYPT_FORMAT_ASN1,
	KEYCRYPT_FORMAT_PEM,
	KEYCRYPT_FORMAT_PVK,
};

/*
 * To generate a suitable private key, use:
 *
 *      chmod 0700 .ssh
 *      openssl genpkey -algorithm RSA -out .ssh/frr
 *      chmod 0400 .ssh/frr
 *
 * returns pointer to EVP_PKEY, or NULL. Caller must free EVP_PKEY
 * when done, via EVP_PKEY_free(pkey).
 *
 * We read only the private keyfile because:
 *  1. It contains both the private and public keys
 *  2. We need to be able to decrypt and encrypt
 */
/* clang-format off */
static enum keycrypt_err keycrypt_read_keyfile_openssl(
	const char *path,
	EVP_PKEY **ppKey)
/* clang-format on */
{
	FILE *fp;
	BIO *fb;
	EVP_PKEY *pkey = NULL;
	const char *formatstr = "";
	enum keycrypt_openssl_key_format format = KEYCRYPT_FORMAT_PEM;

	*ppKey = NULL;

	/*
	 * Use fopen() instead of BIO_new_file() so we can get meaningful
	 * error messages to the log for not-found or permission issues.
	 */
	fp = fopen(path, "r");
	if (!fp) {
		zlog_err("%s: fopen(\"%s\") failed: %s", __func__, path,
			 safe_strerror(errno));
		return KC_ERR_KEYFILE_READ;
	}

	fb = BIO_new_fp(fp, BIO_CLOSE);
	if (!fb) {
		fclose(fp);
		zlog_err("%s: BIO_new_fp() failed", __func__);
		return KC_ERR_KEYFILE_READ;
	}

	switch (format) {
	case KEYCRYPT_FORMAT_ASN1:
		pkey = d2i_PrivateKey_bio(fb, NULL);
		formatstr = "ASN1";
		break;
	case KEYCRYPT_FORMAT_PEM:
		pkey = PEM_read_bio_PrivateKey(fb, NULL, NULL, NULL);
		formatstr = "PEM";
		break;
	case KEYCRYPT_FORMAT_PVK:
		pkey = b2i_PVK_bio(fb, NULL, NULL);
		formatstr = "PVK";
		break;
	default:
		zlog_err("%s: unknown format %u: not supported", __func__,
			 format);
	}

	BIO_free(fb);

	if (!pkey)
		zlog_err(
			"%s: unable to load format \"%s\" key from file \"%s\"",
			__func__, formatstr, path);

	*ppKey = pkey;
	return 0;
}

/*
 * Caller must free result XFREE(MTYPE_KEYCRYPT_CIPHER_B64, *pOut)
 */
static void keycrypt_base64_encode_openssl(const char *pIn, size_t InLen,
					   char **ppOut, size_t *pOutLen)
{
	BIO *bio_b64;
	BIO *bio_mem;
	BUF_MEM *obufmem;

	bio_mem = BIO_new(BIO_s_mem());
	bio_b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(bio_b64, bio_mem);
	BIO_write(bio_b64, pIn, InLen);

	/* NetBSD 8 openssl BIO_flush() returns int */
	(void)BIO_flush(bio_b64);

	BIO_get_mem_ptr(bio_mem, &obufmem);
	*ppOut = XMALLOC(MTYPE_KEYCRYPT_CIPHER_B64, obufmem->length + 1);
	memcpy(*ppOut, obufmem->data, obufmem->length);
	*((*ppOut) + obufmem->length) = 0; /* NUL-terminate */
	*pOutLen = obufmem->length;

	BIO_free_all(bio_b64);
}

/*
 * Caller must free result XFREE(MTYPE_KEYCRYPT_B64DEC, *pOut)
 */
static void keycrypt_base64_decode_openssl(const char *pIn, size_t InLen,
					   char **ppOut, size_t *pOutLen)
{
	BIO *bio_b64;
	BIO *bio_mem;
	BIO *bio_omem;
	BUF_MEM *obufmem;
	char inbuf[512];
	int inlen;

	/*
	 * Debian 8, Ubuntu 14.04 openssl
	 * BIO_new_mem_buf() discards const from 1st arg
	 */
	bio_mem = BIO_new_mem_buf((void *)pIn, InLen);
	bio_b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(bio_b64, BIO_FLAGS_BASE64_NO_NL);
	BIO_push(bio_b64, bio_mem);

	bio_omem = BIO_new(BIO_s_mem());

	while ((inlen = BIO_read(bio_b64, inbuf, sizeof(inbuf))) > 0)
		BIO_write(bio_omem, inbuf, inlen);

	/* NetBSD 8 openssl BIO_flush() returns int */
	(void)BIO_flush(bio_omem);
	BIO_free_all(bio_b64);

	BIO_get_mem_ptr(bio_omem, &obufmem);
	*ppOut = XMALLOC(MTYPE_KEYCRYPT_B64DEC, obufmem->length + 1);
	memcpy(*ppOut, obufmem->data, obufmem->length);
	*((*ppOut) + obufmem->length) = 0; /* NUL-terminate */
	*pOutLen = obufmem->length;

	BIO_free_all(bio_omem);
}

/*
 * Encrypt provided plain text.
 *
 * Returns dynamically-allocated cipher text, which caller must
 * free via XFREE(KEYCRYPT_CIPHER_TEXT, pCipherText)
 *
 * Return value is 0 if successful, non-0 for error
 *
 * NOTE: RSA encryption has a cleartext size limit slightly less
 * (11 bits => 2 bytes?) than the key size.
 */
/* clang-format off */
static int keycrypt_encrypt_internal_openssl_padding(
	int		paddingtype,			/* IN */
	EVP_PKEY	*pKey,				/* IN */
	struct memtype	*mt,	/* of CipherText */	/* IN */
	const char	*pPlainText,			/* IN */
	size_t		PlainTextLen,			/* IN */
	char		**ppCipherText,			/* OUT */
	size_t		*pCipherTextLen)		/* OUT */

/* clang-format on */
{
	EVP_PKEY_CTX *ctx;
	ENGINE *eng = NULL; /* default RSA impl */
	int rc;

	ctx = EVP_PKEY_CTX_new(pKey, eng);
	if (!ctx) {
		zlog_warn("%s: unable to alloc context", __func__);
		return -1;
	}

	rc = EVP_PKEY_encrypt_init(ctx);
	if (rc <= 0) {
		EVP_PKEY_CTX_free(ctx);
		zlog_warn("%s: Error: EVP_PKEY_encrypt_init%s", __func__,
			  ((rc == -2) ? ": not supported by public key alg"
				      : ""));
		return -1;
	}

	rc = EVP_PKEY_CTX_set_rsa_padding(ctx, paddingtype);
	if (rc <= 0) {
		EVP_PKEY_CTX_free(ctx);
		zlog_warn("%s: Error: EVP_PKEY_CTX_set_rsa_padding%s", __func__,
			  ((rc == -2) ? ": not supported by public key alg"
				      : ""));
		return -1;
	}

	/* Determine buffer length */
	rc = EVP_PKEY_encrypt(ctx, NULL, pCipherTextLen,
			      (const u8 *)pPlainText, PlainTextLen);
	if (rc <= 0) {
		EVP_PKEY_CTX_free(ctx);
		zlog_warn("%s: Error: EVP_PKEY_encrypt (1)%s", __func__,
			  ((rc == -2) ? ": not supported by public key alg"
				      : ""));
		return -1;
	}

	*ppCipherText = XMALLOC(mt, *pCipherTextLen);

	rc = EVP_PKEY_encrypt(ctx, (u8 *)*ppCipherText, pCipherTextLen,
			      (const u8 *)pPlainText, PlainTextLen);
	if (rc <= 0) {
		EVP_PKEY_CTX_free(ctx);
		XFREE(mt, *ppCipherText);
		zlog_warn("%s: Error: EVP_PKEY_encrypt (2)%s", __func__,
			  ((rc == -2) ? ": not supported by public key alg"
				      : ""));
		return -1;
	}

	EVP_PKEY_CTX_free(ctx);

	return 0;
}

/*
 * Decrypt provided cipher text.
 *
 * Returns dynamically-allocated plain text, which caller must
 * free via XFREE(KEYCRYPT_PLAIN_TEXT, pPlainText)
 *
 * Return value is 0 if successful, non-0 for error
 */
/* clang-format off */
static int keycrypt_decrypt_internal_openssl_padding(
	int		paddingtype,			/* IN */
	EVP_PKEY	*pKey,				/* IN */
	struct memtype	*mt,	/* of PlainText */	/* IN */
	const char	*pCipherText,			/* IN */
	size_t		CipherTextLen,			/* IN */
	char		**ppPlainText,			/* OUT */
	size_t		*pPlainTextLen)			/* OUT */

/* clang-format on */
{
	EVP_PKEY_CTX *ctx;
	ENGINE *eng = NULL; /* default RSA impl */
	int rc;

	ctx = EVP_PKEY_CTX_new(pKey, eng);
	if (!ctx) {
		zlog_warn("%s: unable to alloc context", __func__);
		return -1;
	}

	rc = EVP_PKEY_decrypt_init(ctx);
	if (rc <= 0) {
		EVP_PKEY_CTX_free(ctx);
		zlog_warn("%s: Error: EVP_PKEY_decrypt_init%s", __func__,
			  ((rc == -2) ? ": not supported by public key alg"
				      : ""));
		return -1;
	}

	rc = EVP_PKEY_CTX_set_rsa_padding(ctx, paddingtype);
	if (rc <= 0) {
		EVP_PKEY_CTX_free(ctx);
		zlog_warn("%s: Error: EVP_PKEY_CTX_set_rsa_padding%s", __func__,
			  ((rc == -2) ? ": not supported by public key alg"
				      : ""));
		return -1;
	}

	/* Determine buffer length */
	rc = EVP_PKEY_decrypt(ctx, NULL, pPlainTextLen,
			      (const u8 *)pCipherText, CipherTextLen);
	if (rc <= 0) {
		EVP_PKEY_CTX_free(ctx);
		zlog_warn("%s: Error: EVP_PKEY_decrypt (1)%s", __func__,
			  ((rc == -2) ? ": not supported by public key alg"
				      : ""));
		return -1;
	}

	*ppPlainText = XMALLOC(mt, *pPlainTextLen + 1);

	rc = EVP_PKEY_decrypt(ctx, (u8 *)*ppPlainText, pPlainTextLen,
			      (const u8 *)pCipherText, CipherTextLen);
	if (rc <= 0) {
		EVP_PKEY_CTX_free(ctx);
		if (*ppPlainText)
			XFREE(mt, *ppPlainText);
		zlog_warn(
			"%s: EVP_PKEY_decrypt (2) CipherTextLen %zu, PlainTextLen %zu",
			__func__, CipherTextLen, *pPlainTextLen);
		zlog_warn("%s: Error: EVP_PKEY_decrypt (2)%s", __func__,
			  ((rc == -2) ? ": not supported by public key alg"
				      : ""));
		return -1;
	}
	(*ppPlainText)[*pPlainTextLen] = '\0';

	EVP_PKEY_CTX_free(ctx);

	return 0;
}

/*
 * Allocates an EVP_PKEY which should later be freed via EVP_PKEY_free()
 */
static enum keycrypt_err keycrypt_read_default_keyfile_openssl(EVP_PKEY **ppKey)
{
	char *keyfile_path;
	enum keycrypt_err krc;

	*ppKey = NULL;

	keyfile_path = keycrypt_keyfile_path();
	if (!keyfile_path) {
		zlog_err("%s: Error: can't compute keyfile path\n", __func__);
		return KC_ERR_KEYFILE_PATH;
	}

	krc = keycrypt_read_keyfile_openssl(keyfile_path, ppKey);
	if (krc) {
		zlog_err("%s: Error: %s can't read \"%s\"\n",
			 __func__, "keycrypt_read_keyfile_openssl",
			 keyfile_path);
		XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);
		return KC_ERR_KEYFILE_READ;
	}
	XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);
	return KC_OK;
}

/*
 * Caller should not free returned key
 */
static EVP_PKEY *keycrypt_get_pkey_openssl()
{
	static time_t keycrypt_pkey_check_time;
	static EVP_PKEY *keycrypt_cached_pkey;

	time_t now;

	now = monotime(NULL);
	if (now - keycrypt_pkey_check_time > KEYCRYPT_CHECK_PKEY_SECONDS) {
		EVP_PKEY *pKey;
		enum keycrypt_err rc;

		keycrypt_pkey_check_time = now;

		rc = keycrypt_read_default_keyfile_openssl(&pKey);
		if (rc != KC_OK)
			goto end;

		if (keycrypt_cached_pkey)
			EVP_PKEY_free(keycrypt_cached_pkey);

		keycrypt_cached_pkey = pKey;
	}
end:
	return keycrypt_cached_pkey;
}

/*
 * After successful return (0), caller MUST free base-64 encoded
 * cipher text via XFREE(MTYPE_KEYCRYPT_CIPHER_B64, ptr)
 */
/* clang-format off */
static int keycrypt_encrypt_openssl_padding(
	int		paddingtype,		/* IN */
	const char	*pPlainText,		/* IN */
	size_t		PlainTextLen,		/* IN */
	char		**ppCipherTextB64,	/* OUT */
	size_t		*pCipherTextB64Len)	/* OUT */

/* clang-format on */
{
	EVP_PKEY *pKey;
	int rc;
	char *pCipherTextRaw;
	size_t CipherTextRawLen;
	size_t B64len;

	pKey = keycrypt_get_pkey_openssl();
	if (!pKey)
		return -1;

	rc = keycrypt_encrypt_internal_openssl_padding(
		paddingtype, pKey, MTYPE_KEYCRYPT_CIPHER_TEXT, pPlainText,
		PlainTextLen, &pCipherTextRaw, &CipherTextRawLen);
	if (rc)
		return -1;

	keycrypt_base64_encode_openssl(pCipherTextRaw, CipherTextRawLen,
				       ppCipherTextB64, &B64len);

	if (pCipherTextB64Len)
		*pCipherTextB64Len = B64len;

	XFREE(MTYPE_KEYCRYPT_CIPHER_TEXT, pCipherTextRaw);

	return 0;
}

/* clang-format off */
static int keycrypt_encrypt_openssl_pkcs1(
	const char	*pPlainText,		/* IN */
	size_t		PlainTextLen,		/* IN */
	char		**ppCipherTextB64,	/* OUT */
	size_t		*pCipherTextB64Len)	/* OUT */

{
	return keycrypt_encrypt_openssl_padding(
			RSA_PKCS1_PADDING,
			pPlainText,
			PlainTextLen,
			ppCipherTextB64,
			pCipherTextB64Len);
}

static int keycrypt_encrypt_openssl_oaep(
	const char	*pPlainText,		/* IN */
	size_t		PlainTextLen,		/* IN */
	char		**ppCipherTextB64,	/* OUT */
	size_t		*pCipherTextB64Len)	/* OUT */

{
	return keycrypt_encrypt_openssl_padding(
			RSA_PKCS1_OAEP_PADDING,
			pPlainText,
			PlainTextLen,
			ppCipherTextB64,
			pCipherTextB64Len);
}
/* clang-format on */

/* clang-format off */
static int keycrypt_decrypt_openssl_padding(
	int		paddingtype,			/* IN */
	struct memtype	*mt,	/* of PlainText */	/* IN */
	const char	*pCipherTextB64,		/* IN */
	size_t		CipherTextB64Len,		/* IN */
	char		**ppPlainText,			/* OUT */
	size_t		*pPlainTextLen)			/* OUT */

/* clang-format on */
{
	EVP_PKEY *pKey;
	int rc;
	char *pCipherTextRaw;
	size_t CipherTextRawLen;
	size_t PlainTextLen;

	pKey = keycrypt_get_pkey_openssl();
	if (!pKey)
		return -1;

	keycrypt_base64_decode_openssl(pCipherTextB64, CipherTextB64Len,
				       &pCipherTextRaw, &CipherTextRawLen);

	rc = keycrypt_decrypt_internal_openssl_padding(
		paddingtype, pKey, mt, pCipherTextRaw, CipherTextRawLen,
		ppPlainText, &PlainTextLen);

	XFREE(MTYPE_KEYCRYPT_B64DEC, pCipherTextRaw);

	if (rc)
		return -1;

	if (pPlainTextLen)
		*pPlainTextLen = PlainTextLen;

	return 0;
}

/* clang-format off */
static int keycrypt_decrypt_openssl_pkcs1(
	struct memtype	*mt,	/* of PlainText */	/* IN */
	const char	*pCipherTextB64,		/* IN */
	size_t		CipherTextB64Len,		/* IN */
	char		**ppPlainText,			/* OUT */
	size_t		*pPlainTextLen)			/* OUT */

{
	return keycrypt_decrypt_openssl_padding(
			RSA_PKCS1_PADDING,
			mt,
			pCipherTextB64,
			CipherTextB64Len,
			ppPlainText,
			pPlainTextLen);
}

static int keycrypt_decrypt_openssl_oaep(
	struct memtype	*mt,	/* of PlainText */	/* IN */
	const char	*pCipherTextB64,		/* IN */
	size_t		CipherTextB64Len,		/* IN */
	char		**ppPlainText,			/* OUT */
	size_t		*pPlainTextLen)			/* OUT */

{
	return keycrypt_decrypt_openssl_padding(
			RSA_PKCS1_OAEP_PADDING,
			mt,
			pCipherTextB64,
			CipherTextB64Len,
			ppPlainText,
			pPlainTextLen);
}
/* clang-format on */

/* clang-format off */
static int debug_keycrypt_test_cmd_openssl_padding(
	int		paddingtype,
	struct vty	*vty,
	const char	*cleartext)
/* clang-format on */
{
	char *keyfile_path = NULL;
	EVP_PKEY *pKey;
	int rc;
	char *pCipherText = NULL;
	size_t CipherTextLen;
	char *pClearText = NULL;
	size_t ClearTextLen;
	char *pB64Text;
	size_t B64TextLen;
	enum keycrypt_err krc;

	keyfile_path = keycrypt_keyfile_path();
	if (!keyfile_path) {
		vty_out(vty, "%s: Error: can't compute keyfile path\n",
			__func__);
		return CMD_SUCCESS;
	}

	krc = keycrypt_read_keyfile_openssl(keyfile_path, &pKey);
	if (krc) {
		vty_out(vty, "%s: Error: %s\n", __func__,
			"keycrypt_read_keyfile_openssl");
		XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);
		return CMD_SUCCESS;
	}
	XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);

	rc = keycrypt_encrypt_internal_openssl_padding(
		RSA_PKCS1_PADDING, pKey, MTYPE_KEYCRYPT_CIPHER_TEXT, cleartext,
		strlen(cleartext), &pCipherText, &CipherTextLen);
	if (rc) {
		EVP_PKEY_free(pKey);
		vty_out(vty, "%s: Error: keycrypt_encrypt_internal_openssl\n",
			__func__);
		return CMD_SUCCESS;
	}

	if (!pCipherText) {
		vty_out(vty, "%s: missing cipher text\n", __func__);
		return CMD_SUCCESS;
	}

	/*
	 * Encode for printing
	 */

	keycrypt_base64_encode_openssl(pCipherText, CipherTextLen, &pB64Text,
				       &B64TextLen);

	XFREE(MTYPE_KEYCRYPT_CIPHER_TEXT, pCipherText);

	vty_out(vty,
		"INFO: clear text len: %zu, CipherTextLen: %zu, B64TextLen %zu\n",
		strlen(cleartext), CipherTextLen, B64TextLen);

	vty_out(vty, "INFO: base64 cipher text:\n%s\n", pB64Text);


	/*
	 * Decode back to binary
	 */
	keycrypt_base64_decode_openssl(pB64Text, B64TextLen, &pCipherText,
				       &CipherTextLen);

	XFREE(MTYPE_KEYCRYPT_CIPHER_B64, pB64Text);

	vty_out(vty, "INFO: After B64 decode, CipherTextLen: %zu\n",
		CipherTextLen);


	rc = keycrypt_decrypt_internal_openssl_padding(
		RSA_PKCS1_PADDING, pKey, MTYPE_KEYCRYPT_PLAIN_TEXT, pCipherText,
		CipherTextLen, &pClearText, &ClearTextLen);

	EVP_PKEY_free(pKey);

	if (pCipherText) {
		if (!strncmp(cleartext, pCipherText, strlen(cleartext))) {
			vty_out(vty,
				"%s: cipher text and cleartext same for %zu chars\n",
				__func__, strlen(cleartext));
			XFREE(MTYPE_KEYCRYPT_B64DEC, pCipherText);
			if (pClearText)
				XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
			return CMD_SUCCESS;
		}
		XFREE(MTYPE_KEYCRYPT_B64DEC, pCipherText);
	}

	if (rc) {
		vty_out(vty, "%s: Error: keycrypt_decrypt_internal_openssl\n",
			__func__);
		if (pClearText)
			XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
		return CMD_SUCCESS;
	}

	if (!pClearText) {
		vty_out(vty,
			"%s: keycrypt_decrypt_internal_openssl didn't return clear text pointer\n",
			__func__);
		return CMD_SUCCESS;
	}
	if (strlen(cleartext) != ClearTextLen) {
		vty_out(vty,
			"%s: decrypted ciphertext length (%zu) != original length (%zu)\n",
			__func__, ClearTextLen, strlen(cleartext));
		XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
		return CMD_SUCCESS;
	}

	if (strncmp(cleartext, pClearText, ClearTextLen)) {
		vty_out(vty,
			"%s: decrypted ciphertext differs from original text\n",
			__func__);
		XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
		return CMD_SUCCESS;
	}

	vty_out(vty, "OK: decrypted ciphertext matches original text\n");
	return CMD_SUCCESS;
}

/* clang-format off */
static int debug_keycrypt_test_cmd_openssl_pkcs1(
	struct vty	*vty,
	const char	*cleartext)
/* clang-format on */
{
	return debug_keycrypt_test_cmd_openssl_padding(RSA_PKCS1_PADDING, vty,
						       cleartext);
}

/* clang-format off */
static int debug_keycrypt_test_cmd_openssl_oaep(
	struct vty	*vty,
	const char	*cleartext)
/* clang-format on */
{
	return debug_keycrypt_test_cmd_openssl_padding(RSA_PKCS1_OAEP_PADDING,
						       vty, cleartext);
}

static enum keycrypt_err keyfile_read_status_openssl(const char *keyfile_path,
						  const char **detail)
{
	enum keycrypt_err krc;
	EVP_PKEY *pKey;

	*detail = NULL;

	krc = keycrypt_read_keyfile_openssl(keyfile_path, &pKey);
	if (krc)
		*detail = keycrypt_strerror(krc);
	else
		EVP_PKEY_free(pKey);

	return krc;
}

static const char *keycrypt_backend_version_string_openssl(void)
{
	return OpenSSL_version(OPENSSL_VERSION);
}

/* clang-format off */
struct keycrypt_backend kbe_openssl_pkcs1 = {
	.name			= "openssl-pkcs1-padding",
	.f_encrypt		= keycrypt_encrypt_openssl_pkcs1,
	.f_decrypt		= keycrypt_decrypt_openssl_pkcs1,
	.f_test_cmd		= debug_keycrypt_test_cmd_openssl_pkcs1,
	.f_keyfile_read_status	= keyfile_read_status_openssl,
	.f_be_version_string	= keycrypt_backend_version_string_openssl,
};
struct keycrypt_backend kbe_openssl_oaep = {
	.name			= "openssl",
	.f_encrypt		= keycrypt_encrypt_openssl_oaep,
	.f_decrypt		= keycrypt_decrypt_openssl_oaep,
	.f_test_cmd		= debug_keycrypt_test_cmd_openssl_oaep,
	.f_keyfile_read_status	= keyfile_read_status_openssl,
	.f_be_version_string	= keycrypt_backend_version_string_openssl,
};
/* clang-format on */

#endif /* KEYCRYPT_HAVE_OPENSSL */


/***********************************************************************
 *		gnutls-specific functions
 ***********************************************************************/

#if defined KEYCRYPT_HAVE_GNUTLS

/*
 * If successful (return value is 0), allocates and fills in
 * private key structure. Caller is responsible for calling
 * gnutls_x509_privkey_deinit() to free private key structure
 */
/* clang-format off */
static enum keycrypt_err keycrypt_read_keyfile_gnutls(
	const char		*filename,
	/* gnutls_x509_privkey_t is a pointer to key struct */
	gnutls_x509_privkey_t	*ppPrivKey)	/* ptr to caller's ptr */
/* clang-format on */
{
	int rc;
	gnutls_datum_t data;

	rc = gnutls_load_file(filename, &data);
	if (rc) {
		zlog_err("%s: error: gnutls_load_file(\"%s\") returned %d: %s ",
			 __func__, filename, rc, gnutls_strerror(rc));
		return KC_ERR_KEYFILE_READ;
	}

	/*
	 * Allocates structure and saves ptr in *ppPrivKey
	 */
	rc = gnutls_x509_privkey_init(ppPrivKey);
	if (rc < 0) {
		zlog_err("%s: %s returned error %d: %s\n", __func__,
			 "gnutls_x509_privkey_init", rc, gnutls_strerror(rc));
		return KC_ERR_MEMORY;
	}
	rc = gnutls_x509_privkey_import2(*ppPrivKey, &data, GNUTLS_X509_FMT_PEM,
					 NULL /* password */,
					 GNUTLS_PKCS_PLAIN);
	free(data.data);
	if (rc < 0) {
		zlog_err("%s: %s returned error %d: %s\n", __func__,
			 "gnutls_x509_privkey_import2", rc,
			 gnutls_strerror(rc));
		gnutls_x509_privkey_deinit(*ppPrivKey); /* frees structure */
		return KC_ERR_KEYFILE_PARSE;
	}
	return KC_OK;
}

/*
 * Allocates a *gnutls_x509_privkey_t  which should later be
 * freed via gnutls_x509_privkey_deinit()
 */
static enum keycrypt_err
keycrypt_read_default_keyfile_gnutls(gnutls_x509_privkey_t *ppPrivKey)
{
	enum keycrypt_err rc;
	char *keyfile_path;

	*ppPrivKey = NULL;

	keyfile_path = keycrypt_keyfile_path();
	if (!keyfile_path) {
		zlog_err("%s: Error: can't compute keyfile path\n", __func__);
		return KC_ERR_KEYFILE_PATH;
	}

	rc = keycrypt_read_keyfile_gnutls(keyfile_path, ppPrivKey);
	if (rc) {
		zlog_err("%s: Error: %s can't read \"%s\"\n", __func__,
			 "keycrypt_read_keyfile_gnutls", keyfile_path);
		XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);
		return rc;
	}

	XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);
	return KC_OK;
}

/*
 * Caller should not free returned key
 */
static gnutls_x509_privkey_t keycrypt_get_pkey_gnutls(void)
{
	static time_t keycrypt_pkey_check_time;
	static gnutls_x509_privkey_t keycrypt_cached_pkey_gnutls; /* ptr type */
	time_t now;

	now = monotime(NULL);
	if (now - keycrypt_pkey_check_time > KEYCRYPT_CHECK_PKEY_SECONDS) {
		gnutls_x509_privkey_t pKey;
		enum keycrypt_err rc;

		keycrypt_pkey_check_time = now;

		rc = keycrypt_read_default_keyfile_gnutls(&pKey);
		if (rc != KC_OK)
			goto end;

		if (keycrypt_cached_pkey_gnutls)
			gnutls_x509_privkey_deinit(keycrypt_cached_pkey_gnutls);

		keycrypt_cached_pkey_gnutls = pKey;
	}
end:
	return keycrypt_cached_pkey_gnutls;
}

/* clang-format off */
enum kc_gt_privdata_params {
	GT_DATUM_M = 0,
	GT_DATUM_E,
	GT_DATUM_D,
	GT_DATUM_P,
	GT_DATUM_Q,
	GT_DATUM_U,
	GT_DATUM_E1,
	GT_DATUM_E2,
	N_GT_DATA
};

static int keycrypt_encrypt_internal_gnutls(
	gnutls_x509_privkey_t	pPrivKey,			/* IN */
	struct memtype		*mt,	/* of CipherText */	/* IN */
	const char		*pPlainText,			/* IN */
	size_t			PlainTextLen,			/* IN */
	char			**ppCipherText,			/* OUT */
	size_t			*pCipherTextLen)		/* OUT */

{
	int				rc;
	gnutls_datum_t			d[N_GT_DATA];
	gnutls_pubkey_t			pPubKey;
	enum kc_gt_privdata_params	i;
	/* clang-format on */

	for (i = GT_DATUM_M; i < N_GT_DATA; ++i)
		d[i].data = NULL;

	/*
	 * Derive public key from private key
	 */
	/* clang-format off */
	rc = gnutls_x509_privkey_export_rsa_raw(pPrivKey,
		d+GT_DATUM_M,
		d+GT_DATUM_E,
		d+GT_DATUM_D,
		d+GT_DATUM_P,
		d+GT_DATUM_Q,
		d+GT_DATUM_U);
	/* clang-format on */
	if (rc) {
		zlog_err("%s: error: %s returned %d: %s", __func__,
			 "gnutls_privkey_export_rsa_raw", rc,
			 gnutls_strerror(rc));
		return KC_ERR_ENCRYPT;
	}

	gnutls_pubkey_init(&pPubKey);

	rc = gnutls_pubkey_import_rsa_raw(pPubKey, d + GT_DATUM_M,
					  d + GT_DATUM_E);

	/*
	 * gnutls documentation is not clear on need to keep data components
	 * allocated during lifetime of public key
	 */
	for (i = GT_DATUM_M; i < N_GT_DATA; ++i) {
		if (d[i].data)
			gnutls_free(d[i].data);
	}

	if (rc) {
		zlog_err("%s: error: %s returned %d: %s", __func__,
			 "gnutls_pubkey_import_rsa_raw", rc,
			 gnutls_strerror(rc));
		gnutls_pubkey_deinit(pPubKey);
		return KC_ERR_ENCRYPT;
	}

	gnutls_datum_t datum_plaintext;
	gnutls_datum_t datum_ciphertext;

	datum_plaintext.data = (unsigned char *)pPlainText;
	datum_plaintext.size = PlainTextLen;

	rc = gnutls_pubkey_encrypt_data(pPubKey, 0, &datum_plaintext,
					&datum_ciphertext);
	gnutls_pubkey_deinit(pPubKey);
	if (rc) {
		zlog_err("%s: error: %s returned %d: %s", __func__,
			 "gnutls_pubkey_encrypt_data", rc, gnutls_strerror(rc));
		return KC_ERR_ENCRYPT;
	}
	*pCipherTextLen = datum_ciphertext.size;
	*ppCipherText = XMALLOC(mt, datum_ciphertext.size);
	memcpy(*ppCipherText, datum_ciphertext.data, datum_ciphertext.size);

	gnutls_free(datum_ciphertext.data);

	return 0;
}

/*
 * Decrypt provided cipher text.
 *
 * Returns dynamically-allocated plain text, which caller must
 * free via XFREE(KEYCRYPT_PLAIN_TEXT, pPlainText)
 *
 * Return value is 0 if successful, non-0 for error
 */
/* clang-format off */
static int keycrypt_decrypt_internal_gnutls(
	gnutls_x509_privkey_t	pX509PrivKey,			/* IN */
	struct memtype		*mt,	/* of PlainText */	/* IN */
	const char		*pCipherText,			/* IN */
	size_t			CipherTextLen,			/* IN */
	char			**ppPlainText,			/* OUT */
	size_t			*pPlainTextLen)			/* OUT */

{
	gnutls_datum_t		datum_ciphertext;
	gnutls_datum_t		datum_plaintext;
	gnutls_privkey_t	pPrivKey;
	int		rc;
	/* clang-format on */

	/*
	 * make a generic private key
	 */
	rc = gnutls_privkey_init(&pPrivKey);
	if (rc) {
		zlog_err("%s: error: %s returned %d: %s", __func__,
			 "gnutls_privkey_init", rc, gnutls_strerror(rc));
		return KC_ERR_DECRYPT;
	}
	rc = gnutls_privkey_import_x509(pPrivKey, pX509PrivKey, 0);
	if (rc) {
		zlog_err("%s: error: %s returned %d: %s", __func__,
			 "gnutls_privkey_import_x509", rc, gnutls_strerror(rc));
		return KC_ERR_DECRYPT;
	}

	datum_ciphertext.data = (unsigned char *)pCipherText;
	datum_ciphertext.size = CipherTextLen;

	rc = gnutls_privkey_decrypt_data(pPrivKey, 0, &datum_ciphertext,
					 &datum_plaintext);
	gnutls_privkey_deinit(pPrivKey);
	if (rc) {
		zlog_err("%s: error: %s returned %d: %s", __func__,
			 "gnutls_privkey_decrypt_data", rc,
			 gnutls_strerror(rc));
		zlog_debug(
			"%s: datum_ciphertext.data %p, datum_ciphertext.size %u",
			__func__, datum_ciphertext.data, datum_ciphertext.size);
		return KC_ERR_DECRYPT;
	}
	*pPlainTextLen = datum_plaintext.size;
	*ppPlainText = XMALLOC(mt, datum_plaintext.size + 1);
	memcpy(*ppPlainText, datum_plaintext.data, datum_plaintext.size);
	(*ppPlainText)[*pPlainTextLen] = '\0';

	gnutls_free(datum_plaintext.data);

	return 0;
}


/*
 * Caller must free result XFREE(MTYPE_KEYCRYPT_CIPHER_B64, *pOut)
 */
/* clang-format off */
static enum keycrypt_err keycrypt_base64_encode_gnutls(
	const char	*pIn,
	size_t		InLen,
	char		**ppOut,
	size_t		*pOutLen)
{
	gnutls_datum_t	d_raw;
	gnutls_datum_t	d_b64;
	int		rc;
	/* clang-format on */

	d_raw.data = (unsigned char *)pIn;
	d_raw.size = InLen;

	rc = gnutls_base64_encode2(&d_raw, &d_b64);
	if (rc) {
		zlog_err("%s: error: %s returned %d: %s", __func__,
			 "gnutls_base64_encode2", rc, gnutls_strerror(rc));
		return KC_ERR_BASE64;
	}

	*ppOut = XMALLOC(MTYPE_KEYCRYPT_CIPHER_B64, d_b64.size + 1);
	memcpy(*ppOut, d_b64.data, d_b64.size);
	*(*ppOut + d_b64.size) = '\0';
	*pOutLen = d_b64.size;
	gnutls_free(d_b64.data);
	return 0;
}

/*
 * Caller must free result XFREE(MTYPE_KEYCRYPT_B64DEC, *pOut)
 */
/* clang-format off */
static enum keycrypt_err keycrypt_base64_decode_gnutls(
	const char	*pIn,
	size_t		InLen,
	char		**ppOut,
	size_t		*pOutLen)
{
	gnutls_datum_t	d_raw;
	gnutls_datum_t	d_b64;
	int		rc;
	/* clang-format on */

	d_b64.data = (unsigned char *)pIn;
	d_b64.size = InLen;

	rc = gnutls_base64_decode2(&d_b64, &d_raw);
	if (rc) {
		zlog_err("%s: error: %s returned %d: %s", __func__,
			 "gnutls_base64_decode2", rc, gnutls_strerror(rc));
		zlog_err("%s: d_b64.data %p, d_b64.size %u", __func__,
			 d_b64.data, d_b64.size);
		return KC_ERR_BASE64;
	}

	*ppOut = XMALLOC(MTYPE_KEYCRYPT_B64DEC, d_raw.size + 1);
	memcpy(*ppOut, d_raw.data, d_raw.size);
	*(*ppOut + d_raw.size) = '\0';
	*pOutLen = d_raw.size;
	gnutls_free(d_raw.data);
	return 0;
}

/*
 * After successful return (0), caller MUST free base-64 encoded
 * cipher text via XFREE(MTYPE_KEYCRYPT_CIPHER_B64, ptr)
 */
/* clang-format off */
static int keycrypt_encrypt_gnutls(
	const char	*pPlainText,		/* IN */
	size_t		PlainTextLen,		/* IN */
	char		**ppCipherTextB64,	/* OUT */
	size_t		*pCipherTextB64Len)	/* OUT */

{
	gnutls_x509_privkey_t	pKey;
	int			rc;
	enum keycrypt_err	krc;
	char			*pCipherTextRaw;
	size_t			CipherTextRawLen = 0;
	size_t			B64len = 0;
	/* clang-format on */

	pKey = keycrypt_get_pkey_gnutls();
	if (!pKey)
		return -1;

	rc = keycrypt_encrypt_internal_gnutls(
		pKey, MTYPE_KEYCRYPT_CIPHER_TEXT, pPlainText, PlainTextLen,
		&pCipherTextRaw, &CipherTextRawLen);
	if (rc)
		return -1;

	krc = keycrypt_base64_encode_gnutls(pCipherTextRaw, CipherTextRawLen,
					    ppCipherTextB64, &B64len);

	if (krc) {
		zlog_err("%s: %s returned %d: %s", __func__,
			 "keycrypt_base64_encode_gnutls", krc,
			 keycrypt_strerror(krc));
		XFREE(MTYPE_KEYCRYPT_CIPHER_TEXT, pCipherTextRaw);
		return krc;
	}

	if (pCipherTextB64Len)
		*pCipherTextB64Len = B64len;

	XFREE(MTYPE_KEYCRYPT_CIPHER_TEXT, pCipherTextRaw);

	return 0;
}

/* clang-format off */
static int keycrypt_decrypt_gnutls(
	struct memtype	*mt,	/* of PlainText */	/* IN */
	const char	*pCipherTextB64,		/* IN */
	size_t		CipherTextB64Len,		/* IN */
	char		**ppPlainText,			/* OUT */
	size_t		*pPlainTextLen)			/* OUT */

{
	gnutls_x509_privkey_t	pKey;
	int			rc;
	char			*pCipherTextRaw;
	size_t			CipherTextRawLen = 0;
	size_t			PlainTextLen = 0;
	/* clang-format on */

	pKey = keycrypt_get_pkey_gnutls();
	if (!pKey)
		return -1;

	keycrypt_base64_decode_gnutls(pCipherTextB64, CipherTextB64Len,
				      &pCipherTextRaw, &CipherTextRawLen);

	rc = keycrypt_decrypt_internal_gnutls(pKey, mt, pCipherTextRaw,
					      CipherTextRawLen, ppPlainText,
					      &PlainTextLen);

	XFREE(MTYPE_KEYCRYPT_B64DEC, pCipherTextRaw);

	if (rc)
		return -1;

	if (pPlainTextLen)
		*pPlainTextLen = PlainTextLen;

	return 0;
}

/* clang-format off */
static int debug_keycrypt_test_cmd_gnutls(
	struct vty	*vty,
	const char	*cleartext)
{
	char			*keyfile_path = NULL;
	gnutls_x509_privkey_t	pPrivKey;

	int			rc;
	enum keycrypt_err	krc;
	char			*pCipherText = NULL;
	size_t			CipherTextLen;
	char			*pClearText = NULL;
	size_t			ClearTextLen;
	char			*pB64Text;
	size_t			B64TextLen = 0;
	/* clang-format on */

	keyfile_path = keycrypt_keyfile_path();
	if (!keyfile_path) {
		vty_out(vty, "%s: Error: can't compute keyfile path\n",
			__func__);
		return CMD_SUCCESS;
	}

	zlog_debug("%s: Computed keyfile_path: %s", __func__, keyfile_path);

	krc = keycrypt_read_keyfile_gnutls(keyfile_path, &pPrivKey);
	if (krc) {
		vty_out(vty, "%s: Error: %s returned %d: %s\n", __func__,
			"keycrypt_read_keyfile_gnutls", krc,
			keycrypt_strerror(krc));
		XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);
		return CMD_SUCCESS;
	}

	zlog_debug("%s: Read keyfile", __func__);

	krc = keycrypt_encrypt_internal_gnutls(
		pPrivKey, MTYPE_KEYCRYPT_CIPHER_TEXT, cleartext,
		strlen(cleartext), &pCipherText, &CipherTextLen);
	if (krc) {
		vty_out(vty, "%s: Error: %s returned %d: %s\n", __func__,
			"keycrypt_encrypt_internal_gnutls", krc,
			keycrypt_strerror(krc));
		return CMD_SUCCESS;
	}

	zlog_debug("%s: encrypted successfully", __func__);

	if (!pCipherText) {
		vty_out(vty, "%s: missing cipher text\n", __func__);
		return CMD_SUCCESS;
	}

	/*
	 * Encode for printing
	 */

	krc = keycrypt_base64_encode_gnutls(pCipherText, CipherTextLen,
					    &pB64Text, &B64TextLen);

	XFREE(MTYPE_KEYCRYPT_CIPHER_TEXT, pCipherText);

	if (krc) {
		vty_out(vty, "%s: Error: %s returned %d: %s\n", __func__,
			"keycrypt_base64_encode_gnutls", krc,
			keycrypt_strerror(krc));
		/* TBD does anything else need to be freed here? */
		return CMD_SUCCESS;
	}

	zlog_debug("%s: base64-encoded successfully", __func__);

	vty_out(vty,
		"INFO: clear text len: %zu, CipherTextLen: %zu, B64TextLen %zu\n",
		strlen(cleartext), CipherTextLen, B64TextLen);

	vty_out(vty, "INFO: base64 cipher text:\n%s\n", pB64Text);


	/*
	 * Decode back to binary
	 */
	keycrypt_base64_decode_gnutls(pB64Text, B64TextLen, &pCipherText,
				      &CipherTextLen);

	vty_out(vty, "INFO: After B64 decode, CipherTextLen: %zu\n",
		CipherTextLen);


	rc = keycrypt_decrypt_internal_gnutls(
		pPrivKey, MTYPE_KEYCRYPT_PLAIN_TEXT, pCipherText, CipherTextLen,
		&pClearText, &ClearTextLen);

	XFREE(MTYPE_KEYCRYPT_CIPHER_B64, pB64Text);

	if (pCipherText) {
		if (!strncmp(cleartext, pCipherText, strlen(cleartext))) {
			vty_out(vty,
				"%s: cipher text and cleartext same for %zu chars\n",
				__func__, strlen(cleartext));
			XFREE(MTYPE_KEYCRYPT_B64DEC, pCipherText);
			if (pClearText)
				XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
			return CMD_SUCCESS;
		}
		XFREE(MTYPE_KEYCRYPT_B64DEC, pCipherText);
	}

	if (rc) {
		vty_out(vty, "%s: Error: keycrypt_decrypt_internal_gnutls\n",
			__func__);
		if (pClearText)
			XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
		return CMD_SUCCESS;
	}

	if (!pClearText) {
		vty_out(vty,
			"%s: keycrypt_decrypt_internal_gnutls didn't return clear text pointer\n",
			__func__);
		return CMD_SUCCESS;
	}
	if (strlen(cleartext) != ClearTextLen) {
		vty_out(vty,
			"%s: decrypted ciphertext length (%zu) != original length (%lu)\n",
			__func__, ClearTextLen, strlen(cleartext));
		XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
		return CMD_SUCCESS;
	}

	if (strncmp(cleartext, pClearText, ClearTextLen)) {
		vty_out(vty,
			"%s: decrypted ciphertext differs from original text\n",
			__func__);
		XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
		return CMD_SUCCESS;
	}

	vty_out(vty, "OK: decrypted ciphertext matches original text\n");
	return CMD_SUCCESS;
}

static enum keycrypt_err keyfile_read_status_gnutls(const char *keyfile_path,
						 const char **detail)
{
	enum keycrypt_err krc;
	gnutls_x509_privkey_t pPrivKey;

	*detail = NULL;

	krc = keycrypt_read_keyfile_gnutls(keyfile_path, &pPrivKey);
	if (krc)
		*detail = keycrypt_strerror(krc);
	else
		gnutls_x509_privkey_deinit(pPrivKey);

	return krc;
}

static const char *keycrypt_backend_version_string_gnutls(void)
{
	return gnutls_check_version(NULL);
}

/* clang-format off */
struct keycrypt_backend kbe_gnutls_pkcs1 = {
	.name			= "gnutls-pkcs1-padding",
	.f_encrypt		= keycrypt_encrypt_gnutls,
	.f_decrypt		= keycrypt_decrypt_gnutls,
	.f_test_cmd		= debug_keycrypt_test_cmd_gnutls,
	.f_keyfile_read_status	= keyfile_read_status_gnutls,
	.f_be_version_string	= keycrypt_backend_version_string_gnutls,
};
/* clang-format on */

#endif /* KEYCRYPT_HAVE_GNUTLS */

/***********************************************************************
 *		libgcrypt-specific functions
 ***********************************************************************/

#if defined KEYCRYPT_HAVE_GCRYPT

/*
 * Based on libgcrypt-1.5.8 tests/fipsdrv.c read_private_key_file()
 */

/* clang-format off */
static unsigned char const asctobin[128] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
	0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
	0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
	0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
	0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff
};

static const unsigned char bintoasc[64+1] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* clang-format on */

/* clang-format off */
static enum keycrypt_err keycrypt_base64_decode_gcrypt(
	const char	*pB64,
	size_t		B64Length,
	char		**ppData,
	size_t		*pDataLength)
	/* clang-format on */
{
	struct sbuf data;
	size_t length;
	const char *s;
	uint8_t val = 0;
	uint idx = 0;
	int c = 0;

	sbuf_init(&data, NULL, 0); /* MTYPE_TMP */

	for (s = pB64, length = B64Length; length; length--, s++) {
		if (isspace(*s))
			continue;
		if (*s == '=') {
			/* Pad character: stop */
			if (idx == 1)
				sbuf_push(&data, 0, "%c", val);
			break;
		}
		/* start: change to resolve checkpatch style error */
		if (*s & 0x80) {
			sbuf_free(&data);
			return KC_ERR_BASE64;
		}
		c = asctobin[*(unsigned char *)s];
		if (c == 0xff) {
			sbuf_free(&data);
			return KC_ERR_BASE64;
		}
		/* end: change to resolve checkpatch style error */

		switch (idx) {
		case 0:
			val = c << 2;
			break;
		case 1:
			val |= (c >> 4) & 3;
			sbuf_push(&data, 0, "%c", val);
			val = (c << 4) & 0xf0;
			break;
		case 2:
			val |= (c >> 2) & 15;
			sbuf_push(&data, 0, "%c", val);
			val = (c << 6) & 0xc0;
			break;
		case 3:
			val |= c & 0x3f;
			sbuf_push(&data, 0, "%c", val);
			break;
		}
		idx = (idx + 1) % 4;
	}

	*ppData = XMALLOC(MTYPE_KEYCRYPT_B64DEC, data.pos + 1);
	memcpy(*ppData, sbuf_buf(&data), data.pos);
	*(*ppData + data.pos) = '\0';
	*pDataLength = data.pos;
	sbuf_free(&data);
	return KC_OK;
}

/* clang-format off */
static enum keycrypt_err keycrypt_base64_encode_gcrypt(
	const char	*pIn,
	size_t		InLen,
	char		**ppOut,
	size_t		*pOutLen)
{
	struct sbuf	data;
	const uint8_t	*p;
	uint8_t		inbuf[4];
	char		outbuf[4];
	int		idx;
	int		quads;
	size_t		length;
	/* clang-format on */

	sbuf_init(&data, NULL, 0); /* MTYPE_TMP */

	idx = quads = 0;
	length = InLen;
	for (p = (const uint8_t *)pIn; length; p++, length--) {
		inbuf[idx++] = *p;
		if (idx > 2) {
			/* clang-format off */
			outbuf[0] = bintoasc[(*inbuf>>2)&077];
			outbuf[1] = bintoasc[(((*inbuf<<4)&060)
						|((inbuf[1] >> 4)&017))&077];
			outbuf[2] = bintoasc[(((inbuf[1]<<2)&074)
						|((inbuf[2]>>6)&03))&077];
			outbuf[3] = bintoasc[inbuf[2]&077];
			/* clang-format on */
			sbuf_push(&data, 0, "%c%c%c%c", outbuf[0], outbuf[1],
				  outbuf[2], outbuf[3]);
			idx = 0;
			if (++quads >= (64 / 4)) {
#ifdef KC_GCRYPT_B64_USE_NEWLINES /* openssl b64 decode doesn't like */
				sbuf_push(&data, 0, "\n");
#endif
				quads = 0;
			}
		}
	}
	if (idx) {
		/* clang-format off */
		outbuf[0] = bintoasc[(*inbuf>>2)&077];
		if (idx == 1) {
			outbuf[1] = bintoasc[((*inbuf<<4)&060)&077];
			outbuf[2] = outbuf[3] = '=';
		} else {
			outbuf[1] = bintoasc[(((*inbuf<<4)&060)
						|((inbuf[1]>>4)&017))&077];
			outbuf[2] = bintoasc[((inbuf[1]<<2)&074)&077];
			outbuf[3] = '=';
		}
		/* clang-format on */
		sbuf_push(&data, 0, "%c%c%c%c", outbuf[0], outbuf[1], outbuf[2],
			  outbuf[3]);
		quads++;
	}
#ifdef KC_GCRYPT_B64_USE_NEWLINES
	if (quads)
		sbuf_push(&data, 0, "\n");
#endif

	*ppOut = XMALLOC(MTYPE_KEYCRYPT_CIPHER_B64, data.pos + 1);
	memcpy(*ppOut, sbuf_buf(&data), data.pos);
	*(*ppOut + data.pos) = '\0';
	*pOutLen = data.pos;
	sbuf_free(&data);
	return KC_OK;
}

/* clang-format off */
enum keyfile_type {
	KEYFILE_TYPE_UNKNOWN = 0,
	KEYFILE_TYPE_PKCS1,
	KEYFILE_TYPE_PKCS8,
};

/* ASN.1 classes.  */
enum {
	UNIVERSAL = 0,
	APPLICATION = 1,
	ASNCONTEXT = 2,
	PRIVATE = 3
};

/* ASN.1 tags.  */
enum {
	TAG_NONE = 0,
	TAG_BOOLEAN = 1,
	TAG_INTEGER = 2,
	TAG_BIT_STRING = 3,
	TAG_OCTET_STRING = 4,
	TAG_NULL = 5,
	TAG_OBJECT_ID = 6,
	TAG_OBJECT_DESCRIPTOR = 7,
	TAG_EXTERNAL = 8,
	TAG_REAL = 9,
	TAG_ENUMERATED = 10,
	TAG_EMBEDDED_PDV = 11,
	TAG_UTF8_STRING = 12,
	TAG_REALTIVE_OID = 13,
	TAG_SEQUENCE = 16,
	TAG_SET = 17,
	TAG_NUMERIC_STRING = 18,
	TAG_PRINTABLE_STRING = 19,
	TAG_TELETEX_STRING = 20,
	TAG_VIDEOTEX_STRING = 21,
	TAG_IA5_STRING = 22,
	TAG_UTC_TIME = 23,
	TAG_GENERALIZED_TIME = 24,
	TAG_GRAPHIC_STRING = 25,
	TAG_VISIBLE_STRING = 26,
	TAG_GENERAL_STRING = 27,
	TAG_UNIVERSAL_STRING = 28,
	TAG_CHARACTER_STRING = 29,
	TAG_BMP_STRING = 30
};

/* ASN.1 Parser object.  */
struct tag_info {
	int class;             /* Object class.  */
	unsigned long tag;     /* The tag of the object.  */
	unsigned long length;  /* Length of the values.  */
	int nhdr;              /* Length of the header (TL).  */
	unsigned int ndef:1;   /* The object has an indefinite length.  */
	unsigned int cons:1;   /* This is a constructed object.  */
};
/* clang-format on */

/* clang-format off */
static int keycrypt_parse_tag_gcrypt(
	const char		**buffer,
	size_t			*buflen,
	struct tag_info		*ti)
/* clang-format on */
{
	int c;
	unsigned long tag;
	const unsigned char *buf = *(const unsigned char **)buffer;
	size_t length = *buflen;

	ti->length = 0;
	ti->ndef = 0;
	ti->nhdr = 0;

	/* Get the tag */
	if (!length)
		return -1; /* Premature EOF.  */
	c = *buf++;
	length--;
	ti->nhdr++;

	ti->class = (c & 0xc0) >> 6;
	ti->cons = !!(c & 0x20);
	tag = (c & 0x1f);

	if (tag == 0x1f) {
		tag = 0;
		do {
			tag <<= 7;
			if (!length)
				return -1; /* Premature EOF.  */
			c = *buf++;
			length--;
			ti->nhdr++;
			tag |= (c & 0x7f);
		} while ((c & 0x80));
	}
	ti->tag = tag;

	/* Get the length */
	if (!length)
		return -1; /* Premature EOF. */
	c = *buf++;
	length--;
	ti->nhdr++;

	if (!(c & 0x80))
		ti->length = c;
	else if (c == 0x80)
		ti->ndef = 1;
	else if (c == 0xff)
		return -1; /* Forbidden length value.  */
	else {
		unsigned long len = 0;
		int count = c & 0x7f;

		for (; count; count--) {
			len <<= 8;
			if (!length)
				return -1; /* Premature EOF.  */
			c = *buf++;
			length--;
			ti->nhdr++;
			len |= (c & 0xff);
		}
		ti->length = len;
	}

	if (ti->class == UNIVERSAL && !ti->tag)
		ti->length = 0;

	if (ti->length > length)
		return -1; /* Data larger than buffer.  */

	*buffer = (const char *)buf;
	*buflen = length;
	return 0;
}

/*
 * Caller must free returned MTYPE_TMP buffer
 */
/* clang-format off */
static enum keycrypt_err keycrypt_unwrap_privkey_file(
	const char		*filename,
	char			**ppBuf,
	size_t			*pLength,
	enum keyfile_type	*pKeyfileType)
/* clang-format on */
{
	FILE *fp;
	char buf[BUFSIZ];
	bool seenbegin = false;
	struct sbuf data;

	*pKeyfileType = KEYFILE_TYPE_UNKNOWN;

	fp = fopen(filename, "rb");
	if (!fp) {
		zlog_err("%s: fopen(\"%s\"): %m", __func__, filename);
		return KC_ERR_KEYFILE_READ;
	}
	sbuf_init(&data, NULL, 0); /* MTYPE_TMP */
	while (fgets(buf, BUFSIZ, fp)) {
		if (!strncmp(buf, "-----END ", 9))
			break;
		if (seenbegin)
			sbuf_push(&data, 0, "%s", buf);
		if (!strncmp(buf, "-----BEGIN ", 11)) {
			char *p;

			seenbegin = true;

			/*
			 * BEGIN RSA PRIVATE KEY: PKCS1: (rsa) key only
			 * BEGIN PRIVATE KEY: PKCS8: ver, algo, key
			 */
			p = buf + 11;
			if (!strncmp(p, "RSA PRIVATE KEY-----", 20))
				*pKeyfileType = KEYFILE_TYPE_PKCS1;
			else if (!strncmp(p, "PRIVATE KEY-----", 16))
				*pKeyfileType = KEYFILE_TYPE_PKCS8;
			continue;
		}
	}
	fclose(fp);

	*ppBuf = XCALLOC(MTYPE_KEYCRYPT_CIPHER_B64, data.pos + 1);
	memcpy(*ppBuf, sbuf_buf(&data), data.pos);
	*(*ppBuf + data.pos) = '\0';
	*pLength = data.pos;
	sbuf_free(&data);

	return KC_OK;
}

/* clang-format off */
static enum keycrypt_err kc_parse_pkcs1(
	const char		*pAsn1,
	size_t			Asn1Length,
	gcry_sexp_t		*ppPrivKey,	/* caller must free */
	gcry_sexp_t		*ppPubKey)	/* caller must free */

{
	const char		*der;
	size_t			derlen;
	struct tag_info		ti;
	gcry_mpi_t		keyparms[8];
	int			n_keyparms = 8;
	gcry_sexp_t		s_key_private;
	gcry_sexp_t		s_key_public;
	uint8_t			idx;
	gcry_error_t		err;
	int			rc;
	/* clang-format on */

	/* Parse the ASN.1 structure. */
	der = (const char *)pAsn1;
	derlen = Asn1Length;

	if (keycrypt_parse_tag_gcrypt(&der, &derlen, &ti)
	    || ti.tag != TAG_SEQUENCE || ti.class || !ti.cons || ti.ndef) {
		zlog_debug("%s: %s 1 error", __func__,
			   "keycrypt_parse_tag_gcrypt");
		goto bad_asn1;
	}
	zlog_debug("%s: tag %lu, length %lu", __func__, ti.tag, ti.length);
	if (keycrypt_parse_tag_gcrypt(&der, &derlen, &ti)
	    || ti.tag != TAG_INTEGER || ti.class || ti.cons || ti.ndef) {
		zlog_debug("%s: %s 2 error", __func__,
			   "keycrypt_parse_tag_gcrypt");
		goto bad_asn1;
	}
	zlog_debug("%s: tag %lu, length %lu", __func__, ti.tag, ti.length);
	if (ti.length != 1 || *der) {
		zlog_debug("%s: value of the first integer is not 0", __func__);
		goto bad_asn1; /* The value of the first integer is not 0. */
	}
	der += ti.length;
	derlen -= ti.length;

	for (idx = 0; idx < n_keyparms; idx++) {
		rc = keycrypt_parse_tag_gcrypt(&der, &derlen, &ti);
		if (rc || ti.tag != TAG_INTEGER || ti.class || ti.cons
		    || ti.ndef) {
			zlog_debug("%s: idx %u error, rc %d", __func__, idx,
				   rc);
			if (!rc) {
				zlog_debug(
					"  tag %lu, class %d, cons %d, ndef %d",
					ti.tag, ti.class, ti.cons, ti.ndef);
			}
			goto bad_asn1;
		}
		err = gcry_mpi_scan(keyparms + idx, GCRYMPI_FMT_USG, der,
				    ti.length, NULL);
		if (err) {
			zlog_err("%s: error scanning RSA parameter %d: %s\n",
				 __func__, idx, gpg_strerror(err));
			goto error;
		}
		der += ti.length;
		derlen -= ti.length;
	}
	if (idx != n_keyparms) {
		zlog_err("%s: not enough RSA key parameters", __func__);
		goto error;
	}

	/*
	 * Convert from OpenSSL parameter ordering to the OpenPGP order.
	 * First check that p < q; if not swap p and q and recompute u.
	 */
	if (gcry_mpi_cmp(keyparms[3], keyparms[4]) > 0) {
		zlog_debug("%s: p<q swapping", __func__);
		gcry_mpi_swap(keyparms[3], keyparms[4]);
		gcry_mpi_invm(keyparms[7], keyparms[3], keyparms[4]);
	} else {
		/*
		 * Sigh. It seems we must recompute u when we don't swap
		 */
		gcry_mpi_invm(keyparms[7], keyparms[3], keyparms[4]);
	}
#ifdef KEYCRYPT_LOG_PRIVATE_KEYS /* don't enable in production code */
	gcry_mpi_t u_copy = NULL;

	for (idx = 0; idx < n_keyparms; idx++) {
		char pfx;
		unsigned char *pbuf;

		pfx = idx < 8 ? "nedpq12u"[idx] : '?';
		err = gcry_mpi_aprint(GCRYMPI_FMT_HEX, &pbuf, NULL,
				      keyparms[idx]);
		if (err) {
			zlog_err("%s: idx %u, gcry_mpi_aprint: %s", __func__,
				 idx, gpg_strerror(err));
			continue;
		}
		zlog_debug("%s: %c: %s", __func__, pfx, pbuf);
		gcry_free(pbuf);
	}
#endif

	/* Build private key S-expression. */
	/* clang-format off */
	err = gcry_sexp_build(&s_key_private, NULL,
	    "(private-key(rsa(n%m)(e%m)"
	    /**/            "(d%m)(p%m)(q%m)(u%m)))",
	    keyparms[0], keyparms[1], keyparms[2],
	    keyparms[3], keyparms[4], keyparms[7]);
	/* clang-format on */

	if (err) {
		for (idx = 0; idx < n_keyparms; idx++)
			gcry_mpi_release(keyparms[idx]);
		zlog_err("%s: error building private-key S-expression: %s",
			 __func__, gpg_strerror(err));
		return KC_ERR_KEYFILE_PARSE;
	}

	/* Build public key S-expression */
	/* clang-format off */
	err = gcry_sexp_build(&s_key_public, NULL,
	    "(public-key(rsa(n%m)(e%m)))",
	    keyparms[0], keyparms[1]);
	/* clang-format on */

	/* get this out of the way before possible error return */
	for (idx = 0; idx < n_keyparms; idx++)
		gcry_mpi_release(keyparms[idx]);

	if (err) {
		/* TBD free s_key_private */
		zlog_err("%s: error building private-key S-expression: %s",
			 __func__, gpg_strerror(err));
		return KC_ERR_KEYFILE_PARSE;
	}

	*ppPrivKey = s_key_private;
	*ppPubKey = s_key_public;

	return KC_OK;

bad_asn1:
	zlog_err("%s: invalid ASN.1 structure", __func__);
error:
	return KC_ERR_KEYFILE_PARSE;
}

/* currently only handles RSA keys */
/* clang-format off */
static enum keycrypt_err kc_parse_pkcs8(
	char			*pAsn1,
	size_t			Asn1Length,
	gcry_sexp_t		*ppPrivKey,	/* caller must free */
	gcry_sexp_t		*ppPubKey)	/* caller must free */

{
	const char		*der;
	size_t			derlen;
	struct tag_info		ti;
	/* clang-format on */

	/*
	 * % openssl asn1parse -in ~/.ssh/frr
	 *  0:d=0  hl=4 l=1214 cons: SEQUENCE
	 *  4:d=1  hl=2 l=   1 prim: INTEGER           :00
	 *  7:d=1  hl=2 l=  13 cons: SEQUENCE
	 *  9:d=2  hl=2 l=   9 prim: OBJECT            :rsaEncryption
	 * 20:d=2  hl=2 l=   0 prim: NULL
	 * 22:d=1  hl=4 l=1192 prim: OCTET STRING      [HEX DUMP]:[bytes...]
	 *
	 * The octet string is the private key, which should be asn1-parsed
	 */

	/*
	 * Get to the octet string
	 */

	/* first we should see an integer */

	der = (const char *)pAsn1;
	derlen = Asn1Length;

	/* This sequence should enclose everything */
	if (keycrypt_parse_tag_gcrypt(&der, &derlen, &ti)
	    || ti.tag != TAG_SEQUENCE || ti.class || !ti.cons || ti.ndef) {
		zlog_debug("%s: %s 1 error", __func__,
			   "keycrypt_parse_tag_gcrypt");
		return KC_ERR_KEYFILE_PARSE;
	}
	zlog_debug("%s: tag %lu, length %lu", __func__, ti.tag, ti.length);

	/* integer: version 0 */
	if (keycrypt_parse_tag_gcrypt(&der, &derlen, &ti)
	    || ti.tag != TAG_INTEGER || ti.class || ti.cons || ti.ndef) {
		zlog_debug("%s: %s 2 error", __func__,
			   "keycrypt_parse_tag_gcrypt");
		return KC_ERR_KEYFILE_PARSE;
	}
	zlog_debug("%s: tag %lu, length %lu", __func__, ti.tag, ti.length);
	if (ti.length != 1 || *der) {
		zlog_debug("%s: value of the first integer is not 0", __func__);
		return KC_ERR_KEYFILE_PARSE;
	}
	der += ti.length;
	derlen -= ti.length; /* go past value */

	/* This sequence should enclose the algorithm id and any params */
	if (keycrypt_parse_tag_gcrypt(&der, &derlen, &ti)
	    || ti.tag != TAG_SEQUENCE || ti.class || !ti.cons || ti.ndef) {
		zlog_debug("%s: %s 3 error", __func__,
			   "keycrypt_parse_tag_gcrypt");
		return KC_ERR_KEYFILE_PARSE;
	}
	zlog_debug("%s: tag %lu, length %lu", __func__, ti.tag, ti.length);

	/* clang-format off */
	{
		/* look at enclosed object ID to ensure it is "rsaEncryption" */
		const char	*der_inner = der;
		size_t		derlen_inner = ti.length;
		struct tag_info	ti_inner;
		bool		is_rsaEncryption = false;

		while (!keycrypt_parse_tag_gcrypt(&der_inner, &derlen_inner,
			&ti_inner)) {

			if (ti_inner.tag == TAG_OBJECT_ID &&
			    ti_inner.length == 9) {

				const char *p = der_inner;

				zlog_debug("%s: examining oid", __func__);
				zlog_debug("  %02x%02x%02x%02x %02x%02x%02x%02x %02x",
				    p[0], p[1], p[2], p[3],
				    p[4], p[5], p[6], p[7],
				    p[8]);
				/*
				 * 1.2.840.113549.1.1.1 is "rsaEncryption"
				 * which is encoded as
				 * 06 09 2A 86 48 86 F7 0D 01 01 01
				 * Type 0x06 = TAG_OBJECT_ID
				 * Len 0x09
				 *
				 */
				if (!memcmp(p,
				    "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01",
				    ti_inner.length))
					is_rsaEncryption = true;
			}
			der_inner += ti_inner.length;
			derlen_inner -= ti_inner.length;
		}

		if (!is_rsaEncryption) {
			zlog_err("%s: rsaEncryption objectID not found",
			    __func__);
			return KC_ERR_KEYFILE_PARSE;
		}
	}
	/* clang-format on */
	der += ti.length;
	derlen -= ti.length; /* skip oid sequence value */

	/* This sequence should enclose the algorithm id and any params */
	if (keycrypt_parse_tag_gcrypt(&der, &derlen, &ti)
	    || ti.tag != TAG_OCTET_STRING || ti.class || ti.cons || ti.ndef) {
		zlog_debug("%s: %s 4 error", __func__,
			   "keycrypt_parse_tag_gcrypt");
		return KC_ERR_KEYFILE_PARSE;
	}
	zlog_debug("%s: tag %lu, length %lu", __func__, ti.tag, ti.length);

	/*
	 * Now we're lined up at the octet stream
	 */
	return kc_parse_pkcs1(der, derlen, ppPrivKey, ppPubKey);
}

/* clang-format off */
static enum keycrypt_err keycrypt_read_keyfile_gcrypt(
	const char		*filename,
	gcry_sexp_t		*ppPrivKey,	/* caller must free */
	gcry_sexp_t		*ppPubKey)	/* caller must free */

{
	enum keycrypt_err	krc;
	char			*pB64 = NULL;
	size_t			B64Length;
	char			*pAsn1;
	size_t			Asn1Length;
	enum keyfile_type	KeyfileType;
	/* clang-format on */

	/* get buffer that is base64-encoded contents of PEM file */
	krc = keycrypt_unwrap_privkey_file(filename, &pB64, &B64Length,
					   &KeyfileType);
	if (krc)
		return krc;

	/* base64 decode key */
	krc = keycrypt_base64_decode_gcrypt(pB64, B64Length, &pAsn1,
					    &Asn1Length);
	XFREE(MTYPE_KEYCRYPT_CIPHER_B64, pB64);
	if (krc)
		return krc;

	zlog_debug("%s: B64Length %zu, Asn1Length %zu", __func__, B64Length,
		   Asn1Length);

	/*
	 * parse DER structure
	 */
	switch (KeyfileType) {
	case KEYFILE_TYPE_PKCS1:
		krc = kc_parse_pkcs1(pAsn1, Asn1Length, ppPrivKey, ppPubKey);
		break;
	case KEYFILE_TYPE_PKCS8:
		krc = kc_parse_pkcs8(pAsn1, Asn1Length, ppPrivKey, ppPubKey);
		break;
	case KEYFILE_TYPE_UNKNOWN:
		zlog_debug("%s: \"%s\": unknown private key format", __func__,
			   filename);
		break;
	}

	XFREE(MTYPE_KEYCRYPT_B64DEC, pAsn1);
	return krc;
}

/* clang-format off */
static enum keycrypt_err
keycrypt_read_default_keyfile_gcrypt(
	gcry_sexp_t	*ppPrivKey,
	gcry_sexp_t	*ppPubKey)
/* clang-format on */
{
	enum keycrypt_err rc;
	char *keyfile_path;

	*ppPrivKey = NULL;
	*ppPubKey = NULL;

	keyfile_path = keycrypt_keyfile_path();
	if (!keyfile_path) {
		zlog_err("%s: Error: can't compute keyfile path\n", __func__);
		return KC_ERR_KEYFILE_PATH;
	}

	rc = keycrypt_read_keyfile_gcrypt(keyfile_path, ppPrivKey, ppPubKey);
	if (rc) {
		zlog_err("%s: Error: %s can't read \"%s\"\n", __func__,
			 "keycrypt_read_keyfile_gcrypt", keyfile_path);
		XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);
		return rc;
	}

	XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);
	return KC_OK;
}

/*
 * Caller should not free returned keys
 */
/* clang-format off */
static void keycrypt_get_pkey_gcrypt(
	gcry_sexp_t	*ppPrivKey,
	gcry_sexp_t	*ppPubKey)
{
	static time_t		keycrypt_pkey_check_time;
	static gcry_sexp_t	pCachedPrivKey;
	static gcry_sexp_t	pCachedPubKey;
	time_t			now;
	bool			old = false;
	/* clang-format on */

	now = monotime(NULL);
	if (now - keycrypt_pkey_check_time > KEYCRYPT_CHECK_PKEY_SECONDS)
		old = true;

	if (!pCachedPrivKey || !pCachedPubKey || old) {
		enum keycrypt_err rc;
		gcry_sexp_t pPrivKey;
		gcry_sexp_t pPubKey;

		keycrypt_pkey_check_time = now;

		rc = keycrypt_read_default_keyfile_gcrypt(&pPrivKey, &pPubKey);
		if (rc != KC_OK)
			goto end;

		if (pCachedPrivKey)
			gcry_sexp_release(pCachedPrivKey);
		if (pCachedPubKey)
			gcry_sexp_release(pCachedPubKey);

		pCachedPrivKey = pPrivKey;
		pCachedPubKey = pPubKey;
	}
end:
	*ppPrivKey = pCachedPrivKey;
	*ppPubKey = pCachedPubKey;
}

/* clang-format off */
static int keycrypt_encrypt_internal_gcrypt_padding(
	bool			use_pkcs1_padding,		/* 0: oaep */
	gcry_sexp_t		pPubKey,			/* IN */
	struct memtype		*mt,	/* of CipherText */	/* IN */
	const char		*pPlainText,			/* IN */
	size_t			PlainTextLen,			/* IN */
	char			**ppCipherText,			/* OUT */
	size_t			*pCipherTextLen)		/* OUT */

{
	gcry_error_t		grc;
	gcry_sexp_t		s_ciphertext;
	gcry_sexp_t		s_plaintext;
	gcry_buffer_t		b_ciphertext;
	/* clang-format on */

	grc = gcry_sexp_build(&s_plaintext, NULL, "(data(flags %s)(value %b))",
			      (use_pkcs1_padding ? "pkcs1" : "oaep"),
			      PlainTextLen, pPlainText);
	if (grc) {
		zlog_err("%s: Error: gcry_sexp_build(s_plaintext): %s",
			 __func__, gpg_strerror(grc));
		return KC_ERR_DECRYPT;
	}
	grc = gcry_pk_encrypt(&s_ciphertext, s_plaintext, pPubKey);
	gcry_sexp_release(s_plaintext);
	if (grc) {
		zlog_err("%s: Error: gcry_pk_encrypt(s_ciphertext): %s",
			 __func__, gpg_strerror(grc));
		return KC_ERR_DECRYPT;
	}

	/*
	 * extract plaintext from s-expression
	 */
	memset(&b_ciphertext, 0, sizeof(b_ciphertext));
	grc = gcry_sexp_extract_param(s_ciphertext, NULL, "&'a'", &b_ciphertext,
				      NULL);
	gcry_sexp_release(s_ciphertext);
	if (grc) {
		zlog_err("%s: Error: %s: %s", __func__,
			 "gcry_sexp_extract_param", gpg_strerror(grc));
		return -1;
	}

	/*
	 * Copy ciphertext to FRR buffer
	 */
	*ppCipherText = XCALLOC(mt, b_ciphertext.len + 1);
	*pCipherTextLen = b_ciphertext.len;
	memcpy(*ppCipherText, ((char *)b_ciphertext.data) + b_ciphertext.off,
	       b_ciphertext.len);
	*(*ppCipherText + b_ciphertext.len) = 0;
	if (b_ciphertext.data)
		gcry_free(b_ciphertext.data);

	return KC_OK;
}

/* clang-format off */
static int keycrypt_decrypt_internal_gcrypt_padding(
	bool			use_pkcs1_padding,		/* 0: oaep */
	gcry_sexp_t		pPrivKey,			/* IN */
	struct memtype		*mt,	/* of PlainText */	/* IN */
	const char		*pCipherText,			/* IN */
	size_t			CipherTextLen,			/* IN */
	char			**ppPlainText,			/* OUT */
	size_t			*pPlainTextLen)			/* OUT */

{
	gcry_error_t		grc;
	gcry_sexp_t		s_ciphertext;
	gcry_sexp_t		s_plaintext;
	gcry_buffer_t		b_plaintext;
	/* clang-format on */

	grc = gcry_sexp_build(&s_ciphertext, NULL,
			      "(enc-val(flags %s)(rsa(a%b)))",
			      (use_pkcs1_padding ? "pkcs1" : "oaep"),
			      CipherTextLen, pCipherText);
	if (grc) {
		zlog_err("%s: Error: gcry_sexp_build(s_ciphertext): %s",
			 __func__, gpg_strerror(grc));
		return KC_ERR_DECRYPT;
	}

	grc = gcry_pk_decrypt(&s_plaintext, s_ciphertext, pPrivKey);
	gcry_sexp_release(s_ciphertext);
	if (grc) {
		zlog_err("%s: Error: gcry_pk_decrypt(s_ciphertext): %s",
			 __func__, gpg_strerror(grc));
		return KC_ERR_DECRYPT;
	}

	/*
	 * extract plaintext from s-expression
	 */
	memset(&b_plaintext, 0, sizeof(b_plaintext));
	grc = gcry_sexp_extract_param(s_plaintext, NULL, "&'value'",
				      &b_plaintext, NULL);
	gcry_sexp_release(s_plaintext);
	if (grc) {
		zlog_err("%s: Error: %s: %s", __func__,
			 "gcry_sexp_extract_param", gpg_strerror(grc));
		return -1;
	}

	/*
	 * Copy plaintext to FRR buffer
	 */
	*ppPlainText = XCALLOC(mt, b_plaintext.len + 1);
	*pPlainTextLen = b_plaintext.len;
	memcpy(*ppPlainText, ((char *)b_plaintext.data) + b_plaintext.off,
	       b_plaintext.len);
	*(*ppPlainText + b_plaintext.len) = 0;
	if (b_plaintext.data)
		gcry_free(b_plaintext.data);

	return KC_OK;
}

/*
 * After successful return (0), caller MUST free base-64 encoded
 * cipher text via XFREE(MTYPE_KEYCRYPT_CIPHER_B64, ptr)
 */
/* clang-format off */
static int keycrypt_encrypt_gcrypt_padding(
	bool		use_pkcs1_padding,	/* 0: oaep */
	const char	*pPlainText,		/* IN */
	size_t		PlainTextLen,		/* IN */
	char		**ppCipherTextB64,	/* OUT */
	size_t		*pCipherTextB64Len)	/* OUT */

{
	gcry_sexp_t		pPrivKey;
	gcry_sexp_t		pPubKey;
	int			rc;
	enum keycrypt_err	krc;
	char			*pCipherTextRaw;
	size_t			CipherTextRawLen = 0;
	size_t			B64len = 0;
	/* clang-format on */

	keycrypt_get_pkey_gcrypt(&pPrivKey, &pPubKey);
	if (!pPubKey)
		return -1;

	rc = keycrypt_encrypt_internal_gcrypt_padding(
		use_pkcs1_padding, pPubKey, MTYPE_KEYCRYPT_CIPHER_TEXT,
		pPlainText, PlainTextLen, &pCipherTextRaw, &CipherTextRawLen);
	if (rc)
		return -1;

	krc = keycrypt_base64_encode_gcrypt(pCipherTextRaw, CipherTextRawLen,
					    ppCipherTextB64, &B64len);

	if (krc) {
		zlog_err("%s: %s returned %d: %s", __func__,
			 "keycrypt_base64_encode_gnutls", krc,
			 keycrypt_strerror(krc));
		XFREE(MTYPE_KEYCRYPT_CIPHER_TEXT, pCipherTextRaw);
		return krc;
	}

	if (pCipherTextB64Len)
		*pCipherTextB64Len = B64len;

	XFREE(MTYPE_KEYCRYPT_CIPHER_TEXT, pCipherTextRaw);

	return 0;
}

/* clang-format off */
static int keycrypt_encrypt_gcrypt_pkcs1(
	const char	*pPlainText,		/* IN */
	size_t		PlainTextLen,		/* IN */
	char		**ppCipherTextB64,	/* OUT */
	size_t		*pCipherTextB64Len)	/* OUT */

/* clang-format on */
{
	return keycrypt_encrypt_gcrypt_padding(1, pPlainText, PlainTextLen,
					       ppCipherTextB64,
					       pCipherTextB64Len);
}

/* clang-format off */
static int keycrypt_encrypt_gcrypt_oaep(
	const char	*pPlainText,		/* IN */
	size_t		PlainTextLen,		/* IN */
	char		**ppCipherTextB64,	/* OUT */
	size_t		*pCipherTextB64Len)	/* OUT */

/* clang-format on */
{
	return keycrypt_encrypt_gcrypt_padding(0, pPlainText, PlainTextLen,
					       ppCipherTextB64,
					       pCipherTextB64Len);
}

/* clang-format off */
static int keycrypt_decrypt_gcrypt_padding(
	bool		use_pkcs1_padding,		/* 0: oaep */
	struct memtype	*mt,	/* of PlainText */	/* IN */
	const char	*pCipherTextB64,		/* IN */
	size_t		CipherTextB64Len,		/* IN */
	char		**ppPlainText,			/* OUT */
	size_t		*pPlainTextLen)			/* OUT */

{
	gcry_sexp_t		pPrivKey;
	gcry_sexp_t		pPubKey;
	int			rc;
	char			*pCipherTextRaw;
	size_t			CipherTextRawLen = 0;
	size_t			PlainTextLen = 0;
	enum keycrypt_err	krc;
	/* clang-format on */

	keycrypt_get_pkey_gcrypt(&pPrivKey, &pPubKey);
	if (!pPrivKey)
		return -1;

	krc = keycrypt_base64_decode_gcrypt(pCipherTextB64, CipherTextB64Len,
					    &pCipherTextRaw, &CipherTextRawLen);
	if (krc) {
		zlog_err("%s: Error: %s returned %d: %s", __func__,
			 "keycrypt_base64_decode_gcrypt", krc,
			 keycrypt_strerror(krc));
		return -1;
	}

	rc = keycrypt_decrypt_internal_gcrypt_padding(
		0, pPrivKey, mt, pCipherTextRaw, CipherTextRawLen, ppPlainText,
		&PlainTextLen);

	XFREE(MTYPE_KEYCRYPT_B64DEC, pCipherTextRaw);

	if (rc)
		return -1;

	if (pPlainTextLen)
		*pPlainTextLen = PlainTextLen;

	return 0;
}

/* clang-format off */
static int keycrypt_decrypt_gcrypt_pkcs1(
	struct memtype	*mt,	/* of PlainText */	/* IN */
	const char	*pCipherTextB64,		/* IN */
	size_t		CipherTextB64Len,		/* IN */
	char		**ppPlainText,			/* OUT */
	size_t		*pPlainTextLen)			/* OUT */

/* clang-format on */
{
	return keycrypt_decrypt_gcrypt_padding(1, mt, pCipherTextB64,
					       CipherTextB64Len, ppPlainText,
					       pPlainTextLen);
}

/* clang-format off */
static int keycrypt_decrypt_gcrypt_oaep(
	struct memtype	*mt,	/* of PlainText */	/* IN */
	const char	*pCipherTextB64,		/* IN */
	size_t		CipherTextB64Len,		/* IN */
	char		**ppPlainText,			/* OUT */
	size_t		*pPlainTextLen)			/* OUT */

/* clang-format on */
{
	return keycrypt_decrypt_gcrypt_padding(0, mt, pCipherTextB64,
					       CipherTextB64Len, ppPlainText,
					       pPlainTextLen);
}

/* clang-format off */
static int debug_keycrypt_test_cmd_gcrypt_padding(
	bool		use_pkcs1_padding,		/* 0: oaep */
	struct vty	*vty,
	const char	*cleartext)
{
	char			*keyfile_path = NULL;
	gcry_sexp_t		pPrivKey;
	gcry_sexp_t		pPubKey;

	int			rc;
	enum keycrypt_err	krc;
	char			*pCipherText = NULL;
	size_t			CipherTextLen;
	char			*pClearText = NULL;
	size_t			ClearTextLen;
	char			*pB64Text;
	size_t			B64TextLen = 0;
	/* clang-format on */

	keyfile_path = keycrypt_keyfile_path();
	if (!keyfile_path) {
		vty_out(vty, "%s: Error: can't compute keyfile path\n",
			__func__);
		return CMD_SUCCESS;
	}

	zlog_debug("%s: Computed keyfile_path: %s", __func__, keyfile_path);

	krc = keycrypt_read_keyfile_gcrypt(keyfile_path, &pPrivKey, &pPubKey);
	if (krc) {
		vty_out(vty, "%s: Error: %s returned %d: %s\n", __func__,
			"keycrypt_read_keyfile_gcrypt", krc,
			keycrypt_strerror(krc));
		XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);
		return CMD_SUCCESS;
	}

	zlog_debug("%s: Read keyfile", __func__);

	krc = keycrypt_encrypt_internal_gcrypt_padding(
		use_pkcs1_padding, pPrivKey, MTYPE_KEYCRYPT_CIPHER_TEXT,
		cleartext, strlen(cleartext), &pCipherText, &CipherTextLen);
	if (krc) {
		vty_out(vty, "%s: Error: %s returned %d: %s\n", __func__,
			"keycrypt_encrypt_internal_gcrypt_padding", krc,
			keycrypt_strerror(krc));
		return CMD_SUCCESS;
	}

	zlog_debug("%s: encrypted successfully", __func__);

	if (!pCipherText) {
		vty_out(vty, "%s: missing cipher text\n", __func__);
		return CMD_SUCCESS;
	}

	/*
	 * Encode for printing
	 */

	krc = keycrypt_base64_encode_gcrypt(pCipherText, CipherTextLen,
					    &pB64Text, &B64TextLen);

	XFREE(MTYPE_KEYCRYPT_CIPHER_TEXT, pCipherText);

	if (krc) {
		vty_out(vty, "%s: Error: %s returned %d: %s\n", __func__,
			"keycrypt_base64_encode_gcrypt", krc,
			keycrypt_strerror(krc));
		/* TBD does anything else need to be freed here? */
		return CMD_SUCCESS;
	}

	zlog_debug("%s: base64-encoded successfully", __func__);

	vty_out(vty,
		"INFO: clear text len: %zu, CipherTextLen: %zu, B64TextLen %zu\n",
		strlen(cleartext), CipherTextLen, B64TextLen);

	vty_out(vty, "INFO: base64 cipher text:\n%s\n", pB64Text);


	/*
	 * Decode back to binary
	 */
	keycrypt_base64_decode_gcrypt(pB64Text, B64TextLen, &pCipherText,
				      &CipherTextLen);

	vty_out(vty, "INFO: After B64 decode, CipherTextLen: %zu\n",
		CipherTextLen);


	rc = keycrypt_decrypt_internal_gcrypt_padding(
		use_pkcs1_padding, pPrivKey, MTYPE_KEYCRYPT_PLAIN_TEXT,
		pCipherText, CipherTextLen, &pClearText, &ClearTextLen);

	XFREE(MTYPE_KEYCRYPT_CIPHER_B64, pB64Text);

	if (pCipherText) {
		if (!strncmp(cleartext, pCipherText, strlen(cleartext))) {
			vty_out(vty,
				"%s: cipher text and cleartext same for %zu chars\n",
				__func__, strlen(cleartext));
			XFREE(MTYPE_KEYCRYPT_B64DEC, pCipherText);
			if (pClearText)
				XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
			return CMD_SUCCESS;
		}
		XFREE(MTYPE_KEYCRYPT_B64DEC, pCipherText);
	}

	if (rc) {
		vty_out(vty,
			"%s: Error: keycrypt_decrypt_internal_gcrypt_padding\n",
			__func__);
		if (pClearText)
			XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
		return CMD_SUCCESS;
	}

	if (!pClearText) {
		vty_out(vty,
			"%s: keycrypt_decrypt_internal_gcrypt_padding didn't return clear text pointer\n",
			__func__);
		return CMD_SUCCESS;
	}
	if (strlen(cleartext) != ClearTextLen) {
		vty_out(vty,
			"%s: decrypted ciphertext length (%zu) != original length (%lu)\n",
			__func__, ClearTextLen, strlen(cleartext));
		XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
		return CMD_SUCCESS;
	}

	if (strncmp(cleartext, pClearText, ClearTextLen)) {
		vty_out(vty,
			"%s: decrypted ciphertext differs from original text\n",
			__func__);
		XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
		return CMD_SUCCESS;
	}

	vty_out(vty, "OK: decrypted ciphertext matches original text\n");
	return CMD_SUCCESS;
}

/* clang-format off */
static int debug_keycrypt_test_cmd_gcrypt_pkcs1(
	struct vty	*vty,
	const char	*cleartext)
{
	return debug_keycrypt_test_cmd_gcrypt_padding(1, vty, cleartext);
}

static int debug_keycrypt_test_cmd_gcrypt_oaep(
	struct vty	*vty,
	const char	*cleartext)
{
	return debug_keycrypt_test_cmd_gcrypt_padding(0, vty, cleartext);
}
/* clang-format on */

/* clang-format off */
static enum keycrypt_err keyfile_read_status_gcrypt(
	const char	*keyfile_path,
	const char	**detail)
{
	enum keycrypt_err	krc;
	gcry_sexp_t		pPrivKey;
	gcry_sexp_t		pPubKey;
	/* clang-format on */

	*detail = NULL;

	krc = keycrypt_read_keyfile_gcrypt(keyfile_path, &pPrivKey, &pPubKey);
	if (krc)
		*detail = keycrypt_strerror(krc);

	return krc;
}

static const char *keycrypt_backend_version_string_gcrypt(void)
{
	static char versionstring[80]; /* arbitrary limit */

	versionstring[0] = 0;

	char *str = gcry_get_config(0, "version");

	if (str) {
		strlcpy(versionstring, str, sizeof(versionstring));
		gcry_free(str);
		return versionstring;
	}
	return "gcrypt (unknown version)";
}

/* clang-format off */
struct keycrypt_backend kbe_gcrypt_pkcs1 = {
	.name			= "gcrypt-pkcs1-padding",
	.f_encrypt		= keycrypt_encrypt_gcrypt_pkcs1,
	.f_decrypt		= keycrypt_decrypt_gcrypt_pkcs1,
	.f_test_cmd		= debug_keycrypt_test_cmd_gcrypt_pkcs1,
	.f_keyfile_read_status	= keyfile_read_status_gcrypt,
	.f_be_version_string	= keycrypt_backend_version_string_gcrypt,
};

struct keycrypt_backend kbe_gcrypt_oaep = {
	.name			= "gcrypt",
	.f_encrypt		= keycrypt_encrypt_gcrypt_oaep,
	.f_decrypt		= keycrypt_decrypt_gcrypt_oaep,
	.f_test_cmd		= debug_keycrypt_test_cmd_gcrypt_oaep,
	.f_keyfile_read_status	= keyfile_read_status_gcrypt,
	.f_be_version_string	= keycrypt_backend_version_string_gcrypt,
};
/* clang-format on */

#endif /* KEYCRYPT_HAVE_GCRYPT */

/***********************************************************************
 *		null backend simplifies error handling below
 ***********************************************************************/

/* clang-format off */
static int keycrypt_encrypt_null(
	const char	*pPlainText,		/* IN */
	size_t		PlainTextLen,		/* IN */
	char		**ppCipherTextB64,	/* OUT */
	size_t		*pCipherTextB64Len)	/* OUT */

{
	zlog_err("%s: KEYCRYPT_ENABLED not defined: keycrypt not available",
		 __func__);
	return -1;
}
static int keycrypt_decrypt_null(
	struct memtype	*mt,	/* of PlainText */	/* IN */
	const char	*pCipherTextB64,		/* IN */
	size_t		CipherTextB64Len,		/* IN */
	char		**ppPlainText,			/* OUT */
	size_t		*pPlainTextLen)			/* OUT */

{
	zlog_err("%s: KEYCRYPT_ENABLED not defined: keycrypt not available",
		 __func__);
	return -1;
}

static int debug_keycrypt_test_cmd_null(
	struct vty	*vty,
	const char	*cleartext)
{
	vty_out(vty, "Error: keycrypt not enabled in this build\n");
	return CMD_SUCCESS;
}

static const char *keycrypt_backend_version_string_null(void)
{
	return "null backend version 0";
}

struct keycrypt_backend kbe_null = {
	.name			= NULL,
	.f_encrypt		= keycrypt_encrypt_null,
	.f_decrypt		= keycrypt_decrypt_null,
	.f_test_cmd		= debug_keycrypt_test_cmd_null,
	.f_keyfile_read_status	= NULL,
	.f_be_version_string	= keycrypt_backend_version_string_null,
};
/* clang-format on */

/***********************************************************************
 *		externally-visible functions
 ***********************************************************************/


/*
 * first backend present is the one we use
 */
/* clang-format off */
static struct keycrypt_backend *keycrypt_backends[] = {
#ifdef KEYCRYPT_HAVE_GCRYPT
	&kbe_gcrypt_oaep,
#if KEYCRYPT_ENABLE_PKCS1_PADDING
	&kbe_gcrypt_pkcs1,
#endif
#endif
#ifdef KEYCRYPT_HAVE_OPENSSL
	&kbe_openssl_oaep,
#if KEYCRYPT_ENABLE_PKCS1_PADDING
	&kbe_openssl_pkcs1,
#endif
#endif
#ifdef KEYCRYPT_HAVE_GNUTLS
#if KEYCRYPT_ENABLE_PKCS1_PADDING
	&kbe_gnutls_pkcs1,
#endif
#endif
	&kbe_null,
	NULL};
/* clang-format on */

struct keycrypt_backend *kc_current_backend;

#define KC_BACKEND (kc_current_backend)

const char *keycrypt_strerror(enum keycrypt_err kc_err)
{
	switch (kc_err) {
	case KC_OK:
		return "No error";
	case KC_ERR_MEMORY:
		return "Can't allocate memory";
	case KC_ERR_BASE64:
		return "base64 encode/decode error";
	case KC_ERR_DECRYPT:
		return "Can't decrypt";
	case KC_ERR_ENCRYPT:
		return "Can't encrypt";
	case KC_ERR_BUILD_NOT_ENABLED:
		return "keycrypt not enabled in this build";
	case KC_ERR_KEYFILE_PATH:
		return "Can't compute private key file path";
	case KC_ERR_KEYFILE_READ:
		return "Can't read private key file";
	case KC_ERR_KEYFILE_PARSE:
		return "Can't parse private key file";
	case KC_ERR_KEYFILE_EXISTS:
		return "Keyfile already exists";
	case KC_ERR_INTERNAL:
		return "Unexpected/internal error";
	}
	return "Unknown error";
}

/*
 * After successful return (0), caller MUST free base-64 encoded
 * cipher text via XFREE(MTYPE_KEYCRYPT_CIPHER_B64, ptr)
 */
int keycrypt_encrypt(const char *pPlainText,    /* IN */
		     size_t PlainTextLen,       /* IN */
		     char **ppCipherTextB64,    /* OUT */
		     size_t *pCipherTextB64Len) /* OUT */

{
	return (*KC_BACKEND->f_encrypt)(pPlainText, PlainTextLen,
					ppCipherTextB64, pCipherTextB64Len);
}

int keycrypt_decrypt(struct memtype *mt, /* of PlainText */ /* IN */
		     const char *pCipherTextB64,	    /* IN */
		     size_t CipherTextB64Len,		    /* IN */
		     char **ppPlainText,		    /* OUT */
		     size_t *pPlainTextLen)		    /* OUT */

{
	return (*KC_BACKEND->f_decrypt)(mt, pCipherTextB64, CipherTextB64Len,
					ppPlainText, pPlainTextLen);
}

/*
 * keycrypt_build_passwords
 *
 * Takes a single encrypted or plaintext password as input.
 *
 * Attempts to encrypt or decrypt as needed, and returns either
 * one or two dynamically-allocated strings containing the
 * plaintext and encrypted passwords.
 *
 * Caller MUST take ownership of any returned allocated strings.
 * These strings are indicated by non-NULL pointer values returned
 * via the ppPlainText and ppCryptText parameters.
 *
 * NOTE! By design, this function allocates strings even if it
 * returns an error value.
 *
 * Return codes:
 *
 *	0: KC_OK	Successful encrypt or decrypt operation
 *	!0		encrypt or decrypt failed
 */
/* clang-format off */
enum keycrypt_err
keycrypt_build_passwords(
	const char	*password_in,	/* IN */
	bool		is_encrypted,	/* IN */
	struct memtype	*mt_plaintext,	/* IN */
	char		**ppPlainText,	/* OUT type mt_plaintext */
	char		**ppCryptText)	/* OUT MTYPE_KEYCRYPT_CIPHER_B64 */

{
	*ppPlainText = NULL;
	*ppCryptText = NULL;

	if (is_encrypted) {
		/* don't lose encrypted password */
		*ppCryptText = XSTRDUP(MTYPE_KEYCRYPT_CIPHER_B64, password_in);

#ifdef KEYCRYPT_ENABLED
		int rc;

		rc = keycrypt_decrypt(mt_plaintext, password_in,
				     strlen(password_in), ppPlainText, NULL);

		if (rc) {
			zlog_err("%s: keycrypt_decrypt failed", __func__);
			return KC_ERR_DECRYPT;
		}
#else
		zlog_err("%s: can't decrypt: keycrypt not supported in this build",
		    __func__);
		return KC_ERR_BUILD_NOT_ENABLED;
#endif

	} else {

		*ppPlainText = XSTRDUP(mt_plaintext, password_in);

		if (keycrypt_is_now_encrypting()) {

#ifdef KEYCRYPT_ENABLED
			if (keycrypt_encrypt(password_in, strlen(password_in),
					     ppCryptText, NULL)) {
				zlog_err("%s: keycrypt_encrypt failed",
				    __func__);
				return KC_ERR_ENCRYPT;
			}
#else
			zlog_err("%s: can't encrypt: keycrypt not supported in this build",
			    __func__);
			return KC_ERR_BUILD_NOT_ENABLED;
#endif

		}
	}

	return KC_OK;
}
/* clang-format on */

/* clang-format off */
DEFUN_HIDDEN (debug_keycrypt_test,
	      debug_keycrypt_test_cmd,
	      "debug keycrypt-test STRING",
	      "Debug command\n"
	      "Test keycrypt encryption and decryption\n"
	      "plain text to encrypt and decrypt\n")
/* clang-format on */
{
	int idx_string = 2;
	const char *cleartext = argv[idx_string]->arg;

	return (*KC_BACKEND->f_test_cmd)(vty, cleartext);
}

/* clang-format off */
static void inter_backend_test(
	struct vty		*vty,
	const char		*cleartext,
	struct keycrypt_backend	*b1,
	struct keycrypt_backend	*b2)
{
	size_t	cleartext_len;
	char	*pPlainText;
	char	*pCipherTextB64;
	size_t	PlainTextLen;
	size_t	CipherTextB64Len;
	int	rc;
	/* clang-format on */

	cleartext_len = strlen(cleartext);

	vty_out(vty, "cross-backend test %s->%s\n", b1->name, b2->name);
	vty_out(vty, "  cleartext \"%s\", cleartext_len %zu\n", cleartext,
		cleartext_len);

	/*
	 * encrypt with b1
	 * allocates pCipherTextB64 MTYPE_KEYCRYPT_CIPHER_B64
	 */
	rc = (*b1->f_encrypt)(cleartext, cleartext_len, &pCipherTextB64,
			      &CipherTextB64Len);
	if (rc) {
		vty_out(vty, "Error: %s encryption failed, rc=%d\n", b1->name,
			rc);
		return;
	}

	vty_out(vty, "OK: %s encryption result len %zu: \"%s\"\n", b1->name,
		CipherTextB64Len, pCipherTextB64);

	/*
	 * Decrypt with b1 (same as encrypt) first
	 */
	rc = (*b1->f_decrypt)(MTYPE_TMP, pCipherTextB64, CipherTextB64Len,
			      &pPlainText, &PlainTextLen);
	if (rc) {
		vty_out(vty, "Error: %s decryption failed, rc=%d\n", b1->name,
			rc);
		XFREE(MTYPE_KEYCRYPT_CIPHER_B64, pCipherTextB64);
		return;
	}

	/*
	 * compare plaintext
	 */
	if (PlainTextLen != cleartext_len) {
		vty_out(vty,
			"Error: orig cleartext len %zu, decrypted len %zu\n",
			cleartext_len, PlainTextLen);
		XFREE(MTYPE_KEYCRYPT_CIPHER_B64, pCipherTextB64);
		XFREE(MTYPE_TMP, pPlainText);
		return;
	}
	if (strncmp(pPlainText, cleartext, cleartext_len)) {
		vty_out(vty, "Error: orig cleartext differs from decrypted\n");
		XFREE(MTYPE_KEYCRYPT_CIPHER_B64, pCipherTextB64);
		XFREE(MTYPE_TMP, pPlainText);
		return;
	}

	vty_out(vty, "OK %s->%s \"%s\" == \"%s\"\n", b1->name, b1->name,
		cleartext, pPlainText);

	XFREE(MTYPE_TMP, pPlainText);


	/*
	 * decrypt with b2
	 * allocates pPlainText MTYPE_TMP
	 */
	rc = (*b2->f_decrypt)(MTYPE_TMP, pCipherTextB64, CipherTextB64Len,
			      &pPlainText, &PlainTextLen);
	if (rc) {
		vty_out(vty, "Error: %s decryption failed, rc=%d\n", b2->name,
			rc);
		XFREE(MTYPE_KEYCRYPT_CIPHER_B64, pCipherTextB64);
		return;
	}

	/*
	 * compare plaintext
	 */
	if (PlainTextLen != cleartext_len) {
		vty_out(vty,
			"Error: orig cleartext len %zu, decrypted len %zu\n",
			cleartext_len, PlainTextLen);
		XFREE(MTYPE_KEYCRYPT_CIPHER_B64, pCipherTextB64);
		XFREE(MTYPE_TMP, pPlainText);
		return;
	}
	if (strncmp(pPlainText, cleartext, cleartext_len)) {
		vty_out(vty, "Error: orig cleartext differs from decrypted\n");
		XFREE(MTYPE_KEYCRYPT_CIPHER_B64, pCipherTextB64);
		XFREE(MTYPE_TMP, pPlainText);
		return;
	}

	vty_out(vty, "OK %s->%s \"%s\" == \"%s\"\n", b1->name, b2->name,
		cleartext, pPlainText);

	XFREE(MTYPE_KEYCRYPT_CIPHER_B64, pCipherTextB64);
	XFREE(MTYPE_TMP, pPlainText);
}

/* clang-format off */
DEFUN_HIDDEN (debug_keycrypt_test_inter_backend,
	      debug_keycrypt_test_inter_backend_cmd,
	      "debug keycrypt-test-inter-backend BE1 BE2 STRING",
	      "Debug command\n"
	      "Test keycrypt encryption and decryption\n"
	      "Name of first backend\n"
	      "Name of second backend\n"
	      "plain text to encrypt and decrypt\n")
/* clang-format on */
{
	int idx = 0;
	const char *cleartext = NULL;

	const char *name1 = NULL;
	const char *name2 = NULL;

	struct keycrypt_backend *b1 = NULL;
	struct keycrypt_backend *b2 = NULL;
	struct keycrypt_backend **p;

	if (argv_find(argv, argc, "BE1", &idx))
		name1 = argv[idx]->arg;
	if (argv_find(argv, argc, "BE2", &idx))
		name2 = argv[idx]->arg;
	if (argv_find(argv, argc, "STRING", &idx))
		cleartext = argv[idx]->arg;

	if (!name1 || !name2) {
		vty_out(vty, "missing two required backend names\n");
		return CMD_SUCCESS;
	}

	for (p = keycrypt_backends; *p; ++p) {
		if (!(*p)->name)
			continue;
		if (!strcmp((*p)->name, name1))
			b1 = *p;
		if (!strcmp((*p)->name, name2))
			b2 = *p;
	}

	/*
	 * Do we have cleartext?
	 */
	if (!cleartext) {
		vty_out(vty, "no %s\n", "cleartext");
		return CMD_SUCCESS;
	}

	/*
	 * Do we have both backends?
	 */
	if (!b1) {
		vty_out(vty, "no %s\n", name1);
		return CMD_SUCCESS;
	}
	if (!b2) {
		vty_out(vty, "no %s\n", name2);
		return CMD_SUCCESS;
	}

	inter_backend_test(vty, cleartext, b1, b2);
	inter_backend_test(vty, cleartext, b2, b1);

	return CMD_SUCCESS;
}

/* clang-format off */
DEFUN_HIDDEN (debug_keycrypt_test_inter_padding,
	      debug_keycrypt_test_inter_padding_cmd,
	      "debug keycrypt-test-inter-padding STRING",
	      "Debug command\n"
	      "Test keycrypt encryption and decryption\n"
	      "plain text to encrypt and decrypt\n")
/* clang-format on */
{
	int idx_string = 2;
	const char *cleartext = argv[idx_string]->arg;

	struct keycrypt_backend *b1 = NULL;
	struct keycrypt_backend *b2 = NULL;
	struct keycrypt_backend **p;

	for (p = keycrypt_backends; *p; ++p) {
		if (!(*p)->name)
			continue;
		if (!strcmp((*p)->name, "openssl"))
			b1 = *p;
		if (!strcmp((*p)->name, "openssl-oaep"))
			b2 = *p;
	}

	/*
	 * Do we have both backends?
	 */
	if (!b1) {
		vty_out(vty, "no b1\n");
		return CMD_SUCCESS;
	}
	if (!b2) {
		vty_out(vty, "no b2\n");
		return CMD_SUCCESS;
	}

	inter_backend_test(vty, cleartext, b2, b1);
	inter_backend_test(vty, cleartext, b1, b2);

	return CMD_SUCCESS;
}

/* clang-format off */
DEFUN_HIDDEN (debug_keycrypt_show_backends,
	      debug_keycrypt_show_backends_cmd,
	      "debug keycrypt show backends",
	      "Debug command\n"
	      "Keycrypt encryption and decryption\n"
	      "show\n"
	      "list available crypto backends\n")
/* clang-format on */
{
	struct keycrypt_backend **p;

	for (p = keycrypt_backends; *p; ++p) {
		const char *version;
		bool selected;

		if (!(*p)->name)
			continue;
		if ((*p)->f_be_version_string)
			version = ((*p)->f_be_version_string)();
		else
			version = "?";

		if (*p == kc_current_backend)
			selected = true;
		else
			selected = false;

		/* clang-format off */
		vty_out(vty, "%c%s: %s\n",
			(selected ? '*' : ' '), (*p)->name, version);
		/* clang-format on */
	}

	return CMD_SUCCESS;
}

/* clang-format off */
DEFUN_HIDDEN (debug_keycrypt_set_backend,
	      debug_keycrypt_set_backend_cmd,
	      "debug keycrypt set backend STRING",
	      "Debug command\n"
	      "keycrypt encryption and decryption\n"
	      "set\n"
	      "backend\n"
	      "select an available crypto backend")
/* clang-format on */
{
	int idx_string = 4;
	const char *be_name = argv[idx_string]->arg;

	struct keycrypt_backend *b = NULL;
	struct keycrypt_backend **p;

	for (p = keycrypt_backends; *p; ++p) {
		if (!(*p)->name)
			continue;
		if (!strcmp((*p)->name, be_name)) {
			b = *p;
			break;
		}
	}

	if (!b) {
		vty_out(vty, "keycrypt: unknown backend \"%s\"\n", be_name);
		return CMD_SUCCESS;
	}

	kc_current_backend = b;

	return CMD_SUCCESS;
}

static bool keycrypt_now_encrypting;
static keycrypt_callback_t *keycrypt_protocol_callback;
static keycrypt_show_callback_t *keycrypt_protocol_show_callback;

void keycrypt_register_protocol_callback(keycrypt_callback_t *kcb)
{
	keycrypt_protocol_callback = kcb;
}

bool keycrypt_is_now_encrypting(void)
{
	return keycrypt_now_encrypting;
}

void keycrypt_state_change(bool now_encrypting)
{
	if (now_encrypting == keycrypt_now_encrypting)
		return;

	keycrypt_now_encrypting = now_encrypting;

	if (keycrypt_protocol_callback)
		(*keycrypt_protocol_callback)(now_encrypting);

	keychain_encryption_state_change(now_encrypting);
}

static void keycrypt_show_status_internal(struct vty *vty)
{
	const char *status;

#ifdef KEYCRYPT_ENABLED
	status = keycrypt_now_encrypting ? "ON" : "off";
#else
	status = "not included in software build";
#endif
	vty_out(vty, "%s Keycrypt status: %s\n", frr_protoname, status);

#ifdef KEYCRYPT_ENABLED
	const char *indentstr = "  ";
	char *keyfile_path;
	enum keycrypt_err krc;

	vty_out(vty, "%s%s: Keycrypt backend: %s\n", indentstr, frr_protoname,
		KC_BACKEND->name);

	vty_out(vty, "%s%s: Keycrypt backend version: %s\n", indentstr,
		frr_protoname, KC_BACKEND->f_be_version_string());

	keyfile_path = keycrypt_keyfile_path();

	/* clang-format off */
	if (keyfile_path) {

		const char *details = NULL;

		vty_out(vty, "%s%s: Private key file name: \"%s\"\n",
			indentstr, frr_protoname, keyfile_path);

		if (KC_BACKEND->f_keyfile_read_status) {
			krc = (*KC_BACKEND->f_keyfile_read_status)(
				keyfile_path, &details);
			XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);
			if (krc) {
				vty_out(vty,
				    "%s%s: Private key file status: NOT READABLE\n",
				    indentstr, frr_protoname);
				if (details) {
					vty_out(vty,
					    "%s%s: Private key file details: %s\n",
					    indentstr, frr_protoname, details);
				}
			} else {
				vty_out(vty,
				    "%s%s: Private key file status: readable\n",
				    indentstr, frr_protoname);
			}
		}

	} else {
		uid_t uid = geteuid();

		vty_out(vty,
		    "%s%s: Private key file name: UNABLE TO COMPUTE (euid %u)\n",
		    indentstr, frr_protoname, (unsigned int)uid);
	}
	/* clang-format on */

	keychain_encryption_show_status(vty, indentstr);

	if (keycrypt_protocol_show_callback)
		(*keycrypt_protocol_show_callback)(vty, indentstr);
#endif
}

void keycrypt_register_protocol_show_callback(keycrypt_show_callback_t *kcb)
{
	keycrypt_protocol_show_callback = kcb;
}

DEFUN (keycrypt_show_status,
       keycrypt_show_status_cmd,
       "show keycrypt status",
       "Show command\n"
       "keycrypt protocol key encryption\n"
       "status\n")
{
	keycrypt_show_status_internal(vty);
	return CMD_SUCCESS;
}

void keycrypt_init(void)
{
	kc_current_backend = keycrypt_backends[0];

	install_element(VIEW_NODE, &debug_keycrypt_show_backends_cmd);

	install_element(ENABLE_NODE, &debug_keycrypt_set_backend_cmd);
	/* install in config node for benefit of topotests/authentication */
	install_element(CONFIG_NODE, &debug_keycrypt_set_backend_cmd);

	install_element(VIEW_NODE, &debug_keycrypt_test_cmd);
	install_element(VIEW_NODE, &debug_keycrypt_test_inter_backend_cmd);
	install_element(VIEW_NODE, &debug_keycrypt_test_inter_padding_cmd);
	install_element(VIEW_NODE, &keycrypt_show_status_cmd);
}
