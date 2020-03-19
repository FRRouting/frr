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

#include <zebra.h>

#include "memory.h"
#include "log.h"
#include "keycrypt.h"
#include "command.h"
#include "keychain.h"
#include "libfrr.h"

DEFINE_MTYPE(LIB, KEYCRYPT_CIPHER_B64, "keycrypt base64 encoded")
DEFINE_MTYPE(LIB, KEYCRYPT_PLAIN_TEXT, "keycrypt plain text")

#ifdef CRYPTO_OPENSSL

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

#define KEYFILE_NAME_PRIVATE ".ssh/frr"
#define PWENT_BUFSIZE 512

DEFINE_MTYPE_STATIC(LIB, KEYCRYPT_KEYFILE_PATH, "keycrypt keyfile path")
DEFINE_MTYPE_STATIC(LIB, KEYCRYPT_CIPHER_TEXT, "keycrypt cipher text")
DEFINE_MTYPE_STATIC(LIB, KEYCRYPT_B64DEC, "keycrypt base64 decoded")

typedef enum {
	KEYCRYPT_FORMAT_ASN1,
	KEYCRYPT_FORMAT_PEM,
	KEYCRYPT_FORMAT_PVK,
} keycrypt_key_format_t;

/*
 * TBD: validate permissions on keyfile path
 */

/*
 * Compute path to keyfile
 *
 * Caller must free returned buffer XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, path)
 *
 * Return value is NULL on failure.
 */
static char *keycrypt_keyfile_path(void)
{
	/*
	 * get homedir
	 */
	uid_t uid = geteuid();
	struct passwd pwd;
	struct passwd *pwd_result;
	char *pbuf = XMALLOC(MTYPE_TMP, PWENT_BUFSIZE);
	int rc;
	char *path = NULL;
	size_t len_pw_dir;
	size_t len;
	const char *sep = "/";

	rc = getpwuid_r(uid, &pwd, pbuf, PWENT_BUFSIZE, &pwd_result);
	if (rc) {
		zlog_warn("%s: getpwuid_r(uid=%u): %s", __func__, uid,
			  safe_strerror(errno));
		XFREE(MTYPE_TMP, pbuf);
		return NULL;
	}

	len_pw_dir = strlen(pwd.pw_dir);
	len = len_pw_dir + 1 + strlen(KEYFILE_NAME_PRIVATE) + 1;
	path = XMALLOC(MTYPE_KEYCRYPT_KEYFILE_PATH, len);

	/* clean up one trailing slash if needed */
	if (pwd.pw_dir[len_pw_dir - 1] == '/')
		sep = "";
	snprintf(path, len, "%s%s%s", pwd.pw_dir, sep, KEYFILE_NAME_PRIVATE);
	XFREE(MTYPE_TMP, pbuf);

	return path;
}

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
static EVP_PKEY *keycrypt_read_keyfile(char *path, keycrypt_key_format_t format)
{
	FILE *fp;
	BIO *fb;
	EVP_PKEY *pkey = NULL;
	const char *formatstr = "";

	/*
	 * Use fopen() instead of BIO_new_file() so we can get meaningful
	 * error messages to the log for not-found or permission issues.
	 */
	fp = fopen(path, "r");
	if (!fp) {
		zlog_err("%s: fopen(\"%s\") failed: %s", __func__, path,
			 safe_strerror(errno));
		return NULL;
	}

	fb = BIO_new_fp(fp, BIO_CLOSE);
	if (!fb) {
		fclose(fp);
		zlog_err("%s: BIO_new_fp() failed", __func__);
		return NULL;
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

	return pkey;
}

/*
 * Caller must free result XFREE(MTYPE_KEYCRYPT_CIPHER_B64, *pOut)
 */
void keycrypt_base64_encode(const char *pIn, size_t InLen, char **ppOut,
			    size_t *pOutLen)
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
void keycrypt_base64_decode(const char *pIn, size_t InLen, char **ppOut,
			    size_t *pOutLen)
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
static int keycrypt_encrypt_internal(EVP_PKEY *pKey, /* IN */
				     struct memtype *mt,
				     /* of CipherText */     /* IN */
				     const char *pPlainText, /* IN */
				     size_t PlainTextLen,    /* IN */
				     char **ppCipherText,    /* OUT */
				     size_t *pCipherTextLen) /* OUT */
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

	rc = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
	if (rc <= 0) {
		EVP_PKEY_CTX_free(ctx);
		zlog_warn("%s: Error: EVP_PKEY_CTX_set_rsa_padding%s", __func__,
			  ((rc == -2) ? ": not supported by public key alg"
				      : ""));
		return -1;
	}

	/* Determine buffer length */
	rc = EVP_PKEY_encrypt(ctx, NULL, pCipherTextLen,
			      (const u_char *)pPlainText, PlainTextLen);
	if (rc <= 0) {
		EVP_PKEY_CTX_free(ctx);
		zlog_warn("%s: Error: EVP_PKEY_encrypt (1)%s", __func__,
			  ((rc == -2) ? ": not supported by public key alg"
				      : ""));
		return -1;
	}

	*ppCipherText = XMALLOC(mt, *pCipherTextLen);

	rc = EVP_PKEY_encrypt(ctx, (u_char *)*ppCipherText, pCipherTextLen,
			      (const u_char *)pPlainText, PlainTextLen);
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
static int keycrypt_decrypt_internal(EVP_PKEY *pKey, /* IN */
				     struct memtype *mt,
				     /* of PlainText */       /* IN */
				     const char *pCipherText, /* IN */
				     size_t CipherTextLen,    /* IN */
				     char **ppPlainText,      /* OUT */
				     size_t *pPlainTextLen)   /* OUT */
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

	rc = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
	if (rc <= 0) {
		EVP_PKEY_CTX_free(ctx);
		zlog_warn("%s: Error: EVP_PKEY_CTX_set_rsa_padding%s", __func__,
			  ((rc == -2) ? ": not supported by public key alg"
				      : ""));
		return -1;
	}

	/* Determine buffer length */
	rc = EVP_PKEY_decrypt(ctx, NULL, pPlainTextLen,
			      (const u_char *)pCipherText, CipherTextLen);
	if (rc <= 0) {
		EVP_PKEY_CTX_free(ctx);
		zlog_warn("%s: Error: EVP_PKEY_encrypt (1)%s", __func__,
			  ((rc == -2) ? ": not supported by public key alg"
				      : ""));
		return -1;
	}

	*ppPlainText = XMALLOC(mt, *pPlainTextLen + 1);

	rc = EVP_PKEY_decrypt(ctx, (u_char *)*ppPlainText, pPlainTextLen,
			      (const u_char *)pCipherText, CipherTextLen);
	if (rc <= 0) {
		EVP_PKEY_CTX_free(ctx);
		if (*ppPlainText)
			XFREE(mt, *ppPlainText);
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
static keycrypt_err_t keycrypt_read_default_keyfile(EVP_PKEY **ppKey)
{
	char *keyfile_path;

	*ppKey = NULL;

	keyfile_path = keycrypt_keyfile_path();
	if (!keyfile_path) {
		zlog_err("%s: Error: can't compute keyfile path\n", __func__);
		return KC_ERR_KEYFILE_PATH;
	}

	*ppKey = keycrypt_read_keyfile(keyfile_path, KEYCRYPT_FORMAT_PEM);
	if (!*ppKey) {
		zlog_err("%s: Error: keycrypt_read_keyfile can't read \"%s\"\n",
			 __func__, keyfile_path);
		XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);
		return KC_ERR_KEYFILE_READ;
	}
	XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);
	return KC_OK;
}

static EVP_PKEY *keycrypt_cached_pkey;
static time_t keycrypt_pkey_check_time;
#define KEYCRYPT_CHECK_PKEY_SECONDS 10

/*
 * Caller should not free returned key
 */
static EVP_PKEY *keycrypt_get_pkey()
{
	time_t now;

	now = monotime(NULL);
	if (now - keycrypt_pkey_check_time > KEYCRYPT_CHECK_PKEY_SECONDS) {
		EVP_PKEY *pKey;
		keycrypt_err_t rc;

		keycrypt_pkey_check_time = now;

		rc = keycrypt_read_default_keyfile(&pKey);
		if (rc != KC_OK)
			goto end;

		if (keycrypt_cached_pkey)
			EVP_PKEY_free(keycrypt_cached_pkey);

		keycrypt_cached_pkey = pKey;
	}
end:
	return keycrypt_cached_pkey;
}

#endif /* CRYPTO_OPENSSL */


/*
 * After successful return (0), caller MUST free base-64 encoded
 * cipher text via XFREE(MTYPE_KEYCRYPT_CIPHER_B64, ptr)
 */
int keycrypt_encrypt(const char *pPlainText,    /* IN */
		     size_t PlainTextLen,       /* IN */
		     char **ppCipherTextB64,    /* OUT */
		     size_t *pCipherTextB64Len) /* OUT */
{
#ifdef CRYPTO_OPENSSL
	EVP_PKEY *pKey;
	int rc;
	char *pCipherTextRaw;
	size_t CipherTextRawLen;
	size_t B64len;

	pKey = keycrypt_get_pkey();
	if (!pKey)
		return -1;

	rc = keycrypt_encrypt_internal(pKey, MTYPE_KEYCRYPT_CIPHER_TEXT,
				       pPlainText, PlainTextLen,
				       &pCipherTextRaw, &CipherTextRawLen);
	if (rc)
		return -1;

	keycrypt_base64_encode(pCipherTextRaw, CipherTextRawLen,
			       ppCipherTextB64, &B64len);

	if (pCipherTextB64Len)
		*pCipherTextB64Len = B64len;

	XFREE(MTYPE_KEYCRYPT_CIPHER_TEXT, pCipherTextRaw);

	return 0;
#else
	zlog_err("%s: CRYPTO_OPENSSL not defined: keycrypt not available",
		 __func__);
	return -1;
#endif
}

int keycrypt_decrypt(struct memtype *mt, /* of PlainText */ /* IN */
		     const char *pCipherTextB64,	    /* IN */
		     size_t CipherTextB64Len,		    /* IN */
		     char **ppPlainText,		    /* OUT */
		     size_t *pPlainTextLen)		    /* OUT */
{
#ifdef CRYPTO_OPENSSL
	EVP_PKEY *pKey;
	int rc;
	char *pCipherTextRaw;
	size_t CipherTextRawLen;
	size_t PlainTextLen;

	pKey = keycrypt_get_pkey();
	if (!pKey)
		return -1;

	keycrypt_base64_decode(pCipherTextB64, CipherTextB64Len,
			       &pCipherTextRaw, &CipherTextRawLen);

	rc = keycrypt_decrypt_internal(pKey, mt, pCipherTextRaw,
				       CipherTextRawLen, ppPlainText,
				       &PlainTextLen);

	XFREE(MTYPE_KEYCRYPT_B64DEC, pCipherTextRaw);

	if (rc)
		return -1;

	if (pPlainTextLen)
		*pPlainTextLen = PlainTextLen;

	return 0;
#else
	zlog_err("%s: CRYPTO_OPENSSL not defined: keycrypt not available",
		 __func__);
	return -1;
#endif
}

const char *keycrypt_strerror(keycrypt_err_t kc_err)
{
	switch (kc_err) {
	case KC_OK:
		return "No error";
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
	}
	return "Unknown error";
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
keycrypt_err_t
keycrypt_build_passwords(const char *password_in,      /* IN */
			 bool is_encrypted,	    /* IN */
			 struct memtype *mt_plaintext, /* IN */
			 char **ppPlainText, /* OUT type mt_plaintext */
			 char **ppCryptText) /* OUT MTYPE_KEYCRYPT_CIPHER_B64 */
{
	*ppPlainText = NULL;
	*ppCryptText = NULL;

	if (is_encrypted) {
		/* don't lose encrypted password */
		*ppCryptText = XSTRDUP(MTYPE_KEYCRYPT_CIPHER_B64, password_in);

#ifdef KEYCRYPT_ENABLED
		if (keycrypt_decrypt(mt_plaintext, password_in,
				     strlen(password_in), ppPlainText, NULL)) {

			zlog_err("%s: keycrypt_decrypt failed", __func__);
			return KC_ERR_DECRYPT;
		}
#else
		zlog_err(
			"%s: can't decrypt: keycrypt not supported in this build",
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
			zlog_err(
				"%s: can't encrypt: keycrypt not supported in this build",
				__func__);
			return KC_ERR_BUILD_NOT_ENABLED;
#endif
		}
	}

	return KC_OK;
}

DEFUN_HIDDEN (debug_keycrypt_test,
	      debug_keycrypt_test_cmd,
	      "debug keycrypt-test STRING",
	      "Debug command\n"
	      "Test keycrypt encryption and decryption\n"
	      "plain text to encrypt and decrypt\n")
{
#ifdef CRYPTO_OPENSSL
	char *keyfile_path = NULL;
	EVP_PKEY *pKey;
	int rc;
	char *pCipherText = NULL;
	size_t CipherTextLen;
	char *pClearText = NULL;
	size_t ClearTextLen;
	int idx_string = 2;
	char *pB64Text;
	size_t B64TextLen;

	const char *cleartext = argv[idx_string]->arg;

	keyfile_path = keycrypt_keyfile_path();
	if (!keyfile_path) {
		vty_out(vty, "%s: Error: can't compute keyfile path\n",
			__func__);
		return CMD_SUCCESS;
	}

	pKey = keycrypt_read_keyfile(keyfile_path, KEYCRYPT_FORMAT_PEM);
	if (!pKey) {
		vty_out(vty, "%s: Error: keycrypt_read_keyfile\n", __func__);
		XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);
		return CMD_SUCCESS;
	}
	XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);

	rc = keycrypt_encrypt_internal(pKey, MTYPE_KEYCRYPT_CIPHER_TEXT,
				       cleartext, strlen(cleartext),
				       &pCipherText, &CipherTextLen);
	if (rc) {
		EVP_PKEY_free(pKey);
		vty_out(vty, "%s: Error: keycrypt_encrypt_internal\n",
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

	keycrypt_base64_encode(pCipherText, CipherTextLen, &pB64Text,
			       &B64TextLen);

	XFREE(MTYPE_KEYCRYPT_CIPHER_TEXT, pCipherText);

	vty_out(vty,
		"INFO: clear text len: %zu, CipherTextLen: %zu, B64TextLen %zu\n",
		strlen(cleartext), CipherTextLen, B64TextLen);

	vty_out(vty, "INFO: base64 cipher text:\n%s\n", pB64Text);


	/*
	 * Decode back to binary
	 */
	keycrypt_base64_decode(pB64Text, B64TextLen, &pCipherText,
			       &CipherTextLen);

	XFREE(MTYPE_KEYCRYPT_CIPHER_B64, pB64Text);

	vty_out(vty, "INFO: After B64 decode, CipherTextLen: %zu\n",
		CipherTextLen);


	rc = keycrypt_decrypt_internal(pKey, MTYPE_KEYCRYPT_PLAIN_TEXT,
				       pCipherText, CipherTextLen, &pClearText,
				       &ClearTextLen);

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
		vty_out(vty, "%s: Error: keycrypt_decrypt_internal\n",
			__func__);
		if (pClearText)
			XFREE(MTYPE_KEYCRYPT_PLAIN_TEXT, pClearText);
		return CMD_SUCCESS;
	}

	if (!pClearText) {
		vty_out(vty,
			"%s: keycrypt_decrypt_internal didn't return clear text pointer\n",
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

#else  /* CRYPTO_OPENSSL */
	vty_out(vty,
		"Error: CRYPTO_OPENSSL not defined, keycrypt not enabled\n");
#endif /* CRYPTO_OPENSSL */

	return CMD_SUCCESS;
}

static bool keycrypt_now_encrypting = false;
static keycrypt_callback_t *keycrypt_protocol_callback = NULL;
static keycrypt_show_callback_t *keycrypt_protocol_show_callback = NULL;

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

	keyfile_path = keycrypt_keyfile_path();

	if (keyfile_path) {
		EVP_PKEY *pKey;

		vty_out(vty, "%s%s: Private key file name: \"%s\"\n", indentstr,
			frr_protoname, keyfile_path);
		pKey = keycrypt_read_keyfile(keyfile_path, KEYCRYPT_FORMAT_PEM);
		XFREE(MTYPE_KEYCRYPT_KEYFILE_PATH, keyfile_path);
		if (pKey) {
			vty_out(vty,
				"%s%s: Private key file status: readable\n",
				indentstr, frr_protoname);
			EVP_PKEY_free(pKey);
		} else {
			vty_out(vty,
				"%s%s: Private key file status: NOT READABLE\n",
				indentstr, frr_protoname);
		}

	} else {
		uid_t uid = geteuid();
		vty_out(vty,
			"%s%s: Private key file name: UNABLE TO COMPUTE (euid %u)\n",
			indentstr, frr_protoname, uid);
	}

	keychain_encryption_show_status(vty, indentstr);

	if (keycrypt_protocol_show_callback) {
		(*keycrypt_protocol_show_callback)(vty, indentstr);
	}
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
	install_element(VIEW_NODE, &debug_keycrypt_test_cmd);
	install_element(VIEW_NODE, &keycrypt_show_status_cmd);
}
