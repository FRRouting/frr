// SPDX-License-Identifier: BSD-2-Clause
/*-
 * Copyright 2005,2007,2009 Colin Percival
 * All rights reserved.
 *
 * $FreeBSD: src/lib/libmd/sha256.h,v 1.2 2006/01/17 15:35:56 phk Exp $
 */

#ifndef _SHA256_H_
#define _SHA256_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SHA256Context {
	uint32_t state[8];
	uint32_t count[2];
	unsigned char buf[64];
} SHA256_CTX;

typedef struct HMAC_SHA256Context {
	SHA256_CTX ictx;
	SHA256_CTX octx;
} HMAC_SHA256_CTX;

void SHA256_Init(SHA256_CTX *ctx);
void SHA256_Update(SHA256_CTX *ctx, const void *in, size_t len);
void SHA256_Final(unsigned char digest[32], SHA256_CTX *ctx);
void HMAC__SHA256_Init(HMAC_SHA256_CTX *ctx, const void *_K, size_t Klen);
void HMAC__SHA256_Update(HMAC_SHA256_CTX *ctx, const void *in, size_t len);
void HMAC__SHA256_Final(unsigned char digest[32], HMAC_SHA256_CTX *ctx);

/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
void PBKDF2_SHA256(const uint8_t *passwd, size_t passwdlen, const uint8_t *salt, size_t saltlen,
		   uint64_t c, uint8_t *buf, size_t dkLen);

#ifdef __cplusplus
}
#endif

#endif /* !_SHA256_H_ */
