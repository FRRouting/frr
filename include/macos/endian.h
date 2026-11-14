// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * <endian.h> for macOS
 * Copyright (C) 2026 Donald Sharp
 *
 * Linux, glibc and the BSDs provide <endian.h> (or <sys/endian.h>) with
 * BYTE_ORDER and the htobe64()/be64toh() family.  macOS has neither an
 * <endian.h> nor, depending on the SDK, the 16/32/64-bit conversion functions:
 *
 * - <machine/endian.h> provides BYTE_ORDER, LITTLE_ENDIAN and BIG_ENDIAN
 * - <libkern/OSByteOrder.h> provides the byte swapping primitives
 * - <sys/endian.h> (recent SDKs only) provides htobe16() and friends
 *
 * This file glues those together so that FRR can keep saying
 * "#include <endian.h>".  configure adds include/macos to the include path on
 * macOS (and only there), which makes this file get picked up.
 */

#ifndef _FRR_MACOS_ENDIAN_H
#define _FRR_MACOS_ENDIAN_H

#include <sys/types.h>
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>

/*
 * Quoted form on purpose.  <sys/endian.h> is the system header, but
 * checkpatch rejects the angle brackets inside __has_include().  The
 * quoted spelling still searches the system include path.
 */
#if defined(__has_include) && __has_include("sys/endian.h")
#include <sys/endian.h>
#endif

/* <machine/endian.h> hides these under strict POSIX feature test macros */
#ifndef BYTE_ORDER
#define LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#define BIG_ENDIAN    __ORDER_BIG_ENDIAN__
#define BYTE_ORDER    __BYTE_ORDER__
#endif

#ifndef htobe16
#define htobe16(x) OSSwapHostToBigInt16(x)
#endif
#ifndef htole16
#define htole16(x) OSSwapHostToLittleInt16(x)
#endif
#ifndef be16toh
#define be16toh(x) OSSwapBigToHostInt16(x)
#endif
#ifndef le16toh
#define le16toh(x) OSSwapLittleToHostInt16(x)
#endif

#ifndef htobe32
#define htobe32(x) OSSwapHostToBigInt32(x)
#endif
#ifndef htole32
#define htole32(x) OSSwapHostToLittleInt32(x)
#endif
#ifndef be32toh
#define be32toh(x) OSSwapBigToHostInt32(x)
#endif
#ifndef le32toh
#define le32toh(x) OSSwapLittleToHostInt32(x)
#endif

#ifndef htobe64
#define htobe64(x) OSSwapHostToBigInt64(x)
#endif
#ifndef htole64
#define htole64(x) OSSwapHostToLittleInt64(x)
#endif
#ifndef be64toh
#define be64toh(x) OSSwapBigToHostInt64(x)
#endif
#ifndef le64toh
#define le64toh(x) OSSwapLittleToHostInt64(x)
#endif

#endif /* _FRR_MACOS_ENDIAN_H */
