// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef _FRR_CHECKSUM_H
#define _FRR_CHECKSUM_H

#include <stdint.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif


/* IPv4 pseudoheader */
struct ipv4_ph {
	struct in_addr src;
	struct in_addr dst;
	uint8_t rsvd;
	uint8_t proto;
	uint16_t len;
} __attribute__((packed));

/* IPv6 pseudoheader */
struct ipv6_ph {
	struct in6_addr src;
	struct in6_addr dst;
	uint32_t ulpl;
	uint8_t zero[3];
	uint8_t next_hdr;
} __attribute__((packed));


extern uint16_t in_cksumv(const struct iovec *iov, size_t iov_len);

static inline uint16_t in_cksum(const void *data, size_t nbytes)
{
	struct iovec iov[1];

	iov[0].iov_base = (void *)data;
	iov[0].iov_len = nbytes;
	return in_cksumv(iov, array_size(iov));
}

static inline uint16_t in_cksum_with_ph4(const struct ipv4_ph *ph,
					 const void *data, size_t nbytes)
{
	struct iovec iov[2];

	iov[0].iov_base = (void *)ph;
	iov[0].iov_len = sizeof(*ph);
	iov[1].iov_base = (void *)data;
	iov[1].iov_len = nbytes;
	return in_cksumv(iov, array_size(iov));
}

static inline uint16_t in_cksum_with_ph6(const struct ipv6_ph *ph,
					 const void *data, size_t nbytes)
{
	struct iovec iov[2];

	iov[0].iov_base = (void *)ph;
	iov[0].iov_len = sizeof(*ph);
	iov[1].iov_base = (void *)data;
	iov[1].iov_len = nbytes;
	return in_cksumv(iov, array_size(iov));
}

#define FLETCHER_CHECKSUM_VALIDATE 0xffff
extern uint16_t fletcher_checksum(uint8_t *, const size_t len,
				  const uint16_t offset);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_CHECKSUM_H */
