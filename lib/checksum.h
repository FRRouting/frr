#include <stdint.h>
#include <netinet/in.h>

extern int in_cksum(void *, int);
#define FLETCHER_CHECKSUM_VALIDATE 0xffff
extern uint16_t fletcher_checksum(uint8_t *, const size_t len,
				  const uint16_t offset);

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
