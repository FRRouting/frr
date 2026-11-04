// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Unit tests for the BFD raw frame builder (bfdd/bfd_frame.c).
 *
 * Copyright (C) 2026 Aviz Networks
 */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <zebra.h>

#include "lib/checksum.h"

#include "bfdd/bfd_frame.h"

#ifdef GNU_LINUX
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#endif

#define ETH_HLEN_ 14
#define IP4_HLEN  20
#define IP6_HLEN  40
#define UDP_HLEN  8

static unsigned int checks;

#define CHECK(expr)                                                                               \
	do {                                                                                      \
		assert(expr);                                                                     \
		checks++;                                                                         \
	} while (0)

static uint16_t get16(const uint8_t *p)
{
	return (uint16_t)(p[0] << 8 | p[1]);
}

static void params_v4(struct bfd_frame_params *fp)
{
	static const uint8_t smac[] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
	static const uint8_t dmac[] = { 0x01, 0x00, 0x5e, 0x90, 0x00, 0x01 };

	memset(fp, 0, sizeof(*fp));
	fp->family = AF_INET;
	memcpy(fp->smac, smac, sizeof(smac));
	memcpy(fp->dmac, dmac, sizeof(dmac));
	inet_pton(AF_INET, "10.0.12.1", &fp->src.v4);
	inet_pton(AF_INET, "10.0.12.2", &fp->dst.v4);
	fp->sport = 49152;
	fp->dport = 6784;
	fp->ttl = 255;
	fp->tos = 0xc0;
	fp->ip_id = 0x1234;
}

static void params_v6(struct bfd_frame_params *fp)
{
	params_v4(fp);
	fp->family = AF_INET6;
	inet_pton(AF_INET6, "2001:db8:10::1", &fp->src.v6);
	inet_pton(AF_INET6, "2001:db8:10::2", &fp->dst.v6);
}

/* Verify a UDP checksum over the IPv4 pseudo header: the sum must fold to 0. */
static bool udp4_cksum_ok(const uint8_t *ip, const uint8_t *udp, size_t udplen)
{
	struct ipv4_ph ph = {};

	memcpy(&ph.src, ip + 12, 4);
	memcpy(&ph.dst, ip + 16, 4);
	ph.proto = IPPROTO_UDP;
	ph.len = htons(udplen);
	return in_cksum_with_ph4(&ph, udp, udplen) == 0;
}

static bool udp6_cksum_ok(const uint8_t *ip, const uint8_t *udp, size_t udplen)
{
	struct ipv6_ph ph = {};

	memcpy(&ph.src, ip + 8, 16);
	memcpy(&ph.dst, ip + 24, 16);
	ph.ulpl = htonl(udplen);
	ph.next_hdr = IPPROTO_UDP;
	return in_cksum_with_ph6(&ph, udp, udplen) == 0;
}

/* TC-1: IPv4 frame layout and checksums. */
static void test_ipv4_layout(void)
{
	struct bfd_frame_params fp;
	uint8_t payload[24], buf[128];
	const uint8_t *ip = buf + ETH_HLEN_, *udp = ip + IP4_HLEN;
	ssize_t len;

	for (size_t i = 0; i < sizeof(payload); i++)
		payload[i] = (uint8_t)(i * 7 + 1);

	params_v4(&fp);
	len = bfd_frame_build(buf, sizeof(buf), &fp, payload, sizeof(payload));
	CHECK(len == ETH_HLEN_ + IP4_HLEN + UDP_HLEN + (ssize_t)sizeof(payload));

	/* Ethernet */
	CHECK(memcmp(buf, fp.dmac, 6) == 0);
	CHECK(memcmp(buf + 6, fp.smac, 6) == 0);
	CHECK(get16(buf + 12) == 0x0800);

	/* IPv4 */
	CHECK(ip[0] == 0x45);
	CHECK(ip[1] == 0xc0);
	CHECK(get16(ip + 2) == IP4_HLEN + UDP_HLEN + sizeof(payload));
	CHECK(get16(ip + 4) == 0x1234);
	CHECK(get16(ip + 6) == 0);
	CHECK(ip[8] == 255);
	CHECK(ip[9] == IPPROTO_UDP);
	CHECK(memcmp(ip + 12, &fp.src.v4, 4) == 0);
	CHECK(memcmp(ip + 16, &fp.dst.v4, 4) == 0);
	CHECK(in_cksum(ip, IP4_HLEN) == 0);

	/* UDP */
	CHECK(get16(udp) == 49152);
	CHECK(get16(udp + 2) == 6784);
	CHECK(get16(udp + 4) == UDP_HLEN + sizeof(payload));
	CHECK(get16(udp + 6) != 0);
	CHECK(udp4_cksum_ok(ip, udp, UDP_HLEN + sizeof(payload)));
	CHECK(memcmp(udp + UDP_HLEN, payload, sizeof(payload)) == 0);
}

/* TC-2: IPv6 frame layout and checksums. */
static void test_ipv6_layout(void)
{
	struct bfd_frame_params fp;
	uint8_t payload[24], buf[128];
	const uint8_t *ip = buf + ETH_HLEN_, *udp = ip + IP6_HLEN;
	ssize_t len;

	memset(payload, 0xa5, sizeof(payload));
	params_v6(&fp);
	len = bfd_frame_build(buf, sizeof(buf), &fp, payload, sizeof(payload));
	CHECK(len == ETH_HLEN_ + IP6_HLEN + UDP_HLEN + (ssize_t)sizeof(payload));

	CHECK(get16(buf + 12) == 0x86dd);

	/* Version 6, traffic class 0xc0 (CS6), flow label 0. */
	CHECK(ip[0] == 0x6c);
	CHECK(ip[1] == 0x00);
	CHECK(ip[2] == 0 && ip[3] == 0);
	CHECK(get16(ip + 4) == UDP_HLEN + sizeof(payload));
	CHECK(ip[6] == IPPROTO_UDP);
	CHECK(ip[7] == 255);
	CHECK(memcmp(ip + 8, &fp.src.v6, 16) == 0);
	CHECK(memcmp(ip + 24, &fp.dst.v6, 16) == 0);

	CHECK(get16(udp) == 49152);
	CHECK(get16(udp + 2) == 6784);
	CHECK(get16(udp + 6) != 0);
	CHECK(udp6_cksum_ok(ip, udp, UDP_HLEN + sizeof(payload)));
}

/* TC-3: traffic class bits are split correctly across the IPv6 header. */
static void test_ipv6_traffic_class(void)
{
	struct bfd_frame_params fp;
	uint8_t buf[128];
	const uint8_t *ip = buf + ETH_HLEN_;

	params_v6(&fp);
	fp.tos = 0xab;
	CHECK(bfd_frame_build(buf, sizeof(buf), &fp, NULL, 0) > 0);
	CHECK(ip[0] == 0x6a);
	CHECK(ip[1] == 0xb0);
}

/* TC-4: argument and size validation. */
static void test_errors(void)
{
	struct bfd_frame_params fp;
	uint8_t payload[24] = {}, buf[128];
	size_t need = ETH_HLEN_ + IP4_HLEN + UDP_HLEN + sizeof(payload);

	params_v4(&fp);
	fp.family = AF_UNSPEC;
	CHECK(bfd_frame_build(buf, sizeof(buf), &fp, payload, sizeof(payload)) == -1);

	params_v4(&fp);
	CHECK(bfd_frame_build(buf, need, &fp, payload, sizeof(payload)) == (ssize_t)need);
	CHECK(bfd_frame_build(buf, need - 1, &fp, payload, sizeof(payload)) == -1);
	CHECK(bfd_frame_build(NULL, need, &fp, payload, sizeof(payload)) == -1);
	CHECK(bfd_frame_build(buf, sizeof(buf), &fp, NULL, sizeof(payload)) == -1);
	CHECK(bfd_frame_build(buf, SIZE_MAX, &fp, payload, UINT16_MAX) == -1);

	params_v6(&fp);
	need = ETH_HLEN_ + IP6_HLEN + UDP_HLEN + sizeof(payload);
	CHECK(bfd_frame_build(buf, need, &fp, payload, sizeof(payload)) == (ssize_t)need);
	CHECK(bfd_frame_build(buf, need - 1, &fp, payload, sizeof(payload)) == -1);
}

/*
 * TC-7: payload size limits. The largest payload that fits in a 65535 byte
 * IP packet is accepted and one byte more is refused. Lengths that would
 * wrap when the headers are added are refused before anything is copied
 * (the buffer is far too small for them).
 */
static void test_payload_limits(void)
{
	static uint8_t big[ETH_HLEN_ + UINT16_MAX];
	static const uint8_t payload[UINT16_MAX];
	struct bfd_frame_params fp;
	uint8_t buf[128];
	size_t max;

	params_v4(&fp);
	max = UINT16_MAX - IP4_HLEN - UDP_HLEN;
	CHECK(bfd_frame_build(big, sizeof(big), &fp, payload, max) ==
	      (ssize_t)(ETH_HLEN_ + UINT16_MAX));
	CHECK(get16(big + ETH_HLEN_ + 2) == UINT16_MAX);
	CHECK(bfd_frame_build(big, sizeof(big), &fp, payload, max + 1) == -1);
	CHECK(bfd_frame_build(buf, sizeof(buf), &fp, payload, SIZE_MAX) == -1);
	CHECK(bfd_frame_build(buf, sizeof(buf), &fp, payload, SIZE_MAX - UDP_HLEN + 1) == -1);

	params_v6(&fp);
	max = UINT16_MAX - IP6_HLEN - UDP_HLEN;
	CHECK(bfd_frame_build(big, sizeof(big), &fp, payload, max) ==
	      (ssize_t)(ETH_HLEN_ + UINT16_MAX));
	CHECK(get16(big + ETH_HLEN_ + 4) == UDP_HLEN + max);
	CHECK(bfd_frame_build(big, sizeof(big), &fp, payload, max + 1) == -1);
	CHECK(bfd_frame_build(buf, sizeof(buf), &fp, payload, SIZE_MAX) == -1);
	CHECK(bfd_frame_build(buf, sizeof(buf), &fp, payload, SIZE_MAX - UDP_HLEN + 1) == -1);
}

/* TC-5: a UDP checksum that computes to zero is sent as 0xffff (RFC 768). */
static void test_zero_checksum(void)
{
	struct bfd_frame_params fp;
	uint8_t buf[128];
	bool found = false;

	params_v4(&fp);
	for (uint32_t v = 0; v <= UINT16_MAX && !found; v++) {
		uint8_t payload[2] = { v >> 8, v & 0xff };
		uint8_t *ip = buf + ETH_HLEN_, *udp = ip + IP4_HLEN;
		struct ipv4_ph ph = {};

		CHECK(bfd_frame_build(buf, sizeof(buf), &fp, payload, sizeof(payload)) > 0);

		/* Raw checksum with the field cleared. */
		udp[6] = udp[7] = 0;
		memcpy(&ph.src, &fp.src.v4, 4);
		memcpy(&ph.dst, &fp.dst.v4, 4);
		ph.proto = IPPROTO_UDP;
		ph.len = htons(UDP_HLEN + sizeof(payload));
		if (in_cksum_with_ph4(&ph, udp, UDP_HLEN + sizeof(payload)) != 0)
			continue;

		CHECK(bfd_frame_build(buf, sizeof(buf), &fp, payload, sizeof(payload)) > 0);
		CHECK(get16(udp + 6) == 0xffff);
		CHECK(udp4_cksum_ok(ip, udp, UDP_HLEN + sizeof(payload)));
		found = true;
	}
	CHECK(found);
}

#ifdef GNU_LINUX
/*
 * TC-6: the builder produces exactly the frame the echo path built by hand
 * before it was converted (reference copied from ptm_bfd_echo_fp_snd()).
 */
static void test_echo_equivalence(void)
{
	struct bfd_frame_params fp;
	/*
	 * Offset the reference frame by 2 bytes so that its IP and UDP headers
	 * are 4-byte aligned for the struct accesses below.
	 */
	uint8_t built[100], refbuf[104] __attribute__((aligned(8))) = {};
	uint8_t *ref = refbuf + 2;
	uint8_t payload[32];
	struct ethhdr *eth = (struct ethhdr *)ref;
	struct iphdr *iph = (struct iphdr *)(ref + sizeof(*eth));
	struct udphdr *uh = (struct udphdr *)(ref + sizeof(*eth) + sizeof(*iph));
	struct ipv4_ph ph = {};
	size_t total;
	ssize_t len;

	for (size_t i = 0; i < sizeof(payload); i++)
		payload[i] = (uint8_t)(0x30 + i);

	params_v4(&fp);
	fp.dst.v4 = fp.src.v4;
	fp.sport = fp.dport = 3785;

	/* Reference frame, built the way the echo path used to. */
	memcpy(eth->h_source, fp.smac, 6);
	memcpy(eth->h_dest, fp.dmac, 6);
	eth->h_proto = htons(ETH_P_IP);
	iph->ihl = sizeof(struct ip) >> 2;
	iph->version = IPVERSION;
	iph->tos = 0xc0;
	iph->id = htons(fp.ip_id);
	iph->ttl = 255;
	iph->protocol = IPPROTO_UDP;
	memcpy(&iph->saddr, &fp.src.v4, 4);
	memcpy(&iph->daddr, &fp.src.v4, 4);
	uh->source = htons(3785);
	uh->dest = htons(3785);
	memcpy(ref + sizeof(*eth) + sizeof(*iph) + sizeof(*uh), payload, sizeof(payload));
	total = sizeof(*eth) + sizeof(*iph) + sizeof(*uh) + sizeof(payload);
	uh->len = htons(sizeof(*uh) + sizeof(payload));
	memcpy(&ph.src, &fp.src.v4, 4);
	memcpy(&ph.dst, &fp.src.v4, 4);
	ph.proto = IPPROTO_UDP;
	ph.len = uh->len;
	uh->check = in_cksum_with_ph4(&ph, uh, sizeof(*uh) + sizeof(payload));
	iph->tot_len = htons(total - sizeof(*eth));
	iph->check = in_cksum(iph, sizeof(*iph));

	len = bfd_frame_build(built, sizeof(built), &fp, payload, sizeof(payload));
	CHECK(len == (ssize_t)total);
	CHECK(memcmp(built, ref, total) == 0);
}
#endif

int main(void)
{
	test_ipv4_layout();
	test_ipv6_layout();
	test_ipv6_traffic_class();
	test_errors();
	test_payload_limits();
	test_zero_checksum();
#ifdef GNU_LINUX
	test_echo_equivalence();
#endif

	assert(checks > 0);
	puts("BFD frame builder checks passed.");

	return 0;
}
