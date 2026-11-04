// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MLD query encoding tests.
 *
 * MLD queries have different lengths: MLDv1 queries are shorter than the
 * MLDv2 query header and MLDv2 queries with sources are longer.  These
 * tests send each kind with gm_send_query(), capture it before it reaches
 * the kernel (which would fix the checksum) and verify the ICMPv6
 * checksum against a pseudo-header carrying the real packet length and
 * source address.
 */
#include <zebra.h>

#include "pimd/pim6_mld.c"

/* pimd globals not linked into this test */
static struct pim_router test_router;
struct pim_router *router = &test_router;
struct zebra_privs_t pimd_privs;

/* Stubs for pimd functions pim6_mld.c references */
void json_object_pim_ifp_add(struct json_object *json, struct interface *ifp)
{
}

struct channel_oil *pim_channel_oil_del(struct channel_oil *c_oil, const char *name)
{
	return NULL;
}

void pim_embedded_rp_new(struct pim_instance *pim, const pim_addr *group, const pim_addr *rp)
{
}

void pim_embedded_rp_delete(struct pim_instance *pim, const pim_addr *group)
{
}

bool pim_embedded_rp_is_embedded(const pim_addr *group)
{
	return false;
}

bool pim_embedded_rp_filter_match(const struct pim_instance *pim, const pim_addr *group)
{
	return false;
}

bool pim_embedded_rp_extract(const pim_addr *group, pim_addr *rp)
{
	return false;
}

bool pim_filter_match(const struct pim_filter_ref *ref, const struct prefix_sg *sg,
		      struct interface *interface, struct interface *source_interface)
{
	return true;
}

bool tib_sg_gm_join(struct pim_instance *pim, pim_sgaddr sg, struct interface *oif,
		    struct channel_oil **oilp)
{
	return true;
}

void tib_sg_gm_prune(struct pim_instance *pim, pim_sgaddr sg, struct interface *oif,
		     struct channel_oil **oilp)
{
}

#define TEST_SOCKET 1000

/* Last query captured by sendmsg() */
static uint8_t sent_pkt[1024];
static size_t sent_len;
static struct in6_addr sent_src, sent_dst;

ssize_t sendmsg(int fd, const struct msghdr *mh, int flags)
{
	const struct sockaddr_in6 *dst = mh->msg_name;
	struct cmsghdr *cmh;
	size_t i;

	assert(fd == TEST_SOCKET);

	sent_len = 0;
	for (i = 0; i < mh->msg_iovlen; i++) {
		assert(sent_len + mh->msg_iov[i].iov_len <= sizeof(sent_pkt));
		memcpy(sent_pkt + sent_len, mh->msg_iov[i].iov_base, mh->msg_iov[i].iov_len);
		sent_len += mh->msg_iov[i].iov_len;
	}

	sent_dst = dst->sin6_addr;
	memset(&sent_src, 0, sizeof(sent_src));
	for (cmh = CMSG_FIRSTHDR(mh); cmh; cmh = CMSG_NXTHDR((struct msghdr *)mh, cmh)) {
		if (cmh->cmsg_level == IPPROTO_IPV6 && cmh->cmsg_type == IPV6_PKTINFO)
			sent_src = ((struct in6_pktinfo *)CMSG_DATA(cmh))->ipi6_addr;
	}

	return sent_len;
}

static struct vrf test_vrf = { .name = "default" };
static struct interface test_ifp = {
	.name = "eth0",
	.ifindex = 2,
};
static struct pim_interface test_pim_ifp;
static struct pim_instance test_pim;
static struct gm_if test_gm_ifp;

static int failures;

static pim_addr addr(const char *str)
{
	pim_addr a;

	assert(inet_pton(PIM_AF, str, &a) == 1);
	return a;
}

static void run_case(const char *name, enum gm_version version, const char *grp,
		     const char *const *srcs, size_t n_srcs, size_t expected_len)
{
	struct icmp6_plain_hdr *hdr = (struct icmp6_plain_hdr *)sent_pkt;
	pim_addr src_addrs[8];
	struct ipv6_ph ph6 = {
		.next_hdr = IPPROTO_ICMPV6,
	};
	int before = failures;
	uint16_t cksum;
	size_t i;

	assert(n_srcs <= array_size(src_addrs));
	for (i = 0; i < n_srcs; i++)
		src_addrs[i] = addr(srcs[i]);

	test_gm_ifp.cur_version = version;
	sent_len = 0;
	gm_send_query(&test_gm_ifp, addr(grp), src_addrs, n_srcs, false);

	if (sent_len != expected_len) {
		printf("%s: sent %zu bytes, expected %zu\n", name, sent_len, expected_len);
		failures++;
	}

	if (sent_len >= sizeof(*hdr) && hdr->icmp6_type != ICMP6_MLD_QUERY) {
		printf("%s: sent ICMPv6 type %u, expected %u\n", name, hdr->icmp6_type,
		       ICMP6_MLD_QUERY);
		failures++;
	}

	/* A correct checksum makes the sum over the whole packet zero */
	ph6.src = sent_src;
	ph6.dst = sent_dst;
	ph6.ulpl = htonl(sent_len);
	cksum = in_cksum_with_ph6(&ph6, sent_pkt, sent_len);
	if (cksum != 0) {
		printf("%s: bad checksum 0x%04x (residue 0x%04x)\n", name, ntohs(hdr->icmp6_cksum),
		       cksum);
		failures++;
	}

	printf("%s %s\n", name, failures == before ? "OK" : "failed");
}

int main(int argc, char **argv)
{
	static const char *const srcs[] = { "2001:db8::1", "2001:db8::2", "2001:db8::3" };

	zprivs_preinit(&pimd_privs);

	test_ifp.vrf = &test_vrf;
	test_ifp.info = &test_pim_ifp;
	test_pim_ifp.ll_lowest = addr("fe80::1");
	test_pim.gm_socket = TEST_SOCKET;

	test_gm_ifp.ifp = &test_ifp;
	test_gm_ifp.pim = &test_pim;
	test_gm_ifp.cur_ll_lowest = test_pim_ifp.ll_lowest;
	test_gm_ifp.cur_qrv = 2;
	test_gm_ifp.cur_query_intv = 125000;
	test_gm_ifp.cur_max_resp = 10000;

	run_case("mldv1_general_query", GM_MLDV1, "::", NULL, 0,
		 sizeof(struct icmp6_plain_hdr) + sizeof(struct mld_v1_pkt));
	run_case("mldv1_group_query", GM_MLDV1, "ff05::100", NULL, 0,
		 sizeof(struct icmp6_plain_hdr) + sizeof(struct mld_v1_pkt));
	run_case("mldv2_general_query", GM_MLDV2, "::", NULL, 0,
		 sizeof(struct icmp6_plain_hdr) + sizeof(struct mld_v2_query_hdr));
	run_case("mldv2_group_query", GM_MLDV2, "ff05::100", NULL, 0,
		 sizeof(struct icmp6_plain_hdr) + sizeof(struct mld_v2_query_hdr));
	run_case("mldv2_group_source_query", GM_MLDV2, "ff35::100", srcs, array_size(srcs),
		 sizeof(struct icmp6_plain_hdr) + sizeof(struct mld_v2_query_hdr) +
			 array_size(srcs) * sizeof(pim_addr));

	/* The querier address (sent with IPV6_PKTINFO) isn't updated yet */
	test_pim_ifp.ll_lowest = addr("fe80::2");
	run_case("mldv2_query_querier_source", GM_MLDV2, "::", NULL, 0,
		 sizeof(struct icmp6_plain_hdr) + sizeof(struct mld_v2_query_hdr));

	return failures ? 1 : 0;
}
