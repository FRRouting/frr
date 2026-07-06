// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SRv6 per-SID tx/rx statistics DB. See zebra_srv6_sid_stats.h.
 */
#include <zebra.h>

#ifdef GNU_LINUX /* SRv6 L2 EVPN uses the Linux netlink/seg6 dataplane */

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/lwtunnel.h>
#include <linux/seg6_local.h>
#include <net/if.h>
#include <errno.h>
#include <poll.h>

#include "vlan.h"
#include "lib/monotime.h"
#include "lib/memory.h"
#include "lib/hash.h"
#include "lib/jhash.h"
#include "lib/linklist.h"
#include "lib/log.h"

#include "zebra/zebra_router.h"
#include "zebra/zebra_srl2.h"
#include "zebra/zebra_srv6_sid_stats.h"
#include "zebra/zebra_srv6_vpws.h"
#include "zebra/rib.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZSRV6_SID_STAT, "SRv6 SID statistics entry");

#ifndef NLA_TYPE_MASK
#define NLA_TYPE_MASK (~(NLA_F_NESTED | NLA_F_NET_BYTEORDER))
#endif

#define SRV6_SID_STATS_NL_BUDGET_MS 500

static int nl_sock = -1;
static uint32_t nl_seq;

/* ---- hash helpers ------------------------------------------------------- */
static int sid_stat_htab_cmp(const struct zebra_srv6_sid_stat *a,
			     const struct zebra_srv6_sid_stat *b)
{
	return memcmp(&a->sid, &b->sid, sizeof(a->sid));
}

static uint32_t sid_stat_htab_hash(const struct zebra_srv6_sid_stat *e)
{
	return jhash(&e->sid, sizeof(e->sid), 0);
}

DECLARE_HASH(sid_stat_htab, struct zebra_srv6_sid_stat, htab_item, sid_stat_htab_cmp,
	     sid_stat_htab_hash);

static struct sid_stat_htab_head stats_table[1];
static bool stats_inited;

static struct zebra_srv6_sid_stat *sid_stat_get(const struct in6_addr *sid)
{
	struct zebra_srv6_sid_stat key = {}, *e;

	key.sid = *sid;
	e = sid_stat_htab_find(stats_table, &key);
	if (e)
		return e;

	e = XCALLOC(MTYPE_ZSRV6_SID_STAT, sizeof(*e));
	e->sid = *sid;
	sid_stat_htab_add(stats_table, e);
	return e;
}

/* ---- rtattr parsing ----------------------------------------------------- */
static void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		int type = rta->rta_type & NLA_TYPE_MASK;

		if (type <= max)
			tb[type] = rta;
		rta = RTA_NEXT(rta, len);
	}
}

static uint16_t rta_get_u16(const struct rtattr *rta)
{
	uint16_t v = 0;

	memcpy(&v, RTA_DATA(rta), sizeof(v));
	return v;
}

static uint32_t rta_get_u32(const struct rtattr *rta)
{
	uint32_t v = 0;

	memcpy(&v, RTA_DATA(rta), sizeof(v));
	return v;
}

static uint64_t rta_get_u64(const struct rtattr *rta)
{
	uint64_t v = 0;

	memcpy(&v, RTA_DATA(rta), sizeof(v));
	return v;
}

static int srv6_sid_stats_nl_socket(void)
{
	struct sockaddr_nl sa = { .nl_family = AF_NETLINK };

	if (nl_sock >= 0)
		return nl_sock;

	nl_sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
	if (nl_sock < 0) {
		zlog_warn("%s: netlink socket: %s", __func__, safe_strerror(errno));
		return -1;
	}
	if (bind(nl_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		zlog_warn("%s: netlink bind: %s", __func__, safe_strerror(errno));
		close(nl_sock);
		nl_sock = -1;
		return -1;
	}
	return nl_sock;
}

/* ---- rx: poll SEG6_LOCAL_COUNTERS via an RTM_GETROUTE dump -------------- */
static void srv6_sid_stats_poll_rx(void)
{
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
	} req = {};
	char buf[16384];
	struct timeval start;
	uint32_t seq;
	bool done = false;
	int fd;

	fd = srv6_sid_stats_nl_socket();
	if (fd < 0)
		return;

	/* drop any leftovers from a previous (timed-out) dump */
	while (recv(fd, buf, sizeof(buf), MSG_DONTWAIT) > 0)
		;

	seq = ++nl_seq;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_type = RTM_GETROUTE;
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.n.nlmsg_seq = seq;
	req.r.rtm_family = AF_INET6;

	if (send(fd, &req, req.n.nlmsg_len, 0) < 0)
		return;

	monotime(&start);

	while (!done) {
		ssize_t n = recv(fd, buf, sizeof(buf), 0);
		struct nlmsghdr *h;

		if (n < 0) {
			struct pollfd pfd = { .fd = fd, .events = POLLIN };
			int64_t elapsed_ms;
			int wait_ms;

			if (errno == EINTR)
				continue;
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				break;

			/* nothing ready: wait, but never exceed the budget */
			elapsed_ms = monotime_since(&start, NULL) / 1000;
			wait_ms = SRV6_SID_STATS_NL_BUDGET_MS - (int)elapsed_ms;
			if (wait_ms <= 0 || poll(&pfd, 1, wait_ms) <= 0)
				break;
			continue;
		}

		for (h = (struct nlmsghdr *)buf; NLMSG_OK(h, (unsigned int)n);
		     h = NLMSG_NEXT(h, n)) {
			struct rtattr *tb[RTA_MAX + 1];
			struct rtattr *s6[SEG6_LOCAL_MAX + 1];
			struct rtattr *cnt[SEG6_LOCAL_CNT_MAX + 1];
			struct zebra_srv6_sid_stat *e;
			struct in6_addr sid;
			struct rtmsg *rtm;

			if (h->nlmsg_seq != seq)
				continue; /* stale from a prior dump */
			if (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR) {
				done = true;
				break;
			}
			if (h->nlmsg_type != RTM_NEWROUTE)
				continue;

			rtm = NLMSG_DATA(h);
			if (rtm->rtm_family != AF_INET6)
				continue;

			parse_rtattr(tb, RTA_MAX, RTM_RTA(rtm), RTM_PAYLOAD(h));
			if (!tb[RTA_DST] || !tb[RTA_ENCAP] || !tb[RTA_ENCAP_TYPE])
				continue;
			if (rta_get_u16(tb[RTA_ENCAP_TYPE]) != LWTUNNEL_ENCAP_SEG6_LOCAL)
				continue;

			parse_rtattr(s6, SEG6_LOCAL_MAX, RTA_DATA(tb[RTA_ENCAP]),
				     RTA_PAYLOAD(tb[RTA_ENCAP]));
			if (!s6[SEG6_LOCAL_COUNTERS])
				continue; /* counting not enabled on this SID */

			parse_rtattr(cnt, SEG6_LOCAL_CNT_MAX, RTA_DATA(s6[SEG6_LOCAL_COUNTERS]),
				     RTA_PAYLOAD(s6[SEG6_LOCAL_COUNTERS]));

			memcpy(&sid, RTA_DATA(tb[RTA_DST]), sizeof(sid));
			e = sid_stat_get(&sid);
			e->is_local = true;
			e->seen = true;
			if (s6[SEG6_LOCAL_ACTION])
				e->k_action = rta_get_u32(s6[SEG6_LOCAL_ACTION]);
			if (cnt[SEG6_LOCAL_CNT_PACKETS])
				e->rx_pkts = rta_get_u64(cnt[SEG6_LOCAL_CNT_PACKETS]);
			if (cnt[SEG6_LOCAL_CNT_BYTES])
				e->rx_bytes = rta_get_u64(cnt[SEG6_LOCAL_CNT_BYTES]);
		}
	}
}

/* ---- tx: per-srl2 netdev TX stats (the iface that encaps toward a SID) -- */
static uint64_t srv6_sid_stats_read_u64(const char *path)
{
	unsigned long long val = 0;
	FILE *f = fopen(path, "r");

	if (f) {
		if (fscanf(f, "%llu", &val) != 1)
			val = 0;
		fclose(f);
	}
	return val;
}

static void srv6_sid_stats_tx_cb(struct zebra_srl2 *srl2, void *arg)
{
	struct zebra_srv6_sid_stat *e;
	char path[128];

	e = sid_stat_get(&srl2->sid);
	e->is_encap = true;
	e->seen = true;
	e->tx_ifindex = srl2->ifindex;

	snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_packets", srl2->ifname);
	e->tx_pkts = srv6_sid_stats_read_u64(path);

	snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_bytes", srl2->ifname);
	e->tx_bytes = srv6_sid_stats_read_u64(path);
}

static void srv6_sid_stats_vpws_tx_cb(const struct in6_addr *peer_sid, ifindex_t ifindex, void *arg)
{
	struct zebra_srv6_sid_stat *e;
	char ifname[IF_NAMESIZE];
	char path[128];

	if (!if_indextoname(ifindex, ifname))
		return;

	e = sid_stat_get(peer_sid);
	e->is_encap = true;
	e->seen = true;
	e->tx_ifindex = ifindex;

	snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_packets", ifname);
	e->tx_pkts = srv6_sid_stats_read_u64(path);
	snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_bytes", ifname);
	e->tx_bytes = srv6_sid_stats_read_u64(path);
}

/* ---- poll: refresh + prune --------------------------------------------- */
void zebra_srv6_sid_stats_poll(void)
{
	struct zebra_srv6_sid_stat *e;

	if (!stats_inited)
		return;

	frr_each (sid_stat_htab, stats_table, e)
		e->seen = false;

	srv6_sid_stats_poll_rx();
	zebra_srl2_walk(srv6_sid_stats_tx_cb, NULL);
	zebra_srv6_vpws_walk_encap(srv6_sid_stats_vpws_tx_cb, NULL);

	/* Prune entries not refreshed this poll (frr_each_safe permits delete). */
	frr_each_safe (sid_stat_htab, stats_table, e)
		if (!e->seen) {
			sid_stat_htab_del(stats_table, e);
			XFREE(MTYPE_ZSRV6_SID_STAT, e);
		}
}

/* ---- clear (baseline) -------------------------------------------------- */
void zebra_srv6_sid_stats_clear(const struct in6_addr *sid)
{
	struct zebra_srv6_sid_stat *e;

	if (!stats_inited)
		return;

	frr_each (sid_stat_htab, stats_table, e) {
		if (sid && memcmp(&e->sid, sid, sizeof(e->sid)) != 0)
			continue;
		e->rx_pkts_base = e->rx_pkts;
		e->rx_bytes_base = e->rx_bytes;
		e->tx_pkts_base = e->tx_pkts;
		e->tx_bytes_base = e->tx_bytes;
	}
}

/* ---- walk for the CLI -------------------------------------------------- */
void zebra_srv6_sid_stats_walk(void (*cb)(const struct zebra_srv6_sid_stat *srl2, void *arg),
			       void *arg)
{
	struct zebra_srv6_sid_stat *e;

	if (stats_inited)
		frr_each (sid_stat_htab, stats_table, e)
			cb(e, arg);
}

/* ---- init / fini ------------------------------------------------------- */
void zebra_srv6_sid_stats_init(void)
{
	sid_stat_htab_init(stats_table);
	stats_inited = true;
}

void zebra_srv6_sid_stats_fini(void)
{
	struct zebra_srv6_sid_stat *e;

	if (nl_sock >= 0) {
		close(nl_sock);
		nl_sock = -1;
	}
	if (!stats_inited)
		return;

	frr_each_safe (sid_stat_htab, stats_table, e) {
		sid_stat_htab_del(stats_table, e);
		XFREE(MTYPE_ZSRV6_SID_STAT, e);
	}
	sid_stat_htab_fini(stats_table);
	stats_inited = false;
}

#else /* !GNU_LINUX - SRv6 L2 EVPN dataplane is netlink-only; stub out */

#include "zebra/zebra_srv6_sid_stats.h"

void zebra_srv6_sid_stats_init(void)
{
}

void zebra_srv6_sid_stats_fini(void)
{
}

void zebra_srv6_sid_stats_poll(void)
{
}

void zebra_srv6_sid_stats_clear(const struct in6_addr *sid)
{
}

void zebra_srv6_sid_stats_walk(void (*cb)(const struct zebra_srv6_sid_stat *srl2, void *arg),
			       void *arg)
{
}

#endif /* GNU_LINUX */
