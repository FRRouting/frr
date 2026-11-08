// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM-DM State Refresh prune indicator.
 *
 * RFC 3973 4.7.10: a State Refresh sent on an interface whose (S,G) state
 * is Pruned carries the Prune Indicator (P) bit, whether originated (4.5.2)
 * or forwarded. 4.5.1: a router that forwards a State Refresh onto such an
 * interface sets P and resets the Prune Timer to the prune holdtime. The
 * interface's pruned state lives in bit 23 of the ifchannel flags
 * (PIM_UPSTREAM_DM_FLAG_MASK_PRUNE).
 *
 * The rows run pim_send_staterefresh() (originate) or
 * pim_staterefresh_recv() (forward) for an upstream interface and one
 * dense-mode downstream interface with one neighbor. pim_msg_send() is
 * stubbed to capture what would go on the wire, and the P bit is read from
 * the trailing State Refresh header. Forward rows start with the downstream
 * Prune Timer about to expire, so a restart moves its deadline out to the
 * prune holdtime.
 *
 * Each case runs in a child process so that a sanitizer abort fails only
 * that case.
 *
 * Copyright (C) 2026 Dave Seddon
 */
#include <zebra.h>

#include <sys/wait.h>

#include "printfrr.h"

#include "pimd/pim_state_refresh.c"

/* pimd globals not linked into this test */
static struct pim_router test_router;
struct pim_router *router = &test_router;
const pim_addr qpim_all_pim_routers_addr;

/* Test topology, set up in main() */
static struct pim_instance test_pim;
static struct pim_upstream test_up;
static struct channel_oil test_oil;
static struct interface *up_ifp, *down_ifp;
static struct pim_ifchannel *test_ch; /* NULL: no (S,G) state downstream */
static bool test_lost_assert;

/* Messages "sent" on the downstream interface */
static int sent_count;
static uint8_t sent_msg[1000];
static int sent_size;

/* Stubs for pimd functions pim_state_refresh.c references */
struct pim_upstream *pim_upstream_find(struct pim_instance *pim, pim_sgaddr *sg)
{
	return &test_up;
}

void pim_ifchannel_find(struct interface *ifp, pim_sgaddr *sg, struct pim_ifchannel **ch,
			struct pim_ifchannel **chrpt)
{
	*ch = ifp == down_ifp ? test_ch : NULL;
	*chrpt = NULL;
}

int pim_macro_ch_lost_assert(const struct pim_ifchannel *ch)
{
	return test_lost_assert;
}

bool pim_is_group_filtered(struct pim_interface *pim_ifp, pim_addr *grp, pim_addr *src)
{
	return false;
}

struct interface *pim_if_find_by_vif_index(struct pim_instance *pim, ifindex_t vif_index)
{
	return up_ifp;
}

void pim_dm_prune_iff_on_timer(struct event *t)
{
}

int pim_msg_send(int fd, pim_addr src, pim_addr dst, uint8_t *pim_msg, int pim_msg_size,
		 struct interface *ifp)
{
	assert(ifp == down_ifp);
	assert(pim_msg_size > 0 && (size_t)pim_msg_size <= sizeof(sent_msg));
	memcpy(sent_msg, pim_msg, pim_msg_size);
	sent_size = pim_msg_size;
	sent_count++;
	return 0;
}

/* Test table */
enum kind { POSITIVE, NEGATIVE, BOUNDARY, CORNER };
static const char *const kind2str[] = { "positive", "negative", "boundary", "corner" };

enum path {
	SEND, /* pim_send_staterefresh(): originate */
	RECV, /* pim_staterefresh_recv(): forward */
};

/* Child exit codes, distinct from the sanitizers' error exit code (1). */
#define EXIT_MATCH    10
#define EXIT_MISMATCH 11

#define PRUNED PIM_UPSTREAM_DM_FLAG_MASK_PRUNE
#define NO_CH  0xffffffffU /* no (S,G) ifchannel on the downstream interface */

#define PRUNE_HOLDTIME 210 /* seconds */
#define NEAR_EXPIRY    1   /* seconds left on the Prune Timer before a forward */

struct tcase {
	const char *description;
	enum kind kind;
	enum path path;
	uint32_t ch_flags; /* downstream ifchannel flags, or NO_CH */
	bool lost_assert;  /* downstream ifchannel lost the assert */
	uint8_t ttl;	   /* RECV: TTL of the received State Refresh */
	/* expected */
	bool sent;  /* a State Refresh went out downstream */
	bool p;	    /* its Prune Indicator */
	bool timer; /* RECV: Prune Timer reset to the prune holdtime */
};

static const struct tcase tcases[] = {
	{ "originate: pruned interface sets P", POSITIVE, SEND, PRUNED | 0x5, false, 0, true, true,
	  false },
	{ "originate: forwarding interface clears P", NEGATIVE, SEND, 0x5, false, 0, true, false,
	  false },
	{ "originate: no (S,G) state clears P", NEGATIVE, SEND, NO_CH, false, 0, true, false,
	  false },
	{ "originate: prune flag alone sets P", BOUNDARY, SEND, PRUNED, false, 0, true, true,
	  false },
	{ "originate: every flag but prune clears P", CORNER, SEND, ~PRUNED, false, 0, true, false,
	  false },
	{ "forward: pruned interface sets P and restarts the prune timer", POSITIVE, RECV,
	  PRUNED | 0x5, false, 64, true, true, true },
	{ "forward: forwarding interface clears P, prune timer untouched", NEGATIVE, RECV, 0x5,
	  false, 64, true, false, false },
	{ "forward: no (S,G) state clears P", NEGATIVE, RECV, NO_CH, false, 64, true, false,
	  false },
	{ "forward: TTL 2 is forwarded with the prune state", BOUNDARY, RECV, PRUNED, false, 2,
	  true, true, true },
	{ "forward: TTL 1 is not forwarded", BOUNDARY, RECV, PRUNED, false, 1, false, false,
	  false },
	{ "forward: interface that lost the assert is skipped", CORNER, RECV, PRUNED, true, 64,
	  false, false, false },
};

static int run_case(const struct tcase *tc)
{
	struct pim_ifchannel ch = {};
	struct pim_staterefresh_header *hdr;
	unsigned long remain = 0; /* RECV: msec left on the downstream Prune Timer */
	bool timer = false;
	int rc = EXIT_MATCH;

	if (tc->ch_flags != NO_CH) {
		ch.flags = tc->ch_flags;
		ch.prune_holdtime = PRUNE_HOLDTIME;
		test_ch = &ch;
	}
	if (tc->path == RECV && test_ch)
		/* A Prune Timer about to expire, as set by an earlier refresh */
		event_add_timer(router->master, pim_dm_prune_iff_on_timer, test_ch, NEAR_EXPIRY,
				&test_ch->t_ifjoin_expiry_timer);
	test_lost_assert = tc->lost_assert;

	if (tc->path == SEND) {
		pim_send_staterefresh(&test_up);
	} else {
		/* The State Refresh as the upstream neighbor sends it */
		struct pim_interface *pim_up = up_ifp->info;
		uint8_t msg[1000];
		int len;

		len = pim_staterefresh_build_msg(msg, sizeof(msg), up_ifp, test_up.sg.grp,
						 test_up.sg.src, pim_up->primary_address, 0, 0, 0,
						 IPV4_MAX_BITLEN, tc->ttl, false, false, true, 0,
						 60);
		pim_staterefresh_recv(up_ifp, pim_up->primary_address, msg + PIM_MSG_HEADER_LEN,
				      len - PIM_MSG_HEADER_LEN);
		/* Restarted: the deadline moved out to the prune holdtime */
		if (test_ch && test_ch->t_ifjoin_expiry_timer)
			remain = event_timer_remain_msec(test_ch->t_ifjoin_expiry_timer);
		timer = remain > (PRUNE_HOLDTIME - NEAR_EXPIRY) * 1000UL;
	}

	if (sent_count) {
		/* The State Refresh header is the last 4 bytes */
		hdr = (struct pim_staterefresh_header *)(sent_msg + sent_size - sizeof(*hdr));
		printf("    sent %d, P %u", sent_count, hdr->p);
		if (!tc->sent || hdr->p != tc->p)
			rc = EXIT_MISMATCH;
	} else {
		printf("    not sent");
		if (tc->sent)
			rc = EXIT_MISMATCH;
	}
	if (tc->path == RECV)
		printf(", prune timer %lums left", remain);
	printf("\n");
	if (timer != tc->timer)
		rc = EXIT_MISMATCH;

	return rc;
}

static struct interface *test_if(const char *name, ifindex_t ifindex, const char *addr)
{
	struct interface *ifp = if_get_by_name(name, VRF_DEFAULT, VRF_DEFAULT_NAME);
	struct pim_interface *pim_ifp = XCALLOC(MTYPE_TMP, sizeof(*pim_ifp));
	struct pim_neighbor *neigh = XCALLOC(MTYPE_TMP, sizeof(*neigh));

	if_set_index(ifp, ifindex);
	pim_ifp->pim = &test_pim;
	pim_ifp->pim_enable = true;
	pim_ifp->pim_mode = PIM_MODE_DENSE;
	inet_pton(AF_INET, addr, &pim_ifp->primary_address);
	pim_ifp->pim_neighbor_list = list_new();
	inet_pton(AF_INET, addr, &neigh->source_addr);
	listnode_add(pim_ifp->pim_neighbor_list, neigh);
	ifp->info = pim_ifp;
	return ifp;
}

int main(int argc, char **argv)
{
	int failures = 0;

	router->master = event_master_create(NULL);
	vrf_init(NULL, NULL, NULL, NULL);

	up_ifp = test_if("up0", 1, "10.0.1.1");
	down_ifp = test_if("down0", 2, "10.0.2.1");

	test_pim.staterefresh_time = 60;
	test_up.pim = &test_pim;
	inet_pton(AF_INET, "232.1.1.1", &test_up.sg.grp);
	inet_pton(AF_INET, "10.0.0.1", &test_up.sg.src);
	test_up.channel_oil = &test_oil;
	test_oil.iif.index = 1;
	test_up.rpf.source_nexthop.interface = up_ifp;

	printf("PIM-DM State Refresh prune indicator tests\n\n");

	for (size_t i = 0; i < array_size(tcases); i++) {
		const struct tcase *tc = &tcases[i];
		char why[96] = "";
		int status;
		pid_t pid;

		fflush(stdout);
		pid = fork();
		if (pid == 0) {
			int rc = run_case(tc);

			fflush(stdout);
			_exit(rc);
		}

		waitpid(pid, &status, 0);
		if (WIFSIGNALED(status))
			snprintfrr(why, sizeof(why), " (crashed: signal %d)", WTERMSIG(status));
		else if (WEXITSTATUS(status) == EXIT_MISMATCH)
			snprintfrr(why, sizeof(why), " (expected %s%s%s)",
				   tc->sent ? "sent" : "not sent",
				   tc->sent ? (tc->p ? " with P" : " without P") : "",
				   tc->path == RECV
					   ? (tc->timer ? ", prune timer" : ", no prune timer")
					   : "");
		else if (WEXITSTATUS(status) != EXIT_MATCH)
			snprintfrr(why, sizeof(why), " (abnormal exit %d)", WEXITSTATUS(status));

		printf("[%-8s] %s ... %s%s\n", kind2str[tc->kind], tc->description,
		       why[0] ? "failed" : "OK", why);
		if (why[0])
			failures++;
	}

	printf("\n%d of %zu cases failed\n", failures, array_size(tcases));
	return failures ? 1 : 0;
}
