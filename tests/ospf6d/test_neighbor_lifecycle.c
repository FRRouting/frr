// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * A neighbor must not leave events behind that carry its own address.
 *
 * seqnumber_mismatch() and bad_lsreq() are queued by ospf6_message.c with the
 * neighbor as the event argument; the neighbor keeps a handle for each of them
 * (thread_seqnumber_mismatch, thread_bad_lsreq), so ospf6_neighbor_delete()
 * cancels both before the memory goes away, without touching events of other
 * neighbors or events that carry the interface pointer.
 *
 * The test queues the real handlers, deletes the neighbor the way
 * ospf6_neighbor_remove() does and runs the event loop.  The event loop counts
 * how many events are dispatched with the deleted neighbor as argument before
 * running them; without the fix those callbacks run on freed memory.
 *
 * NEIGHBOR_TEST_HANDLER=bad_lsreq|seqnumber_mismatch|both selects which
 * handlers are queued (default: both).
 */

#include <zebra.h>

#include "memory.h"
#include "frrevent.h"
#include "libospf.h"
#include "ospf6d/ospf6_proto.h"
#include "ospf6d/ospf6_lsa.h"
#include "ospf6d/ospf6_lsdb.h"
#include "ospf6d/ospf6_interface.h"
#include "ospf6d/ospf6_top.h"
#include "ospf6d/ospf6_neighbor.h"
#include "ospf6d/ospf6d.h"

#define TEST_PENDING	"neighbor: pending events cancelled on delete"
#define TEST_OTHER	"neighbor: other neighbor's events survive"
#define TEST_IFACE	"neighbor: interface events survive"

struct event_loop *master;
struct zebra_privs_t ospf6d_privs;

static int dispatched_pending;
static int dispatched_other;
static int dispatched_iface;
/* Keeps the control callbacks' reads alive. */
static unsigned int seen;

static void other_cb(struct event *event)
{
	struct ospf6_neighbor *on = EVENT_ARG(event);

	seen += on->state;
	dispatched_other++;
}

static void iface_cb(struct event *event)
{
	struct ospf6_interface *oi = EVENT_ARG(event);

	seen += oi->interface ? 1 : 0;
	dispatched_iface++;
}

/* The real constructor, so the neighbor owns the memory types and lsdb lists
 * that ospf6_neighbor_delete() expects to free.
 */
static struct ospf6_neighbor *neighbor_new(struct ospf6_interface *oi)
{
	struct ospf6_neighbor *on = ospf6_neighbor_create(htonl(0x02020202), oi);

	on->state = OSPF6_NEIGHBOR_FULL;
	return on;
}

static void failed(const char *test, const char *why)
{
	printf("%s\n%s\nfailed!\n", test, why);
	exit(1);
}

/* Count events that were queued for the deleted neighbor, then run them. */
static void run_loop(struct ospf6_neighbor *gone)
{
	struct event event;

	while (event_fetch(master, &event)) {
		if (event.arg == gone && (event.func == seqnumber_mismatch ||
					  event.func == bad_lsreq))
			dispatched_pending++;
		event_call(&event);
	}
}

int main(void)
{
	struct ospf6_interface *oi;
	struct ospf6_neighbor *on, *other;
	const char *which = getenv("NEIGHBOR_TEST_HANDLER");
	bool want_bad, want_seq;

	if (which == NULL || !strcmp(which, "both")) {
		want_bad = want_seq = true;
	} else if (!strcmp(which, "bad_lsreq")) {
		want_bad = true;
		want_seq = false;
	} else if (!strcmp(which, "seqnumber_mismatch")) {
		want_bad = false;
		want_seq = true;
	} else {
		printf("unknown NEIGHBOR_TEST_HANDLER=%s\n", which);
		return 2;
	}

	master = event_master_create(NULL);

	oi = XCALLOC(MTYPE_TMP, sizeof(*oi));
	oi->neighbor_list = list_new();
	oi->interface = XCALLOC(MTYPE_TMP, sizeof(struct interface));

	on = neighbor_new(oi);
	other = neighbor_new(oi);

	/* The two handlers, queued exactly like ospf6_message.c does it. */
	if (want_seq)
		event_add_event(master, seqnumber_mismatch, on, 0,
				&on->thread_seqnumber_mismatch);
	if (want_bad)
		event_add_event(master, bad_lsreq, on, 0,
				&on->thread_bad_lsreq);
	/* Controls: another neighbor, and the interface itself. */
	event_add_event(master, other_cb, other, 0, NULL);
	event_add_event(master, iface_cb, oi, 0, NULL);

	/* ospf6_neighbor_remove(): unlink first, then free. */
	listnode_delete(oi->neighbor_list, on);
	ospf6_neighbor_delete(on);

	run_loop(on);

	printf("queued: %s%s%s dispatched=%d other=%d iface=%d\n",
	       want_seq ? "seqnumber_mismatch" : "", want_seq && want_bad ? "+" : "",
	       want_bad ? "bad_lsreq" : "", dispatched_pending, dispatched_other,
	       dispatched_iface);

	if (dispatched_pending)
		failed(TEST_PENDING,
		       dispatched_pending == 1
			       ? "handler ran with the deleted neighbor as argument"
			       : "handlers ran with the deleted neighbor as argument");
	printf("%s\nOK\n", TEST_PENDING);

	if (dispatched_other != 1)
		failed(TEST_OTHER, "event of another neighbor was cancelled");
	printf("%s\nOK\n", TEST_OTHER);

	if (dispatched_iface != 1)
		failed(TEST_IFACE, "event with the interface was cancelled");
	printf("%s\nOK\n", TEST_IFACE);

	ospf6_neighbor_delete(other);
	list_delete(&oi->neighbor_list);
	XFREE(MTYPE_TMP, oi->interface);
	XFREE(MTYPE_TMP, oi);
	event_master_free(master);
	return 0;
}
