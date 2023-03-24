// SPDX-License-Identifier: GPL-2.0-or-later
/* This file is part of Quagga.
 */

/*
 * Simple program to demonstrate how OSPF API can be used. This
 * application retrieves the LSDB from the OSPF daemon and then
 * originates, updates and finally deletes an application-specific
 * opaque LSA. You can use this application as a template when writing
 * your own application.
 */

/* The following includes are needed in all OSPF API client
   applications. */

#include <zebra.h>
#include "prefix.h" /* needed by ospf_asbr.h */
#include "privs.h"
#include "log.h"
#include "lib/printfrr.h"

/* work around gcc bug 69981, disable MTYPEs in libospf */
#define _QUAGGA_OSPF_MEMORY_H

#include "ospfd/ospfd.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_opaque.h"
#include "ospfd/ospf_api.h"
#include "ospf_apiclient.h"

/* privileges struct.
 * set cap_num_* and uid/gid to nothing to use NULL privs
 * as ospfapiclient links in libospf.a which uses privs.
 */
struct zebra_privs_t ospfd_privs = {.user = NULL,
				    .group = NULL,
				    .cap_num_p = 0,
				    .cap_num_i = 0};

/* The following includes are specific to this application. For
   example it uses threads from libfrr, however your application is
   free to use any thread library (like pthreads). */

#include "ospfd/ospf_dump.h" /* for ospf_lsa_header_dump */
#include "frrevent.h"
#include "log.h"

/* Local portnumber for async channel. Note that OSPF API library will also
   allocate a sync channel at ASYNCPORT+1. */
#define ASYNCPORT 4000

/* Master thread */
struct event_loop *master;

/* Global variables */
struct ospf_apiclient *oclient;
char **args;

/* Our opaque LSAs have the following format. */
struct my_opaque_lsa {
	struct lsa_header hdr; /* include common LSA header */
	uint8_t data[4];       /* our own data format then follows here */
};


/* ---------------------------------------------------------
 * Threads for asynchronous messages and LSA update/delete
 * ---------------------------------------------------------
 */

static void lsa_delete(struct event *t)
{
	struct ospf_apiclient *oclient;
	struct in_addr area_id;
	int rc;

	oclient = EVENT_ARG(t);

	rc = inet_aton(args[6], &area_id);
	if (rc <= 0) {
		printf("Address Specified: %s is invalid\n", args[6]);
		return;
	}

	printf("Deleting LSA... ");
	rc = ospf_apiclient_lsa_delete(oclient, area_id,
				       atoi(args[2]), /* lsa type */
				       atoi(args[3]), /* opaque type */
				       atoi(args[4]), /* opaque ID */
				       0); /* send data in withdrawals */
	printf("done, return code is = %d\n", rc);
}

static void lsa_inject(struct event *t)
{
	struct ospf_apiclient *cl;
	struct in_addr ifaddr;
	struct in_addr area_id;
	uint8_t lsa_type;
	uint8_t opaque_type;
	uint32_t opaque_id;
	void *opaquedata;
	int opaquelen;

	static uint32_t counter = 1; /* Incremented each time invoked */
	int rc;

	cl = EVENT_ARG(t);

	rc = inet_aton(args[5], &ifaddr);
	if (rc <= 0) {
		printf("Ifaddr specified %s is invalid\n", args[5]);
		return;
	}

	rc = inet_aton(args[6], &area_id);
	if (rc <= 0) {
		printf("Area ID specified %s is invalid\n", args[6]);
		return;
	}
	lsa_type = atoi(args[2]);
	opaque_type = atoi(args[3]);
	opaque_id = atoi(args[4]);
	opaquedata = &counter;
	opaquelen = sizeof(uint32_t);

	printf("Originating/updating LSA with counter=%d... ", counter);
	rc = ospf_apiclient_lsa_originate(cl, ifaddr, area_id, lsa_type,
					  opaque_type, opaque_id, opaquedata,
					  opaquelen);

	printf("done, return code is %d\n", rc);

	counter++;
}


/* This thread handles asynchronous messages coming in from the OSPF
   API server */
static void lsa_read(struct event *thread)
{
	struct ospf_apiclient *oclient;
	int fd;
	int ret;

	printf("lsa_read called\n");

	oclient = EVENT_ARG(thread);
	fd = EVENT_FD(thread);

	/* Handle asynchronous message */
	ret = ospf_apiclient_handle_async(oclient);
	if (ret < 0) {
		printf("Connection closed, exiting...");
		exit(0);
	}

	/* Reschedule read thread */
	event_add_read(master, lsa_read, oclient, fd, NULL);
}

/* ---------------------------------------------------------
 * Callback functions for asynchronous events
 * ---------------------------------------------------------
 */

static void lsa_update_callback(struct in_addr ifaddr, struct in_addr area_id,
				uint8_t is_self_originated,
				struct lsa_header *lsa)
{
	printf("lsa_update_callback: ");
	printfrr("ifaddr: %pI4 ", &ifaddr);
	printfrr("area: %pI4\n", &area_id);
	printf("is_self_origin: %u\n", is_self_originated);

	/* It is important to note that lsa_header does indeed include the
	   header and the LSA payload. To access the payload, first check
	   the LSA type and then typecast lsa into the corresponding type,
	   e.g.:

	   if (lsa->type == OSPF_ROUTER_LSA) {
	     struct router_lsa *rl = (struct router_lsa) lsa;
	     ...
	     uint16_t links = rl->links;
	     ...
	  }
	*/

	ospf_lsa_header_dump(lsa);
}

static void lsa_delete_callback(struct in_addr ifaddr, struct in_addr area_id,
				uint8_t is_self_originated,
				struct lsa_header *lsa)
{
	printf("lsa_delete_callback: ");
	printf("ifaddr: %pI4 ", &ifaddr);
	printf("area: %pI4\n", &area_id);
	printf("is_self_origin: %u\n", is_self_originated);

	ospf_lsa_header_dump(lsa);
}

static void ready_callback(uint8_t lsa_type, uint8_t opaque_type,
			   struct in_addr addr)
{
	printfrr("ready_callback: lsa_type: %d opaque_type: %d addr=%pI4\n",
		 lsa_type, opaque_type, &addr);

	/* Schedule opaque LSA originate in 5 secs */
	event_add_timer(master, lsa_inject, oclient, 5, NULL);

	/* Schedule opaque LSA update with new value */
	event_add_timer(master, lsa_inject, oclient, 10, NULL);

	/* Schedule delete */
	event_add_timer(master, lsa_delete, oclient, 30, NULL);
}

static void new_if_callback(struct in_addr ifaddr, struct in_addr area_id)
{
	printfrr("new_if_callback: ifaddr: %pI4 ", &ifaddr);
	printfrr("area_id: %pI4\n", &area_id);
}

static void del_if_callback(struct in_addr ifaddr)
{
	printfrr("new_if_callback: ifaddr: %pI4\n ", &ifaddr);
}

static void ism_change_callback(struct in_addr ifaddr, struct in_addr area_id,
				uint8_t state)
{
	printfrr("ism_change: ifaddr: %pI4 ", &ifaddr);
	printfrr("area_id: %pI4\n", &area_id);
	printf("state: %d [%s]\n", state,
	       lookup_msg(ospf_ism_state_msg, state, NULL));
}

static void nsm_change_callback(struct in_addr ifaddr, struct in_addr nbraddr,
				struct in_addr router_id, uint8_t state)
{
	printfrr("nsm_change: ifaddr: %pI4 ", &ifaddr);
	printfrr("nbraddr: %pI4\n", &nbraddr);
	printfrr("router_id: %pI4\n", &router_id);
	printf("state: %d [%s]\n", state,
	       lookup_msg(ospf_nsm_state_msg, state, NULL));
}


/* ---------------------------------------------------------
 * Main program
 * ---------------------------------------------------------
 */

static int usage(void)
{
	printf("Usage: ospfclient <ospfd> <lsatype> <opaquetype> <opaqueid> <ifaddr> <areaid>\n");
	printf("where ospfd     : router where API-enabled OSPF daemon is running\n");
	printf("      lsatype   : either 9, 10, or 11 depending on flooding scope\n");
	printf("      opaquetype: 0-255 (e.g., experimental applications use > 128)\n");
	printf("      opaqueid  : arbitrary application instance (24 bits)\n");
	printf("      ifaddr    : interface IP address (for type 9) otherwise ignored\n");
	printf("      areaid    : area in IP address format (for type 10) otherwise ignored\n");

	exit(1);
}

int main(int argc, char *argv[])
{
	struct event thread;

	args = argv;

	/* ospfclient should be started with the following arguments:
	 *
	 * (1) host (2) lsa_type (3) opaque_type (4) opaque_id (5) if_addr
	 * (6) area_id
	 *
	 * host: name or IP of host where ospfd is running
	 * lsa_type: 9, 10, or 11
	 * opaque_type: 0-255 (e.g., experimental applications use > 128)
	 * opaque_id: arbitrary application instance (24 bits)
	 * if_addr: interface IP address (for type 9) otherwise ignored
	 * area_id: area in IP address format (for type 10) otherwise ignored
	 */

	if (argc != 7) {
		usage();
	}

	/* Initialization */
	zprivs_preinit(&ospfd_privs);
	zprivs_init(&ospfd_privs);
	master = event_master_create(NULL);

	/* Open connection to OSPF daemon */
	oclient = ospf_apiclient_connect(args[1], ASYNCPORT);
	if (!oclient) {
		printf("Connecting to OSPF daemon on %s failed!\n", args[1]);
		exit(1);
	}

	/* Register callback functions. */
	ospf_apiclient_register_callback(
		oclient, ready_callback, new_if_callback, del_if_callback,
		ism_change_callback, nsm_change_callback, lsa_update_callback,
		lsa_delete_callback);

	/* Register LSA type and opaque type. */
	ospf_apiclient_register_opaque_type(oclient, atoi(args[2]),
					    atoi(args[3]));

	/* Synchronize database with OSPF daemon. */
	ospf_apiclient_sync_lsdb(oclient);

	/* Schedule thread that handles asynchronous messages */
	event_add_read(master, lsa_read, oclient, oclient->fd_async, NULL);

	/* Now connection is established, run loop */
	while (1) {
		event_fetch(master, &thread);
		event_call(&thread);
	}

	/* Never reached */
	return 0;
}
