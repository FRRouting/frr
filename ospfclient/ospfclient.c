/* 
 * Simple main program to demonstrate how OSPF API can be used.  
 */

/* The following includes are needed in all OSPF API client
   applications */

#include <zebra.h>
#include "prefix.h" /* for ospf_asbr.h */

#include "ospfd/ospfd.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_opaque.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_api.h"
#include "ospf_apiclient.h"

/* The following includes are specific to this main application. Here
   main uses the thread functionality from libzebra (however an
   application can use any thread library like pthreads) */

#include "thread.h"
#include "log.h"

/* local portnumber for async channel */
#define ASYNCPORT 4000

/* Master thread */
struct thread_master *master;

/* Global variables */
struct ospf_apiclient *oclient;
char **args;

/* Our opaque LSAs have the following format */
struct my_opaque_lsa
{
  struct lsa_header hdr;
  u_char data[4];
};


/* ---------------------------------------------------------
 * Threads for asynchronous messages and LSA update/delete 
 * ---------------------------------------------------------
 */

int
lsa_delete (struct thread *t)
{
  struct ospf_apiclient *oclient;
  struct in_addr area_id;
  int rc;

  oclient = THREAD_ARG (t);

  inet_aton (args[6], &area_id);

  printf ("Deleting LSA... ");
  rc = ospf_apiclient_lsa_delete (oclient, 
				  area_id, 
				  atoi (args[2]),       /* lsa type */
				  atoi (args[3]),	/* opaque type */
				  atoi (args[4]));	/* opaque ID */
  printf ("done, return code is = %d\n", rc);
  return rc;
}

int
lsa_inject (struct thread *t)
{
  struct ospf_apiclient *cl;
  struct in_addr ifaddr;
  struct in_addr area_id;
  u_char lsa_type;
  u_char opaque_type;
  u_int32_t opaque_id;
  void *opaquedata;
  int opaquelen;

  static u_int32_t counter = 1;	/* Incremented each time */
  int rc;

  cl = THREAD_ARG (t);

  inet_aton (args[5], &ifaddr);
  inet_aton (args[6], &area_id);
  lsa_type = atoi (args[2]);
  opaque_type = atoi (args[3]);
  opaque_id = atoi (args[4]);
  opaquedata = &counter;
  opaquelen = sizeof (u_int32_t);

  printf ("Originating/updating LSA with counter=%d... ", counter);
  rc = ospf_apiclient_lsa_originate(cl, ifaddr, area_id,
				    lsa_type,
				    opaque_type, opaque_id,
				    opaquedata, opaquelen);

  printf ("done, return code is %d\n", rc);

  counter++;

  return 0;
};


/* This thread handles asynchronous messages coming in from the OSPF
   API server */
int
lsa_read (struct thread *thread)
{
  struct ospf_apiclient *oclient;
  int fd;
  int ret;

  printf ("lsa_read called\n");

  oclient = THREAD_ARG (thread);
  fd = THREAD_FD (thread);

  /* Handle asynchronous message */
  ret = ospf_apiclient_handle_async (oclient);
  if (ret < 0) {
    printf ("Connection closed, exiting...");
    exit(0);
  }

  /* Reschedule read thread */
  thread_add_read (master, lsa_read, oclient, fd);

  return 0;
}



/* ---------------------------------------------------------
 * Callback functions for asynchronous events 
 * ---------------------------------------------------------
 */

void
lsa_update_callback (struct in_addr ifaddr, struct in_addr area_id,
		     u_char is_self_originated,
		     struct lsa_header *lsa)
{
  printf ("lsa_update_callback: ");
  printf ("ifaddr: %s ", inet_ntoa (ifaddr));
  printf ("area: %s\n", inet_ntoa (area_id));
  printf ("is_self_origin: %u\n", is_self_originated);

  ospf_lsa_header_dump (lsa);
}

void
lsa_delete_callback (struct in_addr ifaddr, struct in_addr area_id,
		     u_char is_self_originated,
		     struct lsa_header *lsa)
{
  printf ("lsa_delete_callback: ");
  printf ("ifaddr: %s ", inet_ntoa (ifaddr));
  printf ("area: %s\n", inet_ntoa (area_id));
  printf ("is_self_origin: %u\n", is_self_originated);

  ospf_lsa_header_dump (lsa);
}

void
ready_callback (u_char lsa_type, u_char opaque_type, struct in_addr addr)
{
  printf ("ready_callback: lsa_type: %d opaque_type: %d addr=%s\n",
	  lsa_type, opaque_type, inet_ntoa (addr));

  /* Schedule opaque LSA originate in 5 secs */
  thread_add_timer (master, lsa_inject, oclient, 5);

  /* Schedule opaque LSA update with new value */
  thread_add_timer (master, lsa_inject, oclient, 10);

  /* Schedule delete */
  thread_add_timer (master, lsa_delete, oclient, 30);
}

void
new_if_callback (struct in_addr ifaddr, struct in_addr area_id)
{
  printf ("new_if_callback: ifaddr: %s ", inet_ntoa (ifaddr));
  printf ("area_id: %s\n", inet_ntoa (area_id));
}

void
del_if_callback (struct in_addr ifaddr)
{
  printf ("new_if_callback: ifaddr: %s\n ", inet_ntoa (ifaddr));
}

void
ism_change_callback (struct in_addr ifaddr, struct in_addr area_id,
		     u_char state)
{
  printf ("ism_change: ifaddr: %s ", inet_ntoa (ifaddr));
  printf ("area_id: %s\n", inet_ntoa (area_id));
  printf ("state: %d [%s]\n", state, LOOKUP (ospf_ism_state_msg, state));
}

void
nsm_change_callback (struct in_addr ifaddr, struct in_addr nbraddr,
		     struct in_addr router_id, u_char state)
{
  printf ("nsm_change: ifaddr: %s ", inet_ntoa (ifaddr));
  printf ("nbraddr: %s\n", inet_ntoa (nbraddr));
  printf ("router_id: %s\n", inet_ntoa (router_id));
  printf ("state: %d [%s]\n", state, LOOKUP (ospf_nsm_state_msg, state));
}


/* ---------------------------------------------------------
 * Main program 
 * ---------------------------------------------------------
 */

int
main (int argc, char *argv[])
{
  struct thread thread;

  args = argv;

  /* Main should be started with the following arguments:
   * 
   * (1) host (2) lsa_type (3) opaque_type (4) opaque_id (5) if_addr 
   * (6) area_id
   * 
   * host: name or IP of host where ospfd is running
   * lsa_type: 9, 10, or 11
   * opaque_type: 0-255 (e.g., 140 for experimental Active Networking)
   * opaque_id: arbitrary application instance (24 bits)
   * if_addr: interface IP address (for type 9) otherwise ignored
   * area_id: area in IP address format (for type 10) otherwise ignored
   */

  if (argc != 7)
    {
      printf ("main: wrong number of arguments!\n");
      exit (1);
    }

  /* Initialization */
  master = thread_master_create ();

  /* Open connection to OSPF daemon */
  oclient = ospf_apiclient_connect (args[1], ASYNCPORT);
  if (!oclient)
    {
      printf ("main: connect failed!\n");
      exit (1);
    }

  /* Register callback functions. */
  ospf_apiclient_register_callback (oclient,
				    ready_callback,
				    new_if_callback,
				    del_if_callback,
				    ism_change_callback,
				    nsm_change_callback,
				    lsa_update_callback, 
				    lsa_delete_callback);

  /* Register LSA type and opaque type. */
  ospf_apiclient_register_opaque_type (oclient, atoi (args[2]),
				       atoi (args[3]));

  /* Synchronize database with OSPF daemon. */
  ospf_apiclient_sync_lsdb (oclient);

  /* Schedule thread that handles asynchronous messages */
  thread_add_read (master, lsa_read, oclient, oclient->fd_async);

  /* Now connection is established, run loop */
  while (1)
    {
      thread_fetch (master, &thread);
      thread_call (&thread);
    }

  /* Never reached */
  return 0;
}

