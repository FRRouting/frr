/*
 * Test code to test lib/cmgd_frntnd_client.h
 * 
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <pthread.h>
#include "getopt.h"
#include "lib/thread.h"
#include "lib/libfrr.h"
#include "lib/cmgd_frntnd_client.h"

#define NUM_TEST_SESSIONS	10

static bool cmgd_connected = false;

static cmgd_lib_hndl_t frntd_lib_hndl;
static struct thread_master *master = NULL;
static cmgd_session_id_t frntnd_session_id[NUM_TEST_SESSIONS] = {0};

static void cmgd_test_frntnd_server_connected(
	cmgd_lib_hndl_t lib_hndl, cmgd_user_data_t usr_data,
	bool connected)
{
	int indx;

	cmgd_connected = connected;
	printf("%sGot %sconnected %s CMGD Frontend Server\n",
		!connected ? "ERROR: " : "", !connected ? "dis: " : "",
		!connected ? "from" : "to");

	if (connected) {
		for(indx = 0; indx < NUM_TEST_SESSIONS; indx++) {
			if (cmgd_frntnd_create_client_session(
				frntd_lib_hndl, indx, 0) != CMGD_SUCCESS) {
				printf("ERROR: Failed to creaet a new session!\n");
				exit(-1);
			}
		}
	}
}

static void cmgd_test_frntnd_session_created(
	cmgd_lib_hndl_t lib_hndl, cmgd_user_data_t usr_data,
	cmgd_client_id_t client_id, bool create, bool success,
	cmgd_session_id_t session_id, cmgd_client_req_id_t req_id,
	uintptr_t user_ctxt)
{
	if (!success) {
		printf("ERROR: %s session for client %lu failed!\n", 
			create ? "Creating" : "Destroying", client_id);
		exit(-1);
	}

	printf("%s session for client %lu successfully!\n", 
			create ? "Created" : "Destroyed", client_id);
	if (create) {
		frntnd_session_id[client_id] = session_id;

		/* TODO: Send some GET_DATA_REQ */
	} else {
		frntnd_session_id[client_id] = 0;
	}
}

static cmgd_frntnd_client_params_t client_params = {
	.name = "Frontend Test",
	.conn_notify_cb = cmgd_test_frntnd_server_connected,
	.sess_req_result_cb = cmgd_test_frntnd_session_created,
};

/* Main routine of cmgd. Treatment of argument and start cmgd finite
   state machine is handled at here. */
int main(int argc, char **argv)
{
	struct thread thread;

	master = thread_master_create("main");
	if (!master)
		exit(-1);

	frntd_lib_hndl = cmgd_frntnd_client_lib_init(&client_params, master);

	while (thread_fetch(master, &thread))
		thread_call(&thread);

	/* Not reached. */
	return 0;
}
