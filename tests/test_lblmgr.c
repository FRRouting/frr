/*
 * Label Manager Test
 *
 * Copyright (C) 2017 by Bingen Eguzkitza,
 *                       Volta Networks Inc.
 *
 * This file is part of FreeRangeRouting (FRR)
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "lib/stream.h"
#include "lib/zclient.h"

#define ZSERV_PATH "/tmp/zserv.api" // TODO!!
#define KEEP 0 /* change to 1 to avoid garbage collection */
#define CHUNK_SIZE 32

struct zclient *zclient;
unsigned short instance = 1;

const char *sequence = "GGRGGGRRG";

static int zebra_send_get_label_chunk(void);
static int zebra_send_release_label_chunk(uint32_t start, uint32_t end);

static void process_next_call(uint32_t start, uint32_t end)
{
	sleep(3);
	if (!*sequence)
		exit(0);
	if (*sequence == 'G')
		zebra_send_get_label_chunk();
	else if (*sequence == 'R')
		zebra_send_release_label_chunk(start, end);
}

/* Connect to Label Manager */

static int zebra_send_label_manager_connect()
{
	int ret;

	printf("Connect to Label Manager\n");

	ret = lm_label_manager_connect(zclient);
	printf("Label Manager connection result: %u \n", ret);
	if (ret != 0) {
		fprintf(stderr, "Error %d connecting to Label Manager %s\n",
			ret, strerror(errno));
		exit(1);
	}

	process_next_call(0, 0);
}

/* Get Label Chunk */

static int zebra_send_get_label_chunk()
{
	uint32_t start;
	uint32_t end;
	int ret;

	printf("Ask for label chunk \n");

	ret = lm_get_label_chunk(zclient, KEEP, CHUNK_SIZE, &start, &end);
	if (ret != 0) {
		fprintf(stderr, "Error %d requesting label chunk %s\n", ret,
			strerror(errno));
		exit(1);
	}

	sequence++;

	printf("Label Chunk assign: %u - %u \n", start, end);

	process_next_call(start, end);
}

/* Release Label Chunk */

static int zebra_send_release_label_chunk(uint32_t start, uint32_t end)
{
	struct stream *s;
	int ret;

	printf("Release label chunk: %u - %u\n", start, end);

	ret = lm_release_label_chunk(zclient, start, end);
	if (ret != 0) {
		fprintf(stderr, "Error releasing label chunk\n");
		exit(1);
	}

	sequence++;

	process_next_call(start - CHUNK_SIZE, end - CHUNK_SIZE);
}


void init_zclient(struct thread_master *master, char *lm_zserv_path)
{
	frr_zclient_addr(&zclient_addr, &zclient_addr_len, lm_zserv_path);

	zclient = zclient_new_notify(master, &zclient_options_default);
	/* zclient_init(zclient, ZEBRA_LABEL_MANAGER, 0); */
	zclient->sock = -1;
	zclient->redist_default = ZEBRA_ROUTE_LDP;
	zclient->instance = instance;
	if (zclient_socket_connect(zclient) < 0) {
		printf("Error connecting synchronous zclient!\n");
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	struct thread_master *master;
	struct thread thread;
	int ret;

	printf("Sequence to be tested: %s\n", sequence);

	master = thread_master_create(NULL);
	init_zclient(master, ZSERV_PATH);

	zebra_send_label_manager_connect();

	return 0;
}
