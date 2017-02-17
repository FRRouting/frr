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
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include "lib/stream.h"
#include "lib/zclient.h"
#include "lib/mpls.h"

#define ZSERV_PATH "/tmp/zserv.api" // TODO!!

struct zclient *zclient;

const char *sequence = "GGRGGGRRG";
#define CHUNK_SIZE 32

static int zebra_send_get_label_chunk (struct thread *);
static int zebra_send_release_label_chunk (uint32_t start, uint32_t end);

static void
process_next_call (uint32_t start, uint32_t end)
{
		if (!*sequence)
				exit (0);
		if (*sequence == 'G')
				zebra_send_get_label_chunk (NULL);
		else if (*sequence == 'R')
				zebra_send_release_label_chunk (start, end);
}

/* Get Label Chunk */

static int
zebra_send_get_label_chunk (struct thread * thread)
{
		struct stream		*s;

		printf("Ask for label chunk (%d)\n", getpid());

		/* Reset stream. */
		s = zclient->obuf;
		stream_reset(s);

		zclient_create_header(s, ZEBRA_GET_LABEL_CHUNK, VRF_DEFAULT);

		/* owner */
		stream_putl (s, getpid());

		/* Put length at the first point of the stream. */
		stream_putw_at(s, 0, stream_get_endp(s));

		if (zclient_send_message(zclient) != 0) {
				fprintf (stderr, "Error sending get label chunk request\n");
				exit (1);
		}

		sequence++;
}

static int
zebra_read_get_label_chunk_response (struct zclient *zclient, zebra_size_t length,
									 vrf_id_t vrf_id)
{
		struct stream		*s;
		uint32_t owner;
		uint32_t start;
		uint32_t end;

		s = zclient->ibuf;

		/* owner */
		owner = stream_getl(s);
		/* start and end labels */
		start = stream_getl(s);
		end = stream_getl(s);

		printf ("Label Chunk assign: %u - %u (%u) \n",
				start, end, owner);

		/* not owning this response */
		if (owner != (uint32_t)getpid())
				return -1;
		/* sanity */
		if (start > end
			|| start < MPLS_MIN_UNRESERVED_LABEL
			|| end > MPLS_MAX_UNRESERVED_LABEL) {
				printf ("%s: Invalid Label chunk: %u - %u\n", __func__,
						  start, end);
				return -1;
		}

		process_next_call (start, end);

		return 0;
}

/* Release Label Chunk */

static int
zebra_send_release_label_chunk (uint32_t start, uint32_t end)
{
		struct stream		*s;

		printf("Release label chunk: %u - %u\n", start, end);

		/* Reset stream. */
		s = zclient->obuf;
		stream_reset(s);

		zclient_create_header(s, ZEBRA_RELEASE_LABEL_CHUNK, VRF_DEFAULT);

		/* owner */
		stream_putl (s, getpid());

		/* start */
		stream_putl (s, start);
		/* end */
		stream_putl (s, end);

		/* Put length at the first point of the stream. */
		stream_putw_at(s, 0, stream_get_endp(s));

		if (zclient_send_message(zclient) != 0)
				fprintf (stderr, "Error sending release label chunk request\n");

		sequence++;

		process_next_call (start-CHUNK_SIZE, end-CHUNK_SIZE);
}


void init_zclient (struct thread_master *master, char *lm_zserv_path)
{
		if (lm_zserv_path)
				zclient_serv_path_set(lm_zserv_path);

		zclient = zclient_new(master);
		zclient_init(zclient, ZEBRA_LABEL_MANAGER, 0);
		zclient->assign_label_chunk = zebra_read_get_label_chunk_response;

}

int main (int argc, char *argv[])
{
		struct thread_master *master;
		struct thread		 thread;
		int ret;

		printf ("pid: %d\n", getpid());
		printf ("Sequence to be tested: %s\n", sequence);

		master = thread_master_create();
		init_zclient (master, ZSERV_PATH);

		thread_add_background (master, zebra_send_get_label_chunk, NULL, 0);

		/* Fetch next active thread. */
		printf ("Starting thread loop\n");
		while (thread_fetch(master, &thread))
				thread_call(&thread);

}
