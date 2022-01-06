/*
 * Copyright (C) 2021, LabN Consulting, L.L.C
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

#ifndef NORTHBOUND_GRPC_CANDIDATE_H
#define NORTHBOUND_GRPC_CANDIDATE_H

#include <assert.h>
#include <map>
#include <stdint.h>

#include "lib/northbound.h"

struct candidate {
	uint64_t id;
	struct nb_config *config;
	struct nb_transaction *transaction;
};

class Candidates
{
      public:
	~Candidates(void)
	{
		// Delete candidates.
		for (auto candidate : m_cdb)
			delete_candidate(&candidate.second);
	}

	struct candidate *create_candidate(void)
	{
		uint64_t id = ++m_next_id;
		assert(id); // TODO: implement an algorithm for unique reusable
			    // IDs.
		struct candidate *c = &m_cdb[id];
		c->id = id;
		c->config = nb_config_dup(running_config);
		c->transaction = NULL;

		return c;
	}

	void delete_candidate(struct candidate *c)
	{
		char errmsg[BUFSIZ] = {0};

		m_cdb.erase(c->id);
		nb_config_free(c->config);
		if (c->transaction)
			nb_candidate_commit_abort(c->transaction, errmsg,
						  sizeof(errmsg));
	}

	struct candidate *get_candidate(uint32_t id)
	{
		return m_cdb.count(id) == 0 ? NULL : &m_cdb[id];
	}

      private:
	uint64_t m_next_id = 0;
	std::map<uint32_t, struct candidate> m_cdb;
};

#endif /* NORTHBOUND_GRPC_CANDIDATE_H */
