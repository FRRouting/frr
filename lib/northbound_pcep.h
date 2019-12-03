/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Sascha Kattelmann
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

#ifndef _FRR_NORTHBOUND_PCEP_H_
#define _FRR_NORTHBOUND_PCEP_H_

#include "northbound.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Add a MPLS label to an existing segment list.
 *
 * segment_list_name
 *    Name of the segment list to which a label should be added.
 *
 * label
 *    MPLS label which should be added to the segment list.
 */
extern int nb_pcep_add_segment_list_label(const char *segment_list_name,
					  const char *label);

/*
 * Create an empty named segment list.
 *
 * name
 *    Name of the segment list.
 */
extern int nb_pcep_create_segment_list(const char *name);

/*
 * Add a Candidate Path to an existing SR Policy.
 *
 * color
 *    Color of the SR Policy (is used together with 'endpoint' to select the SR
 * Policy)
 *
 * endpoint
 *    Endpoint of the SR Policy (is used together with 'color' to select the SR
 * Policy)
 *
 * originator
 *    IP of the originating PCE endpoint.
 *
 * preference
 *    Preference of the Candidate Path, used for Active Candidate Path
 * selection.
 *
 * segment_list_name
 *    Name of the Segment List which should be installed as LSP.
 */
extern int nb_pcep_add_candidate_path(const char *color, const char *endpoint,
				      const char *originator,
				      const char *preference,
				      const char *segment_list_name);

/* internal */
int nb_pcep_commit_candidate_config(struct nb_config *candidate_config,
				    const char *comment);
void nb_pcep_edit_candidate_config(struct nb_config *candidate_config,
				   const char *xpath,
				   enum nb_operation operation,
				   const char *value);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_NORTHBOUND_PCEP_H_ */
