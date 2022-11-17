/*
 * Copyright 2022 6WIND S.A.
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

#include <zebra.h>

#include "northbound.h"
#include "libfrr.h"
#include "zebra/zebra_tracker.h"
#include "zebra/zebra_tracker_nb.h"

/* clang-format off */
const struct frr_yang_module_info frr_zebra_tracker_info = {
	.name = "frr-zebra-tracker",
	.nodes = {
		{
			.xpath = "/frr-zebra-tracker:trackers/tracker",
			.cbs = {
				.cli_show = cli_show_tracker,
				.create = zebra_tracker_create,
				.destroy = zebra_tracker_destroy,
			}
		},
		{
			.xpath = "/frr-zebra-tracker:trackers/tracker/filepath",
			.cbs = {
				.modify = zebra_tracker_filepath_modify,
				.destroy = zebra_tracker_filepath_destroy,
			}
		},
		{
			.xpath = "/frr-zebra-tracker:trackers/tracker/filepattern",
			.cbs = {
				.modify = zebra_tracker_filepattern_modify,
				.destroy = zebra_tracker_filepattern_destroy,
			}
		},
		{
			.xpath = "/frr-zebra-tracker:trackers/tracker/filepattern-exact",
			.cbs = {
				.create = zebra_tracker_filepattern_exact_create,
				.destroy = zebra_tracker_filepattern_exact_destroy,
			}
		},
		{
			.xpath = "/frr-zebra-tracker:trackers/tracker/fileexists",
			.cbs = {
				.create = zebra_tracker_fileexists_create,
				.destroy = zebra_tracker_fileexists_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
