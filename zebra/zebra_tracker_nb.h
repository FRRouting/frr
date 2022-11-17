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

#ifndef _FRR_ZEBRA_TRACKER_NB_H_
#define _FRR_ZEBRA_TRACKER_NB_H_

#ifdef __cplusplus
extern "C" {
#endif

extern const struct frr_yang_module_info frr_zebra_tracker_info;

/* prototypes */
int zebra_tracker_create(struct nb_cb_create_args *args);
int zebra_tracker_destroy(struct nb_cb_destroy_args *args);
int zebra_tracker_filepath_modify(struct nb_cb_modify_args *args);
int zebra_tracker_filepath_destroy(struct nb_cb_destroy_args *args);
int zebra_tracker_filepattern_modify(struct nb_cb_modify_args *args);
int zebra_tracker_filepattern_destroy(struct nb_cb_destroy_args *args);
int zebra_tracker_filepattern_exact_create(struct nb_cb_create_args *args);
int zebra_tracker_filepattern_exact_destroy(struct nb_cb_destroy_args *args);
int zebra_tracker_fileexists_create(struct nb_cb_create_args *args);
int zebra_tracker_fileexists_destroy(struct nb_cb_destroy_args *args);

#ifdef __cplusplus
}
#endif

#endif
