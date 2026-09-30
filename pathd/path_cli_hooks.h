// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for pathd/path_cli.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

/*
 * If config is not empty, pathd_srte_check_config_not_empty must
 * return 1, otherwise - 0. If no hook subscribers return 1 and there is no
 * configuration in pathd, headers `segment-routing/traffic-eng` won't be
 * output for `write` command and `pathd_srte_config_write` won't be called.
 */
DO_HOOK(pathd_srte_check_config_not_empty);

DO_HOOK(pathd_srte_config_write, (struct vty *, vty));

/* Sent when user requests 'no traffic-eng', please clean configuration */
DO_HOOK(pathd_srte_no_srte);
