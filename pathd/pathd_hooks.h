// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for pathd/pathd.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(pathd_candidate_created, (struct srte_candidate *, candidate));

DO_HOOK(pathd_candidate_updated, (struct srte_candidate *, candidate));

DO_HOOK(pathd_candidate_removed, (struct srte_candidate *, candidate));
