// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for isisd/isis_nb_notifications.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(isis_hook_lsp_too_large, (const struct isis_circuit *, circuit), (uint32_t, pdu_size),
	(const uint8_t *, lsp_id));
DO_HOOK(isis_hook_corrupted_lsp, (const struct isis_area *, area));
/* Note: no isis_hook_corrupted_lsp - because this notification is not used */
DO_HOOK(isis_hook_lsp_exceed_max, (const struct isis_area *, area), (const uint8_t *, lsp_id));
DO_HOOK(isis_hook_max_area_addr_mismatch, (const struct isis_circuit *, circuit),
	(uint8_t, max_addrs), (const char *, raw_pdu), (size_t, raw_pdu_len));
DO_HOOK(isis_hook_authentication_type_failure, (const struct isis_circuit *, circuit),
	(const char *, raw_pdu), (size_t, raw_pdu_len));
DO_HOOK(isis_hook_authentication_failure, (const struct isis_circuit *, circuit),
	(const char *, raw_pdu), (size_t, raw_pdu_len));
DO_HOOK(isis_hook_adj_state_change, (const struct isis_adjacency *, adj));
DO_HOOK(isis_hook_reject_adjacency, (const struct isis_circuit *, circuit),
	(const char *, raw_pdu), (size_t, raw_pdu_len));
DO_HOOK(isis_hook_area_mismatch, (const struct isis_circuit *, circuit), (const char *, raw_pdu),
	(size_t, raw_pdu_len));
DO_HOOK(isis_hook_id_len_mismatch, (const struct isis_circuit *, circuit), (uint8_t, rcv_id_len),
	(const char *, raw_pdu), (size_t, raw_pdu_len));
DO_HOOK(isis_hook_version_skew, (const struct isis_circuit *, circuit), (uint8_t, version),
	(const char *, raw_pdu), (size_t, raw_pdu_len));
DO_HOOK(isis_hook_lsp_error, (const struct isis_circuit *, circuit), (const uint8_t *, lsp_id),
	(const char *, raw_pdu), (size_t, raw_pdu_len));
DO_HOOK(isis_hook_seqno_skipped, (const struct isis_circuit *, circuit), (const uint8_t *, lsp_id));
DO_HOOK(isis_hook_own_lsp_purge, (const struct isis_circuit *, circuit), (const uint8_t *, lsp_id));
