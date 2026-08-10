// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for isisd/isis_circuit.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(isis_if_new_hook, (struct interface *, ifp));

DO_HOOK(isis_circuit_new_hook, (struct isis_circuit *, circuit));

DO_HOOK(isis_circuit_del_hook, (struct isis_circuit *, circuit));

DO_HOOK(isis_circuit_add_addr_hook, (struct isis_circuit *, circuit));

#ifdef FABRICD
DO_HOOK(isis_circuit_config_write, (struct isis_circuit *, circuit), (struct vty *, vty));
#endif
