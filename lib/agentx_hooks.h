// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for lib/agentx.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

#ifdef SNMP_AGENTX
DO_HOOK(agentx_enabled);
#endif
