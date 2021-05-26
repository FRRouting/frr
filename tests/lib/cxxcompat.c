/*
 * C++ compatibility compile-time smoketest
 * Copyright (C) 2019  David Lamparter for NetDEF, Inc.
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

#define test__cplusplus

#include "lib/zebra.h"

#include "lib/agg_table.h"
#include "lib/bfd.h"
#include "lib/bitfield.h"
#include "lib/buffer.h"
#include "lib/checksum.h"
#include "lib/command.h"
#include "lib/command_graph.h"
#include "lib/command_match.h"
#include "lib/compiler.h"
#include "lib/csv.h"
#include "lib/debug.h"
#include "lib/distribute.h"
#include "lib/ferr.h"
#include "lib/filter.h"
#include "lib/frr_pthread.h"
#include "lib/frratomic.h"
#include "lib/frrstr.h"
#include "lib/getopt.h"
#include "lib/graph.h"
#include "lib/hash.h"
#include "lib/hook.h"
#include "lib/id_alloc.h"
#include "lib/if.h"
#include "lib/if_rmap.h"
#include "lib/imsg.h"
#include "lib/ipaddr.h"
#include "lib/jhash.h"
#include "lib/json.h"
#include "lib/keychain.h"
#include "lib/lib_errors.h"
#include "lib/lib_vty.h"
#include "lib/libfrr.h"
#include "lib/libospf.h"
#include "lib/linklist.h"
#include "lib/log.h"
#include "lib/md5.h"
#include "lib/memory.h"
#include "lib/mlag.h"
#include "lib/module.h"
#include "lib/monotime.h"
#include "lib/mpls.h"
#include "lib/network.h"
#include "lib/nexthop.h"
#include "lib/nexthop_group.h"
#include "lib/northbound.h"
#include "lib/northbound_cli.h"
#include "lib/northbound_db.h"
#include "lib/ns.h"
#include "lib/openbsd-tree.h"
#include "lib/pbr.h"
#include "lib/plist.h"
#include "lib/prefix.h"
#include "lib/privs.h"
#include "lib/ptm_lib.h"
#include "lib/pw.h"
#include "lib/qobj.h"
#include "lib/queue.h"
#include "lib/ringbuf.h"
#include "lib/routemap.h"
#include "lib/sbuf.h"
#include "lib/sha256.h"
#include "lib/sigevent.h"
#include "lib/skiplist.h"
#include "lib/sockopt.h"
#include "lib/sockunion.h"
#include "lib/spf_backoff.h"
#include "lib/srcdest_table.h"
#include "lib/stream.h"
#include "lib/table.h"
#include "lib/termtable.h"
#include "lib/thread.h"
#include "lib/typesafe.h"
#include "lib/typerb.h"
#include "lib/vector.h"
#include "lib/vlan.h"
#include "lib/vrf.h"
#include "lib/vty.h"
#include "lib/vxlan.h"
#include "lib/wheel.h"
/* #include "lib/workqueue.h"		-- macro problem with STAILQ_LAST */
#include "lib/yang.h"
#include "lib/yang_translator.h"
#include "lib/yang_wrappers.h"
#include "lib/zclient.h"

PREDECL_RBTREE_UNIQ(footree);
struct foo {
	int dummy;
	struct footree_item item;
};
static int foocmp(const struct foo *a, const struct foo *b)
{
	return memcmp(&a->dummy, &b->dummy, sizeof(a->dummy));
}
DECLARE_RBTREE_UNIQ(footree, struct foo, item, foocmp);

int main(int argc, char **argv)
{
	return 0;
}
