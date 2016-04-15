#include <zebra.h>
#include "nexthop.h"
#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/zebra_mpls.h"

int
zebra_mpls_lsp_label_consistent (struct zebra_vrf *zvrf, mpls_label_t in_label,
                     mpls_label_t out_label, enum nexthop_types_t gtype,
                     union g_addr *gate, char *ifname, ifindex_t ifindex)
{
  return 1;
}

int
zebra_mpls_static_lsp_add (struct zebra_vrf *zvrf, mpls_label_t in_label,
                     mpls_label_t out_label, enum nexthop_types_t gtype,
                     union g_addr *gate, char *ifname, ifindex_t ifindex)
{
  return 0;
}

int
zebra_mpls_static_lsp_del (struct zebra_vrf *zvrf, mpls_label_t in_label,
                           enum nexthop_types_t gtype, union g_addr *gate,
                           char *ifname, ifindex_t ifindex)
{
  return 0;
}

int
zebra_mpls_write_lsp_config (struct vty *vty, struct zebra_vrf *zvrf)
{
  return 0;
}

void
zebra_mpls_init_tables (struct zebra_vrf *zvrf)
{
}

void
zebra_mpls_init (void)
{
}
