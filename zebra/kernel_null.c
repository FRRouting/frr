/* NULL kernel methods for testing. */

#include <zebra.h>
#include <log.h>

#include "zebra/zserv.h"
#include "zebra/rt.h"
#include "zebra/redistribute.h"
#include "zebra/connected.h"

int kernel_add_ipv4 (struct prefix *a, struct rib *b) { return 0; }
#pragma weak kernel_delete_ipv4 = kernel_add_ipv4
int kernel_add_ipv6 (struct prefix *a, struct rib *b) { return 0; }
#pragma weak kernel_delete_ipv6 = kernel_add_ipv6
int kernel_delete_ipv6_old (struct prefix_ipv6 *dest, struct in6_addr *gate,
                            unsigned int index, int flags, int table)
{ return 0; }

int kernel_add_route (struct prefix_ipv4 *a, struct in_addr *b, int c, int d)
{ return 0; }

int kernel_address_add_ipv4 (struct interface *a, struct connected *b)
{
  zlog_debug ("%s", __func__);
  SET_FLAG (b->conf, ZEBRA_IFC_REAL);
  connected_add_ipv4 (a, 0, &b->address->u.prefix4, b->address->prefixlen, 
                      (b->destination ? &b->destination->u.prefix4 : NULL), 
                      NULL);
  return 0;
}

int kernel_address_delete_ipv4 (struct interface *a, struct connected *b)
{
  zlog_debug ("%s", __func__);
  connected_delete_ipv4 (a, 0, &b->address->u.prefix4, b->address->prefixlen, 
                         (b->destination ? &b->destination->u.prefix4 : NULL));
  return 0;
}

void kernel_init (void) { return; }
#pragma weak route_read = kernel_init
