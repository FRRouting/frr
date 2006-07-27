/* NULL kernel methods for testing. */

#include <zebra.h>

#include "zebra/zserv.h"
#include "zebra/rt.h"
#include "zebra/redistribute.h"

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
{ return 0; }
#pragma weak kernel_address_delete_ipv4 = kernel_address_add_ipv4

void kernel_init (void) { return; }
#pragma weak route_read = kernel_init
