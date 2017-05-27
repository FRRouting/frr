#include "zebra.h"
#include "if.h"
#include "ioctl.h"
#include "version.h"
#include "zserv.h"
#include "rt_netlink.h"
#include "interface.h"
#include "hook.h"
#include "module.h"

#include "zebra_dataplane.h"

int
init_default_dataplane (void)
{
  hook_register (address_change, address_change);

  hook_register (route_change, route_change);
  hook_register (rib_process_after, rib_process_after);

  hook_register (mpls_route_change, mpls_route_change);
  /* not needed */
  /* hook_register (pw_change, pw_change); */

  return 0;
}
