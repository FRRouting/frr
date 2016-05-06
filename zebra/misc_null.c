#include <zebra.h>

#include "prefix.h"
#include "zebra/rtadv.h"
#include "zebra/irdp.h"
#include "zebra/interface.h"
#include "zebra/zebra_fpm.h"

void rtadv_config_write (struct vty *vty, struct interface *ifp) { return; }
void irdp_config_write (struct vty *vty, struct interface *ifp) { return; }

void
zfpm_trigger_update (struct route_node *rn, const char *reason)
{
  return;
}
