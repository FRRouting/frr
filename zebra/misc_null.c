#include <zebra.h>

#include "prefix.h"
#include "zebra/rtadv.h"
#include "zebra/irdp.h"
#include "zebra/interface.h"
#include "zebra/zebra_fpm.h"

void ifstat_update_proc (void) { return; }
#pragma weak rtadv_config_write = ifstat_update_proc
#pragma weak irdp_config_write = ifstat_update_proc
#pragma weak ifstat_update_sysctl = ifstat_update_proc

void
zfpm_trigger_update (struct route_node *rn, const char *reason)
{
  return;
}
