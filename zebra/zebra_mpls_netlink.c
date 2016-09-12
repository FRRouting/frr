#include <zebra.h>
#include "zebra/rt.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_mpls.h"

/*
 * Install Label Forwarding entry into the kernel.
 */
int
kernel_add_lsp (zebra_lsp_t *lsp)
{
  int ret;

  if (!lsp || !lsp->best_nhlfe) // unexpected
    return -1;

  UNSET_FLAG (lsp->flags, LSP_FLAG_CHANGED);
  ret = netlink_mpls_multipath (RTM_NEWROUTE, lsp);
  if (!ret)
    SET_FLAG (lsp->flags, LSP_FLAG_INSTALLED);
  else
    clear_nhlfe_installed (lsp);

  return ret;
}

/*
 * Update Label Forwarding entry in the kernel. This means that the Label
 * forwarding entry is already installed and needs an update - either a new
 * path is to be added, an installed path has changed (e.g., outgoing label)
 * or an installed path (but not all paths) has to be removed.
 * TODO: Performs a DEL followed by ADD now, need to change to REPLACE. Note
 * that REPLACE was originally implemented for IPv4 nexthops but removed as
 * it was not functioning when moving from swap to PHP as that was signaled
 * through the metric field (before kernel-MPLS). This shouldn't be an issue
 * any longer, so REPLACE can be reintroduced.
 */
int
kernel_upd_lsp (zebra_lsp_t *lsp)
{
  int ret;

  if (!lsp || !lsp->best_nhlfe) // unexpected
    return -1;

  UNSET_FLAG (lsp->flags, LSP_FLAG_CHANGED);

  /* First issue a DEL and clear the installed flag. */
  netlink_mpls_multipath (RTM_DELROUTE, lsp);
  UNSET_FLAG (lsp->flags, LSP_FLAG_INSTALLED);

  /* Then issue an ADD. */
  ret = netlink_mpls_multipath (RTM_NEWROUTE, lsp);
  if (!ret)
    SET_FLAG (lsp->flags, LSP_FLAG_INSTALLED);
  else
    clear_nhlfe_installed (lsp);

  return ret;
}

/*
 * Delete Label Forwarding entry from the kernel.
 */
int
kernel_del_lsp (zebra_lsp_t *lsp)
{
  if (!lsp) // unexpected
    return -1;

  if (CHECK_FLAG (lsp->flags, LSP_FLAG_INSTALLED))
    {
      netlink_mpls_multipath (RTM_DELROUTE, lsp);
      UNSET_FLAG (lsp->flags, LSP_FLAG_INSTALLED);
    }

  return 0;
}
