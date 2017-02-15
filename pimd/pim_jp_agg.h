#ifndef __PIM_JP_AGG_H__
#define __PIM_JP_AGG_H__

struct pim_jp_sources
{
  struct pim_upstream *up;
  int is_join;
};

struct pim_jp_agg_group
{
  struct in_addr group;
  //int onetime;
  struct list *sources;
};

void pim_jp_agg_group_list_free (struct pim_jp_agg_group *jag);
int pim_jp_agg_group_list_cmp (void *arg1, void *arg2);

void pim_jp_agg_clear_group (struct list *group);
void pim_jp_agg_remove_group (struct list *group, struct pim_upstream *up);

void pim_jp_agg_add_group (struct list *group,
                           struct pim_upstream *up, bool is_join);

void pim_jp_agg_switch_interface (struct pim_rpf *orpf,
                                  struct pim_rpf *nrpf,
                                  struct pim_upstream *up);

void pim_jp_agg_single_upstream_send (struct pim_rpf *rpf,
                                      struct pim_upstream *up,
                                      bool is_join);
#endif
