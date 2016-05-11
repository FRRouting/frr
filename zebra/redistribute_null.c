#include <zebra.h>
#include "zebra/rib.h"
#include "zebra/zserv.h"

#include "zebra/redistribute.h"

void zebra_redistribute_add (int a, struct zserv *b, int c,
			     struct zebra_vrf *zvrf)
{ return; }
#ifdef HAVE_SYS_WEAK_ALIAS_PRAGMA
#pragma weak zebra_redistribute_delete = zebra_redistribute_add
#pragma weak zebra_redistribute_default_add = zebra_redistribute_add
#pragma weak zebra_redistribute_default_delete = zebra_redistribute_add
#else
void zebra_redistribute_delete  (int a, struct zserv *b, int c,
				 struct zebra_vrf *zvrf)
{ return; }
void zebra_redistribute_default_add (int a, struct zserv *b, int c,
				     struct zebra_vrf *zvrf)
{ return; }
void zebra_redistribute_default_delete (int a, struct zserv *b, int c,
					struct zebra_vrf *zvrf)
{ return; }
#endif

void redistribute_update (struct prefix *a, struct rib *b, struct rib *c)
{ return; }
#ifdef HAVE_SYS_WEAK_ALIAS_PRAGMA
#pragma weak redistribute_delete = redistribute_update
#else
void redistribute_delete (struct prefix *a, struct rib *b)
{ return; }
#endif

void zebra_interface_up_update (struct interface *a)
{ return; }
#ifdef HAVE_SYS_WEAK_ALIAS_PRAGMA
#pragma weak zebra_interface_down_update = zebra_interface_up_update
#pragma weak zebra_interface_add_update = zebra_interface_up_update
#pragma weak zebra_interface_delete_update = zebra_interface_up_update
#else
void zebra_interface_down_update  (struct interface *a)
{ return; }
void zebra_interface_add_update (struct interface *a)
{ return; }
void zebra_interface_delete_update (struct interface *a)
{ return; }
#endif


void zebra_interface_address_add_update (struct interface *a,
					 	struct connected *b)
{ return; }
#ifdef HAVE_SYS_WEAK_ALIAS_PRAGMA
#pragma weak zebra_interface_address_delete_update = zebra_interface_address_add_update
#else
void zebra_interface_address_delete_update (struct interface *a,
                                                struct connected *b)
{ return; }
#endif

void zebra_interface_vrf_update_del (struct interface *a, vrf_id_t new_vrf_id)
{ return; }

void zebra_interface_vrf_update_add (struct interface *a, vrf_id_t old_vrf_id)
{ return; }

int zebra_import_table (afi_t afi, u_int32_t table_id, u_int32_t distance,
			const char *rmap_name, int add)
{ return 0; }

int zebra_add_import_table_entry (struct route_node *rn, struct rib *rib, const char *rmap_name)
{ return 0; }

int zebra_del_import_table_entry (struct route_node *rn, struct rib *rib)
{ return 0; }

int is_zebra_import_table_enabled(afi_t afi, u_int32_t table_id)
{ return 0; }

int zebra_import_table_config(struct vty *vty)
{ return 0; }

void zebra_import_table_rm_update()
{ return; }
