#include <zebra.h>
#include "zebra/rib.h"
#include "zebra/zserv.h"

#include "zebra/redistribute.h"

void zebra_redistribute_add (int a, struct zserv *b, int c)
{ return; }
#pragma weak zebra_redistribute_delete = zebra_redistribute_add
#pragma weak zebra_redistribute_default_add = zebra_redistribute_add
#pragma weak zebra_redistribute_default_delete = zebra_redistribute_add

void redistribute_add (struct prefix *a, struct rib *b)
{ return; }
#pragma weak redistribute_delete = redistribute_add

void zebra_interface_up_update (struct interface *a)
{ return; }
#pragma weak zebra_interface_down_update = zebra_interface_up_update
#pragma weak zebra_interface_add_update = zebra_interface_up_update
#pragma weak zebra_interface_delete_update = zebra_interface_up_update

void zebra_interface_address_add_update (struct interface *a,
					 	struct connected *b)
{ return; }
#pragma weak zebra_interface_address_delete_update = zebra_interface_address_add_update
