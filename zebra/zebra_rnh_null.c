#include <zebra.h>
#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/zebra_rnh.h"

int zebra_rnh_ip_default_route = 0;
int zebra_rnh_ipv6_default_route = 0;

int zebra_evaluate_rnh (int vrfid, int family, int force, rnh_type_t type,
		        struct prefix *p)
{ return 0; }

void zebra_print_rnh_table (int vrfid, int family, struct vty *vty,
			    rnh_type_t type)
{}

void zebra_register_rnh_static_nh(struct prefix *p, struct route_node *rn)
{}

void zebra_deregister_rnh_static_nh(struct prefix *p, struct route_node *rn)
{}
