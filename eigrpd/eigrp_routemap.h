/**eigrp_routemap.h**Createdon:Nov19,2015*Author:root*/#ifndefEIGRPD_EIGRP_ROUTE
MAP_H_#defineEIGRPD_EIGRP_ROUTEMAP_H_#include"if_rmap.h"externbooleigrp_routemap
_prefix_apply(structeigrp*eigrp,structeigrp_interface*ei,intin,structprefix*pref
ix);externvoideigrp_route_map_update(constchar*);externvoideigrp_route_map_init(
);externvoideigrp_if_rmap_update(structif_rmap*);externvoideigrp_if_rmap_update_
interface(structinterface*);externvoideigrp_routemap_update_redistribute(void);e
xternvoideigrp_rmap_update(constchar*);#endif/*EIGRPD_EIGRP_ROUTEMAP_H_*/