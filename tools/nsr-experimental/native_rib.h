/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_attr.h"
static json_object *rib_error(const char *message){
    json_object *r=json_object_new_object();json_object_object_add(r,"error",json_object_new_string(message));return r;
}
static json_object *native_rib(void){
    struct bgp *bgp=bgp_get_default();
    if(!bgp||!bgp->rib[AFI_IP][SAFI_UNICAST]||!bgp->mq||bgp->mq->size)return rib_error("native_rib_not_quiescent");
    json_object *reply=json_object_new_object(),*routes=json_object_new_object();size_t count=0;
    json_object_object_add(reply,"routes",routes);
    for(struct bgp_dest *dest=bgp_table_top(bgp->rib[AFI_IP][SAFI_UNICAST]);dest;dest=bgp_route_next(dest)){
        for(struct bgp_path_info *path=bgp_dest_get_bgp_path_info(dest);path;path=path->next){
            if(path->peer==bgp->peer_self||!CHECK_FLAG(path->flags,BGP_PATH_VALID)||!CHECK_FLAG(path->flags,BGP_PATH_SELECTED))continue;
            if(!path->attr||++count>20000){bgp_dest_unlock_node(dest);json_object_put(reply);return rib_error("native_rib_snapshot_bound");}
            char prefix[PREFIX_STRLEN],gateway[INET_ADDRSTRLEN];prefix2str(bgp_dest_get_prefix(dest),prefix,sizeof(prefix));
            if(!inet_ntop(AF_INET,&path->attr->nexthop,gateway,sizeof(gateway))){bgp_dest_unlock_node(dest);json_object_put(reply);return rib_error("native_rib_nexthop_invalid");}
            json_object *group=NULL;if(!json_object_object_get_ex(routes,gateway,&group)){group=json_object_new_array();json_object_object_add(routes,gateway,group);}
            json_object_array_add(group,json_object_new_string(prefix));
        }
    }
    json_object_object_add(reply,"ok",json_object_new_boolean(true));json_object_object_add(reply,"count",json_object_new_int64(count));
    if(strlen(json_object_to_json_string_ext(reply,JSON_C_TO_STRING_PLAIN))>380000){json_object_put(reply);return rib_error("native_rib_response_bound");}
    return reply;
}
