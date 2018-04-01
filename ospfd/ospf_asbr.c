/**OSPFASBoundaryRouterfunctions.*Copyright(C)1999,2000KunihiroIshiguro,Toshiaki
Takada**ThisfileispartofGNUZebra.**GNUZebraisfreesoftware;youcanredistributeitan
d/ormodifyit*underthetermsoftheGNUGeneralPublicLicenseaspublishedbythe*FreeSoftw
areFoundation;eitherversion2,or(atyouroption)any*laterversion.**GNUZebraisdistri
butedinthehopethatitwillbeuseful,but*WITHOUTANYWARRANTY;withouteventheimpliedwar
rantyof*MERCHANTABILITYorFITNESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLic
enseformoredetails.**YoushouldhavereceivedacopyoftheGNUGeneralPublicLicensealong
*withthisprogram;seethefileCOPYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,
51FranklinSt,FifthFloor,Boston,MA02110-1301USA*/#include<zebra.h>#include"thread
.h"#include"memory.h"#include"linklist.h"#include"prefix.h"#include"if.h"#includ
e"table.h"#include"vty.h"#include"filter.h"#include"log.h"#include"ospfd/ospfd.h
"#include"ospfd/ospf_interface.h"#include"ospfd/ospf_asbr.h"#include"ospfd/ospf_
lsa.h"#include"ospfd/ospf_lsdb.h"#include"ospfd/ospf_neighbor.h"#include"ospfd/o
spf_spf.h"#include"ospfd/ospf_flood.h"#include"ospfd/ospf_route.h"#include"ospfd
/ospf_zebra.h"#include"ospfd/ospf_dump.h"/*Removeexternalroute.*/voidospf_extern
al_route_remove(structospf*ospf,structprefix_ipv4*p){structroute_node*rn;structo
spf_route*or;rn=route_node_lookup(ospf->old_external_route,(structprefix*)p);if(
rn)if((or=rn->info)){zlog_info("Route[%s/%d]:externalpathdeleted",inet_ntoa(p->p
refix),p->prefixlen);/*Removeroutefromzebra.*/if(or->type==OSPF_DESTINATION_NETW
ORK)ospf_zebra_delete(ospf,(structprefix_ipv4*)&rn->p,or);ospf_route_free(or);rn
->info=NULL;route_unlock_node(rn);route_unlock_node(rn);return;}zlog_info("Route
[%s/%d]:nosuchexternalpath",inet_ntoa(p->prefix),p->prefixlen);}/*Lookupexternal
route.*/structospf_route*ospf_external_route_lookup(structospf*ospf,structprefix
_ipv4*p){structroute_node*rn;rn=route_node_lookup(ospf->old_external_route,(stru
ctprefix*)p);if(rn){route_unlock_node(rn);if(rn->info)returnrn->info;}zlog_warn(
"Route[%s/%d]:lookup,nosuchprefix",inet_ntoa(p->prefix),p->prefixlen);returnNULL
;}/*AddanExternalinfoforAS-external-LSA.*/structexternal_info*ospf_external_info
_new(uint8_ttype,unsignedshortinstance){structexternal_info*new;new=(structexter
nal_info*)XCALLOC(MTYPE_OSPF_EXTERNAL_INFO,sizeof(structexternal_info));new->typ
e=type;new->instance=instance;ospf_reset_route_map_set_values(&new->route_map_se
t);returnnew;}staticvoidospf_external_info_free(structexternal_info*ei){XFREE(MT
YPE_OSPF_EXTERNAL_INFO,ei);}voidospf_reset_route_map_set_values(structroute_map_
set_values*values){values->metric=-1;values->metric_type=-1;}intospf_route_map_s
et_compare(structroute_map_set_values*values1,structroute_map_set_values*values2
){returnvalues1->metric==values2->metric&&values1->metric_type==values2->metric_
type;}/*AddanExternalinfoforAS-external-LSA.*/structexternal_info*ospf_external_
info_add(structospf*ospf,uint8_ttype,unsignedshortinstance,structprefix_ipv4p,if
index_tifindex,structin_addrnexthop,route_tag_ttag){structexternal_info*new;stru
ctroute_node*rn;structospf_external*ext;charinetbuf[INET6_BUFSIZ];ext=ospf_exter
nal_lookup(ospf,type,instance);if(!ext)ext=ospf_external_add(ospf,type,instance)
;rn=route_node_get(EXTERNAL_INFO(ext),(structprefix*)&p);/*Ifoldinfoexists,--dis
cardnewoneoroverwritewithnewone?*/if(rn)if(rn->info){new=rn->info;if((new->ifind
ex==ifindex)&&(new->nexthop.s_addr==nexthop.s_addr)&&(new->tag==tag)){route_unlo
ck_node(rn);returnNULL;/*NULL=>noLSAtorefresh*/}inet_ntop(AF_INET,(void*)&nextho
p.s_addr,inetbuf,INET6_BUFSIZ);zlog_warn("Redistribute[%s][%d][%u]:%s/%ddiscardi
ngoldinfowithNH%s.",ospf_redist_string(type),instance,ospf->vrf_id,inet_ntoa(p.p
refix),p.prefixlen,inetbuf);XFREE(MTYPE_OSPF_EXTERNAL_INFO,rn->info);rn->info=NU
LL;}/*CreatenewExternalinfoinstance.*/new=ospf_external_info_new(type,instance);
new->p=p;new->ifindex=ifindex;new->nexthop=nexthop;new->tag=tag;/*wedon'tunlockr
nfromtheget()becausewe'reattachingtheinfo*/if(rn)rn->info=new;if(IS_DEBUG_OSPF(l
sa,LSA_GENERATE)){inet_ntop(AF_INET,(void*)&nexthop.s_addr,inetbuf,INET6_BUFSIZ)
;zlog_debug("Redistribute[%s][%u]:%s/%dexternalinfocreated,withNH%s",ospf_redist
_string(type),ospf->vrf_id,inet_ntoa(p.prefix),p.prefixlen,inetbuf);}returnnew;}
voidospf_external_info_delete(structospf*ospf,uint8_ttype,unsignedshortinstance,
structprefix_ipv4p){structroute_node*rn;structospf_external*ext;ext=ospf_externa
l_lookup(ospf,type,instance);if(!ext)return;rn=route_node_lookup(EXTERNAL_INFO(e
xt),(structprefix*)&p);if(rn){ospf_external_info_free(rn->info);rn->info=NULL;ro
ute_unlock_node(rn);route_unlock_node(rn);}}structexternal_info*ospf_external_in
fo_lookup(structospf*ospf,uint8_ttype,unsignedshortinstance,structprefix_ipv4*p)
{structroute_node*rn;structospf_external*ext;ext=ospf_external_lookup(ospf,type,
instance);if(!ext)returnNULL;rn=route_node_lookup(EXTERNAL_INFO(ext),(structpref
ix*)p);if(rn){route_unlock_node(rn);if(rn->info)returnrn->info;}returnNULL;}stru
ctospf_lsa*ospf_external_info_find_lsa(structospf*ospf,structprefix_ipv4*p){stru
ctospf_lsa*lsa;structas_external_lsa*al;structin_addrmask,id;lsa=ospf_lsdb_looku
p_by_id(ospf->lsdb,OSPF_AS_EXTERNAL_LSA,p->prefix,ospf->router_id);if(!lsa)retur
nNULL;al=(structas_external_lsa*)lsa->data;masklen2ip(p->prefixlen,&mask);if(mas
k.s_addr!=al->mask.s_addr){id.s_addr=p->prefix.s_addr|(~mask.s_addr);lsa=ospf_ls
db_lookup_by_id(ospf->lsdb,OSPF_AS_EXTERNAL_LSA,id,ospf->router_id);if(!lsa)retu
rnNULL;}returnlsa;}/*UpdateASBRstatus.*/voidospf_asbr_status_update(structospf*o
spf,uint8_tstatus){zlog_info("ASBR[Status:%d]:Update",status);/*ASBRon.*/if(stat
us){/*AlreadyASBR.*/if(IS_OSPF_ASBR(ospf)){zlog_info("ASBR[Status:%d]:AlreadyASB
R",status);return;}SET_FLAG(ospf->flags,OSPF_FLAG_ASBR);}else{/*AlreadynonASBR.*
/if(!IS_OSPF_ASBR(ospf)){zlog_info("ASBR[Status:%d]:AlreadynonASBR",status);retu
rn;}UNSET_FLAG(ospf->flags,OSPF_FLAG_ASBR);}/*Transitionfrom/tostatusASBR,schedu
letimer.*/ospf_spf_calculate_schedule(ospf,SPF_FLAG_ASBR_STATUS_CHANGE);ospf_rou
ter_lsa_update(ospf);}voidospf_redistribute_withdraw(structospf*ospf,uint8_ttype
,unsignedshortinstance){structroute_node*rn;structexternal_info*ei;structospf_ex
ternal*ext;ext=ospf_external_lookup(ospf,type,instance);if(!ext)return;/*Deletee
xternalinfoforspecifiedtype.*/if(EXTERNAL_INFO(ext))for(rn=route_top(EXTERNAL_IN
FO(ext));rn;rn=route_next(rn))if((ei=rn->info))if(ospf_external_info_find_lsa(os
pf,&ei->p)){if(is_prefix_default(&ei->p)&&ospf->default_originate!=DEFAULT_ORIGI
NATE_NONE)continue;ospf_external_lsa_flush(ospf,type,&ei->p,ei->ifindex/*,ei->ne
xthop*/);ospf_external_info_free(ei);route_unlock_node(rn);rn->info=NULL;}}