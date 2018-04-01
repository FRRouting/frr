/**PIMforQuagga*Copyright(C)2008EvertondaSilvaMarques**Thisprogramisfreesoftware
;youcanredistributeitand/ormodify*itunderthetermsoftheGNUGeneralPublicLicenseasp
ublishedby*theFreeSoftwareFoundation;eitherversion2oftheLicense,or*(atyouroption
)anylaterversion.**Thisprogramisdistributedinthehopethatitwillbeuseful,but*WITHO
UTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSFORAPARTIC
ULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Youshouldhavereceived
acopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefileCOPYING;ifnot,w
ritetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA02110-130
1USA*/#include<zebra.h>#include"zebra/rib.h"#include"if.h"#include"log.h"#includ
e"prefix.h"#include"zclient.h"#include"stream.h"#include"network.h"#include"vty.
h"#include"plist.h"#include"lib/bfd.h"#include"pimd.h"#include"pim_pim.h"#includ
e"pim_zebra.h"#include"pim_iface.h"#include"pim_str.h"#include"pim_oil.h"#includ
e"pim_rpf.h"#include"pim_time.h"#include"pim_join.h"#include"pim_zlookup.h"#incl
ude"pim_ifchannel.h"#include"pim_rp.h"#include"pim_igmpv3.h"#include"pim_jp_agg.
h"#include"pim_nht.h"#include"pim_ssm.h"#undefPIM_DEBUG_IFADDR_DUMP#definePIM_DE
BUG_IFADDR_DUMPstaticstructzclient*zclient=NULL;/*Router-idupdatemessagefromzebr
a.*/staticintpim_router_id_update_zebra(intcommand,structzclient*zclient,zebra_s
ize_tlength,vrf_id_tvrf_id){structprefixrouter_id;zebra_router_id_update_read(zc
lient->ibuf,&router_id);return0;}staticintpim_zebra_if_add(intcommand,structzcli
ent*zclient,zebra_size_tlength,vrf_id_tvrf_id){structinterface*ifp;/*zebraapiadd
s/delsinterfacesusingthesamecallinterface_add_readbelow,seecommentsinlib/zclient
.c*/ifp=zebra_interface_add_read(zclient->ibuf,vrf_id);if(!ifp)return0;if(PIM_DE
BUG_ZEBRA){zlog_debug("%s:%sindex%d(%u)flags%ldmetric%dmtu%doperative%d",__PRETT
Y_FUNCTION__,ifp->name,ifp->ifindex,vrf_id,(long)ifp->flags,ifp->metric,ifp->mtu
,if_is_operative(ifp));}if(if_is_operative(ifp))pim_if_addr_add_all(ifp);/**Ifwe
areavrfdevicethatisup,openupthepim_socketfor*listening*toincomingpimmessagesirre
levantiftheuserhasconfiguredus*forpimornot.*/if(pim_if_is_vrf_device(ifp)){struc
tpim_interface*pim_ifp;if(!ifp->info){pim_ifp=pim_if_new(ifp,0,0);ifp->info=pim_
ifp;}pim_sock_add(ifp);}return0;}staticintpim_zebra_if_del(intcommand,structzcli
ent*zclient,zebra_size_tlength,vrf_id_tvrf_id){structinterface*ifp;/*zebraapiadd
s/delsinterfacesusingthesamecallinterface_add_readbelow,seecommentsinlib/zclient
.ccommentsinlib/zclient.cseemtoindicatethatcallingzebra_interface_add_readisthec
orrectcall,butthatresultsinanattemtedoutofboundsreadwhichcausespimdtoassert.Othe
rclientsusezebra_interface_state_readanditappearstoworkjustfine.*/ifp=zebra_inte
rface_state_read(zclient->ibuf,vrf_id);if(!ifp)return0;if(PIM_DEBUG_ZEBRA){zlog_
debug("%s:%sindex%d(%u)flags%ldmetric%dmtu%doperative%d",__PRETTY_FUNCTION__,ifp
->name,ifp->ifindex,vrf_id,(long)ifp->flags,ifp->metric,ifp->mtu,if_is_operative
(ifp));}if(!if_is_operative(ifp))pim_if_addr_del_all(ifp);return0;}staticintpim_
zebra_if_state_up(intcommand,structzclient*zclient,zebra_size_tlength,vrf_id_tvr
f_id){structinterface*ifp;uint32_ttable_id;/*zebraapinotifiesinterfaceup/downeve
ntsbyusingthesamecallzebra_interface_state_readbelow,seecommentsinlib/zclient.c*
/ifp=zebra_interface_state_read(zclient->ibuf,vrf_id);if(!ifp)return0;if(PIM_DEB
UG_ZEBRA){zlog_debug("%s:%sindex%d(%u)flags%ldmetric%dmtu%doperative%d",__PRETTY
_FUNCTION__,ifp->name,ifp->ifindex,vrf_id,(long)ifp->flags,ifp->metric,ifp->mtu,
if_is_operative(ifp));}if(if_is_operative(ifp)){/*pim_if_addr_add_all()sufficesf
orbringingupbothIGMPandPIM*/pim_if_addr_add_all(ifp);}/**Ifwehaveapimregdeviceca
llbackandit'sforaspecific*tablesetthemasterappropriately*/if(sscanf(ifp->name,"p
imreg%d",&table_id)==1){structvrf*vrf;RB_FOREACH(vrf,vrf_name_head,&vrfs_by_name
){if((table_id==vrf->data.l.table_id)&&(ifp->vrf_id!=vrf->vrf_id)){structinterfa
ce*master=if_lookup_by_name(vrf->name,vrf->vrf_id);if(!master){zlog_debug("%s:Un
abletofindMasterinterfacefor%s",__PRETTY_FUNCTION__,vrf->name);return0;}zclient_
interface_set_master(zclient,master,ifp);}}}return0;}staticintpim_zebra_if_state
_down(intcommand,structzclient*zclient,zebra_size_tlength,vrf_id_tvrf_id){struct
interface*ifp;/*zebraapinotifiesinterfaceup/downeventsbyusingthesamecallzebra_in
terface_state_readbelow,seecommentsinlib/zclient.c*/ifp=zebra_interface_state_re
ad(zclient->ibuf,vrf_id);if(!ifp)return0;if(PIM_DEBUG_ZEBRA){zlog_debug("%s:%sin
dex%d(%u)flags%ldmetric%dmtu%doperative%d",__PRETTY_FUNCTION__,ifp->name,ifp->if
index,vrf_id,(long)ifp->flags,ifp->metric,ifp->mtu,if_is_operative(ifp));}if(!if
_is_operative(ifp)){pim_ifchannel_delete_all(ifp);/*pim_if_addr_del_all()suffice
sforshuttingdownIGMP,butnotforshuttingdownPIM*/pim_if_addr_del_all(ifp);/*pim_so
ck_delete()closesthesocket,stopsreadandtimerthreads,andkillsallneighbors.*/if(if
p->info){pim_sock_delete(ifp,"linkdown");}}if(ifp->info)pim_if_del_vif(ifp);retu
rn0;}#ifdefPIM_DEBUG_IFADDR_DUMPstaticvoiddump_if_address(structinterface*ifp){s
tructconnected*ifc;structlistnode*node;zlog_debug("%s%s:interface%saddresses:",_
_FILE__,__PRETTY_FUNCTION__,ifp->name);for(ALL_LIST_ELEMENTS_RO(ifp->connected,n
ode,ifc)){structprefix*p=ifc->address;if(p->family!=AF_INET)continue;zlog_debug(
"%s%s:interface%saddress%s%s",__FILE__,__PRETTY_FUNCTION__,ifp->name,inet_ntoa(p
->u.prefix4),CHECK_FLAG(ifc->flags,ZEBRA_IFA_SECONDARY)?"secondary":"primary");}
}#endifstaticintpim_zebra_if_address_add(intcommand,structzclient*zclient,zebra_
size_tlength,vrf_id_tvrf_id){structconnected*c;structprefix*p;structpim_interfac
e*pim_ifp;/*zebraapinotifiesaddressadds/delseventsbyusingthesamecallinterface_ad
d_readbelow,seecommentsinlib/zclient.czebra_interface_address_read(ZEBRA_INTERFA
CE_ADDRESS_ADD,...)willaddaddresstointerfacelistbycallingconnected_add_by_prefix
()*/c=zebra_interface_address_read(command,zclient->ibuf,vrf_id);if(!c)return0;p
im_ifp=c->ifp->info;p=c->address;if(PIM_DEBUG_ZEBRA){charbuf[BUFSIZ];prefix2str(
p,buf,BUFSIZ);zlog_debug("%s:%s(%u)connectedIPaddress%sflags%u%s",__PRETTY_FUNCT
ION__,c->ifp->name,vrf_id,buf,c->flags,CHECK_FLAG(c->flags,ZEBRA_IFA_SECONDARY)?
"secondary":"primary");#ifdefPIM_DEBUG_IFADDR_DUMPdump_if_address(c->ifp);#endif
}if(!CHECK_FLAG(c->flags,ZEBRA_IFA_SECONDARY)){/*tryingtoaddprimaryaddress*/stru
ctin_addrprimary_addr=pim_find_primary_addr(c->ifp);if(p->family!=AF_INET||prima
ry_addr.s_addr!=p->u.prefix4.s_addr){if(PIM_DEBUG_ZEBRA){/*butwehadaprimaryaddre
ssalready*/charbuf[BUFSIZ];prefix2str(p,buf,BUFSIZ);zlog_warn("%s:%s:forcingseco
ndaryflagon%s",__PRETTY_FUNCTION__,c->ifp->name,buf);}SET_FLAG(c->flags,ZEBRA_IF
A_SECONDARY);}}pim_if_addr_add(c);if(pim_ifp)pim_rp_check_on_if_add(pim_ifp);if(
if_is_loopback(c->ifp)){structvrf*vrf=vrf_lookup_by_id(VRF_DEFAULT);structinterf
ace*ifp;FOR_ALL_INTERFACES(vrf,ifp){if(!if_is_loopback(ifp)&&if_is_operative(ifp
))pim_if_addr_add_all(ifp);}}return0;}staticintpim_zebra_if_address_del(intcomma
nd,structzclient*client,zebra_size_tlength,vrf_id_tvrf_id){structconnected*c;str
uctprefix*p;structvrf*vrf=vrf_lookup_by_id(vrf_id);structpim_instance*pim;if(!vr
f)return0;pim=vrf->info;/*zebraapinotifiesaddressadds/delseventsbyusingthesameca
llinterface_add_readbelow,seecommentsinlib/zclient.czebra_interface_address_read
(ZEBRA_INTERFACE_ADDRESS_DELETE,...)willremoveaddressfrominterfacelistbycallingc
onnected_delete_by_prefix()*/c=zebra_interface_address_read(command,client->ibuf
,vrf_id);if(!c)return0;p=c->address;if(p->family==AF_INET){if(PIM_DEBUG_ZEBRA){c
harbuf[BUFSIZ];prefix2str(p,buf,BUFSIZ);zlog_debug("%s:%s(%u)disconnectedIPaddre
ss%sflags%u%s",__PRETTY_FUNCTION__,c->ifp->name,vrf_id,buf,c->flags,CHECK_FLAG(c
->flags,ZEBRA_IFA_SECONDARY)?"secondary":"primary");#ifdefPIM_DEBUG_IFADDR_DUMPd
ump_if_address(c->ifp);#endif}pim_if_addr_del(c,0);pim_rp_setup(pim);pim_i_am_rp
_re_evaluate(pim);}connected_free(c);return0;}staticvoidscan_upstream_rpf_cache(
structpim_instance*pim){structlistnode*up_node;structlistnode*up_nextnode;struct
listnode*node;structpim_upstream*up;structinterface*ifp;for(ALL_LIST_ELEMENTS(pi
m->upstream_list,up_node,up_nextnode,up)){enumpim_rpf_resultrpf_result;structpim
_rpfold;structprefixnht_p;nht_p.family=AF_INET;nht_p.prefixlen=IPV4_MAX_BITLEN;n
ht_p.u.prefix4.s_addr=up->upstream_addr.s_addr;pim_resolve_upstream_nh(pim,&nht_
p);old.source_nexthop.interface=up->rpf.source_nexthop.interface;old.source_next
hop.nbr=up->rpf.source_nexthop.nbr;rpf_result=pim_rpf_update(pim,up,&old,0);if(r
pf_result==PIM_RPF_FAILURE)continue;if(rpf_result==PIM_RPF_CHANGED){structpim_ne
ighbor*nbr;nbr=pim_neighbor_find(old.source_nexthop.interface,old.rpf_addr.u.pre
fix4);if(nbr)pim_jp_agg_remove_group(nbr->upstream_jp_agg,up);/**Wehavedetecteda
casewherewemightneed*torescan*theinheritedo_listsodoit.*/if(up->channel_oil->oil
_inherited_rescan){pim_upstream_inherited_olist_decide(pim,up);up->channel_oil->
oil_inherited_rescan=0;}if(up->join_state==PIM_UPSTREAM_JOINED){/**Ifwecomeuprea
lfastwecanbehere*wherethemroutehasnotbeeninstalled*soinstallit.*/if(!up->channel
_oil->installed)pim_mroute_add(up->channel_oil,__PRETTY_FUNCTION__);/**RFC4601:4
.5.7.Sending(S,G)*Join/PruneMessages**TransitionsfromJoinedState**RPF'(S,G)chang
esnotduetoanAssert**Theupstream(S,G)statemachineremains*inJoinedstate.SendJoin(S
,G)tothenew*upstreamneighbor,whichisthenewvalue*ofRPF'(S,G).SendPrune(S,G)totheo
ld*upstreamneighbor,whichistheoldvalue*ofRPF'(S,G).SettheJoinTimer(JT)to*expirea
ftert_periodicseconds.*/pim_jp_agg_switch_interface(&old,&up->rpf,up);pim_upstre
am_join_timer_restart(up,&old);}/*up->join_state==PIM_UPSTREAM_JOINED*//*FIXMEca
njoin_desiredactuallybechangedbypim_rpf_update()returningPIM_RPF_CHANGED?*/pim_u
pstream_update_join_desired(pim,up);}/*PIM_RPF_CHANGED*/}/*for(qpim_upstream_lis
t)*/FOR_ALL_INTERFACES(pim->vrf,ifp)if(ifp->info){structpim_interface*pim_ifp=if
p->info;structpim_iface_upstream_switch*us;for(ALL_LIST_ELEMENTS_RO(pim_ifp->ups
tream_switch_list,node,us)){structpim_rpfrpf;rpf.source_nexthop.interface=ifp;rp
f.rpf_addr.u.prefix4=us->address;pim_joinprune_send(&rpf,us->us);pim_jp_agg_clea
r_group(us->us);}}}voidpim_scan_individual_oil(structchannel_oil*c_oil,intin_vif
_index){structin_addrvif_source;intinput_iface_vif_index;intold_vif_index;if(!pi
m_rp_set_upstream_addr(c_oil->pim,&vif_source,c_oil->oil.mfcc_origin,c_oil->oil.
mfcc_mcastgrp))return;if(in_vif_index)input_iface_vif_index=in_vif_index;else{st
ructprefixsrc,grp;src.family=AF_INET;src.prefixlen=IPV4_MAX_BITLEN;src.u.prefix4
=vif_source;grp.family=AF_INET;grp.prefixlen=IPV4_MAX_BITLEN;grp.u.prefix4=c_oil
->oil.mfcc_mcastgrp;if(PIM_DEBUG_ZEBRA){charsource_str[INET_ADDRSTRLEN];chargrou
p_str[INET_ADDRSTRLEN];pim_inet4_dump("<source?>",c_oil->oil.mfcc_origin,source_
str,sizeof(source_str));pim_inet4_dump("<group?>",c_oil->oil.mfcc_mcastgrp,group
_str,sizeof(group_str));zlog_debug("%s:channel_oil(%s,%s)upstreaminfoisnotpresen
t.",__PRETTY_FUNCTION__,source_str,group_str);}input_iface_vif_index=pim_ecmp_fi
b_lookup_if_vif_index(c_oil->pim,vif_source,&src,&grp);}if(input_iface_vif_index
<1){if(PIM_DEBUG_ZEBRA){charsource_str[INET_ADDRSTRLEN];chargroup_str[INET_ADDRS
TRLEN];pim_inet4_dump("<source?>",c_oil->oil.mfcc_origin,source_str,sizeof(sourc
e_str));pim_inet4_dump("<group?>",c_oil->oil.mfcc_mcastgrp,group_str,sizeof(grou
p_str));zlog_debug("%s%s:couldnotfindinputinterface(%d)for(S,G)=(%s,%s)",__FILE_
_,__PRETTY_FUNCTION__,c_oil->oil.mfcc_parent,source_str,group_str);}pim_mroute_d
el(c_oil,__PRETTY_FUNCTION__);return;}if(input_iface_vif_index==c_oil->oil.mfcc_
parent){if(!c_oil->installed)pim_mroute_add(c_oil,__PRETTY_FUNCTION__);/*RPFunch
anged*/return;}if(PIM_DEBUG_ZEBRA){structinterface*old_iif=pim_if_find_by_vif_in
dex(c_oil->pim,c_oil->oil.mfcc_parent);structinterface*new_iif=pim_if_find_by_vi
f_index(c_oil->pim,input_iface_vif_index);charsource_str[INET_ADDRSTRLEN];chargr
oup_str[INET_ADDRSTRLEN];pim_inet4_dump("<source?>",c_oil->oil.mfcc_origin,sourc
e_str,sizeof(source_str));pim_inet4_dump("<group?>",c_oil->oil.mfcc_mcastgrp,gro
up_str,sizeof(group_str));zlog_debug("%s%s:(S,G)=(%s,%s)inputinterfacechangedfro
m%svif_index=%dto%svif_index=%d",__FILE__,__PRETTY_FUNCTION__,source_str,group_s
tr,(old_iif)?old_iif->name:"<old_iif?>",c_oil->oil.mfcc_parent,(new_iif)?new_iif
->name:"<new_iif?>",input_iface_vif_index);}/*newiifloopstoexistingoif?*/if(c_oi
l->oil.mfcc_ttls[input_iface_vif_index]){structinterface*new_iif=pim_if_find_by_
vif_index(c_oil->pim,input_iface_vif_index);if(PIM_DEBUG_ZEBRA){charsource_str[I
NET_ADDRSTRLEN];chargroup_str[INET_ADDRSTRLEN];pim_inet4_dump("<source?>",c_oil-
>oil.mfcc_origin,source_str,sizeof(source_str));pim_inet4_dump("<group?>",c_oil-
>oil.mfcc_mcastgrp,group_str,sizeof(group_str));zlog_debug("%s%s:(S,G)=(%s,%s)ne
wiifloopstoexistingoif:%svif_index=%d",__FILE__,__PRETTY_FUNCTION__,source_str,g
roup_str,(new_iif)?new_iif->name:"<new_iif?>",input_iface_vif_index);}}/*updatei
ifvif_index*/old_vif_index=c_oil->oil.mfcc_parent;c_oil->oil.mfcc_parent=input_i
face_vif_index;/*updatekernelmulticastforwardingcache(MFC)*/if(pim_mroute_add(c_
oil,__PRETTY_FUNCTION__)){if(PIM_DEBUG_MROUTE){/*justlogwarning*/structinterface
*old_iif=pim_if_find_by_vif_index(c_oil->pim,old_vif_index);structinterface*new_
iif=pim_if_find_by_vif_index(c_oil->pim,input_iface_vif_index);charsource_str[IN
ET_ADDRSTRLEN];chargroup_str[INET_ADDRSTRLEN];pim_inet4_dump("<source?>",c_oil->
oil.mfcc_origin,source_str,sizeof(source_str));pim_inet4_dump("<group?>",c_oil->
oil.mfcc_mcastgrp,group_str,sizeof(group_str));zlog_debug("%s%s:(S,G)=(%s,%s)fai
lureupdatinginputinterfacefrom%svif_index=%dto%svif_index=%d",__FILE__,__PRETTY_
FUNCTION__,source_str,group_str,old_iif?old_iif->name:"<old_iif?>",c_oil->oil.mf
cc_parent,new_iif?new_iif->name:"<new_iif?>",input_iface_vif_index);}}}voidpim_s
can_oil(structpim_instance*pim){structlistnode*node;structlistnode*nextnode;stru
ctchannel_oil*c_oil;ifindex_tifindex;intvif_index=0;pim->scan_oil_last=pim_time_
monotonic_sec();++pim->scan_oil_events;for(ALL_LIST_ELEMENTS(pim->channel_oil_li
st,node,nextnode,c_oil)){if(c_oil->up&&c_oil->up->rpf.source_nexthop.interface){
ifindex=c_oil->up->rpf.source_nexthop.interface->ifindex;vif_index=pim_if_find_v
ifindex_by_ifindex(pim,ifindex);/*PassCurrentselectedNHvifindextomroute*download
*/if(vif_index)pim_scan_individual_oil(c_oil,vif_index);}elsepim_scan_individual
_oil(c_oil,0);}}staticinton_rpf_cache_refresh(structthread*t){structpim_instance
*pim=THREAD_ARG(t);/*updatePIMprotocolstate*/scan_upstream_rpf_cache(pim);/*upda
tekernelmulticastforwardingcache(MFC)*/pim_scan_oil(pim);pim->rpf_cache_refresh_
last=pim_time_monotonic_sec();++pim->rpf_cache_refresh_events;//Itiscalledaspart
ofpim_neighbor_add//pim_rp_setup();return0;}voidsched_rpf_cache_refresh(structpi
m_instance*pim){++pim->rpf_cache_refresh_requests;pim_rpf_set_refresh_time(pim);
if(pim->rpf_cache_refresher){/*Refreshtimerisalreadyrunning*/return;}/*Startrefr
eshtimer*/if(PIM_DEBUG_ZEBRA){zlog_debug("%s:triggering%ldmsectimer",__PRETTY_FU
NCTION__,qpim_rpf_cache_refresh_delay_msec);}thread_add_timer_msec(master,on_rpf
_cache_refresh,pim,qpim_rpf_cache_refresh_delay_msec,&pim->rpf_cache_refresher);
}staticvoidpim_zebra_connected(structzclient*zclient){/*Sendtheclientregistratio
n*/bfd_client_sendmsg(zclient,ZEBRA_BFD_CLIENT_REGISTER);zclient_send_reg_reques
ts(zclient,pimg->vrf_id);}voidpim_zebra_init(void){inti;/*Socketforreceivingupda
tesfromZebradaemon*/zclient=zclient_new_notify(master,&zclient_options_default);
zclient->zebra_connected=pim_zebra_connected;zclient->router_id_update=pim_route
r_id_update_zebra;zclient->interface_add=pim_zebra_if_add;zclient->interface_del
ete=pim_zebra_if_del;zclient->interface_up=pim_zebra_if_state_up;zclient->interf
ace_down=pim_zebra_if_state_down;zclient->interface_address_add=pim_zebra_if_add
ress_add;zclient->interface_address_delete=pim_zebra_if_address_del;zclient->nex
thop_update=pim_parse_nexthop_update;zclient_init(zclient,ZEBRA_ROUTE_PIM,0,&pim
d_privs);if(PIM_DEBUG_PIM_TRACE){zlog_info("zclient_initclearedredistributionreq
uest");}/*Requestallredistribution*/for(i=0;i<ZEBRA_ROUTE_MAX;i++){if(i==zclient
->redist_default)continue;vrf_bitmap_set(zclient->redist[AFI_IP][i],pimg->vrf_id
);;if(PIM_DEBUG_PIM_TRACE){zlog_debug("%s:requestingredistributionfor%s(%i)",__P
RETTY_FUNCTION__,zebra_route_string(i),i);}}/*Requestdefaultinformation*/zclient
_redistribute_default(ZEBRA_REDISTRIBUTE_DEFAULT_ADD,zclient,pimg->vrf_id);if(PI
M_DEBUG_PIM_TRACE){zlog_info("%s:requestingdefaultinformationredistribution",__P
RETTY_FUNCTION__);zlog_notice("%s:zclientupdatesocketinitialized",__PRETTY_FUNCT
ION__);}zclient_lookup_new();}voidigmp_anysource_forward_start(structpim_instanc
e*pim,structigmp_group*group){structigmp_source*source;structin_addrsrc_addr={.s
_addr=0};/*Anysource(*,G)isforwardedonlyifmodeisEXCLUDE{empty}*/zassert(group->g
roup_filtermode_isexcl);zassert(listcount(group->group_source_list)<1);source=so
urce_new(group,src_addr);if(!source){zlog_warn("%s:Failuretocreate*source",__PRE
TTY_FUNCTION__);return;}igmp_source_forward_start(pim,source);}voidigmp_anysourc
e_forward_stop(structigmp_group*group){structigmp_source*source;structin_addrsta
r={.s_addr=0};source=igmp_find_source_by_addr(group,star);if(source)igmp_source_
forward_stop(source);}staticvoidigmp_source_forward_reevaluate_one(structpim_ins
tance*pim,structigmp_source*source){structprefix_sgsg;structigmp_group*group=sou
rce->source_group;structpim_ifchannel*ch;if((source->source_addr.s_addr!=INADDR_
ANY)||!IGMP_SOURCE_TEST_FORWARDING(source->source_flags))return;memset(&sg,0,siz
eof(structprefix_sg));sg.src=source->source_addr;sg.grp=group->group_addr;ch=pim
_ifchannel_find(group->group_igmp_sock->interface,&sg);if(pim_is_grp_ssm(pim,gro
up->group_addr)){/*IfSSMgroupwithdrawlocalmembership*/if(ch&&(ch->local_ifmember
ship==PIM_IFMEMBERSHIP_INCLUDE)){if(PIM_DEBUG_PIM_EVENTS)zlog_debug("localmember
shipdelfor%sasGisnowSSM",pim_str_sg_dump(&sg));pim_ifchannel_local_membership_de
l(group->group_igmp_sock->interface,&sg);}}else{/*IfASMgroupaddlocalmembership*/
if(!ch||(ch->local_ifmembership==PIM_IFMEMBERSHIP_NOINFO)){if(PIM_DEBUG_PIM_EVEN
TS)zlog_debug("localmembershipaddfor%sasGisnowASM",pim_str_sg_dump(&sg));pim_ifc
hannel_local_membership_add(group->group_igmp_sock->interface,&sg);}}}voidigmp_s
ource_forward_reevaluate_all(structpim_instance*pim){structinterface*ifp;FOR_ALL
_INTERFACES(pim->vrf,ifp){structpim_interface*pim_ifp=ifp->info;structlistnode*s
ock_node;structigmp_sock*igmp;if(!pim_ifp)continue;/*scanigmpsockets*/for(ALL_LI
ST_ELEMENTS_RO(pim_ifp->igmp_socket_list,sock_node,igmp)){structlistnode*grpnode
;structigmp_group*grp;/*scanigmpgroups*/for(ALL_LIST_ELEMENTS_RO(igmp->igmp_grou
p_list,grpnode,grp)){structlistnode*srcnode;structigmp_source*src;/*scangroupsou
rces*/for(ALL_LIST_ELEMENTS_RO(grp->group_source_list,srcnode,src)){igmp_source_
forward_reevaluate_one(pim,src);}/*scangroupsources*/}/*scanigmpgroups*/}/*scani
gmpsockets*/}/*scaninterfaces*/}voidigmp_source_forward_start(structpim_instance
*pim,structigmp_source*source){structigmp_group*group;structprefix_sgsg;intresul
t;intinput_iface_vif_index=0;memset(&sg,0,sizeof(structprefix_sg));sg.src=source
->source_addr;sg.grp=source->source_group->group_addr;if(PIM_DEBUG_IGMP_TRACE){z
log_debug("%s:(S,G)=%sigmp_sock=%doif=%sfwd=%d",__PRETTY_FUNCTION__,pim_str_sg_d
ump(&sg),source->source_group->group_igmp_sock->fd,source->source_group->group_i
gmp_sock->interface->name,IGMP_SOURCE_TEST_FORWARDING(source->source_flags));}/*
PreventIGMPinterfacefrominstallingmulticastroutemultipletimes*/if(IGMP_SOURCE_TE
ST_FORWARDING(source->source_flags)){return;}group=source->source_group;if(!sour
ce->source_channel_oil){structin_addrvif_source;structpim_interface*pim_oif;stru
ctprefixnht_p,src,grp;structpim_nexthop_cacheout_pnc;structpim_nexthopnexthop;st
ructpim_upstream*up=NULL;if(!pim_rp_set_upstream_addr(pim,&vif_source,source->so
urce_addr,sg.grp))return;/*RegisteraddrwithZebraNHT*/nht_p.family=AF_INET;nht_p.
prefixlen=IPV4_MAX_BITLEN;nht_p.u.prefix4=vif_source;memset(&out_pnc,0,sizeof(st
ructpim_nexthop_cache));src.family=AF_INET;src.prefixlen=IPV4_MAX_BITLEN;src.u.p
refix4=vif_source;//RPorSrcaddressgrp.family=AF_INET;grp.prefixlen=IPV4_MAX_BITL
EN;grp.u.prefix4=sg.grp;if(pim_find_or_track_nexthop(pim,&nht_p,NULL,NULL,&out_p
nc)){if(out_pnc.nexthop_num){up=pim_upstream_find(pim,&sg);memset(&nexthop,0,siz
eof(nexthop));if(up)memcpy(&nexthop,&up->rpf.source_nexthop,sizeof(structpim_nex
thop));pim_ecmp_nexthop_search(pim,&out_pnc,&nexthop,&src,&grp,0);if(nexthop.int
erface)input_iface_vif_index=pim_if_find_vifindex_by_ifindex(pim,nexthop.interfa
ce->ifindex);}else{if(PIM_DEBUG_ZEBRA){charbuf1[INET_ADDRSTRLEN];charbuf2[INET_A
DDRSTRLEN];pim_inet4_dump("<source?>",nht_p.u.prefix4,buf1,sizeof(buf1));pim_ine
t4_dump("<source?>",grp.u.prefix4,buf2,sizeof(buf2));zlog_debug("%s:NHTNexthopno
tfoundforaddr%sgrp%s",__PRETTY_FUNCTION__,buf1,buf2);}}}elseinput_iface_vif_inde
x=pim_ecmp_fib_lookup_if_vif_index(pim,vif_source,&src,&grp);if(PIM_DEBUG_ZEBRA)
{charbuf2[INET_ADDRSTRLEN];pim_inet4_dump("<source?>",vif_source,buf2,sizeof(buf
2));zlog_debug("%s:NHT%svif_source%svif_index:%d",__PRETTY_FUNCTION__,pim_str_sg
_dump(&sg),buf2,input_iface_vif_index);}if(input_iface_vif_index<1){if(PIM_DEBUG
_IGMP_TRACE){charsource_str[INET_ADDRSTRLEN];pim_inet4_dump("<source?>",source->
source_addr,source_str,sizeof(source_str));zlog_debug("%s%s:couldnotfindinputint
erfaceforsource%s",__FILE__,__PRETTY_FUNCTION__,source_str);}return;}/*ProtectIG
MPagainstaddingloopedMFCentriescreatedbybothsourceandreceiverattachedtothesamein
terface.SeeTODOT22.*/pim_oif=source->source_group->group_igmp_sock->interface->i
nfo;if(!pim_oif){if(PIM_DEBUG_IGMP_TRACE){zlog_debug("%s:multicastnotenabledonoi
f=%s?",__PRETTY_FUNCTION__,source->source_group->group_igmp_sock->interface->nam
e);}return;}if(input_iface_vif_index==pim_oif->mroute_vif_index){/*ignorerequest
forloopedMFCentry*/if(PIM_DEBUG_IGMP_TRACE){zlog_debug("%s:ignoringrequestforloo
pedMFCentry(S,G)=%s:igmp_sock=%doif=%svif_index=%d",__PRETTY_FUNCTION__,pim_str_
sg_dump(&sg),source->source_group->group_igmp_sock->fd,source->source_group->gro
up_igmp_sock->interface->name,input_iface_vif_index);}return;}source->source_cha
nnel_oil=pim_channel_oil_add(pim,&sg,input_iface_vif_index);if(!source->source_c
hannel_oil){if(PIM_DEBUG_IGMP_TRACE){zlog_debug("%s%s:couldnotcreateOILforchanne
l(S,G)=%s",__FILE__,__PRETTY_FUNCTION__,pim_str_sg_dump(&sg));}return;}}result=p
im_channel_add_oif(source->source_channel_oil,group->group_igmp_sock->interface,
PIM_OIF_FLAG_PROTO_IGMP);if(result){if(PIM_DEBUG_MROUTE){zlog_warn("%s:add_oif()
failedwithreturn=%d",__func__,result);}return;}/*FeedIGMPv3-gatheredlocalmembers
hipinformationintoPIMper-interface(S,G)state.*/if(!pim_ifchannel_local_membershi
p_add(group->group_igmp_sock->interface,&sg)){if(PIM_DEBUG_MROUTE)zlog_warn("%s:
Failuretoaddlocalmembershipfor%s",__PRETTY_FUNCTION__,pim_str_sg_dump(&sg));retu
rn;}IGMP_SOURCE_DO_FORWARDING(source->source_flags);}/*igmp_source_forward_stop:
stopfowarding,butkeepthesourceigmp_source_delete:stopfowarding,anddeletethesourc
e*/voidigmp_source_forward_stop(structigmp_source*source){structigmp_group*group
;structprefix_sgsg;intresult;memset(&sg,0,sizeof(structprefix_sg));sg.src=source
->source_addr;sg.grp=source->source_group->group_addr;if(PIM_DEBUG_IGMP_TRACE){z
log_debug("%s:(S,G)=%sigmp_sock=%doif=%sfwd=%d",__PRETTY_FUNCTION__,pim_str_sg_d
ump(&sg),source->source_group->group_igmp_sock->fd,source->source_group->group_i
gmp_sock->interface->name,IGMP_SOURCE_TEST_FORWARDING(source->source_flags));}/*
PreventIGMPinterfacefromremovingmulticastroutemultipletimes*/if(!IGMP_SOURCE_TES
T_FORWARDING(source->source_flags)){return;}group=source->source_group;/*Itappea
rsthatincertaincircumstancesthatigmp_source_forward_stopiscalledwhenIGMPforwardi
ngwasnotenabledinoif_flagsforthisoutgoinginterface.Possiblybecauseofmultiplecall
s.Whenthathappens,weenterthebelowifstatementandthisfunctionreturnsearlywhichintu
rntriggersthecallingfunctiontoassert.Makingthecalltopim_channel_del_oifandignori
ngthereturncodefixestheissuewithoutilleffect,similartopim_forward_stopbelow.*/re
sult=pim_channel_del_oif(source->source_channel_oil,group->group_igmp_sock->inte
rface,PIM_OIF_FLAG_PROTO_IGMP);if(result){if(PIM_DEBUG_IGMP_TRACE)zlog_debug("%s
:pim_channel_del_oif()failedwithreturn=%d",__func__,result);return;}/*FeedIGMPv3
-gatheredlocalmembershipinformationintoPIMper-interface(S,G)state.*/pim_ifchanne
l_local_membership_del(group->group_igmp_sock->interface,&sg);IGMP_SOURCE_DONT_F
ORWARDING(source->source_flags);}voidpim_forward_start(structpim_ifchannel*ch){s
tructpim_upstream*up=ch->upstream;uint32_tmask=PIM_OIF_FLAG_PROTO_PIM;intinput_i
face_vif_index=0;structpim_instance*pim;structpim_interface*pim_ifp;pim_ifp=ch->
interface->info;pim=pim_ifp->pim;if(PIM_DEBUG_PIM_TRACE){charsource_str[INET_ADD
RSTRLEN];chargroup_str[INET_ADDRSTRLEN];charupstream_str[INET_ADDRSTRLEN];pim_in
et4_dump("<source?>",ch->sg.src,source_str,sizeof(source_str));pim_inet4_dump("<
group?>",ch->sg.grp,group_str,sizeof(group_str));pim_inet4_dump("<upstream?>",up
->upstream_addr,upstream_str,sizeof(upstream_str));zlog_debug("%s:(S,G)=(%s,%s)o
if=%s(%s)",__PRETTY_FUNCTION__,source_str,group_str,ch->interface->name,upstream
_str);}/*ResolveIIFforupstreamasmroute_delsetsmfcc_parenttoMAXVIFS,aspartofmrout
e_delcalledbypim_forward_stop.*/if(!up->channel_oil||(up->channel_oil&&up->chann
el_oil->oil.mfcc_parent>=MAXVIFS)){structprefixnht_p,src,grp;structpim_nexthop_c
acheout_pnc;/*RegisteraddrwithZebraNHT*/nht_p.family=AF_INET;nht_p.prefixlen=IPV
4_MAX_BITLEN;nht_p.u.prefix4.s_addr=up->upstream_addr.s_addr;grp.family=AF_INET;
grp.prefixlen=IPV4_MAX_BITLEN;grp.u.prefix4=up->sg.grp;memset(&out_pnc,0,sizeof(
structpim_nexthop_cache));if(pim_find_or_track_nexthop(pim,&nht_p,NULL,NULL,&out
_pnc)){if(out_pnc.nexthop_num){src.family=AF_INET;src.prefixlen=IPV4_MAX_BITLEN;
src.u.prefix4=up->upstream_addr;//RPorSrcaddressgrp.family=AF_INET;grp.prefixlen
=IPV4_MAX_BITLEN;grp.u.prefix4=up->sg.grp;//ComputePIMRPFusingCachednexthopif(pi
m_ecmp_nexthop_search(pim,&out_pnc,&up->rpf.source_nexthop,&src,&grp,0))input_if
ace_vif_index=pim_if_find_vifindex_by_ifindex(pim,up->rpf.source_nexthop.interfa
ce->ifindex);else{if(PIM_DEBUG_TRACE)zlog_debug("%s:Nexthopselectionfailedfor%s"
,__PRETTY_FUNCTION__,up->sg_str);}}else{if(PIM_DEBUG_ZEBRA){charbuf1[INET_ADDRST
RLEN];charbuf2[INET_ADDRSTRLEN];pim_inet4_dump("<source?>",nht_p.u.prefix4,buf1,
sizeof(buf1));pim_inet4_dump("<source?>",grp.u.prefix4,buf2,sizeof(buf2));zlog_d
ebug("%s:NHTpncisNULLforaddr%sgrp%s",__PRETTY_FUNCTION__,buf1,buf2);}}}elseinput
_iface_vif_index=pim_ecmp_fib_lookup_if_vif_index(pim,up->upstream_addr,&src,&gr
p);if(input_iface_vif_index<1){if(PIM_DEBUG_PIM_TRACE){charsource_str[INET_ADDRS
TRLEN];pim_inet4_dump("<source?>",up->sg.src,source_str,sizeof(source_str));zlog
_debug("%s%s:couldnotfindinputinterfaceforsource%s",__FILE__,__PRETTY_FUNCTION__
,source_str);}return;}if(PIM_DEBUG_TRACE){structinterface*in_intf=pim_if_find_by
_vif_index(pim,input_iface_vif_index);zlog_debug("%s:Updatechannel_oilIIF%sVIFI%
dentry%s",__PRETTY_FUNCTION__,in_intf?in_intf->name:"NIL",input_iface_vif_index,
up->sg_str);}up->channel_oil=pim_channel_oil_add(pim,&up->sg,input_iface_vif_ind
ex);if(!up->channel_oil){if(PIM_DEBUG_PIM_TRACE)zlog_debug("%s%s:couldnotcreateO
ILforchannel(S,G)=%s",__FILE__,__PRETTY_FUNCTION__,up->sg_str);return;}}if(up->f
lags&PIM_UPSTREAM_FLAG_MASK_SRC_IGMP)mask=PIM_OIF_FLAG_PROTO_IGMP;pim_channel_ad
d_oif(up->channel_oil,ch->interface,mask);}voidpim_forward_stop(structpim_ifchan
nel*ch,boolinstall_it){structpim_upstream*up=ch->upstream;if(PIM_DEBUG_PIM_TRACE
){zlog_debug("%s:(S,G)=%soif=%sinstall_it:%dinstalled:%d",__PRETTY_FUNCTION__,ch
->sg_str,ch->interface->name,install_it,up->channel_oil->installed);}pim_channel
_del_oif(up->channel_oil,ch->interface,PIM_OIF_FLAG_PROTO_PIM);if(install_it&&!u
p->channel_oil->installed)pim_mroute_add(up->channel_oil,__PRETTY_FUNCTION__);}v
oidpim_zebra_zclient_update(structvty*vty){vty_out(vty,"Zclientupdatesocket:");i
f(zclient){vty_out(vty,"%dfailures=%d\n",zclient->sock,zclient->fail);}else{vty_
out(vty,"<nullzclient>\n");}}structzclient*pim_zebra_zclient_get(void){if(zclien
t)returnzclient;elsereturnNULL;}