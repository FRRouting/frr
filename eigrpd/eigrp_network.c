/**EIGRPNetworkRelatedFunctions.*Copyright(C)2013-2014*Authors:*DonnieSavage*Jan
Janovic*MatejPerina*PeterOrsag*PeterPaluch**ThisfileispartofGNUZebra.**GNUZebrai
sfreesoftware;youcanredistributeitand/ormodifyit*underthetermsoftheGNUGeneralPub
licLicenseaspublishedbythe*FreeSoftwareFoundation;eitherversion2,or(atyouroption
)any*laterversion.**GNUZebraisdistributedinthehopethatitwillbeuseful,but*WITHOUT
ANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSFORAPARTICUL
ARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Youshouldhavereceivedac
opyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefileCOPYING;ifnot,wri
tetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA02110-1301U
SA*/#include<zebra.h>#include"thread.h"#include"linklist.h"#include"prefix.h"#in
clude"if.h"#include"sockunion.h"#include"log.h"#include"sockopt.h"#include"privs
.h"#include"table.h"#include"vty.h"#include"eigrpd/eigrp_structs.h"#include"eigr
pd/eigrpd.h"#include"eigrpd/eigrp_interface.h"#include"eigrpd/eigrp_neighbor.h"#
include"eigrpd/eigrp_packet.h"#include"eigrpd/eigrp_zebra.h"#include"eigrpd/eigr
p_vty.h"#include"eigrpd/eigrp_network.h"staticinteigrp_network_match_iface(const
structconnected*,conststructprefix*);staticvoideigrp_network_run_interface(struc
teigrp*,structprefix*,structinterface*);inteigrp_sock_init(void){inteigrp_sock;i
ntret,hincl=1;if(eigrpd_privs.change(ZPRIVS_RAISE))zlog_err("eigrp_sock_init:cou
ldnotraiseprivs,%s",safe_strerror(errno));eigrp_sock=socket(AF_INET,SOCK_RAW,IPP
ROTO_EIGRPIGP);if(eigrp_sock<0){intsave_errno=errno;if(eigrpd_privs.change(ZPRIV
S_LOWER))zlog_err("eigrp_sock_init:couldnotlowerprivs,%s",safe_strerror(errno));
zlog_err("eigrp_read_sock_init:socket:%s",safe_strerror(save_errno));exit(1);}#i
fdefIP_HDRINCL/*wewillincludeIPheaderwithpacket*/ret=setsockopt(eigrp_sock,IPPRO
TO_IP,IP_HDRINCL,&hincl,sizeof(hincl));if(ret<0){intsave_errno=errno;if(eigrpd_p
rivs.change(ZPRIVS_LOWER))zlog_err("eigrp_sock_init:couldnotlowerprivs,%s",safe_
strerror(errno));zlog_warn("Can'tsetIP_HDRINCLoptionforfd%d:%s",eigrp_sock,safe_
strerror(save_errno));}#elifdefined(IPTOS_PREC_INTERNETCONTROL)#warning"IP_HDRIN
CLnotavailableonthissystem"#warning"usingIPTOS_PREC_INTERNETCONTROL"ret=setsocko
pt_ipv4_tos(eigrp_sock,IPTOS_PREC_INTERNETCONTROL);if(ret<0){intsave_errno=errno
;if(eigrpd_privs.change(ZPRIVS_LOWER))zlog_err("eigrpd_sock_init:couldnotlowerpr
ivs,%s",safe_strerror(errno));zlog_warn("can'tsetsockoptIP_TOS%dtosocket%d:%s",t
os,eigrp_sock,safe_strerror(save_errno));close(eigrp_sock);/*Preventsdleak.*/ret
urnret;}#else/*!IPTOS_PREC_INTERNETCONTROL*/#warning"IP_HDRINCLnotavailable,nori
sIPTOS_PREC_INTERNETCONTROL"zlog_warn("IP_HDRINCLoptionnotavailable");#endif/*IP
_HDRINCL*/ret=setsockopt_ifindex(AF_INET,eigrp_sock,1);if(ret<0)zlog_warn("Can't
setpktinfooptionforfd%d",eigrp_sock);if(eigrpd_privs.change(ZPRIVS_LOWER)){zlog_
err("eigrp_sock_init:couldnotlowerprivs,%s",safe_strerror(errno));}returneigrp_s
ock;}voideigrp_adjust_sndbuflen(structeigrp*eigrp,unsignedintbuflen){intnewbufle
n;/*Checkifanyworkhastobedoneatall.*/if(eigrp->maxsndbuflen>=buflen)return;if(ei
grpd_privs.change(ZPRIVS_RAISE))zlog_err("%s:couldnotraiseprivs,%s",__func__,saf
e_strerror(errno));/*NowwetrytosetSO_SNDBUFtowhatourcallerhasrequested*(theMTUof
anewlyaddedinterface).However,iftheOShas*truncatedtheactualbuffersizetosomewhatl
esssize,try*todetectitandupdateourrecordsappropriately.TheOS*mayallocatemorebuff
erspace,thanrequested,thisisn't*aerror.*/setsockopt_so_sendbuf(eigrp->fd,buflen)
;newbuflen=getsockopt_so_sendbuf(eigrp->fd);if(newbuflen<0||newbuflen<(int)bufle
n)zlog_warn("%s:triedtosetSO_SNDBUFto%u,butgot%d",__func__,buflen,newbuflen);if(
newbuflen>=0)eigrp->maxsndbuflen=(unsignedint)newbuflen;elsezlog_warn("%s:failed
togetSO_SNDBUF",__func__);if(eigrpd_privs.change(ZPRIVS_LOWER))zlog_err("%s:coul
dnotlowerprivs,%s",__func__,safe_strerror(errno));}inteigrp_if_ipmulticast(struc
teigrp*top,structprefix*p,unsignedintifindex){uint8_tval;intret,len;val=0;len=si
zeof(val);/*Preventreceivingself-originedmulticastpackets.*/ret=setsockopt(top->
fd,IPPROTO_IP,IP_MULTICAST_LOOP,(void*)&val,len);if(ret<0)zlog_warn("can'tsetsoc
koptIP_MULTICAST_LOOP(0)forfd%d:%s",top->fd,safe_strerror(errno));/*Explicitlyse
tmulticastttlto1--endo.*/val=1;ret=setsockopt(top->fd,IPPROTO_IP,IP_MULTICAST_TT
L,(void*)&val,len);if(ret<0)zlog_warn("can'tsetsockoptIP_MULTICAST_TTL(1)forfd%d
:%s",top->fd,safe_strerror(errno));ret=setsockopt_ipv4_multicast_if(top->fd,p->u
.prefix4,ifindex);if(ret<0)zlog_warn("can'tsetsockoptIP_MULTICAST_IF(fd%d,addr%s
,""ifindex%u):%s",top->fd,inet_ntoa(p->u.prefix4),ifindex,safe_strerror(errno));
returnret;}/*JointotheEIGRPmulticastgroup.*/inteigrp_if_add_allspfrouters(struct
eigrp*top,structprefix*p,unsignedintifindex){intret;ret=setsockopt_ipv4_multicas
t(top->fd,IP_ADD_MEMBERSHIP,p->u.prefix4,htonl(EIGRP_MULTICAST_ADDRESS),ifindex)
;if(ret<0)zlog_warn("can'tsetsockoptIP_ADD_MEMBERSHIP(fd%d,addr%s,""ifindex%u,Al
lSPFRouters):%s;perhapsakernellimit""on#ofmulticastgroupmembershipshasbeenexceed
ed?",top->fd,inet_ntoa(p->u.prefix4),ifindex,safe_strerror(errno));elsezlog_debu
g("interface%s[%u]joinEIGRPMulticastgroup.",inet_ntoa(p->u.prefix4),ifindex);ret
urnret;}inteigrp_if_drop_allspfrouters(structeigrp*top,structprefix*p,unsignedin
tifindex){intret;ret=setsockopt_ipv4_multicast(top->fd,IP_DROP_MEMBERSHIP,p->u.p
refix4,htonl(EIGRP_MULTICAST_ADDRESS),ifindex);if(ret<0)zlog_warn("can'tsetsocko
ptIP_DROP_MEMBERSHIP(fd%d,addr%s,""ifindex%u,AllSPFRouters):%s",top->fd,inet_nto
a(p->u.prefix4),ifindex,safe_strerror(errno));elsezlog_debug("interface%s[%u]lea
veEIGRPMulticastgroup.",inet_ntoa(p->u.prefix4),ifindex);returnret;}inteigrp_net
work_set(structeigrp*eigrp,structprefix*p){structvrf*vrf=vrf_lookup_by_id(VRF_DE
FAULT);structroute_node*rn;structinterface*ifp;rn=route_node_get(eigrp->networks
,(structprefix*)p);if(rn->info){/*Thereisalreadysamenetworkstatement.*/route_unl
ock_node(rn);return0;}structprefix*pref=prefix_new();PREFIX_COPY_IPV4(pref,p);rn
->info=(void*)pref;/*ScheduleRouterIDUpdate.*/if(eigrp->router_id==0)eigrp_route
r_id_update(eigrp);/*Runnetworkconfignow.*//*Gettargetinterface.*/FOR_ALL_INTERF
ACES(vrf,ifp){zlog_debug("Settingup%s",ifp->name);eigrp_network_run_interface(ei
grp,p,ifp);}return1;}/*Checkwhetherinterfacematchesgivennetwork*returns:1,true.0
,false*/staticinteigrp_network_match_iface(conststructconnected*co,conststructpr
efix*net){/*newapproach:moreelegantandconceptuallyclean*/returnprefix_match_netw
ork_statement(net,CONNECTED_PREFIX(co));}staticvoideigrp_network_run_interface(s
tructeigrp*eigrp,structprefix*p,structinterface*ifp){structeigrp_interface*ei;st
ructlistnode*cnode;structconnected*co;/*ifinterfaceprefixismatchspecifiedprefix,
thencreatesocketandjoinmulticastgroup.*/for(ALL_LIST_ELEMENTS_RO(ifp->connected,
cnode,co)){if(CHECK_FLAG(co->flags,ZEBRA_IFA_SECONDARY))continue;if(p->family==c
o->address->family&&!ifp->info&&eigrp_network_match_iface(co,p)){ei=eigrp_if_new
(eigrp,ifp,co->address);ei->connected=co;/*Relateeigrpinterfacetoeigrpinstance.*
/ei->eigrp=eigrp;/*ifrouter_idisnotconfigured,dontbringup*interfaces.*eigrp_rout
er_id_update()willcalleigrp_if_update*wheneverr-idisconfiguredinstead.*/if(if_is
_operative(ifp))eigrp_if_up(ei);}}}voideigrp_if_update(structinterface*ifp){stru
ctlistnode*node,*nnode;structroute_node*rn;structeigrp*eigrp;/**Intheeventtherea
remultipleeigrpautonymnoussystemsrunning,*weneedtocheckeaconeandaddtheinterfacea
sapproperate*/for(ALL_LIST_ELEMENTS(eigrp_om->eigrp,node,nnode,eigrp)){/*EIGRPmu
stbeonandRouter-IDmustbeconfigured.*/if(!eigrp||eigrp->router_id==0)continue;/*R
uneachnetworkforthisinterface.*/for(rn=route_top(eigrp->networks);rn;rn=route_ne
xt(rn))if(rn->info!=NULL){eigrp_network_run_interface(eigrp,&rn->p,ifp);}}}intei
grp_network_unset(structeigrp*eigrp,structprefix*p){structroute_node*rn;structli
stnode*node,*nnode;structeigrp_interface*ei;structprefix*pref;rn=route_node_look
up(eigrp->networks,p);if(rn==NULL)return0;pref=rn->info;route_unlock_node(rn);if
(!IPV4_ADDR_SAME(&pref->u.prefix4,&p->u.prefix4))return0;prefix_ipv4_free(rn->in
fo);rn->info=NULL;route_unlock_node(rn);/*initialreference*//*Findinterfacesthat
notconfiguredalready.*/for(ALL_LIST_ELEMENTS(eigrp->eiflist,node,nnode,ei)){intf
ound=0;structconnected*co=ei->connected;for(rn=route_top(eigrp->networks);rn;rn=
route_next(rn)){if(rn->info==NULL)continue;if(eigrp_network_match_iface(co,&rn->
p)){found=1;route_unlock_node(rn);break;}}if(found==0){eigrp_if_free(ei,INTERFAC
E_DOWN_BY_VTY);}}return1;}uint32_teigrp_calculate_metrics(structeigrp*eigrp,stru
cteigrp_metricsmetric){uint64_ttemp_metric;temp_metric=0;if(metric.delay==EIGRP_
MAX_METRIC)returnEIGRP_MAX_METRIC;//EIGRPMetric=//{K1*BW+[(K2*BW)/(256-load)]+(K
3*delay)}*{K5/(reliability+K4)}if(eigrp->k_values[0])temp_metric+=(eigrp->k_valu
es[0]*metric.bandwidth);if(eigrp->k_values[1])temp_metric+=((eigrp->k_values[1]*
metric.bandwidth)/(256-metric.load));if(eigrp->k_values[2])temp_metric+=(eigrp->
k_values[2]*metric.delay);if(eigrp->k_values[3]&&!eigrp->k_values[4])temp_metric
*=eigrp->k_values[3];if(!eigrp->k_values[3]&&eigrp->k_values[4])temp_metric*=(ei
grp->k_values[4]/metric.reliability);if(eigrp->k_values[3]&&eigrp->k_values[4])t
emp_metric*=((eigrp->k_values[4]/metric.reliability)+eigrp->k_values[3]);if(temp
_metric<=EIGRP_MAX_METRIC)return(uint32_t)temp_metric;elsereturnEIGRP_MAX_METRIC
;}uint32_teigrp_calculate_total_metrics(structeigrp*eigrp,structeigrp_nexthop_en
try*entry){structeigrp_interface*ei=entry->ei;entry->total_metric=entry->reporte
d_metric;uint64_ttemp_delay=(uint64_t)entry->total_metric.delay+(uint64_t)eigrp_
delay_to_scaled(ei->params.delay);entry->total_metric.delay=temp_delay>EIGRP_MAX
_METRIC?EIGRP_MAX_METRIC:(uint32_t)temp_delay;uint32_tbw=eigrp_bandwidth_to_scal
ed(ei->params.bandwidth);entry->total_metric.bandwidth=entry->total_metric.bandw
idth>bw?bw:entry->total_metric.bandwidth;returneigrp_calculate_metrics(eigrp,ent
ry->total_metric);}uint8_teigrp_metrics_is_same(structeigrp_metricsmetric1,struc
teigrp_metricsmetric2){if((metric1.bandwidth==metric2.bandwidth)&&(metric1.delay
==metric2.delay)&&(metric1.hop_count==metric2.hop_count)&&(metric1.load==metric2
.load)&&(metric1.reliability==metric2.reliability)&&(metric1.mtu[0]==metric2.mtu
[0])&&(metric1.mtu[1]==metric2.mtu[1])&&(metric1.mtu[2]==metric2.mtu[2]))return1
;return0;//ifdifferent}voideigrp_external_routes_refresh(structeigrp*eigrp,intty
pe){}