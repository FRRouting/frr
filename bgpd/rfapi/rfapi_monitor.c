/***Copyright2009-2016,LabNConsulting,L.L.C.***Thisprogramisfreesoftware;youcanr
edistributeitand/or*modifyitunderthetermsoftheGNUGeneralPublicLicense*aspublishe
dbytheFreeSoftwareFoundation;eitherversion2*oftheLicense,or(atyouroption)anylate
rversion.**Thisprogramisdistributedinthehopethatitwillbeuseful,*butWITHOUTANYWAR
RANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSFORAPARTICULARPURP
OSE.Seethe*GNUGeneralPublicLicenseformoredetails.**Youshouldhavereceivedacopyoft
heGNUGeneralPublicLicensealong*withthisprogram;seethefileCOPYING;ifnot,writetoth
eFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA02110-1301USA*//*
*File:rfapi_monitor.c*//*TBDremoveunneededincludes*/#include<errno.h>#include"li
b/zebra.h"#include"lib/prefix.h"#include"lib/table.h"#include"lib/vty.h"#include
"lib/memory.h"#include"lib/log.h"#include"lib/table.h"#include"lib/skiplist.h"#i
nclude"bgpd/bgpd.h"#include"bgpd/rfapi/bgp_rfapi_cfg.h"#include"bgpd/rfapi/rfapi
.h"#include"bgpd/rfapi/rfapi_backend.h"#include"bgpd/rfapi/rfapi.h"#include"bgpd
/rfapi/rfapi_import.h"#include"bgpd/rfapi/vnc_import_bgp.h"#include"bgpd/rfapi/r
fapi_private.h"#include"bgpd/rfapi/rfapi_monitor.h"#include"bgpd/rfapi/rfapi_vty
.h"#include"bgpd/rfapi/rfapi_rib.h"#include"bgpd/rfapi/vnc_debug.h"#defineDEBUG_
L2_EXTRA0#defineDEBUG_DUP_CHECK0#defineDEBUG_ETH_SL0staticvoidrfapiMonitorTimerR
estart(structrfapi_monitor_vpn*m);staticvoidrfapiMonitorEthTimerRestart(structrf
api_monitor_eth*m);/**Forwarddeclarations*/staticvoidrfapiMonitorEthDetachImport
(structbgp*bgp,structrfapi_monitor_eth*mon);#ifDEBUG_ETH_SL/**Debugfunction,spec
ialcase*/voidrfapiMonitorEthSlCheck(structroute_node*rn,constchar*tag1,constchar
*tag2){structroute_node*rn_saved=NULL;staticstructskiplist*sl_saved=NULL;structs
kiplist*sl;if(!rn)return;if(rn_saved&&(rn!=rn_saved))return;if(!rn_saved)rn_save
d=rn;sl=RFAPI_MONITOR_ETH(rn);if(sl||sl_saved){vnc_zlog_debug_verbose("%s[%s%s]:
rn=%p,rn->lock=%d,oldsl=%p,newsl=%p",__func__,(tag1?tag1:""),(tag2?tag2:""),rn,r
n->lock,sl_saved,sl);sl_saved=sl;}}#endif/**Debuggingfunctionthatabortswhenitfin
dsmonitorswhose*"next"pointer*referencesthemselves*/voidrfapiMonitorLoopCheck(st
ructrfapi_monitor_vpn*mchain){structrfapi_monitor_vpn*m;for(m=mchain;m;m=m->next
)assert(m!=m->next);}#ifDEBUG_DUP_CHECK/**Debuggingcode:seeifamonitorismentioned
morethanonce*inaHD'smonitorlist*/voidrfapiMonitorDupCheck(structbgp*bgp){structl
istnode*hnode;structrfapi_descriptor*rfd;for(ALL_LIST_ELEMENTS_RO(&bgp->rfapi->d
escriptors,hnode,rfd)){structroute_node*mrn;if(!rfd->mon)continue;for(mrn=route_
top(rfd->mon);mrn;mrn=route_next(mrn)){structrfapi_monitor_vpn*m;for(m=(structrf
api_monitor_vpn*)(mrn->info);m;m=m->next)m->dcount=0;}}for(ALL_LIST_ELEMENTS_RO(
&bgp->rfapi->descriptors,hnode,rfd)){structroute_node*mrn;if(!rfd->mon)continue;
for(mrn=route_top(rfd->mon);mrn;mrn=route_next(mrn)){structrfapi_monitor_vpn*m;f
or(m=(structrfapi_monitor_vpn*)(mrn->info);m;m=m->next)assert(++m->dcount==1);}}
}#endif/*debug*/voidrfapiMonitorCleanCheck(structbgp*bgp){structlistnode*hnode;s
tructrfapi_descriptor*rfd;for(ALL_LIST_ELEMENTS_RO(&bgp->rfapi->descriptors,hnod
e,rfd)){assert(!rfd->import_table->vpn0_queries[AFI_IP]);assert(!rfd->import_tab
le->vpn0_queries[AFI_IP6]);structroute_node*rn;for(rn=route_top(rfd->import_tabl
e->imported_vpn[AFI_IP]);rn;rn=route_next(rn)){assert(!RFAPI_MONITOR_VPN(rn));}f
or(rn=route_top(rfd->import_table->imported_vpn[AFI_IP6]);rn;rn=route_next(rn)){
assert(!RFAPI_MONITOR_VPN(rn));}}}/*debug*/voidrfapiMonitorCheckAttachAllowed(vo
id){structbgp*bgp=bgp_get_default();assert(!(bgp->rfapi_cfg->flags&BGP_VNC_CONFI
G_CALLBACK_DISABLE));}voidrfapiMonitorExtraFlush(safi_tsafi,structroute_node*rn)
{structrfapi_it_extra*hie;structrfapi_monitor_vpn*v;structrfapi_monitor_vpn*v_ne
xt;structrfapi_monitor_encap*e=NULL;structrfapi_monitor_encap*e_next=NULL;if(!rn
)return;if(!rn->aggregate)return;hie=(structrfapi_it_extra*)(rn->aggregate);swit
ch(safi){caseSAFI_ENCAP:for(e=hie->u.encap.e;e;e=e_next){e_next=e->next;e->next=
NULL;XFREE(MTYPE_RFAPI_MONITOR_ENCAP,e);route_unlock_node(rn);}hie->u.encap.e=NU
LL;break;caseSAFI_MPLS_VPN:for(v=hie->u.vpn.v;v;v=v_next){v_next=v->next;v->next
=NULL;XFREE(MTYPE_RFAPI_MONITOR,e);route_unlock_node(rn);}hie->u.vpn.v=NULL;if(h
ie->u.vpn.e.source){while(!skiplist_delete_first(hie->u.vpn.e.source)){route_unl
ock_node(rn);}skiplist_free(hie->u.vpn.e.source);hie->u.vpn.e.source=NULL;route_
unlock_node(rn);}if(hie->u.vpn.idx_rd){/*loopingthroughbi->extra->vnc.import.rdi
stbd*/while(!skiplist_delete_first(hie->u.vpn.idx_rd)){route_unlock_node(rn);}sk
iplist_free(hie->u.vpn.idx_rd);hie->u.vpn.idx_rd=NULL;route_unlock_node(rn);}if(
hie->u.vpn.mon_eth){while(!skiplist_delete_first(hie->u.vpn.mon_eth)){route_unlo
ck_node(rn);}skiplist_free(hie->u.vpn.mon_eth);hie->u.vpn.mon_eth=NULL;route_unl
ock_node(rn);}break;default:assert(0);}XFREE(MTYPE_RFAPI_IT_EXTRA,hie);rn->aggre
gate=NULL;route_unlock_node(rn);}/**Ifthechildlistsareempty,releasetherfapi_it_e
xtrastruct*/voidrfapiMonitorExtraPrune(safi_tsafi,structroute_node*rn){structrfa
pi_it_extra*hie;if(!rn)return;if(!rn->aggregate)return;hie=(structrfapi_it_extra
*)(rn->aggregate);switch(safi){caseSAFI_ENCAP:if(hie->u.encap.e)return;break;cas
eSAFI_MPLS_VPN:if(hie->u.vpn.v)return;if(hie->u.vpn.mon_eth){if(skiplist_count(h
ie->u.vpn.mon_eth))return;skiplist_free(hie->u.vpn.mon_eth);hie->u.vpn.mon_eth=N
ULL;route_unlock_node(rn);/*uncountskiplist*/}if(hie->u.vpn.e.source){if(skiplis
t_count(hie->u.vpn.e.source))return;skiplist_free(hie->u.vpn.e.source);hie->u.vp
n.e.source=NULL;route_unlock_node(rn);}if(hie->u.vpn.idx_rd){if(skiplist_count(h
ie->u.vpn.idx_rd))return;skiplist_free(hie->u.vpn.idx_rd);hie->u.vpn.idx_rd=NULL
;route_unlock_node(rn);}if(hie->u.vpn.mon_eth){if(skiplist_count(hie->u.vpn.mon_
eth))return;skiplist_free(hie->u.vpn.mon_eth);hie->u.vpn.mon_eth=NULL;route_unlo
ck_node(rn);}break;default:assert(0);}XFREE(MTYPE_RFAPI_IT_EXTRA,hie);rn->aggreg
ate=NULL;route_unlock_node(rn);}/**returnslockednode*/structroute_node*rfapiMoni
torGetAttachNode(structrfapi_descriptor*rfd,structprefix*p){afi_tafi;structroute
_node*rn;if(RFAPI_0_PREFIX(p)){assert(1);}afi=family2afi(p->family);assert(afi);
/**It'spossiblethateventhoughthereisarouteatthisnode,*therearenorouteswithvalidU
Naddresses(i.e,.withno*validtunnelroutes).Checkforthatandwalkbackupthe*treeifnec
essary.**Whentheouterloopcompletes,thematchednode,ifany,is*locked(i.e.,itsrefere
ncecounthasbeenincremented)to*accountfortheVPNmonitorweareabouttoattach.**ifamon
itorismovedtoanothernode,theremustbe*correspondingunlock/locks*/for(rn=route_nod
e_match(rfd->import_table->imported_vpn[afi],p);rn;){structbgp_info*bi;structpre
fixpfx_dummy;/*TBDupdatethiscodetousenewvalid_interior_count*/for(bi=rn->info;bi
;bi=bi->next){/**IfthereisacachedENCAPUNaddress,it'sausable*VPNroute*/if(bi->ext
ra&&bi->extra->vnc.import.un_family){break;}/**OrifthereisavalidEncapAttributetu
nnelsubtlv*address,*it'sausableVPNroute.*/if(!rfapiGetVncTunnelUnAddr(bi->attr,&
pfx_dummy)){break;}}if(bi)break;route_unlock_node(rn);if((rn=rn->parent)){route_
lock_node(rn);}}if(!rn){structprefixpfx_default;memset(&pfx_default,0,sizeof(pfx
_default));pfx_default.family=p->family;/*createsdefaultnodeifnoneexists,andincr
ementsrefcount*/rn=route_node_get(rfd->import_table->imported_vpn[afi],&pfx_defa
ult);}returnrn;}/**Ifthisfunctionhappenstoattachthemonitortoaradixtree*node(asop
posedtothe0-prefixlist),thenodepointeris*returned(forthebenefitofcallerwhichmigh
tliketouseit*togenerateanimmediatequeryresponse).*/staticstructroute_node*rfapiM
onitorAttachImport(structrfapi_descriptor*rfd,structrfapi_monitor_vpn*m){structr
oute_node*rn;rfapiMonitorCheckAttachAllowed();if(RFAPI_0_PREFIX(&m->p)){/**Addne
wmonitorentrytovpn0list*/afi_tafi;afi=family2afi(m->p.family);assert(afi);m->nex
t=rfd->import_table->vpn0_queries[afi];rfd->import_table->vpn0_queries[afi]=m;vn
c_zlog_debug_verbose("%s:attachedmonitor%ptovpn0list",__func__,m);returnNULL;}/*
*Attachnewmonitorentrytoimporttablenode*/rn=rfapiMonitorGetAttachNode(rfd,&m->p)
;/*returnslockedrn*/m->node=rn;m->next=RFAPI_MONITOR_VPN(rn);RFAPI_MONITOR_VPN_W
_ALLOC(rn)=m;RFAPI_CHECK_REFCOUNT(rn,SAFI_MPLS_VPN,0);vnc_zlog_debug_verbose("%s
:attachedmonitor%ptorn%p",__func__,m,rn);returnrn;}/**reattachmonitorsforthisHDt
oimporttable*/voidrfapiMonitorAttachImportHd(structrfapi_descriptor*rfd){structr
oute_node*mrn;if(!rfd->mon){/**NomonitorsforthisHD*/return;}for(mrn=route_top(rf
d->mon);mrn;mrn=route_next(mrn)){if(!mrn->info)continue;(void)rfapiMonitorAttach
Import(rfd,(structrfapi_monitor_vpn*)(mrn->info));}}/**Addsamonitorforaquerytoth
eNVEdescriptor'slist*and,ifcallbacksareenabled,attachesittotheimporttable.**Ifwe
happenedtolocatetheimporttableradixtreeattachment*point,returnitsothecallercanus
eittogenerateaquery*responsewithoutrepeatingthelookup.Notethatwhencallbacks*ared
isabled,thisfunctionwillnotperformalookup,andthe*callerwillhavetodoitsownlookup.
*/structroute_node*rfapiMonitorAdd(structbgp*bgp,structrfapi_descriptor*rfd,stru
ctprefix*p){structrfapi_monitor_vpn*m;structroute_node*rn;/**Initializenve'smoni
torlistifneeded*NBusethesameradixtreeforIPv4andIPv6targets.*Theprefixwillalwaysh
avefull-lengthmask(/32,/128)*orbe0/0sotheywon'tgetmixedup.*/if(!rfd->mon){rfd->m
on=route_table_init();}rn=route_node_get(rfd->mon,p);if(rn->info){/**receivedthi
squerybefore,nofurtheractionneeded*/rfapiMonitorTimerRestart((structrfapi_monito
r_vpn*)rn->info);route_unlock_node(rn);returnNULL;}/**Newqueryforthisnve,recordi
tintheHD*/rn->info=XCALLOC(MTYPE_RFAPI_MONITOR,sizeof(structrfapi_monitor_vpn));
m=(structrfapi_monitor_vpn*)(rn->info);m->rfd=rfd;prefix_copy(&m->p,p);++rfd->mo
nitor_count;++bgp->rfapi->monitor_count;rfapiMonitorTimerRestart(m);if(bgp->rfap
i_cfg->flags&BGP_VNC_CONFIG_CALLBACK_DISABLE){/**callbacksturnedoff,sodon'tattac
hmonitortoimporttable*/returnNULL;}/**attachtoimporttable*/returnrfapiMonitorAtt
achImport(rfd,m);}/**returnsmonitorpointeriffound,NULLifnot*/staticstructrfapi_m
onitor_vpn*rfapiMonitorDetachImport(structrfapi_monitor_vpn*m){structrfapi_monit
or_vpn*prev;structrfapi_monitor_vpn*this=NULL;if(RFAPI_0_PREFIX(&m->p)){afi_tafi
;/**0-prefixmonitorsarestoredinaspeciallistandnot*intheimportVPNtree*/afi=family
2afi(m->p.family);assert(afi);if(m->rfd->import_table){for(prev=NULL,this=m->rfd
->import_table->vpn0_queries[afi];this;prev=this,this=this->next){if(this==m)bre
ak;}if(this){if(!prev){m->rfd->import_table->vpn0_queries[afi]=this->next;}else{
prev->next=this->next;}}}}else{if(m->node){for(prev=NULL,this=RFAPI_MONITOR_VPN(
m->node);this;prev=this,this=this->next){if(this==m)break;}if(this){if(prev){pre
v->next=this->next;}else{RFAPI_MONITOR_VPN_W_ALLOC(m->node)=this->next;}RFAPI_CH
ECK_REFCOUNT(m->node,SAFI_MPLS_VPN,1);route_unlock_node(m->node);}m->node=NULL;}
}returnthis;}voidrfapiMonitorDetachImportHd(structrfapi_descriptor*rfd){structro
ute_node*rn;if(!rfd->mon)return;for(rn=route_top(rfd->mon);rn;rn=route_next(rn))
{if(rn->info){rfapiMonitorDetachImport((structrfapi_monitor_vpn*)(rn->info));}}}
voidrfapiMonitorDel(structbgp*bgp,structrfapi_descriptor*rfd,structprefix*p){str
uctroute_node*rn;structrfapi_monitor_vpn*m;assert(rfd->mon);rn=route_node_get(rf
d->mon,p);/*locksnode*/m=rn->info;assert(m);/**removefromimporttable*/if(!(bgp->
rfapi_cfg->flags&BGP_VNC_CONFIG_CALLBACK_DISABLE)){rfapiMonitorDetachImport(m);}
if(m->timer){thread_cancel(m->timer);m->timer=NULL;}/**removefromrfdlist*/XFREE(
MTYPE_RFAPI_MONITOR,m);rn->info=NULL;route_unlock_node(rn);/*undooriginallockwhe
ncreated*/route_unlock_node(rn);/*undolockinroute_node_get*/--rfd->monitor_count
;--bgp->rfapi->monitor_count;}/**returnscountofmonitorsdeleted*/intrfapiMonitorD
elHd(structrfapi_descriptor*rfd){structroute_node*rn;structbgp*bgp;intcount=0;vn
c_zlog_debug_verbose("%s:entryrfd=%p",__func__,rfd);bgp=bgp_get_default();if(rfd
->mon){for(rn=route_top(rfd->mon);rn;rn=route_next(rn)){structrfapi_monitor_vpn*
m;if((m=rn->info)){if(!(bgp->rfapi_cfg->flags&BGP_VNC_CONFIG_CALLBACK_DISABLE)){
rfapiMonitorDetachImport(m);}if(m->timer){thread_cancel(m->timer);m->timer=NULL;
}XFREE(MTYPE_RFAPI_MONITOR,m);rn->info=NULL;route_unlock_node(rn);/*undooriginal
lockwhencreated*/++count;--rfd->monitor_count;--bgp->rfapi->monitor_count;}}rout
e_table_finish(rfd->mon);rfd->mon=NULL;}if(rfd->mon_eth){structrfapi_monitor_eth
*mon_eth;while(!skiplist_first(rfd->mon_eth,NULL,(void**)&mon_eth)){intrc;if(!(b
gp->rfapi_cfg->flags&BGP_VNC_CONFIG_CALLBACK_DISABLE)){rfapiMonitorEthDetachImpo
rt(bgp,mon_eth);}else{#ifDEBUG_L2_EXTRAvnc_zlog_debug_verbose("%s:callbacksdisab
led,notattemptingtodetachmon_eth%p",__func__,mon_eth);#endif}if(mon_eth->timer){
thread_cancel(mon_eth->timer);mon_eth->timer=NULL;}/**removefromrfdlist*/rc=skip
list_delete(rfd->mon_eth,mon_eth,mon_eth);assert(!rc);vnc_zlog_debug_verbose("%s
:freeingmon_eth%p",__func__,mon_eth);XFREE(MTYPE_RFAPI_MONITOR_ETH,mon_eth);++co
unt;--rfd->monitor_count;--bgp->rfapi->monitor_count;}skiplist_free(rfd->mon_eth
);rfd->mon_eth=NULL;}returncount;}voidrfapiMonitorResponseRemovalOff(structbgp*b
gp){if(bgp->rfapi_cfg->flags&BGP_VNC_CONFIG_RESPONSE_REMOVAL_DISABLE){return;}bg
p->rfapi_cfg->flags|=BGP_VNC_CONFIG_RESPONSE_REMOVAL_DISABLE;}voidrfapiMonitorRe
sponseRemovalOn(structbgp*bgp){if(!(bgp->rfapi_cfg->flags&BGP_VNC_CONFIG_RESPONS
E_REMOVAL_DISABLE)){return;}bgp->rfapi_cfg->flags&=~BGP_VNC_CONFIG_RESPONSE_REMO
VAL_DISABLE;}staticintrfapiMonitorTimerExpire(structthread*t){structrfapi_monito
r_vpn*m=t->arg;/*forgetreferencetothread,it'sgone*/m->timer=NULL;/*deletethemoni
tor*/rfapiMonitorDel(bgp_get_default(),m->rfd,&m->p);return0;}staticvoidrfapiMon
itorTimerRestart(structrfapi_monitor_vpn*m){if(m->timer){unsignedlongremain=thre
ad_timer_remain_second(m->timer);/*unexpectedcase,butavoidwraparoundproblemsbelo
w*/if(remain>m->rfd->response_lifetime)return;/*don'trestartifwejustrestartedrec
ently*/if(m->rfd->response_lifetime-remain<2)return;thread_cancel(m->timer);m->t
imer=NULL;}{charbuf[BUFSIZ];vnc_zlog_debug_verbose("%s:target%slife%u",__func__,
rfapi_ntop(m->p.family,m->p.u.val,buf,BUFSIZ),m->rfd->response_lifetime);}m->tim
er=NULL;thread_add_timer(bm->master,rfapiMonitorTimerExpire,m,m->rfd->response_l
ifetime,&m->timer);}/**calledwhenanupdatedresponseissenttotheNVE.Per*ticket255,r
estarttimersforanymonitorsthatcouldhave*beenresponsiblefortheresponse,i.e.,anymo
nitorsfor*theexactprefixoraparentofit.*/voidrfapiMonitorTimersRestart(structrfap
i_descriptor*rfd,structprefix*p){structroute_node*rn;if(AF_ETHERNET==p->family){
structrfapi_monitor_eth*mon_eth;intrc;void*cursor;/**XXXmatchanyLNI*/for(cursor=
NULL,rc=skiplist_next(rfd->mon_eth,NULL,(void**)&mon_eth,&cursor);rc==0;rc=skipl
ist_next(rfd->mon_eth,NULL,(void**)&mon_eth,&cursor)){if(!memcmp(mon_eth->macadd
r.octet,p->u.prefix_eth.octet,ETH_ALEN)){rfapiMonitorEthTimerRestart(mon_eth);}}
}else{for(rn=route_top(rfd->mon);rn;rn=route_next(rn)){structrfapi_monitor_vpn*m
;if(!((m=rn->info)))continue;/*NBorderoftestissignificant!*/if(!m->node||prefix_
match(&m->node->p,p)){rfapiMonitorTimerRestart(m);}}}}/**Findmonitorsatthisnodea
ndallitsparents.Call*rfapiRibUpdatePendingNodewiththisnodeandallcorrespondingNVE
s.*/voidrfapiMonitorItNodeChanged(structrfapi_import_table*import_table,structro
ute_node*it_node,structrfapi_monitor_vpn*monitor_list)/*forbaseitnode,NULL=all*/
{structskiplist*nves_seen;structroute_node*rn=it_node;structbgp*bgp=bgp_get_defa
ult();afi_tafi=family2afi(rn->p.family);#ifDEBUG_L2_EXTRAcharbuf_prefix[PREFIX_S
TRLEN];#endifassert(bgp);assert(import_table);nves_seen=skiplist_new(0,NULL,NULL
);#ifDEBUG_L2_EXTRAprefix2str(&it_node->p,buf_prefix,sizeof(buf_prefix));vnc_zlo
g_debug_verbose("%s:it=%p,it_node=%p,it_node->prefix=%s",__func__,import_table,i
t_node,buf_prefix);#endifif(AFI_L2VPN==afi){structrfapi_monitor_eth*m;structskip
list*sl;void*cursor;intrc;if((sl=RFAPI_MONITOR_ETH(rn))){for(cursor=NULL,rc=skip
list_next(sl,NULL,(void**)&m,(void**)&cursor);!rc;rc=skiplist_next(sl,NULL,(void
**)&m,(void**)&cursor)){if(skiplist_search(nves_seen,m->rfd,NULL)){/**Haven'tdon
ethisNVEyet.Addto*"seen"list.*/assert(!skiplist_insert(nves_seen,m->rfd,NULL));/
**updateitsRIB*/rfapiRibUpdatePendingNode(bgp,m->rfd,import_table,it_node,m->rfd
->response_lifetime);}}}}else{structrfapi_monitor_vpn*m;if(monitor_list){m=monit
or_list;}else{m=RFAPI_MONITOR_VPN(rn);}do{/**Ifwehavereachedtherootnode(parent==
NULL)and*there*arenorouteshere(info==NULL),andtheITnodethat*changedwasnottheroot
node(it_node->parent!=*NULL),*thenanymonitorsatthisnodeareherebecausethey*had*no
matchatall.Therefore,donotsendrouteupdates*tothem*becausewehaven'tsentthemaninit
ialroute.*/if(!rn->parent&&!rn->info&&it_node->parent)break;for(;m;m=m->next){if
(RFAPI_0_PREFIX(&m->p)){/*shouldn'thappen,butbesafe*/continue;}if(skiplist_searc
h(nves_seen,m->rfd,NULL)){/**Haven'tdonethisNVEyet.Addto*"seen"list.*/assert(!sk
iplist_insert(nves_seen,m->rfd,NULL));charbuf_attach_pfx[PREFIX_STRLEN];charbuf_
target_pfx[PREFIX_STRLEN];prefix2str(&m->node->p,buf_attach_pfx,sizeof(buf_attac
h_pfx));prefix2str(&m->p,buf_target_pfx,sizeof(buf_target_pfx));vnc_zlog_debug_v
erbose("%s:updaterfd%pattachedtopfx%s(targ=%s)",__func__,m->rfd,buf_attach_pfx,b
uf_target_pfx);/**updateitsRIB*/rfapiRibUpdatePendingNode(bgp,m->rfd,import_tabl
e,it_node,m->rfd->response_lifetime);}}rn=rn->parent;if(rn)m=RFAPI_MONITOR_VPN(r
n);}while(rn);}/**All-routesL2monitors*/if(AFI_L2VPN==afi){structrfapi_monitor_e
th*e;#ifDEBUG_L2_EXTRAvnc_zlog_debug_verbose("%s:checkingL2all-routesmonitors",_
_func__);#endiffor(e=import_table->eth0_queries;e;e=e->next){#ifDEBUG_L2_EXTRAvn
c_zlog_debug_verbose("%s:checkingeth0mon=%p",__func__,e);#endifif(skiplist_searc
h(nves_seen,e->rfd,NULL)){/**Haven'tdonethisNVEyet.Addto"seen"*list.*/assert(!sk
iplist_insert(nves_seen,e->rfd,NULL));/**updateitsRIB*/#ifDEBUG_L2_EXTRAvnc_zlog
_debug_verbose("%s:foundL2all-routesmonitor%p",__func__,e);#endifrfapiRibUpdateP
endingNode(bgp,e->rfd,import_table,it_node,e->rfd->response_lifetime);}}}else{st
ructrfapi_monitor_vpn*m;/**All-routesIPv4.IPv6monitors*/for(m=import_table->vpn0
_queries[afi];m;m=m->next){if(skiplist_search(nves_seen,m->rfd,NULL)){/**Haven't
donethisNVEyet.Addto"seen"*list.*/assert(!skiplist_insert(nves_seen,m->rfd,NULL)
);/**updateitsRIB*/rfapiRibUpdatePendingNode(bgp,m->rfd,import_table,it_node,m->
rfd->response_lifetime);}}}skiplist_free(nves_seen);}/**Forthelistedmonitors,upd
atenewnodeanditssubtree,but*omitoldnodeanditssubtree*/voidrfapiMonitorMovedUp(st
ructrfapi_import_table*import_table,structroute_node*old_node,structroute_node*n
ew_node,structrfapi_monitor_vpn*monitor_list){structbgp*bgp=bgp_get_default();st
ructrfapi_monitor_vpn*m;assert(new_node);assert(old_node);assert(new_node!=old_n
ode);/**Ifnewnodeis0/0andthereisnoroutethere,don't*generateanupdatebecauseitwill
notcontainany*routesincludingthetarget.*/if(!new_node->parent&&!new_node->info){
vnc_zlog_debug_verbose("%s:newmonitorat0/0andnoroutes,noupdates",__func__);retur
n;}for(m=monitor_list;m;m=m->next){rfapiRibUpdatePendingNode(bgp,m->rfd,import_t
able,new_node,m->rfd->response_lifetime);rfapiRibUpdatePendingNodeSubtree(bgp,m-
>rfd,import_table,new_node,old_node,m->rfd->response_lifetime);}}staticintrfapiM
onitorEthTimerExpire(structthread*t){structrfapi_monitor_eth*m=t->arg;/*forgetre
ferencetothread,it'sgone*/m->timer=NULL;/*deletethemonitor*/rfapiMonitorEthDel(b
gp_get_default(),m->rfd,&m->macaddr,m->logical_net_id);return0;}staticvoidrfapiM
onitorEthTimerRestart(structrfapi_monitor_eth*m){if(m->timer){unsignedlongremain
=thread_timer_remain_second(m->timer);/*unexpectedcase,butavoidwraparoundproblem
sbelow*/if(remain>m->rfd->response_lifetime)return;/*don'trestartifwejustrestart
edrecently*/if(m->rfd->response_lifetime-remain<2)return;thread_cancel(m->timer)
;m->timer=NULL;}{charbuf[BUFSIZ];vnc_zlog_debug_verbose("%s:target%slife%u",__fu
nc__,rfapiEthAddr2Str(&m->macaddr,buf,BUFSIZ),m->rfd->response_lifetime);}m->tim
er=NULL;thread_add_timer(bm->master,rfapiMonitorEthTimerExpire,m,m->rfd->respons
e_lifetime,&m->timer);}staticintmon_eth_cmp(void*a,void*b){structrfapi_monitor_e
th*m1;structrfapi_monitor_eth*m2;inti;m1=(structrfapi_monitor_eth*)a;m2=(structr
fapi_monitor_eth*)b;/**compareethernetaddresses*/for(i=0;i<ETH_ALEN;++i){if(m1->
macaddr.octet[i]!=m2->macaddr.octet[i])return(m1->macaddr.octet[i]-m2->macaddr.o
ctet[i]);}/**compareLNIs*/return(m1->logical_net_id-m2->logical_net_id);}staticv
oidrfapiMonitorEthAttachImport(structrfapi_import_table*it,structroute_node*rn,/
*itnodeattachpointifnon-0*/structrfapi_monitor_eth*mon)/*monitorstructtoattach*/
{structskiplist*sl;intrc;vnc_zlog_debug_verbose("%s:it=%p",__func__,it);rfapiMon
itorCheckAttachAllowed();if(RFAPI_0_ETHERADDR(&mon->macaddr)){/**Thesegoonadiffe
rentlist*/mon->next=it->eth0_queries;it->eth0_queries=mon;#ifDEBUG_L2_EXTRAvnc_z
log_debug_verbose("%s:attachedmonitor%ptoeth0list",__func__,mon);#endifreturn;}i
f(rn==NULL){#ifDEBUG_L2_EXTRAvnc_zlog_debug_verbose("%s:rnisnull!",__func__);#en
difreturn;}/**Getsltoattachto*/sl=RFAPI_MONITOR_ETH_W_ALLOC(rn);if(!sl){sl=RFAPI
_MONITOR_ETH_W_ALLOC(rn)=skiplist_new(0,NULL,NULL);route_lock_node(rn);/*countsk
iplistmon_eth*/}#ifDEBUG_L2_EXTRAvnc_zlog_debug_verbose("%s:rn=%p,rn->lock=%d,sl
=%p,attachingethmon%p",__func__,rn,rn->lock,sl,mon);#endifrc=skiplist_insert(sl,
(void*)mon,(void*)mon);assert(!rc);/*countethmonitor*/route_lock_node(rn);}/**re
attachmonitorsforthisHDtoimporttable*/staticvoidrfapiMonitorEthAttachImportHd(st
ructbgp*bgp,structrfapi_descriptor*rfd){void*cursor;structrfapi_monitor_eth*mon;
intrc;if(!rfd->mon_eth){/**NomonitorsforthisHD*/return;}for(cursor=NULL,rc=skipl
ist_next(rfd->mon_eth,NULL,(void**)&mon,&cursor);rc==0;rc=skiplist_next(rfd->mon
_eth,NULL,(void**)&mon,&cursor)){structrfapi_import_table*it;structprefixpfx_mac
_buf;structroute_node*rn;it=rfapiMacImportTableGet(bgp,mon->logical_net_id);asse
rt(it);memset((void*)&pfx_mac_buf,0,sizeof(structprefix));pfx_mac_buf.family=AF_
ETHERNET;pfx_mac_buf.prefixlen=48;pfx_mac_buf.u.prefix_eth=mon->macaddr;rn=route
_node_get(it->imported_vpn[AFI_L2VPN],&pfx_mac_buf);assert(rn);(void)rfapiMonito
rEthAttachImport(it,rn,mon);}}staticvoidrfapiMonitorEthDetachImport(structbgp*bg
p,structrfapi_monitor_eth*mon)/*monitorstructtodetach*/{structrfapi_import_table
*it;structprefixpfx_mac_buf;structskiplist*sl;structroute_node*rn;intrc;it=rfapi
MacImportTableGet(bgp,mon->logical_net_id);assert(it);if(RFAPI_0_ETHERADDR(&mon-
>macaddr)){structrfapi_monitor_eth*prev;structrfapi_monitor_eth*this=NULL;for(pr
ev=NULL,this=it->eth0_queries;this;prev=this,this=this->next){if(this==mon)break
;}if(this){if(!prev){it->eth0_queries=this->next;}else{prev->next=this->next;}}#
ifDEBUG_L2_EXTRAvnc_zlog_debug_verbose("%s:it=%p,LNI=%d,detachedeth0mon%p",__fun
c__,it,mon->logical_net_id,mon);#endifreturn;}memset((void*)&pfx_mac_buf,0,sizeo
f(structprefix));pfx_mac_buf.family=AF_ETHERNET;pfx_mac_buf.prefixlen=48;pfx_mac
_buf.u.prefix_eth=mon->macaddr;rn=route_node_get(it->imported_vpn[AFI_L2VPN],&pf
x_mac_buf);assert(rn);#ifDEBUG_L2_EXTRAcharbuf_prefix[PREFIX_STRLEN];prefix2str(
&rn->p,buf_prefix,sizeof(buf_prefix));#endif/**Getsltodetachfrom*/sl=RFAPI_MONIT
OR_ETH(rn);#ifDEBUG_L2_EXTRAvnc_zlog_debug_verbose("%s:it=%p,rn=%p,rn->lock=%d,s
l=%p,pfx=%s,LNI=%d,detachingethmon%p",__func__,it,rn,rn->lock,sl,buf_prefix,mon-
>logical_net_id,mon);#endifassert(sl);rc=skiplist_delete(sl,(void*)mon,(void*)mo
n);assert(!rc);/*uncountethmonitor*/route_unlock_node(rn);}structroute_node*rfap
iMonitorEthAdd(structbgp*bgp,structrfapi_descriptor*rfd,structethaddr*macaddr,ui
nt32_tlogical_net_id){intrc;structrfapi_monitor_ethmon_buf;structrfapi_monitor_e
th*val;structrfapi_import_table*it;structroute_node*rn=NULL;structprefixpfx_mac_
buf;if(!rfd->mon_eth){rfd->mon_eth=skiplist_new(0,mon_eth_cmp,NULL);}it=rfapiMac
ImportTableGet(bgp,logical_net_id);assert(it);/**Getroutenodeinimporttable.Herei
swhereweattachthe*monitor.**Lookitupnowbecausewereturnittocallerregardlessof*whe
therwecreateanewmonitorornot.*/memset((void*)&pfx_mac_buf,0,sizeof(structprefix)
);pfx_mac_buf.family=AF_ETHERNET;pfx_mac_buf.prefixlen=48;pfx_mac_buf.u.prefix_e
th=*macaddr;if(!RFAPI_0_ETHERADDR(macaddr)){rn=route_node_get(it->imported_vpn[A
FI_L2VPN],&pfx_mac_buf);assert(rn);}memset((void*)&mon_buf,0,sizeof(mon_buf));mo
n_buf.rfd=rfd;mon_buf.macaddr=*macaddr;mon_buf.logical_net_id=logical_net_id;{ch
arbuf[BUFSIZ];vnc_zlog_debug_verbose("%s:LNI=%d:rfd=%p,pfx=%s",__func__,logical_
net_id,rfd,rfapi_ntop(pfx_mac_buf.family,pfx_mac_buf.u.val,buf,BUFSIZ));}/**look
upquery*/rc=skiplist_search(rfd->mon_eth,(void*)&mon_buf,(void**)&val);if(!rc){/
**Foundmonitor-wehaveseenthisquerybefore*restarttimer*/vnc_zlog_debug_verbose("%
s:alreadypresentinrfd->mon_eth,notadding",__func__);rfapiMonitorEthTimerRestart(
val);returnrn;}/**Newquery*/val=XCALLOC(MTYPE_RFAPI_MONITOR_ETH,sizeof(structrfa
pi_monitor_eth));assert(val);*val=mon_buf;++rfd->monitor_count;++bgp->rfapi->mon
itor_count;rc=skiplist_insert(rfd->mon_eth,val,val);#ifDEBUG_L2_EXTRAvnc_zlog_de
bug_verbose("%s:insertedrfd=%pmon_eth=%p,rc=%d",__func__,rfd,val,rc);#else(void)
rc;#endif/**starttimer*/rfapiMonitorEthTimerRestart(val);if(bgp->rfapi_cfg->flag
s&BGP_VNC_CONFIG_CALLBACK_DISABLE){/**callbacksturnedoff,sodon'tattachmonitortoi
mporttable*/#ifDEBUG_L2_EXTRAvnc_zlog_debug_verbose("%s:callbacksturnedoff,notat
tachingmon_eth%ptoimporttable",__func__,val);#endifreturnrn;}/**attachtoimportta
ble*/rfapiMonitorEthAttachImport(it,rn,val);returnrn;}voidrfapiMonitorEthDel(str
uctbgp*bgp,structrfapi_descriptor*rfd,structethaddr*macaddr,uint32_tlogical_net_
id){structrfapi_monitor_eth*val;structrfapi_monitor_ethmon_buf;intrc;vnc_zlog_de
bug_verbose("%s:entryrfd=%p",__func__,rfd);assert(rfd->mon_eth);memset((void*)&m
on_buf,0,sizeof(mon_buf));mon_buf.macaddr=*macaddr;mon_buf.logical_net_id=logica
l_net_id;rc=skiplist_search(rfd->mon_eth,(void*)&mon_buf,(void**)&val);assert(!r
c);/**removefromimporttable*/if(!(bgp->rfapi_cfg->flags&BGP_VNC_CONFIG_CALLBACK_
DISABLE)){rfapiMonitorEthDetachImport(bgp,val);}if(val->timer){thread_cancel(val
->timer);val->timer=NULL;}/**removefromrfdlist*/rc=skiplist_delete(rfd->mon_eth,
val,val);assert(!rc);#ifDEBUG_L2_EXTRAvnc_zlog_debug_verbose("%s:freeingmon_eth%
p",__func__,val);#endifXFREE(MTYPE_RFAPI_MONITOR_ETH,val);--rfd->monitor_count;-
-bgp->rfapi->monitor_count;}voidrfapiMonitorCallbacksOff(structbgp*bgp){structrf
api_import_table*it;afi_tafi;structroute_table*rt;structroute_node*rn;void*curso
r;intrc;structrfapi*h=bgp->rfapi;if(bgp->rfapi_cfg->flags&BGP_VNC_CONFIG_CALLBAC
K_DISABLE){/**Alreadyoff.*/return;}bgp->rfapi_cfg->flags|=BGP_VNC_CONFIG_CALLBAC
K_DISABLE;#ifDEBUG_L2_EXTRAvnc_zlog_debug_verbose("%s:turnedoffcallbacks",__func
__);#endifif(h==NULL)return;/**detachmonitorsfromimportVPNtables.Themonitors*wil
lstillbelinkedinper-nvemonitorlists.*/for(it=h->imports;it;it=it->next){for(afi=
AFI_IP;afi<AFI_MAX;++afi){structrfapi_monitor_vpn*m;structrfapi_monitor_vpn*next
;rt=it->imported_vpn[afi];for(rn=route_top(rt);rn;rn=route_next(rn)){m=RFAPI_MON
ITOR_VPN(rn);if(RFAPI_MONITOR_VPN(rn))RFAPI_MONITOR_VPN_W_ALLOC(rn)=NULL;for(;m;
m=next){next=m->next;m->next=NULL;/*gratuitoussafeness*/m->node=NULL;route_unloc
k_node(rn);/*uncount*/}}for(m=it->vpn0_queries[afi];m;m=next){next=m->next;m->ne
xt=NULL;/*gratuitoussafeness*/m->node=NULL;}it->vpn0_queries[afi]=NULL;/*detachf
irstmonitor*/}}/**detachmonitorsfromimportEthtables.Themonitors*willstillbelinke
dinper-nvemonitorlists.*//**Loopoverethernetimporttables*/for(cursor=NULL,rc=ski
plist_next(h->import_mac,NULL,(void**)&it,&cursor);!rc;rc=skiplist_next(h->impor
t_mac,NULL,(void**)&it,&cursor)){structrfapi_monitor_eth*e;structrfapi_monitor_e
th*enext;/**Theactualroutetable*/rt=it->imported_vpn[AFI_L2VPN];/**Findnon-0moni
tors(i.e.,actualaddresses,notFTD*monitors)*/for(rn=route_top(rt);rn;rn=route_nex
t(rn)){structskiplist*sl;sl=RFAPI_MONITOR_ETH(rn);while(!skiplist_delete_first(s
l)){route_unlock_node(rn);/*uncountmonitor*/}}/**Find0-monitors(FTDqueries)*/for
(e=it->eth0_queries;e;e=enext){#ifDEBUG_L2_EXTRAvnc_zlog_debug_verbose("%s:detac
hingeth0mon%p",__func__,e);#endifenext=e->next;e->next=NULL;/*gratuitoussafeness
*/}it->eth0_queries=NULL;/*detachfirstmonitor*/}}voidrfapiMonitorCallbacksOn(str
uctbgp*bgp){structlistnode*hnode;structrfapi_descriptor*rfd;if(!(bgp->rfapi_cfg-
>flags&BGP_VNC_CONFIG_CALLBACK_DISABLE)){/**Alreadyon.It'simportantthatwedon'ttr
ytoreattach*monitorsthatarealreadyattachedbecause,intheinterest*ofperformance,th
ereisnocheckingatthelowerlevel*whetheramonitorisalreadyattached.Itleadsto*corrup
tedchains(e.g.,loopedpointers)*/return;}bgp->rfapi_cfg->flags&=~BGP_VNC_CONFIG_C
ALLBACK_DISABLE;#ifDEBUG_L2_EXTRAvnc_zlog_debug_verbose("%s:turnedoncallbacks",_
_func__);#endifif(bgp->rfapi==NULL)return;/**reattachmonitors*/for(ALL_LIST_ELEM
ENTS_RO(&bgp->rfapi->descriptors,hnode,rfd)){rfapiMonitorAttachImportHd(rfd);rfa
piMonitorEthAttachImportHd(bgp,rfd);}}