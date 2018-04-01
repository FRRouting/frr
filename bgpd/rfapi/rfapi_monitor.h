/***Copyright2009-2016,LabNConsulting,L.L.C.***Thisprogramisfreesoftware;youcanr
edistributeitand/or*modifyitunderthetermsoftheGNUGeneralPublicLicense*aspublishe
dbytheFreeSoftwareFoundation;eitherversion2*oftheLicense,or(atyouroption)anylate
rversion.**Thisprogramisdistributedinthehopethatitwillbeuseful,*butWITHOUTANYWAR
RANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSFORAPARTICULARPURP
OSE.Seethe*GNUGeneralPublicLicenseformoredetails.**Youshouldhavereceivedacopyoft
heGNUGeneralPublicLicensealong*withthisprogram;seethefileCOPYING;ifnot,writetoth
eFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA02110-1301USA*/#i
fndefQUAGGA_HGP_RFAPI_MONITOR_H#defineQUAGGA_HGP_RFAPI_MONITOR_H#include"lib/zeb
ra.h"#include"lib/prefix.h"#include"lib/table.h"/**Thesegetattachedtothenodesina
nimporttable(using"aggregate"ptr)*toindicatewhichnvesareinterestedinaprefix/targ
et*/structrfapi_monitor_vpn{structrfapi_monitor_vpn*next;/*chainfromstructroute_
node*/structrfapi_descriptor*rfd;/*whichNVErequestedtheroute*/structprefixp;/*co
nstant:pfxinoriginalrequest*/structroute_node*node;/*nodewe'recurrentlyattachedt
o*/uint32_tflags;#defineRFAPI_MON_FLAG_NEEDCALLBACK0x00000001/*deferredcallback*
///intdcount;/*debuggingcounter*/structthread*timer;};structrfapi_monitor_encap{
structrfapi_monitor_encap*next;structrfapi_monitor_encap*prev;structroute_node*n
ode;/*VPNnode*/structbgp_info*bi;/*VPNbi*/structroute_node*rn;/*parentnode*/};st
ructrfapi_monitor_eth{structrfapi_monitor_eth*next;/*foruseinvpn0_querieslist*/s
tructrfapi_descriptor*rfd;/*whichNVErequestedtheroute*/structethaddrmacaddr;uint
32_tlogical_net_id;structthread*timer;};/**Thisisreferencedbythe"aggregate"field
ofaroutenode*inanRFAPIimporttable.**nodelock/unlock:*-onelockincrementforthisstr
uctureitself*-onelockperchainedstructrfapi_monitor_vpn*-onelockforthemon_ethskip
listitself*-onelockpermon_ethskiplistentry*-onelockfortheextskiplistitself*-onel
ockforeachextskiplistentry*remembertofreeskiplistwhenfreeingrfapi_it_extra*-onel
ockperchainedstructrfapi_monitor_encap**/structrfapi_it_extra{union{struct{struc
trfapi_monitor_vpn*v;structskiplist*idx_rd;/*RDindex*/structskiplist*mon_eth;/*e
therqueries*/struct{/*routeswithUNaddrs,eithercachedencapor*EncapTLV*/intvalid_i
nterior_count;/*unicastexteriorroutes,key=bi,*val=allocatedprefix*/structskiplis
t*source;}e;}vpn;struct{structrfapi_monitor_encap*e;}encap;}u;};#defineRFAPI_IT_
EXTRA_GET(rn)\((structrfapi_it_extra\*)((rn)->aggregate\?(rn)->aggregate\:(route
_lock_node(rn),\(rn)->aggregate=XCALLOC(\MTYPE_RFAPI_IT_EXTRA,\sizeof(structrfap
i_it_extra)))))#defineRFAPI_RDINDEX(rn)\((rn)->aggregate?RFAPI_IT_EXTRA_GET(rn)-
>u.vpn.idx_rd:NULL)#defineRFAPI_RDINDEX_W_ALLOC(rn)(RFAPI_IT_EXTRA_GET(rn)->u.vp
n.idx_rd)#defineRFAPI_MONITOR_ETH(rn)\((rn)->aggregate?RFAPI_IT_EXTRA_GET(rn)->u
.vpn.mon_eth:NULL)#defineRFAPI_MONITOR_ETH_W_ALLOC(rn)(RFAPI_IT_EXTRA_GET(rn)->u
.vpn.mon_eth)#defineRFAPI_MONITOR_VPN(rn)\((rn)->aggregate?RFAPI_IT_EXTRA_GET(rn
)->u.vpn.v:NULL)#defineRFAPI_MONITOR_VPN_W_ALLOC(rn)(RFAPI_IT_EXTRA_GET(rn)->u.v
pn.v)#defineRFAPI_MONITOR_ENCAP(rn)\((rn)->aggregate?RFAPI_IT_EXTRA_GET(rn)->u.e
ncap.e:NULL)#defineRFAPI_MONITOR_ENCAP_W_ALLOC(rn)(RFAPI_IT_EXTRA_GET(rn)->u.enc
ap.e)#defineRFAPI_MONITOR_EXTERIOR(rn)(&(RFAPI_IT_EXTRA_GET(rn)->u.vpn.e))#defin
eRFAPI_HAS_MONITOR_EXTERIOR(rn)\(rn&&rn->aggregate\&&((structrfapi_it_extra*)(rn
->aggregate))->u.vpn.e.source\&&!skiplist_first(((structrfapi_it_extra*)(rn->agg
regate))\->u.vpn.e.source,\NULL,NULL))externvoidrfapiMonitorLoopCheck(structrfap
i_monitor_vpn*mchain);externvoidrfapiMonitorCleanCheck(structbgp*bgp);externvoid
rfapiMonitorCheckAttachAllowed(void);externvoidrfapiMonitorExtraFlush(safi_tsafi
,structroute_node*rn);externstructroute_node*rfapiMonitorGetAttachNode(structrfa
pi_descriptor*rfd,structprefix*p);externvoidrfapiMonitorAttachImportHd(structrfa
pi_descriptor*rfd);externstructroute_node*rfapiMonitorAdd(structbgp*bgp,structrf
api_descriptor*rfd,structprefix*p);externvoidrfapiMonitorDetachImportHd(structrf
api_descriptor*rfd);externvoidrfapiMonitorDel(structbgp*bgp,structrfapi_descript
or*rfd,structprefix*p);externintrfapiMonitorDelHd(structrfapi_descriptor*rfd);ex
ternvoidrfapiMonitorCallbacksOff(structbgp*bgp);externvoidrfapiMonitorCallbacksO
n(structbgp*bgp);externvoidrfapiMonitorResponseRemovalOff(structbgp*bgp);externv
oidrfapiMonitorResponseRemovalOn(structbgp*bgp);externvoidrfapiMonitorExtraPrune
(safi_tsafi,structroute_node*rn);externvoidrfapiMonitorTimersRestart(structrfapi
_descriptor*rfd,structprefix*p);externvoidrfapiMonitorItNodeChanged(structrfapi_
import_table*import_table,structroute_node*it_node,structrfapi_monitor_vpn*monit
or_list);externvoidrfapiMonitorMovedUp(structrfapi_import_table*import_table,str
uctroute_node*old_node,structroute_node*new_node,structrfapi_monitor_vpn*monitor
_list);externstructroute_node*rfapiMonitorEthAdd(structbgp*bgp,structrfapi_descr
iptor*rfd,structethaddr*macaddr,uint32_tlogical_net_id);externvoidrfapiMonitorEt
hDel(structbgp*bgp,structrfapi_descriptor*rfd,structethaddr*macaddr,uint32_tlogi
cal_net_id);#endif/*QUAGGA_HGP_RFAPI_MONITOR_H*/