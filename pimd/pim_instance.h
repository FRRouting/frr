/**PIMforFRR-PIMInstance*Copyright(C)2017CumulusNetworks,Inc.*DonaldSharp**Thisp
rogramisfreesoftware;youcanredistributeitand/ormodify*itunderthetermsoftheGNUGen
eralPublicLicenseaspublishedby*theFreeSoftwareFoundation;eitherversion2oftheLice
nse,or*(atyouroption)anylaterversion.**Thisprogramisdistributedinthehopethatitwi
llbeuseful,but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILIT
YorFITNESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Y
oushouldhavereceivedacopyoftheGNUGeneralPublicLicense*alongwiththisprogram;seeth
efileCOPYING;ifnot,writetothe*FreeSoftwareFoundation,Inc.,51FranklinSt,FifthFloo
r,Boston,*MA02110-1301USA*/#ifndef__PIM_INSTANCE_H__#define__PIM_INSTANCE_H__#in
clude"pim_str.h"#include"pim_msdp.h"#ifdefined(HAVE_LINUX_MROUTE_H)#include<linu
x/mroute.h>#else/*Below:from<linux/mroute.h>*/#ifndefMAXVIFS#defineMAXVIFS(256)#
endif#endifexternstructpim_instance*pimg;//PimGlobalInstanceenumpim_spt_switchov
er{PIM_SPT_IMMEDIATE,PIM_SPT_INFINITY,};/*PerVRFPIMDB*/structpim_instance{vrf_id
_tvrf_id;structvrf*vrf;struct{enumpim_spt_switchoverswitchover;char*plist;}spt;s
tructhash*rpf_hash;void*ssm_info;/*per-vrfSSMconfiguration*/intsend_v6_secondary
;structthread*thread;intmroute_socket;int64_tmroute_socket_creation;int64_tmrout
e_add_events;int64_tmroute_add_last;int64_tmroute_del_events;int64_tmroute_del_l
ast;structinterface*regiface;//Listofstaticroutes;structlist*static_routes;//Ups
treamvrfspecificinformationstructlist*upstream_list;structhash*upstream_hash;str
ucttimer_wheel*upstream_sg_wheel;/**RPinformation*/structlist*rp_list;structrout
e_table*rp_table;intiface_vif_index[MAXVIFS];structlist*channel_oil_list;structh
ash*channel_oil_hash;structpim_msdpmsdp;structlist*ssmpingd_list;structin_addrss
mpingd_group_addr;unsignedintkeep_alive_time;unsignedintrp_keep_alive_time;/*Ifw
eneedtorescanallourupstreams*/structthread*rpf_cache_refresher;int64_trpf_cache_
refresh_requests;int64_trpf_cache_refresh_events;int64_trpf_cache_refresh_last;i
nt64_tscan_oil_events;int64_tscan_oil_last;int64_tnexthop_lookups;int64_tnexthop
_lookups_avoided;int64_tlast_route_change_time;};voidpim_vrf_init(void);voidpim_
vrf_terminate(void);structpim_instance*pim_get_pim_instance(vrf_id_tvrf_id);#end
if