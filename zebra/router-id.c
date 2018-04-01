/**RouterIDforzebradaemon.**Copyright(C)2004JamesR.Leu**ThisfileispartofQuaggaro
utingsuite.**Quaggaisfreesoftware;youcanredistributeitand/ormodifyit*undertheter
msoftheGNUGeneralPublicLicenseaspublishedbythe*FreeSoftwareFoundation;eithervers
ion2,or(atyouroption)any*laterversion.**Quaggaisdistributedinthehopethatitwillbe
useful,but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorF
ITNESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Yoush
ouldhavereceivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefil
eCOPYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Bo
ston,MA02110-1301USA*/#include<zebra.h>#include"if.h"#include"vty.h"#include"soc
kunion.h"#include"prefix.h"#include"stream.h"#include"command.h"#include"memory.
h"#include"zebra_memory.h"#include"ioctl.h"#include"connected.h"#include"network
.h"#include"log.h"#include"table.h"#include"rib.h"#include"vrf.h"#include"zebra/
zserv.h"#include"zebra/zebra_vrf.h"#include"zebra/router-id.h"#include"zebra/red
istribute.h"/*masterzebraserverstructure*/externstructzebra_tzebrad;staticstruct
connected*router_id_find_node(structlist*l,structconnected*ifc){structlistnode*n
ode;structconnected*c;for(ALL_LIST_ELEMENTS_RO(l,node,c))if(prefix_same(ifc->add
ress,c->address))returnc;returnNULL;}staticintrouter_id_bad_address(structconnec
ted*ifc){if(ifc->address->family!=AF_INET)return1;/*non-redistributableaddresses
shouldn'tbeusedforRIDseither*/if(!zebra_check_addr(ifc->address))return1;return0
;}voidrouter_id_get(structprefix*p,vrf_id_tvrf_id){structlistnode*node;structcon
nected*c;structzebra_vrf*zvrf=vrf_info_get(vrf_id);p->u.prefix4.s_addr=0;p->fami
ly=AF_INET;p->prefixlen=32;if(zvrf->rid_user_assigned.u.prefix4.s_addr)p->u.pref
ix4.s_addr=zvrf->rid_user_assigned.u.prefix4.s_addr;elseif(!list_isempty(zvrf->r
id_lo_sorted_list)){node=listtail(zvrf->rid_lo_sorted_list);c=listgetdata(node);
p->u.prefix4.s_addr=c->address->u.prefix4.s_addr;}elseif(!list_isempty(zvrf->rid
_all_sorted_list)){node=listtail(zvrf->rid_all_sorted_list);c=listgetdata(node);
p->u.prefix4.s_addr=c->address->u.prefix4.s_addr;}}staticvoidrouter_id_set(struc
tprefix*p,vrf_id_tvrf_id){structprefixp2;structlistnode*node;structzserv*client;
structzebra_vrf*zvrf;if(p->u.prefix4.s_addr==0)/*unset*/{zvrf=vrf_info_lookup(vr
f_id);if(!zvrf)return;}else/*set*/zvrf=vrf_info_get(vrf_id);zvrf->rid_user_assig
ned.u.prefix4.s_addr=p->u.prefix4.s_addr;router_id_get(&p2,vrf_id);for(ALL_LIST_
ELEMENTS_RO(zebrad.client_list,node,client))zsend_router_id_update(client,&p2,vr
f_id);}voidrouter_id_add_address(structconnected*ifc){structlist*l=NULL;structli
stnode*node;structprefixbefore;structprefixafter;structzserv*client;structzebra_
vrf*zvrf=vrf_info_get(ifc->ifp->vrf_id);if(router_id_bad_address(ifc))return;rou
ter_id_get(&before,zvrf_id(zvrf));if(!strncmp(ifc->ifp->name,"lo",2)||!strncmp(i
fc->ifp->name,"dummy",5))l=zvrf->rid_lo_sorted_list;elsel=zvrf->rid_all_sorted_l
ist;if(!router_id_find_node(l,ifc))listnode_add_sort(l,ifc);router_id_get(&after
,zvrf_id(zvrf));if(prefix_same(&before,&after))return;for(ALL_LIST_ELEMENTS_RO(z
ebrad.client_list,node,client))zsend_router_id_update(client,&after,zvrf_id(zvrf
));}voidrouter_id_del_address(structconnected*ifc){structconnected*c;structlist*
l;structprefixafter;structprefixbefore;structlistnode*node;structzserv*client;st
ructzebra_vrf*zvrf=vrf_info_get(ifc->ifp->vrf_id);if(router_id_bad_address(ifc))
return;router_id_get(&before,zvrf_id(zvrf));if(!strncmp(ifc->ifp->name,"lo",2)||
!strncmp(ifc->ifp->name,"dummy",5))l=zvrf->rid_lo_sorted_list;elsel=zvrf->rid_al
l_sorted_list;if((c=router_id_find_node(l,ifc)))listnode_delete(l,c);router_id_g
et(&after,zvrf_id(zvrf));if(prefix_same(&before,&after))return;for(ALL_LIST_ELEM
ENTS_RO(zebrad.client_list,node,client))zsend_router_id_update(client,&after,zvr
f_id(zvrf));}voidrouter_id_write(structvty*vty){structvrf*vrf;structzebra_vrf*zv
rf;RB_FOREACH(vrf,vrf_name_head,&vrfs_by_name)if((zvrf=vrf->info)!=NULL)if(zvrf-
>rid_user_assigned.u.prefix4.s_addr){if(zvrf_id(zvrf)==VRF_DEFAULT)vty_out(vty,"
router-id%s\n",inet_ntoa(zvrf->rid_user_assigned.u.prefix4));elsevty_out(vty,"ro
uter-id%svrf%s\n",inet_ntoa(zvrf->rid_user_assigned.u.prefix4),zvrf_name(zvrf));
}}DEFUN(router_id,router_id_cmd,"router-idA.B.C.D[vrfNAME]","Manuallysettheroute
r-id\n""IPaddresstouseforrouter-id\n"VRF_CMD_HELP_STR){intidx_ipv4=1;intidx_name
=3;structprefixrid;vrf_id_tvrf_id=VRF_DEFAULT;rid.u.prefix4.s_addr=inet_addr(arg
v[idx_ipv4]->arg);if(!rid.u.prefix4.s_addr)returnCMD_WARNING_CONFIG_FAILED;rid.p
refixlen=32;rid.family=AF_INET;if(argc>2)VRF_GET_ID(vrf_id,argv[idx_name]->arg);
router_id_set(&rid,vrf_id);returnCMD_SUCCESS;}DEFUN(no_router_id,no_router_id_cm
d,"norouter-id[A.B.C.D[vrfNAME]]",NO_STR"Removethemanuallyconfiguredrouter-id\n"
"IPaddresstouseforrouter-id\n"VRF_CMD_HELP_STR){intidx_name=4;structprefixrid;vr
f_id_tvrf_id=VRF_DEFAULT;rid.u.prefix4.s_addr=0;rid.prefixlen=0;rid.family=AF_IN
ET;if(argc>3)VRF_GET_ID(vrf_id,argv[idx_name]->arg);router_id_set(&rid,vrf_id);r
eturnCMD_SUCCESS;}staticintrouter_id_cmp(void*a,void*b){conststructconnected*ifa
=(conststructconnected*)a;conststructconnected*ifb=(conststructconnected*)b;retu
rnIPV4_ADDR_CMP(&ifa->address->u.prefix4.s_addr,&ifb->address->u.prefix4.s_addr)
;}voidrouter_id_cmd_init(void){install_element(CONFIG_NODE,&router_id_cmd);insta
ll_element(CONFIG_NODE,&no_router_id_cmd);}voidrouter_id_init(structzebra_vrf*zv
rf){zvrf->rid_all_sorted_list=&zvrf->_rid_all_sorted_list;zvrf->rid_lo_sorted_li
st=&zvrf->_rid_lo_sorted_list;memset(zvrf->rid_all_sorted_list,0,sizeof(zvrf->_r
id_all_sorted_list));memset(zvrf->rid_lo_sorted_list,0,sizeof(zvrf->_rid_lo_sort
ed_list));memset(&zvrf->rid_user_assigned,0,sizeof(zvrf->rid_user_assigned));zvr
f->rid_all_sorted_list->cmp=router_id_cmp;zvrf->rid_lo_sorted_list->cmp=router_i
d_cmp;zvrf->rid_user_assigned.family=AF_INET;zvrf->rid_user_assigned.prefixlen=3
2;}