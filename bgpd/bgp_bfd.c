/***bgp_bfd.c:BGPBFDhandlingroutines**@copyrightCopyright(C)2015CumulusNetworks,
Inc.**ThisfileispartofGNUZebra.**GNUZebraisfreesoftware;youcanredistributeitand/
ormodifyit*underthetermsoftheGNUGeneralPublicLicenseaspublishedbythe*FreeSoftwar
eFoundation;eitherversion2,or(atyouroption)any*laterversion.**GNUZebraisdistribu
tedinthehopethatitwillbeuseful,but*WITHOUTANYWARRANTY;withouteventheimpliedwarra
ntyof*MERCHANTABILITYorFITNESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicen
seformoredetails.**YoushouldhavereceivedacopyoftheGNUGeneralPublicLicensealong*w
iththisprogram;seethefileCOPYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51
FranklinSt,FifthFloor,Boston,MA02110-1301USA*/#include<zebra.h>#include"command.
h"#include"linklist.h"#include"memory.h"#include"prefix.h"#include"thread.h"#inc
lude"buffer.h"#include"stream.h"#include"zclient.h"#include"bfd.h"#include"lib/j
son.h"#include"filter.h"#include"bgpd/bgpd.h"#include"bgp_fsm.h"#include"bgpd/bg
p_bfd.h"#include"bgpd/bgp_debug.h"#include"bgpd/bgp_vty.h"externstructzclient*zc
lient;/**bgp_bfd_peer_group2peer_copy-CopytheBFDinformationfrompeergroup*templat
e*topeer.*/voidbgp_bfd_peer_group2peer_copy(structpeer*conf,structpeer*peer){str
uctbfd_info*bfd_info;structbfd_info*conf_bfd_info;if(!conf->bfd_info)return;conf
_bfd_info=(structbfd_info*)conf->bfd_info;if(!peer->bfd_info)peer->bfd_info=bfd_
info_create();bfd_info=(structbfd_info*)peer->bfd_info;/*CopyBFDparametervalues*
/bfd_info->required_min_rx=conf_bfd_info->required_min_rx;bfd_info->desired_min_
tx=conf_bfd_info->desired_min_tx;bfd_info->detect_mult=conf_bfd_info->detect_mul
t;bfd_info->type=conf_bfd_info->type;}/**bgp_bfd_is_peer_multihop-returnswhether
BFDpeerismulti-hoporsingle*hop.*/intbgp_bfd_is_peer_multihop(structpeer*peer){st
ructbfd_info*bfd_info;bfd_info=(structbfd_info*)peer->bfd_info;if(!bfd_info)retu
rn0;if((bfd_info->type==BFD_TYPE_MULTIHOP)||((peer->sort==BGP_PEER_IBGP)&&!peer-
>shared_network)||is_ebgp_multihop_configured(peer))return1;elsereturn0;}/**bgp_
bfd_peer_sendmsg-FormatandsendaPeerregister/Unregister*commandtoZebratobeforward
edtoBFD*/staticvoidbgp_bfd_peer_sendmsg(structpeer*peer,intcommand){structbfd_in
fo*bfd_info;vrf_id_tvrf_id=VRF_DEFAULT;intmultihop;bfd_info=(structbfd_info*)pee
r->bfd_info;if(peer->bgp->inst_type==BGP_INSTANCE_TYPE_VRF)vrf_id=peer->bgp->vrf
_id;if(command==ZEBRA_BFD_DEST_DEREGISTER){multihop=CHECK_FLAG(bfd_info->flags,B
FD_FLAG_BFD_TYPE_MULTIHOP);UNSET_FLAG(bfd_info->flags,BFD_FLAG_BFD_TYPE_MULTIHOP
);}else{multihop=bgp_bfd_is_peer_multihop(peer);if((command==ZEBRA_BFD_DEST_REGI
STER)&&multihop)SET_FLAG(bfd_info->flags,BFD_FLAG_BFD_TYPE_MULTIHOP);}if(peer->s
u.sa.sa_family==AF_INET)bfd_peer_sendmsg(zclient,bfd_info,AF_INET,&peer->su.sin.
sin_addr,(peer->su_local)?&peer->su_local->sin.sin_addr:NULL,(peer->nexthop.ifp)
?peer->nexthop.ifp->name:NULL,peer->ttl,multihop,command,1,vrf_id);elseif(peer->
su.sa.sa_family==AF_INET6)bfd_peer_sendmsg(zclient,bfd_info,AF_INET6,&peer->su.s
in6.sin6_addr,(peer->su_local)?&peer->su_local->sin6.sin6_addr:NULL,(peer->nexth
op.ifp)?peer->nexthop.ifp->name:NULL,peer->ttl,multihop,command,1,vrf_id);}/**bg
p_bfd_register_peer-registerapeerwithBFDthroughzebra*formonitoringthepeerrechaha
bility.*/voidbgp_bfd_register_peer(structpeer*peer){structbfd_info*bfd_info;if(!
peer->bfd_info)return;bfd_info=(structbfd_info*)peer->bfd_info;/*CheckifBFDisena
bledandpeerhasalreadybeenregisteredwithBFD*/if(CHECK_FLAG(bfd_info->flags,BFD_FL
AG_BFD_REG))return;bgp_bfd_peer_sendmsg(peer,ZEBRA_BFD_DEST_REGISTER);}/***bgp_b
fd_deregister_peer-deregisterapeerwithBFDthroughzebra*forstoppingthemonitoringof
thepeer*rechahability.*/voidbgp_bfd_deregister_peer(structpeer*peer){structbfd_i
nfo*bfd_info;if(!peer->bfd_info)return;bfd_info=(structbfd_info*)peer->bfd_info;
/*CheckifBFDiseanbledandpeerhasnotbeenregistered*/if(!CHECK_FLAG(bfd_info->flags
,BFD_FLAG_BFD_REG))return;bfd_info->status=BFD_STATUS_DOWN;bfd_info->last_update
=bgp_clock();bgp_bfd_peer_sendmsg(peer,ZEBRA_BFD_DEST_DEREGISTER);}/**bgp_bfd_up
date_peer-updatepeerwithBFDwithnewBFDparamters*throughzebra.*/staticvoidbgp_bfd_
update_peer(structpeer*peer){structbfd_info*bfd_info;if(!peer->bfd_info)return;b
fd_info=(structbfd_info*)peer->bfd_info;/*CheckifthepeerhasbeenregisteredwithBFD
*/if(!CHECK_FLAG(bfd_info->flags,BFD_FLAG_BFD_REG))return;bgp_bfd_peer_sendmsg(p
eer,ZEBRA_BFD_DEST_UPDATE);}/**bgp_bfd_update_type-updatesessiontypewithBFDthrou
ghzebra.*/staticvoidbgp_bfd_update_type(structpeer*peer){structbfd_info*bfd_info
;intmultihop;if(!peer->bfd_info)return;bfd_info=(structbfd_info*)peer->bfd_info;
/*CheckifthepeerhasbeenregisteredwithBFD*/if(!CHECK_FLAG(bfd_info->flags,BFD_FLA
G_BFD_REG))return;if(bfd_info->type==BFD_TYPE_NOT_CONFIGURED){multihop=bgp_bfd_i
s_peer_multihop(peer);if((multihop&&!CHECK_FLAG(bfd_info->flags,BFD_FLAG_BFD_TYP
E_MULTIHOP))||(!multihop&&CHECK_FLAG(bfd_info->flags,BFD_FLAG_BFD_TYPE_MULTIHOP)
)){bgp_bfd_peer_sendmsg(peer,ZEBRA_BFD_DEST_DEREGISTER);bgp_bfd_peer_sendmsg(pee
r,ZEBRA_BFD_DEST_REGISTER);}}else{if((bfd_info->type==BFD_TYPE_MULTIHOP&&!CHECK_
FLAG(bfd_info->flags,BFD_FLAG_BFD_TYPE_MULTIHOP))||(bfd_info->type==BFD_TYPE_SIN
GLEHOP&&CHECK_FLAG(bfd_info->flags,BFD_FLAG_BFD_TYPE_MULTIHOP))){bgp_bfd_peer_se
ndmsg(peer,ZEBRA_BFD_DEST_DEREGISTER);bgp_bfd_peer_sendmsg(peer,ZEBRA_BFD_DEST_R
EGISTER);}}}/**bgp_bfd_dest_replay-ReplayallthepeersthathaveBFDenabled*tozebra*/
staticintbgp_bfd_dest_replay(intcommand,structzclient*client,zebra_size_tlength,
vrf_id_tvrf_id){structlistnode*mnode,*node,*nnode;structbgp*bgp;structpeer*peer;
if(BGP_DEBUG(zebra,ZEBRA))zlog_debug("Zebra:BFDDestreplayrequest");/*Sendtheclie
ntregistration*/bfd_client_sendmsg(zclient,ZEBRA_BFD_CLIENT_REGISTER);/*Replayth
epeer,ifBFDisenabledinBGP*/for(ALL_LIST_ELEMENTS_RO(bm->bgp,mnode,bgp))for(ALL_L
IST_ELEMENTS(bgp->peer,node,nnode,peer)){bgp_bfd_update_peer(peer);}return0;}/**
bgp_bfd_peer_status_update-UpdatetheBFDstatusifithaschanged.Bring*downthepeerift
heBFDsessionwentdownfrom**up.*/staticvoidbgp_bfd_peer_status_update(structpeer*p
eer,intstatus){structbfd_info*bfd_info;intold_status;bfd_info=(structbfd_info*)p
eer->bfd_info;if(bfd_info->status==status)return;old_status=bfd_info->status;bfd
_info->status=status;bfd_info->last_update=bgp_clock();if((status==BFD_STATUS_DO
WN)&&(old_status==BFD_STATUS_UP)){peer->last_reset=PEER_DOWN_BFD_DOWN;BGP_EVENT_
ADD(peer,BGP_Stop);}}/**bgp_bfd_dest_update-FindthepeerforwhichtheBFDstatus*hasc
hangedandbringdownthepeer*connectivityiftheBFDsessionwentdown.*/staticintbgp_bfd
_dest_update(intcommand,structzclient*zclient,zebra_size_tlength,vrf_id_tvrf_id)
{structinterface*ifp;structprefixdp;structprefixsp;intstatus;ifp=bfd_get_peer_in
fo(zclient->ibuf,&dp,&sp,&status,vrf_id);if(BGP_DEBUG(zebra,ZEBRA)){charbuf[2][P
REFIX2STR_BUFFER];prefix2str(&dp,buf[0],sizeof(buf[0]));if(ifp){zlog_debug("Zebr
a:vrf%uinterface%sbfddestination%s%s",vrf_id,ifp->name,buf[0],bfd_get_status_str
(status));}else{prefix2str(&sp,buf[1],sizeof(buf[1]));zlog_debug("Zebra:vrf%usou
rce%sbfddestination%s%s",vrf_id,buf[1],buf[0],bfd_get_status_str(status));}}/*Br
ingthepeerdownifBFDisenabledinBGP*/{structlistnode*mnode,*node,*nnode;structbgp*
bgp;structpeer*peer;for(ALL_LIST_ELEMENTS_RO(bm->bgp,mnode,bgp))for(ALL_LIST_ELE
MENTS(bgp->peer,node,nnode,peer)){if(!peer->bfd_info)continue;if((dp.family==AF_
INET)&&(peer->su.sa.sa_family==AF_INET)){if(dp.u.prefix4.s_addr!=peer->su.sin.si
n_addr.s_addr)continue;}elseif((dp.family==AF_INET6)&&(peer->su.sa.sa_family==AF
_INET6)){if(memcmp(&dp.u.prefix6,&peer->su.sin6.sin6_addr,sizeof(structin6_addr)
))continue;}elsecontinue;if(ifp&&(ifp==peer->nexthop.ifp)){bgp_bfd_peer_status_u
pdate(peer,status);}else{if(!peer->su_local)continue;if((sp.family==AF_INET)&&(p
eer->su_local->sa.sa_family==AF_INET)){if(sp.u.prefix4.s_addr!=peer->su_local->s
in.sin_addr.s_addr)continue;}elseif((sp.family==AF_INET6)&&(peer->su_local->sa.s
a_family==AF_INET6)){if(memcmp(&sp.u.prefix6,&peer->su_local->sin6.sin6_addr,siz
eof(structin6_addr)))continue;}elsecontinue;if((vrf_id!=VRF_DEFAULT)&&(peer->bgp
->vrf_id!=vrf_id))continue;bgp_bfd_peer_status_update(peer,status);}}}return0;}/
**bgp_bfd_peer_param_set-SettheconfiguredBFDparamtervaluesforpeer.*/staticintbgp
_bfd_peer_param_set(structpeer*peer,uint32_tmin_rx,uint32_tmin_tx,uint8_tdetect_
mult,intdefaults){structpeer_group*group;structlistnode*node,*nnode;intcommand=0
;bfd_set_param((structbfd_info**)&(peer->bfd_info),min_rx,min_tx,detect_mult,def
aults,&command);if(CHECK_FLAG(peer->sflags,PEER_STATUS_GROUP)){group=peer->group
;for(ALL_LIST_ELEMENTS(group->peer,node,nnode,peer)){command=0;bfd_set_param((st
ructbfd_info**)&(peer->bfd_info),min_rx,min_tx,detect_mult,defaults,&command);if
((peer->status==Established)&&(command==ZEBRA_BFD_DEST_REGISTER))bgp_bfd_registe
r_peer(peer);elseif(command==ZEBRA_BFD_DEST_UPDATE)bgp_bfd_update_peer(peer);}}e
lse{if((peer->status==Established)&&(command==ZEBRA_BFD_DEST_REGISTER))bgp_bfd_r
egister_peer(peer);elseif(command==ZEBRA_BFD_DEST_UPDATE)bgp_bfd_update_peer(pee
r);}return0;}/**bgp_bfd_peer_param_unset-DeletetheconfiguredBFDparamtervaluesfor
*peer.*/staticintbgp_bfd_peer_param_unset(structpeer*peer){structpeer_group*grou
p;structlistnode*node,*nnode;if(!peer->bfd_info)return0;if(CHECK_FLAG(peer->sfla
gs,PEER_STATUS_GROUP)){bfd_info_free(&(peer->bfd_info));group=peer->group;for(AL
L_LIST_ELEMENTS(group->peer,node,nnode,peer)){bgp_bfd_deregister_peer(peer);bfd_
info_free(&(peer->bfd_info));}}else{bgp_bfd_deregister_peer(peer);bfd_info_free(
&(peer->bfd_info));}return0;}/**bgp_bfd_peer_param_type_set-settheBFDsessiontype
(multihopor*singlehop)*/staticintbgp_bfd_peer_param_type_set(structpeer*peer,enu
mbfd_sess_typetype){structpeer_group*group;structlistnode*node,*nnode;intcommand
=0;structbfd_info*bfd_info;if(!peer->bfd_info)bfd_set_param((structbfd_info**)&(
peer->bfd_info),BFD_DEF_MIN_RX,BFD_DEF_MIN_TX,BFD_DEF_DETECT_MULT,1,&command);bf
d_info=(structbfd_info*)peer->bfd_info;bfd_info->type=type;if(CHECK_FLAG(peer->s
flags,PEER_STATUS_GROUP)){group=peer->group;for(ALL_LIST_ELEMENTS(group->peer,no
de,nnode,peer)){command=0;if(!peer->bfd_info)bfd_set_param((structbfd_info**)&(p
eer->bfd_info),BFD_DEF_MIN_RX,BFD_DEF_MIN_TX,BFD_DEF_DETECT_MULT,1,&command);bfd
_info=(structbfd_info*)peer->bfd_info;bfd_info->type=type;if(peer->status==Estab
lished){if(command==ZEBRA_BFD_DEST_REGISTER)bgp_bfd_register_peer(peer);elsebgp_
bfd_update_type(peer);}}}else{if(peer->status==Established){if(command==ZEBRA_BF
D_DEST_REGISTER)bgp_bfd_register_peer(peer);elsebgp_bfd_update_type(peer);}}retu
rn0;}/**bgp_bfd_peer_config_write-WritethepeerBFDconfiguration.*/voidbgp_bfd_pee
r_config_write(structvty*vty,structpeer*peer,char*addr){structbfd_info*bfd_info;
if(!peer->bfd_info)return;bfd_info=(structbfd_info*)peer->bfd_info;if(CHECK_FLAG
(bfd_info->flags,BFD_FLAG_PARAM_CFG))vty_out(vty,"neighbor%sbfd%d%d%d\n",addr,bf
d_info->detect_mult,bfd_info->required_min_rx,bfd_info->desired_min_tx);if(bfd_i
nfo->type!=BFD_TYPE_NOT_CONFIGURED)vty_out(vty,"neighbor%sbfd%s\n",addr,(bfd_inf
o->type==BFD_TYPE_MULTIHOP)?"multihop":"singlehop");if(!CHECK_FLAG(bfd_info->fla
gs,BFD_FLAG_PARAM_CFG)&&(bfd_info->type==BFD_TYPE_NOT_CONFIGURED))vty_out(vty,"n
eighbor%sbfd\n",addr);}/**bgp_bfd_show_info-ShowthepeerBFDinformation.*/voidbgp_
bfd_show_info(structvty*vty,structpeer*peer,uint8_tuse_json,json_object*json_nei
gh){bfd_show_info(vty,(structbfd_info*)peer->bfd_info,bgp_bfd_is_peer_multihop(p
eer),0,use_json,json_neigh);}DEFUN(neighbor_bfd,neighbor_bfd_cmd,"neighbor<A.B.C
.D|X:X::X:X|WORD>bfd",NEIGHBOR_STRNEIGHBOR_ADDR_STR2"EnablesBFDsupport\n"){intid
x_peer=1;structpeer*peer;intret;peer=peer_and_group_lookup_vty(vty,argv[idx_peer
]->arg);if(!peer)returnCMD_WARNING_CONFIG_FAILED;ret=bgp_bfd_peer_param_set(peer
,BFD_DEF_MIN_RX,BFD_DEF_MIN_TX,BFD_DEF_DETECT_MULT,1);if(ret!=0)returnbgp_vty_re
turn(vty,ret);returnCMD_SUCCESS;}DEFUN(neighbor_bfd_param,neighbor_bfd_param_cmd
,"neighbor<A.B.C.D|X:X::X:X|WORD>bfd(2-255)(50-60000)(50-60000)",NEIGHBOR_STRNEI
GHBOR_ADDR_STR2"EnablesBFDsupport\n""DetectMultiplier\n""Requiredminreceiveinter
val\n""Desiredmintransmitinterval\n"){intidx_peer=1;intidx_number_1=3;intidx_num
ber_2=4;intidx_number_3=5;structpeer*peer;uint32_trx_val;uint32_ttx_val;uint8_td
m_val;intret;peer=peer_and_group_lookup_vty(vty,argv[idx_peer]->arg);if(!peer)re
turnCMD_WARNING_CONFIG_FAILED;if((ret=bfd_validate_param(vty,argv[idx_number_1]-
>arg,argv[idx_number_2]->arg,argv[idx_number_3]->arg,&dm_val,&rx_val,&tx_val))!=
CMD_SUCCESS)returnret;ret=bgp_bfd_peer_param_set(peer,rx_val,tx_val,dm_val,0);if
(ret!=0)returnbgp_vty_return(vty,ret);returnCMD_SUCCESS;}DEFUN_HIDDEN(neighbor_b
fd_type,neighbor_bfd_type_cmd,"neighbor<A.B.C.D|X:X::X:X|WORD>bfd<multihop|singl
ehop>",NEIGHBOR_STRNEIGHBOR_ADDR_STR2"EnablesBFDsupport\n""Multihopsession\n""Si
nglehopsession\n"){intidx_peer=1;intidx_hop=3;structpeer*peer;enumbfd_sess_typet
ype;intret;peer=peer_and_group_lookup_vty(vty,argv[idx_peer]->arg);if(!peer)retu
rnCMD_WARNING_CONFIG_FAILED;if(strmatch(argv[idx_hop]->text,"singlehop"))type=BF
D_TYPE_SINGLEHOP;elseif(strmatch(argv[idx_hop]->text,"multihop"))type=BFD_TYPE_M
ULTIHOP;elsereturnCMD_WARNING_CONFIG_FAILED;ret=bgp_bfd_peer_param_type_set(peer
,type);if(ret!=0)returnbgp_vty_return(vty,ret);returnCMD_SUCCESS;}DEFUN(no_neigh
bor_bfd,no_neighbor_bfd_cmd,"noneighbor<A.B.C.D|X:X::X:X|WORD>bfd[(2-255)(50-600
00)(50-60000)]",NO_STRNEIGHBOR_STRNEIGHBOR_ADDR_STR2"DisablesBFDsupport\n""Detec
tMultiplier\n""Requiredminreceiveinterval\n""Desiredmintransmitinterval\n"){inti
dx_peer=2;structpeer*peer;intret;peer=peer_and_group_lookup_vty(vty,argv[idx_pee
r]->arg);if(!peer)returnCMD_WARNING_CONFIG_FAILED;ret=bgp_bfd_peer_param_unset(p
eer);if(ret!=0)returnbgp_vty_return(vty,ret);returnCMD_SUCCESS;}DEFUN_HIDDEN(no_
neighbor_bfd_type,no_neighbor_bfd_type_cmd,"noneighbor<A.B.C.D|X:X::X:X|WORD>bfd
<multihop|singlehop>",NO_STRNEIGHBOR_STRNEIGHBOR_ADDR_STR2"DisablesBFDsupport\n"
"Multihopsession\n""Singlehopsession\n"){intidx_peer=2;structpeer*peer;intret;pe
er=peer_and_group_lookup_vty(vty,argv[idx_peer]->arg);if(!peer)returnCMD_WARNING
_CONFIG_FAILED;if(!peer->bfd_info)return0;ret=bgp_bfd_peer_param_type_set(peer,B
FD_TYPE_NOT_CONFIGURED);if(ret!=0)returnbgp_vty_return(vty,ret);returnCMD_SUCCES
S;}voidbgp_bfd_init(void){bfd_gbl_init();/*InitializeBFDclientfunctions*/zclient
->interface_bfd_dest_update=bgp_bfd_dest_update;zclient->bfd_dest_replay=bgp_bfd
_dest_replay;/*"neighborbfd"commands.*/install_element(BGP_NODE,&neighbor_bfd_cm
d);install_element(BGP_NODE,&neighbor_bfd_param_cmd);install_element(BGP_NODE,&n
eighbor_bfd_type_cmd);install_element(BGP_NODE,&no_neighbor_bfd_cmd);install_ele
ment(BGP_NODE,&no_neighbor_bfd_type_cmd);}