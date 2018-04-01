/***bgp_updgrp.c:BGPupdategroupstructures**@copyrightCopyright(C)2014CumulusNetw
orks,Inc.**@authorAvneeshSachdev<avneesh@sproute.net>*@authorRajeshVaradarajan<r
ajesh@sproute.net>*@authorPradoshMohapatra<pradosh@sproute.net>**Thisfileisparto
fGNUZebra.**GNUZebraisfreesoftware;youcanredistributeitand/ormodifyit*underthete
rmsoftheGNUGeneralPublicLicenseaspublishedbythe*FreeSoftwareFoundation;eitherver
sion2,or(atyouroption)any*laterversion.**GNUZebraisdistributedinthehopethatitwil
lbeuseful,but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITY
orFITNESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Yo
ushouldhavereceivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethe
fileCOPYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor
,Boston,MA02110-1301USA*/#ifndef_QUAGGA_BGP_UPDGRP_H#define_QUAGGA_BGP_UPDGRP_H#
include"bgp_advertise.h"/**Thefollowingthreeheuristicconstantsdeterminehowlongad
vertisementto*asubgroupwillbedelayedafteritiscreated.Theintentistoallow*transien
tchangesinpeerstate(primarilysessionestablishment)tosettle,*sothatmorepeerscanbe
groupedtogetherandbenefitfromsharing*advertisementcomputationswiththesubgroup.**
Thesevalueshaveaverylargeimpactoninitialconvergencetime;any*changesshouldbeaccom
paniedbycarefulperformancetestingatallscales.**Thecoalescetime'C'foranewsubgroup
withinaparticularBGPinstance*'B'withtotalnumberofknownpeers'P',establishedornot,
iscomputedas*follows:**C=MIN(BGP_MAX_SUBGROUP_COALESCE_TIME,*BGP_DEFAULT_SUBGROU
P_COALESCE_TIME+*(P*BGP_PEER_ADJUST_SUBGROUP_COALESCE_TIME))*/#defineBGP_DEFAULT
_SUBGROUP_COALESCE_TIME1000#defineBGP_MAX_SUBGROUP_COALESCE_TIME10000#defineBGP_
PEER_ADJUST_SUBGROUP_COALESCE_TIME50#definePEER_UPDGRP_FLAGS\(PEER_FLAG_LOCAL_AS
_NO_PREPEND|PEER_FLAG_LOCAL_AS_REPLACE_AS)#definePEER_UPDGRP_AF_FLAGS\(PEER_FLAG
_SEND_COMMUNITY|PEER_FLAG_SEND_EXT_COMMUNITY\|PEER_FLAG_DEFAULT_ORIGINATE|PEER_F
LAG_REFLECTOR_CLIENT\|PEER_FLAG_RSERVER_CLIENT|PEER_FLAG_NEXTHOP_SELF\|PEER_FLAG
_NEXTHOP_UNCHANGED|PEER_FLAG_FORCE_NEXTHOP_SELF\|PEER_FLAG_AS_PATH_UNCHANGED|PEE
R_FLAG_MED_UNCHANGED\|PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED|PEER_FLAG_REMOVE_PRIVATE
_AS\|PEER_FLAG_REMOVE_PRIVATE_AS_ALL\|PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE\|PEER_
FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE\|PEER_FLAG_ADDPATH_TX_ALL_PATHS\|PEER_FLAG_AD
DPATH_TX_BESTPATH_PER_AS|PEER_FLAG_AS_OVERRIDE)#definePEER_UPDGRP_CAP_FLAGS(PEER
_CAP_AS4_RCV)#definePEER_UPDGRP_AF_CAP_FLAGS\(PEER_CAP_ORF_PREFIX_SM_RCV|PEER_CA
P_ORF_PREFIX_SM_OLD_RCV\|PEER_CAP_ADDPATH_AF_TX_ADV|PEER_CAP_ADDPATH_AF_RX_RCV\|
PEER_CAP_ENHE_AF_NEGO)typedefenum{BGP_ATTR_VEC_NH=0,BGP_ATTR_VEC_MAX}bpacket_att
r_vec_type;typedefstruct{uint32_tflags;unsignedlongoffset;}bpacket_attr_vec;#def
ineBPKT_ATTRVEC_FLAGS_UPDATED(1<<0)#defineBPKT_ATTRVEC_FLAGS_RMAP_NH_PEER_ADDRES
S(1<<1)#defineBPKT_ATTRVEC_FLAGS_REFLECTED(1<<2)#defineBPKT_ATTRVEC_FLAGS_RMAP_N
H_UNCHANGED(1<<3)#defineBPKT_ATTRVEC_FLAGS_RMAP_IPV4_NH_CHANGED(1<<4)#defineBPKT
_ATTRVEC_FLAGS_RMAP_IPV6_GNH_CHANGED(1<<5)#defineBPKT_ATTRVEC_FLAGS_RMAP_IPV6_LN
H_CHANGED(1<<6)typedefstructbpacket_attr_vec_arr{bpacket_attr_vecentries[BGP_ATT
R_VEC_MAX];}bpacket_attr_vec_arr;structbpacket{/*forbeingpartofanupdatesubgroup'
smessagelist*/TAILQ_ENTRY(bpacket)pkt_train;/*listofpeers(well,peer_afs)thatthep
acketneedstobesentto*/LIST_HEAD(pkt_peer_list,peer_af)peers;structstream*buffer;
bpacket_attr_vec_arrarr;unsignedintver;};structbpacket_queue{TAILQ_HEAD(pkt_queu
e,bpacket)pkts;#if0/*Adummypacketthatisusedtothreadallpeersthathavecompletedthei
rwork*/structbpacketsentinel;#endifunsignedintconf_max_count;unsignedintcurr_cou
nt;unsignedinthwm_count;unsignedintmax_count_reached_count;};structupdate_group{
/*backpointertotheBGPinstance*/structbgp*bgp;/*listofsubgroupsthatbelongtotheupd
ategroup*/LIST_HEAD(subgrp_list,update_subgroup)subgrps;/*lazywaytostoreconfigur
ationcommontoallpeershashfunctionwillcomputefromthisdata*/structpeer*conf;afi_ta
fi;safi_tsafi;intafid;uint64_tid;time_tuptime;uint32_tjoin_events;uint32_tprune_
events;uint32_tmerge_events;uint32_tupdgrp_switch_events;uint32_tpeer_refreshes_
combined;uint32_tadj_count;uint32_tsplit_events;uint32_tmerge_checks_triggered;u
int32_tsubgrps_created;uint32_tsubgrps_deleted;uint32_tnum_dbg_en_peers;};/**Sho
rthandforaglobalstatisticscounter.*/#defineUPDGRP_GLOBAL_STAT(updgrp,stat)\((upd
grp)->bgp->update_group_stats.stat)/**Addthegivenvaluetoacounteronanupdategroupa
ndthebgp*instance.*/#defineUPDGRP_INCR_STAT_BY(updgrp,stat,value)\do{\(updgrp)->
stat+=(value);\UPDGRP_GLOBAL_STAT(updgrp,stat)+=(value);\}while(0)/**Incrementac
ounteronaupdategroupanditsparentstructures.*/#defineUPDGRP_INCR_STAT(subgrp,stat
)UPDGRP_INCR_STAT_BY(subgrp,stat,1)structupdate_subgroup{/*backpointertotheparen
tupdategroup*/structupdate_group*update_group;/*listofpeersthatbelongtothesubgro
up*/LIST_HEAD(peer_list,peer_af)peers;intpeer_count;/*forbeingpartofanupdategrou
p'ssubgrouplist*/LIST_ENTRY(update_subgroup)updgrp_train;structbpacket_queuepkt_
queue;/**Listofadj-outstructuresforthissubgroup.*Itessentiallyrepresentsthesnaps
hotofeveryprefixthat*hasbeenadvertisedtothemembersofthesubgroup*/TAILQ_HEAD(adjo
ut_queue,bgp_adj_out)adjq;/*packetbufferforupdategeneration*/structstream*work;/
*WeuseaseparatestreamtoencodeMP_REACH_NLRIforefficient*NLRIpacking.peer->obuf_wo
rkstoresalltheotherattributes.The*actualpacketisthenconstructedbyconcatenatingth
etwo.*/structstream*scratch;/*synchronizationlistandtime*/structbgp_synchronize*
sync;/*sendprefixcount*/unsignedlongscount;/*announcementattributehash*/structha
sh*hash;structthread*t_coalesce;uint32_tv_coalesce;structthread*t_merge_check;/*
tableversionthatthesubgrouphascaughtupto.*/uint64_tversion;/*versionmaintainedto
recordadjchanges*/uint64_tadj_version;time_tuptime;/**Identifyinginformationabou
tthesubgroupthatthissubgroupwas*split*from,ifany.*/struct{uint64_tupdate_group_i
d;uint64_tsubgroup_id;}split_from;uint32_tjoin_events;uint32_tprune_events;/**Th
isisbumpedupwhenanothersubgroupmergesintothisone.*/uint32_tmerge_events;uint32_t
updgrp_switch_events;uint32_tpeer_refreshes_combined;uint32_tadj_count;uint32_ts
plit_events;uint32_tmerge_checks_triggered;uint64_tid;uint16_tsflags;/*Subgroupf
lags,seebelow*/uint16_tflags;};/**Weneedtodoanoutboundrefreshtogetthissubgroupin
toa*consistentstate.*/#defineSUBGRP_FLAG_NEEDS_REFRESH(1<<0)#defineSUBGRP_STATUS
_DEFAULT_ORIGINATE(1<<0)/**Addthegivenvaluetothespecifiedcounteronasubgroupandit
s*parentstructures.*/#defineSUBGRP_INCR_STAT_BY(subgrp,stat,value)\do{\(subgrp)-
>stat+=(value);\if((subgrp)->update_group)\UPDGRP_INCR_STAT_BY((subgrp)->update_
group,stat,\value);\}while(0)/**Incrementacounteronasubgroupanditsparentstructur
es.*/#defineSUBGRP_INCR_STAT(subgrp,stat)SUBGRP_INCR_STAT_BY(subgrp,stat,1)/**De
crementacounteronasubgroupanditsparentstructures.*/#defineSUBGRP_DECR_STAT(subgr
p,stat)SUBGRP_INCR_STAT_BY(subgrp,stat,-1)typedefint(*updgrp_walkcb)(structupdat
e_group*updgrp,void*ctx);/*reallyaprivatestructure*/structupdwalk_context{struct
vty*vty;structbgp_node*rn;structbgp_info*ri;uint64_tupdgrp_id;uint64_tsubgrp_id;
bgp_policy_type_epolicy_type;constchar*policy_name;intpolicy_event_start_flag;in
tpolicy_route_update;updgrp_walkcbcb;void*context;uint8_tflags;#defineUPDWALK_FL
AGS_ADVQUEUE(1<<0)#defineUPDWALK_FLAGS_ADVERTISED(1<<1)};#defineUPDWALK_CONTINUE
HASHWALK_CONTINUE#defineUPDWALK_ABORTHASHWALK_ABORT#definePAF_PEER(p)((p)->peer)
#definePAF_SUBGRP(p)((p)->subgroup)#definePAF_UPDGRP(p)((p)->subgroup->update_gr
oup)#definePAF_PKTQ(f)SUBGRP_PKTQ((f)->subgroup)#defineUPDGRP_PEER(u)((u)->conf)
#defineUPDGRP_AFI(u)((u)->afi)#defineUPDGRP_SAFI(u)((u)->safi)#defineUPDGRP_INST
(u)((u)->bgp)#defineUPDGRP_AFFLAGS(u)((u)->conf->af_flags[UPDGRP_AFI(u)][UPDGRP_
SAFI(u)])#defineUPDGRP_DBG_ON(u)((u)->num_dbg_en_peers)#defineUPDGRP_PEER_DBG_EN
(u)(((u)->num_dbg_en_peers)++)#defineUPDGRP_PEER_DBG_DIS(u)(((u)->num_dbg_en_pee
rs)--)#defineUPDGRP_PEER_DBG_OFF(u)(u)->num_dbg_en_peers=0#defineSUBGRP_AFI(s)UP
DGRP_AFI((s)->update_group)#defineSUBGRP_SAFI(s)UPDGRP_SAFI((s)->update_group)#d
efineSUBGRP_PEER(s)UPDGRP_PEER((s)->update_group)#defineSUBGRP_PCOUNT(s)((s)->pe
er_count)#defineSUBGRP_PFIRST(s)LIST_FIRST(&((s)->peers))#defineSUBGRP_PKTQ(s)&(
(s)->pkt_queue)#defineSUBGRP_INST(s)UPDGRP_INST((s)->update_group)#defineSUBGRP_
AFFLAGS(s)UPDGRP_AFFLAGS((s)->update_group)#defineSUBGRP_UPDGRP(s)((s)->update_g
roup)/**Walkallsubgroupsinanupdategroup.*/#defineUPDGRP_FOREACH_SUBGRP(updgrp,su
bgrp)\LIST_FOREACH(subgrp,&((updgrp)->subgrps),updgrp_train)#defineUPDGRP_FOREAC
H_SUBGRP_SAFE(updgrp,subgrp,tmp_subgrp)\LIST_FOREACH_SAFE(subgrp,&((updgrp)->sub
grps),updgrp_train,\tmp_subgrp)#defineSUBGRP_FOREACH_PEER(subgrp,paf)\LIST_FOREA
CH(paf,&(subgrp->peers),subgrp_train)#defineSUBGRP_FOREACH_PEER_SAFE(subgrp,paf,
temp_paf)\LIST_FOREACH_SAFE(paf,&(subgrp->peers),subgrp_train,temp_paf)#defineSU
BGRP_FOREACH_ADJ(subgrp,adj)\TAILQ_FOREACH(adj,&(subgrp->adjq),subgrp_adj_train)
#defineSUBGRP_FOREACH_ADJ_SAFE(subgrp,adj,adj_temp)\TAILQ_FOREACH_SAFE(adj,&(sub
grp->adjq),subgrp_adj_train,adj_temp)/*Prototypes.*//*bgp_updgrp.c*/externvoidup
date_bgp_group_init(structbgp*);externvoidudpate_bgp_group_free(structbgp*);exte
rnvoidupdate_group_show(structbgp*bgp,afi_tafi,safi_tsafi,structvty*vty,uint64_t
subgrp_id);externvoidupdate_group_show_stats(structbgp*bgp,structvty*vty);extern
voidupdate_group_adjust_peer(structpeer_af*paf);externintupdate_group_adjust_sol
oness(structpeer*peer,intset);externvoidupdate_subgroup_remove_peer(structupdate
_subgroup*,structpeer_af*);externstructbgp_table*update_subgroup_rib(structupdat
e_subgroup*);externvoidupdate_subgroup_split_peer(structpeer_af*,structupdate_gr
oup*);externintupdate_subgroup_check_merge(structupdate_subgroup*,constchar*);ex
ternintupdate_subgroup_trigger_merge_check(structupdate_subgroup*,intforce);exte
rnvoidupdate_group_policy_update(structbgp*bgp,bgp_policy_type_eptype,constchar*
pname,introute_update,intstart_event);externvoidupdate_group_af_walk(structbgp*b
gp,afi_tafi,safi_tsafi,updgrp_walkcbcb,void*ctx);externvoidupdate_group_walk(str
uctbgp*bgp,updgrp_walkcbcb,void*ctx);externvoidupdate_group_periodic_merge(struc
tbgp*bgp);externintupdate_group_refresh_default_originate_route_map(structthread
*thread);externvoidupdate_group_start_advtimer(structbgp*bgp);externvoidupdate_s
ubgroup_inherit_info(structupdate_subgroup*to,structupdate_subgroup*from);/*bgp_
updgrp_packet.c*/externstructbpacket*bpacket_alloc(void);externvoidbpacket_free(
structbpacket*pkt);externvoidbpacket_queue_init(structbpacket_queue*q);externvoi
dbpacket_queue_cleanup(structbpacket_queue*q);externvoidbpacket_queue_sanity_che
ck(structbpacket_queue*q);externstructbpacket*bpacket_queue_add(structbpacket_qu
eue*q,structstream*s,structbpacket_attr_vec_arr*vecarr);structbpacket*bpacket_qu
eue_remove(structbpacket_queue*q);externstructbpacket*bpacket_queue_first(struct
bpacket_queue*q);structbpacket*bpacket_queue_last(structbpacket_queue*q);unsigne
dintbpacket_queue_length(structbpacket_queue*q);unsignedintbpacket_queue_hwm_len
gth(structbpacket_queue*q);intbpacket_queue_is_full(structbgp*bgp,structbpacket_
queue*q);externvoidbpacket_queue_advance_peer(structpeer_af*paf);externvoidbpack
et_queue_remove_peer(structpeer_af*paf);externvoidbpacket_add_peer(structbpacket
*pkt,structpeer_af*paf);unsignedintbpacket_queue_virtual_length(structpeer_af*pa
f);externvoidbpacket_queue_show_vty(structbpacket_queue*q,structvty*vty);intsubg
roup_packets_to_build(structupdate_subgroup*subgrp);externstructbpacket*subgroup
_update_packet(structupdate_subgroup*s);externstructbpacket*subgroup_withdraw_pa
cket(structupdate_subgroup*s);externstructstream*bpacket_reformat_for_peer(struc
tbpacket*pkt,structpeer_af*paf);externvoidbpacket_attr_vec_arr_reset(structbpack
et_attr_vec_arr*vecarr);externvoidbpacket_attr_vec_arr_set_vec(structbpacket_att
r_vec_arr*vecarr,bpacket_attr_vec_typetype,structstream*s,structattr*attr);exter
nvoidsubgroup_default_update_packet(structupdate_subgroup*subgrp,structattr*attr
,structpeer*from);externvoidsubgroup_default_withdraw_packet(structupdate_subgro
up*subgrp);/*bgp_updgrp_adv.c*/externstructbgp_advertise*bgp_advertise_clean_sub
group(structupdate_subgroup*subgrp,structbgp_adj_out*adj);externvoidupdate_group
_show_adj_queue(structbgp*bgp,afi_tafi,safi_tsafi,structvty*vty,uint64_tid);exte
rnvoidupdate_group_show_advertised(structbgp*bgp,afi_tafi,safi_tsafi,structvty*v
ty,uint64_tid);externvoidupdate_group_show_packet_queue(structbgp*bgp,afi_tafi,s
afi_tsafi,structvty*vty,uint64_tid);externvoidsubgroup_announce_route(structupda
te_subgroup*subgrp);externvoidsubgroup_announce_all(structupdate_subgroup*subgrp
);externvoidsubgroup_default_originate(structupdate_subgroup*subgrp,intwithdraw)
;externvoidgroup_announce_route(structbgp*bgp,afi_tafi,safi_tsafi,structbgp_node
*rn,structbgp_info*ri);externvoidsubgroup_clear_table(structupdate_subgroup*subg
rp);externvoidupdate_group_announce(structbgp*bgp);externvoidupdate_group_announ
ce_rrclients(structbgp*bgp);externvoidpeer_af_announce_route(structpeer_af*paf,i
ntcombine);externstructbgp_adj_out*bgp_adj_out_alloc(structupdate_subgroup*subgr
p,structbgp_node*rn,uint32_taddpath_tx_id);externvoidbgp_adj_out_remove_subgroup
(structbgp_node*rn,structbgp_adj_out*adj,structupdate_subgroup*subgrp);externvoi
dbgp_adj_out_set_subgroup(structbgp_node*rn,structupdate_subgroup*subgrp,structa
ttr*attr,structbgp_info*binfo);externvoidbgp_adj_out_unset_subgroup(structbgp_no
de*rn,structupdate_subgroup*subgrp,charwithdraw,uint32_taddpath_tx_id);voidsubgr
oup_announce_table(structupdate_subgroup*subgrp,structbgp_table*table);externvoi
dsubgroup_trigger_write(structupdate_subgroup*subgrp);externintupdate_group_clea
r_update_dbg(structupdate_group*updgrp,void*arg);externvoidupdate_bgp_group_free
(structbgp*bgp);externintbgp_addpath_encode_tx(structpeer*peer,afi_tafi,safi_tsa
fi);externintbgp_addpath_tx_path(structpeer*peer,afi_tafi,safi_tsafi,structbgp_i
nfo*ri);/**Inlinefunctions*//**bpacket_queue_is_empty*/staticinlineintbpacket_qu
eue_is_empty(structbpacket_queue*queue){/**Thepacketqueueisemptyifitonlycontains
asentinel.*/if(queue->curr_count!=1)return0;assert(bpacket_queue_first(queue)->b
uffer==NULL);return1;}/**bpacket_next**Returnsthepacketafterthegivenpacketinabpa
cketqueue.*/staticinlinestructbpacket*bpacket_next(structbpacket*pkt){returnTAIL
Q_NEXT(pkt,pkt_train);}/**update_group_adjust_peer_afs**Adjustallpeer_afstructur
esforthegivenpeer.*/staticinlinevoidupdate_group_adjust_peer_afs(structpeer*peer
){structpeer_af*paf;intafidx;for(afidx=BGP_AF_START;afidx<BGP_AF_MAX;afidx++){pa
f=peer->peer_af_array[afidx];if(paf!=NULL)update_group_adjust_peer(paf);}}/**upd
ate_group_remove_peer_afs**Removeallpeer_afstructuresforthegivenpeerfromtheirsub
groups.*/staticinlinevoidupdate_group_remove_peer_afs(structpeer*peer){structpee
r_af*paf;intafidx;for(afidx=BGP_AF_START;afidx<BGP_AF_MAX;afidx++){paf=peer->pee
r_af_array[afidx];if(paf!=NULL)update_subgroup_remove_peer(PAF_SUBGRP(paf),paf);
}}/**update_subgroup_needs_refresh*/staticinlineintupdate_subgroup_needs_refresh
(conststructupdate_subgroup*subgrp){if(CHECK_FLAG(subgrp->flags,SUBGRP_FLAG_NEED
S_REFRESH))return1;elsereturn0;}/**update_subgroup_set_needs_refresh*/staticinli
nevoidupdate_subgroup_set_needs_refresh(structupdate_subgroup*subgrp,intvalue){i
f(value)SET_FLAG(subgrp->flags,SUBGRP_FLAG_NEEDS_REFRESH);elseUNSET_FLAG(subgrp-
>flags,SUBGRP_FLAG_NEEDS_REFRESH);}staticinlinestructupdate_subgroup*peer_subgro
up(structpeer*peer,afi_tafi,safi_tsafi){structpeer_af*paf;paf=peer_af_find(peer,
afi,safi);if(paf)returnPAF_SUBGRP(paf);returnNULL;}/**update_group_adjust_peer_a
fs**Adjustallpeer_afstructuresforthegivenpeer.*/staticinlinevoidbgp_announce_pee
r(structpeer*peer){structpeer_af*paf;intafidx;for(afidx=BGP_AF_START;afidx<BGP_A
F_MAX;afidx++){paf=peer->peer_af_array[afidx];if(paf!=NULL)subgroup_announce_all
(PAF_SUBGRP(paf));}}/***advertise_list_is_empty*/staticinlineintadvertise_list_i
s_empty(structupdate_subgroup*subgrp){if(!BGP_ADV_FIFO_EMPTY(&subgrp->sync->upda
te)||!BGP_ADV_FIFO_EMPTY(&subgrp->sync->withdraw)||!BGP_ADV_FIFO_EMPTY(&subgrp->
sync->withdraw_low)){return0;}return1;}#endif/*_QUAGGA_BGP_UPDGRP_H*/