/*BGPadvertisementandadjacency*Copyright(C)1996,97,98,99,2000KunihiroIshiguro**T
hisfileispartofGNUZebra.**GNUZebraisfreesoftware;youcanredistributeitand/ormodif
yit*underthetermsoftheGNUGeneralPublicLicenseaspublishedbythe*FreeSoftwareFounda
tion;eitherversion2,or(atyouroption)any*laterversion.**GNUZebraisdistributedinth
ehopethatitwillbeuseful,but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*M
ERCHANTABILITYorFITNESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformo
redetails.**YoushouldhavereceivedacopyoftheGNUGeneralPublicLicensealong*withthis
program;seethefileCOPYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51Frankli
nSt,FifthFloor,Boston,MA02110-1301USA*/#ifndef_QUAGGA_BGP_ADVERTISE_H#define_QUA
GGA_BGP_ADVERTISE_H#include<lib/fifo.h>structupdate_subgroup;/*BGPadvertiseFIFO.
*/structbgp_advertise_fifo{structbgp_advertise*next;structbgp_advertise*prev;uin
t32_tcount;};/*BGPadvertiseattribute.*/structbgp_advertise_attr{/*Headofadvertis
ementpointer.*/structbgp_advertise*adv;/*Referencecounter.*/unsignedlongrefcnt;/
*Attributepointertobeannounced.*/structattr*attr;};structbgp_advertise{/*FIFOfor
advertisement.*/structbgp_advertise_fifofifo;/*Linklistforsameattributeadvertise
.*/structbgp_advertise*next;structbgp_advertise*prev;/*Prefixinformation.*/struc
tbgp_node*rn;/*Referencepointer.*/structbgp_adj_out*adj;/*Advertisementattribute
.*/structbgp_advertise_attr*baa;/*BGPinfo.*/structbgp_info*binfo;};/*BGPadjacenc
yout.*/structbgp_adj_out{/*Linedlistpointer.*/structbgp_adj_out*next;structbgp_a
dj_out*prev;/*Advertisedsubgroup.*/structupdate_subgroup*subgroup;/*Threadingtha
tmakestheadjpartofsubgroup'sadjqueue*/TAILQ_ENTRY(bgp_adj_out)subgrp_adj_train;/
*Prefixinformation.*/structbgp_node*rn;uint32_taddpath_tx_id;/*Advertisedattribu
te.*/structattr*attr;/*Advertisementinformation.*/structbgp_advertise*adv;};/*BG
Padjacencyin.*/structbgp_adj_in{/*Linkedlistpointer.*/structbgp_adj_in*next;stru
ctbgp_adj_in*prev;/*Receivedpeer.*/structpeer*peer;/*Receivedattribute.*/structa
ttr*attr;/*Addpathidentifier*/uint32_taddpath_rx_id;};/*BGPadvertisementlist.*/s
tructbgp_synchronize{structbgp_advertise_fifoupdate;structbgp_advertise_fifowith
draw;structbgp_advertise_fifowithdraw_low;};/*BGPadjacencylinkedlist.*/#defineBG
P_INFO_ADD(N,A,TYPE)\do{\(A)->prev=NULL;\(A)->next=(N)->TYPE;\if((N)->TYPE)\(N)-
>TYPE->prev=(A);\(N)->TYPE=(A);\}while(0)#defineBGP_INFO_DEL(N,A,TYPE)\do{\if((A
)->next)\(A)->next->prev=(A)->prev;\if((A)->prev)\(A)->prev->next=(A)->next;\els
e\(N)->TYPE=(A)->next;\}while(0)#defineBGP_ADJ_IN_ADD(N,A)BGP_INFO_ADD(N,A,adj_i
n)#defineBGP_ADJ_IN_DEL(N,A)BGP_INFO_DEL(N,A,adj_in)#defineBGP_ADJ_OUT_ADD(N,A)B
GP_INFO_ADD(N,A,adj_out)#defineBGP_ADJ_OUT_DEL(N,A)BGP_INFO_DEL(N,A,adj_out)#def
ineBGP_ADV_FIFO_ADD(F,N)\do{\FIFO_ADD((F),(N));\(F)->count++;\}while(0)#defineBG
P_ADV_FIFO_DEL(F,N)\do{\FIFO_DEL((N));\(F)->count--;\}while(0)#defineBGP_ADV_FIF
O_INIT(F)\do{\FIFO_INIT((F));\(F)->count=0;\}while(0)#defineBGP_ADV_FIFO_COUNT(F
)(F)->count#defineBGP_ADV_FIFO_EMPTY(F)\(((structbgp_advertise_fifo*)(F))->next\
==(structbgp_advertise*)(F))#defineBGP_ADV_FIFO_HEAD(F)\((((structbgp_advertise_
fifo*)(F))->next\==(structbgp_advertise*)(F))\?NULL\:(F)->next)/*Prototypes.*/ex
ternintbgp_adj_out_lookup(structpeer*,structbgp_node*,uint32_t);externvoidbgp_ad
j_in_set(structbgp_node*,structpeer*,structattr*,uint32_t);externintbgp_adj_in_u
nset(structbgp_node*,structpeer*,uint32_t);externvoidbgp_adj_in_remove(structbgp
_node*,structbgp_adj_in*);externvoidbgp_sync_init(structpeer*);externvoidbgp_syn
c_delete(structpeer*);externunsignedintbaa_hash_key(void*p);externintbaa_hash_cm
p(constvoid*p1,constvoid*p2);externvoidbgp_advertise_add(structbgp_advertise_att
r*baa,structbgp_advertise*adv);externstructbgp_advertise*bgp_advertise_new(void)
;externvoidbgp_advertise_free(structbgp_advertise*adv);externstructbgp_advertise
_attr*bgp_advertise_intern(structhash*hash,structattr*attr);externstructbgp_adve
rtise_attr*baa_new(void);externvoidbgp_advertise_delete(structbgp_advertise_attr
*baa,structbgp_advertise*adv);externvoidbgp_advertise_unintern(structhash*hash,s
tructbgp_advertise_attr*baa);#endif/*_QUAGGA_BGP_ADVERTISE_H*/