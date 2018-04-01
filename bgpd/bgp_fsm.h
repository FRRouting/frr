/*BGP-4FiniteStateMachine*FromRFC1771[ABorderGatewayProtocol4(BGP-4)]*Copyright(
C)1998KunihiroIshiguro**ThisfileispartofGNUZebra.**GNUZebraisfreesoftware;youcan
redistributeitand/ormodifyit*underthetermsoftheGNUGeneralPublicLicenseaspublishe
dbythe*FreeSoftwareFoundation;eitherversion2,or(atyouroption)any*laterversion.**
GNUZebraisdistributedinthehopethatitwillbeuseful,but*WITHOUTANYWARRANTY;withoute
ventheimpliedwarrantyof*MERCHANTABILITYorFITNESSFORAPARTICULARPURPOSE.SeetheGNU*
GeneralPublicLicenseformoredetails.**YoushouldhavereceivedacopyoftheGNUGeneralPu
blicLicensealong*withthisprogram;seethefileCOPYING;ifnot,writetotheFreeSoftware*
Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA02110-1301USA*/#ifndef_QUAGGA_B
GP_FSM_H#define_QUAGGA_BGP_FSM_H/*MacroforBGPread,writeandtimerthread.*/#defineB
GP_TIMER_ON(T,F,V)\do{\if((peer->status!=Deleted))\thread_add_timer(bm->master,(
F),peer,(V),&(T));\}while(0)#defineBGP_TIMER_OFF(T)\do{\if(T)\THREAD_TIMER_OFF(T
);\}while(0)#defineBGP_EVENT_ADD(P,E)\do{\if((P)->status!=Deleted)\thread_add_ev
ent(bm->master,bgp_event,(P),(E),\NULL);\}while(0)#defineBGP_EVENT_FLUSH(P)\do{\
assert(peer);\thread_cancel_event(bm->master,(P));\}while(0)#defineBGP_MSEC_JITT
ER10/*Statuscodesforbgp_event_update()*/#defineFSM_PEER_NOOP0#defineFSM_PEER_STO
PPED1#defineFSM_PEER_TRANSFERRED2#defineFSM_PEER_TRANSITIONED3/*Prototypes.*/ext
ernvoidbgp_fsm_nht_update(structpeer*,intvalid);externintbgp_event(structthread*
);externintbgp_event_update(structpeer*,intevent);externintbgp_stop(structpeer*p
eer);externvoidbgp_timer_set(structpeer*);externintbgp_routeadv_timer(structthre
ad*);externvoidbgp_fsm_change_status(structpeer*peer,intstatus);externconstchar*
peer_down_str[];externvoidbgp_update_delay_end(structbgp*);externvoidbgp_maxmed_
update(structbgp*);externintbgp_maxmed_onstartup_configured(structbgp*);externin
tbgp_maxmed_onstartup_active(structbgp*);/***Starttherouteadvertisementtimer(tha
thonorsMRAI)forallthe*peers.Typicallycalledattheendofinitialconvergence,coming*o
utofread-onlymode.*/externvoidbgp_start_routeadv(structbgp*);/***Seeiftheroutead
vertisementtimerneedstobeadjustedfora*peer.Forexample,ifthelastupdatewaswrittent
othepeera*longwhileback,wedon'tneedtowaitfortheperiodicadvertisement*timertoexpi
retosendthenewsetofprefixes.Itshouldfire*instantlyandupdatesshouldgooutsooner.*/
externvoidbgp_adjust_routeadv(structpeer*);#include"hook.h"DECLARE_HOOK(peer_bac
kward_transition,(structpeer*peer),(peer))DECLARE_HOOK(peer_established,(structp
eer*peer),(peer))#endif/*_QUAGGA_BGP_FSM_H*/