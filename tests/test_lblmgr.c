/**LabelManagerTest**Copyright(C)2017byBingenEguzkitza,*VoltaNetworksInc.**Thisf
ileispartofFreeRangeRouting(FRR)**FRRisfreesoftware;youcanredistributeitand/ormo
difyit*underthetermsoftheGNUGeneralPublicLicenseaspublishedbythe*FreeSoftwareFou
ndation;eitherversion2,or(atyouroption)any*laterversion.**FRRisdistributedintheh
opethatitwillbeuseful,but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MER
CHANTABILITYorFITNESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformore
details.**YoushouldhavereceivedacopyoftheGNUGeneralPublicLicensealong*withthispr
ogram;seethefileCOPYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinS
t,FifthFloor,Boston,MA02110-1301USA*/#include"lib/stream.h"#include"lib/zclient.
h"#defineZSERV_PATH"/tmp/zserv.api"//TODO!!#defineKEEP0/*changeto1toavoidgarbage
collection*/#defineCHUNK_SIZE32structzclient*zclient;unsignedshortinstance=1;con
stchar*sequence="GGRGGGRRG";staticintzebra_send_get_label_chunk(void);staticintz
ebra_send_release_label_chunk(uint32_tstart,uint32_tend);staticvoidprocess_next_
call(uint32_tstart,uint32_tend){sleep(3);if(!*sequence)exit(0);if(*sequence=='G'
)zebra_send_get_label_chunk();elseif(*sequence=='R')zebra_send_release_label_chu
nk(start,end);}/*ConnecttoLabelManager*/staticintzebra_send_label_manager_connec
t(){intret;printf("ConnecttoLabelManager\n");ret=lm_label_manager_connect(zclien
t);printf("LabelManagerconnectionresult:%u\n",ret);if(ret!=0){fprintf(stderr,"Er
ror%dconnectingtoLabelManager%s\n",ret,strerror(errno));exit(1);}process_next_ca
ll(0,0);}/*GetLabelChunk*/staticintzebra_send_get_label_chunk(){uint32_tstart;ui
nt32_tend;intret;printf("Askforlabelchunk\n");ret=lm_get_label_chunk(zclient,KEE
P,CHUNK_SIZE,&start,&end);if(ret!=0){fprintf(stderr,"Error%drequestinglabelchunk
%s\n",ret,strerror(errno));exit(1);}sequence++;printf("LabelChunkassign:%u-%u\n"
,start,end);process_next_call(start,end);}/*ReleaseLabelChunk*/staticintzebra_se
nd_release_label_chunk(uint32_tstart,uint32_tend){structstream*s;intret;printf("
Releaselabelchunk:%u-%u\n",start,end);ret=lm_release_label_chunk(zclient,start,e
nd);if(ret!=0){fprintf(stderr,"Errorreleasinglabelchunk\n");exit(1);}sequence++;
process_next_call(start-CHUNK_SIZE,end-CHUNK_SIZE);}voidinit_zclient(structthrea
d_master*master,char*lm_zserv_path){frr_zclient_addr(&zclient_addr,&zclient_addr
_len,lm_zserv_path);zclient=zclient_new_notify(master,&zclient_options_default);
/*zclient_init(zclient,ZEBRA_LABEL_MANAGER,0);*/zclient->sock=-1;zclient->redist
_default=ZEBRA_ROUTE_LDP;zclient->instance=instance;if(zclient_socket_connect(zc
lient)<0){printf("Errorconnectingsynchronouszclient!\n");exit(1);}}intmain(intar
gc,char*argv[]){structthread_master*master;structthreadthread;intret;printf("Seq
uencetobetested:%s\n",sequence);master=thread_master_create(NULL);init_zclient(m
aster,ZSERV_PATH);zebra_send_label_manager_connect();return0;}