/**PIMforQuagga*Copyright(C)2008EvertondaSilvaMarques**Thisprogramisfreesoftware
;youcanredistributeitand/ormodify*itunderthetermsoftheGNUGeneralPublicLicenseasp
ublishedby*theFreeSoftwareFoundation;eitherversion2oftheLicense,or*(atyouroption
)anylaterversion.**Thisprogramisdistributedinthehopethatitwillbeuseful,but*WITHO
UTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSFORAPARTIC
ULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Youshouldhavereceived
acopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefileCOPYING;ifnot,w
ritetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA02110-130
1USA*/#ifndefPIM_CMD_H#definePIM_CMD_H#definePIM_STR"PIMinformation\n"#defineIGM
P_STR"IGMPinformation\n"#defineIGMP_GROUP_STR"IGMPgroupsinformation\n"#defineIGM
P_SOURCE_STR"IGMPsourcesinformation\n"#defineCONF_SSMPINGD_STR"Enablessmpingdope
ration\n"#defineSHOW_SSMPINGD_STR"ssmpingdoperation\n"#defineIFACE_PIM_STR"Enabl
ePIMSSMoperation\n"#defineIFACE_PIM_SM_STR"EnablePIMSMoperation\n"#defineIFACE_P
IM_HELLO_STR"HelloInterval\n"#defineIFACE_PIM_HELLO_TIME_STR"TimeinsecondsforHel
loInterval\n"#defineIFACE_PIM_HELLO_HOLD_STR"TimeinsecondsforHoldInterval\n"#def
ineIFACE_IGMP_STR"EnableIGMPoperation\n"#defineIFACE_IGMP_QUERY_INTERVAL_STR"IGM
Phostqueryinterval\n"#defineIFACE_IGMP_QUERY_MAX_RESPONSE_TIME_STR"IGMPmaxqueryr
esponsevalue(seconds)\n"#defineIFACE_IGMP_QUERY_MAX_RESPONSE_TIME_DSEC_STR"IGMPm
axqueryresponsevalue(deciseconds)\n"#defineDEBUG_IGMP_STR"IGMPprotocolactivity\n
"#defineDEBUG_IGMP_EVENTS_STR"IGMPprotocolevents\n"#defineDEBUG_IGMP_PACKETS_STR
"IGMPprotocolpackets\n"#defineDEBUG_IGMP_TRACE_STR"IGMPinternaldaemonactivity\n"
#defineDEBUG_MROUTE_STR"PIMinteractionwithkernelMFCcache\n"#defineDEBUG_STATIC_S
TR"PIMStaticMulticastRouteactivity\n"#defineDEBUG_PIM_STR"PIMprotocolactivity\n"
#defineDEBUG_PIM_EVENTS_STR"PIMprotocolevents\n"#defineDEBUG_PIM_PACKETS_STR"PIM
protocolpackets\n"#defineDEBUG_PIM_HELLO_PACKETS_STR"PIMHelloprotocolpackets\n"#
defineDEBUG_PIM_J_P_PACKETS_STR"PIMJoin/Pruneprotocolpackets\n"#defineDEBUG_PIM_
PIM_REG_PACKETS_STR"PIMRegister/Reg-Stopprotocolpackets\n"#defineDEBUG_PIM_PACKE
TDUMP_STR"PIMpacketdump\n"#defineDEBUG_PIM_PACKETDUMP_SEND_STR"Dumpsentpackets\n
"#defineDEBUG_PIM_PACKETDUMP_RECV_STR"Dumpreceivedpackets\n"#defineDEBUG_PIM_TRA
CE_STR"PIMinternaldaemonactivity\n"#defineDEBUG_PIM_ZEBRA_STR"ZEBRAprotocolactiv
ity\n"#defineDEBUG_SSMPINGD_STR"ssmpingdactivity\n"#defineCLEAR_IP_IGMP_STR"IGMP
clearcommands\n"#defineCLEAR_IP_PIM_STR"PIMclearcommands\n"#defineMROUTE_STR"IPm
ulticastroutingtable\n"#defineRIB_STR"IPunicastroutingtable\n"#defineCFG_MSDP_ST
R"Configuremulticastsourcediscoveryprotocol\n"#defineMSDP_STR"MSDPinformation\n"
#defineDEBUG_MSDP_STR"MSDPprotocolactivity\n"#defineDEBUG_MSDP_EVENTS_STR"MSDPpr
otocolevents\n"#defineDEBUG_MSDP_INTERNAL_STR"MSDPprotocolinternal\n"#defineDEBU
G_MSDP_PACKETS_STR"MSDPprotocolpackets\n"#defineDEBUG_MTRACE_STR"Mtraceprotocola
ctivity\n"voidpim_cmd_init(void);/**SpecialMacrotoallowustogetthecorrectpim_inst
ance;*/#definePIM_DECLVAR_CONTEXT(A,B)\structvrf*A=VTY_GET_CONTEXT(vrf);\structp
im_instance*B=\(vrf)?vrf->info:pim_get_pim_instance(VRF_DEFAULT);\vrf=(vrf)?vrf:
pim->vrf;#endif/*PIM_CMD_H*/