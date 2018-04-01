/**Copyright(C)2003YasuhiroOhara**ThisfileispartofGNUZebra.**GNUZebraisfreesoftw
are;youcanredistributeitand/ormodifyit*underthetermsoftheGNUGeneralPublicLicense
aspublishedbythe*FreeSoftwareFoundation;eitherversion2,or(atyouroption)any*later
version.**GNUZebraisdistributedinthehopethatitwillbeuseful,but*WITHOUTANYWARRANT
Y;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSFORAPARTICULARPURPOSE.
SeetheGNU*GeneralPublicLicenseformoredetails.**YoushouldhavereceivedacopyoftheGN
UGeneralPublicLicensealong*withthisprogram;seethefileCOPYING;ifnot,writetotheFre
eSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA02110-1301USA*/#ifnde
fOSPF6_INTERFACE_H#defineOSPF6_INTERFACE_H#include"qobj.h"#include"hook.h"#inclu
de"if.h"/*Debugoption*/externunsignedcharconf_debug_ospf6_interface;#defineOSPF6
_DEBUG_INTERFACE_ON()(conf_debug_ospf6_interface=1)#defineOSPF6_DEBUG_INTERFACE_
OFF()(conf_debug_ospf6_interface=0)#defineIS_OSPF6_DEBUG_INTERFACE(conf_debug_os
pf6_interface)/*Interfacestructure*/structospf6_interface{/*IFinfofromzebra*/str
uctinterface*interface;/*backpointer*/structospf6_area*area;/*listofospf6neighbo
r*/structlist*neighbor_list;/*linklocaladdressofthisI/F*/structin6_addr*linkloca
l_addr;/*InterfaceID;useinterface->ifindex*//*ospf6instanceid*/uint8_tinstance_i
d;/*I/Ftransmissiondelay*/uint32_ttransdelay;/*NetworkType*/uint8_ttype;/*Router
Priority*/uint8_tpriority;/*TimeInterval*/uint16_thello_interval;uint16_tdead_in
terval;uint32_trxmt_interval;uint32_tstate_change;/*Cost*/uint32_tcost;/*I/FMTU*
/uint32_tifmtu;/*ConfiguredMTU*/uint32_tc_ifmtu;/*InterfaceState*/uint8_tstate;/
*Interfacesocketsettingtrialcounter,resetsonsuccess*/uint8_tsso_try_cnt;/*OSPF6I
nterfaceflag*/charflag;/*MTUmismatchcheck*/uint8_tmtu_ignore;/*DecisionofDRElect
ion*/uint32_tdrouter;uint32_tbdrouter;uint32_tprev_drouter;uint32_tprev_bdrouter
;/*LinklocalLSADatabase:includesLink-LSA*/structospf6_lsdb*lsdb;structospf6_lsdb
*lsdb_self;structospf6_lsdb*lsupdate_list;structospf6_lsdb*lsack_list;/*OngoingT
asks*/structthread*thread_send_hello;structthread*thread_send_lsupdate;structthr
ead*thread_send_lsack;structthread*thread_network_lsa;structthread*thread_link_l
sa;structthread*thread_intra_prefix_lsa;structthread*thread_as_extern_lsa;struct
ospf6_route_table*route_connected;/*prefix-listnametofilterconnectedprefix*/char
*plist_name;/*BFDinformation*/void*bfd_info;/*StatisticsFields*/uint32_thello_in
;uint32_thello_out;uint32_tdb_desc_in;uint32_tdb_desc_out;uint32_tls_req_in;uint
32_tls_req_out;uint32_tls_upd_in;uint32_tls_upd_out;uint32_tls_ack_in;uint32_tls
_ack_out;uint32_tdiscarded;QOBJ_FIELDS};DECLARE_QOBJ_TYPE(ospf6_interface)/*inte
rfacestate*/#defineOSPF6_INTERFACE_NONE0#defineOSPF6_INTERFACE_DOWN1#defineOSPF6
_INTERFACE_LOOPBACK2#defineOSPF6_INTERFACE_WAITING3#defineOSPF6_INTERFACE_POINTT
OPOINT4#defineOSPF6_INTERFACE_DROTHER5#defineOSPF6_INTERFACE_BDR6#defineOSPF6_IN
TERFACE_DR7#defineOSPF6_INTERFACE_MAX8externconstchar*ospf6_interface_state_str[
];/*flags*/#defineOSPF6_INTERFACE_DISABLE0x01#defineOSPF6_INTERFACE_PASSIVE0x02#
defineOSPF6_INTERFACE_NOAUTOCOST0x04/*defaultvalues*/#defineOSPF6_INTERFACE_HELL
O_INTERVAL10#defineOSPF6_INTERFACE_DEAD_INTERVAL40#defineOSPF6_INTERFACE_RXMT_IN
TERVAL5#defineOSPF6_INTERFACE_COST1#defineOSPF6_INTERFACE_PRIORITY1#defineOSPF6_
INTERFACE_TRANSDELAY1#defineOSPF6_INTERFACE_INSTANCE_ID0#defineOSPF6_INTERFACE_B
ANDWIDTH10000/*Mbps*/#defineOSPF6_REFERENCE_BANDWIDTH100000/*Mbps*/#defineOSPF6_
INTERFACE_SSO_RETRY_INT1#defineOSPF6_INTERFACE_SSO_RETRY_MAX5/*FunctionPrototype
s*/externstructospf6_interface*ospf6_interface_lookup_by_ifindex(ifindex_t);exte
rnstructospf6_interface*ospf6_interface_create(structinterface*);externvoidospf6
_interface_delete(structospf6_interface*);externvoidospf6_interface_enable(struc
tospf6_interface*);externvoidospf6_interface_disable(structospf6_interface*);ext
ernvoidospf6_interface_if_add(structinterface*);externvoidospf6_interface_if_del
(structinterface*);externvoidospf6_interface_state_update(structinterface*);exte
rnvoidospf6_interface_connected_route_update(structinterface*);/*interfaceevent*
/externintinterface_up(structthread*);externintinterface_down(structthread*);ext
ernintwait_timer(structthread*);externintbackup_seen(structthread*);externintnei
ghbor_change(structthread*);externvoidospf6_interface_init(void);externvoidinsta
ll_element_ospf6_clear_interface(void);externintconfig_write_ospf6_debug_interfa
ce(structvty*vty);externvoidinstall_element_ospf6_debug_interface(void);DECLARE_
HOOK(ospf6_interface_change,(structospf6_interface*oi,intstate,intold_state),(oi
,state,old_state))#endif/*OSPF6_INTERFACE_H*/