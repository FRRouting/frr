/**Thisisanimplementationofrfc2370.*Copyright(C)2001KDDR&DLaboratories,Inc.*http
://www.kddlabs.co.jp/**ThisfileispartofGNUZebra.**GNUZebraisfreesoftware;youcanr
edistributeitand/ormodifyit*underthetermsoftheGNUGeneralPublicLicenseaspublished
bythe*FreeSoftwareFoundation;eitherversion2,or(atyouroption)any*laterversion.**G
NUZebraisdistributedinthehopethatitwillbeuseful,but*WITHOUTANYWARRANTY;withoutev
entheimpliedwarrantyof*MERCHANTABILITYorFITNESSFORAPARTICULARPURPOSE.SeetheGNU*G
eneralPublicLicenseformoredetails.**YoushouldhavereceivedacopyoftheGNUGeneralPub
licLicensealong*withthisprogram;seethefileCOPYING;ifnot,writetotheFreeSoftware*F
oundation,Inc.,51FranklinSt,FifthFloor,Boston,MA02110-1301USA*/#ifndef_ZEBRA_OSP
F_OPAQUE_H#define_ZEBRA_OSPF_OPAQUE_H#include"vty.h"#defineIS_OPAQUE_LSA(type)\(
(type)==OSPF_OPAQUE_LINK_LSA||(type)==OSPF_OPAQUE_AREA_LSA\||(type)==OSPF_OPAQUE
_AS_LSA)/**OpaqueLSA'slinkstateIDisredefinedasfollows.**241680*+--------+-------
-+--------+--------+*|tttttttt|........|........|........|*+--------+--------+--
------+--------+*|<-Type->|<-------OpaqueID------>|*/#defineLSID_OPAQUE_TYPE_MAS
K0xff000000/*8bits*/#defineLSID_OPAQUE_ID_MASK0x00ffffff/*24bits*/#defineGET_OPA
QUE_TYPE(lsid)(((uint32_t)(lsid)&LSID_OPAQUE_TYPE_MASK)>>24)#defineGET_OPAQUE_ID
(lsid)((uint32_t)(lsid)&LSID_OPAQUE_ID_MASK)#defineSET_OPAQUE_LSID(type,id)\((((
unsigned)(type)<<24)&LSID_OPAQUE_TYPE_MASK)\|((id)&LSID_OPAQUE_ID_MASK))/**Opaqu
eLSAtypeswillbeassignedbyIANA.*<http://www.iana.org/assignments/ospf-opaque-type
s>*/#defineOPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA1#defineOPAQUE_TYPE_SYCAMORE_OPTIC
AL_TOPOLOGY_DESC2#defineOPAQUE_TYPE_GRACE_LSA3#defineOPAQUE_TYPE_L1VPN_LSA5#defi
neOPAQUE_TYPE_ROUTER_INFORMATION_LSA4#defineOPAQUE_TYPE_INTER_AS_LSA6#defineOPAQ
UE_TYPE_EXTENDED_PREFIX_LSA7#defineOPAQUE_TYPE_EXTENDED_LINK_LSA8#defineOPAQUE_T
YPE_MAX8/*Followingstypesareproposedininternet-draftdocuments.*/#defineOPAQUE_TY
PE_8021_QOSPF129#defineOPAQUE_TYPE_SECONDARY_NEIGHBOR_DISCOVERY224#defineOPAQUE_
TYPE_FLOODGATE225/*Uglyhacktomakeuseofanunallocatedvalueforwildcardmatching!*/#d
efineOPAQUE_TYPE_WILDCARD0#defineOPAQUE_TYPE_RANGE_UNASSIGNED(type)\(OPAQUE_TYPE
_MAX<=(type)&&(type)<=127)#defineOPAQUE_TYPE_RANGE_RESERVED(type)(127<(type)&&(t
ype)<=255)#defineVALID_OPAQUE_INFO_LEN(lsahdr)\((ntohs((lsahdr)->length)>=sizeof
(structlsa_header))\&&((ntohs((lsahdr)->length)%sizeof(uint32_t))==0))/**Followi
ngsectiondefinesgenericTLV(type,length,value)macros,*usedforvariousLSAopaqueusag
ee.g.TrafficEngineering.*/structtlv_header{uint16_ttype;/*TypeofValue*/uint16_tl
ength;/*LengthofValueportiononly,inbytes*/};#defineTLV_HDR_SIZE(sizeof(structtlv
_header))#defineTLV_BODY_SIZE(tlvh)(ROUNDUP(ntohs((tlvh)->length),sizeof(uint32_
t)))#defineTLV_SIZE(tlvh)(TLV_HDR_SIZE+TLV_BODY_SIZE(tlvh))#defineTLV_HDR_TOP(ls
ah)\(structtlv_header*)((char*)(lsah)+OSPF_LSA_HEADER_SIZE)#defineTLV_HDR_NEXT(t
lvh)\(structtlv_header*)((char*)(tlvh)+TLV_SIZE(tlvh))#defineTLV_HDR_SUBTLV(tlvh
)\(structtlv_header*)((char*)(tlvh)+TLV_HDR_SIZE)#defineTLV_DATA(tlvh)(void*)((c
har*)(tlvh)+TLV_HDR_SIZE)#defineTLV_TYPE(tlvh)tlvh.header.type#defineTLV_LEN(tlv
h)tlvh.header.length#defineTLV_HDR(tlvh)tlvh.header/*Followingdeclarationconcern
stheOpaqueLSAmanagement*/enumlsa_opcode{REORIGINATE_THIS_LSA,REFRESH_THIS_LSA,FL
USH_THIS_LSA};/*Prototypes.*/externvoidospf_opaque_init(void);externvoidospf_opa
que_term(void);externvoidospf_opaque_finish(void);externintospf_opaque_type9_lsa
_init(structospf_interface*oi);externvoidospf_opaque_type9_lsa_term(structospf_i
nterface*oi);externintospf_opaque_type10_lsa_init(structospf_area*area);externvo
idospf_opaque_type10_lsa_term(structospf_area*area);externintospf_opaque_type11_
lsa_init(structospf*ospf);externvoidospf_opaque_type11_lsa_term(structospf*ospf)
;externintospf_register_opaque_functab(uint8_tlsa_type,uint8_topaque_type,int(*n
ew_if_hook)(structinterface*ifp),int(*del_if_hook)(structinterface*ifp),void(*is
m_change_hook)(structospf_interface*oi,intold_status),void(*nsm_change_hook)(str
uctospf_neighbor*nbr,intold_status),void(*config_write_router)(structvty*vty),vo
id(*config_write_if)(structvty*vty,structinterface*ifp),void(*config_write_debug
)(structvty*vty),void(*show_opaque_info)(structvty*vty,structospf_lsa*lsa),int(*
lsa_originator)(void*arg),structospf_lsa*(*lsa_refresher)(structospf_lsa*lsa),in
t(*new_lsa_hook)(structospf_lsa*lsa),int(*del_lsa_hook)(structospf_lsa*lsa));ext
ernvoidospf_delete_opaque_functab(uint8_tlsa_type,uint8_topaque_type);externinto
spf_opaque_new_if(structinterface*ifp);externintospf_opaque_del_if(structinterfa
ce*ifp);externvoidospf_opaque_ism_change(structospf_interface*oi,intold_status);
externvoidospf_opaque_nsm_change(structospf_neighbor*nbr,intold_status);externvo
idospf_opaque_config_write_router(structvty*vty,structospf*ospf);externvoidospf_
opaque_config_write_if(structvty*vty,structinterface*ifp);externvoidospf_opaque_
config_write_debug(structvty*vty);externvoidshow_opaque_info_detail(structvty*vt
y,structospf_lsa*lsa);externvoidospf_opaque_lsa_dump(structstream*s,uint16_tleng
th);externvoidospf_opaque_lsa_originate_schedule(structospf_interface*oi,int*ini
t_delay);externstructospf_lsa*ospf_opaque_lsa_install(structospf_lsa*lsa,intrt_r
ecalc);externstructospf_lsa*ospf_opaque_lsa_refresh(structospf_lsa*lsa);externvo
idospf_opaque_lsa_reoriginate_schedule(void*lsa_type_dependent,uint8_tlsa_type,u
int8_topaque_type);externvoidospf_opaque_lsa_refresh_schedule(structospf_lsa*lsa
);externvoidospf_opaque_lsa_flush_schedule(structospf_lsa*lsa);externvoidospf_op
aque_self_originated_lsa_received(structospf_neighbor*nbr,structospf_lsa*lsa);ex
ternstructospf*oi_to_top(structospf_interface*oi);#endif/*_ZEBRA_OSPF_OPAQUE_H*/
