/**PIMforQuagga*Copyright(C)2015CumulusNetworks,Inc.*DonaldSharp**Thisprogramisf
reesoftware;youcanredistributeitand/ormodify*itunderthetermsoftheGNUGeneralPubli
cLicenseaspublishedby*theFreeSoftwareFoundation;eitherversion2oftheLicense,or*(a
tyouroption)anylaterversion.**Thisprogramisdistributedinthehopethatitwillbeusefu
l,but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNES
SFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Youshouldh
avereceivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefileCOPY
ING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,
MA02110-1301USA*/#ifndefPIM_RP_H#definePIM_RP_H#include<zebra.h>#include"prefix.
h"#include"vty.h"#include"plist.h"#include"pim_iface.h"#include"pim_rpf.h"struct
rp_info{structprefixgroup;structpim_rpfrp;inti_am_rp;char*plist;};voidpim_rp_ini
t(structpim_instance*pim);voidpim_rp_free(structpim_instance*pim);voidpim_rp_lis
t_hash_clean(void*data);intpim_rp_new(structpim_instance*pim,constchar*rp,constc
har*group,constchar*plist);intpim_rp_del(structpim_instance*pim,constchar*rp,con
stchar*group,constchar*plist);voidpim_rp_prefix_list_update(structpim_instance*p
im,structprefix_list*plist);intpim_rp_config_write(structpim_instance*pim,struct
vty*vty,constchar*spaces);voidpim_rp_setup(structpim_instance*pim);intpim_rp_i_a
m_rp(structpim_instance*pim,structin_addrgroup);voidpim_rp_check_on_if_add(struc
tpim_interface*pim_ifp);voidpim_i_am_rp_re_evaluate(structpim_instance*pim);intp
im_rp_check_is_my_ip_address(structpim_instance*pim,structin_addrgroup,structin_
addrdest_addr);intpim_rp_set_upstream_addr(structpim_instance*pim,structin_addr*
up,structin_addrsource,structin_addrgroup);structpim_rpf*pim_rp_g(structpim_inst
ance*pim,structin_addrgroup);#defineI_am_RP(P,G)pim_rp_i_am_rp((P),(G))#defineRP
(P,G)pim_rp_g((P),(G))voidpim_rp_show_information(structpim_instance*pim,structv
ty*vty,uint8_tuj);voidpim_resolve_rp_nh(structpim_instance*pim);intpim_rp_list_c
mp(void*v1,void*v2);#endif