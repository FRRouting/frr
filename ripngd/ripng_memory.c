/*ripngdmemorytypedefinitions**Copyright(C)2015DavidLamparter**ThisfileispartofQ
uagga.**Quaggaisfreesoftware;youcanredistributeitand/ormodifyit*underthetermsoft
heGNUGeneralPublicLicenseaspublishedbythe*FreeSoftwareFoundation;eitherversion2,
or(atyouroption)any*laterversion.**Quaggaisdistributedinthehopethatitwillbeusefu
l,but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNES
SFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Youshouldh
avereceivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefileCOPY
ING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,
MA02110-1301USA*/#ifdefHAVE_CONFIG_H#include"config.h"#endif#include"ripng_memor
y.h"DEFINE_MGROUP(RIPNGD,"ripngd")DEFINE_MTYPE(RIPNGD,RIPNG,"RIPngstructure")DEF
INE_MTYPE(RIPNGD,RIPNG_ROUTE,"RIPngrouteinfo")DEFINE_MTYPE(RIPNGD,RIPNG_AGGREGAT
E,"RIPngaggregate")DEFINE_MTYPE(RIPNGD,RIPNG_PEER,"RIPngpeer")DEFINE_MTYPE(RIPNG
D,RIPNG_OFFSET_LIST,"RIPngoffsetlst")DEFINE_MTYPE(RIPNGD,RIPNG_RTE_DATA,"RIPngrt
edata")