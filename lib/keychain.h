/*key-chainforauthentication.*Copyright(C)2000KunihiroIshiguro**Thisfileispartof
GNUZebra.**GNUZebraisfreesoftware;youcanredistributeitand/ormodify*itundertheter
msoftheGNUGeneralPublicLicenseaspublished*bytheFreeSoftwareFoundation;eithervers
ion2,or(atyour*option)anylaterversion.**GNUZebraisdistributedinthehopethatitwill
beuseful,but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYo
rFITNESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**You
shouldhavereceivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethef
ileCOPYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,
Boston,MA02110-1301USA*/#ifndef_ZEBRA_KEYCHAIN_H#define_ZEBRA_KEYCHAIN_H#include
"qobj.h"structkeychain{char*name;structlist*key;QOBJ_FIELDS};DECLARE_QOBJ_TYPE(k
eychain)structkey_range{time_tstart;time_tend;uint8_tduration;};structkey{uint32
_tindex;char*string;structkey_rangesend;structkey_rangeaccept;QOBJ_FIELDS};DECLA
RE_QOBJ_TYPE(key)externvoidkeychain_init(void);externstructkeychain*keychain_loo
kup(constchar*);externstructkey*key_lookup_for_accept(conststructkeychain*,uint3
2_t);externstructkey*key_match_for_accept(conststructkeychain*,constchar*);exter
nstructkey*key_lookup_for_send(conststructkeychain*);#endif/*_ZEBRA_KEYCHAIN_H*/
