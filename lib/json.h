/*json-cwrapper*Copyright(C)2015CumulusNetworks,Inc.**ThisfileispartofGNUZebra.*
*GNUZebraisfreesoftware;youcanredistributeitand/ormodifyit*underthetermsoftheGNU
GeneralPublicLicenseaspublishedbythe*FreeSoftwareFoundation;eitherversion2,or(at
youroption)any*laterversion.**GNUZebraisdistributedinthehopethatitwillbeuseful,b
ut*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSFO
RAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Youshouldhave
receivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefileCOPYING
;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA0
2110-1301USA*/#ifndef_QUAGGA_JSON_H#define_QUAGGA_JSON_H#ifdefined(HAVE_JSON_C_J
SON_H)#include<json-c/json.h>#else#include<json/json.h>/**json_object_to_json_st
ring_extisonlyavailableforjson-c*solet'sjustturnitbacktotheoriginalusage.*/#defi
nejson_object_to_json_string_ext(A,B)json_object_to_json_string(A)externintjson_
object_object_get_ex(structjson_object*obj,constchar*key,structjson_object**valu
e);#endif#include"command.h"externintuse_json(constintargc,structcmd_token*argv[
]);externvoidjson_object_string_add(structjson_object*obj,constchar*key,constcha
r*s);externvoidjson_object_int_add(structjson_object*obj,constchar*key,int64_ti)
;externvoidjson_object_boolean_false_add(structjson_object*obj,constchar*key);ex
ternvoidjson_object_boolean_true_add(structjson_object*obj,constchar*key);extern
structjson_object*json_object_lock(structjson_object*obj);externvoidjson_object_
free(structjson_object*obj);#defineJSON_STR"JavaScriptObjectNotation\n"/*NOTE:js
on-clibhasfollowingcommit316da85which*handlesescapeofforwardslash.*Thisallowspre
fix"20.0.14.0\/24":{*to"20.0.14.0/24":{someplatformsdonothave*latestcopyofjson-c
wheredefiningbelowmacro.*/#ifndefJSON_C_TO_STRING_NOSLASHESCAPE/***Don'tescapefo
rwardslashes.*/#defineJSON_C_TO_STRING_NOSLASHESCAPE(1<<4)#endif#endif/*_QUAGGA_
JSON_H*/