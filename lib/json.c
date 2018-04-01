/*json-cwrapper*Copyright(C)2015CumulusNetworks,Inc.**ThisfileispartofGNUZebra.*
*GNUZebraisfreesoftware;youcanredistributeitand/ormodifyit*underthetermsoftheGNU
GeneralPublicLicenseaspublishedbythe*FreeSoftwareFoundation;eitherversion2,or(at
youroption)any*laterversion.**GNUZebraisdistributedinthehopethatitwillbeuseful,b
ut*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSFO
RAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Youshouldhave
receivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefileCOPYING
;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA0
2110-1301USA*/#include<zebra.h>#include"command.h"#include"lib/json.h"/**Thisfun
ctionassumesthatthejsonkeyword*isthe*last*keywordonthelinenomatter*what.*/intuse
_json(constintargc,structcmd_token*argv[]){if(argc==0)return0;if(argv[argc-1]->a
rg&&strmatch(argv[argc-1]->text,"json"))return1;return0;}voidjson_object_string_
add(structjson_object*obj,constchar*key,constchar*s){json_object_object_add(obj,
key,json_object_new_string(s));}voidjson_object_int_add(structjson_object*obj,co
nstchar*key,int64_ti){#ifdefined(HAVE_JSON_C_JSON_H)json_object_object_add(obj,k
ey,json_object_new_int64(i));#elsejson_object_object_add(obj,key,json_object_new
_int((int)i));#endif}voidjson_object_boolean_false_add(structjson_object*obj,con
stchar*key){json_object_object_add(obj,key,json_object_new_boolean(0));}voidjson
_object_boolean_true_add(structjson_object*obj,constchar*key){json_object_object
_add(obj,key,json_object_new_boolean(1));}structjson_object*json_object_lock(str
uctjson_object*obj){returnjson_object_get(obj);}voidjson_object_free(structjson_
object*obj){json_object_put(obj);}#if!defined(HAVE_JSON_C_JSON_H)intjson_object_
object_get_ex(structjson_object*obj,constchar*key,structjson_object**value){*val
ue=json_object_object_get(obj,key);if(*value)return1;return0;}#endif