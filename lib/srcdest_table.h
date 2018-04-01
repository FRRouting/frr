/**SRC-DESTRoutingTable**Copyright(C)2017byDavidLamparter&ChristianFranke,*OpenS
ourceRouting/NetDEFInc.**ThisfileispartofFreeRangeRouting(FRR)**FRRisfreesoftwar
e;youcanredistributeitand/ormodifyit*underthetermsoftheGNUGeneralPublicLicenseas
publishedbythe*FreeSoftwareFoundation;eitherversion2,or(atyouroption)any*laterve
rsion.**FRRisdistributedinthehopethatitwillbeuseful,but*WITHOUTANYWARRANTY;witho
uteventheimpliedwarrantyof*MERCHANTABILITYorFITNESSFORAPARTICULARPURPOSE.SeetheG
NU*GeneralPublicLicenseformoredetails.**YoushouldhavereceivedacopyoftheGNUGenera
lPublicLicensealong*withthisprogram;seethefileCOPYING;ifnot,writetotheFreeSoftwa
re*Foundation,Inc.,51FranklinSt,FifthFloor,Boston,MA02110-1301USA*/#ifndef_ZEBRA
_SRC_DEST_TABLE_H#define_ZEBRA_SRC_DEST_TABLE_H/*old/IPv4/non-srcdest:*table->ro
ute_node.info->[obj]**new/IPv6/srcdest:*table-...->srcdest_rnode[prefix=dest].in
fo->[obj]*.src_table->*srcdesttable-...->route_node[prefix=src].info->[obj]**non
-srcdestroutes(src=::/0)aretreatedjustlikebefore,their*informationbeingdirectlyt
hereintheinfopointer.**srcdestroutesarefoundbylookingupdestinationfirst,thenlook
ing*upthesourceinthe"src_table".src_tablecontainsnormalroute_nodes,*whoseprefixi
sthe_source_prefix.**NB:infocanbeNULLonthedestinationrnode,ifthereareonlysrcdest
*routesforaparticulardestinationprefix.*/#include"prefix.h"#include"table.h"#def
ineSRCDEST2STR_BUFFER(2*PREFIX2STR_BUFFER+sizeof("from"))/*extendedroutenodeforI
Pv6srcdestrouting*/structsrcdest_rnode;externroute_table_delegate_t_srcdest_dstn
ode_delegate;externroute_table_delegate_t_srcdest_srcnode_delegate;externstructr
oute_table*srcdest_table_init(void);externstructroute_node*srcdest_rnode_get(str
uctroute_table*table,unionprefixptrdst_pu,structprefix_ipv6*src_p);externstructr
oute_node*srcdest_rnode_lookup(structroute_table*table,unionprefixptrdst_pu,stru
ctprefix_ipv6*src_p);externvoidsrcdest_rnode_prefixes(structroute_node*rn,struct
prefix**p,structprefix**src_p);externconstchar*srcdest_rnode2str(structroute_nod
e*rn,char*str,intsize);externstructroute_node*srcdest_route_next(structroute_nod
e*rn);staticinlineintrnode_is_dstnode(structroute_node*rn){returnrn->table->dele
gate==&_srcdest_dstnode_delegate;}staticinlineintrnode_is_srcnode(structroute_no
de*rn){returnrn->table->delegate==&_srcdest_srcnode_delegate;}staticinlinestruct
route_table*srcdest_rnode_table(structroute_node*rn){if(rnode_is_srcnode(rn)){st
ructroute_node*dst_rn=rn->table->info;returndst_rn->table;}else{returnrn->table;
}}staticinlinevoid*srcdest_rnode_table_info(structroute_node*rn){returnsrcdest_r
node_table(rn)->info;}#endif/*_ZEBRA_SRC_DEST_TABLE_H*/