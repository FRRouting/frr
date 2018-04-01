/*Genericlinkedlist*Copyright(C)1997,2000KunihiroIshiguro**ThisfileispartofGNUZe
bra.**GNUZebraisfreesoftware;youcanredistributeitand/ormodifyit*underthetermsoft
heGNUGeneralPublicLicenseaspublishedbythe*FreeSoftwareFoundation;eitherversion2,
or(atyouroption)any*laterversion.**GNUZebraisdistributedinthehopethatitwillbeuse
ful,but*WITHOUTANYWARRANTY;withouteventheimpliedwarrantyof*MERCHANTABILITYorFITN
ESSFORAPARTICULARPURPOSE.SeetheGNU*GeneralPublicLicenseformoredetails.**Youshoul
dhavereceivedacopyoftheGNUGeneralPublicLicensealong*withthisprogram;seethefileCO
PYING;ifnot,writetotheFreeSoftware*Foundation,Inc.,51FranklinSt,FifthFloor,Bosto
n,MA02110-1301USA*/#ifndef_ZEBRA_LINKLIST_H#define_ZEBRA_LINKLIST_H/*listnodesmu
stalwayscontaindatatobevalid.Addinganemptynode*toalistisinvalid*/structlistnode{
structlistnode*next;structlistnode*prev;/*privatemember,usegetdata()toretrieve,d
onotaccessdirectly*/void*data;};structlist{structlistnode*head;structlistnode*ta
il;/*invariant:countisthenumberoflistnodesinthelist*/unsignedintcount;/**Returns
-1ifval1<val2,0ifequal?,1ifval1>val2.*Usedasdefinitionofsortedforlistnode_add_so
rt*/int(*cmp)(void*val1,void*val2);/*callbacktofreeuser-owneddatawhenlistnodeisd
eleted.supplying*thiscallbackisverymuchencouraged!*/void(*del)(void*val);};#defi
nelistnextnode(X)((X)?((X)->next):NULL)#definelisthead(X)((X)?((X)->head):NULL)#
definelisttail(X)((X)?((X)->tail):NULL)#definelistcount(X)((X)->count)#definelis
t_isempty(X)((X)->head==NULL&&(X)->tail==NULL)/*returnX->dataonlyifXandX->dataar
enotNULL*/#definelistgetdata(X)(assert(X),assert((X)->data!=NULL),(X)->data)/*Pr
ototypes.*/externstructlist*list_new(void);/*encouraged:setlist.delcallbackonnew
lists*/externvoidlistnode_add(structlist*,void*);externvoidlistnode_add_sort(str
uctlist*,void*);externstructlistnode*listnode_add_after(structlist*,structlistno
de*,void*);externstructlistnode*listnode_add_before(structlist*,structlistnode*,
void*);externvoidlistnode_move_to_tail(structlist*,structlistnode*);externvoidli
stnode_delete(structlist*,void*);externstructlistnode*listnode_lookup(structlist
*,void*);externvoid*listnode_head(structlist*);/**Theusageoflist_deleteisbeingtr
ansitionedtopassin*thedoublepointertoremoveuseafterfree's.*list_freeusageisdepre
cated,itleadstomemoryleaks*ofthelinklistnodes.Pleaseuselist_delete_and_null**InO
ctof2018,renamelist_delete_and_nulltolist_delete*andremovelist_delete_originalan
dthelist_delete#define*Additionallyremovelist_freeentirely*/#ifCONFDATE>20181001
CPP_NOTICE("list_deletewithoutdoublepointerisdeprecated,pleasefixup")#endifexter
nvoidlist_delete_and_null(structlist**);externvoidlist_delete_original(structlis
t*);#definelist_delete(X)\list_delete_original((X))\CPP_WARN("Pleasetransitionto
usinglist_delete_and_null")#definelist_free(X)\list_delete_original((X))\CPP_WAR
N("Pleasetransitiontousinglist_delete_and_null")externvoidlist_delete_all_node(s
tructlist*);/*Forospfdandospf6d.*/externvoidlist_delete_node(structlist*,structl
istnode*);/*Forospf_spf.c*/externvoidlist_add_list(structlist*,structlist*);/*Li
stiterationmacro.*Usage:for(ALL_LIST_ELEMENTS(...){...}*Itissafetodeletethelistn
odeusingthismacro.*/#defineALL_LIST_ELEMENTS(list,node,nextnode,data)\(node)=lis
thead(list),((data)=NULL);\(node)!=NULL\&&((data)=listgetdata(node),(nextnode)=n
ode->next,1);\(node)=(nextnode),((data)=NULL)/*read-onlylistiterationmacro.*Usag
e:asperALL_LIST_ELEMENTS,butnotsafetodeletethelistnodeOnly*usethismacrowhenitis*
immediatelyobvious*thelistnodeisnot*deletedinthebodyoftheloop.Doesnothaveforward
-referenceoverhead*ofpreviousmacro.*/#defineALL_LIST_ELEMENTS_RO(list,node,data)
\(node)=listhead(list),((data)=NULL);\(node)!=NULL&&((data)=listgetdata(node),1)
;\(node)=listnextnode(node),((data)=NULL)/*these*donot*cleanuplistnodesandrefere
nceddata,asthefunctions*do-thesemacrossimply{de,at}tachalistnodefrom/toalist.*//
*Listnodeattachmacro.*/#defineLISTNODE_ATTACH(L,N)\do{\(N)->prev=(L)->tail;\(N)-
>next=NULL;\if((L)->head==NULL)\(L)->head=(N);\else\(L)->tail->next=(N);\(L)->ta
il=(N);\(L)->count++;\}while(0)/*Listnodedetachmacro.*/#defineLISTNODE_DETACH(L,
N)\do{\if((N)->prev)\(N)->prev->next=(N)->next;\else\(L)->head=(N)->next;\if((N)
->next)\(N)->next->prev=(N)->prev;\else\(L)->tail=(N)->prev;\(L)->count--;\}whil
e(0)#endif/*_ZEBRA_LINKLIST_H*/