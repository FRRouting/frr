/**DictionaryAbstractDataType*Copyright(C)1997KazKylheku<kaz@ashi.footprints.net
>**FreeSoftwareLicense:**Allrightsarereservedbytheauthor,withthefollowingexcepti
ons:*Permissionisgrantedtofreelyreproduceanddistributethissoftware,*possiblyinex
changeforafee,providedthatthiscopyrightnoticeappears*intact.Permissionisalsogran
tedtoadaptthissoftwaretoproduce*derivativeworks,aslongasthemodifiedversionscarry
thiscopyright*noticeandadditionalnoticesstatingthattheworkhasbeenmodified.*Thiss
ourcecodemaybetranslatedintoexecutableformandincorporated*intoproprietarysoftwar
e;thereisnorequirementforsuchsoftwareto*containacopyrightnoticerelatedtothissour
ce.*/#include"zebra.h"#include"zassert.h"#include"memory.h"#include"isis_memory.
h"#include"dict.h"/**Thesemacrosprovideshortconvenientnamesforstructuremembers,*
whichareembellishedwithdict_prefixessothattheyare*properlyconfinedtothedocumente
dnamespace.It'slegalfora*programwhichusesdicttodefine,forinstance,amacrocalled``
parent''.*Suchamacrowouldinterferewiththednode_tstructdefinition.*Ingeneral,high
lyportableandreusableCmoduleswhichexposetheir*structuresneedtoconfinestructureme
mbernamestowell-definedspaces.*Theresultingidentifiersaren'tnecessarilyconvenien
ttouse,nor*readable,intheimplementation,however!*/#defineleftdict_left#definerig
htdict_right#defineparentdict_parent#definecolordict_color#definekeydict_key#def
inedatadict_data#definenilnodedict_nilnode#definenodecountdict_nodecount#definem
axcountdict_maxcount#definecomparedict_compare#defineallocnodedict_allocnode#def
inefreenodedict_freenode#definecontextdict_context#definedupesdict_dupes#defined
ictptrdict_dictptr#definedict_root(D)((D)->nilnode.left)#definedict_nil(D)(&(D)-
>nilnode)#defineDICT_DEPTH_MAX64staticdnode_t*dnode_alloc(void*context);staticvo
iddnode_free(dnode_t*node,void*context);/**Performa``leftrotation''adjustmentont
hetree.ThegivennodePand*itsrightchildCarerearrangedsothatthePinsteadbecomesthele
ft*childofC.TheleftsubtreeofCisinheritedasthenewrightsubtree*forP.Theorderingoft
hekeyswithinthetreeisthuspreserved.*/staticvoidrotate_left(dnode_t*upper){dnode_
t*lower,*lowleft,*upparent;lower=upper->right;upper->right=lowleft=lower->left;l
owleft->parent=upper;lower->parent=upparent=upper->parent;/*don'tneedtocheckforr
ootnodeherebecauseroot->parentisthesentinelnilnode,androot->parent->leftpointsba
cktoroot*/if(upper==upparent->left){upparent->left=lower;}else{assert(upper==upp
arent->right);upparent->right=lower;}lower->left=upper;upper->parent=lower;}/**T
hisoperationisthe``mirror''imageofrotate_left.Itis*thesameprocedure,butwithlefta
ndrightinterchanged.*/staticvoidrotate_right(dnode_t*upper){dnode_t*lower,*lowri
ght,*upparent;lower=upper->left;upper->left=lowright=lower->right;lowright->pare
nt=upper;lower->parent=upparent=upper->parent;if(upper==upparent->right){upparen
t->right=lower;}else{assert(upper==upparent->left);upparent->left=lower;}lower->
right=upper;upper->parent=lower;}/**Doapostordertraversalofthetreerootedatthespe
cified*nodeandfreeeverythingunderit.Usedbydict_free().*/staticvoidfree_nodes(dic
t_t*dict,dnode_t*node,dnode_t*nil){if(node==nil)return;free_nodes(dict,node->lef
t,nil);free_nodes(dict,node->right,nil);dict->freenode(node,dict->context);}/**T
hisprocedureperformsaverificationthatthegivensubtreeisabinary*searchtree.Itperfo
rmsaninordertraversalofthetreeusingthe*dict_next()successorfunction,verifyingtha
tthekeyofeachnodeis*strictlylowerthanthatofitssuccessor,ifduplicatesarenotallowe
d,*orlowerorequalifduplicatesareallowed.Thisfunctionisusedfor*debuggingpurposes.
*/staticintverify_bintree(dict_t*dict){dnode_t*first,*next;first=dict_first(dict
);if(dict->dupes){while(first&&(next=dict_next(dict,first))){if(dict->compare(fi
rst->key,next->key)>0)return0;first=next;}}else{while(first&&(next=dict_next(dic
t,first))){if(dict->compare(first->key,next->key)>=0)return0;first=next;}}return
1;}/**Thisfunctionrecursivelyverifiesthatthegivenbinarysubtreesatisfies*threeoft
heredblackproperties.Itchecksthateveryrednodehasonly*blackchildren.Itmakessureth
ateachnodeiseitherredorblack.Andit*checksthateverypathhasthesamecountofblacknode
sfromroottoleaf.*Itreturnstheblackheightofthegivensubtree;thisallowsblackheights
to*becomputedrecursivelyandcomparedforleftandrightsiblingsfor*mismatches.Itdoesn
otcheckforeverynilnodebeingblack,becausethere*isonlyonesentinelnilnode.Thereturn
valueofthisfunctionisthe*blackheightofthesubtreerootedatthenode``root'',orzeroif
the*subtreeisnotred-black.*/#ifdefEXTREME_DICT_DEBUGstaticunsignedintverify_redb
lack(dnode_t*nil,dnode_t*root){unsignedheight_left,height_right;if(root!=nil){he
ight_left=verify_redblack(nil,root->left);height_right=verify_redblack(nil,root-
>right);if(height_left==0||height_right==0)return0;if(height_left!=height_right)
return0;if(root->color==dnode_red){if(root->left->color!=dnode_black)return0;if(
root->right->color!=dnode_black)return0;returnheight_left;}if(root->color!=dnode
_black)return0;returnheight_left+1;}return1;}#endif/**Computetheactualcountofnod
esbytraversingthetreeand*returnit.Thiscouldbecomparedagainstthestoredcountto*det
ectamismatch.*/#ifdefEXTREME_DICT_DEBUGstaticdictcount_tverify_node_count(dnode_
t*nil,dnode_t*root){if(root==nil)return0;elsereturn1+verify_node_count(nil,root-
>left)+verify_node_count(nil,root->right);}#endif/**Verifythatthetreecontainsthe
givennode.Thisisdoneby*traversingallofthenodesandcomparingtheirpointerstothe*giv
enpointer.Returns1ifthenodeisfound,otherwise*returnszero.Itisintendedfordebuggin
gpurposes.*/staticintverify_dict_has_node(dnode_t*nil,dnode_t*root,dnode_t*node)
{if(root!=nil){returnroot==node||verify_dict_has_node(nil,root->left,node)||veri
fy_dict_has_node(nil,root->right,node);}return0;}/**Dynamicallyallocateandinitia
lizeadictionaryobject.*/dict_t*dict_create(dictcount_tmaxcount,dict_comp_tcomp){
dict_t*new=XCALLOC(MTYPE_ISIS_DICT,sizeof(dict_t));if(new){new->compare=comp;new
->allocnode=dnode_alloc;new->freenode=dnode_free;new->context=NULL;new->nodecoun
t=0;new->maxcount=maxcount;new->nilnode.left=&new->nilnode;new->nilnode.right=&n
ew->nilnode;new->nilnode.parent=&new->nilnode;new->nilnode.color=dnode_black;new
->dupes=0;}returnnew;}/**Selectadifferentsetofnodeallocatorroutines.*/voiddict_s
et_allocator(dict_t*dict,dnode_alloc_tal,dnode_free_tfr,void*context){assert(dic
t_count(dict)==0);assert((al==NULL&&fr==NULL)||(al!=NULL&&fr!=NULL));dict->alloc
node=al?al:dnode_alloc;dict->freenode=fr?fr:dnode_free;dict->context=context;}/*
*Freeadynamicallyallocateddictionaryobject.Removingthenodes*fromthetreebeforedel
etingitisrequired.*/voiddict_destroy(dict_t*dict){assert(dict_isempty(dict));XFR
EE(MTYPE_ISIS_DICT,dict);}/**Freeallthenodesinthedictionarybyusingthedictionary'
s*installedfreeroutine.Thedictionaryisemptied.*/voiddict_free_nodes(dict_t*dict)
{dnode_t*nil=dict_nil(dict),*root=dict_root(dict);free_nodes(dict,root,nil);dict
->nodecount=0;dict->nilnode.left=&dict->nilnode;dict->nilnode.right=&dict->nilno
de;}/**Obsolescentfunction,equivalenttodict_free_nodes*/voiddict_free(dict_t*dic
t){dict_free_nodes(dict);}/**Initializeauser-supplieddictionaryobject.*/dict_t*d
ict_init(dict_t*dict,dictcount_tmaxcount,dict_comp_tcomp){dict->compare=comp;dic
t->allocnode=dnode_alloc;dict->freenode=dnode_free;dict->context=NULL;dict->node
count=0;dict->maxcount=maxcount;dict->nilnode.left=&dict->nilnode;dict->nilnode.
right=&dict->nilnode;dict->nilnode.parent=&dict->nilnode;dict->nilnode.color=dno
de_black;dict->dupes=0;returndict;}/**Initializeadictionaryinthelikenessofanothe
rdictionary*/voiddict_init_like(dict_t*dict,constdict_t*template){dict->compare=
template->compare;dict->allocnode=template->allocnode;dict->freenode=template->f
reenode;dict->context=template->context;dict->nodecount=0;dict->maxcount=templat
e->maxcount;dict->nilnode.left=&dict->nilnode;dict->nilnode.right=&dict->nilnode
;dict->nilnode.parent=&dict->nilnode;dict->nilnode.color=dnode_black;dict->dupes
=template->dupes;assert(dict_similar(dict,template));}/**Removeallnodesfromthedi
ctionary(withoutfreeingtheminanyway).*/staticvoiddict_clear(dict_t*dict){dict->n
odecount=0;dict->nilnode.left=&dict->nilnode;dict->nilnode.right=&dict->nilnode;
dict->nilnode.parent=&dict->nilnode;assert(dict->nilnode.color==dnode_black);}/*
*Verifytheintegrityofthedictionarystructure.Thisisprovidedfor*debuggingpurposes,
andshouldbeplacedinassertstatements.Justbecause*thisfunctionsucceedsdoesn'tmeant
hatthetreeisnotcorrupt.Certain*corruptionsinthetreemaysimplycauseundefinedbehavi
or.*/intdict_verify(dict_t*dict){#ifdefEXTREME_DICT_DEBUGdnode_t*nil=dict_nil(di
ct),*root=dict_root(dict);/*checkthatthesentinelnodeandrootnodeareblack*/if(root
->color!=dnode_black)return0;if(nil->color!=dnode_black)return0;if(nil->right!=n
il)return0;/*nil->leftistherootnode;checkthatitsparentpointerisnil*/if(nil->left
->parent!=nil)return0;/*performaweaktestthatthetreeisabinarysearchtree*/if(!veri
fy_bintree(dict))return0;/*verifythatthetreeisared-blacktree*/if(!verify_redblac
k(nil,root))return0;if(verify_node_count(nil,root)!=dict_count(dict))return0;#en
difreturn1;}/**Determinewhethertwodictionariesaresimilar:havethesamecomparisonan
d*allocatorfunctions,andsamestatusastowhetherduplicatesareallowed.*/intdict_simi
lar(constdict_t*left,constdict_t*right){if(left->compare!=right->compare)return0
;if(left->allocnode!=right->allocnode)return0;if(left->freenode!=right->freenode
)return0;if(left->context!=right->context)return0;if(left->dupes!=right->dupes)r
eturn0;return1;}/**Locateanodeinthedictionaryhavingthegivenkey.*Ifthenodeisnotfo
und,anullapointerisreturned(ratherthan*apointerthatdictionary'snilsentinelnode),
otherwiseapointertothe*locatednodeisreturned.*/dnode_t*dict_lookup(dict_t*dict,c
onstvoid*key){dnode_t*root=dict_root(dict);dnode_t*nil=dict_nil(dict);dnode_t*sa
ved;intresult;/*simplebinarysearchadaptedfortreesthatcontainduplicatekeys*/while
(root!=nil){result=dict->compare(key,root->key);if(result<0)root=root->left;else
if(result>0)root=root->right;else{if(!dict->dupes){/*noduplicates,returnmatch*/r
eturnroot;}else{/*couldbedupes,findleftmostone*/do{saved=root;root=root->left;wh
ile(root!=nil&&dict->compare(key,root->key))root=root->right;}while(root!=nil);r
eturnsaved;}}}returnNULL;}/**Lookforthenodecorrespondingtothelowestkeythatisequa
ltoor*greaterthanthegivenkey.Ifthereisnosuchnode,returnnull.*/dnode_t*dict_lower
_bound(dict_t*dict,constvoid*key){dnode_t*root=dict_root(dict);dnode_t*nil=dict_
nil(dict);dnode_t*tentative=0;while(root!=nil){intresult=dict->compare(key,root-
>key);if(result>0){root=root->right;}elseif(result<0){tentative=root;root=root->
left;}else{if(!dict->dupes){returnroot;}else{tentative=root;root=root->left;}}}r
eturntentative;}/**Lookforthenodecorrespondingtothegreatestkeythatisequaltoor*lo
werthanthegivenkey.Ifthereisnosuchnode,returnnull.*/dnode_t*dict_upper_bound(dic
t_t*dict,constvoid*key){dnode_t*root=dict_root(dict);dnode_t*nil=dict_nil(dict);
dnode_t*tentative=0;while(root!=nil){intresult=dict->compare(key,root->key);if(r
esult<0){root=root->left;}elseif(result>0){tentative=root;root=root->right;}else
{if(!dict->dupes){returnroot;}else{tentative=root;root=root->right;}}}returntent
ative;}/**Insertanodeintothedictionary.Thenodeshouldhavebeen*initializedwithadat
afield.Allotherfieldsareignored.*Thebehaviorisundefinediftheuserattemptstoinsert
into*adictionarythatisalreadyfull(forwhichthedict_isfull()*functionreturnstrue).
*/voiddict_insert(dict_t*dict,dnode_t*node,constvoid*key){dnode_t*where=dict_roo
t(dict),*nil=dict_nil(dict);dnode_t*parent=nil,*uncle,*grandpa;intresult=-1;node
->key=key;assert(!dict_isfull(dict));assert(!dict_contains(dict,node));assert(!d
node_is_in_a_dict(node));/*basicbinarytreeinsert*/while(where!=nil){parent=where
;result=dict->compare(key,where->key);/*trapattemptsatduplicatekeyinsertionunles
sit's*explicitlyallowed*/assert(dict->dupes||result!=0);if(result<0)where=where-
>left;elsewhere=where->right;}assert(where==nil);if(result<0)parent->left=node;e
lseparent->right=node;node->parent=parent;node->left=nil;node->right=nil;dict->n
odecount++;/*redblackadjustments*/node->color=dnode_red;while(parent->color==dno
de_red){grandpa=parent->parent;if(parent==grandpa->left){uncle=grandpa->right;if
(uncle->color==dnode_red){/*redparent,reduncle*/parent->color=dnode_black;uncle-
>color=dnode_black;grandpa->color=dnode_red;node=grandpa;parent=grandpa->parent;
}else{/*redparent,blackuncle*/if(node==parent->right){rotate_left(parent);parent
=node;assert(grandpa==parent->parent);/*rotationbetweenparentandchild*preservesg
randpa*/}parent->color=dnode_black;grandpa->color=dnode_red;rotate_right(grandpa
);break;}}else{/*symmetriccases:parent==parent->parent->right*/uncle=grandpa->le
ft;if(uncle->color==dnode_red){parent->color=dnode_black;uncle->color=dnode_blac
k;grandpa->color=dnode_red;node=grandpa;parent=grandpa->parent;}else{if(node==pa
rent->left){rotate_right(parent);parent=node;assert(grandpa==parent->parent);}pa
rent->color=dnode_black;grandpa->color=dnode_red;rotate_left(grandpa);break;}}}d
ict_root(dict)->color=dnode_black;assert(dict_verify(dict));}/**Deletethegivenno
defromthedictionary.Ifthegivennodedoesnotbelong*tothegivendictionary,undefinedbe
haviorresults.Apointertothe*deletednodeisreturned.*/dnode_t*dict_delete(dict_t*d
ict,dnode_t*delete){dnode_t*nil=dict_nil(dict),*child,*delparent=delete->parent;
/*basicdeletion*/assert(!dict_isempty(dict));assert(dict_contains(dict,delete));
/**Ifthenodebeingdeletedhastwochildren,thenwereplaceitwith*its*successor(i.e.the
leftmostnodeintherightsubtree.)Bydoing*this,*weavoidthetraditionalalgorithmunder
whichthesuccessor'skey*and*value*only*movetothedeletednodeandthesuccessorissplic
ed*out*fromthetree.Wecannotusethisapproachbecausetheusermayhold*pointerstothesuc
cessor,ornodesmaybeinextricablytiedtosome*otherstructuresbywayofembedding,etc.So
wemustspliceoutthe*nodewearegiven,notsomeothernode,andmustnotmovecontents*from*o
nenodetoanotherbehindtheuser'sback.*/if(delete->left!=nil&&delete->right!=nil){d
node_t*next=dict_next(dict,delete);assert(next);dnode_t*nextparent=next->parent;
dnode_color_tnextcolor=next->color;assert(next!=nil);assert(next->parent!=nil);a
ssert(next->left==nil);/**First,spliceoutthesuccessorfromthetreecompletely,by*mo
vingupitsrightchildintoitsplace.*/child=next->right;child->parent=nextparent;if(
nextparent->left==next){nextparent->left=child;}else{assert(nextparent->right==n
ext);nextparent->right=child;}/**Nowthatthesuccessorhasbeenextricatedfromthetree
,*installit*inplaceofthenodethatwewantdeleted.*/next->parent=delparent;next->lef
t=delete->left;next->right=delete->right;next->left->parent=next;next->right->pa
rent=next;next->color=delete->color;delete->color=nextcolor;if(delparent->left==
delete){delparent->left=next;}else{assert(delparent->right==delete);delparent->r
ight=next;}}else{assert(delete!=nil);assert(delete->left==nil||delete->right==ni
l);child=(delete->left!=nil)?delete->left:delete->right;child->parent=delparent=
delete->parent;if(delete==delparent->left){delparent->left=child;}else{assert(de
lete==delparent->right);delparent->right=child;}}delete->parent=NULL;delete->rig
ht=NULL;delete->left=NULL;dict->nodecount--;assert(verify_bintree(dict));/*red-b
lackadjustments*/if(delete->color==dnode_black){dnode_t*parent,*sister;dict_root
(dict)->color=dnode_red;while(child->color==dnode_black){parent=child->parent;if
(child==parent->left){sister=parent->right;assert(sister!=nil);if(sister->color=
=dnode_red){sister->color=dnode_black;parent->color=dnode_red;rotate_left(parent
);sister=parent->right;assert(sister!=nil);}if(sister->left->color==dnode_black&
&sister->right->color==dnode_black){sister->color=dnode_red;child=parent;}else{i
f(sister->right->color==dnode_black){assert(sister->left->color==dnode_red);sist
er->left->color=dnode_black;sister->color=dnode_red;rotate_right(sister);sister=
parent->right;assert(sister!=nil);}sister->color=parent->color;sister->right->co
lor=dnode_black;parent->color=dnode_black;rotate_left(parent);break;}}else{/*sym
metriccase:child==child->parent->right*/assert(child==parent->right);sister=pare
nt->left;assert(sister!=nil);if(sister->color==dnode_red){sister->color=dnode_bl
ack;parent->color=dnode_red;rotate_right(parent);sister=parent->left;assert(sist
er!=nil);}if(sister->right->color==dnode_black&&sister->left->color==dnode_black
){sister->color=dnode_red;child=parent;}else{if(sister->left->color==dnode_black
){assert(sister->right->color==dnode_red);sister->right->color=dnode_black;siste
r->color=dnode_red;rotate_left(sister);sister=parent->left;assert(sister!=nil);}
sister->color=parent->color;sister->left->color=dnode_black;parent->color=dnode_
black;rotate_right(parent);break;}}}child->color=dnode_black;dict_root(dict)->co
lor=dnode_black;}assert(dict_verify(dict));returndelete;}/**Allocateanodeusingth
edictionary'sallocatorroutine,giveit*thedataitem.*/intdict_alloc_insert(dict_t*d
ict,constvoid*key,void*data){dnode_t*node=dict->allocnode(dict->context);if(node
){dnode_init(node,data);dict_insert(dict,node,key);return1;}return0;}voiddict_de
lete_free(dict_t*dict,dnode_t*node){dict_delete(dict,node);dict->freenode(node,d
ict->context);}/**Returnthenodewiththelowest(leftmost)key.Ifthedictionaryisempty
*(thatis,dict_isempty(dict)returns1)anullpointerisreturned.*/dnode_t*dict_first(
dict_t*dict){dnode_t*nil=dict_nil(dict),*root=dict_root(dict),*left;if(root!=nil
)while((left=root->left)!=nil)root=left;return(root==nil)?NULL:root;}/**Returnth
enodewiththehighest(rightmost)key.Ifthedictionaryisempty*(thatis,dict_isempty(di
ct)returns1)anullpointerisreturned.*/dnode_t*dict_last(dict_t*dict){dnode_t*nil=
dict_nil(dict),*root=dict_root(dict),*right;if(root!=nil)while((right=root->righ
t)!=nil)root=right;return(root==nil)?NULL:root;}/**Returnthegivennode'ssuccessor
node---thenodewhichhasthe*nextkeyinthethelefttorightordering.Ifthenodehas*nosucc
essor,anullpointerisreturnedratherthanapointerto*thenilnode.*/dnode_t*dict_next(
dict_t*dict,dnode_t*curr){dnode_t*nil=dict_nil(dict),*parent,*left;if(curr->righ
t!=nil){curr=curr->right;while((left=curr->left)!=nil)curr=left;returncurr;}pare
nt=curr->parent;while(parent!=nil&&curr==parent->right){curr=parent;parent=curr-
>parent;}return(parent==nil)?NULL:parent;}/**Returnthegivennode'spredecessor,int
hekeyorder.*Thenilsentinelnodeisreturnedifthereisnopredecessor.*/dnode_t*dict_pr
ev(dict_t*dict,dnode_t*curr){dnode_t*nil=dict_nil(dict),*parent,*right;if(curr->
left!=nil){curr=curr->left;while((right=curr->right)!=nil)curr=right;returncurr;
}parent=curr->parent;while(parent!=nil&&curr==parent->left){curr=parent;parent=c
urr->parent;}return(parent==nil)?NULL:parent;}voiddict_allow_dupes(dict_t*dict){
dict->dupes=1;}#undefdict_count#undefdict_isempty#undefdict_isfull#undefdnode_ge
t#undefdnode_put#undefdnode_getkeydictcount_tdict_count(dict_t*dict){returndict-
>nodecount;}intdict_isempty(dict_t*dict){returndict->nodecount==0;}intdict_isful
l(dict_t*dict){returndict->nodecount==dict->maxcount;}intdict_contains(dict_t*di
ct,dnode_t*node){returnverify_dict_has_node(dict_nil(dict),dict_root(dict),node)
;}staticdnode_t*dnode_alloc(void*context){returnXCALLOC(MTYPE_ISIS_DICT_NODE,siz
eof(dnode_t));}staticvoiddnode_free(dnode_t*node,void*context){XFREE(MTYPE_ISIS_
DICT_NODE,node);}dnode_t*dnode_create(void*data){dnode_t*new=XCALLOC(MTYPE_ISIS_
DICT_NODE,sizeof(dnode_t));if(new){new->data=data;new->parent=NULL;new->left=NUL
L;new->right=NULL;}returnnew;}dnode_t*dnode_init(dnode_t*dnode,void*data){dnode-
>data=data;dnode->parent=NULL;dnode->left=NULL;dnode->right=NULL;returndnode;}vo
iddnode_destroy(dnode_t*dnode){assert(!dnode_is_in_a_dict(dnode));XFREE(MTYPE_IS
IS_DICT_NODE,dnode);}void*dnode_get(dnode_t*dnode){returndnode->data;}constvoid*
dnode_getkey(dnode_t*dnode){returndnode->key;}voiddnode_put(dnode_t*dnode,void*d
ata){dnode->data=data;}intdnode_is_in_a_dict(dnode_t*dnode){return(dnode->parent
&&dnode->left&&dnode->right);}voiddict_process(dict_t*dict,void*context,dnode_pr
ocess_tfunction){dnode_t*node=dict_first(dict),*next;while(node!=NULL){/*checkfo
rcallbackfunctiondeleting*//*thenextnodefromunderus*/assert(dict_contains(dict,n
ode));next=dict_next(dict,node);function(dict,node,context);node=next;}}staticvo
idload_begin_internal(dict_load_t*load,dict_t*dict){load->dictptr=dict;load->nil
node.left=&load->nilnode;load->nilnode.right=&load->nilnode;}voiddict_load_begin
(dict_load_t*load,dict_t*dict){assert(dict_isempty(dict));load_begin_internal(lo
ad,dict);}voiddict_load_next(dict_load_t*load,dnode_t*newnode,constvoid*key){dic
t_t*dict=load->dictptr;dnode_t*nil=&load->nilnode;assert(!dnode_is_in_a_dict(new
node));assert(dict->nodecount<dict->maxcount);#ifndefNDEBUGif(dict->nodecount>0)
{if(dict->dupes)assert(dict->compare(nil->left->key,key)<=0);elseassert(dict->co
mpare(nil->left->key,key)<0);}#endifnewnode->key=key;nil->right->left=newnode;ni
l->right=newnode;newnode->left=nil;dict->nodecount++;}voiddict_load_end(dict_loa
d_t*load){dict_t*dict=load->dictptr;dnode_t*tree[DICT_DEPTH_MAX]={0};dnode_t*cur
r,*dictnil=dict_nil(dict),*loadnil=&load->nilnode,*next;dnode_t*complete=0;dictc
ount_tfullcount=DICTCOUNT_T_MAX,nodecount=dict->nodecount;dictcount_tbotrowcount
;unsignedbaselevel=0,level=0,i;assert(dnode_red==0&&dnode_black==1);while(fullco
unt>=nodecount&&fullcount)fullcount>>=1;botrowcount=nodecount-fullcount;for(curr
=loadnil->left;curr!=loadnil;curr=next){next=curr->left;if(complete==NULL&&botro
wcount--==0){assert(baselevel==0);assert(level==0);baselevel=level=1;complete=tr
ee[0];if(complete!=0){tree[0]=0;complete->right=dictnil;while(tree[level]!=0){tr
ee[level]->right=complete;complete->parent=tree[level];complete=tree[level];tree
[level++]=0;}}}if(complete==NULL){curr->left=dictnil;curr->right=dictnil;curr->c
olor=level%2;complete=curr;assert(level==baselevel);while(tree[level]!=0){tree[l
evel]->right=complete;complete->parent=tree[level];complete=tree[level];tree[lev
el++]=0;}}else{curr->left=complete;curr->color=(level+1)%2;complete->parent=curr
;tree[level]=curr;complete=0;level=baselevel;}}if(complete==NULL)complete=dictni
l;for(i=0;i<DICT_DEPTH_MAX;i++){if(tree[i]!=0){tree[i]->right=complete;complete-
>parent=tree[i];complete=tree[i];}}dictnil->color=dnode_black;dictnil->right=dic
tnil;complete->parent=dictnil;complete->color=dnode_black;dict_root(dict)=comple
te;assert(dict_verify(dict));}voiddict_merge(dict_t*dest,dict_t*source){dict_loa
d_tload;dnode_t*leftnode=dict_first(dest),*rightnode=dict_first(source);assert(d
ict_similar(dest,source));if(source==dest)return;dest->nodecount=0;load_begin_in
ternal(&load,dest);for(;;){if(leftnode!=NULL&&rightnode!=NULL){if(dest->compare(
leftnode->key,rightnode->key)<0)gotocopyleft;elsegotocopyright;}elseif(leftnode!
=NULL){gotocopyleft;}elseif(rightnode!=NULL){gotocopyright;}else{assert(leftnode
==NULL&&rightnode==NULL);break;}copyleft:{dnode_t*next=dict_next(dest,leftnode);
#ifndefNDEBUGleftnode->left=NULL;/*suppressassertionindict_load_next*/#endifdict
_load_next(&load,leftnode,leftnode->key);leftnode=next;continue;}copyright:{dnod
e_t*next=dict_next(source,rightnode);#ifndefNDEBUGrightnode->left=NULL;#endifdic
t_load_next(&load,rightnode,rightnode->key);rightnode=next;continue;}}dict_clear
(source);dict_load_end(&load);}#ifdefKAZLIB_TEST_MAIN#include<stdio.h>#include<s
tring.h>#include<ctype.h>#include<stdarg.h>typedefcharinput_t[256];staticinttoke
nize(char*string,...){char**tokptr;va_listarglist;inttokcount=0;va_start(arglist
,string);tokptr=va_arg(arglist,char**);while(tokptr){while(*string&&isspace((uns
ignedchar)*string))string++;if(!*string)break;*tokptr=string;while(*string&&!iss
pace((unsignedchar)*string))string++;tokptr=va_arg(arglist,char**);tokcount++;if
(!*string)break;*string++=0;}va_end(arglist);returntokcount;}staticintcomparef(c
onstvoid*key1,constvoid*key2){returnstrcmp(key1,key2);}staticchar*dupstring(char
*str){intsz=strlen(str)+1;char*new=XCALLOC(MTYPE_ISIS_TMP,sz);if(new)memcpy(new,
str,sz);returnnew;}staticdnode_t*new_node(void*c){staticdnode_tfew[5];staticintc
ount;if(count<5)returnfew+count++;returnNULL;}staticvoiddel_node(dnode_t*n,void*
c){}staticintprompt=0;staticvoidconstruct(dict_t*d){input_tin;intdone=0;dict_loa
d_tdl;dnode_t*dn;char*tok1,*tok2,*val;constchar*key;char*help="pturnprompton\n""
qfinishconstruction\n""a<key><val>addnewentry\n";if(!dict_isempty(d))puts("warni
ng:dictionarynotempty!");dict_load_begin(&dl,d);while(!done){if(prompt)putchar('
>');fflush(stdout);if(!fgets(in,sizeof(input_t),stdin))break;switch(in[0]){case'
?':puts(help);break;case'p':prompt=1;break;case'q':done=1;break;case'a':if(token
ize(in+1,&tok1,&tok2,(char**)0)!=2){puts("what?");break;}key=dupstring(tok1);val
=dupstring(tok2);dn=dnode_create(val);if(!key||!val||!dn){puts("outofmemory");fr
ee((void*)key);free(val);if(dn)dnode_destroy(dn);}dict_load_next(&dl,dn,key);bre
ak;default:putchar('?');putchar('\n');break;}}dict_load_end(&dl);}intmain(void){
input_tin;dict_tdarray[10];dict_t*d=&darray[0];dnode_t*dn;inti;char*tok1,*tok2,*
val;constchar*key;char*help="a<key><val>addvaluetodictionary\n""d<key>deletevalu
efromdictionary\n""l<key>lookupvalueindictionary\n""(<key>lookuplowerbound\n"")<
key>lookupupperbound\n""#<num>switchtoalternatedictionary(0-9)\n""j<num><num>mer
getwodictionaries\n""ffreethewholedictionary\n""kallowduplicatekeys\n""cshownumb
erofentries\n""tdumpwholedictionaryinsortorder\n""mmakedictionaryoutofsorteditem
s\n""pturnprompton\n""sswitchtonon-functioningallocator\n""qquit";for(i=0;i<10;i
++)dict_init(&darray[i],DICTCOUNT_T_MAX,comparef);for(;;){if(prompt)putchar('>')
;fflush(stdout);if(!fgets(in,sizeof(input_t),stdin))break;switch(in[0]){case'?':
puts(help);break;case'a':if(tokenize(in+1,&tok1,&tok2,(char**)0)!=2){puts("what?
");break;}key=dupstring(tok1);val=dupstring(tok2);if(!key||!val){puts("outofmemo
ry");free((void*)key);free(val);}if(!dict_alloc_insert(d,key,val)){puts("dict_al
loc_insertfailed");free((void*)key);free(val);break;}break;case'd':if(tokenize(i
n+1,&tok1,(char**)0)!=1){puts("what?");break;}dn=dict_lookup(d,tok1);if(!dn){put
s("dict_lookupfailed");break;}val=dnode_get(dn);key=dnode_getkey(dn);dict_delete
_free(d,dn);free(val);free((void*)key);break;case'f':dict_free(d);break;case'l':
case'(':case')':if(tokenize(in+1,&tok1,(char**)0)!=1){puts("what?");break;}dn=0;
switch(in[0]){case'l':dn=dict_lookup(d,tok1);break;case'(':dn=dict_lower_bound(d
,tok1);break;case')':dn=dict_upper_bound(d,tok1);break;}if(!dn){puts("lookupfail
ed");break;}val=dnode_get(dn);puts(val);break;case'm':construct(d);break;case'k'
:dict_allow_dupes(d);break;case'c':printf("%lu\n",(unsignedlong)dict_count(d));b
reak;case't':for(dn=dict_first(d);dn;dn=dict_next(d,dn)){printf("%s\t%s\n",(char
*)dnode_getkey(dn),(char*)dnode_get(dn));}break;case'q':exit(0);break;case'\0':b
reak;case'p':prompt=1;break;case's':dict_set_allocator(d,new_node,del_node,NULL)
;break;case'#':if(tokenize(in+1,&tok1,(char**)0)!=1){puts("what?");break;}else{i
ntdictnum=atoi(tok1);if(dictnum<0||dictnum>9){puts("invalidnumber");break;}d=&da
rray[dictnum];}break;case'j':if(tokenize(in+1,&tok1,&tok2,(char**)0)!=2){puts("w
hat?");break;}else{intdict1=atoi(tok1),dict2=atoi(tok2);if(dict1<0||dict1>9||dic
t2<0||dict2>9){puts("invalidnumber");break;}dict_merge(&darray[dict1],&darray[di
ct2]);}break;default:putchar('?');putchar('\n');break;}}return0;}#endif