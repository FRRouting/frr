/*$OpenBSD:subr_tree.c,v1.92017/06/0803:30:52dlgExp$*//**Copyright2002NielsProvo
s<provos@citi.umich.edu>*Allrightsreserved.**Redistributionanduseinsourceandbina
ryforms,withorwithout*modification,arepermittedprovidedthatthefollowingcondition
s*aremet:*1.Redistributionsofsourcecodemustretaintheabovecopyright*notice,thisli
stofconditionsandthefollowingdisclaimer.*2.Redistributionsinbinaryformmustreprod
ucetheabovecopyright*notice,thislistofconditionsandthefollowingdisclaimerinthe*d
ocumentationand/orothermaterialsprovidedwiththedistribution.**THISSOFTWAREISPROV
IDEDBYTHEAUTHOR``ASIS''ANDANYEXPRESSOR*IMPLIEDWARRANTIES,INCLUDING,BUTNOTLIMITED
TO,THEIMPLIEDWARRANTIES*OFMERCHANTABILITYANDFITNESSFORAPARTICULARPURPOSEAREDISCL
AIMED.*INNOEVENTSHALLTHEAUTHORBELIABLEFORANYDIRECT,INDIRECT,*INCIDENTAL,SPECIAL,
EXEMPLARY,ORCONSEQUENTIALDAMAGES(INCLUDING,BUT*NOTLIMITEDTO,PROCUREMENTOFSUBSTIT
UTEGOODSORSERVICES;LOSSOFUSE,*DATA,ORPROFITS;ORBUSINESSINTERRUPTION)HOWEVERCAUSE
DANDONANY*THEORYOFLIABILITY,WHETHERINCONTRACT,STRICTLIABILITY,ORTORT*(INCLUDINGN
EGLIGENCEOROTHERWISE)ARISINGINANYWAYOUTOFTHEUSEOF*THISSOFTWARE,EVENIFADVISEDOFTH
EPOSSIBILITYOFSUCHDAMAGE.*//**Copyright(c)2016DavidGwynne<dlg@openbsd.org>**Perm
issiontouse,copy,modify,anddistributethissoftwareforany*purposewithorwithoutfeei
sherebygranted,providedthattheabove*copyrightnoticeandthispermissionnoticeappear
inallcopies.**THESOFTWAREISPROVIDED"ASIS"ANDTHEAUTHORDISCLAIMSALLWARRANTIES*WITH
REGARDTOTHISSOFTWAREINCLUDINGALLIMPLIEDWARRANTIESOF*MERCHANTABILITYANDFITNESS.IN
NOEVENTSHALLTHEAUTHORBELIABLEFOR*ANYSPECIAL,DIRECT,INDIRECT,ORCONSEQUENTIALDAMAG
ESORANYDAMAGES*WHATSOEVERRESULTINGFROMLOSSOFUSE,DATAORPROFITS,WHETHERINAN*ACTION
OFCONTRACT,NEGLIGENCEOROTHERTORTIOUSACTION,ARISINGOUTOF*ORINCONNECTIONWITHTHEUSE
ORPERFORMANCEOFTHISSOFTWARE.*/#include<stdlib.h>#include<lib/openbsd-tree.h>stat
icinlinestructrb_entry*rb_n2e(conststructrb_type*t,void*node){unsignedlongaddr=(
unsignedlong)node;return((structrb_entry*)(addr+t->t_offset));}staticinlinevoid*
rb_e2n(conststructrb_type*t,structrb_entry*rbe){unsignedlongaddr=(unsignedlong)r
be;return((void*)(addr-t->t_offset));}#defineRBE_LEFT(_rbe)(_rbe)->rbt_left#defi
neRBE_RIGHT(_rbe)(_rbe)->rbt_right#defineRBE_PARENT(_rbe)(_rbe)->rbt_parent#defi
neRBE_COLOR(_rbe)(_rbe)->rbt_color#defineRBH_ROOT(_rbt)(_rbt)->rbt_rootstaticinl
inevoidrbe_set(structrb_entry*rbe,structrb_entry*parent){RBE_PARENT(rbe)=parent;
RBE_LEFT(rbe)=RBE_RIGHT(rbe)=NULL;RBE_COLOR(rbe)=RB_RED;}staticinlinevoidrbe_set
_blackred(structrb_entry*black,structrb_entry*red){RBE_COLOR(black)=RB_BLACK;RBE
_COLOR(red)=RB_RED;}staticinlinevoidrbe_augment(conststructrb_type*t,structrb_en
try*rbe){(*t->t_augment)(rb_e2n(t,rbe));}staticinlinevoidrbe_if_augment(conststr
uctrb_type*t,structrb_entry*rbe){if(t->t_augment!=NULL)rbe_augment(t,rbe);}stati
cinlinevoidrbe_rotate_left(conststructrb_type*t,structrbt_tree*rbt,structrb_entr
y*rbe){structrb_entry*parent;structrb_entry*tmp;tmp=RBE_RIGHT(rbe);RBE_RIGHT(rbe
)=RBE_LEFT(tmp);if(RBE_RIGHT(rbe)!=NULL)RBE_PARENT(RBE_LEFT(tmp))=rbe;parent=RBE
_PARENT(rbe);RBE_PARENT(tmp)=parent;if(parent!=NULL){if(rbe==RBE_LEFT(parent))RB
E_LEFT(parent)=tmp;elseRBE_RIGHT(parent)=tmp;}elseRBH_ROOT(rbt)=tmp;RBE_LEFT(tmp
)=rbe;RBE_PARENT(rbe)=tmp;if(t->t_augment!=NULL){rbe_augment(t,rbe);rbe_augment(
t,tmp);parent=RBE_PARENT(tmp);if(parent!=NULL)rbe_augment(t,parent);}}staticinli
nevoidrbe_rotate_right(conststructrb_type*t,structrbt_tree*rbt,structrb_entry*rb
e){structrb_entry*parent;structrb_entry*tmp;tmp=RBE_LEFT(rbe);RBE_LEFT(rbe)=RBE_
RIGHT(tmp);if(RBE_LEFT(rbe)!=NULL)RBE_PARENT(RBE_RIGHT(tmp))=rbe;parent=RBE_PARE
NT(rbe);RBE_PARENT(tmp)=parent;if(parent!=NULL){if(rbe==RBE_LEFT(parent))RBE_LEF
T(parent)=tmp;elseRBE_RIGHT(parent)=tmp;}elseRBH_ROOT(rbt)=tmp;RBE_RIGHT(tmp)=rb
e;RBE_PARENT(rbe)=tmp;if(t->t_augment!=NULL){rbe_augment(t,rbe);rbe_augment(t,tm
p);parent=RBE_PARENT(tmp);if(parent!=NULL)rbe_augment(t,parent);}}staticinlinevo
idrbe_insert_color(conststructrb_type*t,structrbt_tree*rbt,structrb_entry*rbe){s
tructrb_entry*parent,*gparent,*tmp;while((parent=RBE_PARENT(rbe))!=NULL&&RBE_COL
OR(parent)==RB_RED){gparent=RBE_PARENT(parent);if(parent==RBE_LEFT(gparent)){tmp
=RBE_RIGHT(gparent);if(tmp!=NULL&&RBE_COLOR(tmp)==RB_RED){RBE_COLOR(tmp)=RB_BLAC
K;rbe_set_blackred(parent,gparent);rbe=gparent;continue;}if(RBE_RIGHT(parent)==r
be){rbe_rotate_left(t,rbt,parent);tmp=parent;parent=rbe;rbe=tmp;}rbe_set_blackre
d(parent,gparent);rbe_rotate_right(t,rbt,gparent);}else{tmp=RBE_LEFT(gparent);if
(tmp!=NULL&&RBE_COLOR(tmp)==RB_RED){RBE_COLOR(tmp)=RB_BLACK;rbe_set_blackred(par
ent,gparent);rbe=gparent;continue;}if(RBE_LEFT(parent)==rbe){rbe_rotate_right(t,
rbt,parent);tmp=parent;parent=rbe;rbe=tmp;}rbe_set_blackred(parent,gparent);rbe_
rotate_left(t,rbt,gparent);}}RBE_COLOR(RBH_ROOT(rbt))=RB_BLACK;}staticinlinevoid
rbe_remove_color(conststructrb_type*t,structrbt_tree*rbt,structrb_entry*parent,s
tructrb_entry*rbe){structrb_entry*tmp;while((rbe==NULL||RBE_COLOR(rbe)==RB_BLACK
)&&rbe!=RBH_ROOT(rbt)&&parent){if(RBE_LEFT(parent)==rbe){tmp=RBE_RIGHT(parent);i
f(RBE_COLOR(tmp)==RB_RED){rbe_set_blackred(tmp,parent);rbe_rotate_left(t,rbt,par
ent);tmp=RBE_RIGHT(parent);}if((RBE_LEFT(tmp)==NULL||RBE_COLOR(RBE_LEFT(tmp))==R
B_BLACK)&&(RBE_RIGHT(tmp)==NULL||RBE_COLOR(RBE_RIGHT(tmp))==RB_BLACK)){RBE_COLOR
(tmp)=RB_RED;rbe=parent;parent=RBE_PARENT(rbe);}else{if(RBE_RIGHT(tmp)==NULL||RB
E_COLOR(RBE_RIGHT(tmp))==RB_BLACK){structrb_entry*oleft;oleft=RBE_LEFT(tmp);if(o
left!=NULL)RBE_COLOR(oleft)=RB_BLACK;RBE_COLOR(tmp)=RB_RED;rbe_rotate_right(t,rb
t,tmp);tmp=RBE_RIGHT(parent);}RBE_COLOR(tmp)=RBE_COLOR(parent);RBE_COLOR(parent)
=RB_BLACK;if(RBE_RIGHT(tmp))RBE_COLOR(RBE_RIGHT(tmp))=RB_BLACK;rbe_rotate_left(t
,rbt,parent);rbe=RBH_ROOT(rbt);break;}}else{tmp=RBE_LEFT(parent);if(RBE_COLOR(tm
p)==RB_RED){rbe_set_blackred(tmp,parent);rbe_rotate_right(t,rbt,parent);tmp=RBE_
LEFT(parent);}if((RBE_LEFT(tmp)==NULL||RBE_COLOR(RBE_LEFT(tmp))==RB_BLACK)&&(RBE
_RIGHT(tmp)==NULL||RBE_COLOR(RBE_RIGHT(tmp))==RB_BLACK)){RBE_COLOR(tmp)=RB_RED;r
be=parent;parent=RBE_PARENT(rbe);}else{if(RBE_LEFT(tmp)==NULL||RBE_COLOR(RBE_LEF
T(tmp))==RB_BLACK){structrb_entry*oright;oright=RBE_RIGHT(tmp);if(oright!=NULL)R
BE_COLOR(oright)=RB_BLACK;RBE_COLOR(tmp)=RB_RED;rbe_rotate_left(t,rbt,tmp);tmp=R
BE_LEFT(parent);}RBE_COLOR(tmp)=RBE_COLOR(parent);RBE_COLOR(parent)=RB_BLACK;if(
RBE_LEFT(tmp)!=NULL)RBE_COLOR(RBE_LEFT(tmp))=RB_BLACK;rbe_rotate_right(t,rbt,par
ent);rbe=RBH_ROOT(rbt);break;}}}if(rbe!=NULL)RBE_COLOR(rbe)=RB_BLACK;}staticinli
nestructrb_entry*rbe_remove(conststructrb_type*t,structrbt_tree*rbt,structrb_ent
ry*rbe){structrb_entry*child,*parent,*old=rbe;unsignedintcolor;if(RBE_LEFT(rbe)=
=NULL)child=RBE_RIGHT(rbe);elseif(RBE_RIGHT(rbe)==NULL)child=RBE_LEFT(rbe);else{
structrb_entry*tmp;rbe=RBE_RIGHT(rbe);while((tmp=RBE_LEFT(rbe))!=NULL)rbe=tmp;ch
ild=RBE_RIGHT(rbe);parent=RBE_PARENT(rbe);color=RBE_COLOR(rbe);if(child!=NULL)RB
E_PARENT(child)=parent;if(parent!=NULL){if(RBE_LEFT(parent)==rbe)RBE_LEFT(parent
)=child;elseRBE_RIGHT(parent)=child;rbe_if_augment(t,parent);}elseRBH_ROOT(rbt)=
child;if(RBE_PARENT(rbe)==old)parent=rbe;*rbe=*old;tmp=RBE_PARENT(old);if(tmp!=N
ULL){if(RBE_LEFT(tmp)==old)RBE_LEFT(tmp)=rbe;elseRBE_RIGHT(tmp)=rbe;rbe_if_augme
nt(t,parent);}elseRBH_ROOT(rbt)=rbe;RBE_PARENT(RBE_LEFT(old))=rbe;if(RBE_RIGHT(o
ld))RBE_PARENT(RBE_RIGHT(old))=rbe;if(t->t_augment!=NULL&&parent!=NULL){tmp=pare
nt;do{rbe_augment(t,tmp);tmp=RBE_PARENT(tmp);}while(tmp!=NULL);}gotocolor;}paren
t=RBE_PARENT(rbe);color=RBE_COLOR(rbe);if(child!=NULL)RBE_PARENT(child)=parent;i
f(parent!=NULL){if(RBE_LEFT(parent)==rbe)RBE_LEFT(parent)=child;elseRBE_RIGHT(pa
rent)=child;rbe_if_augment(t,parent);}elseRBH_ROOT(rbt)=child;color:if(color==RB
_BLACK)rbe_remove_color(t,rbt,parent,child);return(old);}void*_rb_remove(constst
ructrb_type*t,structrbt_tree*rbt,void*elm){structrb_entry*rbe=rb_n2e(t,elm);stru
ctrb_entry*old;old=rbe_remove(t,rbt,rbe);return(old==NULL?NULL:rb_e2n(t,old));}v
oid*_rb_insert(conststructrb_type*t,structrbt_tree*rbt,void*elm){structrb_entry*
rbe=rb_n2e(t,elm);structrb_entry*tmp;structrb_entry*parent=NULL;void*node;intcom
p=0;tmp=RBH_ROOT(rbt);while(tmp!=NULL){parent=tmp;node=rb_e2n(t,tmp);comp=(*t->t
_compare)(elm,node);if(comp<0)tmp=RBE_LEFT(tmp);elseif(comp>0)tmp=RBE_RIGHT(tmp)
;elsereturn(node);}rbe_set(rbe,parent);if(parent!=NULL){if(comp<0)RBE_LEFT(paren
t)=rbe;elseRBE_RIGHT(parent)=rbe;rbe_if_augment(t,parent);}elseRBH_ROOT(rbt)=rbe
;rbe_insert_color(t,rbt,rbe);return(NULL);}/*Findsthenodewiththesamekeyaselm*/vo
id*_rb_find(conststructrb_type*t,structrbt_tree*rbt,constvoid*key){structrb_entr
y*tmp=RBH_ROOT(rbt);void*node;intcomp;while(tmp!=NULL){node=rb_e2n(t,tmp);comp=(
*t->t_compare)(key,node);if(comp<0)tmp=RBE_LEFT(tmp);elseif(comp>0)tmp=RBE_RIGHT
(tmp);elsereturn(node);}return(NULL);}/*Findsthefirstnodegreaterthanorequaltothe
searchkey*/void*_rb_nfind(conststructrb_type*t,structrbt_tree*rbt,constvoid*key)
{structrb_entry*tmp=RBH_ROOT(rbt);void*node;void*res=NULL;intcomp;while(tmp!=NUL
L){node=rb_e2n(t,tmp);comp=(*t->t_compare)(key,node);if(comp<0){res=node;tmp=RBE
_LEFT(tmp);}elseif(comp>0)tmp=RBE_RIGHT(tmp);elsereturn(node);}return(res);}void
*_rb_next(conststructrb_type*t,void*elm){structrb_entry*rbe=rb_n2e(t,elm);if(RBE
_RIGHT(rbe)!=NULL){rbe=RBE_RIGHT(rbe);while(RBE_LEFT(rbe)!=NULL)rbe=RBE_LEFT(rbe
);}else{if(RBE_PARENT(rbe)&&(rbe==RBE_LEFT(RBE_PARENT(rbe))))rbe=RBE_PARENT(rbe)
;else{while(RBE_PARENT(rbe)&&(rbe==RBE_RIGHT(RBE_PARENT(rbe))))rbe=RBE_PARENT(rb
e);rbe=RBE_PARENT(rbe);}}return(rbe==NULL?NULL:rb_e2n(t,rbe));}void*_rb_prev(con
ststructrb_type*t,void*elm){structrb_entry*rbe=rb_n2e(t,elm);if(RBE_LEFT(rbe)){r
be=RBE_LEFT(rbe);while(RBE_RIGHT(rbe))rbe=RBE_RIGHT(rbe);}else{if(RBE_PARENT(rbe
)&&(rbe==RBE_RIGHT(RBE_PARENT(rbe))))rbe=RBE_PARENT(rbe);else{while(RBE_PARENT(r
be)&&(rbe==RBE_LEFT(RBE_PARENT(rbe))))rbe=RBE_PARENT(rbe);rbe=RBE_PARENT(rbe);}}
return(rbe==NULL?NULL:rb_e2n(t,rbe));}void*_rb_root(conststructrb_type*t,structr
bt_tree*rbt){structrb_entry*rbe=RBH_ROOT(rbt);return(rbe==NULL?rbe:rb_e2n(t,rbe)
);}void*_rb_min(conststructrb_type*t,structrbt_tree*rbt){structrb_entry*rbe=RBH_
ROOT(rbt);structrb_entry*parent=NULL;while(rbe!=NULL){parent=rbe;rbe=RBE_LEFT(rb
e);}return(parent==NULL?NULL:rb_e2n(t,parent));}void*_rb_max(conststructrb_type*
t,structrbt_tree*rbt){structrb_entry*rbe=RBH_ROOT(rbt);structrb_entry*parent=NUL
L;while(rbe!=NULL){parent=rbe;rbe=RBE_RIGHT(rbe);}return(parent==NULL?NULL:rb_e2
n(t,parent));}void*_rb_left(conststructrb_type*t,void*node){structrb_entry*rbe=r
b_n2e(t,node);rbe=RBE_LEFT(rbe);return(rbe==NULL?NULL:rb_e2n(t,rbe));}void*_rb_r
ight(conststructrb_type*t,void*node){structrb_entry*rbe=rb_n2e(t,node);rbe=RBE_R
IGHT(rbe);return(rbe==NULL?NULL:rb_e2n(t,rbe));}void*_rb_parent(conststructrb_ty
pe*t,void*node){structrb_entry*rbe=rb_n2e(t,node);rbe=RBE_PARENT(rbe);return(rbe
==NULL?NULL:rb_e2n(t,rbe));}void_rb_set_left(conststructrb_type*t,void*node,void
*left){structrb_entry*rbe=rb_n2e(t,node);structrb_entry*rbl=(left==NULL)?NULL:rb
_n2e(t,left);RBE_LEFT(rbe)=rbl;}void_rb_set_right(conststructrb_type*t,void*node
,void*right){structrb_entry*rbe=rb_n2e(t,node);structrb_entry*rbr=(right==NULL)?
NULL:rb_n2e(t,right);RBE_RIGHT(rbe)=rbr;}void_rb_set_parent(conststructrb_type*t
,void*node,void*parent){structrb_entry*rbe=rb_n2e(t,node);structrb_entry*rbp=(pa
rent==NULL)?NULL:rb_n2e(t,parent);RBE_PARENT(rbe)=rbp;}void_rb_poison(conststruc
trb_type*t,void*node,unsignedlongpoison){structrb_entry*rbe=rb_n2e(t,node);RBE_P
ARENT(rbe)=RBE_LEFT(rbe)=RBE_RIGHT(rbe)=(structrb_entry*)poison;}int_rb_check(co
nststructrb_type*t,void*node,unsignedlongpoison){structrb_entry*rbe=rb_n2e(t,nod
e);return((unsignedlong)RBE_PARENT(rbe)==poison&&(unsignedlong)RBE_LEFT(rbe)==po
ison&&(unsignedlong)RBE_RIGHT(rbe)==poison);}