@@
expression e1, e2;
@@

(
- bgp_flag_check(e1, e2)
+ CHECK_FLAG(e1->flags, e2)
|
- bgp_flag_set(e1, e2)
+ SET_FLAG(e1->flags, e2)
|
- bgp_flag_unset(e1, e2)
+ UNSET_FLAG(e1->flags, e2)
)
