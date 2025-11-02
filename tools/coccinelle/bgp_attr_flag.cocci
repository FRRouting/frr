@@
expression e1, e2;
@@

(
- CHECK_FLAG(e1->flag, ATTR_FLAG_BIT(e2))
+ bgp_attr_exists(e1, e2)
|
- SET_FLAG(e1->flag, ATTR_FLAG_BIT(e2))
+ bgp_attr_set(e1, e2)
|
- UNSET_FLAG(e1->flag, ATTR_FLAG_BIT(e2))
+ bgp_attr_unset(e1, e2)
)
