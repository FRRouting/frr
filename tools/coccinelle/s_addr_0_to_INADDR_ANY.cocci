@@
expression e;
@@

(
- e.s_addr == 0
+ e.s_addr == INADDR_ANY
|
- e.s_addr != 0
+ e.s_addr != INADDR_ANY
|
- e.s_addr = 0
+ e.s_addr = INADDR_ANY
)
