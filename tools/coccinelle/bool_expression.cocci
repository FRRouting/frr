@@
bool t;
@@

(
- t == true
+ t
|
- true == t
+ t
|
- t != true
+ !t
|
- true != t
+ !t
|
- t == false
+ !t
|
- false == t
+ !t
|
- t != false
+ t
|
- false != t
+ t
)
