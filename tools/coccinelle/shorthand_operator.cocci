@@
identifier data;
constant x;
@@

(
- data = data + x
+ data += x
|
- data = data - x
+ data -= x
)
