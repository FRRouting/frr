//

@@
identifier src, dst;
identifier str, len;
type t =~ "struct";

@@

(
- memset(&dst, 0, sizeof(t));
+ memset(&dst, 0, sizeof(dst));
|
- memcpy(&dst, &src, sizeof(t));
+ memcpy(&dst, &src, sizeof(dst));
|
- char str[...];
...
- memset(&str, 0, ...);
+ memset(&str, 0, sizeof(str));
)
