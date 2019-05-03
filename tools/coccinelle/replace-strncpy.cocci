@@
type T;
T[] E;
expression buf, srclen;
@@

- strncpy(E, src, srclen)
+ strlcpy(E, src, sizeof(E))
