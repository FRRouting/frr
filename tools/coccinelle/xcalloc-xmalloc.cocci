// No need checking against NULL for XMALLOC/XCALLOC.
// If that happens, we have more problems with memory.

@@
type T;
T *ptr;
@@

ptr =
(
XCALLOC(...)
|
XMALLOC(...)
)
...
- if (ptr == NULL)
- return ...;
