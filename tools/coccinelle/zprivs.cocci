@@
identifier change;
identifier end;
expression E, f, g;
iterator name frr_with_privs;
@@

- if (E.change(ZPRIVS_RAISE))
-   f;
+ frr_with_privs(&E) {
  <+...
-   goto end;
+   break;
  ...+>
- end:
- if (E.change(ZPRIVS_LOWER))
-   g;
+ }

@@
identifier change, errno, safe_strerror, exit;
expression E, f1, f2, f3, ret, fn;
iterator name frr_with_privs;
@@

  if (E.change(ZPRIVS_RAISE))
    f1;
  ...
  if (...) {
-   int save_errno = errno;
    ...
-   if (E.change(ZPRIVS_LOWER))
-     f2;
    ...
-   safe_strerror(save_errno)
+   safe_strerror(errno)
    ...
    \( return ret; \| exit(ret); \)
  }
  ...
  if (E.change(ZPRIVS_LOWER))
    f3;

@@
identifier change;
expression E, f1, f2, f3, ret;
iterator name frr_with_privs;
@@

  if (E.change(ZPRIVS_RAISE))
    f1;
  ...
  if (...) {
    ...
-   if (E.change(ZPRIVS_LOWER))
-     f2;
    ...
    return ret;
  }
  ...
  if (E.change(ZPRIVS_LOWER))
    f3;

@@
identifier change;
expression E, f, g;
iterator name frr_with_privs;
@@

- if (E.change(ZPRIVS_RAISE))
-   f;
+ frr_with_privs(&E) {
  ...
- if (E.change(ZPRIVS_LOWER))
-   g;
+ }
