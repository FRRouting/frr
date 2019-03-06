/*
 * VTY_DECLVAR_CONTEXT contains a built-in "if (!var) return;"
 */
@@
identifier var, typ;
statement S;
@@

  {
    ...
  \(
    VTY_DECLVAR_CONTEXT(typ, var);
  \|
    VTY_DECLVAR_CONTEXT_SUB(typ, var);
  \)
    ...
-   if (
-         \(  !var  \|  var == NULL \)
-      )
-      S
    ...
  }
