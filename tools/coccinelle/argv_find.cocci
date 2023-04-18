@@
identifier idx;
identifier argv;
identifier argc;
expression e1;
expression e2;
identifier I;
@@

(
- argv_find(argv, argc, e1, &idx);
  if (
-   idx
+   argv_find(argv, argc, e1, &idx)
  )
  {
    e2;
  }
|
- argv_find(argv, argc, e1, &idx);
... when != I = idx;
    when strict
)
