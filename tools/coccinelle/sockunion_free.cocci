@@
expression E;
@@

(
sockunion_free(E);
- E = NULL;
|
- if (E)
- {
  sockunion_free(E);
- E = NULL;
- }
|
- if (E)
    sockunion_free(E);
)
