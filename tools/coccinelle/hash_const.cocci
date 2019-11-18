//
// Transition hash key signatures to take their argument as const.
// Does not handle headers or weirdly named hash functions.
//
@noconst disable optional_qualifier@
identifier A;
identifier func =~ ".*key$|.*key_make$|.*hash_make$|.*hash_keymake$|.*hash_key$|.*hash_key.*";
@@

- func (void *A)
+ func (const void *A)
  { ... }

@ depends on noconst disable optional_qualifier @
identifier noconst.A;
identifier noconst.func;
identifier b;
type T;
@@

func( ... ) {
<...
-  T b = A;
+  const T b = A;
...>
  }

@ depends on noconst disable optional_qualifier @
identifier noconst.A;
identifier noconst.func;
identifier b;
type T;
@@

func(...)
  {
<...
-  T b = (T) A;
+  const T b = A;
...>
  }

@ depends on noconst disable optional_qualifier @
identifier noconst.A;
identifier noconst.func;
identifier b;
type T;
@@

func(...)
  {
<...
-  T b;
+  const T b;
...
   b = A;
...>
  }

@ depends on noconst disable optional_qualifier @
identifier noconst.A;
identifier noconst.func;
identifier b;
type T;
@@

func(...)
  {
<...
-  T b;
+  const T b;
...
-  b = (T) A;
+  b = A;
...>
  }
