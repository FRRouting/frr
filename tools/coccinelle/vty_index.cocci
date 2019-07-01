/*
 * prep: strip off casts, they cause things to fail matching later.
 */

@@
identifier casttarget;
symbol vty;
@@

- (struct casttarget *)vty->index
+ vty->index

/*
 * variant 1:  local variable assigned from vty->index
 */

@@
identifier sn, nn;
identifier fn;
@@

  int fn(...)
  {
+ VTY_DECLVAR_CONTEXT (sn, nn);
  ...
  \(
-   struct sn *nn;
    ...
-   nn = vty->index;
  \|
-   struct sn *nn = vty->index;
  \|
-   struct sn *nn = vty->index;
    ...
-   nn = vty->index;
  \)
  ...
  }

@@
identifier sn, nn;
identifier fn;
type Tr;
@@

  Tr *fn(...)
  {
+   struct sn *nn = VTY_GET_CONTEXT(sn);
  ...
  \(
-   struct sn *nn;
    ...
-   nn = vty->index;
+   if (!nn) {
+     return NULL;
+   }
  \|
-   struct sn *nn = vty->index;
+   if (!nn) {
+     return NULL;
+   }
  \|
-   struct sn *nn = vty->index;
    ...
-   nn = vty->index;
+   if (!nn) {
+     return NULL;
+   }
  \)
  ...
  }

/*
 * variant 2:  vty wrapper func with (vty, vty->index, ...) signature
 */

/* find calls of this pattern first; arg will be dropped in rule3 */
@rule1@
identifier fn !~ "generic_(set|match)_";
expression arg;
@@
 
 fn(arg, arg->index, ...)

@ script:python @
fn << rule1.fn;
arg << rule1.arg;
@@
print "R01 removing vty-index argument on %s(%s, ...)" % (fn, arg)

#/* strip arg on the vty wrapper func, add local handling */
@ rule2 @
identifier rule1.fn;
identifier arg;
identifier T;
@@

  static int fn (struct vty *vty,
-                struct T * arg,
                 ...)
  {
+   VTY_DECLVAR_CONTEXT (T, arg);
    ...
  }

/* drop argument on call sites identified earlier */
@ rule3 @
identifier rule1.fn;
expression arg;
@@

  fn(arg,
-    arg->index,
     ...)


/*
 * variant 3:  function calls with "vty->index" argument (but no vty)
 *
 * a bit more complicated since we need to find the type from the header.
 */

/* find call sites first
 * remember function name for later declvar insertion
 */
@ rule11 exists@
identifier fn;
identifier fparent;
type Tr;
@@
 
  Tr fparent (...)
  {
    ...
    fn(vty->index, ...)
    ...
  }

@ script:python @
fn << rule11.fn;
@@
print "R11 removing vty-index argument on %s(...)" % (fn)

#/* find type of the argument - note args are mostly unnamed in FRR :( */
@ rule12 @
identifier rule11.fn;
identifier T, argname;
type Tr;
@@

(
  Tr fn(struct T *, ...);
|
  Tr fn(struct T * argname, ...);
)

@ script:python @
fn << rule11.fn;
T << rule12.T;
@@
print "R12 removing vty-index type is %s for %s(...)" % (T, fn)

#/* add declvar
# * this is split from rule14 so we support multiple calls in one func */
@ rule13a @
identifier rule11.fparent;
identifier rule12.T;
@@

  int fparent (...)
  {
+   VTY_DECLVAR_CONTEXT(T, T);
    ...
  }

@ rule13b @
identifier rule11.fparent;
identifier rule12.T;
type Tr;
@@

  Tr *fparent (...)
  {
+   struct T *T = VTY_GET_CONTEXT(T);
+   if (!T) {
+     return NULL;
+   }
    ...
  }

/* now replace the argument in the call */
@ rule14 exists @
identifier rule11.fn;
identifier rule12.T;
@@

  {
    ...
    \(
    fn(
-       vty->index,
+       T,
        ...)
    \|
    fn(
-       vty->index
+       T
        )
    \)
    ...
  }

/* special case ... */
@rule30@
identifier fn =~ "generic_(set|match)_";
expression arg;
@@
 
  fn(arg,
-    arg->index,
+    VTY_GET_CONTEXT(route_map_index),
     ...)

/* and finally - PUSH_CONTEXT */
@ rule99a exists @
identifier tnode;
identifier vexpr =~ "NULL";
@@

- vty->node = tnode;
  ...
- vty->index = vexpr;
+ VTY_PUSH_CONTEXT_NULL(tnode);

@ rule99b exists @
identifier tnode;
expression vexpr;
@@

- vty->node = tnode;
  ...
- vty->index = vexpr;
+ VTY_PUSH_CONTEXT(tnode, vexpr);

