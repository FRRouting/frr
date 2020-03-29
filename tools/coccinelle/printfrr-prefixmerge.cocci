@initialize:python@
@@

import sys

sys.path.append('tools/coccinelle')

from cocci_re import fmt_replace

prev_replacements = set()

@formatter@
expression E;
expression dummy;
expression b;
position pos;
identifier af =~ "^AF_INET6?$";
@@

(
 inet_ntoa@pos((E.u.prefix4))
|
 inet6_ntoa@pos((E.u.prefix))
|
 inet6_ntoa@pos((E.u.prefix6))
|
 inet_ntop@pos(af, &(E.u.prefix), b, dummy)
|
 inet_ntop@pos(E.family, &(E.u.prefix), b, dummy)
|
 inet_ntop@pos(af, (E.u.val), b, dummy)
|
 inet_ntop@pos(E.family, (E.u.val), b, dummy)
|
 inet_ntoa@pos((E.prefix))
|
 inet6_ntoa@pos((E.prefix))
|
 inet_ntop@pos(af, &(E.prefix), b, dummy)
|
 inet_ntop@pos(E.family, &(E.prefix), b, dummy)
)

@logcall@
position formatter.pos;
position callpos;
identifier logfunc =~ "^(z|)log_(err|warn|info|notice|debug)$";
identifier argfunc =~ "^(flog_(err|warn|info|notice|debug)|vty_out)$";
identifier snpfunc =~ "^snprintf(rr)?$";
format list fmt;
expression list P;
expression formatter.E;
expression formatter.b;
expression F, G;
expression arg, arg2;
@@

(
 logfunc@callpos("%@fmt@", P, F@pos(...), E.prefixlen, ...)
|
 argfunc@callpos(arg, "%@fmt@", P, F@pos(...), E.prefixlen, ...)
|
 G = argfunc@callpos(arg, "%@fmt@", P, F@pos(...), E.prefixlen, ...)
|
 snpfunc@callpos(arg, arg2, "%@fmt@", P, F@pos(...), E.prefixlen, ...)
|
 G = snpfunc@callpos(arg, arg2, "%@fmt@", P, F@pos(...), E.prefixlen, ...)
)

@script:python logcallfmt@
oldexpr << formatter.E;
oldaf << formatter.af = "...";
otherargs << logcall.P;
callpos << logcall.callpos;
fmtfn << logcall.F;
fmt << logcall.fmt;
newfmt;
newexpr;
@@

once_key = (fmt, callpos[0].file, callpos[0].line)

if once_key in prev_replacements:
    sys.stderr.write('\033[33;1mmore replacements, run again\033[m\n')
    cocci.include_match(False)
else:
    prev_replacements.add(once_key)

    newfmt = fmt_replace(fmt, len(otherargs.elements), 'pFX', True)
    if newfmt is not None:
        coccinelle.newfmt = cocci.make_expr('"%s"' % newfmt)

@@
expression logcall.F;
expression logcall.G;
expression formatter.E;
expression formatter.b;
position formatter.pos;
expression list logcall.P;
identifier logcall.logfunc;
identifier logcall.argfunc;
identifier logcall.snpfunc;
format list logcall.fmt;
expression logcallfmt.newfmt;
expression logcallfmt.newexpr;
expression arg, arg2;
@@

(
  logfunc(
-	"%@fmt@"
+	newfmt
	, P,
-	F@pos(...), E.prefixlen
+	&E
	,
	...
	);
|
  argfunc(arg,
-	"%@fmt@"
+	newfmt
	, P,
-	F@pos(...), E.prefixlen
+	&E
	,
	...
	);
|
  G = argfunc(arg,
-	"%@fmt@"
+	newfmt
	, P,
-	F@pos(...), E.prefixlen
+	&E
	,
	...
	);
|
- snpfunc
+ snprintfrr
  (arg, arg2,
-	"%@fmt@"
+	newfmt
	, P,
-	F@pos(...), E.prefixlen
+	&E
	,
	...
	);
|
  G =
- snpfunc
+ snprintfrr
  (arg, arg2,
-	"%@fmt@"
+	newfmt
	, P,
-	F@pos(...), E.prefixlen
+	&E
	,
	...
	);
)


