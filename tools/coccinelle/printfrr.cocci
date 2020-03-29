@initialize:python@
@@

import sys

sys.path.append('tools/coccinelle')

from cocci_re import fmt_replace

prev_replacements = set()

@formatter@
expression E;
expression dummy;
identifier b;
position pos;
identifier af =~ "^AF_INET6?$";
@@

(
 prefix2str@pos(E, b, dummy)
|
 prefix_mac2str@pos(E, b, dummy)
|
 inet_ntoa@pos(E)
|
 inet_ntop@pos(af, E, b, dummy)
|
 ipaddr2str@pos(E, b, dummy)
)

@logcall@
position formatter.pos;
identifier formatter.b;
position callpos;
identifier logfunc =~ "^(z|)log_(err|warn|info|notice|debug)$";
identifier argfunc =~ "^(flog_(err|warn|info|notice|debug)|vty_out)$";
identifier snpfunc =~ "^snprintf(rr)?$";
format list fmt;
expression list P;
expression F;
expression arg, arg2;
@@

(
 logfunc@callpos("%@fmt@", P, F@pos(...), ...);
|
 argfunc@callpos(arg, "%@fmt@", P, F@pos(...), ...);
|
 snpfunc@callpos(arg, arg2, "%@fmt@", P, F@pos(...), ...);
|
 { ...
 F@pos(...)
 ... when != b
(
 logfunc@callpos("%@fmt@", P, b, ...);
|
 argfunc@callpos(arg, "%@fmt@", P, b, ...);
|
 snpfunc@callpos(arg, arg2, "%@fmt@", P, b, ...);
)
 ... when != b
 }
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

replacements = {
    'prefix2str': 'pFX',
    'prefix_mac2str': 'pEA',
    'ipaddr2str': 'pIA',
    'inet_ntoa': 'pI4',
    'inet_ntop': 'pI6' if oldaf == 'AF_INET6' else 'pI4',
}

once_key = (fmt, callpos[0].file, callpos[0].line)

if fmtfn not in replacements:
    sys.stderr.write('\033[33;1mno replacement for %s()\033[m\n' % fmtfn)
    cocci.include_match(False)
elif once_key in prev_replacements:
    sys.stderr.write('\033[33;1mmore replacements, run again\033[m\n')
    cocci.include_match(False)
else:
    prev_replacements.add(once_key)

    newfmt = fmt_replace(fmt, len(otherargs.elements), replacements[fmtfn])
    if newfmt is not None:
        coccinelle.newfmt = cocci.make_expr('"%s"' % newfmt)

    if fmtfn in ['inet_ntoa']:
        if oldexpr.startswith('*'):
            coccinelle.newexpr = cocci.make_expr(oldexpr[1:].strip())
        else:
            coccinelle.newexpr = cocci.make_expr('&%s' % oldexpr)
    else:
        coccinelle.newexpr = cocci.make_expr(oldexpr)

@@
expression logcall.F;
identifier formatter.b;
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
-	F@pos(...)
+	newexpr
	,
	...
	);
|
  argfunc(arg,
-	"%@fmt@"
+	newfmt
	, P,
-	F@pos(...)
+	newexpr
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
-	F@pos(...)
+	newexpr
	,
	...
	);
|
- F@pos(...);
  ...
(
  logfunc(
-	"%@fmt@"
+	newfmt
	, P,
-	b
+	newexpr
	,
	...
	);
|
  argfunc(arg,
-	"%@fmt@"
+	newfmt
	, P,
-	b
+	newexpr
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
-	b
+	newexpr
	,
	...
	);
)
)

@@
identifier formatter.b;
type T;
expression Z;
@@

  {
  ...
- T b[Z];
  ... when != b
  }
