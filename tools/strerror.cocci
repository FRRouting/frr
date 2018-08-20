@initialize:python@
@@
import sys, re


@@
symbol zlog_warn;
symbol flog_warn_sys;
symbol safe_strerror;
symbol errno;
@@

- zlog_warn(
+ flog_warn_sys(LIB_ERR_SYSTEM_CALL,
	..., safe_strerror(errno), ...);

@@
symbol zlog_err;
symbol flog_err_sys;
symbol safe_strerror;
symbol errno;
@@

- zlog_err(
+ flog_err_sys(LIB_ERR_SYSTEM_CALL,
	..., safe_strerror(errno), ...);

/*
 * part 2: flog_* -> flog_*_sys
 */

@@
symbol errno;
expression errx !~ "^errno$";
identifier strerror =~ "^(safe_)?strerror$";
expression list p;
identifier errfunc =~ "^flog_err|^flog_warn";
@@

- errfunc(p, strerror(errx));
+ errno = errx;
+ errfunc(p, strerror(errno));

@r0@
symbol errno;
identifier strerror =~ "^(safe_)?strerror$";
identifier errfunc =~ "^flog_err$|^flog_warn$";
fresh identifier sysfunc = errfunc ## "_sys";
@@

- errfunc(
+ sysfunc(
    ..., strerror(errno));

/*
 * part 3: strip safe_strerror()
 */

@rstr@
symbol errno;
identifier sysfunc =~ "^flog_err_sys$|^flog_warn_sys$";
identifier strerror =~ "^(safe_)?strerror$";
format list fmt;
expression list p;
expression e;
@@

sysfunc(e, "%@fmt@", p, strerror(errno));

@script:python sstr@
fmt << rstr.fmt;
newfmt;
@@

matches = [
    (r'^(.*)[:,] %s\.?\s*$',   r'\1'),
    (r'^(.*)[:,] %s\)\s*$', r'\1)'),
    (r'^(.*) \(%s\)\s*$', r'\1'),
    (r'^(.*) %s\.?\s*$',   r'\1'),
    (r'^(.*), err=%s\.?\s*$',   r'\1'),
    (r'^(.*%d)\(%s\)\.?\s*$',   r'\1'),
]
if fmt.endswith('\\n'): fmt = fmt[:-2]
for expr, repl in matches:
    m = re.match(expr, fmt)
    if m is not None:
        newfmt = re.sub(expr, repl, fmt)
	sys.stderr.write('\033[32;1m%s => %s\033[m\n' % (fmt, newfmt))
	break
else:
    newfmt = ''
    cocci.include_match(False)
    sys.stderr.write('\033[31;1m%s\033[m\n' % (fmt))
newfmt = '"%s"' % newfmt
coccinelle.newfmt = cocci.make_expr(newfmt)

@@
symbol errno;
identifier rstr.strerror;
identifier rstr.sysfunc;
format list rstr.fmt;
expression sstr.newfmt;
expression list p;
expression e;
@@

- sysfunc(e, "%@fmt@", p, strerror(errno));
+ sysfunc(e, newfmt, p);

/*
 * part 4: strip errno
 */

@rno@
symbol errno;
identifier sysfunc =~ "^flog_err_sys$|^flog_warn_sys$";
format list fmt;
expression list p;
expression e;
@@

sysfunc(e, "%@fmt@", p, errno);

@script:python sno@
fmt << rno.fmt;
newfmt;
@@

matches = [
    (r'^(.*)[:,] errno=%[du]$',   r'\1'),
    (r'^(.*) errno=%[du]$',   r'\1'),
    (r'^(.*)[:,] %[du]$',   r'\1'),
    (r'^(.*)[:,] %[du]\)$', r'\1)'),
    (r'^(.*) ?\((errno )?%[du]\)$', r'\1'),
    (r'^(.*) %[du]$',   r'\1'),
]
if fmt.endswith('\\n'): fmt = fmt[:-2]
for expr, repl in matches:
    m = re.match(expr, fmt)
    if m is not None:
        newfmt = re.sub(expr, repl, fmt)
	sys.stderr.write('\033[32;1m%s => %s\033[m\n' % (fmt, newfmt))
	break
else:
    newfmt = ''
    cocci.include_match(False)
    sys.stderr.write('\033[31;1m%s\033[m\n' % (fmt))

newfmt = '"%s"' % newfmt
coccinelle.newfmt = cocci.make_expr(newfmt)

@@
symbol errno;
identifier rno.sysfunc;
format list rno.fmt;
expression sno.newfmt;
expression list p;
expression e;
@@

- sysfunc(e, "%@fmt@", p, errno);
+ sysfunc(e, newfmt, p);


