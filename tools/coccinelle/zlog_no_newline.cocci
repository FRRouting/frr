// zlog_* should not have \n or \r at the end usually.
// spatch --sp-file tools/coccinelle/zlog_no_newline.cocci --macro-file tools/cocci.h ./ 2>/dev/null

@r@
expression fmt;
identifier func =~ "zlog_";
position p;
@@
(
  func(fmt)@p
|
  func(fmt, ...)@p
)

@script:python@
fmt << r.fmt;
p << r.p;
@@
if "\\n" in str(fmt) or "\\r" in str(fmt):
    print("Newline in logging function detected %s:%s:%s:%s" % (p[0].file, p[0].line, p[0].column, fmt))
