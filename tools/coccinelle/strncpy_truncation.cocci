/// Use strlcpy rather than strncpy(dest,..,sz) + dest[sz-1] = '\0'
///
// Confidence: High
// Comments:
// Options: --no-includes --include-headers

virtual patch
virtual context
virtual report
virtual org

@r@
expression dest, src, sz;
position p;
@@

strncpy@p(dest, src, sz);
dest[sz - 1] = '\0';

@script:python depends on org@
p << r.p;
@@

cocci.print_main("strncpy followed by truncation can be strlcpy",p)

@script:python depends on report@
p << r.p;
@@

msg = "SUGGESTION: strncpy followed by truncation can be strlcpy"
coccilib.report.print_report(p[0],msg)

@ok depends on patch@
expression r.dest, r.src, r.sz;
position r.p;
@@

-strncpy@p(
+strlcpy(
  dest, src, sz);
-dest[sz - 1] = '\0';
