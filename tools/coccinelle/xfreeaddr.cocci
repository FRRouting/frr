/// Free of a structure field
///
// Confidence: High
// Copyright: (C) 2013 Julia Lawall, INRIA/LIP6.  GPLv2.
// Copyright: (C) 2019 Quentin Young.  GPLv2.
// URL: http://coccinelle.lip6.fr/
// Comments:
// Options: --no-includes --include-headers

virtual org
virtual report
virtual context

@r depends on context || report || org @
expression e, t;
identifier f;
position p;
@@

* XFREE@p(t, &e->f)

@script:python depends on org@
p << r.p;
@@

cocci.print_main("XFREE",p)

@script:python depends on report@
p << r.p;
@@

msg = "ERROR: invalid free of structure field"
coccilib.report.print_report(p[0],msg)
