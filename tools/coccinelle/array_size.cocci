/// Use array_size instead of dividing sizeof array with sizeof an element
///
//# This makes an effort to find cases where array_size can be used such as
//# where there is a division of sizeof the array by the sizeof its first
//# element or by any indexed element or the element type. It replaces the
//# division of the two sizeofs by array_size.
//
// Confidence: High
// Copyright: (C) 2014 Himangi Saraogi.  GPLv2.
// Copyright: (C) 2019 Quentin Young.  GPLv2.
// Comments:
// Options: --no-includes --include-headers

virtual patch
virtual context
virtual org
virtual report

//----------------------------------------------------------
//  For context mode
//----------------------------------------------------------

@depends on context@
type T;
T[] E;
@@
(
* (sizeof(E)/sizeof(*E))
|
* (sizeof(E)/sizeof(E[...]))
|
* (sizeof(E)/sizeof(T))
)

//----------------------------------------------------------
//  For patch mode
//----------------------------------------------------------

@depends on patch@
type T;
T[] E;
@@
(
- (sizeof(E)/sizeof(*E))
+ array_size(E)
|
- (sizeof(E)/sizeof(E[...]))
+ array_size(E)
|
- (sizeof(E)/sizeof(T))
+ array_size(E)
)

//----------------------------------------------------------
//  For org and report mode
//----------------------------------------------------------

@r depends on (org || report)@
type T;
T[] E;
position p;
@@
(
 (sizeof(E)@p /sizeof(*E))
|
 (sizeof(E)@p /sizeof(E[...]))
|
 (sizeof(E)@p /sizeof(T))
)

@script:python depends on org@
p << r.p;
@@

coccilib.org.print_todo(p[0], "WARNING should use array_size")

@script:python depends on report@
p << r.p;
@@

msg="WARNING: Use array_size"
coccilib.report.print_report(p[0], msg)

