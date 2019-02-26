///
/// Use zeroing allocator rather than allocator followed by memset with 0
///
/// This considers some simple cases that are common and easy to validate
/// Note in particular that there are no ...s in the rule, so all of the
/// matched code has to be contiguous
///
// Confidence: High
// Copyright: (C) 2009-2010 Julia Lawall, Nicolas Palix, DIKU.  GPLv2.
// Copyright: (C) 2009-2010 Gilles Muller, INRIA/LiP6.  GPLv2.
// Copyright: (C) 2017 Himanshu Jha GPLv2.
// Copyright: (C) 2019 Quentin Young.  GPLv2.
// URL: http://coccinelle.lip6.fr/rules/kzalloc.html
// Options: --no-includes --include-headers
//
// Keywords: XMALLOC, XCALLOC
// Version min: < 2.6.12 kmalloc
// Version min:   2.6.14 kzalloc
//

virtual context
virtual patch

//----------------------------------------------------------
//  For context mode
//----------------------------------------------------------

@depends on context@
type T, T2;
expression x;
expression E1;
expression t;
@@

* x = (T)XMALLOC(t, E1);
* memset((T2)x,0,E1);

//----------------------------------------------------------
//  For patch mode
//----------------------------------------------------------

@depends on patch@
type T, T2;
expression x;
expression E1;
expression t;
@@

- x = (T)XMALLOC(t, E1);
+ x = (T)XCALLOC(t, E1);
- memset((T2)x,0,E1);

