/// XMALLOC, XCALLOC etc either return non-null, or abort the program.
/// Never nullcheck these.
//
// Copyright: (C) 2019 Quentin Young.  GPLv2.

virtual patch

//----------------------------------------------------------
//  For patch mode
//----------------------------------------------------------

@depends on patch@
identifier alloc;
@@

alloc = XMALLOC(...);

...

- if (alloc == NULL)
- {
- ...
- }

@depends on patch@
identifier alloc;
@@

alloc = XCALLOC(...);

...

- if (alloc == NULL)
- {
- ...
- }

