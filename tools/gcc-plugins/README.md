frr-format GCC plugin
=====================

Context
-------

This plugin provides improved type checking for Linux kernel style printf
extensions (i.e. `%pI4` printing `struct in_addr *` as `1.2.3.4`.)

Other than additional warnings, (non-)usage of this plugin should not affect
the build outcome.  It is perfectly fine to build FRR without this plugin.


Binary Debian packages
----------------------

Can be found at [https://deb.nox.tf/devel/].


GCC requirements
----------------

To use this plugin, you need a **patched 9.3.0** or a **patched 10.1.0**
version of GCC using the [gcc-retain-typeinfo.patch] provided in this repo.

Without this patch, GCC strips type information too early during compilation,
leaving to the plugin being unable to perform more meaningful type checks.
(Specifically, all `typedef` casts will be "cooked down" to their final type.)
If the patch is missing, `format-test.c` will show 4 false negative/positive
warnings marked with `(need retain-typeinfo patch)`.

(@eqvinox has discussed this one-line diff with some GCC people on their
IRC channel around mid 2019, the consensus was that the line is an "early
optimization" and removing it should not be harmful.  However, doing so is
likely to break GCC's unit tests since warnings would print different types.)

Other versions of gcc are not supported.  gcc 8 previously did work but isn't
actively tested/maintained.


Usage
-----

First, all plugin-specific statements should be wrapped by an ifdef:

```
#ifdef _FRR_ATTRIBUTE_PRINTFRR
...
#endif
```

`_FRR_ATTRIBUTE_PRINTFRR` will be defined to the plugin's version (currently
0x10000) whenever the plugin is loaded.

Then, annotate extended printf functions with the `frr_format` attribute.
This works exactly like the `format` attribute:

```
int printfn(const char *fmt, ...) __attribute__((frr_format("frr_printf", 1, 2)));
```

In the FRR codebase, use the `PRINTFRR` macro provided in
[../../lib/compiler.h].

Lastly, "declare" extensions with `#pragma FRR printfrr_ext`:
```
#ifdef _FRR_ATTRIBUTE_PRINTFRR
#pragma FRR printfrr_ext "%pI4"  (struct in_addr *)
#pragma FRR printfrr_ext "%pI4"  (in_addr_t *)
#endif
```

Note that you can use multiple such lines if a particular extended printer
works for more than one type (as seen above.)

The pragma type "parameter" looks like a C cast but unfortunately due to GCC
not exporting a good interface to proper type parsing, it is "ghetto parsed",
with only `struct`, `union`, `enum` being properly supported.  `const` is
ignored if it occurs as the first token.  (The plugin always accepts `const`
parameters for printf since printf shouldn't change the passed data it's
printing.)  The last token may be zero or more counts of `*`, note that
qualifiers on the intermediate pointers (e.g. `const char * const *`) are not
supported.


TODOs and future direction
--------------------------

* support two-parameter extension printers that use the precision field
  (e.g. `"%.*pI5" (int af, void *addr)` to print an IP address with the
  address family in the "precision".

* port to future GCC versions

* get the one-liner patch upstreamed


License
-------

This plugin is **derivative of GCC 9.x**.  It was created by copying off
`c-format.c`.  It must therefore adhere to GCC's GPLv3+ license.
