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

The build system no longer attempts to use an installed copy of the plugin,
therefore binary packages would be nonsensical.


GCC requirements
----------------

To use this plugin, you need GCC installed with matching plugin development
headers.  On Fedora these headers seem to be included in the default GCC
package, and this should "just work".  On Debian and derivatives, install the
`gcc-${version}-plugin-dev` package, e.g. `gcc-15-plugin-dev`.  There is
unfortunately no meta-package to get the "current"/"matching" version
automatically, so you will have to do this again when a new major version of
GCC ships in Debian.


type information on casts
-------------------------

Technically, for full functionality a GCC patch is necessary and provided in
this repo (it still applies to some newer versions.)

Without this patch, GCC strips type information too early during compilation,
leaving to the plugin being unable to perform more meaningful type checks.
(Specifically, all `typedef` casts will be "cooked down" to their final type.)
If the patch is missing, `format-test.c` will show 4 false negative/positive
warnings marked with `(need retain-typeinfo patch)`.

The conditions to trigger this are sufficiently rare that we just work around
them in FRR code.  Using curly-brace constructor syntax works, e.g. where
```
printfrr("%" PRIu64, (uint64_t)foo);
```
gives a false-positive warning, this will not:
```
printfrr("%" PRIu64, (uint64_t){ foo });
```

That syntax is normally used with structs rather than plain types, but it does
apply to those as well.


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


Source control/maintenance
--------------------------

The GCC source files are first imported into a separately-rooted, empty git
repository that starts at 2fbb5ef8bf33 (root commit).  That is then merged
into FRR.  It's looks a bit odd in a commit graph but works surprisingly well.


Source formatting
-----------------

The `frr-format.cc` and `frr-format.h` files retain GCC's formatting.
**Do not reformat these files.**


License
-------

This plugin is **derivative of GCC**.  It was created by copying off
`c-format.cc`.  It must therefore adhere to GCC's GPLv3+ license.
