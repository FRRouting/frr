Building the tcmalloc library
=============================

The tcmalloc library can release free memory to the host OS. That
support must be compiled-in: at this time there are no pre-built
packages that include it.

Download or clone the google perftools tcmalloc code from github:
 <https://github.com/gperftools/gperftools>

Apply this patch:

::

  diff --git a/configure.ac b/configure.ac
  index ad00def..c06e602 100644
  --- a/configure.ac
  +++ b/configure.ac
  @@ -320,6 +320,7 @@ case "$host" in
    *-mingw*) default_emergency_malloc=no;;
    *) default_emergency_malloc=yes
       AC_DEFINE(HAVE_MMAP, 1, [Define to 1 if you have a working `mmap' system call.])
  +      AC_DEFINE(FREE_MMAP_PROT_NONE, 1, [Use mmap.])
  esac
 
  # We want to access the "PC" (Program Counter) register from a struct

generate the configure script following the project's instructions,
and run configure like this:

.. code-block:: console

  ./configure --libdir=/usr/lib

Then configure and build FRR. Use the `--enable-gperf-tcmalloc`
configure option.
