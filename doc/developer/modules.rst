Modules
=======

FRR has facilities to load DSOs at startup via ``dlopen()``. These are used to
implement modules, such as SNMP and FPM.

Limitations
-----------

-  can't load, unload, or reload during runtime. This just needs some
   work and can probably be done in the future.
-  doesn't fix any of the "things need to be changed in the code in the
   library" issues. Most prominently, you can't add a CLI node because
   CLI nodes are listed in the library...
-  if your module crashes, the daemon crashes. Should be obvious.
-  **does not provide a stable API or ABI**. Your module must match a
   version of FRR and you may have to update it frequently to match
   changes.
-  **does not create a license boundary**. Your module will need to link
   libzebra and include header files from the daemons, meaning it will
   be GPL-encumbered.

Installation
------------

Look for ``moduledir`` in ``configure.ac``, default is normally
``/usr/lib64/frr/modules`` but depends on ``--libdir`` / ``--prefix``.

The daemon's name is prepended when looking for a module, e.g. "snmp"
tries to find "zebra\_snmp" first when used in zebra. This is just to
make it nicer for the user, with the snmp module having the same name
everywhere.

Modules can be packaged separately from FRR. The SNMP and FPM modules
are good candidates for this because they have dependencies (net-snmp /
protobuf) that are not FRR dependencies. However, any distro packages
should have an "exact-match" dependency onto the FRR package. Using a
module from a different FRR version will probably blow up nicely.

For snapcraft (and during development), modules can be loaded with full
path (e.g. -M ``$SNAP/lib/frr/modules/zebra_snmp.so``). Note that
libtool puts output files in the .libs directory, so during development
you have to use ``./zebra -M .libs/zebra_snmp.so``.

Creating a module
-----------------

... best to look at the existing SNMP or FPM modules.

Basic boilerplate:

::

    #include "hook.h"
    #include "module.h"

    static int
    module_init (void)
    {
      hook_register(frr_late_init, module_late_init);
      return 0;
    }

    FRR_MODULE_SETUP(
        .name = "my module",
        .version = "0.0",
        .description = "my module",
        .init = module_init,
    )

The ``frr_late_init`` hook will be called after the daemon has finished
its other startup and is about to enter the main event loop; this is the
best place for most initialisation.

Compiler & Linker magic
-----------------------

There's a ``THIS_MODULE`` (like in the Linux kernel), which uses
``visibility`` attributes to restrict it to the current module. If you
get a linker error with ``_frrmod_this_module``, there is some linker
SNAFU. This shouldn't be possible, though one way to get it would be to
not include libzebra (which provides a fallback definition for the
symbol).

libzebra and the daemons each have their own ``THIS_MODULE``, as do all
loadable modules. In any other libraries (e.g. ``libfrrsnmp``),
``THIS_MODULE`` will use the definition in libzebra; same applies if the
main executable doesn't use ``FRR_DAEMON_INFO`` (e.g. all testcases).

The deciding factor here is "what dynamic linker unit are you using the
symbol from." If you're in a library function and want to know who
called you, you can't use ``THIS_MODULE`` (because that'll just tell you
you're in the library). Put a macro around your function that adds
``THIS_MODULE`` in the *caller's code calling your function*.

The idea is to use this in the future for module unloading. Hooks
already remember which module they were installed by, as groundwork for
a function that removes all of a module's installed hooks.

There's also the ``frr_module`` symbol in modules, pretty much a
standard entry point for loadable modules.

Hooks
-----

Hooks are just points in the code where you can register your callback
to be called. The parameter list is specific to the hook point. Since
there is no stable API, the hook code has some extra type safety checks
making sure you get a compiler warning when the hook parameter list
doesn't match your callback. Don't ignore these warnings.

Relation to MTYPE macros
------------------------

The MTYPE macros, while primarily designed to decouple MTYPEs from the
library and beautify the code, also work very nicely with loadable
modules -- both constructors and destructors are executed when
loading/unloading modules.

This means there is absolutely no change required to MTYPEs, you can
just use them in a module and they will even clean up themselves when we
implement module unloading and an unload happens. In fact, it's
impossible to create a bug where unloading fails to de-register a MTYPE.
