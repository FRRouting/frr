.. highlight:: c

Hooks
=====

Libfrr provides type-safe subscribable hook points where other pieces of
code can add one or more callback functions.  "type-safe" in this case
applies to the function pointers used for subscriptions.  The
implementations checks (at compile-time) whether a callback to be added has
the appropriate function signature (parameters) for the hook.

Example:

.. code-block:: c
   :caption: mydaemon_hooks.h

   /* note: file may be included multiple times - no include guard! */
   DO_HOOK(some_update_event, (struct eventinfo *, info));

.. code-block:: c
   :caption: mydaemon.h

   #define HOOKS_DECLARE
   #include "lib/hooks_begin.h"
   #include "mydaemon/mydaemon_hooks.h"
   #include "lib/hooks_end.h"

.. code-block:: c
   :caption: mydaemon.c

   #include "mydaemon/mydaemon.h"

   #define HOOKS_DEFINE
   #include "lib/hooks_begin.h"
   #include "mydaemon/mydaemon_hooks.h"
   #include "lib/hooks_end.h"

   ...
   hook_call(some_update_event, info);

.. code-block:: c
   :caption: mymodule.c

   #include "mydaemon/mydaemon.h"
   static int event_handler(struct eventinfo *info);
   ...
   hook_register(some_update_event, event_handler);

Do not use parameter names starting with "hook", these can collide with
names used by the hook code itself.


File splitting and positioning
------------------------------

As shown in the example above, the actual hook definitions are now split off
into separate ``_hooks.h`` files.  These files should contain only
:c:macro:`DO_HOOK` and :c:macro:`DO_KOOH` macro statements and their comments
(and possibly some ``#ifdef``), nothing else.

The ``lib/hooks_begin.h`` and ``lib/hooks_end.h`` files connect the
:c:macro:`DO_HOOK` macro into :c:macro:`DECLARE_HOOK`, :c:macro:`DEFINE_HOOK`
or :c:macro:`LUA_HOOK` (plus analog for ``_KOOH``), depending on whether
``HOOKS_DECLARE``, ``HOOKS_DEFINE`` or ``HOOKS_LUA`` were set.

The purpose of this is that the same "definition" can be reused for the hook
declaration, definition, and at some point in the future scripting language
bindings.

.. todo::

   The :c:macro:`LUA_HOOK` macro used when ``HOOKS_LUA`` is set don't actually
   exist yet.

Generally, the following patterns should be followed in this regard:

* each "block" (declaration/definition per hooks file) should only be included
  in one place.  Including it more than once will cause compiler errors due to
  duplicate symbols.
* if a file references multiple ``_hooks.h`` files (this should only happen
  in header files), group them all together and include ``hooks_begin.h`` /
  ``hooks_end.h`` only once.
* the ``_hooks.h`` is mostly named to match the ``.c`` file that the hooks are
  defined and invoked in.
* the ``HOOKS_DECLARE`` block in a ``.h`` file should be towards the end of
  the file (but inside the ``extern "C"`` block if there is one.)
* the ``HOOKS_DEFINE`` block in a ``.c`` file should be towards the beginning
  of the file, after all ``#include`` statements and before any function
  definitions.


Return values
-------------

Callbacks to be placed on hooks always return "int" for now;  hook_call will
sum up the return values from each called function.  (The default is 0 if no
callbacks are registered.)

There are no pre-defined semantics for the value, in most cases it is
ignored.  For success/failure indication, 0 should be success, and
handlers should make sure to only return 0 or 1 (not -1 or other values).

There is no built-in way to abort executing a chain after a failure of one
of the callbacks.  If this is needed, the hook can use an extra
``bool *aborted`` argument.


Priorities
----------

Hooks support a "priority" value for ordering registered calls
relative to each other.  The priority is a signed integer where lower
values are called earlier.  There are also "Koohs", which is hooks with
reverse priority ordering (for cleanup/deinit hooks, so you can use the
same priority value).

Recommended priority value ranges are:

======================== ===================================================
Range                    Usage
------------------------ ---------------------------------------------------
 -999 ...     0 ...  999 main executable / daemon, or library

-1999 ... -1000          modules registering calls that should run before
                         the daemon's bits

1000 ... 1999            modules' calls that should run after daemon's
                         (includes default value: 1000)
======================== ===================================================

Note: the default value is 1000, based on the following 2 expectations:

- most hook_register() usage will be in loadable modules
- usage of hook_register() in the daemon itself may need relative ordering
  to itself, making an explicit value the expected case

The priority value is passed as extra argument on hook_register_prio() /
hook_register_arg_prio().  Whether a hook runs in reverse is determined
solely by the code defining / calling the hook.  (DECLARE_KOOH is actually
the same thing as DECLARE_HOOK, it's just there to make it obvious.)


Definition
----------

.. c:macro:: DO_HOOK(name, args...)
.. c:macro:: DO_KOOH(name, args...)

   :param name: Name of the hook to be defined
   :param args: List of (type, name) tuples specifying hook parameters.

   "dispatcher" macros for use in ``_hooks.h`` files that get included multiple
   times.  What it expands to depends on whether ``HOOKS_DECLARE``,
   ``HOOKS_DEFINE`` or ``HOOKS_LUA`` was set before including
   ``hooks_begin.h``.

.. c:macro:: DECLARE_HOOK(name, args...)
.. c:macro:: DECLARE_KOOH(name, args...)

   :param name: Name of the hook to be defined
   :param args: List of (type, name) tuples specifying hook parameters.

   The tuples specifying parameters are essentially just "insert a comma
   between the type and the name and put braces around it".  Without the extra
   comma, the macro would be unable to use the name without the declaration in
   front of it.

   This macro must be placed in a header file;  this header file must be
   included to register a callback on the hook.

   Examples:

   .. code-block:: c

      DECLARE_HOOK(foo);
      DECLARE_HOOK(bar, (int, arg));
      DECLARE_HOOK(baz, (const void *, x), (in_addr_t, y));

   .. note::
      Due to this way of specifying the parameter list, it is not possible to
      use plain function pointers as parameters on hooks, since there the
      function pointer's parameter list is after the name of the parameter.

      This is considered an acceptable limitation of the way this macro works.
      The workaround/solution to defining a hook that takes a function pointer
      as a parameter is to either use a typedef for the function pointer, put
      the function pointer in a struct, or use ``__typeof__``.

      At the time this note was written, none of the hooks in FRR had a
      function pointer parameter.

.. c:macro:: DEFINE_HOOK(name, args...)

   Implements an hook.  Each ``DECLARE_HOOK`` must have be accompanied by
   exactly one ``DEFINE_HOOK``, which needs to be placed in a source file.
   **The hook can only be called from this source file.**  This is intentional
   to avoid overloading and/or misusing hooks for distinct purposes.

   The compiled source file will include a global symbol with the name of the
   hook prefixed by `_hook_`.  Trying to register a callback for a hook that
   doesn't exist will therefore result in a linker error, or a module
   load-time error for dynamic modules.

.. c:macro:: DEFINE_KOOH(name, args...)

   Same as ``DEFINE_HOOK``, but the sense of priorities / order of callbacks
   is reversed.  This should be used for cleanup hooks.

.. c:macro:: LUA_HOOK(name, args...)

   Expands into a Lua binding for the given hook.  Note there is no need for a
   ``KOOH`` form of this, only a ``HOOK`` form for this which would be used for
   both call orderings.

   .. todo:: not implemented yet.

.. c:function:: int hook_call(name, ...)

   Calls the specified named hook.  Parameters to the hook are passed right
   after the hook name, e.g.:

   .. code-block:: c

      hook_call(foo);
      hook_call(bar, 0);
      hook_call(baz, NULL, INADDR_ANY);

   Returns the sum of return values from all callbacks.  The ``DEFINE_HOOK``
   statement for the hook must be placed in the file before any ``hook_call``
   use of the hook.


Callback registration
---------------------

.. c:function:: void hook_register(name, int (*callback)(...))
.. c:function:: void hook_register_prio(name, int priority, int (*callback)(...))
.. c:function:: void hook_register_arg(name, int (*callback)(void *arg, ...), void *arg)
.. c:function:: void hook_register_arg_prio(name, int priority, int (*callback)(void *arg, ...), void *arg)

   Register a callback with an hook.  If the caller needs to pass an extra
   argument to the callback, the _arg variant can be used and the extra
   parameter will be passed as first argument to the callback.  There is no
   typechecking for this argument.

   The priority value is used as described above.  The variants without a
   priority parameter use 1000 as priority value.

.. c:function:: void hook_unregister(name, int (*callback)(...))
.. c:function:: void hook_unregister_arg(name, int (*callback)(void *arg, ...), void *arg)

   Removes a previously registered callback from a hook.  Note that there
   is no _prio variant of these calls.  The priority value is only used during
   registration.
