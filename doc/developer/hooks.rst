.. highlight:: c

Hooks
=====

Libfrr provides type-safe subscribable hook points where other pieces of
code can add one or more callback functions.  "type-safe" in this case
applies to the function pointers used for subscriptions.  The
implementations checks (at compile-time) wheter a callback to be added has
the appropriate function signature (parameters) for the hook.

Example:

.. code-block:: c
   :caption: mydaemon.h

   #include "hook.h"
   DECLARE_HOOK(some_update_event, (struct eventinfo *info), (info))

.. code-block:: c
   :caption: mydaemon.c

   #include "mydaemon.h"
   DEFINE_HOOK(some_update_event, (struct eventinfo *info), (info))
   ...
   hook_call(some_update_event, info);

.. code-block:: c
   :caption: mymodule.c

   #include "mydaemon.h"
   static int event_handler(struct eventinfo *info);
   ...
   hook_register(some_update_event, event_handler);

Do not use parameter names starting with "hook", these can collide with
names used by the hook code itself.


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

.. c:macro:: DECLARE_HOOK(name, arglist, passlist)
.. c:macro:: DECLARE_KOOH(name, arglist, passlist)

   :param name: Name of the hook to be defined
   :param arglist: Function definition style parameter list in braces.
   :param passlist: List of the same parameters without their types.

   Note:  the second and third macro args must be the hook function's
   parameter list, with the same names for each parameter.  The second
   macro arg is with types (used for defining things), the third arg is
   just the names (used for passing along parameters).

   This macro must be placed in a header file;  this header file must be
   included to register a callback on the hook.

   Examples:

   .. code-block:: c

      DECLARE_HOOK(foo, (), ())
      DECLARE_HOOK(bar, (int arg), (arg))
      DECLARE_HOOK(baz, (const void *x, in_addr_t y), (x, y))

.. c:macro:: DEFINE_HOOK(name, arglist, passlist)

   Implements an hook.  Each ``DECLARE_HOOK`` must have be accompanied by
   exactly one ``DEFINE_HOOK``, which needs to be placed in a source file.
   **The hook can only be called from this source file.**  This is intentional
   to avoid overloading and/or misusing hooks for distinct purposes.

   The compiled source file will include a global symbol with the name of the
   hook prefixed by `_hook_`.  Trying to register a callback for a hook that
   doesn't exist will therefore result in a linker error, or a module
   load-time error for dynamic modules.

.. c:macro:: DEFINE_KOOH(name, arglist, passlist)

   Same as ``DEFINE_HOOK``, but the sense of priorities / order of callbacks
   is reversed.  This should be used for cleanup hooks.

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
