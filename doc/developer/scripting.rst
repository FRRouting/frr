.. _scripting:

Scripting
=========

.. seealso:: User docs for scripting

Overview
--------

FRR has the ability to call Lua scripts to perform calculations, make
decisions, or otherwise extend builtin behavior with arbitrary user code. This
is implemented using the standard Lua C bindings. The supported version of Lua
is 5.3.

C objects may be passed into Lua and Lua objects may be retrieved by C code via
a marshalling system. In this way, arbitrary data from FRR may be passed to
scripts. It is possible to pass C functions as well.

The Lua environment is isolated from the C environment; user scripts cannot
access FRR's address space unless explicitly allowed by FRR.

For general information on how Lua is used to extend C, refer to Part IV of
"Programming in Lua".

https://www.lua.org/pil/contents.html#24


Design
------

Why Lua
^^^^^^^

Lua is designed to be embedded in C applications. It is very small; the
standard library is 220K. It is relatively fast. It has a simple, minimal
syntax that is relatively easy to learn and can be understood by someone with
little to no programming experience. Moreover it is widely used to add
scripting capabilities to applications. In short it is designed for this task.

Reasons against supporting multiple scripting languages:

- Each language would require different FFI methods, and specifically
  different object encoders; a lot of code
- Languages have different capabilities that would have to be brought to
  parity with each other; a lot of work
- Languages have vastly different performance characteristics; this would
  create alot of basically unfixable issues, and result in a single de facto
  standard scripting language (the fastest)
- Each language would need a dedicated maintainer for the above reasons;
  this is pragmatically difficult
- Supporting multiple languages fractures the community and limits the audience
  with which a given script can be shared

General
^^^^^^^

FRR's concept of a script is somewhat abstracted away from the fact that it is
Lua underneath. A script in has two things:

- name
- state

In code:

.. code-block:: c

   struct frrscript {
           /* Script name */
           char *name;

           /* Lua state */
           struct lua_State *L;
   };


``name`` is simply a string. Everything else is in ``state``, which is itself a
Lua library object (``lua_State``). This is an opaque struct that is
manipulated using ``lua_*`` functions. The basic ones are imported from
``lua.h`` and the rest are implemented within FRR to fill our use cases. The
thing to remember is that all operations beyond the initial loading the script
take place on this opaque state object.

There are four basic actions that can be done on a script:

- load
- execute
- query state
- unload

They are typically done in this order.


Loading
^^^^^^^

A snippet of Lua code is referred to as a "chunk". These are simply text. FRR
presently assumes chunks are located in individual files specific to one task.
These files are stored in the scripts directory and must end in ``.lua``.

A script object is created by loading a script. This is done with
``frrscript_load()``. This function takes the name of the script and an
optional callback function. The string ".lua" is appended to the script name,
and the resultant filename is looked for in the scripts directory.

For example, to load ``/etc/frr/scripts/bingus.lua``:

.. code-block:: c

   struct frrscript *fs = frrscript_load("bingus", NULL);

During loading the script is validated for syntax and its initial environment
is setup. By default this does not include the Lua standard library; there are
security issues to consider, though for practical purposes untrusted users
should not be able to write the scripts directory anyway. If desired the Lua
standard library may be added to the script environment using
``luaL_openlibs(fs->L)`` after loading the script. Further information on
setting up the script environment is in the Lua manual.


Executing
^^^^^^^^^

After loading, scripts may be executed. A script may take input in the form of
variable bindings set in its environment prior to being run, and may provide
results by setting the value of variables. Arbitrary C values may be
transferred into the script environment, including functions.

A typical execution call looks something like this:

.. code-block:: c

   struct frrscript *fs = frrscript_load(...);

   int status_ok = 0, status_fail = 1;
   struct prefix p = ...;

   int result = frrscript_call(fs,
                ("STATUS_FAIL", &status_fail),
                ("STATUS_OK", &status_ok),
                ("prefix", &p));


To execute a loaded script, we need to define the inputs. These inputs are
passed in by binding values to variable names that will be accessible within the
Lua environment. Basically, all communication with the script takes place via
global variables within the script, and to provide inputs we predefine globals
before the script runs. This is done by passing ``frrscript_call()`` a list of
parenthesized pairs, where the first and second fields identify, respectively,
the name of the global variable within the script environment and the value it
is bound to.

The script is then executed and returns a general status code. In the success
case this will be 0, otherwise it will be nonzero. The script itself does not
determine this code, it is provided by the Lua interpreter.


Querying State
^^^^^^^^^^^^^^

.. todo::

   This section will be updated once ``frrscript_get_result`` has been
   updated to work with the new ``frrscript_call`` and the rest of the new API.


Unloading
^^^^^^^^^

To destroy a script and its associated state:

.. code-block:: c

   frrscript_unload(fs);


.. _marshalling:

Marshalling
^^^^^^^^^^^

Earlier sections glossed over the types of values that can be passed into
``frrscript_call`` and how data is passed between C and Lua. Lua, as a dynamically
typed, garbage collected language, cannot directly use C values without some
kind of marshalling / unmarshalling system to translate types between the two
runtimes.

Lua communicates with C code using a stack. C code wishing to provide data to
Lua scripts must provide a function that marshalls the C data into a Lua
representation and pushes it on the stack. C code wishing to retrieve data from
Lua must provide a corresponding unmarshalling function that retrieves a Lua
value from the stack and converts it to the corresponding C type. These
functions are known as encoders and decoders in FRR.

An encoder is a function that takes a ``lua_State *`` and a C type and pushes
onto the Lua stack a value representing the C type. For C structs, the usual
case, this will typically be a Lua table (tables are the only datastructure Lua
has). For example, here is the encoder function for ``struct prefix``:


.. code-block:: c

   void lua_pushprefix(lua_State *L, struct prefix *prefix)
   {
           char buffer[PREFIX_STRLEN];

           zlog_debug("frrlua: pushing prefix table");

           lua_newtable(L);
           lua_pushstring(L, prefix2str(prefix, buffer, PREFIX_STRLEN));
           lua_setfield(L, -2, "network");
           lua_pushinteger(L, prefix->prefixlen);
           lua_setfield(L, -2, "length");
           lua_pushinteger(L, prefix->family);
           lua_setfield(L, -2, "family");
   }

This function pushes a single value onto the Lua stack. It is a table whose
equivalent in Lua is:

.. code-block:: c

   { ["network"] = "1.2.3.4/24", ["prefixlen"] = 24, ["family"] = 2 }


Decoders are a bit more involved. They do the reverse; a decoder function takes
a ``lua_State *``, pops a value off the Lua stack and converts it back into its
C type.
However, since Lua programs have the ability to directly modify their inputs
(i.e. values passed in via ``frrscript_call``), we need two separate decoder
functions, called ``lua_decode_*`` and ``lua_to*``.

A ``lua_decode_*`` function takes a ``lua_State*``, an index, and a C type, and
unmarshalls a Lua value into that C type.
Again, for ``struct prefix``:

.. code-block:: c

   void lua_decode_prefix(lua_State *L, int idx, struct prefix *prefix)
   {
        lua_getfield(L, idx, "network");
        (void)str2prefix(lua_tostring(L, -1), prefix);
        lua_pop(L, 1);
        /* pop the table */
        lua_pop(L, 1);
   }

.. warning::

   ``lua_decode_prefix`` functions should leave the Lua stack completely empty
   when they return.
   For decoders that unmarshall fields from tables, remember to pop the table
   at the end.


A ``lua_to*`` function perform a similar role except that it first allocates
memory for the new C type before decoding the value from the Lua stack, then
returns a pointer to the newly allocated C type.
This function can and should be implemented using ``lua_decode_*``:

.. code-block:: c

   void *lua_toprefix(lua_State *L, int idx)
   {
           struct prefix *p = XCALLOC(MTYPE_TMP, sizeof(struct prefix));

           lua_decode_prefix(L, idx, p);
           return p;
   }


The returned data must always be copied off the stack and the copy must be
allocated with ``MTYPE_TMP``. This way it is possible to unload the script
(destroy the state) without invalidating any references to values stored in it.
Note that it is the caller's responsibility to free the data.

For consistency, we should always name functions of the first type
``lua_decode_*``.
Functions of the second type should be named ``lua_to*``, as this is the
naming convention used by the Lua C library for the basic types e.g.
``lua_tointeger`` and ``lua_tostring``.

This two-function design allows the compiler to warn if a value passed into
``frrscript_call`` does not have a encoder and decoder for that type.
The ``lua_to*`` functions enable us to easily create decoders for nested
structures.

To register a new type with its corresponding encoding and decoding functions,
add the mapping in the following macros in ``frrscript.h``:

.. code-block:: diff

     #define ENCODE_ARGS_WITH_STATE(L, value) \
          _Generic((value), \
          ...
   - struct peer * : lua_pushpeer \
   + struct peer * : lua_pushpeer, \
   + struct prefix * : lua_pushprefix \
     )(L, value)

     #define DECODE_ARGS_WITH_STATE(L, value) \
          _Generic((value), \
          ...
   - struct peer * : lua_decode_peer \
   + struct peer * : lua_decode_peer, \
   + struct prefix * : lua_decode_prefix \
     )(L, -1, value)


At compile time, the compiler will search for encoders/decoders for the type of
each value passed in via ``frrscript_call``. If a encoder/decoder cannot be
found, it will appear as a compile warning. Note that the types must
match *exactly*.
In the above example, we defined encoders/decoders for a value of
``struct prefix *``, but not ``struct prefix`` or ``const struct prefix *``.

.. code-block:: diff

     #define DECODE_ARGS_WITH_STATE(L, value) \
          _Generic((value), \
          ...
   + const struct prefix * : lua_decode_noop \
     )(L, -1, value)


.. note::

   Marshalled types are not restricted to simple values like integers, strings
   and tables. It is possible to marshall a type such that the resultant object
   in Lua is an actual object-oriented object, complete with methods that call
   back into defined C functions. See the Lua manual for how to do this; for a
   code example, look at how zlog is exported into the script environment.


Script Environment
------------------

Logging
^^^^^^^

For convenience, script environments are populated by default with a ``log``
object which contains methods corresponding to each of the ``zlog`` levels:

.. code-block:: lua

   log.info("info")
   log.warn("warn")
   log.error("error")
   log.notice("notice")
   log.debug("debug")

The log messages will show up in the daemon's log output.


Examples
--------

For a complete code example involving passing custom types, retrieving results,
and doing complex calculations in Lua, look at the implementation of the
``match script SCRIPT`` command for BGP routemaps. This example calls into a
script with a route prefix and attributes received from a peer and expects the
script to return a match / no match / match and update result.

An example script to use with this follows. This script matches, does not match
or updates a route depending on how many BGP UPDATE messages the peer has
received when the script is called, simply as a demonstration of what can be
accomplished with scripting.

.. code-block:: lua


   -- Example route map matching
   -- author: qlyoung
   --
   -- The following variables are available to us:
   --   log
   --     logging library, with the usual functions
   --   prefix
   --     the route under consideration
   --   attributes
   --     the route's attributes
   --   peer
   --     the peer which received this route
   --   RM_FAILURE
   --     status code in case of failure
   --   RM_NOMATCH
   --     status code for no match
   --   RM_MATCH
   --     status code for match
   --   RM_MATCH_AND_CHANGE
   --     status code for match-and-set
   --
   -- We need to set the following out values:
   --   action
   --      Set to the appropriate status code to indicate what we did
   --   attributes
   --      Setting fields on here will propagate them back up to the caller if
   --      'action' is set to RM_MATCH_AND_CHANGE.
   
   
   log.info("Evaluating route " .. prefix.network .. " from peer " .. peer.remote_id.string)
   
   function on_match (prefix, attrs)
           log.info("Match")
           action = RM_MATCH
   end
   
   function on_nomatch (prefix, attrs)
           log.info("No match")
           action = RM_NOMATCH
   end
   
   function on_match_and_change (prefix, attrs)
           action = RM_MATCH_AND_CHANGE
           log.info("Match and change")
           attrs["metric"] = attrs["metric"] + 7
   end
   
   special_routes = {
           ["172.16.10.4/24"] = on_match,
           ["172.16.13.1/8"] = on_nomatch,
           ["192.168.0.24/8"] = on_match_and_change,
   }
   
   
   if special_routes[prefix.network] then
           special_routes[prefix.network](prefix, attributes)
   elseif peer.stats.update_in % 3 == 0 then
           on_match(prefix, attributes)
   elseif peer.stats.update_in % 2 == 0 then
           on_nomatch(prefix, attributes)
   else
           on_match_and_change(prefix, attributes)
   end

