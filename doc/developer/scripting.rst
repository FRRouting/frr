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
a encoding/decoding system. In this way, arbitrary data from FRR may be passed to
scripts.

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
-------

FRR's scripting functionality is provided in the form of Lua functions in Lua
scripts (``.lua`` files). One Lua script may contain many Lua functions. These
are respectively encapsulated in the following structures:

.. code-block:: c

   struct frrscript {
       /* Lua file name */
       char *name;

       /* hash of lua_function_states */
       struct hash *lua_function_hash;
   };

   struct lua_function_state {
       /* Lua function name */
       char *name;

       lua_State *L;
   };


`struct frrscript`: Since all Lua functions are contained within scripts, the
following APIs manipulates this structure. ``name`` contains the
Lua script name and a hash of Lua functions to their function names.

`struct lua_function_state` is an internal structure, but it essentially contains
the name of the Lua function and its state (a stack), which is run using Lua
library functions.

In general, to run a Lua function, these steps must take place:

- Initialization
- Load
- Call
- Delete

Initialization
^^^^^^^^^^^^^^

The ``frrscript`` object encapsulates the Lua function state(s) from
one Lua script file. To create, use ``frrscript_new()`` which takes the
name of the Lua script.
The string ".lua" is appended to the script name, and the resultant filename
will be used to look for the script when we want to load a Lua function from it.

For example, to create ``frrscript`` for ``/etc/frr/scripts/bingus.lua``:

.. code-block:: c

   struct frrscript *fs = frrscript_new("bingus");


The script is *not* read at this stage.
This function cannot be used to test for a script's presence.

Load
^^^^

The function to be called must first be loaded. Use ``frrscript_load()``
which takes a ``frrscript`` object, the name of the Lua function
and a callback function.
The script file will be read to load and compile the function.

For example, to load the Lua function ``on_foo``
in ``/etc/frr/scripts/bingus.lua``:

.. code-block:: c

   int ret = frrscript_load(fs, "on_foo", NULL);


This function returns 0 if and only if the Lua function was successfully loaded.
A non-zero return could indicate either a missing Lua script, a missing
Lua function, or an error when loading the function.

During loading the script is validated for syntax and its environment
is set up. By default this does not include the Lua standard library; there are
security issues to consider, though for practical purposes untrusted users
should not be able to write the scripts directory anyway.

Call
^^^^

After loading, a Lua function can be called any number of times.

Input
"""""

Inputs to the Lua script should be given by providing a list of parenthesized
pairs,
where the first and second field identify the name of the variable and the
value it is bound to, respectively.
The types of the values must have registered encoders (more below); the compiler
will warn you otherwise.

These variables are first encoded in-order, then provided as arguments
to the Lua function. In the example, note that ``c`` is passed in as a value
while ``a`` and ``b`` are passed in as pointers.

.. code-block:: c

   int a = 100, b = 200, c = 300;
   frrscript_call(fs, "on_foo", ("a", &a), ("b", &b), ("c", c));


.. code-block:: lua

   function on_foo(a, b, c)
     -- a is 100, b is 200, c is 300
     ...


Output
""""""

.. code-block:: c

   int a = 100, b = 200, c = 300;
   frrscript_call(fs, "on_foo", ("a", &a), ("b", &b), ("c", c));
   // a is 500, b is 200, c is 300

   int* d = frrscript_get_result(fs, "on_foo", "d", lua_tointegerp);
   // d is 800


.. code-block:: lua

   function on_foo(a, b, c)
     b = 600
     return { ["a"] = 500, ["c"] = 700, ["d"] = 800 }
   end


**Lua functions being called must return a single table of string names to
values.**
(Lua functions should return an empty table if there is no output.)
The keys of the table are mapped back to names of variables in C. Note that
the values in the table can also be tables. Since tables are Lua's primary
data structure, this design lets us return any Lua value.

After the Lua function returns, the names of variables  to ``frrscript_call()``
are matched against keys of the returned table, and then decoded. The types
being decoded must have registered decoders (more below); the compiler will
warn you otherwise.

In the example, since ``a`` was in the returned table and ``b`` was not,
``a`` was decoded and its value modified, while ``b`` was not decoded.
``c`` was decoded as well, but its decoder is a noop.
What modifications happen given a variable depends whether its name was
in the returned table and the decoder's implementation.

.. warning::
   Always keep in mind that non const-qualified pointers in
   ``frrscript_call()`` may be modified - this may be a source of bugs.
   On the other hand, const-qualified pointers and other values cannot
   be modified.


.. tip::
   You can make a copy of a data structure and pass that in instead,
   so that modifications only happen to that copy.

``frrscript_call()`` returns 0 if and only if the Lua function was successfully
called. A non-zero return could indicate either a missing Lua script, a missing
Lua function, or an error from the Lua interpreter.

In the above example, ``d`` was not an input to ``frrscript_call()``, so its
value must be explicitly retrieved with ``frrscript_get_result``.

``frrscript_get_result()`` takes a
decoder and string name which is used as a key to search the returned table.
Returns the pointer to the decoded value, or NULL if it was not found.
In the example, ``d`` is a "new" value in C space,
so memory allocation might take place. Hence the caller is
responsible for memory deallocation.

``frrscript_call()`` may be called multiple times without re-loading with
``frrscript_load()``. Results are not preserved between consecutive calls.

.. code-block:: c

   frrscript_load(fs, "on_foo");

   frrscript_call(fs, "on_foo");
   frrscript_get_result(fs, "on_foo", ...);
   frrscript_call(fs, "on_foo");
   frrscript_get_result(fs, "on_foo", ...);


Delete
^^^^^^

To delete a script and the all Lua states associated with it:

.. code-block:: c

   frrscript_delete(fs);


A complete example
""""""""""""""""""

So, a typical execution call, with error checking, looks something like this:

.. code-block:: c

   struct frrscript *fs = frrscript_new("my_script"); // name *without* .lua

   int ret = frrscript_load(fs, "on_foo", NULL);
   if (ret != 0)
       goto DONE; // Lua script or function might have not been found

   int a = 100, b = 200, c = 300;
   ret = frrscript_call(fs, "on_foo", ("a", &a), ("b", &b), ("c", c));
   if (ret != 0)
       goto DONE; // Lua function might have not successfully run

   // a and b might be modified
   assert(a == 500);
   assert(b == 200);

   // c could not have been modified
   assert(c == 300);

   // d is new
   int* d = frrscript_get_result(fs, "on_foo", "d", lua_tointegerp);

   if (!d)
       goto DONE; // "d" might not have been in returned table

   assert(*d == 800);
   XFREE(MTYPE_SCRIPT_RES, d); // caller responsible for free

   DONE:
   frrscript_delete(fs);


.. code-block:: lua

   function on_foo(a, b, c)
     b = 600
     return { a = 500, c = 700, d = 800 }
   end


Note that ``{ a = ...`` is same as ``{ ["a"] = ...``; it is Lua shorthand to
use the variable name as the key in a table.

Encoding and Decoding
^^^^^^^^^^^^^^^^^^^^^

Earlier sections glossed over the types of values that can be passed into
``frrscript_call()`` and how data is passed between C and Lua. Lua, as a
dynamically typed, garbage collected language, cannot directly use C values
without some kind of encoding / decoding system to
translate types between the two runtimes.

Lua communicates with C code using a stack. C code wishing to provide data to
Lua scripts must provide a function that encodes the C data into a Lua
representation and pushes it on the stack. C code wishing to retrieve data from
Lua must provide a corresponding decoder function that retrieves a Lua
value from the stack and converts it to the corresponding C type.

Encoders and decoders are provided for common data types.
Developers wishing to pass their own data structures between C and Lua need to
create encoders and decoders for that data type.

We try to keep them named consistently.
There are three kinds of encoders and decoders:

1. lua_push*: encodes a value onto the Lua stack.
   Required for ``frrscript_call``.

2. lua_decode*: decodes a value from the Lua stack.
   Required for ``frrscript_call``.
   Only non const-qualified pointers may be actually decoded (more below).

3. lua_to*: allocates memory and decodes a value from the Lua stack.
   Required for ``frrscript_get_result``.

This design allows us to combine typesafe *modification* of C values as well as
*allocation* of new C values.

In the following sections, we will use the encoders/decoders for ``struct prefix`` as an example.

Encoding
""""""""

An encoder function takes a ``lua_State *``, a C type and pushes that value onto
the Lua state (a stack).
For C structs, the usual case,
this will typically be encoded to a Lua table, then pushed onto the Lua stack.

Here is the encoder function for ``struct prefix``:

.. code-block:: c

   void lua_pushprefix(lua_State *L, struct prefix *prefix)
   {
           char buffer[PREFIX_STRLEN];

           lua_newtable(L);
           lua_pushstring(L, prefix2str(prefix, buffer, PREFIX_STRLEN));
           lua_setfield(L, -2, "network");
           lua_pushinteger(L, prefix->prefixlen);
           lua_setfield(L, -2, "length");
           lua_pushinteger(L, prefix->family);
           lua_setfield(L, -2, "family");
   }

This function pushes a single value, a table, onto the Lua stack, whose
equivalent in Lua is:

.. code-block:: c

   { ["network"] = "1.2.3.4/24", ["prefixlen"] = 24, ["family"] = 2 }


Decoding
""""""""

Decoders are a bit more involved. They do the reverse; a decoder function takes
a ``lua_State *``, pops a value off the Lua stack and converts it back into its
C type.

There are two: ``lua_decode*`` and ``lua_to*``. The former does no mememory
allocation and is needed for ``frrscript_call``.
The latter performs allocation and is optional.

A ``lua_decode_*`` function takes a ``lua_State*``, an index, and a pointer
to a C data structure, and directly modifies the structure with values from the
Lua stack. Note that only non const-qualified pointers may be modified;
``lua_decode_*`` for other types will be noops.

Again, for ``struct prefix *``:

.. code-block:: c

   void lua_decode_prefix(lua_State *L, int idx, struct prefix *prefix)
   {
        lua_getfield(L, idx, "network");
        (void)str2prefix(lua_tostring(L, -1), prefix);
        /* pop the network string */
        lua_pop(L, 1);
        /* pop the prefix table */
        lua_pop(L, 1);
   }


Note:
 - Before ``lua_decode*`` is run, the "prefix" table is already on the top of
   the stack. ``frrscript_call`` does this for us.
 - However, at the end of ``lua_decode*``, the "prefix" table should be popped.
 - The other two fields in the "network" table are disregarded, meaning that any
   modification to them is discarded in C space. In this case, this is desired
   behavior.

.. warning::

   ``lua_decode*`` functions should pop all values that ``lua_to*`` pushed onto
   the Lua stack.
   For encoders that pushed a table, its decoder should pop the table at the end.
   The above is an example.



``int`` is not a non const-qualified pointer, so for ``int``:

.. code-block:: c

   void lua_decode_int_noop(lua_State *L, int idx, int i)
   { //noop
   }


A ``lua_to*`` function provides identical functionality except that it first
allocates memory for the new C type before decoding the value from the Lua stack,
then returns a pointer to the newly allocated C type. You only need to implement
this function to use with ``frrscript_get_result`` to retrieve a result of
this type.

This function can and should be implemented using ``lua_decode_*``:

.. code-block:: c

   void *lua_toprefix(lua_State *L, int idx)
   {
           struct prefix *p = XCALLOC(MTYPE_SCRIPT_RES, sizeof(struct prefix));

           lua_decode_prefix(L, idx, p);
           return p;
   }


The returned data must always be copied off the stack and the copy must be
allocated with ``MTYPE_SCRIPT_RES``. This way it is possible to unload the script
(destroy the state) without invalidating any references to values stored in it.
Note that it is the caller's responsibility to free the data.


Registering encoders and decoders for frrscript_call
""""""""""""""""""""""""""""""""""""""""""""""""""""

To register a new type with its ``lua_push*`` and ``lua_decode*`` functions,
add the mapping in the following macros in ``frrscript.h``:

.. code-block:: diff

     #define ENCODE_ARGS_WITH_STATE(L, value) \
          _Generic((value), \
          ...
   - struct peer * : lua_pushpeer \
   + struct peer * : lua_pushpeer, \
   + struct prefix * : lua_pushprefix \
     )((L), (value))

     #define DECODE_ARGS_WITH_STATE(L, value) \
          _Generic((value), \
          ...
   - struct peer * : lua_decode_peer \
   + struct peer * : lua_decode_peer, \
   + struct prefix * : lua_decode_prefix \
     )((L), -1, (value))


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

   Encodable/decodable types are not restricted to simple values like integers,
   strings and tables.
   It is possible to encode a type such that the resultant object in Lua
   is an actual object-oriented object, complete with methods that call
   back into defined C functions. See the Lua manual for how to do this;
   for a code example, look at how zlog is exported into the script environment.


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
script with a function named ``route_match``,
provides route prefix and attributes received from a peer and expects the
function to return a match / no match / match and update result.

An example script to use with this follows. This function matches, does not match
or updates a route depending on how many BGP UPDATE messages the peer has
received when the script is called, simply as a demonstration of what can be
accomplished with scripting.

.. code-block:: lua


   -- Example route map matching
   -- author: qlyoung
   --
   -- The following variables are available in the global environment:
   --   log
   --     logging library, with the usual functions
   --
   -- route_match arguments:
   --   table prefix
   --     the route under consideration
   --   table attributes
   --     the route's attributes
   --   table peer
   --     the peer which received this route
   --   integer RM_FAILURE
   --     status code in case of failure
   --   integer RM_NOMATCH
   --     status code for no match
   --   integer RM_MATCH
   --     status code for match
   --   integer RM_MATCH_AND_CHANGE
   --     status code for match-and-set
   --
   -- route_match returns table with following keys:
   --   integer action, required
   --     resultant status code. Should be one of RM_*
   --   table attributes, optional
   --     updated route attributes
   --

   function route_match(prefix, attributes, peer,
           RM_FAILURE, RM_NOMATCH, RM_MATCH, RM_MATCH_AND_CHANGE)

           log.info("Evaluating route " .. prefix.network .. " from peer " .. peer.remote_id.string)
   
           function on_match (prefix, attributes)
                   log.info("Match")
                   return {
                           attributes = RM_MATCH
                   }
           end
   
           function on_nomatch (prefix, attributes)
                   log.info("No match")
                   return {
                           action = RM_NOMATCH
                   }
           end

           function on_match_and_change (prefix, attributes)
                   log.info("Match and change")
                   attributes["metric"] = attributes["metric"] + 7
                   return {
                           action = RM_MATCH_AND_CHANGE,
                           attributes = attributes
                   }
           end

           special_routes = {
                   ["172.16.10.4/24"] = on_match,
                   ["172.16.13.1/8"] = on_nomatch,
                   ["192.168.0.24/8"] = on_match_and_change,
           }


           if special_routes[prefix.network] then
                   return special_routes[prefix.network](prefix, attributes)
           elseif peer.stats.update_in % 3 == 0 then
                   return on_match(prefix, attributes)
           elseif peer.stats.update_in % 2 == 0 then
                   return on_nomatch(prefix, attributes)
           else
                   return on_match_and_change(prefix, attributes)
           end
    end
