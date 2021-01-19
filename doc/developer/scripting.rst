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

   struct frrscript_env env[] = {
           {"integer", "STATUS_FAIL", &status_fail},
           {"integer", "STATUS_OK", &status_ok},
           {"prefix", "myprefix", &p},
           {}};

   int result = frrscript_call(fs, env);


To execute a loaded script, we need to define the inputs. These inputs are
passed by binding values to variable names that will be accessible within the
Lua environment. Basically, all communication with the script takes place via
global variables within the script, and to provide inputs we predefine globals
before the script runs. This is done by passing ``frrscript_call()`` an array
of ``struct frrscript_env``. Each struct has three fields. The first identifies
the type of the value being passed; more on this later. The second defines the
name of the global variable within the script environment to bind the third
argument (the value) to.

The script is then executed and returns a general status code. In the success
case this will be 0, otherwise it will be nonzero. The script itself does not
determine this code, it is provided by the Lua interpreter.


Querying State
^^^^^^^^^^^^^^

When a chunk is executed, its state at exit is preserved and can be inspected.

After running a script, results may be retrieved by querying the script's
state. Again this is done by retrieving the values of global variables, which
are known to the script author to be "output" variables.

A result is retrieved like so:

.. code-block:: c

   struct frrscript_env myresult = {"string", "myresult"};

   char *myresult = frrscript_get_result(fs, &myresult);

   ... do something ...

   XFREE(MTYPE_TMP, myresult);


As with arguments, results are retrieved by providing a ``struct
frrscript_env`` specifying a type and a global name. No value is necessary, nor
is it modified by ``frrscript_get_result()``. That function simply extracts the
requested value from the script state and returns it.

In most cases the returned value will be allocated with ``MTYPE_TMP`` and will
need to be freed after use.


Unloading
^^^^^^^^^

To destroy a script and its associated state:

.. code-block:: c

   frrscript_unload(fs);

Values returned by ``frrscript_get_result`` are still valid after the script
they were retrieved from is unloaded.

Note that you must unload and then load the script if you want to reset its
state, for example to run it again with different inputs. Otherwise the state
from the previous run carries over into subsequent runs.


.. _marshalling:

Marshalling
^^^^^^^^^^^

Earlier sections glossed over the meaning of the type name field in ``struct
frrscript_env`` and how data is passed between C and Lua. Lua, as a dynamically
typed, garbage collected language, cannot directly use C values without some
kind of marshalling / unmarshalling system to translate types between the two
runtimes.

Lua communicates with C code using a stack. C code wishing to provide data to
Lua scripts must provide a function that marshalls the C data into a Lua
representation and pushes it on the stack. C code wishing to retrieve data from
Lua must provide a corresponding unmarshalling function that retrieves a Lua
value from the stack and converts it to the corresponding C type. These two
functions, together with a chosen name of the type they operate on, are
referred to as ``codecs`` in FRR.

A codec is defined as:

.. code-block:: c

   typedef void (*encoder_func)(lua_State *, const void *);
   typedef void *(*decoder_func)(lua_State *, int);

   struct frrscript_codec {
           const char *typename;
           encoder_func encoder;
           decoder_func decoder;
   };

A typename string and two function pointers.

``typename`` can be anything you want. For example, for the combined types of
``struct prefix`` and its equivalent in Lua I have chosen the name ``prefix``.
There is no restriction on naming here, it is just a human name used as a key
and specified when passing and retrieving values.

``encoder`` is a function that takes a ``lua_State *`` and a C type and pushes
onto the Lua stack a value representing the C type. For C structs, the usual
case, this will typically be a Lua table (tables are the only datastructure Lua
has). For example, here is the encoder function for ``struct prefix``:


.. code-block:: c

   void lua_pushprefix(lua_State *L, const struct prefix *prefix)
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

This function pushes a single value onto the Lua stack. It is a table whose equivalent in Lua is:

.. code-block::

   { ["network"] = "1.2.3.4/24", ["prefixlen"] = 24, ["family"] = 2 }


``decoder`` does the reverse; it takes a ``lua_State *`` and an index into the
stack, and unmarshalls a Lua value there into the corresponding C type. Again
for ``struct prefix``:


.. code-block:: c

   void *lua_toprefix(lua_State *L, int idx)
   {
           struct prefix *p = XCALLOC(MTYPE_TMP, sizeof(struct prefix));

           lua_getfield(L, idx, "network");
           str2prefix(lua_tostring(L, -1), p);
           lua_pop(L, 1);

           return p;
   }

By convention these functions should be called ``lua_to*``, as this is the
naming convention used by the Lua C library for the basic types e.g.
``lua_tointeger`` and ``lua_tostring``.

The returned data must always be copied off the stack and the copy must be
allocated with ``MTYPE_TMP``. This way it is possible to unload the script
(destroy the state) without invalidating any references to values stored in it.

To register a new type with its corresponding encoding functions:

.. code-block:: c

   struct frrscript_codec frrscript_codecs_lib[] = {    
             {.typename = "prefix",    
              .encoder = (encoder_func)lua_pushprefix,    
              .decoder = lua_toprefix},    
             {.typename = "sockunion",    
              .encoder = (encoder_func)lua_pushsockunion,    
              .decoder = lua_tosockunion},    
              ...
              {}};

   frrscript_register_type_codecs(frrscript_codecs_lib);

From this point on the type names are available to be used when calling any
script and getting its results.

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

