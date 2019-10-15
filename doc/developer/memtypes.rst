.. highlight:: c

Memtypes
========

FRR includes wrappers around ``malloc()`` and ``free()`` that count the number
of objects currently allocated, for each of a defined ``MTYPE``.

To this extent, there are *memory groups* and *memory types*.  Each memory
type must belong to a memory group, this is used just to provide some basic
structure.

Example:

.. code-block:: c
   :caption: mydaemon.h

   DECLARE_MGROUP(MYDAEMON)
   DECLARE_MTYPE(MYNEIGHBOR)

.. code-block:: c
   :caption: mydaemon.c

   DEFINE_MGROUP(      MYDAEMON, "My daemon's memory")
   DEFINE_MTYPE(       MYDAEMON, MYNEIGHBOR,     "Neighbor entry")
   DEFINE_MTYPE_STATIC(MYDAEMON, MYNEIGHBORNAME, "Neighbor name")

   struct neigh *neighbor_new(const char *name)
   {
           struct neigh *n = XMALLOC(MYNEIGHBOR, sizeof(*n));
           n->name = XSTRDUP(MYNEIGHBORNAME, name);
           return n;
   }

   void neighbor_free(struct neigh *n)
   {
           XFREE(MYNEIGHBORNAME, n->name);
           XFREE(MYNEIGHBOR, n);
   }


Definition
----------

.. c:type:: struct memtype

   This is the (internal) type used for MTYPE definitions.  The macros below
   should be used to create these, but in some cases it is useful to pass a
   ``struct memtype *`` pointer to some helper function.

   The ``MTYPE_name`` created by the macros is declared as a pointer, i.e.
   a function taking a ``struct memtype *`` argument can be called with an
   ``MTYPE_name`` argument (as opposed to ``&MTYPE_name``.)

   .. note::

      As ``MTYPE_name`` is a variable assigned from ``&_mt_name`` and not a
      constant expression, it cannot be used as initializer for static
      variables. In the case please fall back to ``&_mt_name``.

.. c:macro:: DECLARE_MGROUP(name)

   This macro forward-declares a memory group and should be placed in a
   ``.h`` file.  It expands to an ``extern struct memgroup`` statement.

.. c:macro:: DEFINE_MGROUP(mname, description)

   Defines/implements a memory group.  Must be placed into exactly one ``.c``
   file (multiple inclusion will result in a link-time symbol conflict).

   Contains additional logic (constructor and destructor) to register the
   memory group in a global list.

.. c:macro:: DECLARE_MTYPE(name)

   Forward-declares a memory type and makes ``MTYPE_name`` available for use.
   Note that the ``MTYPE_`` prefix must not be included in the name, it is
   automatically prefixed.

   ``MTYPE_name`` is created as a `static const` symbol, i.e. a compile-time
   constant.  It refers to an ``extern struct memtype _mt_name``, where `name`
   is replaced with the actual name.

.. c:macro:: DEFINE_MTYPE(group, name, description)

   Define/implement a memory type, must be placed into exactly one ``.c``
   file (multiple inclusion will result in a link-time symbol conflict).

   Like ``DEFINE_MGROUP``, this contains actual code to register the MTYPE
   under its group.

.. c:macro:: DEFINE_MTYPE_STATIC(group, name, description)

   Same as ``DEFINE_MTYPE``, but the ``DEFINE_MTYPE_STATIC`` variant places
   the C ``static`` keyword on the definition, restricting the MTYPE's
   availability to the current source file.  This should be appropriate in
   >80% of cases.

   .. todo::

      Daemons currently have ``daemon_memory.[ch]`` files listing all of
      their MTYPEs.  This is not how it should be, most of these types
      should be moved into the appropriate files where they are used.
      Only a few MTYPEs should remain non-static after that.


Usage
-----

.. c:function:: void *XMALLOC(struct memtype *mtype, size_t size)

.. c:function:: void *XCALLOC(struct memtype *mtype, size_t size)

.. c:function:: void *XSTRDUP(struct memtype *mtype, const char *name)

   Allocation wrappers for malloc/calloc/realloc/strdup, taking an extra
   mtype parameter.

.. c:function:: void *XREALLOC(struct memtype *mtype, void *ptr, size_t size)

   Wrapper around realloc() with MTYPE tracking.  Note that ``ptr`` may
   be NULL, in which case the function does the same as XMALLOC (regardless
   of whether the system realloc() supports this.)

.. c:function:: void XFREE(struct memtype *mtype, void *ptr)

   Wrapper around free(), again taking an extra mtype parameter.  This is
   actually a macro, with the following additional properties:

   - the macro contains ``ptr = NULL``
   - if ptr is NULL, no operation is performed (as is guaranteed by system
     implementations.)  Do not surround XFREE with ``if (ptr != NULL)``
     checks.
