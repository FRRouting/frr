.. _lists:

Type-safe containers
====================

.. note::

   This section previously used the term *list*; it was changed to *container*
   to be more clear.

Common container interface
--------------------------

FRR includes a set of container implementations with abstracted
common APIs.  The purpose of this is easily allow swapping out one
data structure for another while also making the code easier to read and write.
There is one API for unsorted containers and a similar but not identical API
for sorted containers - and heaps use a middle ground of both.

For unsorted containers, the following implementations exist:

- single-linked list with tail pointer (e.g. STAILQ in BSD)

- double-linked list

- atomic single-linked list with tail pointer


Being partially sorted, the oddball structure:

- an 8-ary heap


For sorted containers, these data structures are implemented:

- single-linked list

- atomic single-linked list

- skiplist

- red-black tree (based on OpenBSD RB_TREE)

- hash table (note below)

Except for hash tables, each of the sorted data structures has a variant with
unique and non-unique items.  Hash tables always require unique items
and mostly follow the "sorted" API but use the hash value as sorting
key.  Also, iterating while modifying does not work with hash tables.
Conversely, the heap always has non-unique items, but iterating while modifying
doesn't work either.


The following sorted structures are likely to be implemented at some point
in the future:

- atomic skiplist

- atomic hash table (note below)


The APIs are all designed to be as type-safe as possible.  This means that
there will be a compiler warning when an item doesn't match the container, or
the return value has a different type, or other similar situations.  **You
should never use casts with these APIs.**  If a cast is necessary in relation
to these APIs, there is probably something wrong with the overall design.

Only the following pieces use dynamically allocated memory:

- the hash table itself is dynamically grown and shrunk

- skiplists store up to 4 next pointers inline but will dynamically allocate
  memory to hold an item's 5th up to 16th next pointer (if they exist)

- the heap uses a dynamically grown and shrunk array of items

Cheat sheet
-----------

Available types:

::

   DECLARE_LIST
   DECLARE_ATOMLIST
   DECLARE_DLIST

   DECLARE_HEAP

   DECLARE_SORTLIST_UNIQ
   DECLARE_SORTLIST_NONUNIQ
   DECLARE_ATOMLIST_UNIQ
   DECLARE_ATOMLIST_NONUNIQ
   DECLARE_SKIPLIST_UNIQ
   DECLARE_SKIPLIST_NONUNIQ
   DECLARE_RBTREE_UNIQ
   DECLARE_RBTREE_NONUNIQ

   DECLARE_HASH

Functions provided:

+------------------------------------+-------+------+------+---------+------------+
| Function                           | LIST  | HEAP | HASH | \*_UNIQ | \*_NONUNIQ |
+====================================+=======+======+======+=========+============+
| _init, _fini                       | yes   | yes  | yes  | yes     | yes        |
+------------------------------------+-------+------+------+---------+------------+
| _first, _next, _next_safe,         | yes   | yes  | yes  | yes     | yes        |
|                                    |       |      |      |         |            |
| _const_first, _const_next          |       |      |      |         |            |
+------------------------------------+-------+------+------+---------+------------+
| _last, _prev, _prev_safe,          | DLIST | --   | --   | RB only | RB only    |
|                                    | only  |      |      |         |            |
| _const_last, _const_prev           |       |      |      |         |            |
+------------------------------------+-------+------+------+---------+------------+
| _swap_all                          | yes   | yes  | yes  | yes     | yes        |
+------------------------------------+-------+------+------+---------+------------+
| _anywhere                          | yes   | --   | --   | --      | --         |
+------------------------------------+-------+------+------+---------+------------+
| _add_head, _add_tail, _add_after   | yes   | --   | --   | --      | --         |
+------------------------------------+-------+------+------+---------+------------+
| _add                               | --    | yes  | yes  | yes     | yes        |
+------------------------------------+-------+------+------+---------+------------+
| _member                            | yes   | yes  | yes  | yes     | yes        |
+------------------------------------+-------+------+------+---------+------------+
| _del, _pop                         | yes   | yes  | yes  | yes     | yes        |
+------------------------------------+-------+------+------+---------+------------+
| _find, _const_find                 | --    | --   | yes  | yes     | --         |
+------------------------------------+-------+------+------+---------+------------+
| _find_lt, _find_gteq,              | --    | --   | --   | yes     | yes        |
|                                    |       |      |      |         |            |
| _const_find_lt, _const_find_gteq   |       |      |      |         |            |
+------------------------------------+-------+------+------+---------+------------+
| use with frr_each() macros         | yes   | yes  | yes  | yes     | yes        |
+------------------------------------+-------+------+------+---------+------------+



Datastructure type setup
------------------------

Each of the data structures has a ``PREDECL_*`` and a ``DECLARE_*`` macro to
set up an "instantiation" of the container.  This works somewhat similar to C++
templating, though much simpler.

**In all following text, the Z prefix is replaced with a name chosen
for the instance of the datastructure.**

The common setup pattern will look like this:

.. code-block:: c

   #include <typesafe.h>

   PREDECL_XXX(Z);
   struct item {
       int otherdata;
       struct Z_item mylistitem;
   }

   struct Z_head mylisthead;

   /* unsorted: */
   DECLARE_XXX(Z, struct item, mylistitem);

   /* sorted, items that compare as equal cannot be added to list */
   int compare_func(const struct item *a, const struct item *b);
   DECLARE_XXX_UNIQ(Z, struct item, mylistitem, compare_func);

   /* sorted, items that compare as equal can be added to list */
   int compare_func(const struct item *a, const struct item *b);
   DECLARE_XXX_NONUNIQ(Z, struct item, mylistitem, compare_func);

   /* hash tables: */
   int compare_func(const struct item *a, const struct item *b);
   uint32_t hash_func(const struct item *a);
   DECLARE_XXX(Z, struct item, mylistitem, compare_func, hash_func);

``XXX`` is replaced with the name of the data structure, e.g. ``SKIPLIST``
or ``ATOMLIST``.  The ``DECLARE_XXX`` invocation can either occur in a `.h`
file (if the container needs to be accessed from several C files) or it can be
placed in a `.c` file (if the container is only accessed from that file.)  The
``PREDECL_XXX`` invocation defines the ``struct Z_item`` and ``struct
Z_head`` types and must therefore occur before these are used.

To switch between compatible data structures, only these two lines need to be
changes.  To switch to a data structure with a different API, some source
changes are necessary.

Common iteration macros
-----------------------

The following iteration macros work across all data structures:

.. c:macro:: frr_each(Z, head, item)

   Equivalent to:

   .. code-block:: c

      for (item = Z_first(&head); item; item = Z_next(&head, item))

   Note that this will fail if the container is modified while being iterated
   over.

.. c:macro:: frr_each_safe(Z, head, item)

   Same as the previous, but the next element is pre-loaded into a "hidden"
   variable (named ``Z_safe``.)  Equivalent to:

   .. code-block:: c

      for (item = Z_first(&head); item; item = next) {
          next = Z_next_safe(&head, item);
          ...
      }

   .. warning::

      Iterating over hash tables while adding or removing items is not
      possible.  The iteration position will be corrupted when the hash
      tables is resized while iterating.  This will cause items to be
      skipped or iterated over twice.

.. c:macro:: frr_each_from(Z, head, item, from)

   Iterates over the container, starting at item ``from``.  This variant is
   "safe" as in the previous macro.  Equivalent to:

   .. code-block:: c

      for (item = from; item; item = from) {
          from = Z_next_safe(&head, item);
          ...
      }

   .. note::

      The ``from`` variable is written to.  This is intentional - you can
      resume iteration after breaking out of the loop by keeping the ``from``
      value persistent and reusing it for the next loop.

.. c:macro:: frr_rev_each(Z, head, item)
.. c:macro:: frr_rev_each_safe(Z, head, item)
.. c:macro:: frr_rev_each_from(Z, head, item, from)

   Reverse direction variants of the above.  Only supported on containers that
   implement ``_last`` and ``_prev`` (i.e. ``RBTREE`` and ``DLIST``).

To iterate over ``const`` pointers, add ``_const`` to the name of the
datastructure (``Z`` above), e.g. ``frr_each (mylist, head, item)`` becomes
``frr_each (mylist_const, head, item)``.

Common API
----------

The following documentation assumes that a container has been defined using
``Z`` as the name, and ``itemtype`` being the type of the items (e.g.
``struct item``.)

.. c:function:: void Z_init(struct Z_head *)

   Initializes the container for use.  For most implementations, this just sets
   some values.  Hash tables are the only implementation that allocates
   memory in this call.

.. c:function:: void Z_fini(struct Z_head *)

   Reverse the effects of :c:func:`Z_init()`.  The container must be empty
   when this function is called.

   .. warning::

      This function may ``assert()`` if the container is not empty.

.. c:function:: size_t Z_count(const struct Z_head *)

   Returns the number of items in a structure.  All structures store a
   counter in their `Z_head` so that calling this function completes
   in O(1).

   .. note::

      For atomic containers with concurrent access, the value will already be
      outdated by the time this function returns and can therefore only be
      used as an estimate.

.. c:function:: bool Z_member(const struct Z_head *, const itemtype *)

   Determines whether some item is a member of the given container.  The
   item must either be valid on some container, or set to all zeroes.

   On some containers, if no faster way to determine membership is possible,
   this is simply ``item == Z_find(head, item)``.

   Not currently available for atomic containers.

.. c:function:: const itemtype *Z_const_first(const struct Z_head *)
.. c:function:: itemtype *Z_first(struct Z_head *)

   Returns the first item in the structure, or ``NULL`` if the structure is
   empty.  This is O(1) for all data structures except red-black trees
   where it is O(log n).

.. c:function:: const itemtype *Z_const_last(const struct Z_head *)
.. c:function:: itemtype *Z_last(struct Z_head *)

   Last item in the structure, or ``NULL``.  Only available on containers
   that support reverse iteration (i.e. ``RBTREE`` and ``DLIST``).

.. c:function:: itemtype *Z_pop(struct Z_head *)

   Remove and return the first item in the structure, or ``NULL`` if the
   structure is empty.  Like :c:func:`Z_first`, this is O(1) for all
   data structures except red-black trees where it is O(log n) again.

   This function can be used to build queues (with unsorted structures) or
   priority queues (with sorted structures.)

   Another common pattern is deleting all container items:

   .. code-block:: c

      while ((item = Z_pop(head)))
          item_free(item);

   .. note::

      This function can - and should - be used with hash tables.  It is not
      affected by the "modification while iterating" problem.  To remove
      all items from a hash table, use the loop demonstrated above.

.. c:function:: const itemtype *Z_const_next(const struct Z_head *, const itemtype *prev)
.. c:function:: itemtype *Z_next(struct Z_head *, itemtype *prev)

   Return the item that follows after ``prev``, or ``NULL`` if ``prev`` is
   the last item.

   .. warning::

      ``prev`` must not be ``NULL``!  Use :c:func:`Z_next_safe()` if
      ``prev`` might be ``NULL``.

.. c:function:: itemtype *Z_next_safe(struct Z_head *, itemtype *prev)

   Same as :c:func:`Z_next()`, except that ``NULL`` is returned if
   ``prev`` is ``NULL``.

.. c:function:: const itemtype *Z_const_prev(const struct Z_head *, const itemtype *next)
.. c:function:: itemtype *Z_prev(struct Z_head *, itemtype *next)
.. c:function:: itemtype *Z_prev_safe(struct Z_head *, itemtype *next)

   As above, but preceding item.  Only available on structures that support
   reverse iteration (i.e. ``RBTREE`` and ``DLIST``).

.. c:function:: itemtype *Z_del(struct Z_head *, itemtype *item)

   Remove ``item`` from the container and return it.

   .. note::

      This function's behaviour is undefined if ``item`` is not actually
      on the container.  Some structures return ``NULL`` in this case while
      others return ``item``.  The function may also call ``assert()`` (but
      most don't.)

.. c:function:: itemtype *Z_swap_all(struct Z_head *, struct Z_head *)

   Swap the contents of 2 containers (of identical type).  This exchanges the
   contents of the two head structures and updates pointers if necessary for
   the particular data structure.  Fast for all structures.

   (Not currently available on atomic containers.)

.. todo::

   ``Z_del_after()`` / ``Z_del_hint()``?

API for unsorted structures
---------------------------

Since the insertion position is not pre-defined for unsorted data, there
are several functions exposed to insert data:

.. note::

   ``item`` must not be ``NULL`` for any of the following functions.

.. c:macro:: DECLARE_XXX(Z, type, field)

   :param listtype XXX: ``LIST``, ``DLIST`` or ``ATOMLIST`` to select a data
      structure implementation.
   :param token Z: Gives the name prefix that is used for the functions
      created for this instantiation.  ``DECLARE_XXX(foo, ...)``
      gives ``struct foo_item``, ``foo_add_head()``, ``foo_count()``, etc.  Note
      that this must match the value given in ``PREDECL_XXX(foo)``.
   :param typename type: Specifies the data type of the list items, e.g.
      ``struct item``.  Note that ``struct`` must be added here, it is not
      automatically added.
   :param token field: References a struct member of ``type`` that must be
      typed as ``struct foo_item``.  This struct member is used to
      store "next" pointers or other data structure specific data.

.. c:function:: void Z_add_head(struct Z_head *, itemtype *item)

   Insert an item at the beginning of the structure, before the first item.
   This is an O(1) operation for non-atomic lists.

.. c:function:: void Z_add_tail(struct Z_head *, itemtype *item)

   Insert an item at the end of the structure, after the last item.
   This is also an O(1) operation for non-atomic lists.

.. c:function:: void Z_add_after(struct Z_head *, itemtype *after, itemtype *item)

   Insert ``item`` behind ``after``. If ``after`` is ``NULL``, the item is
   inserted at the beginning of the list as with :c:func:`Z_add_head`.
   This is also an O(1) operation for non-atomic lists.

   A common pattern is to keep a "previous" pointer around while iterating:

   .. code-block:: c

      itemtype *prev = NULL, *item;

      frr_each_safe(Z, head, item) {
          if (something) {
              Z_add_after(head, prev, item);
              break;
          }
          prev = item;
      }

   .. todo::

      maybe flip the order of ``item`` & ``after``?
      ``Z_add_after(head, item, after)``

.. c:function:: bool Z_anywhere(const itemtype *)

   Returns whether an item is a member of *any* container of this type.
   The item must either be valid on some container, or set to all zeroes.

   Guaranteed to be fast (pointer compare or similar.)

   Not currently available for sorted and atomic containers.  Might be added
   for sorted containers at some point (when needed.)


API for sorted structures
-------------------------

Sorted data structures do not need to have an insertion position specified,
therefore the insertion calls are different from unsorted containers.  Also,
sorted containers can be searched for a value.

.. c:macro:: DECLARE_XXX_UNIQ(Z, type, field, compare_func)

   :param listtype XXX: One of the following:
       ``SORTLIST`` (single-linked sorted list), ``SKIPLIST`` (skiplist),
       ``RBTREE`` (RB-tree) or ``ATOMSORT`` (atomic single-linked list).
   :param token Z: Gives the name prefix that is used for the functions
      created for this instantiation.  ``DECLARE_XXX(foo, ...)``
      gives ``struct foo_item``, ``foo_add()``, ``foo_count()``, etc.  Note
      that this must match the value given in ``PREDECL_XXX(foo)``.
   :param typename type: Specifies the data type of the items, e.g.
      ``struct item``.  Note that ``struct`` must be added here, it is not
      automatically added.
   :param token field: References a struct member of ``type`` that must be
      typed as ``struct foo_item``.  This struct member is used to
      store "next" pointers or other data structure specific data.
   :param funcptr compare_func: Item comparison function, must have the
      following function signature:
      ``int function(const itemtype *, const itemtype*)``.  This function
      may be static if the container is only used in one file.

.. c:macro:: DECLARE_XXX_NONUNIQ(Z, type, field, compare_func)

   Same as above, but allow adding multiple items to the container that compare
   as equal in ``compare_func``.  Ordering between these items is undefined
   and depends on the container implementation.

.. c:function:: itemtype *Z_add(struct Z_head *, itemtype *item)

   Insert an item at the appropriate sorted position.  If another item exists
   in the container that compares as equal (``compare_func()`` == 0), ``item``
   is not inserted and the already-existing item in the container is
   returned.  Otherwise, on successful insertion, ``NULL`` is returned.

   For ``_NONUNIQ`` containers, this function always returns NULL since
   ``item`` can always be successfully added to the container.

.. c:function:: const itemtype *Z_const_find(const struct Z_head *, const itemtype *ref)
.. c:function:: itemtype *Z_find(struct Z_head *, const itemtype *ref)

   Search the container for an item that compares equal to ``ref``.  If no
   equal item is found, return ``NULL``.

   This function is likely used with a temporary stack-allocated value for
   ``ref`` like so:

   .. code-block:: c

      itemtype searchfor = { .foo = 123 };

      itemtype *item = Z_find(head, &searchfor);

   .. note::

      The ``Z_find()`` function is only available for containers that contain
      unique items (i.e. ``DECLARE_XXX_UNIQ``.)  This is because on a container
      with non-unique items, more than one item may compare as equal to
      the item that is searched for.

.. c:function:: const itemtype *Z_const_find_gteq(const struct Z_head *, const itemtype *ref)
.. c:function:: itemtype *Z_find_gteq(struct Z_head *, const itemtype *ref)

   Search the container for an item that compares greater or equal to
   ``ref``.  See :c:func:`Z_find()` above.

.. c:function:: const itemtype *Z_const_find_lt(const struct Z_head *, const itemtype *ref)
.. c:function:: itemtype *Z_find_lt(struct Z_head *, const itemtype *ref)

   Search the container for an item that compares less than
   ``ref``.  See :c:func:`Z_find()` above.


API for hash tables
-------------------

.. c:macro:: DECLARE_HASH(Z, type, field, compare_func, hash_func)

   :param listtype HASH: Only ``HASH`` is currently available.
   :param token Z: Gives the name prefix that is used for the functions
      created for this instantiation.  ``DECLARE_XXX(foo, ...)``
      gives ``struct foo_item``, ``foo_add()``, ``foo_count()``, etc.  Note
      that this must match the value given in ``PREDECL_XXX(foo)``.
   :param typename type: Specifies the data type of the items, e.g.
      ``struct item``.  Note that ``struct`` must be added here, it is not
      automatically added.
   :param token field: References a struct member of ``type`` that must be
      typed as ``struct foo_item``.  This struct member is used to
      store "next" pointers or other data structure specific data.
   :param funcptr compare_func: Item comparison function, must have the
      following function signature:
      ``int function(const itemtype *, const itemtype*)``.  This function
      may be static if the container is only used in one file.  For hash tables,
      this function is only used to check for equality, the ordering is
      ignored.
   :param funcptr hash_func: Hash calculation function, must have the
      following function signature:
      ``uint32_t function(const itemtype *)``.  The hash value for items
      stored in a hash table is cached in each item, so this value need not
      be cached by the user code.

   .. warning::

      Items that compare as equal cannot be inserted.  Refer to the notes
      about sorted structures in the previous section.


.. c:function:: void Z_init_size(struct Z_head *, size_t size)

   Same as :c:func:`Z_init()` but preset the minimum hash table to
   ``size``.

Hash tables also support :c:func:`Z_add()` and :c:func:`Z_find()` with
the same semantics as noted above. :c:func:`Z_find_gteq()` and
:c:func:`Z_find_lt()` are **not** provided for hash tables.

Hash table invariants
^^^^^^^^^^^^^^^^^^^^^

There are several ways to injure yourself using the hash table API.

First, note that there are two functions related to computing uniqueness of
objects inserted into the hash table. There is a hash function and a comparison
function. The hash function computes the hash of the object. Our hash table
implementation uses `chaining
<https://en.wikipedia.org/wiki/Hash_table#Separate_chaining_with_linked_lists>`_.
This means that your hash function does not have to be perfect; multiple
objects having the same computed hash will be placed into a linked list
corresponding to that key. The closer to perfect the hash function, the better
performance, as items will be more evenly distributed and the chain length will
not be long on any given lookup, minimizing the number of list operations
required to find the correct item. However, the comparison function *must* be
perfect, in the sense that any two unique items inserted into the hash table
must compare not equal. At insertion time, if you try to insert an item that
compares equal to an existing item the insertion will not happen and
``hash_get()`` will return the existing item. However, this invariant *must* be
maintained while the object is in the hash table. Suppose you insert items
``A`` and ``B`` into the hash table which both hash to the same value ``1234``
but do not compare equal. They will be placed in a chain like so::

   1234 : A -> B

Now suppose you do something like this elsewhere in the code::

   *A = *B

I.e. you copy all fields of ``B`` into ``A``, such that the comparison function
now says that they are equal based on their contents. At this point when you
look up ``B`` in the hash table, ``hash_get()`` will search the chain for the
first item that compares equal to ``B``, which will be ``A``. This leads to
insidious bugs.

.. warning::

   Never modify the values looked at by the comparison or hash functions after
   inserting an item into a hash table.

A similar situation can occur with the hash allocation function. ``hash_get()``
accepts a function pointer that it will call to get the item that should be
inserted into the list if the provided item is not already present. There is a
builtin function, ``hash_alloc_intern``, that will simply return the item you
provided; if you always want to store the value you pass to ``hash_get`` you
should use this one. If you choose to provide a different one, that function
*must* return a new item that hashes and compares equal to the one you provided
to ``hash_get()``. If it does not the behavior of the hash table is undefined.

.. warning::

   Always make sure your hash allocation function returns a value that hashes
   and compares equal to the item you provided to ``hash_get()``.

Finally, if you maintain pointers to items you have inserted into a hash table,
then before deallocating them you must release them from the hash table. This
is basic memory management but worth repeating as bugs have arisen from failure
to do this.


API for heaps
-------------

Heaps provide the same API as the sorted data structures, except:

* none of the find functions (:c:func:`Z_find()`, :c:func:`Z_find_gteq()`
  or :c:func:`Z_find_lt()`) are available.
* iterating over the heap yields the items in semi-random order, only the
  first item is guaranteed to be in order and actually the "lowest" item
  on the heap.  Being a heap, only the rebalancing performed on removing the
  first item (either through :c:func:`Z_pop()` or :c:func:`Z_del()`) causes
  the new lowest item to bubble up to the front.
* all heap modifications are O(log n).  However, cacheline efficiency and
  latency is likely quite a bit better than with other data structures.

Atomic lists
------------

`atomlist.h` provides an unsorted and a sorted atomic single-linked list.
Since atomic memory accesses can be considerably slower than plain memory
accessses (depending on the CPU type), these lists should only be used where
necessary.

The following guarantees are provided regarding concurrent access:

- the operations are lock-free but not wait-free.

  Lock-free means that it is impossible for all threads to be blocked.  Some
  thread will always make progress, regardless of what other threads do.  (This
  even includes a random thread being stopped by a debugger in a random
  location.)

  Wait-free implies that the time any single thread might spend in one of the
  calls is bounded.  This is not provided here since it is not normally
  relevant to practical operations.  What this means is that if some thread is
  hammering a particular list with requests, it is possible that another
  thread is blocked for an extended time.  The lock-free guarantee still
  applies since the hammering thread is making progress.

- without a RCU mechanism in place, the point of contention for atomic lists
  is memory deallocation.  As it is, **a rwlock is required for correct
  operation**.  The *read* lock must be held for all accesses, including
  reading the list, adding items to the list, and removing items from the
  list.  The *write* lock must be acquired and released before deallocating
  any list element.  If this is not followed, an use-after-free can occur
  as a MT race condition when an element gets deallocated while another
  thread is accessing the list.

  .. note::

     The *write* lock does not need to be held for deleting items from the
     list, and there should not be any instructions between the
     ``pthread_rwlock_wrlock`` and ``pthread_rwlock_unlock``.  The write lock
     is used as a sequence point, not as an exclusion mechanism.

- insertion operations are always safe to do with the read lock held.
  Added items are immediately visible after the insertion call returns and
  should not be touched anymore.

- when removing a *particular* (pre-determined) item, the caller must ensure
  that no other thread is attempting to remove that same item.  If this cannot
  be guaranteed by architecture, a separate lock might need to be added.

- concurrent `pop` calls are always safe to do with only the read lock held.
  This does not fall under the previous rule since the `pop` call will select
  the next item if the first is already being removed by another thread.

  **Deallocation locking still applies.**  Assume another thread starts
  reading the list, but gets task-switched by the kernel while reading the
  first item.  `pop` will happily remove and return that item.  If it is
  deallocated without acquiring and releasing the write lock, the other thread
  will later resume execution and try to access the now-deleted element.

- the list count should be considered an estimate.  Since there might be
  concurrent insertions or removals in progress, it might already be outdated
  by the time the call returns.  No attempt is made to have it be correct even
  for a nanosecond.

Overall, atomic lists are well-suited for MT queues; concurrent insertion,
iteration and removal operations will work with the read lock held.

Code snippets
^^^^^^^^^^^^^

Iteration:

.. code-block:: c

   struct item *i;

   pthread_rwlock_rdlock(&itemhead_rwlock);
   frr_each(itemlist, &itemhead, i) {
     /* lock must remain held while iterating */
     ...
   }
   pthread_rwlock_unlock(&itemhead_rwlock);

Head removal (pop) and deallocation:

.. code-block:: c

   struct item *i;

   pthread_rwlock_rdlock(&itemhead_rwlock);
   i = itemlist_pop(&itemhead);
   pthread_rwlock_unlock(&itemhead_rwlock);

   /* i might still be visible for another thread doing an
    * frr_each() (but won't be returned by another pop()) */
   ...

   pthread_rwlock_wrlock(&itemhead_rwlock);
   pthread_rwlock_unlock(&itemhead_rwlock);
   /* i now guaranteed to be gone from the list.
    * note nothing between wrlock() and unlock() */
   XFREE(MTYPE_ITEM, i);

FAQ
---

What are the semantics of ``const`` in the container APIs?
   ``const`` pointers to list heads and/or items are interpreted to mean that
   both the container itself as well as the data items are read-only.

Why is it ``PREDECL`` + ``DECLARE`` instead of ``DECLARE`` + ``DEFINE``?
   The rule is that a ``DEFINE`` must be in a ``.c`` file, and linked exactly
   once because it defines some kind of global symbol.  This is not the case
   for the data structure macros;  they only define ``static`` symbols and it
   is perfectly fine to include both ``PREDECL`` and ``DECLARE`` in a header
   file.  It is also perfectly fine to have the same ``DECLARE`` statement in
   2 ``.c`` files, but only **if the macro arguments are identical.**  Maybe
   don't do that unless you really need it.

FRR lists
---------

.. TODO::

   document

BSD lists
---------

.. TODO::

   refer to external docs
