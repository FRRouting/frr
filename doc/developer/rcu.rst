.. highlight:: c

RCU
===

Introduction
------------

RCU (Read-Copy-Update) is, fundamentally, a paradigm of multithreaded
operation (and not a set of APIs.)  The core ideas are:

* longer, complicated updates to structures are made only on private,
  "invisible" copies.  Other threads, when they access the structure, see an
  older (but consistent) copy.

* once done, the updated copy is swapped in a single operation so that
  other threads see either the old or the new data but no inconsistent state
  between.

* the old instance is only released after making sure that it is impossible
  any other thread might still be reading it.

For more information, please search for general or Linux kernel RCU
documentation; there is no way this doc can be comprehensive in explaining the
interactions:

* https://en.wikipedia.org/wiki/Read-copy-update
* https://www.kernel.org/doc/html/latest/kernel-hacking/locking.html#avoiding-locks-read-copy-update
* https://lwn.net/Articles/262464/
* http://www.rdrop.com/users/paulmck/RCU/rclock_OLS.2001.05.01c.pdf
* http://lse.sourceforge.net/locking/rcupdate.html

RCU, the TL;DR
^^^^^^^^^^^^^^

#. data structures are always consistent for reading.  That's the "R" part.
#. reading never blocks / takes a lock.
#. rcu_read_lock is not a lock in the traditional sense.  Think of it as a
   "reservation";  it notes what the *oldest* possible thing the thread might
   be seeing is, and which thus can't be deleted yet.
#. you create some object, finish it up, and then publish it.
#. publishing is an ``atomic_*`` call with ``memory_order_release``, which
   tells the compiler to make sure prior memory writes have completed before
   doing the atomic op.
#. ``ATOMLIST_*`` ``add`` operations do the ``memory_order_release`` for you.
#. you can't touch the object after it is published, except with atomic ops.
#. because you can't touch it, if you want to change it you make a new copy,
   work on that, and then publish the new copy.  That's the "CU" part.
#. deleting the object is also an atomic op.
#. other threads that started working before you published / deleted an object
   might not see the new object / still see the deleted object.
#. because other threads may still see deleted objects, the ``free()`` needs
   to be delayed.  That's what :c:func:`rcu_free()` is for.


When (not) to use RCU
^^^^^^^^^^^^^^^^^^^^^

RCU is designed for read-heavy workloads where objects are updated relatively
rarely, but frequently accessed.  Do *not* indiscriminately replace locking by
RCU patterns.

The "copy" part of RCU implies that, while updating, several copies of a given
object exist in parallel.  Even after the updated copy is swapped in, the old
object remains queued for freeing until all other threads are guaranteed to
not be accessing it anymore, due to passing a sequence point.  In addition to
the increased memory usage, there may be some bursted (due to batching) malloc
contention when the RCU cleanup thread does its thing and frees memory.

Other useful patterns
^^^^^^^^^^^^^^^^^^^^^

In addition to the full "copy object, apply changes, atomically update"
approach, there are 2 "reduced" usage cases that can be done:

* atomically updating single pieces of a particular object, e.g. some flags
  or configuration piece

* straight up read-only / immutable objects

Both of these cases can be considered RCU "subsets".  For example, when
maintaining an atomic list of items, but these items only have a single
integer value that needs to be updated, that value can be atomically updated
without copying the entire object.  However, the object still needs to be
free'd through :c:func:`rcu_free()` since reading/updating and deleting might
be happening concurrently.  The same applies for immutable objects;  deletion
might still race with reading so they need to be free'd through RCU.

FRR API
-------

Before diving into detail on the provided functions, it is important to note
that the FRR RCU API covers the **cleanup part of RCU, not the read-copy-update
paradigm itself**.  These parts are handled by standard C11 atomic operations,
and by extension through the atomic data structures (ATOMLIST, ATOMSORT & co.)

The ``rcu_*`` functions only make sense in conjunction with these RCU access
patterns.  If you're calling the RCU API but not using these, something is
wrong.  The other way around is not necessarily true;  it is possible to use
atomic ops & datastructures with other types of locking, e.g. rwlocks.

.. c:function:: void rcu_read_lock()
.. c:function:: void rcu_read_unlock()

   These functions acquire / release the RCU read-side lock.  All access to
   RCU-guarded data must be inside a block guarded by these.  Any number of
   threads may hold the RCU read-side lock at a given point in time, including
   both no threads at all and all threads.

   The functions implement a depth counter, i.e. can be nested.  The nested
   calls are cheap, since they only increment/decrement the counter.
   Therefore, any place that uses RCU data and doesn't have a guarantee that
   the caller holds RCU (e.g. ``lib/`` code) should just have its own
   rcu_read_lock/rcu_read_unlock pair.

   At the "root" level (e.g. un-nested), these calls can incur the cost of one
   syscall (to ``futex()``).  That puts them on about the same cost as a
   mutex lock/unlock.

   The ``thread_master`` code currently always holds RCU everywhere, except
   while doing the actual ``poll()`` syscall.  This is both an optimization as
   well as an "easement" into getting RCU going.  The current implementation
   contract is that any ``struct event *`` callback is called with a RCU
   holding depth of 1, and that this is owned by the thread so it may (should)
   drop and reacquire it when doing some longer-running work.

   .. warning::

      The RCU read-side lock must be held **continuously** for the entire time
      any piece of RCU data is used.  This includes any access to RCU data
      after the initial ``atomic_load``.  If the RCU read-side lock is
      released, any RCU-protected pointers as well as the data they refer to
      become invalid, as another thread may have called :c:func:`rcu_free` on
      them.

.. c:struct:: rcu_head
.. c:struct:: rcu_head_close
.. c:struct:: rcu_action

   The ``rcu_head`` structures are small (16-byte) bits that contain the
   queueing machinery for the RCU sweeper/cleanup mechanisms.

   Any piece of data that is cleaned up by RCU needs to have a matching
   ``rcu_head`` embedded in it.  If there is more than one cleanup operation
   to be done (e.g. closing a file descriptor), more than one ``rcu_head`` may
   be embedded.

   .. warning::

      It is not possible to reuse a ``rcu_head``.  It is owned by the RCU code
      as soon as ``rcu_*`` is called on it.

   The ``_close`` variant carries an extra ``int fd`` field to store the fd to
   be closed.

   To minimize the amount of memory used for ``rcu_head``, details about the
   RCU operation to be performed are moved into the ``rcu_action`` structure.
   It contains e.g. the MTYPE for :c:func:`rcu_free` calls.  The pointer to be
   freed is stored as an offset relative to the ``rcu_head``, which means it
   must be embedded as a struct field so the offset is constant.

   The ``rcu_action`` structure is an implementation detail.  Using
   ``rcu_free`` or ``rcu_close`` will set it up correctly without further
   code needed.

   The ``rcu_head`` may be put in an union with other data if the other data
   is only used during "life" of the data, since the ``rcu_head`` is used only
   for the "death" of data.  But note that other threads may still be reading
   a piece of data while a thread is working to free it.

.. c:function:: void rcu_free(struct memtype *mtype, struct X *ptr, field)

   Free a block of memory after RCU has ensured no other thread can be
   accessing it anymore.  The pointer remains valid for any other thread that
   has called :c:func:`rcu_read_lock` before the ``rcu_free`` call.

   .. warning::

      In some other RCU implementations, the pointer remains valid to the
      *calling* thread if it is holding the RCU read-side lock.  This is not
      the case in FRR, particularly when running single-threaded.  Enforcing
      this rule also allows static analysis to find use-after-free issues.

   ``mtype`` is the libfrr ``MTYPE_FOO`` allocation type to pass to
   :c:func:`XFREE`.

   ``field`` must be the name of a ``struct rcu_head`` member field in ``ptr``.
   The offset of this field (which must be constant) is used to reduce the
   memory size of ``struct rcu_head``.

   .. note::

      ``rcu_free`` (and ``rcu_close``) calls are more efficient if they are
      put close to each other.  When freeing several RCU'd resources, try to
      move the calls next to each other (even if the data structures do not
      directly point to each other.)

      Having the calls bundled reduces the cost of adding the ``rcu_head`` to
      the RCU queue;  the RCU queue is an atomic data structure whose usage
      will require the CPU to acquire an exclusive hold on relevant cache
      lines.

.. c:function:: void rcu_close(struct rcu_head_close *head, int fd)

   Close a file descriptor after ensuring no other thread might be using it
   anymore.  Same as :c:func:`rcu_free`, except it calls ``close`` instead of
   ``free``.

Internals
^^^^^^^^^

.. c:struct:: rcu_thread

   Per-thread state maintained by the RCU code, set up by the following
   functions.  A pointer to a thread's own ``rcu_thread`` is saved in
   thread-local storage.

.. c:function:: struct rcu_thread *rcu_thread_prepare(void)
.. c:function:: void rcu_thread_unprepare(struct rcu_thread *rcu_thread)
.. c:function:: void rcu_thread_start(struct rcu_thread *rcu_thread)

   Since the RCU code needs to have a list of all active threads, these
   functions are used by the ``frr_pthread`` code to set up threads.  Teardown
   is automatic.  It should not be necessary to call these functions.

   Any thread that accesses RCU-protected data needs to be registered with
   these functions.  Threads that do not access RCU-protected data may call
   these functions but do not need to.

   Note that passing a pointer to RCU-protected data to some library which
   accesses that pointer makes the library "access RCU-protected data".  In
   that case, either all of the library's threads must be registered for RCU,
   or the code must instead pass a (non-RCU) copy of the data to the library.

.. c:function:: int frr_pthread_non_controlled_startup(pthread_t thread, const char *name, const char *os_name)

   If a pthread is started outside the control of normal pthreads in frr
   then frr_pthread_non_controlled_startup should be called.  This will
   properly setup both the pthread with rcu usage as well as some data
   structures pertaining to the name of the pthread.  This is especially
   important if the pthread created ends up calling back into FRR and
   one of the various zlog_XXX functions is called.

.. c:function:: void rcu_shutdown(void)

   Stop the RCU sweeper thread and make sure all cleanup has finished.

   This function is called on daemon exit by the libfrr code to ensure pending
   RCU operations are completed.  This is mostly to get a clean exit without
   memory leaks from queued RCU operations.  It should not be necessary to
   call this function as libfrr handles this.

FRR specifics and implementation details
----------------------------------------

The FRR RCU infrastructure has the following characteristics:

* it is Epoch-based with a 32-bit wrapping counter.  (This is somewhat
  different from other Epoch-based approaches which may be designed to only
  use 3 counter values, but works out to a simple implementation.)

* instead of tracking CPUs as the Linux kernel does, threads are tracked.  This
  has exactly zero semantic impact, RCU just cares about "threads of
  execution", which the kernel can optimize to CPUs but we can't.  But it
  really boils down to the same thing.

* there are no ``rcu_dereference`` and ``rcu_assign_pointer`` - use
  ``atomic_load`` and ``atomic_store`` instead.  (These didn't exist when the
  Linux RCU code was created.)

* there is no ``synchronize_rcu``; this is a design choice but may be revisited
  at a later point.  ``synchronize_rcu`` blocks a thread until it is guaranteed
  that no other threads might still be accessing data structures that they may
  have access to at the beginning of the function call.  This is a blocking
  design and probably not appropriate for FRR.  Instead, ``rcu_call`` can be
  used to have the RCU sweeper thread make a callback after the same constraint
  is fulfilled in an asynchronous way.  Most needs should be covered by
  ``rcu_free`` and ``rcu_close``.
