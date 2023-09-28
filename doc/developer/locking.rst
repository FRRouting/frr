.. _locking:

Locking
=======

FRR ships two small wrappers around ``pthread_mutex_lock()`` /
``pthread_mutex_unlock``.  Use ``#include "frr_pthread.h"`` to get these
macros.

.. c:macro:: frr_with_mutex (mutex)

   (With ``pthread_mutex_t *mutex``.)

   Begin a C statement block that is executed with the mutex locked.  Any
   exit from the block (``break``, ``return``, ``goto``, end of block) will
   cause the mutex to be unlocked::

      int somefunction(int option)
      {
          frr_with_mutex (&my_mutex) {
              /* mutex will be locked */

              if (!option)
                  /* mutex will be unlocked before return */
                  return -1;

              if (something(option))
                  /* mutex will be unlocked before goto */
                  goto out_err;

              somethingelse();

              /* mutex will be unlocked at end of block */
          }

          return 0;

      out_err:
          somecleanup();
          return -1;
      }

   This is a macro that internally uses a ``for`` loop.  It is explicitly
   acceptable to use ``break`` to get out of the block.  Even though a single
   statement works correctly, FRR coding style requires that this macro always
   be used with a ``{ ... }`` block.

.. c:macro:: frr_mutex_lock_autounlock(mutex)

   (With ``pthread_mutex_t *mutex``.)

   Lock mutex and unlock at the end of the current C statement block::

      int somefunction(int option)
      {
          frr_mutex_lock_autounlock(&my_mutex);
          /* mutex will be locked */

          ...
          if (error)
            /* mutex will be unlocked before return */
            return -1;
          ...

          /* mutex will be unlocked before return */
          return 0;
      }

   This is a macro that internally creates a variable with a destructor.
   When the variable goes out of scope (i.e. the block ends), the mutex is
   released.

   .. warning::

      This macro should only used when :c:func:`frr_with_mutex` would
      result in excessively/weirdly nested code.  This generally is an
      indicator that the code might be trying to do too many things with
      the lock held.  Try any possible venues to reduce the amount of
      code covered by the lock and move to :c:func:`frr_with_mutex`.
