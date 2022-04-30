Core test item structures
=========================

.. py:currentmodule:: topotato.base

.. automodule:: topotato.base
   :members:
   :exclude-members: _SkipTrace, skiptrace, TopotatoItem, TimedElement,
      TopotatoWrapped, TopotatoClass, TopotatoInstance,
      InstanceStartup, InstanceShutdown
   :private-members:

   This includes the single most visible (and pivotal) class in topotato:
   :py:class:`TestBase`:

.. autoclass:: InstanceStartup
   :members:

.. autoclass:: InstanceShutdown
   :members:

..
   Other bits of topotato.base are documented in pytest_lowlevel.rst
