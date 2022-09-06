Low-level pytest integration
============================

To understand how topotato integrates into pytest, the main thing to understand
is that pytest sets up a hierarchy of "handles", i.e. tools and wrappers that
deal with various pieces of test source code.  This is best explained with
some annotated code::

                             # 1. pytest_sess = _pytest.main.Session()
   # test_something.py       # 2. pytest_mod = _pytest.python.Module(obj=test_something)
   class SomeTest:           # 3. pytest_cls = _pytest.python.Class(obj=SomeTest)
                             # 4. pytest_inst = _pytest.python.Instance(obj=SomeTest()) - pytest 6.x ONLY
      def test_foo(self):    # 5. pytest_fun = _pytest.python.Function(obj=test_foo)

topotato customizes this starting at the class level, using
:py:class:`TopotatoClass` instead.  The
function level does not (currently) have a direct equivalent, it is replaced
with the assertions yielded from the test function.  The assertions are all
subclasses of :py:class:`TopotatoItem`::

                             # 1. pytest_sess = _pytest.main.Session()
   # test_something.py       # 2. pytest_mod = _pytest.python.Module(obj=test_something)
   class SomeTest(TestBase): # 3. pytest_cls = TopotatoClass(obj=SomeTest)
                             # 4. pytest_inst = _pytest.python.Instance(obj=SomeTest()) - pytest 6.x ONLY
                             # 5. pytest_item = InstanceStartup()   (automagic)
      @topotatofunc          #
      def test_foo(self):    # n/a currently
          yield from AssertFoo.make(...)
                             # 5. pytest_item = AssertFoo(...)
                             # 5. pytest_item = InstanceShutdown()  (automagic)

.. hint::

   It is extremely important to understand the difference between these two
   hierarchies, and what the "current" position in each of them is.

.. py:currentmodule:: topotato.base

.. autoclass:: TopotatoClass
   :members:
   :private-members:

.. autoclass:: TopotatoItem
   :members:
   :private-members:

Auxiliary bits
--------------

.. autoclass:: TopotatoWrapped
   :members:
   :private-members:

.. autodata:: skiptrace

.. autoclass:: _SkipTrace
   :members:

.. autoclass:: TimedElement
   :members:
