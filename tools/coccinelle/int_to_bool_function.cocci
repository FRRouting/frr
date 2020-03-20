@@
identifier fn;
typedef bool;
symbol false;
symbol true;
identifier I;
struct thread *thread;
@@

- int
+ bool
fn (...)
{
... when strict
    when != I = THREAD_ARG(thread);
(
- return 0;
+ return false;
|
- return 1;
+ return true;
)
?...
}
