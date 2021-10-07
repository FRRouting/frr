@r1@
identifier fn, m, f, a, v, t;
identifier func =~ "thread_add_";
type T1, T2;
position p;
@@

?static
T1 fn(T2 *t)
{
...
func(m,f,a,v,&t)@p
...
}

@r2@
identifier m, f, a, v, t;
identifier func =~ "thread_add_";
type T1;
position p;
@@

T1 *t;
...
func(m,f,a,v,&t)@p

@script:python@
p << r1.p;
@@
coccilib.report.print_report(p[0],"Passed double 'struct thread' pointer")

@script:python@
p << r2.p;
@@
coccilib.report.print_report(p[0],"Passed double 'struct thread' pointer")
