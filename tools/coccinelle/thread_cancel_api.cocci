@ptrupdate@
expression E;
@@
- thread_cancel(E);
+ thread_cancel(&E);

@nullcheckremove depends on ptrupdate@
expression E;
@@

thread_cancel(&E);
- E = NULL;

@cancelguardremove depends on nullcheckremove@
expression E;
@@
- if (E)
- {
   thread_cancel(&E);
- }

@cancelguardremove2 depends on nullcheckremove@
expression E;
@@
- if (E != NULL)
- {
   thread_cancel(&E);
- }

@cancelguardremove3 depends on nullcheckremove@
expression E;
@@
- if (E)
   thread_cancel(&E);

@cancelguardremove4 depends on nullcheckremove@
expression E;
@@
- if (E != NULL)
   thread_cancel(&E);

@replacetimeroff@
expression E;
@@

- THREAD_TIMER_OFF(E);
+ thread_cancel(&E);

@replacewriteoff@
expression E;
@@

- THREAD_WRITE_OFF(E);
+ thread_cancel(&E);

@replacereadoff@
expression E;
@@

- THREAD_READ_OFF(E);
+ thread_cancel(&E);

@replacethreadoff@
expression E;
@@

- THREAD_OFF(E);
+ thread_cancel(&E);