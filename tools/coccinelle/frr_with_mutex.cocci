@@
expression E;
iterator name frr_with_mutex;
@@

- pthread_mutex_lock(E);
+ frr_with_mutex(E) {
- {
    ...
- }
- pthread_mutex_unlock(E);
+ }


@@
expression E;
@@

- pthread_mutex_lock(E);
+ frr_with_mutex(E) {
  ...
- pthread_mutex_unlock(E);
+ }
