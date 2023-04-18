// Do not apply only for ldpd daemon since it uses the BSD coding style,
// where parentheses on return is expected.

@@
constant c;
@@

- return (c);
+ return c;
