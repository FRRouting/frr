
@@
identifier func =~ "^(to|is)(alnum|cntrl|print|xdigit|alpha|digit|punct|ascii|graph|space|blank|lower|upper)$";
expression e;
@@

 func(
-  (int)
+  (unsigned char)
  e)

