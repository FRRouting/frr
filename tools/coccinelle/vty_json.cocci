@@
identifier vty;
identifier json;
constant fmt;
@@

-vty_out(vty, fmt, json_object_to_json_string_ext(json, ...));
...
-json_object_free(json);
+vty_json(vty, json);
