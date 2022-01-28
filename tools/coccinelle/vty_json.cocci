@@
identifier vty;
identifier json;
@@

-vty_out(vty, "%s\n", json_object_to_json_string_ext(json, ...));
...
-json_object_free(json);
+vty_json(vty, json);
