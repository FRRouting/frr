@@
identifier json;
expression family, value;
expression prefix;
constant key;
@@

(
-prefix2str(prefix, value, ...);
...
-json_object_string_add(json, key, value);
+json_object_string_addf(json, key, "%pFX", prefix);
|
-json_object_string_add(json, key, prefix2str(prefix, value, ...));
+json_object_string_addf(json, key, "%pFX", prefix);
)
