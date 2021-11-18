@@
identifier json;
expression family, buf, value;
constant key, buflen;
@@

(
-json_object_string_add(json, key, inet_ntop(AF_INET, &value, buf, sizeof(buf)));
+json_object_string_addf(json, key, "%pI4", &value);
|
-json_object_string_add(json, key, inet_ntop(AF_INET, &value, buf, buflen));
+json_object_string_addf(json, key, "%pI4", &value);
|
-json_object_string_add(json, key, inet_ntop(AF_INET6, &value, buf, sizeof(buf)));
+json_object_string_addf(json, key, "%pI6", &value);
|
-json_object_string_add(json, key, inet_ntop(AF_INET6, &value, buf, buflen));
+json_object_string_addf(json, key, "%pI6", &value);
)
