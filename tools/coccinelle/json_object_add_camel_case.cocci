// Catch whitespaces in JSON keys

@r@
identifier json;
constant key;
identifier func =~ "json_object_";
position p;
@@

func(json, key, ...)@p

@script:python@
fmt << r.key;
p << r.p;
@@
if " " in str(fmt):
    print("Whitespace detected in JSON keys %s:%s:%s:%s" % (p[0].file, p[0].line, p[0].column, fmt))
if str(fmt)[1].isupper():
    print("Capital first detected in JSON keys %s:%s:%s:%s" % (p[0].file, p[0].line, p[0].column, fmt))
