// There is no need to test for null values in the hash compare
// function as that we are guaranteed to send in data in
// the hash compare functions.
@@
identifier fn =~ "_hash_cmp";
type T;
identifier p1;
identifier p2;
@@

?static
T fn(...)
{
...
- if (p1 == NULL && p2 == NULL)
-	return ...;
- if (p1 == NULL || p2 == NULL)
-	return ...;
...
}
