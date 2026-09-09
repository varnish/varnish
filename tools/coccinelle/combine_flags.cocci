/*
 * Combine multiple assertions for flags into one
 */

@@
expression flags;
constant v1, v2;
@@

-AZ(flags & v1);
-AZ(flags & v2);
+AZ(flags & (v1|v2));

@@
expression flags;
constant v1, v2;
@@

-AN(flags & v1);
-AN(flags & v2);
+assert((flags & (v1|v2)) == (v1|v2));


