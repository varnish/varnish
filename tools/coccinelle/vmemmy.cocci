/*
 * Replace memcpy etc with our v* variants, which allow
 * compilers to make better optimizations for constant values
 */

// memory builtins in order of documentation
@@
expression x, y, z;
@@

-memcpy(x, y, z)
+vmemcpy(x, y, z)

@@
expression x, y, z;
@@

-memmove(x, y, z)
+vmemmove(x, y, z)

