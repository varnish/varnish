/*
 * Replace strlen, strcmp, memcmp etc. with our v* variants, which allow
 * compilers to make better optimizations for constant values
 */

// string builtins in order of documentation
@@
expression x, y, z;
@@

-memchr(x, y, z)
+vmemchr(x, y, z)

@@
expression x, y, z;
@@

-memcmp(x, y, z)
+vmemcmp(x, y, z)

@@
expression x, y, z;
@@

-strchr(x, y, z)
+vstrchr(x, y, z)

@@
expression x, y;
@@

-strcmp(x, y)
+vstrcmp(x, y)

@@
expression x;
@@

-strlen(x)
+vstrlen(x)

@@
expression x, y, z;
@@

-strncmp(x, y, z)
+vstrncmp(x, y, z)
