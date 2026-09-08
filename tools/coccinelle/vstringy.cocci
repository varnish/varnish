/*
 * Replace strlen, strcmp, memcmp etc. with our v* variants, which allow
 * compilers to make better optimizations for constant values
 */

@@
idexpression x;
@@

-strlen(x)
+vstrlen(x)

@@
idexpression x, y;
@@

-strcmp(x, y)
+vstrcmp(x, y)
