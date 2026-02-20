/*
 * This patch was used to replace VSL_Setup() with VSL_Init() / VSL_Alloc() once
 *
 * For VSL_Alloc() use, VSL_Free() has to be added maually
 *
 * Retained for reference and use by VMODs only
 */
using "varnish.iso"

@@
expression vsl;
@@

- VSL_Setup(vsl, NULL, 0)
+ VSL_Alloc(vsl)

@@
expression vsl, ptr, len;
@@

- VSL_Setup(vsl, ptr, len);
+ VSL_Init(vsl, ptr, len);

