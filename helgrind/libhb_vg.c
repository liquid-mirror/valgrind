
/////////////////////////////////////////////////////////////////
//                                                             //
// BEGIN In-Valgrind impedance matcher for libhb_core.c.       //
//                                                             //
/////////////////////////////////////////////////////////////////

#include "pub_tool_basics.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"

static void* libhbPlainVG_memset ( void *s, Int c, SizeT sz ) {
   return VG_(memset)(s,c,sz);
}

static void* libhbPlainVG_memcpy ( void *d, const void *s, SizeT sz ) {
   return VG_(memcpy)(d,s,sz);
}

static void libhbPlainVG_ssort ( void* base, SizeT nmemb, SizeT size,
                                 Int (*compar)(void*, void*) ) {
   VG_(ssort)(base,nmemb,size,compar);
}

static SizeT libhbPlainVG_strlen ( const char* s ) {
   return VG_(strlen)(s);
}

static char* libhbPlainVG_strcat (char *dest, const char *src) {
   return VG_(strcat)(dest,src);
}


#define vg_assert(__x)  tl_assert((__x))

#define libhbPlainVG_assert_fail(_isCore,_expr,_file,_line,_fn,_format) \
   vgPlain_assert_fail(_isCore,_expr,_file,_line,_fn,_format)

#define libhbPlainVG_printf(_format, _args...) \
   vgPlain_printf(_format, _args)

#define libhbPlainVG_sprintf(_str, _format, _args...) \
   vgPlain_sprintf(_str, _format, _args)


//////////////////////////////////////
#include "libhb_core.c"
//////////////////////////////////////


/////////////////////////////////////////////////////////////////
//                                                             //
// END In-Valgrind impedance matcher for libhb_core.c.         //
//                                                             //
/////////////////////////////////////////////////////////////////
