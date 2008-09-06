
/////////////////////////////////////////////////////////////////
//                                                             //
// BEGIN In-Valgrind impedance matcher for libhb_core.c.       //
//                                                             //
/////////////////////////////////////////////////////////////////

#include "pub_tool_basics.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_oset.h"

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


#define libhbPlainVG_OSetGen_Remove(_arg1, _arg2) \
   vgPlain_OSetGen_Remove((_arg1),(_arg2))

#define libhbPlainVG_OSetGen_FreeNode(_arg1, _arg2) \
   vgPlain_OSetGen_FreeNode((_arg1),(_arg2))

#define libhbPlainVG_OSetGen_Lookup(_arg1, _arg2) \
   vgPlain_OSetGen_Lookup((_arg1),(_arg2))

#define libhbPlainVG_OSetGen_AllocNode(_arg1, _arg2) \
   vgPlain_OSetGen_AllocNode((_arg1),(_arg2))

#define libhbPlainVG_OSetGen_Insert(_arg1, _arg2) \
   vgPlain_OSetGen_Insert((_arg1),(_arg2))

#define libhbPlainVG_OSetGen_Create(_arg1, _arg2, _arg3, _arg4, _arg5) \
   vgPlain_OSetGen_Create((_arg1),(_arg2),(_arg3),(_arg4),(_arg5))

#define libhbPlainVG_OSetGen_Size(_arg1) \
   vgPlain_OSetGen_Size((_arg1))

#define libhbPlainVG_OSetGen_ResetIter(_arg1) \
   vgPlain_OSetGen_ResetIter((_arg1))

#define libhbPlainVG_OSetGen_Next(_arg1) \
   vgPlain_OSetGen_Next((_arg1))



//////////////////////////////////////
#include "libhb_core.c"
//////////////////////////////////////


/////////////////////////////////////////////////////////////////
//                                                             //
// END In-Valgrind impedance matcher for libhb_core.c.         //
//                                                             //
/////////////////////////////////////////////////////////////////
