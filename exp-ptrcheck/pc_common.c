
/*--------------------------------------------------------------------*/
/*--- Ptrcheck: a pointer-use checker.                             ---*/
/*--- Provides stuff shared between sg_ and h_ subtools.           ---*/
/*---                                                  pc_common.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Ptrcheck, a Valgrind tool for checking pointer
   use in programs.

   Copyright (C) 2008-2009 OpenWorks Ltd
      info@open-works.co.uk

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.

   Neither the names of the U.S. Department of Energy nor the
   University of California nor the names of its contributors may be
   used to endorse or promote products derived from this software
   without prior written permission.
*/

#include "pub_tool_basics.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_options.h"
#include "pub_tool_replacemalloc.h"
#include "pub_tool_execontext.h"
#include "pub_tool_tooliface.h"    // CorePart
#include "pub_tool_threadstate.h"  // VG_(get_running_tid)
#include "pub_tool_debuginfo.h"

#include "pc_common.h"   // self, & Seg

#include "h_main.h"      // NONPTR, BOTTOM, UNKNOWN


//////////////////////////////////////////////////////////////
//                                                          //
// Command line options                                     //
//                                                          //
//////////////////////////////////////////////////////////////

Bool h_clo_partial_loads_ok  = True;   /* user visible */
/* Bool h_clo_lossage_check     = False; */ /* dev flag only */
Bool sg_clo_enable_sg_checks = True;   /* user visible */

Bool pc_process_cmd_line_options(Char* arg)
{
        if VG_BOOL_CLO(arg, "--partial-loads-ok", h_clo_partial_loads_ok) {}
   /* else if VG_BOOL_CLO(arg, "--lossage-check",    h_clo_lossage_check) {} */
   else if VG_BOOL_CLO(arg, "--enable-sg-checks", sg_clo_enable_sg_checks) {}
   else
      return VG_(replacement_malloc_process_cmd_line_option)(arg);

   return True;
}

void pc_print_usage(void)
{
   VG_(printf)(
   "    --partial-loads-ok=no|yes  same as for Memcheck [yes]\n"
   "    --enable-sg-checks=no|yes  enable stack & global array checking? [yes]\n"
   );
   VG_(replacement_malloc_print_usage)();
}

void pc_print_debug_usage(void)
{
  /*
   VG_(printf)(
   "    --lossage-check=no|yes    gather stats for quality control [no]\n"
   );
  */
   VG_(replacement_malloc_print_debug_usage)();
}



//////////////////////////////////////////////////////////////
//                                                          //
// Error management -- storage                              //
//                                                          //
//////////////////////////////////////////////////////////////

/* What kind of error it is. */
typedef
   enum {
      XE_SorG=1202, // sg: stack or global array inconsistency
      XE_Heap,      // h: mismatched ptr/addr segments on load/store
      XE_Arith,     // h: bad arithmetic between two segment pointers
      XE_SysParam   // h: block straddling >1 segment passed to syscall
   }
   XErrorTag;

typedef
   enum {
      XS_SorG=2021,
      XS_Heap,
      XS_Arith,
      XS_SysParam
   }
   XSuppTag;

typedef
   struct {
      XErrorTag tag;
      union {
         struct {
            Addr   addr;
            SSizeT sszB;  /* -ve is write, +ve is read */
            HChar  expect[128];
            HChar  actual[128];
         } SorG;
         struct {
            Addr     addr;
            SSizeT   sszB;  /* -ve is write, +ve is read */
            Seg*     vseg;
            Char     descr1[96];
            Char     descr2[96];
            Char     datasym[96];
            PtrdiffT datasymoff;
         } Heap;
         struct {
            Seg* seg1;
            Seg* seg2;
            const HChar* opname; // user-understandable text name
         } Arith;
         struct {
            CorePart part;
            Addr lo;
            Addr hi;
            Seg* seglo;
            Seg* seghi;
         } SysParam;
      } XE;
   }
   XError;


void sg_record_error_SorG ( ThreadId tid,
                            Addr addr, SSizeT sszB,
                            HChar* expect, HChar* actual )
{
   XError xe;
   VG_(memset)(&xe, 0, sizeof(xe));
   xe.tag = XE_SorG;
   xe.XE.SorG.addr = addr;
   xe.XE.SorG.sszB = sszB;
   VG_(strncpy)( &xe.XE.SorG.expect[0],
                 expect, sizeof(xe.XE.SorG.expect) );
   VG_(strncpy)( &xe.XE.SorG.actual[0],
                 actual, sizeof(xe.XE.SorG.actual) );
   xe.XE.SorG.expect[ sizeof(xe.XE.SorG.expect)-1 ] = 0;
   xe.XE.SorG.actual[ sizeof(xe.XE.SorG.actual)-1 ] = 0;
   VG_(maybe_record_error)( tid, XE_SorG, 0, NULL, &xe );
}

void h_record_heap_error( Addr a, SizeT size, Seg* vseg, Bool is_write )
{
   XError xe;
   tl_assert(size > 0);
   VG_(memset)(&xe, 0, sizeof(xe));
   xe.tag = XE_Heap;
   xe.XE.Heap.addr = a;
   xe.XE.Heap.sszB = is_write ? -size : size;
   xe.XE.Heap.vseg = vseg;
   VG_(maybe_record_error)( VG_(get_running_tid)(), XE_Heap,
                            /*a*/0, /*str*/NULL, /*extra*/(void*)&xe);
}

void h_record_arith_error( Seg* seg1, Seg* seg2, HChar* opname )
{
   XError xe;
   VG_(memset)(&xe, 0, sizeof(xe));
   xe.tag = XE_Arith;
   xe.XE.Arith.seg1   = seg1;
   xe.XE.Arith.seg2   = seg2;
   xe.XE.Arith.opname = opname;
   VG_(maybe_record_error)( VG_(get_running_tid)(), XE_Arith,
                            /*a*/0, /*str*/NULL, /*extra*/(void*)&xe);
}

void h_record_sysparam_error( ThreadId tid, CorePart part, Char* s,
                              Addr lo, Addr hi, Seg* seglo, Seg* seghi )
{
   XError xe;
   VG_(memset)(&xe, 0, sizeof(xe));
   xe.tag = XE_SysParam;
   xe.XE.SysParam.part = part;
   xe.XE.SysParam.lo = lo;
   xe.XE.SysParam.hi = hi;
   xe.XE.SysParam.seglo = seglo;
   xe.XE.SysParam.seghi = seghi;
   VG_(maybe_record_error)( tid, XE_SysParam, /*a*/(Addr)0, /*str*/s,
                            /*extra*/(void*)&xe);
}


Bool pc_eq_Error ( VgRes res, Error* e1, Error* e2 )
{
   XError *xe1, *xe2;
   tl_assert(VG_(get_error_kind)(e1) == VG_(get_error_kind)(e2));
   //tl_assert(VG_(get_error_string)(e1) == NULL);
   //tl_assert(VG_(get_error_string)(e2) == NULL);

   xe1 = (XError*)VG_(get_error_extra)(e1);
   xe2 = (XError*)VG_(get_error_extra)(e2);
   tl_assert(xe1);
   tl_assert(xe2);

   if (xe1->tag != xe2->tag)
      return False;

   switch (xe1->tag) {
      case XE_SorG:
         return //xe1->XE.SorG.addr == xe2->XE.SorG.addr
                //&& 
                xe1->XE.SorG.sszB == xe2->XE.SorG.sszB
                && 0 == VG_(strncmp)( &xe1->XE.SorG.expect[0],
                                      &xe2->XE.SorG.expect[0],
                                      sizeof(xe1->XE.SorG.expect) ) 
                && 0 == VG_(strncmp)( &xe1->XE.SorG.actual[0],
                                      &xe2->XE.SorG.actual[0],
                                      sizeof(xe1->XE.SorG.actual) );
      case XE_Heap:
      case XE_Arith:
      case XE_SysParam:
         return True;
      default:
         VG_(tool_panic)("eq_Error: unrecognised error kind");
   }
}


//////////////////////////////////////////////////////////////
//                                                          //
// Error management -- printing                             //
//                                                          //
//////////////////////////////////////////////////////////////

/* Do a printf-style operation on either the XML or normal output
   channel, depending on the setting of VG_(clo_xml).
*/
static void emit_WRK ( HChar* format, va_list vargs )
{
   if (VG_(clo_xml)) {
      VG_(vprintf_xml)(format, vargs);
   } else {
      VG_(vmessage)(Vg_UserMsg, format, vargs);
   }
}
static void emit ( HChar* format, ... ) PRINTF_CHECK(1, 2);
static void emit ( HChar* format, ... )
{
   va_list vargs;
   va_start(vargs, format);
   emit_WRK(format, vargs);
   va_end(vargs);
}


static Char* readwrite(SSizeT sszB)
{
   return ( sszB < 0 ? "write" : "read" );
}

static Word Word__abs ( Word w ) {
   return w < 0 ? -w : w;
}

void pc_pp_Error ( Error* err )
{
   HChar* what_pre  = VG_(clo_xml) ? "  <what>"    : "";
   HChar* what_post = VG_(clo_xml) ? "</what>"     : "";
   HChar* auxw_pre  = VG_(clo_xml) ? "  <auxwhat>" : " ";
   HChar* auxw_post = VG_(clo_xml) ? "</auxwhat>"  : "";

   XError *xe = (XError*)VG_(get_error_extra)(err);
   tl_assert(xe);

   switch (VG_(get_error_kind)(err)) {

   //----------------------------------------------------------
   case XE_SorG:
      tl_assert(xe);

      if (VG_(clo_xml))
         VG_(printf_xml)( "  <kind>SorG</kind>\n");
      emit( "%sInvalid %s of size %ld%s\n", 
            what_pre,
            xe->XE.SorG.sszB < 0 ? "write" : "read",
            Word__abs(xe->XE.SorG.sszB),
            what_post );
      VG_(pp_ExeContext)( VG_(get_error_where)(err) );

      emit( "%sAddress %#lx expected vs actual:%s\n",
            auxw_pre, xe->XE.SorG.addr, auxw_post );
      emit( "%sExpected: %s%s\n",
            auxw_pre, &xe->XE.SorG.expect[0], auxw_post );
      emit( "%sActual:   %s%s\n", 
            auxw_pre, &xe->XE.SorG.actual[0], auxw_post );
      break;

   //----------------------------------------------------------
   case XE_Heap: {
      Char *place, *legit, *how_invalid;
      Addr a    = xe->XE.Heap.addr;
      Seg* vseg = xe->XE.Heap.vseg;

      tl_assert(is_known_segment(vseg) || NONPTR == vseg);

      if (NONPTR == vseg) {
         // Access via a non-pointer
         if (VG_(clo_xml))
            VG_(printf_xml)( "  <kind>Heap</kind>\n");
         emit( "%sInvalid %s of size %ld%s\n",
               what_pre, readwrite(xe->XE.Heap.sszB),
               Word__abs(xe->XE.Heap.sszB), what_post );
         VG_(pp_ExeContext)( VG_(get_error_where)(err) );

         emit( "%sAddress %#lx is not derived from "
               "any known block%s\n",
               auxw_pre, a, auxw_post );
      } else {
         // Access via a pointer, but outside its range.
         Int cmp;
         UWord miss_size;
         Seg__cmp(vseg, a, &cmp, &miss_size);
         if      (cmp  < 0) place = "before";
         else if (cmp == 0) place = "inside";
         else               place = "after";
         how_invalid = ( ( Seg__is_freed(vseg) && 0 != cmp )
                       ? "Doubly-invalid" : "Invalid" );
         legit = ( Seg__is_freed(vseg) ? "once-" : "" );

         if (VG_(clo_xml))
            VG_(printf_xml)( "  <kind>Heap</kind>\n");
         emit( "%s%s %s of size %ld%s\n",
               what_pre, how_invalid,
               readwrite(xe->XE.Heap.sszB),
               Word__abs(xe->XE.Heap.sszB), what_post );
         VG_(pp_ExeContext)( VG_(get_error_where)(err) );

         emit( "%sAddress %#lx is %lu bytes %s the accessing pointer's%s\n",
               auxw_pre, a, miss_size, place , auxw_post );
         emit( "%s%slegitimate range, a block of size %lu %s%s\n",
               auxw_pre, legit, Seg__size(vseg),
               Seg__is_freed(vseg) ? "free'd" : "alloc'd", auxw_post );
         VG_(pp_ExeContext)(Seg__where(vseg));
      }
      if (xe->XE.Heap.descr1[0] != 0)
         emit( "%s%s%s\n", auxw_pre, xe->XE.Heap.descr1, auxw_post );
      if (xe->XE.Heap.descr2[0] != 0)
         emit( "%s%s%s\n", auxw_pre, xe->XE.Heap.descr2, auxw_post );
      if (xe->XE.Heap.datasym[0] != 0)
         emit( "%sAddress 0x%llx is %llu bytes "
               "inside data symbol \"%s\"%s\n",
               auxw_pre,
               (ULong)xe->XE.Heap.addr,
               (ULong)xe->XE.Heap.datasymoff,
               xe->XE.Heap.datasym, auxw_post );
      break;
   }

   //----------------------------------------------------------
   case XE_Arith: {
      Seg*   seg1   = xe->XE.Arith.seg1;
      Seg*   seg2   = xe->XE.Arith.seg2;
      Char*  which;

      tl_assert(BOTTOM != seg1);
      tl_assert(BOTTOM != seg2 && UNKNOWN != seg2);

      if (VG_(clo_xml))
         VG_(printf_xml)("  <kind>Arith</kind>\n");
      emit( "%sInvalid arguments to %s%s\n",
            what_pre, xe->XE.Arith.opname, what_post );
      VG_(pp_ExeContext)( VG_(get_error_where)(err) );

      if (seg1 != seg2) {
         if (NONPTR == seg1) {
            emit( "%sFirst arg not a pointer%s\n", auxw_pre, auxw_post );
         } else if (UNKNOWN == seg1) {
            emit( "%sFirst arg may be a pointer%s\n", auxw_pre, auxw_post );
         } else {
            emit( "%sFirst arg derived from address %#lx of "
                  "%lu-byte block alloc'd%s\n",
                  auxw_pre, Seg__addr(seg1), Seg__size(seg1), auxw_post );
            VG_(pp_ExeContext)(Seg__where(seg1));
         }
         which = "Second arg";
      } else {
         which = "Both args";
      }
      if (NONPTR == seg2) {
         emit( "%s%s not a pointer%s\n", auxw_pre, which, auxw_post );
      } else {
         emit( "%s%s derived from address %#lx of "
               "%lu-byte block alloc'd%s\n",
               auxw_pre, which, Seg__addr(seg2), Seg__size(seg2), auxw_post );
         VG_(pp_ExeContext)(Seg__where(seg2));
      }
      break;
   }

   //----------------------------------------------------------
   case XE_SysParam: {
      Addr  lo    = xe->XE.SysParam.lo;
      Addr  hi    = xe->XE.SysParam.hi;
      Seg*  seglo = xe->XE.SysParam.seglo;
      Seg*  seghi = xe->XE.SysParam.seghi;
      Char* s     = VG_(get_error_string) (err);
      Char* what;

      tl_assert(BOTTOM != seglo && BOTTOM != seghi);

      if      (Vg_CoreSysCall == xe->XE.SysParam.part) 
                 what = "Syscall param ";
      else    VG_(tool_panic)("bad CorePart");

      if (seglo == seghi) {
         // freed block
         tl_assert(is_known_segment(seglo));
         tl_assert(Seg__is_freed(seglo)); // XXX what if it's now recycled?

         if (VG_(clo_xml))
            VG_(printf_xml)("  <kind>SysParam</kind>\n");
         emit( "%s%s%s contains unaddressable byte(s)%s\n",
               what_pre, what, s, what_post );
         VG_(pp_ExeContext)( VG_(get_error_where)(err) );

         emit( "%sAddress %#lx is %ld bytes inside a "
               "%ld-byte block free'd%s\n",
               auxw_pre, lo, lo-Seg__addr(seglo),
               Seg__size(seglo), auxw_post );
         VG_(pp_ExeContext)(Seg__where(seglo));
      } else {
         // mismatch
         if (VG_(clo_xml))
            VG_(printf_xml)("  <kind>SysParam</kind>\n");
         emit( "%s%s%s is non-contiguous%s\n",
               what_pre, what, s, what_post );
         VG_(pp_ExeContext)( VG_(get_error_where)(err) );

         if (UNKNOWN == seglo) {
            emit( "%sFirst byte is not inside a known block%s\n",
                  auxw_pre, auxw_post );
         } else {
            emit( "%sFirst byte (%#lx) is %ld bytes inside a "
                  "%ld-byte block alloc'd%s\n",
                  auxw_pre, lo, lo-Seg__addr(seglo), 
                  Seg__size(seglo), auxw_post );
            VG_(pp_ExeContext)(Seg__where(seglo));
         }

         if (UNKNOWN == seghi) {
            emit( "%sLast byte is not inside a known block%s\n",
                  auxw_pre, auxw_post );
         } else {
            emit( "%sLast byte (%#lx) is %ld bytes inside a "
                  "%ld-byte block alloc'd%s\n",
                  auxw_pre, hi, hi-Seg__addr(seghi),
                  Seg__size(seghi), auxw_post );
            VG_(pp_ExeContext)(Seg__where(seghi));
         }
      }
      break;
   }

   default:
      VG_(tool_panic)("pp_Error: unrecognised error kind");
   }
}


UInt pc_update_Error_extra ( Error* err )
{
   XError *xe = (XError*)VG_(get_error_extra)(err);
   tl_assert(xe);
   switch (xe->tag) {
      case XE_SorG:
         return sizeof(XError);
      case XE_Heap: {
         tl_assert(sizeof(xe->XE.Heap.descr1) == sizeof(xe->XE.Heap.descr2));
         tl_assert(sizeof(xe->XE.Heap.descr1) > 0);
         tl_assert(sizeof(xe->XE.Heap.datasym) > 0);
         VG_(memset)(&xe->XE.Heap.descr1, 0, sizeof(xe->XE.Heap.descr1));
         VG_(memset)(&xe->XE.Heap.descr2, 0, sizeof(xe->XE.Heap.descr2));
         VG_(memset)(&xe->XE.Heap.datasym, 0, sizeof(xe->XE.Heap.datasym));
         xe->XE.Heap.datasymoff = 0;
         if (VG_(get_data_description)( &xe->XE.Heap.descr1[0],
                                        &xe->XE.Heap.descr2[0],
                                        sizeof(xe->XE.Heap.descr1)-1,
                                        xe->XE.Heap.addr )) {
            tl_assert(xe->XE.Heap.descr1[sizeof(xe->XE.Heap.descr1)-1] == 0);
            tl_assert(xe->XE.Heap.descr1[sizeof(xe->XE.Heap.descr2)-1] == 0);
         }
         else
         if (VG_(get_datasym_and_offset)( xe->XE.Heap.addr,
                                          &xe->XE.Heap.datasym[0],
                                          sizeof(xe->XE.Heap.datasym)-1,
                                          &xe->XE.Heap.datasymoff )) {
            tl_assert(xe->XE.Heap.datasym[sizeof(xe->XE.Heap.datasym)-1] == 0);
         }
         return sizeof(XError);
      }
      case XE_Arith:
         return sizeof(XError);
      case XE_SysParam:
         return sizeof(XError);
      default:
         VG_(tool_panic)("update_extra");
   }
}

Bool pc_is_recognised_suppression ( Char* name, Supp *su )
{
   SuppKind skind;

   if      (VG_STREQ(name, "SorG"))     skind = XS_SorG;
   else if (VG_STREQ(name, "Heap"))     skind = XS_Heap;
   else if (VG_STREQ(name, "Arith"))    skind = XS_Arith;
   else if (VG_STREQ(name, "SysParam")) skind = XS_SysParam;
   else
      return False;

   VG_(set_supp_kind)(su, skind);
   return True;
}

Bool pc_read_extra_suppression_info ( Int fd, Char* buf, 
                                      Int nBuf, Supp* su )
{
   Bool eof;
   if (VG_(get_supp_kind)(su) == XS_SysParam) {
      eof = VG_(get_line) ( fd, buf, nBuf );
      if (eof) return False;
      VG_(set_supp_string)(su, VG_(strdup)("pc.common.presi.1", buf));
   }
   return True;
}

Bool pc_error_matches_suppression (Error* err, Supp* su)
{
   ErrorKind ekind = VG_(get_error_kind)(err);
   switch (VG_(get_supp_kind)(su)) {
      case XS_SorG:     return ekind == XE_SorG;
      case XS_Heap:     return ekind == XE_Heap;
      case XS_Arith:    return ekind == XE_Arith;
      case XS_SysParam: return ekind == XE_SysParam;
      default:
         VG_(printf)("Error:\n"
                     "  unknown suppression type %d\n",
                     VG_(get_supp_kind)(su));
         VG_(tool_panic)("unknown suppression type in "
                         "pc_error_matches_suppression");
   }
}

Char* pc_get_error_name ( Error* err )
{
   XError *xe = (XError*)VG_(get_error_extra)(err);
   tl_assert(xe);
   switch (xe->tag) {
      case XE_SorG:     return "SorG";
      case XE_Heap:     return "Heap";
      case XE_Arith:    return "Arith";
      case XE_SysParam: return "SysParam";
      default:          VG_(tool_panic)("get_error_name: unexpected type");
   }
}

void pc_print_extra_suppression_info ( Error* err )
{
   if (XE_SysParam == VG_(get_error_kind)(err)) {
      VG_(printf)("   %s\n", VG_(get_error_string)(err));
   }
}




/*--------------------------------------------------------------------*/
/*--- end                                              pc_common.c ---*/
/*--------------------------------------------------------------------*/
