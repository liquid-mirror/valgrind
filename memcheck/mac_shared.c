
/*--------------------------------------------------------------------*/
/*--- Code that is shared between MemCheck and AddrCheck.          ---*/
/*---                                                 mac_shared.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of MemCheck, a heavyweight Valgrind tool for
   detecting memory errors.

   Copyright (C) 2000-2005 Julian Seward 
      jseward@acm.org

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
*/

#include "pub_tool_basics.h"
#include "pub_tool_errormgr.h"      // For mc_include.h
#include "pub_tool_execontext.h"    // For mc_include.h
#include "pub_tool_hashtable.h"     // For mc_include.h
#include "pub_tool_libcassert.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_machine.h"
#include "pub_tool_options.h"
#include "pub_tool_profile.h"       // For mc_include.h
#include "pub_tool_replacemalloc.h"
#include "pub_tool_threadstate.h"
#include "mc_include.h"
#include "memcheck.h"   /* for VG_USERREQ__* */

/*------------------------------------------------------------*/
/*--- Defns                                                ---*/
/*------------------------------------------------------------*/

/* These many bytes below %ESP are considered addressible if we're
   doing the --workaround-gcc296-bugs hack. */
#define VG_GCC296_BUG_STACK_SLOP 1024

/*------------------------------------------------------------*/
/*--- Comparing and printing errors                        ---*/
/*------------------------------------------------------------*/

static __inline__
void clear_AddrInfo ( AddrInfo* ai )
{
   ai->akind      = Unknown;
   ai->blksize    = 0;
   ai->rwoffset   = 0;
   ai->lastchange = NULL;
   ai->stack_tid  = VG_INVALID_THREADID;
   ai->maybe_gcc  = False;
   ai->desc       = NULL;
}

void MAC_(clear_MAC_Error) ( MAC_Error* err_extra )
{
   err_extra->axskind   = ReadAxs;
   err_extra->size      = 0;
   clear_AddrInfo ( &err_extra->addrinfo );
   err_extra->isUnaddr  = True;
}

__attribute__ ((unused))
static Bool eq_AddrInfo ( VgRes res, AddrInfo* ai1, AddrInfo* ai2 )
{
   if (ai1->akind != Undescribed 
       && ai2->akind != Undescribed
       && ai1->akind != ai2->akind) 
      return False;
   if (ai1->akind == Freed || ai1->akind == Mallocd) {
      if (ai1->blksize != ai2->blksize)
         return False;
      if (!VG_(eq_ExeContext)(res, ai1->lastchange, ai2->lastchange))
         return False;
   }
   return True;
}

/* Compare error contexts, to detect duplicates.  Note that if they
   are otherwise the same, the faulting addrs and associated rwoffsets
   are allowed to be different.  */

Bool MAC_(eq_Error) ( VgRes res, Error* e1, Error* e2 )
{
   MAC_Error* e1_extra = VG_(get_error_extra)(e1);
   MAC_Error* e2_extra = VG_(get_error_extra)(e2);

   /* Guaranteed by calling function */
   tl_assert(VG_(get_error_kind)(e1) == VG_(get_error_kind)(e2));
   
   switch (VG_(get_error_kind)(e1)) {
      case CoreMemErr: {
         Char *e1s, *e2s;
         if (e1_extra->isUnaddr != e2_extra->isUnaddr) return False;
         e1s = VG_(get_error_string)(e1);
         e2s = VG_(get_error_string)(e2);
         if (e1s == e2s)                               return True;
         if (0 == VG_(strcmp)(e1s, e2s))               return True;
         return False;
      }

      // Perhaps we should also check the addrinfo.akinds for equality.
      // That would result in more error reports, but only in cases where
      // a register contains uninitialised bytes and points to memory
      // containing uninitialised bytes.  Currently, the 2nd of those to be
      // detected won't be reported.  That is (nearly?) always the memory
      // error, which is good.
      case ParamErr:
         if (0 != VG_(strcmp)(VG_(get_error_string)(e1),
                              VG_(get_error_string)(e2)))   return False;
         // fall through
      case UserErr:
         if (e1_extra->isUnaddr != e2_extra->isUnaddr)      return False;
         return True;

      case FreeErr:
      case FreeMismatchErr:
         /* JRS 2002-Aug-26: comparing addrs seems overkill and can
            cause excessive duplication of errors.  Not even AddrErr
            below does that.  So don't compare either the .addr field
            or the .addrinfo fields. */
         /* if (e1->addr != e2->addr) return False; */
         /* if (!eq_AddrInfo(res, &e1_extra->addrinfo, &e2_extra->addrinfo)) 
               return False;
         */
         return True;

      case AddrErr:
         /* if (e1_extra->axskind != e2_extra->axskind) return False; */
         if (e1_extra->size != e2_extra->size) return False;
         /*
         if (!eq_AddrInfo(res, &e1_extra->addrinfo, &e2_extra->addrinfo)) 
            return False;
         */
         return True;

      case ValueErr:
         if (e1_extra->size != e2_extra->size) return False;
         return True;

      case OverlapErr:
         return True;

      case LeakErr:
         VG_(tool_panic)("Shouldn't get LeakErr in MAC_(eq_Error),\n"
                         "since it's handled with VG_(unique_error)()!");

      case IllegalMempoolErr:
         return True;

      default: 
         VG_(printf)("Error:\n  unknown error code %d\n",
                     VG_(get_error_kind)(e1));
         VG_(tool_panic)("unknown error code in MAC_(eq_Error)");
   }
}

void MAC_(pp_AddrInfo) ( Addr a, AddrInfo* ai )
{
   HChar* xpre  = VG_(clo_xml) ? "  <auxwhat>" : " ";
   HChar* xpost = VG_(clo_xml) ? "</auxwhat>"  : "";

   switch (ai->akind) {
      case Stack: 
         VG_(message)(Vg_UserMsg, 
                      "%sAddress 0x%llx is on thread %d's stack%s", 
                      xpre, (ULong)a, ai->stack_tid, xpost);
         break;
      case Unknown:
         if (ai->maybe_gcc) {
            VG_(message)(Vg_UserMsg, 
               "%sAddress 0x%llx is just below the stack ptr.  "
               "To suppress, use: --workaround-gcc296-bugs=yes%s",
               xpre, (ULong)a, xpost
            );
	 } else {
            VG_(message)(Vg_UserMsg, 
               "%sAddress 0x%llx "
               "is not stack'd, malloc'd or (recently) free'd%s",
               xpre, (ULong)a, xpost);
         }
         break;
      case Freed: case Mallocd: case UserG: case Mempool: {
         SizeT delta;
         const Char* relative;
         const Char* kind;
         if (ai->akind == Mempool) {
            kind = "mempool";
         } else {
            kind = "block";
         }
	 if (ai->desc != NULL)
	    kind = ai->desc;

         if (ai->rwoffset < 0) {
            delta    = (SizeT)(- ai->rwoffset);
            relative = "before";
         } else if (ai->rwoffset >= ai->blksize) {
            delta    = ai->rwoffset - ai->blksize;
            relative = "after";
         } else {
            delta    = ai->rwoffset;
            relative = "inside";
         }
         VG_(message)(Vg_UserMsg, 
            "%sAddress 0x%lx is %,lu bytes %s a %s of size %,lu %s%s",
            xpre,
            a, delta, relative, kind,
            ai->blksize,
            ai->akind==Mallocd ? "alloc'd" 
               : ai->akind==Freed ? "free'd" 
                                  : "client-defined",
            xpost);
         VG_(pp_ExeContext)(ai->lastchange);
         break;
      }
      case Register:
         // print nothing
         tl_assert(0 == a);
         break;
      default:
         VG_(tool_panic)("MAC_(pp_AddrInfo)");
   }
}

/*------------------------------------------------------------*/
/*--- Recording errors                                     ---*/
/*------------------------------------------------------------*/

/* Additional description function for describe_addr();  used by
   MemCheck for user blocks, which Addrcheck doesn't support. */
Bool (*MAC_(describe_addr_supp)) ( Addr a, AddrInfo* ai ) = NULL;

/* Function used when searching MAC_Chunk lists */
static Bool addr_is_in_MAC_Chunk(MAC_Chunk* mc, Addr a)
{
   // Nb: this is not quite right!  It assumes that the heap block has
   // a redzone of size MAC_MALLOC_REDZONE_SZB.  That's true for malloc'd
   // blocks, but not necessarily true for custom-alloc'd blocks.  So
   // in some cases this could result in an incorrect description (eg.
   // saying "12 bytes after block A" when really it's within block B.
   // Fixing would require adding redzone size to MAC_Chunks, though.
   return VG_(addr_is_in_block)( a, mc->data, mc->size,
                                 MAC_MALLOC_REDZONE_SZB );
}

/* Describe an address as best you can, for error messages,
   putting the result in ai. */
static void describe_addr ( Addr a, AddrInfo* ai )
{
   MAC_Chunk* mc;
   ThreadId   tid;
   Addr       stack_min, stack_max;

   /* Perhaps it's a user-def'd block ?  (only check if requested, though) */
   if (NULL != MAC_(describe_addr_supp)) {
      if (MAC_(describe_addr_supp)( a, ai ))
         return;
   }
   /* Perhaps it's on a thread's stack? */
   VG_(thread_stack_reset_iter)();
   while ( VG_(thread_stack_next)(&tid, &stack_min, &stack_max) ) {
      if (stack_min <= a && a <= stack_max) {
         ai->akind     = Stack;
         ai->stack_tid = tid;
         return;
      }
   }
   /* Search for a recently freed block which might bracket it. */
   mc = MAC_(get_freed_list_head)();
   while (mc) {
      if (addr_is_in_MAC_Chunk(mc, a)) {
         ai->akind      = Freed;
         ai->blksize    = mc->size;
         ai->rwoffset   = (Int)a - (Int)mc->data;
         ai->lastchange = mc->where;
         return;
      }
      mc = mc->next; 
   }
   /* Search for a currently malloc'd block which might bracket it. */
   VG_(HT_ResetIter)(MAC_(malloc_list));
   while ( (mc = VG_(HT_Next)(MAC_(malloc_list))) ) {
      if (addr_is_in_MAC_Chunk(mc, a)) {
         ai->akind      = Mallocd;
         ai->blksize    = mc->size;
         ai->rwoffset   = (Int)(a) - (Int)mc->data;
         ai->lastchange = mc->where;
         return;
      }
   }
   /* Clueless ... */
   ai->akind = Unknown;
   return;
}

/* Is this address within some small distance below %ESP?  Used only
   for the --workaround-gcc296-bugs kludge. */
static Bool is_just_below_ESP( Addr esp, Addr aa )
{
   if (esp > aa && (esp - aa) <= VG_GCC296_BUG_STACK_SLOP)
      return True;
   else
      return False;
}

/* This one called from generated code and non-generated code. */

void MAC_(record_address_error) ( ThreadId tid, Addr a, Int size,
                                  Bool isWrite )
{
   MAC_Error err_extra;
   Bool      just_below_esp;

   just_below_esp = is_just_below_ESP( VG_(get_SP)(tid), a );

   /* If this is caused by an access immediately below %ESP, and the
      user asks nicely, we just ignore it. */
   if (MC_(clo_workaround_gcc296_bugs) && just_below_esp)
      return;

   MAC_(clear_MAC_Error)( &err_extra );
   err_extra.axskind = isWrite ? WriteAxs : ReadAxs;
   err_extra.size    = size;
   err_extra.addrinfo.akind     = Undescribed;
   err_extra.addrinfo.maybe_gcc = just_below_esp;
   VG_(maybe_record_error)( tid, AddrErr, a, /*s*/NULL, &err_extra );
}

/* These ones are called from non-generated code */

/* This is for memory errors in pthread functions, as opposed to pthread API
   errors which are found by the core. */
void MAC_(record_core_mem_error) ( ThreadId tid, Bool isUnaddr, Char* msg )
{
   MAC_Error err_extra;

   MAC_(clear_MAC_Error)( &err_extra );
   err_extra.isUnaddr = isUnaddr;
   VG_(maybe_record_error)( tid, CoreMemErr, /*addr*/0, msg, &err_extra );
}

// Three kinds of param errors:
// - register arg contains undefined bytes
// - memory arg is unaddressable
// - memory arg contains undefined bytes
// 'isReg' and 'isUnaddr' dictate which of these it is.
void MAC_(record_param_error) ( ThreadId tid, Addr a, Bool isReg,
                                Bool isUnaddr, Char* msg )
{
   MAC_Error err_extra;

   tl_assert(VG_INVALID_THREADID != tid);
   if (isUnaddr) tl_assert(!isReg);    // unaddressable register is impossible
   MAC_(clear_MAC_Error)( &err_extra );
   err_extra.addrinfo.akind = ( isReg ? Register : Undescribed );
   err_extra.isUnaddr = isUnaddr;
   VG_(maybe_record_error)( tid, ParamErr, a, msg, &err_extra );
}

void MAC_(record_jump_error) ( ThreadId tid, Addr a )
{
   MAC_Error err_extra;

   tl_assert(VG_INVALID_THREADID != tid);
   MAC_(clear_MAC_Error)( &err_extra );
   err_extra.axskind = ExecAxs;
   err_extra.size    = 1;     // size only used for suppressions
   err_extra.addrinfo.akind = Undescribed;
   VG_(maybe_record_error)( tid, AddrErr, a, /*s*/NULL, &err_extra );
}

void MAC_(record_free_error) ( ThreadId tid, Addr a ) 
{
   MAC_Error err_extra;

   tl_assert(VG_INVALID_THREADID != tid);
   MAC_(clear_MAC_Error)( &err_extra );
   err_extra.addrinfo.akind = Undescribed;
   VG_(maybe_record_error)( tid, FreeErr, a, /*s*/NULL, &err_extra );
}

void MAC_(record_illegal_mempool_error) ( ThreadId tid, Addr a ) 
{
   MAC_Error err_extra;

   tl_assert(VG_INVALID_THREADID != tid);
   MAC_(clear_MAC_Error)( &err_extra );
   err_extra.addrinfo.akind = Undescribed;
   VG_(maybe_record_error)( tid, IllegalMempoolErr, a, /*s*/NULL, &err_extra );
}

void MAC_(record_freemismatch_error) ( ThreadId tid, Addr a, MAC_Chunk* mc )
{
   MAC_Error err_extra;
   AddrInfo* ai;

   tl_assert(VG_INVALID_THREADID != tid);
   MAC_(clear_MAC_Error)( &err_extra );
   ai = &err_extra.addrinfo;
   ai->akind      = Mallocd;     // Nb: not 'Freed'
   ai->blksize    = mc->size;
   ai->rwoffset   = (Int)a - (Int)mc->data;
   ai->lastchange = mc->where;
   VG_(maybe_record_error)( tid, FreeMismatchErr, a, /*s*/NULL, &err_extra );
}

void MAC_(record_overlap_error) ( ThreadId tid, 
                                  Char* function, OverlapExtra* ov_extra )
{
   VG_(maybe_record_error)( 
      tid, OverlapErr, /*addr*/0, /*s*/function, ov_extra );
}


/* Updates the copy with address info if necessary (but not for all errors). */
UInt MAC_(update_extra)( Error* err )
{
   switch (VG_(get_error_kind)(err)) {
   // These two don't have addresses associated with them, and so don't
   // need any updating.
   case CoreMemErr:
   case ValueErr: {
      MAC_Error* extra = VG_(get_error_extra)(err);
      tl_assert(Unknown == extra->addrinfo.akind);
      return sizeof(MAC_Error);
   }

   // ParamErrs sometimes involve a memory address; call describe_addr() in
   // this case.
   case ParamErr: {
      MAC_Error* extra = VG_(get_error_extra)(err);
      tl_assert(Undescribed == extra->addrinfo.akind ||
                Register    == extra->addrinfo.akind);
      if (Undescribed == extra->addrinfo.akind)
         describe_addr ( VG_(get_error_address)(err), &(extra->addrinfo) );
      return sizeof(MAC_Error);
   }

   // These four always involve a memory address.
   case AddrErr: 
   case UserErr:
   case FreeErr:
   case IllegalMempoolErr: {
      MAC_Error* extra = VG_(get_error_extra)(err);
      tl_assert(Undescribed == extra->addrinfo.akind);
      describe_addr ( VG_(get_error_address)(err), &(extra->addrinfo) );
      return sizeof(MAC_Error);
   }

   // FreeMismatchErrs have already had their address described;  this is
   // possible because we have the MAC_Chunk on hand when the error is
   // detected.  However, the address may be part of a user block, and if so
   // we override the pre-determined description with a user block one.
   case FreeMismatchErr: {
      MAC_Error* extra = VG_(get_error_extra)(err);
      tl_assert(extra && Mallocd == extra->addrinfo.akind);
      if (NULL != MAC_(describe_addr_supp))
         (void)MAC_(describe_addr_supp)( VG_(get_error_address)(err), 
                                         &(extra->addrinfo) );
      return sizeof(MAC_Error);
   }

   // No memory address involved with these ones.  Nb:  for LeakErrs the
   // returned size does not matter -- LeakErrs are always shown with
   // VG_(unique_error)() so they're not copied.
   case LeakErr:     return 0;
   case OverlapErr:  return sizeof(OverlapExtra);

   default: VG_(tool_panic)("update_extra: bad errkind");
   }
}


/*------------------------------------------------------------*/
/*--- Suppressions                                         ---*/
/*------------------------------------------------------------*/

Bool MAC_(shared_recognised_suppression) ( Char* name, Supp* su )
{
   SuppKind skind;

   if      (VG_STREQ(name, "Param"))   skind = ParamSupp;
   else if (VG_STREQ(name, "CoreMem")) skind = CoreMemSupp;
   else if (VG_STREQ(name, "Addr1"))   skind = Addr1Supp;
   else if (VG_STREQ(name, "Addr2"))   skind = Addr2Supp;
   else if (VG_STREQ(name, "Addr4"))   skind = Addr4Supp;
   else if (VG_STREQ(name, "Addr8"))   skind = Addr8Supp;
   else if (VG_STREQ(name, "Addr16"))  skind = Addr16Supp;
   else if (VG_STREQ(name, "Free"))    skind = FreeSupp;
   else if (VG_STREQ(name, "Leak"))    skind = LeakSupp;
   else if (VG_STREQ(name, "Overlap")) skind = OverlapSupp;
   else if (VG_STREQ(name, "Mempool")) skind = MempoolSupp;
   else
      return False;

   VG_(set_supp_kind)(su, skind);
   return True;
}

Bool MAC_(read_extra_suppression_info) ( Int fd, Char* buf, Int nBuf, Supp *su )
{
   Bool eof;

   if (VG_(get_supp_kind)(su) == ParamSupp) {
      eof = VG_(get_line) ( fd, buf, nBuf );
      if (eof) return False;
      VG_(set_supp_string)(su, VG_(strdup)(buf));
   }
   return True;
}

Bool MAC_(error_matches_suppression)(Error* err, Supp* su)
{
   Int        su_size;
   MAC_Error* err_extra = VG_(get_error_extra)(err);
   ErrorKind  ekind     = VG_(get_error_kind )(err);

   switch (VG_(get_supp_kind)(su)) {
      case ParamSupp:
         return (ekind == ParamErr 
              && VG_STREQ(VG_(get_error_string)(err), 
                          VG_(get_supp_string)(su)));

      case CoreMemSupp:
         return (ekind == CoreMemErr
              && VG_STREQ(VG_(get_error_string)(err),
                          VG_(get_supp_string)(su)));

      case Value0Supp: su_size = 0; goto value_case;
      case Value1Supp: su_size = 1; goto value_case;
      case Value2Supp: su_size = 2; goto value_case;
      case Value4Supp: su_size = 4; goto value_case;
      case Value8Supp: su_size = 8; goto value_case;
      case Value16Supp:su_size =16; goto value_case;
      value_case:
         return (ekind == ValueErr && err_extra->size == su_size);

      case Addr1Supp: su_size = 1; goto addr_case;
      case Addr2Supp: su_size = 2; goto addr_case;
      case Addr4Supp: su_size = 4; goto addr_case;
      case Addr8Supp: su_size = 8; goto addr_case;
      case Addr16Supp:su_size =16; goto addr_case;
      addr_case:
         return (ekind == AddrErr && err_extra->size == su_size);

      case FreeSupp:
         return (ekind == FreeErr || ekind == FreeMismatchErr);

      case OverlapSupp:
         return (ekind = OverlapErr);

      case LeakSupp:
         return (ekind == LeakErr);

      case MempoolSupp:
         return (ekind == IllegalMempoolErr);

      default:
         VG_(printf)("Error:\n"
                     "  unknown suppression type %d\n",
                     VG_(get_supp_kind)(su));
         VG_(tool_panic)("unknown suppression type in "
                         "MAC_(error_matches_suppression)");
   }
}

Char* MAC_(get_error_name) ( Error* err )
{
   Char* s;
   switch (VG_(get_error_kind)(err)) {
   case ParamErr:           return "Param";
   case UserErr:            return NULL;  /* Can't suppress User errors */
   case FreeMismatchErr:    return "Free";
   case IllegalMempoolErr:  return "Mempool";
   case FreeErr:            return "Free";
   case AddrErr:            
      switch ( ((MAC_Error*)VG_(get_error_extra)(err))->size ) {
      case 1:               return "Addr1";
      case 2:               return "Addr2";
      case 4:               return "Addr4";
      case 8:               return "Addr8";
      case 16:              return "Addr16";
      default:              VG_(tool_panic)("unexpected size for Addr");
      }
     
   case ValueErr:
      switch ( ((MAC_Error*)VG_(get_error_extra)(err))->size ) {
      case 0:               return "Cond";
      case 1:               return "Value1";
      case 2:               return "Value2";
      case 4:               return "Value4";
      case 8:               return "Value8";
      case 16:              return "Value16";
      default:              VG_(tool_panic)("unexpected size for Value");
      }
   case CoreMemErr:         return "CoreMem";
   case OverlapErr:         return "Overlap";
   case LeakErr:            return "Leak";
   default:                 VG_(tool_panic)("get_error_name: unexpected type");
   }
   VG_(printf)(s);
}

void MAC_(print_extra_suppression_info) ( Error* err )
{
   if (ParamErr == VG_(get_error_kind)(err)) {
      VG_(printf)("   %s\n", VG_(get_error_string)(err));
   }
}

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
