
/*--------------------------------------------------------------------*/
/*---                                     vg_memcheck_errcontext.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, an x86 protected-mode emulator 
   designed for debugging and profiling binaries on x86-Unixes.

   Copyright (C) 2000-2002 Julian Seward 
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

   The GNU General Public License is contained in the file LICENSE.
*/

#include "vg_memcheck_include.h"

/*------------------------------------------------------------*/
/*--- Defns                                                ---*/
/*------------------------------------------------------------*/

typedef 
   enum { 
      /* Bad syscall params */
      Param = FinalDummySuppressionKind + 1,
      /* Memory errors in core (pthread ops, signal handling) */
      CoreMem,
      /* Use of invalid values of given size */
      Value0, Value1, Value2, Value4, Value8, 
      /* Invalid read/write attempt at given size */
      Addr1, Addr2, Addr4, Addr8,
      /* Invalid or mismatching free */
      FreeS
   } 
   MemCheckSuppressionKind;

/* What kind of error it is. */
typedef 
   enum { ValueErr = FinalDummyErrKind + 1,
          CoreMemErr,
          AddrErr, 
          ParamErr, UserErr, /* behaves like an anonymous ParamErr */
          FreeErr, FreeMismatchErr
   }
   MemCheckErrKind;

/* What kind of memory access is involved in the error? */
typedef
   enum { ReadAxs, WriteAxs, ExecAxs }
   AxsKind;

/* Top-level struct for recording errors. */
typedef
   struct {
      /* AddrErr */
      AxsKind axskind;
      /* AddrErr, ValueErr */
      Int size;
      /* AddrErr, FreeErr, FreeMismatchErr, ParamErr, UserErr */
      AddrInfo addrinfo;
      /* ParamErr, UserErr, CoreMemErr */
      Bool isWrite;
   }
   MemCheckErrContext;

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
}

static __inline__
void clear_MemCheckErrContext ( MemCheckErrContext* ec_extra )
{
   ec_extra->axskind = ReadAxs;
   ec_extra->size    = 0;
   clear_AddrInfo ( &ec_extra->addrinfo );
   ec_extra->isWrite = False;
}

static __inline__
Bool vg_eq_ExeContext ( Bool top_2_only,
                        ExeContext* e1, ExeContext* e2 )
{
   /* Note that frames after the 4th are always ignored. */
   if (top_2_only) {
      return VG_(eq_ExeContext_top2(e1, e2));
   } else {
      return VG_(eq_ExeContext_top4(e1, e2));
   }
}

static Bool eq_AddrInfo ( Bool cheap_addr_cmp,
                          AddrInfo* ai1, AddrInfo* ai2 )
{
   if (ai1->akind != Undescribed 
       && ai2->akind != Undescribed
       && ai1->akind != ai2->akind) 
      return False;
   if (ai1->akind == Freed || ai1->akind == Mallocd) {
      if (ai1->blksize != ai2->blksize)
         return False;
      if (!vg_eq_ExeContext(cheap_addr_cmp, 
                            ai1->lastchange, ai2->lastchange))
         return False;
   }
   return True;
}

/* Compare error contexts, to detect duplicates.  Note that if they
   are otherwise the same, the faulting addrs and associated rwoffsets
   are allowed to be different.  */

Bool SKN_(eq_ErrContext) ( Bool cheap_addr_cmp,
                            ErrContext* e1, ErrContext* e2 )
{
   MemCheckErrContext* e1_extra = e1->extra;
   MemCheckErrContext* e2_extra = e2->extra;
   
   switch (e1->ekind) {
      case CoreMemErr:
         if (e1_extra->isWrite != e2_extra->isWrite)   return False;
         if (e2->ekind != PThreadErr)                  return False; 
         if (e1->string == e2->string)                 return True;
         if (0 == VG_(strcmp)(e1->string, e2->string)) return True;
         return False;

      case UserErr:
      case ParamErr:
         if (e1_extra->isWrite != e2_extra->isWrite)
            return False;
         if (e1->ekind == ParamErr 
             && 0 != VG_(strcmp)(e1->string, e2->string))
            return False;
         return True;

      case FreeErr:
      case FreeMismatchErr:
         if (e1->addr != e2->addr) return False;
         if (!eq_AddrInfo(cheap_addr_cmp, 
                          &e1_extra->addrinfo, &e2_extra->addrinfo)) 
            return False;
         return True;

      case AddrErr:
         if (e1_extra->axskind != e2_extra->axskind) return False;
         if (e1_extra->size != e2_extra->size) return False;
         if (!eq_AddrInfo(cheap_addr_cmp, 
                          &e1_extra->addrinfo, &e2_extra->addrinfo)) 
            return False;
         return True;

      case ValueErr:
         if (e1_extra->size != e2_extra->size) return False;
         return True;

      default: 
         VG_(printf)("Error:\n  unknown MemCheck error code %d\n", e1->ekind);
         VG_(panic)("unknown error code in SKN_(eq_ErrContext)");
   }
}

static void pp_AddrInfo ( Addr a, AddrInfo* ai )
{
   switch (ai->akind) {
      case Stack: 
         VG_(message)(Vg_UserMsg, 
                      "   Address 0x%x is on thread %d's stack", 
                      a, ai->stack_tid);
         break;
      case Unknown:
         if (ai->maybe_gcc) {
            VG_(message)(Vg_UserMsg, 
               "   Address 0x%x is just below %%esp.  Possibly a bug in GCC/G++",
               a);
            VG_(message)(Vg_UserMsg, 
               "   v 2.96 or 3.0.X.  To suppress, use: --workaround-gcc296-bugs=yes");
	 } else {
            VG_(message)(Vg_UserMsg, 
               "   Address 0x%x is not stack'd, malloc'd or free'd", a);
         }
         break;
      case Freed: case Mallocd: case UserG: case UserS: {
         UInt delta;
         UChar* relative;
         if (ai->rwoffset < 0) {
            delta    = (UInt)(- ai->rwoffset);
            relative = "before";
         } else if (ai->rwoffset >= ai->blksize) {
            delta    = ai->rwoffset - ai->blksize;
            relative = "after";
         } else {
            delta    = ai->rwoffset;
            relative = "inside";
         }
         if (ai->akind == UserS) {
            VG_(message)(Vg_UserMsg, 
               "   Address 0x%x is %d bytes %s a %d-byte stack red-zone created",
               a, delta, relative, 
               ai->blksize );
	 } else {
            VG_(message)(Vg_UserMsg, 
               "   Address 0x%x is %d bytes %s a block of size %d %s",
               a, delta, relative, 
               ai->blksize,
               ai->akind==Mallocd ? "alloc'd" 
                  : ai->akind==Freed ? "free'd" 
                                     : "client-defined");
         }
         VG_(pp_ExeContext)(ai->lastchange);
         break;
      }
      default:
         VG_(panic)("pp_AddrInfo");
   }
}

void SKN_(pp_ErrContext) ( ErrContext* ec )
{
   MemCheckErrContext* ec_extra = ec->extra;

   switch (ec->ekind) {
      case CoreMemErr:
         if (ec_extra->isWrite) {
            VG_(message)(Vg_UserMsg, 
               "%s contains unaddressable byte(s)", ec->string );
         } else {
            VG_(message)(Vg_UserMsg, 
                "%s contains uninitialised or unaddressable byte(s)",
                ec->string);
         }
         VG_(pp_ExeContext)(ec->where);
         break;
      
      case ValueErr:
         if (ec_extra->size == 0) {
             VG_(message)(
                Vg_UserMsg,
                "Conditional jump or move depends on uninitialised value(s)");
         } else {
             VG_(message)(Vg_UserMsg,
                          "Use of uninitialised value of size %d",
                          ec_extra->size);
         }
         VG_(pp_ExeContext)(ec->where);
         break;

      case AddrErr:
         switch (ec_extra->axskind) {
            case ReadAxs:
               VG_(message)(Vg_UserMsg, "Invalid read of size %d", 
                                        ec_extra->size ); 
               break;
            case WriteAxs:
               VG_(message)(Vg_UserMsg, "Invalid write of size %d", 
                                        ec_extra->size ); 
               break;
            case ExecAxs:
               VG_(message)(Vg_UserMsg, "Jump to the invalid address "
                                        "stated on the next line");
               break;
            default: 
               VG_(panic)("pp_ErrContext(axskind)");
         }
         VG_(pp_ExeContext)(ec->where);
         pp_AddrInfo(ec->addr, &ec_extra->addrinfo);
         break;

      case FreeErr:
         VG_(message)(Vg_UserMsg,"Invalid free() / delete / delete[]");
         /* fall through */
      case FreeMismatchErr:
         if (ec->ekind == FreeMismatchErr)
            VG_(message)(Vg_UserMsg, 
                         "Mismatched free() / delete / delete []");
         VG_(pp_ExeContext)(ec->where);
         pp_AddrInfo(ec->addr, &ec_extra->addrinfo);
         break;

      case ParamErr:
         if (ec_extra->isWrite) {
            VG_(message)(Vg_UserMsg, 
               "Syscall param %s contains unaddressable byte(s)",
                ec->string );
         } else {
            VG_(message)(Vg_UserMsg, 
                "Syscall param %s contains uninitialised or "
                "unaddressable byte(s)",
            ec->string);
         }
         VG_(pp_ExeContext)(ec->where);
         pp_AddrInfo(ec->addr, &ec_extra->addrinfo);
         break;

      case UserErr:
         if (ec_extra->isWrite) {
            VG_(message)(Vg_UserMsg, 
               "Unaddressable byte(s) found during client check request");
         } else {
            VG_(message)(Vg_UserMsg, 
               "Uninitialised or "
               "unaddressable byte(s) found during client check request");
         }
         VG_(pp_ExeContext)(ec->where);
         pp_AddrInfo(ec->addr, &ec_extra->addrinfo);
         break;

      default: 
         VG_(printf)("Error:\n  unknown MemCheck error code %d\n", ec->ekind);
         VG_(panic)("unknown error code in SKN_(pp_ErrContext)");
   }
}

/*------------------------------------------------------------*/
/*--- Recording errors                                     ---*/
/*------------------------------------------------------------*/

/* Describe an address as best you can, for error messages,
   putting the result in ai. */

static void describe_addr ( Addr a, AddrInfo* ai )
{
   ShadowChunk* sc;
   UInt         ml_no;
   Bool         ok;
   ThreadId     tid;

   /* Perhaps it's a user-def'd block ? */
   ok = SK_(client_perm_maybe_describe)( a, ai );
   if (ok)
      return;
   /* Perhaps it's on a thread's stack? */
   tid = VG_(identify_stack_addr)(a);
   if (tid != VG_INVALID_THREADID) {
      ai->akind     = Stack;
      ai->stack_tid = tid;
      return;
   }
   /* Search for a freed block which might bracket it. */
   for (sc = VG_(freed_list_start); sc != NULL; sc = sc->next) {
      if (sc->data - VG_AR_CLIENT_REDZONE_SZB <= a
          && a < sc->data + sc->size + VG_AR_CLIENT_REDZONE_SZB) {
         ai->akind      = Freed;
         ai->blksize    = sc->size;
         ai->rwoffset   = (Int)(a) - (Int)(sc->data);
         ai->lastchange = sc->where;
         return;
      }
   }
   /* Search for a mallocd block which might bracket it. */
   for (ml_no = 0; ml_no < VG_N_MALLOCLISTS; ml_no++) {
      for (sc = VG_(malloclist)[ml_no]; sc != NULL; sc = sc->next) {
         if (sc->data - VG_AR_CLIENT_REDZONE_SZB <= a
             && a < sc->data + sc->size + VG_AR_CLIENT_REDZONE_SZB) {
            ai->akind      = Mallocd;
            ai->blksize    = sc->size;
            ai->rwoffset   = (Int)(a) - (Int)(sc->data);
            ai->lastchange = sc->where;
            return;
         }
      }
   }
   /* Clueless ... */
   ai->akind = Unknown;
   return;
}


/* Creates a copy of the ec_extra, updates the copy with address info if
   necessary, sticks the copy into the ErrContext. */
void SKN_(dup_extra_and_update)(ErrContext* ec)
{
   MemCheckErrContext* p_extra;
   
   p_extra  = VG_(malloc)(VG_AR_ERRCTXT, sizeof(MemCheckErrContext));
   *p_extra = *((MemCheckErrContext*)ec->extra);

   if (p_extra->addrinfo.akind == Undescribed)
      describe_addr ( ec->addr, &(p_extra->addrinfo) );

   ec->extra = p_extra;
}

/* These two are called from generated code. */
void SK_(record_value_error) ( Int size )
{
   ErrContext ec;
   MemCheckErrContext ec_extra;

   if (VG_(ignore_errors)()) return;

   /* No address to note: hence the '0' */
   VG_(construct_err_context)( &ec, ValueErr, 0, NULL, NULL );
   clear_MemCheckErrContext( &ec_extra );
   ec_extra.size = size;
   ec.extra = &ec_extra;

   VG_(maybe_add_context) ( &ec );
}

/* Is this address within some small distance below %ESP?  Used only
   for the --workaround-gcc296-bugs kludge. */
Bool VG_(is_just_below_ESP)( Addr esp, Addr aa )
{
   if ((UInt)esp > (UInt)aa
       && ((UInt)esp - (UInt)aa) <= VG_GCC296_BUG_STACK_SLOP)
      return True;
   else
      return False;
}

void SK_(record_address_error) ( Addr a, Int size, Bool isWrite )
{
   ErrContext ec;
   MemCheckErrContext ec_extra;
   Bool       just_below_esp;

   if (VG_(ignore_errors)()) return;

   just_below_esp 
      = VG_(is_just_below_ESP)( VG_(baseBlock)[VGOFF_(m_esp)], a );

   /* If this is caused by an access immediately below %ESP, and the
      user asks nicely, we just ignore it. */
   if (VG_(clo_workaround_gcc296_bugs) && just_below_esp)
      return;

   VG_(construct_err_context)( &ec, AddrErr, a, NULL, NULL );
   clear_MemCheckErrContext( &ec_extra );
   ec_extra.axskind = isWrite ? WriteAxs : ReadAxs;
   ec_extra.size    = size;
   ec_extra.addrinfo.akind     = Undescribed;
   ec_extra.addrinfo.maybe_gcc = just_below_esp;
   ec.extra = &ec_extra;

   VG_(maybe_add_context) ( &ec );
}

/* These ones are called from non-generated code */

/* This is for memory errors in pthread functions, as opposed to pthread API
   errors which are found by the core. */
void SK_(record_core_mem_error) ( ThreadState* tst, Bool isWrite, Char* msg )
{
   ErrContext ec;
   MemCheckErrContext ec_extra;

   if (VG_(ignore_errors)) return;

   /* No address to note: hence the '0' */
   VG_(construct_err_context)( &ec, CoreMemErr, 0, msg, tst );
   clear_MemCheckErrContext( &ec_extra );
   ec_extra.isWrite = isWrite;
   ec.extra = &ec_extra;

   VG_(maybe_add_context) ( &ec );
}

void SK_(record_param_error) ( ThreadState* tst, Addr a, Bool isWrite, 
                               Char* msg )
{
   ErrContext ec;
   MemCheckErrContext ec_extra;

   if (VG_(ignore_errors)()) return;

   vg_assert(NULL != tst);
   VG_(construct_err_context)( &ec, ParamErr, a, msg, tst );
   clear_MemCheckErrContext( &ec_extra );
   ec_extra.addrinfo.akind = Undescribed;
   ec_extra.isWrite = isWrite;
   ec.extra = &ec_extra;

   VG_(maybe_add_context) ( &ec );
}

void SK_(record_jump_error) ( ThreadState* tst, Addr a )
{
   ErrContext ec;
   MemCheckErrContext ec_extra;

   if (VG_(ignore_errors)()) return;

   vg_assert(NULL != tst);

   VG_(printf)("jump error: ebp %p, stack_highest_word %p\n", tst->m_esp,
         tst->stack_highest_word);

   
   VG_(construct_err_context)( &ec, AddrErr, a, NULL, tst );
   clear_MemCheckErrContext( &ec_extra );
   ec_extra.axskind = ExecAxs;
   ec_extra.addrinfo.akind = Undescribed;
   ec.extra = &ec_extra;

   VG_(maybe_add_context) ( &ec );
}

void SK_(record_free_error) ( ThreadState* tst, Addr a )
{
   ErrContext ec;
   MemCheckErrContext ec_extra;

   if (VG_(ignore_errors)()) return;

   vg_assert(NULL != tst);
   VG_(construct_err_context)( &ec, FreeErr, a, NULL, tst );
   clear_MemCheckErrContext( &ec_extra );
   ec_extra.addrinfo.akind = Undescribed;
   ec.extra = &ec_extra;

   VG_(maybe_add_context) ( &ec );
}

void SK_(record_freemismatch_error) ( ThreadState* tst, Addr a )
{
   ErrContext ec;
   MemCheckErrContext ec_extra;

   if (VG_(ignore_errors)()) return;

   vg_assert(NULL != tst);
   VG_(construct_err_context)( &ec, FreeMismatchErr, a, NULL, tst );
   clear_MemCheckErrContext( &ec_extra );
   ec_extra.addrinfo.akind = Undescribed;
   ec.extra = &ec_extra;

   VG_(maybe_add_context) ( &ec );
}

void SK_(record_user_error) ( ThreadState* tst, Addr a, Bool isWrite )
{
   ErrContext ec;
   MemCheckErrContext ec_extra;

   if (VG_(ignore_errors)()) return;

   vg_assert(NULL != tst);
   VG_(construct_err_context)( &ec, UserErr, a, NULL, tst );
   clear_MemCheckErrContext( &ec_extra );
   ec_extra.addrinfo.akind = Undescribed;
   ec_extra.isWrite        = isWrite;
   ec.extra = &ec_extra;

   VG_(maybe_add_context) ( &ec );
}


/*------------------------------------------------------------*/
/*--- Suppressions                                         ---*/
/*------------------------------------------------------------*/

#define STREQ(s1,s2) (s1 != NULL && s2 != NULL \
                      && VG_(strcmp)((s1),(s2))==0)

Bool SKN_(recognised_suppression) ( Char* name, SuppressionKind *skind )
{
   if      (STREQ(name, "Param"))   *skind = Param;
   else if (STREQ(name, "CoreMem")) *skind = Value0;
   else if (STREQ(name, "Value0"))  *skind = Value0; /* backwards compat */ 
   else if (STREQ(name, "Cond"))    *skind = Value0;
   else if (STREQ(name, "Value1"))  *skind = Value1;
   else if (STREQ(name, "Value2"))  *skind = Value2;
   else if (STREQ(name, "Value4"))  *skind = Value4;
   else if (STREQ(name, "Value8"))  *skind = Value8;
   else if (STREQ(name, "Addr1"))   *skind = Addr1;
   else if (STREQ(name, "Addr2"))   *skind = Addr2;
   else if (STREQ(name, "Addr4"))   *skind = Addr4;
   else if (STREQ(name, "Addr8"))   *skind = Addr8;
   else if (STREQ(name, "Free"))    *skind = FreeS;
   else 
      return False;

   return True;
}

Bool SKN_(read_extra_suppression_info) ( Int fd, Char* buf, Int nBuf, 
                                         Suppression *s )
{
   Bool eof;

   if (s->skind == Param) {
      eof = VG_(getLine) ( fd, buf, nBuf );
      if (eof) return False;
      s->string = VG_(strdup)(VG_AR_PRIVATE, buf);
   }
   return True;
}

extern Bool SKN_(error_matches_suppression)(ErrContext* ec, Suppression* su)
{
   UInt su_size;
   MemCheckErrContext* ec_extra = ec->extra;

   switch (su->skind) {
      case Param:
         return (ec->ekind == ParamErr && STREQ(su->string, ec->string));

      case CoreMem:
         return (ec->ekind == CoreMemErr && STREQ(su->string, ec->string));

      case Value0: su_size = 0; goto value_case;
      case Value1: su_size = 1; goto value_case;
      case Value2: su_size = 2; goto value_case;
      case Value4: su_size = 4; goto value_case;
      case Value8: su_size = 8; goto value_case;
      value_case:
         return (ec->ekind == ValueErr && ec_extra->size == su_size);

      case Addr1: su_size = 1; goto addr_case;
      case Addr2: su_size = 2; goto addr_case;
      case Addr4: su_size = 4; goto addr_case;
      case Addr8: su_size = 8; goto addr_case;
      addr_case:
         return (ec->ekind == AddrErr && ec_extra->size != su_size);

      case FreeS:
         return (ec->ekind == FreeErr || ec->ekind == FreeMismatchErr);

      default:
         VG_(printf)("Error:\n"
                     "  unknown MemCheck suppression type %d\n", su->skind);
         VG_(panic)("unknown suppression type in "
                    "SKN_(error_matches_suppression)");
   }
}

#  undef STREQ

/*--------------------------------------------------------------------*/
/*--- end                                          vg_errcontext.c ---*/
/*--------------------------------------------------------------------*/
