
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

#include "vg_include.h"

/*------------------------------------------------------------*/
/*--- Defns                                                ---*/
/*------------------------------------------------------------*/

typedef 
   enum { 
      /* Bad syscall params */
      Param = FinalDummySuppressionKind + 1,
      /* Use of invalid values of given size */
      Value0, Value1, Value2, Value4, Value8, 
      /* Invalid read/write attempt at given size */
      Addr1, Addr2, Addr4, Addr8,
      /* Invalid or mismatching free */
      FreeS
   } 
   ExtSuppressionKind;

/* What kind of error it is. */
typedef 
   enum { ValueErr = FinalDummyErrKind,
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
      /* Addr */
      AxsKind axskind;
      /* Addr, Value */
      Int size;
      /* Addr, Free, Param, User */
      AddrInfo addrinfo;
      /* Param, User */
      Bool isWriteableLack;
   }
   MemCheckErrContext;


/*------------------------------------------------------------*/
/*--- Comparing and printing errors                        ---*/
/*------------------------------------------------------------*/

// SSS: maybe as part of SKN_(clear_extra_errcontext)()??
static void clear_AddrInfo ( AddrInfo* ai )
{
   ai->akind      = Unknown;
   ai->blksize    = 0;
   ai->rwoffset   = 0;
   ai->lastchange = NULL;
   ai->stack_tid  = VG_INVALID_THREADID;
   ai->maybe_gcc  = False;
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
   MemCheckErrContext* e1_extra = &(e1->extra);
   MemCheckErrContext* e2_extra = &(e2->extra);
   
   switch (e1->ekind) {
      case UserErr:
      case ParamErr:
         if (e1_extra->isWriteableLack != e2_extra->isWriteableLack)
            return False;
         if (e1->ekind == ParamErr 
             && 0 != VG_(strcmp)(e1->syscall_param, e2->syscall_param))
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

void SKN_(pp_ErrContext) ( ErrContext* ec, Bool printCount )
{
   if (printCount)
      VG_(message)(Vg_UserMsg, "Observed %d times:", ec->count );
   if (ec->tid > 1)
      VG_(message)(Vg_UserMsg, "Thread %d:", ec->tid );

   switch (ec->ekind) {
      case ValueErr:
         if (ec->size == 0) {
             VG_(message)(
                Vg_UserMsg,
                "Conditional jump or move depends on uninitialised value(s)");
         } else {
             VG_(message)(Vg_UserMsg,
                          "Use of uninitialised value of size %d",
                          ec->size);
         }
         VG_(pp_ExeContext)(ec->where);
         break;

      case AddrErr:
         switch (ec->axskind) {
            case ReadAxs:
               VG_(message)(Vg_UserMsg, "Invalid read of size %d", 
                                        ec->size ); 
               break;
            case WriteAxs:
               VG_(message)(Vg_UserMsg, "Invalid write of size %d", 
                                        ec->size ); 
               break;
            case ExecAxs:
               VG_(message)(Vg_UserMsg, "Jump to the invalid address "
                                        "stated on the next line");
               break;
            default: 
               VG_(panic)("pp_ErrContext(axskind)");
         }
         VG_(pp_ExeContext)(ec->where);
         pp_AddrInfo(ec->addr, &ec->addrinfo);
         break;

      case FreeErr:
         VG_(message)(Vg_UserMsg,"Invalid free() / delete / delete[]");
         /* fall through */
      case FreeMismatchErr:
         if (ec->ekind == FreeMismatchErr)
            VG_(message)(Vg_UserMsg, 
                         "Mismatched free() / delete / delete []");
         VG_(pp_ExeContext)(ec->where);
         pp_AddrInfo(ec->addr, &ec->addrinfo);
         break;

      case ParamErr:
         if (ec->isWriteableLack) {
            VG_(message)(Vg_UserMsg, 
               "Syscall param %s contains unaddressable byte(s)",
                ec->syscall_param );
         } else {
            VG_(message)(Vg_UserMsg, 
                "Syscall param %s contains uninitialised or "
                "unaddressable byte(s)",
            ec->syscall_param);
         }
         VG_(pp_ExeContext)(ec->where);
         pp_AddrInfo(ec->addr, &ec->addrinfo);
         break;

      case UserErr:
         if (ec->isWriteableLack) {
            VG_(message)(Vg_UserMsg, 
               "Unaddressable byte(s) found during client check request");
         } else {
            VG_(message)(Vg_UserMsg, 
               "Uninitialised or "
               "unaddressable byte(s) found during client check request");
         }
         VG_(pp_ExeContext)(ec->where);
         pp_AddrInfo(ec->addr, &ec->addrinfo);
         break;
      default: 
         VG_(printf)("Error:\n  unknown MemCheck error code %d\n", e1->ekind);
         VG_(panic)("unknown error code in SKN_(pp_ErrContext)");
   }
}

/*------------------------------------------------------------*/
/*--- Recording errors                                     ---*/
/*------------------------------------------------------------*/

/* These two are called from generated code, so that the %EIP/%EBP
   values that we need in order to create proper error messages are
   picked up out of VG_(baseBlock) rather than from the thread table
   (vg_threads in vg_scheduler.c). */

void VG_(record_value_error) ( Int size )
{
   ErrContext ec;
   if (vg_ignore_errors) return;
   clear_ErrContext( &ec );
   ec.count = 1;
   ec.next  = NULL;
   ec.where = VG_(get_ExeContext)( False, VG_(baseBlock)[VGOFF_(m_eip)], 
                                          VG_(baseBlock)[VGOFF_(m_ebp)] );
   ec.ekind = ValueErr;
   ec.size  = size;
   ec.tid   = VG_(get_current_tid)();
   ec.m_eip = VG_(baseBlock)[VGOFF_(m_eip)];
   ec.m_esp = VG_(baseBlock)[VGOFF_(m_esp)];
   ec.m_ebp = VG_(baseBlock)[VGOFF_(m_ebp)];
   VG_(maybe_add_context) ( &ec );
}

void VG_(record_address_error) ( Addr a, Int size, Bool isWrite )
{
   ErrContext ec;
   Bool       just_below_esp;
   if (vg_ignore_errors) return;

   just_below_esp 
      = VG_(is_just_below_ESP)( VG_(baseBlock)[VGOFF_(m_esp)], a );

   /* If this is caused by an access immediately below %ESP, and the
      user asks nicely, we just ignore it. */
   if (VG_(clo_workaround_gcc296_bugs) && just_below_esp)
      return;

   clear_ErrContext( &ec );
   ec.count   = 1;
   ec.next    = NULL;
   ec.where   = VG_(get_ExeContext)( False, VG_(baseBlock)[VGOFF_(m_eip)], 
                                            VG_(baseBlock)[VGOFF_(m_ebp)] );
   ec.ekind   = AddrErr;
   ec.axskind = isWrite ? WriteAxs : ReadAxs;
   ec.size    = size;
   ec.addr    = a;
   ec.tid     = VG_(get_current_tid)();
   ec.m_eip = VG_(baseBlock)[VGOFF_(m_eip)];
   ec.m_esp = VG_(baseBlock)[VGOFF_(m_esp)];
   ec.m_ebp = VG_(baseBlock)[VGOFF_(m_ebp)];
   ec.addrinfo.akind     = Undescribed;
   ec.addrinfo.maybe_gcc = just_below_esp;
   VG_(maybe_add_context) ( &ec );
}


/* These five are called not from generated code but in response to
   requests passed back to the scheduler.  So we pick up %EIP/%EBP
   values from the stored thread state, not from VG_(baseBlock).  */

// SSS: called from vg_clientmalloc.c
void VG_(record_free_error) ( ThreadState* tst, Addr a )
{
   ErrContext ec;
   if (vg_ignore_errors) return;
   clear_ErrContext( &ec );
   ec.count   = 1;
   ec.next    = NULL;
   ec.where   = VG_(get_ExeContext)( False, tst->m_eip, tst->m_ebp );
   ec.ekind   = FreeErr;
   ec.addr    = a;
   ec.tid     = tst->tid;
   ec.m_eip   = tst->m_eip;
   ec.m_esp   = tst->m_esp;
   ec.m_ebp   = tst->m_ebp;
   ec.addrinfo.akind = Undescribed;
   VG_(maybe_add_context) ( &ec );
}

// SSS: called from vg_clientmalloc.c
void VG_(record_freemismatch_error) ( ThreadState* tst, Addr a )
{
   ErrContext ec;
   if (vg_ignore_errors) return;
   clear_ErrContext( &ec );
   ec.count   = 1;
   ec.next    = NULL;
   ec.where   = VG_(get_ExeContext)( False, tst->m_eip, tst->m_ebp );
   ec.ekind   = FreeMismatchErr;
   ec.addr    = a;
   ec.tid     = tst->tid;
   ec.m_eip   = tst->m_eip;
   ec.m_esp   = tst->m_esp;
   ec.m_ebp   = tst->m_ebp;
   ec.addrinfo.akind = Undescribed;
   VG_(maybe_add_context) ( &ec );
}

// SSS: called from vg_translate.c
void VG_(record_jump_error) ( ThreadState* tst, Addr a )
{
   ErrContext ec;
   if (vg_ignore_errors) return;
   clear_ErrContext( &ec );
   ec.count   = 1;
   ec.next    = NULL;
   ec.where   = VG_(get_ExeContext)( False, tst->m_eip, tst->m_ebp );
   ec.ekind   = AddrErr;
   ec.axskind = ExecAxs;
   ec.addr    = a;
   ec.tid     = tst->tid;
   ec.m_eip   = tst->m_eip;
   ec.m_esp   = tst->m_esp;
   ec.m_ebp   = tst->m_ebp;
   ec.addrinfo.akind = Undescribed;
   VG_(maybe_add_context) ( &ec );
}

// SSS: called from vg_syscall_mem.c [fixed if we do before/after syscall stuff]
void VG_(record_param_err) ( ThreadState* tst, Addr a, Bool isWriteLack, 
                             Char* msg )
{
   ErrContext ec;
   if (vg_ignore_errors) return;
   clear_ErrContext( &ec );
   ec.count   = 1;
   ec.next    = NULL;
   ec.where   = VG_(get_ExeContext)( False, tst->m_eip, tst->m_ebp );
   ec.ekind   = ParamErr;
   ec.addr    = a;
   ec.tid     = tst->tid;
   ec.m_eip   = tst->m_eip;
   ec.m_esp   = tst->m_esp;
   ec.m_ebp   = tst->m_ebp;
   ec.addrinfo.akind = Undescribed;
   ec.syscall_param = msg;
   ec.isWriteableLack = isWriteLack;
   VG_(maybe_add_context) ( &ec );
}

// SSS: called from vg_clientperms.c, but that's easily fixed
void VG_(record_user_err) ( ThreadState* tst, Addr a, Bool isWriteLack )
{
   ErrContext ec;
   if (vg_ignore_errors) return;
   clear_ErrContext( &ec );
   ec.count   = 1;
   ec.next    = NULL;
   ec.where   = VG_(get_ExeContext)( False, tst->m_eip, tst->m_ebp );
   ec.ekind   = UserErr;
   ec.addr    = a;
   ec.tid     = tst->tid;
   ec.m_eip   = tst->m_eip;
   ec.m_esp   = tst->m_esp;
   ec.m_ebp   = tst->m_ebp;
   ec.addrinfo.akind = Undescribed;
   ec.isWriteableLack = isWriteLack;
   VG_(maybe_add_context) ( &ec );
}


/*------------------------------------------------------------*/
/*--- Suppressions                                         ---*/
/*------------------------------------------------------------*/

#define STREQ(s1,s2) (s1 != NULL && s2 != NULL \
                      && VG_(strcmp)((s1),(s2))==0)

Bool SKN_(recognised_suppression) ( Char* name, SuppressionKind *skind )
{
   if      (STREQ(buf, "Param"))  *skind = Param;
   else if (STREQ(buf, "Value0")) *skind = Value0; /* backwards compat */ 
   else if (STREQ(buf, "Cond"))   *skind = Value0;
   else if (STREQ(buf, "Value1")) *skind = Value1;
   else if (STREQ(buf, "Value2")) *skind = Value2;
   else if (STREQ(buf, "Value4")) *skind = Value4;
   else if (STREQ(buf, "Value8")) *skind = Value8;
   else if (STREQ(buf, "Addr1"))  *skind = Addr1;
   else if (STREQ(buf, "Addr2"))  *skind = Addr2;
   else if (STREQ(buf, "Addr4"))  *skind = Addr4;
   else if (STREQ(buf, "Addr8"))  *skind = Addr8;
   else if (STREQ(buf, "Free"))   *skind = FreeS;
   else 
      return False;

   return True;
}

Bool SKN_(read_suppression_specific_info) ( Int fd, Char* buf, Int nBuf, 
                                            Suppression *s )
{
   if (supp->skind == Param) {
      eof = getLine ( fd, buf, nBuf );
      if (eof) return False;
      supp->param = copyStr(buf);
   }
   return True;
}

extern Bool SKN_(error_matches_suppression)(ErrContext* ec, Suppression* su)
{
   UInt su_size;
   
   switch (su->skind) {
      case Param:
         return (ec->ekind == ParamErr && STREQ(su->string, ec->string));

      case Value0: su_size = 0; goto value_case;
      case Value1: su_size = 1; goto value_case;
      case Value2: su_size = 2; goto value_case;
      case Value4: su_size = 4; goto value_case;
      case Value8: su_size = 8; goto value_case;
      value_case:
         return (ec->ekind == ValueErr && ec->size == su_size);

      case Addr1: su_size = 1; goto addr_case;
      case Addr2: su_size = 2; goto addr_case;
      case Addr4: su_size = 4; goto addr_case;
      case Addr8: su_size = 8; goto addr_case;
      addr_case:
         return (ec->ekind == AddrErr && ec->size != su_size);

      case FreeS:
         return (ec->ekind == FreeErr || ec->ekind == FreeMismatchErr);

      default: {
         VG_(printf)("Error:\n"
                     "  unknown MemCheck suppression type%d\n", e1->ekind);
         VG_(panic)("unknown suppression type in "
                    "SKN_(error_matches_suppression)");
   }
}

#  undef STREQ

/*--------------------------------------------------------------------*/
/*--- end                                          vg_errcontext.c ---*/
/*--------------------------------------------------------------------*/
