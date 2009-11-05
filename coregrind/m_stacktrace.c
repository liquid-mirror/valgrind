
/*--------------------------------------------------------------------*/
/*--- Take snapshots of client stacks.              m_stacktrace.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2000-2009 Julian Seward 
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

#include "pub_core_basics.h"
#include "pub_core_vki.h"
#include "pub_core_threadstate.h"
#include "pub_core_debuginfo.h"     // XXX: circular dependency
#include "pub_core_aspacemgr.h"     // For VG_(is_addressable)()
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcprint.h"
#include "pub_core_machine.h"
#include "pub_core_options.h"
#include "pub_core_stacks.h"        // VG_(stack_limits)
#include "pub_core_stacktrace.h"
#include "pub_core_xarray.h"
#include "pub_core_clientstate.h"   // VG_(client__dl_sysinfo_int80)
#include "pub_core_trampoline.h"

/*------------------------------------------------------------*/
/*--- Exported functions.                                  ---*/
/*------------------------------------------------------------*/

/* Take a snapshot of the client's stack, putting up to 'max_n_ips'
   IPs into 'ips'.  In order to be thread-safe, we pass in the
   thread's IP SP, FP if that's meaningful, and LR if that's
   meaningful.  Returns number of IPs put in 'ips'.

   If you know what the thread ID for this stack is, send that as the
   first parameter, else send zero.  This helps generate better stack
   traces on ppc64-linux and has no effect on other platforms.
*/
UInt VG_(get_StackTrace_wrk) ( ThreadId tid_if_known,
                               /*OUT*/Addr* ips, UInt max_n_ips,
                               /*OUT*/Addr* sps, /*OUT*/Addr* fps,
                               Addr ip, Addr sp, Addr fp, Addr lr,
                               Addr fp_min, Addr fp_max_orig )
{
#  if defined(VGP_ppc32_linux) || defined(VGP_ppc64_linux) \
                               || defined(VGP_ppc32_aix5) \
                               || defined(VGP_ppc64_aix5)
   Bool  lr_is_first_RA = False;
#  endif
#  if defined(VGP_ppc64_linux) || defined(VGP_ppc64_aix5) \
                               || defined(VGP_ppc32_aix5)
   Word redir_stack_size = 0;
   Word redirs_used      = 0;
#  endif

   Bool  debug = False;
   Int   i;
   Addr  fp_max;
   UInt  n_found = 0;

   vg_assert(sizeof(Addr) == sizeof(UWord));
   vg_assert(sizeof(Addr) == sizeof(void*));

   /* Snaffle IPs from the client's stack into ips[0 .. max_n_ips-1],
      stopping when the trail goes cold, which we guess to be
      when FP is not a reasonable stack location. */

   // JRS 2002-sep-17: hack, to round up fp_max to the end of the
   // current page, at least.  Dunno if it helps.
   // NJN 2002-sep-17: seems to -- stack traces look like 1.0.X again
   fp_max = VG_PGROUNDUP(fp_max_orig);
   if (fp_max >= sizeof(Addr))
      fp_max -= sizeof(Addr);

   if (debug)
      VG_(printf)("max_n_ips=%d fp_min=0x%lx fp_max_orig=0x%lx, "
                  "fp_max=0x%lx ip=0x%lx fp=0x%lx\n",
		  max_n_ips, fp_min, fp_max_orig, fp_max, ip, fp);

   /* Assertion broken before main() is reached in pthreaded programs;  the
    * offending stack traces only have one item.  --njn, 2002-aug-16 */
   /* vg_assert(fp_min <= fp_max);*/
   // On Darwin, this kicks in for pthread-related stack traces, so they're
   // only 1 entry long which is wrong.
#if !defined(VGO_darwin)
   if (fp_min + 512 >= fp_max) {
      /* If the stack limits look bogus, don't poke around ... but
         don't bomb out either. */
      if (sps) sps[0] = sp;
      if (fps) fps[0] = fp;
      ips[0] = ip;
      return 1;
   } 
#endif

   /* Otherwise unwind the stack in a platform-specific way.  Trying
      to merge the x86, amd64, ppc32 and ppc64 logic into a single
      piece of code is just too confusing and difficult to
      performance-tune.  */

#  if defined(VGP_x86_linux) || defined(VGP_x86_darwin)

   /*--------------------- x86 ---------------------*/

   /* fp is %ebp.  sp is %esp.  ip is %eip. */

   if (sps) sps[0] = sp;
   if (fps) fps[0] = fp;
   ips[0] = ip;
   i = 1;

   /* Loop unwinding the stack. Note that the IP value we get on
    * each pass (whether from CFI info or a stack frame) is a
    * return address so is actually after the calling instruction
    * in the calling function.
    *
    * Because of this we subtract one from the IP after each pass
    * of the loop so that we find the right CFI block on the next
    * pass - otherwise we can find the wrong CFI info if it happens
    * to change after the calling instruction and that will mean
    * that we will fail to unwind the next step.
    *
    * This most frequently happens at the end of a function when
    * a tail call occurs and we wind up using the CFI info for the
    * next function which is completely wrong.
    */
   while (True) {

      if (i >= max_n_ips)
         break;

      /* Try to derive a new (ip,sp,fp) triple from the current
         set. */

      /* On x86, first try the old-fashioned method of following the
         %ebp-chain.  Code which doesn't use this (that is, compiled
         with -fomit-frame-pointer) is not ABI compliant and so
         relatively rare.  Besides, trying the CFI first almost always
         fails, and is expensive. */
      /* Deal with frames resulting from functions which begin "pushl%
         ebp ; movl %esp, %ebp" which is the ABI-mandated preamble. */
      if (fp_min <= fp &&
          fp <= fp_max - 1 * sizeof(UWord)/*see comment below*/)
      {
         /* fp looks sane, so use it. */
         ip = (((UWord*)fp)[1]);
         // We stop if we hit a zero (the traditional end-of-stack
         // marker) or a one -- these correspond to recorded IPs of 0 or -1.
         // The latter because r8818 (in this file) changes the meaning of
         // entries [1] and above in a stack trace, by subtracting 1 from
         // them.  Hence stacks that used to end with a zero value now end in
         // -1 and so we must detect that too.
         if (0 == ip || 1 == ip) break;
         sp = fp + sizeof(Addr) /*saved %ebp*/ 
                 + sizeof(Addr) /*ra*/;
         fp = (((UWord*)fp)[0]);
         if (sps) sps[i] = sp;
         if (fps) fps[i] = fp;
         ips[i++] = ip - 1; /* -1: refer to calling insn, not the RA */
         if (debug)
            VG_(printf)("     ipsF[%d]=0x%08lx\n", i-1, ips[i-1]);
         ip = ip - 1; /* as per comment at the head of this loop */
         continue;
      }

      /* That didn't work out, so see if there is any CF info to hand
         which can be used. */
      if ( VG_(use_CF_info)( &ip, &sp, &fp, fp_min, fp_max ) ) {
         if (0 == ip || 1 == ip) break;
         if (sps) sps[i] = sp;
         if (fps) fps[i] = fp;
         ips[i++] = ip - 1; /* -1: refer to calling insn, not the RA */
         if (debug)
            VG_(printf)("     ipsC[%d]=0x%08lx\n", i-1, ips[i-1]);
         ip = ip - 1; /* as per comment at the head of this loop */
         continue;
      }

      /* And, similarly, try for MSVC FPO unwind info. */
      if ( VG_(use_FPO_info)( &ip, &sp, &fp, fp_min, fp_max ) ) {
         if (0 == ip || 1 == ip) break;
         if (sps) sps[i] = sp;
         if (fps) fps[i] = fp;
         ips[i++] = ip;
         if (debug)
            VG_(printf)("     ipsC[%d]=0x%08lx\n", i-1, ips[i-1]);
         ip = ip - 1;
         continue;
      }

      /* No luck.  We have to give up. */
      break;
   }

#  elif defined(VGP_amd64_linux)  ||  defined(VGP_amd64_darwin)

   /*--------------------- amd64 ---------------------*/

   /* fp is %rbp.  sp is %rsp.  ip is %rip. */

   ips[0] = ip;
   if (sps) sps[0] = sp;
   if (fps) fps[0] = fp;
   i = 1;

   /* Loop unwinding the stack. Note that the IP value we get on
    * each pass (whether from CFI info or a stack frame) is a
    * return address so is actually after the calling instruction
    * in the calling function.
    *
    * Because of this we subtract one from the IP after each pass
    * of the loop so that we find the right CFI block on the next
    * pass - otherwise we can find the wrong CFI info if it happens
    * to change after the calling instruction and that will mean
    * that we will fail to unwind the next step.
    *
    * This most frequently happens at the end of a function when
    * a tail call occurs and we wind up using the CFI info for the
    * next function which is completely wrong.
    */
   while (True) {

      if (i >= max_n_ips)
         break;

      /* Try to derive a new (ip,sp,fp) triple from the current set. */

      /* First off, see if there is any CFI info to hand which can
         be used. */
      if ( VG_(use_CF_info)( &ip, &sp, &fp, fp_min, fp_max ) ) {
         if (0 == ip || 1 == ip) break;
         if (sps) sps[i] = sp;
         if (fps) fps[i] = fp;
         ips[i++] = ip - 1; /* -1: refer to calling insn, not the RA */
         if (debug)
            VG_(printf)("     ipsC[%d]=%#08lx\n", i-1, ips[i-1]);
         ip = ip - 1; /* as per comment at the head of this loop */
         continue;
      }

      /* If VG_(use_CF_info) fails, it won't modify ip/sp/fp, so
         we can safely try the old-fashioned method. */
      /* This bit is supposed to deal with frames resulting from
         functions which begin "pushq %rbp ; movq %rsp, %rbp".
         Unfortunately, since we can't (easily) look at the insns at
         the start of the fn, like GDB does, there's no reliable way
         to tell.  Hence the hack of first trying out CFI, and if that
         fails, then use this as a fallback. */
      /* Note: re "- 1 * sizeof(UWord)", need to take account of the
         fact that we are prodding at & ((UWord*)fp)[1] and so need to
         adjust the limit check accordingly.  Omitting this has been
         observed to cause segfaults on rare occasions. */
      if (fp_min <= fp && fp <= fp_max - 1 * sizeof(UWord)) {
         /* fp looks sane, so use it. */
         ip = (((UWord*)fp)[1]);
         if (0 == ip || 1 == ip) break;
         sp = fp + sizeof(Addr) /*saved %rbp*/ 
                 + sizeof(Addr) /*ra*/;
         fp = (((UWord*)fp)[0]);
         if (sps) sps[i] = sp;
         if (fps) fps[i] = fp;
         ips[i++] = ip - 1; /* -1: refer to calling insn, not the RA */
         if (debug)
            VG_(printf)("     ipsF[%d]=%#08lx\n", i-1, ips[i-1]);
         ip = ip - 1; /* as per comment at the head of this loop */
         continue;
      }

      /* Last-ditch hack (evidently GDB does something similar).  We
         are in the middle of nowhere and we have a nonsense value for
         the frame pointer.  If the stack pointer is still valid,
         assume that what it points at is a return address.  Yes,
         desperate measures.  Could do better here:
         - check that the supposed return address is in
           an executable page
         - check that the supposed return address is just after a call insn
         - given those two checks, don't just consider *sp as the return 
           address; instead scan a likely section of stack (eg sp .. sp+256)
           and use suitable values found there.
      */
      if (fp_min <= sp && sp < fp_max) {
         ip = ((UWord*)sp)[0];
         if (0 == ip || 1 == ip) break;
         if (sps) sps[i] = sp;
         if (fps) fps[i] = fp;
         ips[i++] = ip == 0 
                    ? 0 /* sp[0] == 0 ==> stuck at the bottom of a
                           thread stack */
                    : ip - 1; /* -1: refer to calling insn, not the RA */
         if (debug)
            VG_(printf)("     ipsH[%d]=%#08lx\n", i-1, ips[i-1]);
         ip = ip - 1; /* as per comment at the head of this loop */
         sp += 8;
         continue;
      }

      /* No luck at all.  We have to give up. */
      break;
   }

#  elif defined(VGP_ppc32_linux) || defined(VGP_ppc64_linux) \
        || defined(VGP_ppc32_aix5) || defined(VGP_ppc64_aix5)

   /*--------------------- ppc32/64 ---------------------*/

   /* fp is %r1.  ip is %cia.  Note, ppc uses r1 as both the stack and
      frame pointers. */

#  if defined(VGP_ppc64_linux) || defined(VGP_ppc64_aix5)
   redir_stack_size = VEX_GUEST_PPC64_REDIR_STACK_SIZE;
   redirs_used      = 0;
#  elif defined(VGP_ppc32_aix5)
   redir_stack_size = VEX_GUEST_PPC32_REDIR_STACK_SIZE;
   redirs_used      = 0;
#  endif

#  if defined(VG_PLAT_USES_PPCTOC)
   /* Deal with bogus LR values caused by function
      interception/wrapping on ppc-TOC platforms; see comment on
      similar code a few lines further down. */
   if (ULong_to_Ptr(lr) == (void*)&VG_(ppctoc_magic_redirect_return_stub)
       && VG_(is_valid_tid)(tid_if_known)) {
      Word hsp = VG_(threads)[tid_if_known].arch.vex.guest_REDIR_SP;
      redirs_used++;
      if (hsp >= 1 && hsp < redir_stack_size)
         lr = VG_(threads)[tid_if_known]
                 .arch.vex.guest_REDIR_STACK[hsp-1];
   }
#  endif

   /* We have to determine whether or not LR currently holds this fn
      (call it F)'s return address.  It might not if F has previously
      called some other function, hence overwriting LR with a pointer
      to some part of F.  Hence if LR and IP point to the same
      function then we conclude LR does not hold this function's
      return address; instead the LR at entry must have been saved in
      the stack by F's prologue and so we must get it from there
      instead.  Note all this guff only applies to the innermost
      frame. */
   lr_is_first_RA = False;
   {
#     define M_VG_ERRTXT 1000
      UChar buf_lr[M_VG_ERRTXT], buf_ip[M_VG_ERRTXT];
      /* The following conditional looks grossly inefficient and
         surely could be majorly improved, with not much effort. */
      if (VG_(get_fnname_raw) (lr, buf_lr, M_VG_ERRTXT))
         if (VG_(get_fnname_raw) (ip, buf_ip, M_VG_ERRTXT))
            if (VG_(strncmp)(buf_lr, buf_ip, M_VG_ERRTXT))
               lr_is_first_RA = True;
#     undef M_VG_ERRTXT
   }

   if (sps) sps[0] = fp; /* NB. not sp */
   if (fps) fps[0] = fp;
   ips[0] = ip;
   i = 1;

   if (fp_min <= fp && fp < fp_max-VG_WORDSIZE+1) {

      /* initial FP is sane; keep going */
      fp = (((UWord*)fp)[0]);

      while (True) {

        /* On ppc64-linux (ppc64-elf, really), and on AIX, the lr save
           slot is 2 words back from sp, whereas on ppc32-elf(?) it's
           only one word back. */
#        if defined(VGP_ppc64_linux) \
            || defined(VGP_ppc32_aix5) || defined(VGP_ppc64_aix5)
         const Int lr_offset = 2;
#        else
         const Int lr_offset = 1;
#        endif

         if (i >= max_n_ips)
            break;

         /* Try to derive a new (ip,fp) pair from the current set. */

         if (fp_min <= fp && fp <= fp_max - lr_offset * sizeof(UWord)) {
            /* fp looks sane, so use it. */

            if (i == 1 && lr_is_first_RA)
               ip = lr;
            else
               ip = (((UWord*)fp)[lr_offset]);

#           if defined(VG_PLAT_USES_PPCTOC)
            /* Nasty hack to do with function replacement/wrapping on
               ppc64-linux/ppc64-aix/ppc32-aix.  If LR points to our
               magic return stub, then we are in a wrapped or
               intercepted function, in which LR has been messed with.
               The original LR will have been pushed onto the thread's
               hidden REDIR stack one down from the top (top element
               is the saved R2) and so we should restore the value
               from there instead.  Since nested redirections can and
               do happen, we keep track of the number of nested LRs
               used by the unwinding so far with 'redirs_used'. */
            if (ip == (Addr)&VG_(ppctoc_magic_redirect_return_stub)
                && VG_(is_valid_tid)(tid_if_known)) {
               Word hsp = VG_(threads)[tid_if_known]
                             .arch.vex.guest_REDIR_SP;
               hsp -= 2 * redirs_used;
               redirs_used ++;
               if (hsp >= 1 && hsp < redir_stack_size)
                  ip = VG_(threads)[tid_if_known]
                          .arch.vex.guest_REDIR_STACK[hsp-1];
            }
#           endif

            if (0 == ip || 1 == ip) break;
            fp = (((UWord*)fp)[0]);
            if (sps) sps[i] = fp; /* NB. not sp */
            if (fps) fps[i] = fp;
            ips[i++] = ip - 1; /* -1: refer to calling insn, not the RA */
            if (debug)
               VG_(printf)("     ipsF[%d]=%#08lx\n", i-1, ips[i-1]);
            ip = ip - 1; /* ip is probably dead at this point, but
                            play safe, a la x86/amd64 above.  See
                            extensive comments above. */
            continue;
         }

         /* No luck there.  We have to give up. */
         break;
      }
   }


#  elif defined(VGP_arm_linux)
   if (sps) sps[0] = sp;
   if (fps) fps[0] = fp;
   ips[0] = ip;
   i = 1;


   while (True) {
      Addr prologue;
      Addr scanaddr;
      UInt *idx;
      Int sp_delta = 0; //Offset to old SP from SP, used to recover SP for most functions

      //Set if we spot LR being pushed on the stack
      Bool tracking_lr = False;
      Int lr_sp_delta = 0; // <input sp - lr_sp_delta = lr>, only valid if tracking_lr is true

      //Set if we spot FP being pushed on the stack.
      Bool tracking_fp = False;
      Int fp_sp_delta = 0; // 

      //We also save offsets from FP
      //We use this if we can, as variadic functions will fail with SP method.
      Int fp_lr_offset = 0; // Offset to LR from FP.
      Int fp_sp_offset = 0; // Offset to old SP from FP.
      Int fp_fp_offset = 0; // Offset to old FP from FP.

      Bool fp_modified = False; //did anything in the prologue write to FP?

      /* This one is pretty dirty
       * It seems libc has a tendency of not using standard prologues at all, when it is about to execute a syscall.
       * In many cases following LR is enough, but we also need to know if the stack was modified.
       *
       * If we detect we are trying to generate a stacktrace from a syscall AND we didn't find any "standard" prologue, 
       * try instead to search backwards from IP, to locate any operations that modify SP (and pick up LR,FP if we find them)
       *
       * Not being able to do stacktraces from syscalls decreases the usefulness of memcheck quite a bit, so we go to length to
       * hack around it. (gdb does not)
       *
       */
      Bool reverse = 0;
      Bool svc_hack = 0;

      if(debug) {
         VG_(printf)("i: %d, ip: 0x%x, sp: 0x%x, fp: 0x%x\n",i,(unsigned int)ip,(unsigned int)sp,(unsigned int)fp);
      }

      if (i >= max_n_ips)
         break;

      prologue = 0; //VG_(get_fnaddr)(ip);
      if(prologue != 0){
         scanaddr = prologue;
         /* Stack unwinding on ARM is EXTREMELY gnarley. We scan
          * through the function looking for stuff that affects the stack
          * pointer in order to figure out what the frame looks like. A lot of this
          * has been taken from GDB and then hacked up. We really only care about
          * the EABI calling convention here (feel free to support more ^_^) which is
          *
          * push {..., lr}
          * ...
          * sub sp, sp, #??
          *
          * for functions of fixed arity, and
          * 
          * xxx
          * xxx
          * xxx
          *
          * for variadic functions. To make sure we don't slam into the next function,
          * we only scan the range between the beginning of the function and the point at
          * which we called the child, since in order to call the child, the prologue must
          * have executed to make sure the function can get back. If this is the lowest frame,
          * we do the same only between [the function's entry, the current pc)
          */

//See comment above regarding retry, 'reverse' and svc_hack
         if(*(UInt*)(ip-4) == 0xEF000000) {
            svc_hack = True;
         }
retry: 

         for(idx=(UInt *)scanaddr; idx<(UInt *)ip ;(reverse ? idx-- : idx++)){
            UInt insn = *idx;

            if(svc_hack && idx < (UInt*)prologue) {
               break;
            }
            if(0) 
               VG_(printf)("Decoding 0x%x, insn: 0x%x\n",(UInt)idx,insn);
            if (insn == 0xe52de004 || (i == 1 && (insn & 0xe52d0004) == 0xe52d0004) )   /* str ??, [sp, #-4]! a.k.a. push {one register} */
            {
               if(tracking_lr) {
                  lr_sp_delta+=4;
               }
               if(tracking_fp)
                  fp_sp_delta+=4;
 
               if(insn == 0xe52de004) { /* str lr, [sp, #-4]! */
                  tracking_lr = True;
               if(debug) 
                  VG_(printf)("Backtrace: str lr,[sp, #-4]!\n");
               }
               if(insn == 0xe52db004) { /* str fp, [sp, #-4]! */
                  tracking_fp = True;
                  if(debug) 
                     VG_(printf)("Backtrace: str fp,[sp, #-4]!\n");
               }
              sp_delta += 4;
               continue;
            } else if ((insn & 0xffff0000) == 0xe92d0000)
            {
               int mask = insn & 0xffff;
               int regno;

               /* Calculate offsets of saved registers.  */
               for (regno = 15; regno >= 0; regno--)
               {

                  if (mask & (1 << regno))
                  {
                     if(tracking_lr == True) { 
                        lr_sp_delta+=4; //where is LR
                     }
                     if(tracking_fp == True) {
                        fp_sp_delta+=4;
                     }
                     if(regno == 14) { 
                        tracking_lr = True;
                     }
                     if(regno == 11) {
                        tracking_fp = True;
                     }
                     sp_delta += 4; 
                  }
               }
               if(debug)
                  VG_(printf)("push {...} lr_sp_delta: %d sp_delta: %d, tracking_lr=%d, tracking_fp=%d\n",lr_sp_delta,sp_delta,tracking_lr,tracking_fp);
               continue;
            } else if ((insn & 0xfffff000) == 0xe24dd000)   /* sub sp, sp #n */
            {
               unsigned imm = insn & 0xff;         /* immediate value */
               unsigned rot = (insn & 0xf00) >> 7;      /* rotate amount */
               imm = (imm >> rot) | (imm << (32 - rot));
               if(debug)
                  VG_(printf)("sub sp,sp #%d\n",imm);
               if(tracking_lr == True) {
                  lr_sp_delta += imm;
               }
               if(tracking_fp == True) {
                  fp_sp_delta += imm;
               }
               sp_delta += imm;
               continue;
            } else if((insn & 0xfffff000) == 0xe28DB000) { /* add fp, sp, #n */
               unsigned imm = insn & 0xff;         /* immediate value */
               unsigned rot = (insn & 0xf00) >> 7;      /* rotate amount */
               imm = (imm >> rot) | (imm << (32 - rot));
               fp_modified = True;
               fp_sp_offset = sp_delta - imm;
               fp_lr_offset = lr_sp_delta - imm;
               fp_fp_offset = fp_sp_delta - imm;
               if(debug) {
                  VG_(printf)("add fp,sp, #%d\n",imm);
                  VG_(printf)("fp_sp_offset: %d, fp_lr_offset: %d,fp_fp_offset: %d\n",fp_sp_offset,fp_lr_offset,fp_fp_offset);
               }
               continue;
            } else if ((insn & 0xf0000000) != 0xe0000000) {
               break;         /* Condition not true, exit early */
            //Syscall hack -- deal with pop.
            //XXX: We may need to deal with ldr (1 reg pop), haven't seen any code that needs it though.
            //
            //Since we are iterating backwards, we really don't know if someone stashed LR/FP on the stack
            //So we just assume that both lr and fp are on the stack, and the variables will be set later.
            //This is safe, as the booleans controlling if they are set or not will only be set if they actually get pushed at some point.
            } else if(svc_hack && ((insn & 0xffff0000) == 0xe8bd0000)) { //LDM (POP)
               int mask = insn & 0xffff;
               int regno;
               for (regno = 15; regno >= 0; regno--)
               {
                  if (mask & (1 << regno))
                  {
                     lr_sp_delta-=4; //where is LR
                     fp_sp_delta-=4;
                     sp_delta -= 4; 
                  }
               }
            } else {
               /* The optimizer might shove anything into the prologue,
                  so we just skip what we don't recognize.  */
               if(0)
                  VG_(printf)("Ignoring %x\n",insn);
               continue;
            }
         }
      }
      if(svc_hack && !reverse && !tracking_lr && !fp_modified && !tracking_fp) {
         reverse = True;
         scanaddr = ip - 4;
         goto retry;
      }

      if(tracking_lr){
         if(fp_modified && (fp_min <= fp && fp <= fp_max)) {
            ip = *((UInt *)(fp+fp_lr_offset));
            sp = fp+fp_sp_offset;
            if(tracking_fp) {
               fp = *((UInt *)(fp+fp_fp_offset));
            } else {
               fp = 0x0;
            }
            if(debug)
               VG_(printf)("USING FP: sp: 0x%x ip: 0x%x fp: 0x%x\n",(unsigned int)sp,(unsigned int)ip,(unsigned int)fp);
         } else {
            if(debug && fp_modified)
               VG_(printf)("FP NOT IN RANGE: 0x%x < 0x%x < 0x%x\n",(unsigned int)fp_min,(unsigned int)fp,(unsigned int)fp_max);
            ip = *((UInt *)(sp+lr_sp_delta));
            if(tracking_fp) {
               fp = *((UInt *)(sp+fp_sp_delta));
            } else {
               fp = 0x0;
            }
            sp = (sp+sp_delta);
            if (debug) {
               VG_(printf)("USING SP: lr_sp_delta: %d, sp_delta: %d: sp:0x%x, LR: 0x%x\n",lr_sp_delta,sp_delta,(unsigned int)sp,(unsigned int)ip);
            }
         }
         if (sps) sps[i] = sp;
         if (fps) fps[i] = fp;
         if(ip == 0)
            break;
         ips[i++] = ip - 1;
         continue;
      }else if(i == 1){
         /* We should be able to follow the link reg at this level,
          * since we didn't find a particularly interesting prologue, the link reg
          * is prolly intact. */

         //if fp was modified in the prologue, it is somewhat (more) likely to be intact?
         if(fp_modified && (fp_min <= fp && fp <= fp_max)) {
            sp = fp+fp_sp_offset;
            if(tracking_fp) {
               fp = *((UInt *)(fp+fp_fp_offset));
            } else
               fp = 0x0;
         } else {
            sp = (sp + sp_delta);
            fp = 0x0;
         }
         if (sps) sps[i] = sp;
         if (fps) fps[i] = fp;
         ip = lr;
         if(debug)
            VG_(printf)("USING RAW LR: ip: 0x%x, sp: %x, fp: %x\n",(unsigned int)ip,(unsigned int)sp,(unsigned int)fp);
         ips[i++] = ip -1;
         continue;
      }


      //If all else fails, try to use CFI.
      //Johan: I don't know why I do this. It doesn't make any sense with my very vague understanding of CFI...
      //But it seems to work :( ??
      sp = sp+sp_delta+4;
      if ( VG_(use_CF_info)( &ip, &sp, &fp, fp_min, fp_max ) ) {
         if (sps) sps[i] = sp;
         if (fps) fps[i] = fp;
         ips[i++] = ip -1;
         if (debug)
            VG_(printf)("USING CFI: ip: 0x%x, sp: %x, fp: %x\n",(unsigned int)ip,(unsigned int)sp,(unsigned int)fp);
         ip = ip - 1;
         continue;
      }
      /* No luck.  We have to give up. */
      break;
   }



#  else
#    error "Unknown platform"
#  endif

   n_found = i;
   return n_found;
}

UInt VG_(get_StackTrace) ( ThreadId tid, 
                           /*OUT*/StackTrace ips, UInt max_n_ips,
                           /*OUT*/StackTrace sps,
                           /*OUT*/StackTrace fps,
                           Word first_ip_delta )
{
   /* thread in thread table */
   Addr ip                 = VG_(get_IP)(tid);
   Addr fp                 = VG_(get_FP)(tid);
   Addr sp                 = VG_(get_SP)(tid);
   Addr lr                 = VG_(get_LR)(tid);
   Addr stack_highest_word = VG_(threads)[tid].client_stack_highest_word;
   Addr stack_lowest_word  = 0;

#  if defined(VGP_x86_linux)
   /* Nasty little hack to deal with syscalls - if libc is using its
      _dl_sysinfo_int80 function for syscalls (the TLS version does),
      then ip will always appear to be in that function when doing a
      syscall, not the actual libc function doing the syscall.  This
      check sees if IP is within that function, and pops the return
      address off the stack so that ip is placed within the library
      function calling the syscall.  This makes stack backtraces much
      more useful.

      The function is assumed to look like this (from glibc-2.3.6 sources):
         _dl_sysinfo_int80:
            int $0x80
            ret
      That is 3 (2+1) bytes long.  We could be more thorough and check
      the 3 bytes of the function are as expected, but I can't be
      bothered.
   */
   if (VG_(client__dl_sysinfo_int80) != 0 /* we know its address */
       && ip >= VG_(client__dl_sysinfo_int80)
       && ip < VG_(client__dl_sysinfo_int80)+3
       && VG_(am_is_valid_for_client)(sp, sizeof(Addr), VKI_PROT_READ)) {
      ip = *(Addr *)sp;
      sp += sizeof(Addr);
   }
#  endif

   /* See if we can get a better idea of the stack limits */
   VG_(stack_limits)(sp, &stack_lowest_word, &stack_highest_word);

   /* Take into account the first_ip_delta. */
   vg_assert( sizeof(Addr) == sizeof(Word) );
   ip += first_ip_delta;

   if (0)
      VG_(printf)("tid %d: stack_highest=0x%08lx ip=0x%08lx "
                  "sp=0x%08lx fp=0x%08lx\n",
		  tid, stack_highest_word, ip, sp, fp);

   return VG_(get_StackTrace_wrk)(tid, ips, max_n_ips, 
                                       sps, fps,
                                       ip, sp, fp, lr, sp, 
                                       stack_highest_word);
}

static void printIpDesc(UInt n, Addr ip, void* uu_opaque)
{
   #define BUF_LEN   4096
   
   static UChar buf[BUF_LEN];

   VG_(describe_IP)(ip, buf, BUF_LEN);

   if (VG_(clo_xml)) {
      VG_(printf_xml)("    %s\n", buf);
   } else {
      VG_(message)(Vg_UserMsg, "   %s %s\n", ( n == 0 ? "at" : "by" ), buf);
   }
}

/* Print a StackTrace. */
void VG_(pp_StackTrace) ( StackTrace ips, UInt n_ips )
{
   vg_assert( n_ips > 0 );

   if (VG_(clo_xml))
      VG_(printf_xml)("  <stack>\n");

   VG_(apply_StackTrace)( printIpDesc, NULL, ips, n_ips );

   if (VG_(clo_xml))
      VG_(printf_xml)("  </stack>\n");
}

/* Get and immediately print a StackTrace. */
void VG_(get_and_pp_StackTrace) ( ThreadId tid, UInt max_n_ips )
{
   Addr ips[max_n_ips];
   UInt n_ips
      = VG_(get_StackTrace)(tid, ips, max_n_ips,
                            NULL/*array to dump SP values in*/,
                            NULL/*array to dump FP values in*/,
                            0/*first_ip_delta*/);
   VG_(pp_StackTrace)(ips, n_ips);
}

void VG_(apply_StackTrace)(
        void(*action)(UInt n, Addr ip, void* opaque),
        void* opaque,
        StackTrace ips, UInt n_ips
     )
{
   Bool main_done = False;
   Int i = 0;

   vg_assert(n_ips > 0);
   do {
      Addr ip = ips[i];

      // Stop after the first appearance of "main" or one of the other names
      // (the appearance of which is a pretty good sign that we've gone past
      // main without seeing it, for whatever reason)
      if ( ! VG_(clo_show_below_main) ) {
         Vg_FnNameKind kind = VG_(get_fnname_kind_from_IP)(ip);
         if (Vg_FnNameMain == kind || Vg_FnNameBelowMain == kind) {
            main_done = True;
         }
      }

      // Act on the ip
      action(i, ip, opaque);

      i++;
   } while (i < n_ips && !main_done);

   #undef MYBUF_LEN
}


/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
