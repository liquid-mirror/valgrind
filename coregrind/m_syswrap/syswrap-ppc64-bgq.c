
/*--------------------------------------------------------------------*/
/*--- Platform-specific syscalls stuff.        syswrap-ppc64-bgq.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2005-2011 Nicholas Nethercote <njn@valgrind.org>
   Copyright (C) 2005-2011 Cerion Armour-Brown <cerion@open-works.co.uk>

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

#if defined(VGPV_ppc64_linux_bgq)

#include "pub_core_basics.h"
#include "pub_core_vki.h"
#include "pub_core_vkiscnums.h"
#include "pub_core_libcsetjmp.h"    // to keep _threadstate.h happy
#include "pub_core_threadstate.h"
#include "pub_core_debuginfo.h"     // VG_(di_notify_*)
#include "pub_core_aspacemgr.h"
#include "pub_core_transtab.h"      // VG_(discard_translations)
#include "pub_core_debuglog.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcprint.h"
#include "pub_core_libcproc.h"
#include "pub_core_libcsignal.h"
#include "pub_core_options.h"
#include "pub_core_scheduler.h"
#include "pub_core_sigframe.h"      // For VG_(sigframe_destroy)()
#include "pub_core_signals.h"
#include "pub_core_syscall.h"
#include "pub_core_syswrap.h"
#include "pub_core_tooliface.h"
#include "pub_core_stacks.h"        // VG_(register_stack)

#include "priv_types_n_macros.h"
#include "priv_syswrap-generic.h"   /* for decls of generic wrappers */
#include "priv_syswrap-linux.h"     /* for decls of linux-ish wrappers */
#include "priv_syswrap-main.h"


/* ---------------------------------------------------------------------
   clone() handling
   ------------------------------------------------------------------ */

/* Call f(arg1), but first switch stacks, using 'stack' as the new
   stack, and use 'retaddr' as f's return-to address.  Also, clear all
   the integer registers before entering f.*/
__attribute__((noreturn))
void ML_(call_on_new_stack_0_1) ( Addr stack,
                                  Addr retaddr,
                                  void (*f_desc)(Word),
                                  Word arg1 );
//    r3 = stack
//    r4 = retaddr
//    r5 = function descriptor
//    r6 = arg1
/* On PPC64, a func ptr is represented by a TOC entry ptr.
   This TOC entry contains three words; the first word is the function
   address, the second word is the TOC ptr (r2), and the third word is
   the static chain value. */
asm(
"   .align   2\n"
"   .globl   vgModuleLocal_call_on_new_stack_0_1\n"
"   .section \".opd\",\"aw\"\n"
"   .align   3\n"
"vgModuleLocal_call_on_new_stack_0_1:\n"
"   .quad    .vgModuleLocal_call_on_new_stack_0_1,.TOC.@tocbase,0\n"
"   .previous\n"
"   .type    .vgModuleLocal_call_on_new_stack_0_1,@function\n"
"   .globl   .vgModuleLocal_call_on_new_stack_0_1\n"
".vgModuleLocal_call_on_new_stack_0_1:\n"
"   mr    %r1,%r3\n\t"     // stack to %sp
"   mtlr  %r4\n\t"         // retaddr to %lr
"   ld 5,0(5)\n\t"         // load f_ptr from f_desc[0]
"   mtctr %r5\n\t"         // f_ptr to count reg
"   mr %r3,%r6\n\t"        // arg1 to %r3
"   li 0,0\n\t"            // zero all GP regs
"   li 4,0\n\t"
"   li 5,0\n\t"
"   li 6,0\n\t"
"   li 7,0\n\t"
"   li 8,0\n\t"
"   li 9,0\n\t"
"   li 10,0\n\t"
"   li 11,0\n\t"
"   li 12,0\n\t"
"   li 13,0\n\t"
"   li 14,0\n\t"
"   li 15,0\n\t"
"   li 16,0\n\t"
"   li 17,0\n\t"
"   li 18,0\n\t"
"   li 19,0\n\t"
"   li 20,0\n\t"
"   li 21,0\n\t"
"   li 22,0\n\t"
"   li 23,0\n\t"
"   li 24,0\n\t"
"   li 25,0\n\t"
"   li 26,0\n\t"
"   li 27,0\n\t"
"   li 28,0\n\t"
"   li 29,0\n\t"
"   li 30,0\n\t"
"   li 31,0\n\t"
"   mtxer 0\n\t"           // CAB: Need this?
"   mtcr 0\n\t"            // CAB: Need this?
"   bctr\n\t"              // jump to dst
"   trap\n"                // should never get here
);


/*
        Perform a clone system call.  clone is strange because it has
        fork()-like return-twice semantics, so it needs special
        handling here.

        Upon entry, we have:

            word (fn)(void*)    in r3
            void* child_stack   in r4
            word flags          in r5
            void* arg           in r6
            pid_t* child_tid    in r7
            pid_t* parent_tid   in r8
            void* ???           in r9

        Note: r3 contains fn desc ptr, not fn ptr -- p_fn = p_fn_desc[0]
        System call requires:

            int    $__NR_clone  in r0  (sc number)
            int    flags        in r3  (sc arg1)
            void*  child_stack  in r4  (sc arg2)
            pid_t* parent_tid   in r5  (sc arg3)
            ??     child_tls    in r6  (sc arg4)
            pid_t* child_tid    in r7  (sc arg5)
            void*  ???          in r8  (sc arg6)

        Returns a ULong encoded as: top half is %cr following syscall,
        low half is syscall return value (r3).
 */
#define __NR_CLONE        VG_STRINGIFY(__NR_clone)
#define __NR_EXIT         VG_STRINGIFY(__NR_exit)

extern
ULong do_syscall_clone_ppc64_linux ( Word (*fn)(void *), 
                                     void* stack, 
                                     Int   flags, 
                                     void* arg,
                                     Int*  child_tid, 
                                     Int*  parent_tid, 
                                     void/*vki_modify_ldt_t*/ * );
asm(
"   .align   2\n"
"   .globl   do_syscall_clone_ppc64_linux\n"
"   .section \".opd\",\"aw\"\n"
"   .align   3\n"
"do_syscall_clone_ppc64_linux:\n"
"   .quad    .do_syscall_clone_ppc64_linux,.TOC.@tocbase,0\n"
"   .previous\n"
"   .type    .do_syscall_clone_ppc64_linux,@function\n"
"   .globl   .do_syscall_clone_ppc64_linux\n"
".do_syscall_clone_ppc64_linux:\n"
"       stdu    1,-64(1)\n"
"       std     29,40(1)\n"
"       std     30,48(1)\n"
"       std     31,56(1)\n"
"       mr      30,3\n"              // preserve fn
"       mr      31,6\n"              // preserve arg

        // setup child stack
"       rldicr  4,4, 0,59\n"         // trim sp to multiple of 16 bytes
                                     // (r4 &= ~0xF)
"       li      0,0\n"
"       stdu    0,-32(4)\n"          // make initial stack frame
"       mr      29,4\n"              // preserve sp

        // setup syscall
"       li      0,"__NR_CLONE"\n"    // syscall number
"       mr      3,5\n"               // syscall arg1: flags
        // r4 already setup          // syscall arg2: child_stack
"       mr      5,8\n"               // syscall arg3: parent_tid
"       mr      6,13\n"              // syscall arg4: REAL THREAD tls
"       mr      7,7\n"               // syscall arg5: child_tid
"       mr      8,8\n"               // syscall arg6: ????
"       mr      9,9\n"               // syscall arg7: ????

//"  li 8,0\n"
//"  li 9,0\n"
//"  li 6,0\n"

"       sc\n"                        // clone()

"       mfcr    4\n"                 // CR now in low half r4
"       sldi    4,4,32\n"            // CR now in hi half r4

"       sldi    3,3,32\n"
"       srdi    3,3,32\n"            // zero out hi half r3

"       or      3,3,4\n"             // r3 = CR : syscall-retval
"       cmpwi   3,0\n"               // child if retval == 0 (note, cmpw)
"       bne     1f\n"                // jump if !child

        /* CHILD - call thread function */
        /* Note: 2.4 kernel doesn't set the child stack pointer,
           so we do it here.
           That does leave a small window for a signal to be delivered
           on the wrong stack, unfortunately. */
"       mr      1,29\n"
"       ld      30, 0(30)\n"         // convert fn desc ptr to fn ptr
"       mtctr   30\n"                // ctr reg = fn
"       mr      3,31\n"              // r3 = arg
"       bctrl\n"                     // call fn()

        // exit with result
"       li      0,"__NR_EXIT"\n"
"       sc\n"

        // Exit returned?!
"       .long   0\n"

        // PARENT or ERROR - return
"1:     ld      29,40(1)\n"
"       ld      30,48(1)\n"
"       ld      31,56(1)\n"
"       addi    1,1,64\n"
"       blr\n"
);

#undef __NR_CLONE
#undef __NR_EXIT

// forward declarations
static void setup_child ( ThreadArchState*, ThreadArchState* );

/* 
   When a client clones, we need to keep track of the new thread.  This means:
   1. allocate a ThreadId+ThreadState+stack for the the thread

   2. initialize the thread's new VCPU state

   3. create the thread using the same args as the client requested,
   but using the scheduler entrypoint for IP, and a separate stack
   for SP.
 */
static SysRes do_clone ( ThreadId ptid, 
                         UInt flags, Addr sp, 
                         Int *parent_tidptr, 
                         Int *child_tidptr, 
                         Addr child_tls)
{
   const Bool debug = False;

   ThreadId     ctid = VG_(alloc_ThreadState)();
   ThreadState* ptst = VG_(get_ThreadState)(ptid);
   ThreadState* ctst = VG_(get_ThreadState)(ctid);
   ULong        word64;
   UWord*       stack;
   NSegment const* seg;
   SysRes       res;
   vki_sigset_t blockall, savedmask;

   VG_(sigfillset)(&blockall);

   vg_assert(VG_(is_running_thread)(ptid));
   vg_assert(VG_(is_valid_tid)(ctid));

   stack = (UWord*)ML_(allocstack)(ctid);
   if (stack == NULL) {
      res = VG_(mk_SysRes_Error)( VKI_ENOMEM );
      goto out;
   }

//?   /* make a stack frame */
//?   stack -= 16;
//?   *(UWord *)stack = 0;


   /* Copy register state

      Both parent and child return to the same place, and the code
      following the clone syscall works out which is which, so we
      don't need to worry about it.

      The parent gets the child's new tid returned from clone, but the
      child gets 0.

      If the clone call specifies a NULL SP for the new thread, then
      it actually gets a copy of the parent's SP.

      The child's TLS register (r2) gets set to the tlsaddr argument
      if the CLONE_SETTLS flag is set.
   */
   setup_child( &ctst->arch, &ptst->arch );

   /* Make sys_clone appear to have returned Success(0) in the
      child. */
   { UInt old_cr = LibVEX_GuestPPC64_get_CR( &ctst->arch.vex );
     /* %r3 = 0 */
     ctst->arch.vex.guest_GPR3 = 0;
     /* %cr0.so = 0 */
     LibVEX_GuestPPC64_put_CR( old_cr & ~(1<<28), &ctst->arch.vex );
   }

   if (sp != 0)
      ctst->arch.vex.guest_GPR1 = sp;

   ctst->os_state.parent = ptid;

   /* inherit signal mask */
   ctst->sig_mask = ptst->sig_mask;
   ctst->tmp_sig_mask = ptst->sig_mask;

   /* Start the child with its threadgroup being the same as the
      parent's.  This is so that any exit_group calls that happen
      after the child is created but before it sets its
      os_state.threadgroup field for real (in thread_wrapper in
      syswrap-linux.c), really kill the new thread.  a.k.a this avoids
      a race condition in which the thread is unkillable (via
      exit_group) because its threadgroup is not set.  The race window
      is probably only a few hundred or a few thousand cycles long.
      See #226116. */
   ctst->os_state.threadgroup = ptst->os_state.threadgroup;

   /* We don't really know where the client stack is, because its
      allocated by the client.  The best we can do is look at the
      memory mappings and try to derive some useful information.  We
      assume that esp starts near its highest possible value, and can
      only go down to the start of the mmaped segment. */
   seg = VG_(am_find_nsegment)(sp);
   if (seg && seg->kind != SkResvn) {
      ctst->client_stack_highest_word = (Addr)VG_PGROUNDUP(sp);
      ctst->client_stack_szB = ctst->client_stack_highest_word - seg->start;

      VG_(register_stack)(seg->start, ctst->client_stack_highest_word);

      if (debug)
	 VG_(printf)("\ntid %d: guessed client stack range %#lx-%#lx\n",
		     ctid, seg->start, VG_PGROUNDUP(sp));
   } else {
      VG_(message)(Vg_UserMsg,
                   "!? New thread %d starts with R1(%#lx) unmapped\n",
		   ctid, sp);
      ctst->client_stack_szB  = 0;
   }

   /* Assume the clone will succeed, and tell any tool that wants to
      know that this thread has come into existence.  If the clone
      fails, we'll send out a ll_exit notification for it at the out:
      label below, to clean up. */
   vg_assert(VG_(owns_BigLock_LL)(ptid));
   VG_TRACK ( pre_thread_ll_create, ptid, ctid );

   if (flags & VKI_CLONE_SETTLS) {
      if (debug)
         VG_(printf)("clone child has SETTLS: tls at %#lx\n", child_tls);
      ctst->arch.vex.guest_GPR13 = child_tls;
   }

   /* At this point the ppc64-linux and ppc64-bgq behaviours differ
      slightly.  For ppc64-linux, we run with r13 (the TLS register) ==
      0 permanently, and explicitly do not ask for CLONE_SETTLS (viz,
      it is not propagated into the child).  But the CNK doesn't like
      CLONE_SETTLS == 0, so we have to set it; but then it objects to
      r13 being zero.  So (1) set CLONE_SETTLS == 1 and (2) point r13
      at something harmless; we are never going to use it.  This keeps
      the CNK happy. */

   //flags &= ~VKI_CLONE_SETTLS; // PPC64-LINUX implementation

   // BEGIN BGQ hack
   flags |= VKI_CLONE_SETTLS;
   /* The first time through, we expect r13 to be zero.  If so we
      point it at the dummy area and set it to all 0x55.  On
      subsequent passes we take care to check that r13 remains what we
      set it to and that the area is unchanged, as a sanity check. */
   static ULong harmless[512]; /* DO NOT MAKE NON-STATIC */
   ULong r13;
   __asm__ __volatile__("mr %0, 13" : "=r"(r13) );
   if (r13 == 0) {
      UWord i;
      for (i = 0; i < 512; i++) {
         harmless[i] = 0x5555555555555555ULL;
      }
      __asm__ __volatile__( "mr 13, %0" : : "r"(&harmless[256]) : "r13");
   } else {
      UWord i;
      vg_assert(r13 == (ULong)(UWord)&harmless[256]);
      for (i = 0; i < 512; i++) {
         vg_assert(harmless[i] == 0x5555555555555555ULL);
      }
   }
   /* and check again .. */
   __asm__ __volatile__("mr %0, 13" : "=r"(r13) );
   vg_assert(r13 == (ULong)(UWord)&harmless[256]);
   // END BGQ hack

   /* start the thread with everything blocked */
   VG_(sigprocmask)(VKI_SIG_SETMASK, &blockall, &savedmask);

   /* Create the new thread */
   word64 = do_syscall_clone_ppc64_linux(
               ML_(start_thread_NORETURN),
               stack, flags, &VG_(threads)[ctid],
               child_tidptr, parent_tidptr, NULL
            );

   /* Low half word64 is syscall return value.  Hi half is
      the entire CR, from which we need to extract CR0.SO. */
   /* VG_(printf)("word64 = 0x%llx\n", word64); */
   res = VG_(mk_SysRes_ppc64_linux)( 
            /*val*/(UInt)(word64 & 0xFFFFFFFFULL), 
            /*errflag*/ (UInt)((word64 >> (32+28)) & 1)
         );

   VG_(sigprocmask)(VKI_SIG_SETMASK, &savedmask, NULL);

  out:
   if (sr_isError(res)) {
      /* clone failed */
      VG_(cleanup_thread)(&ctst->arch);
      ctst->status = VgTs_Empty;
      /* oops.  Better tell the tool the thread exited in a hurry :-) */
      VG_TRACK( pre_thread_ll_exit, ctid );
   }

   return res;
}



/* ---------------------------------------------------------------------
   More thread stuff
   ------------------------------------------------------------------ */

void VG_(cleanup_thread) ( ThreadArchState* arch )
{
}  

void setup_child ( /*OUT*/ ThreadArchState *child,
                   /*IN*/  ThreadArchState *parent )
{
   /* We inherit our parent's guest state. */
   child->vex = parent->vex;
   child->vex_shadow1 = parent->vex_shadow1;
   child->vex_shadow2 = parent->vex_shadow2;
}


/* ---------------------------------------------------------------------
   PRE/POST wrappers for ppc64/Linux-specific syscalls
   ------------------------------------------------------------------ */

#define PRE(name)       DEFN_PRE_TEMPLATE(ppc64_bgq, name)
#define POST(name)      DEFN_POST_TEMPLATE(ppc64_bgq, name)

/* Add prototypes for the wrappers declared here, so that gcc doesn't
   harass us for not having prototypes.  Really this is a kludge --
   the right thing to do is to make these wrappers 'static' since they
   aren't visible outside this file, but that requires even more macro
   magic. */

//QQDECL_TEMPLATE(ppc64_bgq, sys_socketcall);
DECL_TEMPLATE(ppc64_bgq, sys_mmap);
DECL_TEMPLATE(ppc64_bgq, sys_munmap);
DECL_TEMPLATE(ppc64_bgq, sys_mprotect);
DECL_TEMPLATE(ppc64_bgq, sys_brk);
//QQ//zz DECL_TEMPLATE(ppc64_bgq, sys_mmap2);
//QQ//zz DECL_TEMPLATE(ppc64_bgq, sys_stat64);
//QQ//zz DECL_TEMPLATE(ppc64_bgq, sys_lstat64);
//QQ//zz DECL_TEMPLATE(ppc64_bgq, sys_fstat64);
//QQDECL_TEMPLATE(ppc64_bgq, sys_ipc);
DECL_TEMPLATE(ppc64_bgq, sys_clone);
//QQ//zz DECL_TEMPLATE(ppc64_bgq, sys_sigreturn);
//QQDECL_TEMPLATE(ppc64_bgq, sys_rt_sigreturn);
//QQDECL_TEMPLATE(ppc64_bgq, sys_fadvise64);

//QQPRE(sys_socketcall)
//QQ{
//QQ#  define ARG2_0  (((UWord*)ARG2)[0])
//QQ#  define ARG2_1  (((UWord*)ARG2)[1])
//QQ#  define ARG2_2  (((UWord*)ARG2)[2])
//QQ#  define ARG2_3  (((UWord*)ARG2)[3])
//QQ#  define ARG2_4  (((UWord*)ARG2)[4])
//QQ#  define ARG2_5  (((UWord*)ARG2)[5])
//QQ
//QQ   *flags |= SfMayBlock;
//QQ   PRINT("sys_socketcall ( %ld, %#lx )",ARG1,ARG2);
//QQ   PRE_REG_READ2(long, "socketcall", int, call, unsigned long *, args);
//QQ
//QQ   switch (ARG1 /* request */) {
//QQ
//QQ   case VKI_SYS_SOCKETPAIR:
//QQ     /* int socketpair(int d, int type, int protocol, int sv[2]); */
//QQ      PRE_MEM_READ( "socketcall.socketpair(args)", ARG2, 4*sizeof(Addr) );
//QQ      ML_(generic_PRE_sys_socketpair)( tid, ARG2_0, ARG2_1, ARG2_2, ARG2_3 );
//QQ      break;
//QQ
//QQ   case VKI_SYS_SOCKET:
//QQ     /* int socket(int domain, int type, int protocol); */
//QQ      PRE_MEM_READ( "socketcall.socket(args)", ARG2, 3*sizeof(Addr) );
//QQ      break;
//QQ
//QQ   case VKI_SYS_BIND:
//QQ     /* int bind(int sockfd, struct sockaddr *my_addr,
//QQ	int addrlen); */
//QQ      PRE_MEM_READ( "socketcall.bind(args)", ARG2, 3*sizeof(Addr) );
//QQ      ML_(generic_PRE_sys_bind)( tid, ARG2_0, ARG2_1, ARG2_2 );
//QQ      break;
//QQ
//QQ   case VKI_SYS_LISTEN:
//QQ     /* int listen(int s, int backlog); */
//QQ      PRE_MEM_READ( "socketcall.listen(args)", ARG2, 2*sizeof(Addr) );
//QQ      break;
//QQ
//QQ   case VKI_SYS_ACCEPT: {
//QQ     /* int accept(int s, struct sockaddr *addr, int *addrlen); */
//QQ      PRE_MEM_READ( "socketcall.accept(args)", ARG2, 3*sizeof(Addr) );
//QQ      ML_(generic_PRE_sys_accept)( tid, ARG2_0, ARG2_1, ARG2_2 );
//QQ      break;
//QQ   }
//QQ
//QQ   case VKI_SYS_ACCEPT4: {
//QQ     /* int accept4(int s, struct sockaddr *addr, int *addrlen, int flags); */
//QQ      PRE_MEM_READ( "socketcall.accept4(args)", ARG2, 4*sizeof(Addr) );
//QQ      ML_(generic_PRE_sys_accept)( tid, ARG2_0, ARG2_1, ARG2_2 );
//QQ      break;
//QQ   }
//QQ
//QQ   case VKI_SYS_SENDTO:
//QQ     /* int sendto(int s, const void *msg, int len,
//QQ                    unsigned int flags,
//QQ                    const struct sockaddr *to, int tolen); */
//QQ     PRE_MEM_READ( "socketcall.sendto(args)", ARG2, 6*sizeof(Addr) );
//QQ     ML_(generic_PRE_sys_sendto)( tid, ARG2_0, ARG2_1, ARG2_2,
//QQ				  ARG2_3, ARG2_4, ARG2_5 );
//QQ     break;
//QQ
//QQ   case VKI_SYS_SEND:
//QQ     /* int send(int s, const void *msg, size_t len, int flags); */
//QQ     PRE_MEM_READ( "socketcall.send(args)", ARG2, 4*sizeof(Addr) );
//QQ     ML_(generic_PRE_sys_send)( tid, ARG2_0, ARG2_1, ARG2_2 );
//QQ     break;
//QQ
//QQ   case VKI_SYS_RECVFROM:
//QQ     /* int recvfrom(int s, void *buf, int len, unsigned int flags,
//QQ	struct sockaddr *from, int *fromlen); */
//QQ     PRE_MEM_READ( "socketcall.recvfrom(args)", ARG2, 6*sizeof(Addr) );
//QQ     ML_(generic_PRE_sys_recvfrom)( tid, ARG2_0, ARG2_1, ARG2_2,
//QQ				    ARG2_3, ARG2_4, ARG2_5 );
//QQ     break;
//QQ
//QQ   case VKI_SYS_RECV:
//QQ     /* int recv(int s, void *buf, int len, unsigned int flags); */
//QQ     /* man 2 recv says:
//QQ         The  recv call is normally used only on a connected socket
//QQ         (see connect(2)) and is identical to recvfrom with a  NULL
//QQ         from parameter.
//QQ     */
//QQ     PRE_MEM_READ( "socketcall.recv(args)", ARG2, 4*sizeof(Addr) );
//QQ     ML_(generic_PRE_sys_recv)( tid, ARG2_0, ARG2_1, ARG2_2 );
//QQ     break;
//QQ
//QQ   case VKI_SYS_CONNECT:
//QQ     /* int connect(int sockfd,
//QQ	struct sockaddr *serv_addr, int addrlen ); */
//QQ     PRE_MEM_READ( "socketcall.connect(args)", ARG2, 3*sizeof(Addr) );
//QQ     ML_(generic_PRE_sys_connect)( tid, ARG2_0, ARG2_1, ARG2_2 );
//QQ     break;
//QQ
//QQ   case VKI_SYS_SETSOCKOPT:
//QQ     /* int setsockopt(int s, int level, int optname,
//QQ	const void *optval, int optlen); */
//QQ     PRE_MEM_READ( "socketcall.setsockopt(args)", ARG2, 5*sizeof(Addr) );
//QQ     ML_(generic_PRE_sys_setsockopt)( tid, ARG2_0, ARG2_1, ARG2_2,
//QQ				      ARG2_3, ARG2_4 );
//QQ     break;
//QQ
//QQ   case VKI_SYS_GETSOCKOPT:
//QQ     /* int getsockopt(int s, int level, int optname,
//QQ	void *optval, socklen_t *optlen); */
//QQ     PRE_MEM_READ( "socketcall.getsockopt(args)", ARG2, 5*sizeof(Addr) );
//QQ     ML_(linux_PRE_sys_getsockopt)( tid, ARG2_0, ARG2_1, ARG2_2,
//QQ				    ARG2_3, ARG2_4 );
//QQ     break;
//QQ
//QQ   case VKI_SYS_GETSOCKNAME:
//QQ     /* int getsockname(int s, struct sockaddr* name, int* namelen) */
//QQ     PRE_MEM_READ( "socketcall.getsockname(args)", ARG2, 3*sizeof(Addr) );
//QQ     ML_(generic_PRE_sys_getsockname)( tid, ARG2_0, ARG2_1, ARG2_2 );
//QQ     break;
//QQ
//QQ   case VKI_SYS_GETPEERNAME:
//QQ     /* int getpeername(int s, struct sockaddr* name, int* namelen) */
//QQ     PRE_MEM_READ( "socketcall.getpeername(args)", ARG2, 3*sizeof(Addr) );
//QQ     ML_(generic_PRE_sys_getpeername)( tid, ARG2_0, ARG2_1, ARG2_2 );
//QQ     break;
//QQ
//QQ   case VKI_SYS_SHUTDOWN:
//QQ     /* int shutdown(int s, int how); */
//QQ     PRE_MEM_READ( "socketcall.shutdown(args)", ARG2, 2*sizeof(Addr) );
//QQ     break;
//QQ
//QQ   case VKI_SYS_SENDMSG: {
//QQ     /* int sendmsg(int s, const struct msghdr *msg, int flags); */
//QQ
//QQ     /* this causes warnings, and I don't get why. glibc bug?
//QQ      * (after all it's glibc providing the arguments array)
//QQ       PRE_MEM_READ( "socketcall.sendmsg(args)", ARG2, 3*sizeof(Addr) );
//QQ     */
//QQ     ML_(generic_PRE_sys_sendmsg)( tid, "msg", (struct vki_msghdr *)ARG2_1 );
//QQ     break;
//QQ   }
//QQ
//QQ   case VKI_SYS_RECVMSG: {
//QQ     /* int recvmsg(int s, struct msghdr *msg, int flags); */
//QQ
//QQ     /* this causes warnings, and I don't get why. glibc bug?
//QQ      * (after all it's glibc providing the arguments array)
//QQ       PRE_MEM_READ("socketcall.recvmsg(args)", ARG2, 3*sizeof(Addr) );
//QQ     */
//QQ     ML_(generic_PRE_sys_recvmsg)( tid, "msg", (struct vki_msghdr *)ARG2_1 );
//QQ     break;
//QQ   }
//QQ
//QQ   default:
//QQ     VG_(message)(Vg_DebugMsg,"Warning: unhandled socketcall 0x%lx\n",ARG1);
//QQ     SET_STATUS_Failure( VKI_EINVAL );
//QQ     break;
//QQ   }
//QQ#  undef ARG2_0
//QQ#  undef ARG2_1
//QQ#  undef ARG2_2
//QQ#  undef ARG2_3
//QQ#  undef ARG2_4
//QQ#  undef ARG2_5
//QQ}
//QQ
//QQPOST(sys_socketcall)
//QQ{
//QQ#  define ARG2_0  (((UWord*)ARG2)[0])
//QQ#  define ARG2_1  (((UWord*)ARG2)[1])
//QQ#  define ARG2_2  (((UWord*)ARG2)[2])
//QQ#  define ARG2_3  (((UWord*)ARG2)[3])
//QQ#  define ARG2_4  (((UWord*)ARG2)[4])
//QQ#  define ARG2_5  (((UWord*)ARG2)[5])
//QQ
//QQ  SysRes r;
//QQ  vg_assert(SUCCESS);
//QQ  switch (ARG1 /* request */) {
//QQ
//QQ  case VKI_SYS_SOCKETPAIR:
//QQ    r = ML_(generic_POST_sys_socketpair)(
//QQ					 tid, VG_(mk_SysRes_Success)(RES),
//QQ					 ARG2_0, ARG2_1, ARG2_2, ARG2_3
//QQ					 );
//QQ    SET_STATUS_from_SysRes(r);
//QQ    break;
//QQ
//QQ  case VKI_SYS_SOCKET:
//QQ    r = ML_(generic_POST_sys_socket)( tid, VG_(mk_SysRes_Success)(RES) );
//QQ    SET_STATUS_from_SysRes(r);
//QQ    break;
//QQ
//QQ  case VKI_SYS_BIND:
//QQ    /* int bind(int sockfd, struct sockaddr *my_addr,
//QQ       int addrlen); */
//QQ    break;
//QQ
//QQ  case VKI_SYS_LISTEN:
//QQ    /* int listen(int s, int backlog); */
//QQ    break;
//QQ
//QQ  case VKI_SYS_ACCEPT:
//QQ  case VKI_SYS_ACCEPT4:
//QQ    /* int accept(int s, struct sockaddr *addr, int *addrlen); */
//QQ    /* int accept4(int s, struct sockaddr *addr, int *addrlen, int flags); */
//QQ    r = ML_(generic_POST_sys_accept)( tid, VG_(mk_SysRes_Success)(RES),
//QQ				      ARG2_0, ARG2_1, ARG2_2 );
//QQ    SET_STATUS_from_SysRes(r);
//QQ    break;
//QQ
//QQ  case VKI_SYS_SENDTO:
//QQ    break;
//QQ
//QQ  case VKI_SYS_SEND:
//QQ    break;
//QQ
//QQ  case VKI_SYS_RECVFROM:
//QQ    ML_(generic_POST_sys_recvfrom)( tid, VG_(mk_SysRes_Success)(RES),
//QQ				    ARG2_0, ARG2_1, ARG2_2,
//QQ				    ARG2_3, ARG2_4, ARG2_5 );
//QQ    break;
//QQ
//QQ  case VKI_SYS_RECV:
//QQ    ML_(generic_POST_sys_recv)( tid, RES, ARG2_0, ARG2_1, ARG2_2 );
//QQ    break;
//QQ
//QQ  case VKI_SYS_CONNECT:
//QQ    break;
//QQ
//QQ  case VKI_SYS_SETSOCKOPT:
//QQ    break;
//QQ
//QQ  case VKI_SYS_GETSOCKOPT:
//QQ    ML_(linux_POST_sys_getsockopt)( tid, VG_(mk_SysRes_Success)(RES),
//QQ				    ARG2_0, ARG2_1,
//QQ				    ARG2_2, ARG2_3, ARG2_4 );
//QQ    break;
//QQ
//QQ  case VKI_SYS_GETSOCKNAME:
//QQ    ML_(generic_POST_sys_getsockname)( tid, VG_(mk_SysRes_Success)(RES),
//QQ				       ARG2_0, ARG2_1, ARG2_2 );
//QQ    break;
//QQ
//QQ  case VKI_SYS_GETPEERNAME:
//QQ    ML_(generic_POST_sys_getpeername)( tid, VG_(mk_SysRes_Success)(RES),
//QQ				       ARG2_0, ARG2_1, ARG2_2 );
//QQ    break;
//QQ
//QQ  case VKI_SYS_SHUTDOWN:
//QQ    break;
//QQ
//QQ  case VKI_SYS_SENDMSG:
//QQ    break;
//QQ
//QQ  case VKI_SYS_RECVMSG:
//QQ    ML_(generic_POST_sys_recvmsg)( tid, "msg", (struct vki_msghdr *)ARG2_1, RES );
//QQ    break;
//QQ
//QQ  default:
//QQ    VG_(message)(Vg_DebugMsg,"FATAL: unhandled socketcall 0x%lx\n",ARG1);
//QQ    VG_(core_panic)("... bye!\n");
//QQ    break; /*NOTREACHED*/
//QQ  }
//QQ#  undef ARG2_0
//QQ#  undef ARG2_1
//QQ#  undef ARG2_2
//QQ#  undef ARG2_3
//QQ#  undef ARG2_4
//QQ#  undef ARG2_5
//QQ}

///////////////////////////////////////////////////////////////////
// BEGIN AM-Obs specials

PRE(sys_mmap)
{
   SysRes r;

   PRINT("sys_mmap ( %#lx, %llu, %ld, %ld, %ld, %ld )",
         ARG1, (ULong)ARG2, ARG3, ARG4, ARG5, ARG6 );
   PRE_REG_READ6(long, "mmap",
                 unsigned long, start, unsigned long, length,
                 unsigned long, prot,  unsigned long, flags,
                 unsigned long, fd,    unsigned long, offset);

   // Just pass through to the kernel and notify aspacem and tool accordingly.
   r = VG_(do_syscall6)(__NR_mmap, ARG1, ARG2, ARG3, ARG4, ARG5, ARG6);
   if (!sr_isError(r)) { 
      // notify aspacem and tool
      Bool d = VG_(am_notify_client_mmap)(
                  sr_Res(r), ARG2, ARG3, ARG4, ARG5, ARG6 );
      if (d)
         VG_(discard_translations)( sr_Res(r), ARG2, "PRE_(sys_mmap)");
      ULong di_handle
         = VG_(di_notify_mmap)( sr_Res(r), False/*allow_SkFileV*/, ARG5 );
      Bool rr = toBool(ARG3 & VKI_PROT_READ);
      Bool ww = toBool(ARG3 & VKI_PROT_WRITE);
      Bool xx = toBool(ARG3 & VKI_PROT_EXEC);
      VG_TRACK( new_mem_mmap, sr_Res(r), ARG2, rr, ww, xx, di_handle );
   }
   SET_STATUS_from_SysRes(r);
}


PRE(sys_munmap)
{
   SysRes r;
   PRINT("sys_munmap ( %#lx, %llu )", ARG1, (ULong)ARG2);
   PRE_REG_READ2(long, "munmap", unsigned long, start, vki_size_t, length);
   r = VG_(do_syscall2)(__NR_munmap, ARG1, ARG2);
   if (!sr_isError(r) && ARG2 > 0) { 
      // notify aspacem and tool
      Bool d = VG_(am_notify_munmap)( ARG1, ARG2 );
      VG_TRACK( die_mem_munmap, ARG1, ARG2 );
      VG_(di_notify_munmap)( ARG1, ARG2 );
      if (d) VG_(discard_translations)( ARG1, ARG2, "PRE_(sys_munmap)" );
   }
   SET_STATUS_from_SysRes(r);
}


/* mprotect handling is pretty close to the standard (non-ObsASpaceM)
   handling. */
PRE(sys_mprotect)
{
   PRINT("sys_mprotect ( %#lx, %llu, %ld )", ARG1,(ULong)ARG2,ARG3);
   PRE_REG_READ3(long, "mprotect",
                 unsigned long, addr, vki_size_t, len, unsigned long, prot);
}
POST(sys_mprotect)
{
   Addr a    = ARG1;
   SizeT len = ARG2;
   Int  prot = ARG3;
   ML_(notify_core_and_tool_of_mprotect)(a, len, prot);
}


PRE(sys_brk)
{
   /* JRS 2012-07-22: this is probably racey, since it is executed
      without holding the bigLock, and involves 2 calls to sys_brk.
      But if the app is doing uncoordinated calls to brk (the only
      case in which this would matter), it is broken anyway. */
   Addr brk_old, brk_new;

   /* libc   says: int   brk(void *end_data_segment);
      kernel says: void* brk(void* end_data_segment);  (more or less)

      libc returns 0 on success, and -1 (and sets errno) on failure.
      Nb: if you ask to shrink the dataseg end below what it
      currently is, that always succeeds, even if the dataseg end
      doesn't actually change (eg. brk(0)).  Unless it seg faults.

      Kernel returns the new dataseg end.  If the brk() failed, this
      will be unchanged from the old one.  That's why calling (kernel)
      brk(0) gives the current dataseg end (libc brk() just returns
      zero in that case).

      Both will seg fault if you shrink it back into a text segment.
   */
   PRINT("sys_brk ( %#lx )", ARG1);
   PRE_REG_READ1(unsigned long, "brk", unsigned long, end_data_segment);

   // Just hand through to the kernel.  If the address space changes
   // then notify tool and aspacem accordingly.
   SysRes sr;
   if (ARG1 == 0) {
      // Enquiring what the current brk is.
      sr = VG_(do_syscall1)(__NR_brk, 0);
      SET_STATUS_from_SysRes(sr);
   } else {
      // Making a change.  So we first need to get the current value.
      sr = VG_(do_syscall1)(__NR_brk, 0);
      if (sr_isError(sr)) { SET_STATUS_from_SysRes(sr); return; } // Hmm
      brk_old = sr_Res(sr);
      // and now make the change
      sr = VG_(do_syscall1)(__NR_brk, ARG1);
      if (sr_isError(sr)) { SET_STATUS_from_SysRes(sr); return; } // Hmm2
      brk_new = sr_Res(sr);

      // tell aspacem and tool
      if (brk_old < brk_new) {
         /* successfully grew the data segment */
         Bool d = VG_(am_notify_client_mmap)(
                     brk_old, brk_new - brk_old,
                     VKI_PROT_READ|VKI_PROT_WRITE,
                     VKI_MAP_PRIVATE|VKI_MAP_ANONYMOUS,
                     -1, 0 
                  );
         if (d)
            VG_(discard_translations)( brk_old, brk_new - brk_old,
                                       "PRE_(sys_brk).1");
         // new_mem_brk in Memcheck marks the new area as accessible but undefined,
         // which doesn't reflect what libc seems to assume.  So use new_mem_mmap
         // instead, with parameters that make it mark the memory as initialised.
         //VG_TRACK( new_mem_brk, brk_old, brk_new - brk_old, tid );
         VG_TRACK( new_mem_mmap, brk_old, brk_new - brk_old, 
                   True/*r*/, True/*w*/, False/*x*/, 0/*di_handle*/ );
      }
      if (brk_old > brk_new) {
         /* successfully shrunk the data segment. */
         Bool d = VG_(am_notify_munmap)( brk_new, brk_old - brk_new );
         if (d)
            VG_(discard_translations)( brk_new, brk_old - brk_new,
                                       "PRE(sys_brk).2" );
         VG_TRACK( die_mem_brk, brk_new, brk_old - brk_new );
      }

      SET_STATUS_from_SysRes(sr);
   }
}

// END AM-Obs specials
///////////////////////////////////////////////////////////////////


//QQ//zz PRE(sys_mmap2)
//QQ//zz {
//QQ//zz    SysRes r;
//QQ//zz 
//QQ//zz    // Exactly like old_mmap() except:
//QQ//zz    //  - the file offset is specified in 4K units rather than bytes,
//QQ//zz    //    so that it can be used for files bigger than 2^32 bytes.
//QQ//zz    PRINT("sys_mmap2 ( %p, %llu, %d, %d, %d, %d )",
//QQ//zz          ARG1, (ULong)ARG2, ARG3, ARG4, ARG5, ARG6 );
//QQ//zz    PRE_REG_READ6(long, "mmap2",
//QQ//zz                  unsigned long, start, unsigned long, length,
//QQ//zz                  unsigned long, prot,  unsigned long, flags,
//QQ//zz                  unsigned long, fd,    unsigned long, offset);
//QQ//zz 
//QQ//zz    r = ML_(generic_PRE_sys_mmap)( tid, ARG1, ARG2, ARG3, ARG4, ARG5, 
//QQ//zz                                        4096 * (Off64T)ARG6 );
//QQ//zz    SET_STATUS_from_SysRes(r);
//QQ//zz }
//QQ//zz 
//QQ//zz // XXX: lstat64/fstat64/stat64 are generic, but not necessarily
//QQ//zz // applicable to every architecture -- I think only to 32-bit archs.
//QQ//zz // We're going to need something like linux/core_os32.h for such
//QQ//zz // things, eventually, I think.  --njn
//QQ//zz PRE(sys_stat64)
//QQ//zz {
//QQ//zz    PRINT("sys_stat64 ( %p, %p )",ARG1,ARG2);
//QQ//zz    PRE_REG_READ2(long, "stat64", char *, file_name, struct stat64 *, buf);
//QQ//zz    PRE_MEM_RASCIIZ( "stat64(file_name)", ARG1 );
//QQ//zz    PRE_MEM_WRITE( "stat64(buf)", ARG2, sizeof(struct vki_stat64) );
//QQ//zz }
//QQ//zz 
//QQ//zz POST(sys_stat64)
//QQ//zz {
//QQ//zz    POST_MEM_WRITE( ARG2, sizeof(struct vki_stat64) );
//QQ//zz }
//QQ//zz 
//QQ//zz PRE(sys_lstat64)
//QQ//zz {
//QQ//zz    PRINT("sys_lstat64 ( %p(%s), %p )",ARG1,ARG1,ARG2);
//QQ//zz    PRE_REG_READ2(long, "lstat64", char *, file_name, struct stat64 *, buf);
//QQ//zz    PRE_MEM_RASCIIZ( "lstat64(file_name)", ARG1 );
//QQ//zz    PRE_MEM_WRITE( "lstat64(buf)", ARG2, sizeof(struct vki_stat64) );
//QQ//zz }
//QQ//zz 
//QQ//zz POST(sys_lstat64)
//QQ//zz {
//QQ//zz    vg_assert(SUCCESS);
//QQ//zz    if (RES == 0) {
//QQ//zz       POST_MEM_WRITE( ARG2, sizeof(struct vki_stat64) );
//QQ//zz    }
//QQ//zz }
//QQ//zz 
//QQ//zz PRE(sys_fstat64)
//QQ//zz {
//QQ//zz   PRINT("sys_fstat64 ( %d, %p )",ARG1,ARG2);
//QQ//zz   PRE_REG_READ2(long, "fstat64", unsigned long, fd, struct stat64 *, buf);
//QQ//zz   PRE_MEM_WRITE( "fstat64(buf)", ARG2, sizeof(struct vki_stat64) );
//QQ//zz }
//QQ//zz 
//QQ//zz POST(sys_fstat64)
//QQ//zz {
//QQ//zz   POST_MEM_WRITE( ARG2, sizeof(struct vki_stat64) );
//QQ//zz }
//QQ
//QQstatic Addr deref_Addr ( ThreadId tid, Addr a, Char* s )
//QQ{
//QQ   Addr* a_p = (Addr*)a;
//QQ   PRE_MEM_READ( s, (Addr)a_p, sizeof(Addr) );
//QQ   return *a_p;
//QQ}
//QQ
//QQPRE(sys_ipc)
//QQ{
//QQ  PRINT("sys_ipc ( %ld, %ld, %ld, %ld, %#lx, %ld )", ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
//QQ  // XXX: this is simplistic -- some args are not used in all circumstances.
//QQ  PRE_REG_READ6(int, "ipc",
//QQ		vki_uint, call, int, first, int, second, int, third,
//QQ		void *, ptr, long, fifth)
//QQ
//QQ    switch (ARG1 /* call */) {
//QQ    case VKI_SEMOP:
//QQ      ML_(generic_PRE_sys_semop)( tid, ARG2, ARG5, ARG3 );
//QQ      *flags |= SfMayBlock;
//QQ      break;
//QQ    case VKI_SEMGET:
//QQ      break;
//QQ    case VKI_SEMCTL:
//QQ      {
//QQ	UWord arg = deref_Addr( tid, ARG5, "semctl(arg)" );
//QQ	ML_(generic_PRE_sys_semctl)( tid, ARG2, ARG3, ARG4, arg );
//QQ	break;
//QQ      }
//QQ    case VKI_SEMTIMEDOP:
//QQ      ML_(generic_PRE_sys_semtimedop)( tid, ARG2, ARG5, ARG3, ARG6 );
//QQ      *flags |= SfMayBlock;
//QQ      break;
//QQ    case VKI_MSGSND:
//QQ      ML_(linux_PRE_sys_msgsnd)( tid, ARG2, ARG5, ARG3, ARG4 );
//QQ      if ((ARG4 & VKI_IPC_NOWAIT) == 0)
//QQ	*flags |= SfMayBlock;
//QQ      break;
//QQ    case VKI_MSGRCV:
//QQ      {
//QQ	Addr msgp;
//QQ	Word msgtyp;
//QQ
//QQ	msgp = deref_Addr( tid,
//QQ			   (Addr) (&((struct vki_ipc_kludge *)ARG5)->msgp),
//QQ			   "msgrcv(msgp)" );
//QQ	msgtyp = deref_Addr( tid,
//QQ			     (Addr) (&((struct vki_ipc_kludge *)ARG5)->msgtyp),
//QQ			     "msgrcv(msgp)" );
//QQ
//QQ	ML_(linux_PRE_sys_msgrcv)( tid, ARG2, msgp, ARG3, msgtyp, ARG4 );
//QQ
//QQ	if ((ARG4 & VKI_IPC_NOWAIT) == 0)
//QQ	  *flags |= SfMayBlock;
//QQ	break;
//QQ      }
//QQ    case VKI_MSGGET:
//QQ      break;
//QQ    case VKI_MSGCTL:
//QQ      ML_(linux_PRE_sys_msgctl)( tid, ARG2, ARG3, ARG5 );
//QQ      break;
//QQ    case VKI_SHMAT:
//QQ      {
//QQ	UWord w;
//QQ	PRE_MEM_WRITE( "shmat(raddr)", ARG4, sizeof(Addr) );
//QQ	w = ML_(generic_PRE_sys_shmat)( tid, ARG2, ARG5, ARG3 );
//QQ	if (w == 0)
//QQ	  SET_STATUS_Failure( VKI_EINVAL );
//QQ	else
//QQ	  ARG5 = w;
//QQ	break;
//QQ      }
//QQ    case VKI_SHMDT:
//QQ      if (!ML_(generic_PRE_sys_shmdt)(tid, ARG5))
//QQ	SET_STATUS_Failure( VKI_EINVAL );
//QQ      break;
//QQ    case VKI_SHMGET:
//QQ      break;
//QQ    case VKI_SHMCTL: /* IPCOP_shmctl */
//QQ      ML_(generic_PRE_sys_shmctl)( tid, ARG2, ARG3, ARG5 );
//QQ      break;
//QQ    default:
//QQ      VG_(message)(Vg_DebugMsg, "FATAL: unhandled syscall(ipc) %ld\n", ARG1 );
//QQ      VG_(core_panic)("... bye!\n");
//QQ      break; /*NOTREACHED*/
//QQ    }
//QQ}
//QQ
//QQPOST(sys_ipc)
//QQ{
//QQ  vg_assert(SUCCESS);
//QQ  switch (ARG1 /* call */) {
//QQ  case VKI_SEMOP:
//QQ  case VKI_SEMGET:
//QQ    break;
//QQ  case VKI_SEMCTL:
//QQ    {
//QQ      UWord arg = deref_Addr( tid, ARG5, "semctl(arg)" );
//QQ      ML_(generic_PRE_sys_semctl)( tid, ARG2, ARG3, ARG4, arg );
//QQ      break;
//QQ    }
//QQ  case VKI_SEMTIMEDOP:
//QQ  case VKI_MSGSND:
//QQ    break;
//QQ  case VKI_MSGRCV:
//QQ    {
//QQ      Addr msgp;
//QQ      Word msgtyp;
//QQ
//QQ      msgp = deref_Addr( tid,
//QQ                         (Addr) (&((struct vki_ipc_kludge *)ARG5)->msgp),
//QQ                         "msgrcv(msgp)" );
//QQ      msgtyp = deref_Addr( tid,
//QQ                           (Addr) (&((struct vki_ipc_kludge *)ARG5)->msgtyp),
//QQ                           "msgrcv(msgp)" );
//QQ
//QQ      ML_(linux_POST_sys_msgrcv)( tid, RES, ARG2, msgp, ARG3, msgtyp, ARG4 );
//QQ      break;
//QQ    }
//QQ  case VKI_MSGGET:
//QQ    break;
//QQ  case VKI_MSGCTL:
//QQ    ML_(linux_POST_sys_msgctl)( tid, RES, ARG2, ARG3, ARG5 );
//QQ    break;
//QQ  case VKI_SHMAT:
//QQ    {
//QQ      Addr addr;
//QQ
//QQ      /* force readability. before the syscall it is
//QQ       * indeed uninitialized, as can be seen in
//QQ       * glibc/sysdeps/unix/sysv/linux/shmat.c */
//QQ      POST_MEM_WRITE( ARG4, sizeof( Addr ) );
//QQ
//QQ      addr = deref_Addr ( tid, ARG4, "shmat(addr)" );
//QQ      ML_(generic_POST_sys_shmat)( tid, addr, ARG2, ARG5, ARG3 );
//QQ      break;
//QQ    }
//QQ  case VKI_SHMDT:
//QQ    ML_(generic_POST_sys_shmdt)( tid, RES, ARG5 );
//QQ    break;
//QQ  case VKI_SHMGET:
//QQ    break;
//QQ  case VKI_SHMCTL:
//QQ    ML_(generic_POST_sys_shmctl)( tid, RES, ARG2, ARG3, ARG5 );
//QQ    break;
//QQ  default:
//QQ    VG_(message)(Vg_DebugMsg,
//QQ		 "FATAL: unhandled syscall(ipc) %ld\n",
//QQ		 ARG1 );
//QQ    VG_(core_panic)("... bye!\n");
//QQ    break; /*NOTREACHED*/
//QQ  }
//QQ}

PRE(sys_clone)
{
   UInt cloneflags;

   PRINT("sys_clone ( %lx, %#lx, %#lx, %#lx, %#lx )",ARG1,ARG2,ARG3,ARG4,ARG5);
   PRE_REG_READ5(int, "clone",
                 unsigned long, flags,
                 void *,        child_stack,
                 int *,         parent_tidptr,
                 void *,        child_tls,
                 int *,         child_tidptr);
   if (ARG1 & VKI_CLONE_PARENT_SETTID) {
      PRE_MEM_WRITE("clone(parent_tidptr)", ARG3, sizeof(Int));
      if (!VG_(am_is_valid_for_client)(ARG3, sizeof(Int), 
                                             VKI_PROT_WRITE)) {
         SET_STATUS_Failure( VKI_EFAULT );
         return;
      }
   }
   if (ARG1 & (VKI_CLONE_CHILD_SETTID | VKI_CLONE_CHILD_CLEARTID)) {
      PRE_MEM_WRITE("clone(child_tidptr)", ARG5, sizeof(Int));
      if (!VG_(am_is_valid_for_client)(ARG5, sizeof(Int), 
                                             VKI_PROT_WRITE)) {
         SET_STATUS_Failure( VKI_EFAULT );
         return;
      }
   }

   cloneflags = ARG1;

   if (!ML_(client_signal_OK)(ARG1 & VKI_CSIGNAL)) {
      SET_STATUS_Failure( VKI_EINVAL );
      return;
   }

   /* Only look at the flags we really care about */
   switch (cloneflags & (VKI_CLONE_VM | VKI_CLONE_FS 
                         | VKI_CLONE_FILES | VKI_CLONE_VFORK)) {
   case VKI_CLONE_VM | VKI_CLONE_FS | VKI_CLONE_FILES:
      /* thread creation */
      SET_STATUS_from_SysRes(
         do_clone(tid,
                  ARG1,         /* flags */
                  (Addr)ARG2,   /* child SP */
                  (Int *)ARG3,  /* parent_tidptr */
                  (Int *)ARG5,  /* child_tidptr */
                  (Addr)ARG4)); /* child_tls */
      break;

   case VKI_CLONE_VFORK | VKI_CLONE_VM: /* vfork */
      /* FALLTHROUGH - assume vfork == fork */
      cloneflags &= ~(VKI_CLONE_VFORK | VKI_CLONE_VM);

   case 0: /* plain fork */
      SET_STATUS_from_SysRes(
         ML_(do_fork_clone)(tid,
                       cloneflags,      /* flags */
                       (Int *)ARG3,     /* parent_tidptr */
                       (Int *)ARG5));   /* child_tidptr */
      break;

   default:
      /* should we just ENOSYS? */
      VG_(message)(Vg_UserMsg, "Unsupported clone() flags: 0x%lx\n", ARG1);
      VG_(message)(Vg_UserMsg, "\n");
      VG_(message)(Vg_UserMsg, "The only supported clone() uses are:\n");
      VG_(message)(Vg_UserMsg, " - via a threads library (LinuxThreads or NPTL)\n");
      VG_(message)(Vg_UserMsg, " - via the implementation of fork or vfork\n");
      VG_(unimplemented)
         ("Valgrind does not support general clone().");
   }

   if (SUCCESS) {
      if (ARG1 & VKI_CLONE_PARENT_SETTID)
         POST_MEM_WRITE(ARG3, sizeof(Int));
      if (ARG1 & (VKI_CLONE_CHILD_SETTID | VKI_CLONE_CHILD_CLEARTID))
         POST_MEM_WRITE(ARG5, sizeof(Int));

      /* Thread creation was successful; let the child have the chance
         to run */
      *flags |= SfYieldAfter;
   }
}

//QQPRE(sys_fadvise64)
//QQ{
//QQ   PRINT("sys_fadvise64 ( %ld, %ld, %lu, %ld )", ARG1,ARG2,ARG3,ARG4);
//QQ   PRE_REG_READ4(long, "fadvise64",
//QQ                 int, fd, vki_loff_t, offset, vki_size_t, len, int, advice);
//QQ}
//QQ
//QQPRE(sys_rt_sigreturn)
//QQ{
//QQ   /* See comments on PRE(sys_rt_sigreturn) in syswrap-amd64-linux.c for
//QQ      an explanation of what follows. */
//QQ
//QQ   //ThreadState* tst;
//QQ   PRINT("sys_rt_sigreturn ( )");
//QQ
//QQ   vg_assert(VG_(is_valid_tid)(tid));
//QQ   vg_assert(tid >= 1 && tid < VG_N_THREADS);
//QQ   vg_assert(VG_(is_running_thread)(tid));
//QQ
//QQ   ///* Adjust esp to point to start of frame; skip back up over handler
//QQ   //   ret addr */
//QQ   //tst = VG_(get_ThreadState)(tid);
//QQ   //tst->arch.vex.guest_ESP -= sizeof(Addr);
//QQ   // Should we do something equivalent on ppc64-linux?  Who knows.
//QQ
//QQ   ///* This is only so that the EIP is (might be) useful to report if
//QQ   //   something goes wrong in the sigreturn */
//QQ   //ML_(fixup_guest_state_to_restart_syscall)(&tst->arch);
//QQ   // Should we do something equivalent on ppc64?  Who knows.
//QQ
//QQ   /* Restore register state from frame and remove it */
//QQ   VG_(sigframe_destroy)(tid, True);
//QQ
//QQ   /* Tell the driver not to update the guest state with the "result",
//QQ      and set a bogus result to keep it happy. */
//QQ   *flags |= SfNoWriteResult;
//QQ   SET_STATUS_Success(0);
//QQ
//QQ   /* Check to see if any signals arose as a result of this. */
//QQ   *flags |= SfPollAfter;
//QQ}

///////////////////////////////////////////////////////////////////
// BEGIN CNK specials

static void pmw_stack ( ThreadId tid, Addr a, SizeT size )
{
return;
vg_assert(0);
   vg_assert( ((a>>20)<<20) == 0x1dbff00000ULL ); // on stack
   POST_MEM_WRITE(a, 10*size);
}

// GETMEMORYREGION: (P?,S,S,S,S,S)
PRE(sys_1024)
{
   PRINT("sys_1024_GETMEMORYREGION ( %#lx,%#lx,%#lx,%#lx,%#lx,%#lx )",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}
POST(sys_1024)
{
   vg_assert(SUCCESS);
   //pmw_stack(tid, ARG1, 4096);
   if (ARG1)
      POST_MEM_WRITE(ARG1, 64);
}

// GET_PERSONALITY
PRE(sys_1025)
{
   PRINT("sys_GET_PERSONALITY(%#lx,%ld)", ARG1,ARG2);
   PRE_REG_READ2(int, "GET_PERSONALITY",
                 void*, dst, unsigned long, size);
   PRE_MEM_WRITE("GET_PERSONALITY(dst)", ARG1, ARG2);
}
POST(sys_1025)
{
   vg_assert(SUCCESS);
   POST_MEM_WRITE(ARG1, ARG2);
}

// SPECALLOCATEDOMAIN
PRE(sys_1029)
{
   PRINT("sys_1029(%#lx,%#lx,%#lx,%#lx,%#lx,%#lx)",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}

// ALLOCATE_INJ_FIFOS
PRE(sys_1032)
{
   PRINT("sys_1032(%#lx,%#lx,%#lx,%#lx,%#lx,%#lx)",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}
POST(sys_1032)
{
   vg_assert(SUCCESS);
   //pmw_stack(tid, ARG4, 4096);
}

// QUERY_INJ_FIFOS: (S,Pout,P?,S,S,S)
#define SYS_1033_QUERY_INJ_FIFOS_ARG2_SIZE 128  // a guess, but seems enough
PRE(sys_1033)
{
   PRINT("sys_1033_QUERY_INJ_FIFOS(%#lx,%#lx,%#lx,%#lx,%#lx,%#lx)",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}
POST(sys_1033)
{
   vg_assert(SUCCESS);
   if (ARG2 != 0)
      POST_MEM_WRITE(ARG2, 128);
   //pmw_stack(tid, ARG2,4096);
   //pmw_stack(tid, ARG3,4096);
}

// QUERY_REC_FIFOS: (S,P?,P?,S,S,S)
PRE(sys_1034)
{
   PRINT("sys_1034(%#lx,%#lx,%#lx,%#lx,%#lx,%#lx)",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}
POST(sys_1034)
{
   vg_assert(SUCCESS);
   if (ARG2 != 0)
      POST_MEM_WRITE(ARG2, 512);
   //pmw_stack(tid, ARG2,4096);
   //pmw_stack(tid, ARG3,4096);
}

// QUERY_BASE_ADDRESS_TABLE: (S,Pout,P?,S,P?,S)
PRE(sys_1035)
{
   PRINT("sys_1035_QUERY_BASE_ADDRESS_TABLE(%#lx,%#lx,%#lx,%#lx,%#lx,%#lx)",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}
POST(sys_1035)
{
   vg_assert(SUCCESS);
   if (ARG2 != 0)
      POST_MEM_WRITE(ARG2, 128);
   //pmw_stack(tid, ARG2,4096);
   //pmw_stack(tid, ARG3,4096);
}

// ALLOCATE_REC_FIFOS
PRE(sys_1036)
{
   PRINT("sys_1036(%#lx,%#lx,%#lx,%#lx,%#lx,%#lx)",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}
POST(sys_1036)
{
   vg_assert(SUCCESS);
   //pmw_stack(tid, ARG4,4096);
}

// ALLOCATE_BASE_ADDRESS_TABLE: (S,?,S,P,S,S)
PRE(sys_1037)
{
   PRINT("sys_1037(%#lx,%#lx,%#lx,%#lx,%#lx,%#lx)",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}
POST(sys_1037)
{
   vg_assert(SUCCESS);
   //pmw_stack(tid, ARG4,4096);
}

// REC_FIFO_ENABLE
PRE(sys_1038)
{
   PRINT("sys_1038(%#lx,%#lx,%#lx,%#lx,%#lx,%#lx)",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}

// CFG_INJ_FIFO_INTS
PRE(sys_1039)
{
   PRINT("sys_1039(%#lx,%#lx,%#lx,%#lx,%#lx,%#lx)",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}
POST(sys_1039)
{
   vg_assert(SUCCESS);
   //pmw_stack(tid,ARG3,4096);
}

// CFG_REC_FIFO_INTS
PRE(sys_1040)
{
   PRINT("sys_1040(%#lx,%#lx,%#lx,%#lx,%#lx,%#lx)",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}
POST(sys_1040)
{
   vg_assert(SUCCESS);
   //pmw_stack(tid, ARG3,4096);
}

// CFG_REC_FIFO_THRESH
PRE(sys_1042)
{
   PRINT("sys_1042(%#lx,%#lx,%#lx,%#lx,%#lx,%#lx)",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}

// RANKS2COORDS: (S,P?,Pout,S,S,S)
#define SYS_1055_RANKS2COORDS_ARG3_SIZE 64 // guess
PRE(sys_1055)
{
   PRINT("sys_1055_RANKS2COORDS(%#lx,%#lx,%#lx,%#lx,%#lx,%#lx)",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}
POST(sys_1055)
{
   vg_assert(SUCCESS);
   if (ARG3 != 0)
      POST_MEM_WRITE(ARG3, 64);
   //pmw_stack(tid, ARG3,4096);
}

// JOBCOORDS: (Pout,S,S,S,S,S)
#define SYS_1056_JOBCOORDS_ARG1_SIZE 64  // a guess, but seems enough
PRE(sys_1056)
{
   PRINT("sys_1056_JOBCOORDS(%#lx,%#lx,%#lx,%#lx,%#lx,%#lx)",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
   /* ARG1 points to an area written by the kernel, size <= 1312
      bytes.  Others args are non-pointers. */
}
POST(sys_1056)
{
   vg_assert(SUCCESS);
   if (ARG1 != 0)
      POST_MEM_WRITE(ARG1, 64);
   //pmw_stack(tid, ARG1,4096);
}

// ALLOCATEL2ATOMIC
PRE(sys_1059)
{
   PRINT("sys_1059_ALLOCATEL2ATOMIC(%#lx,%ld)", ARG1,ARG2);
   PRE_REG_READ2(int, "ALLOCATEL2ATOMIC", void*, base, unsigned long, len);
   PRE_MEM_WRITE("ALLOCATEL2ATOMIC.base", ARG1, ARG2);
}

// SETSPECSTATE
PRE(sys_1063)
{
   PRINT("sys_1063_SETSPECSTATE(%ld,%#lx)", ARG1,ARG2);
   PRE_REG_READ2(int, "SETSPECSTATE",
                 unsigned long, size, void*, base);
   PRE_MEM_READ("SETSPECSTATE.base", ARG2, ARG1);
}

// SETL2SCRUBRATE
PRE(sys_1064)
{
   PRINT("sys_1064(%#lx,%#lx,%#lx,%#lx,%#lx,%#lx)",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}

// QUERYCOLLECTIVECLASSROUTE
PRE(sys_1065)
{
   PRINT("sys_1065(%#lx,%#lx,%#lx,%#lx,%#lx,%#lx)",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}

// ALLOCATECOLLECTIVECLASSROUTE
PRE(sys_1066)
{
   PRINT("sys_1066(%#lx,%#lx,%#lx,%#lx,%#lx,%#lx)",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}

// SETCOLLECTIVECLASSROUTE
PRE(sys_1067)
{
   PRINT("sys_1067(%#lx,%#lx,%#lx,%#lx,%#lx,%#lx)",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}

// QUERYGINTCLASSROUTE
PRE(sys_1069)
{
   PRINT("sys_1069(%#lx,%#lx,%#lx,%#lx,%#lx,%#lx)",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}

// ALLOCATEGINTCLASSROUTE
PRE(sys_1070)
{
   PRINT("sys_1070(%#lx,%#lx,%#lx,%#lx,%#lx,%#lx)",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}

// SETGINTCLASSROUTE
PRE(sys_1071)
{
   PRINT("sys_1071(%#lx,%#lx,%#lx,%#lx,%#lx,%#lx)",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}

// SETNUMSPECDOMAINS
PRE(sys_1075)
{
   PRINT("sys_1075(%#lx,%#lx,%#lx,%#lx,%#lx,%#lx)",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}

// GETRANK
PRE(sys_1076)
{
   PRINT("sys_1075_GETRANK()");
}

// GETPVR: (P?,S,S,S,S,S)
PRE(sys_1089)
{
   PRINT("sys_1089_GETPVR(%#lx,%#lx,%#lx,%#lx,%#lx,%#lx)",
         ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}
POST(sys_1089)
{
   vg_assert(SUCCESS);
   if (ARG1 != 0)
      POST_MEM_WRITE(ARG1, 64);
   //pmw_stack(tid, ARG1,4096);
}

// ENABLEFASTSPECULATIONPATHS
PRE(sys_1090)
{
   PRINT("sys_1090_ENABLEFASTSPECULATIONPATHS()");
}

// END CNK specials
///////////////////////////////////////////////////////////////////

#undef PRE
#undef POST

/* ---------------------------------------------------------------------
   The ppc64/BGQ syscall table
   ------------------------------------------------------------------ */

/* In principle this is the same as the ppc64-linux table, except that
   we have to do some things (mmap, munmap, brk) differently because
   we are using an observational aspacemgr, not the normal one. */

/* Add an ppc64-linux specific wrapper to a syscall table. */
#define PLAX_(sysno, name)    WRAPPER_ENTRY_X_(ppc64_bgq, sysno, name) 
#define PLAXY(sysno, name)    WRAPPER_ENTRY_XY(ppc64_bgq, sysno, name)

// This table maps from __NR_xxx syscall numbers (from
// linux/include/asm-ppc/unistd.h) to the appropriate PRE/POST sys_foo()
// wrappers on ppc64 (as per sys_call_table in linux/arch/ppc/kernel/entry.S).
//
// For those syscalls not handled by Valgrind, the annotation indicate its
// arch/OS combination, eg. */* (generic), */Linux (Linux only), ?/?
// (unknown).

static SyscallTableEntry syscall_table[] = {
//QQ// _____(__NR_restart_syscall,   sys_restart_syscall),    //   0
   GENX_(__NR_exit,              sys_exit),               //   1
//QQ   GENX_(__NR_fork,              sys_fork),               //   2
   GENXY(__NR_read,              sys_read),               //   3
   GENX_(__NR_write,             sys_write),              //   4

   GENXY(__NR_open,              sys_open),               //   5
   GENXY(__NR_close,             sys_close),              //   6
//QQ   GENXY(__NR_waitpid,           sys_waitpid),            //   7
//QQ   GENXY(__NR_creat,             sys_creat),              //   8
//QQ   GENX_(__NR_link,              sys_link),               //   9
//QQ
   GENX_(__NR_unlink,            sys_unlink),             //  10
//QQ   GENX_(__NR_execve,            sys_execve),             //  11
//QQ   GENX_(__NR_chdir,             sys_chdir),              //  12
   GENXY(__NR_time,              sys_time),               //  13
//QQ   GENX_(__NR_mknod,             sys_mknod),              //  14
//QQ
//QQ   GENX_(__NR_chmod,             sys_chmod),              //  15
//QQ   GENX_(__NR_lchown,            sys_lchown),             //  16
//QQ// _____(__NR_break,             sys_break),              //  17
//QQ// _____(__NR_oldstat,           sys_oldstat),            //  18
   LINX_(__NR_lseek,             sys_lseek),              //  19
//QQ
//QQ   GENX_(__NR_getpid,            sys_getpid),             //  20
//QQ   LINX_(__NR_mount,             sys_mount),              //  21
//QQ// _____(__NR_umount,            sys_umount),             //  22
//QQ   GENX_(__NR_setuid,            sys_setuid),             //  23
//QQ   GENX_(__NR_getuid,            sys_getuid),             //  24
//QQ
//QQ// _____(__NR_stime,             sys_stime),              //  25
//QQ// _____(__NR_ptrace,            sys_ptrace),             //  26
//QQ   GENX_(__NR_alarm,             sys_alarm),              //  27
//QQ// _____(__NR_oldfstat,          sys_oldfstat),           //  28
//QQ   GENX_(__NR_pause,             sys_pause),              //  29
//QQ
//QQ   LINX_(__NR_utime,             sys_utime),              //  30
//QQ// _____(__NR_stty,              sys_stty),               //  31
//QQ// _____(__NR_gtty,              sys_gtty),               //  32
//QQ   GENX_(__NR_access,            sys_access),             //  33
//QQ// _____(__NR_nice,              sys_nice),               //  34
//QQ
//QQ// _____(__NR_ftime,             sys_ftime),              //  35
//QQ// _____(__NR_sync,              sys_sync),               //  36
//QQ   GENX_(__NR_kill,              sys_kill),               //  37
//QQ   GENX_(__NR_rename,            sys_rename),             //  38
   GENX_(__NR_mkdir,             sys_mkdir),              //  39
//QQ
//QQ   GENX_(__NR_rmdir,             sys_rmdir),              //  40
//QQ   GENXY(__NR_dup,               sys_dup),                //  41
//QQ   LINXY(__NR_pipe,              sys_pipe),               //  42
//QQ   GENXY(__NR_times,             sys_times),              //  43
//QQ// _____(__NR_prof,              sys_prof),               //  44
//QQ
   PLAX_(__NR_brk,               sys_brk),                //  45  // AM-Obs different
//QQ   GENX_(__NR_setgid,            sys_setgid),             //  46
//QQ   GENX_(__NR_getgid,            sys_getgid),             //  47
//QQ// _____(__NR_signal,            sys_signal),             //  48
//QQ   GENX_(__NR_geteuid,           sys_geteuid),            //  49
//QQ
//QQ   GENX_(__NR_getegid,           sys_getegid),            //  50
//QQ// _____(__NR_acct,              sys_acct),               //  51
//QQ   LINX_(__NR_umount2,           sys_umount),             //  52
//QQ// _____(__NR_lock,              sys_lock),               //  53
   LINXY(__NR_ioctl,             sys_ioctl),              //  54

   LINXY(__NR_fcntl,             sys_fcntl),              //  55
//QQ// _____(__NR_mpx,               sys_mpx),                //  56
//QQ   GENX_(__NR_setpgid,           sys_setpgid),            //  57
//QQ// _____(__NR_ulimit,            sys_ulimit),             //  58
//QQ// _____(__NR_oldolduname,       sys_oldolduname),        //  59
//QQ
//QQ   GENX_(__NR_umask,             sys_umask),              //  60
//QQ   GENX_(__NR_chroot,            sys_chroot),             //  61
//QQ// _____(__NR_ustat,             sys_ustat),              //  62
//QQ   GENXY(__NR_dup2,              sys_dup2),               //  63
//QQ   GENX_(__NR_getppid,           sys_getppid),            //  64
//QQ
//QQ   GENX_(__NR_getpgrp,           sys_getpgrp),            //  65
//QQ   GENX_(__NR_setsid,            sys_setsid),             //  66
//QQ// _____(__NR_sigaction,         sys_sigaction),          //  67
//QQ// _____(__NR_sgetmask,          sys_sgetmask),           //  68
//QQ// _____(__NR_ssetmask,          sys_ssetmask),           //  69
//QQ
//QQ   GENX_(__NR_setreuid,          sys_setreuid),           //  70
//QQ   GENX_(__NR_setregid,          sys_setregid),           //  71
//QQ// _____(__NR_sigsuspend,        sys_sigsuspend),         //  72
//QQ// _____(__NR_sigpending,        sys_sigpending),         //  73
//QQ// _____(__NR_sethostname,       sys_sethostname),        //  74
//QQ
//QQ   GENX_(__NR_setrlimit,         sys_setrlimit),          //  75
//QQ// _____(__NR_getrlimit,         sys_getrlimit),          //  76
//QQ   GENXY(__NR_getrusage,         sys_getrusage),          //  77
   GENXY(__NR_gettimeofday,      sys_gettimeofday),       //  78
//QQ// _____(__NR_settimeofday,      sys_settimeofday),       //  79
//QQ
//QQ   GENXY(__NR_getgroups,         sys_getgroups),          //  80
//QQ   GENX_(__NR_setgroups,         sys_setgroups),          //  81
//QQ// _____(__NR_select,            sys_select),             //  82
//QQ   GENX_(__NR_symlink,           sys_symlink),            //  83
//QQ// _____(__NR_oldlstat,          sys_oldlstat),           //  84
//QQ
//QQ   GENX_(__NR_readlink,          sys_readlink),           //  85
//QQ// _____(__NR_uselib,            sys_uselib),             //  86
//QQ// _____(__NR_swapon,            sys_swapon),             //  87
//QQ// _____(__NR_reboot,            sys_reboot),             //  88
//QQ// _____(__NR_readdir,           sys_readdir),            //  89
//QQ
   PLAX_(__NR_mmap,              sys_mmap),               //  90 // AM-Obs different
   PLAX_(__NR_munmap,            sys_munmap),             //  91 // AM-Obs different
//QQ   GENX_(__NR_truncate,          sys_truncate),           //  92
   GENX_(__NR_ftruncate,         sys_ftruncate),          //  93
//QQ   GENX_(__NR_fchmod,            sys_fchmod),             //  94
//QQ   
//QQ   GENX_(__NR_fchown,            sys_fchown),             //  95
//QQ// _____(__NR_getpriority,       sys_getpriority),        //  96
//QQ// _____(__NR_setpriority,       sys_setpriority),        //  97
//QQ// _____(__NR_profil,            sys_profil),             //  98
   GENXY(__NR_statfs,            sys_statfs),             //  99
//QQ
//QQ   GENXY(__NR_fstatfs,           sys_fstatfs),            // 100
//QQ// _____(__NR_ioperm,            sys_ioperm),             // 101
//QQ   PLAXY(__NR_socketcall,        sys_socketcall),         // 102
//QQ   LINXY(__NR_syslog,            sys_syslog),             // 103
//QQ   GENXY(__NR_setitimer,         sys_setitimer),          // 104
//QQ
//QQ   GENXY(__NR_getitimer,         sys_getitimer),          // 105
//QQ   GENXY(__NR_stat,              sys_newstat),            // 106
//QQ   GENXY(__NR_lstat,             sys_newlstat),           // 107
   GENXY(__NR_fstat,             sys_newfstat),           // 108
//QQ// _____(__NR_olduname,          sys_olduname),           // 109
//QQ
//QQ// _____(__NR_iopl,              sys_iopl),               // 110
//QQ   LINX_(__NR_vhangup,           sys_vhangup),            // 111
//QQ// _____(__NR_idle,              sys_idle),               // 112
//QQ// _____(__NR_vm86,              sys_vm86),               // 113
//QQ   GENXY(__NR_wait4,             sys_wait4),              // 114
//QQ
//QQ// _____(__NR_swapoff,           sys_swapoff),            // 115
//QQ   LINXY(__NR_sysinfo,           sys_sysinfo),            // 116
//QQ   PLAXY(__NR_ipc,               sys_ipc),                // 117
//QQ   GENX_(__NR_fsync,             sys_fsync),              // 118
//QQ// _____(__NR_sigreturn,         sys_sigreturn),          // 119
//QQ
   PLAX_(__NR_clone,             sys_clone),              // 120
//QQ// _____(__NR_setdomainname,     sys_setdomainname),      // 121
   GENXY(__NR_uname,             sys_newuname),           // 122
//QQ// _____(__NR_modify_ldt,        sys_modify_ldt),         // 123
//QQ   LINXY(__NR_adjtimex,          sys_adjtimex),           // 124
//QQ
   PLAXY(__NR_mprotect,          sys_mprotect),           // 125 // AM-Obs different
//QQ// _____(__NR_sigprocmask,       sys_sigprocmask),        // 126
//QQ   GENX_(__NR_create_module,     sys_ni_syscall),         // 127
//QQ   LINX_(__NR_init_module,       sys_init_module),        // 128
//QQ   LINX_(__NR_delete_module,     sys_delete_module),      // 129
//QQ
//QQ// _____(__NR_get_kernel_syms,   sys_get_kernel_syms),    // 130
//QQ// _____(__NR_quotactl,          sys_quotactl),           // 131
//QQ   GENX_(__NR_getpgid,           sys_getpgid),            // 132
//QQ   GENX_(__NR_fchdir,            sys_fchdir),             // 133
//QQ// _____(__NR_bdflush,           sys_bdflush),            // 134
//QQ
//QQ// _____(__NR_sysfs,             sys_sysfs),              // 135
//QQ   LINX_(__NR_personality,       sys_personality),        // 136
//QQ// _____(__NR_afs_syscall,       sys_afs_syscall),        // 137
//QQ   LINX_(__NR_setfsuid,          sys_setfsuid),           // 138
//QQ   LINX_(__NR_setfsgid,          sys_setfsgid),           // 139
//QQ
//QQ   LINXY(__NR__llseek,           sys_llseek),             // 140
//QQ   GENXY(__NR_getdents,          sys_getdents),           // 141
//QQ   GENX_(__NR__newselect,        sys_select),             // 142
//QQ   GENX_(__NR_flock,             sys_flock),              // 143
//QQ   GENX_(__NR_msync,             sys_msync),              // 144
//QQ
//QQ   GENXY(__NR_readv,             sys_readv),              // 145
   GENX_(__NR_writev,            sys_writev),             // 146
//QQ// _____(__NR_getsid,            sys_getsid),             // 147
//QQ   GENX_(__NR_fdatasync,         sys_fdatasync),          // 148
//QQ   LINXY(__NR__sysctl,           sys_sysctl),             // 149
//QQ
//QQ   GENX_(__NR_mlock,             sys_mlock),              // 150
//QQ   GENX_(__NR_munlock,           sys_munlock),            // 151
//QQ   GENX_(__NR_mlockall,          sys_mlockall),           // 152
//QQ   LINX_(__NR_munlockall,        sys_munlockall),         // 153
//QQ   LINXY(__NR_sched_setparam,    sys_sched_setparam),     // 154
//QQ
//QQ   LINXY(__NR_sched_getparam,         sys_sched_getparam),        // 155
//QQ   LINX_(__NR_sched_setscheduler,     sys_sched_setscheduler),    // 156
//QQ   LINX_(__NR_sched_getscheduler,     sys_sched_getscheduler),    // 157
   LINX_(__NR_sched_yield,            sys_sched_yield),           // 158
//QQ   LINX_(__NR_sched_get_priority_max, sys_sched_get_priority_max),// 159
//QQ
//QQ   LINX_(__NR_sched_get_priority_min, sys_sched_get_priority_min),// 160
//QQ   LINXY(__NR_sched_rr_get_interval,  sys_sched_rr_get_interval), // 161
   GENXY(__NR_nanosleep,         sys_nanosleep),          // 162
//QQ   GENX_(__NR_mremap,            sys_mremap),             // 163
//QQ   LINX_(__NR_setresuid,         sys_setresuid),          // 164
//QQ
//QQ   LINXY(__NR_getresuid,         sys_getresuid),          // 165
//QQ// _____(__NR_query_module,      sys_query_module),       // 166
//QQ   GENXY(__NR_poll,              sys_poll),               // 167
//QQ// _____(__NR_nfsservctl,        sys_nfsservctl),         // 168
//QQ   LINX_(__NR_setresgid,         sys_setresgid),          // 169
//QQ
//QQ   LINXY(__NR_getresgid,         sys_getresgid),          // 170
//QQ// _____(__NR_prctl,             sys_prctl),              // 171
//QQ   PLAX_(__NR_rt_sigreturn,      sys_rt_sigreturn),       // 172
   LINXY(__NR_rt_sigaction,      sys_rt_sigaction),       // 173
   LINXY(__NR_rt_sigprocmask,    sys_rt_sigprocmask),     // 174
//QQ
//QQ// _____(__NR_rt_sigpending,     sys_rt_sigpending),      // 175
//QQ   LINXY(__NR_rt_sigtimedwait,   sys_rt_sigtimedwait),    // 176
//QQ   LINXY(__NR_rt_sigqueueinfo,   sys_rt_sigqueueinfo),    // 177
//QQ// _____(__NR_rt_sigsuspend,     sys_rt_sigsuspend),      // 178
//QQ   GENXY(__NR_pread64,           sys_pread64),            // 179
//QQ
//QQ   GENX_(__NR_pwrite64,          sys_pwrite64),           // 180
//QQ   GENX_(__NR_chown,             sys_chown),              // 181
//QQ   GENXY(__NR_getcwd,            sys_getcwd),             // 182
//QQ   LINXY(__NR_capget,            sys_capget),             // 183
//QQ   LINX_(__NR_capset,            sys_capset),             // 184
//QQ
//QQ   GENXY(__NR_sigaltstack,       sys_sigaltstack),        // 185
//QQ   LINXY(__NR_sendfile,          sys_sendfile),           // 186
//QQ// _____(__NR_getpmsg,           sys_getpmsg),            // 187
//QQ// _____(__NR_putpmsg,           sys_putpmsg),            // 188
//QQ   GENX_(__NR_vfork,             sys_fork),               // 189 treat as fork
//QQ
   GENXY(__NR_ugetrlimit,        sys_getrlimit),          // 190
//QQ   LINX_(__NR_readahead,         sys_readahead),          // 191
//QQ// /* #define __NR_mmap2           192     32bit only */
//QQ// /* #define __NR_truncate64      193     32bit only */
//QQ// /* #define __NR_ftruncate64     194     32bit only */
//QQ
//QQ// /* #define __NR_stat64          195     32bit only */
//QQ// /* #define __NR_lstat64         196     32bit only */
//QQ// /* #define __NR_fstat64         197     32bit only */
//QQ// _____(__NR_pciconfig_read,    sys_pciconfig_read),     // 198
//QQ// _____(__NR_pciconfig_write,   sys_pciconfig_write),    // 199
//QQ
//QQ// _____(__NR_pciconfig_iobase,  sys_pciconfig_iobase),   // 200
//QQ// _____(__NR_multiplexer,       sys_multiplexer),        // 201
//QQ   GENXY(__NR_getdents64,        sys_getdents64),         // 202
//QQ// _____(__NR_pivot_root,        sys_pivot_root),         // 203
//QQ   LINXY(__NR_fcntl64,           sys_fcntl64),            // 204 !!!!?? 32bit only */
//QQ
   GENX_(__NR_madvise,           sys_madvise),            // 205
//QQ// _____(__NR_mincore,           sys_mincore),            // 206
   LINX_(__NR_gettid,            sys_gettid),             // 207
//QQ// _____(__NR_tkill,             sys_tkill),              // 208
//QQ// _____(__NR_setxattr,          sys_setxattr),           // 209
//QQ
//QQ// _____(__NR_lsetxattr,         sys_lsetxattr),          // 210
//QQ// _____(__NR_fsetxattr,         sys_fsetxattr),          // 211
//QQ   LINXY(__NR_getxattr,          sys_getxattr),           // 212
//QQ   LINXY(__NR_lgetxattr,         sys_lgetxattr),          // 213
//QQ   LINXY(__NR_fgetxattr,         sys_fgetxattr),          // 214
//QQ   LINXY(__NR_listxattr,         sys_listxattr),          // 215
//QQ   LINXY(__NR_llistxattr,        sys_llistxattr),         // 216
//QQ   LINXY(__NR_flistxattr,        sys_flistxattr),         // 217
//QQ   LINX_(__NR_removexattr,       sys_removexattr),        // 218
//QQ   LINX_(__NR_lremovexattr,      sys_lremovexattr),       // 219
//QQ   LINX_(__NR_fremovexattr,      sys_fremovexattr),       // 220
//QQ
   LINXY(__NR_futex,             sys_futex),              // 221
   LINX_(__NR_sched_setaffinity, sys_sched_setaffinity),  // 222
   LINXY(__NR_sched_getaffinity, sys_sched_getaffinity),  // 223
//QQ// /* 224 currently unused */
//QQ
//QQ// _____(__NR_tuxcall,           sys_tuxcall),            // 225
//QQ// /* #define __NR_sendfile64      226     32bit only */
//QQ   LINX_(__NR_io_setup,          sys_io_setup),           // 227
//QQ   LINX_(__NR_io_destroy,        sys_io_destroy),         // 228
//QQ   LINXY(__NR_io_getevents,      sys_io_getevents),       // 229
//QQ   LINX_(__NR_io_submit,         sys_io_submit),          // 230
//QQ   LINXY(__NR_io_cancel,         sys_io_cancel),          // 231
   LINX_(__NR_set_tid_address,   sys_set_tid_address),    // 232
//QQ   PLAX_(__NR_fadvise64,         sys_fadvise64),          // 233
   LINX_(__NR_exit_group,        sys_exit_group),         // 234

//QQ// _____(__NR_lookup_dcookie,    sys_lookup_dcookie),     // 235
//QQ   LINXY(__NR_epoll_create,      sys_epoll_create),       // 236
//QQ   LINX_(__NR_epoll_ctl,         sys_epoll_ctl),          // 237
//QQ   LINXY(__NR_epoll_wait,        sys_epoll_wait),         // 238
//QQ// _____(__NR_remap_file_pages,  sys_remap_file_pages),   // 239
//QQ
//QQ   LINXY(__NR_timer_create,      sys_timer_create),       // 240
//QQ   LINXY(__NR_timer_settime,     sys_timer_settime),      // 241
//QQ   LINXY(__NR_timer_gettime,     sys_timer_gettime),      // 242
//QQ   LINX_(__NR_timer_getoverrun,  sys_timer_getoverrun),   // 243
//QQ   LINX_(__NR_timer_delete,      sys_timer_delete),       // 244
//QQ   LINX_(__NR_clock_settime,     sys_clock_settime),      // 245
//QQ   LINXY(__NR_clock_gettime,     sys_clock_gettime),      // 246
//QQ   LINXY(__NR_clock_getres,      sys_clock_getres),       // 247
//QQ   LINXY(__NR_clock_nanosleep,   sys_clock_nanosleep),    // 248
//QQ
//QQ// _____(__NR_swapcontext,       sys_swapcontext),        // 249
//QQ
   LINXY(__NR_tgkill,            sys_tgkill),             // 250
//QQ// _____(__NR_utimes,            sys_utimes),             // 251
//QQ// _____(__NR_statfs64,          sys_statfs64),           // 252
//QQ// _____(__NR_fstatfs64,         sys_fstatfs64),          // 253
//QQ// /* #define __NR_fadvise64_64    254     32bit only */
//QQ
//QQ// _____(__NR_rtas,              sys_rtas),               // 255
//QQ// /* Number 256 is reserved for sys_debug_setcontext */
//QQ// /* Number 257 is reserved for vserver */
//QQ// /* 258 currently unused */
//QQ// _____(__NR_mbind,             sys_mbind),              // 259
//QQ
//QQ// _____(__NR_get_mempolicy,     sys_get_mempolicy),      // 260
//QQ// _____(__NR_set_mempolicy,     sys_set_mempolicy),      // 261
//QQ   LINXY(__NR_mq_open,           sys_mq_open),            // 262
//QQ   LINX_(__NR_mq_unlink,         sys_mq_unlink),          // 263
//QQ   LINX_(__NR_mq_timedsend,      sys_mq_timedsend),       // 264
//QQ
//QQ   LINXY(__NR_mq_timedreceive,   sys_mq_timedreceive),    // 265
//QQ   LINX_(__NR_mq_notify,         sys_mq_notify),          // 266
//QQ   LINXY(__NR_mq_getsetattr,     sys_mq_getsetattr),      // 267
//QQ// _____(__NR_kexec_load,        sys_kexec_load),         // 268
//QQ   LINX_(__NR_add_key,           sys_add_key),            // 269
//QQ
//QQ   LINX_(__NR_request_key,       sys_request_key),        // 270
//QQ   LINXY(__NR_keyctl,            sys_keyctl),             // 271
//QQ// _____(__NR_waitid,            sys_waitid),             // 272
//QQ   LINX_(__NR_ioprio_set,        sys_ioprio_set),         // 273
//QQ   LINX_(__NR_ioprio_get,        sys_ioprio_get),         // 274
//QQ
//QQ   LINX_(__NR_inotify_init,  sys_inotify_init),           // 275
//QQ   LINX_(__NR_inotify_add_watch,  sys_inotify_add_watch), // 276
//QQ   LINX_(__NR_inotify_rm_watch,   sys_inotify_rm_watch),  // 277
//QQ
//QQ   LINX_(__NR_pselect6,          sys_pselect6),           // 280
//QQ   LINXY(__NR_ppoll,             sys_ppoll),              // 281
//QQ
//QQ   LINXY(__NR_openat,            sys_openat),             // 286
//QQ   LINX_(__NR_mkdirat,           sys_mkdirat),            // 287
//QQ   LINX_(__NR_mknodat,           sys_mknodat),            // 288
//QQ   LINX_(__NR_fchownat,          sys_fchownat),           // 289
//QQ   LINX_(__NR_futimesat,         sys_futimesat),          // 290
//QQ   LINXY(__NR_newfstatat,        sys_newfstatat),         // 291
//QQ   LINX_(__NR_unlinkat,          sys_unlinkat),           // 292
//QQ   LINX_(__NR_renameat,          sys_renameat),           // 293
//QQ   LINX_(__NR_linkat,            sys_linkat),             // 294
//QQ   LINX_(__NR_symlinkat,         sys_symlinkat),          // 295
//QQ   LINX_(__NR_readlinkat,        sys_readlinkat),         // 296
//QQ   LINX_(__NR_fchmodat,          sys_fchmodat),           // 297
//QQ   LINX_(__NR_faccessat,         sys_faccessat),          // 298
//QQ   LINXY(__NR_get_robust_list,   sys_get_robust_list),    // 299
   LINX_(__NR_set_robust_list,   sys_set_robust_list),    // 300
//QQ   LINXY(__NR_move_pages,        sys_move_pages),        // 301
//QQ   LINXY(__NR_getcpu,            sys_getcpu),            // 302
//QQ   LINXY(__NR_epoll_pwait,       sys_epoll_pwait),       // 303
//QQ   LINX_(__NR_utimensat,         sys_utimensat),         // 304
//QQ   LINXY(__NR_signalfd,          sys_signalfd),          // 305
//QQ   LINXY(__NR_timerfd_create,    sys_timerfd_create),    // 306
//QQ   LINX_(__NR_eventfd,           sys_eventfd),           // 307
//QQ   LINX_(__NR_sync_file_range2,  sys_sync_file_range2),  // 308
//QQ   LINX_(__NR_fallocate,         sys_fallocate),         // 309
//QQ//   LINXY(__NR_subpage_prot,       sys_ni_syscall),       // 310
//QQ   LINXY(__NR_timerfd_settime,   sys_timerfd_settime),  // 311
//QQ   LINXY(__NR_timerfd_gettime,   sys_timerfd_gettime),  // 312
//QQ   LINXY(__NR_signalfd4,         sys_signalfd4),        // 313
//QQ   LINX_(__NR_eventfd2,          sys_eventfd2),         // 314
//QQ   LINXY(__NR_epoll_create1,     sys_epoll_create1),    // 315
//QQ   LINXY(__NR_dup3,              sys_dup3),             // 316
//QQ   LINXY(__NR_pipe2,             sys_pipe2),            // 317
//QQ   LINXY(__NR_inotify_init1,     sys_inotify_init1),    // 318
//QQ   LINXY(__NR_perf_event_open,   sys_perf_event_open),  // 319
//QQ   LINXY(__NR_preadv,            sys_preadv),           // 320
//QQ   LINX_(__NR_pwritev,           sys_pwritev),          // 321
//QQ   LINXY(__NR_rt_tgsigqueueinfo, sys_rt_tgsigqueueinfo),// 322
//QQ
//QQ   LINXY(__NR_process_vm_readv,  sys_process_vm_readv), // 351
//QQ   LINX_(__NR_process_vm_writev, sys_process_vm_writev) // 352
   PLAXY(1024, sys_1024),    // GETMEMORYREGION
   PLAXY(1025, sys_1025),    // GET_PERSONALITY
   PLAX_(1029, sys_1029),    // SPECALLOCATEDOMAIN
   PLAXY(1032, sys_1032),    // ALLOCATE_INJ_FIFOS
   PLAXY(1033, sys_1033),    // QUERY_INJ_FIFOS
   PLAXY(1034, sys_1034),    // QUERY_REC_FIFOS
   PLAXY(1035, sys_1035),    // QUERY_BASE_ADDRESS_TABLE
   PLAXY(1036, sys_1036),    // ALLOCATE_REC_FIFOS
   PLAXY(1037, sys_1037),    // ALLOCATE_BASE_ADDRESS_TABLE
   PLAX_(1038, sys_1038),    // REC_FIFO_ENABLE
   PLAXY(1039, sys_1039),    // CFG_INJ_FIFO_INTS
   PLAXY(1040, sys_1040),    // CFG_REC_FIFO_INTS
   PLAX_(1042, sys_1042),    // CFG_REC_FIFO_THRESH
   PLAXY(1055, sys_1055),    // RANKS2COORDS
   PLAXY(1056, sys_1056),    // JOBCOORDS
   PLAX_(1059, sys_1059),    // ALLOCATEL2ATOMIC
   PLAX_(1063, sys_1063),    // SETSPECSTATE
   PLAX_(1064, sys_1064),    // SETL2SCRUBRATE
   PLAX_(1065, sys_1065),    // QUERYCOLLECTIVECLASSROUTE
   PLAX_(1066, sys_1066),    // ALLOCATECOLLECTIVECLASSROUTE
   PLAX_(1067, sys_1067),    // SETCOLLECTIVECLASSROUTE
   PLAX_(1069, sys_1069),    // QUERYGINTCLASSROUTE
   PLAX_(1070, sys_1070),    // ALLOCATEGINTCLASSROUTE
   PLAX_(1071, sys_1071),    // SETGINTCLASSROUTE
   PLAX_(1075, sys_1075),    // SETNUMSPECDOMAINS
   PLAX_(1076, sys_1076),    // GETRANK
   PLAXY(1089, sys_1089),    // GETPVR
   PLAX_(1090, sys_1090),    // ENABLEFASTSPECULATIONPATHS
};

SyscallTableEntry* ML_(get_linux_syscall_entry) ( UInt sysno )
{
   const UInt syscall_table_size
      = sizeof(syscall_table) / sizeof(syscall_table[0]);
   /* Is it in the contiguous initial section of the table? */
   if (sysno < syscall_table_size) {
      SyscallTableEntry* sys = &syscall_table[sysno];
      if (sys->before == NULL)
         return NULL; /* no entry */
      else
         return sys;
   }

   /* Can't find a wrapper */
   return NULL;
}

#endif // defined(VGPV_ppc64_linux_bgq)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
