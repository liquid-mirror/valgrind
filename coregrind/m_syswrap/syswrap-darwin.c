
/*--------------------------------------------------------------------*/
/*--- Darwin-specific syscalls, etc.              syswrap-darwin.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2005-2008 Apple Inc.
      Greg Parker  gparker@apple.com

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
#include "pub_core_vkiscnums.h"
#include "pub_core_threadstate.h"
#include "pub_core_aspacemgr.h"
#include "pub_core_xarray.h"
#include "pub_core_clientstate.h"
#include "pub_core_debuglog.h"
#include "pub_core_debuginfo.h"    // VG_(di_notify_*)
#include "pub_core_transtab.h"     // VG_(discard_translations)
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcfile.h"
#include "pub_core_libcprint.h"
#include "pub_core_libcproc.h"
#include "pub_core_libcsignal.h"
#include "pub_core_mallocfree.h"
#include "pub_core_options.h"
#include "pub_core_scheduler.h"
#include "pub_core_sigframe.h"      // For VG_(sigframe_destroy)()
#include "pub_core_signals.h"
#include "pub_core_syscall.h"
#include "pub_core_syswrap.h"
#include "pub_core_tooliface.h"

#include "priv_types_n_macros.h"
#include "priv_syswrap-generic.h"   /* for decls of generic wrappers */
#include "priv_syswrap-darwin.h"    /* for decls of darwin-ish wrappers */
#include "priv_syswrap-main.h"


#include <mach/mach.h>
#include <mach/mach_vm.h>
#define msgh_request_port      msgh_remote_port
#define msgh_reply_port        msgh_local_port
#define BOOTSTRAP_MAX_NAME_LEN                  128
typedef char name_t[BOOTSTRAP_MAX_NAME_LEN];

typedef uint64_t mig_addr_t;


// DDD: fixme from aspacemgr-linux.c
extern void VG_(sync_mappings)(const HChar *when, const HChar *where, Int num);


// Saved ports
static mach_port_t vg_host_port = 0;
static mach_port_t vg_task_port = 0;
static mach_port_t vg_bootstrap_port = 0;

// Run a thread from beginning to end and return the thread's
// scheduler-return-code.
static VgSchedReturnCode ML_(thread_wrapper)(Word /*ThreadId*/ tidW)
{
   VgSchedReturnCode ret;
   ThreadId     tid = (ThreadId)tidW;
   ThreadState* tst = VG_(get_ThreadState)(tid);

   VG_(debugLog)(1, "core_os", 
                    "ML_(thread_wrapper)(tid=%lld): entry\n", 
                    (ULong)tidW);

   vg_assert(tst->status == VgTs_Init);

   /* make sure we get the CPU lock before doing anything significant */
   VG_(acquire_BigLock)(tid, "thread_wrapper");

   if (0)
      VG_(printf)("thread tid %d started: stack = %p\n",
                  tid, &tid);

   VG_TRACK(pre_thread_first_insn, tid);

   tst->os_state.lwpid = VG_(gettid)();
   tst->os_state.threadgroup = VG_(getpid)();

   /* Thread created with all signals blocked; scheduler will set the
      appropriate mask */

   ret = VG_(scheduler)(tid);

   vg_assert(VG_(is_exiting)(tid));
   
   vg_assert(tst->status == VgTs_Runnable);
   vg_assert(VG_(is_running_thread)(tid));

   VG_(debugLog)(1, "core_os", 
                    "ML_(thread_wrapper)(tid=%lld): done\n", 
                    (ULong)tidW);

   /* Return to caller, still holding the lock. */
   return ret;
}



/* Allocate a stack for this thread, if it doesn't already have one.
   Returns the initial stack pointer value to use, or 0 if allocation
   failed. */

Addr allocstack ( ThreadId tid )
{
   ThreadState* tst = VG_(get_ThreadState)(tid);
   VgStack*     stack;
   Addr         initial_SP;

   /* Either the stack_base and stack_init_SP are both zero (in which
      case a stack hasn't been allocated) or they are both non-zero,
      in which case it has. */

   if (tst->os_state.valgrind_stack_base == 0)
      vg_assert(tst->os_state.valgrind_stack_init_SP == 0);

   if (tst->os_state.valgrind_stack_base != 0)
      vg_assert(tst->os_state.valgrind_stack_init_SP != 0);

   /* If no stack is present, allocate one. */

   if (tst->os_state.valgrind_stack_base == 0) {
      stack = VG_(am_alloc_VgStack)( &initial_SP );
      if (stack) {
         tst->os_state.valgrind_stack_base    = (Addr)stack;
         tst->os_state.valgrind_stack_init_SP = initial_SP;
      }
   }

   VG_(debugLog)( 2, "syswrap-darwin", "stack for tid %d at %p; init_SP=%p\n",
                   tid, 
                   (void*)tst->os_state.valgrind_stack_base, 
                   (void*)tst->os_state.valgrind_stack_init_SP );

   vg_assert(VG_IS_32_ALIGNED(tst->os_state.valgrind_stack_init_SP));
   
   return tst->os_state.valgrind_stack_init_SP;
}


void find_stack_segment(ThreadId tid, Addr sp)
{
   /* We don't really know where the client stack is, because it's
      allocated by the client.  The best we can do is look at the
      memory mappings and try to derive some useful information.  We
      assume that esp starts near its highest possible value, and can
      only go down to the start of the mmaped segment. */
   ThreadState *tst = VG_(get_ThreadState)(tid);
   const NSegment *seg = VG_(am_find_nsegment)(sp);
   if (seg && seg->kind != SkResvn) {
      tst->client_stack_highest_word = (Addr)VG_PGROUNDUP(sp);
      tst->client_stack_szB = tst->client_stack_highest_word - seg->start;

      if (1)
         VG_(printf)("tid %d: guessed client stack range %#lx-%#lx\n",
                     tid, seg->start, VG_PGROUNDUP(sp));
   } else {
       VG_(printf)("couldn't find user stack\n");
      VG_(message)(Vg_UserMsg, "!? New thread %d starts with SP(%p) unmapped\n",
                   tid, sp);
      tst->client_stack_szB  = 0;
   }
}


/* Run a thread all the way to the end, then do appropriate exit actions
   (this is the last-one-out-turn-off-the-lights bit). 
*/
static void run_a_thread_NORETURN ( Word tidW )
{
   Int               c;
   VgSchedReturnCode src;
   ThreadId tid = (ThreadId)tidW;

   VG_(debugLog)(1, "syswrap-darwin", 
                    "run_a_thread_NORETURN(tid=%lld): "
                       "ML_(thread_wrapper) called\n",
                       (ULong)tidW);

   /* Run the thread all the way through. */
   src = ML_(thread_wrapper)(tid);  

   VG_(debugLog)(1, "syswrap-darwin", 
                    "run_a_thread_NORETURN(tid=%lld): "
                       "ML_(thread_wrapper) done\n",
                       (ULong)tidW);

   c = VG_(count_living_threads)();
   vg_assert(c >= 1); /* stay sane */

   if (c == 1) {

      VG_(debugLog)(1, "syswrap-darwin", 
                       "run_a_thread_NORETURN(tid=%lld): "
                          "last one standing\n",
                          (ULong)tidW);

      /* We are the last one standing.  Keep hold of the lock and
         carry on to show final tool results, then exit the entire system. 
         Use the continuation pointer set at startup in m_main. */
      ( * VG_(address_of_m_main_shutdown_actions_NORETURN) ) (tid, src);

   } else {

      ThreadState *tst;
      mach_msg_header_t msg;

      VG_(debugLog)(1, "syswrap-darwin", 
                       "run_a_thread_NORETURN(tid=%lld): "
                          "not last one standing\n",
                          (ULong)tidW);

      /* OK, thread is dead, but others still exist.  Just exit. */
      tst = VG_(get_ThreadState)(tid);

      /* This releases the run lock */
      VG_(exit_thread)(tid);
      vg_assert(tst->status == VgTs_Zombie);

      /* tid is now invalid. */

      // GrP fixme exit race
      msg.msgh_bits = MACH_MSGH_BITS(17, MACH_MSG_TYPE_MAKE_SEND_ONCE);
      msg.msgh_request_port = VG_(gettid)();
      msg.msgh_reply_port = 0;
      msg.msgh_id = 3600;  // thread_terminate
      
      tst->status = VgTs_Empty;
      // GrP fixme race here! new thread may claim this V thread stack 
      // before we get out here!
      // fixme use bsdthread_terminate for safe cleanup?
      mach_msg(&msg, MACH_SEND_MSG|MACH_MSG_OPTION_NONE, 
               sizeof(msg), 0, 0, MACH_MSG_TIMEOUT_NONE, 0);
      
      VG_(core_panic)("Thread exit failed?\n");
   }
   
   /*NOTREACHED*/
   vg_assert(0);
}


/* Allocate a stack for the main thread, and run it all the way to the
   end.  Although we already have a working VgStack
   (VG_(interim_stack)) it's better to allocate a new one, so that
   overflow detection works uniformly for all threads.
*/
void VG_(main_thread_wrapper_NORETURN)(ThreadId tid)
{
   Addr sp;
   VG_(debugLog)(1, "syswrap-darwin", 
                    "entering VG_(main_thread_wrapper_NORETURN)\n");

   sp = allocstack(tid);

   /* If we can't even allocate the first thread's stack, we're hosed.
      Give up. */
   vg_assert2(sp != 0, "Cannot allocate main thread's stack.");

   /* shouldn't be any other threads around yet */
   vg_assert( VG_(count_living_threads)() == 1 );
   
   call_on_new_stack_0_1( 
      (Addr)sp,             /* stack */
      0,                     /*bogus return address*/
      run_a_thread_NORETURN,  /* fn to call */
      (Word)tid              /* arg to give it */
   );

   /*NOTREACHED*/
   vg_assert(0);
}


void start_thread_NORETURN ( Word arg )
{
   ThreadState* tst = (ThreadState*)arg;
   ThreadId     tid = tst->tid;

   run_a_thread_NORETURN ( (Word)tid );
   /*NOTREACHED*/
   vg_assert(0);
}


void VG_(cleanup_thread) ( ThreadArchState* arch )
{
}  


/* ---------------------------------------------------------------------
   Mach port tracking (based on syswrap-generic's fd tracker)
   ------------------------------------------------------------------ */

/* One of these is allocated for each open port.  */
typedef struct OpenPort
{
   mach_port_t port;
   mach_port_type_t type;         /* right type(s) */
   Int send_count;                /* number of send rights */
   Char *name;                    /* bootstrap name or NULL */
   ExeContext *where;             /* first allocation only */
   struct OpenPort *next, *prev;
} OpenPort;

// strlen("0x12345678")
#define PORT_STRLEN (2+2*sizeof(mach_port_t))

/* List of allocated ports. */
static OpenPort *allocated_ports;

/* Count of open ports. */
static Int allocated_port_count = 0;


static Bool port_exists(mach_port_t port)
{
   OpenPort *i;

   /* Check to see if this port is already open. */
   i = allocated_ports;
   while (i) {
      if (i->port == port) {
         return True;
      }
      i = i->next;
   }
   
   return False;
}

static OpenPort *info_for_port(mach_port_t port)
{
   OpenPort *i;
   if (!port) return NULL;

   i = allocated_ports;
   while (i) {
      if (i->port == port) {
         return i;
      }
      i = i->next;
   }

   return NULL;
}


// Give a port a name, without changing its refcount
// GrP fixme don't override name if it already has a specific one
__private_extern__ void assign_port_name(mach_port_t port, const char *name)
{
   OpenPort *i;
   if (!port) return;
   vg_assert(name);

   i = info_for_port(port);
   vg_assert(i);

   if (i->name) VG_(arena_free)(VG_AR_CORE, i->name);
   i->name = 
       VG_(arena_malloc)(VG_AR_CORE, "syswrap-darwin.mach-port-name", 
                         VG_(strlen)(name) + PORT_STRLEN + 1);
   VG_(sprintf)(i->name, name, port);
}


// Return the name of the given port or "UNKNOWN 0x1234" if not known.
static const char *name_for_port(mach_port_t port)
{
   static char buf[8 + PORT_STRLEN + 1];
   OpenPort *i;

   // hack
   if (port == VG_(gettid)()) return "mach_thread_self()";
   if (port == 0) return "NULL";

   i = allocated_ports;
   while (i) {
      if (i->port == port) {
         return i->name;
      }
      i = i->next;
   }

   VG_(sprintf)(buf, "NONPORT-%p", port);
   return buf;
}

/* Note the fact that a port was just deallocated. */

static
void record_port_mod_refs(mach_port_t port, mach_port_type_t right, Int delta)
{
   OpenPort *i = allocated_ports;
   if (!port) return;

   while(i) {
      if(i->port == port) {
         vg_assert(right != MACH_PORT_TYPE_DEAD_NAME);
         if (right & MACH_PORT_TYPE_SEND) {
            // send rights are refcounted
            if (delta == INT_MIN) delta = -i->send_count; // INT_MIN == destroy
            i->send_count += delta;
            if (i->send_count > 0) i->type |= MACH_PORT_TYPE_SEND;
            else i->type &= ~MACH_PORT_TYPE_SEND;
         } 
         right = right & ~MACH_PORT_TYPE_SEND;
         if (right) {
            // other rights are not refcounted
            if (delta > 0) {
               i->type |= right;
            } else if (delta < 0) {
               i->type &= ~right;
            }
         }

         if (i->type != 0) return;

         // Port has no rights left. Kill it.
         // VG_(printf)("deleting port %p %s", i->port, i->name);
         if(i->prev)
            i->prev->next = i->next;
         else
            allocated_ports = i->next;
         if(i->next)
            i->next->prev = i->prev;
         if(i->name) 
            VG_(arena_free) (VG_AR_CORE, i->name);
         VG_(arena_free) (VG_AR_CORE, i);
         allocated_port_count--;
         return;
      }
      i = i->next;
   }

   VG_(printf)("UNKNOWN Mach port modified (port %p delta %d)\n", port, delta);
}

static 
void record_port_insert_rights(mach_port_t port, mach_msg_type_name_t type)
{
   switch (type) {
   case MACH_MSG_TYPE_PORT_NAME:
      // this task has no rights for the name
      break;
   case MACH_MSG_TYPE_PORT_RECEIVE:
      // this task gets receive rights
      record_port_mod_refs(port, MACH_PORT_TYPE_RECEIVE, 1);
      break;
   case MACH_MSG_TYPE_PORT_SEND:
      // this task gets a send right
      record_port_mod_refs(port, MACH_PORT_TYPE_SEND, 1);
      break;
   case MACH_MSG_TYPE_PORT_SEND_ONCE:
      // this task gets send-once rights
      record_port_mod_refs(port, MACH_PORT_TYPE_SEND_ONCE, 1);
      break;
   default:
      vg_assert(0);
      break;
   }
}

static 
void record_port_dealloc(mach_port_t port)
{
   // deletes 1 send or send-once right (port can't have both)
   record_port_mod_refs(port, MACH_PORT_TYPE_SEND_RIGHTS, -1);
}

static 
void record_port_destroy(mach_port_t port)
{
   // deletes all rights to port
   record_port_mod_refs(port, MACH_PORT_TYPE_ALL_RIGHTS, INT_MIN);
}


/* Note the fact that a Mach port was just allocated or transferred.
   If the port is already known, increment its reference count. */
void record_named_port(ThreadId tid, mach_port_t port, 
                       mach_port_right_t right, const char *name)
{
   OpenPort *i;
   if (!port) return;

   /* Check to see if this port is already open. */
   i = allocated_ports;
   while (i) {
      if (i->port == port) {
         if (right != -1) record_port_mod_refs(port, MACH_PORT_TYPE(right), 1);
         return;
      }
      i = i->next;
   }

   /* Not already one: allocate an OpenPort */
   if (i == NULL) {
      i = VG_(arena_malloc)(VG_AR_CORE, "syswrap-darwin.mach-port", 
                            sizeof(OpenPort));

      i->prev = NULL;
      i->next = allocated_ports;
      if(allocated_ports) allocated_ports->prev = i;
      allocated_ports = i;
      allocated_port_count++;

      i->port = port;
      i->where = (tid == -1) ? NULL : VG_(record_ExeContext)(tid, 0);
      i->name = NULL;
      if (right != -1) {
         i->type = MACH_PORT_TYPE(right);
         i->send_count = (right == MACH_PORT_RIGHT_SEND) ? 1 : 0;
      } else {
         i->type = 0;
         i->send_count = 0;
      }
      
      assign_port_name(port, name);
   }
}


// Record opening of a nameless port.
static void record_unnamed_port(ThreadId tid, mach_port_t port, mach_port_right_t right)
{
   record_named_port(tid, port, right, "unnamed-%p");
}


/* Dump summary of open Mach ports, like VG_(show_open_fds) */
void VG_(show_open_ports)(void)
{
   OpenPort *i;
   
   VG_(message)(Vg_UserMsg, 
                "MACH PORTS: %d open at exit.", allocated_port_count);

   for (i = allocated_ports; i; i = i->next) {
      if (i->name) {
         VG_(message)(Vg_UserMsg, "Open Mach port 0x%x: %s", i->port, i->name);
      } else {
         VG_(message)(Vg_UserMsg, "Open Mach port 0x%x", i->port);
      }

      if (i->where) {
         VG_(pp_ExeContext)(i->where);
         VG_(message)(Vg_UserMsg, "");
      }
   }

   VG_(message)(Vg_UserMsg, "");
}


/* ---------------------------------------------------------------------
   darwin sockopt wrapper helpers
   ------------------------------------------------------------------ */

void 
ML_(PRE_sys_getsockopt) ( ThreadId tid, 
                          UWord arg0, UWord arg1, UWord arg2,
                          UWord arg3, UWord arg4 )
{
#warning GrP fixme darwin-specific sockopts
}

void 
ML_(POST_sys_getsockopt) ( ThreadId tid, 
                           SysRes res,
                           UWord arg0, UWord arg1, UWord arg2,
                           UWord arg3, UWord arg4 )
{
#warning GrP fixme darwin-specific sockopts
}


#define PRE(name)       DEFN_PRE_TEMPLATE(darwin, name)
#define POST(name)      DEFN_POST_TEMPLATE(darwin, name)

#define PRE_FN(name)    vgSysWrap_darwin_##name##_before
#define POST_FN(name)   vgSysWrap_darwin_##name##_after

#define CALL_PRE(name) PRE_FN(name)(tid, layout, arrghs, status, flags)
#define CALL_POST(name) POST_FN(name)(tid, arrghs, status)

#if VG_WORDSIZE == 4
// Combine two 32-bit values into a 64-bit value
// Always use with low-numbered arg first (e.g. LOHI64(ARG1,ARG2) )
# if defined(VGA_x86)
#  define LOHI64(lo,hi)   ( (lo) | ((ULong)(hi) << 32) )
# else
#  error unknown architecture
# endif
#endif

// Retrieve the current Mach thread
#define MACH_THREAD ((Addr)VG_(get_ThreadState)(tid)->os_state.lwpid)

// Set the POST handler for a mach_msg derivative
#define AFTER VG_(get_ThreadState)(tid)->os_state.post_mach_trap_fn

// Set or get values saved from Mach messages
#define MACH_ARG(x) VG_(get_ThreadState)(tid)->os_state.mach_args.x
#define MACH_REMOTE VG_(get_ThreadState)(tid)->os_state.remote_port
#define MACH_MSGH_ID VG_(get_ThreadState)(tid)->os_state.msgh_id

/* ---------------------------------------------------------------------
   darwin ioctl wrapper helpers
   ------------------------------------------------------------------ */

PRE(sys_ioctl)
{
   *flags |= SfMayBlock;
   PRINT("sys_ioctl ( %ld, 0x%lx, %#lx )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "ioctl",
                 unsigned int, fd, unsigned int, request, unsigned long, arg);

   switch (ARG2 /* request */) {
   case VKI_TIOCGWINSZ:
      PRE_MEM_WRITE( "ioctl(TIOCGWINSZ)", ARG3, sizeof(struct vki_winsize) );
      break;
   case VKI_TIOCSWINSZ:
      PRE_MEM_READ( "ioctl(TIOCSWINSZ)",  ARG3, sizeof(struct vki_winsize) );
      break;
   case VKI_TIOCMBIS:
      PRE_MEM_READ( "ioctl(TIOCMBIS)",    ARG3, sizeof(unsigned int) );
      break;
   case VKI_TIOCMBIC:
      PRE_MEM_READ( "ioctl(TIOCMBIC)",    ARG3, sizeof(unsigned int) );
      break;
   case VKI_TIOCMSET:
      PRE_MEM_READ( "ioctl(TIOCMSET)",    ARG3, sizeof(unsigned int) );
      break;
   case VKI_TIOCMGET:
      PRE_MEM_WRITE( "ioctl(TIOCMGET)",   ARG3, sizeof(unsigned int) );
      break;
   case VKI_TIOCGPGRP:
      /* Get process group ID for foreground processing group. */
      PRE_MEM_WRITE( "ioctl(TIOCGPGRP)", ARG3, sizeof(vki_pid_t) );
      break;
   case VKI_TIOCSPGRP:
      /* Set a process group ID? */
      PRE_MEM_WRITE( "ioctl(TIOCGPGRP)", ARG3, sizeof(vki_pid_t) );
      break;
   case VKI_TIOCSCTTY:
      /* Just takes an int value.  */
      break;
   case VKI_FIONBIO:
      PRE_MEM_READ( "ioctl(FIONBIO)",    ARG3, sizeof(int) );
      break;
   case VKI_FIOASYNC:
      PRE_MEM_READ( "ioctl(FIOASYNC)",   ARG3, sizeof(int) );
      break;
   case VKI_FIONREAD:                /* identical to SIOCINQ */
      PRE_MEM_WRITE( "ioctl(FIONREAD)",  ARG3, sizeof(int) );
      break;


      /* These all use struct ifreq AFAIK */
      /* GrP fixme is sizeof(struct vki_if_req) correct if it's using a sockaddr? */
   case VKI_SIOCGIFFLAGS:        /* get flags                    */
      PRE_MEM_RASCIIZ( "ioctl(SIOCGIFFLAGS)",
                     (Addr)((struct vki_ifreq *)ARG3)->vki_ifr_name );
      PRE_MEM_WRITE( "ioctl(SIOCGIFFLAGS)", ARG3, sizeof(struct vki_ifreq));
      break;
   case VKI_SIOCGIFMTU:          /* get MTU size                 */
      PRE_MEM_RASCIIZ( "ioctl(SIOCGIFMTU)",
                     (Addr)((struct vki_ifreq *)ARG3)->vki_ifr_name );
      PRE_MEM_WRITE( "ioctl(SIOCGIFMTU)", ARG3, sizeof(struct vki_ifreq));
      break;
   case VKI_SIOCGIFADDR:         /* get PA address               */
      PRE_MEM_RASCIIZ( "ioctl(SIOCGIFADDR)",
                     (Addr)((struct vki_ifreq *)ARG3)->vki_ifr_name );
      PRE_MEM_WRITE( "ioctl(SIOCGIFADDR)", ARG3, sizeof(struct vki_ifreq));
      break;
   case VKI_SIOCGIFNETMASK:      /* get network PA mask          */
      PRE_MEM_RASCIIZ( "ioctl(SIOCGIFNETMASK)",
                     (Addr)((struct vki_ifreq *)ARG3)->vki_ifr_name );
      PRE_MEM_WRITE( "ioctl(SIOCGIFNETMASK)", ARG3, sizeof(struct vki_ifreq));
      break;
   case VKI_SIOCGIFMETRIC:       /* get metric                   */
      PRE_MEM_RASCIIZ( "ioctl(SIOCGIFMETRIC)",
                     (Addr)((struct vki_ifreq *)ARG3)->vki_ifr_name );
      PRE_MEM_WRITE( "ioctl(SIOCGIFMETRIC)", ARG3, sizeof(struct vki_ifreq));
      break;
   case VKI_SIOCGIFDSTADDR:      /* get remote PA address        */
      PRE_MEM_RASCIIZ( "ioctl(SIOCGIFDSTADDR)",
                     (Addr)((struct vki_ifreq *)ARG3)->vki_ifr_name );
      PRE_MEM_WRITE( "ioctl(SIOCGIFDSTADDR)", ARG3, sizeof(struct vki_ifreq));
      break;
   case VKI_SIOCGIFBRDADDR:      /* get broadcast PA address     */
      PRE_MEM_RASCIIZ( "ioctl(SIOCGIFBRDADDR)",
                     (Addr)((struct vki_ifreq *)ARG3)->vki_ifr_name );
      PRE_MEM_WRITE( "ioctl(SIOCGIFBRDADDR)", ARG3, sizeof(struct vki_ifreq));
      break;
   case VKI_SIOCGIFCONF:         /* get iface list               */
      /* WAS:
         PRE_MEM_WRITE( "ioctl(SIOCGIFCONF)", ARG3, sizeof(struct ifconf));
         KERNEL_DO_SYSCALL(tid,RES);
         if (!VG_(is_kerror)(RES) && RES == 0)
         POST_MEM_WRITE(ARG3, sizeof(struct ifconf));
      */
      PRE_MEM_READ( "ioctl(SIOCGIFCONF)",
                    (Addr)&((struct vki_ifconf *)ARG3)->ifc_len,
                    sizeof(((struct vki_ifconf *)ARG3)->ifc_len));
      PRE_MEM_READ( "ioctl(SIOCGIFCONF)",
                    (Addr)&((struct vki_ifconf *)ARG3)->vki_ifc_buf,
                    sizeof(((struct vki_ifconf *)ARG3)->vki_ifc_buf));
      if ( ARG3 ) {
         // TODO len must be readable and writable
         // buf pointer only needs to be readable
         struct vki_ifconf *ifc = (struct vki_ifconf *) ARG3;
         PRE_MEM_WRITE( "ioctl(SIOCGIFCONF).ifc_buf",
                        (Addr)(ifc->vki_ifc_buf), ifc->ifc_len );
      }
      break;
                    
   case VKI_SIOCSIFFLAGS:        /* set flags                    */
      PRE_MEM_RASCIIZ( "ioctl(SIOCSIFFLAGS)",
                     (Addr)((struct vki_ifreq *)ARG3)->vki_ifr_name );
      PRE_MEM_READ( "ioctl(SIOCSIFFLAGS)",
                     (Addr)&((struct vki_ifreq *)ARG3)->vki_ifr_flags,
                     sizeof(((struct vki_ifreq *)ARG3)->vki_ifr_flags) );
      break;
   case VKI_SIOCSIFADDR:         /* set PA address               */
   case VKI_SIOCSIFDSTADDR:      /* set remote PA address        */
   case VKI_SIOCSIFBRDADDR:      /* set broadcast PA address     */
   case VKI_SIOCSIFNETMASK:      /* set network PA mask          */
      PRE_MEM_RASCIIZ( "ioctl(SIOCSIF*ADDR)",
                     (Addr)((struct vki_ifreq *)ARG3)->vki_ifr_name );
      PRE_MEM_READ( "ioctl(SIOCSIF*ADDR)",
                     (Addr)&((struct vki_ifreq *)ARG3)->ifr_addr,
                     sizeof(((struct vki_ifreq *)ARG3)->ifr_addr) );
      break;
   case VKI_SIOCSIFMETRIC:       /* set metric                   */
      PRE_MEM_RASCIIZ( "ioctl(SIOCSIFMETRIC)",
                     (Addr)((struct vki_ifreq *)ARG3)->vki_ifr_name );
      PRE_MEM_READ( "ioctl(SIOCSIFMETRIC)",
                     (Addr)&((struct vki_ifreq *)ARG3)->vki_ifr_metric,
                     sizeof(((struct vki_ifreq *)ARG3)->vki_ifr_metric) );
      break;
   case VKI_SIOCSIFMTU:          /* set MTU size                 */
      PRE_MEM_RASCIIZ( "ioctl(SIOCSIFMTU)",
                     (Addr)((struct vki_ifreq *)ARG3)->vki_ifr_name );
      PRE_MEM_READ( "ioctl(SIOCSIFMTU)",
                     (Addr)&((struct vki_ifreq *)ARG3)->vki_ifr_mtu,
                     sizeof(((struct vki_ifreq *)ARG3)->vki_ifr_mtu) );
      break;
      /* Routing table calls.  */
#ifdef VKI_SIOCADDRT
   case VKI_SIOCADDRT:           /* add routing table entry      */
   case VKI_SIOCDELRT:           /* delete routing table entry   */
      PRE_MEM_READ( "ioctl(SIOCADDRT/DELRT)", ARG3, 
                    sizeof(struct vki_rtentry));
      break;
#endif

   case VKI_SIOCGPGRP:
      PRE_MEM_WRITE( "ioctl(SIOCGPGRP)", ARG3, sizeof(int) );
      break;
   case VKI_SIOCSPGRP:
      PRE_MEM_READ( "ioctl(SIOCSPGRP)", ARG3, sizeof(int) );
      //tst->sys_flags &= ~SfMayBlock;
      break;

#warning GrP fixme darwin-specific ioctl
   case VKI_FIODTYPE: 
      PRE_MEM_WRITE( "ioctl(FIONREAD)", ARG3, sizeof(int) );
      break;

   case VKI_DTRACEHIOC_REMOVE: 
   case VKI_DTRACEHIOC_ADDDOF: 
       break;

       // ttycom.h
   case VKI_TIOCGETA:
       PRE_MEM_WRITE( "ioctl(TIOCGETA)", ARG3, sizeof(struct vki_termios) );
       break;
   case VKI_TIOCSETA:
       PRE_MEM_READ( "ioctl(TIOCSETA)", ARG3, sizeof(struct vki_termios) );
       break;
   case VKI_TIOCGETD:
       PRE_MEM_WRITE( "ioctl(TIOCGETD)", ARG3, sizeof(int) );
       break;
   case VKI_TIOCSETD:
       PRE_MEM_READ( "ioctl(TIOCSETD)", ARG3, sizeof(int) );
       break;
   case VKI_TIOCPTYGNAME:
       PRE_MEM_WRITE( "ioctl(TIOCPTYGNAME)", ARG3, 128 );
       break;
   case VKI_TIOCPTYGRANT:
   case VKI_TIOCPTYUNLK:
       break;

   default: 
      ML_(PRE_unknown_ioctl)(tid, ARG2, ARG3);
      break;
   }
}


POST(sys_ioctl)
{
   vg_assert(SUCCESS);
   switch (ARG2 /* request */) {
   case VKI_TIOCGWINSZ:
      POST_MEM_WRITE( ARG3, sizeof(struct vki_winsize) );
      break;
   case VKI_TIOCSWINSZ:
   case VKI_TIOCMBIS:
   case VKI_TIOCMBIC:
   case VKI_TIOCMSET:
      break;
   case VKI_TIOCMGET:
      POST_MEM_WRITE( ARG3, sizeof(unsigned int) );
      break;
   case VKI_TIOCGPGRP:
      /* Get process group ID for foreground processing group. */
      POST_MEM_WRITE( ARG3, sizeof(vki_pid_t) );
      break;
   case VKI_TIOCSPGRP:
      /* Set a process group ID? */
      POST_MEM_WRITE( ARG3, sizeof(vki_pid_t) );
      break;
   case VKI_TIOCSCTTY:
      break;
   case VKI_FIONBIO:
      break;
   case VKI_FIOASYNC:
      break;
   case VKI_FIONREAD:                /* identical to SIOCINQ */
      POST_MEM_WRITE( ARG3, sizeof(int) );
      break;

      /* These all use struct ifreq AFAIK */
   case VKI_SIOCGIFFLAGS:        /* get flags                    */
      POST_MEM_WRITE( (Addr)&((struct vki_ifreq *)ARG3)->vki_ifr_flags,
                      sizeof(((struct vki_ifreq *)ARG3)->vki_ifr_flags) );
      break;
   case VKI_SIOCGIFMTU:          /* get MTU size                 */
      POST_MEM_WRITE( (Addr)&((struct vki_ifreq *)ARG3)->vki_ifr_mtu,
                      sizeof(((struct vki_ifreq *)ARG3)->vki_ifr_mtu) );
      break;
   case VKI_SIOCGIFADDR:         /* get PA address               */
   case VKI_SIOCGIFDSTADDR:      /* get remote PA address        */
   case VKI_SIOCGIFBRDADDR:      /* get broadcast PA address     */
   case VKI_SIOCGIFNETMASK:      /* get network PA mask          */
      POST_MEM_WRITE(
                (Addr)&((struct vki_ifreq *)ARG3)->ifr_addr,
                sizeof(((struct vki_ifreq *)ARG3)->ifr_addr) );
      break;
   case VKI_SIOCGIFMETRIC:       /* get metric                   */
      POST_MEM_WRITE(
                (Addr)&((struct vki_ifreq *)ARG3)->vki_ifr_metric,
                sizeof(((struct vki_ifreq *)ARG3)->vki_ifr_metric) );
      break;
   case VKI_SIOCGIFCONF:         /* get iface list               */
      /* WAS:
         PRE_MEM_WRITE("ioctl(SIOCGIFCONF)", ARG3, sizeof(struct ifconf));
         KERNEL_DO_SYSCALL(tid,RES);
         if (!VG_(is_kerror)(RES) && RES == 0)
         POST_MEM_WRITE(ARG3, sizeof(struct ifconf));
      */
      if (RES == 0 && ARG3 ) {
         struct vki_ifconf *ifc = (struct vki_ifconf *) ARG3;
         if (ifc->vki_ifc_buf != NULL)
            POST_MEM_WRITE( (Addr)(ifc->vki_ifc_buf), ifc->ifc_len );
      }
      break;
                    
   case VKI_SIOCSIFFLAGS:        /* set flags                    */
   case VKI_SIOCSIFDSTADDR:      /* set remote PA address        */
   case VKI_SIOCSIFBRDADDR:      /* set broadcast PA address     */
   case VKI_SIOCSIFNETMASK:      /* set network PA mask          */
   case VKI_SIOCSIFMETRIC:       /* set metric                   */
   case VKI_SIOCSIFADDR:         /* set PA address               */
   case VKI_SIOCSIFMTU:          /* set MTU size                 */
      break;

#ifdef VKI_SIOCADDRT
      /* Routing table calls.  */
   case VKI_SIOCADDRT:           /* add routing table entry      */
   case VKI_SIOCDELRT:           /* delete routing table entry   */
      break;
#endif

   case VKI_SIOCGPGRP:
      POST_MEM_WRITE(ARG3, sizeof(int));
      break;
   case VKI_SIOCSPGRP:
      break;

#warning GrP fixme darwin-specific ioctl
   case VKI_FIODTYPE: 
      POST_MEM_WRITE( ARG3, sizeof(int) );
      break;

   case VKI_DTRACEHIOC_REMOVE: 
   case VKI_DTRACEHIOC_ADDDOF: 
       break;

       // ttycom.h
   case VKI_TIOCGETA:
       POST_MEM_WRITE( ARG3, sizeof(struct vki_termios));
       break;
   case VKI_TIOCSETA:
       break;
   case VKI_TIOCGETD:
       POST_MEM_WRITE( ARG3, sizeof(int) );
       break;
   case VKI_TIOCSETD:
       break;
   case VKI_TIOCPTYGNAME:
       POST_MEM_WRITE( ARG3, 128);
       break;
   case VKI_TIOCPTYGRANT:
   case VKI_TIOCPTYUNLK:
       break;

   default:
      break;
   }
}


/* ---------------------------------------------------------------------
   darwin fcntl wrapper helpers
   ------------------------------------------------------------------ */
static const char *name_for_fcntl(UWord cmd) {
#define F(n) case VKI_##n: return #n
   switch (cmd) {
      F(F_CHKCLEAN);
      F(F_RDAHEAD);
      F(F_NOCACHE);
      F(F_FULLFSYNC);
      F(F_FREEZE_FS);
      F(F_THAW_FS);
      F(F_GLOBAL_NOCACHE);
      F(F_PREALLOCATE);
      F(F_SETSIZE);
      F(F_RDADVISE);
      F(F_READBOOTSTRAP);
      F(F_WRITEBOOTSTRAP);
      F(F_LOG2PHYS);
      F(F_GETPATH);
      F(F_PATHPKG_CHECK);
   default:
      return "UNKNOWN";
   }
#undef F
}

PRE(sys_fcntl)
{
   switch (ARG2) {
   // These ones ignore ARG3.
   case VKI_F_GETFD:
   case VKI_F_GETFL:
   case VKI_F_GETOWN:
      PRINT("sys_fcntl ( %ld, %ld )", ARG1,ARG2);
      PRE_REG_READ2(long, "fcntl", unsigned int, fd, unsigned int, cmd);
      break;

   // These ones use ARG3 as "arg".
   case VKI_F_DUPFD:
   case VKI_F_SETFD:
   case VKI_F_SETFL:
   case VKI_F_SETOWN:
      PRINT("sys_fcntl[ARG3=='arg'] ( %ld, %ld, %ld )", ARG1,ARG2,ARG3);
      PRE_REG_READ3(long, "fcntl",
                    unsigned int, fd, unsigned int, cmd, unsigned long, arg);
      break;

   // These ones use ARG3 as "lock".
   case VKI_F_GETLK:
   case VKI_F_SETLK:
   case VKI_F_SETLKW:
      PRINT("sys_fcntl[ARG3=='lock'] ( %ld, %ld, %#lx )", ARG1,ARG2,ARG3);
      PRE_REG_READ3(long, "fcntl",
                    unsigned int, fd, unsigned int, cmd,
                    struct flock64 *, lock);
      // GrP fixme mem read sizeof(flock64)
      if (ARG2 == VKI_F_SETLKW) 
         *flags |= SfMayBlock;
      break;

       // none
   case VKI_F_CHKCLEAN:
   case VKI_F_RDAHEAD:
   case VKI_F_NOCACHE:
   case VKI_F_FULLFSYNC:
   case VKI_F_FREEZE_FS:
   case VKI_F_THAW_FS:
   case VKI_F_GLOBAL_NOCACHE:
      PRINT("sys_fcntl ( %d, %s )", ARG1, name_for_fcntl(ARG1));
      PRE_REG_READ2(long, "fcntl", unsigned int, fd, unsigned int, cmd);
      break;

       // struct fstore
   case VKI_F_PREALLOCATE:
      PRINT("sys_fcntl ( %d, %s, %p )", ARG1, name_for_fcntl(ARG2), ARG3);
      PRE_REG_READ3(long, "fcntl",
                    unsigned int, fd, unsigned int, cmd,
                    struct fstore *, fstore);
      {
         struct vki_fstore *fstore = (struct vki_fstore *)ARG3;
         PRE_FIELD_READ( "fcntl(F_PREALLOCATE, fstore->fst_flags)", 
                         fstore->fst_flags );
         PRE_FIELD_READ( "fcntl(F_PREALLOCATE, fstore->fst_flags)", 
                         fstore->fst_posmode );
         PRE_FIELD_READ( "fcntl(F_PREALLOCATE, fstore->fst_flags)", 
                         fstore->fst_offset );
         PRE_FIELD_READ( "fcntl(F_PREALLOCATE, fstore->fst_flags)", 
                         fstore->fst_length );
         PRE_FIELD_WRITE( "fcntl(F_PREALLOCATE, fstore->fst_bytesalloc)", 
                          fstore->fst_bytesalloc);
      }
      break;

       // off_t
   case VKI_F_SETSIZE:
      PRINT("sys_fcntl ( %d, %s, %p )", ARG1, name_for_fcntl(ARG2), ARG3);
      PRE_REG_READ3(long, "fcntl",
                    unsigned int, fd, unsigned int, cmd,
                    vki_off_t *, offset);
      break;

       // struct radvisory
   case VKI_F_RDADVISE:
      PRINT("sys_fcntl ( %d, %s, %p )", ARG1, name_for_fcntl(ARG2), ARG3);
      PRE_REG_READ3(long, "fcntl",
                    unsigned int, fd, unsigned int, cmd,
                    struct vki_radvisory *, radvisory);
      {
         struct vki_radvisory *radvisory = (struct vki_radvisory *)ARG3;
         PRE_FIELD_READ( "fcntl(F_PREALLOCATE, radvisory->ra_offset)", 
                         radvisory->ra_offset );
         PRE_FIELD_READ( "fcntl(F_PREALLOCATE, radvisory->ra_count)", 
                         radvisory->ra_count );
      }
      break;

       // struct fbootstraptransfer
   case VKI_F_READBOOTSTRAP:
   case VKI_F_WRITEBOOTSTRAP:
      PRINT("sys_fcntl ( %d, %s, %p )", ARG1, name_for_fcntl(ARG2), ARG3);
      PRE_REG_READ3(long, "fcntl",
                    unsigned int, fd, unsigned int, cmd,
                    struct fbootstraptransfer *, bootstrap);
      PRE_MEM_READ( "fcntl(F_READ/WRITEBOOTSTRAP, bootstrap)", 
                    ARG3, sizeof(struct vki_fbootstraptransfer) );
      break;

       // struct log2phys (out)
   case VKI_F_LOG2PHYS:
      PRINT("sys_fcntl ( %d, %s, %p )", ARG1, name_for_fcntl(ARG2), ARG3);
      PRE_REG_READ3(long, "fcntl",
                    unsigned int, fd, unsigned int, cmd,
                    struct log2phys *, l2p);
      PRE_MEM_WRITE( "fcntl(F_LOG2PHYS, l2p)", 
                     ARG3, sizeof(struct vki_log2phys) );
      break;

       // char[maxpathlen] (out)
   case VKI_F_GETPATH:
      PRINT("sys_fcntl ( %d, %s, %p )", ARG1, name_for_fcntl(ARG2), ARG3);
      PRE_REG_READ3(long, "fcntl",
                    unsigned int, fd, unsigned int, cmd,
                    char *, pathbuf);
      PRE_MEM_WRITE( "fcntl(F_GETPATH, pathbuf)", 
                     ARG3, VKI_MAXPATHLEN );
      break;

       // char[maxpathlen] (in)
   case VKI_F_PATHPKG_CHECK:
      PRINT("sys_fcntl ( %d, %s, %p '%s')", ARG1, name_for_fcntl(ARG2), ARG3,
          ARG3);
      PRE_REG_READ3(long, "fcntl",
                    unsigned int, fd, unsigned int, cmd,
                    char *, pathbuf);
      PRE_MEM_RASCIIZ( "fcntl(F_PATHPKG_CHECK, pathbuf)", ARG3);
      break;

   default:
      PRINT("sys_fcntl ( %d, %d [??] )", ARG1, ARG2);
      if (VG_(clo_trace_unknown_syscalls)) {
          VG_(printf)("UNKNOWN fcntl %d!", ARG2);
      }
      break;
   }
}

POST(sys_fcntl)
{
   vg_assert(SUCCESS);
   switch (ARG2) {
   case VKI_F_DUPFD:
      if (!ML_(fd_allowed)(RES, "fcntl(DUPFD)", tid, True)) {
         VG_(close)(RES);
         SET_STATUS_Failure( VKI_EMFILE );
      } else {
         if (VG_(clo_track_fds))
            ML_(record_fd_open_named)(tid, RES);
      }
      break;

   case VKI_F_GETFD:
   case VKI_F_GETFL:
   case VKI_F_GETOWN:
   case VKI_F_SETFD:
   case VKI_F_SETFL:
   case VKI_F_SETOWN:
   case VKI_F_GETLK:
   case VKI_F_SETLK:
   case VKI_F_SETLKW:
       break;

   case VKI_F_PREALLOCATE:
      {
         struct vki_fstore *fstore = (struct vki_fstore *)ARG3;
         POST_FIELD_WRITE( fstore->fst_bytesalloc );
      }
      break;

   case VKI_F_LOG2PHYS:
      POST_MEM_WRITE( ARG3, sizeof(struct vki_log2phys) );
      break;

   case VKI_F_GETPATH:
      POST_MEM_WRITE( ARG3, 1+VG_(strlen)((char *)ARG3) );
      PRINT("\"%s\"", ARG3);
      break;

   default:
      // DDD: ugh, missing lots of cases here, not nice
      break;
   }
}

// XXX: wrapper only suitable for 32-bit systems
PRE(sys_fcntl64)
{
   switch (ARG2) {
   // These ones ignore ARG3.
   case VKI_F_GETFD:
   case VKI_F_GETFL:
   case VKI_F_GETOWN:
      PRINT("sys_fcntl64 ( %ld, %ld )", ARG1,ARG2);
      PRE_REG_READ2(long, "fcntl64", unsigned int, fd, unsigned int, cmd);
      break;

   // These ones use ARG3 as "arg".
   case VKI_F_DUPFD:
   case VKI_F_SETFD:
   case VKI_F_SETFL:
   case VKI_F_SETOWN:
      PRINT("sys_fcntl64[ARG3=='arg'] ( %ld, %ld, %ld )", ARG1,ARG2,ARG3);
      PRE_REG_READ3(long, "fcntl64",
                    unsigned int, fd, unsigned int, cmd, unsigned long, arg);
      break;

   // These ones use ARG3 as "lock".
   case VKI_F_GETLK:
   case VKI_F_SETLK:
   case VKI_F_SETLKW:
      PRINT("sys_fcntl64[ARG3=='lock'] ( %ld, %ld, %lp )", ARG1,ARG2,ARG3);
      PRE_REG_READ3(long, "fcntl64",
                    unsigned int, fd, unsigned int, cmd,
                    struct flock64 *, lock);
   if (ARG2 == VKI_F_SETLKW)
      *flags |= SfMayBlock;
      break;

   default:
      I_die_here;    // DDD: do something better here
      break;
   }
}

POST(sys_fcntl64)
{
   vg_assert(SUCCESS);
   switch (ARG2) {
   case VKI_F_DUPFD:
      if (!ML_(fd_allowed)(RES, "fcntl64(DUPFD)", tid, True)) {
         VG_(close)(RES);
         SET_STATUS_Failure( VKI_EMFILE );
      } else {
         if (VG_(clo_track_fds))
            ML_(record_fd_open_named)(tid, RES);
      }
      break;

   case VKI_F_GETFD:
   case VKI_F_GETFL:
   case VKI_F_GETOWN:
   case VKI_F_SETFD:
   case VKI_F_SETFL:
   case VKI_F_SETOWN:
   case VKI_F_GETLK:
   case VKI_F_SETLK:
   case VKI_F_SETLKW:
       break;

   default:
      I_die_here;    // DDD: do something better here
      break;
   }
}

/* ---------------------------------------------------------------------
   unix syscalls
   ------------------------------------------------------------------ */

PRE(sys_semget)
{
   PRINT("sys_semget ( %d, %d, %d )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "semget", vki_key_t, key, int, nsems, int, semflg);
}

PRE(sys_semop)
{
   *flags |= SfMayBlock;
   PRINT("sys_semop ( %d, %p, %u )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "semop",
                 int, semid, struct sembuf *, sops, vki_size_t, nsoops);
   ML_(generic_PRE_sys_semop)(tid, ARG1,ARG2,ARG3);
}

PRE(sys_semctl)
{
   switch (ARG3) {
   case VKI_IPC_STAT:
   case VKI_IPC_SET:
      PRINT("sys_semctl ( %d, %d, %d, %p )",ARG1,ARG2,ARG3,ARG4);
      PRE_REG_READ4(long, "semctl",
                    int, semid, int, semnum, int, cmd, struct semid_ds *, arg);
      break;
   case VKI_GETALL:
   case VKI_SETALL:
      PRINT("sys_semctl ( %d, %d, %d, %p )",ARG1,ARG2,ARG3,ARG4);
      PRE_REG_READ4(long, "semctl",
                    int, semid, int, semnum, int, cmd, unsigned short *, arg);
      break;
   case VKI_SETVAL:
      PRINT("sys_semctl ( %d, %d, %d, %p )",ARG1,ARG2,ARG3,ARG4);
      PRE_REG_READ4(long, "semctl",
                    int, semid, int, semnum, int, cmd, int, arg);
      break;
   default:
      PRINT("sys_semctl ( %d, %d, %d )",ARG1,ARG2,ARG3);
      PRE_REG_READ3(long, "semctl",
                    int, semid, int, semnum, int, cmd);
      break;
   }
   ML_(generic_PRE_sys_semctl)(tid, ARG1,ARG2,ARG3,ARG4);
}
POST(sys_semctl)
{
   ML_(generic_POST_sys_semctl)(tid, RES,ARG1,ARG2,ARG3,ARG4);
}


PRE(sys_kqueue)
{
    PRINT("kqueue()");
}

POST(sys_kqueue)
{
   if (!ML_(fd_allowed)(RES, "kqueue", tid, True)) {
      VG_(close)(RES);
      SET_STATUS_Failure( VKI_EMFILE );
   } else {
      if (VG_(clo_track_fds)) {
         ML_(record_fd_open_with_given_name)(tid, RES, NULL);
      }
   }
}

PRE(sys_kevent)
{
   PRINT("kevent( %d, %p, %d, %p, %d, %p )", 
         ARG1, ARG2, ARG3, ARG4, ARG5, ARG6);
   PRE_REG_READ6(int,"kevent", int,kq, 
                 const struct vki_kevent *,changelist, int,nchanges, 
                 struct vki_kevent *,eventlist, int,nevents, 
                 const struct vki_timespec *,timeout);

   if (ARG3) PRE_MEM_READ ("kevent(changelist)", 
                           ARG2, ARG3 * sizeof(struct vki_kevent));
   if (ARG5) PRE_MEM_WRITE("kevent(eventlist)", 
                           ARG4, ARG5 * sizeof(struct vki_kevent));
   if (ARG6) PRE_MEM_READ ("kevent(timeout)", 
                           ARG6, sizeof(struct vki_timespec));

   *flags |= SfMayBlock;
}

POST(sys_kevent)
{
   PRINT("kevent ret %d dst %p (%zu)", RES, ARG4, sizeof(struct vki_kevent));
   if (RES > 0) POST_MEM_WRITE(ARG4, RES * sizeof(struct vki_kevent));
}


Addr pthread_starter = 0;
Addr wqthread_starter = 0;
SizeT pthread_structsize = 0;

PRE(sys_bsdthread_register)
{
   PRINT("bsdthread_register( %p, %p, %lu )", ARG1, ARG2, ARG3);
   PRE_REG_READ3(int,"__bsdthread_register", void *,"threadstart", 
                 void *,"wqthread", size_t,"pthsize");

   pthread_starter = ARG1;
   wqthread_starter = ARG2;
   pthread_structsize = ARG3;
   ARG1 = (Word)&pthread_hijack_asm;
   ARG2 = (Word)&wqthread_hijack_asm;
}

PRE(sys_workq_open)
{
   PRINT("workq_open()");
   PRE_REG_READ0(int, "workq_open");

   // This creates lots of threads and thread stacks under the covers, 
   // but we ignore them all until some work item starts running on it.
}

static const char *workqop_name(int op)
{
   switch (op) {
   case VKI_WQOPS_QUEUE_ADD: return "QUEUE_ADD";
   case VKI_WQOPS_QUEUE_REMOVE: return "QUEUE_REMOVE";
   case VKI_WQOPS_THREAD_RETURN: return "THREAD_RETURN";
   default: return "?";
   }
}


PRE(sys_workq_ops)
{
   PRINT("workq_ops( %d(%s), %p, %d )", ARG1, workqop_name(ARG1), ARG2, ARG3);
   PRE_REG_READ3(int,"workq_ops", int,"options", void *,"item", 
                 int,"priority");

   switch (ARG1) {
   case VKI_WQOPS_QUEUE_ADD:
   case VKI_WQOPS_QUEUE_REMOVE:
      // fixme need anything here?
      // fixme may block?
      break;

   case VKI_WQOPS_THREAD_RETURN: {
      // The interesting case. The kernel will do one of two things:
      // 1. Return normally. We continue; libc proceeds to stop the thread.
      //    V does nothing special here.
      // 2. Jump to wqthread_hijack. This wipes the stack and runs a 
      //    new work item, and never returns from workq_ops. 
      //    V handles this by longjmp() from wqthread_hijack back to the 
      //    scheduler, which continues at the new client SP/IP/state.
      //    This works something like V's signal handling.
      //    To the tool, this looks like workq_ops() sometimes returns 
      //    to a strange address.
      ThreadState *tst = VG_(get_ThreadState)(tid);
      tst->os_state.wq_jmpbuf_valid = True;
      *flags |= SfMayBlock;  // fixme true?
      break;
   }

   default:
      VG_(printf)("UNKNOWN workq_ops option %d\n", ARG1);
      break;
   }
}

POST(sys_workq_ops)
{
   ThreadState *tst = VG_(get_ThreadState)(tid);
   tst->os_state.wq_jmpbuf_valid = False;
}



PRE(sys___mac_syscall)
{
   PRINT("__mac_syscall( %p, %d, %p )", ARG1, ARG2, ARG3);
   PRE_REG_READ3(int,"__mac_syscall", char *,"policy", 
                 int,"call", void *,"arg");

   // GrP fixme check call's arg?
   // GrP fixme check policy?
}


/* Not syswrap-generic's sys_exit, which exits only one thread.
   More like syswrap-generic's sys_exit_group. */
PRE(sys_exit)
{
   ThreadId     t;
   ThreadState* tst;

   PRINT("darwin exit( %d )", ARG1);
   PRE_REG_READ1(void, "exit", int, exit_code);

   tst = VG_(get_ThreadState)(tid);

   /* A little complex; find all the threads with the same threadgroup
      as this one (including this one), and mark them to exit */
   for (t = 1; t < VG_N_THREADS; t++) {
      if ( /* not alive */
           VG_(threads)[t].status == VgTs_Empty 
           /* GrP fixme zombie? */
         )
         continue;

      VG_(threads)[t].exitreason = VgSrc_ExitProcess;
      VG_(threads)[t].os_state.exitcode = ARG1;

      if (t != tid)
         VG_(get_thread_out_of_syscall)(t);     /* unblock it, if blocked */
   }

   /* We have to claim the syscall already succeeded. */
   SET_STATUS_Success(0);
}


PRE(sys_sigaction)
{
   // GrP fixme
   static Bool warned;
   if (!warned && VG_(clo_trace_unknown_syscalls)) {
      VG_(printf)("UNKNOWN __sigaction is unsupported. "
                  "This warning will not be repeated.\n");
      warned = True;
   }
   SET_STATUS_Failure( VKI_EINVAL );
}


PRE(sys___pthread_sigmask)
{
   // GrP fixme
   static Bool warned;
   if (!warned && VG_(clo_trace_unknown_syscalls)) {
      VG_(printf)("UNKNOWN __pthread_sigmask is unsupported. "
                  "This warning will not be repeated.\n");
      warned = True;
   }
   SET_STATUS_Success( 0 );
}


PRE(sys___disable_threadsignal)
{
   // GrP fixme
   static Bool warned;
   if (!warned && VG_(clo_trace_unknown_syscalls)) {
      VG_(printf)("UNKNOWN __disable_threadsignal is unsupported. "
                  "This warning will not be repeated.\n");
      warned = True;
   }
   SET_STATUS_Failure( VKI_EINVAL );
}


PRE(sys_kdebug_trace)
{
   PRINT("kdebug_trace(%d, %d, %d, %d, %d, %d)", 
         ARG1, ARG2, ARG3, ARG4, ARG5, ARG6);
   PRE_REG_READ6(long, "kdebug_trace", 
                 int,"code", int,"arg1", int,"arg2", 
                 int,"arg3", int,"arg4", int,"arg5");
   // GrP fixme anything else?
}


PRE(sys_seteuid)
{
    PRINT("seteuid(%d)", ARG1);
    PRE_REG_READ1(long, "seteuid", vki_uid_t, "uid");
}


PRE(sys_setegid)
{
    PRINT("setegid(%d)", ARG1);
    PRE_REG_READ1(long, "setegid", vki_uid_t, "uid");
}

PRE(sys_settid)
{
    PRINT("settid(%d, %d)", ARG1, ARG2);
    PRE_REG_READ2(long, "settid", vki_uid_t, "uid", vki_gid_t, "gid");
}

/* XXX need to check whether we need POST operations for
 * waitevent, watchevent, modwatch -- jpeach 
 */
PRE(sys_watchevent)
{
    PRINT("watchevent(%p, %#x)", ARG1, ARG2);
    PRE_REG_READ2(long, "watchevent",
        vki_eventreq *, "event", unsigned int, "eventmask");

    PRE_MEM_READ("watchevent(event)", ARG1, sizeof(vki_eventreq));
    PRE_MEM_READ("watchevent(eventmask)", ARG2, sizeof(unsigned int));
    *flags |= SfMayBlock;
}

#define WAITEVENT_FAST_POLL ((Addr)(struct timeval *)-1)
PRE(sys_waitevent)
{
   PRINT("waitevent(%p, %p)", ARG1, ARG2);
   PRE_REG_READ2(long, "waitevent",
      vki_eventreq *, "event", struct timeval *, "timeout");
   PRE_MEM_WRITE("waitevent(event)", ARG1, sizeof(vki_eventreq));

   if (ARG2  &&  ARG2 != WAITEVENT_FAST_POLL) {
      PRE_timeval_READ("waitevent(timeout)", ARG2);
   }

   /* XXX ((timeval*)-1) is valid for ARG2 -- jpeach */
   *flags |= SfMayBlock;
}

POST(sys_waitevent)
{
   POST_MEM_WRITE(ARG1, sizeof(vki_eventreq));
}

PRE(sys_modwatch)
{
   PRINT("modwatch(%p, %#x)", ARG1, ARG2);
   PRE_REG_READ2(long, "modwatch",
      vki_eventreq *, "event", unsigned int, "eventmask");

   PRE_MEM_READ("modwatch(event)", ARG1, sizeof(vki_eventreq));
   PRE_MEM_READ("modwatch(eventmask)", ARG2, sizeof(unsigned int));
}

PRE(sys_getxattr)
{
   PRINT("getxattr(%p(%s), %p(%s), %p, %u, %u, %d)",
         ARG1, (char *)ARG1, ARG2, (char *)ARG2, ARG3, ARG4, ARG5, ARG6);

   PRE_REG_READ6(vki_ssize_t, "getxattr",
                const char *, path, char *, name, void *, value,
                vki_size_t, size, uint32_t, position, int, options);
   PRE_MEM_RASCIIZ("getxattr(path)", ARG1);
   PRE_MEM_RASCIIZ("getxattr(name)", ARG2);
   PRE_MEM_WRITE( "getxattr(value)", ARG3, ARG4);
}

POST(sys_getxattr)
{
   vg_assert((vki_ssize_t)RES >= 0);
   POST_MEM_WRITE(ARG3, (vki_ssize_t)RES);
}

PRE(sys_fgetxattr)
{
   PRINT("fgetxattr(%d, %p(%s), %p, %u, %u, %d)",
      ARG1, ARG2, (char *)ARG2, ARG3, ARG4, ARG5, ARG6);

   PRE_REG_READ6(vki_ssize_t, "fgetxattr",
                 int, fd, char *, name, void *, value,
                 vki_size_t, size, uint32_t, position, int, options);
   PRE_MEM_RASCIIZ("getxattr(name)", ARG2);
   PRE_MEM_WRITE( "getxattr(value)", ARG3, ARG4);
}

POST(sys_fgetxattr)
{
   vg_assert((vki_ssize_t)RES >= 0);
   POST_MEM_WRITE(ARG3, (vki_ssize_t)RES);
}

PRE(sys_setxattr)
{
   PRINT("setxattr ( %p(%s), %p(%s), %p, %u, %u, %d )", 
         ARG1, (char *)ARG1, ARG2, (char*)ARG2, ARG3, ARG4, ARG5, ARG6 );
   PRE_REG_READ6(int, "setxattr", 
                 const char *,"path", char *,"name", void *,"value", 
                 vki_size_t,"size", uint32_t,"position", int,"options" );
   
   PRE_MEM_RASCIIZ( "setxattr(path)", ARG1 );
   PRE_MEM_RASCIIZ( "setxattr(name)", ARG2 );
   PRE_MEM_READ( "setxattr(value)", ARG3, ARG4 );
}


PRE(sys_fsetxattr)
{
   PRINT( "fsetxattr ( %d, %p(%s), %p, %u, %u, %d )", 
          ARG1, ARG2, (char*)ARG2, ARG3, ARG4, ARG5, ARG6 );
   PRE_REG_READ6(int, "fsetxattr", 
                 int,"fd", char *,"name", void *,"value", 
                 vki_size_t,"size", uint32_t,"position", int,"options" );
   
   PRE_MEM_RASCIIZ( "fsetxattr(name)", ARG2 );
   PRE_MEM_READ( "fsetxattr(value)", ARG3, ARG4 );
}


PRE(sys_listxattr)
{
   PRINT( "listxattr ( %p(%s), %p, %u, %d )", 
          ARG1, (char *)ARG1, ARG2, ARG3, ARG4 );
   PRE_REG_READ4 (long, "listxattr", 
                 const char *,"path", char *,"namebuf", 
                 vki_size_t,"size", int,"options" );
   
   PRE_MEM_RASCIIZ( "listxattr(path)", ARG1 );
   PRE_MEM_WRITE( "listxattr(namebuf)", ARG2, ARG3 );

   *flags |= SfMayBlock;
}

POST(sys_listxattr)
{
   vg_assert((vki_ssize_t)RES >= 0);
   POST_MEM_WRITE( ARG2, (vki_ssize_t)RES );
}


PRE(sys_shm_open)
{
   PRINT("shm_open(%p(%s), %d, %d)", ARG1, (char *)ARG1, ARG2, ARG3);
   PRE_REG_READ3(long, "shm_open",
                 const char *,"name", int,"flags", vki_mode_t,"mode");

   PRE_MEM_RASCIIZ( "shm_open(filename)", ARG1 );

   *flags |= SfMayBlock;
}

POST(sys_shm_open)
{
   vg_assert(SUCCESS);
   if (!ML_(fd_allowed)(RES, "shm_open", tid, True)) {
      VG_(close)(RES);
      SET_STATUS_Failure( VKI_EMFILE );
   } else {
      if (VG_(clo_track_fds))
         ML_(record_fd_open_with_given_name)(tid, RES, (Char*)ARG1);
   }
}


PRE(sys_statx)
{
   PRINT("statx( %p(%s), %p, %p, %p )", ARG1, ARG1, ARG2, ARG3, ARG4);
   PRE_REG_READ4(int, "statx", char *, file_name, struct stat *, buf, 
                 void *, fsacl, vki_size_t *, fsacl_size);
   PRE_MEM_RASCIIZ( "statx(file_name)",  ARG1 );
   PRE_MEM_READ(    "statx(fsacl_size)", ARG4, sizeof(vki_size_t) );
   PRE_MEM_WRITE(   "statx(buf)",        ARG2, sizeof(struct vki_stat) );
   PRE_MEM_WRITE(   "statx(fsacl_size)", ARG4, sizeof(vki_size_t) );
   PRE_MEM_WRITE(   "statx(fsacl)",      ARG3, *(vki_size_t *)ARG4 );
}

POST(sys_statx)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_stat) );
   POST_MEM_WRITE( ARG4, sizeof(vki_size_t) );
   POST_MEM_WRITE( ARG3, *(vki_size_t *)ARG4 );
}


PRE(sys_accessx)
{
    // fixme difficult
}

POST(sys_accessx)
{
    // fixme
}

PRE(sys_chflags)
{
   PRINT("sys_chflags ( %p(%s), %u )", ARG1, ARG1, ARG2);
   PRE_REG_READ2(int, "chflags", const char *,path, unsigned int,flags);
   PRE_MEM_RASCIIZ("chflags(path)", ARG1);

   // fixme sanity-check flags value?
}

PRE(sys_fchflags)
{
   PRINT("sys_fchflags ( %d, %u )", ARG1, ARG2);
   PRE_REG_READ2(int, "fchflags", int,fd, unsigned int,flags);

   // fixme sanity-check flags value?
}

POST(sys_stat64)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_stat64) );
}

PRE(sys_stat64)
{
   PRINT("sys_stat64 ( %p(%s), %p )", ARG1, ARG1, ARG2);
   PRE_REG_READ2(long, "stat", const char *,path, struct stat64 *,buf);
   PRE_MEM_RASCIIZ("stat64(path)", ARG1);
   PRE_MEM_WRITE( "stat64(buf)", ARG2, sizeof(struct vki_stat64) );
}


POST(sys_lstat64)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_stat64) );
}

PRE(sys_lstat64)
{
   PRINT("sys_lstat64 ( %p(%s), %p )", ARG1, ARG1, ARG2);
   PRE_REG_READ2(long, "stat", const char *,path, struct stat64 *,buf);
   PRE_MEM_RASCIIZ("lstat64(path)", ARG1);
   PRE_MEM_WRITE( "lstat64(buf)", ARG2, sizeof(struct vki_stat64) );
}


POST(sys_fstat64)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_stat64) );
}

PRE(sys_fstat64)
{
   PRINT("sys_fstat64 ( %d, %p )", ARG1,ARG2);
   PRE_REG_READ2(long, "fstat", unsigned int, fd, struct stat64 *, buf);
   PRE_MEM_WRITE( "fstat64(buf)", ARG2, sizeof(struct vki_stat64) );
}


PRE(sys_getfsstat)
{
   PRINT("getfsstat(%p, %d, %d)", ARG1, ARG2, ARG3);
   PRE_REG_READ3(int, "getfsstat", struct vki_statfs *, buf, 
                 int, bufsize, int, flags);
   if (ARG1) {
      // ARG2 is a BYTE SIZE
      PRE_MEM_WRITE("getfsstat", ARG1, ARG2);
   }
}

POST(sys_getfsstat)
{
   if (ARG1) {
      // RES is a STRUCT COUNT
      POST_MEM_WRITE(ARG1, RES * sizeof(struct vki_statfs));
   }
}


static void scan_attrlist(ThreadId tid, struct vki_attrlist *attrList, 
                          void *attrBuf, SizeT attrBufSize, 
                          void (*fn)(ThreadId, void *attrData, SizeT size)
                          )
{
   typedef struct {
      uint32_t attrBit;
      int32_t attrSize;
   } attrspec;
   static const attrspec commonattr[] = {
      // This order is important.
      { ATTR_CMN_NAME,            -1 }, 
      { ATTR_CMN_DEVID,           sizeof(dev_t) }, 
      { ATTR_CMN_FSID,            sizeof(fsid_t) }, 
      { ATTR_CMN_OBJTYPE,         sizeof(fsobj_type_t) }, 
      { ATTR_CMN_OBJTAG,          sizeof(fsobj_tag_t) }, 
      { ATTR_CMN_OBJID,           sizeof(fsobj_id_t) }, 
      { ATTR_CMN_OBJPERMANENTID,  sizeof(fsobj_id_t) }, 
      { ATTR_CMN_PAROBJID,        sizeof(fsobj_id_t) }, 
      { ATTR_CMN_SCRIPT,          sizeof(text_encoding_t) }, 
      { ATTR_CMN_CRTIME,          sizeof(struct timespec) }, 
      { ATTR_CMN_MODTIME,         sizeof(struct timespec) }, 
      { ATTR_CMN_CHGTIME,         sizeof(struct timespec) }, 
      { ATTR_CMN_ACCTIME,         sizeof(struct timespec) }, 
      { ATTR_CMN_BKUPTIME,        sizeof(struct timespec) }, 
      { ATTR_CMN_FNDRINFO,        32 /*FileInfo+ExtendedFileInfo, or FolderInfo+ExtendedFolderInfo*/ }, 
      { ATTR_CMN_OWNERID,         sizeof(uid_t) }, 
      { ATTR_CMN_GRPID,           sizeof(gid_t) }, 
      { ATTR_CMN_ACCESSMASK,      sizeof(uint32_t) }, 
      { ATTR_CMN_NAMEDATTRCOUNT,  sizeof(uint32_t) }, 
      { ATTR_CMN_NAMEDATTRLIST,   -1 }, 
      { ATTR_CMN_FLAGS,           sizeof(uint32_t) }, 
      { ATTR_CMN_USERACCESS,      sizeof(uint32_t) }, 
      { ATTR_CMN_FILEID,          sizeof(uint64_t) }, 
      { ATTR_CMN_PARENTID,        sizeof(uint64_t) }, 
      { 0,                        0 }
   };
   static const attrspec volattr[] = {
      // This order is important.
      { ATTR_VOL_INFO,            0 }, 
      { ATTR_VOL_FSTYPE,          sizeof(uint32_t) }, 
      { ATTR_VOL_SIGNATURE,       sizeof(uint32_t) }, 
      { ATTR_VOL_SIZE,            sizeof(off_t) }, 
      { ATTR_VOL_SPACEFREE,       sizeof(off_t) }, 
      { ATTR_VOL_SPACEAVAIL,      sizeof(off_t) }, 
      { ATTR_VOL_MINALLOCATION,   sizeof(off_t) }, 
      { ATTR_VOL_ALLOCATIONCLUMP, sizeof(off_t) }, 
      { ATTR_VOL_IOBLOCKSIZE,     sizeof(uint32_t) }, 
      { ATTR_VOL_OBJCOUNT,        sizeof(uint32_t) }, 
      { ATTR_VOL_FILECOUNT,       sizeof(uint32_t) }, 
      { ATTR_VOL_DIRCOUNT,        sizeof(uint32_t) }, 
      { ATTR_VOL_MAXOBJCOUNT,     sizeof(uint32_t) }, 
      { ATTR_VOL_MOUNTPOINT,      -1 }, 
      { ATTR_VOL_NAME,            -1 }, 
      { ATTR_VOL_MOUNTFLAGS,      sizeof(uint32_t) }, 
      { ATTR_VOL_MOUNTEDDEVICE,   -1 }, 
      { ATTR_VOL_ENCODINGSUSED,   sizeof(uint64_t) }, 
      { ATTR_VOL_CAPABILITIES,    sizeof(vol_capabilities_attr_t) }, 
      { ATTR_VOL_ATTRIBUTES,      sizeof(vol_attributes_attr_t) }, 
      { 0,                        0 }
   };
   static const attrspec dirattr[] = {
      // This order is important.
      { ATTR_DIR_LINKCOUNT,       sizeof(uint32_t) }, 
      { ATTR_DIR_ENTRYCOUNT,      sizeof(uint32_t) }, 
      { ATTR_DIR_MOUNTSTATUS,     sizeof(uint32_t) }, 
      { 0,                        0 }
   };
   static const attrspec fileattr[] = {
      // This order is important.
      { ATTR_FILE_LINKCOUNT,      sizeof(uint32_t) }, 
      { ATTR_FILE_TOTALSIZE,      sizeof(off_t) }, 
      { ATTR_FILE_ALLOCSIZE,      sizeof(off_t) }, 
      { ATTR_FILE_IOBLOCKSIZE,    sizeof(uint32_t) }, 
      { ATTR_FILE_CLUMPSIZE,      sizeof(uint32_t) }, 
      { ATTR_FILE_DEVTYPE,        sizeof(uint32_t) }, 
      { ATTR_FILE_FILETYPE,       sizeof(uint32_t) }, 
      { ATTR_FILE_FORKCOUNT,      sizeof(uint32_t) }, 
      { ATTR_FILE_FORKLIST,       -1 }, 
      { ATTR_FILE_DATALENGTH,     sizeof(off_t) }, 
      { ATTR_FILE_DATAALLOCSIZE,  sizeof(off_t) }, 
      { ATTR_FILE_DATAEXTENTS,    sizeof(extentrecord) }, 
      { ATTR_FILE_RSRCLENGTH,     sizeof(off_t) }, 
      { ATTR_FILE_RSRCALLOCSIZE,  sizeof(off_t) }, 
      { ATTR_FILE_RSRCEXTENTS,    sizeof(extentrecord) }, 
      { 0,                        0 }
   };
   static const attrspec forkattr[] = {
      // This order is important.
      { ATTR_FORK_TOTALSIZE,      sizeof(off_t) }, 
      { ATTR_FORK_ALLOCSIZE,      sizeof(off_t) }, 
      { 0,                        0 }
   };

   static const attrspec *attrdefs[5] = { 
      commonattr, volattr, dirattr, fileattr, forkattr 
   };
   attrgroup_t a[5];
   uint8_t *d, *dend;
   int g, i;

   vg_assert(attrList->bitmapcount == 5);
   VG_(memcpy)(a, &attrList->commonattr, sizeof(a));
   d = attrBuf;
   dend = d + attrBufSize;

   for (g = 0; g < 5; g++) {
      for (i = 0; attrdefs[g][i].attrBit; i++) {
         uint32_t bit = attrdefs[g][i].attrBit;
         int32_t size = attrdefs[g][i].attrSize;

         if (a[g] & bit) {
             a[g] &= ~bit;  // clear bit for error check later
            if (size == -1) {
               attrreference_t *ref = (attrreference_t *)d;
               size = MIN(sizeof(attrreference_t), dend - d);
               fn(tid, d, size);
               if (size >= sizeof(attrreference_t)  &&  
                   d + ref->attr_dataoffset < dend) 
               {
                  fn(tid, d + ref->attr_dataoffset, 
                     MIN(ref->attr_length, dend - (d + ref->attr_dataoffset)));
               }
               d += size;
            } 
            else {
               size = MIN(size, dend - d);
               fn(tid, d, size);
               d += size;
            }
            
            if ((uintptr_t)d % 4) d += 4 - ((uintptr_t)d % 4);
            if (d > dend) d = dend;
         }
      }

      // Known bits are cleared. Die if any bits are left.
      if (a[g] != 0) {
         VG_(message)(Vg_UserMsg, "UNKNOWN attrlist flags %d:0x%x\n", g, a[g]);
      }
   }
}

static void get1attr(ThreadId tid, void *attrData, SizeT attrDataSize)
{
   POST_MEM_WRITE((Addr)attrData, attrDataSize);
}

static void set1attr(ThreadId tid, void *attrData, SizeT attrDataSize)
{
   PRE_MEM_READ("setattrlist(attrBuf value)", (Addr)attrData, attrDataSize);
}

PRE(sys_getattrlist)
{
   PRINT("getattrlist(%p(%s), %p, %p, %u, %u)", 
         ARG1, ARG1, ARG2, ARG3, ARG4, ARG5);
   PRE_REG_READ5(int, "getattrlist", 
                 const char *,path, struct vki_attrlist *,attrList, 
                 void *,attrBuf, vki_size_t,attrBufSize, unsigned int,options);
   PRE_MEM_RASCIIZ("getattrlist(path)", ARG1);
   PRE_MEM_READ("getattrlist(attrList)", ARG2, sizeof(struct vki_attrlist));
   PRE_MEM_WRITE("getattrlist(attrBuf)", ARG3, ARG4);
}

POST(sys_getattrlist) 
{
   if (ARG4 > sizeof(vki_uint32_t)) {
      // attrBuf is uint32_t bytes written followed by attr data
      vki_uint32_t *sizep = (vki_uint32_t *)ARG3;
      POST_MEM_WRITE(ARG3, sizeof(vki_uint32_t));
      scan_attrlist(tid, (struct vki_attrlist *)ARG2, sizep+1, *sizep, &get1attr);
   }
}


PRE(sys_setattrlist)
{
   PRINT("setattrlist(%p(%s), %p, %p, %u, %u)", 
         ARG1, ARG1, ARG2, ARG3, ARG4, ARG5);
   PRE_REG_READ5(int, "setattrlist", 
                 const char *,path, struct vki_attrlist *,attrList, 
                 void *,attrBuf, vki_size_t,attrBufSize, unsigned int,options);
   PRE_MEM_RASCIIZ("setattrlist(path)", ARG1);
   PRE_MEM_READ("setattrlist(attrList)", ARG2, sizeof(struct vki_attrlist));
   scan_attrlist(tid, (struct vki_attrlist *)ARG2, (void*)ARG3, ARG4, &set1attr);
}


PRE(sys_getdirentriesattr)
{
   PRINT("getdirentriesattr(%d, %p, %p, %d, %p, %p, %p, %d)", 
         ARG1, ARG2, ARG3, ARG4, ARG5, ARG6, ARG7, ARG8);
   PRE_REG_READ8(int, "getdirentriesattr", 
                 int,fd, struct vki_attrlist *,attrList, 
                 void *,attrBuf, size_t,attrBufSize, 
                 unsigned int *,count, unsigned int *,basep, 
                 unsigned int *,newState, unsigned int,options);
   PRE_MEM_READ("getdirentriesattr(attrList)", 
                ARG2, sizeof(struct vki_attrlist));
   PRE_MEM_WRITE("getdirentriesattr(attrBuf)", ARG3, ARG4);
   PRE_MEM_READ("getdirentriesattr(count)", ARG5, sizeof(unsigned int));
   PRE_MEM_WRITE("getdirentriesattr(count)", ARG5, sizeof(unsigned int));
   PRE_MEM_WRITE("getdirentriesattr(basep)", ARG6, sizeof(unsigned int));
   PRE_MEM_WRITE("getdirentriesattr(newState)", ARG7, sizeof(unsigned int));
}

POST(sys_getdirentriesattr) 
{
   char *p, *end;
   unsigned int count;
   unsigned int i;

   POST_MEM_WRITE(ARG5, sizeof(unsigned int));
   POST_MEM_WRITE(ARG6, sizeof(unsigned int));
   POST_MEM_WRITE(ARG7, sizeof(unsigned int));

   // return buffer is concatenation of variable-size structs
   count = *(unsigned int *)ARG5;
   p = (char *)ARG3;
   end = (char *)ARG3 + ARG4;
   for (i = 0; i < count; i++) {
      vg_assert(p < end);  // failure is kernel bug or Valgrind bug
      p += *(unsigned int *)p;
   }

   POST_MEM_WRITE(ARG3, p - (char *)ARG3);

   PRINT("got %d records, %lu/%lu bytes\n", count, p-(char *)ARG3, ARG4);
}


PRE(sys_fsctl)
{
   PRINT("fsctl ( %p(%s), %d, %p, %d )", ARG1, (char *)ARG1, ARG2, ARG3, ARG4);
   PRE_REG_READ4( long, "fsctl", 
                  char *,"path", unsigned int,"request", 
                  void *,"data", unsigned int,"options");
   
   PRE_MEM_RASCIIZ( "fsctl(path)", ARG1 );

   switch (ARG2) {
   case VKI_afpfsByteRangeLock2FSCTL: {
      struct vki_ByteRangeLockPB2 *pb = (struct vki_ByteRangeLockPB2 *)ARG3;
      PRE_FIELD_READ("fsctl(afpfsByteRangeLock2, pb->offset)", 
                     pb->offset);
      PRE_FIELD_READ("fsctl(afpfsByteRangeLock2, pb->length)", 
                     pb->length);
      PRE_FIELD_READ("fsctl(afpfsByteRangeLock2, pb->unLockFlag)", 
                     pb->unLockFlag);
      PRE_FIELD_READ("fsctl(afpfsByteRangeLock2, pb->startEndFlag)", 
                     pb->startEndFlag);
      PRE_FIELD_READ("fsctl(afpfsByteRangeLock2, pb->fd)", 
                     pb->fd);

      PRE_FIELD_WRITE("fsctl(afpfsByteRangeLock2, pb->retRangeStart)", 
                      pb->retRangeStart);

      // GrP fixme check fd
      break;
   }
   case VKI_FSIOC_SYNC_VOLUME:
       PRE_MEM_READ( "fsctl(FSIOC_SYNC_VOLUME)", ARG3, sizeof(int) );
       break;

   default:
      // fsctl requests use ioctl encoding
      ML_(PRE_unknown_ioctl)(tid, ARG2, ARG3);
      break;
   }
}

POST(sys_fsctl)
{
   switch (ARG2) {
   case VKI_afpfsByteRangeLock2FSCTL: {
      struct vki_ByteRangeLockPB2 *pb = (struct vki_ByteRangeLockPB2 *)ARG3;
      POST_FIELD_WRITE(pb->retRangeStart);
      break;
   }
   case VKI_FSIOC_SYNC_VOLUME:
       break;

   default:
      // fsctl requests use ioctl encoding
      ML_(POST_unknown_ioctl)(tid, RES, ARG2, ARG3);
      break;
   }
}

PRE(sys_initgroups)
{
    PRINT("sys_initgroups(%s, %p, %u)", ARG1, ARG2, ARG3);
    PRE_REG_READ3(long, "initgroups",
        int, setlen, vki_gid_t *, gidset, vki_uid_t, gmuid);
    PRE_MEM_READ("gidset", ARG2, ARG1 * sizeof(vki_gid_t));
}

PRE(sys_socket)
{
   PRINT("sys_socket ( %d, %d, %d )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "socket", int, domain, int, type, int, protocol);
}

POST(sys_socket)
{
   SysRes r;
   vg_assert(SUCCESS);
   r = ML_(generic_POST_sys_socket)(tid, VG_(mk_SysRes_Success)(RES));
   SET_STATUS_from_SysRes(r);
}


PRE(sys_setsockopt)
{
   PRINT("sys_setsockopt ( %d, %d, %d, %p, %d )",ARG1,ARG2,ARG3,ARG4,ARG5);
   PRE_REG_READ5(long, "setsockopt",
                 int, s, int, level, int, optname,
                 const void *, optval, int, optlen);
   ML_(generic_PRE_sys_setsockopt)(tid, ARG1,ARG2,ARG3,ARG4,ARG5);
}


PRE(sys_getsockopt)
{
   PRINT("sys_getsockopt ( %d, %d, %d, %p, %p )",ARG1,ARG2,ARG3,ARG4,ARG5);
   PRE_REG_READ5(long, "getsockopt",
                 int, s, int, level, int, optname,
                 void *, optval, int, *optlen);
   ML_(generic_PRE_sys_getsockopt)(tid, ARG1,ARG2,ARG3,ARG4,ARG5);
}

POST(sys_getsockopt)
{
   vg_assert(SUCCESS);
   ML_(generic_POST_sys_getsockopt)(tid, VG_(mk_SysRes_Success)(RES),
                                         ARG1,ARG2,ARG3,ARG4,ARG5);
}


PRE(sys_connect)
{
   *flags |= SfMayBlock;
   PRINT("sys_connect ( %d, %p, %d )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "connect",
                 int, sockfd, struct sockaddr *, serv_addr, int, addrlen);
   ML_(generic_PRE_sys_connect)(tid, ARG1,ARG2,ARG3);
}


PRE(sys_accept)
{
   *flags |= SfMayBlock;
   PRINT("sys_accept ( %d, %p, %d )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "accept",
                 int, s, struct sockaddr *, addr, int, *addrlen);
   ML_(generic_PRE_sys_accept)(tid, ARG1,ARG2,ARG3);
}

POST(sys_accept)
{
   SysRes r;
   vg_assert(SUCCESS);
   r = ML_(generic_POST_sys_accept)(tid, VG_(mk_SysRes_Success)(RES),
                                         ARG1,ARG2,ARG3);
   SET_STATUS_from_SysRes(r);
}


PRE(sys_sendto)
{
   *flags |= SfMayBlock;
   PRINT("sys_sendto ( %d, %s, %d, %u, %p, %d )",ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
   PRE_REG_READ6(long, "sendto",
                 int, s, const void *, msg, int, len, 
                 unsigned int, flags, 
                 const struct sockaddr *, to, int, tolen);
   ML_(generic_PRE_sys_sendto)(tid, ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}

PRE(sys_sendfile)
{
#if VG_WORDSIZE == 4
   PRINT("sys_sendfile(%d, %d, %d, %p, %p, %d)",
         ARG1, ARG2, LOHI64(ARG3, ARG4), ARG5, ARG6, ARG7);

   PRE_REG_READ7(long, "sendfile",
      int, fromfd, int, tofd,
      vki_uint32_t, offset_low32, vki_uint32_t, offset_high32,
      vki_uint64_t *, nwritten, struct sf_hdtr *, sf_header, int, flags);
   PRE_MEM_WRITE("sendfile(nwritten)", ARG5, sizeof(vki_uint64_t));
   if (ARG6) PRE_MEM_WRITE("sendfile(sf_header)", ARG6, sizeof(struct sf_hdtr));
#else
   PRINT("sys_sendfile(%d, %d, %d, %p, %p, %d)",
      ARG1, ARG2, ARG3, ARG4, ARG5, ARG6);

   PRE_REG_READ6(long, "sendfile",
      int, fromfd, int, tofd,
      vki_uint64_t, offset, 
      vki_uint64_t *, nwritten, struct sf_hdtr *, sf_header, int, flags);
   PRE_MEM_WRITE("sendfile(nwritten)", ARG4, sizeof(vki_uint64_t));
   if (ARG5) PRE_MEM_WRITE("sendfile(sf_header)", ARG5, sizeof(struct sf_hdtr));
#endif

   *flags |= SfMayBlock;
}

POST(sys_sendfile)
{
#if VG_WORDSIZE == 4
   POST_MEM_WRITE(ARG5, sizeof(vki_uint64_t));
   if (ARG6) POST_MEM_WRITE(ARG6, sizeof(struct sf_hdtr));
#else
   POST_MEM_WRITE(ARG4, sizeof(vki_uint64_t));
   if (ARG5) POST_MEM_WRITE(ARG5, sizeof(struct sf_hdtr));
#endif
}

PRE(sys_recvfrom)
{
   *flags |= SfMayBlock;
   PRINT("sys_recvfrom ( %d, %p, %d, %u, %p, %p )",ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
   PRE_REG_READ6(long, "recvfrom",
                 int, s, void *, buf, int, len, unsigned int, flags,
                 struct sockaddr *, from, int *, fromlen);
   ML_(generic_PRE_sys_recvfrom)(tid, ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}

POST(sys_recvfrom)
{
   vg_assert(SUCCESS);
   ML_(generic_POST_sys_recvfrom)(tid, VG_(mk_SysRes_Success)(RES),
                                       ARG1,ARG2,ARG3,ARG4,ARG5,ARG6);
}


PRE(sys_sendmsg)
{
   *flags |= SfMayBlock;
   PRINT("sys_sendmsg ( %d, %p, %d )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "sendmsg",
                 int, s, const struct msghdr *, msg, int, flags);
   ML_(generic_PRE_sys_sendmsg)(tid, ARG1,ARG2);
}


PRE(sys_recvmsg)
{
   *flags |= SfMayBlock;
   PRINT("sys_recvmsg ( %d, %p, %d )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "recvmsg", int, s, struct msghdr *, msg, int, flags);
   ML_(generic_PRE_sys_recvmsg)(tid, ARG1,ARG2);
}

POST(sys_recvmsg)
{
   ML_(generic_POST_sys_recvmsg)(tid, ARG1,ARG2);
}


PRE(sys_shutdown)
{
   *flags |= SfMayBlock;
   PRINT("sys_shutdown ( %d, %d )",ARG1,ARG2);
   PRE_REG_READ2(int, "shutdown", int, s, int, how);
}


PRE(sys_bind)
{
   PRINT("sys_bind ( %d, %p, %d )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "bind",
                 int, sockfd, struct sockaddr *, my_addr, int, addrlen);
   ML_(generic_PRE_sys_bind)(tid, ARG1,ARG2,ARG3);
}


PRE(sys_listen)
{
   PRINT("sys_listen ( %d, %d )",ARG1,ARG2);
   PRE_REG_READ2(long, "listen", int, s, int, backlog);
}


PRE(sys_getsockname)
{
   PRINT("sys_getsockname ( %d, %p, %p )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "getsockname",
                 int, s, struct sockaddr *, name, int *, namelen);
   ML_(generic_PRE_sys_getsockname)(tid, ARG1,ARG2,ARG3);
}

POST(sys_getsockname)
{
   vg_assert(SUCCESS);
   ML_(generic_POST_sys_getsockname)(tid, VG_(mk_SysRes_Success)(RES),
                                          ARG1,ARG2,ARG3);
}


PRE(sys_getpeername)
{
   PRINT("sys_getpeername ( %d, %p, %p )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "getpeername",
                 int, s, struct sockaddr *, name, int *, namelen);
   ML_(generic_PRE_sys_getpeername)(tid, ARG1,ARG2,ARG3);
}

POST(sys_getpeername)
{
   vg_assert(SUCCESS);
   ML_(generic_POST_sys_getpeername)(tid, VG_(mk_SysRes_Success)(RES),
                                          ARG1,ARG2,ARG3);
}


PRE(sys_socketpair)
{
   PRINT("sys_socketpair ( %d, %d, %d, %p )",ARG1,ARG2,ARG3,ARG4);
   PRE_REG_READ4(long, "socketpair",
                 int, d, int, type, int, protocol, int *, sv);
   ML_(generic_PRE_sys_socketpair)(tid, ARG1,ARG2,ARG3,ARG4);
}

POST(sys_socketpair)
{
   vg_assert(SUCCESS);
   ML_(generic_POST_sys_socketpair)(tid, VG_(mk_SysRes_Success)(RES),
                                         ARG1,ARG2,ARG3,ARG4);
}


PRE(sys_gethostuuid)
{
   PRINT("sys_gethostuuid ( %p, %p )", ARG1, ARG2);
   PRE_REG_READ2(int,"gethostuuid", 
                 char *,"uuid_buf", 
                 const struct vki_timespec *,"timeout");

   PRE_MEM_WRITE("uuid_buf", ARG1, 16);
   PRE_MEM_READ("timeout", ARG2, sizeof(struct vki_timespec));

   *flags |= SfMayBlock;
}


POST(sys_gethostuuid)
{
   POST_MEM_WRITE(ARG1, 16);
}

/* Darwin pipe() returns the two descriptors in two registers. */
PRE(sys_pipe)
{
   PRINT("sys_pipe ( )");
   PRE_REG_READ0(int, "pipe");
}

POST(sys_pipe)
{
   Int p0, p1;
   vg_assert(SUCCESS);
   // not RES because we need the doubleword result
   p0 = status->sres.res;
   p1 = status->sres.res2;

   if (!ML_(fd_allowed)(p0, "pipe", tid, True) ||
       !ML_(fd_allowed)(p1, "pipe", tid, True)) {
      VG_(close)(p0);
      VG_(close)(p1);
      SET_STATUS_Failure( VKI_EMFILE );
   } else {
      if (VG_(clo_track_fds)) {
         ML_(record_fd_open_nameless)(tid, p0);
         ML_(record_fd_open_nameless)(tid, p1);
      }
   }
}


PRE(sys_getlogin)
{
   PRINT("getlogin ( %p, %d )", ARG1, ARG2);
   PRE_REG_READ2(long, "getlogin", 
                 char *,"namebuf", unsigned int,"namelen");

   PRE_MEM_WRITE("getlogin(namebuf)", ARG1, ARG2);
}

POST(sys_getlogin)
{
   POST_MEM_WRITE(ARG1, ARG2);
}


PRE(sys_ptrace)
{
   PRINT("ptrace ( %d, %d, %p, %d )", ARG1, ARG2, ARG3, ARG4);
   PRE_REG_READ4(long, "ptrace", 
                 int,"request", vki_pid_t,"pid", 
                 vki_caddr_t,"addr", int,"data");
    
   // Note: some code uses ptrace(random, 0, 0, 0) as a profiling mechanism. 

   // GrP fixme anything needed?
}


PRE(sys_issetugid)
{
   PRINT("issetugid ( )");
   PRE_REG_READ0(long, "issetugid");
}


PRE(sys_getdtablesize)
{
   PRINT("getdtablesize ( )");
   PRE_REG_READ0(long, "getdtablesize");
}

POST(sys_getdtablesize)
{
   // Subtract Valgrind's fd range from client's dtable
   if (RES > VG_(fd_hard_limit)) SET_STATUS_Success(VG_(fd_hard_limit));
}

PRE(sys_lseek)
{
   PRINT("lseek ( %d, %lld, %d )", ARG1,ARG2,ARG3);
   PRE_REG_READ4(vki_off_t, "lseek",
                 unsigned int,fd, int,offset_hi, int,offset_lo, 
                 unsigned int,whence);
}


PRE(sys_pathconf)
{
   PRINT("pathconf(%p(%s), %d)", ARG1,(char *)ARG1,ARG2);
   PRE_REG_READ2(long,"pathconf", const char *,"path", int,"name");
   PRE_MEM_RASCIIZ("pathconf(path)", ARG1);

   if (!ML_(fd_allowed)(ARG1, "pathconf", tid, False))
      SET_STATUS_Failure( VKI_EBADF );
}


PRE(sys_fpathconf)
{
   PRINT("fpathconf(%d, %d)", ARG1,ARG2);
   PRE_REG_READ2(long,"fpathconf", int,"fd", int,"name");

   if (!ML_(fd_allowed)(ARG1, "fpathconf", tid, False))
      SET_STATUS_Failure( VKI_EBADF );
}


PRE(sys_getdirentries)
{
   PRINT("getdirentries(%d, %p, %d, %p)", ARG1, ARG2, ARG3, ARG4);
   PRE_REG_READ4(int, "getdirentries", 
                 int, fd, char *, buf, int, nbytes, long *, basep);
   PRE_MEM_WRITE("getdirentries(basep)", ARG4, sizeof(long));
   PRE_MEM_WRITE("getdirentries(buf)", ARG2, ARG3);
}

POST(sys_getdirentries) 
{
   POST_MEM_WRITE(ARG4, sizeof(long));
   // GrP fixme be specific about d_name?
   POST_MEM_WRITE(ARG2, RES);
}


PRE(sys_getdirentries64)
{
   PRINT("getdirentries64(%d, %p, %u, %p)", ARG1, ARG2, ARG3, ARG4);
   PRE_REG_READ4(vki_ssize_t, "getdirentries", 
                 int,fd, char *,buf, vki_size_t,nbytes, vki_off_t *,basep);
   PRE_MEM_WRITE("getdirentries(position)", ARG4, sizeof(vki_off_t));
   PRE_MEM_WRITE("getdirentries(buf)", ARG2, ARG3);
}

POST(sys_getdirentries64) 
{
   POST_MEM_WRITE(ARG4, sizeof(vki_off_t));
   // GrP fixme be specific about d_name? (fixme copied from 32 bit version)
   POST_MEM_WRITE(ARG2, RES);
}


PRE(sys_statfs64)
{
   PRINT("sys_statfs64 ( %p(%s), %p )",ARG1,ARG1,ARG2);
   PRE_REG_READ2(long, "statfs64", const char *, path, struct statfs64 *, buf);
   PRE_MEM_RASCIIZ( "statfs64(path)", ARG1 );
   PRE_MEM_WRITE( "statfs64(buf)", ARG2, sizeof(struct vki_statfs64) );
}

POST(sys_statfs64)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_statfs64) );
}


PRE(sys_fstatfs64)
{
   PRINT("sys_fstatfs64 ( %d, %p )",ARG1,ARG2);
   PRE_REG_READ2(long, "fstatfs64",
                 unsigned int, fd, struct statfs *, buf);
   PRE_MEM_WRITE( "fstatfs64(buf)", ARG2, sizeof(struct vki_statfs64) );
}

POST(sys_fstatfs64)
{
   POST_MEM_WRITE( ARG2, sizeof(struct vki_statfs64) );
}


PRE(sys_auditon)
{
   PRINT("sys_auditon ( %d, %p, %d )", ARG1, ARG2, ARG3);
   PRE_REG_READ3(int,"auditon", 
                 int,"cmd", void*,"data", unsigned int,"length");

   switch (ARG1) {

   case VKI_A_SETPOLICY: 
   case VKI_A_SETKMASK:
   case VKI_A_SETQCTRL:
   case VKI_A_SETCOND:
   case VKI_A_SETCLASS:
   case VKI_A_SETPMASK:
   case VKI_A_SETFSIZE:
      // kernel reads data..data+length
      PRE_MEM_READ("auditon(data)", ARG2, ARG3);
      break;

   case VKI_A_GETKMASK:
   case VKI_A_GETPOLICY:
   case VKI_A_GETQCTRL:
   case VKI_A_GETFSIZE:
   case VKI_A_GETCOND:
      // kernel writes data..data+length
      // fixme be precise about what gets written
      PRE_MEM_WRITE("auditon(data)", ARG2, ARG3);
      break;


   case VKI_A_GETCLASS:
   case VKI_A_GETPINFO:
   case VKI_A_GETPINFO_ADDR:
      // kernel reads and writes data..data+length
      // fixme be precise about what gets read and written
      PRE_MEM_READ("auditon(data)", ARG2, ARG3);
      PRE_MEM_WRITE("auditon(data)", ARG2, ARG3);
      break;

   case VKI_A_SETKAUDIT:
   case VKI_A_SETSTAT:
   case VKI_A_SETUMASK:
   case VKI_A_SETSMASK:
   case VKI_A_GETKAUDIT:
   case VKI_A_GETCWD:
   case VKI_A_GETCAR:
   case VKI_A_GETSTAT:
      // unimplemented on darwin
      break;

   default:
      VG_(message)(Vg_UserMsg, "UNKNOWN auditon cmd %d", ARG1);
      break;
   }
}

POST(sys_auditon)
{
   switch (ARG1) {

   case VKI_A_SETPOLICY: 
   case VKI_A_SETKMASK:
   case VKI_A_SETQCTRL:
   case VKI_A_SETCOND:
   case VKI_A_SETCLASS:
   case VKI_A_SETPMASK:
   case VKI_A_SETFSIZE:
      // kernel reads data..data+length
      break;

   case VKI_A_GETKMASK:
   case VKI_A_GETPOLICY:
   case VKI_A_GETQCTRL:
   case VKI_A_GETFSIZE:
   case VKI_A_GETCOND:
      // kernel writes data..data+length
      // fixme be precise about what gets written
      POST_MEM_WRITE(ARG2, ARG3);
      break;


   case VKI_A_GETCLASS:
   case VKI_A_GETPINFO:
   case VKI_A_GETPINFO_ADDR:
      // kernel reads and writes data..data+length
      // fixme be precise about what gets read and written
      POST_MEM_WRITE(ARG2, ARG3);
      break;

   case VKI_A_SETKAUDIT:
   case VKI_A_SETSTAT:
   case VKI_A_SETUMASK:
   case VKI_A_SETSMASK:
   case VKI_A_GETKAUDIT:
   case VKI_A_GETCWD:
   case VKI_A_GETCAR:
   case VKI_A_GETSTAT:
      // unimplemented on darwin
      break;

   default:
      break;
   }    
}


PRE(sys_mmap)
{
   // SysRes r;

#if VG_WORDSIZE == 4
   PRINT("sys_mmap ( %p, %u, %d, %d, %d, %lld )",
         ARG1, ARG2, ARG3, ARG4, ARG5, LOHI64(ARG6, ARG7) );
   PRE_REG_READ7(Addr, "mmap",
                 Addr,start, vki_size_t,length, int,prot, int,flags, int,fd, 
                 unsigned long,offset_hi, unsigned long,offset_lo);
   // GrP fixme V mmap and kernel mach_msg collided once - don't use 
   // V's mechanism for now
   // r = ML_(generic_PRE_sys_mmap)( tid, ARG1, ARG2, ARG3, ARG4, ARG5, 
   // (Off64T)LOHI64(ARG6, ARG7) );
#else
   PRINT("sys_mmap ( %p, %u, %d, %d, %d, %d )",
         ARG1, ARG2, ARG3, ARG4, ARG5, ARG6 );
   PRE_REG_READ6(long, "mmap",
                 Addr,start, vki_size_t,length, int,prot, int,flags, int,fd, 
                 Off64T,offset);
   // r = ML_(generic_PRE_sys_mmap)( tid, ARG1, ARG2, ARG3, ARG4, ARG5, ARG6 );

#endif

   // SET_STATUS_from_SysRes(r);
}

POST(sys_mmap)
{
   if (RES != -1) {
      ML_(notify_aspacem_and_tool_of_mmap)
          (RES, ARG2, ARG3, ARG4, ARG5, ARG6);
      // Try to load symbols from the region
      VG_(di_notify_mmap)( (Addr)RES, False/*allow_SkFileV*/ );
   }
}


PRE(sys_sysctl)
{
   PRINT( "sysctl ( %p, %d, %p, %p, %p, %d )", 
          ARG1, ARG2, ARG3, ARG4, ARG5, ARG6 );

   PRE_REG_READ6(int, "sysctl", int*, name, unsigned int, namelen, 
                 void*, oldp, vki_size_t *, oldlenp, 
                 void*, newp, vki_size_t *, newlenp);

   PRE_MEM_READ("sysctl(name)", ARG1, ARG2);  // reads name[0..namelen-1]
   if (ARG4) {
      // writes *ARG4
      PRE_MEM_WRITE("sysctl(oldlenp)", ARG4, sizeof(size_t));
      if (ARG3) {
         // also reads *ARG4, and writes as much as ARG3[0..ARG4-1]
         PRE_MEM_READ("sysctl(oldlenp)", ARG4, sizeof(size_t));
         PRE_MEM_WRITE("sysctl(oldp)", ARG3, *(size_t *)ARG4);
      }
   }
   if (ARG5) {
      PRE_MEM_READ("sysctl(newp)", ARG5, ARG6);
   }

   if (VG_(clo_trace_syscalls)) {
      unsigned int i;
      int *name = (int *)ARG1;
      VG_(printf)(" mib: [ ");
      for (i = 0; i < ARG2; i++) {
         VG_(printf)("%d ", name[i]);
      }
      VG_(printf)("]");
   }

   // fixme intercept KERN_PROCARGS and KERN_PROC_PID for our pid
   // (executable path and arguments and environment

   {
      // Intercept sysctl(kern.usrstack). The kernel's reply would be
      // Valgrind's stack, not the client's stack.
      // GrP fixme kern_usrstack64
      if (ARG1  &&  ARG2 == 2  &&  
          ((int *)ARG1)[0] == VKI_CTL_KERN  &&  
#if VG_WORDSIZE == 4
          ((int *)ARG1)[1] == VKI_KERN_USRSTACK32
#else
          ((int *)ARG1)[1] == VKI_KERN_USRSTACK64
#endif
          )
      {
         if (ARG5/*newp*/  ||  ARG6/*newlen*/) {
            SET_STATUS_Failure(VKI_EPERM); // USRSTACK is read-only
         } else {
            Addr *oldp = (Addr *)ARG3;
            size_t *oldlenp = (size_t *)ARG4;
            if (oldlenp) {
               Addr stack_end = VG_(clstk_end)+1;
               size_t oldlen = *oldlenp;
               // always return actual size
               *oldlenp = sizeof(Addr);
               if (oldp  &&  oldlen >= sizeof(Addr)) {
                  // oldp is big enough
                  // copy value and return 0
                  *oldp = stack_end;
                  SET_STATUS_Success(0);
               } else {
                  // oldp isn't big enough
                  // copy as much as possible and return ENOMEM
                  if (oldp) VG_(memcpy)(oldp, &stack_end, oldlen);
                  SET_STATUS_Failure(VKI_ENOMEM);
               }
            }
         }
      }
   }

   if (!SUCCESS  &&  !FAILURE) {
      // Don't set SfPostOnFail if we've already handled it locally.
      *flags |= SfPostOnFail;
   }
}

POST(sys_sysctl)
{
   if (SUCCESS  ||  ERR == VKI_ENOMEM) {
      // sysctl can write truncated data and return VKI_ENOMEM
      if (ARG4) {
         POST_MEM_WRITE(ARG4, sizeof(size_t));
      }
      if (ARG3  &&  ARG4) {
         POST_MEM_WRITE(ARG3, *(size_t *)ARG4);
      }
   }
}


PRE(sys_sigpending)
{
   PRINT( "sys_sigpending ( %p )", ARG1 );
   PRE_REG_READ1(long, "sigpending", vki_sigset_t *, set);
   PRE_MEM_WRITE( "sigpending(set)", ARG1, sizeof(vki_sigset_t));
}

POST(sys_sigpending)
{
   POST_MEM_WRITE( ARG1, sizeof(vki_sigset_t) ) ;
}

PRE(sys_sigprocmask)
{
   vki_sigset_t* set;
   vki_sigset_t* oldset;

   PRINT("sys_sigprocmask ( %d, %p, %p )",ARG1,ARG2,ARG3);
   PRE_REG_READ3(long, "sigprocmask", 
                 int, how, vki_sigset_t *, set, vki_sigset_t *, oldset);
   if (ARG2 != 0)
      PRE_MEM_READ( "sigprocmask(set)", ARG2, sizeof(vki_sigset_t));
   if (ARG3 != 0)
      PRE_MEM_WRITE( "sigprocmask(oldset)", ARG3, sizeof(vki_sigset_t));

   set    = (vki_sigset_t*)ARG2;
   oldset = (vki_sigset_t*)ARG3;

#if defined(VGO_darwin)
#warning GrP fixme signals
#else
   SET_STATUS_from_SysRes(
      VG_(do_sys_sigprocmask) ( tid, ARG1 /*how*/, set, oldset)
   );
#endif

   if (SUCCESS)
      *flags |= SfPollAfter;
}

POST(sys_sigprocmask)
{
   vg_assert(SUCCESS);
   if (RES == 0 && ARG3 != 0)
      POST_MEM_WRITE( ARG3, sizeof(vki_sigset_t));
}


PRE(sys_sigaltstack)
{
   PRINT("sigaltstack ( %p, %p )",ARG1,ARG2);
   PRE_REG_READ2(int, "sigaltstack",
                 const vki_stack_t *, ss, vki_stack_t *, oss);
   if (ARG1 != 0) {
      const vki_stack_t *ss = (vki_stack_t *)ARG1;
      PRE_MEM_READ( "sigaltstack(ss)", (Addr)&ss->ss_sp, sizeof(ss->ss_sp) );
      PRE_MEM_READ( "sigaltstack(ss)", (Addr)&ss->ss_flags, sizeof(ss->ss_flags) );
      PRE_MEM_READ( "sigaltstack(ss)", (Addr)&ss->ss_size, sizeof(ss->ss_size) );
   }
   if (ARG2 != 0) {
      PRE_MEM_WRITE( "sigaltstack(oss)", ARG2, sizeof(vki_stack_t) );
   }

# warning GrP fixme signals
   // GrP fixme leopard 9A241 setjmp dies if sigaltstack fails (ecx)
   SET_STATUS_Success(0);
}


/* ---------------------------------------------------------------------
   mach_msg: formatted messages
   ------------------------------------------------------------------ */

static size_t desc_size(mach_msg_descriptor_t *desc)
{
   switch (desc->type.type) {
   case MACH_MSG_PORT_DESCRIPTOR:          return sizeof(desc->port);
   case MACH_MSG_OOL_DESCRIPTOR:           return sizeof(desc->out_of_line);
   case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:  return sizeof(desc->out_of_line);
   case MACH_MSG_OOL_PORTS_DESCRIPTOR:     return sizeof(desc->ool_ports);
   default: 
      VG_(printf)("UNKNOWN mach message descriptor %d\n", desc->type.type);
      return sizeof(desc->type); // guess
   }
}


static void assign_port_names(mach_msg_ool_ports_descriptor_t *desc, 
                              const char *name)
{
   mach_msg_size_t i;
   mach_port_t *ports = (mach_port_t *)desc->address;
   for (i = 0; i < desc->count; i++) {
      assign_port_name(ports[i], name);
   }
}


static void import_complex_message(ThreadId tid, mach_msg_header_t *mh)
{
   mach_msg_body_t *body;
   mach_msg_size_t count, i;
   uint8_t *p;
   mach_msg_descriptor_t *desc;
   
   vg_assert(mh->msgh_bits & MACH_MSGH_BITS_COMPLEX);
   
   body = (mach_msg_body_t *)(mh+1);
   count = body->msgh_descriptor_count;
   p = (uint8_t *)(body+1);
   
   for (i = 0; i < count; i++) {
      desc = (mach_msg_descriptor_t *)p;
      p += desc_size(desc);
      
      switch (desc->type.type) {
      case MACH_MSG_PORT_DESCRIPTOR:
         // single port
         record_unnamed_port(tid, desc->port.name, -1);
         record_port_insert_rights(desc->port.name, desc->port.disposition);
         PRINT("got port %s; ", name_for_port(desc->port.name));
         break;

      case MACH_MSG_OOL_DESCRIPTOR:
      case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
         // out-of-line memory - map it
         // GrP fixme how is VOLATILE different? do we care?
         // GrP fixme do other flags tell us anything? assume shared for now
         // GrP fixme more SF_ flags marking mach_msg memory might be nice
         // GrP fixme protection
         if (desc->out_of_line.size > 0) {
            Addr start = VG_PGROUNDDN((Addr)desc->out_of_line.address);
            Addr end = VG_PGROUNDUP((Addr)desc->out_of_line.address + 
                                    (Addr)desc->out_of_line.size);
            PRINT("got ool mem %p..%p; ", desc->out_of_line.address, 
                  (Addr)desc->out_of_line.address+desc->out_of_line.size);

            ML_(notify_aspacem_and_tool_of_mmap)
               (start, end - start, VKI_PROT_READ|VKI_PROT_WRITE, 
                VKI_MAP_PRIVATE, -1, 0);
         }
         // GrP fixme mark only un-rounded part as initialized 
         break;

      case MACH_MSG_OOL_PORTS_DESCRIPTOR:
         // out-of-line array of ports - map it
         // GrP fixme see fixmes above
         PRINT("got %d ool ports %p..%p", desc->ool_ports.count, desc->ool_ports.address, (Addr)desc->ool_ports.address+desc->ool_ports.count*sizeof(mach_port_t));

         if (desc->ool_ports.count > 0) {
            Addr start = VG_PGROUNDDN((Addr)desc->ool_ports.address);
            Addr end = VG_PGROUNDUP((Addr)desc->ool_ports.address + desc->ool_ports.count * sizeof(mach_port_t));
            mach_port_t *ports = (mach_port_t *)desc->ool_ports.address;

            ML_(notify_aspacem_and_tool_of_mmap)
               (start, end - start, VKI_PROT_READ|VKI_PROT_WRITE, 
                VKI_MAP_PRIVATE, -1, 0);

            PRINT(":");
            for (i = 0; i < desc->ool_ports.count; i++) {
               record_unnamed_port(tid, ports[i], -1);
               record_port_insert_rights(ports[i], desc->port.disposition);
               PRINT(" %s", name_for_port(ports[i]));
            }
         }
         PRINT(";");
         break;

      default:
         VG_(printf)("UNKNOWN Mach descriptor type %d!\n", desc->type);
         break;
      }
   }
}


static void pre_port_desc_read(ThreadId tid, mach_msg_port_descriptor_t *desc2)
{
#pragma pack(4)
   struct {
      mach_port_t name;
      mach_msg_size_t pad1;
      uint16_t pad2;
      uint8_t disposition;
      uint8_t type;
   } *desc = (void*)desc2;
#pragma pack()

   PRE_FIELD_READ("msg->desc.port.name",        desc->name);
   PRE_FIELD_READ("msg->desc.port.disposition", desc->disposition);
   PRE_FIELD_READ("msg->desc.port.type",        desc->type);
}


static void pre_ool_desc_read(ThreadId tid, mach_msg_ool_descriptor_t *desc2)
{
#pragma pack(4)
   struct {
      Addr address;
#if VG_WORDSIZE != 8
      mach_msg_size_t size;
#endif
      uint8_t deallocate;
      uint8_t copy;
      uint8_t pad1;
      uint8_t type;
#if VG_WORDSIZE == 8
      mach_msg_size_t size;
#endif
   } *desc = (void*)desc2;
#pragma pack()

   PRE_FIELD_READ("msg->desc.out_of_line.address",    desc->address);
   PRE_FIELD_READ("msg->desc.out_of_line.size",       desc->size);
   PRE_FIELD_READ("msg->desc.out_of_line.deallocate", desc->deallocate);
   PRE_FIELD_READ("msg->desc.out_of_line.copy",       desc->copy);
   PRE_FIELD_READ("msg->desc.out_of_line.type",       desc->type);
}

static void pre_oolports_desc_read(ThreadId tid, 
                                   mach_msg_ool_ports_descriptor_t *desc2)
{
#pragma pack(4)
   struct {
      Addr address;
#if VG_WORDSIZE != 8
      mach_msg_size_t size;
#endif
      uint8_t deallocate;
      uint8_t copy;
      uint8_t disposition;
      uint8_t type;
#if VG_WORDSIZE == 8
      mach_msg_size_t size;
#endif
   } *desc = (void*)desc2;
#pragma pack()

   PRE_FIELD_READ("msg->desc.ool_ports.address",     desc->address);
   PRE_FIELD_READ("msg->desc.ool_ports.size",        desc->size);
   PRE_FIELD_READ("msg->desc.ool_ports.deallocate",  desc->deallocate);
   PRE_FIELD_READ("msg->desc.ool_ports.copy",        desc->copy);
   PRE_FIELD_READ("msg->desc.ool_ports.disposition", desc->disposition);
   PRE_FIELD_READ("msg->desc.ool_ports.type",        desc->type);
}


// Returns the size of the descriptor area
// (mach_msg_body_t + any mach_msg_descriptor_t)
static size_t export_complex_message(ThreadId tid, mach_msg_header_t *mh)
{
   mach_msg_body_t *body;
   mach_msg_size_t count, i;
   uint8_t *p;
   mach_msg_descriptor_t *desc;
   
   vg_assert(mh->msgh_bits & MACH_MSGH_BITS_COMPLEX);
   
   body = (mach_msg_body_t *)(mh+1);
   PRE_MEM_READ("msg->msgh_descriptor_count)", (Addr)body, sizeof(*body));

   count = body->msgh_descriptor_count;
   p = (uint8_t *)(body+1);
   
   for (i = 0; i < count; i++) {
      desc = (mach_msg_descriptor_t *)p;
      p += desc_size(desc);
      
      switch (desc->type.type) {
      case MACH_MSG_PORT_DESCRIPTOR:
         // single port; no memory map effects
         pre_port_desc_read(tid, &desc->port);
         break;

      case MACH_MSG_OOL_DESCRIPTOR:
      case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
         // out-of-line memory - unmap it if it's marked dealloc
         // GrP fixme need to remap if message fails?
         // GrP fixme how is VOLATILE different? do we care?
         // GrP fixme struct is different for lp64
         pre_ool_desc_read(tid, &desc->out_of_line);

         if (desc->out_of_line.deallocate  &&  desc->out_of_line.size > 0) {
            vm_size_t size = desc->out_of_line.size;
            Addr start = VG_PGROUNDDN((Addr)desc->out_of_line.address);
            Addr end = VG_PGROUNDUP((Addr)desc->out_of_line.address + size);
            PRINT("kill ool mem %p..%p; ", desc->out_of_line.address, 
                  (Addr)desc->out_of_line.address + size);
            ML_(notify_aspacem_and_tool_of_munmap)(start, end - start);
         }
         break;

      case MACH_MSG_OOL_PORTS_DESCRIPTOR:
         // out-of-line array of ports - unmap it if it's marked dealloc
         // GrP fixme need to remap if message fails?
         // GrP fixme struct different for lp64
         pre_oolports_desc_read(tid, &desc->ool_ports);

         if (desc->ool_ports.deallocate  &&  desc->ool_ports.count > 0) {
            vm_size_t size = desc->ool_ports.count * sizeof(mach_port_t);
            Addr start = VG_PGROUNDDN((Addr)desc->ool_ports.address);
            Addr end = VG_PGROUNDUP((Addr)desc->ool_ports.address + size);
            PRINT("kill ool port array %p..%p; ", desc->ool_ports.address, 
                  (Addr)desc->ool_ports.address + size);
            ML_(notify_aspacem_and_tool_of_munmap)(start, end - start);
         }
         break;
      default:
         VG_(printf)("UNKNOWN Mach descriptor type %d!\n", desc->type);
         break;
      }
   }

   return (size_t)((Addr)p - (Addr)body);
}


/* ---------------------------------------------------------------------
   mach_msg: host-related messages
   ------------------------------------------------------------------ */


POST(host_info)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      mach_msg_type_number_t host_info_outCnt;
      integer_t host_info_out[14];
   } Reply;
#pragma pack()

   Reply *reply = (Reply *)ARG1;

   if (reply->RetCode) PRINT("mig return %d", reply->RetCode);
}

PRE(host_info)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      host_flavor_t flavor;
      mach_msg_type_number_t host_info_outCnt;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("host_info(mach_host_self(), flavor %d)", req->flavor);

   AFTER = POST_FN(host_info);
}


POST(host_page_size)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      vm_size_t out_page_size;
   } Reply;
#pragma pack()

   Reply *reply = (Reply *)ARG1;

   if (!reply->RetCode) {
      PRINT("page size %p", reply->out_page_size);
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}

PRE(host_page_size)
{
   PRINT("host_page_size(mach_host_self(), ...)");
    
   AFTER = POST_FN(host_page_size);
}


POST(host_get_io_master)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      /* start of the kernel processed data */
      mach_msg_body_t msgh_body;
      mach_msg_port_descriptor_t io_master;
      /* end of the kernel processed data */
   } Reply;
#pragma pack()

   Reply *reply = (Reply *)ARG1;

   assign_port_name(reply->io_master.name, "io_master-%p");
   PRINT("%s", name_for_port(reply->io_master.name));
}

PRE(host_get_io_master)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
   } Request;
#pragma pack()

   // Request *req = (Request *)ARG1;

   PRINT("host_get_io_master(mach_host_self())");

   AFTER = POST_FN(host_get_io_master);
}


POST(host_get_clock_service)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      /* start of the kernel processed data */
      mach_msg_body_t msgh_body;
      mach_msg_port_descriptor_t clock_serv;
      /* end of the kernel processed data */
   } Reply;
#pragma pack()

   Reply *reply = (Reply *)ARG1;

   assign_port_name(reply->clock_serv.name, "clock-%p");
   PRINT("%s", name_for_port(reply->clock_serv.name));
}

PRE(host_get_clock_service)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      clock_id_t clock_id;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("host_get_clock_service(mach_host_self(), %d)", req->clock_id);

   AFTER = POST_FN(host_get_clock_service);
}


PRE(host_request_notification)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      /* start of the kernel processed data */
      mach_msg_body_t msgh_body;
      mach_msg_port_descriptor_t notify_port;
      /* end of the kernel processed data */
      NDR_record_t NDR;
      host_flavor_t notify_type;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   if (MACH_REMOTE == mach_task_self()) { 
      if (req->notify_type == 0) {
         PRINT("host_request_notification(mach_host_self(), %s, %s)", 
               "HOST_NOTIFY_CALENDAR_CHANGE", 
               name_for_port(req->notify_port.name));
      } else {
         PRINT("host_request_notification(mach_host_self(), %d, %s)",
               req->notify_type, 
               name_for_port(req->notify_port.name));
      } 
   } else {
      PRINT("host_request_notification(%s, %d, %s)",
            name_for_port(MACH_REMOTE), 
            req->notify_type, 
            name_for_port(req->notify_port.name));
   }

    // fixme only do this on success
   assign_port_name(req->notify_port.name, "host_notify-%p");
}


/* ---------------------------------------------------------------------
   mach_msg: messages to a task
   ------------------------------------------------------------------ */


PRE(mach_port_type)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      mach_port_name_t name;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("mach_port_type(%s, %s, ...)", 
         name_for_port(MACH_REMOTE), name_for_port(req->name));

   AFTER = POST_FN(mach_port_type);
}

POST(mach_port_type)
{
}


PRE(mach_port_extract_member)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      mach_port_name_t name;
      mach_port_name_t pset;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("mach_port_extract_member(%s, 0x%x, 0x%x)", 
         name_for_port(MACH_REMOTE), 
         req->name, req->pset);

   AFTER = POST_FN(mach_port_extract_member);

   // GrP fixme port tracker?
}

POST(mach_port_extract_member)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
   } Reply;
#pragma pack()

   Reply *reply = (Reply *)ARG1;

   if (reply->RetCode) PRINT("mig return %d", reply->RetCode);
}


PRE(mach_port_allocate)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      mach_port_right_t right;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("mach_port_allocate(mach_task_self(), %d, ...)", req->right);

   MACH_ARG(mach_port_allocate.right) = req->right;

   AFTER = POST_FN(mach_port_allocate);
}

POST(mach_port_allocate)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      mach_port_name_t name;
   } Reply;
#pragma pack()

   Reply *reply = (Reply *)ARG1;

   if (!reply->RetCode) {
      if (MACH_REMOTE == vg_task_port) {
         // GrP fixme port tracking is too imprecise
         // vg_assert(!port_exists(reply->name));
         record_unnamed_port(tid, reply->name, MACH_ARG(mach_port_allocate.right));
         PRINT("got port 0x%x", reply->name);
      } else {
         VG_(printf)("UNKNOWN inserted port 0x%x into remote task\n", reply->name);
      }
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}


PRE(mach_port_deallocate)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      mach_port_name_t name;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("mach_port_deallocate(%s, %s)", 
         name_for_port(MACH_REMOTE), 
         name_for_port(req->name));

   MACH_ARG(mach_port.port) = req->name;

   AFTER = POST_FN(mach_port_deallocate);

   // Must block to prevent race (other thread allocates and 
   // notifies after we deallocate but before we notify)
   *flags &= ~SfMayBlock;
}

POST(mach_port_deallocate)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
   } Reply;
#pragma pack()
   
   Reply *reply = (Reply *)ARG1;

   if (!reply->RetCode) {
      if (MACH_REMOTE == vg_task_port) {
         // Must have cleared SfMayBlock in PRE to prevent race
         record_port_dealloc(MACH_ARG(mach_port.port));
      } else {
         VG_(printf)("UNKNOWN remote port dealloc\n");
      }
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}


PRE(mach_port_get_refs)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      mach_port_name_t name;
      mach_port_right_t right;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("mach_port_get_refs(%s, %s, 0x%x)", 
         name_for_port(MACH_REMOTE), 
         name_for_port(req->name), req->right);

   MACH_ARG(mach_port_mod_refs.port) = req->name;
   MACH_ARG(mach_port_mod_refs.right) = req->right;
    
   AFTER = POST_FN(mach_port_get_refs);
}

POST(mach_port_get_refs)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      mach_port_urefs_t refs;
   } Reply;
#pragma pack()
   
   Reply *reply = (Reply *)ARG1;

   if (!reply->RetCode) {
      PRINT("got refs=%d", reply->refs);
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}


PRE(mach_port_mod_refs)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      mach_port_name_t name;
      mach_port_right_t right;
      mach_port_delta_t delta;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("mach_port_mod_refs(%s, %s, 0x%x, 0x%x)", 
         name_for_port(MACH_REMOTE), 
         name_for_port(req->name), req->right, req->delta);

   MACH_ARG(mach_port_mod_refs.port) = req->name;
   MACH_ARG(mach_port_mod_refs.right) = req->right;
   MACH_ARG(mach_port_mod_refs.delta) = req->delta;
    
   AFTER = POST_FN(mach_port_mod_refs);

   // Must block to prevent race (other thread allocates and 
   // notifies after we deallocate but before we notify)
   *flags &= ~SfMayBlock;
}

POST(mach_port_mod_refs)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
   } Reply;
#pragma pack()
   
   Reply *reply = (Reply *)ARG1;

   if (!reply->RetCode) {
      if (MACH_REMOTE == vg_task_port) {
         // Must have cleared SfMayBlock in PRE to prevent race
         record_port_mod_refs(MACH_ARG(mach_port_mod_refs.port), 
                              MACH_PORT_TYPE(MACH_ARG(mach_port_mod_refs.right)), 
                              MACH_ARG(mach_port_mod_refs.delta));
      } else {
         VG_(printf)("UNKNOWN remote port mod refs\n");
      }
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}


PRE(mach_port_get_set_status)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      mach_port_name_t name;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("mach_port_get_set_status(%s, %s)", 
         name_for_port(MACH_REMOTE), 
         name_for_port(req->name));

   AFTER = POST_FN(mach_port_get_set_status);
}

POST(mach_port_get_set_status)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      /* start of the kernel processed data */
      mach_msg_body_t msgh_body;
      mach_msg_ool_descriptor_t members;
      /* end of the kernel processed data */
      NDR_record_t NDR;
      mach_msg_type_number_t membersCnt;
      mach_msg_trailer_t trailer;
   } Reply;
#pragma pack()

   // Reply *reply = (Reply *)ARG1;

   // GrP fixme nothing to do?
}


PRE(mach_port_destroy)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      mach_port_name_t name;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("mach_port_destroy(%s, %s)", 
         name_for_port(MACH_REMOTE), 
         name_for_port(req->name));

   MACH_ARG(mach_port.port) = req->name;

   AFTER = POST_FN(mach_port_destroy);

   // Must block to prevent race (other thread allocates and 
   // notifies after we deallocate but before we notify)
   *flags &= ~SfMayBlock;
}

POST(mach_port_destroy)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
   } Reply;
#pragma pack()
   
   Reply *reply = (Reply *)ARG1;

   if (!reply->RetCode) {
      if (MACH_REMOTE == vg_task_port) {
         // Must have cleared SfMayBlock in PRE to prevent race
         record_port_destroy(MACH_ARG(mach_port.port));
      } else {
         VG_(printf)("UNKNOWN remote port destroy\n");
      }
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}


PRE(mach_port_request_notification)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      /* start of the kernel processed data */
      mach_msg_body_t msgh_body;
      mach_msg_port_descriptor_t notify;
      /* end of the kernel processed data */
      NDR_record_t NDR;
      mach_port_name_t name;
      mach_msg_id_t msgid;
      mach_port_mscount_t sync;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("mach_port_request_notification(%s, %s, %d, %d, %d, %d, ...)", 
         name_for_port(MACH_REMOTE), 
         name_for_port(req->name), req->msgid, req->sync, 
         req->notify.name, req->notify.disposition);

   AFTER = POST_FN(mach_port_request_notification);
}

POST(mach_port_request_notification)
{
   // fixme port tracker? not sure
}


PRE(mach_port_insert_right)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      /* start of the kernel processed data */
      mach_msg_body_t msgh_body;
      mach_msg_port_descriptor_t poly;
      /* end of the kernel processed data */
      NDR_record_t NDR;
      mach_port_name_t name;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("mach_port_insert_right(%s, %s, %d, %d)", 
         name_for_port(MACH_REMOTE), 
         name_for_port(req->name), req->poly.name, req->poly.disposition);

   AFTER = POST_FN(mach_port_insert_right);

   if (MACH_REMOTE == mach_task_self()) {
      // fixme import_complex_message handles everything?
      // what about export_complex_message for MOVE variants?
   } else {
      VG_(printf)("UNKNOWN mach_port_insert_right into remote task!\n");
      // fixme also may remove rights from this task?
   }

   // fixme port tracker?
}

POST(mach_port_insert_right)
{
}


PRE(mach_port_get_attributes)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      mach_port_name_t name;
      mach_port_flavor_t flavor;
      mach_msg_type_number_t port_info_outCnt;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("mach_port_get_attributes(%s, %s, %d, ..., %d)", 
         name_for_port(MACH_REMOTE), 
         name_for_port(req->name), req->flavor, req->port_info_outCnt);

   AFTER = POST_FN(mach_port_get_attributes);
}

POST(mach_port_get_attributes)
{
}


PRE(mach_port_set_attributes)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      mach_port_name_t name;
      mach_port_flavor_t flavor;
      mach_msg_type_number_t port_infoCnt;
      integer_t port_info[10];
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("mach_port_set_attributes(%s, %s, %d, ..., %d)", 
        name_for_port(MACH_REMOTE), 
        name_for_port(req->name), req->flavor, req->port_infoCnt);

   AFTER = POST_FN(mach_port_set_attributes);
}

POST(mach_port_set_attributes)
{
}


PRE(mach_port_insert_member)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      mach_port_name_t name;
      mach_port_name_t pset;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("mach_port_insert_member(%s, 0x%x, 0x%x)", 
         name_for_port(MACH_REMOTE), req->name, req->pset);

   AFTER = POST_FN(mach_port_insert_member);

   // fixme port tracker?
}

POST(mach_port_insert_member)
{
}


PRE(task_get_special_port)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      int which_port;
   } Request;
#pragma pack()
   
   Request *req = (Request *)ARG1;
   
   switch (req->which_port) {
   case TASK_KERNEL_PORT:
      PRINT("task_get_special_port(%s, TASK_KERNEL_PORT)", 
            name_for_port(MACH_REMOTE));
      break;
   case TASK_HOST_PORT:
      PRINT("task_get_special_port(%s, TASK_HOST_PORT)", 
            name_for_port(MACH_REMOTE));
      break;
   case TASK_BOOTSTRAP_PORT:
      PRINT("task_get_special_port(%s, TASK_BOOTSTRAP_PORT)", 
            name_for_port(MACH_REMOTE));
      break;
   case TASK_WIRED_LEDGER_PORT:
      PRINT("task_get_special_port(%s, TASK_WIRED_LEDGER_PORT)", 
            name_for_port(MACH_REMOTE));
      break;
   case TASK_PAGED_LEDGER_PORT:
      PRINT("task_get_special_port(%s, TASK_PAGED_LEDGER_PORT)", 
            name_for_port(MACH_REMOTE));
      break;
   default:
      PRINT("task_get_special_port(%s, %d)", 
            name_for_port(MACH_REMOTE), req->which_port);
      break;
   }
   
   MACH_ARG(task_get_special_port.which_port) = req->which_port;
   
   AFTER = POST_FN(task_get_special_port);
}

POST(task_get_special_port)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      /* start of the kernel processed data */
      mach_msg_body_t msgh_body;
      mach_msg_port_descriptor_t special_port;
      /* end of the kernel processed data */
   } Reply;
#pragma pack()
   
   Reply *reply = (Reply *)ARG1;

   PRINT("got port %p ", reply->special_port.name);

   switch (MACH_ARG(task_get_special_port.which_port)) {
   case TASK_BOOTSTRAP_PORT:
      vg_bootstrap_port = reply->special_port.name;
      assign_port_name(reply->special_port.name, "bootstrap");
      break;
   case TASK_KERNEL_PORT:
      assign_port_name(reply->special_port.name, "kernel");
      break;
   case TASK_HOST_PORT:
      assign_port_name(reply->special_port.name, "host");
      break;
   case TASK_WIRED_LEDGER_PORT:
      assign_port_name(reply->special_port.name, "wired-ledger");
      break;
   case TASK_PAGED_LEDGER_PORT:
      assign_port_name(reply->special_port.name, "paged-ledger");
      break;
   default:
      assign_port_name(reply->special_port.name, "special-%p");
      break;
   }

   PRINT("%s", name_for_port(reply->special_port.name));
}


PRE(semaphore_create)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      int policy;
      int value;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("semaphore_create(%s, ..., %d, %d)",
         name_for_port(MACH_REMOTE), req->policy, req->value);

   AFTER = POST_FN(semaphore_create);
}

POST(semaphore_create)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      /* start of the kernel processed data */
      mach_msg_body_t msgh_body;
      mach_msg_port_descriptor_t semaphore;
      /* end of the kernel processed data */
      mach_msg_trailer_t trailer;
   } Reply;
#pragma pack()

   Reply *reply = (Reply *)ARG1;

   assign_port_name(reply->semaphore.name, "semaphore-%p");
   PRINT("%s", name_for_port(reply->semaphore.name));
}


PRE(semaphore_destroy)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      /* start of the kernel processed data */
      mach_msg_body_t msgh_body;
      mach_msg_port_descriptor_t semaphore;
      /* end of the kernel processed data */
      mach_msg_trailer_t trailer;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("semaphore_destroy(%s, %s)", 
         name_for_port(MACH_REMOTE), name_for_port(req->semaphore.name));

   record_port_destroy(req->semaphore.name);

   AFTER = POST_FN(semaphore_destroy);
}

POST(semaphore_destroy)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      mach_msg_trailer_t trailer;
   } Reply;
#pragma pack()

   Reply *reply = (Reply *)ARG1;        
   if (!reply->RetCode) {
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}


PRE(mach_ports_lookup)
{
#pragma pack(4)
   typedef struct {
       mach_msg_header_t Head;
   } Request;
#pragma pack()

   // Request *req = (Request *)ARG1;

   PRINT("mach_ports_lookup(%s)", name_for_port(MACH_REMOTE));

   AFTER = POST_FN(mach_ports_lookup);
}

POST(mach_ports_lookup)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      /* start of the kernel processed data */
      mach_msg_body_t msgh_body;
      mach_msg_ool_ports_descriptor_t init_port_set;
      /* end of the kernel processed data */
      NDR_record_t NDR;
      mach_msg_type_number_t init_port_setCnt;
   } Reply;
#pragma pack()

    // Reply *reply = (Reply *)ARG1;
}


PRE(task_threads)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
   } Request;
#pragma pack()

   // Request *req = (Request *)ARG1;

   PRINT("task_threads(%s)", name_for_port(MACH_REMOTE));

   AFTER = POST_FN(task_threads);
}

POST(task_threads)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      /* start of the kernel processed data */
      mach_msg_body_t msgh_body;
      mach_msg_ool_ports_descriptor_t act_list;
      /* end of the kernel processed data */
      NDR_record_t NDR;
      mach_msg_type_number_t act_listCnt;
      mach_msg_trailer_t trailer;
   } Reply;
#pragma pack()

   Reply *reply = (Reply *)ARG1;

   if (MACH_REMOTE == vg_task_port) {
      assign_port_names(&reply->act_list, "thread-%p");
   } else {
      assign_port_names(&reply->act_list, "remote-thread-%p");
   }
}


PRE(task_suspend)
{
   PRINT("task_suspend(%s)", name_for_port(MACH_REMOTE));

   if (MACH_REMOTE == vg_task_port) {
      // GrP fixme self-suspend
      vg_assert(0);
   } else {
      // suspend other - no problem
   }

   AFTER = POST_FN(task_suspend);
}

POST(task_suspend)
{
}


PRE(task_resume)
{
   PRINT("task_resume(%s)", name_for_port(MACH_REMOTE));

   if (MACH_REMOTE == vg_task_port) {
      // GrP fixme self-resume
      vg_assert(0);
   } else {
      // resume other - no problem
   }

   AFTER = POST_FN(task_resume);
}

POST(task_resume)
{
}


PRE(vm_allocate)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      vm_address_t address;
      vm_size_t size;
      int flags;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("vm_allocate (%s, at %p, size %d, flags 0x%x)", 
         name_for_port(MACH_REMOTE), 
         req->address, req->size, req->flags);

   MACH_ARG(vm_allocate.size) = req->size;
   MACH_ARG(vm_allocate.flags) = req->flags;

   AFTER = POST_FN(vm_allocate);
}

POST(vm_allocate)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      vm_address_t address;
      mach_msg_trailer_t trailer;
   } Reply;
#pragma pack()
   
   Reply *reply = (Reply *)ARG1;
   
   if (!reply->RetCode) {
      if (MACH_REMOTE == vg_task_port) {
         PRINT("allocated at %p", reply->address);
         // requesting 0 bytes returns address 0 with no error
         if (MACH_ARG(vm_allocate.size)) {
            ML_(notify_aspacem_and_tool_of_mmap)
                (reply->address, MACH_ARG(vm_allocate.size), 
                 VKI_PROT_READ|VKI_PROT_WRITE, VKI_MAP_ANON, -1, 0);
         }
      } else {
         PRINT("allocated at %p in remote task %s", reply->address, 
               name_for_port(MACH_REMOTE));
      }
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}


PRE(vm_deallocate)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      vm_address_t address;
      vm_size_t size;
   } Request;
#pragma pack()
   
   Request *req = (Request *)ARG1;
   
   PRINT("vm_deallocate(%s, at %p, size %d)", 
         name_for_port(MACH_REMOTE), 
         req->address, req->size);
   
   MACH_ARG(vm_deallocate.address) = req->address;
   MACH_ARG(vm_deallocate.size) = req->size;
   
   AFTER = POST_FN(vm_deallocate);

   // Must block to prevent race (other thread allocates and 
   // notifies after we deallocate but before we notify)
   *flags &= ~SfMayBlock;
}

POST(vm_deallocate)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      mach_msg_trailer_t trailer;
   } Reply;
#pragma pack()
   
   Reply *reply = (Reply *)ARG1;
   
   if (!reply->RetCode) {
      if (MACH_REMOTE == vg_task_port) {
         if (MACH_ARG(vm_deallocate.size)) {
            Addr start = VG_PGROUNDDN(MACH_ARG(vm_deallocate.address));
            Addr end = VG_PGROUNDUP(MACH_ARG(vm_deallocate.address) + 
                                    MACH_ARG(vm_deallocate.size));
            // Must have cleared SfMayBlock in PRE to prevent race
            ML_(notify_aspacem_and_tool_of_munmap)(start, end - start);
         }
      }
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}
   

PRE(vm_protect)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      vm_address_t address;
      vm_size_t size;
      boolean_t set_maximum;
      vm_prot_t new_protection;
   } Request;
#pragma pack()
   
   Request *req = (Request *)ARG1;
   
   PRINT("vm_protect(%s, at %p, size %d, set_max %d, prot %d)", 
         name_for_port(MACH_REMOTE), req->address, req->size, 
         req->set_maximum, req->new_protection);
   
   MACH_ARG(vm_protect.address) = req->address;
   MACH_ARG(vm_protect.size) = req->size;
   MACH_ARG(vm_protect.set_maximum) = req->set_maximum;
   MACH_ARG(vm_protect.new_protection) = req->new_protection;
   
   AFTER = POST_FN(vm_protect);
}

POST(vm_protect)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      mach_msg_trailer_t trailer;
   } Reply;
#pragma pack()
   
   Reply *reply = (Reply *)ARG1;
   
   if (!reply->RetCode) {
      if (MACH_REMOTE == vg_task_port) {
         Addr start = VG_PGROUNDDN(MACH_ARG(vm_protect.address));
         Addr end = VG_PGROUNDUP(MACH_ARG(vm_protect.address) + 
                                 MACH_ARG(vm_protect.size));
         UInt prot = MACH_ARG(vm_protect.new_protection);
         if (MACH_ARG(vm_protect.set_maximum)) {
             // GrP fixme mprotect max
             VG_(printf)("UNKNOWN vm_protect set maximum");
            //VG_(mprotect_max_range)(start, end-start, prot);
         } else {
            ML_(notify_aspacem_and_tool_of_mprotect)(start, end-start, prot);
         }
      }
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}


PRE(vm_inherit)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      vm_address_t address;
      vm_size_t size;
      vm_inherit_t new_inheritance;
   } Request;
#pragma pack()
   
   Request *req = (Request *)ARG1;
   
   PRINT("vm_inherit(%s, at %p, size %d, value %d)", 
         name_for_port(MACH_REMOTE), 
         req->address, req->size, 
         req->new_inheritance);
   
   AFTER = POST_FN(vm_inherit);
}

POST(vm_inherit)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      mach_msg_trailer_t trailer;
   } Reply;
#pragma pack()
   
   Reply *reply = (Reply *)ARG1;
   
   if (!reply->RetCode) {
      if (MACH_REMOTE == vg_task_port) {
         // GrP fixme do something?
      }
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}


PRE(vm_read)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      vm_address_t address;
      vm_size_t size;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("vm_read(from %s at %p size %u)", 
         name_for_port(MACH_REMOTE), req->address, req->size);
   
   MACH_ARG(vm_read.addr) = req->address;
   MACH_ARG(vm_read.size) = req->size;

   AFTER = POST_FN(vm_read);
}

POST(vm_read)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      /* start of the kernel processed data */
      mach_msg_body_t msgh_body;
      mach_msg_ool_descriptor_t data;
      /* end of the kernel processed data */
      NDR_record_t NDR;
      mach_msg_type_number_t dataCnt;
   } Reply;
#pragma pack()

   // Reply *reply = (Reply *)ARG1;

   if (MACH_REMOTE == vg_task_port) {
      // vm_read from self
      // GrP fixme copy initialized state
   }
}



PRE(mach_vm_read)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      mach_vm_address_t address;
      mach_vm_size_t size;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("mach_vm_read(from %s at 0x%llx size %llu)", 
         name_for_port(MACH_REMOTE), req->address, req->size);
   
   MACH_ARG(mach_vm_read.addr) = req->address;
   MACH_ARG(mach_vm_read.size) = req->size;

   AFTER = POST_FN(mach_vm_read);
}

POST(mach_vm_read)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      /* start of the kernel processed data */
      mach_msg_body_t msgh_body;
      mach_msg_ool_descriptor_t data;
      /* end of the kernel processed data */
      NDR_record_t NDR;
      mach_msg_type_number_t dataCnt;
   } Reply;
#pragma pack()

   // Reply *reply = (Reply *)ARG1;

   if (MACH_REMOTE == vg_task_port) {
      // vm_read from self
      // GrP fixme copy initialized state
   }
}


PRE(vm_read_overwrite)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      vm_address_t address;
      vm_size_t size;
      vm_address_t data;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("vm_read_overwrite(from %s at %p size %u to %p)", 
         name_for_port(MACH_REMOTE), req->address, req->size, req->data);
   
   MACH_ARG(vm_read_overwrite.addr) = req->address;
   MACH_ARG(vm_read_overwrite.size) = req->size;
   MACH_ARG(vm_read_overwrite.data) = req->data;

   PRE_MEM_WRITE("vm_read_overwrite(data)", req->data, req->size);

   AFTER = POST_FN(vm_read_overwrite);
}

POST(vm_read_overwrite)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      vm_size_t outsize;
   } Reply;
#pragma pack()

   Reply *reply = (Reply *)ARG1;

   if (reply->RetCode) {
       PRINT("mig return %d", reply->RetCode);
   } else {
      PRINT("read %llu bytes", (unsigned long long)reply->outsize);
      if (MACH_REMOTE == vg_task_port) {
         // vm_read_overwrite from self
         // GrP fixme copy initialized state
         POST_MEM_WRITE(MACH_ARG(vm_read_overwrite.data), reply->outsize);
      } else {
         // vm_read_overwrite from remote
         POST_MEM_WRITE(MACH_ARG(vm_read_overwrite.data), reply->outsize);
      }
   }
}


PRE(vm_copy)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      vm_address_t source_address;
      vm_size_t size;
      vm_address_t dest_address;
   } Request;
#pragma pack()
   
   Request *req = (Request *)ARG1;
   
   PRINT("vm_copy(%s, %p, %d, %p)", 
         name_for_port(MACH_REMOTE), 
         req->source_address, req->size, req->dest_address);

   MACH_ARG(vm_copy.src) = req->source_address;
   MACH_ARG(vm_copy.dst) = req->dest_address;
   MACH_ARG(vm_copy.size) = req->size;
   
   AFTER = POST_FN(vm_copy);
}

POST(vm_copy)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      mach_msg_trailer_t trailer;
   } Reply;
#pragma pack()
   
   Reply *reply = (Reply *)ARG1;
   
   if (!reply->RetCode) {
      if (MACH_REMOTE == vg_task_port) {
         // GrP fixme set dst's initialization equal to src's
         // and wipe any symbols or translations in dst
      }
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}


PRE(vm_map)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      /* start of the kernel processed data */
      mach_msg_body_t msgh_body;
      mach_msg_port_descriptor_t object;
      /* end of the kernel processed data */
      NDR_record_t NDR;
      vm_address_t address;
      vm_size_t size;
      vm_address_t mask;
      int flags;
      vm_offset_t offset;
      boolean_t copy;
      vm_prot_t cur_protection;
      vm_prot_t max_protection;
      vm_inherit_t inheritance;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   // GrP fixme check these
   PRINT("vm_map(in %s, at %p, size %d, from %s ...)", 
         name_for_port(MACH_REMOTE), 
         req->address, req->size, 
         name_for_port(req->object.name));

   MACH_ARG(vm_map.size) = req->size;
   MACH_ARG(vm_map.copy) = req->copy;
   MACH_ARG(vm_map.protection) = (req->cur_protection & req->max_protection);

   AFTER = POST_FN(vm_map);
}

POST(vm_map)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      vm_address_t address;
      mach_msg_trailer_t trailer;
   } Reply;
#pragma pack()

   Reply *reply = (Reply *)ARG1;

   if (!reply->RetCode) {
      // GrP fixme check src and dest tasks
      PRINT("mapped at %p", reply->address);
      // GrP fixme max prot
      ML_(notify_aspacem_and_tool_of_mmap)
          (reply->address, VG_PGROUNDUP(MACH_ARG(vm_map.size)), 
          MACH_ARG(vm_map.protection), VKI_MAP_SHARED, -1, 0);
      // GrP fixme VKI_MAP_PRIVATE if !copy?
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}


PRE(vm_remap)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      /* start of the kernel processed data */
      mach_msg_body_t msgh_body;
      mach_msg_port_descriptor_t src_task;
      /* end of the kernel processed data */
      NDR_record_t NDR;
      vm_address_t target_address;
      vm_size_t size;
      vm_address_t mask;
      boolean_t anywhere;
      vm_address_t src_address;
      boolean_t copy;
      vm_inherit_t inheritance;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   // GrP fixme check src and dest tasks

   if (VG_(clo_trace_syscalls)) {
      mach_port_name_t source_task = req->src_task.name;
      if (source_task == mach_task_self()) {
         PRINT("vm_remap(mach_task_self(), "
               "to %p size %d, from mach_task_self() at %p, ...)",
               req->target_address, req->size, req->src_address);
      } else {
          PRINT("vm_remap(mach_task_self(), "
                "to %p size %d, from task %p at %p, ...)",
                req->target_address, req->size, 
                source_task,  req->src_address);
      }
   }

   // arg1 is task
   // vt->syscall_arg2 = req->target_address;
   MACH_ARG(vm_remap.size) = req->size;
   // vt->syscall_arg4 = req->copy;

   AFTER = POST_FN(vm_remap);
}

POST(vm_remap)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      vm_address_t target_address;
      vm_prot_t cur_protection;
      vm_prot_t max_protection;
      mach_msg_trailer_t trailer;
   } Reply;
#pragma pack()

   Reply *reply = (Reply *)ARG1;

   if (!reply->RetCode) {
      // GrP fixme check src and dest tasks
      UInt prot = reply->cur_protection & reply->max_protection;
      // GrP fixme max prot
      PRINT("mapped at %p", reply->target_address);
      ML_(notify_aspacem_and_tool_of_mmap)
          (reply->target_address, VG_PGROUNDUP(MACH_ARG(vm_remap.size)), 
          prot, VKI_MAP_SHARED, -1, 0);
      // GrP fixme VKI_MAP_FIXED if !copy?
      // GrP fixme copy initialized bits from source to dest if source_task is also mach_task_self
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}


PRE(mach_make_memory_entry_64)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      /* start of the kernel processed data */
      mach_msg_body_t msgh_body;
      mach_msg_port_descriptor_t parent_entry;
      /* end of the kernel processed data */
      NDR_record_t NDR;
      memory_object_size_t size;
      memory_object_offset_t offset;
      vm_prot_t permission;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("mach_make_memory_entry_64(%s, %d, %d, %d, ..., %d)", 
         name_for_port(MACH_REMOTE), 
         req->size, req->offset, req->permission, req->parent_entry);

   AFTER = POST_FN(mach_make_memory_entry_64);
}

POST(mach_make_memory_entry_64)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      mach_msg_body_t msgh_body;
      mach_msg_port_descriptor_t object;
      NDR_record_t NDR;
      memory_object_size_t size;
   } Reply;
#pragma pack()

   Reply *reply = (Reply *)ARG1;

   if (reply->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX) {
      assign_port_name(reply->object.name, "memory-%p");
      PRINT("%s", name_for_port(reply->object.name));
   }
}


PRE(vm_purgable_control)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      vm_address_t address;
      vm_purgable_t control;
      int state;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("vm_purgable_control(%s, %p, %d, %d)", 
         name_for_port(MACH_REMOTE), 
         req->address, req->control, req->state);

   // fixme verify address?

   AFTER = POST_FN(vm_purgable_control);
}

POST(vm_purgable_control)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      int state;
   } Reply;
#pragma pack()

   Reply *reply = (Reply *)ARG1;

   if (!reply->RetCode) {
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}


PRE(mach_vm_purgable_control)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      mach_vm_address_t address;
      vm_purgable_t control;
      int state;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("mach_vm_purgable_control(%s, 0x%llx, %d, %d)", 
         name_for_port(MACH_REMOTE), 
         (unsigned long long)req->address, req->control, req->state);

   // fixme verify address?

   AFTER = POST_FN(mach_vm_purgable_control);
}

POST(mach_vm_purgable_control)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      int state;
   } Reply;
#pragma pack()

   Reply *reply = (Reply *)ARG1;

   if (!reply->RetCode) {
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}


PRE(mach_vm_allocate)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      mach_vm_address_t address;
      mach_vm_size_t size;
      int flags;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("mach_vm_allocate (%s, at 0x%llx, size %lld, flags 0x%x)", 
         name_for_port(MACH_REMOTE), 
         req->address, req->size, req->flags);

   MACH_ARG(mach_vm_allocate.size) = req->size;
   MACH_ARG(mach_vm_allocate.flags) = req->flags;

   AFTER = POST_FN(mach_vm_allocate);
}

POST(mach_vm_allocate)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      mach_vm_address_t address;
      mach_msg_trailer_t trailer;
   } Reply;
#pragma pack()
   
   Reply *reply = (Reply *)ARG1;
   
   if (!reply->RetCode) {
      if (MACH_REMOTE == vg_task_port) {
         PRINT("allocated at 0x%llx", reply->address);
         // requesting 0 bytes returns address 0 with no error
         if (MACH_ARG(mach_vm_allocate.size)) {
            ML_(notify_aspacem_and_tool_of_mmap)
                (reply->address, MACH_ARG(mach_vm_allocate.size), 
                 VKI_PROT_READ|VKI_PROT_WRITE, VKI_MAP_ANON, -1, 0);
         }
      } else {
         PRINT("allocated at 0x%llx in remote task %s", reply->address, 
               name_for_port(MACH_REMOTE));
      }
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}


PRE(mach_vm_deallocate)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      mach_vm_address_t address;
      mach_vm_size_t size;
   } Request;
#pragma pack()
   
   Request *req = (Request *)ARG1;
   
   PRINT("mach_vm_deallocate(%s, at 0x%llx, size %lld)", 
         name_for_port(MACH_REMOTE), 
         req->address, req->size);
   
   MACH_ARG(mach_vm_deallocate.address) = req->address;
   MACH_ARG(mach_vm_deallocate.size) = req->size;
   
   AFTER = POST_FN(mach_vm_deallocate);

   // Must block to prevent race (other thread allocates and 
   // notifies after we deallocate but before we notify)
   *flags &= ~SfMayBlock;
}

POST(mach_vm_deallocate)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      mach_msg_trailer_t trailer;
   } Reply;
#pragma pack()
   
   Reply *reply = (Reply *)ARG1;
   
   if (!reply->RetCode) {
      if (MACH_REMOTE == vg_task_port) {
         if (MACH_ARG(mach_vm_deallocate.size)) {
            Addr start = VG_PGROUNDDN(MACH_ARG(mach_vm_deallocate.address));
            Addr end = VG_PGROUNDUP(MACH_ARG(mach_vm_deallocate.address) + 
                                    MACH_ARG(mach_vm_deallocate.size));
            // Must have cleared SfMayBlock in PRE to prevent race
            ML_(notify_aspacem_and_tool_of_munmap)(start, end - start);
         }
      }
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}
   

PRE(mach_vm_protect)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      mach_vm_address_t address;
      mach_vm_size_t size;
      boolean_t set_maximum;
      vm_prot_t new_protection;
   } Request;
#pragma pack()
   
   Request *req = (Request *)ARG1;
   
   PRINT("mach_vm_protect(%s, at 0x%llx, size %lld, set_max %d, prot %d)", 
         name_for_port(MACH_REMOTE), req->address, req->size, 
         req->set_maximum, req->new_protection);
   
   MACH_ARG(mach_vm_protect.address) = req->address;
   MACH_ARG(mach_vm_protect.size) = req->size;
   MACH_ARG(mach_vm_protect.set_maximum) = req->set_maximum;
   MACH_ARG(mach_vm_protect.new_protection) = req->new_protection;
   
   AFTER = POST_FN(mach_vm_protect);
}

POST(mach_vm_protect)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      mach_msg_trailer_t trailer;
   } Reply;
#pragma pack()
   
   Reply *reply = (Reply *)ARG1;
   
   if (!reply->RetCode) {
      if (MACH_REMOTE == vg_task_port) {
         Addr start = VG_PGROUNDDN(MACH_ARG(mach_vm_protect.address));
         Addr end = VG_PGROUNDUP(MACH_ARG(mach_vm_protect.address) + 
                                 MACH_ARG(mach_vm_protect.size));
         UInt prot = MACH_ARG(mach_vm_protect.new_protection);
         if (MACH_ARG(mach_vm_protect.set_maximum)) {
#warning GrP fixme mprotect max
            //VG_(mprotect_max_range)(start, end-start, prot);
         } else {
            ML_(notify_aspacem_and_tool_of_mprotect)(start, end-start, prot);
         }
      }
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}


PRE(mach_vm_inherit)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      mach_vm_address_t address;
      mach_vm_size_t size;
      vm_inherit_t new_inheritance;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;
   
   PRINT("mach_vm_inherit(to %s, at 0x%llx, size %llu, value %u)", 
         name_for_port(MACH_REMOTE), 
         req->address, req->size, req->new_inheritance);

   AFTER = POST_FN(mach_vm_inherit);
}

POST(mach_vm_inherit)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      mach_msg_trailer_t trailer;
   } Reply;
#pragma pack()
   
   Reply *reply = (Reply *)ARG1;
   
   if (!reply->RetCode) {
      // no V-visible side effects
      // fixme except maybe fork/exec
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}


PRE(mach_vm_copy)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      mach_vm_address_t source_address;
      mach_vm_size_t size;
      mach_vm_address_t dest_address;
   } Request;
#pragma pack()
   
   Request *req = (Request *)ARG1;
   
   PRINT("mach_vm_copy(%s, 0x%llx, %llu, 0x%llx)", 
         name_for_port(MACH_REMOTE), 
         req->source_address, req->size, req->dest_address);
   
   // arg1 is task
   // vt->syscall_arg2 = req->source_address;
   // vt->syscall_arg3 = req->size;
   // vt->syscall_arg4 = req->dest_address;
   
   AFTER = POST_FN(mach_vm_copy);
}

POST(mach_vm_copy)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      mach_msg_trailer_t trailer;
   } Reply;
#pragma pack()
   
   Reply *reply = (Reply *)ARG1;
   
   if (!reply->RetCode) {
      if (MACH_REMOTE == vg_task_port) {
         // GrP fixme set dest's initialization equal to src's
         // BUT vm_copy allocates no memory
      }
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}


PRE(mach_vm_map)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      /* start of the kernel processed data */
      mach_msg_body_t msgh_body;
      mach_msg_port_descriptor_t object;
      /* end of the kernel processed data */
      NDR_record_t NDR;
      mach_vm_address_t address;
      mach_vm_size_t size;
      mach_vm_address_t mask;
      int flags;
      memory_object_offset_t offset;
      boolean_t copy;
      vm_prot_t cur_protection;
      vm_prot_t max_protection;
      vm_inherit_t inheritance;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   // GrP fixme check these
   PRINT("mach_vm_map(in %s, at 0x%llx, size %llu, from %s ...)", 
         name_for_port(MACH_REMOTE), 
         req->address, req->size, 
         name_for_port(req->object.name));

   MACH_ARG(mach_vm_map.size) = req->size;
   MACH_ARG(mach_vm_map.copy) = req->copy;
   MACH_ARG(mach_vm_map.protection) = 
      (req->cur_protection & req->max_protection);

   AFTER = POST_FN(mach_vm_map);
}

POST(mach_vm_map)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      mach_vm_address_t address;
      mach_msg_trailer_t trailer;
   } Reply;
#pragma pack()

   Reply *reply = (Reply *)ARG1;

   if (!reply->RetCode) {
      // GrP fixme check src and dest tasks
      PRINT("mapped at 0x%llx", reply->address);
      // GrP fixme max prot
      ML_(notify_aspacem_and_tool_of_mmap)
         (reply->address, VG_PGROUNDUP(MACH_ARG(mach_vm_map.size)), 
          MACH_ARG(mach_vm_map.protection), VKI_MAP_SHARED, -1, 0);
      // GrP fixme VKI_MAP_PRIVATE if !copy?
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}


PRE(mach_vm_region_recurse)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      mach_vm_address_t address;
      natural_t nesting_depth;
      mach_msg_type_number_t infoCnt;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("mach_vm_region_recurse(in %s, at 0x%llx, depth %u, count %u)", 
         name_for_port(MACH_REMOTE), 
         req->address, req->nesting_depth, req->infoCnt);

   AFTER = POST_FN(mach_vm_region_recurse);
}

POST(mach_vm_region_recurse)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      mach_vm_address_t address;
      mach_vm_size_t size;
      natural_t nesting_depth;
      mach_msg_type_number_t infoCnt;
      int info[19];
   } Reply;
#pragma pack()

   Reply *reply = (Reply *)ARG1;

   if (!reply->RetCode) {
       PRINT("got region at 0x%llx, size %llu, depth %u, count %u", 
             reply->address, reply->size, 
             reply->nesting_depth, reply->infoCnt);
       // fixme mark info contents beyond infoCnt as bogus
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}


/* ---------------------------------------------------------------------
   mach_msg: messages to thread
   ------------------------------------------------------------------ */



POST(thread_terminate)
{
}


PRE(thread_terminate)
{
   mach_msg_header_t *mh = (mach_msg_header_t *)ARG1;
   Bool self_terminate = (mh->msgh_request_port == MACH_THREAD);

   PRINT("thread_terminate(%s)", name_for_port(mh->msgh_request_port));

   AFTER = POST_FN(thread_terminate);

   if (self_terminate) {
      // Terminating this thread.
      // Copied from sys_exit.
      ThreadState *tst = VG_(get_ThreadState)(tid);
      tst->exitreason = VgSrc_ExitThread;
      tst->os_state.exitcode = 0;  // GrP fixme anything better?
      SET_STATUS_Success(0);
      *flags &= ~SfMayBlock;  // clear flag set by PRE(mach_msg)
   } else {
      // Terminating some other thread.
      // Do keep the scheduler lock while terminating any other thread. 
      // Otherwise we might halt the other thread while it holds the lock, 
      // which would deadlock the process.
      // GrP fixme good enough?
      // GrP fixme need to clean up other thread's valgrind data?
   }
}


POST(thread_create)
{
}


PRE(thread_create)
{
   PRINT("thread_create(mach_task_self(), ...)");

   AFTER = POST_FN(thread_create);

   // GrP fixme
   VG_(core_panic)("thread_create() unimplemented");
}


PRE(thread_create_running)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      thread_state_flavor_t flavor;
      mach_msg_type_number_t new_stateCnt;
      natural_t new_state[144];
   } Request;
#pragma pack()
   
   Request *req;
   thread_state_t regs;
   ThreadState *new_thread;
   
   PRINT("thread_create_running(mach_task_self(), ...)");
   
   // The new thread will immediately begin execution, 
   // so we need to hijack the register state here.
   
   req = (Request *)ARG1;
   regs = (thread_state_t)req->new_state;
   
   // Build virtual thread.
   new_thread = build_thread(regs, req->flavor, req->new_stateCnt);
   
   // Edit the thread state to send to the real kernel.
   hijack_thread_state(regs, req->flavor, req->new_stateCnt, new_thread);

   AFTER = POST_FN(thread_create_running);
}


POST(thread_create_running)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      /* start of the kernel processed data */
      mach_msg_body_t msgh_body;
      mach_msg_port_descriptor_t child_act;
      /* end of the kernel processed data */
   } Reply;
#pragma pack()
   
   Reply *reply = (Reply *)ARG1;

   assign_port_name(reply->child_act.name, "thread-%p");
   PRINT("%s", name_for_port(reply->child_act.name));
}


PRE(sys_bsdthread_create)
{
   ThreadState *tst;

   PRINT("bsdthread_create( %p, %p, %p, %p, %x )", 
         ARG1, ARG2, ARG3, ARG4, ARG5);
   PRE_REG_READ5(pthread_t,"bsdthread_create", 
                 void *,"func", void *,"func_arg", void *,"stack", 
                 pthread_t,"thread", unsigned int,"flags");

   // The kernel will call V's pthread_hijack() to launch the thread.
   // Here we allocate the thread state and pass it to pthread_hijack()
   // via the func_arg parameter.
   
   tst = VG_(get_ThreadState)(VG_(alloc_ThreadState)());
   allocstack(tst->tid);

   tst->os_state.func_arg = (Addr)ARG2;
   ARG2 = (Word)tst;

   // Create a semaphore that pthread_hijack will signal once it starts
   // POST(sys_bsdthread_create) needs to wait for the new memory map to appear
   semaphore_create(mach_task_self(), &tst->os_state.bsdthread_create_sema, 
                    SYNC_POLICY_FIFO, 0);
}

POST(sys_bsdthread_create)
{ 
   // Wait for pthreead_hijack to finish on new thread.
   // Otherwise V thinks the new pthread struct is still 
   // unmapped when we return to libc, causing false errors

   ThreadState *tst = (ThreadState *)ARG2;
   semaphore_wait(tst->os_state.bsdthread_create_sema);
   semaphore_destroy(mach_task_self(), tst->os_state.bsdthread_create_sema);

   // fixme semaphore destroy needed when thread creation fails
   // fixme probably other cleanup too
}


PRE(sys_bsdthread_terminate)
{
   ThreadState *tst;

   PRINT("bsdthread_terminate( %p, %lx, %s, %s )", 
         ARG1, ARG2, name_for_port(ARG3), name_for_port(ARG4));
   PRE_REG_READ4(int,"bsdthread_terminate", 
                 void *,"freeaddr", size_t,"freesize", 
                 mach_port_t,"kport", mach_port_t,"joinsem");

   // Free memory and signal semaphore.
   // fixme errors?
   if (ARG4) semaphore_signal((semaphore_t)ARG4);
   if (ARG1  &&  ARG2) {
       ML_(notify_aspacem_and_tool_of_munmap)(ARG1, ARG2);
       vm_deallocate(mach_task_self(), (vm_address_t)ARG1, (vm_size_t)ARG2);
   }

   // Tell V to terminate the thread.
   // Copied from sys_exit.
   tst = VG_(get_ThreadState)(tid);
   tst->exitreason = VgSrc_ExitThread;
   tst->os_state.exitcode = 0;  // GrP fixme anything better?
   SET_STATUS_Success(0);
}


POST(thread_suspend)
{
}

PRE(thread_suspend)
{
   mach_msg_header_t *mh = (mach_msg_header_t *)ARG1;
   Bool self_suspend = (mh->msgh_request_port == MACH_THREAD);

   PRINT("thread_suspend(%s)", name_for_port(mh->msgh_request_port));

   AFTER = POST_FN(thread_suspend);

   if (self_suspend) {
       // Don't keep the scheduler lock while self-suspending.
       // Otherwise we might halt while still holding the lock, 
       // which would deadlock the process.
       *flags |= SfMayBlock;
   } else {
       // Do keep the scheduler lock while suspending any other thread. 
       // Otherwise we might halt the other thread while it holds the lock, 
       // which would deadlock the process.
   }
}


POST(thread_get_state)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      mach_msg_type_number_t old_stateCnt;
      natural_t old_state[144];
      mach_msg_trailer_t trailer;
   } Reply;
#pragma pack()

   Reply *reply = (Reply *)ARG1;
   // mach_port_t thread = MACH_ARG(thread_get_state.thread);
   thread_state_flavor_t flavor = MACH_ARG(thread_get_state.flavor);

   if (!reply->RetCode) {
      thread_state_from_vex((thread_state_t)reply->old_state, 
                             flavor, reply->old_stateCnt, 
                             &VG_(get_ThreadState)(tid)->arch.vex);
   } else {
      PRINT("mig return %d", reply->RetCode);
   }
}

PRE(thread_get_state)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      thread_state_flavor_t flavor;
      mach_msg_type_number_t old_stateCnt;
   } Request;
#pragma pack()
    
   Request *req = (Request *)ARG1;
   // Bool self = (req->Head.msgh_request_port == MACH_THREAD);

   // GrP fixme   if (self) {
   PRINT("thread_get_state(%s, %d)", 
         name_for_port(req->Head.msgh_request_port), req->flavor);
       /*} else {
       PRINT("thread_get_state(0x%x, %d)", 
             req->Head.msgh_request_port, req->flavor);
             }*/

   // Hack the thread state after making the real call.
   MACH_ARG(thread_get_state.thread) = req->Head.msgh_request_port;
   MACH_ARG(thread_get_state.flavor) = req->flavor;

   AFTER = POST_FN(thread_get_state);
}


POST(thread_policy)
{
}

PRE(thread_policy)
{
   mach_msg_header_t *mh = (mach_msg_header_t *)ARG1;
   // Bool self = (mh->msgh_request_port == MACH_THREAD);

   // GrP fixme   if (self) {
      PRINT("thread_policy(%s, ...)", name_for_port(mh->msgh_request_port));
      /*} else {
      PRINT("thread_policy(thread 0x%x, ...)", mh->msgh_request_port);
      }*/

   AFTER = POST_FN(thread_policy);
}


PRE(thread_info)
{
   mach_msg_header_t *mh = (mach_msg_header_t *)ARG1;

   PRINT("thread_info(%s, ...)", name_for_port(mh->msgh_request_port));
   // GrP fixme does any thread info need to be hijacked?

   AFTER = POST_FN(thread_info);
}

POST(thread_info)
{
   // fixme mark unused parts of thread_info_out as uninitialized?
}



/* ---------------------------------------------------------------------
   mach_msg: messages to bootstrap port
   ------------------------------------------------------------------ */


POST(bootstrap_register)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      kern_return_t RetCode;
      mach_msg_trailer_t trailer;
   } Reply;
#pragma pack()

   Reply *reply = (Reply *)ARG1;

   if (reply->RetCode) PRINT("mig return %d", reply->RetCode);
}

PRE(bootstrap_register)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      /* start of the kernel processed data */
      mach_msg_body_t msgh_body;
      mach_msg_port_descriptor_t service_port;
      /* end of the kernel processed data */
      NDR_record_t NDR;
      name_t service_name;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("bootstrap_register(port 0x%x, \"%s\")",
         req->service_port.name, req->service_name);

   assign_port_name(req->service_port.name, req->service_name);

   AFTER = POST_FN(bootstrap_register);
}


POST(bootstrap_look_up)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      /* start of the kernel processed data */
      mach_msg_body_t msgh_body;
      mach_msg_port_descriptor_t service_port;
      /* end of the kernel processed data */
      mach_msg_trailer_t trailer;
   } Reply;
#pragma pack()

   Reply *reply = (Reply *)ARG1;

   if ((reply->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX)  &&  
       reply->service_port.name) 
   {
       assign_port_name(reply->service_port.name, 
                        MACH_ARG(bootstrap_look_up.service_name));
       PRINT("%s", name_for_port(reply->service_port.name));
   } else {
       PRINT("not found");
   }
   VG_(arena_free)(VG_AR_CORE, MACH_ARG(bootstrap_look_up.service_name));
}

PRE(bootstrap_look_up)
{
#pragma pack(4)
   typedef struct {
      mach_msg_header_t Head;
      NDR_record_t NDR;
      name_t service_name;
   } Request;
#pragma pack()

   Request *req = (Request *)ARG1;

   PRINT("bootstrap_look_up(\"%s\")", req->service_name);

   MACH_ARG(bootstrap_look_up.service_name) =
      VG_(arena_strdup)(VG_AR_CORE, "syswrap-darwin.bootstrap-name", 
                        req->service_name);

   AFTER = POST_FN(bootstrap_look_up);
}


/* ---------------------------------------------------------------------
   mach_msg: receiver-specific handlers
   ------------------------------------------------------------------ */


POST(mach_msg_receive)
{
   // mach_msg_header_t *mh = (mach_msg_header_t *)ARG1;

   // GrP fixme don't know of anything interesting here currently
   // import_complex_message handles everything
   // PRINT("UNHANDLED reply %d", mh->msgh_id);

   // Assume the call may have mapped or unmapped memory
   VG_(sync_mappings)("after", "mach_msg_receive", 0);
}

PRE(mach_msg_receive)
{
   mach_msg_header_t *mh = (mach_msg_header_t *)ARG1;
   
   PRINT("mach_msg_receive(port %s)", name_for_port(mh->msgh_reply_port));
   
   AFTER = POST_FN(mach_msg_receive);

   // no message sent, only listening for a reply
   // assume message may block
   *flags |= SfMayBlock;
}


PRE(mach_msg_bootstrap)
{
   // message to bootstrap port

   mach_msg_header_t *mh = (mach_msg_header_t *)ARG1;
   
   switch (mh->msgh_id) {
   case 403:
      CALL_PRE(bootstrap_register);
      return;
   case 404:
      CALL_PRE(bootstrap_look_up);
      return;
      
   default:
      PRINT("UNHANDLED bootstrap message [id %d, to %s, reply 0x%x]\n", 
            mh->msgh_id, name_for_port(mh->msgh_request_port),
            mh->msgh_reply_port);
      return;
   }
}


PRE(mach_msg_host)
{
   // message to host self - check for host-level kernel calls

   mach_msg_header_t *mh = (mach_msg_header_t *)ARG1;

   switch (mh->msgh_id) {
   case 200:
      CALL_PRE(host_info);
      return;
   case 202:
      CALL_PRE(host_page_size);
      return;
   case 205:
      CALL_PRE(host_get_io_master);
      return;
   case 206:
      CALL_PRE(host_get_clock_service);
      return;
   case 217:
      CALL_PRE(host_request_notification);
      return;

   default:
      // unknown message to host self
      VG_(printf)("UNKNOWN host message [id %d, to %s, reply 0x%x]\n", 
                  mh->msgh_id, name_for_port(mh->msgh_request_port), 
                  mh->msgh_reply_port);
      return;
   }
} 

PRE(mach_msg_task)
{
   // message to a task port

   mach_msg_header_t *mh = (mach_msg_header_t *)ARG1;

   switch (mh->msgh_id) {
   case 3201:
      CALL_PRE(mach_port_type);
      return;
   case 3204:
      CALL_PRE(mach_port_allocate);
      return;
   case 3205:
      CALL_PRE(mach_port_destroy);
      return;
   case 3206:
      CALL_PRE(mach_port_deallocate);
      return;
   case 3207:
      CALL_PRE(mach_port_get_refs);
      return;
   case 3208:
      CALL_PRE(mach_port_mod_refs);
      return;
   case 3211:
      CALL_PRE(mach_port_get_set_status);
      return;
   case 3213:
      CALL_PRE(mach_port_request_notification);
      return;
   case 3214:
      CALL_PRE(mach_port_insert_right);
      return;
   case 3217:
      CALL_PRE(mach_port_get_attributes);
      return;
   case 3218:
      CALL_PRE(mach_port_set_attributes);
      return;
   case 3226:
      CALL_PRE(mach_port_insert_member);
      return;
   case 3227:
      CALL_PRE(mach_port_extract_member);
      return;
        
   case 3402:
      CALL_PRE(task_threads);
      return;
   case 3404:
      CALL_PRE(mach_ports_lookup);
      return;

   case 3407:
      CALL_PRE(task_suspend);
      return;
   case 3408:
      CALL_PRE(task_resume);
      return;
      
   case 3409:
      CALL_PRE(task_get_special_port);
      return;
   case 3411:
      CALL_PRE(thread_create);
      return;
   case 3412:
      CALL_PRE(thread_create_running);
      return;
      
   case 3418:
      CALL_PRE(semaphore_create);
      return;
   case 3419:
      CALL_PRE(semaphore_destroy);
      return;
      
   case 3801:
      CALL_PRE(vm_allocate);
      return;
   case 3802:
      CALL_PRE(vm_deallocate);
      return;
   case 3803:
      CALL_PRE(vm_protect);
      return;
   case 3804:
      CALL_PRE(vm_inherit);
      return;
   case 3805:
      CALL_PRE(vm_read);
      return;
   case 3808:
      CALL_PRE(vm_copy);
      return;
   case 3809:
      CALL_PRE(vm_read_overwrite);
      return;
   case 3812:
      CALL_PRE(vm_map);
      return;
   case 3814:
      CALL_PRE(vm_remap);
      return;
   case 3825:
      CALL_PRE(mach_make_memory_entry_64);
      return;
   case 3830:
      CALL_PRE(vm_purgable_control);
      return;

   case 4800:
      CALL_PRE(mach_vm_allocate);
      return;
   case 4801:
      CALL_PRE(mach_vm_deallocate);
      return;
   case 4802:
      CALL_PRE(mach_vm_protect);
      return;
   case 4803:
      CALL_PRE(mach_vm_inherit);
      return;
   case 4804:
      CALL_PRE(mach_vm_read);
      return;
   case 4807:
      CALL_PRE(mach_vm_copy);
      return;
   case 4811:
      CALL_PRE(mach_vm_map);
      return;
   case 4815:
      CALL_PRE(mach_vm_region_recurse);
      return;
   case 4817:
      CALL_PRE(mach_make_memory_entry_64);
      return;
   case 4818:
      CALL_PRE(mach_vm_purgable_control);
      return;

   default:
      // unknown message to task self
      VG_(printf)("UNKNOWN task message [id %d, to %s, reply 0x%x]\n",
                  mh->msgh_id, name_for_port(mh->msgh_remote_port),
                  mh->msgh_reply_port);
      return;
   }
} 


PRE(mach_msg_thread)
{
   // message to local thread - check for thread-level kernel calls

   mach_msg_header_t *mh = (mach_msg_header_t *)ARG1;

   switch (mh->msgh_id) {
   case 3600: 
      CALL_PRE(thread_terminate);
      return;
   case 3603:
      CALL_PRE(thread_get_state);
      return;
   case 3605: 
      CALL_PRE(thread_suspend);
      return;
   case 3612: 
      CALL_PRE(thread_info);
      return;
   case 3616: 
      CALL_PRE(thread_policy);
      return;
   default:
      // unknown message to a thread
      VG_(printf)("UNKNOWN thread message [id %d, to %s, reply 0x%x]\n", 
                  mh->msgh_id, name_for_port(mh->msgh_request_port), 
                  mh->msgh_reply_port);
      return;
   }
}


static int is_thread_port(mach_port_t port)
{
   if (port == 0) return False;

   return VG_(lwpid_to_vgtid)(port) != VG_INVALID_THREADID;
}


static int is_task_port(mach_port_t port)
{
   if (port == 0) return False;

   if (port == vg_task_port) return True;

   return (0 == VG_(strncmp)("task-", name_for_port(port), 5));
}


/* ---------------------------------------------------------------------
   mach_msg: base handlers
   ------------------------------------------------------------------ */

POST(mach_msg)
{
   mach_msg_header_t *mh = (mach_msg_header_t *)ARG1;
   mach_msg_option_t option = (mach_msg_option_t)ARG2;

   if (option & MACH_RCV_MSG) {
      if (RES != 0) {
         // error during send or receive
         // GrP fixme need to clean up port rights?
      } else {
         mach_msg_trailer_t *mt = 
             (mach_msg_trailer_t *)((Addr)mh + round_msg(mh->msgh_size));
           
         // Assume the entire received message and trailer is initialized
         // GrP fixme would being more specific catch any bugs?
         POST_MEM_WRITE((Addr)mh, 
                        round_msg(mh->msgh_size) + mt->msgh_trailer_size);
         
         if (mh->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
             // Update memory map for out-of-line message data
             import_complex_message(tid, mh);
         }
      }
   }
   
   // Call handler chosen by PRE(mach_msg)
   if (AFTER) {
      (*AFTER)(tid, arrghs, status);
   }
}


POST(mach_msg_unhandled)
{
   VG_(sync_mappings)("after", "mach_msg_receive", 0);
}

PRE(mach_msg)
{
   mach_msg_header_t *mh = (mach_msg_header_t *)ARG1;
   mach_msg_option_t option = (mach_msg_option_t)ARG2;
   // mach_msg_size_t send_size = (mach_msg_size_t)ARG3;
   mach_msg_size_t rcv_size = (mach_msg_size_t)ARG4;
   // mach_port_t rcv_name = (mach_port_t)ARG5;
   size_t complex_header_size = 0;

   PRE_REG_READ7(long, "mach_msg", 
                 mach_msg_header_t*,"msg", mach_msg_option_t,"option", 
                 mach_msg_size_t,"send_size", mach_msg_size_t,"rcv_size", 
                 mach_port_t,"rcv_name", mach_msg_timeout_t,"timeout", 
                 mach_port_t,"notify");

   // Assume default POST handler until specified otherwise
   AFTER = NULL;

   // Assume call may block unless specified otherwise
   *flags |= SfMayBlock;

   if (option & MACH_SEND_MSG) {
      // Validate outgoing message header
      PRE_MEM_READ("mach_msg(msg.msgh_bits)", 
                   (Addr)&mh->msgh_bits, sizeof(mh->msgh_bits));
      // msgh_size not required, use parameter instead
      PRE_MEM_READ("mach_msg(msg.msgh_remote_port)", 
                   (Addr)&mh->msgh_remote_port, sizeof(mh->msgh_remote_port));
      PRE_MEM_READ("mach_msg(msg.msgh_local_port)", 
                   (Addr)&mh->msgh_local_port, sizeof(mh->msgh_local_port));
      // msgh_reserved not required
      PRE_MEM_READ("mach_msg(msg.msgh_id)", 
                   (Addr)&mh->msgh_id, sizeof(mh->msgh_id));
      
      if (mh->msgh_bits & MACH_MSGH_BITS_COMPLEX) {
         // Validate typed message data and handle memory map changes.
         complex_header_size = export_complex_message(tid, mh);
      }

      // GrP fixme handle sender-specified message trailer
      // (but is this only for too-secure processes?)
      vg_assert(! (mh->msgh_bits & MACH_SEND_TRAILER));

      MACH_REMOTE = mh->msgh_remote_port;
      MACH_MSGH_ID = mh->msgh_id;
   }

   if (option & MACH_RCV_MSG) {
      // Pre-validate receive buffer
      PRE_MEM_WRITE("mach_msg(receive buffer)", (Addr)mh, rcv_size);
   }


   // Call a PRE handler. The PRE handler may set an AFTER handler.

   if (!(option & MACH_SEND_MSG)) {
      // no message sent, receive only
      CALL_PRE(mach_msg_receive);
      return;
   }
   else if (mh->msgh_request_port == vg_host_port) {
      // message sent to mach_host_self()
      CALL_PRE(mach_msg_host);
      return;
   }
   else if (is_task_port(mh->msgh_request_port)) {
      // message sent to a task
      CALL_PRE(mach_msg_task);
      return;
   }
   else if (mh->msgh_request_port == vg_bootstrap_port) {
      // message sent to bootstrap port
      CALL_PRE(mach_msg_bootstrap);
      return;
   }
   else if (is_thread_port(mh->msgh_request_port)) {
      // message sent to one of this process's threads
      CALL_PRE(mach_msg_thread);
      return;
   }
   else {
      // arbitrary message to arbitrary port
      PRINT("UNHANDLED mach_msg [id %d, to %s, reply 0x%x]", 
            mh->msgh_id, name_for_port(mh->msgh_request_port), 
            mh->msgh_reply_port);

      AFTER = POST_FN(mach_msg_unhandled);

      // Assume the entire message body may be read.
      // GrP fixme generates false positives for unknown protocols
      /*
      PRE_MEM_READ("mach_msg(payload)", 
                   (Addr)((char*)mh + sizeof(mach_msg_header_t) + complex_header_size), 
                   send_size - sizeof(mach_msg_header_t) - complex_header_size);
      */
      return;
   }
}


/* ---------------------------------------------------------------------
   other Mach traps
   ------------------------------------------------------------------ */

PRE(mach_reply_port)
{
   PRINT("mach_reply_port()");
}

POST(mach_reply_port)
{
   record_named_port(tid, RES, MACH_PORT_RIGHT_RECEIVE, "reply-%p");
   PRINT("reply port %s", name_for_port(RES));
}


PRE(mach_thread_self)
{
   PRINT("mach_thread_self()");
}

POST(mach_thread_self)
{
   record_named_port(tid, RES, MACH_PORT_RIGHT_SEND, "thread-%p");
   PRINT("thread 0x%x", RES);
}


PRE(mach_host_self)
{
   PRINT("mach_host_self()");
}

POST(mach_host_self)
{
   vg_host_port = RES;
   record_named_port(tid, RES, MACH_PORT_RIGHT_SEND, "mach_host_self()");
   PRINT("host 0x%x", RES);
}


PRE(mach_task_self)
{
   PRINT("mach_task_self()");
}

POST(mach_task_self)
{
   vg_task_port = RES;
   record_named_port(tid, RES, MACH_PORT_RIGHT_SEND, "mach_task_self()");
   PRINT("task 0x%x", RES);
}


PRE(syscall_thread_switch)
{
   PRINT("syscall_thread_switch(%s, %d, %d)", name_for_port(ARG1), ARG2, ARG3);
   PRE_REG_READ3(long, "syscall_thread_switch", 
                 mach_port_t,"thread", int,"option", natural_t,"timeout");

   *flags |= SfMayBlock;
}


PRE(semaphore_signal)
{
   PRINT("semaphore_signal(%s)", name_for_port(ARG1));
   PRE_REG_READ1(long, "semaphore_signal", semaphore_t,"semaphore");
}


PRE(semaphore_signal_all)
{
   PRINT("semaphore_signal_all(%s)", name_for_port(ARG1));
   PRE_REG_READ1(long, "semaphore_signal_all", semaphore_t,"semaphore");
}


PRE(semaphore_signal_thread)
{
   PRINT("semaphore_signal_thread(%s, %s)", 
         name_for_port(ARG1), name_for_port(ARG2));
   PRE_REG_READ2(long, "semaphore_signal_thread", 
                 semaphore_t,"semaphore", mach_port_t,"thread");
}


PRE(semaphore_wait)
{
   PRINT("semaphore_wait(%s)", name_for_port(ARG1));
   PRE_REG_READ1(long, "semaphore_signal", semaphore_t,"semaphore");

   *flags |= SfMayBlock;
}


PRE(semaphore_wait_signal)
{
   PRINT("semaphore_wait_signal(%s, %s)", 
         name_for_port(ARG1), name_for_port(ARG2));
   PRE_REG_READ2(long, "semaphore_wait_signal", 
                 semaphore_t,"wait_semaphore", 
                 semaphore_t,"signal_semaphore");

   *flags |= SfMayBlock;
}


PRE(semaphore_timedwait)
{
   PRINT("semaphore_timedwait(%s, %g seconds)",
         name_for_port(ARG1), ARG2+ARG3/1000000000.0);
   PRE_REG_READ3(long, "semaphore_wait_signal", 
                 semaphore_t,"semaphore", 
                 int,"wait_time_hi", 
                 int,"wait_time_lo");
   
   *flags |= SfMayBlock;
}


PRE(semaphore_timedwait_signal)
{
   PRINT("semaphore_wait_signal(wait %s, signal %s, %g seconds)",
         name_for_port(ARG1), name_for_port(ARG2), ARG3+ARG4/1000000000.0);
   PRE_REG_READ4(long, "semaphore_wait_signal", 
                 semaphore_t,"wait_semaphore", 
                 semaphore_t,"signal_semaphore", 
                 int,"wait_time_hi", 
                 int,"wait_time_lo");

   *flags |= SfMayBlock;
}


PRE(sys___semwait_signal)
{
   PRINT("sys___semwait_signal(wait %s, signal %s, %d, %d, %g seconds)", 
         name_for_port(ARG1), name_for_port(ARG2), ARG3, ARG4, ARG5+ARG6/1000000000.0);
   PRE_REG_READ6(long, "sys___semwait_signal", 
                 int,"cond_sem", int,"mutex_sem",
                 int,"timeout", int,"relative", 
                 vki_time_t,"tv_sec", int,"tv_nsec");

   *flags |= SfMayBlock;
}


PRE(task_for_pid)
{
   PRINT("task_for_pid(%s, %d, %p)", name_for_port(ARG1), ARG2, ARG3);
   PRE_REG_READ3(long, "task_for_pid", 
                 mach_port_t,"target", 
                 vki_pid_t, "pid", mach_port_t *,"task");
   PRE_MEM_WRITE("task_for_pid(task)", ARG3, sizeof(mach_port_t));
}

POST(task_for_pid)
{
   mach_port_t task;

   POST_MEM_WRITE(ARG3, sizeof(mach_port_t));

   task = *(mach_port_t *)ARG3;
   record_named_port(tid, task, MACH_PORT_RIGHT_SEND, "task-%p");
   PRINT("task 0x%x", task);
}


PRE(pid_for_task)
{
   PRINT("pid_for_task(%s, %p)", name_for_port(ARG1), ARG2);
   PRE_REG_READ2(long, "task_for_pid", mach_port_t,"task", vki_pid_t *,"pid");
   PRE_MEM_WRITE("task_for_pid(pid)", ARG2, sizeof(vki_pid_t));
}

POST(pid_for_task)
{
   vki_pid_t pid;

   POST_MEM_WRITE(ARG2, sizeof(vki_pid_t));

   pid = *(vki_pid_t *)ARG2;
   PRINT("pid %u", pid);
}


PRE(mach_timebase_info)
{
   PRINT("mach_timebase_info(%p)", ARG1);
   PRE_REG_READ1(long, "mach_timebase_info", void *,"info");
   PRE_MEM_WRITE("mach_timebase_info(info)", ARG1, sizeof(struct vki_mach_timebase_info));
}

POST(mach_timebase_info)
{
   POST_MEM_WRITE(ARG1, sizeof(struct vki_mach_timebase_info));
}


PRE(mach_wait_until)
{
#if VG_WORDSIZE == 8
   PRINT("mach_wait_until(%llu)", ARG1);
   PRE_REG_READ1(long, "mach_wait_until", 
                 unsigned long long,"deadline");
#else   
   PRINT("mach_wait_until(%llu)", LOHI64(ARG1, ARG2));
   PRE_REG_READ2(long, "mach_wait_until", 
                 int,"deadline_hi", int,"deadline_lo");
#endif   
   *flags |= SfMayBlock;
}


PRE(mk_timer_create)
{
   PRINT("mk_timer_create()");
   PRE_REG_READ0(long, "mk_timer_create");
}

POST(mk_timer_create)
{
   record_named_port(tid, RES, MACH_PORT_RIGHT_SEND, "mk_timer-%p");
}


PRE(mk_timer_destroy)
{
   PRINT("mk_timer_destroy(%s)", name_for_port(ARG1));
   PRE_REG_READ1(long, "mk_timer_destroy", mach_port_t,"name");

   // Must block to prevent race (other thread allocates and 
   // notifies after we deallocate but before we notify)
   *flags &= ~SfMayBlock;
}

POST(mk_timer_destroy)
{
   // Must have cleared SfMayBlock in PRE to prevent race
   record_port_destroy(ARG1);
}


PRE(mk_timer_arm)
{
#if VG_WORDSIZE == 8
   PRINT("mk_timer_arm(%s, %llu)", name_for_port(ARG1), ARG2);
   PRE_REG_READ2(long, "mk_timer_arm", mach_port_t,"name", 
                 unsigned long,"expire_time");
#else
   PRINT("mk_timer_arm(%s, %llu)", name_for_port(ARG1), LOHI64(ARG2, ARG3));
   PRE_REG_READ3(long, "mk_timer_arm", mach_port_t,"name", 
                 int,"expire_time_hi", int,"expire_time_lo");
#endif
}


PRE(mk_timer_cancel)
{
   PRINT("mk_timer_cancel(%s, %p)", name_for_port(ARG1), ARG2);
   PRE_REG_READ2(long, "mk_timer_cancel", 
                 mach_port_t,"name", Addr,"result_time");
   if (ARG2) {
      PRE_MEM_WRITE("mk_timer_cancel(result_time)", ARG2,sizeof(vki_uint64_t));
   }
}

POST(mk_timer_cancel)
{
   if (ARG2) {
      POST_MEM_WRITE(ARG2, sizeof(vki_uint64_t));
   }
}


PRE(iokit_user_client_trap)
{
   PRINT("iokit_user_client_trap(%s, %d, %llx, %llx, %llx, %llx, %llx, %llx)",
         name_for_port(ARG1), ARG2, ARG3, ARG4, ARG5, ARG6, ARG7, ARG8);
   PRE_REG_READ8(kern_return_t, "iokit_user_client_trap", 
                 mach_port_t,connect, unsigned int,index, 
                 uintptr_t,p1, uintptr_t,p2, uintptr_t,p3, 
                 uintptr_t,p4, uintptr_t,p5, uintptr_t,p6);

   // can't do anything else with this in general
   // might be able to use connect+index to choose something sometimes
}

POST(iokit_user_client_trap)
{
   VG_(sync_mappings)("after", "iokit_user_client_trap", ARG2);
}


/*
// GrP fixme gone in Leopard
PRE(MKGetTimeBaseInfo)
{
   PRINT("MKGetTimeBaseInfo(%p, %p, %p, %p, %p)", 
         ARG1, ARG2, ARG3, ARG4, ARG5);
   PRE_REG_READ5(long, "MKGetTimeBaseInfo", void*,"delta", 
                 void*,"abs_to_ns_numer", void*,"abs_to_ns_denom", 
                 void*,"proc_to_abs_numer", void*,"proc_to_abs_denom");

   PRE_MEM_WRITE("MKGetTimeBaseInfo(delta)", 
                 ARG1, sizeof(vki_uint32_t));
   PRE_MEM_WRITE("MKGetTimeBaseInfo(abs_to_ns_numer)", 
                 ARG1, sizeof(vki_uint32_t));
   PRE_MEM_WRITE("MKGetTimeBaseInfo(abs_to_ns_denom)", 
                 ARG1, sizeof(vki_uint32_t));
   PRE_MEM_WRITE("MKGetTimeBaseInfo(proc_to_abs_numer)", 
                 ARG1, sizeof(vki_uint32_t));
   PRE_MEM_WRITE("MKGetTimeBaseInfo(proc_to_abs_denom)", 
                 ARG1, sizeof(vki_uint32_t));
}

POST(MKGetTimeBaseInfo)
{
   POST_MEM_WRITE(ARG1, sizeof(vki_uint32_t));
   POST_MEM_WRITE(ARG1, sizeof(vki_uint32_t));
   POST_MEM_WRITE(ARG1, sizeof(vki_uint32_t));
   POST_MEM_WRITE(ARG1, sizeof(vki_uint32_t));
   POST_MEM_WRITE(ARG1, sizeof(vki_uint32_t));
}
*/


PRE(swtch)
{
   PRINT("swtch ( )");
   PRE_REG_READ0(long, "swtch");

   *flags |= SfMayBlock;
}


PRE(swtch_pri)
{
   PRINT("swtch ( %d )", ARG1);
   PRE_REG_READ1(long, "swtch", int,"pri");

   *flags |= SfMayBlock;
}


/* ---------------------------------------------------------------------
   machine-dependent traps
   ------------------------------------------------------------------ */

#if defined(VGA_x86)
static VexGuestX86SegDescr* alloc_zeroed_x86_LDT ( void )
{
   Int nbytes = VEX_GUEST_X86_LDT_NENT * sizeof(VexGuestX86SegDescr);
   return VG_(arena_calloc)(VG_AR_CORE, "syswrap-darwin.ldt", nbytes, 1);
}
#endif

PRE(pthread_set_self)
{
   PRINT("pthread_set_self ( 0x%x )", ARG1);
   PRE_REG_READ1(void, "pthread_set_self", struct pthread_t *, self);

#if defined(VGA_x86)
   // GrP fixme hack this isn't really pthread_set_self
   // Point the USER_CTHREAD ldt entry (slot 6, reg 0x37) at this pthread
   {
      VexGuestX86SegDescr *ldt;
      ThreadState *tst = VG_(get_ThreadState)(tid);
      ldt = (VexGuestX86SegDescr *)tst->arch.vex.guest_LDT;
      if (!ldt) {
         ldt = alloc_zeroed_x86_LDT();
         tst->arch.vex.guest_LDT = (HWord)ldt;
      }
      VG_(memset)(&ldt[6], 0, sizeof(ldt[6]));
      ldt[6].LdtEnt.Bits.LimitLow = 1;
      ldt[6].LdtEnt.Bits.LimitHi = 0;
      ldt[6].LdtEnt.Bits.BaseLow = ARG1 & 0xffff;
      ldt[6].LdtEnt.Bits.BaseMid = (ARG1 >> 16) & 0xff;
      ldt[6].LdtEnt.Bits.BaseHi = (ARG1 >> 24) & 0xff;
      ldt[6].LdtEnt.Bits.Pres = 1; // ACC_P
      ldt[6].LdtEnt.Bits.Dpl = 3; // ACC_PL_U
      ldt[6].LdtEnt.Bits.Type = 0x12; // ACC_DATA_W
      ldt[6].LdtEnt.Bits.Granularity = 1;  // SZ_G
      ldt[6].LdtEnt.Bits.Default_Big = 1;  // SZ_32
      
      tst->os_state.pthread = ARG1;
      tst->arch.vex.guest_GS = 0x37;
      SET_STATUS_Success(0x37);      
   }

#elif defined(VGA_amd64)
   // GrP fixme bigger hack than x86
   {
      ThreadState *tst = VG_(get_ThreadState)(tid);
      tst->os_state.pthread = ARG1;
      tst->arch.vex.guest_GS_0x60 = ARG1;
      SET_STATUS_Success(0x60);
   }

#else
#error unknown architecture
#endif
}


/* ---------------------------------------------------------------------
   syscall tables
   ------------------------------------------------------------------ */

/* Add a Darwin-specific, arch-independent wrapper to a syscall table. */
#define MACX_(sysno, name)    WRAPPER_ENTRY_X_(darwin, VG_DARWIN_SYSNO_INDEX(sysno), name) 
#define MACXY(sysno, name)    WRAPPER_ENTRY_XY(darwin, VG_DARWIN_SYSNO_INDEX(sysno), name)
#define _____(sysno) GENX_(sysno, sys_ni_syscall)

/*
  // _____ : unsupported by the kernel
     _____ : unimplemented in valgrind (sys_ni_syscall)
     GEN   : handlers are in syswrap-generic.c
     MAC   : handlers are in this file
        X_ : PRE handler only
        XY : PRE and POST handlers
*/
const SyscallTableEntry ML_(syscall_table)[] = {
   _____(__NR_syscall),   // 0
   MACX_(__NR_exit, sys_exit), 
   GENX_(__NR_fork, sys_fork), 
   GENXY(__NR_read, sys_read), 
   GENX_(__NR_write, sys_write), 
   GENXY(__NR_open, sys_open), 
   GENXY(__NR_close, sys_close), 
   GENXY(__NR_wait4, sys_wait4), 
// _____(__NR_creat), 
   GENX_(__NR_link, sys_link), 
   GENX_(__NR_unlink, sys_unlink), 
// _____(__NR_execv), 
   GENX_(__NR_chdir, sys_chdir), 
   GENX_(__NR_fchdir, sys_fchdir), 
   GENX_(__NR_mknod, sys_mknod), 
   GENX_(__NR_chmod, sys_chmod), 
   GENX_(__NR_chown, sys_chown), 
// _____(__NR_break), 
   MACXY(__NR_getfsstat, sys_getfsstat), 
// _____(__NR_lseek), 
   GENX_(__NR_getpid, sys_getpid),     // 20
// _____(__NR_mount), 
// _____(__NR_umount), 
   GENX_(__NR_setuid, sys_setuid), 
   GENX_(__NR_getuid, sys_getuid), 
   GENX_(__NR_geteuid, sys_geteuid), 
   MACX_(__NR_ptrace, sys_ptrace), 
   MACXY(__NR_recvmsg, sys_recvmsg), 
   MACX_(__NR_sendmsg, sys_sendmsg), 
   MACXY(__NR_recvfrom, sys_recvfrom), 
   MACXY(__NR_accept, sys_accept), 
   MACXY(__NR_getpeername, sys_getpeername), 
   MACXY(__NR_getsockname, sys_getsockname), 
   GENX_(__NR_access, sys_access), 
   MACX_(__NR_chflags, sys_chflags), 
   MACX_(__NR_fchflags, sys_fchflags), 
   GENX_(__NR_sync, sys_sync), 
   GENX_(__NR_kill, sys_kill), 
// _____(__NR_stat), 
   GENX_(__NR_getppid, sys_getppid), 
// _____(__NR_lstat),      // 40
   GENXY(__NR_dup, sys_dup), 
   MACXY(__NR_pipe, sys_pipe), 
   GENX_(__NR_getegid, sys_getegid), 
   _____(__NR_profil), 
// _____(__NR_ktrace), 
   MACX_(__NR_sigaction, sys_sigaction), 
   GENX_(__NR_getgid, sys_getgid), 
   MACXY(__NR_sigprocmask, sys_sigprocmask), 
   MACXY(__NR_getlogin, sys_getlogin), 
   _____(__NR_setlogin), 
   _____(__NR_acct), 
   _____(__NR_sigpending), 
   MACX_(__NR_sigaltstack, sys_sigaltstack), 
   MACXY(__NR_ioctl, sys_ioctl), 
   _____(__NR_reboot), 
   _____(__NR_revoke), 
   _____(__NR_symlink), 
   GENX_(__NR_readlink, sys_readlink), 
   GENX_(__NR_execve, sys_execve), 
   GENX_(__NR_umask, sys_umask),     // 60
   GENX_(__NR_chroot, sys_chroot), 
// _____(__NR_fstat), 
// _____(__NR_63), 
// _____(__NR_getpagesize), 
   GENX_(__NR_msync, sys_msync), 
   _____(__NR_vfork), 
// _____(__NR_vread), 
// _____(__NR_vwrite), 
// _____(__NR_sbrk), 
// _____(__NR_sstk), 
// _____(__NR_mmap), 
// _____(__NR_vadvise), 
   GENXY(__NR_munmap, sys_munmap), 
   GENXY(__NR_mprotect, sys_mprotect), 
   GENX_(__NR_madvise, sys_madvise), 
// _____(__NR_vhangup), 
// _____(__NR_vlimit), 
   _____(__NR_mincore), 
   GENXY(__NR_getgroups, sys_getgroups), 
   _____(__NR_setgroups),   // 80
   GENX_(__NR_getpgrp, sys_getpgrp), 
   _____(__NR_setpgid), 
   GENX_(__NR_setitimer, sys_setitimer), 
// _____(__NR_wait), 
   _____(__NR_swapon), 
   GENX_(__NR_getitimer, sys_getitimer), 
// _____(__NR_gethostname), 
// _____(__NR_sethostname), 
   MACXY(__NR_getdtablesize, sys_getdtablesize), 
   GENX_(__NR_dup2, sys_dup2), 
// _____(__NR_getdopt), 
   MACXY(__NR_fcntl, sys_fcntl), 
   GENX_(__NR_select, sys_select), 
// _____(__NR_setdopt), 
   GENX_(__NR_fsync, sys_fsync), 
   GENX_(__NR_setpriority, sys_setpriority), 
   MACXY(__NR_socket, sys_socket), 
   MACX_(__NR_connect, sys_connect), 
// _____(__NR_accept), 
   GENX_(__NR_getpriority, sys_getpriority),   // 100
// _____(__NR_send), 
// _____(__NR_recv), 
// _____(__NR_sigreturn), 
   MACX_(__NR_bind, sys_bind), 
   MACX_(__NR_setsockopt, sys_setsockopt), 
   MACX_(__NR_listen, sys_listen), 
// _____(__NR_vtimes), 
// _____(__NR_sigvec), 
// _____(__NR_sigblock), 
// _____(__NR_sigsetmask), 
   _____(__NR_sigsuspend), 
// _____(__NR_sigstack), 
// _____(__NR_recvmsg), 
// _____(__NR_sendmsg), 
// _____(__NR_vtrace), 
   GENXY(__NR_gettimeofday, sys_gettimeofday), 
   GENXY(__NR_getrusage, sys_getrusage), 
   MACXY(__NR_getsockopt, sys_getsockopt), 
// _____(__NR_resuba), 
   GENXY(__NR_readv, sys_readv),        // 120
   GENX_(__NR_writev, sys_writev), 
   _____(__NR_settimeofday), 
   GENX_(__NR_fchown, sys_fchown), 
   GENX_(__NR_fchmod, sys_fchmod), 
// _____(__NR_recvfrom), 
   _____(__NR_setreuid), 
   _____(__NR_setregid), 
   GENX_(__NR_rename, sys_rename), 
// _____(__NR_truncate), 
// _____(__NR_ftruncate), 
   GENX_(__NR_flock, sys_flock), 
   _____(__NR_mkfifo), 
   MACX_(__NR_sendto, sys_sendto), 
   MACX_(__NR_shutdown, sys_shutdown), 
   MACXY(__NR_socketpair, sys_socketpair), 
   GENX_(__NR_mkdir, sys_mkdir), 
   GENX_(__NR_rmdir, sys_rmdir), 
   GENX_(__NR_utimes, sys_utimes), 
   _____(__NR_futimes), 
   _____(__NR_adjtime),     // 140
// _____(__NR_getpeername), 
   MACXY(__NR_gethostuuid, sys_gethostuuid), 
// _____(__NR_sethostid), 
// _____(__NR_getrlimit), 
// _____(__NR_setrlimit), 
// _____(__NR_killpg), 
   GENX_(__NR_setsid, sys_setsid), 
// _____(__NR_setquota), 
// _____(__NR_qquota), 
// _____(__NR_getsockname), 
   _____(__NR_getpgid), 
   _____(__NR_setprivexec), 
   GENXY(__NR_pread, sys_pread64), 
   GENX_(__NR_pwrite, sys_pwrite64), 
   _____(__NR_nfssvc), 
// _____(__NR_getdirentries), 
   GENXY(__NR_statfs, sys_statfs), 
   GENXY(__NR_fstatfs, sys_fstatfs), 
   _____(__NR_unmount), 
// _____(__NR_async_daemon),   // 160
   _____(__NR_getfh), 
// _____(__NR_getdomainname), 
// _____(__NR_setdomainname), 
// _____(__NR_164), 
   _____(__NR_quotactl), 
// _____(__NR_exportfs), 
   _____(__NR_mount), 
// _____(__NR_ustat), 
   _____(__NR_csops), 
// _____(__NR_table), 
// _____(__NR_wait3), 
// _____(__NR_rpause), 
   _____(__NR_waitid), 
// _____(__NR_getdents), 
// _____(__NR_gc_control), 
   _____(__NR_add_profil), 
// _____(__NR_177), 
// _____(__NR_178), 
// _____(__NR_179), 
   MACX_(__NR_kdebug_trace, sys_kdebug_trace),   // 180
   GENX_(__NR_setgid, sys_setgid), 
   MACX_(__NR_setegid, sys_setegid), 
   MACX_(__NR_seteuid, sys_seteuid), 
   _____(__NR_sigreturn), 
   _____(__NR_chud), 
// _____(__NR_186), 
// _____(__NR_187), 
   GENXY(__NR_stat, sys_newstat), 
   GENXY(__NR_fstat, sys_newfstat), 
   GENXY(__NR_lstat, sys_newlstat), 
   MACX_(__NR_pathconf, sys_pathconf), 
   MACX_(__NR_fpathconf, sys_fpathconf), 
// _____(__NR_193), 
   GENXY(__NR_getrlimit, sys_getrlimit), 
   GENX_(__NR_setrlimit, sys_setrlimit), 
   MACXY(__NR_getdirentries, sys_getdirentries), 
   MACXY(__NR_mmap, sys_mmap), 
// _____(__NR___syscall), 
   MACX_(__NR_lseek, sys_lseek), 
   GENX_(__NR_truncate, sys_truncate64),   // 200
   GENX_(__NR_ftruncate, sys_ftruncate64), 
   MACXY(__NR___sysctl, sys_sysctl), 
   GENX_(__NR_mlock, sys_mlock), 
   GENX_(__NR_munlock, sys_munlock), 
   _____(__NR_undelete), 
   _____(__NR_ATsocket), 
   _____(__NR_ATgetmsg), 
   _____(__NR_ATputmsg), 
   _____(__NR_ATPsndreq), 
   _____(__NR_ATPsndrsp), 
   _____(__NR_ATPgetreq), 
   _____(__NR_ATPgetrsp), 
// _____(__NR_213), 
   _____(__NR_kqueue_from_portset_np), 
   _____(__NR_kqueue_portset_np), 
   _____(__NR_mkcomplex), 
   _____(__NR_statv), 
   _____(__NR_lstatv), 
   _____(__NR_fstatv), 
   MACXY(__NR_getattrlist, sys_getattrlist),   // 220
   MACX_(__NR_setattrlist, sys_setattrlist), 
   MACXY(__NR_getdirentriesattr, sys_getdirentriesattr), 
   _____(__NR_exchangedata), 
// _____(__NR_checkuseraccess), 
   _____(__NR_searchfs), 
   GENX_(__NR_delete, sys_unlink), 
   _____(__NR_copyfile), 
// _____(__NR_228), 
// _____(__NR_229), 
   GENXY(__NR_poll, sys_poll), 
   MACX_(__NR_watchevent, sys_watchevent), 
   MACXY(__NR_waitevent, sys_waitevent), 
   MACX_(__NR_modwatch, sys_modwatch), 
   MACXY(__NR_getxattr, sys_getxattr), 
   MACXY(__NR_fgetxattr, sys_fgetxattr), 
   MACX_(__NR_setxattr, sys_setxattr), 
   MACX_(__NR_fsetxattr, sys_fsetxattr), 
   _____(__NR_removexattr), 
   _____(__NR_fremovexattr), 
   MACXY(__NR_listxattr, sys_listxattr),    // 240
   _____(__NR_flistxattr), 
   MACXY(__NR_fsctl, sys_fsctl), 
   MACX_(__NR_initgroups, sys_initgroups), 
   _____(__NR_posix_spawn), 
// _____(__NR_245), 
// _____(__NR_246), 
   _____(__NR_nfsclnt), 
   _____(__NR_fhopen), 
// _____(__NR_249), 
   _____(__NR_minherit), 
   _____(__NR_semsys), 
   _____(__NR_msgsys), 
   _____(__NR_shmsys), 
   MACXY(__NR_semctl, sys_semctl), 
   MACX_(__NR_semget, sys_semget), 
   MACX_(__NR_semop, sys_semop), 
//  _____(__NR_257), 
   _____(__NR_msgctl), 
   _____(__NR_msgget), 
   _____(__NR_msgsnd),   // 260
   _____(__NR_msgrcv), 
   _____(__NR_shmat), 
   _____(__NR_shmctl), 
   _____(__NR_shmdt), 
   _____(__NR_shmget), 
   MACXY(__NR_shm_open, sys_shm_open), 
   _____(__NR_shm_unlink), 
   _____(__NR_sem_open), 
   _____(__NR_sem_close), 
   _____(__NR_sem_unlink), 
   _____(__NR_sem_wait), 
   _____(__NR_sem_trywait), 
   _____(__NR_sem_post), 
   _____(__NR_sem_getvalue), 
   _____(__NR_sem_init), 
   _____(__NR_sem_destroy), 
   _____(__NR_open_extended), 
   _____(__NR_umask_extended), 
   MACXY(__NR_stat_extended, sys_statx), 
   _____(__NR_lstat_extended),   // 280
   _____(__NR_fstat_extended), 
   _____(__NR_chmod_extended), 
   _____(__NR_fchmod_extended), 
   _____(__NR_access_extended), 
   MACX_(__NR_settid, sys_settid), 
   _____(__NR_gettid), 
   _____(__NR_setsgroups), 
   _____(__NR_getsgroups), 
   _____(__NR_setwgroups), 
   _____(__NR_getwgroups), 
   _____(__NR_mkfifo_extended), 
   _____(__NR_mkdir_extended), 
   _____(__NR_identitysvc), 
   _____(__NR_shared_region_check_np), 
   _____(__NR_shared_region_map_np), 
// _____(__NR_load_shared_file), 
// _____(__NR_reset_shared_file), 
// _____(__NR_new_system_shared_regions), 
// _____(__NR_shared_region_map_file_np), 
// _____(__NR_shared_region_make_private_np),   // 300
   _____(__NR___pthread_mutex_destroy), 
   _____(__NR___pthread_mutex_init), 
   _____(__NR___pthread_mutex_lock), 
   _____(__NR___pthread_mutex_trylock), 
   _____(__NR___pthread_mutex_unlock), 
   _____(__NR___pthread_cond_init), 
   _____(__NR___pthread_cond_destroy), 
   _____(__NR___pthread_cond_broadcast), 
   _____(__NR___pthread_cond_signal), 
   _____(__NR_getsid), 
   _____(__NR_settid_with_pid), 
   _____(__NR___pthread_cond_timedwait), 
   _____(__NR_aio_fsync), 
   _____(__NR_aio_return), 
   _____(__NR_aio_suspend), 
   _____(__NR_aio_cancel), 
   _____(__NR_aio_error), 
   _____(__NR_aio_read), 
   _____(__NR_aio_write), 
   _____(__NR_lio_listio),   // 320
   _____(__NR___pthread_cond_wait), 
   _____(__NR_iopolicysys), 
// _____(__NR_323), 
   _____(__NR_mlockall), 
   _____(__NR_munlockall), 
// _____(__NR_326), 
   MACX_(__NR_issetugid, sys_issetugid), 
   _____(__NR___pthread_kill), 
   MACX_(__NR___pthread_sigmask, sys___pthread_sigmask), 
   _____(__NR___sigwait), 
   MACX_(__NR___disable_threadsignal, sys___disable_threadsignal), 
   _____(__NR___pthread_markcancel), 
   _____(__NR___pthread_canceled), 
   MACX_(__NR___semwait_signal, sys___semwait_signal), 
// _____(__NR_utrace), 
   _____(__NR_proc_info), 
   MACXY(__NR_sendfile, sys_sendfile), 
   MACXY(__NR_stat64, sys_stat64), 
   MACXY(__NR_fstat64, sys_fstat64), 
   MACXY(__NR_lstat64, sys_lstat64),    // 340
   _____(__NR_stat64_extended), 
   _____(__NR_lstat64_extended), 
   _____(__NR_fstat64_extended), 
   MACXY(__NR_getdirentries64, sys_getdirentries64), 
   MACXY(__NR_statfs64, sys_statfs64), 
   MACXY(__NR_fstatfs64, sys_fstatfs64), 
   _____(__NR_getfsstat64), 
   _____(__NR___pthread_chdir), 
   _____(__NR___pthread_fchdir), 
   _____(__NR_audit), 
   MACXY(__NR_auditon, sys_auditon), 
// _____(__NR_352), 
   _____(__NR_getauid), 
   _____(__NR_setauid), 
   _____(__NR_getaudit), 
   _____(__NR_setaudit), 
   _____(__NR_getaudit_addr), 
   _____(__NR_setaudit_addr), 
   _____(__NR_auditctl), 
   MACXY(__NR_bsdthread_create, sys_bsdthread_create),   // 360
   MACX_(__NR_bsdthread_terminate, sys_bsdthread_terminate), 
   MACX_(__NR_kqueue, sys_kqueue), 
   MACXY(__NR_kevent, sys_kevent), 
   _____(__NR_lchown), 
   _____(__NR_stack_snapshot), 
   MACX_(__NR_bsdthread_register, sys_bsdthread_register), 
   MACX_(__NR_workq_open, sys_workq_open), 
   MACXY(__NR_workq_ops, sys_workq_ops), 
// _____(__NR_369),
// _____(__NR_370),
// _____(__NR_371), 
// _____(__NR_372),
// _____(__NR_373),
// _____(__NR_374),
// _____(__NR_375),
// _____(__NR_376),
// _____(__NR_377),
// _____(__NR_378),
// _____(__NR_379),
   _____(__NR___mac_execve),   // 380
   MACX_(__NR___mac_syscall, sys___mac_syscall),
   _____(__NR___mac_get_file),
   _____(__NR___mac_set_file),
   _____(__NR___mac_get_link),
   _____(__NR___mac_set_link),
   _____(__NR___mac_get_proc),
   _____(__NR___mac_set_proc),
   _____(__NR___mac_get_fd),
   _____(__NR___mac_set_fd),
   _____(__NR___mac_get_pid),
   _____(__NR___mac_get_lcid),
   _____(__NR___mac_get_lctx),
   _____(__NR___mac_set_lctx),
   _____(__NR_setlcid),
   _____(__NR_getlcid),
   // GrP fixme need any special nocancel handling?
   GENXY(__NR_read_nocancel, sys_read),
   GENX_(__NR_write_nocancel, sys_write),
   GENXY(__NR_open_nocancel, sys_open),
   GENXY(__NR_close_nocancel, sys_close),
   _____(__NR_wait4_nocancel),   // 400
   MACXY(__NR_recvmsg_nocancel, sys_recvmsg),
   MACX_(__NR_sendmsg_nocancel, sys_sendmsg),
   MACXY(__NR_recvfrom_nocancel, sys_recvfrom),
   MACXY(__NR_accept_nocancel, sys_accept),
   GENX_(__NR_msync_nocancel, sys_msync),
   MACXY(__NR_fcntl_nocancel, sys_fcntl),
   GENX_(__NR_select_nocancel, sys_select),
   GENX_(__NR_fsync_nocancel, sys_fsync),
   MACX_(__NR_connect_nocancel, sys_connect),
   _____(__NR_sigsuspend_nocancel),
   GENXY(__NR_readv_nocancel, sys_readv),
   GENX_(__NR_writev_nocancel, sys_writev),
   MACX_(__NR_sendto_nocancel, sys_sendto),
   GENXY(__NR_pread_nocancel, sys_pread64),
   GENX_(__NR_pwrite_nocancel, sys_pwrite64),
   _____(__NR_waitid_nocancel),
   GENXY(__NR_poll_nocancel, sys_poll),
   _____(__NR_msgsnd_nocancel),
   _____(__NR_msgrcv_nocancel),
   _____(__NR_sem_wait_nocancel),   // 420
   _____(__NR_aio_suspend_nocancel),
   _____(__NR___sigwait_nocancel),
   MACX_(__NR___semwait_signal_nocancel, sys___semwait_signal), 
   _____(__NR___mac_mount),
   _____(__NR___mac_get_mount),
   _____(__NR___mac_getfsstat),
   _____(__NR_MAXSYSCALL)
};


// Mach traps use negative syscall numbers. 
// Use ML_(mach_trap_table)[-mach_trap_number] .

const SyscallTableEntry ML_(mach_trap_table)[] = {
// _____(__NR_0), 
// _____(__NR_1), 
// _____(__NR_2), 
// _____(__NR_3), 
// _____(__NR_4), 
// _____(__NR_5), 
// _____(__NR_6), 
// _____(__NR_7), 
// _____(__NR_8), 
// _____(__NR_9), 
// _____(__NR_10), 
// _____(__NR_11), 
// _____(__NR_12), 
// _____(__NR_13), 
// _____(__NR_14), 
// _____(__NR_15), 
// _____(__NR_16), 
// _____(__NR_17), 
// _____(__NR_18), 
// _____(__NR_19), 
// _____(__NR_20),   // -20
// _____(__NR_21), 
// _____(__NR_22), 
// _____(__NR_23), 
// _____(__NR_24), 
// _____(__NR_25), 
   MACXY(__NR_mach_reply_port, mach_reply_port), 
   MACXY(__NR_thread_self_trap, mach_thread_self), 
   MACXY(__NR_task_self_trap, mach_task_self), 
   MACXY(__NR_host_self_trap, mach_host_self), 
// _____(__NR_30), 
   MACXY(__NR_mach_msg_trap, mach_msg), 
   _____(__NR_mach_msg_overwrite_trap), 
   MACX_(__NR_semaphore_signal_trap, semaphore_signal), 
   MACX_(__NR_semaphore_signal_all_trap, semaphore_signal_all), 
   MACX_(__NR_semaphore_signal_thread_trap, semaphore_signal_thread), 
   MACX_(__NR_semaphore_wait_trap, semaphore_wait), 
   MACX_(__NR_semaphore_wait_signal_trap, semaphore_wait_signal), 
   MACX_(__NR_semaphore_timedwait_trap, semaphore_timedwait), 
   MACX_(__NR_semaphore_timedwait_signal_trap, semaphore_timedwait_signal), 
// _____(__NR_40),    // -40
#if defined(VGA_x86)
   _____(__NR_init_process), 
// _____(__NR_42), 
   _____(__NR_map_fd), 
#else
// _____(__NR_41), 
// _____(__NR_42), 
// _____(__NR_43), 
#endif
   _____(__NR_task_name_for_pid), 
   MACXY(__NR_task_for_pid, task_for_pid), 
   MACXY(__NR_pid_for_task, pid_for_task), 
// _____(__NR_47), 
#if defined(VGA_x86)
   _____(__NR_macx_swapon), 
   _____(__NR_macx_swapoff), 
// _____(__NR_50), 
   _____(__NR_macx_triggers), 
   _____(__NR_macx_backing_store_suspend), 
   _____(__NR_macx_backing_store_recovery), 
#else
// _____(__NR_48), 
// _____(__NR_49), 
// _____(__NR_50), 
// _____(__NR_51), 
// _____(__NR_52), 
// _____(__NR_53), 
#endif
// _____(__NR_54), 
// _____(__NR_55), 
// _____(__NR_56), 
// _____(__NR_57), 
// _____(__NR_58), 
   MACX_(__NR_swtch_pri, swtch_pri), 
   MACX_(__NR_swtch, swtch),   // -60
   MACX_(__NR_syscall_thread_switch, syscall_thread_switch), 
   _____(__NR_clock_sleep_trap), 
// _____(__NR_63), 
// _____(__NR_64), 
// _____(__NR_65), 
// _____(__NR_66), 
// _____(__NR_67), 
// _____(__NR_68), 
// _____(__NR_69), 
// _____(__NR_70), 
// _____(__NR_71), 
// _____(__NR_72), 
// _____(__NR_73), 
// _____(__NR_74), 
// _____(__NR_75), 
// _____(__NR_76), 
// _____(__NR_77), 
// _____(__NR_78), 
// _____(__NR_79), 
// _____(__NR_80),   // -80
// _____(__NR_81), 
// _____(__NR_82), 
// _____(__NR_83), 
// _____(__NR_84), 
// _____(__NR_85), 
// _____(__NR_86), 
// _____(__NR_87), 
// _____(__NR_88), 
   MACXY(__NR_mach_timebase_info, mach_timebase_info), 
   MACX_(__NR_mach_wait_until, mach_wait_until), 
   MACXY(__NR_mk_timer_create, mk_timer_create), 
   MACXY(__NR_mk_timer_destroy, mk_timer_destroy), 
   MACX_(__NR_mk_timer_arm, mk_timer_arm), 
   MACXY(__NR_mk_timer_cancel, mk_timer_cancel), 
// _____(__NR_95), 
// _____(__NR_96), 
// _____(__NR_97), 
// _____(__NR_98), 
// _____(__NR_99), 
   MACXY(__NR_iokit_user_client_trap, iokit_user_client_trap), // -100
};


// Machine-dependent traps have wacky syscall numbers, and use the Mach trap 
// calling convention instead of the syscall convention.
// Use ML_(mdep_trap_table)[syscallno - ML_(mdep_trap_base)] .

#if defined(VGA_x86)
const SyscallTableEntry ML_(mdep_trap_table)[] = {
   MACX_(__NR_pthread_set_self, pthread_set_self), 
};
#elif defined(VGA_amd64)
const SyscallTableEntry ML_(mdep_trap_table)[] = {
   MACX_(__NR_pthread_set_self, pthread_set_self), 
};
#else
#error unknown architecture
#endif

const UInt ML_(syscall_table_size) = 
            sizeof(ML_(syscall_table)) / sizeof(ML_(syscall_table)[0]);

const UInt ML_(mach_trap_table_size) = 
            sizeof(ML_(mach_trap_table)) / sizeof(ML_(mach_trap_table)[0]);

const UInt ML_(mdep_trap_table_size) = 
            sizeof(ML_(mdep_trap_table)) / sizeof(ML_(mdep_trap_table)[0]);
