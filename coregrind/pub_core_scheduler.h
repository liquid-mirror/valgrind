
/*--------------------------------------------------------------------*/
/*--- The scheduler.                          pub_core_scheduler.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2000-2012 Julian Seward
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

#ifndef __PUB_CORE_SCHEDULER_H
#define __PUB_CORE_SCHEDULER_H

//--------------------------------------------------------------------
// PURPOSE: This module is the scheduler, which is the main loop
// controlling the running of all the program's threads.
// It's at the centre of everything.
//--------------------------------------------------------------------

/* Allocate a new ThreadState */
extern ThreadId VG_(alloc_ThreadState)(void);

/* A thread exits.  tid must currently be running. */
extern void VG_(exit_thread)(ThreadId tid);

/* If 'tid' is blocked in a syscall, send it SIGVGKILL so as to get it
   out of the syscall and onto doing the next thing, whatever that is.
   If it isn't blocked in a syscall, has no effect on the thread. */
extern void VG_(get_thread_out_of_syscall)(ThreadId tid);

/* Nuke all threads except tid. */
extern void VG_(nuke_all_threads_except) ( ThreadId me,
                                           VgSchedReturnCode reason );

/* Make a thread acquire a lock of kind slk.
   slk can be either VgTs_ReadLock or VgTs_WriteLock.
   The thread cannot currently have the big lock.
   This will set the  thread state to VgTs_Runnable.
   By the time it returns, tid will be a running thread.
   The global idea is:
     A thread having the write lock can change 
     shared state/shared data structures.
     A thread having a read lock can read safely shared
     state/shared data structures. 

   Note that not all shared data structures are protected in read
   mode by the shared lock. Having all data structures read-only
   would give a very low level of parallelism. So, a read big lock
   protects many but not all shared data structures.
   The data structures not protected by the big read lock must use
   other techniques to be thread safe such as
     use atomic instruction
     use specific mutex or rw lock
     use lock-less algorithms. 

     ??? Need to describe which data structures are supposed to
     be protected by this big lock ???? */
extern void VG_(acquire_BigLock) ( ThreadId tid, SchedLockKind slk,
                                   const HChar* who );

/* Simple version, which simply acquires the lock, but does not mess
   with the guest state in the same way as the non _LL version
   does. */
extern void VG_(acquire_BigLock_LL) ( ThreadId tid, SchedLockKind slk,
                                      const HChar* who);

/* Set a thread into a sleeping state.  Before the call, the thread
   must be runnable, and holding the CPU lock.  When this call
   returns, the thread will be set to the specified sleeping state,
   and will not be holding the CPU lock.  Note that another
   thread could be running by the time this call returns, so the
   caller must be careful not to touch any shared state.  It is also
   the caller's responsibility to actually block until the thread is
   ready to run again. */
extern void VG_(release_BigLock) ( ThreadId tid,
                                   ThreadStatus state,
                                   const HChar* who );

/* Matching function to acquire_BigLock_LL. */
extern void VG_(release_BigLock_LL) ( ThreadId tid, SchedLockKind slk,
                                      const HChar* who );

/* Whether the specified thread owns the big lock. */
extern Bool VG_(owns_BigLock_LL) ( ThreadId tid );

/* Yield the CPU for a while.  Drops/acquires the lock using the
   normal (non _LL) functions. */
extern void VG_(vg_yield)(void);

// The scheduler.
extern VgSchedReturnCode VG_(scheduler) ( ThreadId tid );

// Initialise, phase 1.  Zero out VG_(threads), decide on the root
// ThreadId and initialise the bigLock.
extern ThreadId VG_(scheduler_init_phase1) ( void );

// Initialise, phase 2.  Is passed the extent of the root thread's
// client stack and the root ThreadId decided on by phase 1.
extern void VG_(scheduler_init_phase2) ( ThreadId main_tid, 
                                         Addr     clstack_end, 
                                         SizeT    clstack_size );

// Allows to disable the polling done to detect vgdb input
// or to force a poll at next scheduler call.
extern void VG_(disable_vgdb_poll) (void );
extern void VG_(force_vgdb_poll) ( void );

/* Stats ... */
extern void VG_(print_scheduler_stats) ( void );

/* Sanity checks which may be done at any time.  The scheduler decides when. */
extern void VG_(sanity_check_general) ( Bool force_expensive );

#endif   // __PUB_CORE_SCHEDULER_H

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
