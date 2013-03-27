
/*--------------------------------------------------------------------*/
/*--- Locking primitives.                                 m_lock.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2012-2012 Philippe Waroquiers philippe.waroquiers@skynet.be

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
#include "pub_core_vkiscnums.h"    // __NR_futex
#include "pub_core_vki.h"

#include "pub_core_syscall.h"

#include "pub_core_libcassert.h"
/// TODO: replace assert by a local redefinition (like the aspacemgr one).

#include "pub_core_libcbase.h"

#include "pub_tool_atomic.h"
#include "pub_tool_lock.h"    /* self */

#include "pub_tool_inner.h"
#if defined(ENABLE_INNER_CLIENT_REQUEST)
#include "helgrind/helgrind.h"
#endif


/* Mutex code derived from glib 2.13, copyright FSF */

/* Mutex lock counter:
   bit 31 clear means unlocked;
   bit 31 set means locked.

   All code that looks at bit 31 first increases the 'number of
   interested threads' usage counter, which is in bits 0-30.

   All negative mutex values indicate that the mutex is still locked.  */

void VG_(mutex_init) ( Mutex* mutex) 
{
   // The futex syscall requires that a futex takes four bytes.
   vg_assert(sizeof(*mutex) == 4);

   // Otherwise hg does not understand that the kernel takes care
   // of no race condition on the mutex Word.
   INNER_REQUEST(VALGRIND_HG_DISABLE_CHECKING(mutex, sizeof(*mutex)));

   *mutex = 0;
   INNER_REQUEST(VALGRIND_HG_MUTEX_INIT_POST(mutex, 0));
}

void VG_(mutex_lock) ( Mutex* mutex)
{
   unsigned int v;
   SysRes sres;

   INNER_REQUEST(VALGRIND_HG_MUTEX_LOCK_PRE(mutex, 0));

   /* Bit 31 was clear, we got the mutex.  (this is the fastpath).  */
   if (atomic_bit_test_set (mutex, 31) == 0) {
      INNER_REQUEST(VALGRIND_HG_MUTEX_LOCK_POST(mutex));
      return;
   }

   atomic_increment (mutex);

   while (1) {
      if (atomic_bit_test_set (mutex, 31) == 0) {
         atomic_decrement (mutex);
         INNER_REQUEST(VALGRIND_HG_MUTEX_LOCK_POST(mutex));
         return;
      }

      /* We have to wait now. First make sure the futex value we are
	 monitoring is truly negative (i.e. locked). */
      v = *mutex;
      if (v >= 0)
         continue;

      sres = VG_(do_syscall3)(__NR_futex, (UWord)mutex,
                              VKI_FUTEX_WAIT | VKI_FUTEX_PRIVATE_FLAG,
                              v);
      if (sr_isError(sres) && sres._val != VKI_EAGAIN) {
         vg_assert(False);
      }
   }
}

void VG_(mutex_unlock) ( Mutex* mutex)
{
   SysRes sres;

   INNER_REQUEST(VALGRIND_HG_MUTEX_UNLOCK_PRE (mutex));
   
   /* Adding 0x80000000 to the counter results in 0 if and only if
      there are not other interested threads - we can return (this is
      the fastpath).  */
   if (atomic_add_zero (mutex, 0x80000000)) {
      INNER_REQUEST(VALGRIND_HG_MUTEX_UNLOCK_POST (mutex));
      return;
   }
   INNER_REQUEST(VALGRIND_HG_MUTEX_UNLOCK_POST (mutex));
   
   /* There are other threads waiting for this mutex, wake one of them
      up.  */
   sres = VG_(do_syscall3)(__NR_futex, (UWord)mutex,
                           VKI_FUTEX_WAKE | VKI_FUTEX_PRIVATE_FLAG,
                           1);
   vg_assert(!sr_isError(sres));
}


void VG_(mutex_destroy) ( Mutex* mutex)
{
   INNER_REQUEST(VALGRIND_HG_MUTEX_DESTROY_PRE (mutex));

   // Undo the DISABLE done in mutex_init.
   INNER_REQUEST(VALGRIND_HG_ENABLE_CHECKING(mutex, sizeof(*mutex)));
}


/* lowlevel locking, similar to the above Mutex one, but without
   Helgrind annotations. */
static void ll_lock ( Mutex* mutex)
{
   unsigned int v;
   SysRes sres;

   /* Bit 31 was clear, we got the mutex.  (this is the fastpath).  */
   if (atomic_bit_test_set (mutex, 31) == 0) {
      return;
   }

   atomic_increment (mutex);

   while (1) {
      if (atomic_bit_test_set (mutex, 31) == 0) {
         atomic_decrement (mutex);
         return;
      }

      /* We have to wait now. First make sure the futex value we are
	 monitoring is truly negative (i.e. locked). */
      v = *mutex;
      if (v >= 0)
         continue;

      sres = VG_(do_syscall3)(__NR_futex, (UWord)mutex,
                              VKI_FUTEX_WAIT | VKI_FUTEX_PRIVATE_FLAG,
                              v);
      if (sr_isError(sres) && sres._val != VKI_EAGAIN) {
         vg_assert(False);
      }
   }
}

static void ll_unlock ( Mutex* mutex)
{
   SysRes sres;

   /* Adding 0x80000000 to the counter results in 0 if and only if
      there are not other interested threads - we can return (this is
      the fastpath).  */
   if (atomic_add_zero (mutex, 0x80000000)) {
      return;
   }
   
   /* There are other threads waiting for this mutex, wake one of them
      up.  */
   sres = VG_(do_syscall3)(__NR_futex, (UWord)mutex,
                           VKI_FUTEX_WAKE | VKI_FUTEX_PRIVATE_FLAG,
                           1);
   vg_assert(!sr_isError(sres));
}



void VG_(rwlock_init)    ( RwLock* rwlock)
{
   VG_(memset) (rwlock, 0, sizeof(*rwlock));
   INNER_REQUEST(ANNOTATE_RWLOCK_CREATE(rwlock));
   INNER_REQUEST(VALGRIND_HG_DISABLE_CHECKING(rwlock, sizeof(*rwlock)));
   // ??? or we put annotate requests in the low level locks ???
}

void VG_(rwlock_rdlock)  ( RwLock* rwlock, ThreadId tid)
{
   SysRes sres;

   /* Make sure we are along.  */
   ll_lock (&rwlock->__lock);

   // Note: the original NPTL code handles overflow on the nr of readers.
   // Not clear if that can happen in Valgrind. And if it happens,
   // then what would we do ? (the caller would have to handle EAGAIN).
   
   while (1) {
      /* Get the rwlock if there is no writer...  */
      if (rwlock->__writer == 0
          /* ...and if no writer is waiting.  */
          && !rwlock->__nr_writers_queued) {
         /* Increment the reader counter. */
         ++rwlock->__nr_readers;
         break;
      }
      
      /* Make sure we are not holding the rwlock as a writer.  This is
         a deadlock situation we recognize and report.  */
      vg_assert (rwlock->__writer != tid);
      
      /* Remember that we are a reader.  */
      ++rwlock->__nr_readers_queued;
      
      int waitval = rwlock->__readers_wakeup;
      
      /* Free the lock.  */
      ll_unlock (&rwlock->__lock);
      
      /* Wait for the writer to finish.  */
      sres = VG_(do_syscall3)(__NR_futex, (UWord)&rwlock->__readers_wakeup,
                              VKI_FUTEX_WAIT | VKI_FUTEX_PRIVATE_FLAG,
                              waitval);
      if (sr_isError(sres) && sres._val != VKI_EAGAIN) {
         vg_assert(False);
      }

      /* Get the lock.  */
      ll_lock (&rwlock->__lock);
      
      --rwlock->__nr_readers_queued;
   }
   
   /* We are done, free the lock.  */
   INNER_REQUEST(ANNOTATE_RWLOCK_ACQUIRED(rwlock, /*is_w*/0));
   ll_unlock (&rwlock->__lock);
   
}

void VG_(rwlock_wrlock)  ( RwLock* rwlock, ThreadId tid)
{
   SysRes sres;

   /* Make sure we are along.  */
   ll_lock (&rwlock->__lock);
   
   while (1) {
      /* Get the rwlock if there is no writer and no reader.  */
      if (rwlock->__writer == 0 && rwlock->__nr_readers == 0) {
         /* Mark self as writer.  */
         rwlock->__writer = tid;
         break;
      }
      
      /* Make sure we are not holding the rwlock as a writer.  This is
         a deadlock situation we recognize and report.  */
      vg_assert (rwlock->__writer != tid);
      
      /* Remember that we are a writer.  */
      ++rwlock->__nr_writers_queued;

      int waitval = rwlock->__writer_wakeup;
      
      /* Free the lock.  */
      ll_unlock (&rwlock->__lock);
      
      /* Wait for the writer or reader(s) to finish.  */
      sres = VG_(do_syscall3)(__NR_futex, (UWord)&rwlock->__writer_wakeup,
                              VKI_FUTEX_WAIT | VKI_FUTEX_PRIVATE_FLAG,
                              waitval);
      if (sr_isError(sres) && sres._val != VKI_EAGAIN) {
         vg_assert(False);
      }
      
      /* Get the lock.  */
      ll_lock (&rwlock->__lock);
      
      /* To start over again, remove the thread from the writer list.  */
      --rwlock->__nr_writers_queued;
   }
   
   /* We are done, free the lock.  */
   INNER_REQUEST(ANNOTATE_RWLOCK_ACQUIRED(rwlock, /*is_w*/1));
   ll_unlock (&rwlock->__lock);
}

void VG_(rwlock_unlock)  ( RwLock* rwlock, ThreadId tid)
{
   SysRes sres;

   ll_lock (&rwlock->__lock);
   if (rwlock->__writer) {
      vg_assert (rwlock->__writer == tid);
      rwlock->__writer = 0;
      INNER_REQUEST(ANNOTATE_RWLOCK_RELEASED(rwlock, /*is_w*/1));
   } else {
      --rwlock->__nr_readers;
      INNER_REQUEST(ANNOTATE_RWLOCK_RELEASED(rwlock, /*is_w*/0));
   }
   if (rwlock->__nr_readers == 0) {
      if (rwlock->__nr_writers_queued) {
         ++rwlock->__writer_wakeup;
         ll_unlock (&rwlock->__lock);
         sres = VG_(do_syscall3)(__NR_futex, (UWord)&rwlock->__writer_wakeup,
                                 VKI_FUTEX_WAKE | VKI_FUTEX_PRIVATE_FLAG,
                                 1);
         return;
      } else if (rwlock->__nr_readers_queued) {
         ++rwlock->__readers_wakeup;
         ll_unlock (&rwlock->__lock);
         sres = VG_(do_syscall3)(__NR_futex, (UWord)&rwlock->__readers_wakeup,
                                 VKI_FUTEX_WAKE | VKI_FUTEX_PRIVATE_FLAG,
                                 0x7fffffff);
         return;
      }
   }
   ll_unlock (&rwlock->__lock);
}

void VG_(rwlock_destroy) ( RwLock* rwlock)
{
   INNER_REQUEST(ANNOTATE_RWLOCK_DESTROY(rwlock));
   INNER_REQUEST(VALGRIND_HG_ENABLE_CHECKING(rwlock, sizeof(*rwlock)));
   return; // nothing to do
}


/*--------------------------------------------------------------------*/
/*--- end                                                 m_lock.c ---*/
/*--------------------------------------------------------------------*/
