
/*--------------------------------------------------------------------*/
/*--- Generic scheduler lock implementation   sched-lock-generic.c ---*/
/*---                                                              ---*/
/*--- This implementation does not guarantee fair scheduling on    ---*/
/*--- multicore systems but is sufficient to make the Valgrind     ---*/
/*--- scheduler work reasonably.                                   ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2011 Bart Van Assche <bvanassche@acm.org>.

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
#include "pub_tool_mallocfree.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcsetjmp.h"    // To keep pub_core_threadstate.h happy
#include "pub_core_vki.h"           // To keep pub_core_threadstate.h happy
#include "pub_core_threadstate.h"
#include "priv_sema.h"
#include "priv_sched-lock.h"
#include "priv_sched-lock-impl.h"
#include "pub_tool_inner.h"
#if defined(ENABLE_INNER_CLIENT_REQUEST)
#include "helgrind/helgrind.h"
#endif

struct sched_lock {
   vg_sema_t sema_excl; // exclusive lock, used to protect this data structure.
   vg_sema_t sema_no_writers; // acquire this to ensure there is no (other) writer.
   vg_sema_t sema_no_readers; // acquire this to ensure there is no readers.

   UInt nr_readers; // current nr of threads having a read lock.
};

static const HChar *get_sched_lock_name(void)
{
   return "generic";
}

static struct sched_lock *create_sched_lock(void)
{
   struct sched_lock *p;

   p = VG_(malloc)("sched_lock", sizeof(*p));
   if (p) {
      ML_(sema_init)(&p->sema_excl);
      ML_(sema_init)(&p->sema_no_readers);
      ML_(sema_init)(&p->sema_no_writers);
      p->nr_readers = 0;
      INNER_REQUEST(ANNOTATE_BENIGN_RACE_SIZED
                    (&p->nr_readers,
                     sizeof(&p->nr_readers),
                     "assuming this is properly protected by the low level semaphores"
                     " which are not marked with H annotations"));
   }
   INNER_REQUEST(ANNOTATE_RWLOCK_CREATE(p));
   return p;
}

static void destroy_sched_lock(struct sched_lock *p)
{
   INNER_REQUEST(ANNOTATE_RWLOCK_DESTROY(p));
   ML_(sema_deinit)(&p->sema_excl);
   ML_(sema_deinit)(&p->sema_no_readers);
   ML_(sema_deinit)(&p->sema_no_writers);
   VG_(free)(p);
}

static int get_sched_lock_owner(struct sched_lock *p)
{
   return p->sema_excl.owner_lwpid;
}

static void acquire_sched_lock(struct sched_lock *p, ThreadId tid, SchedLockKind slk)
{
   if (slk == VgTs_ReadLock) {
      int prev_readers;
      ML_(sema_down)(&p->sema_no_writers, False); // ensure no writer.
      ML_(sema_down)(&p->sema_excl, False); // protect nr_readers counter
      prev_readers = p->nr_readers;
      p->nr_readers++;
      ML_(sema_up)(&p->sema_excl, False);
      if (prev_readers == 0)
         ML_(sema_down)(&p->sema_no_readers, False); // indicate there is a reader.
      ML_(sema_up)(&p->sema_no_writers, False); // release writers (they will be blocked on the sema_no_readers.
      INNER_REQUEST(ANNOTATE_RWLOCK_ACQUIRED(p, /*is_w*/0));
   } else if (slk == VgTs_WriteLock) {
      ML_(sema_down)(&p->sema_no_writers, False); // ensure no other writer.
      ML_(sema_down)(&p->sema_no_readers, False); // ensure no readers.
      INNER_REQUEST(ANNOTATE_RWLOCK_ACQUIRED(p, /*is_w*/1));
      ML_(sema_up)(&p->sema_no_writers, False); // release writers (they will be blocked on the sema_no_readers.
   } else {
      vg_assert (0);
   }
}

static void release_sched_lock(struct sched_lock *p, ThreadId tid, SchedLockKind slk)
{
   if (slk == VgTs_ReadLock) {
      UInt current_readers;
      ML_(sema_down)(&p->sema_excl, False); // protect nr_readers counter
      p->nr_readers--;
      current_readers = p->nr_readers;
      INNER_REQUEST(ANNOTATE_RWLOCK_RELEASED(p, /*is_w*/0));
      ML_(sema_up)(&p->sema_excl, False);
      if (current_readers == 0)
         ML_(sema_up)(&p->sema_no_readers, False);
   } else if (slk == VgTs_WriteLock) {
      INNER_REQUEST(ANNOTATE_RWLOCK_RELEASED(p, /*is_w*/1));
      ML_(sema_up)(&p->sema_no_readers, False); // release readers.
   } else vg_assert (0);
}

const struct sched_lock_ops ML_(generic_sched_lock_ops) = {
   .get_sched_lock_name  = get_sched_lock_name,
   .create_sched_lock    = create_sched_lock,
   .destroy_sched_lock   = destroy_sched_lock,
   .get_sched_lock_owner = get_sched_lock_owner,
   .acquire_sched_lock   = acquire_sched_lock,
   .release_sched_lock   = release_sched_lock,
};
