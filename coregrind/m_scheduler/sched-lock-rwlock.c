
/*--------------------------------------------------------------------*/
/*--- Read/Writer scheduler lock impl.        sched-lock-rwlock.c  ---*/
/*---                                                              ---*/
/*--- mtV? is this impl. giving some fair scheduling ?             ---*/
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
#include "pub_tool_mallocfree.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcsetjmp.h"    // To keep pub_core_threadstate.h happy
#include "pub_core_vki.h"           // To keep pub_core_threadstate.h happy
#include "pub_core_threadstate.h"
//#include "priv_sema.h"

#include "pub_tool_lock.h"
#include "priv_sched-lock.h"
#include "priv_sched-lock-impl.h"
#include "pub_tool_inner.h"
#if defined(ENABLE_INNER_CLIENT_REQUEST)
#include "helgrind/helgrind.h"
#endif

static const Char *get_sched_lock_name(void)
{
   return "rwlock";
}

static struct sched_lock *create_sched_lock(void)
{
   RwLock *p;

   p = VG_(malloc)("sched_lock", sizeof(*p));
   vg_assert (p);
   VG_(rwlock_init) (p);
   // annotated in m_lock.c INNER_REQUEST(ANNOTATE_RWLOCK_CREATE(p));
   return (struct sched_lock *)p;
}

static void destroy_sched_lock(struct sched_lock *p)
{
   // annotated in m_lock.c INNER_REQUEST(ANNOTATE_RWLOCK_DESTROY(p));
   VG_(rwlock_destroy)((RwLock *)p);
   VG_(free)(p);
}

static int get_sched_lock_owner(struct sched_lock *p)
{
   return ((RwLock *)p)->__writer; //mtV? horror: dig into the private part of the rwlock
   // mtV? why is there a need to get the owner ?
}

static void acquire_sched_lock(struct sched_lock *p, ThreadId tid, SchedLockKind slk)
{
   if (slk == VgTs_ReadLock) {
      VG_(rwlock_rdlock) ((RwLock *)p, tid);
      // in m_lock.c INNER_REQUEST(ANNOTATE_RWLOCK_ACQUIRED(p, /*is_w*/0));
   } else if (slk == VgTs_WriteLock) {
      VG_(rwlock_wrlock) ((RwLock *)p, tid);
      // in m_lock.c INNER_REQUEST(ANNOTATE_RWLOCK_ACQUIRED(p, /*is_w*/1));
   } else {
      vg_assert (0);
   }
}

static void release_sched_lock(struct sched_lock *p, ThreadId tid, SchedLockKind slk)
{
   vg_assert(tid);
   if (slk == VgTs_ReadLock) {
      VG_(rwlock_unlock) ((RwLock *)p, tid);
      // in m_lock.c INNER_REQUEST(ANNOTATE_RWLOCK_RELEASED(p, /*is_w*/0));
   } else if (slk == VgTs_WriteLock) {
      VG_(rwlock_unlock) ((RwLock *)p, tid);
      // in m_lock.c INNER_REQUEST(ANNOTATE_RWLOCK_RELEASED(p, /*is_w*/1));
   } else vg_assert (0);
}

const struct sched_lock_ops ML_(rwlock_sched_lock_ops) = {
   .get_sched_lock_name  = get_sched_lock_name,
   .create_sched_lock    = create_sched_lock,
   .destroy_sched_lock   = destroy_sched_lock,
   .get_sched_lock_owner = get_sched_lock_owner,
   .acquire_sched_lock   = acquire_sched_lock,
   .release_sched_lock   = release_sched_lock,
};
