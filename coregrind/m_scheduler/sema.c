
/*--------------------------------------------------------------------*/
/*--- Semaphore stuff.                                      sema.c ---*/
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

#include "pub_core_basics.h"
#include "pub_core_debuglog.h"
#include "pub_core_vki.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcfile.h"
#include "pub_core_libcproc.h"      // For VG_(gettid)()
#include "pub_tool_inner.h"
#if defined(ENABLE_INNER_CLIENT_REQUEST)
#include "helgrind/helgrind.h"
#endif
#include "priv_sema.h"

/* 
   Slower (than the removed futex-based sema scheme) but more portable
   pipe-based token passing scheme.
 */

void ML_(sema_init)(vg_sema_t *sema)
{
   HChar buf[2];
   Int res, r;
   r = VG_(pipe)(sema->pipe);
   vg_assert(r == 0);

   vg_assert(sema->pipe[0] != sema->pipe[1]);

   sema->pipe[0] = VG_(safe_fd)(sema->pipe[0]);
   sema->pipe[1] = VG_(safe_fd)(sema->pipe[1]);

   if (0) 
      VG_(debugLog)(0,"zz","sema_init: %d %d\n", sema->pipe[0], 
                                                 sema->pipe[1]);
   vg_assert(sema->pipe[0] != sema->pipe[1]);

   sema->owner_lwpid = -1;
   sema->held_as_LL = False;

   /* create initial token */
   sema->sema_char = 'A';
   buf[0] = sema->sema_char; 
   buf[1] = 0;
   sema->sema_char++;
   //INNER_REQUEST(ANNOTATE_RWLOCK_CREATE(sema));
   // disabled the above inner request, seems to give false problems/alarms
   // with mixing the high level lock logic (the big rwlock) with the low level
   // locks (here).
   // All this should be re-done with proper lock module.

   /* all the below are benign as in any case, such data cannot be used
      anymore when we have a lock that is read-acquired by multiple threads */
   /* The only real mystery is the held_as_LL */
   INNER_REQUEST(ANNOTATE_BENIGN_RACE_SIZED(&sema->owner_lwpid,
                                            sizeof(sema->owner_lwpid), ""));
   INNER_REQUEST(ANNOTATE_BENIGN_RACE_SIZED(&sema->sema_char,
                                            sizeof(sema->sema_char), 
                                            "semaphore sema_char inc"));
   INNER_REQUEST(ANNOTATE_BENIGN_RACE_SIZED(&sema->held_as_LL,
                                            sizeof(sema->held_as_LL), 
                                            "semaphore sema_char inc"));
   res = VG_(write)(sema->pipe[1], buf, 1);
   vg_assert(res == 1);
}

void ML_(sema_deinit)(vg_sema_t *sema)
{
   vg_assert(sema->owner_lwpid != -1); /* must be initialised */
   vg_assert(sema->pipe[0] != sema->pipe[1]);
   //INNER_REQUEST(ANNOTATE_RWLOCK_DESTROY(sema));
   VG_(close)(sema->pipe[0]);
   VG_(close)(sema->pipe[1]);
   sema->pipe[0] = sema->pipe[1] = -1;
   sema->owner_lwpid = -1;
   sema->held_as_LL = False;
}

/* get a token */
void ML_(sema_down)( vg_sema_t *sema, Bool as_LL )
{
   HChar buf[2];
   Int ret;
   Int lwpid = VG_(gettid)();

   vg_assert(sema->pipe[0] != sema->pipe[1]);

  again:
   buf[0] = buf[1] = 0;
   ret = VG_(read)(sema->pipe[0], buf, 1);
   //INNER_REQUEST(ANNOTATE_RWLOCK_ACQUIRED(sema, /*is_w*/1));

   if (ret != 1) 
      VG_(debugLog)(0, "scheduler", 
                       "VG_(sema_down): read returned %d\n", ret);

   if (ret == -VKI_EINTR)
      goto again;

   vg_assert(sema->owner_lwpid != lwpid); /* can't have it already */
   vg_assert(ret == 1);		/* should get exactly 1 token */
   vg_assert(buf[0] >= 'A' && buf[0] <= 'Z');
   vg_assert(buf[1] == 0);

   if (sema->sema_char == 'Z') sema->sema_char = 'A'; else sema->sema_char++;

   sema->owner_lwpid = lwpid;
   sema->held_as_LL = as_LL;
}

/* put token back */
void ML_(sema_up)( vg_sema_t *sema, Bool as_LL )
{
   Int ret;
   HChar buf[2];
   vg_assert(as_LL == sema->held_as_LL);
   buf[0] = sema->sema_char; 
   buf[1] = 0;
   vg_assert(sema->owner_lwpid != -1); /* must be initialised */
   vg_assert(sema->pipe[0] != sema->pipe[1]);
   //??mt vg_assert(sema->owner_lwpid == VG_(gettid)()); /* must have it */
   //??reader lock can be locked by a reader, and unlocked by another one.

   sema->owner_lwpid = 0;

   //INNER_REQUEST(ANNOTATE_RWLOCK_RELEASED(sema, /*is_w*/1));
   ret = VG_(write)(sema->pipe[1], buf, 1);

   if (ret != 1) 
      VG_(debugLog)(0, "scheduler", 
                       "VG_(sema_up):write returned %d\n", ret);

   vg_assert(ret == 1);
}

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/


