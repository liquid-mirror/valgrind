
/*--------------------------------------------------------------------*/
/*--- Thrcheck: a Valgrind tool for detecting errors               ---*/
/*--- in threaded programs.                              tc_main.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Thrcheck, a Valgrind tool for detecting errors
   in threaded programs.

   Copyright (C) 2007-2007 OpenWorks LLP
      info@open-works.co.uk

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

   Neither the names of the U.S. Department of Energy nor the
   University of California nor the names of its contributors may be
   used to endorse or promote products derived from this software
   without prior written permission.
*/

#include "pub_tool_basics.h"
#include "pub_tool_aspacemgr.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_threadstate.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_hashtable.h"
#include "pub_tool_replacemalloc.h"
#include "pub_tool_machine.h"
#include "pub_tool_options.h"

#include "thrcheck.h"

#define TC_(str) VGAPPEND(vgThrcheck_,str)
#include "tc_wordfm.h"
#include "tc_wordset.h"

/*----------------------------------------------------------------*/
/*---                                                          ---*/
/*----------------------------------------------------------------*/

// FIXME what is supposed to happen to locks in memory which
// is relocated as a result of client realloc?

// FIXME some kind of ownership recycling problem in
// init_thread_specific_state() for programs which use the same thread
// slot more than once?

// FIXME put referencing ThreadId into Thread and get
// rid of the slow reverse mapping function.

// FIXME accesses to NoAccess areas: change state to Excl?

// FIXME report errors for accesses of NoAccess memory?

// FIXME pth_cond_wait/timedwait wrappers.  Even if these fail,
// the thread still holds the lock.

// this is:
// shadow_mem_make_NoAccess: 29156 SMs, 1728 scanned
// happens_before_wrk: 1000
// ev__post_thread_join: 3360 SMs, 29 scanned, 252 re-Excls
#define SHOW_EXPENSIVE_STUFF 0

// 0 for silent, 1 for some stuff, 2 for lots of stuff
#define SHOW_EVENTS 0

// Flags for controlling for which events sanity checking is done
#define SCE_THREADS  (1<<0)  // Sanity check at thread create/join
#define SCE_LOCKS    (1<<1)  // Sanity check at lock events
#define SCE_BIGRANGE (1<<2)  // Sanity check at big mem range events
#define SCE_ACCESS   (1<<3)  // Sanity check at mem accesses

#define SCE_BIGRANGE_T 256  // big mem range minimum size

static const Int sanity_flags
//= SCE_THREADS | SCE_LOCKS | SCE_BIGRANGE | SCE_ACCESS;
= 0;

static void all__sanity_check ( char* who ); /* fwds */

#define TC_CLI__MALLOC_REDZONE_SZB 16 /* let's say */


// FIXME: don't hardwire initial entries for root thread.
// Instead, let the pre_thread_ll_create handler do this.

// 0 for none, 1 for dump at end of run
#define SHOW_DATA_STRUCTURES 0

// FIXME move this somewhere sane
// 0 = no segments at all
// 1 = segments at thread create/join
// 2 = as 1 + segments at condition variable signal/broadcast/wait too
static Int clo_happens_before = 2;  /* default setting */


// FIXME: when a SecMap is completely set via and address range
// setting operation to a non-ShR/M state, clear its .anyShared 
// bit

/* FIXME: figure out what the real rules are for Excl->ShR/M
   transitions w.r.t locksets.

   Muelenfeld thesis Sec 2.2.1 p 8/9 says that

     When another thread accesses the memory location, the lock-set
     is initialized with all active locks and the algorithm reports
     the next access that results in an empty lock-set.

   What does "all active locks" mean?  All locks held by the accessing
   thread, or all locks held by the system as a whole?

   However: Muelenfeld's enhanced Helgrind (eraser_mem_read_word)
   seems to use simply the set of locks held by the thread causing the
   transition into a shared state at the time of the transition:

     *sword = SW(Vge_Shar, packLockSet(thread_locks_rd[tid]));

   Original Eraser paper also says "all active locks".
*/

// Major stuff to fix:
// - reader-writer locks

/* Thread async exit:
   
   remove the map_threads entry
   leave the Thread object in place
   complain if holds any locks
   
   unlike with Join, do not change any memory states

   I _think_ this is correctly handled now.
*/

/*----------------------------------------------------------------*/
/*--- Some very basic stuff                                    ---*/
/*----------------------------------------------------------------*/

static void* tc_zalloc ( SizeT n ) {
   void* p;
   tl_assert(n > 0);
   p = VG_(malloc)( n );
   tl_assert(p);
   VG_(memset)(p, 0, n);
   return p;
}
static void tc_free ( void* p ) {
   tl_assert(p);
   VG_(free)(p);
}

/* Round a up to the next multiple of N.  N must be a power of 2 */
#define ROUNDUP(a, N)   ((a + N - 1) & ~(N-1))
/* Round a down to the next multiple of N.  N must be a power of 2 */
#define ROUNDDN(a, N)   ((a) & ~(N-1))

#ifdef HAVE_BUILTIN_EXPECT
#define LIKELY(cond)   __builtin_expect((cond),1)
#define UNLIKELY(cond) __builtin_expect((cond),0)
#else
#define LIKELY(cond)   (cond)
#define UNLIKELY(cond) (cond)
#endif


/*----------------------------------------------------------------*/
/*--- Primary data definitions                                 ---*/
/*----------------------------------------------------------------*/

/* These are handles for thread segments.  CONSTRAINTS: Must be small
   ints numbered from zero, since 30-bit versions of them must are
   used to represent Exclusive shadow states.  Are used as keys in
   WordFMs so must be castable to Words at the appropriate points. */
typedef  UInt  SegmentID;


/* These are handles for Word sets.  CONSTRAINTS: must be (very) small
   ints numbered from zero, since < 30-bit versions of them are used to
   encode thread-sets and lock-sets in 32-bit shadow words. */
typedef  WordSet  WordSetID;


/* Stores information about a thread.  Addresses of these also serve
   as unique thread identifiers and so are never freed, so they should
   be as small as possible. */
typedef
   struct _Thread {
      /* ADMIN */
      struct _Thread* admin;
      UInt            magic;
      /* USEFUL */
      WordSetID locksetA; /* WordSet of Lock* currently held by thread */
      WordSetID locksetW; /* subset of locksetA held in w-mode */
      SegmentID csegid;  /* current thread segment for thread */
      /* EXPOSITION */
      /* Place where parent was when this thread was created. */
      ExeContext* created_at;
      Bool        announced;
      /* Index for generating references in error messages. */
      Int         errmsg_index;
   }
   Thread;


/* Stores information about a lock's current state.  These are
   allocated and later freed (when the containing memory becomes
   NoAccess).  This gives a problem for the XError type, which
   contains Lock*s.  Solution is to copy any Lock which is to be
   incorporated into an XErrors, so as to make it independent from the
   'normal' collection of Locks, which can come and go.  When the lock
   is copied, its .magic is changed from LockN_Magic to
   LockP_Magic. */

/* Lock kinds. */
typedef
   enum {
      LK_mbRec=1001, /* normal mutex, possibly recursive */
      LK_nonRec,     /* normal mutex, definitely non recursive */
      LK_rdwr        /* reader-writer lock */
   }
   LockKind;

typedef
   struct _Lock {
      /* ADMIN */
      struct _Lock* admin;
      ULong         unique; /* used for persistence-hashing */
      UInt          magic;  /* LockN_MAGIC or LockP_MAGIC */
      /* EXPOSITION */
      /* Place where lock first came to the attention of Thrcheck. */
      ExeContext*   appeared_at;
      /* USEFUL-STATIC */
      Addr          guestaddr; /* Guest address of lock */
      LockKind      kind;      /* what kind of lock this is */
      /* USEFUL-DYNAMIC */
      Bool          heldW; 
      WordBag*      heldBy; /* bag of threads that hold this lock */
      /* .heldBy is NULL: lock is unheld, and .heldW is meaningless
                          but arbitrarily set to False
         .heldBy is non-NULL:
            .heldW is True:  lock is w-held by threads in heldBy
            .heldW is False: lock is r-held by threads in heldBy
            Either way, heldBy may not validly be an empty Bag.

         for LK_nonRec, r-holdings are not allowed, and w-holdings may
         only have sizeTotal(heldBy) == 1

         for LK_mbRec, r-holdings are not allowed, and w-holdings may
         only have sizeUnique(heldBy) == 1

         for LK_rdwr, w-holdings may only have sizeTotal(heldBy) == 1 */
   }
   Lock;


/* Stores information about thread segments.  .prev can be NULL only
   when this is the first segment for the thread.  .other is NULL
   unless this segment depends on a message (create, join, signal)
   from some other thread.  Segments are never freed (!) */
typedef
   struct _Segment {
      /* ADMIN */
      struct _Segment* admin;
      UInt             magic;
      /* USEFUL */
      UInt             dfsver; /* Version # for depth-first searches */
      Thread*          thr;    /* The thread that I am part of */
      struct _Segment* prev;   /* The previous segment in this thread */
      struct _Segment* other;  /* Possibly a segment from some other 
                                  thread, which happened-before me */
      /* DEBUGGING ONLY: what does 'other' arise from?  
         c=thread creation, j=join, s=cvsignal */
      Char other_hint;
   }
   Segment;


/* --------- Primary data structures --------- */

/* Admin linked list of Threads */
static Thread* admin_threads = NULL;

/* Admin linked list of Locks */
static Lock* admin_locks = NULL;

/* Admin linked list of Segments */
static Segment* admin_segments = NULL;

/* Shadow memory primary map */
static WordFM* map_shmem = NULL; /* WordFM Addr SecMap* */

/* Mapping table for core ThreadIds to Thread* */
static Thread** map_threads = NULL; /* Array[VG_N_THREADS] of Thread* */

/* Mapping table for thread segments IDs to Segment* */
static WordFM* map_segments = NULL; /* WordFM SegmentID Segment* */

/* Mapping table for lock guest addresses to Lock* */
static WordFM* map_locks = NULL; /* WordFM LockAddr Lock* */

/* The word-set universes for thread sets and lock sets. */
static WordSetU* univ_tsets = NULL;
static WordSetU* univ_lsets = NULL;

/* never changed; we only care about its address.  Is treated as if it
   was a standard userspace lock.  Also we have a Lock* describing it
   so it can participate in lock sets in the usual way. */
static Int   __bus_lock = 0;
static Lock* __bus_lock_Lock = NULL;


/*----------------------------------------------------------------*/
/*--- Simple helpers for the data structures                   ---*/
/*----------------------------------------------------------------*/

#define Thread_MAGIC   0x504fc5e5
#define LockN_MAGIC    0x6545b557 /* normal nonpersistent locks */
#define LockP_MAGIC    0x755b5456 /* persistent (copied) locks */
#define Segment_MAGIC  0x49e94d81
#define SecMap_MAGIC   0x571e58cb

static UWord stats__mk_Segment = 0;

/* --------- Constructors --------- */

static inline Bool is_sane_LockN ( Lock* lock ); /* fwds */

static Thread* mk_Thread ( SegmentID csegid ) {
   static Int indx      = 1;
   Thread* thread       = tc_zalloc( sizeof(Lock) );
   thread->locksetA     = TC_(emptyWS)( univ_lsets );
   thread->locksetW     = TC_(emptyWS)( univ_lsets );
   thread->csegid       = csegid;
   thread->magic        = Thread_MAGIC;
   thread->created_at   = NULL;
   thread->announced    = False;
   thread->errmsg_index = indx++;
   thread->admin        = admin_threads;
   admin_threads        = thread;
   return thread;
}
// Make a new lock which is unlocked (hence ownerless)
static Lock* mk_LockN ( LockKind kind, Addr guestaddr ) {
   static ULong unique = 0;
   Lock* lock        = tc_zalloc( sizeof(Lock) );
   lock->admin       = admin_locks;
   lock->unique      = unique++;
   lock->magic       = LockN_MAGIC;
   lock->appeared_at = NULL;
   lock->guestaddr   = guestaddr;
   lock->kind        = kind;
   lock->heldW       = False;
   lock->heldBy      = NULL;
   tl_assert(is_sane_LockN(lock));
   admin_locks       = lock;
   return lock;
}
static Segment* mk_Segment ( Thread* thr, Segment* prev, Segment* other ) {
   Segment* seg    = tc_zalloc( sizeof(Segment) );
   seg->dfsver     = 0;
   seg->thr        = thr;
   seg->prev       = prev;
   seg->other      = other;
   seg->other_hint = ' ';
   seg->magic      = Segment_MAGIC;
   seg->admin      = admin_segments;
   admin_segments = seg;
   stats__mk_Segment++;
   return seg;
}

static inline Bool is_sane_Segment ( Segment* seg ) {
   return seg != NULL && seg->magic == Segment_MAGIC;
}
static inline Bool is_sane_Thread ( Thread* thr ) {
   return thr != NULL && thr->magic == Thread_MAGIC;
}

static Bool is_sane_Bag_of_Threads ( WordBag* bag )
{
   Thread* thr;
   Word    count;
   TC_(initIterBag)( bag );
   while (TC_(nextIterBag)( bag, (Word*)&thr, &count )) {
      if (count < 1) return False;
      if (!is_sane_Thread(thr)) return False;
   }
   TC_(doneIterBag)( bag );
   return True;
}
static Bool is_sane_Lock_BASE ( Lock* lock )
{
   if (lock == NULL
       || (lock->magic != LockN_MAGIC && lock->magic != LockP_MAGIC))
      return False;
   switch (lock->kind) { 
      case LK_mbRec: case LK_nonRec: case LK_rdwr: break; 
      default: return False; 
   }
   if (lock->heldBy == NULL) {
      /* Unheld.  We arbitrarily require heldW to be False. */
      return !lock->heldW;
   }

   /* If heldBy is non-NULL, we require it to contain at least one
      thread. */
   if (TC_(isEmptyBag)(lock->heldBy))
      return False;

   /* Lock is either r- or w-held. */
   if (!is_sane_Bag_of_Threads(lock->heldBy)) 
      return False;
   if (lock->heldW) {
      /* Held in write-mode */
      if ((lock->kind == LK_nonRec || lock->kind == LK_rdwr)
          && !TC_(isSingletonTotalBag)(lock->heldBy))
         return False;
   } else {
      /* Held in read-mode */
      if (lock->kind != LK_rdwr) return False;
   }
   return True;
}
static inline Bool is_sane_LockP ( Lock* lock ) {
   return lock != NULL 
          && lock->magic == LockP_MAGIC
          && is_sane_Lock_BASE(lock);
}
static inline Bool is_sane_LockN ( Lock* lock ) {
   return lock != NULL 
          && lock->magic == LockN_MAGIC
          && is_sane_Lock_BASE(lock);
}
static inline Bool is_sane_LockNorP ( Lock* lock ) {
   return is_sane_Lock_BASE(lock);
}

/* Release storage for a Lock.  Also release storage in .heldBy, if
   any. */
static void del_LockN ( Lock* lk ) 
{
   tl_assert(is_sane_LockN(lk));
   if (lk->heldBy)
      TC_(deleteBag)( lk->heldBy );
   VG_(memset)(lk, 0xAA, sizeof(*lk));
   tc_free(lk);
}

/* Update 'lk' to reflect that 'thr' now has a write-acquisition of
   it.  This is done strictly: only combinations resulting from
   correct program and libpthread behaviour are allowed. */
static void lockN_acquire_writer ( Lock* lk, Thread* thr ) 
{
   tl_assert(is_sane_LockN(lk));
   tl_assert(is_sane_Thread(thr));
   switch (lk->kind) {
      case LK_nonRec:
      case_LK_nonRec:
         tl_assert(lk->heldBy == NULL); /* can't w-lock recursively */
         tl_assert(!lk->heldW);
         lk->heldW  = True;
         lk->heldBy = TC_(newBag)( tc_zalloc, tc_free );
         TC_(addToBag)( lk->heldBy, (Word)thr );
         break;
      case LK_mbRec:
         if (lk->heldBy == NULL)
            goto case_LK_nonRec;
         /* 2nd and subsequent locking of a lock by its owner */
         tl_assert(lk->heldW);
         /* assert: lk is only held by one thread .. */
         tl_assert(TC_(sizeUniqueBag(lk->heldBy)) == 1);
         /* assert: .. and that thread is 'thr'. */
         tl_assert(TC_(elemBag)(lk->heldBy, (Word)thr)
                   == TC_(sizeTotalBag)(lk->heldBy));
         TC_(addToBag)(lk->heldBy, (Word)thr);
         break;
      case LK_rdwr:
         tl_assert(lk->heldBy == NULL && !lk->heldW); /* must be unheld */
         goto case_LK_nonRec;
      default: 
         tl_assert(0);
  }
  tl_assert(is_sane_LockN(lk));
}

static void lockN_acquire_reader ( Lock* lk, Thread* thr )
{
   tl_assert(is_sane_LockN(lk));
   tl_assert(is_sane_Thread(thr));
   /* can only add reader to a reader-writer lock. */
   tl_assert(lk->kind == LK_rdwr);
   /* lk must be free or already r-held. */
   tl_assert(lk->heldBy == NULL 
             || (lk->heldBy != NULL && !lk->heldW));
   if (lk->heldBy) {
      TC_(addToBag)(lk->heldBy, (Word)thr);
   } else {
      lk->heldW  = False;
      lk->heldBy = TC_(newBag)( tc_zalloc, tc_free );
      TC_(addToBag)( lk->heldBy, (Word)thr );
   }
   tl_assert(!lk->heldW);
   tl_assert(is_sane_LockN(lk));
}

/* Update 'lk' to reflect a release of it by 'thr'.  This is done
   strictly: only combinations resulting from correct program and
   libpthread behaviour are allowed. */

static void lockN_release ( Lock* lk, Thread* thr )
{
   Bool b;
   tl_assert(is_sane_LockN(lk));
   tl_assert(is_sane_Thread(thr));
   /* lock must be held by someone */
   tl_assert(lk->heldBy);
   /* Remove it from the holder set */
   b = TC_(delFromBag)(lk->heldBy, (Word)thr);
   /* thr must actually have been a holder of lk */
   tl_assert(b);
   /* normalise */
   if (TC_(isEmptyBag)(lk->heldBy)) {
      TC_(deleteBag)(lk->heldBy);
      lk->heldBy = NULL;
      lk->heldW = False;
   }
   tl_assert(is_sane_LockN(lk));
}

/* --------- xxxID functions --------- */

/* Proposal (for debugging sanity):

   SegmentIDs from 0x1000000 .. 0x1FFFFFF (16777216)

   All other xxxID handles are invalid.
*/
static inline Bool is_sane_SegmentID ( SegmentID tseg ) {
   return tseg >= 0x1000000 && tseg <= 0x1FFFFFF;
}
static inline Bool is_sane_ThreadId ( ThreadId coretid ) {
   return coretid >= 0 && coretid < VG_N_THREADS;
}
static SegmentID alloc_SegmentID ( void ) {
   static SegmentID next = 0x1000000;
   tl_assert(is_sane_SegmentID(next));
   return next++;
}

/* --------- Shadow memory --------- */

/* Primary Map is the usual FiniteMap Addr SecMap* w/ cache */

#define N_SECMAP_BITS   11
#define N_SECMAP_ARANGE (1 << N_SECMAP_BITS)
#define N_SECMAP_MASK   (~(N_SECMAP_ARANGE - 1))
#define N_SECMAP_W32S   (N_SECMAP_ARANGE / 4)

typedef
   struct {
      UInt magic;
      Bool anyLocks;  /* hint: any locks in range?  safe: True */
      Bool anyShared; /* hint: any ShM/ShR states in range?  safe: True */
      UInt w32s[N_SECMAP_W32S];
   }
   SecMap;

static inline Bool is_sane_SecMap ( SecMap* sm ) {
   return sm != NULL && sm->magic == SecMap_MAGIC;
}

/* Shadow value encodings:

   11 WordSetID:TSID_BITS WordSetID:LSIT_BITS  ShM  thread-set lock-set
   10 WordSetID:TSID_BITS WordSetID:LSIT_BITS  ShR  thread-set lock-set
   01 TSegmentID:30                            Excl thread-segment
   00 0--(20)--0 10 0000 0000                  New
   00 0--(20)--0 01 0000 0000                  NoAccess

   TSID_BITS + LSID_BITS must equal 30.
   The elements in thread sets are Thread*, casted to Word.
   The elements in lock sets are Lock*, casted to Word. 
*/

#define N_LSID_BITS  16
#define N_LSID_MASK  ((1 << (N_LSID_BITS)) - 1)
#define N_LSID_SHIFT 0

#define N_TSID_BITS  (30 - (N_LSID_BITS))
#define N_TSID_MASK  ((1 << (N_TSID_BITS)) - 1)
#define N_TSID_SHIFT (N_LSID_BITS)

static inline Bool is_sane_WordSetID_LSet ( WordSetID wset ) {
   return wset >= 0 && wset <= N_LSID_MASK;
}
static inline Bool is_sane_WordSetID_TSet ( WordSetID wset ) {
   return wset >= 0 && wset <= N_TSID_MASK;
}


#define SHMEM_New      ((UInt)(2<<8))
#define SHMEM_NoAccess ((UInt)(1<<8))
static inline UInt mk_SHMEM_ShM ( WordSetID tset, WordSetID lset ) {
   tl_assert(is_sane_WordSetID_TSet(tset));
   tl_assert(is_sane_WordSetID_LSet(lset));
   return (UInt)( (3<<30) | (tset << N_TSID_SHIFT) 
                          | (lset << N_LSID_SHIFT));
}
static inline UInt mk_SHMEM_ShR ( WordSetID tset, WordSetID lset ) {
   //if ((!is_sane_WordSetID(tset)) || (!is_sane_WordSetID(lset)))
   //  VG_(printf)("XXXXXXXXXX %d %d\n", (Int)tset, (Int)lset);
   tl_assert(is_sane_WordSetID_TSet(tset));
   tl_assert(is_sane_WordSetID_LSet(lset));
   return (UInt)( (2<<30) | (tset << N_TSID_SHIFT) 
                          | (lset << N_LSID_SHIFT));
}
static inline UInt mk_SHMEM_Excl ( SegmentID tseg ) {
   tl_assert(is_sane_SegmentID(tseg));
   return (UInt)( (1<<30) | tseg );
}

static inline Bool is_SHMEM_ShM ( UInt w32 ) { 
   return (w32 >> 30) == 3;
}
static inline Bool is_SHMEM_ShR ( UInt w32 ) {
   return (w32 >> 30) == 2;
}
static inline Bool is_SHMEM_Sh ( UInt w32 ) {
   return (w32 >> 31) == 1;
}
static inline Bool is_SHMEM_Excl ( UInt w32 ) {
   return (w32 >> 30) == 1; 
}
static inline Bool is_SHMEM_New ( UInt w32 ) {
   return w32 == SHMEM_New;
}
static inline Bool is_SHMEM_NoAccess ( UInt w32 ) { 
   return w32 == SHMEM_NoAccess;
}

static inline SegmentID un_SHMEM_Excl ( UInt w32 ) {
   tl_assert(is_SHMEM_Excl(w32));
   return w32 & ~(3<<30);
}
static inline WordSetID un_SHMEM_ShR_tset ( UInt w32 ) {
   tl_assert(is_SHMEM_ShR(w32));
   return (w32 >> N_TSID_SHIFT) & N_TSID_MASK;
}
static inline WordSetID un_SHMEM_ShR_lset ( UInt w32 ) {
   tl_assert(is_SHMEM_ShR(w32));
   return (w32 >> N_LSID_SHIFT) & N_LSID_MASK;
}
static inline WordSetID un_SHMEM_ShM_tset ( UInt w32 ) {
   tl_assert(is_SHMEM_ShM(w32));
   return (w32 >> N_TSID_SHIFT) & N_TSID_MASK;
}
static inline WordSetID un_SHMEM_ShM_lset ( UInt w32 ) {
   tl_assert(is_SHMEM_ShM(w32));
   return (w32 >> N_LSID_SHIFT) & N_LSID_MASK;
}
static inline WordSetID un_SHMEM_Sh_tset ( UInt w32 ) {
   tl_assert(is_SHMEM_Sh(w32));
   return (w32 >> N_TSID_SHIFT) & N_TSID_MASK;
}
static inline WordSetID un_SHMEM_Sh_lset ( UInt w32 ) {
   tl_assert(is_SHMEM_Sh(w32));
   return (w32 >> N_LSID_SHIFT) & N_LSID_MASK;
}


/*----------------------------------------------------------------*/
/*--- Print out the primary data structures                    ---*/
/*----------------------------------------------------------------*/

#define PP_THREADS     (1<<1)
#define PP_LOCKS        (1<<2)
#define PP_SEGMENTS     (1<<3)
#define PP_SHMEM_SHARED (1<<4)
#define PP_ALL (PP_THREADS | PP_LOCKS | PP_SEGMENTS | PP_SHMEM_SHARED)


static const Int sHOW_ADMIN = 0;

static void space ( Int n )
{
   Int  i;
   Char spaces[128+1];
   tl_assert(n >= 0 && n < 128);
   if (n == 0)
      return;
   for (i = 0; i < n; i++)
      spaces[i] = ' ';
   spaces[i] = 0;
   tl_assert(i < 128+1);
   VG_(printf)("%s", spaces);
}

static void pp_Thread ( Int d, Thread* t )
{
   space(d+0); VG_(printf)("Thread %p {\n", t);
   if (sHOW_ADMIN) {
   space(d+3); VG_(printf)("admin    %p\n",   t->admin);
   space(d+3); VG_(printf)("magic    0x%x\n", (UInt)t->magic);
   }
   space(d+3); VG_(printf)("locksetA %d\n",   (Int)t->locksetA);
   space(d+3); VG_(printf)("locksetW %d\n",   (Int)t->locksetW);
   space(d+3); VG_(printf)("csegid   0x%x\n", (UInt)t->csegid);
   space(d+0); VG_(printf)("}\n");
}

static void pp_admin_threads ( Int d )
{
   Int     i, n;
   Thread* t;
   for (n = 0, t = admin_threads;  t;  n++, t = t->admin) {
      /* nothing */
   }
   space(d); VG_(printf)("admin_threads (%d records) {\n", n);
   for (i = 0, t = admin_threads;  t;  i++, t = t->admin) {
      if (0) {
         space(n); 
         VG_(printf)("admin_threads record %d of %d:\n", i, n);
      }
      pp_Thread(d+3, t);
   }
   space(d); VG_(printf)("}\n", n);
}

static void pp_map_threads ( Int d )
{
   Int i, n;
   n = 0;
   space(d); VG_(printf)("map_threads ");
   n = 0;
   for (i = 0; i < VG_N_THREADS; i++) {
      if (map_threads[i] != NULL)
         n++;
   }
   VG_(printf)("(%d entries) {\n", n);
   for (i = 0; i < VG_N_THREADS; i++) {
      if (map_threads[i] == NULL)
         continue;
      space(d+3);
      VG_(printf)("coretid %d -> Thread %p\n", i, map_threads[i]);
   }
   space(d); VG_(printf)("}\n");
}

static const HChar* show_LockKind ( LockKind lkk ) {
   switch (lkk) {
      case LK_mbRec:  return "mbRec";
      case LK_nonRec: return "nonRec";
      case LK_rdwr:   return "rdwr";
      default:        tl_assert(0);
   }
}

static void pp_Lock ( Int d, Lock* lk )
{
   space(d+0); VG_(printf)("Lock %p (ga %p) {\n", lk, lk->guestaddr);
   if (sHOW_ADMIN) {
      space(d+3); VG_(printf)("admin  %p\n",   lk->admin);
      space(d+3); VG_(printf)("magic  0x%x\n", (UInt)lk->magic);
   }
   space(d+3); VG_(printf)("unique %llu\n", lk->unique);
   space(d+3); VG_(printf)("kind   %s\n", show_LockKind(lk->kind));
   space(d+3); VG_(printf)("heldW  %s\n", lk->heldW ? "yes" : "no");
   space(d+3); VG_(printf)("heldBy %p", lk->heldBy);
   if (lk->heldBy) {
      Thread* thr;
      Word    count;
      VG_(printf)(" { ");
      TC_(initIterBag)( lk->heldBy );
      while (TC_(nextIterBag)( lk->heldBy, (Word*)&thr, &count ))
         VG_(printf)("%lu:%p ", count, thr);
      TC_(doneIterBag)( lk->heldBy );
      VG_(printf)("}");
   }
   VG_(printf)("\n");
   space(d+0); VG_(printf)("}\n");
}

static void pp_admin_locks ( Int d )
{
   Int   i, n;
   Lock* lk;
   for (n = 0, lk = admin_locks;  lk;  n++, lk = lk->admin) {
      /* nothing */
   }
   space(d); VG_(printf)("admin_locks (%d records) {\n", n);
   for (i = 0, lk = admin_locks;  lk;  i++, lk = lk->admin) {
      if (0) {
         space(n); 
         VG_(printf)("admin_locks record %d of %d:\n", i, n);
      }
      pp_Lock(d+3, lk);
   }
   space(d); VG_(printf)("}\n", n);
}

static void pp_map_locks ( Int d )
{
   void* gla;
   Lock* lk;
   space(d); VG_(printf)("map_locks (%d entries) {\n",
                         (Int)TC_(sizeFM)( map_locks ));
   TC_(initIterFM)( map_locks );
   while (TC_(nextIterFM)( map_locks, (Word*)&gla, (Word*)&lk )) {
      space(d+3);
      VG_(printf)("guest %p -> Lock %p\n", gla, lk);
   }
   TC_(doneIterFM)( map_locks );
   space(d); VG_(printf)("}\n");
}

static void pp_Segment ( Int d, Segment* s )
{
   space(d+0); VG_(printf)("Segment %p {\n", s);
   if (sHOW_ADMIN) {
   space(d+3); VG_(printf)("admin  %p\n",   s->admin);
   space(d+3); VG_(printf)("magic  0x%x\n", (UInt)s->magic);
   }
   space(d+3); VG_(printf)("dfsver    %u\n", s->dfsver);
   space(d+3); VG_(printf)("thr       %p\n", s->thr);
   space(d+3); VG_(printf)("prev      %p\n", s->prev);
   space(d+3); VG_(printf)("other[%c] %p\n", s->other_hint, s->other);
   space(d+0); VG_(printf)("}\n");
}

static void pp_admin_segments ( Int d )
{
   Int      i, n;
   Segment* s;
   for (n = 0, s = admin_segments;  s;  n++, s = s->admin) {
      /* nothing */
   }
   space(d); VG_(printf)("admin_segments (%d records) {\n", n);
   for (i = 0, s = admin_segments;  s;  i++, s = s->admin) {
      if (0) {
         space(n); 
         VG_(printf)("admin_segments record %d of %d:\n", i, n);
      }
      pp_Segment(d+3, s);
   }
   space(d); VG_(printf)("}\n", n);
}

static void pp_map_segments ( Int d )
{
   SegmentID segid;
   Segment*  seg;
   space(d); VG_(printf)("map_segments (%d entries) {\n", 
                         (Int)TC_(sizeFM)( map_segments ));
   TC_(initIterFM)( map_segments );
   while (TC_(nextIterFM)( map_segments, (Word*)&segid, (Word*)&seg )) {
      space(d+3);
      VG_(printf)("segid 0x%x -> Segment %p\n", (UInt)segid, seg);
   }
   TC_(doneIterFM)( map_segments );
   space(d); VG_(printf)("}\n");
}

static void show_shadow_w32 ( /*OUT*/Char* buf, Int nBuf, UInt w32 )
{
   tl_assert(nBuf-1 >= 99);
   VG_(memset)(buf, 0, nBuf);
   if (is_SHMEM_ShM(w32)) {
      VG_(sprintf)(buf, "ShM(%u,%u)", 
                   un_SHMEM_ShM_tset(w32), un_SHMEM_ShM_lset(w32));
   }
   else
   if (is_SHMEM_ShR(w32)) {
      VG_(sprintf)(buf, "ShR(%u,%u)", 
                   un_SHMEM_ShR_tset(w32), un_SHMEM_ShR_lset(w32));
   }
   else
   if (is_SHMEM_Excl(w32)) {
      VG_(sprintf)(buf, "Excl(%u)", un_SHMEM_Excl(w32));
   }
   else
   if (is_SHMEM_New(w32)) {
      VG_(sprintf)(buf, "%s", "New");
   }
   else
   if (is_SHMEM_NoAccess(w32)) {
      VG_(sprintf)(buf, "%s", "NoAccess");
   }
   else {
      VG_(sprintf)(buf, "Invalid-shadow-word(%u)", w32);
   }
}

static void pp_SecMap_shared ( Int d, SecMap* sm, Addr ga )
{
   Int  i;
   Addr a;
   UInt w32;
   Char buf[100];
   space(d+0); VG_(printf)("SecMap %p (ga %p) {\n", sm, (void*)ga);
   for (i = 0; i < N_SECMAP_W32S; i++) {
      w32 = sm->w32s[i];
      a   = ga + 4 * i;
      if (! (is_SHMEM_ShM(w32) || is_SHMEM_ShR(w32)))
         continue;
      space(d+3); VG_(printf)("%p -> 0x%08x ", (void*)a, w32);
      show_shadow_w32(buf, sizeof(buf), w32);
      VG_(printf)("%s\n", buf);
   }
   space(d+0); VG_(printf)("}\n");
}

static void pp_map_shmem_shared ( Int d )
{
   Addr    ga;
   SecMap* sm;
   space(d); VG_(printf)("map_shmem_ShR_and_ShM_only {\n");
   TC_(initIterFM)( map_shmem );
   while (TC_(nextIterFM)( map_shmem, (Word*)&ga, (Word*)&sm )) {
      pp_SecMap_shared( d+3, sm, ga );
   }
   TC_(doneIterFM) ( map_shmem );
   space(d); VG_(printf)("}\n");
}

static void pp_everything ( Int flags, Char* caller )
{
   Int d = 0;
   VG_(printf)("\n");
   VG_(printf)("All_Data_Structures (caller = \"%s\") {\n", caller);
   if (flags & PP_THREADS) {
      VG_(printf)("\n");
      pp_admin_threads(d+3);
      VG_(printf)("\n");
      pp_map_threads(d+3);
   }
   if (flags & PP_LOCKS) {
      VG_(printf)("\n");
      pp_admin_locks(d+3);
      VG_(printf)("\n");
      pp_map_locks(d+3);
   }
   if (flags & PP_SEGMENTS) {
      VG_(printf)("\n");
      pp_admin_segments(d+3);
      VG_(printf)("\n");
      pp_map_segments(d+3);
   }
   if (flags & PP_SHMEM_SHARED) {
      VG_(printf)("\n");
      pp_map_shmem_shared( d+3 );
   }

   VG_(printf)("\n");
   VG_(printf)("}\n");
   VG_(printf)("\n");
}

#undef SHOW_ADMIN


/*----------------------------------------------------------------*/
/*--- Initialise the primary data structures                   ---*/
/*----------------------------------------------------------------*/

/* fwds */
static void map_segments_add ( SegmentID segid, Segment* seg );
static void shmem__invalidate_cache ( void );
static void hbefore__invalidate_cache ( void );
static void shmem__write_32 ( Addr ga, UInt w32 );
static void shmem__set_anyLocks ( Addr a, Bool b );
static Bool shmem__get_anyLocks ( Addr a );

static void initialise_data_structures ( void )
{
   SegmentID segid;
   Segment*  seg;
   Thread*   thr;

   /* Get everything initialised and zeroed. */
   tl_assert(admin_threads == NULL);
   tl_assert(admin_locks == NULL);
   tl_assert(admin_segments == NULL);

   tl_assert(sizeof(Addr) == sizeof(Word));
   tl_assert(map_shmem == NULL);
   map_shmem = TC_(newFM)( tc_zalloc, tc_free, NULL/*unboxed Word cmp*/);
   tl_assert(map_shmem != NULL);
   shmem__invalidate_cache();

   tl_assert(map_threads == NULL);
   map_threads = tc_zalloc( VG_N_THREADS * sizeof(Thread*) );
   tl_assert(map_threads != NULL);

   /* re <=: < on 64-bit platforms, == on 32-bit ones */
   tl_assert(sizeof(SegmentID) <= sizeof(Word));
   tl_assert(sizeof(Segment*) == sizeof(Word));
   tl_assert(map_segments == NULL);
   map_segments = TC_(newFM)( tc_zalloc, tc_free, NULL/*unboxed Word cmp*/);
   tl_assert(map_segments != NULL);
   hbefore__invalidate_cache();

   tl_assert(sizeof(Addr) == sizeof(Word));
   tl_assert(map_locks == NULL);
   map_locks = TC_(newFM)( tc_zalloc, tc_free, NULL/*unboxed Word cmp*/);
   tl_assert(map_locks != NULL);

   __bus_lock_Lock = mk_LockN( LK_nonRec, (Addr)&__bus_lock );
   tl_assert(is_sane_LockN(__bus_lock_Lock));
   TC_(addToFM)( map_locks, (Word)&__bus_lock, (Word)__bus_lock_Lock );

   tl_assert(univ_tsets == NULL);
   univ_tsets = TC_(newWordSetU)( tc_zalloc, tc_free );
   tl_assert(univ_tsets != NULL);

   tl_assert(univ_lsets == NULL);
   univ_lsets = TC_(newWordSetU)( tc_zalloc, tc_free );
   tl_assert(univ_lsets != NULL);

   /* Set up entries for the root thread */
   // FIXME: this assumes that the first real ThreadId is 1

   /* a segment for the new thread ... */
   // FIXME: code duplication in ev__post_thread_create
   segid = alloc_SegmentID();
   seg   = mk_Segment( NULL, NULL, NULL );
   map_segments_add( segid, seg );

   /* a Thread for the new thread ... */
   thr = mk_Thread( segid );
   seg->thr = thr;

   /* and bind it in the thread-map table */
   map_threads[1] = thr;

   tl_assert(VG_INVALID_THREADID == 0);

   /* Mark the new bus lock correctly (to stop the sanity checks
      complaining) */
   tl_assert( sizeof(__bus_lock) == 4 );
   shmem__write_32( __bus_lock_Lock->guestaddr, mk_SHMEM_Excl(segid) );
   shmem__set_anyLocks( __bus_lock_Lock->guestaddr, True );

   all__sanity_check("initialise_data_structures");
}


/*----------------------------------------------------------------*/
/*--- map_threads :: WordFM core-ThreadId Thread*              ---*/
/*----------------------------------------------------------------*/

/* Doesn't assert if the relevant map_threads entry is NULL. */
static Thread* map_threads_maybe_lookup ( ThreadId coretid )
{
   Thread* thr;
   tl_assert( is_sane_ThreadId(coretid) );
   thr = map_threads[coretid];
   return thr;
}

/* Asserts if the relevant map_threads entry is NULL. */
static inline Thread* map_threads_lookup ( ThreadId coretid )
{
   Thread* thr;
   tl_assert( is_sane_ThreadId(coretid) );
   thr = map_threads[coretid];
   tl_assert(thr);
   return thr;
}

/* Do a reverse lookup.  Warning: POTENTIALLY SLOW.  Does not assert
   if 'thr' is not found in map_threads. */
static ThreadId map_threads_maybe_reverse_lookup_SLOW ( Thread* thr )
{
   Int i;
   tl_assert(is_sane_Thread(thr));
   /* Check nobody used the invalid-threadid slot */
   tl_assert(VG_INVALID_THREADID >= 0 && VG_INVALID_THREADID < VG_N_THREADS);
   tl_assert(map_threads[VG_INVALID_THREADID] == NULL);
   for (i = 0; i < VG_N_THREADS; i++) {
      if (i != VG_INVALID_THREADID && map_threads[i] == thr)
         return (ThreadId)i;
   }
   return VG_INVALID_THREADID;
}

/* Do a reverse lookup.  Warning: POTENTIALLY SLOW.  Asserts if 'thr'
   is not found in map_threads. */
static ThreadId map_threads_reverse_lookup_SLOW ( Thread* thr )
{
   ThreadId tid = map_threads_maybe_reverse_lookup_SLOW( thr );
   tl_assert(tid != VG_INVALID_THREADID);
   return tid;
}

static void map_threads_delete ( ThreadId coretid )
{
   Thread* thr;
   tl_assert(coretid != 0);
   tl_assert( is_sane_ThreadId(coretid) );
   thr = map_threads[coretid];
   tl_assert(thr);
   map_threads[coretid] = NULL;
}


/*----------------------------------------------------------------*/
/*--- map_locks :: WordFM guest-Addr-of-lock Lock*             ---*/
/*----------------------------------------------------------------*/

/* Make sure there is a lock table entry for the given (lock) guest
   address.  If not, create one of the stated 'kind' in unheld state.
   In any case, return the address of the existing or new Lock. */
static 
Lock* map_locks_lookup_or_create ( LockKind lkk, Addr ga, ThreadId tid )
{
   Bool  found;
   Lock* oldlock = NULL;
   tl_assert(is_sane_ThreadId(tid));
   found = TC_(lookupFM)( map_locks, NULL, (Word*)&oldlock, (Word)ga );
   if (!found) {
      Lock* lock = mk_LockN(lkk, ga);
      lock->appeared_at = VG_(record_ExeContext)( tid, 0 );
      tl_assert(is_sane_LockN(lock));
      TC_(addToFM)( map_locks, (Word)ga, (Word)lock );
      tl_assert(oldlock == NULL);
      // mark the relevant secondary map has .anyLocks
      shmem__set_anyLocks( ga, True );
      return lock;
   } else {
      tl_assert(oldlock != NULL);
      tl_assert(is_sane_LockN(oldlock));
      tl_assert(oldlock->guestaddr == ga);
      // check the relevant secondary map has .anyLocks?
      tl_assert(shmem__get_anyLocks(ga) == True);
      return oldlock;
   }
}

static Lock* map_locks_maybe_lookup ( Addr ga )
{
   Bool  found;
   Lock* lk = NULL;
   found = TC_(lookupFM)( map_locks, NULL, (Word*)&lk, (Word)ga );
   tl_assert(found  ?  lk != NULL  :  lk == NULL);
   if (found) {
      // check the relevant secondary map has .anyLocks?
      tl_assert(shmem__get_anyLocks(ga) == True);
   }
   return lk;
}

static void map_locks_delete ( Addr ga )
{
   Lock* lk = NULL;
   TC_(delFromFM)( map_locks, (Word*)&lk, (Word)ga );
   /* delFromFM produces the val which is being deleted, if it is
      found.  So assert it is non-null; that in effect asserts that we
      are deleting a (ga, Lock) pair which actually exists. */
   tl_assert(lk != NULL);
}


/*----------------------------------------------------------------*/
/*--- map_segments :: WordFM SegmentID Segment*                ---*/
/*--- the DAG of thread segments                               ---*/
/*----------------------------------------------------------------*/

/*--------------- SegmentID to Segment* maps ---------------*/

static Segment* map_segments_lookup ( SegmentID segid )
{
   Bool     found;
   Segment* seg = NULL;
   tl_assert( is_sane_SegmentID(segid) );
   found = TC_(lookupFM)( map_segments, NULL, (Word*)&seg, (Word)segid );
   tl_assert(found);
   tl_assert(seg != NULL);
   return seg;
}

static Segment* map_segments_maybe_lookup ( SegmentID segid )
{
   Bool     found;
   Segment* seg = NULL;
   tl_assert( is_sane_SegmentID(segid) );
   found = TC_(lookupFM)( map_segments, NULL, (Word*)&seg, (Word)segid );
   if (!found) tl_assert(seg == NULL);
   return seg;
}

static void map_segments_add ( SegmentID segid, Segment* seg )
{
   /* This is a bit inefficient.  Oh well. */
   tl_assert( !TC_(lookupFM)( map_segments, NULL, NULL, segid ));
   TC_(addToFM)( map_segments, (Word)segid, (Word)seg );
}

/*------------ searching the happens-before graph ------------*/

static UWord stats__hbefore_queries   = 0; // total # queries
static UWord stats__hbefore_cache0s   = 0; // hits at cache[0]
static UWord stats__hbefore_cacheNs   = 0; // hits at cache[> 0]
static UWord stats__hbefore_probes    = 0; // # checks in cache
static UWord stats__hbefore_gsearches = 0; // # searches in graph
static UWord stats__hbefore_gsearchFs = 0; // # fast searches in graph
static UWord stats__hbefore_invals    = 0; // # cache invals

/* Running marker for depth-first searches */
/* NOTE: global variable */
static UInt dfsver_current = 0;

// FIXME: check this - is it really correct?
static Bool happens_before_do_dfs_from_to ( Segment* here, Segment* dst )
{
   /* begin SPEEDUP HACK */
   /* fast track common case, without favouring either the
      ->prev or ->other links */
   tl_assert(here);
   tl_assert(dst);
   if ((here->prev && here->prev == dst)
       || (here->other && here->other == dst)) {
      stats__hbefore_gsearchFs++;
      return True;
   }
   /* end SPEEDUP HACK */

  again:
   tl_assert(here);
   tl_assert(dst);
   if (here == dst)
      return True;
   tl_assert(here->dfsver <= dfsver_current);
   if (here->dfsver == dfsver_current)
      return False; /* We've been here before */
   /* Mark that we've been here */
   here->dfsver = dfsver_current;
   /* See if we can get to 'dst' via either of our two links */
   /* Avoiding recursion if possible */
   /* begin SPEEDUP hack -- the following can safely be omitted */
   if (here->prev && !here->other) {
      here = here->prev;
      goto again;
   }
   if (here->other && !here->prev) {
      here = here->other;
      goto again;
   }
   /* end of SPEEDUP HACK */
   /* GENERAL CASE -- recurse */
   if (here->other) {
      if (happens_before_do_dfs_from_to(here->other, dst))
         return True;
   }
   if (here->prev) {
      if (happens_before_do_dfs_from_to(here->prev, dst))
         return True;
   }
   return False;
}

// FIXME: cache the results of the last few queries and hand
// them out as appropriate
static Bool happens_before_wrk ( SegmentID segid1, SegmentID segid2 )
{
   Bool    reachable;
   Segment *seg1, *seg2;
   tl_assert(is_sane_SegmentID(segid1));
   tl_assert(is_sane_SegmentID(segid2));
   tl_assert(segid1 != segid2);
   seg1 = map_segments_lookup(segid1);
   seg2 = map_segments_lookup(segid2);
   tl_assert(is_sane_Segment(seg1));
   tl_assert(is_sane_Segment(seg2));
   tl_assert(seg1 != seg2);

   { static Int nnn = 0;
     if (SHOW_EXPENSIVE_STUFF && (nnn++ % 1000) == 0)
        VG_(printf)("happens_before_wrk: %d\n", nnn);
   }

   /* Now the question is, is there a chain of pointers through the
      .prev and .other fields, that leads from seg2 back to seg1 ? */
   tl_assert(dfsver_current < 0xFFFFFFFF);
   dfsver_current++;
   reachable = happens_before_do_dfs_from_to( seg2, seg1 );

   if (0)
   VG_(printf)("happens_before 0x%x 0x%x: %s\n",
               (Int)segid1, (Int)segid2, reachable ? "Y" : "N");

   return reachable;
}

/*--------------- the happens_before cache ---------------*/

#define HBEFORE__N_CACHE 64
typedef 
   struct { SegmentID segid1; SegmentID segid2; Bool result; } 
   HBeforeCacheEnt;

static HBeforeCacheEnt hbefore__cache[HBEFORE__N_CACHE];

static void hbefore__invalidate_cache ( void ) 
{
   Int i;
   SegmentID bogus = 0;
   tl_assert(!is_sane_SegmentID(bogus));
   stats__hbefore_invals++;
   for (i = 0; i < HBEFORE__N_CACHE; i++) {
      hbefore__cache[i].segid1 = bogus;
      hbefore__cache[i].segid2 = bogus;
      hbefore__cache[i].result = False;
   }
}

static Bool happens_before ( SegmentID segid1, SegmentID segid2 )
{
   Bool hb;
   Int  i, j, iNSERT_POINT;
   tl_assert(is_sane_SegmentID(segid1));
   tl_assert(is_sane_SegmentID(segid2));
   tl_assert(segid1 != segid2);
   stats__hbefore_queries++;
   stats__hbefore_probes++;
   if (segid1 == hbefore__cache[0].segid1 
       && segid2 == hbefore__cache[0].segid2) {
      stats__hbefore_cache0s++;
      return hbefore__cache[0].result;
   }
   for (i = 1; i < HBEFORE__N_CACHE; i++) {
      stats__hbefore_probes++;
      if (segid1 == hbefore__cache[i].segid1 
          && segid2 == hbefore__cache[i].segid2) {
         /* Found it.  Move it 1 step closer to the front. */
         HBeforeCacheEnt tmp = hbefore__cache[i];
         hbefore__cache[i]   = hbefore__cache[i-1];
         hbefore__cache[i-1] = tmp;
         stats__hbefore_cacheNs++;
         return tmp.result;
      }
   }
   /* Not found.  Search the graph and add an entry to the cache. */
   stats__hbefore_gsearches++;
   hb = happens_before_wrk( segid1, segid2 );
   iNSERT_POINT = (1*HBEFORE__N_CACHE)/4 - 1;
   /* if (iNSERT_POINT > 4) iNSERT_POINT = 4; */

   for (j = HBEFORE__N_CACHE-1; j > iNSERT_POINT; j--) {
      hbefore__cache[j] = hbefore__cache[j-1];
   }
   hbefore__cache[iNSERT_POINT].segid1 = segid1;
   hbefore__cache[iNSERT_POINT].segid2 = segid2;
   hbefore__cache[iNSERT_POINT].result = hb;

   if (0)
   VG_(printf)("hb %d %d\n", (Int)segid1-(1<<24), (Int)segid2-(1<<24));
   return hb;
}

/*--------------- generating .vcg output ---------------*/

static void segments__generate_vcg ( void )
{
#define PFX "xxxxxx"
   /* Edge colours:
         Black  -- the chain of .prev links
         Green  -- thread creation, link to parent
         Red    -- thread exit, link to exiting thread
         Yellow -- signal edge
   */
   Segment* seg;
   VG_(printf)(PFX "graph: { title: \"Segments\"\n");
   VG_(printf)(PFX "orientation: top_to_bottom\n");
   VG_(printf)(PFX "height: 900\n");
   VG_(printf)(PFX "width: 500\n");
   VG_(printf)(PFX "x: 20\n");
   VG_(printf)(PFX "y: 20\n");
   VG_(printf)(PFX "color: lightgrey\n");
   for (seg = admin_segments; seg; seg=seg->admin) {
      VG_(printf)(PFX "node: { title: \"%p\" color: lightcyan "
                  "textcolor: darkgreen label: \"Seg %x\\nThr %x\" }\n", 
                  seg, seg, seg->thr);
      if (seg->prev)
         VG_(printf)(PFX "edge: { sourcename: \"%p\" targetname: \"%p\""
                     "color: black }\n", seg->prev, seg );
      if (seg->other) {
         HChar* colour = "orange";
         switch (seg->other_hint) {
            case 'c': colour = "darkgreen";  break; /* creation */
            case 'j': colour = "red";        break; /* join (exit) */
            case 's': colour = "orange";     break; /* signal */
            case 'u': colour = "cyan";       break; /* unlock */
            default: tl_assert(0);
         }
         VG_(printf)(PFX "edge: { sourcename: \"%p\" targetname: \"%p\""
                     " color: %s }\n", seg->other, seg, colour );
      }
   }
   VG_(printf)(PFX "}\n");
#undef PFX
}


/*----------------------------------------------------------------*/
/*--- map_shmem :: WordFM Addr SecMap                          ---*/
/*--- shadow memory (low level handlers) (shmem__* fns)        ---*/
/*----------------------------------------------------------------*/

/*--------------- SecMap allocation --------------- */

static HChar* shmem__bigchunk_next = NULL;
static HChar* shmem__bigchunk_end1 = NULL;

static void* shmem__bigchunk_alloc ( SizeT n )
{
   const SizeT sHMEM__BIGCHUNK_SIZE = 4096 * 256;
   tl_assert(n > 0);
   n = ROUNDUP(n, 16);
   tl_assert(shmem__bigchunk_next <= shmem__bigchunk_end1);
   tl_assert(shmem__bigchunk_end1 - shmem__bigchunk_next
             <= (SSizeT)sHMEM__BIGCHUNK_SIZE);
   if (shmem__bigchunk_next + n > shmem__bigchunk_end1) {
      if (0)
      VG_(printf)("XXXXX bigchunk: abandoning %d bytes\n", 
                  (Int)(shmem__bigchunk_end1 - shmem__bigchunk_next));
      shmem__bigchunk_next = VG_(am_shadow_alloc)( sHMEM__BIGCHUNK_SIZE );
      shmem__bigchunk_end1 = shmem__bigchunk_next + sHMEM__BIGCHUNK_SIZE;
   }
   tl_assert(shmem__bigchunk_next);
   tl_assert( 0 == (((Addr)shmem__bigchunk_next) & (16-1)) );
   tl_assert(shmem__bigchunk_next + n <= shmem__bigchunk_end1);
   shmem__bigchunk_next += n;
   return shmem__bigchunk_next - n;
}

static SecMap* shmem__alloc_SecMap ( void )
{
   Int     i;
   SecMap* sm = shmem__bigchunk_alloc( sizeof(SecMap) );
   if (0) VG_(printf)("alloc_SecMap %p\n",sm);
   tl_assert(sm);
   sm->anyLocks = False;  /* dangerous */
   sm->anyShared = False; /* dangerous */
   sm->magic = SecMap_MAGIC;
   for (i = 0; i < N_SECMAP_W32S; i++)
      sm->w32s[i] = SHMEM_NoAccess;
   /* Invalidate the cache */
   shmem__invalidate_cache();
   return sm;
}

/*--------------- cache management/lookup --------------- */

static UWord stats__shmem_rw32s     = 0; // total # accesses
static UWord stats__shmem_cache0s   = 0; // hits at cache[0]
static UWord stats__shmem_cacheNs   = 0; // hits at cache[> 0]
static UWord stats__shmem_tsearches = 0; // searches in tree
static UWord stats__shmem_invals    = 0; // # cache invals


/* Keys in the fast cache (and in the backing tree) are rounded down
   to SecMap address boundaries.  So the least significant bit will
   never be 1.  Therefore it is safe to mark unused entries in the
   cache by using a key value with the lsb set to 1 as it will never
   match any valid key value. */

#define SHMEM__N_CACHE 8
static 
   struct { Addr key; SecMap* sm; } 
   shmem__cache[SHMEM__N_CACHE];

static void shmem__invalidate_cache ( void ) 
{
   Int i;
   stats__shmem_invals++;
   for (i = 0; i < SHMEM__N_CACHE; i++) {
      shmem__cache[i].key = 1; /*INVALID*/
      shmem__cache[i].sm = NULL;
   }
}

/* The following macros are bought to you directly from the Department
   of C Preprocessor Abuse :-) */

/* Given guest address _gaf, set _secmapf to point to the relevant
   SecMap, and _swordPf to point to the relevant 32-bit word inside
   the SecMap.  If there is no SecMap currently covering the address,
   one is allocated. */
#define SHMEM__addr_to_SecMap_and_SWord_writable(_secmapf,_swordPf,_gaf) \
   do {                                                                  \
      Int _i, _j;                                                        \
      const Addr _ga    = (_gaf);                                        \
      const Addr _gaKey = _ga & N_SECMAP_MASK;                           \
      const Word _ix    = (_ga & (N_SECMAP_ARANGE-1)) >> 2;              \
      stats__shmem_rw32s++;                                              \
      tl_assert(_ix < N_SECMAP_W32S);                                    \
      if (_gaKey == shmem__cache[0].key) {                               \
         SecMap* _sm = shmem__cache[0].sm;                               \
         _secmapf = _sm;                                                 \
         _swordPf = &_sm->w32s[_ix];                                     \
         stats__shmem_cache0s++;                                         \
         goto out;                                                       \
      }                                                                  \
      for (_i = 1; _i < SHMEM__N_CACHE; _i++) {                          \
         if (_gaKey == shmem__cache[_i].key) {                           \
            /* Found it.  Move it 1 step closer to the front. */         \
            Addr    _tK = shmem__cache[_i].key;                          \
            SecMap* _tS = shmem__cache[_i].sm;                           \
            shmem__cache[_i].key = shmem__cache[_i-1].key;               \
            shmem__cache[_i].sm  = shmem__cache[_i-1].sm;                \
            shmem__cache[_i-1].key = _tK;                                \
            shmem__cache[_i-1].sm  = _tS;                                \
            _secmapf = _tS;                                              \
            _swordPf = &_tS->w32s[_ix];                                  \
            stats__shmem_cacheNs++;                                      \
            goto out;                                                    \
         }                                                               \
      }                                                                  \
      /* Not found.  Find in backing tree and add a cache entry if */    \
      /* found. */                                                       \
      { SecMap* _sm = NULL;                                              \
        stats__shmem_tsearches++;                                        \
        if (TC_(lookupFM)( map_shmem,                                    \
                           NULL/*keyP*/, (Word*)&_sm, (Word)_gaKey )) {  \
           /* Found; address of SecMap is in sm */                       \
           tl_assert(_sm);                                               \
        } else {                                                         \
           /* create a new one */                                        \
           _sm = shmem__alloc_SecMap();                                  \
           tl_assert(_sm);                                               \
           TC_(addToFM)( map_shmem, (Word)_gaKey, (Word)_sm );           \
        }                                                                \
        for (_j = SHMEM__N_CACHE-1; _j > SHMEM__N_CACHE/2; _j--) {       \
           shmem__cache[_j].key = shmem__cache[_j-1].key;                \
           shmem__cache[_j].sm  = shmem__cache[_j-1].sm;                 \
        }                                                                \
        shmem__cache[SHMEM__N_CACHE/2].key = _gaKey;                     \
        shmem__cache[SHMEM__N_CACHE/2].sm  = _sm;                        \
        _secmapf = _sm;                                                  \
        _swordPf = &_sm->w32s[_ix];                                      \
      }                                                                  \
     out:                                                                \
      do {} while (0); /* stop gcc complaining */                        \
   } while (0)


/* Given guest address _gaf, set _secmapf to point to the relevant
   SecMap, and _swordPf to point to the relevant 32-bit word inside
   the SecMap.  If there is no SecMap currently covering the address,
   do not allocate one; instead set both _secmapf and _swordPf to NULL
   to indicate this situation. */
#define SHMEM__addr_to_SecMap_and_SWord_readable(_secmapf,_swordPf,_gaf) \
   do {                                                                  \
      Int _i, _j;                                                        \
      const Addr _ga    = (_gaf);                                        \
      const Addr _gaKey = _ga & N_SECMAP_MASK;                           \
      const Word _ix    = (_ga & (N_SECMAP_ARANGE-1)) >> 2;              \
      stats__shmem_rw32s++;                                              \
      tl_assert(_ix < N_SECMAP_W32S);                                    \
      if (_gaKey == shmem__cache[0].key) {                               \
         SecMap* _sm = shmem__cache[0].sm;                               \
         _secmapf = _sm;                                                 \
         _swordPf = &sm->w32s[_ix];                                      \
         stats__shmem_cache0s++;                                         \
         goto out;                                                       \
      }                                                                  \
      for (_i = 1; _i < SHMEM__N_CACHE; _i++) {                          \
         if (_gaKey == shmem__cache[_i].key) {                           \
            /* Found it.  Move it 1 step closer to the front. */         \
            Addr    _tK = shmem__cache[_i].key;                          \
            SecMap* _tS = shmem__cache[_i].sm;                           \
            shmem__cache[_i].key = shmem__cache[_i-1].key;               \
            shmem__cache[_i].sm  = shmem__cache[_i-1].sm;                \
            shmem__cache[_i-1].key = _tK;                                \
            shmem__cache[_i-1].sm  = _tS;                                \
            _secmapf = _tS;                                              \
            _swordPf = &_tS->w32s[_ix];                                  \
            stats__shmem_cacheNs++;                                      \
            goto out;                                                    \
         }                                                               \
      }                                                                  \
      /* Not found.  Find in backing tree and add a cache entry if */    \
      /* found. */                                                       \
      { SecMap* _sm = NULL;                                              \
        stats__shmem_tsearches++;                                        \
        if (TC_(lookupFM)( map_shmem,                                    \
                           NULL/*keyP*/, (Word*)&_sm, (Word)_gaKey )) {  \
           /* Found; address of SecMap is in sm */                       \
           tl_assert(_sm);                                               \
           for (_j = SHMEM__N_CACHE-1; _j > SHMEM__N_CACHE/2; _j--) {    \
              shmem__cache[_j].key = shmem__cache[_j-1].key;             \
              shmem__cache[_j].sm  = shmem__cache[_j-1].sm;              \
           }                                                             \
           shmem__cache[SHMEM__N_CACHE/2].key = _gaKey;                  \
           shmem__cache[SHMEM__N_CACHE/2].sm  = _sm;                     \
           _secmapf = _sm;                                               \
           _swordPf = &_sm->w32s[_ix];                                   \
        } else {                                                         \
           /* not found in the backing tree */                           \
           _secmapf = NULL;                                              \
           _swordPf = NULL;                                              \
        }                                                                \
      }                                                                  \
     out:                                                                \
      do {} while (0); /* stop gcc complaining */                        \
   } while (0)

/* Convenience functions.  Don't use these if speed is important. */

static UInt shmem__read_32 ( Addr ga )
{
   SecMap* sm     = NULL;
   UInt*   swordP = NULL;
   SHMEM__addr_to_SecMap_and_SWord_readable( sm, swordP, ga );
   if (sm) 
      return *swordP;
   else
      return SHMEM_NoAccess;
}

static void shmem__write_32 ( Addr ga, UInt w32 )
{
   SecMap* sm     = NULL;
   UInt*   swordP = NULL;
   SHMEM__addr_to_SecMap_and_SWord_writable( sm, swordP, ga );
   tl_assert(sm);
   tl_assert(swordP);
   *swordP = w32;
   if (is_SHMEM_Sh(w32))
      sm->anyShared = True;
}


/*--------------- misc --------------- */

static inline Addr shmem__round_to_SecMap_base ( Addr a ) {
   return a & N_SECMAP_MASK;
}
static inline Bool shmem__is_SecMap_base ( Addr a ) {
   return (a & ~N_SECMAP_MASK) == 0;
}

static Bool shmem__get_anyLocks ( Addr a )
{
   SecMap* sm;
   Addr aKey = a & N_SECMAP_MASK;
   if (TC_(lookupFM)( map_shmem, NULL/*keyP*/, (Word*)&sm, (Word)aKey )) {
      /* Found */
      return sm->anyLocks;
   } else {
      return False;
   }
}

static void shmem__set_anyLocks ( Addr a, Bool b )
{
   SecMap* sm;
   const Addr aKey = a & N_SECMAP_MASK;
   tl_assert(b == False || b == True);
   if (TC_(lookupFM)( map_shmem, NULL/*keyP*/, (Word*)&sm, (Word)aKey )) {
      /* Found; address of SecMap is in sm */
   } else {
      /* create a new one */
      sm = shmem__alloc_SecMap();
      tl_assert(sm);
      TC_(addToFM)( map_shmem, (Word)aKey, (Word)sm );
   }
   sm->anyLocks = b;
}

static void shmem__set_anyShared ( Addr a, Bool b )
{
   SecMap* sm;
   const Addr aKey = a & N_SECMAP_MASK;
   tl_assert(b == False || b == True);
   if (TC_(lookupFM)( map_shmem, NULL/*keyP*/, (Word*)&sm, (Word)aKey )) {
      /* Found; address of SecMap is in sm */
   } else {
      /* create a new one */
      sm = shmem__alloc_SecMap();
      tl_assert(sm);
      TC_(addToFM)( map_shmem, (Word)aKey, (Word)sm );
   }
   sm->anyShared = b;
}

/* Block-copy states (needed for implementing realloc()). */
static void shmem__copy_arange_state(Addr src, Addr dst, SizeT len)
{
   SizeT i;
   for (i = 0; i < len; i += 4) {
      UInt sword = shmem__read_32( src+i );
      shmem__write_32 ( dst+i, sword );
   }
}


/*----------------------------------------------------------------*/
/*--- Sanity checking the data structures                      ---*/
/*----------------------------------------------------------------*/

/* REQUIRED INVARIANTS:

   Thread vs Segment/Lock/SecMaps

      for each t in Threads {

         // Thread.lockset: each element is really a valid Lock

         // Thread.lockset: each Lock in set is actually held by that thread
         for lk in Thread.lockset 
            lk == LockedBy(t)

         // Thread.csegid is a valid SegmentID
         // and the associated Segment has .thr == t

      }

      all thread Locksets are pairwise empty under intersection
      (that is, no lock is claimed to be held by more than one thread)
      -- this is guaranteed if all locks in locksets point back to their
      owner threads

   Lock vs Thread/Segment/SecMaps

      for each entry (gla, la) in map_locks
         gla == la->guest_addr

      for each lk in Locks {

         lk->tag is valid
         lk->guest_addr does not have shadow state NoAccess
         if lk == LockedBy(t), then t->lockset contains lk
         if lk == UnlockedBy(segid) then segid is valid SegmentID
             and can be mapped to a valid Segment(seg)
             and seg->thr->lockset does not contain lk
         if lk == UnlockedNew then (no lockset contains lk)

         secmaps for lk has .anyLocks == True

      }

   Segment vs Thread/Lock/SecMaps

      the Segment graph is a dag (no cycles)
      all of the Segment graph must be reachable from the segids
         mentioned in the Threads

      for seg in Segments {

         seg->thr is a sane Thread

      }

   SecMaps vs Segment/Thread/Lock

      for sm in SecMaps {

         sm properly aligned
         if any shadow word is ShR or ShM then .anyShared == True

         for each Excl(segid) state
            map_segments_lookup maps to a sane Segment(seg)
         for each ShM/ShR(tsetid,lsetid) state
            each lk in lset is a valid Lock
            each thr in tset is a valid thread, which is non-dead

      }
*/


/* Return True iff 'thr' holds 'lk' in some mode. */
static Bool thread_is_a_holder_of_Lock ( Thread* thr, Lock* lk )
{
   if (lk->heldBy)
      return TC_(elemBag)( lk->heldBy, (Word)thr ) > 0;
   else
      return False;
}

/* Sanity check Threads, as far as possible */
static void threads__sanity_check ( Char* who )
{
#define BAD(_str) do { how = (_str); goto bad; } while (0)
   Char*     how = "no error";
   Thread*   thr;
   WordSetID wsA, wsW;
   Word*     ls_words;
   Word      ls_size, i;
   Lock*     lk;
   Segment*  seg;
   for (thr = admin_threads; thr; thr = thr->admin) {
      if (!is_sane_Thread(thr)) BAD("1");
      wsA = thr->locksetA;
      wsW = thr->locksetW;
      // locks held in W mode are a subset of all locks held
      if (!TC_(isSubsetOf)( univ_lsets, wsW, wsA )) BAD("7");
      TC_(getPayloadWS)( &ls_words, &ls_size, univ_lsets, wsA );
      for (i = 0; i < ls_size; i++) {
         lk = (Lock*)ls_words[i];
         // Thread.lockset: each element is really a valid Lock
         if (!is_sane_LockN(lk)) BAD("2");
         // Thread.lockset: each Lock in set is actually held by that
         // thread
         if (!thread_is_a_holder_of_Lock(thr,lk)) BAD("3");
         // Thread.csegid is a valid SegmentID
         if (!is_sane_SegmentID(thr->csegid)) BAD("4");
         // and the associated Segment has .thr == t
         seg = map_segments_maybe_lookup(thr->csegid);
         if (!is_sane_Segment(seg)) BAD("5");
         if (seg->thr != thr) BAD("6");
      }
   }
   return;
  bad:
   VG_(printf)("threads__sanity_check: who=\"%s\", bad=\"%s\"\n", who, how);
   tl_assert(0);
#undef BAD
}


/* Sanity check Locks, as far as possible */
static void locks__sanity_check ( Char* who )
{
#define BAD(_str) do { how = (_str); goto bad; } while (0)
   Char*     how = "no error";
   Addr      gla;
   Lock*     lk;
   Int       i;
   // # entries in admin_locks == # entries in map_locks
   for (i = 0, lk = admin_locks;  lk;  i++, lk = lk->admin)
      ;
   if (i != TC_(sizeFM)(map_locks)) BAD("1");
   // for each entry (gla, lk) in map_locks
   //      gla == lk->guest_addr
   TC_(initIterFM)( map_locks );
   while (TC_(nextIterFM)( map_locks, (Word*)&gla, (Word*)&lk )) {
      if (lk->guestaddr != gla) BAD("2");
   }
   TC_(doneIterFM)( map_locks );
   // scan through admin_locks ...
   for (lk = admin_locks; lk; lk = lk->admin) {
      // lock is sane.  Quite comprehensive, also checks that
      // referenced (holder) threads are sane.
      if (!is_sane_LockN(lk)) BAD("3");
      // map_locks binds guest address back to this lock
      if (lk != map_locks_maybe_lookup(lk->guestaddr)) BAD("4");
      // lk->guest_addr does not have shadow state NoAccess
      // FIXME: this could legitimately arise from a buggy guest
      // that attempts to lock in (eg) freed memory.  Detect this
      // and warn about it in the pre/post-mutex-lock event handler.
      if (is_SHMEM_NoAccess(shmem__read_32(lk->guestaddr))) BAD("5");
      // look at all threads mentioned as holders of this lock.  Ensure
      // this lock is mentioned in their locksets.
      if (lk->heldBy) {
         Thread* thr;
         Word    count;
         TC_(initIterBag)( lk->heldBy );
         while (TC_(nextIterBag)( lk->heldBy, (Word*)&thr, &count )) {
            // is_sane_LockN above ensures these
            tl_assert(count >= 1);
            tl_assert(is_sane_Thread(thr));
            if (!TC_(elemWS)(univ_lsets, thr->locksetA, (Word)lk)) 
               BAD("6");
            // also check the w-only lockset
            if (lk->heldW 
                && !TC_(elemWS)(univ_lsets, thr->locksetW, (Word)lk)) 
               BAD("7");
            if ((!lk->heldW)
                && TC_(elemWS)(univ_lsets, thr->locksetW, (Word)lk)) 
               BAD("8");
         }
         TC_(doneIterBag)( lk->heldBy );
      } else {
         /* lock not held by anybody */
         if (lk->heldW) BAD("9"); /* should be False if !heldBy */
         // since lk is unheld, then (no lockset contains lk)
         // hmm, this is really too expensive to check.  Hmm.
      }
      // secmaps for lk has .anyLocks == True
      if (!shmem__get_anyLocks(lk->guestaddr)) BAD("10");
   }

   return;
  bad:
   VG_(printf)("locks__sanity_check: who=\"%s\", bad=\"%s\"\n", who, how);
   tl_assert(0);
#undef BAD
}


/* Sanity check Segments, as far as possible */
static void segments__sanity_check ( Char* who )
{
#define BAD(_str) do { how = (_str); goto bad; } while (0)
   Char*    how = "no error";
   Int      i;
   Segment* seg;
   // FIXME
   //   the Segment graph is a dag (no cycles)
   //   all of the Segment graph must be reachable from the segids
   //      mentioned in the Threads
   // # entries in admin_segments == # entries in map_segments
   for (i = 0, seg = admin_segments;  seg;  i++, seg = seg->admin)
      ;
   if (i != TC_(sizeFM)(map_segments)) BAD("1");
   // for seg in Segments {
   for (seg = admin_segments; seg; seg = seg->admin) {
      if (!is_sane_Segment(seg)) BAD("2");
      if (!is_sane_Thread(seg->thr)) BAD("3");
   }
   return;
  bad:
   VG_(printf)("segments__sanity_check: who=\"%s\", bad=\"%s\"\n", 
               who, how);
   tl_assert(0);
#undef BAD
}


/* Sanity check shadow memory, as far as possible */
static void shmem__sanity_check ( Char* who )
{
#define BAD(_str) do { how = (_str); goto bad; } while (0)
   Char*   how = "no error";
   Word    smga;
   SecMap* sm;
   Word    i, j, ws_size;
   Word*   ws_words;
   TC_(initIterFM)( map_shmem );
   // for sm in SecMaps {
   while (TC_(nextIterFM)( map_shmem, (Word*)&smga, (Word*)&sm )) {
      Bool anyShared = False;
      Bool allNoAccess = True;
      if (!is_sane_SecMap(sm)) BAD("1");
      // sm properly aligned
      if (smga & ~N_SECMAP_MASK) BAD("2");
      // if any shadow word is ShR or ShM then .anyShared == True
      for (i = 0; i < N_SECMAP_W32S; i++) {
         UInt w32 = sm->w32s[i];
         if (is_SHMEM_Sh(w32)) 
            anyShared = True;
         if (!is_SHMEM_NoAccess(w32))
            allNoAccess = False;
         if (is_SHMEM_Excl(w32)) {
            // for each Excl(segid) state
            // map_segments_lookup maps to a sane Segment(seg)
            Segment*  seg;
            SegmentID segid = un_SHMEM_Excl(w32);
            if (!is_sane_SegmentID(segid)) BAD("4");
            seg = map_segments_maybe_lookup(segid);
            if (!is_sane_Segment(seg)) BAD("5");
         } 
         else if (is_SHMEM_Sh(w32)) {
            WordSetID tset = un_SHMEM_Sh_tset(w32);
            WordSetID lset = un_SHMEM_Sh_lset(w32);
            if (!TC_(plausibleWS)( univ_tsets, tset )) BAD("6");
            if (!TC_(saneWS_SLOW)( univ_tsets, tset )) BAD("6a");
            if (TC_(isEmptyWS)( univ_tsets, tset )) BAD("6b");
            if (!TC_(plausibleWS)( univ_lsets, lset )) BAD("7");
            if (!TC_(saneWS_SLOW)( univ_lsets, lset )) BAD("7b");
            TC_(getPayloadWS)( &ws_words, &ws_size, univ_lsets, lset );
            for (j = 0; j < ws_size; j++) {
               Lock* lk = (Lock*)ws_words[j];
               // for each ShM/ShR(tsetid,lsetid) state
               // each lk in lset is a valid Lock
               if (!is_sane_LockN(lk)) BAD("8");
            }
            TC_(getPayloadWS)( &ws_words, &ws_size, univ_tsets, tset );
            for (j = 0; j < ws_size; j++) {
               Thread* thr = (Thread*)ws_words[j];
               //for each ShM/ShR(tsetid,lsetid) state
               // each thr in tset is a valid thread, which is non-dead
               if (!is_sane_Thread(thr)) BAD("9");
               // FIXME
               // if (thr->state != TS_Alive) BAD("10");
            }
         }
         else if (is_SHMEM_NoAccess(w32) || is_SHMEM_New(w32)) {
            /* nothing to check */
         }
         else {
            /* bogus shadow mem value */
            BAD("11");
         }
      } /* iterating over a SecMap */
      // Check essential safety property
      if (anyShared && !sm->anyShared) BAD("3");
      // This is optional - check that destroyed memory has its hint
      // bits cleared.  NB won't work properly unless full, eager
      // GCing of SecMaps is implemented
      //if (allNoAccess && sm->anyLocks) BAD("3a");
   }
   TC_(doneIterFM)( map_shmem );
   return;
  bad:
   VG_(printf)("shmem__sanity_check: who=\"%s\", bad=\"%s\"\n", who, how);
   tl_assert(0);
#undef BAD
}

static void all__sanity_check ( char* who )
{
   if (0) VG_(printf)("all__sanity_check(%s)\n", who);
   threads__sanity_check(who);
   locks__sanity_check(who);
   segments__sanity_check(who);
   shmem__sanity_check(who);
}


/*----------------------------------------------------------------*/
/*--- the core memory state machine (msm__* functions)         ---*/
/*----------------------------------------------------------------*/

static UWord stats__msm_r32_Excl_nochange = 0;
static UWord stats__msm_r32_Excl_transfer = 0;
static UWord stats__msm_r32_Excl_to_ShR   = 0;
static UWord stats__msm_r32_ShR_to_ShR    = 0;
static UWord stats__msm_r32_ShM_to_ShM    = 0;
static UWord stats__msm_r32_New_to_Excl   = 0;
static UWord stats__msm_r32_NoAccess      = 0;

static UWord stats__msm_w32_Excl_nochange = 0;
static UWord stats__msm_w32_Excl_transfer = 0;
static UWord stats__msm_w32_Excl_to_ShM   = 0;
static UWord stats__msm_w32_ShR_to_ShM    = 0;
static UWord stats__msm_w32_ShM_to_ShM    = 0;
static UWord stats__msm_w32_New_to_Excl   = 0;
static UWord stats__msm_w32_NoAccess      = 0;

/* fwds */
static void record_error_Race ( Thread* thr, 
                                Addr data_addr, Bool isWrite, Int szB,
                                UInt old_w32, UInt new_w32, 
                                ExeContext* mb_lastlock );

static void record_error_FreeMemLock ( Thread* thr, Lock* lk );

static void record_error_UnlockUnlocked ( Thread*, Lock* );
static void record_error_UnlockForeign  ( Thread*, Thread*, Lock* );
static void record_error_UnlockBogus    ( Thread*, Addr );
static void record_error_DestroyLocked  ( Thread*, Lock* );
static void record_error_PthAPIerror    ( Thread*, HChar*, Word, HChar* );

static void record_error_Misc ( Thread*, HChar* );

static WordSetID add_BHL ( WordSetID lockset )
{
   return TC_(addToWS)( univ_lsets, lockset, (Word)__bus_lock_Lock );
}

/* Last-lock-lossage records.  This mechanism exists to help explain
   to programmers why we are complaining about a race.  The idea is to
   monitor all lockset transitions.  When a previously nonempty
   lockset becomes empty, the lock(s) that just disappeared (the
   "lossage") are the locks that have consistently protected the
   location (ga_of_access) in question for the longest time.  Most of
   the time the lossage-set is a single lock.  Because the
   lossage-lock is the one that has survived longest, there is there
   is a good chance that it is indeed the lock that the programmer
   intended to use to protect the location.

   Note that we cannot in general just look at the lossage set when we
   see a transition to ShM(...,empty-set), because a transition to an
   empty lockset can happen arbitrarily far before the point where we
   want to report an error.  This is in the case where there are many
   transitions ShR -> ShR, all with an empty lockset, and only later
   is there a transition to ShM.  So what we want to do is note the
   lossage lock at the point where a ShR -> ShR transition empties out
   the lockset, so we can present it later if there should be a
   transition to ShM.

   So this function finds such transitions.  For each, it associates
   in ga_to_lastlock, the guest address and the lossage lock.  In fact
   we do not record the Lock* directly as that may disappear later,
   but instead the ExeContext inside the Lock which says where it was
   initialised or first locked.  ExeContexts are permanent so keeping
   them indefinitely is safe.

   A boring detail: the hardware bus lock is not interesting in this
   respect, so we first remove that from the pre/post locksets.
*/

static UWord stats__ga_LL_adds = 0;

static WordFM* ga_to_lastlock = NULL; /* GuestAddr -> ExeContext* */

static 
void record_last_lock_lossage ( Addr ga_of_access,
                                WordSetID lset_old, WordSetID lset_new )
{
   Lock* lk;
   Int   card_old, card_new;

   tl_assert(lset_old != lset_new);
   tl_assert(VG_IS_4_ALIGNED(ga_of_access));

   if (0) VG_(printf)("XX1: %d (card %d) -> %d (card %d) %p\n", 
                      (Int)lset_old, 
                      TC_(cardinalityWS)(univ_lsets,lset_old),
                      (Int)lset_new, 
                      TC_(cardinalityWS)(univ_lsets,lset_new),
                      ga_of_access );

   /* This is slow, but at least it's simple.  The bus hardware lock
      just confuses the logic, so remove it from the locksets we're
      considering before doing anything else. */
   lset_new = TC_(delFromWS)( univ_lsets, lset_new, (Word)__bus_lock_Lock );

   if (!TC_(isEmptyWS)( univ_lsets, lset_new )) {
      /* The post-transition lock set is not empty.  So we are not
         interested.  We're only interested in spotting transitions
         that make locksets become empty. */
      return;
   }

   /* lset_new is now empty */
   card_new = TC_(cardinalityWS)( univ_lsets, lset_new );
   tl_assert(card_new == 0);

   lset_old = TC_(delFromWS)( univ_lsets, lset_old, (Word)__bus_lock_Lock );
   card_old = TC_(cardinalityWS)( univ_lsets, lset_old );

   if (0) VG_(printf)(" X2: %d (card %d) -> %d (card %d)\n",
                      (Int)lset_old, card_old, (Int)lset_new, card_new );

   if (card_old == 0) {
      /* The old lockset was also empty.  Not interesting. */
      return;
   }

   tl_assert(card_old > 0);
   tl_assert(!TC_(isEmptyWS)( univ_lsets, lset_old ));

   /* Now we know we've got a transition from a nonempty lockset to an
      empty one.  So lset_old must be the set of locks lost.  Record
      some details.  If there is more than one element in the lossage
      set, just choose one arbitrarily -- not the best, but at least
      it's simple. */

   lk = (Lock*)TC_(anyElementOfWS)( univ_lsets, lset_old );
   if (0) VG_(printf)("lossage %d %p\n", 
                      TC_(cardinalityWS)( univ_lsets, lset_old), lk );
   if (lk->appeared_at) {
      if (ga_to_lastlock == NULL)
         ga_to_lastlock = TC_(newFM)( tc_zalloc, tc_free, NULL );
      TC_(addToFM)( ga_to_lastlock, ga_of_access, (Word)lk->appeared_at );
      stats__ga_LL_adds++;
   }
}

/* This queries the table (ga_to_lastlock) made by
   record_last_lock_lossage, when constructing error messages.  It
   attempts to find the ExeContext of the allocation or initialisation
   point for the lossage lock associated with 'ga'. */

static ExeContext* maybe_get_lastlock_initpoint ( Addr ga ) 
{
   ExeContext* ec_hint = NULL;
   tl_assert(VG_IS_4_ALIGNED(ga));
   if (ga_to_lastlock != NULL 
       && TC_(lookupFM)(ga_to_lastlock, NULL, (Word*)&ec_hint, ga)) {
      tl_assert(ec_hint != NULL);
      return ec_hint;
   } else {
      return NULL;
   }
}

static void msm__handle_read_aligned_32 ( Thread* thr_acc, Addr a )
{
   UInt    wold;
   SecMap* sm;
   UInt*   swordP;

   tl_assert(is_sane_Thread(thr_acc));

   if (0) VG_(printf)("read32 thr=%p %p\n", thr_acc, a);

   a = ROUNDDN(a,4);
   SHMEM__addr_to_SecMap_and_SWord_writable(sm,swordP,a);
   /* Yes, really _writable.  As a result of this client read, the
      state of the shadow word may change, so we have to be able to
      write it as well as read it. */

   wold = *swordP;

   /* Exclusive */
   if (is_SHMEM_Excl(wold)) {
      /* read Excl(segid) 
           |  segid_old == segid-of-thread
           -> no change
           |  segid_old `happens_before` segid-of-this-thread
           -> Excl(segid-of-this-thread)
           |  otherwise
           -> ShR
      */
      SegmentID segid_old = un_SHMEM_Excl(wold);
      tl_assert(is_sane_SegmentID(segid_old));
      if (segid_old == thr_acc->csegid) {
         /* no change */
         stats__msm_r32_Excl_nochange++;
      }
      else if (happens_before(segid_old, thr_acc->csegid)) {
         /* -> Excl(segid-of-this-thread) */
         UInt wnew = mk_SHMEM_Excl(thr_acc->csegid);
         *swordP = wnew;
         stats__msm_r32_Excl_transfer++;
      }
      else {
         /* Enter the shared-readonly (ShR) state. */
         UInt      wnew;
         WordSetID tset, lset;
         /* This location has been accessed by precisely two threads.
            Make an appropriate tset. */
         // FIXME: performance: duplicate map_segments_lookup(segid_old)
         // since must also be done in happens_before()
         Segment* seg_old = map_segments_lookup( segid_old );
         Thread*  thr_old = seg_old->thr;
         tset = TC_(doubletonWS)( univ_tsets, (Word)thr_old, (Word)thr_acc );
         lset = add_BHL( thr_acc->locksetA ); /* read ==> use all locks */
         wnew = mk_SHMEM_ShR( tset, lset );
         *swordP = wnew;
         sm->anyShared = True;
         stats__msm_r32_Excl_to_ShR++;
      }
   } 
   /* Shared-Readonly */
   else if (is_SHMEM_ShR(wold)) {
     /* read Shared-Readonly(threadset, lockset)
        We remain in ShR state, but add this thread to the 
        threadset and refine the lockset accordingly.  Do not
        complain if the lockset becomes empty -- that's ok. */
      WordSetID tset_old = un_SHMEM_ShR_tset(wold);
      WordSetID lset_old = un_SHMEM_ShR_lset(wold);
      WordSetID tset_new = TC_(addToWS)( univ_tsets, 
                                         tset_old, (Word)thr_acc );
      WordSetID lset_new = TC_(intersectWS)( univ_lsets,
                                             lset_old, 
                                             add_BHL(thr_acc->locksetA)
                                             /* read ==> use all locks */ );
      UInt      wnew     = mk_SHMEM_ShR( tset_new, lset_new );
      if (lset_old != lset_new)
         record_last_lock_lossage(a,lset_old,lset_new);
      *swordP = wnew;
      tl_assert(sm->anyShared);
      stats__msm_r32_ShR_to_ShR++;
   } 
   /* Shared-Modified */
   else if (is_SHMEM_ShM(wold)) {
      /* read Shared-Modified(threadset, lockset)
         We remain in ShM state, but add this thread to the 
         threadset and refine the lockset accordingly.
         If the lockset becomes empty, complain. */
      WordSetID tset_old = un_SHMEM_ShM_tset(wold);
      WordSetID lset_old = un_SHMEM_ShM_lset(wold);
      WordSetID tset_new = TC_(addToWS)( univ_tsets,
                                         tset_old, (Word)thr_acc );
      WordSetID lset_new = TC_(intersectWS)( univ_lsets,
                                             lset_old,
                                             add_BHL(thr_acc->locksetA)
                                             /* read ==> use all locks */ ); 
      UInt      wnew     = mk_SHMEM_ShM( tset_new, lset_new );
      if (lset_old != lset_new)
         record_last_lock_lossage(a,lset_old,lset_new);
      if (TC_(isEmptyWS)(univ_lsets, lset_new)
          && !TC_(isEmptyWS)(univ_lsets, lset_old)) {
         record_error_Race( thr_acc, a, 
                            False/*isWrite*/, 4/*szB*/, wold, wnew,
                            maybe_get_lastlock_initpoint(a) );
      }
      *swordP = wnew;
      tl_assert(sm->anyShared);
      stats__msm_r32_ShM_to_ShM++;
   } 
   /* New */
   else if (is_SHMEM_New(wold)) {
      /* read New -> Excl(segid) */
      *swordP = mk_SHMEM_Excl( thr_acc->csegid );
      stats__msm_r32_New_to_Excl++;
   } 
   /* NoAccess */
   else if (is_SHMEM_NoAccess(wold)) {
      // FIXME: complain if accessing here
      // FIXME: transition to Excl?
      if (0)
      VG_(printf)(
         "msm__handle_read_aligned_32(thr=%p, addr=%p): NoAccess\n",
         thr_acc, (void*)a );
      stats__msm_r32_NoAccess++;
   } 
   /* hmm, bogus state */
   else {
      tl_assert(0);
   }
}

static void msm__handle_write_aligned_32 ( Thread* thr_acc, Addr a )
{
   UInt    wold;
   SecMap* sm;
   UInt*   swordP;

   tl_assert(is_sane_Thread(thr_acc));

   if (0) VG_(printf)("write32 thr=%p %p\n", thr_acc, a);

   a = ROUNDDN(a,4);
   SHMEM__addr_to_SecMap_and_SWord_writable(sm,swordP,a);

   wold = *swordP;

   /* New */
   if (is_SHMEM_New(wold)) {
      /* write New -> Excl(segid) */
      *swordP = mk_SHMEM_Excl( thr_acc->csegid );
      stats__msm_w32_New_to_Excl++;
   } 
   /* Exclusive */
   else if (is_SHMEM_Excl(wold)) {
      // I believe is identical to case for read Excl
      // apart from enters ShM rather than ShR 
      /* read Excl(segid) 
           |  segid_old == segid-of-thread
           -> no change
           |  segid_old `happens_before` segid-of-this-thread
           -> Excl(segid-of-this-thread)
           |  otherwise
           -> ShM
      */
      SegmentID segid_old = un_SHMEM_Excl(wold);
      tl_assert(is_sane_SegmentID(segid_old));
      if (segid_old == thr_acc->csegid) {
         /* no change */
         stats__msm_w32_Excl_nochange++;
      }
      else if (happens_before(segid_old, thr_acc->csegid)) {
         /* -> Excl(segid-of-this-thread) */
         UInt wnew = mk_SHMEM_Excl(thr_acc->csegid);
         *swordP = wnew;
         stats__msm_w32_Excl_transfer++;
      }
      else {
         /* Enter the shared-modified (ShM) state. */
         UInt      wnew;
         WordSetID tset, lset;
         /* This location has been accessed by precisely two threads.
            Make an appropriate tset. */
         // FIXME: performance: duplicate map_segments_lookup(segid_old)
         // since must also be done in happens_before()
         Segment* seg_old = map_segments_lookup( segid_old );
         Thread*  thr_old = seg_old->thr;
         tset = TC_(doubletonWS)( univ_tsets, (Word)thr_old, (Word)thr_acc );
         lset = thr_acc->locksetW; /* write ==> use only w-held locks */
         wnew = mk_SHMEM_ShM( tset, lset );
         *swordP = wnew;
         sm->anyShared = True;
         if (TC_(isEmptyWS)(univ_lsets, lset)) {
            record_error_Race( thr_acc, 
                               a, True/*isWrite*/, 4/*szB*/, wold, wnew,
                               maybe_get_lastlock_initpoint(a) );
         }
         stats__msm_w32_Excl_to_ShM++;
      }
   } 
   /* Shared-Readonly */
   else if (is_SHMEM_ShR(wold)) {
      /* write Shared-Readonly(threadset, lockset)
         We move to ShM state, add this thread to the 
         threadset and refine the lockset accordingly.
         If the lockset becomes empty, complain. */
      WordSetID tset_old = un_SHMEM_ShR_tset(wold);
      WordSetID lset_old = un_SHMEM_ShR_lset(wold);
      WordSetID tset_new = TC_(addToWS)( univ_tsets, 
                                         tset_old, (Word)thr_acc );
      WordSetID lset_new = TC_(intersectWS)(
                              univ_lsets, 
                              lset_old, 
                              thr_acc->locksetW
                              /* write ==> use only w-held locks */
                           );
      UInt      wnew     = mk_SHMEM_ShM( tset_new, lset_new );
      if (lset_old != lset_new)
         record_last_lock_lossage(a,lset_old,lset_new);
      if (TC_(isEmptyWS)(univ_lsets, lset_new)) {
         record_error_Race( thr_acc, a, 
                            True/*isWrite*/, 4/*szB*/, wold, wnew,
                            maybe_get_lastlock_initpoint(a) );
      }
      *swordP = wnew;
      tl_assert(sm->anyShared);
      stats__msm_w32_ShR_to_ShM++;
   } 
   /* Shared-Modified */
   else if (is_SHMEM_ShM(wold)) {
      /* write Shared-Modified(threadset, lockset)
         We remain in ShM state, but add this thread to the 
         threadset and refine the lockset accordingly.
         If the lockset becomes empty, complain. */
      WordSetID tset_old = un_SHMEM_ShM_tset(wold);
      WordSetID lset_old = un_SHMEM_ShM_lset(wold);
      WordSetID tset_new = TC_(addToWS)( univ_tsets,
                                         tset_old, (Word)thr_acc );
      WordSetID lset_new = TC_(intersectWS)( 
                              univ_lsets,
                              lset_old, 
                              thr_acc->locksetW 
                              /* write ==> use only w-held locks */
                           ); 
      UInt      wnew     = mk_SHMEM_ShM( tset_new, lset_new );
      if (lset_old != lset_new)
         record_last_lock_lossage(a,lset_old,lset_new);
      if (TC_(isEmptyWS)(univ_lsets, lset_new)
          && !TC_(isEmptyWS)(univ_lsets, lset_old)) {
         record_error_Race( thr_acc, a, 
                            True/*isWrite*/, 4/*szB*/, wold, wnew,
                            maybe_get_lastlock_initpoint(a) );
      }
      *swordP = wnew;
      tl_assert(sm->anyShared);
      stats__msm_w32_ShM_to_ShM++;
   } 
   /* NoAccess */
   else if (is_SHMEM_NoAccess(wold)) {
      // FIXME: complain if accessing here
      // FIXME: transition to Excl?
      if (0)
      VG_(printf)(
         "msm__handle_write_aligned_32(thr=%p, addr=%p): NoAccess\n",
         thr_acc, (void*)a );
      stats__msm_w32_NoAccess++;
   } 
   /* hmm, bogus state */
   else {
      VG_(printf)("msm__handle_write_aligned_32: bogus old state 0x%x\n", 
                  wold);
      tl_assert(0);
   }
}


/*----------------------------------------------------------------*/
/*--- Address range handlers                                   ---*/
/*----------------------------------------------------------------*/

static void remove_Lock_from_locksets_of_all_owning_Threads( Lock* lk )
{
   Thread* thr;
   if (!lk->heldBy) {
      tl_assert(!lk->heldW);
      return;
   }
   /* for each thread that holds this lock do ... */
   TC_(initIterBag)( lk->heldBy );
   while (TC_(nextIterBag)( lk->heldBy, (Word*)&thr, NULL )) {
      tl_assert(is_sane_Thread(thr));
      tl_assert(TC_(elemWS)( univ_lsets,
                             thr->locksetA, (Word)lk ));
      thr->locksetA
         = TC_(delFromWS)( univ_lsets, thr->locksetA, (Word)lk );

      if (lk->heldW) {
         tl_assert(TC_(elemWS)( univ_lsets,
                                thr->locksetW, (Word)lk ));
         thr->locksetW
            = TC_(delFromWS)( univ_lsets, thr->locksetW, (Word)lk );
      }
   }
   TC_(doneIterBag)( lk->heldBy );
}

/* Deletion of memory containing locks:

   If the range of memory to be deleted contains no locks, then this
   is simple: set the range to NoAccess.  This is the fast (hopefully
   common) case.

   Otherwise, the range contains some locks.  Then we have to do all
   the complexity below and only then set the range to NoAccess.

   // make up a set containing the which are deleted
   ToDelete = NULL
   scan the range in map_locks, 
   for each lock lk found {
      add lk to ToDelete
    
      case lk of
         UnlockedNew.  simply free up the Lock
         UnlockedBy.   makes a reference to Segment (via
                       map_segments) but just leave that.
                       Maybe we will later GC the segment graph.

         LockedBy.     Bad case.  Report error.
                       remove from from the currlocks set of the
                       owning thread
   }

   modify all shadow words, by removing ToDelete from the lockset
   of all ShM and ShR states.  

   Finally set the range to NoAccess.

   Optimisation 1: skip SecMaps which do not have .hasShared set

   Optimisation 2: for each SecMap, have a summary lock set which is
   the union of all locks mentioned in locksets on this page.
   Then skip the page if the summary lockset does not intersect with
   ToDelete.

   that's potentially cheap, since the usual lockset refinement
   only shrinks locksets; hence there is no point in updating the
   summary lockset for ShM/R -> ShM/R transitions

   Therefore only need to do this for Excl->ShM/R transitions
*/
static void shadow_mem_make_NoAccess ( Thread* thr, Addr a, SizeT len )
{
   Lock*     lk;
   Addr      gla, sma, firstSM, lastSM;
   WordSetID locksToDelete;

   a   = ROUNDDN(a, 4);
   len = ROUNDDN(len, 4);
   tl_assert(len >= 0);
   if (len == 0) return;

   if (0 && len > 500)
      VG_(printf)("make NoAccess ( %p, %d )\n", a,len );

   firstSM = shmem__round_to_SecMap_base(a);
   lastSM  = shmem__round_to_SecMap_base(a + len - 1);
   tl_assert(firstSM <= lastSM);
   for (sma = firstSM; sma <= lastSM; sma += N_SECMAP_ARANGE) {
      if (shmem__get_anyLocks(sma)) 
         goto slow_case;
   }
   goto fast_case;

   /* There's possibly a lock in the range, so we have to do the slow
      case. */
  slow_case:
   if (0) 
   VG_(printf)("shadow_mem_make_NoAccess(%p, %u, %p): maybe slow case\n",
               (void*)a, (UWord)len, (void*)(a+len-1));
   locksToDelete = TC_(emptyWS)( univ_lsets );
   
   // FIXME: don't iterate over the complete lock set
   TC_(initIterFM)( map_locks );
   while (TC_(nextIterFM)( map_locks, (Word*)&gla, (Word*)&lk )) {
      tl_assert(is_sane_LockN(lk));
      if (gla < a || gla >= a+len)
         continue;
      locksToDelete = TC_(addToWS)( univ_lsets, locksToDelete, (Word)lk );
      /* If the lock is held, we must remove it from the currlock sets
         of all threads that hold it.  Also take the opportunity to
         report an error.  To report an error we need to know at least
         one of the threads that holds it; really we should mention
         them all, but that's too much hassle.  So choose one
         arbitrarily. */
      if (lk->heldBy) {
         tl_assert(!TC_(isEmptyBag)(lk->heldBy));
         record_error_FreeMemLock( (Thread*)TC_(anyElementOfBag)(lk->heldBy),
                                   lk );
         /* remove lock from locksets of all owning threads */
         remove_Lock_from_locksets_of_all_owning_Threads( lk );
         /* Leave lk->heldBy in place; del_Lock below will free it up. */
      }
   }
   TC_(doneIterFM)( map_locks );
   // FIXME: optimisation: if locksToDelete is empty, there were no
   // locks in the range, in which case we can jump directly to fast_case.
   if (TC_(isEmptyWS)( univ_lsets, locksToDelete ))
      goto fast_case;

   if (0) 
   VG_(printf)("shadow_mem_make_NoAccess(%p, %u, %p): maybe slow case\n",
               (void*)a, (UWord)len, (void*)(a+len-1));

   /* Modify all shadow words, by removing locksToDelete from the lockset
      of all ShM and ShR states.
      Optimisation 1: skip SecMaps which do not have .hasShared set
   */
   { Int     i, stats_SMs = 0, stats_SMs_scanned = 0;
     Addr    ga;
     SecMap* sm;
     TC_(initIterFM)( map_shmem );
     while (TC_(nextIterFM)( map_shmem, (Word*)&ga, (Word*)&sm )) {
        tl_assert(sm);
        stats_SMs++;
        /* Skip this SecMap if the summary bit indicates it is safe to
           do so. */
        if (!sm->anyShared)
           continue;
        stats_SMs_scanned++;
        for (i = 0; i < N_SECMAP_W32S; i++) {
           Bool isM;
           UInt wold, wnew, lset_old, tset_old, lset_new;
           wold = sm->w32s[i];
           if (!is_SHMEM_Sh(wold))
              continue;
           isM      = is_SHMEM_ShM(wold);
           lset_old = un_SHMEM_Sh_lset(wold);
           tset_old = un_SHMEM_Sh_tset(wold);
           lset_new = TC_(minusWS)( univ_lsets, lset_old, locksToDelete );
           wnew     = isM ? mk_SHMEM_ShM(tset_old, lset_new)
                          : mk_SHMEM_ShR(tset_old, lset_new);
           if (wnew != wold)
              sm->w32s[i] = wnew;
        }
     }
     TC_(doneIterFM)( map_shmem );
     if (SHOW_EXPENSIVE_STUFF)
        VG_(printf)("shadow_mem_make_NoAccess: %d SMs, %d scanned\n", 
                    stats_SMs, stats_SMs_scanned);
   }

   /* Now we have to free up the Locks in locksToDelete and remove
      any mention of them from admin_locks and map_locks.  This is
      inefficient. */
   { Lock* lkprev = NULL;
     lk = admin_locks;
     while (True) {
        if (lk == NULL) break;
        if (lkprev) tl_assert(lkprev->admin == lk);

        if (!TC_(elemWS)(univ_lsets, locksToDelete, (Word)lk)) {
           lkprev = lk;
           lk = lk->admin;
           continue;
        }
        /* Need to delete 'lk' */
        if (lkprev == NULL) {
           admin_locks = lk->admin;
        } else {
           lkprev->admin = lk->admin;
        }
        /* and get it out of map_locks */
        map_locks_delete(lk->guestaddr);
        /* release storage (incl. associated .heldBy Bag) */
        { Lock* tmp = lk->admin;
          del_LockN(lk);
          lk = tmp;
        }
     }
   }

   /* Fall into the fast case handler */

  fast_case:
   // FIXME to be more efficient
   // clear the hint bits on any completely vacated SecMaps.  This
   // isn't necessary for correctness, but it is important to avoid
   // ending up with hint bits being permanently set, which would
   // render them pointless.  Although it would be better just to
   // free up the SecMap and point the relevant primary entry back
   // to the NoAccess DSM.

   do { } while (0);
   { UWord ll = len;
     Addr  aa = a;

     Addr prev = aa;
     while (ll >= 4) {
        // FIXME: shouldn't this go via the msm__ layer?
        shmem__write_32(aa, SHMEM_NoAccess);
        aa += 4;
        ll -= 4;
        if (shmem__is_SecMap_base(aa)) {
           // maybe have completed the page prev .. aa-1
           if (shmem__is_SecMap_base(prev)) {
              tl_assert(aa - prev == N_SECMAP_ARANGE);
              tl_assert(prev >= a && prev+N_SECMAP_ARANGE <= a+len);
              if (0) VG_(printf)("Completely clear secmap %p .. %p\n", 
                                 prev, aa-1);
              shmem__set_anyLocks( prev, False );
              shmem__set_anyShared( prev, False );
           }
           prev = aa;
        }
     }
   }

   if (0) all__sanity_check("Make NoAccess");
}

static void shadow_mem_make_New ( Thread* thr, Addr a, SizeT len )
{
   a   = ROUNDDN(a, 4);
   len = ROUNDDN(len, 4);
   while (len > 0) {
      // FIXME: what if memory is already in some addressible state?
      // FIXME: shouldn't this go via the msm__ layer?
      shmem__write_32(a, SHMEM_New);
      a += 4;
      len -= 4;
   }
}

static void shadow_mem_read_range ( Thread* thr, Addr a, SizeT len )
{
   Addr start = ROUNDDN(a, 4);
   Addr end   = ROUNDUP(a + len, 4);
   tl_assert(is_sane_Thread(thr));
   for (a = start; a < end; a += 4)
      msm__handle_read_aligned_32( thr, a );
}

static void shadow_mem_write_range ( Thread* thr, Addr a, SizeT len )
{
   Addr start = ROUNDDN(a, 4);
   Addr end   = ROUNDUP(a + len, 4);
   tl_assert(is_sane_Thread(thr));
   for (a = start; a < end; a += 4)
      msm__handle_write_aligned_32( thr, a );
}


/*----------------------------------------------------------------*/
/*--- Event handlers (evh__* functions)                        ---*/
/*--- plus helpers (evhH__* functions)                         ---*/
/*----------------------------------------------------------------*/

/*--------- Event handler helpers (evhH__* functions) ---------*/

/* Create a new segment for 'thr', making it depend (.prev) on its
   existing segment, bind together the SegmentID and Segment, and
   return both of them.  Also update 'thr' so it references the new
   Segment. */
static 
void evhH__start_new_segment_for_thread ( /*OUT*/SegmentID* new_segidP,
                                          /*OUT*/Segment** new_segP,
                                          Thread* thr )
{
   Segment* cur_seg;
   tl_assert(new_segP);
   tl_assert(new_segidP);
   tl_assert(is_sane_Thread(thr));
   cur_seg = map_segments_lookup( thr->csegid );
   tl_assert(cur_seg);
   tl_assert(cur_seg->thr == thr); /* all sane segs should point back
                                      at their owner thread. */
   *new_segP = mk_Segment( thr, cur_seg, NULL/*other*/ );
   *new_segidP = alloc_SegmentID();
   map_segments_add( *new_segidP, *new_segP );
   thr->csegid = *new_segidP;
}


/* The lock at 'lock_ga' has acquired a writer.  Make all necessary
   updates, and also do all possible error checks. */
static 
void evhH__post_thread_w_acquires_lock ( Thread* thr, 
                                         LockKind lkk, Addr lock_ga )
{
   Lock* lk; 

   /* Basically what we need to do is call lockN_acquire_writer.
      However, that will barf if any 'invalid' lock states would
      result.  Therefore check before calling.  Side effect is that
      'is_sane_LockN(lk)' is both a pre- and post-condition of this
      routine. 

      Because this routine is only called after successful lock
      acquisition, we should not be asked to move the lock into any
      invalid states.  Requests to do so are bugs in libpthread, since
      that should have rejected any such requests. */

   /* be paranoid w.r.t hint bits, even if lock_ga is complete
      nonsense */
   shmem__set_anyLocks( lock_ga, True );

   tl_assert(is_sane_Thread(thr));
   /* Try to find the lock.  If we can't, then create a new one with
      kind 'lkk'. */
   lk = map_locks_lookup_or_create( 
           lkk, lock_ga, map_threads_reverse_lookup_SLOW(thr) );
   tl_assert( is_sane_LockN(lk) );
   shmem__set_anyLocks( lock_ga, True );

   if (lk->heldBy == NULL) {
      /* the lock isn't held.  Simple. */
      tl_assert(!lk->heldW);
      lockN_acquire_writer( lk, thr );
      goto noerror;
   }

   /* So the lock is already held.  If held as a r-lock then
      libpthread must be buggy. */
   tl_assert(lk->heldBy);
   if (!lk->heldW) {
      record_error_Misc( thr, "Bug in libpthread: write lock "
                              "granted on rwlock which is currently rd-held");
      goto error;
   }

   /* So the lock is held in w-mode.  If it's held by some other
      thread, then libpthread must be buggy. */
   tl_assert(TC_(sizeUniqueBag)(lk->heldBy) == 1); /* from precondition */

   if (thr != (Thread*)TC_(anyElementOfBag)(lk->heldBy)) {
      record_error_Misc( thr, "Bug in libpthread: write lock "
                              "granted on mutex/rwlock which is currently "
                              "wr-held by a different thread");
      goto error;
   }

   /* So the lock is already held in w-mode by 'thr'.  That means this
      is an attempt to lock it recursively, which is only allowable
      for LK_mbRec kinded locks.  Since this routine is called only
      once the lock has been acquired, this must also be a libpthread
      bug. */
   if (lk->kind != LK_mbRec) {
      record_error_Misc( thr, "Bug in libpthread: recursive write lock "
                              "granted on mutex/wrlock which does not "
                              "support recursion");
      goto error;
   }

   /* So we are recursively re-locking a lock we already w-hold. */
   lockN_acquire_writer( lk, thr );
   goto noerror;

  noerror:
   /* update the thread's held-locks set */
   thr->locksetA = TC_(addToWS)( univ_lsets, thr->locksetA, (Word)lk );
   thr->locksetW = TC_(addToWS)( univ_lsets, thr->locksetW, (Word)lk );
   /* fall through */

  error:
   tl_assert(is_sane_LockN(lk));
}


/* The lock at 'lock_ga' has acquired a reader.  Make all necessary
   updates, and also do all possible error checks. */
static 
void evhH__post_thread_r_acquires_lock ( Thread* thr, 
                                         LockKind lkk, Addr lock_ga )
{
   Lock* lk; 

   /* Basically what we need to do is call lockN_acquire_reader.
      However, that will barf if any 'invalid' lock states would
      result.  Therefore check before calling.  Side effect is that
      'is_sane_LockN(lk)' is both a pre- and post-condition of this
      routine. 

      Because this routine is only called after successful lock
      acquisition, we should not be asked to move the lock into any
      invalid states.  Requests to do so are bugs in libpthread, since
      that should have rejected any such requests. */

   /* be paranoid w.r.t hint bits, even if lock_ga is complete
      nonsense */
   shmem__set_anyLocks( lock_ga, True );

   tl_assert(is_sane_Thread(thr));
   /* Try to find the lock.  If we can't, then create a new one with
      kind 'lkk'.  Only a reader-writer lock can be read-locked,
      hence the first assertion. */
   tl_assert(lkk == LK_rdwr);
   lk = map_locks_lookup_or_create( 
           lkk, lock_ga, map_threads_reverse_lookup_SLOW(thr) );
   tl_assert( is_sane_LockN(lk) );
   shmem__set_anyLocks( lock_ga, True );

   if (lk->heldBy == NULL) {
      /* the lock isn't held.  Simple. */
      tl_assert(!lk->heldW);
      lockN_acquire_reader( lk, thr );
      goto noerror;
   }

   /* So the lock is already held.  If held as a w-lock then
      libpthread must be buggy. */
   tl_assert(lk->heldBy);
   if (lk->heldW) {
      record_error_Misc( thr, "Bug in libpthread: read lock "
                              "granted on rwlock which is "
                              "currently wr-held");
      goto error;
   }

   /* Easy enough.  In short anybody can get a read-lock on a rwlock
      provided it is either unlocked or already in rd-held. */
   lockN_acquire_reader( lk, thr );
   goto noerror;

  noerror:
   /* update the thread's held-locks set */
   thr->locksetA = TC_(addToWS)( univ_lsets, thr->locksetA, (Word)lk );
   /* but don't update thr->locksetW, since lk is only rd-held */
   /* fall through */

  error:
   tl_assert(is_sane_LockN(lk));
}


/* The lock at 'lock_ga' is just about to be unlocked.  Make all
   necessary updates, and also do all possible error checks. */
static 
void evhH__pre_thread_releases_lock ( Thread* thr,
                                      Addr lock_ga, Bool isRDWR )
{
   Lock* lock;
   Word  n;

   /* This routine is called prior to a lock release, before
      libpthread has had a chance to validate the call.  Hence we need
      to detect and reject any attempts to move the lock into an
      invalid state.  Such attempts are bugs in the client.

      isRDWR is True if we know from the wrapper context that lock_ga
      should refer to a reader-writer lock, and is False if [ditto]
      lock_ga should refer to a standard mutex. */

   /* be paranoid w.r.t hint bits, even if lock_ga is complete
      nonsense */
   shmem__set_anyLocks( lock_ga, True );

   tl_assert(is_sane_Thread(thr));
   lock = map_locks_maybe_lookup( lock_ga );

   if (!lock) {
      /* We know nothing about a lock at 'lock_ga'.  Nevertheless
         the client is trying to unlock it.  So complain, then ignore
         the attempt. */
      record_error_UnlockBogus( thr, lock_ga );
      return;
   }

   tl_assert(lock->guestaddr == lock_ga);
   tl_assert(is_sane_LockN(lock));

   if (isRDWR && lock->kind != LK_rdwr) {
      record_error_Misc( thr, "pthread_rwlock_unlock with a "
                              "pthread_mutex_t* argument " );
   }
   if ((!isRDWR) && lock->kind == LK_rdwr) {
      record_error_Misc( thr, "pthread_mutex_unlock with a "
                              "pthread_rwlock_t* argument " );
   }

   if (!lock->heldBy) {
      /* The lock is not held.  This indicates a serious bug in the
         client. */
      tl_assert(!lock->heldW);
      record_error_UnlockUnlocked( thr, lock );
      tl_assert(!TC_(elemWS)( univ_lsets, thr->locksetA, (Word)lock ));
      tl_assert(!TC_(elemWS)( univ_lsets, thr->locksetW, (Word)lock ));
      goto error;
   }

   /* The lock is held.  Is this thread one of the holders?  If not,
      report a bug in the client. */
   n = TC_(elemBag)( lock->heldBy, (Word)thr );
   tl_assert(n >= 0);
   if (n == 0) {
      /* We are not a current holder of the lock.  This is a bug in
         the guest, and (per POSIX pthread rules) the unlock
         attempt will fail.  So just complain and do nothing
         else. */
      Thread* realOwner = (Thread*)TC_(anyElementOfBag)( lock->heldBy );
      tl_assert(is_sane_Thread(realOwner));
      tl_assert(realOwner != thr);
      tl_assert(!TC_(elemWS)( univ_lsets, thr->locksetA, (Word)lock ));
      tl_assert(!TC_(elemWS)( univ_lsets, thr->locksetW, (Word)lock ));
      record_error_UnlockForeign( thr, realOwner, lock );
      goto error;
   }

   /* Ok, we hold the lock 'n' times. */
   tl_assert(n >= 1);

   lockN_release( lock, thr );

   n--;
   tl_assert(n >= 0);

   if (n > 0) {
      tl_assert(lock->heldBy);
      tl_assert(n == TC_(elemBag)( lock->heldBy, (Word)thr )); 
      /* We still hold the lock.  So either it's a recursive lock 
         or a rwlock which is currently r-held. */
      tl_assert(lock->kind == LK_mbRec
                || (lock->kind == LK_rdwr && !lock->heldW));
      tl_assert(TC_(elemWS)( univ_lsets, thr->locksetA, (Word)lock ));
      if (lock->heldW)
         tl_assert(TC_(elemWS)( univ_lsets, thr->locksetW, (Word)lock ));
      else
         tl_assert(!TC_(elemWS)( univ_lsets, thr->locksetW, (Word)lock ));
   } else {
      /* We no longer hold the lock. */
      if (lock->heldBy) {
         tl_assert(0 == TC_(elemBag)( lock->heldBy, (Word)thr ));
      }
      /* update this thread's lockset accordingly. */
      thr->locksetA
         = TC_(delFromWS)( univ_lsets, thr->locksetA, (Word)lock );
      thr->locksetW
         = TC_(delFromWS)( univ_lsets, thr->locksetW, (Word)lock );
   }
   /* fall through */

  error:
   tl_assert(is_sane_LockN(lock));
}


/*--------- Event handlers proper (evh__* functions) ---------*/

/* FIXME: Horrible inefficient hack.  Get rid of it somehow. */
// FIXME: get rid of the "if .." hack.  It exists because evim__new_mem
// is called during initialisation (as notification of initial memory
// layout) and VG_(get_running_tid)() returns VG_INVALID_THREADID at
// that point.
static inline Thread* get_current_Thread ( void ) {
   ThreadId coretid;
   Thread*  thr;
   coretid = VG_(get_running_tid)();
   if (coretid == VG_INVALID_THREADID)
      coretid = 1; /* KLUDGE */
   thr = map_threads_lookup( coretid );
   return thr;
}

static
void evh__new_mem ( Addr a, SizeT len ) {
   if (SHOW_EVENTS >= 2)
      VG_(printf)("evh__new_mem(%p, %lu)\n", (void*)a, len );
   shadow_mem_make_New( get_current_Thread(), a, len );
   if (len >= SCE_BIGRANGE_T && (sanity_flags & SCE_BIGRANGE))
      all__sanity_check("evh__new_mem-post");
}

static
void evh__new_mem_w_perms ( Addr a, SizeT len, 
                            Bool rr, Bool ww, Bool xx ) {
   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__new_mem_w_perms(%p, %lu, %d,%d,%d)\n",
                  (void*)a, len, (Int)rr, (Int)ww, (Int)xx );
   if (rr || ww || xx)
      shadow_mem_make_New( get_current_Thread(), a, len );
   if (len >= SCE_BIGRANGE_T && (sanity_flags & SCE_BIGRANGE))
      all__sanity_check("evh__new_mem_w_perms-post");
}

static
void evh__set_perms ( Addr a, SizeT len,
                      Bool rr, Bool ww, Bool xx ) {
   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__set_perms(%p, %lu, %d,%d,%d)\n",
                  (void*)a, len, (Int)rr, (Int)ww, (Int)xx );
   /* Hmm.  What should we do here, that actually makes any sense?
      Let's say: if neither readable nor writable, then declare it
      NoAccess, else leave it alone. */
   if (!(rr || ww))
      shadow_mem_make_NoAccess( get_current_Thread(), a, len );
   if (len >= SCE_BIGRANGE_T && (sanity_flags & SCE_BIGRANGE))
      all__sanity_check("evh__set_perms-post");
}

static
void evh__die_mem ( Addr a, SizeT len ) {
   if (SHOW_EVENTS >= 2)
      VG_(printf)("evh__die_mem(%p, %lu)\n", (void*)a, len );
   shadow_mem_make_NoAccess( get_current_Thread(), a, len );
   if (len >= SCE_BIGRANGE_T && (sanity_flags & SCE_BIGRANGE))
      all__sanity_check("evh__die_mem-post");
}

static
void evh__pre_thread_ll_create ( ThreadId parent, ThreadId child )
{
   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__pre_thread_ll_create(p=%d, c=%d)\n",
                  (Int)parent, (Int)child );

   if (parent != VG_INVALID_THREADID) {
      Thread*   thr_p;
      Thread*   thr_c;
      SegmentID segid_c;
      Segment*  seg_c;

      tl_assert(is_sane_ThreadId(parent));
      tl_assert(is_sane_ThreadId(child));
      tl_assert(parent != child);

      thr_p = map_threads_maybe_lookup( parent );
      thr_c = map_threads_maybe_lookup( child );

      tl_assert(thr_p != NULL);
      tl_assert(thr_c == NULL);

      /* Create a new thread record for the child. */
      // FIXME: code duplication from init_data_structures
      segid_c = alloc_SegmentID();
      seg_c   = mk_Segment( NULL/*thr*/, NULL/*prev*/, NULL/*other*/ );
      map_segments_add( segid_c, seg_c );

      /* a Thread for the new thread ... */
      thr_c = mk_Thread( segid_c );
      seg_c->thr = thr_c;

      /* and bind it in the thread-map table */
      map_threads[child] = thr_c;

      /* Record where the parent is so we can later refer to this in
         error messages.

         On amd64-linux, this entails a nasty glibc-2.5 specific hack.
         The stack snapshot is taken immediately after the parent has
         returned from its sys_clone call.  Unfortunately there is no
         unwind info for the insn following "syscall" - reading the
         glibc sources confirms this.  So we ask for a snapshot to be
         taken as if RIP was 3 bytes earlier, in a place where there
         is unwind info.  Sigh.
      */
      { Word first_ip_delta = 0;
#       if defined(VGP_amd64_linux)
        first_ip_delta = -3;
#       endif
        thr_c->created_at = VG_(record_ExeContext)(parent, first_ip_delta);
      }

      /* Now, mess with segments. */ 
      if (clo_happens_before >= 1) {
         /* Make the child's new segment depend on the parent */
         seg_c->other = map_segments_lookup( thr_p->csegid );
         seg_c->other_hint = 'c';
         /* and start a new segment for the parent. */
         { SegmentID new_segid = 0; /* bogus */
           Segment*  new_seg   = NULL;
           evhH__start_new_segment_for_thread( &new_segid, &new_seg, 
                                               thr_p );
           tl_assert(is_sane_SegmentID(new_segid));
           tl_assert(is_sane_Segment(new_seg));
         }
      }
   }

   if (sanity_flags & SCE_THREADS)
      all__sanity_check("evh__pre_thread_create-post");
}

static
void evh__pre_thread_ll_exit ( ThreadId quit_tid )
{
   Thread* thr_q;
   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__pre_thread_ll_exit(thr=%d)\n",
                  (Int)quit_tid );

   /* quit_tid has disappeared without joining to any other thread.
      Therefore there is no synchronisation event associated with its
      exit and so we have to pretty much treat it as if it was still
      alive but mysteriously making no progress.  That is because, if
      we don't know when it really exited, then we can never say there
      is a point in time when we're sure the thread really has
      finished, and so we need to consider the possibility that it
      lingers indefinitely and continues to interact with other
      threads. */
   tl_assert(is_sane_ThreadId(quit_tid));
   thr_q = map_threads_maybe_lookup( quit_tid );
   tl_assert(thr_q != NULL);
   // FIXME: error-if: exiting thread holds any locks
   /* About the only thing we do need to do is clear the map_threads
      entry, in order that the Valgrind core can re-use it. */
   map_threads_delete( quit_tid );

   if (sanity_flags & SCE_THREADS)
      all__sanity_check("evh__pre_thread_ll_exit-post");
}

static
void evh__TC_PTHREAD_JOIN_POST ( ThreadId stay_tid, Thread* quit_thr )
{
   Int      i, stats_SMs, stats_SMs_scanned, stats_reExcls;
   Addr     ga;
   SecMap*  sm;
   Thread*  thr_s;
   Thread*  thr_q;

   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__post_thread_join(stayer=%d, quitter=%p)\n",
                  (Int)stay_tid, quit_thr );

   tl_assert(is_sane_ThreadId(stay_tid));

   thr_s = map_threads_maybe_lookup( stay_tid );
   thr_q = quit_thr;
   tl_assert(thr_s != NULL);
   tl_assert(thr_q != NULL);
   tl_assert(thr_s != thr_q);

   if (clo_happens_before >= 1) {
      /* Start a new segment for the stayer */
      SegmentID new_segid = 0; /* bogus */
      Segment*  new_seg   = NULL;
      evhH__start_new_segment_for_thread( &new_segid, &new_seg, thr_s );
      tl_assert(is_sane_SegmentID(new_segid));
      tl_assert(is_sane_Segment(new_seg));
      /* and make it depend on the quitter's last segment */
      tl_assert(new_seg->other == NULL);
      new_seg->other = map_segments_lookup( thr_q->csegid );
      new_seg->other_hint = 'j';
   }

   // FIXME: error-if: exiting thread holds any locks
   //        or shouw evh__pre_thread_ll_exit do that?

   /* Delete thread from ShM/ShR thread sets and restore Excl states
      where appropriate */

   /* When Thread(t) joins to Thread(u):

      scan all shadow memory.  For each ShM/ShR thread set, replace
      't' in each set with 'u'.  If this results in a singleton 'u',
      change the state to Excl(u->csegid).

      Optimisation: tag each SecMap with a superset of the union of
      the thread sets in the SecMap.  Then if the tag set does not
      include 't' then the SecMap can be skipped, because there is no
      't' to change to anything else.

      Problem is that the tag set needs to be updated often, after
      every ShR/ShM store.  (that increases the thread set of the
      shadow value.)

      --> Compromise.  Tag each SecMap with a .anyShared bit which
          must be set true if any ShR/ShM on the page.  Set this for
          any transitions into ShR/ShM on the page.  Then skip page if
          not set.
   */
   stats_SMs = stats_SMs_scanned = stats_reExcls = 0;
   TC_(initIterFM)( map_shmem );
   while (TC_(nextIterFM)( map_shmem, (Word*)&ga, (Word*)&sm )) {
      tl_assert(sm);
      stats_SMs++;
      /* Skip this SecMap if the summary bit indicates it is safe to
         do so. */
      if (!sm->anyShared)
         continue;
      stats_SMs_scanned++;
      for (i = 0; i < N_SECMAP_W32S; i++) {
         Bool isM;
         UInt wnew, wold, lset_old, tset_old, tset_new;
         wold = sm->w32s[i];
         if (!is_SHMEM_Sh(wold))
            continue;
         isM = is_SHMEM_ShM(wold);
         lset_old = un_SHMEM_Sh_lset(wold);
         tset_old = un_SHMEM_Sh_tset(wold);
         /* Subst thr_q -> thr_s in the thread set.  Longwindedly, if
            thr_q is in the set, delete it and add thr_s; else leave
            it alone.  FIXME: is inefficient - make a special
            substInWS method for this. */
         tset_new 
            = TC_(elemWS)( univ_tsets, tset_old, (Word)thr_q )
              ? TC_(addToWS)(
                   univ_tsets, 
                   TC_(delFromWS)( univ_tsets, tset_old, (Word)thr_q ),
                   (Word)thr_s 
                )
              : tset_old;

         tl_assert(TC_(cardinalityWS)(univ_tsets, tset_new) 
                   <= TC_(cardinalityWS)(univ_tsets, tset_old));

         if (0) {
            VG_(printf)("%p: old 0x%x new 0x%x   ",
                        (void*)(ga + 4*i), tset_old, tset_new);
            TC_(ppWS)( univ_tsets, tset_old );
            VG_(printf)("  -->  ");
            TC_(ppWS)( univ_tsets, tset_new );
            VG_(printf)("\n");
         }
         if (TC_(isSingletonWS)( univ_tsets, tset_new, (Word)thr_s )) {
            /* This word returns to Excl state */
            wnew = mk_SHMEM_Excl(thr_s->csegid);
            stats_reExcls++;
         } else {
            wnew = isM ? mk_SHMEM_ShM(tset_new, lset_old)
                       : mk_SHMEM_ShR(tset_new, lset_old);
         }
         sm->w32s[i] = wnew;
      }
   }
   TC_(doneIterFM)( map_shmem );

   if (SHOW_EXPENSIVE_STUFF)
      VG_(printf)("evh__post_thread_join: %d SMs, "
                  "%d scanned, %d re-Excls\n", 
                  stats_SMs, stats_SMs_scanned, stats_reExcls);

   /* This holds because, at least when using NPTL as the thread
      library, we should be notified the low level thread exit before
      we hear of any join event on it.  The low level exit
      notification feeds through into evh__pre_thread_ll_exit,
      which should clear the map_threads entry for it.  Hence we
      expect there to be no map_threads entry at this point. */
   tl_assert( map_threads_maybe_reverse_lookup_SLOW(thr_q)
              == VG_INVALID_THREADID);

   if (sanity_flags & SCE_THREADS)
      all__sanity_check("evh__post_thread_join-post");
}

static
void evh__pre_mem_read ( CorePart part, ThreadId tid, Char* s, 
                         Addr a, SizeT size) {
   if (SHOW_EVENTS >= 2
       || (SHOW_EVENTS >= 1 && size != 1))
      VG_(printf)("evh__pre_mem_read(ctid=%d, \"%s\", %p, %lu)\n", 
                  (Int)tid, s, (void*)a, size );
   shadow_mem_read_range( map_threads_lookup(tid), a, size);
   if (size >= SCE_BIGRANGE_T && (sanity_flags & SCE_BIGRANGE))
      all__sanity_check("evh__pre_mem_read-post");
}

static
void evh__pre_mem_read_asciiz ( CorePart part, ThreadId tid,
                                Char* s, Addr a ) {
   Int len;
   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__pre_mem_asciiz(ctid=%d, \"%s\", %p)\n", 
                  (Int)tid, s, (void*)a );
   // FIXME: think of a less ugly hack
   len = VG_(strlen)( (Char*) a );
   shadow_mem_read_range( map_threads_lookup(tid), a, len+1 );
   if (len >= SCE_BIGRANGE_T && (sanity_flags & SCE_BIGRANGE))
      all__sanity_check("evh__pre_mem_read_asciiz-post");
}

static
void evh__pre_mem_write ( CorePart part, ThreadId tid, Char* s,
                          Addr a, SizeT size ) {
   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__pre_mem_write(ctid=%d, \"%s\", %p, %lu)\n", 
                  (Int)tid, s, (void*)a, size );
   shadow_mem_write_range( map_threads_lookup(tid), a, size);
   if (size >= SCE_BIGRANGE_T && (sanity_flags & SCE_BIGRANGE))
      all__sanity_check("evh__pre_mem_write-post");
}

static
void evh__new_mem_heap ( Addr a, SizeT len, Bool is_inited ) {
   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__new_mem_heap(%p, %lu, inited=%d)\n", 
                  (void*)a, len, (Int)is_inited );
   // FIXME: this is kinda stupid
   if (is_inited) {
      shadow_mem_make_New(get_current_Thread(), a, len);
   } else {
      shadow_mem_make_New(get_current_Thread(), a, len);
   }
   if (len >= SCE_BIGRANGE_T && (sanity_flags & SCE_BIGRANGE))
      all__sanity_check("evh__pre_mem_read-post");
}

static
void evh__die_mem_heap ( Addr a, SizeT len ) {
   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__die_mem_heap(%p, %lu)\n", (void*)a, len );
   shadow_mem_make_NoAccess( get_current_Thread(), a, len );
   if (len >= SCE_BIGRANGE_T && (sanity_flags & SCE_BIGRANGE))
      all__sanity_check("evh__pre_mem_read-post");
}

// thread async exit?

static VG_REGPARM(1)
void evh__mem_help_read_1(Addr a) {
   msm__handle_read_aligned_32( get_current_Thread(), ROUNDDN(a,4) );
}
static VG_REGPARM(1)
void evh__mem_help_read_2(Addr a) {
   msm__handle_read_aligned_32( get_current_Thread(), ROUNDDN(a,4) );
}
static VG_REGPARM(1)
void evh__mem_help_read_4(Addr a) {
   msm__handle_read_aligned_32( get_current_Thread(), ROUNDDN(a,4) );
}
static VG_REGPARM(1)
void evh__mem_help_read_8(Addr a) {
   Thread* thr = get_current_Thread();
   msm__handle_read_aligned_32( thr, ROUNDDN(a+0,4) );
   msm__handle_read_aligned_32( thr, ROUNDDN(a+4,4) );
}
static VG_REGPARM(2)
void evh__mem_help_read_N(Addr a, SizeT size) {
   Thread* thr = get_current_Thread();
   a = ROUNDDN(a,4);
   size = ROUNDDN(size, 4);
   while (size >= 4) {
      msm__handle_read_aligned_32( thr, a );
      a += 4;
      size -= 4;
   }
}
static VG_REGPARM(1)
void evh__mem_help_write_1(Addr a) {
   msm__handle_write_aligned_32( get_current_Thread(), ROUNDDN(a,4) );
}
static VG_REGPARM(1)
void evh__mem_help_write_2(Addr a) {
   msm__handle_write_aligned_32( get_current_Thread(), ROUNDDN(a,4) );
}
static VG_REGPARM(1)
void evh__mem_help_write_4(Addr a) {
   msm__handle_write_aligned_32( get_current_Thread(), ROUNDDN(a,4) );
}
static VG_REGPARM(1)
void evh__mem_help_write_8(Addr a) {
   Thread* thr = get_current_Thread();
   msm__handle_write_aligned_32( thr, ROUNDDN(a+0,4) );
   msm__handle_write_aligned_32( thr, ROUNDDN(a+4,4) );
}
static VG_REGPARM(2)
void evh__mem_help_write_N(Addr a, SizeT size) {
   Thread* thr = get_current_Thread();
   a = ROUNDDN(a,4);
   size = ROUNDDN(size, 4);
   while (size >= 4) {
      msm__handle_write_aligned_32( thr, a );
      a += 4;
      size -= 4;
   }
}

static void evh__bus_lock(void) {
   Thread* thr;
   if (0) VG_(printf)("evh__bus_lock()\n");
   thr = map_threads_maybe_lookup( VG_(get_running_tid)() );
   tl_assert(thr); /* cannot fail - Thread* must already exist */
   evhH__post_thread_w_acquires_lock( thr, LK_nonRec, (Addr)&__bus_lock );
}
static void evh__bus_unlock(void) {
   Thread* thr;
   if (0) VG_(printf)("evh__bus_unlock()\n");
   thr = map_threads_maybe_lookup( VG_(get_running_tid)() );
   tl_assert(thr); /* cannot fail - Thread* must already exist */
   evhH__pre_thread_releases_lock( thr, (Addr)&__bus_lock, False/*!isRDWR*/ );
}


/* -------------- events to do with mutexes -------------- */

/* EXPOSITION only: by intercepting lock init events we can show the
   user where the lock was initialised, rather than only being able to
   show where it was first locked.  Intercepting lock initialisations
   is not necessary for the basic operation of the race checker. */
static
void evh__TC_PTHREAD_MUTEX_INIT_POST( ThreadId tid, 
                                      void* mutex, Word mbRec )
{
   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__tc_PTHREAD_MUTEX_INIT_POST(ctid=%d, mbRec=%ld, %p)\n", 
                  (Int)tid, mbRec, (void*)mutex );
   tl_assert(mbRec == 0 || mbRec == 1);
   map_locks_lookup_or_create( mbRec ? LK_mbRec : LK_nonRec,
                               (Addr)mutex, tid );
   if (sanity_flags & SCE_LOCKS)
      all__sanity_check("evh__tc_PTHREAD_MUTEX_INIT_POST");
}

static
void evh__TC_PTHREAD_MUTEX_DESTROY_PRE( ThreadId tid, void* mutex )
{
   Thread* thr;
   Lock*   lk;
   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__tc_PTHREAD_MUTEX_DESTROY_PRE(ctid=%d, %p)\n", 
                  (Int)tid, (void*)mutex );

   thr = map_threads_maybe_lookup( tid );
   /* cannot fail - Thread* must already exist */
   tl_assert( is_sane_Thread(thr) );

   lk = map_locks_maybe_lookup( (Addr)mutex );

   if (lk == NULL || (lk->kind != LK_nonRec && lk->kind != LK_mbRec)) {
      record_error_Misc( thr,
                         "pthread_mutex_destroy with invalid argument" );
   }

   if (lk) {
      tl_assert( is_sane_LockN(lk) );
      tl_assert( lk->guestaddr == (Addr)mutex );
      if (lk->heldBy) {
         /* Basically act like we unlocked the lock */
         record_error_DestroyLocked( thr, lk );
         /* remove lock from locksets of all owning threads */
         remove_Lock_from_locksets_of_all_owning_Threads( lk );
         TC_(deleteBag)( lk->heldBy );
         lk->heldBy = NULL;
         lk->heldW = False;
      }
      tl_assert( !lk->heldBy );
      tl_assert( is_sane_LockN(lk) );
   }

   if (sanity_flags & SCE_LOCKS)
      all__sanity_check("evh__tc_PTHREAD_MUTEX_DESTROY_PRE");
}

static void evh__TC_PTHREAD_MUTEX_LOCK_PRE ( ThreadId tid, void* mutex )
{
   /* Just check the mutex is sane; nothing else to do. */
   // 'mutex' may be invalid - not checked by wrapper
   Thread* thr;
   Lock*   lk;
   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__tc_PTHREAD_MUTEX_LOCK_PRE(ctid=%d, mutex=%p)\n", 
                  (Int)tid, (void*)mutex );

   thr = map_threads_maybe_lookup( tid );
   tl_assert(thr); /* cannot fail - Thread* must already exist */

   lk = map_locks_maybe_lookup( (Addr)mutex );

   if (lk && (lk->kind == LK_rdwr)) {
      record_error_Misc( thr, "pthread_mutex_lock with a "
                              "pthread_rwlock_t* argument " );
   }

   if ( lk 
        && (lk->kind == LK_nonRec || lk->kind == LK_rdwr)
        && lk->heldBy
        && lk->heldW
        && TC_(elemBag)( lk->heldBy, (Word)thr ) > 0 ) {
      /* uh, it's a non-recursive lock and we already w-hold it.  Duh.
         Deadlock coming up; but at least produce an error message. */
      record_error_Misc( thr, "Attempt to re-lock a "
                              "non-recursive lock I already hold" );
   }
}

static void evh__TC_PTHREAD_MUTEX_LOCK_POST ( ThreadId tid, void* mutex )
{
   // only called if the real library call succeeded - so mutex is sane
   Thread* thr;
   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__TC_PTHREAD_MUTEX_LOCK_POST(ctid=%d, mutex=%p)\n", 
                  (Int)tid, (void*)mutex );

   thr = map_threads_maybe_lookup( tid );
   tl_assert(thr); /* cannot fail - Thread* must already exist */

   evhH__post_thread_w_acquires_lock( 
      thr, 
      LK_mbRec, /* if not known, create new lock with this LockKind */
      (Addr)mutex
   );
}

static void evh__TC_PTHREAD_MUTEX_UNLOCK_PRE ( ThreadId tid, void* mutex )
{
   // 'mutex' may be invalid - not checked by wrapper
   Thread* thr;
   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__TC_PTHREAD_MUTEX_UNLOCK_PRE(ctid=%d, mutex=%p)\n", 
                  (Int)tid, (void*)mutex );

   thr = map_threads_maybe_lookup( tid );
   tl_assert(thr); /* cannot fail - Thread* must already exist */

   evhH__pre_thread_releases_lock( thr, (Addr)mutex, False/*!isRDWR*/ );
}

static void evh__TC_PTHREAD_MUTEX_UNLOCK_POST ( ThreadId tid, void* mutex )
{
   // only called if the real library call succeeded - so mutex is sane
   Thread* thr;
   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__tc_PTHREAD_MUTEX_UNLOCK_POST(ctid=%d, mutex=%p)\n", 
                  (Int)tid, (void*)mutex );
   thr = map_threads_maybe_lookup( tid );
   tl_assert(thr); /* cannot fail - Thread* must already exist */

   // anything we should do here?
}


/* --------------- events to do with CVs --------------- */

/* A mapping from CV to the thread segment which has most recently
   signalled/broadcasted on it.  This makes it possible to create
   thread segments to model happens-before events arising from CV
   signallings/broadcasts.
*/

/* pthread_mutex_cond* -> Segment* */
static WordFM* map_cond_to_Segment = NULL;

static void map_cond_to_Segment_INIT ( void ) {
   if (UNLIKELY(map_cond_to_Segment == NULL)) {
      map_cond_to_Segment = TC_(newFM)( tc_zalloc, tc_free, NULL );
      tl_assert(map_cond_to_Segment != NULL);
   }
}

static void evh__TC_PTHREAD_COND_SIGNAL_PRE ( ThreadId tid, void* cond )
{
   /* 'tid' has signalled on 'cond'.  Start a new segment for this
      thread, and make a binding from 'cond' to our old segment in the
      mapping.  This is later used by other thread(s) which
      successfully exit from a pthread_cond_wait on the same cv; then
      they know what the signalling segment was, so a dependency edge
      back to it can be constructed. */

   Thread*   thr;
   SegmentID new_segid;
   Segment*  new_seg;

   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__TC_PTHREAD_COND_SIGNAL_PRE(ctid=%d, cond=%p)\n", 
                  (Int)tid, (void*)cond );

   map_cond_to_Segment_INIT();
   thr = map_threads_maybe_lookup( tid );
   tl_assert(thr); /* cannot fail - Thread* must already exist */

   // error-if: mutex is bogus
   // error-if: mutex is not locked

   if (clo_happens_before >= 2) {
      /* create a new segment ... */
      new_segid = 0; /* bogus */
      new_seg   = NULL;
      evhH__start_new_segment_for_thread( &new_segid, &new_seg, thr );
      tl_assert( is_sane_SegmentID(new_segid) );
      tl_assert( is_sane_Segment(new_seg) );
      tl_assert( new_seg->thr == thr );
      tl_assert( is_sane_Segment(new_seg->prev) );

      /* ... and add the binding. */
      TC_(addToFM)( map_cond_to_Segment, (Word)cond,
                                         (Word)(new_seg->prev) );
   }
}

static void evh__TC_PTHREAD_COND_WAIT_PRE ( ThreadId tid,
                                            void* cond, void* mutex )
{
   Thread* thr;
   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__tc_PTHREAD_COND_WAIT_PRE"
                  "(ctid=%d, cond=%p, mutex=%p)\n", 
                  (Int)tid, (void*)cond, (void*)mutex );

   map_cond_to_Segment_INIT();
   thr = map_threads_maybe_lookup( tid );
   tl_assert(thr); /* cannot fail - Thread* must already exist */

   // error-if: cond is also associated with a different mutex
}

static void evh__TC_PTHREAD_COND_WAIT_POST ( ThreadId tid,
                                             void* cond, void* mutex )
{
   /* A pthread_cond_wait(cond, mutex) completed successfully.  Start
      a new segment for this thread.  Look up the signalling-segment
      for the 'cond' in the mapping, and add a dependency edge from
      the new segment back to it. */

   Thread*   thr;
   SegmentID new_segid;
   Segment*  new_seg;
   Segment*  signalling_seg;
   Bool      found;

   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__TC_PTHREAD_COND_WAIT_POST"
                  "(ctid=%d, cond=%p, mutex=%p)\n", 
                  (Int)tid, (void*)cond, (void*)mutex );

   map_cond_to_Segment_INIT();
   thr = map_threads_maybe_lookup( tid );
   tl_assert(thr); /* cannot fail - Thread* must already exist */

   // error-if: cond is also associated with a different mutex

   if (clo_happens_before >= 2) {
      /* create a new segment ... */
      new_segid = 0; /* bogus */
      new_seg   = NULL;
      evhH__start_new_segment_for_thread( &new_segid, &new_seg, thr );
      tl_assert( is_sane_SegmentID(new_segid) );
      tl_assert( is_sane_Segment(new_seg) );
      tl_assert( new_seg->thr == thr );
      tl_assert( is_sane_Segment(new_seg->prev) );
      tl_assert( new_seg->other == NULL);

      /* and find out which thread signalled us; then add a dependency
         edge back to it. */
      signalling_seg = NULL;
      found = TC_(lookupFM)( map_cond_to_Segment, 
                             NULL, (Word*)&signalling_seg, (Word)cond );
      if (found) {
         tl_assert(is_sane_Segment(signalling_seg));
         new_seg->other      = signalling_seg;
         new_seg->other_hint = 's';
      } else {
         /* Hmm.  How can a wait on 'cond' succeed if nobody signalled
            it?  If this happened it would surely be a bug in the
            threads library. */
         // FIXME
         tl_assert(0);
      }
   }
}


/* -------------- events to do with rwlocks -------------- */

/* EXPOSITION only */
static
void evh__TC_PTHREAD_RWLOCK_INIT_POST( ThreadId tid, void* rwl )
{
   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__tc_PTHREAD_RWLOCK_INIT_POST(ctid=%d, %p)\n", 
                  (Int)tid, (void*)rwl );
   map_locks_lookup_or_create( LK_rdwr, (Addr)rwl, tid );
   if (sanity_flags & SCE_LOCKS)
      all__sanity_check("evh__tc_PTHREAD_RWLOCK_INIT_POST");
}

static
void evh__TC_PTHREAD_RWLOCK_DESTROY_PRE( ThreadId tid, void* rwl )
{
   Thread* thr;
   Lock*   lk;
   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__tc_PTHREAD_RWLOCK_DESTROY_PRE(ctid=%d, %p)\n", 
                  (Int)tid, (void*)rwl );

   thr = map_threads_maybe_lookup( tid );
   /* cannot fail - Thread* must already exist */
   tl_assert( is_sane_Thread(thr) );

   lk = map_locks_maybe_lookup( (Addr)rwl );

   if (lk == NULL || lk->kind != LK_rdwr) {
      record_error_Misc( thr,
                         "pthread_rwlock_destroy with invalid argument" );
   }

   if (lk) {
      tl_assert( is_sane_LockN(lk) );
      tl_assert( lk->guestaddr == (Addr)rwl );
      if (lk->heldBy) {
         /* Basically act like we unlocked the lock */
         record_error_DestroyLocked( thr, lk );
         /* remove lock from locksets of all owning threads */
         remove_Lock_from_locksets_of_all_owning_Threads( lk );
         TC_(deleteBag)( lk->heldBy );
         lk->heldBy = NULL;
         lk->heldW = False;
      }
      tl_assert( !lk->heldBy );
      tl_assert( is_sane_LockN(lk) );
   }

   if (sanity_flags & SCE_LOCKS)
      all__sanity_check("evh__tc_PTHREAD_RWLOCK_DESTROY_PRE");
}

static 
void evh__TC_PTHREAD_RWLOCK_LOCK_PRE ( ThreadId tid, void* rwl, Word isW )
{
   /* Just check the rwl is sane; nothing else to do. */
   // 'rwl' may be invalid - not checked by wrapper
   Thread* thr;
   Lock*   lk;
   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__tc_PTHREAD_RWLOCK_LOCK_PRE(ctid=%d, isW=%d, %p)\n", 
                  (Int)tid, (Int)isW, (void*)rwl );

   tl_assert(isW == 0 || isW == 1); /* assured us by wrapper */
   thr = map_threads_maybe_lookup( tid );
   tl_assert(thr); /* cannot fail - Thread* must already exist */

   lk = map_locks_maybe_lookup( (Addr)rwl );
   if ( lk 
        && (lk->kind == LK_nonRec || lk->kind == LK_mbRec) ) {
      /* Wrong kind of lock.  Duh.  */
      record_error_Misc( thr, "pthread_rwlock_{rd,rw}lock with a "
                              "pthread_mutex_t* argument " );
   }
}

static 
void evh__TC_PTHREAD_RWLOCK_LOCK_POST ( ThreadId tid, void* rwl, Word isW )
{
   // only called if the real library call succeeded - so mutex is sane
   Thread* thr;
   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__tc_PTHREAD_RWLOCK_LOCK_POST(ctid=%d, isW=%d, %p)\n", 
                  (Int)tid, (Int)isW, (void*)rwl );

   tl_assert(isW == 0 || isW == 1); /* assured us by wrapper */
   thr = map_threads_maybe_lookup( tid );
   tl_assert(thr); /* cannot fail - Thread* must already exist */

   (isW ? evhH__post_thread_w_acquires_lock 
        : evhH__post_thread_r_acquires_lock)( 
      thr, 
      LK_rdwr, /* if not known, create new lock with this LockKind */
      (Addr)rwl
   );
}

static void evh__TC_PTHREAD_RWLOCK_UNLOCK_PRE ( ThreadId tid, void* rwl )
{
   // 'rwl' may be invalid - not checked by wrapper
   Thread* thr;
   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__TC_PTHREAD_RWLOCK_UNLOCK_PRE(ctid=%d, rwl=%p)\n", 
                  (Int)tid, (void*)rwl );

   thr = map_threads_maybe_lookup( tid );
   tl_assert(thr); /* cannot fail - Thread* must already exist */

   evhH__pre_thread_releases_lock( thr, (Addr)rwl, True/*isRDWR*/ );
}

static void evh__TC_PTHREAD_RWLOCK_UNLOCK_POST ( ThreadId tid, void* rwl )
{
   // only called if the real library call succeeded - so mutex is sane
   Thread* thr;
   if (SHOW_EVENTS >= 1)
      VG_(printf)("evh__tc_PTHREAD_RWLOCK_UNLOCK_POST(ctid=%d, rwl=%p)\n", 
                  (Int)tid, (void*)rwl );
   thr = map_threads_maybe_lookup( tid );
   tl_assert(thr); /* cannot fail - Thread* must already exist */

   // anything we should do here?
}


/*--------------------------------------------------------------*/
/*--- Malloc/free replacements                               ---*/
/*--------------------------------------------------------------*/

typedef
   struct {
      void*       next;    /* required by m_hashtable */
      Addr        payload; /* ptr to actual block    */
      SizeT       szB;     /* size requested         */
      ExeContext* where;   /* where it was allocated */
      Thread*     thr;     /* allocating thread      */
   }
   MallocMeta;

/* A hash table of MallocMetas, used to track malloc'd blocks
   (obviously). */
static VgHashTable tc_mallocmeta_table = NULL;


static MallocMeta* new_MallocMeta ( void ) {
   MallocMeta* md = tc_zalloc( sizeof(MallocMeta) );
   tl_assert(md);
   return md;
}
static void delete_MallocMeta ( MallocMeta* md ) {
   tc_free(md);
}


/* Allocate a client block and set up the metadata for it. */

static
void* handle_alloc ( ThreadId tid, 
                     SizeT szB, SizeT alignB, Bool is_zeroed )
{
   Addr        p;
   MallocMeta* md;

   p = (Addr)VG_(cli_malloc)(alignB, szB);
   if (!p) {
      return NULL;
   }
   if (is_zeroed)
      VG_(memset)((void*)p, 0, szB);

   /* Note that map_threads_lookup must succeed (cannot assert), since
      memory can only be allocated by currently alive threads, hence
      they must have an entry in map_threads. */
   md = new_MallocMeta();
   md->payload = p;
   md->szB     = szB;
   md->where   = VG_(record_ExeContext)( tid, 0 );
   md->thr     = map_threads_lookup( tid );

   VG_(HT_add_node)( tc_mallocmeta_table, (VgHashNode*)md );

   /* Tell the lower level memory wranglers. */
   evh__new_mem_heap( p, szB, is_zeroed );

   return (void*)p;
}

static void* tc_cli__malloc ( ThreadId tid, SizeT n ) {
   return handle_alloc ( tid, n, VG_(clo_alignment),
                         /*is_zeroed*/False );
}
static void* tc_cli____builtin_new ( ThreadId tid, SizeT n ) {
   return handle_alloc ( tid, n, VG_(clo_alignment),
                         /*is_zeroed*/False );
}
static void* tc_cli____builtin_vec_new ( ThreadId tid, SizeT n ) {
   return handle_alloc ( tid, n, VG_(clo_alignment), 
                         /*is_zeroed*/False );
}
static void* tc_cli__memalign ( ThreadId tid, SizeT align, SizeT n ) {
   return handle_alloc ( tid, n, align, 
                         /*is_zeroed*/False );
}
static void* tc_cli__calloc ( ThreadId tid, SizeT nmemb, SizeT size1 ) {
   return handle_alloc ( tid, nmemb*size1, VG_(clo_alignment),
                         /*is_zeroed*/True );
}


/* Free a client block, including getting rid of the relevant
   metadata. */

static void handle_free ( ThreadId tid, void* p )
{
   MallocMeta *md, *old_md;
   SizeT      szB;

   /* First see if we can find the metadata for 'p'. */
   md = (MallocMeta*) VG_(HT_lookup)( tc_mallocmeta_table, (UWord)p );
   if (!md)
      return; /* apparently freeing a bogus address.  Oh well. */

   tl_assert(md->payload == (Addr)p);
   szB = md->szB;

   /* Nuke the metadata block */
   old_md = (MallocMeta*)
            VG_(HT_remove)( tc_mallocmeta_table, (UWord)p );
   tl_assert(old_md); /* it must be present - we just found it */
   tl_assert(old_md == md);
   tl_assert(old_md->payload == (Addr)p);
   delete_MallocMeta(old_md);

   /* Tell the lower level memory wranglers. */
   evh__die_mem_heap( (Addr)p, szB );
}

static void tc_cli__free ( ThreadId tid, void* p ) {
   handle_free(tid, p);
}
static void tc_cli____builtin_delete ( ThreadId tid, void* p ) {
   handle_free(tid, p);
}
static void tc_cli____builtin_vec_delete ( ThreadId tid, void* p ) {
   handle_free(tid, p);
}


static void* tc_cli__realloc ( ThreadId tid, void* payloadV, SizeT new_size )
{
   MallocMeta *md, *md_new, *md_tmp;
   SizeT      i;

   Addr payload = (Addr)payloadV;

   md = (MallocMeta*) VG_(HT_lookup)( tc_mallocmeta_table, (UWord)payload );
   if (!md)
      return NULL; /* apparently realloc-ing a bogus address.  Oh well. */
  
   tl_assert(md->payload == payload);

   if (md->szB == new_size) {
      /* size unchanged */
     md->where = VG_(record_ExeContext)(tid, 0);
      return payloadV;
   }

   if (md->szB > new_size) {
      /* new size is smaller */
      md->szB   = new_size;
      md->where = VG_(record_ExeContext)(tid, 0);
      evh__die_mem_heap( md->payload + new_size, md->szB - new_size );
      return payloadV;
   }

   /* else */ {
      /* new size is bigger */
      Addr p_new = (Addr)VG_(cli_malloc)(VG_(clo_alignment), new_size);

      /* First half kept and copied, second half new */
      // FIXME: shouldn't we use a copier which implements the
      // memory state machine?
      shmem__copy_arange_state( payload, p_new, md->szB );
      evh__new_mem_heap ( p_new + md->szB, new_size - md->szB,
                           /*inited*/False );
      /* FIXME: can anything funny happen here?  specifically, if the
         old range contained a lock, then die_mem_heap will complain.
         Is that the correct behaviour?  Not sure. */
      evh__die_mem_heap( payload, md->szB );

      /* Copy from old to new */
      for (i = 0; i < md->szB; i++)
         ((UChar*)p_new)[i] = ((UChar*)payload)[i];

      /* Because the metadata hash table is index by payload address,
         we have to get rid of the old hash table entry and make a new
         one.  We can't just modify the existing metadata in place,
         because then it would (almost certainly) be in the wrong hash
         chain. */
      md_new = new_MallocMeta();
      *md_new = *md;

      md_tmp = VG_(HT_remove)( tc_mallocmeta_table, payload );
      tl_assert(md_tmp);
      tl_assert(md_tmp == md);
      delete_MallocMeta(md);

      /* Update fields */
      md_new->where   = VG_(record_ExeContext)( tid, 0 );
      md_new->szB     = new_size;
      md_new->payload = p_new;
      md_new->thr     = map_threads_lookup( tid );

      /* and add */
      VG_(HT_add_node)( tc_mallocmeta_table, (VgHashNode*)md_new );

      return (void*)p_new;
   }  
}


/*--------------------------------------------------------------*/
/*--- Instrumentation                                        ---*/
/*--------------------------------------------------------------*/

static void instrument_mem_access ( IRSB*   bbOut, 
                                    IRExpr* addr,
                                    Int     szB,
                                    Bool    isStore,
                                    Int     hWordTy_szB )
{
   IRType   tyAddr   = Ity_INVALID;
   HChar*   hName    = NULL;
   void*    hAddr    = NULL;
   Int      regparms = 0;
   IRExpr** argv     = NULL;
   IRDirty* di       = NULL;

   tl_assert(isIRAtom(addr));
   tl_assert(hWordTy_szB == 4 || hWordTy_szB == 8);

   tyAddr = typeOfIRExpr( bbOut->tyenv, addr );
   tl_assert(tyAddr == Ity_I32 || tyAddr == Ity_I64);

   /* So the effective address is in 'addr' now. */
   regparms = 1; // unless stated otherwise
   if (isStore) {
      switch (szB) {
         case 1:
            hName = "evh__mem_help_write_1";
            hAddr = &evh__mem_help_write_1;
            argv = mkIRExprVec_1( addr );
            break;
         case 2:
            hName = "evh__mem_help_write_2";
            hAddr = &evh__mem_help_write_2;
            argv = mkIRExprVec_1( addr );
            break;
         case 4:
            hName = "evh__mem_help_write_4";
            hAddr = &evh__mem_help_write_4;
            argv = mkIRExprVec_1( addr );
            break;
         case 8:
            hName = "evh__mem_help_write_8";
            hAddr = &evh__mem_help_write_8;
            argv = mkIRExprVec_1( addr );
            break;
         default:
            tl_assert(szB > 8 && szB <= 512); /* stay sane */
            regparms = 2;
            hName = "evh__mem_help_write_N";
            hAddr = &evh__mem_help_write_N;
            argv = mkIRExprVec_2( addr, mkIRExpr_HWord( szB ));
            break;
      }
   } else {
      switch (szB) {
         case 1:
            hName = "evh__mem_help_read_1";
            hAddr = &evh__mem_help_read_1;
            argv = mkIRExprVec_1( addr );
            break;
         case 2:
            hName = "evh__mem_help_read_2";
            hAddr = &evh__mem_help_read_2;
            argv = mkIRExprVec_1( addr );
            break;
         case 4:
            hName = "evh__mem_help_read_4";
            hAddr = &evh__mem_help_read_4;
            argv = mkIRExprVec_1( addr );
            break;
         case 8:
            hName = "evh__mem_help_read_8";
            hAddr = &evh__mem_help_read_8;
            argv = mkIRExprVec_1( addr );
            break;
         default: 
            tl_assert(szB > 8 && szB <= 512); /* stay sane */
            regparms = 2;
            hName = "evh__mem_help_read_N";
            hAddr = &evh__mem_help_read_N;
            argv = mkIRExprVec_2( addr, mkIRExpr_HWord( szB ));
            break;
      }
   }

   /* Add the helper. */
   tl_assert(hName);
   tl_assert(hAddr);
   tl_assert(argv);
   di = unsafeIRDirty_0_N( regparms,
                           hName, VG_(fnptr_to_fnentry)( hAddr ),
                           argv );
   addStmtToIRSB( bbOut, IRStmt_Dirty(di) );
}


static void instrument_memory_bus_event ( IRSB* bbOut, IRMBusEvent event )
{
   switch (event) {
      case Imbe_Fence:
         break; /* not interesting */
      case Imbe_BusLock:
      case Imbe_BusUnlock:
         addStmtToIRSB(
            bbOut,
            IRStmt_Dirty(
               unsafeIRDirty_0_N( 
                  0/*regparms*/, 
                  event == Imbe_BusLock ? "evh__bus_lock"
                                        : "evh__bus_unlock",
                  VG_(fnptr_to_fnentry)(
                     event == Imbe_BusLock ? &evh__bus_lock 
                                           : &evh__bus_unlock 
                  ),
                  mkIRExprVec_0() 
               )
            )
         );
         break;
      default:
         tl_assert(0);
    }
 }


static
IRSB* tc_instrument ( VgCallbackClosure* closure,
                      IRSB* bbIn,
                      VexGuestLayout* layout,
                      VexGuestExtents* vge,
                      IRType gWordTy, IRType hWordTy )
{
   Int   i;
   IRSB* bbOut;

   if (gWordTy != hWordTy) {
      /* We don't currently support this case. */
      VG_(tool_panic)("host/guest word size mismatch");
   }

   /* Set up BB */
   bbOut           = emptyIRSB();
   bbOut->tyenv    = deepCopyIRTypeEnv(bbIn->tyenv);
   bbOut->next     = deepCopyIRExpr(bbIn->next);
   bbOut->jumpkind = bbIn->jumpkind;

   // Copy verbatim any IR preamble preceding the first IMark
   i = 0;
   while (i < bbIn->stmts_used && bbIn->stmts[i]->tag != Ist_IMark) {
      addStmtToIRSB( bbOut, bbIn->stmts[i] );
      i++;
   }

   for (/*use current i*/; i < bbIn->stmts_used; i++) {
      IRStmt* st = bbIn->stmts[i];
      tl_assert(st);
      tl_assert(isFlatIRStmt(st));
      switch (st->tag) {
         case Ist_NoOp:
         case Ist_AbiHint:
         case Ist_Put:
         case Ist_PutI:
         case Ist_IMark:
         case Ist_Exit:
            /* None of these can contain any memory references. */
            break;

         case Ist_MBE:
            instrument_memory_bus_event( bbOut, st->Ist.MBE.event );
            break;

         case Ist_Store:
            instrument_mem_access( 
               bbOut, 
               st->Ist.Store.addr, 
               sizeofIRType(typeOfIRExpr(bbIn->tyenv, st->Ist.Store.data)),
               True/*isStore*/,
               sizeofIRType(hWordTy)
            );
            break;

         case Ist_WrTmp: {
            IRExpr* data = st->Ist.WrTmp.data;
            if (data->tag == Iex_Load) {
               instrument_mem_access(
                  bbOut,
                  data->Iex.Load.addr,
                  sizeofIRType(data->Iex.Load.ty),
                  False/*!isStore*/,
                  sizeofIRType(hWordTy)
               );
            }
            break;
         }

         case Ist_Dirty: {
            Int      dataSize;
            IRDirty* d = st->Ist.Dirty.details;
            if (d->mFx != Ifx_None) {
               /* This dirty helper accesses memory.  Collect the
                  details. */
               tl_assert(d->mAddr != NULL);
               tl_assert(d->mSize != 0);
               dataSize = d->mSize;
               if (d->mFx == Ifx_Read || d->mFx == Ifx_Modify) {
                  instrument_mem_access( 
                     bbOut, d->mAddr, dataSize, False/*!isStore*/,
                     sizeofIRType(hWordTy)
                  );
               }
               if (d->mFx == Ifx_Write || d->mFx == Ifx_Modify) {
                  instrument_mem_access( 
                     bbOut, d->mAddr, dataSize, True/*isStore*/,
                     sizeofIRType(hWordTy)
                  );
               }
            } else {
               tl_assert(d->mAddr == NULL);
               tl_assert(d->mSize == 0);
            }
            break;
         }

         default:
            tl_assert(0);

      } /* switch (st->tag) */

      addStmtToIRSB( bbOut, st );
   } /* iterate over bbIn->stmts */

   return bbOut;
}


/*----------------------------------------------------------------*/
/*--- Client requests                                          ---*/
/*----------------------------------------------------------------*/

/* Sheesh.  Yet another goddam finite map. */
static WordFM* map_pthread_t_to_Thread = NULL; /* pthread_t -> Thread* */

static void map_pthread_t_to_Thread_INIT ( void ) {
   if (UNLIKELY(map_pthread_t_to_Thread == NULL)) {
      map_pthread_t_to_Thread = TC_(newFM)( tc_zalloc, tc_free, NULL );
      tl_assert(map_pthread_t_to_Thread != NULL);
   }
}


static 
Bool tc_handle_client_request ( ThreadId tid, UWord* args, UWord* ret)
{
   if (!VG_IS_TOOL_USERREQ('T','C',args[0]))
      return False;

   /* Anything that gets past the above check is one of ours, so we
      should be able to handle it. */

   /* default, meaningless return value, unless otherwise set */
   *ret = 0;

   switch (args[0]) {

      /* --- --- User-visible client requests --- --- */

      case VG_USERREQ__TC_CLEAN_MEMORY:
         if (1) VG_(printf)("VG_USERREQ__TC_CLEAN_MEMORY(%p,%d)\n",
                            args[1], args[2]);
         /* Call die_mem to (expensively) tidy up properly, if there
            are any held locks etc in the area */
         // FIXME: next line causes firefox to stall - no idea why
         //         evh__die_mem(args[1], args[2]);
         /* and then set it to New */
         evh__new_mem(args[1], args[2]);
         break;

      /* --- --- Client requests for Thrcheck's use only --- --- */

      /* Some thread is telling us its pthread_t value.  Record the
         binding between that and the associated Thread*, so we can
         later find the Thread* again when notified of a join by the
         thread. */
      case _VG_USERREQ__TC_SET_MY_PTHREAD_T: {
         Thread* my_thr = NULL;
         if (0)
         VG_(printf)("SET_MY_PTHREAD_T (tid %d): pthread_t = %p\n", (Int)tid,
                     (void*)args[1]);
         map_pthread_t_to_Thread_INIT();
         my_thr = map_threads_maybe_lookup( tid );
         /* This assertion should hold because the map_threads (tid to
            Thread*) binding should have been made at the point of
            low-level creation of this thread, which should have
            happened prior to us getting this client request for it.
            That's because this client request is sent from
            client-world from the 'thread_wrapper' function, which
            only runs once the thread has been low-level created. */
         tl_assert(my_thr != NULL);
         /* So now we know that (pthread_t)args[1] is associated with
            (Thread*)my_thr.  Note that down. */
         if (0)
         VG_(printf)("XXXX: bind pthread_t %p to Thread* %p\n",
                     (void*)args[1], (void*)my_thr );
         TC_(addToFM)( map_pthread_t_to_Thread, (Word)args[1], (Word)my_thr );
         break;
      }

      case _VG_USERREQ__TC_PTH_API_ERROR: {
         Thread* my_thr = NULL;
         map_pthread_t_to_Thread_INIT();
         my_thr = map_threads_maybe_lookup( tid );
         tl_assert(my_thr); /* See justification above in SET_MY_PTHREAD_T */
         record_error_PthAPIerror( my_thr, (HChar*)args[1], 
                                           (Word)args[2], (HChar*)args[3] );
         break;
      }

      /* This thread (tid) has completed a join with the quitting
         thread whose pthread_t is in args[1]. */
      case _VG_USERREQ__TC_PTHREAD_JOIN_POST: {
         Thread* thr_q = NULL; /* quitter Thread* */
         Bool    found = False;
         if (0)
         VG_(printf)("NOTIFY_JOIN_COMPLETE (tid %d): quitter = %p\n", (Int)tid,
                     (void*)args[1]);
         map_pthread_t_to_Thread_INIT();
         found = TC_(lookupFM)( map_pthread_t_to_Thread, 
                                NULL, (Word*)&thr_q, (Word)args[1] );
          /* Can this fail?  It would mean that our pthread_join
             wrapper observed a successful join on args[1] yet that
             thread never existed (or at least, it never lodged an
             entry in the mapping (via SET_MY_PTHREAD_T)).  Which
             sounds like a bug in the threads library. */
         // FIXME: get rid of this assertion; handle properly
         tl_assert(found);
         if (found) {
            if (0)
            VG_(printf)(".................... quitter Thread* = %p\n", 
                        thr_q);
            evh__TC_PTHREAD_JOIN_POST( tid, thr_q );
         }
         break;
      }

      /* EXPOSITION only: by intercepting lock init events we can show
         the user where the lock was initialised, rather than only
         being able to show where it was first locked.  Intercepting
         lock initialisations is not necessary for the basic operation
         of the race checker. */
      case _VG_USERREQ__TC_PTHREAD_MUTEX_INIT_POST:
         evh__TC_PTHREAD_MUTEX_INIT_POST( tid, (void*)args[1], args[2] );
         break;

      case _VG_USERREQ__TC_PTHREAD_MUTEX_DESTROY_PRE:
         evh__TC_PTHREAD_MUTEX_DESTROY_PRE( tid, (void*)args[1] );
         break;

      case _VG_USERREQ__TC_PTHREAD_MUTEX_UNLOCK_PRE:   // pth_mx_t*
         evh__TC_PTHREAD_MUTEX_UNLOCK_PRE( tid, (void*)args[1] );
         break;

      case _VG_USERREQ__TC_PTHREAD_MUTEX_UNLOCK_POST:  // pth_mx_t*
         evh__TC_PTHREAD_MUTEX_UNLOCK_POST( tid, (void*)args[1] );
         break;

      case _VG_USERREQ__TC_PTHREAD_MUTEX_LOCK_PRE:     // pth_mx_t*
         evh__TC_PTHREAD_MUTEX_LOCK_PRE( tid, (void*)args[1] );
         break;

      case _VG_USERREQ__TC_PTHREAD_MUTEX_LOCK_POST:    // pth_mx_t*
         evh__TC_PTHREAD_MUTEX_LOCK_POST( tid, (void*)args[1] );
         break;

      /* This thread is about to do pthread_cond_signal on the
         pthread_cond_t* in arg[1].  Ditto pthread_cond_broadcast. */
      case _VG_USERREQ__TC_PTHREAD_COND_SIGNAL_PRE:
      case _VG_USERREQ__TC_PTHREAD_COND_BROADCAST_PRE:
         evh__TC_PTHREAD_COND_SIGNAL_PRE( tid, (void*)args[1] );
         break;

      /* Entry into pthread_cond_wait, cond=arg[1], mutex=arg[2] */
      case _VG_USERREQ__TC_PTHREAD_COND_WAIT_PRE:
         evh__TC_PTHREAD_COND_WAIT_PRE( tid,
                                         (void*)args[1], (void*)args[2] );
         break;

      /* Thread successfully completed pthread_cond_wait, cond=arg[1],
         mutex=arg[2] */
      case _VG_USERREQ__TC_PTHREAD_COND_WAIT_POST:
         evh__TC_PTHREAD_COND_WAIT_POST( tid,
                                          (void*)args[1], (void*)args[2] );
         break;

      case _VG_USERREQ__TC_PTHREAD_RWLOCK_INIT_POST:
         evh__TC_PTHREAD_RWLOCK_INIT_POST( tid, (void*)args[1] );
         break;

      case _VG_USERREQ__TC_PTHREAD_RWLOCK_DESTROY_PRE:
         evh__TC_PTHREAD_RWLOCK_DESTROY_PRE( tid, (void*)args[1] );
         break;

      /* rwlock=arg[1], isW=arg[2] */
      case _VG_USERREQ__TC_PTHREAD_RWLOCK_LOCK_PRE:
         evh__TC_PTHREAD_RWLOCK_LOCK_PRE( tid, (void*)args[1], args[2] );
         break;

      /* rwlock=arg[1], isW=arg[2] */
      case _VG_USERREQ__TC_PTHREAD_RWLOCK_LOCK_POST:
         evh__TC_PTHREAD_RWLOCK_LOCK_POST( tid, (void*)args[1], args[2] );
         break;

      case _VG_USERREQ__TC_PTHREAD_RWLOCK_UNLOCK_PRE:
         evh__TC_PTHREAD_RWLOCK_UNLOCK_PRE( tid, (void*)args[1] );
         break;

      case _VG_USERREQ__TC_PTHREAD_RWLOCK_UNLOCK_POST:
         evh__TC_PTHREAD_RWLOCK_UNLOCK_POST( tid, (void*)args[1] );
         break;

      default:
         /* Unhandled Thrcheck client request! */
        tl_assert2(0, "unhandled Thrcheck client request!");
   }

   return True;
}


/*----------------------------------------------------------------*/
/*--- Error management                                         ---*/
/*----------------------------------------------------------------*/

/* maps (by value) strings to a copy of them in ARENA_TOOL */
static UWord stats__string_table_queries = 0;
static WordFM* string_table = NULL;
static Word string_table_cmp ( Word s1, Word s2 ) {
   return (Word)VG_(strcmp)( (HChar*)s1, (HChar*)s2 );
}
static HChar* string_table_strdup ( HChar* str ) {
   HChar* copy = NULL;
   stats__string_table_queries++;
   if (!str)
      str = "(null)";
   if (!string_table) {
      string_table = TC_(newFM)( tc_zalloc, tc_free, string_table_cmp );
      tl_assert(string_table);
   }
   if (TC_(lookupFM)( string_table, NULL, (Word*)&copy, (Word)str )) {
      tl_assert(copy);
      if (0) VG_(printf)("string_table_strdup: %p -> %p\n", str, copy );
      return copy;
   } else {
      copy = VG_(strdup)(str);
      tl_assert(copy);
      TC_(addToFM)( string_table, (Word)copy, (Word)copy );
      return copy;
   }
}

/* maps from Lock .unique fields to LockP*s */
static UWord stats__ga_LockN_to_P_queries = 0;
static WordFM* yaWFM = NULL;
static Word lock_unique_cmp ( Word lk1W, Word lk2W )
{
   Lock* lk1 = (Lock*)lk1W;
   Lock* lk2 = (Lock*)lk2W;
   tl_assert( is_sane_LockNorP(lk1) );
   tl_assert( is_sane_LockNorP(lk2) );
   if (lk1->unique < lk2->unique) return -1;
   if (lk1->unique > lk2->unique) return 1;
   return 0;
}
static Lock* mk_LockP_from_LockN ( Lock* lkn )
{
   Lock* lkp = NULL;
   stats__ga_LockN_to_P_queries++;
   tl_assert( is_sane_LockN(lkn) );
   if (!yaWFM) {
      yaWFM = TC_(newFM)( tc_zalloc, tc_free, lock_unique_cmp );
      tl_assert(yaWFM);
   }
   if (!TC_(lookupFM)( yaWFM, NULL, (Word*)&lkp, (Word)lkn)) {
      lkp = tc_zalloc( sizeof(Lock) );
      *lkp = *lkn;
      lkp->admin = NULL;
      lkp->magic = LockP_MAGIC;
      /* Forget about the bag of lock holders - don't copy that. */
      lkp->heldW  = False;
      lkp->heldBy = NULL;
      TC_(addToFM)( yaWFM, (Word)lkp, (Word)lkp );
   }
   tl_assert( is_sane_LockP(lkp) );
   return lkp;
}

/* Errors:

      race: program counter
            read or write
            data size
            previous state
            current state

      FIXME: how does state printing interact with lockset gc?
      Are the locksets in prev/curr state always valid?
      Ditto question for the threadsets
          ThreadSets - probably are always valid if Threads
          are never thrown away.
          LockSets - could at least print the lockset elements that
          correspond to actual locks at the time of printing.  Hmm.
*/

/* Error kinds */
typedef
   enum {
      XE_Race=1101,      // race
      XE_FreeMemLock,    // freeing memory containing a locked lock
      XE_UnlockUnlocked, // unlocking a not-locked lock
      XE_UnlockForeign,  // unlocking a lock held by some other thread
      XE_UnlockBogus,    // unlocking an address not known to be a lock
      XE_DestroyLocked,  // pth_mx_destroy on locked lock
      XE_PthAPIerror,    // error from the POSIX pthreads API
      XE_Misc            // misc other error (w/ string to describe it)
   }
   XErrorTag;

/* Extra contexts for kinds */
typedef
   struct  {
      XErrorTag tag;
      union {
         struct {
            Addr  data_addr;
            Int   szB;
            Bool  isWrite;
            UInt  new_state;
            UInt  old_state;
            ExeContext* mb_lastlock;
            Thread* thr;
         } Race;
         struct {
            Thread* thr;  /* doing the freeing */
            Lock*   lock; /* lock which is locked */
         } FreeMemLock;
         struct {
            Thread* thr;  /* doing the unlocking */
            Lock*   lock; /* lock (that is already unlocked) */
         } UnlockUnlocked;
         struct {
            Thread* thr;    /* doing the unlocking */
            Thread* owner;  /* thread that actually holds the lock */
            Lock*   lock;   /* lock (that is held by 'owner') */
         } UnlockForeign;
         struct {
            Thread* thr;     /* doing the unlocking */
            Addr    lock_ga; /* purported address of the lock */
         } UnlockBogus;
         struct {
            Thread* thr;  /* doing the unlocking */
            Lock*   lock; /* lock (that is locked and now destroyed) */
         } DestroyLocked;
         struct {
            Thread* thr; 
            HChar*  fnname; /* persistent, in tool-arena */
            Word    err;    /* pth error code */
            HChar*  errstr; /* persistent, in tool-arena */
         } PthAPIerror;
         struct {
            Thread* thr;
            HChar*  errstr; /* persistent, in tool-arena */
         } Misc;
      } XE;
   }
   XError;

static void init_XError ( XError* xe ) {
   VG_(memset)(xe, 0, sizeof(*xe) );
   xe->tag = XE_Race-1; /* bogus */
}


/* Extensions of suppressions */
typedef
   enum {
      XS_Race=1201, /* race */
      XS_FreeMemLock,
      XS_UnlockUnlocked,
      XS_UnlockForeign,
      XS_UnlockBogus,
      XS_DestroyLocked,
      XS_PthAPIerror,
      XS_Misc
   }
   XSuppTag;


/* Updates the copy with address info if necessary. */
static UInt tc_update_extra ( Error* err )
{
   XError* extra = (XError*)VG_(get_error_extra)(err);
   tl_assert(extra);
   //if (extra != NULL && Undescribed == extra->addrinfo.akind) {
   //   describe_addr ( VG_(get_error_address)(err), &(extra->addrinfo) );
   //}
   return sizeof(XError);
}

static void record_error_Race ( Thread* thr, 
                                Addr data_addr, Bool isWrite, Int szB,
                                UInt old_w32, UInt new_w32,
                                ExeContext* mb_lastlock ) {
   XError xe;
   tl_assert( is_sane_Thread(thr) );
   init_XError(&xe);
   xe.tag = XE_Race;
   xe.XE.Race.data_addr   = data_addr;
   xe.XE.Race.szB         = szB;
   xe.XE.Race.isWrite     = isWrite;
   xe.XE.Race.new_state   = new_w32;
   xe.XE.Race.old_state   = old_w32;
   xe.XE.Race.mb_lastlock = mb_lastlock;
   xe.XE.Race.thr         = thr;
   // FIXME: tid vs thr
   VG_(maybe_record_error)( map_threads_reverse_lookup_SLOW(thr),
                            XE_Race, data_addr, 
                            (isWrite ? "write to" : "read from"),
                            &xe);
}

static void record_error_FreeMemLock ( Thread* thr, Lock* lk ) {
   XError xe;
   tl_assert( is_sane_Thread(thr) );
   tl_assert( is_sane_LockN(lk) );
   init_XError(&xe);
   xe.tag = XE_FreeMemLock;
   xe.XE.FreeMemLock.thr  = thr;
   xe.XE.FreeMemLock.lock = mk_LockP_from_LockN(lk);
   // FIXME: tid vs thr
   VG_(maybe_record_error)( map_threads_reverse_lookup_SLOW(thr),
                            XE_FreeMemLock, 0, NULL, &xe );
}

static void record_error_UnlockUnlocked ( Thread* thr, Lock* lk ) {
   XError xe;
   tl_assert( is_sane_Thread(thr) );
   tl_assert( is_sane_LockN(lk) );
   init_XError(&xe);
   xe.tag = XE_UnlockUnlocked;
   xe.XE.UnlockUnlocked.thr  = thr;
   xe.XE.UnlockUnlocked.lock = mk_LockP_from_LockN(lk);
   // FIXME: tid vs thr
   VG_(maybe_record_error)( map_threads_reverse_lookup_SLOW(thr),
                            XE_UnlockUnlocked, 0, NULL, &xe );
}

static void record_error_UnlockForeign ( Thread* thr,
                                         Thread* owner, Lock* lk ) {
   XError xe;
   tl_assert( is_sane_Thread(thr) );
   tl_assert( is_sane_Thread(owner) );
   tl_assert( is_sane_LockN(lk) );
   init_XError(&xe);
   xe.tag = XE_UnlockForeign;
   xe.XE.UnlockForeign.thr   = thr;
   xe.XE.UnlockForeign.owner = owner;
   xe.XE.UnlockForeign.lock  = mk_LockP_from_LockN(lk);
   // FIXME: tid vs thr
   VG_(maybe_record_error)( map_threads_reverse_lookup_SLOW(thr),
                            XE_UnlockForeign, 0, NULL, &xe );
}

static void record_error_UnlockBogus ( Thread* thr, Addr lock_ga ) {
   XError xe;
   tl_assert( is_sane_Thread(thr) );
   init_XError(&xe);
   xe.tag = XE_UnlockBogus;
   xe.XE.UnlockBogus.thr     = thr;
   xe.XE.UnlockBogus.lock_ga = lock_ga;
   // FIXME: tid vs thr
   VG_(maybe_record_error)( map_threads_reverse_lookup_SLOW(thr),
                            XE_UnlockBogus, 0, NULL, &xe );
}

static void record_error_DestroyLocked ( Thread* thr, Lock* lk ) {
   XError xe;
   tl_assert( is_sane_Thread(thr) );
   tl_assert( is_sane_LockN(lk) );
   init_XError(&xe);
   xe.tag = XE_DestroyLocked;
   xe.XE.DestroyLocked.thr  = thr;
   xe.XE.DestroyLocked.lock = mk_LockP_from_LockN(lk);
   // FIXME: tid vs thr
   VG_(maybe_record_error)( map_threads_reverse_lookup_SLOW(thr),
                            XE_DestroyLocked, 0, NULL, &xe );
}

static 
void record_error_PthAPIerror ( Thread* thr, HChar* fnname, 
                                Word err, HChar* errstr ) {
   XError xe;
   tl_assert( is_sane_Thread(thr) );
   tl_assert(fnname);
   tl_assert(errstr);
   init_XError(&xe);
   xe.tag = XE_PthAPIerror;
   xe.XE.PthAPIerror.thr    = thr;
   xe.XE.PthAPIerror.fnname = string_table_strdup(fnname);
   xe.XE.PthAPIerror.err    = err;
   xe.XE.PthAPIerror.errstr = string_table_strdup(errstr);
   // FIXME: tid vs thr
   VG_(maybe_record_error)( map_threads_reverse_lookup_SLOW(thr),
                            XE_PthAPIerror, 0, NULL, &xe );
}

static void record_error_Misc ( Thread* thr, HChar* errstr ) {
   XError xe;
   tl_assert( is_sane_Thread(thr) );
   tl_assert(errstr);
   init_XError(&xe);
   xe.tag = XE_Misc;
   xe.XE.Misc.thr    = thr;
   xe.XE.Misc.errstr = string_table_strdup(errstr);
   // FIXME: tid vs thr
   VG_(maybe_record_error)( map_threads_reverse_lookup_SLOW(thr),
                            XE_Misc, 0, NULL, &xe );
}

static Bool tc_eq_Error ( VgRes not_used, Error* e1, Error* e2 )
{
   Char   *e1s, *e2s;
   XError *xe1, *xe2;

   tl_assert(VG_(get_error_kind)(e1) == VG_(get_error_kind)(e2));

   xe1 = (XError*)VG_(get_error_extra)(e1);
   xe2 = (XError*)VG_(get_error_extra)(e2);
   tl_assert(xe1);
   tl_assert(xe2);

   switch (VG_(get_error_kind)(e1)) {
      case XE_Race:
         //return VG_(get_error_tid)(e1) == VG_(get_error_tid)(e2);
         break;
         //return VG_(get_error_address)(e1) == VG_(get_error_address)(e2);
      case XE_FreeMemLock:
         return xe1->XE.FreeMemLock.thr == xe2->XE.FreeMemLock.thr
                && xe1->XE.FreeMemLock.lock == xe2->XE.FreeMemLock.lock;
      case XE_UnlockUnlocked:
         return xe1->XE.UnlockUnlocked.thr == xe2->XE.UnlockUnlocked.thr
                && xe1->XE.UnlockUnlocked.lock == xe2->XE.UnlockUnlocked.lock;
      case XE_UnlockForeign:
         return xe1->XE.UnlockForeign.thr == xe2->XE.UnlockForeign.thr
                && xe1->XE.UnlockForeign.owner == xe2->XE.UnlockForeign.owner
                && xe1->XE.UnlockForeign.lock == xe2->XE.UnlockForeign.lock;
      case XE_UnlockBogus:
         return xe1->XE.UnlockBogus.thr == xe2->XE.UnlockBogus.thr
                && xe1->XE.UnlockBogus.lock_ga == xe2->XE.UnlockBogus.lock_ga;
      case XE_DestroyLocked:
         return xe1->XE.DestroyLocked.thr == xe2->XE.DestroyLocked.thr
                && xe1->XE.DestroyLocked.lock == xe2->XE.DestroyLocked.lock;
      case XE_PthAPIerror:
         return xe1->XE.PthAPIerror.thr == xe2->XE.PthAPIerror.thr
                && 0==VG_(strcmp)(xe1->XE.PthAPIerror.fnname,
                                  xe2->XE.PthAPIerror.fnname)
                && xe1->XE.PthAPIerror.err == xe2->XE.PthAPIerror.err;
      case XE_Misc:
         return xe1->XE.Misc.thr == xe2->XE.Misc.thr
                && 0==VG_(strcmp)(xe1->XE.Misc.errstr, xe2->XE.Misc.errstr);
      default:
         tl_assert(0);
   }

   e1s = VG_(get_error_string)(e1);
   e2s = VG_(get_error_string)(e2);
   if (e1s != e2s) return False;
   if (0 != VG_(strcmp)(e1s, e2s)) return False;
   return True;
}

/* Announce (that is, print the point-of-creation) of the threads in
   'tset'.  Only do this once, as we only want to see these
   announcements once each. */

static void announce_threadset ( WordSetID tset )
{
   Thread* thr;
   Word*   ts_words;
   Word    ts_size, i;
   TC_(getPayloadWS)( &ts_words, &ts_size, univ_tsets, tset );
   tl_assert(ts_words);
   tl_assert(ts_size >= 0);
   // FIXME: announce the threads in order of their errmsg_index
   // fields
   for (i = 0; i < ts_size; i++) {
      thr = (Thread*)ts_words[i];
      tl_assert(is_sane_Thread(thr));
      tl_assert(thr->errmsg_index >= 1);
      if (thr->announced)
         continue;
      if (thr->errmsg_index == 1/*FIXME: this hardwires an assumption
                                  about the identity of the root
                                  thread*/) {
         tl_assert(thr->created_at == NULL);
         VG_(message)(Vg_UserMsg, "Thread #%d is the program's root thread",
                                  thr->errmsg_index);
      } else {
         tl_assert(thr->created_at != NULL);
         VG_(message)(Vg_UserMsg, "Thread #%d was created",
                                  thr->errmsg_index);
         VG_(pp_ExeContext)( thr->created_at );
      }
      VG_(message)(Vg_UserMsg, "");
      thr->announced = True;
   }
}

static void announce_one_thread ( Thread* thr ) {
   announce_threadset( TC_(singletonWS)(univ_tsets, (Word)thr ));
}

static void summarise_threadset ( WordSetID tset, Char* buf, UInt nBuf )
{
   const Word limit = 5;
   Thread* thr;
   Word*   ts_words;
   Word    ts_size, i;
   UInt    off = 0;
   Word    loopmax;
   tl_assert(nBuf > 0);
   tl_assert(nBuf >= 40 + 20*limit);
   tl_assert(buf);
   TC_(getPayloadWS)( &ts_words, &ts_size, univ_tsets, tset );
   tl_assert(ts_words);
   tl_assert(ts_size >= 0);
   loopmax = limit < ts_size  ? limit  : ts_size; /* min(limit, ts_size) */
   tl_assert(loopmax >= 0 && loopmax <= limit);

   VG_(memset)(buf, 0, nBuf);
   // FIXME: list the threads in order of their errmsg_index
   // fields
   for (i = 0; i < loopmax; i++) {
      thr = (Thread*)ts_words[i];
      tl_assert(is_sane_Thread(thr));
      tl_assert(thr->errmsg_index >= 1);
      off += VG_(sprintf)(&buf[off], "#%d", (Int)thr->errmsg_index);
      if (i < loopmax-1)
         off += VG_(sprintf)(&buf[off], ", ");
   }
   if (limit < ts_size) {
      Word others = ts_size - limit;
      off += VG_(sprintf)(&buf[off], " and %d other%s", 
                                     (Int)others, others > 1 ? "s" : "");
   }
   tl_assert(off < nBuf);
   tl_assert(buf[nBuf-1] == 0);
}

static void tc_pp_Error ( Error* err )
{
   const Bool show_raw_states = False;
   XError *xe = (XError*)VG_(get_error_extra)(err);

   switch (VG_(get_error_kind)(err)) {

   case XE_Misc: {
      tl_assert(xe);
      tl_assert( is_sane_Thread( xe->XE.Misc.thr ) );
      announce_one_thread( xe->XE.Misc.thr );
      VG_(message)(Vg_UserMsg,
                  "Thread #%d: %s",
                  (Int)xe->XE.Misc.thr->errmsg_index,
                  xe->XE.Misc.errstr);
      VG_(pp_ExeContext)( VG_(get_error_where)(err) );
      break;
   }

   case XE_PthAPIerror: {
      tl_assert(xe);
      tl_assert( is_sane_Thread( xe->XE.PthAPIerror.thr ) );
      announce_one_thread( xe->XE.PthAPIerror.thr );
      VG_(message)(Vg_UserMsg,
                  "Thread #%d's call to %s failed",
                  (Int)xe->XE.PthAPIerror.thr->errmsg_index,
                  xe->XE.PthAPIerror.fnname);
      VG_(message)(Vg_UserMsg,
                  "   with error code %ld (%s)",
                  xe->XE.PthAPIerror.err,
                  xe->XE.PthAPIerror.errstr);
      VG_(pp_ExeContext)( VG_(get_error_where)(err) );
      break;
   }

   case XE_UnlockBogus: {
      tl_assert(xe);
      tl_assert( is_sane_Thread( xe->XE.UnlockBogus.thr ) );
      announce_one_thread( xe->XE.UnlockBogus.thr );
      VG_(message)(Vg_UserMsg,
                   "Thread #%d unlocked an invalid lock at %p ",
                   (Int)xe->XE.UnlockBogus.thr->errmsg_index,
                   (void*)xe->XE.UnlockBogus.lock_ga);
      VG_(pp_ExeContext)( VG_(get_error_where)(err) );
      break;
   }

   case XE_UnlockForeign: {
      tl_assert(xe);
      tl_assert( is_sane_LockP( xe->XE.UnlockForeign.lock ) );
      tl_assert( is_sane_Thread( xe->XE.UnlockForeign.owner ) );
      tl_assert( is_sane_Thread( xe->XE.UnlockForeign.thr ) );
      announce_one_thread( xe->XE.UnlockForeign.thr );
      announce_one_thread( xe->XE.UnlockForeign.owner );
      VG_(message)(Vg_UserMsg,
                   "Thread #%d unlocked lock at %p "
                   "currently held by thread #%d",
                   (Int)xe->XE.UnlockForeign.thr->errmsg_index,
                   (void*)xe->XE.UnlockForeign.lock->guestaddr,
                   (Int)xe->XE.UnlockForeign.owner->errmsg_index );
      VG_(pp_ExeContext)( VG_(get_error_where)(err) );
      if (xe->XE.UnlockForeign.lock->appeared_at) {
         VG_(message)(Vg_UserMsg,
                      "  Lock at %p was first observed",
                      (void*)xe->XE.UnlockForeign.lock->guestaddr);
         VG_(pp_ExeContext)( xe->XE.UnlockForeign.lock->appeared_at );
      }
      break;
   }

   case XE_UnlockUnlocked: {
      tl_assert(xe);
      tl_assert( is_sane_LockP( xe->XE.UnlockUnlocked.lock ) );
      tl_assert( is_sane_Thread( xe->XE.UnlockUnlocked.thr ) );
      announce_one_thread( xe->XE.UnlockUnlocked.thr );
      VG_(message)(Vg_UserMsg,
                   "Thread #%d unlocked a not-locked lock at %p ",
                   (Int)xe->XE.UnlockUnlocked.thr->errmsg_index,
                   (void*)xe->XE.UnlockUnlocked.lock->guestaddr);
      VG_(pp_ExeContext)( VG_(get_error_where)(err) );
      if (xe->XE.UnlockUnlocked.lock->appeared_at) {
         VG_(message)(Vg_UserMsg,
                      "  Lock at %p was first observed",
                      (void*)xe->XE.UnlockUnlocked.lock->guestaddr);
         VG_(pp_ExeContext)( xe->XE.UnlockUnlocked.lock->appeared_at );
      }
      break;
   }

   case XE_FreeMemLock: {
      tl_assert(xe);
      tl_assert( is_sane_LockP( xe->XE.FreeMemLock.lock ) );
      tl_assert( is_sane_Thread( xe->XE.FreeMemLock.thr ) );
      announce_one_thread( xe->XE.FreeMemLock.thr );
      VG_(message)(Vg_UserMsg,
                   "Thread #%d deallocated location %p "
                   "containing a locked lock",
                   (Int)xe->XE.FreeMemLock.thr->errmsg_index,
                   (void*)xe->XE.FreeMemLock.lock->guestaddr);
      VG_(pp_ExeContext)( VG_(get_error_where)(err) );
      if (xe->XE.FreeMemLock.lock->appeared_at) {
         VG_(message)(Vg_UserMsg,
                      "  Lock at %p was first observed",
                      (void*)xe->XE.FreeMemLock.lock->guestaddr);
         VG_(pp_ExeContext)( xe->XE.FreeMemLock.lock->appeared_at );
      }
      break;
   }

   case XE_Race: {
      Addr      err_ga;
      Char      old_buf[100], new_buf[100];
      Char      old_tset_buf[140], new_tset_buf[140];
      UInt      old_state, new_state;
      Thread*   thr_acc;
      WordSetID tset_to_announce = TC_(emptyWS)( univ_tsets );

      /* First extract some essential info */
      tl_assert(xe);
      old_state = xe->XE.Race.old_state;
      new_state = xe->XE.Race.new_state;
      thr_acc   = xe->XE.Race.thr;
      tl_assert(is_sane_Thread(thr_acc));
      err_ga = VG_(get_error_address)(err);

      /* Format the low level state print descriptions */
      show_shadow_w32(old_buf, sizeof(old_buf), old_state);
      show_shadow_w32(new_buf, sizeof(new_buf), new_state);

      /* Now we have to 'announce' the threadset mentioned in the
         error message, if it hasn't already been announced.
         Unfortunately the precise threadset and error message text
         depends on the nature of the transition involved.  So now
         fall into a case analysis of the error state transitions. */

      /* CASE of Excl -> ShM */
      if (is_SHMEM_Excl(old_state) && is_SHMEM_ShM(new_state)) {
         SegmentID old_segid;
         Segment*  old_seg;
         Thread*   old_thr; 
         WordSetID new_tset;
         old_segid = un_SHMEM_Excl( old_state );
         tl_assert(is_sane_SegmentID(old_segid));
         old_seg = map_segments_lookup( old_segid );
         tl_assert(is_sane_Segment(old_seg));
         tl_assert(old_seg->thr);
         old_thr = old_seg->thr;
         tl_assert(is_sane_Thread(old_thr));

         new_tset = un_SHMEM_ShM_tset(new_state);
         tset_to_announce = TC_(addToWS)( univ_tsets,
                                          new_tset, (Word)old_thr );
         announce_threadset( tset_to_announce );

         VG_(message)(Vg_UserMsg, "Possible data race during %s %p %(y",
                      VG_(get_error_string)(err), err_ga, err_ga);
         VG_(pp_ExeContext)( VG_(get_error_where)(err) );
         /* pp_AddrInfo(err_addr, &extra->addrinfo); */
         if (show_raw_states)
         VG_(message)(Vg_UserMsg,
                      "  Old state 0x%08x=%s, new state 0x%08x=%s",
                      old_state, old_buf, new_state, new_buf);
         VG_(message)(Vg_UserMsg,
                      "  Old state: owned exclusively by thread #%d",
                      old_thr->errmsg_index);
         // This should always show exactly 2 threads
         summarise_threadset( new_tset, new_tset_buf, sizeof(new_tset_buf) );
         VG_(message)(Vg_UserMsg,
                      "  New state: shared-modified by threads %s",
                      new_tset_buf );
         VG_(message)(Vg_UserMsg,
                      "  Reason:    this thread, #%d, holds no locks at all",
                      thr_acc->errmsg_index);
      }
      else 
      /* Case of ShR/M -> ShM */
      if (is_SHMEM_Sh(old_state) && is_SHMEM_ShM(new_state)) {
         WordSetID old_tset = un_SHMEM_Sh_tset(old_state);
         WordSetID new_tset = un_SHMEM_Sh_tset(new_state);

         tset_to_announce = TC_(unionWS)( univ_tsets, old_tset, new_tset );
         announce_threadset( tset_to_announce );

         VG_(message)(Vg_UserMsg, "Possible data race during %s %p %(y",
                      VG_(get_error_string)(err), err_ga, err_ga);
         VG_(pp_ExeContext)( VG_(get_error_where)(err) );
         /* pp_AddrInfo(err_addr, &extra->addrinfo); */
         if (show_raw_states)
         VG_(message)(Vg_UserMsg,
                      "  Old state 0x%08x=%s, new state 0x%08x=%s",
                      old_state, old_buf, new_state, new_buf);

         summarise_threadset( old_tset, old_tset_buf, sizeof(old_tset_buf) );
         summarise_threadset( new_tset, new_tset_buf, sizeof(new_tset_buf) );

         VG_(message)(Vg_UserMsg,
                      "  Old state: shared-%s by threads %s", 
                      is_SHMEM_ShM(old_state) ? "modified" : "readonly", 
                      old_tset_buf);
         VG_(message)(Vg_UserMsg,
                      "  New state: shared-modified by threads %s", 
                      new_tset_buf);
         VG_(message)(Vg_UserMsg,
                      "  Reason:    this thread, #%d, holds no "
                      "consistent locks",
                      thr_acc->errmsg_index);
         if (xe->XE.Race.mb_lastlock) {
            VG_(message)(Vg_UserMsg, "  Last consistently used lock for %p was "
                                     "first observed", err_ga);
            VG_(pp_ExeContext)(xe->XE.Race.mb_lastlock);
         } else {
            VG_(message)(Vg_UserMsg, "  Location %p has never been protected "
                                     "by any lock", err_ga);
         }
      }
      /* Hmm, unknown transition.  Just print what we do know. */
      else {
         VG_(message)(Vg_UserMsg, "Possible data race during %s %p %(y",
                      VG_(get_error_string)(err), err_ga, err_ga);
         VG_(pp_ExeContext)( VG_(get_error_where)(err) );

         //pp_AddrInfo(err_addr, &extra->addrinfo);
         VG_(message)(Vg_UserMsg,
                      "  Old state 0x%08x=%s, new state 0x%08x=%s",
                      old_state, old_buf, new_state, new_buf);
      }

      break; /* case XE_Race */
   } /* case XE_Race */

   default:
      tl_assert(0);
   } /* switch (VG_(get_error_kind)(err)) */
}

static Char* tc_get_error_name ( Error* err )
{
   switch (VG_(get_error_kind)(err)) {
      case XE_Race:           return "Race";
      case XE_FreeMemLock:    return "FreeMemLock";
      case XE_UnlockUnlocked: return "UnlockUnlocked";
      case XE_UnlockForeign:  return "UnlockForeign";
      case XE_UnlockBogus:    return "UnlockBogus";
      case XE_DestroyLocked:  return "DestroyLocked";
      case XE_PthAPIerror:    return "PthAPIerror";
      case XE_Misc:           return "Misc";
      default: tl_assert(0); /* fill in missing case */
   }
}

static Bool tc_recognised_suppression ( Char* name, Supp *su )
{
#  define TRY(_name,_xskind)                   \
      if (0 == VG_(strcmp)(name, (_name))) {   \
         VG_(set_supp_kind)(su, (_xskind));    \
         return True;                          \
      }
   TRY("Race",           XS_Race);
   TRY("FreeMemLock",    XS_FreeMemLock);
   TRY("UnlockUnlocked", XS_UnlockUnlocked);
   TRY("UnlockForeign",  XS_UnlockForeign);
   TRY("UnlockBogus",    XS_UnlockBogus);
   TRY("DestroyLocked",  XS_DestroyLocked);
   TRY("PthAPIerror",    XS_PthAPIerror);
   TRY("Misc",           XS_Misc);
   return False;
#  undef TRY
}

static Bool tc_read_extra_suppression_info ( Int fd, Char* buf, Int nBuf,
                                             Supp* su )
{
   /* do nothing -- no extra suppression info present.  Return True to
      indicate nothing bad happened. */
   return True;
}

static Bool tc_error_matches_suppression ( Error* err, Supp* su )
{
   switch (VG_(get_supp_kind)(su)) {
   case XS_Race:           return VG_(get_error_kind)(err) == XE_Race;
   case XS_FreeMemLock:    return VG_(get_error_kind)(err) == XE_FreeMemLock;
   case XS_UnlockUnlocked: return VG_(get_error_kind)(err) == XE_UnlockUnlocked;
   case XS_UnlockForeign:  return VG_(get_error_kind)(err) == XE_UnlockForeign;
   case XS_UnlockBogus:    return VG_(get_error_kind)(err) == XE_UnlockBogus;
   case XS_DestroyLocked:  return VG_(get_error_kind)(err) == XE_DestroyLocked;
   case XS_PthAPIerror:    return VG_(get_error_kind)(err) == XE_PthAPIerror;
   case XS_Misc:           return VG_(get_error_kind)(err) == XE_Misc;
   //case XS_: return VG_(get_error_kind)(err) == XE_;
   default: tl_assert(0); /* fill in missing cases */
   }
}

static void tc_print_extra_suppression_info ( Error* err )
{
   /* Do nothing */
}


/*----------------------------------------------------------------*/
/*--- Setup                                                    ---*/
/*----------------------------------------------------------------*/

static Bool tc_process_cmd_line_option ( Char* arg )
{
   if      (VG_CLO_STREQ(arg, "--happens-before=none"))
      clo_happens_before = 0;
   else if (VG_CLO_STREQ(arg, "--happens-before=threads"))
      clo_happens_before = 1;
   else if (VG_CLO_STREQ(arg, "--happens-before=condvars"))
      clo_happens_before = 2;

   else 
      return VG_(replacement_malloc_process_cmd_line_option)(arg);

   return True;
}

static void tc_print_usage ( void )
{
   VG_(printf)(
"    --happens-before=none|threads|condvars   [condvars] consider no events,\n"
"      thread create/join, thread create/join/cvsignal/cvwait as sync points\n"
   );
   VG_(replacement_malloc_print_usage)();
}

static void tc_print_debug_usage ( void )
{
   VG_(replacement_malloc_print_debug_usage)();
}

static void tc_post_clo_init ( void )
{
}

static void tc_fini ( Int exitcode )
{
   if (SHOW_DATA_STRUCTURES)
      pp_everything( PP_ALL, "SK_(fini)" );
   if (sanity_flags)
      all__sanity_check("SK_(fini)");

   if (0)
      segments__generate_vcg();

   if (VG_(clo_verbosity) >= 2) {
      VG_(printf)("\n");
      VG_(printf)("     msm: %10lu %10lu rd/wr_Excl_nochange\n",
                  stats__msm_r32_Excl_nochange, stats__msm_w32_Excl_nochange);
      VG_(printf)("     msm: %10lu %10lu rd/wr_Excl_transfer\n",
                  stats__msm_r32_Excl_transfer, stats__msm_w32_Excl_transfer);
      VG_(printf)("     msm: %10lu %10lu rd/wr_Excl_to_ShR/ShM\n",
                  stats__msm_r32_Excl_to_ShR,   stats__msm_w32_Excl_to_ShM);
      VG_(printf)("     msm: %10lu %10lu rd/wr_ShR_to_ShR/ShM\n",
                  stats__msm_r32_ShR_to_ShR,    stats__msm_w32_ShR_to_ShM);
      VG_(printf)("     msm: %10lu %10lu rd/wr_ShM_to_ShM\n",
                  stats__msm_r32_ShM_to_ShM,    stats__msm_w32_ShM_to_ShM);
      VG_(printf)("     msm: %10lu %10lu rd/wr_New_to_Excl\n",
                  stats__msm_r32_New_to_Excl,   stats__msm_w32_New_to_Excl);
      VG_(printf)("     msm: %10lu %10lu rd/wr_NoAccess\n",
                  stats__msm_r32_NoAccess,      stats__msm_w32_NoAccess);
      VG_(printf)("\n");
      VG_(printf)("   shmem: %10lu accesses\n",       stats__shmem_rw32s);
      VG_(printf)("   shmem: %10lu cache 0 hits\n",   stats__shmem_cache0s);
      VG_(printf)("   shmem: %10lu cache > 0 hits\n", stats__shmem_cacheNs);
      VG_(printf)("   shmem: %10lu tree searches\n",  stats__shmem_tsearches);
      VG_(printf)("   shmem: %10lu cache invals\n",   stats__shmem_invals);
      VG_(printf)("\n");
      VG_(printf)(" hbefore: %10lu queries\n",        stats__hbefore_queries);
      VG_(printf)(" hbefore: %10lu cache 0 hits\n",   stats__hbefore_cache0s);
      VG_(printf)(" hbefore: %10lu cache > 0 hits\n", stats__hbefore_cacheNs);
      VG_(printf)(" hbefore: %10lu graph searches\n", stats__hbefore_gsearches);
      VG_(printf)(" hbefore: %10lu   of which slow\n",
                  stats__hbefore_gsearches - stats__hbefore_gsearchFs);
      VG_(printf)(" hbefore: %10lu cache invals\n",   stats__hbefore_invals);
      VG_(printf)(" hbefore: %10lu probes\n",         stats__hbefore_probes);
      VG_(printf)("\n");
      VG_(printf)("segments:       %10lu Segment objects allocated\n", 
                  stats__mk_Segment);
      VG_(printf)("locksets:         %8d unique lock sets\n",
                  (Int)TC_(cardinalityWSU)( univ_lsets ));
      VG_(printf)("threadsets:       %8d unique thread sets\n",
                  (Int)TC_(cardinalityWSU)( univ_tsets ));

      VG_(printf)("L(ast)L(ock) map: %8lu inserts (%d map size)\n", 
                  stats__ga_LL_adds,
                  (Int)(ga_to_lastlock ? TC_(sizeFM)( ga_to_lastlock ) : 0) );

      VG_(printf)("LockN-to-P map:   %8lu queries (%d map size)\n", 
                  stats__ga_LockN_to_P_queries,
                  (Int)(yaWFM ? TC_(sizeFM)( yaWFM ) : 0) );

      VG_(printf)("string table map: %8lu queries (%d map size)\n", 
                  stats__string_table_queries,
                  (Int)(string_table ? TC_(sizeFM)( string_table ) : 0) );

      VG_(printf)("\n");
      TC_(ppWSUstats)( univ_tsets, "univ_tsets" );
      VG_(printf)("\n");
      TC_(ppWSUstats)( univ_lsets, "univ_lsets" );
      VG_(printf)("\n");
   }
}

static void tc_pre_clo_init ( void )
{
   VG_(details_name)            ("Thrcheck");
   VG_(details_version)         (NULL);
   VG_(details_description)     ("a thread error detector");
   VG_(details_copyright_author)(
      "Copyright (C) 2007-2007, and GNU GPL'd, by OpenWorks LLP et al.");
   VG_(details_bug_reports_to)  (VG_BUGS_TO);
   VG_(details_avg_translation_sizeB) ( 200 );

   VG_(basic_tool_funcs)          (tc_post_clo_init,
                                   tc_instrument,
                                   tc_fini);

   VG_(needs_core_errors)         ();
   VG_(needs_tool_errors)         (tc_eq_Error,
                                   tc_pp_Error,
                                   False,/*show TIDs for errors*/
                                   tc_update_extra,
                                   tc_recognised_suppression,
                                   tc_read_extra_suppression_info,
                                   tc_error_matches_suppression,
                                   tc_get_error_name,
                                   tc_print_extra_suppression_info);

   VG_(needs_command_line_options)(tc_process_cmd_line_option,
                                   tc_print_usage,
                                   tc_print_debug_usage);
   VG_(needs_client_requests)     (tc_handle_client_request);

   // FIXME?
   //VG_(needs_sanity_checks)       (tc_cheap_sanity_check,
   //                                tc_expensive_sanity_check);

   VG_(needs_malloc_replacement)  (tc_cli__malloc,
                                   tc_cli____builtin_new,
                                   tc_cli____builtin_vec_new,
                                   tc_cli__memalign,
                                   tc_cli__calloc,
                                   tc_cli__free,
                                   tc_cli____builtin_delete,
                                   tc_cli____builtin_vec_delete,
                                   tc_cli__realloc,
                                   TC_CLI__MALLOC_REDZONE_SZB );

   VG_(needs_data_syms)();

   //VG_(needs_xml_output)          ();

   VG_(track_new_mem_startup)     ( evh__new_mem_w_perms );
   VG_(track_new_mem_stack_signal)( evh__die_mem );
   VG_(track_new_mem_brk)         ( evh__new_mem );
   VG_(track_new_mem_mmap)        ( evh__new_mem_w_perms );
   VG_(track_new_mem_stack)       ( evh__new_mem );

   // FIXME: surely this isn't thread-aware
   VG_(track_copy_mem_remap)      ( shmem__copy_arange_state );

   VG_(track_change_mem_mprotect) ( evh__set_perms );

   VG_(track_die_mem_stack_signal)( evh__die_mem );
   VG_(track_die_mem_brk)         ( evh__die_mem );
   VG_(track_die_mem_munmap)      ( evh__die_mem );
   VG_(track_die_mem_stack)       ( evh__die_mem );

   // FIXME: what is this for?
   VG_(track_ban_mem_stack)       (NULL);

   VG_(track_pre_mem_read)        ( evh__pre_mem_read );
   VG_(track_pre_mem_read_asciiz) ( evh__pre_mem_read_asciiz );
   VG_(track_pre_mem_write)       ( evh__pre_mem_write );
   VG_(track_post_mem_write)      (NULL);

   /////////////////

   VG_(track_pre_thread_ll_create)( evh__pre_thread_ll_create );
   VG_(track_pre_thread_ll_exit)  ( evh__pre_thread_ll_exit );

   initialise_data_structures();

   /* Ensure that requirements for "dodgy C-as-C++ style inheritance"
      as described in comments at the top of pub_tool_hashtable.h, are
      met.  Blargh. */
   tl_assert( sizeof(void*) == sizeof(struct _MallocMeta*) );
   tl_assert( sizeof(UWord) == sizeof(Addr) );
   tc_mallocmeta_table
      = VG_(HT_construct)( "tc_malloc_metadata_table" );
}

VG_DETERMINE_INTERFACE_VERSION(tc_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                tc_main.c ---*/
/*--------------------------------------------------------------------*/
