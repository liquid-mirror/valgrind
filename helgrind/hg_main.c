/*--------------------------------------------------------------------*/
/*--- The Eraser skin: checking for data races in threaded         ---*/
/*--- programs.                                                    ---*/
/*---                                                  vg_eraser.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, an x86 protected-mode emulator
   designed for debugging and profiling binaries on x86-Unixes.

   Copyright (C) 2000-2002 Nicholas Nethercote
      njn25@cam.ac.uk

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

static UInt n_eraser_warnings = 0;

/*------------------------------------------------------------*/
/*--- Debug guff                                           ---*/
/*------------------------------------------------------------*/

#define DEBUG_LOCK_TABLE    1   /* Print lock table at end */

#define DEBUG_MAKE_ACCESSES 0   /* Print make_access() calls */
#define DEBUG_LOCKS         0   /* Print lock()/unlock() calls and locksets */
#define DEBUG_NEW_LOCKSETS  0   /* Print new locksets when created */
#define DEBUG_ACCESSES      0   /* Print reads, writes */
#define DEBUG_MEM_LOCKSET_CHANGES 0   /* Print when an address's lockset changes;  only useful with DEBUG_ACCESSES */

#define DEBUG_VIRGIN_READS  1   /* Dump around address on VIRGIN reads */

/*------------------------------------------------------------*/
/*--- Low-level support for memory tracking.               ---*/
/*------------------------------------------------------------*/

/*
   All reads and writes are recorded in the memory map, which
   records the state of all memory in the process.  The memory map is
   organised like that for normal Valgrind, except each that everything
   is done at word-level instead of byte-level, and each word has only
   one word of shadow (instead of 36 bits).  

   As for normal Valgrind there is a distinguished secondary map.  But we're
   working at word-granularity, so it has 16k word entries instead of 64k byte
   entries.  Lookup is done as follows:

     bits 31..16:   primary map lookup
     bits 15.. 2:   secondary map lookup
     bits  1.. 0:   ignored
*/

/*------------------------------------------------------------*/
/*--- Crude profiling machinery.                           ---*/
/*------------------------------------------------------------*/

// PPP: work out if I want this

#define PROF_EVENT(x)
#if 0
#ifdef VG_PROFILE_MEMORY

#define N_PROF_EVENTS 150

static UInt event_ctr[N_PROF_EVENTS];

void VGE_(done_prof_mem) ( void )
{
   Int i;
   for (i = 0; i < N_PROF_EVENTS; i++) {
      if ((i % 10) == 0)
         VG_(printf)("\n");
      if (event_ctr[i] > 0)
         VG_(printf)( "prof mem event %2d: %d\n", i, event_ctr[i] );
   }
   VG_(printf)("\n");
}

#define PROF_EVENT(ev)                                  \
   do { vg_assert((ev) >= 0 && (ev) < N_PROF_EVENTS);   \
        event_ctr[ev]++;                                \
   } while (False);

#else

//static void init_prof_mem ( void ) { }
//       void VG_(done_prof_mem) ( void ) { }

#define PROF_EVENT(ev) /* */

#endif

/* Event index.  If just the name of the fn is given, this means the
   number of calls to the fn.  Otherwise it is the specified event.

   [PPP: snip event numbers...]
*/
#endif 

/*------------------------------------------------------------*/
/*--- Data defns.                                          ---*/
/*------------------------------------------------------------*/

typedef enum 
   { Vge_VirginInit, Vge_NonVirginInit, Vge_SegmentInit } 
   VgeInitStatus;

/* Should add up to 32 to fit in one word */
#define OTHER_BITS      30
#define STATE_BITS      2

#define ESEC_MAP_WORDS  16384   /* Words per secondary map */

/* This is for indicating that a memory block has been initialised but not
 * really directly by a particular thread... (eg. text/data initialised
 * automatically at startup).
 * Must be different to virgin_word.other */
#define TID_INDICATING_NONVIRGIN    1

/* Number of entries must fit in STATE_BITS bits */
typedef enum { Vge_Virgin, Vge_Excl, Vge_Shar, Vge_SharMod } pth_state;

typedef
   struct {
      UInt other:OTHER_BITS;
      UInt state:STATE_BITS;
   } shadow_word;

typedef
   struct {
      shadow_word swords[ESEC_MAP_WORDS];
   }
   ESecMap;

static ESecMap* primary_map[ 65536 ];
static ESecMap  distinguished_secondary_map;

static shadow_word virgin_sword = { 0, Vge_Virgin };

#define VGE_IS_DISTINGUISHED_SM(smap) \
   ((smap) == &distinguished_secondary_map)

#define ENSURE_MAPPABLE(addr,caller)                                   \
   do {                                                                \
      if (VGE_IS_DISTINGUISHED_SM(primary_map[(addr) >> 16])) {       \
         primary_map[(addr) >> 16] = alloc_secondary_map(caller); \
         /*VG_(printf)("new 2map because of %p\n", addr);*/           \
      } \
   } while(0)

/*------------------------------------------------------------*/
/*--- Basic bitmap management, reading and writing.        ---*/
/*------------------------------------------------------------*/

/* Allocate and initialise a secondary map, marking all words as virgin. */

/* Just a value that isn't a real pointer */
#define SEC_MAP_ACCESS  (shadow_word*)0x99    

static ESecMap* alloc_secondary_map ( __attribute__ ((unused))
                                     Char* caller )
{
   ESecMap* map;
   UInt  i;
   //PROF_EVENT(10); PPP

   /* It just happens that a SecMap occupies exactly 18 pages --
      although this isn't important, so the following assert is
      spurious. (SSS: not true for ESecMaps -- they're 16 pages) */
   vg_assert(0 == (sizeof(ESecMap) % VKI_BYTES_PER_PAGE));
   map = VG_(get_memory_from_mmap)( sizeof(ESecMap), caller );

   for (i = 0; i < ESEC_MAP_WORDS; i++)
      map->swords[i] = virgin_sword;

   return map;
}

/* Set a word.  The byte give by 'a' could be anywhere in the word -- the whole
 * word gets set. */
static __inline__ void set_sword ( Addr a, shadow_word sword )
{
   ESecMap* sm;

   //PROF_EVENT(23); PPP
   ENSURE_MAPPABLE(a, "VGE_(set_sword)");

   /* Use bits 31..16 for primary, 15..2 for secondary lookup */
   sm     = primary_map[a >> 16];
   vg_assert(sm != &distinguished_secondary_map);
   sm->swords[(a & 0xFFFC) >> 2] = sword;

   if (VGE_IS_DISTINGUISHED_SM(sm)) {
      VG_(printf)("wrote to distinguished 2ndary map! 0x%x\n", a);
      // XXX: may be legit, but I want to know when it happens --njn
      VG_(panic)("wrote to distinguished 2ndary map!");
   }
}

static __inline__ shadow_word* get_sword_addr ( Addr a )
{
   /* Use bits 31..16 for primary, 15..2 for secondary lookup */
   ESecMap* sm     = primary_map[a >> 16];
   UInt    sm_off = (a & 0xFFFC) >> 2;

   if (VGE_IS_DISTINGUISHED_SM(sm)) {
      VG_(printf)("accessed distinguished 2ndary map! 0x%x\n", a);
      // XXX: may be legit, but I want to know when it happens --njn
      //VG_(panic)("accessed distinguished 2ndary map!");
      return SEC_MAP_ACCESS;
   }

   //PROF_EVENT(21); PPP
   return & (sm->swords[sm_off]);
}

// SSS: rename these so they're not so similar to memcheck, unless it's
// appropriate of course

static __inline__ void init_virgin_sword(Addr a)
{
   set_sword(a, virgin_sword);
}

/* 'a' is guaranteed to be 4-byte aligned here (not that that's important,
 * really) */
void make_writable_aligned ( Addr a, UInt size )
{
   Addr a_past_end = a + size;

   //PROF_EVENT(??)  PPP
   vg_assert(IS_ALIGNED4_ADDR(a));

   for ( ; a < a_past_end; a += 4) {
      set_sword(a, virgin_sword);
   }
}

static __inline__ void init_nonvirgin_sword(Addr a)
{
   shadow_word sword;

   sword.other = VG_(get_current_tid_1_if_root)();
   sword.state = Vge_Excl;
   set_sword(a, sword);
}

/* In this case, we treat it for Eraser's sake like virgin (it hasn't
 * been inited by a particular thread, it's just done automatically upon
 * startup), but we mark its .state specially so it doesn't look like an 
 * uninited read. */
static __inline__ void init_magically_inited_sword(Addr a)
{
   shadow_word sword;

   vg_assert(1 == VG_(get_current_tid_1_if_root)());
   sword.other = TID_INDICATING_NONVIRGIN;
   sword.state = Vge_Virgin;
   set_sword(a, virgin_sword);
}

/*------------------------------------------------------------*/
/*--- Setting and checking permissions.                    ---*/
/*------------------------------------------------------------*/

void set_address_range_state ( Addr a, UInt len /* in bytes */, 
                               VgeInitStatus status )
{
   Addr aligned_a, end, aligned_end;

#if DEBUG_MAKE_ACCESSES
   VG_(printf)("make_access: 0x%x, %u, status=%u\n", a, len, status);
#endif
   //PROF_EVENT(30); PPP

   if (len == 0)
      return;

   if (len > 100 * 1000 * 1000)
      VG_(message)(Vg_UserMsg,
                   "Warning: set address range perms: large range %d",
                   len);

   VGP_PUSHCC(VgpSARP);

   /* Memory block may not be aligned or a whole word multiple.  In neat cases,
    * we have to init len/4 words (len is in bytes).  In nasty cases, it's
    * len/4+1 words.  This works out which it is by aligning the block and
    * seeing if the end byte is in the same word as it is for the unaligned
    * block; if not, it's the awkward case. */
   aligned_a   = a & 0xc;                       /* zero bottom two bits */
   end         = a + len;
   aligned_end = aligned_a + len;
   if ((end & 0xc) != (aligned_end & 0xc)) {
       end += 4;    /* len/4 + 1 case */
   }

   /* Do it ... */
   switch (status) {
   case Vge_VirginInit:
      for ( ; a < end; a += 4) {
         //PROF_EVENT(31);  PPP
         init_virgin_sword(a);
      }
      break;

   case Vge_NonVirginInit:
      for ( ; a < end; a += 4) {
         //PROF_EVENT(31);  PPP
         init_nonvirgin_sword(a);
      }
      break;

   case Vge_SegmentInit:
      for ( ; a < end; a += 4) {
         //PROF_EVENT(31);  PPP
         init_magically_inited_sword(a);
      }
      break;
   
   default:
      VG_(printf)("init_status = %u\n", status);
      VG_(panic)("Unexpected Vge_InitStatus");
   }
      
   /* Check that zero page and highest page have not been written to
      -- this could happen with buggy syscall wrappers.  Today
      (2001-04-26) had precisely such a problem with
      __NR_setitimer. */
   vg_assert(SKN_(cheap_sanity_check)());
   VGP_POPCC;
}



void make_segment_readable ( Addr a, UInt len )
{
   //PROF_EVENT(??);    PPP
   set_address_range_state ( a, len, Vge_SegmentInit );
}

void make_writable ( Addr a, UInt len )
{
   //PROF_EVENT(36);  PPP
   set_address_range_state( a, len, Vge_VirginInit );
}

void make_readable ( Addr a, UInt len )
{
   //PROF_EVENT(37);  PPP
   set_address_range_state( a, len, Vge_NonVirginInit );
}


// SSS: change name
/* Block-copy states (needed for implementing realloc()). */
void copy_address_range_state(Addr src, Addr dst, UInt len)
{
   UInt i;

   //PROF_EVENT(40); PPP

   for (i = 0; i < len; i += 4) {
      shadow_word sword = *(get_sword_addr ( src+i ));
      //PROF_EVENT(41);  PPP
      set_sword ( dst+i, sword );
   }
}

// SSS: put these somewhere better
static void eraser_mem_read (Addr a, UInt data_size);
static void eraser_mem_write(Addr a, UInt data_size);

static
void eraser_pre_mem_read(CorePart part, ThreadState* tst,
                         Char* s, UInt base, UInt size )
{
   eraser_mem_read(base, size);
}

static
void eraser_pre_mem_read_asciiz(CorePart part, ThreadState* tst,
                                Char* s, UInt base )
{
   eraser_mem_read(base, VG_(strlen)((Char*)base));
}

static
void eraser_pre_mem_write(CorePart part, ThreadState* tst,
                          Char* s, UInt base, UInt size )
{
   eraser_mem_write(base, size);
}



static
void eraser_new_mem_startup( Addr a, UInt len, Bool rr, Bool ww, Bool xx )
{
   // JJJ: this ignores the permissions and just makes it readable, like the
   // old code did, AFAICT
   make_segment_readable(a, len);
}


static
void eraser_new_mem_heap ( Addr a, UInt len, Bool is_inited )
{
   if (is_inited) {
      make_readable(a, len);
   } else {
      make_writable(a, len);
   }
}

static
void eraser_set_perms (Addr a, UInt len,
                       Bool nn, Bool rr, Bool ww, Bool xx)
{
   if      (rr) make_readable(a, len);
   else if (ww) make_writable(a, len);
   /* else do nothing */
}


/*--------------------------------------------------------------*/
/*--- Initialise the memory audit system on program startup. ---*/
/*--------------------------------------------------------------*/

void init_shadow_memory(void)
{
   Int i;

   for (i = 0; i < ESEC_MAP_WORDS; i++)
      distinguished_secondary_map.swords[i] = virgin_sword;

   /* These entries gradually get overwritten as the used address
      space expands. */
   for (i = 0; i < 65536; i++)
      primary_map[i] = &distinguished_secondary_map;
}

/*--------------------------------------------------------------*/
/*--- Machinery to support sanity checking                   ---*/
/*--------------------------------------------------------------*/

/* Check that nobody has spuriously claimed that the first or last 16
   pages (64 KB) of address space have become accessible.  Failure of
   the following do not per se indicate an internal consistency
   problem, but they are so likely to that we really want to know
   about it if so. */

Bool SKN_(cheap_sanity_check) ( void )
{
   if (VGE_IS_DISTINGUISHED_SM(primary_map[0]) && 
       VGE_IS_DISTINGUISHED_SM(primary_map[65535]))
      return True;
   else
      return False;
}

Bool SKN_(expensive_sanity_check)(void)
{
   Int i;

   /* Make sure nobody changed the distinguished secondary. */
   for (i = 0; i < ESEC_MAP_WORDS; i++)
      if (distinguished_secondary_map.swords[i].other != virgin_sword.other ||
          distinguished_secondary_map.swords[i].state != virgin_sword.state)
         return False;

   return True;
}

/*--------------------------------------------------------------*/
/*--- Instrumentation                                        ---*/
/*--------------------------------------------------------------*/

#define uInstr1   VG_(newUInstr1)
#define uInstr2   VG_(newUInstr2)
#define uLiteral  VG_(setLiteralField)
#define newTemp   VG_(getNewTemp)

/* Create and return an instrumented version of cb_in.  Free cb_in
   before returning. */
static UCodeBlock* eraser_instrument ( UCodeBlock* cb_in )
{
   UCodeBlock* cb;
   Int         i;
   UInstr*     u_in;
   Int         t_size = INVALID_TEMPREG;



   cb = VG_(allocCodeBlock)();
   cb->nextTemp = cb_in->nextTemp;

   for (i = 0; i < cb_in->used; i++) {
      u_in = &cb_in->instrs[i];

      /* VG_(ppUInstr)(0, u_in); */
      switch (u_in->opcode) {

         case NOP: case CALLM_S: case CALLM_E:
            break;

         /* For LOAD, address is in val1 */
         case LOAD:
            t_size = newTemp(cb);
            uInstr2(cb, MOV,   4, Literal, 0, TempReg, t_size);
            uLiteral(cb, (UInt)u_in->size);

            vg_assert(1 == u_in->size || 2 == u_in->size || 4 == u_in->size || 
                      8 == u_in->size || 10 == u_in->size);
            uInstr2(cb, CCALL_2_0, 0, TempReg, u_in->val1, TempReg, t_size);
            uLiteral(cb, (Addr) & eraser_mem_read);
            VG_(copyUInstr)(cb, u_in);
            t_size = INVALID_TEMPREG;
            break;

         /* For others, address is in val2 */
         case STORE:  case FPU_R:  case FPU_W:
            t_size = newTemp(cb);
            uInstr2(cb, MOV,   4, Literal, 0, TempReg, t_size);
            uLiteral(cb, (UInt)u_in->size);

            vg_assert(1 == u_in->size || 2 == u_in->size || 4 == u_in->size || 
                      8 == u_in->size || 10 == u_in->size);
            uInstr2(cb, CCALL_2_0, 0, TempReg, u_in->val2, TempReg, t_size);
            uLiteral(cb, (Addr) & eraser_mem_write);
            VG_(copyUInstr)(cb, u_in);
            t_size = INVALID_TEMPREG;
            break;

         default:
            VG_(copyUInstr)(cb, u_in);
            break;
      }
   }

   VG_(freeCodeBlock)(cb_in);
   return cb;
}

UCodeBlock* SK_(instrument)(UCodeBlock* cb, Addr not_used)
{
   /* VGP_PUSHCC(VgpInstrument); */
   cb = eraser_instrument(cb);
   /* VGP_POPCC; */
   if (VG_(disassemble)) 
      VG_(ppUCodeBlock) ( cb, "Eraser instrumented code:" );
   return cb;
}

/* ---------------------------------------------------------------------
   Lock tracking machinery
   ------------------------------------------------------------------ */

#define LOCKSET_TABLE_SIZE  1000
#define MAX_LOCKS           5
#define INVALID_LOCKSET_ENTRY   (lock_vector*)0xFFFFFFFF

#include <pthread.h>

typedef 
   struct _lock_vector {
       pthread_mutex_t*     mutex;
       struct _lock_vector* next;
   } lock_vector;

/* Each one is an index into the lockset table */
UInt thread_locks[VG_N_THREADS];

/* lockset_table[0] is always NULL, representing the empty lockset */
lock_vector* lockset_table[LOCKSET_TABLE_SIZE];

static void print_lock_vector(lock_vector* p)
{
   VG_(printf)("vector = ");
   while (p != NULL) {
      VG_(printf)("%x ", p->mutex);
      p = p->next;
   }
   VG_(printf)("\n");
}

/*--------------------------------------------------------------------*/
/*--- Error and suppression handling                               ---*/
/*--------------------------------------------------------------------*/

typedef
   enum {
      /* Possible data race */
      Eraser = FinalDummySuppressionKind + 1
   }
   EraserSuppressionKind;

/* What kind of error it is. */
typedef
   enum { EraserErr = FinalDummyErrKind + 1
   }
   EraserErrKind;


void record_eraser_error ( ThreadId tid, Addr a, Bool is_write )
{
   ErrContext ec;

   if (VG_(ignore_errors)()) return;

   VG_(construct_err_context)(&ec, EraserErr, a, 
                              (is_write ? "writing" : "reading"),
                              &VG_(threads)[tid]);

   /* Nothing required in 'extra' field */
   VG_(maybe_add_context) ( &ec );
}

Bool SKN_(eq_ErrContext) ( Bool cheap_addr_cmp,
                           ErrContext* e1, ErrContext* e2 )
{
   vg_assert(EraserErr == e1->ekind && EraserErr == e2->ekind);
   if (e1->string != e2->string) return False;
   if (0 != VG_(strcmp)(e1->string, e2->string)) return False;
   return True;
}

void SKN_(pp_ErrContext) ( ErrContext* ec )
{
   vg_assert(EraserErr == ec->ekind);
   VG_(message)(Vg_UserMsg, "Possible data race %s variable at 0x%x",
                ec->string, ec->addr );
   VG_(pp_ExeContext)(ec->where);
}

void SKN_(dup_extra_and_update)(ErrContext* ec)
{
   /* do nothing -- extra field not used */
}

Bool SKN_(recognised_suppression) ( Char* name, SuppressionKind *skind )
{
   if (0 == VG_(strcmp)(name, "Eraser")) {
      *skind = Eraser;
      return True;
   } else {
      return False;
   }
}

Bool SKN_(read_extra_suppression_info) ( Int fd, Char* buf, 
                                         Int nBuf, Suppression *s )
{
   /* do nothing -- no extra suppression info present.  Return True to
      indicate nothing bad happened. */
   return True;
}

Bool SKN_(error_matches_suppression)(ErrContext* ec, Suppression* su)
{
   vg_assert(su->skind == Eraser);
   vg_assert(ec->ekind == EraserErr);
   return True;
}


/*--------------------------------------------------------------------*/
/*--- Locks n stuff                                                ---*/
/*--------------------------------------------------------------------*/

static Bool lock_vector_equals(lock_vector* a, lock_vector* b)
{
   while (a && b) {
      if (a->mutex != b->mutex) {
         return False;
      }
      a = a->next;
      b = b->next;
   }
   return (NULL == a && NULL == b);
}

/* Tricky: equivalent to (compare(insert(missing_elem, a), b)), but
 * doesn't do the insertion.  Returns True if they match.
 */
static Bool 
weird_lock_vector_equals(lock_vector* a, lock_vector* b, 
                         pthread_mutex_t* missing_mutex)
{
   while (True) {
      if (NULL == a) {
         return (b != NULL && b->mutex == missing_mutex && b->next == NULL);
         
      } else if (b == NULL) {
         return False;
      
      } else if (a->mutex == b->mutex) { 
         a = a->next; 
         b = b->next; 

      } else if (b->mutex == missing_mutex) { 
         b = b->next; 
         /* by now we've matched the missing element;  rest of lists
          * should be identical */
         while (True) {
            if (NULL == a && NULL == b) return True;
            else if (NULL == a || NULL == b) return False;
            else if (a->mutex == b->mutex) {
               a = a->next; 
               b = b->next; 
            } else 
               return False;
         }
      }
      else return False;
   }
}

// SSS: copying mutex's pointer... is that ok?  Could they get deallocated?
// (does that make sense, deallocating a mutex?)
void eraser_post_mutex_lock(ThreadId tid, void* void_mutex)
{
   Int i = 1;
   lock_vector*  new_node;
   lock_vector*  p;
   lock_vector** q;
   pthread_mutex_t* mutex = (pthread_mutex_t*)void_mutex;
   
#if DEBUG_LOCKS
   VG_(printf)("lock  (%u, %x)\n", tid, mutex);
#endif

   vg_assert(tid < VG_N_THREADS &&
             thread_locks[tid] < LOCKSET_TABLE_SIZE);

   while (True) {
      if (i == LOCKSET_TABLE_SIZE) 
         VG_(panic)("lockset table full -- increase LOCKSET_TABLE_SIZE");

      /* the lockset didn't already exist */
      if (lockset_table[i] == INVALID_LOCKSET_ENTRY) {

         p = lockset_table[thread_locks[tid]];
         q = &lockset_table[i];

         /* copy the thread's lockset, creating a new list */
         while (p != NULL) {
            new_node = VG_(malloc)(VG_AR_PRIVATE, sizeof(lock_vector));
            new_node->mutex = p->mutex;
            *q = new_node;
            q = &((*q)->next);
            p = p->next;
         }
         (*q) = NULL;

         /* find spot for the new mutex in the new list */
         p = lockset_table[i];
         q = &lockset_table[i];
         while (NULL != p && mutex > p->mutex) {
            p = p->next;
            q = &((*q)->next);
         }


         /* insert new mutex in new list */
         new_node = VG_(malloc)(VG_AR_PRIVATE, sizeof(lock_vector));
         new_node->mutex = mutex;
         new_node->next = p;
         (*q) = new_node;

         p = lockset_table[i];
#if DEBUG_NEW_LOCKSETS
         VG_(printf)("new lockset vector (%d): ", i);
         print_lock_vector(p);
#endif
         
         goto done;

      } else {
         /* If this succeeds, the required vector (with the new mutex added)
          * already exists in the table at position i.  Otherwise, keep
          * looking. */
         if (weird_lock_vector_equals(lockset_table[thread_locks[tid]],
                               lockset_table[i], mutex)) {
            goto done;
         }
      }
      /* if we get to here, table lockset didn't match the new thread
       * lockset, so keep looking */
      i++;
   }

   done:
      /* Update the thread's lock vector */
      thread_locks[tid] = i;
#if DEBUG_LOCKS
      VG_(printf)("tid %u now has lockset %d\n", tid, i);
#endif
}


void eraser_post_mutex_unlock(ThreadId tid, void* void_mutex)
{
   Int i = 0;
   pthread_mutex_t* mutex = (pthread_mutex_t*)void_mutex;
   
#if DEBUG_LOCKS
   VG_(printf)("unlock(%u, %x)\n", tid, mutex);
#endif

   // find the lockset that is the current one minus tid, change thread to use
   // that index.



// SSS: this can easily happen, consider:
//    lock a, lock b, lock c, unlock b
//
// sets seen are {a}, {a,b}, {a,b,c} -- {a,c} isn't there.  Code only
// works if locks/unlocks are done entirely stack-style.

   
   while (True) {
      if (lockset_table[i] == INVALID_LOCKSET_ENTRY || i == LOCKSET_TABLE_SIZE) 
         VG_(panic)("couldn't find diminished lockset on unlock!");

      /* Args are in opposite order to call above, for reverse effect */
      if (weird_lock_vector_equals(lockset_table[i],
                           lockset_table[thread_locks[tid]], mutex))
         break;
      
      i++;
   }

   /* Update the thread's lock vector */
#if DEBUG_LOCKS
   VG_(printf)("tid %u reverts from %d to lockset %d\n", 
               tid, thread_locks[tid], i);
#endif
   thread_locks[tid] = i;
}

/* ---------------------------------------------------------------------
   Checking memory reads and writes
   ------------------------------------------------------------------ */

/* Behaviour on reads and writes:
 *
 *                      VIR          EXCL        SHAR        SH_MOD
 * ----------------------------------------------------------------
 * rd/wr, 1st thread |  -            EXCL        -           -
 * rd, new thread    |  -            SHAR        -           -
 * wr, new thread    |  -            SH_MOD      -           -
 * rd                |  error!       -           SHAR        SH_MOD
 * wr                |  EXCL         -           SH_MOD      SH_MOD
 * ----------------------------------------------------------------
 */
static void dump_around_a(Addr a)
{
   UInt i;
   shadow_word* sword;

   VG_(printf)("NEARBY:\n");
   for (i = a - 12; i <= a + 12; i += 4) {
      sword = get_sword_addr(i); 
      VG_(printf)("    %x -- tid: %u, state: %u\n", i, sword->other, sword->state);
   }
}

static void free_lock_vector(lock_vector *p)
{
   lock_vector* q;
   while (NULL != p) {
      q = p;
      p = p->next;
      VG_(free)(VG_AR_PRIVATE, q);
#if DEBUG_MEM_LOCKSET_CHANGES
      VG_(printf)("free'd   %x\n", q);
#endif
   }
}

/* Builds the intersection, and then unbuilds it if it's already in the table.
 */
static UInt intersect(UInt ia, UInt ib)
{
   Int           i = 0;
   lock_vector*  a = lockset_table[ia];
   lock_vector*  b = lockset_table[ib];
   lock_vector*  new_vector = NULL;
   lock_vector*  new_node;
   lock_vector** prev_ptr = &new_vector;

#if DEBUG_MEM_LOCKSET_CHANGES
   VG_(printf)("Intersecting %d %d:\n", ia, ib);
#endif

   /* Fast case -- when the two are the same */
   if (ia == ib) {
#if DEBUG_MEM_LOCKSET_CHANGES
      VG_(printf)("Fast case -- both the same: %u\n", ia);
      print_lock_vector(a);
#endif
      return ia;
   }

#if DEBUG_MEM_LOCKSET_CHANGES
   print_lock_vector(a);
   print_lock_vector(b);
#endif

   /* Build the intersection of the two lists */
   while (a && b) {
      if (a->mutex == b->mutex) {
         new_node = VG_(malloc)(VG_AR_PRIVATE, sizeof(lock_vector));
#if DEBUG_MEM_LOCKSET_CHANGES
         VG_(printf)("malloc'd %x\n", new_node);
#endif
         new_node->mutex = a->mutex;
         *prev_ptr = new_node;
         prev_ptr = &((*prev_ptr)->next);
         a = a->next;
         b = b->next;
      } else if (a->mutex < b->mutex) {
         a = a->next;
      } else if (a->mutex > b->mutex) {
         b = b->next;
      } else VG_(panic)("STOP PRESS: Laws of arithmetic broken");

      *prev_ptr = NULL;
   }

   /* Now search for it in the table, adding it if not seen before */
   while (True) {
      if (i == LOCKSET_TABLE_SIZE) 
         VG_(panic)("lockset table full -- increase LOCKSET_TABLE_SIZE");

      /* the lockset didn't already exist */
      if (lockset_table[i] == INVALID_LOCKSET_ENTRY) {
#if DEBUG_MEM_LOCKSET_CHANGES || DEBUG_NEW_LOCKSETS
         VG_(printf)("intersection: NEW LOCKSET VECTOR (%d)...\n", i);
#endif
         lockset_table[i] = new_vector;
         goto done;

      } else {
         if (lock_vector_equals(lockset_table[i], new_vector)) {
            free_lock_vector(new_vector);
            goto done;
         }
      }
      i++;
   }
   done:

#if DEBUG_MEM_LOCKSET_CHANGES
   print_lock_vector(lockset_table[i]);
#endif
   /* Check we won't overflow the OTHER_BITS bits of sword->other */
   vg_assert(i < (1 << OTHER_BITS));
   return i;
}

/* Find which word the first and last bytes are in (by shifting out bottom 2
 * bits) then find the difference. */
static __inline__ Int compute_num_words_accessed(Addr a, UInt size) {
   Int x, y, n_words;

   x =  a             >> 2;
   y = (a + size - 1) >> 2;
   n_words = y - x + 1;

   return n_words;
}

#if DEBUG_ACCESSES
   #define DEBUG_STATE(args...)   \
      VG_(printf)("(%u) ", size), \
      VG_(printf)(args)

#else
   #define DEBUG_STATE(args...)
#endif

static void eraser_mem_read(Addr a, UInt size)
{
   shadow_word* sword;
   ThreadId tid = VG_(get_current_tid_1_if_root)();
   Addr     end = a + 4*compute_num_words_accessed(a, size);

   for ( ; a < end; a += 4) {

      sword = get_sword_addr(a);
      if (sword == SEC_MAP_ACCESS) {
         VG_(printf)("read distinguished 2ndary map! 0x%x\n", a);
         continue;
      }

      switch (sword->state) {

      /* This looks like reading of unitialised memory, may be legit.  Eg. 
       * calloc() zeroes its values, so untouched memory may actually be 
       * initialised.   Leave that stuff to Valgrind.  */
      case Vge_Virgin:
         if (TID_INDICATING_NONVIRGIN == sword->other) {
            DEBUG_STATE("Read  VIRGIN --> EXCL:   %8x, %u\n", a, tid);
#if DEBUG_VIRGIN_READS
            dump_around_a(a);
#endif
         } else {
            DEBUG_STATE("Read  SPECIAL --> EXCL:  %8x, %u\n", a, tid);
         }
         sword->state = Vge_Excl;
         sword->other = tid;       /* remember exclusive owner */
         break;

      case Vge_Excl:
         if (tid == sword->other) {
            DEBUG_STATE("Read  EXCL:              %8x, %u\n", a, tid);

         } else {
            DEBUG_STATE("Read  EXCL(%u) --> SHAR:  %8x, %u\n", sword->other, a, tid);
            sword->state = Vge_Shar;
            sword->other = thread_locks[tid];
#if DEBUG_MEM_LOCKSET_CHANGES
            print_lock_vector(lockset_table[sword->other]);
#endif
         }
         break;

      case Vge_Shar:
         DEBUG_STATE("Read  SHAR:              %8x, %u\n", a, tid);
         sword->other = intersect(sword->other, thread_locks[tid]);
         break;

      case Vge_SharMod:
         DEBUG_STATE("Read  SHAR_MOD:          %8x, %u\n", a, tid);
         sword->other = intersect(sword->other, thread_locks[tid]);

         if (lockset_table[sword->other] == NULL) {
            record_eraser_error(tid, a, False /* !is_write */);
            n_eraser_warnings++;
         }
         break;

      default:
         VG_(panic)("Unknown eraser state");
      }
   }
}

static void eraser_mem_write(Addr a, UInt size)
{
   shadow_word* sword;
   ThreadId tid = VG_(get_current_tid_1_if_root)();
   Addr     end = a + 4*compute_num_words_accessed(a, size);

   for ( ; a < end; a += 4) {

      sword = get_sword_addr(a);
      if (sword == SEC_MAP_ACCESS) {
         VG_(printf)("read distinguished 2ndary map! 0x%x\n", a);
         continue;
      }

      switch (sword->state) {
      case Vge_Virgin:
         if (TID_INDICATING_NONVIRGIN == sword->other)
            DEBUG_STATE("Write VIRGIN --> EXCL:   %8x, %u\n", a, tid);
         else
            DEBUG_STATE("Write SPECIAL --> EXCL:  %8x, %u\n", a, tid);
         sword->state = Vge_Excl;
         sword->other = tid;       /* remember exclusive owner */
         break;

      case Vge_Excl:
         if (tid == sword->other) {
            DEBUG_STATE("Write EXCL:              %8x, %u\n", a, tid);
            break;

         } else {
            DEBUG_STATE("Write EXCL(%u) --> SHAR_MOD: %8x, %u\n", sword->other, a, tid);
            sword->state = Vge_SharMod;
            sword->other = thread_locks[tid];
#if DEBUG_MEM_LOCKSET_CHANGES
            print_lock_vector(lockset_table[sword->other]);
#endif
            goto SHARED_MODIFIED;
         }

      case Vge_Shar:
         DEBUG_STATE("Write SHAR --> SHAR_MOD: %8x, %u\n", a, tid);
         sword->state = Vge_SharMod;
         sword->other = intersect(sword->other, thread_locks[tid]);
         goto SHARED_MODIFIED;

      case Vge_SharMod:
         DEBUG_STATE("Write SHAR_MOD:          %8x, %u\n", a, tid);
         sword->other = intersect(sword->other, thread_locks[tid]);
         SHARED_MODIFIED:
         if (lockset_table[sword->other] == NULL) {
            record_eraser_error(tid, a, True /* is_write */);
            n_eraser_warnings++;
         }
         break;

      default:
         VG_(panic)("Unknown eraser state");
      }
   }
}

#undef DEBUG_STATE

/*--------------------------------------------------------------------*/
/*--- Setup                                                        ---*/
/*--------------------------------------------------------------------*/

void SK_(pre_clo_init)(VgNeeds* needs, VgTrackEvents* track)
{
   Int i;

   needs->name                    = "helgrind";
   needs->description             = "a data race detector";

   needs->record_mem_exe_context  = False;
   needs->postpone_mem_reuse      = False;
   needs->debug_info              = True;
   needs->pthread_errors          = True;
   needs->report_errors           = True;
   needs->run_libc_freeres        = False;

   needs->identifies_basic_blocks = False;
   needs->shadow_regs             = False;
   needs->command_line_options    = False;
   needs->client_requests         = False;
   needs->extends_UCode           = False;
   needs->wrap_syscalls           = False;
   needs->sanity_checks           = False;

   VG_(register_compact_helper)((Addr) & eraser_mem_read);
   VG_(register_compact_helper)((Addr) & eraser_mem_write);

   /* Events to track */
   track->new_mem_startup       = & eraser_new_mem_startup;
   track->new_mem_heap          = & eraser_new_mem_heap;
   track->new_mem_stack         = & make_writable;
   track->new_mem_stack_aligned = & make_writable_aligned;
   track->new_mem_stack_signal  = & make_writable;
   track->new_mem_brk           = & make_writable;
   track->new_mem_mmap          = & eraser_set_perms;

   track->copy_mem_heap         = & copy_address_range_state;
   track->change_mem_mprotect   = & eraser_set_perms;

   track->ban_mem_heap          = NULL;
   track->ban_mem_stack         = NULL;

   track->die_mem_heap          = NULL;
   track->die_mem_stack         = NULL;
   track->die_mem_stack_aligned = NULL;
   track->die_mem_stack_signal  = NULL;
   track->die_mem_brk           = NULL;
   track->die_mem_munmap        = NULL;

   track->pre_mem_read          = & eraser_pre_mem_read;
   track->pre_mem_read_asciiz   = & eraser_pre_mem_read_asciiz;
   track->pre_mem_write         = & eraser_pre_mem_write;
   track->post_mem_write        = NULL;

   track->post_mutex_lock       = & eraser_post_mutex_lock;
   track->post_mutex_unlock     = & eraser_post_mutex_unlock;

   /* Init lock table */
   for (i = 0; i < VG_N_THREADS; i++) 
      thread_locks[i] = 0;

   lockset_table[0] = NULL;
   for (i = 1; i < LOCKSET_TABLE_SIZE; i++) 
      lockset_table[i] = INVALID_LOCKSET_ENTRY;

   init_shadow_memory();
}

void SK_(post_clo_init)(void)
{
}

void SK_(fini)(void)
{
#if DEBUG_LOCK_TABLE
    Int i;
    for (i = 0; lockset_table[i] != INVALID_LOCKSET_ENTRY; i++) {
       VG_(printf)("[%2d] = ", i);
       print_lock_vector(lockset_table[i]);
    }
#endif
    VG_(message)(Vg_UserMsg, "%u possible data races found", n_eraser_warnings);
}

/*--------------------------------------------------------------------*/
/*--- end                                              vg_eraser.c ---*/
/*--------------------------------------------------------------------*/
