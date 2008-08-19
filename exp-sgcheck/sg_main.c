
/*--------------------------------------------------------------------*/
/*--- sgcheck: a stack/global array overrun checker.               ---*/
/*---                                                    sg_main.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of SGcheck, a Valgrind tool for checking 
   overruns in stack and global arrays in programs.

   Copyright (C) 2008-2008 OpenWorks Ltd
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
*/

#include "pub_tool_basics.h"

#include "pub_tool_libcbase.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"

#include "pub_tool_tooliface.h"

#include "pub_tool_wordfm.h"
#include "pub_tool_xarray.h"
#include "pub_tool_threadstate.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_machine.h"
#include "pub_tool_options.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_replacemalloc.h"


static void preen_Invars ( Addr a, SizeT len, Bool isHeap ); /*fwds*/


//////////////////////////////////////////////////////////////
//                                                          //
// Basic Stuff                                              //
//                                                          //
//////////////////////////////////////////////////////////////

static inline Bool is_sane_TId ( ThreadId tid )
{
   return tid >= 0 && tid < VG_N_THREADS
          && tid != VG_INVALID_THREADID;
}

static void* pc_malloc ( SizeT n ) {
   void* p;
   tl_assert(n > 0);
   p = VG_(malloc)( n );
   tl_assert(p);
   return p;
}

static void pc_free ( void* p ) {
   tl_assert(p);
   VG_(free)(p);
}


//////////////////////////////////////////////////////////////
//                                                          //
// Management of StackBlocks                                //
//                                                          //
//////////////////////////////////////////////////////////////

/* We maintain a set of XArray* of StackBlocks.  These are never
   freed.  When a new StackBlock vector is acquired from
   VG_(di_get_local_blocks_at_ip), we compare it to the existing set.
   If not present, it is added.  If present, the just-acquired one is
   freed and the copy used.

   This simplifies storage management elsewhere.  It allows us to
   assume that a pointer to an XArray* of StackBlock is valid forever.
   It also means there are no duplicates anywhere, which could be
   important from a space point of view for programs that generate a
   lot of translations, or where translations are frequently discarded
   and re-made.

   Note that we normalise the arrays by sorting the elements according
   to an arbitrary total order, so as to avoid the situation that two
   vectors describe the same set of variables but are not structurally
   identical. */

static inline Bool StackBlock__sane ( StackBlock* fb ) {
   if (fb->name[ sizeof(fb->name)-1 ] != 0)
      return False;
   if (fb->spRel != False && fb->spRel != True)
      return False;
   if (fb->isVec != False && fb->isVec != True)
      return False;
   return True;
}

static Int StackBlock__cmp ( StackBlock* fb1, StackBlock* fb2 ) {
   Int r;
   tl_assert(StackBlock__sane(fb1));
   tl_assert(StackBlock__sane(fb2));
   /* Hopefully the .base test hits most of the time.  For the blocks
      associated with any particular instruction, if the .base values
      are the same then probably it doesn't make sense for the other
      fields to be different.  But this is supposed to be a completely
      general structural total order, so we have to compare everything
      anyway. */
   if (fb1->base < fb2->base) return -1;
   if (fb1->base > fb2->base) return 1;
   /* compare sizes */
   if (fb1->szB < fb2->szB) return -1;
   if (fb1->szB > fb2->szB) return 1;
   /* compare sp/fp flag */
   if (fb1->spRel < fb2->spRel) return -1;
   if (fb1->spRel > fb2->spRel) return 1;
   /* compare is/is-not array-typed flag */
   if (fb1->isVec < fb2->isVec) return -1;
   if (fb1->isVec > fb2->isVec) return 1;
   /* compare the name */
   r = VG_(strcmp)(fb1->name, fb2->name);
   return r;
}

/* Generate an arbitrary total ordering on vectors of StackBlocks. */
static Word StackBlocks__cmp ( XArray* fb1s, XArray* fb2s ) {
   Int  r;
   Word i;
   Word n1 = VG_(sizeXA)( fb1s );
   Word n2 = VG_(sizeXA)( fb2s );
   Word n  = n1 > n2 ? n1 : n2;  /* max(n1,n2) */
   for (i = 0; i < n; i++) {
      StackBlock *fb1, *fb2;
      if (i >= n1) {
         /* fb1s ends first, and all previous entries identical. */
         tl_assert(i < n2);
         return -1;
      }
      if (i >= n2) {
         /* fb2s ends first, and all previous entries identical. */
         tl_assert(i < n1);
         return 1;
      }
      tl_assert(i < n1 && i < n2);
      fb1 = VG_(indexXA)( fb1s, i );
      fb2 = VG_(indexXA)( fb2s, i );
      r = StackBlock__cmp( fb1, fb2 );
      if (r != 0) return r;
   }
   tl_assert(n1 == n2);
   return 0;
}


/* ---------- The StackBlock vector cache ---------- */

static WordFM* /* XArray* of StackBlock -> nothing */
       frameBlocks_set = NULL;

static void init_StackBlocks_set ( void )
{
   tl_assert(!frameBlocks_set);
   frameBlocks_set = VG_(newFM)( pc_malloc, pc_free, 
                                 (Word(*)(UWord,UWord))StackBlocks__cmp );
   tl_assert(frameBlocks_set);
}

/* Find the given StackBlock-vector in our collection thereof.  If
   found, deallocate the supplied one, and return the address of the
   copy.  If not found, add the supplied one to our collection and
   return its address. */
static XArray* /* of StackBlock */
       StackBlocks__find_and_dealloc__or_add
          ( XArray* /* of StackBlock */ orig )
{
   UWord key, val;

   /* First, normalise, as per comments above. */
   VG_(setCmpFnXA)( orig, (Int(*)(void*,void*))StackBlock__cmp );
   VG_(sortXA)( orig );

   /* Now, do we have it already? */
   if (VG_(lookupFM)( frameBlocks_set, &key, &val, (UWord)orig )) {
      /* yes */
      tl_assert(val == 0);
      tl_assert(key != (UWord)orig);
      VG_(deleteXA)(orig);
      return (XArray*)key;
   } else {
      /* no */
      VG_(addToFM)( frameBlocks_set, (UWord)orig, 0 );
      return orig;
   }
}

/* Top level function for getting the StackBlock vector for a given
   instruction. */

static XArray* /* of StackBlock */ get_StackBlocks_for_IP ( Addr ip )
{
   XArray* blocks = VG_(di_get_stack_blocks_at_ip)( ip, False/*!arrays only*/ );
   tl_assert(blocks);
   return StackBlocks__find_and_dealloc__or_add( blocks );
}


//////////////////////////////////////////////////////////////
//                                                          //
// The Global Block Interval Tree                           //
//                                                          //
//////////////////////////////////////////////////////////////

/* This tree holds all the currently known-about globals.  We must
   modify it at each mmap that results in debuginfo being read, and at
   each munmap, as the latter will cause globals to disappear.  At
   each munmap, we must also prune the Invars, since munmaps may cause
   GlobalBlocks to disappear, and so the Invars may no longer mention
   them. */

/* Implement an interval tree, containing GlobalBlocks.  The blocks
   must all be non-zero sized and may not overlap.  The access
   functions maintain that invariant.

   Storage management: GlobalBlocks in the tree are copies of ones
   presented as args to add_GlobalBlock.  The originals are never
   added to the tree.  del_GlobalBlocks_in_range frees up the storage
   allocated by add_GlobalBlock. */

/* The tree */
static WordFM* globals = NULL; /* WordFM GlobalBlock* void */

static Word cmp_intervals_GlobalBlock ( GlobalBlock* gb1, GlobalBlock* gb2 )
{
   tl_assert(gb1 && gb1->szB > 0);
   tl_assert(gb2 && gb2->szB > 0);
   if (gb1->addr + gb1->szB <= gb2->addr) return -1;
   if (gb2->addr + gb2->szB <= gb1->addr) return 1;
   return 0;
}

static void init_globals ( void )
{
   tl_assert(!globals);
   globals = VG_(newFM)( pc_malloc, pc_free,
                         (Word(*)(UWord,UWord))cmp_intervals_GlobalBlock );
   tl_assert(globals);
}


/* Find the block containing 'a', if possible.  Returned pointer is
   only transiently valid; it will become invalid at the next global
   mapping or unmapping operation. */
static GlobalBlock* find_GlobalBlock_containing ( Addr a )
{
   UWord oldK, oldV;
   GlobalBlock key;
   key.addr = a;
   key.szB  = 1;
   if (VG_(lookupFM)( globals, &oldK, &oldV, (UWord)&key )) {
      GlobalBlock* res = (GlobalBlock*)oldK;
      tl_assert(oldV == 0);
      tl_assert(res->szB > 0);
      tl_assert(res->addr <= a && a < res->addr + res->szB);
      return res;
   } else {
      return NULL;
   }
}


/* Add a block to the collection.  Presented block is not stored
   directly; instead a copy is made and stored.  If the block overlaps
   an existing block (it should not, but we need to be robust to such
   eventualities) it is merged with existing block(s), so as to
   preserve the no-overlap property of the tree as a whole. */
static void add_GlobalBlock ( GlobalBlock* gbOrig )
{
   UWord keyW, valW;
   GlobalBlock* gb;
   tl_assert(gbOrig && gbOrig->szB > 0);
   gb = pc_malloc( sizeof(GlobalBlock) );
   *gb = *gbOrig;

   /* Dealing with overlaps.  One possibility is to look up the entire
      interval to be added.  If we get something back, it overlaps an
      existing interval; then delete the existing interval, merge it
      into the one to be added, and repeat, until the to-be added
      interval really doesn't intersect any existing interval. */

   while (VG_(lookupFM)( globals, &keyW, &valW, (UWord)gb )) {
      tl_assert(valW == 0);
      /* keyW is the overlapping key.  Pull it out of the tree, merge
         into 'gb', free keyW, complain to the user, repeat. */
      tl_assert(0);
   }

   VG_(addToFM)(globals, (UWord)gb, (UWord)0);
}


/* Remove all blocks from the tree intersecting [a,a+len), and release
   associated storage.  One way to do it is to simply look up the
   interval, and if something comes back, delete it on the basis that
   it must intersect the interval.  Keep doing this until the lookup
   finds nothing.  Returns a Bool indicating whether any blocks
   did actually intersect the range. */
static Bool del_GlobalBlocks_in_range ( Addr a, SizeT len )
{
   UWord oldK, oldV;
   GlobalBlock key;
   Bool foundAny = False;

   tl_assert(len > 0);
   key.addr = a;
   key.szB  = len;
   while (VG_(delFromFM)( globals, &oldK, &oldV, (UWord)&key )) {
      GlobalBlock* old;
      tl_assert(oldV == 0);
      old = (GlobalBlock*)oldK;
      /* 'old' will be removed.  Preen the Invars now? */
      pc_free(old);
      foundAny = True;
   }
   return foundAny;
}


//////////////////////////////////////////////////////////////

static void acquire_globals ( ULong di_handle )
{
   Word n, i;
   XArray* /* of GlobalBlock */ gbs;

   if (0) VG_(printf)("ACQUIRE GLOBALS %llu\n", di_handle );
   gbs = VG_(di_get_global_blocks_from_dihandle)
            (di_handle, False/*!arrays only*/);
   if (0) VG_(printf)("   GOT %ld globals\n", VG_(sizeXA)( gbs ));

   n = VG_(sizeXA)( gbs );
   for (i = 0; i < n; i++) {
      GlobalBlock* gb = VG_(indexXA)( gbs, i );
      VG_(printf)("   new Global size %2lu at %#lx:  %s %s\n", 
                  gb->szB, gb->addr, gb->soname, gb->name );
      tl_assert(gb->szB > 0);
      /* Add each global to the map.  We can present them
         indiscriminately to add_GlobalBlock, since that adds copies
         of presented blocks, not the original.  This is important
         because we are just about to delete the XArray in which we
         received these GlobalBlocks. */
      add_GlobalBlock( gb );
   }

   VG_(deleteXA)( gbs );
}


/* We only intercept these two because we need to see any di_handles
   that might arise from the mappings/allocations. */
static void sg_new_mem_mmap( Addr a, SizeT len,
                             Bool rr, Bool ww, Bool xx, ULong di_handle )
{
   if (di_handle > 0)
      acquire_globals(di_handle);
}
static void sg_new_mem_startup( Addr a, SizeT len,
                             Bool rr, Bool ww, Bool xx, ULong di_handle )
{
   if (di_handle > 0)
      acquire_globals(di_handle);
}
static void sg_die_mem_munmap ( Addr a, SizeT len )
{
   Bool debug = 0||False;
   Bool overlap = False;
   if (debug) VG_(printf)("MUNMAP %#lx %lu\n", a, len );
   if (len == 0)
      return;

   overlap = del_GlobalBlocks_in_range(a, len);
   if (!overlap)
      return;

   /* Ok, the range contained some blocks.  Therefore we'll need to
      visit all the Invars in all the thread shadow stacks, and
      convert all Inv_Global{S,V} entries that intersect [a,a+len) to
      Inv_Unknown. */
   tl_assert(len > 0);
   preen_Invars( a, len, False/*!isHeap*/ );
}


//////////////////////////////////////////////////////////////
//                                                          //
// The Heap Block Interval Tree                             //
//                                                          //
//////////////////////////////////////////////////////////////

/* This tree holds all the currently known-about heap blocks.  We must
   modify it at each malloc/free, and prune the Invars when freeing
   blocks (since they disappear, the Invars may no longer mention
   them). */

/* Implement an interval tree, containing HeapBlocks.  The blocks must
   all be non-zero sized and may not overlap, although if they do
   overlap that must constitute a bug in our malloc/free
   implementation, and so we might as well just assert.

   There's a nasty kludge.  In fact we must be able to deal with zero
   sized blocks, since alloc_mem_heap/free_mem_heap/pc_replace_malloc
   use the blocks stored to keep track of what blocks the client has
   allocated, so there's no avoiding the requirement of having one
   block in the tree for each client allocated block, even for
   zero-sized client blocks.

   The kludge is: have two size fields.  One is the real size
   (.realSzB) and can be zero.  The other (.fakeSzB) is used, along
   with .addr to provide the ordering induced by
   cmp_intervals_HeapBlock.  .fakeSzB is the same as .realSzB except
   in the single case where .realSzB is zero, in which case .fakeSzB
   is 1.  This works because the allocator won't allocate two zero
   sized blocks at the same location (ANSI C disallows this) and so,
   from an ordering point of view, it's safe treat zero sized blocks
   as blocks of size 1.  However, we need to keep the real un-kludged
   size around too (as .realSzB), so that
   alloc_mem_heap/free_mem_heap/pc_replace_malloc and also
   classify_block have correct information.

   Storage management: HeapBlocks in the tree are copies of ones
   presented as args to add_HeapBlock.  The originals are never
   added to the tree.  del_HeapBlocks_in_range frees up the storage
   allocated by add_GlobalBlock. */

typedef
   struct {
      Addr  addr;
      SizeT fakeSzB;
      SizeT realSzB;
   }
   HeapBlock;

/* the tree */
static WordFM* heap = NULL; /* WordFM HeapBlock* void */

static Word cmp_intervals_HeapBlock ( HeapBlock* hb1, HeapBlock* hb2 )
{
   tl_assert(hb1);
   tl_assert(hb2);
   tl_assert(hb1->fakeSzB > 0);
   tl_assert(hb2->fakeSzB > 0);
   if (hb1->addr + hb1->fakeSzB <= hb2->addr) return -1;
   if (hb2->addr + hb2->fakeSzB <= hb1->addr) return 1;
   return 0;
}


static void init_heap ( void )
{
   tl_assert(!heap);
   heap = VG_(newFM)( pc_malloc, pc_free,
                      (Word(*)(UWord,UWord))cmp_intervals_HeapBlock );
   tl_assert(heap);
}


/* Find the heap block containing 'a', if possible.  Returned pointer
   is only transiently valid; it will become invalid at the next
   client malloc or free operation. */
static HeapBlock* find_HeapBlock_containing ( Addr a )
{
   UWord oldK, oldV;
   HeapBlock key;
   key.addr    = a;
   key.fakeSzB = 1;
   key.realSzB = 0; /* unused, but initialise it anyway */
   if (VG_(lookupFM)( heap, &oldK, &oldV, (UWord)&key )) {
      HeapBlock* res = (HeapBlock*)oldK;
      tl_assert(oldV == 0);
      tl_assert(res->fakeSzB > 0);
      tl_assert(res->addr <= a && a < res->addr + res->fakeSzB);
      /* Now, just one more thing.  If the real size is in fact zero
         then 'a' can't fall within it.  No matter what 'a' is.  Hence: */
      if (res->realSzB == 0) {
         tl_assert(res->fakeSzB == 1);
         return NULL;
      }
      /* Normal case. */
      return res;
   } else {
      return NULL;
   }
}


/* Add a block to the collection.  If the block overlaps an existing
   block (it should not, but we need to be robust to such
   eventualities) we simply assert, as that is probably a result of a
   bug in our malloc implementation.  (although could be due to buggy
   custom allocators?)  In any case we must either assert or somehow
   (as per GlobalBlocks) avoid overlap, so as to preserve the
   no-overlap property of the tree as a whole. */
static void add_HeapBlock ( Addr addr, SizeT realSzB )
{
   UWord      keyW, valW;
   HeapBlock* hb;

   SizeT fakeSzB = realSzB == 0  ? 1  : realSzB;
   tl_assert(fakeSzB > 0);

   tl_assert(addr);
   hb = pc_malloc( sizeof(HeapBlock) );
   hb->addr    = addr;
   hb->fakeSzB = fakeSzB;
   hb->realSzB = realSzB;
   /* Check there's no overlap happening. */
   while (VG_(lookupFM)( heap, &keyW, &valW, (UWord)hb )) {
      tl_assert(valW == 0);
      /* keyW is the overlapping HeapBlock*.  Need to handle this
         case, as per comment above. */
      tl_assert(0);
   }

   VG_(addToFM)(heap, (UWord)hb, (UWord)0);
}


/* Delete a heap block at guest address 'addr' from the tree.  Ignore
   if there is no block beginning exactly at 'addr' (means the guest
   is handing invalid pointers to free() et al).  Returns the True if
   found, in which case the block's size is written to *szB.  The
   shadow block (HeapBlock) is freed, but the payload (what .addr
   points at) are not. */
static Bool del_HeapBlock_at ( SizeT* szB, Addr addr )
{
   Bool      b;
   UWord     oldK, oldV;
   HeapBlock key, *hb;
   
   hb = find_HeapBlock_containing(addr);
   if (!hb) return False;
   if (hb->addr != addr) return False;

   key.addr    = addr;
   key.fakeSzB = 1;
   key.realSzB = 0; /* unused, but initialise it anyway */
   b = VG_(delFromFM)( heap, &oldK, &oldV, (UWord)&key );
   tl_assert(b); /* we just looked it up, so deletion must succeed */
   tl_assert(oldV == 0);

   hb = (HeapBlock*)oldK;
   tl_assert(hb);
   tl_assert(hb->addr == addr);

   *szB = hb->realSzB;
   pc_free(hb);
   return True;
}


//////////////////////////////////////////////////////////////
static
void* alloc_mem_heap ( ThreadId tid,
                       SizeT size, SizeT alignment, Bool is_zeroed )
{
   Addr p;
   if ( ((SSizeT)size) < 0)
      return NULL;
   p = (Addr)VG_(cli_malloc)(alignment, size);
   if (p == 0)
      return NULL;
   if (is_zeroed)
      VG_(memset)((void*)p, 0, size);
   add_HeapBlock( p, size );
   return (void*)p;
}

static void free_mem_heap ( ThreadId tid, Addr p )
{
   SizeT old_size = 0;
   Bool  found = del_HeapBlock_at( &old_size, p );
   if (found) {
      VG_(cli_free)( (void*)p );
      if (old_size > 0)
         preen_Invars( p, old_size, True/*isHeap*/ );
   }
}

static void* pc_replace_malloc ( ThreadId tid, SizeT n ) {
   return alloc_mem_heap ( tid, n, VG_(clo_alignment),
                                   /*is_zeroed*/False );
}

static void* pc_replace___builtin_new ( ThreadId tid, SizeT n ) {
   return alloc_mem_heap ( tid, n, VG_(clo_alignment),
                                   /*is_zeroed*/False );
}

static void* pc_replace___builtin_vec_new ( ThreadId tid, SizeT n ) {
   return alloc_mem_heap ( tid, n, VG_(clo_alignment),
                                   /*is_zeroed*/False );
}

static void* pc_replace_memalign ( ThreadId tid, SizeT align, SizeT n ) {
   return alloc_mem_heap ( tid, n, align,
                                   /*is_zeroed*/False );
}

static void* pc_replace_calloc ( ThreadId tid, SizeT nmemb, SizeT size1 ) {
   return alloc_mem_heap ( tid, nmemb*size1, VG_(clo_alignment),
                                /*is_zeroed*/True );
}

static void pc_replace_free ( ThreadId tid, void* p ) {
   free_mem_heap(tid, (Addr)p);
}

static void pc_replace___builtin_delete ( ThreadId tid, void* p ) {
   free_mem_heap(tid, (Addr)p);
}

static void pc_replace___builtin_vec_delete ( ThreadId tid, void* p ) {
   free_mem_heap(tid, (Addr)p);
}

static void* pc_replace_realloc ( ThreadId tid, void* p_old, SizeT new_size )
{
   Addr p_new;

   /* First try and find the block. */
   SizeT old_size = 0;
   Bool  found    = del_HeapBlock_at( &old_size, (Addr)p_old );

   if (!found)
      return NULL;

   if (old_size > 0)
      preen_Invars( (Addr)p_old, old_size, True/*isHeap*/ );

   if (new_size <= old_size) {
      /* new size is smaller: allocate, copy from old to new */
      p_new = (Addr)VG_(cli_malloc)(VG_(clo_alignment), new_size);
      VG_(memcpy)((void*)p_new, p_old, new_size);
   } else {
      /* new size is bigger: allocate, copy from old to new */
      p_new = (Addr)VG_(cli_malloc)(VG_(clo_alignment), new_size);
      VG_(memcpy)((void*)p_new, p_old, old_size);
   }

   VG_(cli_free)( (void*)p_old );
   add_HeapBlock( p_new, new_size );
   return (void*)p_new;
}


//////////////////////////////////////////////////////////////
//                                                          //
// Invar                                                    //
//                                                          //
//////////////////////////////////////////////////////////////

/* An invariant, as resulting from watching the destination of a
   memory referencing instruction.  Initially is Inv_Unset until the
   instruction makes a first access. */

typedef
   enum {
      Inv_Unset=1,              /* not established yet */
      Inv_Unknown,              /* unknown location */
      Inv_StackS,  Inv_StackV,  /* scalar/vector stack block */ 
      Inv_GlobalS, Inv_GlobalV, /* scalar/vector global block */
      Inv_Heap                  /* a block in the heap */
   }
   InvarTag;

typedef
   struct {
      InvarTag tag;
      union {
         struct {
         } Unset;
         struct {
         } Unknown;
         struct {
            /* EQ    */ UWord framesBack;
            /* EQ    */ UWord fbIndex;
            /* EXPO  */ HChar name[16]; /* asciiz */
            /* ReVal */ Addr  start;
            /* ReVal */ SizeT len;
         } Stack;
         struct {
            /* EQ */    HChar name[16]; /* asciiz */
            /* EQ */    HChar soname[16]; /* asciiz */
            /* ReVal */ Addr  start;
            /* ReVal */ SizeT len;
         } Global;
         struct {
            /* EQ, ReVal */ Addr  start;
            /* ReVal */     SizeT len;
         } Heap;
      }
      Inv;
   }
   Invar;

/* Compare two Invars for equality, based on the EQ fields in the
   declaration above. */
static Bool eq_Invar ( Invar* i1, Invar* i2 )
{
   tl_assert(i1->tag != Inv_Unset);
   tl_assert(i2->tag != Inv_Unset);
   if (i1->tag != i2->tag)
      return False;
   switch (i1->tag) {
      case Inv_Unknown:
         return True;
      case Inv_StackS:
      case Inv_StackV:
         return i1->Inv.Stack.framesBack == i2->Inv.Stack.framesBack
                && i1->Inv.Stack.fbIndex == i2->Inv.Stack.fbIndex;
      case Inv_GlobalS:
      case Inv_GlobalV:
         tl_assert(i1->Inv.Global.name[
                      sizeof(i1->Inv.Global.name)-1 ] == 0);
         tl_assert(i2->Inv.Global.name[
                      sizeof(i2->Inv.Global.name)-1 ] == 0);
         tl_assert(i1->Inv.Global.soname[
                      sizeof(i1->Inv.Global.soname)-1 ] == 0);
         tl_assert(i2->Inv.Global.soname[
                      sizeof(i2->Inv.Global.soname)-1 ] == 0);
         return
            0==VG_(strcmp)(i1->Inv.Global.name, i2->Inv.Global.name)
            && 0==VG_(strcmp)(i1->Inv.Global.soname, i2->Inv.Global.soname);
      case Inv_Heap:
         return i1->Inv.Heap.start == i2->Inv.Heap.start
                && i1->Inv.Heap.len == i2->Inv.Heap.len;
      default:
         tl_assert(0);
   }
   /*NOTREACHED*/
   tl_assert(0);
}

/* Print selected parts of an Invar, suitable for use in error
   messages. */
static void show_Invar( HChar* buf, Word nBuf, Invar* inv )
{
   HChar* str;
   tl_assert(nBuf >= 128);
   buf[0] = 0;
   switch (inv->tag) {
      case Inv_Unknown:
         VG_(sprintf)(buf, "%s", "unknown");
         break;
      case Inv_StackS:
      case Inv_StackV:
         tl_assert(inv->Inv.Stack.name[sizeof(inv->Inv.Stack.name)-1] == 0);
         str = inv->tag == Inv_StackS ? "non-array" : "array";
         if (inv->Inv.Stack.framesBack == 0) {
            VG_(sprintf)(buf, "stack %s \"%s\" in this frame",
                         str, inv->Inv.Stack.name );
         } else {
            VG_(sprintf)(buf, "stack %s \"%s\" in frame %lu back from here",
                         str, inv->Inv.Stack.name,
                              inv->Inv.Stack.framesBack );
         }
         break;
      case Inv_GlobalS:
      case Inv_GlobalV:
         str = inv->tag == Inv_GlobalS ? "non-array" : "array";
         VG_(sprintf)(buf, "global %s \"%s\" in object with soname \"%s\"",
                      str, inv->Inv.Global.name, inv->Inv.Global.soname );
         break;
      case Inv_Heap:
         VG_(sprintf)(buf, "%s", "heap block");
         break;
      case Inv_Unset:
         VG_(sprintf)(buf, "%s", "Unset!");
         break;
      default:
         tl_assert(0);
   }
}


//////////////////////////////////////////////////////////////
//                                                          //
// StackFrame                                               //
//                                                          //
//////////////////////////////////////////////////////////////

static ULong stats__total_accesses   = 0;
static ULong stats__reval_Stack      = 0;
static ULong stats__reval_Global     = 0;
static ULong stats__reval_Heap       = 0;
static ULong stats__classify_Stack   = 0;
static ULong stats__classify_Global  = 0;
static ULong stats__classify_Heap    = 0;
static ULong stats__classify_Unknown = 0;
static ULong stats__Invars_preened   = 0;
static ULong stats__Invars_changed   = 0;

/* A dynamic instance of an instruction */
typedef
   struct {
      /* IMMUTABLE */
      Addr    insn_addr; /* NB! zero means 'not in use' */
      XArray* blocks; /* XArray* of StackBlock */
      /* MUTABLE */
      Invar invar;
   }
   IInstance;


typedef
   struct {
      /* The sp when the frame was created, so we know when to get rid
         of it. */
      Addr creation_sp;
      /* Information for each memory referencing instruction, for this
         instantiation of the function.  The iinstances array is
         operated as a simple linear-probe hash table, which is
         dynamically expanded as necessary.  Once critical thing is
         that an IInstance with a .insn_addr of zero is interpreted to
         mean that hash table slot is unused.  This means we can't
         store an IInstance for address zero. */
      IInstance* htab;
      UWord      htab_size; /* size of hash table, MAY ONLY BE A POWER OF 2 */
      UWord      htab_used; /* number of hash table slots currently in use */
      /* If this frame is currently making a call, then the following
         are relevant. */
      Addr sp_at_call;
      Addr fp_at_call;
      XArray* /* of StackBlock */ blocks_at_call;
   }
   StackFrame;


/* ShadowStack == XArray of StackFrame */


static XArray* shadowStacks[VG_N_THREADS];

static void shadowStacks_init ( void )
{
   Int i;
   for (i = 0; i < VG_N_THREADS; i++) {
      shadowStacks[i] = NULL;
   }
}


/* Move this somewhere else? */
/* Visit all Invars in the entire system.  If 'isHeap' is True, change
   all Inv_Heap Invars that intersect [a,a+len) to Inv_Unknown.  If
   'isHeap' is False, do the same but to the Inv_Global{S,V} Invars
   instead. */
inline
static Bool rangesOverlap ( Addr a1, SizeT n1, Addr a2, SizeT n2 ) {
   tl_assert(n1 > 0 && n2 > 0);
   if (a1 + n1 < a2) return False;
   if (a2 + n2 < a1) return False;
   return True;
}

__attribute__((noinline))
static void preen_Invar ( Invar* inv, Addr a, SizeT len, Bool isHeap )
{
   stats__Invars_preened++;
   tl_assert(len > 0);
   tl_assert(inv);
   switch (inv->tag) {
      case Inv_Heap:
         tl_assert(inv->Inv.Heap.len > 0);
         if (isHeap && rangesOverlap(a, len, inv->Inv.Heap.start,
                                             inv->Inv.Heap.len)) {
            inv->tag = Inv_Unknown;
            stats__Invars_changed++;
         }
         break;
      case Inv_GlobalS:
      case Inv_GlobalV:
         tl_assert(inv->Inv.Global.len > 0);
         if ((!isHeap)
             && rangesOverlap(a, len, inv->Inv.Global.start,
                                      inv->Inv.Global.len)) {
            inv->tag = Inv_Unknown;
            stats__Invars_changed++;
         }
         break;
      case Inv_StackS:
      case Inv_StackV:
      case Inv_Unknown:
         break;
      default: tl_assert(0);
   }
}

__attribute__((noinline))
static void preen_Invars ( Addr a, SizeT len, Bool isHeap )
{
   Int         i;
   Word        ixFrames, nFrames;
   UWord       u;
   XArray*     stack; /* XArray* of StackFrame */
   StackFrame* frame;
   tl_assert(len > 0);
   for (i = 0; i < VG_N_THREADS; i++) {
      stack = shadowStacks[i];
      if (!stack)
         continue;
      nFrames = VG_(sizeXA)( stack );
      for (ixFrames = 0; ixFrames < nFrames; ixFrames++) {
         UWord xx = 0; /* sanity check only; count of used htab entries */
         frame = VG_(indexXA)( stack, ixFrames );
         tl_assert(frame->htab);
         for (u = 0; u < frame->htab_size; u++) {
            IInstance* ii = &frame->htab[u];
            if (ii->insn_addr == 0)
               continue; /* not in use */
            preen_Invar( &ii->invar, a, len, isHeap );
            xx++;           
         }
         tl_assert(xx == frame->htab_used);
      }
   }
}


__attribute__((noinline))
static void initialise_hash_table ( StackFrame* sf )
{
   UWord i;
   sf->htab_size = 4; /* initial hash table size */
   sf->htab = pc_malloc(sf->htab_size * sizeof(IInstance));
   tl_assert(sf->htab);
   sf->htab_used = 0;
   for (i = 0; i < sf->htab_size; i++)
      sf->htab[i].insn_addr = 0; /* NOT IN USE */
}


__attribute__((noinline))
static void resize_hash_table ( StackFrame* sf )
{
   UWord     i, j, ix, old_size, new_size;
   IInstance *old_htab, *new_htab, *old;

   tl_assert(sf && sf->htab);
   old_size = sf->htab_size;
   new_size = 2 * old_size;
   old_htab = sf->htab;
   new_htab = pc_malloc( new_size * sizeof(IInstance) );
   for (i = 0; i < new_size; i++) {
      new_htab[i].insn_addr = 0; /* NOT IN USE */
   }
   for (i = 0; i < old_size; i++) {
      old = &old_htab[i];
      if (old->insn_addr == 0 /* NOT IN USE */)
         continue;
      ix = (old->insn_addr >> 0) & (new_size - 1);
      /* find out where to put this, in the new table */
      j = new_size;
      while (1) {
         if (new_htab[ix].insn_addr == 0)
            break;
         /* This can't ever happen, because it would mean the new
            table is full; that isn't allowed -- even the old table is
            only allowed to become half full. */
         tl_assert(j > 0);
         j--;
         ix++; if (ix == new_size) ix = 0;
      }
      /* copy the old entry to this location */
      tl_assert(ix < new_size);
      tl_assert(new_htab[ix].insn_addr == 0);
      new_htab[ix] = *old;
      tl_assert(new_htab[ix].insn_addr != 0);
   }
   /* all entries copied; free old table. */
   pc_free(old_htab);
   sf->htab = new_htab;
   sf->htab_size = new_size;
   /* check sf->htab_used is correct.  Optional and a bit expensive
      but anyway: */
   j = 0;
   for (i = 0; i < new_size; i++) {
     if (new_htab[i].insn_addr != 0) {
       j++;
     }
   }
   tl_assert(j == sf->htab_used);
   if (0) VG_(printf)("resized tab for SF %p to %lu\n", sf, new_size);
}


__attribute__((noinline))
static IInstance* find_or_create_IInstance (
                     StackFrame* sf, 
                     Addr ip,
                     XArray* /* StackBlock */ ip_frameblocks
                  )
{
   UWord i, ix;
  start_over:
   tl_assert(sf);
   tl_assert(sf->htab);

   if (0) VG_(printf)("XXX ip %#lx size %lu used %lu\n",
                      ip, sf->htab_size, sf->htab_used);
   tl_assert(2 * sf->htab_used <= sf->htab_size);
  
   ix = (ip >> 0) & (sf->htab_size - 1);
   i = sf->htab_size;
   while (1) {
      if (sf->htab[ix].insn_addr == ip)
         return &sf->htab[ix];
      if (sf->htab[ix].insn_addr == 0)
         break;
      /* If i ever gets to zero and we have found neither what we're
         looking for nor an empty slot, the table must be full.  Which
         isn't possible -- we monitor the load factor to ensure it
         doesn't get above say 50%; if that ever does happen the table
         is resized. */
      tl_assert(i > 0);
      i--;
      ix++;
      if (ix == sf->htab_size) ix = 0;
   }

   /* So now we've found a free slot at ix, and we can use that.
      Except, first check if we need to resize the table.  If so,
      resize it, and start all over again. */
   tl_assert(sf->htab[ix].insn_addr == 0);
   if (2 * sf->htab_used >= 1 * sf->htab_size) {
      resize_hash_table(sf);
      goto start_over;
   }

   /* Add a new record in this slot. */
   tl_assert(ip != 0); /* CAN'T REPRESENT THIS */
   sf->htab[ix].insn_addr = ip;
   sf->htab[ix].blocks    = ip_frameblocks;
   sf->htab[ix].invar.tag = Inv_Unset;
   sf->htab_used++;
   return &sf->htab[ix];
}


__attribute__((noinline))
static Bool find_in_StackBlocks ( /*OUT*/UWord*  ix,
                                  /*OUT*/Bool*   isVec,
                                  /*OUT*/Addr*   blockEA,
                                  /*OUT*/SizeT*  blockSzB,
                                  /*OUT*/HChar** name,
                                  Addr ea, Addr sp, Addr fp,
                                  UWord szB, XArray* blocks )
{
   Word i, n;
   OffT delta_FP = ea - fp;
   OffT delta_SP = ea - sp;
   tl_assert(szB > 0 && szB <= 512);
   n = VG_(sizeXA)( blocks );
   for (i = 0; i < n; i++) {
      OffT delta;
      StackBlock* block = VG_(indexXA)( blocks, i );
      delta = block->spRel ? delta_SP : delta_FP;
      { Word w1 = block->base;
        Word w2 = delta;
        Word w3 = (Word)( ((UWord)delta) + ((UWord)szB) );
        Word w4 = (Word)( ((UWord)block->base) + ((UWord)block->szB) );
        if (w1 <= w2 && w3 <= w4) {
           *ix       = i;
           *isVec    = block->isVec;
           *blockEA  = block->base + (block->spRel ? sp : fp);
           *blockSzB = block->szB;
           *name     = &block->name[0];
           return True;
        }
      }
   }
   return False;
}


/* Try to classify the block into which a memory access falls, and
   write the result in 'inv'.  This writes all fields of 'inv',
   including, importantly the ReVal (revalidation) fields. */
__attribute__((noinline)) 
static void classify_address ( /*OUT*/Invar* inv,
                               ThreadId tid,
                               Addr ea, Addr sp, Addr fp,
                               UWord szB,
                               XArray* /* of StackBlock */ thisInstrBlocks,
                               XArray* /* of StackFrame */ thisThreadFrames )
{
   tl_assert(szB > 0);
   /* First, look in the stack blocks accessible in this instruction's
      frame. */
   { 
     UWord  ix;
     Bool   isVec;
     Addr   blockEA;
     SizeT  blockSzB;
     HChar* name;
     Bool   b = find_in_StackBlocks(
                   &ix, &isVec, &blockEA, &blockSzB, &name,
                   ea, sp, fp, szB, thisInstrBlocks
                );
     if (b) {
        SizeT nameSzB = sizeof(inv->Inv.Stack.name);
        inv->tag = isVec ? Inv_StackV : Inv_StackS;
        inv->Inv.Stack.framesBack = 0;
        inv->Inv.Stack.fbIndex    = ix;
        inv->Inv.Stack.start = blockEA;
        inv->Inv.Stack.len   = blockSzB;
        VG_(memcpy)( &inv->Inv.Stack.name[0], name, nameSzB );
        inv->Inv.Stack.name[ nameSzB-1 ] = 0;
        stats__classify_Stack++;
        return;
     }
   }
   /* Perhaps it's a heap block? */
   { HeapBlock* hb = find_HeapBlock_containing(ea);
     if (hb) {
        /* it's not possible for find_HeapBlock_containing to
           return a block of zero size.  Hence: */
        tl_assert(hb->realSzB > 0);
        tl_assert(hb->fakeSzB == hb->realSzB);
     }
     if (hb && !rangesOverlap(ea, szB, hb->addr, hb->realSzB))
        hb = NULL;
     if (hb) {
        inv->tag            = Inv_Heap;
        inv->Inv.Heap.start = hb->addr;
        inv->Inv.Heap.len   = hb->realSzB;
        stats__classify_Heap++;
        return;
     }
   }
   /* Not in a stack block.  Try the global pool. */
   { GlobalBlock* gb2 = find_GlobalBlock_containing(ea);
     /* We know that [ea,ea+1) is in the block, but we need to
        restrict to the case where the whole access falls within
        it. */
     if (gb2 && !rangesOverlap(ea, szB, gb2->addr, gb2->szB)) {
        gb2 = NULL;
     }
     if (gb2) {
        inv->tag = gb2->isVec ? Inv_GlobalV : Inv_GlobalS;
        tl_assert(sizeof(gb2->name) == sizeof(inv->Inv.Global.name));
        tl_assert(sizeof(gb2->soname) == sizeof(inv->Inv.Global.soname));
        VG_(memcpy)( &inv->Inv.Global.name[0],
                     gb2->name, sizeof(gb2->name) );
        VG_(memcpy)( &inv->Inv.Global.soname[0],
                     gb2->soname, sizeof(gb2->soname) );
        inv->Inv.Global.start = gb2->addr;
        inv->Inv.Global.len   = gb2->szB;
        stats__classify_Global++;
        return;
     }
   }
   /* Ok, so it's not a block in the top frame.  Perhaps it's a block
      in some calling frame?  Work back down the stack to see if it's
      an access to an array in any calling frame. */
   {
     UWord  ix;
     Bool   isVec, b;
     Addr   blockEA;
     SizeT  blockSzB;
     HChar* name;
     Word   n, i; /* i must remain signed */
     StackFrame* frame;
     n = VG_(sizeXA)( thisThreadFrames );
     tl_assert(n > 0);
     if (0) VG_(printf)("n = %ld\n", n);
     i = n - 2;
     while (1) {
        if (i < 0) break;
        frame = VG_(indexXA)( thisThreadFrames, i );
        if (frame->blocks_at_call == NULL) { i--; continue; }
        if (0) VG_(printf)("considering %ld\n", i);
        b = find_in_StackBlocks( 
                   &ix, &isVec, &blockEA, &blockSzB, &name,
                   ea, frame->sp_at_call, frame->fp_at_call, szB,
                   frame->blocks_at_call
            );
        if (b) {
           SizeT nameSzB = sizeof(inv->Inv.Stack.name);
           inv->tag = isVec ? Inv_StackV : Inv_StackS;
           inv->Inv.Stack.framesBack = n - i - 1;;
           inv->Inv.Stack.fbIndex    = ix;
           inv->Inv.Stack.start = blockEA;
           inv->Inv.Stack.len   = blockSzB;
           VG_(memcpy)( &inv->Inv.Stack.name[0], name, nameSzB );
           inv->Inv.Stack.name[ nameSzB-1 ] = 0;
           stats__classify_Stack++;
           return;
        }
        if (i == 0) break;
        i--;
     }
   }
   /* No idea - give up.  We have to say it's Unknown.  Note that this
      is highly undesirable because it means we can't cache any ReVal
      info, and so we have to do this very slow path for every access
      made by this instruction-instance.  That's why we make big
      efforts to classify all instructions -- once classified, we can
      do cheap ReVal checks for second and subsequent accesses. */
   inv->tag = Inv_Unknown;
   stats__classify_Unknown++;
}


/* CALLED FROM GENERATED CODE */
static 
VG_REGPARM(3)
void helperc__mem_access ( /* Known only at run time: */
                           Addr ea, Addr sp, Addr fp,
                           /* Known at translation time: */
                           Word sszB, Addr ip, XArray* ip_frameBlocks )
{
   Word n;
   UWord szB;
   XArray* /* of StackFrame */ frames;
   IInstance* iinstance;
   Invar* inv;
   Invar new_inv;
   ThreadId tid = VG_(get_running_tid)();
   StackFrame* frame;
   HChar buf[160];

   stats__total_accesses++;

   tl_assert(is_sane_TId(tid));
   frames = shadowStacks[tid];
   tl_assert(frames != NULL);
   n = VG_(sizeXA)( frames );
   tl_assert(n > 0);

   frame = VG_(indexXA)( frames, n-1 );

   /* Find the instance info for this instruction. */
   tl_assert(ip_frameBlocks);
   iinstance = find_or_create_IInstance( frame, ip, ip_frameBlocks );
   tl_assert(iinstance);
   tl_assert(iinstance->blocks == ip_frameBlocks);

   szB = (sszB < 0) ? (-sszB) : sszB;
   tl_assert(szB > 0);

   inv = &iinstance->invar;

   /* Deal with first uses of instruction instances.  We hope this is
      rare, because it's expensive. */
   if (inv->tag == Inv_Unset) {
      /* This is the first use of this instance of the instruction, so
         we can't make any check; we merely record what we saw, so we
         can compare it against what happens for 2nd and subsequent
         accesses. */
      classify_address( inv,
                        tid, ea, sp, fp, szB,
                        iinstance->blocks, frames );
      tl_assert(inv->tag != Inv_Unset);
      return;
   }

   /* Now, try to re-validate (ReVal).  What that means is, quickly
      establish whether or not this instruction is accessing the same
      block as it was last time.  We hope this is the common, fast
      case. */
   switch (inv->tag) {
      case Inv_StackS:
      case Inv_StackV:
         if (inv->Inv.Stack.start <= ea 
             && ea + szB <= inv->Inv.Stack.start + inv->Inv.Stack.len) {
            stats__reval_Stack++;
            return; /* yay! */
         }
         break; /* boo! */
      case Inv_GlobalS:
      case Inv_GlobalV:
         if (inv->Inv.Global.start <= ea
             && ea + szB <= inv->Inv.Global.start + inv->Inv.Global.len) {
            stats__reval_Global++;
            return; /* yay! */
         }
         break; /* boo! */
      case Inv_Heap:
         if (inv->Inv.Heap.start <= ea
             && ea + szB <= inv->Inv.Heap.start + inv->Inv.Heap.len) {
            stats__reval_Heap++;
            return; /* yay! */
         }
         break; /* boo! */
      case Inv_Unknown:
         break; /* boo! */
         /* this is the undesirable case.  If the instruction has
            previously been poking around some place we can't account
            for, we have to laboriously check all the many places
            (blocks) we do know about, to check it hasn't transitioned
            into any of them. */
      default:
         tl_assert(0);
   }

   /* We failed to quickly establish that the instruction is poking
      around in the same block it was before.  So we have to do it the
      hard way: generate a full description (Invar) of this access,
      and compare it to the previous Invar, to see if there are really
      any differences.  Note that we will be on this code path if the
      program has made any invalid transitions, and so we may emit
      error messages in the code below. */
   classify_address( &new_inv,
                     tid, ea, sp, fp, szB,
                     iinstance->blocks, frames );
   tl_assert(new_inv.tag != Inv_Unset);

   /* Did we see something different from before?  If no, then there's
      no error. */
   if (eq_Invar(&new_inv, inv))
      return;

   /* The new and old Invars really are different.  So report an
      error. */
   { Bool v_old = inv->tag == Inv_StackV || inv->tag == Inv_GlobalV;
     Bool v_new = new_inv.tag == Inv_StackV || new_inv.tag == Inv_GlobalV;
     if ( (v_old || v_new) && new_inv.tag != inv->tag)  {
     } else {
        goto noerror;
     }
   }

   VG_(message)(Vg_UserMsg, "");
   VG_(message)(Vg_UserMsg, "Invalid %s of size %lu", 
                            sszB < 0 ? "write" : "read", szB );
   VG_(pp_ExeContext)(
      VG_(record_ExeContext)( tid, 0/*first_ip_delta*/ ) );
      // VG_(record_depth_1_ExeContext)( tid ) );

   VG_(message)(Vg_UserMsg, " Address %#lx expected vs actual:", ea);

   VG_(memset)(buf, 0, sizeof(buf));
   show_Invar( buf, sizeof(buf)-1, inv );
   VG_(message)(Vg_UserMsg, " Expected: %s", buf );

   VG_(memset)(buf, 0, sizeof(buf));
   show_Invar( buf, sizeof(buf)-1, &new_inv );
   VG_(message)(Vg_UserMsg, " Actual:   %s", buf );

  noerror:
   /* And now install the new observation as "standard", so as to
      make future error messages make more sense. */
   *inv = new_inv;
}


////////////////////////////////////////
/* Primary push-a-new-frame routine.  Called indirectly from
   generated code. */

#define N_SPACES 40
static HChar* spaces
   = "                                        ";

static
void shadowStack_new_frame ( ThreadId tid,
                             Addr     sp_at_call_insn,
                             Addr     sp_post_call_insn,
                             Addr     fp_at_call_insn,
                             Addr     ip_post_call_insn,
                             XArray*  blocks_at_call_insn )
{
   Word n;
   StackFrame callee, *caller;
   tl_assert(is_sane_TId(tid));
   tl_assert(shadowStacks[tid] != NULL);

   n = VG_(sizeXA)( shadowStacks[tid] );
   tl_assert(n > 0);

   if (n > 1)
      tl_assert(blocks_at_call_insn);

   caller = VG_(indexXA)( shadowStacks[tid], n-1 );

   caller->sp_at_call     = sp_at_call_insn;
   caller->fp_at_call     = fp_at_call_insn;
   caller->blocks_at_call = blocks_at_call_insn;

   /* This sets up .htab, .htab_size and .htab_used */
   initialise_hash_table( &callee );

   callee.creation_sp    = sp_post_call_insn;
   callee.sp_at_call     = 0; // not actually required ..
   callee.fp_at_call     = 0; // .. these 3 initialisations are ..
   callee.blocks_at_call = NULL; // .. just for cleanness

   VG_(addToXA)( shadowStacks[tid], &callee );

   if (0)
   { Word d = VG_(sizeXA)( shadowStacks[tid] );
     HChar fnname[80];
     Bool ok;
     Addr ip = ip_post_call_insn;
     ok = VG_(get_fnname_w_offset)( ip, fnname, sizeof(fnname) );
     while (d > 0) {
        VG_(printf)(" ");
        d--;
     }
     VG_(printf)("> %s %#lx\n", ok ? fnname : "???", ip);
   }
}

/* CALLED FROM GENERATED CODE */
static
VG_REGPARM(3)
void helperc__new_frame ( Addr sp_post_call_insn,
                          Addr fp_at_call_insn,
                          Addr ip_post_call_insn,
                          XArray* blocks_at_call_insn,
                          Word sp_adjust )
{
   ThreadId tid = VG_(get_running_tid)();
   Addr     sp_at_call_insn = sp_post_call_insn + sp_adjust;
   shadowStack_new_frame( tid,
                          sp_at_call_insn,
                          sp_post_call_insn,
                          fp_at_call_insn,
                          ip_post_call_insn,
                          blocks_at_call_insn );
}


////////////////////////////////////////
/* Primary remove-frame(s) routine.  Called indirectly from
   generated code. */

static void shadowStack_unwind ( ThreadId tid, Addr sp_now )
{
   StackFrame* innermost;
   tl_assert(is_sane_TId(tid));
   tl_assert(shadowStacks[tid] != NULL);
   //VG_(printf)("UNWIND sp_new = %p\n", sp_now);
   while (1) {
      Word nFrames = VG_(sizeXA)( shadowStacks[tid] );
      tl_assert(nFrames >= 0);
      if (nFrames == 0) break;
      innermost = VG_(indexXA)( shadowStacks[tid], nFrames-1 );
      if (sp_now <= innermost->creation_sp) break;
      //VG_(printf)("UNWIND     dump %p\n", innermost->creation_sp);
      tl_assert(innermost->htab);
      pc_free(innermost->htab);
      /* be on the safe side */
      innermost->creation_sp = 0;
      innermost->htab = NULL;
      innermost->htab_size = 0;
      innermost->htab_used = 0;
      innermost->sp_at_call = 0;
      innermost->fp_at_call = 0;
      innermost->blocks_at_call = NULL;
      VG_(dropTailXA)( shadowStacks[tid], 1 );

      if (0) {
         Word d = nFrames;
         while (d > 0) {
            VG_(printf)(" ");
            d--;
         }
         VG_(printf)("X\n");
      }

   }
}



//////////////////////////////////////////////////////////////
//                                                          //
// Instrumentation                                          //
//                                                          //
//////////////////////////////////////////////////////////////

/* What does instrumentation need to do?

   - at each Call transfer, generate a call to shadowStack_new_frame
     do this by manually inspecting the IR

   - at each sp change, if the sp change is negative, 
     call shadowStack_unwind
     do this by asking for SP-change analysis

   - for each memory referencing instruction,
     call helperc__mem_access
*/

static IRTemp gen_Get_SP ( IRSB*           bbOut,
                           VexGuestLayout* layout,
                           Int             hWordTy_szB )
{
   IRExpr* sp_expr;
   IRTemp  sp_temp;
   IRType  sp_type;
   /* This in effect forces the host and guest word sizes to be the
      same. */
   tl_assert(hWordTy_szB == layout->sizeof_SP);
   sp_type = layout->sizeof_SP == 8 ? Ity_I64 : Ity_I32;
   sp_expr = IRExpr_Get( layout->offset_SP, sp_type );
   sp_temp = newIRTemp( bbOut->tyenv, sp_type );
   addStmtToIRSB( bbOut, IRStmt_WrTmp( sp_temp, sp_expr ) );
   return sp_temp;
}

static IRTemp gen_Get_FP ( IRSB*           bbOut,
                           VexGuestLayout* layout,
                           Int             hWordTy_szB )
{
   IRExpr* fp_expr;
   IRTemp  fp_temp;
   IRType  fp_type;
   /* This in effect forces the host and guest word sizes to be the
      same. */
   tl_assert(hWordTy_szB == layout->sizeof_SP);
   fp_type = layout->sizeof_FP == 8 ? Ity_I64 : Ity_I32;
   fp_expr = IRExpr_Get( layout->offset_FP, fp_type );
   fp_temp = newIRTemp( bbOut->tyenv, fp_type );
   addStmtToIRSB( bbOut, IRStmt_WrTmp( fp_temp, fp_expr ) );
   return fp_temp;
}

static void instrument_mem_access ( IRSB*   bbOut, 
                                    IRExpr* addr,
                                    Int     szB,
                                    Bool    isStore,
                                    Int     hWordTy_szB,
                                    Addr    curr_IP,
                                    VexGuestLayout* layout )
{
   IRType  tyAddr      = Ity_INVALID;
   XArray* frameBlocks = NULL;

   tl_assert(isIRAtom(addr));
   tl_assert(hWordTy_szB == 4 || hWordTy_szB == 8);

   tyAddr = typeOfIRExpr( bbOut->tyenv, addr );
   tl_assert(tyAddr == Ity_I32 || tyAddr == Ity_I64);

#if defined(VGA_x86)
   { UChar* p = (UChar*)curr_IP;
     // pop %ebp; RET
     if (p[-1] == 0x5d && p[0] == 0xc3) return;
     // pop %ebp; RET $imm16
     if (p[-1] == 0x5d && p[0] == 0xc2) return;
     // PUSH %EBP; mov %esp,%ebp
     if (p[0] == 0x55 && p[1] == 0x89 && p[2] == 0xe5) return;
   }
#endif

   /* First off, find or create the StackBlocks for this instruction. */
   frameBlocks = get_StackBlocks_for_IP( curr_IP );
   tl_assert(frameBlocks);

   /* Generate a call to "helperc__mem_access", passing:
         addr current_SP current_FP szB curr_IP frameBlocks
   */
   { IRTemp t_SP = gen_Get_SP( bbOut, layout, hWordTy_szB );
     IRTemp t_FP = gen_Get_FP( bbOut, layout, hWordTy_szB );
     IRExpr** args
        = mkIRExprVec_6( addr,
                         IRExpr_RdTmp(t_SP),
                         IRExpr_RdTmp(t_FP),
                         mkIRExpr_HWord( isStore ? (-szB) : szB ),
                         mkIRExpr_HWord( curr_IP ),
                         mkIRExpr_HWord( (HWord)frameBlocks ) );
     IRDirty* di
        = unsafeIRDirty_0_N( 3/*regparms*/, 
                             "helperc__mem_access", 
                             VG_(fnptr_to_fnentry)( &helperc__mem_access ),
                             args );

     addStmtToIRSB( bbOut, IRStmt_Dirty(di) );
   }
}


static
IRSB* di_instrument ( VgCallbackClosure* closure,
                      IRSB* sbIn,
                      VexGuestLayout* layout,
                      VexGuestExtents* vge,
                      IRType gWordTy, IRType hWordTy )
{
   Int   i;
   IRSB* sbOut;

   Addr curr_IP       = 0;
   Bool curr_IP_known = False;

   Bool firstRef = True;

   if (gWordTy != hWordTy) {
      /* We don't currently support this case. */
      VG_(tool_panic)("host/guest word size mismatch");
   }

   /* Set up BB */
   sbOut           = emptyIRSB();
   sbOut->tyenv    = deepCopyIRTypeEnv(sbIn->tyenv);
   sbOut->next     = deepCopyIRExpr(sbIn->next);
   sbOut->jumpkind = sbIn->jumpkind;

   // Copy verbatim any IR preamble preceding the first IMark
   i = 0;
   while (i < sbIn->stmts_used && sbIn->stmts[i]->tag != Ist_IMark) {
      addStmtToIRSB( sbOut, sbIn->stmts[i] );
      i++;
   }

   for (/*use current i*/; i < sbIn->stmts_used; i++) {
      IRStmt* st = sbIn->stmts[i];
      tl_assert(st);
      tl_assert(isFlatIRStmt(st));
      switch (st->tag) {
         case Ist_NoOp:
         case Ist_AbiHint:
         case Ist_Put:
         case Ist_PutI:
         case Ist_MBE:
            /* None of these can contain any memory references. */
            break;

         case Ist_Exit:
            tl_assert(st->Ist.Exit.jk != Ijk_Call);
            /* else we must deal with a conditional call */
            break;

         case Ist_IMark:
            curr_IP_known = True;
            curr_IP       = (Addr)st->Ist.IMark.addr;
            firstRef      = True;
            break;

         case Ist_Store:
            tl_assert(curr_IP_known);
            if (firstRef) {
            instrument_mem_access( 
               sbOut, 
               st->Ist.Store.addr, 
               sizeofIRType(typeOfIRExpr(sbIn->tyenv, st->Ist.Store.data)),
               True/*isStore*/,
               sizeofIRType(hWordTy),
               curr_IP, layout
            );
            firstRef = False;
            }
            break;

         case Ist_WrTmp: {
            IRExpr* data = st->Ist.WrTmp.data;
            if (data->tag == Iex_Load) {
               tl_assert(curr_IP_known);
               if (firstRef) {
               instrument_mem_access(
                  sbOut,
                  data->Iex.Load.addr,
                  sizeofIRType(data->Iex.Load.ty),
                  False/*!isStore*/,
                  sizeofIRType(hWordTy),
                  curr_IP, layout
               );
               firstRef = False;
               }
            }
            break;
         }

         case Ist_Dirty: {
            Int      dataSize;
            IRDirty* d = st->Ist.Dirty.details;
            if (d->mFx != Ifx_None) {
               /* This dirty helper accesses memory.  Collect the
                  details. */
               tl_assert(curr_IP_known);
               if (firstRef) {
               tl_assert(d->mAddr != NULL);
               tl_assert(d->mSize != 0);
               dataSize = d->mSize;
               if (d->mFx == Ifx_Read || d->mFx == Ifx_Modify) {
                  instrument_mem_access( 
                     sbOut, d->mAddr, dataSize, False/*!isStore*/,
                     sizeofIRType(hWordTy), curr_IP, layout
                  );
               }
               if (d->mFx == Ifx_Write || d->mFx == Ifx_Modify) {
                  instrument_mem_access( 
                     sbOut, d->mAddr, dataSize, True/*isStore*/,
                     sizeofIRType(hWordTy), curr_IP, layout
                  );
               }
               firstRef = False;
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

      addStmtToIRSB( sbOut, st );
   } /* iterate over sbIn->stmts */

   if (sbIn->jumpkind == Ijk_Call) {
      // Assumes x86 or amd64
      IRTemp   sp_post_call_insn, fp_post_call_insn;
      XArray*  frameBlocks;
      IRExpr** args;
      IRDirty* di;
      sp_post_call_insn
         = gen_Get_SP( sbOut, layout, sizeofIRType(hWordTy) );
      fp_post_call_insn
         = gen_Get_FP( sbOut, layout, sizeofIRType(hWordTy) );
      tl_assert(curr_IP_known);
      frameBlocks = get_StackBlocks_for_IP( curr_IP );
      tl_assert(frameBlocks);
      args
         = mkIRExprVec_5(
              IRExpr_RdTmp(sp_post_call_insn),
              IRExpr_RdTmp(fp_post_call_insn), 
                         /* assume the call doesn't change FP */
              sbIn->next,
              mkIRExpr_HWord( (HWord)frameBlocks ),
              mkIRExpr_HWord( sizeofIRType(gWordTy) )
           );
      di = unsafeIRDirty_0_N(
              3/*regparms*/,
              "helperc__new_frame",
              VG_(fnptr_to_fnentry)( &helperc__new_frame ),
              args ); 
      addStmtToIRSB( sbOut, IRStmt_Dirty(di) );
   }

   return sbOut;
}


//////////////////////////////////////////////////////////////
//                                                          //
// end Instrumentation                                      //
//                                                          //
//////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////
//                                                          //
// misc                                                     //
//                                                          //
//////////////////////////////////////////////////////////////

/* Make a new shadow stack, with a creation_sp of effectively infinity,
   so that the top frame can never be removed. */
static XArray* /* of StackFrame */ new_empty_Stack ( void )
{
   StackFrame sframe;
   XArray* st = VG_(newXA)( pc_malloc, pc_free, sizeof(StackFrame) );
   VG_(memset)( &sframe, 0, sizeof(sframe) );
   sframe.creation_sp = ~0UL;

   /* This sets up .htab, .htab_size and .htab_used */
   initialise_hash_table( &sframe );

   VG_(addToXA)( st, &sframe );
   return st;
}

/* Primary routine for setting up the shadow stack for a new thread.
   Note that this is used to create not only child thread stacks, but
   the root thread's stack too.  We create a new stack with
   .creation_sp set to infinity, so that the outermost frame can never
   be removed (by shadowStack_unwind).  The core calls this function
   as soon as a thread is created.  We cannot yet get its SP value,
   since that may not yet be set. */
static void shadowStack_thread_create ( ThreadId parent, ThreadId child )
{
   tl_assert(is_sane_TId(child));
   if (parent == VG_INVALID_THREADID) {
      /* creating the main thread's stack */
   } else {
      tl_assert(shadowStacks[parent] != NULL);
   }
   if (shadowStacks[child] != NULL) {
      VG_(deleteXA)( shadowStacks[child] );
   }
   shadowStacks[child] = new_empty_Stack();
}

/* Once a thread is ready to go, the core calls here.  We take the
   opportunity to push a second frame on its stack, with the
   presumably valid SP value that is going to be used for the thread's
   startup.  Hence we should always wind up with a valid outermost
   frame for the thread. */
static void shadowStack_set_initial_SP ( ThreadId tid )
{
   StackFrame* sfp;
   tl_assert(is_sane_TId(tid));
   tl_assert(shadowStacks[tid] != NULL);
   tl_assert( VG_(sizeXA)(shadowStacks[tid]) == 1 );
   sfp = VG_(indexXA)( shadowStacks[tid], 0 );
   tl_assert(sfp->creation_sp == ~0UL);
   shadowStack_new_frame( tid, 0, VG_(get_SP)(tid),
                               0, VG_(get_IP)(tid), NULL );
}

/* CALLED indirectly FROM GENERATED CODE */
static void sg_die_mem_stack ( Addr old_SP, SizeT len ) {
   ThreadId  tid = VG_(get_running_tid)();
   shadowStack_unwind( tid, old_SP+len );
}


static void sg_post_clo_init(void)
{
}

static void sg_fini(Int exitcode)
{
  VG_(message)(Vg_DebugMsg,
     "%'llu total accesses, of which:", stats__total_accesses);
  VG_(message)(Vg_DebugMsg,
     "    stack: %'12llu classify, %'12llu reval",
     stats__classify_Stack, stats__reval_Stack);
  VG_(message)(Vg_DebugMsg,
     "     heap: %'12llu classify, %'12llu reval",
     stats__classify_Heap, stats__reval_Heap);
  VG_(message)(Vg_DebugMsg,
     "   global: %'12llu classify, %'12llu reval",
     stats__classify_Global, stats__reval_Global);
  VG_(message)(Vg_DebugMsg,
     "  unknown: %'12llu classify",
     stats__classify_Unknown);
  VG_(message)(Vg_DebugMsg,
     "%'llu Invars preened, of which %'llu changed",
     stats__Invars_preened, stats__Invars_changed);
  VG_(message)(Vg_DebugMsg, "");
}

static void sg_pre_clo_init(void)
{
   VG_(details_name)            ("SGcheck");
   VG_(details_version)         (NULL);
   VG_(details_description)     ("a stack & global array overrun detector");
   VG_(details_copyright_author)(
      "Copyright (C) 2008-2008, and GNU GPL'd, by OpenWorks Ltd.");
   VG_(details_bug_reports_to)  (VG_BUGS_TO);

   VG_(basic_tool_funcs)        (sg_post_clo_init,
                                 di_instrument,
                                 sg_fini);

   VG_(needs_var_info)            ();

   VG_(needs_malloc_replacement)( pc_replace_malloc,
                                  pc_replace___builtin_new,
                                  pc_replace___builtin_vec_new,
                                  pc_replace_memalign,
                                  pc_replace_calloc,
                                  pc_replace_free,
                                  pc_replace___builtin_delete,
                                  pc_replace___builtin_vec_delete,
                                  pc_replace_realloc,
                                  0 /* no need for client heap redzones */ );
   shadowStacks_init();
   init_StackBlocks_set();
   init_globals();
   init_heap();
   VG_(clo_vex_control).iropt_unroll_thresh = 0;
   VG_(clo_vex_control).guest_chase_thresh = 0;
   VG_(track_die_mem_stack) ( sg_die_mem_stack );
   VG_(track_pre_thread_ll_create)( shadowStack_thread_create );
   VG_(track_pre_thread_first_insn)( shadowStack_set_initial_SP );

   VG_(track_new_mem_mmap)         ( sg_new_mem_mmap );
   VG_(track_new_mem_startup) (sg_new_mem_startup);
   VG_(track_die_mem_munmap)( sg_die_mem_munmap );
}

VG_DETERMINE_INTERFACE_VERSION(sg_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                sg_main.c ---*/
/*--------------------------------------------------------------------*/
