
/*--------------------------------------------------------------------*/
/*--- Interval skip list for segments.                   pc_list.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Ptrcheck, a Valgrind tool for checking pointer
   use in programs.

   Copyright (C) 2003-2008 Nicholas Nethercote
      njn@valgrind.org

   This file is derived from a C++ interval skip-list implementation by Eric
   Hanson, which had this copyright notice:

     This software is copyright 1994 by the University of Florida and Eric
     Hanson (hanson@cise.ufl.edu).  It has been placed in the public domain.
     Copies can be made, modified, distributed freely, and used for any and 
     all purposes, provided that copies attribute the original source.  
     This software is not warranted to be free of defects or to be suitable 
     for any particular purpose.

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
#include "pub_tool_libcprint.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_execontext.h"
#include "pub_tool_hashtable.h"

#include "h_list.h"

#ifdef OUTSIDE_PTRCHECK
 #include <assert.h>
 #include <stdio.h>
 #include <stdlib.h>
 #define my_malloc      malloc
 #define my_free        free
 #define my_assert      assert
 #define my_printf      printf
 #define my_random(_x)  random()
 #define MY_RAND_MAX    RAND_MAX
#else
 #define my_malloc      VG_(malloc)
 #define my_free        VG_(free)
 #define my_assert      tl_assert
 #define my_printf      VG_(printf)
 #define MY_RAND_MAX    VG_RAND_MAX
 #define my_random(_x)  VG_(random)(_x)
#endif

// XXX: I think that, because I'm only doing [,] intervals, not (,)
// intervals, that I can dispense with edge markers, and use only node
// markers.  (Nb: need node markers eg for a range [7,7] -- no edges
// involved.)
// [Hmm, not quite, or at least I would need to change the data structure
// invariants quite a bit, and mark every node in an interval as belonging
// to that interval, whereas currently this isn't always necessary because
// long (marked) edges can span multiple nodes, saving them from needing
// markers.]

//-------------------------------------------------------------------
// Types
//-------------------------------------------------------------------

struct _Interval {
   Addr        left;
   Addr        right;  // left and right boundary values
   ExeContext* where;
   UInt        magic;
   UChar       status;
   UChar       is_zero;
};

typedef struct _INode INode;
struct _INode {
   Interval* I;
   INode*    next;
};

struct _IList {
   INode* header;
};

typedef struct _ISNode ISNode;
struct _ISNode {
   Addr     key;
   ISNode** forward;    // array of forward pointers
   IList**  markers;    // array of interval marker sets, 1 per forward ptr
   IList*   eqMarkers;  // markers for node itself
   Int      ownerCount; // number of interval end points with (value == key)
   Int      topLevel;   // index of top level of forward pointers in this
                        // node.  Levels are numbered 0..topLevel.
};

// Nb: the header node has key=0
struct _ISList {
   Int     maxLevel;
   ISNode* header;
};

//-------------------------------------------------------------------
// Miscellaneous
//-------------------------------------------------------------------

#define MAX_FORWARD 32

static void print_Addr(Addr a)
{
   my_printf("0x%lx", a);
}

//-------------------------------------------------------------------
// Interval
//-------------------------------------------------------------------

static
Bool Interval__hasValidMagic ( Interval* o )
{
   return o->magic == (0x14141356 ^ (UInt)(UWord)o);
}

static
Interval* Interval__construct(Addr left, Addr right, Bool is_zero,
                              ExeContext* where, SegStatus status)
{
   Interval* o = my_malloc( sizeof(Interval) );
   if (0) VG_(printf)("Interval__construct(%#lx,%#lx,%d)\n",
                      left, right, (Int)is_zero);
   o->left     = left;
   o->right    = right;
   o->is_zero  = is_zero;
   o->where    = where;
   o->magic    = 0x14141356 ^ (UInt)(UWord)o;
   o->status   = status;
   return o;
}

__attribute__((unused))
static
void Interval__destruct(Interval* o)
{
   my_free(o);
}

static void Interval__print(Interval* o)
{
   my_printf("[");
   print_Addr(o->left);
   my_printf(",");
   print_Addr(o->right);
   my_printf("]");
}

// true iff this contains (l,r)
static __inline__ Bool Interval__containsI(Interval* o, Addr l, Addr r)
{
   return ( o->left <= l && r <= o->right ? True : False );
}

static __inline__ Bool Interval__contains(Interval* o, Addr a)
{
   return Interval__containsI(o, a, a); 
}

static Interval* Interval__choose(Interval* o, Interval* I)
{
   my_assert(NULL != o);

   if (NULL == I)
      return o;

   else if (SegHeap == o->status && SegHeapFree == I->status) 
      return o;

   else if (SegHeap == I->status && SegHeapFree == o->status) 
      return I;
#if 0
   else if (SegMmap == o->status && SegMmapFree == I->status) 
      return o;

   else if (SegMmap == I->status && SegMmapFree == o->status) 
      return I;
#endif
   else if (SegHeapFree == I->status && SegHeapFree == o->status) 
      return ( o->left < I->left ? o : I);
#if 0
   else if (SegMmapFree == I->status && SegMmapFree == o->status) 
      return ( o->left < I->left ? o : I);
#endif

   else if (SegMmap == I->status && SegMmap == o->status) 
      return ( o->left < I->left ? o : I);

   else {
      my_printf("o->status = %d, I->status = %d\n", o->status, I->status);
      my_printf("o->left   = %#lx, I->left   = %#lx\n", o->left,   I->left);
      my_printf("o->right  = %#lx, I->right  = %#lx\n", o->right , I->right );
      my_printf("o->is_zero= %d, I->is_zero= %d\n", o->is_zero,I->is_zero);
      my_assert(1 == 2);
//      return ( o->left < I->left ? o : I);
   }
}

//-------------------------------------------------------------------
// Seg
//-------------------------------------------------------------------

Bool Seg__plausible ( Seg seg ) {
   return Interval__hasValidMagic( seg );
}

Seg Seg__construct(Addr a, SizeT len, ExeContext* where, SegStatus status)
{
   Bool is_zero;
   Addr right;
   if (0) VG_(printf)("Seg__construct(addr=%#lx, len=%lu)\n", a, len);
   if (0 == len) {
      is_zero = True;
      right   = a;
   } else {
      is_zero = False;
      right   = a + len - 1;
   }
   return Interval__construct(a, right, is_zero, where, status);
}

Addr Seg__a(Seg seg)
{
   return seg->left;
}

ExeContext* Seg__where(Seg seg)
{
   return seg->where;
}

void Seg__heap_free(Seg seg, ExeContext* where)
{
   my_assert(SegHeap == seg->status);
   seg->status = SegHeapFree;
   seg->where  = where;
}

SizeT Seg__size(Seg seg)
{
   if (seg->is_zero) {
      my_assert(seg->left == seg->right);
      return 0;
   } else {
      return (seg->right - seg->left + 1);
   }
}

Bool Seg__is_freed(Seg seg)
{
   return (SegHeapFree == seg->status || SegMmapFree == seg->status);
}

Bool Seg__containsI(Seg seg, Addr l, Addr r)
{
   my_assert(Interval__hasValidMagic(seg));
   if (seg->is_zero) {
      my_assert(seg->left == seg->right);
      return False;
   } else {
      return ( seg->left <= l && r <= seg->right ? True : False );
   }
}

Bool Seg__contains(Seg seg, Addr a)
{
   return Seg__containsI(seg, a, a);
}

// Determines if 'a' is before, within, or after seg's range.  Sets 'cmp' to
// -1/0/1 accordingly.  Sets 'n' to the number of bytes before/within/after.
void Seg__cmp(Seg seg, Addr a, Int* cmp, UWord* n)
{
   if (a < seg->left) {
      *cmp = -1;
      *n   = seg->left - a;
   } else if (a <= seg->right && !seg->is_zero) {
      *cmp = 0;
      *n = a - seg->left;
   } else {
      *cmp = 1;
      *n = ( seg->is_zero ? a - seg->right : a - seg->right - 1);
   }
}

void Seg__resize(Seg seg, SizeT new_size, ExeContext* where) 
{
   my_assert(0 != new_size);
   seg->right = seg->left + new_size - 1;
   seg->where = where;
}

Char* Seg__status_str(Seg seg)
{
   switch (seg->status) {
   case SegHeap:     return "alloc'd";
   case SegHeapFree: return "free'd";
   case SegMmap:     return "mmap'd";
   case SegMmapFree: return "munmap'd";
   default:          VG_(tool_panic)("Seg__status_str");
   }
}

Bool Seg__status_is_SegHeap ( Seg seg )
{
   return seg->status == SegHeap;
}

__attribute__((unused))
static void pseg(VgHashNode* n)
{
   Seg seg = (Seg)n;
   VG_(printf)("%#lx--%#lx (%s)\n", seg->left, seg->right, Seg__status_str(seg));
}

__attribute__((unused))
static void print_segs(void)
{
#if 0
   VG_(printf)("heap limits: %#lx, %#lx\n", heap_min, heap_max);
   VG_(printf)("-- hlist ----\n");
   VG_(HT_apply_to_all_nodes)( (VgHashTable)hlist, pseg );
   VG_(printf)("-- hfreelist ----\n");
   VG_(HT_apply_to_all_nodes)( (VgHashTable)hfreelist, pseg );
   VG_(printf)("-- mlist ----\n");
   VG_(HT_apply_to_all_nodes)( (VgHashTable)mlist, pseg );
   VG_(printf)("-- mfreelist ----\n");
   VG_(HT_apply_to_all_nodes)( (VgHashTable)mfreelist, pseg );
   VG_(printf)("\n");
#endif
}

__attribute__((unused))
static void count_segs(void)
{
#if 0
   VG_(printf)("hlist:     %d\n", VG_(HT_count_nodes)((VgHashTable)hlist));
   VG_(printf)("hfreelist: %d\n", VG_(HT_count_nodes)((VgHashTable)hfreelist));
   VG_(printf)("mlist:     %d\n", VG_(HT_count_nodes)((VgHashTable)mlist));
   VG_(printf)("mfreelist: %d\n", VG_(HT_count_nodes)((VgHashTable)mfreelist));
   VG_(printf)("\n");
#endif
}
 
//-------------------------------------------------------------------
// INode
//-------------------------------------------------------------------

static INode* INode__construct(Interval* I)
{
   INode* o = my_malloc( sizeof(INode) );
   o->I    = I;
   o->next = NULL;
   return o;
}

// Nb: Intervals must be freed elsewhere, because there are possibly
// multiple pointers to each Interval in the ISList;  freeing them here
// could cause double-freeing.
static void INode__destruct(INode* o)
{
   my_assert(NULL != o);
   while (NULL != o) {
      //Interval__destruct(o->I);
      INode* tmp = o;
      o = o->next;
      my_free(tmp);
   }
}

//-------------------------------------------------------------------
// IList
//-------------------------------------------------------------------

static __inline__ void IList__static_construct(IList* o)
{
   o->header = NULL;
}

static IList* IList__construct(void)
{
   IList* o = my_malloc( sizeof(IList) );
   IList__static_construct(o);
   return o;
}

static void IList__empty(IList* o)
{
   my_assert(NULL != o);
   if (NULL != o->header)
      INode__destruct(o->header);
   o->header = NULL;
}

static void IList__destruct(IList* o)
{
   my_assert(NULL != o);
   IList__empty(o);
   my_free(o);
}

static void IList__static_destruct(IList* o)
{
   my_assert(NULL != o);
   IList__empty(o);
}

static void IList__insert(IList* o, Interval* I)
{
   INode* tmp = INode__construct(I);
   tmp->next = o->header;
   o->header = tmp;
}

static void IList__copy(IList* o, IList* from)
{
   INode* e = from->header;
   while (NULL != e) { 
      IList__insert(o, e->I);
      e = e->next;
   }
}

__attribute__((unused))
static Int IList__length(IList* o)
{
   INode* x;
   Int    n = 0;
   for (x = o->header; NULL != x; x = x->next) 
      n++;
   return n;
}

static void IList__remove(IList* o, Interval* I)
{
   INode *x, **prev_ptr;

   x = o->header; 
   prev_ptr = &(o->header);
   while (True) {
      if (NULL == x) 
         return;                 // not found
      if (x->I == I) {
         *prev_ptr = x->next;    // found
         x->next = NULL;         // must clobber 'next' before INode__destruct
         INode__destruct(x);
         return;
      }
      prev_ptr = &(x->next);
      x = x->next;
   } 
}

static void IList__removeAll(IList* o, IList *l)
{
   INode *x;
   for (x = l->header; NULL != x; x = x->next)
      IList__remove(o, x->I);
}

static void IList__print(IList* o)
{
   INode* e = o->header;
   if (NULL == e)
      my_printf("[]");
   else 
      while (NULL != e) {
         Interval__print(e->I);
         e = e->next;
      }
}

static void IList__print2(IList* o, Addr a)
{
   INode* e = o->header;
   my_printf("<");
   while (NULL != e) {
      if (e->I->left == a)
         Interval__print(e->I);
      e = e->next;
   }
   my_printf(">\n");
}

static Interval* IList__choose(IList* o, Interval* I, Bool find_zero)
{
   INode* e = o->header;
   while (NULL != e) {
      if (find_zero || !e->I->is_zero)
         I = (Interval__choose(e->I, I));
      e = e->next;
   }
   return I;
}

static __inline__ Bool IList__isEmpty(IList* o)
{
   return (NULL == o->header);
}

//-------------------------------------------------------------------
// ISNode
//-------------------------------------------------------------------

static ISNode* ISNode__construct(Addr a, Int levels)
{
   Int     i;
   ISNode* o = my_malloc( sizeof(ISNode) );
   
   // levels is actually one less than the real number of levels
   o->key        = a;
   o->topLevel   = levels;
   o->forward    = my_malloc( sizeof(ISNode*) * (levels+1) );
   o->markers    = my_malloc( sizeof(IList*)  * (levels+1) );
   for (i = 0; i <= levels; i++) {
      o->forward[i] = NULL;
      o->markers[i] = IList__construct(); // initialize an empty interval list
   }
   o->eqMarkers  = IList__construct();
   o->ownerCount = 0;
   return o;
}

static __inline__ ISNode* ISNode__get_next(ISNode* o)
{
   return o->forward[0];
}

static void ISNode__destruct(ISNode* o)
{
   Int i;
   // Nb: We only destruct nodes pointed to by level-0 pointers, to avoid
   //     destructing any node more than once.
   my_assert(NULL != o);
   while (NULL != o) {
      ISNode* tmp = o;
      o = ISNode__get_next(o);
      for (i = 0; i <= tmp->topLevel; i++)
         IList__destruct(tmp->markers[i]);
      my_free(tmp->forward);
      my_free(tmp->markers);
      IList__destruct(tmp->eqMarkers);
      my_free(tmp);
   }
}

static __inline__ Bool ISNode__isHeader(ISNode* o)
{
   return (0 == o->key ? True : False);
}

static void ISNode__print(ISNode* o)
{
   Int i;
   my_printf("key:  ");
   if (ISNode__isHeader(o))
      my_printf("HEADER");
   else 
      print_Addr(o->key); 
   my_printf("  ");
   IList__print(o->eqMarkers);
   my_printf("  ownerCount = %d\n", o->ownerCount);
   for (i = o->topLevel; i >= 0; i--) {
      my_printf("[%d] --> ", i);
      if (o->forward[i] != NULL)
         print_Addr(o->forward[i]->key);
      else
         my_printf("NULL");
      my_printf("  ");
      if (o->markers[i] != NULL)
         IList__print(o->markers[i]);
      else
         my_printf("NULL");
      my_printf("\n");
   }
   my_printf("\n");
}

//-------------------------------------------------------------------
// ISList
//-------------------------------------------------------------------

#define P      0.5f

ISList* ISList__construct(void)
{
   ISList* o = my_malloc( sizeof(ISList) );
   o->maxLevel = 0;
   o->header = ISNode__construct(0, MAX_FORWARD);
   return o;
}

void ISList__destruct(ISList* o)
{
   my_assert(NULL != o);
   ISNode__destruct(o->header);
   my_free(o);
}

Bool ISList__isEmpty(ISList* o)
{
   return ( NULL == o->header->forward[0] ? True : False );
}

void ISList__printDetails(ISList* o)
{
   ISNode* n = o->header; //ISNode__get_next(o->header);
   my_printf("\nAn ISList:  (maxLevel = %d)\n", o->maxLevel);
   while ( NULL != n ) {
      ISNode__print(n);
      n = ISNode__get_next(n);
   }
}

void ISList__print(ISList* o)
{
   ISNode* n = ISNode__get_next(o->header);
   my_printf("intervals in list:\n");
   while ( NULL != n ) {
      IList__print2(n->eqMarkers, n->key);
      n = ISNode__get_next(n);
   }
   my_printf("\n");
}

// Remove markers for interval m from the edges and nodes on the level i
// path from l to r.
static void ISList__removeMarkFromLevel(ISList* o, Interval* m, Int i,
                                        ISNode *l, ISNode* r)
{
   ISNode *x;
   for (x = l; NULL != x && x != r; x = x->forward[i]) {
      IList__remove(x->markers[i], m);
      IList__remove(x->eqMarkers, m);
   }
   if (NULL != x) IList__remove(x->eqMarkers, m);
}

// Adjust markers on this IS-list to maintain marker invariant now that
// node x has just been inserted, with update vector `update.'
static void ISList__adjustMarkersOnInsert(ISList* o, ISNode* x,
                                          ISNode** update)
{
   // Phase 1:  place markers on edges leading out of x as needed.

   // Starting at bottom level, place markers on outgoing level i edge of x.
   // If a marker has to be promoted from level i to i+1 of higher, place it
   // in the promoted set at each step.

   IList promoted;       // list of intervals that identify markers being
                         // promoted, initially empty.
   IList newPromoted;    // temporary set to hold newly promoted markers.
   IList removePromoted; // holding place for elements to be removed
                         // from promoted list.
   IList tempMarkList;   // temporary mark list
   INode* m;
   Int i;

   IList__static_construct(&promoted);
   IList__static_construct(&newPromoted);
   IList__static_construct(&removePromoted);
   IList__static_construct(&tempMarkList);

   for (i = 0; i < x->topLevel && NULL != x->forward[i+1]; i++)
   {
      IList* markList = update[i]->markers[i];
      for (m = markList->header; m != NULL; m = m->next) {
         if (Interval__containsI(m->I, x->key, x->forward[i+1]->key)) { 
            // promote m
            // remove m from level i path from x->forward[i] to x->forward[i+1]
            ISList__removeMarkFromLevel(o, m->I, i, x->forward[i],
                                                    x->forward[i+1]);
            // add m to newPromoted
            IList__insert(&newPromoted, m->I);
         } else {
            // place m on the level i edge out of x
            IList__insert(x->markers[i], m->I);
            // do *not* place m on x->forward[i] -- it must already be there. 
         }
      }

      for (m = promoted.header; m != NULL; m = m->next) {
         if (!Interval__containsI(m->I, x->key, x->forward[i+1]->key)) {
            // Then m does not need to be promoted higher.
            // Place m on the level i edge out of x and remove m from promoted.
            IList__insert(x->markers[i], m->I);
            // mark x->forward[i] if needed
            if (Interval__contains(m->I, x->forward[i]->key))
               IList__insert(x->forward[i]->eqMarkers, m->I);
            IList__insert(&removePromoted, m->I);
         } else { 
            // continue to promote m
            // Remove m from the level i path from x->forward[i]
            // to x->forward[i+1].
            ISList__removeMarkFromLevel(o, m->I, i, x->forward[i],
                                                    x->forward[i+1]);
         }
      }
      IList__removeAll(&promoted, &removePromoted);
      IList__empty(&removePromoted);
      IList__copy(&promoted, &newPromoted);
      IList__empty(&newPromoted);
   }
   // Combine the promoted set and updated[i]->markers[i]
   // and install them as the set of markers on the top edge out of x
   // that is non-null.  

   IList__copy(x->markers[i], &promoted);
   IList__copy(x->markers[i], update[i]->markers[i]);
   for (m = promoted.header; NULL != m; m = m->next)
      if (Interval__contains(m->I, x->forward[i]->key))
         IList__insert(x->forward[i]->eqMarkers, m->I);

   // Phase 2:  place markers on edges leading into x as needed.

   // Markers on edges leading into x may need to be promoted as high as
   // the top edge coming into x, but never higher.

   IList__empty(&promoted);
   for (i = 0; i < x->topLevel && !ISNode__isHeader(update[i+1]); i++)
   {
      IList__copy(&tempMarkList, update[i]->markers[i]);
      for (m = tempMarkList.header; m != NULL; m = m->next) {
         if (Interval__containsI(m->I, update[i+1]->key, x->key)) {
            // m needs to be promoted
            // add m to newPromoted
            IList__insert(&newPromoted, m->I);

            // Remove m from the path of level i edges between updated[i+1]
            // and x (it will be on all those edges or else the invariant
            // would have previously been violated).
            ISList__removeMarkFromLevel(o, m->I, i, update[i+1], x);
         }
      }
      IList__empty(&tempMarkList);  // reclaim storage

      for (m = promoted.header; m != NULL; m = m->next) {
         if (!ISNode__isHeader(update[i]) && 
             Interval__containsI(m->I, update[i]->key, x->key) &&
             !ISNode__isHeader(update[i+1]) &&
             !Interval__containsI(m->I, update[i+1]->key, x->key) )
         {
            // Place m on the level i edge between update[i] and x, and
            // remove m from promoted.
            IList__insert(update[i]->markers[i], m->I);
            // mark update[i] if needed
            if (Interval__contains(m->I, update[i]->key))
               IList__insert(update[i]->eqMarkers, m->I);
            IList__insert(&removePromoted, m->I);
         } else {
            // Strip m from the level i path from update[i+1] to x.
            ISList__removeMarkFromLevel(o, m->I, i, update[i+1], x);
         }
      }
      // remove non-promoted marks from promoted
      IList__removeAll(&promoted, &removePromoted);
      IList__empty(&removePromoted);  // reclaim storage

      // add newPromoted to promoted and make newPromoted empty
      IList__copy(&promoted, &newPromoted);
      IList__empty(&newPromoted);     
   }

   /* Assertion:  i=x->level()-1 OR update[i+1] is the header.

   If i==x->level()-1 then either x has only one level, or the top-level
   pointer into x must not be from the header, since otherwise we would
   have stopped on the previous iteration.  If x has 1 level, then
   promoted is empty.  If x has 2 or more levels, and i!=x->level()-1,
   then the edge on the next level up (level i+1) is from the header.  In
   any of these cases, all markers in the promoted set should be
   deposited on the current level i edge into x.  An edge out of the
   header should never be marked.  Note that in the case where x has only
   1 level, we try to copy the contents of the promoted set onto the
   marker set of the edge out of the header into x at level i==0, but of
   course, the promoted set will be empty in this case, so no markers
   will be placed on the edge.  */

   IList__copy(update[i]->markers[i], &promoted);
   for (m = promoted.header; NULL != m; m = m->next)
      if (Interval__contains(m->I, update[i]->key))
         IList__insert(update[i]->eqMarkers, m->I);

   // Place markers on x for all intervals the cross x.
   // (Since x is a new node, every marker comming into x must also leave x).
   for (i = 0; i <= x->topLevel; i++)
      IList__copy(x->eqMarkers, x->markers[i]);

   IList__static_destruct(&promoted);
   IList__static_destruct(&newPromoted);
   IList__static_destruct(&removePromoted);
   IList__static_destruct(&tempMarkList);
}

// Find ISNode x containing the search key.  Also sets up 'update'
// vector to show pointers into x. 
static ISNode* ISList__search(ISList* o, Addr a, ISNode** update)
{
   Int     i;
   ISNode* x = o->header;

   for (i = o->maxLevel; i >= 0; i--) {
      while (NULL != x->forward[i] && x->forward[i]->key < a) {
         x = x->forward[i];
      }
      update[i] = x;
   }
   return x->forward[0];
}

/* Return a "random" float in the range [0.0 .. 1.0) */
static float normalizedRandom(void)
{
   //static Int uh = 0, lh = 0;
   float f = ((float)my_random(NULL))/ (MY_RAND_MAX + 1.0);
   tl_assert(f >= 0.0);
   tl_assert(f <= 1.0); /* in fact < and not <=, but we'll overlook that. */
   //if (f >= 0.5) uh++; else lh++;
   //VG_(printf)("(%d,%d) %d\n", lh, uh, (Int)(1000.0 * f));
   return f;
}

// choose a new node level at random
static Int ISList__randomLevel(ISList* o)
{
   Int levels = 0;
   while ( P <= normalizedRandom() ) levels++;   
   return ( levels <= o->maxLevel ? levels : o->maxLevel+1 );
}

// insert a new single value into list, returning a pointer to its location.
static ISNode* ISList__insert(ISList* o, Addr a)
{
   ISNode* update[MAX_FORWARD]; // array for maintaining update pointers 
   ISNode* x;
   Int i;

   // Find location of 'a', building update vector indicating
   // pointers to change on insertion.
   x = ISList__search(o, a, update);
   if (NULL == x || x->key != a) {
      // put a new node in the list for this 'a'
      Int newLevel = ISList__randomLevel(o);

      // most likely reason for this to fail is that normalizedRandom isn't
      // working properly.  It is supposed to generate numbers uniformly
      // in the range [0.0 .. 1.0), hence with a mean of 0.5.
      tl_assert(newLevel < MAX_FORWARD-1);

      if (newLevel > o->maxLevel){
         // New node is bigger than any previous, add the header node to the
         // update vector for the new levels.
         for (i = o->maxLevel+1; i <= newLevel; i++) {
            // Markers list was initialised in ISNode__construct
            my_assert(IList__isEmpty(o->header->markers[i]));
            update[i] = o->header;
         }
         o->maxLevel = newLevel;
      }
      x = ISNode__construct(a, newLevel);

      // add x to the list
      for (i = 0; i <= newLevel; i++) {
         x->forward[i] = update[i]->forward[i];
         update[i]->forward[i] = x;
      }

      // adjust markers to maintain marker invariant
      ISList__adjustMarkersOnInsert(o, x, update);
   }
   // else, 'a' is in the list already, and x points to it.
   return x;
}

// adjust markers to prepare for deletion of x, which has update vector 
// "update"
static void ISList__adjustMarkersOnDelete(ISList* o, ISNode* x,
                                          ISNode** update)
{
   // x is node being deleted.  It is still in the list.
   // update is the update vector for x.
   IList demoted;
   IList newDemoted;
   IList tempRemoved;
   INode* m;
   Int i;
   ISNode *y;

   IList__static_construct(&demoted);
   IList__static_construct(&newDemoted);
   IList__static_construct(&tempRemoved);

   // Phase 1:  lower markers on edges to the left of x as needed.

   for (i = x->topLevel; i >= 0; i--){
      // find marks on edge into x at level i to be demoted
      for (m = update[i]->markers[i]->header; NULL != m; m = m->next) {
         if (NULL == x->forward[i] ||
            !Interval__containsI(m->I, update[i]->key, x->forward[i]->key))
         {
            IList__insert(&newDemoted, m->I);
         }
      }
      // Remove newly demoted marks from edge.
      IList__removeAll(update[i]->markers[i], &newDemoted);
      // NOTE:  update[i]->eqMarkers is left unchanged because any markers
      // there before demotion must be there afterwards.

      // Place previously demoted marks on this level as needed.
      for (m = demoted.header; NULL != m; m = m->next) {
         // Place mark on level i from update[i+1] to update[i], not including 
         // update[i+1] itself, since it already has a mark if it needs one.
         for (y = update[i+1]; NULL != y && y != update[i]; y = y->forward[i]) {
            if (y != update[i+1] && Interval__contains(m->I, y->key)) 
               IList__insert(y->eqMarkers, m->I);
            IList__insert(y->markers[i], m->I);
         }
         if (NULL == y && y != update[i+1] && Interval__contains(m->I, y->key)) 
            IList__insert(y->eqMarkers, m->I);

         // if this is the lowest level m needs to be placed on,
         // then place m on the level i edge out of update[i]
         // and remove m from the demoted set.
         if (NULL != x->forward[i] &&
             Interval__containsI(m->I, update[i]->key, x->forward[i]->key))
         {
            IList__insert(update[i]->markers[i], m->I);
            IList__insert(&tempRemoved, m->I);
         }
      }
      IList__removeAll(&demoted, &tempRemoved);
      IList__empty(&tempRemoved);
      IList__copy(&demoted, &newDemoted);
      IList__empty(&newDemoted);
   }

   // Phase 2:  lower markers on edges to the right of D as needed
  
   IList__empty(&demoted);
   // newDemoted is already empty

   for (i = x->topLevel; i >= 0; i--){
      for (m = x->markers[i]->header; NULL != m; m = m->next) {
         if (NULL != x->forward[i] && (ISNode__isHeader(update[i]) ||
             !Interval__containsI(m->I, update[i]->key, x->forward[i]->key)))
         {
            IList__insert(&newDemoted, m->I);
         }
      }
    
      for (m = demoted.header; NULL != m; m = m->next) {
         // Place mark on level i from x->forward[i] to x->forward[i+1].
         // Don't place a mark directly on x->forward[i+1] since it is already
         // marked.
         for (y = x->forward[i]; y != x->forward[i+1]; y = y->forward[i]){
            IList__insert(y->eqMarkers, m->I);
            IList__insert(y->markers[i], m->I);
         }

         if (NULL != x->forward[i] && !ISNode__isHeader(update[i]) &&
             Interval__containsI(m->I, update[i]->key, x->forward[i]->key))
         {
            IList__insert(&tempRemoved, m->I);
         }
      }
      IList__removeAll(&demoted, &tempRemoved);
      IList__copy(&demoted, &newDemoted);
      IList__empty(&newDemoted);
   }
   IList__static_destruct(&demoted);
   IList__static_destruct(&newDemoted);
   IList__static_destruct(&tempRemoved);
}

// remove node x, which has updated vector update.
static void ISList__remove(ISList* o, ISNode* x, ISNode** update)
{
   Int i;
  
   // Remove interval skip list node x.  The markers that the interval
   // x belongs to have already been removed.
   ISList__adjustMarkersOnDelete(o, x, update);

   // now splice out x.
   for (i = 0; i <= x->topLevel; i++) {
      update[i]->forward[i] = x->forward[i];
      x->forward[i] = NULL;   // must clobber forward pointers from x
   }

   ISNode__destruct(x);
}

// remove markers for Interval I starting at left, the left endpoint
// of I, and and stopping at the right endpoint of I.
static void ISList__removeMarkers(ISList* o, ISNode* left, Interval* I)
{
   Int i;
   // Remove markers for interval I, which has left as it's left
   // endpoint,  following a staircase pattern.

   // remove marks from ascending path
   ISNode* x = left;
   if (Interval__contains(I, x->key)) IList__remove(x->eqMarkers, I);
   i = 0;  // start at level 0 and go up
   while (NULL != x->forward[i]
        && Interval__containsI(I, x->key, x->forward[i]->key)) 
   {
      // find level to take mark from
      while (i != x->topLevel 
            && NULL != x->forward[i+1]
            && Interval__containsI(I, x->key, x->forward[i+1]->key))
         i++;
      // Remove mark from current level i edge since it is the highest edge out 
      // of x that contains I, except in the case where current level i edge
      // is null, in which case there are no markers on it.
      if (NULL != x->forward[i]) { 
         IList__remove(x->markers[i], I);  
         x = x->forward[i];
         // remove I from eqMarkers set on node unless currently at right 
         // endpoint of I and I doesn't contain right endpoint.
         if (Interval__contains(I, x->key)) IList__remove(x->eqMarkers, I);
      }
   }

   // remove marks from non-ascending path
   while (x->key != I->right) {
      // find level to remove mark from
      while (i != 0 && (x->forward[i] == 0 || 
                    !Interval__containsI(I, x->key, x->forward[i]->key)))
         i--;
      // At this point, we can assert that i=0 or x->forward[i]!=0 and I
      // contains (x->key,x->forward[i]->key).  In addition, x is between
      // left and right so i=0 implies I contains
      // (x->key,x->forward[i]->key).  Hence, the interval is marked and the
      // mark must be removed.  Note that it is impossible for us to be at
      // the end of the list because x->key is not equal to right->key.
      IList__remove(x->markers[i], I);
      x = x->forward[i];
      if (Interval__contains(I, x->key)) IList__remove(x->eqMarkers, I);     
   }
}

// delete an interval from list
void ISList__removeI(ISList* o, Interval* I)
{
   ISNode* right;
   // arrays for maintaining update pointers 
   ISNode* update[MAX_FORWARD]; 

   ISNode* left = ISList__search(o, I->left, update);
   my_assert(NULL != left && left->ownerCount > 0);
   ISList__removeMarkers(o, left, I);
   left->ownerCount--;
   if (0 == left->ownerCount) ISList__remove(o, left, update);

   // Note:  we search for right after removing left since some
   // of left's forward pointers may point to right.  We don't
   // want any pointers of update vector pointing to a node that is gone.

   right = ISList__search(o, I->right, update);
   my_assert(NULL != right && right->ownerCount > 0);
   right->ownerCount--;
   if (0 == right->ownerCount) ISList__remove(o, right, update);
}

// return one of the intervals overlapping V
static Bool ISList__findI2(ISList* o, Addr a, Bool find_zero, Interval** out)
{
   Int     i;
   ISNode* x = o->header;

   *out = NULL;

   for (i = o->maxLevel; i >= 0 && (ISNode__isHeader(x) || x->key != a); i--) 
   {
      while (NULL != x->forward[i] && a >= x->forward[i]->key)
         x = x->forward[i];

      if ( ! ISNode__isHeader(x) ) {
         if (x->key == a) 
            *out = IList__choose(x->eqMarkers,  *out, find_zero);
         else
            *out = IList__choose(x->markers[i], *out, find_zero);
      }
   }
   return ( NULL == *out ? False : True );
}

Bool ISList__findI (ISList* o, Addr a, Interval** out)
{
   return ISList__findI2(o, a, /*find_zero*/False, out);
}

Bool ISList__findI0(ISList* o, Addr a, Interval** out)
{
   return ISList__findI2(o, a, /*find_zero*/True, out);
}

// *** needs to be fixed: (actually can be deleted since it's not used.)
// place markers for Interval I.  I must have been inserted in the list.
// left is the left endpoint of I and right is the right endpoint if I.
static void ISList__placeMarkers(ISList* o, ISNode* left, 
                                 ISNode* right, Interval* I)
{
   Int i;
   // Place markers for the interval I.  left is the left endpoint
   // of I and right is the right endpoint of I, so it isn't necessary
   // to search to find the endpoints.

   ISNode* x = left;
   if (Interval__contains(I, x->key)) IList__insert(x->eqMarkers, I);
   i = 0;  // start at level 0 and go up
   while (NULL != x->forward[i]
        && Interval__containsI(I, x->key, x->forward[i]->key)) 
   {
      // find level to put mark on
      while (i != x->topLevel
            && NULL != x->forward[i+1]
            && Interval__containsI(I, x->key, x->forward[i+1]->key))
         i++;
      // Mark current level i edge since it is the highest edge out of
      // x that contains I, except in the case where current level i edge
      // is null, in which case it should never be marked.
      if (NULL != x->forward[i]) { 
         IList__insert(x->markers[i], I);  
         x = x->forward[i];
         // Add I to eqMarkers set on node unless currently at right endpoint
         // of I and I doesn't contain right endpoint.
         if (Interval__contains(I, x->key)) IList__insert(x->eqMarkers, I);
      }
   }

   // mark non-ascending path
   while (x->key != right->key) {
      // find level to put mark on
      while (i != 0 && (NULL == x->forward[i] || 
                    !Interval__containsI(I, x->key, x->forward[i]->key)))
         i--;
      // At this point, we can assert that i=0 or x->forward[i]!=0 and I
      // contains (x->key,x->forward[i]->key).  In addition, x is between
      // left and right so i=0 implies I contains
      // (x->key,x->forward[i]->key).  Hence, the interval must be marked.
      // Note that it is impossible for us to be at the end of the list
      // because x->key is not equal to right->key.
      IList__insert(x->markers[i], I);
      x = x->forward[i];
      if (Interval__contains(I, x->key)) IList__insert(x->eqMarkers, I);     
   }
}

// insert an interval into list
void ISList__insertI(ISList* o, Interval* I)
{
   // insert end points of interval
   ISNode* left  = ISList__insert(o, I->left);
   ISNode* right = ( I->right == I->left
                   ? left
                   : ISList__insert(o, I->right) );

   left ->ownerCount++;
   right->ownerCount++;

   // place markers on interval
   ISList__placeMarkers(o, left, right, I);
}

/*--------------------------------------------------------------------*/
/*--- end                                                pc_list.c ---*/
/*--------------------------------------------------------------------*/
