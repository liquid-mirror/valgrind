
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
//                                                             //
// BEGIN libhb_core.c (core library).  Do not compile          //
// Instead, is to be #included into libhb_sa.c or libhb_vg.c.  //
//                                                             //
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////

/*
   This file is part of LibHB, a library for implementing and checking
   the happens-before relationship in concurrent programs.

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

   //////////////////////////

   Note .. apart from those sections of the file which are copyright
   others of course .. only WordFM I believe.  Such sections will be
   moved out to separate files in due course.
*/

#include "libhb.h"

#undef VG_
#undef HG_

#define VG_(_xx) libhbPlainVG_##_xx
#define HG_(_xx) libhbPlainHG_##_xx

/* fwds for
   Globals needed by other parts of the library.  These are set
   once at startup and then never changed. */
static void*       (*main_zalloc)( HChar*, SizeT ) = NULL;
static void        (*main_dealloc)( void* ) = NULL;
static void*       (*main_shadow_alloc)( SizeT ) = NULL;
static void        (*main_get_stacktrace)( Thr*, Addr*, UWord ) = NULL;
static struct EC_* (*main_stacktrace_to_EC)( Addr*, UWord ) = NULL;
static struct EC_* (*main_get_EC)( Thr* ) = NULL;

/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
//                                                             //
//                                                             //
//                                                             //
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
//                                                             //
// SECTION BEGIN xarray                                        //
//                                                             //
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////

/*--------------------------------------------------------------------*/
/*--- An expandable array implementation.        pub_tool_xarray.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2007-2008 OpenWorks LLP
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

#ifndef __PUB_TOOL_XARRAY_H
#define __PUB_TOOL_XARRAY_H

//--------------------------------------------------------------------
// PURPOSE: Provides a simple but useful structure, which is an array
// in which elements can be added at the end.  The array is expanded
// as needed by multiplying its size by a constant factor (usually 2).
// This gives amortised O(1) insertion cost, and, following sorting,
// the usual O(log N) binary search cost.  Arbitrary element sizes
// are allowed; the comparison function for sort/lookup can be changed
// at any time, and duplicates (modulo the comparison function) are
// allowed.
//--------------------------------------------------------------------


/* It's an abstract type.  Bwaha. */
typedef  void  XArray;

/* Create new XArray, using given allocation and free function, and
   for elements of the specified size.  Alloc fn must not fail (that
   is, if it returns it must have succeeded.) */
extern XArray* VG_(newXA) ( void*(*alloc_fn)(HChar*,SizeT), 
                            HChar* cc,
                            void(*free_fn)(void*),
                            Word elemSzB );

/* Free all memory associated with an XArray. */
extern void VG_(deleteXA) ( XArray* );

/* Set the comparison function for this XArray.  This clears an
   internal 'array is sorted' flag, which means you must call sortXA
   before making further queries with lookupXA. */
extern void VG_(setCmpFnXA) ( XArray*, Int (*compar)(void*,void*) );

/* Add an element to an XArray.  Element is copied into the XArray.
   Index at which it was added is returned.  Note this will be
   invalidated if the array is later sortXA'd. */
extern Int VG_(addToXA) ( XArray*, void* elem );

/* Add a sequence of bytes to an XArray of bytes.  Asserts if nbytes
   is negative or the array's element size is not 1.  Returns the
   index at which the first byte was added. */
extern Int VG_(addBytesToXA) ( XArray* xao, void* bytesV, Int nbytes );

/* Sort an XArray using its comparison function, if set; else bomb.
   Probably not a stable sort w.r.t. equal elements module cmpFn. */
extern void VG_(sortXA) ( XArray* );

/* Lookup (by binary search) 'key' in the array.  Set *first to be the
   index of the first, and *last to be the index of the last matching
   value found.  If any values are found, return True, else return
   False, and don't change *first or *last.  Bomb if the array is not
   sorted. */
extern Bool VG_(lookupXA) ( XArray*, void* key, 
                            /*OUT*/Word* first, /*OUT*/Word* last );

/* How elements are there in this XArray now? */
extern Word VG_(sizeXA) ( XArray* );

/* Index into the XArray.  Checks bounds and bombs if the index is
   invalid.  What this returns is the address of the specified element
   in the array, not (of course) the element itself.  Note that the
   element may get moved by subsequent addToXAs/sortXAs, so you should
   copy it out immediately and not regard its address as unchanging.
   Note also that indexXA will of course not return NULL if it
   succeeds. */
extern void* VG_(indexXA) ( XArray*, Word );

/* Drop the last n elements of an XArray.  Bombs if there are less
   than n elements in the array. */
extern void VG_(dropTailXA) ( XArray*, Word );

/* Make a new, completely independent copy of the given XArray, using
   the existing allocation function to allocate the new space.
   Returns NULL if the allocation function didn't manage to allocate
   space (but did return NULL rather than merely abort.) */
extern XArray* VG_(cloneXA)( XArray* xa );

#endif   // __PUB_TOOL_XARRAY_H

/*--------------------------------------------------------------------*/
/*--- end                                        pub_tool_xarray.h ---*/
/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/
/*--- An expandable array implementation.               m_xarray.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2007-2008 OpenWorks LLP
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

/* See pub_tool_xarray.h for details of what this is all about. */

struct _XArray {
   void* (*alloc) ( HChar*, SizeT );        /* alloc fn (nofail) */
   HChar* cc;
   void  (*free) ( void* );         /* free fn */
   Int   (*cmpFn) ( void*, void* ); /* cmp fn (may be NULL) */
   Word  elemSzB;   /* element size in bytes */
   void* arr;       /* pointer to elements */
   Word  usedsizeE; /* # used elements in arr */
   Word  totsizeE;  /* max size of arr, in elements */
   Bool  sorted;    /* is it sorted? */
};


XArray* VG_(newXA) ( void*(*alloc_fn)(HChar*,SizeT), 
                     HChar* cc,
                     void(*free_fn)(void*),
                     Word elemSzB )
{
   struct _XArray* xa;
   /* Implementation relies on Word being signed and (possibly)
      on SizeT being unsigned. */
   vg_assert( sizeof(Word) == sizeof(void*) );
   vg_assert( ((Word)(-1)) < ((Word)(0)) );
   vg_assert( ((SizeT)(-1)) > ((SizeT)(0)) );
   /* check user-supplied info .. */
   vg_assert(alloc_fn);
   vg_assert(free_fn);
   vg_assert(elemSzB > 0);
   xa = alloc_fn( cc, sizeof(struct _XArray) );
   vg_assert(xa);
   xa->alloc     = alloc_fn;
   xa->cc        = cc;
   xa->free      = free_fn;
   xa->cmpFn     = NULL;
   xa->elemSzB   = elemSzB;
   xa->usedsizeE = 0;
   xa->totsizeE  = 0;
   xa->sorted    = False;
   xa->arr       = NULL;
   return xa;
}

XArray* VG_(cloneXA)( XArray* xao )
{
   struct _XArray* xa = (struct _XArray*)xao;
   struct _XArray* nyu;
   vg_assert(xa);
   vg_assert(xa->alloc);
   vg_assert(xa->free);
   vg_assert(xa->elemSzB >= 1);
   nyu = xa->alloc( xa->cc, sizeof(struct _XArray) );
   if (!nyu)
      return NULL;
   /* Copy everything verbatim ... */
   *nyu = *xa;
   /* ... except we have to clone the contents-array */
   if (nyu->arr) {
      nyu->arr = nyu->alloc( nyu->cc, nyu->totsizeE * nyu->elemSzB );
      if (!nyu->arr) {
         nyu->free(nyu);
         return NULL;
      }
      VG_(memcpy)( nyu->arr, xa->arr, nyu->totsizeE * nyu->elemSzB );
   }
   /* We're done! */
   return nyu;
}

void VG_(deleteXA) ( XArray* xao )
{
   struct _XArray* xa = (struct _XArray*)xao;
   vg_assert(xa);
   vg_assert(xa->free);
   if (xa->arr)
      xa->free(xa->arr);
   xa->free(xa);
}

void VG_(setCmpFnXA) ( XArray* xao, Int (*compar)(void*,void*) )
{
   struct _XArray* xa = (struct _XArray*)xao;
   vg_assert(xa);
   vg_assert(compar);
   xa->cmpFn  = compar;
   xa->sorted = False;
}

inline void* VG_(indexXA) ( XArray* xao, Word n )
{
   struct _XArray* xa = (struct _XArray*)xao;
   vg_assert(xa);
   vg_assert(n >= 0);
   vg_assert(n < xa->usedsizeE);
   return ((char*)xa->arr) + n * xa->elemSzB;
}

static inline void ensureSpaceXA ( struct _XArray* xa )
{
   if (xa->usedsizeE == xa->totsizeE) {
      void* tmp;
      Word  newsz;
      if (xa->totsizeE == 0)
         vg_assert(!xa->arr);
      if (xa->totsizeE > 0)
         vg_assert(xa->arr);
      if (xa->totsizeE == 0) {
         /* No point in having tiny (eg) 2-byte allocations for the
            element array, since all allocs are rounded up to 8 anyway.
            Hence increase the initial array size for tiny elements in
            an attempt to avoid reallocations of size 2, 4, 8 if the
            array does start to fill up. */
         if (xa->elemSzB == 1) newsz = 8;
         else if (xa->elemSzB == 2) newsz = 4;
         else newsz = 2;
      } else {
         newsz = 2 * xa->totsizeE;
      }
      if (0) 
         VG_(printf)("addToXA: increasing from %ld to %ld\n", 
                     xa->totsizeE, newsz);
      tmp = xa->alloc(xa->cc, newsz * xa->elemSzB);
      vg_assert(tmp);
      if (xa->usedsizeE > 0) 
         VG_(memcpy)(tmp, xa->arr, xa->usedsizeE * xa->elemSzB);
      if (xa->arr)
         xa->free(xa->arr);
      xa->arr = tmp;
      xa->totsizeE = newsz;
   }
}

Int VG_(addToXA) ( XArray* xao, void* elem )
{
   struct _XArray* xa = (struct _XArray*)xao;
   vg_assert(xa);
   vg_assert(elem);
   vg_assert(xa->totsizeE >= 0);
   vg_assert(xa->usedsizeE >= 0 && xa->usedsizeE <= xa->totsizeE);
   ensureSpaceXA( xa );
   vg_assert(xa->usedsizeE < xa->totsizeE);
   vg_assert(xa->arr);
   VG_(memcpy)( ((UChar*)xa->arr) + xa->usedsizeE * xa->elemSzB,
                elem, xa->elemSzB );
   xa->usedsizeE++;
   xa->sorted = False;
   return xa->usedsizeE-1;
}

Int VG_(addBytesToXA) ( XArray* xao, void* bytesV, Int nbytes )
{
   Int r, i;
   struct _XArray* xa = (struct _XArray*)xao;
   vg_assert(xa);
   vg_assert(xa->elemSzB == 1);
   vg_assert(nbytes >= 0);
   vg_assert(xa->totsizeE >= 0);
   vg_assert(xa->usedsizeE >= 0 && xa->usedsizeE <= xa->totsizeE);
   r = xa->usedsizeE;
   for (i = 0; i < nbytes; i++) {
      ensureSpaceXA( xa );
      vg_assert(xa->usedsizeE < xa->totsizeE);
      vg_assert(xa->arr);
      * (((UChar*)xa->arr) + xa->usedsizeE) = ((UChar*)bytesV)[i];
      xa->usedsizeE++;
   }
   xa->sorted = False;
   return r;
}

void VG_(sortXA) ( XArray* xao )
{
   struct _XArray* xa = (struct _XArray*)xao;
   vg_assert(xa);
   vg_assert(xa->cmpFn);
   VG_(ssort)( xa->arr, xa->usedsizeE, xa->elemSzB, xa->cmpFn );
   xa->sorted = True;
}

Bool VG_(lookupXA) ( XArray* xao, void* key, Word* first, Word* last )
{
   Word  lo, mid, hi, cres;
   void* midv;
   struct _XArray* xa = (struct _XArray*)xao;
   vg_assert(xa);
   vg_assert(xa->cmpFn);
   vg_assert(xa->sorted);
   vg_assert(first);
   vg_assert(last);
   lo = 0;
   hi = xa->usedsizeE-1;
   while (True) {
      /* current unsearched space is from lo to hi, inclusive. */
      if (lo > hi) return False; /* not found */
      mid  = (lo + hi) / 2;
      midv = VG_(indexXA)( xa, mid );
      cres = xa->cmpFn( key, midv );
      if (cres < 0)  { hi = mid-1; continue; }
      if (cres > 0)  { lo = mid+1; continue; }
      /* Found it, at mid.  See how far we can expand this. */
      vg_assert(xa->cmpFn( key, VG_(indexXA)(xa, lo) ) >= 0);
      vg_assert(xa->cmpFn( key, VG_(indexXA)(xa, hi) ) <= 0);
      *first = *last = mid;
      while (*first > 0 
             && 0 == xa->cmpFn( key, VG_(indexXA)(xa, (*first)-1)))
         (*first)--;
      while (*last < xa->usedsizeE-1
             && 0 == xa->cmpFn( key, VG_(indexXA)(xa, (*last)+1)))
         (*last)++;
      return True;
   }
}

Word VG_(sizeXA) ( XArray* xao )
{
   struct _XArray* xa = (struct _XArray*)xao;
   vg_assert(xa);
   return xa->usedsizeE;
}

void VG_(dropTailXA) ( XArray* xao, Word n )
{
   struct _XArray* xa = (struct _XArray*)xao;
   vg_assert(xa);
   vg_assert(n >= 0);
   vg_assert(n <= xa->usedsizeE);
   xa->usedsizeE -= n;
}

/*--------------------------------------------------------------------*/
/*--- end                                               m_xarray.c ---*/
/*--------------------------------------------------------------------*/

/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
//                                                             //
// SECTION END xarray                                          //
//                                                             //
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////



/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
//                                                             //
// SECTION BEGIN wordfm                                        //
//                                                             //
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////

/*--------------------------------------------------------------------*/
/*--- An AVL tree based finite map for word keys and word values.  ---*/
/*--- Inspired by Haskell's "FiniteMap" library.                   ---*/
/*---                                                  hg_wordfm.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Helgrind, a Valgrind tool for detecting errors
   in threaded programs.

   Copyright (C) 2007-2008 Julian Seward
      jseward@acm.org

   This code is based on previous work by Nicholas Nethercote
   (coregrind/m_oset.c) which is

   Copyright (C) 2005-2008 Nicholas Nethercote
       njn@valgrind.org

   which in turn was derived partially from:

      AVL C library
      Copyright (C) 2000,2002  Daniel Nagy

      This program is free software; you can redistribute it and/or
      modify it under the terms of the GNU General Public License as
      published by the Free Software Foundation; either version 2 of
      the License, or (at your option) any later version.
      [...]

      (taken from libavl-0.4/debian/copyright)

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

#ifndef __HG_WORDFM_H
#define __HG_WORDFM_H

//------------------------------------------------------------------//
//---                           WordFM                           ---//
//---                      Public interface                      ---//
//------------------------------------------------------------------//

/* As of r7409 (15 Feb 08), all these word-based abstractions (WordFM,
   WordSet, WordBag) now operate on unsigned words (UWord), whereas
   they previously operated on signed words (Word).  This became a
   problem, when using unboxed comparisons (when kCmp == NULL), with
   the introduction of HG_(initIterAtFM), which allows iteration over
   parts of mappings.  Iterating over a mapping in increasing order of
   signed Word keys is not what callers expect when iterating through
   maps whose keys represent addresses (Addr) since Addr is unsigned,
   and causes logical problems and assertion failures. */

typedef  struct _WordFM  WordFM; /* opaque */

/* Allocate and initialise a WordFM.  If kCmp is non-NULL, elements in
   the set are ordered according to the ordering specified by kCmp,
   which becomes obvious if you use VG_(initIterFM),
   VG_(initIterAtFM), VG_(nextIterFM), VG_(doneIterFM) to iterate over
   sections of the map, or the whole thing.  If kCmp is NULL then the
   ordering used is unsigned word ordering (UWord) on the key
   values. */
WordFM* HG_(newFM) ( void* (*alloc_nofail)( HChar*, SizeT ),
                     HChar* cc,
                     void  (*dealloc)(void*),
                     Word  (*kCmp)(UWord,UWord) );

/* Free up the FM.  If kFin is non-NULL, it is applied to keys before
   the FM is deleted; ditto with vFin and wFin for vals. */
void HG_(deleteFM) ( WordFM* fm, void(*kFin)(UWord), 
                                 void(*vFin)(UWord),
                                 void(*wFin)(UWord) );

/* Add (k,v,w) to fm.  If a binding for k already exists, it is
   updated to map to this new (v,w).  In that case we should really
   return the previous (v,w) so that caller can finalise them.  Oh
   well.  Returns True if a binding for k already exists.*/
Bool HG_(addToFM) ( WordFM* fm, UWord k, UWord v, UWord w );

// Delete key from fm, returning associated key and vals if found
Bool HG_(delFromFM) ( WordFM* fm,
                      /*OUT*/UWord* oldK,
                      /*OUT*/UWord* oldV, /*OUT*/UWord* oldW,
                      UWord key );

// Look up in fm, assigning found key & vals at spec'd addresses
Bool HG_(lookupFM) ( WordFM* fm, 
                     /*OUT*/UWord* resK,
                     /*OUT*/UWord* resV, /*OUT*/UWord* resW,
                     UWord key );

// How many elements are there in fm?  Note; slow; O(# elems in the fm)
UWord HG_(sizeFM) ( WordFM* fm );

// Is the fm empty?  Fast (constant-time)
Bool HG_(isEmptyFM)( WordFM* fm );

// If fm is non-empty, return arbitrarily chosen key/values
// through *res{K,V,W}, and return True.  If empty return False.
Bool HG_(anyElementOfFM) ( WordFM* fm,
                           /*OUT*/UWord* resK,
                           /*OUT*/UWord* resV, /*OUT*/UWord* resW );

// set up FM for iteration
void HG_(initIterFM) ( WordFM* fm );

// set up FM for iteration so that the first key subsequently produced
// by HG_(nextIterFM) is the smallest key in the map >= start_at.
// Naturally ">=" is defined by the comparison function supplied to
// HG_(newFM), as documented above.
void HG_(initIterAtFM) ( WordFM* fm, UWord start_at );

// get next key/vals.  Will assert if fm has been modified
// or looked up in since initIterFM/initIterWithStartFM was called.
Bool HG_(nextIterFM) ( WordFM* fm,
                       /*OUT*/UWord* resK,
                       /*OUT*/UWord* resV, /*OUT*/UWord* resW );

// clear the I'm iterating flag
void HG_(doneIterFM) ( WordFM* fm );

// Deep copy a FM.  If dopyK is NULL, keys are copied verbatim.
// If non-null, dopyK is applied to each key to generate the
// version in the new copy.  In that case, if the argument to dopyK
// is non-NULL but the result is NULL, it is assumed that dopyK
// could not allocate memory, in which case the copy is abandoned
// and NULL is returned.  Ditto with dopyV and dopyW for values.
WordFM* HG_(dopyFM) ( WordFM* fm,
                      UWord(*dopyK)(UWord), 
                      UWord(*dopyV)(UWord), UWord(*dopyW)(UWord) );

//------------------------------------------------------------------//
//---                         end WordFM                         ---//
//---                      Public interface                      ---//
//------------------------------------------------------------------//

//------------------------------------------------------------------//
//---                WordBag (unboxed words only)                ---//
//---                      Public interface                      ---//
//------------------------------------------------------------------//

//typedef  struct _WordBag  WordBag; /* opaque */

// FIXME! find some way to turn this back into an abstract type.
typedef
   struct {
      void*   (*alloc_nofail)( HChar*, SizeT );
      HChar*  cc;
      void    (*dealloc)(void*);
      UWord   firstWord;
      UWord   firstCount;
      WordFM* rest;
      /* When zero, the next call to HG_(nextIterBag) gives
         (.firstWord, .firstCount).  When nonzero, such calls traverse
         .rest. */
      UWord   iterCount;
   }
   WordBag;


/* Initialise a WordBag and make it empty.  Only do this once for each
   bag, at the start of its lifetime. */
void HG_(initBag) ( WordBag* bag,
                    void* (*alloc_nofail)( HChar*, SizeT ),
                    HChar* cc,
                    void  (*dealloc)(void*) );

/* Remove all elements from a bag, thereby making it empty, and free
   all associated memory.  This can be done as many times as required,
   but only after the initial HG_(initBag) call. */
void HG_(emptyOutBag) ( WordBag* bag );

/* Add a word. */
void HG_(addToBag)( WordBag*, UWord );

/* Find out how many times the given word exists in the bag. */
UWord HG_(elemBag) ( WordBag*, UWord );

/* Delete a word from the bag. */
Bool HG_(delFromBag)( WordBag*, UWord );

/* Is the bag empty? */
Bool HG_(isEmptyBag)( WordBag* );

/* Is the bag empty, skipping all sanity checks? */
static inline Bool HG_(isEmptyBag_UNCHECKED)( WordBag* bag ) {
   return bag->firstCount == 0;
}

/* Does the bag have exactly one element? */
Bool HG_(isSingletonTotalBag)( WordBag* );

/* Return an arbitrary element from the bag. */
UWord HG_(anyElementOfBag)( WordBag* );

/* How many different / total elements are in the bag? */
UWord HG_(sizeUniqueBag)( WordBag* ); /* warning: slow */
UWord HG_(sizeTotalBag)( WordBag* );  /* warning: very slow */

/* Iterating over the elements of a bag. */
void HG_(initIterBag)( WordBag* );
Bool HG_(nextIterBag)( WordBag*, /*OUT*/UWord* pVal, /*OUT*/UWord* pCount );
void HG_(doneIterBag)( WordBag* );

//------------------------------------------------------------------//
//---             end WordBag (unboxed words only)               ---//
//---                      Public interface                      ---//
//------------------------------------------------------------------//

#endif /* ! __HG_WORDFM_H */

/*--------------------------------------------------------------------*/
/*--- end                                              hg_wordfm.h ---*/
/*--------------------------------------------------------------------*/

/*--------------------------------------------------------------------*/
/*--- An AVL tree based finite map for word keys and word values.  ---*/
/*--- Inspired by Haskell's "FiniteMap" library.                   ---*/
/*---                                                  hg_wordfm.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Helgrind, a Valgrind tool for detecting errors
   in threaded programs.

   Copyright (C) 2007-2008 Julian Seward
      jseward@acm.org

   This code is based on previous work by Nicholas Nethercote
   (coregrind/m_oset.c) which is

   Copyright (C) 2005-2008 Nicholas Nethercote
       njn@valgrind.org

   which in turn was derived partially from:

      AVL C library
      Copyright (C) 2000,2002  Daniel Nagy

      This program is free software; you can redistribute it and/or
      modify it under the terms of the GNU General Public License as
      published by the Free Software Foundation; either version 2 of
      the License, or (at your option) any later version.
      [...]

      (taken from libavl-0.4/debian/copyright)

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

#if 0
#include "pub_tool_basics.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcbase.h"


#ifdef HG_WORDFM_STANDALONE  // standalone compilation
// Standalone mode (for testing). 
// On x86_64 compile like this: 
//   gcc -m64 hg_wordfm.c -I../include -I../VEX/pub
//       -DVGA_amd64=1 -DHG_WORDFM_STANDALONE -g -O -Wall
# include <assert.h>
# include <string.h>
# include <stdio.h>
# include <stdlib.h>

# undef  tl_assert
# define tl_assert assert
# define vgPlain_memset memset

#endif /* def HG_WORDFM_STANDALONE */
#endif /* 0 */


//------------------------------------------------------------------//
//---                           WordFM                           ---//
//---                       Implementation                       ---//
//------------------------------------------------------------------//

/* One element of the AVL tree */
typedef
   struct _AvlNode {
      UWord key;
      UWord val;
      UWord wal;
      struct _AvlNode* child[2]; /* [0] is left subtree, [1] is right */
      Char balance; /* do not make this unsigned */
   }
   AvlNode;

typedef 
   struct {
      UWord w;
      Bool b;
   }
   MaybeWord;

#define WFM_STKMAX    32    // At most 2**32 entries can be iterated over

struct _WordFM {
   AvlNode* root;
   void*    (*alloc_nofail)( HChar*, SizeT );
   HChar*   cc;
   void     (*dealloc)(void*);
   Word     (*kCmp)(UWord,UWord);
   AvlNode* nodeStack[WFM_STKMAX]; // Iterator node stack
   Int      numStack[WFM_STKMAX];  // Iterator num stack
   Int      stackTop;              // Iterator stack pointer, one past end
}; 

/* forward */
static Bool avl_removeroot_wrk(AvlNode** t, Word(*kCmp)(UWord,UWord));

/* Swing to the left.  Warning: no balance maintainance. */
static void avl_swl ( AvlNode** root )
{
   AvlNode* a  = *root;
   AvlNode* b  = a->child[1];
   *root       = b;
   a->child[1] = b->child[0];
   b->child[0] = a;
}

/* Swing to the right.  Warning: no balance maintainance. */
static void avl_swr ( AvlNode** root )
{
   AvlNode* a  = *root;
   AvlNode* b  = a->child[0];
   *root       = b;
   a->child[0] = b->child[1];
   b->child[1] = a;
}

/* Balance maintainance after especially nasty swings. */
static void avl_nasty ( AvlNode* root )
{
   switch (root->balance) {
      case -1: 
         root->child[0]->balance = 0;
         root->child[1]->balance = 1;
         break;
      case 1:
         root->child[0]->balance = -1;
         root->child[1]->balance = 0;
         break;
      case 0:
         root->child[0]->balance = 0;
         root->child[1]->balance = 0;
         break;
      default:
         tl_assert(0);
   }
   root->balance=0;
}

/* Find size of a non-NULL tree. */
static UWord size_avl_nonNull ( AvlNode* nd )
{
   return 1 + (nd->child[0] ? size_avl_nonNull(nd->child[0]) : 0)
            + (nd->child[1] ? size_avl_nonNull(nd->child[1]) : 0);
}

/* Unsignedly compare w1 and w2.  If w1 < w2, produce a negative
   number; if w1 > w2 produce a positive number, and if w1 == w2
   produce zero. */
static inline Word cmp_unsigned_Words ( UWord w1, UWord w2 ) {
   if (w1 < w2) return -1;
   if (w1 > w2) return 1;
   return 0;
}

/* Insert element a into the AVL tree t.  Returns True if the depth of
   the tree has grown.  If element with that key is already present,
   just copy a->val to existing node, first returning old ->val field
   of existing node in *oldV, so that the caller can finalize it
   however it wants.
*/
static 
Bool avl_insert_wrk ( AvlNode**         rootp, 
                      /*OUT*/MaybeWord* oldV,
                      AvlNode*          a, 
                      Word              (*kCmp)(UWord,UWord) )
{
   Word cmpres;

   /* initialize */
   a->child[0] = 0;
   a->child[1] = 0;
   a->balance  = 0;
   oldV->b     = False;

   /* insert into an empty tree? */
   if (!(*rootp)) {
      (*rootp) = a;
      return True;
   }

   cmpres = kCmp ? /*boxed*/   kCmp( (*rootp)->key, a->key )
                 : /*unboxed*/ cmp_unsigned_Words( (UWord)(*rootp)->key,
                                                   (UWord)a->key );

   if (cmpres > 0) {
      /* insert into the left subtree */
      if ((*rootp)->child[0]) {
         AvlNode* left_subtree = (*rootp)->child[0];
         if (avl_insert_wrk(&left_subtree, oldV, a, kCmp)) {
            switch ((*rootp)->balance--) {
               case  1: return False;
               case  0: return True;
               case -1: break;
               default: tl_assert(0);
            }
            if ((*rootp)->child[0]->balance < 0) {
               avl_swr( rootp );
               (*rootp)->balance = 0;
               (*rootp)->child[1]->balance = 0;
            } else {
               avl_swl( &((*rootp)->child[0]) );
               avl_swr( rootp );
               avl_nasty( *rootp );
            }
         } else {
            (*rootp)->child[0] = left_subtree;
         }
         return False;
      } else {
         (*rootp)->child[0] = a;
         if ((*rootp)->balance--) 
            return False;
         return True;
      }
      tl_assert(0);/*NOTREACHED*/
   }
   else 
   if (cmpres < 0) {
      /* insert into the right subtree */
      if ((*rootp)->child[1]) {
         AvlNode* right_subtree = (*rootp)->child[1];
         if (avl_insert_wrk(&right_subtree, oldV, a, kCmp)) {
            switch((*rootp)->balance++){
               case -1: return False;
               case  0: return True;
               case  1: break;
               default: tl_assert(0);
            }
            if ((*rootp)->child[1]->balance > 0) {
               avl_swl( rootp );
               (*rootp)->balance = 0;
               (*rootp)->child[0]->balance = 0;
            } else {
               avl_swr( &((*rootp)->child[1]) );
               avl_swl( rootp );
               avl_nasty( *rootp );
            }
         } else {
            (*rootp)->child[1] = right_subtree;
         }
         return False;
      } else {
         (*rootp)->child[1] = a;
         if ((*rootp)->balance++) 
            return False;
         return True;
      }
      tl_assert(0);/*NOTREACHED*/
   }
   else {
      /* cmpres == 0, a duplicate - replace the val, but don't
         incorporate the node in the tree */
      oldV->b = True;
      oldV->w = (*rootp)->val;
      (*rootp)->val = a->val;
      return False;
   }
}

/* Remove an element a from the AVL tree t.  a must be part of
   the tree.  Returns True if the depth of the tree has shrunk. 
*/
static
Bool avl_remove_wrk ( AvlNode** rootp, 
                      AvlNode*  a, 
                      Word(*kCmp)(UWord,UWord) )
{
   Bool ch;
   Word cmpres;
   cmpres = kCmp ? /*boxed*/   kCmp( (*rootp)->key, a->key )
                 : /*unboxed*/ cmp_unsigned_Words( (UWord)(*rootp)->key,
                                                   (UWord)a->key );

   if (cmpres > 0){
      /* remove from the left subtree */
      AvlNode* left_subtree = (*rootp)->child[0];
      tl_assert(left_subtree);
      ch = avl_remove_wrk(&left_subtree, a, kCmp);
      (*rootp)->child[0]=left_subtree;
      if (ch) {
         switch ((*rootp)->balance++) {
            case -1: return True;
            case  0: return False;
            case  1: break;
            default: tl_assert(0);
         }
         switch ((*rootp)->child[1]->balance) {
            case 0:
               avl_swl( rootp );
               (*rootp)->balance = -1;
               (*rootp)->child[0]->balance = 1;
               return False;
            case 1: 
               avl_swl( rootp );
               (*rootp)->balance = 0;
               (*rootp)->child[0]->balance = 0;
               return True;
            case -1:
               break;
            default:
               tl_assert(0);
         }
         avl_swr( &((*rootp)->child[1]) );
         avl_swl( rootp );
         avl_nasty( *rootp );
         return True;
      }
   }
   else
   if (cmpres < 0) {
      /* remove from the right subtree */
      AvlNode* right_subtree = (*rootp)->child[1];
      tl_assert(right_subtree);
      ch = avl_remove_wrk(&right_subtree, a, kCmp);
      (*rootp)->child[1] = right_subtree;
      if (ch) {
         switch ((*rootp)->balance--) {
            case  1: return True;
            case  0: return False;
            case -1: break;
            default: tl_assert(0);
         }
         switch ((*rootp)->child[0]->balance) {
            case 0:
               avl_swr( rootp );
               (*rootp)->balance = 1;
               (*rootp)->child[1]->balance = -1;
               return False;
            case -1:
               avl_swr( rootp );
               (*rootp)->balance = 0;
               (*rootp)->child[1]->balance = 0;
               return True;
            case 1:
               break;
            default:
               tl_assert(0);
         }
         avl_swl( &((*rootp)->child[0]) );
         avl_swr( rootp );
         avl_nasty( *rootp );
         return True;
      }
   }
   else {
      tl_assert(cmpres == 0);
      tl_assert((*rootp)==a);
      return avl_removeroot_wrk(rootp, kCmp);
   }
   return 0;
}

/* Remove the root of the AVL tree *rootp.
 * Warning: dumps core if *rootp is empty
 */
static 
Bool avl_removeroot_wrk ( AvlNode** rootp, 
                          Word(*kCmp)(UWord,UWord) )
{
   Bool     ch;
   AvlNode* a;
   if (!(*rootp)->child[0]) {
      if (!(*rootp)->child[1]) {
         (*rootp) = 0;
         return True;
      }
      (*rootp) = (*rootp)->child[1];
      return True;
   }
   if (!(*rootp)->child[1]) {
      (*rootp) = (*rootp)->child[0];
      return True;
   }
   if ((*rootp)->balance < 0) {
      /* remove from the left subtree */
      a = (*rootp)->child[0];
      while (a->child[1]) a = a->child[1];
   } else {
      /* remove from the right subtree */
      a = (*rootp)->child[1];
      while (a->child[0]) a = a->child[0];
   }
   ch = avl_remove_wrk(rootp, a, kCmp);
   a->child[0] = (*rootp)->child[0];
   a->child[1] = (*rootp)->child[1];
   a->balance  = (*rootp)->balance;
   (*rootp)    = a;
   if(a->balance == 0) return ch;
   return False;
}

static 
AvlNode* avl_find_node ( AvlNode* t, Word k, Word(*kCmp)(UWord,UWord) )
{
   if (kCmp) {
      /* Boxed comparisons */
      Word cmpresS;
      while (True) {
         if (t == NULL) return NULL;
         cmpresS = kCmp(t->key, k);
         if (cmpresS > 0) t = t->child[0]; else
         if (cmpresS < 0) t = t->child[1]; else
         return t;
      }
   } else {
      /* Unboxed comparisons */
      Word  cmpresS; /* signed */
      UWord cmpresU; /* unsigned */
      while (True) {
         if (t == NULL) return NULL; /* unlikely ==> predictable */
         cmpresS = cmp_unsigned_Words( (UWord)t->key, (UWord)k );
         if (cmpresS == 0) return t; /* unlikely ==> predictable */
         cmpresU = (UWord)cmpresS;
         cmpresU >>=/*unsigned*/ (8 * sizeof(cmpresU) - 1);
         t = t->child[cmpresU];
      }
   }
}

// Clear the iterator stack.
static void stackClear(WordFM* fm)
{
   Int i;
   tl_assert(fm);
   for (i = 0; i < WFM_STKMAX; i++) {
      fm->nodeStack[i] = NULL;
      fm->numStack[i]  = 0;
   }
   fm->stackTop = 0;
}

// Push onto the iterator stack.
static inline void stackPush(WordFM* fm, AvlNode* n, Int i)
{
   tl_assert(fm->stackTop < WFM_STKMAX);
   tl_assert(1 <= i && i <= 3);
   fm->nodeStack[fm->stackTop] = n;
   fm-> numStack[fm->stackTop] = i;
   fm->stackTop++;
}

// Pop from the iterator stack.
static inline Bool stackPop(WordFM* fm, AvlNode** n, Int* i)
{
   tl_assert(fm->stackTop <= WFM_STKMAX);

   if (fm->stackTop > 0) {
      fm->stackTop--;
      *n = fm->nodeStack[fm->stackTop];
      *i = fm-> numStack[fm->stackTop];
      tl_assert(1 <= *i && *i <= 3);
      fm->nodeStack[fm->stackTop] = NULL;
      fm-> numStack[fm->stackTop] = 0;
      return True;
   } else {
      return False;
   }
}

static 
AvlNode* avl_dopy ( AvlNode* nd, 
                    UWord(*dopyK)(UWord), 
                    UWord(*dopyV)(UWord),
                    UWord(*dopyW)(UWord),
                    void*(alloc_nofail)(HChar*,SizeT),
                    HChar* cc )
{
   AvlNode* nyu;
   if (! nd)
      return NULL;
   nyu = alloc_nofail(cc, sizeof(AvlNode));
   tl_assert(nyu);
   
   nyu->child[0] = nd->child[0];
   nyu->child[1] = nd->child[1];
   nyu->balance = nd->balance;

   /* Copy key */
   if (dopyK) {
      nyu->key = dopyK( nd->key );
      if (nd->key != 0 && nyu->key == 0)
         return NULL; /* oom in key dcopy */
   } else {
      /* copying assumedly unboxed keys */
      nyu->key = nd->key;
   }

   /* Copy val */
   if (dopyV) {
      nyu->val = dopyV( nd->val );
      if (nd->val != 0 && nyu->val == 0)
         return NULL; /* oom in val dcopy */
   } else {
      /* copying assumedly unboxed vals */
      nyu->val = nd->val;
   }

   /* Copy second val */
   if (dopyW) {
      nyu->wal = dopyW( nd->wal );
      if (nd->wal != 0 && nyu->wal == 0)
         return NULL; /* oom in wal dcopy */
   } else {
      /* copying assumedly unboxed wals */
      nyu->wal = nd->wal;
   }

   /* Copy subtrees */
   if (nyu->child[0]) {
      nyu->child[0] = avl_dopy( nyu->child[0],
                                dopyK, dopyV, dopyW, alloc_nofail, cc );
      if (! nyu->child[0])
         return NULL;
   }
   if (nyu->child[1]) {
      nyu->child[1] = avl_dopy( nyu->child[1],
                                dopyK, dopyV, dopyW, alloc_nofail, cc );
      if (! nyu->child[1])
         return NULL;
   }

   return nyu;
}

/* Initialise a WordFM. */
static void initFM ( WordFM* fm,
                     void*   (*alloc_nofail)( HChar*, SizeT ),
                     HChar*  cc,
                     void    (*dealloc)(void*),
                     Word    (*kCmp)(UWord,UWord) )
{
   fm->root         = NULL;
   fm->kCmp         = kCmp;
   fm->alloc_nofail = alloc_nofail;
   fm->cc           = cc;
   fm->dealloc      = dealloc;
   fm->stackTop     = 0;
}

/* --- Public interface functions --- */

/* Allocate and initialise a WordFM.  If kCmp is non-NULL, elements in
   the set are ordered according to the ordering specified by kCmp,
   which becomes obvious if you use VG_(initIterFM),
   VG_(initIterAtFM), VG_(nextIterFM), VG_(doneIterFM) to iterate over
   sections of the map, or the whole thing.  If kCmp is NULL then the
   ordering used is unsigned word ordering (UWord) on the key
   values. */
WordFM* HG_(newFM) ( void* (*alloc_nofail)( HChar*, SizeT ),
                     HChar* cc,
                     void  (*dealloc)(void*),
                     Word  (*kCmp)(UWord,UWord) )
{
   WordFM* fm = alloc_nofail(cc, sizeof(WordFM));
   tl_assert(fm);
   initFM(fm, alloc_nofail, cc, dealloc, kCmp);
   return fm;
}

static void avl_free ( AvlNode* nd, 
                       void(*kFin)(UWord),
                       void(*vFin)(UWord),
                       void(*wFin)(UWord),
                       void(*dealloc)(void*) )
{
   if (!nd)
      return;
   if (nd->child[0])
      avl_free(nd->child[0], kFin, vFin, wFin, dealloc);
   if (nd->child[1])
      avl_free(nd->child[1], kFin, vFin, wFin, dealloc);
   if (kFin)
      kFin( nd->key );
   if (vFin)
      vFin( nd->val );
   if (wFin)
      wFin( nd->wal );
   VG_(memset)(nd, 0, sizeof(AvlNode));
   dealloc(nd);
}

/* Free up the FM.  If kFin is non-NULL, it is applied to keys before
   the FM is deleted; ditto with vFin and wFin for vals. */
void HG_(deleteFM) ( WordFM* fm, void(*kFin)(UWord), 
                                 void(*vFin)(UWord),
                                 void(*wFin)(UWord) )
{
   void(*dealloc)(void*) = fm->dealloc;
   if (fm->root)
      avl_free( fm->root, kFin, vFin, wFin, dealloc );
   VG_(memset)(fm, 0, sizeof(WordFM) );
   dealloc(fm);
}

/* Add (k,v,w) to fm. */
Bool HG_(addToFM) ( WordFM* fm, UWord k, UWord v, UWord w )
{
   MaybeWord oldV;
   AvlNode* node;
   node = fm->alloc_nofail( fm->cc, sizeof(struct _AvlNode) );
   node->key = k;
   node->val = v;
   node->wal = w;
   oldV.b = False;
   oldV.w = 0;
   avl_insert_wrk( &fm->root, &oldV, node, fm->kCmp );
   //if (oldV.b && fm->vFin)
   //   fm->vFin( oldV.w );
   if (oldV.b)
      fm->dealloc(node);
   return oldV.b;
}

// Delete key from fm, returning associated key and vals if found
Bool HG_(delFromFM) ( WordFM* fm,
                      /*OUT*/UWord* oldK,
                      /*OUT*/UWord* oldV, /*OUT*/UWord* oldW,
                      UWord key )
{
   AvlNode* node = avl_find_node( fm->root, key, fm->kCmp );
   if (node) {
      avl_remove_wrk( &fm->root, node, fm->kCmp );
      if (oldK)
         *oldK = node->key;
      if (oldV)
         *oldV = node->val;
      if (oldW)
         *oldW = node->wal;
      fm->dealloc(node);
      return True;
   } else {
      return False;
   }
}

// Look up in fm, assigning found key & vals at spec'd addresses
Bool HG_(lookupFM) ( WordFM* fm, 
                     /*OUT*/UWord* resK,
                     /*OUT*/UWord* resV, /*OUT*/UWord* resW,
                     UWord key )
{
   AvlNode* node = avl_find_node( fm->root, key, fm->kCmp );
   if (node) {
      if (resK)
         *resK = node->key;
      if (resV)
         *resV = node->val;
      if (resW)
         *resW = node->wal;
      return True;
   } else {
      return False;
   }
}

UWord HG_(sizeFM) ( WordFM* fm )
{
   // Hmm, this is a bad way to do this
   return fm->root ? size_avl_nonNull( fm->root ) : 0;
}

Bool HG_(isEmptyFM)( WordFM* fm )
{
   return fm->root == NULL;
}

Bool HG_(anyElementOfFM) ( WordFM* fm,
                           /*OUT*/UWord* resK,
                           /*OUT*/UWord* resV, /*OUT*/UWord* resW )
{
   if (!fm->root)
      return False;
   if (resK)
      *resK = fm->root->key;
   if (resV)
      *resV = fm->root->val;
   if (resW)
      *resW = fm->root->wal;
   return True;
}

// set up FM for iteration
void HG_(initIterFM) ( WordFM* fm )
{
   tl_assert(fm);
   stackClear(fm);
   if (fm->root)
      stackPush(fm, fm->root, 1);
}

// set up FM for iteration so that the first key subsequently produced
// by HG_(nextIterFM) is the smallest key in the map >= start_at.
// Naturally ">=" is defined by the comparison function supplied to
// HG_(newFM), as documented above.
void HG_(initIterAtFM) ( WordFM* fm, UWord start_at )
{
   Int     i;
   AvlNode *n, *t;
   Word    cmpresS; /* signed */
   UWord   cmpresU; /* unsigned */

   tl_assert(fm);
   stackClear(fm);

   if (!fm->root) 
      return;

   n = NULL;
   // We need to do regular search and fill in the stack. 
   t = fm->root;

   while (True) {
      if (t == NULL) return;

      cmpresS 
         = fm->kCmp ? /*boxed*/   fm->kCmp( t->key, start_at )
                    : /*unboxed*/ cmp_unsigned_Words( t->key, start_at );

      if (cmpresS == 0) {
         // We found the exact key -- we are done. 
         // The iteration should start with this node.
         stackPush(fm, t, 2);
         // The stack now looks like {2, 2, ... ,2, 2}
         return;
      }
      cmpresU = (UWord)cmpresS;
      cmpresU >>=/*unsigned*/ (8 * sizeof(cmpresU) - 1);
      if (!cmpresU) {
         // Push this node only if we go to the left child. 
         stackPush(fm, t, 2);
      }
      t = t->child[cmpresU];
   }
   if (stackPop(fm, &n, &i)) {
      // If we've pushed something to stack and did not find the exact key, 
      // we must fix the top element of stack. 
      tl_assert(i == 2);
      stackPush(fm, n, 3);
      // the stack looks like {2, 2, ..., 2, 3}
   }
}

// get next key/vals.  Will assert if fm has been modified
// or looked up in since initIterFM/initIterWithStartFM was called.
Bool HG_(nextIterFM) ( WordFM* fm,
                       /*OUT*/UWord* resK,
                       /*OUT*/UWord* resV, /*OUT*/UWord* resW )
{
   Int i = 0;
   AvlNode* n = NULL;
   
   tl_assert(fm);

   // This in-order traversal requires each node to be pushed and popped
   // three times.  These could be avoided by updating nodes in-situ on the
   // top of the stack, but the push/pop cost is so small that it's worth
   // keeping this loop in this simpler form.
   while (stackPop(fm, &n, &i)) {
      switch (i) {
      case 1: case_1:
         stackPush(fm, n, 2);
         /* if (n->child[0])  stackPush(fm, n->child[0], 1); */
         if (n->child[0]) { n = n->child[0]; goto case_1; }
         break;
      case 2: 
         stackPush(fm, n, 3);
         if (resK) *resK = n->key;
         if (resV) *resV = n->val;
         if (resW) *resW = n->wal;
         return True;
      case 3:
         /* if (n->child[1]) stackPush(fm, n->child[1], 1); */
         if (n->child[1]) { n = n->child[1]; goto case_1; }
         break;
      default:
         tl_assert(0);
      }
   }

   // Stack empty, iterator is exhausted, return NULL
   return False;
}

// clear the I'm iterating flag
void HG_(doneIterFM) ( WordFM* fm )
{
}

WordFM* HG_(dopyFM) ( WordFM* fm,
                      UWord(*dopyK)(UWord), 
                      UWord(*dopyV)(UWord), UWord(*dopyW)(UWord) )
{
   WordFM* nyu; 

   /* can't clone the fm whilst iterating on it */
   tl_assert(fm->stackTop == 0);

   nyu = fm->alloc_nofail( fm->cc, sizeof(WordFM) );
   tl_assert(nyu);

   *nyu = *fm;

   fm->stackTop = 0;
   VG_(memset)(fm->nodeStack, 0, sizeof(fm->nodeStack));
   VG_(memset)(fm->numStack, 0,  sizeof(fm->numStack));

   if (nyu->root) {
      nyu->root = avl_dopy( nyu->root,
                            dopyK, dopyV, dopyW,
                            fm->alloc_nofail, fm->cc );
      if (! nyu->root)
         return NULL;
   }

   return nyu;
}

//------------------------------------------------------------------//
//---                         end WordFM                         ---//
//---                       Implementation                       ---//
//------------------------------------------------------------------//

//------------------------------------------------------------------//
//---                WordBag (unboxed words only)                ---//
//---                       Implementation                       ---//
//------------------------------------------------------------------//

//struct _WordBag {
//   void*   (*alloc_nofail)( SizeT );
//   void    (*dealloc)(void*);
//   UWord   firstWord;
//   UWord   firstCount;
//   WordFM* rest;
//   /* When zero, the next call to HG_(nextIterBag) gives
//      (.firstWord, .firstCount).  When nonzero, such calls traverse
//      .rest. */
//   UWord   iterCount;
//};

/* Representational invariants.  Either:

   * bag is empty
       firstWord == firstCount == 0
       rest == NULL

   * bag contains just one unique element
       firstCount > 0
       rest == NULL

   * bag contains more than one unique element
       firstCount > 0
       rest != NULL

   If rest != NULL, then 
   (1) firstWord != any .key in rest, and
   (2) all .val in rest > 0
*/

static inline Bool is_plausible_WordBag ( WordBag* bag ) {
   if (bag->firstWord == 0 && bag->firstCount == 0 && bag->rest == NULL)
      return True;
   if (bag->firstCount > 0 && bag->rest == NULL)
      return True;
   if (bag->firstCount > 0 && bag->rest != NULL)
      /* really should check (1) and (2) now, but that's
         v. expensive */
      return True;
   return False;
}

void HG_(initBag) ( WordBag* bag,
                    void* (*alloc_nofail)( HChar*, SizeT ),
                    HChar* cc,
                    void  (*dealloc)(void*) )
{
   bag->alloc_nofail = alloc_nofail;
   bag->cc           = cc;
   bag->dealloc      = dealloc;
   bag->firstWord    = 0;
   bag->firstCount   = 0;
   bag->rest         = NULL;
   bag->iterCount    = 0;
}

void HG_(emptyOutBag) ( WordBag* bag )
{
   if (bag->rest)
      HG_(deleteFM)( bag->rest, NULL, NULL, NULL );
   /* Don't zero out the alloc and dealloc function pointers, since we
      want to be able to keep on using this bag later, without having
      to call HG_(initBag) again. */
   bag->firstWord    = 0;
   bag->firstCount   = 0;
   bag->rest         = NULL;
   bag->iterCount    = 0;
}

void HG_(addToBag)( WordBag* bag, UWord w )
{
   tl_assert(is_plausible_WordBag(bag));
   /* case where the bag is completely empty */
   if (bag->firstCount == 0) {
      tl_assert(bag->firstWord == 0 && bag->rest == NULL);
      bag->firstWord  = w;
      bag->firstCount = 1;
      return;
   }
   /* there must be at least one element in it */
   tl_assert(bag->firstCount > 0);
   if (bag->firstWord == w) {
      bag->firstCount++;
      return;
   }
   /* it's not the Distinguished Element.  Try the rest */
   { UWord key, count;
     if (bag->rest == NULL) {
       bag->rest = HG_(newFM)( bag->alloc_nofail, bag->cc, bag->dealloc,
                                NULL/*unboxed uword cmp*/ );
     }
     tl_assert(bag->rest);
     if (HG_(lookupFM)(bag->rest, &key, &count, NULL, w)) {
        tl_assert(key == w);
        tl_assert(count >= 1);
        HG_(addToFM)(bag->rest, w, count+1, (UWord)0/*unused*/ );
     } else {
        HG_(addToFM)(bag->rest, w, 1, (UWord)0/*unused*/ );
     }
   }
}

UWord HG_(elemBag) ( WordBag* bag, UWord w )
{
   tl_assert(is_plausible_WordBag(bag));
   if (bag->firstCount == 0) {
      return 0;
   }
   if (w == bag->firstWord) {
      return bag->firstCount;
   }
   if (!bag->rest) {
      return 0;
   }
   { UWord key, count;
     if (HG_(lookupFM)( bag->rest, &key, &count, NULL, w)) {
        tl_assert(key == w);
        tl_assert(count >= 1);
        return count;
     } else {
        return 0;
     }
   }
}

UWord HG_(sizeUniqueBag) ( WordBag* bag )
{
   tl_assert(is_plausible_WordBag(bag));
   if (bag->firstCount == 0) {
      tl_assert(bag->firstWord == 0);
      tl_assert(bag->rest == NULL);
      return 0;
   }
   return 1 + (bag->rest ? HG_(sizeFM)( bag->rest ) : 0);
}

static UWord sizeTotalBag_wrk ( AvlNode* nd )
{
   /* unchecked pre: nd is non-NULL */
   UWord w = nd->val;
   tl_assert(w >= 1);
   if (nd->child[0])
      w += sizeTotalBag_wrk(nd->child[0]);
   if (nd->child[1])
      w += sizeTotalBag_wrk(nd->child[1]);
   return w;
}
UWord HG_(sizeTotalBag)( WordBag* bag )
{
   UWord res;
   tl_assert(is_plausible_WordBag(bag));
   if (bag->firstCount == 0) {
      tl_assert(bag->firstWord == 0);
      tl_assert(bag->rest == NULL);
      return 0;
   }
   res = bag->firstCount;
   if (bag->rest && bag->rest->root)
      res += sizeTotalBag_wrk( bag->rest->root );
   return res;
}

Bool HG_(delFromBag)( WordBag* bag, UWord w )
{
   tl_assert(is_plausible_WordBag(bag));

   /* Case: bag is empty */
   if (bag->firstCount == 0) {
      /* empty */
      tl_assert(bag->firstWord == 0 && bag->rest == NULL);
      return False;
   }
   tl_assert(bag->firstCount > 0);

   /* Case: deleting from the distinguished (word,count) */
   if (w == bag->firstWord) {
      Bool  b;
      UWord tmpWord, tmpCount;
      if (bag->firstCount > 1) {
         /* Easy. */
         bag->firstCount--;
         return True;
      }
      tl_assert(bag->firstCount == 1);
      /* Now it gets complex.  Since the distinguished (word,count)
         pair is about to disappear, we have to get a new one from
         'rest'. */
      if (bag->rest == NULL) {
         /* Resulting bag really is completely empty. */
         bag->firstWord = 0;
         bag->firstCount = 0;
         return True;
      }
      /* Get a new distinguished element from 'rest'. This must be
         possible if 'rest' is non-NULL. */
      b = HG_(anyElementOfFM)( bag->rest, &bag->firstWord,
                                          &bag->firstCount, NULL/*unused*/ );
      tl_assert(b);
      tl_assert(bag->firstCount > 0);
      b = HG_(delFromFM)( bag->rest, &tmpWord, &tmpCount, NULL/*unused*/,
                                     bag->firstWord );
      tl_assert(b);
      tl_assert(tmpWord == bag->firstWord);
      tl_assert(tmpCount == bag->firstCount);
      if (HG_(isEmptyFM)( bag->rest )) {
         HG_(deleteFM)( bag->rest, NULL, NULL, NULL );
         bag->rest = NULL;
      }
      return True;
   }

   /* Case: deleting from 'rest' */
   tl_assert(bag->firstCount > 0);
   tl_assert(bag->firstWord != w);
   if (bag->rest) { 
      UWord key, count;
      if (HG_(lookupFM)(bag->rest, &key, &count, NULL/*unused*/, w)) {
         tl_assert(key == w);
         tl_assert(count >= 1);
         if (count > 1) {
           HG_(addToFM)(bag->rest, w, count-1, (UWord)0/*unused*/);
         } else {
            tl_assert(count == 1);
            HG_(delFromFM)(bag->rest, NULL, NULL, NULL, w);
            if (HG_(isEmptyFM)( bag->rest )) {
               HG_(deleteFM)( bag->rest, NULL, NULL, NULL );
               bag->rest = NULL;
            }
         }
         return True;
      } else {
         return False;
      }
   } else {
      return False;
   }
   /*NOTREACHED*/
   tl_assert(0);
}

Bool HG_(isEmptyBag)( WordBag* bag )
{
   tl_assert(is_plausible_WordBag(bag));
   if (bag->firstCount == 0) {
      tl_assert(bag->firstWord == 0);
      tl_assert(bag->rest == NULL);
      return True;
   } else {
      return False;
   }
}

Bool HG_(isSingletonTotalBag)( WordBag* bag )
{
   tl_assert(is_plausible_WordBag(bag));
   return bag->firstCount > 0 && bag->rest == NULL;
}

UWord HG_(anyElementOfBag)( WordBag* bag )
{
   tl_assert(is_plausible_WordBag(bag));
   if (bag->firstCount > 0) {
      return bag->firstWord;
   }
   /* The bag is empty, so the caller is in error, and we should
      assert. */
   tl_assert(0);
}

void HG_(initIterBag)( WordBag* bag )
{
   tl_assert(is_plausible_WordBag(bag));
   bag->iterCount = 0;
}

Bool HG_(nextIterBag)( WordBag* bag, /*OUT*/UWord* pVal, /*OUT*/UWord* pCount )
{
   Bool b;
   if (bag->iterCount == 0) {
      /* Emitting (.firstWord, .firstCount) if we have it. */
      if (bag->firstCount == 0) {
         /* empty */
         return False;
      }
      if (pVal) *pVal = bag->firstWord;
      if (pCount) *pCount = bag->firstCount;
      bag->iterCount = 1;
      return True;
   }

   /* else emitting from .rest, if present */
   if (!bag->rest)
      return False;

   if (bag->iterCount == 1)
      HG_(initIterFM)( bag->rest );

   b = HG_(nextIterFM)( bag->rest, pVal, pCount, NULL/*unused*/ );
   bag->iterCount++;

   return b;
}

void HG_(doneIterBag)( WordBag* bag )
{
   bag->iterCount = 0;
   if (bag->rest)
      HG_(doneIterFM)( bag->rest );
}

//------------------------------------------------------------------//
//---             end WordBag (unboxed words only)               ---//
//---                       Implementation                       ---//
//------------------------------------------------------------------//

#ifdef HG_WORDFM_STANDALONE

//------------------------------------------------------------------//
//---                      Simple test driver.                   ---//
//------------------------------------------------------------------//

// We create a map with N values {1, 3, 5, ..., (N*2-1)}
// and do some trivial stuff with it. 


// Return the number of elements in range [beg, end). 
// Just lookup for each element in range and count. 
int search_all_elements_in_range_1(WordFM *map, long beg, long end)
{
   long n_found = 0;
   long i;
   for (i = beg; i < end; i++) {
      UWord key, val;
      if (HG_(lookupFM)(map, &key, &val, (Word)i)) {
         n_found++;
         assert(key == -val);
         assert(key == (UWord)i);
      }
   }
   return n_found;
}

// Return the number of elements in range [beg, end). 
// Start with the largest element 'e' such that 'e <= beg' 
// and iterate until 'e < end'. 
int search_all_elements_in_range_2(WordFM *map, long beg, long end)
{
   int n_found = 0;
   UWord key, val;
   HG_(initIterAtFM)(map, beg);
   while (HG_(nextIterFM)(map, &key, &val) && (long)key < end) {
      assert(key == -val);
      n_found++;
   }
   HG_(doneIterFM)(map);
   return n_found;
}

void showBag ( WordBag* bag )
{
   UWord val, count;
   printf("Bag{");
   HG_(initIterBag)( bag );
   while (HG_(nextIterBag)( bag, &val, &count )) {
      printf(" %lux%lu ", count, val );
   }
   HG_(doneIterBag)( bag );
   printf("}"); fflush(stdout);
}

int main(void)
{
   long i, n = 10;
   UWord key, val;
   long beg, end;

   printf("Create the map, n=%ld\n", n);
   WordFM *map = HG_(newFM)(malloc, free, NULL/*unboxed Word cmp*/);

   printf("Add keys: ");
   for(i = 0; i < n; i++) {
      long val = i * 2 + 1; // 1, 3, 5, ... (n*2-1)
      printf("%ld ", val);
      HG_(addToFM)(map, val, -val);
   }
   assert(HG_(sizeFM)(map) == (UWord)n);
   printf("\n");
   printf("Iterate elements, size=%d\n", (int)HG_(sizeFM)(map));
   HG_(initIterFM)(map);

   while (HG_(nextIterFM(map, &key, &val))) {
   //   int j;
   //   printf("Stack k=%d\n", (int)key);
   //   for(j = map->stackTop-1; j >= 0; j--) {
   //      printf("\t[%d]: k=%d s=%d\n", j,
   //             (int)map->nodeStack[j]->key, (int)map->numStack[j]);
   //   }
      assert(key == -val);
   }
   HG_(doneIterFM)(map);

   printf("Test initIterAtFM\n");
   for(beg = 0; beg <= n*2; beg++) {
      HG_(initIterAtFM)(map, (Word)beg);
      int prev = -1; 
      printf("StartWith: %ld: ", beg);
      int n_iter = 0;

      while(HG_(nextIterFM(map, &key, &val))) {
         printf("%d ", (int)key);
         assert(key == -val);
         if(prev > 0) assert(prev + 2 == (int)key);
         prev = (int)key;
         n_iter++;
      }
      HG_(doneIterFM)(map);

      printf("\ntotal: %d\n", n_iter);
      if      (beg < 1   ) assert(n_iter == n);
      else if (beg >= n*2) assert(n_iter == 0);
      else                 assert(n_iter == (n - beg/2));
   }

   printf("Compare search_all_elements_in_range_[12]\n");
   for (beg = 0; beg <= n*2; beg++) {
      for (end = 0; end <= n*2; end++) {
         assert(   search_all_elements_in_range_1(map, beg, end) 
                == search_all_elements_in_range_2(map, beg, end));
      }
   }

   printf("Delete the map\n");
   HG_(deleteFM)(map, NULL, NULL);
   printf("Ok!\n");

   printf("\nBEGIN testing WordBag\n");
   WordBag bag;
   Bool b;

   HG_(initBag)( &bag, malloc, free );
   
   printf("operations on an empty bag\n");
   printf(" show:       " ); showBag( &bag ); printf("\n");
   printf(" elem:       %lu\n", HG_(elemBag)( &bag, 42 ));
   printf(" isEmpty:    %lu\n", (UWord) HG_(isEmptyBag)( &bag ));
   printf(" iSTB:       %lu\n", (UWord) HG_(isSingletonTotalBag)( &bag ));
   printf(" sizeUnique: %lu\n", HG_(sizeUniqueBag)( &bag ));
   printf(" sizeTotal:  %lu\n", HG_(sizeTotalBag)( &bag ));
   printf(" delFrom:    %lu\n", (UWord)HG_(delFromBag)( &bag, 42 ));

   assert( HG_(isEmptyBag)( &bag ));
   printf("\noperations on bag { 41 }\n");
   HG_(addToBag)( &bag, 41 );
   printf(" show:       " ); showBag( &bag ); printf("\n");
   printf(" elem:       %lu\n", HG_(elemBag)( &bag, 42 ));
   printf(" isEmpty:    %lu\n", (UWord) HG_(isEmptyBag)( &bag ));
   printf(" iSTB:       %lu\n", (UWord) HG_(isSingletonTotalBag)( &bag ));
   printf(" sizeUnique: %lu\n", HG_(sizeUniqueBag)( &bag ));
   printf(" sizeTotal:  %lu\n", HG_(sizeTotalBag)( &bag ));
   printf(" delFrom:    %lu\n", (UWord)HG_(delFromBag)( &bag, 42 ));

   b = HG_(delFromBag)( &bag, 41 ); assert(b);

   printf("\noperations on bag { 41,41 }\n");
   HG_(addToBag)( &bag, 41 );
   HG_(addToBag)( &bag, 41 );
   printf(" show:       " ); showBag( &bag ); printf("\n");
   printf(" elem:       %lu\n", HG_(elemBag)( &bag, 42 ));
   printf(" isEmpty:    %lu\n", (UWord) HG_(isEmptyBag)( &bag ));
   printf(" iSTB:       %lu\n", (UWord) HG_(isSingletonTotalBag)( &bag ));
   printf(" sizeUnique: %lu\n", HG_(sizeUniqueBag)( &bag ));
   printf(" sizeTotal:  %lu\n", HG_(sizeTotalBag)( &bag ));
   printf(" delFrom:    %lu\n", (UWord)HG_(delFromBag)( &bag, 42 ));

   printf("\noperations on bag { 41,41, 42, 43,43 }\n");
   HG_(addToBag)( &bag, 42 );
   HG_(addToBag)( &bag, 43 );
   HG_(addToBag)( &bag, 43 );
   printf(" show:       " ); showBag( &bag ); printf("\n");
   printf(" elem:       %lu\n", HG_(elemBag)( &bag, 42 ));
   printf(" isEmpty:    %lu\n", (UWord) HG_(isEmptyBag)( &bag ));
   printf(" iSTB:       %lu\n", (UWord) HG_(isSingletonTotalBag)( &bag ));
   printf(" sizeUnique: %lu\n", HG_(sizeUniqueBag)( &bag ));
   printf(" sizeTotal:  %lu\n", HG_(sizeTotalBag)( &bag ));
   printf(" delFrom:    %lu\n", (UWord)HG_(delFromBag)( &bag, 42 ));

   b = HG_(delFromBag)( &bag, 41 ); assert(b);
   printf(" after del of 41: " ); showBag( &bag ); printf("\n");
   b = HG_(delFromBag)( &bag, 41 ); assert(b);
   printf(" after del of 41: " ); showBag( &bag ); printf("\n");
   b = HG_(delFromBag)( &bag, 43 ); assert(b);
   printf(" after del of 43: " ); showBag( &bag ); printf("\n");
   b = HG_(delFromBag)( &bag, 42 ); assert(!b); // already gone
   printf(" after del of 42: " ); showBag( &bag ); printf("\n");
   b = HG_(delFromBag)( &bag, 43 ); assert(b);
   printf(" after del of 43: " ); showBag( &bag ); printf("\n");

   HG_(emptyOutBag)( &bag );

   printf("\noperations on now empty bag\n");
   printf(" show:       " ); showBag( &bag ); printf("\n");
   printf(" elem:       %lu\n", HG_(elemBag)( &bag, 42 ));
   printf(" isEmpty:    %lu\n", (UWord) HG_(isEmptyBag)( &bag ));
   printf(" iSTB:       %lu\n", (UWord) HG_(isSingletonTotalBag)( &bag ));
   printf(" sizeUnique: %lu\n", HG_(sizeUniqueBag)( &bag ));
   printf(" sizeTotal:  %lu\n", HG_(sizeTotalBag)( &bag ));
   printf(" delFrom:    %lu\n", (UWord)HG_(delFromBag)( &bag, 42 ));

   printf("\nEND testing WordBag\n");

   return 0;
}

#endif

/*--------------------------------------------------------------------*/
/*--- end                                              hg_wordfm.c ---*/
/*--------------------------------------------------------------------*/


/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
//                                                             //
// SECTION END wordfm                                          //
//                                                             //
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////



/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
//                                                             //
// SECTION BEGIN compressed shadow memory                      //
//                                                             //
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////

#ifndef __HB_ZSM_H
#define __HB_ZSM_H

typedef  ULong  SVal;

/* This value has special significance to the implementation, and callers
   may not store it in the shadow memory. */
#define SVal_INVALID (3ULL << 62)

/* This is the default value for shadow memory.  Initially the shadow
   memory contains no accessible areas and so all reads produce this
   value.  TODO: make this caller-defineable. */
#define SVal_NOACCESS (2ULL << 62)

/* Initialise the library.  Once initialised, it will (or may) call
   rcinc and rcdec in response to all the calls below, in order to
   allow the user to do reference counting on the SVals stored herein.
   It is important to understand, however, that due to internal
   caching, the reference counts are in general inaccurate, and can be
   both above or below the true reference count for an item.  In
   particular, the library may indicate that the reference count for
   an item is zero, when in fact it is not.

   To make the reference counting exact and therefore non-pointless,
   call zsm_flush_cache.  Immediately after it returns, the reference
   counts for all items, as deduced by the caller by observing calls
   to rcinc and rcdec, will be correct, and so any items with a zero
   reference count may be freed (or at least considered to be
   unreferenced by this library).
*/
static void zsm_init ( void(*rcinc)(SVal), void(*rcdec)(SVal) );

static void zsm_apply8      ( Addr,        SVal(*)(SVal,void*), void* );
static void zsm_apply16     ( Addr,        SVal(*)(SVal,void*), void* );
static void zsm_apply32     ( Addr,        SVal(*)(SVal,void*), void* );
static void zsm_apply64     ( Addr,        SVal(*)(SVal,void*), void* );
static void zsm_apply_range ( Addr, SizeT, SVal(*)(SVal,void*), void* );
static void zsm_set_range   ( Addr, SizeT, SVal );
static SVal zsm_read8       ( Addr );
static void zsm_copy_range  ( Addr, Addr, SizeT );
static void zsm_flush_cache ( void );

#endif /* ! __HB_ZSM_H */


/* For the shadow mem cache stuff we may want more intrusive
   checks.  Unfortunately there's no almost-zero-cost way to make them
   selectable at run time.  Hence set the #if 0 to #if 1 and
   rebuild if you want them. */
#if 0
#  define SCE_CACHELINE 1  /* do sanity-check CacheLine stuff */
#  define inline __attribute__((noinline))
   /* probably want to ditch -fomit-frame-pointer too */
#else
#  define SCE_CACHELINE 0   /* don't sanity-check CacheLine stuff */
#endif

/* For the SegmentID, SegmentSet and SVal stuff we may want more
   intrusive checks.  Again there's no zero cost way to do this.  Set
   the #if 0 to #if 1 and rebuild if you want them. */
#if 0
#  define SCE_SVALS 1 /* sanity-check shadow value stuff */
#else
#  define SCE_SVALS 0
#endif


/* Round a up to the next multiple of N.  N must be a power of 2 */
#define ROUNDUP(a, N)   ((a + N - 1) & ~(N-1))
/* Round a down to the next multiple of N.  N must be a power of 2 */
#define ROUNDDN(a, N)   ((a) & ~(N-1))



/* ------ User-supplied RC functions ------ */
static void(*rcinc)(SVal) = NULL;
static void(*rcdec)(SVal) = NULL;


/* ------ CacheLine ------ */

#define N_LINE_BITS      6 /* must be >= 3 */
#define N_LINE_ARANGE    (1 << N_LINE_BITS)
#define N_LINE_TREES     (N_LINE_ARANGE >> 3)

typedef
   struct {
      UShort descrs[N_LINE_TREES];
      SVal   svals[N_LINE_ARANGE]; // == N_LINE_TREES * 8
   }
   CacheLine;

#define TREE_DESCR_16_0 (1<<0)
#define TREE_DESCR_32_0 (1<<1)
#define TREE_DESCR_16_1 (1<<2)
#define TREE_DESCR_64   (1<<3)
#define TREE_DESCR_16_2 (1<<4)
#define TREE_DESCR_32_1 (1<<5)
#define TREE_DESCR_16_3 (1<<6)
#define TREE_DESCR_8_0  (1<<7)
#define TREE_DESCR_8_1  (1<<8)
#define TREE_DESCR_8_2  (1<<9)
#define TREE_DESCR_8_3  (1<<10)
#define TREE_DESCR_8_4  (1<<11)
#define TREE_DESCR_8_5  (1<<12)
#define TREE_DESCR_8_6  (1<<13)
#define TREE_DESCR_8_7  (1<<14)
#define TREE_DESCR_DTY  (1<<15)

typedef
   struct {
      SVal  dict[4]; /* can represent up to 4 diff values in the line */
      UChar ix2s[N_LINE_ARANGE/4]; /* array of N_LINE_ARANGE 2-bit
                                      dict indexes */
      /* if dict[0] == SVal_INVALID then dict[1] is the index of the
         LineF to use, and dict[2..] are also SVal_INVALID. */
   }
   LineZ; /* compressed rep for a cache line */

typedef
   struct {
      Bool inUse;
      SVal w64s[N_LINE_ARANGE];
   }
   LineF; /* full rep for a cache line */

/* Shadow memory.
   Primary map is a WordFM Addr SecMap*.  
   SecMaps cover some page-size-ish section of address space and hold
     a compressed representation.
   CacheLine-sized chunks of SecMaps are copied into a Cache, being
   decompressed when moved into the cache and recompressed on the
   way out.  Because of this, the cache must operate as a writeback
   cache, not a writethrough one.

   Each SecMap must hold a power-of-2 number of CacheLines.  Hence
   N_SECMAP_BITS must >= N_LINE_BITS.
*/
#define N_SECMAP_BITS   13
#define N_SECMAP_ARANGE (1 << N_SECMAP_BITS)

// # CacheLines held by a SecMap
#define N_SECMAP_ZLINES (N_SECMAP_ARANGE / N_LINE_ARANGE)

/* The data in the SecMap is held in the array of LineZs.  Each LineZ
   either carries the required data directly, in a compressed
   representation, or it holds (in .dict[0]) an index to the LineF in
   .linesF that holds the full representation.

   Currently-unused LineF's have their .inUse bit set to zero.
   Since each in-use LineF is referred to be exactly one LineZ,
   the number of .linesZ[] that refer to .linesF should equal
   the number of .linesF[] that have .inUse == True.

   RC obligations: the RCs presented to the user include exactly
   the values in:
   * direct Z reps, that is, ones for which .dict[0] != SVal_INVALID
   * F reps that are in use (.inUse == True)

   Hence the following actions at the following transitions are required:

   F rep: .inUse==True  -> .inUse==False        -- rcdec_LineF
   F rep: .inUse==False -> .inUse==True         -- rcinc_LineF
   Z rep: .dict[0] from other to SVal_INVALID   -- rcdec_LineZ
   Z rep: .dict[0] from SVal_INVALID to other   -- rcinc_LineZ
*/
typedef
   struct {
      UInt   magic;
      LineZ  linesZ[N_SECMAP_ZLINES];
      LineF* linesF;
      UInt   linesF_size;
   }
   SecMap;

#define SecMap_MAGIC   0x571e58cbU

static inline Bool is_sane_SecMap ( SecMap* sm ) {
   return sm != NULL && sm->magic == SecMap_MAGIC;
}

/* ------ Cache ------ */

#define N_WAY_BITS 16
#define N_WAY_NENT (1 << N_WAY_BITS)

/* Each tag is the address of the associated CacheLine, rounded down
   to a CacheLine address boundary.  A CacheLine size must be a power
   of 2 and must be 8 or more.  Hence an easy way to initialise the
   cache so it is empty is to set all the tag values to any value % 8
   != 0, eg 1.  This means all queries in the cache initially miss.
   It does however require us to detect and not writeback, any line
   with a bogus tag. */
typedef
   struct {
      CacheLine lyns0[N_WAY_NENT];
      Addr      tags0[N_WAY_NENT];
   }
   Cache;

static inline Bool is_valid_scache_tag ( Addr tag ) {
   /* a valid tag should be naturally aligned to the start of
      a CacheLine. */
   return 0 == (tag & (N_LINE_ARANGE - 1));
}


/* --------- Primary data structures --------- */

/* Shadow memory primary map */
static WordFM* map_shmem = NULL; /* WordFM Addr SecMap* */
static Cache   cache_shmem;


static UWord stats__secmaps_search       = 0; // # SM finds
static UWord stats__secmaps_search_slow  = 0; // # SM lookupFMs
static UWord stats__secmaps_allocd       = 0; // # SecMaps issued
static UWord stats__secmap_ga_space_covered = 0; // # ga bytes covered
static UWord stats__secmap_linesZ_allocd = 0; // # LineZ's issued
static UWord stats__secmap_linesZ_bytes  = 0; // .. using this much storage
static UWord stats__secmap_linesF_allocd = 0; // # LineF's issued
static UWord stats__secmap_linesF_bytes  = 0; //  .. using this much storage
static UWord stats__secmap_iterator_steppings = 0; // # calls to stepSMIter
static UWord stats__cache_Z_fetches      = 0; // # Z lines fetched
static UWord stats__cache_Z_wbacks       = 0; // # Z lines written back
static UWord stats__cache_F_fetches      = 0; // # F lines fetched
static UWord stats__cache_F_wbacks       = 0; // # F lines written back
static UWord stats__cache_invals         = 0; // # cache invals
static UWord stats__cache_flushes        = 0; // # cache flushes
static UWord stats__cache_totrefs        = 0; // # total accesses
static UWord stats__cache_totmisses      = 0; // # misses
static ULong stats__cache_make_New_arange = 0; // total arange made New
static ULong stats__cache_make_New_inZrep = 0; // arange New'd on Z reps
static UWord stats__cline_normalises     = 0; // # calls to cacheline_normalise
static UWord stats__cline_read64s        = 0; // # calls to s_m_read64
static UWord stats__cline_read32s        = 0; // # calls to s_m_read32
static UWord stats__cline_read16s        = 0; // # calls to s_m_read16
static UWord stats__cline_read8s         = 0; // # calls to s_m_read8
static UWord stats__cline_write64s       = 0; // # calls to s_m_write64
static UWord stats__cline_write32s       = 0; // # calls to s_m_write32
static UWord stats__cline_write16s       = 0; // # calls to s_m_write16
static UWord stats__cline_write8s        = 0; // # calls to s_m_write8
static UWord stats__cline_set64s         = 0; // # calls to s_m_set64
static UWord stats__cline_set32s         = 0; // # calls to s_m_set32
static UWord stats__cline_set16s         = 0; // # calls to s_m_set16
static UWord stats__cline_set8s          = 0; // # calls to s_m_set8
static UWord stats__cline_get8s          = 0; // # calls to s_m_get8
static UWord stats__cline_copy8s         = 0; // # calls to s_m_copy8
static UWord stats__cline_64to32splits   = 0; // # 64-bit accesses split
static UWord stats__cline_32to16splits   = 0; // # 32-bit accesses split
static UWord stats__cline_16to8splits    = 0; // # 16-bit accesses split
static UWord stats__cline_64to32pulldown = 0; // # calls to pulldown_to_32
static UWord stats__cline_32to16pulldown = 0; // # calls to pulldown_to_16
static UWord stats__cline_16to8pulldown  = 0; // # calls to pulldown_to_8

static inline Addr shmem__round_to_SecMap_base ( Addr a ) {
   return a & ~(N_SECMAP_ARANGE - 1);
}
static inline UWord shmem__get_SecMap_offset ( Addr a ) {
   return a & (N_SECMAP_ARANGE - 1);
}


/*--------------- SecMap allocation --------------- */

static SecMap* shmem__alloc_SecMap ( void )
{
   Word    i, j;
   SecMap* sm = main_shadow_alloc( sizeof(SecMap) );
   if (0) VG_(printf)("alloc_SecMap %p\n",sm);
   tl_assert(sm);
   sm->magic = SecMap_MAGIC;
   for (i = 0; i < N_SECMAP_ZLINES; i++) {
      sm->linesZ[i].dict[0] = SVal_NOACCESS;
      sm->linesZ[i].dict[1] = SVal_INVALID;
      sm->linesZ[i].dict[2] = SVal_INVALID;
      sm->linesZ[i].dict[3] = SVal_INVALID;
      for (j = 0; j < N_LINE_ARANGE/4; j++)
         sm->linesZ[i].ix2s[j] = 0; /* all reference dict[0] */
   }
   sm->linesF      = NULL;
   sm->linesF_size = 0;
   stats__secmaps_allocd++;
   stats__secmap_ga_space_covered += N_SECMAP_ARANGE;
   stats__secmap_linesZ_allocd += N_SECMAP_ZLINES;
   stats__secmap_linesZ_bytes += N_SECMAP_ZLINES * sizeof(LineZ);
   return sm;
}

typedef struct { Addr gaKey; SecMap* sm; } SMCacheEnt;
static SMCacheEnt smCache[3] = { {1,NULL}, {1,NULL}, {1,NULL} };

static SecMap* shmem__find_SecMap ( Addr ga ) 
{
   SecMap* sm    = NULL;
   Addr    gaKey = shmem__round_to_SecMap_base(ga);
   // Cache
   stats__secmaps_search++;
   if (LIKELY(gaKey == smCache[0].gaKey))
      return smCache[0].sm;
   if (LIKELY(gaKey == smCache[1].gaKey)) {
      SMCacheEnt tmp = smCache[0];
      smCache[0] = smCache[1];
      smCache[1] = tmp;
      return smCache[0].sm;
   }
   if (gaKey == smCache[2].gaKey) {
      SMCacheEnt tmp = smCache[1];
      smCache[1] = smCache[2];
      smCache[2] = tmp;
      return smCache[1].sm;
   }
   // end Cache
   stats__secmaps_search_slow++;
   if (HG_(lookupFM)( map_shmem,
                      NULL/*keyP*/, (UWord*)&sm, NULL/*2ndvalP*/,
                      (UWord)gaKey )) {
      tl_assert(sm != NULL);
      smCache[2] = smCache[1];
      smCache[1] = smCache[0];
      smCache[0].gaKey = gaKey;
      smCache[0].sm    = sm;
   } else {
      tl_assert(sm == NULL);
   }
   return sm;
}

static SecMap* shmem__find_or_alloc_SecMap ( Addr ga )
{
   SecMap* sm = shmem__find_SecMap ( ga );
   if (LIKELY(sm)) {
      return sm;
   } else {
      /* create a new one */
      Addr gaKey = shmem__round_to_SecMap_base(ga);
      sm = shmem__alloc_SecMap();
      tl_assert(sm);
      HG_(addToFM)( map_shmem, (UWord)gaKey, (UWord)sm, (UWord)0/*unused*/ );
      return sm;
   }
}


/* ------------ LineF and LineZ related ------------ */

static void rcinc_LineF ( LineF* lineF ) {
   UWord i;
   tl_assert(lineF->inUse);
   for (i = 0; i < N_LINE_ARANGE; i++)
      rcinc(lineF->w64s[i]);
}

static void rcdec_LineF ( LineF* lineF ) {
   UWord i;
   tl_assert(lineF->inUse);
   for (i = 0; i < N_LINE_ARANGE; i++)
      rcdec(lineF->w64s[i]);
}

static void rcinc_LineZ ( LineZ* lineZ ) {
   tl_assert(lineZ->dict[0] != SVal_INVALID);
   rcinc(lineZ->dict[0]);
   if (lineZ->dict[1] != SVal_INVALID) rcinc(lineZ->dict[1]);
   if (lineZ->dict[2] != SVal_INVALID) rcinc(lineZ->dict[2]);
   if (lineZ->dict[3] != SVal_INVALID) rcinc(lineZ->dict[3]);
}

static void rcdec_LineZ ( LineZ* lineZ ) {
   tl_assert(lineZ->dict[0] != SVal_INVALID);
   rcdec(lineZ->dict[0]);
   if (lineZ->dict[1] != SVal_INVALID) rcdec(lineZ->dict[1]);
   if (lineZ->dict[2] != SVal_INVALID) rcdec(lineZ->dict[2]);
   if (lineZ->dict[3] != SVal_INVALID) rcdec(lineZ->dict[3]);
}

inline
static void write_twobit_array ( UChar* arr, UWord ix, UWord b2 ) {
   Word bix, shft, mask, prep;
   tl_assert(ix >= 0);
   bix  = ix >> 2;
   shft = 2 * (ix & 3); /* 0, 2, 4 or 6 */
   mask = 3 << shft;
   prep = b2 << shft;
   arr[bix] = (arr[bix] & ~mask) | prep;
}

inline
static UWord read_twobit_array ( UChar* arr, UWord ix ) {
   Word bix, shft;
   tl_assert(ix >= 0);
   bix  = ix >> 2;
   shft = 2 * (ix & 3); /* 0, 2, 4 or 6 */
   return (arr[bix] >> shft) & 3;
}

/* Given address 'tag', find either the Z or F line containing relevant
   data, so it can be read into the cache.
*/
static void find_ZF_for_reading ( /*OUT*/LineZ** zp,
                                  /*OUT*/LineF** fp, Addr tag ) {
   LineZ* lineZ;
   LineF* lineF;
   UWord   zix;
   SecMap* sm    = shmem__find_or_alloc_SecMap(tag);
   UWord   smoff = shmem__get_SecMap_offset(tag);
   /* since smoff is derived from a valid tag, it should be
      cacheline-aligned. */
   tl_assert(0 == (smoff & (N_LINE_ARANGE - 1)));
   zix = smoff >> N_LINE_BITS;
   tl_assert(zix < N_SECMAP_ZLINES);
   lineZ = &sm->linesZ[zix];
   lineF = NULL;
   if (lineZ->dict[0] == SVal_INVALID) {
      UInt fix = (UInt)lineZ->dict[1];
      tl_assert(sm->linesF);
      tl_assert(sm->linesF_size > 0);
      tl_assert(fix >= 0 && fix < sm->linesF_size);
      lineF = &sm->linesF[fix];
      tl_assert(lineF->inUse);
      lineZ = NULL;
   }
   *zp = lineZ;
   *fp = lineF;
}

/* Given address 'tag', return the relevant SecMap and the index of
   the LineZ within it, in the expectation that the line is to be
   overwritten.  Regardless of whether 'tag' is currently associated
   with a Z or F representation, to rcdec on the current
   representation, in recognition of the fact that the contents are
   just about to be overwritten. */
static __attribute__((noinline))
void find_Z_for_writing ( /*OUT*/SecMap** smp,
                          /*OUT*/Word* zixp,
                          Addr tag ) {
   LineZ* lineZ;
   LineF* lineF;
   UWord   zix;
   SecMap* sm    = shmem__find_or_alloc_SecMap(tag);
   UWord   smoff = shmem__get_SecMap_offset(tag);
   /* since smoff is derived from a valid tag, it should be
      cacheline-aligned. */
   tl_assert(0 == (smoff & (N_LINE_ARANGE - 1)));
   zix = smoff >> N_LINE_BITS;
   tl_assert(zix < N_SECMAP_ZLINES);
   lineZ = &sm->linesZ[zix];
   lineF = NULL;
   /* re RCs, we are freeing up this LineZ/LineF so that new data can
      be parked in it.  Hence have to rcdec it accordingly. */
   /* If lineZ has an associated lineF, free it up. */
   if (lineZ->dict[0] == SVal_INVALID) {
      UInt fix = (UInt)lineZ->dict[1];
      tl_assert(sm->linesF);
      tl_assert(sm->linesF_size > 0);
      tl_assert(fix >= 0 && fix < sm->linesF_size);
      lineF = &sm->linesF[fix];
      tl_assert(lineF->inUse);
      rcdec_LineF(lineF);
      lineF->inUse = False;
   } else {
      rcdec_LineZ(lineZ);
   }
   *smp  = sm;
   *zixp = zix;
}

static __attribute__((noinline))
void alloc_F_for_writing ( /*MOD*/SecMap* sm, /*OUT*/Word* fixp ) {
   UInt        i, new_size;
   LineF* nyu;

   if (sm->linesF) {
      tl_assert(sm->linesF_size > 0);
   } else {
      tl_assert(sm->linesF_size == 0);
   }

   if (sm->linesF) {
      for (i = 0; i < sm->linesF_size; i++) {
         if (!sm->linesF[i].inUse) {
            *fixp = (Word)i;
            return;
         }
      }
   }

   /* No free F line found.  Expand existing array and try again. */
   new_size = sm->linesF_size==0 ? 1 : 2 * sm->linesF_size;
   nyu      = main_zalloc( "libhb.aFfw.1 (LineF storage)",
                           new_size * sizeof(LineF) );
   tl_assert(nyu);

   stats__secmap_linesF_allocd += (new_size - sm->linesF_size);
   stats__secmap_linesF_bytes  += (new_size - sm->linesF_size)
                                  * sizeof(LineF);

   if (0)
   VG_(printf)("SM %p: expand F array from %d to %d\n", 
               sm, (Int)sm->linesF_size, new_size);

   for (i = 0; i < new_size; i++)
      nyu[i].inUse = False;

   if (sm->linesF) {
      for (i = 0; i < sm->linesF_size; i++) {
         tl_assert(sm->linesF[i].inUse);
         nyu[i] = sm->linesF[i];
      }
      VG_(memset)(sm->linesF, 0, sm->linesF_size * sizeof(LineF) );
      main_dealloc(sm->linesF);
   }

   sm->linesF      = nyu;
   sm->linesF_size = new_size;

   for (i = 0; i < sm->linesF_size; i++) {
      if (!sm->linesF[i].inUse) {
         *fixp = (Word)i;
         return;
      }
    }

    /*NOTREACHED*/
    tl_assert(0);
}


/* ------------ CacheLine and implicit-tree related ------------ */

__attribute__((unused))
static void pp_CacheLine ( CacheLine* cl ) {
   Word i;
   if (!cl) {
      VG_(printf)("%s","pp_CacheLine(NULL)\n");
      return;
   }
   for (i = 0; i < N_LINE_TREES; i++) 
      VG_(printf)("   descr: %04lx\n", (UWord)cl->descrs[i]);
   for (i = 0; i < N_LINE_ARANGE; i++) 
      VG_(printf)("    sval: %08lx\n", (UWord)cl->svals[i]);
}

static UChar descr_to_validbits ( UShort descr )
{
   /* a.k.a Party Time for gcc's constant folder */
#  define DESCR(b8_7, b8_6, b8_5, b8_4, b8_3, b8_2, b8_1, b8_0, \
                b16_3, b32_1, b16_2, b64, b16_1, b32_0, b16_0)  \
             ( (UShort) ( ( (b8_7)  << 14) | ( (b8_6)  << 13) | \
                          ( (b8_5)  << 12) | ( (b8_4)  << 11) | \
                          ( (b8_3)  << 10) | ( (b8_2)  << 9)  | \
                          ( (b8_1)  << 8)  | ( (b8_0)  << 7)  | \
                          ( (b16_3) << 6)  | ( (b32_1) << 5)  | \
                          ( (b16_2) << 4)  | ( (b64)   << 3)  | \
                          ( (b16_1) << 2)  | ( (b32_0) << 1)  | \
                          ( (b16_0) << 0) ) )

#  define BYTE(bit7, bit6, bit5, bit4, bit3, bit2, bit1, bit0) \
             ( (UChar) ( ( (bit7) << 7) | ( (bit6) << 6) | \
                         ( (bit5) << 5) | ( (bit4) << 4) | \
                         ( (bit3) << 3) | ( (bit2) << 2) | \
                         ( (bit1) << 1) | ( (bit0) << 0) ) )

   /* these should all get folded out at compile time */
   tl_assert(DESCR(1,0,0,0,0,0,0,0, 0,0,0, 0, 0,0,0) == TREE_DESCR_8_7);
   tl_assert(DESCR(0,0,0,0,0,0,0,1, 0,0,0, 0, 0,0,0) == TREE_DESCR_8_0);
   tl_assert(DESCR(0,0,0,0,0,0,0,0, 1,0,0, 0, 0,0,0) == TREE_DESCR_16_3);
   tl_assert(DESCR(0,0,0,0,0,0,0,0, 0,1,0, 0, 0,0,0) == TREE_DESCR_32_1);
   tl_assert(DESCR(0,0,0,0,0,0,0,0, 0,0,1, 0, 0,0,0) == TREE_DESCR_16_2);
   tl_assert(DESCR(0,0,0,0,0,0,0,0, 0,0,0, 1, 0,0,0) == TREE_DESCR_64);
   tl_assert(DESCR(0,0,0,0,0,0,0,0, 0,0,0, 0, 1,0,0) == TREE_DESCR_16_1);
   tl_assert(DESCR(0,0,0,0,0,0,0,0, 0,0,0, 0, 0,1,0) == TREE_DESCR_32_0);
   tl_assert(DESCR(0,0,0,0,0,0,0,0, 0,0,0, 0, 0,0,1) == TREE_DESCR_16_0);

   switch (descr) {
   /*
              +--------------------------------- TREE_DESCR_8_7
              |             +------------------- TREE_DESCR_8_0
              |             |  +---------------- TREE_DESCR_16_3
              |             |  | +-------------- TREE_DESCR_32_1
              |             |  | | +------------ TREE_DESCR_16_2
              |             |  | | |  +--------- TREE_DESCR_64
              |             |  | | |  |  +------ TREE_DESCR_16_1
              |             |  | | |  |  | +---- TREE_DESCR_32_0
              |             |  | | |  |  | | +-- TREE_DESCR_16_0
              |             |  | | |  |  | | |
              |             |  | | |  |  | | |   GRANULARITY, 7 -> 0 */
   case DESCR(1,1,1,1,1,1,1,1, 0,0,0, 0, 0,0,0): /* 8 8 8 8  8 8 8 8 */
                                                 return BYTE(1,1,1,1,1,1,1,1);
   case DESCR(1,1,0,0,1,1,1,1, 0,0,1, 0, 0,0,0): /* 8 8 16   8 8 8 8 */
                                                 return BYTE(1,1,0,1,1,1,1,1);
   case DESCR(0,0,1,1,1,1,1,1, 1,0,0, 0, 0,0,0): /* 16  8 8  8 8 8 8 */ 
                                                 return BYTE(0,1,1,1,1,1,1,1);
   case DESCR(0,0,0,0,1,1,1,1, 1,0,1, 0, 0,0,0): /* 16  16   8 8 8 8 */
                                                 return BYTE(0,1,0,1,1,1,1,1);

   case DESCR(1,1,1,1,1,1,0,0, 0,0,0, 0, 0,0,1): /* 8 8 8 8  8 8 16 */ 
                                                 return BYTE(1,1,1,1,1,1,0,1);
   case DESCR(1,1,0,0,1,1,0,0, 0,0,1, 0, 0,0,1): /* 8 8 16   8 8 16 */
                                                 return BYTE(1,1,0,1,1,1,0,1);
   case DESCR(0,0,1,1,1,1,0,0, 1,0,0, 0, 0,0,1): /* 16  8 8  8 8 16 */
                                                 return BYTE(0,1,1,1,1,1,0,1);
   case DESCR(0,0,0,0,1,1,0,0, 1,0,1, 0, 0,0,1): /* 16  16   8 8 16 */
                                                 return BYTE(0,1,0,1,1,1,0,1);

   case DESCR(1,1,1,1,0,0,1,1, 0,0,0, 0, 1,0,0): /* 8 8 8 8  16 8 8 */
                                                 return BYTE(1,1,1,1,0,1,1,1);
   case DESCR(1,1,0,0,0,0,1,1, 0,0,1, 0, 1,0,0): /* 8 8 16   16 8 8 */
                                                 return BYTE(1,1,0,1,0,1,1,1);
   case DESCR(0,0,1,1,0,0,1,1, 1,0,0, 0, 1,0,0): /* 16  8 8  16 8 8 */
                                                 return BYTE(0,1,1,1,0,1,1,1);
   case DESCR(0,0,0,0,0,0,1,1, 1,0,1, 0, 1,0,0): /* 16  16   16 8 8 */
                                                 return BYTE(0,1,0,1,0,1,1,1);

   case DESCR(1,1,1,1,0,0,0,0, 0,0,0, 0, 1,0,1): /* 8 8 8 8  16 16 */
                                                 return BYTE(1,1,1,1,0,1,0,1);
   case DESCR(1,1,0,0,0,0,0,0, 0,0,1, 0, 1,0,1): /* 8 8 16   16 16 */
                                                 return BYTE(1,1,0,1,0,1,0,1);
   case DESCR(0,0,1,1,0,0,0,0, 1,0,0, 0, 1,0,1): /* 16  8 8  16 16 */
                                                 return BYTE(0,1,1,1,0,1,0,1);
   case DESCR(0,0,0,0,0,0,0,0, 1,0,1, 0, 1,0,1): /* 16  16   16 16 */
                                                 return BYTE(0,1,0,1,0,1,0,1);

   case DESCR(0,0,0,0,1,1,1,1, 0,1,0, 0, 0,0,0): /* 32  8 8 8 8 */
                                                 return BYTE(0,0,0,1,1,1,1,1);
   case DESCR(0,0,0,0,1,1,0,0, 0,1,0, 0, 0,0,1): /* 32  8 8 16  */
                                                 return BYTE(0,0,0,1,1,1,0,1);
   case DESCR(0,0,0,0,0,0,1,1, 0,1,0, 0, 1,0,0): /* 32  16  8 8 */
                                                 return BYTE(0,0,0,1,0,1,1,1);
   case DESCR(0,0,0,0,0,0,0,0, 0,1,0, 0, 1,0,1): /* 32  16  16  */
                                                 return BYTE(0,0,0,1,0,1,0,1);

   case DESCR(1,1,1,1,0,0,0,0, 0,0,0, 0, 0,1,0): /* 8 8 8 8  32 */
                                                 return BYTE(1,1,1,1,0,0,0,1);
   case DESCR(1,1,0,0,0,0,0,0, 0,0,1, 0, 0,1,0): /* 8 8 16   32 */
                                                 return BYTE(1,1,0,1,0,0,0,1);
   case DESCR(0,0,1,1,0,0,0,0, 1,0,0, 0, 0,1,0): /* 16  8 8  32 */
                                                 return BYTE(0,1,1,1,0,0,0,1);
   case DESCR(0,0,0,0,0,0,0,0, 1,0,1, 0, 0,1,0): /* 16  16   32 */
                                                 return BYTE(0,1,0,1,0,0,0,1);

   case DESCR(0,0,0,0,0,0,0,0, 0,1,0, 0, 0,1,0): /* 32 32 */
                                                 return BYTE(0,0,0,1,0,0,0,1);

   case DESCR(0,0,0,0,0,0,0,0, 0,0,0, 1, 0,0,0): /* 64 */
                                                 return BYTE(0,0,0,0,0,0,0,1);

   default: return BYTE(0,0,0,0,0,0,0,0); 
                   /* INVALID - any valid descr produces at least one
                      valid bit in tree[0..7]*/
   }
   /* NOTREACHED*/
   tl_assert(0);

#  undef DESCR
#  undef BYTE
}

__attribute__((unused))
static Bool is_sane_Descr ( UShort descr ) {
   return descr_to_validbits(descr) != 0;
}

static void sprintf_Descr ( /*OUT*/HChar* dst, UShort descr ) {
   VG_(sprintf)(dst, 
                "%d%d%d%d%d%d%d%d %d%d%d %d %d%d%d",
                (Int)((descr & TREE_DESCR_8_7) ? 1 : 0),
                (Int)((descr & TREE_DESCR_8_6) ? 1 : 0),
                (Int)((descr & TREE_DESCR_8_5) ? 1 : 0),
                (Int)((descr & TREE_DESCR_8_4) ? 1 : 0),
                (Int)((descr & TREE_DESCR_8_3) ? 1 : 0),
                (Int)((descr & TREE_DESCR_8_2) ? 1 : 0),
                (Int)((descr & TREE_DESCR_8_1) ? 1 : 0),
                (Int)((descr & TREE_DESCR_8_0) ? 1 : 0),
                (Int)((descr & TREE_DESCR_16_3) ? 1 : 0),
                (Int)((descr & TREE_DESCR_32_1) ? 1 : 0),
                (Int)((descr & TREE_DESCR_16_2) ? 1 : 0),
                (Int)((descr & TREE_DESCR_64)   ? 1 : 0),
                (Int)((descr & TREE_DESCR_16_1) ? 1 : 0),
                (Int)((descr & TREE_DESCR_32_0) ? 1 : 0),
                (Int)((descr & TREE_DESCR_16_0) ? 1 : 0)
   );
}
static void sprintf_Byte ( /*OUT*/HChar* dst, UChar byte ) {
   VG_(sprintf)(dst, "%d%d%d%d%d%d%d%d",
                     (Int)((byte & 128) ? 1 : 0),
                     (Int)((byte &  64) ? 1 : 0),
                     (Int)((byte &  32) ? 1 : 0),
                     (Int)((byte &  16) ? 1 : 0),
                     (Int)((byte &   8) ? 1 : 0),
                     (Int)((byte &   4) ? 1 : 0),
                     (Int)((byte &   2) ? 1 : 0),
                     (Int)((byte &   1) ? 1 : 0)
   );
}

static Bool is_sane_Descr_and_Tree ( UShort descr, SVal* tree ) {
   Word  i;
   UChar validbits = descr_to_validbits(descr);
   HChar buf[128], buf2[128];
   if (validbits == 0)
      goto bad;
   for (i = 0; i < 8; i++) {
      if (validbits & (1<<i)) {
         if (tree[i] == SVal_INVALID)
            goto bad;
      } else {
         if (tree[i] != SVal_INVALID)
            goto bad;
      }
   }
   return True;
  bad:
   sprintf_Descr( buf, descr );
   sprintf_Byte( buf2, validbits );
   VG_(printf)("%s","is_sane_Descr_and_Tree: bad tree {\n");
   VG_(printf)("   validbits 0x%02lx    %s\n", (UWord)validbits, buf2);
   VG_(printf)("       descr 0x%04lx  %s\n", (UWord)descr, buf);
   for (i = 0; i < 8; i++)
      VG_(printf)("   [%ld] 0x%016llx\n", i, tree[i]);
   VG_(printf)("%s","}\n");
   return 0;
}

static Bool is_sane_CacheLine ( CacheLine* cl )
{
   Word tno, cloff;

   if (!cl) goto bad;

   for (tno = 0, cloff = 0;  tno < N_LINE_TREES;  tno++, cloff += 8) {
      UShort descr = cl->descrs[tno];
      SVal*  tree  = &cl->svals[cloff];
      if (!is_sane_Descr_and_Tree(descr, tree))
         goto bad;
   }
   tl_assert(cloff == N_LINE_ARANGE);
   return True;
  bad:
   pp_CacheLine(cl);
   return False;
}

static UShort normalise_tree ( /*MOD*/SVal* tree )
{
   UShort descr;
   /* pre: incoming tree[0..7] does not have any invalid shvals, in
      particular no zeroes. */
   if (UNLIKELY(tree[7] == SVal_INVALID || tree[6] == SVal_INVALID
                || tree[5] == SVal_INVALID || tree[4] == SVal_INVALID
                || tree[3] == SVal_INVALID || tree[2] == SVal_INVALID
                || tree[1] == SVal_INVALID || tree[0] == SVal_INVALID))
      tl_assert(0);
   
   descr = TREE_DESCR_8_7 | TREE_DESCR_8_6 | TREE_DESCR_8_5
           | TREE_DESCR_8_4 | TREE_DESCR_8_3 | TREE_DESCR_8_2
           | TREE_DESCR_8_1 | TREE_DESCR_8_0;
   /* build 16-bit layer */
   if (tree[1] == tree[0]) {
      tree[1] = SVal_INVALID;
      descr &= ~(TREE_DESCR_8_1 | TREE_DESCR_8_0);
      descr |= TREE_DESCR_16_0;
   }
   if (tree[3] == tree[2]) {
      tree[3] = SVal_INVALID;
      descr &= ~(TREE_DESCR_8_3 | TREE_DESCR_8_2);
      descr |= TREE_DESCR_16_1;
   }
   if (tree[5] == tree[4]) {
      tree[5] = SVal_INVALID;
      descr &= ~(TREE_DESCR_8_5 | TREE_DESCR_8_4);
      descr |= TREE_DESCR_16_2;
   }
   if (tree[7] == tree[6]) {
      tree[7] = SVal_INVALID;
      descr &= ~(TREE_DESCR_8_7 | TREE_DESCR_8_6);
      descr |= TREE_DESCR_16_3;
   }
   /* build 32-bit layer */
   if (tree[2] == tree[0]
       && (descr & TREE_DESCR_16_1) && (descr & TREE_DESCR_16_0)) {
      tree[2] = SVal_INVALID; /* [3,1] must already be SVal_INVALID */
      descr &= ~(TREE_DESCR_16_1 | TREE_DESCR_16_0);
      descr |= TREE_DESCR_32_0;
   }
   if (tree[6] == tree[4]
       && (descr & TREE_DESCR_16_3) && (descr & TREE_DESCR_16_2)) {
      tree[6] = SVal_INVALID; /* [7,5] must already be SVal_INVALID */
      descr &= ~(TREE_DESCR_16_3 | TREE_DESCR_16_2);
      descr |= TREE_DESCR_32_1;
   }
   /* build 64-bit layer */
   if (tree[4] == tree[0]
       && (descr & TREE_DESCR_32_1) && (descr & TREE_DESCR_32_0)) {
      tree[4] = SVal_INVALID; /* [7,6,5,3,2,1] must already be SVal_INVALID */
      descr &= ~(TREE_DESCR_32_1 | TREE_DESCR_32_0);
      descr |= TREE_DESCR_64;
   }
   return descr;
}

/* This takes a cacheline where all the data is at the leaves
   (w8[..]) and builds a correctly normalised tree. */
static void normalise_CacheLine ( /*MOD*/CacheLine* cl )
{
   Word tno, cloff;
   for (tno = 0, cloff = 0;  tno < N_LINE_TREES;  tno++, cloff += 8) {
      SVal* tree = &cl->svals[cloff];
      cl->descrs[tno] = normalise_tree( tree );
   }
   tl_assert(cloff == N_LINE_ARANGE);
   if (SCE_CACHELINE)
      tl_assert(is_sane_CacheLine(cl)); /* EXPENSIVE */
   stats__cline_normalises++;
}


typedef struct { UChar count; SVal sval; } CountedSVal;

static
void sequentialise_CacheLine ( /*OUT*/CountedSVal* dst,
                               /*OUT*/Word* dstUsedP,
                               Word nDst, CacheLine* src )
{
   Word  tno, cloff, dstUsed;

   tl_assert(nDst == N_LINE_ARANGE);
   dstUsed = 0;

   for (tno = 0, cloff = 0;  tno < N_LINE_TREES;  tno++, cloff += 8) {
      UShort descr = src->descrs[tno];
      SVal*  tree  = &src->svals[cloff];

      /* sequentialise the tree described by (descr,tree). */
#     define PUT(_n,_v)                                \
         do { dst[dstUsed  ].count = (_n);             \
              dst[dstUsed++].sval  = (_v);             \
         } while (0)

      /* byte 0 */
      if (descr & TREE_DESCR_64)   PUT(8, tree[0]); else
      if (descr & TREE_DESCR_32_0) PUT(4, tree[0]); else
      if (descr & TREE_DESCR_16_0) PUT(2, tree[0]); else
      if (descr & TREE_DESCR_8_0)  PUT(1, tree[0]);
      /* byte 1 */
      if (descr & TREE_DESCR_8_1)  PUT(1, tree[1]);
      /* byte 2 */
      if (descr & TREE_DESCR_16_1) PUT(2, tree[2]); else
      if (descr & TREE_DESCR_8_2)  PUT(1, tree[2]);
      /* byte 3 */
      if (descr & TREE_DESCR_8_3)  PUT(1, tree[3]);
      /* byte 4 */
      if (descr & TREE_DESCR_32_1) PUT(4, tree[4]); else
      if (descr & TREE_DESCR_16_2) PUT(2, tree[4]); else
      if (descr & TREE_DESCR_8_4)  PUT(1, tree[4]);
      /* byte 5 */
      if (descr & TREE_DESCR_8_5)  PUT(1, tree[5]);
      /* byte 6 */
      if (descr & TREE_DESCR_16_3) PUT(2, tree[6]); else
      if (descr & TREE_DESCR_8_6)  PUT(1, tree[6]);
      /* byte 7 */
      if (descr & TREE_DESCR_8_7)  PUT(1, tree[7]);

#     undef PUT
      /* END sequentialise the tree described by (descr,tree). */

   }
   tl_assert(cloff == N_LINE_ARANGE);
   tl_assert(dstUsed <= nDst);

   *dstUsedP = dstUsed;
}

/* Write the cacheline 'wix' to backing store.  Where it ends up
   is determined by its tag field. */
static __attribute__((noinline)) void cacheline_wback ( UWord wix )
{
   Word        i, j, k, m;
   Addr        tag;
   SecMap*     sm;
   CacheLine*  cl;
   LineZ* lineZ;
   LineF* lineF;
   Word        zix, fix, csvalsUsed;
   CountedSVal csvals[N_LINE_ARANGE];
   SVal        sv;

   if (0)
   VG_(printf)("scache wback line %d\n", (Int)wix);

   tl_assert(wix >= 0 && wix < N_WAY_NENT);

   tag =  cache_shmem.tags0[wix];
   cl  = &cache_shmem.lyns0[wix];

   /* The cache line may have been invalidated; if so, ignore it. */
   if (!is_valid_scache_tag(tag))
      return;

   /* Where are we going to put it? */
   sm         = NULL;
   lineZ      = NULL;
   lineF      = NULL;
   zix = fix = -1;

   /* find the Z line to write in and rcdec it or the associated F
      line. */
   find_Z_for_writing( &sm, &zix, tag );

   tl_assert(sm);
   tl_assert(zix >= 0 && zix < N_SECMAP_ZLINES);
   lineZ = &sm->linesZ[zix];

   /* Generate the data to be stored */
   if (SCE_CACHELINE)
      tl_assert(is_sane_CacheLine(cl)); /* EXPENSIVE */

   csvalsUsed = -1;
   sequentialise_CacheLine( csvals, &csvalsUsed, 
                            N_LINE_ARANGE, cl );
   tl_assert(csvalsUsed >= 1 && csvalsUsed <= N_LINE_ARANGE);
   if (0) VG_(printf)("%lu ", csvalsUsed);

   lineZ->dict[0] = lineZ->dict[1] 
                  = lineZ->dict[2] = lineZ->dict[3] = SVal_INVALID;

   /* i indexes actual shadow values, k is cursor in csvals */
   i = 0;
   for (k = 0; k < csvalsUsed; k++) {

      sv = csvals[k].sval;
      if (SCE_SVALS)
         tl_assert(csvals[k].count >= 1 && csvals[k].count <= 8);
      /* do we already have it? */
      if (sv == lineZ->dict[0]) { j = 0; goto dict_ok; }
      if (sv == lineZ->dict[1]) { j = 1; goto dict_ok; }
      if (sv == lineZ->dict[2]) { j = 2; goto dict_ok; }
      if (sv == lineZ->dict[3]) { j = 3; goto dict_ok; }
      /* no.  look for a free slot. */
      if (SCE_SVALS)
         tl_assert(sv != SVal_INVALID);
      if (lineZ->dict[0] 
          == SVal_INVALID) { lineZ->dict[0] = sv; j = 0; goto dict_ok; }
      if (lineZ->dict[1]
          == SVal_INVALID) { lineZ->dict[1] = sv; j = 1; goto dict_ok; }
      if (lineZ->dict[2]
          == SVal_INVALID) { lineZ->dict[2] = sv; j = 2; goto dict_ok; }
      if (lineZ->dict[3]
          == SVal_INVALID) { lineZ->dict[3] = sv; j = 3; goto dict_ok; }
      break; /* we'll have to use the f rep */
     dict_ok:
      m = csvals[k].count;
      if (m == 8) {
         write_twobit_array( lineZ->ix2s, i+0, j );
         write_twobit_array( lineZ->ix2s, i+1, j );
         write_twobit_array( lineZ->ix2s, i+2, j );
         write_twobit_array( lineZ->ix2s, i+3, j );
         write_twobit_array( lineZ->ix2s, i+4, j );
         write_twobit_array( lineZ->ix2s, i+5, j );
         write_twobit_array( lineZ->ix2s, i+6, j );
         write_twobit_array( lineZ->ix2s, i+7, j );
         i += 8;
      }
      else if (m == 4) {
         write_twobit_array( lineZ->ix2s, i+0, j );
         write_twobit_array( lineZ->ix2s, i+1, j );
         write_twobit_array( lineZ->ix2s, i+2, j );
         write_twobit_array( lineZ->ix2s, i+3, j );
         i += 4;
      }
      else if (m == 1) {
         write_twobit_array( lineZ->ix2s, i+0, j );
         i += 1;
      }
      else if (m == 2) {
         write_twobit_array( lineZ->ix2s, i+0, j );
         write_twobit_array( lineZ->ix2s, i+1, j );
         i += 2;
      }
      else {
         tl_assert(0); /* 8 4 2 or 1 are the only legitimate values for m */
      }

   }

   if (LIKELY(i == N_LINE_ARANGE)) {
      /* Construction of the compressed representation was
         successful. */
      rcinc_LineZ(lineZ);
      stats__cache_Z_wbacks++;
   } else {
      /* Cannot use the compressed(z) representation.  Use the full(f)
         rep instead. */
      tl_assert(i >= 0 && i < N_LINE_ARANGE);
      alloc_F_for_writing( sm, &fix );
      tl_assert(sm->linesF);
      tl_assert(sm->linesF_size > 0);
      tl_assert(fix >= 0 && fix < (Word)sm->linesF_size);
      lineF = &sm->linesF[fix];
      tl_assert(!lineF->inUse);
      lineZ->dict[0] = lineZ->dict[2] = lineZ->dict[3] = SVal_INVALID;
      lineZ->dict[1] = (SVal)fix;
      lineF->inUse = True;
      i = 0;
      for (k = 0; k < csvalsUsed; k++) {
         if (SCE_SVALS)
            tl_assert(csvals[k].count >= 1 && csvals[k].count <= 8);
         sv = csvals[k].sval;
         if (SCE_SVALS)
            tl_assert(sv != SVal_INVALID);
         for (m = csvals[k].count; m > 0; m--) {
            lineF->w64s[i] = sv;
            i++;
         }
      }
      tl_assert(i == N_LINE_ARANGE);
      rcinc_LineF(lineF);
      stats__cache_F_wbacks++;
   }

   //if (anyShared)
   //   sm->mbHasShared = True;

   /* mb_tidy_one_cacheline(); */
}

/* Fetch the cacheline 'wix' from the backing store.  The tag
   associated with 'wix' is assumed to have already been filled in;
   hence that is used to determine where in the backing store to read
   from. */
static __attribute__((noinline)) void cacheline_fetch ( UWord wix )
{
   Word       i;
   Addr       tag;
   CacheLine* cl;
   LineZ*     lineZ;
   LineF*     lineF;

   if (0)
   VG_(printf)("scache fetch line %d\n", (Int)wix);

   tl_assert(wix >= 0 && wix < N_WAY_NENT);

   tag =  cache_shmem.tags0[wix];
   cl  = &cache_shmem.lyns0[wix];

   /* reject nonsense requests */
   tl_assert(is_valid_scache_tag(tag));

   lineZ = NULL;
   lineF = NULL;
   find_ZF_for_reading( &lineZ, &lineF, tag );
   tl_assert( (lineZ && !lineF) || (!lineZ && lineF) );

   /* expand the data into the bottom layer of the tree, then get
      cacheline_normalise to build the descriptor array. */
   if (lineF) {
      tl_assert(lineF->inUse);
      for (i = 0; i < N_LINE_ARANGE; i++) {
         cl->svals[i] = lineF->w64s[i];
      }
      stats__cache_F_fetches++;
   } else {
      for (i = 0; i < N_LINE_ARANGE; i++) {
         SVal sv;
         UWord ix = read_twobit_array( lineZ->ix2s, i );
         /* correct, but expensive: tl_assert(ix >= 0 && ix <= 3); */
         sv = lineZ->dict[ix];
         tl_assert(sv != SVal_INVALID);
         cl->svals[i] = sv;
      }
      stats__cache_Z_fetches++;
   }
   normalise_CacheLine( cl );
}

static void shmem__invalidate_scache ( void ) {
   Word wix;
   if (0) VG_(printf)("%s","scache inval\n");
   tl_assert(!is_valid_scache_tag(1));
   for (wix = 0; wix < N_WAY_NENT; wix++) {
      cache_shmem.tags0[wix] = 1/*INVALID*/;
   }
   stats__cache_invals++;
}

static void shmem__flush_and_invalidate_scache ( void ) {
   Word wix;
   Addr tag;
   if (0) VG_(printf)("%s","scache flush and invalidate\n");
   tl_assert(!is_valid_scache_tag(1));
   for (wix = 0; wix < N_WAY_NENT; wix++) {
      tag = cache_shmem.tags0[wix];
      if (tag == 1/*INVALID*/) {
         /* already invalid; nothing to do */
      } else {
         tl_assert(is_valid_scache_tag(tag));
         cacheline_wback( wix );
      }
      cache_shmem.tags0[wix] = 1/*INVALID*/;
   }
   stats__cache_flushes++;
   stats__cache_invals++;
}


static inline Bool aligned16 ( Addr a ) {
   return 0 == (a & 1);
}
static inline Bool aligned32 ( Addr a ) {
   return 0 == (a & 3);
}
static inline Bool aligned64 ( Addr a ) {
   return 0 == (a & 7);
}
static inline UWord get_cacheline_offset ( Addr a ) {
   return (UWord)(a & (N_LINE_ARANGE - 1));
}
static inline Addr cacheline_ROUNDUP ( Addr a ) {
   return ROUNDUP(a, N_LINE_ARANGE);
}
static inline Addr cacheline_ROUNDDN ( Addr a ) {
   return ROUNDDN(a, N_LINE_ARANGE);
}
static inline UWord get_treeno ( Addr a ) {
   return get_cacheline_offset(a) >> 3;
}
static inline UWord get_tree_offset ( Addr a ) {
   return a & 7;
}

static __attribute__((noinline))
       CacheLine* get_cacheline_MISS ( Addr a ); /* fwds */
static inline CacheLine* get_cacheline ( Addr a )
{
   /* tag is 'a' with the in-line offset masked out, 
      eg a[31]..a[4] 0000 */
   Addr       tag = a & ~(N_LINE_ARANGE - 1);
   UWord      wix = (a >> N_LINE_BITS) & (N_WAY_NENT - 1);
   stats__cache_totrefs++;
   if (LIKELY(tag == cache_shmem.tags0[wix])) {
      return &cache_shmem.lyns0[wix];
   } else {
      return get_cacheline_MISS( a );
   }
}

static __attribute__((noinline))
       CacheLine* get_cacheline_MISS ( Addr a )
{
   /* tag is 'a' with the in-line offset masked out, 
      eg a[31]..a[4] 0000 */

   CacheLine* cl;
   Addr*      tag_old_p;
   Addr       tag = a & ~(N_LINE_ARANGE - 1);
   UWord      wix = (a >> N_LINE_BITS) & (N_WAY_NENT - 1);

   tl_assert(tag != cache_shmem.tags0[wix]);

   /* Dump the old line into the backing store. */
   stats__cache_totmisses++;

   cl        = &cache_shmem.lyns0[wix];
   tag_old_p = &cache_shmem.tags0[wix];

   if (is_valid_scache_tag( *tag_old_p )) {
      /* EXPENSIVE and REDUNDANT: callee does it */
      if (SCE_CACHELINE)
         tl_assert(is_sane_CacheLine(cl)); /* EXPENSIVE */
      cacheline_wback( wix );
   }
   /* and reload the new one */
   *tag_old_p = tag;
   cacheline_fetch( wix );
   if (SCE_CACHELINE)
      tl_assert(is_sane_CacheLine(cl)); /* EXPENSIVE */
   return cl;
}

static UShort pulldown_to_32 ( /*MOD*/SVal* tree, UWord toff, UShort descr ) {
   stats__cline_64to32pulldown++;
   switch (toff) {
      case 0: case 4:
         tl_assert(descr & TREE_DESCR_64);
         tree[4] = tree[0];
         descr &= ~TREE_DESCR_64;
         descr |= (TREE_DESCR_32_1 | TREE_DESCR_32_0);
         break;
      default:
         tl_assert(0);
   }
   return descr;
}

static UShort pulldown_to_16 ( /*MOD*/SVal* tree, UWord toff, UShort descr ) {
   stats__cline_32to16pulldown++;
   switch (toff) {
      case 0: case 2:
         if (!(descr & TREE_DESCR_32_0)) {
            descr = pulldown_to_32(tree, 0, descr);
         }
         tl_assert(descr & TREE_DESCR_32_0);
         tree[2] = tree[0];
         descr &= ~TREE_DESCR_32_0;
         descr |= (TREE_DESCR_16_1 | TREE_DESCR_16_0);
         break;
      case 4: case 6:
         if (!(descr & TREE_DESCR_32_1)) {
            descr = pulldown_to_32(tree, 4, descr);
         }
         tl_assert(descr & TREE_DESCR_32_1);
         tree[6] = tree[4];
         descr &= ~TREE_DESCR_32_1;
         descr |= (TREE_DESCR_16_3 | TREE_DESCR_16_2);
         break;
      default:
         tl_assert(0);
   }
   return descr;
}

static UShort pulldown_to_8 ( /*MOD*/SVal* tree, UWord toff, UShort descr ) {
   stats__cline_16to8pulldown++;
   switch (toff) {
      case 0: case 1:
         if (!(descr & TREE_DESCR_16_0)) {
            descr = pulldown_to_16(tree, 0, descr);
         }
         tl_assert(descr & TREE_DESCR_16_0);
         tree[1] = tree[0];
         descr &= ~TREE_DESCR_16_0;
         descr |= (TREE_DESCR_8_1 | TREE_DESCR_8_0);
         break;
      case 2: case 3:
         if (!(descr & TREE_DESCR_16_1)) {
            descr = pulldown_to_16(tree, 2, descr);
         }
         tl_assert(descr & TREE_DESCR_16_1);
         tree[3] = tree[2];
         descr &= ~TREE_DESCR_16_1;
         descr |= (TREE_DESCR_8_3 | TREE_DESCR_8_2);
         break;
      case 4: case 5:
         if (!(descr & TREE_DESCR_16_2)) {
            descr = pulldown_to_16(tree, 4, descr);
         }
         tl_assert(descr & TREE_DESCR_16_2);
         tree[5] = tree[4];
         descr &= ~TREE_DESCR_16_2;
         descr |= (TREE_DESCR_8_5 | TREE_DESCR_8_4);
         break;
      case 6: case 7:
         if (!(descr & TREE_DESCR_16_3)) {
            descr = pulldown_to_16(tree, 6, descr);
         }
         tl_assert(descr & TREE_DESCR_16_3);
         tree[7] = tree[6];
         descr &= ~TREE_DESCR_16_3;
         descr |= (TREE_DESCR_8_7 | TREE_DESCR_8_6);
         break;
      default:
         tl_assert(0);
   }
   return descr;
}


static UShort pullup_descr_to_16 ( UShort descr, UWord toff ) {
   UShort mask;
   switch (toff) {
      case 0:
         mask = TREE_DESCR_8_1 | TREE_DESCR_8_0;
         tl_assert( (descr & mask) == mask );
         descr &= ~mask;
         descr |= TREE_DESCR_16_0;
         break;
      case 2:
         mask = TREE_DESCR_8_3 | TREE_DESCR_8_2;
         tl_assert( (descr & mask) == mask );
         descr &= ~mask;
         descr |= TREE_DESCR_16_1;
         break;
      case 4:
         mask = TREE_DESCR_8_5 | TREE_DESCR_8_4;
         tl_assert( (descr & mask) == mask );
         descr &= ~mask;
         descr |= TREE_DESCR_16_2;
         break;
      case 6:
         mask = TREE_DESCR_8_7 | TREE_DESCR_8_6;
         tl_assert( (descr & mask) == mask );
         descr &= ~mask;
         descr |= TREE_DESCR_16_3;
         break;
      default:
         tl_assert(0);
   }
   return descr;
}

static UShort pullup_descr_to_32 ( UShort descr, UWord toff ) {
   UShort mask;
   switch (toff) {
      case 0:
         if (!(descr & TREE_DESCR_16_0))
            descr = pullup_descr_to_16(descr, 0);
         if (!(descr & TREE_DESCR_16_1))
            descr = pullup_descr_to_16(descr, 2);
         mask = TREE_DESCR_16_1 | TREE_DESCR_16_0;
         tl_assert( (descr & mask) == mask );
         descr &= ~mask;
         descr |= TREE_DESCR_32_0;
         break;
      case 4:
         if (!(descr & TREE_DESCR_16_2))
            descr = pullup_descr_to_16(descr, 4);
         if (!(descr & TREE_DESCR_16_3))
            descr = pullup_descr_to_16(descr, 6);
         mask = TREE_DESCR_16_3 | TREE_DESCR_16_2;
         tl_assert( (descr & mask) == mask );
         descr &= ~mask;
         descr |= TREE_DESCR_32_1;
         break;
      default:
         tl_assert(0);
   }
   return descr;
}

static Bool valid_value_is_above_me_32 ( UShort descr, UWord toff ) {
   switch (toff) {
      case 0: case 4:
         return 0 != (descr & TREE_DESCR_64);
      default:
         tl_assert(0);
   }
}

static Bool valid_value_is_below_me_16 ( UShort descr, UWord toff ) {
   switch (toff) {
      case 0:
         return 0 != (descr & (TREE_DESCR_8_1 | TREE_DESCR_8_0));
      case 2:
         return 0 != (descr & (TREE_DESCR_8_3 | TREE_DESCR_8_2));
      case 4:
         return 0 != (descr & (TREE_DESCR_8_5 | TREE_DESCR_8_4));
      case 6:
         return 0 != (descr & (TREE_DESCR_8_7 | TREE_DESCR_8_6));
      default:
         tl_assert(0);
   }
}

static
void zsm_apply8 ( Addr a, SVal(*fn)(SVal,void*), void* fn_opaque ) {
   CacheLine* cl; 
   UWord      cloff, tno, toff;
   SVal       svOld, svNew;
   UShort     descr;
   stats__cline_read8s++;
   cl    = get_cacheline(a);
   cloff = get_cacheline_offset(a);
   tno   = get_treeno(a);
   toff  = get_tree_offset(a); /* == 0 .. 7 */
   descr = cl->descrs[tno];
   if (UNLIKELY( !(descr & (TREE_DESCR_8_0 << toff)) )) {
      SVal* tree = &cl->svals[tno << 3];
      cl->descrs[tno] = pulldown_to_8(tree, toff, descr);
      if (SCE_CACHELINE)
         tl_assert(is_sane_CacheLine(cl)); /* EXPENSIVE */
   }
   svOld = cl->svals[cloff];
   svNew = fn( svOld, fn_opaque );
   tl_assert(svNew != SVal_INVALID);
   cl->svals[cloff] = svNew;
}

static
void zsm_apply16 ( Addr a, SVal(*fn)(SVal,void*), void* fn_opaque ) {
   CacheLine* cl; 
   UWord      cloff, tno, toff;
   SVal       svOld, svNew;
   UShort     descr;
   stats__cline_read16s++;
   if (UNLIKELY(!aligned16(a))) goto slowcase;
   cl    = get_cacheline(a);
   cloff = get_cacheline_offset(a);
   tno   = get_treeno(a);
   toff  = get_tree_offset(a); /* == 0, 2, 4 or 6 */
   descr = cl->descrs[tno];
   if (UNLIKELY( !(descr & (TREE_DESCR_16_0 << toff)) )) {
      if (valid_value_is_below_me_16(descr, toff)) {
         goto slowcase;
      } else {
         SVal* tree = &cl->svals[tno << 3];
         cl->descrs[tno] = pulldown_to_16(tree, toff, descr);
      }
      if (SCE_CACHELINE)
         tl_assert(is_sane_CacheLine(cl)); /* EXPENSIVE */
   }
   svOld = cl->svals[cloff];
   svNew = fn( svOld, fn_opaque );
   tl_assert(svNew != SVal_INVALID);
   cl->svals[cloff] = svNew;
   return;
  slowcase: /* misaligned, or must go further down the tree */
   stats__cline_16to8splits++;
   zsm_apply8( a + 0, fn, fn_opaque );
   zsm_apply8( a + 1, fn, fn_opaque );
}

__attribute__((noinline))
static
void zsm_apply32_SLOW ( Addr a, SVal(*fn)(SVal,void*), void* fn_opaque ) {
   CacheLine* cl; 
   UWord      cloff, tno, toff;
   SVal       svOld, svNew;
   UShort     descr;
   if (UNLIKELY(!aligned32(a))) goto slowcase;
   cl    = get_cacheline(a);
   cloff = get_cacheline_offset(a);
   tno   = get_treeno(a);
   toff  = get_tree_offset(a); /* == 0 or 4 */
   descr = cl->descrs[tno];
   if (UNLIKELY( !(descr & (TREE_DESCR_32_0 << toff)) )) {
      if (valid_value_is_above_me_32(descr, toff)) {
         SVal* tree = &cl->svals[tno << 3];
         cl->descrs[tno] = pulldown_to_32(tree, toff, descr);
      } else {
         goto slowcase;
      }
      if (SCE_CACHELINE)
         tl_assert(is_sane_CacheLine(cl)); /* EXPENSIVE */
   }
   svOld = cl->svals[cloff];
   svNew = fn( svOld, fn_opaque );
   tl_assert(svNew != SVal_INVALID);
   cl->svals[cloff] = svNew;
   return;
  slowcase: /* misaligned, or must go further down the tree */
   stats__cline_32to16splits++;
   zsm_apply16( a + 0, fn, fn_opaque );
   zsm_apply16( a + 2, fn, fn_opaque );
}

static
void zsm_apply32 ( Addr a, SVal(*fn)(SVal,void*), void* fn_opaque ) {
   CacheLine* cl; 
   UWord      cloff, tno, toff;
   UShort     descr;
   stats__cline_read32s++;
   if (UNLIKELY(!aligned32(a))) goto slowcase;
   cl    = get_cacheline(a);
   cloff = get_cacheline_offset(a);
   tno   = get_treeno(a);
   toff  = get_tree_offset(a); /* == 0 or 4 */
   descr = cl->descrs[tno];
   if (UNLIKELY( !(descr & (TREE_DESCR_32_0 << toff)) )) goto slowcase;
   { SVal* p     = &cl->svals[cloff];
     SVal  svOld = *p;
     SVal  svNew = fn( svOld, fn_opaque );
     tl_assert(svNew != SVal_INVALID);
     *p = svNew;
   }
   return;
  slowcase: /* misaligned, or not at this level in the tree */
   zsm_apply32_SLOW( a, fn, fn_opaque );
}

static
void zsm_apply64 ( Addr a, SVal(*fn)(SVal,void*), void* fn_opaque ) {
   CacheLine* cl; 
   UWord      cloff, tno, toff;
   SVal       svOld, svNew;
   UShort     descr;
   stats__cline_read64s++;
   if (UNLIKELY(!aligned64(a))) goto slowcase;
   cl    = get_cacheline(a);
   cloff = get_cacheline_offset(a);
   tno   = get_treeno(a);
   toff  = get_tree_offset(a); /* == 0, unused */
   descr = cl->descrs[tno];
   if (UNLIKELY( !(descr & TREE_DESCR_64) )) {
      goto slowcase;
   }
   svOld = cl->svals[cloff];
   svNew = fn( svOld, fn_opaque );
   tl_assert(svNew != SVal_INVALID);
   cl->svals[cloff] = svNew;
   return;
  slowcase: /* misaligned, or must go further down the tree */
   stats__cline_64to32splits++;
   zsm_apply32( a + 0, fn, fn_opaque );
   zsm_apply32( a + 4, fn, fn_opaque );
}

static
void zsm_write8 ( Addr a, SVal svNew ) {
   CacheLine* cl; 
   UWord      cloff, tno, toff;
   UShort     descr;
   stats__cline_set8s++;
   cl    = get_cacheline(a);
   cloff = get_cacheline_offset(a);
   tno   = get_treeno(a);
   toff  = get_tree_offset(a); /* == 0 .. 7 */
   descr = cl->descrs[tno];
   if (UNLIKELY( !(descr & (TREE_DESCR_8_0 << toff)) )) {
      SVal* tree = &cl->svals[tno << 3];
      cl->descrs[tno] = pulldown_to_8(tree, toff, descr);
      if (SCE_CACHELINE)
         tl_assert(is_sane_CacheLine(cl)); /* EXPENSIVE */
   }
   tl_assert(svNew != SVal_INVALID);
   cl->svals[cloff] = svNew;
}

static
void zsm_write16 ( Addr a, SVal svNew ) {
   CacheLine* cl; 
   UWord      cloff, tno, toff;
   UShort     descr;
   stats__cline_set16s++;
   if (UNLIKELY(!aligned16(a))) goto slowcase;
   cl    = get_cacheline(a);
   cloff = get_cacheline_offset(a);
   tno   = get_treeno(a);
   toff  = get_tree_offset(a); /* == 0, 2, 4 or 6 */
   descr = cl->descrs[tno];
   if (UNLIKELY( !(descr & (TREE_DESCR_16_0 << toff)) )) {
      if (valid_value_is_below_me_16(descr, toff)) {
         /* Writing at this level.  Need to fix up 'descr'. */
         cl->descrs[tno] = pullup_descr_to_16(descr, toff);
         /* At this point, the tree does not match cl->descr[tno] any
            more.  The assignments below will fix it up. */
      } else {
         /* We can't indiscriminately write on the w16 node as in the
            w64 case, as that might make the node inconsistent with
            its parent.  So first, pull down to this level. */
         SVal* tree = &cl->svals[tno << 3];
         cl->descrs[tno] = pulldown_to_16(tree, toff, descr);
      if (SCE_CACHELINE)
         tl_assert(is_sane_CacheLine(cl)); /* EXPENSIVE */
      }
   }
   tl_assert(svNew != SVal_INVALID);
   cl->svals[cloff + 0] = svNew;
   cl->svals[cloff + 1] = SVal_INVALID;
   return;
  slowcase: /* misaligned */
   stats__cline_16to8splits++;
   zsm_write8( a + 0, svNew );
   zsm_write8( a + 1, svNew );
}

static
void zsm_write32 ( Addr a, SVal svNew ) {
   CacheLine* cl; 
   UWord      cloff, tno, toff;
   UShort     descr;
   stats__cline_set32s++;
   if (UNLIKELY(!aligned32(a))) goto slowcase;
   cl    = get_cacheline(a);
   cloff = get_cacheline_offset(a);
   tno   = get_treeno(a);
   toff  = get_tree_offset(a); /* == 0 or 4 */
   descr = cl->descrs[tno];
   if (UNLIKELY( !(descr & (TREE_DESCR_32_0 << toff)) )) {
      if (valid_value_is_above_me_32(descr, toff)) {
         /* We can't indiscriminately write on the w32 node as in the
            w64 case, as that might make the node inconsistent with
            its parent.  So first, pull down to this level. */
         SVal* tree = &cl->svals[tno << 3];
         cl->descrs[tno] = pulldown_to_32(tree, toff, descr);
         if (SCE_CACHELINE)
            tl_assert(is_sane_CacheLine(cl)); /* EXPENSIVE */
      } else {
         /* Writing at this level.  Need to fix up 'descr'. */
         cl->descrs[tno] = pullup_descr_to_32(descr, toff);
         /* At this point, the tree does not match cl->descr[tno] any
            more.  The assignments below will fix it up. */
      }
   }
   tl_assert(svNew != SVal_INVALID);
   cl->svals[cloff + 0] = svNew;
   cl->svals[cloff + 1] = SVal_INVALID;
   cl->svals[cloff + 2] = SVal_INVALID;
   cl->svals[cloff + 3] = SVal_INVALID;
   return;
  slowcase: /* misaligned */
   stats__cline_32to16splits++;
   zsm_write16( a + 0, svNew );
   zsm_write16( a + 2, svNew );
}

static
void zsm_write64 ( Addr a, SVal svNew ) {
   CacheLine* cl; 
   UWord      cloff, tno, toff;
   stats__cline_set64s++;
   if (UNLIKELY(!aligned64(a))) goto slowcase;
   cl    = get_cacheline(a);
   cloff = get_cacheline_offset(a);
   tno   = get_treeno(a);
   toff  = get_tree_offset(a); /* == 0 */
   cl->descrs[tno] = TREE_DESCR_64;
   tl_assert(svNew != SVal_INVALID);
   cl->svals[cloff + 0] = svNew;
   cl->svals[cloff + 1] = SVal_INVALID;
   cl->svals[cloff + 2] = SVal_INVALID;
   cl->svals[cloff + 3] = SVal_INVALID;
   cl->svals[cloff + 4] = SVal_INVALID;
   cl->svals[cloff + 5] = SVal_INVALID;
   cl->svals[cloff + 6] = SVal_INVALID;
   cl->svals[cloff + 7] = SVal_INVALID;
   return;
  slowcase: /* misaligned */
   stats__cline_64to32splits++;
   zsm_write32( a + 0, svNew );
   zsm_write32( a + 4, svNew );
}

static
SVal zsm_read8 ( Addr a ) {
   CacheLine* cl; 
   UWord      cloff, tno, toff;
   UShort     descr;
   stats__cline_get8s++;
   cl    = get_cacheline(a);
   cloff = get_cacheline_offset(a);
   tno   = get_treeno(a);
   toff  = get_tree_offset(a); /* == 0 .. 7 */
   descr = cl->descrs[tno];
   if (UNLIKELY( !(descr & (TREE_DESCR_8_0 << toff)) )) {
      SVal* tree = &cl->svals[tno << 3];
      cl->descrs[tno] = pulldown_to_8(tree, toff, descr);
   }
   return cl->svals[cloff];
}

static void zsm_copy8 ( Addr src, Addr dst, Bool uu_normalise ) {
   SVal       sv;
   stats__cline_copy8s++;
   sv = zsm_read8( src );
   zsm_write8( dst, sv );
}

/* ------------ Shadow memory range setting ops ------------ */

/* Apply 'fn' to SVals in the given range. */

static void zsm_apply_range ( Addr a, SizeT len,
                              SVal(*fn)(SVal,void*), void* fn_opaque )
{
   /* fast track a couple of common cases */
   if (len == 4 && aligned32(a)) {
      zsm_apply32( a, fn, fn_opaque );
      return;
   }
   if (len == 8 && aligned64(a)) {
      zsm_apply64( a, fn, fn_opaque );
      return;
   }

   /* be completely general (but as efficient as possible) */
   if (len == 0) return;

   if (!aligned16(a) && len >= 1) {
      zsm_apply8( a, fn, fn_opaque );
      a += 1;
      len -= 1;
      tl_assert(aligned16(a));
   }
   if (len == 0) return;

   if (!aligned32(a) && len >= 2) {
      zsm_apply16( a, fn, fn_opaque );
      a += 2;
      len -= 2;
      tl_assert(aligned32(a));
   }
   if (len == 0) return;

   if (!aligned64(a) && len >= 4) {
      zsm_apply32( a, fn, fn_opaque );
      a += 4;
      len -= 4;
      tl_assert(aligned64(a));
   }
   if (len == 0) return;

   if (len >= 8) {
      tl_assert(aligned64(a));
      while (len >= 8) {
         zsm_apply64( a, fn, fn_opaque );
         a += 8;
         len -= 8;
      }
      tl_assert(aligned64(a));
   }
   if (len == 0) return;

   if (len >= 4)
      tl_assert(aligned32(a));
   if (len >= 4) {
      zsm_apply32( a, fn, fn_opaque );
      a += 4;
      len -= 4;
   }
   if (len == 0) return;

   if (len >= 2)
      tl_assert(aligned16(a));
   if (len >= 2) {
      zsm_apply16( a, fn, fn_opaque );
      a += 2;
      len -= 2;
   }
   if (len == 0) return;

   if (len >= 1) {
      zsm_apply8( a, fn, fn_opaque );
      a += 1;
      len -= 1;
   }
   tl_assert(len == 0);
}

/* Block-copy states (needed for implementing realloc()). */

static void zsm_copy_range ( Addr src, Addr dst, SizeT len )
{
   SizeT i;
   if (len == 0)
      return;

   /* assert for non-overlappingness */
   tl_assert(src+len <= dst || dst+len <= src);

   /* To be simple, just copy byte by byte.  But so as not to wreck
      performance for later accesses to dst[0 .. len-1], normalise
      destination lines as we finish with them, and also normalise the
      line containing the first and last address. */
   for (i = 0; i < len; i++) {
      Bool normalise
         = get_cacheline_offset( dst+i+1 ) == 0 /* last in line */
           || i == 0       /* first in range */
           || i == len-1;  /* last in range */
      zsm_copy8( src+i, dst+i, normalise );
   }
}


/* For setting address ranges to a given value.  Has considerable
   sophistication so as to avoid generating large numbers of pointless
   cache loads/writebacks for large ranges. */

/* Do small ranges in-cache, in the obvious way. */
static
void zsm_set_range_SMALL ( Addr a, SizeT len, SVal svNew )
{
   /* fast track a couple of common cases */
   if (len == 4 && aligned32(a)) {
      zsm_write32( a, svNew );
      return;
   }
   if (len == 8 && aligned64(a)) {
      zsm_write64( a, svNew );
      return;
   }

   /* be completely general (but as efficient as possible) */
   if (len == 0) return;

   if (!aligned16(a) && len >= 1) {
      zsm_write8( a, svNew );
      a += 1;
      len -= 1;
      tl_assert(aligned16(a));
   }
   if (len == 0) return;

   if (!aligned32(a) && len >= 2) {
      zsm_write16( a, svNew );
      a += 2;
      len -= 2;
      tl_assert(aligned32(a));
   }
   if (len == 0) return;

   if (!aligned64(a) && len >= 4) {
      zsm_write32( a, svNew );
      a += 4;
      len -= 4;
      tl_assert(aligned64(a));
   }
   if (len == 0) return;

   if (len >= 8) {
      tl_assert(aligned64(a));
      while (len >= 8) {
         zsm_write64( a, svNew );
         a += 8;
         len -= 8;
      }
      tl_assert(aligned64(a));
   }
   if (len == 0) return;

   if (len >= 4)
      tl_assert(aligned32(a));
   if (len >= 4) {
      zsm_write32( a, svNew );
      a += 4;
      len -= 4;
   }
   if (len == 0) return;

   if (len >= 2)
      tl_assert(aligned16(a));
   if (len >= 2) {
      zsm_write16( a, svNew );
      a += 2;
      len -= 2;
   }
   if (len == 0) return;

   if (len >= 1) {
      zsm_write8( a, svNew );
      a += 1;
      len -= 1;
   }
   tl_assert(len == 0);
}


/* If we're doing a small range, hand off to zsm_set_range_SMALL.  But
   for larger ranges, try to operate directly on the out-of-cache
   representation, rather than dragging lines into the cache,
   overwriting them, and forcing them out.  This turns out to be an
   important performance optimisation. */

static void zsm_set_range ( Addr a, SizeT len, SVal svNew )
{
   tl_assert(svNew != SVal_INVALID);
   stats__cache_make_New_arange += (ULong)len;

   if (0 && len > 500)
      VG_(printf)("make New      ( %#lx, %ld )\n", a, len );

   if (0) {
      static UWord n_New_in_cache = 0;
      static UWord n_New_not_in_cache = 0;
      /* tag is 'a' with the in-line offset masked out, 
         eg a[31]..a[4] 0000 */
      Addr       tag = a & ~(N_LINE_ARANGE - 1);
      UWord      wix = (a >> N_LINE_BITS) & (N_WAY_NENT - 1);
      if (LIKELY(tag == cache_shmem.tags0[wix])) {
         n_New_in_cache++;
      } else {
         n_New_not_in_cache++;
      }
      if (0 == ((n_New_in_cache + n_New_not_in_cache) % 100000))
         VG_(printf)("shadow_mem_make_New: IN %lu OUT %lu\n",
                     n_New_in_cache, n_New_not_in_cache );
   }

   if (LIKELY(len < 2 * N_LINE_ARANGE)) {
      zsm_set_range_SMALL( a, len, svNew );
   } else {
      Addr  before_start  = a;
      Addr  aligned_start = cacheline_ROUNDUP(a);
      Addr  after_start   = cacheline_ROUNDDN(a + len);
      UWord before_len    = aligned_start - before_start;
      UWord aligned_len   = after_start - aligned_start;
      UWord after_len     = a + len - after_start;
      tl_assert(before_start <= aligned_start);
      tl_assert(aligned_start <= after_start);
      tl_assert(before_len < N_LINE_ARANGE);
      tl_assert(after_len < N_LINE_ARANGE);
      tl_assert(get_cacheline_offset(aligned_start) == 0);
      if (get_cacheline_offset(a) == 0) {
         tl_assert(before_len == 0);
         tl_assert(a == aligned_start);
      }
      if (get_cacheline_offset(a+len) == 0) {
         tl_assert(after_len == 0);
         tl_assert(after_start == a+len);
      }
      if (before_len > 0) {
         zsm_set_range_SMALL( before_start, before_len, svNew );
      }
      if (after_len > 0) {
         zsm_set_range_SMALL( after_start, after_len, svNew );
      }
      stats__cache_make_New_inZrep += (ULong)aligned_len;

      while (1) {
         Addr tag;
         UWord wix;
         if (aligned_start >= after_start)
            break;
         tl_assert(get_cacheline_offset(aligned_start) == 0);
         tag = aligned_start & ~(N_LINE_ARANGE - 1);
         wix = (aligned_start >> N_LINE_BITS) & (N_WAY_NENT - 1);
         if (tag == cache_shmem.tags0[wix]) {
            UWord i;
            for (i = 0; i < N_LINE_ARANGE / 8; i++)
               zsm_write64( aligned_start + i * 8, svNew );
         } else {
            UWord i;
            Word zix;
            SecMap* sm;
            LineZ* lineZ;
            /* This line is not in the cache.  Do not force it in; instead
               modify it in-place. */
            /* find the Z line to write in and rcdec it or the
               associated F line. */
            find_Z_for_writing( &sm, &zix, tag );
            tl_assert(sm);
            tl_assert(zix >= 0 && zix < N_SECMAP_ZLINES);
            lineZ = &sm->linesZ[zix];
            lineZ->dict[0] = svNew;
            lineZ->dict[1] = lineZ->dict[2] = lineZ->dict[3] = SVal_INVALID;
            for (i = 0; i < N_LINE_ARANGE/4; i++)
               lineZ->ix2s[i] = 0; /* all refer to dict[0] */
            rcinc_LineZ(lineZ);
         }
         aligned_start += N_LINE_ARANGE;
         aligned_len -= N_LINE_ARANGE;
      }
      tl_assert(aligned_start == after_start);
      tl_assert(aligned_len == 0);
   }
}


static void zsm_flush_cache ( void )
{
   shmem__flush_and_invalidate_scache();
}


static void zsm_init ( void(*p_rcinc)(SVal), void(*p_rcdec)(SVal) )
{
   tl_assert( sizeof(UWord) == sizeof(Addr) );

   rcinc = p_rcinc;
   rcdec = p_rcdec;

   tl_assert(map_shmem == NULL);
   map_shmem = HG_(newFM)( main_zalloc, "libhb.zsm_init.1 (map_shmem)",
                           main_dealloc, 
                           NULL/*unboxed UWord cmp*/);
   tl_assert(map_shmem != NULL);
   shmem__invalidate_scache();

   /* a SecMap must contain an integral number of CacheLines */
   tl_assert(0 == (N_SECMAP_ARANGE % N_LINE_ARANGE));
   /* also ... a CacheLine holds an integral number of trees */
   tl_assert(0 == (N_LINE_ARANGE % 8));
}

/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
//                                                             //
// SECTION END compressed shadow memory                        //
//                                                             //
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////



/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
//                                                             //
// SECTION BEGIN vts primitives                                //
//                                                             //
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////

#ifndef __HB_VTS_H
#define __HB_VTS_H

/* VtsIDs can't exceed 30 bits, since they have to be packed into the
   lowest 30 bits of an SVal. */
typedef  UInt  VtsID;
#define VtsID_INVALID 0xFFFFFFFF

/* A VTS contains .ts, its vector clock, and also .id, a field to hold
   a backlink for the caller's convenience.  Since we have no idea
   what to set that to in the library, it always gets set to
   VtsID_INVALID. */
typedef
   struct {
      VtsID   id;
      XArray* ts; /* XArray* ScalarTS(abstract) */
   }
   VTS;


/* Create a new, empty VTS. */
VTS* VTS__new ( void );

/* Delete this VTS in its entirety. */
void VTS__delete ( VTS* vts );

/* Create a new singleton VTS. */
VTS* VTS__singleton ( Thr* thr, ULong tym );

/* Return a new VTS in which vts[me]++, so to speak.  'vts' itself is
   not modified. */
VTS* VTS__tick ( Thr* me, VTS* vts );

/* Return a new VTS constructed as the join (max) of the 2 args.
   Neither arg is modified. */
VTS* VTS__join ( VTS* a, VTS* b );

/* Compute the partial ordering relation of the two args. */
typedef
   enum { POrd_EQ=4, POrd_LT, POrd_GT, POrd_UN }
   POrd;

POrd VTS__cmp ( VTS* a, VTS* b );

/* Compute an arbitrary structural (total) ordering on the two args,
   based on their VCs, so they can be looked up in a table, tree, etc.
   Returns -1, 0 or 1. */
Word VTS__cmp_structural ( VTS* a, VTS* b );

/* Debugging only.  Display the given VTS in the buffer. */
void VTS__show ( HChar* buf, Int nBuf, VTS* vts );

/* Debugging only.  Return vts[index], so to speak. */
ULong VTS__indexAt_SLOW ( VTS* vts, Thr* index );

#endif /* ! __HB_VTS_H */


/*--------------- to do with Vector Timestamps ---------------*/

/* Scalar Timestamp */
typedef
   struct {
      Thr*    thr;
      ULong   tym;
   }
   ScalarTS;


static Bool is_sane_VTS ( VTS* vts )
{
   UWord     i, n;
   ScalarTS  *st1, *st2;
   if (!vts) return False;
   if (!vts->ts) return False;
   n = VG_(sizeXA)( vts->ts );
   if (n >= 2) {
      for (i = 0; i < n-1; i++) {
         st1 = VG_(indexXA)( vts->ts, i );
         st2 = VG_(indexXA)( vts->ts, i+1 );
         if (st1->thr >= st2->thr)
            return False;
         if (st1->tym == 0 || st2->tym == 0)
            return False;
      }
   }
   return True;
}


/* Create a new, empty VTS.
*/
VTS* VTS__new ( void )
{
   VTS* vts;
   vts = main_zalloc( "libhb.VTS__new.1", sizeof(VTS) );
   tl_assert(vts);
   vts->id = VtsID_INVALID;
   vts->ts = VG_(newXA)( main_zalloc, "libhb.VTS__new.2",
                         main_dealloc, sizeof(ScalarTS) );
   tl_assert(vts->ts);
   return vts;
}


/* Delete this VTS in its entirety.
*/
void VTS__delete ( VTS* vts )
{
   tl_assert(vts);
   tl_assert(vts->ts);
   VG_(deleteXA)( vts->ts );
   main_dealloc(vts);
}


/* Create a new singleton VTS. 
*/
VTS* VTS__singleton ( Thr* thr, ULong tym ) {
   ScalarTS st;
   VTS*     vts;
   tl_assert(thr);
   tl_assert(tym >= 1);
   vts = VTS__new();
   st.thr = thr;
   st.tym = tym;
   VG_(addToXA)( vts->ts, &st );
   return vts;
}


/* Return a new VTS in which vts[me]++, so to speak.  'vts' itself is
   not modified.
*/
VTS* VTS__tick ( Thr* me, VTS* vts )
{
   ScalarTS* here = NULL;
   ScalarTS  tmp;
   VTS*      res;
   Word      i, n; 
   tl_assert(me);
   tl_assert(is_sane_VTS(vts));
   //if (0) VG_(printf)("tick vts thrno %ld szin %d\n",
   //                   (Word)me->errmsg_index, (Int)VG_(sizeXA)(vts) );
   res = VTS__new();
   n = VG_(sizeXA)( vts->ts );

   /* main loop doesn't handle zero-entry case correctly, so
      special-case it. */
   if (n == 0) {
      tmp.thr = me;
      tmp.tym = 1;
      VG_(addToXA)( res->ts, &tmp );
      tl_assert(is_sane_VTS(res));
      return res;
   }

   for (i = 0; i < n; i++) {
      here = VG_(indexXA)( vts->ts, i );
      if (me < here->thr) {
         /* We just went past 'me', without seeing it. */
         tmp.thr = me;
         tmp.tym = 1;
         VG_(addToXA)( res->ts, &tmp );
         tmp = *here;
         VG_(addToXA)( res->ts, &tmp );
         i++;
         break;
      } 
      else if (me == here->thr) {
         tmp = *here;
         tmp.tym++;
         VG_(addToXA)( res->ts, &tmp );
         i++;
         break;
      }
      else /* me > here->thr */ {
         tmp = *here;
         VG_(addToXA)( res->ts, &tmp );
      }
   }
   tl_assert(i >= 0 && i <= n);
   if (i == n && here && here->thr < me) {
      tmp.thr = me;
      tmp.tym = 1;
      VG_(addToXA)( res->ts, &tmp );
   } else {
      for (/*keepgoing*/; i < n; i++) {
         here = VG_(indexXA)( vts->ts, i );
         tmp = *here;
         VG_(addToXA)( res->ts, &tmp );
      }
   }
   tl_assert(is_sane_VTS(res));
   //if (0) VG_(printf)("tick vts thrno %ld szou %d\n",
   //                   (Word)me->errmsg_index, (Int)VG_(sizeXA)(res) );
   return res;
}


/* Return a new VTS constructed as the join (max) of the 2 args.
   Neither arg is modified.
*/
VTS* VTS__join ( VTS* a, VTS* b )
{
   Word     ia, ib, useda, usedb;
   ULong    tyma, tymb, tymMax;
   Thr*     thr;
   VTS*     res;
   ScalarTS *tmpa, *tmpb;

   tl_assert(a && a->ts);
   tl_assert(b && b->ts);
   useda = VG_(sizeXA)( a->ts );
   usedb = VG_(sizeXA)( b->ts );

   res = VTS__new();
   ia = ib = 0;

   while (1) {

      /* This logic is to enumerate triples (thr, tyma, tymb) drawn
         from a and b in order, where thr is the next Thr*
         occurring in either a or b, and tyma/b are the relevant
         scalar timestamps, taking into account implicit zeroes. */
      tl_assert(ia >= 0 && ia <= useda);
      tl_assert(ib >= 0 && ib <= usedb);
      tmpa = tmpb = NULL;

      if (ia == useda && ib == usedb) {
         /* both empty - done */
         break;
      }
      else
      if (ia == useda && ib != usedb) {
         /* a empty, use up b */
         tmpb = VG_(indexXA)( b->ts, ib );
         thr  = tmpb->thr;
         tyma = 0;
         tymb = tmpb->tym;
         ib++;
      }
      else
      if (ia != useda && ib == usedb) {
         /* b empty, use up a */
         tmpa = VG_(indexXA)( a->ts, ia );
         thr  = tmpa->thr;
         tyma = tmpa->tym;
         tymb = 0;
         ia++;
      }
      else {
         /* both not empty; extract lowest-Thr*'d triple */
         tmpa = VG_(indexXA)( a->ts, ia );
         tmpb = VG_(indexXA)( b->ts, ib );
         if (tmpa->thr < tmpb->thr) {
            /* a has the lowest unconsidered Thr* */
            thr  = tmpa->thr;
            tyma = tmpa->tym;
            tymb = 0;
            ia++;
         }
         else
         if (tmpa->thr > tmpb->thr) {
            /* b has the lowest unconsidered Thr* */
            thr  = tmpb->thr;
            tyma = 0;
            tymb = tmpb->tym;
            ib++;
         } else {
            /* they both next mention the same Thr* */
            tl_assert(tmpa->thr == tmpb->thr);
            thr  = tmpa->thr; /* == tmpb->thr */
            tyma = tmpa->tym;
            tymb = tmpb->tym;
            ia++;
            ib++;
         }
      }

      /* having laboriously determined (thr, tyma, tymb), do something
         useful with it. */
      tymMax = tyma > tymb ? tyma : tymb;
      if (tymMax > 0) {
         ScalarTS st;
         st.thr = thr;
         st.tym = tymMax;
         VG_(addToXA)( res->ts, &st );
      }

   }

   tl_assert(is_sane_VTS( res ));

   return res;
}


/* Compute the partial ordering relation of the two args.
*/
POrd VTS__cmp ( VTS* a, VTS* b )
{
   Word     ia, ib, useda, usedb;
   ULong    tyma, tymb;
   Thr*     thr;
   ScalarTS *tmpa, *tmpb;

   Bool all_leq = True;
   Bool all_geq = True;

   tl_assert(a && a->ts);
   tl_assert(b && b->ts);
   useda = VG_(sizeXA)( a->ts );
   usedb = VG_(sizeXA)( b->ts );

   ia = ib = 0;

   while (1) {

      /* This logic is to enumerate triples (thr, tyma, tymb) drawn
         from a and b in order, where thr is the next Thr*
         occurring in either a or b, and tyma/b are the relevant
         scalar timestamps, taking into account implicit zeroes. */
      tl_assert(ia >= 0 && ia <= useda);
      tl_assert(ib >= 0 && ib <= usedb);
      tmpa = tmpb = NULL;

      if (ia == useda && ib == usedb) {
         /* both empty - done */
         break;
      }
      else
      if (ia == useda && ib != usedb) {
         /* a empty, use up b */
         tmpb = VG_(indexXA)( b->ts, ib );
         thr  = tmpb->thr;
         tyma = 0;
         tymb = tmpb->tym;
         ib++;
      }
      else
      if (ia != useda && ib == usedb) {
         /* b empty, use up a */
         tmpa = VG_(indexXA)( a->ts, ia );
         thr  = tmpa->thr;
         tyma = tmpa->tym;
         tymb = 0;
         ia++;
      }
      else {
         /* both not empty; extract lowest-Thr*'d triple */
         tmpa = VG_(indexXA)( a->ts, ia );
         tmpb = VG_(indexXA)( b->ts, ib );
         if (tmpa->thr < tmpb->thr) {
            /* a has the lowest unconsidered Thr* */
            thr  = tmpa->thr;
            tyma = tmpa->tym;
            tymb = 0;
            ia++;
         }
         else
         if (tmpa->thr > tmpb->thr) {
            /* b has the lowest unconsidered Thr* */
            thr  = tmpb->thr;
            tyma = 0;
            tymb = tmpb->tym;
            ib++;
         } else {
            /* they both next mention the same Thr* */
            tl_assert(tmpa->thr == tmpb->thr);
            thr  = tmpa->thr; /* == tmpb->thr */
            tyma = tmpa->tym;
            tymb = tmpb->tym;
            ia++;
            ib++;
         }
      }

      /* having laboriously determined (thr, tyma, tymb), do something
         useful with it. */
      if (tyma < tymb)
         all_geq = False;
      if (tyma > tymb)
         all_leq = False;
   }

   if (all_leq && all_geq)
      return POrd_EQ;
   /* now we know they aren't equal, so either all_leq or all_geq or
      both are false. */
   if (all_leq)
      return POrd_LT;
   if (all_geq)
      return POrd_GT;
   /* hmm, neither all_geq or all_leq.  This means unordered. */
   return POrd_UN;
}


/* Compute an arbitrary structural (total) ordering on the two args,
   based on their VCs, so they can be looked up in a table, tree, etc.
   Returns -1, 0 or 1.  (really just 'deriving Ord' :-)
*/
Word VTS__cmp_structural ( VTS* a, VTS* b )
{
   /* We just need to generate an arbitrary total ordering based on
      a->ts and b->ts.  Preferably do it in a way which comes across likely
      differences relatively quickly. */
   Word     i, useda, usedb;
   ScalarTS *tmpa, *tmpb;

   tl_assert(a && a->ts);
   tl_assert(b && b->ts);
   useda = VG_(sizeXA)( a->ts );
   usedb = VG_(sizeXA)( b->ts );

   if (useda < usedb) return -1;
   if (useda > usedb) return 1;

   /* Same length vectors, so let's step through them together. */
   tl_assert(useda == usedb);
   for (i = 0; i < useda; i++) {
      tmpa = VG_(indexXA)( a->ts, i );
      tmpb = VG_(indexXA)( b->ts, i );
      if (tmpa->tym < tmpb->tym) return -1;
      if (tmpa->tym > tmpb->tym) return 1;
      if (tmpa->thr < tmpb->thr) return -1;
      if (tmpa->thr > tmpb->thr) return 1;
   }

   /* They're identical. */
   return 0;
}


/* Debugging only.  Display the given VTS in the buffer.
*/
void VTS__show ( HChar* buf, Int nBuf, VTS* vts ) {
   ScalarTS* st;
   HChar     unit[64];
   Word      i, n;
   Int       avail = nBuf;
   tl_assert(vts && vts->ts);
   tl_assert(nBuf > 16);
   buf[0] = '[';
   buf[1] = 0;
   n = VG_(sizeXA)( vts->ts );
   for (i = 0; i < n; i++) {
      tl_assert(avail >= 40);
      st = VG_(indexXA)( vts->ts, i );
      VG_(memset)(unit, 0, sizeof(unit));
      VG_(sprintf)(unit, i < n-1 ? "%p:%lld " : "%p:%lld",
                         st->thr, st->tym);
      if (avail < VG_(strlen)(unit) + 40/*let's say*/) {
         VG_(strcat)(buf, " ...]");
         buf[nBuf-1] = 0;
         return;
      }
      VG_(strcat)(buf, unit);
      avail -= VG_(strlen)(unit);
   }
   VG_(strcat)(buf, "]");
   buf[nBuf-1] = 0;
}


/* Debugging only.  Return vts[index], so to speak.
*/
ULong VTS__indexAt_SLOW ( VTS* vts, Thr* idx ) {
   UWord i, n;
   tl_assert(vts && vts->ts);
   n = VG_(sizeXA)( vts->ts );
   for (i = 0; i < n; i++) {
      ScalarTS* st = VG_(indexXA)( vts->ts, i );
      if (st->thr == idx)
         return st->tym;
   }
   return 0;
}


/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
//                                                             //
// SECTION END vts primitives                                  //
//                                                             //
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////



/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
//                                                             //
// SECTION BEGIN main library                                  //
//                                                             //
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////
//                                                     //
// VTS set                                             //
//                                                     //
/////////////////////////////////////////////////////////

static WordFM* /* VTS* void void */ vts_set = NULL;

static void vts_set_init ( void )
{
   tl_assert(!vts_set);
   vts_set = HG_(newFM)( main_zalloc, "libhb.vts_set_init.1",
                         main_dealloc,
                         (Word(*)(UWord,UWord))VTS__cmp_structural );
   tl_assert(vts_set);
}

/* Given a newly made VTS, look in vts_set to see if we already have
   an identical one.  If yes, free up this one and return instead a
   pointer to the existing one.  If no, add this one to the set and
   return the same pointer.  Caller differentiates the two cases by
   comparing returned pointer with the supplied one (although that
   does require that the supplied VTS is not already in the set).
*/
static VTS* vts_set__find_and_dealloc__or_add ( VTS* cand )
{
   UWord keyW, valW, walW;
   /* lookup cand (by value) */
   if (HG_(lookupFM)( vts_set, &keyW, &valW, &walW, (UWord)cand )) {
      /* found it */
      tl_assert(valW == 0);
      tl_assert(walW == 0);
      /* if this fails, cand (by ref) was already present (!) */
      tl_assert(keyW != (UWord)cand);
      VTS__delete(cand);
      return (VTS*)keyW;
   } else {
      /* not present.  Add and return pointer to same. */
      HG_(addToFM)( vts_set,
                    (UWord)cand, 0/*val is unused*/, 0/*wal is unused*/ );
      return cand;
   }
}


/////////////////////////////////////////////////////////
//                                                     //
// VTS table                                           //
//                                                     //
/////////////////////////////////////////////////////////

static void VtsID__invalidate_caches ( void ); /* fwds */

/* A type to hold VTS table entries.  Invariants:
   If .vts == NULL, then this entry is not in use, so:
   - .rc == 0
   - this entry is on the freelist (unfortunately, does not imply
     any constraints on value for .nextfree)
   If .vts != NULL, then this entry is in use:
   - .vts is findable in vts_set
   - .vts->id == this entry number
   - no specific value for .rc (even 0 is OK)
   - this entry is not on freelist, so .nextfree == VtsID_INVALID
*/
typedef
   struct {
      VTS*  vts;      /* vts, in vts_set */
      UWord rc;       /* reference count - enough for entire aspace */
      VtsID freelink; /* chain for free entries, VtsID_INVALID at end */
   }
   VtsTE;

/* The VTS table. */
static XArray* /* of VtsTE */ vts_tab = NULL;

/* An index into the VTS table, indicating the start of the list of
   free (available for use) entries.  If the list is empty, this is
   VtsID_INVALID. */
static VtsID vts_tab_freelist = VtsID_INVALID;

/* Do a GC of vts_tab when the freelist becomes empty AND the size of
   vts_tab equals or exceeds this size.  After GC, the value here is
   set appropriately so as to check for the next GC point. */
static Word vts_next_GC_at = 1000;

static void vts_tab_init ( void )
{
   vts_tab
      = VG_(newXA)( main_zalloc, "libhb.vts_tab_init.1",
                    main_dealloc, sizeof(VtsTE) );
   vts_tab_freelist
      = VtsID_INVALID;
   tl_assert(vts_tab);
}

/* Add ii to the free list, checking that it looks out-of-use. */
static void add_to_free_list ( VtsID ii )
{
   VtsTE* ie = VG_(indexXA)( vts_tab, ii );
   tl_assert(ie->vts == NULL);
   tl_assert(ie->rc == 0);
   tl_assert(ie->freelink == VtsID_INVALID);
   ie->freelink = vts_tab_freelist;
   vts_tab_freelist = ii;
}

/* Get an entry from the free list.  This will return VtsID_INVALID if
   the free list is empty. */
static VtsID get_from_free_list ( void )
{
   VtsID  ii;
   VtsTE* ie;
   if (vts_tab_freelist == VtsID_INVALID)
      return VtsID_INVALID;
   ii = vts_tab_freelist;
   ie = VG_(indexXA)( vts_tab, ii );
   tl_assert(ie->vts == NULL);
   tl_assert(ie->rc == 0);
   vts_tab_freelist = ie->freelink;
   return ii;
}

/* Produce a new VtsID that can be used, either by getting it from
   the freelist, or, if that is empty, by expanding vts_tab. */
static VtsID get_new_VtsID ( void )
{
   VtsID ii;
   VtsTE te;
   ii = get_from_free_list();
   if (ii != VtsID_INVALID)
      return ii;
   te.vts = NULL;
   te.rc = 0;
   te.freelink = VtsID_INVALID;
   ii = (VtsID)VG_(addToXA)( vts_tab, &te );
   return ii;
}


/* Indirect callback from lib_zsm. */
static void VtsID__rcinc ( VtsID ii )
{
   VtsTE* ie;
   /* VG_(indexXA) does a range check for us */
   ie = VG_(indexXA)( vts_tab, ii );
   tl_assert(ie->vts); /* else it's not in use */
   tl_assert(ie->rc < ~0UL); /* else we can't continue */
   tl_assert(ie->vts->id == ii);
   ie->rc++;
}

/* Indirect callback from lib_zsm. */
static void VtsID__rcdec ( VtsID ii )
{
   VtsTE* ie;
   /* VG_(indexXA) does a range check for us */
   ie = VG_(indexXA)( vts_tab, ii );
   tl_assert(ie->vts); /* else it's not in use */
   tl_assert(ie->rc > 0); /* else RC snafu */
   tl_assert(ie->vts->id == ii);
   ie->rc--;
}


/* Look up 'cand' in our collection of VTSs.  If present, deallocate
   it and return the VtsID for the pre-existing version.  If not
   present, add it to both vts_tab and vts_set, allocate a fresh VtsID
   for it, and return that. */
static VtsID vts_tab__find_and_dealloc__or_add ( VTS* cand )
{
   VTS* auld;
   tl_assert(cand->id == VtsID_INVALID);
   auld = vts_set__find_and_dealloc__or_add(cand);
   if (auld != cand) {
      /* We already have an Aulde one.  Use that. */
      VtsTE* ie;
      tl_assert(auld->id != VtsID_INVALID);
      ie = VG_(indexXA)( vts_tab, auld->id );
      tl_assert(ie->vts == auld);
      return auld->id;
   } else {
      VtsID  ii = get_new_VtsID();
      VtsTE* ie = VG_(indexXA)( vts_tab, ii );
      ie->vts = cand;
      ie->rc = 0;
      ie->freelink = VtsID_INVALID;
      cand->id = ii;
      return ii;
   }
}


static void show_vts_stats ( HChar* caller )
{
   UWord nSet, nTab, nLive;
   ULong totrc;
   UWord n, i;
   nSet = HG_(sizeFM)( vts_set );
   nTab = VG_(sizeXA)( vts_tab );
   totrc = 0;
   nLive = 0;
   n = VG_(sizeXA)( vts_tab );
   for (i = 0; i < n; i++) {
      VtsTE* ie = VG_(indexXA)( vts_tab, i );
      if (ie->vts) {
         nLive++;
         totrc += (ULong)ie->rc;
      } else {
         tl_assert(ie->rc == 0);
      }
   }
   VG_(printf)("  show_vts_stats %s\n", caller);
   VG_(printf)("    vts_tab size %4lu\n", nTab);
   VG_(printf)("    vts_tab live %4lu\n", nLive);
   VG_(printf)("    vts_set size %4lu\n", nSet);
   VG_(printf)("        total rc %4llu\n", totrc);
}

/* NOT TO BE CALLED FROM WITHIN libzsm. */
static void vts_tab__do_GC ( Bool show_stats )
{
   UWord i, nTab, nLive, nFreed;

   /* check this is actually necessary. */
   tl_assert(vts_tab_freelist == VtsID_INVALID);

   /* empty the caches for partial order checks and binary joins.  We
      could do better and prune out the entries to be deleted, but it
      ain't worth the hassle. */
   VtsID__invalidate_caches();

   /* First, make the reference counts up to date. */
   zsm_flush_cache();

   nTab = VG_(sizeXA)( vts_tab );

   if (show_stats) {
      VG_(printf)("<<GC begins at vts_tab size %lu>>\n", nTab);
      show_vts_stats("before GC");
   }

   /* Now we can inspect the entire vts_tab.  Any entries
      with zero .rc fields are now no longer in use and can be
      free list, removed from vts_set, and deleted. */
   nFreed = 0;
   for (i = 0; i < nTab; i++) {
      Bool present;
      UWord oldK = 0, oldV = 0, oldW = 0;
      VtsTE* te = VG_(indexXA)( vts_tab, i );
      if (te->vts == NULL) {
         tl_assert(te->rc == 0);
         continue; /* already on the free list (presumably) */
      }
      if (te->rc > 0)
         continue; /* in use */
      /* Ok, we got one we can free. */
      tl_assert(te->vts->id == i);
      /* first, remove it from vts_set. */
      present = HG_(delFromFM)( vts_set,
                                &oldK, &oldV, &oldW, (UWord)te->vts );
      tl_assert(present); /* else it isn't in vts_set ?! */
      tl_assert(oldV == 0); /* no info stored in vts_set val fields */
      tl_assert(oldW == 0); /* no info stored in vts_set wal fields */
      tl_assert(oldK == (UWord)te->vts); /* else what did delFromFM find?! */
      /* now free the VTS itself */
      VTS__delete(te->vts);
      te->vts = NULL;
      /* and finally put this entry on the free list */
      tl_assert(te->freelink == VtsID_INVALID); /* can't already be on it */
      add_to_free_list( i );
      nFreed++;
   }

   /* Now figure out when the next GC should be.  We'll allow the
      number of VTSs to double before GCing again.  Except of course
      that since we can't (or, at least, don't) shrink vts_tab, we
      can't set the threshhold value smaller than it. */
   tl_assert(nFreed <= nTab);
   nLive = nTab - nFreed;
   tl_assert(nLive >= 0 && nLive <= nTab);
   vts_next_GC_at = 2 * nLive;
   if (vts_next_GC_at < nTab)
      vts_next_GC_at = nTab;

   if (show_stats) {
      show_vts_stats("after GC");
      VG_(printf)("<<GC ends, next gc at %ld>>\n", vts_next_GC_at);
   }

   if (1) {
      static UInt ctr = 0;
      tl_assert(nTab > 0);
      VG_(printf)("libhb: GC %u:  size %lu  live %lu  (%2llu%%)\n",
                  ctr++, nTab, nLive, (100ULL * nLive) / nTab);
   }
}


/////////////////////////////////////////////////////////
//                                                     //
// Vts IDs                                             //
//                                                     //
/////////////////////////////////////////////////////////

//////////////////////////
static ULong stats__getOrdering_queries = 0;
static ULong stats__getOrdering_misses  = 0;
static ULong stats__join2_queries       = 0;
static ULong stats__join2_misses        = 0;

static inline UInt ROL32 ( UInt w, Int n ) {
   w = (w << n) | (w >> (32-n));
   return w;
}
static inline UInt hash_VtsIDs ( VtsID vi1, VtsID vi2, UInt nTab ) {
   UInt hash = ROL32(vi1,19) ^ ROL32(vi2,13);
   return hash % nTab;
}

#define N_GETORDERING_CACHE 1023
static
   struct { VtsID vi1; VtsID vi2; POrd ord; }
   getOrdering_cache[N_GETORDERING_CACHE];

#define N_JOIN2_CACHE 1023
static
   struct { VtsID vi1; VtsID vi2; VtsID res; }
   join2_cache[N_JOIN2_CACHE];

static void VtsID__invalidate_caches ( void ) {
   Int i;
   for (i = 0; i < N_GETORDERING_CACHE; i++) {
      getOrdering_cache[i].vi1 = VtsID_INVALID;
      getOrdering_cache[i].vi2 = VtsID_INVALID;
      getOrdering_cache[i].ord = 0; /* an invalid POrd value */
   }
   for (i = 0; i < N_JOIN2_CACHE; i++) {
     join2_cache[i].vi1 = VtsID_INVALID;
     join2_cache[i].vi2 = VtsID_INVALID;
     join2_cache[i].res = VtsID_INVALID;
   }
}
//////////////////////////

static Bool VtsID__is_valid ( VtsID vi ) {
   VtsTE* ve;
   if (vi >= (VtsID)VG_(sizeXA)( vts_tab ))
      return False;
   ve = VG_(indexXA)( vts_tab, vi );
   if (!ve->vts)
      return False;
   tl_assert(ve->vts->id == vi);
   return True;
}

static VTS* VtsID__to_VTS ( VtsID vi ) {
   VtsTE* te = VG_(indexXA)( vts_tab, vi );
   tl_assert(te->vts);
   return te->vts;
}

static void VtsID__pp ( VtsID vi ) {
   HChar buf[100];
   VTS* vts = VtsID__to_VTS(vi);
   VTS__show( buf, sizeof(buf)-1, vts );
   buf[sizeof(buf)-1] = 0;
   VG_(printf)("%s", buf);
}

/* compute partial ordering relation of vi1 and vi2. */
__attribute__((noinline))
static POrd VtsID__getOrdering_WRK ( VtsID vi1, VtsID vi2 ) {
   UInt hash;
   POrd ord;
   VTS  *v1, *v2;
   //if (vi1 == vi2) return POrd_EQ;
   tl_assert(vi1 != vi2);
   ////++
   stats__getOrdering_queries++;
   hash = hash_VtsIDs(vi1, vi2, N_GETORDERING_CACHE);
   if (getOrdering_cache[hash].vi1 == vi1
       && getOrdering_cache[hash].vi2 == vi2)
      return getOrdering_cache[hash].ord;
   stats__getOrdering_misses++;
   ////--
   v1  = VtsID__to_VTS(vi1);
   v2  = VtsID__to_VTS(vi2);
   ord = VTS__cmp( v1, v2 );
   ////++
   getOrdering_cache[hash].vi1 = vi1;
   getOrdering_cache[hash].vi2 = vi2;
   getOrdering_cache[hash].ord = ord;
   ////--
   return ord;
}
static inline POrd VtsID__getOrdering ( VtsID vi1, VtsID vi2 ) {
   return vi1 == vi2  ? POrd_EQ  : VtsID__getOrdering_WRK(vi1, vi2);
}

/* compute binary join */
__attribute__((noinline))
static VtsID VtsID__join2_WRK ( VtsID vi1, VtsID vi2 ) {
   UInt  hash;
   VtsID res;
   VTS   *vts1, *vts2, *nyu;
   //if (vi1 == vi2) return vi1;
   tl_assert(vi1 != vi2);
   ////++
   stats__join2_queries++;
   hash = hash_VtsIDs(vi1, vi2, N_JOIN2_CACHE);
   if (join2_cache[hash].vi1 == vi1
       && join2_cache[hash].vi2 == vi2)
      return join2_cache[hash].res;
   stats__join2_misses++;
   ////--
   vts1 = VtsID__to_VTS(vi1);
   vts2 = VtsID__to_VTS(vi2);
   nyu  = VTS__join(vts1,vts2);
   res  = vts_tab__find_and_dealloc__or_add(nyu);
   ////++
   join2_cache[hash].vi1 = vi1;
   join2_cache[hash].vi2 = vi2;
   join2_cache[hash].res = res;
   ////--
   return res;
}
static inline VtsID VtsID__join2 ( VtsID vi1, VtsID vi2 ) {
   return vi1 == vi2  ? vi1  : VtsID__join2_WRK(vi1, vi2);
}

/* create a singleton VTS, namely [thr:1] */
static VtsID VtsID__mk_Singleton ( Thr* thr, ULong tym ) {
   VTS* nyu = VTS__singleton(thr,tym);
   return vts_tab__find_and_dealloc__or_add(nyu);
}

/* tick operation, creates value 1 if specified index is absent */
static VtsID VtsID__tick ( VtsID vi, Thr* idx ) {
   VTS* vts = VtsID__to_VTS(vi);
   VTS* nyu = VTS__tick(idx,vts);
   return vts_tab__find_and_dealloc__or_add(nyu);
}

/* index into a VTS (only for assertions) */
static ULong VtsID__indexAt ( VtsID vi, Thr* idx ) {
   VTS* vts = VtsID__to_VTS(vi);
   return VTS__indexAt_SLOW( vts, idx );
}


/////////////////////////////////////////////////////////
//                                                     //
// Threads                                             //
//                                                     //
/////////////////////////////////////////////////////////

struct _Thr {
   /* Current VTSs for this thread.  They change as we go along.  viR
      is the VTS to be used for reads, viW for writes.  Usually they
      are the same, but can differ when we deal with reader-writer
      locks.  It is always the case that VtsID__getOrdering(viW,viR)
      == POrd_LT or POrdEQ -- that is, viW must be the same, or
      lagging behind, viR. */
   VtsID viR;
   VtsID viW;
   /* opaque (to us) data we hold on behalf of the library's user. */
   void* opaque;
};

static Thr* Thr__new ( void ) {
   Thr* thr = main_zalloc( "libhb.Thr__new.1", sizeof(Thr) );
   thr->viR = VtsID_INVALID;
   thr->viW = VtsID_INVALID;
   return thr;
}


/////////////////////////////////////////////////////////
//                                                     //
// Shadow Values                                       //
//                                                     //
/////////////////////////////////////////////////////////

// type SVal, SVal_INVALID and SVal_NOACCESS are defined by
// hb_zsm.h.  We have to do everything else here.

/* SVal is 64 bit unsigned int.

      <---------30--------->    <---------30--------->
   00 X-----Rmin-VtsID-----X 00 X-----Wmin-VtsID-----X   C(Rmin,Wmin)
   01 X--------------------X XX X--------------------X   E(rror)
   10 X--------------------X XX X--------------------X   A: SVal_NOACCESS
   11 X--------------------X XX X--------------------X   I: SVal_INVALID
*/
#define SVAL_TAGMASK (3ULL << 62)

static inline Bool SVal__isC ( SVal s ) {
   return (0ULL << 62) == (s & SVAL_TAGMASK);
}
static inline SVal SVal__mkC ( VtsID rmini, VtsID wmini ) {
   //tl_assert(VtsID__is_valid(rmini));
   //tl_assert(VtsID__is_valid(wmini));
   return (((ULong)rmini) << 32) | ((ULong)wmini);
}
static inline VtsID SVal__unC_Rmin ( SVal s ) {
   tl_assert(SVal__isC(s));
   return (VtsID)(s >> 32);
}
static inline VtsID SVal__unC_Wmin ( SVal s ) {
   tl_assert(SVal__isC(s));
   return (VtsID)(s & 0xFFFFFFFFULL);
}

static Bool SVal__isE ( SVal s ) {
   return (1ULL << 62) == (s & SVAL_TAGMASK);
}
static SVal SVal__mkE ( void ) {
   return 1ULL << 62;
}

static Bool SVal__isA ( SVal s ) {
   return (2ULL << 62) == (s & SVAL_TAGMASK);
}
static SVal SVal__mkA ( void ) {
   return 2ULL << 62;
}

/* Direct callback from lib_zsm. */
static void SVal__rcinc ( SVal s ) {
   if (SVal__isC(s)) {
      VtsID__rcinc( SVal__unC_Rmin(s) );
      VtsID__rcinc( SVal__unC_Wmin(s) );
   }
}

/* Direct callback from lib_zsm. */
static void SVal__rcdec ( SVal s ) {
   if (SVal__isC(s)) {
      VtsID__rcdec( SVal__unC_Rmin(s) );
      VtsID__rcdec( SVal__unC_Wmin(s) );
   }
}


/////////////////////////////////////////////////////////
//                                                     //
// Change-event map2                                   //
//                                                     //
/////////////////////////////////////////////////////////

#define EVENT_MAP_GC_AT                (1 * 1000 * 1000)
#define EVENT_MAP_GC_DISCARD_FRACTION  0.5

/* This is in two parts:

   1. An OSet of RCECs.  This is a set of reference-counted stack
      traces.  When the reference count of a stack trace becomes zero,
      it is removed from the set and freed up.  The intent is to have
      a set of stack traces which can be referred to from (2), but to
      only represent each one once.  The set is indexed/searched by
      ordering on the stack trace vectors.

   2. An OSet of OldRefs.  These store information about each old ref
      that we need to record.  It is indexed by address (of the
      location for which the information is recorded), and contains a
      pointer to a RCEC in (1).  Each OldRef also contains a
      generation number, indicating when it was most recently
      accessed.

      When we this set becomes too big, we can throw away the subset
      of this set whose generation numbers are below some threshold;
      hence doing approximate LRU discarding.  For each discarded
      OldRef we must of course decrement the reference count on the
      ECEC it refers to, in order that entries from (1) eventually get
      discarded too.
*/

///////////////////////////////////////////////////////
//// Part (1): An OSet of RCECs
///

#define N_FRAMES 8

// (UInt) `echo "Reference Counted Execution Context" | md5sum`
#define RCEC_MAGIC 0xab88abb2UL

typedef
   struct {
      UWord magic;
      UWord rc;
      UWord rcX; /* used for crosschecking */
      UWord frames[1 + N_FRAMES]; /* first word is hash of all the rest */
   }
   RCEC;

static OSet* contextTree = NULL; /* OSet* of RCEC */


/* Gives an arbitrary total order on RCEC .frames fields */
static Word RCEC__cmp_by_frames ( RCEC* ec1, RCEC* ec2 ) {
   Word i;
   tl_assert(ec1 && ec1->magic == RCEC_MAGIC);
   tl_assert(ec2 && ec2->magic == RCEC_MAGIC);
   if (ec1->frames[0] < ec2->frames[0]) return -1;
   if (ec1->frames[0] > ec2->frames[0]) return 1;
   for (i = 1; i < 1 + N_FRAMES; i++) {
      if (ec1->frames[i] < ec2->frames[i]) return -1;
      if (ec1->frames[i] > ec2->frames[i]) return 1;
   }
   return 0;
}


/* Dec the ref of this EC_RC, and if it becomes zero,
   delete it from the contextTree. */
static void ctxt__rcdec ( RCEC* ec )
{
   tl_assert(ec && ec->magic == RCEC_MAGIC);
   tl_assert(ec->rc > 0);
   ec->rc--;
   if (ec->rc == 0) {
      void* nd = VG_(OSetGen_Remove)( contextTree, ec );
      tl_assert(nd); /* must be in the tree */
      tl_assert(nd == ec);
      tl_assert( ((RCEC*)nd)->magic == RCEC_MAGIC );
      VG_(OSetGen_FreeNode)( contextTree, nd );
   }
}

static void ctxt__rcinc ( RCEC* ec )
{
   tl_assert(ec && ec->magic == RCEC_MAGIC);
   ec->rc++;
}

/* Find the given RCEC in the tree, and return a pointer to it.  Or,
   if not present, add the given one to the tree (by making a copy of
   it, so the caller can immediately deallocate the original) and
   return a pointer to the copy.  The caller can safely have 'example'
   on its stack, since we will always return a pointer to a copy of
   it, not to the original.  Note that the inserted node will have .rc
   of zero and so the caller must immediatly increment it. */
static RCEC* ctxt__find_or_add ( RCEC* example )
{
   RCEC* copy;
   tl_assert(example && example->magic == RCEC_MAGIC);
   tl_assert(example->rc == 0);
   copy = VG_(OSetGen_Lookup)( contextTree, example );
   if (copy) {
      tl_assert(copy != example);
   } else {
      copy = VG_(OSetGen_AllocNode)( contextTree, sizeof(RCEC) );
      tl_assert(copy != example);
      *copy = *example;
      VG_(OSetGen_Insert)( contextTree, copy );
   }
   return copy;
}

static inline UWord ROLW ( UWord w, Int n )
{
   Int bpw = 8 * sizeof(UWord);
   w = (w << n) | (w >> (bpw-n));
   return w;
}

static RCEC* get_RCEC ( Thr* thr )
{
   UWord hash, i;
   RCEC  example;
   example.magic = RCEC_MAGIC;
   example.rc = 0;
   example.rcX = 0;
   main_get_stacktrace( thr, &example.frames[1], N_FRAMES );
   hash = 0;
   for (i = 1; i < 1 + N_FRAMES; i++) {
      hash ^= example.frames[i];
      hash = ROLW(hash, 19);
   }
   example.frames[0] = hash;
   return ctxt__find_or_add( &example );
}

///////////////////////////////////////////////////////
//// Part (2): An OSet of OldRefs, that refer to (1)
///

// (UInt) `echo "Old Reference Information" | md5sum`
#define OldRef_MAGIC 0x30b1f075UL

typedef  struct { Thr* thr; RCEC* rcec; }  Thr_n_RCEC;

#define N_OLDREF_ACCS 3

typedef
   struct {
      UWord magic;
      UWord gen;    /* when most recently accessed */
      Addr  ea;
      /* unused slots in this array have .thr == NULL */
      Thr_n_RCEC accs[N_OLDREF_ACCS];
   }
   OldRef;

static Word OldRef__cmp_by_EA ( OldRef* r1, OldRef* r2 ) {
   tl_assert(r1 && r1->magic == OldRef_MAGIC);
   tl_assert(r2 && r2->magic == OldRef_MAGIC);
   if (r1->ea < r2->ea) return -1;
   if (r1->ea > r2->ea) return 1;
   return 0;
}

static OSet* oldrefTree     = NULL; /* OSet* of OldRef */
static UWord oldrefGen      = 0;    /* current LRU generation # */
static UWord oldrefTreeN    = 0;    /* # elems in oldrefTree */
static UWord oldrefGenIncAt = 0;    /* inc gen # when size hits this */

static void event_map_bind ( Addr a, struct EC_* ecxx, Thr* thr )
{
   OldRef key, *ref;
   RCEC*  here;
   Word   i, j;

   key.ea    = a;
   key.magic = OldRef_MAGIC;

   ref = VG_(OSetGen_Lookup)( oldrefTree, &key );

   if (ref) {

      /* We already have a record for this address.  We now need to
         see if we have a stack trace pertaining to this thread's
         access. */
      tl_assert(ref->magic == OldRef_MAGIC);

      tl_assert(thr);
      for (i = 0; i < N_OLDREF_ACCS; i++) {
         if (ref->accs[i].thr == thr)
            break;
      }

      if (i < N_OLDREF_ACCS) {
         /* thread 'thr' has an entry at index 'i'.  Update it. */
         if (i > 0) {
            Thr_n_RCEC tmp = ref->accs[i-1];
            ref->accs[i-1] = ref->accs[i];
            ref->accs[i] = tmp;
            i--;
         }
         here = get_RCEC( thr );
         ctxt__rcinc( here );
         ctxt__rcdec( ref->accs[i].rcec );
         ref->accs[i].rcec = here;
         tl_assert(ref->accs[i].thr == thr);
      } else {
         here = get_RCEC( thr );
         ctxt__rcinc( here );
         /* No entry for this thread.  Shuffle all of them down one
            slot, and put the new entry at the start of the array. */
         if (ref->accs[N_OLDREF_ACCS-1].thr) {
            /* the last slot is in use.  We must dec the rc on the
               associated rcec. */
            tl_assert(ref->accs[N_OLDREF_ACCS-1].rcec);
            ctxt__rcdec(ref->accs[N_OLDREF_ACCS-1].rcec);
         } else {
            tl_assert(!ref->accs[N_OLDREF_ACCS-1].rcec);
         }
         for (j = N_OLDREF_ACCS-1; j >= 1; j--)
            ref->accs[j] = ref->accs[j-1];
         ref->accs[0].thr = thr;
         ref->accs[0].rcec = here;
         tl_assert(thr); /* thr==NULL is used to signify an empty slot,
                            so we can't add a NULL thr. */
      }

      ref->gen = oldrefGen;
      tl_assert(ref->ea == a);

   } else {

      /* We don't have a record for this address.  Create a new one. */
      if (oldrefTreeN >= oldrefGenIncAt) {
         oldrefGen++;
         oldrefGenIncAt = oldrefTreeN + 50000;
         VG_(printf)("oldrefTree: new gen %lu at size %lu\n",
                     oldrefGen, oldrefTreeN );
      }
      here = get_RCEC( thr );
      ctxt__rcinc(here);
      ref = VG_(OSetGen_AllocNode)( oldrefTree, sizeof(OldRef) );
      ref->magic = OldRef_MAGIC;
      ref->gen = oldrefGen;
      ref->ea = a;
      ref->accs[0].rcec = here;
      ref->accs[0].thr = thr;
      tl_assert(thr); /* thr==NULL is used to signify an empty slot,
                         so we can't add a NULL thr. */
      for (j = 1; j < N_OLDREF_ACCS; j++) {
         ref->accs[j].thr = NULL;
         ref->accs[j].rcec = NULL;
      }
      VG_(OSetGen_Insert)( oldrefTree, ref );
      oldrefTreeN++;

   }
}


static
Bool event_map_lookup ( /*OUT*/struct EC_** resEC,
                        /*OUT*/Thr** resThr,
                        Thr* thr_acc, Addr a )
{
  Word   i;
  OldRef key, *ref;

  tl_assert(thr_acc);

  key.ea = a;
  key.magic = OldRef_MAGIC;

   ref = VG_(OSetGen_Lookup)( oldrefTree, &key );
   if (ref) {
      tl_assert(ref->magic == OldRef_MAGIC);
      tl_assert(ref->accs[0].thr); /* first slot must always be used */

      for (i = 0; i < N_OLDREF_ACCS; i++) {
         if (ref->accs[i].thr != NULL
             && ref->accs[i].thr != thr_acc)
            break;
      }
      /* If we didn't find an entry for some thread other than
         thr_acc, just return the entry for thread 0.  It'll look
         pretty stupid to the user though. */
      if (i == N_OLDREF_ACCS)
         i = 0;

      tl_assert(i >= 0 && i < N_OLDREF_ACCS);
      tl_assert(ref->accs[i].thr);
      tl_assert(ref->accs[i].rcec);
      tl_assert(ref->accs[i].rcec->magic == RCEC_MAGIC);

      *resEC  = main_stacktrace_to_EC(&ref->accs[i].rcec->frames[1], N_FRAMES);
      *resThr = ref->accs[i].thr;
      return True;
   } else {
      return False;
   }
}

static void event_map_init ( void )
{
   tl_assert(!contextTree);
   contextTree = VG_(OSetGen_Create)(
                    0, 
                    (Word(*)(const void *, const void*))RCEC__cmp_by_frames, 
                    main_zalloc, "libhb.event_map_init.1 (context tree)",
                    main_dealloc
                 );
   tl_assert(contextTree);

   tl_assert(!oldrefTree);
   oldrefTree = VG_(OSetGen_Create)(
                   0, 
                   (Word(*)(const void *, const void*))OldRef__cmp_by_EA,
                   main_zalloc, "libhb.event_map_init.2 (oldref tree)", 
                   main_dealloc
                );
   tl_assert(oldrefTree);

   oldrefGen = 0;
   oldrefGenIncAt = 0;
   oldrefTreeN = 0;
}

static void event_map__check_reference_counts ( void )
{
   RCEC*   rcec;
   OldRef* oldref;
   Word    i;

   /* Set the 'check' reference counts to zero */
   VG_(OSetGen_ResetIter)( contextTree );
   while ( (rcec = VG_(OSetGen_Next)( contextTree )) ) {
      tl_assert(rcec->magic == RCEC_MAGIC);
      tl_assert(rcec->rc > 0); /* unrefd nodes should be immediately rm'd */
      rcec->rcX = 0;
   }

   /* visit all the referencing points, inc check ref counts */
   VG_(OSetGen_ResetIter)( oldrefTree );
   while ( (oldref = VG_(OSetGen_Next)( oldrefTree )) ) {
      tl_assert(oldref->magic == OldRef_MAGIC);
      for (i = 0; i < N_OLDREF_ACCS; i++) {
         if (oldref->accs[i].thr) {
            tl_assert(oldref->accs[i].rcec);
            tl_assert(oldref->accs[i].rcec->magic == RCEC_MAGIC);
            oldref->accs[i].rcec->rcX++;
         } else {
            tl_assert(!oldref->accs[i].rcec);
         }
      }
   }

   /* compare check ref counts with actual */
   VG_(OSetGen_ResetIter)( contextTree );
   while ( (rcec = VG_(OSetGen_Next)( contextTree )) ) {
      tl_assert(rcec->rc == rcec->rcX);
   }
}

static void event_map_maybe_GC ( void )
{
   OldRef* oldref;
   UWord   keyW, valW, retained, maxGen;
   WordFM* genMap;
   XArray* refs2del;
   Word    i, j, n2del;

   if (LIKELY(oldrefTreeN < EVENT_MAP_GC_AT))
      return;
   VG_(printf)("libhb: event_map GC at size %lu\n", oldrefTreeN);

   /* Check our counting is sane */
   tl_assert(oldrefTreeN == (UWord) VG_(OSetGen_Size)( oldrefTree ));

   /* Check the reference counts */
   event_map__check_reference_counts();

   /* Compute the distribution of generation values in the ref tree */
   /* genMap :: generation-number -> count-of-nodes-with-that-number */
   genMap = HG_(newFM)( main_zalloc, "libhb.emmG.1",
                                      main_dealloc, NULL );

   VG_(OSetGen_ResetIter)( oldrefTree );
   while ( (oldref = VG_(OSetGen_Next)( oldrefTree )) ) {
      UWord key = oldref->gen;
      keyW = valW = 0;
      if (HG_(lookupFM)(genMap, &keyW, &valW, NULL, key )) {
         tl_assert(keyW == key);
         tl_assert(valW > 0);
      }
      /* now valW is the old count for generation 'key' */
      HG_(addToFM)(genMap, key, valW+1, 0);
   }

   tl_assert(HG_(sizeFM)(genMap) > 0);

   retained = oldrefTreeN;
   maxGen = 0;
   HG_(initIterFM)( genMap );
   while (HG_(nextIterFM)( genMap, &keyW, &valW, NULL )) {
      tl_assert(keyW > 0); /* can't allow a generation # 0 */
      VG_(printf)("  XXX: gen %lu has %lu\n", keyW, valW );
      tl_assert(keyW >= maxGen);
      tl_assert(retained >= valW);
      if (retained - valW
          > (UWord)(EVENT_MAP_GC_AT * EVENT_MAP_GC_DISCARD_FRACTION)) {
         retained -= valW;
         maxGen = keyW;
      } else {
         break;
      }
   }
   HG_(doneIterFM)( genMap );

   VG_(printf)(
      "  XXX: delete generations %lu and below, retaining %lu entries\n",
      maxGen, retained );

   HG_(deleteFM)( genMap, NULL, NULL, NULL );

   /* If this fails, it means there's only one generation in the
      entire tree.  So we're kind of in a bad situation, and need to
      do some stop-gap measure, such as randomly deleting half the
      entries. */
   tl_assert(retained < oldrefTreeN);

   /* Now make up a big list of the oldrefTree entries we want to
      delete.  We can't simultaneously traverse the tree and delete
      stuff from it, so first we need to copy them off somewhere
      else. (sigh) */
   refs2del = VG_(newXA)( main_zalloc, "libhb.emmG.1",
                          main_dealloc, sizeof(OldRef*) );

   VG_(OSetGen_ResetIter)( oldrefTree );
   while ( (oldref = VG_(OSetGen_Next)( oldrefTree )) ) {
      tl_assert(oldref->magic == OldRef_MAGIC);
      if (oldref->gen <= maxGen) {
         VG_(addToXA)( refs2del, &oldref );
      }
   }

   n2del = VG_(sizeXA)( refs2del );
   tl_assert(n2del == (Word)(oldrefTreeN - retained));

   VG_(printf)("%s","deleting entries\n");
   for (i = 0; i < n2del; i++) {
      void* nd;
      OldRef* ref = *(OldRef**)VG_(indexXA)( refs2del, i );
      tl_assert(ref);
      tl_assert(ref->magic == OldRef_MAGIC);
      for (j = 0; j < N_OLDREF_ACCS; j++) {
         if (ref->accs[j].rcec) {
            tl_assert(ref->accs[j].thr);
            ctxt__rcdec( ref->accs[j].rcec );
         } else {
            tl_assert(!ref->accs[j].thr);
         }
      }
      nd = VG_(OSetGen_Remove)( oldrefTree, ref );
      VG_(OSetGen_FreeNode)( oldrefTree, nd );
   }

   VG_(deleteXA)( refs2del );

   tl_assert( VG_(OSetGen_Size)( oldrefTree ) == retained );

   oldrefTreeN = retained;
   oldrefGenIncAt = oldrefTreeN; /* start new gen right away */

   /* Check the reference counts */
   event_map__check_reference_counts();

   VG_(printf)("XXXX final sizes: oldrefTree %ld, contextTree %ld\n\n",
               VG_(OSetGen_Size)(oldrefTree), VG_(OSetGen_Size)(contextTree));

}


/////////////////////////////////////////////////////////
//                                                     //
// Core MSM                                            //
//                                                     //
/////////////////////////////////////////////////////////

#define MSM_CONFACC 1

#define MSM_RACE2ERR 1

#define MSM_CHECK 0

static ULong stats__msm_read         = 0;
static ULong stats__msm_read_change  = 0;
static ULong stats__msm_write        = 0;
static ULong stats__msm_write_change = 0;

typedef 
   struct {
      /* IN - RO */
      Thr* acc_thr; /* thread making this access */
      Addr ea;      /* address of access */
      /* OUT */
      Bool race; /* caller sets this to False beforehand */
      struct EC_* where; /* only filled in if .race == True */
      struct EC_* wherep;
      Thr* thrp;
   }
   MSMInfo;

static void record_race_info ( /*MOD*/MSMInfo* info, SVal svOld, SVal svNew )
{
   struct EC_* wherep = NULL;
   Thr*        thrp   = NULL;
   Bool found;

   info->where = main_get_EC( info->acc_thr );

   found = event_map_lookup( &wherep, &thrp, info->acc_thr, info->ea );
   if (found) {
     tl_assert(wherep);
     tl_assert(thrp);
     info->wherep = wherep;
     info->thrp   = thrp;
   } else {
     tl_assert(!wherep);
     tl_assert(!thrp);
     info->wherep = NULL;
     info->thrp   = NULL;
   }
}

static Bool is_sane_SVal_C ( SVal sv ) {
   POrd ord;
   if (!SVal__isC(sv)) return True;
   ord = VtsID__getOrdering( SVal__unC_Rmin(sv), SVal__unC_Wmin(sv) );
   if (ord == POrd_EQ || ord == POrd_LT) return True;
   return False;
}

/* Direct callback from lib_zsm. */
/* Compute new state following a read */
static SVal msm_read ( SVal svOld, /*MOD*/MSMInfo* info )
{
   SVal svNew = SVal_INVALID;
   stats__msm_read++;

   /* Redundant sanity check on the constraints */
   if (MSM_CHECK) {
      tl_assert(is_sane_SVal_C(svOld));
   }

   if (SVal__isC(svOld)) {
      POrd  ord;
      VtsID tviR  = info->acc_thr->viR;
      VtsID tviW  = info->acc_thr->viW;
      VtsID rmini = SVal__unC_Rmin(svOld);
      VtsID wmini = SVal__unC_Wmin(svOld);

      ord = VtsID__getOrdering(rmini,tviR);
      if (ord == POrd_EQ || ord == POrd_LT) {
         /* no race */
         /* Note: RWLOCK subtlety: use tviW, not tviR */
         svNew = SVal__mkC( rmini, VtsID__join2(wmini, tviW) );
         goto out;
      } else {
         svNew = MSM_RACE2ERR
                    ? SVal__mkE()
                    : SVal__mkC( rmini, VtsID__join2(wmini,tviR) );
         if (!info->race) {
            info->race = True;
            record_race_info( info, svOld, svNew );
         }
         goto out;
      }
   }
   if (SVal__isA(svOld)) {
      /* reading no-access memory (sigh); leave unchanged */
      /* check for no pollution */
      tl_assert(svOld == SVal_NOACCESS);
      svNew = SVal_NOACCESS;
      goto out;
   }
   if (SVal__isE(svOld)) {
      /* no race, location is already "in error" */
      svNew = SVal__mkE();
      goto out;
   }
   VG_(printf)("msm_read: bad svOld: 0x%016llx\n", svOld);
   tl_assert(0);

  out:
   if (MSM_CHECK) {
      tl_assert(is_sane_SVal_C(svNew));
   }
   tl_assert(svNew != SVal_INVALID);
   if (svNew != svOld) {
      if (MSM_CONFACC && SVal__isC(svOld) && SVal__isC(svNew)) {
         struct EC_* ec = NULL; //main_get_EC( info->acc_thr );
         event_map_bind( info->ea, ec, info->acc_thr );
         stats__msm_read_change++;
      }
   }
   return svNew;
}

/* Direct callback from lib_zsm. */
/* Compute new state following a write */
static SVal msm_write ( SVal svOld, /*MOD*/MSMInfo* info )
{
   SVal svNew = SVal_INVALID;
   stats__msm_write++;

   /* Redundant sanity check on the constraints */
   if (MSM_CHECK) {
      tl_assert(is_sane_SVal_C(svOld));
   }

   if (SVal__isC(svOld)) {
      POrd  ord;
      VtsID tviW  = info->acc_thr->viW;
      VtsID wmini = SVal__unC_Wmin(svOld);

      ord = VtsID__getOrdering(wmini,tviW);
      if (ord == POrd_EQ || ord == POrd_LT) {
         /* no race */
         svNew = SVal__mkC( tviW, tviW );
         goto out;
      } else {
         VtsID rmini = SVal__unC_Rmin(svOld);
         svNew = MSM_RACE2ERR
                    ? SVal__mkE()
                    : SVal__mkC( VtsID__join2(rmini,tviW),
                                 VtsID__join2(wmini,tviW) );
         if (!info->race) {
            info->race = True;
            record_race_info( info, svOld, svNew );
         }
         goto out;
      }
   }
   if (SVal__isA(svOld)) {
      /* writing no-access memory (sigh); leave unchanged */
      /* check for no pollution */
      tl_assert(svOld == SVal_NOACCESS);
      svNew = SVal_NOACCESS;
      goto out;
   }
   if (SVal__isE(svOld)) {
      /* no race, location is already "in error" */
      svNew = SVal__mkE();
      goto out;
   }
   VG_(printf)("msm_write: bad svOld: 0x%016llx\n", svOld);
   tl_assert(0);

  out:
   if (MSM_CHECK) {
      tl_assert(is_sane_SVal_C(svNew));
   }
   tl_assert(svNew != SVal_INVALID);
   if (svNew != svOld) {
      if (MSM_CONFACC && SVal__isC(svOld) && SVal__isC(svNew)) {
         struct EC_* ec = NULL; //main_get_EC( info->acc_thr );
         event_map_bind( info->ea, ec, info->acc_thr );
         stats__msm_write_change++;
      }
   }
   return svNew;
}


/////////////////////////////////////////////////////////
//                                                     //
// Synchronisation objects                             //
//                                                     //
/////////////////////////////////////////////////////////

// (UInt) `echo "Synchronisation object" | md5sum`
#define SO_MAGIC 0x56b3c5b0U

struct _SO {
   VtsID viR; /* r-clock of sender */
   VtsID viW; /* w-clock of sender */
   UInt  magic;
};

static SO* SO__Alloc ( void ) {
   SO* so = main_zalloc( "libhb.SO__Alloc.1", sizeof(SO) );
   so->viR   = VtsID_INVALID;
   so->viW   = VtsID_INVALID;
   so->magic = SO_MAGIC;
   return so;
}
static void SO__Dealloc ( SO* so ) {
   tl_assert(so);
   tl_assert(so->magic == SO_MAGIC);
   if (so->viR == VtsID_INVALID) {
      tl_assert(so->viW == VtsID_INVALID);
   } else {
      tl_assert(so->viW != VtsID_INVALID);
      VtsID__rcdec(so->viR);
      VtsID__rcdec(so->viW);
   }
   so->magic = 0;
   main_dealloc( so );
}


/////////////////////////////////////////////////////////
//                                                     //
// Top Level API                                       //
//                                                     //
/////////////////////////////////////////////////////////

static void show_thread_state ( HChar* str, Thr* t ) 
{
   if (1) return;
   if (t->viR == t->viW) {
      VG_(printf)("thr \"%s\" %p has vi* %u==", str, t, t->viR );
      VtsID__pp( t->viR );
      VG_(printf)("%s","\n");
   } else {
      VG_(printf)("thr \"%s\" %p has viR %u==", str, t, t->viR );
      VtsID__pp( t->viR );
      VG_(printf)(" viW %u==", t->viW);
      VtsID__pp( t->viW );
      VG_(printf)("%s","\n");
   }
}


Thr* libhb_init (
        void*       (*zalloc)( HChar*, SizeT ),
        void        (*dealloc)( void* ),
        void*       (*shadow_alloc)( SizeT ),
        void        (*get_stacktrace)( Thr*, Addr*, UWord ),
        struct EC_* (*stacktrace_to_EC)( Addr*, UWord ),
        struct EC_* (*get_EC)( Thr* )
     )
{
   Thr*  thr;
   VtsID vi;
   tl_assert(zalloc);
   tl_assert(dealloc);
   tl_assert(shadow_alloc);
   tl_assert(get_stacktrace);
   tl_assert(stacktrace_to_EC);
   tl_assert(get_EC);
   main_zalloc           = zalloc;
   main_dealloc          = dealloc;
   main_shadow_alloc     = shadow_alloc;
   main_get_stacktrace   = get_stacktrace;
   main_stacktrace_to_EC = stacktrace_to_EC;
   main_get_EC           = get_EC;

   // No need to initialise hg_wordfm.
   // No need to initialise hg_wordset.

   vts_set_init();
   vts_tab_init();
   event_map_init();
   VtsID__invalidate_caches();

   // initialise shadow memory
   zsm_init( SVal__rcinc, SVal__rcdec );

   thr = Thr__new();
   vi  = VtsID__mk_Singleton( thr, 1 );
   thr->viR = vi;
   thr->viW = vi;
   VtsID__rcinc(thr->viR);
   VtsID__rcinc(thr->viW);

   show_thread_state("  root", thr);
   return thr;
}

Thr* libhb_create ( Thr* parent )
{
   /* The child's VTSs are copies of the parent's VTSs, but ticked at
      the child's index.  Since the child's index is guaranteed
      unique, it has never been seen before, so the implicit value
      before the tick is zero and after that is one. */
   Thr* child = Thr__new();

   child->viR = VtsID__tick( parent->viR, child );
   child->viW = VtsID__tick( parent->viW, child );
   VtsID__rcinc(child->viR);
   VtsID__rcinc(child->viW);

   tl_assert(VtsID__indexAt( child->viR, child ) == 1);
   tl_assert(VtsID__indexAt( child->viW, child ) == 1);

   /* and the parent has to move along too */
   VtsID__rcdec(parent->viR);
   VtsID__rcdec(parent->viW);
   parent->viR = VtsID__tick( parent->viR, parent );
   parent->viW = VtsID__tick( parent->viW, parent );
   VtsID__rcinc(parent->viR);
   VtsID__rcinc(parent->viW);

   show_thread_state(" child", child);
   show_thread_state("parent", parent);

   return child;
}

/* Shut down the library, and print stats (in fact that's _all_
   this is for. */
void libhb_shutdown ( Bool show_stats )
{
   if (show_stats) {
      VG_(printf)("%s","<<< BEGIN libhb stats >>>\n");
      VG_(printf)(" secmaps: %'10lu allocd (%'12lu g-a-range)\n",
                  stats__secmaps_allocd,
                  stats__secmap_ga_space_covered);
      VG_(printf)("  linesZ: %'10lu allocd (%'12lu bytes occupied)\n",
                  stats__secmap_linesZ_allocd,
                  stats__secmap_linesZ_bytes);
      VG_(printf)("  linesF: %'10lu allocd (%'12lu bytes occupied)\n",
                  stats__secmap_linesF_allocd,
                  stats__secmap_linesF_bytes);
      VG_(printf)(" secmaps: %'10lu iterator steppings\n",
                  stats__secmap_iterator_steppings);
      VG_(printf)(" secmaps: %'10lu searches (%'12lu slow)\n",
                  stats__secmaps_search, stats__secmaps_search_slow);

      VG_(printf)("%s","\n");
      VG_(printf)("   cache: %'lu totrefs (%'lu misses)\n",
                  stats__cache_totrefs, stats__cache_totmisses );
      VG_(printf)("   cache: %'14lu Z-fetch,    %'14lu F-fetch\n",
                  stats__cache_Z_fetches, stats__cache_F_fetches );
      VG_(printf)("   cache: %'14lu Z-wback,    %'14lu F-wback\n",
                  stats__cache_Z_wbacks, stats__cache_F_wbacks );
      VG_(printf)("   cache: %'14lu invals,     %'14lu flushes\n",
                  stats__cache_invals, stats__cache_flushes );
      VG_(printf)("   cache: %'14llu arange_New  %'14llu direct-to-Zreps\n",
                  stats__cache_make_New_arange,
                  stats__cache_make_New_inZrep);

      VG_(printf)("%s","\n");
      VG_(printf)("   cline: %'10lu normalises\n",
                  stats__cline_normalises );
      VG_(printf)("   cline:  rds 8/4/2/1: %'13lu %'13lu %'13lu %'13lu\n",
                  stats__cline_read64s,
                  stats__cline_read32s,
                  stats__cline_read16s,
                  stats__cline_read8s );
      VG_(printf)("   cline:  wrs 8/4/2/1: %'13lu %'13lu %'13lu %'13lu\n",
                  stats__cline_write64s,
                  stats__cline_write32s,
                  stats__cline_write16s,
                  stats__cline_write8s );
      VG_(printf)("   cline: sets 8/4/2/1: %'13lu %'13lu %'13lu %'13lu\n",
                  stats__cline_set64s,
                  stats__cline_set32s,
                  stats__cline_set16s,
                  stats__cline_set8s );
      VG_(printf)("   cline: get1s %'lu, copy1s %'lu\n",
                  stats__cline_get8s, stats__cline_copy8s );
      VG_(printf)("   cline:    splits: 8to4 %'12lu    4to2 %'12lu    2to1 %'12lu\n",
                 stats__cline_64to32splits,
                 stats__cline_32to16splits,
                 stats__cline_16to8splits );
      VG_(printf)("   cline: pulldowns: 8to4 %'12lu    4to2 %'12lu    2to1 %'12lu\n",
                 stats__cline_64to32pulldown,
                 stats__cline_32to16pulldown,
                 stats__cline_16to8pulldown );
      if (0)
      VG_(printf)("   cline: sizeof(CacheLineZ) %ld, covers %ld bytes of arange\n",
                  (Word)sizeof(LineZ), (Word)N_LINE_ARANGE);

      VG_(printf)("%s","\n");

      VG_(printf)("   libhb: %'13llu msm_read  (%'llu changed)\n",
                  stats__msm_read, stats__msm_read_change);
      VG_(printf)("   libhb: %'13llu msm_write (%'llu changed)\n",
                  stats__msm_write, stats__msm_write_change);
      VG_(printf)("   libhb: %'13llu getOrd queries (%'llu misses)\n",
                  stats__getOrdering_queries, stats__getOrdering_misses);
      VG_(printf)("   libhb: %'13llu join2  queries (%'llu misses)\n",
                  stats__join2_queries, stats__join2_misses);

      VG_(printf)("%s","\n");
      VG_(printf)(
         "   libhb: %ld entries in vts_table (approximately %lu bytes)\n",
         VG_(sizeXA)( vts_tab ), VG_(sizeXA)( vts_tab ) * sizeof(VtsTE)
      );
      VG_(printf)( "   libhb: %lu entries in vts_set\n",
                   HG_(sizeFM)( vts_set ) );
      //VG_(printf)( "   libhb: %lu entries in event_map\n", 
      //             HG_(sizeFM)( event_map ) );

#if 0
      VG_(printf)("sizeof(AvlNode)     = %lu\n", sizeof(AvlNode));
      VG_(printf)("sizeof(WordBag)     = %lu\n", sizeof(WordBag));
      VG_(printf)("sizeof(MaybeWord)   = %lu\n", sizeof(MaybeWord));
      VG_(printf)("sizeof(CacheLine)   = %lu\n", sizeof(CacheLine));
      VG_(printf)("sizeof(LineZ)       = %lu\n", sizeof(LineZ));
      VG_(printf)("sizeof(LineF)       = %lu\n", sizeof(LineF));
      VG_(printf)("sizeof(SecMap)      = %lu\n", sizeof(SecMap));
      VG_(printf)("sizeof(Cache)       = %lu\n", sizeof(Cache));
      VG_(printf)("sizeof(SMCacheEnt)  = %lu\n", sizeof(SMCacheEnt));
      VG_(printf)("sizeof(CountedSVal) = %lu\n", sizeof(CountedSVal));
      VG_(printf)("sizeof(VTS)         = %lu\n", sizeof(VTS));
      VG_(printf)("sizeof(ScalarTS)    = %lu\n", sizeof(ScalarTS));
      VG_(printf)("sizeof(VtsTE)       = %lu\n", sizeof(VtsTE));
      VG_(printf)("sizeof(MSMInfo)     = %lu\n", sizeof(MSMInfo));

      VG_(printf)("sizeof(struct _XArray)     = %lu\n", sizeof(struct _XArray));
      VG_(printf)("sizeof(struct _WordFM)     = %lu\n", sizeof(struct _WordFM));
      VG_(printf)("sizeof(struct _Thr)     = %lu\n", sizeof(struct _Thr));
      VG_(printf)("sizeof(struct _SO)     = %lu\n", sizeof(struct _SO));
#endif

      VG_(printf)("%s","<<< END libhb stats >>>\n");
      VG_(printf)("%s","\n");

   }
}

void libhb_async_exit ( Thr* thr )
{
   /* is there anything we need to do? */
}

/* Both Segs and SOs point to VTSs.  However, there is no sharing, so
   a Seg that points at a VTS is its one-and-only owner, and ditto for
   a SO that points at a VTS. */

SO* libhb_so_alloc ( void )
{
   return SO__Alloc();
}

void libhb_so_dealloc ( SO* so )
{
   tl_assert(so);
   tl_assert(so->magic == SO_MAGIC);
   SO__Dealloc(so);
}

/* See comments in libhb.h for details on the meaning of 
   strong vs weak sends and strong vs weak receives. */
void libhb_so_send ( Thr* thr, SO* so, Bool strong_send )
{
   /* Copy the VTSs from 'thr' into the sync object, and then move
      the thread along one step. */

   tl_assert(so);
   tl_assert(so->magic == SO_MAGIC);

   /* stay sane .. a thread's read-clock must always lead or be the
      same as its write-clock */
   { POrd ord = VtsID__getOrdering(thr->viW, thr->viR);
     tl_assert(ord == POrd_EQ || ord == POrd_LT);
   }

   /* since we're overwriting the VtsIDs in the SO, we need to drop
      any references made by the previous contents thereof */
   if (so->viR == VtsID_INVALID) {
      tl_assert(so->viW == VtsID_INVALID);
      so->viR = thr->viR;
      so->viW = thr->viW;
      VtsID__rcinc(so->viR);
      VtsID__rcinc(so->viW);
   } else {
      /* In a strong send, we dump any previous VC in the SO and
         install the sending thread's VC instead.  For a weak send we
         must join2 with what's already there. */
      tl_assert(so->viW != VtsID_INVALID);
      VtsID__rcdec(so->viR);
      VtsID__rcdec(so->viW);
      so->viR = strong_send ? thr->viR : VtsID__join2( so->viR, thr->viR );
      so->viW = strong_send ? thr->viW : VtsID__join2( so->viW, thr->viW );
      VtsID__rcinc(so->viR);
      VtsID__rcinc(so->viW);
   }

   /* move both parent clocks along */
   VtsID__rcdec(thr->viR);
   VtsID__rcdec(thr->viW);
   thr->viR = VtsID__tick( thr->viR, thr );
   thr->viW = VtsID__tick( thr->viW, thr );
   VtsID__rcinc(thr->viR);
   VtsID__rcinc(thr->viW);
   if (strong_send)
      show_thread_state("s-send", thr);
   else
      show_thread_state("w-send", thr);
}

void libhb_so_recv ( Thr* thr, SO* so, Bool strong_recv )
{
   tl_assert(so);
   tl_assert(so->magic == SO_MAGIC);

   if (so->viR != VtsID_INVALID) {
      tl_assert(so->viW != VtsID_INVALID);

      /* Weak receive (basically, an R-acquisition of a R-W lock).
         This advances the read-clock of the receiver, but not the
         write-clock. */
      VtsID__rcdec(thr->viR);
      thr->viR = VtsID__join2( thr->viR, so->viR );
      VtsID__rcinc(thr->viR);

      /* For a strong receive, we also advance the receiver's write
         clock, which means the receive as a whole is essentially
         equivalent to a W-acquisition of a R-W lock. */
      if (strong_recv) {
         VtsID__rcdec(thr->viW);
         thr->viW = VtsID__join2( thr->viW, so->viW );
         VtsID__rcinc(thr->viW);
      }

      if (strong_recv) 
         show_thread_state("s-recv", thr);
      else 
         show_thread_state("w-recv", thr);

   } else {
      tl_assert(so->viW == VtsID_INVALID);
      /* Deal with degenerate case: 'so' has no vts, so there has been
         no message posted to it.  Just ignore this case. */
      show_thread_state("d-recv", thr);
   }
}

Bool libhb_so_everSent ( SO* so )
{
   if (so->viR == VtsID_INVALID) {
      tl_assert(so->viW == VtsID_INVALID);
      return False;
   } else {
      tl_assert(so->viW != VtsID_INVALID);
      return True;
   }
}

#define XXX1 0 // 0x67a106c
#define XXX2 0

static Bool TRACEME(Addr a, SizeT szB) {
   if (XXX1 && a <= XXX1 && XXX1 <= a+szB) return True;
   if (XXX2 && a <= XXX2 && XXX2 <= a+szB) return True;
   return False;
}
static void trace ( Thr* thr, Addr a, SizeT szB, HChar* s ) {
  SVal sv = zsm_read8(a);
  VG_(printf)("thr %p (%#lx,%lu) %s: 0x%016llx ", thr,a,szB,s,sv);
  show_thread_state("", thr);
  VG_(printf)("%s","\n");
}

Bool libhb_read ( /*OUT*/RaceInfo* ri, Thr* thr, Addr a, SizeT szB )
{
   MSMInfo info;
   void* opaque = (void*)&info;
   if(TRACEME(a,szB))trace(thr,a,szB,"rd-before");
   info.acc_thr = thr;
   info.ea      = a;
   info.race    = False;
   switch (szB) {
      case 8:
         zsm_apply64( a, (SVal(*)(SVal,void*))msm_read, opaque );
         break;
      case 4:
         zsm_apply32( a, (SVal(*)(SVal,void*))msm_read, opaque );
         break;
      case 2:
         zsm_apply16( a, (SVal(*)(SVal,void*))msm_read, opaque );
         break;
      case 1:
         zsm_apply8 ( a, (SVal(*)(SVal,void*))msm_read, opaque );
         break;
      default:
         zsm_apply_range( a, szB, (SVal(*)(SVal,void*))msm_read, opaque );
         break;
   }
   if(TRACEME(a,szB))trace(thr,a,szB,"rd-after ");
   if (!info.race) return False;
   ri->thr    = thr;
   ri->where  = info.where;
   ri->a      = a;
   ri->szB    = szB;
   ri->isW    = False;
   ri->thrp   = info.thrp;
   ri->wherep = info.wherep;
   return True;
}

Bool libhb_write ( /*OUT*/RaceInfo* ri, Thr* thr, Addr a, SizeT szB )
{
   MSMInfo info;
   void* opaque = (void*)&info;
   if(TRACEME(a,szB))trace(thr,a,szB,"wr-before");
   info.acc_thr = thr;
   info.ea      = a;
   info.race    = False;
   switch (szB) {
      case 8:
         zsm_apply64( a, (SVal(*)(SVal,void*))msm_write, opaque );
         break;
      case 4:
         zsm_apply32( a, (SVal(*)(SVal,void*))msm_write, opaque );
         break;
      case 2:
         zsm_apply16( a, (SVal(*)(SVal,void*))msm_write, opaque );
         break;
      case 1:
         zsm_apply8 ( a, (SVal(*)(SVal,void*))msm_write, opaque );
         break;
      default:
         zsm_apply_range( a, szB, (SVal(*)(SVal,void*))msm_write, opaque );
         break;
   }
   if(TRACEME(a,szB))trace(thr,a,szB,"wr-after ");
   if (!info.race) return False;
   ri->thr    = thr;
   ri->where  = info.where;
   ri->a      = a;
   ri->szB    = szB;
   ri->isW    = True;
   ri->thrp   = info.thrp;
   ri->wherep = info.wherep;
   return True;
}

void libhb_range_new ( Thr* thr, Addr a, SizeT szB )
{
   SVal sv = SVal__mkC(thr->viW, thr->viW);
   tl_assert(is_sane_SVal_C(sv));
   if(TRACEME(a,szB))trace(thr,a,szB,"nw-before");
   zsm_set_range( a, szB, sv );
   if(TRACEME(a,szB))trace(thr,a,szB,"nw-after ");
}

void libhb_range_noaccess ( Thr* thr, Addr a, SizeT szB )
{
   if(TRACEME(a,szB))trace(thr,a,szB,"NA-before");
   zsm_set_range( a, szB, SVal__mkA() );
   if(TRACEME(a,szB))trace(thr,a,szB,"NA-after ");
}

void* libhb_get_Thr_opaque ( Thr* thr ) {
   tl_assert(thr);
   return thr->opaque;
}

void libhb_set_Thr_opaque ( Thr* thr, void* v ) {
   tl_assert(thr);
   thr->opaque = v;
}

void libhb_copy_shadow_state ( Addr dst, Addr src, SizeT len )
{
   zsm_copy_range(dst, src, len);
}

void libhb_maybe_GC ( void )
{
   event_map_maybe_GC();
   /* If there are still freelist entries available, no need for a
      GC. */
   if (vts_tab_freelist != VtsID_INVALID)
      return;
   /* So all the table entries are full, and we're having to expand
      the table.  But did we hit the threshhold point yet? */
   if (VG_(sizeXA)( vts_tab ) < vts_next_GC_at)
      return;
   vts_tab__do_GC( False/*don't show stats*/ );
}


/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
//                                                             //
// SECTION END main library                                    //
//                                                             //
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
//                                                             //
// END libhb_core.c (core library).                            //
//                                                             //
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
