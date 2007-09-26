
/*--------------------------------------------------------------------*/
/*--- An AVL tree based finite map for word keys and word values.  ---*/
/*--- Inspired by Haskell's "FiniteMap" library.                   ---*/
/*---                                                  tc_wordfm.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Thrcheck, a Valgrind tool for detecting errors
   in threaded programs.

   Copyright (C) 2007-2007 Julian Seward
      jseward@acm.org

   This code is based on previous work by Nicholas Nethercote
   (coregrind/m_oset.c) which is

   Copyright (C) 2005-2007 Nicholas Nethercote
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

#ifndef __TC_WORDFM_H
#define __TC_WORDFM_H

//------------------------------------------------------------------//
//---                           WordFM                           ---//
//---                      Public interface                      ---//
//------------------------------------------------------------------//

typedef  struct _WordFM  WordFM; /* opaque */

/* Allocate and initialise a WordFM */
WordFM* TC_(newFM) ( void* (*alloc_nofail)( SizeT ),
                     void  (*dealloc)(void*),
                     Word  (*kCmp)(Word,Word) );

/* Free up the FM.  If kFin is non-NULL, it is applied to keys
   before the FM is deleted; ditto with vFin for vals. */
void TC_(deleteFM) ( WordFM*, void(*kFin)(Word), void(*vFin)(Word) );

/* Add (k,v) to fm.  If a binding for k already exists, it is updated
   to map to this new v.  In that case we should really return the
   previous v so that caller can finalise it.  Oh well. */
void TC_(addToFM) ( WordFM* fm, Word k, Word v );

// Delete key from fm, returning associated val if found
Bool TC_(delFromFM) ( WordFM* fm, /*OUT*/Word* oldV, Word key );

// Look up in fm, assigning found key & val at spec'd addresses
Bool TC_(lookupFM) ( WordFM* fm, 
                     /*OUT*/Word* keyP, /*OUT*/Word* valP, Word key );

// How many elements are there in fm?
Word TC_(sizeFM) ( WordFM* fm );

// set up FM for iteration
void TC_(initIterFM) ( WordFM* fm );

// get next key/val pair.  Will assert if fm has been modified
// or looked up in since initIterFM was called.
Bool TC_(nextIterFM) ( WordFM* fm,
                       /*OUT*/Word* pKey, /*OUT*/Word* pVal );

// clear the I'm iterating flag
void TC_(doneIterFM) ( WordFM* fm );

// Deep copy a FM.  If dopyK is NULL, keys are copied verbatim.
// If non-null, dopyK is applied to each key to generate the
// version in the new copy.  In that case, if the argument to dopyK
// is non-NULL but the result is NULL, it is assumed that dopyK
// could not allocate memory, in which case the copy is abandoned
// and NULL is returned.  Ditto with dopyV for values.
WordFM* TC_(dopyFM) ( WordFM* fm,
                      Word(*dopyK)(Word), Word(*dopyV)(Word) );

//------------------------------------------------------------------//
//---                         end WordFM                         ---//
//---                      Public interface                      ---//
//------------------------------------------------------------------//

//------------------------------------------------------------------//
//---                WordBag (unboxed words only)                ---//
//---                      Public interface                      ---//
//------------------------------------------------------------------//

typedef  struct _WordBag  WordBag; /* opaque */

/* Allocate and initialise a WordBag */
WordBag* TC_(newBag) ( void* (*alloc_nofail)( SizeT ),
                       void  (*dealloc)(void*) );

/* Free up the Bag. */
void TC_(deleteBag) ( WordBag* );

/* Add a word. */
void TC_(addToBag)( WordBag*, Word );

/* Find out how many times the given word exists in the bag. */
Word TC_(elemBag) ( WordBag*, Word );

/* Delete a word from the bag. */
Bool TC_(delFromBag)( WordBag*, Word );

/* Is the bag empty? */
Bool TC_(isEmptyBag)( WordBag* );

/* Does the bag have exactly one element? */
Bool TC_(isSingletonTotalBag)( WordBag* );

/* Return an arbitrary element from the bag. */
Word TC_(anyElementOfBag)( WordBag* );

/* How many different / total elements are in the bag? */
Word TC_(sizeUniqueBag)( WordBag* ); /* fast */
Word TC_(sizeTotalBag)( WordBag* );  /* warning: slow */

/* Iterating over the elements of a bag. */
void TC_(initIterBag)( WordBag* );
Bool TC_(nextIterBag)( WordBag*, /*OUT*/Word* pVal, /*OUT*/Word* pCount );
void TC_(doneIterBag)( WordBag* );

//------------------------------------------------------------------//
//---             end WordBag (unboxed words only)               ---//
//---                      Public interface                      ---//
//------------------------------------------------------------------//

#endif /* ! __TC_WORDFM_H */

/*--------------------------------------------------------------------*/
/*--- end                                              tc_wordfm.h ---*/
/*--------------------------------------------------------------------*/
