
/*--------------------------------------------------------------------*/
/*--- An AVL tree based finite map for word keys and word values.  ---*/
/*--- Inspired by Haskell's "FiniteMap" library.                   ---*/
/*---                                                  tc_wordfm.c ---*/
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

#include "pub_tool_basics.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcbase.h"

#define TC_(str) VGAPPEND(vgThrcheck_,str)
#include "tc_wordfm.h"

//------------------------------------------------------------------//
//---                           WordFM                           ---//
//---                       Implementation                       ---//
//------------------------------------------------------------------//

/* One element of the AVL tree */
typedef
   struct _AvlNode {
      Word key;
      Word val;
      struct _AvlNode* child[2]; /* [0] is left subtree, [1] is right */
      Char balance;
   }
   AvlNode;

typedef 
   struct {
      Word w;
      Bool b;
   }
   MaybeWord;

#define WFM_STKMAX    32    // At most 2**32 entries can be iterated over

struct _WordFM {
   AvlNode* root;
   void*    (*alloc_nofail)( SizeT );
   void     (*dealloc)(void*);
   Word     (*kCmp)(Word,Word);
   AvlNode* nodeStack[WFM_STKMAX]; // Iterator node stack
   Int      numStack[WFM_STKMAX];  // Iterator num stack
   Int      stackTop;              // Iterator stack pointer, one past end
}; 

/* forward */
static Bool avl_removeroot_wrk(AvlNode** t, Word(*kCmp)(Word,Word));

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
static Word size_avl_nonNull ( AvlNode* nd )
{
   return 1 + (nd->child[0] ? size_avl_nonNull(nd->child[0]) : 0)
            + (nd->child[1] ? size_avl_nonNull(nd->child[1]) : 0);
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
                      Word              (*kCmp)(Word,Word) )
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
                 : /*unboxed*/ ((Word)(*rootp)->key) - ((Word)a->key);

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
                      Word(*kCmp)(Word,Word) )
{
   Bool ch;
   Word cmpres;
   cmpres = kCmp ? /*boxed*/   kCmp( (*rootp)->key, a->key )
                 : /*unboxed*/ ((Word)(*rootp)->key) - ((Word)a->key);

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
                          Word(*kCmp)(Word,Word) )
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
AvlNode* avl_find_node ( AvlNode* t, Word k, Word(*kCmp)(Word,Word) )
{
   if (kCmp) {
      /* Boxed comparisons */
      Word cmpres;
      while (True) {
         if (t == NULL) return NULL;
         cmpres = kCmp(t->key, k);
         if (cmpres > 0) t = t->child[0];  else
         if (cmpres < 0) t = t->child[1]; else
         return t;
      }
   } else {
      /* Unboxed comparisons */
      Word  cmpres; /* signed */
      UWord cmpresU; /* unsigned */
      while (True) {
         if (t == NULL) return NULL; /* unlikely ==> predictable */
         cmpres = ((Word)t->key) - ((Word)k);
         if (cmpres == 0) return t; /* unlikely ==> predictable */
         cmpresU = (UWord)cmpres;
         cmpresU >>=/*unsigned*/ (8 * sizeof(cmpres) - 1);
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
                    Word(*dopyK)(Word), 
                    Word(*dopyV)(Word),
                    void*(alloc_nofail)(SizeT) )
{
   AvlNode* nyu;
   if (! nd)
      return NULL;
   nyu = alloc_nofail(sizeof(AvlNode));
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

   /* Copy subtrees */
   if (nyu->child[0]) {
      nyu->child[0] = avl_dopy( nyu->child[0], dopyK, dopyV, alloc_nofail );
      if (! nyu->child[0])
         return NULL;
   }
   if (nyu->child[1]) {
      nyu->child[1] = avl_dopy( nyu->child[1], dopyK, dopyV, alloc_nofail );
      if (! nyu->child[1])
         return NULL;
   }

   return nyu;
}

/* --- Public interface functions --- */

/* Initialise a WordFM. */
void TC_(initFM) ( WordFM* fm,
                   void*   (*alloc_nofail)( SizeT ),
                   void    (*dealloc)(void*),
                   Word    (*kCmp)(Word,Word) )
{
   fm->root         = 0;
   fm->kCmp         = kCmp;
   fm->alloc_nofail = alloc_nofail;
   fm->dealloc      = dealloc;
   fm->stackTop     = 0;
}

/* Allocate and Initialise a WordFM. */
WordFM* TC_(newFM) ( void* (*alloc_nofail)( SizeT ),
                     void  (*dealloc)(void*),
                     Word  (*kCmp)(Word,Word) )
{
   WordFM* fm = alloc_nofail(sizeof(WordFM));
   tl_assert(fm);
   TC_(initFM)(fm, alloc_nofail, dealloc, kCmp);
   return fm;
}

static void avl_free ( AvlNode* nd, 
                       void(*kFin)(Word),
                       void(*vFin)(Word),
                       void(*dealloc)(void*) )
{
   if (!nd)
      return;
   if (nd->child[0])
      avl_free(nd->child[0], kFin, vFin, dealloc);
   if (nd->child[1])
      avl_free(nd->child[1], kFin, vFin, dealloc);
   if (kFin)
      kFin( nd->key );
   if (vFin)
      vFin( nd->val );
   VG_(memset)(nd, 0, sizeof(AvlNode));
   dealloc(nd);
}

/* Free up the FM.  If kFin is non-NULL, it is applied to keys
   before the FM is deleted; ditto with vFin for vals. */
void TC_(deleteFM) ( WordFM* fm, void(*kFin)(Word), void(*vFin)(Word) )
{
   void(*dealloc)(void*) = fm->dealloc;
   avl_free( fm->root, kFin, vFin, dealloc );
   VG_(memset)(fm, 0, sizeof(WordFM) );
   dealloc(fm);
}

/* Add (k,v) to fm. */
void TC_(addToFM) ( WordFM* fm, Word k, Word v )
{
   MaybeWord oldV;
   AvlNode* node;
   node = fm->alloc_nofail( sizeof(struct _AvlNode) );
   node->key = k;
   node->val = v;
   oldV.b = False;
   oldV.w = 0;
   avl_insert_wrk( &fm->root, &oldV, node, fm->kCmp );
   //if (oldV.b && fm->vFin)
   //   fm->vFin( oldV.w );
   if (oldV.b)
      fm->dealloc(node);
}

// Delete key from fm, returning associated val if found
Bool TC_(delFromFM) ( WordFM* fm, /*OUT*/Word* oldV, Word key )
{
   AvlNode* node = avl_find_node( fm->root, key, fm->kCmp );
   if (node) {
      avl_remove_wrk( &fm->root, node, fm->kCmp );
      if (oldV)
         *oldV = node->val;
      fm->dealloc(node);
      return True;
   } else {
      return False;
   }
}

// Look up in fm, assigning found key & val at spec'd addresses
Bool TC_(lookupFM) ( WordFM* fm, 
                     /*OUT*/Word* keyP, /*OUT*/Word* valP, Word key )
{
   AvlNode* node = avl_find_node( fm->root, key, fm->kCmp );
   if (node) {
      if (keyP)
         *keyP = node->key;
      if (valP)
         *valP = node->val;
      return True;
   } else {
      return False;
   }
}

Word TC_(sizeFM) ( WordFM* fm )
{
   // Hmm, this is a bad way to do this
   return fm->root ? size_avl_nonNull( fm->root ) : 0;
}

// set up FM for iteration
void TC_(initIterFM) ( WordFM* fm )
{
   tl_assert(fm);
   stackClear(fm);
   if (fm->root)
      stackPush(fm, fm->root, 1);
}

// get next key/val pair.  Will tl_assert if fm has been modified
// or looked up in since initIterFM was called.
Bool TC_(nextIterFM) ( WordFM* fm, /*OUT*/Word* pKey, /*OUT*/Word* pVal )
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
      case 1: 
         stackPush(fm, n, 2);
         if (n->child[0])  stackPush(fm, n->child[0], 1);
         break;
      case 2: 
         stackPush(fm, n, 3);
         if (pKey) *pKey = n->key;
         if (pVal) *pVal = n->val;
         return True;
      case 3:
         if (n->child[1]) stackPush(fm, n->child[1], 1);
         break;
      default:
         tl_assert(0);
      }
   }

   // Stack empty, iterator is exhausted, return NULL
   return False;
}

// clear the I'm iterating flag
void TC_(doneIterFM) ( WordFM* fm )
{
}

WordFM* TC_(dopyFM) ( WordFM* fm, Word(*dopyK)(Word), Word(*dopyV)(Word) )
{
   WordFM* nyu; 

   /* can't clone the fm whilst iterating on it */
   tl_assert(fm->stackTop == 0);

   nyu = fm->alloc_nofail( sizeof(WordFM) );
   tl_assert(nyu);

   *nyu = *fm;

   fm->stackTop = 0;
   VG_(memset)(fm->nodeStack, 0, sizeof(fm->nodeStack));
   VG_(memset)(fm->numStack, 0,  sizeof(fm->numStack));

   if (nyu->root) {
      nyu->root = avl_dopy( nyu->root, dopyK, dopyV, fm->alloc_nofail );
      if (! nyu->root)
         return NULL;
   }

   return nyu;
}

//------------------------------------------------------------------//
//---                         end WordFM                         ---//
//---                       Implementation                       ---//
//------------------------------------------------------------------//

/*--------------------------------------------------------------------*/
/*--- end                                              tc_wordfm.c ---*/
/*--------------------------------------------------------------------*/
