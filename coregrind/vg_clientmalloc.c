
/*--------------------------------------------------------------------*/
/*--- An implementation of malloc/free for the client.             ---*/
/*---                                            vg_clientmalloc.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, an x86 protected-mode emulator 
   designed for debugging and profiling binaries on x86-Unixes.

   Copyright (C) 2000-2002 Julian Seward 
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

   The GNU General Public License is contained in the file LICENSE.
*/

#include "vg_include.h"


/*------------------------------------------------------------*/
/*--- Defns                                                ---*/
/*------------------------------------------------------------*/

/* #define DEBUG_CLIENTMALLOC */

static Bool vg_needs_shadow_chunks = False;

/* Holds malloc'd but not freed blocks. */
#define VG_MALLOCLIST_NO(aa) (((UInt)(aa)) % VG_N_MALLOCLISTS)
static ShadowChunk* vg_malloclist[VG_N_MALLOCLISTS];
static Bool         vg_client_malloc_init_done = False;

/* Holds blocks after freeing. */
static ShadowChunk* vg_freed_list_start   = NULL;
static ShadowChunk* vg_freed_list_end     = NULL;
static Int          vg_freed_list_volume  = 0;

/* Stats ... */
static UInt         vg_cmalloc_n_mallocs  = 0;
static UInt         vg_cmalloc_n_frees    = 0;
static UInt         vg_cmalloc_bs_mallocd = 0;

static UInt         vg_mlist_frees = 0;
static UInt         vg_mlist_tries = 0;


/*------------------------------------------------------------*/
/*--- Fns                                                  ---*/
/*------------------------------------------------------------*/

/* Allocate a suitably-sized array, copy all the malloc-d block
   shadows into it, and return both the array and the size of it.
   This is used by the memory-leak detector.
*/
ShadowChunk** VG_(get_malloc_shadows) ( /*OUT*/ UInt* n_shadows )
{
   UInt          i, scn;
   ShadowChunk** arr;
   ShadowChunk*  sc;
   *n_shadows = 0;
   for (scn = 0; scn < VG_N_MALLOCLISTS; scn++) {
      for (sc = vg_malloclist[scn]; sc != NULL; sc = sc->next) {
         (*n_shadows)++;
      }
   }
   if (*n_shadows == 0) return NULL;

   arr = VG_(malloc)( VG_AR_PRIVATE, 
                      *n_shadows * sizeof(ShadowChunk*) );

   i = 0;
   for (scn = 0; scn < VG_N_MALLOCLISTS; scn++) {
      for (sc = vg_malloclist[scn]; sc != NULL; sc = sc->next) {
         arr[i++] = sc;
      }
   }
   vg_assert(i == *n_shadows);
   return arr;
}

static void client_malloc_init ( void )
{
   UInt ml_no;
   if (vg_client_malloc_init_done) return;

   /* Basically need to record shadow chunks if anything non-ordinary is
    * required of allocations */
   vg_needs_shadow_chunks = 
      (VG_(needs).postpone_mem_reuse     || 
       VG_(needs).record_mem_exe_context ||
       VG_(track_events).copy_mem_heap   ||
       VG_(track_events).die_mem_heap);

   for (ml_no = 0; ml_no < VG_N_MALLOCLISTS; ml_no++)
      vg_malloclist[ml_no] = NULL;

   vg_client_malloc_init_done = True;
}


static __attribute__ ((unused))
       Int count_freelist ( void )
{
   ShadowChunk* sc;
   Int n = 0;
   for (sc = vg_freed_list_start; sc != NULL; sc = sc->next)
      n++;
   return n;
}

static __attribute__ ((unused))
       Int count_malloclists ( void )
{
   ShadowChunk* sc;
   UInt ml_no;
   Int  n = 0;
   for (ml_no = 0; ml_no < VG_N_MALLOCLISTS; ml_no++) 
      for (sc = vg_malloclist[ml_no]; sc != NULL; sc = sc->next)
         n++;
   return n;
}

static __attribute__ ((unused))
       void freelist_sanity ( void )
{
   ShadowChunk* sc;
   Int n = 0;
   /* VG_(printf)("freelist sanity\n"); */
   for (sc = vg_freed_list_start; sc != NULL; sc = sc->next)
      n += sc->size;
   vg_assert(n == vg_freed_list_volume);
}

/* Remove sc from malloc list # sc.  It is an unchecked error for
   sc not to be present in the list. 
*/
static void remove_from_malloclist ( UInt ml_no, ShadowChunk* sc )
{
   ShadowChunk *sc1, *sc2;
   if (sc == vg_malloclist[ml_no]) {
      vg_malloclist[ml_no] = vg_malloclist[ml_no]->next;
   } else {
      sc1 = vg_malloclist[ml_no];
      vg_assert(sc1 != NULL);
      sc2 = sc1->next;
      while (sc2 != sc) {
         vg_assert(sc2 != NULL);
         sc1 = sc2;
         sc2 = sc2->next;
      }
      vg_assert(sc1->next == sc);
      vg_assert(sc2 == sc);
      sc1->next = sc2->next;
   }
}


/* Put a shadow chunk on the freed blocks queue, possibly freeing up
   some of the oldest blocks in the queue at the same time. */

static void add_to_freed_queue ( ShadowChunk* sc )
{
   ShadowChunk* sc1;

   /* Put it at the end of the freed list */
   if (vg_freed_list_end == NULL) {
      vg_assert(vg_freed_list_start == NULL);
      vg_freed_list_end = vg_freed_list_start = sc;
      vg_freed_list_volume = sc->size;
   } else {
      vg_assert(vg_freed_list_end->next == NULL);
      vg_freed_list_end->next = sc;
      vg_freed_list_end = sc;
      vg_freed_list_volume += sc->size;
   }
   sc->next = NULL;

   /* Release enough of the oldest blocks to bring the free queue
      volume below vg_clo_freelist_vol. */

   while (vg_freed_list_volume > VG_(clo_freelist_vol)) {
      /* freelist_sanity(); */
      vg_assert(vg_freed_list_start != NULL);
      vg_assert(vg_freed_list_end != NULL);

      sc1 = vg_freed_list_start;
      vg_freed_list_volume -= sc1->size;
      /* VG_(printf)("volume now %d\n", vg_freed_list_volume); */
      vg_assert(vg_freed_list_volume >= 0);

      if (vg_freed_list_start == vg_freed_list_end) {
         vg_freed_list_start = vg_freed_list_end = NULL;
      } else {
         vg_freed_list_start = sc1->next;
      }
      sc1->next = NULL; /* just paranoia */
      VG_(free)(VG_AR_CLIENT,  (void*)(sc1->data));
      VG_(free)(VG_AR_PRIVATE, sc1);
   }
}


// SSS: not entirely satisfied with this... some of it is memcheck-specific
// but some of it is core.  Hmm.

/* Allocate a user-chunk of size bytes.  Also allocate its shadow
   block, make the shadow block point at the user block.  Put the
   shadow chunk on the appropriate list, and set all memory
   protections correctly. */

static void client_malloc_shadow ( ThreadState* tst,
                                   Addr p, UInt size, VgAllocKind kind )
{
   ShadowChunk* sc;
   UInt         ml_no;

#  ifdef DEBUG_CLIENTMALLOC
   VG_(printf)("[m %d, f %d (%d)] client_malloc_shadow ( al %d, sz %d )\n", 
               count_malloclists(), 
               count_freelist(), vg_freed_list_volume,
               align, size );
#  endif

   sc        = VG_(malloc)(VG_AR_PRIVATE, sizeof(ShadowChunk));
   sc->where = ( VG_(needs).record_mem_exe_context
               ? VG_(get_ExeContext)(tst->m_eip, tst->m_ebp, 
                                     tst->m_esp, tst->stack_highest_word)
               : NULL);
   sc->size  = size;
   sc->allockind = kind;
   sc->data  = p;
   ml_no     = VG_MALLOCLIST_NO(p);
   sc->next  = vg_malloclist[ml_no];
   vg_malloclist[ml_no] = sc;
}

static void track_new_heap_block( Addr p, UInt size, Bool is_inited )
{
   VG_TRACK( new_mem_heap, p, size, is_inited );
   VG_TRACK( ban_mem_heap, p+size, VG_AR_CLIENT_REDZONE_SZB );
   VG_TRACK( ban_mem_heap, p-VG_AR_CLIENT_REDZONE_SZB, 
                           VG_AR_CLIENT_REDZONE_SZB );
}

static void track_reused_heap_block( Addr old, Addr new, 
                                     UInt old_size, UInt new_size )
{
   /* First half is kept and copied, second half is new;  red zones as
      normal */
   VG_TRACK( copy_mem_heap, old, new, old_size );
   VG_TRACK( new_mem_heap, new+old_size, new_size-old_size, /*inited=*/False );
   VG_TRACK( ban_mem_heap, new+new_size, VG_AR_CLIENT_REDZONE_SZB );
   VG_TRACK( ban_mem_heap, new-VG_AR_CLIENT_REDZONE_SZB, 
                           VG_AR_CLIENT_REDZONE_SZB );
}


/* Allocate memory, noticing whether or not we are doing the full
   instrumentation thing. */

// SSS: factor out commonality between client_{malloc,calloc,memalign}
//      make a worker, inline it

void* VG_(client_malloc) ( ThreadState* tst, UInt size, VgAllocKind kind )
{
   void* p;

   VGP_PUSHCC(VgpCliMalloc);
   client_malloc_init();
#  ifdef DEBUG_CLIENTMALLOC
   VG_(printf)("[m %d, f %d (%d)] client_malloc ( %d, %x )\n", 
               count_malloclists(), 
               count_freelist(), vg_freed_list_volume,
               size, raw_alloc_kind );
#  endif

   vg_cmalloc_n_mallocs ++;
   vg_cmalloc_bs_mallocd += size;

   // SSS: identical to client_memalign below
   // JJJ: changed it so the --alignment option is always paid attention to;
   // previously it wasn't for --instrument=none.
   vg_assert(VG_(clo_alignment) >= 4);
   if (VG_(clo_alignment) == 4)
      p = VG_(malloc)(VG_AR_CLIENT, size);
   else
      p = VG_(malloc_aligned)(VG_AR_CLIENT, VG_(clo_alignment), size);

   if (vg_needs_shadow_chunks)
      client_malloc_shadow ( tst, (Addr)p, size, kind );

   track_new_heap_block ( (Addr)p, size, /*is_inited = */False );

   VGP_POPCC;
   return p;
}


void* VG_(client_memalign) ( ThreadState* tst, UInt align, UInt size )
{
   void* p;

   VGP_PUSHCC(VgpCliMalloc);
   client_malloc_init();
#  ifdef DEBUG_CLIENTMALLOC
   VG_(printf)("[m %d, f %d (%d)] client_memalign ( al %d, sz %d )\n", 
               count_malloclists(), 
               count_freelist(), vg_freed_list_volume,
               align, size );
#  endif

   vg_cmalloc_n_mallocs ++;
   vg_cmalloc_bs_mallocd += size;

   vg_assert(VG_(clo_alignment) >= 4);
   if (align == 4)
      p = VG_(malloc)(VG_AR_CLIENT, size);
   else
      p = VG_(malloc_aligned)(VG_AR_CLIENT, VG_(clo_alignment), size);

   if (vg_needs_shadow_chunks)
      client_malloc_shadow ( tst, (Addr)p, size, Vg_AllocMalloc );

   track_new_heap_block ( (Addr)p, size, /*is_inited = */False );

   VGP_POPCC;
   return p;
}


void* VG_(client_calloc) ( ThreadState* tst, UInt nmemb, UInt size1 )
{
   void*        p;
   UInt         size, i;

   VGP_PUSHCC(VgpCliMalloc);
   client_malloc_init();

#  ifdef DEBUG_CLIENTMALLOC
   VG_(printf)("[m %d, f %d (%d)] client_calloc ( %d, %d )\n", 
               count_malloclists(), 
               count_freelist(), vg_freed_list_volume,
               nmemb, size1 );
#  endif

   vg_cmalloc_n_mallocs ++;
   vg_cmalloc_bs_mallocd += nmemb * size1;

   size = nmemb * size1;

   // JJJ: changed it so the --alignment option is paid attention to for
   // calloc, previously it wasn't even for --instrument=yes
   vg_assert(VG_(clo_alignment) >= 4);
   if (VG_(clo_alignment) == 4)
      p = VG_(malloc)(VG_AR_CLIENT, size);
   else
      p = VG_(malloc_aligned)(VG_AR_CLIENT, VG_(clo_alignment), size);

   /* Must zero block for calloc! */
   for (i = 0; i < size; i++) ((UChar*)p)[i] = 0;

   if (vg_needs_shadow_chunks)
      client_malloc_shadow ( tst, (Addr)p, size, Vg_AllocMalloc );

   track_new_heap_block ( (Addr)p, size, /*is_inited = */True );

   VGP_POPCC;
   return p;
}


void VG_(client_free) ( ThreadState* tst, void* p, VgAllocKind kind )
{
   ShadowChunk* sc;
   UInt         ml_no;

   VGP_PUSHCC(VgpCliMalloc);
   client_malloc_init();
#  ifdef DEBUG_CLIENTMALLOC
   VG_(printf)("[m %d, f %d (%d)] client_free ( %p, %x )\n", 
               count_malloclists(), 
               count_freelist(), vg_freed_list_volume,
               p, raw_alloc_kind );
#  endif

   vg_cmalloc_n_frees ++;

   // SSS: still a bit icky
   if (! vg_needs_shadow_chunks) {
      // JJJ: could use glibc free() here? (via 'ld --wrap')
      VG_(free) ( VG_AR_CLIENT, p );

   } else {
      /* first, see if p is one vg_client_malloc gave out. */
      ml_no = VG_MALLOCLIST_NO(p);
      vg_mlist_frees++;
      for (sc = vg_malloclist[ml_no]; sc != NULL; sc = sc->next) {
         vg_mlist_tries++;
         if ((Addr)p == sc->data)
            break;
      }

      if (sc == NULL) {
         VG_TRACK( die_mem_heap, tst, (Addr)NULL, 0, True );

      } else {
         remove_from_malloclist ( ml_no, sc );
         VG_TRACK( die_mem_heap, tst, sc->data - VG_AR_CLIENT_REDZONE_SZB, 
                                 sc->size + 2*VG_AR_CLIENT_REDZONE_SZB,
                                 (sc->allockind==kind) ? True : False );

         // JJJ: this seems to be more of a check for Valgrind itself?  Needed?
         //VG_TRACK( die_mem_heap, (Addr)sc, sizeof(ShadowChunk) );

         if (VG_(needs).record_mem_exe_context)
            sc->where = VG_(get_ExeContext)(tst->m_eip, tst->m_ebp,
                                       tst->m_esp, tst->stack_highest_word);
         if (VG_(needs).postpone_mem_reuse) {
            /* Put it out of harm's way for a while. */
            add_to_freed_queue ( sc );
         } else {
            VG_(free) ( VG_AR_CLIENT, p );
            VG_(free) ( VG_AR_PRIVATE, sc );
         }
      }
   } 
   VGP_POPCC;
}


void* VG_(client_realloc) ( ThreadState* tst, void* p, UInt size_new )
{
   ShadowChunk *sc;
   UInt         i, ml_no;

   VGP_PUSHCC(VgpCliMalloc);
   client_malloc_init();

#  ifdef DEBUG_CLIENTMALLOC
   VG_(printf)("[m %d, f %d (%d)] client_realloc ( %p, %d )\n", 
               count_malloclists(), 
               count_freelist(), vg_freed_list_volume,
               p, size_new );
#  endif

   vg_cmalloc_n_frees ++;
   vg_cmalloc_n_mallocs ++;
   vg_cmalloc_bs_mallocd += size_new;

   if (! vg_needs_shadow_chunks) {
      vg_assert(p != NULL && size_new != 0);
      VGP_POPCC;
      return VG_(realloc) ( VG_AR_CLIENT, p, size_new );

   } else {
      /* First try and find the block. */
      ml_no = VG_MALLOCLIST_NO(p);
      for (sc = vg_malloclist[ml_no]; sc != NULL; sc = sc->next) {
         if ((Addr)p == sc->data)
            break;
      }
     
      if (sc == NULL) {
         VG_TRACK( die_mem_heap, tst, (Addr)NULL, 0, True );
         /* Perhaps we should keep going regardless. */
         VGP_POPCC;
         return NULL;

      } else {
         /* Cannot realloc a range that was allocated with new or new[],
            but keep going anyway */
         Bool alloc_matches = (sc->allockind==Vg_AllocMalloc ? True : False);

         if (sc->size == size_new) {
            /* size unchanged */
            VG_TRACK( die_mem_heap, tst, sc->data + size_new, 
                      0, alloc_matches );
            VGP_POPCC;
            return p;
            
         } else if (sc->size > size_new) {
            /* new size is smaller */
            VG_TRACK( die_mem_heap, tst, sc->data + size_new, 
                                         sc->size - size_new, alloc_matches );
            sc->size = size_new;
            VGP_POPCC;
            return p;

         } else {
            void* p_new;
            
            /* new size is bigger */
            /* Get new memory */
            vg_assert(VG_(clo_alignment) >= 4);
            if (VG_(clo_alignment) == 4)
               p_new = VG_(malloc)(VG_AR_CLIENT, size_new);
            else
               p_new = VG_(malloc_aligned)(VG_AR_CLIENT, VG_(clo_alignment),
                                           size_new);
            client_malloc_shadow ( tst, (Addr)p_new, size_new, Vg_AllocMalloc );

            track_reused_heap_block ( (Addr)p, (Addr)p_new, 
                                      sc->size, size_new );
            /* Copy from old to new */
            for (i = 0; i < sc->size; i++)
               ((UChar*)p_new)[i] = ((UChar*)p)[i];

            /* Free old memory */
            remove_from_malloclist ( VG_MALLOCLIST_NO(p), sc );
            VG_TRACK( die_mem_heap, tst, (Addr)(p - VG_AR_CLIENT_REDZONE_SZB), 
                                    sc->size + 2*VG_AR_CLIENT_REDZONE_SZB,
                                    alloc_matches );
            // JJJ: just for Valgrind internals?
            //VG_TRACK( die_mem_heap, (Addr)sc, sizeof(ShadowChunk) );
            if (VG_(needs).postpone_mem_reuse) {
               add_to_freed_queue ( sc );
            } else {
               VG_(free) ( VG_AR_CLIENT, p );
               VG_(free) ( VG_AR_PRIVATE, sc );
            }
            VGP_POPCC;
            return p_new;
         }  
      }
   }
}


void VG_(clientmalloc_done) ( void )
{
   UInt         nblocks, nbytes, ml_no;
   ShadowChunk* sc;

   client_malloc_init();

   nblocks = nbytes = 0;

   for (ml_no = 0; ml_no < VG_N_MALLOCLISTS; ml_no++) {
      for (sc = vg_malloclist[ml_no]; sc != NULL; sc = sc->next) {
         nblocks ++;
         nbytes  += sc->size;
      }
   }

   if (VG_(clo_verbosity) == 0)
     return;

   VG_(message)(Vg_UserMsg, 
                "malloc/free: in use at exit: %d bytes in %d blocks.",
                nbytes, nblocks);
   VG_(message)(Vg_UserMsg, 
                "malloc/free: %d allocs, %d frees, %d bytes allocated.",
                vg_cmalloc_n_mallocs,
                vg_cmalloc_n_frees, vg_cmalloc_bs_mallocd);
   if (!VG_(clo_leak_check))
      VG_(message)(Vg_UserMsg, 
                   "For a detailed leak analysis,  rerun with: --leak-check=yes");
   if (0)
      VG_(message)(Vg_DebugMsg,
                   "free search: %d tries, %d frees", 
                   vg_mlist_tries, 
                   vg_mlist_frees );
   if (VG_(clo_verbosity) > 1)
      VG_(message)(Vg_UserMsg, "");
}


/* Describe an address as best you can, for error messages,
   putting the result in ai. */

// SSS: this is a service only used when record_mem_exe_context == True, 
// it seems
void VG_(describe_addr) ( Addr a, AddrInfo* ai )
{
   ShadowChunk* sc;
   UInt         ml_no;
   Bool         ok;
   ThreadId     tid;

   /* Perhaps it's a user-def'd block ? */
   ok = VG_(client_perm_maybe_describe)( a, ai );
   if (ok)
      return;
   /* Perhaps it's on a thread's stack? */
   tid = VG_(identify_stack_addr)(a);
   if (tid != VG_INVALID_THREADID) {
      ai->akind     = Stack;
      ai->stack_tid = tid;
      return;
   }
   /* Search for a freed block which might bracket it. */
   for (sc = vg_freed_list_start; sc != NULL; sc = sc->next) {
      if (sc->data - VG_AR_CLIENT_REDZONE_SZB <= a
          && a < sc->data + sc->size + VG_AR_CLIENT_REDZONE_SZB) {
         ai->akind      = Freed;
         ai->blksize    = sc->size;
         ai->rwoffset   = (Int)(a) - (Int)(sc->data);
         ai->lastchange = sc->where;
         return;
      }
   }
   /* Search for a mallocd block which might bracket it. */
   for (ml_no = 0; ml_no < VG_N_MALLOCLISTS; ml_no++) {
      for (sc = vg_malloclist[ml_no]; sc != NULL; sc = sc->next) {
         if (sc->data - VG_AR_CLIENT_REDZONE_SZB <= a
             && a < sc->data + sc->size + VG_AR_CLIENT_REDZONE_SZB) {
            ai->akind      = Mallocd;
            ai->blksize    = sc->size;
            ai->rwoffset   = (Int)(a) - (Int)(sc->data);
            ai->lastchange = sc->where;
            return;
         }
      }
   }
   /* Clueless ... */
   ai->akind = Unknown;
   return;
}


/*--------------------------------------------------------------------*/
/*--- end                                        vg_clientmalloc.c ---*/
/*--------------------------------------------------------------------*/
