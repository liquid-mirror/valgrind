
/*--------------------------------------------------------------------*/
/*--- Generic stuff shared by all cache simulation files.          ---*/
/*---                                            vg_cachesim_gen.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, an x86 protected-mode emulator 
   designed for debugging and profiling binaries on x86-Unixes.

   Copyright (C) 2002 Nicholas Nethercote
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

/* Notes:
  - simulates a write-allocate cache
  - (block --> set) hash function uses simple bit selection
  - handling of references straddling two cache blocks:
      - counts as only one cache access (not two)
      - both blocks hit                  --> one hit
      - one block hits, the other misses --> one miss
      - both blocks miss                 --> one miss (not two)
*/

#ifndef __VG_CACHESIM_GEN_C
#define __VG_CACHESIM_GEN_C

typedef struct {
   int          size;                   /* bytes */
   int          assoc;
   int          line_size;              /* bytes */
   int          sets;
   int          sets_min_1;
   int          assoc_bits;
   int          line_size_bits;
   int          tag_shift;
   char         desc_line[128];
   int*         tags;
} cache_t2;

/* By this point, the size/assoc/line_size has been checked. */
static void cachesim_initcache(cache_t config, cache_t2* c)
{
   int i;

   c->size      = config.size;
   c->assoc     = config.assoc;
   c->line_size = config.line_size;

   c->sets           = (c->size / c->line_size) / c->assoc;
   c->sets_min_1     = c->sets - 1;
   c->assoc_bits     = VG_(log2)(c->assoc);
   c->line_size_bits = VG_(log2)(c->line_size);
   c->tag_shift      = c->line_size_bits + VG_(log2)(c->sets);

   if (c->assoc == 1) {
      VG_(sprintf)(c->desc_line, "%d B, %d B, direct-mapped", 
                                 c->size, c->line_size);
   } else {
      VG_(sprintf)(c->desc_line, "%d B, %d B, %d-way associative",
                                 c->size, c->line_size, c->assoc);
   }

   c->tags = VG_(malloc)(sizeof(UInt) * c->sets * c->assoc);

   for (i = 0; i < c->sets * c->assoc; i++)
      c->tags[i] = 0;
}

#if 0
static void print_cache(cache_t2* c)
{
   UInt set, way, i;

   /* Note initialisation and update of 'i'. */
   for (i = 0, set = 0; set < c->sets; set++) {
      for (way = 0; way < c->assoc; way++, i++) {
         VG_(printf)("%8x ", c->tags[i]);
      }
      VG_(printf)("\n");
   }
}
#endif 

/* This is done as a macro rather than by passing in the cache_t2 as an 
 * arg because it slows things down by a small amount (3-5%) due to all 
 * that extra indirection. */

#define CACHESIM(L, MISS_TREATMENT)                                         \
/* The cache and associated bits and pieces. */                             \
static cache_t2 L;                                                          \
                                                                            \
static void cachesim_##L##_initcache(cache_t config)                        \
{                                                                           \
    cachesim_initcache(config, &L);                                         \
}                                                                           \
                                                                            \
static __inline__                                                           \
void cachesim_##L##_doref(Addr a, UChar size, ULong* m1, ULong *m2)         \
{                                                                           \
   register UInt set1 = ( a         >> L.line_size_bits) & (L.sets_min_1);  \
   register UInt set2 = ((a+size-1) >> L.line_size_bits) & (L.sets_min_1);  \
   register UInt tag  = a >> L.tag_shift;                                   \
   int i, j;                                                                \
   Bool is_miss = False;                                                    \
   int* set;                                                                \
                                                                            \
   /* First case: word entirely within line. */                             \
   if (set1 == set2) {                                                      \
                                                                            \
      /* Shifting is a bit faster than multiplying */                       \
      set = &(L.tags[set1 << L.assoc_bits]);                                \
                                                                            \
      /* This loop is unrolled for just the first case, which is the most */\
      /* common.  We can't unroll any further because it would screw up   */\
      /* if we have a direct-mapped (1-way) cache.                        */\
      if (tag == set[0]) {                                                  \
         return;                                                            \
      }                                                                     \
      /* If the tag is one other than the MRU, move it into the MRU spot  */\
      /* and shuffle the rest down.                                       */\
      for (i = 1; i < L.assoc; i++) {                                       \
         if (tag == set[i]) {                                               \
            for (j = i; j > 0; j--) {                                       \
               set[j] = set[j - 1];                                         \
            }                                                               \
            set[0] = tag;                                                   \
            return;                                                         \
         }                                                                  \
      }                                                                     \
                                                                            \
      /* A miss;  install this tag as MRU, shuffle rest down. */            \
      for (j = L.assoc - 1; j > 0; j--) {                                   \
         set[j] = set[j - 1];                                               \
      }                                                                     \
      set[0] = tag;                                                         \
      MISS_TREATMENT;                                                       \
      return;                                                               \
                                                                            \
   /* Second case: word straddles two lines. */                             \
   /* Nb: this is a fast way of doing ((set1+1) % L.sets) */                \
   } else if (((set1 + 1) & (L.sets-1)) == set2) {                          \
      set = &(L.tags[set1 << L.assoc_bits]);                                \
      if (tag == set[0]) {                                                  \
         goto block2;                                                       \
      }                                                                     \
      for (i = 1; i < L.assoc; i++) {                                       \
         if (tag == set[i]) {                                               \
            for (j = i; j > 0; j--) {                                       \
               set[j] = set[j - 1];                                         \
            }                                                               \
            set[0] = tag;                                                   \
            goto block2;                                                    \
         }                                                                  \
      }                                                                     \
      for (j = L.assoc - 1; j > 0; j--) {                                   \
         set[j] = set[j - 1];                                               \
      }                                                                     \
      set[0] = tag;                                                         \
      is_miss = True;                                                       \
block2:                                                                     \
      set = &(L.tags[set2 << L.assoc_bits]);                                \
      if (tag == set[0]) {                                                  \
         goto miss_treatment;                                               \
      }                                                                     \
      for (i = 1; i < L.assoc; i++) {                                       \
         if (tag == set[i]) {                                               \
            for (j = i; j > 0; j--) {                                       \
               set[j] = set[j - 1];                                         \
            }                                                               \
            set[0] = tag;                                                   \
            goto miss_treatment;                                            \
         }                                                                  \
      }                                                                     \
      for (j = L.assoc - 1; j > 0; j--) {                                   \
         set[j] = set[j - 1];                                               \
      }                                                                     \
      set[0] = tag;                                                         \
      is_miss = True;                                                       \
miss_treatment:                                                             \
      if (is_miss) { MISS_TREATMENT; }                                      \
                                                                            \
   } else {                                                                 \
       VG_(panic)("item straddles more than two cache sets");               \
   }                                                                        \
   return;                                                                  \
}

#endif  /* ndef __VG_CACHESIM_GEN_C */

/*--------------------------------------------------------------------*/
/*--- end                                        vg_cachesim_gen.c ---*/
/*--------------------------------------------------------------------*/

