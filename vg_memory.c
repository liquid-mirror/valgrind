
/*--------------------------------------------------------------------*/
/*--- Maintain bitmaps of memory, tracking the accessibility (A)   ---*/
/*--- and validity (V) status of each byte.                        ---*/
/*---                                                  vg_memory.c ---*/
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

/* Define to debug the mem audit system. */
/* #define VG_DEBUG_MEMORY */

/* Define to debug the memory-leak-detector. */
/* #define VG_DEBUG_LEAKCHECK */

/* Define to collect detailed performance info. */
/* #define VG_PROFILE_MEMORY */


/*------------------------------------------------------------*/
/*--- Low-level support for memory checking.               ---*/
/*------------------------------------------------------------*/

/* 
   All reads and writes are checked against a memory map, which
   records the state of all memory in the process.  The memory map is
   organised like this:

   Backing store
   ~~~~~~~~~~~~~
   The top 16 bits of an address are used to index into a top-level
   map table, containing 65536 entries.  Each entry is a pointer to a
   second-level map, which records the accessibililty and validity
   permissions for the 65536 bytes indexed by the lower 16 bits of the
   address.  Each byte is represented by nine bits, one indicating
   accessibility, the other eight validity.  So each second-level map
   contains 73728 bytes.  This two-level arrangement conveniently
   divides the 4G address space into 64k lumps, each size 64k bytes.

   Each primary (top-level) map entry either points to a valid
   secondary (second-level) map, or is NULL.  Since most of the 4G of
   address space will not be in use -- ie, not mapped at all -- there
   is a distinguished secondary map, which indicates `not addressible
   and not valid' writeable for all bytes.  Entries in the primary map
   for which the entire 64k is not in use at all are therefore NULL.

   VCache
   ~~~~~~
   This is a simple direct-mapped cache which caches selected parts of
   the backing store.  The VCache is carefully designed so that the
   common (hit) case can be done in very few (5-10) instructions,
   which are placed in-line in the generated code.  We only call here
   for cache misses.

   In fact it just _sounds_ simple.  There are several subtleties in
   the design.

   The VCache is a direct-mapped, write-back cache containing
   VG_N_CACHE entries.  The "line" size is 4 bytes, which sounds
   surprising, but allows faster, shorter common-case code.  In any
   case the cache-refill-after-miss code (try_fault_in_range) will
   prefetch multiple lines into the cache, so this small line size is
   not the performance problem it might seem.

   Each VCache entry consists of three words: the _vbits word, holding
   the V bits for the stored word, the _discr word, which is the tag,
   and the _vorig word, which holds the original V bits at the time
   the cache entry was created.  This last word allows discrimination
   of clean vs dirty blocks, which helps reduce the number of
   write-backs (dramatically).

   The _discr field simply holds the address of the word stored in
   that line.  Since it must be 4-aligned, the lowest two bits of this
   field must be zero.  An important feature of the _discr field is as
   follows.  In a normal direct-mapped cache, the middle bits of the
   address are used as the line-number, and we are no exception.
   Therefore it is redundant to store also those line-number bits in
   the _discr field, since any given address can only be mapped to one
   particular line in the cache.  HOWEVER, we need to have a way to
   make a cache line invalid -- to never match any address.  To do
   this, we invert the bits in the _descr entry corresponding to the
   line number.  This guarantees that the _discr entry will not match
   any candidate address.  In fact this could be achieved by changing
   the line number bits in the _discr address to any value other than
   that's line's number, but inverting them is distinctive and
   probably helps doing stronger sanity checking.

   The final subtlety is this: A word may only reside in the cache if
   its A bits, as defined by the backing store, indicate that the word
   is completely accessible.  This is an absolute invariant of the
   system.  The effect is to automatically force a cache miss if there
   is any addressibility failure whatsoever, which in turn means the
   inline check code does not have to explicitly check for
   addressibility failures; they show up as cache misses and are
   detected by the helper functions in this file.

   This is the reason why it is necessary to have a way to mark a
   cache entry as invalid.  We can't simply let cache entries point at
   any old junk; all valid cache entries MUST correspond to
   addressible, aligned words.  This means that when addressibility of
   memory is being changed, we may have to flush and invalidate some
   cache entries.

   What the inline code fragments do is: (integer 4/2/1 bytes loads
   and stores): check that the address is suitably aligned and is
   mapped by the vcache.  If either test fails, the helper function
   here is called.  (FPU loads and stores: just call here anyway; no
   in-line consulation of the cache is done).

   The net effect of all this complexity is that 4-byte aligned loads
   and stores to addressible memory (the common case) can be done in
   just 5 x86 instructions and two memory references, which is vastly
   cheaper than the old scheme.

   The write-back nature of the cache complicates matters, and we have
   to be careful not to forget to flush evicted entries to the backing
   store.  
*/


/*------------------------------------------------------------*/
/*--- Crude profiling machinery.                           ---*/
/*------------------------------------------------------------*/

#ifdef VG_PROFILE_MEMORY

#define N_PROF_EVENTS 120

static UInt event_ctr[N_PROF_EVENTS];

static void init_prof_mem ( void )
{
   Int i;
   for (i = 0; i < N_PROF_EVENTS; i++)
      event_ctr[i] = 0;
}

void VG_(done_prof_mem) ( void )
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

static void init_prof_mem ( void ) { }
       void VG_(done_prof_mem) ( void ) { }

#define PROF_EVENT(ev) /* */

#endif

/* Event index.  If just the name of the fn is given, this means the
   number of calls to the fn.  Otherwise it is the specified event.

   10   alloc_secondary_map

   20   get_abit
   21   get_vbyte
   22   set_abit
   23   set_vbyte
   24   get_abits4_ALIGNED
   25   get_vbytes4_ALIGNED

   30   set_address_range_perms
   31   set_address_range_perms(lower byte loop)
   32   set_address_range_perms(quadword loop)
   33   set_address_range_perms(upper byte loop)
   
   35   make_noaccess
   36   make_writable
   37   make_readable

   40   copy_address_range_perms
   41   copy_address_range_perms(byte loop)
   42   check_writable
   43   check_writable(byte loop)
   44   check_readable
   45   check_readable(byte loop)
   46   check_readable_asciiz
   47   check_readable_asciiz(byte loop)

   50   make_aligned_word_NOACCESS
   51   make_aligned_word_WRITABLE

   60   helperc_LOADV4
   61   helperc_STOREV4
   62   helperc_LOADV2
   63   helperc_STOREV2
   64   helperc_LOADV1
   65   helperc_STOREV1

   70   rim_rd_V4_SLOWLY
   71   rim_wr_V4_SLOWLY
   72   rim_rd_V2_SLOWLY
   73   rim_wr_V2_SLOWLY
   74   rim_rd_V1_SLOWLY
   75   rim_wr_V1_SLOWLY

   80   fpu_read
   81   fpu_read aligned 4
   82   fpu_read aligned 8
   83   fpu_read 2
   84   fpu_read 10

   85   fpu_write
   86   fpu_write aligned 4
   87   fpu_write aligned 8
   88   fpu_write 2
   89   fpu_write 10

   90   fpu_read_check_SLOWLY
   91   fpu_read_check_SLOWLY(byte loop)
   92   fpu_write_check_SLOWLY
   93   fpu_write_check_SLOWLY(byte loop)

   100  is_plausible_stack_addr
   101  handle_esp_assignment
   102  handle_esp_assignment(-4)
   103  handle_esp_assignment(+4)
   104  handle_esp_assignment(+16)
   105  handle_esp_assignment(-12)
   106  handle_esp_assignment(+8)
   107  handle_esp_assignment(-8)

   110  vg_handle_esp_assignment_SLOWLY
   111  vg_handle_esp_assignment_SLOWLY(normal; move down)
   112  vg_handle_esp_assignment_SLOWLY(normal; move up)
   113  vg_handle_esp_assignment_SLOWLY(normal)
   114  vg_handle_esp_assignment_SLOWLY(>= HUGE_DELTA)
*/

/*------------------------------------------------------------*/
/*--- Function declarations.                               ---*/
/*------------------------------------------------------------*/

/* Set permissions for an address range.  Not speed-critical. */
void VGM_(make_noaccess) ( Addr a, UInt len );
void VGM_(make_writable) ( Addr a, UInt len );
void VGM_(make_readable) ( Addr a, UInt len );

/* Check permissions for an address range.  Not speed-critical. */
Bool VGM_(check_writable) ( Addr a, UInt len, Addr* bad_addr );
Bool VGM_(check_readable) ( Addr a, UInt len, Addr* bad_addr );
Bool VGM_(check_readable_asciiz) ( Addr a, Addr* bad_addr );

static UInt vgm_rd_V4_SLOWLY ( Addr a );
static UInt vgm_rd_V2_SLOWLY ( Addr a );
static UInt vgm_rd_V1_SLOWLY ( Addr a );
static void vgm_wr_V4_SLOWLY ( Addr a, UInt vbytes );
static void vgm_wr_V2_SLOWLY ( Addr a, UInt vbytes );
static void vgm_wr_V1_SLOWLY ( Addr a, UInt vbytes );
static void fpu_read_check_SLOWLY ( Addr addr, Int size );
static void fpu_write_check_SLOWLY ( Addr addr, Int size );


/*------------------------------------------------------------*/
/*--- Data defns.                                          ---*/
/*------------------------------------------------------------*/

/*----------- BACKING STORE -----------*/

/* This covers 64k of address space. */
typedef 
   struct {
      UChar abits[8192];
      UChar vbyte[65536];
   }
   SecMap;

/* Only needs to be visible in this file. */
static SecMap* vg_primary_map[65536];


/*----------- VCACHE -----------*/

/* Referred to from generated code, hence public. */

       /* Tag bits for the direct-mapped cache. */
       Addr VG_(vcache_discr)[VG_N_VCACHE];

       /* "Lines" in the direct-mapped cache. */
       UInt VG_(vcache_vbits)[VG_N_VCACHE];

       /* Original contents of the "lines", so we can tell easily when
          a line is dirty.  This doesn't need to be public. */
static UInt VG_(vcache_vorig)[VG_N_VCACHE];


#define VG_N_VCACHE_LINES_PER_GROUP 2   /* must be a power of 2 */
#define VG_N_VCACHE_BYTES_PER_GROUP (4 * VG_N_VCACHE_LINES_PER_GROUP)


/*----------- Some handy bit values -----------*/

#define VGM_BIT_VALID      0
#define VGM_BIT_INVALID    1

#define VGM_NIBBLE_VALID   0
#define VGM_NIBBLE_INVALID 0xF

#define VGM_BYTE_VALID     0
#define VGM_BYTE_INVALID   0xFF

/* Now in vg_include.h.
#define VGM_WORD_VALID     0
#define VGM_WORD_INVALID   0xFFFFFFFF
*/

#define VGM_EFLAGS_VALID   0xFFFFFFFE
#define VGM_EFLAGS_INVALID 0xFFFFFFFF


#define IS_ALIGNED4_ADDR(aaa_p) (0 == (((UInt)(aaa_p)) & 3))


/*------------------------------------------------------------*/
/*--- Operations on the backing store.                     ---*/
/*------------------------------------------------------------*/

#define ENSURE_MAPPABLE(addr,caller)                                   \
   do {                                                                \
      if (NULL == VG_(primary_map)[(addr) >> 16])              {       \
         VG_(primary_map)[(addr) >> 16] = alloc_secondary_map(caller); \
         /* VG_(printf)("new 2map because of %p\n", addr);   */        \
      }                                                                \
   } while(0)


#define BITARR_SET(aaa_p,iii_p)                         \
   do {                                                 \
      UInt   iii = (UInt)iii_p;                         \
      UChar* aaa = (UChar*)aaa_p;                       \
      aaa[iii >> 3] |= (1 << (iii & 7));                \
   } while (0)

#define BITARR_CLEAR(aaa_p,iii_p)                       \
   do {                                                 \
      UInt   iii = (UInt)iii_p;                         \
      UChar* aaa = (UChar*)aaa_p;                       \
      aaa[iii >> 3] &= ~(1 << (iii & 7));               \
   } while (0)

#define BITARR_TEST(aaa_p,iii_p)                        \
      (0 != (((UChar*)aaa_p)[ ((UInt)iii_p) >> 3 ]      \
               & (1 << (((UInt)iii_p) & 7))))           \


/* Allocate and initialise a secondary map. */

static SecMap* alloc_secondary_map ( __attribute__ ((unused)) 
                                     Char* caller )
{
   SecMap* map;
   UInt  i;
   PROF_EVENT(10);

   /* Mark all bytes as invalid access and invalid value. */

   /* It just happens that a SecMap occupies exactly 18 pages --
      although this isn't important, so the following assert is
      spurious. */
   vg_assert(0 == (sizeof(SecMap) % VKI_BYTES_PER_PAGE));
   map = VG_(get_memory_from_mmap)( sizeof(SecMap) );

   for (i = 0; i < 8192; i++)
      map->abits[i] = VGM_BYTE_INVALID; /* Invalid address */
   for (i = 0; i < 65536; i++)
      map->vbyte[i] = VGM_BYTE_INVALID; /* Invalid Value */

   /* VG_(printf)("ALLOC_2MAP(%s)\n", caller ); */
   return map;
}


/* Basic reading/writing of the bitmaps, for byte-sized accesses. */

static __inline__ UChar get_backing_abit ( Addr a )
{
   SecMap* sm;
   UInt    sm_off;
   ENSURE_MAPPABLE(a, "get_backing_abit");
   sm     = VG_(primary_map)[a >> 16];
   sm_off = a & 0xFFFF;
   PROF_EVENT(20);
   return BITARR_TEST(sm->abits, sm_off) 
             ? VGM_BIT_INVALID : VGM_BIT_VALID;
}

static __inline__ UChar get_backing_vbyte ( Addr a )
{
   SecMap* sm;
   UInt    sm_off;
   ENSURE_MAPPABLE(a, "get_backing_vbyte");
   sm     = VG_(primary_map)[a >> 16];
   sm_off = a & 0xFFFF;
   PROF_EVENT(21);
   return sm->vbyte[sm_off];
}

static __inline__ void set_backing_abit ( Addr a, UChar abit )
{
   SecMap* sm;
   UInt    sm_off;
   PROF_EVENT(22);
   ENSURE_MAPPABLE(a, "set_backing_abit");
   sm     = VG_(primary_map)[a >> 16];
   sm_off = a & 0xFFFF;
   if (abit) 
      BITARR_SET(sm->abits, sm_off);
   else
      BITARR_CLEAR(sm->abits, sm_off);
}

static __inline__ void set_backing_vbyte ( Addr a, UChar vbyte )
{
   SecMap* sm;
   UInt    sm_off;
   PROF_EVENT(23);
   ENSURE_MAPPABLE(a, "set_backing_vbyte");
   sm     = VG_(primary_map)[a >> 16];
   sm_off = a & 0xFFFF;
   sm->vbyte[sm_off] = vbyte;
}


/* Reading/writing of the bitmaps, for aligned word-sized accesses. */

static __inline__ UChar get_backing_abits4_ALIGNED ( Addr a )
{
   SecMap* sm;
   UInt    sm_off;
   UChar   abits8;
   PROF_EVENT(24);
#  ifdef VG_DEBUG_MEMORY
   vg_assert(IS_ALIGNED4_ADDR(a));
#  endif
   ENSURE_MAPPABLE(a, "get_backing_abits4_ALIGNED");
   sm     = VG_(primary_map)[a >> 16];
   sm_off = a & 0xFFFF;
   abits8 = sm->abits[sm_off >> 3];
   abits8 >>= (a & 4 /* 100b */);   /* a & 4 is either 0 or 4 */
   abits8 &= 0x0F;
   return abits8;
}

static UInt __inline__ get_backing_vbytes4_ALIGNED ( Addr a )
{
   SecMap* sm;
   UInt    sm_off;
   PROF_EVENT(25);
#  ifdef VG_DEBUG_MEMORY
   vg_assert(IS_ALIGNED4_ADDR(a));
#  endif
   ENSURE_MAPPABLE(a, "get_backing_vbytes4_ALIGNED");
   sm     = VG_(primary_map)[a >> 16];
   sm_off = a & 0xFFFF;
   return ((UInt*)(sm->vbyte))[sm_off >> 2];
}


/* Setting permissions for aligned words.  This supports fast stack
   operations and general address-range-permissions-setting. */

static __inline__ void make_aligned_backing_word_NOACCESS ( Addr a )
{
   SecMap* sm;
   UInt    sm_off;
   UChar   mask;
   PROF_EVENT(50);
#  ifdef VG_DEBUG_MEMORY
   vg_assert(IS_ALIGNED4_ADDR(a));
#  endif
   ENSURE_MAPPABLE(a, "make_aligned_word_backing_NOACCESS");
   sm     = VG_(primary_map)[a >> 16];
   sm_off = a & 0xFFFF;
   ((UInt*)(sm->vbyte))[sm_off >> 2] = VGM_WORD_INVALID;
   mask = 0x0F;
   mask <<= (a & 4 /* 100b */);   /* a & 4 is either 0 or 4 */
   /* mask now contains 1s where we wish to make address bits
      invalid (1s). */
   sm->abits[sm_off >> 3] |= mask;
}

static __inline__ void make_aligned_backing_word_WRITABLE ( Addr a )
{
   SecMap* sm;
   UInt    sm_off;
   UChar   mask;
   PROF_EVENT(51);
#  ifdef VG_DEBUG_MEMORY
   vg_assert(IS_ALIGNED4_ADDR(a));
#  endif
   ENSURE_MAPPABLE(a, "make_aligned_backing_word_WRITABLE");
   sm     = VG_(primary_map)[a >> 16];
   sm_off = a & 0xFFFF;
   ((UInt*)(sm->vbyte))[sm_off >> 2] = VGM_WORD_INVALID;
   mask = 0x0F;
   mask <<= (a & 4 /* 100b */);   /* a & 4 is either 0 or 4 */
   /* mask now contains 1s where we wish to make address bits
      invalid (0s). */
   sm->abits[sm_off >> 3] &= ~mask;
}

static __inline__ void make_aligned_backing_word_READABLE ( Addr a )
{
   SecMap* sm;
   UInt    sm_off;
   UChar   mask;
   PROF_EVENT(51);
#  ifdef VG_DEBUG_MEMORY
   vg_assert(IS_ALIGNED4_ADDR(a));
#  endif
   ENSURE_MAPPABLE(a, "make_aligned_backing_word_READABLE");
   sm     = VG_(primary_map)[a >> 16];
   sm_off = a & 0xFFFF;
   ((UInt*)(sm->vbyte))[sm_off >> 2] = VGM_WORD_VALID;
   mask = 0x0F;
   mask <<= (a & 4 /* 100b */);   /* a & 4 is either 0 or 4 */
   /* mask now contains 1s where we wish to make address bits
      invalid (0s). */
   sm->abits[sm_off >> 3] &= ~mask;
}


/*------------------------------------------------------------*/
/*--- Operations on vcache, which may also involve messing ---*/
/*--- with the backing store.                              ---*/
/*------------------------------------------------------------*/

static __inline__
UInt addr_to_voffset ( Addr addr )
{
   return addr & ((VG_N_VCACHE_MASK << 2) | (1 << 1) | 1);
}

static __inline__
UInt addr_to_doffset ( Addr addr )
{
   return addr & ((VG_N_VCACHE_MASK << 2) | (0 << 1) | 0);
}

static __inline__
UInt addr_to_lineno ( Addr addr )
{
   return addr_to_doffset(addr) >> 2;
}

static __inline__
void is_empty_vcache_line ( UInt lineno )
{
   vg_assert(lineno < VG_N_VCACHE);
   d = VG_(vcache_discr)[lineno];
   return
      addr_to_lineno(d) == lineno   ? False  : True;
}

static __inline__
void make_empty_vcache_line ( UInt lineno )
{
   vg_assert(lineno < VG_N_VCACHE);
   vg_assert(!is_empty_vcache_line(lineno));
   VG_(vcache_discr)[lineno] ^= (VG_N_VCACHE_MASK << 2);
   vg_assert(is_empty_vcache_line(lineno));
}


/* Assuming a is 4-aligned, return the 2 4 bytes in the cache that
   would correspond to a, ignoring the _discr (tag) field. */
static 
UUInt get_vcache_vbits4 ( Addr a )
{
   Addr   voffset = addr_to_voffset(a);
   UChar* pc      = (UChar*)(& VG_(vcache_vbits)[0] );
   pc += voffset;
   return * ((UInt*)pc);
}

/* Same, for 2-byte access. */
static 
UShort get_vcache_vbits2 ( Addr a )
{
   Addr   voffset = addr_to_voffset(a);
   UChar* pc      = (UChar*)(& VG_(vcache_vbits)[0] );
   pc += voffset;
   return * ((UShort*)pc);
}

/* Same, for 1-byte access. */
static
UChar get_vcache_vbits1 ( Addr a )
{
   Addr   voffset = addr_to_voffset(a);
   UChar* pc      = (UChar*)(& VG_(vcache_vbits)[0] );
   pc += voffset;
   return * ((UChar*)pc);
}

static
void set_vcache_vbits1 ( Addr a, UChar v )
{
   Addr   voffset = addr_to_voffset(a);
   UChar* pc      = (UChar*)(& VG_(vcache_vbits)[0] );
   pc += voffset;
   * ((UChar*)pc) = v & 0x000000FF;
}


/* Flush a line to the backing store.  Do not change the state of the
   line, though. */
static
void writeback_vcache_line ( UInt lineno )
{
   Addr addr;

   if (is_empty_vcache_line(lineno))
      /* Not in use. */
      return;

   addr = VG_(vcache_discr)[lineno];
   vg_assert(get_backing_abits4_ALIGNED(addr) == VGM_NIBBLE_VALID);

   if (VG_(vcache_vbits)[lineno] == VG_(vcache_vorig)[lineno])
      /* Not different from backing store. */
      return;

   put_backing_vbytes4_ALIGNED ( addr, VG_(vcache_vbits)[lineno] );
}


/* Does its best to fault in the group containing the given address
   range.  It guarantees to _attempt_ to fault in all groups (hence
   all lines) covered by the range.  It does not _guarantee_ success
   -- since part of that range could be inaddressible, and so we
   simply can't have those parts in the cache.  
*/
static
void try_fault_in_range ( Addr addr, UInt size )
{
   UInt gno_lo, gno_hi, lno_lo, lno_hi, lno;
   Addr a_base;
   vg_assert(size <= 10);
   gno_lo = addr_to_groupno(addr);
   gno_hi = addr_to_groupno(addr + size - 1);
   lno_lo = gno_lo * VG_N_VCACHE_LINES_PER_GROUP;
   lno_hi = gno_hi * VG_N_VCACHE_LINES_PER_GROUP;
   a_base = addr & (~(VG_N_VCACHE_BYTES_PER_GROUP-1));
   for (lno = lno_lo; lno <= lno_hi; lno++) {
      if (get_backing_abits4_ALIGNED(a_base) == VGM_NIBBLE_VALID) {
         /* We can validly put [a_base .. a_base+3] into line lno. */
         writeback_vcache_line ( lno );
         VG_(vcache_vbits)[lno] = VG_(vcache_vorig)[lno] 
                                = get_backing_vbytes4_ALIGNED(a_base);
         VG_(vcache_discr)[lno] = a_base;
         a_base += 4;
      }
   }
}


static
void invalidate_vcache ( void )
{
   UInt lno;
   for (lno = 0; lno < VG_N_VCACHE; lno++) {
      make_empty_vcache_line(lno);
   }
}

static
void flush_and_invalidate_vcache ( void )
{
   UInt lno;
   for (lno = 0; lno < VG_N_VCACHE; lno++) {
      writeback_vcache_line(lno);
      make_empty_vcache_line(lno);
   }
}


/*--------------------------------------------------------*/
/*--- Main entry points for the vcache+backing system. ---*/
/*--------------------------------------------------------*/

/* Read the A and V bits for an arbitrary byte, first by consulting
   the cache, and, if that misses, by consulting the backing map.
   Does not change either. */
static
void get_byte_A_and_V ( Addr addr, /*OUT*/ UChar* p_A, /*OUT*/ UInt* p_V )
{
   UInt lineno = addr_to_lineno(addr);
   if (ALIGN4(addr) == VG_(vcache_discr)[lineno]) {
      /* Cache hit. */
      *p_A = VGM_BIT_VALID; /* by definition; otherwise it wouldn't be
                               in the cache. */
      *p_V = get_vcache_vbyte(addr);
   } else {
      /* Cache miss.  Consult backing. */
      *p_A = get_backing_abit(addr);
      *p_V = get_backing_vbyte(addr);
   }
}


/* Write the V bits for some completely arbitrary byte, and return the
   corresponding A bit.  Just update the vcache if addr hits;
   otherwise update the backing map.  VCache remains unchanged in the
   case of a miss. */
static
UChar put_byte_V_and_get_A ( Addr addr, UInt vbyte )
{
   UInt lineno = addr_to_lineno(addr);
   if (ALIGN4(addr) == VG_(vcache_discr)[lineno]) {
      /* Hit. */
      set_vcache_vbyte ( addr, vbyte );
      return VGM_BIT_VALID;
   } else {
      /* Miss. */
      set_backing_vbyte ( addr, vbyte );
      return get_backing_abit(addr);
   }
}


/* Write A and V bits for some completely arbitrary byte. */
static
void set_byte_A_and_V ( Addr addr, UChar abit, UInt vbyte )
{
   UInt lno = addr_to_lineno(addr);
   if (ALIGN4(addr) == VG_(vcache_discr)[lineno]) {
      /* Hit. */
      set_vcache_vbyte ( addr, vbyte );
      if (abit == VGM_BIT_INVALID) {
 	 /* Now we have to dump this line. */
	 writeback_vcache_line(lno);
	 make_empty_vcache_line(lno);
      }
      set_backing_abit ( addr, abit );
   } else {
      /* Miss. */
      set_backing_vbyte ( addr, vbyte );
      set_backing_abit ( addr, abit );
   }
}


/* The word containing addr is to be made wholly or partially
   unaddressible.  Mark the relevant cache line, if any, as invalid, 
   and set the backing A bits to indicate this.  We don't do anything to 
   V bits since V bits stored at invalid addresses are irrelevant.
*/
static
void make_aligned_word_NOACCESS ( Addr addr )
{
   UInt lno;
   vg_assert(IS_ALIGNED4(addr));
   lno = addr_to_lineno(addr);
   if (ALIGN4(addr) == VG_(vcache_discr)[lineno]) {
      /* Hit. */
      make_empty_vcache_line ( lineno );
   }
   /* In all cases ... */
   make_aligned_backing_word_NOACCESS ( addr );
}


static
void make_aligned_word_WRITABLE ( Addr addr )
{
   UInt lno;
   vg_assert(IS_ALIGNED4(addr));
   lno = addr_to_lineno(addr);
   if (ALIGN4(addr) == VG_(vcache_discr)[lineno]) {
      /* Hit.  Set the V bits to invalid. */
      VG_(vcache_discr)[lno] = VGM_WORD_INVALID;
   }
   /* In all cases ... */
   make_aligned_backing_word_WRITABLE ( addr );
}


static
void make_aligned_word_READABLE ( Addr addr )
{
   UInt lno;
   vg_assert(IS_ALIGNED4(addr));
   lno = addr_to_lineno(addr);
   if (ALIGN4(addr) == VG_(vcache_discr)[lineno]) {
      /* Hit.  Set the V bits to valid. */
      VG_(vcache_discr)[lno] = VGM_WORD_VALID;
   }
   /* In all cases ... */
   make_aligned_backing_word_READABLE ( addr );
}



/*------------------------------------------------------------*/
/*--- Helpers for integer load/store misses.               ---*/
/*------------------------------------------------------------*/

/* Integer load and store helpers -- helperc_{LOADV,STOREV}{1,2,4}
   have the following structure: 

   - The call has happened because the in-line generated code missed
     in the vcache.  So first we call try_fault_in_range to try and
     get the missing lines into the cache.  This may or may not
     succeed.  We hope it does, but it's not a problem if it doesn't.
     A side effect is lines may be ejected -- writeback'd -- from the
     cache.  Not that that's actually relevant here.

   - Then we just consult/update the relevant values from the
     vcache+backing using the official "front door" access functions,
     get_byte_A_and_V and put_byte_A_and_get_V.  */
*/

UInt VG_(helperc_LOADV4) ( Addr addr )
{
   UChar aa0, aa1, aa2, aa3;
   UInt  vv0, vv1, vv2, vv3, vw;

   try_fault_in_range ( addr, 4 );

   get_byte_A_and_V ( addr+0, &aa0, &vv0 );
   get_byte_A_and_V ( addr+1, &aa1, &vv1 );
   get_byte_A_and_V ( addr+2, &aa2, &vv2 );
   get_byte_A_and_V ( addr+3, &aa3, &vv3 );

   /* Now distinguish 3 cases */

   if (aa0 == VGM_BIT_VALID && aa1 == VGM_BIT_VALID
       && aa2 == VGM_BIT_VALID && aa3 == VGM_BIT_VALID) {
      /* Case 1: the address is completely valid, so:
         - no addressing error
         - return V bytes as read from vcache+backing
      */
      vw = VGM_WORD_INVALID;
      vw <<= 8; vw |= (vv3 & 0x000000FF);
      vw <<= 8; vw |= (vv2 & 0x000000FF);
      vw <<= 8; vw |= (vv1 & 0x000000FF);
      vw <<= 8; vw |= (vv0 & 0x000000FF);
      return vw;
   } 

   else 
   if (!VG_(clo_partial_loads_ok) 
       || (aa0 != VGM_BIT_VALID && aa1 != VGM_BIT_VALID
           && aa2 != VGM_BIT_VALID && aa3 != VGM_BIT_VALID))
      /* Case 2: the address is completely invalid.  
         - emit addressing error
         - return V word indicating validity.  
         This sounds strange, but if we make loads from invalid addresses 
         give invalid data, we also risk producing a number of confusing
         undefined-value errors later, which confuses the fact that the
         error arose in the first place from an invalid address. 
      */
      VG_(record_address_error)( addr, 4, False );
      return (VGM_BYTE_VALID << 24) | (VGM_BYTE_VALID << 16) 
             | (VGM_BYTE_VALID << 8) | VGM_BYTE_VALID;
   }

   else {
      /* Case 3: the address is partially valid.  
         - no addressing error
         - returned V word is invalid where the address is invalid, 
           and contains V bytes from memory otherwise. 
         Case 3 is only allowed if VG_(clo_partial_loads_ok) is True
         (which is the default), and the address is 4-aligned.  
         If not, Case 2 will have applied.
      */
      vg_assert(VG_(clo_partial_loads_ok));
      vw = VGM_WORD_INVALID;
      vw <<= 8; 
      vw |= (aa3 == VGM_BIT_VALID ? (vv3 & 0x000000FF) : VGM_BYTE_INVALID);
      vw <<= 8; 
      vw |= (aa2 == VGM_BIT_VALID ? (vv2 & 0x000000FF) : VGM_BYTE_INVALID);
      vw <<= 8; 
      vw |= (aa1 == VGM_BIT_VALID ? (vv1 & 0x000000FF) : VGM_BYTE_INVALID);
      vw <<= 8; 
      vw |= (aa0 == VGM_BIT_VALID ? (vv0 & 0x000000FF) : VGM_BYTE_INVALID);
      return vw;
   }
}


UInt VG_(helperc_LOADV2) ( Addr addr )
{
   UChar aa0, aa1;
   UInt  vv0, vv1, vw;

   try_fault_in_range ( addr, 2 );

   get_byte_A_and_V ( addr+0, &aa0, &vv0 );
   get_byte_A_and_V ( addr+1, &aa1, &vv1 );

   if (aa0 == VGM_BIT_VALID && aa1 == VGM_BIT_VALID) {
      vw = VGM_WORD_INVALID;
      vw <<= 8; vw |= (vv1 & 0x000000FF);
      vw <<= 8; vw |= (vv0 & 0x000000FF);
      return vw;
   } else {
      VG_(record_address_error)( addr, 2, False );
      return (VGM_BYTE_INVALID << 24) | (VGM_BYTE_INVALID << 16) 
             | (VGM_BYTE_VALID << 8) | VGM_BYTE_VALID;

   }
}


UInt VG_(helperc_LOADV1) ( Addr addr )
{
   UChar aa0;
   UInt  vv0, vw;

   /* We're in a miss situation.  Try and fault in the containing
      group. */
   try_fault_in_range ( addr, 1 );

   get_byte_A_and_V ( addr, &aa0, &vv0 );

   if (aa0 == VGM_BIT_VALID) {
      vw = VGM_WORD_INVALID;
      vw <<= 8; vw |= (vv0 & 0x000000FF);
      return vw;
   } else {
      VG_(record_address_error)( addr, 1, False );
      return (VGM_BYTE_INVALID << 24) | (VGM_BYTE_INVALID << 16) 
             | (VGM_BYTE_INVALID << 8) | VGM_BYTE_VALID;

   }
}


void VG_(helperc_STOREV4) ( Addr addr, UInt vbyte )
{
   Bool aerr;

   try_fault_in_range ( addr, 4 );

   aerr = False;
   if (put_byte_V_and_get_A(a+0, vbyte & 0x000000FF) != VGM_BIT_VALID) 
      aerr = True;
   vbyte >>= 8;
   if (put_byte_V_and_get_A(a+1, vbyte & 0x000000FF) != VGM_BIT_VALID) 
      aerr = True;
   vbyte >>= 8;
   if (put_byte_V_and_get_A(a+2, vbyte & 0x000000FF) != VGM_BIT_VALID) 
      aerr = True;
   vbyte >>= 8;
   if (put_byte_V_and_get_A(a+3, vbyte & 0x000000FF) != VGM_BIT_VALID) 
      aerr = True;

   /* If an address error has happened, report it. */
   if (aerr)
      VG_(record_address_error)( a, 4, True );
}


void VG_(helperc_STOREV2) ( Addr addr, UInt vbyte )
{
   Bool aerr;

   try_fault_in_range ( addr, 2 );

   aerr = False;
   if (put_byte_V_and_get_A(a+0, vbyte & 0x000000FF) != VGM_BIT_VALID) 
      aerr = True;
   vbyte >>= 8;
   if (put_byte_V_and_get_A(a+1, vbyte & 0x000000FF) != VGM_BIT_VALID) 
      aerr = True;

   /* If an address error has happened, report it. */
   if (aerr)
      VG_(record_address_error)( a, 2, True );
}


void VG_(helperc_STOREV1) ( Addr addr, UInt vbyte )
{
   Bool aerr;

   try_fault_in_range ( addr, 1 );

   aerr = False;
   if (put_byte_V_and_get_A(a+0, vbyte & 0x000000FF) != VGM_BIT_VALID) 
      aerr = True;

   /* If an address error has happened, report it. */
   if (aerr)
      VG_(record_address_error)( a, 1, True );
}


/*------------------------------------------------------------*/
/*--- Helpers for FPU loads/stores misses.                 ---*/
/*------------------------------------------------------------*/

/* These are a bit different from the integer load/store helpers above
   in that we call here for _all_ accesses, with the in-line code
   doing no checking at all for a cache miss.  So we do the cache
   check first, and then more-or-less behaving like the integer cases.  */

void VG_(helperc_LOADV_FP) ( Addr addr, Int size )
{
   Bool aerr;
   Bool verr;

   /* Deal with the only two important cases quickly. */

   if (IS_ALIGNED4(addr) && size == 4) {
      lno03 = addr_to_lineno(addr);
      if (addr == VG_(vcache_discr)[lno03]) {
         /* Cache hit, so there can't be any addressing error. */
         if (VG_(vcache_vbits)[lno03] != VGM_WORD_VALID) {
            VG_(record_value_error)( addr, 4, False );
         }
         return;
      } else {
	 goto slowcase;
      }
   }

   if (IS_ALIGNED4(addr) && size == 8) {
      lno03 = addr_to_lineno(addr+0);
      lno47 = addr_to_lineno(addr+4);
      if (addr+0 == VG_(vcache_discr)[lno03]
          && addr+4 == VG_(vcache_discr)[lno47]) {
         /* Cache hit, so there can't be any addressing error. */
         if (VG_(vcache_vbits)[lno03] != VGM_WORD_VALID
             || VG_(vcache_vbits)[lno47] != VGM_WORD_VALID) {
            VG_(record_value_error)( addr, 8, False );
         }
         return;
      } else {
	 goto slowcase;
      }
   }

  slowcase:

   try_fault_in_range ( addr, size );

   aerr = verr = False;
   for (i = 0; i < size; i++) {
      get_byte_A_and_V(addr+i, &a0, &v0 );
      if (a0 != VGM_BIT_VALID)
         aerr = True;
      if (v0 != VGM_BYTE_VALID)
         verr = True;
   }

   if (aerr) {
      VG_(record_address_error)( addr, size, False );
   } else {
      if (verr)
         VG_(record_value_error)( size );
   }

}


void VG_(helperc_STOREV_FP) ( Addr addr, Int size )
{
   Bool aerr;
   Bool verr;

   /* Deal with the only two important cases quickly. */

   if (IS_ALIGNED4(addr) && size == 4) {
      lno03 = addr_to_lineno(addr);
      if (addr == VG_(vcache_discr)[lno03]) {
         /* Cache hit, so there can't be any addressing error. */
         VG_(vcache_vbits)[lno03] = VGM_WORD_VALID;
         return;
      } else {
	 goto slowcase;
      }
   }

   if (IS_ALIGNED4(addr) && size == 8) {
      lno03 = addr_to_lineno(addr+0);
      lno47 = addr_to_lineno(addr+4);
      if (addr+0 == VG_(vcache_discr)[lno03]
          && addr+4 == VG_(vcache_discr)[lno47]) {
         /* Cache hit, so there can't be any addressing error. */
         VG_(vcache_vbits)[lno03] = VGM_WORD_VALID;
         VG_(vcache_vbits)[lno47] = VGM_WORD_VALID;
         return;
      } else {
	 goto slowcase;
      }
   }

  slowcase:

   try_fault_in_range ( addr, size );

   aerr = verr = False;
   for (i = 0; i < size; i++) {
      a0 = set_byte_V_and_get_A ( addr+i, VGM_BYTE_VALID );
      if (a0 != VGM_BIT_VALID)
         aerr = True;
   }

   if (aerr) {
      VG_(record_address_error)( addr, size, False );
   }
}


/*------------------------------------------------------------*/
/*--- Setting permissions over address ranges.             ---*/
/*------------------------------------------------------------*/

static void set_address_range_perms ( Addr a, UInt len, 
                                      UInt example_a_bit,
                                      UInt example_v_bit )
{
   UChar   vbyte, abyte8;
   UInt    vword4, sm_off;
   SecMap* sm;

   PROF_EVENT(30);

   if (len == 0)
      return;

   if (len > 100 * 1000 * 1000) 
      VG_(message)(Vg_UserMsg, 
                   "Warning: set address range perms: "
                   "large range %d, a %d, v %d",
                   len, example_a_bit, example_v_bit );

   VGP_PUSHCC(VgpSARP);

   /* Requests to change permissions of huge address ranges may
      indicate bugs in our machinery.  30,000,000 is arbitrary, but so
      far all legitimate requests have fallen beneath that size. */
   /* 4 Mar 02: this is just stupid; get rid of it. */
   /* vg_assert(len < 30000000); */

   /* Check the permissions make sense. */
   vg_assert(example_a_bit == VGM_BIT_VALID 
             || example_a_bit == VGM_BIT_INVALID);
   vg_assert(example_v_bit == VGM_BIT_VALID 
             || example_v_bit == VGM_BIT_INVALID);
   if (example_a_bit == VGM_BIT_INVALID)
      vg_assert(example_v_bit == VGM_BIT_INVALID);

   /* The validity bits to write. */
   vbyte = example_v_bit==VGM_BIT_VALID 
              ? VGM_BYTE_VALID : VGM_BYTE_INVALID;

   /* In order that we can charge through the address space at 8
      bytes/main-loop iteration, make up some perms. */
   abyte8 = (example_a_bit << 7)
            | (example_a_bit << 6)
            | (example_a_bit << 5)
            | (example_a_bit << 4)
            | (example_a_bit << 3)
            | (example_a_bit << 2)
            | (example_a_bit << 1)
            | (example_a_bit << 0);
   vword4 = (vbyte << 24) | (vbyte << 16) | (vbyte << 8) | vbyte;

   /* Slowly do parts preceding 4-byte alignment. */
   while (True) {
      PROF_EVENT(31);
      if (len == 0) break;
      if (IS_ALIGNED4(a)) break;
      put_byte_A_and_V ( a, example_a_bit, vbyte );
      a++;
      len--;
   }   

   if (len == 0) {
      VGP_POPCC;
      return;
   }
   vg_assert(IS_ALIGNED4(a) && len > 0);

   /* Once aligned, go fast(ish). */

   if (example_a_bit == VGM_BIT_INVALID 
       && example_v_bit == VGM_BIT_INVALID) {
      while (True) {
         PROF_EVENT(32);
         if (len < 4) break;
         make_aligned_word_NOACCESS ( a );
         a += 4;
         len -= 4;
      }
   }
   else
   if (example_a_bit == VGM_BIT_VALID 
       && example_v_bit == VGM_BIT_INVALID) {
      while (True) {
         PROF_EVENT(32);
         if (len < 4) break;
         make_aligned_word_WRITABLE ( a );
         a += 4;
         len -= 4;
      }
   }
   else
   if (example_a_bit == VGM_BIT_VALID 
       && example_v_bit == VGM_BIT_VALID) {
      while (True) {
         PROF_EVENT(32);
         if (len < 4) break;
         make_aligned_word_READABLE ( a );
         a += 4;
         len -= 4;
      }
   }
   else
      VG_(panic)("set_address_range_perms");

   if (len == 0) {
      VGP_POPCC;
      return;
   }
   vg_assert(IS_ALIGNED4(a) && len > 0 && len < 4);

   /* Finish the upper fragment. */
   while (True) {
      PROF_EVENT(33);
      if (len == 0) break;
      put_byte_A_and_V ( a, example_a_bit, vbyte );
      a++;
      len--;
   }   

   /* Check that zero page and highest page have not been written to
      -- this could happen with buggy syscall wrappers.  Today
      (2001-04-26) had precisely such a problem with
      __NR_setitimer. */
   vg_assert(VG_(first_and_last_secondaries_look_plausible)());
   VGP_POPCC;
}


/* Set permissions for address ranges ... */

void VGM_(make_noaccess) ( Addr a, UInt len )
{
   PROF_EVENT(35);
   set_address_range_perms ( a, len, VGM_BIT_INVALID, VGM_BIT_INVALID );
}

void VGM_(make_writable) ( Addr a, UInt len )
{
   PROF_EVENT(36);
   set_address_range_perms ( a, len, VGM_BIT_VALID, VGM_BIT_INVALID );
}

void VGM_(make_readable) ( Addr a, UInt len )
{
   PROF_EVENT(37);
   set_address_range_perms ( a, len, VGM_BIT_VALID, VGM_BIT_VALID );
}

void VGM_(make_readwritable) ( Addr a, UInt len )
{
   PROF_EVENT(38);
   set_address_range_perms ( a, len, VGM_BIT_VALID, VGM_BIT_VALID );
}

/* Block-copy permissions (needed for implementing realloc()). */

void VGM_(copy_address_range_perms) ( Addr src, Addr dst, UInt len )
{
   UInt  i;
   UChar abit;
   UInt  vbyte;
   PROF_EVENT(40);
   for (i = 0; i < len; i++) {
      PROF_EVENT(41);
      get_byte_A_and_V ( src+i, &abit, &vbyte );
      set_byte_A_and_V ( dst+i, abit, vbyte );
   }
}


/* Check permissions for address range.  If inadequate permissions
   exist, *bad_addr is set to the offending address, so the caller can
   know what it is. */

Bool VGM_(check_writable) ( Addr a, UInt len, Addr* bad_addr )
{
   UInt  i;
   UChar abit;
   UInt  vbyte;
   PROF_EVENT(42);
   for (i = 0; i < len; i++) {
      PROF_EVENT(43);
      get_byte_A_and_V ( a, &abit, &vbyte );
      if (abit == VGM_BIT_INVALID) {
         if (bad_addr != NULL) *bad_addr = a;
         return False;
      }
      a++;
   }
   return True;
}

Bool VGM_(check_readable) ( Addr a, UInt len, Addr* bad_addr )
{
   UInt  i;
   UChar abit;
   UInt  vbyte;
   PROF_EVENT(44);
   for (i = 0; i < len; i++) {
      PROF_EVENT(45);
      get_byte_A_and_V ( a, &abit, &vbyte );
      if (abit != VGM_BIT_VALID || vbyte != VGM_BYTE_VALID) {
         if (bad_addr != NULL) *bad_addr = a;
         return False;
      }
      a++;
   }
   return True;
}


/* Check a zero-terminated ascii string.  Tricky -- don't want to
   examine the actual bytes, to find the end, until we're sure it is
   safe to do so. */

Bool VGM_(check_readable_asciiz) ( Addr a, Addr* bad_addr )
{
   UChar abit;
   UInt  vbyte;
   PROF_EVENT(46);
   while (True) {
      PROF_EVENT(47);
      get_byte_A_and_V ( a, &abit, &vbyte );
      if (abit != VGM_BIT_VALID || vbyte != VGM_BYTE_VALID) {
         if (bad_addr != NULL) *bad_addr = a;
         return False;
      }
      /* Ok, a is safe to read. */
      if (* ((UChar*)a) == 0) return True;
      a++;
   }
}


/* Setting permissions for aligned words.  This supports fast stack
   operations. */

static __inline__ void make_aligned_word_NOACCESS ( Addr a )
{
   SecMap* sm;
   UInt    sm_off;
   UChar   mask;
   PROF_EVENT(50);
#  ifdef VG_DEBUG_MEMORY
   vg_assert(IS_ALIGNED4_ADDR(a));
#  endif
   ENSURE_MAPPABLE(a, "make_aligned_word_NOACCESS");
   sm     = VG_(primary_map)[a >> 16];
   sm_off = a & 0xFFFF;
   ((UInt*)(sm->vbyte))[sm_off >> 2] = VGM_WORD_INVALID;
   mask = 0x0F;
   mask <<= (a & 4 /* 100b */);   /* a & 4 is either 0 or 4 */
   /* mask now contains 1s where we wish to make address bits
      invalid (1s). */
   sm->abits[sm_off >> 3] |= mask;
}

static __inline__ void make_aligned_word_WRITABLE ( Addr a )
{
   SecMap* sm;
   UInt    sm_off;
   UChar   mask;
   PROF_EVENT(51);
#  ifdef VG_DEBUG_MEMORY
   vg_assert(IS_ALIGNED4_ADDR(a));
#  endif
   ENSURE_MAPPABLE(a, "make_aligned_word_WRITABLE");
   sm     = VG_(primary_map)[a >> 16];
   sm_off = a & 0xFFFF;
   ((UInt*)(sm->vbyte))[sm_off >> 2] = VGM_WORD_INVALID;
   mask = 0x0F;
   mask <<= (a & 4 /* 100b */);   /* a & 4 is either 0 or 4 */
   /* mask now contains 1s where we wish to make address bits
      invalid (0s). */
   sm->abits[sm_off >> 3] &= ~mask;
}


/* ---------------------------------------------------------------------
   Called from generated code, or from the assembly helpers.
   Handlers for value check failures.
   ------------------------------------------------------------------ */

void VG_(helperc_value_check0_fail) ( void )
{
   VG_(record_value_error) ( 0 );
}

void VG_(helperc_value_check1_fail) ( void )
{
   VG_(record_value_error) ( 1 );
}

void VG_(helperc_value_check2_fail) ( void )
{
   VG_(record_value_error) ( 2 );
}

void VG_(helperc_value_check4_fail) ( void )
{
   VG_(record_value_error) ( 4 );
}


/*------------------------------------------------------------*/
/*--- Tracking permissions around %esp changes.            ---*/
/*------------------------------------------------------------*/

/*
   The stack
   ~~~~~~~~~
   The stack's segment seems to be dynamically extended downwards
   by the kernel as the stack pointer moves down.  Initially, a
   1-page (4k) stack is allocated.  When %esp moves below that for
   the first time, presumably a page fault occurs.  The kernel
   detects that the faulting address is in the range from %esp upwards
   to the current valid stack.  It then extends the stack segment
   downwards for enough to cover the faulting address, and resumes
   the process (invisibly).  The process is unaware of any of this.

   That means that Valgrind can't spot when the stack segment is
   being extended.  Fortunately, we want to precisely and continuously
   update stack permissions around %esp, so we need to spot all
   writes to %esp anyway.

   The deal is: when %esp is assigned a lower value, the stack is
   being extended.  Create a secondary maps to fill in any holes
   between the old stack ptr and this one, if necessary.  Then 
   mark all bytes in the area just "uncovered" by this %esp change
   as write-only.

   When %esp goes back up, mark the area receded over as unreadable
   and unwritable.

   Just to record the %esp boundary conditions somewhere convenient:
   %esp always points to the lowest live byte in the stack.  All
   addresses below %esp are not live; those at and above it are.  
*/

/* Does this address look like something in or vaguely near the
   current thread's stack? */
static
Bool is_plausible_stack_addr ( ThreadState* tst, Addr aa )
{
   UInt a = (UInt)aa;
   PROF_EVENT(100);
   if (a <= tst->stack_highest_word && 
       a > tst->stack_highest_word - VG_PLAUSIBLE_STACK_SIZE)
      return True;
   else
      return False;
}


/* Is this address within some small distance below %ESP?  Used only
   for the --workaround-gcc296-bugs kludge. */
Bool VG_(is_just_below_ESP)( Addr esp, Addr aa )
{
   if ((UInt)esp > (UInt)aa
       && ((UInt)esp - (UInt)aa) <= VG_GCC296_BUG_STACK_SLOP)
      return True;
   else
      return False;
}


/* Kludgey ... how much does %esp have to change before we reckon that
   the application is switching stacks ? */
#define VG_HUGE_DELTA (VG_PLAUSIBLE_STACK_SIZE / 4)

static Addr get_page_base ( Addr a )
{
   return a & ~(VKI_BYTES_PER_PAGE-1);
}


static void vg_handle_esp_assignment_SLOWLY ( Addr );

void VGM_(handle_esp_assignment) ( Addr new_espA )
{
   UInt old_esp = VG_(baseBlock)[VGOFF_(m_esp)];
   UInt new_esp = (UInt)new_espA;
   Int  delta   = ((Int)new_esp) - ((Int)old_esp);

   PROF_EVENT(101);

#  ifndef VG_DEBUG_MEMORY

   if (IS_ALIGNED4_ADDR(old_esp)) {

      /* Deal with the most common cases fast.  These are ordered in
         the sequence most common first. */

      if (delta == -4) {
         /* Moving down by 4 and properly aligned.. */
         PROF_EVENT(102);
         make_aligned_word_WRITABLE(new_esp);
         return;
      }

      if (delta == 4) {
         /* Moving up by 4 and properly aligned. */
         PROF_EVENT(103);
         make_aligned_word_NOACCESS(old_esp);
         return;
      }

      if (delta == 16) {
         /* Also surprisingly common. */
         PROF_EVENT(104);
         make_aligned_word_NOACCESS(old_esp);
         make_aligned_word_NOACCESS(old_esp+4);
         make_aligned_word_NOACCESS(old_esp+8);
         make_aligned_word_NOACCESS(old_esp+12);
         return;
      }

      if (delta == -12) {
         PROF_EVENT(105);
         make_aligned_word_WRITABLE(new_esp);
         make_aligned_word_WRITABLE(new_esp+4);
         make_aligned_word_WRITABLE(new_esp+8);
         return;
      }

      if (delta == 8) {
         PROF_EVENT(106);
         make_aligned_word_NOACCESS(old_esp);
         make_aligned_word_NOACCESS(old_esp+4);
         return;
      }

      if (delta == -8) {
         PROF_EVENT(107);
         make_aligned_word_WRITABLE(new_esp);
         make_aligned_word_WRITABLE(new_esp+4);
         return;
      }
   }

#  endif

   /* The above special cases handle 90% to 95% of all the stack
      adjustments.  The rest we give to the slow-but-general
      mechanism. */
   vg_handle_esp_assignment_SLOWLY ( new_espA );
}


static void vg_handle_esp_assignment_SLOWLY ( Addr new_espA )
{
   UInt old_esp = VG_(baseBlock)[VGOFF_(m_esp)];
   UInt new_esp = (UInt)new_espA;
   Int  delta   = ((Int)new_esp) - ((Int)old_esp);

   PROF_EVENT(110);
   if (-(VG_HUGE_DELTA) < delta && delta < VG_HUGE_DELTA) {
      /* "Ordinary" stack change. */
      if (new_esp < old_esp) {
         /* Moving down; the stack is growing. */
         PROF_EVENT(111);
         VGM_(make_writable) ( new_esp, old_esp - new_esp );
         return;
      }
      if (new_esp > old_esp) {
         /* Moving up; the stack is shrinking. */
         PROF_EVENT(112);
         VGM_(make_noaccess) ( old_esp, new_esp - old_esp );
         return;
      }
      PROF_EVENT(113);
      return; /* when old_esp == new_esp */
   }

   /* %esp has changed by more than HUGE_DELTA.  We take this to mean
      that the application is switching to a new stack, for whatever
      reason, and we attempt to initialise the permissions around the
      new stack in some plausible way.  All pretty kludgey; needed to
      make netscape-4.07 run without generating thousands of error
      contexts.

      If we appear to be switching back to the main stack, don't mess
      with the permissions in the area at and above the stack ptr.
      Otherwise, we're switching to an alternative stack; make the
      area above %esp readable -- this doesn't seem right -- the right
      thing to do would be to make it writable -- but is needed to
      avoid huge numbers of errs in netscape.  To be investigated. */

   { Addr invalid_down_to = get_page_base(new_esp) 
                            - 0 * VKI_BYTES_PER_PAGE;
     Addr valid_up_to     = get_page_base(new_esp) + VKI_BYTES_PER_PAGE
                            + 0 * VKI_BYTES_PER_PAGE;
     ThreadState* tst     = VG_(get_current_thread_state)();
     PROF_EVENT(114);
     if (VG_(clo_verbosity) > 1)
        VG_(message)(Vg_UserMsg, "Warning: client switching stacks?  "
                                 "%%esp: %p --> %p",
                                  old_esp, new_esp);
     /* VG_(printf)("na %p,   %%esp %p,   wr %p\n",
                    invalid_down_to, new_esp, valid_up_to ); */
     VGM_(make_noaccess) ( invalid_down_to, new_esp - invalid_down_to );
     if (!is_plausible_stack_addr(tst, new_esp)) {
        VGM_(make_readable) ( new_esp, valid_up_to - new_esp );
     }
   }
}


/*--------------------------------------------------------------*/
/*--- Initialise the memory audit system on program startup. ---*/
/*--------------------------------------------------------------*/

/* Handle one entry derived from /proc/self/maps. */

static
void init_memory_audit_callback ( 
        Addr start, UInt size, 
        Char rr, Char ww, Char xx, 
        UInt foffset, UChar* filename )
{
   UChar example_a_bit;
   UChar example_v_bit;
   UInt  r_esp;
   Bool  is_stack_segment;

   /* Sanity check ... if this is the executable's text segment,
      ensure it is loaded where we think it ought to be.  Any file
      name which doesn't contain ".so" is assumed to be the
      executable. */
   if (filename != NULL
       && xx == 'x'
       && VG_(strstr(filename, ".so")) == NULL
      ) {
      /* We assume this is the executable. */
      if (start != VG_ASSUMED_EXE_BASE) {
         VG_(message)(Vg_UserMsg,
                      "FATAL: executable base addr not as assumed.");
         VG_(message)(Vg_UserMsg, "name %s, actual %p, assumed %p.",
                      filename, start, VG_ASSUMED_EXE_BASE);
         VG_(message)(Vg_UserMsg,
            "One reason this could happen is that you have a shared object");
         VG_(message)(Vg_UserMsg,
            " whose name doesn't contain the characters \".so\", so Valgrind ");
         VG_(message)(Vg_UserMsg,
            "naively assumes it is the executable.  ");
         VG_(message)(Vg_UserMsg,
            "In that case, rename it appropriately.");
         VG_(panic)("VG_ASSUMED_EXE_BASE doesn't match reality");
      }
   }
    
   if (0)
      VG_(message)(Vg_DebugMsg, 
                   "initial map %8x-%8x %c%c%c? %8x (%d) (%s)",
                   start,start+size,rr,ww,xx,foffset,
                   size, filename?filename:(UChar*)"NULL");

   r_esp = VG_(baseBlock)[VGOFF_(m_esp)];
   is_stack_segment = start <= r_esp && r_esp < start+size;

   /* Figure out the segment's permissions.

      All segments are addressible -- since a process can read its
      own text segment.

      A read-but-not-write segment presumably contains initialised
      data, so is all valid.  Read-write segments presumably contains
      uninitialised data, so is all invalid.  */

   /* ToDo: make this less bogus. */
   if (rr != 'r' && xx != 'x' && ww != 'w') {
      /* Very bogus; this path never gets taken. */
      /* A no, V no */
      example_a_bit = VGM_BIT_INVALID;
      example_v_bit = VGM_BIT_INVALID;
   } else {
      /* A yes, V yes */
      example_a_bit = VGM_BIT_VALID;
      example_v_bit = VGM_BIT_VALID;
      /* Causes a lot of errs for unknown reasons. 
         if (filename is valgrind.so 
               [careful about end conditions on filename]) {
            example_a_bit = VGM_BIT_INVALID;
            example_v_bit = VGM_BIT_INVALID;
         }
      */
   }

   set_address_range_perms ( start, size, 
                             example_a_bit, example_v_bit );

   if (is_stack_segment) {
      /* This is the stack segment.  Mark all below %esp as
         noaccess. */
      if (0)
         VG_(message)(Vg_DebugMsg, 
                      "invalidating stack area: %x .. %x",
                      start,r_esp);
      VGM_(make_noaccess)( start, r_esp-start );
   }
}



/* ONLY HERE for sbrk() */
#include <unistd.h>

/* Initialise the memory audit system. */
void VGM_(init_memory_audit) ( void )
{
   Int i;

   init_prof_mem();

   /* These entries gradually get overwritten as the used address
      space expands. */
   for (i = 0; i < 65536; i++)
      VG_(primary_map)[i] = NULL;

   /* Make the vcache completely invalid. */
   invalidate_vcache();

   /* Read the initial memory mapping from the /proc filesystem, and
      set up our own maps accordingly. */
   VG_(read_procselfmaps) ( init_memory_audit_callback );

   /* Last but not least, set up the shadow regs with reasonable (sic)
      values.  All regs are claimed to have valid values.
   */
   VG_(baseBlock)[VGOFF_(sh_esp)]    = VGM_WORD_VALID;
   VG_(baseBlock)[VGOFF_(sh_ebp)]    = VGM_WORD_VALID;
   VG_(baseBlock)[VGOFF_(sh_eax)]    = VGM_WORD_VALID;
   VG_(baseBlock)[VGOFF_(sh_ecx)]    = VGM_WORD_VALID;
   VG_(baseBlock)[VGOFF_(sh_edx)]    = VGM_WORD_VALID;
   VG_(baseBlock)[VGOFF_(sh_ebx)]    = VGM_WORD_VALID;
   VG_(baseBlock)[VGOFF_(sh_esi)]    = VGM_WORD_VALID;
   VG_(baseBlock)[VGOFF_(sh_edi)]    = VGM_WORD_VALID;
   VG_(baseBlock)[VGOFF_(sh_eflags)] = VGM_EFLAGS_VALID;

   /* Record the end of the data segment, so that vg_syscall_mem.c
      can make sense of calls to brk(). 
   */
   VGM_(curr_dataseg_end) = (Addr)sbrk(0);
   if (VGM_(curr_dataseg_end) == (Addr)(-1))
      VG_(panic)("vgm_init_memory_audit: can't determine data-seg end");

   if (0)
      VG_(printf)("DS END is %p\n", (void*)VGM_(curr_dataseg_end));

   /* Read the list of errors to suppress.  This should be found in
      the file specified by vg_clo_suppressions. */
   VG_(load_suppressions)();
}


/*------------------------------------------------------------*/
/*--- Low-level address-space scanning, for the leak       ---*/
/*--- detector.                                            ---*/
/*------------------------------------------------------------*/

static 
jmp_buf memscan_jmpbuf;

static
void vg_scan_all_valid_memory_sighandler ( Int sigNo )
{
   __builtin_longjmp(memscan_jmpbuf, 1);
}

UInt VG_(scan_all_valid_memory) ( void (*notify_word)( Addr, UInt ) )
{
   /* All volatile, because some gccs seem paranoid about longjmp(). */
   volatile UInt res, numPages, page, vbytes, primaryMapNo, nWordsNotified;
   volatile Addr pageBase, addr;
   volatile SecMap* sm;
   volatile UChar abits;
   volatile UInt page_first_word;

   vki_ksigaction sigbus_saved;
   vki_ksigaction sigbus_new;
   vki_ksigaction sigsegv_saved;
   vki_ksigaction sigsegv_new;
   vki_ksigset_t  blockmask_saved;
   vki_ksigset_t  unblockmask_new;

   /* Temporarily install a new sigsegv and sigbus handler, and make
      sure SIGBUS, SIGSEGV and SIGTERM are unblocked.  (Perhaps the
      first two can never be blocked anyway?)  */

   sigbus_new.ksa_handler = vg_scan_all_valid_memory_sighandler;
   sigbus_new.ksa_flags = VKI_SA_ONSTACK | VKI_SA_RESTART;
   sigbus_new.ksa_restorer = NULL;
   res = VG_(ksigemptyset)( &sigbus_new.ksa_mask );
   vg_assert(res == 0);

   sigsegv_new.ksa_handler = vg_scan_all_valid_memory_sighandler;
   sigsegv_new.ksa_flags = VKI_SA_ONSTACK | VKI_SA_RESTART;
   sigsegv_new.ksa_restorer = NULL;
   res = VG_(ksigemptyset)( &sigsegv_new.ksa_mask );
   vg_assert(res == 0+0);

   res =  VG_(ksigemptyset)( &unblockmask_new );
   res |= VG_(ksigaddset)( &unblockmask_new, VKI_SIGBUS );
   res |= VG_(ksigaddset)( &unblockmask_new, VKI_SIGSEGV );
   res |= VG_(ksigaddset)( &unblockmask_new, VKI_SIGTERM );
   vg_assert(res == 0+0+0);

   res = VG_(ksigaction)( VKI_SIGBUS, &sigbus_new, &sigbus_saved );
   vg_assert(res == 0+0+0+0);

   res = VG_(ksigaction)( VKI_SIGSEGV, &sigsegv_new, &sigsegv_saved );
   vg_assert(res == 0+0+0+0+0);

   res = VG_(ksigprocmask)( VKI_SIG_UNBLOCK, &unblockmask_new, &blockmask_saved );
   vg_assert(res == 0+0+0+0+0+0);

   /* The signal handlers are installed.  Actually do the memory scan. */
   numPages = 1 << (32-VKI_BYTES_PER_PAGE_BITS);
   vg_assert(numPages == 1048576);
   vg_assert(4096 == (1 << VKI_BYTES_PER_PAGE_BITS));

   nWordsNotified = 0;

   flush_and_invalidate_vcache();

   for (page = 0; page < numPages; page++) {
      pageBase = page << VKI_BYTES_PER_PAGE_BITS;
      primaryMapNo = pageBase >> 16;
      sm = VG_(primary_map)[primaryMapNo];
      if (sm == NULL) continue;
      if (__builtin_setjmp(memscan_jmpbuf) == 0) {
         /* try this ... */
         page_first_word = * (volatile UInt*)pageBase;
         /* we get here if we didn't get a fault */
         /* Scan the page */
         for (addr = pageBase; addr < pageBase+VKI_BYTES_PER_PAGE; addr += 4) {
            abits  = get_abits4_ALIGNED(addr);
            vbytes = get_vbytes4_ALIGNED(addr);
            if (abits == VGM_NIBBLE_VALID 
                && vbytes == VGM_WORD_VALID) {
               nWordsNotified++;
               notify_word ( addr, *(UInt*)addr );
	    }
         }
      } else {
         /* We get here if reading the first word of the page caused a
            fault, which in turn caused the signal handler to longjmp.
            Ignore this page. */
         if (0)
         VG_(printf)(
            "vg_scan_all_valid_memory_sighandler: ignoring page at %p\n",
            (void*)pageBase 
         );
      }
   }

   /* Restore signal state to whatever it was before. */
   res = VG_(ksigaction)( VKI_SIGBUS, &sigbus_saved, NULL );
   vg_assert(res == 0 +0);

   res = VG_(ksigaction)( VKI_SIGSEGV, &sigsegv_saved, NULL );
   vg_assert(res == 0 +0 +0);

   res = VG_(ksigprocmask)( VKI_SIG_SETMASK, &blockmask_saved, NULL );
   vg_assert(res == 0 +0 +0 +0);

   return nWordsNotified;
}


/*------------------------------------------------------------*/
/*--- Detecting leaked (unreachable) malloc'd blocks.      ---*/
/*------------------------------------------------------------*/

/* A block is either 
   -- Proper-ly reached; a pointer to its start has been found
   -- Interior-ly reached; only an interior pointer to it has been found
   -- Unreached; so far, no pointers to any part of it have been found. 
*/
typedef 
   enum { Unreached, Interior, Proper } 
   Reachedness;

/* A block record, used for generating err msgs. */
typedef
   struct _LossRecord {
      struct _LossRecord* next;
      /* Where these lost blocks were allocated. */
      ExeContext*  allocated_at;
      /* Their reachability. */
      Reachedness  loss_mode;
      /* Number of blocks and total # bytes involved. */
      UInt         total_bytes;
      UInt         num_blocks;
   }
   LossRecord;


/* Find the i such that ptr points at or inside the block described by
   shadows[i].  Return -1 if none found.  This assumes that shadows[]
   has been sorted on the ->data field. */

#ifdef VG_DEBUG_LEAKCHECK
/* Used to sanity-check the fast binary-search mechanism. */
static Int find_shadow_for_OLD ( Addr          ptr, 
                                 ShadowChunk** shadows,
                                 Int           n_shadows )

{
   Int  i;
   Addr a_lo, a_hi;
   PROF_EVENT(70);
   for (i = 0; i < n_shadows; i++) {
      PROF_EVENT(71);
      a_lo = shadows[i]->data;
      a_hi = ((Addr)shadows[i]->data) + shadows[i]->size - 1;
      if (a_lo <= ptr && ptr <= a_hi)
         return i;
   }
   return -1;
}
#endif


static Int find_shadow_for ( Addr          ptr, 
                             ShadowChunk** shadows,
                             Int           n_shadows )
{
   Addr a_mid_lo, a_mid_hi;
   Int lo, mid, hi, retVal;
   PROF_EVENT(70);
   /* VG_(printf)("find shadow for %p = ", ptr); */
   retVal = -1;
   lo = 0;
   hi = n_shadows-1;
   while (True) {
      PROF_EVENT(71);

      /* invariant: current unsearched space is from lo to hi,
         inclusive. */
      if (lo > hi) break; /* not found */

      mid      = (lo + hi) / 2;
      a_mid_lo = shadows[mid]->data;
      a_mid_hi = ((Addr)shadows[mid]->data) + shadows[mid]->size - 1;

      if (ptr < a_mid_lo) {
         hi = mid-1;
         continue;
      } 
      if (ptr > a_mid_hi) {
         lo = mid+1;
         continue;
      }
      vg_assert(ptr >= a_mid_lo && ptr <= a_mid_hi);
      retVal = mid;
      break;
   }

#  ifdef VG_DEBUG_LEAKCHECK
   vg_assert(retVal == find_shadow_for_OLD ( ptr, shadows, n_shadows ));
#  endif
   /* VG_(printf)("%d\n", retVal); */
   return retVal;
}



static void sort_malloc_shadows ( ShadowChunk** shadows, UInt n_shadows )
{
   Int   incs[14] = { 1, 4, 13, 40, 121, 364, 1093, 3280,
                      9841, 29524, 88573, 265720,
                      797161, 2391484 };
   Int          lo = 0;
   Int          hi = n_shadows-1;
   Int          i, j, h, bigN, hp;
   ShadowChunk* v;

   PROF_EVENT(72);
   bigN = hi - lo + 1; if (bigN < 2) return;
   hp = 0; while (incs[hp] < bigN) hp++; hp--;

   for (; hp >= 0; hp--) {
      PROF_EVENT(73);
      h = incs[hp];
      i = lo + h;
      while (1) {
         PROF_EVENT(74);
         if (i > hi) break;
         v = shadows[i];
         j = i;
         while (shadows[j-h]->data > v->data) {
            PROF_EVENT(75);
            shadows[j] = shadows[j-h];
            j = j - h;
            if (j <= (lo + h - 1)) break;
         }
         shadows[j] = v;
         i++;
      }
   }
}

/* Globals, for the callback used by VG_(detect_memory_leaks). */

static ShadowChunk** vglc_shadows;
static Int           vglc_n_shadows;
static Reachedness*  vglc_reachedness;
static Addr          vglc_min_mallocd_addr;
static Addr          vglc_max_mallocd_addr;

static 
void vg_detect_memory_leaks_notify_addr ( Addr a, UInt word_at_a )
{
   Int sh_no;
   Addr ptr = (Addr)word_at_a;
   if (ptr >= vglc_min_mallocd_addr && ptr <= vglc_max_mallocd_addr) {
      /* Might be legitimate; we'll have to investigate further. */
      sh_no = find_shadow_for ( ptr, vglc_shadows, vglc_n_shadows );
      if (sh_no != -1) {
         /* Found a block at/into which ptr points. */
         vg_assert(sh_no >= 0 && sh_no < vglc_n_shadows);
         vg_assert(ptr < vglc_shadows[sh_no]->data 
                         + vglc_shadows[sh_no]->size);
         /* Decide whether Proper-ly or Interior-ly reached. */
         if (ptr == vglc_shadows[sh_no]->data) {
            vglc_reachedness[sh_no] = Proper;
         } else {
            if (vglc_reachedness[sh_no] == Unreached)
               vglc_reachedness[sh_no] = Interior;
         }
      }
   }
}


void VG_(detect_memory_leaks) ( void )
{
   Int    i;
   Int    blocks_leaked, bytes_leaked;
   Int    blocks_dubious, bytes_dubious;
   Int    blocks_reachable, bytes_reachable;
   Int    n_lossrecords;
   UInt   bytes_notified;
   
   LossRecord*  errlist;
   LossRecord*  p;

   Bool (*ec_comparer_fn) ( ExeContext*, ExeContext* );
   PROF_EVENT(76);
   vg_assert(VG_(clo_instrument));

   /* Decide how closely we want to match ExeContexts in leak
      records. */
   switch (VG_(clo_leak_resolution)) {
      case 2: 
         ec_comparer_fn = VG_(eq_ExeContext_top2); 
         break;
      case 4: 
         ec_comparer_fn = VG_(eq_ExeContext_top4); 
         break;
      case VG_DEEPEST_BACKTRACE: 
         ec_comparer_fn = VG_(eq_ExeContext_all); 
         break;
      default: 
         VG_(panic)("VG_(detect_memory_leaks): "
                    "bad VG_(clo_leak_resolution)");
         break;
   }

   /* vg_get_malloc_shadows allocates storage for shadows */
   vglc_shadows = VG_(get_malloc_shadows)( &vglc_n_shadows );
   if (vglc_n_shadows == 0) {
      vg_assert(vglc_shadows == NULL);
      VG_(message)(Vg_UserMsg, 
                   "No malloc'd blocks -- no leaks are possible.\n");
      return;
   }

   VG_(message)(Vg_UserMsg, 
                "searching for pointers to %d not-freed blocks.", 
                vglc_n_shadows );
   sort_malloc_shadows ( vglc_shadows, vglc_n_shadows );

   /* Sanity check; assert that the blocks are now in order and that
      they don't overlap. */
   for (i = 0; i < vglc_n_shadows-1; i++) {
      vg_assert( ((Addr)vglc_shadows[i]->data)
                 < ((Addr)vglc_shadows[i+1]->data) );
      vg_assert( ((Addr)vglc_shadows[i]->data) + vglc_shadows[i]->size
                 < ((Addr)vglc_shadows[i+1]->data) );
   }

   vglc_min_mallocd_addr = ((Addr)vglc_shadows[0]->data);
   vglc_max_mallocd_addr = ((Addr)vglc_shadows[vglc_n_shadows-1]->data)
                         + vglc_shadows[vglc_n_shadows-1]->size - 1;

   vglc_reachedness 
      = VG_(malloc)( VG_AR_PRIVATE, vglc_n_shadows * sizeof(Reachedness) );
   for (i = 0; i < vglc_n_shadows; i++)
      vglc_reachedness[i] = Unreached;

   /* Do the scan of memory. */
   bytes_notified
       = VG_(scan_all_valid_memory)( &vg_detect_memory_leaks_notify_addr )
         * VKI_BYTES_PER_WORD;

   VG_(message)(Vg_UserMsg, "checked %d bytes.", bytes_notified);

   blocks_leaked    = bytes_leaked    = 0;
   blocks_dubious   = bytes_dubious   = 0;
   blocks_reachable = bytes_reachable = 0;

   for (i = 0; i < vglc_n_shadows; i++) {
      if (vglc_reachedness[i] == Unreached) {
         blocks_leaked++;
         bytes_leaked += vglc_shadows[i]->size;
      }
      else if (vglc_reachedness[i] == Interior) {
         blocks_dubious++;
         bytes_dubious += vglc_shadows[i]->size;
      }
      else if (vglc_reachedness[i] == Proper) {
         blocks_reachable++;
         bytes_reachable += vglc_shadows[i]->size;
      }
   }

   VG_(message)(Vg_UserMsg, "");
   VG_(message)(Vg_UserMsg, "definitely lost: %d bytes in %d blocks.", 
                            bytes_leaked, blocks_leaked );
   VG_(message)(Vg_UserMsg, "possibly lost:   %d bytes in %d blocks.", 
                            bytes_dubious, blocks_dubious );
   VG_(message)(Vg_UserMsg, "still reachable: %d bytes in %d blocks.", 
                            bytes_reachable, blocks_reachable );


   /* Common up the lost blocks so we can print sensible error
      messages. */

   n_lossrecords = 0;
   errlist       = NULL;
   for (i = 0; i < vglc_n_shadows; i++) {
      for (p = errlist; p != NULL; p = p->next) {
         if (p->loss_mode == vglc_reachedness[i]
             && ec_comparer_fn (
                   p->allocated_at, 
                   vglc_shadows[i]->where) ) {
            break;
	 }
      }
      if (p != NULL) {
         p->num_blocks  ++;
         p->total_bytes += vglc_shadows[i]->size;
      } else {
         n_lossrecords ++;
         p = VG_(malloc)(VG_AR_PRIVATE, sizeof(LossRecord));
         p->loss_mode    = vglc_reachedness[i];
         p->allocated_at = vglc_shadows[i]->where;
         p->total_bytes  = vglc_shadows[i]->size;
         p->num_blocks   = 1;
         p->next         = errlist;
         errlist         = p;
      }
   }
   
   for (i = 0; i < n_lossrecords; i++) {
      LossRecord* p_min = NULL;
      UInt        n_min = 0xFFFFFFFF;
      for (p = errlist; p != NULL; p = p->next) {
         if (p->num_blocks > 0 && p->total_bytes < n_min) {
            n_min = p->total_bytes;
            p_min = p;
         }
      }
      vg_assert(p_min != NULL);

      if ( (!VG_(clo_show_reachable)) && p_min->loss_mode == Proper) {
         p_min->num_blocks = 0;
         continue;
      }

      VG_(message)(Vg_UserMsg, "");
      VG_(message)(
         Vg_UserMsg,
         "%d bytes in %d blocks are %s in loss record %d of %d",
         p_min->total_bytes, p_min->num_blocks,
         p_min->loss_mode==Unreached ? "definitely lost" :
            (p_min->loss_mode==Interior ? "possibly lost"
                                        : "still reachable"),
         i+1, n_lossrecords
      );
      VG_(pp_ExeContext)(p_min->allocated_at);
      p_min->num_blocks = 0;
   }

   VG_(message)(Vg_UserMsg, "");
   VG_(message)(Vg_UserMsg, "LEAK SUMMARY:");
   VG_(message)(Vg_UserMsg, "   possibly lost:   %d bytes in %d blocks.", 
                            bytes_dubious, blocks_dubious );
   VG_(message)(Vg_UserMsg, "   definitely lost: %d bytes in %d blocks.", 
                            bytes_leaked, blocks_leaked );
   VG_(message)(Vg_UserMsg, "   still reachable: %d bytes in %d blocks.", 
                            bytes_reachable, blocks_reachable );
   if (!VG_(clo_show_reachable)) {
      VG_(message)(Vg_UserMsg, 
         "Reachable blocks (those to which a pointer was found) are not shown.");
      VG_(message)(Vg_UserMsg, 
         "To see them, rerun with: --show-reachable=yes");
   }
   VG_(message)(Vg_UserMsg, "");

   VG_(free) ( VG_AR_PRIVATE, vglc_shadows );
   VG_(free) ( VG_AR_PRIVATE, vglc_reachedness );
}


/* ---------------------------------------------------------------------
   Sanity check machinery (permanently engaged).
   ------------------------------------------------------------------ */

/* Check that nobody has spuriously claimed that the first or last 16
   pages (64 KB) of address space have become accessible.  Failure of
   the following do not per se indicate an internal consistency
   problem, but they are so likely to that we really want to know
   about it if so. */

Bool VG_(first_and_last_secondaries_look_plausible) ( void )
{
   if (IS_DISTINGUISHED_SM(VG_(primary_map)[0])
       && IS_DISTINGUISHED_SM(VG_(primary_map)[65535])) {
      return True;
   } else {
      return False;
   }
}


/* A fast sanity check -- suitable for calling circa once per
   millisecond. */

void VG_(do_sanity_checks) ( Bool force_expensive )
{
   Int          i;
   Bool         do_expensive_checks;

   if (VG_(sanity_level) < 1) return;

   /* --- First do all the tests that we can do quickly. ---*/

   VG_(sanity_fast_count)++;

   /* Check that we haven't overrun our private stack. */
   for (i = 0; i < 10; i++) {
      vg_assert(VG_(stack)[i]
                == ((UInt)(&VG_(stack)[i]) ^ 0xA4B3C2D1));
      vg_assert(VG_(stack)[10000-1-i] 
                == ((UInt)(&VG_(stack)[10000-i-1]) ^ 0xABCD4321));
   }

   /* Check stuff pertaining to the memory check system. */

   if (VG_(clo_instrument)) {

      /* Check that nobody has spuriously claimed that the first or
         last 16 pages of memory have become accessible [...] */
      vg_assert(VG_(first_and_last_secondaries_look_plausible));
   }

   /* --- Now some more expensive checks. ---*/

   /* Once every 25 times, check some more expensive stuff. */

   do_expensive_checks = False;
   if (force_expensive) 
      do_expensive_checks = True;
   if (VG_(sanity_level) > 1) 
      do_expensive_checks = True;
   if (VG_(sanity_level) == 1 
       && (VG_(sanity_fast_count) % 25) == 0)
      do_expensive_checks = True;

   if (do_expensive_checks) {
      VG_(sanity_slow_count)++;

#     if 0
      { void zzzmemscan(void); zzzmemscan(); }
#     endif

      if ((VG_(sanity_fast_count) % 250) == 0)
         VG_(sanity_check_tc_tt)();

      if (VG_(clo_instrument)) {
      }
      /* 
      if ((VG_(sanity_fast_count) % 500) == 0) VG_(mallocSanityCheckAll)(); 
      */
   }

   if (VG_(sanity_level) > 1) {
      /* Check sanity of the low-level memory manager.  Note that bugs
         in the client's code can cause this to fail, so we don't do
         this check unless specially asked for.  And because it's
         potentially very expensive. */
      VG_(mallocSanityCheckAll)();
   }
}


/* ---------------------------------------------------------------------
   Debugging machinery (turn on to debug).  Something of a mess.
   ------------------------------------------------------------------ */

/* Print the value tags on the 8 integer registers & flag reg. */

static void uint_to_bits ( UInt x, Char* str )
{
   Int i;
   Int w = 0;
   /* str must point to a space of at least 36 bytes. */
   for (i = 31; i >= 0; i--) {
      str[w++] = (x & ( ((UInt)1) << i)) ? '1' : '0';
      if (i == 24 || i == 16 || i == 8)
         str[w++] = ' ';
   }
   str[w++] = 0;
   vg_assert(w == 36);
}

/* Caution!  Not vthread-safe; looks in VG_(baseBlock), not the thread
   state table. */

void VG_(show_reg_tags) ( void )
{
   Char buf1[36];
   Char buf2[36];
   UInt z_eax, z_ebx, z_ecx, z_edx, 
        z_esi, z_edi, z_ebp, z_esp, z_eflags;

   z_eax    = VG_(baseBlock)[VGOFF_(sh_eax)];
   z_ebx    = VG_(baseBlock)[VGOFF_(sh_ebx)];
   z_ecx    = VG_(baseBlock)[VGOFF_(sh_ecx)];
   z_edx    = VG_(baseBlock)[VGOFF_(sh_edx)];
   z_esi    = VG_(baseBlock)[VGOFF_(sh_esi)];
   z_edi    = VG_(baseBlock)[VGOFF_(sh_edi)];
   z_ebp    = VG_(baseBlock)[VGOFF_(sh_ebp)];
   z_esp    = VG_(baseBlock)[VGOFF_(sh_esp)];
   z_eflags = VG_(baseBlock)[VGOFF_(sh_eflags)];
   
   uint_to_bits(z_eflags, buf1);
   VG_(message)(Vg_DebugMsg, "efl %\n", buf1);

   uint_to_bits(z_eax, buf1);
   uint_to_bits(z_ebx, buf2);
   VG_(message)(Vg_DebugMsg, "eax %s   ebx %s\n", buf1, buf2);

   uint_to_bits(z_ecx, buf1);
   uint_to_bits(z_edx, buf2);
   VG_(message)(Vg_DebugMsg, "ecx %s   edx %s\n", buf1, buf2);

   uint_to_bits(z_esi, buf1);
   uint_to_bits(z_edi, buf2);
   VG_(message)(Vg_DebugMsg, "esi %s   edi %s\n", buf1, buf2);

   uint_to_bits(z_ebp, buf1);
   uint_to_bits(z_esp, buf2);
   VG_(message)(Vg_DebugMsg, "ebp %s   esp %s\n", buf1, buf2);
}


#if 0
/* For debugging only.  Scan the address space and touch all allegedly
   addressible words.  Useful for establishing where Valgrind's idea of
   addressibility has diverged from what the kernel believes. */

static 
void zzzmemscan_notify_word ( Addr a, UInt w )
{
}

void zzzmemscan ( void )
{
   Int n_notifies
      = VG_(scan_all_valid_memory)( zzzmemscan_notify_word );
   VG_(printf)("zzzmemscan: n_bytes = %d\n", 4 * n_notifies );
}
#endif




#if 0
static Int zzz = 0;

void show_bb ( Addr eip_next )
{
   VG_(printf)("[%4d] ", zzz);
   VG_(show_reg_tags)( &VG_(m_shadow );
   VG_(translate) ( eip_next, NULL, NULL, NULL );
}
#endif /* 0 */

/*--------------------------------------------------------------------*/
/*--- end                                              vg_memory.c ---*/
/*--------------------------------------------------------------------*/
