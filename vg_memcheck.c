/*--------------------------------------------------------------------*/
/*--- Part of the MemCheck skin: Maintain bitmaps of memory,       ---*/
/*--- tracking the accessibility (A) and validity (V) status of    ---*/
/*--- each byte.                                                   ---*/
/*---                                                vg_memcheck.c ---*/
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

#include "vg_memcheck_include.h"
#include "vg_memcheck.h"   /* for client requests */

/* Define to debug the mem audit system. */
/* #define VG_DEBUG_MEMORY */

/* Define to debug the memory-leak-detector. */
/* #define VG_DEBUG_LEAKCHECK */

/* Define to collect detailed performance info. */
/* #define VG_PROFILE_MEMORY */

#define DEBUG(fmt, args...) //VG_(printf)(fmt, ## args)

/*------------------------------------------------------------*/
/*--- Low-level support for memory checking.               ---*/
/*------------------------------------------------------------*/

/* 
   All reads and writes are checked against a memory map, which
   records the state of all memory in the process.  The memory map is
   organised like this:

   The top 16 bits of an address are used to index into a top-level
   map table, containing 65536 entries.  Each entry is a pointer to a
   second-level map, which records the accesibililty and validity
   permissions for the 65536 bytes indexed by the lower 16 bits of the
   address.  Each byte is represented by nine bits, one indicating
   accessibility, the other eight validity.  So each second-level map
   contains 73728 bytes.  This two-level arrangement conveniently
   divides the 4G address space into 64k lumps, each size 64k bytes.

   All entries in the primary (top-level) map must point to a valid
   secondary (second-level) map.  Since most of the 4G of address
   space will not be in use -- ie, not mapped at all -- there is a
   distinguished secondary map, which indicates `not addressible and
   not valid' writeable for all bytes.  Entries in the primary map for
   which the entire 64k is not in use at all point at this
   distinguished map.

   [...] lots of stuff deleted due to out of date-ness

   As a final optimisation, the alignment and address checks for
   4-byte loads and stores are combined in a neat way.  The primary
   map is extended to have 262144 entries (2^18), rather than 2^16.
   The top 3/4 of these entries are permanently set to the
   distinguished secondary map.  For a 4-byte load/store, the
   top-level map is indexed not with (addr >> 16) but instead f(addr),
   where

    f( XXXX XXXX XXXX XXXX ____ ____ ____ __YZ )
        = ____ ____ ____ __YZ XXXX XXXX XXXX XXXX  or 
        = ____ ____ ____ __ZY XXXX XXXX XXXX XXXX

   ie the lowest two bits are placed above the 16 high address bits.
   If either of these two bits are nonzero, the address is misaligned;
   this will select a secondary map from the upper 3/4 of the primary
   map.  Because this is always the distinguished secondary map, a
   (bogus) address check failure will result.  The failure handling
   code can then figure out whether this is a genuine addr check
   failure or whether it is a possibly-legitimate access at a
   misaligned address.  
*/


/*------------------------------------------------------------*/
/*--- Crude profiling machinery.                           ---*/
/*------------------------------------------------------------*/

#ifdef VG_PROFILE_MEMORY

#define N_PROF_EVENTS 150

static UInt event_ctr[N_PROF_EVENTS];

//static void init_prof_mem ( void )
//{
//   Int i;
//   for (i = 0; i < N_PROF_EVENTS; i++)
//      event_ctr[i] = 0;
//}

void done_prof_mem ( void )
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

// SSS: starting this at the right time is tricky... should be between
// init() and setup()...
// static void init_prof_mem ( void ) { }
       void done_prof_mem ( void ) { }

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

   40   copy_address_range_state
   41   copy_address_range_state(byte loop)
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
   104  handle_esp_assignment(-12)
   105  handle_esp_assignment(-8)
   106  handle_esp_assignment(+16)
   107  handle_esp_assignment(+12)
   108  handle_esp_assignment(0)
   109  handle_esp_assignment(+8)
   110  handle_esp_assignment(-16)
   111  handle_esp_assignment(+20)
   112  handle_esp_assignment(-20)
   113  handle_esp_assignment(+24)
   114  handle_esp_assignment(-24)

   120  vg_handle_esp_assignment_SLOWLY
   121  vg_handle_esp_assignment_SLOWLY(normal; move down)
   122  vg_handle_esp_assignment_SLOWLY(normal; move up)
   123  vg_handle_esp_assignment_SLOWLY(normal)
   124  vg_handle_esp_assignment_SLOWLY(>= HUGE_DELTA)
*/

/*------------------------------------------------------------*/
/*--- Function declarations.                               ---*/
/*------------------------------------------------------------*/

static UInt vgmext_rd_V4_SLOWLY ( Addr a );
static UInt vgmext_rd_V2_SLOWLY ( Addr a );
static UInt vgmext_rd_V1_SLOWLY ( Addr a );
static void vgmext_wr_V4_SLOWLY ( Addr a, UInt vbytes );
static void vgmext_wr_V2_SLOWLY ( Addr a, UInt vbytes );
static void vgmext_wr_V1_SLOWLY ( Addr a, UInt vbytes );
static void fpu_read_check_SLOWLY ( Addr addr, Int size );
static void fpu_write_check_SLOWLY ( Addr addr, Int size );

static void vg_detect_memory_leaks ( void );


/*------------------------------------------------------------*/
/*--- Data defns.                                          ---*/
/*------------------------------------------------------------*/

typedef 
   struct {
      UChar abits[8192];
      UChar vbyte[65536];
   }
   SecMap;

static SecMap* primary_map[ /*65536*/ 262144 ];
static SecMap  distinguished_secondary_map;

#define IS_DISTINGUISHED_SM(smap) \
   ((smap) == &distinguished_secondary_map)

#define ENSURE_MAPPABLE(addr,caller)                                   \
   do {                                                                \
      if (IS_DISTINGUISHED_SM(primary_map[(addr) >> 16])) {       \
         primary_map[(addr) >> 16] = alloc_secondary_map(caller); \
         /* VG_(printf)("new 2map because of %p\n", addr); */          \
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


void init_shadow_memory ( void )
{
   Int i;

   for (i = 0; i < 8192; i++)             /* Invalid address */
      distinguished_secondary_map.abits[i] = VGM_BYTE_INVALID; 
   for (i = 0; i < 65536; i++)            /* Invalid Value */
      distinguished_secondary_map.vbyte[i] = VGM_BYTE_INVALID; 

   /* These entries gradually get overwritten as the used address
      space expands. */
   for (i = 0; i < 65536; i++)
      primary_map[i] = &distinguished_secondary_map;

   /* These ones should never change; it's a bug in Valgrind if they do. */
   for (i = 65536; i < 262144; i++)
      primary_map[i] = &distinguished_secondary_map;
}


void SK_(init) ( void )
{
   init_shadow_memory();

   /* Mark global variables touched from generated code */
   VG_(track_events).post_mem_write ( (Addr)&VG_(clo_trace_malloc),  1 );
   VG_(track_events).post_mem_write ( (Addr)&VG_(clo_sloppy_malloc), 1 );

   /* Set up the shadow regs with reasonable (sic) values.  All regs are
      claimed to have valid values.
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

}

void SK_(fini) ( void )
{
   VG_(clientmalloc_done)();
   if (VG_(clo_verbosity) == 1) {
      VG_(message)(Vg_UserMsg, 
                   "For counts of detected errors, rerun with: -v");
   }
   if (VG_(clo_leak_check)) vg_detect_memory_leaks();

   done_prof_mem();
}

/*------------------------------------------------------------*/
/*--- Basic bitmap management, reading and writing.        ---*/
/*------------------------------------------------------------*/

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
   map = VG_(get_memory_from_mmap)( sizeof(SecMap), caller );

   for (i = 0; i < 8192; i++)
      map->abits[i] = VGM_BYTE_INVALID; /* Invalid address */
   for (i = 0; i < 65536; i++)
      map->vbyte[i] = VGM_BYTE_INVALID; /* Invalid Value */

   /* VG_(printf)("ALLOC_2MAP(%s)\n", caller ); */
   return map;
}


/* Basic reading/writing of the bitmaps, for byte-sized accesses. */

static __inline__ UChar get_abit ( Addr a )
{
   SecMap* sm     = primary_map[a >> 16];
   UInt    sm_off = a & 0xFFFF;
   PROF_EVENT(20);
   return BITARR_TEST(sm->abits, sm_off) 
             ? VGM_BIT_INVALID : VGM_BIT_VALID;
}

static __inline__ UChar get_vbyte ( Addr a )
{
   SecMap* sm     = primary_map[a >> 16];
   UInt    sm_off = a & 0xFFFF;
   PROF_EVENT(21);

   // SSS
   if (IS_DISTINGUISHED_SM(sm))
      VG_(printf)("accessed distinguished 2ndary map! 0x%x\n", a);

   return sm->vbyte[sm_off];
}

static __inline__ void set_abit ( Addr a, UChar abit )
{
   SecMap* sm;
   UInt    sm_off;
   PROF_EVENT(22);
   ENSURE_MAPPABLE(a, "set_abit");
   sm     = primary_map[a >> 16];
   sm_off = a & 0xFFFF;
   if (abit) 
      BITARR_SET(sm->abits, sm_off);
   else
      BITARR_CLEAR(sm->abits, sm_off);
}

static __inline__ void set_vbyte ( Addr a, UChar vbyte )
{
   SecMap* sm;
   UInt    sm_off;
   PROF_EVENT(23);
   ENSURE_MAPPABLE(a, "set_vbyte");
   sm     = primary_map[a >> 16];
   sm_off = a & 0xFFFF;
   sm->vbyte[sm_off] = vbyte;
}


/* Reading/writing of the bitmaps, for aligned word-sized accesses. */

static __inline__ UChar get_abits4_ALIGNED ( Addr a )
{
   SecMap* sm;
   UInt    sm_off;
   UChar   abits8;
   PROF_EVENT(24);
#  ifdef VG_DEBUG_MEMORY
   vg_assert(IS_ALIGNED4_ADDR(a));
#  endif
   sm     = primary_map[a >> 16];
   sm_off = a & 0xFFFF;
   abits8 = sm->abits[sm_off >> 3];
   abits8 >>= (a & 4 /* 100b */);   /* a & 4 is either 0 or 4 */
   abits8 &= 0x0F;
   return abits8;
}

static UInt __inline__ get_vbytes4_ALIGNED ( Addr a )
{
   SecMap* sm     = primary_map[a >> 16];
   UInt    sm_off = a & 0xFFFF;
   PROF_EVENT(25);
#  ifdef VG_DEBUG_MEMORY
   vg_assert(IS_ALIGNED4_ADDR(a));
#  endif
   return ((UInt*)(sm->vbyte))[sm_off >> 2];
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

   if (len > 100 * 1000 * 1000) {
      VG_(message)(Vg_UserMsg, 
                   "Warning: set address range perms: "
                   "large range %u, a %d, v %d",
                   len, example_a_bit, example_v_bit );
      // SSS: temporary
      VG_(panic)("too big, argh");
   }

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

#  ifdef VG_DEBUG_MEMORY
   /* Do it ... */
   while (True) {
      PROF_EVENT(31);
      if (len == 0) break;
      set_abit ( a, example_a_bit );
      set_vbyte ( a, vbyte );
      a++;
      len--;
   }

#  else
   /* Slowly do parts preceding 8-byte alignment. */
   while (True) {
      PROF_EVENT(31);
      if (len == 0) break;
      if ((a % 8) == 0) break;
      set_abit ( a, example_a_bit );
      set_vbyte ( a, vbyte );
      a++;
      len--;
   }   

   if (len == 0) {
      VGP_POPCC;
      return;
   }
   vg_assert((a % 8) == 0 && len > 0);

   /* Once aligned, go fast. */
   while (True) {
      PROF_EVENT(32);
      if (len < 8) break;
      ENSURE_MAPPABLE(a, "set_address_range_perms(fast)");
      sm = primary_map[a >> 16];
      sm_off = a & 0xFFFF;
      sm->abits[sm_off >> 3] = abyte8;
      ((UInt*)(sm->vbyte))[(sm_off >> 2) + 0] = vword4;
      ((UInt*)(sm->vbyte))[(sm_off >> 2) + 1] = vword4;
      a += 8;
      len -= 8;
   }

   if (len == 0) {
      VGP_POPCC;
      return;
   }
   vg_assert((a % 8) == 0 && len > 0 && len < 8);

   /* Finish the upper fragment. */
   while (True) {
      PROF_EVENT(33);
      if (len == 0) break;
      set_abit ( a, example_a_bit );
      set_vbyte ( a, vbyte );
      a++;
      len--;
   }   
#  endif

   /* Check that zero page and highest page have not been written to
      -- this could happen with buggy syscall wrappers.  Today
      (2001-04-26) had precisely such a problem with __NR_setitimer. */
   vg_assert(SKN_(cheap_sanity_check)());
   VGP_POPCC;
}


/* Set permissions for address ranges ... */
#if 0
#define MAKE_NOACCESS(nnn) \
void make_noaccess##nnn ( Addr a, UInt len )\
{\
   PROF_EVENT(35);\
     /* VG_(printf)(# nnn);*/\
   DEBUG("make_noaccess(%p, %x)\n", a, len);\
   set_address_range_perms ( a, len, VGM_BIT_INVALID, VGM_BIT_INVALID );\
}
#endif

void make_noaccess ( Addr a, UInt len )
{
   PROF_EVENT(35);
   DEBUG("make_noaccess(%p, %x)\n", a, len);
   set_address_range_perms ( a, len, VGM_BIT_INVALID, VGM_BIT_INVALID );
}

void make_writable ( Addr a, UInt len )
{
   PROF_EVENT(36);
   DEBUG("make_writable(%p, %x)\n", a, len);
   set_address_range_perms ( a, len, VGM_BIT_VALID, VGM_BIT_INVALID );
}

void make_readable ( Addr a, UInt len )
{
   PROF_EVENT(37);
   DEBUG("make_readable(%p, 0x%x)\n", a, len);
   set_address_range_perms ( a, len, VGM_BIT_VALID, VGM_BIT_VALID );
}

//void SKN_(make_readwritable) ( Addr a, UInt len )
//{
//   PROF_EVENT(38);
//   set_address_range_perms ( a, len, VGM_BIT_VALID, VGM_BIT_VALID );
//}

/* Block-copy permissions (needed for implementing realloc()). */

void copy_address_range_state ( Addr src, Addr dst, UInt len )
{
   UInt i;

   DEBUG("copy_address_range_state\n");

   PROF_EVENT(40);
   for (i = 0; i < len; i++) {
      UChar abit  = get_abit ( src+i );
      UChar vbyte = get_vbyte ( src+i );
      PROF_EVENT(41);
      set_abit ( dst+i, abit );
      set_vbyte ( dst+i, vbyte );
   }
}


/* Check permissions for address range.  If inadequate permissions
   exist, *bad_addr is set to the offending address, so the caller can
   know what it is. */

Bool check_writable ( Addr a, UInt len, Addr* bad_addr )
{
   UInt  i;
   UChar abit;
   PROF_EVENT(42);
   for (i = 0; i < len; i++) {
      PROF_EVENT(43);
      abit = get_abit(a);
      if (abit == VGM_BIT_INVALID) {
         if (bad_addr != NULL) *bad_addr = a;
         return False;
      }
      a++;
   }
   return True;
}

Bool check_readable ( Addr a, UInt len, Addr* bad_addr )
{
   UInt  i;
   UChar abit;
   UChar vbyte;

   PROF_EVENT(44);
   DEBUG("check_readable\n");
   for (i = 0; i < len; i++) {
      abit  = get_abit(a);
      vbyte = get_vbyte(a);
      PROF_EVENT(45);
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

Bool check_readable_asciiz ( Addr a, Addr* bad_addr )
{
   UChar abit;
   UChar vbyte;
   PROF_EVENT(46);
   DEBUG("check_readable_asciiz\n");
   while (True) {
      PROF_EVENT(47);
      abit  = get_abit(a);
      vbyte = get_vbyte(a);
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

void make_noaccess_aligned ( Addr a, UInt len )
{
   SecMap* sm;
   UInt    sm_off;
   UChar   mask;
   Addr    a_past_end = a + len;

   PROF_EVENT(50);
#  ifdef VG_DEBUG_MEMORY
   vg_assert(IS_ALIGNED4_ADDR(a));
   vg_assert(IS_ALIGNED4_ADDR(len));
#  endif

   for ( ; a < a_past_end; a += 4) {
      ENSURE_MAPPABLE(a, "make_aligned_word_NOACCESS");
      sm     = primary_map[a >> 16];
      sm_off = a & 0xFFFF;
      ((UInt*)(sm->vbyte))[sm_off >> 2] = VGM_WORD_INVALID;
      mask = 0x0F;
      mask <<= (a & 4 /* 100b */);   /* a & 4 is either 0 or 4 */
      /* mask now contains 1s where we wish to make address bits
         invalid (1s). */
      sm->abits[sm_off >> 3] |= mask;
   }
}

void make_writable_aligned ( Addr a, UInt len )
{
   SecMap* sm;
   UInt    sm_off;
   UChar   mask;
   Addr    a_past_end = a + len;

   PROF_EVENT(51);
#  ifdef VG_DEBUG_MEMORY
   vg_assert(IS_ALIGNED4_ADDR(a));
   vg_assert(IS_ALIGNED4_ADDR(len));
#  endif

   for ( ; a < a_past_end; a += 4) {
      ENSURE_MAPPABLE(a, "make_aligned_word_WRITABLE");
      sm     = primary_map[a >> 16];
      sm_off = a & 0xFFFF;
      ((UInt*)(sm->vbyte))[sm_off >> 2] = VGM_WORD_INVALID;
      mask = 0x0F;
      mask <<= (a & 4 /* 100b */);   /* a & 4 is either 0 or 4 */
      /* mask now contains 1s where we wish to make address bits
         invalid (0s). */
      sm->abits[sm_off >> 3] &= ~mask;
   }
}


/*------------------------------------------------------------*/
/*--- Memory event handlers                                ---*/
/*------------------------------------------------------------*/

/* SSS: This overrides the default definition which doesn't do anything */
UInt VG_(dereference) ( Addr aa )
{
   if (check_readable(aa,4,NULL))
      return * (UInt*)aa;
   else
      return 0;
}

void memcheck_new_mem_startup( Addr a, UInt len, Bool rr, Bool ww, Bool xx )
{
   // JJJ: this ignores the permissions and just makes it readable, like the
   // old code did, AFAICT
   DEBUG("new_mem_startup(%p, %u, rr=%u, ww=%u, xx=%u)\n", a,len,rr,ww,xx);
   make_readable(a, len);
}

void memcheck_new_mem_heap ( Addr a, UInt len, Bool is_inited )
{
   if (is_inited) {
      make_readable(a, len);
   } else {
      make_writable(a, len);
   }
}

void memcheck_set_perms (Addr a, UInt len, 
                         Bool nn, Bool rr, Bool ww, Bool xx)
{
   DEBUG("memcheck_set_perms(%p, %u, nn=%u, rr=%u ww=%u, xx=%u)\n",
                             a, len, nn, rr, ww, xx);
   if      (rr) make_readable(a, len);
   else if (ww) make_writable(a, len);
   else         make_noaccess(a, len);
}

/* If a == NULL, 'size', 'alloc_free_kinds_match' are meaningless */
void memcheck_die_mem_heap ( ThreadState* tst, Addr a, UInt size,
                             Bool alloc_free_kinds_match )
{
   DEBUG("memcheck_die_mem_heap(%p, %u)\n", a, size);
   if ((Addr)NULL == a)
      SK_(record_free_error) ( tst, a );

   if (! alloc_free_kinds_match)
      SK_(record_freemismatch_error) ( tst, a );

   make_noaccess(a, size);
}


/*------------------------------------------------------------*/
/*--- Functions called directly from generated code.       ---*/
/*------------------------------------------------------------*/

static __inline__ UInt rotateRight16 ( UInt x )
{
   /* Amazingly, gcc turns this into a single rotate insn. */
   return (x >> 16) | (x << 16);
}


static __inline__ UInt shiftRight16 ( UInt x )
{
   return x >> 16;
}


/* Read/write 1/2/4 sized V bytes, and emit an address error if
   needed. */

/* VG_(helperc_{LD,ST}V{1,2,4}) handle the common case fast.
   Under all other circumstances, it defers to the relevant _SLOWLY
   function, which can handle all situations.
*/
UInt SK_(helperc_LOADV4) ( Addr a )
{
#  ifdef VG_DEBUG_MEMORY
   return vgmext_rd_V4_SLOWLY(a);
#  else
   UInt    sec_no = rotateRight16(a) & 0x3FFFF;
   SecMap* sm     = primary_map[sec_no];
   UInt    a_off  = (a & 0xFFFF) >> 3;
   UChar   abits  = sm->abits[a_off];
   abits >>= (a & 4);
   abits &= 15;
   PROF_EVENT(60);
   if (abits == VGM_NIBBLE_VALID) {
      /* Handle common case quickly: a is suitably aligned, is mapped,
         and is addressible. */
      UInt v_off = a & 0xFFFF;
      return ((UInt*)(sm->vbyte))[ v_off >> 2 ];
   } else {
      /* Slow but general case. */
      return vgmext_rd_V4_SLOWLY(a);
   }
#  endif
}

void SK_(helperc_STOREV4) ( Addr a, UInt vbytes )
{
#  ifdef VG_DEBUG_MEMORY
   vgmext_wr_V4_SLOWLY(a, vbytes);
#  else
   UInt    sec_no = rotateRight16(a) & 0x3FFFF;
   SecMap* sm     = primary_map[sec_no];
   UInt    a_off  = (a & 0xFFFF) >> 3;
   UChar   abits  = sm->abits[a_off];
   abits >>= (a & 4);
   abits &= 15;
   PROF_EVENT(61);
   if (abits == VGM_NIBBLE_VALID) {
      /* Handle common case quickly: a is suitably aligned, is mapped,
         and is addressible. */
      UInt v_off = a & 0xFFFF;
      ((UInt*)(sm->vbyte))[ v_off >> 2 ] = vbytes;
   } else {
      /* Slow but general case. */
      vgmext_wr_V4_SLOWLY(a, vbytes);
   }
#  endif
}

UInt SK_(helperc_LOADV2) ( Addr a )
{
#  ifdef VG_DEBUG_MEMORY
   return vgmext_rd_V2_SLOWLY(a);
#  else
   UInt    sec_no = rotateRight16(a) & 0x1FFFF;
   SecMap* sm     = primary_map[sec_no];
   UInt    a_off  = (a & 0xFFFF) >> 3;
   PROF_EVENT(62);
   if (sm->abits[a_off] == VGM_BYTE_VALID) {
      /* Handle common case quickly. */
      UInt v_off = a & 0xFFFF;
      return 0xFFFF0000 
             |  
             (UInt)( ((UShort*)(sm->vbyte))[ v_off >> 1 ] );
   } else {
      /* Slow but general case. */
      return vgmext_rd_V2_SLOWLY(a);
   }
#  endif
}

void SK_(helperc_STOREV2) ( Addr a, UInt vbytes )
{
#  ifdef VG_DEBUG_MEMORY
   vgmext_wr_V2_SLOWLY(a, vbytes);
#  else
   UInt    sec_no = rotateRight16(a) & 0x1FFFF;
   SecMap* sm     = primary_map[sec_no];
   UInt    a_off  = (a & 0xFFFF) >> 3;
   PROF_EVENT(63);
   if (sm->abits[a_off] == VGM_BYTE_VALID) {
      /* Handle common case quickly. */
      UInt v_off = a & 0xFFFF;
      ((UShort*)(sm->vbyte))[ v_off >> 1 ] = vbytes & 0x0000FFFF;
   } else {
      /* Slow but general case. */
      vgmext_wr_V2_SLOWLY(a, vbytes);
   }
#  endif
}

UInt SK_(helperc_LOADV1) ( Addr a )
{
#  ifdef VG_DEBUG_MEMORY
   return vgmext_rd_V1_SLOWLY(a);
#  else
   UInt    sec_no = shiftRight16(a);
   SecMap* sm     = primary_map[sec_no];
   UInt    a_off  = (a & 0xFFFF) >> 3;
   PROF_EVENT(64);
   if (sm->abits[a_off] == VGM_BYTE_VALID) {
      /* Handle common case quickly. */
      UInt v_off = a & 0xFFFF;
      return 0xFFFFFF00
             |
             (UInt)( ((UChar*)(sm->vbyte))[ v_off ] );
   } else {
      /* Slow but general case. */
      return vgmext_rd_V1_SLOWLY(a);
   }
#  endif
}

void SK_(helperc_STOREV1) ( Addr a, UInt vbytes )
{
#  ifdef VG_DEBUG_MEMORY
   vgmext_wr_V1_SLOWLY(a, vbytes);
#  else
   UInt    sec_no = shiftRight16(a);
   SecMap* sm     = primary_map[sec_no];
   UInt    a_off  = (a & 0xFFFF) >> 3;
   PROF_EVENT(65);
   if (sm->abits[a_off] == VGM_BYTE_VALID) {
      /* Handle common case quickly. */
      UInt v_off = a & 0xFFFF;
      ((UChar*)(sm->vbyte))[ v_off ] = vbytes & 0x000000FF;
   } else {
      /* Slow but general case. */
      vgmext_wr_V1_SLOWLY(a, vbytes);
   }
#  endif
}


/*------------------------------------------------------------*/
/*--- Fallback functions to handle cases that the above    ---*/
/*--- VG_(helperc_{LD,ST}V{1,2,4}) can't manage.           ---*/
/*------------------------------------------------------------*/

static UInt vgmext_rd_V4_SLOWLY ( Addr a )
{
   Bool a0ok, a1ok, a2ok, a3ok;
   UInt vb0, vb1, vb2, vb3;

   PROF_EVENT(70);

   /* First establish independently the addressibility of the 4 bytes
      involved. */
   a0ok = get_abit(a+0) == VGM_BIT_VALID;
   a1ok = get_abit(a+1) == VGM_BIT_VALID;
   a2ok = get_abit(a+2) == VGM_BIT_VALID;
   a3ok = get_abit(a+3) == VGM_BIT_VALID;

   /* Also get the validity bytes for the address. */
   vb0 = (UInt)get_vbyte(a+0);
   vb1 = (UInt)get_vbyte(a+1);
   vb2 = (UInt)get_vbyte(a+2);
   vb3 = (UInt)get_vbyte(a+3);

   /* Now distinguish 3 cases */

   /* Case 1: the address is completely valid, so:
      - no addressing error
      - return V bytes as read from memory
   */
   if (a0ok && a1ok && a2ok && a3ok) {
      UInt vw = VGM_WORD_INVALID;
      vw <<= 8; vw |= vb3;
      vw <<= 8; vw |= vb2;
      vw <<= 8; vw |= vb1;
      vw <<= 8; vw |= vb0;
      return vw;
   }

   /* Case 2: the address is completely invalid.  
      - emit addressing error
      - return V word indicating validity.  
      This sounds strange, but if we make loads from invalid addresses 
      give invalid data, we also risk producing a number of confusing
      undefined-value errors later, which confuses the fact that the
      error arose in the first place from an invalid address. 
   */
   /* VG_(printf)("%p (%d %d %d %d)\n", a, a0ok, a1ok, a2ok, a3ok); */
   if (!VG_(clo_partial_loads_ok) 
       || ((a & 3) != 0)
       || (!a0ok && !a1ok && !a2ok && !a3ok)) {
      SK_(record_address_error)( a, 4, False );
      return (VGM_BYTE_VALID << 24) | (VGM_BYTE_VALID << 16) 
             | (VGM_BYTE_VALID << 8) | VGM_BYTE_VALID;
   }

   /* Case 3: the address is partially valid.  
      - no addressing error
      - returned V word is invalid where the address is invalid, 
        and contains V bytes from memory otherwise. 
      Case 3 is only allowed if VG_(clo_partial_loads_ok) is True
      (which is the default), and the address is 4-aligned.  
      If not, Case 2 will have applied.
   */
   vg_assert(VG_(clo_partial_loads_ok));
   {
      UInt vw = VGM_WORD_INVALID;
      vw <<= 8; vw |= (a3ok ? vb3 : VGM_BYTE_INVALID);
      vw <<= 8; vw |= (a2ok ? vb2 : VGM_BYTE_INVALID);
      vw <<= 8; vw |= (a1ok ? vb1 : VGM_BYTE_INVALID);
      vw <<= 8; vw |= (a0ok ? vb0 : VGM_BYTE_INVALID);
      return vw;
   }
}

static void vgmext_wr_V4_SLOWLY ( Addr a, UInt vbytes )
{
   /* Check the address for validity. */
   Bool aerr = False;
   PROF_EVENT(71);

   if (get_abit(a+0) != VGM_BIT_VALID) aerr = True;
   if (get_abit(a+1) != VGM_BIT_VALID) aerr = True;
   if (get_abit(a+2) != VGM_BIT_VALID) aerr = True;
   if (get_abit(a+3) != VGM_BIT_VALID) aerr = True;

   /* Store the V bytes, remembering to do it little-endian-ly. */
   set_vbyte( a+0, vbytes & 0x000000FF ); vbytes >>= 8;
   set_vbyte( a+1, vbytes & 0x000000FF ); vbytes >>= 8;
   set_vbyte( a+2, vbytes & 0x000000FF ); vbytes >>= 8;
   set_vbyte( a+3, vbytes & 0x000000FF );

   /* If an address error has happened, report it. */
   if (aerr)
      SK_(record_address_error)( a, 4, True );
}

static UInt vgmext_rd_V2_SLOWLY ( Addr a )
{
   /* Check the address for validity. */
   UInt vw   = VGM_WORD_INVALID;
   Bool aerr = False;
   PROF_EVENT(72);

   if (get_abit(a+0) != VGM_BIT_VALID) aerr = True;
   if (get_abit(a+1) != VGM_BIT_VALID) aerr = True;

   /* Fetch the V bytes, remembering to do it little-endian-ly. */
   vw <<= 8; vw |= (UInt)get_vbyte(a+1);
   vw <<= 8; vw |= (UInt)get_vbyte(a+0);

   /* If an address error has happened, report it. */
   if (aerr) {
      SK_(record_address_error)( a, 2, False );
      vw = (VGM_BYTE_INVALID << 24) | (VGM_BYTE_INVALID << 16) 
           | (VGM_BYTE_VALID << 8) | (VGM_BYTE_VALID);
   }
   return vw;   
}

static void vgmext_wr_V2_SLOWLY ( Addr a, UInt vbytes )
{
   /* Check the address for validity. */
   Bool aerr = False;
   PROF_EVENT(73);

   if (get_abit(a+0) != VGM_BIT_VALID) aerr = True;
   if (get_abit(a+1) != VGM_BIT_VALID) aerr = True;

   /* Store the V bytes, remembering to do it little-endian-ly. */
   set_vbyte( a+0, vbytes & 0x000000FF ); vbytes >>= 8;
   set_vbyte( a+1, vbytes & 0x000000FF );

   /* If an address error has happened, report it. */
   if (aerr)
      SK_(record_address_error)( a, 2, True );
}

static UInt vgmext_rd_V1_SLOWLY ( Addr a )
{
   /* Check the address for validity. */
   UInt vw   = VGM_WORD_INVALID;
   Bool aerr = False;
   PROF_EVENT(74);

   if (get_abit(a+0) != VGM_BIT_VALID) aerr = True;

   /* Fetch the V byte. */
   vw <<= 8; vw |= (UInt)get_vbyte(a+0);

   /* If an address error has happened, report it. */
   if (aerr) {
      SK_(record_address_error)( a, 1, False );
      vw = (VGM_BYTE_INVALID << 24) | (VGM_BYTE_INVALID << 16) 
           | (VGM_BYTE_INVALID << 8) | (VGM_BYTE_VALID);
   }
   return vw;   
}

static void vgmext_wr_V1_SLOWLY ( Addr a, UInt vbytes )
{
   /* Check the address for validity. */
   Bool aerr = False;
   PROF_EVENT(75);
   if (get_abit(a+0) != VGM_BIT_VALID) aerr = True;

   /* Store the V bytes, remembering to do it little-endian-ly. */
   set_vbyte( a+0, vbytes & 0x000000FF );

   /* If an address error has happened, report it. */
   if (aerr)
      SK_(record_address_error)( a, 1, True );
}


/* ---------------------------------------------------------------------
   Called from generated code, or from the assembly helpers.
   Handlers for value check failures.
   ------------------------------------------------------------------ */

void SK_(helperc_value_check0_fail) ( void )
{
   SK_(record_value_error) ( 0 );
}

void SK_(helperc_value_check1_fail) ( void )
{
   SK_(record_value_error) ( 1 );
}

void SK_(helperc_value_check2_fail) ( void )
{
   SK_(record_value_error) ( 2 );
}

void SK_(helperc_value_check4_fail) ( void )
{
   SK_(record_value_error) ( 4 );
}


/* ---------------------------------------------------------------------
   FPU load and store checks, called from generated code.
   ------------------------------------------------------------------ */

void SK_(fpu_read_check) ( Addr addr, Int size )
{
   /* Ensure the read area is both addressible and valid (ie,
      readable).  If there's an address error, don't report a value
      error too; but if there isn't an address error, check for a
      value error. 

      Try to be reasonably fast on the common case; wimp out and defer
      to fpu_read_check_SLOWLY for everything else.  */

   SecMap* sm;
   UInt    sm_off, v_off, a_off;
   Addr    addr4;

   PROF_EVENT(80);

#  ifdef VG_DEBUG_MEMORY
   fpu_read_check_SLOWLY ( addr, size );
#  else

   if (size == 4) {
      if (!IS_ALIGNED4_ADDR(addr)) goto slow4;
      PROF_EVENT(81);
      /* Properly aligned. */
      sm     = primary_map[addr >> 16];
      sm_off = addr & 0xFFFF;
      a_off  = sm_off >> 3;
      if (sm->abits[a_off] != VGM_BYTE_VALID) goto slow4;
      /* Properly aligned and addressible. */
      v_off = addr & 0xFFFF;
      if (((UInt*)(sm->vbyte))[ v_off >> 2 ] != VGM_WORD_VALID) 
         goto slow4;
      /* Properly aligned, addressible and with valid data. */
      return;
     slow4:
      fpu_read_check_SLOWLY ( addr, 4 );
      return;
   }

   if (size == 8) {
      if (!IS_ALIGNED4_ADDR(addr)) goto slow8;
      PROF_EVENT(82);
      /* Properly aligned.  Do it in two halves. */
      addr4 = addr + 4;
      /* First half. */
      sm     = primary_map[addr >> 16];
      sm_off = addr & 0xFFFF;
      a_off  = sm_off >> 3;
      if (sm->abits[a_off] != VGM_BYTE_VALID) goto slow8;
      /* First half properly aligned and addressible. */
      v_off = addr & 0xFFFF;
      if (((UInt*)(sm->vbyte))[ v_off >> 2 ] != VGM_WORD_VALID) 
         goto slow8;
      /* Second half. */
      sm     = primary_map[addr4 >> 16];
      sm_off = addr4 & 0xFFFF;
      a_off  = sm_off >> 3;
      if (sm->abits[a_off] != VGM_BYTE_VALID) goto slow8;
      /* Second half properly aligned and addressible. */
      v_off = addr4 & 0xFFFF;
      if (((UInt*)(sm->vbyte))[ v_off >> 2 ] != VGM_WORD_VALID) 
         goto slow8;
      /* Both halves properly aligned, addressible and with valid
         data. */
      return;
     slow8:
      fpu_read_check_SLOWLY ( addr, 8 );
      return;
   }

   /* Can't be bothered to huff'n'puff to make these (allegedly) rare
      cases go quickly.  */
   if (size == 2) {
      PROF_EVENT(83);
      fpu_read_check_SLOWLY ( addr, 2 );
      return;
   }

   if (size == 10) {
      PROF_EVENT(84);
      fpu_read_check_SLOWLY ( addr, 10 );
      return;
   }

   if (size == 28) {
      PROF_EVENT(84); /* XXX assign correct event number */
      fpu_read_check_SLOWLY ( addr, 28 );
      return;
   }

   VG_(printf)("size is %d\n", size);
   VG_(panic)("vgmext_fpu_read_check: unhandled size");
#  endif
}


void SK_(fpu_write_check) ( Addr addr, Int size )
{
   /* Ensure the written area is addressible, and moan if otherwise.
      If it is addressible, make it valid, otherwise invalid. 
   */

   SecMap* sm;
   UInt    sm_off, v_off, a_off;
   Addr    addr4;

   PROF_EVENT(85);

#  ifdef VG_DEBUG_MEMORY
   fpu_write_check_SLOWLY ( addr, size );
#  else

   if (size == 4) {
      if (!IS_ALIGNED4_ADDR(addr)) goto slow4;
      PROF_EVENT(86);
      /* Properly aligned. */
      sm     = primary_map[addr >> 16];
      sm_off = addr & 0xFFFF;
      a_off  = sm_off >> 3;
      if (sm->abits[a_off] != VGM_BYTE_VALID) goto slow4;
      /* Properly aligned and addressible.  Make valid. */
      v_off = addr & 0xFFFF;
      ((UInt*)(sm->vbyte))[ v_off >> 2 ] = VGM_WORD_VALID;
      return;
     slow4:
      fpu_write_check_SLOWLY ( addr, 4 );
      return;
   }

   if (size == 8) {
      if (!IS_ALIGNED4_ADDR(addr)) goto slow8;
      PROF_EVENT(87);
      /* Properly aligned.  Do it in two halves. */
      addr4 = addr + 4;
      /* First half. */
      sm     = primary_map[addr >> 16];
      sm_off = addr & 0xFFFF;
      a_off  = sm_off >> 3;
      if (sm->abits[a_off] != VGM_BYTE_VALID) goto slow8;
      /* First half properly aligned and addressible.  Make valid. */
      v_off = addr & 0xFFFF;
      ((UInt*)(sm->vbyte))[ v_off >> 2 ] = VGM_WORD_VALID;
      /* Second half. */
      sm     = primary_map[addr4 >> 16];
      sm_off = addr4 & 0xFFFF;
      a_off  = sm_off >> 3;
      if (sm->abits[a_off] != VGM_BYTE_VALID) goto slow8;
      /* Second half properly aligned and addressible. */
      v_off = addr4 & 0xFFFF;
      ((UInt*)(sm->vbyte))[ v_off >> 2 ] = VGM_WORD_VALID;
      /* Properly aligned, addressible and with valid data. */
      return;
     slow8:
      fpu_write_check_SLOWLY ( addr, 8 );
      return;
   }

   /* Can't be bothered to huff'n'puff to make these (allegedly) rare
      cases go quickly.  */
   if (size == 2) {
      PROF_EVENT(88);
      fpu_write_check_SLOWLY ( addr, 2 );
      return;
   }

   if (size == 10) {
      PROF_EVENT(89);
      fpu_write_check_SLOWLY ( addr, 10 );
      return;
   }

   if (size == 28) {
      PROF_EVENT(89); /* XXX assign correct event number */
      fpu_write_check_SLOWLY ( addr, 28 );
      return;
   }

   VG_(printf)("size is %d\n", size);
   VG_(panic)("vgmext_fpu_write_check: unhandled size");
#  endif
}


/* ---------------------------------------------------------------------
   Slow, general cases for FPU load and store checks.
   ------------------------------------------------------------------ */

/* Generic version.  Test for both addr and value errors, but if
   there's an addr error, don't report a value error even if it
   exists. */

void fpu_read_check_SLOWLY ( Addr addr, Int size )
{
   Int  i;
   Bool aerr = False;
   Bool verr = False;
   PROF_EVENT(90);
   for (i = 0; i < size; i++) {
      PROF_EVENT(91);
      if (get_abit(addr+i) != VGM_BIT_VALID)
         aerr = True;
      if (get_vbyte(addr+i) != VGM_BYTE_VALID)
         verr = True;
   }

   if (aerr) {
      SK_(record_address_error)( addr, size, False );
   } else {
     if (verr)
        SK_(record_value_error)( size );
   }
}


/* Generic version.  Test for addr errors.  Valid addresses are
   given valid values, and invalid addresses invalid values. */

void fpu_write_check_SLOWLY ( Addr addr, Int size )
{
   Int  i;
   Addr a_here;
   Bool a_ok;
   Bool aerr = False;
   PROF_EVENT(92);
   for (i = 0; i < size; i++) {
      PROF_EVENT(93);
      a_here = addr+i;
      a_ok = get_abit(a_here) == VGM_BIT_VALID;
      if (a_ok) {
	set_vbyte(a_here, VGM_BYTE_VALID);
      } else {
	set_vbyte(a_here, VGM_BYTE_INVALID);
        aerr = True;
      }
   }
   if (aerr) {
      SK_(record_address_error)( addr, size, True );
   }
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

/* Safely (avoiding SIGSEGV / SIGBUS) scan the entire valid address
   space and pass the addresses and values of all addressible,
   defined, aligned words to notify_word.  This is the basis for the
   leak detector.  Returns the number of calls made to notify_word.  */
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

   for (page = 0; page < numPages; page++) {
      pageBase = page << VKI_BYTES_PER_PAGE_BITS;
      primaryMapNo = pageBase >> 16;
      sm = primary_map[primaryMapNo];
      if (IS_DISTINGUISHED_SM(sm)) continue;
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

/* Globals, for the callback used by vg_detect_memory_leaks. */

static ShadowChunk** vglc_shadows;
static Int           vglc_n_shadows;
static Reachedness*  vglc_reachedness;
static Addr          vglc_min_mallocd_addr;
static Addr          vglc_max_mallocd_addr;

static 
void vg_detect_memory_leaks_notify_addr ( Addr a, UInt word_at_a )
{
   Int  sh_no;
   Addr ptr;

   /* Rule out some known causes of bogus pointers.  Mostly these do
      not cause much trouble because only a few false pointers can
      ever lurk in these places.  This mainly stops it reporting that
      blocks are still reachable in stupid test programs like this

         int main (void) { char* a = malloc(100); return 0; }

      which people seem inordinately fond of writing, for some reason.  

      Note that this is a complete kludge.  It would be better to
      ignore any addresses corresponding to valgrind.so's .bss and
      .data segments, but I cannot think of a reliable way to identify
      where the .bss segment has been put.  If you can, drop me a
      line.  
   */
   if (a >= ((Addr)(&VG_(stack)))
       && a <= ((Addr)(&VG_(stack))) + sizeof(VG_(stack))) {
      return;
   }
   if (a >= ((Addr)(&VG_(m_state_static)))
       && a <= ((Addr)(&VG_(m_state_static))) + sizeof(VG_(m_state_static))) {
      return;
   }
   if (a == (Addr)(&vglc_min_mallocd_addr))
      return;
   if (a == (Addr)(&vglc_max_mallocd_addr))
      return;

   /* OK, let's get on and do something Useful for a change. */

   ptr = (Addr)word_at_a;
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
            if (0) VG_(printf)("pointer at %p to %p\n", a, word_at_a );
            vglc_reachedness[sh_no] = Proper;
         } else {
            if (vglc_reachedness[sh_no] == Unreached)
               vglc_reachedness[sh_no] = Interior;
         }
      }
   }
}


void vg_detect_memory_leaks ( void )
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
         VG_(panic)("vg_detect_memory_leaks: "
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
   VG_(message)(Vg_UserMsg, "   definitely lost: %d bytes in %d blocks.", 
                            bytes_leaked, blocks_leaked );
   VG_(message)(Vg_UserMsg, "   possibly lost:   %d bytes in %d blocks.", 
                            bytes_dubious, blocks_dubious );
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

Bool SKN_(cheap_sanity_check) ( void )
{
   if (IS_DISTINGUISHED_SM(primary_map[0])
       && IS_DISTINGUISHED_SM(primary_map[65535]))
      return True;
   else
      return False;
}

void SKN_(expensive_sanity_check) ( void )
{
   Int i;

   /* Make sure nobody changed the distinguished secondary. */
   for (i = 0; i < 8192; i++)
      vg_assert(distinguished_secondary_map.abits[i] == VGM_BYTE_INVALID);
   for (i = 0; i < 65536; i++)
      vg_assert(distinguished_secondary_map.vbyte[i] == VGM_BYTE_INVALID);

   /* Make sure that the upper 3/4 of the primary map hasn't
      been messed with. */
   for (i = 65536; i < 262144; i++)
      vg_assert(primary_map[i] == & distinguished_secondary_map);
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

void vg_show_reg_tags ( void )
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
   vg_show_reg_tags( &VG_(m_shadow );
   VG_(translate) ( eip_next, NULL, NULL, NULL );
}
#endif /* 0 */

/*------------------------------------------------------------*/
/*--- Syscall wrappers                                     ---*/
/*------------------------------------------------------------*/

void* SKN_(pre_syscall)  ( ThreadId tid )
{
   Int sane = SKN_(cheap_sanity_check)();
   return (void*)sane;
}

void  SKN_(post_syscall) ( ThreadId tid, UInt syscallno,
                           void* pre_result, Int res )
{
   Int  sane_before_call = (Int)pre_result;
   Bool sane_after_call  = SKN_(cheap_sanity_check)();

   if ((Int)sane_before_call && (!sane_after_call)) {
      VG_(message)(Vg_DebugMsg, "post_syscall: ");
      VG_(message)(Vg_DebugMsg,
                   "probable sanity check failure for syscall number %d\n",
                   syscallno );
      VG_(panic)("aborting due to the above ... bye!");
   }
}

void* SKN_(pre_check_known_blocking_syscall)
          ( ThreadId tid, Int syscallno, Int* res )
{
   return SKN_(pre_syscall) ( tid );
}

void  SKN_(post_check_known_blocking_syscall)
          ( ThreadId tid, Int syscallno, void* pre_result, Int* res )
{
   Int  sane_before_call = (Int)pre_result;
   Bool sane_after_call = SKN_(cheap_sanity_check)();

   if ((Int)sane_before_call && (!sane_after_call)) {
      VG_(message)(Vg_DebugMsg, "post_check_known_blocking_syscall: ");
      VG_(message)(Vg_DebugMsg,
                   "probable sanity check failure for syscall number %d\n",
                   syscallno );
      VG_(panic)("aborting due to the above ... bye!");
   }
}


/*------------------------------------------------------------*/
/*--- MemCheck-specific client requests                    ---*/
/*------------------------------------------------------------*/

UInt SKN_(handle_client_request) ( ThreadState* tst, UInt* arg)
{
   Bool  ok;
   Addr  bad_addr;

   switch (arg[0]) {

// SSS: this is all screwed up, because of the client blocks...
      case VG_USERREQ__CHECK_WRITABLE: /* check writable */
         ok = check_writable ( arg[1], arg[2], &bad_addr );
         if (!ok)
            SK_(record_user_error) ( tst, bad_addr, /*isWrite=*/True );
         return ok ? (UInt)NULL : bad_addr;

      case VG_USERREQ__CHECK_READABLE: /* check readable */
         ok = check_readable ( arg[1], arg[2], &bad_addr );
         if (!ok)
            SK_(record_user_error) ( tst, bad_addr, /*isWrite=*/False );
         return ok ? (UInt)NULL : bad_addr;

      case VG_USERREQ__DO_LEAK_CHECK:
         vg_detect_memory_leaks();
         return 0; /* return value is meaningless */

      default:
         VG_(printf)("\nError:\n"
                     "  unknown MemCheck client request: 0x%x\n", arg[0]);
         VG_(panic)("SKN_(handle_client_request) unknown request");
   }
}

/*------------------------------------------------------------*/
/*--- Stuff (SSS: rename, reorder)                         ---*/
/*------------------------------------------------------------*/

static
void check_is_writable ( CorePart part, ThreadState* tst,
                         Char* s, UInt base, UInt size )
{
   Bool ok;
   Addr bad_addr;
   /* VG_(message)(Vg_DebugMsg,"check is writable: %x .. %x",
                               base,base+size-1); */
   ok = check_writable ( base, size, &bad_addr );
   if (!ok) {
      // SSS: fill in other cases
      switch (part) {
      case Vg_CoreSysCall:
         SK_(record_param_error) ( tst, bad_addr, /*isWrite =*/True, s );
         break;

      case Vg_CorePThread:
         SK_(record_pthread_mem_error)( tst, /*isWrite=*/True, s );
         break;

      default:
         VG_(panic)("check_is_readable: Unknown or unexpected CorePart");
      }
   }
}

static
void check_is_readable ( CorePart part, ThreadState* tst,
                         Char* s, UInt base, UInt size )
{     
   Bool ok;
   Addr bad_addr;
   /* VG_(message)(Vg_DebugMsg,"check is readable: %x .. %x",
                               base,base+size-1); */
   ok = check_readable ( base, size, &bad_addr );
   if (!ok) {
      switch (part) {
      case Vg_CoreSysCall:
         SK_(record_param_error) ( tst, bad_addr, /*isWrite =*/False, s );
         break;
      
      case Vg_CorePThread:
         SK_(record_pthread_mem_error)( tst, /*isWrite=*/False, s );
         break;

      /* If we're being asked to jump to a silly address, record an error 
         message before potentially crashing the entire system. */
      case Vg_CoreTranslate:
         SK_(record_jump_error)( tst, bad_addr );
         break;

      default:
         VG_(panic)("check_is_readable: Unknown or unexpected CorePart");
      }
   }
}

static
void check_is_readable_asciiz ( CorePart part, ThreadState* tst,
                                Char* s, UInt str )
{
   Bool ok = True;
   Addr bad_addr;
   /* VG_(message)(Vg_DebugMsg,"check is readable asciiz: 0x%x",str); */

   vg_assert(part == Vg_CoreSysCall);
   ok = check_readable_asciiz ( (Addr)str, &bad_addr );
   if (!ok) {
      SK_(record_param_error) ( tst, bad_addr, /*is_writable =*/False, s );
   }
}


/*------------------------------------------------------------*/
/*--- Setup                                                ---*/
/*------------------------------------------------------------*/

void SK_(setup)(VgNeeds* needs, VgTrackEvents* track)
{
   needs->name                    = "valgrind";
   needs->description             = "a memory error detector";

   needs->record_mem_exe_context  = True;
   needs->postpone_mem_reuse      = True;
   
   needs->debug_info              = Vg_DebugImprecise;
   needs->precise_x86_instr_sizes = False;
   needs->pthread_errors          = True;
   needs->report_errors           = True;

   needs->identifies_basic_blocks = False;

   needs->run_libc_freeres        = True;

   needs->command_line_options    = False;  // SSS: will be true eventually
   needs->client_requests         = True;

   needs->extends_UCode           = True;

   needs->wrap_syscalls           = True;

   needs->sanity_checks           = True;

   VG_(register_compact_helper)((Addr) & SK_(helper_value_check4_fail));
   VG_(register_compact_helper)((Addr) & SK_(helper_value_check0_fail));
   VG_(register_compact_helper)((Addr) & SK_(helperc_STOREV4));
   VG_(register_compact_helper)((Addr) & SK_(helperc_STOREV1));
   VG_(register_compact_helper)((Addr) & SK_(helperc_LOADV4));
   VG_(register_compact_helper)((Addr) & SK_(helperc_LOADV1));

   /* These two made non-compact because 2-byte transactions are rare. */
   VG_(register_noncompact_helper)((Addr) & SK_(helperc_STOREV2));
   VG_(register_noncompact_helper)((Addr) & SK_(helperc_LOADV2));
   VG_(register_noncompact_helper)((Addr) & SK_(fpu_write_check));
   VG_(register_noncompact_helper)((Addr) & SK_(fpu_read_check));
   VG_(register_noncompact_helper)((Addr) & SK_(helper_value_check2_fail));
   VG_(register_noncompact_helper)((Addr) & SK_(helper_value_check1_fail));

   /* Events to track */
   track->new_mem_startup       = & memcheck_new_mem_startup;
   track->new_mem_heap          = & memcheck_new_mem_heap;
   track->new_mem_stack         = & make_writable;
   track->new_mem_stack_aligned = & make_writable_aligned;
   track->new_mem_brk           = & make_writable;
   track->new_mem_mmap          = & memcheck_set_perms;
   
   track->copy_mem_heap         = & copy_address_range_state;
   track->change_mem_mprotect   = & memcheck_set_perms;
      
   track->ban_mem_heap          = & make_noaccess;

   track->die_mem_heap          = & memcheck_die_mem_heap;
   track->die_mem_stack         = & make_noaccess;
   track->die_mem_stack_aligned = & make_noaccess_aligned; 
   track->die_mem_stack_thread  = & make_noaccess;
   track->die_mem_brk           = & make_noaccess;
   track->die_mem_munmap        = & make_noaccess; 
   track->die_mem_pthread       = & make_noaccess;
   track->die_mem_signal        = & make_noaccess; 

   track->pre_mem_read          = & check_is_readable;
   track->pre_mem_read_asciiz   = & check_is_readable_asciiz;
   track->pre_mem_write         = & check_is_writable;
   track->post_mem_write        = & make_readable;
}

/*--------------------------------------------------------------------*/
/*--- end                                            vg_memcheck.c ---*/
/*--------------------------------------------------------------------*/
