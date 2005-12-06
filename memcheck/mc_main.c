
/*--------------------------------------------------------------------*/
/*--- MemCheck: Maintain bitmaps of memory, tracking the           ---*/
/*--- accessibility (A) and validity (V) status of each byte.      ---*/
/*---                                                    mc_main.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of MemCheck, a heavyweight Valgrind tool for
   detecting memory errors.

   Copyright (C) 2000-2005 Julian Seward 
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

   The GNU General Public License is contained in the file COPYING.
*/

/* TODO 22 Apr 05

   test whether it would be faster, for LOADV4, to check
   only for 8-byte validity on the fast path
*/

#include "pub_tool_basics.h"
#include "pub_tool_aspacemgr.h"
#include "pub_tool_errormgr.h"      // For mac_shared.h
#include "pub_tool_execontext.h"    // For mac_shared.h
#include "pub_tool_hashtable.h"     // For mac_shared.h
#include "pub_tool_libcbase.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_machine.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_options.h"
#include "pub_tool_oset.h"
#include "pub_tool_profile.h"       // For mac_shared.h
#include "pub_tool_replacemalloc.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_threadstate.h"

#include "mc_include.h"
#include "memcheck.h"   /* for client requests */

// XXX: introduce PM_OFF macro

#define EXPECTED_TAKEN(cond)     __builtin_expect((cond),1)
#define EXPECTED_NOT_TAKEN(cond) __builtin_expect((cond),0)

/* Define to debug the mem audit system.  Set to:
      0  no debugging, fast cases are used
      1  some sanity checking, fast cases are used
      2  max sanity checking, only slow cases are used
*/
#define VG_DEBUG_MEMORY 0

#define DEBUG(fmt, args...) //VG_(printf)(fmt, ## args)


/*------------------------------------------------------------*/
/*--- Basic A/V bitmap representation.                     ---*/
/*------------------------------------------------------------*/

/* TODO: fix this comment */
//zz /* All reads and writes are checked against a memory map, which
//zz    records the state of all memory in the process.  The memory map is
//zz    organised like this:
//zz 
//zz    The top 16 bits of an address are used to index into a top-level
//zz    map table, containing 65536 entries.  Each entry is a pointer to a
//zz    second-level map, which records the accesibililty and validity
//zz    permissions for the 65536 bytes indexed by the lower 16 bits of the
//zz    address.  Each byte is represented by nine bits, one indicating
//zz    accessibility, the other eight validity.  So each second-level map
//zz    contains 73728 bytes.  This two-level arrangement conveniently
//zz    divides the 4G address space into 64k lumps, each size 64k bytes.
//zz 
//zz    All entries in the primary (top-level) map must point to a valid
//zz    secondary (second-level) map.  Since most of the 4G of address
//zz    space will not be in use -- ie, not mapped at all -- there is a
//zz    distinguished secondary map, which indicates 'not addressible and
//zz    not valid' writeable for all bytes.  Entries in the primary map for
//zz    which the entire 64k is not in use at all point at this
//zz    distinguished map.
//zz 
//zz    There are actually 4 distinguished secondaries.  These are used to
//zz    represent a memory range which is either not addressable (validity
//zz    doesn't matter), addressable+not valid, addressable+valid.
//zz */

/* --------------- Basic configuration --------------- */

/* Only change this.  N_PRIMARY_MAP *must* be a power of 2. */

#if VG_WORDSIZE == 4

/* cover the entire address space */
#  define N_PRIMARY_BITS  16

#else

/* Just handle the first 32G fast and the rest via auxiliary
   primaries. */
#  define N_PRIMARY_BITS  19

#endif


/* Do not change this. */
#define N_PRIMARY_MAP  ( ((UWord)1) << N_PRIMARY_BITS)

/* Do not change this. */
#define MAX_PRIMARY_ADDRESS (Addr)((((Addr)65536) * N_PRIMARY_MAP)-1)


/* --------------- Stats maps --------------- */

static Int   n_secmaps_issued   = 0;
static Int   n_secmaps_deissued = 0;
static ULong n_auxmap_searches  = 0;
static ULong n_auxmap_cmps      = 0;
static Int   n_sanity_cheap     = 0;
static Int   n_sanity_expensive = 0;


/* --------------- Secondary maps --------------- */

// Each byte of memory conceptually has an A bit, which indicates its
// addressability, and 8 V bits, which indicates its definedness.
//
// But because very few bytes are partially defined, we can use a nice
// compression scheme to reduce the size of shadow memory.  Each byte of
// memory has 2 bits which indicates its state (ie. V+A bits):
//
//   00:  noaccess (unaddressable but treated as fully defined)
//   01:  writable (addressable and fully undefined)
//   10:  readable (addressable and fully defined)
//   11:  other    (addressable and partially defined)
//
// In the "other" case, we use a secondary table to store the V bits.  Each
// entry in the table maps a byte address to its 8 V bits.
//
// We store the compressed V+A bits in 8-bit chunks, ie. the V+A bits for
// four bytes (32 bits) of memory are in each chunk.  Hence the name
// "vabits32".  This lets us get the V+A bits for four bytes at a time
// easily (without having to do any shifting and/or masking), and that is a
// very common operation.  (Note that although each vabits32 chunk
// represents 32 bits of memory, but is only 8 bits in size.)
// 
// XXX: something about endianness.  Storing 1st byte in bits 1..0, 2nd byte
// in bits 3..2, 3rd in 5..4, 4th in 7..6.  (Little endian?)
//
// But note that we don't compress the V bits stored in registers;  they
// need to be explicit to made the shadow operations possible.  Therefore
// when moving values between registers and memory we need to convert between
// the expanded in-register format and the compressed in-memory format.
// This isn't so difficult, it just requires careful attention in a few
// places.

#define MC_BITS8_NOACCESS     0x0      // 00b
#define MC_BITS8_WRITABLE     0x1      // 01b
#define MC_BITS8_READABLE     0x2      // 10b
#define MC_BITS8_OTHER        0x3      // 11b

#define MC_BITS16_NOACCESS    0x0      // 00_00b
#define MC_BITS16_WRITABLE    0x5      // 01_01b
#define MC_BITS16_READABLE    0xa      // 10_10b

#define MC_BITS32_NOACCESS    0x00     // 00_00_00_00b
#define MC_BITS32_WRITABLE    0x55     // 01_01_01_01b
#define MC_BITS32_READABLE    0xaa     // 10_10_10_10b

#define MC_BITS64_NOACCESS    0x0000   // 00_00_00_00b x 2
#define MC_BITS64_WRITABLE    0x5555   // 01_01_01_01b x 2
#define MC_BITS64_READABLE    0xaaaa   // 10_10_10_10b x 2


#define SM_CHUNKS             16384
#define SM_OFF(aaa)           (((aaa) & 0xffff) >> 2)
#define SM_OFF_64(aaa)        (((aaa) & 0xffff) >> 3)

static inline Addr start_of_this_sm ( Addr a ) {
   return (a & (~SM_MASK));
}
static inline Bool is_start_of_sm ( Addr a ) {
   return (start_of_this_sm(a) == a);
}

typedef 
   struct {
      UChar vabits32[SM_CHUNKS];
   }
   SecMap;

/* 3 distinguished secondary maps, one for no-access, one for
   accessible but undefined, and one for accessible and defined.
   Distinguished secondaries may never be modified.
*/
#define SM_DIST_NOACCESS   0
#define SM_DIST_WRITABLE   1
#define SM_DIST_READABLE   2

static SecMap sm_distinguished[3];

static inline Bool is_distinguished_sm ( SecMap* sm ) {
   return sm >= &sm_distinguished[0] && sm <= &sm_distinguished[2];
}

/* dist_sm points to one of our three distinguished secondaries.  Make
   a copy of it so that we can write to it.
*/
static SecMap* copy_for_writing ( SecMap* dist_sm )
{
   SecMap* new_sm;
   tl_assert(dist_sm == &sm_distinguished[0]
          || dist_sm == &sm_distinguished[1]
          || dist_sm == &sm_distinguished[2]);

   new_sm = VG_(am_shadow_alloc)(sizeof(SecMap));
   if (new_sm == NULL)
      VG_(out_of_memory_NORETURN)( "memcheck:allocate new SecMap", 
                                   sizeof(SecMap) );
   VG_(memcpy)(new_sm, dist_sm, sizeof(SecMap));
   n_secmaps_issued++;
   return new_sm;
}

/* --------------- Primary maps --------------- */

/* The main primary map.  This covers some initial part of the address
   space, addresses 0 .. (N_PRIMARY_MAP << 16)-1.  The rest of it is
   handled using the auxiliary primary map.  
*/
static SecMap* primary_map[N_PRIMARY_MAP];


/* An entry in the auxiliary primary map.  base must be a 64k-aligned
   value, and sm points at the relevant secondary map.  As with the
   main primary map, the secondary may be either a real secondary, or
   one of the three distinguished secondaries.
*/
typedef
   struct { 
      Addr    base;
      SecMap* sm;
   }
   AuxMapEnt;

/* An expanding array of AuxMapEnts. */
#define N_AUXMAPS 20000 /* HACK */
static AuxMapEnt  hacky_auxmaps[N_AUXMAPS];
static Int        auxmap_size = N_AUXMAPS;
static Int        auxmap_used = 0;
static AuxMapEnt* auxmap      = &hacky_auxmaps[0];


/* Find an entry in the auxiliary map.  If an entry is found, move it
   one step closer to the front of the array, then return its address.
   If an entry is not found, return NULL.  Note carefully that
   because a each call potentially rearranges the entries, each call
   to this function invalidates ALL AuxMapEnt*s previously obtained by
   calling this fn.  
*/
static AuxMapEnt* maybe_find_in_auxmap ( Addr a )
{
   UWord i;
   tl_assert(a > MAX_PRIMARY_ADDRESS);

   a &= ~(Addr)0xFFFF;

   /* Search .. */
   n_auxmap_searches++;
   for (i = 0; i < auxmap_used; i++) {
      if (auxmap[i].base == a)
         break;
   }
   n_auxmap_cmps += (ULong)(i+1);

   if (i < auxmap_used) {
      /* Found it.  Nudge it a bit closer to the front. */
      if (i > 0) {
         AuxMapEnt tmp = auxmap[i-1];
         auxmap[i-1] = auxmap[i];
         auxmap[i] = tmp;
         i--;
      }
      return &auxmap[i];
   }

   return NULL;
}


/* Find an entry in the auxiliary map.  If an entry is found, move it
   one step closer to the front of the array, then return its address.
   If an entry is not found, allocate one.  Note carefully that
   because a each call potentially rearranges the entries, each call
   to this function invalidates ALL AuxMapEnt*s previously obtained by
   calling this fn.  
*/
static AuxMapEnt* find_or_alloc_in_auxmap ( Addr a )
{
   AuxMapEnt* am = maybe_find_in_auxmap(a);
   if (am)
      return am;

   /* We didn't find it.  Hmm.  This is a new piece of address space.
      We'll need to allocate a new AuxMap entry for it. */
   if (auxmap_used >= auxmap_size) {
      tl_assert(auxmap_used == auxmap_size);
      /* Out of auxmap entries. */
      tl_assert2(0, "failed to expand the auxmap table");
   }

   tl_assert(auxmap_used < auxmap_size);

   auxmap[auxmap_used].base = a & ~(Addr)0xFFFF;
   auxmap[auxmap_used].sm   = &sm_distinguished[SM_DIST_NOACCESS];

   if (0)
      VG_(printf)("new auxmap, base = 0x%llx\n", 
                  (ULong)auxmap[auxmap_used].base );

   auxmap_used++;
   return &auxmap[auxmap_used-1];
}


/* --------------- SecMap fundamentals --------------- */

/* Produce the secmap for 'a', either from the primary map or by
   ensuring there is an entry for it in the aux primary map.  The
   secmap may be a distinguished one as the caller will only want to
   be able to read it. 
*/
static SecMap* get_secmap_readable ( Addr a )
{
   if (a <= MAX_PRIMARY_ADDRESS) {
      UWord pm_off = a >> 16;
      return primary_map[ pm_off ];
   } else {
      AuxMapEnt* am = find_or_alloc_in_auxmap(a);
      return am->sm;
   }
}

/* If 'a' has a SecMap, produce it.  Else produce NULL.  But don't
   allocate one if one doesn't already exist.  This is used by the
   leak checker.
*/
static SecMap* maybe_get_secmap_for ( Addr a )
{
   if (a <= MAX_PRIMARY_ADDRESS) {
      UWord pm_off = a >> 16;
      return primary_map[ pm_off ];
   } else {
      AuxMapEnt* am = maybe_find_in_auxmap(a);
      return am ? am->sm : NULL;
   }
}



/* Produce the secmap for 'a', either from the primary map or by
   ensuring there is an entry for it in the aux primary map.  The
   secmap may not be a distinguished one, since the caller will want
   to be able to write it.  If it is a distinguished secondary, make a
   writable copy of it, install it, and return the copy instead.  (COW
   semantics).
*/
static SecMap* get_secmap_writable ( Addr a )
{
   if (a <= MAX_PRIMARY_ADDRESS) {
      UWord pm_off = a >> 16;
      if (is_distinguished_sm(primary_map[ pm_off ]))
         primary_map[pm_off] = copy_for_writing(primary_map[pm_off]);
      return primary_map[pm_off];
   } else {
      AuxMapEnt* am = find_or_alloc_in_auxmap(a);
      if (is_distinguished_sm(am->sm))
         am->sm = copy_for_writing(am->sm);
      return am->sm;
   }
}


/* --------------- Secondary V bit table ------------ */

// XXX: this table can hold out-of-date stuff.  Eg. write a partially
// defined byte, then overwrite it with a fully defined byte.  The info for
// the partially defined bytes will still be here.  But it shouldn't ever
// get accessed, I think...

// XXX: profile, esp. with Julian's random-ORing stress test.  Could maybe
// store in chunks up to a page size.

OSet* secVBitTable;

typedef 
   struct {
      Addr  a;
      UWord vbits8;
   } 
   SecVBitNode;

static UWord get_sec_vbits8(Addr a)
{
   SecVBitNode* n;
   n = VG_(OSet_Lookup)(secVBitTable, &a);
   tl_assert(n);
   // Shouldn't be fully defined or fully undefined -- those cases shouldn't
   // make it to the secondary V bits table.
   tl_assert(VGM_BYTE_VALID != n->vbits8 && VGM_BYTE_INVALID != n->vbits8 );
   return n->vbits8;
}

static void set_sec_vbits8(Addr a, UWord vbits8)
{
   SecVBitNode* n;
   n = VG_(OSet_Lookup)(secVBitTable, &a);
   // Shouldn't be fully defined or fully undefined -- those cases shouldn't
   // make it to the secondary V bits table.
   tl_assert(VGM_BYTE_VALID != vbits8 && VGM_BYTE_INVALID != vbits8 );
   if (n) {
      n->vbits8 = vbits8;  // update
   } else {
      n = VG_(OSet_AllocNode)(secVBitTable, sizeof(SecVBitNode));
      n->a      = a;
      n->vbits8 = vbits8;
      VG_(OSet_Insert)(secVBitTable, n);
   }
}


/* --------------- Endianness helpers --------------- */

/* Returns the offset in memory of the byteno-th most significant byte
   in a wordszB-sized word, given the specified endianness. */
static inline UWord byte_offset_w ( UWord wordszB, Bool bigendian, 
                                    UWord byteno ) {
   return bigendian ? (wordszB-1-byteno) : byteno;
}


/* --------------- Fundamental functions --------------- */

static inline
void insert_vabit8_into_vabits32 ( Addr a, UChar vabits8, UChar* vabits32 )
{
   UInt shift =  (a & 3)  << 1;        // shift by 0, 2, 4, or 6
   *vabits32 &= ~(0x3     << shift);   // mask out the two old bits
   *vabits32 |=  (vabits8 << shift);   // mask  in the two new bits
}

static inline
void insert_vabits16_into_vabits32 ( Addr a, UChar vabits16, UChar* vabits32 )
{
   UInt shift =  (a & 2)   << 1;       // shift by 0 or 4
   *vabits32 &= ~(0xf      << shift);  // mask out the four old bits
   *vabits32 |=  (vabits16 << shift);  // mask  in the four new bits
}

static inline
UChar extract_vabits8_from_vabits32 ( Addr a, UChar vabits32 )
{
   UInt shift = (a & 3) << 1;       // use (a % 4) for the offset
   vabits32 >>= shift;              // shift the two bits to the bottom
   return 0x3 & vabits32;           // mask out the rest
}

// Note that these two are only used in slow cases.  The fast cases do
// clever things like combine the auxmap check (in
// get_secmap_{read,writ}able) with alignment checks.

static inline
void set_vabits8 ( Addr a, UChar vabits8 )
{
   SecMap* sm       = get_secmap_writable(a);
   UWord   sm_off   = SM_OFF(a);
//   VG_(printf)("se:%p, %d\n", a, sm_off);
//   VG_(printf)("s1:%p (0x%x)\n", &(sm->vabits32[sm_off]), vabits8);
   insert_vabit8_into_vabits32( a, vabits8, &(sm->vabits32[sm_off]) );
//   VG_(printf)("s2: 0x%x\n", sm->vabits32[sm_off]);
}

static inline
UChar get_vabits8 ( Addr a )
{
   SecMap* sm       = get_secmap_readable(a);
   UWord   sm_off   = SM_OFF(a);
   UChar   vabits32 = sm->vabits32[sm_off];
   return extract_vabits8_from_vabits32(a, vabits32);
}


/* --------------- Load/store slow cases. --------------- */

static
ULong mc_LOADVn_slow ( Addr a, SizeT szB, Bool bigendian )
{
   /* Make up a result V word, which contains the loaded data for
      valid addresses and Defined for invalid addresses.  Iterate over
      the bytes in the word, from the most significant down to the
      least. */
   ULong vw          = VGM_WORD64_INVALID;
   SizeT i           = szB-1;
   SizeT n_addrs_bad = 0;
   Addr  ai;
   Bool  partial_load_exemption_applies;
   UWord vbyte, vabits8;

   PROF_EVENT(30, "mc_LOADVn_slow");
   tl_assert(szB == 8 || szB == 4 || szB == 2 || szB == 1);

   // XXX: change this to a for loop.  The loop var i must be signed.
   while (True) {
      PROF_EVENT(31, "mc_LOADVn_slow(loop)");
      ai = a+byte_offset_w(szB,bigendian,i);
      vabits8 = get_vabits8(ai);
      // Convert the in-memory format to in-register format.
      // XXX: We check in order of most likely to least likely...
      // XXX: could maybe have a little lookup table instead of these
      //      chained conditionals?  and elsewhere?
      if      ( MC_BITS8_READABLE == vabits8 ) { vbyte = VGM_BYTE_VALID;   }
      else if ( MC_BITS8_WRITABLE == vabits8 ) { vbyte = VGM_BYTE_INVALID; }
      else if ( MC_BITS8_NOACCESS == vabits8 ) {
         vbyte = VGM_BYTE_VALID;    // Make V bits defined!
         n_addrs_bad++;
      } else {
         tl_assert( MC_BITS8_OTHER == vabits8 );
         vbyte = get_sec_vbits8(ai);
      }
      vw <<= 8; 
      vw |= vbyte;
      if (i == 0) break;
      i--;
   }

   /* This is a hack which avoids producing errors for code which
      insists in stepping along byte strings in aligned word-sized
      chunks, and there is a partially defined word at the end.  (eg,
      optimised strlen).  Such code is basically broken at least WRT
      semantics of ANSI C, but sometimes users don't have the option
      to fix it, and so this option is provided.  Note it is now
      defaulted to not-engaged.

      A load from a partially-addressible place is allowed if:
      - the command-line flag is set
      - it's a word-sized, word-aligned load
      - at least one of the addresses in the word *is* valid
   */
   partial_load_exemption_applies
      = MAC_(clo_partial_loads_ok) && szB == VG_WORDSIZE 
                                   && VG_IS_WORD_ALIGNED(a) 
                                   && n_addrs_bad < VG_WORDSIZE;

   if (n_addrs_bad > 0 && !partial_load_exemption_applies)
      MAC_(record_address_error)( VG_(get_running_tid)(), a, szB, False );

   return vw;
}


static 
void mc_STOREVn_slow ( Addr a, SizeT szB, ULong vbytes, Bool bigendian )
{
   SizeT i, n_addrs_bad = 0;
   UWord vbyte, vabits8;
   Addr  ai;

   PROF_EVENT(35, "mc_STOREVn_slow");
   tl_assert(szB == 8 || szB == 4 || szB == 2 || szB == 1);

   /* Dump vbytes in memory, iterating from least to most significant
      byte.  At the same time establish addressibility of the
      location. */
   for (i = 0; i < szB; i++) {
      PROF_EVENT(36, "mc_STOREVn_slow(loop)");
      ai = a+byte_offset_w(szB,bigendian,i);
      vbyte = vbytes & 0xff;
      vabits8 = get_vabits8(ai);
      if ( MC_BITS8_NOACCESS != vabits8 ) {
         // Addressable.  Convert in-register format to in-memory format.
         if      ( VGM_BYTE_VALID   == vbyte ) { vabits8 = MC_BITS8_READABLE; }
         else if ( VGM_BYTE_INVALID == vbyte ) { vabits8 = MC_BITS8_WRITABLE; }
         else    { 
            vabits8 = MC_BITS8_OTHER;
            set_sec_vbits8(ai, vbyte);
         }
         set_vabits8(ai, vabits8);
      } else {
         // Unaddressable!  Do nothing -- when writing to unaddressable
         // memory it acts as a black hole, and the V bits can never be seen
         // again.  So we don't have to write them at all.
         n_addrs_bad++;
      }
      vbytes >>= 8;
   }

   /* If an address error has happened, report it. */
   if (n_addrs_bad > 0)
      MAC_(record_address_error)( VG_(get_running_tid)(), a, szB, True );
}


//zz /* Reading/writing of the bitmaps, for aligned word-sized accesses. */
//zz 
//zz static __inline__ UChar get_abits4_ALIGNED ( Addr a )
//zz {
//zz    SecMap* sm;
//zz    UInt    sm_off;
//zz    UChar   abits8;
//zz    PROF_EVENT(24);
//zz #  ifdef VG_DEBUG_MEMORY
//zz    tl_assert(VG_IS_4_ALIGNED(a));
//zz #  endif
//zz    sm     = primary_map[PM_IDX(a)];
//zz    sm_off = SM_OFF(a);
//zz    abits8 = sm->abits[sm_off >> 3];
//zz    abits8 >>= (a & 4 /* 100b */);   /* a & 4 is either 0 or 4 */
//zz    abits8 &= 0x0F;
//zz    return abits8;
//zz }
//zz 
//zz static UInt __inline__ get_vbytes4_ALIGNED ( Addr a )
//zz {
//zz    SecMap* sm     = primary_map[PM_IDX(a)];
//zz    UInt    sm_off = SM_OFF(a);
//zz    PROF_EVENT(25);
//zz #  ifdef VG_DEBUG_MEMORY
//zz    tl_assert(VG_IS_4_ALIGNED(a));
//zz #  endif
//zz    return ((UInt*)(sm->vbyte))[sm_off >> 2];
//zz }
//zz 
//zz 
//zz static void __inline__ set_vbytes4_ALIGNED ( Addr a, UInt vbytes )
//zz {
//zz    SecMap* sm;
//zz    UInt    sm_off;
//zz    ENSURE_MAPPABLE(a, "set_vbytes4_ALIGNED");
//zz    sm     = primary_map[PM_IDX(a)];
//zz    sm_off = SM_OFF(a);
//zz    PROF_EVENT(23);
//zz #  ifdef VG_DEBUG_MEMORY
//zz    tl_assert(VG_IS_4_ALIGNED(a));
//zz #  endif
//zz    ((UInt*)(sm->vbyte))[sm_off >> 2] = vbytes;
//zz }


/*------------------------------------------------------------*/
/*--- Setting permissions over address ranges.             ---*/
/*------------------------------------------------------------*/

/* Given address 'a', find the place where the pointer to a's
   secondary map lives.  If a falls into the primary map, the returned
   value points to one of the entries in primary_map[].  Otherwise,
   the auxiliary primary map is searched for 'a', or an entry is
   created for it; either way, the returned value points to the
   relevant AuxMapEnt's .sm field.

   The point of this is to enable set_address_range_perms to assign
   secondary maps in a uniform way, without worrying about whether a
   given secondary map is pointed to from the main or auxiliary
   primary map.  
*/

static SecMap** find_secmap_binder_for_addr ( Addr aA )
{
   if (aA > MAX_PRIMARY_ADDRESS) {
      AuxMapEnt* am = find_or_alloc_in_auxmap(aA);
      return &am->sm;
   } else {
      UWord a      = (UWord)aA;
      UWord sec_no = (UWord)(a >> 16);
#     if VG_DEBUG_MEMORY >= 1
      tl_assert(sec_no < N_PRIMARY_MAP);
#     endif
      return &primary_map[sec_no];
   }
}

static void set_address_range_perms ( Addr a, SizeT lenT, UWord vabits64,
                                      UWord dsm_num )
{
   UWord    vabits8, sm_off, sm_off64;
   SizeT    lenA, lenB, len_to_next_secmap;
   Addr     aNext;
   SecMap*  sm;
   SecMap** binder;
   SecMap*  example_dsm;

   PROF_EVENT(150, "set_address_range_perms");

   /* Check the V+A bits make sense. */
   tl_assert(vabits64 == MC_BITS64_NOACCESS ||
             vabits64 == MC_BITS64_WRITABLE ||
             vabits64 == MC_BITS64_READABLE);

   if (lenT == 0)
      return;

   if (lenT > 100 * 1000 * 1000) {
      if (VG_(clo_verbosity) > 0 && !VG_(clo_xml)) {
         Char* s = "unknown???";
         if (vabits64 == MC_BITS64_NOACCESS) s = "noaccess";
         if (vabits64 == MC_BITS64_WRITABLE) s = "writable";
         if (vabits64 == MC_BITS64_READABLE) s = "readable";
         VG_(message)(Vg_UserMsg, "Warning: set address range perms: "
                                  "large range %lu (%s)", lenT, s);
      }
   }

#  if VG_DEBUG_MEMORY >= 2
   /*------------------ debug-only case ------------------ */
   {
      UWord vabits8 = vabits64 & 0x3;
      SizeT i;
      for (i = 0; i < lenT; i++) {
         set_vabits8(aA + i, vabits8);
      }
      return;
   }
#  endif

   /*------------------ standard handling ------------------ */

   /* Get the distinguished secondary that we might want
      to use (part of the space-compression scheme). */
   example_dsm = &sm_distinguished[dsm_num];

   vabits8 = vabits64 & 0x3;
   
   // We have to handle ranges covering various combinations of partial and
   // whole sec-maps.  Here is how parts 1, 2 and 3 are used in each case.
   // Cases marked with a '*' are common.
   //
   //   TYPE                                             PARTS USED
   //   ----                                             ----------
   // * one partial sec-map                  (p)         1
   // - one whole sec-map                    (P)         2
   //
   // * two partial sec-maps                 (pp)        1,3 
   // - one partial, one whole sec-map       (pP)        1,2
   // - one whole, one partial sec-map       (Pp)        2,3
   // - two whole sec-maps                   (PP)        2,2
   //
   // * one partial, one whole, one partial  (pPp)       1,2,3
   // - one partial, two whole               (pPP)       1,2,2
   // - two whole, one partial               (PPp)       2,2,3
   // - three whole                          (PPP)       2,2,2
   //
   // * one partial, N-2 whole, one partial  (pP...Pp)   1,2...2,3
   // - one partial, N-1 whole               (pP...PP)   1,2...2,2
   // - N-1 whole, one partial               (PP...Pp)   2,2...2,3
   // - N whole                              (PP...PP)   2,2...2,3

   // Break up total length (lenT) into two parts:  length in the first
   // sec-map (lenA), and the rest (lenB);   lenT == lenA + lenB.
   aNext = start_of_this_sm(a) + SM_SIZE;
   len_to_next_secmap = aNext - a;
   if ( lenT <= len_to_next_secmap ) {
      // Range entirely within one sec-map.  Covers almost all cases.
      PROF_EVENT(151, "set_address_range_perms-single-secmap");
      lenA = lenT;
      lenB = 0;
   } else if (is_start_of_sm(a)) {
      // Range spans at least one whole sec-map, and starts at the beginning
      // of a sec-map; skip to Part 2.
      PROF_EVENT(152, "set_address_range_perms-startof-secmap");
      lenA = 0;
      lenB = lenT;
      goto part2;
   } else {
      // Range spans two or more sec-maps, first one is partial.
      PROF_EVENT(153, "set_address_range_perms-multiple-secmaps");
      lenA = len_to_next_secmap;
      lenB = lenT - lenA;
   }

   //------------------------------------------------------------------------
   // Part 1: Deal with the first sec_map.  Most of the time the range will be
   // entirely within a sec_map and this part alone will suffice.  Also,
   // doing it this way lets us avoid repeatedly testing for the crossing of
   // a sec-map boundary within these loops.
   //------------------------------------------------------------------------

   // If it's distinguished, make it undistinguished if necessary.
   binder = find_secmap_binder_for_addr(a);
   if (is_distinguished_sm(*binder)) {
      if (*binder == example_dsm) {
         // Sec-map already has the V+A bits that we want, so skip.
         PROF_EVENT(154, "set_address_range_perms-dist-sm1-quick");
         a    = aNext;
         lenA = 0;
      } else {
         PROF_EVENT(155, "set_address_range_perms-dist-sm1");
         *binder = copy_for_writing(*binder);
      }
   }
   sm = *binder;

   // 1 byte steps
   while (True) {
      if (VG_IS_8_ALIGNED(a)) break;
      if (lenA < 1)           break;
      PROF_EVENT(156, "set_address_range_perms-loop1a");
      sm_off = SM_OFF(a);
      insert_vabit8_into_vabits32( a, vabits8, &(sm->vabits32[sm_off]) );
      a    += 1;
      lenA -= 1;
   }
   // 8-aligned, 8 byte steps
   while (True) {
      if (lenA < 8) break;
      PROF_EVENT(157, "set_address_range_perms-loop8a");
      sm_off64 = SM_OFF_64(a);
      ((UShort*)(sm->vabits32))[sm_off64] = vabits64;
      a    += 8;
      lenA -= 8;
   }
   // 1 byte steps
   while (True) {
      if (lenA < 1) break;
      PROF_EVENT(158, "set_address_range_perms-loop1b");
      sm_off = SM_OFF(a);
      insert_vabit8_into_vabits32( a, vabits8, &(sm->vabits32[sm_off]) );
      a    += 1;
      lenA -= 1;
   }

   // We've finished the first sec-map.  Is that it?
   if (lenB == 0)
      return;

   //------------------------------------------------------------------------
   // Part 2: Fast-set entire sec-maps at a time.
   //------------------------------------------------------------------------
  part2:
   // 64KB-aligned, 64KB steps.
   // Nb: we can reach here with lenB < SM_SIZE
   while (True) {
      if (lenB < SM_SIZE) break;
      tl_assert(is_start_of_sm(a));
      PROF_EVENT(159, "set_address_range_perms-loop64K");
      binder = find_secmap_binder_for_addr(a);
      if (!is_distinguished_sm(*binder)) {
         PROF_EVENT(160, "set_address_range_perms-loop64K-free-dist-sm");
         // Free the non-distinguished sec-map that we're replacing.  This
         // case happens moderately often, enough to be worthwhile.
         VG_(am_munmap_valgrind)((Addr)*binder, sizeof(SecMap));
         n_secmaps_deissued++;      // Needed for the expensive sanity check
      }
      // Make the sec-map entry point to the example DSM
      *binder = example_dsm;
      lenB -= SM_SIZE;
      a    += SM_SIZE;
   }

   // We've finished the whole sec-maps.  Is that it?
   if (lenB == 0)
      return;

   //------------------------------------------------------------------------
   // Part 3: Finish off the final partial sec-map, if necessary.
   //------------------------------------------------------------------------

   tl_assert(is_start_of_sm(a) && lenB < SM_SIZE);

   // If it's distinguished, make it undistinguished if necessary.
   binder = find_secmap_binder_for_addr(a);
   if (is_distinguished_sm(*binder)) {
      if (*binder == example_dsm) {
         // Sec-map already has the V+A bits that we want, so stop.
         PROF_EVENT(161, "set_address_range_perms-dist-sm2-quick");
         return;
      } else {
         PROF_EVENT(162, "set_address_range_perms-dist-sm2");
         *binder = copy_for_writing(*binder);
      }
   }
   sm = *binder;

   // 8-aligned, 8 byte steps
   while (True) {
      if (lenB < 8) break;
      PROF_EVENT(163, "set_address_range_perms-loop8b");
      sm_off64 = SM_OFF_64(a);
      ((UShort*)(sm->vabits32))[sm_off64] = vabits64;
      a    += 8;
      lenB -= 8;
   }
   // 1 byte steps
   while (True) {
      if (lenB < 1) return;
      PROF_EVENT(164, "set_address_range_perms-loop1c");
      sm_off = SM_OFF(a);
      insert_vabit8_into_vabits32( a, vabits8, &(sm->vabits32[sm_off]) );
      a    += 1;
      lenB -= 1;
   }
}


/* --- Set permissions for arbitrary address ranges --- */

static void mc_make_noaccess ( Addr a, SizeT len )
{
   PROF_EVENT(40, "mc_make_noaccess");
   DEBUG("mc_make_noaccess(%p, %lu)\n", a, len);
   set_address_range_perms ( a, len, MC_BITS64_NOACCESS, SM_DIST_NOACCESS );
}

static void mc_make_writable ( Addr a, SizeT len )
{
   PROF_EVENT(41, "mc_make_writable");
   DEBUG("mc_make_writable(%p, %lu)\n", a, len);
   set_address_range_perms ( a, len, MC_BITS64_WRITABLE, SM_DIST_WRITABLE );
}

static void mc_make_readable ( Addr a, SizeT len )
{
   PROF_EVENT(42, "mc_make_readable");
   DEBUG("mc_make_readable(%p, %lu)\n", a, len);
   set_address_range_perms ( a, len, MC_BITS64_READABLE, SM_DIST_READABLE );
}


/* --- Block-copy permissions (needed for implementing realloc() and
       sys_mremap). --- */

static void mc_copy_address_range_state ( Addr src, Addr dst, SizeT len )
{
   SizeT i, j;

   DEBUG("mc_copy_address_range_state\n");
   PROF_EVENT(50, "mc_copy_address_range_state");

   if (len == 0)
      return;

   if (src < dst) {
      for (i = 0, j = len-1; i < len; i++, j--) {
         PROF_EVENT(51, "mc_copy_address_range_state(loop)");
         set_vabits8( dst+j, get_vabits8( src+j ) );
      }
   }

   if (src > dst) {
      for (i = 0; i < len; i++) {
         PROF_EVENT(51, "mc_copy_address_range_state(loop)");
         set_vabits8( dst+i, get_vabits8( src+i ) );
      }
   }
}


/* --- Fast case permission setters, for dealing with stacks. --- */

static __inline__
void make_aligned_word32_writable ( Addr a )
{
   UWord   sec_no, sm_off;
   SecMap* sm;

   PROF_EVENT(300, "make_aligned_word32_writable");

#  if VG_DEBUG_MEMORY >= 2
   mc_make_writable(a, 4);
   return;
#  endif

   if (EXPECTED_NOT_TAKEN(a > MAX_PRIMARY_ADDRESS)) {
      PROF_EVENT(301, "make_aligned_word32_writable-slow1");
      mc_make_writable(a, 4);
      return;
   }

   sec_no = (UWord)(a >> 16);
#  if VG_DEBUG_MEMORY >= 1
   tl_assert(sec_no < N_PRIMARY_MAP);
#  endif

   // XXX: This is basically what get_secmap_writable is doing.
   if (EXPECTED_NOT_TAKEN(is_distinguished_sm(primary_map[sec_no])))
      primary_map[sec_no] = copy_for_writing(primary_map[sec_no]);

   sm                   = primary_map[sec_no];
   sm_off               = SM_OFF(a);
   sm->vabits32[sm_off] = MC_BITS32_WRITABLE;
}


// XXX: can surely merge this somehow with make_aligned_word32_writable
static __inline__
void make_aligned_word32_noaccess ( Addr a )
{
   UWord   sec_no, sm_off;
   SecMap* sm;

   PROF_EVENT(310, "make_aligned_word32_noaccess");

#  if VG_DEBUG_MEMORY >= 2
   mc_make_noaccess(a, 4);
   return;
#  endif

   if (EXPECTED_NOT_TAKEN(a > MAX_PRIMARY_ADDRESS)) {
      PROF_EVENT(311, "make_aligned_word32_noaccess-slow1");
      mc_make_noaccess(a, 4);
      return;
   }

   sec_no = (UWord)(a >> 16);
#  if VG_DEBUG_MEMORY >= 1
   tl_assert(sec_no < N_PRIMARY_MAP);
#  endif

   // XXX: This is basically what get_secmap_writable is doing.
   if (EXPECTED_NOT_TAKEN(is_distinguished_sm(primary_map[sec_no])))
      primary_map[sec_no] = copy_for_writing(primary_map[sec_no]);

   sm                   = primary_map[sec_no];
   sm_off               = SM_OFF(a);
   sm->vabits32[sm_off] = MC_BITS32_NOACCESS;
}


/* Nb: by "aligned" here we mean 8-byte aligned */
static __inline__
void make_aligned_word64_writable ( Addr a )
{
   UWord   sec_no, sm_off;
   SecMap* sm;

   PROF_EVENT(320, "make_aligned_word64_writable");

#  if VG_DEBUG_MEMORY >= 2
   mc_make_writable(a, 8);
   return;
#  endif

   if (EXPECTED_NOT_TAKEN(a > MAX_PRIMARY_ADDRESS)) {
      PROF_EVENT(321, "make_aligned_word64_writable-slow1");
      mc_make_writable(a, 8);
      return;
   }

   sec_no = (UWord)(a >> 16);
#  if VG_DEBUG_MEMORY >= 1
   tl_assert(sec_no < N_PRIMARY_MAP);
#  endif

   if (EXPECTED_NOT_TAKEN(is_distinguished_sm(primary_map[sec_no])))
      primary_map[sec_no] = copy_for_writing(primary_map[sec_no]);

   sm     = primary_map[sec_no];
   sm_off = SM_OFF(a);
   sm->vabits32[sm_off+0] = MC_BITS32_WRITABLE;
   sm->vabits32[sm_off+1] = MC_BITS32_WRITABLE;
}


static __inline__
void make_aligned_word64_noaccess ( Addr a )
{
   UWord   sec_no, sm_off;
   SecMap* sm;

   PROF_EVENT(330, "make_aligned_word64_noaccess");

#  if VG_DEBUG_MEMORY >= 2
   mc_make_noaccess(a, 8);
   return;
#  endif

   if (EXPECTED_NOT_TAKEN(a > MAX_PRIMARY_ADDRESS)) {
      PROF_EVENT(331, "make_aligned_word64_noaccess-slow1");
      mc_make_noaccess(a, 8);
      return;
   }

   sec_no = (UWord)(a >> 16);
#  if VG_DEBUG_MEMORY >= 1
   tl_assert(sec_no < N_PRIMARY_MAP);
#  endif

   if (EXPECTED_NOT_TAKEN(is_distinguished_sm(primary_map[sec_no])))
      primary_map[sec_no] = copy_for_writing(primary_map[sec_no]);

   sm     = primary_map[sec_no];
   sm_off = SM_OFF(a);
   sm->vabits32[sm_off+0] = MC_BITS32_NOACCESS;
   sm->vabits32[sm_off+1] = MC_BITS32_NOACCESS;
}


/* The stack-pointer update handling functions */
SP_UPDATE_HANDLERS ( make_aligned_word32_writable,
                     make_aligned_word32_noaccess,
                     make_aligned_word64_writable,
                     make_aligned_word64_noaccess,
                     mc_make_writable,
                     mc_make_noaccess 
                   );


/* The AMD64 ABI says:

   "The 128-byte area beyond the location pointed to by %rsp is considered
    to be reserved and shall not be modified by signal or interrupt
    handlers.  Therefore, functions may use this area for temporary data
    that is not needed across function calls.  In particular, leaf functions
    may use this area for their entire stack frame, rather than adjusting
    the stack pointer in the prologue and epilogue.  This area is known as
    red zone [sic]."

   So after any call or return we need to mark this redzone as containing
   undefined values.

   Consider this:  we're in function f.  f calls g.  g moves rsp down
   modestly (say 16 bytes) and writes stuff all over the red zone, making it
   defined.  g returns.  f is buggy and reads from parts of the red zone
   that it didn't write on.  But because g filled that area in, f is going
   to be picking up defined V bits and so any errors from reading bits of
   the red zone it didn't write, will be missed.  The only solution I could
   think of was to make the red zone undefined when g returns to f.

   This is in accordance with the ABI, which makes it clear the redzone
   is volatile across function calls.

   The problem occurs the other way round too: f could fill the RZ up
   with defined values and g could mistakenly read them.  So the RZ
   also needs to be nuked on function calls.
*/
void MC_(helperc_MAKE_STACK_UNINIT) ( Addr base, UWord len )
{
   tl_assert(sizeof(UWord) == sizeof(SizeT));
   if (0)
      VG_(printf)("helperc_MAKE_STACK_UNINIT %p %d\n", base, len );

#  if 0
   /* Really slow version */
   mc_make_writable(base, len);
#  endif

#  if 0
   /* Slow(ish) version, which is fairly easily seen to be correct.
   */
   if (EXPECTED_TAKEN( VG_IS_8_ALIGNED(base) && len==128 )) {
      make_aligned_word64_writable(base +   0);
      make_aligned_word64_writable(base +   8);
      make_aligned_word64_writable(base +  16);
      make_aligned_word64_writable(base +  24);

      make_aligned_word64_writable(base +  32);
      make_aligned_word64_writable(base +  40);
      make_aligned_word64_writable(base +  48);
      make_aligned_word64_writable(base +  56);

      make_aligned_word64_writable(base +  64);
      make_aligned_word64_writable(base +  72);
      make_aligned_word64_writable(base +  80);
      make_aligned_word64_writable(base +  88);

      make_aligned_word64_writable(base +  96);
      make_aligned_word64_writable(base + 104);
      make_aligned_word64_writable(base + 112);
      make_aligned_word64_writable(base + 120);
   } else {
      mc_make_writable(base, len);
   }
#  endif 

   /* Idea is: go fast when
         * 8-aligned and length is 128
         * the sm is available in the main primary map
         * the address range falls entirely with a single
           secondary map
         * the SM is modifiable
      If all those conditions hold, just update the V+A bits
      by writing directly into the vabits array.   
   */
   if (EXPECTED_TAKEN( len == 128
                       && VG_IS_8_ALIGNED(base) 
      )) {
      /* Now we know the address range is suitably sized and aligned. */
      UWord a_lo   = (UWord)base;
      UWord a_hi   = (UWord)(base + 127);
      UWord sec_lo = a_lo >> 16;
      UWord sec_hi = a_hi >> 16;

      if (EXPECTED_TAKEN( sec_lo == sec_hi 
                          && sec_lo <= N_PRIMARY_MAP
         )) {
         /* Now we know that the entire address range falls within a
            single secondary map, and that that secondary 'lives' in
            the main primary map. */
         SecMap* sm = primary_map[sec_lo];

         if (EXPECTED_TAKEN( !is_distinguished_sm(sm) )) {
            /* And finally, now we know that the secondary in question
               is modifiable. */
            UWord   v_off = SM_OFF(a_lo);
            UShort* p     = (UShort*)(&sm->vabits32[v_off]);
            p[ 0] =  MC_BITS64_WRITABLE;
            p[ 1] =  MC_BITS64_WRITABLE;
            p[ 2] =  MC_BITS64_WRITABLE;
            p[ 3] =  MC_BITS64_WRITABLE;
            p[ 4] =  MC_BITS64_WRITABLE;
            p[ 5] =  MC_BITS64_WRITABLE;
            p[ 6] =  MC_BITS64_WRITABLE;
            p[ 7] =  MC_BITS64_WRITABLE;
            p[ 8] =  MC_BITS64_WRITABLE;
            p[ 9] =  MC_BITS64_WRITABLE;
            p[10] =  MC_BITS64_WRITABLE;
            p[11] =  MC_BITS64_WRITABLE;
            p[12] =  MC_BITS64_WRITABLE;
            p[13] =  MC_BITS64_WRITABLE;
            p[14] =  MC_BITS64_WRITABLE;
            p[15] =  MC_BITS64_WRITABLE;
            return;
         }
      }
   }

   /* else fall into slow case */
   mc_make_writable(base, len);
}


/*------------------------------------------------------------*/
/*--- Checking memory                                      ---*/
/*------------------------------------------------------------*/

typedef 
   enum {
      MC_Ok = 5, 
      MC_AddrErr = 6, 
      MC_ValueErr = 7
   } 
   MC_ReadResult;


/* Check permissions for address range.  If inadequate permissions
   exist, *bad_addr is set to the offending address, so the caller can
   know what it is. */

/* Returns True if [a .. a+len) is not addressible.  Otherwise,
   returns False, and if bad_addr is non-NULL, sets *bad_addr to
   indicate the lowest failing address.  Functions below are
   similar. */
static Bool mc_check_noaccess ( Addr a, SizeT len, Addr* bad_addr )
{
   SizeT i;
   UWord vabits8;

   PROF_EVENT(60, "mc_check_noaccess");
   for (i = 0; i < len; i++) {
      PROF_EVENT(61, "mc_check_noaccess(loop)");
      vabits8 = get_vabits8(a);
      if (MC_BITS8_NOACCESS != vabits8) {
         if (bad_addr != NULL) *bad_addr = a;
         return False;
      }
      a++;
   }
   return True;
}

// Note that this succeeds also if the memory is readable.
static Bool mc_check_writable ( Addr a, SizeT len, Addr* bad_addr )
{
   SizeT i;
   UWord vabits8;

   PROF_EVENT(62, "mc_check_writable");
   for (i = 0; i < len; i++) {
      PROF_EVENT(63, "mc_check_writable(loop)");
      vabits8 = get_vabits8(a);
      if (MC_BITS8_NOACCESS == vabits8) {
         if (bad_addr != NULL) *bad_addr = a;
         return False;
      }
      a++;
   }
   return True;
}

static MC_ReadResult mc_check_readable ( Addr a, SizeT len, Addr* bad_addr )
{
   SizeT i;
   UWord vabits8;

   PROF_EVENT(64, "mc_check_readable");
   DEBUG("mc_check_readable\n");
   for (i = 0; i < len; i++) {
      PROF_EVENT(65, "mc_check_readable(loop)");
      vabits8 = get_vabits8(a);
      if (MC_BITS8_READABLE != vabits8) {
         // Error!  Nb: Report addressability errors in preference to
         // definedness errors.
         if (bad_addr != NULL) *bad_addr = a;
         return ( MC_BITS8_NOACCESS == vabits8 ? MC_AddrErr : MC_ValueErr );
      }
      a++;
   }
   return MC_Ok;
}


/* Check a zero-terminated ascii string.  Tricky -- don't want to
   examine the actual bytes, to find the end, until we're sure it is
   safe to do so. */

static Bool mc_check_readable_asciiz ( Addr a, Addr* bad_addr )
{
   UWord vabits8;

   PROF_EVENT(66, "mc_check_readable_asciiz");
   DEBUG("mc_check_readable_asciiz\n");
   while (True) {
      PROF_EVENT(67, "mc_check_readable_asciiz(loop)");
      vabits8 = get_vabits8(a);
      if (MC_BITS8_READABLE != vabits8) {
         // Error!  Nb: Report addressability errors in preference to
         // definedness errors.
         if (bad_addr != NULL) *bad_addr = a;
         return ( MC_BITS8_NOACCESS == vabits8 ? MC_AddrErr : MC_ValueErr );
      }
      /* Ok, a is safe to read. */
      if (* ((UChar*)a) == 0) {
         return MC_Ok;
      }
      a++;
   }
}


/*------------------------------------------------------------*/
/*--- Memory event handlers                                ---*/
/*------------------------------------------------------------*/

static
void mc_check_is_writable ( CorePart part, ThreadId tid, Char* s,
                            Addr base, SizeT size )
{
   Bool ok;
   Addr bad_addr;

   VGP_PUSHCC(VgpCheckMem);

   /* VG_(message)(Vg_DebugMsg,"check is writable: %x .. %x",
                               base,base+size-1); */
   ok = mc_check_writable ( base, size, &bad_addr );
   if (!ok) {
      switch (part) {
      case Vg_CoreSysCall:
         MAC_(record_param_error) ( tid, bad_addr, /*isReg*/False,
                                    /*isUnaddr*/True, s );
         break;

      case Vg_CorePThread:
      case Vg_CoreSignal:
         MAC_(record_core_mem_error)( tid, /*isUnaddr*/True, s );
         break;

      default:
         VG_(tool_panic)("mc_check_is_writable: unexpected CorePart");
      }
   }

   VGP_POPCC(VgpCheckMem);
}

static
void mc_check_is_readable ( CorePart part, ThreadId tid, Char* s,
                            Addr base, SizeT size )
{     
   Addr bad_addr;
   MC_ReadResult res;

   VGP_PUSHCC(VgpCheckMem);
   
   res = mc_check_readable ( base, size, &bad_addr );

   if (0)
      VG_(printf)("mc_check_is_readable(0x%x, %d, %s) -> %s\n",
                  (UInt)base, (Int)size, s, res==MC_Ok ? "yes" : "no" );

   if (MC_Ok != res) {
      Bool isUnaddr = ( MC_AddrErr == res ? True : False );

      switch (part) {
      case Vg_CoreSysCall:
         MAC_(record_param_error) ( tid, bad_addr, /*isReg*/False,
                                    isUnaddr, s );
         break;
      
      case Vg_CorePThread:
         MAC_(record_core_mem_error)( tid, isUnaddr, s );
         break;

      /* If we're being asked to jump to a silly address, record an error 
         message before potentially crashing the entire system. */
      case Vg_CoreTranslate:
         MAC_(record_jump_error)( tid, bad_addr );
         break;

      default:
         VG_(tool_panic)("mc_check_is_readable: unexpected CorePart");
      }
   }
   VGP_POPCC(VgpCheckMem);
}

static
void mc_check_is_readable_asciiz ( CorePart part, ThreadId tid,
                                   Char* s, Addr str )
{
   MC_ReadResult res;
   Addr bad_addr = 0;   // shut GCC up
   /* VG_(message)(Vg_DebugMsg,"check is readable asciiz: 0x%x",str); */

   VGP_PUSHCC(VgpCheckMem);

   tl_assert(part == Vg_CoreSysCall);
   res = mc_check_readable_asciiz ( (Addr)str, &bad_addr );
   if (MC_Ok != res) {
      Bool isUnaddr = ( MC_AddrErr == res ? True : False );
      MAC_(record_param_error) ( tid, bad_addr, /*isReg*/False, isUnaddr, s );
   }

   VGP_POPCC(VgpCheckMem);
}

static
void mc_new_mem_startup( Addr a, SizeT len, Bool rr, Bool ww, Bool xx )
{
   /* Ignore the permissions, just make it readable.  Seems to work... */
   DEBUG("mc_new_mem_startup(%p, %llu, rr=%u, ww=%u, xx=%u)\n",
         a,(ULong)len,rr,ww,xx);
   mc_make_readable(a, len);
}

static
void mc_new_mem_heap ( Addr a, SizeT len, Bool is_inited )
{
   if (is_inited) {
      mc_make_readable(a, len);
   } else {
      mc_make_writable(a, len);
   }
}

static
void mc_new_mem_mmap ( Addr a, SizeT len, Bool rr, Bool ww, Bool xx )
{
   mc_make_readable(a, len);
}

static
void mc_post_mem_write(CorePart part, ThreadId tid, Addr a, SizeT len)
{
   mc_make_readable(a, len);
}


/*------------------------------------------------------------*/
/*--- Register event handlers                              ---*/
/*------------------------------------------------------------*/

/* When some chunk of guest state is written, mark the corresponding
   shadow area as valid.  This is used to initialise arbitrarily large
   chunks of guest state, hence the (somewhat arbitrary) 1024 limit.
*/
static void mc_post_reg_write ( CorePart part, ThreadId tid, 
                                OffT offset, SizeT size)
{
   UChar area[1024];
   tl_assert(size <= 1024);
   VG_(memset)(area, VGM_BYTE_VALID, size);
   VG_(set_shadow_regs_area)( tid, offset, size, area );
}

static 
void mc_post_reg_write_clientcall ( ThreadId tid, 
                                    OffT offset, SizeT size,
                                    Addr f)
{
   mc_post_reg_write(/*dummy*/0, tid, offset, size);
}

/* Look at the definedness of the guest's shadow state for 
   [offset, offset+len).  If any part of that is undefined, record 
   a parameter error.
*/
static void mc_pre_reg_read ( CorePart part, ThreadId tid, Char* s, 
                              OffT offset, SizeT size)
{
   Int   i;
   Bool  bad;

   UChar area[16];
   tl_assert(size <= 16);

   VG_(get_shadow_regs_area)( tid, offset, size, area );

   bad = False;
   for (i = 0; i < size; i++) {
      if (area[i] != VGM_BYTE_VALID) {
         bad = True;
         break;
      }
   }

   if (bad)
      MAC_(record_param_error) ( tid, 0, /*isReg*/True, /*isUnaddr*/False, s );
}


/*------------------------------------------------------------*/
/*--- Printing errors                                      ---*/
/*------------------------------------------------------------*/

static void mc_pp_Error ( Error* err )
{
   MAC_Error* err_extra = VG_(get_error_extra)(err);

   HChar* xpre  = VG_(clo_xml) ? "  <what>" : "";
   HChar* xpost = VG_(clo_xml) ? "</what>"  : "";

   switch (VG_(get_error_kind)(err)) {
      case CoreMemErr: {
         Char* s = ( err_extra->isUnaddr ? "unaddressable" : "uninitialised" );
         if (VG_(clo_xml))
            VG_(message)(Vg_UserMsg, "  <kind>CoreMemError</kind>");
            /* What the hell *is* a CoreMemError? jrs 2005-May-18 */
         VG_(message)(Vg_UserMsg, "%s%s contains %s byte(s)%s", 
                      xpre, VG_(get_error_string)(err), s, xpost);

         VG_(pp_ExeContext)( VG_(get_error_where)(err) );
         break;
      
      } 
      
      case ValueErr:
         if (err_extra->size == 0) {
            if (VG_(clo_xml))
               VG_(message)(Vg_UserMsg, "  <kind>UninitCondition</kind>");
            VG_(message)(Vg_UserMsg, "%sConditional jump or move depends"
                                     " on uninitialised value(s)%s", 
                                     xpre, xpost);
         } else {
            if (VG_(clo_xml))
               VG_(message)(Vg_UserMsg, "  <kind>UninitValue</kind>");
            VG_(message)(Vg_UserMsg,
                         "%sUse of uninitialised value of size %d%s",
                         xpre, err_extra->size, xpost);
         }
         VG_(pp_ExeContext)( VG_(get_error_where)(err) );
         break;

      case ParamErr: {
         Bool isReg = ( Register == err_extra->addrinfo.akind );
         Char* s1 = ( isReg ? "contains" : "points to" );
         Char* s2 = ( err_extra->isUnaddr ? "unaddressable" : "uninitialised" );
         if (isReg) tl_assert(!err_extra->isUnaddr);

         if (VG_(clo_xml))
            VG_(message)(Vg_UserMsg, "  <kind>SyscallParam</kind>");
         VG_(message)(Vg_UserMsg, "%sSyscall param %s %s %s byte(s)%s",
                      xpre, VG_(get_error_string)(err), s1, s2, xpost);

         VG_(pp_ExeContext)( VG_(get_error_where)(err) );
         MAC_(pp_AddrInfo)(VG_(get_error_address)(err), &err_extra->addrinfo);
         break;
      }
      case UserErr: {
         Char* s = ( err_extra->isUnaddr ? "Unaddressable" : "Uninitialised" );

         if (VG_(clo_xml))
            VG_(message)(Vg_UserMsg, "  <kind>ClientCheck</kind>");
         VG_(message)(Vg_UserMsg, 
            "%s%s byte(s) found during client check request%s", 
            xpre, s, xpost);

         VG_(pp_ExeContext)( VG_(get_error_where)(err) );
         MAC_(pp_AddrInfo)(VG_(get_error_address)(err), &err_extra->addrinfo);
         break;
      }
      default: 
         MAC_(pp_shared_Error)(err);
         break;
   }
}

/*------------------------------------------------------------*/
/*--- Recording errors                                     ---*/
/*------------------------------------------------------------*/

/* Creates a copy of the 'extra' part, updates the copy with address info if
   necessary, and returns the copy. */
/* This one called from generated code and non-generated code. */
static void mc_record_value_error ( ThreadId tid, Int size )
{
   MAC_Error err_extra;

   MAC_(clear_MAC_Error)( &err_extra );
   err_extra.size     = size;
   err_extra.isUnaddr = False;
   VG_(maybe_record_error)( tid, ValueErr, /*addr*/0, /*s*/NULL, &err_extra );
}

/* This called from non-generated code */

static void mc_record_user_error ( ThreadId tid, Addr a, Bool isWrite,
                                   Bool isUnaddr )
{
   MAC_Error err_extra;

   tl_assert(VG_INVALID_THREADID != tid);
   MAC_(clear_MAC_Error)( &err_extra );
   err_extra.addrinfo.akind = Undescribed;
   err_extra.isUnaddr       = isUnaddr;
   VG_(maybe_record_error)( tid, UserErr, a, /*s*/NULL, &err_extra );
}

/*------------------------------------------------------------*/
/*--- Suppressions                                         ---*/
/*------------------------------------------------------------*/

static Bool mc_recognised_suppression ( Char* name, Supp* su )
{
   SuppKind skind;

   if (MAC_(shared_recognised_suppression)(name, su))
      return True;

   /* Extra suppressions not used by Addrcheck */
   else if (VG_STREQ(name, "Cond"))    skind = Value0Supp;
   else if (VG_STREQ(name, "Value0"))  skind = Value0Supp;/* backwards compat */
   else if (VG_STREQ(name, "Value1"))  skind = Value1Supp;
   else if (VG_STREQ(name, "Value2"))  skind = Value2Supp;
   else if (VG_STREQ(name, "Value4"))  skind = Value4Supp;
   else if (VG_STREQ(name, "Value8"))  skind = Value8Supp;
   else if (VG_STREQ(name, "Value16")) skind = Value16Supp;
   else 
      return False;

   VG_(set_supp_kind)(su, skind);
   return True;
}

/*------------------------------------------------------------*/
/*--- Functions called directly from generated code:       ---*/
/*--- Load/store handlers.                                 ---*/
/*------------------------------------------------------------*/

/* Types:  LOADV4, LOADV2, LOADV1 are:
               UWord fn ( Addr a )
   so they return 32-bits on 32-bit machines and 64-bits on
   64-bit machines.  Addr has the same size as a host word.

   LOADV8 is always  ULong fn ( Addr a )

   Similarly for STOREV1, STOREV2, STOREV4, the supplied vbits
   are a UWord, and for STOREV8 they are a ULong.
*/

/* ------------------------ Size = 8 ------------------------ */

static inline __attribute__((always_inline))
ULong mc_LOADV8 ( Addr aA, Bool isBigEndian )
{
   UWord   mask, a, sec_no, sm_off64, vabits64;
   SecMap* sm;

   PROF_EVENT(200, "mc_LOADV8");

   if (VG_DEBUG_MEMORY >= 2)
      return mc_LOADVn_slow( aA, 8, isBigEndian );

   mask = ~((0x10000-8) | ((N_PRIMARY_MAP-1) << 16));
   a    = (UWord)aA;

   /* If any part of 'a' indicated by the mask is 1, either */
   /* 'a' is not naturally aligned, or 'a' exceeds the range */
   /* covered by the primary map.  Either way we defer to the */
   /* slow-path case. */
   if (EXPECTED_NOT_TAKEN(a & mask)) {
      PROF_EVENT(201, "mc_LOADV8-slow1");
      return (UWord)mc_LOADVn_slow( aA, 8, isBigEndian );
   }

   sec_no = (UWord)(a >> 16);

   if (VG_DEBUG_MEMORY >= 1)
      tl_assert(sec_no < N_PRIMARY_MAP);

   sm       = primary_map[sec_no];
   sm_off64 = SM_OFF_64(a);
   vabits64 = ((UShort*)(sm->vabits32))[sm_off64];

   // Convert V bits from compact memory form to expanded register form
   if (EXPECTED_TAKEN(vabits64 == MC_BITS64_READABLE)) {
      return VGM_WORD64_VALID;
   } else if (EXPECTED_TAKEN(vabits64 == MC_BITS64_WRITABLE)) {
      return VGM_WORD64_INVALID;
   } else {
      /* Slow but general case. */
      PROF_EVENT(202, "mc_STOREV-slow2");
      return mc_LOADVn_slow( a, 8, isBigEndian );
   }
}

VG_REGPARM(1)
ULong MC_(helperc_LOADV8be) ( Addr a )
{
   return mc_LOADV8(a, True);
}
VG_REGPARM(1)
ULong MC_(helperc_LOADV8le) ( Addr a )
{
   return mc_LOADV8(a, False);
}


static inline __attribute__((always_inline))
void mc_STOREV8 ( Addr aA, ULong vbytes, Bool isBigEndian )
{
   UWord   mask, a, sec_no, sm_off64, vabits64;
   SecMap* sm;

   PROF_EVENT(210, "mc_STOREV8");

   if (VG_DEBUG_MEMORY >= 2) {
      mc_STOREVn_slow( aA, 8, vbytes, isBigEndian );
      return;
   }

   mask = ~((0x10000-8) | ((N_PRIMARY_MAP-1) << 16));
   a    = (UWord)aA;

   /* If any part of 'a' indicated by the mask is 1, either */
   /* 'a' is not naturally aligned, or 'a' exceeds the range */
   /* covered by the primary map.  Either way we defer to the */
   /* slow-path case. */
   if (EXPECTED_NOT_TAKEN(a & mask)) {
      PROF_EVENT(211, "mc_STOREV8-slow1");
      mc_STOREVn_slow( aA, 8, vbytes, isBigEndian );
      return;
   }

   sec_no = (UWord)(a >> 16);

   if (VG_DEBUG_MEMORY >= 1)
      tl_assert(sec_no < N_PRIMARY_MAP);

   sm       = primary_map[sec_no];
   sm_off64 = SM_OFF_64(a);
   vabits64 = ((UShort*)(sm->vabits32))[sm_off64];

   if (EXPECTED_TAKEN( !is_distinguished_sm(sm) && 
                       (MC_BITS64_READABLE == vabits64 ||
                        MC_BITS64_WRITABLE == vabits64) ))
   {
      /* Handle common case quickly: a is suitably aligned, */
      /* is mapped, and is addressible. */
      // Convert full V-bits in register to compact 2-bit form.
      // XXX: is it best to check for VALID before INVALID?
      if (VGM_WORD64_VALID == vbytes) {
         ((UShort*)(sm->vabits32))[sm_off64] = (UShort)MC_BITS64_READABLE;
      } else if (VGM_WORD64_INVALID == vbytes) {
         ((UShort*)(sm->vabits32))[sm_off64] = (UShort)MC_BITS64_WRITABLE;
      } else {
         /* Slow but general case -- writing partially defined bytes. */
         PROF_EVENT(212, "mc_STOREV8-slow2");
         mc_STOREVn_slow( aA, 8, vbytes, isBigEndian );
      }
   } else {
      /* Slow but general case. */
      PROF_EVENT(213, "mc_STOREV8-slow3");
      mc_STOREVn_slow( aA, 8, vbytes, isBigEndian );
   }
}

VG_REGPARM(1)
void MC_(helperc_STOREV8be) ( Addr a, ULong vbytes )
{
   mc_STOREV8(a, vbytes, True);
}
VG_REGPARM(1)
void MC_(helperc_STOREV8le) ( Addr a, ULong vbytes )
{
   mc_STOREV8(a, vbytes, False);
}


/* ------------------------ Size = 4 ------------------------ */

static inline __attribute__((always_inline))
UWord mc_LOADV4 ( Addr a, Bool isBigEndian )
{
   UWord   mask, sec_no, sm_off, vabits32;
   SecMap* sm;

   PROF_EVENT(220, "mc_LOADV4");

   if (VG_DEBUG_MEMORY >= 2)
      return (UWord)mc_LOADVn_slow( a, 4, isBigEndian );

   mask = ~((0x10000-4) | ((N_PRIMARY_MAP-1) << 16));

   /* If any part of 'a' indicated by the mask is 1, either */
   /* 'a' is not naturally aligned, or 'a' exceeds the range */
   /* covered by the primary map.  Either way we defer to the */
   /* slow-path case. */
   if (EXPECTED_NOT_TAKEN(a & mask)) {
      PROF_EVENT(221, "mc_LOADV4-slow1");
      return (UWord)mc_LOADVn_slow( a, 4, isBigEndian );
   }

   sec_no = (UWord)(a >> 16);

   if (VG_DEBUG_MEMORY >= 1)
      tl_assert(sec_no < N_PRIMARY_MAP);

   sm       = primary_map[sec_no];
   sm_off   = SM_OFF(a);
   vabits32 = sm->vabits32[sm_off];

   // XXX: copy this comment to all the LOADV* functions.
   // Handle common case quickly: a is suitably aligned, is mapped, and is
   // addressible.
   // Convert V bits from compact memory form to expanded register form
   // For 64-bit platforms, set the high 32 bits of retval to 1 (undefined).
   // Almost certainly not necessary, but be paranoid.
   if (EXPECTED_TAKEN(vabits32 == MC_BITS32_READABLE)) {
      return ((UWord)0xFFFFFFFF00000000ULL | (UWord)VGM_WORD32_VALID);
   } else if (EXPECTED_TAKEN(vabits32 == MC_BITS32_WRITABLE)) {
      return ((UWord)0xFFFFFFFF00000000ULL | (UWord)VGM_WORD32_INVALID);
   } else {
      /* Slow but general case. */
      PROF_EVENT(222, "mc_LOADV4-slow2");
      return (UWord)mc_LOADVn_slow( a, 4, isBigEndian );
   }
}

VG_REGPARM(1)
UWord MC_(helperc_LOADV4be) ( Addr a )
{
   return mc_LOADV4(a, True);
}
VG_REGPARM(1)
UWord MC_(helperc_LOADV4le) ( Addr a )
{
   return mc_LOADV4(a, False);
}


static inline __attribute__((always_inline))
void mc_STOREV4 ( Addr aA, UWord vbytes, Bool isBigEndian )
{
   UWord   mask, a, sec_no, sm_off, vabits32;
   SecMap* sm;

   PROF_EVENT(230, "mc_STOREV4");

   if (VG_DEBUG_MEMORY >= 2) {
      mc_STOREVn_slow( aA, 4, (ULong)vbytes, isBigEndian );
      return;
   }

   mask = ~((0x10000-4) | ((N_PRIMARY_MAP-1) << 16));
   a    = (UWord)aA;

   /* If any part of 'a' indicated by the mask is 1, either */
   /* 'a' is not naturally aligned, or 'a' exceeds the range */
   /* covered by the primary map.  Either way we defer to the */
   /* slow-path case. */
   if (EXPECTED_NOT_TAKEN(a & mask)) {
      PROF_EVENT(231, "mc_STOREV4-slow1");
      mc_STOREVn_slow( aA, 4, (ULong)vbytes, isBigEndian );
      return;
   }

   sec_no = (UWord)(a >> 16);

   if (VG_DEBUG_MEMORY >= 1)
      tl_assert(sec_no < N_PRIMARY_MAP);

   sm       = primary_map[sec_no];
   sm_off   = SM_OFF(a);
   vabits32 = sm->vabits32[sm_off];

//---------------------------------------------------------------------------
#if 1
   // Cleverness:  sometimes we don't have to write the shadow memory at
   // all, if we can tell that what we want to write is the same as what is
   // already there.
   if (VGM_WORD32_VALID == vbytes) {
      if (vabits32 == (UInt)MC_BITS32_READABLE) {
         return;
      } else if (!is_distinguished_sm(sm) && MC_BITS32_NOACCESS != vabits32) {
         sm->vabits32[sm_off] = (UInt)MC_BITS32_READABLE;
      } else {
         // unaddressable, or distinguished and changing state
         PROF_EVENT(232, "mc_STOREV4-slow2");
         mc_STOREVn_slow( aA, 4, (ULong)vbytes, isBigEndian );
      }
   } else if (VGM_WORD32_INVALID == vbytes) {
      if (vabits32 == (UInt)MC_BITS32_WRITABLE) {
         return;
      } else if (!is_distinguished_sm(sm) && MC_BITS32_NOACCESS != vabits32) {
         sm->vabits32[sm_off] = (UInt)MC_BITS32_WRITABLE;
      } else {
         // unaddressable, or distinguished and changing state
         PROF_EVENT(233, "mc_STOREV4-slow3");
         mc_STOREVn_slow( aA, 4, (ULong)vbytes, isBigEndian );
      }
   } else {
      // Partially defined word
      PROF_EVENT(234, "mc_STOREV4-slow4");
      mc_STOREVn_slow( aA, 4, (ULong)vbytes, isBigEndian );
   }
//---------------------------------------------------------------------------
#else
   if (EXPECTED_TAKEN( !is_distinguished_sm(sm) && 
                       (MC_BITS32_READABLE == vabits32 ||
                        MC_BITS32_WRITABLE == vabits32) ))
   {
      /* Handle common case quickly: a is suitably aligned, */
      /* is mapped, and is addressible. */
      // Convert full V-bits in register to compact 2-bit form.
      // XXX: is it best to check for VALID before INVALID?
      if (VGM_WORD32_VALID == vbytes) {
         sm->vabits32[sm_off] = MC_BITS32_READABLE;
      } else if (VGM_WORD32_INVALID == vbytes) {
         sm->vabits32[sm_off] = MC_BITS32_WRITABLE;
      } else {
         /* Slow but general case -- writing partially defined bytes. */
         PROF_EVENT(232, "mc_STOREV4-slow2");
         mc_STOREVn_slow( aA, 4, (ULong)vbytes, isBigEndian );
      }
   } else {
      /* Slow but general case. */
      PROF_EVENT(233, "mc_STOREV4-slow3");
      mc_STOREVn_slow( aA, 4, (ULong)vbytes, isBigEndian );
   }
#endif
//---------------------------------------------------------------------------
}

VG_REGPARM(2)
void MC_(helperc_STOREV4be) ( Addr a, UWord vbytes )
{
   mc_STOREV4(a, vbytes, True);
}
VG_REGPARM(2)
void MC_(helperc_STOREV4le) ( Addr a, UWord vbytes )
{
   mc_STOREV4(a, vbytes, False);
}


/* ------------------------ Size = 2 ------------------------ */

static inline __attribute__((always_inline))
UWord mc_LOADV2 ( Addr aA, Bool isBigEndian )
{
   UWord   mask, a, sec_no, sm_off, vabits32;
   SecMap* sm;

   PROF_EVENT(240, "mc_LOADV2");

   if (VG_DEBUG_MEMORY >= 2)
      return (UWord)mc_LOADVn_slow( aA, 2, isBigEndian );

   mask = ~((0x10000-2) | ((N_PRIMARY_MAP-1) << 16));
   a    = (UWord)aA;

   /* If any part of 'a' indicated by the mask is 1, either */
   /* 'a' is not naturally aligned, or 'a' exceeds the range */
   /* covered by the primary map.  Either way we defer to the */
   /* slow-path case. */
   if (EXPECTED_NOT_TAKEN(a & mask)) {
      PROF_EVENT(241, "mc_LOADV2-slow1");
      return (UWord)mc_LOADVn_slow( aA, 2, isBigEndian );
   }

   sec_no = (UWord)(a >> 16);

   if (VG_DEBUG_MEMORY >= 1)
      tl_assert(sec_no < N_PRIMARY_MAP);

   sm       = primary_map[sec_no];
   sm_off   = SM_OFF(a);
   vabits32 = sm->vabits32[sm_off];
   // Convert V bits from compact memory form to expanded register form
   // XXX: checking READABLE before WRITABLE a good idea?
   // XXX: set the high 16/48 bits of retval to 1?
   if (EXPECTED_TAKEN(vabits32 == MC_BITS32_READABLE)) {
      return VGM_SHORT_VALID;
   } else if (EXPECTED_TAKEN(vabits32 == MC_BITS32_WRITABLE)) {
      return VGM_SHORT_INVALID;
   } else {
      // XXX: could extract the vabits16 and check it first... (see
      // LOADV1)... depends how common this case is.
      PROF_EVENT(242, "mc_LOADV2-slow2");
      return (UWord)mc_LOADVn_slow( aA, 2, isBigEndian );
   }
}

VG_REGPARM(1)
UWord MC_(helperc_LOADV2be) ( Addr a )
{
   return mc_LOADV2(a, True);
}
VG_REGPARM(1)
UWord MC_(helperc_LOADV2le) ( Addr a )
{
   return mc_LOADV2(a, False);
}


static inline __attribute__((always_inline))
void mc_STOREV2 ( Addr aA, UWord vbytes, Bool isBigEndian )
{
   UWord   mask, a, sec_no, sm_off, vabits32;
   SecMap* sm;

   PROF_EVENT(250, "mc_STOREV2");

   if (VG_DEBUG_MEMORY >= 2) {
      mc_STOREVn_slow( aA, 2, (ULong)vbytes, isBigEndian );
      return;
   }

   mask = ~((0x10000-2) | ((N_PRIMARY_MAP-1) << 16));
   a    = (UWord)aA;

   /* If any part of 'a' indicated by the mask is 1, either */
   /* 'a' is not naturally aligned, or 'a' exceeds the range */
   /* covered by the primary map.  Either way we defer to the */
   /* slow-path case. */
   if (EXPECTED_NOT_TAKEN(a & mask)) {
      PROF_EVENT(251, "mc_STOREV2-slow1");
      mc_STOREVn_slow( aA, 2, (ULong)vbytes, isBigEndian );
      return;
   }

   sec_no = (UWord)(a >> 16);

   if (VG_DEBUG_MEMORY >= 1)
      tl_assert(sec_no < N_PRIMARY_MAP);

   sm       = primary_map[sec_no];
   sm_off   = SM_OFF(a);
   vabits32 = sm->vabits32[sm_off];
   if (EXPECTED_TAKEN( !is_distinguished_sm(sm) && 
                       (MC_BITS32_READABLE == vabits32 ||
                        MC_BITS32_WRITABLE == vabits32) ))
   {
      /* Handle common case quickly: a is suitably aligned, */
      /* is mapped, and is addressible. */
      // Convert full V-bits in register to compact 2-bit form.
      // XXX: is it best to check for VALID before INVALID?
      if (VGM_SHORT_VALID == vbytes) {
         //mc_STOREVn_slow( aA, 2, (ULong)vbytes, isBigEndian );
         insert_vabits16_into_vabits32( a, MC_BITS16_READABLE,
                                        &(sm->vabits32[sm_off]) );
      } else if (VGM_SHORT_INVALID == vbytes) {
         //mc_STOREVn_slow( aA, 2, (ULong)vbytes, isBigEndian );
         insert_vabits16_into_vabits32( a, MC_BITS16_WRITABLE,
                                        &(sm->vabits32[sm_off]) );
      } else {
         /* Slow but general case -- writing partially defined bytes. */
         PROF_EVENT(252, "mc_STOREV2-slow2");
         mc_STOREVn_slow( aA, 2, (ULong)vbytes, isBigEndian );
      }
   } else {
      /* Slow but general case. */
      PROF_EVENT(253, "mc_STOREV2-slow3");
      mc_STOREVn_slow( aA, 2, (ULong)vbytes, isBigEndian );
   }
}

VG_REGPARM(2)
void MC_(helperc_STOREV2be) ( Addr a, UWord vbytes )
{
   mc_STOREV2(a, vbytes, True);
}
VG_REGPARM(2)
void MC_(helperc_STOREV2le) ( Addr a, UWord vbytes )
{
   mc_STOREV2(a, vbytes, False);
}


/* ------------------------ Size = 1 ------------------------ */
/* Note: endianness is irrelevant for size == 1 */

VG_REGPARM(1)
UWord MC_(helperc_LOADV1) ( Addr aA )
{
   UWord   mask, a, sec_no, sm_off, vabits32;
   SecMap* sm;

   PROF_EVENT(260, "helperc_LOADV1");

#  if VG_DEBUG_MEMORY >= 2
   return (UWord)mc_LOADVn_slow( aA, 1, False/*irrelevant*/ );
#  endif

   mask = ~((0x10000-1) | ((N_PRIMARY_MAP-1) << 16));
   a    = (UWord)aA;

   /* If any part of 'a' indicated by the mask is 1, it means 'a'
      exceeds the range covered by the primary map.  In which case we
      defer to the slow-path case. */
   if (EXPECTED_NOT_TAKEN(a & mask)) {
      PROF_EVENT(261, "helperc_LOADV1-slow1");
      return (UWord)mc_LOADVn_slow( aA, 1, False/*irrelevant*/ );
   }

   sec_no = (UWord)(a >> 16);

#  if VG_DEBUG_MEMORY >= 1
   tl_assert(sec_no < N_PRIMARY_MAP);
#  endif

   sm       = primary_map[sec_no];
   sm_off   = SM_OFF(a);
   vabits32 = sm->vabits32[sm_off];
   // Convert V bits from compact memory form to expanded register form
   /* Handle common case quickly: a is mapped, and the entire
      word32 it lives in is addressible. */
   // XXX: set the high 24/56 bits of retval to 1?
   // XXX: check if this sequence is reasonable
   if      (vabits32 == MC_BITS32_READABLE) { return VGM_BYTE_VALID;   }
   else if (vabits32 == MC_BITS32_WRITABLE) { return VGM_BYTE_INVALID; }
   else {
      // XXX: Could just do the slow but general case if this is uncommon...
      UChar vabits8 = extract_vabits8_from_vabits32(a, vabits32);
      if      (vabits8 == MC_BITS8_READABLE) { return VGM_BYTE_VALID;   }
      else if (vabits8 == MC_BITS8_WRITABLE) { return VGM_BYTE_INVALID; }
      else {
         /* Slow but general case. */
         PROF_EVENT(262, "helperc_LOADV1-slow2");
         return (UWord)mc_LOADVn_slow( aA, 1, False/*irrelevant*/ );
      }
   }
}


VG_REGPARM(2)
void MC_(helperc_STOREV1) ( Addr aA, UWord vbyte )
{
   UWord   mask, a, sec_no, sm_off, vabits32;
   SecMap* sm;

   PROF_EVENT(270, "helperc_STOREV1");

#  if VG_DEBUG_MEMORY >= 2
   mc_STOREVn_slow( aA, 1, (ULong)vbyte, False/*irrelevant*/ );
   return;
#  endif

   mask = ~((0x10000-1) | ((N_PRIMARY_MAP-1) << 16));
   a    = (UWord)aA;
   /* If any part of 'a' indicated by the mask is 1, it means 'a'
      exceeds the range covered by the primary map.  In which case we
      defer to the slow-path case. */
   if (EXPECTED_NOT_TAKEN(a & mask)) {
      PROF_EVENT(271, "helperc_STOREV1-slow1");
      mc_STOREVn_slow( aA, 1, (ULong)vbyte, False/*irrelevant*/ );
      return;
   }

   sec_no = (UWord)(a >> 16);

#  if VG_DEBUG_MEMORY >= 1
   tl_assert(sec_no < N_PRIMARY_MAP);
#  endif

   sm       = primary_map[sec_no];
   sm_off   = SM_OFF(a);
   vabits32 = sm->vabits32[sm_off];
   if (EXPECTED_TAKEN( !is_distinguished_sm(sm) && 
                       (MC_BITS32_READABLE == vabits32 ||
                        MC_BITS32_WRITABLE == vabits32) ))
   {
      /* Handle common case quickly: a is mapped, the entire word32 it
         lives in is addressible. */
      // Convert full V-bits in register to compact 2-bit form.
      // XXX: is it best to check for VALID before INVALID?
      if (VGM_BYTE_VALID == vbyte) {
         insert_vabit8_into_vabits32( a, MC_BITS8_READABLE,
                                      &(sm->vabits32[sm_off]) );
      } else if (VGM_BYTE_INVALID == vbyte) {
         insert_vabit8_into_vabits32( a, MC_BITS8_WRITABLE,
                                      &(sm->vabits32[sm_off]) );
      } else {
         /* Slow but general case -- writing partially defined bytes. */
         PROF_EVENT(272, "helperc_STOREV1-slow2");
         mc_STOREVn_slow( a, 1, (ULong)vbyte, False/*irrelevant*/ );
      }
   } else {
      /* Slow but general case. */
      PROF_EVENT(273, "helperc_STOREV1-slow3");
      mc_STOREVn_slow( a, 1, (ULong)vbyte, False/*irrelevant*/ );
   }
}


/*------------------------------------------------------------*/
/*--- Functions called directly from generated code:       ---*/
/*--- Value-check failure handlers.                        ---*/
/*------------------------------------------------------------*/

void MC_(helperc_value_check0_fail) ( void )
{
   mc_record_value_error ( VG_(get_running_tid)(), 0 );
}

void MC_(helperc_value_check1_fail) ( void )
{
   mc_record_value_error ( VG_(get_running_tid)(), 1 );
}

void MC_(helperc_value_check4_fail) ( void )
{
   mc_record_value_error ( VG_(get_running_tid)(), 4 );
}

void MC_(helperc_value_check8_fail) ( void )
{
   mc_record_value_error ( VG_(get_running_tid)(), 8 );
}

VG_REGPARM(1) void MC_(helperc_complain_undef) ( HWord sz )
{
   mc_record_value_error ( VG_(get_running_tid)(), (Int)sz );
}


//zz /*------------------------------------------------------------*/
//zz /*--- Metadata get/set functions, for client requests.     ---*/
//zz /*------------------------------------------------------------*/
//zz 
//zz /* Copy Vbits for src into vbits. Returns: 1 == OK, 2 == alignment
//zz    error, 3 == addressing error. */
//zz static Int mc_get_or_set_vbits_for_client ( 
//zz    ThreadId tid,
//zz    Addr dataV, 
//zz    Addr vbitsV, 
//zz    SizeT size, 
//zz    Bool setting /* True <=> set vbits,  False <=> get vbits */ 
//zz )
//zz {
//zz    Bool addressibleD = True;
//zz    Bool addressibleV = True;
//zz    UInt* data  = (UInt*)dataV;
//zz    UInt* vbits = (UInt*)vbitsV;
//zz    SizeT szW   = size / 4; /* sigh */
//zz    SizeT i;
//zz    UInt* dataP  = NULL; /* bogus init to keep gcc happy */
//zz    UInt* vbitsP = NULL; /* ditto */
//zz 
//zz    /* Check alignment of args. */
//zz    if (!(VG_IS_4_ALIGNED(data) && VG_IS_4_ALIGNED(vbits)))
//zz       return 2;
//zz    if ((size & 3) != 0)
//zz       return 2;
//zz   
//zz    /* Check that arrays are addressible. */
//zz    for (i = 0; i < szW; i++) {
//zz       dataP  = &data[i];
//zz       vbitsP = &vbits[i];
//zz       if (get_abits4_ALIGNED((Addr)dataP) != VGM_NIBBLE_VALID) {
//zz          addressibleD = False;
//zz          break;
//zz       }
//zz       if (get_abits4_ALIGNED((Addr)vbitsP) != VGM_NIBBLE_VALID) {
//zz          addressibleV = False;
//zz          break;
//zz       }
//zz    }
//zz    if (!addressibleD) {
//zz       MAC_(record_address_error)( tid, (Addr)dataP, 4, 
//zz                                   setting ? True : False );
//zz       return 3;
//zz    }
//zz    if (!addressibleV) {
//zz       MAC_(record_address_error)( tid, (Addr)vbitsP, 4, 
//zz                                   setting ? False : True );
//zz       return 3;
//zz    }
//zz  
//zz    /* Do the copy */
//zz    if (setting) {
//zz       /* setting */
//zz       for (i = 0; i < szW; i++) {
//zz          if (get_vbytes4_ALIGNED( (Addr)&vbits[i] ) != VGM_WORD_VALID)
//zz             mc_record_value_error(tid, 4);
//zz          set_vbytes4_ALIGNED( (Addr)&data[i], vbits[i] );
//zz       }
//zz    } else {
//zz       /* getting */
//zz       for (i = 0; i < szW; i++) {
//zz          vbits[i] = get_vbytes4_ALIGNED( (Addr)&data[i] );
//zz          set_vbytes4_ALIGNED( (Addr)&vbits[i], VGM_WORD_VALID );
//zz       }
//zz    }
//zz 
//zz    return 1;
//zz }


/*------------------------------------------------------------*/
/*--- Detecting leaked (unreachable) malloc'd blocks.      ---*/
/*------------------------------------------------------------*/

/* For the memory leak detector, say whether an entire 64k chunk of
   address space is possibly in use, or not.  If in doubt return
   True.
*/
static
Bool mc_is_within_valid_secondary ( Addr a )
{
   SecMap* sm = maybe_get_secmap_for ( a );
   if (sm == NULL || sm == &sm_distinguished[SM_DIST_NOACCESS]) {
      /* Definitely not in use. */
      return False;
   } else {
      return True;
   }
}


/* For the memory leak detector, say whether or not a given word
   address is to be regarded as valid. */
static
Bool mc_is_valid_aligned_word ( Addr a )
{
   tl_assert(sizeof(UWord) == 4 || sizeof(UWord) == 8);
   if (sizeof(UWord) == 4) {
      tl_assert(VG_IS_4_ALIGNED(a));
   } else {
      tl_assert(VG_IS_8_ALIGNED(a));
   }
   if (mc_check_readable( a, sizeof(UWord), NULL ) == MC_Ok) {
      return True;
   } else {
      return False;
   }
}


/* Leak detector for this tool.  We don't actually do anything, merely
   run the generic leak detector with suitable parameters for this
   tool. */
static void mc_detect_memory_leaks ( ThreadId tid, LeakCheckMode mode )
{
   MAC_(do_detect_memory_leaks) ( 
      tid, 
      mode, 
      mc_is_within_valid_secondary, 
      mc_is_valid_aligned_word 
   );
}


/*------------------------------------------------------------*/
/*--- Initialisation                                       ---*/
/*------------------------------------------------------------*/

static void init_shadow_memory ( void )
{
   Int     i;
   SecMap* sm;

   tl_assert(VGM_BIT_INVALID  == 1);
   tl_assert(VGM_BIT_VALID    == 0);
   tl_assert(VGM_BYTE_INVALID == 0xFF);
   tl_assert(VGM_BYTE_VALID   == 0);

   /* Build the 3 distinguished secondaries */
   sm = &sm_distinguished[SM_DIST_NOACCESS];
   for (i = 0; i < SM_CHUNKS; i++) sm->vabits32[i] = MC_BITS32_NOACCESS;

   sm = &sm_distinguished[SM_DIST_WRITABLE];
   for (i = 0; i < SM_CHUNKS; i++) sm->vabits32[i] = MC_BITS32_WRITABLE;

   sm = &sm_distinguished[SM_DIST_READABLE];
   for (i = 0; i < SM_CHUNKS; i++) sm->vabits32[i] = MC_BITS32_READABLE;

   /* Set up the primary map. */
   /* These entries gradually get overwritten as the used address
      space expands. */
   for (i = 0; i < N_PRIMARY_MAP; i++)
      primary_map[i] = &sm_distinguished[SM_DIST_NOACCESS];

   /* auxmap_size = auxmap_used = 0; 
      no ... these are statically initialised */

   /* Secondary V bit table */
   secVBitTable = VG_(OSet_Create)( offsetof(SecVBitNode, a), 
                                    NULL, // use fast comparisons
                                    VG_(malloc), VG_(free) );
}


/*------------------------------------------------------------*/
/*--- Sanity check machinery (permanently engaged)         ---*/
/*------------------------------------------------------------*/

static Bool mc_cheap_sanity_check ( void )
{
   /* nothing useful we can rapidly check */
   n_sanity_cheap++;
   PROF_EVENT(490, "cheap_sanity_check");
   return True;
}

static Bool mc_expensive_sanity_check ( void )
{
   Int     i, n_secmaps_found;
   SecMap* sm;
   Bool    bad = False;

   n_sanity_expensive++;
   PROF_EVENT(491, "expensive_sanity_check");

   /* Check that the 3 distinguished SMs are still as they should be. */

   /* Check noaccess. */
   sm = &sm_distinguished[SM_DIST_NOACCESS];
   for (i = 0; i < SM_CHUNKS; i++)
      if (sm->vabits32[i] != MC_BITS32_NOACCESS)
         bad = True;

   /* Check writable. */
   sm = &sm_distinguished[SM_DIST_WRITABLE];
   for (i = 0; i < SM_CHUNKS; i++)
      if (sm->vabits32[i] != MC_BITS32_WRITABLE)
         bad = True;

   /* Check readable. */
   sm = &sm_distinguished[SM_DIST_READABLE];
   for (i = 0; i < SM_CHUNKS; i++)
      if (sm->vabits32[i] != MC_BITS32_READABLE)
         bad = True;

   if (bad) {
      VG_(printf)("memcheck expensive sanity: "
                  "distinguished_secondaries have changed\n");
      return False;
   }

   /* If we're not checking for undefined value errors, the secondary V bit
    * table should be empty. */
   if (!MAC_(clo_undef_value_errors)) {
      if (0 != VG_(OSet_Size)(secVBitTable))
         return False;
   }

   /* check nonsensical auxmap sizing */
   if (auxmap_used > auxmap_size)
       bad = True;

   if (bad) {
      VG_(printf)("memcheck expensive sanity: "
                  "nonsensical auxmap sizing\n");
      return False;
   }

   /* check that the number of secmaps issued matches the number that
      are reachable (iow, no secmap leaks) */
   n_secmaps_found = 0;
   for (i = 0; i < N_PRIMARY_MAP; i++) {
     if (primary_map[i] == NULL) {
       bad = True;
     } else {
     if (!is_distinguished_sm(primary_map[i]))
       n_secmaps_found++;
     }
   }

   for (i = 0; i < auxmap_used; i++) {
      if (auxmap[i].sm == NULL) {
         bad = True;
      } else {
         if (!is_distinguished_sm(auxmap[i].sm))
            n_secmaps_found++;
      }
   }

   if (n_secmaps_found != (n_secmaps_issued - n_secmaps_deissued))
      bad = True;

   if (bad) {
      VG_(printf)("memcheck expensive sanity: "
                  "apparent secmap leakage\n");
      return False;
   }

   /* check that auxmap only covers address space that the primary doesn't */
   
   for (i = 0; i < auxmap_used; i++)
      if (auxmap[i].base <= MAX_PRIMARY_ADDRESS)
         bad = True;

   if (bad) {
      VG_(printf)("memcheck expensive sanity: "
                  "auxmap covers wrong address space\n");
      return False;
   }

   /* there is only one pointer to each secmap (expensive) */

   return True;
}

/*------------------------------------------------------------*/
/*--- Command line args                                    ---*/
/*------------------------------------------------------------*/

static Bool mc_process_cmd_line_option(Char* arg)
{
   return MAC_(process_common_cmd_line_option)(arg);
}

static void mc_print_usage(void)
{  
   MAC_(print_common_usage)();
}

static void mc_print_debug_usage(void)
{  
   MAC_(print_common_debug_usage)();
}


/*------------------------------------------------------------*/
/*--- Client requests                                      ---*/
/*------------------------------------------------------------*/

/* Client block management:
  
   This is managed as an expanding array of client block descriptors.
   Indices of live descriptors are issued to the client, so it can ask
   to free them later.  Therefore we cannot slide live entries down
   over dead ones.  Instead we must use free/inuse flags and scan for
   an empty slot at allocation time.  This in turn means allocation is
   relatively expensive, so we hope this does not happen too often. 

   An unused block has start == size == 0
*/

typedef
   struct {
      Addr          start;
      SizeT         size;
      ExeContext*   where;
      Char*            desc;
   } 
   CGenBlock;

/* This subsystem is self-initialising. */
static UInt       cgb_size = 0;
static UInt       cgb_used = 0;
static CGenBlock* cgbs     = NULL;

/* Stats for this subsystem. */
static UInt cgb_used_MAX = 0;   /* Max in use. */
static UInt cgb_allocs   = 0;   /* Number of allocs. */
static UInt cgb_discards = 0;   /* Number of discards. */
static UInt cgb_search   = 0;   /* Number of searches. */


static
Int alloc_client_block ( void )
{
   UInt       i, sz_new;
   CGenBlock* cgbs_new;

   cgb_allocs++;

   for (i = 0; i < cgb_used; i++) {
      cgb_search++;
      if (cgbs[i].start == 0 && cgbs[i].size == 0)
         return i;
   }

   /* Not found.  Try to allocate one at the end. */
   if (cgb_used < cgb_size) {
      cgb_used++;
      return cgb_used-1;
   }

   /* Ok, we have to allocate a new one. */
   tl_assert(cgb_used == cgb_size);
   sz_new = (cgbs == NULL) ? 10 : (2 * cgb_size);

   cgbs_new = VG_(malloc)( sz_new * sizeof(CGenBlock) );
   for (i = 0; i < cgb_used; i++) 
      cgbs_new[i] = cgbs[i];

   if (cgbs != NULL)
      VG_(free)( cgbs );
   cgbs = cgbs_new;

   cgb_size = sz_new;
   cgb_used++;
   if (cgb_used > cgb_used_MAX)
      cgb_used_MAX = cgb_used;
   return cgb_used-1;
}


static void show_client_block_stats ( void )
{
   VG_(message)(Vg_DebugMsg, 
      "general CBs: %d allocs, %d discards, %d maxinuse, %d search",
      cgb_allocs, cgb_discards, cgb_used_MAX, cgb_search 
   );
}

static Bool client_perm_maybe_describe( Addr a, AddrInfo* ai )
{
   UInt i;
   /* VG_(printf)("try to identify %d\n", a); */

   /* Perhaps it's a general block ? */
   for (i = 0; i < cgb_used; i++) {
      if (cgbs[i].start == 0 && cgbs[i].size == 0) 
         continue;
      // Use zero as the redzone for client blocks.
      if (VG_(addr_is_in_block)(a, cgbs[i].start, cgbs[i].size, 0)) {
         /* OK - maybe it's a mempool, too? */
         MAC_Mempool* mp = VG_(HT_lookup)(MAC_(mempool_list),
                                          (UWord)cgbs[i].start);
         if (mp != NULL) {
            if (mp->chunks != NULL) {
               MAC_Chunk* mc;
               VG_(HT_ResetIter)(mp->chunks);
               while ( (mc = VG_(HT_Next)(mp->chunks)) ) {
                  if (VG_(addr_is_in_block)(a, mc->data, mc->size,
                                            MAC_MALLOC_REDZONE_SZB)) {
                     ai->akind      = UserG;
                     ai->blksize    = mc->size;
                     ai->rwoffset   = (Int)(a) - (Int)mc->data;
                     ai->lastchange = mc->where;
                     return True;
                  }
               }
            }
            ai->akind      = Mempool;
            ai->blksize    = cgbs[i].size;
            ai->rwoffset   = (Int)(a) - (Int)(cgbs[i].start);
            ai->lastchange = cgbs[i].where;
            return True;
         }
         ai->akind      = UserG;
         ai->blksize    = cgbs[i].size;
         ai->rwoffset   = (Int)(a) - (Int)(cgbs[i].start);
         ai->lastchange = cgbs[i].where;
         ai->desc       = cgbs[i].desc;
         return True;
      }
   }
   return False;
}

static Bool mc_handle_client_request ( ThreadId tid, UWord* arg, UWord* ret )
{
   Int   i;
   Bool  ok;
   Addr  bad_addr;

   if (!VG_IS_TOOL_USERREQ('M','C',arg[0])
    && VG_USERREQ__MALLOCLIKE_BLOCK != arg[0]
    && VG_USERREQ__FREELIKE_BLOCK   != arg[0]
    && VG_USERREQ__CREATE_MEMPOOL   != arg[0]
    && VG_USERREQ__DESTROY_MEMPOOL  != arg[0]
    && VG_USERREQ__MEMPOOL_ALLOC    != arg[0]
    && VG_USERREQ__MEMPOOL_FREE     != arg[0])
      return False;

   switch (arg[0]) {
      case VG_USERREQ__CHECK_WRITABLE: /* check writable */
         ok = mc_check_writable ( arg[1], arg[2], &bad_addr );
         if (!ok)
            mc_record_user_error ( tid, bad_addr, /*isWrite*/True,
                                   /*isUnaddr*/True );
         *ret = ok ? (UWord)NULL : bad_addr;
         break;

      case VG_USERREQ__CHECK_READABLE: { /* check readable */
         MC_ReadResult res;
         res = mc_check_readable ( arg[1], arg[2], &bad_addr );
         if (MC_AddrErr == res)
            mc_record_user_error ( tid, bad_addr, /*isWrite*/False,
                                   /*isUnaddr*/True );
         else if (MC_ValueErr == res)
            mc_record_user_error ( tid, bad_addr, /*isWrite*/False,
                                   /*isUnaddr*/False );
         *ret = ( res==MC_Ok ? (UWord)NULL : bad_addr );
         break;
      }

      case VG_USERREQ__DO_LEAK_CHECK:
         mc_detect_memory_leaks(tid, arg[1] ? LC_Summary : LC_Full);
         *ret = 0; /* return value is meaningless */
         break;

      case VG_USERREQ__MAKE_NOACCESS: /* make no access */
         mc_make_noaccess ( arg[1], arg[2] );
         *ret = -1;
         break;

      case VG_USERREQ__MAKE_WRITABLE: /* make writable */
         mc_make_writable ( arg[1], arg[2] );
         *ret = -1;
         break;

      case VG_USERREQ__MAKE_READABLE: /* make readable */
         mc_make_readable ( arg[1], arg[2] );
         *ret = -1;
         break;

      case VG_USERREQ__CREATE_BLOCK: /* describe a block */
         if (arg[1] != 0 && arg[2] != 0) {
            i = alloc_client_block();
            /* VG_(printf)("allocated %d %p\n", i, cgbs); */
            cgbs[i].start = arg[1];
            cgbs[i].size  = arg[2];
            cgbs[i].desc  = VG_(strdup)((Char *)arg[3]);
            cgbs[i].where = VG_(record_ExeContext) ( tid );

            *ret = i;
         } else
            *ret = -1;
         break;

      case VG_USERREQ__DISCARD: /* discard */
         if (cgbs == NULL 
             || arg[2] >= cgb_used ||
             (cgbs[arg[2]].start == 0 && cgbs[arg[2]].size == 0)) {
            *ret = 1;
         } else {
            tl_assert(arg[2] >= 0 && arg[2] < cgb_used);
            cgbs[arg[2]].start = cgbs[arg[2]].size = 0;
            VG_(free)(cgbs[arg[2]].desc);
            cgb_discards++;
            *ret = 0;
         }
         break;

//zz       case VG_USERREQ__GET_VBITS:
//zz          /* Returns: 1 == OK, 2 == alignment error, 3 == addressing
//zz             error. */
//zz          /* VG_(printf)("get_vbits %p %p %d\n", arg[1], arg[2], arg[3] ); */
//zz          *ret = mc_get_or_set_vbits_for_client
//zz                    ( tid, arg[1], arg[2], arg[3], False /* get them */ );
//zz          break;
//zz 
//zz       case VG_USERREQ__SET_VBITS:
//zz          /* Returns: 1 == OK, 2 == alignment error, 3 == addressing
//zz             error. */
//zz          /* VG_(printf)("set_vbits %p %p %d\n", arg[1], arg[2], arg[3] ); */
//zz          *ret = mc_get_or_set_vbits_for_client
//zz                    ( tid, arg[1], arg[2], arg[3], True /* set them */ );
//zz          break;

      default:
         if (MAC_(handle_common_client_requests)(tid, arg, ret )) {
            return True;
         } else {
            VG_(message)(Vg_UserMsg, 
                         "Warning: unknown memcheck client request code %llx",
                         (ULong)arg[0]);
            return False;
         }
   }
   return True;
}

/*------------------------------------------------------------*/
/*--- Setup and finalisation                               ---*/
/*------------------------------------------------------------*/

static void mc_post_clo_init ( void )
{
   /* If we've been asked to emit XML, mash around various other
      options so as to constrain the output somewhat. */
   if (VG_(clo_xml)) {
      /* Extract as much info as possible from the leak checker. */
      /* MAC_(clo_show_reachable) = True; */
      MAC_(clo_leak_check) = LC_Full;
   }
}

static void mc_fini ( Int exitcode )
{
   Int     i, n_accessible_dist;
   SecMap* sm;

   MAC_(common_fini)( mc_detect_memory_leaks );

   if (VG_(clo_verbosity) > 1) {
      VG_(message)(Vg_DebugMsg,
         " memcheck: sanity checks: %d cheap, %d expensive",
         n_sanity_cheap, n_sanity_expensive );
      VG_(message)(Vg_DebugMsg,
         " memcheck: auxmaps: %d auxmap entries (%dk, %dM) in use",
         auxmap_used, 
         auxmap_used * 64, 
         auxmap_used / 16 );
      VG_(message)(Vg_DebugMsg,
         " memcheck: auxmaps: %lld searches, %lld comparisons",
         n_auxmap_searches, n_auxmap_cmps );   
      VG_(message)(Vg_DebugMsg,
         " memcheck: secondaries: %d issued (%dk, %dM), %d deissued",
         n_secmaps_issued, 
         n_secmaps_issued * sizeof(SecMap) / 1024,
         n_secmaps_issued * sizeof(SecMap) / (1024 * 1024),
         n_secmaps_deissued);   

      n_accessible_dist = 0;
      for (i = 0; i < N_PRIMARY_MAP; i++) {
         sm = primary_map[i];
         if (is_distinguished_sm(sm)
             && sm != &sm_distinguished[SM_DIST_NOACCESS])
            n_accessible_dist ++;
      }
      for (i = 0; i < auxmap_used; i++) {
         sm = auxmap[i].sm;
         if (is_distinguished_sm(sm)
             && sm != &sm_distinguished[SM_DIST_NOACCESS])
            n_accessible_dist ++;
      }

      VG_(message)(Vg_DebugMsg,
         " memcheck: secondaries: %d accessible and distinguished (%dk, %dM)",
         n_accessible_dist, 
         n_accessible_dist * sizeof(SecMap) / 1024,
         n_accessible_dist * sizeof(SecMap) / (1024 * 1024) );

      VG_(message)(Vg_DebugMsg,
         " memcheck: sec V bit entries: %d",
         VG_(OSet_Size)(secVBitTable) );
   }

   if (0) {
      VG_(message)(Vg_DebugMsg, 
        "------ Valgrind's client block stats follow ---------------" );
      show_client_block_stats();
   }
}

static void mc_pre_clo_init(void)
{
   VG_(details_name)            ("Memcheck");
   VG_(details_version)         (NULL);
   VG_(details_description)     ("a memory error detector");
   VG_(details_copyright_author)(
      "Copyright (C) 2002-2005, and GNU GPL'd, by Julian Seward et al.");
   VG_(details_bug_reports_to)  (VG_BUGS_TO);
   VG_(details_avg_translation_sizeB) ( 370 );

   VG_(basic_tool_funcs)          (mc_post_clo_init,
                                   MC_(instrument),
                                   mc_fini);

   VG_(needs_core_errors)         ();
   VG_(needs_tool_errors)         (MAC_(eq_Error),
                                   mc_pp_Error,
                                   MAC_(update_extra),
                                   mc_recognised_suppression,
                                   MAC_(read_extra_suppression_info),
                                   MAC_(error_matches_suppression),
                                   MAC_(get_error_name),
                                   MAC_(print_extra_suppression_info));
   VG_(needs_libc_freeres)        ();
   VG_(needs_command_line_options)(mc_process_cmd_line_option,
                                   mc_print_usage,
                                   mc_print_debug_usage);
   VG_(needs_client_requests)     (mc_handle_client_request);
   VG_(needs_sanity_checks)       (mc_cheap_sanity_check,
                                   mc_expensive_sanity_check);

   VG_(needs_malloc_replacement)  (MAC_(malloc),
                                   MAC_(__builtin_new),
                                   MAC_(__builtin_vec_new),
                                   MAC_(memalign),
                                   MAC_(calloc),
                                   MAC_(free),
                                   MAC_(__builtin_delete),
                                   MAC_(__builtin_vec_delete),
                                   MAC_(realloc),
                                   MAC_MALLOC_REDZONE_SZB );

   MAC_( new_mem_heap)             = & mc_new_mem_heap;
   MAC_( ban_mem_heap)             = & mc_make_noaccess;
   MAC_(copy_mem_heap)             = & mc_copy_address_range_state;
   MAC_( die_mem_heap)             = & mc_make_noaccess;
   MAC_(check_noaccess)            = & mc_check_noaccess;

   VG_(track_new_mem_startup)     ( & mc_new_mem_startup );
   VG_(track_new_mem_stack_signal)( & mc_make_writable );
   VG_(track_new_mem_brk)         ( & mc_make_writable );
   VG_(track_new_mem_mmap)        ( & mc_new_mem_mmap );
   
   VG_(track_copy_mem_remap)      ( & mc_copy_address_range_state );

   // Nb: we don't do anything with mprotect.  This means that V bits are
   // preserved if a program, for example, marks some memory as inaccessible
   // and then later marks it as accessible again.
   // 
   // If an access violation occurs (eg. writing to read-only memory) we let
   // it fault and print an informative termination message.  This doesn't
   // happen if the program catches the signal, though, which is bad.  If we
   // had two A bits (for readability and writability) that were completely
   // distinct from V bits, then we could handle all this properly.
   VG_(track_change_mem_mprotect) ( NULL );
      
   VG_(track_die_mem_stack_signal)( & mc_make_noaccess ); 
   VG_(track_die_mem_brk)         ( & mc_make_noaccess );
   VG_(track_die_mem_munmap)      ( & mc_make_noaccess ); 

   VG_(track_new_mem_stack_4)     ( & MAC_(new_mem_stack_4)  );
   VG_(track_new_mem_stack_8)     ( & MAC_(new_mem_stack_8)  );
   VG_(track_new_mem_stack_12)    ( & MAC_(new_mem_stack_12) );
   VG_(track_new_mem_stack_16)    ( & MAC_(new_mem_stack_16) );
   VG_(track_new_mem_stack_32)    ( & MAC_(new_mem_stack_32) );
   VG_(track_new_mem_stack)       ( & MAC_(new_mem_stack)    );

   VG_(track_die_mem_stack_4)     ( & MAC_(die_mem_stack_4)  );
   VG_(track_die_mem_stack_8)     ( & MAC_(die_mem_stack_8)  );
   VG_(track_die_mem_stack_12)    ( & MAC_(die_mem_stack_12) );
   VG_(track_die_mem_stack_16)    ( & MAC_(die_mem_stack_16) );
   VG_(track_die_mem_stack_32)    ( & MAC_(die_mem_stack_32) );
   VG_(track_die_mem_stack)       ( & MAC_(die_mem_stack)    );
   
   VG_(track_ban_mem_stack)       ( & mc_make_noaccess );

   VG_(track_pre_mem_read)        ( & mc_check_is_readable );
   VG_(track_pre_mem_read_asciiz) ( & mc_check_is_readable_asciiz );
   VG_(track_pre_mem_write)       ( & mc_check_is_writable );
   VG_(track_post_mem_write)      ( & mc_post_mem_write );

   VG_(track_pre_reg_read)        ( & mc_pre_reg_read );

   VG_(track_post_reg_write)                  ( & mc_post_reg_write );
   VG_(track_post_reg_write_clientcall_return)( & mc_post_reg_write_clientcall );

   VG_(register_profile_event) ( VgpSetMem,   "set-mem-perms" );
   VG_(register_profile_event) ( VgpCheckMem, "check-mem-perms" );
   VG_(register_profile_event) ( VgpESPAdj,   "adjust-ESP" );

   /* Additional block description for VG_(describe_addr)() */
   MAC_(describe_addr_supp) = client_perm_maybe_describe;

   init_shadow_memory();
   MAC_(common_pre_clo_init)();

   tl_assert( mc_expensive_sanity_check() );

}

VG_DETERMINE_INTERFACE_VERSION(mc_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
