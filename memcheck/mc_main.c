
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
#include "pub_tool_hashtable.h"     // For mc_include.h
#include "pub_tool_libcbase.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_machine.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_options.h"
#include "pub_tool_oset.h"
#include "pub_tool_profile.h"       // For mc_include.h
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
/*--- V bits and A bits                                    ---*/
/*------------------------------------------------------------*/

/* Conceptually, every byte value has 8 V bits, which track whether Memcheck
   thinks the corresponding value bit is defined.  And every memory byte
   has an A bit, which tracks whether Memcheck thinks the program can access
   it safely.   So every N-bit register is shadowed with N V bits, and every
   memory byte is shadowed with 8 V bits and one A bit.

   In the implementation, we use two forms of compression (compressed V bits
   and distinguished secondary maps) to avoid the 9-bit-per-byte overhead
   for memory.

   Memcheck also tracks extra information about each heap block that is
   allocated, for detecting memory leaks and other purposes.
*/

/*------------------------------------------------------------*/
/*--- Basic A/V bitmap representation.                     ---*/
/*------------------------------------------------------------*/

/* All reads and writes are checked against a memory map (a.k.a. shadow
   memory), which records the state of all memory in the process.  
   
   On 32-bit machine the memory map is organised as follows.
   The top 16 bits of an address are used to index into a top-level
   map table, containing 65536 entries.  Each entry is a pointer to a
   second-level map, which records the accesibililty and validity
   permissions for the 65536 bytes indexed by the lower 16 bits of the
   address.  Each byte is represented by two bits (details are below).  So
   each second-level map contains 16384 bytes.  This two-level arrangement
   conveniently divides the 4G address space into 64k lumps, each size 64k
   bytes.

   All entries in the primary (top-level) map must point to a valid
   secondary (second-level) map.  Since many of the 64kB chunks will
   have the same status for every bit -- ie. not mapped at all (for unused
   address space) or entirely readable (for code segments) -- there are
   three distinguished secondary maps, which indicate 'noaccess', 'writable'
   and 'readable'.  For these uniform 64kB chunks, the primary map entry
   points to the relevant distinguished map.  In practice, typically around
   half of the addressable memory is represented with the 'writable' or
   'readable' distinguished secondary map, so it gives a good saving.  It
   also lets us set the V+A bits of large address regions quickly in
   set_address_range_perms().

   On 64-bit machines it's more complicated.  If we followed the same basic
   scheme we'd have a four-level table which would require too many memory
   accesses.  So instead the top-level map table has 2^19 entries (indexed
   using bits 16..34 of the address);  this covers the bottom 32GB.  Any
   accesses above 32GB are handled with a slow, sparse auxiliary table.
   Valgrind's address space manager tries very hard to keep things below
   this 32GB barrier so that performance doesn't suffer too much.

   Note that this file has a lot of different functions for reading and
   writing shadow memory.  Only a couple are strictly necessary (eg.
   get_vabits8 and set_vabits8), most are just specialised for specific
   common cases to improve performance.
*/

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
// The representation is "inverse" little-endian... each 4 bytes of
// memory is represented by a 1 byte value, where:
//
// - the status of byte (a+0) is held in bits [1..0]
// - the status of byte (a+1) is held in bits [3..2]
// - the status of byte (a+2) is held in bits [5..4]
// - the status of byte (a+3) is held in bits [7..6]
//
// It's "inverse" because endianness normally describes a mapping from
// value bits to memory addresses;  in this case the mapping is inverted.
// Ie. instead of particular value bits being held in certain addresses, in
// this case certain addresses are represented by particular value bits.
// See insert_vabits8_into_vabits32() for an example.
// 
// But note that we don't compress the V bits stored in registers;  they
// need to be explicit to made the shadow operations possible.  Therefore
// when moving values between registers and memory we need to convert
// between the expanded in-register format and the compressed in-memory
// format.  This isn't so difficult, it just requires careful attention in a
// few places.

#define VA_BITS8_NOACCESS     0x0      // 00b
#define VA_BITS8_WRITABLE     0x1      // 01b
#define VA_BITS8_READABLE     0x2      // 10b
#define VA_BITS8_OTHER        0x3      // 11b

#define VA_BITS16_NOACCESS    0x0      // 00_00b
#define VA_BITS16_WRITABLE    0x5      // 01_01b
#define VA_BITS16_READABLE    0xa      // 10_10b

#define VA_BITS32_NOACCESS    0x00     // 00_00_00_00b
#define VA_BITS32_WRITABLE    0x55     // 01_01_01_01b
#define VA_BITS32_READABLE    0xaa     // 10_10_10_10b

#define VA_BITS64_NOACCESS    0x0000   // 00_00_00_00b x 2
#define VA_BITS64_WRITABLE    0x5555   // 01_01_01_01b x 2
#define VA_BITS64_READABLE    0xaaaa   // 10_10_10_10b x 2


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

__attribute__((always_inline))
static inline SecMap* get_secmap_readable_low ( Addr a )
{
   UWord pm_off = a >> 16;
#  if VG_DEBUG_MEMORY >= 1
   tl_assert(pm_off < N_PRIMARY_MAP);
#  endif
   return primary_map[ pm_off ];
}

/* Produce the secmap for 'a', either from the primary map or by
   ensuring there is an entry for it in the aux primary map.  The
   secmap may be a distinguished one as the caller will only want to
   be able to read it. 
*/
static SecMap* get_secmap_readable ( Addr a )
{
   if (a <= MAX_PRIMARY_ADDRESS) {
      return get_secmap_readable_low(a);
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
      return get_secmap_readable_low(a);
   } else {
      AuxMapEnt* am = maybe_find_in_auxmap(a);
      return am ? am->sm : NULL;
   }
}

// Produce the secmap for 'a', where 'a' is known to be in the primary map.
__attribute__((always_inline))
static inline SecMap* get_secmap_writable_low(Addr a)
{
   UWord pm_off = a >> 16;
#  if VG_DEBUG_MEMORY >= 1
   tl_assert(pm_off < N_PRIMARY_MAP);
#  endif
   if (EXPECTED_NOT_TAKEN(is_distinguished_sm(primary_map[pm_off])))
      primary_map[pm_off] = copy_for_writing(primary_map[pm_off]);
   return primary_map[pm_off];
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
      return get_secmap_writable_low(a);
   } else {
      AuxMapEnt* am = find_or_alloc_in_auxmap(a);
      if (is_distinguished_sm(am->sm))
         am->sm = copy_for_writing(am->sm);
      return am->sm;
   }
}


/* --------------- Secondary V bit table ------------ */

// Note: the nodes in this table can become stale.  Eg. if you write a
// partially defined byte (PDB), then overwrite the same address with a
// fully defined byte, the sec-V-bit node will not necessarily be removed.
// This is because checking for whether removal is necessary would slow down
// the fast paths.  Hopefully this is not a problem.  If it becomes a
// problem, we may have to consider doing a clean-up pass every so often.

static OSet* secVBitTable;

static ULong sec_vbits_bytes_allocd = 0;
static ULong sec_vbits_bytes_freed  = 0;
static ULong sec_vbits_bytes_curr   = 0;
static ULong sec_vbits_bytes_peak   = 0;

// sizeof(Addr) is the best value here.  We can go from 1 to sizeof(Addr)
// for free -- it doesn't change the size of the SecVBitNode because of
// padding.  If we make it larger, we have bigger nodes, but can possibly
// fit more partially defined bytes in each node.  In practice it seems that
// partially defined bytes are rarely clustered close to each other, so
// going bigger than sizeof(Addr) does not save space.
#define BYTES_PER_SEC_VBIT_NODE  sizeof(Addr)

typedef 
   struct {
      Addr  a;
      UChar vbits8[BYTES_PER_SEC_VBIT_NODE];
   } 
   SecVBitNode;

static UWord get_sec_vbits8(Addr a)
{
   Addr         aAligned = VG_ROUNDDN(a, BYTES_PER_SEC_VBIT_NODE);
   Int          amod     = a % BYTES_PER_SEC_VBIT_NODE;
   SecVBitNode* n        = VG_(OSet_Lookup)(secVBitTable, &aAligned);
   UChar        vbits8;
   tl_assert(n);
   // Shouldn't be fully defined or fully undefined -- those cases shouldn't
   // make it to the secondary V bits table.
   vbits8 = n->vbits8[amod];
   tl_assert(V_BITS8_VALID != vbits8 && V_BITS8_INVALID != vbits8);
   return vbits8;
}

static void set_sec_vbits8(Addr a, UWord vbits8)
{
   Addr         aAligned = VG_ROUNDDN(a, BYTES_PER_SEC_VBIT_NODE);
   Int          i, amod  = a % BYTES_PER_SEC_VBIT_NODE;
   SecVBitNode* n        = VG_(OSet_Lookup)(secVBitTable, &aAligned);
   // Shouldn't be fully defined or fully undefined -- those cases shouldn't
   // make it to the secondary V bits table.
   tl_assert(V_BITS8_VALID != vbits8 && V_BITS8_INVALID != vbits8);
   if (n) {
      n->vbits8[amod] = vbits8;  // update
   } else {
      // New node:  assign the specific byte, make the rest invalid (they
      // should never be read as-is, but be cautious).
      sec_vbits_bytes_allocd += sizeof(SecVBitNode);
      sec_vbits_bytes_curr   += sizeof(SecVBitNode);
      if (sec_vbits_bytes_curr > sec_vbits_bytes_peak)
         sec_vbits_bytes_peak = sec_vbits_bytes_curr;
      n = VG_(OSet_AllocNode)(secVBitTable, sizeof(SecVBitNode));
      n->a            = aAligned;
      for (i = 0; i < BYTES_PER_SEC_VBIT_NODE; i++) {
         n->vbits8[i] = V_BITS8_INVALID;
      }
      n->vbits8[amod] = vbits8;
      VG_(OSet_Insert)(secVBitTable, n);
   }
}

// Remove the node if its V bytes (other than the one for 'a') are all fully
// defined or fully undefined.  We ignore the V byte for 'a' because it's
// about to be overwritten with a fully defined or fully undefined value.
__attribute__((unused))
static void maybe_remove_sec_vbits8(Addr a)
{
   Addr         aAligned = VG_ROUNDDN(a, BYTES_PER_SEC_VBIT_NODE);
   Int          i, amod  = a % BYTES_PER_SEC_VBIT_NODE;
   SecVBitNode* n        = VG_(OSet_Lookup)(secVBitTable, &aAligned);
   tl_assert(n);
   for (i = 0; i < BYTES_PER_SEC_VBIT_NODE; i++) {
      UChar vbits8 = n->vbits8[i];

      // Ignore the V byte for 'a'.
      if (i == amod)
         continue;
      
      // One of the other V bytes is still partially defined -- don't remove
      // this entry from the table.
      if (V_BITS8_VALID != vbits8 && V_BITS8_INVALID != vbits8)
         return;
   }
   n = VG_(OSet_Remove)(secVBitTable, &aAligned);
   VG_(OSet_FreeNode)(secVBitTable, n);
   sec_vbits_bytes_freed += sizeof(SecVBitNode);
   sec_vbits_bytes_curr  -= sizeof(SecVBitNode);
   tl_assert(n);
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
void insert_vabits8_into_vabits32 ( Addr a, UChar vabits8, UChar* vabits32 )
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
   insert_vabits8_into_vabits32( a, vabits8, &(sm->vabits32[sm_off]) );
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

// Forward declarations
static void mc_record_address_error  ( ThreadId tid, Addr a,
                                       Int size, Bool isWrite );
static void mc_record_core_mem_error ( ThreadId tid, Bool isUnaddr, Char* s );
static void mc_record_param_error    ( ThreadId tid, Addr a, Bool isReg,
                                       Bool isUnaddr, Char* msg );
static void mc_record_jump_error     ( ThreadId tid, Addr a );

static
ULong mc_LOADVn_slow ( Addr a, SizeT szB, Bool bigendian )
{
   /* Make up a 64-bit result V word, which contains the loaded data for
      valid addresses and Defined for invalid addresses.  Iterate over
      the bytes in the word, from the most significant down to the
      least. */
   ULong vbits64     = V_BITS64_INVALID;
   SSizeT i          = szB-1;    // Must be signed
   SizeT n_addrs_bad = 0;
   Addr  ai;
   Bool  partial_load_exemption_applies;
   UWord vbits8, vabits8;

   PROF_EVENT(30, "mc_LOADVn_slow");
   tl_assert(szB == 8 || szB == 4 || szB == 2 || szB == 1);

   for (i = szB-1; i >= 0; i--) {
      PROF_EVENT(31, "mc_LOADVn_slow(loop)");
      ai = a+byte_offset_w(szB,bigendian,i);
      vabits8 = get_vabits8(ai);
      // Convert the in-memory format to in-register format.
      if      ( VA_BITS8_READABLE == vabits8 ) { vbits8 = V_BITS8_VALID;   }
      else if ( VA_BITS8_WRITABLE == vabits8 ) { vbits8 = V_BITS8_INVALID; }
      else if ( VA_BITS8_NOACCESS == vabits8 ) {
         vbits8 = V_BITS8_VALID;    // Make V bits defined!
         n_addrs_bad++;
      } else {
         tl_assert( VA_BITS8_OTHER == vabits8 );
         vbits8 = get_sec_vbits8(ai);
      }
      vbits64 <<= 8; 
      vbits64 |= vbits8;
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
      = MC_(clo_partial_loads_ok) && szB == VG_WORDSIZE 
                                   && VG_IS_WORD_ALIGNED(a) 
                                   && n_addrs_bad < VG_WORDSIZE;

   if (n_addrs_bad > 0 && !partial_load_exemption_applies)
      mc_record_address_error( VG_(get_running_tid)(), a, szB, False );

   return vbits64;
}


static 
void mc_STOREVn_slow ( Addr a, SizeT szB, ULong vbytes, Bool bigendian )
{
   SizeT i, n_addrs_bad = 0;
   UWord vbits8, vabits8;
   Addr  ai;

   PROF_EVENT(35, "mc_STOREVn_slow");
   tl_assert(szB == 8 || szB == 4 || szB == 2 || szB == 1);

   /* Dump vbytes in memory, iterating from least to most significant
      byte.  At the same time establish addressibility of the
      location. */
   for (i = 0; i < szB; i++) {
      PROF_EVENT(36, "mc_STOREVn_slow(loop)");
      ai = a+byte_offset_w(szB,bigendian,i);
      vbits8  = vbytes & 0xff;
      vabits8 = get_vabits8(ai);
      if ( VA_BITS8_NOACCESS != vabits8 ) {
         // Addressable.  Convert in-register format to in-memory format.
         // Also remove any existing sec V bit entry for the byte if no
         // longer necessary.
         //
         // XXX: the calls to maybe_remove_sec_vbits8() are commented out
         // because they slow things down a bit (eg. 10% for perf/bz2)
         // and the space saving is quite small (eg. 1--2% reduction in the
         // size of the sec-V-bit-table?)
         if ( V_BITS8_VALID == vbits8 ) { 
//            if (VA_BITS8_OTHER == vabits8)
//               maybe_remove_sec_vbits8(ai);
            vabits8 = VA_BITS8_READABLE; 

         } else if ( V_BITS8_INVALID == vbits8 ) { 
//            if (VA_BITS8_OTHER == vabits8)
//               maybe_remove_sec_vbits8(ai);
            vabits8 = VA_BITS8_WRITABLE; 

         } else    { 
            vabits8 = VA_BITS8_OTHER;
            set_sec_vbits8(ai, vbits8);
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
      mc_record_address_error( VG_(get_running_tid)(), a, szB, True );
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

static SecMap** find_secmap_binder_for_addr ( Addr a )
{
   if (a > MAX_PRIMARY_ADDRESS) {
      AuxMapEnt* am = find_or_alloc_in_auxmap(a);
      return &am->sm;
   } else {
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
   tl_assert(vabits64 == VA_BITS64_NOACCESS ||
             vabits64 == VA_BITS64_WRITABLE ||
             vabits64 == VA_BITS64_READABLE);

   if (lenT == 0)
      return;

   if (lenT > 100 * 1000 * 1000) {
      if (VG_(clo_verbosity) > 0 && !VG_(clo_xml)) {
         Char* s = "unknown???";
         if (vabits64 == VA_BITS64_NOACCESS) s = "noaccess";
         if (vabits64 == VA_BITS64_WRITABLE) s = "writable";
         if (vabits64 == VA_BITS64_READABLE) s = "readable";
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
         set_vabits8(a + i, vabits8);
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
      insert_vabits8_into_vabits32( a, vabits8, &(sm->vabits32[sm_off]) );
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
      insert_vabits8_into_vabits32( a, vabits8, &(sm->vabits32[sm_off]) );
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
      insert_vabits8_into_vabits32( a, vabits8, &(sm->vabits32[sm_off]) );
      a    += 1;
      lenB -= 1;
   }
}


/* --- Set permissions for arbitrary address ranges --- */

static void mc_make_noaccess ( Addr a, SizeT len )
{
   PROF_EVENT(40, "mc_make_noaccess");
   DEBUG("mc_make_noaccess(%p, %lu)\n", a, len);
   set_address_range_perms ( a, len, VA_BITS64_NOACCESS, SM_DIST_NOACCESS );
}

static void mc_make_writable ( Addr a, SizeT len )
{
   PROF_EVENT(41, "mc_make_writable");
   DEBUG("mc_make_writable(%p, %lu)\n", a, len);
   set_address_range_perms ( a, len, VA_BITS64_WRITABLE, SM_DIST_WRITABLE );
}

static void mc_make_readable ( Addr a, SizeT len )
{
   PROF_EVENT(42, "mc_make_readable");
   DEBUG("mc_make_readable(%p, %lu)\n", a, len);
   set_address_range_perms ( a, len, VA_BITS64_READABLE, SM_DIST_READABLE );
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
   UWord   sm_off;
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

   sm                   = get_secmap_writable_low(a);
   sm_off               = SM_OFF(a);
   sm->vabits32[sm_off] = VA_BITS32_WRITABLE;
}


// XXX: can surely merge this somehow with make_aligned_word32_writable
static __inline__
void make_aligned_word32_noaccess ( Addr a )
{
   UWord   sm_off;
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

   sm                   = get_secmap_writable_low(a);
   sm_off               = SM_OFF(a);
   sm->vabits32[sm_off] = VA_BITS32_NOACCESS;
}


/* Nb: by "aligned" here we mean 8-byte aligned */
static __inline__
void make_aligned_word64_writable ( Addr a )
{
   UWord   sm_off64;
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

   sm       = get_secmap_writable_low(a);
   sm_off64 = SM_OFF_64(a);
   ((UShort*)(sm->vabits32))[sm_off64] = VA_BITS64_WRITABLE;
}


static __inline__
void make_aligned_word64_noaccess ( Addr a )
{
   UWord   sm_off64;
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

   sm       = get_secmap_writable_low(a);
   sm_off64 = SM_OFF_64(a);
   ((UShort*)(sm->vabits32))[sm_off64] = VA_BITS64_NOACCESS;
}


/*------------------------------------------------------------*/
/*--- Stack pointer adjustment                             ---*/
/*------------------------------------------------------------*/

static void VG_REGPARM(1) mc_new_mem_stack_4(Addr new_SP)
{
   PROF_EVENT(110, "new_mem_stack_4");
   if (VG_IS_4_ALIGNED(new_SP)) {
      make_aligned_word32_writable  ( -VG_STACK_REDZONE_SZB + new_SP );
   } else {
      mc_make_writable ( -VG_STACK_REDZONE_SZB + new_SP, 4 );
   }
}

static void VG_REGPARM(1) mc_die_mem_stack_4(Addr new_SP)
{
   PROF_EVENT(120, "die_mem_stack_4");
   if (VG_IS_4_ALIGNED(new_SP)) {
      make_aligned_word32_noaccess  ( -VG_STACK_REDZONE_SZB + new_SP-4 );
   } else {
      mc_make_noaccess ( -VG_STACK_REDZONE_SZB + new_SP-4, 4 );
   }
}

static void VG_REGPARM(1) mc_new_mem_stack_8(Addr new_SP)
{
   PROF_EVENT(111, "new_mem_stack_8");
   if (VG_IS_8_ALIGNED(new_SP)) {
      make_aligned_word64_writable  ( -VG_STACK_REDZONE_SZB + new_SP );
   } else if (VG_IS_4_ALIGNED(new_SP)) {
      make_aligned_word32_writable  ( -VG_STACK_REDZONE_SZB + new_SP   );
      make_aligned_word32_writable  ( -VG_STACK_REDZONE_SZB + new_SP+4 );
   } else {
      mc_make_writable ( -VG_STACK_REDZONE_SZB + new_SP, 8 );
   }
}

static void VG_REGPARM(1) mc_die_mem_stack_8(Addr new_SP)
{
   PROF_EVENT(121, "die_mem_stack_8");
   if (VG_IS_8_ALIGNED(new_SP)) {
      make_aligned_word64_noaccess  ( -VG_STACK_REDZONE_SZB + new_SP-8 );
   } else if (VG_IS_4_ALIGNED(new_SP)) {
      make_aligned_word32_noaccess  ( -VG_STACK_REDZONE_SZB + new_SP-8 );
      make_aligned_word32_noaccess  ( -VG_STACK_REDZONE_SZB + new_SP-4 );
   } else {
      mc_make_noaccess ( -VG_STACK_REDZONE_SZB + new_SP-8, 8 );
   }
}

static void VG_REGPARM(1) mc_new_mem_stack_12(Addr new_SP)
{
   PROF_EVENT(112, "new_mem_stack_12");
   if (VG_IS_8_ALIGNED(new_SP)) {
      make_aligned_word64_writable  ( -VG_STACK_REDZONE_SZB + new_SP   );
      make_aligned_word32_writable  ( -VG_STACK_REDZONE_SZB + new_SP+8 );
   } else if (VG_IS_4_ALIGNED(new_SP)) {
      make_aligned_word32_writable  ( -VG_STACK_REDZONE_SZB + new_SP   );
      make_aligned_word64_writable  ( -VG_STACK_REDZONE_SZB + new_SP+4 );
   } else {
      mc_make_writable ( -VG_STACK_REDZONE_SZB + new_SP, 12 );
   }
}

static void VG_REGPARM(1) mc_die_mem_stack_12(Addr new_SP)
{
   PROF_EVENT(122, "die_mem_stack_12");
   /* Note the -12 in the test */
   if (VG_IS_8_ALIGNED(new_SP-12)) {
      make_aligned_word64_noaccess  ( -VG_STACK_REDZONE_SZB + new_SP-12 );
      make_aligned_word32_noaccess  ( -VG_STACK_REDZONE_SZB + new_SP-4  );
   } else if (VG_IS_4_ALIGNED(new_SP)) {
      make_aligned_word32_noaccess  ( -VG_STACK_REDZONE_SZB + new_SP-12 );
      make_aligned_word64_noaccess  ( -VG_STACK_REDZONE_SZB + new_SP-8  );
   } else {
      mc_make_noaccess ( -VG_STACK_REDZONE_SZB + new_SP-12, 12 );
   }
}

static void VG_REGPARM(1) mc_new_mem_stack_16(Addr new_SP)
{
   PROF_EVENT(113, "new_mem_stack_16");
   if (VG_IS_8_ALIGNED(new_SP)) {
      make_aligned_word64_writable  ( -VG_STACK_REDZONE_SZB + new_SP   );
      make_aligned_word64_writable  ( -VG_STACK_REDZONE_SZB + new_SP+8 );
   } else if (VG_IS_4_ALIGNED(new_SP)) {
      make_aligned_word32_writable  ( -VG_STACK_REDZONE_SZB + new_SP    );
      make_aligned_word64_writable  ( -VG_STACK_REDZONE_SZB + new_SP+4  );
      make_aligned_word32_writable  ( -VG_STACK_REDZONE_SZB + new_SP+12 );
   } else {
      mc_make_writable ( -VG_STACK_REDZONE_SZB + new_SP, 16 );
   }
}

static void VG_REGPARM(1) mc_die_mem_stack_16(Addr new_SP)
{
   PROF_EVENT(123, "die_mem_stack_16");
   if (VG_IS_8_ALIGNED(new_SP)) {
      make_aligned_word64_noaccess  ( -VG_STACK_REDZONE_SZB + new_SP-16 );
      make_aligned_word64_noaccess  ( -VG_STACK_REDZONE_SZB + new_SP-8  );
   } else if (VG_IS_4_ALIGNED(new_SP)) {
      make_aligned_word32_noaccess  ( -VG_STACK_REDZONE_SZB + new_SP-16 );
      make_aligned_word64_noaccess  ( -VG_STACK_REDZONE_SZB + new_SP-12 );
      make_aligned_word32_noaccess  ( -VG_STACK_REDZONE_SZB + new_SP-4  );
   } else {
      mc_make_noaccess ( -VG_STACK_REDZONE_SZB + new_SP-16, 16 );
   }
}

static void VG_REGPARM(1) mc_new_mem_stack_32(Addr new_SP)
{
   PROF_EVENT(114, "new_mem_stack_32");
   if (VG_IS_8_ALIGNED(new_SP)) {
      make_aligned_word64_writable  ( -VG_STACK_REDZONE_SZB + new_SP    );
      make_aligned_word64_writable  ( -VG_STACK_REDZONE_SZB + new_SP+8  );
      make_aligned_word64_writable  ( -VG_STACK_REDZONE_SZB + new_SP+16 );
      make_aligned_word64_writable  ( -VG_STACK_REDZONE_SZB + new_SP+24 );
   } else if (VG_IS_4_ALIGNED(new_SP)) {
      make_aligned_word32_writable  ( -VG_STACK_REDZONE_SZB + new_SP    );
      make_aligned_word64_writable  ( -VG_STACK_REDZONE_SZB + new_SP+4  );
      make_aligned_word64_writable  ( -VG_STACK_REDZONE_SZB + new_SP+12 );
      make_aligned_word64_writable  ( -VG_STACK_REDZONE_SZB + new_SP+20 );
      make_aligned_word32_writable  ( -VG_STACK_REDZONE_SZB + new_SP+28 );
   } else {
      mc_make_writable ( -VG_STACK_REDZONE_SZB + new_SP, 32 );
   }
}

static void VG_REGPARM(1) mc_die_mem_stack_32(Addr new_SP)
{
   PROF_EVENT(124, "die_mem_stack_32");
   if (VG_IS_8_ALIGNED(new_SP)) {
      make_aligned_word64_noaccess  ( -VG_STACK_REDZONE_SZB + new_SP-32 );
      make_aligned_word64_noaccess  ( -VG_STACK_REDZONE_SZB + new_SP-24 );
      make_aligned_word64_noaccess  ( -VG_STACK_REDZONE_SZB + new_SP-16 );
      make_aligned_word64_noaccess  ( -VG_STACK_REDZONE_SZB + new_SP- 8 );
   } else if (VG_IS_4_ALIGNED(new_SP)) {
      make_aligned_word32_noaccess  ( -VG_STACK_REDZONE_SZB + new_SP-32 );
      make_aligned_word64_noaccess  ( -VG_STACK_REDZONE_SZB + new_SP-28 );
      make_aligned_word64_noaccess  ( -VG_STACK_REDZONE_SZB + new_SP-20 );
      make_aligned_word64_noaccess  ( -VG_STACK_REDZONE_SZB + new_SP-12 );
      make_aligned_word32_noaccess  ( -VG_STACK_REDZONE_SZB + new_SP-4  );
   } else {
      mc_make_noaccess ( -VG_STACK_REDZONE_SZB + new_SP-32, 32 );
   }
}

static void mc_new_mem_stack ( Addr a, SizeT len )
{
   PROF_EVENT(115, "new_mem_stack");
   mc_make_writable ( -VG_STACK_REDZONE_SZB + a, len );
}

static void mc_die_mem_stack ( Addr a, SizeT len )
{
   PROF_EVENT(125, "die_mem_stack");
   mc_make_noaccess ( -VG_STACK_REDZONE_SZB + a, len );
}


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
            p[ 0] =  VA_BITS64_WRITABLE;
            p[ 1] =  VA_BITS64_WRITABLE;
            p[ 2] =  VA_BITS64_WRITABLE;
            p[ 3] =  VA_BITS64_WRITABLE;
            p[ 4] =  VA_BITS64_WRITABLE;
            p[ 5] =  VA_BITS64_WRITABLE;
            p[ 6] =  VA_BITS64_WRITABLE;
            p[ 7] =  VA_BITS64_WRITABLE;
            p[ 8] =  VA_BITS64_WRITABLE;
            p[ 9] =  VA_BITS64_WRITABLE;
            p[10] =  VA_BITS64_WRITABLE;
            p[11] =  VA_BITS64_WRITABLE;
            p[12] =  VA_BITS64_WRITABLE;
            p[13] =  VA_BITS64_WRITABLE;
            p[14] =  VA_BITS64_WRITABLE;
            p[15] =  VA_BITS64_WRITABLE;
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
      if (VA_BITS8_NOACCESS != vabits8) {
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
      if (VA_BITS8_NOACCESS == vabits8) {
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
      if (VA_BITS8_READABLE != vabits8) {
         // Error!  Nb: Report addressability errors in preference to
         // definedness errors.
         if (bad_addr != NULL) *bad_addr = a;
         return ( VA_BITS8_NOACCESS == vabits8 ? MC_AddrErr : MC_ValueErr );
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
      if (VA_BITS8_READABLE != vabits8) {
         // Error!  Nb: Report addressability errors in preference to
         // definedness errors.
         if (bad_addr != NULL) *bad_addr = a;
         return ( VA_BITS8_NOACCESS == vabits8 ? MC_AddrErr : MC_ValueErr );
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

   /* VG_(message)(Vg_DebugMsg,"check is writable: %x .. %x",
                               base,base+size-1); */
   ok = mc_check_writable ( base, size, &bad_addr );
   if (!ok) {
      switch (part) {
      case Vg_CoreSysCall:
         mc_record_param_error ( tid, bad_addr, /*isReg*/False,
                                    /*isUnaddr*/True, s );
         break;

      case Vg_CorePThread:
      case Vg_CoreSignal:
         mc_record_core_mem_error( tid, /*isUnaddr*/True, s );
         break;

      default:
         VG_(tool_panic)("mc_check_is_writable: unexpected CorePart");
      }
   }
}

static
void mc_check_is_readable ( CorePart part, ThreadId tid, Char* s,
                            Addr base, SizeT size )
{     
   Addr bad_addr;
   MC_ReadResult res;

   res = mc_check_readable ( base, size, &bad_addr );

   if (0)
      VG_(printf)("mc_check_is_readable(0x%x, %d, %s) -> %s\n",
                  (UInt)base, (Int)size, s, res==MC_Ok ? "yes" : "no" );

   if (MC_Ok != res) {
      Bool isUnaddr = ( MC_AddrErr == res ? True : False );

      switch (part) {
      case Vg_CoreSysCall:
         mc_record_param_error ( tid, bad_addr, /*isReg*/False,
                                    isUnaddr, s );
         break;
      
      case Vg_CorePThread:
         mc_record_core_mem_error( tid, isUnaddr, s );
         break;

      /* If we're being asked to jump to a silly address, record an error 
         message before potentially crashing the entire system. */
      case Vg_CoreTranslate:
         mc_record_jump_error( tid, bad_addr );
         break;

      default:
         VG_(tool_panic)("mc_check_is_readable: unexpected CorePart");
      }
   }
}

static
void mc_check_is_readable_asciiz ( CorePart part, ThreadId tid,
                                   Char* s, Addr str )
{
   MC_ReadResult res;
   Addr bad_addr = 0;   // shut GCC up
   /* VG_(message)(Vg_DebugMsg,"check is readable asciiz: 0x%x",str); */

   tl_assert(part == Vg_CoreSysCall);
   res = mc_check_readable_asciiz ( (Addr)str, &bad_addr );
   if (MC_Ok != res) {
      Bool isUnaddr = ( MC_AddrErr == res ? True : False );
      mc_record_param_error ( tid, bad_addr, /*isReg*/False, isUnaddr, s );
   }
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
   VG_(memset)(area, V_BITS8_VALID, size);
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
      if (area[i] != V_BITS8_VALID) {
         bad = True;
         break;
      }
   }

   if (bad)
      mc_record_param_error ( tid, 0, /*isReg*/True, /*isUnaddr*/False, s );
}


/*------------------------------------------------------------*/
/*--- Error and suppression types                          ---*/
/*------------------------------------------------------------*/

/* The classification of a faulting address. */
typedef 
   enum { 
      Undescribed,   // as-yet unclassified
      Stack, 
      Unknown,       // classification yielded nothing useful
      Freed, Mallocd, 
      UserG,         // in a user-defined block
      Mempool,       // in a mempool
      Register,      // in a register;  for Param errors only
   }
   AddrKind;

/* Records info about a faulting address. */
typedef
   struct {                   // Used by:
      AddrKind akind;         //   ALL
      SizeT blksize;          //   Freed, Mallocd
      OffT rwoffset;          //   Freed, Mallocd
      ExeContext* lastchange; //   Freed, Mallocd
      ThreadId stack_tid;     //   Stack
      const Char *desc;	      //   UserG
      Bool maybe_gcc;         // True if just below %esp -- could be a gcc bug.
   }
   AddrInfo;

typedef 
   enum { 
      ParamSupp,     // Bad syscall params
      CoreMemSupp,   // Memory errors in core (pthread ops, signal handling)

      // Use of invalid values of given size (MemCheck only)
      Value0Supp, Value1Supp, Value2Supp, Value4Supp, Value8Supp, Value16Supp,

      // Invalid read/write attempt at given size
      Addr1Supp, Addr2Supp, Addr4Supp, Addr8Supp, Addr16Supp,

      FreeSupp,      // Invalid or mismatching free
      OverlapSupp,   // Overlapping blocks in memcpy(), strcpy(), etc
      LeakSupp,      // Something to be suppressed in a leak check.
      MempoolSupp,   // Memory pool suppression.
   } 
   MC_SuppKind;

/* What kind of error it is. */
typedef 
   enum { ValueErr,     /* Memcheck only */
          CoreMemErr,
          AddrErr, 
          ParamErr, UserErr,  /* behaves like an anonymous ParamErr */
          FreeErr, FreeMismatchErr,
          OverlapErr,
          LeakErr,
          IllegalMempoolErr,
   }
   MC_ErrorKind;

/* What kind of memory access is involved in the error? */
typedef
   enum { ReadAxs, WriteAxs, ExecAxs }
   AxsKind;

/* Extra context for memory errors */
typedef
   struct {                // Used by:
      AxsKind axskind;     //   AddrErr
      Int size;            //   AddrErr, ValueErr
      AddrInfo addrinfo;   //   {Addr,Free,FreeMismatch,Param,User}Err
      Bool isUnaddr;       //   {CoreMem,Param,User}Err
   }
   MC_Error;

/*------------------------------------------------------------*/
/*--- Printing errors                                      ---*/
/*------------------------------------------------------------*/

static void mc_pp_AddrInfo ( Addr a, AddrInfo* ai )
{
   HChar* xpre  = VG_(clo_xml) ? "  <auxwhat>" : " ";
   HChar* xpost = VG_(clo_xml) ? "</auxwhat>"  : "";

   switch (ai->akind) {
      case Stack: 
         VG_(message)(Vg_UserMsg, 
                      "%sAddress 0x%llx is on thread %d's stack%s", 
                      xpre, (ULong)a, ai->stack_tid, xpost);
         break;
      case Unknown:
         if (ai->maybe_gcc) {
            VG_(message)(Vg_UserMsg, 
               "%sAddress 0x%llx is just below the stack ptr.  "
               "To suppress, use: --workaround-gcc296-bugs=yes%s",
               xpre, (ULong)a, xpost
            );
	 } else {
            VG_(message)(Vg_UserMsg, 
               "%sAddress 0x%llx "
               "is not stack'd, malloc'd or (recently) free'd%s",
               xpre, (ULong)a, xpost);
         }
         break;
      case Freed: case Mallocd: case UserG: case Mempool: {
         SizeT delta;
         const Char* relative;
         const Char* kind;
         if (ai->akind == Mempool) {
            kind = "mempool";
         } else {
            kind = "block";
         }
	 if (ai->desc != NULL)
	    kind = ai->desc;

         if (ai->rwoffset < 0) {
            delta    = (SizeT)(- ai->rwoffset);
            relative = "before";
         } else if (ai->rwoffset >= ai->blksize) {
            delta    = ai->rwoffset - ai->blksize;
            relative = "after";
         } else {
            delta    = ai->rwoffset;
            relative = "inside";
         }
         VG_(message)(Vg_UserMsg, 
            "%sAddress 0x%lx is %,lu bytes %s a %s of size %,lu %s%s",
            xpre,
            a, delta, relative, kind,
            ai->blksize,
            ai->akind==Mallocd ? "alloc'd" 
               : ai->akind==Freed ? "free'd" 
                                  : "client-defined",
            xpost);
         VG_(pp_ExeContext)(ai->lastchange);
         break;
      }
      case Register:
         // print nothing
         tl_assert(0 == a);
         break;
      default:
         VG_(tool_panic)("mc_pp_AddrInfo");
   }
}

static void mc_pp_Error ( Error* err )
{
   MC_Error* err_extra = VG_(get_error_extra)(err);

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
         mc_pp_AddrInfo(VG_(get_error_address)(err), &err_extra->addrinfo);
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
         mc_pp_AddrInfo(VG_(get_error_address)(err), &err_extra->addrinfo);
         break;
      }
      case FreeErr:
         if (VG_(clo_xml))
            VG_(message)(Vg_UserMsg, "  <kind>InvalidFree</kind>");
         VG_(message)(Vg_UserMsg, 
                      "%sInvalid free() / delete / delete[]%s",
                      xpre, xpost);
         VG_(pp_ExeContext)( VG_(get_error_where)(err) );
         mc_pp_AddrInfo(VG_(get_error_address)(err), &err_extra->addrinfo);
         break;

      case FreeMismatchErr:
         if (VG_(clo_xml))
            VG_(message)(Vg_UserMsg, "  <kind>MismatchedFree</kind>");
         VG_(message)(Vg_UserMsg, 
                      "%sMismatched free() / delete / delete []%s",
                      xpre, xpost);
         VG_(pp_ExeContext)( VG_(get_error_where)(err) );
         mc_pp_AddrInfo(VG_(get_error_address)(err), &err_extra->addrinfo);
         break;

      case AddrErr:
         switch (err_extra->axskind) {
            case ReadAxs:
               if (VG_(clo_xml))
                  VG_(message)(Vg_UserMsg, "  <kind>InvalidRead</kind>");
               VG_(message)(Vg_UserMsg,
                            "%sInvalid read of size %d%s", 
                            xpre, err_extra->size, xpost ); 
               break;
            case WriteAxs:
               if (VG_(clo_xml))
                  VG_(message)(Vg_UserMsg, "  <kind>InvalidWrite</kind>");
               VG_(message)(Vg_UserMsg, 
                           "%sInvalid write of size %d%s", 
                           xpre, err_extra->size, xpost ); 
               break;
            case ExecAxs:
               if (VG_(clo_xml))
                  VG_(message)(Vg_UserMsg, "  <kind>InvalidJump</kind>");
               VG_(message)(Vg_UserMsg, 
                            "%sJump to the invalid address "
                            "stated on the next line%s",
                            xpre, xpost);
               break;
            default: 
               VG_(tool_panic)("mc_pp_Error(axskind)");
         }
         VG_(pp_ExeContext)( VG_(get_error_where)(err) );
         mc_pp_AddrInfo(VG_(get_error_address)(err), &err_extra->addrinfo);
         break;

      case OverlapErr: {
         OverlapExtra* ov_extra = (OverlapExtra*)VG_(get_error_extra)(err);
         if (VG_(clo_xml))
            VG_(message)(Vg_UserMsg, "  <kind>Overlap</kind>");
         if (ov_extra->len == -1)
            VG_(message)(Vg_UserMsg,
                         "%sSource and destination overlap in %s(%p, %p)%s",
                         xpre,
                         VG_(get_error_string)(err),
                         ov_extra->dst, ov_extra->src,
                         xpost);
         else
            VG_(message)(Vg_UserMsg,
                         "%sSource and destination overlap in %s(%p, %p, %d)%s",
                         xpre,
                         VG_(get_error_string)(err),
                         ov_extra->dst, ov_extra->src, ov_extra->len,
                         xpost);
         VG_(pp_ExeContext)( VG_(get_error_where)(err) );
         break;
      }
      case LeakErr: {
         MC_(pp_LeakError)(err_extra);
         break;
      }

      case IllegalMempoolErr:
         if (VG_(clo_xml))
            VG_(message)(Vg_UserMsg, "  <kind>InvalidMemPool</kind>");
         VG_(message)(Vg_UserMsg, "%sIllegal memory pool address%s",
                                  xpre, xpost);
         VG_(pp_ExeContext)( VG_(get_error_where)(err) );
         mc_pp_AddrInfo(VG_(get_error_address)(err), &err_extra->addrinfo);
         break;

      default: 
         VG_(printf)("Error:\n  unknown Memcheck error code %d\n",
                     VG_(get_error_kind)(err));
         VG_(tool_panic)("unknown error code in mc_pp_Error)");
   }
}

/*------------------------------------------------------------*/
/*--- Recording errors                                     ---*/
/*------------------------------------------------------------*/

/* These many bytes below %ESP are considered addressible if we're
   doing the --workaround-gcc296-bugs hack. */
#define VG_GCC296_BUG_STACK_SLOP 1024

/* Is this address within some small distance below %ESP?  Used only
   for the --workaround-gcc296-bugs kludge. */
static Bool is_just_below_ESP( Addr esp, Addr aa )
{
   if (esp > aa && (esp - aa) <= VG_GCC296_BUG_STACK_SLOP)
      return True;
   else
      return False;
}

static void mc_clear_MC_Error ( MC_Error* err_extra )
{
   err_extra->axskind             = ReadAxs;
   err_extra->size                = 0;
   err_extra->isUnaddr            = True;
   err_extra->addrinfo.akind      = Unknown;
   err_extra->addrinfo.blksize    = 0;
   err_extra->addrinfo.rwoffset   = 0;
   err_extra->addrinfo.lastchange = NULL;
   err_extra->addrinfo.stack_tid  = VG_INVALID_THREADID;
   err_extra->addrinfo.maybe_gcc  = False;
   err_extra->addrinfo.desc       = NULL;
}

/* This one called from generated code and non-generated code. */
static void mc_record_address_error ( ThreadId tid, Addr a, Int size,
                                      Bool isWrite )
{
   MC_Error err_extra;
   Bool      just_below_esp;

   just_below_esp = is_just_below_ESP( VG_(get_SP)(tid), a );

   /* If this is caused by an access immediately below %ESP, and the
      user asks nicely, we just ignore it. */
   if (MC_(clo_workaround_gcc296_bugs) && just_below_esp)
      return;

   mc_clear_MC_Error( &err_extra );
   err_extra.axskind = isWrite ? WriteAxs : ReadAxs;
   err_extra.size    = size;
   err_extra.addrinfo.akind     = Undescribed;
   err_extra.addrinfo.maybe_gcc = just_below_esp;
   VG_(maybe_record_error)( tid, AddrErr, a, /*s*/NULL, &err_extra );
}

/* These ones are called from non-generated code */

/* This is for memory errors in pthread functions, as opposed to pthread API
   errors which are found by the core. */
static void mc_record_core_mem_error ( ThreadId tid, Bool isUnaddr, Char* msg )
{
   MC_Error err_extra;

   mc_clear_MC_Error( &err_extra );
   err_extra.isUnaddr = isUnaddr;
   VG_(maybe_record_error)( tid, CoreMemErr, /*addr*/0, msg, &err_extra );
}

// Three kinds of param errors:
// - register arg contains undefined bytes
// - memory arg is unaddressable
// - memory arg contains undefined bytes
// 'isReg' and 'isUnaddr' dictate which of these it is.
static void mc_record_param_error ( ThreadId tid, Addr a, Bool isReg,
                                    Bool isUnaddr, Char* msg )
{
   MC_Error err_extra;

   tl_assert(VG_INVALID_THREADID != tid);
   if (isUnaddr) tl_assert(!isReg);    // unaddressable register is impossible
   mc_clear_MC_Error( &err_extra );
   err_extra.addrinfo.akind = ( isReg ? Register : Undescribed );
   err_extra.isUnaddr = isUnaddr;
   VG_(maybe_record_error)( tid, ParamErr, a, msg, &err_extra );
}

static void mc_record_jump_error ( ThreadId tid, Addr a )
{
   MC_Error err_extra;

   tl_assert(VG_INVALID_THREADID != tid);
   mc_clear_MC_Error( &err_extra );
   err_extra.axskind = ExecAxs;
   err_extra.size    = 1;     // size only used for suppressions
   err_extra.addrinfo.akind = Undescribed;
   VG_(maybe_record_error)( tid, AddrErr, a, /*s*/NULL, &err_extra );
}

void MC_(record_free_error) ( ThreadId tid, Addr a ) 
{
   MC_Error err_extra;

   tl_assert(VG_INVALID_THREADID != tid);
   mc_clear_MC_Error( &err_extra );
   err_extra.addrinfo.akind = Undescribed;
   VG_(maybe_record_error)( tid, FreeErr, a, /*s*/NULL, &err_extra );
}

void MC_(record_illegal_mempool_error) ( ThreadId tid, Addr a ) 
{
   MC_Error err_extra;

   tl_assert(VG_INVALID_THREADID != tid);
   mc_clear_MC_Error( &err_extra );
   err_extra.addrinfo.akind = Undescribed;
   VG_(maybe_record_error)( tid, IllegalMempoolErr, a, /*s*/NULL, &err_extra );
}

void MC_(record_freemismatch_error) ( ThreadId tid, Addr a, MC_Chunk* mc )
{
   MC_Error err_extra;
   AddrInfo* ai;

   tl_assert(VG_INVALID_THREADID != tid);
   mc_clear_MC_Error( &err_extra );
   ai = &err_extra.addrinfo;
   ai->akind      = Mallocd;     // Nb: not 'Freed'
   ai->blksize    = mc->size;
   ai->rwoffset   = (Int)a - (Int)mc->data;
   ai->lastchange = mc->where;
   VG_(maybe_record_error)( tid, FreeMismatchErr, a, /*s*/NULL, &err_extra );
}

static void mc_record_overlap_error ( ThreadId tid, 
                                      Char* function, OverlapExtra* ov_extra )
{
   VG_(maybe_record_error)( 
      tid, OverlapErr, /*addr*/0, /*s*/function, ov_extra );
}

Bool MC_(record_leak_error) ( ThreadId tid, /*LeakExtra*/void* leak_extra,
                              ExeContext* where, Bool print_record )
{
   return
   VG_(unique_error) ( tid, LeakErr, /*Addr*/0, /*s*/NULL,
                       /*extra*/leak_extra, where, print_record,
                       /*allow_GDB_attach*/False, /*count_error*/False );
}


/* Creates a copy of the 'extra' part, updates the copy with address info if
   necessary, and returns the copy. */
/* This one called from generated code and non-generated code. */
static void mc_record_value_error ( ThreadId tid, Int size )
{
   MC_Error err_extra;

   mc_clear_MC_Error( &err_extra );
   err_extra.size     = size;
   err_extra.isUnaddr = False;
   VG_(maybe_record_error)( tid, ValueErr, /*addr*/0, /*s*/NULL, &err_extra );
}

/* This called from non-generated code */

static void mc_record_user_error ( ThreadId tid, Addr a, Bool isWrite,
                                   Bool isUnaddr )
{
   MC_Error err_extra;

   tl_assert(VG_INVALID_THREADID != tid);
   mc_clear_MC_Error( &err_extra );
   err_extra.addrinfo.akind = Undescribed;
   err_extra.isUnaddr       = isUnaddr;
   VG_(maybe_record_error)( tid, UserErr, a, /*s*/NULL, &err_extra );
}

__attribute__ ((unused))
static Bool eq_AddrInfo ( VgRes res, AddrInfo* ai1, AddrInfo* ai2 )
{
   if (ai1->akind != Undescribed 
       && ai2->akind != Undescribed
       && ai1->akind != ai2->akind) 
      return False;
   if (ai1->akind == Freed || ai1->akind == Mallocd) {
      if (ai1->blksize != ai2->blksize)
         return False;
      if (!VG_(eq_ExeContext)(res, ai1->lastchange, ai2->lastchange))
         return False;
   }
   return True;
}

/* Compare error contexts, to detect duplicates.  Note that if they
   are otherwise the same, the faulting addrs and associated rwoffsets
   are allowed to be different.  */
static Bool mc_eq_Error ( VgRes res, Error* e1, Error* e2 )
{
   MC_Error* e1_extra = VG_(get_error_extra)(e1);
   MC_Error* e2_extra = VG_(get_error_extra)(e2);

   /* Guaranteed by calling function */
   tl_assert(VG_(get_error_kind)(e1) == VG_(get_error_kind)(e2));
   
   switch (VG_(get_error_kind)(e1)) {
      case CoreMemErr: {
         Char *e1s, *e2s;
         if (e1_extra->isUnaddr != e2_extra->isUnaddr) return False;
         e1s = VG_(get_error_string)(e1);
         e2s = VG_(get_error_string)(e2);
         if (e1s == e2s)                               return True;
         if (0 == VG_(strcmp)(e1s, e2s))               return True;
         return False;
      }

      // Perhaps we should also check the addrinfo.akinds for equality.
      // That would result in more error reports, but only in cases where
      // a register contains uninitialised bytes and points to memory
      // containing uninitialised bytes.  Currently, the 2nd of those to be
      // detected won't be reported.  That is (nearly?) always the memory
      // error, which is good.
      case ParamErr:
         if (0 != VG_(strcmp)(VG_(get_error_string)(e1),
                              VG_(get_error_string)(e2)))   return False;
         // fall through
      case UserErr:
         if (e1_extra->isUnaddr != e2_extra->isUnaddr)      return False;
         return True;

      case FreeErr:
      case FreeMismatchErr:
         /* JRS 2002-Aug-26: comparing addrs seems overkill and can
            cause excessive duplication of errors.  Not even AddrErr
            below does that.  So don't compare either the .addr field
            or the .addrinfo fields. */
         /* if (e1->addr != e2->addr) return False; */
         /* if (!eq_AddrInfo(res, &e1_extra->addrinfo, &e2_extra->addrinfo)) 
               return False;
         */
         return True;

      case AddrErr:
         /* if (e1_extra->axskind != e2_extra->axskind) return False; */
         if (e1_extra->size != e2_extra->size) return False;
         /*
         if (!eq_AddrInfo(res, &e1_extra->addrinfo, &e2_extra->addrinfo)) 
            return False;
         */
         return True;

      case ValueErr:
         if (e1_extra->size != e2_extra->size) return False;
         return True;

      case OverlapErr:
         return True;

      case LeakErr:
         VG_(tool_panic)("Shouldn't get LeakErr in mc_eq_Error,\n"
                         "since it's handled with VG_(unique_error)()!");

      case IllegalMempoolErr:
         return True;

      default: 
         VG_(printf)("Error:\n  unknown error code %d\n",
                     VG_(get_error_kind)(e1));
         VG_(tool_panic)("unknown error code in mc_eq_Error");
   }
}

/* Function used when searching MC_Chunk lists */
static Bool addr_is_in_MC_Chunk(MC_Chunk* mc, Addr a)
{
   // Nb: this is not quite right!  It assumes that the heap block has
   // a redzone of size MC_MALLOC_REDZONE_SZB.  That's true for malloc'd
   // blocks, but not necessarily true for custom-alloc'd blocks.  So
   // in some cases this could result in an incorrect description (eg.
   // saying "12 bytes after block A" when really it's within block B.
   // Fixing would require adding redzone size to MC_Chunks, though.
   return VG_(addr_is_in_block)( a, mc->data, mc->size,
                                 MC_MALLOC_REDZONE_SZB );
}

// Forward declaration
static Bool client_perm_maybe_describe( Addr a, AddrInfo* ai );

/* Describe an address as best you can, for error messages,
   putting the result in ai. */
static void describe_addr ( Addr a, AddrInfo* ai )
{
   MC_Chunk* mc;
   ThreadId   tid;
   Addr       stack_min, stack_max;

   /* Perhaps it's a user-def'd block? */
   if (client_perm_maybe_describe( a, ai ))
      return;

   /* Perhaps it's on a thread's stack? */
   VG_(thread_stack_reset_iter)();
   while ( VG_(thread_stack_next)(&tid, &stack_min, &stack_max) ) {
      if (stack_min <= a && a <= stack_max) {
         ai->akind     = Stack;
         ai->stack_tid = tid;
         return;
      }
   }
   /* Search for a recently freed block which might bracket it. */
   mc = MC_(get_freed_list_head)();
   while (mc) {
      if (addr_is_in_MC_Chunk(mc, a)) {
         ai->akind      = Freed;
         ai->blksize    = mc->size;
         ai->rwoffset   = (Int)a - (Int)mc->data;
         ai->lastchange = mc->where;
         return;
      }
      mc = mc->next; 
   }
   /* Search for a currently malloc'd block which might bracket it. */
   VG_(HT_ResetIter)(MC_(malloc_list));
   while ( (mc = VG_(HT_Next)(MC_(malloc_list))) ) {
      if (addr_is_in_MC_Chunk(mc, a)) {
         ai->akind      = Mallocd;
         ai->blksize    = mc->size;
         ai->rwoffset   = (Int)(a) - (Int)mc->data;
         ai->lastchange = mc->where;
         return;
      }
   }
   /* Clueless ... */
   ai->akind = Unknown;
   return;
}

/* Updates the copy with address info if necessary (but not for all errors). */
static UInt mc_update_extra( Error* err )
{
   switch (VG_(get_error_kind)(err)) {
   // These two don't have addresses associated with them, and so don't
   // need any updating.
   case CoreMemErr:
   case ValueErr: {
      MC_Error* extra = VG_(get_error_extra)(err);
      tl_assert(Unknown == extra->addrinfo.akind);
      return sizeof(MC_Error);
   }

   // ParamErrs sometimes involve a memory address; call describe_addr() in
   // this case.
   case ParamErr: {
      MC_Error* extra = VG_(get_error_extra)(err);
      tl_assert(Undescribed == extra->addrinfo.akind ||
                Register    == extra->addrinfo.akind);
      if (Undescribed == extra->addrinfo.akind)
         describe_addr ( VG_(get_error_address)(err), &(extra->addrinfo) );
      return sizeof(MC_Error);
   }

   // These four always involve a memory address.
   case AddrErr: 
   case UserErr:
   case FreeErr:
   case IllegalMempoolErr: {
      MC_Error* extra = VG_(get_error_extra)(err);
      tl_assert(Undescribed == extra->addrinfo.akind);
      describe_addr ( VG_(get_error_address)(err), &(extra->addrinfo) );
      return sizeof(MC_Error);
   }

   // FreeMismatchErrs have already had their address described;  this is
   // possible because we have the MC_Chunk on hand when the error is
   // detected.  However, the address may be part of a user block, and if so
   // we override the pre-determined description with a user block one.
   case FreeMismatchErr: {
      MC_Error* extra = VG_(get_error_extra)(err);
      tl_assert(extra && Mallocd == extra->addrinfo.akind);
      (void)client_perm_maybe_describe( VG_(get_error_address)(err), 
                                        &(extra->addrinfo) );
      return sizeof(MC_Error);
   }

   // No memory address involved with these ones.  Nb:  for LeakErrs the
   // returned size does not matter -- LeakErrs are always shown with
   // VG_(unique_error)() so they're not copied.
   case LeakErr:     return 0;
   case OverlapErr:  return sizeof(OverlapExtra);

   default: VG_(tool_panic)("mc_update_extra: bad errkind");
   }
}

/*------------------------------------------------------------*/
/*--- Suppressions                                         ---*/
/*------------------------------------------------------------*/

static Bool mc_recognised_suppression ( Char* name, Supp* su )
{
   SuppKind skind;

   if      (VG_STREQ(name, "Param"))   skind = ParamSupp;
   else if (VG_STREQ(name, "CoreMem")) skind = CoreMemSupp;
   else if (VG_STREQ(name, "Addr1"))   skind = Addr1Supp;
   else if (VG_STREQ(name, "Addr2"))   skind = Addr2Supp;
   else if (VG_STREQ(name, "Addr4"))   skind = Addr4Supp;
   else if (VG_STREQ(name, "Addr8"))   skind = Addr8Supp;
   else if (VG_STREQ(name, "Addr16"))  skind = Addr16Supp;
   else if (VG_STREQ(name, "Free"))    skind = FreeSupp;
   else if (VG_STREQ(name, "Leak"))    skind = LeakSupp;
   else if (VG_STREQ(name, "Overlap")) skind = OverlapSupp;
   else if (VG_STREQ(name, "Mempool")) skind = MempoolSupp;
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

static 
Bool mc_read_extra_suppression_info ( Int fd, Char* buf, Int nBuf, Supp *su )
{
   Bool eof;

   if (VG_(get_supp_kind)(su) == ParamSupp) {
      eof = VG_(get_line) ( fd, buf, nBuf );
      if (eof) return False;
      VG_(set_supp_string)(su, VG_(strdup)(buf));
   }
   return True;
}

static Bool mc_error_matches_suppression(Error* err, Supp* su)
{
   Int        su_size;
   MC_Error* err_extra = VG_(get_error_extra)(err);
   ErrorKind  ekind     = VG_(get_error_kind )(err);

   switch (VG_(get_supp_kind)(su)) {
      case ParamSupp:
         return (ekind == ParamErr 
              && VG_STREQ(VG_(get_error_string)(err), 
                          VG_(get_supp_string)(su)));

      case CoreMemSupp:
         return (ekind == CoreMemErr
              && VG_STREQ(VG_(get_error_string)(err),
                          VG_(get_supp_string)(su)));

      case Value0Supp: su_size = 0; goto value_case;
      case Value1Supp: su_size = 1; goto value_case;
      case Value2Supp: su_size = 2; goto value_case;
      case Value4Supp: su_size = 4; goto value_case;
      case Value8Supp: su_size = 8; goto value_case;
      case Value16Supp:su_size =16; goto value_case;
      value_case:
         return (ekind == ValueErr && err_extra->size == su_size);

      case Addr1Supp: su_size = 1; goto addr_case;
      case Addr2Supp: su_size = 2; goto addr_case;
      case Addr4Supp: su_size = 4; goto addr_case;
      case Addr8Supp: su_size = 8; goto addr_case;
      case Addr16Supp:su_size =16; goto addr_case;
      addr_case:
         return (ekind == AddrErr && err_extra->size == su_size);

      case FreeSupp:
         return (ekind == FreeErr || ekind == FreeMismatchErr);

      case OverlapSupp:
         return (ekind = OverlapErr);

      case LeakSupp:
         return (ekind == LeakErr);

      case MempoolSupp:
         return (ekind == IllegalMempoolErr);

      default:
         VG_(printf)("Error:\n"
                     "  unknown suppression type %d\n",
                     VG_(get_supp_kind)(su));
         VG_(tool_panic)("unknown suppression type in "
                         "MC_(error_matches_suppression)");
   }
}

static Char* mc_get_error_name ( Error* err )
{
   Char* s;
   switch (VG_(get_error_kind)(err)) {
   case ParamErr:           return "Param";
   case UserErr:            return NULL;  /* Can't suppress User errors */
   case FreeMismatchErr:    return "Free";
   case IllegalMempoolErr:  return "Mempool";
   case FreeErr:            return "Free";
   case AddrErr:            
      switch ( ((MC_Error*)VG_(get_error_extra)(err))->size ) {
      case 1:               return "Addr1";
      case 2:               return "Addr2";
      case 4:               return "Addr4";
      case 8:               return "Addr8";
      case 16:              return "Addr16";
      default:              VG_(tool_panic)("unexpected size for Addr");
      }
     
   case ValueErr:
      switch ( ((MC_Error*)VG_(get_error_extra)(err))->size ) {
      case 0:               return "Cond";
      case 1:               return "Value1";
      case 2:               return "Value2";
      case 4:               return "Value4";
      case 8:               return "Value8";
      case 16:              return "Value16";
      default:              VG_(tool_panic)("unexpected size for Value");
      }
   case CoreMemErr:         return "CoreMem";
   case OverlapErr:         return "Overlap";
   case LeakErr:            return "Leak";
   default:                 VG_(tool_panic)("get_error_name: unexpected type");
   }
   VG_(printf)(s);
}

static void mc_print_extra_suppression_info ( Error* err )
{
   if (ParamErr == VG_(get_error_kind)(err)) {
      VG_(printf)("   %s\n", VG_(get_error_string)(err));
   }
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

/* If any part of '_a' indicated by the mask is 1, either
   '_a' is not naturally '_sz'-aligned, or it exceeds the range
   covered by the primary map. */
#define UNALIGNED_OR_HIGH(_a,_sz)   ((_a) & MASK((_sz)))
#define MASK(_sz)   ( ~((0x10000-(_sz)) | ((N_PRIMARY_MAP-1) << 16)) )


/* ------------------------ Size = 8 ------------------------ */

static inline __attribute__((always_inline))
ULong mc_LOADV8 ( Addr a, Bool isBigEndian )
{
   UWord   sm_off64, vabits64;
   SecMap* sm;

   PROF_EVENT(200, "mc_LOADV8");

   if (VG_DEBUG_MEMORY >= 2)
      return mc_LOADVn_slow( a, 8, isBigEndian );

   if (EXPECTED_NOT_TAKEN( UNALIGNED_OR_HIGH(a,8) )) {
      PROF_EVENT(201, "mc_LOADV8-slow1");
      return (UWord)mc_LOADVn_slow( a, 8, isBigEndian );
   }

   sm       = get_secmap_readable_low(a);
   sm_off64 = SM_OFF_64(a);
   vabits64 = ((UShort*)(sm->vabits32))[sm_off64];

   // Convert V bits from compact memory form to expanded register form.
   if (EXPECTED_TAKEN(vabits64 == VA_BITS64_READABLE)) {
      return V_BITS64_VALID;
   } else if (EXPECTED_TAKEN(vabits64 == VA_BITS64_WRITABLE)) {
      return V_BITS64_INVALID;
   } else {
      /* Slow case: the 8 bytes are not all-readable or all-writable. */
      PROF_EVENT(202, "mc_LOADV8-slow2");
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
void mc_STOREV8 ( Addr a, ULong vbytes, Bool isBigEndian )
{
   UWord   sm_off64, vabits64;
   SecMap* sm;

   PROF_EVENT(210, "mc_STOREV8");

   // XXX: this slow case seems to be marginally faster than the fast case!
   // Investigate further.
   if (VG_DEBUG_MEMORY >= 2) {
      mc_STOREVn_slow( a, 8, vbytes, isBigEndian );
      return;
   }

   if (EXPECTED_NOT_TAKEN( UNALIGNED_OR_HIGH(a,8) )) {
      PROF_EVENT(211, "mc_STOREV8-slow1");
      mc_STOREVn_slow( a, 8, vbytes, isBigEndian );
      return;
   }

   sm       = get_secmap_readable_low(a);
   sm_off64 = SM_OFF_64(a);
   vabits64 = ((UShort*)(sm->vabits32))[sm_off64];

   if (EXPECTED_TAKEN( !is_distinguished_sm(sm) && 
                       (VA_BITS64_READABLE == vabits64 ||
                        VA_BITS64_WRITABLE == vabits64) ))
   {
      /* Handle common case quickly: a is suitably aligned, */
      /* is mapped, and is addressible. */
      // Convert full V-bits in register to compact 2-bit form.
      // XXX: is it best to check for VALID before INVALID?
      if (V_BITS64_VALID == vbytes) {
         ((UShort*)(sm->vabits32))[sm_off64] = (UShort)VA_BITS64_READABLE;
      } else if (V_BITS64_INVALID == vbytes) {
         ((UShort*)(sm->vabits32))[sm_off64] = (UShort)VA_BITS64_WRITABLE;
      } else {
         /* Slow but general case -- writing partially defined bytes. */
         PROF_EVENT(212, "mc_STOREV8-slow2");
         mc_STOREVn_slow( a, 8, vbytes, isBigEndian );
      }
   } else {
      /* Slow but general case. */
      PROF_EVENT(213, "mc_STOREV8-slow3");
      mc_STOREVn_slow( a, 8, vbytes, isBigEndian );
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
   UWord   sm_off, vabits32;
   SecMap* sm;

   PROF_EVENT(220, "mc_LOADV4");

   if (VG_DEBUG_MEMORY >= 2)
      return (UWord)mc_LOADVn_slow( a, 4, isBigEndian );

   if (EXPECTED_NOT_TAKEN( UNALIGNED_OR_HIGH(a,4) )) {
      PROF_EVENT(221, "mc_LOADV4-slow1");
      return (UWord)mc_LOADVn_slow( a, 4, isBigEndian );
   }

   sm       = get_secmap_readable_low(a);
   sm_off   = SM_OFF(a);
   vabits32 = sm->vabits32[sm_off];

   // XXX: copy this comment to all the LOADV* functions.
   // Handle common case quickly: a is suitably aligned, is mapped, and is
   // addressible.
   // Convert V bits from compact memory form to expanded register form
   // For 64-bit platforms, set the high 32 bits of retval to 1 (undefined).
   // Almost certainly not necessary, but be paranoid.
   if (EXPECTED_TAKEN(vabits32 == VA_BITS32_READABLE)) {
      return ((UWord)0xFFFFFFFF00000000ULL | (UWord)V_BITS32_VALID);
   } else if (EXPECTED_TAKEN(vabits32 == VA_BITS32_WRITABLE)) {
      return ((UWord)0xFFFFFFFF00000000ULL | (UWord)V_BITS32_INVALID);
   } else {
      /* Slow case: the 4 bytes are not all-readable or all-writable. */
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
void mc_STOREV4 ( Addr a, UWord vbytes, Bool isBigEndian )
{
   UWord   sm_off, vabits32;
   SecMap* sm;

   PROF_EVENT(230, "mc_STOREV4");

   if (VG_DEBUG_MEMORY >= 2) {
      mc_STOREVn_slow( a, 4, (ULong)vbytes, isBigEndian );
      return;
   }

   if (EXPECTED_NOT_TAKEN( UNALIGNED_OR_HIGH(a,4) )) {
      PROF_EVENT(231, "mc_STOREV4-slow1");
      mc_STOREVn_slow( a, 4, (ULong)vbytes, isBigEndian );
      return;
   }

   sm       = get_secmap_readable_low(a);
   sm_off   = SM_OFF(a);
   vabits32 = sm->vabits32[sm_off];

//---------------------------------------------------------------------------
#if 1
   // Cleverness:  sometimes we don't have to write the shadow memory at
   // all, if we can tell that what we want to write is the same as what is
   // already there.
   if (V_BITS32_VALID == vbytes) {
      if (vabits32 == (UInt)VA_BITS32_READABLE) {
         return;
      } else if (!is_distinguished_sm(sm) && VA_BITS32_WRITABLE == vabits32) {
         sm->vabits32[sm_off] = (UInt)VA_BITS32_READABLE;
      } else {
         // not readable/writable, or distinguished and changing state
         PROF_EVENT(232, "mc_STOREV4-slow2");
         mc_STOREVn_slow( a, 4, (ULong)vbytes, isBigEndian );
      }
   } else if (V_BITS32_INVALID == vbytes) {
      if (vabits32 == (UInt)VA_BITS32_WRITABLE) {
         return;
      } else if (!is_distinguished_sm(sm) && VA_BITS32_READABLE == vabits32) {
         sm->vabits32[sm_off] = (UInt)VA_BITS32_WRITABLE;
      } else {
         // not readable/writable, or distinguished and changing state
         PROF_EVENT(233, "mc_STOREV4-slow3");
         mc_STOREVn_slow( a, 4, (ULong)vbytes, isBigEndian );
      }
   } else {
      // Partially defined word
      PROF_EVENT(234, "mc_STOREV4-slow4");
      mc_STOREVn_slow( a, 4, (ULong)vbytes, isBigEndian );
   }
//---------------------------------------------------------------------------
#else
   if (EXPECTED_TAKEN( !is_distinguished_sm(sm) && 
                       (VA_BITS32_READABLE == vabits32 ||
                        VA_BITS32_WRITABLE == vabits32) ))
   {
      /* Handle common case quickly: a is suitably aligned, */
      /* is mapped, and is addressible. */
      // Convert full V-bits in register to compact 2-bit form.
      // XXX: is it best to check for VALID before INVALID?
      if (V_BITS32_VALID == vbytes) {
         sm->vabits32[sm_off] = VA_BITS32_READABLE;
      } else if (V_BITS32_INVALID == vbytes) {
         sm->vabits32[sm_off] = VA_BITS32_WRITABLE;
      } else {
         /* Slow but general case -- writing partially defined bytes. */
         PROF_EVENT(232, "mc_STOREV4-slow2");
         mc_STOREVn_slow( a, 4, (ULong)vbytes, isBigEndian );
      }
   } else {
      /* Slow but general case. */
      PROF_EVENT(233, "mc_STOREV4-slow3");
      mc_STOREVn_slow( a, 4, (ULong)vbytes, isBigEndian );
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
UWord mc_LOADV2 ( Addr a, Bool isBigEndian )
{
   UWord   sm_off, vabits32;
   SecMap* sm;

   PROF_EVENT(240, "mc_LOADV2");

   if (VG_DEBUG_MEMORY >= 2)
      return (UWord)mc_LOADVn_slow( a, 2, isBigEndian );

   if (EXPECTED_NOT_TAKEN( UNALIGNED_OR_HIGH(a,2) )) {
      PROF_EVENT(241, "mc_LOADV2-slow1");
      return (UWord)mc_LOADVn_slow( a, 2, isBigEndian );
   }

   sm       = get_secmap_readable_low(a);
   sm_off   = SM_OFF(a);
   vabits32 = sm->vabits32[sm_off];
   // Convert V bits from compact memory form to expanded register form
   // XXX: checking READABLE before WRITABLE a good idea?
   // XXX: set the high 16/48 bits of retval to 1?
   if (EXPECTED_TAKEN(vabits32 == VA_BITS32_READABLE)) {
      return V_BITS16_VALID;
   } else if (EXPECTED_TAKEN(vabits32 == VA_BITS32_WRITABLE)) {
      return V_BITS16_INVALID;
   } else {
      /* Slow case: the 4 (yes, 4) bytes are not all-readable or all-writable. */
      PROF_EVENT(242, "mc_LOADV2-slow2");
      return (UWord)mc_LOADVn_slow( a, 2, isBigEndian );
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
void mc_STOREV2 ( Addr a, UWord vbytes, Bool isBigEndian )
{
   UWord   sm_off, vabits32;
   SecMap* sm;

   PROF_EVENT(250, "mc_STOREV2");

   if (VG_DEBUG_MEMORY >= 2) {
      mc_STOREVn_slow( a, 2, (ULong)vbytes, isBigEndian );
      return;
   }

   if (EXPECTED_NOT_TAKEN( UNALIGNED_OR_HIGH(a,2) )) {
      PROF_EVENT(251, "mc_STOREV2-slow1");
      mc_STOREVn_slow( a, 2, (ULong)vbytes, isBigEndian );
      return;
   }

   sm       = get_secmap_readable_low(a);
   sm_off   = SM_OFF(a);
   vabits32 = sm->vabits32[sm_off];
   if (EXPECTED_TAKEN( !is_distinguished_sm(sm) && 
                       (VA_BITS32_READABLE == vabits32 ||
                        VA_BITS32_WRITABLE == vabits32) ))
   {
      /* Handle common case quickly: a is suitably aligned, */
      /* is mapped, and is addressible. */
      // Convert full V-bits in register to compact 2-bit form.
      // XXX: is it best to check for VALID before INVALID?
      if (V_BITS16_VALID == vbytes) {
         insert_vabits16_into_vabits32( a, VA_BITS16_READABLE,
                                        &(sm->vabits32[sm_off]) );
      } else if (V_BITS16_INVALID == vbytes) {
         insert_vabits16_into_vabits32( a, VA_BITS16_WRITABLE,
                                        &(sm->vabits32[sm_off]) );
      } else {
         /* Slow but general case -- writing partially defined bytes. */
         PROF_EVENT(252, "mc_STOREV2-slow2");
         mc_STOREVn_slow( a, 2, (ULong)vbytes, isBigEndian );
      }
   } else {
      /* Slow but general case. */
      PROF_EVENT(253, "mc_STOREV2-slow3");
      mc_STOREVn_slow( a, 2, (ULong)vbytes, isBigEndian );
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
UWord MC_(helperc_LOADV1) ( Addr a )
{
   UWord   sm_off, vabits32;
   SecMap* sm;

   PROF_EVENT(260, "helperc_LOADV1");

#  if VG_DEBUG_MEMORY >= 2
   return (UWord)mc_LOADVn_slow( a, 1, False/*irrelevant*/ );
#  endif

   if (EXPECTED_NOT_TAKEN( UNALIGNED_OR_HIGH(a,1) )) {
      PROF_EVENT(261, "helperc_LOADV1-slow1");
      return (UWord)mc_LOADVn_slow( a, 1, False/*irrelevant*/ );
   }

   sm       = get_secmap_readable_low(a);
   sm_off   = SM_OFF(a);
   vabits32 = sm->vabits32[sm_off];
   // Convert V bits from compact memory form to expanded register form
   /* Handle common case quickly: a is mapped, and the entire
      word32 it lives in is addressible. */
   // XXX: set the high 24/56 bits of retval to 1?
   if      (vabits32 == VA_BITS32_READABLE) { return V_BITS8_VALID;   }
   else if (vabits32 == VA_BITS32_WRITABLE) { return V_BITS8_INVALID; }
   else {
      // XXX: Could just do the slow but general case if this is uncommon,
      //      but removing it slowed perf/bz2 down some...
      // The 4 (yes, 4) bytes are not all-readable or all-writable, check
      // the single byte.
      UChar vabits8 = extract_vabits8_from_vabits32(a, vabits32);
      if      (vabits8 == VA_BITS8_READABLE) { return V_BITS8_VALID;   }
      else if (vabits8 == VA_BITS8_WRITABLE) { return V_BITS8_INVALID; }
      else {
         /* Slow case: the byte is not all-readable or all-writable. */
         PROF_EVENT(262, "helperc_LOADV1-slow2");
         return (UWord)mc_LOADVn_slow( a, 1, False/*irrelevant*/ );
      }
   }
}


VG_REGPARM(2)
void MC_(helperc_STOREV1) ( Addr a, UWord vbyte )
{
   UWord   sm_off, vabits32;
   SecMap* sm;

   PROF_EVENT(270, "helperc_STOREV1");

#  if VG_DEBUG_MEMORY >= 2
   mc_STOREVn_slow( a, 1, (ULong)vbyte, False/*irrelevant*/ );
   return;
#  endif

   if (EXPECTED_NOT_TAKEN( UNALIGNED_OR_HIGH(a,1) )) {
      PROF_EVENT(271, "helperc_STOREV1-slow1");
      mc_STOREVn_slow( a, 1, (ULong)vbyte, False/*irrelevant*/ );
      return;
   }

   sm       = get_secmap_readable_low(a);
   sm_off   = SM_OFF(a);
   vabits32 = sm->vabits32[sm_off];
   if (EXPECTED_TAKEN( !is_distinguished_sm(sm) && 
                       (VA_BITS32_READABLE == vabits32 ||
                        VA_BITS32_WRITABLE == vabits32) ))
   {
      /* Handle common case quickly: a is mapped, the entire word32 it
         lives in is addressible. */
      // Convert full V-bits in register to compact 2-bit form.
      // XXX: is it best to check for VALID before INVALID?
      if (V_BITS8_VALID == vbyte) {
         insert_vabits8_into_vabits32( a, VA_BITS8_READABLE,
                                       &(sm->vabits32[sm_off]) );
      } else if (V_BITS8_INVALID == vbyte) {
         insert_vabits8_into_vabits32( a, VA_BITS8_WRITABLE,
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
//zz       if (get_abits4_ALIGNED((Addr)dataP) != V_NIBBLE_VALID) {
//zz          addressibleD = False;
//zz          break;
//zz       }
//zz       if (get_abits4_ALIGNED((Addr)vbitsP) != V_NIBBLE_VALID) {
//zz          addressibleV = False;
//zz          break;
//zz       }
//zz    }
//zz    if (!addressibleD) {
//zz       mc_record_address_error( tid, (Addr)dataP, 4, 
//zz                                   setting ? True : False );
//zz       return 3;
//zz    }
//zz    if (!addressibleV) {
//zz       mc_record_address_error( tid, (Addr)vbitsP, 4, 
//zz                                   setting ? False : True );
//zz       return 3;
//zz    }
//zz  
//zz    /* Do the copy */
//zz    if (setting) {
//zz       /* setting */
//zz       for (i = 0; i < szW; i++) {
//zz          if (get_vbytes4_ALIGNED( (Addr)&vbits[i] ) != V_WORD_VALID)
//zz             mc_record_value_error(tid, 4);
//zz          set_vbytes4_ALIGNED( (Addr)&data[i], vbits[i] );
//zz       }
//zz    } else {
//zz       /* getting */
//zz       for (i = 0; i < szW; i++) {
//zz          vbits[i] = get_vbytes4_ALIGNED( (Addr)&data[i] );
//zz          set_vbytes4_ALIGNED( (Addr)&vbits[i], V_WORD_VALID );
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
   MC_(do_detect_memory_leaks) ( 
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

   tl_assert(V_BIT_INVALID  == 1);
   tl_assert(V_BIT_VALID    == 0);
   tl_assert(V_BITS8_INVALID == 0xFF);
   tl_assert(V_BITS8_VALID   == 0);

   /* Build the 3 distinguished secondaries */
   sm = &sm_distinguished[SM_DIST_NOACCESS];
   for (i = 0; i < SM_CHUNKS; i++) sm->vabits32[i] = VA_BITS32_NOACCESS;

   sm = &sm_distinguished[SM_DIST_WRITABLE];
   for (i = 0; i < SM_CHUNKS; i++) sm->vabits32[i] = VA_BITS32_WRITABLE;

   sm = &sm_distinguished[SM_DIST_READABLE];
   for (i = 0; i < SM_CHUNKS; i++) sm->vabits32[i] = VA_BITS32_READABLE;

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
      if (sm->vabits32[i] != VA_BITS32_NOACCESS)
         bad = True;

   /* Check writable. */
   sm = &sm_distinguished[SM_DIST_WRITABLE];
   for (i = 0; i < SM_CHUNKS; i++)
      if (sm->vabits32[i] != VA_BITS32_WRITABLE)
         bad = True;

   /* Check readable. */
   sm = &sm_distinguished[SM_DIST_READABLE];
   for (i = 0; i < SM_CHUNKS; i++)
      if (sm->vabits32[i] != VA_BITS32_READABLE)
         bad = True;

   if (bad) {
      VG_(printf)("memcheck expensive sanity: "
                  "distinguished_secondaries have changed\n");
      return False;
   }

   /* If we're not checking for undefined value errors, the secondary V bit
    * table should be empty. */
   if (!MC_(clo_undef_value_errors)) {
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

Bool          MC_(clo_partial_loads_ok)       = False;
Int           MC_(clo_freelist_vol)           = 5000000;
LeakCheckMode MC_(clo_leak_check)             = LC_Summary;
VgRes         MC_(clo_leak_resolution)        = Vg_LowRes;
Bool          MC_(clo_show_reachable)         = False;
Bool          MC_(clo_workaround_gcc296_bugs) = False;
Bool          MC_(clo_undef_value_errors)     = True;

static Bool mc_process_cmd_line_options(Char* arg)
{
	VG_BOOL_CLO(arg, "--partial-loads-ok",      MC_(clo_partial_loads_ok))
   else VG_BOOL_CLO(arg, "--show-reachable",        MC_(clo_show_reachable))
   else VG_BOOL_CLO(arg, "--workaround-gcc296-bugs",MC_(clo_workaround_gcc296_bugs))

   else VG_BOOL_CLO(arg, "--undef-value-errors",    MC_(clo_undef_value_errors))
   
   else VG_BNUM_CLO(arg, "--freelist-vol",  MC_(clo_freelist_vol), 0, 1000000000)
   
   else if (VG_CLO_STREQ(arg, "--leak-check=no"))
      MC_(clo_leak_check) = LC_Off;
   else if (VG_CLO_STREQ(arg, "--leak-check=summary"))
      MC_(clo_leak_check) = LC_Summary;
   else if (VG_CLO_STREQ(arg, "--leak-check=yes") ||
	    VG_CLO_STREQ(arg, "--leak-check=full"))
      MC_(clo_leak_check) = LC_Full;

   else if (VG_CLO_STREQ(arg, "--leak-resolution=low"))
      MC_(clo_leak_resolution) = Vg_LowRes;
   else if (VG_CLO_STREQ(arg, "--leak-resolution=med"))
      MC_(clo_leak_resolution) = Vg_MedRes;
   else if (VG_CLO_STREQ(arg, "--leak-resolution=high"))
      MC_(clo_leak_resolution) = Vg_HighRes;

   else
      return VG_(replacement_malloc_process_cmd_line_option)(arg);

   return True;
}

static void mc_print_usage(void)
{  
   VG_(printf)(
"    --leak-check=no|summary|full     search for memory leaks at exit?  [summary]\n"
"    --leak-resolution=low|med|high   how much bt merging in leak check [low]\n"
"    --show-reachable=no|yes          show reachable blocks in leak check? [no]\n"
"    --undef-value-errors=no|yes      check for undefined value errors [yes]\n"
"    --partial-loads-ok=no|yes        too hard to explain here; see manual [no]\n"
"    --freelist-vol=<number>          volume of freed blocks queue [5000000]\n"
"    --workaround-gcc296-bugs=no|yes  self explanatory [no]\n"
   );
   VG_(replacement_malloc_print_usage)();
}

static void mc_print_debug_usage(void)
{  
   VG_(replacement_malloc_print_debug_usage)();
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
         MC_Mempool* mp = VG_(HT_lookup)(MC_(mempool_list),
                                          (UWord)cgbs[i].start);
         if (mp != NULL) {
            if (mp->chunks != NULL) {
               MC_Chunk* mc;
               VG_(HT_ResetIter)(mp->chunks);
               while ( (mc = VG_(HT_Next)(mp->chunks)) ) {
                  if (addr_is_in_MC_Chunk(mc, a)) {
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

      case VG_USERREQ__COUNT_LEAKS: { /* count leaked bytes */
         UWord** argp = (UWord**)arg;
         // MC_(bytes_leaked) et al were set by the last leak check (or zero
         // if no prior leak checks performed).
         *argp[1] = MC_(bytes_leaked) + MC_(bytes_indirect);
         *argp[2] = MC_(bytes_dubious);
         *argp[3] = MC_(bytes_reachable);
         *argp[4] = MC_(bytes_suppressed);
         // there is no argp[5]
         //*argp[5] = MC_(bytes_indirect);
         // XXX need to make *argp[1-4] readable
         *ret = 0;
         return True;
      }
      case VG_USERREQ__MALLOCLIKE_BLOCK: {
         Addr p         = (Addr)arg[1];
         SizeT sizeB    =       arg[2];
         UInt rzB       =       arg[3];
         Bool is_zeroed = (Bool)arg[4];

         MC_(new_block) ( tid, p, sizeB, /*ignored*/0, rzB, is_zeroed, 
                          MC_AllocCustom, MC_(malloc_list) );
         return True;
      }
      case VG_USERREQ__FREELIKE_BLOCK: {
         Addr p         = (Addr)arg[1];
         UInt rzB       =       arg[2];

         MC_(handle_free) ( tid, p, rzB, MC_AllocCustom );
         return True;
      }

      case _VG_USERREQ__MEMCHECK_RECORD_OVERLAP_ERROR: {
         Char*         s     = (Char*)        arg[1];
         OverlapExtra* extra = (OverlapExtra*)arg[2];
         mc_record_overlap_error(tid, s, extra);
         return True;
      }

      case VG_USERREQ__CREATE_MEMPOOL: {
         Addr pool      = (Addr)arg[1];
         UInt rzB       =       arg[2];
         Bool is_zeroed = (Bool)arg[3];

         MC_(create_mempool) ( pool, rzB, is_zeroed );
         return True;
      }

      case VG_USERREQ__DESTROY_MEMPOOL: {
         Addr pool      = (Addr)arg[1];

         MC_(destroy_mempool) ( pool );
         return True;
      }

      case VG_USERREQ__MEMPOOL_ALLOC: {
         Addr pool      = (Addr)arg[1];
         Addr addr      = (Addr)arg[2];
         UInt size      =       arg[3];

         MC_(mempool_alloc) ( tid, pool, addr, size );
         return True;
      }

      case VG_USERREQ__MEMPOOL_FREE: {
         Addr pool      = (Addr)arg[1];
         Addr addr      = (Addr)arg[2];

         MC_(mempool_free) ( pool, addr );
         return True;
      }

      default:
         VG_(message)(Vg_UserMsg, 
                      "Warning: unknown memcheck client request code %llx",
                      (ULong)arg[0]);
         return False;
   }
   return True;
}

/*------------------------------------------------------------*/
/*--- Crude profiling machinery.                           ---*/
/*------------------------------------------------------------*/

/* Event index.  If just the name of the fn is given, this means the
   number of calls to the fn.  Otherwise it is the specified event.
   Ones marked 'M' are MemCheck only.  Ones marked 'A' are AddrCheck only.
   The rest are shared.

   10   alloc_secondary_map

   20   get_abit
M  21   get_vbyte
   22   set_abit
M  23   set_vbyte
   24   get_abits4_ALIGNED
M  25   get_vbytes4_ALIGNED       

   30   set_address_range_perms
   31   set_address_range_perms(lower byte loop)
   32   set_address_range_perms(quadword loop)
   33   set_address_range_perms(upper byte loop)
   
   35   make_noaccess
   36   make_writable
   37   make_readable
A  38   make_accessible

   40   copy_address_range_state
   41   copy_address_range_state(byte loop)
   42   check_writable
   43   check_writable(byte loop)
   44   check_readable
   45   check_readable(byte loop)
   46   check_readable_asciiz
   47   check_readable_asciiz(byte loop)
A  48   check_accessible
A  49   check_accessible(byte loop)

   50   make_noaccess_aligned
   51   make_writable_aligned

M  60   helperc_LOADV4
M  61   helperc_STOREV4
M  62   helperc_LOADV2
M  63   helperc_STOREV2
M  64   helperc_LOADV1
M  65   helperc_STOREV1

A  66   helperc_ACCESS4
A  67   helperc_ACCESS2
A  68   helperc_ACCESS1

M  70   rim_rd_V4_SLOWLY
M  71   rim_wr_V4_SLOWLY
M  72   rim_rd_V2_SLOWLY
M  73   rim_wr_V2_SLOWLY
M  74   rim_rd_V1_SLOWLY
M  75   rim_wr_V1_SLOWLY

A  76   ACCESS4_SLOWLY
A  77   ACCESS2_SLOWLY
A  78   ACCESS1_SLOWLY

   80   fpu_read
   81   fpu_read aligned 4
   82   fpu_read aligned 8
   83   fpu_read 2
   84   fpu_read 10/28/108/512

M  85   fpu_write
M  86   fpu_write aligned 4
M  87   fpu_write aligned 8
M  88   fpu_write 2
M  89   fpu_write 10/28/108/512

   90   fpu_access
   91   fpu_access aligned 4
   92   fpu_access aligned 8
   93   fpu_access 2
   94   fpu_access 10/28/108/512

   100  fpu_access_check_SLOWLY
   101  fpu_access_check_SLOWLY(byte loop)

   110  new_mem_stack_4
   111  new_mem_stack_8
   112  new_mem_stack_12
   113  new_mem_stack_16
   114  new_mem_stack_32
   115  new_mem_stack

   120  die_mem_stack_4
   121  die_mem_stack_8
   122  die_mem_stack_12
   123  die_mem_stack_16
   124  die_mem_stack_32
   125  die_mem_stack
*/

#ifdef MC_PROFILE_MEMORY

UInt   MC_(event_ctr)[N_PROF_EVENTS];
HChar* MC_(event_ctr_name)[N_PROF_EVENTS];

static void init_prof_mem ( void )
{
   Int i;
   for (i = 0; i < N_PROF_EVENTS; i++) {
      MC_(event_ctr)[i] = 0;
      MC_(event_ctr_name)[i] = NULL;
   }
}

static void done_prof_mem ( void )
{
   Int  i;
   Bool spaced = False;
   for (i = 0; i < N_PROF_EVENTS; i++) {
      if (!spaced && (i % 10) == 0) {
         VG_(printf)("\n");
         spaced = True;
      }
      if (MC_(event_ctr)[i] > 0) {
         spaced = False;
         VG_(printf)( "prof mem event %3d: %9d   %s\n", 
                      i, MC_(event_ctr)[i],
                      MC_(event_ctr_name)[i] 
                         ? MC_(event_ctr_name)[i] : "unnamed");
      }
   }
}

#else

static void init_prof_mem ( void ) { }
static void done_prof_mem ( void ) { }

#endif

/*------------------------------------------------------------*/
/*--- Setup and finalisation                               ---*/
/*------------------------------------------------------------*/

static void mc_post_clo_init ( void )
{
   /* If we've been asked to emit XML, mash around various other
      options so as to constrain the output somewhat. */
   if (VG_(clo_xml)) {
      /* Extract as much info as possible from the leak checker. */
      /* MC_(clo_show_reachable) = True; */
      MC_(clo_leak_check) = LC_Full;
   }
}

static void mc_fini ( Int exitcode )
{
   Int     i, n_accessible_dist;
   SecMap* sm;

   MC_(print_malloc_stats)();

   if (VG_(clo_verbosity) == 1 && !VG_(clo_xml)) {
      if (MC_(clo_leak_check) == LC_Off)
         VG_(message)(Vg_UserMsg, 
             "For a detailed leak analysis,  rerun with: --leak-check=yes");

      VG_(message)(Vg_UserMsg, 
                   "For counts of detected errors, rerun with: -v");
   }
   if (MC_(clo_leak_check) != LC_Off)
      mc_detect_memory_leaks(1/*bogus ThreadId*/, MC_(clo_leak_check));

   done_prof_mem();

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
   VG_(needs_tool_errors)         (mc_eq_Error,
                                   mc_pp_Error,
                                   mc_update_extra,
                                   mc_recognised_suppression,
                                   mc_read_extra_suppression_info,
                                   mc_error_matches_suppression,
                                   mc_get_error_name,
                                   mc_print_extra_suppression_info);
   VG_(needs_libc_freeres)        ();
   VG_(needs_command_line_options)(mc_process_cmd_line_options,
                                   mc_print_usage,
                                   mc_print_debug_usage);
   VG_(needs_client_requests)     (mc_handle_client_request);
   VG_(needs_sanity_checks)       (mc_cheap_sanity_check,
                                   mc_expensive_sanity_check);

   VG_(needs_malloc_replacement)  (MC_(malloc),
                                   MC_(__builtin_new),
                                   MC_(__builtin_vec_new),
                                   MC_(memalign),
                                   MC_(calloc),
                                   MC_(free),
                                   MC_(__builtin_delete),
                                   MC_(__builtin_vec_delete),
                                   MC_(realloc),
                                   MC_MALLOC_REDZONE_SZB );

   MC_( new_mem_heap)             = mc_new_mem_heap;
   MC_( ban_mem_heap)             = mc_make_noaccess;
   MC_(copy_mem_heap)             = mc_copy_address_range_state;
   MC_( die_mem_heap)             = mc_make_noaccess;
   MC_(check_noaccess)            = mc_check_noaccess;

   VG_(track_new_mem_startup)     ( mc_new_mem_startup );
   VG_(track_new_mem_stack_signal)( mc_make_writable );
   VG_(track_new_mem_brk)         ( mc_make_writable );
   VG_(track_new_mem_mmap)        ( mc_new_mem_mmap );
   
   VG_(track_copy_mem_remap)      ( mc_copy_address_range_state );

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
      
   VG_(track_die_mem_stack_signal)( mc_make_noaccess ); 
   VG_(track_die_mem_brk)         ( mc_make_noaccess );
   VG_(track_die_mem_munmap)      ( mc_make_noaccess ); 

   VG_(track_new_mem_stack_4)     ( mc_new_mem_stack_4  );
   VG_(track_new_mem_stack_8)     ( mc_new_mem_stack_8  );
   VG_(track_new_mem_stack_12)    ( mc_new_mem_stack_12 );
   VG_(track_new_mem_stack_16)    ( mc_new_mem_stack_16 );
   VG_(track_new_mem_stack_32)    ( mc_new_mem_stack_32 );
   VG_(track_new_mem_stack)       ( mc_new_mem_stack    );

   VG_(track_die_mem_stack_4)     ( mc_die_mem_stack_4  );
   VG_(track_die_mem_stack_8)     ( mc_die_mem_stack_8  );
   VG_(track_die_mem_stack_12)    ( mc_die_mem_stack_12 );
   VG_(track_die_mem_stack_16)    ( mc_die_mem_stack_16 );
   VG_(track_die_mem_stack_32)    ( mc_die_mem_stack_32 );
   VG_(track_die_mem_stack)       ( mc_die_mem_stack    );
   
   VG_(track_ban_mem_stack)       ( mc_make_noaccess );

   VG_(track_pre_mem_read)        ( mc_check_is_readable );
   VG_(track_pre_mem_read_asciiz) ( mc_check_is_readable_asciiz );
   VG_(track_pre_mem_write)       ( mc_check_is_writable );
   VG_(track_post_mem_write)      ( mc_post_mem_write );

   VG_(track_pre_reg_read)        ( mc_pre_reg_read );

   VG_(track_post_reg_write)                  ( mc_post_reg_write );
   VG_(track_post_reg_write_clientcall_return)( mc_post_reg_write_clientcall );

   VG_(register_profile_event) ( VgpSetMem,   "set-mem-perms" );
   VG_(register_profile_event) ( VgpCheckMem, "check-mem-perms" );
   VG_(register_profile_event) ( VgpESPAdj,   "adjust-ESP" );

   init_shadow_memory();
   MC_(malloc_list)  = VG_(HT_construct)( 80021 );   // prime, big
   MC_(mempool_list) = VG_(HT_construct)( 1009  );   // prime, not so big
   init_prof_mem();

   tl_assert( mc_expensive_sanity_check() );

   // {LOADV,STOREV}[8421] will all fail horribly if this isn't true.
   tl_assert(sizeof(UWord) == sizeof(Addr));
}

VG_DETERMINE_INTERFACE_VERSION(mc_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
