
/*--------------------------------------------------------------------*/
/*--- The address space manager: segment initialisation and        ---*/
/*--- tracking, stack operations                                   ---*/
/*---                                                m_aspacemgr.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

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

#include "pub_core_basics.h"
#include "pub_core_debuglog.h"
#include "pub_core_debuginfo.h"  // Needed for pub_core_aspacemgr.h :(
#include "pub_core_aspacemgr.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcfile.h"   // For VG_(fstat), VG_(resolve_filename_nodup)
#include "pub_core_libcprint.h"
#include "pub_core_syscall.h"
#include "pub_core_tooliface.h"
#include "pub_core_transtab.h"   // For VG_(discard_translations)
#include "vki_unistd.h"

static void aspacem_barf ( HChar* what );


/* Define to debug the memory-leak-detector. */
/* #define VG_DEBUG_LEAKCHECK */

static const Bool mem_debug = False;

/*--------------------------------------------------------------*/
/*--- Basic globals about the address space.                 ---*/
/*--------------------------------------------------------------*/

/* Client address space, lowest to highest (see top of ume.c) */
Addr VG_(client_base);           /* client address space limits */
Addr VG_(client_end);
Addr VG_(client_mapbase);
Addr VG_(clstk_base);
Addr VG_(clstk_end);
UWord VG_(clstk_id);

Addr VG_(brk_base)  = 0;         /* start of brk */
Addr VG_(brk_limit) = 0;         /* current brk */

Addr VG_(shadow_base);	         /* tool's shadow memory */
Addr VG_(shadow_end);

Addr VG_(valgrind_base);	 /* valgrind's address range */

// Note that VG_(valgrind_last) names the last byte of the section, whereas
// the VG_(*_end) vars name the byte one past the end of the section.
Addr VG_(valgrind_last);

/*--------------------------------------------------------------*/
/*--- The raw mman syscalls                                  ---*/
/*--------------------------------------------------------------*/

SysRes VG_(mmap_native)(void *start, SizeT length, UInt prot, UInt flags,
                        UInt fd, OffT offset)
{
   SysRes res;
aspacem_barf("mmap_native");
#if defined(VGP_x86_linux)
   { 
      UWord args[6];
      args[0] = (UWord)start;
      args[1] = length;
      args[2] = prot;
      args[3] = flags;
      args[4] = fd;
      args[5] = offset;
      res = VG_(do_syscall1)(__NR_mmap, (UWord)args );
   }
#elif defined(VGP_amd64_linux)
   res = VG_(do_syscall6)(__NR_mmap, (UWord)start, length, 
                         prot, flags, fd, offset);
#elif defined(VGP_ppc32_linux)
   res = VG_(do_syscall6)(__NR_mmap, (UWord)(start), (length),
			  prot, flags, fd, offset);
#else
#  error Unknown platform
#endif
   return res;
}

SysRes VG_(munmap_native)(void *start, SizeT length)
{
aspacem_barf("munmap_native");
   return VG_(do_syscall2)(__NR_munmap, (UWord)start, length );
}

SysRes VG_(mprotect_native)( void *start, SizeT length, UInt prot )
{
aspacem_barf("mprotect_native");
   return VG_(do_syscall3)(__NR_mprotect, (UWord)start, length, prot );
}

/*--------------------------------------------------------------*/
/*--- A simple, self-contained ordered array of segments.    ---*/
/*--------------------------------------------------------------*/

/* Max number of segments we can track. */
#define VG_N_SEGMENTS 2000

/* Max number of segment file names we can track. */
#define VG_N_SEGNAMES 400

/* Max length of a segment file name. */
#define VG_MAX_SEGNAMELEN 1000


/* ------ STATE for the address-space manager ------ */

/* Array [0 .. segments_used-1] of all mappings. */
/* Sorted by .addr field. */
/* I: len may not be zero. */
/* I: overlapping segments are not allowed. */
/* Each segment can optionally hold an index into the filename table. */

static Segment segments[VG_N_SEGMENTS];
static Int     segments_used = 0;

typedef
   struct {
      Bool  inUse;
      Bool  mark;
      HChar fname[VG_MAX_SEGNAMELEN];
   }
   SegName;

/* Filename table.  _used is the high water mark; an entry is only
   valid if its index >= 0, < _used, and its .inUse field == True.
   The .mark field is used to garbage-collect dead entries.
*/
static SegName segnames[VG_N_SEGNAMES];
static Int     segnames_used = 0;


/* ------ end of STATE for the address-space manager ------ */


/* Searches the filename table to find an index for the given name.
   If none is found, an index is allocated and the name stored.  If no
   space is available we just give up.  If the string is too long to
   store, return -1.
*/
static Int allocate_segname ( const HChar* name )
{
   Int i, j, len;

   vg_assert(name);

   if (0) VG_(printf)("allocate_segname %s\n", name);

   len = VG_(strlen)(name);
   if (len >= VG_MAX_SEGNAMELEN-1) {
      return -1;
   }

   /* first see if we already have the name. */
   for (i = 0; i < segnames_used; i++) {
      if (!segnames[i].inUse)
         continue;
      if (0 == VG_(strcmp)(name, &segnames[i].fname[0])) {
         return i;
      }
   }

   /* no we don't.  So look for a free slot. */
   for (i = 0; i < segnames_used; i++)
      if (!segnames[i].inUse)
         break;

   if (i == segnames_used) {
      /* no free slots .. advance the high-water mark. */
      if (segnames_used+1 < VG_N_SEGNAMES) {
         i = segnames_used;
         segnames_used++;
      } else {
         VG_(printf)(
            "coregrind/m_aspacemgr/aspacemgr.c:\n"
            "   VG_N_SEGNAMES is too small: "
            "increase it and rebuild Valgrind.\n"
         );
         VG_(printf)(
            "coregrind/m_aspacemgr/aspacemgr.c:\n"
            "   giving up now.\n\n"
         );
         VG_(exit)(0);
      }
   }

   /* copy it in */
   segnames[i].inUse = True;
   for (j = 0; j < len; j++)
      segnames[i].fname[j] = name[j];
   vg_assert(len < VG_MAX_SEGNAMELEN);
   segnames[i].fname[len] = 0;
   return i;
}


/* Returns -1 if 'a' denotes an address prior to seg, 1 if it denotes
   an address after it, and 0 if it denotes an address covered by
   seg. 
*/
static inline Int compare_addr_with_seg ( Addr a, Segment* seg )
{
   if (a < seg->addr) 
      return -1;
   if (a >= seg->addr + seg->len) 
      return 1;
   return 0;
}


/* Find the (index of the) segment that contains 'a', or -1 if
   none. 
*/
static Int find_segment ( Addr a )
{
   Int i;
   for (i = 0; i < segments_used; i++) {
      if (compare_addr_with_seg(a, &segments[i]) == 0)
         return i;
   }
   return -1;
}


/* Assumes that 'a' is not in any segment.  Finds the index of the
   lowest-addressed segment above 'a', or -1 if none.  Passing 'a'
   which is in fact in a segment is a checked error. 
*/
static Int find_segment_above_unmapped ( Addr a )
{
   Int i, r;
   for (i = 0; i < segments_used; i++) {
      r = compare_addr_with_seg(a, &segments[i]);
      vg_assert(r != 0); /* 'a' should not be in any segment. */
      if (r == 1)
         continue;
      vg_assert(r == -1);
      break;
   }

   if (i == segments_used)
      return -1; /* not found */
   else
      return i;
}


/* Assumes that 'a' is in some segment.  Finds the next segment along,
   or NULL if none.  Passing 'a' which is in fact not in a segment is
   a checked error.
*/
static Int find_segment_above_mapped ( Addr a )
{
   Int i, r;
   for (i = 0; i < segments_used; i++) {
      r = compare_addr_with_seg(a, &segments[i]);
      if (r == 1)
         continue; /* not yet there */
      if (r == 0)
         break; /* found it */
      vg_assert(0);
      /* we shouldn't get here -- r == -1 and so it means we went past 
         'a' without seeing it -- it is therefore unmapped. */
      /*NOTREACHED*/
   }

   vg_assert(i < segments_used);
   if (i == segments_used-1)
      return -1; /* not found */
   else
      return i+1;
}


/* Shift segments[i .. segments_used-1] up by one. */
static void make_space_at ( Int i )
{
   Int j;
   vg_assert(i >= 0 && i <= segments_used);
   vg_assert(segments_used >= 0);
   if (segments_used+1 == VG_N_SEGMENTS) {
      VG_(printf)(
         "coregrind/m_aspacemgr/aspacemgr.c:\n"
         "   VG_N_SEGMENTS is too small: "
         "increase it and rebuild Valgrind.\n"
      );
      VG_(printf)(
         "coregrind/m_aspacemgr/aspacemgr.c:\n"
         "   giving up now.\n\n"
      );
      VG_(exit)(0);
   }
   vg_assert(segments_used+1 < VG_N_SEGMENTS);
   for (j = segments_used; j > i; j--)
      segments[j] = segments[j-1];
   segments_used++;
}

// Forward declaration
static void dealloc_seg_memory(Segment *s);

/* Shift segments [i+1 .. segments_used-1] down by one, and decrement
   segments_used. 
*/
static void delete_segment_at ( Int i )
{
   Int j;
   vg_assert(i >= 0 && i < segments_used);
   dealloc_seg_memory(&segments[i]);
   for (j = i+1; j < segments_used; j++) {
      segments[j-1] = segments[j];
   }
   segments_used--;
   vg_assert(segments_used >= 0 && segments_used < VG_N_SEGMENTS);
}


/* Fill the i'th record all with zeroes. */
static void zeroise_segment ( Int i )
{
   vg_assert(i >= 0 && i < segments_used);
   segments[i].prot     = 0;
   segments[i].flags    = 0;
   segments[i].addr     = 0;
   segments[i].len      = 0;
   segments[i].offset   = 0;
   segments[i].filename = NULL;
   segments[i].fnIdx    = -1;
   segments[i].dev      = 0;
   segments[i].ino      = 0;
   segments[i].seginfo  = NULL;
}


/* Create a segment to contain 'a', and return its index.  Or -1 if
   this failed because some other segment already contains 'a'.  If
   successful, fill in the segment's .addr field with 'a' but leave
   all other fields alone. 
*/
static Int create_segment ( Addr a )
{
   Int i, r;
   for (i = 0; i < segments_used; i++) {
      r = compare_addr_with_seg( a, &segments[i] );
      if (r == 1)
         continue; /* seg[i] precedes a */
      if (r == 0)
         return -1; /* seg[i] contains a.  Give up */
      vg_assert(r == -1);
      break;
   }
   /* a precedes seg[i].  Shift segs at i and above up one, and use
      this slot. */
   make_space_at(i);
   zeroise_segment(i);
   segments[i].addr = a;
   return i;
}


/* Print out the segment array (debugging only!).  Note, this calls
   VG_(printf), and I'm not 100% clear that that wouldn't require
   dynamic memory allocation and hence more segments to be allocated.
*/
static void show_segments ( HChar* who )
{
   Int i;
   VG_(printf)("<<< SHOW_SEGMENTS: %s (%d segments, %d segnames)\n", 
               who, segments_used, segnames_used);
   for (i = 0; i < segnames_used; i++) {
      if (!segnames[i].inUse)
         continue;
      VG_(printf)("(%2d) %s\n", i, segnames[i].fname);
   }
   for (i = 0; i < segments_used; i++) {
      VG_(printf)(
         "%3d: %08p-%08p %7llu pr=0x%x fl=0x%04x d=0x%03x i=%-7d o=%-7lld (%d)\n",
         i,
         segments[i].addr, segments[i].addr + segments[i].len,
         (ULong)segments[i].len, segments[i].prot, 
         segments[i].flags, segments[i].dev, segments[i].ino, 
         (Long)segments[i].offset, 
         segments[i].fnIdx);
   }
   VG_(printf)(">>>\n");
}


/* Find the segment containing 'a' and split it into two pieces at
   'a'.  Does nothing if no segment contains 'a', or if the split
   would cause either of the pieces to have zero size.

   If 'a' is not found, or if no splitting happens, -1 is returned.

   If a value 'r' other than -1 is returned, this is the index of the
   higher-addressed segment resulting from the split, and the index of
   the lower-addressed segment is r-1.
*/
static Int split_segment ( Addr a )
{
   Int r;
   HWord delta;
   vg_assert(VG_IS_PAGE_ALIGNED(a));
   r = find_segment(a);
   if (r == -1)
      /* not found */
      return -1;
   if (segments[r].addr == a)
      /* segment starts at 'a', so splitting it would create a
         zero-sized segment */
      return -1;

   /* copy original; make adjustments. */
   vg_assert(a > segments[r].addr);
   delta = a - segments[r].addr;
   make_space_at(r);
   
   segments[r] = segments[r+1];
   segments[r].len = delta;
   if (segments[r].seginfo)
      VG_(seginfo_incref)(segments[r].seginfo);
   
   segments[r+1].len -= delta;
   segments[r+1].addr += delta;
   segments[r+1].offset += delta;
   return r+1;
}


/* Return true if two segments are adjacent and mergable (s1 is
   assumed to have a lower ->addr than s2) */
static inline Bool segments_are_mergeable(Segment *s1, Segment *s2)
{
   if (s1->addr+s1->len != s2->addr)
      return False;

   if (s1->flags != s2->flags)
      return False;

   if (s1->prot != s2->prot)
      return False;

   if (s1->seginfo != s2->seginfo)
      return False;

   if (s1->flags & SF_FILE){
      if ((s1->offset + s1->len) != s2->offset)
	 return False;
      if (s1->dev != s2->dev)
	 return False;
      if (s1->ino != s2->ino)
	 return False;
      if (s1->fnIdx != s2->fnIdx)
         return False;
   }
   
   return True;
}


/* Clean up and sanity check the segment array:
   - check segments are in ascending order
   - check segments do not overlap
   - check no segment has zero size
   - merge adjacent where possible
   - perform checks on the filename table, and reclaim dead entries
*/
static void preen_segments ( void )
{
   Int i, j, rd, wr;
   Segment *s, *s1;
   vg_assert(segments_used >= 0 && segments_used < VG_N_SEGMENTS);
   vg_assert(segnames_used >= 0 && segnames_used < VG_N_SEGNAMES);

   if (0) show_segments("before preen");

   /* clear string table mark bits */
   for (i = 0; i < segnames_used; i++)
      segnames[i].mark = False;

   /* check for non-zero size, and set mark bits for any used strings */
   for (i = 0; i < segments_used; i++) {
      vg_assert(segments[i].len > 0);
      j = segments[i].fnIdx;
      vg_assert(j >= -1 && j < segnames_used);
      if (j >= 0) {
         vg_assert(segnames[j].inUse);
         segnames[j].mark = True;
      }
   }

   /* check ascendingness and non-overlap */
   for (i = 0; i < segments_used-1; i++) {
      s = &segments[i];
      s1 = &segments[i+1];
      vg_assert(s->addr < s1->addr);
      vg_assert(s->addr + s->len <= s1->addr);
   }

   /* merge */
   if (segments_used < 1)
      return;

   wr = 1;
   for (rd = 1; rd < segments_used; rd++) {
      s = &segments[wr-1];
      s1 = &segments[rd];
      if (segments_are_mergeable(s,s1)) {
         if (0)
            VG_(printf)("merge %p-%p with %p-%p\n",
                        s->addr, s->addr+s->len,
                        s1->addr, s1->addr+s1->len);
         s->len += s1->len;

         vg_assert(s->seginfo == s1->seginfo);
         dealloc_seg_memory(s1);
         
         continue;
      }
      if (wr < rd)
         segments[wr] = segments[rd];
      wr++;
   }
   vg_assert(wr >= 0 && wr <= segments_used);
   segments_used = wr;

   /* Free up any strings which are no longer referenced. */
   for (i = 0; i < segnames_used; i++) {
      if (segnames[i].mark == False) {
         segnames[i].inUse = False;
         segnames[i].fname[0] = 0;
      }
   }

   if (0) show_segments("after preen");
}


/*--------------------------------------------------------------*/
/*--- Maintain an ordered list of all the client's mappings  ---*/
/*--------------------------------------------------------------*/

Bool VG_(seg_contains)(const Segment *s, Addr p, SizeT len)
{
   Addr se = s->addr+s->len;
   Addr pe = p+len;
aspacem_barf("seg_contains");
   vg_assert(pe >= p);

   return (p >= s->addr && pe <= se);
}

Bool VG_(seg_overlaps)(const Segment *s, Addr p, SizeT len)
{
   Addr se = s->addr+s->len;
   Addr pe = p+len;
aspacem_barf("seg_overlaps");
   vg_assert(pe >= p);

   return (p < se && pe > s->addr);
}

/* When freeing a Segment, also clean up every one else's ideas of
   what was going on in that range of memory */
static void dealloc_seg_memory(Segment *s)
{
   if (s->seginfo != NULL) {
      VG_(seginfo_decref)(s->seginfo, s->addr);
      s->seginfo = NULL;
   }
}

/* Get rid of any translations arising from s. */
/* Note, this is not really the job of the low level memory manager.
   When it comes time to rewrite this subsystem, clean this up. */
static void dump_translations_from ( Segment* s )
{
   if (s->flags & SF_CODE) {
      VG_(discard_translations)(s->addr, s->len);
      if (0)
         VG_(printf)("dumping translations in %p .. %p\n",
                     s->addr, s->addr+s->len);
   }
}


/* This unmaps all the segments in the range [addr, addr+len); any
   partial mappings at the ends are truncated. */
void VG_(unmap_range)(Addr addr, SizeT len)
{
   const Bool debug = False || mem_debug;
   Segment* s;
   Addr     end, s_end;
   Int      i;
   Bool     deleted;
aspacem_barf("unmap_range");

   if (len == 0)
      return;

   len = VG_PGROUNDUP(len);

   if (debug)
      VG_(printf)("unmap_range(%p, %llu)\n", addr, (ULong)len);
   if (0) show_segments("unmap_range(BEFORE)");
   end = addr+len;

   /* Everything must be page-aligned */
   vg_assert(VG_IS_PAGE_ALIGNED(addr));
   vg_assert(VG_IS_PAGE_ALIGNED(len));

   for (i = 0; i < segments_used; i++) {

      /* do not delete .. even though it looks stupid */
      vg_assert(i >= 0);

      deleted = False;
      s = &segments[i];
      s_end = s->addr + s->len;

      if (0 && debug)
	 VG_(printf)("unmap: addr=%p-%p s=%p ->addr=%p-%p len=%d\n",
		     addr, end, s, s->addr, s_end, s->len);

      if (!VG_(seg_overlaps)(s, addr, len)) {
	 if (0 && debug)
	    VG_(printf)("   (no overlap)\n");
	 continue;
      }

      /* 4 cases: */
      if (addr > s->addr &&
	  addr < s_end &&
	  end >= s_end) {
	 /* this segment's tail is truncated by [addr, addr+len)
	    -> truncate tail
	 */
         dump_translations_from(s);
	 s->len = addr - s->addr;

	 if (debug)
	    VG_(printf)("  case 1: s->len=%lu\n", s->len);
      } else if (addr <= s->addr && end > s->addr && end < s_end) {
	 /* this segment's head is truncated by [addr, addr+len)
	    -> truncate head
	 */
	 Word delta = end - s->addr;

	 if (debug)
	    VG_(printf)("  case 2: s->addr=%p s->len=%lu delta=%d\n", 
                        s->addr, s->len, delta);

         dump_translations_from(s);
	 s->addr += delta;
	 s->offset += delta;
	 s->len -= delta;

	 vg_assert(s->len != 0);
      } else if (addr <= s->addr && end >= s_end) {
	 /* this segment is completely contained within [addr, addr+len)
	    -> delete segment
	 */
         dump_translations_from(s);
         delete_segment_at(i);
         deleted = True;

	 if (debug)
	    VG_(printf)("  case 3: seg %d deleted\n", i);
      } else if (addr > s->addr && end < s_end) {
	 /* [addr, addr+len) is contained within a single segment
	    -> split segment into 3, delete middle portion
	  */
         Int i_middle;
         dump_translations_from(s);
         i_middle = split_segment(addr);
	 vg_assert(i_middle != -1);
	 (void)split_segment(addr+len);
	 vg_assert(segments[i_middle].addr == addr);
	 delete_segment_at(i_middle);
	 deleted = True;

	 if (debug)
	    VG_(printf)("  case 4: subrange %p-%p deleted\n",
			addr, addr+len);
      }

      /* If we deleted this segment (or any above), those above will
         have been moved down to fill in the hole in the segment
         array.  In order that we don't miss them, we have to
         re-consider this slot number; hence the i--. */
      if (deleted)
         i--;
   }
   preen_segments();
   if (0) show_segments("unmap_range(AFTER)");
}


/* Add a binding of [addr,addr+len) to
   (prot,flags,dev,ino,off,filename) in the segment array.
   Delete/truncate any previous mapping(s) covering that range.
*/
void 
VG_(map_file_segment)( Addr addr, SizeT len, 
                       UInt prot, UInt flags, 
                       UInt dev, UInt ino, ULong off, 
                       const Char *filename)
{
   const Bool debug = False || mem_debug;
   Segment* s;
   Int      idx;
   HChar*   stage2_suffix1 = "lib/valgrind/stage2";
   HChar*   stage2_suffix2 = "coregrind/stage2";
   Bool     is_stage2 = False;
aspacem_barf("map_file_segment");
   
   is_stage2 = is_stage2 || ( VG_(strstr)(filename, stage2_suffix1) != NULL );
   is_stage2 = is_stage2 || ( VG_(strstr)(filename, stage2_suffix2) != NULL );

   if (debug)
      VG_(printf)(
         "\n"
         "map_file_segment(addr=%p len=%lu prot=0x%x flags=0x%x\n"
         "                 dev=0x%4x ino=%d off=%ld\n"
         "                 filename='%s')\n",
         addr, (ULong)len, prot, flags, dev, ino, off, filename);

   if (0) show_segments("before map_file_segment");

   /* Everything must be page-aligned */
   vg_assert(VG_IS_PAGE_ALIGNED(addr));
   len = VG_PGROUNDUP(len);

   /* Nuke/truncate any existing segment(s) covering [addr,addr+len) */
   VG_(unmap_range)(addr, len);

   /* and now install this one */
   idx = create_segment(addr);
   vg_assert(segments_used >= 0 && segments_used <= VG_N_SEGMENTS);
   vg_assert(idx != -1);
   vg_assert(idx >= 0 && idx < segments_used);

   s = &segments[idx];
   vg_assert(s->addr == addr);
   s->prot     = prot;
   s->flags    = flags;
   s->len      = len;
   s->offset   = off;
   s->fnIdx    = filename==NULL ? -1 : allocate_segname(filename);
   s->filename = s->fnIdx==-1 ? NULL : &segnames[s->fnIdx].fname[0];
   s->dev      = dev;
   s->ino      = ino;
   s->seginfo  = NULL;

   /* Clean up right now */
   preen_segments();
   if (0) show_segments("after map_file_segment");

   /* If this mapping is at the beginning of a file, isn't part of
      Valgrind, is at least readable and seems to contain an object
      file, then try reading symbols from it.

      Getting this heuristic right is critical.  On x86-linux,
      objects are typically mapped twice:

      1b8fb000-1b8ff000 r-xp 00000000 08:02 4471477 vgpreload_memcheck.so
      1b8ff000-1b900000 rw-p 00004000 08:02 4471477 vgpreload_memcheck.so

      whereas ppc32-linux mysteriously does this:

      118a6000-118ad000 r-xp 00000000 08:05 14209428 vgpreload_memcheck.so
      118ad000-118b6000 ---p 00007000 08:05 14209428 vgpreload_memcheck.so
      118b6000-118bd000 rwxp 00000000 08:05 14209428 vgpreload_memcheck.so

      The third mapping should not be considered to have executable code in.
      Therefore a test which works for both is: r and x and NOT w.  Reading
      symbols from the rwx segment -- which overlaps the r-x segment in the
      file -- causes the redirection mechanism to redirect to addresses in
      that third segment, which is wrong and causes crashes.
   */
   if (s->seginfo == NULL
       && ( (addr+len < VG_(valgrind_base) || addr > VG_(valgrind_last))
            || is_stage2
          )
       && (flags & (SF_MMAP|SF_NOSYMS)) == SF_MMAP
      ) {
      if (off == 0
         && s->fnIdx != -1
         /* r, x are set */
         && (prot & (VKI_PROT_READ|VKI_PROT_EXEC)) == (VKI_PROT_READ|VKI_PROT_EXEC)
         /* w is clear */
         && (prot & VKI_PROT_WRITE) == 0
         /* other checks .. */
         && len >= VKI_PAGE_SIZE
         && VG_(is_object_file)((void *)addr) ) {
         s->seginfo = VG_(read_seg_symbols)(s->addr, s->len, s->offset,
                                            s->filename);
      }
      else if (flags & SF_MMAP) 
      {
         const SegInfo *si;
      
         /* Otherwise see if an existing SegInfo applies to this Segment */
         for (si = VG_(next_seginfo)(NULL);
              si != NULL;
              si = VG_(next_seginfo)(si)) 
         {
            if (VG_(seg_overlaps)(s, VG_(seginfo_start)(si), 
                                     VG_(seginfo_size)(si)))
            {
               s->seginfo = (SegInfo *)si;
               VG_(seginfo_incref)((SegInfo *)si);
            }
         }
      }
   }

   /* clean up */
   preen_segments();
}

void VG_(map_fd_segment)(Addr addr, SizeT len, UInt prot, UInt flags, 
			 Int fd, ULong off, const Char *filename)
{
   Char buf[VKI_PATH_MAX];
   struct vki_stat st;
aspacem_barf("map_fd_segment");

   st.st_dev = 0;
   st.st_ino = 0;

   if (fd != -1 && (flags & SF_FILE)) {
      vg_assert((off & (VKI_PAGE_SIZE-1)) == 0);

      if (VG_(fstat)(fd, &st) < 0)
	 flags &= ~SF_FILE;
   }

   if ((flags & SF_FILE) && filename == NULL && fd != -1)
      if (VG_(resolve_filename)(fd, buf, VKI_PATH_MAX))
         filename = buf;

   VG_(map_file_segment)(addr, len, prot, flags, 
                         st.st_dev, st.st_ino, off, filename);
}

void VG_(map_segment)(Addr addr, SizeT len, UInt prot, UInt flags)
{
aspacem_barf("map_segment");
   flags &= ~SF_FILE;

   VG_(map_file_segment)(addr, len, prot, flags, 0, 0, 0, 0);
}

/* set new protection flags on an address range */
void VG_(mprotect_range)(Addr a, SizeT len, UInt prot)
{
   Int r;
   const Bool debug = False || mem_debug;
aspacem_barf("mprotect_range");

   if (debug)
      VG_(printf)("\nmprotect_range(%p, %lu, %x)\n", a, len, prot);

   if (0) show_segments( "mprotect_range(before)" );

   /* Everything must be page-aligned */
   vg_assert(VG_IS_PAGE_ALIGNED(a));
   len = VG_PGROUNDUP(len);

   split_segment(a);
   split_segment(a+len);

   r = find_segment(a);
   vg_assert(r != -1);
   segments[r].prot = prot;

   preen_segments();

   if (0) show_segments( "mprotect_range(after)");
}


/* Try to find a map space for [addr,addr+len).  If addr==0, it means
   the caller is prepared to accept a space at any location; if not,
   we will try for addr, but fail if we can't get it.  This mimics
   mmap fixed vs mmap not-fixed.
*/
Addr VG_(find_map_space)(Addr addr, SizeT len, Bool for_client)
{
   const Bool debug = False || mem_debug;
aspacem_barf("find_map_space");

   Addr ret;
   Addr addrOrig = addr;
   Addr limit = (for_client ? VG_(client_end)-1   : VG_(valgrind_last));
   Addr base  = (for_client ? VG_(client_mapbase) : VG_(valgrind_base));
   Addr hole_start, hole_end, hstart_any, hstart_fixed, hstart_final;
   Int i, i_any, i_fixed, i_final;
   SizeT hole_len;

   Bool fixed;

   if (debug) {
      VG_(printf)("\n\n");
      VG_(printf)("find_map_space(%p, %llu, %d) ...\n",
                  addr, (ULong)len, for_client);
   }

   if (0) show_segments("find_map_space: start");

   if (addr == 0) {
      fixed = False;
   } else {
      fixed = True;
      /* leave space for redzone and still try to get the exact
         address asked for */
      addr -= VKI_PAGE_SIZE;
   }

   /* Everything must be page-aligned */
   vg_assert((addr & (VKI_PAGE_SIZE-1)) == 0);
   len = VG_PGROUNDUP(len);

   len += VKI_PAGE_SIZE * 2; /* leave redzone gaps before and after mapping */

   /* Scan the segment list, looking for a hole which satisfies the
      requirements.  At each point i we ask the question "can we use
      the hole in between segments[i-1] and segments[i] ?" */
   i_any = i_fixed = -1;
   hstart_any = hstart_fixed = 0;

   hole_start = hole_end = 0;

   /* Iterate over all possible holes, generating them into
      hole_start/hole_end.  Filter out invalid ones.  Then see if any
      are usable; if so set i_fixed/i_any and hstart_fixed/hstart_any.  
   */
   for (i = 0; i <=/*yes,really*/ segments_used; i++) {
      if (i == 0) {
         hole_start = 0;
         hole_end = segments[0].addr-1;
      } 
      else {
         vg_assert(segments_used > 0);
         if (i == segments_used) {
            hole_start = segments[i-1].addr + segments[i-1].len;
            hole_end = ~(Addr)0;
         } else {
            hole_start = segments[i-1].addr + segments[i-1].len;
            hole_end = segments[i].addr - 1;
         }
      }

      vg_assert(hole_start <= hole_end || hole_start == hole_end+1);

      /* ignore zero-sized holes */
      if (hole_start == hole_end+1)
         continue;

      vg_assert(VG_IS_PAGE_ALIGNED(hole_start));
      vg_assert(VG_IS_PAGE_ALIGNED(hole_end+1));

      /* ignore holes which fall outside the allowable area */
      if (!(hole_start >= base && hole_end <= limit))
         continue;

      vg_assert(hole_end > hole_start);
      hole_len = hole_end - hole_start + 1;
      vg_assert(VG_IS_PAGE_ALIGNED(hole_len));

      if (hole_len >= len && i_any == -1) {
         /* It will at least fit in this hole. */
         i_any = i;
         hstart_any = hole_start;
      }

      if (fixed && hole_start <= addr 
                && hole_start+hole_len >= addr+len) {
         /* We were asked for a fixed mapping, and this hole works.
            Bag it -- and stop searching as further searching is
            pointless. */
         i_fixed = i;
         hstart_fixed = addr;
         break;
      }
   }

   /* Summarise the final decision into i_final/hstart_final. */
   i_final = -1;
   hstart_final = 0;

   if (fixed) {
      i_final = i_fixed;
      hstart_final = hstart_fixed + VKI_PAGE_SIZE;  /* skip leading redzone */
   } else {
      i_final = i_any;
      hstart_final = hstart_any;
   }


   if (i_final != -1)
      ret = hstart_final;
   else
      ret = 0; /* not found */

   if (debug)
      VG_(printf)("find_map_space(%p, %llu, %d) -> %p\n\n",
                  addr, (ULong)len, for_client, ret);

   if (fixed) {
      vg_assert(ret == 0 || ret == addrOrig);
   }

   return ret;
}


/* Pad the entire process address space, from "start"
   to VG_(valgrind_last) by creating an anonymous and inaccessible
   mapping over any part of the address space which is not covered
   by an entry in the segment list.

   This is designed for use around system calls which allocate
   memory in the process address space without providing a way to
   control its location such as io_setup. By choosing a suitable
   address with VG_(find_map_space) and then adding a segment for
   it and padding the address space valgrind can ensure that the
   kernel has no choice but to put the memory where we want it. */
void VG_(pad_address_space)(Addr start)
{
   Addr     addr = (start == 0) ? VG_(client_base) : start;
   SysRes   ret;
aspacem_barf("pad_address_space");

   Int      i = 0;
   Segment* s = i >= segments_used ? NULL : &segments[i];
   
   while (s && addr <= VG_(valgrind_last)) {
      if (addr < s->addr) {
         ret = VG_(mmap_native)((void*)addr, s->addr - addr, 0,
                     VKI_MAP_FIXED | VKI_MAP_PRIVATE | VKI_MAP_ANONYMOUS,
                     -1, 0);
         vg_assert(!ret.isError);
      }
      addr = s->addr + s->len;
      i++;
      s = i >= segments_used ? NULL : &segments[i];
   }

   if (addr <= VG_(valgrind_last)) {
      ret = VG_(mmap_native)((void*)addr, VG_(valgrind_last) - addr + 1, 0,
                  VKI_MAP_FIXED | VKI_MAP_PRIVATE | VKI_MAP_ANONYMOUS,
                  -1, 0);
      vg_assert(!ret.isError);
   }
}

/* Remove the address space padding added by VG_(pad_address_space)
   by removing any mappings that it created. */
void VG_(unpad_address_space)(Addr start)
{
   Addr     addr = (start == 0) ? VG_(client_base) : start;
   SysRes   ret;

   Int      i = 0;
   Segment* s = i >= segments_used ? NULL : &segments[i];
aspacem_barf("unpad_address_space");

   while (s && addr <= VG_(valgrind_last)) {
      if (addr < s->addr) {
         //ret = VG_(do_syscall2)(__NR_munmap, addr, s->addr - addr);
         ret = VG_(do_syscall2)(__NR_munmap, addr, s->addr - addr);
      }
      addr = s->addr + s->len;
      i++;
      s = i >= segments_used ? NULL : &segments[i];
   }

   if (addr <= VG_(valgrind_last)) {
      ret = VG_(do_syscall2)(__NR_munmap, addr, 
                             (VG_(valgrind_last) - addr) + 1);
   }
}

/* Find the segment holding 'a', or NULL if none. */
Segment *VG_(find_segment)(Addr a)
{
  Int r = find_segment(a);
aspacem_barf("find_segment");

  if (0) show_segments("find_segment");
  if (r == -1) return NULL;
  return &segments[r];
}

/* Assumes that 'a' is not in any segment.  Finds the lowest-addressed
   segment above 'a', or NULL if none.  Passing 'a' which is in fact in
   a segment is a checked error.
*/
Segment *VG_(find_segment_above_unmapped)(Addr a)
{
  Int r = find_segment_above_unmapped(a);
aspacem_barf("find_segment_above_unmapped");
  if (0) show_segments("find_segment_above_unmapped");
  if (r == -1) return NULL;
  return &segments[r];
}

/* Assumes that 'a' is in some segment.  Finds the next segment along,
   or NULL if none.  Passing 'a' which is in fact not in a segment is
   a checked error.
*/
Segment *VG_(find_segment_above_mapped)(Addr a)
{
  Int r = find_segment_above_mapped(a);
aspacem_barf("find_segment_above_mapped");
  if (0) show_segments("find_segment_above_mapped");
  if (r == -1) return NULL;
  return &segments[r];
}


/* 
   Test if a piece of memory is addressable with at least the "prot"
   protection permissions by examining the underlying segments.

   Really this is a very stupid algorithm and we could do much
   better by iterating through the segment array instead of through
   the address space.
 */
Bool VG_(is_addressable)(Addr p, SizeT size, UInt prot)
{
   Segment *seg;
aspacem_barf("is_addressable");

   if ((p + size) < p)
      return False; /* reject wraparounds */
   if (size == 0)
      return True; /* isn't this a bit of a strange case? */

   p    = VG_PGROUNDDN(p);
   size = VG_PGROUNDUP(size);
   vg_assert(VG_IS_PAGE_ALIGNED(p));
   vg_assert(VG_IS_PAGE_ALIGNED(size));

   for (; size > 0; size -= VKI_PAGE_SIZE) {
      seg = VG_(find_segment)(p);
      if (!seg)
         return False;
      if ((seg->prot & prot) != prot)
         return False;
      p += VKI_PAGE_SIZE;
   }

   return True;
}


/*--------------------------------------------------------------------*/
/*--- Random function that doesn't really belong here              ---*/
/*--------------------------------------------------------------------*/

/* We'll call any RW mmaped memory segment, within the client address
   range, which isn't SF_CORE, a root. 
*/
void VG_(find_root_memory)(void (*add_rootrange)(Addr a, SizeT sz))
{
   Int     i;
   UInt    flags;
   Segment *s;
aspacem_barf("find_root_memory");

   for (i = 0; i < segments_used; i++) {
      s = &segments[i];
      flags = s->flags & (SF_SHARED|SF_MMAP|SF_VALGRIND|SF_CORE|SF_STACK);
      if (flags != SF_MMAP && flags != SF_STACK && flags != (SF_MMAP|SF_STACK))
         continue;
      if ((s->prot & (VKI_PROT_READ|VKI_PROT_WRITE)) 
          != (VKI_PROT_READ|VKI_PROT_WRITE))
         continue;
      if (!VG_(is_client_addr)(s->addr) ||
          !VG_(is_client_addr)(s->addr+s->len-1))
         continue;

      (*add_rootrange)(s->addr, s->len);
   }
}


/*--------------------------------------------------------------------*/
/*--- Querying memory layout                                       ---*/
/*--------------------------------------------------------------------*/

Bool VG_(is_client_addr)(Addr a)
{
aspacem_barf("is_client_addr");
   return a >= VG_(client_base) && a < VG_(client_end);
}

Bool VG_(is_shadow_addr)(Addr a)
{
aspacem_barf("is_shadow_addr");
   return a >= VG_(shadow_base) && a < VG_(shadow_end);
}


/*--------------------------------------------------------------------*/
/*--- Handling shadow memory                                       ---*/
/*--------------------------------------------------------------------*/

void *VG_(shadow_alloc)(UInt size)
{
   static Addr shadow_alloc = 0;
   Addr try_here;
   SysRes r;
aspacem_barf("shadow_alloc");

   if (0) show_segments("shadow_alloc(before)");

   vg_assert(VG_(needs).shadow_memory);

   size = VG_PGROUNDUP(size);

   if (shadow_alloc == 0)
      shadow_alloc = VG_(shadow_base);

   if (shadow_alloc >= VG_(shadow_end))
      goto failed;

   try_here = shadow_alloc;
   vg_assert(VG_IS_PAGE_ALIGNED(try_here));
   vg_assert(VG_IS_PAGE_ALIGNED(size));
   vg_assert(size > 0);

   if (0)
      VG_(printf)("shadow_alloc: size %d, trying at %p\n", size, (void*)try_here);

   /* this is big-bang allocated, so we don't expect to find a listed
      segment for it. */
   /* This is really an absolute disgrace.  Sometimes the big-bang
      mapping is in the list (due to re-reads of /proc/self/maps,
      presumably) and sometimes it isn't. */
#if 0
   r = find_segment(try_here);
   vg_assert(r == -1);
   r = find_segment(try_here+size-1);
   vg_assert(r == -1);
#endif

   r = VG_(mprotect_native)( (void*)try_here, 
                             size,  VKI_PROT_READ|VKI_PROT_WRITE );

   if (r.isError)
      goto failed;

   shadow_alloc += size;
   return (void*)try_here;

  failed:
   VG_(printf)(
       "valgrind: Could not allocate address space (0x%x bytes)\n"
       "valgrind:   for shadow memory chunk.\n",
       size
      ); 
   VG_(exit)(1);
}

/*------------------------------------------------------------*/
/*--- pointercheck                                         ---*/
/*------------------------------------------------------------*/

Bool VG_(setup_pointercheck)(Addr client_base, Addr client_end)
{
aspacem_barf("setup_pointercheck");
   vg_assert(0 != client_end);
#if defined(VGP_x86_linux)
   /* Client address space segment limit descriptor entry */
   #define POINTERCHECK_SEGIDX  1

   vki_modify_ldt_t ldt = { 
      POINTERCHECK_SEGIDX,       // entry_number
      client_base,               // base_addr
      (client_end - client_base) / VKI_PAGE_SIZE, // limit
      1,                         // seg_32bit
      0,                         // contents: data, RW, non-expanding
      0,                         // ! read_exec_only
      1,                         // limit_in_pages
      0,                         // ! seg not present
      1,                         // useable
   };
   SysRes ret = VG_(do_syscall3)(__NR_modify_ldt, 1, (UWord)&ldt, sizeof(ldt));
   if (ret.isError) {
      VG_(message)(Vg_UserMsg,
                   "Warning: ignoring --pointercheck=yes, "
                   "because modify_ldt failed (errno=%d)", ret.val);
      return False;
   } else {
      return True;
   }
#elif defined(VGP_amd64_linux)
   if (0) 
      VG_(message)(Vg_DebugMsg, "ignoring --pointercheck (unimplemented)");
   return True;
#elif defined(VGP_ppc32_linux)
   if (0) 
      VG_(message)(Vg_DebugMsg, "ignoring --pointercheck (unimplemented)");
   return True;
#else
#  error Unknown architecture
#endif
}

/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////

static void add_to_aspacem_sprintf_buf ( HChar c, void *p )
{
   HChar** aspacem_sprintf_ptr = p;
   *(*aspacem_sprintf_ptr)++ = c;
}

static
UInt aspacem_vsprintf ( HChar* buf, const HChar *format, va_list vargs )
{
   Int ret;
   Char *aspacem_sprintf_ptr = buf;

   ret = VG_(debugLog_vprintf)
            ( add_to_aspacem_sprintf_buf, 
              &aspacem_sprintf_ptr, format, vargs );
   add_to_aspacem_sprintf_buf('\0', &aspacem_sprintf_ptr);

   return ret;
}

static
UInt aspacem_sprintf ( HChar* buf, const HChar *format, ... )
{
   UInt ret;
   va_list vargs;

   va_start(vargs,format);
   ret = aspacem_vsprintf(buf, format, vargs);
   va_end(vargs);

   return ret;
}


/////////////////////////////////////////////////////////////////

SysRes VG_(aspacem_do_mmap_NO_NOTIFY)( Addr start, SizeT length, UInt prot, 
                                       UInt flags, UInt fd, OffT offset)
{
   SysRes res;
#  if defined(VGP_x86_linux)
   { 
      UWord args[6];
      args[0] = (UWord)start;
      args[1] = length;
      args[2] = prot;
      args[3] = flags;
      args[4] = fd;
      args[5] = offset;
      res = VG_(do_syscall1)(__NR_mmap, (UWord)args );
   }
#  elif defined(VGP_amd64_linux)
   res = VG_(do_syscall6)(__NR_mmap, (UWord)start, length, 
                         prot, flags, fd, offset);
#  elif defined(VGP_ppc32_linux)
   res = VG_(do_syscall6)(__NR_mmap, (UWord)(start), (length),
			  prot, flags, fd, offset);
#  else
#    error Unknown platform
#  endif
   return res;
}

static
SysRes do_munmap_NATIVE(Addr start, SizeT length)
{
   return VG_(do_syscall2)(__NR_munmap, (UWord)start, length );
}



static 
Bool get_inode_for_fd ( Int fd, /*OUT*/UInt* dev, /*OUT*/UInt* ino )
{
   return False;
}

static
Bool get_name_for_fd ( Int fd, /*OUT*/HChar* buf, Int nbuf )
{
   return False;
}


/////////////////////////////////////////////////////////////////

static void aspacem_barf ( HChar* what )
{
  VG_(debugLog)(0, "aspacem", "Valgrind: FATAL: %s\n", what);
  VG_(debugLog)(0, "aspacem", "Exiting now.\n");
  VG_(exit)(1);
}

static void aspacem_barf_toolow ( HChar* what )
{
  VG_(debugLog)(0, "aspacem", "Valgrind: FATAL: %s is too low.\n", what);
  VG_(debugLog)(0, "aspacem", "  Increase it and rebuild.  "
                              "Exiting now.\n");
  VG_(exit)(1);
}

static void aspacem_assert_fail( const HChar* expr,
                                 const Char* file,
				 Int line, 
                                 const Char* fn )
{
  VG_(debugLog)(0, "aspacem", "Valgrind: FATAL: assertion failed:\n");
  VG_(debugLog)(0, "aspacem", "  %s\n", expr);
  VG_(debugLog)(0, "aspacem", "  at %s:%d (%s)\n", file,line,fn);
  VG_(debugLog)(0, "aspacem", "Exiting now.\n");
  VG_(exit)(1);
}

#define aspacem_assert(expr)                           \
  ((void) ((expr) ? 0 :                                \
           (aspacem_assert_fail(#expr,                 \
                              __FILE__, __LINE__,      \
                              __PRETTY_FUNCTION__))))



#define Addr_MIN ((Addr)0)
#define Addr_MAX ((Addr)(-1ULL))


/* Array [0 .. nsegments_used-1] of all mappings. */
/* Sorted by .addr field. */
/* I: len may not be zero. */
/* I: overlapping segments are not allowed. */
/* Each segment can optionally hold an index into the filename table. */

static NSegment nsegments[VG_N_SEGMENTS];
static Int      nsegments_used = 0;


/* Given a pointer to a seg, tries to figure out which one it is in
   nsegments[..].  Very paranoid. */
static Int segAddr_to_index ( NSegment* seg )
{
   Int i;
   if (seg < &nsegments[0] || seg >= &nsegments[nsegments_used])
      return -1;
   i = ((UChar*)seg - (UChar*)(&nsegments[0])) / sizeof(NSegment);
   if (i < 0 || i >= nsegments_used)
      return -1;
   if (seg == &nsegments[i])
      return i;
   return -1;
}

/* Find the next segment along from HERE, if it is a file/anon/resvn
   segment. */
NSegment* VG_(next_nsegment) ( NSegment* here, Bool fwds )
{
   Int i = segAddr_to_index(here);
   if (i < 0 || i >= nsegments_used)
      return NULL;
   if (fwds) {
      i++;
      if (i >= nsegments_used)
         return NULL;
   } else {
      i--;
      if (i < 0)
         return NULL;
   }
   if (nsegments[i].kind == SkFile 
       || nsegments[i].kind == SkAnon
       || nsegments[i].kind == SkResvn)
     return &nsegments[i];
   else 
      return NULL;
}


ULong VG_(aspacem_get_anonsize_total)( void )
{
  Int i;
  ULong total = 0;
  for (i = 0; i < nsegments_used; i++) {
    if (nsegments[i].kind != SkAnon)
      continue;
    total += (ULong)nsegments[i].end - (ULong)nsegments[i].start + 1ULL;
  }
  return total;
}

/* check the interval array */
static void check_nsegments ( void )
{
  Int i;
  aspacem_assert(nsegments_used > 0);
  aspacem_assert(nsegments[0].start == Addr_MIN);
  aspacem_assert(nsegments[nsegments_used-1].end == Addr_MAX);
  for (i = 1; i < nsegments_used; i++)
    aspacem_assert(nsegments[i-1].end+1 == nsegments[i].start);
}


/* Binary search the interval array for a given address.  Since the
   array covers the entire address space the search cannot fail. */
static Int find_nsegment_idx ( Addr a )
{
   Addr a_mid_lo, a_mid_hi;
   Int  mid,
        lo = 0,
        hi = nsegments_used-1;
   while (True) {
      /* current unsearched space is from lo to hi, inclusive. */
      if (lo > hi) {
         /* Not found.  This can't happen. */
         aspacem_barf("find_nsegment_idx: not found");
      }
      mid      = (lo + hi) / 2;
      a_mid_lo = nsegments[mid].start;
      a_mid_hi = nsegments[mid].end;

      if (a < a_mid_lo) { hi = mid-1; continue; }
      if (a > a_mid_hi) { lo = mid+1; continue; }
      aspacem_assert(a >= a_mid_lo && a <= a_mid_hi);
      aspacem_assert(0 <= mid && mid < nsegments_used);
      return mid;
   }
}

/* Find a segment, not include free-space and ones, for outside use. */
NSegment* VG_(find_nsegment) ( Addr a )
{
   Int i = find_nsegment_idx(a);
   aspacem_assert(i >= 0 && i < nsegments_used);
   aspacem_assert(nsegments[i].start <= a);
   aspacem_assert(a <= nsegments[i].end);
   if (nsegments[i].kind == SkFree) 
      return NULL;
   else
      return &nsegments[i];
}



/* Limits etc */

// The smallest address that aspacem will try to allocate
static Addr aspacem_minAddr;

// The largest address that aspacem will try to allocate
static Addr aspacem_maxAddr;

// Where aspacem will start looking for client space
static Addr aspacem_cStart;

// Where aspacem will start looking for Valgrind space
static Addr aspacem_vStart;


Bool VG_(aspacem_getAdvisory) ( MapRequest*  req, 
                                Bool         forClient, 
                                /*OUT*/Addr* result )
{
   /* This function implements allocation policy.

      The nature of the allocation request is determined by req, which
      specifies the start and length of the request and indicates
      whether the start address is mandatory, a hint, or irrelevant,
      and by forClient, which says whether this is for the client or
      for V. 

      Return values: the request can be vetoed (return False), in
      which case the caller should not attempt to proceed with making
      the mapping.  Otherwise, the caller may proceed, and the
      preferred address at which the mapping should happen is written
      in *result.

      Note that this is an advisory system only: the kernel can in
      fact do whatever it likes as far as placement goes, and we have
      no absolute control over it.

      Allocations will never be granted in a reserved area.

      The Default Policy is:

        Search the address space for two free intervals: one of them
        big enough to contain the request without regard to the
        specified address (viz, as if it was a floating request) and
        the other being able to contain the request at the specified
        address (viz, as if were a fixed request).  Then, depending on
        the outcome of the search and the kind of request made, decide
        whether the request is allowable and what address to advise.

      The Default Policy is overriden by Policy Exception #1:

        If the request is for a fixed client map, we are prepared to
        grant it providing all areas inside the request are either
        free or are file mappings belonging to the client.  In other
        words we are prepared to let the client trash its own mappings
        if it wants to.  
   */
   Int  i, j;
   Addr holeStart, holeEnd, holeLen;
   Bool fixed_not_required;

   Addr startPoint = forClient ? aspacem_cStart : aspacem_vStart;

   Addr reqStart = req->rkind==MAny ? 0 : req->start;
   Addr reqEnd   = reqStart + req->len - 1;
   Addr reqLen   = req->len;

   /* These hold indices for segments found during search, or -1 if not
      found. */
   Int floatIdx = -1;
   Int fixedIdx = -1;

   aspacem_assert(nsegments_used > 0);

   VG_(show_nsegments)(0,"getAdvisory");
   VG_(debugLog)(0,"aspacem", "getAdvisory 0x%llx %lld\n", 
                   (ULong)req->start, (ULong)req->len);

   /* Reject zero-length requests */
   if (req->len == 0)
      return False;

   /* Reject wraparounds */
   if ((req->rkind==MFixed || req->rkind==MHint)
       && req->start + req->len < req->start)
      return False;

   /* ------ Implement Policy Exception #1 ------ */

   if (forClient && req->rkind == MFixed) {
      Int  iLo   = find_nsegment_idx(reqStart);
      Int  iHi   = find_nsegment_idx(reqEnd);
      Bool allow = True;
      for (i = iLo; i <= iHi; i++) {
         if (nsegments[i].kind == SkFree
             || (nsegments[i].kind == SkFile && nsegments[i].isClient)) {
            /* ok */
         } else {
            allow = False;
            break;
         }
      }
      if (allow) {
         *result = reqStart;
         return True;
       }
       return False;
   }

   /* ------ Implement the Default Policy ------ */

   /* Don't waste time looking for a fixed match if not requested to. */
   fixed_not_required = req->rkind == MAny;

   i = find_nsegment_idx(startPoint);

   /* Examine holes from index i back round to i-1.  Record the
      index first fixed hole and the first floating hole which would
      satisfy the request. */
   for (j = 0; j < nsegments_used; j++) {

      if (nsegments[i].kind != SkFree) {
         i++;
         if (i >= nsegments_used) i = 0;
         continue;
      }

      holeStart = nsegments[i].start;
      holeEnd   = nsegments[i].end;

      /* Stay sane .. */
      aspacem_assert(holeStart <= holeEnd);
      aspacem_assert(aspacem_minAddr <= holeStart);
      aspacem_assert(holeEnd <= aspacem_maxAddr);

      /* See if it's any use to us. */
      holeLen = holeEnd - holeStart + 1;

      if (fixedIdx == -1 && holeStart <= reqStart && reqEnd <= holeEnd)
         fixedIdx = i;

      if (floatIdx == -1 && holeLen >= reqLen)
         floatIdx = i;
  
      /* Don't waste time searching once we've found what we wanted. */
      if ((fixed_not_required || fixedIdx >= 0) && floatIdx >= 0)
         break;

      i++;
      if (i >= nsegments_used) i = 0;
   }

   aspacem_assert(fixedIdx >= -1 && fixedIdx < nsegments_used);
   if (fixedIdx >= 0) 
      aspacem_assert(nsegments[fixedIdx].kind == SkFree);

   aspacem_assert(floatIdx >= -1 && floatIdx < nsegments_used);
   if (floatIdx >= 0) 
      aspacem_assert(nsegments[floatIdx].kind == SkFree);

   /* Now see if we found anything which can satisfy the request. */
   switch (req->rkind) {
      case MFixed:
         if (fixedIdx >= 0) {
            *result = req->start;
            return True;
         } else {
            return False;
         }
         break;
      case MHint:
         if (fixedIdx >= 0) {
            *result = req->start;
            return True;
         }
         if (floatIdx >= 0) {
            *result = nsegments[floatIdx].start;
            return True;
         }
         return False;
      case MAny:
         if (floatIdx >= 0) {
            *result = nsegments[floatIdx].start;
            return True;
         }
         return False;
      default: 
         break;
   }

   /*NOTREACHED*/
   aspacem_barf("getAdvisory: unknown request kind");
   return False;
}



static void init_nsegment ( /*OUT*/NSegment* seg )
{
   seg->kind     = SkAnon;
   seg->isClient = False;
   seg->start    = 0;
   seg->end      = 0;
   seg->smode    = SmFixed;
   seg->dev      = 0;
   seg->ino      = 0;
   seg->offset   = 0;
   seg->fnIdx    = -1;
   seg->hasR = seg->hasR = seg->hasW = seg->hasT = False;
   seg->mark = False;
}

static void init_resvn ( /*OUT*/NSegment* seg, Addr start, Addr end )
{
  aspacem_assert(start < end);
  aspacem_assert(VG_IS_PAGE_ALIGNED(start));
  aspacem_assert(VG_IS_PAGE_ALIGNED(end+1));
  init_nsegment(seg);
  seg->kind = SkResvn;
  seg->start = start;
  seg->end = end;
}

static HChar* show_seg_kind ( NSegment* seg )
{
  switch (seg->kind) {
  case SkFree: return "    ";
  case SkAnon: return seg->isClient ? "anon" : "ANON";
  case SkFile: return seg->isClient ? "file" : "FILE";
  case SkResvn: return "RSVN";
  default: return "????";
  }
}

static HChar* show_ShrinkMode ( ShrinkMode sm )
{
  switch (sm) {
  case SmLower: return "SmLower";
  case SmUpper: return "SmUpper";
  case SmFixed: return "SmFixed";
  default: return "Sm?????";
  }
}

static void show_Addr_concisely ( /*OUT*/HChar* buf, Addr aA )
{
  HChar* fmt;
  ULong a = (ULong)aA;
  if (a >= 10000000ULL) {
    fmt = "%6llum";
a /= 1024*1024ULL;
  } else {
    fmt = "%7llu";
  }
  aspacem_sprintf(buf, fmt, a);
}

static void show_nsegment ( Int logLevel, Int segNo, NSegment* seg )
{
  HChar len_buf[20];
    ULong len = ((ULong)seg->end) - ((ULong)seg->start) + 1;
    show_Addr_concisely(len_buf, len);

  switch (seg->kind) {
  case SkFree: {
  VG_(debugLog)(
     logLevel, "aspacem",
     "%3d: %s %08llx-%08llx %s\n",
      segNo,
     show_seg_kind(seg),
     (ULong)seg->start,
     (ULong)seg->end,
     len_buf
  );
  break;
  }

  case SkAnon:
  VG_(debugLog)(
     logLevel, "aspacem",
     "%3d: %s %08llx-%08llx %s %c%c%c%c d=0x%03x i=%-7d o=%-7lld (%d)\n",
      segNo,
     show_seg_kind(seg),
     (ULong)seg->start,
     (ULong)seg->end,
     len_buf,
     seg->hasR ? 'r' : '-', 
     seg->hasW ? 'w' : '-', 
     seg->hasX ? 'x' : '-', 
     seg->hasT ? 'T' : '-', 
     seg->dev,
     seg->ino,
     (Long)seg->offset,
     seg->fnIdx
     );
  break;
  case SkFile:
  VG_(debugLog)(
     logLevel, "aspacem",
     "%3d: %s %08llx-%08llx %s %c%c%c%c d=0x%03x i=%-7d o=%-7lld (%d)\n",
      segNo,
     show_seg_kind(seg),
     (ULong)seg->start,
     (ULong)seg->end,
     len_buf,
     seg->hasR ? 'r' : '-', 
     seg->hasW ? 'w' : '-', 
     seg->hasX ? 'x' : '-', 
     seg->hasT ? 'T' : '-', 
     seg->dev,
     seg->ino,
     (Long)seg->offset,
     seg->fnIdx
     );
  break;
  case SkResvn:
  VG_(debugLog)(
     logLevel, "aspacem",
     "%3d: %s %08llx-%08llx %s %c%c%c%c %s\n",
      segNo,
     show_seg_kind(seg),
     (ULong)seg->start,
     (ULong)seg->end,
     len_buf,
     seg->hasR ? 'r' : '-', 
     seg->hasW ? 'w' : '-', 
     seg->hasX ? 'x' : '-', 
     seg->hasT ? 'T' : '-', 
     show_ShrinkMode(seg->smode)
     );
  break;

  default:
  VG_(debugLog)(
     logLevel, "aspacem",
     "%3d: ???? UNKNOWN SEGMENT KIND\n",
segNo );
  break;
  }
}

/* Print out the segment array (debugging only!). */
void VG_(show_nsegments) ( Int logLevel, HChar* who )
{
   Int i;
   VG_(debugLog)(logLevel, "aspacem",
                 "<<< SHOW_SEGMENTS: %s (%d segments, %d segnames)\n", 
                 who, segments_used, segnames_used);
   for (i = 0; i < segnames_used; i++) {
      if (!segnames[i].inUse)
         continue;
      VG_(debugLog)(logLevel, "aspacem",
                    "(%2d) %s\n", i, segnames[i].fname);
   }
   for (i = 0; i < nsegments_used; i++)
     show_nsegment( logLevel, i, &nsegments[i] );
   VG_(debugLog)(logLevel, "aspacem",
                 ">>>\n");
}


/* Add SEG to the collection, deleting/truncating any it overlaps */
static void add_segment ( NSegment* seg )
{
  Int  nDeld, i, j, k;
  Addr iStart, iEnd;

  Addr dStart = seg->start;
  Addr dEnd   = seg->end;

  aspacem_assert(dStart <= dEnd);
  aspacem_assert(VG_IS_PAGE_ALIGNED(dStart));
  aspacem_assert(VG_IS_PAGE_ALIGNED(dEnd+1));

  nDeld = 0;

  for (i = 0; i < nsegments_used; i++) {

    nsegments[i].mark = False;

    iStart = nsegments[i].start;
    iEnd = nsegments[i].end;

    /* no-overlap cases */
    if (iEnd < dStart) continue;
    if (dEnd < iStart) continue;

    if (dStart <= iStart && iEnd <= dEnd) {
      /* i is completely overlapped.  Mark it for deletion. */
      nsegments[i].mark = True;
      nDeld++;
      continue;
    }

    if (iStart < dStart && iEnd > dEnd) {
      /* deleted interval is completely contained within i.  This
	 means i has to be split into two pieces.  As a result, first
	 move the following elements up by one place to make space for
	 the new part. */
      if (nsegments_used >= VG_N_SEGMENTS)
	aspacem_barf_toolow("VG_N_SEGMENTS");
      for (j = nsegments_used-1; j > i; j--)
	nsegments[j+1] = nsegments[j];
      nsegments_used++;
      nsegments[i+1] = nsegments[i];
      nsegments[i].end = dStart-1;
      nsegments[i+1].start = dEnd+1;
      nsegments[i+1].offset += (nsegments[i+1].start - nsegments[i].start);
      continue;
    }

    if (iStart < dStart && iEnd <= dEnd && iEnd >= dStart) {
      /* interval to be deleted straddles upper boundary of i. */
      nsegments[i].end = dStart-1;
      continue;
    }

    if (iEnd > dEnd && iStart >= dStart && iStart <= dEnd) {
      /* interval to be deleted straddles lower boundary of i. */
      nsegments[i].offset += (dEnd+1 - nsegments[i].start);
      nsegments[i].start = dEnd+1;
      continue;
    }

    /* I don't think we can get here. */
    aspacem_assert(0);
  }

  /* Get rid of the intervals marked for deletion. */
  if (nDeld > 0) {
    j = 0;
    for (i = 0; i < nsegments_used; i++) {
      if (nsegments[i].mark)
	continue;
      nsegments[j] = nsegments[i];
      j++;
    }
    nsegments_used -= nDeld;
  }

  /* At this point, there should be a gap dStart .. dEnd inclusive.
     Find the gap and insert the new interval in it.  Set k so that
     all entries >= k must be moved up 1, and the new interval placed
     at k. */
  if (nsegments_used >= VG_N_SEGMENTS)
    aspacem_barf_toolow("VG_N_SEGMENTS");
  if (nsegments_used == 0) {
    k = 0;
  } else {
     for (i = 0; i < nsegments_used; i++)
       if (dEnd+1 == nsegments[i].start 
           && /*guard against wraparound*/dEnd+1 > dEnd)
         break;
     k = i;
  }

  aspacem_assert(k >= 0 && k <= nsegments_used);
  for (j = nsegments_used-1; j >= k; j--)
    nsegments[j+1] = nsegments[j];
  nsegments_used++;

  nsegments[k] = *seg;

  check_nsegments();
}



static void read_maps_callback ( 
 Addr addr, SizeT len, UInt prot,
			   UInt dev, UInt ino, ULong foff, const UChar* filename )
{
  NSegment seg;
  init_nsegment( &seg );
  seg.start = addr;
  seg.end = addr+len-1;
  seg.dev = dev;
  seg.ino = ino;
  seg.offset = foff;
  seg.hasR = toBool(prot & VKI_PROT_READ);
  seg.hasW = toBool(prot & VKI_PROT_WRITE);
  seg.hasX = toBool(prot & VKI_PROT_EXEC);

  seg.kind = SkAnon;
  if (filename) { 
     seg.kind = SkFile;
     seg.fnIdx = allocate_segname( filename );
  }

  show_nsegment( 2,0, &seg );
  add_segment( &seg );
}

Addr VG_(new_aspacem_start) ( Addr sp_at_startup )
{
   NSegment seg;
   Addr     suggested_clstack_top;

   aspacem_assert(sizeof(Word)   == sizeof(void*));
   aspacem_assert(sizeof(Addr)   == sizeof(void*));
   aspacem_assert(sizeof(SizeT)  == sizeof(void*));
   aspacem_assert(sizeof(SSizeT) == sizeof(void*));

   /* Add a single interval covering the entire address space. */
   init_nsegment(&seg);
   seg.kind        = SkFree;
   seg.start       = Addr_MIN;
   seg.end         = Addr_MAX;
   nsegments[0]    = seg;
   nsegments_used  = 1;

   /* Establish address limits and block out unusable parts
      accordingly. */

   VG_(debugLog)(2, "aspacem", 
                    "        sp_at_startup = 0x%llx (supplied)\n", 
                    (ULong)sp_at_startup );

   aspacem_minAddr = (Addr) 0x04000000; // 64M

#  if VG_WORDSIZE == 8
   aspacem_maxAddr = (Addr)0x400000000 - 1; // 16G
#  else
   aspacem_maxAddr = VG_PGROUNDDN( sp_at_startup ) - 1;
#  endif

   aspacem_cStart = aspacem_minAddr; // 64M
   aspacem_vStart = VG_PGROUNDUP((aspacem_minAddr + aspacem_maxAddr + 1) / 2);

   suggested_clstack_top = aspacem_maxAddr - 16*1024*1024ULL
                                           + VKI_PAGE_SIZE;

   aspacem_assert(VG_IS_PAGE_ALIGNED(aspacem_minAddr));
   aspacem_assert(VG_IS_PAGE_ALIGNED(aspacem_maxAddr + 1));
   aspacem_assert(VG_IS_PAGE_ALIGNED(aspacem_cStart));
   aspacem_assert(VG_IS_PAGE_ALIGNED(aspacem_vStart));
   aspacem_assert(VG_IS_PAGE_ALIGNED(suggested_clstack_top + 1));

   VG_(debugLog)(2, "aspacem", 
                    "              minAddr = 0x%08llx (computed)\n", 
                    (ULong)aspacem_minAddr);
   VG_(debugLog)(2, "aspacem", 
                    "              maxAddr = 0x%08llx (computed)\n", 
                    (ULong)aspacem_maxAddr);
   VG_(debugLog)(2, "aspacem", 
                    "               cStart = 0x%08llx (computed)\n", 
                    (ULong)aspacem_cStart);
   VG_(debugLog)(2, "aspacem", 
                    "               vStart = 0x%08llx (computed)\n", 
                    (ULong)aspacem_vStart);
   VG_(debugLog)(2, "aspacem", 
                    "suggested_clstack_top = 0x%08llx (computed)\n", 
                    (ULong)suggested_clstack_top);

   if (aspacem_cStart > Addr_MIN) {
      init_resvn(&seg, Addr_MIN, aspacem_cStart-1);
      add_segment(&seg);
   }
   if (aspacem_maxAddr < Addr_MAX) {
      init_resvn(&seg, aspacem_maxAddr+1, Addr_MAX);
      add_segment(&seg);
   }

   /* Create a 1-page reservation at the notional initial
      client/valgrind boundary.  This isn't strictly necessary, but
      because the advisor does first-fit and starts searches for
      valgrind allocations at the boundary, this is kind of necessary
      in order to get it to start allocating in the right place. */
   init_resvn(&seg, aspacem_vStart,  aspacem_vStart + VKI_PAGE_SIZE - 1);
   add_segment(&seg);

   VG_(show_nsegments)(2, "Initial layout");

   VG_(debugLog)(2, "aspacem", "Reading /proc/self/maps\n");
   VG_(parse_procselfmaps) ( read_maps_callback );

   VG_(show_nsegments)(2, "With contents of /proc/self/maps");

   return suggested_clstack_top;
}


SysRes VG_(mmap_file_fixed_client)
     ( void* startV, SizeT length, Int prot, Int fd, SizeT offset )
{
   SysRes     sres;
   NSegment   seg;
   Addr       advised;
   Bool       ok;
   MapRequest req;
   UInt       dev, ino;
   HChar      buf[VKI_PATH_MAX];
 
   Addr start = (Addr)startV; 
 
   /* Not allowable. */
   /* Not allowable. */
   if (length == 0 || !VG_IS_PAGE_ALIGNED(start))
      return VG_(mk_SysRes_Error)( VKI_EINVAL );

   /* Ask for an advisory.  If it's negative, fail immediately. */
   req.rkind = MFixed;
   req.start = start;
   req.len   = length;
   ok = VG_(aspacem_getAdvisory)( &req, True/*client*/, &advised );
   if (!ok || advised != start)
      return VG_(mk_SysRes_Error)( VKI_EINVAL );

   /* We have been advised that the mapping is allowable at the
      specified address.  So hand it off to the kernel, and propagate
      any resulting failure immediately. */
   sres = VG_(aspacem_do_mmap_NO_NOTIFY)( 
             start, length, prot, 
             VKI_MAP_FIXED|VKI_MAP_PRIVATE, 
             fd, offset 
          );
   if (sres.isError)
      return sres;

   if (sres.val != start) {
      /* I don't think this can happen.  It means the kernel made a
         fixed map succeed but not at the requested location.  Try to
         repair the damage, then return saying the mapping failed. */
      (void)do_munmap_NATIVE( sres.val, length );
      return VG_(mk_SysRes_Error)( VKI_EINVAL );
   }

   /* Ok, the mapping succeeded.  Now notify the interval map. */
   init_nsegment( &seg );
   seg.kind     = SkFile;
   seg.isClient = True;
   seg.start    = start;
   seg.end      = seg.start + VG_PGROUNDUP(length) - 1;
   seg.offset   = offset;
   seg.hasR     = toBool(prot & VKI_PROT_READ);
   seg.hasW     = toBool(prot & VKI_PROT_WRITE);
   seg.hasX     = toBool(prot & VKI_PROT_EXEC);
   if (get_inode_for_fd(fd, &dev, &ino)) {
      seg.dev = dev;
      seg.ino = ino;
   }
   if (get_name_for_fd(fd, buf, VKI_PATH_MAX)) {
      seg.fnIdx = allocate_segname( buf );
   }
   add_segment( &seg );

   return sres;
}


SysRes VG_(mmap_anon_fixed_client)
     ( void* startV, SizeT length, Int prot )
{
   SysRes     sres;
   NSegment   seg;
   Addr       advised;
   Bool       ok;
   MapRequest req;
 
   Addr start = (Addr)startV; 
 
   /* Not allowable. */
   if (length == 0 || !VG_IS_PAGE_ALIGNED(start))
      return VG_(mk_SysRes_Error)( VKI_EINVAL );

   /* Ask for an advisory.  If it's negative, fail immediately. */
   req.rkind = MFixed;
   req.start = start;
   req.len   = length;
   ok = VG_(aspacem_getAdvisory)( &req, True/*client*/, &advised );
   if (!ok || advised != start)
      return VG_(mk_SysRes_Error)( VKI_EINVAL );

   /* We have been advised that the mapping is allowable at the
      specified address.  So hand it off to the kernel, and propagate
      any resulting failure immediately. */
   sres = VG_(aspacem_do_mmap_NO_NOTIFY)( 
             start, length, prot, 
             VKI_MAP_FIXED|VKI_MAP_PRIVATE|VKI_MAP_ANONYMOUS, 
             0, 0 
          );
   if (sres.isError)
      return sres;

   if (sres.val != start) {
      /* I don't think this can happen.  It means the kernel made a
         fixed map succeed but not at the requested location.  Try to
         repair the damage, then return saying the mapping failed. */
      (void)do_munmap_NATIVE( sres.val, length );
      return VG_(mk_SysRes_Error)( VKI_EINVAL );
   }

   /* Ok, the mapping succeeded.  Now notify the interval map. */
   init_nsegment( &seg );
   seg.kind     = SkAnon;
   seg.isClient = True;
   seg.start    = start;
   seg.end      = seg.start + VG_PGROUNDUP(length) - 1;
   seg.hasR     = toBool(prot & VKI_PROT_READ);
   seg.hasW     = toBool(prot & VKI_PROT_WRITE);
   seg.hasX     = toBool(prot & VKI_PROT_EXEC);
   add_segment( &seg );

   return sres;
}


SysRes VG_(mmap_anon_float_client)
     ( SizeT length, Int prot )
{
   SysRes     sres;
   NSegment   seg;
   Addr       advised;
   Bool       ok;
   MapRequest req;
 
   /* Not allowable. */
   if (length == 0)
      return VG_(mk_SysRes_Error)( VKI_EINVAL );

   /* Ask for an advisory.  If it's negative, fail immediately. */
   req.rkind = MAny;
   req.start = 0;
   req.len   = length;
   ok = VG_(aspacem_getAdvisory)( &req, True/*client*/, &advised );
   if (!ok)
      return VG_(mk_SysRes_Error)( VKI_EINVAL );

   /* We have been advised that the mapping is allowable at the
      advised address.  So hand it off to the kernel, and propagate
      any resulting failure immediately. */
   sres = VG_(aspacem_do_mmap_NO_NOTIFY)( 
             advised, length, prot, 
             VKI_MAP_FIXED|VKI_MAP_PRIVATE|VKI_MAP_ANONYMOUS, 
             0, 0 
          );
   if (sres.isError)
      return sres;

   if (sres.val != advised) {
      /* I don't think this can happen.  It means the kernel made a
         fixed map succeed but not at the requested location.  Try to
         repair the damage, then return saying the mapping failed. */
      (void)do_munmap_NATIVE( sres.val, length );
      return VG_(mk_SysRes_Error)( VKI_EINVAL );
   }

   /* Ok, the mapping succeeded.  Now notify the interval map. */
   init_nsegment( &seg );
   seg.kind     = SkAnon;
   seg.isClient = True;
   seg.start    = advised;
   seg.end      = seg.start + VG_PGROUNDUP(length) - 1;
   seg.hasR     = toBool(prot & VKI_PROT_READ);
   seg.hasW     = toBool(prot & VKI_PROT_WRITE);
   seg.hasX     = toBool(prot & VKI_PROT_EXEC);
   add_segment( &seg );

   return sres;
}


SysRes VG_(map_anon_float_valgrind)( SizeT length )
{
   SysRes     sres;
   NSegment   seg;
   Addr       advised;
   Bool       ok;
   MapRequest req;
 
   /* Not allowable. */
   if (length == 0)
      return VG_(mk_SysRes_Error)( VKI_EINVAL );

   /* Ask for an advisory.  If it's negative, fail immediately. */
   req.rkind = MAny;
   req.start = 0;
   req.len   = length;
   ok = VG_(aspacem_getAdvisory)( &req, False/*valgrind*/, &advised );
   if (!ok)
      return VG_(mk_SysRes_Error)( VKI_EINVAL );

   /* We have been advised that the mapping is allowable at the
      specified address.  So hand it off to the kernel, and propagate
      any resulting failure immediately. */
   sres = VG_(aspacem_do_mmap_NO_NOTIFY)( 
             advised, length, 
             VKI_PROT_READ|VKI_PROT_WRITE|VKI_PROT_EXEC, 
             VKI_MAP_FIXED|VKI_MAP_PRIVATE|VKI_MAP_ANONYMOUS, 
             0, 0 
          );
   if (sres.isError)
      return sres;

   if (sres.val != advised) {
      /* I don't think this can happen.  It means the kernel made a
         fixed map succeed but not at the requested location.  Try to
         repair the damage, then return saying the mapping failed. */
      (void)do_munmap_NATIVE( sres.val, length );
      return VG_(mk_SysRes_Error)( VKI_EINVAL );
   }

   /* Ok, the mapping succeeded.  Now notify the interval map. */
   init_nsegment( &seg );
   seg.kind     = SkAnon;
   seg.isClient = False;
   seg.start    = advised;
   seg.end      = seg.start + VG_PGROUNDUP(length) - 1;
   seg.hasR     = True;
   seg.hasW     = True;
   seg.hasX     = True;
   add_segment( &seg );

   return sres;
}


SysRes VG_(munmap_client)( Addr base, SizeT length )
{
   NSegment seg;
   SysRes   sres;

   if (length == 0 || !VG_IS_PAGE_ALIGNED(base))
      return VG_(mk_SysRes_Error)( VKI_EINVAL );

   sres = do_munmap_NATIVE( base, length );
   if (sres.isError)
      return sres;

   init_nsegment( &seg );
   seg.kind = SkFree;
   seg.start = base;
   seg.end = seg.start + VG_PGROUNDUP(length) - 1;
   add_segment( &seg );

   return sres;
}


/* See comment on prototype in pub_core_aspacemgr.h for a description
   of this. */
Bool VG_(create_reservation) ( Addr start, SizeT length, 
                               ShrinkMode smode, SSizeT extra )
{
   Int      startI, endI;
   NSegment seg;

   /* start and end, not taking into account the extra space. */
   Addr start1 = start;
   Addr end1   = start + length - 1;

   /* start and end, taking into account the extra space. */
   Addr start2 = start1;
   Addr end2   = end1;

   if (extra < 0) start2 += extra; // this moves it down :-)
   if (extra > 0) end2 += extra;

   aspacem_assert(VG_IS_PAGE_ALIGNED(start));
   aspacem_assert(VG_IS_PAGE_ALIGNED(start+length));
   aspacem_assert(VG_IS_PAGE_ALIGNED(start2));
   aspacem_assert(VG_IS_PAGE_ALIGNED(end2+1));

   startI = find_nsegment_idx( start2 );
   endI = find_nsegment_idx( end2 );

   /* If the start and end points don't fall within the same (free)
      segment, we're hosed.  This does rely on the assumption that all
      mergeable adjacent segments can be merged, but add_segment()
      should ensure that. */
   if (startI != endI)
      return False;

   if (nsegments[startI].kind != SkFree)
      return False;

   /* Looks good - make the reservation. */
   aspacem_assert(nsegments[startI].start <= start2);
   aspacem_assert(end2 <= nsegments[startI].end);

   init_nsegment( &seg );
   seg.kind = SkResvn;
   seg.start = start1;  /* NB: extra space is not included in the reservation. */
   seg.end = end1;
   seg.smode = smode;
   add_segment( &seg );
   return True;
}


/* See comment on prototype in pub_core_aspacemgr.h for a description
   of this. */
Bool VG_(extend_into_adjacent_reservation)( NSegment* seg, SSizeT delta )
{
   Int    segA, segR;
   UInt   prot;
   SysRes sres;

   /* Find the segment array index for SEG.  If the assertion fails it
      probably means you passed in a bogus SEG. */
   segA = segAddr_to_index( seg );
   aspacem_assert(segA >= 0 && segA < nsegments_used);

   if (nsegments[segA].kind != SkAnon)
      return False;

   if (delta == 0)
      return True;

   prot =   (nsegments[segA].hasR ? VKI_PROT_READ : 0)
          | (nsegments[segA].hasW ? VKI_PROT_WRITE : 0)
          | (nsegments[segA].hasX ? VKI_PROT_EXEC : 0);

   aspacem_assert(VG_IS_PAGE_ALIGNED(delta<0 ? -delta : delta));

   if (delta > 0) {

      /* Extending the segment forwards. */
      segR = segA+1;
      if (segR >= nsegments_used
          || nsegments[segR].kind != SkResvn
          || nsegments[segR].smode != SmLower
          || nsegments[segR].start != nsegments[segA].end + 1
          || delta > (nsegments[segR].end - nsegments[segR].start + 1))
	return False;
        
      /* Extend the kernel's mapping. */
      sres = VG_(aspacem_do_mmap_NO_NOTIFY)( 
                nsegments[segR].start, delta,
                prot,
                VKI_MAP_FIXED|VKI_MAP_PRIVATE|VKI_MAP_ANONYMOUS, 
                0, 0 
             );
      if (sres.isError)
         return False; /* kernel bug if this happens? */
      if (sres.val != nsegments[segR].start) {
	 /* kernel bug if this happens? */
	do_munmap_NATIVE( sres.val, delta );
	return False;
      }

      /* Ok, success with the kernel.  Update our structures. */
      nsegments[segR].start += delta;
      nsegments[segA].end += delta;
      aspacem_assert(nsegments[segR].start <= nsegments[segR].end);

   } else {

      /* Extending the segment backwards. */
      delta = -delta;
      aspacem_assert(delta > 0);

      segR = segA-1;
      if (segR < 0
          || nsegments[segR].kind != SkResvn
          || nsegments[segR].smode != SmUpper
          || nsegments[segR].end + 1 != nsegments[segA].start
          || delta > (nsegments[segR].end - nsegments[segR].start + 1))
	return False;
        
      /* Extend the kernel's mapping. */
      sres = VG_(aspacem_do_mmap_NO_NOTIFY)( 
                nsegments[segA].start-delta, delta,
                prot,
                VKI_MAP_FIXED|VKI_MAP_PRIVATE|VKI_MAP_ANONYMOUS, 
                0, 0 
             );
      if (sres.isError)
         return False; /* kernel bug if this happens? */
      if (sres.val != nsegments[segA].start-delta) {
	 /* kernel bug if this happens? */
	do_munmap_NATIVE( sres.val, delta );
	return False;
      }

      /* Ok, success with the kernel.  Update our structures. */
      nsegments[segR].end -= delta;
      nsegments[segA].start -= delta;
      aspacem_assert(nsegments[segR].start <= nsegments[segR].end);

   }

   return True;
}


void 
VG_(notify_client_mmap)( Addr a, SizeT len, UInt prot, UInt flags,
                         Int fd, SizeT offset )
{
   HChar buf[VKI_PATH_MAX];
   UInt dev, ino;
   NSegment seg;
   aspacem_assert(len > 0);
   aspacem_assert(VG_IS_PAGE_ALIGNED(a));
   aspacem_assert(VG_IS_PAGE_ALIGNED(len));
   init_nsegment( &seg );
   seg.kind     = (flags & VKI_MAP_ANONYMOUS) ? SkAnon : SkFile;
   seg.isClient = True;
   seg.start    = a;
   seg.end      = a + len - 1;
   seg.offset   = offset;
   seg.hasR     = toBool(prot & VKI_PROT_READ);
   seg.hasW     = toBool(prot & VKI_PROT_WRITE);
   seg.hasX     = toBool(prot & VKI_PROT_EXEC);
   /* TODO: what about seg.hasT ? */
   if (get_inode_for_fd(fd, &dev, &ino)) {
     seg.dev = dev;
     seg.ino = ino;
   }
   if (get_name_for_fd(fd, buf, VKI_PATH_MAX)) {
      seg.fnIdx = allocate_segname( buf );
   }
   add_segment( &seg );
}


void VG_(notify_client_mprotect)( Addr start, SizeT len, UInt prot )
{
   Int iLo, iHi;

   if (len == 0)
      return;

   iLo = find_nsegment_idx(start);
   iHi = find_nsegment_idx(start + len - 1);

   if (iLo == iHi 
       && nsegments[iLo].start == start 
       && nsegments[iLo].end+1 == start+len
       && (nsegments[iLo].kind == SkFile || nsegments[iLo].kind == SkAnon)) {
      nsegments[iLo].hasR = toBool(prot & VKI_PROT_READ);
      nsegments[iLo].hasW = toBool(prot & VKI_PROT_WRITE);
      nsegments[iLo].hasX = toBool(prot & VKI_PROT_EXEC);
      return;
   }

   /* FIXME: unhandled general case */
   aspacem_barf("notify_mprotect general case");
}


void VG_(notify_client_munmap)( Addr start, SizeT len )
{
   NSegment seg;

   if (len == 0)
      return;

   init_nsegment( &seg );
   seg.kind  = SkFree;
   seg.start = start;
   seg.end   = start + len - 1;
   add_segment( &seg );
}


/* Test if a piece of memory is addressable by the client with at
   least the "prot" protection permissions by examining the underlying
   segments.
*/
Bool VG_(aspacem_is_valid_for_client)( Addr start, SizeT len, UInt prot )
{
   Int  i, iLo, iHi;
   Bool needR, needW, needX;

   if (len == 0)
      return True; /* somewhat dubious case */
   if (start + len < start)
      return False; /* reject wraparounds */

   needR = toBool(prot & VKI_PROT_READ);
   needW = toBool(prot & VKI_PROT_WRITE);
   needX = toBool(prot & VKI_PROT_EXEC);

   iLo = find_nsegment_idx(start);
   iHi = find_nsegment_idx(start + len - 1);
   for (i = iLo; i <= iHi; i++) {
      if (nsegments[i].isClient
          && (nsegments[i].kind == SkFile || nsegments[i].kind == SkAnon)
          && (needR ? nsegments[i].hasR : True)
          && (needW ? nsegments[i].hasW : True)
          && (needX ? nsegments[i].hasX : True)) {
         /* ok */
      } else {
         return False;
      }
   }
   return True;
}


/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
