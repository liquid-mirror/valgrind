
/*--------------------------------------------------------------------*/
/*--- The address space manager: segment initialisation and        ---*/
/*--- tracking, stack operations                                   ---*/
/*---                                                              ---*/
/*--- Implementation for BlueGene              m_aspacemgr-blrts.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2006-2006 OpenWorks LLP
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

#if defined(VGPV_ppc64_linux_bgq)

/* *************************************************************
   DO NOT INCLUDE ANY OTHER FILES HERE.
   ADD NEW INCLUDES ONLY TO priv_aspacemgr.h
   AND THEN ONLY AFTER READING DIRE WARNINGS THERE TOO.
   ************************************************************* */

#include "priv_aspacemgr.h"

/* A Purely Observational Address Space Manager.  Merely observes and
   records events pertaining to address space of the process, but
   makes no attempt to influence layout. */

/* ----------------- BlueGene configuration ----------------- */

/* This is the only unknown: how big do we believe the kernel will let
   the main thread stack become?  Needed because we need to add a
   BSegment covering the main thread stack, but we don't know how big
   it is. */

#define CONFIG_CLIENT_STACK_MBYTES 4

/* --------------- end BlueGene configuration --------------- */



/* Note: many of the exported functions implemented below are
   described more fully in comments in pub_core_aspacemgr.h.
*/


/*-----------------------------------------------------------------*/
/*---                                                           ---*/
/*--- The Address Space Manager's state.                        ---*/
/*---                                                           ---*/
/*-----------------------------------------------------------------*/

/* Describes observational segment kinds */

typedef
   enum {
      BSkUnknown=1,  // status of this area is unknown
      BSkAnonC,      // non-file-backed mapping belonging to the client
      BSkAnonV,      // non-file-backed mapping belonging to valgrind
      BSkFileC,      // file backed mapping belonging to the client
      BSkFileV       // file backed mapping belonging to valgrind
   }
   BSegKind;

/* Segment table entries, in summary:

   BSkUnknown  start end
   BSkAnonC    start end perms isCH hasT isCS
   BSkAnonV    start end perms 
   BSkFileC    start end perms hasT fd offset isExe
   BSkFileV    start end perms fd offset

   Entries are non-overlapping, non-zero-sized, in order, and together
   cover the entire address space exactly once.  They do not have to be
   page aligned.
*/
typedef
   struct {
      BSegKind kind;

      /* ALL: extent */
      /* Note: zero-length segments are not allowed.  That guarantees
         that start <= end. */
      Addr start;  // lowest addr in range (ALL)
      Addr end;    // highest addr in range (ALL)

      /* {Anon,File}{C,V}: perms */
      Bool hasR;
      Bool hasW;
      Bool hasX;

      /* misc */
      Bool isCH;  // AnonC: is this part of the client's heap?
      Bool isCS;  // AnonC: is this part of the client's (thread-1) stack?
      Bool hasT;  // {Anon,File}C: true if this seg has or might have had
                  // translations taken from it
      Int    fd;    // File{C,V}: fd that got mapped
      Off64T offs;  // File{C,V}: offset in file
      Bool   isExe; // FileC: is this file the main exe? (BGQ-specific hack)
   }
   BSegment;


/* ------ start of STATE for the address-space manager ------ */

#define VG_N_BSEGMENTS 1000

static BSegment bsegs[VG_N_BSEGMENTS];
static Int      bsegs_used = 0;

static HChar* name_of_exe = NULL;

/* ------ end of STATE for the address-space manager ------ */

#define Addr_MIN ((Addr)0)
#define Addr_MAX ((Addr)(-1ULL))

/* ------ Forwards decls ------ */

static void read_elf_phdr ( HChar* fname );



/*-----------------------------------------------------------------*/
/*---                                                           ---*/
/*--- Low level BSegment stuff.                                 ---*/
/*---                                                           ---*/
/*-----------------------------------------------------------------*/

static Bool eq_Bool ( Bool b1, Bool b2 ) {
   if (b1 && b2) return True;
   if (!b1 && !b2) return True;
   return False;
}

static void local_memset ( void* pV, UChar b, UWord n )
{
   UChar* p = (UChar*)pV;
   while (n > 0) { *p = b; p++; n--; }
}

static void init_BSegment ( BSegment* s )
{
   // This sets s->kind == 0, which is invalid.
   local_memset(s, 0, sizeof(*s));
}


static HChar* name_of_BSegKind ( BSegKind sk )
{
   switch (sk) {
      case BSkUnknown: return "UnKnown";
      case BSkAnonC:   return "AnonC  ";
      case BSkAnonV:   return "AnonV  ";
      case BSkFileC:   return "FileC  ";
      case BSkFileV:   return "FileV  ";
      default:         ML_(am_barf)("name_of_BSegKind");
      /*NOTREACHED*/
      return NULL;
   }
}


/* FIXME: duplicate of -linux version; common up. */
static void show_len_concisely ( /*OUT*/HChar* buf, Addr start, Addr end )
{
   HChar* fmt;
   ULong len = ((ULong)end) - ((ULong)start) + 1;

   if (len < 10*1000*1000ULL) {
      fmt = "%7llu";
   } 
   else if (len < 999999ULL * (1ULL<<20)) {
      fmt = "%6llum";
      len >>= 20;
   }
   else if (len < 999999ULL * (1ULL<<30)) {
      fmt = "%6llug";
      len >>= 30;
   }
   else if (len < 999999ULL * (1ULL<<40)) {
      fmt = "%6llut";
      len >>= 40;
   }
   else {
      fmt = "%6llue";
      len >>= 50;
   }
   ML_(am_sprintf)(buf, fmt, len);
}


static 
void show_BSegment ( Int logLevel, Int segNo, BSegment* seg )
{
   HChar* segName = name_of_BSegKind( seg->kind );
   HChar  len_buf[20];
   show_len_concisely(len_buf, seg->start, seg->end);
   HChar perms[8];
   perms[0] = seg->hasR ? 'r' : '-';
   perms[1] = seg->hasW ? 'w' : '-';
   perms[2] = seg->hasX ? 'x' : '-';
   perms[3] = ' ';
   perms[4] = seg->hasT ? 'T' : '-';
   perms[5] = seg->isCH ? 'H' : '-';
   perms[6] = seg->isCS ? 'S' : '-';
   perms[7] = '\0';

   switch (seg->kind) {
      case BSkUnknown:
         VG_(debugLog)(logLevel, "aspacem",
            "%3d: %s %016llx-%016llx (%s)\n",
            segNo, segName,
            (ULong)seg->start, (ULong)seg->end, len_buf
         );
         break;
      case BSkAnonC:
      case BSkAnonV:
         VG_(debugLog)(logLevel, "aspacem",
            "%3d: %s %016llx-%016llx (%s)  %s\n",
            segNo, segName,
            (ULong)seg->start, (ULong)seg->end, len_buf, perms
         );
         break;
      case BSkFileC:
      case BSkFileV:
         VG_(debugLog)(logLevel, "aspacem",
            "%3d: %s %016llx-%016llx (%s)  %s  isExe=%c  fd=%d  offset=%llu\n",
            segNo, segName,
            (ULong)seg->start, (ULong)seg->end, len_buf, perms,
            seg->isExe ? 'Y' : 'n',
            (Int)seg->fd, (ULong)seg->offs
         );
         break;
      default:
         VG_(debugLog)(logLevel, "aspacem",
                       "%3d: show_BSegment: unknown segment\n", 
                       segNo);
         break;
   }
}


static void init_BSegments ( void )
{
   bsegs_used = 1;
   init_BSegment( &bsegs[0] );
   bsegs[0].kind  = BSkUnknown;
   bsegs[0].start = Addr_MIN;
   bsegs[0].end   = Addr_MAX;
}


static 
void show_BSegments ( Int logLevel, HChar* who )
{
   Int i;
   VG_(debugLog)(logLevel, "aspacem", "<<< %s\n", who);
   VG_(debugLog)(logLevel, "aspacem", "  EXE = %s\n",
                           name_of_exe ? name_of_exe : "(none)" );
   for (i = 0; i < bsegs_used; i++)
      show_BSegment( logLevel, i, &bsegs[i] );
   VG_(debugLog)(logLevel, "aspacem", ">>>\n");
}


static Bool sane_BSegment ( BSegment* seg )
{
   /* disallow zero and negative length segments */
   if (seg->end < seg->start)
      return False;
   switch (seg->kind) {
      case BSkUnknown:
         if (seg->hasR || seg->hasW || seg->hasX
             || seg->isCH || seg->isCS || seg->hasT
             || seg->fd != 0 || seg->offs != 0 || seg->isExe)
            return False;
         break;
      case BSkAnonC:
         if (seg->fd != 0 || seg->offs != 0 || seg->isExe)
            return False;
         break;
      case BSkAnonV:
         if (seg->isCH || seg->isCS || seg->hasT
             || seg->fd != 0 || seg->offs != 0 || seg->isExe)
            return False;
         break;
      case BSkFileC:
         if (seg->isCH || seg->isCS)
            return False;
         break;
      case BSkFileV:
         if (seg->isCH || seg->isCS || seg->hasT || seg->isExe)
            return False;
         break;
      default:
        return False;
   }
   return True;
}


/* Binary search the interval array for a given address.  Since the
   array covers the entire address space the search cannot fail. */

static Int find_bsegment_idx ( Addr a )
{
   Addr a_mid_lo, a_mid_hi;
   Int  mid,
        lo = 0,
        hi = bsegs_used-1;
   aspacem_assert(lo <= hi);
   while (True) {
      /* current unsearched space is from lo to hi, inclusive. */
      if (lo > hi) {
         /* Not found.  This can't happen. */
         ML_(am_barf)("find_bsegment_idx: not found");
      }
      mid      = (lo + hi) / 2;
      a_mid_lo = bsegs[mid].start;
      a_mid_hi = bsegs[mid].end;

      if (a < a_mid_lo) { hi = mid-1; continue; }
      if (a > a_mid_hi) { lo = mid+1; continue; }
      aspacem_assert(a >= a_mid_lo && a <= a_mid_hi);
      aspacem_assert(0 <= mid && mid < bsegs_used);
      return mid;
   }
}


static Bool sane_BSegments ( void )
{
   Int i;

   /* Check endpoints */
   if (bsegs_used < 1 || bsegs_used > VG_N_BSEGMENTS) {
      VG_(debugLog)(0, "aspacem", "sane_BSegments: bad _used");
      return False;
   }
   if (bsegs[0].start != Addr_MIN
       || bsegs[bsegs_used-1].end != Addr_MAX) {
      VG_(debugLog)(0, "aspacem", "sane_BSegments: bad endpoints");
      return False;
   }

   /* Check each segment, and check entire range is covered. */
   for (i = 0; i < bsegs_used; i++) {
      if (!sane_BSegment( &bsegs[i] )) {
         VG_(debugLog)(0, "aspacem", 
	                  "sane_BSegments: bad segment %d\n", i);
         return False;
      }
   }
   for (i = 1; i < bsegs_used; i++) {
      if (bsegs[i-1].end + 1 != bsegs[i].start) {
         VG_(debugLog)(0, "aspacem", 
	                  "sane_BSegments: bad transition at %d/%d\n", i-1,i);
         return False;
      }
   }

   return True;
}


/* Try merging s2 into s1, if possible.  If successful, s1 is
   modified, and True is returned.  Otherwise s1 is unchanged and
   False is returned. */

static Bool maybe_merge_asegments ( BSegment* s1, BSegment* s2 )
{
   if (s1->kind != s2->kind) 
      return False;

   if (s1->end+1 != s2->start)
      return False;

   Bool eq_perms = eq_Bool(s1->hasR, s2->hasR)
                   && eq_Bool(s1->hasW, s2->hasW)
                   && eq_Bool(s1->hasX, s2->hasX);

   switch (s1->kind) {
      case BSkUnknown:
         s1->end = s2->end;
         return True;
      case BSkAnonC:
         if (eq_perms && eq_Bool(s1->isCS, s2->isCS)) {
            s1->end = s2->end;
            s1->isCH = s1->isCH || s2->isCH;
            s1->hasT = s1->hasT || s2->hasT;
            return True;
         }
         break;
      case BSkAnonV:
         if (eq_perms) {
            s1->end = s2->end;
            return True;
         }
         break;
      case BSkFileC:
      case BSkFileV:
         break;
      default:
         break;
   }
   return False;
}


/* Merge mergable segments. */

static void preen_bsegments ( void )
{
   Int r, w;

   aspacem_assert(bsegs_used >= 1);
   if (bsegs_used == 1)
      return;

   w = 0;
   for (r = 1; r < bsegs_used; r++) {
      if (maybe_merge_asegments(&bsegs[w], &bsegs[r])) {
         /* nothing */
      } else {
         w++;
         if (w != r) 
            bsegs[w] = bsegs[r];
      }
   }
   w++;
   aspacem_assert(w > 0 && w <= bsegs_used);
   bsegs_used = w;
}


/* Returns True if any part of the address range is marked as having
   translations made from it.  This is used to determine when to
   discard code, so if in doubt return True. */

static Bool any_Ts_in_range ( Addr start, SizeT len )
{
   Int iLo, iHi, i;
   aspacem_assert(len > 0);
   aspacem_assert(start + len > start);
   iLo = find_bsegment_idx(start);
   iHi = find_bsegment_idx(start + len - 1);
   for (i = iLo; i <= iHi; i++) {
      BSegment* bseg = &bsegs[i];
      aspacem_assert(sane_BSegment(bseg));
      if (bseg->hasT)
         return True;
   }
   return False;
}


/*-----------------------------------------------------------------*/
/*---                                                           ---*/
/*--- Modifying a segment array, and constructing segments.     ---*/
/*---                                                           ---*/
/*-----------------------------------------------------------------*/

/* Split the segment containing 'a' into two, so that 'a' is
   guaranteed to be the start of a new segment.  If 'a' is already the
   start of a segment, do nothing. */

static void split_bsegment_at ( Addr a )
{
   Int i, j;

   aspacem_assert(a > 0);
   aspacem_assert(bsegs_used >= 1);
 
   i = find_bsegment_idx(a);
   aspacem_assert(i >= 0 && i < bsegs_used);

   if (bsegs[i].start == a)
      /* 'a' is already the start point of a segment, so nothing to be
         done. */
      return;

   /* else we have to slide the segments upwards to make a hole */
   if (bsegs_used >= VG_N_BSEGMENTS)
      ML_(am_barf_toolow)("VG_N_BSEGMENTS");
   for (j = bsegs_used-1; j > i; j--)
      bsegs[j+1] = bsegs[j];
   bsegs_used++;

   bsegs[i+1]       = bsegs[i];
   bsegs[i+1].start = a;
   bsegs[i].end     = a-1;

   if (bsegs[i].kind == BSkFileV || bsegs[i].kind == BSkFileC)
      bsegs[i+1].offs 
         += ((ULong)bsegs[i+1].start) - ((ULong)bsegs[i].start);

   aspacem_assert(sane_BSegment(&bsegs[i]));
   aspacem_assert(sane_BSegment(&bsegs[i+1]));
}


/* Do the minimum amount of segment splitting necessary to ensure that
   sLo is the first address denoted by some segment and sHi is the
   highest address denoted by some other segment.  Returns the indices
   of the lowest and highest segments in the range. */

static 
void split_bsegments_lo_and_hi ( Addr sLo, Addr sHi,
                                 /*OUT*/Int* iLo,
                                 /*OUT*/Int* iHi )
{
   aspacem_assert(sLo <= sHi);

   if (sLo > 0)
      split_bsegment_at(sLo);
   if (sHi < Addr_MAX)
      split_bsegment_at(sHi+1);

   *iLo = find_bsegment_idx(sLo);
   *iHi = find_bsegment_idx(sHi);
   aspacem_assert(0 <= *iLo && *iLo < bsegs_used);
   aspacem_assert(0 <= *iHi && *iHi < bsegs_used);
   aspacem_assert(*iLo <= *iHi);
   aspacem_assert(bsegs[*iLo].start == sLo);
   aspacem_assert(bsegs[*iHi].end == sHi);
   /* Not that I'm overly paranoid or anything, definitely not :-) */
}


/* Add SEG to the collection, deleting/truncating any it overlaps.
   This deals with all the tricky cases of splitting up segments as
   needed.  Contents of SEG are copied. */

static void add_bsegment ( BSegment* seg )
{
   Int  i, iLo, iHi, delta;
   Bool segment_is_sane;

   Addr sStart = seg->start;
   Addr sEnd   = seg->end;

   aspacem_assert(sStart <= sEnd);

   segment_is_sane = sane_BSegment(seg);
   if (!segment_is_sane) show_BSegment(0,0,seg);
   aspacem_assert(segment_is_sane);

   split_bsegments_lo_and_hi( sStart, sEnd, &iLo, &iHi );

   /* Now iLo .. iHi inclusive is the range of segment indices which
      seg will replace.  If we're replacing more than one segment,
      slide those above the range down to fill the hole. */
   delta = iHi - iLo;
   aspacem_assert(delta >= 0);
   if (delta > 0) {
      for (i = iLo; i < bsegs_used-delta; i++)
         bsegs[i] = bsegs[i+delta];
      bsegs_used -= delta;
   }
   aspacem_assert(bsegs_used >= 1);

   bsegs[iLo] = *seg;

   preen_bsegments();
   ML_(am_do_sanity_check)();
   if (0) VG_(am_show_nsegments)(0,"AFTER preen (add_segment)");
}


/*-----------------------------------------------------------------*/
/*---                                                           ---*/
/*--- Pushing of segments into the collection.                  ---*/
/*---                                                           ---*/
/*-----------------------------------------------------------------*/

static void add_bsegment_Unknown ( Addr start, Addr end )
{
   BSegment seg;
   init_BSegment(&seg);
   seg.kind  = BSkUnknown;
   seg.start = start;
   seg.end   = end;
   add_bsegment(&seg);
}

static void add_bsegment_AnonC ( Addr start, Addr end,
                                 Bool hasR, Bool hasW, Bool hasX,
                                 Bool isCH, Bool hasT, Bool isCS )
{
   BSegment seg;
   init_BSegment(&seg);
   seg.kind  = BSkAnonC;
   seg.start = start;
   seg.end   = end;
   seg.hasR  = hasR;
   seg.hasW  = hasW;
   seg.hasX  = hasX;
   seg.isCH  = isCH;
   seg.hasT  = hasT;
   seg.isCS  = isCS;
   add_bsegment(&seg);
}

static void add_bsegment_AnonV ( Addr start, Addr end,
                                 Bool hasR, Bool hasW, Bool hasX )
{
   BSegment seg;
   init_BSegment(&seg);
   seg.kind  = BSkAnonV;
   seg.start = start;
   seg.end   = end;
   seg.hasR  = hasR;
   seg.hasW  = hasW;
   seg.hasX  = hasX;
   add_bsegment(&seg);
}

static void add_bsegment_FileC ( Addr start, Addr end,
                                 Bool hasR, Bool hasW, Bool hasX,
                                 Bool hasT, Int fd, Off64T offs, Bool isExe )
{
   BSegment seg;
   init_BSegment(&seg);
   seg.kind  = BSkFileC;
   seg.start = start;
   seg.end   = end;
   seg.hasR  = hasR;
   seg.hasW  = hasW;
   seg.hasX  = hasX;
   seg.hasT  = hasT;
   seg.fd    = fd;
   seg.offs  = offs;
   seg.isExe = isExe;
   add_bsegment(&seg);
}

static void add_bsegment_FileV ( Addr start, Addr end,
                                 Bool hasR, Bool hasW, Bool hasX,
                                 Int fd, Off64T offs )
{
   BSegment seg;
   init_BSegment(&seg);
   seg.kind  = BSkFileV;
   seg.start = start;
   seg.end   = end;
   seg.hasR  = hasR;
   seg.hasW  = hasW;
   seg.hasX  = hasX;
   seg.fd    = fd;
   seg.offs  = offs;
   add_bsegment(&seg);
}


/*-----------------------------------------------------------------*/
/*---                                                           ---*/
/*--- Overview.                                                 ---*/
/*---                                                           ---*/
/*-----------------------------------------------------------------*/

/* BGQ special hack.  Get the bounds of the stack segment.  If there
   isn't exactly one, assert. */
void VG_(amo_get_stack_segment) ( /*OUT*/Addr* start, /*OUT*/Addr* end )
{
   Int i, nFound = 0;
   for (i = 0; i < bsegs_used; i++) {
      BSegment* bseg = &bsegs[i];
      if (bseg->kind != BSkAnonC) {
         aspacem_assert(!bseg->isCS);
         continue;
      }
      if (!bseg->isCS) continue;
      if (nFound == 0) {
         *start = bseg->start;
         *end = bseg->end;
      }
      nFound++;
   }
   aspacem_assert(nFound == 1);
}


/* Find the current data seg end.  Asserts if none found. */
#if 0
Addr VG_(am_find_dataseg_last) ( void )
{
   /* non-observational */
   ML_(am_barf)("am_find_dataseg_last");

   Int i;
   Addr b = 0;
   for (i = 0; i < bsegs_used; i++) {
      if (bsegs[i].kind == BSkData) {
         aspacem_assert(bsegs[i].end >= b);
         b = bsegs[i].end;
      }
   }
   aspacem_assert(b > 0);
   return b;
}
#endif

#if 0
void VG_(am_blrts_create_dataseg)( Addr start, Addr end )
{
   /* non-observational */
   ML_(am_barf)("FIXME");

   BSegment seg;
   init_BSegment( &seg );
   seg.kind  = BSkData;
   seg.start = start;
   seg.end   = end;
   add_bsegment( &seg );
}
#endif

#if 0
/* Allocate anonymous (zero-filled) pages from pool.  Size must be
   page aligned.  Do this by searching from resvn_end down to the
   current data seg end. */

static SysRes bgl_get_anon_pages( Bool forClient, SizeT nbytes )
{
   /* non-observational */
   ML_(am_barf)("FIXME");

   Word i, segS, segE;
   //Addr avail_start;
   Addr s = 0, e = 0;
   BSegment seg;
   Bool debug = 1||False;

   if (debug)
      VG_(debugLog)(0, "aspacem", "bgl_get_anon_pages(%ld)\n", nbytes);

   //aspacem_assert(AM_IS_4K_ALIGNED(resvn_end+1));

   //avail_start = AM_4K_ROUNDUP( VG_(am_find_dataseg_last)() + 1 );

   nbytes = AM_4K_ROUNDUP(nbytes);

   aspacem_assert(AM_IS_4K_ALIGNED(nbytes));

   //if (avail_start >= resvn_end
   //    || (resvn_end - avail_start + 1 < nbytes))
   //   goto eNoMem;

   segS = 0; //find_bsegment_idx( avail_start );
   segE = bsegs_used-1; //find_bsegment_idx( resvn_end );

   aspacem_assert(nbytes > 0);

   for (i = segE; i >= segS; i--) {
      aspacem_assert(i >= 0 && i < bsegs_used);
      if (bsegs[i].kind != BSkFree)
         continue;
      /* find the usable limits of current segment */
      s = bsegs[i].start;
      e = bsegs[i].end;
      aspacem_assert(s < e);
      //if (s < avail_start)
      //   s = avail_start;
      //if (e > resvn_end)
      //   e = resvn_end;
      //if (!(s < e))
      //   continue;
      s = AM_4K_ROUNDUP(s);
      e = AM_4K_ROUNDDN(e+1)-1;
      if (!(s < e))
         continue;
      if (e - s + 1 >= nbytes)
         break;
   }

   aspacem_assert(i >= segS-1 && i <= segE);
   if (i == segS - 1)
      goto eNoMem;

   if (debug)
      VG_(debugLog)(0,"aspacem", "bgl_get_anon_pages: using %p .. %p\n",
                    (void*)s, (void*)e);

   aspacem_assert(i >= 0 && i < bsegs_used);
   aspacem_assert(bsegs[i].kind == BSkFree);
   aspacem_assert(bsegs[i].start <= s);
   aspacem_assert(bsegs[i].end >= e);

   init_BSegment( &seg );
   seg.kind  = forClient ? BSkAnonC : BSkAnonV;
   seg.start = e - nbytes + 1;
   seg.end   = e;
   aspacem_assert(AM_IS_4K_ALIGNED(seg.start));
   aspacem_assert(AM_IS_4K_ALIGNED(seg.end + 1));
   
   add_bsegment( &seg );
   { 
     UChar* up = (UChar*)seg.start;
     SizeT  ii;
     for (ii = 0; ii < nbytes; ii++)
        up[ii] = 0;
   }
   return VG_(mk_SysRes_Success)( (UWord)seg.start );

 eNoMem:
   return VG_(mk_SysRes_Error)( VKI_ENOMEM );
}
#endif

/*-----------------------------------------------------------------*/
/*---                                                           ---*/
/*--- Functions for finding information about file descriptors. ---*/
/*---                                                           ---*/
/*-----------------------------------------------------------------*/

/*-----------------------------------------------------------------*/
/*---                                                           ---*/
/*--- SegName array management.                                 ---*/
/*---                                                           ---*/
/*-----------------------------------------------------------------*/

/*-----------------------------------------------------------------*/
/*---                                                           ---*/
/*--- Displaying the segment array.                             ---*/
/*---                                                           ---*/
/*-----------------------------------------------------------------*/

/* Print out the segment array (debugging only!). */
void VG_(am_show_nsegments) ( Int logLevel, HChar* who )
{
   show_BSegments( logLevel, who );
}


/* Get the filename corresponding to this segment, if known and if it
   has one.  The returned name's storage cannot be assumed to be
   persistent, so the caller should immediately copy the name
   elsewhere. */
HChar* VG_(am_get_filename)( NSegment const * seg )
{
   // Kludge.  The only file that we can come up with a name for is
   // the executable itself.  We have to find the BSegment associated
   // with this NSegment, so we can ask if it is the exe.
   Int i = find_bsegment_idx( seg->start );
   aspacem_assert(i >= 0 && i < bsegs_used);
   aspacem_assert(i < VG_N_BSEGMENTS);
   if (bsegs[i].kind == BSkFileC && bsegs[i].isExe) {
      aspacem_assert(name_of_exe);
      aspacem_assert(name_of_exe[0] == '/');
      return name_of_exe;
   }
   return NULL;
}

/* Collect up the start addresses of all non-free, non-resvn segments.
   The interface is a bit strange in order to avoid potential
   segment-creation races caused by dynamic allocation of the result
   buffer *starts.

   The function first computes how many entries in the result
   buffer *starts will be needed.  If this number <= nStarts,
   they are placed in starts[0..], and the number is returned.
   If nStarts is not large enough, nothing is written to
   starts[0..], and the negation of the size is returned.

   Correct use of this function may mean calling it multiple times in
   order to establish a suitably-sized buffer. */

Int VG_(am_get_segment_starts)( Addr* starts, Int nStarts )
{
   Int needed = 0, i = 0, j = 0;

   for (i = 0; i < bsegs_used; i++) {
      if (bsegs[i].kind == BSkAnonC
          || bsegs[i].kind == BSkAnonV
          || bsegs[i].kind == BSkFileC
          || bsegs[i].kind == BSkFileV)
         needed++;
   }

   if (nStarts < needed)
      return -needed;

   for (i = 0; i < bsegs_used; i++) {
      if (bsegs[i].kind == BSkAnonC
          || bsegs[i].kind == BSkAnonV
          || bsegs[i].kind == BSkFileC
          || bsegs[i].kind == BSkFileV)
         starts[j++] = bsegs[i].start;
   }

   aspacem_assert(j == needed);
   return needed;
}


/*-----------------------------------------------------------------*/
/*---                                                           ---*/
/*--- Sanity checking and preening of the segment array.        ---*/
/*---                                                           ---*/
/*-----------------------------------------------------------------*/

Bool VG_(am_do_sync_check) ( const HChar* fn, 
                             const HChar* file, Int line )
{
   ML_(am_barf)("am_do_sync_check");
   return True;
}

/* Hook to allow sanity checks to be done from aspacemgr-common.c. */
void ML_(am_do_sanity_check)( void )
{
   Bool ok = sane_BSegments();
   aspacem_assert(ok);
}


/*-----------------------------------------------------------------*/
/*---                                                           ---*/
/*--- Low level access / modification of the segment array.     ---*/
/*---                                                           ---*/
/*-----------------------------------------------------------------*/

/* Finds the segment containing 'a'.  Only returns file/anon/resvn
   segments.  This returns a 'NSegment const *' - a pointer to 
   readonly data. */
NSegment const * VG_(am_find_nsegment) ( Addr a )
{
   /* Converts the bseg containing 'a' into an NSeg and returns that.
      In order that the interface has the behaviour that different
      bsegs produce different nsegs, we have a complete shadow array
      of nsegs (sigh) and the relevant entry is filled in and
      returned. */

   Int i = find_bsegment_idx( a );
   aspacem_assert(i >= 0 && i < bsegs_used);
   aspacem_assert(i < VG_N_BSEGMENTS);

   if (bsegs[i].kind == BSkUnknown)
      return NULL;   

   /* DO NOT MAKE NON-STATIC */
   static NSegment bogus_nsegs[VG_N_BSEGMENTS];

   NSegment* bogus = &bogus_nsegs[i];

   /* Fill in default info. */
   local_memset(bogus, 0, sizeof(*bogus));
   bogus->kind   = SkAnonC;
   bogus->start  = 0;
   bogus->end    = 0;
   bogus->smode  = SmFixed;
   bogus->dev    = 0;
   bogus->ino    = 0;
   bogus->mode   = 0;
   bogus->offset = 0;
   bogus->fnIdx  = -1;
   bogus->hasR   = bogus->hasW = bogus->hasX = False;
   bogus->hasT   = False;
   bogus->isCH   = False;
   bogus->mark   = False;


   bogus->start = bsegs[i].start;
   bogus->end   = bsegs[i].end;
   Bool rr = bsegs[i].hasR;
   Bool ww = bsegs[i].hasW;
   Bool xx = bsegs[i].hasX;

   switch (bsegs[i].kind) {
      case BSkAnonC:
         bogus->kind = SkAnonC;
         bogus->hasR = rr; bogus->hasW = ww; bogus->hasX = xx;
         bogus->isCH = bsegs[i].isCH;
         bogus->hasT = bsegs[i].hasT;
         break;
      case BSkAnonV:
         bogus->kind = SkAnonV;
         bogus->hasR = rr; bogus->hasW = ww; bogus->hasX = xx;
         break;
      case BSkFileC:
         bogus->kind = SkFileC;
         bogus->hasR = rr; bogus->hasW = ww; bogus->hasX = xx;
         bogus->hasT = bsegs[i].hasT;
         bogus->offset = bsegs[i].offs;
         if (bsegs[i].isExe)
            bogus->fnIdx = 0;/* else di_notify_mmap ignores this segment */
         break;
      case BSkFileV:
         bogus->kind = SkFileV;
         bogus->hasR = rr; bogus->hasW = ww; bogus->hasX = xx;
         bogus->offset = bsegs[i].offs;
         break;
      default:
         aspacem_assert(0);
   }

   return bogus;
}


/* Find the next segment along from 'here', if it is a file/anon/resvn
   segment. */
NSegment const * VG_(am_next_nsegment) ( NSegment* here, Bool fwds )
{
   ML_(am_barf)("am_next_nsegment");
   return NULL;
}


/* Trivial fn: return the total amount of space in anonymous mappings,
   both for V and the client.  Is used for printing stats in
   out-of-memory messages. */
ULong VG_(am_get_anonsize_total)( void )
{
   Int   i;
   ULong total = 0;
   for (i = 0; i < bsegs_used; i++) {
      if (bsegs[i].kind == BSkAnonC || bsegs[i].kind == BSkAnonV) {
         total += (ULong)bsegs[i].end 
                  - (ULong)bsegs[i].start + 1ULL;
      }
   }
   return total;
}


/* Test if a piece of memory is addressable by the client with at
   least the "prot" protection permissions by examining the underlying
   segments. */
Bool VG_(am_is_valid_for_client)( Addr start, SizeT len, 
                                  UInt prot )
{
   if (0)
   VG_(debugLog)(0,"aspacem",
                   "BGL: kludged VG_(am_is_valid_for_client)\n");
   return True;
}

/* Variant of VG_(am_is_valid_for_client) which allows free areas to
   be consider part of the client's addressable space.  It also
   considers reservations to be allowable, since from the client's
   point of view they don't exist. */
Bool VG_(am_is_valid_for_client_or_free_or_resvn)
   ( Addr start, SizeT len, UInt prot )
{
   ML_(am_barf)("am_is_valid_for_client_or_free_or_resvn");
   return False;
#if 0
   Int  i, iLo, iHi;

   if (len == 0)
      return True; /* somewhat dubious case */
   if (start + len < start)
      return False; /* reject wraparounds */

   iLo = find_bsegment_idx(start);
   aspacem_assert(start >= bsegs[iLo].start);
   iHi = find_bsegment_idx(start + len - 1);
   aspacem_assert(bsegs[iHi].end < start+len );

   for (i = iLo; i <= iHi; i++) {
      if ( bsegs[i].kind == BSkText
           || bsegs[i].kind == BSkData
           || bsegs[i].kind == BSkAnonC
           || bsegs[i].kind == BSkFree) {
         /* ok */
      } else {
         return False;
      }
   }
   return True;
#endif
}

#if 0
/* Similar to VG_(am_find_nsegment) but only returns free segments. */
static NSegment const * VG_(am_find_free_nsegment) ( Addr a )
{
   Int i = find_nsegment_idx(a);
   aspacem_assert(i >= 0 && i < nsegments_used);
   aspacem_assert(nsegments[i].start <= a);
   aspacem_assert(a <= nsegments[i].end);
   if (nsegments[i].kind == SkFree) 
      return &nsegments[i];
   else
      return NULL;
}
#endif

Bool VG_(am_covered_by_single_free_segment)
   ( Addr start, SizeT len)
{
   ML_(am_barf)("am_covered_by_single_free_segment");
   return False;
#if 0
   NSegment const* segLo = VG_(am_find_free_nsegment)( start );
   NSegment const* segHi = VG_(am_find_free_nsegment)( start + len - 1 );

   return segLo != NULL && segHi != NULL && segLo == segHi;
#endif
}


SysRes VG_(am_shared_mmap_file_float_valgrind)
   ( SizeT length, UInt prot, Int fd, Off64T offset )
{
   aspacem_assert(0);
  // the following is wrong for shared (I edited the wrong fn)
   SysRes sres;
   sres = VG_(am_do_mmap_NO_NOTIFY)( 
             0, length, 
             prot, 
             VKI_MAP_PRIVATE,
             fd, offset
          );
   if (sr_isError(sres))
      return sres;
   Bool rr = toBool(prot & VKI_PROT_READ);
   Bool ww = toBool(prot & VKI_PROT_WRITE);
   Bool xx = toBool(prot & VKI_PROT_EXEC);
   add_bsegment_FileV( sr_Res(sres), sr_Res(sres) + VG_PGROUNDUP(length) - 1,
                       rr, ww, xx, fd, offset );
   return sres;
}


/*-----------------------------------------------------------------*/
/*---                                                           ---*/
/*--- Modifying the segment array, and constructing segments.   ---*/
/*---                                                           ---*/
/*-----------------------------------------------------------------*/

/*-----------------------------------------------------------------*/
/*---                                                           ---*/
/*--- Startup, including reading /proc/self/maps.               ---*/
/*---                                                           ---*/
/*-----------------------------------------------------------------*/

/* Initialise the address space manager, setting up the initial
   segment list, and reading /proc/self/maps into it.  This must
   be called before any other function.

   Takes a pointer to the SP at the time V gained control.  This is
   taken to be the highest usable address (more or less).  Based on
   that (and general consultation of tea leaves, etc) return a
   suggested end address for the client's stack. */

void VG_(am_bgq_set_name_of_executable)( HChar* name )
{
   aspacem_assert(name_of_exe == NULL);
   aspacem_assert(name);
   if (name[0] != '/') {
      VG_(debugLog)(0, "valgrind", 
         "** ERROR **: Cannot continue: executable name must be absolute.\n");
      VG_(debugLog)(0, "valgrind", 
         "** ERROR **: Give a fully qualified path name to mpirun.\n");
      ML_(am_exit)(1);
   }
   name_of_exe = name;
}

const HChar* VG_(am_bgq_get_name_of_executable)( void )
{
   return name_of_exe;
}

static void initFailed ( HChar* how )
{
   VG_(debugLog)(0, "valgrind", 
      "** ERROR **: Initial setup of node's memory failed:\n");
   VG_(debugLog)(0, "valgrind", 
      "** ERROR **: %s.\n", how);
   ML_(am_exit)(1);
}

Addr VG_(am_startup) ( Addr sp_at_startup )
{
   const Addr m1   = 1024 * 1024;
#if 0
   UWord      i;
   BSegment   seg;
   const Addr m256 = 256 * m1;
   Addr memTop, curBrk1;

   curBrk1 = 0; // FIXME: remove curBrk1 entirely

   aspacem_assert(sizeof(Word)   == sizeof(void*));
   aspacem_assert(sizeof(Addr)   == sizeof(void*));
   aspacem_assert(sizeof(SizeT)  == sizeof(void*));
   aspacem_assert(sizeof(SSizeT) == sizeof(void*));

   aspacem_assert(CONFIG_CLIENT_STACK_MBYTES >= 8);
   aspacem_assert(CONFIG_CLIENT_STACK_MBYTES <= 64);
#endif
   init_BSegments();
   if (0) show_BSegments(0, "startup-1");

   if (0) VG_(debugLog)(0,"xx","sp at startup = 0x%lx\n", sp_at_startup);

   /* Make up a stack segment.  This is pretty fictional, since
      unfortunately we don't know how big it can get. */
   Addr stackEnd = //VG_PGROUNDUP(sp_at_startup + 8) - 1;
                   VG_ROUNDUP(sp_at_startup + 8, 65536) - 1;
   Addr stackStart = VG_PGROUNDDN(stackEnd - m1 * CONFIG_CLIENT_STACK_MBYTES);
   add_bsegment_AnonC( stackStart, stackEnd,
                       True/*r*/, True/*w*/, False/*!x*/, False/*!isCH*/,
                       False/*!isT*/, True/*isCS*/ );

   if (0) show_BSegments(0, "startup-2");
#if 0
   /* Figure out how many 256-M pages of memory this node has.  We
      assume the initial SP is pretty close to the top of memory. */
   for (i = 0; i <= 500; i++) {
      Addr page_lo = m256 * i;
      Addr page_hi = page_lo + m256 - 1;
      if (page_lo <= sp_at_startup && sp_at_startup <= page_hi)
         break;
   }
   i++;
VG_(debugLog)(0,"xx","256M chunks: %lu\n", i);

   /* 'i' should now be the number of 256-M pages on the node.
       Currently the only known valid values are:
       460  (115.0 GB)    Q32, srun -N1
   */
   aspacem_assert(i == 460);
   memTop = m256 * i - 1;

   /* Paint the bottom 256*i mbytes as free.  We'll tidy up later. */
   init_BSegment( &seg );
   seg.kind  = BSkFree;
   seg.start = 0;
   seg.end   = memTop;
   add_bsegment( &seg );
#endif
   /* Establish the executable's text/data segments */
   aspacem_assert(name_of_exe && name_of_exe[0] == '/');
   read_elf_phdr( name_of_exe );
#if 0
   /* Mark the CNK area as off-limits.  Rather than assume it lives in
      the bottom 2 M of memory (as it seems to), just mark the entire
      first segment as off-limits. */
   //bsegs[0].kind = BSkUnAddr;
   init_BSegment( &seg );
   seg.kind  = BSkUnAddr;
   seg.start = 0;
   seg.end   = 16 * m1 - 1;
   add_bsegment( &seg );

   if (1) show_BSegments(0, "startup2");
#endif

#if 0
   /* Figure out how big the stack is, and stop if it is already
      bigger than CONFIG_CLIENT_STACK_MBYTES. */
   if (sp_at_startup >= memTop /* ?!?! */
       || ((SizeT)(memTop - sp_at_startup)) 
          >= m1 * (CONFIG_CLIENT_STACK_MBYTES - 1))
      initFailed("Initial stack exceeds CONFIG_CLIENT_STACK_MBYTES");

   /* Figure out where the current dseg end is, so we can
      check that there's enough room to reserve for the stack. */
   //curBrk1 = VG_(am_find_dataseg_last)() + 1;
   //if (curBrk1 >= memTop /* ?!?! */
   //    || ((SizeT)(memTop - curBrk1 + 1)) <= m1 * CONFIG_CLIENT_STACK_MBYTES)
   //   initFailed("Cannot reserve CONFIG_CLIENT_STACK_MBYTES for stack");

   /* Decide where the top of the reservation area is. */
   resvn_end 
      = AM_4K_ROUNDDN( memTop + 1 - m1 * CONFIG_CLIENT_STACK_MBYTES) - 1;
   VG_(debugLog)(1,"aspacem","startup: resvn_end = %08lx\n", resvn_end);

   aspacem_assert(resvn_end < sp_at_startup);
   aspacem_assert(resvn_end >= curBrk1);

   /* Put a 4k marker just above it so we can see where it is. */
   init_BSegment( &seg );
   seg.kind  = BSkUnAddr;
   seg.start = resvn_end + 1;
   seg.end   = seg.start + AM_4K_PAGESZ - 1;
   add_bsegment( &seg );
#endif

#if 0
   /* Mark the stack segment as SkAnonC. */
   i = find_bsegment_idx( sp_at_startup );
   aspacem_assert(i >= 0 && i < bsegs_used );
   aspacem_assert(bsegs[i].start <= sp_at_startup);
   aspacem_assert(bsegs[i].end == memTop);
   aspacem_assert(bsegs[i].kind == BSkFree);
   bsegs[i].kind    = BSkAnonC;
   bsegs[i].isCH    = False;
   bsegs[i].isStack = True;

   VG_(debugLog)(1, "aspacem", "startup: available %016lx-%016lx (%ld bytes)\n", 
                 curBrk1, resvn_end,
		 (UWord)(resvn_end - curBrk1 + 1));

   /* Do what we can to protect our own data structures. */
   init_BSegment( &seg );
   seg.kind = BSkUnAddr;

   seg.start = (Addr)&bsegs;
   seg.end   = (Addr)seg.start + sizeof(bsegs) - 1;
   add_bsegment( &seg );

   seg.start = (Addr)&bsegs_used;
   seg.end   = (Addr)seg.start + sizeof(bsegs_used) - 1;
   add_bsegment( &seg );

   seg.start = (Addr)&resvn_end;
   seg.end   = (Addr)seg.start + sizeof(resvn_end) - 1;
   add_bsegment( &seg );

#endif
   if (0) show_BSegments(0, "at end of VG_(am_startup)");

   /* Initial client SP is unchanged by all this. */
   return sp_at_startup;
}


/*-----------------------------------------------------------------*/
/*---                                                           ---*/
/*--- The core query-notify mechanism.                          ---*/
/*---                                                           ---*/
/*-----------------------------------------------------------------*/

/* Query aspacem to ask where a mapping should go. */

Addr VG_(am_get_advisory) ( MapRequest*  req, 
                            Bool         forClient, 
                            /*OUT*/Bool* ok )
{
   ML_(am_barf)("am_get_advisory");
   return 0;
}


/* Convenience wrapper for VG_(am_get_advisory) for client floating or
   fixed requests.  If start is zero, a floating request is issued; if
   nonzero, a fixed request at that address is issued.  Same comments
   about return values apply. */

Addr VG_(am_get_advisory_client_simple) ( Addr start, SizeT len, 
                                          /*OUT*/Bool* ok )
{
   ML_(am_barf)("am_get_advisory_client_simple");
   return 0;
}


/* Notifies aspacem that the client completed an mmap successfully.
   The segment array is updated accordingly.  If the returned Bool is
   True, the caller should immediately discard translations from the
   specified address range. */

Bool
VG_(am_notify_client_mmap)( Addr a, SizeT len, UInt prot, UInt flags,
                            Int fd, Off64T offset )
{
   Bool isAnon = toBool(flags & VKI_MAP_ANONYMOUS);
   if (0)
      VG_(debugLog)(0,"xx","am_notify_client_mmap 0x%lx %lu isAnon=%d\n",
                    a, len, (Int)isAnon);
   if (len == 0)
      return False;
   Bool hadT = any_Ts_in_range(a, len);
   Bool rr = toBool(prot & VKI_PROT_READ);
   Bool ww = toBool(prot & VKI_PROT_WRITE);
   Bool xx = toBool(prot & VKI_PROT_EXEC);
   if (isAnon) {
      add_bsegment_AnonC( a, a + len - 1, rr, ww, xx,
                          False/*!isCH*/, False/*!hasT*/, False/*!isCS*/ );
   } else {
      add_bsegment_FileC( a, a + len - 1, rr, ww, xx,
                          False/*!hasT*/, fd, offset, False/*!isExe*/ );
   }
   return hadT;
}


/* Notifies aspacem that the client completed a shmat successfully.
   The segment array is updated accordingly.  If the returned Bool is
   True, the caller should immediately discard translations from the
   specified address range. */

Bool
VG_(am_notify_client_shmat)( Addr a, SizeT len, UInt prot )
{
   ML_(am_barf)("am_notify_client_shmat");
   return True;
}


/* Notifies aspacem that an mprotect was completed successfully.  The
   segment array is updated accordingly.  Note, as with
   VG_(am_notify_munmap), it is not the job of this function to reject
   stupid mprotects, for example the client doing mprotect of
   non-client areas.  Such requests should be intercepted earlier, by
   the syscall wrapper for mprotect.  This function merely records
   whatever it is told.  If the returned Bool is True, the caller
   should immediately discard translations from the specified address
   range. */

Bool VG_(am_notify_mprotect)( Addr start, SizeT len, UInt prot )
{
   Int  i, iLo, iHi;
   Bool newR, newW, newX, needDiscard;

   if (len == 0)
      return False;

   newR = toBool(prot & VKI_PROT_READ);
   newW = toBool(prot & VKI_PROT_WRITE);
   newX = toBool(prot & VKI_PROT_EXEC);

   /* Discard is needed if we're dumping X permission */
   needDiscard = any_Ts_in_range( start, len ) && !newX;

   split_bsegments_lo_and_hi( start, start+len-1, &iLo, &iHi );

   iLo = find_bsegment_idx(start);
   iHi = find_bsegment_idx(start + len - 1);

   for (i = iLo; i <= iHi; i++) {
      /* Apply the permissions to all relevant segments. */
      switch (bsegs[i].kind) {
         case BSkAnonC: case BSkAnonV: case BSkFileC: case BSkFileV:
            bsegs[i].hasR = newR;
            bsegs[i].hasW = newW;
            bsegs[i].hasX = newX;
            aspacem_assert(sane_BSegment(&bsegs[i]));
            break;
         default:
            break;
      }
   }

   /* Changing permissions could have made previously un-mergable
      segments mergeable.  Therefore have to re-preen them. */
   preen_bsegments();
   ML_(am_do_sanity_check)();
   return needDiscard;
}


/* Notifies aspacem that an munmap completed successfully.  The
   segment array is updated accordingly.  As with
   VG_(am_notify_munmap), we merely record the given info, and don't
   check it for sensibleness.  If the returned Bool is True, the
   caller should immediately discard translations from the specified
   address range. */

Bool VG_(am_notify_munmap)( Addr start, SizeT len )
{
   if (0)
      VG_(debugLog)(0,"xx","am_notify_munmap 0x%lx %lu\n",
                    start, len );
   if (len == 0)
      return False;
   Bool hadT = any_Ts_in_range(start, len);
   add_bsegment_Unknown(start, start + len - 1);
   return hadT;
}


/*-----------------------------------------------------------------*/
/*---                                                           ---*/
/*--- Handling mappings which do not arise directly from the    ---*/
/*--- simulation of the client.                                 ---*/
/*---                                                           ---*/
/*-----------------------------------------------------------------*/

/* --- --- --- map, unmap, protect  --- --- --- */

/* Map a file at a fixed address for the client, and update the
   segment array accordingly. */

SysRes VG_(am_mmap_file_fixed_client)
     ( Addr start, SizeT length, UInt prot, Int fd, Off64T offset )
{
aspacem_assert(0);
#if 0
   ML_(am_barf)("am_mmap_file_fixed_client");
VG_(debugLog)(0,"xx","mmap_file_fixed_client %p %lu\n", (void*)start, length);
   SysRes sres;
   sres = VG_(am_do_mmap_NO_NOTIFY)( 
             start, length, prot, 
             VKI_MAP_FIXED|VKI_MAP_PRIVATE, 
             fd, offset 
          );
   if (sr_isError(sres))
      return sres;

   /* Ok, the mapping succeeded.  Now notify the interval map. */
   BSegment seg;
   init_BSegment( &seg );
   seg.kind   = SkFileC;
   seg.start  = start;
   seg.end    = seg.start + VG_PGROUNDUP(length) - 1;
   seg.isCH = False;
   seg.isStack = False;
   add_bsegment( &seg );

   return sres;
#endif
}


/* Map anonymously at a fixed address for the client, and update
   the segment array accordingly. */

SysRes VG_(am_mmap_anon_fixed_client) ( Addr start, SizeT length, UInt prot )
{
   ML_(am_barf)("am_mmap_anon_fixed_client");
   return VG_(mk_SysRes_Error)(0);
}


/* Map anonymously at an unconstrained address for the client, and
   update the segment array accordingly.  */

SysRes VG_(am_mmap_anon_float_client) ( SizeT length, Int prot )
{
   SysRes sres;
   sres = VG_(am_do_mmap_NO_NOTIFY)( 
             0, length, 
             prot,
             VKI_MAP_PRIVATE|VKI_MAP_ANONYMOUS, 
             -1, 0
          );
   if (sr_isError(sres))
      return sres;
   Bool rr = toBool(prot & VKI_PROT_READ);
   Bool ww = toBool(prot & VKI_PROT_WRITE);
   Bool xx = toBool(prot & VKI_PROT_EXEC);
   add_bsegment_AnonC( sr_Res(sres), sr_Res(sres) + length - 1,
                       rr, ww, xx,
                       False/*!isCH*/, False/*!hasT*/, False/*!isCS*/ );
   return sres;
}


/* Similarly, acquire new address space for the client but with
   considerable restrictions on what can be done with it: (1) the
   actual protections may exceed those stated in 'prot', (2) the
   area's protections cannot be later changed using any form of
   mprotect, and (3) the area cannot be freed using any form of
   munmap.  On Linux this behaves the same as
   VG_(am_mmap_anon_float_client).  On AIX5 this *may* allocate memory
   by using sbrk, so as to make use of large pages on AIX. */

SysRes VG_(am_sbrk_anon_float_client) ( SizeT length, Int prot )
{
   return VG_(am_mmap_anon_float_client) ( length, prot );
}


/* Map anonymously at an unconstrained address for V, and update the
   segment array accordingly.  This is fundamentally how V allocates
   itself more address space when needed. */

SysRes VG_(am_mmap_anon_float_valgrind)( SizeT length )
{
   SysRes sres;
   sres = VG_(am_do_mmap_NO_NOTIFY)( 
             0, length, 
             VKI_PROT_READ|VKI_PROT_WRITE|VKI_PROT_EXEC, 
             VKI_MAP_PRIVATE|VKI_MAP_ANONYMOUS, 
             -1, 0
          );
   if (sr_isError(sres))
      return sres;
   add_bsegment_AnonV( sr_Res(sres), sr_Res(sres) + length - 1,
                       True/*r*/, True/*w*/, True/*x*/ );
   return sres;
}

/* Really just a wrapper around VG_(am_mmap_anon_float_valgrind). */

void* VG_(am_shadow_alloc)(SizeT size)
{
   SysRes sres = VG_(am_mmap_anon_float_valgrind)( size );
   return sr_isError(sres) ? NULL : (void*)sr_Res(sres);
}

/* Same comments apply as per VG_(am_sbrk_anon_float_client).  On
   Linux this behaves the same as VG_(am_mmap_anon_float_valgrind). */

SysRes VG_(am_sbrk_anon_float_valgrind)( SizeT cszB )
{
   return VG_(am_mmap_anon_float_valgrind)( cszB );
}


/* Map a file at an unconstrained address for V, and update the
   segment array accordingly.  This is used by V for transiently
   mapping in object files to read their debug info.  */

SysRes VG_(am_mmap_file_float_valgrind) ( SizeT length, UInt prot, 
                                          Int fd, Off64T offset )
{
   SysRes sres;
   sres = VG_(am_do_mmap_NO_NOTIFY)( 
             0, length, 
             prot, 
             VKI_MAP_PRIVATE,
             fd, offset
          );
   if (sr_isError(sres))
      return sres;
   Bool rr = toBool(prot & VKI_PROT_READ);
   Bool ww = toBool(prot & VKI_PROT_WRITE);
   Bool xx = toBool(prot & VKI_PROT_EXEC);
   if (length > 0)
      add_bsegment_FileV( sr_Res(sres), sr_Res(sres) + length - 1,
                          rr, ww, xx, fd, offset );
   return sres;
}


/* Unmap the given address range and update the segment array
   accordingly.  This fails if the range isn't valid for the client.
   If *need_discard is True after a successful return, the caller
   should immediately discard translations from the specified address
   range. */

SysRes VG_(am_munmap_client)( /*OUT*/Bool* need_discard,
                              Addr start, SizeT len )
{
#if 0
aspacem_assert(0);
   Int i;
   Int iLo = find_bsegment_idx( start );
   Int iHi = find_bsegment_idx( start + len - 1);
   BSegment seg;

   if (0)
      VG_(debugLog)(0,"aspacem", "am_munmap_client( 0x%lx, %ld )\n", 
                      start,len);

   if (len == 0) {
      *need_discard = False;
      return VG_(mk_SysRes_Success)(0);
   }

   for (i = iLo; i <= iHi; i++) {
      aspacem_assert(i >= 0 && i < bsegs_used);
      if (bsegs[i].kind != BSkAnonC 
          && bsegs[i].kind != BSkData
          && bsegs[i].kind != BSkFree)
         return VG_(mk_SysRes_Error)( VKI_EINVAL );
   }

   init_BSegment( &seg );
   seg.start = start;
   seg.end   = start + len - 1;
   seg.kind  = BSkFree;
   add_bsegment( &seg );

   *need_discard = True;
   return VG_(mk_SysRes_Success)(0);
#else
   if (0)
      VG_(debugLog)(0,"aspacem", "am_munmap_client( 0x%lx, %ld )\n", 
                      start,len);

   if (len == 0)
      return VG_(mk_SysRes_Success)(0);

   Int i;
   Int iLo = find_bsegment_idx( start );
   Int iHi = find_bsegment_idx( start + len - 1);

   for (i = iLo; i <= iHi; i++) {
      aspacem_assert(i >= 0 && i < bsegs_used);
      BSegment* bseg = &bsegs[i];
      if (bseg->kind != BSkAnonC && bseg->kind != BSkFileC)
         return VG_(mk_SysRes_Error)( VKI_EINVAL );
   }

   SysRes sres = ML_(am_do_munmap_NO_NOTIFY)(start, len);
   if (sr_isError(sres))
      return sres;

   add_bsegment_Unknown(start, start + len - 1);

   *need_discard = True;
   return VG_(mk_SysRes_Success)(0);
#endif
}

/* Unmap the given address range and update the segment array
   accordingly.  This fails if the range isn't valid for valgrind. */

SysRes VG_(am_munmap_valgrind)( Addr start, SizeT len )
{
   if (0)
      VG_(debugLog)(0,"aspacem", "am_munmap_valgrind( 0x%lx, %ld )\n", 
                      start,len);

   if (len == 0)
      return VG_(mk_SysRes_Success)(0);

   Int i;
   Int iLo = find_bsegment_idx( start );
   Int iHi = find_bsegment_idx( start + len - 1);

   for (i = iLo; i <= iHi; i++) {
      aspacem_assert(i >= 0 && i < bsegs_used);
      BSegment* bseg = &bsegs[i];
      if (bseg->kind != BSkAnonV && bseg->kind != BSkFileV)
         return VG_(mk_SysRes_Error)( VKI_EINVAL );
   }

   SysRes sres = ML_(am_do_munmap_NO_NOTIFY)(start, len);
   if (sr_isError(sres))
      return sres;

   add_bsegment_Unknown(start, start + len - 1);
   return VG_(mk_SysRes_Success)(0);
}


/* Let (start,len) denote an area within a single Valgrind-owned
  segment (anon or file).  Change the ownership of [start, start+len)
  to the client instead.  Fails if (start,len) does not denote a
  suitable segment. */

Bool VG_(am_change_ownership_v_to_c)( Addr start, SizeT len )
{
   /* On BGQ this is completely nonsensical, since the combined
      tool+client executable is deemed to belong to the client
      (SkFileC); hence there is nothing to do.  We just sanity
      check the params and return. */
   Int i; //, iLo, iHi;

   if (len == 0)
      return True;
   if (start + len < start)
      return False;
   if (!VG_IS_PAGE_ALIGNED(start) || !VG_IS_PAGE_ALIGNED(len))
      return False;

   i = find_bsegment_idx(start);
   if (bsegs[i].kind != BSkFileC)  /* FileC: duh */
      return False;
   if (start+len-1 > bsegs[i].end)
      return False;

   aspacem_assert(start >= bsegs[i].start);
   aspacem_assert(start+len-1 <= bsegs[i].end);

   /* In fact changing BSkText to BSkAnonC is more dangerous than
      doing nothing, since it falsely gives the impression the new
      area is writable whereas it isn't.  Given that there is no
      distinction between V and C code in this system, we may as well
      do nothing.  Hence: */
   return True;
   /*NOTREACHED*/
}

/* 'seg' must be NULL or have been obtained from
   VG_(am_find_nsegment), and still valid.  If non-NULL, and if it
   denotes a SkAnonC (anonymous client mapping) area, set the .isCH
   (is-client-heap) flag for that area.  Otherwise do nothing.
   (Bizarre interface so that the same code works for both Linux and
   AIX and does not impose inefficiencies on the Linux version.) */
void VG_(am_set_segment_isCH_if_SkAnonC)( NSegment* seg )
{
   Int i;
   if (seg == NULL)
      return;
   i = find_bsegment_idx( seg->start );
   aspacem_assert(i >= 0 && i < bsegs_used );
   if (bsegs[i].kind == BSkAnonC) {
      bsegs[i].isCH = True;
      if (0)
         VG_(debugLog)(0,"aspacem","set isCH for %p\n", (void*)seg->start );
   } else {
      aspacem_assert(bsegs[i].isCH == False);
   }
}

/* Same idea as VG_(am_set_segment_isCH_if_SkAnonC), except set the
   segment's hasT bit (has-cached-code) if this is SkFileC or SkAnonC
   segment. */
void VG_(am_set_segment_hasT_if_SkFileC_or_SkAnonC)( NSegment* seg )
{
   Int i;
   if (seg == NULL)
      return;
   i = find_bsegment_idx( seg->start );
   aspacem_assert(i >= 0 && i < bsegs_used );
   if (bsegs[i].kind == BSkAnonC || bsegs[i].kind == BSkFileC) {
      bsegs[i].hasT = True;
      if (0)
         VG_(debugLog)(0,"aspacem","set hasT for %p\n", (void*)seg->start );
   } else {
      aspacem_assert(bsegs[i].hasT == False);
   }
}


/* --- --- --- reservations --- --- --- */

/* Create a reservation from START .. START+LENGTH-1, with the given
   ShrinkMode.  When checking whether the reservation can be created,
   also ensure that at least abs(EXTRA) extra free bytes will remain
   above (> 0) or below (< 0) the reservation.

   The reservation will only be created if it, plus the extra-zone,
   falls entirely within a single free segment.  The returned Bool
   indicates whether the creation succeeded. */

Bool VG_(am_create_reservation) ( Addr start, SizeT length, 
                                  ShrinkMode smode, SSizeT extra )
{
   ML_(am_barf)("am_create_reservation");
   return False;
}


/* Let SEG be an anonymous client mapping.  This fn extends the
   mapping by DELTA bytes, taking the space from a reservation section
   which must be adjacent.  If DELTA is positive, the segment is
   extended forwards in the address space, and the reservation must be
   the next one along.  If DELTA is negative, the segment is extended
   backwards in the address space and the reservation must be the
   previous one.  DELTA must be page aligned.  abs(DELTA) must not
   exceed the size of the reservation segment minus one page, that is,
   the reservation segment after the operation must be at least one
   page long. */

Bool VG_(am_extend_into_adjacent_reservation_client) ( NSegment* seg, 
                                                       SSizeT    delta )
{
   ML_(am_barf)("am_extend_into_adjacent_reservation_client");
   return False;
}


/* --- --- --- resizing/move a mapping --- --- --- */

/* Let SEG be a client mapping (anonymous or file).  This fn extends
   the mapping forwards only by DELTA bytes, and trashes whatever was
   in the new area.  Fails if SEG is not a single client mapping or if
   the new area is not accessible to the client.  Fails if DELTA is
   not page aligned.  *seg is invalid after a successful return.  If
   *need_discard is True after a successful return, the caller should
   immediately discard translations from the new area. */

Bool VG_(am_extend_map_client)( /*OUT*/Bool* need_discard,
                                NSegment* seg, SizeT delta )
{
   ML_(am_barf)("am_extend_map_client");
   return False;
}


/* Remap the old address range to the new address range.  Fails if any
   parameter is not page aligned, if the either size is zero, if any
   wraparound is implied, if the old address range does not fall
   entirely within a single segment, if the new address range overlaps
   with the old one, or if the old address range is not a valid client
   mapping.  If *need_discard is True after a successful return, the
   caller should immediately discard translations from both specified
   address ranges.  */

Bool VG_(am_relocate_nooverlap_client)( /*OUT*/Bool* need_discard,
                                        Addr old_addr, SizeT old_len,
                                        Addr new_addr, SizeT new_len )
{
   ML_(am_barf)("am_relocate_nooverlap_client");
   return False;
}


/*-----------------------------------------------------------------*/
/*---                                                           ---*/
/*--- A simple parser for /proc/self/maps on Linux 2.4.X/2.6.X. ---*/
/*--- Almost completely independent of the stuff above.  The    ---*/
/*--- only function it 'exports' to the code above this comment ---*/
/*--- is parse_procselfmaps.                                    ---*/
/*---                                                           ---*/
/*-----------------------------------------------------------------*/

/* --- !!! --- EXTERNAL HEADERS start --- !!! --- */
/* BGL hack: the standard BlueGene compiler (mpgcc) doesn't include
   ELF stuff.  So in this case explicitly use the host's ELF headers.
*/

/* Be paranoid.  We don't want to accidentally include headers on any
   target where we don't absolutely need them. */
#if defined(VGPV_ppc64_linux_bgq)
# include "/usr/include/elf.h"
#else
# error "Incorrect or missing #ifdef(VGPV_..) at top or file? " \
        " This is a serious error."
#endif

/* --- !!! --- EXTERNAL HEADERS end --- !!! --- */

/* For all the ELF macros and types which specify '32' or '64',
   select the correct variant for this platform and give it
   an 'XX' name.  Then use the 'XX' variant consistently in
   the rest of this file. 
*/
#if VG_WORDSIZE == 8
#  define  ElfXX_Ehdr     Elf64_Ehdr
#  define  ElfXX_Shdr     Elf64_Shdr
#  define  ElfXX_Phdr     Elf64_Phdr
#  define  ElfXX_Sym      Elf64_Sym
#  define  ElfXX_Word     Elf64_Word
#  define  ElfXX_Addr     Elf64_Addr
#  define  ElfXX_Dyn      Elf64_Dyn
#  define  ELFXX_ST_BIND  ELF64_ST_BIND
#  define  ELFXX_ST_TYPE  ELF64_ST_TYPE

#else
# error "VG_WORDSIZE should be 8 on this platform (VGPV_ppc64_linux_bgq)"
#endif


#define N_MINIBUF 4096
static UChar minibuf[N_MINIBUF];
static UInt  n_minibuf = 0;

/* Identify an ELF object file by peering at the first few bytes of
   it. */
static Bool is_elf_object_file( const void* buf )
{
   ElfXX_Ehdr* ehdr = (ElfXX_Ehdr*)buf;
   Int ok = 1;

   ok &= (ehdr->e_ident[EI_MAG0] == 0x7F
          && ehdr->e_ident[EI_MAG1] == 'E'
          && ehdr->e_ident[EI_MAG2] == 'L'
          && ehdr->e_ident[EI_MAG3] == 'F');
   ok &= (ehdr->e_ident[EI_CLASS] == ELFCLASS64
          && ehdr->e_ident[EI_DATA] == ELFDATA2MSB
          && ehdr->e_ident[EI_VERSION] == EV_CURRENT);
   ok &= (ehdr->e_type == ET_EXEC);
   ok &= (ehdr->e_machine == EM_PPC64);
   ok &= (ehdr->e_version == EV_CURRENT);
   ok &= (ehdr->e_shstrndx != SHN_UNDEF);
   ok &= (ehdr->e_shoff != 0 && ehdr->e_shnum != 0);
   ok &= (ehdr->e_phoff != 0 && ehdr->e_phnum != 0);

   if (ok)
      return True;
   else
      return False;
}

/* Read ELF program header info from the executable, and
   barf if not possible. */
static void read_elf_phdr ( HChar* fname )
{
   Int      i, rr;
   SysRes   fd;
   Bool     bad;
   BSegment seg;

   aspacem_assert(name_of_exe);
   aspacem_assert(name_of_exe[0] == '/');

   aspacem_assert(sizeof(ElfXX_Ehdr) <= N_MINIBUF);
   for (i = 0; i < N_MINIBUF; i++)
      minibuf[i] = 0;

   fd = ML_(am_open)( name_of_exe, VKI_O_RDONLY, 0 );
   if (sr_isError(fd))
      ML_(am_barf)("Can't open the executable to read ELF PHDR");

   rr = ML_(am_read)( sr_Res(fd), &minibuf, N_MINIBUF );

   ML_(am_close)( sr_Res(fd) );

   if (rr < 1)
      ML_(am_barf)("I/O error whilst reading executable's ELF PHDR");

   n_minibuf = rr;
   aspacem_assert(n_minibuf > 0 && n_minibuf <= N_MINIBUF);

   if (!is_elf_object_file( &minibuf[0] ))
      ML_(am_barf)("Executable isn't a suitable ELF object file (?!)");

   VG_(debugLog)(1,"aspacem","read_elf_phdr: looks like a valid ELF file\n");

   ElfXX_Ehdr* ehdr = (ElfXX_Ehdr*)(&minibuf[0]);
   Int ph_off_min = (Int)ehdr->e_phoff;
   Int ph_esize   = (Int)ehdr->e_phentsize;
   Int ph_num     = (Int)ehdr->e_phnum;
   Int ph_off_max = ph_off_min + ph_esize * ph_num - 1;

   bad = (ph_off_min < 0 || ph_off_min >= n_minibuf
          || ph_off_max < 0 || ph_off_max >= n_minibuf
          || ph_off_max < ph_off_min
          || ph_num == 0);

   if (bad || 1)
      VG_(debugLog)(1,"aspacem",
                    "read_elf_phdr: phoff %d, #ent %d, size-ent %d\n", 
                    ph_off_min, ph_num, ph_esize);

   if (bad)
      ML_(am_barf)("Executable's program hdrs don't fit in MINIBUF.");

   ElfXX_Phdr* phdr;
   for (i = 0; i < ph_num; i++) {
      phdr = (ElfXX_Phdr*)( &minibuf[ ph_off_min + i * ph_esize ]);
      aspacem_assert( ((UChar*)phdr) >= &minibuf[0] );
      aspacem_assert( ((UChar*)phdr) + sizeof(ElfXX_Phdr) 
                      < &minibuf[n_minibuf] );
      VG_(debugLog)(1,"aspacem","[%d] va %08x, pa %08x, fs %08x, ms %08x\n",
		    i,
		    (UInt)phdr->p_vaddr, (UInt)phdr->p_paddr,
		    (UInt)phdr->p_filesz, (UInt)phdr->p_memsz);
      Bool rrr = toBool(phdr->p_flags & PF_R);
      Bool www = toBool(phdr->p_flags & PF_W);
      Bool xxx = toBool(phdr->p_flags & PF_X);
      VG_(debugLog)(1,"aspacem","    ty %s  flags %c%c%c\n",
		    phdr->p_type == PT_LOAD ? "LOAD " : "other",
                    rrr ? 'r' : '-', www ? 'w' : '-', xxx ? 'x' : '-'
                   );
      Bool acquire
         = phdr->p_type == PT_LOAD
	   && ( (rrr && !www && xxx) || (rrr && www && !xxx) );
      if (acquire) {           
         add_bsegment_FileC(
            (Addr)phdr->p_vaddr,
            (Addr)phdr->p_vaddr + (Addr)phdr->p_memsz - 1,
            rrr, www, xxx, False/*!hasT*/,
            0/*fd*/, (Off64T)phdr->p_offset,
            True/*isExe*/
         );
      }
   }

}

#endif // defined(VGPV_ppc64_linux_bgq)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
