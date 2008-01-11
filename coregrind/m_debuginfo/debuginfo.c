
/*--------------------------------------------------------------------*/
/*--- Top level management of symbols and debugging information.   ---*/
/*---                                                  debuginfo.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2000-2007 Julian Seward 
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
/*
   Stabs reader greatly improved by Nick Nethercote, Apr 02.
   This module was also extensively hacked on by Jeremy Fitzhardinge
   and Tom Hughes.
*/

#include "pub_core_basics.h"
#include "pub_core_vki.h"
#include "pub_core_threadstate.h"
#include "pub_core_debuginfo.h"   /* self */
#include "pub_core_demangle.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcprint.h"
#include "pub_core_libcfile.h"
#include "pub_core_mallocfree.h"
#include "pub_core_options.h"
#include "pub_core_redir.h"       // VG_(redir_notify_{new,delete}_SegInfo)
#include "pub_core_aspacemgr.h"
#include "pub_core_machine.h"     // VG_PLAT_USES_PPCTOC
#include "pub_core_xarray.h"
#include "priv_storage.h"
#include "priv_readdwarf.h"
#include "priv_readstabs.h"
#if defined(VGO_linux)
# include "priv_readelf.h"
#elif defined(VGO_aix5)
# include "pub_core_debuglog.h"
# include "pub_core_libcproc.h"
# include "pub_core_libcfile.h"
# include "priv_readxcoff.h"
#endif


/*------------------------------------------------------------*/
/*--- The _svma / _avma / _image / _bias naming scheme     ---*/
/*------------------------------------------------------------*/

/* JRS 11 Jan 07: I find the different kinds of addresses involved in
   debuginfo reading confusing.  Recently I arrived at some
   terminology which makes it clearer (to me, at least).  There are 3
   kinds of address used in the debuginfo reading process:
 
   stated VMAs - the address where (eg) a .so says a symbol is, that
                 is, what it tells you if you consider the .so in
                 isolation
 
   actual VMAs - the address where (eg) said symbol really wound up
                 after the .so was mapped into memory
 
   image addresses - pointers into the copy of the .so (etc)
                     transiently mmaped aboard whilst we read its info

   Additionally I use the term 'bias' to denote the difference
   between stated and actual VMAs for a given entity.

   This terminology is not used consistently, but a start has been
   made.  readelf.c and the call-frame info reader in readdwarf.c now
   use it.  Specifically, various variables and structure fields have
   been annotated with _avma / _svma / _image / _bias.  In places _img
   is used instead of _image for the sake of brevity.
*/


/*------------------------------------------------------------*/
/*--- Root structure                                       ---*/
/*------------------------------------------------------------*/

/* The root structure for the entire debug info system.  It is a
   linked list of DebugInfos. */
static DebugInfo* debugInfo_list = NULL;


/*------------------------------------------------------------*/
/*--- Notification (acquire/discard) helpers               ---*/
/*------------------------------------------------------------*/

/* Allocate and zero out a new DebugInfo record. */
static 
DebugInfo* alloc_DebugInfo( const UChar* filename,
                            const UChar* memname )
{
   Bool       traceme;
   DebugInfo* di;

   vg_assert(filename);

   di = VG_(arena_calloc)(VG_AR_DINFO, 1, sizeof(DebugInfo));
   di->filename  = VG_(arena_strdup)(VG_AR_DINFO, filename);
   di->memname   = memname 
                      ?  VG_(arena_strdup)(VG_AR_DINFO, memname)
                      :  NULL;

   /* Everything else -- pointers, sizes, arrays -- is zeroed by calloc.
      Now set up the debugging-output flags. */
   traceme 
      = VG_(string_match)( VG_(clo_trace_symtab_patt), filename )
        || (memname && VG_(string_match)( VG_(clo_trace_symtab_patt), 
                                          memname ));
   if (traceme) {
      di->trace_symtab = VG_(clo_trace_symtab);
      di->trace_cfi    = VG_(clo_trace_cfi);
      di->ddump_syms   = VG_(clo_debug_dump_syms);
      di->ddump_line   = VG_(clo_debug_dump_line);
      di->ddump_frames = VG_(clo_debug_dump_frames);
   }

   return di;
}


/* Free a DebugInfo, and also all the stuff hanging off it. */
static void free_DebugInfo ( DebugInfo* di )
{
   struct strchunk *chunk, *next;
   vg_assert(di != NULL);
   if (di->filename)   VG_(arena_free)(VG_AR_DINFO, di->filename);
   if (di->symtab)     VG_(arena_free)(VG_AR_DINFO, di->symtab);
   if (di->loctab)     VG_(arena_free)(VG_AR_DINFO, di->loctab);
   if (di->cfsi)       VG_(arena_free)(VG_AR_DINFO, di->cfsi);
   if (di->cfsi_exprs) VG_(deleteXA)(di->cfsi_exprs);

   for (chunk = di->strchunks; chunk != NULL; chunk = next) {
      next = chunk->next;
      VG_(arena_free)(VG_AR_DINFO, chunk);
   }
   VG_(arena_free)(VG_AR_DINFO, di);
}


/* 'si' is a member of debugInfo_list.  Find it, remove it from the
   list, notify m_redir that this has happened, and free all storage
   reachable from it.
*/
static void discard_DebugInfo ( DebugInfo* di )
{
#  if defined(VGP_ppc32_aix5)
   HChar* reason = "__unload";
#  elif defined(VGP_ppc64_aix5)
   HChar* reason = "kunload64";
#  else
   HChar* reason = "munmap";
#  endif

   DebugInfo** prev_next_ptr = &debugInfo_list;
   DebugInfo*  curr          =  debugInfo_list;

   while (curr) {
      if (curr == di) {
         // Found it;  remove from list and free it.
         if (VG_(clo_verbosity) > 1 || VG_(clo_trace_redir))
            VG_(message)(Vg_DebugMsg, 
                         "Discarding syms at %p-%p in %s due to %s()", 
                         di->text_avma, 
                         di->text_avma + di->text_size,
                         curr->filename ? curr->filename : (UChar*)"???",
                         reason);
         vg_assert(*prev_next_ptr == curr);
         *prev_next_ptr = curr->next;
         VG_(redir_notify_delete_DebugInfo)( curr );
         free_DebugInfo(curr);
         return;
      }
      prev_next_ptr = &curr->next;
      curr          =  curr->next;
   }

   // Not found.
}


/* Repeatedly scan debugInfo_list, looking for DebugInfos intersecting
   [start,start+length), and call discard_DebugInfo to get rid of
   them.  This modifies the list, hence the multiple iterations.
*/
static void discard_syms_in_range ( Addr start, SizeT length )
{
   Bool       found;
   DebugInfo* curr;

   while (True) {
      found = False;

      curr = debugInfo_list;
      while (True) {
         if (curr == NULL)
            break;
         if (curr->text_size > 0
             && (start+length - 1 < curr->text_avma 
                 || curr->text_avma + curr->text_size - 1 < start)) {
            /* no overlap */
	 } else {
	    found = True;
	    break;
	 }
	 curr = curr->next;
      }

      if (!found) break;
      discard_DebugInfo( curr );
   }
}

#if 0
/* Create a new SegInfo with the specific address/length/vma offset,
   then snarf whatever info we can from the given filename into it. */
static
SegInfo* acquire_syms_for_range( 
            /* ALL        */ Addr  seg_addr, 
            /* ALL        */ SizeT seg_len,
            /* ELF only   */ OffT  seg_offset, 
            /* ALL        */ const UChar* seg_filename,
            /* XCOFF only */ const UChar* seg_memname,
	    /* XCOFF only */ Addr  data_addr,
	    /* XCOFF only */ SizeT data_len,
	    /* XCOFF only */ Bool  is_mainexe
         )
{
   Bool     ok;
   SegInfo* si = alloc_SegInfo(seg_addr, seg_len, seg_offset, 
                               seg_filename, seg_memname);
#  if defined(VGO_linux)
   ok = ML_(read_elf_debug_info) ( si );
#  elif defined(VGO_aix5)
   ok = ML_(read_xcoff_debug_info) ( si, data_addr, data_len, is_mainexe );
#  else
#    error Unknown OS
#  endif

   if (!ok) {
      // Something went wrong (eg. bad ELF file).
      free_SegInfo( si );
      si = NULL;

   } else {
      // Prepend si to segInfo_list
      si->next = segInfo_list;
      segInfo_list = si;

      ML_(canonicaliseTables) ( si );

      /* notify m_redir about it */
      VG_(redir_notify_new_SegInfo)( si );
   }

   return si;
}
#endif

static Bool ranges_overlap (Addr s1, SizeT len1, Addr s2, SizeT len2 )
{
   Addr e1, e2;
   if (len1 == 0 || len2 == 0) 
      return False;
   e1 = s1 + len1 - 1;
   e2 = s2 + len2 - 1;
   /* Assert that we don't have wraparound.  If we do it would imply
      that file sections are getting mapped around the end of the
      address space, which sounds unlikely. */
   vg_assert(s1 <= e1);
   vg_assert(s2 <= e2);
   if (e1 < s2 || e2 < s1) return False;
   return True;
}

static Bool do_DebugInfos_overlap ( DebugInfo* di1, DebugInfo* di2 )
{
   vg_assert(di1);
   vg_assert(di2);

   if (di1->have_rx_map && di2->have_rx_map
       && ranges_overlap(di1->rx_map_avma, di1->rx_map_size,
                         di2->rx_map_avma, di2->rx_map_size))
      return True;

   if (di1->have_rx_map && di2->have_rw_map
       && ranges_overlap(di1->rx_map_avma, di1->rx_map_size,
                         di2->rw_map_avma, di2->rw_map_size))
      return True;

   if (di1->have_rw_map && di2->have_rx_map
       && ranges_overlap(di1->rw_map_avma, di1->rw_map_size,
                         di2->rx_map_avma, di2->rx_map_size))
      return True;

   if (di1->have_rw_map && di2->have_rw_map
       && ranges_overlap(di1->rw_map_avma, di1->rw_map_size,
                         di2->rw_map_avma, di2->rw_map_size))
      return True;

   return False;
}

static void discard_marked_DebugInfos ( void )
{
   DebugInfo* curr;

   while (True) {

      curr = debugInfo_list;
      while (True) {
         if (!curr)
            break;
         if (curr->mark)
            break;
	 curr = curr->next;
      }

      if (!curr) break;
      discard_DebugInfo( curr );

   }
}

static void discard_DebugInfos_which_overlap_with ( DebugInfo* diRef )
{
   DebugInfo* di;
   /* Mark all the DebugInfos in debugInfo_list that need to be
      deleted.  First, clear all the mark bits; then set them if they
      overlap with siRef.  Since siRef itself is in this list we at
      least expect its own mark bit to be set. */
   for (di = debugInfo_list; di; di = di->next) {
      di->mark = do_DebugInfos_overlap( di, diRef );
      if (di == diRef) {
         vg_assert(di->mark);
         di->mark = False;
      }
   }
   discard_marked_DebugInfos();
}

/* Find the existing DebugInfo for (memname,filename) or if not found,
   create one.  In the latter case memname and filename are strdup'd
   into VG_AR_DINFO, and the new DebugInfo is added to
   debugInfo_list. */
static
DebugInfo* find_or_create_DebugInfo_for ( UChar* filename, UChar* memname )
{
   DebugInfo* di;
   vg_assert(filename);
   for (di = debugInfo_list; di; di = di->next) {
      vg_assert(di->filename);
      if (0==VG_(strcmp)(di->filename, filename)
          && ( (memname && di->memname) 
                  ? 0==VG_(strcmp)(memname, di->memname)
                  : True ))
         break;
   }
   if (!di) {
      di = alloc_DebugInfo(filename, memname);
      vg_assert(di);
      di->next = debugInfo_list;
      debugInfo_list = di;
   }
   return di;
}


/*--------------------------------------------------------------*/
/*---                                                        ---*/
/*--- TOP LEVEL: NOTIFICATION (ACQUIRE/DISCARD INFO) (LINUX) ---*/
/*---                                                        ---*/
/*--------------------------------------------------------------*/

#if defined(VGO_linux)

/* The debug info system is driven by notifications that a text
   segment has been mapped in, or unmapped.  When that happens it
   tries to acquire/discard whatever info is available for the
   corresponding object.  This section contains the notification
   handlers. */

/* Notify the debuginfo system about a new mapping.  This is the way
   new debug information gets loaded.  If allow_SkFileV is True, it
   will try load debug info if the mapping at 'a' belongs to Valgrind;
   whereas normally (False) it will not do that.  This allows us to
   carefully control when the thing will read symbols from the
   Valgrind executable itself. */

void VG_(di_notify_mmap)( Addr a, Bool allow_SkFileV )
{
   NSegment const * seg;
   HChar*     filename;
   Bool       ok, is_rx_map, is_rw_map;
   DebugInfo* di;
   SysRes     fd;
   Int        nread;
   HChar      buf1k[1024];
   Bool       debug = False;

   /* In short, figure out if this mapping is of interest to us, and
      if so, try to guess what ld.so is doing and when/if we should
      read debug info. */
   seg = VG_(am_find_nsegment)(a);
   vg_assert(seg);

   if (debug)
      VG_(printf)("di_notify_mmap-1: %p-%p %c%c%c\n",
                  seg->start, seg->end, 
                  seg->hasR ? 'r' : '-',
                  seg->hasW ? 'w' : '-',seg->hasX ? 'x' : '-' );

   /* guaranteed by aspacemgr-linux.c, sane_NSegment() */
   vg_assert(seg->end > seg->start);

   /* Ignore non-file mappings */
   if ( ! (seg->kind == SkFileC
           || (seg->kind == SkFileV && allow_SkFileV)) )
      return;

   /* If the file doesn't have a name, we're hosed.  Give up. */
   filename = VG_(am_get_filename)( (NSegment*)seg );
   if (!filename)
      return;

   if (debug)
      VG_(printf)("di_notify_mmap-2: %s\n", filename);

   /* Peer at the first few bytes of the file, to see if it is an ELF
      object file. */
   VG_(memset)(buf1k, 0, sizeof(buf1k));
   fd = VG_(open)( filename, VKI_O_RDONLY, 0 );
   if (fd.isError) {
      ML_(symerr)(NULL, True, "can't open file to inspect ELF header");
      return;
   }
   nread = VG_(read)( fd.res, buf1k, sizeof(buf1k) );
   VG_(close)( fd.res );

   if (nread <= 0) {
      ML_(symerr)(NULL, True, "can't read file to inspect ELF header");
      return;
   }
   vg_assert(nread > 0 && nread <= sizeof(buf1k) );

   /* We're only interested in mappings of ELF object files. */
   if (!ML_(is_elf_object_file)( buf1k, (SizeT)nread ))
      return;

   /* Now we have to guess if this is a text-like mapping, a data-like
      mapping, neither or both.  The rules are:

        text if:   x86-linux    r and x
                   other-linux  r and x and not w

        data if:   x86-linux    r and w
                   other-linux  r and w and not x

      Background: On x86-linux, objects are typically mapped twice:

      1b8fb000-1b8ff000 r-xp 00000000 08:02 4471477 vgpreload_memcheck.so
      1b8ff000-1b900000 rw-p 00004000 08:02 4471477 vgpreload_memcheck.so

      whereas ppc32-linux mysteriously does this:

      118a6000-118ad000 r-xp 00000000 08:05 14209428 vgpreload_memcheck.so
      118ad000-118b6000 ---p 00007000 08:05 14209428 vgpreload_memcheck.so
      118b6000-118bd000 rwxp 00000000 08:05 14209428 vgpreload_memcheck.so

      The third mapping should not be considered to have executable
      code in.  Therefore a test which works for both is: r and x and
      NOT w.  Reading symbols from the rwx segment -- which overlaps
      the r-x segment in the file -- causes the redirection mechanism
      to redirect to addresses in that third segment, which is wrong
      and causes crashes.

      JRS 28 Dec 05: unfortunately icc 8.1 on x86 has been seen to
      produce executables with a single rwx segment rather than a
      (r-x,rw-) pair. That means the rules have to be modified thusly:

      x86-linux:   consider if r and x
      all others:  consider if r and x and not w
   */
   is_rx_map = False;
   is_rw_map = False;
#  if defined(VGP_x86_linux)
   is_rx_map = seg->hasR && seg->hasX;
   is_rw_map = seg->hasR && seg->hasW;
#  elif defined(VGP_amd64_linux) \
        || defined(VGP_ppc32_linux) || defined(VGP_ppc64_linux)
   is_rx_map = seg->hasR && seg->hasX && !seg->hasW;
   is_rw_map = seg->hasR && seg->hasW && !seg->hasX;
#  else
#    error "Unknown platform"
#  endif

   if (debug)
      VG_(printf)("di_notify_mmap-3: is_rx_map %d, is_rw_map %d\n",
                  (Int)is_rx_map, (Int)is_rw_map);

   /* If it is neither text-ish nor data-ish, we're not interested. */
   if (!(is_rx_map || is_rw_map))
      return;

   /* See if we have a DebugInfo for this filename.  If not,
      create one. */
   di = find_or_create_DebugInfo_for( filename, NULL/*membername*/ );
   vg_assert(di);

   if (is_rx_map) {
      /* We have a text-like mapping.  Note the details. */
      if (!di->have_rx_map) {
         di->have_rx_map = True;
         di->rx_map_avma = a;
         di->rx_map_size = seg->end + 1 - seg->start;
         di->rx_map_foff = seg->offset;
      } else {
         /* FIXME: complain about a second text-like mapping */
      }
   }

   if (is_rw_map) {
      /* We have a data-like mapping.  Note the details. */
      if (!di->have_rw_map) {
         di->have_rw_map = True;
         di->rw_map_avma = a;
         di->rw_map_size = seg->end + 1 - seg->start;
         di->rw_map_foff = seg->offset;
      } else {
         /* FIXME: complain about a second data-like mapping */
      }
   }

   if (di->have_rx_map && di->have_rw_map && !di->have_dinfo) {
      /* We're going to read symbols and debug info for the vma ranges
         [rx_map_avma,+rx_map_size) and [rw_map_avma,+rw_map_size).
         First get rid of any other DebugInfos which overlap either of
         those ranges (to avoid total confusion). */
      discard_DebugInfos_which_overlap_with( di );

      /* .. and acquire new info. */
      ok = ML_(read_elf_debug_info)( di );

      if (ok) {
         /* prepare read data for use */
         ML_(canonicaliseTables)( di );
         /* notify m_redir about it */
         VG_(redir_notify_new_DebugInfo)( di );
         /* Note that we succeeded */
         di->have_dinfo = True;
      } else {
         /* Something went wrong (eg. bad ELF file).  Should we delete
            this DebugInfo?  No - it contains info on the rw/rx
            mappings, at least. */
      }

   }
}


/* Unmap is simpler - throw away any SegInfos intersecting 
   [a, a+len).  */
void VG_(di_notify_munmap)( Addr a, SizeT len )
{
   if (0) VG_(printf)("DISCARD %p %p\n", a, a+len);
   discard_syms_in_range(a, len);
}


/* Uh, this doesn't do anything at all.  IIRC glibc (or ld.so, I don't
   remember) does a bunch of mprotects on itself, and if we follow
   through here, it causes the debug info for that object to get
   discarded. */
void VG_(di_notify_mprotect)( Addr a, SizeT len, UInt prot )
{
   Bool exe_ok = toBool(prot & VKI_PROT_EXEC);
#  if defined(VGP_x86_linux)
   exe_ok = exe_ok || toBool(prot & VKI_PROT_READ);
#  endif
   if (0 && !exe_ok)
      discard_syms_in_range(a, len);
}

#endif /* defined(VGO_linux) */


/*-------------------------------------------------------------*/
/*---                                                       ---*/
/*--- TOP LEVEL: NOTIFICATION (ACQUIRE/DISCARD INFO) (AIX5) ---*/
/*---                                                       ---*/
/*-------------------------------------------------------------*/

#if defined(VGO_aix5)

/* The supplied parameters describe a code segment and its associated
   data segment, that have recently been mapped in -- so we need to
   read debug info for it -- or conversely, have recently been dumped,
   in which case the relevant debug info has to be unloaded. */

void VG_(di_aix5_notify_segchange)( 
               Addr   code_start,
               Word   code_len,
               Addr   data_start,
               Word   data_len,
               UChar* file_name,
               UChar* mem_name,
               Bool   is_mainexe,
               Bool   acquire )
{
   SegInfo* si;

   if (acquire) {

      acquire_syms_for_range(
         /* ALL        */ code_start, 
         /* ALL        */ code_len,
         /* ELF only   */ 0,
         /* ALL        */ file_name,
         /* XCOFF only */ mem_name,
         /* XCOFF only */ data_start,
         /* XCOFF only */ data_len,
         /* XCOFF only */ is_mainexe 
      );

   } else {

      /* Dump all the segInfos whose text segments intersect
         code_start/code_len. */
      while (True) {
         for (si = debugInfo_list; si; si = si->next) {
            if (code_start + code_len <= si->text_start_avma
                || si->text_start_avma + si->text_size <= code_start)
               continue; /* no overlap */
            else 
               break;
         }
         if (si == NULL)
            break;
         /* Need to delete 'si' */
         discard_SegInfo(si);
      }

   }
}
        

#endif /* defined(VGO_aix5) */


/*------------------------------------------------------------*/
/*---                                                      ---*/
/*--- TOP LEVEL: QUERYING EXISTING DEBUG INFO              ---*/
/*---                                                      ---*/
/*------------------------------------------------------------*/

/*------------------------------------------------------------*/
/*--- Use of symbol table & location info to create        ---*/
/*--- plausible-looking stack dumps.                       ---*/
/*------------------------------------------------------------*/

/* Search all symtabs that we know about to locate ptr.  If found, set
   *pdi to the relevant DebugInfo, and *symno to the symtab entry
   *number within that.  If not found, *psi is set to NULL.
   If findText==True,  only text symbols are searched for.
   If findText==False, only data symbols are searched for.
*/
static void search_all_symtabs ( Addr ptr, /*OUT*/DebugInfo** pdi,
                                           /*OUT*/Int* symno,
                                 Bool match_anywhere_in_sym,
                                 Bool findText )
{
   Int        sno;
   DebugInfo* di;
   Bool       inRange;

   for (di = debugInfo_list; di != NULL; di = di->next) {

      if (findText) {
         inRange = di->text_size > 0
                   && di->text_avma <= ptr 
                   && ptr < di->text_avma + di->text_size;
      } else {
         inRange = di->data_size > 0
                   && di->data_avma <= ptr 
                   && ptr < di->data_avma + di->data_size + di->bss_size;
      }

      /* Note this short-circuit check relies on the assumption that
         .bss is mapped immediately after .data. */
      if (!inRange) continue;

      sno = ML_(search_one_symtab) ( 
               di, ptr, match_anywhere_in_sym, findText );
      if (sno == -1) goto not_found;
      *symno = sno;
      *pdi = di;
      return;

   }
  not_found:
   *pdi = NULL;
}


/* Search all loctabs that we know about to locate ptr.  If found, set
   *pdi to the relevant DebugInfo, and *locno to the loctab entry
   *number within that.  If not found, *pdi is set to NULL. */
static void search_all_loctabs ( Addr ptr, /*OUT*/DebugInfo** pdi,
                                           /*OUT*/Int* locno )
{
   Int        lno;
   DebugInfo* di;
   for (di = debugInfo_list; di != NULL; di = di->next) {
      if (di->text_avma <= ptr 
          && ptr < di->text_avma + di->text_size) {
         lno = ML_(search_one_loctab) ( di, ptr );
         if (lno == -1) goto not_found;
         *locno = lno;
         *pdi = di;
         return;
      }
   }
  not_found:
   *pdi = NULL;
}


/* The whole point of this whole big deal: map a code address to a
   plausible symbol name.  Returns False if no idea; otherwise True.
   Caller supplies buf and nbuf.  If demangle is False, don't do
   demangling, regardless of VG_(clo_demangle) -- probably because the
   call has come from VG_(get_fnname_nodemangle)().  findText
   indicates whether we're looking for a text symbol or a data symbol
   -- caller must choose one kind or the other. */
static
Bool get_sym_name ( Bool demangle, Addr a, Char* buf, Int nbuf,
                    Bool match_anywhere_in_sym, Bool show_offset,
                    Bool findText, /*OUT*/OffT* offsetP )
{
   DebugInfo* di;
   Int        sno;
   Int        offset;

   search_all_symtabs ( a, &di, &sno, match_anywhere_in_sym, findText );
   if (di == NULL) 
      return False;
   if (demangle) {
      VG_(demangle) ( True/*do C++ demangle*/,
                      di->symtab[sno].name, buf, nbuf );
   } else {
      VG_(strncpy_safely) ( buf, di->symtab[sno].name, nbuf );
   }

   offset = a - di->symtab[sno].addr;
   if (offsetP) *offsetP = (OffT)offset;

   if (show_offset && offset != 0) {
      Char     buf2[12];
      Char*    symend = buf + VG_(strlen)(buf);
      Char*    end = buf + nbuf;
      Int      len;

      len = VG_(sprintf)(buf2, "%c%d",
			 offset < 0 ? '-' : '+',
			 offset < 0 ? -offset : offset);
      vg_assert(len < (Int)sizeof(buf2));

      if (len < (end - symend)) {
	 Char *cp = buf2;
	 VG_(memcpy)(symend, cp, len+1);
      }
   }

   return True;
}

/* ppc64-linux only: find the TOC pointer (R2 value) that should be in
   force at the entry point address of the function containing
   guest_code_addr.  Returns 0 if not known. */
Addr VG_(get_tocptr) ( Addr guest_code_addr )
{
   DebugInfo* si;
   Int        sno;
   search_all_symtabs ( guest_code_addr, 
                        &si, &sno,
                        True/*match_anywhere_in_fun*/,
                        True/*consider text symbols only*/ );
   if (si == NULL) 
      return 0;
   else
      return si->symtab[sno].tocptr;
}

/* This is available to tools... always demangle C++ names,
   match anywhere in function, but don't show offsets. */
Bool VG_(get_fnname) ( Addr a, Char* buf, Int nbuf )
{
   return get_sym_name ( /*demangle*/True, a, buf, nbuf,
                         /*match_anywhere_in_fun*/True, 
                         /*show offset?*/False,
                         /*text syms only*/True,
                         /*offsetP*/NULL );
}

/* This is available to tools... always demangle C++ names,
   match anywhere in function, and show offset if nonzero. */
Bool VG_(get_fnname_w_offset) ( Addr a, Char* buf, Int nbuf )
{
   return get_sym_name ( /*demangle*/True, a, buf, nbuf,
                         /*match_anywhere_in_fun*/True, 
                         /*show offset?*/True,
                         /*text syms only*/True,
                         /*offsetP*/NULL );
}

/* This is available to tools... always demangle C++ names,
   only succeed if 'a' matches first instruction of function,
   and don't show offsets. */
Bool VG_(get_fnname_if_entry) ( Addr a, Char* buf, Int nbuf )
{
   return get_sym_name ( /*demangle*/True, a, buf, nbuf,
                         /*match_anywhere_in_fun*/False, 
                         /*show offset?*/False,
                         /*text syms only*/True,
                         /*offsetP*/NULL );
}

/* This is only available to core... don't demangle C++ names,
   match anywhere in function, and don't show offsets. */
Bool VG_(get_fnname_nodemangle) ( Addr a, Char* buf, Int nbuf )
{
   return get_sym_name ( /*demangle*/False, a, buf, nbuf,
                         /*match_anywhere_in_fun*/True, 
                         /*show offset?*/False,
                         /*text syms only*/True,
                         /*offsetP*/NULL );
}

/* This is only available to core... don't demangle C++ names, but do
   do Z-demangling, match anywhere in function, and don't show
   offsets. */
Bool VG_(get_fnname_Z_demangle_only) ( Addr a, Char* buf, Int nbuf )
{
#  define N_TMPBUF 4096 /* arbitrary, 4096 == ERRTXT_LEN */
   Char tmpbuf[N_TMPBUF];
   Bool ok;
   vg_assert(nbuf > 0);
   ok = get_sym_name ( /*demangle*/False, a, tmpbuf, N_TMPBUF,
                       /*match_anywhere_in_fun*/True, 
                       /*show offset?*/False,
                       /*text syms only*/True,
                       /*offsetP*/NULL );
   tmpbuf[N_TMPBUF-1] = 0; /* paranoia */
   if (!ok) 
      return False;

   /* We have something, at least.  Try to Z-demangle it. */
   VG_(demangle)( False/*don't do C++ demangling*/, tmpbuf, buf, nbuf);

   buf[nbuf-1] = 0; /* paranoia */
   return True;
#  undef N_TMPBUF
}

/* Looks up 'a' in the collection of data symbols, and if found puts
   its name (or as much as will fit) into dname[0 .. n_dname-1]
   including zero terminator.  Also the 'a's offset from the symbol
   start is put into *offset. */
Bool VG_(get_dataname_and_offset)( Addr a,
                                   /*OUT*/Char* dname, Int n_dname,
                                   /*OUT*/OffT* offset )
{
   Bool ok;
   vg_assert(n_dname > 1);
   ok = get_sym_name ( /*demangle*/False, a, dname, n_dname,
                       /*match_anywhere_in_sym*/True, 
                       /*show offset?*/False,
                       /*data syms only please*/False,
                       offset );
   if (!ok)
      return False;
   dname[n_dname-1] = 0;
   return True;
}


/* Map a code address to the name of a shared object file or the
   executable.  Returns False if no idea; otherwise True.  Doesn't
   require debug info.  Caller supplies buf and nbuf. */
Bool VG_(get_objname) ( Addr a, Char* buf, Int nbuf )
{
   Int        used;
   DebugInfo* di;
   vg_assert(nbuf > 0);
   for (di = debugInfo_list; di != NULL; di = di->next) {
      if (di->text_avma <= a 
          && a < di->text_avma + di->text_size) {
         VG_(strncpy_safely)(buf, di->filename, nbuf);
         if (di->memname) {
            used = VG_(strlen)(buf);
            if (used < nbuf) 
               VG_(strncpy_safely)(&buf[used], "(", nbuf-used);
            used = VG_(strlen)(buf);
            if (used < nbuf) 
               VG_(strncpy_safely)(&buf[used], di->memname, nbuf-used);
            used = VG_(strlen)(buf);
            if (used < nbuf) 
               VG_(strncpy_safely)(&buf[used], ")", nbuf-used);
         }
         buf[nbuf-1] = 0;
         return True;
      }
   }
   return False;
}

/* Map a code address to its DebugInfo.  Returns NULL if not found.  Doesn't
   require debug info. */
DebugInfo* VG_(find_seginfo) ( Addr a )
{
   DebugInfo* di;
   for (di = debugInfo_list; di != NULL; di = di->next) {
      if (di->text_avma <= a 
          && a < di->text_avma + di->text_size) {
         return di;
      }
   }
   return NULL;
}

/* Map a code address to a filename.  Returns True if successful.  */
Bool VG_(get_filename)( Addr a, Char* filename, Int n_filename )
{
   DebugInfo* si;
   Int      locno;
   search_all_loctabs ( a, &si, &locno );
   if (si == NULL) 
      return False;
   VG_(strncpy_safely)(filename, si->loctab[locno].filename, n_filename);
   return True;
}

/* Map a code address to a line number.  Returns True if successful. */
Bool VG_(get_linenum)( Addr a, UInt* lineno )
{
   DebugInfo* si;
   Int      locno;
   search_all_loctabs ( a, &si, &locno );
   if (si == NULL) 
      return False;
   *lineno = si->loctab[locno].lineno;

   return True;
}

/* Map a code address to a filename/line number/dir name info.
   See prototype for detailed description of behaviour.
*/
Bool VG_(get_filename_linenum) ( Addr a, 
                                 /*OUT*/Char* filename, Int n_filename,
                                 /*OUT*/Char* dirname,  Int n_dirname,
                                 /*OUT*/Bool* dirname_available,
                                 /*OUT*/UInt* lineno )
{
   DebugInfo* si;
   Int      locno;

   vg_assert( (dirname == NULL && dirname_available == NULL)
              ||
              (dirname != NULL && dirname_available != NULL) );

   search_all_loctabs ( a, &si, &locno );
   if (si == NULL) {
      if (dirname_available) {
         *dirname_available = False;
         *dirname = 0;
      }
      return False;
   }

   VG_(strncpy_safely)(filename, si->loctab[locno].filename, n_filename);
   *lineno = si->loctab[locno].lineno;

   if (dirname) {
      /* caller wants directory info too .. */
      vg_assert(n_dirname > 0);
      if (si->loctab[locno].dirname) {
         /* .. and we have some */
         *dirname_available = True;
         VG_(strncpy_safely)(dirname, si->loctab[locno].dirname,
                                      n_dirname);
      } else {
         /* .. but we don't have any */
         *dirname_available = False;
         *dirname = 0;
      }
   }

   return True;
}


/* Map a function name to its entry point and toc pointer.  Is done by
   sequential search of all symbol tables, so is very slow.  To
   mitigate the worst performance effects, you may specify a soname
   pattern, and only objects matching that pattern are searched.
   Therefore specify "*" to search all the objects.  On TOC-afflicted
   platforms, a symbol is deemed to be found only if it has a nonzero
   TOC pointer.  */
Bool VG_(lookup_symbol_SLOW)(UChar* sopatt, UChar* name, Addr* pEnt, Addr* pToc)
{
   Bool     require_pToc = False;
   Int      i;
   DebugInfo* si;
   Bool     debug = False;
#  if defined(VG_PLAT_USES_PPCTOC)
   require_pToc = True;
#  endif
   for (si = debugInfo_list; si; si = si->next) {
      if (debug)
         VG_(printf)("lookup_symbol_SLOW: considering %s\n", si->soname);
      if (!VG_(string_match)(sopatt, si->soname)) {
         if (debug)
            VG_(printf)(" ... skip\n");
         continue;
      }
      for (i = 0; i < si->symtab_used; i++) {
         if (0==VG_(strcmp)(name, si->symtab[i].name)
             && (require_pToc ? si->symtab[i].tocptr : True)) {
            *pEnt = si->symtab[i].addr;
            *pToc = si->symtab[i].tocptr;
            return True;
         }
      }
   }
   return False;
}


/* VG_(describe_IP): print into buf info on code address, function
   name and filename. */

/* Copy str into buf starting at n, but not going past buf[n_buf-1]
   and always ensuring that buf is zero-terminated. */

static Int putStr ( Int n, Int n_buf, Char* buf, Char* str ) 
{
   vg_assert(n_buf > 0);
   vg_assert(n >= 0 && n < n_buf);
   for (; n < n_buf-1 && *str != 0; n++,str++)
      buf[n] = *str;
   vg_assert(n >= 0 && n < n_buf);
   buf[n] = '\0';
   return n;
}

/* Same as putStr, but escaping chars for XML output, and
   also not adding more than count chars to n_buf. */

static Int putStrEsc ( Int n, Int n_buf, Int count, Char* buf, Char* str ) 
{
   Char alt[2];
   vg_assert(n_buf > 0);
   vg_assert(count >= 0 && count < n_buf);
   vg_assert(n >= 0 && n < n_buf);
   for (; *str != 0; str++) {
      vg_assert(count >= 0);
      if (count <= 0)
         goto done;
      switch (*str) {
         case '&': 
            if (count < 5) goto done;
            n = putStr( n, n_buf, buf, "&amp;"); 
            count -= 5;
            break;
         case '<': 
            if (count < 4) goto done;
            n = putStr( n, n_buf, buf, "&lt;"); 
            count -= 4;
            break;
         case '>': 
            if (count < 4) goto done;
            n = putStr( n, n_buf, buf, "&gt;"); 
            count -= 4;
            break;
         default:
            if (count < 1) goto done;
            alt[0] = *str;
            alt[1] = 0;
            n = putStr( n, n_buf, buf, alt );
            count -= 1;
            break;
      }
   }
  done:
   vg_assert(count >= 0); /* should not go -ve in loop */
   vg_assert(n >= 0 && n < n_buf);
   return n;
}

Char* VG_(describe_IP)(Addr eip, Char* buf, Int n_buf)
{
#  define APPEND(_str) \
      n = putStr(n, n_buf, buf, _str)
#  define APPEND_ESC(_count,_str) \
      n = putStrEsc(n, n_buf, (_count), buf, (_str))
#  define BUF_LEN    4096

   UInt  lineno; 
   UChar ibuf[50];
   Int   n = 0;
   static UChar buf_fn[BUF_LEN];
   static UChar buf_obj[BUF_LEN];
   static UChar buf_srcloc[BUF_LEN];
   static UChar buf_dirname[BUF_LEN];
   Bool  know_dirinfo = False;
   Bool  know_fnname  = VG_(clo_sym_offsets)
                        ? VG_(get_fnname_w_offset) (eip, buf_fn, BUF_LEN)
                        : VG_(get_fnname) (eip, buf_fn, BUF_LEN);
   Bool  know_objname = VG_(get_objname)(eip, buf_obj, BUF_LEN);
   Bool  know_srcloc  = VG_(get_filename_linenum)(
                           eip, 
                           buf_srcloc,  BUF_LEN, 
                           buf_dirname, BUF_LEN, &know_dirinfo,
                           &lineno 
                        );
   if (VG_(clo_xml)) {

      Bool   human_readable = True;
      HChar* maybe_newline  = human_readable ? "\n      " : "";
      HChar* maybe_newline2 = human_readable ? "\n    "   : "";

      /* Print in XML format, dumping in as much info as we know.
         Ensure all tags are balanced even if the individual strings
         are too long.  Allocate 1/10 of BUF_LEN to the object name,
         6/10s to the function name, 1/10 to the directory name and
         1/10 to the file name, leaving 1/10 for all the fixed-length
         stuff. */
      APPEND("<frame>");
      VG_(sprintf)(ibuf,"<ip>0x%llX</ip>", (ULong)eip);
      APPEND(maybe_newline);
      APPEND(ibuf);
      if (know_objname) {
         APPEND(maybe_newline);
         APPEND("<obj>");
         APPEND_ESC(1*BUF_LEN/10, buf_obj);
         APPEND("</obj>");
      }
      if (know_fnname) {
         APPEND(maybe_newline);
         APPEND("<fn>");
         APPEND_ESC(6*BUF_LEN/10, buf_fn);
         APPEND("</fn>");
      }
      if (know_srcloc) {
         if (know_dirinfo) {
            APPEND(maybe_newline);
            APPEND("<dir>");
            APPEND_ESC(1*BUF_LEN/10, buf_dirname);
            APPEND("</dir>");
         }
         APPEND(maybe_newline);
         APPEND("<file>");
         APPEND_ESC(1*BUF_LEN/10, buf_srcloc);
         APPEND("</file>");
         APPEND(maybe_newline);
         APPEND("<line>");
         VG_(sprintf)(ibuf,"%d",lineno);
         APPEND(ibuf);
         APPEND("</line>");
      }
      APPEND(maybe_newline2);
      APPEND("</frame>");

   } else {

      /* Print for humans to read */
      VG_(sprintf)(ibuf,"0x%llX: ", (ULong)eip);
      APPEND(ibuf);
      if (know_fnname) { 
         APPEND(buf_fn);
         if (!know_srcloc && know_objname) {
            APPEND(" (in ");
            APPEND(buf_obj);
            APPEND(")");
         }
      } else if (know_objname && !know_srcloc) {
         APPEND("(within ");
         APPEND(buf_obj);
         APPEND(")");
      } else {
         APPEND("???");
      }
      if (know_srcloc) {
         APPEND(" (");
         APPEND(buf_srcloc);
         APPEND(":");
         VG_(sprintf)(ibuf,"%d",lineno);
         APPEND(ibuf);
         APPEND(")");
      }

   }
   return buf;

#  undef APPEND
#  undef APPEND_ESC
#  undef BUF_LEN
}


/*------------------------------------------------------------*/
/*--- For unwinding the stack using                       --- */
/*--- pre-summarised DWARF3 .eh_frame info                 ---*/
/*------------------------------------------------------------*/

/* Gather up all the constant pieces of info needed to evaluate
   a CfiExpr into one convenient struct. */
typedef
   struct {
      Addr ipHere;
      Addr spHere;
      Addr fpHere;
      Addr min_accessible;
      Addr max_accessible;
   }
   CfiExprEvalContext;

/* Evaluate the CfiExpr rooted at ix in exprs given the context eec.
   *ok is set to False on failure, but not to True on success.  The
   caller must set it to True before calling. */
static 
UWord evalCfiExpr ( XArray* exprs, Int ix, 
                    CfiExprEvalContext* eec, Bool* ok )
{
   UWord wL, wR;
   Addr  a;
   CfiExpr* e = VG_(indexXA)( exprs, ix );
   switch (e->tag) {
      case Cex_Binop:
         wL = evalCfiExpr( exprs, e->Cex.Binop.ixL, eec, ok );
         if (!(*ok)) return 0;
         wR = evalCfiExpr( exprs, e->Cex.Binop.ixR, eec, ok );
         if (!(*ok)) return 0;
         switch (e->Cex.Binop.op) {
            case Cop_Add: return wL + wR;
            case Cop_Sub: return wL - wR;
            case Cop_And: return wL & wR;
            case Cop_Mul: return wL * wR;
            default: goto unhandled;
         }
         /*NOTREACHED*/
      case Cex_CfiReg:
         switch (e->Cex.CfiReg.reg) {
            case Creg_IP: return (Addr)eec->ipHere;
            case Creg_SP: return (Addr)eec->spHere;
            case Creg_FP: return (Addr)eec->fpHere;
            default: goto unhandled;
         }
         /*NOTREACHED*/
      case Cex_Const:
         return e->Cex.Const.con;
      case Cex_Deref:
         a = evalCfiExpr( exprs, e->Cex.Deref.ixAddr, eec, ok );
         if (!(*ok)) return 0;
         if (a < eec->min_accessible
             || (a + sizeof(UWord) - 1) > eec->max_accessible) {
            *ok = False;
            return 0;
         }
         /* let's hope it doesn't trap! */
         return * ((UWord*)a);
      default: 
         goto unhandled;
   }
   /*NOTREACHED*/
  unhandled:
   VG_(printf)("\n\nevalCfiExpr: unhandled\n");
   ML_(ppCfiExpr)( exprs, ix );
   VG_(printf)("\n");
   vg_assert(0);
   /*NOTREACHED*/
   return 0;
}


/* The main function for DWARF2/3 CFI-based stack unwinding.
   Given an IP/SP/FP triple, produce the IP/SP/FP values for the
   previous frame, if possible. */
/* Returns True if OK.  If not OK, *{ip,sp,fp}P are not changed. */
/* NOTE: this function may rearrange the order of entries in the
   DebugInfo list. */
Bool VG_(use_CF_info) ( /*MOD*/Addr* ipP,
                        /*MOD*/Addr* spP,
                        /*MOD*/Addr* fpP,
                        Addr min_accessible,
                        Addr max_accessible )
{
   Bool     ok;
   Int      i;
   DebugInfo* si;
   DiCfSI*  cfsi = NULL;
   Addr     cfa, ipHere, spHere, fpHere, ipPrev, spPrev, fpPrev;

   CfiExprEvalContext eec;

   static UInt n_search = 0;
   static UInt n_steps = 0;
   n_search++;

   if (0) VG_(printf)("search for %p\n", *ipP);

   for (si = debugInfo_list; si != NULL; si = si->next) {
      n_steps++;

      /* Use the per-DebugInfo summary address ranges to skip
	 inapplicable DebugInfos quickly. */
      if (si->cfsi_used == 0)
         continue;
      if (*ipP < si->cfsi_minaddr || *ipP > si->cfsi_maxaddr)
         continue;

      i = ML_(search_one_cfitab)( si, *ipP );
      if (i != -1) {
         vg_assert(i >= 0 && i < si->cfsi_used);
         cfsi = &si->cfsi[i];
         break;
      }
   }

   if (cfsi == NULL)
      return False;

   if (0 && ((n_search & 0xFFFFF) == 0))
      VG_(printf)("%u %u\n", n_search, n_steps);

   /* Start of performance-enhancing hack: once every 16 (chosen
      hackily after profiling) successful searches, move the found
      DebugInfo one step closer to the start of the list.  This makes
      future searches cheaper.  For starting konqueror on amd64, this
      in fact reduces the total amount of searching done by the above
      find-the-right-DebugInfo loop by more than a factor of 20. */
   if ((n_search & 0xF) == 0) {
      /* Move si one step closer to the start of the list. */
      DebugInfo* si0 = debugInfo_list;
      DebugInfo* si1 = NULL;
      DebugInfo* si2 = NULL;
      DebugInfo* tmp;
      while (True) {
         if (si0 == NULL) break;
         if (si0 == si) break;
         si2 = si1;
         si1 = si0;
         si0 = si0->next;
      }
      if (si0 == si && si0 != NULL && si1 != NULL && si2 != NULL) {
         /* si0 points to si, si1 to its predecessor, and si2 to si1's
            predecessor.  Swap si0 and si1, that is, move si0 one step
            closer to the start of the list. */
         tmp = si0->next;
         si2->next = si0;
         si0->next = si1;
         si1->next = tmp;
      }
   }
   /* End of performance-enhancing hack. */

   if (0) {
      VG_(printf)("found cfisi: "); 
      ML_(ppDiCfSI)(si->cfsi_exprs, cfsi);
   }

   ipPrev = spPrev = fpPrev = 0;

   ipHere = *ipP;
   spHere = *spP;
   fpHere = *fpP;

   /* First compute the CFA. */
   cfa = 0;
   switch (cfsi->cfa_how) {
      case CFIC_SPREL: 
         cfa = cfsi->cfa_off + spHere;
         break;
      case CFIC_FPREL: 
         cfa = cfsi->cfa_off + fpHere;
         break;
      case CFIC_EXPR: 
         if (0) {
            VG_(printf)("CFIC_EXPR: ");
            ML_(ppCfiExpr)(si->cfsi_exprs, cfsi->cfa_off);
            VG_(printf)("\n");
         }
         eec.ipHere = ipHere;
         eec.spHere = spHere;
         eec.fpHere = fpHere;
         eec.min_accessible = min_accessible;
         eec.max_accessible = max_accessible;
         ok = True;
         cfa = evalCfiExpr(si->cfsi_exprs, cfsi->cfa_off, &eec, &ok );
         if (!ok) return False;
         break;
      default: 
         vg_assert(0);
   }

   /* Now we know the CFA, use it to roll back the registers we're
      interested in. */

#  define COMPUTE(_prev, _here, _how, _off)             \
      do {                                              \
         switch (_how) {                                \
            case CFIR_UNKNOWN:                          \
               return False;                            \
            case CFIR_SAME:                             \
               _prev = _here; break;                    \
            case CFIR_MEMCFAREL: {                      \
               Addr a = cfa + (Word)_off;               \
               if (a < min_accessible                   \
                   || a+sizeof(Addr) > max_accessible)  \
                  return False;                         \
               _prev = *(Addr*)a;                       \
               break;                                   \
            }                                           \
            case CFIR_CFAREL:                           \
               _prev = cfa + (Word)_off;                \
               break;                                   \
            case CFIR_EXPR:                             \
               if (0)                                   \
                  ML_(ppCfiExpr)(si->cfsi_exprs,_off);  \
               eec.ipHere = ipHere;                     \
               eec.spHere = spHere;                     \
               eec.fpHere = fpHere;                     \
               eec.min_accessible = min_accessible;     \
               eec.max_accessible = max_accessible;     \
               ok = True;                               \
               _prev = evalCfiExpr(si->cfsi_exprs, _off, &eec, &ok ); \
               if (!ok) return False;                   \
               break;                                   \
            default:                                    \
               vg_assert(0);                            \
         }                                              \
      } while (0)

   COMPUTE(ipPrev, ipHere, cfsi->ra_how, cfsi->ra_off);
   COMPUTE(spPrev, spHere, cfsi->sp_how, cfsi->sp_off);
   COMPUTE(fpPrev, fpHere, cfsi->fp_how, cfsi->fp_off);

#  undef COMPUTE

   *ipP = ipPrev;
   *spP = spPrev;
   *fpP = fpPrev;
   return True;
}


/*------------------------------------------------------------*/
/*--- DebugInfo accessor functions                         ---*/
/*------------------------------------------------------------*/

const DebugInfo* VG_(next_seginfo)(const DebugInfo* di)
{
   if (di == NULL)
      return debugInfo_list;
   return di->next;
}

Addr VG_(seginfo_start)(const DebugInfo* di)
{
   return di->text_avma;
}

SizeT VG_(seginfo_size)(const DebugInfo* di)
{
   return di->text_size;
}

const UChar* VG_(seginfo_soname)(const DebugInfo* di)
{
   return di->soname;
}

const UChar* VG_(seginfo_filename)(const DebugInfo* di)
{
   return di->filename;
}

ULong VG_(seginfo_sym_offset)(const DebugInfo* di)
{
   return di->text_bias;
}

Int VG_(seginfo_syms_howmany) ( const DebugInfo *si )
{
   return si->symtab_used;
}

void VG_(seginfo_syms_getidx) ( const DebugInfo *si, 
                                      Int idx,
                               /*OUT*/Addr*   addr,
                               /*OUT*/Addr*   tocptr,
                               /*OUT*/UInt*   size,
                               /*OUT*/HChar** name,
                               /*OUT*/Bool*   isText )
{
   vg_assert(idx >= 0 && idx < si->symtab_used);
   if (addr)   *addr   = si->symtab[idx].addr;
   if (tocptr) *tocptr = si->symtab[idx].tocptr;
   if (size)   *size   = si->symtab[idx].size;
   if (name)   *name   = (HChar*)si->symtab[idx].name;
   if (isText) *isText = si->symtab[idx].isText;
}


/*------------------------------------------------------------*/
/*--- SectKind query functions                             ---*/
/*------------------------------------------------------------*/

/* Convert a VgSectKind to a string, which must be copied if you want
   to change it. */
const HChar* VG_(pp_SectKind)( VgSectKind kind )
{
   switch (kind) {
      case Vg_SectUnknown: return "Unknown";
      case Vg_SectText:    return "Text";
      case Vg_SectData:    return "Data";
      case Vg_SectBSS:     return "BSS";
      case Vg_SectGOT:     return "GOT";
      case Vg_SectPLT:     return "PLT";
      case Vg_SectOPD:     return "OPD";
      default:             vg_assert(0);
   }
}

/* Given an address 'a', make a guess of which section of which object
   it comes from.  If name is non-NULL, then the last n_name-1
   characters of the object's name is put in name[0 .. n_name-2], and
   name[n_name-1] is set to zero (guaranteed zero terminated). */

VgSectKind VG_(seginfo_sect_kind)( /*OUT*/UChar* name, SizeT n_name, 
                                   Addr a)
{
   DebugInfo* di;
   VgSectKind res = Vg_SectUnknown;

   for (di = debugInfo_list; di != NULL; di = di->next) {

      if (0)
         VG_(printf)(
            "addr=%p di=%p %s got=%p,%ld plt=%p,%ld data=%p,%ld bss=%p,%ld\n",
            a, di, di->filename,
            di->got_avma,  di->got_size,
            di->plt_avma,  di->plt_size,
            di->data_avma, di->data_size,
            di->bss_avma,  di->bss_size);

      if (di->text_size > 0
          && a >= di->text_avma && a < di->text_avma + di->text_size) {
         res = Vg_SectText;
         break;
      }
      if (di->data_size > 0
          && a >= di->data_avma && a < di->data_avma + di->data_size) {
         res = Vg_SectData;
         break;
      }
      if (di->bss_size > 0
          && a >= di->bss_avma && a < di->bss_avma + di->bss_size) {
         res = Vg_SectBSS;
         break;
      }
      if (di->plt_size > 0
          && a >= di->plt_avma && a < di->plt_avma + di->plt_size) {
         res = Vg_SectPLT;
         break;
      }
      if (di->got_size > 0
          && a >= di->got_avma && a < di->got_avma + di->got_size) {
         res = Vg_SectGOT;
         break;
      }
      if (di->opd_size > 0
          && a >= di->opd_avma && a < di->opd_avma + di->opd_size) {
         res = Vg_SectOPD;
         break;
      }
      /* we could also check for .eh_frame, if anyone really cares */
   }

   vg_assert( (di == NULL && res == Vg_SectUnknown)
              || (di != NULL && res != Vg_SectUnknown) );

   if (name) {

      vg_assert(n_name >= 8);

      if (di && di->filename) {
         Int i, j;
         Int fnlen = VG_(strlen)(di->filename);
         Int start_at = 1 + fnlen - n_name;
         if (start_at < 0) start_at = 0;
         vg_assert(start_at < fnlen);
         i = start_at; j = 0;
         while (True) {
            vg_assert(j >= 0 && j+1 < n_name);
            vg_assert(i >= 0 && i <= fnlen);
            name[j] = di->filename[i];
            name[j+1] = 0;
            if (di->filename[i] == 0) break;
            i++; j++;
         }
      } else {
         VG_(snprintf)(name, n_name, "%s", "???");
      }

      name[n_name-1] = 0;
   }

   return res;

}


/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
