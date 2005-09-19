
/*--------------------------------------------------------------------*/
/*--- The address space manager.              pub_core_aspacemgr.h ---*/
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

#ifndef __PUB_CORE_ASPACEMGR_H
#define __PUB_CORE_ASPACEMGR_H

//--------------------------------------------------------------------
// PURPOSE: This module deals with management of the entire process
// address space.  Almost everything depends upon it, including dynamic
// memory management.  Hence this module is almost completely
// standalone; the only module it uses is m_debuglog.  DO NOT CHANGE
// THIS.
// [XXX: actually, this is far from true... especially that to #include
// this header, you have to #include pub_core_debuginfo in order to 
// see the SegInfo type, which is very bad...]
//--------------------------------------------------------------------

#include "pub_tool_aspacemgr.h"

// Address space globals
extern Addr VG_(client_base);	 // client address space limits
extern Addr VG_(client_end);
extern Addr VG_(client_mapbase); // base of mappings
extern Addr VG_(clstk_base);	 // client stack range
extern Addr VG_(clstk_end);
extern UWord VG_(clstk_id);      // client stack id

extern Addr VG_(brk_base);	 // start of brk
extern Addr VG_(brk_limit);	 // current brk
extern Addr VG_(shadow_base);	 // tool's shadow memory
extern Addr VG_(shadow_end);
extern Addr VG_(valgrind_base);	 // valgrind's address range
extern Addr VG_(valgrind_last);  // Nb: last byte, rather than one past the end

// Direct access to these system calls.
extern SysRes VG_(mmap_native)     ( void* start, SizeT length, UInt prot,
                                     UInt flags, UInt fd, OffT offset );
extern SysRes VG_(munmap_native)   ( void* start, SizeT length );
extern SysRes VG_(mprotect_native) ( void *start, SizeT length, UInt prot );

/* A Segment is mapped piece of client memory.  This covers all kinds
   of mapped memory (exe, brk, mmap, .so, shm, stack, etc)

   We encode relevant info about each segment with these constants.
*/
#define SF_SHARED   (1 <<  0) // shared
#define SF_SHM      (1 <<  1) // SYSV SHM (also SF_SHARED)
#define SF_MMAP     (1 <<  2) // mmap memory
#define SF_FILE     (1 <<  3) // mapping is backed by a file
#define SF_STACK    (1 <<  4) // is a stack
#define SF_GROWDOWN (1 <<  5) // segment grows down
#define SF_NOSYMS   (1 <<  6) // don't load syms, even if present
#define SF_CORE     (1 <<  7) // allocated by core on behalf of the client
#define SF_VALGRIND (1 <<  8) // a valgrind-internal mapping - not in client
#define SF_CODE     (1 <<  9) // segment contains cached code

typedef struct _Segment Segment;

struct _Segment {
   UInt         prot;         // VKI_PROT_*
   UInt         flags;        // SF_*

   Addr         addr;         // mapped addr (page aligned)
   SizeT        len;          // size of mapping (page aligned)

   // These are valid if (flags & SF_FILE)
   OffT        offset;        // file offset
   const Char* filename;      // filename (NULL if unknown)
   Int         fnIdx;         // filename table index (-1 if unknown)
   UInt        dev;           // device
   UInt        ino;           // inode

   SegInfo*    seginfo;       // symbol table, etc
};

/* segment mapped from a file descriptor */
extern void VG_(map_fd_segment)  (Addr addr, SizeT len, UInt prot, UInt flags, 
				  Int fd, ULong off, const Char *filename);

/* segment mapped from a file */
extern void VG_(map_file_segment)(Addr addr, SizeT len, UInt prot, UInt flags, 
				  UInt dev, UInt ino, ULong off, const Char *filename);

/* simple segment */
extern void VG_(map_segment)     (Addr addr, SizeT len, UInt prot, UInt flags);

extern void VG_(unmap_range)   (Addr addr, SizeT len);
extern void VG_(mprotect_range)(Addr addr, SizeT len, UInt prot);
extern Addr VG_(find_map_space)(Addr base, SizeT len, Bool for_client);

/* Find the segment containing a, or NULL if none. */
extern Segment *VG_(find_segment)(Addr a);

/* a is an unmapped address (is checked).  Find the next segment 
   along in the address space, or NULL if none. */
extern Segment *VG_(find_segment_above_unmapped)(Addr a);

/* a is a mapped address (in a segment, is checked).  Find the
   next segment along. */
extern Segment *VG_(find_segment_above_mapped)(Addr a);

extern Bool VG_(seg_contains)(const Segment *s, Addr ptr, SizeT size);
extern Bool VG_(seg_overlaps)(const Segment *s, Addr ptr, SizeT size);

extern Segment *VG_(split_segment)(Addr a);

extern void VG_(pad_address_space)  (Addr start);
extern void VG_(unpad_address_space)(Addr start);

///* Search /proc/self/maps for changes which aren't reflected in the
//   segment list */
//extern void VG_(sync_segments)(UInt flags);

/* Return string for prot */
extern const HChar *VG_(prot_str)(UInt prot);

/* Parses /proc/self/maps, calling `record_mapping' for each entry. */
extern 
void VG_(parse_procselfmaps) (
   void (*record_mapping)( Addr addr, SizeT len, UInt prot,
			   UInt dev, UInt ino, ULong foff,
                           const UChar *filename ) );

// Pointercheck
extern Bool VG_(setup_pointercheck) ( Addr client_base, Addr client_end );

/////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////

/* New address-space-manager stuff from here on down. */


//--------------------------------------------------------------
// Definition of address-space segments

/* types SegKind, ShrinkMode and NSegment are described in
   the tool-visible header file, not here. */


//--------------------------------------------------------------
// Initialisation

/* Initialise the address space manager, setting up the initial
   segment list, and reading /proc/self/maps into it.  This must
   be called before any other function.

   Takes a pointer to the SP at the time V gained control.  This is
   taken to be the highest usable address (more or less).  Based on
   that (and general consultation of tea leaves, etc) return a
   suggested end address for the client's stack. */
extern Addr VG_(am_startup) ( Addr sp_at_startup );


//--------------------------------------------------------------
// Querying current status

/* Finds the segment containing 'a'.  Only returns file/anon/resvn
   segments. */
// Is in tool-visible header file.
// extern NSegment* VG_(am_find_nsegment) ( Addr a );

/* Find the next segment along from 'here', if it is a file/anon/resvn
   segment. */
extern NSegment* VG_(am_next_nsegment) ( NSegment* here, Bool fwds );

/* Is the area [start .. start+len-1] validly accessible by the 
   client with at least the permissions 'prot' ?  To find out
   simply if said area merely belongs to the client, pass 
   VKI_PROT_NONE as 'prot'.  Will return False if any part of the
   area does not belong to the client or does not have at least
   the stated permissions. */
// Is in tool-visible header file.
// extern Bool VG_(am_is_valid_for_client)
//   ( Addr start, SizeT len, UInt prot );

/* Variant of VG_(am_is_valid_for_client) which allows free areas to
   be consider part of the client's addressable space.  It also
   considers reservations to be allowable, since from the client's
   point of view they don't exist. */
extern Bool VG_(am_is_valid_for_client_or_free_or_resvn)
   ( Addr start, SizeT len, UInt prot );

/* Trivial fn: return the total amount of space in anonymous mappings,
   both for V and the client.  Is used for printing stats in
   out-of-memory messages. */
extern ULong VG_(am_get_anonsize_total)( void );

/* Show the segment array on the debug log, at given loglevel. */
extern void VG_(am_show_nsegments) ( Int logLevel, HChar* who );

/* Get the filename corresponding to this segment, if known and if it
   has one.  The returned name's storage cannot be assumed to be
   persistent, so the caller should immediately copy the name
   elsewhere. */
extern HChar* VG_(am_get_filename)( NSegment* );

/* VG_(am_get_segment_starts) is also part of this section, but its
   prototype is tool-visible, hence not in this header file. */


//--------------------------------------------------------------
// Functions pertaining to the central query-notify mechanism
// used to handle mmap/munmap/mprotect resulting from client
// syscalls.

/* Describes a request for VG_(am_get_advisory). */
typedef
   struct {
      enum { MFixed, MHint, MAny } rkind;
      Addr start;
      Addr len;
   }
   MapRequest;

/* Query aspacem to ask where a mapping should go.  On success, the
   advised placement is returned, and *ok is set to True.  On failure,
   zero is returned and *ok is set to False.  Note that *ok must be
   consulted by the caller to establish success or failure; that
   cannot be established reliably from the returned value.  If *ok is
   set to False, it means aspacem has vetoed the mapping, and so the
   caller should not proceed with it. */
extern Addr VG_(am_get_advisory)
   ( MapRequest* req, Bool forClient, /*OUT*/Bool* ok );

/* Convenience wrapper for VG_(am_get_advisory) for client floating or
   fixed requests.  If start is zero, a floating request is issued; if
   nonzero, a fixed request at that address is issued.  Same comments
   about return values apply. */
extern Addr VG_(am_get_advisory_client_simple) 
   ( Addr start, SizeT len, /*OUT*/Bool* ok );

/* Notifies aspacem that the client completed an mmap successfully.
   The segment array is updated accordingly. */
extern void VG_(am_notify_client_mmap)
   ( Addr a, SizeT len, UInt prot, UInt flags, Int fd, SizeT offset );

/* Notifies aspacem that an mprotect was completed successfully.  The
   segment array is updated accordingly.  Note, as with
   VG_(am_notify_munmap), it is not the job of this function to reject
   stupid mprotects, for example the client doing mprotect of
   non-client areas.  Such requests should be intercepted earlier, by
   the syscall wrapper for mprotect.  This function merely records
   whatever it is told. */
extern void VG_(am_notify_mprotect)( Addr start, SizeT len, UInt prot );

/* Notifies aspacem that an munmap completed successfully.  The
   segment array is updated accordingly.  As with
   VG_(am_notify_munmap), we merely record the given info, and don't
   check it for sensibleness. */
extern void VG_(am_notify_munmap)( Addr start, SizeT len );


/* Hand a raw mmap to the kernel, without aspacem updating the segment
   array.  THIS FUNCTION IS DANGEROUS -- it will cause aspacem's view
   of the address space to diverge from that of the kernel.  DO NOT
   USE IT UNLESS YOU UNDERSTAND the request-notify model used by
   aspacem.  In short, DO NOT USE THIS FUNCTION. */
extern SysRes VG_(am_do_mmap_NO_NOTIFY)
   ( Addr start, SizeT length, UInt prot, UInt flags, UInt fd, OffT offset);


//--------------------------------------------------------------
// Dealing with mappings which do not arise directly from the
// simulation of the client.  These are typically used for
// loading the client and building its stack/data segment, before
// execution begins.  Also for V's own administrative use.

/* --- --- --- map, unmap, protect  --- --- --- */

/* Map a file at a fixed address for the client, and update the
   segment array accordingly. */
extern SysRes VG_(am_mmap_file_fixed_client)
   ( Addr start, SizeT length, UInt prot, Int fd, SizeT offset );

/* Map anonymously at a fixed address for the client, and update
   the segment array accordingly. */
extern SysRes VG_(am_mmap_anon_fixed_client)
   ( Addr start, SizeT length, UInt prot );

/* Map anonymously at an unconstrained address for the client, and
   update the segment array accordingly.  */
extern SysRes VG_(am_mmap_anon_float_client) ( SizeT length, Int prot );

/* Map anonymously at an unconstrained address for V, and update the
   segment array accordingly.  This is fundamentally how V allocates
   itself more address space when needed. */
extern SysRes VG_(am_mmap_anon_float_valgrind)( SizeT cszB );

/* Map a file at an unconstrained address for V, and update the
   segment array accordingly.  This is used by V for transiently
   mapping in object files to read their debug info.  */
extern SysRes VG_(am_mmap_file_float_valgrind)
   ( SizeT length, UInt prot, Int fd, SizeT offset );

/* Unmap the given address range and update the segment array
   accordingly.  This fails if the range isn't valid for the
   client. */
extern SysRes VG_(am_munmap_client)( Addr start, SizeT length );

/* Unmap the given address range and update the segment array
   accordingly.  This fails if the range isn't valid for valgrind. */
extern SysRes VG_(am_munmap_valgrind)( Addr start, SizeT length );

/* --- --- --- reservations --- --- --- */

/* Create a reservation from START .. START+LENGTH-1, with the given
   ShrinkMode.  When checking whether the reservation can be created,
   also ensure that at least abs(EXTRA) extra free bytes will remain
   above (> 0) or below (< 0) the reservation.

   The reservation will only be created if it, plus the extra-zone,
   falls entirely within a single free segment.  The returned Bool
   indicates whether the creation succeeded. */
extern Bool VG_(am_create_reservation) 
   ( Addr start, SizeT length, ShrinkMode smode, SSizeT extra );

/* Let SEG be an anonymous client mapping.  This fn extends the
   mapping by DELTA bytes, taking the space from a reservation section
   which must be adjacent.  If DELTA is positive, the segment is
   extended forwards in the address space, and the reservation must be
   the next one along.  If DELTA is negative, the segment is extended
   backwards in the address space and the reservation must be the
   previous one.  DELTA must be page aligned and must not exceed the
   size of the reservation segment. */
extern Bool VG_(am_extend_into_adjacent_reservation_client) 
   ( NSegment* seg, SSizeT delta );

/* --- --- --- resizing/move a mapping --- --- --- */

/* Let SEG be a client mapping (anonymous or file).  This fn extends
   the mapping forwards only by DELTA bytes, and trashes whatever was
   in the new area.  Fails if SEG is not a single client mapping or if
   the new area is not accessible to the client.  Fails if DELTA is
   not page aligned.  *seg is invalid after a successful return. */
extern Bool VG_(am_extend_map_client)( NSegment* seg, SizeT delta );

/* Remap the old address range to the new address range.  Fails if any
   parameter is not page aligned, if the either size is zero, if any
   wraparound is implied, if the old address range does not fall
   entirely within a single segment, if the new address range overlaps
   with the old one, or if the old address range is not a valid client
   mapping. */
extern Bool VG_(am_relocate_nooverlap_client)( Addr old_addr, SizeT old_len,
                                               Addr new_addr, SizeT new_len );

//--------------------------------------------------------------
// Valgrind (non-client) thread stacks.  V itself runs on such
// stacks.  The address space manager provides and suitably
// protects such stacks.

#define VG_STACK_GUARD_SZB  8192   // 2 pages
#define VG_STACK_ACTIVE_SZB 65536  // 16 pages

typedef
   struct {
      HChar bytes[VG_STACK_GUARD_SZB 
                  + VG_STACK_ACTIVE_SZB 
                  + VG_STACK_GUARD_SZB];
   }
   VgStack;


/* Allocate and initialise a VgStack (anonymous client space).
   Protect the stack active area and the guard areas appropriately.
   Returns NULL on failure, else the address of the bottom of the
   stack.  On success, also sets *initial_sp to what the stack pointer
   should be set to. */

extern VgStack* VG_(am_alloc_VgStack)( /*OUT*/Addr* initial_sp );

/* Figure out how many bytes of the stack's active area have not
   been used.  Used for estimating if we are close to overflowing it. */

extern Int VG_(am_get_VgStack_unused_szB)( VgStack* stack ); 


#endif   // __PUB_CORE_ASPACEMGR_H

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
