
/*--------------------------------------------------------------------*/
/*--- A header file for all parts of the MemCheck tool.            ---*/
/*---                                                 mc_include.h ---*/
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

#ifndef __MC_INCLUDE_H
#define __MC_INCLUDE_H

#define MC_(str)    VGAPPEND(vgMemCheck_,str)

/*------------------------------------------------------------*/
/*--- Errors and suppressions                              ---*/
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
   MAC_SuppKind;

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
   MAC_ErrorKind;

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
   MAC_Error;

/* Extra info for overlap errors */
typedef
   struct {
      Addr src;
      Addr dst;
      Int  len;   // -1 if unused
   }
   OverlapExtra;

/* For malloc()/new/new[] vs. free()/delete/delete[] mismatch checking. */
typedef
   enum {
      MAC_AllocMalloc = 0,
      MAC_AllocNew    = 1,
      MAC_AllocNewVec = 2,
      MAC_AllocCustom = 3
   }
   MAC_AllocKind;
   
/* Nb: first two fields must match core's VgHashNode. */
typedef
   struct _MAC_Chunk {
      struct _MAC_Chunk* next;
      Addr          data;           // ptr to actual block
      SizeT         size : (sizeof(UWord)*8)-2; // size requested; 30 or 62 bits
      MAC_AllocKind allockind : 2;  // which wrapper did the allocation
      ExeContext*   where;          // where it was allocated
   }
   MAC_Chunk;

/* Memory pool.  Nb: first two fields must match core's VgHashNode. */
typedef
   struct _MAC_Mempool {
      struct _MAC_Mempool* next;
      Addr          pool;           // pool identifier
      SizeT         rzB;            // pool red-zone size
      Bool          is_zeroed;      // allocations from this pool are zeroed
      VgHashTable   chunks;         // chunks associated with this pool
   }
   MAC_Mempool;

extern void MC_(record_free_error)            ( ThreadId tid, Addr a ); 
extern void MC_(record_illegal_mempool_error) ( ThreadId tid, Addr a );
extern void MC_(record_freemismatch_error)    ( ThreadId tid, Addr a,
                                                MAC_Chunk* mc );

/*------------------------------------------------------------*/
/*--- Profiling of tools and memory events                 ---*/
/*------------------------------------------------------------*/

typedef 
   enum { 
      VgpCheckMem = VgpFini+1,
      VgpSetMem,
      VgpESPAdj
   } 
   VgpToolCC;

/* Define to collect detailed performance info. */
/* #define MAC_PROFILE_MEMORY */

#ifdef MAC_PROFILE_MEMORY
#  define N_PROF_EVENTS 500

extern UInt   MC_(event_ctr)[N_PROF_EVENTS];
extern HChar* MC_(event_ctr_name)[N_PROF_EVENTS];

#  define PROF_EVENT(ev, name)                                \
   do { tl_assert((ev) >= 0 && (ev) < N_PROF_EVENTS);         \
        /* crude and inaccurate check to ensure the same */   \
        /* event isn't being used with > 1 name */            \
        if (MC_(event_ctr_name)[ev])                         \
           tl_assert(name == MC_(event_ctr_name)[ev]);       \
        MC_(event_ctr)[ev]++;                                \
        MC_(event_ctr_name)[ev] = (name);                    \
   } while (False);

#else

#  define PROF_EVENT(ev, name) /* */

#endif   /* MAC_PROFILE_MEMORY */


/*------------------------------------------------------------*/
/*--- V and A bits (Victoria & Albert ?)                   ---*/
/*------------------------------------------------------------*/

/* The number of entries in the primary map can be altered.  However
   we hardwire the assumption that each secondary map covers precisely
   64k of address space. */
#define SM_SIZE 65536            /* DO NOT CHANGE */
#define SM_MASK (SM_SIZE-1)      /* DO NOT CHANGE */

#define VGM_BIT_VALID       0
#define VGM_BIT_INVALID     1

#define VGM_NIBBLE_VALID    0
#define VGM_NIBBLE_INVALID  0xF

#define VGM_BYTE_VALID      0
#define VGM_BYTE_INVALID    0xFF

#define VGM_SHORT_VALID     0
#define VGM_SHORT_INVALID   0xFFFF

#define VGM_WORD32_VALID    0
#define VGM_WORD32_INVALID  0xFFFFFFFF

#define VGM_WORD64_VALID    0ULL
#define VGM_WORD64_INVALID  0xFFFFFFFFFFFFFFFFULL


/* We want a 16B redzone on heap blocks for Memcheck */
#define MAC_MALLOC_REDZONE_SZB    16

/*------------------------------------------------------------*/
/*--- Variables                                            ---*/
/*------------------------------------------------------------*/

/* For tracking malloc'd blocks */
extern VgHashTable MC_(malloc_list);

/* For tracking memory pools. */
extern VgHashTable MC_(mempool_list);

/* Function pointers for the two tools to track interesting events. */
extern void (*MC_(new_mem_heap)) ( Addr a, SizeT len, Bool is_inited );
extern void (*MC_(ban_mem_heap)) ( Addr a, SizeT len );
extern void (*MC_(die_mem_heap)) ( Addr a, SizeT len );
extern void (*MC_(copy_mem_heap))( Addr from, Addr to, SizeT len );

/* Function pointers for internal sanity checking. */
extern Bool (*MC_(check_noaccess))( Addr a, SizeT len, Addr* bad_addr );

/* For VALGRIND_COUNT_LEAKS client request */
extern SizeT MC_(bytes_leaked);
extern SizeT MC_(bytes_indirect);
extern SizeT MC_(bytes_dubious);
extern SizeT MC_(bytes_reachable);
extern SizeT MC_(bytes_suppressed);

/*------------------------------------------------------------*/
/*--- Functions                                            ---*/
/*------------------------------------------------------------*/

extern void MC_(pp_AddrInfo) ( Addr a, AddrInfo* ai );

extern void MC_(clear_MAC_Error)          ( MAC_Error* err_extra );

extern void* MC_(new_block) ( ThreadId tid,
                               Addr p, SizeT size, SizeT align, UInt rzB,
                               Bool is_zeroed, MAC_AllocKind kind,
                               VgHashTable table);

extern void MC_(handle_free) ( ThreadId tid,
                                Addr p, UInt rzB, MAC_AllocKind kind );

extern void MC_(create_mempool)(Addr pool, UInt rzB, Bool is_zeroed);

extern void MC_(destroy_mempool)(Addr pool);

extern void MC_(mempool_alloc)(ThreadId tid, 
                                Addr pool, Addr addr, SizeT size);

extern void MC_(mempool_free)(Addr pool, Addr addr);

extern MAC_Chunk* MC_(get_freed_list_head)( void );

/* For leak checking */
extern void MC_(pp_LeakError)(void* extra);
                           
extern void MC_(print_malloc_stats) ( void );

typedef
   enum {
      LC_Off,
      LC_Summary,
      LC_Full,
   }
   LeakCheckMode;

extern void MC_(do_detect_memory_leaks) (
          ThreadId tid, LeakCheckMode mode,
          Bool (*is_within_valid_secondary) ( Addr ),
          Bool (*is_valid_aligned_word)     ( Addr )
       );

extern void* MC_(malloc)               ( ThreadId tid, SizeT n );
extern void* MC_(__builtin_new)        ( ThreadId tid, SizeT n );
extern void* MC_(__builtin_vec_new)    ( ThreadId tid, SizeT n );
extern void* MC_(memalign)             ( ThreadId tid, SizeT align, SizeT n );
extern void* MC_(calloc)               ( ThreadId tid, SizeT nmemb, SizeT size1 );
extern void  MC_(free)                 ( ThreadId tid, void* p );
extern void  MC_(__builtin_delete)     ( ThreadId tid, void* p );
extern void  MC_(__builtin_vec_delete) ( ThreadId tid, void* p );
extern void* MC_(realloc)              ( ThreadId tid, void* p, SizeT new_size );

/*------------------------------------------------------------*/
/*--- Command line options + defaults                      ---*/
/*------------------------------------------------------------*/

/* Allow loads from partially-valid addresses?  default: YES */
extern Bool MC_(clo_partial_loads_ok);

/* Max volume of the freed blocks queue. */
extern Int MC_(clo_freelist_vol);

/* Do leak check at exit?  default: NO */
extern LeakCheckMode MC_(clo_leak_check);

/* How closely should we compare ExeContexts in leak records? default: 2 */
extern VgRes MC_(clo_leak_resolution);

/* In leak check, show reachable-but-not-freed blocks?  default: NO */
extern Bool MC_(clo_show_reachable);

/* Assume accesses immediately below %esp are due to gcc-2.96 bugs.
 * default: NO */
extern Bool MC_(clo_workaround_gcc296_bugs);

/* Do undefined value checking? "No" gives Addrcheck-style behaviour, ie.
 * faster but fewer errors found.  Note that although Addrcheck had 1 bit
 * per byte overhead vs the old Memcheck's 9 bits per byte, with this mode
 * and compressed V bits, no memory is saved with this mode -- it's still
 * 2 bits per byte overhead.  This is a little wasteful -- it could be done
 * with 1 bit per byte -- but lets us reuse the many shadow memory access
 * functions.  Note also that in this mode the secondary V bit table is
 * never used.
 *
 * default: YES */
extern Bool MC_(clo_undef_value_errors);


/*------------------------------------------------------------*/
/*--- Functions                                            ---*/
/*------------------------------------------------------------*/

/* Functions defined in mc_main.c */
extern VG_REGPARM(1) void MC_(helperc_complain_undef) ( HWord );
extern void MC_(helperc_value_check8_fail) ( void );
extern void MC_(helperc_value_check4_fail) ( void );
extern void MC_(helperc_value_check1_fail) ( void );
extern void MC_(helperc_value_check0_fail) ( void );

extern VG_REGPARM(1) void MC_(helperc_STOREV8be) ( Addr, ULong );
extern VG_REGPARM(1) void MC_(helperc_STOREV8le) ( Addr, ULong );
extern VG_REGPARM(2) void MC_(helperc_STOREV4be) ( Addr, UWord );
extern VG_REGPARM(2) void MC_(helperc_STOREV4le) ( Addr, UWord );
extern VG_REGPARM(2) void MC_(helperc_STOREV2be) ( Addr, UWord );
extern VG_REGPARM(2) void MC_(helperc_STOREV2le) ( Addr, UWord );
extern VG_REGPARM(2) void MC_(helperc_STOREV1)   ( Addr, UWord );

extern VG_REGPARM(1) ULong MC_(helperc_LOADV8be) ( Addr );
extern VG_REGPARM(1) ULong MC_(helperc_LOADV8le) ( Addr );
extern VG_REGPARM(1) UWord MC_(helperc_LOADV4be) ( Addr );
extern VG_REGPARM(1) UWord MC_(helperc_LOADV4le) ( Addr );
extern VG_REGPARM(1) UWord MC_(helperc_LOADV2be) ( Addr );
extern VG_REGPARM(1) UWord MC_(helperc_LOADV2le) ( Addr );
extern VG_REGPARM(1) UWord MC_(helperc_LOADV1)   ( Addr );

extern void MC_(helperc_MAKE_STACK_UNINIT) ( Addr base, UWord len );

/* Functions defined in mc_translate.c */
extern
IRBB* MC_(instrument) ( IRBB* bb_in, VexGuestLayout* layout, 
                        Addr64 orig_addr_noredir, VexGuestExtents* vge,
                        IRType gWordTy, IRType hWordTy );

#endif /* ndef __MC_INCLUDE_H */

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/

