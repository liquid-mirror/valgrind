/*--------------------------------------------------------------------*/
/*--- A header file for all parts of the MemCheck skin.            ---*/
/*---                                        vg_memcheck_include.h ---*/
/*--------------------------------------------------------------------*/

#ifndef __VG_MEMCHECK_INCLUDE_H
#define __VG_MEMCHECK_INCLUDE_H


#include "vg_skin.h"

/* UCode extension for efficient memory checking operations */
typedef
   enum {
      /* uinstrs which are not needed for mere translation of x86 code,
         only for instrumentation of it. */
      LOADV = DUMMY_FINAL_UOPCODE + 1,
      STOREV,
      GETV,
      PUTV,
      TESTV,
      SETV, 
      /* Get/set the v-bit (and it is only one bit) for the simulated
         %eflags register. */
      GETVF,
      PUTVF,

      /* Do a unary or binary tag op.  Only for post-instrumented
         code.  For TAG1, first and only arg is a TempReg, and is both
         arg and result reg.  For TAG2, first arg is src, second is
         dst, in the normal way; both are TempRegs.  In both cases,
         3rd arg is a RiCHelper with a Lit16 tag.  This indicates
         which tag op to do. */
      TAG1,
      TAG2
   }
   MemCheckOpcode;


/* Lists the names of value-tag operations used in instrumented
   code.  These are the third argument to TAG1 and TAG2 uinsns. */
typedef
   enum { 
     /* Unary. */
     VgT_PCast40, VgT_PCast20, VgT_PCast10,
     VgT_PCast01, VgT_PCast02, VgT_PCast04,

     VgT_PCast14, VgT_PCast12, VgT_PCast11,

     VgT_Left4, VgT_Left2, VgT_Left1,

     VgT_SWiden14, VgT_SWiden24, VgT_SWiden12,
     VgT_ZWiden14, VgT_ZWiden24, VgT_ZWiden12,

     /* Binary; 1st is rd; 2nd is rd+wr */
     VgT_UifU4, VgT_UifU2, VgT_UifU1, VgT_UifU0,
     VgT_DifD4, VgT_DifD2, VgT_DifD1,

     VgT_ImproveAND4_TQ, VgT_ImproveAND2_TQ, VgT_ImproveAND1_TQ,
     VgT_ImproveOR4_TQ, VgT_ImproveOR2_TQ, VgT_ImproveOR1_TQ,
     VgT_DebugFn
   }
   VgTagOp;

/* The classification of a faulting address. */
typedef 
   enum { Undescribed, /* as-yet unclassified */
          Stack, 
          Unknown, /* classification yielded nothing useful */
          Freed, Mallocd, 
          UserG, UserS }
   AddrKind;

/* Records info about a faulting address. */
typedef
   struct {
      /* ALL */
      AddrKind akind;
      /* Freed, Mallocd */
      Int blksize;
      /* Freed, Mallocd */
      Int rwoffset;
      /* Freed, Mallocd */
      ExeContext* lastchange;
      /* Stack */
      ThreadId stack_tid;
      /* True if is just-below %esp -- could be a gcc bug. */
      Bool maybe_gcc;
   }
   AddrInfo;


/*------------------------------------------------------------*/
/*--- Skin-specific command line options + defaults        ---*/
/*------------------------------------------------------------*/

/* Allow loads from partially-valid addresses?  default: YES */
Bool VG_(clo_partial_loads_ok);

/* Do leak check at exit?  default: NO */
Bool VG_(clo_leak_check);

/* How closely should we compare ExeContexts in leak records? default: 2 */
Int  VG_(clo_leak_resolution);

/* In leak check, show reachable-but-not-freed blocks?  default: NO */
Bool VG_(clo_show_reachable);

/* Assume accesses immediately below %esp are due to gcc-2.96 bugs.
 * default: NO*/
Bool VG_(clo_workaround_gcc296_bugs);

/* Shall we V-check addrs? (they are always A checked too)   default: YES */
Bool VG_(clo_check_addrVs);

/* DEBUG: clean up instrumented code?  default: YES */
Bool VG_(clo_cleanup);

/*------------------------------------------------------------*/
/*--- Functions                                            ---*/
/*------------------------------------------------------------*/

// SSS: work out a consistent prefix convention here

/* Functions defined in vg_memcheck_helpers.S */
extern void SK_(helper_value_check4_fail) ( void );
extern void SK_(helper_value_check2_fail) ( void );
extern void SK_(helper_value_check1_fail) ( void );
extern void SK_(helper_value_check0_fail) ( void );

/* Functions defined in vg_memcheck.c */
extern void SK_(helperc_STOREV4) ( UInt, Addr );
extern void SK_(helperc_STOREV2) ( UInt, Addr );
extern void SK_(helperc_STOREV1) ( UInt, Addr );
   
extern UInt SK_(helperc_LOADV1) ( Addr );
extern UInt SK_(helperc_LOADV2) ( Addr );
extern UInt SK_(helperc_LOADV4) ( Addr );

extern void SK_(fpu_write_check) ( Addr addr, Int size );
extern void SK_(fpu_read_check)  ( Addr addr, Int size );

/* For client requests */
extern void VG_(make_noaccess) ( Addr a, UInt len );
extern void VG_(make_readable) ( Addr a, UInt len );
extern void VG_(make_writable) ( Addr a, UInt len );

extern Bool VG_(check_writable) ( Addr a, UInt len, Addr* bad_addr );
extern Bool VG_(check_readable) ( Addr a, UInt len, Addr* bad_addr );

extern void VG_(detect_memory_leaks) ( void );


/* Functions defined in vg_memcheck_clientreqs.c */
extern Bool SK_(client_perm_maybe_describe)( Addr a, AddrInfo* ai );
extern void SK_(delete_client_stack_blocks_following_ESP_change) ( void );
extern void SK_(show_client_block_stats) ( void );

/* Functions defined in vg_memcheck_errcontext.c */
extern void SK_(record_value_error)       ( Int size );
extern void SK_(record_address_error)     ( Addr a, Int size, Bool isWrite );
extern void SK_(record_core_mem_error)    ( ThreadState* tst, Bool isWrite,
                                            Char* s );
extern void SK_(record_param_error)       ( ThreadState* tst, Addr a,   
                                            Bool isWriteLack, Char* msg );
extern void SK_(record_jump_error)        ( ThreadState* tst, Addr a );
extern void SK_(record_free_error)        ( ThreadState* tst, Addr a );
extern void SK_(record_freemismatch_error)( ThreadState* tst, Addr a );
extern void SK_(record_user_error)        ( ThreadState* tst, Addr a, 
                                            Bool isWrite );

#endif

/*--------------------------------------------------------------------*/
/*--- end                                    vg_memcheck_include.h ---*/
/*--------------------------------------------------------------------*/

