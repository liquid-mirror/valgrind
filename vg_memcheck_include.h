/*--------------------------------------------------------------------*/
/*--- A header file for all parts of the MemCheck skin.            ---*/
/*---                                        vg_memcheck_include.h ---*/
/*--------------------------------------------------------------------*/

// UCode extension for efficient memory checking operations
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
   ExtOpcode;

extern Addr SK_(curr_dataseg_end);

// Functions defined in vg_memcheck_helpers.S
extern void SK_(helper_value_check4_fail) ( void );
extern void SK_(helper_value_check2_fail) ( void );
extern void SK_(helper_value_check1_fail) ( void );
extern void SK_(helper_value_check0_fail) ( void );

// Functions defined in vg_memcheck.c
extern void SK_(helperc_STOREV4) ( UInt, Addr );
extern void SK_(helperc_STOREV2) ( UInt, Addr );
extern void SK_(helperc_STOREV1) ( UInt, Addr );
   
extern UInt SK_(helperc_LOADV1) ( Addr );
extern UInt SK_(helperc_LOADV2) ( Addr );
extern UInt SK_(helperc_LOADV4) ( Addr );

extern void SK_(fpu_write_check) ( Addr addr, Int size );
extern void SK_(fpu_read_check)  ( Addr addr, Int size );

// Functions defined in vg_memcheck_errcontext.c
extern void VG_(record_value_error)   ( Int size );
extern void VG_(record_address_error) ( Addr a, Int size, Bool isWrite );


/*--------------------------------------------------------------------*/
/*--- end                                    vg_memcheck_include.h ---*/
/*--------------------------------------------------------------------*/

