
/*--------------------------------------------------------------------*/
/*--- Part of the MemCheck skin: Generate code for skin-specific   ---*/
/*--- UInstrs.                                                     ---*/
/*---                                     vg_memcheck_from_ucode.c ---*/
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

/*------------------------------------------------------------*/
/*--- Renamings of frequently-used global functions.       ---*/
/*------------------------------------------------------------*/

#define dis       VG_(disassemble)
#define nameIReg  VG_(nameOfIntReg)
#define nameISize VG_(nameOfIntSize)


/*------------------------------------------------------------*/
/*--- Instruction emission -- turning final uinstrs back   ---*/
/*--- into x86 code.                                       ---*/
/*------------------------------------------------------------*/

/* See the corresponding comment at the top of vg_from_ucode.c to find out
 * how all this works */


/* Is this a callee-save register, in the normal C calling convention?  */
#define VG_CALLEE_SAVED(reg) (reg == R_EBX || reg == R_ESI || reg == R_EDI)


/*----------------------------------------------------*/
/*--- Addressing modes                             ---*/
/*----------------------------------------------------*/

static __inline__ UChar mkModRegRM ( UChar mod, UChar reg, UChar regmem )
{
   return ((mod & 3) << 6) | ((reg & 7) << 3) | (regmem & 7);
}

static __inline__ void emit_amode_regmem_reg ( Int regmem, Int reg )
{
   /* (regmem), reg */
   if (regmem == R_ESP) 
      VG_(panic)("emit_amode_regmem_reg");
   if (regmem == R_EBP) {
      VG_(emitB) ( mkModRegRM(1, reg, 5) );
      VG_(emitB) ( 0x00 );
   } else {
      VG_(emitB)( mkModRegRM(0, reg, regmem) );
   }
}

static __inline__ void emit_amode_offregmem_reg ( Int off, Int regmem, Int reg )
{
   if (regmem == R_ESP)
      VG_(panic)("emit_amode_offregmem_reg(ESP)");
   if (off < -128 || off > 127) {
      /* Use a large offset */
      /* d32(regmem), reg */
      VG_(emitB) ( mkModRegRM(2, reg, regmem) );
      VG_(emitL) ( off );
   } else {
      /* d8(regmem), reg */
      VG_(emitB) ( mkModRegRM(1, reg, regmem) );
      VG_(emitB) ( off & 0xFF );
   }
}

static __inline__ void emit_amode_ereg_greg ( Int e_reg, Int g_reg )
{
   /* other_reg, reg */
   VG_(emitB) ( mkModRegRM(3, g_reg, e_reg) );
}

static __inline__ void emit_amode_greg_ereg ( Int g_reg, Int e_reg )
{
   /* other_reg, reg */
   VG_(emitB) ( mkModRegRM(3, g_reg, e_reg) );
}


/*----------------------------------------------------*/
/*--- Opcode translation                           ---*/
/*----------------------------------------------------*/

static __inline__ Int mkGrp1opcode ( Opcode opc )
{
   switch (opc) {
      case ADD: return 0;
      case OR:  return 1;
      case ADC: return 2;
      case SBB: return 3;
      case AND: return 4;
      case SUB: return 5;
      case XOR: return 6;
      default: VG_(panic)("mkGrp1opcode");
   }
}

static __inline__ Int mkGrp2opcode ( Opcode opc )
{
   switch (opc) {
      case ROL: return 0;
      case ROR: return 1;
      case RCL: return 2;
      case RCR: return 3;
      case SHL: return 4;
      case SHR: return 5;
      case SAR: return 7;
      default: VG_(panic)("mkGrp2opcode");
   }
}

static __inline__ Int mkGrp3opcode ( Opcode opc )
{
   switch (opc) {
      case NOT: return 2;
      case NEG: return 3;
      default: VG_(panic)("mkGrp3opcode");
   }
}

static __inline__ Int mkGrp4opcode ( Opcode opc )
{
   switch (opc) {
      case INC: return 0;
      case DEC: return 1;
      default: VG_(panic)("mkGrp4opcode");
   }
}

static __inline__ Int mkGrp5opcode ( Opcode opc )
{
   switch (opc) {
      case CALLM: return 2;
      case JMP:   return 4;
      default: VG_(panic)("mkGrp5opcode");
   }
}

static __inline__ UChar mkPrimaryOpcode ( Opcode opc )
{
   switch (opc) {
      case ADD: return 0x00;
      case ADC: return 0x10;
      case AND: return 0x20;
      case XOR: return 0x30;
      case OR:  return 0x08;
      case SBB: return 0x18;
      case SUB: return 0x28;
      default: VG_(panic)("mkPrimaryOpcode");
  }
}

/*----------------------------------------------------*/
/*--- v-size (4, or 2 with OSO) insn emitters      ---*/
/*----------------------------------------------------*/

static void emit_movv_offregmem_reg ( Int sz, Int off, Int areg, Int reg )
{
   VG_(newEmit)();
   if (sz == 2) VG_(emitB) ( 0x66 );
   VG_(emitB) ( 0x8B ); /* MOV Ev, Gv */
   emit_amode_offregmem_reg ( off, areg, reg );
   if (dis)
      VG_(printf)( "\n\t\tmov%c\t0x%x(%s), %s\n", 
                   nameISize(sz), off, nameIReg(4,areg), nameIReg(sz,reg));
}

static void emit_movv_reg_offregmem ( Int sz, Int reg, Int off, Int areg )
{
   VG_(newEmit)();
   if (sz == 2) VG_(emitB) ( 0x66 );
   VG_(emitB) ( 0x89 ); /* MOV Gv, Ev */
   emit_amode_offregmem_reg ( off, areg, reg );
   if (dis)
      VG_(printf)( "\n\t\tmov%c\t%s, 0x%x(%s)\n", 
                   nameISize(sz), nameIReg(sz,reg), off, nameIReg(4,areg));
}

static void emit_movv_reg_reg ( Int sz, Int reg1, Int reg2 )
{
   VG_(newEmit)();
   if (sz == 2) VG_(emitB) ( 0x66 );
   VG_(emitB) ( 0x89 ); /* MOV Gv, Ev */
   emit_amode_ereg_greg ( reg2, reg1 );
   if (dis)
      VG_(printf)( "\n\t\tmov%c\t%s, %s\n", 
                   nameISize(sz), nameIReg(sz,reg1), nameIReg(sz,reg2));
}

static void emit_nonshiftopv_lit_reg ( Int sz, Opcode opc, 
                                       UInt lit, Int reg )
{
   VG_(newEmit)();
   if (sz == 2) VG_(emitB) ( 0x66 );
   if (lit == VG_(extend_s_8to32)(lit & 0x000000FF)) {
      /* short form OK */
      VG_(emitB) ( 0x83 ); /* Grp1 Ib,Ev */
      emit_amode_ereg_greg ( reg, mkGrp1opcode(opc) );
      VG_(emitB) ( lit & 0x000000FF );
   } else {
      VG_(emitB) ( 0x81 ); /* Grp1 Iv,Ev */
      emit_amode_ereg_greg ( reg, mkGrp1opcode(opc) );
      if (sz == 2) VG_(emitW) ( lit ); else VG_(emitL) ( lit );
   }
   if (dis)
      VG_(printf)( "\n\t\t%s%c\t$0x%x, %s\n", 
                   VG_(nameUOpcode)(False,opc), nameISize(sz), 
                   lit, nameIReg(sz,reg));
}

static void emit_shiftopv_lit_reg ( Int sz, Opcode opc, UInt lit, Int reg )
{
   VG_(newEmit)();
   if (sz == 2) VG_(emitB) ( 0x66 );
   VG_(emitB) ( 0xC1 ); /* Grp2 Ib,Ev */
   emit_amode_ereg_greg ( reg, mkGrp2opcode(opc) );
   VG_(emitB) ( lit );
   if (dis)
      VG_(printf)( "\n\t\t%s%c\t$%d, %s\n", 
                   VG_(nameUOpcode)(False,opc), nameISize(sz), 
                   lit, nameIReg(sz,reg));
}

static void emit_nonshiftopv_reg_reg ( Int sz, Opcode opc, 
                                       Int reg1, Int reg2 )
{
   VG_(newEmit)();
   if (sz == 2) VG_(emitB) ( 0x66 );
#  if 0
   /* Perfectly correct, but the GNU assembler uses the other form.
      Therefore we too use the other form, to aid verification. */
   VG_(emitB) ( 3 + mkPrimaryOpcode(opc) ); /* op Ev, Gv */
   emit_amode_ereg_greg ( reg1, reg2 );
#  else
   VG_(emitB) ( 1 + mkPrimaryOpcode(opc) ); /* op Gv, Ev */
   emit_amode_greg_ereg ( reg1, reg2 );
#  endif
   if (dis)
      VG_(printf)( "\n\t\t%s%c\t%s, %s\n", 
                   VG_(nameUOpcode)(False,opc), nameISize(sz), 
                   nameIReg(sz,reg1), nameIReg(sz,reg2));
}

static void emit_movv_lit_reg ( Int sz, UInt lit, Int reg )
{
   if (lit == 0) {
      emit_nonshiftopv_reg_reg ( sz, XOR, reg, reg );
      return;
   }
   VG_(newEmit)();
   if (sz == 2) VG_(emitB) ( 0x66 );
   VG_(emitB) ( 0xB8+reg ); /* MOV imm, Gv */
   if (sz == 2) VG_(emitW) ( lit ); else VG_(emitL) ( lit );
   if (dis)
      VG_(printf)( "\n\t\tmov%c\t$0x%x, %s\n", 
                   nameISize(sz), lit, nameIReg(sz,reg));
}

static void emit_unaryopv_reg ( Int sz, Opcode opc, Int reg )
{
   VG_(newEmit)();
   if (sz == 2) VG_(emitB) ( 0x66 );
   switch (opc) {
      case NEG:
         VG_(emitB) ( 0xF7 );
         emit_amode_ereg_greg ( reg, mkGrp3opcode(NEG) );
         if (dis)
            VG_(printf)( "\n\t\tneg%c\t%s\n", 
                         nameISize(sz), nameIReg(sz,reg));
         break;
      case NOT:
         VG_(emitB) ( 0xF7 );
         emit_amode_ereg_greg ( reg, mkGrp3opcode(NOT) );
         if (dis)
            VG_(printf)( "\n\t\tnot%c\t%s\n", 
                         nameISize(sz), nameIReg(sz,reg));
         break;
      case DEC:
         VG_(emitB) ( 0x48 + reg );
         if (dis)
            VG_(printf)( "\n\t\tdec%c\t%s\n", 
                         nameISize(sz), nameIReg(sz,reg));
         break;
      case INC:
         VG_(emitB) ( 0x40 + reg );
         if (dis)
            VG_(printf)( "\n\t\tinc%c\t%s\n", 
                         nameISize(sz), nameIReg(sz,reg));
         break;
      default: 
         VG_(panic)("emit_unaryopv_reg");
   }
}

static void emit_pushv_reg ( Int sz, Int reg )
{
   VG_(newEmit)();
   if (sz == 2) {
      VG_(emitB) ( 0x66 ); 
   } else {
      vg_assert(sz == 4);
   }
   VG_(emitB) ( 0x50 + reg );
   if (dis)
      VG_(printf)("\n\t\tpush%c %s\n", nameISize(sz), nameIReg(sz,reg));
}

static void emit_popv_reg ( Int sz, Int reg )
{
   VG_(newEmit)();
   if (sz == 2) {
      VG_(emitB) ( 0x66 ); 
   } else {
      vg_assert(sz == 4);
   }
   VG_(emitB) ( 0x58 + reg );
   if (dis)
      VG_(printf)("\n\t\tpop%c %s\n", nameISize(sz), nameIReg(sz,reg));
}

static void emit_pushl_lit8 ( Int lit8 )
{
   vg_assert(lit8 >= -128 && lit8 < 128);
   VG_(newEmit)();
   VG_(emitB) ( 0x6A );
   VG_(emitB) ( (UChar)((UInt)lit8) );
   if (dis)
      VG_(printf)("\n\t\tpushl $%d\n", lit8 );
}

static void emit_pushl_lit32 ( UInt int32 )
{
   VG_(newEmit)();
   VG_(emitB) ( 0x68 );
   VG_(emitL) ( int32 );
   if (dis)
      VG_(printf)("\n\t\tpushl $0x%x\n", int32 );
}

static void emit_cmpl_zero_reg ( Int reg )
{
   VG_(newEmit)();
   VG_(emitB) ( 0x83 );
   emit_amode_ereg_greg ( reg, 7 /* Grp 3 opcode for CMP */ );
   VG_(emitB) ( 0x00 );
   if (dis)
      VG_(printf)("\n\t\tcmpl $0, %s\n", nameIReg(4,reg));
}

static void emit_swapl_reg_EAX ( Int reg )
{
   VG_(newEmit)();
   VG_(emitB) ( 0x90 + reg ); /* XCHG Gv,eAX */
   if (dis) 
      VG_(printf)("\n\t\txchgl %%eax, %s\n", nameIReg(4,reg));
}

static void emit_testv_lit_reg ( Int sz, UInt lit, Int reg )
{
   VG_(newEmit)();
   if (sz == 2) {
      VG_(emitB) ( 0x66 );
   } else {
      vg_assert(sz == 4);
   }
   VG_(emitB) ( 0xF7 ); /* Grp3 Ev */
   emit_amode_ereg_greg ( reg, 0 /* Grp3 subopcode for TEST */ );
   if (sz == 2) VG_(emitW) ( lit ); else VG_(emitL) ( lit );
   if (dis)
      VG_(printf)("\n\t\ttest%c $0x%x, %s\n", nameISize(sz), 
                                            lit, nameIReg(sz,reg));
}

static void emit_testv_lit_offregmem ( Int sz, UInt lit, Int off, Int reg )
{
   VG_(newEmit)();
   if (sz == 2) {
      VG_(emitB) ( 0x66 );
   } else {
      vg_assert(sz == 4);
   }
   VG_(emitB) ( 0xF7 ); /* Grp3 Ev */
   emit_amode_offregmem_reg ( off, reg, 0 /* Grp3 subopcode for TEST */ );
   if (sz == 2) VG_(emitW) ( lit ); else VG_(emitL) ( lit );
   if (dis)
      VG_(printf)("\n\t\ttest%c $%d, 0x%x(%s)\n", 
                  nameISize(sz), lit, off, nameIReg(4,reg) );
}

static void emit_movv_lit_offregmem ( Int sz, UInt lit, Int off, Int memreg )
{
   VG_(newEmit)();
   if (sz == 2) {
      VG_(emitB) ( 0x66 );
   } else {
      vg_assert(sz == 4);
   }
   VG_(emitB) ( 0xC7 ); /* Grp11 Ev */
   emit_amode_offregmem_reg ( off, memreg, 0 /* Grp11 subopcode for MOV */ );
   if (sz == 2) VG_(emitW) ( lit ); else VG_(emitL) ( lit );
   if (dis)
      VG_(printf)( "\n\t\tmov%c\t$0x%x, 0x%x(%s)\n", 
                   nameISize(sz), lit, off, nameIReg(4,memreg) );
}


/*----------------------------------------------------*/
/*--- b-size (1 byte) instruction emitters         ---*/
/*----------------------------------------------------*/

/* There is some doubt as to whether C6 (Grp 11) is in the
   486 insn set.  ToDo: investigate. */
static void emit_movb_lit_offregmem ( UInt lit, Int off, Int memreg )
{
   VG_(newEmit)();
   VG_(emitB) ( 0xC6 ); /* Grp11 Eb */
   emit_amode_offregmem_reg ( off, memreg, 0 /* Grp11 subopcode for MOV */ );
   VG_(emitB) ( lit );
   if (dis)
      VG_(printf)( "\n\t\tmovb\t$0x%x, 0x%x(%s)\n", 
                   lit, off, nameIReg(4,memreg) );
}

static void emit_movb_reg_offregmem ( Int reg, Int off, Int areg )
{
   /* Could do better when reg == %al. */
   VG_(newEmit)();
   VG_(emitB) ( 0x88 ); /* MOV G1, E1 */
   emit_amode_offregmem_reg ( off, areg, reg );
   if (dis)
      VG_(printf)( "\n\t\tmovb\t%s, 0x%x(%s)\n", 
                   nameIReg(1,reg), off, nameIReg(4,areg));
}

static void emit_unaryopb_reg ( Opcode opc, Int reg )
{
   VG_(newEmit)();
   switch (opc) {
      case INC:
         VG_(emitB) ( 0xFE );
         emit_amode_ereg_greg ( reg, mkGrp4opcode(INC) );
         if (dis)
            VG_(printf)( "\n\t\tincb\t%s\n", nameIReg(1,reg));
         break;
      case DEC:
         VG_(emitB) ( 0xFE );
         emit_amode_ereg_greg ( reg, mkGrp4opcode(DEC) );
         if (dis)
            VG_(printf)( "\n\t\tdecb\t%s\n", nameIReg(1,reg));
         break;
      case NOT:
         VG_(emitB) ( 0xF6 );
         emit_amode_ereg_greg ( reg, mkGrp3opcode(NOT) );
         if (dis)
            VG_(printf)( "\n\t\tnotb\t%s\n", nameIReg(1,reg));
         break;
      case NEG:
         VG_(emitB) ( 0xF6 );
         emit_amode_ereg_greg ( reg, mkGrp3opcode(NEG) );
         if (dis)
            VG_(printf)( "\n\t\tnegb\t%s\n", nameIReg(1,reg));
         break;
      default: 
         VG_(panic)("emit_unaryopb_reg");
   }
}

static void emit_testb_lit_reg ( UInt lit, Int reg )
{
   VG_(newEmit)();
   VG_(emitB) ( 0xF6 ); /* Grp3 Eb */
   emit_amode_ereg_greg ( reg, 0 /* Grp3 subopcode for TEST */ );
   VG_(emitB) ( lit );
   if (dis)
      VG_(printf)("\n\t\ttestb $0x%x, %s\n", lit, nameIReg(1,reg));
}


/*----------------------------------------------------*/
/*--- zero-extended load emitters                  ---*/
/*----------------------------------------------------*/

static void emit_movzbl_offregmem_reg ( Int off, Int regmem, Int reg )
{
   VG_(newEmit)();
   VG_(emitB) ( 0x0F ); VG_(emitB) ( 0xB6 ); /* MOVZBL */
   emit_amode_offregmem_reg ( off, regmem, reg );
   if (dis)
      VG_(printf)( "\n\t\tmovzbl\t0x%x(%s), %s\n", 
                   off, nameIReg(4,regmem), nameIReg(4,reg));
}

static void emit_movzwl_offregmem_reg ( Int off, Int areg, Int reg )
{
   VG_(newEmit)();
   VG_(emitB) ( 0x0F ); VG_(emitB) ( 0xB7 ); /* MOVZWL */
   emit_amode_offregmem_reg ( off, areg, reg );
   if (dis)
      VG_(printf)( "\n\t\tmovzwl\t0x%x(%s), %s\n",
                   off, nameIReg(4,areg), nameIReg(4,reg));
}

/*----------------------------------------------------*/
/*--- misc instruction emitters                    ---*/
/*----------------------------------------------------*/

static void emit_call_reg ( Int reg )
{
   VG_(newEmit)();
   VG_(emitB) ( 0xFF ); /* Grp5 */
   emit_amode_ereg_greg ( reg, mkGrp5opcode(CALLM) );
   if (dis)
      VG_(printf)( "\n\t\tcall\t*%s\n", nameIReg(4,reg) );
}


static void emit_add_lit_to_esp ( Int lit )
{
   if (lit < -128 || lit > 127) VG_(panic)("emit_add_lit_to_esp");
   VG_(newEmit)();
   VG_(emitB) ( 0x83 );
   VG_(emitB) ( 0xC4 );
   VG_(emitB) ( lit & 0xFF );
   if (dis)
      VG_(printf)( "\n\t\taddl $%d, %%esp\n", lit );
}


/* Emit a jump short with an 8-bit signed offset.  Note that the
   offset is that which should be added to %eip once %eip has been
   advanced over this insn.  */
static void emit_jcondshort_delta ( Condcode cond, Int delta )
{
   vg_assert(delta >= -128 && delta <= 127);
   VG_(newEmit)();
   VG_(emitB) ( 0x70 + (UInt)cond );
   VG_(emitB) ( (UChar)delta );
   if (dis)
      VG_(printf)( "\n\t\tj%s-8\t%%eip+%d\n", 
                   VG_(nameCondcode)(cond), delta );
}

static void emit_pushal ( void )
{
   VG_(newEmit)();
   VG_(emitB) ( 0x60 ); /* PUSHAL */
   if (dis)
      VG_(printf)("\n\t\tpushal\n");
}

static void emit_popal ( void )
{
   VG_(newEmit)();
   VG_(emitB) ( 0x61 ); /* POPAL */
   if (dis)
      VG_(printf)("\n\t\tpopal\n");
}

static void emit_AMD_prefetch_reg ( Int reg )
{
   VG_(newEmit)();
   VG_(emitB) ( 0x0F );
   VG_(emitB) ( 0x0D );
   emit_amode_regmem_reg ( reg, 1 /* 0 is prefetch; 1 is prefetchw */ );
   if (dis)
      VG_(printf)("\n\t\tamd-prefetch (%s)\n", nameIReg(4,reg) );
}

/*----------------------------------------------------*/
/*--- Instruction synthesisers                     ---*/
/*----------------------------------------------------*/

/* Synthesise a minimal test (and which discards result) of reg32
   against lit.  It's always safe do simply
      emit_testv_lit_reg ( 4, lit, reg32 )
   but we try to do better when possible.
*/
static void synth_minimal_test_lit_reg ( UInt lit, Int reg32 )
{
   if ((lit & 0xFFFFFF00) == 0 && reg32 < 4) {
      /* We can get away with a byte insn. */
      emit_testb_lit_reg ( lit, reg32 );
   }
   else 
   if ((lit & 0xFFFF0000) == 0) {
      /* Literal fits in 16 bits; do a word insn. */
      emit_testv_lit_reg ( 2, lit, reg32 );
   }
   else {
      /* Totally general ... */
      emit_testv_lit_reg ( 4, lit, reg32 );
   }
}


/*----------------------------------------------------*/
/*--- Top level of the uinstr -> x86 translation.  ---*/
/*----------------------------------------------------*/

/* Return the byte offset from %ebp (ie, into baseBlock)
   for the specified ArchReg or SpillNo. */

static Int shadowOffset ( Int arch )
{
   switch (arch) {
      case R_EAX: return 4 * VGOFF_(sh_eax);
      case R_ECX: return 4 * VGOFF_(sh_ecx);
      case R_EDX: return 4 * VGOFF_(sh_edx);
      case R_EBX: return 4 * VGOFF_(sh_ebx);
      case R_ESP: return 4 * VGOFF_(sh_esp);
      case R_EBP: return 4 * VGOFF_(sh_ebp);
      case R_ESI: return 4 * VGOFF_(sh_esi);
      case R_EDI: return 4 * VGOFF_(sh_edi);
      default:    VG_(panic)( "shadowOffset");
   }
}


static Int shadowFlagsOffset ( void )
{
   return 4 * VGOFF_(sh_eflags);
}


static void synth_LOADV ( Int sz, Int a_reg, Int tv_reg )
{
   Int i, j, helper_offw;
   Int pushed[VG_MAX_REALREGS+2];
   Int n_pushed;
   switch (sz) {
      case 4: helper_offw =
                 VG_(helper_offset)((Addr) & SK_(helperc_LOADV4));
              break;
      case 2: helper_offw =
                 VG_(helper_offset)((Addr) & SK_(helperc_LOADV2));
              break;
      case 1: helper_offw =
                 VG_(helper_offset)((Addr) & SK_(helperc_LOADV1));
              break;
      default: VG_(panic)("synth_LOADV");
   }
   n_pushed = 0;
   for (i = 0; i < VG_MAX_REALREGS; i++) {
      j = VG_(rankToRealRegNo) ( i );
      if (VG_CALLEE_SAVED(j)) continue;
      if (j == tv_reg || j == a_reg) continue;
      emit_pushv_reg ( 4, j );
      pushed[n_pushed++] = j;
   }
   emit_pushv_reg ( 4, a_reg );
   pushed[n_pushed++] = a_reg;
   vg_assert(n_pushed <= VG_MAX_REALREGS+1);

   VG_(synth_call_baseBlock_method) ( False, helper_offw );
   /* Result is in %eax; we need to get it to tv_reg. */
   if (tv_reg != R_EAX)
      emit_movv_reg_reg ( 4, R_EAX, tv_reg );

   while (n_pushed > 0) {
      n_pushed--;
      if (pushed[n_pushed] == tv_reg) {
         emit_add_lit_to_esp ( 4 );
      } else {
         emit_popv_reg ( 4, pushed[n_pushed] );
      }
   }
}


static void synth_STOREV ( Int sz,
                           Int tv_tag, Int tv_val,
                           Int a_reg )
{
   Int i, j, helper_offw;
   vg_assert(tv_tag == RealReg || tv_tag == Literal);
   switch (sz) {
      case 4: helper_offw =
                 VG_(helper_offset)((Addr) & SK_(helperc_STOREV4));
              break;
      case 2: helper_offw =
                 VG_(helper_offset)((Addr) & SK_(helperc_STOREV2));
              break;
      case 1: helper_offw =
                 VG_(helper_offset)((Addr) & SK_(helperc_STOREV1));
              break;
      default: VG_(panic)("synth_STOREV");
   }
   for (i = 0; i < VG_MAX_REALREGS; i++) {
      j = VG_(rankToRealRegNo) ( i );
      if (VG_CALLEE_SAVED(j)) continue;
      if ((tv_tag == RealReg && j == tv_val) || j == a_reg) continue;
      emit_pushv_reg ( 4, j );
   }
   if (tv_tag == RealReg) {
      emit_pushv_reg ( 4, tv_val );
   } else {
     if (tv_val == VG_(extend_s_8to32)(tv_val))
        emit_pushl_lit8 ( VG_(extend_s_8to32)(tv_val) );
     else
        emit_pushl_lit32(tv_val);
   }
   emit_pushv_reg ( 4, a_reg );
   VG_(synth_call_baseBlock_method) ( False, helper_offw );
   emit_popv_reg ( 4, a_reg );
   if (tv_tag == RealReg) {
      emit_popv_reg ( 4, tv_val );
   } else {
      emit_add_lit_to_esp ( 4 );
   }
   for (i = VG_MAX_REALREGS-1; i >= 0; i--) {
      j = VG_(rankToRealRegNo) ( i );
      if (VG_CALLEE_SAVED(j)) continue;
      if ((tv_tag == RealReg && j == tv_val) || j == a_reg) continue;
      emit_popv_reg ( 4, j );
   }
}


static void synth_SETV ( Int sz, Int reg )
{
   UInt val;
   switch (sz) {
      case 4: val = 0x00000000; break;
      case 2: val = 0xFFFF0000; break;
      case 1: val = 0xFFFFFF00; break;
      case 0: val = 0xFFFFFFFE; break;
      default: VG_(panic)("synth_SETV");
   }
   emit_movv_lit_reg ( 4, val, reg );
}


static void synth_TESTV ( Int sz, Int tag, Int val )
{
   vg_assert(tag == ArchReg || tag == RealReg);
   if (tag == ArchReg) {
      switch (sz) {
         case 4: 
            emit_testv_lit_offregmem ( 
               4, 0xFFFFFFFF, shadowOffset(val), R_EBP );
            break;
         case 2: 
            emit_testv_lit_offregmem ( 
               4, 0x0000FFFF, shadowOffset(val), R_EBP );
            break;
         case 1:
            if (val < 4) {
               emit_testv_lit_offregmem ( 
                  4, 0x000000FF, shadowOffset(val), R_EBP );
            } else {
               emit_testv_lit_offregmem ( 
                  4, 0x0000FF00, shadowOffset(val-4), R_EBP );
            }
            break;
         case 0: 
            /* should never happen */
         default: 
            VG_(panic)("synth_TESTV(ArchReg)");
      }
   } else {
      switch (sz) {
         case 4:
            /* Works, but holds the entire 32-bit literal, hence
               generating a 6-byte insn.  We want to know if any bits
               in the reg are set, but since this is for the full reg,
               we might as well compare it against zero, which can be
               done with a shorter insn. */
            /* synth_minimal_test_lit_reg ( 0xFFFFFFFF, val ); */
            emit_cmpl_zero_reg ( val );
            break;
         case 2:
            synth_minimal_test_lit_reg ( 0x0000FFFF, val );
            break;
         case 1:
            synth_minimal_test_lit_reg ( 0x000000FF, val );
            break;
         case 0:
            synth_minimal_test_lit_reg ( 0x00000001, val );
            break;
         default: 
            VG_(panic)("synth_TESTV(RealReg)");
      }
   }
   emit_jcondshort_delta ( CondZ, 3 );
   VG_(synth_call_baseBlock_method) (
      True, /* needed to guarantee that this insn is indeed 3 bytes long */
      ( sz==4 
      ? VG_(helper_offset)((Addr) & SK_(helper_value_check4_fail))
      : ( sz==2 
        ? VG_(helper_offset)((Addr) & SK_(helper_value_check2_fail))
        : ( sz==1 
          ? VG_(helper_offset)((Addr) & SK_(helper_value_check1_fail))
          : VG_(helper_offset)((Addr) & SK_(helper_value_check0_fail)))))
   );
}


static void synth_GETV ( Int sz, Int arch, Int reg )
{
   /* VG_(printf)("synth_GETV %d of Arch %s\n", sz, nameIReg(sz, arch)); */
   switch (sz) {
      case 4: 
         emit_movv_offregmem_reg ( 4, shadowOffset(arch), R_EBP, reg );
         break;
      case 2: 
         emit_movzwl_offregmem_reg ( shadowOffset(arch), R_EBP, reg );
         emit_nonshiftopv_lit_reg ( 4, OR, 0xFFFF0000, reg );
         break;
      case 1: 
         if (arch < 4) {
            emit_movzbl_offregmem_reg ( shadowOffset(arch), R_EBP, reg );
         } else {
            emit_movzbl_offregmem_reg ( shadowOffset(arch-4)+1, R_EBP, reg );
         }
         emit_nonshiftopv_lit_reg ( 4, OR, 0xFFFFFF00, reg );
         break;
      default: 
         VG_(panic)("synth_GETV");
   }
}


static void synth_PUTV ( Int sz, Int srcTag, UInt lit_or_reg, Int arch )
{
   if (srcTag == Literal) {
     /* PUTV with a Literal is only ever used to set the corresponding
        ArchReg to `all valid'.  Should really be a kind of SETV. */
      UInt lit = lit_or_reg;
      switch (sz) {
         case 4:
            vg_assert(lit == 0x00000000);
            emit_movv_lit_offregmem ( 4, 0x00000000, 
                                      shadowOffset(arch), R_EBP );
            break;
         case 2:
            vg_assert(lit == 0xFFFF0000);
            emit_movv_lit_offregmem ( 2, 0x0000, 
                                      shadowOffset(arch), R_EBP );
            break;
         case 1:
            vg_assert(lit == 0xFFFFFF00);
            if (arch < 4) {
               emit_movb_lit_offregmem ( 0x00, 
                                         shadowOffset(arch), R_EBP );
            } else {
               emit_movb_lit_offregmem ( 0x00, 
                                         shadowOffset(arch-4)+1, R_EBP );
            }
            break;
         default: 
            VG_(panic)("synth_PUTV(lit)");
      }

   } else {

      UInt reg;
      vg_assert(srcTag == RealReg);

      if (sz == 1 && lit_or_reg >= 4) {
         emit_swapl_reg_EAX ( lit_or_reg );
         reg = R_EAX;
      } else {
         reg = lit_or_reg;
      }

      if (sz == 1) vg_assert(reg < 4);

      switch (sz) {
         case 4:
            emit_movv_reg_offregmem ( 4, reg,
                                      shadowOffset(arch), R_EBP );
            break;
         case 2:
            emit_movv_reg_offregmem ( 2, reg,
                                      shadowOffset(arch), R_EBP );
            break;
         case 1:
            if (arch < 4) {
               emit_movb_reg_offregmem ( reg,
                                         shadowOffset(arch), R_EBP );
	    } else {
               emit_movb_reg_offregmem ( reg,
                                         shadowOffset(arch-4)+1, R_EBP );
            }
            break;
         default: 
            VG_(panic)("synth_PUTV(reg)");
      }

      if (sz == 1 && lit_or_reg >= 4) {
         emit_swapl_reg_EAX ( lit_or_reg );
      }
   }
}


static void synth_GETVF ( Int reg )
{
   emit_movv_offregmem_reg ( 4, shadowFlagsOffset(), R_EBP, reg );
   /* paranoia only; should be unnecessary ... */
   /* emit_nonshiftopv_lit_reg ( 4, OR, 0xFFFFFFFE, reg ); */
}


static void synth_PUTVF ( UInt reg )
{
   emit_movv_reg_offregmem ( 4, reg, shadowFlagsOffset(), R_EBP );
}


static void synth_TAG1_op ( VgTagOp op, Int reg )
{
   switch (op) {

      /* Scheme is
            neg<sz> %reg          -- CF = %reg==0 ? 0 : 1
            sbbl %reg, %reg       -- %reg = -CF
            or 0xFFFFFFFE, %reg   -- invalidate all bits except lowest
      */
      case VgT_PCast40:
         emit_unaryopv_reg(4, NEG, reg);
         emit_nonshiftopv_reg_reg(4, SBB, reg, reg);
         emit_nonshiftopv_lit_reg(4, OR, 0xFFFFFFFE, reg);
         break;
      case VgT_PCast20:
         emit_unaryopv_reg(2, NEG, reg);
         emit_nonshiftopv_reg_reg(4, SBB, reg, reg);
         emit_nonshiftopv_lit_reg(4, OR, 0xFFFFFFFE, reg);
         break;
      case VgT_PCast10:
         if (reg >= 4) {
            emit_swapl_reg_EAX(reg);
            emit_unaryopb_reg(NEG, R_EAX);
            emit_swapl_reg_EAX(reg);
         } else {
            emit_unaryopb_reg(NEG, reg);
         }
         emit_nonshiftopv_reg_reg(4, SBB, reg, reg);
         emit_nonshiftopv_lit_reg(4, OR, 0xFFFFFFFE, reg);
         break;

      /* Scheme is
            andl $1, %reg -- %reg is 0 or 1
            negl %reg -- %reg is 0 or 0xFFFFFFFF
            and possibly an OR to invalidate unused bits.
      */
      case VgT_PCast04:
         emit_nonshiftopv_lit_reg(4, AND, 0x00000001, reg);
         emit_unaryopv_reg(4, NEG, reg);
         break;
      case VgT_PCast02:
         emit_nonshiftopv_lit_reg(4, AND, 0x00000001, reg);
         emit_unaryopv_reg(4, NEG, reg);
         emit_nonshiftopv_lit_reg(4, OR, 0xFFFF0000, reg);
         break;
      case VgT_PCast01:
         emit_nonshiftopv_lit_reg(4, AND, 0x00000001, reg);
         emit_unaryopv_reg(4, NEG, reg);
         emit_nonshiftopv_lit_reg(4, OR, 0xFFFFFF00, reg);
         break;

      /* Scheme is
            shl $24, %reg -- make irrelevant bits disappear
            negl %reg             -- CF = %reg==0 ? 0 : 1
            sbbl %reg, %reg       -- %reg = -CF
            and possibly an OR to invalidate unused bits.
      */
      case VgT_PCast14:
         emit_shiftopv_lit_reg(4, SHL, 24, reg);
         emit_unaryopv_reg(4, NEG, reg);
         emit_nonshiftopv_reg_reg(4, SBB, reg, reg);
         break;
      case VgT_PCast12:
         emit_shiftopv_lit_reg(4, SHL, 24, reg);
         emit_unaryopv_reg(4, NEG, reg);
         emit_nonshiftopv_reg_reg(4, SBB, reg, reg);
         emit_nonshiftopv_lit_reg(4, OR, 0xFFFF0000, reg);
         break;
      case VgT_PCast11:
         emit_shiftopv_lit_reg(4, SHL, 24, reg);
         emit_unaryopv_reg(4, NEG, reg);
         emit_nonshiftopv_reg_reg(4, SBB, reg, reg);
         emit_nonshiftopv_lit_reg(4, OR, 0xFFFFFF00, reg);
         break;

      /* We steal %ebp (a non-allocable reg) as a temporary:
            pushl %ebp
            movl %reg, %ebp
            negl %ebp
            orl %ebp, %reg
            popl %ebp
         This sequence turns out to be correct regardless of the 
         operation width.
      */
      case VgT_Left4:
      case VgT_Left2:
      case VgT_Left1:
         vg_assert(reg != R_EDI);
         emit_movv_reg_reg(4, reg, R_EDI);
         emit_unaryopv_reg(4, NEG, R_EDI);
         emit_nonshiftopv_reg_reg(4, OR, R_EDI, reg);
         break;

      /* These are all fairly obvious; do the op and then, if
         necessary, invalidate unused bits. */
      case VgT_SWiden14:
         emit_shiftopv_lit_reg(4, SHL, 24, reg);
         emit_shiftopv_lit_reg(4, SAR, 24, reg);
         break;
      case VgT_SWiden24:
         emit_shiftopv_lit_reg(4, SHL, 16, reg);
         emit_shiftopv_lit_reg(4, SAR, 16, reg);
         break;
      case VgT_SWiden12:
         emit_shiftopv_lit_reg(4, SHL, 24, reg);
         emit_shiftopv_lit_reg(4, SAR, 24, reg);
         emit_nonshiftopv_lit_reg(4, OR, 0xFFFF0000, reg);
         break;
      case VgT_ZWiden14:
         emit_nonshiftopv_lit_reg(4, AND, 0x000000FF, reg);
         break;
      case VgT_ZWiden24:
         emit_nonshiftopv_lit_reg(4, AND, 0x0000FFFF, reg);
         break;
      case VgT_ZWiden12:
         emit_nonshiftopv_lit_reg(4, AND, 0x000000FF, reg);
         emit_nonshiftopv_lit_reg(4, OR, 0xFFFF0000, reg);
         break;

      default:
         VG_(panic)("synth_TAG1_op");
   }
}


static void synth_TAG2_op ( VgTagOp op, Int regs, Int regd )
{
   switch (op) {

      /* UifU is implemented by OR, since 1 means Undefined. */
      case VgT_UifU4:
      case VgT_UifU2:
      case VgT_UifU1:
      case VgT_UifU0:
         emit_nonshiftopv_reg_reg(4, OR, regs, regd);
         break;

      /* DifD is implemented by AND, since 0 means Defined. */
      case VgT_DifD4:
      case VgT_DifD2:
      case VgT_DifD1:
         emit_nonshiftopv_reg_reg(4, AND, regs, regd);
         break;

      /* ImproveAND(value, tags) = value OR tags.
	 Defined (0) value 0s give defined (0); all other -> undefined (1).
         value is in regs; tags is in regd. 
         Be paranoid and invalidate unused bits; I don't know whether 
         or not this is actually necessary. */
      case VgT_ImproveAND4_TQ:
         emit_nonshiftopv_reg_reg(4, OR, regs, regd);
         break;
      case VgT_ImproveAND2_TQ:
         emit_nonshiftopv_reg_reg(4, OR, regs, regd);
         emit_nonshiftopv_lit_reg(4, OR, 0xFFFF0000, regd);
         break;
      case VgT_ImproveAND1_TQ:
         emit_nonshiftopv_reg_reg(4, OR, regs, regd);
         emit_nonshiftopv_lit_reg(4, OR, 0xFFFFFF00, regd);
         break;

      /* ImproveOR(value, tags) = (not value) OR tags.
	 Defined (0) value 1s give defined (0); all other -> undefined (1).
         value is in regs; tags is in regd. 
         To avoid trashing value, this is implemented (re de Morgan) as
               not (value AND (not tags))
         Be paranoid and invalidate unused bits; I don't know whether 
         or not this is actually necessary. */
      case VgT_ImproveOR4_TQ:
         emit_unaryopv_reg(4, NOT, regd);
         emit_nonshiftopv_reg_reg(4, AND, regs, regd);
         emit_unaryopv_reg(4, NOT, regd);
         break;
      case VgT_ImproveOR2_TQ:
         emit_unaryopv_reg(4, NOT, regd);
         emit_nonshiftopv_reg_reg(4, AND, regs, regd);
         emit_unaryopv_reg(4, NOT, regd);
         emit_nonshiftopv_lit_reg(4, OR, 0xFFFF0000, regd);
         break;
      case VgT_ImproveOR1_TQ:
         emit_unaryopv_reg(4, NOT, regd);
         emit_nonshiftopv_reg_reg(4, AND, regs, regd);
         emit_unaryopv_reg(4, NOT, regd);
         emit_nonshiftopv_lit_reg(4, OR, 0xFFFFFF00, regd);
         break;

      default:
         VG_(panic)("synth_TAG2_op");
   }
}

static void synth_fpu_mem_check_actions ( Bool isWrite, 
                                          Int size, Int a_reg )
{
   Int helper_offw
     = isWrite ? VG_(helper_offset)( (Addr) & SK_(fpu_write_check))
               : VG_(helper_offset)( (Addr) & SK_(fpu_read_check));
   emit_pushal();
   emit_pushl_lit8 ( size );
   emit_pushv_reg ( 4, a_reg );
   VG_(synth_call_baseBlock_method) ( False, helper_offw );
   emit_add_lit_to_esp ( 8 );   
   emit_popal();
}


/*----------------------------------------------------*/
/*--- Generate code for a single UInstr.           ---*/
/*----------------------------------------------------*/

void SKN_(augmentUInstr) ( UInstr* u )
{
   switch (u->opcode) {

   /* This FPU MemCheck test is simple enough that we don't bother with a 
      separate UInstr for it;  the core emits the code to actually execute
      the operation. 

      We assume that writes to memory done by FPU_Ws are not going
      to be used to create new code, so there's no orig-code-write
      checks done by default. */
   case FPU_R: 
   case FPU_W:
      synth_fpu_mem_check_actions ( u->opcode==FPU_W, u->size, u->val2 );
      break;

   default:
      break;
   }
}

void SKN_(emitExtUInstr) ( UInstr* u )
{
   switch (u->opcode) {

      case SETV: {
         vg_assert(u->tag1 == RealReg);
         synth_SETV ( u->size, u->val1 );
         break;
      }

      case STOREV: {
         vg_assert(u->tag1 == RealReg || u->tag1 == Literal);
         vg_assert(u->tag2 == RealReg);
         synth_STOREV ( u->size, u->tag1, 
                                 u->tag1==Literal ? u->lit32 : u->val1, 
                                 u->val2 );
         break;
      }

      case LOADV: {
         vg_assert(u->tag1 == RealReg);
         vg_assert(u->tag2 == RealReg);
         if (0)
            emit_AMD_prefetch_reg ( u->val1 );
         synth_LOADV ( u->size, u->val1, u->val2 );
         break;
      }

      case TESTV: {
         vg_assert(u->tag1 == RealReg || u->tag1 == ArchReg);
         synth_TESTV(u->size, u->tag1, u->val1);
         break;
      }

      case GETV: {
         vg_assert(u->tag1 == ArchReg);
         vg_assert(u->tag2 == RealReg);
         synth_GETV(u->size, u->val1, u->val2);
         break;
      }

      case GETVF: {
         vg_assert(u->tag1 == RealReg);
         vg_assert(u->size == 0);
         synth_GETVF(u->val1);
         break;
      }

      case PUTV: {
         vg_assert(u->tag1 == RealReg || u->tag1 == Literal);
         vg_assert(u->tag2 == ArchReg);
         synth_PUTV(u->size, u->tag1, 
                             u->tag1==Literal ? u->lit32 : u->val1, 
                             u->val2 );
         break;
      }

      case PUTVF: {
         vg_assert(u->tag1 == RealReg);
         vg_assert(u->size == 0);
         synth_PUTVF(u->val1);
         break;
      }

      case TAG1:
         synth_TAG1_op ( u->val3, u->val1 );
         break;

      case TAG2:
         if (u->val3 != VgT_DebugFn) {
            synth_TAG2_op ( u->val3, u->val1, u->val2 );
         } else {
            /* Assume a call to VgT_DebugFn passing both args
               and placing the result back in the second. */
            Int j, k;
            /* u->val2 is the reg into which the result is written.  So
               don't save/restore it.  And it can be used at a temp for
               the call target, too.  Since %eax is used for the return
               value from the C procedure, it is preserved only by
               virtue of not being mentioned as a VG_CALLEE_SAVED reg. */
            for (k = 0; k < VG_MAX_REALREGS; k++) {
               j = VG_(rankToRealRegNo) ( k );
               if (VG_CALLEE_SAVED(j)) continue;
               if (j == u->val2) continue;
               emit_pushv_reg ( 4, j );
            }
            emit_pushv_reg(4, u->val2);
            emit_pushv_reg(4, u->val1);
            emit_movv_lit_reg ( 4, (UInt)(&VG_(DebugFn)), u->val2 );
            emit_call_reg ( u->val2 );
            if (u->val2 != R_EAX)
               emit_movv_reg_reg ( 4, R_EAX, u->val2 );
            /* nuke args */
            emit_add_lit_to_esp(8);
            for (k = VG_MAX_REALREGS-1; k >= 0; k--) {
               j = VG_(rankToRealRegNo) ( k );
               if (VG_CALLEE_SAVED(j)) continue;
               if (j == u->val2) continue;
               emit_popv_reg ( 4, j );
            }
         }
         break;

      default: 
         VG_(printf)("emitExtUInstr: unhandled extension insn:\n");
         VG_(ppUInstr)(0,u);
         VG_(panic)("emitExtUInstr: unhandled extension opcode");
   }

}

/*--------------------------------------------------------------------*/
/*--- end                                 vg_memcheck_from_ucode.c ---*/
/*--------------------------------------------------------------------*/
