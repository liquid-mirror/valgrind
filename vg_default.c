/*--------------------------------------------------------------------*/
/*--- Default panicky definitions of template functions that skins ---*/
/*--- should override.                                             ---*/
/*---                                                vg_defaults.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, an x86 protected-mode emulator 
   designed for debugging and profiling binaries on x86-Unixes.

   Copyright (C) 2000-2002 Nicholas Nethercote
      njn25@cam.ac.uk

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


/* These functions aren't intended to be run.  Replacement functions used by
 * the chosen skin are substituted by compiling the skin into a .so and
 * LD_PRELOADing it.  Nasty :) */

#include "vg_include.h"

/* ---------------------------------------------------------------------
   Error messages (for malformed skins)
   ------------------------------------------------------------------ */

/* If the skin fails to define one or more of the required functions,
 * make it very clear what went wrong! */

static char* fund_panic =
    "\nSkin error:\n"
    "  The skin you have selected is missing one or more of the\n"
    "  required fundamental functions.  Please check it and try again.\n";

static char* nonfund_panic =
    "\nSkin error:\n"
    "  The skin you have selected is missing one or more of the\n"
    "  functions required by the skin's needs.  Please check it and\n"
    "  try again.\n";

/* ---------------------------------------------------------------------
   Fundamental template functions
   ------------------------------------------------------------------ */

void SK_(pre_clo_init)(VgNeeds* needs, VgTrackEvents* track)
{
   VG_(printf)(fund_panic);
   VG_(panic)("called SK_(pre_clo_init)");
}

void SK_(post_clo_init)(void)
{
   VG_(printf)(fund_panic);
   VG_(panic)("called SK_(post_clo_init)");
}

UCodeBlock* SK_(instrument)(UCodeBlock* cb, Addr not_used)
{
   VG_(printf)(fund_panic);
   VG_(panic)("called SK_(instrument)");
}

void SK_(fini)(void)
{
   VG_(printf)(fund_panic);
   VG_(panic)("called SK_(fini)");
}

/* ---------------------------------------------------------------------
   For error reporting and suppression handling
   ------------------------------------------------------------------ */

Bool SKN_(eq_SkinError)(VgRes res, SkinError* e1, SkinError* e2)
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("called SKN_(eq_SkinError)");
}

void SKN_(pp_SkinError)(SkinError* ec, void (*pp_ExeContext)(void))
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("called SKN_(pp_SkinError)");
}

void SKN_(dup_extra_and_update)(SkinError* ec)
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("called SKN_(dup_extra_and_update)");
}

Bool SKN_(recognised_suppression)(Char* name, SuppKind* skind)
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("called SKN_(recognised_suppression)");
}

Bool SKN_(read_extra_suppression_info)(Int fd, Char* buf, 
                                       Int nBuf, SkinSupp *s)
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("called SKN_(read_extra_suppression_info)");
}

Bool SKN_(error_matches_suppression)(SkinError* ec, SkinSupp* su)
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("called SKN_(error_matches_suppression)");
}


/* ---------------------------------------------------------------------
   For throwing out basic block level info when code is invalidated
   ------------------------------------------------------------------ */

void SKN_(discard_basic_block_info)(Addr a, UInt size)
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("called SKN_(discard_basic_block_info)");
}


/* ---------------------------------------------------------------------
   For throwing out basic block level info when code is invalidated
   ------------------------------------------------------------------ */

void SKN_(written_shadow_regs_values)(UInt* gen_reg, UInt* eflags)
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("called SKN_(written_shadow_regs_values)");
}


/* ---------------------------------------------------------------------
   Command line arg template function
   ------------------------------------------------------------------ */

Bool SKN_(process_cmd_line_option)(UChar* argv)
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("called SKN_(process_cmd_line_option)");
}

Char* SKN_(usage)(void)
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("called SKN_(usage)");
}

/* ---------------------------------------------------------------------
   Client request template function
   ------------------------------------------------------------------ */

UInt SKN_(handle_client_request)(ThreadState* tst, UInt* arg_block)
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("called SKN_(handle_client_request)");
}

/* ---------------------------------------------------------------------
   UCode extension
   ------------------------------------------------------------------ */

void SKN_(emitExtUInstr)(UInstr* u)
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("called SKN_(emitExtUInstr)");
}

Bool SKN_(saneExtUInstr)(Bool beforeRA, Bool beforeLiveness, UInstr* u)
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("called SKN_(saneExtUInstr)");
}

Char* SKN_(nameExtUOpcode)(Opcode opc)
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("called SKN_(nameExtUOpcode)");
}

void SKN_(ppExtUInstr)(UInstr* u)
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("called SKN_(ppExtUInstr)");
}

Int SKN_(getExtRegUsage)(UInstr* u, Tag tag, RegUse* arr)
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("called SKN_(getExtTempUsage)");
}

/* ---------------------------------------------------------------------
   Syscall wrapping
   ------------------------------------------------------------------ */

void* SKN_(pre_syscall)(ThreadId tid)
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("called SKN_(pre_syscall)");
}

void  SKN_(post_syscall)(ThreadId tid, UInt syscallno,
                         void* pre_result, Int res)
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("called SKN_(post_syscall)");
}

void* SKN_(pre_check_known_blocking_syscall)  
          (ThreadId tid, Int syscallno, Int* res)
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("called SKN_(pre_check_known_blocking_syscall)");
}

void  SKN_(post_check_known_blocking_syscall) 
          (ThreadId tid, Int syscallno, void* pre_result, Int* res)
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("called SKN_(post_check_known_blocking_syscall)");
}

/* ---------------------------------------------------------------------
   Shadow chunks
   ------------------------------------------------------------------ */

void SKN_(complete_shadow_chunk)( ShadowChunk* sc, ThreadState* tst )
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("SKN_(complete_shadow_chunk)");
}

/* ---------------------------------------------------------------------
   Alternative free()
   ------------------------------------------------------------------ */

void SKN_(alt_free) ( ShadowChunk* sc, ThreadState* tst )
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("SKN_(alt_free)");
}

/* ---------------------------------------------------------------------
   Sanity checks
   ------------------------------------------------------------------ */

Bool SKN_(cheap_sanity_check)(void)
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("SKN_(cheap_sanity_check)");
}

Bool SKN_(expensive_sanity_check)(void)
{
   VG_(printf)(nonfund_panic);
   VG_(panic)("SKN_(expensive_sanity_check)");
}

/*--------------------------------------------------------------------*/
/*--- end                                            vg_defaults.c ---*/
/*--------------------------------------------------------------------*/
