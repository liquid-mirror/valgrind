/*--------------------------------------------------------------------*/
/*--- Simple skin for counting UInstrs, using a C helper.          ---*/
/*---                                                  vg_lackey.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, an x86 protected-mode emulator 
   designed for debugging and profiling binaries on x86-Unixes.

   Copyright (C) 2002 Nicholas Nethercote
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

#include "vg_include.h"
#include "vg_instrument.h"

//#define uInstr0   VG_(newUInstr0)
//#define uLiteral  VG_(setLiteralField)

/* Note: could overflow fairly easily */
static UInt n_uinstrs = 0;

static void add_one(void)
{
   n_uinstrs++;
}

void SK_(setup)(VgNeeds* needs)
{
   needs->name                    = "lackey";
   needs->description             = "a UInstr counter";
   needs->debug_info              = Vg_DebugNone;
   needs->precise_x86_instr_sizes = False;
   needs->pthread_errors          = False;
   needs->report_errors           = False;

   needs->identifies_basic_blocks = False;

   needs->command_line_options    = False;
   needs->client_requests         = False;

   needs->augments_UInstrs        = False;
   needs->extends_UCode           = False;

   needs->wrap_syscalls           = False;

   needs->sanity_checks           = False;

   needs->shadow_memory           = False;
   needs->track_threads           = False;

   VG_(register_compact_helper)((Addr) & add_one);

   // SSS: temporary
   VG_(clo_skin) = Vg_Other;
}

void SK_(init)(void)
{
}

static UCodeBlock* lackey_instrument(UCodeBlock* cb_in)
{
   UCodeBlock* cb;
   Int         i;
   UInstr*     u_in;

   cb = VG_(allocCodeBlock)();
   cb->nextTemp = cb_in->nextTemp;

   for (i = 0; i < cb_in->used; i++) {
      u_in = &cb_in->instrs[i];

      switch (u_in->opcode) {
         case NOP: case CALLM_S: case CALLM_E:
            break;
   
         default:
            //uInstr0(cb, CCALL_0_0, 0);
            //uLiteral(cb, (Addr) & add_one);
            VG_(callHelper_0_0)(cb, (Addr) & add_one);
            VG_(copyUInstr)(cb, u_in);
            break;
      }
   }

   VG_(freeCodeBlock)(cb_in);
   return cb;
}

UCodeBlock* SK_(instrument) ( UCodeBlock* cb, Addr not_used )
{
   /* VGP_PUSHCC(VgpInstrument); */
   cb = lackey_instrument(cb);
   /* VGP_POPCC; */
   if (VG_(disassemble)) 
      VG_(ppUCodeBlock) ( cb, "Lackey instrumented code:" );
   return cb;
}

void SK_(fini)(void)
{
    VG_(printf)("UInstrs counted: %u\n", n_uinstrs);
}

/*--------------------------------------------------------------------*/
/*--- end                                              vg_lackey.c ---*/
/*--------------------------------------------------------------------*/

