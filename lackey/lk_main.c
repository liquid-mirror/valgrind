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

   The GNU General Public License is contained in the file COPYING.
*/

#include "vg_skin.h"

//#define uInstr0   VG_(newUInstr0)
//#define uLiteral  VG_(setLiteralField)

/* Note: could overflow fairly easily */
static UInt n_uinstrs = 0;

static void add_one(void)
{
   n_uinstrs++;
}

void SK_(pre_clo_init)(VgNeeds* needs, VgTrackEvents* not_used)
{
   needs->name                    = "lackey";
   needs->description             = "a UInstr counter";

   VG_(register_compact_helper)((Addr) & add_one);
}

void SK_(post_clo_init)(void)
{
}

UCodeBlock* SK_(instrument)(UCodeBlock* cb_in, Addr not_used)
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

void SK_(fini)(void)
{
    VG_(message)(Vg_UserMsg, "UInstrs counted: %u", n_uinstrs);
}

/*--------------------------------------------------------------------*/
/*--- end                                              vg_lackey.c ---*/
/*--------------------------------------------------------------------*/

