/*--------------------------------------------------------------------*/
/*--- Functions to make writing instrumentation routines easier.   ---*/
/*---                                              vg_instrument.c ---*/
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

#include "vg_include.h"

#define uInstr0   VG_(newUInstr0)
#define uInstr1   VG_(newUInstr1)
#define uInstr2   VG_(newUInstr2)
#define uLiteral  VG_(setLiteralField)
#define newTemp   VG_(getNewTemp)


// SSS: would these be better as macros?  No extra code, no need to pass in
// cb (assuming cb was the name used by the programmer)
void VG_(callHelper_0_0)(UCodeBlock* cb, Addr f)
{
   uInstr0(cb, CCALL_0_0, 0);
   uLiteral(cb, f);
}

void VG_(callHelper_1_0)(UCodeBlock* cb, Addr f, UInt arg1)
{
   UInt t1 = newTemp(cb);

   uInstr2(cb, MOV,   4, Literal, 0, TempReg, t1);
   uLiteral(cb, arg1);
   uInstr1(cb, CCALL_1_0, 0, TempReg, t1);
   uLiteral(cb, f);
}

void VG_(callHelper_2_0)(UCodeBlock* cb, Addr f, UInt arg1, UInt arg2)
{
   UInt t1 = newTemp(cb);
   UInt t2 = newTemp(cb);

   uInstr2(cb, MOV,   4, Literal, 0, TempReg, t1);
   uLiteral(cb, arg1);
   uInstr2(cb, MOV,   4, Literal, 0, TempReg, t2);
   uLiteral(cb, arg2);
   uInstr2(cb, CCALL_2_0, 0, TempReg, t1, TempReg, t2);
   uLiteral(cb, f);
}

/*--------------------------------------------------------------------*/
/*--- end                                          vg_instrument.c ---*/
/*--------------------------------------------------------------------*/

