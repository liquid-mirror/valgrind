
/*--------------------------------------------------------------------*/
/*--- A header file for instrumentation help.                      ---*/
/*---                                              vg_instrument.h ---*/
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

extern void VG_(callHelper_0_0)(UCodeBlock* cb, Addr f);
extern void VG_(callHelper_1_0)(UCodeBlock* cb, Addr f, UInt arg1);
extern void VG_(callHelper_2_0)(UCodeBlock* cb, Addr f, UInt arg1, UInt arg2);

/*--------------------------------------------------------------------*/
/*--- end                                          vg_instrument.h ---*/
/*--------------------------------------------------------------------*/

