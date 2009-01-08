
/*--------------------------------------------------------------------*/
/*--- gdb remote debugging                    pub_tool_debugstub.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2007 Apple Inc.
      Greg Parker  gparker@apple.com

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

#ifndef __PUB_TOOL_DEBUGSTUB_H
#define __PUB_TOOL_DEBUGSTUB_H

// Send a reply packet to the gdb remote debugger.
// Use this inside your handlers for VG_(needs_debugger_commands).
extern void VG_(debugstub_write_reply)(Int sock, const Char* contents);

// Encode binary data in gdb's hex format, with nul terminator. 
// len is the number of bytes in SRC; dst must be 2*len+1 bytes.
extern void VG_(debugstub_tohex)(Char *dst, const void *src, Int len);

// Decode binary data from gdb's hex format. 
// len is the number of bytes in DST; src must be 2*len bytes.
extern void VG_(debugstub_fromhex)(void *dst, const Char *src, Int len);

// Retrieve register contents (from the "current thread" as designated 
// by the remote debugger). Stores the register or vex_shadowN value in 
// *rbuf, and returns the number of bytes written.
extern Int VG_(reg_for_regnum)(Int regnum, void *rbuf, Int shadow);

#endif

