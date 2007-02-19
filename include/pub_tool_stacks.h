
/*--------------------------------------------------------------------*/
/*--- Stack management.                          pub_tool_stacks.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2007-2007 Nicholas Nethercote
      njn@valgrind.org

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

#ifndef __PUB_TOOL_STACKS_H
#define __PUB_TOOL_STACKS_H

// This is useful for tools doing their own SP-update handling, rather than
// using the new_mem_stack/die_mem_stack events.  It can be called at
// run-time when the SP changes to determine if we've switched to another
// stack.
extern Bool VG_(check_if_stack_has_changed)(Addr old_SP, Addr new_SP);

#endif   // __PUB_TOOL_STACKS_H

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
