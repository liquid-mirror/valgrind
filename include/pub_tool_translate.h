
/*--------------------------------------------------------------------*/
/*--- The JITter wrapper.                     pub_tool_translate.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2000-2006 Julian Seward
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

   The GNU General Public License is contained in the file COPYING.
*/

#ifndef __PUB_TOOL_TRANSLATE_H
#define __PUB_TOOL_TRANSLATE_H

/* Most tools that want to know about SP changes should use the
   new_mem_stack/die_mem_stack events.  But some tools need more flexibility
   than that.  This function provides it.  It should be called at the end of
   the tools 'instrument' function.  The my_handle_SP_update function is
   called for each SP update that occurs.  It's passed various arguments:
   - sb_in: the input SB
   - sb_out: the output SB
   - layout: the machine's layout
   - i: the index of the SP-update statement
   - st: the SP-update statement itself
   - ip: the IP of the SP-update
   - SP_update_expr: the expression holding the new value for SP
   - is_delta_known: whether the SP-update delta is known
   - delta_szB: if is_delta_known is true, what the delta actually is
   This function needs to copy 'st' into sb_out itself.  It can also add
   other code before or after 'st' in sb_out.

   Nb: if the tool uses this, it shouldn't use the
   new_mem_stack/die_mem_stack events, otherwise SP updates will be
   instrumented twice!
*/
IRSB* VG_(SP_update_pass) (
         IRSB*             sb_in, 
         VexGuestLayout*   layout, 
         Bool(*my_handle_SP_update)(
                  IRSB* sb_in, IRSB* sb_out, VexGuestLayout* layout, Int i,
                  IRStmt* st, Addr ip, IRExpr* SP_update_expr,
                  Bool is_delta_known, Int delta_szB)
      );

#endif   // __PUB_TOOL_TRANSLATE_H

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
