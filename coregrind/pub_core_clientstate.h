
/*--------------------------------------------------------------------*/
/*--- Misc client state info                pub_core_clientstate.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2000-2005 Julian Seward
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

#ifndef __PUB_CORE_CLIENTSTATE_H
#define __PUB_CORE_CLIENTSTATE_H

//--------------------------------------------------------------------
// PURPOSE: This module holds various bits of client state which don't
// live comfortably anywhere else.  Note that the ThreadStates for the
// client don't live here; they instead live in m_threadstate.h.
//--------------------------------------------------------------------

#include "pub_tool_clientstate.h"

// Address space globals

extern Addr  VG_(client_base);	 // client address space limits
extern Addr  VG_(client_end);

extern Addr  VG_(clstk_base);	 // client stack range
extern Addr  VG_(clstk_end);
extern UWord VG_(clstk_id);      // client stack id

extern Addr  VG_(brk_base);	 // start of brk
extern Addr  VG_(brk_limit);	 // current brk

/* A fd which refers to the client executable. */
extern Int VG_(clexecfd);

// Client's original rlimit data and rlimit stack
extern struct vki_rlimit VG_(client_rlimit_data);
extern struct vki_rlimit VG_(client_rlimit_stack);

// Name of the launcher, as extracted from VALGRIND_LAUNCHER at
// startup.
extern HChar* VG_(name_of_launcher);


#endif   // __PUB_CORE_CLIENTSTATE_H

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
