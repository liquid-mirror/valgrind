
/*--------------------------------------------------------------------*/
/*--- A home for miscellaneous bits of information which pertain   ---*/
/*--- to the client's state.                                       ---*/
/*---                                              m_clientstate.c ---*/
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

#include "pub_core_basics.h"
#include "pub_core_clientstate.h"

/*-----------------------------------------------------------------*/
/*---                                                           ---*/
/*--- Basic globals about the address space.                    ---*/
/*---                                                           ---*/
/*-----------------------------------------------------------------*/

// TODO: get rid of as many of these as possible.

/* Client address space, lowest to highest (see top of ume.c) */
Addr  VG_(client_base);           /* client address space limits */
Addr  VG_(client_end);

Addr  VG_(clstk_base);
Addr  VG_(clstk_end);
UWord VG_(clstk_id);

Addr  VG_(brk_base)  = 0;         /* start of brk */
Addr  VG_(brk_limit) = 0;         /* current brk */


/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
