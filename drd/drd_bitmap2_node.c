/* -*- mode: C; c-basic-offset: 3; -*- */
/*
  This file is part of drd, a thread error detector.

  Copyright (C) 2006-2009 Bart Van Assche <bart.vanassche@gmail.com>.

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


#include "drd_basics.h"           /* DRD_() */
#include "pub_drd_bitmap.h"
#include "pub_tool_basics.h"      /* Addr, SizeT */
#include "pub_tool_libcassert.h"  /* tl_assert() */
#include "pub_tool_mallocfree.h"  /* VG_(malloc), VG_(free) */


/* Local function declarations. */



/* Local variables. */



/* Function definitions. */

void* DRD_(bm2_alloc_node)(HChar* const ec, const SizeT szB)
{
   return VG_(malloc)(ec, szB);
}

void  DRD_(bm2_free_node)(void* const bm2)
{
   return VG_(free)(bm2);
}
