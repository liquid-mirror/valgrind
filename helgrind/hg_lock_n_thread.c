
/*--------------------------------------------------------------------*/
/*--- Definitions for Locks and Threads.                           ---*/
/*---                                           hg_lock_n_thread.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Helgrind, a Valgrind tool for detecting errors
   in threaded programs.

   Copyright (C) 2007-2008 OpenWorks Ltd
      info@open-works.co.uk

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

#include "pub_tool_basics.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_execontext.h"
#include "pub_tool_wordfm.h"

#include "hg_basics.h"
#include "hg_wordset.h"
#include "hg_lock_n_thread.h"            /* self */


/*--------------------------------------------------------------------*/
/*--- end                                       hg_lock_n_thread.c ---*/
/*--------------------------------------------------------------------*/
