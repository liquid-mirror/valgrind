
/*--------------------------------------------------------------------*/
/*--- Ptrcheck: a pointer-use checker.                             ---*/
/*--- Exports for stack and global access checking.                ---*/
/*---                                                    sg_main.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Ptrcheck, a Valgrind tool for checking pointer
   use in programs.

   Copyright (C) 2008-2008 OpenWorks Ltd
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

#ifndef __SG_MAIN_H

#define __SG_MAIN_H

void sg_pre_clo_init ( void );
void sg_post_clo_init ( void );
void sg_fini(Int exitcode);

void sg_die_mem_stack ( Addr old_SP, SizeT len );
void sg_pre_thread_ll_create ( ThreadId parent, ThreadId child );
void sg_pre_thread_first_insn ( ThreadId tid );

void sg_new_mem_mmap( Addr a, SizeT len,
                      Bool rr, Bool ww, Bool xx, ULong di_handle );
void sg_new_mem_startup( Addr a, SizeT len,
                         Bool rr, Bool ww, Bool xx, ULong di_handle );
void sg_die_mem_munmap ( Addr a, SizeT len );

#endif

/*--------------------------------------------------------------------*/
/*--- end                                                sg_main.h ---*/
/*--------------------------------------------------------------------*/
