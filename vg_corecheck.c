
/*--------------------------------------------------------------------*/
/*--- Skin reporting errors detected in core.       vg_corecheck.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, an x86 protected-mode emulator 
   designed for debugging and profiling binaries on x86-Unixes.

   Copyright (C) 2002 Nicholas Nethercote
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

#include "vg_skin.h"


void SK_(pre_clo_init)(VgNeeds* needs, VgTrackEvents* track) 
{
   needs->name                    = "coregrind";
   needs->description             = "a rudimentary error detector";

   needs->core_errors             = True;
   needs->skin_errors             = False;
   needs->run_libc_freeres        = False;

   needs->identifies_basic_blocks = False;
   needs->shadow_regs             = False;
   needs->command_line_options    = False;
   needs->client_requests         = False;
   needs->extends_UCode           = False;
   needs->wrap_syscalls           = False;
   needs->sizeof_shadow_chunk     = 0;
   needs->alternative_free        = False;
   needs->sanity_checks           = False;

   /* No core events to track */
}

void SK_(post_clo_init)(void)
{
}

UCodeBlock* SK_(instrument)(UCodeBlock* cb, Addr a)
{
    return cb;
}

void SK_(fini)(void)
{
}

/*--------------------------------------------------------------------*/
/*--- end                                           vg_corecheck.c ---*/
/*--------------------------------------------------------------------*/
