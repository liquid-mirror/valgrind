
/*--------------------------------------------------------------------*/
/*--- Syscall numbers and related operations. pub_tool_vkiscnums.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2005-2008 Nicholas Nethercote
      njn@valgrind.org
   Copyright (C) 2006-2008 OpenWorks LLP
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

/* This file defines the system call numbers.

   On Linux they are a bunch of #define'd constants of the form
   __NR_name, and this file must contain nothing else, since it will
   be included in assembly code (m_trampoline.S).

   On AIX the __NR_name consts are renamings of global variables which
   tell us the number for each syscall.  This elaboration is necessary
   because on AIX the syscall numbers are not constant; they can be
   different for each process (in principle; in practice they rarely
   change).  32- and 64-bit AIX5 share a common "implementation".

   On Darwin the __NR_name consts are #define'd constants which are
   computed using various macros.  32- and 64-bit Darwin share a common
   "implementation" also.

   This file is merely a top-level "steering" file, which pulls in the
   correct bits for the relevant platform.  You should not directly
   #include any file in include/vki; instead #include only this one or
   pub_core_vkiscnums.h.
*/

#ifndef __PUB_TOOL_VKISCNUMS_H
#define __PUB_TOOL_VKISCNUMS_H

#if defined(VGP_x86_linux)
#  include "vki/vki-scnums-x86-linux.h"

#elif defined(VGP_amd64_linux)
#  include "vki/vki-scnums-amd64-linux.h"

#elif defined(VGP_ppc32_linux)
#  include "vki/vki-scnums-ppc32-linux.h"

#elif defined(VGP_ppc64_linux)
#  include "vki/vki-scnums-ppc64-linux.h"

#elif defined(VGP_ppc32_aix5) || defined(VGP_ppc64_aix5)
#  include "vki/vki-scnums-aix5.h"

/* Look up the name of a syscall, using the bindings previously
   created by VG_(aix5_register_syscall), for the purposes of making
   error messages. */
// DDD: should combine this and VG_DARWIN_SYSNO_PRINT into a single generic
// function which returns a string, something like VG_(pprint_sysno)().
extern UChar* VG_(aix5_sysno_to_sysname)( Int sysno );

#elif defined(VGP_x86_darwin) || defined(VGP_amd64_darwin)
#  include "vki/vki-scnums-darwin.h"

/* Convert a syscall number into a nice form for printing. */
#define VG_DARWIN_SYSNO_PRINT(sysno) \
    ((VG_DARWIN_SYSNO_CLASS(sysno) == VG_DARWIN_SYSCALL_CLASS_MACH) \
    ? -VG_DARWIN_SYSNO_INDEX(sysno) \
    :  VG_DARWIN_SYSNO_INDEX(sysno) \
    )

#else
#  error Unknown platform
#endif

#endif   // __PUB_TOOL_VKISCNUMS_H

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
