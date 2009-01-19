
/*--------------------------------------------------------------------*/
/*--- User-mode execve().                               priv_ume.h ---*/
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

#ifndef __PRIV_UME_H
#define __PRIV_UME_H

#include "pub_core_basics.h"
#include "pub_core_vki.h"

#if defined(VGO_linux) 
#define HAVE_UME
#define HAVE_SCRIPT
#define HAVE_ELF

#elif defined(VGO_darwin)
#define HAVE_UME
#define HAVE_SCRIPT
#define HAVE_MACHO

#elif defined(VGO_aix5)
#undef HAVE_UME

#else
#error unknown architecture
#endif

#if defined(HAVE_UME)

#include "pub_core_aspacemgr.h"   // various mapping fns
#include "pub_core_debuglog.h"
#include "pub_core_libcbase.h"
#include "pub_core_machine.h"
#include "pub_core_libcprint.h"
#include "pub_core_libcfile.h"    // VG_(close) et al
#include "pub_core_libcproc.h"    // VG_(geteuid), VG_(getegid)
#include "pub_core_libcassert.h"  // VG_(exit), vg_assert
#include "pub_core_mallocfree.h"  // VG_(malloc), VG_(free)
#include "pub_core_syscall.h"     // VG_(strerror)
#include "pub_core_options.h"     // VG_(clo_xml)
#include "pub_core_ume.h"         // self

extern int VG_(do_exec_inner)(const HChar *exe, ExeInfo *info);

extern Bool VG_(match_script)(char *hdr, Int len);
extern Int VG_(load_script)(Int fd, const HChar *name, ExeInfo *info);

extern Bool VG_(match_ELF)(char *hdr, Int len);
extern Int VG_(load_ELF)(Int fd, const HChar *name, ExeInfo *info);

extern Bool VG_(match_macho)(char *hdr, Int len);
extern Int VG_(load_macho)(Int fd, const HChar *name, ExeInfo *info);

#endif

#endif /* __PRIV_UME_H */

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/

