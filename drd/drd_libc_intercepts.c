
/*--------------------------------------------------------------------*/
/*--- Replacements for functions operating on FILE objects, which  ---*/
/*--- run on the simulated CPU                                     ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of DRD, a heavyweight Valgrind tool for
   detecting threading errors.

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

#include <stdio.h>
#include "pub_tool_basics.h"
#include "pub_tool_redir.h"
#include "valgrind.h"
#include "drd_clientreq.h"


/* --------- Some handy Z-encoded names. --------- */

/* --- Soname of the standard C library. --- */

#if defined(VGO_linux)
#  define  m_libc_soname     libcZdsoZa              // libc.so*
#elif defined(VGP_ppc32_aix5)
   /* AIX has both /usr/lib/libc.a and /usr/lib/libc_r.a. */
#  define  m_libc_soname     libcZaZdaZLshrZdoZR     // libc*.a(shr.o)
#elif defined(VGP_ppc64_aix5)
#  define  m_libc_soname     libcZaZdaZLshrZu64ZdoZR // libc*.a(shr_64.o)
#else
#  error "Unknown platform"
#endif

#define LIBC_FUNC(ret_ty, f, args...)                        \
  ret_ty VG_WRAP_FUNCTION_ZZ(m_libc_soname, f)(args);        \
  ret_ty VG_WRAP_FUNCTION_ZZ(m_libc_soname, f)(args)

LIBC_FUNC(int, ZuIOZuflockfile, // _IO_flockfile
          FILE * stream)
{
  int      ret;
  int      res;
  OrigFn   fn;

  VALGRIND_GET_ORIG_FN(fn);
  VALGRIND_DO_CLIENT_REQUEST(res, 0, VG_USERREQ__PRE_MUTEX_LOCK,
                             stream, mutex_type_libio_file, 0, 0, 0);
  CALL_FN_W_W(ret, fn, stream);
  VALGRIND_DO_CLIENT_REQUEST(res, 0, VG_USERREQ__POST_MUTEX_LOCK,
                             stream, True, 0, 0, 0);
  return ret;
}

LIBC_FUNC(int, ZuIOZufunlockfile, // _IO_funlockfile
          FILE *stream)
{
  int      ret;
  int      res;
  OrigFn   fn;

  VALGRIND_GET_ORIG_FN(fn);
  VALGRIND_DO_CLIENT_REQUEST(res, -1,
                             VG_USERREQ__PRE_MUTEX_UNLOCK,
                             stream, mutex_type_libio_file, 0, 0, 0);
  CALL_FN_W_W(ret, fn, stream);
  VALGRIND_DO_CLIENT_REQUEST(res, -1,
                             VG_USERREQ__POST_MUTEX_UNLOCK,
                             stream, 0, 0, 0, 0);
  return ret;
}

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
