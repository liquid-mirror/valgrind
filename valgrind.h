
/*
   This file is part of Valgrind, an x86 protected-mode emulator 
   designed for debugging and profiling binaries on x86-Unixes.

   Copyright (C) 2000-2002 Julian Seward 
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

   The GNU General Public License is contained in the file LICENSE.
*/


#ifndef __VALGRIND_H
#define __VALGRIND_H


/* This file is for inclusion into client (your!) code.

   You can use these macros to manipulate and query Valgrind's 
   execution inside your own programs.

   The resulting executables will still run without Valgrind, just a
   little bit more slowly than they otherwise would, but otherwise
   unchanged.  

   When run on Valgrind with --client-perms=yes, Valgrind observes
   these macro calls and takes appropriate action.  When run on
   Valgrind with --client-perms=no (the default), Valgrind observes
   these macro calls but does not take any action as a result.  */



/* This defines the magic code sequence which the JITter spots and
   handles magically.  Don't look too closely at this; it will rot
   your brain.  Valgrind dumps the result value in %EDX, so we first
   copy the default value there, so that it is returned when not
   running on Valgrind.  Since %EAX points to a block of mem
   containing the args, you can pass as many args as you want like
   this.  Currently this is set up to deal with 4 args since that's
   the max that we appear to need (pthread_create).  
*/
#define VALGRIND_MAGIC_SEQUENCE(                                        \
        _zzq_rlval,   /* result lvalue */                               \
        _zzq_default, /* result returned when running on real CPU */    \
        _zzq_request, /* request code */                                \
        _zzq_arg1,    /* request first param */                         \
        _zzq_arg2,    /* request second param */                        \
        _zzq_arg3,    /* request third param */                         \
        _zzq_arg4     /* request fourth param */ )                      \
                                                                        \
  { volatile unsigned int _zzq_args[5];                                 \
    _zzq_args[0] = (volatile unsigned int)(_zzq_request);               \
    _zzq_args[1] = (volatile unsigned int)(_zzq_arg1);                  \
    _zzq_args[2] = (volatile unsigned int)(_zzq_arg2);                  \
    _zzq_args[3] = (volatile unsigned int)(_zzq_arg3);                  \
    _zzq_args[4] = (volatile unsigned int)(_zzq_arg4);                  \
    asm volatile("movl %1, %%eax\n\t"                                   \
                 "movl %2, %%edx\n\t"                                   \
                 "roll $29, %%eax ; roll $3, %%eax\n\t"                 \
                 "rorl $27, %%eax ; rorl $5, %%eax\n\t"                 \
                 "roll $13, %%eax ; roll $19, %%eax\n\t"                \
                 "movl %%edx, %0\t"                                     \
                 : "=r" (_zzq_rlval)                                    \
                 : "r" (&_zzq_args[0]), "r" (_zzq_default)              \
                 : "eax", "edx", "cc", "memory"                         \
                );                                                      \
  }


/* Some request codes.  There are many more of these, but most are not
   exposed to end-user view.  These are the public ones, all of the
   form 0x1000 + small_number.
*/

typedef
   enum { VG_USERREQ__RUNNING_ON_VALGRIND = 0x1001,
          VG_USERREQ__DISCARD_TRANSLATIONS,
          VG_USERREQ__FINAL_DUMMY_CLIENT_REQUEST,
   } Vg_ClientRequest;


/* Returns 1 if running on Valgrind, 0 if running on the real CPU. 
   Currently implemented but untested. */
#define RUNNING_ON_VALGRIND                                        \
   ({unsigned int _qzz_res;                                        \
    VALGRIND_MAGIC_SEQUENCE(_qzz_res, 0 /* returned if not */,     \
                            VG_USERREQ__RUNNING_ON_VALGRIND,       \
                            0, 0, 0, 0);                           \
    _qzz_res;                                                      \
   })


/* Discard translation of code in the range [_qzz_addr .. _qzz_addr +
   _qzz_len - 1].  Useful if you are debugging a JITter or some such,
   since it provides a way to make sure valgrind will retranslate the
   invalidated area.  Returns no value. */
#define VALGRIND_DISCARD_TRANSLATIONS(_qzz_addr,_qzz_len)          \
   {unsigned int _qzz_res;                                         \
    VALGRIND_MAGIC_SEQUENCE(_qzz_res, 0,                           \
                            VG_USERREQ__DISCARD_TRANSLATIONS,      \
                            _qzz_addr, _qzz_len, 0, 0);            \
   }


#endif
