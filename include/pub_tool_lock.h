
/*--------------------------------------------------------------------*/
/*--- Locking primitives.                          pub_tool_lock.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2012-2012 Philippe Waroquiers

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

#ifndef __PUB_TOOL_LOCK_H
#define __PUB_TOOL_LOCK_H

//--------------------------------------------------------------------
// PURPOSE: Provides locking primitives.
//--------------------------------------------------------------------


/* A simple non recursive mutex. */
#if defined(VGO_linux)
typedef  Int  Mutex;
// Currently only available for Linux, via futex syscall
#else
OS missing in pub_tool_lock.h;
#endif

extern void VG_(mutex_init)    ( Mutex* );
extern void VG_(mutex_lock)    ( Mutex* );
extern void VG_(mutex_unlock)  ( Mutex* );
extern void VG_(mutex_destroy) ( Mutex* );

/* A simple non recursive rw lock, writer preferrence. */
#if defined(VGO_linux)
typedef
  struct {
     int __lock;
     unsigned int __nr_readers;
     unsigned int __readers_wakeup;
     unsigned int __writer_wakeup;
     unsigned int __nr_readers_queued;
     unsigned int __nr_writers_queued;
     unsigned char __flags;
     unsigned char __shared;
     unsigned char __pad1;
     unsigned char __pad2;
     int __writer;
  }
  RwLock; 
  // TODO ??? some alignment requirements. See if NPTL union is for that ???
  // TODO move RwLock definition in priv_tool_lock.h to decrease its visibility ???

// Currently only available for Linux, via futex syscall
#else
OS missing in pub_tool_lock.h;
#endif

extern void VG_(rwlock_init)    ( RwLock* );
extern void VG_(rwlock_rdlock)  ( RwLock*, ThreadId );
extern void VG_(rwlock_wrlock)  ( RwLock*, ThreadId );
extern void VG_(rwlock_unlock)  ( RwLock*, ThreadId );
extern void VG_(rwlock_destroy) ( RwLock* );

#endif   // __PUB_TOOL_LOCK_H

/*--------------------------------------------------------------------*/
/*--- end                                          pub_tool_lock.h ---*/
/*--------------------------------------------------------------------*/
