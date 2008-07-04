
/*--------------------------------------------------------------------*/
/*--- Interval skip list header.                         pc_list.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Ptrcheck, a Valgrind tool for checking pointer
   use in programs.

   Copyright (C) 2003-2008 Nicholas Nethercote
      njn@valgrind.org

   This file is derived from a C++ interval skip-list implementation by Eric
   Hanson, which had this copyright notice:

     This software is copyright 1994 by the University of Florida and Eric
     Hanson (hanson@cise.ufl.edu).  It has been placed in the public domain.
     Copies can be made, modified, distributed freely, and used for any and 
     all purposes, provided that copies attribute the original source.  
     This software is not warranted to be free of defects or to be suitable 
     for any particular purpose.

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


// C++ implementation of interval skip lists
// Author:  Eric N. Hanson, hanson@cis.ufl.edu, University of Florida


//-------------------------------------------------------------------
typedef
   enum { SegHeap, SegMmap, SegHeapFree, SegMmapFree }
   SegStatus;

//-------------------------------------------------------------------
// Seg is equivalent to Interval, but is an extra abstraction layer that
// makes things a bit easier for use by Annelid.  They're both abstract,
// primarily because it's easy to screw up the handling of the is_zero case.
typedef struct _Interval  Interval;
typedef struct _Interval* Seg;

extern Seg   Seg__construct(Addr a, SizeT len, ExeContext* where,
                            SegStatus status);
extern Addr  Seg__a(Seg seg);
extern ExeContext* Seg__where(Seg seg);
extern void  Seg__heap_free(Seg seg, ExeContext* where);
extern SizeT Seg__size(Seg seg);
extern Bool  Seg__is_freed(Seg seg);
extern Bool  Seg__containsI(Seg seg, Addr l, Addr r);
extern Bool  Seg__contains(Seg seg, Addr a);
extern void  Seg__cmp(Seg seg, Addr a, Int* cmp, Word* n);
extern void  Seg__resize(Seg seg, SizeT new_size, ExeContext* where) ;
extern Char* Seg__status_str(Seg seg);

extern Bool Seg__plausible ( Seg seg );


//-------------------------------------------------------------------
typedef struct _IList IList;

//-------------------------------------------------------------------
typedef struct _ISList ISList;

extern ISList* ISList__construct   (void);
extern Bool    ISList__isEmpty     (ISList* o);

extern void    ISList__insertI     (ISList* o, Interval* I);
extern void    ISList__removeI     (ISList* o, Interval* I);
extern Bool    ISList__findI       (ISList* o, Addr a, Interval** out);
extern Bool    ISList__findI0      (ISList* o, Addr a, Interval** out);

extern void    ISList__printDetails(ISList* o);
extern void    ISList__print       (ISList* o);
extern void    ISList__destruct    (ISList* o);

/*--------------------------------------------------------------------*/
/*--- end                                                pc_list.h ---*/
/*--------------------------------------------------------------------*/
