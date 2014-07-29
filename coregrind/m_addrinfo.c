
/*--------------------------------------------------------------------*/
/*--- Obtaining information about an address.                      ---*/
/*---                                                 m_addrinfo.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2008-2013 OpenWorks Ltd
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

#include "pub_core_basics.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcprint.h"
#include "pub_core_xarray.h"
#include "pub_core_debuginfo.h"
#include "pub_core_execontext.h"
#include "pub_core_addrinfo.h"
#include "pub_core_mallocfree.h"
#include "pub_core_machine.h"
#include "pub_core_options.h"
#include "pub_core_stacktrace.h"

void VG_(describe_addr) ( Addr a, /*OUT*/AddrInfo* ai )
{
   ThreadId   tid;
   VgSectKind sect;

   /* -- Perhaps the variable type/location data describes it? -- */
   ai->Addr.Variable.descr1
      = VG_(newXA)( VG_(malloc), "mc.da.descr1",
                    VG_(free), sizeof(HChar) );
   ai->Addr.Variable.descr2
      = VG_(newXA)( VG_(malloc), "mc.da.descr2",
                    VG_(free), sizeof(HChar) );

   (void) VG_(get_data_description)( ai->Addr.Variable.descr1,
                                     ai->Addr.Variable.descr2, a );
   /* If there's nothing in descr1/2, free them.  Why is it safe to to
      VG_(indexXA) at zero here?  Because VG_(get_data_description)
      guarantees to zero terminate descr1/2 regardless of the outcome
      of the call.  So there's always at least one element in each XA
      after the call.
   */
   if (0 == VG_(strlen)( VG_(indexXA)( ai->Addr.Variable.descr1, 0 ))) {
      VG_(deleteXA)( ai->Addr.Variable.descr1 );
      ai->Addr.Variable.descr1 = NULL;
   }
   if (0 == VG_(strlen)( VG_(indexXA)( ai->Addr.Variable.descr2, 0 ))) {
      VG_(deleteXA)( ai->Addr.Variable.descr2 );
      ai->Addr.Variable.descr2 = NULL;
   }
   /* Assume (assert) that VG_(get_data_description) fills in descr1
      before it fills in descr2 */
   if (ai->Addr.Variable.descr1 == NULL)
      vg_assert(ai->Addr.Variable.descr2 == NULL);
   /* So did we get lucky? */
   if (ai->Addr.Variable.descr1 != NULL) {
      ai->tag = Addr_Variable;
      return;
   }
   /* -- Have a look at the low level data symbols - perhaps it's in
      there. -- */
   HChar *name;
   if (VG_(get_datasym_and_offset)(
             a, &name,
             &ai->Addr.DataSym.offset )) {
      ai->Addr.DataSym.name = VG_(strdup)("mc.da.dsname", name);
      ai->tag = Addr_DataSym;
      return;
   }
   /* -- Perhaps it's on a thread's stack? -- */
   {
      Addr       stack_min, stack_max;
      VG_(thread_stack_reset_iter)(&tid);
      while ( VG_(thread_stack_next)(&tid, &stack_min, &stack_max) ) {
         if (stack_min - VG_STACK_REDZONE_SZB <= a && a <= stack_max) {
            Addr ips[VG_(clo_backtrace_size)],
                 sps[VG_(clo_backtrace_size)];
            UInt n_frames;
            UInt f;

            ai->tag            = Addr_Stack;
            VG_(initThreadInfo)(&ai->Addr.Stack.tinfo);
            ai->Addr.Stack.tinfo.tid = tid;
            ai->Addr.Stack.IP = 0;
            ai->Addr.Stack.frameNo = -1;
            /* It is on thread tid stack. Build a stacktrace, and
               find the frame sp[f] .. sp[f+1] where the address is.
               Store the found frameNo and the corresponding IP in
               the description. 
               When description is printed, IP will be translated to
               the function name containing IP. 
               Before accepting to describe addr with sp[f] .. sp[f+1],
               we verify the sp looks sane: reasonably sized frame,
               inside the stack.
               We could check the ABI required alignment for sp (what is it?)
               is respected, except for the innermost stack pointer ? */
            n_frames = VG_(get_StackTrace)( tid, ips, VG_(clo_backtrace_size),
                                            sps, NULL, 0/*first_ip_delta*/ );
            for (f = 0; f < n_frames-1; f++) {
               if (sps[f] <= a && a < sps[f+1]
                   && sps[f+1] - sps[f] <= 0x4000000 // 64 MB, arbitrary
                   && sps[f+1] <= stack_max
                   && sps[f]   >= stack_min - VG_STACK_REDZONE_SZB) {
                  ai->Addr.Stack.frameNo = f;
                  ai->Addr.Stack.IP = ips[f];
                  break;
               }
            }
            return;
         }
      }
   }

   /* -- Maybe it is in one of the m_mallocfree.c arenas. --  */
   {
      AddrArenaInfo aai;
      VG_(describe_arena_addr) ( a, &aai );
      if (aai.name != NULL) {
         ai->tag = Addr_Block;
         if (aai.aid == VG_AR_CLIENT)
            ai->Addr.Block.block_kind 
               = aai.free ? Block_ClientArenaFree : Block_ClientArenaMallocd;
         else
            ai->Addr.Block.block_kind 
               = aai.free 
                  ? Block_ValgrindArenaFree :  Block_ValgrindArenaMallocd;
         ai->Addr.Block.block_desc = aai.name;
         ai->Addr.Block.block_szB = aai.block_szB;
         ai->Addr.Block.rwoffset = aai.rwoffset;
         ai->Addr.Block.allocated_at = VG_(null_ExeContext)();
         VG_(initThreadInfo) (&ai->Addr.Block.alloc_tinfo);
         ai->Addr.Block.freed_at = VG_(null_ExeContext)();
         return;
      }
   }

   /* -- last ditch attempt at classification -- */
   vg_assert( sizeof(ai->Addr.SectKind.objname) > 4 );
   VG_(memset)( &ai->Addr.SectKind.objname, 
                0, sizeof(ai->Addr.SectKind.objname));
   VG_(strcpy)( ai->Addr.SectKind.objname, "???" );
   sect = VG_(DebugInfo_sect_kind)( &ai->Addr.SectKind.objname[0],
                                    sizeof(ai->Addr.SectKind.objname)-1, a);
   if (sect != Vg_SectUnknown) {
      ai->tag = Addr_SectKind;
      ai->Addr.SectKind.kind = sect;
      vg_assert( ai->Addr.SectKind.objname
                    [ sizeof(ai->Addr.SectKind.objname)-1 ] == 0);
      return;
   }
   /* -- Clueless ... -- */
   ai->tag = Addr_Unknown;
   return;
}

void VG_(initThreadInfo) (ThreadInfo *tinfo)
{
   tinfo->tid = 0;
   tinfo->tnr = 0;
}

void VG_(clear_addrinfo) ( AddrInfo* ai)
{
   switch (ai->tag) {
      case Addr_Unknown:
          break;

      case Addr_Stack: 
          break;

      case Addr_Block:
         break;

      case Addr_DataSym:
         VG_(free)(ai->Addr.DataSym.name);
         break;

      case Addr_Variable:
         if (ai->Addr.Variable.descr1 != NULL) {
            VG_(deleteXA)( ai->Addr.Variable.descr1 );
            ai->Addr.Variable.descr1 = NULL;
         }
         if (ai->Addr.Variable.descr2 != NULL) {
            VG_(deleteXA)( ai->Addr.Variable.descr2 );
            ai->Addr.Variable.descr2 = NULL;
         }
         break;

      case Addr_SectKind:
         break;

      default:
         VG_(core_panic)("VG_(clear_addrinfo)");
   }

   ai->tag = Addr_Undescribed;
}

static Bool is_arena_BlockKind(BlockKind bk)
{
   switch (bk) {
      case Block_Mallocd:
      case Block_Freed:
      case Block_MempoolChunk:
      case Block_UserG:                return False;

      case Block_ClientArenaMallocd:
      case Block_ClientArenaFree:
      case Block_ValgrindArenaMallocd:
      case Block_ValgrindArenaFree:    return True;

      default:                         vg_assert (0);
   }
}

static const HChar* opt_tnr_prefix (ThreadInfo tinfo)
{
   if (tinfo.tnr != 0)
      return "#";
   else
      return "";
}

static UInt tnr_else_tid (ThreadInfo tinfo)
{
   if (tinfo.tnr != 0)
      return tinfo.tnr;
   else
      return tinfo.tid;
}

static void pp_addrinfo_WRK ( Addr a, AddrInfo* ai, Bool mc, Bool maybe_gcc )
{
   const HChar* xpre  = VG_(clo_xml) ? "  <auxwhat>" : " ";
   const HChar* xpost = VG_(clo_xml) ? "</auxwhat>"  : "";

   vg_assert (!maybe_gcc || mc); // maybe_gcc can only be given in mc mode.

   switch (ai->tag) {
      case Addr_Unknown:
         if (maybe_gcc) {
            VG_(emit)( "%sAddress 0x%llx is just below the stack ptr.  "
                       "To suppress, use: --workaround-gcc296-bugs=yes%s\n",
                       xpre, (ULong)a, xpost );
	 } else {
            VG_(emit)( "%sAddress 0x%llx "
                       "is not stack'd, malloc'd or %s%s\n",
                       xpre, 
                       (ULong)a, 
                       mc ? "(recently) free'd" : "on a free list",
                       xpost );
         }
         break;

      case Addr_Stack: 
         VG_(emit)( "%sAddress 0x%llx is on thread %s%d's stack%s\n", 
                    xpre, (ULong)a, 
                    opt_tnr_prefix (ai->Addr.Stack.tinfo), 
                    tnr_else_tid (ai->Addr.Stack.tinfo), 
                    xpost );
         if (ai->Addr.Stack.frameNo != -1 && ai->Addr.Stack.IP != 0) {
#define     FLEN                256
            HChar *fn;
            Bool  hasfn;
            HChar file[FLEN];
            Bool  hasfile;
            UInt linenum;
            Bool haslinenum;
            PtrdiffT offset;

            if (VG_(get_inst_offset_in_function)( ai->Addr.Stack.IP,
                                                  &offset))
               haslinenum = VG_(get_linenum) (ai->Addr.Stack.IP - offset,
                                              &linenum);
            else
               haslinenum = False;

            hasfile = VG_(get_filename)(ai->Addr.Stack.IP, file, FLEN);
            if (hasfile && haslinenum) {
               HChar strlinenum[10];
               VG_(snprintf) (strlinenum, 10, ":%d", linenum);
               VG_(strncat) (file, strlinenum, 
                             FLEN - VG_(strlen)(file) - 1);
            }

            hasfn = VG_(get_fnname)(ai->Addr.Stack.IP, &fn);

            if (hasfn || hasfile)
               VG_(emit)( "%sin frame #%d, created by %s (%s)%s\n",
                          xpre,
                          ai->Addr.Stack.frameNo, 
                          hasfn ? fn : "???", 
                          hasfile ? file : "???", 
                          xpost );
#undef      FLEN
         }
         break;

      case Addr_Block: {
         SizeT    block_szB = ai->Addr.Block.block_szB;
         PtrdiffT rwoffset  = ai->Addr.Block.rwoffset;
         SizeT    delta;
         const    HChar* relative;

         if (rwoffset < 0) {
            delta    = (SizeT)(-rwoffset);
            relative = "before";
         } else if (rwoffset >= block_szB) {
            delta    = rwoffset - block_szB;
            relative = "after";
         } else {
            delta    = rwoffset;
            relative = "inside";
         }
         if (is_arena_BlockKind (ai->Addr.Block.block_kind))
            VG_(emit)(
               "%sAddress 0x%lx is %'lu bytes %s a%s block of size %'lu"
               " in arena \"%s\"%s\n",
               xpre,
               a, delta,
               relative,
               ai->Addr.Block.block_kind==Block_ClientArenaMallocd
                 || ai->Addr.Block.block_kind==Block_ValgrindArenaMallocd
                 ? "" : "n unallocated",
               block_szB,
               ai->Addr.Block.block_desc,  // arena name
               xpost
            );
         else
            VG_(emit)(
               "%sAddress 0x%lx is %'lu bytes %s a %s of size %'lu %s%s\n",
               xpre,
               a, delta,
               relative,
               ai->Addr.Block.block_desc,
               block_szB,
               ai->Addr.Block.block_kind==Block_Mallocd ? "alloc'd" 
               : ai->Addr.Block.block_kind==Block_Freed ? "free'd" 
                                                        : "client-defined",
               xpost
            );
         if (ai->Addr.Block.block_kind==Block_Mallocd) {
            VG_(pp_ExeContext)(ai->Addr.Block.allocated_at);
            tl_assert (ai->Addr.Block.freed_at == VG_(null_ExeContext)());
         }
         else if (ai->Addr.Block.block_kind==Block_Freed) {
            VG_(pp_ExeContext)(ai->Addr.Block.freed_at);
            if (ai->Addr.Block.allocated_at != VG_(null_ExeContext)()) {
               VG_(emit)(
                  "%sBlock was alloc'd at%s\n",
                  xpre,
                  xpost
               );
               VG_(pp_ExeContext)(ai->Addr.Block.allocated_at);
            }
         }
         else if (ai->Addr.Block.block_kind==Block_MempoolChunk
                  || ai->Addr.Block.block_kind==Block_UserG) {
            // client-defined
            VG_(pp_ExeContext)(ai->Addr.Block.allocated_at);
            tl_assert (ai->Addr.Block.freed_at == VG_(null_ExeContext)());
            /* Nb: cannot have a freed_at, as a freed client-defined block
               has a Block_Freed block_kind. */
         } else {
            // Client or Valgrind arena. At least currently, we never
            // have stacktraces for these.
            tl_assert (ai->Addr.Block.allocated_at == VG_(null_ExeContext)());
            tl_assert (ai->Addr.Block.freed_at == VG_(null_ExeContext)());
         }
         if (ai->Addr.Block.alloc_tinfo.tnr || ai->Addr.Block.alloc_tinfo.tid)
            VG_(emit)(
               "%sBlock was alloc'd by thread %s%d%s\n",
               xpre,
               opt_tnr_prefix (ai->Addr.Block.alloc_tinfo),
               tnr_else_tid (ai->Addr.Block.alloc_tinfo),
               xpost
            );  
         break;
      }

      case Addr_DataSym:
         VG_(emit)( "%sAddress 0x%llx is %llu bytes "
                    "inside data symbol \"%pS\"%s\n",
                    xpre,
                    (ULong)a,
                    (ULong)ai->Addr.DataSym.offset,
                    ai->Addr.DataSym.name,
                    xpost );
         break;

      case Addr_Variable:
         /* Note, no need for XML tags here, because descr1/2 will
            already have <auxwhat> or <xauxwhat>s on them, in XML
            mode. */
         if (ai->Addr.Variable.descr1)
            VG_(emit)( "%s%s\n",
                       VG_(clo_xml) ? "  " : " ",
                       (HChar*)VG_(indexXA)(ai->Addr.Variable.descr1, 0) );
         if (ai->Addr.Variable.descr2)
            VG_(emit)( "%s%s\n",
                       VG_(clo_xml) ? "  " : " ",
                       (HChar*)VG_(indexXA)(ai->Addr.Variable.descr2, 0) );
         break;

      case Addr_SectKind:
         VG_(emit)( "%sAddress 0x%llx is in the %pS segment of %pS%s\n",
                    xpre,
                    (ULong)a,
                    VG_(pp_SectKind)(ai->Addr.SectKind.kind),
                    ai->Addr.SectKind.objname,
                    xpost );
         if (ai->Addr.SectKind.kind == Vg_SectText) {
            /* To better describe the address in a text segment,
               pp a dummy stacktrace made of this single address. */
            VG_(pp_StackTrace)( &a, 1 );
         }
         break;

      default:
         VG_(tool_panic)("mc_pp_AddrInfo");
   }
}

void VG_(pp_addrinfo) ( Addr a, AddrInfo* ai )
{
   pp_addrinfo_WRK (a, ai, False /*mc*/, False /*maybe_gcc*/);
}

void VG_(pp_addrinfo_mc) ( Addr a, AddrInfo* ai, Bool maybe_gcc )
{
   pp_addrinfo_WRK (a, ai, True /*mc*/, maybe_gcc);
}


/*--------------------------------------------------------------------*/
/*--- end                                             m_addrinfo.c ---*/
/*--------------------------------------------------------------------*/
