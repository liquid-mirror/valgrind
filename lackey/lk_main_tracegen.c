
/*--------------------------------------------------------------------*/
/*--- An example Valgrind tool.                          lk_main.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Lackey, an example Valgrind tool that does
   some simple program measurement and tracing.

   Copyright (C) 2002-2012 Nicholas Nethercote
      njn@valgrind.org

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
#include "pub_tool_vki.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_options.h"
#include "pub_tool_machine.h"     // VG_(fnptr_to_fnentry)
#include "pub_tool_mallocfree.h"

/*------------------------------------------------------------*/
/*--- Command line options                                 ---*/
/*------------------------------------------------------------*/

static UInt clo_buf_size_mb = 100;
static Bool clo_write_trace = True;

static Bool lk_process_cmd_line_option(Char* arg)
{
   if (VG_BINTN_CLO(10, arg, "--buf-size-mb", clo_buf_size_mb, 0, 10000)) {}
   else if (VG_XACT_CLO(arg, "--write-trace=n", clo_write_trace, False)) {}
   else if (VG_XACT_CLO(arg, "--write-trace=y", clo_write_trace, True)) {}
   else
      return False;
    
   return True;
}

static void lk_print_usage(void)
{   
   VG_(printf)(
"      --buf-size-mb         size of buffer in MBytes [100]\n"
"      --write-trace=[n|y]   dump results at end? [y]\n"
   );
}
static void lk_print_debug_usage(void)
{  
  VG_(printf)(
"    (none)\n"
  );
}

/*------------------------------------------------------------*/
/*--- Stuff for --trace-mem                                ---*/
/*------------------------------------------------------------*/

static UWord  buf_sizeW = 0;
static UWord  buf_usedW = 0;
static UWord* buf = NULL;

#define TAG_LOAD  0x55550001
#define TAG_STORE 0x55550002
#define TAG_PUT   0x55550003

static VG_REGPARM(2) void trace_load(Addr addr, UWord data)
{
  if (LIKELY(buf_usedW + 3 >= buf_sizeW)) return;
  buf[buf_usedW++] = TAG_LOAD;
  buf[buf_usedW++] = addr;
  buf[buf_usedW++] = data;
  tl_assert(buf_usedW <= buf_sizeW);
  //VG_(printf)(" L %08lx,%lu\n", addr, data);
}

static VG_REGPARM(2) void trace_store(Addr addr, UWord data)
{
  if (LIKELY(buf_usedW + 3 >= buf_sizeW)) return;
  buf[buf_usedW++] = TAG_STORE;
  buf[buf_usedW++] = addr;
  buf[buf_usedW++] = data;
  tl_assert(buf_usedW <= buf_sizeW);
  //VG_(printf)(" S %08lx,%lx\n", addr, data);
}

static VG_REGPARM(3) void trace_put(UWord offs, UWord szB, UWord data)
{
  if (LIKELY(buf_usedW + 3 >= buf_sizeW)) return;
  buf[buf_usedW++] = TAG_PUT;
  buf[buf_usedW++] = ((szB & 0xFF) << 16) | (offs & 0xFFFF);
  buf[buf_usedW++] = data;
  tl_assert(buf_usedW <= buf_sizeW);
  //VG_(printf)(" P %03ld,%ld,%08lx\n", offs, szB, data);
}

// Returns the casted value in a new IRTemp
static IRTemp to_hWordTy ( IRSB* sbOut, IRType hWordTy, IRExpr* e )
{
  IRType tE  = typeOfIRExpr(sbOut->tyenv, e);
  IRTemp res = newIRTemp(sbOut->tyenv, Ity_I64);
  if (hWordTy == Ity_I64) {
    switch (tE) {
    case Ity_I64:
      addStmtToIRSB(sbOut, IRStmt_WrTmp(res, e));
      return res;
    case Ity_I8:
      addStmtToIRSB(sbOut,
                    IRStmt_WrTmp(res, IRExpr_Unop(Iop_8Uto64, e)));
      return res;
    case Ity_I16:
      addStmtToIRSB(sbOut,
                    IRStmt_WrTmp(res, IRExpr_Unop(Iop_16Uto64, e)));
      return res;
    case Ity_I32:
      addStmtToIRSB(sbOut,
                    IRStmt_WrTmp(res, IRExpr_Unop(Iop_32Uto64, e)));
      return res;
    case Ity_V128:
      addStmtToIRSB(sbOut,
                    IRStmt_WrTmp(res, IRExpr_Unop(Iop_V128to64, e)));
      return res;
    case Ity_F64:
      addStmtToIRSB(sbOut,
                    IRStmt_WrTmp(res, IRExpr_Unop(Iop_ReinterpF64asI64, e)));
      return res;
    case Ity_F32: {
       IRTemp tmp = newIRTemp(sbOut->tyenv, Ity_I32);
       addStmtToIRSB(sbOut,
                     IRStmt_WrTmp(tmp, IRExpr_Unop(Iop_ReinterpF32asI32, e)));
       addStmtToIRSB(sbOut,
                     IRStmt_WrTmp(res, IRExpr_Unop(Iop_32Uto64,
                                                   IRExpr_RdTmp(tmp))));
       return res;
    }
    default:
      break;
    }
  }
  VG_(printf)("to_hWordTy: fail: from\n");
  ppIRType(tE);
  VG_(printf)(" .. to ..\n");
  ppIRType(hWordTy);
  tl_assert(0);
}

static IRExpr* mkexpr ( IRTemp t ) { return IRExpr_RdTmp(t); }
static void gen_event_Put( IRSB* sbOut, IRType hWordTy,
                           UWord offs, IRExpr* data)
{
  tl_assert(isIRAtom(data));
  IRTemp   dataW = to_hWordTy(sbOut, hWordTy, data);
  Int      sz    = sizeofIRType(typeOfIRExpr(sbOut->tyenv, data));
  IRExpr** argv  = mkIRExprVec_3( mkIRExpr_HWord(offs), mkIRExpr_HWord(sz),
                                  mkexpr(dataW) );
  HChar* helperName = "trace_put";
  void*      helperAddr   = &trace_put;
  IRDirty*   di = unsafeIRDirty_0_N( /*regparms*/3,
                                     helperName,
                                     VG_(fnptr_to_fnentry)( helperAddr ),
                                     argv );
  addStmtToIRSB( sbOut, IRStmt_Dirty(di) );
}

static void gen_event_Store( IRSB* sbOut, IRType hWordTy,
                             IRExpr* addr, IRExpr* data )
{
  tl_assert(isIRAtom(addr));
  tl_assert(isIRAtom(data));
  IRTemp dataW = to_hWordTy(sbOut, hWordTy, data);
  IRTemp addrW = to_hWordTy(sbOut, hWordTy, addr);
  IRExpr** argv  = mkIRExprVec_2( mkexpr(addrW), mkexpr(dataW) );
  HChar* helperName = "trace_store";
  void*      helperAddr   = &trace_store;
  IRDirty*   di = unsafeIRDirty_0_N( /*regparms*/2,
                                     helperName,
                                     VG_(fnptr_to_fnentry)( helperAddr ),
                                     argv );
  addStmtToIRSB( sbOut, IRStmt_Dirty(di) );
}

static void gen_event_Load( IRSB* sbOut, IRType hWordTy,
                            IRExpr* addr, IRTemp data )
{
  tl_assert(isIRAtom(addr));
  IRTemp dataW = to_hWordTy(sbOut, hWordTy, mkexpr(data));
  IRTemp addrW = to_hWordTy(sbOut, hWordTy, addr);
  IRExpr** argv  = mkIRExprVec_2( mkexpr(addrW), mkexpr(dataW) );
  HChar* helperName = "trace_load";
  void*      helperAddr   = &trace_load;
  IRDirty*   di = unsafeIRDirty_0_N( /*regparms*/2,
                                     helperName,
                                     VG_(fnptr_to_fnentry)( helperAddr ),
                                     argv );
  addStmtToIRSB( sbOut, IRStmt_Dirty(di) );
}

/*------------------------------------------------------------*/
/*--- Basic tool functions                                 ---*/
/*------------------------------------------------------------*/

static void lk_post_clo_init(void)
{
  tl_assert(buf_sizeW == 0);
  tl_assert(buf_usedW == 0);
  tl_assert(buf == NULL);
  buf_sizeW = (clo_buf_size_mb * 1048576) / sizeof(UWord);
  buf = VG_(malloc)( "lk_post_clo_init.buf", buf_sizeW * sizeof(UWord) );
  tl_assert(buf != NULL);
  VG_(umsg)("Allocated buffer of %'lu words\n", buf_sizeW);
}

static
IRSB* lk_instrument ( VgCallbackClosure* closure,
                      IRSB* sbIn, 
                      VexGuestLayout* layout, 
                      VexGuestExtents* vge,
                      IRType gWordTy, IRType hWordTy )
{
  Int        i;
  IRSB*      sbOut;
  IRTypeEnv* tyenv = sbIn->tyenv;

  if (gWordTy != hWordTy) {
    /* We don't currently support this case. */
    VG_(tool_panic)("host/guest word size mismatch");
  }

  /* Set up SB */
  sbOut = deepCopyIRSBExceptStmts(sbIn);

  // Copy verbatim any IR preamble preceding the first IMark
  i = 0;
  while (i < sbIn->stmts_used && sbIn->stmts[i]->tag != Ist_IMark) {
    addStmtToIRSB( sbOut, sbIn->stmts[i] );
    i++;
  }

  for (/*use current i*/; i < sbIn->stmts_used; i++) {
    IRStmt* st = sbIn->stmts[i];
    if (!st || st->tag == Ist_NoOp) continue;

    switch (st->tag) {
    case Ist_NoOp:
    case Ist_AbiHint:
    case Ist_PutI:
    case Ist_MBE:
    case Ist_IMark:
    case Ist_Dirty:
    case Ist_CAS:
    case Ist_Exit:
      addStmtToIRSB( sbOut, st );
      break;

    case Ist_Put:
      gen_event_Put(sbOut, hWordTy, st->Ist.Put.offset,
                    st->Ist.Put.data);
      addStmtToIRSB( sbOut, st );
      break;

    case Ist_Store: {
      IRExpr* data = st->Ist.Store.data;
      IRType  type = typeOfIRExpr(tyenv, data);
      tl_assert(type != Ity_INVALID);
      gen_event_Store(sbOut, hWordTy,
                      st->Ist.Store.addr, st->Ist.Store.data);
      addStmtToIRSB( sbOut, st );
      break;
    }

    case Ist_WrTmp:
      // do the load first
      addStmtToIRSB( sbOut, st );

      IRExpr* data = st->Ist.WrTmp.data;
      if (data->tag == Iex_Load) {
        gen_event_Load(sbOut, hWordTy,
                       data->Iex.Load.addr, st->Ist.WrTmp.tmp);
      }
      break;

    case Ist_LLSC: {
      // do the transaction first
      addStmtToIRSB( sbOut, st );

      IRType dataTy;
      if (st->Ist.LLSC.storedata == NULL) {
        /* LL */
        dataTy = typeOfIRTemp(tyenv, st->Ist.LLSC.result);
        gen_event_Load(sbOut, hWordTy, st->Ist.LLSC.addr,
                       st->Ist.LLSC.result);
      } else {
        /* SC */
        dataTy = typeOfIRExpr(tyenv, st->Ist.LLSC.storedata);
        gen_event_Store(sbOut, hWordTy, st->Ist.LLSC.addr,
                        st->Ist.LLSC.storedata);
      }
      break;
    }

    default:
      ppIRStmt(st);
      tl_assert(0);
    }
  }

  return sbOut;
}

static HChar block[1048576];
static UInt  nBlock = 0;

static ULong totalOut = 0;

static void lk_fini(Int exitcode)
{
  VG_(umsg)("Used %'lu of available %'lu words\n", buf_usedW, buf_sizeW);

  VG_(umsg)("--write-trace=%c\n", clo_write_trace ? 'y' : 'n');
  if (!clo_write_trace) return;

  if (buf_sizeW == 0) {
    VG_(umsg)("No trace recorded, not writing output file\n");
    return;
  }

  HChar* fname = VG_(expand_file_name)("fake_option_name", "lackey.out.%p");

  VG_(umsg)("Writing trace to %s ..\n", fname);

  SysRes sres = VG_(open)(fname,  VKI_O_CREAT|VKI_O_TRUNC|VKI_O_WRONLY,
                          VKI_S_IRUSR|VKI_S_IWUSR);
  if (sr_isError(sres)) {
    VG_(umsg)("lackey: can't create output file: %s\n", fname);
    VG_(free)(fname);
    return;
  }

  Int fd = sr_Res(sres);
  VG_(free)(fname);

  VG_(umsg)("Write: FD = %d\n", fd);

  VG_(memset)(block, 0, sizeof(block));
  nBlock = 0;

  UInt chNo = 0;

  UWord i = 0;
  while (1) {

    tl_assert(nBlock >= 0 && nBlock <= sizeof(block));
    if (nBlock > sizeof(block)-1024) {
       chNo++;
       totalOut += (ULong)nBlock;
       VG_(write)(fd, block, nBlock);
       nBlock = 0;
       VG_(memset)(block, 0, sizeof(block));
       if (0)
       VG_(umsg)("write block %u done, total %'llu,  i %'lu, buf_usedW %'lu\n",
                 chNo, totalOut, i, buf_usedW);
    }

    tl_assert(i <= buf_usedW);
    if (i == buf_usedW) break;

    switch (buf[i+0]) {
    case TAG_LOAD:
      nBlock += VG_(sprintf)(&block[nBlock],
                             "L %lx,%lx\n", buf[i+1], buf[i+2]);
      i += 3;
      break;
    case TAG_STORE:
      nBlock += VG_(sprintf)(&block[nBlock],
                             "S %lx,%lx\n", buf[i+1], buf[i+2]);
      i += 3;
      break;
    case TAG_PUT: {
      UWord offs = buf[i+1] & 0xFFFF;
      UWord szB = (buf[i+1] >> 16) & 0xFF;
      nBlock += VG_(sprintf)(&block[nBlock],
                             "P %ld,%ld,%lx\n", offs, szB, buf[i+2]);
      i += 3;
      break;
    }
    default:
      tl_assert(0);
    }

  }

  tl_assert(nBlock >= 0 && nBlock <= sizeof(block));
  if (nBlock > 0) {
     VG_(write)(fd, block, nBlock);
  }

  VG_(close)(fd);
  VG_(umsg)(".. done\n");
}

static void lk_pre_clo_init(void)
{
  VG_(details_name)            ("Lackey");
  VG_(details_version)         (NULL);
  VG_(details_description)     ("an example Valgrind tool");
  VG_(details_copyright_author)(
                                "Copyright (C) 2002-2012, and GNU GPL'd, by Nicholas Nethercote.");
  VG_(details_bug_reports_to)  (VG_BUGS_TO);
  VG_(details_avg_translation_sizeB) ( 200 );

  VG_(basic_tool_funcs)          (lk_post_clo_init,
                                  lk_instrument,
                                  lk_fini);
  VG_(needs_command_line_options)(lk_process_cmd_line_option,
                                  lk_print_usage,
                                  lk_print_debug_usage);
}

VG_DETERMINE_INTERFACE_VERSION(lk_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                lk_main.c ---*/
/*--------------------------------------------------------------------*/
