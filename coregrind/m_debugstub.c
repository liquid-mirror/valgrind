/*--------------------------------------------------------------------*/
/*--- gdb remote debugging                           m_debugstub.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2007 Apple Inc.
      Greg Parker  gparker@apple.com

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
#include "pub_core_vki.h"
#include "pub_core_aspacemgr.h"
#include "pub_core_threadstate.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcfile.h"
#include "pub_core_libcprint.h"
#include "pub_core_xarray.h"
#include "pub_core_clientstate.h"
#include "pub_core_libcproc.h"
#include "pub_core_mallocfree.h"
#include "pub_core_options.h"
#include "pub_core_tooliface.h"
#include "pub_core_transtab.h"
#include "pub_core_scheduler.h"
#include "pub_core_debugger.h"

#include "pub_core_debugstub.h"
#include "pub_tool_debugstub.h"

#include <mach/mach.h>
#include <mach/mach_vm.h>

#define msgbufsize 4096
static char msgbuf[msgbufsize];
static char outbuf[msgbufsize];
static const char xdigit[] = "0123456789abcdef";

static ThreadId query_tid = VG_INVALID_THREADID;
static ThreadId control_tid = VG_INVALID_THREADID;

static Bool debugger_running = False;
static Int debugger_lwpid;
static Int debugger_notify[2];
static ThreadId stop_tid;
static Int stop_sig;

// GDB's register numbers for 'g', in order
#if defined(VGA_x86)
enum { rEAX = 0, rECX, rEDX, rEBX, rESP, rEBP, rESI, rEDI, 
       rEIP, rEFLAGS, rCS, rSS, rDS, rES, rFS, rGS, 
       rST0, rST1, rST2, rST3, rST4, rST5, rST6, rST7, 
       rFCTRL, rFSTAT, rFTAG, rFISEG, rFIOFF, rFOSEG, rFOOFF, rFOP, 
       rXMM0, rXMM1, rXMM2, rXMM3, rXMM4, rXMM5, rXMM6, rXMM7, 
       rMXCSR, 
       rcount, grcount = rST0 };
#define rPC rEIP
#define guest_PC guest_EIP

#elif defined(VGA_amd64)
// fixme check
enum { rRAX = 0, rRBX, rRCX, rRDX, rRSI, rRDI, rRBP, rRSP, 
       rR8,      rR9,  rR10, rR11, rR12, rR13, rR14, rR15, 
       rRIP, rRFLAGS, rCS, rSS, rDS, rES, rFS, rGS, 
       rST0, rST1, rST2, rST3, rST4, rST5, rST6, rST7, 
       rFCTRL, rFSTAT, rFTAG, rFISEG, rFIOFF, rFOSEG, rFOOFF, rFOP, 
       rXMM0, rXMM1, rXMM2, rXMM3, rXMM4, rXMM5, rXMM6, rXMM7, 
       rXMM8, rXMM9, rXMM10, rXMM11, rXMM12, rXMM13, rXMM14, rXMM15, 
       rMXCSR, 
       rcount, grcount = rST0 };
#define rPC rRIP
#define guest_PC guest_RIP

#else
#error unknown architecture
#endif

#if defined(VGA_x86)  ||  defined(VGA_amd64)
// hack - functions from vex
extern void convert_f64le_to_f80le ( const void *f64, void *f80 );
extern void convert_f80le_to_f64le ( const void *f80, void *f64 );
#endif

static void debuglog(const HChar *format, ...)
{
    if (VG_(clo_verbosity) > 1) {
        va_list vargs;
        va_start(vargs,format);
        VG_(vmessage) ( Vg_DebugMsg, format, vargs );
        va_end(vargs);
    }
}

static ThreadId first_valid_tid(void)
{
    ThreadId tid;
    for (tid = 0; tid < VG_N_THREADS; tid++) {
        if (VG_(is_valid_tid)(tid)) return tid;
    }
    return VG_INVALID_THREADID;
}

static void debugger_lock(Int sock)
{
    VG_(lock)();

    if (stop_tid) {
        query_tid = stop_tid;
        control_tid = stop_tid;
    } else {
        if (! VG_(is_valid_tid)(query_tid)) {
            query_tid = first_valid_tid();
        }
        if (! VG_(is_valid_tid)(control_tid)) {
            control_tid = first_valid_tid();
        }
    }

    // Flush commands already sent by gdb - it may have given up on 
    // them already and will be confused if we reply
    // This should only happen on initial connect, where we may accept the 
    // connection but not reply until the user answers "Attach to debugger ?"
    // On control-C or error report entry, gdb shouldn't say anything 
    // further until we send a stop reply.
    {
        int flags;
        char c;
        flags = VG_(fcntl)(sock, VKI_F_GETFL, 0);
        VG_(fcntl)(sock, VKI_F_SETFL, flags | VKI_O_NONBLOCK);
        while (1 == VG_(read)(sock, &c, 1)) 
            ;
        VG_(fcntl)(sock, VKI_F_SETFL, flags);
    }
}

static void debugger_unlock(void)
{
    if (stop_tid) {
        Int lwpid = VG_(threads)[stop_tid].os_state.lwpid;
        stop_tid = 0;
        stop_sig = 0;
        VG_(unlock_lwpid)(lwpid);
    } else {
        VG_(unlock)();
    }
}

static int reg_from_vex(ThreadId tid, Int regnum, void *rbuf, Int shadow)
{
    ThreadState *tst = &VG_(threads)[tid];

#if defined(VGA_x86)
    Addr w;
    VexGuestX86State *state;
    switch (shadow) {
    case 0: state = &tst->arch.vex; break;
    case 1: state = &tst->arch.vex_shadow1; break;
    case 2: state = &tst->arch.vex_shadow2; break;
    default: vg_assert(0);
    }

    switch (regnum) {
    case rEAX: VG_(memcpy)(rbuf, &state->guest_EAX, 4); return 4;
    case rECX: VG_(memcpy)(rbuf, &state->guest_ECX, 4); return 4;
    case rEDX: VG_(memcpy)(rbuf, &state->guest_EDX, 4); return 4;
    case rEBX: VG_(memcpy)(rbuf, &state->guest_EBX, 4); return 4;
    case rESP: VG_(memcpy)(rbuf, &state->guest_ESP, 4); return 4;
    case rEBP: VG_(memcpy)(rbuf, &state->guest_EBP, 4); return 4;
    case rESI: VG_(memcpy)(rbuf, &state->guest_ESI, 4); return 4;
    case rEDI: VG_(memcpy)(rbuf, &state->guest_EDI, 4); return 4;

    case rEIP: VG_(memcpy)(rbuf, &state->guest_EIP, 4); return 4;
    case rEFLAGS: 
        if (shadow) return 0;  // fixme
        w = LibVEX_GuestX86_get_eflags(state);
        VG_(memcpy)(rbuf, &w, 4);
        return 4;
    case rCS: VG_(memcpy)(rbuf, &state->guest_CS, 2); return 2;
    case rSS: VG_(memcpy)(rbuf, &state->guest_SS, 2); return 2;
    case rDS: VG_(memcpy)(rbuf, &state->guest_DS, 2); return 2;
    case rES: VG_(memcpy)(rbuf, &state->guest_ES, 2); return 2;
    case rFS: VG_(memcpy)(rbuf, &state->guest_FS, 2); return 2;
    case rGS: VG_(memcpy)(rbuf, &state->guest_GS, 2); return 2;

        // vex does not simulate 80-bit precision
        // fixme shift by FTOP?
    case rST0: 
    case rST1: 
    case rST2: 
    case rST3: 
    case rST4: 
    case rST5: 
    case rST6: 
    case rST7: 
        convert_f64le_to_f80le(&state->guest_FPREG[regnum-rST0], rbuf);
        return 10;

    case rFCTRL: {
        // vex only models the rounding bits (see libvex_guest_x86.h)
        UWord value = 0x037f;
        value |= state->guest_FPROUND << 10;
        VG_(memcpy)(rbuf, &value, 4); 
        return 4;
    }
    case rFSTAT: {
        UWord value = state->guest_FC3210;
        value |= (state->guest_FTOP & 7) << 11;
        VG_(memcpy)(rbuf, &value, 4); 
        return 4;
    }
    case rFTAG: {
        // vex doesn't model these precisely
        UWord value = 
            ((state->guest_FPTAG[0] ? 0 : 3) << 0)  | 
            ((state->guest_FPTAG[1] ? 0 : 3) << 2)  | 
            ((state->guest_FPTAG[2] ? 0 : 3) << 4)  | 
            ((state->guest_FPTAG[3] ? 0 : 3) << 6)  | 
            ((state->guest_FPTAG[4] ? 0 : 3) << 8)  | 
            ((state->guest_FPTAG[5] ? 0 : 3) << 10) | 
            ((state->guest_FPTAG[6] ? 0 : 3) << 12) | 
            ((state->guest_FPTAG[7] ? 0 : 3) << 14);
        VG_(memcpy)(rbuf, &value, 4); 
        return 4;
    }
    case rFISEG: 
    case rFIOFF:
    case rFOSEG:
    case rFOOFF:
    case rFOP: {
        // fixme lie
        UWord value = 0;
        VG_(memcpy)(rbuf, &value, 4);
        return 4;
    }

    case rXMM0: VG_(memcpy)(rbuf, &state->guest_XMM0, 16); return 16;
    case rXMM1: VG_(memcpy)(rbuf, &state->guest_XMM1, 16); return 16;
    case rXMM2: VG_(memcpy)(rbuf, &state->guest_XMM2, 16); return 16;
    case rXMM3: VG_(memcpy)(rbuf, &state->guest_XMM3, 16); return 16;
    case rXMM4: VG_(memcpy)(rbuf, &state->guest_XMM4, 16); return 16;
    case rXMM5: VG_(memcpy)(rbuf, &state->guest_XMM5, 16); return 16;
    case rXMM6: VG_(memcpy)(rbuf, &state->guest_XMM6, 16); return 16;
    case rXMM7: VG_(memcpy)(rbuf, &state->guest_XMM7, 16); return 16;

    case rMXCSR: {
        // vex only models the rounding bits (see libvex_guest_x86.h)
        UWord value = 0x1f80;
        value |= state->guest_SSEROUND << 13;
        VG_(memcpy)(rbuf, &value, 4); 
        return 4;
    }

    default:  vg_assert(0);
    }

#elif defined(VGA_amd64)
    Addr w;
    VexGuestAMD64State *state;
    switch (shadow) {
    case 0: state = &tst->arch.vex; break;
    case 1: state = &tst->arch.vex_shadow1; break;
    case 2: state = &tst->arch.vex_shadow2; break;
    default: vg_assert(0);
    }

    switch (regnum) {
    case rRAX: VG_(memcpy)(rbuf, &state->guest_RAX, 8); return 8;
    case rRCX: VG_(memcpy)(rbuf, &state->guest_RCX, 8); return 8;
    case rRDX: VG_(memcpy)(rbuf, &state->guest_RDX, 8); return 8;
    case rRBX: VG_(memcpy)(rbuf, &state->guest_RBX, 8); return 8;
    case rRSP: VG_(memcpy)(rbuf, &state->guest_RSP, 8); return 8;
    case rRBP: VG_(memcpy)(rbuf, &state->guest_RBP, 8); return 8;
    case rRSI: VG_(memcpy)(rbuf, &state->guest_RSI, 8); return 8;
    case rRDI: VG_(memcpy)(rbuf, &state->guest_RDI, 8); return 8;

    case rR8: VG_(memcpy)(rbuf, &state->guest_R8, 8); return 8;
    case rR9: VG_(memcpy)(rbuf, &state->guest_R9, 8); return 8;
    case rR10: VG_(memcpy)(rbuf, &state->guest_R10, 8); return 8;
    case rR11: VG_(memcpy)(rbuf, &state->guest_R11, 8); return 8;
    case rR12: VG_(memcpy)(rbuf, &state->guest_R12, 8); return 8;
    case rR13: VG_(memcpy)(rbuf, &state->guest_R13, 8); return 8;
    case rR14: VG_(memcpy)(rbuf, &state->guest_R14, 8); return 8;
    case rR15: VG_(memcpy)(rbuf, &state->guest_R15, 8); return 8;

    case rRIP: VG_(memcpy)(rbuf, &state->guest_RIP, 8); return 8;
    case rRFLAGS: 
        if (shadow) return 0;  // fixme
        w = LibVEX_GuestAMD64_get_rflags(state);
        VG_(memcpy)(rbuf, &w, 8);
        return 8;
    case rCS: return 0; // fixme state->guest_CS;
    case rSS: return 0; // fixme state->guest_SS;
    case rDS: return 0; // fixme state->guest_DS;
    case rES: return 0; // fixme state->guest_ES;
    case rFS: return 0; // fixme state->guest_FS;
    case rGS: 
        VG_(memcpy)(rbuf, &state->guest_GS_0x60, 8); return 8; // fixme state->guest_GS;

        // vex does not simulate 80-bit precision
        // fixme shift by FTOP?
    case rST0: 
    case rST1: 
    case rST2: 
    case rST3: 
    case rST4: 
    case rST5: 
    case rST6: 
    case rST7: 
        convert_f64le_to_f80le(&state->guest_FPREG[regnum-rST0], rbuf);
        return 10;

    case rFCTRL: {
        // vex only models the rounding bits (see libvex_guest_x86.h)
        UWord value = 0x037f;
        value |= state->guest_FPROUND << 10;
        VG_(memcpy)(rbuf, &value, 4); 
        return 4;
    }
    case rFSTAT: {
        UWord value = state->guest_FC3210;
        value |= (state->guest_FTOP & 7) << 11;
        VG_(memcpy)(rbuf, &value, 4); 
        return 4;
    }
    case rFTAG: {
        // vex doesn't model these precisely
        UWord value = 
            ((state->guest_FPTAG[0] ? 0 : 3) << 0)  | 
            ((state->guest_FPTAG[1] ? 0 : 3) << 2)  | 
            ((state->guest_FPTAG[2] ? 0 : 3) << 4)  | 
            ((state->guest_FPTAG[3] ? 0 : 3) << 6)  | 
            ((state->guest_FPTAG[4] ? 0 : 3) << 8)  | 
            ((state->guest_FPTAG[5] ? 0 : 3) << 10) | 
            ((state->guest_FPTAG[6] ? 0 : 3) << 12) | 
            ((state->guest_FPTAG[7] ? 0 : 3) << 14);
        VG_(memcpy)(rbuf, &value, 4); 
        return 4;
    }
    case rFISEG: 
    case rFIOFF:
    case rFOSEG:
    case rFOOFF:
    case rFOP: {
        // fixme lie
        UWord value = 0;
        VG_(memcpy)(rbuf, &value, 4);
        return 4;
    }

    case rXMM0: VG_(memcpy)(rbuf, &state->guest_XMM0, 16); return 16;
    case rXMM1: VG_(memcpy)(rbuf, &state->guest_XMM1, 16); return 16;
    case rXMM2: VG_(memcpy)(rbuf, &state->guest_XMM2, 16); return 16;
    case rXMM3: VG_(memcpy)(rbuf, &state->guest_XMM3, 16); return 16;
    case rXMM4: VG_(memcpy)(rbuf, &state->guest_XMM4, 16); return 16;
    case rXMM5: VG_(memcpy)(rbuf, &state->guest_XMM5, 16); return 16;
    case rXMM6: VG_(memcpy)(rbuf, &state->guest_XMM6, 16); return 16;
    case rXMM7: VG_(memcpy)(rbuf, &state->guest_XMM7, 16); return 16;
    case rXMM8: VG_(memcpy)(rbuf, &state->guest_XMM8, 16); return 16;
    case rXMM9: VG_(memcpy)(rbuf, &state->guest_XMM9, 16); return 16;
    case rXMM10: VG_(memcpy)(rbuf, &state->guest_XMM10, 16); return 16;
    case rXMM11: VG_(memcpy)(rbuf, &state->guest_XMM11, 16); return 16;
    case rXMM12: VG_(memcpy)(rbuf, &state->guest_XMM12, 16); return 16;
    case rXMM13: VG_(memcpy)(rbuf, &state->guest_XMM13, 16); return 16;
    case rXMM14: VG_(memcpy)(rbuf, &state->guest_XMM14, 16); return 16;
    case rXMM15: VG_(memcpy)(rbuf, &state->guest_XMM15, 16); return 16;

    case rMXCSR: {
        // vex only models the rounding bits (see libvex_guest_x86.h)
        UWord value = 0x1f80;
        value |= state->guest_SSEROUND << 13;
        VG_(memcpy)(rbuf, &value, 4); 
        return 4;
    }

    default:  vg_assert(0);
    }

#else
#error unknown architecture
#endif
}


static void reg_to_vex(ThreadId tid, Int regnum, const void *rbuf)
{
#if defined(VGA_x86)
    VexGuestX86State *state = &VG_(threads)[tid].arch.vex;

    switch (regnum) {
    case rEAX: VG_(memcpy)(&state->guest_EAX, rbuf, 4); break;
    case rECX: VG_(memcpy)(&state->guest_ECX, rbuf, 4); break;
    case rEDX: VG_(memcpy)(&state->guest_EDX, rbuf, 4); break;
    case rEBX: VG_(memcpy)(&state->guest_EBX, rbuf, 4); break;
    case rESP: VG_(memcpy)(&state->guest_ESP, rbuf, 4); break;
    case rEBP: VG_(memcpy)(&state->guest_EBP, rbuf, 4); break;
    case rESI: VG_(memcpy)(&state->guest_ESI, rbuf, 4); break;
    case rEDI: VG_(memcpy)(&state->guest_EDI, rbuf, 4); break;

    case rEIP: VG_(memcpy)(&state->guest_EIP, rbuf, 4); break;
    case rEFLAGS: break;// fixme LibVEX_GuestX86_put_eflags(state, value);
    case rCS: VG_(memcpy)(&state->guest_CS, rbuf, 2); break;
    case rSS: VG_(memcpy)(&state->guest_SS, rbuf, 2); break;
    case rDS: VG_(memcpy)(&state->guest_DS, rbuf, 2); break;
    case rES: VG_(memcpy)(&state->guest_ES, rbuf, 2); break;
    case rFS: VG_(memcpy)(&state->guest_FS, rbuf, 2); break;
    case rGS: VG_(memcpy)(&state->guest_GS, rbuf, 2); break;

        // vex does not simulate 80-bit precision
        // fixme shift by FTOP?
    case rST0: 
    case rST1: 
    case rST2: 
    case rST3: 
    case rST4: 
    case rST5: 
    case rST6: 
    case rST7: 
        convert_f80le_to_f64le(rbuf, &state->guest_FPREG[regnum-rST0]);
        break;

    case rXMM0: VG_(memcpy)(&state->guest_XMM0, rbuf, 16); break;
    case rXMM1: VG_(memcpy)(&state->guest_XMM1, rbuf, 16); break;
    case rXMM2: VG_(memcpy)(&state->guest_XMM2, rbuf, 16); break;
    case rXMM3: VG_(memcpy)(&state->guest_XMM3, rbuf, 16); break;
    case rXMM4: VG_(memcpy)(&state->guest_XMM4, rbuf, 16); break;
    case rXMM5: VG_(memcpy)(&state->guest_XMM5, rbuf, 16); break;
    case rXMM6: VG_(memcpy)(&state->guest_XMM6, rbuf, 16); break;
    case rXMM7: VG_(memcpy)(&state->guest_XMM7, rbuf, 16); break;

    default:  vg_assert(0);
    }

#elif defined(VGA_amd64)
    VexGuestAMD64State *state = &VG_(threads)[tid].arch.vex;

    switch (regnum) {
    case rRAX: VG_(memcpy)(&state->guest_RAX, rbuf, 8); break;
    case rRCX: VG_(memcpy)(&state->guest_RCX, rbuf, 8); break;
    case rRDX: VG_(memcpy)(&state->guest_RDX, rbuf, 8); break;
    case rRBX: VG_(memcpy)(&state->guest_RBX, rbuf, 8); break;
    case rRSP: VG_(memcpy)(&state->guest_RSP, rbuf, 8); break;
    case rRBP: VG_(memcpy)(&state->guest_RBP, rbuf, 8); break;
    case rRSI: VG_(memcpy)(&state->guest_RSI, rbuf, 8); break;
    case rRDI: VG_(memcpy)(&state->guest_RDI, rbuf, 8); break;

    case rR8:  VG_(memcpy)(&state->guest_R8,  rbuf, 8); break;
    case rR9:  VG_(memcpy)(&state->guest_R9,  rbuf, 8); break;
    case rR10: VG_(memcpy)(&state->guest_R10, rbuf, 8); break;
    case rR11: VG_(memcpy)(&state->guest_R11, rbuf, 8); break;
    case rR12: VG_(memcpy)(&state->guest_R12, rbuf, 8); break;
    case rR13: VG_(memcpy)(&state->guest_R13, rbuf, 8); break;
    case rR14: VG_(memcpy)(&state->guest_R14, rbuf, 8); break;
    case rR15: VG_(memcpy)(&state->guest_R15, rbuf, 8); break;

    case rRIP: VG_(memcpy)(&state->guest_RIP, rbuf, 8); break;
    case rRFLAGS: break;// fixme LibVEX_GuestX86_put_eflags(state, value);
    case rCS: /* fixme state->guest_CS = value; */ break;
    case rSS: /* fixme state->guest_SS = value; */ break;
    case rDS: /* fixme state->guest_DS = value; */ break;
    case rES: /* fixme state->guest_ES = value; */ break;
    case rFS: /* fixme state->guest_FS = value; */ break;
    case rGS: /* fixme state->guest_GS = value; */ break;

        // vex does not simulate 80-bit precision
        // fixme shift by FTOP?
    case rST0: 
    case rST1: 
    case rST2: 
    case rST3: 
    case rST4: 
    case rST5: 
    case rST6: 
    case rST7: 
        convert_f80le_to_f64le(rbuf, &state->guest_FPREG[regnum-rST0]);
        break;

    case rXMM0: VG_(memcpy)(&state->guest_XMM0, rbuf, 16); break;
    case rXMM1: VG_(memcpy)(&state->guest_XMM1, rbuf, 16); break;
    case rXMM2: VG_(memcpy)(&state->guest_XMM2, rbuf, 16); break;
    case rXMM3: VG_(memcpy)(&state->guest_XMM3, rbuf, 16); break;
    case rXMM4: VG_(memcpy)(&state->guest_XMM4, rbuf, 16); break;
    case rXMM5: VG_(memcpy)(&state->guest_XMM5, rbuf, 16); break;
    case rXMM6: VG_(memcpy)(&state->guest_XMM6, rbuf, 16); break;
    case rXMM7: VG_(memcpy)(&state->guest_XMM7, rbuf, 16); break;
    case rXMM8: VG_(memcpy)(&state->guest_XMM8, rbuf, 16); break;
    case rXMM9: VG_(memcpy)(&state->guest_XMM9, rbuf, 16); break;
    case rXMM10: VG_(memcpy)(&state->guest_XMM10, rbuf, 16); break;
    case rXMM11: VG_(memcpy)(&state->guest_XMM11, rbuf, 16); break;
    case rXMM12: VG_(memcpy)(&state->guest_XMM12, rbuf, 16); break;
    case rXMM13: VG_(memcpy)(&state->guest_XMM13, rbuf, 16); break;
    case rXMM14: VG_(memcpy)(&state->guest_XMM14, rbuf, 16); break;
    case rXMM15: VG_(memcpy)(&state->guest_XMM15, rbuf, 16); break;

    default:  vg_assert(0);
    }

#else
#error unknown architecture
#endif
}


Int VG_(reg_for_regnum)(Int regnum, void *rbuf, Int shadow)
{
    // fixme sanitize tid?
    return reg_from_vex(query_tid, regnum, rbuf, shadow);
}


static Bool VG_(isxdigit)(int c)
{
    if (c >= '0'  &&  c <= '9') return True;
    if (c >= 'a'  &&  c <= 'f') return True;
    if (c >= 'A'  &&  c <= 'F') return True;
    return False;
}

static Int fromhex(char c)
{
    if (c >= '0'  &&  c <= '9') return c - '0';
    if (c >= 'a'  &&  c <= 'z') return c - 'a' + 10;
    if (c >= 'A'  &&  c <= 'F') return c - 'A' + 10;
    return -1;
}

// len is in BINARY BYTES (sizeof bin, not dst)
static void hexify(char *dst, const void *bin, Int len)
{
    const UChar *src = (const UChar *)bin;
    const UChar *end = src + len;

    for ( ; src < end; src++) {
        *dst++ = xdigit[*src >> 4];
        *dst++ = xdigit[*src & 0xf];
    }
    *dst++ = 0;
}

// len is in BINARY BYTES (sizeof bin, not src)
static void binify(void *bin, const char *src, Int len)
{
    UChar *dst = (UChar *)bin;
    UChar *end = dst + len;

    for ( ; dst < end; dst++) {
        *dst = fromhex(*src++) * 16;
        *dst += fromhex(*src++);
    }
}

// like binify, but can write to read-only memory
static void binify_force(void *bin, unsigned char *src, Int len)
{
    mach_vm_address_t vmaddr = (mach_vm_address_t)(uintptr_t)bin;
    mach_vm_size_t vmsize = len;
    vm_region_flavor_t flavor = VM_REGION_BASIC_INFO_64;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    vm_region_basic_info_data_64_t data;
    mach_port_t unused;
    kern_return_t kr;
    
    kr = mach_vm_region(mach_task_self(), &vmaddr, &vmsize, 
                        flavor, (vm_region_info_t)&data, &count, &unused);
    if (kr) debuglog("debugger: mach_vm_region failed (%d)", kr);
    kr = mach_vm_protect(mach_task_self(), vmaddr, vmsize, 
                         0, VM_PROT_READ|VM_PROT_WRITE);
    if (kr) debuglog("debugger: mach_vm_protect failed (%d)", kr);

    binify(bin, src, len);

    kr = mach_vm_protect(mach_task_self(), vmaddr, vmsize, 0, data.protection);
    if (kr) debuglog("debugger: mach_vm_protect failed (%d)", kr);
}

static ThreadId current_tid(void)
{
    ThreadId tid = VG_(last_running_tid);
    if (VG_(is_valid_tid)(tid)) {
        return tid;
    }

    // find a new thread
    for (tid = 1; tid < VG_N_THREADS; tid++) {
        if (VG_(is_valid_tid)(tid)) {
            return tid;
        }
    }

    return 0;
}


static Int listen_to(Int port)
{
    Int opt;
    Int serv;
    Int err;
    vki_socklen_t size;
    struct vki_sockaddr_in addr = { sizeof(struct vki_sockaddr_in), VKI_AF_INET, VG_(htons)(port), {VG_(htonl)(VKI_INADDR_LOOPBACK)} };

    serv = VG_(socket)(VKI_AF_INET, VKI_SOCK_STREAM, 0);
    if (serv < 0) {
        return -1;
    }
    serv = VG_(safe_fd)(serv);
    if (serv < 0) {
        return -1;
    }

    // set SO_REUSEADDR to help prevent "address already in use" errors
    opt = 1;
    VG_(setsockopt)(serv, VKI_SOL_SOCKET, VKI_SO_REUSEADDR, &opt, sizeof(opt));

    size = sizeof(addr);
    err = VG_(bind)(serv, (struct vki_sockaddr *)&addr, size);
    if (err < 0) {
        VG_(close)(serv);
        return -1;
    }

    err = VG_(listen)(serv, 1);
    if (err < 0) {
        VG_(close)(serv);
        return -1;
    }

    return serv;
}



static Int accept_from(Int serv)
{
    Int sock;
    struct vki_sockaddr_in addr;
    vki_socklen_t size;
    
    size = sizeof(addr);
    sock = VG_(accept)(serv, (struct vki_sockaddr *)&addr, &size);
    if (sock < 0) {
        return -1;
    }
    sock = VG_(safe_fd)(sock);
    if (sock < 0) {
        return -1;
    }

    return sock;
}


static char *read_command(Int sock)
{
    char checksum[2];
    char *p = msgbuf;
    Int count;
    char c;

    // read '$'
    do {
        count = VG_(read)(sock, &c, 1);
    } while (count == 1  &&  c != '$');
    if (count != 1) {
        debuglog("debugger: failed while looking for '$'");
        return NULL;
    }

    // read through '#'
    do {
        count = VG_(read)(sock, &c, 1);
        *p++ = c;
        if (p == msgbuf+msgbufsize) {
            debuglog("debugger: command too large");
            return NULL;
        }
    } while (count == 1  &&  c != '#');
    if (count != 1) {
        debuglog("debugger: failed while looking for '#'");
        return NULL;
    }
    vg_assert(p > msgbuf  &&  p < msgbuf+msgbufsize);
    p[-1] = 0;  // overwrite '#'

    // read checksum
    do {
        count = VG_(read)(sock, &checksum[0], 1);
    } while (count != 1);
    if (count != 1) {
        debuglog("debugger: failed while looking for checksum digit");
        return NULL;
    }
    do {
        count = VG_(read)(sock, &checksum[1], 1);
    } while (count != 1);
    if (count != 1) {
        debuglog("debugger: failed while looking for checksum digit");
        return NULL;
    }

    // check checksum
    // fixme actually do the sum
    if (!VG_(isxdigit)(checksum[0])  ||  !VG_(isxdigit)(checksum[1])) {
        debuglog("bad checksum digits %c%c", checksum[0], checksum[1]);
    }

    // acknoledge
    VG_(write)(sock, "+", 1);

    debuglog("debugger: received command '%s'", msgbuf);

    return VG_(arena_strdup)(VG_AR_CORE, "debugstub.msg", msgbuf);
}


static void write_command(Int sock, const char *cmd)
{
    const char *p;
    unsigned int sum = 0;
    char suffix[3];
    // Int count;
    // char c;

    // compute checksum
    for (p = cmd; *p; p++) {
        sum += (unsigned char)*p;
    }
    sum &= 0xff;

    suffix[0] = '#';
    suffix[1] = xdigit[sum >> 4];
    suffix[2] = xdigit[sum & 0x0f];
    
    // write $cmd#ck
    VG_(write)(sock, "$", 1);
    VG_(write)(sock, cmd, VG_(strlen)(cmd));
    VG_(write)(sock, suffix, sizeof(suffix));
    debuglog("debugger: sent command '%s'", cmd);

    // read '+'
    /*
    do {
        count = read(sock, &c, 1);
    } while (count == 1);
    if (count != 1  ||  c != '+') return fail("packet not acknowledged");
    */
}

static void list_threads(Int sock)
{
    ThreadId tid;
    char *p;
    char prefix;

    prefix = 'm';  // first thread starts with 'm'
    p = outbuf;
    for (tid = 1; tid < VG_N_THREADS; tid++) {
        if (VG_(is_valid_tid)(tid)) {
            p += VG_(sprintf)(p, "%c%08x", prefix, tid);
            prefix = ',';  // comma-separated after first
        }
    }
    write_command(sock, outbuf);
}

static void handle_m(Int sock, char *cmd)
{
    Long addr, len;

    addr = VG_(atoll16)(cmd);
    cmd = VG_(strchr)(cmd, ',');
    if (!cmd) {
        write_command(sock, "E01"); // fixme errno
        return;
    }
    len = VG_(atoll16)(cmd+1);
    if (len > (sizeof(outbuf)-1) / 2) len = (sizeof(outbuf)-1) / 2;

    if (! VG_(am_is_valid_for_client)((Addr)addr, (SizeT)len, VKI_PROT_READ)) {
        write_command(sock, "E14");  // fixme EFAULT
        return;
    }
    
    hexify(outbuf, (char *)(Addr)addr, len);
    write_command(sock, outbuf);
}

static void handle_M(Int sock, char *cmd)
{
    Long addr, len;
    unsigned char *inbuf;

    addr = VG_(atoll16)(cmd);

    cmd = VG_(strchr)(cmd, ',');
    if (!cmd) {
        write_command(sock, "E01"); // fixme errno
        return;
    }
    len = VG_(atoll16)(cmd+1);

    if (! VG_(am_is_valid_for_client)((Addr)addr, (SizeT)len, VKI_PROT_READ)) {
        write_command(sock, "E14");  // fixme EFAULT
        return;
    }

    inbuf = VG_(strchr)(cmd, ':');
    if (!inbuf) {
        write_command(sock, "E01");
        return;
    }
    inbuf++;

    binify_force((char *)(Addr)addr, inbuf, len);
    VG_TRACK( post_mem_write, Vg_CoreClientReq/*fixme?*/, 1/*fixme*/, addr, len);
    VG_(discard_translations)(addr, len, "debugger(M)");

    write_command(sock, "OK");
}



static Bool handle_q_valgrind(Int sock, char *cmd)
{
    Bool handled = True;  // False means unknown valgrind query command
    Char *toolname = VG_(details).name;
    Int toollen = VG_(strlen)(VG_(details).name);

    debuglog("qvalgrind command %s", cmd);

    if (VG_(needs).debugger_commands  &&  
        VG_(tdict).tool_handle_debugger_query  &&  
        0 == VG_(strncmp)(cmd, toolname, toollen)  &&  
        cmd[toollen] == '.')
    {
        debuglog("forwarding %s to tool", cmd);
        handled = VG_(tdict).tool_handle_debugger_query(sock, cmd+toollen+1);
    }
    /*
    else if (0 == VG_(strncmp)(cmd, "core.", 5)) {
        // any core-provided commands go here
    }
    */
    else {
        handled = False;
    }

    return handled;
}

static Bool handle_q(Int sock, char *cmd)
{
    Bool handled = True;  // False means unknown query command

    debuglog("q command %s", cmd);

    if (0 == VG_(strcmp)(cmd, "C")) {
        // current thread
        VG_(sprintf)(outbuf, "QC%04x", current_tid());
        write_command(sock, outbuf);
    }
    else if (0 == VG_(strcmp)(cmd, "fThreadInfo")) {
        // thread list
        list_threads(sock);
    }
    else if (0 == VG_(strcmp)(cmd, "sThreadInfo")) {
        // fThreadInfo continuation - we did it all the first time
        write_command(sock, "l");
    }
    else if (0 == VG_(strcmp)(cmd, "Offsets")) {
        // text and data offsets
        // fixme hack
        write_command(sock, "Text=0;Data=0;Bss=0");
    }
    else if (0 == VG_(strcmp)(cmd, "valgrind")) {
        // valgrind existence query - reply with tool name
        write_command(sock, VG_(details).name);
    }
    else if (0 == VG_(strncmp)(cmd, "valgrind.", 9)) {
        // valgrind subcommand
        handled = handle_q_valgrind(sock, cmd+9);
    }
    else {
        // unknown query
        handled = False;
    }

    return handled;
}


static Bool handle_Q_valgrind(Int sock, char *cmd)
{
    Bool handled = True;  // False means unknown valgrind action command
    Char *toolname = VG_(details).name;
    Int toollen = VG_(strlen)(VG_(details).name);

    if (VG_(needs).debugger_commands  &&  
        VG_(tdict).tool_handle_debugger_action  &&  
        0 == VG_(strncmp)(cmd, toolname, toollen)  &&  
        cmd[toollen] == '.')
    {
        debuglog("forwarding %s to tool", cmd);
        handled = VG_(tdict).tool_handle_debugger_action(sock, cmd+toollen+1);
    }
    /*
    else if (0 == VG_(strncmp)(cmd, "core.", 5)) {
        // any core-provided commands go here
    }
    */
    else {
        handled = False;
    }

    return handled;
}

static Bool handle_Q(Int sock, char *cmd)
{
    Bool handled = True;  // False means unknown action command
    
    if (0 == VG_(strncmp)(cmd, "valgrind.", 10)) {
        // valgrind subcommand
        handled = handle_Q_valgrind(sock, cmd+10);
    }
    else {
        // unknown query
        handled = False;
    }

    return handled;
}


__attribute__((unused))
static Bool handle_v(Int sock, char *cmd)
{
    if (0 == VG_(strncmp)(cmd, "Cont", 4)) {
        // vCont
        if (0 == VG_(strcmp)(cmd, "Cont?")) {
            // capability query
            // fixme can't really handle C/s/S, but gdb won't use c otherwise
            write_command(sock, "vCont;c;C;s;S");
            return True;
        }
        else if (0 == VG_(strncmp)(cmd, "Cont;", 5)) {
            // continue command
            ThreadId tid = -1;
            Bool continueOthers = True;

            cmd += 5;
            // fixme this only handles a subset of possible vCont commands, 
            // but gdb only generates a subset anyway
            // fixme incorrect C/S/s handling
            switch (cmd[0]) {
            case 'c':
            case 's':
                cmd++;
                break;
            case 'C':
            case 'S':
                cmd += 3;  // skip signal number
                break;
            default:
                return False;
            }
            if (cmd[0] == ':') {
                // target thread ID
                tid = VG_(atoll16)(cmd+1);
                continueOthers = False;
            }

            // command for other threads - assume 'c' or empty
            cmd = VG_(strchr)(cmd, ';');
            if (cmd) {
                if (cmd[0] == 'c') continueOthers = True;
            }

            if (tid != -1  &&  !continueOthers) {
                // Run tid only
            } else if (tid) {
                // Run all threads, tid first
            } else {
                // Run all threads
            }

            return True;
        }
    }

    return False;
}


static void handle_p(Int sock, char *cmd)
{
    char rbuf[16];
    int rsize;
    Long reg = VG_(atoll16)(cmd);
    if (!VG_(is_valid_tid)(query_tid)) {
        write_command(sock, "E01"); // fixme errno
    } else if (reg < 0  ||  reg >= rcount) {
        write_command(sock, "E01");
    } else {
        rsize = reg_from_vex(query_tid, reg, rbuf, 0);
        hexify(outbuf, rbuf, rsize);
        write_command(sock, outbuf);
    }
}

static void handle_P(Int sock, char *cmd)
{
    uint8_t rbuf[16] = {0};
    int rsize;

    Long reg = VG_(atoll16)(cmd);
    cmd = VG_(strchr)(cmd, '=');
    if (!cmd) {
        write_command(sock, "E01");
        return;
    }
    cmd++;
    
    rsize = VG_(strlen)(cmd) / 2;
    vg_assert(rsize <= 16);
    binify(rbuf, cmd, rsize);
    /*
    char oldbuf[16];
    int oldsize = reg_from_vex(query_tid, reg, oldbuf, 0);
    if (rsize == oldsize  &&  0 == VG_(memcmp)(rbuf, oldbuf, rsize)) {
        // no change - ok for any register
        write_command(sock, "OK");
        return;
    }
    */
    // fixme can't change all registers all the time
    // - can't change PC during error report
    // - other registers during error report?
    if (reg == rPC  &&  stop_sig != 5) {
        write_command(sock, "E01");
        return;
    }
    reg_to_vex(query_tid, reg, rbuf);
    debuglog("pc %p", VG_(threads)[query_tid].arch.vex.guest_PC);
    write_command(sock, "OK");
}

static void handle_T(Int sock, char *cmd)
{
    Long tid = VG_(atoll16)(cmd);
    if (VG_(is_valid_tid)(tid)) {
        write_command(sock, "OK");
    } else {
        write_command(sock, "E01");
    }
}

static void handle_g(Int sock)
{
    Addr regs[grcount];
    Int r;

    if (!VG_(is_valid_tid)(query_tid)) {
        write_command(sock, "E01"); // fixme errno
        return;
    }

    for (r = 0; r < grcount; r++) {
        reg_from_vex(query_tid, r, &regs[r], 0);
    }

    hexify(outbuf, (char *)regs, sizeof(regs));
    write_command(sock, outbuf);
}


static void handle_G(Int sock, char *cmd)
{
    Addr regs[grcount];
    Int r;

    if (!VG_(is_valid_tid)(query_tid)) {
        write_command(sock, "E01"); // fixme errno
        return;
    }

    if (VG_(strlen)(cmd) != 2 * sizeof(regs)) {
        write_command(sock, "E01"); // fixme errno
        return;
    }

    binify((char *)regs, cmd, sizeof(regs));

    for (r = 0; r < grcount; r++) {
        reg_to_vex(query_tid, r, &regs[r]);
    }

    write_command(sock, "OK");
}


static Bool handle_why(Int sock)
{
    if (stop_tid) {
        VG_(sprintf)(outbuf, "T%02xthread:%x;", stop_sig, stop_tid);
    } else {
        VG_(sprintf)(outbuf, "T%02xthread:%x;", 0, query_tid);
    }
    write_command(sock, outbuf);
    return True;
}

// run until remote debugger or local tools asks us to stop
// return False if debugger disconnects
static Bool do_continue(Int sock)
{
    Bool halt = False;

    VG_(message)(Vg_UserMsg, "Continuing.");

    debugger_unlock();

    while (1) {
        int selected;
        int nfds = 1 + (sock > debugger_notify[0] ? sock : debugger_notify[0]);
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        FD_SET(debugger_notify[0], &fds);
        selected = VG_(select)(nfds, &fds, NULL, NULL, NULL);

        if (FD_ISSET(sock, &fds)) {
            char c;
            Int count = VG_(read)(sock, &c, 1);
            if (count != 1) {
                halt = True; 
                break;
            } else if (c == 0x03) {
                break;
            }
        }
        if (FD_ISSET(debugger_notify[0], &fds)) {
            Int count = VG_(read)(debugger_notify[0], &stop_tid, sizeof(stop_tid));
            count += VG_(read)(debugger_notify[0], &stop_sig, sizeof(stop_sig));
            if (count == sizeof(stop_tid)+sizeof(stop_sig)) {
                break;
            } else {
                stop_tid = 0;
                stop_sig = 0;
            }
        }
    }

    debugger_lock(sock);

    if (halt) {
        debuglog("debugger: failed while continuing");
        return False;
    } else if (stop_tid) {
        debuglog("debugger: stopped by thread %d", stop_tid);
    } else {
        debuglog("debugger: stopped by remote debugger interrupt");
    }

    VG_(message)(Vg_UserMsg, "Stopped in debugger.");

    handle_why(sock);

    return True;
}

static Bool handle_command(Int sock, char *cmd)
{
    Bool handled = True;   // False means unknown command
    Bool result = True;    // False means disconnect

    if (0 == VG_(strcmp)(cmd, "?")) {
        // ?: query stop reason
        handled = handle_why(sock);
    }
    else if (0 == VG_(strcmp)(cmd, "c")) {
        // c: continue
        result = do_continue(sock);
    } 
    else if (0 == VG_(strcmp)(cmd, "s")) {
        // s: single-step
        // GrP fixme sorry
        result = do_continue(sock);
    } 
    else if (0 == VG_(strcmp)(cmd, "D")) {
        // D: debugger detach - disconnect
        write_command(sock, "OK");
        result = False; 
    }
    else if (0 == VG_(strcmp)(cmd, "g")) {
        // g: read all registers
        handle_g(sock);
    }
    else if (cmd[0] == 'G') {
        // Gxx...: write registers
        handle_G(sock, cmd+1);
    }
    else if (cmd[0] == 'H') {
        // Hcxx, Hgxx: set thread focus
        if (cmd[1] == 'g' || cmd[1] == 'c') {
            ThreadId tid = VG_(atoll16)(cmd+2);
            // fixme -1
            if (tid == 0) {
                tid = first_valid_tid();
            }
            if (VG_(is_valid_tid)(tid)) {
                if (cmd[1] == 'g') query_tid = tid;
                else control_tid = tid;
                write_command(sock, "OK");
            } else {
                write_command(sock, "E01"); // fixme error number
            }
        } else {
            // huh?
            handled = False;
        }
    }
    else if (cmd[0] == 'm') {
        // m...: read memory
        handle_m(sock, cmd+1);
    }
    else if (cmd[0] == 'M') {
        // m...: write memory
        handle_M(sock, cmd+1);
    }
    else if (cmd[0] == 'p') {
        // pxx: read register
        handle_p(sock, cmd+1);
    }
    else if (cmd[0] == 'P') {
        // Pxx: write register
        handle_P(sock, cmd+1);
    }
    else if (cmd[0] == 'q') {
        // q...: query something
        handled = handle_q(sock, cmd+1);
    }
    else if (cmd[0] == 'Q') {
        // Q...: set something
        handled = handle_Q(sock, cmd+1);
    }
    else if (cmd[0] == 'T') {
        // Txx: thread alive check
        handle_T(sock, cmd+1);
    }
    /*else if (cmd[0] == 'v') {
        // v...: vCont
        // fixme can't support all of vCont
        handled = handle_v(sock, cmd+1);
    }*/
    else {
        // unknown command
        handled = False;
    }

    if (!handled) {
        // unknown command - reply with empty string
        write_command(sock, "");
    }

    VG_(arena_free)(VG_AR_CORE, cmd);

    return result;
}


static void debugstub_thread(void)
{
    Int serv, sock;
    Int port = VG_(clo_db_listen_port);

    // fixme VG_(message) is technically invalid without VG_(lock)

    // set up debugger notification pipe
    VG_(pipe)(debugger_notify);
    debugger_notify[0] = VG_(safe_fd)(debugger_notify[0]);
    debugger_notify[1] = VG_(safe_fd)(debugger_notify[1]);

    serv = listen_to(port);
    if (serv < 0) {
        char c;
        VG_(message)(Vg_UserMsg, "debugger: couldn't listen on port %d", port);
        VG_(message)(Vg_UserMsg, "No debugger can attach.");

        // block forever
        while (1) VG_(read)(debugger_notify[0], &c, 1);
    }

    debugger_running = True;
    debugger_lwpid = mach_thread_self();

    while (1) {
        char *cmd;

        stop_tid = 0;
        stop_sig = 0;

        // wait for a debugger or a thread error
        VG_(message)(Vg_UserMsg, "Listening for debugger on port %d", port);
        while (1) {
            fd_set rfds;
            int nfds = 1 + (serv > debugger_notify[0] ? serv : debugger_notify[0]);
            FD_ZERO(&rfds);
            FD_SET(serv, &rfds);
            FD_SET(debugger_notify[0], &rfds);
            VG_(select)(nfds, &rfds, NULL, NULL, NULL);
            
            if (FD_ISSET(debugger_notify[0], &rfds)) {
                Int count = VG_(read)(debugger_notify[0], &stop_tid, sizeof(stop_tid));
                count += VG_(read)(debugger_notify[0], &stop_sig, sizeof(stop_sig));
                if (count == sizeof(stop_tid)+sizeof(stop_sig)) {
                    // thread error report, but no debugger attached yet
                    // stop_tid is suspended and holds VG_(lock) on our behalf
                    // Continue waiting for a debugger.
                    VG_(message)(Vg_UserMsg, "Stopped until a debugger attaches.");
                    VG_(message)(Vg_UserMsg, "Attach with:");
                    VG_(message)(Vg_UserMsg, "    valgrind-gdb %s", VG_(args_the_exename));
                    VG_(message)(Vg_UserMsg, "    target remote :%d", port);
                }
            }
            if (FD_ISSET(serv, &rfds)) {
                sock = accept_from(serv);
                if (sock >= 0) break;
            }
        }

        // debugger attached
        debugger_lock(sock);
        VG_(message)(Vg_UserMsg, "Debugger attached.");
        VG_(message)(Vg_UserMsg, "Stopped in debugger.");

        // process commands
        while ((cmd = read_command(sock))  &&  
               handle_command(sock, cmd))
            ;

        // debugger disconnected
        VG_(message)(Vg_UserMsg, "Debugger disconnected.");
        VG_(message)(Vg_UserMsg, "Continuing.");
        VG_(close)(sock);

        debugger_unlock();
    }
}



void VG_(debugstub_init)(void)
{
    VG_(start_helper_thread)(&debugstub_thread);
}


void VG_(start_debugger_signal)(ThreadId tid, Int sig)
{
    if (debugger_running) {
        VG_(write)(debugger_notify[1], &tid, sizeof(tid));
        VG_(write)(debugger_notify[1], &sig, sizeof(sig));

        VG_(unlock_lwpid)(debugger_lwpid);
        // debugger runs here, then gives lock back to us
        VG_(lock)();
    }
}

void VG_(start_debugger)(ThreadId tid)
{
    VG_(start_debugger_signal)(tid, 0);
}


// Functions for tools

void VG_(debugstub_write_reply)(Int sock, const Char* contents)
{
    write_command(sock, (const char *)contents);
}


void VG_(debugstub_tohex)(Char *dst, const void *src, Int len)
{
    hexify((char *)dst, src, len);
}

void VG_(debugstub_fromhex)(void *dst, const Char *src, Int len)
{
    binify(dst, (const char *)src, len);
}
