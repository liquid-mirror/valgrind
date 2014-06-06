
/*--------------------------------------------------------------------*/
/*--- Startup: create initial process image on BlueGene            ---*/
/*---                                                initimg-bgq.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2006-2012 OpenWorks LLP
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

#if defined(VGPV_ppc64_linux_bgq)

#include "pub_core_basics.h"
#include "pub_core_vki.h"
#include "pub_core_debuglog.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcfile.h"
#include "pub_core_libcproc.h"
#include "pub_core_libcprint.h"
#include "pub_core_xarray.h"
#include "pub_core_clientstate.h"
#include "pub_core_aspacemgr.h"
#include "pub_core_mallocfree.h"
#include "pub_core_machine.h"
#include "pub_core_ume.h"
#include "pub_core_options.h"
#include "pub_core_tooliface.h"       /* VG_TRACK */
#include "pub_core_libcsetjmp.h"      // to keep _threadstate.h happy
#include "pub_core_threadstate.h"     /* ThreadArchState */
#include "pub_core_initimg.h"         /* self */

/* Create the client's initial memory image. */

IIFinaliseImageInfo VG_(ii_create_image)( IICreateImageInfo iicii )
{
   IIFinaliseImageInfo iifii;
   VG_(memset)( &iifii, 0, sizeof(iifii) );

   iifii.clstack_max_size  = 0; /* not known yet */
   iifii.initial_client_SP = iicii.sp_at_startup;
   iifii.have_hardwired_args = False; /* not known yet */
   { extern void _start;
     Addr* desc = (Addr*)&_start;
     iifii.initial_client_IP = desc[0]; // entry point for _start
     iifii.r2_at_startup     = desc[1]; // the TOCptr for _start
   }

   // This is a bit of a kludge, but at least putting it here
   // is consistent with the other platforms (linux)
   VG_(machine_ppc64_set_clszB)( 64 );

   Addr s_min = 0, s_max = 0;
   VG_(amo_get_stack_segment)( &s_min, &s_max );
   /* Basic sanity checks -- we actually have a stack, and it's at least 64k */
   vg_assert(s_min > 0 && s_max > 0 && s_min < s_max);
   vg_assert(s_min + 65536 <= s_max); 

   iifii.clstack_max_size = s_max - s_min + 1;

   /* Record stack extent -- needed for stack-change code. */
   // FIXME .. is this right?
   VG_(clstk_base) = s_min;
   VG_(clstk_end)  = s_max;

   return iifii;
}


/* Just before starting the client, we may need to make final
   adjustments to its initial image.  Also we need to set up the VEX
   guest state for thread 1 (the root thread) and copy in essential
   starting values.  This is handed the IIFinaliseImageInfo created by
   VG_(ii_create_image).
*/
void VG_(ii_finalise_image)( IIFinaliseImageInfo iifii )
{
   ThreadArchState* arch = &VG_(threads)[1].arch;

   /* On BlueGene we get client_{ip/sp/toc}, and start the client with
      all other registers zeroed. */

   vg_assert(0 == sizeof(VexGuestPPC64State) % 16);

   /* Zero out the initial state, and set up the simulated FPU in a
      sane way. */
   LibVEX_GuestPPC64_initialise(&arch->vex);

   /* Zero out the shadow areas. */
   VG_(memset)(&arch->vex_shadow1, 0, sizeof(VexGuestPPC64State));
   VG_(memset)(&arch->vex_shadow2, 0, sizeof(VexGuestPPC64State));

   /* Put essential stuff into the new state. */
   arch->vex.guest_GPR1 = iifii.initial_client_SP;
   arch->vex.guest_GPR2 = iifii.r2_at_startup;
   arch->vex.guest_CIA  = iifii.initial_client_IP;

   /* For startup of a statically linked binary, viz, a jump to
      _start, we have R1 (the stack pointer) pointing at the
      following, and R3 (the first arg register) == R1 (afaict):

      argc  argv[0] .. argv[argc-1] NULL envp[0] ... NULL auxv

      Hence just point R3 at whatever R1 is pointing at.
   */
   arch->vex.guest_GPR3 = arch->vex.guest_GPR1;

   // for argc/argv debugging
   if (0) {
      ULong*  p    = (ULong*)arch->vex.guest_GPR1;
      Long    argc = p[0];
      UChar** argv = (UChar**)&p[1];
      UChar** envp = (UChar**)&p[1+argc+1];
      Long i;
      VG_(printf)("<<<< BEFORE\n");
      VG_(printf)("ARGC %lld\n", argc);
      for (i = 0; i < argc; i++)
         VG_(printf)("ARGV %lld %s\n", i, argv[i]);
      vg_assert(envp[-1] == 0);
      for (; *envp; envp++)
         VG_(printf)("ENVP %s\n", *envp);
      VG_(printf)(">>>> BEFORE\n");
   }

   { /* Monkey around with argc/argv so the client doesn't see the
        args intended for Valgrind.  Do this by moving argv forward
        enough to move past the args intended for Valgrind, and the
        separating "--", copying argv[0] over the latter, so the
        program sees its own executable name in argv[0], and
        decreasing argc accordingly. */
     Long    i;
     Long*   p      = (Long*)arch->vex.guest_GPR1;
     Long    t_argc = p[0];
     HChar** t_argv = (HChar**)&p[1];
     vg_assert(t_argc > 0 && t_argc < 1000000); /* stay sane */

     if (0)
        VG_(debugLog)(0,"initimg", "GPR1 before = 0x%llx\n",
                      arch->vex.guest_GPR1);

     /* Find new place for argv[0].  Either just before terminating
        zero of argv, or on the "--", whichever appears first. */
     i = 0;
     if (!iifii.have_hardwired_args) {
        while (1) {
           vg_assert(i <= t_argc);
           if (0 == t_argv[i]) {
              i--;
              break;
           }
           if (0 == VG_(strcmp)(t_argv[i], "--"))
              break;
           i++;
        }
     } else {
        /* If there are hardwired args to V, we don't want to mess
           with the args or exename for the client at all.  So leave i
           at zero. */
     }

     vg_assert(i >= 0 && i < t_argc);
     t_argv[i] = t_argv[0];
     t_argv += i;
     t_argc -= i;

     /* Now reinstall argc/argv in the guest image.  This implies
        modifying it, but I think that's OK since by now we have copied
        out all the arguments intended for Valgrind.  Update R3
        accordingly, as per comments above. */
     t_argv[-1] = (HChar*)t_argc;
     arch->vex.guest_GPR1 = (ULong)&t_argv[-1];
     arch->vex.guest_GPR3 = arch->vex.guest_GPR1;

     // R3 = argc
     arch->vex.guest_GPR3 = t_argc;
     // R4 = argv
     arch->vex.guest_GPR4 = (ULong)&t_argv[0];
     // R5 = envp
     arch->vex.guest_GPR5 = (ULong)&t_argv[t_argc+1];
     // R6 = auxv
     { ULong* p2 = (ULong*)arch->vex.guest_GPR5;
       while (*p2) p2++;
       p2++;
       arch->vex.guest_GPR6 = (ULong)p2;
     }
     // R7 (term fn ptr) = 0
     arch->vex.guest_GPR7 = 0;
     // R1 is 16-aligned and points to a zero
     arch->vex.guest_GPR1 -= 32;
     arch->vex.guest_GPR1 &= ~31ULL;
     *(ULong*)arch->vex.guest_GPR1 = 0;
   }

   // for argc/argv debugging
   if (0) {
      ULong*  p    = (ULong*)arch->vex.guest_GPR1;
      Long    argc = p[0];
      UChar** argv = (UChar**)&p[1];
      UChar** envp = (UChar**)&p[1+argc+1];
      Long i;
      VG_(printf)("<<<< AFTER\n");
      VG_(printf)("ARGC %lld\n", argc);
      for (i = 0; i < argc; i++)
         VG_(printf)("ARGV %lld %s\n", i, argv[i]);
      vg_assert(envp[-1] == 0);
      for (; *envp; envp++)
         VG_(printf)("iimg ENVP %s\n", *envp);
      VG_(printf)(">>>> AFTER\n");
   }

   /* Tell the tool that we just wrote to the registers. */
   VG_TRACK( post_reg_write, Vg_CoreStartup, /*tid*/1, /*offset*/0,
             sizeof(VexGuestArchState));
}

#endif // defined(VGPV_ppc64_linux_bgq)

/*--------------------------------------------------------------------*/
/*---                                                initimg-bgq.c ---*/
/*--------------------------------------------------------------------*/
