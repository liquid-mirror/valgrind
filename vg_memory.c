
/*--------------------------------------------------------------------*/
/*--- Shadow memory framework: initialisation, stack tracking,     ---*/
/*--- sanity checks.                                               ---*/
/*---                                                  vg_memory.c ---*/
/*--------------------------------------------------------------------*/

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

#include "vg_include.h"

/*--------------------------------------------------------------*/
/*--- Initialise the memory audit system on program startup. ---*/
/*--------------------------------------------------------------*/

/* Handle one entry derived from /proc/self/maps. */

static
void init_memory_audit_callback ( 
        Addr start, UInt size, 
        Char rr, Char ww, Char xx, 
        UInt foffset, UChar* filename )
{
   UInt  r_esp;
   Bool  is_stack_segment;

   /* Sanity check ... if this is the executable's text segment,
      ensure it is loaded where we think it ought to be.  Any file
      name which doesn't contain ".so" is assumed to be the
      executable. */
   if (filename != NULL
       && xx == 'x'
       && VG_(strstr(filename, ".so")) == NULL
      ) {
      /* We assume this is the executable. */
      if (start != VG_ASSUMED_EXE_BASE) {
         VG_(message)(Vg_UserMsg,
                      "FATAL: executable base addr not as assumed.");
         VG_(message)(Vg_UserMsg, "name %s, actual %p, assumed %p.",
                      filename, start, VG_ASSUMED_EXE_BASE);
         VG_(message)(Vg_UserMsg,
            "One reason this could happen is that you have a shared object");
         VG_(message)(Vg_UserMsg,
            " whose name doesn't contain the characters \".so\", so Valgrind ");
         VG_(message)(Vg_UserMsg,
            "naively assumes it is the executable.  ");
         VG_(message)(Vg_UserMsg,
            "In that case, rename it appropriately.");
         VG_(panic)("VG_ASSUMED_EXE_BASE doesn't match reality");
      }
   }
    
   if (0)
      VG_(message)(Vg_DebugMsg, 
                   "initial map %8x-%8x %c%c%c? %8x (%d) (%s)",
                   start,start+size,rr,ww,xx,foffset,
                   size, filename?filename:(UChar*)"NULL");

   r_esp = VG_(baseBlock)[VGOFF_(m_esp)];
   is_stack_segment = start <= r_esp && r_esp < start+size;

   /* Figure out the segment's permissions.

      All segments are addressible -- since a process can read its
      own text segment.

      [this comment looks wrong --njn]
      A read-but-not-write segment presumably contains initialised
      data, so is all valid.  Read-write segments presumably contains
      uninitialised data, so is all invalid.  */

   /* ToDo: make this less bogus. */
   if (rr != 'r' && xx != 'x' && ww != 'w') {
      /* Very bogus; this path never gets taken. */
      /* A no, V no */
      //SKN_(make_segment_noaccess) ( start, size );
      VG_(panic)("non-readable, writable, executable segment");
       
   } else {
      /* A yes, V yes */
      SKN_(make_segment_readable) ( start, size );

      /* This is an old comment --njn */
      /* Causes a lot of errs for unknown reasons. 
         if (filename is valgrind.so 
               [careful about end conditions on filename]) {
            example_a_bit = VGM_BIT_INVALID;
            example_v_bit = VGM_BIT_INVALID;
         }
      */
   }

   if (is_stack_segment) {
      /* This is the stack segment.  Mark all below %esp as
         noaccess. */
      if (0)
         VG_(message)(Vg_DebugMsg, 
                      "invalidating stack area: %x .. %x",
                      start,r_esp);
      SKN_(make_noaccess)( start, r_esp-start );
   }
}

/* Initialise the memory audit system. */
void VGM_(init_memory_audit) ( void )
{
   SKN_(init_shadow_memory)();

   // JJJ: is VG_(read_procselfmaps) necessary if not using shadow memory?
   // (currently I'm cutting init_memory_audit_callback() short halfway if
   // not using shadow memory)

   /* Read the initial memory mapping from the /proc filesystem, and
      set up our own maps accordingly. */
   VG_(read_procselfmaps) ( init_memory_audit_callback );

}


/*------------------------------------------------------------*/
/*--- Tracking permissions around %esp changes.            ---*/
/*------------------------------------------------------------*/

/*
   The stack
   ~~~~~~~~~
   The stack's segment seems to be dynamically extended downwards
   by the kernel as the stack pointer moves down.  Initially, a
   1-page (4k) stack is allocated.  When %esp moves below that for
   the first time, presumably a page fault occurs.  The kernel
   detects that the faulting address is in the range from %esp upwards
   to the current valid stack.  It then extends the stack segment
   downwards for enough to cover the faulting address, and resumes
   the process (invisibly).  The process is unaware of any of this.

   That means that Valgrind can't spot when the stack segment is
   being extended.  Fortunately, we want to precisely and continuously
   update stack permissions around %esp, so we need to spot all
   writes to %esp anyway.

   The deal is: when %esp is assigned a lower value, the stack is
   being extended.  Create a secondary maps to fill in any holes
   between the old stack ptr and this one, if necessary.  Then 
   mark all bytes in the area just "uncovered" by this %esp change
   as write-only.

   When %esp goes back up, mark the area receded over as unreadable
   and unwritable.

   Just to record the %esp boundary conditions somewhere convenient:
   %esp always points to the lowest live byte in the stack.  All
   addresses below %esp are not live; those at and above it are.  
*/

/* Does this address look like something in or vaguely near the
   current thread's stack? */
static
Bool is_plausible_stack_addr ( ThreadState* tst, Addr aa )
{
   UInt a = (UInt)aa;
   //PROF_EVENT(100);   PPP
   if (a <= tst->stack_highest_word && 
       a > tst->stack_highest_word - VG_PLAUSIBLE_STACK_SIZE)
      return True;
   else
      return False;
}


/* Is this address within some small distance below %ESP?  Used only
   for the --workaround-gcc296-bugs kludge. */
Bool VG_(is_just_below_ESP)( Addr esp, Addr aa )
{
   if ((UInt)esp > (UInt)aa
       && ((UInt)esp - (UInt)aa) <= VG_GCC296_BUG_STACK_SLOP)
      return True;
   else
      return False;
}


/* Kludgey ... how much does %esp have to change before we reckon that
   the application is switching stacks ? */
#define VG_HUGE_DELTA (VG_PLAUSIBLE_STACK_SIZE / 4)

static Addr get_page_base ( Addr a )
{
   return a & ~(VKI_BYTES_PER_PAGE-1);
}

static void vg_handle_esp_assignment_SLOWLY ( Addr );

void VGM_(handle_esp_assignment) ( Addr new_espA )
{
   UInt old_esp = VG_(baseBlock)[VGOFF_(m_esp)];
   UInt new_esp = (UInt)new_espA;
   Int  delta   = ((Int)new_esp) - ((Int)old_esp);

   //PROF_EVENT(101);   PPP

#  ifndef VG_DEBUG_MEMORY

   if (IS_ALIGNED4_ADDR(old_esp)) {

      /* Deal with the most common cases fast.  These are ordered in
         the sequence most common first. */

      if (delta == -4) {
         /* Moving down by 4 and properly aligned.. */
         //PROF_EVENT(102); PPP
         SKN_(make_aligned_word_WRITABLE)(new_esp);
         return;
      }

      if (delta == 4) {
         /* Moving up by 4 and properly aligned. */
         //PROF_EVENT(103); PPP
         SKN_(make_aligned_word_NOACCESS)(old_esp);
         return;
      }

      if (delta == -12) {
         //PROF_EVENT(104); PPP
         SKN_(make_aligned_word_WRITABLE)(new_esp);
         SKN_(make_aligned_word_WRITABLE)(new_esp+4);
         SKN_(make_aligned_word_WRITABLE)(new_esp+8);
         return;
      }

      if (delta == -8) {
         //PROF_EVENT(105); PPP
         SKN_(make_aligned_word_WRITABLE)(new_esp);
         SKN_(make_aligned_word_WRITABLE)(new_esp+4);
         return;
      }

      if (delta == 16) {
         //PROF_EVENT(106); PPP
         SKN_(make_aligned_word_NOACCESS)(old_esp);
         SKN_(make_aligned_word_NOACCESS)(old_esp+4);
         SKN_(make_aligned_word_NOACCESS)(old_esp+8);
         SKN_(make_aligned_word_NOACCESS)(old_esp+12);
         return;
      }

      if (delta == 12) {
         //PROF_EVENT(107); PPP
         SKN_(make_aligned_word_NOACCESS)(old_esp);
         SKN_(make_aligned_word_NOACCESS)(old_esp+4);
         SKN_(make_aligned_word_NOACCESS)(old_esp+8);
         return;
      }

      if (delta == 0) {
         //PROF_EVENT(108); PPP
         return;
      }

      if (delta == 8) {
         //PROF_EVENT(109); PPP
         SKN_(make_aligned_word_NOACCESS)(old_esp);
         SKN_(make_aligned_word_NOACCESS)(old_esp+4);
         return;
      }

      if (delta == -16) {
         //PROF_EVENT(110); PPP
         SKN_(make_aligned_word_WRITABLE)(new_esp);
         SKN_(make_aligned_word_WRITABLE)(new_esp+4);
         SKN_(make_aligned_word_WRITABLE)(new_esp+8);
         SKN_(make_aligned_word_WRITABLE)(new_esp+12);
         return;
      }

      if (delta == 20) {
         //PROF_EVENT(111); PPP
         SKN_(make_aligned_word_NOACCESS)(old_esp);
         SKN_(make_aligned_word_NOACCESS)(old_esp+4);
         SKN_(make_aligned_word_NOACCESS)(old_esp+8);
         SKN_(make_aligned_word_NOACCESS)(old_esp+12);
         SKN_(make_aligned_word_NOACCESS)(old_esp+16);
         return;
      }

      if (delta == -20) {
         //PROF_EVENT(112); PPP
         SKN_(make_aligned_word_WRITABLE)(new_esp);
         SKN_(make_aligned_word_WRITABLE)(new_esp+4);
         SKN_(make_aligned_word_WRITABLE)(new_esp+8);
         SKN_(make_aligned_word_WRITABLE)(new_esp+12);
         SKN_(make_aligned_word_WRITABLE)(new_esp+16);
         return;
      }

      if (delta == 24) {
         //PROF_EVENT(113); PPP
         SKN_(make_aligned_word_NOACCESS)(old_esp);
         SKN_(make_aligned_word_NOACCESS)(old_esp+4);
         SKN_(make_aligned_word_NOACCESS)(old_esp+8);
         SKN_(make_aligned_word_NOACCESS)(old_esp+12);
         SKN_(make_aligned_word_NOACCESS)(old_esp+16);
         SKN_(make_aligned_word_NOACCESS)(old_esp+20);
         return;
      }

      if (delta == -24) {
         //PROF_EVENT(114); PPP
         SKN_(make_aligned_word_WRITABLE)(new_esp);
         SKN_(make_aligned_word_WRITABLE)(new_esp+4);
         SKN_(make_aligned_word_WRITABLE)(new_esp+8);
         SKN_(make_aligned_word_WRITABLE)(new_esp+12);
         SKN_(make_aligned_word_WRITABLE)(new_esp+16);
         SKN_(make_aligned_word_WRITABLE)(new_esp+20);
         return;
      }

   }

#  endif

   /* The above special cases handle 90% to 95% of all the stack
      adjustments.  The rest we give to the slow-but-general
      mechanism. */
   vg_handle_esp_assignment_SLOWLY ( new_espA );
}


static void vg_handle_esp_assignment_SLOWLY ( Addr new_espA )
{
   UInt old_esp = VG_(baseBlock)[VGOFF_(m_esp)];
   UInt new_esp = (UInt)new_espA;
   Int  delta   = ((Int)new_esp) - ((Int)old_esp);
   //   VG_(printf)("%d ", delta);
   //PROF_EVENT(120);   PPP
   if (-(VG_HUGE_DELTA) < delta && delta < VG_HUGE_DELTA) {
      /* "Ordinary" stack change. */
      if (new_esp < old_esp) {
         /* Moving down; the stack is growing. */
         //PROF_EVENT(121); PPP
         SKN_(make_writable) ( new_esp, old_esp - new_esp );
         return;
      }
      if (new_esp > old_esp) {
         /* Moving up; the stack is shrinking. */
         //PROF_EVENT(122); PPP
         SKN_(make_noaccess) ( old_esp, new_esp - old_esp );
         return;
      }
      //PROF_EVENT(123);    PPP
      return; /* when old_esp == new_esp */
   }

   /* %esp has changed by more than HUGE_DELTA.  We take this to mean
      that the application is switching to a new stack, for whatever
      reason, and we attempt to initialise the permissions around the
      new stack in some plausible way.  All pretty kludgey; needed to
      make netscape-4.07 run without generating thousands of error
      contexts.

      If we appear to be switching back to the main stack, don't mess
      with the permissions in the area at and above the stack ptr.
      Otherwise, we're switching to an alternative stack; make the
      area above %esp readable -- this doesn't seem right -- the right
      thing to do would be to make it writable -- but is needed to
      avoid huge numbers of errs in netscape.  To be investigated. */

   { Addr invalid_down_to = get_page_base(new_esp) 
                            - 0 * VKI_BYTES_PER_PAGE;
     Addr valid_up_to     = get_page_base(new_esp) + VKI_BYTES_PER_PAGE
                            + 0 * VKI_BYTES_PER_PAGE;
     ThreadState* tst     = VG_(get_current_thread_state)();
     //PROF_EVENT(124); PPP
     if (VG_(clo_verbosity) > 1)
        VG_(message)(Vg_UserMsg, "Warning: client switching stacks?  "
                                 "%%esp: %p --> %p",
                                  old_esp, new_esp);
     /* VG_(printf)("na %p,   %%esp %p,   wr %p\n",
                    invalid_down_to, new_esp, valid_up_to ); */
     SKN_(make_noaccess) ( invalid_down_to, new_esp - invalid_down_to );
     if (!is_plausible_stack_addr(tst, new_esp)) {
        SKN_(make_readable) ( new_esp, valid_up_to - new_esp );
     }
   }
}


/*--------------------------------------------------------------------*/
/*--- end                                              vg_memory.c ---*/
/*--------------------------------------------------------------------*/

