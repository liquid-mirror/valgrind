
/*--------------------------------------------------------------------*/
/*--- Support for doing system calls.         syscall-x86-darwin.S ---*/
/*--------------------------------------------------------------------*/

/*
  This file is part of Valgrind, a dynamic binary instrumentation
  framework.

  Copyright (C) 2000-2007 Julian Seward 
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

#include "pub_core_basics_asm.h"
#include "libvex_guest_offsets.h"
		
	
/*----------------------------------------------------------------*/
/*
	Perform a syscall for the client.  This will run a syscall
	with the client's specific per-thread signal mask.
	
	The structure of this function is such that, if the syscall is
	interrupted by a signal, we can determine exactly what
	execution state we were in with respect to the execution of
	the syscall by examining the value of %eip in the signal
	handler.  This means that we can always do the appropriate
	thing to precisely emulate the kernel's signal/syscall
	interactions.

	The syscall number is taken from the argument, even though it
	should also be in regs->m_eax.  The syscall result is written
	back to regs->m_eax on completion.
	
	Returns 0 if the syscall was successfully called (even if the
	syscall itself failed), or a -ve error code if one of the
	sigprocmasks failed (there's no way to determine which one
	failed).

	VG_(fixup_guest_state_after_syscall_interrupted) does the
	thread state fixup in the case where we were interrupted by a
	signal.
	
	Prototype:

	Int _ML_(do_syscall_for_client_WRK)(
	                          Int syscallno,		// ebp+8
				  void* guest_state,		// ebp+12
				  const vki_sigset_t *sysmask,	// ebp+16
				  const vki_sigset_t *postmask,	// ebp+20
				  Int nsigwords)		// ebp+24
				   
*/

/* from vki_arch.h */	
#define VKI_SIG_SETMASK	2

/* DO_SYSCALL MACH|MDEP|UNIX|UX64 */
#define MACH 1
#define MDEP 2
#define UNIX 3
#define UX64 4
	
.macro DO_SYSCALL
	/* establish stack frame */
	push	%ebp
	mov	%esp, %ebp
	subl	$$8, %esp	/* 16-byte align stack */
	
L_$0_1:	/* Even though we can't take a signal until the sigprocmask completes,
	   start the range early.
	   If eip is in the range [1,2), the syscall hasn't been started yet */

	/* Set the signal mask which should be current during the syscall. */
	/* GrP fixme signals (deleted) */

	/* Copy syscall parameters to the stack - assume no more than 8 
	 * plus the return address */
	/* do_syscall8 */
	/* stack is currently aligned assuming 8 parameters */
	movl	12(%ebp), %edx			
	movl	OFFSET_x86_ESP(%edx), %edx	/* edx = simulated ESP */
	movl	28+4(%edx), %eax
	pushl	%eax
	movl	24+4(%edx), %eax
	pushl	%eax
	movl	20+4(%edx), %eax
	pushl	%eax
	movl	16+4(%edx), %eax
	pushl	%eax
	movl	12+4(%edx), %eax
	pushl	%eax
	movl	8+4(%edx), %eax
	pushl	%eax
	movl	4+4(%edx), %eax
	pushl	%eax
	movl	0+4(%edx), %eax
	pushl	%eax
	/* return address */
	movl	0(%edx), %eax
	pushl	%eax

	/* Put syscall number in eax */
	movl	8(%ebp), %eax

	/* If eip==2, then the syscall was either just about to start, 
	   or was interrupted and the kernel was restarting it. */
L_$0_2:
.if $0 == UX64
	int	$$0x80			/* UX64 */
.elseif $0 == UNIX
	int	$$0x80			/* UNIX (fixme should be sysenter?) */
.elseif $0 == MACH
	int	$$0x81
.elseif $0 == MDEP
	int	$$0x82
.else
	error$0 x
.endif

L_$0_3:	/* In the range [3, 4), the syscall result is in %eax and %edx and C, but hasn't been committed to the thread state. */
	setc	0(%esp)				/* stash returned carry flag */
	movl	12(%ebp), %ecx
	movl	%eax, OFFSET_x86_EAX(%ecx)	/* save EAX to vex*/
.if $0 == UX64
	movl	%edx, OFFSET_x86_EDX(%ecx)	/* save EDX to vex */
.endif
.if $0 != MACH
.if $0 != MDEP
	/* UNIX or UX64 */
	/* save carry flag to vex */
	subl	$$12, %esp
	movl	%ecx, 4(%esp)
	movl	$$0, 0(%esp)
	movb	12(%esp), %al
	movb	%al, 0(%esp)
	call	_LibVEX_GuestX86_put_eflag_c
	addl	$$12, %esp
.endif
.endif

L_$0_4:	/* Re-block signals.  If eip is in [4,5), then the syscall is complete and 
	   we needn't worry about it. */
	/* GrP fixme signals (deleted) */

L_$0_5:	/* now safe from signals */

	/* Return zero (GrP fixme signals) */
	movl	$$0, %eax
	movl	%ebp, %esp
	popl	%ebp
	ret
.endmacro
	

.globl _ML_(do_syscall_for_client_unix_WRK)
_ML_(do_syscall_for_client_unix_WRK):
	DO_SYSCALL UNIX

.globl _ML_(do_syscall_for_client_ux64_WRK)
_ML_(do_syscall_for_client_ux64_WRK):
	DO_SYSCALL UX64
	
.globl _ML_(do_syscall_for_client_mach_WRK)
_ML_(do_syscall_for_client_mach_WRK):
	DO_SYSCALL MACH
	
.globl _ML_(do_syscall_for_client_mdep_WRK)
_ML_(do_syscall_for_client_mdep_WRK):
	DO_SYSCALL MDEP

.data
/* export the ranges so that
   VG_(fixup_guest_state_after_syscall_interrupted) can do the
   right thing */
	
/* GrP fixme wrong */
.globl _ML_(blksys_setup)
.globl _ML_(blksys_restart)
.globl _ML_(blksys_complete)
.globl _ML_(blksys_committed)
.globl _ML_(blksys_finished)
_ML_(blksys_setup):	.long L_1_1
_ML_(blksys_restart):	.long L_1_2
_ML_(blksys_complete):	.long L_1_3
_ML_(blksys_committed):	.long L_1_4
_ML_(blksys_finished):	.long L_1_5

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
