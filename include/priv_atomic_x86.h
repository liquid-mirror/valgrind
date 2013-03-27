
/*--------------------------------------------------------------------*/
/*--- Atomic primitives for x86.                 priv_atomic_x86.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.
   Derived from glibc 2.13
   Copyright (C) 2002-2004, 2006, 2007, 2009 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@redhat.com>, 2002.

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

#ifndef __PRIV_ATOMIC_X86_H
#define __PRIV_ATOMIC_X86_H

#define LOCK_PREFIX "lock;"


# define __arch_compare_and_exchange_val_8_acq(mem, newval, oldval) \
  ({ __typeof (*mem) ret;						      \
     __asm __volatile (LOCK_PREFIX "cmpxchgb %b2, %1"			      \
		       : "=a" (ret), "=m" (*mem)			      \
		       : "q" (newval), "m" (*mem), "0" (oldval));	      \
     ret; })

# define __arch_compare_and_exchange_val_16_acq(mem, newval, oldval) \
  ({ __typeof (*mem) ret;						      \
     __asm __volatile (LOCK_PREFIX "cmpxchgw %w2, %1"			      \
		       : "=a" (ret), "=m" (*mem)			      \
		       : "r" (newval), "m" (*mem), "0" (oldval));	      \
     ret; })

# define __arch_compare_and_exchange_val_32_acq(mem, newval, oldval) \
  ({ __typeof (*mem) ret;						      \
     __asm __volatile (LOCK_PREFIX "cmpxchgl %2, %1"			      \
		       : "=a" (ret), "=m" (*mem)			      \
		       : "r" (newval), "m" (*mem), "0" (oldval));	      \
     ret; })

#  define __arch_compare_and_exchange_val_64_acq(mem, newval, oldval) \
  ({ __typeof (*mem) ret;						      \
     __asm __volatile (LOCK_PREFIX "cmpxchg8b %1"			      \
		       : "=A" (ret), "=m" (*mem)			      \
		       : "b" (((unsigned long long int) (newval))	      \
			      & 0xffffffff),				      \
			 "c" (((unsigned long long int) (newval)) >> 32),     \
			 "m" (*mem), "a" (((unsigned long long int) (oldval)) \
					  & 0xffffffff),		      \
			 "d" (((unsigned long long int) (oldval)) >> 32));    \
     ret; })


/* Note that we need no lock prefix.  */
#define atomic_exchange_acq(mem, newvalue) \
  ({ __typeof (*mem) result;						      \
     if (sizeof (*mem) == 1)						      \
       __asm __volatile ("xchgb %b0, %1"				      \
			 : "=q" (result), "=m" (*mem)			      \
			 : "0" (newvalue), "m" (*mem));			      \
     else if (sizeof (*mem) == 2)					      \
       __asm __volatile ("xchgw %w0, %1"				      \
			 : "=r" (result), "=m" (*mem)			      \
			 : "0" (newvalue), "m" (*mem));			      \
     else if (sizeof (*mem) == 4)					      \
       __asm __volatile ("xchgl %0, %1"					      \
			 : "=r" (result), "=m" (*mem)			      \
			 : "0" (newvalue), "m" (*mem));			      \
     else								      \
       {								      \
	 result = 0;							      \
	 vg_assert (False);						      \
       }								      \
     result; })


#define __arch_exchange_and_add_body(lock, pfx, mem, value) \
  ({ __typeof (*mem) __result;						      \
     __typeof (value) __addval = (value);				      \
     if (sizeof (*mem) == 1)						      \
       __asm __volatile (lock "xaddb %b0, %1"				      \
			 : "=q" (__result), "=m" (*mem)			      \
			 : "0" (__addval), "m" (*mem));                       \
     else if (sizeof (*mem) == 2)					      \
       __asm __volatile (lock "xaddw %w0, %1"				      \
			 : "=r" (__result), "=m" (*mem)			      \
			 : "0" (__addval), "m" (*mem)));                      \
     else if (sizeof (*mem) == 4)					      \
       __asm __volatile (lock "xaddl %0, %1"				      \
			 : "=r" (__result), "=m" (*mem)			      \
			 : "0" (__addval), "m" (*mem));                       \
     else								      \
       {								      \
	 __typeof (mem) __memp = (mem);					      \
	 __typeof (*mem) __tmpval;					      \
	 __result = *__memp;						      \
	 do								      \
	   __tmpval = __result;						      \
	 while ((__result = pfx##_compare_and_exchange_val_64_acq	      \
		 (__memp, __result + __addval, __result)) == __tmpval);	      \
       }								      \
     __result; })

# define atomic_exchange_and_add(mem, value) \
  __arch_exchange_and_add_body (LOCK_PREFIX, __arch, mem, value)

#define __arch_add_body(lock, pfx, mem, value) \
  do {									      \
    if (__builtin_constant_p (value) && (value) == 1)			      \
      atomic_increment (mem);						      \
    else if (__builtin_constant_p (value) && (value) == -1)		      \
      atomic_decrement (mem);						      \
    else if (sizeof (*mem) == 1)					      \
      __asm __volatile (lock "addb %b1, %0"				      \
			: "=m" (*mem)					      \
			: "iq" (value), "m" (*mem));                          \
    else if (sizeof (*mem) == 2)					      \
      __asm __volatile (lock "addw %w1, %0"				      \
			: "=m" (*mem)					      \
			: "ir" (value), "m" (*mem));                          \
    else if (sizeof (*mem) == 4)					      \
      __asm __volatile (lock "addl %1, %0"				      \
			: "=m" (*mem)					      \
			: "ir" (value), "m" (*mem));                          \
    else                                                                      \
      __sync_add_and_fetch(mem, value);                                       \
  } while (0)
#if 0
//mtV?
  The below gives compilation problems:
error: impossible register constraint in ‘asm’
Waiting for that, we use __sync_add_and_fetch
To be fixed ...
    else								      \
      {									      \
	__typeof (value) __addval = (value);				      \
	__typeof (mem) __memp = (mem);					      \
	__typeof (*mem) __oldval = *__memp;				      \
	__typeof (*mem) __tmpval;					      \
	do								      \
	  __tmpval = __oldval;						      \
	while ((__oldval = pfx##_compare_and_exchange_val_64_acq	      \
		(__memp, __oldval + __addval, __oldval)) == __tmpval);	      \
      }}	 while (0)
#endif


#define atomic_add(mem, value) \
  __arch_add_body (LOCK_PREFIX, __arch, mem, value)


#define atomic_add_negative(mem, value) \
  ({ unsigned char __result;						      \
     if (sizeof (*mem) == 1)						      \
       __asm __volatile (LOCK_PREFIX "addb %b2, %0; sets %1"		      \
			 : "=m" (*mem), "=qm" (__result)		      \
			 : "iq" (value), "m" (*mem));			      \
     else if (sizeof (*mem) == 2)					      \
       __asm __volatile (LOCK_PREFIX "addw %w2, %0; sets %1"		      \
			 : "=m" (*mem), "=qm" (__result)		      \
			 : "ir" (value), "m" (*mem));			      \
     else if (sizeof (*mem) == 4)					      \
       __asm __volatile (LOCK_PREFIX "addl %2, %0; sets %1"		      \
			 : "=m" (*mem), "=qm" (__result)		      \
			 : "ir" (value), "m" (*mem));			      \
     else								      \
       vg_assert (False);						      \
     __result; })


#define atomic_add_zero(mem, value) \
  ({ unsigned char __result;						      \
     if (sizeof (*mem) == 1)						      \
       __asm __volatile (LOCK_PREFIX "addb %b2, %0; setz %1"		      \
			 : "=m" (*mem), "=qm" (__result)		      \
			 : "iq" (value), "m" (*mem));			      \
     else if (sizeof (*mem) == 2)					      \
       __asm __volatile (LOCK_PREFIX "addw %w2, %0; setz %1"		      \
			 : "=m" (*mem), "=qm" (__result)		      \
			 : "ir" (value), "m" (*mem));			      \
     else if (sizeof (*mem) == 4)					      \
       __asm __volatile (LOCK_PREFIX "addl %2, %0; setz %1"		      \
			 : "=m" (*mem), "=qm" (__result)		      \
			 : "ir" (value), "m" (*mem));			      \
     else								      \
       vg_assert (False);						      \
     __result; })


#define __arch_increment_body(lock,  pfx, mem) \
  do {									      \
    if (sizeof (*mem) == 1)						      \
      __asm __volatile (lock "incb %b0"					      \
			: "=m" (*mem)					      \
			: "m" (*mem));                                        \
    else if (sizeof (*mem) == 2)					      \
      __asm __volatile (lock "incw %w0"					      \
			: "=m" (*mem)					      \
			: "m" (*mem));                                        \
    else if (sizeof (*mem) == 4)					      \
      __asm __volatile (lock "incl %0"					      \
			: "=m" (*mem)					      \
			: "m" (*mem));                                        \
    else                                                                      \
      __sync_add_and_fetch(mem, 1);					      \
  } while (0)

#if 0
     //mtV?
     //????? the below gives asm error on x86 at least ?????
     /// replacing by __sync_add_and_fetch
    else								      \
      {									      \
	__typeof (mem) __memp = (mem);					      \
	__typeof (*mem) __oldval = *__memp;				      \
	__typeof (*mem) __tmpval;					      \
	do								      \
	  __tmpval = __oldval;						      \
	while ((__oldval = pfx##_compare_and_exchange_val_64_acq	      \
		(__memp, __oldval + 1, __oldval)) == __tmpval);		      \
      }	
#endif

#define atomic_increment(mem) __arch_increment_body (LOCK_PREFIX, __arch, mem)


#define atomic_increment_and_test(mem) \
  ({ unsigned char __result;						      \
     if (sizeof (*mem) == 1)						      \
       __asm __volatile (LOCK_PREFIX "incb %0; sete %b1"		      \
			 : "=m" (*mem), "=qm" (__result)		      \
			 : "m" (*mem));					      \
     else if (sizeof (*mem) == 2)					      \
       __asm __volatile (LOCK_PREFIX "incw %0; sete %w1"		      \
			 : "=m" (*mem), "=qm" (__result)		      \
			 : "m" (*mem));					      \
     else if (sizeof (*mem) == 4)					      \
       __asm __volatile (LOCK_PREFIX "incl %0; sete %1"			      \
			 : "=m" (*mem), "=qm" (__result)		      \
			 : "m" (*mem));					      \
     else								      \
       vg_assert (False);						      \
     __result; })


#define __arch_decrement_body(lock, pfx, mem) \
  do {									      \
    if (sizeof (*mem) == 1)						      \
      __asm __volatile (lock "decb %b0"					      \
			: "=m" (*mem)					      \
			: "m" (*mem));                                        \
    else if (sizeof (*mem) == 2)					      \
      __asm __volatile (lock "decw %w0"					      \
			: "=m" (*mem)					      \
			: "m" (*mem));                                        \
    else if (sizeof (*mem) == 4)					      \
      __asm __volatile (lock "decl %0"					      \
			: "=m" (*mem)					      \
			: "m" (*mem));                                        \
    else								      \
      {									      \
	__typeof (mem) __memp = (mem);					      \
	__typeof (*mem) __oldval = *__memp;				      \
	__typeof (*mem) __tmpval;					      \
	do								      \
	  __tmpval = __oldval;						      \
	while ((__oldval = pfx##_compare_and_exchange_val_64_acq	      \
		(__memp, __oldval - 1, __oldval)) == __tmpval); 	      \
      }									      \
  } while (0)

#define atomic_decrement(mem) __arch_decrement_body (LOCK_PREFIX, __arch, mem)

#define atomic_decrement_and_test(mem) \
  ({ unsigned char __result;						      \
     if (sizeof (*mem) == 1)						      \
       __asm __volatile (LOCK_PREFIX "decb %b0; sete %1"		      \
			 : "=m" (*mem), "=qm" (__result)		      \
			 : "m" (*mem));					      \
     else if (sizeof (*mem) == 2)					      \
       __asm __volatile (LOCK_PREFIX "decw %w0; sete %1"		      \
			 : "=m" (*mem), "=qm" (__result)		      \
			 : "m" (*mem));					      \
     else if (sizeof (*mem) == 4)					      \
       __asm __volatile (LOCK_PREFIX "decl %0; sete %1"			      \
			 : "=m" (*mem), "=qm" (__result)		      \
			 : "m" (*mem));					      \
     else								      \
       vg_assert (False);						      \
     __result; })


#define atomic_bit_set(mem, bit) \
  do {									      \
    if (sizeof (*mem) == 1)						      \
      __asm __volatile (LOCK_PREFIX "orb %b2, %0"			      \
			: "=m" (*mem)					      \
			: "m" (*mem), "iq" (1 << (bit)));		      \
    else if (sizeof (*mem) == 2)					      \
      __asm __volatile (LOCK_PREFIX "orw %w2, %0"			      \
			: "=m" (*mem)					      \
			: "m" (*mem), "ir" (1 << (bit)));		      \
    else if (sizeof (*mem) == 4)					      \
      __asm __volatile (LOCK_PREFIX "orl %2, %0"			      \
			: "=m" (*mem)					      \
			: "m" (*mem), "ir" (1 << (bit)));		      \
    else								      \
      vg_assert (False);						      \
  } while (0)


#define atomic_bit_test_set(mem, bit) \
  ({ unsigned char __result;						      \
     if (sizeof (*mem) == 1)						      \
       __asm __volatile (LOCK_PREFIX "btsb %3, %1; setc %0"		      \
			 : "=q" (__result), "=m" (*mem)			      \
			 : "m" (*mem), "ir" (bit));			      \
     else if (sizeof (*mem) == 2)					      \
       __asm __volatile (LOCK_PREFIX "btsw %3, %1; setc %0"		      \
			 : "=q" (__result), "=m" (*mem)			      \
			 : "m" (*mem), "ir" (bit));			      \
     else if (sizeof (*mem) == 4)					      \
       __asm __volatile (LOCK_PREFIX "btsl %3, %1; setc %0"		      \
			 : "=q" (__result), "=m" (*mem)			      \
			 : "m" (*mem), "ir" (bit));			      \
     else							      	      \
       vg_assert (False);						      \
     __result; })


#define atomic_delay() asm ("rep; nop")


#define __arch_and_body(lock, mem, mask) \
  do {									      \
    if (sizeof (*mem) == 1)						      \
      __asm __volatile (lock "andb %b1, %0"				      \
			: "=m" (*mem)					      \
			: "iq" (mask), "m" (*mem));                           \
    else if (sizeof (*mem) == 2)					      \
      __asm __volatile (lock "andw %w1, %0"				      \
			: "=m" (*mem)					      \
			: "ir" (mask), "m" (*mem));                           \
    else if (sizeof (*mem) == 4)					      \
      __asm __volatile (lock "andl %1, %0"				      \
			: "=m" (*mem)					      \
			: "ir" (mask), "m" (*mem));                           \
    else								      \
      vg_assert (False);						      \
  } while (0)


#define atomic_and(mem, mask) __arch_and_body (LOCK_PREFIX, mem, mask)

#define __arch_or_body(lock, mem, mask) \
  do {									      \
    if (sizeof (*mem) == 1)						      \
      __asm __volatile (lock "orb %b1, %0"				      \
			: "=m" (*mem)					      \
			: "iq" (mask), "m" (*mem));                           \
    else if (sizeof (*mem) == 2)					      \
      __asm __volatile (lock "orw %w1, %0"				      \
			: "=m" (*mem)					      \
			: "ir" (mask), "m" (*mem));                           \
    else if (sizeof (*mem) == 4)					      \
      __asm __volatile (lock "orl %1, %0"				      \
			: "=m" (*mem)					      \
			: "ir" (mask), "m" (*mem));                           \
    else								      \
      vg_assert (False);						      \
  } while (0)

#define atomic_or(mem, mask) __arch_or_body (LOCK_PREFIX, mem, mask)

#endif	/* __PRIV_ATOMIC_X86_H */

/*--------------------------------------------------------------------*/
/*--- end                                        priv_atomic_x86.h ---*/
/*--------------------------------------------------------------------*/
