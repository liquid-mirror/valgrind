## Process this file with automake to produce Makefile.in

##---------------------------------------------------------------------------
## Some of them user client requests which are now totally different for
## HEAD vs. ERASER due to changed client request codes.

## Some of them are hard to test because they require signals or something:
## blocked_syscall, signal1, signal3, sigwait_all, pth_pause, pth_sig*

## pthread ones hard to test due to non-determinism: pth_threadpool, others?

## gxx304 writes a file...

## Need more tests:
## - more C++ ones
## - more realloc ones
## - lots more mmap/munmap/mremap/mprotect ones
##---------------------------------------------------------------------------

CXX = g++

noinst_PROGRAMS = \
	bitfield1 bt_everything bt_literal coolo_strlen \
	cpuid dastest floored fucomip rcl_assert \
	rcrl readline1 sha1_test shortpush shorts smc1 \
	pth_atfork1 pth_cancel1 pth_cancel2 pth_cvsimple pth_mutexspeed \
	pth_once pth_semaphore1 pth_simple_mutex pth_simple_threads \
	pth_specific pth_yield

# XXX: want to have this inherited from ../Makefile.am
CFLAGS = $(WERROR) -Winline -Wall -Wshadow -g

# generic (--skin=none) ones, no errors
bitfield1_SOURCES 	= bitfield1.c
bt_everything_SOURCES 	= bt_everything.c
bt_literal_SOURCES 	= bt_literal.c
cpuid_SOURCES 		= cpuid_c.c cpuid_s.s
# Not sure how to specify CXX in configure.in to compile C++ progs...
#coolo_sigaction_SOURCES	= coolo_sigaction.cpp
coolo_strlen_SOURCES 	= coolo_strlen.c
dastest_SOURCES 	= dastest_c.c dastest_s.s
floored_SOURCES 	= floored.c
floored_LDADD 		= -lm
fucomip_SOURCES 	= fucomip.c
#gxx304_SOURCES		= gxx304.cpp	(C++)
rcl_assert_SOURCES 	= rcl_assert.S
rcrl_SOURCES 		= rcrl.c
readline1_SOURCES 	= readline1.c
smc1_SOURCES 		= smc1.c
sha1_test_SOURCES 	= sha1_test.c
shortpush_SOURCES 	= shortpush.c
shorts_SOURCES 		= shorts.c

# generic pthreads ones, no errors(?)
## XXX: _LDADD for every one sucks
pth_atfork1_SOURCES		= pth_atfork1.c
pth_atfork1_LDADD  		= -lpthread
pth_cancel1_SOURCES		= pth_cancel1.c
pth_cancel1_LDADD		= -lpthread
pth_cancel2_SOURCES		= pth_cancel2.c
pth_cancel2_LDADD		= -lpthread
pth_cvsimple_SOURCES		= pth_cvsimple.c
pth_cvsimple_LDADD		= -lpthread
pth_mutexspeed_SOURCES		= pth_mutexspeed.c
pth_mutexspeed_LDADD		= -lpthread
pth_once_SOURCES		= pth_once.c
pth_once_LDADD			= -lpthread
pth_semaphore1_SOURCES		= pth_semaphore1.c
pth_semaphore1_LDADD		= -lpthread
pth_simple_mutex_SOURCES	= pth_simple_mutex.c
pth_simple_mutex_LDADD		= -lpthread
pth_simple_threads_SOURCES	= pth_simple_threads.c
pth_simple_threads_LDADD	= -lpthread
pth_specific_SOURCES		= pth_specific.c
pth_specific_LDADD		= -lpthread
pth_yield_SOURCES		= pth_yield.c
pth_yield_LDADD			= -lpthread


