## Process this file with automake to produce Makefile.in

##---------------------------------------------------------------------------
## Some of them user client requests which are now totally different for
## HEAD vs. ERASER due to changed client request codes.

## Need more tests:
## - more C++ ones
## - lots more mmap/munmap/mremap/mprotect ones
##---------------------------------------------------------------------------

noinst_PROGRAMS = \
	bitfield1 bt_everything bt_literal coolo_strlen \
	cpuid dastest floored fucomip munmap_exe rcl_assert \
	rcrl readline1 sha1_test shortpush shorts smc1 \
	pth_atfork1 \
	coolo_sigaction gxx304

CFLAGS   = $(WERROR) -Winline -Wall -Wshadow -g
CXXFLAGS = $(CFLAGS)

# generic C ones
bitfield1_SOURCES 	= bitfield1.c
bt_everything_SOURCES 	= bt_everything.c
bt_literal_SOURCES 	= bt_literal.c
cpuid_SOURCES 		= cpuid_c.c cpuid_s.s
coolo_strlen_SOURCES 	= coolo_strlen.c
dastest_SOURCES 	= dastest_c.c dastest_s.s
floored_SOURCES 	= floored.c
floored_LDADD 		= -lm
fucomip_SOURCES 	= fucomip.c
munmap_exe_SOURCES 	= munmap_exe.c
rcl_assert_SOURCES 	= rcl_assert.S
rcrl_SOURCES 		= rcrl.c
readline1_SOURCES 	= readline1.c
smc1_SOURCES 		= smc1.c
sha1_test_SOURCES 	= sha1_test.c
shortpush_SOURCES 	= shortpush.c
shorts_SOURCES 		= shorts.c

# generic C++ ones
coolo_sigaction_SOURCES	= coolo_sigaction.cpp
gxx304_SOURCES		= gxx304.cpp


# generic pthreads ones
# XXX: is output right for pth_atfork1?
pth_atfork1_SOURCES		= pth_atfork1.c
pth_atfork1_LDADD  		= -lpthread

