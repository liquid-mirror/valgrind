
# For AM_FLAG_M3264_PRI
include $(top_srcdir)/Makefile.flags.am

#SUBDIRS = .
#if VGP_X86_LINUX
#SUBDIRS += x86
#endif
#if VGP_AMD64_LINUX
#SUBDIRS += amd64
#endif
#if VGP_PPC32_LINUX
#SUBDIRS += ppc32
#endif
#if VGP_PPC64_LINUX
#SUBDIRS += ppc64
#endif

DIST_SUBDIRS = ${VG_ARCH_ALL} .

noinst_SCRIPTS = filter_stderr filter_add filter_suppgen \
	sh_script

EXTRA_DIST = $(noinst_SCRIPTS) \
	add.vgtest-disabled add.stderr.exp \
	and.vgtest-disabled and.stderr.exp \
	arith.vgtest-disabled arith.stderr.exp \
	arith_include1.c arith_include2.c \
	base.vgtest \
	base.stderr.exp-glibc25-amd64 base.stderr.exp-glibc25-x86 \
	ccc.vgtest \
	ccc.stderr.exp-glibc25-x86 ccc.stderr.exp-glibc25-amd64 \
	cmp.vgtest-disabled cmp.stderr.exp \
	fp.vgtest fp.stderr.exp \
	hp_bounds.vgtest hp_bounds.stderr.exp \
	hp_dangle.vgtest hp_dangle.stderr.exp \
	idiv.vgtest-disabled idiv.stderr.exp \
	imul.vgtest-disabled imul.stderr.exp \
	justify.vgtest justify.stderr.exp \
	mm.vgtest-disabled mm.stderr.exp \
	neg.vgtest-disabled neg.stderr.exp \
	not.vgtest-disabled not.stderr.exp \
	or.vgtest-disabled or.stderr.exp \
	partial_bad.vgtest \
	partial_bad.stderr.exp-glibc25-x86 \
	partial_bad.stderr.exp-glibc25-amd64 \
	partial_good.vgtest \
	partial_good.stderr.exp-glibc25-x86 \
	partial_good.stderr.exp-glibc25-amd64 \
	pth_create.vgtest pth_create.stderr.exp \
	pth_specific.vgtest pth_specific.stderr.exp \
	realloc.vgtest \
	realloc.stderr.exp-glibc25-x86 realloc.stderr.exp-glibc25-amd64 \
	sh_script.vgtest-disabled sh_script.stderr.exp \
	strcpy.vgtest strcpy.stderr.exp \
	strlen_bad.vgtest-disabled strlen_bad.stderr.exp \
	strlen_good.vgtest-disabled strlen_good.stderr.exp \
	sub.vgtest-disabled sub.stderr.exp \
	supp.vgtest supp.stderr.exp supp.supp \
	suppgen.vgtest-disabled suppgen.stderr.exp suppgen.stdin \
	syscall.vgtest-disabled syscall.stderr.exp \
	tricky.vgtest tricky.stderr.exp \
	unaligned.vgtest \
	unaligned.stderr.exp-glibc25-x86 unaligned.stderr.exp-glibc25-amd64 \
	xor.vgtest-disabled xor.stderr.exp \
	zero.vgtest zero.stderr.exp

check_PROGRAMS = \
	add and arith base ccc cmp fp hp_bounds hp_dangle idiv imul \
	justify mm not neg or partial pth_create pth_specific realloc \
	strcpy strlen sub supp syscall tricky unaligned xor zero

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/include \
		-I$(top_srcdir)/coregrind -I$(top_builddir)/include \
		-I@VEX_DIR@/pub
AM_CFLAGS   = $(WERROR) -Winline -Wall -Wshadow -g $(AM_FLAG_M3264_PRI)
AM_CXXFLAGS = $(AM_CFLAGS)

# C ones
add_SOURCES		= add.c
and_SOURCES		= and.c
arith_SOURCES		= arith.c
base_SOURCES		= base.c
cmp_SOURCES		= cmp.c
fp_SOURCES		= fp.c
hp_bounds_SOURCES	= hp_bounds.c
hp_dangle_SOURCES	= hp_dangle.c
idiv_SOURCES		= idiv.c
imul_SOURCES		= imul.c
justify_SOURCES		= justify.c
mm_SOURCES		= mm.c
neg_SOURCES		= neg.c
not_SOURCES		= not.c
or_SOURCES		= or.c
partial_SOURCES		= partial.c
pth_create_SOURCES	= pth_create.c
pth_create_LDADD	= -lpthread
pth_specific_SOURCES	= pth_specific.c
pth_specific_LDADD	= -lpthread
realloc_SOURCES		= realloc.c
strcpy_SOURCES		= strcpy.c
strlen_SOURCES		= strlen.c
sub_SOURCES		= sub.c
supp_SOURCES		= supp.c
syscall_SOURCES		= syscall.c
tricky_SOURCES		= tricky.c
unaligned_SOURCES	= unaligned.c
xor_SOURCES		= xor.c
zero_SOURCES		= zero.c

# C++ ones
ccc_SOURCES		= ccc.cpp
