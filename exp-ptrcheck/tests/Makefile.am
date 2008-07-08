
# For AM_FLAG_M3264_PRI
include $(top_srcdir)/Makefile.flags.am

noinst_SCRIPTS = filter_stderr filter_add filter_suppgen \
	sh_script

EXTRA_DIST = $(noinst_SCRIPTS) \
	add.vgtest add.stderr.exp \
	and.vgtest and.stderr.exp \
	arith.vgtest arith.stderr.exp \
	arith_include1.c arith_include2.c \
	base.vgtest base.stderr.exp \
	ccc.vgtest ccc.stderr.exp \
	cmp.vgtest cmp.stderr.exp \
	fp.vgtest fp.stderr.exp \
	hp_bounds.vgtest hp_bounds.stderr.exp \
	hp_dangle.vgtest hp_dangle.stderr.exp \
	idiv.vgtest idiv.stderr.exp \
	imul.vgtest imul.stderr.exp \
	justify.vgtest justify.stderr.exp \
	mm.vgtest mm.stderr.exp \
	neg.vgtest neg.stderr.exp \
	not.vgtest not.stderr.exp \
	or.vgtest or.stderr.exp \
	partial_bad.vgtest partial_bad.stderr.exp \
	partial_good.vgtest partial_good.stderr.exp \
	pth_create.vgtest pth_create.stderr.exp \
	pth_specific.vgtest pth_specific.stderr.exp \
	realloc.vgtest realloc.stderr.exp \
	sh_script.vgtest sh_script.stderr.exp \
	strcpy.vgtest strcpy.stderr.exp \
	strlen_bad.vgtest strlen_bad.stderr.exp \
	strlen_good.vgtest strlen_good.stderr.exp \
	sub.vgtest sub.stderr.exp \
	supp.vgtest supp.stderr.exp supp.supp \
	suppgen.vgtest suppgen.stderr.exp suppgen.stdin \
	syscall.vgtest syscall.stderr.exp \
	tricky.vgtest tricky.stderr.exp \
	unaligned.vgtest unaligned.stderr.exp \
	xor.vgtest xor.stderr.exp \
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
