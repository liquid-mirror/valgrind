
# For AM_FLAG_M3264_PRI
include $(top_srcdir)/Makefile.flags.am

SUBDIRS = .
if VGP_X86_LINUX
SUBDIRS += x86
endif
if VGP_AMD64_LINUX
SUBDIRS += amd64
endif
if VGP_PPC32_LINUX
SUBDIRS += ppc32
endif
if VGP_PPC64_LINUX
SUBDIRS += ppc64
endif
if VGP_X86_DARWIN
SUBDIRS += x86
endif
if VGP_AMD64_DARWIN
SUBDIRS += amd64
endif
if VGP_PPC32_DARWIN
SUBDIRS += ppc32
endif
if VGP_PPC64_DARWIN
SUBDIRS += ppc64
endif

DIST_SUBDIRS = ${VG_ARCH_ALL} .

noinst_SCRIPTS = filter_stderr filter_cachesim_discards

EXTRA_DIST = $(noinst_SCRIPTS) \
	chdir.vgtest chdir.stderr.exp \
	clreq.vgtest clreq.stderr.exp \
	dlclose.vgtest dlclose.stderr.exp dlclose.stdout.exp \
	wrap5.vgtest wrap5.stderr.exp wrap5.stdout.exp

check_PROGRAMS = \
	chdir clreq dlclose myprint.so

AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS   = $(WERROR) -Winline -Wall -Wshadow -g $(AM_FLAG_M3264_PRI)

# C ones
dlclose_LDADD		= -ldl
myprint_so_SOURCES	= myprint.c
if VGO_DARWIN
myprint_so_LDFLAGS	= $(AM_FLAG_M3264_PRI) -dynamic -dynamiclib -all_load -fpic
else
myprint_so_LDFLAGS	= $(AM_FLAG_M3264_PRI) -shared -fPIC
endif
myprint_so_CFLAGS	= $(AM_FLAG_M3264_PRI) -fPIC
