include $(top_srcdir)/Makefile.all.am
include $(top_srcdir)/Makefile.core-AM_CPPFLAGS.am

MODULES = \
	m_aspacemgr \
	m_debuginfo \
	m_demangle \
	m_dispatch \
	m_replacemalloc \
	m_scheduler \
	m_sigframe \
	m_syswrap

## When building, we are only interested in the current arch/OS/platform.
## But when doing 'make dist', we are interested in every arch/OS/platform.
## That's what DIST_SUBDIRS specifies.
SUBDIRS = $(MODULES) .

DIST_SUBDIRS = $(MODULES) .

AM_CPPFLAGS += -DVG_LIBDIR="\"$(valdir)"\" \
		-DKICKSTART_BASE=@KICKSTART_BASE@

default.supp: $(SUPP_FILES)

## XXXXXXXXXXXXX JRS 8 Aug 05: the next three lines constitute an
## appalling hack.  Although we purportedly create a .a file, in fact
## it is really a .o (relocatable ELF object) file.  The root reason
## is that some of the inputs to libcoregrind.a are themselves .a files,
## and I don't know how to get /usr/bin/ar to accept .a files as inputs.
noinst_LIBRARIES = libcoregrind.a
libcoregrind_a_AR = $(LD) --whole-archive -r -o
RANLIB = echo "Not really ranlib-ing"
## end of hack

bin_PROGRAMS = \
	valgrind

val_PROGRAMS = \
	vg_preload_core.so

noinst_HEADERS = \
	coregrind.h		\
	pub_core_aspacemgr.h	\
	pub_core_basics.h	\
	pub_core_cpuid.h	\
	pub_core_debuginfo.h	\
	pub_core_debugger.h	\
	pub_core_debuglog.h	\
	pub_core_demangle.h	\
	pub_core_dispatch.h	\
	pub_core_dispatch_asm.h	\
	pub_core_errormgr.h	\
	pub_core_execontext.h	\
	pub_core_hashtable.h	\
	pub_core_libcbase.h	\
	pub_core_libcassert.h	\
	pub_core_libcfile.h	\
	pub_core_libcmman.h	\
	pub_core_libcprint.h	\
	pub_core_libcproc.h	\
	pub_core_libcsignal.h	\
	pub_core_machine.h	\
	pub_core_main.h		\
	pub_core_mallocfree.h	\
	pub_core_options.h	\
	pub_core_profile.h	\
	pub_core_pthreadmodel.h	\
	pub_core_redir.h	\
	pub_core_replacemalloc.h\
	pub_core_scheduler.h	\
	pub_core_sigframe.h	\
	pub_core_signals.h	\
	pub_core_skiplist.h	\
	pub_core_stacks.h	\
	pub_core_stacktrace.h	\
	pub_core_syscall.h	\
	pub_core_syswrap.h	\
	pub_core_threadmodel.h	\
	pub_core_threadstate.h	\
	pub_core_tooliface.h	\
	pub_core_trampoline.h	\
	pub_core_translate.h	\
	pub_core_transtab.h	\
	pub_core_transtab_asm.h	\
	pub_core_ume.h		\
	vki_unistd.h		\
	vki_unistd-amd64-linux.h\
	vki_unistd-ppc32-linux.h\
	vki_unistd-x86-linux.h

BUILT_SOURCES = 
CLEANFILES = 

valgrind_SOURCES = \
	m_launcher.c \
	m_debuglog.c

libcoregrind_a_SOURCES = \
	m_cpuid.S \
	m_debugger.c \
	m_debuglog.c \
	m_errormgr.c \
	m_execontext.c \
	m_hashtable.c \
	m_libcbase.c \
	m_libcassert.c \
	m_libcfile.c \
	m_libcmman.c \
	m_libcprint.c \
	m_libcproc.c \
	m_libcsignal.c \
	m_machine.c \
	m_main.c \
	m_mallocfree.c \
	m_options.c \
	m_profile.c \
	m_pthreadmodel.c \
	m_redir.c \
	m_signals.c \
	m_skiplist.c \
	m_stacks.c \
	m_stacktrace.c \
	m_syscall.c \
	m_threadmodel.c \
	m_threadstate.c \
	m_tooliface.c \
	m_trampoline.S \
	m_translate.c \
	m_transtab.c \
	m_ume.c

## Nb: libscheduler.a must precede libdispatch.a in this list.
libcoregrind_a_extra= \
	m_debuginfo/libdebuginfo.a \
	m_demangle/libdemangle.a \
	m_scheduler/libscheduler.a \
	m_dispatch/libdispatch.a \
	m_aspacemgr/libaspacemgr.a \
	m_sigframe/libsigframe.a \
	m_syswrap/libsyswrap.a \
	@VEX_DIR@/libvex.a

## These ones must be linked in with the --whole-archive flag, because
## they wouldn't get pulled into libcoregrind otherwise (because they
## contain symbols only referred to by tool shared objects).
libcoregrind_a_extra2 = \
	m_replacemalloc/libreplacemalloc_core.a

## Nb: older versions of automake don't seem to like having += within an
## if-then-else, so we have to use these variables for the common parts.
libcoregrind_a_DEPS_common = \
	$(libcoregrind_a_extra) \
	$(libcoregrind_a_extra2)

st2_LDFLAGS_common = \
	-Wl,--export-dynamic -g \
	-Wl,--whole-archive $(libcoregrind_a_extra2) -Wl,--no-whole-archive

libcoregrind_a_DEPENDENCIES = $(libcoregrind_a_DEPS_common)
libcoregrind_a_LIBFLAGS = \
	$(st2_LDFLAGS_common)

libcoregrind_a_LIBADD= $(libcoregrind_a_extra) $(libcoregrind_a_extra2)

vg_preload_core_so_SOURCES = vg_preloaded.c
vg_preload_core_so_CFLAGS = $(AM_CFLAGS) -fpic
vg_preload_core_so_LDADD = -ldl
vg_preload_core_so_LDFLAGS = \
	-shared \
	-Wl,--soname,vg_preload_core.so \
	-Wl,-z,initfirst

@VEX_DIR@/libvex.a: @VEX_DIR@/priv/main/vex_svnversion.h
	$(MAKE) -C @VEX_DIR@ libvex.a

@VEX_DIR@/priv/main/vex_svnversion.h:
	$(MAKE) -C @VEX_DIR@ version

clean-local:
	$(MAKE) -C @VEX_DIR@ clean

MANUAL_DEPS = $(noinst_HEADERS) $(include_HEADERS)

all-local:
	mkdir -p $(inplacedir)
	for i in $(val_PROGRAMS); do \
		to=$(inplacedir)/$$i; \
		rm -f $$$to; \
		ln -sf ../$(subdir)/$$i $$to; \
	done

