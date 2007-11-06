include $(top_srcdir)/Makefile.tool.am

noinst_PROGRAMS = 
if VGP_X86_LINUX
noinst_PROGRAMS += thrcheck-x86-linux vgpreload_thrcheck-x86-linux.so
endif
if VGP_AMD64_LINUX
noinst_PROGRAMS += thrcheck-amd64-linux vgpreload_thrcheck-amd64-linux.so
endif
if VGP_PPC32_LINUX
noinst_PROGRAMS += thrcheck-ppc32-linux vgpreload_thrcheck-ppc32-linux.so
endif
if VGP_PPC64_LINUX
noinst_PROGRAMS += thrcheck-ppc64-linux vgpreload_thrcheck-ppc64-linux.so
endif
if VGP_PPC32_AIX5
noinst_PROGRAMS += thrcheck-ppc32-aix5 vgpreload_thrcheck-ppc32-aix5.so
endif
if VGP_PPC64_AIX5
noinst_PROGRAMS += thrcheck-ppc64-aix5 vgpreload_thrcheck-ppc64-aix5.so
endif

VGPRELOAD_THRCHECK_SOURCES_COMMON = tc_intercepts.c

vgpreload_thrcheck_x86_linux_so_SOURCES      = $(VGPRELOAD_THRCHECK_SOURCES_COMMON)
vgpreload_thrcheck_x86_linux_so_CPPFLAGS     = $(AM_CPPFLAGS_X86_LINUX) -O -g -fno-omit-frame-pointer
vgpreload_thrcheck_x86_linux_so_CFLAGS       = $(AM_CFLAGS_X86_LINUX) $(AM_CFLAGS_PIC)
vgpreload_thrcheck_x86_linux_so_DEPENDENCIES = $(LIBREPLACEMALLOC_X86_LINUX)
vgpreload_thrcheck_x86_linux_so_LDFLAGS      = \
	$(PRELOAD_LDFLAGS_X86_LINUX) \
	$(LIBREPLACEMALLOC_LDFLAGS_X86_LINUX)

vgpreload_thrcheck_amd64_linux_so_SOURCES      = $(VGPRELOAD_THRCHECK_SOURCES_COMMON)
vgpreload_thrcheck_amd64_linux_so_CPPFLAGS     = $(AM_CPPFLAGS_AMD64_LINUX) -O -g
vgpreload_thrcheck_amd64_linux_so_CFLAGS       = $(AM_CFLAGS_AMD64_LINUX) $(AM_CFLAGS_PIC)
vgpreload_thrcheck_amd64_linux_so_DEPENDENCIES = $(LIBREPLACEMALLOC_AMD64_LINUX)
vgpreload_thrcheck_amd64_linux_so_LDFLAGS      = \
	$(PRELOAD_LDFLAGS_AMD64_LINUX) \
	$(LIBREPLACEMALLOC_LDFLAGS_AMD64_LINUX)

vgpreload_thrcheck_ppc32_linux_so_SOURCES      = $(VGPRELOAD_THRCHECK_SOURCES_COMMON)
vgpreload_thrcheck_ppc32_linux_so_CPPFLAGS     = $(AM_CPPFLAGS_PPC32_LINUX) -O -g
vgpreload_thrcheck_ppc32_linux_so_CFLAGS       = $(AM_CFLAGS_PPC32_LINUX) $(AM_CFLAGS_PIC)
vgpreload_thrcheck_ppc32_linux_so_DEPENDENCIES = $(LIBREPLACEMALLOC_PPC32_LINUX)
vgpreload_thrcheck_ppc32_linux_so_LDFLAGS      = \
	$(PRELOAD_LDFLAGS_PPC32_LINUX) \
	$(LIBREPLACEMALLOC_LDFLAGS_PPC32_LINUX)

vgpreload_thrcheck_ppc64_linux_so_SOURCES      = $(VGPRELOAD_THRCHECK_SOURCES_COMMON)
vgpreload_thrcheck_ppc64_linux_so_CPPFLAGS     = $(AM_CPPFLAGS_PPC64_LINUX) -O -g
vgpreload_thrcheck_ppc64_linux_so_CFLAGS       = $(AM_CFLAGS_PPC64_LINUX) $(AM_CFLAGS_PIC)
vgpreload_thrcheck_ppc64_linux_so_DEPENDENCIES = $(LIBREPLACEMALLOC_PPC64_LINUX)
vgpreload_thrcheck_ppc64_linux_so_LDFLAGS      = \
	$(PRELOAD_LDFLAGS_PPC64_LINUX) \
	$(LIBREPLACEMALLOC_LDFLAGS_PPC64_LINUX)

vgpreload_thrcheck_ppc32_aix5_so_SOURCES      = $(VGPRELOAD_THRCHECK_SOURCES_COMMON)
vgpreload_thrcheck_ppc32_aix5_so_CPPFLAGS     = $(AM_CPPFLAGS_PPC32_AIX5) -O -g
vgpreload_thrcheck_ppc32_aix5_so_CFLAGS       = $(AM_CFLAGS_PPC32_AIX5) $(AM_CFLAGS_PIC)
vgpreload_thrcheck_ppc32_aix5_so_DEPENDENCIES = $(LIBREPLACEMALLOC_PPC32_AIX5)
vgpreload_thrcheck_ppc32_aix5_so_LDFLAGS      = \
	$(PRELOAD_LDFLAGS_PPC32_AIX5) \
	$(LIBREPLACEMALLOC_LDFLAGS_PPC32_AIX5)

vgpreload_thrcheck_ppc64_aix5_so_SOURCES      = $(VGPRELOAD_THRCHECK_SOURCES_COMMON)
vgpreload_thrcheck_ppc64_aix5_so_CPPFLAGS     = $(AM_CPPFLAGS_PPC64_AIX5) -O -g
vgpreload_thrcheck_ppc64_aix5_so_CFLAGS       = $(AM_CFLAGS_PPC64_AIX5) $(AM_CFLAGS_PIC)
vgpreload_thrcheck_ppc64_aix5_so_DEPENDENCIES = $(LIBREPLACEMALLOC_PPC64_AIX5)
vgpreload_thrcheck_ppc64_aix5_so_LDFLAGS      = \
	$(PRELOAD_LDFLAGS_PPC64_AIX5) \
	$(LIBREPLACEMALLOC_LDFLAGS_PPC64_AIX5)

THRCHECK_SOURCES_COMMON = tc_wordfm.c tc_wordset.c tc_main.c

thrcheck_x86_linux_SOURCES      = $(THRCHECK_SOURCES_COMMON)
thrcheck_x86_linux_CPPFLAGS     = $(AM_CPPFLAGS_X86_LINUX)
thrcheck_x86_linux_CFLAGS       = $(AM_CFLAGS_X86_LINUX) -O2
thrcheck_x86_linux_DEPENDENCIES = $(COREGRIND_LIBS_X86_LINUX)
thrcheck_x86_linux_LDADD        = $(TOOL_LDADD_X86_LINUX)
thrcheck_x86_linux_LDFLAGS      = $(TOOL_LDFLAGS_X86_LINUX)

thrcheck_amd64_linux_SOURCES      = $(THRCHECK_SOURCES_COMMON)
thrcheck_amd64_linux_CPPFLAGS     = $(AM_CPPFLAGS_AMD64_LINUX)
thrcheck_amd64_linux_CFLAGS       = $(AM_CFLAGS_AMD64_LINUX) -O2
thrcheck_amd64_linux_DEPENDENCIES = $(COREGRIND_LIBS_AMD64_LINUX)
thrcheck_amd64_linux_LDADD        = $(TOOL_LDADD_AMD64_LINUX)
thrcheck_amd64_linux_LDFLAGS      = $(TOOL_LDFLAGS_AMD64_LINUX)

thrcheck_ppc32_linux_SOURCES      = $(THRCHECK_SOURCES_COMMON)
thrcheck_ppc32_linux_CPPFLAGS     = $(AM_CPPFLAGS_PPC32_LINUX)
thrcheck_ppc32_linux_CFLAGS       = $(AM_CFLAGS_PPC32_LINUX) -O2
thrcheck_ppc32_linux_DEPENDENCIES = $(COREGRIND_LIBS_PPC32_LINUX)
thrcheck_ppc32_linux_LDADD        = $(TOOL_LDADD_PPC32_LINUX)
thrcheck_ppc32_linux_LDFLAGS      = $(TOOL_LDFLAGS_PPC32_LINUX)

thrcheck_ppc64_linux_SOURCES      = $(THRCHECK_SOURCES_COMMON)
thrcheck_ppc64_linux_CPPFLAGS     = $(AM_CPPFLAGS_PPC64_LINUX)
thrcheck_ppc64_linux_CFLAGS       = $(AM_CFLAGS_PPC64_LINUX) -O2
thrcheck_ppc64_linux_DEPENDENCIES = $(COREGRIND_LIBS_PPC64_LINUX)
thrcheck_ppc64_linux_LDADD        = $(TOOL_LDADD_PPC64_LINUX)
thrcheck_ppc64_linux_LDFLAGS      = $(TOOL_LDFLAGS_PPC64_LINUX)

thrcheck_ppc32_aix5_SOURCES      = $(THRCHECK_SOURCES_COMMON)
thrcheck_ppc32_aix5_CPPFLAGS     = $(AM_CPPFLAGS_PPC32_AIX5)
thrcheck_ppc32_aix5_CFLAGS       = $(AM_CFLAGS_PPC32_AIX5) -O2
thrcheck_ppc32_aix5_DEPENDENCIES = $(COREGRIND_LIBS_PPC32_AIX5)
thrcheck_ppc32_aix5_LDADD        = $(TOOL_LDADD_PPC32_AIX5)
thrcheck_ppc32_aix5_LDFLAGS      = $(TOOL_LDFLAGS_PPC32_AIX5)

thrcheck_ppc64_aix5_SOURCES      = $(THRCHECK_SOURCES_COMMON)
thrcheck_ppc64_aix5_CPPFLAGS     = $(AM_CPPFLAGS_PPC64_AIX5)
thrcheck_ppc64_aix5_CFLAGS       = $(AM_CFLAGS_PPC64_AIX5) -O2
thrcheck_ppc64_aix5_DEPENDENCIES = $(COREGRIND_LIBS_PPC64_AIX5)
thrcheck_ppc64_aix5_LDADD        = $(TOOL_LDADD_PPC64_AIX5)
thrcheck_ppc64_aix5_LDFLAGS      = $(TOOL_LDFLAGS_PPC64_AIX5)

tcincludedir = $(includedir)/valgrind

tcinclude_HEADERS = thrcheck.h

noinst_HEADERS = tc_wordfm.h tc_wordset.h
