include $(top_srcdir)/Makefile.tool.am

## Build Memcheck at a higher optimisation level
AM_CFLAGS += -O2

val_PROGRAMS = vgpreload_memcheck.so
bin_PROGRAMS = valgrind_memcheck

vgpreload_memcheck_so_SOURCES = \
	mac_replace_strmem.c
vgpreload_memcheck_so_DEPENDENCIES = \
	$(LIBREPLACEMALLOC)
vgpreload_memcheck_so_LDFLAGS = -shared -Wl,-z,interpose,-z,initfirst \
	-Wl,--whole-archive \
	$(LIBREPLACEMALLOC) \
	-Wl,--no-whole-archive

valgrind_memcheck_DEPENDENCIES = $(top_srcdir)/coregrind/libcoregrind.a
valgrind_memcheck_SOURCES = \
	mac_leakcheck.c \
	mac_malloc_wrappers.c \
	mc_main.c \
	mac_shared.c \
	mc_translate.c
valgrind_memcheck_LDFLAGS = \
	$(top_srcdir)/coregrind/libcoregrind.a

# \
#	-Wl,-T,$(top_srcdir)/valt_load_address.lds \
#	-Wl,-defsym,valt_load_address=@VALT_LOAD_ADDRESS@

mcincludedir = $(includedir)/valgrind

mcinclude_HEADERS = \
	memcheck.h

noinst_HEADERS =	\
	mac_shared.h	\
	mc_include.h

mac_replace_strmem.o: CFLAGS += -fno-omit-frame-pointer

mc_main.o: CFLAGS += -fomit-frame-pointer
