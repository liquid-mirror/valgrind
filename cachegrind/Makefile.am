include $(top_srcdir)/Makefile.tool.am

bin_SCRIPTS = cg_annotate

# Remember to include all the arch-specific files in the distribution.
EXTRA_DIST = \
	cg_sim.c \
	$(addsuffix .c,$(addprefix cg-,$(VG_ARCH_ALL)))

noinst_HEADERS = cg_arch.h

bin_PROGRAMS = valgrind_cachegrind

valgrind_cachegrind_DEPENDENCIES = $(top_srcdir)/coregrind/libcoregrind.a
valgrind_cachegrind_SOURCES = \
	cg_main.c \
	cg-@VG_ARCH@.c
valgrind_cachegrind_LDFLAGS = \
	-static \
	$(top_srcdir)/coregrind/libcoregrind.a \
	-Wl,-defsym,valt_load_address=@VALT_LOAD_ADDRESS@ \
	-Wl,-T,$(top_srcdir)/valt_load_address.lds \
	-nodefaultlibs -lgcc -nostartfiles
