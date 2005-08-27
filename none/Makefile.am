include $(top_srcdir)/Makefile.tool.am

bin_PROGRAMS = valgrind_none

valgrind_none_DEPENDENCIES = $(top_srcdir)/coregrind/libcoregrind.a
valgrind_none_SOURCES = \
	nl_main.c
valgrind_none_LDFLAGS = \
	-static \
	$(top_srcdir)/coregrind/libcoregrind.a \
	-Wl,-defsym,valt_load_address=@VALT_LOAD_ADDRESS@ \
	-Wl,-T,$(top_srcdir)/valt_load_address.lds \
	-nodefaultlibs -lgcc -nostartfiles
