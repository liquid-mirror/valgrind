include $(top_srcdir)/Makefile.tool.am

bin_PROGRAMS = valgrind_lackey

valgrind_lackey_DEPENDENCIES = $(top_srcdir)/coregrind/libcoregrind.a
valgrind_lackey_SOURCES = \
	lk_main.c
valgrind_lackey_LDFLAGS = \
	-static \
	$(top_srcdir)/coregrind/libcoregrind.a \
	-Wl,-defsym,valt_load_address=@VALT_LOAD_ADDRESS@ \
	-Wl,-T,$(top_srcdir)/valt_load_address.lds \
	-nodefaultlibs -lgcc -nostartfiles
