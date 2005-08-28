include $(top_srcdir)/Makefile.tool.am

val_PROGRAMS = none

none_DEPENDENCIES = $(top_srcdir)/coregrind/libcoregrind.a
none_SOURCES = \
	nl_main.c
none_LDFLAGS = \
	-static \
	$(top_srcdir)/coregrind/libcoregrind.a \
	-Wl,-defsym,valt_load_address=@VALT_LOAD_ADDRESS@ \
	-Wl,-T,$(top_srcdir)/valt_load_address.lds \
	-nodefaultlibs -lgcc -nostartfiles
