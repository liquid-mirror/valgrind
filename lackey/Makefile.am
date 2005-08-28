include $(top_srcdir)/Makefile.tool.am

val_PROGRAMS = lackey

lackey_DEPENDENCIES = $(top_srcdir)/coregrind/libcoregrind.a
lackey_SOURCES = \
	lk_main.c
lackey_LDFLAGS = \
	-static \
	$(top_srcdir)/coregrind/libcoregrind.a \
	-Wl,-defsym,valt_load_address=@VALT_LOAD_ADDRESS@ \
	-Wl,-T,$(top_srcdir)/valt_load_address.lds \
	-nodefaultlibs -lgcc -nostartfiles
