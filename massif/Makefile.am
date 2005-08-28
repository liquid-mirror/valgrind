include $(top_srcdir)/Makefile.tool.am

SUBDIRS += hp2ps

val_PROGRAMS = massif vgpreload_massif.so

vgpreload_massif_so_SOURCES = 
vgpreload_massif_so_DEPENDENCIES = \
	$(LIBREPLACEMALLOC)
vgpreload_massif_so_LDFLAGS = -shared -Wl,-z,interpose,-z,initfirst \
	-Wl,--whole-archive \
	$(LIBREPLACEMALLOC) \
	-Wl,--no-whole-archive

massif_DEPENDENCIES = $(top_srcdir)/coregrind/libcoregrind.a
massif_SOURCES = \
	ms_main.c
massif_LDFLAGS = \
	-static \
	$(top_srcdir)/coregrind/libcoregrind.a \
	-Wl,-defsym,valt_load_address=@VALT_LOAD_ADDRESS@ \
	-Wl,-T,$(top_srcdir)/valt_load_address.lds \
	-nodefaultlibs -lgcc -nostartfiles
