
# For AM_FLAG_M3264_PRI
include $(top_srcdir)/Makefile.flags.am

noinst_SCRIPTS = \
	vg_regtest \
	filter_addresses \
	filter_discards \
	filter_libc \
	filter_numbers \
	filter_stderr_basic \
	filter_sink \
	filter_test_paths

EXTRA_DIST = $(noinst_SCRIPTS)

check_PROGRAMS = \
	cputest \
	toobig-allocs \
	true

AM_CFLAGS   = $(WERROR) -Winline -Wall -Wshadow -g $(AM_FLAG_M3264_PRI)
AM_CXXFLAGS = $(AM_CFLAGS)

# generic C ones
cputest_SOURCES 	= cputest.c
cputest_CFLAGS  	= $(AM_CFLAGS) \
				-DVGA_$(VG_ARCH_PRI)=1 -DVGO_$(VG_OS)=1 \
				-DVGP_$(VG_ARCH_PRI)_$(VG_OS)=1
cputest_DEPENDENCIES	= 
cputest_LDADD		= 
toobig_allocs_SOURCES	= toobig-allocs.c
true_SOURCES 		= true.c
