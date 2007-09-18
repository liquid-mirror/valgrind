
# For AM_FLAG_M3264_PRI
include $(top_srcdir)/Makefile.flags.am

noinst_SCRIPTS = filter_stderr

EXTRA_DIST = $(noinst_SCRIPTS) \
	basic.post.exp basic.stderr.exp basic.vgtest \
        basic_malloc.stderr.exp basic_malloc.vgtest \
        toobig-allocs.stderr.exp toobig-allocs.vgtest

AM_CFLAGS   = $(WERROR) -Winline -Wall -Wshadow -g $(AM_FLAG_M3264_PRI)

check_PROGRAMS = \
	basic \
	basic_malloc

