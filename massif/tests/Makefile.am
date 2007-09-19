
# For AM_FLAG_M3264_PRI
include $(top_srcdir)/Makefile.flags.am

noinst_SCRIPTS = filter_stderr

EXTRA_DIST = $(noinst_SCRIPTS) \
	basic.post.exp basic.stderr.exp basic.vgtest \
        basic_malloc.stderr.exp basic_malloc.vgtest \
	thresholds_0_0.post.exp   thresholds_0_0.stderr.exp   thresholds_0_0.vgtest \
	thresholds_0_10.post.exp  thresholds_0_10.stderr.exp  thresholds_0_10.vgtest \
	thresholds_10_0.post.exp  thresholds_10_0.stderr.exp  thresholds_10_0.vgtest \
	thresholds_5_0.post.exp   thresholds_5_0.stderr.exp   thresholds_5_0.vgtest \
	thresholds_5_10.post.exp  thresholds_5_10.stderr.exp  thresholds_5_10.vgtest \
	thresholds_10_10.post.exp thresholds_10_10.stderr.exp thresholds_10_10.vgtest \
        toobig-allocs.stderr.exp toobig-allocs.vgtest

AM_CFLAGS   = $(WERROR) -Winline -Wall -Wshadow -g $(AM_FLAG_M3264_PRI)

check_PROGRAMS = \
	basic \
	basic_malloc \
	thresholds

