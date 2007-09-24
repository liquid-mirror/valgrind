
# For AM_FLAG_M3264_PRI
include $(top_srcdir)/Makefile.flags.am

noinst_SCRIPTS = filter_stderr filter_verbose

EXTRA_DIST = $(noinst_SCRIPTS) \
	alloc-fns-A.post.exp alloc-fns-A.stderr.exp alloc-fns-A.vgtest \
	alloc-fns-B.post.exp alloc-fns-B.stderr.exp alloc-fns-B.vgtest \
	basic.post.exp basic.stderr.exp basic.vgtest \
        basic_malloc.stderr.exp basic_malloc.vgtest \
        culling1.stderr.exp culling1.vgtest \
        culling2.stderr.exp culling2.vgtest \
	long-time.post.exp long-time.stderr.exp long-time.vgtest \
	null.post.exp null.stderr.exp null.vgtest \
	one.post.exp one.stderr.exp one.vgtest \
	realloc.post.exp realloc.stderr.exp realloc.vgtest \
	thresholds_0_0.post.exp   thresholds_0_0.stderr.exp   thresholds_0_0.vgtest \
	thresholds_0_10.post.exp  thresholds_0_10.stderr.exp  thresholds_0_10.vgtest \
	thresholds_10_0.post.exp  thresholds_10_0.stderr.exp  thresholds_10_0.vgtest \
	thresholds_5_0.post.exp   thresholds_5_0.stderr.exp   thresholds_5_0.vgtest \
	thresholds_5_10.post.exp  thresholds_5_10.stderr.exp  thresholds_5_10.vgtest \
	thresholds_10_10.post.exp thresholds_10_10.stderr.exp thresholds_10_10.vgtest \
        toobig-allocs.stderr.exp toobig-allocs.vgtest \
	zero1.post.exp zero1.stderr.exp zero1.vgtest
	zero2.post.exp zero2.stderr.exp zero2.vgtest

AM_CFLAGS   = $(WERROR) -Winline -Wall -Wshadow -g $(AM_FLAG_M3264_PRI)

check_PROGRAMS = \
	alloc-fns \
	basic \
	basic_malloc \
	culling1 culling2 \
	long-time \
	null \
	one \
	realloc \
	thresholds \
	zero

