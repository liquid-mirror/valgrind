noinst_SCRIPTS = filter_stderr

EXTRA_DIST = $(noinst_SCRIPTS) \
	linux-capget linux-capget.stderr.exp \
	linux-timerfd-syscall linux-timerfd-syscall.stderr.exp

check_PROGRAMS = \
	linux-capget \
	linux-timerfd-syscall

AM_CPPFLAGS  = -I$(top_srcdir)/include
AM_CFLAGS    = $(WERROR) @FLAG_M32@ -Winline -Wall -Wshadow -g \
		$(FLAG_MMMX) $(FLAG_MSSE)
AM_CXXFLAGS  = $(AM_CFLAGS)
AM_CCASFLAGS = @FLAG_M32@

linux_timerfd_syscall_LDADD = -lrt

