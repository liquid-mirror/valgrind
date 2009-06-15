
include $(top_srcdir)/Makefile.tool-tests.am

dist_noinst_SCRIPTS = filter_stderr

check_PROGRAMS = asm lea

EXTRA_DIST = \
	asm.vgtest-disabled asm.stderr.exp \
	lea.vgtest-disabled lea.stderr.exp


AM_CFLAGS    += @FLAG_M32@ $(FLAG_MMMX) $(FLAG_MSSE)
AM_CXXFLAGS  += @FLAG_M32@ $(FLAG_MMMX) $(FLAG_MSSE)
AM_CCASFLAGS += @FLAG_M32@

asm_SOURCES = asm.S
lea_SOURCES = lea.S
