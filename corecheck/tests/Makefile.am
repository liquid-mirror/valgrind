## Process this file with automake to produce Makefile.in

##---------------------------------------------------------------------------
## These test core error checking, eg. "silly values" for malloc/calloc,
## pthread errors, signal handling errors, invalid fds for blocking 
## syscalls, etc.
##---------------------------------------------------------------------------

noinst_PROGRAMS = \
	erringfds malloc3 sigkill pth_empty

# XXX: want to have this inherited from ../Makefile.am
CFLAGS   = $(WERROR) -Winline -Wall -Wshadow -g
CXXFLAGS = $(CFLAGS)

erringfds_SOURCES 	= erringfds.c
malloc3_SOURCES 	= malloc3.c
sigkill_SOURCES 	= sigkill.c
pth_empty_SOURCES 	= pth_empty.c
pth_empty_LDADD 	= -lpthread


