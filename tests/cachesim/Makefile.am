## Process this file with automake to produce Makefile.in

noinst_PROGRAMS = \
	dlclose myprint.so

# XXX: want to have this inherited from ../Makefile.am
CFLAGS = $(WERROR) -Winline -Wall -Wshadow -g
CC = /usr/bin/gcc

# --skin=cachesim ones
dlclose_SOURCES		= dlclose.c
dlclose_LDADD		= -ldl
myprint_so_SOURCES	= myprint.c
myprint_so_LDFLAGS	= -shared

#myprint.so$(EXEEXT): $(myprint_so_OBJECTS)
#	$(CC) $(CFLAGS) -shared -o myprint.so $(myprint_so_OBJECTS)



