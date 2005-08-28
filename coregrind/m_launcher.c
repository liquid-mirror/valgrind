
/*--------------------------------------------------------------------*/
/*--- Launching valgrind                              m_launcher.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2000-2005 Julian Seward 
      jseward@acm.org

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.
*/

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pub_core_basics.h"
#include "pub_core_commandline.h"
#include "pub_core_debuglog.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcfile.h"
#include "pub_core_libcprint.h"
#include "pub_core_libcproc.h"   // For VALGRINDLIB
#include "pub_core_mallocfree.h"

/* Where we expect to find all our aux files */
static const char *valgrind_lib = VG_LIBDIR;

int main(int argc, char** argv, char** envp)
{
   int i, loglevel;
   Int vg_argc;
   Char **vg_argv;
   char **cl_argv;
   const char *toolname = NULL;
   const char *cp;
   char *toolfile;

   /* Start the debugging-log system ASAP.  First find out how many 
      "-d"s were specified.  This is a pre-scan of the command line. */
   loglevel = 0;
   for (i = 1; i < argc; i++) {
     if (argv[i][0] != '-')
        break;
     if (0 == strcmp(argv[i], "--")) 
        break;
     if (0 == strcmp(argv[i], "-d")) 
        loglevel++;
   }

   /* ... and start the debug logger.  Now we can safely emit logging
      messages all through startup. */
   VG_(debugLog_startup)(loglevel, "Stage 1");

   /* Get the full command line */
   VG_(get_command_line)(argc, argv, &vg_argc, &vg_argv, &cl_argv);

   /* Look for a --tool switch */
   for (i = 1; i < vg_argc; i++) {
     if (0 == strncmp(vg_argv[i], "--tool=", 7)) 
        toolname = vg_argv[i] + 7;
   }

   /* Make sure we know which tool we're using */
   if (toolname) {
      VG_(debugLog)(1, "stage1", "tool %s requested\n", toolname);
   } else {
      VG_(debugLog)(1, "stage1", "no tool requested, defaulting to memcheck\n");
      toolname = "memcheck";
   }

   cp = getenv(VALGRINDLIB);

   if (cp != NULL)
      valgrind_lib = cp;

   toolfile = malloc(strlen(valgrind_lib) + strlen(toolname) + 2);
   sprintf(toolfile, "%s/%s", valgrind_lib, toolname);

   VG_(debugLog)(1, "stage1", "launching %s\n", toolfile);

   execve(toolfile, argv, envp);

   fprintf(stderr, "valgrind: failed to start %s: %s", toolname, strerror(errno));

   exit(1);
}

void* VG_(malloc) ( SizeT nbytes )
{
   return malloc(nbytes);
}

Bool VG_(isspace) ( Char c )
{
   return isspace(c);
}

Int VG_(strcmp) ( const Char* s1, const Char* s2 )
{
   return strcmp(s1, s2);
}

Char *VG_(getenv)(Char *varname)
{
   return getenv(varname);
}

SysRes VG_(open) ( const Char* pathname, Int flags, Int mode )
{
   SysRes res;
   Int fd;
   if ((fd = open(pathname, flags, mode)) < 0) {
      res.isError = True;
      res.val = errno;
   } else {
      res.isError = False;
      res.val = fd;
   }
   return res;
}

void VG_(close) ( Int fd )
{
   close(fd);
   return;
}

Int VG_(read) ( Int fd, void* buf, Int count)
{
   return read(fd, buf, count);
}

Int VG_(fstat) ( Int fd, struct vki_stat* buf )
{
   return fstat(fd, buf);
}

UInt VG_(snprintf) ( Char* buf, Int size, const HChar *format, ... )
{
   va_list vargs;
   UInt n;

   va_start(vargs, format);
   n = vsnprintf(buf, size, format, vargs);
   va_end(vargs);

   return n;
}

void VG_(assert_fail) ( Bool isCore, const Char* expr, const Char* file, 
                        Int line, const Char* fn, const HChar* format, ... )
{
   va_list vargs;
   Char buf[256];

   va_start(vargs, format);
   vsprintf(buf, format, vargs);
   va_end(vargs);

   fprintf(stderr, "\nvalgrind: %s:%d (%s): Assertion '%s' failed.\n",
           file, line, fn, expr );
   if (!strcmp(buf, ""))
      fprintf(stderr, "valgrind: %s\n", buf);

   exit(1);
}

static Bool isterm ( Char c )
{
   return ( VG_(isspace)(c) || 0 == c );
}

Int VG_(strcmp_ws) ( const Char* s1, const Char* s2 )
{
   while (True) {
      if (isterm(*s1) && isterm(*s2)) return 0;
      if (isterm(*s1)) return -1;
      if (isterm(*s2)) return 1;

      if (*(UChar*)s1 < *(UChar*)s2) return -1;
      if (*(UChar*)s1 > *(UChar*)s2) return 1;

      s1++; s2++;
   }
}
