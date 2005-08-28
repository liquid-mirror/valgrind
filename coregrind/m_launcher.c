
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pub_core_basics.h"
#include "pub_core_debuglog.h"
#include "pub_core_libcproc.h"   // For VALGRINDLIB

/* Where we expect to find all our aux files */
static const char *valgrind_lib = VG_LIBDIR;

int main(int argc, char** argv, char** envp)
{
   const char *toolname = NULL;
   const char *cp;
   int i, loglevel;
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
     if (0 == strncmp(argv[i], "--tool=", 7)) 
        toolname = argv[i] + 7;
   }

   /* ... and start the debug logger.  Now we can safely emit logging
      messages all through startup. */
   VG_(debugLog_startup)(loglevel, "Stage 1");

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
