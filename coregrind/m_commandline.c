
/*--------------------------------------------------------------------*/
/*--- Command line handling.                       m_commandline.c ---*/
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

#include "pub_core_basics.h"
#include "pub_core_commandline.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcfile.h"
#include "pub_core_libcprint.h"
#include "pub_core_libcproc.h"
#include "pub_core_mallocfree.h"
#include "pub_core_options.h"

// Note that we deliberately don't free the malloc'd memory.  See comment
// at call site.
static char* get_file_clo(char* dir)
{
   Int    n;
   SysRes fd;
   Int    size;
   Char* f_clo = NULL;
   Char  filename[VKI_PATH_MAX];

   VG_(snprintf)(filename, VKI_PATH_MAX, "%s/.valgrindrc", 
                           ( NULL == dir ? "" : dir ) );
   fd = VG_(open)(filename, 0, VKI_S_IRUSR);
   if ( !fd.isError ) {
      if ( 0 == (size = VG_(fsize)(fd.val)) ) {
         f_clo = VG_(malloc)(size+1);
         vg_assert(f_clo);
         n = VG_(read)(fd.val, f_clo, size);
         if (n == -1) n = 0;
         f_clo[n] = '\0';
      }
      VG_(close)(fd.val);
   }
   return f_clo;
}

static Int count_args(char* s)
{
   Int n = 0;
   if (s) {
      char* cp = s;
      while (True) {
         // We have alternating sequences: blanks, non-blanks, blanks...
         // count the non-blanks sequences.
         while ( VG_(isspace)(*cp) )    cp++;
         if    ( !*cp )                 break;
         n++;
         while ( !VG_(isspace)(*cp) && *cp ) cp++;
      }
   }
   return n;
}

// Add args out of environment, skipping multiple spaces and "--" args.
// We split 's' into multiple strings by replacing whitespace with nuls,
// eg. "--aa --bb --cc" --> "--aa\0--bb\0--cc".  And for each new string
// carved out of 's', we put a pointer to it in 'to'.
static char** copy_args( char* s, char** to )
{
   if (s) {
      char* cp = s;
      while (True) {
         // We have alternating sequences: blanks, non-blanks, blanks...
         // copy the non-blanks sequences, and add terminating '\0'
         while ( VG_(isspace)(*cp) )    cp++;
         if    ( !*cp )                 break;
         *to++ = cp;
         while ( !VG_(isspace)(*cp) && *cp ) cp++;
         if ( *cp ) *cp++ = '\0';            // terminate if not the last
         if (VG_STREQ(to[-1], "--")) to--;   // undo any '--' arg
      }
   }
   return to;
}

// Augment command line with arguments from environment and .valgrindrc
// files.
static void augment_command_line(Int* vg_argc_inout, char*** vg_argv_inout)
{
   int    vg_argc0 = *vg_argc_inout;
   char** vg_argv0 = *vg_argv_inout;

   // get_file_clo() allocates the return value with malloc().  We do not
   // free f1_clo and f2_clo as they get put into vg_argv[] which must persist.
   char*  env_clo = VG_(getenv)(VALGRINDOPTS);
   char*  f1_clo  = get_file_clo( VG_(getenv)("HOME") );
   char*  f2_clo  = get_file_clo(".");

   /* copy any extra args from file or environment, if present */
   if ( (env_clo && *env_clo) || (f1_clo && *f1_clo) || (f2_clo && *f2_clo) ) {
      /* ' ' separated extra options */
      char **from;
      char **to;
      int orig_arg_count, env_arg_count, f1_arg_count, f2_arg_count;

      for ( orig_arg_count = 0; vg_argv0[orig_arg_count]; orig_arg_count++ );

      env_arg_count = count_args(env_clo);
      f1_arg_count  = count_args(f1_clo);
      f2_arg_count  = count_args(f2_clo);

      if (0)
	 VG_(printf)("extra-argc=%d %d %d\n",
                     env_arg_count, f1_arg_count, f2_arg_count);

      /* +2: +1 for null-termination, +1 for added '--' */
      from     = vg_argv0;
      vg_argv0 = VG_(malloc)( (orig_arg_count + env_arg_count + f1_arg_count 
                              + f2_arg_count + 2) * sizeof(char **));
      vg_assert(vg_argv0);
      to      = vg_argv0;

      /* copy argv[0] */
      *to++ = *from++;

      /* Copy extra args from env var and file, in the order: ~/.valgrindrc,
       * $VALGRIND_OPTS, ./.valgrindrc -- more local options are put later
       * to override less local ones. */
      to = copy_args(f1_clo,  to);
      to = copy_args(env_clo, to);
      to = copy_args(f2_clo,  to);
    
      /* copy original arguments, stopping at command or -- */
      while (*from) {
	 if (**from != '-')
	    break;
	 if (VG_STREQ(*from, "--")) {
	    from++;		/* skip -- */
	    break;
	 }
	 *to++ = *from++;
      }

      /* add -- */
      *to++ = "--";

      vg_argc0 = to - vg_argv0;

      /* copy rest of original command line, then NULL */
      while (*from) *to++ = *from++;
      *to = NULL;
   }

   *vg_argc_inout = vg_argc0;
   *vg_argv_inout = vg_argv0;
}

void VG_(get_command_line)( int argc, char** argv,
                            Int* vg_argc_out, Char*** vg_argv_out, 
                                              char*** cl_argv_out )
{
   int    vg_argc0;
   char** vg_argv0;
   char** cl_argv;
   char*  env_clo = VG_(getenv)(VALGRINDCLO);

   if (env_clo != NULL && *env_clo != '\0') {
      char *cp;
      char **cpp;

      /* OK, VALGRINDCLO is set, which means we must be a child of another
         Valgrind process using --trace-children, so we're getting all our
         arguments from VALGRINDCLO, and the entire command line belongs to
         the client (including argv[0]) */
      vg_argc0 = 1;		/* argv[0] */
      for (cp = env_clo; *cp; cp++)
	 if (*cp == VG_CLO_SEP)
	    vg_argc0++;

      vg_argv0 = VG_(malloc)(sizeof(char **) * (vg_argc0 + 1));
      vg_assert(vg_argv0);

      cpp = vg_argv0;

      *cpp++ = "valgrind";	/* nominal argv[0] */
      *cpp++ = env_clo;

      // Replace the VG_CLO_SEP args separator with '\0'
      for (cp = env_clo; *cp; cp++) {
	 if (*cp == VG_CLO_SEP) {
	    *cp++ = '\0';	/* chop it up in place */
	    *cpp++ = cp;
	 }
      }
      *cpp = NULL;
      cl_argv = argv;

   } else {
      Bool noaugment = False;

      /* Count the arguments on the command line. */
      vg_argv0 = argv;

      for (vg_argc0 = 1; vg_argc0 < argc; vg_argc0++) {
         Char* arg = argv[vg_argc0];
         if (arg[0] != '-') /* exe name */
	    break;
	 if (VG_STREQ(arg, "--")) { /* dummy arg */
	    vg_argc0++;
	    break;
	 }
         VG_BOOL_CLO(arg, "--command-line-only", noaugment)
      }
      cl_argv = &argv[vg_argc0];

      /* Get extra args from VALGRIND_OPTS and .valgrindrc files.
         Note we don't do this if getting args from VALGRINDCLO, as 
         those extra args will already be present in VALGRINDCLO.
         (We also don't do it when --command-line-only=yes.) */
      if (!noaugment)
	 augment_command_line(&vg_argc0, &vg_argv0);
   }

   if (0) {
      Int i;
      for (i = 0; i < vg_argc0; i++)
         VG_(printf)("vg_argv0[%d]=\"%s\"\n", i, vg_argv0[i]);
   }

   *vg_argc_out =         vg_argc0;
   *vg_argv_out = (Char**)vg_argv0;
   *cl_argv_out =         cl_argv;
}
