
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

// TODO: prune these
#include "pub_core_basics.h"
#include "pub_core_commandline.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcfile.h"
#include "pub_core_libcprint.h"
#include "pub_core_libcproc.h"
#include "pub_core_mallocfree.h"
#include "pub_core_options.h"
#include "pub_core_clientstate.h"


/* Add a string to an expandable array of strings. */
static void add_string ( XArrayStrings* xa, HChar* str )
{
   Int     i;
   HChar** strs2;
   vg_assert(xa->used >= 0);
   vg_assert(xa->size >= 0);
   vg_assert(xa->used <= xa->size);
   if (xa->strs == NULL) vg_assert(xa->size == 0);

   if (xa->used == xa->size) {
      xa->size = xa->size==0 ? 2 : 2*xa->size;
      strs2 = VG_(malloc)( xa->size * sizeof(HChar*) );
      for (i = 0; i < xa->used; i++)
         strs2[i] = xa->strs[i];
      if (xa->strs) 
         VG_(free)(xa->strs);
      xa->strs = strs2;
   }
   vg_assert(xa->used < xa->size);
   xa->strs[xa->used++] = str;
}


/* Split up the args presented by the launcher to m_main.main(), and
   park them in VG_(args_for_client), VG_(args_for_valgrind),
   VG_(args_for_valgrind_extras) and VG_(args_the_exename).  The
   latter are acquired from $VALGRIND_OPTS, ./.valgrindrc and
   ~/.valgrindrc. 
*/
/* Scheme: args look like this:

      args-for-v  exe_name  args-for-c

   args-for-v are taken until either they don't start with '-' or
   a "--" is seen.

   If args-for-v includes --command-line-only=yes, then the extra
   sources (env vars, files) are not consulted.

   Note that args-for-c[0] is the first real arg for the client, not
   its executable name.
*/


void VG_(split_up_argv)( Int argc, HChar** argv )
{
          Int  i;
          Bool augment = True;
   static Bool already_called = False;

   /* This function should be called once, at startup, and then never
      again. */
   vg_assert(!already_called);
   already_called = True;

   /* Collect up the args-for-V. */
   i = 1; /* skip the exe (stage2) name. */
   for (; i < argc; i++) {
      vg_assert(argv[i]);
      if (0 == VG_(strcmp)(argv[i], "--")) {
         i++;
         break;
      }
      if (0 == VG_(strcmp)(argv[i], "--command-line-only=yes"))
         augment = False;
      if (argv[i][0] != '-')
	break;
      add_string( &VG_(args_for_valgrind), argv[i] );
   }

   /* Should now be looking at the exe name. */
   if (i < argc) {
     vg_assert(argv[i]);
      VG_(args_the_exename) = argv[i];
      i++;
   }

   /* The rest are args for the client. */
   for (; i < argc; i++) {
     vg_assert(argv[i]);
     add_string( &VG_(args_for_client), argv[i] );
   }


}


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
#if 0
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
#endif
}
