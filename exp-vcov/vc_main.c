
/*--------------------------------------------------------------------*/
/*--- VCov: a testing coverage tool.                     vc_main.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of VCov, a Valgrind tool for measuring execution
   coverage.

   Copyright (C) 2002-2008 Nicholas Nethercote
      njn25@cam.ac.uk

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

// XXX TODO:
// - inline CC incrementing, rather than using a C call
// - add branch coverage, at least for encountered branches
// - the new seginfo_* functions -- would providing an iterator be better?
// - write tests -- work out how to make them deterministic...
// - write docs

// Overview:
// - VCov is a coverage testing tool.  It has similarities and differences
//   to gcov.
//
// - VCov counts the number of instructions executed for each source line.
//   This is different from gcov, which counts how many times each line was
//   executed;  VCov's counts will be strictly higher than gcov's for
//   equivalent runs, since each executable line is compiled down to one or
//   more instructions.
//
// - VCov relies entirely on debugging line information to determine which
//   lines have been executed, and more importantly, which lines have not.
//   Because of this, VCov works best when programs are compiled with no
//   optimisation.  When optimisation is used, the line numbers don't match
//   up as well and the annotated source can be confusing.
//
// - VCov does not use the same file format that 'gcov' uses.  gcov creates
//   three files for each source file: .bb, .bbg and .da.  The first two are
//   generated at compile time.  The third is generated at run-time.  This
//   file format is not easy to use by VCov because VCov is entirely
//   dynamic.  Therefore VCov uses its own file format.
//
// - Data for each run is stored in a single file, which is called
//   "vcov.out" by default.  Subsequent runs augment the file.  A different
//   file name can be specified.  Debugging information must be present in a
//   file for coverage data to be collected for it.
//
// - The accompanying script "vc_annotate" can calculate per-file execution
//   coverage.  It can also annotate source files.

#include "pub_tool_basics.h"
#include "pub_tool_vki.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_libcproc.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_options.h"
#include "pub_tool_tooliface.h"

/*------------------------------------------------------------*/
/*--- Types and Data Structures                            ---*/
/*------------------------------------------------------------*/

//------------------------------------------------------------
// Primary data structure: CC table
// - Holds the per-source-line exec counts, grouped by file.
// - hash_table(Char* filename, sorted_array(UInt line_num, ULong num_execs))
// - The hash table is separately chained.
// - Lookups are done by instruction address.
// - Traversed for dumping stats at end in a per-file, then per-line order.

#define N_FILE_ENTRIES        4999     // Must be prime.    XXX: too big?

// Nb: the log function accesses the 'n_execs' field directly.
typedef struct {
   UInt  line_num;      // Line number.
   ULong n_execs;       // How many times it has executed.
} LineCC;

typedef struct _FileCC FileCC;
struct _FileCC {
   Char*   dirname;     // Directory of this file.     
   Char*   filename;    // Name of this file.     
   FileCC* next;        // Next FileCC in the table.
   UInt    n_lineCCs;   // Number of LineCCs for this file.
   LineCC* lineCCs;     // The array of LineCCs for this file.
};

// Top level of CC table.  Auto-zeroed.
static FileCC *CC_table[N_FILE_ENTRIES];

//------------------------------------------------------------
// Stats

static Int  n_src_files          = 0;
static Int  n_no_debugs          = 0;
static Int  n_yes_debugs         = 0;
static Int  n_lineCC_slots_used  = 0;
static Int  n_lineCC_slots_total = 0;

/*------------------------------------------------------------*/
/*--- CC table operations                                  ---*/
/*------------------------------------------------------------*/

static UInt hash(Char* dirname, Char* filename, UInt table_size)
{
   const int hash_constant = 256;
   int hash_value = 0;
   for ( ; *dirname; dirname++)
      hash_value = (hash_constant * hash_value + *dirname) % table_size;
   for ( ; *filename; filename++)
      hash_value = (hash_constant * hash_value + *filename) % table_size;
   return hash_value;
}

static Int compareLineCC(void* va, void* vb)
{
   LineCC* a = (LineCC*)va;
   LineCC* b = (LineCC*)vb;

   // This should be safe because line numbers are fairly small (never
   // greater than 2 billion) and positive.  And it's faster than doing one
   // or more comparisons.
   return ((Int)a->line_num) - ((Int)b->line_num);
}

static void sort_and_remove_dups_from_FileCC(FileCC* cc)
{
   Int i, src, dst;
   Int n_line_CCs_with_dups = cc->n_lineCCs;

   // First, sort the array.
   VG_(ssort)(cc->lineCCs, cc->n_lineCCs, sizeof(LineCC), compareLineCC);
   for (i = 0; i < (Int)cc->n_lineCCs - 1; i++) {
      tl_assert(cc->lineCCs[i].line_num <= cc->lineCCs[i+1].line_num);
   }

   // Now remove any adjacent dups by shuffling entries down, and fill in
   // the tail with zeroes.
   dst = 1;
   src = 1;
   while (src < cc->n_lineCCs) {
      // If we hit a new src line_num (ie. it differs from its predecessor)
      // then we copy it to dst and increment dst.
      if (cc->lineCCs[src].line_num != cc->lineCCs[src-1].line_num) {
         cc->lineCCs[dst].line_num = cc->lineCCs[src].line_num;
         dst++;
      }
      src++;
   }
   for (i = dst ; i < cc->n_lineCCs; i++) {     // Zero the tail.
      cc->lineCCs[i].line_num = 0;
   }
   cc->n_lineCCs = dst;

   // Update stats.
   n_lineCC_slots_total += n_line_CCs_with_dups;
   n_lineCC_slots_used  += cc->n_lineCCs;

   // Check it's sorted and has no dups.
   for (i = 1; i < cc->n_lineCCs; i++) {
      tl_assert(cc->lineCCs[i-1].line_num < cc->lineCCs[i].line_num);
   }
}

static __inline__ 
FileCC* new_FileCC(Addr instrAddr, Char* dirname, Char* filename, FileCC* next)
{
   FileCC* cc;
   const SegInfo* seg;
   UInt  n_matches;
   Int   i;
   UInt  tmp_line;
   Char* tmp_dirname;
   Char* tmp_filename;

   // Print the filename, if asked-for.
   if (VG_(clo_verbosity) > 1) {
      VG_(message)(Vg_DebugMsg, "vcov: first occurrence of '%s'", filename);
   }
      
   // Create the FileCC.
   cc = VG_(malloc)(sizeof(FileCC));
   cc->dirname  = VG_(strdup)(dirname);
   cc->filename = VG_(strdup)(filename);
   cc->next = next;

   // XXX: better: malloc space according to the number of locns.  Then copy
   // the matching ones in, sort-and-remove-dups, then copy the remaining
   // ones into a new, right-sized array.

   // Now create the LineCCs.
   // Count how many locs in this SegInfo match 'filename' in order to
   // allocate the right-sized buffer.
   seg = VG_(find_seginfo)(instrAddr);
   tl_assert(seg);
   n_matches = 0;
   for (i = 0; i < VG_(seginfo_num_locs)(seg); i++) {
      tl_assert( VG_(seginfo_locN_dirname) (seg, i, &tmp_dirname) );
      tl_assert( VG_(seginfo_locN_filename)(seg, i, &tmp_filename) );
//    VG_(printf)("dirnames:  %s %s\n",  dirname,  tmp_dirname);
//    VG_(printf)("filenames: %s %s\n", filename, tmp_filename);
      if (VG_STREQ(dirname, tmp_dirname) && VG_STREQ(filename, tmp_filename))
         n_matches++;
   }
   // If there weren't any matches, something has gone wrong...
   tl_assert(n_matches > 0);

   // Allocate the lineCCs array.
   cc->n_lineCCs = n_matches;
   cc->lineCCs   = VG_(malloc)(n_matches * sizeof(LineCC));

   // Go through locs again, this time initialising the array.
   n_matches = 0;
   for (i = 0; i < VG_(seginfo_num_locs)(seg); i++) {
      tl_assert( VG_(seginfo_locN_dirname) (seg, i, &tmp_dirname) );
      tl_assert( VG_(seginfo_locN_filename)(seg, i, &tmp_filename) );
      tl_assert( VG_(seginfo_locN_line)    (seg, i, &tmp_line) );
      if (VG_STREQ(dirname, tmp_dirname) && VG_STREQ(filename, tmp_filename)) {
         cc->lineCCs[n_matches].line_num = tmp_line;
         cc->lineCCs[n_matches].n_execs  = 0;
         n_matches++;
      }
   }
   // Make sure we get the same number of matches the second time around.
   tl_assert(n_matches == cc->n_lineCCs); 

   // Loctabs are sorted by address.  We want our LineCC entries sorted by
   // line number.  Usually address ordering is pretty close to line
   // ordering, but it's not exactly the same.  Also, sometimes a line can
   // get mentioned more than once in the loctab.  So now we sort and remove
   // any dups in the line numbers, and update n_lineCCs accordingly.  As a
   // result, we will have over-allocated for lineCCs[], but the amount
   // should usually be very small.
   sort_and_remove_dups_from_FileCC(cc);

   if (VG_(clo_verbosity) > 1) {
      VG_(message)(Vg_DebugMsg, "vcov: %d debuginfo lines, %d matches, "
                                "%d unique matches:",
         VG_(seginfo_num_locs)(seg), n_matches, cc->n_lineCCs);
      // Here we fake up a VG_(message)-style line annotation;  we have to
      // use VG_(printf)() because we want to print multiple things on one
      // line.
      VG_(printf)("--%d-- vcov:   ", VG_(getpid)());
      for (i = 0; i < cc->n_lineCCs; i++)
         VG_(printf)("%d ", cc->lineCCs[i].line_num);
      VG_(printf)("\n");
   }

   return cc;
}

// Returns a pointer to FileCC, creates a new one if necessary (unless
// 'must_be_present' is true, in which case it aborts if the FileCC isn't
// present).  New nodes are prepended to their chain.  
static FileCC* get_FileCC(Addr instrAddr, Char* dirname, Char* filename,
                          Bool must_be_present)
{
   FileCC *curr_fileCC;
   UInt    file_hash;

   file_hash = hash(dirname, filename, N_FILE_ENTRIES);
   curr_fileCC = CC_table[file_hash];
   // Look for the filename in the appropriate chain.
   while (NULL != curr_fileCC &&
          !VG_STREQ( dirname, curr_fileCC-> dirname) &&
          !VG_STREQ(filename, curr_fileCC->filename))
   {
      curr_fileCC = curr_fileCC->next;
   }
   if (NULL == curr_fileCC) {
      if (must_be_present) {
         // XXX: don't panic, quit in a better way
         tl_assert2(0, "file not present: %s, %s", dirname, filename);
      }
      // It wasn't in the chain.  Create a new FileCC.
      CC_table[file_hash] = curr_fileCC = 
         new_FileCC(instrAddr, dirname, filename, CC_table[file_hash]);
      n_src_files++;
   }
   return curr_fileCC;
}

/*--------------------------------------------------------------------*/
/*--- Command line processing                                      ---*/
/*--------------------------------------------------------------------*/

static Bool clo_fresh = False;

static Bool vc_process_cmd_line_option(Char* arg)
{
   VG_BOOL_CLO(arg, "--fresh", clo_fresh)
   else return False;

   return True;
}

static void vc_print_usage(void)
{
   // XXX: allow people to change the name of the outfile.  The %p option
   // isn't so useful here, but might as well allow it.
   VG_(printf)(
"    --fresh=no|yes            clear all previous coverage info [no]\n"
   );
}

static void vc_print_debug_usage(void)
{
   VG_(printf)(
"    (none)\n"
   );
}

/*------------------------------------------------------------*/
/*--- Instrumentation                                      ---*/
/*------------------------------------------------------------*/

static VG_REGPARM(1)
void log_instr(LineCC* lineCC)
{
   (lineCC->n_execs)++;
}

// Instrumentation for the end of each original instruction.
static
void doOneInstr(IRSB* sbOut, Addr instrAddr)
{
   #define FILE_LEN  1024 

   IRDirty* di;
   IRExpr*  arg1;
   LineCC*  lineCC;
   Char     filename[FILE_LEN];
   Char     dirname[VKI_PATH_MAX + 1];
   Bool     dirname_available;
   Int      line;
   FileCC*  fileCC;
   Int      mid, mid_line, lo, hi;

   // Nb: This sets dirname to "" if it doesn't find a dirname.
   Bool found_file_line = 
      VG_(get_filename_linenum)(instrAddr, filename, FILE_LEN,
                                dirname, VKI_PATH_MAX, &dirname_available,
                                &line);

   // Only bother instrumenting the instruction if it has debug info!
   if (found_file_line) {
      // Get CC table for the file (creating it if necessary).
      fileCC = get_FileCC(instrAddr, dirname, filename,
                          /*must_be_present*/False);

      // Get the LineCC for the instruction.  Binary search.
      lo = 0;
      hi = fileCC->n_lineCCs - 1;

      while (True) {
         /* current unsearched space is from lo to hi, inclusive. */
         if (lo > hi) tl_assert2(0, "didn't find %d in lineCCs", line);
         mid      = (lo + hi) / 2;
         mid_line = fileCC->lineCCs[mid].line_num;
         if (line < mid_line) { hi = mid-1; continue; } 
         if (line > mid_line) { lo = mid+1; continue; }
         tl_assert(line == mid_line);
         break;
      }
      lineCC = &(fileCC->lineCCs[mid]);

      // Insert call to log function
      arg1 = mkIRExpr_HWord( (HWord)lineCC );
      di = unsafeIRDirty_0_N( 1, "log_instr", &log_instr, mkIRExprVec_1(arg1));
      addStmtToIRSB( sbOut, IRStmt_Dirty(di) );

      n_yes_debugs++;

   } else {
      n_no_debugs++;
   }
}

static
IRSB* vc_instrument ( VgCallbackClosure* closure,
                      IRSB* sbIn, 
                      VexGuestLayout* layout, 
                      VexGuestExtents* vge,
                      IRType gWordTy, IRType hWordTy )
{
   Int      i;
   IRSB*    sbOut;
   IRStmt*  st;

   if (gWordTy != hWordTy) {
      /* We don't currently support this case. */
      VG_(tool_panic)("host/guest word size mismatch");
   }

   // Set up new SB.
   sbOut = deepCopyIRSBExceptStmts(sbIn);

   for (i = 0; i < sbIn->stmts_used; i++) {
      st = sbIn->stmts[i];

      if (Ist_IMark == st->tag) {
         // Ist.IMark.addr is an Addr64.  We convert it to an Addr, then
         // check the conversion didn't change the value (it should never if
         // all is right with the world).
         Addr instrAddr = (Addr)st->Ist.IMark.addr;
         tl_assert( ((Addr64)instrAddr) == st->Ist.IMark.addr );
         doOneInstr(sbOut, instrAddr);
      }
      addStmtToIRSB( sbOut, st );
   }

   return sbOut;
}

/*------------------------------------------------------------*/
/*--- vc_fini() and related function                       ---*/
/*------------------------------------------------------------*/

// Parse buffer.  Each filename line has the exact form:
//
//    fl=<name>
//
// Each exec_counts line has the exact form
//
//    integer space integer newline
//
// Simple, huh?  We move through lines in the file and lines in
// fileCC->lineCCs[] in tandem.
//
static Bool parse_buffer(Char* outfile, struct vki_stat* outfile_statbuf, 
                         Char* buf)
{
   Int   buf_i = 0, line_i = 0, curr_line = 1;
   Char* error_msg = NULL;
   FileCC* fileCC = NULL;

   #define BOO(s) { error_msg = s; goto parse_end; }

   while ('\0' != buf[buf_i]) {

      if ('f' == buf[buf_i]) {
         Int fl_start_i, buf_j;
         Char*  dirname;
         Char* filename;

         // Check the previous fileCC (if there is one) had the right number
         // of lines.
         if (fileCC && line_i != fileCC->n_lineCCs) {
            BOO("consistency error: not enough lines in existing file");
         }

         // fl=<name>
         if (buf[buf_i+0] != 'f' ||
             buf[buf_i+1] != 'l' ||
             buf[buf_i+2] != '=')
         {
            BOO("parse error: bad 'fl=' line");
         } 
         buf_i += 3;
         fl_start_i = buf_i;
         while (buf[buf_i] != '\n') { buf_i++; }
         // Replace '\n' with '\0'.  Ok because 'buf' is only temporary.
         buf[buf_i] = '\0';   

   // Warn if srcfile is present and newer than the existing outfile.
   // XXX: should I warn if the srcfile isn't present?
   {
      struct vki_stat srcfile_statbuf;
      Char* srcfile = &buf[fl_start_i];
      if ( ! (VG_(stat)(srcfile, &srcfile_statbuf)).isError ) {
         if (srcfile_statbuf.st_mtime > outfile_statbuf->st_mtime) {
            VG_(message)(Vg_UserMsg,
               "Warning: Source file '%s' is more recent than ", srcfile);
            VG_(message)(Vg_UserMsg, 
               "         old data file '%s'.", outfile);
            VG_(message)(Vg_UserMsg,
               "         Coverage information may be incorrect.",
               srcfile);
            VG_(message)(Vg_UserMsg,
               "         Rerun with --fresh to purge old data and start again");
         }
      }
   }



         // Ok, we've isolated the function name.  Now split it into a
         // filename and a dirname.
         buf_j = buf_i-1;
         while (True) {
            if (buf_j == fl_start_i) {
               dirname  = "";
               filename = &buf[fl_start_i];
               break;
            } else if ('/' == buf[buf_j]) {
               buf[buf_j] = '\0';      // Replace '/' with '\0'.
               dirname  = &buf[fl_start_i];
               filename = &buf[buf_j+1];
               break;
            }
            buf_j--;
         }

         // Find the corresponding FileCC.
         // XXX: the unused instrAddr is ugly.
         fileCC = get_FileCC(/*instrAddr--unused*/0, dirname, filename,
                             /*must_be_present*/True);

         // Move past the newline, and reset line_i.
         buf_i++;
         line_i = 0;

      } else if (VG_(isdigit)(buf[buf_i])) {
         Long line_num, n_execs;

         // Line number.
         line_num = VG_(atoll)(buf+buf_i);
         while (VG_(isdigit)(buf[buf_i])) { buf_i++; }

         // Space.
         if (' ' != buf[buf_i++]) BOO("parse error: expected ' '");

         // n_execs number.
         if (!VG_(isdigit)(buf[buf_i]))
            BOO("parse error: expected exec count");
         // XXX: use strtol instead?  better checking...
         n_execs = VG_(atoll)(buf+buf_i);
         while (VG_(isdigit)(buf[buf_i])) { buf_i++; }

         // Newline.
         if ('\n' != buf[buf_i++]) BOO("parse error: expected newline");

         // Update fileCC with the data from the line.
         // XXX: have regtests for all these cases...
         if (!fileCC) {
            BOO("parse error: first line is not a 'fl=' line");
         }
         if (line_i >= fileCC->n_lineCCs) {
            BOO("consistency error: too many lines in existing file");
         }
         if (fileCC->lineCCs[line_i].line_num != line_num) {
            BOO("consistency error: line mismatch with existing file");
         }
         fileCC->lineCCs[line_i].n_execs += n_execs;
         line_i++;

      } else {
         VG_(printf)("bad char: %c\n",buf[buf_i]);
         BOO("parse error: line doesn't start with 'fl=' or line number");
      }
      curr_line++;

      #undef BOO
   }

  parse_end:
   
   if (error_msg) {
      VG_(message)(Vg_UserMsg, "%s:%d: %s;\n", outfile, curr_line, error_msg);
      VG_(message)(Vg_UserMsg, "    coverage data not written to file;\n");
      VG_(message)(Vg_UserMsg, "    rerun VCov with --fresh to purge old data and start again");
   }

   return (NULL == error_msg);
}

// If an output file for this source file already exists, read it in and
// update the fileCC stats with its data.  Returns 'False' if something went
// wrong and we should not write out the new data.
static Bool maybe_read_existing_outfile(Char* outfile)
{
   Int   fd;
   Char* buf;
   OffT  size;
   struct vki_stat outfile_statbuf;
   SysRes res;
   Bool   ok;
   
   // If no old file exists, or we are overwriting it, our work here is done.
   if ( clo_fresh || (VG_(stat)(outfile, &outfile_statbuf)).isError ) {
      if (VG_(clo_verbosity) > 1)
         VG_(message)(Vg_DebugMsg, "vcov: create new outfile:  '%s'", outfile);
      return True;
   }

   // Right, we have to augment the old file.
   if (VG_(clo_verbosity) > 1)
      VG_(message)(Vg_DebugMsg, "vcov: augment old outfile: '%s'", outfile);

   // Open existing data file.
   res = VG_(open)(outfile, VKI_O_RDONLY, 0);
   if (res.isError) {
      VG_(message)(Vg_UserMsg, "warning: could not open existing '%s'",
                   outfile);
      return False;
   }
   fd = (Int)res.res;

   // Allocate a buffer big enough to hold the entire file.  Files should be
   // compact enough that even huge ones are only a few megabytes...
   size = outfile_statbuf.st_size;
   buf  = VG_(malloc)(size+1); 

   // Read entire file into buffer.  
   if (VG_(read)(fd, buf, size) != size) {
      VG_(message)(Vg_UserMsg, "error: could not read '%s'\n", outfile);
      VG_(free)(buf);
      VG_(close)(fd);
      return False;
   }

   buf[size] = '\0';      // Ensure null-termination.

   // Parse the buffer.
   ok = parse_buffer(outfile, &outfile_statbuf, buf);

   // Deallocate buffer, close the file.
   VG_(free)(buf);
   VG_(close)(fd);

   return ok;
}

static void write_outfile(Char* outfile)
{
   Char   buf[VKI_PATH_MAX+1];
   Int    i, j, fd;
   SysRes res;

   res = VG_(open)(outfile, VKI_O_CREAT|VKI_O_TRUNC|VKI_O_RDWR,
                            VKI_S_IRUSR|VKI_S_IWUSR);
   if (!res.isError) {
      fd = (Int)res.res;

      // For each FileCC, output the new/updated counts.
      for (i = 0; i < N_FILE_ENTRIES; i++) {
         FileCC* fileCC = CC_table[i];
         while (fileCC != NULL) {
            // Write the filename line.
            if (! VG_STREQ(fileCC->dirname, "")) {
               VG_(sprintf)(buf, "fl=%s/%s\n", fileCC->dirname,
                                               fileCC->filename);
            } else {
               VG_(sprintf)(buf, "fl=%s\n", fileCC->filename);
            }
            VG_(write)(fd, (void*)buf, VG_(strlen)(buf));

            // Write the execution count lines.
            for (j = 0; j < fileCC->n_lineCCs; j++) {
               LineCC* lineCC = &(fileCC->lineCCs[j]);
               VG_(sprintf)(buf, "%u %llu\n", lineCC->line_num,
                                              lineCC->n_execs);
               VG_(write)(fd, (void*)buf, VG_(strlen)(buf));
            }

            fileCC = fileCC->next;
         }
      }
      VG_(close)(fd);

   } else {
      // If the file can't be opened for whatever reason, just skip.
      VG_(message)(Vg_UserMsg,
         "error: cannot open output file `%s'", outfile );
   }
}

static void vc_fini(Int exitcode)
{
   Char* outfile = "vcov.out";
   Bool  ok;

   // ... read the old vcov.out first ...

//   XXX: need to lock the file first.
   
   ok = maybe_read_existing_outfile(outfile);
   if (ok)
      write_outfile(outfile);

//   XXX: now unlock the file

   // Stats
   if (VG_(clo_verbosity) > 1) {
       Int n_tot_debugs = n_no_debugs + n_yes_debugs;

       tl_assert(0 != n_tot_debugs);
       if (0 == n_lineCC_slots_total) n_lineCC_slots_total = 1;

       VG_(message)(Vg_DebugMsg, "vcov: number of source files: %d",
                                 n_src_files);
       VG_(message)(Vg_DebugMsg, "vcov: lines with debug info: %d%% (%d/%d)", 
                    n_yes_debugs * 100 / n_tot_debugs,
                    n_yes_debugs, n_tot_debugs);
       VG_(message)(Vg_DebugMsg, "vcov: lineCC slot usage: %d%% (%d/%d)", 
                    n_lineCC_slots_used * 100 / n_lineCC_slots_total,
                    n_lineCC_slots_used, n_lineCC_slots_total);
   }
}

/*--------------------------------------------------------------------*/
/*--- Setup                                                        ---*/
/*--------------------------------------------------------------------*/

static void vc_post_clo_init(void)
{
}

static void vc_pre_clo_init(void)
{
   VG_(details_name)            ("VCov");
   VG_(details_version)         (NULL);
   VG_(details_description)     ("a coverage testing tool");
   VG_(details_copyright_author)(
      "Copyright (C) 2002-2008, and GNU GPL'd, by Nicholas Nethercote.");
   VG_(details_bug_reports_to)  (VG_BUGS_TO);

   VG_(basic_tool_funcs)          (vc_post_clo_init,
                                   vc_instrument,
                                   vc_fini);

   VG_(needs_command_line_options)(vc_process_cmd_line_option,
                                   vc_print_usage,
                                   vc_print_debug_usage);
}

VG_DETERMINE_INTERFACE_VERSION(vc_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
