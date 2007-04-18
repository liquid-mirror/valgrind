//--------------------------------------------------------------------*/
//--- Massif: a heap profiling tool.                     ms_main.c ---*/
//--------------------------------------------------------------------*/

/*
   This file is part of Massif, a Valgrind tool for profiling memory
   usage of programs.

   Copyright (C) 2003-2007 Nicholas Nethercote
      njn@valgrind.org

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

//---------------------------------------------------------------------------
// XXX:
//---------------------------------------------------------------------------
// Next:
// - Check MALLOCLIKE_BLOCK works, write regtest
//
// Work out how to take the peak.
// - exact peak, or within a certain percentage?
// - include the stack?  makes it harder
//
// Option #1
// - just take the peak snapshot.
// - pros:
//   - easy, fast
// - cons:
//   - not the true peak
//
// #2: true peak
// - check every malloc, every new_mem_stack
// - slow
// - most accurate
//
// #2a:
// - same, but only do detailed snapshot if x% larger than previous peak
// 
// #3: in-between
// - check every malloc, but not every new_mem_stack
//
// Separate content from presentation by dumping all results to a file and
// then post-processing with a separate program, a la Cachegrind?
// - work out the file format (Josef wants Callgrind format, Donna wants
//   XML, Nick wants something easy to read in Perl)
// - allow truncation of long fnnames if the exact line number is
//   identified?  [hmm, could make getting the name of alloc-fns more
//   difficult]
//
// Examine and fix bugs on bugzilla:
// IGNORE:
// 112163  nor     MASSIF crashed with signal 7 (SIGBUS) after running 2 days
//   - weird, crashes in VEX, ignore
// 82871   nor     Massif output function names too short
//   - on .ps graph, now irrelevant, ignore
// 129576  nor     Massif loses track of memory, incorrect graphs
//   - dunno, hard to reproduce, ignore
// 132132  nor     massif --format=html output does not do html entity escaping
//   - only for HTML output, irrelevant, ignore
//
// FIXED/NOW IRRELEVANT:
// 142197  nor     massif tool ignores --massif:alloc-fn parameters in .valg...
//   - fixed in trunk
// 142491  nor     Maximise use of alloc_fns array
//   - addressed, using the patch (with minor changes) from the bug report
// 89061   cra     Massif: ms_main.c:485 (get_XCon): Assertion `xpt->max_chi...
//   - relevant code now gone
//
// TODO:
// 141631  nor     Massif: percentages don't add up correctly
//   - better sanity-checking should help this greatly
// 142706  nor     massif numbers don't seem to add up
//   - better sanity-checking should help this greatly
// 143062  cra     massif crashes on app exit with signal 8 SIGFPE
//   - occurs with no allocations -- ensure that case works
//
// Michael Meeks:
// - wants an interactive way to request a dump (callgrind_control-style)
//   - "profile now"
//   - "show me the extra allocations from last-snapshot"
//   - "start/stop logging" (eg. quickly skip boring bits)
//
// Artur Wisz:
// - added a feature to Massif to ignore any heap blocks larger than a
//   certain size!  Because:
//     "linux's malloc allows to set a MMAP_THRESHOLD value, so we
//      set it to 4096 - all blocks above that will be handled directly by
//      the kernel, and are guaranteed to be returned to the system when
//      freed. So we needed to profile only blocks below this limit."
//
// Other:
//   - am I recording asked-for sizes or actual rounded-up sizes?
//   - there's a gap between the ms timer initialisation during Valgrind
//     start-up and our first use of it.  Could normalise versus our first
//     use...
//   - could conceivably remove XPts that have their szB reduced to zero.
//
// Docs:
// - need to explain that --alloc-fn changed slightly -- now if an entry
//   matches an alloc-fn, that entry *and all above it* are removed.  So you
//   can cut out allc-fn chains at the bottom, rather than having to name
//   all of them, which is better.
// - Mention that the C++ overloadable new/new[] operators aren't include in
//   alloc-fns by default.  
// - Mention that complex functions names are best protected with single
//   quotes, eg:
//       --alloc-fn='operator new(unsigned, std::nothrow_t const&)'
//   [XXX: that doesn't work if the option is in a .valgrindrc file or in
//    $VALGRIND_OPTS.  In m_commandline.c:add_args_from_string() need to
//    respect single quotes...]
// - Explain the --threshold=0 case -- entries with zero bytes must have
//   allocated some memory and then freed it all again.
//
// Tests:
// - tests/overloaded_new.cpp is there
// - one involving MALLOCLIKE
//
//---------------------------------------------------------------------------

#include "pub_tool_basics.h"
#include "pub_tool_vki.h"
#include "pub_tool_aspacemgr.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_hashtable.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_libcproc.h"
#include "pub_tool_machine.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_options.h"
#include "pub_tool_replacemalloc.h"
#include "pub_tool_stacktrace.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_xarray.h"
#include "pub_tool_clientstate.h"

#include "valgrind.h"           // For {MALLOC,FREE}LIKE_BLOCK

//------------------------------------------------------------*/
//--- Overview of operation                                ---*/
//------------------------------------------------------------*/

// The size of the stacks and heap is tracked.  The heap is tracked in a lot
// of detail, enough to tell how many bytes each line of code is responsible
// for, more or less.
//
// "Snapshots" are recordings of the memory usage.  There are two basic
// kinds:
// - Normal:  these record the current time, total memory size, total heap
//   size, heap admin size and stack size.
// - Detailed: these record those things in a normal snapshot, plus a very
//   detailed XTree (see below) indicating how the heap is structured.
//
// Snapshots are taken every so often.  There are two storage classes of
// snapshots:
// - Temporary:  Massif does a temporary snapshot every so often.  The idea
//   is to always have a certain number of temporary snapshots around.  So
//   we take them frequently to begin with, but decreasingly often as the
//   program continues to run.  Also, we remove some old ones after a while.
//   Overall it's a kind of exponential decay thing.  Most of these are
//   normal snapshots, a small fraction are detailed snapshots.
// - Permanent:  Massif takes a permanent (detailed) snapshot in some
//   circumstances.  They are:
//   - Peak snapshot:  When the memory usage peak is reached, it takes a
//     snapshot.  It keeps this, unless the peak is subsequently exceeded,
//     in which case it will overwrite the peak snapshot.
//   - User-requested snapshots:  These are done in response to client
//     requests.  They are always kept.
//
// The summary output produced by Massif could include a graph like this.
//  
//---------------------------------------------------------------------------
// 100M|B                .      :A
//     |               .:::   :::#      
//     |              :::::. c:::#:     
//     |             b:::::: |:::#::    
//     |            :|:::::::|:::#::    
//  75M|            :|:::::::|:::#:::   
//     |           ::|:::::::|:::#:::   
//     |           ::|:::::::|:::#:::d  
//     |           ::|:::::::|:::#:::|: 
//     |          .::|:::::::|:::#:::|::
//  50M|          :::|:::::::|:::#:::|:::                      
//     |         ::::|:::::::|:::#:::|:::::                        :::.
//     |        :::::|:::::::|:::#:::|::::::                    g::::::::
//     |       a:::::|:::::::|:::#:::|:::::::e:               ::|::::::::::h
//     |       |:::::|:::::::|:::#:::|:::::::|::.        :: .:::|::::::::::|::
//  25M|       |:::::|:::::::|:::#:::|:::::::|::::      f:::::::|::::::::::|::
//     |      :|:::::|:::::::|:::#:::|:::::::|::::.  .::|:::::::|::::::::::|::
//     |    .::|:::::|:::::::|:::#:::|:::::::|::::::::::|:::::::|::::::::::|::
//     |  .::::|:::::|:::::::|:::#:::|:::::::|::::::::::|:::::::|::::::::::|::
//     |:::::::|:::::|:::::::|:::#:::|:::::::|::::::::::|:::::::|::::::::::|::
//   0M+----------------------------------------------------------------------t
//     012                                                               
//
//      Temporary snapshots:
//       a: periodic snapshot, total size: 33,000,000 bytes
//       b: periodic snapshot, total size: 82,000,000 bytes
//       c: periodic snapshot, total size: 90,000,000 bytes
//       d: periodic snapshot, total size: 64,000,000 bytes
//       e: periodic snapshot, total size: 34,000,000 bytes
//       f: periodic snapshot, total size: 24,000,000 bytes
//       g: periodic snapshot, total size: 39,000,000 bytes
//       h: periodic snapshot, total size: 33,000,000 bytes
//
//      Permanent snapshots:
//       A: peak snapshot, total size: 100,000,000 bytes
//---------------------------------------------------------------------------
//
// Explanation of the y-axis:
// - Top of the x-axis box represents 0.
//
//    4M^|   .:     This row has base=2M, half-threshold=3M, full-threshold=4M
//    2M^| .:::     This row has base=0M, half-threshold=1M, full-threshold=2M
//    0M +-----        
//        abcde        
//                   
// - A '.' is only shown in a row if we've reached its half-threshold
// - A ':' is only shown in a row if we've reached its full-threshold
// - So: a is in range 0 -- 0.99 
//       b is in range 1 -- 1.99 
//       c is in range 2 -- 2.99
//       d is in range 3 -- 3.99
//       e is in range 4 -- 4.99
//
// Explanation of x-axis:
// - Assume each column represents one second
// - First usable column has range 0..0.99s
// - Second usable column has range 1..1.99s
// - etc.


///-----------------------------------------------------------//
//--- Main types                                           ---//
//------------------------------------------------------------//

// An XPt represents an "execution point", ie. a code address.  Each XPt is
// part of a tree of XPts (an "execution tree", or "XTree").  The details of
// the heap are represented by a single XTree.
//
// The root of the tree is 'alloc_xpt', which represents all allocation
// functions, eg:
// - malloc/calloc/realloc/memalign/new/new[];
// - user-specified allocation functions (using --alloc-fn);
// - custom allocation (MALLOCLIKE) points
// It's a bit of a fake XPt (ie. its 'ip' is zero), and is only used because
// it makes the code simpler.
//
// Any child of 'alloc_xpt' is called a "top-XPt".  The XPts are the bottom
// of an XTree (leaf nodes) are "bottom-XPTs".  The number of XCons in an
// XTree is equal to the number of bottom-XPTs in that XTree.
//
// Each path from a top-XPt to a bottom-XPt through an XTree gives an
// execution context ("XCon"), ie. a stack trace.  (And sub-paths represent
// stack sub-traces.)
//
//      alloc_xpt       XTrees are bi-directional.
//        | ^
//        v |
//     > parent <       Example: if child1() calls parent() and child2()
//    /    |     \      also calls parent(), and parent() calls malloc(),
//   |    / \     |     the XTree will look like this.
//   |   v   v    |
//  child1   child2
//
// Sanity checking:  we check snapshot XTrees when they are taken, deleted
// and printed.  We periodically check the main heap XTree periodically via
// ms_expensive_sanity_check.

typedef struct _XPt XPt;

struct _XPt {
   Addr  ip;              // code address

   // Bottom-XPts: space for the precise context.
   // Other XPts:  space of all the descendent bottom-XPts.
   // Nb: this value goes up and down as the program executes.
   UInt  curr_szB;

   XPt*  parent;           // pointer to parent XPt

   // Children.
   // n_children and max_children are 32-bit integers, not 16-bit, because
   // a very big program might have more than 65536 allocation points (ie.
   // top-XPts) -- Konqueror starting up has 1800.
   UInt  n_children;       // number of children
   UInt  max_children;     // capacity of children array
   XPt** children;         // pointers to children XPts
};

// Snapshots are done so we keep a good number of them.  If MAX_N_SNAPSHOTS
// equals 200, then it works something like this:
//   - do a snapshot every 1ms for first 200ms --> 200, all          (200 ms)
//   - halve (drop half of them)               --> 100, every 2nd
//   - do a snapshot every 2ms for next 200ms  --> 200, every 2nd    (400 ms)
//   - halve                                   --> 100, every 4th
//   - do a snapshot every 4ms for next 400ms  --> 200, every 4th    (800 ms)
//   - etc.
//
// This isn't exactly right, because we actually drop (N/2)-1 when halving,
// but it shows the basic idea.

// XXX: if the program is really short, we may get no detailed snapshots...
// that's bad, do something about it.
#define MAX_N_SNAPSHOTS        100  // Keep it even, for simplicity
#define DETAILED_SNAPSHOT_FREQ  10  // Every Nth snapshot will be detailed

typedef
   struct {
      Int   time_ms;       // Int: must allow -1.
      SizeT total_szB;     // Size of all allocations at that snapshot time.
      SizeT heap_admin_szB;
      SizeT heap_szB;
      SizeT stacks_szB;
      XPt*  alloc_xpt;     // Heap XTree root, if a detailed snapshot,
   }                       // otherwise NULL
   Snapshot;

// Metadata for heap blocks.  Each one contains a pointer to a bottom-XPt,
// which is a foothold into the XCon at which it was allocated.  From
// HP_Chunks, XPt 'space' fields are incremented (at allocation) and
// decremented (at deallocation).
//
// Nb: first two fields must match core's VgHashNode. [XXX: is that still
// true?]
typedef
   struct _HP_Chunk {
      struct _HP_Chunk* next;
      Addr              data;    // Ptr to actual block
      SizeT             szB;     // Size requested
      XPt*              where;   // Where allocated; bottom-XPt
   }
   HP_Chunk;


//------------------------------------------------------------//
//--- Statistics                                           ---//
//------------------------------------------------------------//

// Konqueror startup, to give an idea of the numbers involved with a biggish
// program, with default depth:
//
//  depth=3                   depth=40
//  - 310,000 allocations
//  - 300,000 frees
//  -  15,000 XPts            800,000 XPts
//  -   1,800 top-XPts

static UInt n_xpts               = 0;
static UInt n_dupd_xpts          = 0;
static UInt n_dupd_xpts_freed    = 0;
static UInt n_allocs             = 0;
static UInt n_zero_allocs        = 0;
static UInt n_frees              = 0;
static UInt n_children_reallocs  = 0;

static UInt n_getXCon_redo       = 0;

static UInt n_halvings           = 0;
static UInt n_real_snapshots     = 0;
static UInt n_fake_snapshots     = 0;


//------------------------------------------------------------//
//--- Globals                                              ---//
//------------------------------------------------------------//

#define FILENAME_LEN    256

#define P               VG_(printf)

#define SPRINTF(zz_buf, fmt, args...) \
   do { Int len = VG_(sprintf)(zz_buf, fmt, ## args); \
        VG_(write)(fd, (void*)zz_buf, len); \
   } while (0)

#define BUF_LEN         1024     // general purpose
static Char buf [BUF_LEN];
static Char buf2[BUF_LEN];

// Make these signed so things are more obvious if they go negative.
static SSizeT sigstacks_szB = 0;     // Current signal stacks space sum
static SSizeT heap_szB      = 0;     // Live heap size
static SSizeT peak_heap_szB = 0;    // XXX: currently unused
static SSizeT peak_snapshot_total_szB = 0;

static VgHashTable malloc_list  = NULL;   // HP_Chunks

static UInt n_heap_blocks = 0;

// Current directory at startup.
static Char base_dir[VKI_PATH_MAX];

#define MAX_ALLOC_FNS      128     // includes the builtin ones

// First few filled in, rest should be zeroed.  Zero-terminated vector.
// Nb: I used to have the following four C++ global overloadable allocators
// in alloc_fns:
//   operator new(unsigned)
//   operator new[](unsigned)
//   operator new(unsigned, std::nothrow_t const&)
//   operator new[](unsigned, std::nothrow_t const&)
// But someone might be interested in seeing them.  If they're not, they can
// specify them with --alloc-fn.
static UInt  n_alloc_fns = 6;
static Char* alloc_fns[MAX_ALLOC_FNS] = { 
   "malloc",
   "__builtin_new",
   "__builtin_vec_new",
   "calloc",
   "realloc",
   "memalign",
};


//------------------------------------------------------------//
//--- Command line args                                    ---//
//------------------------------------------------------------//

#define MAX_DEPTH       50

static Bool clo_heap        = True;
static UInt clo_heap_admin  = 8;
static Bool clo_stacks      = True;
static Bool clo_depth       = 8;
static UInt clo_threshold   = 100;     // 100 == 1%

static Bool ms_process_cmd_line_option(Char* arg)
{
        VG_BOOL_CLO(arg, "--heap",       clo_heap)
   else VG_BOOL_CLO(arg, "--stacks",     clo_stacks)

   else VG_NUM_CLO (arg, "--heap-admin", clo_heap_admin)
   else VG_BNUM_CLO(arg, "--depth",      clo_depth, 1, MAX_DEPTH)

   else VG_NUM_CLO(arg, "--threshold",   clo_threshold)

   else if (VG_CLO_STREQN(11, arg, "--alloc-fn=")) {
      int i;

      // Check first if the function is already present.
      for (i = 0; i < n_alloc_fns; i++) {
         if ( VG_STREQ(alloc_fns[i], & arg[11]) )
            return True;
      }
      // Abort if we reached the limit.
      if (n_alloc_fns >= MAX_ALLOC_FNS) {
         VG_(printf)("Too many alloc functions specified, sorry");
         VG_(err_bad_option)(arg);
      }
      // Ok, add the function.
      alloc_fns[n_alloc_fns] = & arg[11];
      n_alloc_fns++;
   }

   else
      return VG_(replacement_malloc_process_cmd_line_option)(arg);

   return True;
}

static void ms_print_usage(void)
{
   VG_(printf)( 
"    --heap=no|yes             profile heap blocks [yes]\n"
"    --heap-admin=<number>     average admin bytes per heap block [8]\n"
"    --stacks=no|yes           profile stack(s) [yes]\n"
"    --depth=<number>          depth of contexts [8]\n"
"    --alloc-fn=<name>         specify <fn> as an alloc function [empty]\n"
"    --threshold=<n>           significance threshold, in 100ths of a percent\n"
"                              (eg. <n>=100 shows nodes covering >= 1%% of\n"
"                               total size, <n>=0 shows all nodes) [100]\n"
   );
   VG_(replacement_malloc_print_usage)();
}

static void ms_print_debug_usage(void)
{
   VG_(replacement_malloc_print_debug_usage)();
}


//------------------------------------------------------------//
//--- XPts                                                 ---//
//------------------------------------------------------------//

// Fake XPt representing all allocation functions like malloc().  Acts as
// parent node to all top-XPts.
static XPt* alloc_xpt;

// Cheap allocation for blocks that never need to be freed.  Saves about 10%
// for Konqueror startup with --depth=40.
static void* perm_malloc(SizeT n_bytes)
{
   static Addr hp     = 0;    // current heap pointer
   static Addr hp_lim = 0;    // maximum usable byte in current block

   #define SUPERBLOCK_SIZE  (1 << 20)         // 1 MB

   if (hp + n_bytes > hp_lim) {
      hp = (Addr)VG_(am_shadow_alloc)(SUPERBLOCK_SIZE);
      if (hp == 0)
         VG_(out_of_memory_NORETURN)( "massif:perm_malloc", 
                                      SUPERBLOCK_SIZE);
      hp_lim = hp + SUPERBLOCK_SIZE - 1;
   }

   hp += n_bytes;

   return (void*)(hp - n_bytes);
}

__attribute__((unused))
static void pp_XPt(XPt* xpt)
{
   Int i;
   P("XPt (%p):\n", xpt);
   P("- ip:         : %p\n", (void*)xpt->ip);
   P("- curr_szB    : %ld\n", xpt->curr_szB);
   P("- parent      : %p\n", xpt->parent);
   P("- n_children  : %d\n", xpt->n_children);
   P("- max_children: %d\n", xpt->max_children);
   for (i = 0; i < xpt->n_children; i++) {
      P("- children[%2d]: %p\n", i, xpt->children[i]);
   }
}

static XPt* new_XPt(Addr ip, XPt* parent)
{
   // XPts are never freed, so we can use perm_malloc to allocate them.
   // Note that we cannot use perm_malloc for the 'children' array, because
   // that needs to be resizable.
   XPt* xpt          = perm_malloc(sizeof(XPt));
   xpt->ip           = ip;
   xpt->curr_szB     = 0;
   xpt->parent       = parent;

   // We don't initially allocate any space for children.  We let that
   // happen on demand.  Many XPts (ie. all the bottom-XPts) don't have any
   // children anyway.
   xpt->n_children   = 0;
   xpt->max_children = 0;
   xpt->children     = NULL;

   // Update statistics
   n_xpts++;

   return xpt;
}

static void add_child_xpt(XPt* parent, XPt* child)
{
   // Expand 'children' if necessary.
   tl_assert(parent->n_children <= parent->max_children);
   if (parent->n_children == parent->max_children) {
      if (parent->max_children == 0) {
         parent->max_children = 4;
         parent->children = VG_(malloc)( parent->max_children * sizeof(XPt*) );
      } else {
         parent->max_children *= 2;    // Double size
         parent->children = VG_(realloc)( parent->children,
                                          parent->max_children * sizeof(XPt*) );
      }
      n_children_reallocs++;
   }

   // Insert new child XPt in parent's children list.
   parent->children[ parent->n_children++ ] = child;
}

// Reverse comparison for a reverse sort -- biggest to smallest.
static Int XPt_revcmp_curr_szB(void* n1, void* n2)
{
   XPt* xpt1 = *(XPt**)n1;
   XPt* xpt2 = *(XPt**)n2;
   return ( xpt1->curr_szB < xpt2->curr_szB ?  1 
          : xpt1->curr_szB > xpt2->curr_szB ? -1
          :                                    0);
}


//------------------------------------------------------------//
//--- XTrees                                               ---//
//------------------------------------------------------------//

// XXX: taking a full snapshot... could/should just snapshot the significant
// parts.  Nb: then the amounts wouldn't add up, unless I represented the
// "other insignificant places" in XPts.
static XPt* dup_XTree(XPt* xpt, XPt* parent)
{
   Int  i;
   XPt* dup_xpt = VG_(malloc)(sizeof(XPt));
   dup_xpt->ip           = xpt->ip;
   dup_xpt->curr_szB     = xpt->curr_szB;
   dup_xpt->parent       = parent;           // Nb: not xpt->children!
   dup_xpt->n_children   = xpt->n_children;
   dup_xpt->max_children = xpt->n_children;  // Nb: don't copy max_children!
   dup_xpt->children     = VG_(malloc)(dup_xpt->max_children * sizeof(XPt*));
   for (i = 0; i < xpt->n_children; i++) {
      dup_xpt->children[i] = dup_XTree(xpt->children[i], dup_xpt);
   }

   n_dupd_xpts++;

   return dup_xpt;
}

static void free_XTree(XPt* xpt)
{
   Int  i;
   // Free all children XPts, then the children array, then the XPt itself.
   tl_assert(xpt != NULL);
   for (i = 0; i < xpt->n_children; i++) {
      XPt* child = xpt->children[i];
      free_XTree(child);
      xpt->children[i] = NULL;
   }
   VG_(free)(xpt->children);  xpt->children = NULL;
   VG_(free)(xpt);            xpt           = NULL;

   n_dupd_xpts_freed++;
}

// XXX: improve this so that it prints the failing XPt always.
static void sanity_check_XTree(XPt* xpt, XPt* parent)
{
   Int i;
   SizeT children_sum_szB = 0;

   tl_assert(xpt != NULL);

   // Check back-pointer.
   tl_assert2(xpt->parent == parent,
      "xpt->parent = %p, parent = %p\n", xpt->parent, parent);

   // Check children counts look sane.
   tl_assert(xpt->n_children <= xpt->max_children);

   // Check the sum of any children szBs equals the XPt's szB.
   if (xpt->n_children > 0) {
      for (i = 0; i < xpt->n_children; i++) {
         children_sum_szB += xpt->children[i]->curr_szB;
      }
      tl_assert(children_sum_szB == xpt->curr_szB);
   }

   // Check each child.
   for (i = 0; i < xpt->n_children; i++) {
      sanity_check_XTree(xpt->children[i], xpt);
   }
}


//------------------------------------------------------------//
//--- XCons                                                ---//
//------------------------------------------------------------//

// This is the limit on the number of removed alloc-fns that can be in a
// single XCon.
#define MAX_OVERESTIMATE   50
#define MAX_IPS            (MAX_DEPTH + MAX_OVERESTIMATE)

static Bool is_alloc_fn(Char* fnname)
{
   Int i;
   for (i = 0; i < n_alloc_fns; i++) {
      if (VG_STREQ(fnname, alloc_fns[i]))
         return True;
   }
   return False;
}

// XXX: look at the "(below main)"/"__libc_start_main" mess (m_stacktrace.c
//      and m_demangle.c).  Don't hard-code "(below main)" in here.
// [Nb: Josef wants --show-below-main to work for his fn entry/exit tracing]
static Bool is_main_or_below_main(Char* fnname)
{
   Int i;

   for (i = 0; i < n_alloc_fns; i++) {
      if (VG_STREQ(fnname, "main"))         return True;
      if (VG_STREQ(fnname, "(below main)")) return True;
   }
   return False;
}

// Get the stack trace for an XCon, filtering out uninteresting entries:
// alloc-fns and entries above alloc-fns, and entries below
// main-or-below-main.
// Eg:       alloc-fn1 / alloc-fn2 / a / b / main / (below main) / c
// becomes:  a / b / main
static 
Int get_IPs( ThreadId tid, Bool is_custom_malloc, Addr ips[], Int max_ips)
{
   Int n_ips, i, n_alloc_fns_removed = 0;
   Int overestimate;
   Bool fewer_IPs_than_asked_for   = False;
   Bool removed_below_main         = False;
   Bool enough_IPs_after_filtering = False;

   // XXX: get this properly
   Bool should_hide_below_main     = /*!VG_(clo_show_below_main)*/True;

   // We ask for a few more IPs than clo_depth suggests we need.  Then we
   // remove every entry that is an alloc-fns or above an alloc-fn, and
   // remove anything below main-or-below-main functions.  Depending on the
   // circumstances, we may need to redo it all, asking for more IPs.
   // Details:
   // - If the original stack trace is smaller than asked-for,   redo=False
   // - Else if we see main-or-below-main in the stack trace,    redo=False
   // - Else if after filtering we have more than clo_depth IPs, redo=False
   // - Else redo=True
   // In other words, to redo, we'd have to get a stack trace as big as we
   // asked for, remove more than 'overestimate' alloc-fns, and not hit
   // main-or-below-main.

   // Main loop
   for (overestimate = 3; True; overestimate += 6) {
      // This should never happen -- would require MAX_OVERESTIMATE
      // alloc-fns to be removed from the stack trace.
      if (overestimate > MAX_OVERESTIMATE)
         VG_(tool_panic)("get_IPs: ips[] too small, inc. MAX_OVERESTIMATE?");

      // Ask for more than clo_depth suggests we need.
      n_ips = VG_(get_StackTrace)( tid, ips, clo_depth + overestimate );
      tl_assert(n_ips > 0);

      // If we got fewer IPs than we asked for, redo=False
      if (n_ips < clo_depth + overestimate)
         fewer_IPs_than_asked_for = True;

      // Filter uninteresting entries out of the stack trace.  n_ips is
      // updated accordingly.
      for (i = n_ips-1; i >= 0; i--) {
         if (VG_(get_fnname)(ips[i], buf, BUF_LEN)) {

            // If it's a main-or-below-main function, we (may) want to
            // ignore everything after it.
            // If we see one of these functions, redo=False.
            if (should_hide_below_main && is_main_or_below_main(buf)) {
               n_ips = i+1;            // Ignore everything below here.
               removed_below_main = True;
            }

            // If it's an alloc-fn, we want to delete it and everything
            // before it.
            if (is_alloc_fn(buf)) {
               Int j;
               if (i+1 >= n_ips) {
                  // This occurs if removing an alloc-fn and entries above
                  // it results in an empty stack trace.
                  VG_(message)(Vg_UserMsg,
                     "User error: nothing but alloc-fns in stack trace");
                  VG_(message)(Vg_UserMsg,
                     "Try removing --alloc-fn=%s option and try again.", buf);
                  VG_(message)(Vg_UserMsg,
                     "Exiting.");
                  VG_(exit)(1);
               }
               n_alloc_fns_removed = i+1;
               
               for (j = 0; j < n_ips; j++) {  // Shuffle the rest down.
                  ips[j] = ips[j + n_alloc_fns_removed]; 
               }
               n_ips -= n_alloc_fns_removed;
               break;
            }
         }
      }

      // Must be at least one alloc function, unless client used
      // MALLOCLIKE_BLOCK.
      if (!is_custom_malloc) tl_assert(n_alloc_fns_removed > 0);    

      // Did we get enough IPs after filtering?  If so, redo=False.
      if (n_ips >= clo_depth) {
         n_ips = clo_depth;      // Ignore any IPs below --depth.
         enough_IPs_after_filtering = True;
      }

      if (fewer_IPs_than_asked_for ||
          removed_below_main       ||
          enough_IPs_after_filtering)
      {
         return n_ips;

      } else {
         n_getXCon_redo++;
      }
   }
}

// Gets an XCon and puts it in the tree.  Returns the XCon's bottom-XPt.
static XPt* get_XCon( ThreadId tid, Bool is_custom_malloc )
{
   static Addr ips[MAX_IPS];     // Static to minimise stack size.
   Int i;
   XPt* xpt = alloc_xpt;

   // After this call, the IPs we want are in ips[0]..ips[n_ips-1].
   Int n_ips = get_IPs(tid, is_custom_malloc, ips, MAX_IPS);

   // Now do the search/insertion of the XCon. 'L' is the loop counter,
   // being the index into ips[].
   for (i = 0; i < n_ips; i++) {
      Addr ip = ips[i];
      Int ch;
      // Look for IP in xpt's children.
      // XXX: linear search, ugh -- about 10% of time for konqueror startup
      // XXX: tried caching last result, only hit about 4% for konqueror
      // Nb:  this search hits about 98% of the time for konqueror
      for (ch = 0; True; ch++) {
         if (ch == xpt->n_children) {
            // IP not found in the children.
            // Create and add new child XPt, then stop.
            XPt* new_child_xpt = new_XPt(ip, xpt);
            add_child_xpt(xpt, new_child_xpt);
            xpt = new_child_xpt;
            break;

         } else if (ip == xpt->children[ch]->ip) {
            // Found the IP in the children, stop.
            xpt = xpt->children[ch];
            break;
         }
      }
   }
   tl_assert(0 == xpt->n_children); // Must be bottom-XPt   XXX: really?
   return xpt;
}

// Update 'curr_szB' of every XPt in the XCon, by percolating upwards.
static void update_XCon(XPt* xpt, SSizeT space_delta)
{
   tl_assert(True == clo_heap);
   tl_assert(NULL != xpt);
   tl_assert(0    == xpt->n_children);    // must be bottom-XPt

   if (0 == space_delta)
      return;

   while (xpt != alloc_xpt) {
      if (space_delta < 0) tl_assert(xpt->curr_szB >= -space_delta);
      xpt->curr_szB += space_delta;
      xpt = xpt->parent;
   } 
   if (space_delta < 0) tl_assert(alloc_xpt->curr_szB >= -space_delta);
   alloc_xpt->curr_szB += space_delta;
}


//------------------------------------------------------------//
//--- Snapshots                                            ---//
//------------------------------------------------------------//

static Snapshot snapshots[MAX_N_SNAPSHOTS];
static UInt     next_snapshot = 0;   // Points to where next snapshot will go.

static Bool is_snapshot_in_use(Snapshot* snapshot)
{
   if (-1 == snapshot->time_ms) {
      // If .time_ms looks unused, check everything else is.
      tl_assert(snapshot->total_szB      == 0);
      tl_assert(snapshot->heap_admin_szB == 0);
      tl_assert(snapshot->heap_szB       == 0);
      tl_assert(snapshot->stacks_szB     == 0);
      tl_assert(snapshot->alloc_xpt      == NULL);
      return False;
   } else {
      return True;
   }
}

static Bool is_detailed_snapshot(Snapshot* snapshot)
{
   return (snapshot->alloc_xpt ? True : False);
}

static void sanity_check_snapshot(Snapshot* snapshot)
{
   tl_assert(snapshot->total_szB ==
      snapshot->heap_admin_szB + snapshot->heap_szB + snapshot->stacks_szB);
   if (snapshot->alloc_xpt) {
      sanity_check_XTree(snapshot->alloc_xpt, /*parent*/NULL);
   }
}

// All the used entries should look used, all the unused ones should be clear.
static void sanity_check_snapshots_array(void)
{
   Int i;
   for (i = 0; i < next_snapshot; i++) {
      tl_assert( is_snapshot_in_use( & snapshots[i] ));
   }
   for (    ; i < MAX_N_SNAPSHOTS; i++) {
      tl_assert(!is_snapshot_in_use( & snapshots[i] ));
   }
}

// This zeroes all the fields in the snapshot, but does not free the heap
// XTree if present.
static void clear_snapshot(Snapshot* snapshot)
{
   sanity_check_snapshot(snapshot);
   snapshot->time_ms        = -1;
   snapshot->total_szB      = 0;
   snapshot->heap_admin_szB = 0;
   snapshot->heap_szB       = 0;
   snapshot->stacks_szB     = 0;
   snapshot->alloc_xpt      = NULL;
}

// This zeroes all the fields in the snapshot, and frees the heap XTree if
// present.  
static void delete_snapshot(Snapshot* snapshot)
{
   // Nb: if there's an XTRee, we free it after calling clear_snapshot,
   // because clear_snapshot does a sanity check which includes checking the
   // XTree.
   XPt* tmp_xpt = snapshot->alloc_xpt;
   clear_snapshot(snapshot);
   if (tmp_xpt) {
      free_XTree(tmp_xpt);
   }
}

// Weed out half the snapshots;  we choose those that represent the smallest
// time-spans, because that loses the least information.
//
// Algorithm for N snapshots:  We find the snapshot representing the smallest
// timeframe, and remove it.  We repeat this until (N/2)-1 snapshots are gone.
// (It's (N/2)-1 because we never remove the first and last snapshots.)
// We have to do this one snapshot at a time, rather than finding the (N/2)-1
// smallest snapshots in one hit, because when a snapshot is removed, its
// neighbours immediately cover greater timespans.  So it's N^2, but N is
// small, and it's not done very often.
static void halve_snapshots(void)
{
   Int       i, jp, j, jn;
   Snapshot* min_snapshot;

   n_halvings++;
   if (VG_(clo_verbosity) > 1)
      VG_(message)(Vg_DebugMsg, "Halving snapshots...");

   // Sets j to the index of the first not-yet-removed snapshot at or after i
   #define FIND_SNAPSHOT(i, j) \
      for (j = i; \
           j < MAX_N_SNAPSHOTS && !is_snapshot_in_use(&snapshots[j]); \
           j++) { }

   for (i = 2; i < MAX_N_SNAPSHOTS; i += 2) {
      // Find the snapshot representing the smallest timespan.  The timespan
      // for snapshot n = d(N-1,N)+d(N,N+1), where d(A,B) is the time between
      // snapshot A and B.  We don't consider the first and last snapshots for
      // removal.
      Int min_span = 0x7fffffff;
      Int min_j    = 0;

      // Initial triple: (prev, curr, next) == (jp, j, jn)
      jp = 0;
      FIND_SNAPSHOT(1,   j);
      FIND_SNAPSHOT(j+1, jn);
      while (jn < MAX_N_SNAPSHOTS) {
         Int timespan = snapshots[jn].time_ms - snapshots[jp].time_ms;
         tl_assert(timespan >= 0);
         if (timespan < min_span) {
            min_span = timespan;
            min_j    = j;
         }
         // Move on to next triple
         jp = j; 
         j  = jn;
         FIND_SNAPSHOT(jn+1, jn);
      }
      // We've found the least important snapshot, now delete it.
      min_snapshot = & snapshots[ min_j ];
      delete_snapshot(min_snapshot);
   }

   // Slide down the remaining snapshots over the removed ones.  The '<=' is
   // because we are removing on (N/2)-1, rather than N/2.
   // First set i to point to the first empty slot, and j to the first full
   // slot after i.  Then slide everything down.
   for (i = 0;  is_snapshot_in_use( &snapshots[i] ); i++) { }
   for (j = i; !is_snapshot_in_use( &snapshots[j] ); j++) { }
   for (  ; j < MAX_N_SNAPSHOTS; j++) {
      if (is_snapshot_in_use( &snapshots[j] )) {
         snapshots[i++] = snapshots[j];
         clear_snapshot(&snapshots[j]);
      }
   }
   next_snapshot = i;

   // Check snapshots array looks ok after changes.
   sanity_check_snapshots_array();

   if (VG_(clo_verbosity) > 1)
      VG_(message)(Vg_DebugMsg, "...done");
}

// Take a snapshot.  Note that with bigger depths, snapshots can be slow,
// eg. konqueror snapshots can easily take 50ms!
// [XXX: is that still true?]
static void take_snapshot(void)
{
   static UInt interval_ms      = 5;
   static UInt ms_prev_snapshot = 0;
   static UInt ms_next_snapshot = 0;     // zero allows startup snapshot
   static Int  n_snapshots_since_last_detailed = 0;

   Int       time_ms, time_ms_since_prev;
   Snapshot* snapshot;

   // Only do a snapshot if it's time.
   time_ms            = VG_(read_millisecond_timer)();
   time_ms_since_prev = time_ms - ms_prev_snapshot;
   if (time_ms < ms_next_snapshot) {
      n_fake_snapshots++;
      return;
   }

   // Right!  We're taking a real snapshot.
   n_real_snapshots++;
   snapshot = & snapshots[next_snapshot];
   next_snapshot++;
   tl_assert(!is_snapshot_in_use(snapshot));

   // Heap -------------------------------------------------------------
   if (clo_heap) {
      snapshot->heap_szB = heap_szB;
      // Take a detailed snapshot if it's been long enough since the last one.
      if (DETAILED_SNAPSHOT_FREQ == n_snapshots_since_last_detailed) {
         snapshot->alloc_xpt = dup_XTree(alloc_xpt, /*parent*/NULL);
         tl_assert(snapshot->alloc_xpt->curr_szB == heap_szB);
         n_snapshots_since_last_detailed = 0;
      } else {
         n_snapshots_since_last_detailed++;
      }
   }

   // Heap admin -------------------------------------------------------
   if (clo_heap_admin > 0) {
      snapshot->heap_admin_szB = clo_heap_admin * n_heap_blocks;
   }

   // Stack(s) ---------------------------------------------------------
   if (clo_stacks) {
      ThreadId tid;
      Addr     stack_min, stack_max;
      VG_(thread_stack_reset_iter)();
      while ( VG_(thread_stack_next)(&tid, &stack_min, &stack_max) ) {
         snapshot->stacks_szB += (stack_max - stack_min);
      }
      snapshot->stacks_szB += sigstacks_szB;    // Add signal stacks, too
   }

   // Finish writing snapshot ------------------------------------------
   snapshot->time_ms   = time_ms;
   snapshot->total_szB =
      snapshot->heap_szB + snapshot->heap_admin_szB + snapshot->stacks_szB;

   // Sanity-check it.
   sanity_check_snapshot(snapshot);

   // Update peak data -------------------------------------------------
   // XXX: this is not really the right way to do peak data -- it's only
   // peak snapshot data, the true peak could be between snapshots.
   if (snapshot->total_szB > peak_snapshot_total_szB) {
      peak_snapshot_total_szB = snapshot->total_szB;
//      VG_(printf)("new peak snapshot total szB = %ld B\n",
//         peak_snapshot_total_szB);
   }

//   VG_(printf)("heap, admin, stacks: %ld, %ld, %ld B\n",
//      snapshot_heap_szB, snapshot_heap_admin_szB, snapshot_stacks_szB);

   // Halve the entries, if our snapshot table is full
   if (MAX_N_SNAPSHOTS == next_snapshot) {
      halve_snapshots();
      interval_ms *= 2;
   }

   // Take time for next snapshot from now, rather than when this snapshot
   // should have happened.  Because, if there's a big gap due to a kernel
   // operation, there's no point doing catch-up snapshots every allocation
   // for a while -- that would just give N snapshots at almost the same time.
   if (VG_(clo_verbosity) > 1) {
      VG_(message)(Vg_DebugMsg, "snapshot: %d ms (took %d ms)", time_ms, 
                                VG_(read_millisecond_timer)() - time_ms );
   }
   ms_prev_snapshot = time_ms;
   ms_next_snapshot = time_ms + interval_ms;
} 


//------------------------------------------------------------//
//--- Sanity checking                                      ---//
//------------------------------------------------------------//

static Bool ms_cheap_sanity_check ( void )
{
   // Nothing useful we can rapidly check.
   return True;
}

static Bool ms_expensive_sanity_check ( void )
{
   sanity_check_XTree(alloc_xpt, /*parent*/NULL);
   sanity_check_snapshots_array();
   return True;
}


//------------------------------------------------------------//
//--- Heap management                                      ---//
//------------------------------------------------------------//

static void update_heap_stats(SSizeT heap_szB_delta, Int n_heap_blocks_delta)
{
   if (n_heap_blocks_delta<0) tl_assert(n_heap_blocks >= -n_heap_blocks_delta);
   if (heap_szB_delta     <0) tl_assert(heap_szB      >= -heap_szB_delta     );
   n_heap_blocks += n_heap_blocks_delta;
   heap_szB      += heap_szB_delta;
   if (heap_szB > peak_heap_szB) {
      peak_heap_szB = heap_szB;
   }
}

static
void* new_block ( ThreadId tid, void* p, SizeT szB, SizeT alignB,
                  Bool is_zeroed )
{
   HP_Chunk* hc;
   Bool custom_alloc = (NULL == p);
   if (szB < 0) return NULL;

   // Update statistics
   n_allocs++;
   if (0 == szB) n_zero_allocs++;

   // Allocate and zero if necessary
   if (!p) {
      p = VG_(cli_malloc)( alignB, szB );
      if (!p) {
         return NULL;
      }
      if (is_zeroed) VG_(memset)(p, 0, szB);
   }

   // Make new HP_Chunk node, add to malloc_list
   hc       = VG_(malloc)(sizeof(HP_Chunk));
   hc->szB  = szB;
   hc->data = (Addr)p;
   hc->where = NULL;    // paranoia

   // Update heap stats
   update_heap_stats(hc->szB, /*n_heap_blocks_delta*/1);

   // Update XTree, if necessary
   if (clo_heap) {
      hc->where = get_XCon( tid, custom_alloc );
      update_XCon(hc->where, szB);
   }
   VG_(HT_add_node)(malloc_list, hc);

   // Do a snapshot!
   take_snapshot();      

   return p;
}

static __inline__
void die_block ( void* p, Bool custom_free )
{
   HP_Chunk* hc;
   
   // Update statistics
   n_frees++;

   // Remove HP_Chunk from malloc_list
   hc = VG_(HT_remove)(malloc_list, (UWord)p);
   if (NULL == hc) {
      return;   // must have been a bogus free()
   }

   // Update heap stats
   update_heap_stats(-hc->szB, /*n_heap_blocks_delta*/-1);

   // Update XTree, if necessary
   if (clo_heap) {
      update_XCon(hc->where, -hc->szB);
   }

   // Actually free the chunk, and the heap block (if necessary)
   VG_(free)( hc );  hc = NULL;
   if (!custom_free)
      VG_(cli_free)( p );

   // Do a snapshot!
   take_snapshot();
}

static __inline__
void* renew_block ( ThreadId tid, void* p_old, SizeT new_size )
{
   HP_Chunk* hc;
   void*     p_new;
   SizeT     old_size;
   XPt      *old_where, *new_where;
   
   // Remove the old block
   hc = VG_(HT_remove)(malloc_list, (UWord)p_old);
   if (hc == NULL) {
      return NULL;   // must have been a bogus realloc()
   }

   old_size = hc->szB;

   // Update heap stats
   update_heap_stats(new_size - old_size, /*n_heap_blocks_delta*/0);
  
   if (new_size <= old_size) {
      // new size is smaller or same;  block not moved
      p_new = p_old;

   } else {
      // new size is bigger;  make new block, copy shared contents, free old
      p_new = VG_(cli_malloc)(VG_(clo_alignment), new_size);
      if (p_new) {
         VG_(memcpy)(p_new, p_old, old_size);
         VG_(cli_free)(p_old);
      }
   }

   if (p_new) {
      old_where = hc->where;
      new_where = get_XCon( tid, /*custom_malloc*/False);

      // Update HP_Chunk
      hc->data  = (Addr)p_new;
      hc->szB   = new_size;
      hc->where = new_where;

      // Update XPt curr_szB fields
      if (clo_heap) {
         update_XCon(old_where, -old_size);
         update_XCon(new_where,  new_size);
      }
   }

   // Now insert the new hc (with a possibly new 'data' field) into
   // malloc_list.  If this realloc() did not increase the memory size, we
   // will have removed and then re-added mc unnecessarily.  But that's ok
   // because shrinking a block with realloc() is (presumably) much rarer
   // than growing it, and this way simplifies the growing case.
   VG_(HT_add_node)(malloc_list, hc);

   return p_new;
}
 

//------------------------------------------------------------//
//--- malloc() et al replacement wrappers                  ---//
//------------------------------------------------------------//

static void* ms_malloc ( ThreadId tid, SizeT szB )
{
   return new_block( tid, NULL, szB, VG_(clo_alignment), /*is_zeroed*/False );
}

static void* ms___builtin_new ( ThreadId tid, SizeT szB )
{
   return new_block( tid, NULL, szB, VG_(clo_alignment), /*is_zeroed*/False );
}

static void* ms___builtin_vec_new ( ThreadId tid, SizeT szB )
{
   return new_block( tid, NULL, szB, VG_(clo_alignment), /*is_zeroed*/False );
}

static void* ms_calloc ( ThreadId tid, SizeT m, SizeT szB )
{
   return new_block( tid, NULL, m*szB, VG_(clo_alignment), /*is_zeroed*/True );
}

static void *ms_memalign ( ThreadId tid, SizeT alignB, SizeT szB )
{
   return new_block( tid, NULL, szB, alignB, False );
}

static void ms_free ( ThreadId tid, void* p )
{
   die_block( p, /*custom_free*/False );
}

static void ms___builtin_delete ( ThreadId tid, void* p )
{
   die_block( p, /*custom_free*/False);
}

static void ms___builtin_vec_delete ( ThreadId tid, void* p )
{
   die_block( p, /*custom_free*/False );
}

static void* ms_realloc ( ThreadId tid, void* p_old, SizeT new_szB )
{
   return renew_block(tid, p_old, new_szB);
}


//------------------------------------------------------------//
//--- Tracked events                                       ---//
//------------------------------------------------------------//

static void new_mem_stack_signal(Addr a, SizeT len)
{
   sigstacks_szB += len;
}

static void die_mem_stack_signal(Addr a, SizeT len)
{
   tl_assert(sigstacks_szB >= len);
   sigstacks_szB -= len;
}


//------------------------------------------------------------//
//--- Client Requests                                      ---//
//------------------------------------------------------------//

static Bool ms_handle_client_request ( ThreadId tid, UWord* argv, UWord* ret )
{
   switch (argv[0]) {
   case VG_USERREQ__MALLOCLIKE_BLOCK: {
      void* res;
      void* p   = (void*)argv[1];
      SizeT szB =        argv[2];
      *ret = 0;
      res  =
         new_block( tid, p, szB, /*alignB--ignored*/0, /*is_zeroed*/False );
      tl_assert(res == p);
      return True;
   }
   case VG_USERREQ__FREELIKE_BLOCK: {
      void* p         = (void*)argv[1];
      *ret            = 0;
      die_block( p, /*custom_free*/True );
      return True;
   }
   default:
      *ret = 0;
      return False;
   }
}

//------------------------------------------------------------//
//--- Instrumentation                                      ---//
//------------------------------------------------------------//

static
IRSB* ms_instrument ( VgCallbackClosure* closure,
                      IRSB* bb_in, 
                      VexGuestLayout* layout, 
                      VexGuestExtents* vge,
                      IRType gWordTy, IRType hWordTy )
{
   static Bool is_first_SB = True;

   if (is_first_SB) {
      // Do an initial sample for t = 0
      take_snapshot();
      is_first_SB = False;
   }

   return bb_in;
}


//------------------------------------------------------------//
//--- Writing the graph file                               ---//
//------------------------------------------------------------//

#if 0
static Char* make_filename(Char* dir, Char* suffix)
{
   Char* filename;

   /* Block is big enough for dir name + massif.<pid>.<suffix> */
   filename = VG_(malloc)((VG_(strlen)(dir) + 32)*sizeof(Char));
   VG_(sprintf)(filename, "%s/massif.%d%s", dir, VG_(getpid)(), suffix);

   return filename;
}

static void file_err ( Char* file )
{
   VG_(message)(Vg_UserMsg, "error: can't open output file '%s'", file );
   VG_(message)(Vg_UserMsg, "       ... so profile results will be missing.");
}
#endif

#if 0
static void write_text_graph(void)
{
   Int    i;
   Int    x, y;         // y must be signed!
   Int end_time_ms;
   Char unit;
   Int orders_of_magnitude;
   SizeT peak_snapshot_total_szScaled;

   // XXX: unhardwire the sizes later
   #define GRAPH_X   72
   #define GRAPH_Y   20

   // The ASCII graph.
   // Row    0 ([0..GRAPH_X][0]) is the x-axis.
   // Column 0 ([0][0..GRAPH_Y]) is the y-axis.
   // The rest ([1][1]..[GRAPH_X][GRAPH_Y]) is the usable graph area.
   Char graph[GRAPH_X+1][GRAPH_Y+1];

   // We increment end_time_ms by 1 so that the last snapshot occurs just
   // before it, and doesn't spill over into the final column.
   tl_assert(next_snapshot > 0);
   end_time_ms = snapshots[next_snapshot-1].time_ms + 1;
   tl_assert(end_time_ms > 0);

   // Setup graph[][].
   graph[0][0] = '+';                                       // axes join point
   for (x = 1; x <= GRAPH_X; x++) { graph[x][0] = '-'; }    // x-axis
   for (y = 1; y <= GRAPH_Y; y++) { graph[0][y] = '|'; }    // y-axis
   for (x = 1; x <= GRAPH_X; x++) {                         // usable area
      for (y = 1; y <= GRAPH_Y; y++) {
         graph[x][y] = ' ';
      }
   }

   // Write snapshot bars into graph[][].
   // XXX: many detailed snapshot bars are being overwritten by
   for (i = 0; i < next_snapshot; i++) {
      Snapshot* snapshot = & snapshots[i];

      // Work out how many bytes each row represents.
      double per_row_full_thresh_szB = (double)peak_snapshot_total_szB / GRAPH_Y;
      double per_row_half_thresh_szB = per_row_full_thresh_szB / 2;

      // Work out which column this snapshot belongs to.
      double x_pos_frac = ((double)snapshot->time_ms / end_time_ms) * GRAPH_X;
      x = (int)x_pos_frac + 1;    // +1 due to y-axis

      // Grow this snapshot bar from bottom to top.
      for (y = 1; y <= GRAPH_Y; y++) {
         double this_row_full_thresh_szB = y * per_row_full_thresh_szB;
         double this_row_half_thresh_szB =
            this_row_full_thresh_szB - per_row_half_thresh_szB;

         graph[x][y] = ' ';
         if (snapshot->total_szB >= this_row_half_thresh_szB)
            graph[x][y] = '.';
         if (snapshot->total_szB >= this_row_full_thresh_szB)
            graph[x][y] = ( is_detailed_snapshot(snapshot) ? '|' : ':' );
      }
      // If it's detailed, mark the x-axis
      if (is_detailed_snapshot(snapshot)) 
         graph[x][0] = '|';
   }

   // Work out the units for the y-axis.
   orders_of_magnitude = 0;
   peak_snapshot_total_szScaled = peak_snapshot_total_szB;
   while (peak_snapshot_total_szScaled > 1000) {
      orders_of_magnitude++;
      peak_snapshot_total_szScaled /= 1000;
   }
   switch (orders_of_magnitude) {
      case 0: unit = ' '; break;
      case 1: unit = 'k'; break;
      case 2: unit = 'M'; break;
      case 3: unit = 'G'; break;
      case 4: unit = 'T'; break;
      default:
         tl_assert2(0, "unknown order of magnitude: %d", orders_of_magnitude);
   }

   // Print graph header, including command line.
   P("-- start graph header --\n");
   P("cmd: ");
   if (VG_(args_the_exename)) {
      P("%s", VG_(args_the_exename));
      for (i = 0; i < VG_(sizeXA)( VG_(args_for_client) ); i++) {
         HChar* arg = * (HChar**) VG_(indexXA)( VG_(args_for_client), i );
         if (arg)
            P(" %s", arg);
      }
   } else {
      P(" ???");
   }
   P("\n");
   P("-- end graph header --\n");

   // Print graph[][].
   P("-- start graph --\n");
   for (y = GRAPH_Y; y >= 0; y--) {
      // Row prefix
      if (GRAPH_Y == y)                // top point
         P("%3lu%c", peak_snapshot_total_szScaled, unit);
      else if (0 == y)                 // bottom point
         P("  0 ");
      else                             // anywhere else
         P("    ");
         
      // Axis and data for the row
      for (x = 0; x <= GRAPH_X; x++) {
         P("%c", graph[x][y]);
      }
      P("\n");
   }
   P("-- end graph --\n");

   // Print graph legend.
   P("-- start graph legend --\n");
   for (i = 0; i < next_snapshot; i++) {
      Snapshot* snapshot = & snapshots[i];
      if (is_detailed_snapshot(snapshot)) {
         P("    snapshot %3d: t = %,12d ms, size = %,12ld bytes\n",
            i, snapshot->time_ms, snapshot->total_szB);
      }
   }
   P("-- end graph legend --\n");
}
#endif


//------------------------------------------------------------//
//--- Writing snapshots                                    ---//
//------------------------------------------------------------//

// Nb: uses a static buffer, each call trashes the last string returned.
static Char* make_perc(ULong x, ULong y)
{
   static Char mbuf[32];

//   tl_assert(x <= y);    XXX; put back in later...
   
// XXX: I'm not confident that VG_(percentify) works as it should...
   VG_(percentify)(x, y, 2, 6, mbuf); 
   // XXX: this is bogus if the denominator was zero -- resulting string is
   // something like "0 --%")
   if (' ' == mbuf[0]) mbuf[0] = '0';
   return mbuf;
}

// Does the xpt account for >= 1% of total memory used?
// XXX: make command-line controllable?
static Bool is_significant_XPt(XPt* xpt, SizeT curr_total_szB)
{
   // clo_threshold is measured in hundredths of a percent of total size,
   // ie. 10,000ths of total size.  So clo_threshold=100 means that the
   // threshold is 1% of total size.
   tl_assert(xpt->curr_szB <= curr_total_szB);
   // XXX: overflow danger here...
   return (xpt->curr_szB * 10000 / curr_total_szB >= clo_threshold);
}

static void pp_snapshot_XPt(XPt* xpt, Int depth, Char* depth_str,
                            Int depth_str_len,
                            SizeT curr_heap_szB, SizeT curr_total_szB)
{
   Int   i;
   Char* ip_desc, *perc;
   SizeT printed_children_szB = 0;
   Int   n_sig_children;
   Int   n_insig_children;
   Int   n_child_entries;

   // If the XPt has children, check that the sum of all their sizes equals
   // the XPt's size.
   if (xpt->n_children > 0) {
      SizeT children_sum_szB = 0;
      for (i = 0; i < xpt->n_children; i++) {
         children_sum_szB += xpt->children[i]->curr_szB;
      }
      tl_assert(children_sum_szB == xpt->curr_szB);
   }

   // Sort XPt's children by curr_szB (reverse order:  biggest to smallest)
   // XXX: is it better to keep them always in order?
   // XXX: or, don't keep them in order, inspect all of them, but sort
   //      the selected ones in the queue when they're added.
   VG_(ssort)(xpt->children, xpt->n_children, sizeof(XPt*),
              XPt_revcmp_curr_szB);

   // How many children are significant?  Also calculate the number of child
   // entries to print:  there may be a need for an "insignificant rest"
   // line.
   for (i = 0; 
        i < xpt->n_children && 
           is_significant_XPt(xpt->children[i], curr_total_szB);
        i++) { }
   n_sig_children   = i;    
   n_insig_children = xpt->n_children - n_sig_children;    
   n_child_entries = n_sig_children + ( n_insig_children > 0 ? 1 : 0 );

   // Print the XPt entry
   if (xpt->ip == 0) {
      ip_desc =
         "(heap allocation functions) malloc/new/new[], --alloc-fns, etc.";
   } else {
      ip_desc = VG_(describe_IP)(xpt->ip-1, buf2, BUF_LEN);
   }
   perc = make_perc(xpt->curr_szB, curr_total_szB);
   P("%sn%d: %ld %s\n",
         depth_str, n_child_entries, xpt->curr_szB, ip_desc);

   // Indent
   tl_assert(depth+1 < depth_str_len-1);    // -1 for end NUL char
   depth_str[depth+0] = ' ';
   depth_str[depth+1] = '\0';

   // Print the children
   for (i = 0; i < n_sig_children; i++) {
      XPt* child = xpt->children[i];
      pp_snapshot_XPt(child, depth+1, depth_str, depth_str_len,
         curr_heap_szB, curr_total_szB);
      printed_children_szB += child->curr_szB;
   }

   // Print the extra "insignificant rest" entry, if necessary
   if (n_insig_children > 0) {
      Char* s        = ( n_insig_children == 1 ? "" : "s" );
      Char* other    = ( 0 == i ? "" : "other " );
      SizeT unprinted_children_szB = xpt->curr_szB - printed_children_szB;
      // XXX: should give the percentage.  be careful when computing
      // it...
      perc = make_perc(unprinted_children_szB, curr_total_szB);
      P("%sn0: %ld in %d %sinsignificant place%s\n",
         depth_str, unprinted_children_szB, n_insig_children, other, s);
   }

   // Unindent.
   depth_str[depth+0] = '\0';
   depth_str[depth+1] = '\0';
}

static void pp_snapshot(Snapshot* snapshot, Int snapshot_n)
{
   sanity_check_snapshot(snapshot);
   
   P("#--------------------------------\n");
   P("snapshot=%d\n", snapshot_n);
   P("#--------------------------------\n");
   P("time_ms=%lu\n",          snapshot->time_ms);
   P("mem_total_B=%lu\n",      snapshot->total_szB);
   P("mem_heap_B=%lu\n",       snapshot->heap_szB);
   P("mem_heap_admin_B=%lu\n", snapshot->heap_admin_szB);
   P("mem_stacks_B=%lu\n",     snapshot->stacks_szB);

   if (is_detailed_snapshot(snapshot)) {
      // Detailed snapshot -- print heap tree
      // XXX: check this works ok when no heap memory has been allocated
      Int   depth_str_len = clo_depth + 3;
      Char* depth_str = VG_(malloc)(sizeof(Char) * depth_str_len);
      depth_str[0] = '\0';   // Initialise depth_str to "".

      P("heap_tree=...\n");
      pp_snapshot_XPt(snapshot->alloc_xpt, 0, depth_str,
                      depth_str_len, snapshot->heap_szB,
                      snapshot->total_szB);

      VG_(free)(depth_str);

   } else {
      P("heap_tree=empty\n");
   }
}

static void write_detailed_snapshots(void)
{
   Int i;

   // Print description lines.
   P("desc: XXX\n");

   // Print "cmd:" line.
   P("cmd: ");
   if (VG_(args_the_exename)) {
      P("%s", VG_(args_the_exename));
      for (i = 0; i < VG_(sizeXA)( VG_(args_for_client) ); i++) {
         HChar* arg = * (HChar**) VG_(indexXA)( VG_(args_for_client), i );
         if (arg)
            P(" %s", arg);
      }
   } else {
      P(" ???");
   }
   P("\n");


   for (i = 0; i < next_snapshot; i++) {
      Snapshot* snapshot = & snapshots[i];
      pp_snapshot(snapshot, i);     // Detailed snapshot!
   }
}


//------------------------------------------------------------//
//--- Finalisation                                         ---//
//------------------------------------------------------------//

static void ms_fini(Int exit_status)
{
   // Do a final (empty) sample to show program's end
   take_snapshot();

   // Output.
   write_detailed_snapshots();

   // Stats
   if (VG_(clo_verbosity) > 1) {
      tl_assert(n_xpts > 0);  // always have alloc_xpt
      VG_(message)(Vg_DebugMsg, "    allocs:      %u", n_allocs);
      VG_(message)(Vg_DebugMsg, "zeroallocs:      %u (%d%%)", n_zero_allocs,
         n_zero_allocs * 100 / n_allocs );
      VG_(message)(Vg_DebugMsg, "     frees:      %u", n_frees);
      VG_(message)(Vg_DebugMsg, "      XPts:      %u", n_xpts);
      VG_(message)(Vg_DebugMsg, "  top-XPts:      %u (%d%%)",
         alloc_xpt->n_children, alloc_xpt->n_children * 100 / n_xpts);
      VG_(message)(Vg_DebugMsg, "dup'd XPts:      %u", n_dupd_xpts);
      VG_(message)(Vg_DebugMsg, "dup'd/freed XPts:%u", n_dupd_xpts_freed);
      VG_(message)(Vg_DebugMsg, "c-reallocs:      %u", n_children_reallocs);
      VG_(message)(Vg_DebugMsg, "fake snapshots:  %u", n_fake_snapshots);
      VG_(message)(Vg_DebugMsg, "real snapshots:  %u", n_real_snapshots);
      VG_(message)(Vg_DebugMsg, "  halvings:      %u", n_halvings);
      VG_(message)(Vg_DebugMsg, "XCon_redos:      %u", n_getXCon_redo);
   }
}


//------------------------------------------------------------//
//--- Initialisation                                       ---//
//------------------------------------------------------------//

static void ms_post_clo_init(void)
{
   Int i;
   if (VG_(clo_verbosity) > 1) {
      VG_(message)(Vg_DebugMsg, "alloc-fns:");
      for (i = 0; i < n_alloc_fns; i++) {
         VG_(message)(Vg_DebugMsg, "  %d: %s", i, alloc_fns[i]);
      }
   }

   // We don't take a snapshot now, because there's still some core
   // initialisation to do, in which case we have an artificial gap.
   // Instead we do it when the first translation occurs.  See
   // ms_instrument().
}

static void ms_pre_clo_init(void)
{ 
   Int i;
   
   VG_(details_name)            ("Massif");
   VG_(details_version)         (NULL);
   VG_(details_description)     ("a space profiler");
   VG_(details_copyright_author)("Copyright (C) 2003, Nicholas Nethercote");
   VG_(details_bug_reports_to)  (VG_BUGS_TO);

   // Basic functions
   VG_(basic_tool_funcs)          (ms_post_clo_init,
                                   ms_instrument,
                                   ms_fini);

   // Needs
   VG_(needs_libc_freeres)();
   VG_(needs_command_line_options)(ms_process_cmd_line_option,
                                   ms_print_usage,
                                   ms_print_debug_usage);
   VG_(needs_client_requests)     (ms_handle_client_request);
   VG_(needs_sanity_checks)       (ms_cheap_sanity_check,
                                   ms_expensive_sanity_check);
   VG_(needs_malloc_replacement)  (ms_malloc,
                                   ms___builtin_new,
                                   ms___builtin_vec_new,
                                   ms_memalign,
                                   ms_calloc,
                                   ms_free,
                                   ms___builtin_delete,
                                   ms___builtin_vec_delete,
                                   ms_realloc,
                                   0 );

   // Events to track
   VG_(track_new_mem_stack_signal)( new_mem_stack_signal );
   VG_(track_die_mem_stack_signal)( die_mem_stack_signal );

   // HP_Chunks
   malloc_list  = VG_(HT_construct)( 80021 );   // prime, big

   // Dummy node at top of the context structure.
   alloc_xpt = new_XPt(/*ip*/0, /*parent*/NULL);

   // Initialise snapshot array, and sanity check it.
   for (i = 0; i < MAX_N_SNAPSHOTS; i++) {
      clear_snapshot( & snapshots[i] );
   }
   sanity_check_snapshots_array();

   tl_assert( VG_(getcwd)(base_dir, VKI_PATH_MAX) );
}

VG_DETERMINE_INTERFACE_VERSION(ms_pre_clo_init)

//--------------------------------------------------------------------//
//--- end                                                          ---//
//--------------------------------------------------------------------//
