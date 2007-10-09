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
// Todo:
// - do snapshots on client requests
// - Add ability to draw multiple graphs, eg. heap-only, stack-only, total.
//   Give each graph a title.  (try to do it generically!)
// - make file format more generic.  Obstacles:
//   - unit prefixes are not generic
//   - preset column widths for stats are not generic
//   - preset column headers are not generic
//   - "Massif arguments:" line is not generic
// - consider 'instructions executed' as a time unit -- more regular than
//   ms, less artificial than B (bug #121629)
// - do a graph-drawing test
// - write a good basic test that shows how the tool works, suitable for
//   documentation
// - make everything configurable, eg. min/max number of snapshots (which
//   also determine culling proportion), frequency of detailed snapshots,
//   etc.
//
// Misc:
// - with --heap=no, --heap-admin still counts.  should it?
// - in each XPt, record both bytes and the number of live allocations? (or
//   even total allocations and total deallocations?)
//
// Dumping the results to file:
// - work out the file format (Josef wants Callgrind format, Donna wants
//   XML, Nick wants something easy to read in Perl)
// - allow truncation of long fnnames if the exact line number is
//   identified?  [hmm, could make getting the name of alloc-fns more
//   difficult] [could dump full names to file, truncate in ms_print]
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
// 132950   Heap alloc/usage summary
//   - doesn't seem that interesting or general
//
// FIXED/NOW IRRELEVANT:
// 89061   cra     Massif: ms_main.c:485 (get_XCon): Assertion `xpt->max_chi...
//   - relevant code now gone
// 143062  cra     massif crashes on app exit with signal 8 SIGFPE
//   - fixed
// 95483   nor     massif feature request: include peak allocation in report
//   - implemented in Massif2
// 92615    nor    Write output from Massif at crash
//   - this happens unless Massif2 itself crashes
// 121629   add instruction-counting mode for timing
//   - time-unit=B is similar, plus I'm considering this above anyway
// 142197  nor     massif tool ignores --massif:alloc-fn parameters in .valg...
//   - fixed in trunk
// 142491  nor     Maximise use of alloc_fns array
//   - addressed, it's now an OSet and thus unlimited in size
// 144453   (get_XCon): Assertion 'xpt->max_children != 0' failed.
//   - relevant code now gone
//
// POSSIBLY FIXED BY BETTER SANITY CHECKING, BUT HARD TO TELL:
// 141631   Massif: percentages don't add up correctly
//   - better sanity-checking should help this greatly
// 142706   massif numbers don't seem to add up
//   - better sanity-checking should help this greatly
// 149504   Assertion hit on alloc_xpt->curr_space >= -space_delta
//   - better sanity-checking should help this greatly
// 146456   (update_XCon): Assertion 'xpt->curr_space >= -space_delta' failed.
//   - better sanity-checking should help this greatly
//
// Michael Meeks:
// - wants an interactive way to request a dump (callgrind_control-style)
//   - "profile now"
//   - "show me the extra allocations since the last snapshot"
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
//     [asked-for.  Should probably be actual.  But that might be
//     confusing...]
//   - could conceivably remove XPts that have their szB reduced to zero.
//   - allow the output file name to be changed
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
// - Explain that no peak will be taken if no deallocations are done.
// - Explain how the stack is computed -- size is assumed to be zero when
//   code starts executing, which isn't true, but reflects what you have
//   control over in a normal program.
//
// Tests:
// - tests/overloaded_new.cpp is there
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
#include "pub_tool_oset.h"
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
// for, more or less.  The main data structure is a tree representing the
// call tree beneath all the allocation functions like malloc().
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

// Used for printing things when clo_verbosity > 1.
#define VERB(verb, format, args...) \
   if (VG_(clo_verbosity) > verb) { \
      VG_(message)(Vg_DebugMsg, "Massif: " format, ##args); \
   }



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

static UInt n_xpts                 = 0;
static UInt n_dupd_xpts            = 0;
static UInt n_dupd_xpts_freed      = 0;
static UInt n_allocs               = 0;
static UInt n_zero_allocs          = 0;
static UInt n_reallocs             = 0;
static UInt n_frees                = 0;
static UInt n_stack_allocs         = 0;
static UInt n_stack_frees          = 0;
static UInt n_xpt_init_expansions  = 0;
static UInt n_xpt_later_expansions = 0;
static UInt n_getXCon_redo         = 0;
static UInt n_cullings             = 0;
static UInt n_real_snapshots       = 0;
static UInt n_detailed_snapshots   = 0;
static UInt n_peak_snapshots       = 0;
static UInt n_skipped_snapshots    = 0;
static UInt n_skipped_snapshots_since_last_snapshot = 0;


//------------------------------------------------------------//
//--- Globals                                              ---//
//------------------------------------------------------------//

static SizeT heap_szB   = 0;       // Live heap size
static SizeT stacks_szB = 0;       // Live stacks size

// This is the total size from the current peak snapshot, or 0 if no peak
// snapshot has been taken yet.
static SizeT peak_snapshot_total_szB = 0;

// Incremented every time memory is allocated/deallocated, by the
// allocated/deallocated amount;  includes heap, heap-admin and stack
// memory.  An alternative to milliseconds as a unit of program "time".
static ULong total_allocs_deallocs_szB = 0;

static UInt n_heap_blocks = 0;

// Current directory at startup.
static Char base_dir[VKI_PATH_MAX]; // XXX: currently unused

// We don't start taking snapshots until the first basic block is executed,
// rather than doing it in ms_post_clo_init (which is the obvious spot), for
// two reasons.
// - It lets us ignore stack events prior to that, because they're not
//   really proper ones and just would screw things up.
// - Because there's still some core initialisation to do, and so there
//   would be an artificial time gap between the first and second snapshots.
//
static Bool have_started_executing_code = False;

//------------------------------------------------------------//
//--- Alloc fns                                            ---//
//------------------------------------------------------------//

// Nb: I used to have the following four C++ global overloadable allocators
// in alloc_fns:
//   operator new(unsigned)
//   operator new[](unsigned)
//   operator new(unsigned, std::nothrow_t const&)
//   operator new[](unsigned, std::nothrow_t const&)
// [Dennis Lubert says these are also necessary on AMD64:
//  "operator new(unsigned long)",
//  "operator new[](unsigned long)",
//  "operator new(unsigned long, std::nothrow_t const&)",
//  "operator new[](unsigned long, std::nothrow_t const&)",
// ]
// But someone might be interested in seeing them.  If they're not, they can
// specify them with --alloc-fn.

OSet* alloc_fns;

static void init_alloc_fns(void)
{
   // Create the OSet, and add the default elements.
   alloc_fns = VG_(OSetWord_Create)(VG_(malloc), VG_(free));
   #define DO(x)  VG_(OSetWord_Insert)(alloc_fns, (Word)x);
   DO("malloc"           );
   DO("calloc"           );
   DO("realloc"          );
   DO("memalign"         );
   DO("__builtin_new"    );
   DO("__builtin_vec_new");
}

static Bool is_alloc_fn(Char* fnname)
{
   Word alloc_fn_word;

   // Nb: It's a linear search through the list, because we're comparing
   // strings rather than pointers to strings.
   VG_(OSetWord_ResetIter)(alloc_fns);
   while ( VG_(OSetWord_Next)(alloc_fns, &alloc_fn_word) ) {
      if (VG_STREQ(fnname, (Char*)alloc_fn_word))
         return True;
   }
   return False;
}


//------------------------------------------------------------//
//--- Command line args                                    ---//
//------------------------------------------------------------//

#define MAX_DEPTH       50

typedef enum { TimeMS, TimeB } TimeUnit;

static Char* TimeUnit_to_string(TimeUnit time_unit)
{
   switch (time_unit) {
   case TimeMS: return "ms";
   case TimeB:  return "B";
   default:     tl_assert2(0, "TimeUnit_to_string: unrecognised TimeUnit");
   }
}

static Bool clo_heap        = True;
static UInt clo_heap_admin  = 8;
static Bool clo_stacks      = True;
static UInt clo_depth       = 8;       // XXX: too low?
static UInt clo_threshold   = 100;     // 100 == 1%
static UInt clo_time_unit   = TimeMS;

static XArray* args_for_massif;

static Bool ms_process_cmd_line_option(Char* arg)
{
   // Remember the arg for later use.
   VG_(addToXA)(args_for_massif, &arg);

        VG_BOOL_CLO(arg, "--heap",       clo_heap)
   else VG_BOOL_CLO(arg, "--stacks",     clo_stacks)

   // XXX: currently allows negative heap admin sizes!  Abort if negative.
   else VG_NUM_CLO (arg, "--heap-admin", clo_heap_admin)
   else VG_BNUM_CLO(arg, "--depth",      clo_depth, 1, MAX_DEPTH)

   // XXX: use a fractional number, so no division by 100
   else VG_NUM_CLO(arg, "--threshold",   clo_threshold)

   else if (VG_CLO_STREQ(arg, "--time-unit=ms")) clo_time_unit = TimeMS;
   else if (VG_CLO_STREQ(arg, "--time-unit=B"))  clo_time_unit = TimeB;

   else if (VG_CLO_STREQN(11, arg, "--alloc-fn=")) {
      VG_(OSetWord_Insert)(alloc_fns, (Word) & arg[11]);
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
"    --time-unit=ms|B          time unit, milliseconds or bytes\n"
"                               alloc'd/dealloc'd on the heap [ms]\n"
   );
   VG_(replacement_malloc_print_usage)();
}

static void ms_print_debug_usage(void)
{
   VG_(replacement_malloc_print_debug_usage)();
}


//------------------------------------------------------------//
//--- XPts, XTrees and XCons                               ---//
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
// Any child of 'alloc_xpt' is called a "top-XPt".  The XPts at the bottom
// of an XTree (leaf nodes) are "bottom-XPTs".
//
// Each path from a top-XPt to a bottom-XPt through an XTree gives an
// execution context ("XCon"), ie. a stack trace.  (And sub-paths represent
// stack sub-traces.)  The number of XCons in an XTree is equal to the
// number of bottom-XPTs in that XTree.
//
//      alloc_xpt       XTrees are bi-directional.
//        | ^
//        v |
//     > parent <       Example: if child1() calls parent() and child2()
//    /    |     \      also calls parent(), and parent() calls malloc(),
//   |    / \     |     the XTree will look like this.
//   |   v   v    |
//  child1   child2

typedef struct _XPt XPt;
struct _XPt {
   Addr  ip;              // code address

   // Bottom-XPts: space for the precise context.
   // Other XPts:  space of all the descendent bottom-XPts.
   // Nb: this value goes up and down as the program executes.
   SizeT curr_szB;

   XPt*  parent;           // pointer to parent XPt

   // Children.
   // n_children and max_children are 32-bit integers.  16-bit integers
   // are too small -- a very big program might have more than 65536
   // allocation points (ie. top-XPts) -- Konqueror starting up has 1800.
   UInt  n_children;       // number of children
   UInt  max_children;     // capacity of children array
   XPt** children;         // pointers to children XPts
};

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

   VG_(printf)("XPt (%p):\n", xpt);
   VG_(printf)("- ip:         : %p\n", (void*)xpt->ip);
   VG_(printf)("- curr_szB    : %ld\n", xpt->curr_szB);
   VG_(printf)("- parent      : %p\n", xpt->parent);
   VG_(printf)("- n_children  : %d\n", xpt->n_children);
   VG_(printf)("- max_children: %d\n", xpt->max_children);
   for (i = 0; i < xpt->n_children; i++) {
      VG_(printf)("- children[%2d]: %p\n", i, xpt->children[i]);
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
         n_xpt_init_expansions++;
      } else {
         parent->max_children *= 2;    // Double size
         parent->children = VG_(realloc)( parent->children,
                                          parent->max_children * sizeof(XPt*) );
         n_xpt_later_expansions++;
      }
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
//--- XTree Operations                                     ---//
//------------------------------------------------------------//

// XXX: taking a full snapshot... could/should just snapshot the significant
// parts.  Nb: then the amounts wouldn't add up, unless I represented the
// "insignificant places" in XPts.  Might be worthwhile -- there can
// be a lot of zero nodes in the XTree... (simpler: ignore all zero nodes
// unless threshold=0?)
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

// Sanity checking:  we check snapshot XTrees when they are taken, deleted
// and printed.  We periodically check the main heap XTree with
// ms_expensive_sanity_check.
//
static void sanity_check_XTree(XPt* xpt, XPt* parent)
{
   Int i;

   tl_assert(xpt != NULL);

   // Check back-pointer.
   tl_assert2(xpt->parent == parent,
      "xpt->parent = %p, parent = %p\n", xpt->parent, parent);

   // Check children counts look sane.
   tl_assert(xpt->n_children <= xpt->max_children);

   // Check the sum of any children szBs equals the XPt's szB.
   if (xpt->n_children > 0) {
      SizeT children_sum_szB = 0;
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
//--- XCon Operations                                      ---//
//------------------------------------------------------------//

// This is the limit on the number of removed alloc-fns that can be in a
// single XCon.
#define MAX_OVERESTIMATE   50
#define MAX_IPS            (MAX_DEPTH + MAX_OVERESTIMATE)

// XXX: look at the "(below main)"/"__libc_start_main" mess (m_stacktrace.c
//      and m_demangle.c).  Don't hard-code "(below main)" in here.
// [Nb: Josef wants --show-below-main to work for his fn entry/exit tracing]
static Bool is_main_or_below_main(Char* fnname)
{
   if (VG_STREQ(fnname, "main"))         return True;
   if (VG_STREQ(fnname, "(below main)")) return True;
   return False;
}

// Get the stack trace for an XCon, filtering out uninteresting entries:
// alloc-fns and entries above alloc-fns, and entries below main-or-below-main.
//   Eg:       alloc-fn1 / alloc-fn2 / a / b / main / (below main) / c
//   becomes:  a / b / main
// Nb: it's possible to end up with an empty trace, eg. if 'main' is marked
// as an alloc-fn.  This is ok.
static
Int get_IPs( ThreadId tid, Bool is_custom_alloc, Addr ips[], Int max_ips)
{
   Int n_ips, i, n_alloc_fns_removed = 0;
   Int overestimate;
   Bool fewer_IPs_than_asked_for   = False;
   Bool removed_below_main         = False;
   Bool enough_IPs_after_filtering = False;

   // XXX: get this properly
   Bool should_hide_below_main     = /*!VG_(clo_show_below_main)*/True;

   // We ask for a few more IPs than clo_depth suggests we need.  Then we
   // remove every entry that is an alloc-fn or above an alloc-fn, and
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
   //
   // Nb: it's possible that an alloc-fn may be found in the overestimate
   // portion, in which case the trace will be shrunk, even though it
   // arguably shouldn't.  But it would require a very large chain of
   // alloc-fns, and the best behaviour isn't all that clear, so we don't
   // worry about it.

   // Main loop
   for (overestimate = 3; True; overestimate += 6) {
      // This should never happen -- would require MAX_OVERESTIMATE
      // alloc-fns to be removed from the stack trace.
      if (overestimate > MAX_OVERESTIMATE)
         VG_(tool_panic)("get_IPs: ips[] too small, inc. MAX_OVERESTIMATE?");

      // Ask for some more IPs than clo_depth suggests we need.
      n_ips = VG_(get_StackTrace)( tid, ips, clo_depth + overestimate );
      tl_assert(n_ips > 0);

      // If we got fewer IPs than we asked for, redo=False
      if (n_ips < clo_depth + overestimate) {
         fewer_IPs_than_asked_for = True;
      }

      // Filter uninteresting entries out of the stack trace.  n_ips is
      // updated accordingly.
      for (i = n_ips-1; i >= 0; i--) {
         #define BUF_LEN   1024
         Char buf[BUF_LEN];

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
               n_alloc_fns_removed = i+1;

               // Shuffle the rest down.
               for (j = 0; j < n_ips; j++) {
                  ips[j] = ips[j + n_alloc_fns_removed];
               }
               n_ips -= n_alloc_fns_removed;
               break;
            }
         }
      }

      // There must be at least one alloc function, unless the client used
      // MALLOCLIKE_BLOCK.
      if (!is_custom_alloc)
         tl_assert2(n_alloc_fns_removed > 0,
                    "n_alloc_fns_removed = %s\n", n_alloc_fns_removed);

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
static XPt* get_XCon( ThreadId tid, Bool is_custom_alloc )
{
   static Addr ips[MAX_IPS];     // Static to minimise stack size.
   Int i;
   XPt* xpt = alloc_xpt;

   // After this call, the IPs we want are in ips[0]..ips[n_ips-1].
   Int n_ips = get_IPs(tid, is_custom_alloc, ips, MAX_IPS);

   // Now do the search/insertion of the XCon. 'L' is the loop counter,
   // being the index into ips[].
   for (i = 0; i < n_ips; i++) {
      Addr ip = ips[i];
      Int ch;
      // Look for IP in xpt's children.
      // Linear search, ugh -- about 10% of time for konqueror startup tried
      // caching last result, only hit about 4% for konqueror.
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
   tl_assert(0 == xpt->n_children); // Must be bottom-XPt
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

// Snapshots are done in a way so that we always have a reasonable number of
// them.  We start by taking them quickly.  Once we hit our limit, we cull
// some (eg. half), and start taking them more slowly.  Once we hit the
// limit again, we again cull and then take them even more slowly, and so
// on.

// XXX: if the program is really short, we may get no detailed snapshots...
// that's bad, do something about it.
#define MAX_N_SNAPSHOTS        100  // Keep it even, for simplicity
#define DETAILED_SNAPSHOT_FREQ  10  // Every Nth snapshot will be detailed

// Time is measured either in ms or bytes, depending on the --time-unit
// option.  It's a Long because it can exceed 32-bits reasonably easily, and
// because we need to allow negative values to represent unset times.
typedef Long Time;

#define UNUSED_SNAPSHOT_TIME  -333  // A conspicuous negative number.

typedef
   enum {
      Normal = 77,
      Peak,
      Unused
   }
   SnapshotKind;

typedef
   struct {
      SnapshotKind kind;
      Time  time;
      SizeT heap_szB;
      SizeT heap_admin_szB;
      SizeT stacks_szB;
      XPt*  alloc_xpt;     // Heap XTree root, if a detailed snapshot,
   }                       // otherwise NULL
   Snapshot;

static UInt     next_snapshot_i = 0;   // Index of where next snapshot will go.
static Snapshot snapshots[MAX_N_SNAPSHOTS];

static Bool is_snapshot_in_use(Snapshot* snapshot)
{
   if (Unused == snapshot->kind) {
      // If snapshot is unused, check all the fields are unset.
      tl_assert(snapshot->time           == UNUSED_SNAPSHOT_TIME);
      tl_assert(snapshot->heap_admin_szB == 0);
      tl_assert(snapshot->heap_szB       == 0);
      tl_assert(snapshot->stacks_szB     == 0);
      tl_assert(snapshot->alloc_xpt      == NULL);
      return False;
   } else {
      tl_assert(snapshot->time           != UNUSED_SNAPSHOT_TIME);
      return True;
   }
}

static Bool is_detailed_snapshot(Snapshot* snapshot)
{
   return (snapshot->alloc_xpt ? True : False);
}

static Bool is_uncullable_snapshot(Snapshot* snapshot)
{
   return &snapshots[0] == snapshot                   // First snapshot
       || &snapshots[next_snapshot_i-1] == snapshot   // Last snapshot
       || snapshot->kind == Peak;                     // Peak snapshot
}

static void sanity_check_snapshot(Snapshot* snapshot)
{
   if (snapshot->alloc_xpt) {
      sanity_check_XTree(snapshot->alloc_xpt, /*parent*/NULL);
   }
}

// All the used entries should look used, all the unused ones should be clear.
static void sanity_check_snapshots_array(void)
{
   Int i;
   for (i = 0; i < next_snapshot_i; i++) {
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
   snapshot->kind           = Unused;
   snapshot->time           = UNUSED_SNAPSHOT_TIME;
   snapshot->heap_admin_szB = 0;
   snapshot->heap_szB       = 0;
   snapshot->stacks_szB     = 0;
   snapshot->alloc_xpt      = NULL;
}

// This zeroes all the fields in the snapshot, and frees the heap XTree if
// present.
static void delete_snapshot(Snapshot* snapshot)
{
   // Nb: if there's an XTree, we free it after calling clear_snapshot,
   // because clear_snapshot does a sanity check which includes checking the
   // XTree.
   XPt* tmp_xpt = snapshot->alloc_xpt;
   clear_snapshot(snapshot);
   if (tmp_xpt) {
      free_XTree(tmp_xpt);
   }
}

static void VERB_snapshot(Int verbosity, Char* prefix, Int i)
{
   Snapshot* snapshot = &snapshots[i];
   Char* suffix;
   switch (snapshot->kind) {
   case Peak:   suffix = "p";                                            break;
   case Normal: suffix = ( is_detailed_snapshot(snapshot) ? "d" : "." ); break;
   case Unused: suffix = "u";                                            break;
   default:
      tl_assert2(0, "VERB_snapshot: unknown snapshot kind: %d", snapshot->kind);
   }
   VERB(verbosity, "%s S%s%3d (t:%lld, hp:%ld, ad:%ld, st:%ld)",
      prefix, suffix, i,
      snapshot->time,
      snapshot->heap_szB,
      snapshot->heap_admin_szB,
      snapshot->stacks_szB
   );
}

// Cull half the snapshots;  we choose those that represent the smallest
// time-spans, because that gives us the most even distribution of snapshots
// over time.  (It's possible to lose interesting spikes, however.)
//
// Algorithm for N snapshots:  We find the snapshot representing the smallest
// timeframe, and remove it.  We repeat this until (N/2) snapshots are gone.
// We have to do this one snapshot at a time, rather than finding the (N/2)
// smallest snapshots in one hit, because when a snapshot is removed, its
// neighbours immediately cover greater timespans.  So it's O(N^2), but N is
// small, and it's not done very often.
//
// Once we're done, we return the new smallest interval between snapshots.
// That becomes our minimum time interval.
static UInt cull_snapshots(void)
{
   Int  i, jp, j, jn, min_timespan_i;
   Int  n_deleted = 0;
   Time min_timespan;

   n_cullings++;

   // Sets j to the index of the first not-yet-removed snapshot at or after i
   #define FIND_SNAPSHOT(i, j) \
      for (j = i; \
           j < MAX_N_SNAPSHOTS && !is_snapshot_in_use(&snapshots[j]); \
           j++) { }

   VERB(1, "Culling...");

   // First we remove enough snapshots by clearing them in-place.  Once
   // that's done, we can slide the remaining ones down.
   for (i = 0; i < MAX_N_SNAPSHOTS/2; i++) {
      // Find the snapshot representing the smallest timespan.  The timespan
      // for snapshot n = d(N-1,N)+d(N,N+1), where d(A,B) is the time between
      // snapshot A and B.  We don't consider the first and last snapshots for
      // removal.
      Snapshot* min_snapshot;
      Int min_j;

      // Initial triple: (prev, curr, next) == (jp, j, jn)
      // Initial min_timespan is the first one.
      jp = 0;
      FIND_SNAPSHOT(1,   j);
      FIND_SNAPSHOT(j+1, jn);
      min_timespan = 0x7fffffffffffffffLL;
      min_j        = -1;
      while (jn < MAX_N_SNAPSHOTS) {
         Time timespan = snapshots[jn].time - snapshots[jp].time;
         tl_assert(timespan >= 0);
         // Nb: We never cull the peak snapshot.
         if (Peak != snapshots[j].kind && timespan < min_timespan) {
            min_timespan = timespan;
            min_j        = j;
         }
         // Move on to next triple
         jp = j;
         j  = jn;
         FIND_SNAPSHOT(jn+1, jn);
      }
      // We've found the least important snapshot, now delete it.  First
      // print it if necessary.
      tl_assert(-1 != min_j);    // Check we found a minimum.
      min_snapshot = & snapshots[ min_j ];
      if (VG_(clo_verbosity) > 1) {
         Char buf[64];
         VG_(snprintf)(buf, 64, " %3d (t-span = %lld)", i, min_timespan);
         VERB_snapshot(1, buf, min_j);
      }
      delete_snapshot(min_snapshot);
      n_deleted++;
   }

   // Slide down the remaining snapshots over the removed ones.  First set i
   // to point to the first empty slot, and j to the first full slot after
   // i.  Then slide everything down.
   for (i = 0;  is_snapshot_in_use( &snapshots[i] ); i++) { }
   for (j = i; !is_snapshot_in_use( &snapshots[j] ); j++) { }
   for (  ; j < MAX_N_SNAPSHOTS; j++) {
      if (is_snapshot_in_use( &snapshots[j] )) {
         snapshots[i++] = snapshots[j];
         clear_snapshot(&snapshots[j]);
      }
   }
   next_snapshot_i = i;

   // Check snapshots array looks ok after changes.
   sanity_check_snapshots_array();

   // Find the minimum timespan remaining;  that will be our new minimum
   // time interval.  Note that above we were finding timespans by measuring
   // two intervals around a snapshot that was under consideration for
   // deletion.  Here we only measure single intervals because all the
   // deletions have occurred.
   //
   // But we have to be careful -- some snapshots (eg. snapshot 0, and the
   // peak snapshot) are uncullable.  If two uncullable snapshots end up
   // next to each other, they'll never be culled (assuming the peak doesn't
   // change), and the time gap between them will not change.  However, the
   // time between the remaining cullable snapshots will grow ever larger.
   // This means that the min_timespan found will always be that between the
   // two uncullable snapshots, and it will be much smaller than it should
   // be.  To avoid this problem, when computing the minimum timespan, we
   // ignore any timespans between two uncullable snapshots.
   tl_assert(next_snapshot_i > 1);
   min_timespan = 0x7fffffffffffffffLL;
   min_timespan_i = -1;
   for (i = 1; i < next_snapshot_i; i++) {
      if (is_uncullable_snapshot(&snapshots[i]) &&
          is_uncullable_snapshot(&snapshots[i-1]))
      {
         VERB(1, "(Ignoring interval %d--%d when computing minimum)", i-1, i);
      } else {
         Time timespan = snapshots[i].time - snapshots[i-1].time;
         tl_assert(timespan >= 0);
         if (timespan < min_timespan) {
            min_timespan = timespan;
            min_timespan_i = i;
         }
      }
   }
   tl_assert(-1 != min_timespan_i);    // Check we found a minimum.

   // Print remaining snapshots, if necessary.
   if (VG_(clo_verbosity) > 1) {
      VERB(1, "Finished culling (%3d of %3d deleted)",
         n_deleted, MAX_N_SNAPSHOTS);
      for (i = 0; i < next_snapshot_i; i++) {
         VERB_snapshot(1, "  post-cull", i);
      }
      VERB(1, "New time interval = %lld (between snapshots %d and %d)",
         min_timespan, min_timespan_i-1, min_timespan_i);
   }

   return min_timespan;
}

static Time get_time(void)
{
   // Get current time, in whatever time unit we're using.
   if (clo_time_unit == TimeMS) {
      // Some stuff happens between the millisecond timer being initialised
      // to zero and us taking our first snapshot.  We determine that time
      // gap so we can subtract it from all subsequent times so that our
      // first snapshot is considered to be at t = 0ms.  Unfortunately, a
      // bunch of symbols get read after the first snapshot is taken but
      // before the second one (which is triggered by the first allocation),
      // so when the time-unit is 'ms' we always have a big gap between the
      // first two snapshots.  But at least users won't have to wonder why
      // the first snapshot isn't at t=0.
      static Bool is_first_get_time = True;
      static Time start_time_ms;
      if (is_first_get_time) {
         start_time_ms = VG_(read_millisecond_timer)();
         is_first_get_time = False;
         return 0;
      } else {
         return VG_(read_millisecond_timer)() - start_time_ms;
      }
   } else if (clo_time_unit == TimeB) {
      return total_allocs_deallocs_szB;
   } else {
      tl_assert2(0, "bad --time-unit value");
   }
}

// Take a snapshot, and only that -- decisions on whether to take a
// snapshot, or what kind of snapshot, are made elsewhere.
//
// Note that with bigger depths, snapshots can be slow, eg. konqueror
// snapshots can easily take 50ms!  [XXX: is that still true?]
static void
take_snapshot(Snapshot* snapshot, SnapshotKind kind, Time time,
              Bool is_detailed, Char* what)
{
   tl_assert(!is_snapshot_in_use(snapshot));
   tl_assert(have_started_executing_code);

   // Heap.
   if (clo_heap) {
      snapshot->heap_szB = heap_szB;
      if (is_detailed) {
         snapshot->alloc_xpt = dup_XTree(alloc_xpt, /*parent*/NULL);
         tl_assert(snapshot->alloc_xpt->curr_szB == heap_szB);
      }
   }

   // Heap admin.
   if (clo_heap_admin > 0) {
      snapshot->heap_admin_szB = clo_heap_admin * n_heap_blocks;
   }

   // Stack(s).
   if (clo_stacks) {
      snapshot->stacks_szB = stacks_szB;
   }

   // Rest of snapshot.
   snapshot->kind = kind;
   snapshot->time = time;
   sanity_check_snapshot(snapshot);

   // Update stats.
   if (Peak == kind) n_peak_snapshots++;
   if (is_detailed)  n_detailed_snapshots++;
   n_real_snapshots++;
}


// Take a snapshot, if it's time, or if we've hit a peak.
static void
maybe_take_snapshot(SnapshotKind kind, Char* what)
{
   // 'min_time_interval' is the minimum time interval between snapshots.
   // If we try to take a snapshot and less than this much time has passed,
   // we don't take it.  It gets larger as the program runs longer.  It's
   // initialised to zero so that we begin by taking snapshots as quickly as
   // possible.
   static Time min_time_interval = 0;
   // Zero allows startup snapshot.
   static Time earliest_possible_time_of_next_snapshot = 0;
   static Int n_snapshots_until_next_detailed = DETAILED_SNAPSHOT_FREQ - 1;

   Snapshot* snapshot;
   Bool      is_detailed;
   Time      time = get_time();

   switch (kind) {
    case Normal: 
      // Only do a snapshot if it's time.
      if (time < earliest_possible_time_of_next_snapshot) {
         n_skipped_snapshots++;
         n_skipped_snapshots_since_last_snapshot++;
         return;
      }
      is_detailed = (0 == n_snapshots_until_next_detailed);
      break;

    case Peak: {
      // Because we're about to do a deallocation, we're coming down from a
      // local peak.  If it is (a) actually a global peak, and (b) a certain
      // amount bigger than the previous peak, then we take a peak snapshot.
      //
      // XXX: make the percentage configurable
      SizeT total_szB = heap_szB + clo_heap_admin*n_heap_blocks + stacks_szB;
      double excess_over_previous_peak = 1.00;
      if (total_szB <= peak_snapshot_total_szB * excess_over_previous_peak) {
         return;
      }
      is_detailed = True;
      break;
    }

    default:
      tl_assert2(0, "maybe_take_snapshot: unrecognised snapshot kind");
   }

   // Take the snapshot.
   snapshot = & snapshots[next_snapshot_i];
   take_snapshot(snapshot, kind, time, is_detailed, what);

   // Record if it was detailed.
   if (is_detailed) {
      n_snapshots_until_next_detailed = DETAILED_SNAPSHOT_FREQ - 1;
   } else {
      n_snapshots_until_next_detailed--;
   }

   // Update peak data, if it's a Peak snapshot.
   if (Peak == kind) {
      Int i, number_of_peaks_snapshots_found = 0;

      // Sanity check the size, then update our recorded peak.
      SizeT snapshot_total_szB =
         snapshot->heap_szB + snapshot->heap_admin_szB + snapshot->stacks_szB;
      tl_assert(snapshot_total_szB > peak_snapshot_total_szB);
      peak_snapshot_total_szB = snapshot_total_szB;

      // Find the old peak snapshot, if it exists, and mark it as normal.
      for (i = 0; i < next_snapshot_i; i++) {
         if (Peak == snapshots[i].kind) {
            snapshots[i].kind = Normal;
            number_of_peaks_snapshots_found++;
         }
      }
      tl_assert(number_of_peaks_snapshots_found <= 1);
   }

   // Finish up verbosity and stats stuff.
   if (n_skipped_snapshots_since_last_snapshot > 0) {
      VERB(1, "  (skipped %d snapshot%s)",
         n_skipped_snapshots_since_last_snapshot,
         ( n_skipped_snapshots_since_last_snapshot == 1 ? "" : "s") );
   }
   VERB_snapshot(1, what, next_snapshot_i);
   n_skipped_snapshots_since_last_snapshot = 0;

   // Cull the entries, if our snapshot table is full.
   next_snapshot_i++;
   if (MAX_N_SNAPSHOTS == next_snapshot_i) {
      min_time_interval = cull_snapshots();
   }

   // Work out the earliest time when the next snapshot can happen.
   earliest_possible_time_of_next_snapshot = time + min_time_interval;
}


//------------------------------------------------------------//
//--- Sanity checking                                      ---//
//------------------------------------------------------------//

static Bool ms_cheap_sanity_check ( void )
{
   return True;   // Nothing useful we can cheaply check.
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

// Metadata for heap blocks.  Each one contains a pointer to a bottom-XPt,
// which is a foothold into the XCon at which it was allocated.  From
// HP_Chunks, XPt 'space' fields are incremented (at allocation) and
// decremented (at deallocation).
//
// Nb: first two fields must match core's VgHashNode.
typedef
   struct _HP_Chunk {
      struct _HP_Chunk* next;
      Addr              data;    // Ptr to actual block
      SizeT             szB;     // Size requested
      XPt*              where;   // Where allocated; bottom-XPt
   }
   HP_Chunk;

static VgHashTable malloc_list  = NULL;   // HP_Chunks

static void update_alloc_stats(SSizeT szB_delta)
{
   // Update total_allocs_deallocs_szB.
   if (szB_delta < 0) szB_delta = -szB_delta;
   total_allocs_deallocs_szB += szB_delta;
}

static void update_heap_stats(SSizeT heap_szB_delta, Int n_heap_blocks_delta)
{
   if (n_heap_blocks_delta<0) tl_assert(n_heap_blocks >= -n_heap_blocks_delta);
   if (heap_szB_delta     <0) tl_assert(heap_szB      >= -heap_szB_delta     );
   n_heap_blocks += n_heap_blocks_delta;
   heap_szB      += heap_szB_delta;

   update_alloc_stats(heap_szB_delta + clo_heap_admin*n_heap_blocks_delta);
}

static
void* new_block ( ThreadId tid, void* p, SizeT szB, SizeT alignB,
                  Bool is_zeroed )
{
   HP_Chunk* hc;
   Bool is_custom_alloc = (NULL != p);
   if (szB < 0) return NULL;

   VERB(2, "<<< new_mem_heap (%lu)", szB);

   // Update statistics
   n_allocs++;
   if (0 == szB) n_zero_allocs++;

   // Allocate and zero if necessary
   if (!p) {
      p = VG_(cli_malloc)( alignB, szB );
      if (!p) {
         VERB(2, ">>> (null)");
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
      hc->where = get_XCon( tid, is_custom_alloc );
      update_XCon(hc->where, szB);
   }
   VG_(HT_add_node)(malloc_list, hc);

   // Maybe take a snapshot.
   maybe_take_snapshot(Normal, "  alloc");

   VERB(2, ">>>");

   return p;
}

static __inline__
void die_block ( void* p, Bool custom_free )
{
   HP_Chunk* hc;
   SizeT     die_szB;

   VERB(2, "<<< die_mem_heap");

   // Update statistics
   n_frees++;

   // Remove HP_Chunk from malloc_list
   hc = VG_(HT_remove)(malloc_list, (UWord)p);
   if (NULL == hc) {
      VERB(2, ">>> (bogus)");
      return;   // must have been a bogus free()
   }
   die_szB = hc->szB;

   // Maybe take a peak snapshot, since it's a deallocation.
   maybe_take_snapshot(Peak, "de-PEAK");

   // Update heap stats
   update_heap_stats(-die_szB, /*n_heap_blocks_delta*/-1);

   // Update XTree, if necessary
   if (clo_heap) {
      update_XCon(hc->where, -hc->szB);
   }

   // Actually free the chunk, and the heap block (if necessary)
   VG_(free)( hc );  hc = NULL;
   if (!custom_free)
      VG_(cli_free)( p );

   // Maybe take a snapshot.
   maybe_take_snapshot(Normal, "dealloc");

   VERB(2, ">>> (-%lu)", die_szB);
}

static __inline__
void* renew_block ( ThreadId tid, void* p_old, SizeT new_szB )
{
   HP_Chunk* hc;
   void*     p_new;
   SizeT     old_szB;
   XPt      *old_where, *new_where;

   VERB(2, "<<< renew_mem_heap (%lu)", new_szB);

   // Update statistics
   n_reallocs++;

   // Remove the old block
   hc = VG_(HT_remove)(malloc_list, (UWord)p_old);
   if (hc == NULL) {
      VERB(2, ">>> (bogus)");
      return NULL;   // must have been a bogus realloc()
   }

   old_szB = hc->szB;

   // Maybe take a peak snapshot, if it's (effectively) a deallocation.
   if (new_szB < old_szB) {
      maybe_take_snapshot(Peak, "re-PEAK");
   }

   // Update heap stats
   update_heap_stats(new_szB - old_szB, /*n_heap_blocks_delta*/0);

   if (new_szB <= old_szB) {
      // new size is smaller or same;  block not moved
      p_new = p_old;

   } else {
      // new size is bigger;  make new block, copy shared contents, free old
      p_new = VG_(cli_malloc)(VG_(clo_alignment), new_szB);
      if (p_new) {
         VG_(memcpy)(p_new, p_old, old_szB);
         VG_(cli_free)(p_old);
      }
   }

   if (p_new) {
      old_where = hc->where;
      new_where = get_XCon( tid, /*custom_malloc*/False);

      // Update HP_Chunk
      hc->data  = (Addr)p_new;
      hc->szB   = new_szB;
      hc->where = new_where;

      // Update XPt curr_szB fields
      if (clo_heap) {
         update_XCon(old_where, -old_szB);
         update_XCon(new_where,  new_szB);
      }
   }

   // Now insert the new hc (with a possibly new 'data' field) into
   // malloc_list.  If this realloc() did not increase the memory size, we
   // will have removed and then re-added mc unnecessarily.  But that's ok
   // because shrinking a block with realloc() is (presumably) much rarer
   // than growing it, and this way simplifies the growing case.
   VG_(HT_add_node)(malloc_list, hc);

   // Maybe take a snapshot.
   maybe_take_snapshot(Normal, "realloc");

   VERB(2, ">>> (%ld)", new_szB - old_szB);

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
//--- Stacks                                               ---//
//------------------------------------------------------------//

// We really want the inlining to occur...
#define INLINE    inline __attribute__((always_inline))

static void update_stack_stats(SSizeT stack_szB_delta)
{
   if (stack_szB_delta < 0) tl_assert(stacks_szB >= -stack_szB_delta);
   stacks_szB += stack_szB_delta;

   update_alloc_stats(stack_szB_delta);
}

static INLINE void new_mem_stack_2(Addr a, SizeT len, Char* what)
{
   if (have_started_executing_code) {
      VERB(2, "<<< new_mem_stack (%ld)", len);
      n_stack_allocs++;
      update_stack_stats(len);
      maybe_take_snapshot(Normal, what);
      VERB(2, ">>>");
   }
}

static INLINE void die_mem_stack_2(Addr a, SizeT len, Char* what)
{
   if (have_started_executing_code) {
      VERB(2, "<<< die_mem_stack (%ld)", -len);
      n_stack_frees++;
      maybe_take_snapshot(Peak,   "stkPEAK");
      update_stack_stats(-len);
      maybe_take_snapshot(Normal, what);
      VERB(2, ">>>");
   }
}

static void new_mem_stack(Addr a, SizeT len)
{
   new_mem_stack_2(a, len, "stk-new");
}

static void die_mem_stack(Addr a, SizeT len)
{
   die_mem_stack_2(a, len, "stk-die");
}

static void new_mem_stack_signal(Addr a, SizeT len)
{
   new_mem_stack_2(a, len, "sig-new");
}

static void die_mem_stack_signal(Addr a, SizeT len)
{
   die_mem_stack_2(a, len, "sig-die");
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
      res = new_block( tid, p, szB, /*alignB--ignored*/0, /*is_zeroed*/False );
      tl_assert(res == p);
      *ret = 0;
      return True;
   }
   case VG_USERREQ__FREELIKE_BLOCK: {
      void* p = (void*)argv[1];
      die_block( p, /*custom_free*/True );
      *ret = 0;
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
   if (! have_started_executing_code) {
      // Do an initial sample to guarantee that we have at least one.
      // We use 'maybe_take_snapshot' instead of 'take_snapshot' to ensure
      // 'maybe_take_snapshot's internal static variables are initialised.
      have_started_executing_code = True;
      maybe_take_snapshot(Normal, "startup");
   }
   return bb_in;
}


//------------------------------------------------------------//
//--- Writing snapshots                                    ---//
//------------------------------------------------------------//

// XXX: do the filename properly, eventually
static Char* massif_out_file = "massif.out";

#define BUF_SIZE     1024
Char buf[1024];

// XXX: implement f{,n}printf in m_libcprint.c eventually, and use it here.
// Then change Cachegrind to use it too.
#define FP(format, args...) ({ \
   VG_(snprintf)(buf, BUF_SIZE, format, ##args); \
   VG_(write)(fd, (void*)buf, VG_(strlen)(buf)); \
})

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

// Does the xpt account for >= 1% (or so) of total memory used?
static Bool is_significant_XPt(XPt* xpt, SizeT curr_total_szB)
{
   // clo_threshold is measured in hundredths of a percent of total size,
   // ie. 10,000ths of total size.  So clo_threshold=100 means that the
   // threshold is 1% of total size.  If curr_total_szB is zero, we consider
   // every XPt significant.  We also always consider the alloc_xpt to be
   // significant.
   tl_assert(xpt->curr_szB <= curr_total_szB);
   return xpt == alloc_xpt || 0 == clo_threshold ||
      (0 != curr_total_szB &&
           xpt->curr_szB * 10000 / curr_total_szB >= clo_threshold);
}

static void pp_snapshot_XPt(Int fd, XPt* xpt, Int depth, Char* depth_str,
                            Int depth_str_len,
                            SizeT curr_heap_szB, SizeT curr_total_szB)
{
   #define BUF_LEN   1024
   Int   i;
   Char* perc;
   Char  ip_desc_array[BUF_LEN];
   Char* ip_desc = ip_desc_array;
   SizeT printed_children_szB = 0;
   Int   n_sig_children;
   Int   n_insig_children;
   Int   n_child_entries;

   // Sort XPt's children by curr_szB (reverse order:  biggest to smallest)
   VG_(ssort)(xpt->children, xpt->n_children, sizeof(XPt*),
              XPt_revcmp_curr_szB);

   // How many children are significant?  Also calculate the number of child
   // entries to print -- there may be a need for an "in N places" line.
   n_sig_children = 0;
   while (n_sig_children < xpt->n_children &&
          is_significant_XPt(xpt->children[n_sig_children], curr_total_szB)) {
      n_sig_children++;
   }
   n_insig_children = xpt->n_children - n_sig_children;
   n_child_entries = n_sig_children + ( n_insig_children > 0 ? 1 : 0 );

   // Print the XPt entry.
   if (xpt->ip == 0) {
      ip_desc =
         "(heap allocation functions) malloc/new/new[], --alloc-fns, etc.";
   } else {
      ip_desc = VG_(describe_IP)(xpt->ip-1, ip_desc, BUF_LEN);
   }
   perc = make_perc(xpt->curr_szB, curr_total_szB);
   FP("%sn%d: %lu %s\n", depth_str, n_child_entries, xpt->curr_szB, ip_desc);

   // Indent.
   tl_assert(depth+1 < depth_str_len-1);    // -1 for end NUL char
   depth_str[depth+0] = ' ';
   depth_str[depth+1] = '\0';

   // Print the children.
   for (i = 0; i < n_sig_children; i++) {
      XPt* child = xpt->children[i];
      pp_snapshot_XPt(fd, child, depth+1, depth_str, depth_str_len,
         curr_heap_szB, curr_total_szB);
      printed_children_szB += child->curr_szB;
   }

   // Print the extra "in N places" line, if any children were insignificant.
   if (n_insig_children > 0) {
      Char* s        = ( n_insig_children == 1 ? "," : "s, all" );
      SizeT total_insig_children_szB = xpt->curr_szB - printed_children_szB;
      perc = make_perc(total_insig_children_szB, curr_total_szB);
      FP("%sn0: %lu in %d place%s below massif's threshold (%s)\n",
         depth_str, total_insig_children_szB, n_insig_children, s,
         make_perc(clo_threshold, 10000));
   }

   // Unindent.
   depth_str[depth+0] = '\0';
   depth_str[depth+1] = '\0';
}

static void pp_snapshot(Int fd, Snapshot* snapshot, Int snapshot_n)
{
   sanity_check_snapshot(snapshot);

   FP("#-----------\n");
   FP("snapshot=%d\n", snapshot_n);
   FP("#-----------\n");
   FP("time=%lld\n",            snapshot->time);
   FP("mem_heap_B=%lu\n",       snapshot->heap_szB);
   FP("mem_heap_admin_B=%lu\n", snapshot->heap_admin_szB);
   FP("mem_stacks_B=%lu\n",     snapshot->stacks_szB);

   if (is_detailed_snapshot(snapshot)) {
      // Detailed snapshot -- print heap tree.
      Int   depth_str_len = clo_depth + 3;
      Char* depth_str = VG_(malloc)(sizeof(Char) * depth_str_len);
      SizeT snapshot_total_szB =
         snapshot->heap_szB + snapshot->heap_admin_szB + snapshot->stacks_szB;
      depth_str[0] = '\0';   // Initialise depth_str to "".

      FP("heap_tree=%s\n", ( Peak == snapshot->kind ? "peak" : "detailed" ));
      pp_snapshot_XPt(fd, snapshot->alloc_xpt, 0, depth_str,
                      depth_str_len, snapshot->heap_szB,
                      snapshot_total_szB);

      VG_(free)(depth_str);

   } else {
      FP("heap_tree=empty\n");
   }
}

static void write_snapshots_to_file(void)
{
   Int i, fd;
   SysRes sres;

   sres = VG_(open)(massif_out_file, VKI_O_CREAT|VKI_O_TRUNC|VKI_O_WRONLY,
                                     VKI_S_IRUSR|VKI_S_IWUSR);
   if (sres.isError) {
      // If the file can't be opened for whatever reason (conflict
      // between multiple cachegrinded processes?), give up now.
      VG_(message)(Vg_UserMsg,
         "error: can't open output file '%s'", massif_out_file );
      VG_(message)(Vg_UserMsg,
         "       ... so profiling results will be missing.");
      return;
   } else {
      fd = sres.res;
   }

   // Print massif-specific options that were used.
   // XXX: is it worth having a "desc:" line?  Could just call it "options:"
   // -- this file format isn't as generic as Cachegrind's, so the
   // implied genericity of "desc:" is bogus.
   FP("desc:");
   for (i = 0; i < VG_(sizeXA)(args_for_massif); i++) {
      Char* arg = *(Char**)VG_(indexXA)(args_for_massif, i);
      FP(" %s", arg);
   }
   if (0 == i) FP(" (none)");
   FP("\n");

   // Print "cmd:" line.
   FP("cmd: ");
   if (VG_(args_the_exename)) {
      FP("%s", VG_(args_the_exename));
      for (i = 0; i < VG_(sizeXA)( VG_(args_for_client) ); i++) {
         HChar* arg = * (HChar**) VG_(indexXA)( VG_(args_for_client), i );
         if (arg)
            FP(" %s", arg);
      }
   } else {
      FP(" ???");
   }
   FP("\n");

   FP("time_unit: %s\n", TimeUnit_to_string(clo_time_unit));

   for (i = 0; i < next_snapshot_i; i++) {
      Snapshot* snapshot = & snapshots[i];
      pp_snapshot(fd, snapshot, i);     // Detailed snapshot!
   }
}


//------------------------------------------------------------//
//--- Finalisation                                         ---//
//------------------------------------------------------------//

static void ms_fini(Int exit_status)
{
   // Output.
   write_snapshots_to_file();

   // Stats
   tl_assert(n_xpts > 0);  // always have alloc_xpt
   VERB(1, "allocs:               %u", n_allocs);
   VERB(1, "zeroallocs:           %u (%d%%)",
      n_zero_allocs,
      ( n_allocs ? n_zero_allocs * 100 / n_allocs : 0 ));
   VERB(1, "reallocs:             %u", n_reallocs);
   VERB(1, "frees:                %u", n_frees);
   VERB(1, "stack allocs:         %u", n_stack_allocs);
   VERB(1, "stack frees:          %u", n_stack_frees);
   VERB(1, "XPts:                 %u", n_xpts);
   VERB(1, "top-XPts:             %u (%d%%)",
      alloc_xpt->n_children,
      ( n_xpts ? alloc_xpt->n_children * 100 / n_xpts : 0));
   VERB(1, "dup'd XPts:           %u", n_dupd_xpts);
   VERB(1, "dup'd/freed XPts:     %u", n_dupd_xpts_freed);
   VERB(1, "XPt-init-expansions:  %u", n_xpt_init_expansions);
   VERB(1, "XPt-later-expansions: %u", n_xpt_later_expansions);
   VERB(1, "skipped snapshots:    %u", n_skipped_snapshots);
   VERB(1, "real snapshots:       %u", n_real_snapshots);
   VERB(1, "detailed snapshots:   %u", n_detailed_snapshots);
   VERB(1, "peak snapshots:       %u", n_peak_snapshots);
   VERB(1, "cullings:             %u", n_cullings);
   VERB(1, "XCon_redos:           %u", n_getXCon_redo);
}


//------------------------------------------------------------//
//--- Initialisation                                       ---//
//------------------------------------------------------------//

static void ms_post_clo_init(void)
{
   Int i = 1;
   Word alloc_fn_word;

   if (VG_(clo_verbosity) > 1) {
      VERB(1, "alloc-fns:");
      VG_(OSetWord_ResetIter)(alloc_fns);
      while ( VG_(OSetWord_Next)(alloc_fns, &alloc_fn_word) ) {
         VERB(1, "  %d: %s", i, (Char*)alloc_fn_word);
         i++;
      }
   }

   if (clo_stacks) {
      // Events to track.
      VG_(track_new_mem_stack)        ( new_mem_stack        );
      VG_(track_die_mem_stack)        ( die_mem_stack        );
      VG_(track_new_mem_stack_signal) ( new_mem_stack_signal );
      VG_(track_die_mem_stack_signal) ( die_mem_stack_signal );
   }
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

   // HP_Chunks
   malloc_list = VG_(HT_construct)( 80021 );   // prime, big

   // Dummy node at top of the context structure.
   alloc_xpt = new_XPt(/*ip*/0, /*parent*/NULL);

   // Initialise snapshot array, and sanity check it.
   for (i = 0; i < MAX_N_SNAPSHOTS; i++) {
      clear_snapshot( & snapshots[i] );
   }
   sanity_check_snapshots_array();

   // Initialise alloc_fns.
   init_alloc_fns();

   // Initialise args_for_massif.
   args_for_massif = VG_(newXA)(VG_(malloc), VG_(free), sizeof(HChar*));

   tl_assert( VG_(getcwd)(base_dir, VKI_PATH_MAX) );
}

VG_DETERMINE_INTERFACE_VERSION(ms_pre_clo_init)

//--------------------------------------------------------------------//
//--- end                                                          ---//
//--------------------------------------------------------------------//
