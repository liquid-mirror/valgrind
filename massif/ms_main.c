
/*--------------------------------------------------------------------*/
/*--- Massif: a heap profiling tool.                     ms_main.c ---*/
/*--------------------------------------------------------------------*/

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
// Separate content from presentation by dumping all results to a file and
// then post-processing with a separate program, a la Cachegrind?
// - work out the file format
// - allow two decimal places in percentages (Kirk Johnson says people want
//   it)
// - allow truncation of long fnnames if the exact line number is
//   identified?
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
// FIXED:
// 142197  nor     massif tool ignores --massif:alloc-fn parameters in .valg...
//   - fixed in trunk
// 142491  nor     Maximise use of alloc_fns array
//   - addressed, using the patch (with minor changes) from the bug report
//
// TODO:
// 89061   cra     Massif: ms_main.c:485 (get_XCon): Assertion `xpt->max_chi...
// 141631  nor     Massif: percentages don't add up correctly
// 142706  nor     massif numbers don't seem to add up
// 143062  cra     massif crashes on app exit with signal 8 SIGFPE
//   - occurs with no allocations -- ensure that case works
//
// Work out when to take periodic snapshots.
// - If I separate content from presentation I don't have to thin out the
//   old ones (but not doing so takes space...)
//
// Work out how to take the peak.
// - exact peak, or within a certain percentage?
// - include the stack?  makes it harder
//
// Michael Meeks:
// - wants an interactive way to request a dump (callgrind_control-style)
//   - "profile now"
//   - "show me the extra allocations from last-snapshot"
//   - "start/stop logging" (eg. quickly skip boring bits)
//
//---------------------------------------------------------------------------

// Memory profiler.  Produces a graph, gives lots of information about
// allocation contexts, in terms of space.time values (ie. area under the
// graph).  Allocation context information is hierarchical, and can thus
// be inspected step-wise to an appropriate depth.  See comments on data
// structures below for more info on how things work.

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

/*------------------------------------------------------------*/
/*--- Overview of operation                                ---*/
/*------------------------------------------------------------*/

// Heap blocks are tracked, and the amount of space allocated by various
// contexts (ie. lines of code, more or less) is also tracked.
// Periodically, a census is taken.  There are two
//
//
//  
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
// 25M^|       |:::::|:::::::|:::#:::|:::::::|::::      f:::::::|::::::::::|::
//  20M|      :|:::::|:::::::|:::#:::|:::::::|::::.  .::|:::::::|::::::::::|::
//  15M|    .::|:::::|:::::::|:::#:::|:::::::|::::::::::|:::::::|::::::::::|::
//  10M|  .::::|:::::|:::::::|:::#:::|:::::::|::::::::::|:::::::|::::::::::|::
//   5M|:::::::|:::::|:::::::|:::#:::|:::::::|::::::::::|:::::::|::::::::::|::
//   0M+----------------------------------------------------------------------t
//     012                                                               
//
// Explanation of y-axis:
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




// Ideas:
// - Graph has 72 columns of data, 0..71
//   - Once we've had the first 72, always have 72.
//   - On number  73, remove column 1, (0,2..71)
//   - On number  74, remove column 2, (0,2,4..71)
//   - On number  75, remove column 3, (0,2,4,6..71)
//   - On number 72+n, remove col   n, (0,2,4,6,...,2n..71)
//   - ...
//   - On number 107, remove column 35, (0,2,4,6,...,70..71)
//   

// column: 00 01 02 03 04 05 06 07 08 09 10 11 12
// census  --------------------------------------
// 00      00
// 01      00 01
// 02      00 01 02
// ...
// 11      00 01 02 03 04 05 06 07 08 09 10 11
// 12      00 01 02 03 04 05 06 07 08 09 10 11 12
// 13      00 02 03 04 05 06 07 08 09 10 11 12 13     removed col 01
// 14      00 02 04 05 06 07 08 09 10 11 12 13 14     removed col 02
// 15      00 02 04 06 07 08 09 10 11 12 13 14 15     removed col 03
// 16      00 02 04 06 08 09 10 11 12 13 14 15 16     removed col 04
// 17      00 02 04 06 08 10 11 12 13 14 15 16 17     removed col 05
// 18      00 02 04 06 08 10 12 13 14 15 16 17 18     removed col 06
// 19      00 02 04 06 08 10 12 14 15 16 17 18 19     removed col 07
// 20      00 02 04 06 08 10 12 14 16 17 18 19 20     removed col 08
// 21      00 02 04 06 08 10 12 14 16 18 19 20 21     removed col 09
// 22      00 02 04 06 08 10 12 14 16 18 20 21 22     removed col 10
// 23      00 02 04 06 08 10 12 14 16 18 20 22 23     removed col 11
// 24      00 02 04 06 08 10 12 14 16 18 20 22 24     removed col 12
//
// Problem with this is that we don't have an even x-axis distribution.
// Getting such a distribution is difficult in general.
//
// 



// - like Callgrind, allow multiple data sets to be dumped, by choosing points.
//   That way you could print one graph per phase, for example, for better
//   granularity.




// Periodically, a census is taken, and the amount of space used, at that
// point, by the most significant (highly allocating) contexts is recorded.
// Census start off frequently, but are scaled back as the program goes on,
// so that there are always a good number of them.  At the end, overall
// spacetimes for different contexts (of differing levels of precision) is
// calculated, the graph is printed, and the text giving spacetimes for the
// increasingly precise contexts is given.
//
// Measures the following:
// - heap blocks
// - heap admin bytes
// - stack(s)
// - code (code segments loaded at startup, and loaded with mmap)
// - data (data segments loaded at startup, and loaded/created with mmap,
//         and brk()d segments)

/*------------------------------------------------------------*/
/*--- Main types                                           ---*/
/*------------------------------------------------------------*/

// An XPt represents an "execution point", ie. a code address.  Each XPt is
// part of a tree of XPts (an "execution tree", or "XTree").  Each
// top-to-bottom path through an XTree gives an execution context ("XCon"),
// and is equivalent to a traditional Valgrind ExeContext.  
//
// The XPt at the top of an XTree (but below "alloc_xpt") is called a
// "top-XPt".  The XPts are the bottom of an XTree (leaf nodes) are
// "bottom-XPTs".  The number of XCons in an XTree is equal to the number of
// bottom-XPTs in that XTree.
//
// All XCons have the same top-XPt, "alloc_xpt", which represents all
// allocation functions like malloc().  It's a bit of a fake XPt, though,
// and is only used because it makes some of the code simpler.
//
// XTrees are bi-directional.
//
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
   UInt  curr_szB;

   // n_children and max_children are 32-bit integers, not 16-bit, because
   // a very big program might have more than 65536 allocation points
   // (Konqueror startup has 1800).
   XPt*  parent;           // pointer to parent XPt

   UInt  n_children;       // number of children
   UInt  max_children;     // capacity of children array
   XPt** children;         // pointers to children XPts
};

// Each census snapshots the most significant XTrees, each XTree having a
// top-XPt as its root.  The 'curr_szB' element for each XPt is recorded 
// in the snapshot.  The snapshot contains all the XTree's XPts, not in a
// tree structure, but flattened into an array.  This flat snapshot is used
// at the end for computing exact_ST_dbld for each XPt.
//
// Graph resolution, x-axis: no point having more than about 200 census
// x-points;  you can't see them on the graph.  Therefore:
//
//   - do a census every 1 ms for first 200 --> 200, all          (200 ms)
//   - halve (drop half of them)            --> 100, every 2nd    (200 ms)
//   - do a census every 2 ms for next 200  --> 200, every 2nd    (400 ms)
//   - halve                                --> 100, every 4th    (400 ms)
//   - do a census every 4 ms for next 400  --> 200, every 4th    (800 ms)
//   - etc.
//
// This isn't exactly right, because we actually drop (N/2)-1 when halving,
// but it shows the basic idea.

#define MAX_N_CENSI           10   // Keep it even, for simplicity

// Graph resolution, y-axis: hp2ps only draws the 19 biggest (in space-time)
// bands, rest get lumped into OTHERS.  I only print the top N
// (cumulative-so-far space-time) at each point.  N should be a bit bigger
// than 19 in case the cumulative space-time doesn't fit with the eventual
// space-time computed by hp2ps (but it should be close if the samples are
// evenly spread, since hp2ps does an approximate per-band space-time
// calculation that just sums the totals;  ie. it assumes all samples are
// the same distance apart).

#define MAX_SNAPSHOTS         32

typedef
   struct {
      XPt* xpt;
      UInt space;
   }
   XPtSnapshot;

// An XTree snapshot is stored as an array of of XPt snapshots.
typedef XPtSnapshot* XTreeSnapshot;

typedef
   struct {
      Int   ms_time;    // Int: must allow -1
      SizeT total_szB;  // Size of all allocations at that census time
   } 
   Census;

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

/*------------------------------------------------------------*/
/*--- Statistics                                           ---*/
/*------------------------------------------------------------*/

// Konqueror startup, to give an idea of the numbers involved with a biggish
// program, with default depth:
//
//  depth=3                   depth=40
//  - 310,000 allocations
//  - 300,000 frees
//  -  15,000 XPts            800,000 XPts
//  -   1,800 top-XPts

// XXX: check if we still need all these...
static UInt n_xpts               = 0;
static UInt n_bot_xpts           = 0;
static UInt n_allocs             = 0;
static UInt n_zero_allocs        = 0;
static UInt n_frees              = 0;
static UInt n_children_reallocs  = 0;
//static UInt n_snapshot_frees     = 0;

static UInt n_halvings           = 0;
static UInt n_real_censi         = 0;
static UInt n_fake_censi         = 0;

/*------------------------------------------------------------*/
/*--- Globals                                              ---*/
/*------------------------------------------------------------*/

#define FILENAME_LEN    256

#define SPRINTF(zz_buf, fmt, args...) \
   do { Int len = VG_(sprintf)(zz_buf, fmt, ## args); \
        VG_(write)(fd, (void*)zz_buf, len); \
   } while (0)

#define BUF_LEN         1024     // general purpose
static Char buf [BUF_LEN];
static Char buf2[BUF_LEN];
//static Char buf3[BUF_LEN];

// Make these signed so things are more obvious if they go negative.
static SSizeT sigstacks_szB = 0;     // Current signal stacks space sum
static SSizeT heap_szB      = 0;     // Live heap size
static SSizeT peak_heap_szB = 0;
static SSizeT peak_census_total_szB = 0;

static VgHashTable malloc_list  = NULL;   // HP_Chunks

static UInt n_heap_blocks = 0;

// Current directory at startup.
static Char base_dir[VKI_PATH_MAX];

#define MAX_ALLOC_FNS      128     // includes the builtin ones

// First few filled in, rest should be zeroed.  Zero-terminated vector.
static UInt  n_alloc_fns = 10;
static Char* alloc_fns[MAX_ALLOC_FNS] = { 
   "malloc",
   "operator new(unsigned)",
   "operator new[](unsigned)",
   "operator new(unsigned, std::nothrow_t const&)",
   "operator new[](unsigned, std::nothrow_t const&)",
   "__builtin_new",
   "__builtin_vec_new",
   "calloc",
   "realloc",
   "memalign",
};


/*------------------------------------------------------------*/
/*--- Command line args                                    ---*/
/*------------------------------------------------------------*/

#define MAX_DEPTH       50

static Bool clo_heap        = True;
static UInt clo_heap_admin  = 8;
static Bool clo_stacks      = True;
static Bool clo_depth       = 8;

static Bool ms_process_cmd_line_option(Char* arg)
{
        VG_BOOL_CLO(arg, "--heap",       clo_heap)
   else VG_BOOL_CLO(arg, "--stacks",     clo_stacks)

   else VG_NUM_CLO (arg, "--heap-admin",  clo_heap_admin)
   else VG_BNUM_CLO(arg, "--depth",       clo_depth, 1, MAX_DEPTH)

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
   );
   VG_(replacement_malloc_print_usage)();
}

static void ms_print_debug_usage(void)
{
   VG_(replacement_malloc_print_debug_usage)();
}

/*------------------------------------------------------------*/
/*--- Execution contexts                                   ---*/
/*------------------------------------------------------------*/

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



static XPt* new_XPt(Addr ip, XPt* parent, Bool is_bottom)
{
   XPt* xpt          = perm_malloc(sizeof(XPt));
   xpt->ip           = ip;
   xpt->curr_szB     = 0;
   xpt->parent       = parent;

   // Check parent is not a bottom-XPt
   tl_assert(parent == NULL || 0 != parent->max_children);

   xpt->n_children   = 0;

   // If a bottom-XPt, don't allocate space for children.  This can be 50%
   // or more, although it tends to drop as --depth increases (eg. 10% for
   // konqueror with --depth=20).
   if ( is_bottom ) {
      xpt->max_children = 0;
      xpt->children     = NULL;
      n_bot_xpts++;
   } else {
      xpt->max_children = 4;
      xpt->children     = VG_(malloc)( xpt->max_children * sizeof(XPt*) );
   }

   // Update statistics
   n_xpts++;

   return xpt;
}

static Bool is_alloc_fn(Addr ip)
{
   Int i;

   if ( VG_(get_fnname)(ip, buf, BUF_LEN) ) {
      for (i = 0; i < n_alloc_fns; i++) {
         if (VG_STREQ(buf, alloc_fns[i]))
            return True;
      }
   }
   return False;
}

// XXX: check, improve this!
// Returns an XCon, from the bottom-XPt.  Nb: the XPt returned must be a
// bottom-XPt now and must always remain a bottom-XPt.  We go to some effort
// to ensure this in certain cases.  See comments below.
static XPt* get_XCon( ThreadId tid, Bool custom_malloc )
{
   // Static to minimise stack size.  +1 for added ~0 IP
   // XXX: MAX_ALLOC_FNS isn't the right number to use here -- that's the
   // total number of them, we want the number that might occur in a
   // stacktrace (if there were repeats...)
   static Addr ips[MAX_DEPTH + MAX_ALLOC_FNS + 1];

   XPt* xpt = alloc_xpt;
   UInt n_ips, L, A, B, nC;
   UInt overestimate;
   Bool reached_bottom;


//---------------------------------------------------------------------------
// simplified Algorithm
// - get the biggest stack-trace possible: ips[n]
// - filter out alloc-fns: --> ips[n2], n2<=n
// - curr_xpt = alloc_xpt
// - foreach ip in ips[]:
//   - if ip is in curr_xpt->children[]
//     - then: curr_xpt = the matching child
//     - else: add new child (with ip) to curr_xpt->children[],
//             curr_xpt = the new child
// - return curr_xpt as the bottom-XPt
//
// Notes:
// - a bottom-XPt should never become a non-bottom-XPt, because its curr_szB
//   would get mucked up.  Eg. if we have an XCon A/B/C, we should never see
//   a later XCon A/B/C/D, because C would no longer be a bottom-XPt.  It
//   doesn't seem like this should ever happen, but it's hard to know for
//   sure.  
//   [XXX: if main is recursive, you could imagine getting main/A,
//   then main/main/A...]
//   [XXX: actually, not true -- the curr_szB wouldn't be mucked up.
//
//---------------------------------------------------------------------------

   // Want at least clo_depth non-alloc-fn entries in the snapshot.
   // However, because we have 1 or more (an unknown number, at this point)
   // alloc-fns ignored, we overestimate the size needed for the stack
   // snapshot.  Then, if necessary, we repeatedly increase the size until
   // it is enough.
   overestimate = 2;
   while (True) {
      n_ips = VG_(get_StackTrace)( tid, ips, clo_depth + overestimate );

      // Now we add a dummy "unknown" IP at the end.  This is only used if we
      // run out of IPs before hitting clo_depth.  It's done to ensure the
      // XPt we return is (now and forever) a bottom-XPt.  If the returned XPt
      // wasn't a bottom-XPt (now or later) it would cause problems later (eg.
      // the parent's approx_ST wouldn't be equal [or almost equal] to the
      // total of the childrens' approx_STs).  
      ips[ n_ips++ ] = ~((Addr)0);

      // Skip over alloc functions in ips[]. 
      for (L = 0; is_alloc_fn(ips[L]) && L < n_ips; L++) { }

      // Must be at least one alloc function, unless client used
      // MALLOCLIKE_BLOCK
      if (!custom_malloc) tl_assert(L > 0);    

      // Should be at least one non-alloc function.  If not, try again.
      if (L == n_ips) {
         overestimate += 2;
         if (overestimate > MAX_ALLOC_FNS)
            VG_(tool_panic)("No stk snapshot big enough to find non-alloc fns");
      } else {
         break;
      }
   }
   A = L;
   B = n_ips - 1;
   reached_bottom = False;

   // By this point, the IPs we care about are in ips[A]..ips[B]

   // Now do the search/insertion of the XCon. 'L' is the loop counter,
   // being the index into ips[].
   while (True) {
      // Look for IP in xpt's children.
      // XXX: linear search, ugh -- about 10% of time for konqueror startup
      // XXX: tried cacheing last result, only hit about 4% for konqueror
      // Nb:  this search hits about 98% of the time for konqueror

      // If we've searched/added deep enough, or run out of EIPs, this is
      // the bottom XPt.
      if (L - A + 1 == clo_depth || L == B) 
         reached_bottom = True;

      nC = 0;
      while (True) {
         if (nC == xpt->n_children) {
            // not found, insert new XPt
            // XXX: assertion can fail (eg.  bug 89061).  Apparently caused
            //      by getting an IP in the stack trace that is ~0 (eg.
            //      0xffffffff).
            tl_assert(xpt->max_children != 0);     
            tl_assert(xpt->n_children <= xpt->max_children);
            // Expand 'children' if necessary
            if (xpt->n_children == xpt->max_children) {
               xpt->max_children *= 2;
               xpt->children = VG_(realloc)( xpt->children,
                                             xpt->max_children * sizeof(XPt*) );
               n_children_reallocs++;
            }
            // Make new XPt for IP, insert in list
            xpt->children[ xpt->n_children++ ] = 
               new_XPt(ips[L], xpt, reached_bottom);
            break;
         }
         if (ips[L] == xpt->children[nC]->ip) break;   // found the IP
         nC++;                                           // keep looking
      }

      // Return found/built bottom-XPt.
      if (reached_bottom) {
         tl_assert(0 == xpt->children[nC]->n_children);   // Must be bottom-XPt
         return xpt->children[nC];
      }

      // Descend to next level in XTree, the newly found/built non-bottom-XPt
      xpt = xpt->children[nC];
      L++;
   }
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

// Reverse comparison for a reverse sort -- biggest to smallest.
static Int XPt_revcmp_curr_szB(void* n1, void* n2)
{
   XPt* xpt1 = *(XPt**)n1;
   XPt* xpt2 = *(XPt**)n2;
   return ( xpt1->curr_szB < xpt2->curr_szB ?  1 
          : xpt1->curr_szB > xpt2->curr_szB ? -1
          :                                    0);
}

/*------------------------------------------------------------*/
/*--- Heap management                                      ---*/
/*------------------------------------------------------------*/

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


// Forward declaration
static void hp_census(void);

static
void* new_block ( ThreadId tid, void* p, SizeT size, SizeT align,
                  Bool is_zeroed )
{
   HP_Chunk* hc;
   Bool custom_alloc = (NULL == p);
   if (size < 0) return NULL;

   // Update statistics
   n_allocs++;
   if (0 == size) n_zero_allocs++;

   // Allocate and zero if necessary
   if (!p) {
      p = VG_(cli_malloc)( align, size );
      if (!p) {
         return NULL;
      }
      if (is_zeroed) VG_(memset)(p, 0, size);
   }

   // Make new HP_Chunk node, add to malloc_list
   hc       = VG_(malloc)(sizeof(HP_Chunk));
   hc->szB  = size;
   hc->data = (Addr)p;
   hc->where = NULL;    // paranoia

   // Update heap stats
   update_heap_stats(hc->szB, /*n_heap_blocks_delta*/1);

   // Update XTree, if necessary
   if (clo_heap) {
      hc->where = get_XCon( tid, custom_alloc );
      update_XCon(hc->where, size);
   }
   VG_(HT_add_node)(malloc_list, hc);

   // Do a census!
   hp_census();      

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

   // Do a census!
   hp_census();
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
 
/*------------------------------------------------------------*/
/*--- malloc() et al replacement wrappers                  ---*/
/*------------------------------------------------------------*/

static void* ms_malloc ( ThreadId tid, SizeT n )
{
   return new_block( tid, NULL, n, VG_(clo_alignment), /*is_zeroed*/False );
}

static void* ms___builtin_new ( ThreadId tid, SizeT n )
{
   return new_block( tid, NULL, n, VG_(clo_alignment), /*is_zeroed*/False );
}

static void* ms___builtin_vec_new ( ThreadId tid, SizeT n )
{
   return new_block( tid, NULL, n, VG_(clo_alignment), /*is_zeroed*/False );
}

static void* ms_calloc ( ThreadId tid, SizeT m, SizeT size )
{
   return new_block( tid, NULL, m*size, VG_(clo_alignment), /*is_zeroed*/True );
}

static void *ms_memalign ( ThreadId tid, SizeT align, SizeT n )
{
   return new_block( tid, NULL, n, align, False );
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

static void* ms_realloc ( ThreadId tid, void* p_old, SizeT new_size )
{
   return renew_block(tid, p_old, new_size);
}


/*------------------------------------------------------------*/
/*--- Taking a census                                      ---*/
/*------------------------------------------------------------*/

static Census censi[MAX_N_CENSI];
static UInt   curr_census = 0;   // Points to where next census will go.

static UInt ms_interval;
static UInt do_every_nth_census = 30;

// Weed out half the censi;  we choose those that represent the smallest
// time-spans, because that loses the least information.
//
// Algorithm for N censi:  We find the census representing the smallest
// timeframe, and remove it.  We repeat this until (N/2)-1 censi are gone.
// (It's (N/2)-1 because we never remove the first and last censi.)
// We have to do this one census at a time, rather than finding the (N/2)-1
// smallest censi in one hit, because when a census is removed, it's
// neighbours immediately cover greater timespans.  So it's N^2, but N only
// equals 200, and this is only done every 100 censi, which is not too often.
static void halve_censi(void)
{
   Int     i, jp, j, jn;
   Census* min_census;

   n_halvings++;
   if (VG_(clo_verbosity) > 1)
      VG_(message)(Vg_UserMsg, "Halving censi...");

   // Sets j to the index of the first not-yet-removed census at or after i
   #define FIND_CENSUS(i, j) \
      for (j = i; j < MAX_N_CENSI && -1 == censi[j].ms_time; j++) { }

   for (i = 2; i < MAX_N_CENSI; i += 2) {
      // Find the censi representing the smallest timespan.  The timespan
      // for census n = d(N-1,N)+d(N,N+1), where d(A,B) is the time between
      // censi A and B.  We don't consider the first and last censi for
      // removal.
      Int min_span = 0x7fffffff;
      Int min_j    = 0;

      // Initial triple: (prev, curr, next) == (jp, j, jn)
      jp = 0;
      FIND_CENSUS(1,   j);
      FIND_CENSUS(j+1, jn);
      while (jn < MAX_N_CENSI) {
         Int timespan = censi[jn].ms_time - censi[jp].ms_time;
         tl_assert(timespan >= 0);
         if (timespan < min_span) {
            min_span = timespan;
            min_j    = j;
         }
         // Move on to next triple
         jp = j; 
         j  = jn;
         FIND_CENSUS(jn+1, jn);
      }
      // We've found the least important census, now remove it
      min_census = & censi[ min_j ];
      min_census->ms_time = -1;
   }

   // Slide down the remaining censi over the removed ones.  The '<=' is
   // because we are removing on (N/2)-1, rather than N/2.
   for (i = 0, j = 0; i <= MAX_N_CENSI / 2; i++, j++) {
      FIND_CENSUS(j, j);
      if (i != j) {
         censi[i] = censi[j];
      }
   }
   curr_census = i;

   // Double intervals
   ms_interval         *= 2;
   do_every_nth_census *= 2;

   if (VG_(clo_verbosity) > 1)
      VG_(message)(Vg_UserMsg, "...done");
}

// Forward declaration.
// XXX: necessary?
static void pp_snapshot(SizeT curr_heap_szB,   SizeT curr_heap_admin_szB,
                        SizeT curr_stacks_szB, SizeT curr_total_szB);


// Take a census.  Census time seems to be insignificant (usually <= 0 ms,
// almost always <= 1ms) so don't have to worry about subtracting it from
// running time in any way.
//
// XXX: NOT TRUE!  with bigger depths, konqueror censuses can easily take
//      50ms!
static void hp_census(void)
{
   static UInt ms_prev_census = 0;
   static UInt ms_next_census = 0;     // zero allows startup census

   SSizeT census_heap_szB       = 0;
   SSizeT census_heap_admin_szB = 0;
   SSizeT census_stacks_szB     = 0;

   Int     ms_time, ms_time_since_prev;
   Census* census;

   // Only do a census if it's time
   ms_time            = VG_(read_millisecond_timer)();
   ms_time_since_prev = ms_time - ms_prev_census;
   if (ms_time < ms_next_census) {
      n_fake_censi++;
      return;
   }
   n_real_censi++;

   census = & censi[curr_census];

   // Heap -------------------------------------------------------------
   if (clo_heap) {
      census_heap_szB = heap_szB;
   }

   // Heap admin -------------------------------------------------------
   if (clo_heap_admin > 0) {
      census_heap_admin_szB = clo_heap_admin * n_heap_blocks;
   }

   // Stack(s) ---------------------------------------------------------
   if (clo_stacks) {
      ThreadId tid;
      Addr     stack_min, stack_max;
      VG_(thread_stack_reset_iter)();
      while ( VG_(thread_stack_next)(&tid, &stack_min, &stack_max) ) {
         census_stacks_szB += (stack_max - stack_min);
      }
      census_stacks_szB += sigstacks_szB;    // Add signal stacks, too
   }

   // Write out census -------------------------------------------------
   census->ms_time = ms_time;
   census->total_szB =
      census_heap_szB + census_heap_admin_szB + census_stacks_szB;
//   VG_(printf)("heap, admin, stacks: %ld, %ld, %ld B\n",
//      census_heap_szB, census_heap_admin_szB, census_stacks_szB);
   if (census->total_szB > peak_census_total_szB) {
      peak_census_total_szB = census->total_szB;
      VG_(printf)("new peak census total szB = %ld B\n", peak_census_total_szB);
   }

   // Print the significant part of the XTree  [XXX: temporary]
   if (clo_heap)
      pp_snapshot(census_heap_szB,   census_heap_admin_szB,
                  census_stacks_szB, census->total_szB);

   // Clean-ups
   curr_census++;
   census = NULL;    // don't use again now that curr_census changed

   // Halve the entries, if our census table is full
   if (MAX_N_CENSI == curr_census) {
      halve_censi();
   }

   // Take time for next census from now, rather than when this census
   // should have happened.  Because, if there's a big gap due to a kernel
   // operation, there's no point doing catch-up censi every allocation for
   // a while -- that would just give N censi at almost the same time.
   if (VG_(clo_verbosity) > 1) {
      VG_(message)(Vg_UserMsg, "census: %d ms (took %d ms)", ms_time, 
                               VG_(read_millisecond_timer)() - ms_time );
   }
   ms_prev_census = ms_time;
   ms_next_census = ms_time + ms_interval;

   //VG_(printf)("Next: %d ms\n", ms_next_census);
} 

/*------------------------------------------------------------*/
/*--- Tracked events                                       ---*/
/*------------------------------------------------------------*/

static void new_mem_stack_signal(Addr a, SizeT len)
{
   sigstacks_szB += len;
}

static void die_mem_stack_signal(Addr a, SizeT len)
{
   tl_assert(sigstacks_szB >= len);
   sigstacks_szB -= len;
}

/*------------------------------------------------------------*/
/*--- Client Requests                                      ---*/
/*------------------------------------------------------------*/

static Bool ms_handle_client_request ( ThreadId tid, UWord* argv, UWord* ret )
{
   switch (argv[0]) {
   case VG_USERREQ__MALLOCLIKE_BLOCK: {
      void* res;
      void* p         = (void*)argv[1];
      SizeT sizeB     =        argv[2];
      *ret            = 0;
      res = new_block( tid, p, sizeB, /*align--ignored*/0, /*is_zeroed*/False );
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

/*------------------------------------------------------------*/
/*--- Instrumentation                                      ---*/
/*------------------------------------------------------------*/

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
      hp_census();
      is_first_SB = False;
   }

   return bb_in;
}

/*------------------------------------------------------------*/
/*--- Writing the graph file                               ---*/
/*------------------------------------------------------------*/

#if 0
static Char* make_filename(Char* dir, Char* suffix)
{
   Char* filename;

   /* Block is big enough for dir name + massif.<pid>.<suffix> */
   filename = VG_(malloc)((VG_(strlen)(dir) + 32)*sizeof(Char));
   VG_(sprintf)(filename, "%s/massif.%d%s", dir, VG_(getpid)(), suffix);

   return filename;
}

// Make string acceptable to hp2ps (sigh): remove spaces, escape parentheses.
static Char* clean_fnname(Char *d, Char* s)
{
   Char* dorig = d;
   while (*s) {
      if      (' ' == *s) { *d   = '%';            }
      else if ('(' == *s) { *d++ = '\\'; *d = '('; }
      else if (')' == *s) { *d++ = '\\'; *d = ')'; }
      else                { *d   = *s;             };
      s++;
      d++;
   }
   *d = '\0';
   return dorig;
}

static void file_err ( Char* file )
{
   VG_(message)(Vg_UserMsg, "error: can't open output file '%s'", file );
   VG_(message)(Vg_UserMsg, "       ... so profile results will be missing.");
}
#endif

#define P   VG_(printf)

static void write_text_graph(void)
{
   Int    i /*,j*/;
   Int    x, y;         // y must be signed!
   Int end_ms_time;
   Char unit;
   Int orders_of_magnitude;
   SizeT peak_census_total_szScaled;


   // XXX: unhardwire the sizes later
   #define GRAPH_X   72
   #define GRAPH_Y   20

   // The ASCII graph.
   // Row    0 ([0..GRAPH_X][0]) is the x-axis.
   // Column 0 ([0][0..GRAPH_Y]) is the y-axis.
   // The rest ([1][1]..[GRAPH_X][GRAPH_Y]) is the usable graph area.
   Char graph[GRAPH_X+1][GRAPH_Y+1];

   // Setup the graph
   graph[0][0] = '+';                     // axes join point
   for (x = 1; x <= GRAPH_X; x++) {       // x-axis
      graph[x][0] = '-';
   }
   for (y = 1; y <= GRAPH_Y; y++) {       // y-axis
      graph[0][y] = '|';
   }
   for (x = 1; x <= GRAPH_X; x++) {       // usable area
      for (y = 1; y <= GRAPH_Y; y++) {
         graph[x][y] = ' ';
      }
   }

   // We increment end_ms_time by 1 so that the last census occurs just
   // before it, and doesn't spill over into the final column.
   tl_assert(curr_census > 0);
   end_ms_time = censi[curr_census-1].ms_time + 1;
   tl_assert(end_ms_time > 0);
   tl_assert(peak_census_total_szB > 0);
   P("end time = %d ms\n", end_ms_time);
   P("peak census total szB = %ld B\n", peak_census_total_szB);

   // Header, including command line
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

   // Censi
   for (i = 0; i < curr_census; i++) {
      Census* census = & censi[i];

      // Work out how many bytes each row represents.
      double per_row_full_thresh_szB = (double)peak_census_total_szB / GRAPH_Y;
      double per_row_half_thresh_szB = per_row_full_thresh_szB / 2;

      // Work out which column this census belongs to.
      double bar_x_pos_frac = ((double)census->ms_time / end_ms_time) * GRAPH_X;
      int    bar_x_pos      = (int)bar_x_pos_frac + 1;    // +1 due to y-axis
      // XXX: why is the 0 one not getting drawn?
      P("n: %d\n", bar_x_pos);
      tl_assert(1 <= bar_x_pos && bar_x_pos <= GRAPH_X);

      // Grow this census bar from bottom to top.
      for (y = 1; y <= GRAPH_Y; y++) {
         double this_row_full_thresh_szB = y * per_row_full_thresh_szB;
         double this_row_half_thresh_szB =
            this_row_full_thresh_szB - per_row_half_thresh_szB;

         graph[bar_x_pos][y] = ' ';
         if (census->total_szB >= this_row_half_thresh_szB)
            graph[bar_x_pos][y] = '.';
         if (census->total_szB >= this_row_full_thresh_szB)
            graph[bar_x_pos][y] = ':';
      }
   }

   orders_of_magnitude = 0;
   peak_census_total_szScaled = peak_census_total_szB;
   while (peak_census_total_szScaled > 1000) {
      orders_of_magnitude++;
      peak_census_total_szScaled /= 1000;
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

   // Print graph
   P("-- start graph --\n");
   for (y = GRAPH_Y; y >= 0; y--) {
      // Row prefix
      if (GRAPH_Y == y)                // top point
         P("%3lu%c", peak_census_total_szScaled, unit);
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
}

/*------------------------------------------------------------*/
/*--- Writing the output                                   ---*/
/*------------------------------------------------------------*/

#if 0
static void percentify(Int n, Int pow, Int field_width, char xbuf[])
{
   int i, len, space;

   VG_(sprintf)(xbuf, "%d.%d%%", n / pow, n % pow);
   len = VG_(strlen)(xbuf);
   space = field_width - len;
   if (space < 0) space = 0;     /* Allow for v. small field_width */
   i = len;

   /* Right justify in field */
   for (     ; i >= 0;    i--)  xbuf[i + space] = xbuf[i];
   for (i = 0; i < space; i++)  xbuf[i] = ' ';
}
#endif

// Nb: uses a static buffer, each call trashes the last string returned.
static Char* make_perc(ULong x, ULong y)
{
   static Char mbuf[32];
   
// XXX: I'm not confident that VG_(percentify) works as it should...
   VG_(percentify)(x, y, 1, 5, mbuf); 
   // XXX: this is bogus if the denominator was zero -- resulting string is
   // something like "0 --%")
   if (' ' == mbuf[0]) mbuf[0] = '0';
   return mbuf;
}

#if 0
// Nb: passed in XPt is a lower-level XPt;  IPs are grabbed from
// bottom-to-top of XCon, and then printed in the reverse order.
static UInt pp_XCon(XPt* xpt)
{
   Addr  rev_ips[clo_depth+1];
   Int   i = 0;
   Int   n = 0;

   tl_assert(NULL != xpt);

   while (True) {
      rev_ips[i] = xpt->ip;
      n++;
      if (alloc_xpt == xpt->parent) break;
      i++;
      xpt = xpt->parent;
   }

   for (i = n-1; i >= 0; i--) {
      // -1 means point to calling line
      VG_(describe_IP)(rev_ips[i]-1, buf2, BUF_LEN);
      P("  %s\n", buf2);
   }

   return n;
}
#endif

// Does the xpt account for >= 1% of total memory used?
// XXX: make command-line controllable?
static Bool is_significant_XPt(XPt* xpt, SizeT curr_total_szB)
{
   return (xpt->curr_szB * 1000 / curr_total_szB >= 10);   // < 1%?
}

static void pp_snapshot_child_XPts(XPt* parent, Int depth, Char* depth_str,
                                   Int depth_str_len,
                                   SizeT curr_heap_szB, SizeT curr_total_szB)
{
   Int   i;
   XPt*  child;
   Bool  child_is_last_sibling;
   Char* ip_desc, *perc;

   // XXX: don't want to see 0xFFFFFFFE entries
   
   // Check that the sum of all children's sizes equals the parent's size.
   SizeT children_sum_szB = 0;
   for (i = 0; i < parent->n_children; i++) {
      children_sum_szB += parent->children[i]->curr_szB;
   }
   tl_assert(children_sum_szB == parent->curr_szB);

   // Sort children by curr_szB (reverse order:  biggest to smallest)
   // XXX: is it better to keep them always in order?
   // XXX: or, don't keep them in order, inspect all of them, but sort
   //      the selected ones in the queue when they're added.
   VG_(ssort)(parent->children, parent->n_children, sizeof(XPt*),
              XPt_revcmp_curr_szB);

   // Show all children that account for > 1% of current total szB.
   for (i = 0; i < parent->n_children; i++) {
      child = parent->children[i];

      child_is_last_sibling = ( i+1 == parent->n_children ? True : False );
   
      // Indent appropriately
      P("%s", depth_str);
      if (is_significant_XPt(child, curr_total_szB)) {
         // This child is significant.  Print it.
         perc = make_perc(child->curr_szB, curr_total_szB);
         ip_desc = VG_(describe_IP)(child->ip-1, buf2, BUF_LEN);
         P("->%6s: %s\n", perc, ip_desc);

         // If the child has any children, print them.  But first add the
         // prefix for them, which is "  " if the parent has no smaller
         // siblings following, or "| " if it does.
         tl_assert(depth*2+1 < depth_str_len-1);   // -1 for end NUL char
         if (child_is_last_sibling) {
            depth_str[depth*2+0] = ' ';
            depth_str[depth*2+1] = ' ';
            depth_str[depth*2+2] = '\0';
         } else {
            depth_str[depth*2+0] = '|';
            depth_str[depth*2+1] = ' ';
            depth_str[depth*2+2] = '\0';
         }
         if (child->n_children > 0 &&
            // XXX: horrible -- need to totally overhaul below-main checking,
            // do it in m_stacktrace.c.  [Ah, but we don't know the function
            // names at that point, just the IPs...]
            !VG_(strstr)(ip_desc, " main (")
#             if defined(VGO_linux)
              && !VG_(strstr)(ip_desc, "__libc_start_main")  // glibc glibness
              && !VG_(strstr)(ip_desc, "generic_start_main") // Yellow Dog doggedness
#             endif
            ) 
         {
            pp_snapshot_child_XPts(child, depth+1, depth_str, depth_str_len,
               curr_heap_szB, curr_total_szB);
         } else {
            // Reached the bottom of an XCon, print a blank (modulo
            // indentation lines) line.
            P("%s\n", depth_str);
         }
         // Undo the indentation.
         depth_str[depth*2+0] = '\0';
         depth_str[depth*2+1] = '\0';
         depth_str[depth*2+2] = '\0';

      } else {
         // This child is insignificant, as are all those remaining.
         // Don't bother with them.
         UInt  n_insig = parent->n_children - i;
         Char* s       = ( n_insig == 1 ? "" : "s" );
         Char* other   = ( 0 == i ? "" : "other " );
         P("->the rest in %d %sinsignificant place%s\n", n_insig, other, s);
         P("%s\n", depth_str);
         return;
      }
   }
}

static void pp_snapshot(SizeT curr_heap_szB,   SizeT curr_heap_admin_szB,
                        SizeT curr_stacks_szB, SizeT curr_total_szB)
{
   Int  depth_str_len = clo_depth * 2 + 2;
   Char* depth_str = VG_(malloc)(sizeof(Char) * depth_str_len);
   depth_str[0] = '\0';    // Initialise to "".
   
   P("=================================\n");
   P("== snapshot\n");
   P("=================================\n");
   P("Total memory usage: %,12lu bytes\n", curr_total_szB);
   P("Useful heap usage : %,12lu bytes (%s)\n",
      curr_heap_szB,       make_perc(curr_heap_szB, curr_total_szB));
   P("Admin  heap usage : %,12lu bytes (%s)\n",
      curr_heap_admin_szB, make_perc(curr_heap_admin_szB, curr_total_szB));
   P("Stacks usage      : %,12lu bytes (%s)\n",
      curr_stacks_szB,     make_perc(curr_stacks_szB, curr_total_szB));

   if (0 == curr_heap_szB) {
      P("(No heap memory currently allocated)\n");
   } else {
      P("Heap tree:\n");
      P("%6s: (heap allocation functions) malloc, new, new[], etc.\n",
         make_perc(curr_heap_szB, curr_total_szB));

      pp_snapshot_child_XPts(alloc_xpt, 0, depth_str, depth_str_len,
                             curr_heap_szB, curr_total_szB);
   }

   P("\n");
   VG_(free)(depth_str);
}

/*------------------------------------------------------------*/
/*--- Finalisation                                         ---*/
/*------------------------------------------------------------*/

static void ms_fini(Int exit_status)
{
   // Do a final (empty) sample to show program's end
   hp_census();

   // Output.
   write_text_graph();
}

/*------------------------------------------------------------*/
/*--- Initialisation                                       ---*/
/*------------------------------------------------------------*/

static void ms_post_clo_init(void)
{
   Int i;
   if (VG_(clo_verbosity) > 1) {
      VG_(message)(Vg_DebugMsg, "alloc-fns:");
      for (i = 0; i < n_alloc_fns; i++) {
         VG_(message)(Vg_DebugMsg, "  %d: %s", i, alloc_fns[i]);
      }
   }
   
   ms_interval = 1;

   // We don't take a census now, because there's still some core
   // initialisation to do, in which case we have an artificial gap.
   // Instead we do it when the first translation occurs.  See
   // ms_instrument().
}

static void ms_pre_clo_init(void)
{ 
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
   alloc_xpt = new_XPt(0, NULL, /*is_bottom*/False);

   tl_assert( VG_(getcwd)(base_dir, VKI_PATH_MAX) );
}

VG_DETERMINE_INTERFACE_VERSION(ms_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/


