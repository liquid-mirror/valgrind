
/*--------------------------------------------------------------------*/
/*--- Function replacement and wrapping.                 m_redir.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2000-2005 Julian Seward 
      jseward@acm.org
   Copyright (C) 2003-2005 Jeremy Fitzhardinge
      jeremy@goop.org

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
#include "pub_core_debuglog.h"
#include "pub_core_debuginfo.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcprint.h"
#include "pub_core_mallocfree.h"
#include "pub_core_options.h"
#include "pub_core_oset.h"
#include "pub_core_redir.h"
#include "pub_core_trampoline.h"
#include "pub_core_transtab.h"
#include "pub_core_tooliface.h"    // VG_(needs).malloc_replacement
#include "pub_core_aspacemgr.h"    // VG_(am_find_nsegment)

/*------------------------------------------------------------*/
/*--- Semantics                                            ---*/
/*------------------------------------------------------------*/

/* The redirector holds two pieces of state:

     Specs  - a set of   (soname pattern, fnname pattern) -> redir addr
     Active - a set of   orig addr -> redir addr

   Active is the currently active set of bindings that the translator
   consults.  Specs is the current set of specifications as harvested
   from reading symbol tables of the currently loaded objects.

   Active is a pure function of Specs and the current symbol table
   state (maintained by m_debuginfo).  Call the latter SyminfoState.

   Therefore whenever either Specs or SyminfoState changes, Active
   must be recomputed.  [Inefficient if done naively, but this is a
   spec].

   Active is computed as follows:

      Active = empty
      for spec in Specs {
         sopatt = spec.soname pattern
         fnpatt = spec.fnname pattern
         redir  = spec.redir addr
         for so matching sopatt in SyminfoState {
            for fn matching fnpatt in fnnames_of(so) {
               &fn -> redir is added to Active
            }
         }
      }

   [as an implementation detail, when a binding (orig -> redir) is
   deleted from Active as a result of recomputing it, then all
   translations intersecting redir must be deleted.  However, this is
   not part of the spec].

   [Active also depends on where the aspacemgr has decided to put all
   the pieces of code -- that affects the "orig addr" and "redir addr"
   values.]

   ---------------------

   That completes the spec, apart from one difficult issue: duplicates.

   Clearly we must impose the requirement that domain(Active) contains
   no duplicates.  The difficulty is how to constrain Specs enough to
   avoid getting into that situation.  It's easy to write specs which
   could cause conflicting bindings in Active, eg:

      (libpthread.so, pthread_mutex_lock) ->    a1
      (libpthread.so, pthread_*)          ->    a2

   for a1 != a2.  Or even hairier:

      (libpthread.so, pthread_mutex_*) ->    a1
      (libpthread.so, pthread_*_lock)  ->    a2

   I can't think of any sane way of detecting when an addition to
   Specs would generate conflicts.  However, considering we don't
   actually want to have a system that allows this, I propose this:
   all changes to Specs are acceptable.  But, when recomputing Active
   following the change, if the same orig is bound to more than one
   redir, then all bindings for orig are thrown out (of Active) and a
   warning message printed.  That's pretty much what we have at
   present anyway (warning, but no throwout; instead just keep the
   first).

   ===========================================================
   ===========================================================
   Incremental implementation:

   When a new SegInfo appears:
   - it may be the source of new specs
   - it may be the source of new matches for existing specs
   Therefore:

   - (new Specs x existing SegInfos): scan all symbols in the new 
     SegInfo to find new specs.  Each of these needs to be compared 
     against all symbols in all the existing SegInfos to generate 
     new actives.
     
   - (existing Specs x new SegInfo): scan all symbols in the SegInfo,
     trying to match them to any existing specs, also generating
     new actives.

   - (new Specs x new SegInfo): scan all symbols in the new SegInfo,
     trying to match them against the new specs, to generate new
     actives.

   - Finally, add new new specs to the current set of specs.

   When adding a new active (s,d) to the Actives:
     lookup s in Actives
        if already bound to d, ignore
        if already bound to something other than d, complain loudly and ignore
        else add (s,d) to Actives
             and discard (s,1) and (d,1)  (maybe overly conservative)

   When a SegInfo disappears:
   - delete all specs acquired from the seginfo
   - delete all actives derived from the just-deleted specs
   - if each active (s,d) deleted, discard (s,1) and (d,1)
*/

#define TRACE_REDIR(format, args...) \
   if (VG_(clo_trace_redir)) { VG_(message)(Vg_DebugMsg, format, ## args); }

static void*  symtab_alloc(SizeT);
static void   symtab_free(void*);
static HChar* symtab_strdup(HChar*);
static Bool   is_plausible_guest_addr(Addr);

/*------------------------------------------------------------*/
/*--- REDIRECTION SPECIFICATIONS                           ---*/
/*------------------------------------------------------------*/

/* A specification of a redirection we want to do.  Note that because
   both the "from" soname and function name may contain wildcards, the
   spec can match an arbitrary number of times. */
typedef
   struct _Spec {
      struct _Spec* next;       /* linked list */
      HChar*      from_sopatt;  /* from soname pattern  */
      const Char* from_fnpatt;  /* from fnname pattern  */
      Addr        to_addr;      /* where redirecting to */
      Bool        mark; /* transient temporary used during matching */
   }
   Spec;

/* Top-level data structure.  It contains a pointer to a SegInfo and
   also a list of the specs harvested from that SegInfo.  Note that
   seginfo is allowed to be NULL, meaning that the specs are
   pre-loaded ones at startup and are not associated with any
   particular seginfo. */
typedef
   struct _TopSpec {
      struct _TopSpec* next; /* linked list */
      SegInfo* seginfo; /* symbols etc */
      Spec*    specs;   /* specs pulled out of seginfo */
      Bool     mark; /* transient temporary used during deletion */
   }
   TopSpec;

/* This is the top level list of redirections.  m_debuginfo maintains
   a list of SegInfos, and the idea here is to maintain a list with
   the same number of elements (in fact, with one more element, so as
   to record abovementioned preloaded specifications.) */
static TopSpec* topSpecs = NULL;


/*------------------------------------------------------------*/
/*--- CURRENTLY ACTIVE REDIRECTIONS                        ---*/
/*------------------------------------------------------------*/

/* Represents a currently active binding.  If either parent_spec or
   parent_sym is NULL, then this binding was hardwired at startup and
   should not be deleted.  Same is true if either parent's seginfo
   field is NULL. */
typedef
   struct {
      Addr     from_addr;   /* old addr -- MUST BE THE FIRST WORD! */
      Addr     to_addr;     /* where redirecting to */
      TopSpec* parent_spec; /* the TopSpec which supplied the Spec */
      TopSpec* parent_sym;  /* the TopSpec which supplied the symbol */
   }
   Active;

/* The active set is a fast lookup table */
static OSet* activeSet = NULL;

static void maybe_add_active ( Active /*by value; callee copies*/ );


/*------------------------------------------------------------*/
/*--- NOTIFICATIONS                                        ---*/
/*------------------------------------------------------------*/

static 
void generate_and_add_actives ( 
        /* spec list and the owning TopSpec */
        Spec*    specs, 
        TopSpec* parent_spec,
	/* seginfo and the owning TopSpec */
        SegInfo* si,
        TopSpec* parent_sym 
     );

/* Notify m_redir of the arrival of a new SegInfo.  This is fairly
   complex, but the net effect is to (1) add a new entry to the
   topspecs list, and (2) figure out what new binding are now active,
   and, as a result, add them to the actives mapping. */

#define N_DEMANGLED 256

void VG_(redir_notify_new_SegInfo)( SegInfo* newsi )
{
   Bool     ok;
   Int      i, nsyms;
   Spec*    specList;
   Spec*    spec;
   TopSpec* ts;
   TopSpec* newts;
   HChar*   sym_name;
   Addr     sym_addr;
   HChar    demangled_sopatt[N_DEMANGLED];
   HChar    demangled_fnpatt[N_DEMANGLED];

   vg_assert(newsi);

   /* stay sane: we don't already have this. */
   for (ts = topSpecs; ts; ts = ts->next)
      vg_assert(ts->seginfo != newsi);

   /* scan this SegInfo's symbol table, pulling out and demangling
      any specs found */

   specList = NULL; /* the spec list we're building up */

   nsyms = VG_(seginfo_syms_howmany)( newsi );
   for (i = 0; i < nsyms; i++) {
      VG_(seginfo_syms_getidx)( newsi, i, &sym_addr, NULL, &sym_name );
      ok = VG_(maybe_Z_demangle)( sym_name, demangled_sopatt, N_DEMANGLED,
				  demangled_fnpatt, N_DEMANGLED );
      if (!ok) continue;
      spec = symtab_alloc(sizeof(Spec));
      vg_assert(spec);
      spec->from_sopatt = symtab_strdup(demangled_sopatt);
      spec->from_fnpatt = symtab_strdup(demangled_fnpatt);
      vg_assert(spec->from_sopatt);
      vg_assert(spec->from_fnpatt);
      spec->to_addr = sym_addr;
      /* check we're not adding manifestly stupid destinations */
      vg_assert(is_plausible_guest_addr(sym_addr));
      spec->next = specList;
      spec->mark = False; /* not significant */
      specList = spec;
   }

   /* Ok.  Now specList holds the list of specs from the SegInfo. 
      Build a new TopSpec, but don't add it to topSpecs yet. */
   newts = symtab_alloc(sizeof(TopSpec));
   vg_assert(newts);
   newts->next    = NULL; /* not significant */
   newts->seginfo = newsi;
   newts->specs   = specList;
   newts->mark    = False; /* not significant */

   /* We now need to augment the active set with the following partial
      cross product:

      (1) actives formed by matching the new specs in specList against
          all symbols currently listed in topSpecs

      (2) actives formed by matching the new symbols in newsi against
          all specs currently listed in topSpecs

      (3) actives formed by matching the new symbols in newsi against
          the new specs in specList

      This is necessary in order to maintain the invariant that
      Actives contains all bindings generated by matching ALL specs in
      topSpecs against ALL symbols in topSpecs (that is, a cross
      product of ALL known specs against ALL known symbols).
   */
   /* Case (1) */
   for (ts = topSpecs; ts; ts = ts->next) {
      if (ts->seginfo)
         generate_and_add_actives( specList,    newts,
                                   ts->seginfo, ts );
   }
	
   /* Case (2) */
   for (ts = topSpecs; ts; ts = ts->next) {
      generate_and_add_actives( ts->specs, ts, 
                                newsi,     newts );
   }

   /* Case (3) */
   generate_and_add_actives( specList, newts, 
                             newsi,    newts );

   /* Finally, add the new TopSpec. */
   newts->next = topSpecs;
   topSpecs = newts;
}

#undef N_DEMANGLED


/* Do one element of the basic cross product: add to the active set,
   all matches resulting from comparing all the given specs against
   all the symbols in the given seginfo.  If a conflicting binding
   would thereby arise, don't add it, but do complain. */

static 
void generate_and_add_actives ( 
        /* spec list and the owning TopSpec */
        Spec*    specs, 
        TopSpec* parent_spec,
	/* seginfo and the owning TopSpec */
        SegInfo* si,
        TopSpec* parent_sym 
     )
{
   Spec*  sp;
   Bool   anyMark;
   Active act;
   Int    nsyms, i;
   Addr   sym_addr;
   HChar* sym_name;

   /* First figure out which of the specs match the seginfo's
      soname. */
   anyMark = False;
   for (sp = specs; sp; sp = sp->next) {
      sp->mark = VG_(string_match)( sp->from_sopatt, 
                                    VG_(seginfo_soname)(si) );
      anyMark = anyMark || sp->mark;
   }

   /* shortcut: if none of the sonames match, there will be no bindings. */
   if (!anyMark)
      return;

   /* Iterate outermost over the symbols in the seginfo, in the hope
      of trashing the caches less. */
   nsyms = VG_(seginfo_syms_howmany)( si );
   for (i = 0; i < nsyms; i++) {
      VG_(seginfo_syms_getidx)( si, i, &sym_addr, NULL, &sym_name );
      for (sp = specs; sp; sp = sp->next) {
         if (!sp->mark)
            continue; /* soname doesn't match */
         if (VG_(string_match)( sp->from_fnpatt, sym_name )) {
            /* got a new binding.  Add to collection. */
            act.from_addr   = sym_addr;
            act.to_addr     = sp->to_addr;
            act.parent_spec = parent_spec;
            act.parent_sym  = parent_sym;
            maybe_add_active( act );
         }
      }
   }
}


/* Add an act (passed by value; is copied here) and deal with
   conflicting bindings. */
static void maybe_add_active ( Active act )
{
   Active* old = VG_(OSet_Lookup)( activeSet, &act.from_addr );
   if (old) {
      /* Dodgy.  Conflicting binding. */
      vg_assert(old->from_addr == act.from_addr);
      if (old->to_addr != act.to_addr) {
         /* COMPLAIN */
         /* we have to ignore it -- otherwise activeSet would contain
            conflicting bindings. */
      } else {
         /* This appears to be a duplicate of an existing binding.
            Safe(ish) -- ignore. */
         /* COMPLAIN if new and old parents differ */
      }
   } else {
      Active* a = VG_(OSet_AllocNode)(activeSet, sizeof(Active));
      vg_assert(a);
      *a = act;
      VG_(OSet_Insert)(activeSet, a);
   }
}


/* Notify m_redir of the deletion of a SegInfo.  This is relatively
   simple -- just get rid of all actives derived from it, and free up
   the associated list elements. */

void VG_(redir_notify_delete_SegInfo)( SegInfo* delsi )
{
   TopSpec* ts;
   OSet*    tmpSet;
   Active*  act;
   Bool     delMe;
   Addr*    addrP;

   vg_assert(delsi);

   /* Search for it. */
   for (ts = topSpecs; ts; ts = ts->next)
      if (ts->seginfo == delsi)
         break;

   vg_assert(ts); /* else we don't have the deleted SegInfo */

   /* Traverse the actives, copying the addresses of those we intend
      to delete into tmpSet. */
   tmpSet = VG_(OSet_Create)( 0/*keyOff*/, NULL/*fastCmp*/,
                              symtab_alloc, symtab_free);

   ts->mark = True;

   VG_(OSet_ResetIter)( activeSet );
   while ( (act = VG_(OSet_Next)(activeSet)) ) {
      delMe = act->parent_spec != NULL
              && act->parent_sym != NULL
              && act->parent_spec->seginfo != NULL
              && act->parent_sym->seginfo != NULL
              && (act->parent_spec->mark || act->parent_sym->mark);
      if (delMe) {
         addrP = VG_(OSet_AllocNode)( tmpSet, sizeof(Addr) );
         *addrP = act->from_addr;
         VG_(OSet_Insert)( tmpSet, addrP );
      }
   }

   /* Now traverse tmpSet, deleting corresponding elements in
      activeSet. */
   VG_(OSet_ResetIter)( tmpSet );
   while ( (addrP = VG_(OSet_Next)(tmpSet)) ) {
      VG_(OSet_Remove)( activeSet, addrP );
      VG_(OSet_FreeNode)( activeSet, addrP );
   }

   VG_(OSet_Destroy)( tmpSet );
}


/*------------------------------------------------------------*/
/*--- QUERIES (really the whole point of this module)      ---*/
/*------------------------------------------------------------*/

/* This is the crucial redirection function.  It answers the question:
   should this code address be redirected somewhere else?  It's used
   just before translating a basic block. */
Addr VG_(redir_do_lookup) ( Addr orig )
{
   Spec* r = VG_(OSet_Lookup)(activeSet, &orig);
   if (r == NULL)
      return orig;

   vg_assert(r->to_addr != 0);
   return r->to_addr;
}


/*------------------------------------------------------------*/
/*--- INITIALISATION                                       ---*/
/*------------------------------------------------------------*/

/* Add a never-delete-me Active. */

__attribute__((unused)) /* only used on amd64 */
static void add_hardwired_active ( Addr from, Addr to )
{
   Active act;
   act.from_addr   = from;
   act.to_addr     = to;
   act.parent_spec = NULL;
   act.parent_sym  = NULL;
   maybe_add_active( act );
}


/* Add a never-delete-me Spec.  This is a bit of a kludge.  On the
   assumption that this is called only at startup, only handle the
   case where topSpecs is completely empty, or if it isn't, it has
   just one entry and that is the one with NULL seginfo -- that is the
   entry that holds these initial specs. */

__attribute__((unused)) /* not used on all platforms */
static void add_hardwired_spec ( HChar* sopatt, HChar* fnpatt, Addr to_addr )
{
   Spec* spec = symtab_alloc(sizeof(Spec));
   vg_assert(spec);

   if (topSpecs == NULL) {
      topSpecs = symtab_alloc(sizeof(TopSpec));
      vg_assert(topSpecs);
      topSpecs->next    = NULL;
      topSpecs->seginfo = NULL;
      topSpecs->specs   = NULL;
      topSpecs->mark    = False;
   }

   vg_assert(topSpecs != NULL);
   vg_assert(topSpecs->next == NULL);
   vg_assert(topSpecs->seginfo == NULL);

   spec->from_sopatt = sopatt;
   spec->from_fnpatt = fnpatt;
   spec->to_addr     = to_addr;
   spec->mark        = False; /* not significant */

   spec->next = topSpecs->specs;
   topSpecs->specs = spec;
}


/* Initialise the redir system, and create the initial Spec list and
   for amd64-linux a couple of permanent active mappings.  The initial
   Specs are not converted into Actives yet, on the (checked)
   assumption that no SegInfos have so far been created, and so when
   they are created, that will happen. */

void VG_(redir_initialise) ( void )
{
   // Assert that there are no SegInfos so far
   vg_assert( VG_(next_seginfo)(NULL) == NULL );

   // Initialise active mapping.
   activeSet = VG_(OSet_Create)(offsetof(Active, from_addr),
                                NULL,     // Use fast comparison
                                symtab_alloc,
                                symtab_free);

   // The rest of this function just adds initial Specs.   

#  if defined(VGP_x86_linux)
   /* Redirect _dl_sysinfo_int80, which is glibc's default system call
      routine, to our copy so that the special sysinfo unwind hack in
      m_stacktrace.c will kick in. */
   add_hardwired_spec(
      "ld-linux.so.2", "_dl_sysinfo_int80",
      (Addr)&VG_(x86_linux_REDIR_FOR__dl_sysinfo_int80) 
   );
   /* If we're using memcheck, use this intercept right from the
      start, otherwise ld.so (glibc-2.3.5) makes a lot of noise. */
   if (0==VG_(strcmp)("Memcheck", VG_(details).name)) {
      add_hardwired_spec(
         "ld-linux.so.2", "index",
          (Addr)&VG_(x86_linux_REDIR_FOR_index)
      );
   }

#  elif defined(VGP_amd64_linux)
   /* Redirect vsyscalls to local versions */
   add_hardwired_active(
      0xFFFFFFFFFF600000ULL,
      (Addr)&VG_(amd64_linux_REDIR_FOR_vgettimeofday) 
   );
   add_hardwired_active( 
      0xFFFFFFFFFF600400ULL,
      (Addr)&VG_(amd64_linux_REDIR_FOR_vtime) 
   );

#  elif defined(VGP_ppc32_linux)
   /* If we're using memcheck, use these intercepts right from
      the start, otherwise ld.so makes a lot of noise. */
   if (0==VG_(strcmp)("Memcheck", VG_(details).name)) {
      add_hardwired_spec(
         "ld.so.1", "strlen",
          (Addr)&VG_(ppc32_linux_REDIR_FOR_strlen),
      );   
      add_hardwired_spec(
         "soname:ld.so.1", "strcmp",
         (Addr)&VG_(ppc32_linux_REDIR_FOR_strcmp),
      );
   }

#  elif defined(VGP_ppc64_linux)
   // we'll have to stick some godawful hacks in here, no doubt

#  else
#    error Unknown platform
#  endif
}


//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////

static void* symtab_alloc(SizeT n)
{
   return VG_(arena_malloc)(VG_AR_SYMTAB, n);
}

static void symtab_free(void* p)
{
   return VG_(arena_free)(VG_AR_SYMTAB, p);
}

static HChar* symtab_strdup(HChar* str)
{
   return VG_(arena_strdup)(VG_AR_SYMTAB, str);
}

/* Really this should be merged with  translations_allowable_from_seg
   in m_translate. */
static Bool is_plausible_guest_addr(Addr a)
{
   NSegment* seg = VG_(am_find_nsegment)(a);
   return seg != NULL
          && (seg->kind == SkAnonC || seg->kind == SkFileC)
          && (seg->hasX || seg->hasR); /* crude x86-specific hack */
}

//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////


// This is specifically for stringifying VG_(x) function names.  We
// need to do two macroexpansions to get the VG_ macro expanded before
// stringifying.
//zz #define _STR(x) #x
//zz #define STR(x)  _STR(x)
//zz 
//zz static void handle_load_notifier( Char* symbol, Addr addr )
//zz {
//zz    if (VG_(strcmp)(symbol, STR(VG_NOTIFY_ON_LOAD(freeres))) == 0)
//zz       VG_(client___libc_freeres_wrapper) = addr;
// else
// if (VG_(strcmp)(symbol, STR(VG_WRAPPER(pthread_startfunc_wrapper))) == 0)
//    VG_(pthread_startfunc_wrapper)((Addr)(si->offset + sym->st_value));
//zz    else
//zz       vg_assert2(0, "unrecognised load notification function: %s", symbol);
//zz }
//zz 
//zz static Bool is_replacement_function(Char* s)
//zz {
//zz    return (0 == VG_(strncmp)(s,
//zz                              VG_REPLACE_FUNCTION_PREFIX,
//zz                              VG_REPLACE_FUNCTION_PREFIX_LEN));
//zz }
//zz 
//zz static Bool is_load_notifier(Char* s)
//zz {
//zz    return (0 == VG_(strncmp)(s,
//zz                              VG_NOTIFY_ON_LOAD_PREFIX,
//zz                              VG_NOTIFY_ON_LOAD_PREFIX_LEN));
//zz }


/*------------------------------------------------------------*/
/*--- THE DEMANGLER                                        ---*/
/*------------------------------------------------------------*/

/* Demangle 'sym' into its soname and fnname parts, putting them in
   the specified buffers.  Returns a Bool indicating whether the
   demangled failed or not.  A failure can occur because the prefix
   isn't recognised, the internal Z-escaping is wrong, or because one
   or the other (or both) of the output buffers becomes full. */

Bool VG_(maybe_Z_demangle) ( const HChar* sym, 
                             /*OUT*/HChar* so, Int soLen,
                             /*OUT*/HChar* fn, Int fnLen )
{
#  define EMITSO(ch)                        \
      do {                                  \
         if (soi >= soLen) {                \
            so[soLen-1] = 0; oflow = True;  \
         } else {                           \
            so[soi++] = ch; so[soi] = 0;    \
         }                                  \
      } while (0)
#  define EMITFN(ch)                        \
      do {                                  \
         if (fni >= fnLen) {                \
            fn[fnLen-1] = 0; oflow = True;  \
         } else {                           \
            fn[fni++] = ch; fn[fni] = 0;    \
         }                                  \
      } while (0)

   Bool error, oflow, valid, fn_is_encoded;
   Int  soi, fni, i;

   vg_assert(soLen > 0);
   vg_assert(fnLen > 0);
   error = False;
   oflow = False;
   soi = 0;
   fni = 0;

   valid =     sym[0] == '_'
           &&  sym[1] == 'v'
           &&  sym[2] == 'g'
           && (sym[3] == 'r' || sym[3] == 'n')
           &&  sym[4] == 'Z'
           && (sym[5] == 'Z' || sym[5] == 'U')
           &&  sym[6] == '_';
   if (!valid)
      return False;

   fn_is_encoded = sym[5] == 'Z';

   /* Now scan the Z-encoded soname. */
   i = 7;
   while (True) {

      if (sym[i] == '_')
      /* Found the delimiter.  Move on to the fnname loop. */
         break;

      if (sym[i] == 0) {
         error = True;
         goto out;
      }

      if (sym[i] != 'Z') {
         EMITSO(sym[i]);
         i++;
         continue;
      }

      /* We've got a Z-escape. */
      i++;
      switch (sym[i]) {
         case 'a': EMITSO('*'); break;
         case 'p': EMITSO('+'); break;
         case 'c': EMITSO(':'); break;
         case 'd': EMITSO('.'); break;
         case 'u': EMITSO('_'); break;
         case 'h': EMITSO('-'); break;
         case 's': EMITSO(' '); break;
         case 'Z': EMITSO('Z'); break;
         case 'A': EMITSO('@'); break;
         default: error = True; goto out;
      }
      i++;
   }

   vg_assert(sym[i] == '_');
   i++;

   /* Now deal with the function name part. */
   if (!fn_is_encoded) {

      /* simple; just copy. */
      while (True) {
         if (sym[i] == 0)
            break;
         EMITFN(sym[i]);
         i++;
      }
      goto out;

   }

   /* else use a Z-decoding loop like with soname */
   while (True) {

      if (sym[i] == 0)
         break;

      if (sym[i] != 'Z') {
         EMITFN(sym[i]);
         i++;
         continue;
      }

      /* We've got a Z-escape. */
      i++;
      switch (sym[i]) {
         case 'a': EMITFN('*'); break;
         case 'p': EMITFN('+'); break;
         case 'c': EMITFN(':'); break;
         case 'd': EMITFN('.'); break;
         case 'u': EMITFN('_'); break;
         case 'h': EMITFN('-'); break;
         case 's': EMITFN(' '); break;
         case 'Z': EMITFN('Z'); break;
         case 'A': EMITFN('@'); break;
         default: error = True; goto out;
      }
      i++;
   }

  out:
   EMITSO(0);
   EMITFN(0);

   if (error) {
      /* Something's wrong.  Give up. */
      VG_(message)(Vg_UserMsg, "m_redir: error demangling: %s", sym);
      return False;
   }
   if (oflow) {
      /* It didn't fit.  Give up. */
      VG_(message)(Vg_UserMsg, "m_debuginfo: oflow demangling: %s", sym);
      return False;
   }

   return True;
}


/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
