
/*--------------------------------------------------------------------*/
/*--- Dynamic invariant inference and checking.                    ---*/
/*---                                                  vg_diduce.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, an x86 protected-mode emulator 
   designed for debugging and profiling binaries on x86-Unixes.

   Copyright (C) 2002 Nicholas Nethercote
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

   The GNU General Public License is contained in the file LICENSE.
*/

#include "vg_include.h"

/* According to IA-32 Intel Architecture Software Developer's Manual: Vol 2 */
#define MAX_x86_INSTR_SIZE              16

/* Size of various buffers used for storing strings */

/* XXX check and clean these up */
#define FILENAME_LEN                    256
#define FN_NAME_LEN                     256
#define BUF_LEN                         512
#define COMMIFY_BUF_LEN                 128
#define RESULTS_BUF_LEN                 128
#define LINE_BUF_LEN                    128

#define BB_MARKER                       "BB "

/*------------------------------------------------------------*/
/*--- Output file related stuff                            ---*/
/*------------------------------------------------------------*/

#define  IN_FILE        "diduce.in"
#define OUT_FILE        "diduce.out"

static void file_err()
{
   VG_(message)(Vg_UserMsg,
                "error: can't open invariants output file `%s'",
                OUT_FILE );
   VG_(exit)(1);
}

/*------------------------------------------------------------*/
/*--- Invariant types, operations                          ---*/
/*------------------------------------------------------------*/

typedef enum { INV1, INV2 } CC_type;

/* WARNING: the 'tag' field must be in same place for both types, since we
 * distinguish different invariants using it. */
struct _invariant1 {
   UChar tag;           /* Word 1  */
   UChar opcode;
   UChar data_size;

   Addr instr_addr;     /* Words 2+ */
   UInt accesses;
   UInt V;
   UInt M;
};

struct _invariant2 {
   UChar tag;           /* Words 1  */
   UChar opcode;
   UChar data_size;
   
   Addr instr_addr;     /* Words 2+ */
   UInt accesses;
   UInt V1, M1;
   UInt V2, M2;
};

static void init_invariant1(UChar opcode, invariant1* inv, Addr instr_addr, 
                            UInt data_size)
{
   inv->tag        = INV1;
   inv->opcode     = opcode;
   inv->data_size  = data_size;

   inv->instr_addr = instr_addr;
   inv->accesses   = 0;
   inv->V          = 0;
   inv->M          = 0xffffffff;
}

static void init_invariant2(UChar opcode, invariant2* inv, Addr instr_addr, 
                            UInt data_size)
{
   inv->tag        = INV2;
   inv->opcode     = opcode;
   inv->data_size  = data_size;

   inv->instr_addr = instr_addr;
   inv->accesses   = 0;
   inv->V1         = inv->V2 = 0;
   inv->M1         = inv->M2 = 0xffffffff;
}

static __inline__ void sprint_invariant1(Char buf[], invariant1* inv)
{
   VG_(sprintf)(buf, "%x %u %u %u %x %x\n",
                      inv->instr_addr, inv->opcode, inv->data_size, 
                      inv->accesses, inv->V, inv->M);
}

static __inline__ void sprint_invariant2(Char buf[], invariant2* inv)
{
   VG_(sprintf)(buf, "%x %u %u %u %x %x %x %x\n",
                      inv->instr_addr, inv->opcode, inv->data_size, 
                      inv->accesses, inv->V1, inv->M1, inv->M2, inv->V2);
}

/*------------------------------------------------------------*/
/*--- BBinvs hash table stuff                                ---*/
/*------------------------------------------------------------*/

#define N_ENTRIES        19997

/* The cost centres for a basic block are stored in a contiguous array.
 * They are distinguishable by their tag field. */
typedef struct _BBinvs BBinvs;
struct _BBinvs {
   Addr  orig_addr;
   UInt  array_size;    /* byte-size of variable length array */
   BBinvs* next;
   Addr  array[0];      /* variable length array */
};

/* BBinvs_table structure:  list(filename, list(fn_name, list(BBinvs))) */
static BBinvs *BBinvs_table[N_ENTRIES];

//static Int  distinct_files      = 0;
//static Int  distinct_fns        = 0;

static Int  distinct_invs       = 0;
static Int  full_debug_BBs      = 0;
static Int  file_line_debug_BBs = 0;
static Int  fn_name_debug_BBs   = 0;
static Int  no_debug_BBs        = 0;

static Int  BB_retranslations   = 0;

static void init_BBinvs_table()
{
   Int i;
   for (i = 0; i < N_ENTRIES; i++)
      BBinvs_table[i] = NULL;
}

static void get_debug_info(Addr instr_addr, Char filename[FILENAME_LEN],
                           Char fn_name[FN_NAME_LEN], Int* line_num)
{
   Bool found1, found2, no_demangle = False;

   found1 = VG_(what_line_is_this)(instr_addr, filename,
                                   FILENAME_LEN, line_num);
   found2 = VG_(what_fn_is_this)(no_demangle, instr_addr, fn_name, FN_NAME_LEN);

   if (!found1 && !found2) {
      no_debug_BBs++;
      VG_(strcpy)(filename, "???");
      VG_(strcpy)(fn_name,  "???");
      *line_num = 0;

   } else if ( found1 &&  found2) {
      full_debug_BBs++;

   } else if ( found1 && !found2) {
      file_line_debug_BBs++;
      VG_(strcpy)(fn_name,  "???");

   } else  /*(!found1 &&  found2)*/ {
      fn_name_debug_BBs++;
      VG_(strcpy)(filename, "???");
      *line_num = 0;
   }
}

/* Forward declaration. */
static Int compute_BBinvs_array_size(UCodeBlock* cb, Addr orig_addr);

/* If no invariants needed for block, return NULL */
static __inline__ 
BBinvs* new_BBinvs(Addr bb_orig_addr, UCodeBlock* cb, BBinvs* next)
{
   Int BBinvs_array_size = compute_BBinvs_array_size(cb, bb_orig_addr);
   BBinvs* new;

   if (0 == BBinvs_array_size) return NULL;

   new = (BBinvs*)VG_(malloc)(VG_AR_PRIVATE, sizeof(BBinvs) + BBinvs_array_size);
   new->orig_addr  = bb_orig_addr;
   new->array_size = BBinvs_array_size;
   new->next = next;

   return new;
}

#define HASH_CONSTANT   256

//static UInt hash(Char *s, UInt table_size)
//{
//    int hash_value = 0;
//    for ( ; *s; s++)
//        hash_value = (HASH_CONSTANT * hash_value + *s) % table_size;
//    return hash_value;
//}

/* Prepends new nodes to their chain.  Returns a pointer to the cost centre (or
 * NULL if no instructions have invariants).  Also sets BB_seen_before by
 * reference. 
 */ 
static __inline__ BBinvs* get_BBinvs(Addr bb_orig_addr, UCodeBlock* cb, 
                                 Bool remove, Bool *BB_seen_before)
{
   BBinvs   **prev_next_ptr, *curr;
   UInt       pos;

   pos = bb_orig_addr % N_ENTRIES;
   prev_next_ptr = &(BBinvs_table[pos]);
   curr = BBinvs_table[pos];
   while (NULL != curr && bb_orig_addr != curr->orig_addr) {
      prev_next_ptr = &(curr->next);
      curr = curr->next;
   }
   if (NULL == curr) {
      vg_assert(False == remove);
      *BB_seen_before = False;
      curr = new_BBinvs(bb_orig_addr, cb, BBinvs_table[pos]);
      if (NULL == curr) 
          return NULL;
      BBinvs_table[pos] = curr;

   } else {
      vg_assert(bb_orig_addr == curr->orig_addr);
      vg_assert(curr->array_size > 0 && curr->array_size < 1000000);
      if (VG_(clo_verbosity) > 2) {
          VG_(message)(Vg_DebugMsg, 
            "BB retranslation or loaded from training file");
      }
      *BB_seen_before = True;

      // XXX: this will screw up removals of self-modifying code because BBinvs
      // can be put in the table from the diduce.in file without having
      // encountered and translated the code block.

      if (True == remove) {
          // Remove curr from chain;  it will be used and free'd by the
          // caller.
          *prev_next_ptr = curr->next;

      } else {
          BB_retranslations++;
      }
   }
   VGP_POPCC;
   return curr;
}

/*------------------------------------------------------------*/
/*--- Invariant detection/checking instrumentation phase   ---*/
/*------------------------------------------------------------*/

#define uInstr1   VG_(newUInstr1)
#define uInstr2   VG_(newUInstr2)
#define uInstr3   VG_(newUInstr3)
#define dis       VG_(disassemble)
#define uLiteral  VG_(setLiteralField)
#define newTemp   VG_(getNewTemp)

static __inline__ Bool is_crud(Addr instr_addr)
{
   Char fl[FILENAME_LEN], fn[FN_NAME_LEN];
   Int line_num = 0;
#if 0
   Int res;

   /* One way of avoiding crud -- only print if a source file in current
    * directory.  Means you must be in the current directory, though. */
   if (-1 != (res = VG_(open_read)(fl))) {
       VG_(close)(res);
       return 0;
   } else {
       return 1;
   }
#endif
   get_debug_info(instr_addr, fl, fn, &line_num);

   return (
           0 == VG_(strcmp)(fl, "???"                           ) ||
           0 == VG_(strcmp)(fn, "???"                           ) ||
           0 == VG_(strcmp)(fl, "do-lookup.h"                   ) ||
           0 == VG_(strcmp)(fl, "dl-lookup.c"                   ) ||
           0 == VG_(strcmp)(fl, "dl-runtime.c"                  ) ||
           0 == VG_(strcmp)(fl, "dl-init.c"                     ) ||
           0 == VG_(strcmp)(fl, "dl-fini.c"                     ) ||
           0 == VG_(strcmp)(fl, "dl-debug.c"                    ) ||
           0 == VG_(strcmp)(fl, "cxa_atexit.c"                  ) ||
           0 == VG_(strcmp)(fl, "exit.c"                        ) ||
           0 == VG_(strcmp)(fl, "genops.c"                      ) ||
           0 == VG_(strcmp)(fl, "getopt_init.c"                 ) ||
           0 == VG_(strcmp)(fn, "set_progname"                  ) ||
           0 == VG_(strcmp)(fn, "fixup"                         ) ||
           0 == VG_(strcmp)(fn, "__libc_init"                   ) ||
           0 == VG_(strcmp)(fn, "_dl_runtime_resolve"           ) ||
           0 == VG_(strcmp)(fn, "_dl_lookup_versioned_symbol"   ) ||
           0 == VG_(strcmp)(fn, "__getopt_clean_environment"    ) ||
           0 == VG_(strcmp)(fn, "__deregister_frame_info"       ) ||
           False);
}

static __inline__ Bool is_ok_unary_op(UInstr *u, Addr instr_addr)
{
    Bool ok1, ok2;
   
    ok1  = (FlagsEmpty != u->flags_w && (
            INC   == u->opcode ||
            DEC   == u->opcode ||
            NOT   == u->opcode ||
            NEG   == u->opcode ||
            BSWAP == u->opcode ||
            WIDEN == u->opcode ||
            False)  /* just allows easy commenting out of lines */
           );

    ok2 = !is_crud(instr_addr);

    return (ok1 && ok2);
}

static __inline__ Bool is_ok_binary_op(UInstr *u, Addr instr_addr)
{
    Bool ok1, ok2;
   
    ok1  =  (FlagsEmpty != u->flags_w && (
            //ADD   == u->opcode ||
            //ADC   == u->opcode ||
            SUB   == u->opcode ||
            //AND   == u->opcode ||
            //OR    == u->opcode ||
            //XOR   == u->opcode ||
            //SBB   == u->opcode ||
            //SHL   == u->opcode ||
            //SHR   == u->opcode ||
            //SAR   == u->opcode ||
            //ROL   == u->opcode ||
            //ROR   == u->opcode ||
            //RCL   == u->opcode ||
            //RCR   == u->opcode ||
            False)  /* just allows easy commenting out of lines */
           );

    ok2 = !is_crud(instr_addr);

    return (ok1 && ok2);
}

static Int compute_BBinvs_array_size(UCodeBlock* cb, Addr orig_addr)
{
   Int  i, BBinvs_size = 0;
   Addr instr_addr = orig_addr;

   for (i = 0; i < cb->used; i++) {
      UInstr* u = &cb->instrs[i];
      
      if (INCEIP == u->opcode) {
         instr_addr += u->val1;

      } else if (JMP == u->opcode) {
         /* This will be zero when necessary... works itself out */
         instr_addr += u->extra4b;
      
      } else if (is_ok_unary_op(u, instr_addr)) {
         BBinvs_size += sizeof(invariant1);

      } else if (is_ok_binary_op(u, instr_addr)) {
         BBinvs_size += sizeof(invariant2);
      }
   }

   return BBinvs_size;
}

/* Use this rather than eg. -1 because it's stored as a UInt. */
#define INVALID_DATA_SIZE   999999

UCodeBlock* VG_(diduce_instrument)(UCodeBlock* cb_in, Addr orig_addr)
{
   UCodeBlock* cb;
   Int         i;
   UInstr*     u_in;
   BBinvs*       BBinvs_node;
   Int         t_CC_addr, t_2nd_addr;
   Addr        instr_addr = orig_addr;
   UInt        instr_size = INVALID_DATA_SIZE;
   Int         helper = -1;     /* Shut gcc warnings up */
   UInt        stack_used;
   Bool        BB_seen_before       = False;
   Bool        prev_instr_was_Jcond = False;

   Addr        BBinvs_ptr0, BBinvs_ptr; 

   /* Get BBinvs (creating if necessary -- requires a counting pass over the BB
    * if it's the first time it's been seen), and point to start of the 
    * BBinvs array.  If no instructions need invariants for the basic block,
    * skip instrumentation also (by returning cb unchanged). */
   BBinvs_node = get_BBinvs(orig_addr, cb_in, False, &BB_seen_before);
   if (NULL == BBinvs_node) {
       return cb_in;
   }
   BBinvs_ptr0 = BBinvs_ptr = (Addr)(BBinvs_node->array);

   cb = VG_(allocCodeBlock)();
   cb->nextTemp = cb_in->nextTemp;

   t_CC_addr = t_2nd_addr = INVALID_TEMPREG;

   for (i = 0; i < cb_in->used; i++) {
      u_in = &cb_in->instrs[i];

      //VG_(ppUInstr)(0, u_in);

      /* What this is all about:  we want to instrument each x86 instruction 
       * translation.  The end of these are marked in three ways.  The three
       * ways, and the way we instrument them, are as follows:
       *
       * 1. UCode, INCEIP         --> UCode, Instrumentation, INCEIP
       * 2. UCode, Juncond        --> UCode, Instrumentation, Juncond
       * 3. UCode, Jcond, Juncond --> UCode, Instrumentation, Jcond, Juncond
       *
       * We must put the instrumentation before the jumps so that it is always
       * executed.  We don't have to put the instrumentation before the INCEIP
       * (it could go after) but we do so for consistency.
       *
       * Junconds are always the last instruction in a basic block.  Jconds are
       * always the 2nd last, and must be followed by a Jcond.  We check this
       * with various assertions.
       *
       * Note that in VG_(disBB) we patched the `extra4b' field of the first
       * occurring JMP in a block with the size of its x86 instruction.  This
       * is used now.
       *
       * Note that we don't have to treat JIFZ specially;  unlike JMPs, JIFZ
       * occurs in the middle of a BB and gets an INCEIP after it.
       */
      if (prev_instr_was_Jcond) vg_assert(u_in->opcode == JMP);

      if (INCEIP == u_in->opcode) {
            instr_size = u_in->val1;
            goto case_for_end_of_x86_instr;

      } else if (JMP == u_in->opcode) {
            if (u_in->cond == CondAlways) {
               vg_assert(i+1 == cb_in->used); 

               /* Don't instrument if previous instr was a Jcond. */
               if (prev_instr_was_Jcond) {
                  vg_assert(0 == u_in->extra4b);
                  VG_(copyUInstr)(cb, u_in);
                  goto end_case;
               }
               prev_instr_was_Jcond = False;

            } else {
               vg_assert(i+2 == cb_in->used);  /* 2nd last instr in block */
               prev_instr_was_Jcond = True;
            }
            /* Ah, the first JMP... */
            instr_size = u_in->extra4b;

            goto case_for_end_of_x86_instr;

           case_for_end_of_x86_instr:
            VG_(copyUInstr)(cb, u_in);
            instr_addr += instr_size;
            vg_assert(instr_size >= 1 && instr_size <= MAX_x86_INSTR_SIZE);
            vg_assert(0 != instr_addr);

           end_case:
            /* do nothing */

#define SAVE_REGS                               \
   uInstr1(cb, PUSH, 4, RealReg, R_EAX);        \
   /*uInstr1(cb, PUSH, 4, RealReg, R_ECX);*/        \
   /*uInstr1(cb, PUSH, 4, RealReg, R_EDX)*/

#define PUSH_3RD_ARG                            \
   uInstr1(cb, PUSH, 4, TempReg, u_in->val2);   \
   stack_used += 4

#define PUSH_2ND_AND_1ST_ARGS_CALL_HELPER_AND_RESTORE_REGS              \
   /*t_2nd_addr = newTemp(cb);                                          */  \
   /*if (TempReg == u_in->tag1) {                                       */  \
   /*   uInstr2(cb, MOV, 4, TempReg, u_in->val1, TempReg, t_2nd_addr);  */  \
   /*} else if (Literal == u_in->tag1) {                                */  \
   /*   uInstr2(cb, MOV,  4, Literal, 0, TempReg, t_2nd_addr);          */  \
   /*   uLiteral(cb, u_in->val1);                                       */  \
   /*} else if (ArchReg == u_in->tag1) {                                */  \
   /*   uInstr2(cb, GET,  4, ArchReg, u_in->val1, TempReg, t_2nd_addr); */  \
   /*} else {                                                           */  \
   /*   VG_(panic)("Unknown tag type!");                                */  \
   /*}                                                                  */  \
   /*uInstr1(cb, PUSH, 4, TempReg, t_2nd_addr);                         */  \
   /*stack_used += 4;                                                   */  \
   /*t_CC_addr = newTemp(cb);                  */                           \
   /*uInstr2(cb, MOV,  4, Literal, 0, TempReg, t_CC_addr);  */              \
   /*uLiteral(cb, BBinvs_ptr);               */                             \
   /*uInstr1(cb, PUSH, 4, TempReg, t_CC_addr);*/                            \
   /*stack_used += 4;*/                                                     \
   /*uInstr1(cb, CALLM, 0, Lit16,   helper);*/                            \
   uInstr1(cb, CLEAR, 0, Lit16,   stack_used);                          \
   /*uInstr1(cb, POP, 4, RealReg, R_EDX);*/                                 \
   /*uInstr1(cb, POP, 4, RealReg, R_ECX);*/                               \
   uInstr1(cb, POP, 4, RealReg, R_EAX)

      } else if (is_ok_binary_op(u_in, instr_addr)) {

            invariant2* CC_ptr = (invariant2*)(BBinvs_ptr);
            stack_used = 0;
            helper = VGOFF_(diduce_log_instr2);
            if (!BB_seen_before)
               init_invariant2(u_in->opcode, CC_ptr, instr_addr, u_in->size);
            SAVE_REGS;
            PUSH_3RD_ARG;
            PUSH_2ND_AND_1ST_ARGS_CALL_HELPER_AND_RESTORE_REGS;
            VG_(copyUInstr)(cb, u_in);
            BBinvs_ptr += sizeof(invariant2);

      } else if (is_ok_unary_op(u_in, instr_addr)) {

            invariant1* CC_ptr = (invariant1*)(BBinvs_ptr);
            stack_used = 0;
            helper = VGOFF_(diduce_log_instr1);
            if (!BB_seen_before)
               init_invariant1(u_in->opcode, CC_ptr, instr_addr, u_in->size);
            SAVE_REGS;
            PUSH_2ND_AND_1ST_ARGS_CALL_HELPER_AND_RESTORE_REGS;
            VG_(copyUInstr)(cb, u_in);
            BBinvs_ptr += sizeof(invariant1);

#undef SAVE_REGS
#undef PUSH_3RD_ARG
#undef PUSH_2ND_AND_1ST_ARGS_CALL_HELPER_AND_RESTORE_REGS

      } else if (NOP     == u_in->opcode ||
                 CALLM_E == u_in->opcode ||
                 CALLM_S == u_in->opcode) {
         /* do nothing */          

      } else {
            VG_(copyUInstr)(cb, u_in);
      }
   }

   /* Just check everything looks ok */
   vg_assert(BBinvs_ptr - BBinvs_ptr0 == BBinvs_node->array_size);
   //if (BBinvs_ptr - BBinvs_ptr0 != BBinvs_node->array_size) {
   //   VG_(printf)("%x %x diff is %x, should be %x\n", BBinvs_ptr, BBinvs_ptr0, BBinvs_ptr - BBinvs_ptr0, BBinvs_node->array_size);
   //   VG_(panic)("everything doesn't look ok!");
  // }

   VG_(freeCodeBlock)(cb_in);
   return cb;
}

//UCodeBlock* VG_(diduce_instrument)(UCodeBlock* cb_in, Addr orig_addr)
//{
//   UCodeBlock* cb;
//   Int         i;
//   UInstr*     u_in;
//   BBinvs*       BBinvs_node;
//   Int         t_CC_addr, t_read_addr, t_write_addr, t_data_addr;
//   Int         CC_size = -1;    /* Shut gcc warnings up */
//   Addr        instr_addr = orig_addr;
//   UInt        instr_size, data_size = INVALID_DATA_SIZE;
//   Int         helper = -1;     /* Shut gcc warnings up */
//   UInt        stack_used;
//   Bool        BB_seen_before       = False;
//   Bool        prev_instr_was_Jcond = False;
//   Addr        BBinvs_ptr0, BBinvs_ptr; 
//
//   /* Get BBinvs (creating if necessary -- requires a counting pass over the BB
//    * if it's the first time it's been seen), and point to start of the 
//    * BBinvs array.  */
//   BBinvs_node = get_BBinvs(orig_addr, cb_in, False, &BB_seen_before);
//   BBinvs_ptr0 = BBinvs_ptr = (Addr)(BBinvs_node->array);
//
//   cb = VG_(allocCodeBlock)();
//   cb->nextTemp = cb_in->nextTemp;
//
//   t_CC_addr = t_read_addr = t_write_addr = t_data_addr = INVALID_TEMPREG;
//
//   for (i = 0; i < cb_in->used; i++) {
//      u_in = &cb_in->instrs[i];
//
//      //VG_(ppUInstr)(0, u_in);
//
//      if (prev_instr_was_Jcond) vg_assert(u_in->opcode == JMP);
//
//      switch (u_in->opcode) {
//
//         case INCEIP:
//            instr_size = u_in->val1;
//            goto case_for_end_of_x86_instr;
//
//         case JMP:
//            if (u_in->cond == CondAlways) {
//               vg_assert(i+1 == cb_in->used); 
//
//               /* Don't instrument if previous instr was a Jcond. */
//               if (prev_instr_was_Jcond) {
//                  vg_assert(0 == u_in->extra4b);
//                  VG_(copyUInstr)(cb, u_in);
//                  break;
//               }
//               prev_instr_was_Jcond = False;
//
//            } else {
//               vg_assert(i+2 == cb_in->used);  /* 2nd last instr in block */
//               prev_instr_was_Jcond = True;
//            }
//
//            /* Ah, the first JMP... instrument, please. */
//            instr_size = u_in->extra4b;
//            goto case_for_end_of_x86_instr;
//
//            /* Shared code that is executed at the end of an x86 translation
//             * block, marked by either an INCEIP or an unconditional JMP. */
//            case_for_end_of_x86_instr:
//
//#define IS_(X)      (INVALID_TEMPREG != t_##X##_addr)
//             
//            /* Initialise the CC in the BBinvs array appropriately if it hasn't
//             * been initialised before.
//             * Then call appropriate sim function, passing it the CC address.
//             * Note that CALLM_S/CALL_E aren't required here;  by this point,
//             * the checking related to them has already happened. */
//            stack_used = 0;
//
//            vg_assert(instr_size >= 1 && instr_size <= MAX_x86_INSTR_SIZE);
//            vg_assert(0 != instr_addr);
//
//            CC_size = sizeof(invariant);
//            if (!IS_(read) && !IS_(write)) {
////               invariant* CC_ptr = (invariant*)(BBinvs_ptr);
//               vg_assert(INVALID_DATA_SIZE == data_size);
//               vg_assert(INVALID_TEMPREG == t_read_addr && 
//                         INVALID_TEMPREG == t_write_addr);
//#if 0
//               if (!BB_seen_before)
//                   init_invariant(CC_ptr, instr_addr, instr_size);
//
//               helper = VGOFF_(cachesim_log_non_mem_instr);
//#endif
//            } else { 
//               Bool is_write;
//               invariant* CC_ptr = (invariant*)(BBinvs_ptr);
//                
//               vg_assert(4 == data_size || 2  == data_size || 1 == data_size || 
//                         8 == data_size || 10 == data_size);
//               
//               //CC_size = sizeof(invariant);
//               helper = VGOFF_(diduce_log_instr);
//
//               if (IS_(read) && !IS_(write)) {
//                  is_write = False;
//                  vg_assert(INVALID_TEMPREG != t_read_addr && 
//                            INVALID_TEMPREG == t_write_addr);
//                  t_data_addr = t_read_addr;
//
//               } else if (!IS_(read) && IS_(write)) {
//                  is_write = True;
//                  vg_assert(INVALID_TEMPREG == t_read_addr && 
//                            INVALID_TEMPREG != t_write_addr);
//                  t_data_addr = t_write_addr;
//
//               } else {
//                  vg_assert(IS_(read) && IS_(write));
//                  is_write = True;
//                  vg_assert(INVALID_TEMPREG != t_read_addr && 
//                            INVALID_TEMPREG != t_write_addr);
//                  t_data_addr = t_read_addr;
//               }
//
//               if (!BB_seen_before)
//                  init_invariant(is_write, CC_ptr, instr_addr, instr_size, data_size);
//
//               /* Save the caller-save registers before we push our args */
//               uInstr1(cb, PUSH, 4, RealReg, R_EAX);
//               uInstr1(cb, PUSH, 4, RealReg, R_ECX);
//               uInstr1(cb, PUSH, 4, RealReg, R_EDX);
//
//               /* 2nd arg: data addr */
//               uInstr1(cb, PUSH,  4, TempReg, t_data_addr);
//               stack_used += 4;
//
//               /* 1st arg: CC addr */
//               t_CC_addr = newTemp(cb);
//               uInstr2(cb, MOV,   4, Literal, 0, TempReg, t_CC_addr);
//               uLiteral(cb, BBinvs_ptr);
//               uInstr1(cb, PUSH,  4, TempReg, t_CC_addr);
//               stack_used += 4;
//
//               /* Call function and return. */
//               uInstr1(cb, CALLM, 0, Lit16,   helper);
//               uInstr1(cb, CLEAR, 0, Lit16,   stack_used);
//
//               /* Restore the caller-save registers now the call is done */
//               uInstr1(cb, POP, 4, RealReg, R_EDX);
//               uInstr1(cb, POP, 4, RealReg, R_ECX);
//               uInstr1(cb, POP, 4, RealReg, R_EAX);
//            }
//
//            VG_(copyUInstr)(cb, u_in);
//
//            /* Update BBinvs_ptr, EIP, de-init read/write temps for next instr */
//            BBinvs_ptr   += CC_size; 
//            instr_addr += instr_size;
//            t_CC_addr = t_read_addr = t_write_addr = 
//                                      t_data_addr  = INVALID_TEMPREG;
//            data_size = INVALID_DATA_SIZE;
//#undef IS_
//
//            break;
//
//
//         /* For memory-ref instrs, copy the data_addr into a temporary to be
//          * passed to the cachesim_log_function at the end of the instruction.
//          */
//         case LOAD: 
//            t_read_addr = newTemp(cb);
//            uInstr2(cb, MOV, 4, TempReg, u_in->val1,  TempReg, t_read_addr);
//            data_size = u_in->size;
//            VG_(copyUInstr)(cb, u_in);
//            break;
//
//         case FPU_R:
//            t_read_addr = newTemp(cb);
//            uInstr2(cb, MOV, 4, TempReg, u_in->val2,  TempReg, t_read_addr);
//            data_size = u_in->size;
//            VG_(copyUInstr)(cb, u_in);
//            break;
//
//         /* Note that we must set t_write_addr even for mod instructions;
//          * that's how the code above determines whether it does a write;
//          * without it, it would think a mod instruction is a read.
//          * As for the MOV, if it's a mod instruction it's redundant, but it's
//          * not expensive and mod instructions are rare anyway. */
//         case STORE:
//         case FPU_W:
//            t_write_addr = newTemp(cb);
//            uInstr2(cb, MOV, 4, TempReg, u_in->val2, TempReg, t_write_addr);
//            data_size = u_in->size;
//            VG_(copyUInstr)(cb, u_in);
//            break;
//
//         case NOP:  case CALLM_E:  case CALLM_S:
//            break;
//
//         default:
//            VG_(copyUInstr)(cb, u_in);
//            break;
//      }
//   }
//
//   /* Just check everything looks ok */
//   vg_assert(BBinvs_ptr - BBinvs_ptr0 == BBinvs_node->array_size);
//
//   VG_(freeCodeBlock)(cb_in);
//   return cb;
//}

/* Returns size of the invariant read into the space pointed to by blk */
static Int read_invariant_line ( Int fd, void* blk, Int line_num )
{
#define N_COMMON_PARTS  6
    
   Int   i, j;
   Int   nums[N_COMMON_PARTS];
   Char *l;
   Char  buf[LINE_BUF_LEN];
   invariant1* inv1;
   invariant2* inv2;

   Bool eof = VG_(getLine) ( fd, buf, LINE_BUF_LEN );
   if (eof) { 
      VG_(printf)("%d: unexpected end of file\n", line_num);
      VG_(exit)(1);
   }
   l = VG_(strdup)(VG_AR_PRIVATE, buf);

   /* Option looks like one of (ie. 6/8 fields for unary/binary op):
    *   "<addr> <opcode> <data_size> <occs> <V> <M>".
    *   "<addr> <opcode> <data_size> <occs> <V1> <M1> <V2> <M2>".
    * Find spaces, replace with NULs to make several independent 
    * strings, then extract numbers.  Yuck. */
   i = nums[0] = 0;
   for (j = 1; j < N_COMMON_PARTS; j++) {
       while (VG_(isxdigit)(l[i])) i++;
       if (' ' == l[i]) {
          l[i++] = '\0';
          nums[j] = i;
       } else goto bad;
   }
   while (VG_(isxdigit)(l[i])) i++;

   if ('\0' == l[i]) {
      /* only 6 present */
      inv1             = (invariant1*)blk;
      inv1->tag        = INV1;
      inv1->instr_addr = (UInt)VG_(atoll16)(l + nums[0]);
      inv1->opcode     = (UChar)VG_(atoll) (l + nums[1]);
      inv1->data_size  = (UChar)VG_(atoll) (l + nums[2]);
      inv1->accesses   = (UInt)VG_(atoll)  (l + nums[3]);
      inv1->V          = (UInt)VG_(atoll16)(l + nums[4]);
      inv1->M          = (UInt)VG_(atoll16)(l + nums[5]);

      vg_assert(1  == inv1->data_size || 2 == inv1->data_size ||
                4  == inv1->data_size || 8 == inv1->data_size ||
                10 == inv1->data_size);
      vg_assert(inv1->accesses > 0);

      //VG_(printf)("inv(%x): %s, %dB %dx (%x,%x)\n", 
      //        inv1->instr_addr,
      //        VG_(nameUOpcode)(False, inv1->opcode),
      //        inv1->data_size, inv1->accesses, inv1->V, inv1->M);
      VG_(printf)(".");
      return sizeof(invariant1);

   } else if (' ' == l[i]) {
      /* must be 8 present */
      l[i++] = '\0';
      nums[6] = i;
      while (VG_(isxdigit)(l[i])) i++;
      if (' ' == l[i]) {
         l[i++] = '\0';
         nums[7] = i;
      } else goto bad;
      while (VG_(isxdigit)(l[i])) i++;
      if ('\0' != l[i]) goto bad;

      inv2             = (invariant2*)blk;
      inv2->tag        = INV2;
      inv2->instr_addr = (UInt)VG_(atoll16)(l + nums[0]);
      inv2->opcode     = (UChar)VG_(atoll) (l + nums[1]);
      inv2->data_size  = (UChar)VG_(atoll) (l + nums[2]);
      inv2->accesses   = (UInt)VG_(atoll)  (l + nums[3]);
      inv2->V1         = (UInt)VG_(atoll16)(l + nums[4]);
      inv2->M1         = (UInt)VG_(atoll16)(l + nums[5]);
      inv2->V2         = (UInt)VG_(atoll16)(l + nums[6]);
      inv2->M2         = (UInt)VG_(atoll16)(l + nums[7]);

      vg_assert(1  == inv2->data_size || 2 == inv2->data_size ||
                4  == inv2->data_size || 8 == inv2->data_size ||
                10 == inv2->data_size);
      vg_assert(inv2->accesses > 0);

      //VG_(printf)("inv(%x): %s, %dB %dx (%x,%x)(%x,%x)\n", 
      //        inv2->instr_addr,
      //        VG_(nameUOpcode)(False, inv2->opcode),
      //        inv2->data_size, inv2->accesses, inv2->V1, inv2->M1,
      //        inv2->V2, inv2->M2);
      VG_(printf)(".");
      return sizeof(invariant2);

   } else goto bad;

bad:    
   VG_(printf)("%d: bad invariant line: '%s'\n", line_num, l);
   VG_(exit)(1);
}

static Bool read_BB_line(Int fd, Int* line_num)
{
   Bool eof;
   Char buf[LINE_BUF_LEN];
   Int i, i1, i2, j;
   Int array_size;
   BBinvs* new;
   UInt pos;
   
   eof = VG_(getLine) ( fd, buf, LINE_BUF_LEN );
   if (!eof) {
      if (0 == VG_(strncmp)(buf, BB_MARKER, VG_(strlen)(BB_MARKER))) {

         i = i1 = VG_(strlen)(BB_MARKER);

         (*line_num)++;         /* For the BB line */
         while (VG_(isxdigit)(buf[i])) i++;
         if (' ' == buf[i]) {
            buf[i++] = '\0';
            i2 = i; 
         } else goto bad;
         while (VG_(isxdigit)(buf[i])) i++;
         if ('\0' != buf[i]) goto bad;

         /* Nb: need array_size pre-malloc, but orig_addr can be set after */
         array_size = (UInt)VG_(atoll)(buf + i2);
         new = (BBinvs*)VG_(malloc)(VG_AR_PRIVATE, sizeof(BBinvs) + array_size);
         new->orig_addr  = (UInt)VG_(atoll16)(buf + i1);
         new->array_size = array_size;

         //VG_(printf)("Allocated BBinvs at %x(%x)\n", new, &(new->array[0]));

         j = 0;
         while (j < array_size) {
            //VG_(printf)("j = %x(%x)\n", j, &(new->array[j/sizeof(Addr)]));
            j += read_invariant_line(fd, (void*)&(new->array[j/sizeof(Addr)]), 
                                     *line_num);
            (*line_num)++;      /* For the invariant line */
         }

         /* Stick array in table, prepending to the relevant chain */
         pos = new->orig_addr % N_ENTRIES;
         new->next = BBinvs_table[pos];
         BBinvs_table[pos] = new;

         return True;
         
      } else {
         VG_(printf)("%d: bad line\n", *line_num);
         VG_(exit)(1);
      }

   } else {
       return False;
   }

bad:
   VG_(printf)("%d: bad BB line: '%s'\n", *line_num, buf);
   VG_(exit)(1);
}

/* Sticks any invariants found in file into BBinvs_table */
static void read_invariants_file(char *filename) {
   Int fd, eof, line_num = 1;
   Char buf[LINE_BUF_LEN];

   fd = VG_(open_read)( filename );
   if (fd == -1) {
      VG_(message)(Vg_UserMsg, 
                   "WARNING: can't open diduce training file `%s'", 
                   filename );
      return;
   }

   /* XXX: check if the current command is the same, warn if not 
    * (could even record executable name/timestamp/size for really careful
    * check?)
    */
   eof = VG_(getLine) ( fd, buf, LINE_BUF_LEN );
   if (eof || 0 != VG_(strncmp)("cmd: ", buf, 5)) {
      VG_(printf)("bad first line: '%s'\n", buf);
      VG_(exit)(1);
   }
   VG_(message)(Vg_UserMsg, "Training file %s is for cmd: '%s'", filename, buf+5);
   line_num++;

   while (read_BB_line(fd, &line_num)) { }

   VG_(close)(fd);
   return;
}

void VG_(init_diduce)(void)
{
   Int fd;

   init_BBinvs_table();
   read_invariants_file(IN_FILE);

   VG_(printf)("DIDUCE INIT (finished reading input file)\n");

   /* Make sure the output file can be written.  This zeroes the file, so must
    * happen after reading training file (in case reading doesn't work). */
   /* XXX: only do this when training */
   fd = VG_(open_write)(OUT_FILE);
   if (-1 == fd) { 
      fd = VG_(create_and_write)(OUT_FILE);
      if (-1 == fd) {
         file_err(); 
      }
   }
   VG_(close)(fd);
   //fprint_BBinvs_table_and_calc_totals(0, NULL);

}

static Int violations = 0;

static UInt num_of_zero_bits(UInt x) 
{
    Int i;
   UInt n = 0;

   for (i = 0; i < sizeof(UInt)*8; i++) {
      if (0 == (x & 0x1)) n++;
      x >>= 1;
   }

   return n;
}

/* 'which' indicates if it was a unary or binary op, and if binary, whether the
 * first or second arg caused the violation. */
static __inline__ 
void print_if_violation(Int which, Addr instr_addr, UInt old_mask, 
                        UInt M, UInt W, UInt accesses, UChar opcode) 
{
   Char fl_buf[FILENAME_LEN], fn_buf[FN_NAME_LEN];
   Int line_num         = 0;

   /* Use ULongs because (1 << 32) (which is possible) overflows a UInt.
    * The "ULL" suffix is necessary! */
   ULong range_of_values1 = (1ULL << num_of_zero_bits(old_mask));
   ULong range_of_values2 = (1ULL << num_of_zero_bits(M));
   double confidence1    =  accesses    / (double)range_of_values1;
   double confidence2    = (accesses+1) / (double)range_of_values2;

   get_debug_info(instr_addr, fl_buf, fn_buf, &line_num);

//VG_(printf)("a = %u, Mold = %x, M = %x, r1 = %llu, r2 = %llu\n", accesses, old_mask, M, range_of_values1, range_of_values2);

   if (confidence1 - confidence2 < 0) {
      VG_(printf)("confidence difference negative: c1=%llu, c2=%llu, diff=%llu  \n", (ULong)confidence1, (ULong)confidence2, (ULong)(confidence1 - confidence2));
      VG_(panic)("confidence difference negative");
   }
   
   if (confidence1 - confidence2 >= VG_(clo_confidence)) {
      VG_(printf)("V%3d(%s-%d): conf loss %d, count %d, values %llu, "
                  "vbits %d->%d, value 0x%x at %s:%s:%d (%x)\n", 
                  violations, 
                  VG_(nameUOpcode)(False, opcode), which,
                  (Int)(confidence1 - confidence2),
                  accesses+1, range_of_values2,
                  num_of_zero_bits(old_mask), 
                  num_of_zero_bits(M), 
                  W,
                  fl_buf, fn_buf, line_num,
                  instr_addr);
      violations++;
   }
}

#if 0
static jmp_buf sigsegv_jmpbuf;

static
void SIGSEGV_handler(int signum)
{
   __builtin_longjmp(sigsegv_jmpbuf, 1);
}
#endif

void VG_(diduce_log_instr1)(invariant1* inv, UInt arg2)
{
   UInt x, W;

#if 0
   /* Install own SIGSEGV handler */
   Int res = 0;
   vki_ksigaction sigsegv_new, sigsegv_saved;
   sigsegv_new.ksa_handler  = SIGSEGV_handler;
   sigsegv_new.ksa_flags    = 0;
   sigsegv_new.ksa_restorer = NULL;
   res = VG_(ksigemptyset)( &sigsegv_new.ksa_mask );
   vg_assert(res == 0);
   res = VG_(ksigaction)( VKI_SIGSEGV, &sigsegv_new, &sigsegv_saved );
   vg_assert(res == 0);
   if (__builtin_setjmp(sigsegv_jmpbuf) == 0) {

      switch (inv->data_size) {
         case 1:  W = *(UChar*) data_addr;  break;
         case 2:  W = *(UShort*)data_addr;  break;
         case 4: case 8: case 10:
                  W = *(UInt*)  data_addr;  break;
         default: VG_(printf)("inv->data_size = %u\n", inv->data_size);
                  VG_(panic)("inv->data_size not 1, 2, 4, 8 or 10");
      }

      /* Restore old SIGILL handler */
      res = VG_(ksigaction)( VKI_SIGSEGV, &sigsegv_saved, NULL );
      vg_assert(res == 0);

   } else  {
      VG_(printf)("SEGMENTATION FAULT!!!: (%c) data_addr=%x, data_size=%u", 
            (inv->is_write ? 'w' : 'r'), data_addr, inv->data_size);
      get_debug_info(inv->instr_addr, fl_buf, fn_buf, &line_num);
      VG_(printf)(" at %s:%s:%d (%x)\n",  fl_buf, fn_buf, line_num, inv->instr_addr);
      /* Restore old SIGILL handler */
      res = VG_(ksigaction)( VKI_SIGSEGV, &sigsegv_saved, NULL );
      vg_assert(res == 0);
      W = 999;
   }
#endif
   
   switch (inv->data_size) {
      case 1:  W = (UChar) arg2;  break;
      case 2:  W = (UShort)arg2;  break;
      case 4: case 8: case 10:
               W = (UInt)  arg2;  break;
      default: VG_(printf)("inv->data_size = %u\n", inv->data_size);
               VG_(panic)("inv->data_size(1) not 1, 2, 4, 8 or 10");
   }

   if (0 != inv->accesses) {
      x = inv->V ^ W;

      if (0 != (x & inv->M)) {
         UInt old_mask = inv->M;
         inv->M &= ~x;            /* Relax invariant */
         print_if_violation(0, inv->instr_addr, old_mask, inv->M, W, 
                            inv->accesses, inv->opcode);
      }

   } else {
      inv->V = W;
   }
   inv->accesses++;
}

void VG_(diduce_log_instr2)(invariant2* inv, Addr arg2, UInt arg3)
{
   UInt x1, x2;
   UInt W1, W2;
   UInt old_mask;
   
   switch (inv->data_size) {
      case 1:  W1 = (UChar) arg2; W2 = (UChar) arg3; break;
      case 2:  W1 = (UShort)arg2; W2 = (UShort)arg3; break;
      case 4: case 8: case 10:
               W1 = (UInt)  arg2; W2 = (UShort)arg3; break;
      default: VG_(printf)("---\ninv->data_size = %u\n", inv->data_size);
               VG_(printf)("address = %x\n", inv);
               VG_(printf)("inv(%x): %d, %dB %dx (%x,%x)(%x,%x)\n", 
               inv->instr_addr, inv->opcode, inv->data_size, inv->accesses, 
               inv->V1, inv->M1, inv->V2, inv->M2);

               VG_(panic)("inv->data_size(2) not 1, 2, 4, 8 or 10");
   }

   if (0 != inv->accesses) {
      x1 = inv->V1 ^ W1;
      x2 = inv->V2 ^ W2;

      if (0 != (x1 & inv->M1)) {
         old_mask = inv->M1;
         inv->M1 &= ~x1;            /* Relax invariant */
         print_if_violation(1, inv->instr_addr, old_mask, inv->M1, W1,
                            inv->accesses, inv->opcode);
      }
      if (0 != (x2 & inv->M2)) {
         old_mask = inv->M2;
         inv->M2 &= ~x2;            /* Relax invariant */
         print_if_violation(2, inv->instr_addr, old_mask, inv->M2, W2,
                            inv->accesses, inv->opcode);
      }

   } else {
      inv->V1 = W1;
      inv->V2 = W2;
   }
   inv->accesses++;
}

/*------------------------------------------------------------*/
/*--- Printing of output file and summary stats            ---*/
/*------------------------------------------------------------*/

static void fprint_BBinvs(Int fd, BBinvs* BBinvs_node)
{
   Addr BBinvs_ptr0, BBinvs_ptr;
   Char buf[LINE_BUF_LEN];     

   BBinvs_ptr0 = BBinvs_ptr = (Addr)(BBinvs_node->array);

   /* Mark start of basic block in output, just to ease debugging */
   VG_(sprintf)(buf, "%s%x %d\n", BB_MARKER, BBinvs_node->orig_addr, 
                                             BBinvs_node->array_size);
   VG_(write)(fd, (void*)buf, VG_(strlen)(buf));  

   while (BBinvs_ptr - BBinvs_ptr0 < BBinvs_node->array_size) {

      /* We pretend the invariant is an invariant1 for getting the tag.  This
       * is ok because both invariant types have tag as their first byte.  Once
       * we know the type, we can cast and act appropriately. */

      //Char fl_buf[FILENAME_LEN];
      //Char fn_buf[FN_NAME_LEN];

      Addr instr_addr;
      switch ( ((invariant1*)BBinvs_ptr)->tag ) {

         case INV1:
            instr_addr = ((invariant1*)BBinvs_ptr)->instr_addr;
            sprint_invariant1(buf, (invariant1*)BBinvs_ptr);
            BBinvs_ptr += sizeof(invariant1);
            break;

         case INV2:
            instr_addr = ((invariant2*)BBinvs_ptr)->instr_addr;
            sprint_invariant2(buf, (invariant2*)BBinvs_ptr);
            BBinvs_ptr += sizeof(invariant2);
            break;

         default:
            VG_(panic)("Unknown invariant type in fprint_BBinvs()\n");
            break;
      }
      VG_(write)(fd, (void*)buf, VG_(strlen)(buf));

      distinct_invs++;
   }
#if 0
      get_debug_info(instr_addr, fl_buf, fn_buf, &line_num);

      /* Allow for filename switching in the middle of a BB;  if this happens,
       * must print the new filename with the function name. */
      if (0 != VG_(strcmp)(fl_buf, curr_file)) {
         VG_(strcpy)(curr_file, fl_buf);
         VG_(sprintf)(fbuf, "fi=%s\n", curr_file);
         VG_(write)(fd, (void*)fbuf, VG_(strlen)(fbuf));
      }

      /* If the function name for this instruction doesn't match that of the
       * first instruction in the BB, print warning. */
      if (VG_(clo_trace_symtab) && 0 != VG_(strcmp)(fn_buf, first_instr_fn)) {
         VG_(printf)("Mismatched function names\n");
         VG_(printf)("  filenames: BB:%s, instr:%s;"
                     "  fn_names:  BB:%s, instr:%s;"
                     "  line: %d\n", 
                     first_instr_fl, fl_buf, 
                     first_instr_fn, fn_buf, 
                     line_num);
      }

      VG_(sprintf)(lbuf, "%u ", line_num);
      VG_(write)(fd, (void*)lbuf, VG_(strlen)(lbuf));   /* line number */
      VG_(write)(fd, (void*)buf, VG_(strlen)(buf));     /* cost centre */
   }
   /* If we switched filenames in the middle of the BB without switching back,
    * switch back now because the subsequent BB may be relying on falling under
    * the original file name. */
   if (0 != VG_(strcmp)(first_instr_fl, curr_file)) {
      VG_(sprintf)(fbuf, "fe=%s\n", first_instr_fl);
      VG_(write)(fd, (void*)fbuf, VG_(strlen)(fbuf));
   }

   /* Mark end of basic block */
   /* VG_(write)(fd, (void*)"#}\n", 3); */
#endif

   vg_assert(BBinvs_ptr - BBinvs_ptr0 == BBinvs_node->array_size);
}

static void fprint_BBinvs_table_and_calc_totals(Int client_argc, 
                                              Char** client_argv)
{
   Int        fd;
   Char       buf[BUF_LEN];
   BBinvs    *curr;
   Int        i;

   VGP_PUSHCC(VgpCacheDump);
   fd = VG_(open_write)(OUT_FILE);
   if (-1 == fd) { file_err(); }

   /* "cmd:" line */
   VG_(strcpy)(buf, "cmd:");
   VG_(write)(fd, (void*)buf, VG_(strlen)(buf));
   for (i = 0; i < client_argc; i++) {
       VG_(sprintf)(buf, " %s", client_argv[i]);
       VG_(write)(fd, (void*)buf, VG_(strlen)(buf));
   }
   VG_(sprintf)(buf, "\n");
   VG_(write)(fd, (void*)buf, VG_(strlen)(buf));

   /* Invariants, printed flat */
   for (i = 0; i < N_ENTRIES; i++) {
      curr = BBinvs_table[i];
      while (curr != NULL) {
         fprint_BBinvs(fd, curr);
         curr = curr->next;
      }
   }
   VG_(close)(fd);
}

void VG_(do_diduce_results)(Int client_argc, Char** client_argv)
{
   VG_(printf)("DIDUCE RESULTS\n");
#if 0
   CC D_total;
   ULong L2_total_m, L2_total_mr, L2_total_mw,
         L2_total, L2_total_r, L2_total_w;
   char buf1[RESULTS_BUF_LEN], 
        buf2[RESULTS_BUF_LEN], 
        buf3[RESULTS_BUF_LEN];
   Int l1, l2, l3;
   Int p;
#endif
   fprint_BBinvs_table_and_calc_totals(client_argc, client_argv);
#if 0
   if (VG_(clo_verbosity) == 0) 
      return;

   /* I cache results.  Use the I_refs value to determine the first column
    * width. */
   l1 = commify(Ir_total.a, 0, buf1);
   VG_(message)(Vg_UserMsg, "I   refs:      %s", buf1);

   commify(Ir_total.m1, l1, buf1);
   VG_(message)(Vg_UserMsg, "I1  misses:    %s", buf1);

   commify(Ir_total.m2, l1, buf1);
   VG_(message)(Vg_UserMsg, "L2i misses:    %s", buf1);

   p = 100;

   percentify(Ir_total.m1 * 100 * p / Ir_total.a, p, l1+1, buf1);
   VG_(message)(Vg_UserMsg, "I1  miss rate: %s", buf1);
                
   percentify(Ir_total.m2 * 100 * p / Ir_total.a, p, l1+1, buf1);
   VG_(message)(Vg_UserMsg, "L2i miss rate: %s", buf1);
   VG_(message)(Vg_UserMsg, "");

   /* D cache results.  Use the D_refs.rd and D_refs.wr values to determine the
    * width of columns 2 & 3. */
   D_total.a  = Dr_total.a  + Dw_total.a;
   D_total.m1 = Dr_total.m1 + Dw_total.m1;
   D_total.m2 = Dr_total.m2 + Dw_total.m2;
       
        commify( D_total.a, l1, buf1);
   l2 = commify(Dr_total.a, 0,  buf2);
   l3 = commify(Dw_total.a, 0,  buf3);
   VG_(message)(Vg_UserMsg, "D   refs:      %s  (%s rd + %s wr)",
                buf1,  buf2,  buf3);

   commify( D_total.m1, l1, buf1);
   commify(Dr_total.m1, l2, buf2);
   commify(Dw_total.m1, l3, buf3);
   VG_(message)(Vg_UserMsg, "D1  misses:    %s  (%s rd + %s wr)",
                buf1, buf2, buf3);

   commify( D_total.m2, l1, buf1);
   commify(Dr_total.m2, l2, buf2);
   commify(Dw_total.m2, l3, buf3);
   VG_(message)(Vg_UserMsg, "L2d misses:    %s  (%s rd + %s wr)",
                buf1, buf2, buf3);

   p = 10;
   
   percentify( D_total.m1 * 100 * p / D_total.a,  p, l1+1, buf1);
   percentify(Dr_total.m1 * 100 * p / Dr_total.a, p, l2+1, buf2);
   percentify(Dw_total.m1 * 100 * p / Dw_total.a, p, l3+1, buf3);
   VG_(message)(Vg_UserMsg, "D1  miss rate: %s (%s   + %s  )", buf1, buf2,buf3);

   percentify( D_total.m2 * 100 * p / D_total.a,  p, l1+1, buf1);
   percentify(Dr_total.m2 * 100 * p / Dr_total.a, p, l2+1, buf2);
   percentify(Dw_total.m2 * 100 * p / Dw_total.a, p, l3+1, buf3);
   VG_(message)(Vg_UserMsg, "L2d miss rate: %s (%s   + %s  )", buf1, buf2,buf3);
   VG_(message)(Vg_UserMsg, "");

   /* L2 overall results */

   L2_total   = Dr_total.m1 + Dw_total.m1 + Ir_total.m1;
   L2_total_r = Dr_total.m1 + Ir_total.m1;
   L2_total_w = Dw_total.m1;
   commify(L2_total,   l1, buf1);
   commify(L2_total_r, l2, buf2);
   commify(L2_total_w, l3, buf3);
   VG_(message)(Vg_UserMsg, "L2 refs:       %s  (%s rd + %s wr)",
                buf1, buf2, buf3);

   L2_total_m  = Dr_total.m2 + Dw_total.m2 + Ir_total.m2;
   L2_total_mr = Dr_total.m2 + Ir_total.m2;
   L2_total_mw = Dw_total.m2;
   commify(L2_total_m,  l1, buf1);
   commify(L2_total_mr, l2, buf2);
   commify(L2_total_mw, l3, buf3);
   VG_(message)(Vg_UserMsg, "L2 misses:     %s  (%s rd + %s wr)",
                buf1, buf2, buf3);

   percentify(L2_total_m  * 100 * p / (Ir_total.a + D_total.a),  p, l1+1, buf1);
   percentify(L2_total_mr * 100 * p / (Ir_total.a + Dr_total.a), p, l2+1, buf2);
   percentify(L2_total_mw * 100 * p / Dw_total.a, p, l3+1, buf3);
   VG_(message)(Vg_UserMsg, "L2 miss rate:  %s (%s   + %s  )", buf1, buf2,buf3);
            

   /* Hash table stats */
   if (VG_(clo_verbosity) > 1) {
       int BB_lookups = full_debug_BBs      + fn_name_debug_BBs +
                        file_line_debug_BBs + no_debug_BBs;
      
       VG_(message)(Vg_DebugMsg, "");
       VG_(message)(Vg_DebugMsg, "Distinct files:   %d", distinct_files);
       VG_(message)(Vg_DebugMsg, "Distinct fns:     %d", distinct_fns);
       VG_(message)(Vg_DebugMsg, "BB lookups:       %d", BB_lookups);
       VG_(message)(Vg_DebugMsg, "With full      debug info:%3d%% (%d)", 
                    full_debug_BBs    * 100 / BB_lookups,
                    full_debug_BBs);
       VG_(message)(Vg_DebugMsg, "With file/line debug info:%3d%% (%d)", 
                    file_line_debug_BBs * 100 / BB_lookups,
                    file_line_debug_BBs);
       VG_(message)(Vg_DebugMsg, "With fn name   debug info:%3d%% (%d)", 
                    fn_name_debug_BBs * 100 / BB_lookups,
                    fn_name_debug_BBs);
       VG_(message)(Vg_DebugMsg, "With no        debug info:%3d%% (%d)", 
                    no_debug_BBs      * 100 / BB_lookups,
                    no_debug_BBs);
       VG_(message)(Vg_DebugMsg, "BBs Retranslated: %d", BB_retranslations);
       VG_(message)(Vg_DebugMsg, "Distinct instrs:  %d", distinct_instrs);
   }
   VGP_POPCC;
#endif
}


/* Called when a translation is invalidated due to self-modifying code or
 * unloaded of a shared object.
 *
 * Finds the BBinvs in the table, removes it, adds the counts to the discard
 * counters, and then frees the BBinvs. */
void VG_(diduce_notify_discard) ( TTEntry* tte )
{
#if 0
   BBinvs *BBinvs_node;
   Addr BBinvs_ptr0, BBinvs_ptr;
   Bool BB_seen_before;
#endif
    
   if (0)
   VG_(printf)( "IGNORING!!  cachesim_notify_discard: %p for %d\n", 
                tte->orig_addr, (Int)tte->orig_size);
#if 0
   /* 2nd arg won't be used since BB should have been seen before (assertions
    * ensure this). */
   BBinvs_node = get_BBinvs(tte->orig_addr, NULL, True, &BB_seen_before);
   BBinvs_ptr0 = BBinvs_ptr = (Addr)(BBinvs_node->array);

   vg_assert(True == BB_seen_before);

   while (BBinvs_ptr - BBinvs_ptr0 < BBinvs_node->array_size) {

      /* We pretend the CC is an invariant for getting the tag.  This is ok
       * because both CC types have tag as their first byte.  Once we know
       * the type, we can cast and act appropriately. */

      switch ( ((invariant*)BBinvs_ptr)->tag ) {

         case INSTR_CC:
            ADD_CC_TO(invariant, I, Ir_discards);
            BBinvs_ptr += sizeof(invariant);
            break;

         case READ_CC:
         case  MOD_CC:
            ADD_CC_TO(idCC, I, Ir_discards);
            ADD_CC_TO(idCC, D, Dr_discards);
            BBinvs_ptr += sizeof(idCC);
            break;

         case WRITE_CC:
            ADD_CC_TO(idCC, I, Ir_discards);
            ADD_CC_TO(idCC, D, Dw_discards);
            BBinvs_ptr += sizeof(idCC);
            break;

         default:
            VG_(panic)("Unknown CC type in VG_(cachesim_notify_discard)()\n");
            break;
      }
   }

   VG_(free)(VG_AR_PRIVATE, BBinvs_node);
#endif
}

/*--------------------------------------------------------------------*/
/*--- end                                              vg_diduce.c ---*/
/*--------------------------------------------------------------------*/
