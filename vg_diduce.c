
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
#define FILENAME_LEN                    256
#define FN_NAME_LEN                     256
#define BUF_LEN                         512
#define COMMIFY_BUF_LEN                 128
#define RESULTS_BUF_LEN                 128
#define LINE_BUF_LEN                     64


/*------------------------------------------------------------*/
/*--- Output file related stuff                            ---*/
/*------------------------------------------------------------*/

#define OUT_FILE        "cachegrind.out"

#if 0
static void file_err()
{
   VG_(message)(Vg_UserMsg,
                "error: can't open cache simulation output file `%s'",
                OUT_FILE );
   VG_(exit)(1);
}
#endif

/*------------------------------------------------------------*/
/*--- Invariant types, operations                          ---*/
/*------------------------------------------------------------*/

struct _invariant {
   Addr instr_addr;
   UInt V;
   UInt M;
   UInt accesses;
   Bool is_set;
   Bool is_write;
   UChar data_size;
};

static void init_iCC(Bool is_write, invariant* cc, Addr instr_addr, UInt instr_size, UInt data_size)
{
   cc->instr_addr = instr_addr;
   cc->V          = 0;
   cc->M          = 0xffffffff;
   cc->accesses   = 0;
   cc->is_set     = False;
   cc->is_write   = is_write;
   cc->data_size  = data_size;
}

/* If 1, address of each instruction is printed as a comment after its counts
 * in cachegrind.out */
#define PRINT_INSTR_ADDRS 0

#if 0
static __inline__ void sprint_iCC(Char buf[BUF_LEN], invariant* cc)
{
#if PRINT_INSTR_ADDRS
   VG_(sprintf)(buf, "%llu %llu %llu # %x\n",
                      cc->I.a, cc->I.m1, cc->I.m2, cc->instr_addr);
#else
   VG_(sprintf)(buf, "%llu %llu %llu\n",
                      cc->I.a, cc->I.m1, cc->I.m2);
#endif
}

static __inline__ void sprint_read_or_mod_CC(Char buf[BUF_LEN], idCC* cc)
{
#if PRINT_INSTR_ADDRS
   VG_(sprintf)(buf, "%llu %llu %llu %llu %llu %llu # %x\n",
                      cc->I.a, cc->I.m1, cc->I.m2, 
                      cc->D.a, cc->D.m1, cc->D.m2, cc->instr_addr);
#else
   VG_(sprintf)(buf, "%llu %llu %llu %llu %llu %llu\n",
                      cc->I.a, cc->I.m1, cc->I.m2, 
                      cc->D.a, cc->D.m1, cc->D.m2);
#endif
}

static __inline__ void sprint_write_CC(Char buf[BUF_LEN], idCC* cc)
{
#if PRINT_INSTR_ADDRS
   VG_(sprintf)(buf, "%llu %llu %llu . . . %llu %llu %llu # %x\n",
                      cc->I.a, cc->I.m1, cc->I.m2, 
                      cc->D.a, cc->D.m1, cc->D.m2, cc->instr_addr);
#else
   VG_(sprintf)(buf, "%llu %llu %llu . . . %llu %llu %llu\n",
                      cc->I.a, cc->I.m1, cc->I.m2, 
                      cc->D.a, cc->D.m1, cc->D.m2);
#endif
}
#endif

/*------------------------------------------------------------*/
/*--- BBCC hash table stuff                                ---*/
/*------------------------------------------------------------*/

/* The table of BBCCs is of the form hash(filename, hash(fn_name,
 * hash(BBCCs))).  Each hash table is separately chained.  The sizes below work
 * fairly well for Konqueror. */

#define N_FILE_ENTRIES        251
#define   N_FN_ENTRIES         53
#define N_BBCC_ENTRIES         37

/* The cost centres for a basic block are stored in a contiguous array.
 * They are distinguishable by their tag field. */
typedef struct _BBCC BBCC;
struct _BBCC {
   Addr  orig_addr;
   UInt  array_size;    /* byte-size of variable length array */
   BBCC* next;
   Addr  array[0];      /* variable length array */
};

typedef struct _fn_node fn_node;
struct _fn_node {
   Char*    fn_name;
   BBCC*    BBCCs[N_BBCC_ENTRIES];
   fn_node* next;
};

typedef struct _file_node file_node;
struct _file_node {
   Char*      filename;
   fn_node*   fns[N_FN_ENTRIES];
   file_node* next;
};

/* BBCC_table structure:  list(filename, list(fn_name, list(BBCC))) */
static file_node *BBCC_table[N_FILE_ENTRIES];

static Int  distinct_files      = 0;
static Int  distinct_fns        = 0;

//static Int  distinct_instrs     = 0;
static Int  full_debug_BBs      = 0;
static Int  file_line_debug_BBs = 0;
static Int  fn_name_debug_BBs   = 0;
static Int  no_debug_BBs        = 0;

static Int  BB_retranslations   = 0;

static void init_BBCC_table()
{
   Int i;
   for (i = 0; i < N_FILE_ENTRIES; i++)
      BBCC_table[i] = NULL;
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
static Int compute_BBCC_array_size(UCodeBlock* cb);

static __inline__ 
file_node* new_file_node(Char filename[FILENAME_LEN], file_node* next)
{
   Int i;
   file_node* new = VG_(malloc)(VG_AR_PRIVATE, sizeof(file_node));
   new->filename  = VG_(strdup)(VG_AR_PRIVATE, filename);
   for (i = 0; i < N_FN_ENTRIES; i++) {
      new->fns[i] = NULL;
   }
   new->next      = next;
   return new;
}

static __inline__ 
fn_node* new_fn_node(Char fn_name[FILENAME_LEN], fn_node* next)
{
   Int i;
   fn_node* new = VG_(malloc)(VG_AR_PRIVATE, sizeof(fn_node));
   new->fn_name = VG_(strdup)(VG_AR_PRIVATE, fn_name);
   for (i = 0; i < N_BBCC_ENTRIES; i++) {
      new->BBCCs[i] = NULL;
   }
   new->next    = next;
   return new;
}

static __inline__ 
BBCC* new_BBCC(Addr bb_orig_addr, UCodeBlock* cb, BBCC* next)
{
   Int BBCC_array_size = compute_BBCC_array_size(cb);
   BBCC* new;

   new = (BBCC*)VG_(malloc)(VG_AR_PRIVATE, sizeof(BBCC) + BBCC_array_size);
   new->orig_addr  = bb_orig_addr;
   new->array_size = BBCC_array_size;
   new->next = next;

   return new;
}

#define HASH_CONSTANT   256

static UInt hash(Char *s, UInt table_size)
{
    int hash_value = 0;
    for ( ; *s; s++)
        hash_value = (HASH_CONSTANT * hash_value + *s) % table_size;
    return hash_value;
}

/* Do a three step traversal: by filename, then fn_name, then instr_addr.
 * In all cases prepends new nodes to their chain.  Returns a pointer to the
 * cost centre.  Also sets BB_seen_before by reference. 
 */ 
static __inline__ BBCC* get_BBCC(Addr bb_orig_addr, UCodeBlock* cb, 
                                 Bool remove, Bool *BB_seen_before)
{
   file_node *curr_file_node;
   fn_node   *curr_fn_node;
   BBCC     **prev_BBCC_next_ptr, *curr_BBCC;
   Char       filename[FILENAME_LEN], fn_name[FN_NAME_LEN];
   UInt       filename_hash, fnname_hash, BBCC_hash;
   Int        dummy_line_num;

   get_debug_info(bb_orig_addr, filename, fn_name, &dummy_line_num);

   VGP_PUSHCC(VgpCacheGetBBCC);
   filename_hash = hash(filename, N_FILE_ENTRIES);
   curr_file_node = BBCC_table[filename_hash];
   while (NULL != curr_file_node && 
          VG_(strcmp)(filename, curr_file_node->filename) != 0) {
      curr_file_node = curr_file_node->next;
   }
   if (NULL == curr_file_node) {
      BBCC_table[filename_hash] = curr_file_node = 
         new_file_node(filename, BBCC_table[filename_hash]);
      distinct_files++;
   }

   fnname_hash = hash(fn_name, N_FN_ENTRIES);
   curr_fn_node = curr_file_node->fns[fnname_hash];
   while (NULL != curr_fn_node && 
          VG_(strcmp)(fn_name, curr_fn_node->fn_name) != 0) {
      curr_fn_node = curr_fn_node->next;
   }
   if (NULL == curr_fn_node) {
      curr_file_node->fns[fnname_hash] = curr_fn_node = 
         new_fn_node(fn_name, curr_file_node->fns[fnname_hash]);
      distinct_fns++;
   }

   BBCC_hash = bb_orig_addr % N_BBCC_ENTRIES;
   prev_BBCC_next_ptr = &(curr_fn_node->BBCCs[BBCC_hash]);
   curr_BBCC = curr_fn_node->BBCCs[BBCC_hash];
   while (NULL != curr_BBCC && bb_orig_addr != curr_BBCC->orig_addr) {
      prev_BBCC_next_ptr = &(curr_BBCC->next);
      curr_BBCC = curr_BBCC->next;
   }
   if (curr_BBCC == NULL) {

      vg_assert(False == remove);

      curr_fn_node->BBCCs[BBCC_hash] = curr_BBCC = 
         new_BBCC(bb_orig_addr, cb, curr_fn_node->BBCCs[BBCC_hash]);
      *BB_seen_before = False;

   } else {
      vg_assert(bb_orig_addr == curr_BBCC->orig_addr);
      vg_assert(curr_BBCC->array_size > 0 && curr_BBCC->array_size < 1000000);
      if (VG_(clo_verbosity) > 2) {
          VG_(message)(Vg_DebugMsg, 
            "BB retranslation, retrieving from BBCC table");
      }
      *BB_seen_before = True;

      if (True == remove) {
          // Remove curr_BBCC from chain;  it will be used and free'd by the
          // caller.
          *prev_BBCC_next_ptr = curr_BBCC->next;

      } else {
          BB_retranslations++;
      }
   }
   VGP_POPCC;
   return curr_BBCC;
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

static Int compute_BBCC_array_size(UCodeBlock* cb)
{
   UInstr* u_in;
   Int     i, CC_size, BBCC_size = 0;
   Bool    is_LOAD, is_STORE, is_FPU_R, is_FPU_W;
    
   is_LOAD = is_STORE = is_FPU_R = is_FPU_W = False;

   for (i = 0; i < cb->used; i++) {
      /* VG_(ppUInstr)(0, &cb->instrs[i]); */

      u_in = &cb->instrs[i];
      switch(u_in->opcode) {

         case INCEIP: 
            goto case_for_end_of_instr;
         
         case JMP:
            if (u_in->cond != CondAlways) break;

            goto case_for_end_of_instr;

            case_for_end_of_instr:

            CC_size = //(is_LOAD || is_STORE || is_FPU_R || is_FPU_W 
                      //? sizeof(invariant) : sizeof(invariant));
                      sizeof(invariant);

            BBCC_size += CC_size;
            is_LOAD = is_STORE = is_FPU_R = is_FPU_W = False;
            break;

         case LOAD:
            /* Two LDBs are possible for a single instruction */
            /* Also, a STORE can come after a LOAD for bts/btr/btc */
            vg_assert(/*!is_LOAD &&*/ /* !is_STORE && */ 
                      !is_FPU_R && !is_FPU_W);
            is_LOAD = True;
            break;

         case STORE:
            /* Multiple STOREs are possible for 'pushal' */
            vg_assert(            /*!is_STORE &&*/ !is_FPU_R && !is_FPU_W);
            is_STORE = True;
            break;

         case FPU_R:
            vg_assert(!is_LOAD && !is_STORE && !is_FPU_R && !is_FPU_W);
            is_FPU_R = True;
            break;

         case FPU_W:
            vg_assert(!is_LOAD && !is_STORE && !is_FPU_R && !is_FPU_W);
            is_FPU_W = True;
            break;

         default:
            break;
      }
   }
//VG_(printf)("END OF BB\n");

   return BBCC_size;
}

/* Use this rather than eg. -1 because it's stored as a UInt. */
#define INVALID_DATA_SIZE   999999

UCodeBlock* VG_(diduce_instrument)(UCodeBlock* cb_in, Addr orig_addr)
{
   UCodeBlock* cb;
   Int         i;
   UInstr*     u_in;
   BBCC*       BBCC_node;
   Int         t_CC_addr, t_read_addr, t_write_addr, t_data_addr;
   Int         CC_size = -1;    /* Shut gcc warnings up */
   Addr        instr_addr = orig_addr;
   UInt        instr_size, data_size = INVALID_DATA_SIZE;
   Int         helper = -1;     /* Shut gcc warnings up */
   UInt        stack_used;
   Bool        BB_seen_before       = False;
   Bool        prev_instr_was_Jcond = False;
   Addr        BBCC_ptr0, BBCC_ptr; 

   /* Get BBCC (creating if necessary -- requires a counting pass over the BB
    * if it's the first time it's been seen), and point to start of the 
    * BBCC array.  */
   BBCC_node = get_BBCC(orig_addr, cb_in, False, &BB_seen_before);
   BBCC_ptr0 = BBCC_ptr = (Addr)(BBCC_node->array);

   cb = VG_(allocCodeBlock)();
   cb->nextTemp = cb_in->nextTemp;

   t_CC_addr = t_read_addr = t_write_addr = t_data_addr = INVALID_TEMPREG;

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
       *
       * The instrumentation is just a call to the appropriate helper function,
       * passing it the address of the instruction's CC.
       */
      if (prev_instr_was_Jcond) vg_assert(u_in->opcode == JMP);

      switch (u_in->opcode) {

         case INCEIP:
            instr_size = u_in->val1;
            goto case_for_end_of_x86_instr;

         case JMP:
            if (u_in->cond == CondAlways) {
               vg_assert(i+1 == cb_in->used); 

               /* Don't instrument if previous instr was a Jcond. */
               if (prev_instr_was_Jcond) {
                  vg_assert(0 == u_in->extra4b);
                  VG_(copyUInstr)(cb, u_in);
                  break;
               }
               prev_instr_was_Jcond = False;

            } else {
               vg_assert(i+2 == cb_in->used);  /* 2nd last instr in block */
               prev_instr_was_Jcond = True;
            }

            /* Ah, the first JMP... instrument, please. */
            instr_size = u_in->extra4b;
            goto case_for_end_of_x86_instr;

            /* Shared code that is executed at the end of an x86 translation
             * block, marked by either an INCEIP or an unconditional JMP. */
            case_for_end_of_x86_instr:

#define IS_(X)      (INVALID_TEMPREG != t_##X##_addr)
             
            /* Initialise the CC in the BBCC array appropriately if it hasn't
             * been initialised before.
             * Then call appropriate sim function, passing it the CC address.
             * Note that CALLM_S/CALL_E aren't required here;  by this point,
             * the checking related to them has already happened. */
            stack_used = 0;

//            vg_assert(instr_size >= 1 && instr_size <= MAX_x86_INSTR_SIZE);
            if (instr_size < 1 || instr_size > MAX_x86_INSTR_SIZE) {
               VG_(printf)("instr_size = %d", instr_size);
               VG_(panic)("X");
            }
            vg_assert(0 != instr_addr);

            CC_size = sizeof(invariant);
            if (!IS_(read) && !IS_(write)) {
//               invariant* CC_ptr = (invariant*)(BBCC_ptr);
               vg_assert(INVALID_DATA_SIZE == data_size);
               vg_assert(INVALID_TEMPREG == t_read_addr && 
                         INVALID_TEMPREG == t_write_addr);
#if 0
               if (!BB_seen_before)
                   init_iCC(CC_ptr, instr_addr, instr_size);

               helper = VGOFF_(cachesim_log_non_mem_instr);
#endif
            } else { 
               Bool is_write;
               invariant* CC_ptr = (invariant*)(BBCC_ptr);
                
               vg_assert(4 == data_size || 2  == data_size || 1 == data_size || 
                         8 == data_size || 10 == data_size);
               
               //CC_size = sizeof(invariant);
               helper = VGOFF_(diduce_log_instr);

               if (IS_(read) && !IS_(write)) {
                  is_write = False;
                  vg_assert(INVALID_TEMPREG != t_read_addr && 
                            INVALID_TEMPREG == t_write_addr);
                  t_data_addr = t_read_addr;

               } else if (!IS_(read) && IS_(write)) {
                  is_write = True;
                  vg_assert(INVALID_TEMPREG == t_read_addr && 
                            INVALID_TEMPREG != t_write_addr);
                  t_data_addr = t_write_addr;

               } else {
                  vg_assert(IS_(read) && IS_(write));
                  is_write = True;
                  vg_assert(INVALID_TEMPREG != t_read_addr && 
                            INVALID_TEMPREG != t_write_addr);
                  t_data_addr = t_read_addr;
               }

               if (!BB_seen_before)
                  init_iCC(is_write, CC_ptr, instr_addr, instr_size, data_size);

               /* Save the caller-save registers before we push our args */
               uInstr1(cb, PUSH, 4, RealReg, R_EAX);
               uInstr1(cb, PUSH, 4, RealReg, R_ECX);
               uInstr1(cb, PUSH, 4, RealReg, R_EDX);

               /* 2nd arg: data addr */
               uInstr1(cb, PUSH,  4, TempReg, t_data_addr);
               stack_used += 4;

               /* 1st arg: CC addr */
               t_CC_addr = newTemp(cb);
               uInstr2(cb, MOV,   4, Literal, 0, TempReg, t_CC_addr);
               uLiteral(cb, BBCC_ptr);
               uInstr1(cb, PUSH,  4, TempReg, t_CC_addr);
               stack_used += 4;

               /* Call function and return. */
               uInstr1(cb, CALLM, 0, Lit16,   helper);
               uInstr1(cb, CLEAR, 0, Lit16,   stack_used);

               /* Restore the caller-save registers now the call is done */
               uInstr1(cb, POP, 4, RealReg, R_EDX);
               uInstr1(cb, POP, 4, RealReg, R_ECX);
               uInstr1(cb, POP, 4, RealReg, R_EAX);
            }

            VG_(copyUInstr)(cb, u_in);

            /* Update BBCC_ptr, EIP, de-init read/write temps for next instr */
            BBCC_ptr   += CC_size; 
            instr_addr += instr_size;
            t_CC_addr = t_read_addr = t_write_addr = 
                                      t_data_addr  = INVALID_TEMPREG;
            data_size = INVALID_DATA_SIZE;
#undef IS_

            break;


         /* For memory-ref instrs, copy the data_addr into a temporary to be
          * passed to the cachesim_log_function at the end of the instruction.
          */
         case LOAD: 
            t_read_addr = newTemp(cb);
            uInstr2(cb, MOV, 4, TempReg, u_in->val1,  TempReg, t_read_addr);
            data_size = u_in->size;
            VG_(copyUInstr)(cb, u_in);
            break;

         case FPU_R:
            t_read_addr = newTemp(cb);
            uInstr2(cb, MOV, 4, TempReg, u_in->val2,  TempReg, t_read_addr);
            data_size = u_in->size;
            VG_(copyUInstr)(cb, u_in);
            break;

         /* Note that we must set t_write_addr even for mod instructions;
          * that's how the code above determines whether it does a write;
          * without it, it would think a mod instruction is a read.
          * As for the MOV, if it's a mod instruction it's redundant, but it's
          * not expensive and mod instructions are rare anyway. */
         case STORE:
         case FPU_W:
            t_write_addr = newTemp(cb);
            uInstr2(cb, MOV, 4, TempReg, u_in->val2, TempReg, t_write_addr);
            data_size = u_in->size;
            VG_(copyUInstr)(cb, u_in);
            break;

         case NOP:  case CALLM_E:  case CALLM_S:
            break;

         default:
            VG_(copyUInstr)(cb, u_in);
            break;
      }
   }

   /* Just check everything looks ok */
   vg_assert(BBCC_ptr - BBCC_ptr0 == BBCC_node->array_size);

   VG_(freeCodeBlock)(cb_in);
   return cb;
}

void VG_(init_diduce)(void)
{
   /* Make sure the output file can be written. */
//   Int fd = VG_(open_write)(OUT_FILE);
//   if (-1 == fd) { 
//      fd = VG_(create_and_write)(OUT_FILE);
//      if (-1 == fd) {
//         file_err(); 
//      }
//   }
//   VG_(close)(fd);

//   cachesim_I1_initcache(I1c);
//   cachesim_D1_initcache(D1c);
//   cachesim_L2_initcache(L2c);

   VG_(printf)("DIDUCE INIT\n");

   init_BBCC_table();
}

static Int violations = 0;

static Int num_of_zero_bits_in_UInt(UInt x) 
{
   Int i, n = 0;

   for (i = 0; i < sizeof(UInt)*8; i++) {
      if (0 == (x & 0x1)) n++;
      x >>= 1;
   }

   return n;
}

static __inline__ Bool is_crud(char* fl, char* fn)
{
   return (0 == VG_(strcmp)(fl, "do-lookup.h"                   ) ||
           0 == VG_(strcmp)(fl, "dl-lookup.c"                   ) ||
           0 == VG_(strcmp)(fl, "dl-runtime.c"                  ) ||
           0 == VG_(strcmp)(fl, "dl-init.c"                     ) ||
           0 == VG_(strcmp)(fl, "dl-fini.c"                     ) ||
           0 == VG_(strcmp)(fl, "dl-debug.c"                    ) ||
           0 == VG_(strcmp)(fl, "cxa_atexit.c"                  ) ||
           0 == VG_(strcmp)(fl, "exit.c"                        ) ||
           0 == VG_(strcmp)(fl, "genops.c"                      ) ||
           0 == VG_(strcmp)(fl, "getopt_init.c"                 ) ||
           0 == VG_(strcmp)(fl, "???"                           ) ||
           0 == VG_(strcmp)(fn, "???"                           ) ||
           0 == VG_(strcmp)(fn, "set_progname"                  ) ||
           0 == VG_(strcmp)(fn, "fixup"                         ) ||
           0 == VG_(strcmp)(fn, "__libc_init"                   ) ||
           0 == VG_(strcmp)(fn, "_dl_runtime_resolve"           ) ||
           0 == VG_(strcmp)(fn, "_dl_lookup_versioned_symbol"   ) ||
           0 == VG_(strcmp)(fn, "__getopt_clean_environment"    ) ||
           0 == VG_(strcmp)(fn, "__deregister_frame_info"       ));
}


//static jmp_buf sigsegv_jmpbuf;
//
//static
//void SIGSEGV_handler(int signum)
//{
//   __builtin_longjmp(sigsegv_jmpbuf, 1);
//}


void VG_(diduce_log_instr)(invariant* inv, Addr data_addr)
{
   //VG_(printf)("sim  D: CCaddr=0x%x, iaddr=0x%x, isize=%u, daddr=0x%x, dsize=%u\n",
   //            inv, inv->instr_addr, inv->instr_size, data_addr, inv->data_size)
#if 0
   VGP_PUSHCC(VgpCacheSimulate);
   cachesim_I1_doref(inv->instr_addr, inv->instr_size, &inv->I.m1, &inv->I.m2);
   inv->I.a++;

   cachesim_D1_doref(data_addr,      inv->data_size,  &inv->D.m1, &inv->D.m2);
   inv->D.a++;
   VGP_POPCC;
#endif

   UInt x, W;

   Char fl_buf[256], fn_buf[256];
   Int line_num = 0;

//   VG_(printf)("%x...", data_addr);
   
//   W = *(UInt*)data_addr;

   /* Install own SIGSEGV handler */
#if 0
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
      W = *(UInt*)data_addr;

      /* Restore old SIGILL handler */
      res = VG_(ksigaction)( VKI_SIGSEGV, &sigsegv_saved, NULL );
      vg_assert(res == 0);

   } else  {
      //VG_(message)(Vg_UserMsg, "SEGMENTATION FAULT!!!");
      VG_(printf)("SEGMENTATION FAULT!!!: (%c)deref'd %x, data_size=%u", 
            (inv->is_write ? 'w' : 'r'), W, inv->data_size);
      get_debug_info(inv->instr_addr, fl_buf, fn_buf, &line_num);
      VG_(printf)(" at %s:%s:%d (%x)\n",  fl_buf, fn_buf, line_num, inv->instr_addr);

      /* Restore old SIGILL handler */
      res = VG_(ksigaction)( VKI_SIGSEGV, &sigsegv_saved, NULL );
      vg_assert(res == 0);

      W = 999;
   }
#endif
   switch (inv->data_size) {
      case 1:  W = *(UChar*) data_addr;  break;
      case 2:  W = *(UShort*)data_addr;  break;
      case 4: case 8: case 10:
               W = *(UInt*)  data_addr;  break;
      default: VG_(panic)("inv->data size not 1, 2, 4, 8 or 10");
   }
   
//   if (inv->is_write) {
      if (inv->is_set) {

         x = inv->V ^ W;
         //VG_(printf)("V(%8x): %8x, W: %8x, V^W = %8x, old mask = %8x, change? = %x\n",
         //    data_addr, inv->V, W, x, inv->M, x & inv->M);
         if (0 != (x & inv->M)) {
            UInt old_mask = inv->M;
            get_debug_info(inv->instr_addr, fl_buf, fn_buf, &line_num);
            
            inv->M &= ~x;            /* Relax inv */

            if (! is_crud(fl_buf, fn_buf)) {
            
               Int range_of_values1 = (1 << num_of_zero_bits_in_UInt(old_mask));
               Int range_of_values2 = (1 << num_of_zero_bits_in_UInt(inv->M));
               //float confidence_threshold = 5;
               float confidence1 =  inv->accesses    / (float)range_of_values1;
               float confidence2 = (inv->accesses+1) / (float)range_of_values2;

               // ignore unless confidence threshold reached
               if (confidence1 - confidence2 > VG_(clo_confidence)) {
#                 if 0
                  VG_(printf)("V%c%3d: %u/%d, %u/%d, vbits: %d -> %d, V: %08x, val = %08x"
                              " at %s:%s:%d\n", 
                              (inv->is_write ? 'w' : 'r'), violations, 
                              inv->accesses, range_of_values1,
                              inv->accesses+1, range_of_values2,
                              old_mask, inv->M, inv->V, W,
                              fl_buf, fn_buf, line_num);
#                 else
                  VG_(printf)("V%c%3d: conf loss %d, count %d, values %d, "
                              "vbits %d->%d, value 0x%x"
                              "  at %s:%s:%d\n", 
                              (inv->is_write ? 'w' : 'r'), violations, 
                              ((Int)confidence1) - ((Int)confidence2),
                              inv->accesses+1, range_of_values2,
                              num_of_zero_bits_in_UInt(old_mask), 
                              num_of_zero_bits_in_UInt(inv->M), 
                              W,
                              fl_buf, fn_buf, line_num);
#                 endif
                  violations++;
               }
            }
         }

      } else {
         //VG_(printf)("unset_%c(%8x, %8x) ---> %x\n", 
         //      (inv->is_write ? 'w' : 'r'), data_addr, inv, W);
         inv->V = W;
         inv->is_set = True;
      }
      inv->accesses++;

//   } else {
//      //VG_(printf)("read (%x)\n", W);
//      if (! cc->is_set) {
//         VG_(printf)("Reading unitialised value at address 0x%x\n", data_addr);
//      }
//   }
}

/*------------------------------------------------------------*/
/*--- Printing of output file and summary stats            ---*/
/*------------------------------------------------------------*/

#if 0
static void fprint_BBCC(Int fd, BBCC* BBCC_node, Char *first_instr_fl, 
                                                 Char *first_instr_fn)
{
   Addr BBCC_ptr0, BBCC_ptr;
   Char buf[BUF_LEN], curr_file[BUF_LEN], 
        fbuf[BUF_LEN+4], lbuf[LINE_BUF_LEN];
   UInt line_num;

   BBCC_ptr0 = BBCC_ptr = (Addr)(BBCC_node->array);

   /* Mark start of basic block in output, just to ease debugging */
   VG_(write)(fd, (void*)"\n", 1);  

   VG_(strcpy)(curr_file, first_instr_fl);
   
   while (BBCC_ptr - BBCC_ptr0 < BBCC_node->array_size) {

      /* We pretend the CC is an invariant for getting the tag.  This is ok
       * because both CC types have tag as their first byte.  Once we know
       * the type, we can cast and act appropriately. */

      Char fl_buf[FILENAME_LEN];
      Char fn_buf[FN_NAME_LEN];

      Addr instr_addr;
      switch ( ((invariant*)BBCC_ptr)->tag ) {

         case INSTR_CC:
            instr_addr = ((invariant*)BBCC_ptr)->instr_addr;
            sprint_iCC(buf, (invariant*)BBCC_ptr);
            ADD_CC_TO(invariant, I, Ir_total);
            BBCC_ptr += sizeof(invariant);
            break;

         case READ_CC:
         case  MOD_CC:
            instr_addr = ((idCC*)BBCC_ptr)->instr_addr;
            sprint_read_or_mod_CC(buf, (idCC*)BBCC_ptr);
            ADD_CC_TO(idCC, I, Ir_total);
            ADD_CC_TO(idCC, D, Dr_total);
            BBCC_ptr += sizeof(idCC);
            break;

         case WRITE_CC:
            instr_addr = ((idCC*)BBCC_ptr)->instr_addr;
            sprint_write_CC(buf, (idCC*)BBCC_ptr);
            ADD_CC_TO(idCC, I, Ir_total);
            ADD_CC_TO(idCC, D, Dw_total);
            BBCC_ptr += sizeof(idCC);
            break;

         default:
            VG_(panic)("Unknown CC type in fprint_BBCC()\n");
            break;
      }
      distinct_instrs++;
      
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

   vg_assert(BBCC_ptr - BBCC_ptr0 == BBCC_node->array_size);
}
#endif

#if 0
static void fprint_BBCC_table_and_calc_totals(Int client_argc, 
                                              Char** client_argv)
{
   Int        fd;
   Char       buf[BUF_LEN];
   file_node *curr_file_node;
   fn_node   *curr_fn_node;
   BBCC      *curr_BBCC;
   Int        i,j,k;

   VGP_PUSHCC(VgpCacheDump);
   fd = VG_(open_write)(OUT_FILE);
   if (-1 == fd) { file_err(); }

   /* "desc:" lines (giving I1/D1/L2 cache configuration) */
   VG_(sprintf)(buf, "desc: I1 cache:         %s\n", I1.desc_line);
   VG_(write)(fd, (void*)buf, VG_(strlen)(buf));
   VG_(sprintf)(buf, "desc: D1 cache:         %s\n", D1.desc_line);
   VG_(write)(fd, (void*)buf, VG_(strlen)(buf));
   VG_(sprintf)(buf, "desc: L2 cache:         %s\n", L2.desc_line);
   VG_(write)(fd, (void*)buf, VG_(strlen)(buf));

   /* "cmd:" line */
   VG_(strcpy)(buf, "cmd:");
   VG_(write)(fd, (void*)buf, VG_(strlen)(buf));
   for (i = 0; i < client_argc; i++) {
       VG_(sprintf)(buf, " %s", client_argv[i]);
       VG_(write)(fd, (void*)buf, VG_(strlen)(buf));
   }
   /* "events:" line */
   VG_(sprintf)(buf, "\nevents: Ir I1mr I2mr Dr D1mr D2mr Dw D1mw D2mw\n");
   VG_(write)(fd, (void*)buf, VG_(strlen)(buf));

   /* Six loops here:  three for the hash table arrays, and three for the
    * chains hanging off the hash table arrays. */
   for (i = 0; i < N_FILE_ENTRIES; i++) {
      curr_file_node = BBCC_table[i];
      while (curr_file_node != NULL) {
         VG_(sprintf)(buf, "fl=%s\n", curr_file_node->filename);
         VG_(write)(fd, (void*)buf, VG_(strlen)(buf));

         for (j = 0; j < N_FN_ENTRIES; j++) {
            curr_fn_node = curr_file_node->fns[j];
            while (curr_fn_node != NULL) {
               VG_(sprintf)(buf, "fn=%s\n", curr_fn_node->fn_name);
               VG_(write)(fd, (void*)buf, VG_(strlen)(buf));

               for (k = 0; k < N_BBCC_ENTRIES; k++) {
                  curr_BBCC = curr_fn_node->BBCCs[k];
                  while (curr_BBCC != NULL) {
                     fprint_BBCC(fd, curr_BBCC, 
                             
                             curr_file_node->filename,
                             curr_fn_node->fn_name);

                     curr_BBCC = curr_BBCC->next;
                  }
               }
               curr_fn_node = curr_fn_node->next;
            }
         }
         curr_file_node = curr_file_node->next;
      }
   }

   /* Print stats from any discarded basic blocks */
   if (0 != Ir_discards.a) {

      VG_(sprintf)(buf, "fl=(discarded)\n");
      VG_(write)(fd, (void*)buf, VG_(strlen)(buf));
      VG_(sprintf)(buf, "fn=(discarded)\n");
      VG_(write)(fd, (void*)buf, VG_(strlen)(buf));

      /* Use 0 as line number */
      VG_(sprintf)(buf, "0 %llu %llu %llu %llu %llu %llu %llu %llu %llu\n",
                   Ir_discards.a, Ir_discards.m1, Ir_discards.m2, 
                   Dr_discards.a, Dr_discards.m1, Dr_discards.m2, 
                   Dw_discards.a, Dw_discards.m1, Dw_discards.m2);
      VG_(write)(fd, (void*)buf, VG_(strlen)(buf));

      Ir_total.a  += Ir_discards.a;
      Ir_total.m1 += Ir_discards.m1;
      Ir_total.m2 += Ir_discards.m2;
      Dr_total.a  += Dr_discards.a;
      Dr_total.m1 += Dr_discards.m1;
      Dr_total.m2 += Dr_discards.m2;
      Dw_total.a  += Dw_discards.a;
      Dw_total.m1 += Dw_discards.m1;
      Dw_total.m2 += Dw_discards.m2;
   }

   /* Summary stats must come after rest of table, since we calculate them
    * during traversal.  */ 
   VG_(sprintf)(buf, "summary: "
                     "%llu %llu %llu "
                     "%llu %llu %llu "
                     "%llu %llu %llu\n", 
                     Ir_total.a, Ir_total.m1, Ir_total.m2,
                     Dr_total.a, Dr_total.m1, Dr_total.m2,
                     Dw_total.a, Dw_total.m1, Dw_total.m2);
   VG_(write)(fd, (void*)buf, VG_(strlen)(buf));
   VG_(close)(fd);
}
#endif

#if 0
/* Adds commas to ULong, right justifying in a field field_width wide, returns
 * the string in buf. */
static
Int commify(ULong n, int field_width, char buf[COMMIFY_BUF_LEN])
{
   int len, n_commas, i, j, new_len, space;

   VG_(sprintf)(buf, "%lu", n);
   len = VG_(strlen)(buf);
   n_commas = (len - 1) / 3;
   new_len = len + n_commas;
   space = field_width - new_len;

   /* Allow for printing a number in a field_width smaller than it's size */
   if (space < 0) space = 0;    

   /* Make j = -1 because we copy the '\0' before doing the numbers in groups
    * of three. */
   for (j = -1, i = len ; i >= 0; i--) {
      buf[i + n_commas + space] = buf[i];

      if (3 == ++j) {
         j = 0;
         n_commas--;
         buf[i + n_commas + space] = ',';
      }
   }
   /* Right justify in field. */
   for (i = 0; i < space; i++)  buf[i] = ' ';
   return new_len;
}

static
void percentify(Int n, Int pow, Int field_width, char buf[]) 
{
   int i, len, space;
    
   VG_(sprintf)(buf, "%d.%d%%", n / pow, n % pow);
   len = VG_(strlen)(buf);
   space = field_width - len;
   i = len;

   /* Right justify in field */
   for (     ; i >= 0;    i--)  buf[i + space] = buf[i];
   for (i = 0; i < space; i++)  buf[i] = ' ';
}
#endif
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

   fprint_BBCC_table_and_calc_totals(client_argc, client_argv);

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
 * Finds the BBCC in the table, removes it, adds the counts to the discard
 * counters, and then frees the BBCC. */
void VG_(diduce_notify_discard) ( TTEntry* tte )
{
#if 0
   BBCC *BBCC_node;
   Addr BBCC_ptr0, BBCC_ptr;
   Bool BB_seen_before;
#endif
    
   if (0)
   VG_(printf)( "IGNORING!!  cachesim_notify_discard: %p for %d\n", 
                tte->orig_addr, (Int)tte->orig_size);
#if 0
   /* 2nd arg won't be used since BB should have been seen before (assertions
    * ensure this). */
   BBCC_node = get_BBCC(tte->orig_addr, NULL, True, &BB_seen_before);
   BBCC_ptr0 = BBCC_ptr = (Addr)(BBCC_node->array);

   vg_assert(True == BB_seen_before);

   while (BBCC_ptr - BBCC_ptr0 < BBCC_node->array_size) {

      /* We pretend the CC is an invariant for getting the tag.  This is ok
       * because both CC types have tag as their first byte.  Once we know
       * the type, we can cast and act appropriately. */

      switch ( ((invariant*)BBCC_ptr)->tag ) {

         case INSTR_CC:
            ADD_CC_TO(invariant, I, Ir_discards);
            BBCC_ptr += sizeof(invariant);
            break;

         case READ_CC:
         case  MOD_CC:
            ADD_CC_TO(idCC, I, Ir_discards);
            ADD_CC_TO(idCC, D, Dr_discards);
            BBCC_ptr += sizeof(idCC);
            break;

         case WRITE_CC:
            ADD_CC_TO(idCC, I, Ir_discards);
            ADD_CC_TO(idCC, D, Dw_discards);
            BBCC_ptr += sizeof(idCC);
            break;

         default:
            VG_(panic)("Unknown CC type in VG_(cachesim_notify_discard)()\n");
            break;
      }
   }

   VG_(free)(VG_AR_PRIVATE, BBCC_node);
#endif
}

/*--------------------------------------------------------------------*/
/*--- end                                              vg_diduce.c ---*/
/*--------------------------------------------------------------------*/
