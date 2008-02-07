
/*--------------------------------------------------------------------*/
/*--- Read DWARF3 ".debug_info" sections (DIE trees).              ---*/
/*---                                                 readdwarf3.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2008-2008 OpenWorks LLP and others; see below
      info@open-works.co.uk

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

   Neither the names of the U.S. Department of Energy nor the
   University of California nor the names of its contributors may be
   used to endorse or promote products derived from this software
   without prior written permission.

   -------------

   Some of this code (DWARF3 enumerations) is taken from FSF's
   gdb-6.6/include/elf/dwarf2.h, which is Copyright (C) 1992 to 2006
   Free Software Foundation, Inc and is also GPL-2-or-later.
*/

/* Current hacks:
      DW_TAG_{const,volatile}_type no DW_AT_type is allowed; it is
         assumed to mean "const void" or "volatile void" respectively.
         GDB appears to interpret them like this, anyway.

   get rid of cu_svma_known and document the assumed-zero svma hack.

   (text)-bias the code ranges handed to ML_(addVar); add check that
   they actually fall into the text segment

   parse all the types first, then resolve, then parse all the vars,
   so that when we come to add vars, we know what their types are.
   This is important, else we cannot know their sizes.
*/

#include "pub_core_basics.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcprint.h"
#include "pub_core_mallocfree.h"
#include "pub_core_options.h"
#include "pub_core_xarray.h"
#include "priv_storage.h"
#include "priv_readdwarf3.h"       /* self */

#ifdef HAVE_BUILTIN_EXPECT
#define LIKELY(cond)   __builtin_expect(!!(cond),1)
#define UNLIKELY(cond) __builtin_expect(!!(cond),0)
#else
#define LIKELY(cond)   (cond)
#define UNLIKELY(cond) (cond)
#endif

// FIXME common these up 
static void* dinfo_zalloc ( SizeT szB ) {
   void* v;
   vg_assert(szB > 0);
   v = VG_(arena_malloc)( VG_AR_DINFO, szB );
   vg_assert(v);
   VG_(memset)(v, 0, szB);
   return v;
}
static void dinfo_free ( void* v ) {
   VG_(arena_free)( VG_AR_DINFO, v );
}
static UChar* dinfo_strdup ( UChar* str ) {
   return VG_(arena_strdup)( VG_AR_DINFO, str );
}

/*------------------------------------------------------------*/
/*--- The "new" DWARF3 reader -- enumerations and types    ---*/
/*------------------------------------------------------------*/

#define TRACE_D3(format, args...) \
   if (td3) { VG_(printf)(format, ## args); }


/* This stuff is taken from gdb-6.6/include/elf/dwarf2.h, which is
   GPL2+.
*/
/* Tag names and codes.  */
typedef enum 
  {
    DW_TAG_padding = 0x00,
    DW_TAG_array_type = 0x01,
    DW_TAG_class_type = 0x02,
    DW_TAG_entry_point = 0x03,
    DW_TAG_enumeration_type = 0x04,
    DW_TAG_formal_parameter = 0x05,
    DW_TAG_imported_declaration = 0x08,
    DW_TAG_label = 0x0a,
    DW_TAG_lexical_block = 0x0b,
    DW_TAG_member = 0x0d,
    DW_TAG_pointer_type = 0x0f,
    DW_TAG_reference_type = 0x10,
    DW_TAG_compile_unit = 0x11,
    DW_TAG_string_type = 0x12,
    DW_TAG_structure_type = 0x13,
    DW_TAG_subroutine_type = 0x15,
    DW_TAG_typedef = 0x16,
    DW_TAG_union_type = 0x17,
    DW_TAG_unspecified_parameters = 0x18,
    DW_TAG_variant = 0x19,
    DW_TAG_common_block = 0x1a,
    DW_TAG_common_inclusion = 0x1b,
    DW_TAG_inheritance = 0x1c,
    DW_TAG_inlined_subroutine = 0x1d,
    DW_TAG_module = 0x1e,
    DW_TAG_ptr_to_member_type = 0x1f,
    DW_TAG_set_type = 0x20,
    DW_TAG_subrange_type = 0x21,
    DW_TAG_with_stmt = 0x22,
    DW_TAG_access_declaration = 0x23,
    DW_TAG_base_type = 0x24,
    DW_TAG_catch_block = 0x25,
    DW_TAG_const_type = 0x26,
    DW_TAG_constant = 0x27,
    DW_TAG_enumerator = 0x28,
    DW_TAG_file_type = 0x29,
    DW_TAG_friend = 0x2a,
    DW_TAG_namelist = 0x2b,
    DW_TAG_namelist_item = 0x2c,
    DW_TAG_packed_type = 0x2d,
    DW_TAG_subprogram = 0x2e,
    DW_TAG_template_type_param = 0x2f,
    DW_TAG_template_value_param = 0x30,
    DW_TAG_thrown_type = 0x31,
    DW_TAG_try_block = 0x32,
    DW_TAG_variant_part = 0x33,
    DW_TAG_variable = 0x34,
    DW_TAG_volatile_type = 0x35,
    /* DWARF 3.  */
    DW_TAG_dwarf_procedure = 0x36,
    DW_TAG_restrict_type = 0x37,
    DW_TAG_interface_type = 0x38,
    DW_TAG_namespace = 0x39,
    DW_TAG_imported_module = 0x3a,
    DW_TAG_unspecified_type = 0x3b,
    DW_TAG_partial_unit = 0x3c,
    DW_TAG_imported_unit = 0x3d,
    DW_TAG_condition = 0x3f,
    DW_TAG_shared_type = 0x40,
    /* SGI/MIPS Extensions.  */
    DW_TAG_MIPS_loop = 0x4081,
    /* HP extensions.  See: ftp://ftp.hp.com/pub/lang/tools/WDB/wdb-4.0.tar.gz .  */
    DW_TAG_HP_array_descriptor = 0x4090,
    /* GNU extensions.  */
    DW_TAG_format_label = 0x4101,	/* For FORTRAN 77 and Fortran 90.  */
    DW_TAG_function_template = 0x4102,	/* For C++.  */
    DW_TAG_class_template = 0x4103,	/* For C++.  */
    DW_TAG_GNU_BINCL = 0x4104,
    DW_TAG_GNU_EINCL = 0x4105,
    /* Extensions for UPC.  See: http://upc.gwu.edu/~upc.  */
    DW_TAG_upc_shared_type = 0x8765,
    DW_TAG_upc_strict_type = 0x8766,
    DW_TAG_upc_relaxed_type = 0x8767,
    /* PGI (STMicroelectronics) extensions.  No documentation available.  */
    DW_TAG_PGI_kanji_type      = 0xA000,
    DW_TAG_PGI_interface_block = 0xA020
  }
  DW_TAG;

#define DW_TAG_lo_user	0x4080
#define DW_TAG_hi_user	0xffff

/* Flag that tells whether entry has a child or not.  */
typedef enum
  {
    DW_children_no = 0,
    DW_children_yes = 1
  }
  DW_children;

/* Source language names and codes.  */
typedef enum dwarf_source_language
  {
    DW_LANG_C89 = 0x0001,
    DW_LANG_C = 0x0002,
    DW_LANG_Ada83 = 0x0003,
    DW_LANG_C_plus_plus = 0x0004,
    DW_LANG_Cobol74 = 0x0005,
    DW_LANG_Cobol85 = 0x0006,
    DW_LANG_Fortran77 = 0x0007,
    DW_LANG_Fortran90 = 0x0008,
    DW_LANG_Pascal83 = 0x0009,
    DW_LANG_Modula2 = 0x000a,
    /* DWARF 3.  */
    DW_LANG_Java = 0x000b,
    DW_LANG_C99 = 0x000c,
    DW_LANG_Ada95 = 0x000d,
    DW_LANG_Fortran95 = 0x000e,
    DW_LANG_PLI = 0x000f,
    DW_LANG_ObjC = 0x0010,
    DW_LANG_ObjC_plus_plus = 0x0011,
    DW_LANG_UPC = 0x0012,
    DW_LANG_D = 0x0013,
    /* MIPS.  */
    DW_LANG_Mips_Assembler = 0x8001,
    /* UPC.  */
    DW_LANG_Upc = 0x8765
  }
  DW_LANG;

/* Form names and codes.  */
typedef enum
  {
    DW_FORM_addr = 0x01,
    DW_FORM_block2 = 0x03,
    DW_FORM_block4 = 0x04,
    DW_FORM_data2 = 0x05,
    DW_FORM_data4 = 0x06,
    DW_FORM_data8 = 0x07,
    DW_FORM_string = 0x08,
    DW_FORM_block = 0x09,
    DW_FORM_block1 = 0x0a,
    DW_FORM_data1 = 0x0b,
    DW_FORM_flag = 0x0c,
    DW_FORM_sdata = 0x0d,
    DW_FORM_strp = 0x0e,
    DW_FORM_udata = 0x0f,
    DW_FORM_ref_addr = 0x10,
    DW_FORM_ref1 = 0x11,
    DW_FORM_ref2 = 0x12,
    DW_FORM_ref4 = 0x13,
    DW_FORM_ref8 = 0x14,
    DW_FORM_ref_udata = 0x15,
    DW_FORM_indirect = 0x16
  }
  DW_FORM;

/* Attribute names and codes.  */
typedef enum
  {
    DW_AT_sibling = 0x01,
    DW_AT_location = 0x02,
    DW_AT_name = 0x03,
    DW_AT_ordering = 0x09,
    DW_AT_subscr_data = 0x0a,
    DW_AT_byte_size = 0x0b,
    DW_AT_bit_offset = 0x0c,
    DW_AT_bit_size = 0x0d,
    DW_AT_element_list = 0x0f,
    DW_AT_stmt_list = 0x10,
    DW_AT_low_pc = 0x11,
    DW_AT_high_pc = 0x12,
    DW_AT_language = 0x13,
    DW_AT_member = 0x14,
    DW_AT_discr = 0x15,
    DW_AT_discr_value = 0x16,
    DW_AT_visibility = 0x17,
    DW_AT_import = 0x18,
    DW_AT_string_length = 0x19,
    DW_AT_common_reference = 0x1a,
    DW_AT_comp_dir = 0x1b,
    DW_AT_const_value = 0x1c,
    DW_AT_containing_type = 0x1d,
    DW_AT_default_value = 0x1e,
    DW_AT_inline = 0x20,
    DW_AT_is_optional = 0x21,
    DW_AT_lower_bound = 0x22,
    DW_AT_producer = 0x25,
    DW_AT_prototyped = 0x27,
    DW_AT_return_addr = 0x2a,
    DW_AT_start_scope = 0x2c,
    DW_AT_stride_size = 0x2e,
    DW_AT_upper_bound = 0x2f,
    DW_AT_abstract_origin = 0x31,
    DW_AT_accessibility = 0x32,
    DW_AT_address_class = 0x33,
    DW_AT_artificial = 0x34,
    DW_AT_base_types = 0x35,
    DW_AT_calling_convention = 0x36,
    DW_AT_count = 0x37,
    DW_AT_data_member_location = 0x38,
    DW_AT_decl_column = 0x39,
    DW_AT_decl_file = 0x3a,
    DW_AT_decl_line = 0x3b,
    DW_AT_declaration = 0x3c,
    DW_AT_discr_list = 0x3d,
    DW_AT_encoding = 0x3e,
    DW_AT_external = 0x3f,
    DW_AT_frame_base = 0x40,
    DW_AT_friend = 0x41,
    DW_AT_identifier_case = 0x42,
    DW_AT_macro_info = 0x43,
    DW_AT_namelist_items = 0x44,
    DW_AT_priority = 0x45,
    DW_AT_segment = 0x46,
    DW_AT_specification = 0x47,
    DW_AT_static_link = 0x48,
    DW_AT_type = 0x49,
    DW_AT_use_location = 0x4a,
    DW_AT_variable_parameter = 0x4b,
    DW_AT_virtuality = 0x4c,
    DW_AT_vtable_elem_location = 0x4d,
    /* DWARF 3 values.  */
    DW_AT_allocated     = 0x4e,
    DW_AT_associated    = 0x4f,
    DW_AT_data_location = 0x50,
    DW_AT_stride        = 0x51,
    DW_AT_entry_pc      = 0x52,
    DW_AT_use_UTF8      = 0x53,
    DW_AT_extension     = 0x54,
    DW_AT_ranges        = 0x55,
    DW_AT_trampoline    = 0x56,
    DW_AT_call_column   = 0x57,
    DW_AT_call_file     = 0x58,
    DW_AT_call_line     = 0x59,
    DW_AT_description   = 0x5a,
    DW_AT_binary_scale  = 0x5b,
    DW_AT_decimal_scale = 0x5c,
    DW_AT_small         = 0x5d,
    DW_AT_decimal_sign  = 0x5e,
    DW_AT_digit_count   = 0x5f,
    DW_AT_picture_string = 0x60,
    DW_AT_mutable       = 0x61,
    DW_AT_threads_scaled = 0x62,
    DW_AT_explicit      = 0x63,
    DW_AT_object_pointer = 0x64,
    DW_AT_endianity     = 0x65,
    DW_AT_elemental     = 0x66,
    DW_AT_pure          = 0x67,
    DW_AT_recursive     = 0x68,
    /* SGI/MIPS extensions.  */
    DW_AT_MIPS_fde = 0x2001,
    DW_AT_MIPS_loop_begin = 0x2002,
    DW_AT_MIPS_tail_loop_begin = 0x2003,
    DW_AT_MIPS_epilog_begin = 0x2004,
    DW_AT_MIPS_loop_unroll_factor = 0x2005,
    DW_AT_MIPS_software_pipeline_depth = 0x2006,
    DW_AT_MIPS_linkage_name = 0x2007,
    DW_AT_MIPS_stride = 0x2008,
    DW_AT_MIPS_abstract_name = 0x2009,
    DW_AT_MIPS_clone_origin = 0x200a,
    DW_AT_MIPS_has_inlines = 0x200b,
    /* HP extensions.  */
    DW_AT_HP_block_index         = 0x2000,
    DW_AT_HP_unmodifiable        = 0x2001, /* Same as DW_AT_MIPS_fde.  */
    DW_AT_HP_actuals_stmt_list   = 0x2010,
    DW_AT_HP_proc_per_section    = 0x2011,
    DW_AT_HP_raw_data_ptr        = 0x2012,
    DW_AT_HP_pass_by_reference   = 0x2013,
    DW_AT_HP_opt_level           = 0x2014,
    DW_AT_HP_prof_version_id     = 0x2015,
    DW_AT_HP_opt_flags           = 0x2016,
    DW_AT_HP_cold_region_low_pc  = 0x2017,
    DW_AT_HP_cold_region_high_pc = 0x2018,
    DW_AT_HP_all_variables_modifiable = 0x2019,
    DW_AT_HP_linkage_name        = 0x201a,
    DW_AT_HP_prof_flags          = 0x201b,  /* In comp unit of procs_info for -g.  */
    /* GNU extensions.  */
    DW_AT_sf_names   = 0x2101,
    DW_AT_src_info   = 0x2102,
    DW_AT_mac_info   = 0x2103,
    DW_AT_src_coords = 0x2104,
    DW_AT_body_begin = 0x2105,
    DW_AT_body_end   = 0x2106,
    DW_AT_GNU_vector = 0x2107,
    /* VMS extensions.  */
    DW_AT_VMS_rtnbeg_pd_address = 0x2201,
    /* UPC extension.  */
    DW_AT_upc_threads_scaled = 0x3210,
    /* PGI (STMicroelectronics) extensions.  */
    DW_AT_PGI_lbase    = 0x3a00,
    DW_AT_PGI_soffset  = 0x3a01,
    DW_AT_PGI_lstride  = 0x3a02
  }
  DW_AT;

#define DW_AT_lo_user	0x2000	/* Implementation-defined range start.  */
#define DW_AT_hi_user	0x3ff0	/* Implementation-defined range end.  */

/* Type encodings.  */
typedef enum
  {
    DW_ATE_void = 0x0,
    DW_ATE_address = 0x1,
    DW_ATE_boolean = 0x2,
    DW_ATE_complex_float = 0x3,
    DW_ATE_float = 0x4,
    DW_ATE_signed = 0x5,
    DW_ATE_signed_char = 0x6,
    DW_ATE_unsigned = 0x7,
    DW_ATE_unsigned_char = 0x8,
    /* DWARF 3.  */
    DW_ATE_imaginary_float = 0x9,
    DW_ATE_packed_decimal = 0xa,
    DW_ATE_numeric_string = 0xb,
    DW_ATE_edited = 0xc,
    DW_ATE_signed_fixed = 0xd,
    DW_ATE_unsigned_fixed = 0xe,
    DW_ATE_decimal_float = 0xf,
    /* HP extensions.  */
    DW_ATE_HP_float80            = 0x80, /* Floating-point (80 bit).  */
    DW_ATE_HP_complex_float80    = 0x81, /* Complex floating-point (80 bit).  */
    DW_ATE_HP_float128           = 0x82, /* Floating-point (128 bit).  */
    DW_ATE_HP_complex_float128   = 0x83, /* Complex floating-point (128 bit).  */
    DW_ATE_HP_floathpintel       = 0x84, /* Floating-point (82 bit IA64).  */
    DW_ATE_HP_imaginary_float80  = 0x85,
    DW_ATE_HP_imaginary_float128 = 0x86
  }
  DW_ATE;


/* Expression operations. */
typedef enum
  {
    DW_OP_addr = 0x03,
    DW_OP_deref = 0x06,
    DW_OP_const1u = 0x08,
    DW_OP_const1s = 0x09,
    DW_OP_const2u = 0x0a,
    DW_OP_const2s = 0x0b,
    DW_OP_const4u = 0x0c,
    DW_OP_const4s = 0x0d,
    DW_OP_const8u = 0x0e,
    DW_OP_const8s = 0x0f,
    DW_OP_constu = 0x10,
    DW_OP_consts = 0x11,
    DW_OP_dup = 0x12,
    DW_OP_drop = 0x13,
    DW_OP_over = 0x14,
    DW_OP_pick = 0x15,
    DW_OP_swap = 0x16,
    DW_OP_rot = 0x17,
    DW_OP_xderef = 0x18,
    DW_OP_abs = 0x19,
    DW_OP_and = 0x1a,
    DW_OP_div = 0x1b,
    DW_OP_minus = 0x1c,
    DW_OP_mod = 0x1d,
    DW_OP_mul = 0x1e,
    DW_OP_neg = 0x1f,
    DW_OP_not = 0x20,
    DW_OP_or = 0x21,
    DW_OP_plus = 0x22,
    DW_OP_plus_uconst = 0x23,
    DW_OP_shl = 0x24,
    DW_OP_shr = 0x25,
    DW_OP_shra = 0x26,
    DW_OP_xor = 0x27,
    DW_OP_bra = 0x28,
    DW_OP_eq = 0x29,
    DW_OP_ge = 0x2a,
    DW_OP_gt = 0x2b,
    DW_OP_le = 0x2c,
    DW_OP_lt = 0x2d,
    DW_OP_ne = 0x2e,
    DW_OP_skip = 0x2f,
    DW_OP_lit0 = 0x30,
    DW_OP_lit1 = 0x31,
    DW_OP_lit2 = 0x32,
    DW_OP_lit3 = 0x33,
    DW_OP_lit4 = 0x34,
    DW_OP_lit5 = 0x35,
    DW_OP_lit6 = 0x36,
    DW_OP_lit7 = 0x37,
    DW_OP_lit8 = 0x38,
    DW_OP_lit9 = 0x39,
    DW_OP_lit10 = 0x3a,
    DW_OP_lit11 = 0x3b,
    DW_OP_lit12 = 0x3c,
    DW_OP_lit13 = 0x3d,
    DW_OP_lit14 = 0x3e,
    DW_OP_lit15 = 0x3f,
    DW_OP_lit16 = 0x40,
    DW_OP_lit17 = 0x41,
    DW_OP_lit18 = 0x42,
    DW_OP_lit19 = 0x43,
    DW_OP_lit20 = 0x44,
    DW_OP_lit21 = 0x45,
    DW_OP_lit22 = 0x46,
    DW_OP_lit23 = 0x47,
    DW_OP_lit24 = 0x48,
    DW_OP_lit25 = 0x49,
    DW_OP_lit26 = 0x4a,
    DW_OP_lit27 = 0x4b,
    DW_OP_lit28 = 0x4c,
    DW_OP_lit29 = 0x4d,
    DW_OP_lit30 = 0x4e,
    DW_OP_lit31 = 0x4f,
    DW_OP_reg0 = 0x50,
    DW_OP_reg1 = 0x51,
    DW_OP_reg2 = 0x52,
    DW_OP_reg3 = 0x53,
    DW_OP_reg4 = 0x54,
    DW_OP_reg5 = 0x55,
    DW_OP_reg6 = 0x56,
    DW_OP_reg7 = 0x57,
    DW_OP_reg8 = 0x58,
    DW_OP_reg9 = 0x59,
    DW_OP_reg10 = 0x5a,
    DW_OP_reg11 = 0x5b,
    DW_OP_reg12 = 0x5c,
    DW_OP_reg13 = 0x5d,
    DW_OP_reg14 = 0x5e,
    DW_OP_reg15 = 0x5f,
    DW_OP_reg16 = 0x60,
    DW_OP_reg17 = 0x61,
    DW_OP_reg18 = 0x62,
    DW_OP_reg19 = 0x63,
    DW_OP_reg20 = 0x64,
    DW_OP_reg21 = 0x65,
    DW_OP_reg22 = 0x66,
    DW_OP_reg23 = 0x67,
    DW_OP_reg24 = 0x68,
    DW_OP_reg25 = 0x69,
    DW_OP_reg26 = 0x6a,
    DW_OP_reg27 = 0x6b,
    DW_OP_reg28 = 0x6c,
    DW_OP_reg29 = 0x6d,
    DW_OP_reg30 = 0x6e,
    DW_OP_reg31 = 0x6f,
    DW_OP_breg0 = 0x70,
    DW_OP_breg1 = 0x71,
    DW_OP_breg2 = 0x72,
    DW_OP_breg3 = 0x73,
    DW_OP_breg4 = 0x74,
    DW_OP_breg5 = 0x75,
    DW_OP_breg6 = 0x76,
    DW_OP_breg7 = 0x77,
    DW_OP_breg8 = 0x78,
    DW_OP_breg9 = 0x79,
    DW_OP_breg10 = 0x7a,
    DW_OP_breg11 = 0x7b,
    DW_OP_breg12 = 0x7c,
    DW_OP_breg13 = 0x7d,
    DW_OP_breg14 = 0x7e,
    DW_OP_breg15 = 0x7f,
    DW_OP_breg16 = 0x80,
    DW_OP_breg17 = 0x81,
    DW_OP_breg18 = 0x82,
    DW_OP_breg19 = 0x83,
    DW_OP_breg20 = 0x84,
    DW_OP_breg21 = 0x85,
    DW_OP_breg22 = 0x86,
    DW_OP_breg23 = 0x87,
    DW_OP_breg24 = 0x88,
    DW_OP_breg25 = 0x89,
    DW_OP_breg26 = 0x8a,
    DW_OP_breg27 = 0x8b,
    DW_OP_breg28 = 0x8c,
    DW_OP_breg29 = 0x8d,
    DW_OP_breg30 = 0x8e,
    DW_OP_breg31 = 0x8f,
    DW_OP_regx = 0x90,
    DW_OP_fbreg = 0x91,
    DW_OP_bregx = 0x92,
    DW_OP_piece = 0x93,
    DW_OP_deref_size = 0x94,
    DW_OP_xderef_size = 0x95,
    DW_OP_nop = 0x96,
    /* DWARF 3 extensions.  */
    DW_OP_push_object_address = 0x97,
    DW_OP_call2 = 0x98,
    DW_OP_call4 = 0x99,
    DW_OP_call_ref = 0x9a,
    DW_OP_form_tls_address = 0x9b,
    DW_OP_call_frame_cfa = 0x9c,
    DW_OP_bit_piece = 0x9d,
    /* GNU extensions.  */
    DW_OP_GNU_push_tls_address = 0xe0,
    /* HP extensions.  */
    DW_OP_HP_unknown     = 0xe0, /* Ouch, the same as GNU_push_tls_address.  */
    DW_OP_HP_is_value    = 0xe1,
    DW_OP_HP_fltconst4   = 0xe2,
    DW_OP_HP_fltconst8   = 0xe3,
    DW_OP_HP_mod_range   = 0xe4,
    DW_OP_HP_unmod_range = 0xe5,
    DW_OP_HP_tls         = 0xe6
  }
  DW_OP;


static HChar* pp_DW_children ( DW_children hashch )
{
   switch (hashch) {
      case DW_children_no:  return "no children";
      case DW_children_yes: return "has children";
      default:              return "DW_children_???";
   }
}

static HChar* pp_DW_TAG ( DW_TAG tag )
{
   switch (tag) {
      case DW_TAG_padding:            return "DW_TAG_padding";
      case DW_TAG_array_type:         return "DW_TAG_array_type";
      case DW_TAG_class_type:         return "DW_TAG_class_type";
      case DW_TAG_entry_point:        return "DW_TAG_entry_point";
      case DW_TAG_enumeration_type:   return "DW_TAG_enumeration_type";
      case DW_TAG_formal_parameter:   return "DW_TAG_formal_parameter";
      case DW_TAG_imported_declaration: 
         return "DW_TAG_imported_declaration";
      case DW_TAG_label:              return "DW_TAG_label";
      case DW_TAG_lexical_block:      return "DW_TAG_lexical_block";
      case DW_TAG_member:             return "DW_TAG_member";
      case DW_TAG_pointer_type:       return "DW_TAG_pointer_type";
      case DW_TAG_reference_type:     return "DW_TAG_reference_type";
      case DW_TAG_compile_unit:       return "DW_TAG_compile_unit";
      case DW_TAG_string_type:        return "DW_TAG_string_type";
      case DW_TAG_structure_type:     return "DW_TAG_structure_type";
      case DW_TAG_subroutine_type:    return "DW_TAG_subroutine_type";
      case DW_TAG_typedef:            return "DW_TAG_typedef";
      case DW_TAG_union_type:         return "DW_TAG_union_type";
      case DW_TAG_unspecified_parameters: 
         return "DW_TAG_unspecified_parameters";
      case DW_TAG_variant:            return "DW_TAG_variant";
      case DW_TAG_common_block:       return "DW_TAG_common_block";
      case DW_TAG_common_inclusion:   return "DW_TAG_common_inclusion";
      case DW_TAG_inheritance:        return "DW_TAG_inheritance";
      case DW_TAG_inlined_subroutine:
         return "DW_TAG_inlined_subroutine";
      case DW_TAG_module:             return "DW_TAG_module";
      case DW_TAG_ptr_to_member_type: return "DW_TAG_ptr_to_member_type";
      case DW_TAG_set_type:           return "DW_TAG_set_type";
      case DW_TAG_subrange_type:      return "DW_TAG_subrange_type";
      case DW_TAG_with_stmt:          return "DW_TAG_with_stmt";
      case DW_TAG_access_declaration: return "DW_TAG_access_declaration";
      case DW_TAG_base_type:          return "DW_TAG_base_type";
      case DW_TAG_catch_block:        return "DW_TAG_catch_block";
      case DW_TAG_const_type:         return "DW_TAG_const_type";
      case DW_TAG_constant:           return "DW_TAG_constant";
      case DW_TAG_enumerator:         return "DW_TAG_enumerator";
      case DW_TAG_file_type:          return "DW_TAG_file_type";
      case DW_TAG_friend:             return "DW_TAG_friend";
      case DW_TAG_namelist:           return "DW_TAG_namelist";
      case DW_TAG_namelist_item:      return "DW_TAG_namelist_item";
      case DW_TAG_packed_type:        return "DW_TAG_packed_type";
      case DW_TAG_subprogram:         return "DW_TAG_subprogram";
      case DW_TAG_template_type_param:
         return "DW_TAG_template_type_param";
      case DW_TAG_template_value_param:
         return "DW_TAG_template_value_param";
      case DW_TAG_thrown_type:        return "DW_TAG_thrown_type";
      case DW_TAG_try_block:          return "DW_TAG_try_block";
      case DW_TAG_variant_part:       return "DW_TAG_variant_part";
      case DW_TAG_variable:           return "DW_TAG_variable";
      case DW_TAG_volatile_type:      return "DW_TAG_volatile_type";
      /* DWARF 3.  */
      case DW_TAG_dwarf_procedure:    return "DW_TAG_dwarf_procedure";
      case DW_TAG_restrict_type:      return "DW_TAG_restrict_type";
      case DW_TAG_interface_type:     return "DW_TAG_interface_type";
      case DW_TAG_namespace:          return "DW_TAG_namespace";
      case DW_TAG_imported_module:    return "DW_TAG_imported_module";
      case DW_TAG_unspecified_type:   return "DW_TAG_unspecified_type";
      case DW_TAG_partial_unit:       return "DW_TAG_partial_unit";
      case DW_TAG_imported_unit:      return "DW_TAG_imported_unit";
      case DW_TAG_condition:          return "DW_TAG_condition";
      case DW_TAG_shared_type:        return "DW_TAG_shared_type";
      /* SGI/MIPS Extensions.  */
      case DW_TAG_MIPS_loop:          return "DW_TAG_MIPS_loop";
      /* HP extensions.  See:
         ftp://ftp.hp.com/pub/lang/tools/WDB/wdb-4.0.tar.gz .  */
      case DW_TAG_HP_array_descriptor:
         return "DW_TAG_HP_array_descriptor";
      /* GNU extensions.  */
      case DW_TAG_format_label:       return "DW_TAG_format_label";
      case DW_TAG_function_template:  return "DW_TAG_function_template";
      case DW_TAG_class_template:     return "DW_TAG_class_template";
      case DW_TAG_GNU_BINCL:          return "DW_TAG_GNU_BINCL";
      case DW_TAG_GNU_EINCL:          return "DW_TAG_GNU_EINCL";
      /* Extensions for UPC.  See: http://upc.gwu.edu/~upc.  */
      case DW_TAG_upc_shared_type:    return "DW_TAG_upc_shared_type";
      case DW_TAG_upc_strict_type:    return "DW_TAG_upc_strict_type";
      case DW_TAG_upc_relaxed_type:   return "DW_TAG_upc_relaxed_type";
      /* PGI (STMicroelectronics) extensions.  No documentation available.  */
      case DW_TAG_PGI_kanji_type:     return "DW_TAG_PGI_kanji_type";
      case DW_TAG_PGI_interface_block:
         return "DW_TAG_PGI_interface_block";
      default:                        return "DW_TAG_???";
   }
}

static HChar* pp_DW_FORM ( DW_FORM form )
{
   switch (form) {
      case DW_FORM_addr:      return "DW_FORM_addr";
      case DW_FORM_block2:    return "DW_FORM_block2";
      case DW_FORM_block4:    return "DW_FORM_block4";
      case DW_FORM_data2:     return "DW_FORM_data2";
      case DW_FORM_data4:     return "DW_FORM_data4";
      case DW_FORM_data8:     return "DW_FORM_data8";
      case DW_FORM_string:    return "DW_FORM_string";
      case DW_FORM_block:     return "DW_FORM_block";
      case DW_FORM_block1:    return "DW_FORM_block1";
      case DW_FORM_data1:     return "DW_FORM_data1";
      case DW_FORM_flag:      return "DW_FORM_flag";
      case DW_FORM_sdata:     return "DW_FORM_sdata";
      case DW_FORM_strp:      return "DW_FORM_strp";
      case DW_FORM_udata:     return "DW_FORM_udata";
      case DW_FORM_ref_addr:  return "DW_FORM_ref_addr";
      case DW_FORM_ref1:      return "DW_FORM_ref1";
      case DW_FORM_ref2:      return "DW_FORM_ref2";
      case DW_FORM_ref4:      return "DW_FORM_ref4";
      case DW_FORM_ref8:      return "DW_FORM_ref8";
      case DW_FORM_ref_udata: return "DW_FORM_ref_udata";
      case DW_FORM_indirect:  return "DW_FORM_indirect";
      default:                return "DW_FORM_???";
   }
}

static HChar* pp_DW_AT ( DW_AT attr )
{
   switch (attr) {
      case DW_AT_sibling:             return "DW_AT_sibling";
      case DW_AT_location:            return "DW_AT_location";
      case DW_AT_name: return "DW_AT_name";
      case DW_AT_ordering: return "DW_AT_ordering";
      case DW_AT_subscr_data: return "DW_AT_subscr_data";
      case DW_AT_byte_size: return "DW_AT_byte_size";
      case DW_AT_bit_offset: return "DW_AT_bit_offset";
      case DW_AT_bit_size: return "DW_AT_bit_size";
      case DW_AT_element_list: return "DW_AT_element_list";
      case DW_AT_stmt_list: return "DW_AT_stmt_list";
      case DW_AT_low_pc: return "DW_AT_low_pc";
      case DW_AT_high_pc: return "DW_AT_high_pc";
      case DW_AT_language: return "DW_AT_language";
      case DW_AT_member: return "DW_AT_member";
      case DW_AT_discr: return "DW_AT_discr";
      case DW_AT_discr_value: return "DW_AT_discr_value";
      case DW_AT_visibility: return "DW_AT_visibility";
      case DW_AT_import: return "DW_AT_import";
      case DW_AT_string_length: return "DW_AT_string_length";
      case DW_AT_common_reference: return "DW_AT_common_reference";
      case DW_AT_comp_dir: return "DW_AT_comp_dir";
      case DW_AT_const_value: return "DW_AT_const_value";
      case DW_AT_containing_type: return "DW_AT_containing_type";
      case DW_AT_default_value: return "DW_AT_default_value";
      case DW_AT_inline: return "DW_AT_inline";
      case DW_AT_is_optional: return "DW_AT_is_optional";
      case DW_AT_lower_bound: return "DW_AT_lower_bound";
      case DW_AT_producer: return "DW_AT_producer";
      case DW_AT_prototyped: return "DW_AT_prototyped";
      case DW_AT_return_addr: return "DW_AT_return_addr";
      case DW_AT_start_scope: return "DW_AT_start_scope";
      case DW_AT_stride_size: return "DW_AT_stride_size";
      case DW_AT_upper_bound: return "DW_AT_upper_bound";
      case DW_AT_abstract_origin: return "DW_AT_abstract_origin";
      case DW_AT_accessibility: return "DW_AT_accessibility";
      case DW_AT_address_class: return "DW_AT_address_class";
      case DW_AT_artificial: return "DW_AT_artificial";
      case DW_AT_base_types: return "DW_AT_base_types";
      case DW_AT_calling_convention: return "DW_AT_calling_convention";
      case DW_AT_count: return "DW_AT_count";
      case DW_AT_data_member_location: return "DW_AT_data_member_location";
      case DW_AT_decl_column: return "DW_AT_decl_column";
      case DW_AT_decl_file: return "DW_AT_decl_file";
      case DW_AT_decl_line: return "DW_AT_decl_line";
      case DW_AT_declaration: return "DW_AT_declaration";
      case DW_AT_discr_list: return "DW_AT_discr_list";
      case DW_AT_encoding: return "DW_AT_encoding";
      case DW_AT_external: return "DW_AT_external";
      case DW_AT_frame_base: return "DW_AT_frame_base";
      case DW_AT_friend: return "DW_AT_friend";
      case DW_AT_identifier_case: return "DW_AT_identifier_case";
      case DW_AT_macro_info: return "DW_AT_macro_info";
      case DW_AT_namelist_items: return "DW_AT_namelist_items";
      case DW_AT_priority: return "DW_AT_priority";
      case DW_AT_segment: return "DW_AT_segment";
      case DW_AT_specification: return "DW_AT_specification";
      case DW_AT_static_link: return "DW_AT_static_link";
      case DW_AT_type: return "DW_AT_type";
      case DW_AT_use_location: return "DW_AT_use_location";
      case DW_AT_variable_parameter: return "DW_AT_variable_parameter";
      case DW_AT_virtuality: return "DW_AT_virtuality";
      case DW_AT_vtable_elem_location: return "DW_AT_vtable_elem_location";
      /* DWARF 3 values.  */
      case DW_AT_allocated: return "DW_AT_allocated";
      case DW_AT_associated: return "DW_AT_associated";
      case DW_AT_data_location: return "DW_AT_data_location";
      case DW_AT_stride: return "DW_AT_stride";
      case DW_AT_entry_pc: return "DW_AT_entry_pc";
      case DW_AT_use_UTF8: return "DW_AT_use_UTF8";
      case DW_AT_extension: return "DW_AT_extension";
      case DW_AT_ranges: return "DW_AT_ranges";
      case DW_AT_trampoline: return "DW_AT_trampoline";
      case DW_AT_call_column: return "DW_AT_call_column";
      case DW_AT_call_file: return "DW_AT_call_file";
      case DW_AT_call_line: return "DW_AT_call_line";
      case DW_AT_description: return "DW_AT_description";
      case DW_AT_binary_scale: return "DW_AT_binary_scale";
      case DW_AT_decimal_scale: return "DW_AT_decimal_scale";
      case DW_AT_small: return "DW_AT_small";
      case DW_AT_decimal_sign: return "DW_AT_decimal_sign";
      case DW_AT_digit_count: return "DW_AT_digit_count";
      case DW_AT_picture_string: return "DW_AT_picture_string";
      case DW_AT_mutable: return "DW_AT_mutable";
      case DW_AT_threads_scaled: return "DW_AT_threads_scaled";
      case DW_AT_explicit: return "DW_AT_explicit";
      case DW_AT_object_pointer: return "DW_AT_object_pointer";
      case DW_AT_endianity: return "DW_AT_endianity";
      case DW_AT_elemental: return "DW_AT_elemental";
      case DW_AT_pure: return "DW_AT_pure";
      case DW_AT_recursive: return "DW_AT_recursive";
      /* SGI/MIPS extensions.  */
      /* case DW_AT_MIPS_fde: return "DW_AT_MIPS_fde"; */
      /* DW_AT_MIPS_fde == DW_AT_HP_unmodifiable */
      case DW_AT_MIPS_loop_begin: return "DW_AT_MIPS_loop_begin";
      case DW_AT_MIPS_tail_loop_begin: return "DW_AT_MIPS_tail_loop_begin";
      case DW_AT_MIPS_epilog_begin: return "DW_AT_MIPS_epilog_begin";
      case DW_AT_MIPS_loop_unroll_factor: return "DW_AT_MIPS_loop_unroll_factor";
      case DW_AT_MIPS_software_pipeline_depth: return "DW_AT_MIPS_software_pipeline_depth";
      case DW_AT_MIPS_linkage_name: return "DW_AT_MIPS_linkage_name";
      case DW_AT_MIPS_stride: return "DW_AT_MIPS_stride";
      case DW_AT_MIPS_abstract_name: return "DW_AT_MIPS_abstract_name";
      case DW_AT_MIPS_clone_origin: return "DW_AT_MIPS_clone_origin";
      case DW_AT_MIPS_has_inlines: return "DW_AT_MIPS_has_inlines";
      /* HP extensions.  */
      case DW_AT_HP_block_index: return "DW_AT_HP_block_index";
      case DW_AT_HP_unmodifiable: return "DW_AT_HP_unmodifiable";
      case DW_AT_HP_actuals_stmt_list: return "DW_AT_HP_actuals_stmt_list";
      case DW_AT_HP_proc_per_section: return "DW_AT_HP_proc_per_section";
      case DW_AT_HP_raw_data_ptr: return "DW_AT_HP_raw_data_ptr";
      case DW_AT_HP_pass_by_reference: return "DW_AT_HP_pass_by_reference";
      case DW_AT_HP_opt_level: return "DW_AT_HP_opt_level";
      case DW_AT_HP_prof_version_id: return "DW_AT_HP_prof_version_id";
      case DW_AT_HP_opt_flags: return "DW_AT_HP_opt_flags";
      case DW_AT_HP_cold_region_low_pc: return "DW_AT_HP_cold_region_low_pc";
      case DW_AT_HP_cold_region_high_pc: return "DW_AT_HP_cold_region_high_pc";
      case DW_AT_HP_all_variables_modifiable: return "DW_AT_HP_all_variables_modifiable";
      case DW_AT_HP_linkage_name: return "DW_AT_HP_linkage_name";
      case DW_AT_HP_prof_flags: return "DW_AT_HP_prof_flags";
      /* GNU extensions.  */
      case DW_AT_sf_names: return "DW_AT_sf_names";
      case DW_AT_src_info: return "DW_AT_src_info";
      case DW_AT_mac_info: return "DW_AT_mac_info";
      case DW_AT_src_coords: return "DW_AT_src_coords";
      case DW_AT_body_begin: return "DW_AT_body_begin";
      case DW_AT_body_end: return "DW_AT_body_end";
      case DW_AT_GNU_vector: return "DW_AT_GNU_vector";
      /* VMS extensions.  */
      case DW_AT_VMS_rtnbeg_pd_address: return "DW_AT_VMS_rtnbeg_pd_address";
      /* UPC extension.  */
      case DW_AT_upc_threads_scaled: return "DW_AT_upc_threads_scaled";
      /* PGI (STMicroelectronics) extensions.  */
      case DW_AT_PGI_lbase: return "DW_AT_PGI_lbase";
      case DW_AT_PGI_soffset: return "DW_AT_PGI_soffset";
      case DW_AT_PGI_lstride: return "DW_AT_PGI_lstride";
      default: return "DW_AT_???";
   }
}

////////////////////////////////////////////////////////////////

#define D3_INVALID_CUOFF  ((void*)(-1UL))
#define D3_FAKEVOID_CUOFF ((void*)(-2UL))

typedef  struct _D3TyAdmin   D3TyAdmin;
typedef  struct _D3TyAtom    D3TyAtom;
typedef  struct _D3TyField   D3TyField;
typedef  struct _D3TyBounds  D3TyBounds;
typedef  struct _D3Expr      D3Expr;
typedef  struct _D3Type      D3Type;

#define D3TyBounds_MAGIC 0x06ff1eb9UL

typedef
   enum { D3TyA_Atom=10, D3TyA_Field, 
          D3TyA_Bounds, D3TyA_Expr, D3TyA_Type } 
   D3TyAdminTag;

struct _D3TyAdmin {
   UWord        cuOff;
   void*        payload;
   D3TyAdmin*   next;
   D3TyAdminTag tag;
};

struct _D3TyAtom {
   UChar* name;
   Long   value;
};

struct _D3TyField {
   UChar*  name;
   D3Type* typeR;
   D3Expr* loc;
   Bool    isStruct;
};

struct _D3TyBounds {
   UInt magic;
   Bool knownL;
   Bool knownU;
   Long boundL;
   Long boundU;
};

struct _D3Expr {
   UChar* bytes;
   UWord  nbytes;
};

struct _D3Type {
   enum { D3Ty_Base=30, D3Ty_PorR, D3Ty_Ref, D3Ty_TyDef, D3Ty_StOrUn, 
          D3Ty_Enum, D3Ty_Array, D3Ty_Fn, D3Ty_Qual, D3Ty_Void } tag;
   union {
      struct {
         UChar* name;
         Int    szB;
         UChar  enc; /* S:signed U:unsigned F:floating */
      } Base;
      struct {
         Int     szB;
         D3Type* typeR;
         Bool    isPtr;
      } PorR;
      struct {
         UChar*  name;
         D3Type* typeR; /* MAY BE NULL, denoting unknown */
      } TyDef;
      struct {
         UChar*  name;
         UWord   szB;
         XArray* /* of D3TyField* */ fields;
         Bool    complete;
         Bool    isStruct;
      } StOrUn;
      struct {
         UChar*  name;
         Int     szB;
         XArray* /* of D3TyAtom* */ atomRs;
      } Enum;
      struct {
         D3Type* typeR;
         XArray* /* of D3TyBounds* */ bounds;
      } Array;
      struct {
      } Fn;
      struct {
         UChar   qual; /* C:const V:volatile */
         D3Type* typeR;
      } Qual;
      struct {
         Bool isFake; /* True == introduced by the reader */
      } Void;
   } D3Ty;
};

static D3TyAdmin* new_D3TyAdmin ( UWord cuOff, D3TyAdmin* next ) {
   D3TyAdmin* admin = dinfo_zalloc( sizeof(D3TyAdmin) );
   admin->cuOff = cuOff;
   admin->next  = next;
   return admin;
}
static D3TyAtom* new_D3TyAtom ( UChar* name, Long value ) {
   D3TyAtom* atom = dinfo_zalloc( sizeof(D3TyAtom) );
   atom->name  = name;
   atom->value = value;
   return atom;
}
static D3TyField* new_D3TyField ( UChar* name,
                                  D3Type* typeR, D3Expr* loc ) {
   D3TyField* field = dinfo_zalloc( sizeof(D3TyField) );
   field->name  = name;
   field->typeR = typeR;
   field->loc   = loc;
   return field;
}
static D3TyBounds* new_D3TyBounds ( void ) {
   D3TyBounds* bounds = dinfo_zalloc( sizeof(D3TyBounds) );
   bounds->magic = D3TyBounds_MAGIC;
   return bounds;
}
static D3Expr* new_D3Expr ( UChar* bytes, UWord nbytes ) {
   D3Expr* expr = dinfo_zalloc( sizeof(D3Expr) );
   expr->bytes = bytes;
   expr->nbytes = nbytes;
   return expr;
}
static D3Type* new_D3Type ( void ) {
   D3Type* type = dinfo_zalloc( sizeof(D3Type) );
   return type;
}

static void pp_XArray_of_pointersOrRefs ( XArray* xa ) {
   Word i;
   VG_(printf)("{");
   for (i = 0; i < VG_(sizeXA)(xa); i++) {
      void* ptr = *(void**) VG_(indexXA)(xa, i);
      VG_(printf)("0x%05lx", ptr);
      if (i+1 < VG_(sizeXA)(xa))
         VG_(printf)(",");
   }
   VG_(printf)("}");
}
static void pp_D3TyAtom ( D3TyAtom* atom ) {
   VG_(printf)("D3TyAtom(%lld,\"%s\")", atom->value, atom->name);
}
static void pp_D3Expr ( D3Expr* expr ) {
   VG_(printf)("D3Expr(%p,%lu)", expr->bytes, expr->nbytes);
}
static void pp_D3TyField ( D3TyField* field ) {
   VG_(printf)("D3TyField(0x%05lx,%p,\"%s\")",
               field->typeR, field->loc,
               field->name ? field->name : (UChar*)"");
}
static void pp_D3TyBounds ( D3TyBounds* bounds ) {
   vg_assert(bounds->magic == D3TyBounds_MAGIC);
   VG_(printf)("D3TyBounds[");
   if (bounds->knownL)
      VG_(printf)("%lld", bounds->boundL);
   else
      VG_(printf)("??");
   VG_(printf)(",");
   if (bounds->knownU)
      VG_(printf)("%lld", bounds->boundU);
   else
      VG_(printf)("??");
   VG_(printf)("]");
}

static void pp_D3TyBounds_C_ishly ( D3TyBounds* bounds ) {
   vg_assert(bounds->magic == D3TyBounds_MAGIC);
   if (bounds->knownL && bounds->knownU && bounds->boundL == 0) {
      VG_(printf)("[%lld]", 1 + bounds->boundU);
   }
   else
   if (bounds->knownL && (!bounds->knownU) && bounds->boundL == 0) {
      VG_(printf)("[]");
   }
   else
      pp_D3TyBounds( bounds );
}


static void pp_D3Type ( D3Type* ty )
{
   switch (ty->tag) {
      case D3Ty_Base:
         VG_(printf)("D3Ty_Base(%d,%c,\"%s\")",
                     ty->D3Ty.Base.szB, ty->D3Ty.Base.enc,
                     ty->D3Ty.Base.name ? ty->D3Ty.Base.name
                                        : (UChar*)"(null)" );
         break;
      case D3Ty_PorR:
         VG_(printf)("D3Ty_PorR(%d,%c,0x%05lx)",
                     ty->D3Ty.PorR.szB, 
                     ty->D3Ty.PorR.isPtr ? 'P' : 'R',
                     ty->D3Ty.PorR.typeR);
         break;
      case D3Ty_Enum:
         VG_(printf)("D3Ty_Enum(%d,%p,\"%s\")",
                     ty->D3Ty.Enum.szB, ty->D3Ty.Enum.atomRs,
                     ty->D3Ty.Enum.name ? ty->D3Ty.Enum.name
                                        : (UChar*)"" );
         if (ty->D3Ty.Enum.atomRs)
            pp_XArray_of_pointersOrRefs( ty->D3Ty.Enum.atomRs );
         break;
      case D3Ty_StOrUn:
         if (ty->D3Ty.StOrUn.complete) {
            VG_(printf)("D3Ty_StOrUn(%d,%c,%p,\"%s\")",
                        ty->D3Ty.StOrUn.szB, 
                        ty->D3Ty.StOrUn.isStruct ? 'S' : 'U',
                        ty->D3Ty.StOrUn.fields,
                        ty->D3Ty.StOrUn.name ? ty->D3Ty.StOrUn.name
                                             : (UChar*)"" );
            if (ty->D3Ty.StOrUn.fields)
               pp_XArray_of_pointersOrRefs( ty->D3Ty.StOrUn.fields );
         } else {
            VG_(printf)("D3Ty_StOrUn(INCOMPLETE,\"%s\")",
                        ty->D3Ty.StOrUn.name);
         }
         break;
      case D3Ty_Array:
         VG_(printf)("D3Ty_Array(0x%05lx,%p)",
                     ty->D3Ty.Array.typeR, ty->D3Ty.Array.bounds);
         if (ty->D3Ty.Array.bounds)
            pp_XArray_of_pointersOrRefs( ty->D3Ty.Array.bounds );
         break;
      case D3Ty_TyDef:
         VG_(printf)("D3Ty_TyDef(0x%05lx,\"%s\")",
                     ty->D3Ty.TyDef.typeR,
                     ty->D3Ty.TyDef.name ? ty->D3Ty.TyDef.name
                                         : (UChar*)"" );
         break;
      case D3Ty_Fn:
         VG_(printf)("D3Ty_Fn");
         break;
      case D3Ty_Qual:
         VG_(printf)("D3Ty_Qual(%c,0x%05lx)", ty->D3Ty.Qual.qual,
                     ty->D3Ty.Qual.typeR);
         break;
      case D3Ty_Void:
         VG_(printf)("D3Ty_Void%s",
                     ty->D3Ty.Void.isFake ? "(fake)" : "");
         break;
      default: VG_(printf)("pp_D3Type:???");
         break;
   }
}
static void pp_D3TyAdmin ( D3TyAdmin* admin ) {
  if (admin->cuOff != (UWord)D3_INVALID_CUOFF) {
      VG_(printf)("<%05lx,%p> ", admin->cuOff, admin->payload);
   } else {
      VG_(printf)("<INVAL,%p> ", admin->payload);
   }
   switch (admin->tag) {
      case D3TyA_Type:   pp_D3Type(admin->payload);       break;
      case D3TyA_Atom:   pp_D3TyAtom(admin->payload);     break;
      case D3TyA_Expr:   pp_D3Expr(admin->payload);       break;
      case D3TyA_Field:  pp_D3TyField(admin->payload);    break;
      case D3TyA_Bounds: pp_D3TyBounds(admin->payload);   break;
      default:           VG_(printf)("pp_D3TyAdmin:???"); break;
   }
}

/* NOTE: this assumes that the types have all been 'resolved' (that
   is, inter-type references expressed as .debug_info offsets have
   been converted into pointers) */
void ML_(pp_D3Type_C_ishly) ( void* /* D3Type* */ tyV )
{
   D3Type* ty = (D3Type*)tyV;

   switch (ty->tag) {
      case D3Ty_Base:
         if (!ty->D3Ty.Base.name) goto unhandled;
         VG_(printf)("%s", ty->D3Ty.Base.name);
         break;
      case D3Ty_PorR:
         ML_(pp_D3Type_C_ishly)(ty->D3Ty.PorR.typeR);
         VG_(printf)("%s", ty->D3Ty.PorR.isPtr ? "*" : "&");
         break;
      case D3Ty_Enum:
         if (!ty->D3Ty.Enum.name) goto unhandled;
         VG_(printf)("enum %s", ty->D3Ty.Enum.name);
         break;
      case D3Ty_StOrUn:
         if (!ty->D3Ty.StOrUn.name) goto unhandled;
         VG_(printf)("%s %s",
                     ty->D3Ty.StOrUn.isStruct ? "struct" : "union",
                     ty->D3Ty.StOrUn.name);
         break;
      case D3Ty_Array:
         ML_(pp_D3Type_C_ishly)(ty->D3Ty.Array.typeR);
         if (ty->D3Ty.Array.bounds) {
            Word    w;
            XArray* xa = ty->D3Ty.Array.bounds;
            for (w = 0; w < VG_(sizeXA)(xa); w++) {
               pp_D3TyBounds_C_ishly( *(D3TyBounds**)VG_(indexXA)(xa, w) );
            }
         } else {
            VG_(printf)("%s", "[??]");
         }
         break;
      case D3Ty_TyDef:
         if (!ty->D3Ty.TyDef.name) goto unhandled;
         VG_(printf)("%s", ty->D3Ty.TyDef.name);
         break;
      case D3Ty_Fn:
         VG_(printf)("%s", "<function_type>");
         break;
      case D3Ty_Qual:
         switch (ty->D3Ty.Qual.qual) {
            case 'C': VG_(printf)("const "); break;
            case 'V': VG_(printf)("volatile "); break;
            default: goto unhandled;
         }
         ML_(pp_D3Type_C_ishly)(ty->D3Ty.Qual.typeR);
         break;
      case D3Ty_Void:
         VG_(printf)("%svoid",
                     ty->D3Ty.Void.isFake ? "fake" : "");
         break;
      default: VG_(printf)("pp_D3Type_C_ishly:???");
         break;
   }
   return;

  unhandled:
   pp_D3Type(ty);
}


/* How big is this type?  (post-resolved only) */
/* FIXME: check all pointers before dereferencing */
SizeT ML_(sizeOfD3Type)( void* /* D3Type */ tyV )
{
   SizeT   eszB;
   Word    i;
   D3Type* ty = (D3Type*)tyV;
   switch (ty->tag) {
      case D3Ty_Base:
         return ty->D3Ty.Base.szB;
      case D3Ty_Qual:
         return ML_(sizeOfD3Type)( ty->D3Ty.Qual.typeR );
      case D3Ty_TyDef:
         if (!ty->D3Ty.TyDef.typeR)
            return 0; /*UNKNOWN*/
         return ML_(sizeOfD3Type)( ty->D3Ty.TyDef.typeR );
      case D3Ty_PorR:
         vg_assert(ty->D3Ty.PorR.szB == 4 || ty->D3Ty.PorR.szB == 8);
         return ty->D3Ty.PorR.szB;
      case D3Ty_StOrUn:
         return ty->D3Ty.StOrUn.szB;
      case D3Ty_Enum:
         return ty->D3Ty.Enum.szB;
      case D3Ty_Array:
         if (!ty->D3Ty.Array.typeR)
            return 0;
         eszB = ML_(sizeOfD3Type)( ty->D3Ty.Array.typeR );
         for (i = 0; i < VG_(sizeXA)( ty->D3Ty.Array.bounds ); i++) {
            D3TyBounds* bo
               = *(D3TyBounds**)VG_(indexXA)(ty->D3Ty.Array.bounds, i);
            vg_assert(bo);
            if (!(bo->knownL && bo->knownU))
               return 0;
            eszB *= (SizeT)( bo->boundU - bo->boundL + 1 );
         }
         return eszB;
      default:
         VG_(printf)("ML_(sizeOfD3Type): unhandled: ");
         pp_D3Type(tyV);
         VG_(printf)("\n");
         vg_assert(0);
   }
}


/*------------------------------------------------------------*/
/*--- The "new" DWARF3 reader                              ---*/
/*------------------------------------------------------------*/

typedef
   struct {
      UChar* region_start_img;
      UWord  region_szB;
      UWord  region_next;
      __attribute__((noreturn)) void (*barf)( HChar* );
      HChar* barfstr;
   }
   Cursor;

static inline Bool is_sane_Cursor ( Cursor* c ) {
   if (!c)                return False;
   if (!c->barf)          return False;
   if (!c->barfstr)       return False;
   return True;
}

static void init_Cursor ( Cursor* c,
                          UChar*  region_start_img,
                          UWord   region_szB,
                          UWord   region_next,
                          __attribute__((noreturn)) void (*barf)( HChar* ),
                          HChar*  barfstr )
{
   vg_assert(c);
   VG_(memset)(c, 0, sizeof(*c));
   c->region_start_img = region_start_img;
   c->region_szB       = region_szB;
   c->region_next      = region_next;
   c->barf             = barf;
   c->barfstr          = barfstr;
   vg_assert(is_sane_Cursor(c));
}

static Bool is_at_end_Cursor ( Cursor* c ) {
   vg_assert(is_sane_Cursor(c));
   return c->region_next >= c->region_szB;
}

static Word get_position_of_Cursor ( Cursor* c ) {
   vg_assert(is_sane_Cursor(c));
   return c->region_next;
}
static void set_position_of_Cursor ( Cursor* c, Word pos ) {
   c->region_next = pos;
   vg_assert(is_sane_Cursor(c));
}

static UChar* get_address_of_Cursor ( Cursor* c ) {
   vg_assert(is_sane_Cursor(c));
   return &c->region_start_img[ c->region_next ];
}

__attribute__((noreturn)) 
static void failWith ( Cursor* c, HChar* str ) {
   vg_assert(c);
   vg_assert(c->barf);
   c->barf(str);
   /*NOTREACHED*/
   vg_assert(0);
}

/* FIXME: document assumptions on endianness for
   get_UShort/UInt/ULong. */
static inline UChar get_UChar ( Cursor* c ) {
   UChar r;
   /* vg_assert(is_sane_Cursor(c)); */
   if (c->region_next + sizeof(UChar) > c->region_szB) {
      c->barf(c->barfstr);
      /*NOTREACHED*/
      vg_assert(0);
   }
   r = * (UChar*) &c->region_start_img[ c->region_next ];
   c->region_next += sizeof(UChar);
   return r;
}
static UShort get_UShort ( Cursor* c ) {
   UShort r;
   vg_assert(is_sane_Cursor(c));
   if (c->region_next + sizeof(UShort) > c->region_szB) {
      c->barf(c->barfstr);
      /*NOTREACHED*/
      vg_assert(0);
   }
   r = * (UShort*) &c->region_start_img[ c->region_next ];
   c->region_next += sizeof(UShort);
   return r;
}
static UInt get_UInt ( Cursor* c ) {
   UInt r;
   vg_assert(is_sane_Cursor(c));
   if (c->region_next + sizeof(UInt) > c->region_szB) {
      c->barf(c->barfstr);
      /*NOTREACHED*/
      vg_assert(0);
   }
   r = * (UInt*) &c->region_start_img[ c->region_next ];
   c->region_next += sizeof(UInt);
   return r;
}
static ULong get_ULong ( Cursor* c ) {
   ULong r;
   vg_assert(is_sane_Cursor(c));
   if (c->region_next + sizeof(ULong) > c->region_szB) {
      c->barf(c->barfstr);
      /*NOTREACHED*/
      vg_assert(0);
   }
   r = * (ULong*) &c->region_start_img[ c->region_next ];
   c->region_next += sizeof(ULong);
   return r;
}
static inline ULong get_ULEB128 ( Cursor* c ) {
   ULong result;
   Int   shift;
   UChar byte;
   /* unroll first iteration */
   byte = get_UChar( c );
   result = (ULong)(byte & 0x7f);
   if (LIKELY(!(byte & 0x80))) return result;
   shift = 7;
   /* end unroll first iteration */
   do {
      byte = get_UChar( c );
      result |= ((ULong)(byte & 0x7f)) << shift;
      shift += 7;
   } while (byte & 0x80);
   return result;
}
static Long get_SLEB128 ( Cursor* c ) {
   ULong  result = 0;
   Int    shift = 0;
   UChar  byte;
   do {
      byte = get_UChar(c);
      result |= ((ULong)(byte & 0x7f)) << shift;
      shift += 7;
   } while (byte & 0x80);
   if (shift < 64 && (byte & 0x40))
      result |= -(1ULL << shift);
   return result;
}

static ULong peek_ULEB128 ( Cursor* c ) {
   Word here = c->region_next;
   ULong r = get_ULEB128( c );
   c->region_next = here;
   return r;
}

static ULong get_Dwarfish_UWord ( Cursor* c, Bool is_dw64 ) {
   return is_dw64 ? get_ULong(c) : (ULong) get_UInt(c);
}

static UWord get_UWord ( Cursor* c ) {
   vg_assert(sizeof(UWord) == sizeof(void*));
   if (sizeof(UWord) == 4) return get_UInt(c);
   if (sizeof(UWord) == 8) return get_ULong(c);
   vg_assert(0);
}


#define N_ABBV_CACHE 32

/* Holds information that is constant through the parsing of a
   Compilation Unit.  This is basically plumbed through to
   everywhere. */
typedef
   struct {
      /* Call here if anything goes wrong */
      __attribute__((noreturn)) void (*barf)( HChar* );
      /* Is this 64-bit DWARF ? */
      Bool   is_dw64;
      /* Which DWARF version ?  (2 or 3) */
      UShort version;
      /* Length of this Compilation Unit, excluding its Header */
      ULong  unit_length;
      /* Offset of start of this unit in .debug_info */
      UWord  cu_start_offset;
      /* SVMA for this CU.  In the D3 spec, is known as the "base
         address of the compilation unit (last para sec 3.1.1).
         Needed for (amongst things) interpretation of location-list
         values. */
      Addr   cu_svma;
      Bool   cu_svma_known;
      /* The debug_abbreviations table to be used for this Unit */
      UChar* debug_abbv;
      /* Upper bound on size thereof (an overestimate, in general) */
      UWord  debug_abbv_maxszB;
      /* Where is .debug_str ? */
      UChar* debug_str_img;
      UWord  debug_str_sz;
      /* Where is .debug_ranges ? */
      UChar* debug_ranges_img;
      UWord  debug_ranges_sz;
      /* Where is .debug_loc ? */
      UChar* debug_loc_img;
      UWord  debug_loc_sz;
      /* --- a cache for set_abbv_Cursor --- */
      /* abbv_code == (ULong)-1 for an unused entry. */
      struct { ULong abbv_code; UWord posn; } saC_cache[N_ABBV_CACHE];
      UWord saC_cache_queries;
      UWord saC_cache_misses;
   }
   CUConst;


/* Read a DWARF3 'Initial Length' field */
static ULong get_Initial_Length ( /*OUT*/Bool* is64,
                                  Cursor* c, 
                                  HChar* barfMsg )
{
   ULong w64;
   UInt  w32;
   *is64 = False;
   w32 = get_UInt( c );
   if (w32 >= 0xFFFFFFF0 && w32 < 0xFFFFFFFF) {
      c->barf( barfMsg );
   }
   else if (w32 == 0xFFFFFFFF) {
      *is64 = True;
      w64   = get_ULong( c );
   } else {
      *is64 = False;
      w64 = (ULong)w32;
   }
   return w64;
}


/* Denotes an address range.  Both aMin and aMax are included in the
   range; hence a complete range is (0, ~0) and an empty range is any
   (X, X-1) for X > 0.*/
typedef 
   struct { Addr aMin; Addr aMax; }
   AddrRange;

static XArray* unitary_range_list ( Addr aMin, Addr aMax ) {
   XArray*   xa;
   AddrRange pair;
   vg_assert(aMin <= aMax);
   /* Who frees this xa?  varstack_preen() does. */
   xa = VG_(newXA)( dinfo_zalloc, dinfo_free, sizeof(AddrRange) );
   pair.aMin = aMin;
   pair.aMax = aMax;
   VG_(addToXA)( xa, &pair );
   return xa;
}

//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////
/// begin GUARDED EXPRESSIONS

/* Parse the location list starting at img-offset 'debug_loc_offset'
   in .debug_loc.  Results are biased with 'svma_of_referencing_CU'
   and so I believe are correct SVMAs for the object as a whole.  This
   function allocates the UChar*, and the caller must deallocate it.
   The resulting block is in so-called Guarded-Expression format.

   Guarded-Expression format is similar but not identical to the DWARF3
   location-list format.  The format of each returned block is:

      UChar biasMe;
      UChar isEnd;
      followed by zero or more of

      (Addr aMin;  Addr aMax;  UShort nbytes;  ..bytes..;  UChar isEnd)

   '..bytes..' is an standard DWARF3 location expression which is
   valid when aMin <= pc <= aMax (possibly after suitable biasing).

   The number of bytes in '..bytes..' is nbytes.

   The end of the sequence is marked by an isEnd == 1 value.  All
   previous isEnd values must be zero.

   biasMe is 1 if the aMin/aMax fields need this DebugInfo's
   text_bias added before use, and 0 if the GX is this is not
   necessary (is ready to go).

   Hence the block can be quickly parsed and is self-describing.  Note
   that aMax is 1 less than the corresponding value in a DWARF3
   location list.  Zero length ranges, with aMax == aMin-1, are not
   allowed.
*/
static void copy_bytes_into_XA ( XArray* /* of UChar */ xa, 
                                 void* bytes, Word nbytes ) {
   Word i;
   for (i = 0; i < nbytes; i++)
      VG_(addToXA)( xa, & ((UChar*)bytes)[i] );
}
void ML_(pp_GX) ( GExpr* gx ) {
   Addr   aMin, aMax;
   UChar  uc;
   UShort nbytes;
   UChar* p = &gx->payload[0];
   uc = *p++;
   VG_(printf)("GX(%s){", uc == 0 ? "final" : "Breqd" );
   vg_assert(uc == 0 || uc == 1);
   while (True) {
      uc = *p++;
      if (uc == 1)
         break; /*isEnd*/
      vg_assert(uc == 0);
      aMin   = * (Addr*)p;  p += sizeof(Addr);
      aMax   = * (Addr*)p;  p += sizeof(Addr);
      nbytes = * (UShort*)p; p += sizeof(UShort);
      VG_(printf)("[%p,%p]=", aMin, aMax);
      while (nbytes > 0) {
         VG_(printf)("%02x", (UInt)*p++);
         nbytes--;
      }
      if (*p == 0)
         VG_(printf)(",");
   }
   VG_(printf)("}");
}

static void bias_GX ( /*MOD*/GExpr* gx, Addr bias )
{
   UShort nbytes;
   UChar* p = &gx->payload[0];
   UChar  uc;
   uc = *p++; /*biasMe*/
   if (uc == 0)
      return;
   vg_assert(uc == 1);
   p[-1] = 0; /* mark it as done */
   while (True) {
      uc = *p++;
      if (uc == 1)
         break; /*isEnd*/
      vg_assert(uc == 0);
      * ((Addr*)p) += bias; /*aMin*/  p += sizeof(Addr);
      * ((Addr*)p) += bias; /*aMax*/  p += sizeof(Addr);
      nbytes = * (UShort*)p; p += sizeof(UShort);
      p += nbytes;
   }
}

/* FIXME: duplicated in readdwarf.c */
static 
ULong read_leb128 ( UChar* data, Int* length_return, Int sign )
{
  ULong  result = 0;
  UInt   num_read = 0;
  Int    shift = 0;
  UChar  byte;

  vg_assert(sign == 0 || sign == 1);

  do
    {
      byte = * data ++;
      num_read ++;

      result |= ((ULong)(byte & 0x7f)) << shift;

      shift += 7;

    }
  while (byte & 0x80);

  if (length_return != NULL)
    * length_return = num_read;

  if (sign && (shift < 64) && (byte & 0x40))
    result |= -(1ULL << shift);

  return result;
}

/* Small helper functions easier to use
 * value is returned and the given pointer is
 * moved past end of leb128 data */
/* FIXME: duplicated in readdwarf.c */
static ULong read_leb128U( UChar **data )
{
  Int len;
  ULong val = read_leb128( *data, &len, 0 );
  *data += len;
  return val;
}

/* Same for signed data */
/* FIXME: duplicated in readdwarf.c */
static Long read_leb128S( UChar **data )
{
   Int len;
   ULong val = read_leb128( *data, &len, 1 );
   *data += len;
   return (Long)val;
}

/* FIXME: duplicates logic in readdwarf.c: copy_convert_CfiExpr_tree
   and {FP,SP}_REG decls */
static Bool get_Dwarf_Reg( /*OUT*/Addr* a, Word regno, RegSummary* regs )
{
#  if defined(VGP_amd64_linux)
   if (regno == 6) { *a = regs->fp; return True; }
   if (regno == 7) { *a = regs->sp; return True; }
#  elif defined(VGP_x86_linux)
   if (regno == 5) { *a = regs->fp; return True; }
   if (regno == 4) { *a = regs->sp; return True; }
#  else
#    error "Unknown platform"
#  endif
   return False;
}


static
GXResult evaluate_Dwarf3_Expr ( UChar* expr, UWord exprszB, 
                                GExpr* fbGX, RegSummary* regs )
{
#  define N_EXPR_STACK 20

#  define FAIL(_str)                                       \
      do {                                                 \
         GXResult res;                                     \
         res.res = 0;                                      \
         res.failure = (_str);                             \
         return res;                                       \
      } while (0)

#  define PUSH(_arg)                                       \
      do {                                                 \
         vg_assert(sp >= -1 && sp < N_EXPR_STACK);         \
         if (sp == N_EXPR_STACK-1)                         \
            FAIL("evaluate_Dwarf3_Expr: stack overflow(1)");  \
         sp++;                                             \
         stack[sp] = (_arg);                               \
      } while (0)

#  define POP(_lval)                                       \
      do {                                                 \
         vg_assert(sp >= -1 && sp < N_EXPR_STACK);         \
         if (sp == -1)                                     \
            FAIL("evaluate_Dwarf3_Expr: stack underflow(1)"); \
         _lval = stack[sp];                                \
         sp--;                                             \
      } while (0)

   UChar    opcode;
   UChar*   limit;
   Int      sp; /* # of top element: valid is -1 .. N_EXPR_STACK-1 */
   Addr     stack[N_EXPR_STACK]; /* stack of addresses, as per D3 spec */
   GXResult fbval;
   Addr     a1;
   Word     sw1;

   sp = -1;
   vg_assert(expr);
   vg_assert(exprszB >= 0);
   limit = expr + exprszB;

   while (True) {

      vg_assert(sp >= -1 && sp < N_EXPR_STACK);

      if (expr > limit) 
         /* overrun - something's wrong */
         FAIL("evaluate_Dwarf3_Expr: ran off end of expr");

      if (expr == limit) {
         /* end of expr - return expr on the top of stack. */
         if (sp == -1)
            /* stack empty.  Bad. */
            FAIL("evaluate_Dwarf3_Expr: stack empty at end of expr");
         else
            break;
      }

      opcode = *expr++;
      switch (opcode) {
         case DW_OP_addr:
            /* FIXME: surely this is an svma?  Should be t- or d-
               biased before being pushed? */
            PUSH( *(Addr*)expr ); 
            expr += sizeof(Addr);
            break;
         case DW_OP_fbreg:
            if (!fbGX)
               FAIL("evaluate_Dwarf3_Expr: DW_OP_fbreg with "
                    "no expr for fbreg present");
            fbval = ML_(evaluate_GX)(fbGX, NULL, regs);
            if (fbval.failure)
               return fbval;
            sw1 = (Word)read_leb128S( &expr );
            PUSH( fbval.res + sw1 );
            break;
         case DW_OP_breg0 ... DW_OP_breg31:
            a1 = 0;
            if (!get_Dwarf_Reg( &a1, opcode - DW_OP_breg0, regs ))
               FAIL("evaluate_Dwarf3_Expr: unhandled DW_OP_breg*");
            sw1 = (Word)read_leb128S( &expr );
            a1 += sw1;
            PUSH( a1 );
            break;
         default:
            if (!VG_(clo_xml))
               VG_(message)(Vg_DebugMsg, 
                            "Warning: DWARF3 CFI reader: unhandled DW_OP_ "
                            "opcode 0x%x", (Int)opcode); 
            FAIL("evaluate_Dwarf3_Expr: unhandled DW_OP_");
      }

   }

   vg_assert(sp >= 0 && sp < N_EXPR_STACK);

   { GXResult res; 
     res.res = stack[sp];
     res.failure = NULL;
     return res;
   }

#  undef POP
#  undef PUSH
#  undef FAIL
#  undef N_EXPR_STACK
}

/* Evaluate a guarded expression, using 'ip' to select which of the
   embedded DWARF3 location expressions to use. */
GXResult ML_(evaluate_GX)( GExpr* gx, GExpr* fbGX, RegSummary* regs )
{
   GXResult res;
   Addr     aMin, aMax;
   UChar    uc;
   UShort   nbytes;
   UChar* p = &gx->payload[0];
   uc = *p++; /*biasMe*/
   vg_assert(uc == 0 || uc == 1);
   /* in fact it's senseless to evaluate if the guards need biasing.
      So don't. */
   vg_assert(uc == 0);
   while (True) {
      uc = *p++;
      if (uc == 1) { /*isEnd*/
         /* didn't find any matching range. */
         res.res = 0;
         res.failure = "no matching range";
         return res;
      }
      vg_assert(uc == 0);
      aMin   = * (Addr*)p;   p += sizeof(Addr);
      aMax   = * (Addr*)p;   p += sizeof(Addr);
      nbytes = * (UShort*)p; p += sizeof(UShort);
      if (aMin <= regs->ip && regs->ip <= aMax) {
         /* found a matching range.  Evaluate the expression. */
         return evaluate_Dwarf3_Expr( p, (UWord)nbytes, fbGX, regs );
      }
      /* else keep searching */
      p += (UWord)nbytes;
   }
}

__attribute__((noinline))
static GExpr* make_singleton_GX ( UChar* block, UWord nbytes )
{
   SizeT  bytesReqd;
   GExpr* gx;
   UChar *p, *pstart;

   vg_assert(sizeof(UWord) == sizeof(Addr));
   vg_assert(nbytes <= 0xFFFF); /* else we overflow the nbytes field */
   bytesReqd
      =   sizeof(UChar)  /*biasMe*/    + sizeof(UChar) /*!isEnd*/
        + sizeof(UWord)  /*aMin*/      + sizeof(UWord) /*aMax*/
        + sizeof(UShort) /*nbytes*/    + nbytes
        + sizeof(UChar); /*isEnd*/

   gx = dinfo_zalloc( sizeof(GExpr) + bytesReqd );
   vg_assert(gx);

   p = pstart = &gx->payload[0];

   * ((UChar*)p)  = 0;          /*biasMe*/ p += sizeof(UChar);
   * ((UChar*)p)  = 0;          /*!isEnd*/ p += sizeof(UChar);
   * ((Addr*)p)   = 0;          /*aMin*/   p += sizeof(Addr);
   * ((Addr*)p)   = ~((Addr)0); /*aMax */  p += sizeof(Addr);
   * ((UShort*)p) = (UShort)nbytes; /*nbytes*/ p += sizeof(UShort);
   VG_(memcpy)(p, block, nbytes); p += nbytes;
   * ((UChar*)p)  = 1;          /*isEnd*/  p += sizeof(UChar);

   vg_assert(p - pstart == bytesReqd);
   vg_assert( &gx->payload[bytesReqd] 
              == ((UChar*)gx) + sizeof(GExpr) + bytesReqd );

   gx->next = NULL;
   return gx;
}

__attribute__((noinline))
static GExpr* make_general_GX ( CUConst* cc,
                                Bool     td3,
                                UWord    debug_loc_offset,
                                Addr     svma_of_referencing_CU )
{
   Addr      base;
   Cursor    loc;
   XArray*   xa; /* XArray of UChar */
   GExpr*    gx;
   Word      nbytes;

   vg_assert(sizeof(UWord) == sizeof(Addr));
   if (cc->debug_loc_sz == 0)
      cc->barf("make_general_GX: .debug_loc is empty/missing");

   init_Cursor( &loc, cc->debug_loc_img, 
                cc->debug_loc_sz, 0, cc->barf,
                "Overrun whilst reading .debug_loc section(2)" );
   set_position_of_Cursor( &loc, (Word)debug_loc_offset );

   /* Who frees this xa?  It is freed before this fn exits. */
   xa = VG_(newXA)( dinfo_zalloc, dinfo_free, sizeof(UChar) );

   { UChar c = 1; /*biasMe*/ VG_(addToXA)( xa, &c ); }

   base = 0;
   while (True) {
      Bool  acquire;
      UWord len;
      /* Read a (host-)word pair.  This is something of a hack since
         the word size to read is really dictated by the ELF file;
         however, we assume we're reading a file with the same
         word-sizeness as the host.  Reasonably enough. */
      UWord w1 = get_UWord( &loc );
      UWord w2 = get_UWord( &loc );

      if (w1 == 0 && w2 == 0)
         break; /* end of list */

      if (w1 == -1UL) {
         /* new value for 'base' */
         base = w2;
         continue;
      }

      /* else a location expression follows */
      /* else enumerate [w1+base, w2+base) */
      /* w2 is 1 past end of range, as per D3 defn for "DW_AT_high_pc"
         (sec 2.17.2) */
      if (w1 > w2)
         cc->barf( "negative range in .debug_loc section" );
      /* ignore zero length ranges */
      acquire = w1 < w2;
      len     = (UWord)get_UShort( &loc );

      if (acquire) {
         UWord  w;
         UShort s;
         UChar  c;
         c = 0; /* !isEnd*/
         VG_(addToXA)( xa, &c );
         w = w1    + base + svma_of_referencing_CU;
         copy_bytes_into_XA( xa, &w, sizeof(w) );
         w = w2 -1 + base + svma_of_referencing_CU;
         copy_bytes_into_XA( xa, &w, sizeof(w) );
         s = (UShort)len;
         copy_bytes_into_XA( xa, &s, sizeof(s) );
      }

      while (len > 0) {
         UChar byte = get_UChar( &loc );
         TRACE_D3("%02x", (UInt)byte);
         if (acquire)
            VG_(addToXA)( xa, &byte );
         len--;
      }
      TRACE_D3("\n");
   }

   { UChar c = 1; /*isEnd*/ VG_(addToXA)( xa, &c ); }

   nbytes = VG_(sizeXA)( xa );
   vg_assert(nbytes >= 1);

   gx = dinfo_zalloc( sizeof(GExpr) + nbytes );
   vg_assert(gx);
   VG_(memcpy)( &gx->payload[0], (UChar*)VG_(indexXA)(xa,0), nbytes );
   vg_assert( &gx->payload[nbytes] 
              == ((UChar*)gx) + sizeof(GExpr) + nbytes );

   VG_(deleteXA)( xa );

   gx->next = NULL;
   return gx;
}

/// end GUARDED EXPRESSIONS
//////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////

__attribute__((noinline))
static XArray* /* of AddrRange */ empty_range_list ( void )
{
   XArray* xa; /* XArray of AddrRange */
   /* Who frees this xa?  varstack_preen() does. */
   xa = VG_(newXA)( dinfo_zalloc, dinfo_free, sizeof(AddrRange) );
   return xa;
}


/* Enumerate the address ranges starting at img-offset
   'debug_ranges_offset' in .debug_ranges.  Results are biased with
   'svma_of_referencing_CU' and so I believe are correct SVMAs for the
   object as a whole.  This function allocates the XArray, and the
   caller must deallocate it. */
__attribute__((noinline))
static XArray* /* of AddrRange */
       get_range_list ( CUConst* cc,
                        Bool     td3,
                        UWord    debug_ranges_offset,
                        Addr     svma_of_referencing_CU )
{
   Addr      base;
   Cursor    ranges;
   XArray*   xa; /* XArray of AddrRange */
   AddrRange pair;

   if (cc->debug_ranges_sz == 0)
      cc->barf("get_range_list: .debug_ranges is empty/missing");

   init_Cursor( &ranges, cc->debug_ranges_img, 
                cc->debug_ranges_sz, 0, cc->barf,
                "Overrun whilst reading .debug_ranges section(2)" );
   set_position_of_Cursor( &ranges, (Word)debug_ranges_offset );

   /* Who frees this xa?  varstack_preen() does. */
   xa = VG_(newXA)( dinfo_zalloc, dinfo_free, sizeof(AddrRange) );
   base = 0;
   while (True) {
      /* Read a (host-)word pair.  This is something of a hack since
         the word size to read is really dictated by the ELF file;
         however, we assume we're reading a file with the same
         word-sizeness as the host.  Reasonably enough. */
      UWord w1 = get_UWord( &ranges );
      UWord w2 = get_UWord( &ranges );

      if (w1 == 0 && w2 == 0)
         break; /* end of list. */

      if (w1 == -1UL) {
         /* new value for 'base' */
         base = w2;
         continue;
      }

      /* else enumerate [w1+base, w2+base) */
      /* w2 is 1 past end of range, as per D3 defn for "DW_AT_high_pc"
         (sec 2.17.2) */
      if (w1 > w2)
         cc->barf( "negative range in .debug_ranges section" );
      if (w1 < w2) {
         pair.aMin = w1     + base + svma_of_referencing_CU;
         pair.aMax = w2 - 1 + base + svma_of_referencing_CU;
         vg_assert(pair.aMin <= pair.aMax);
         VG_(addToXA)( xa, &pair );
      }
   }
   return xa;
}


/* Parse the Compilation Unit header indicated at 'c' and 
   initialise 'cc' accordingly. */
static __attribute__((noinline))
void parse_CU_Header ( /*OUT*/CUConst* cc,
                       Bool td3,
                       Cursor* c, 
                       UChar* debug_abbv_img, UWord debug_abbv_sz )
{
   UChar  address_size;
   UWord  debug_abbrev_offset;
   Int    i;

   VG_(memset)(cc, 0, sizeof(*cc));
   vg_assert(c && c->barf);
   cc->barf = c->barf;

   /* initial_length field */
   cc->unit_length 
      = get_Initial_Length( &cc->is_dw64, c, 
           "parse_CU_Header: invalid initial-length field" );

   TRACE_D3("   Length:        %lld\n", cc->unit_length );

   /* version */
   cc->version = get_UShort( c );
   if (cc->version != 2 && cc->version != 3)
      cc->barf( "parse_CU_Header: is neither DWARF2 nor DWARF3" );
   TRACE_D3("   Version:       %d\n", (Int)cc->version );

   /* debug_abbrev_offset */
   debug_abbrev_offset = get_Dwarfish_UWord( c, cc->is_dw64 );
   if (debug_abbrev_offset >= debug_abbv_sz)
      cc->barf( "parse_CU_Header: invalid debug_abbrev_offset" );
   TRACE_D3("   Abbrev Offset: %ld\n", debug_abbrev_offset );

   /* address size.  If this isn't equal to the host word size, just
      give up.  This makes it safe to assume elsewhere that
      DW_FORM_addr can be treated as a host word. */
   address_size = get_UChar( c );
   if (address_size != sizeof(void*))
      cc->barf( "parse_CU_Header: invalid address_size" );
   TRACE_D3("   Pointer Size:  %d\n", (Int)address_size );

   /* Set up so that cc->debug_abbv points to the relevant table for
      this CU.  Set the szB so that at least we can't read off the end
      of the debug_abbrev section -- potentially (and quite likely)
      too big, if this isn't the last table in the section, but at
      least it's safe. */
   cc->debug_abbv        = debug_abbv_img + debug_abbrev_offset;
   cc->debug_abbv_maxszB = debug_abbv_sz  - debug_abbrev_offset;
   /* and empty out the set_abbv_Cursor cache */
   if (0) VG_(printf)("XXXXXX initialise set_abbv_Cursor cache\n");
   for (i = 0; i < N_ABBV_CACHE; i++) {
      cc->saC_cache[i].abbv_code = (ULong)-1; /* unused */
      cc->saC_cache[i].posn = 0;
   }
   cc->saC_cache_queries = 0;
   cc->saC_cache_misses = 0;
}


/* Set up 'c' so it is ready to parse the abbv table entry code
   'abbv_code' for this compilation unit.  */
static __attribute__((noinline))
void set_abbv_Cursor ( /*OUT*/Cursor* c, Bool td3,
                       CUConst* cc, ULong abbv_code )
{
   Int   i;
   ULong acode;

   if (abbv_code == 0)
      cc->barf("set_abbv_Cursor: abbv_code == 0" );

   /* (ULong)-1 is used to represent an empty cache slot.  So we can't
      allow it.  In any case no valid DWARF3 should make a reference
      to a negative abbreviation code.  [at least, they always seem to
      be numbered upwards from zero as far as I have seen] */
   vg_assert(abbv_code != (ULong)-1);

   /* First search the cache. */
   if (0) VG_(printf)("XXXXXX search set_abbv_Cursor cache\n");
   cc->saC_cache_queries++;
   for (i = 0; i < N_ABBV_CACHE; i++) {
      /* No need to test the cached abbv_codes for -1 (empty), since
         we just asserted that abbv_code is not -1. */
     if (cc->saC_cache[i].abbv_code == abbv_code) {
        /* Found it.  Cool.  Set up the parser using the cached
           position, and move this cache entry 1 step closer to the
           front. */
        if (0) VG_(printf)("XXXXXX found in set_abbv_Cursor cache\n");
        init_Cursor( c, cc->debug_abbv,
                     cc->debug_abbv_maxszB, cc->saC_cache[i].posn, 
                     cc->barf,
                     "Overrun whilst parsing .debug_abbrev section(1)" );
        if (i > 0) {
           ULong t_abbv_code = cc->saC_cache[i].abbv_code;
           UWord t_posn = cc->saC_cache[i].posn;
           while (i > 0) {
              cc->saC_cache[i] = cc->saC_cache[i-1];
              cc->saC_cache[0].abbv_code = t_abbv_code;
              cc->saC_cache[0].posn = t_posn;
              i--;
           }
        }
        return;
     }
   }

   /* No.  It's not in the cache.  We have to search through
      .debug_abbrev, of course taking care to update the cache
      when done. */

   cc->saC_cache_misses++;
   init_Cursor( c, cc->debug_abbv, cc->debug_abbv_maxszB, 0, cc->barf,
               "Overrun whilst parsing .debug_abbrev section(2)" );

   /* Now iterate though the table until we find the requested
      entry. */
   while (True) {
      ULong atag;
      UInt  has_children;
      acode = get_ULEB128( c );
      if (acode == 0) break; /* end of the table */
      if (acode == abbv_code) break; /* found it */
      atag         = get_ULEB128( c );
      has_children = get_UChar( c );
      //TRACE_D3("   %llu      %s    [%s]\n", 
      //         acode, pp_DW_TAG(atag), pp_DW_children(has_children));
      while (True) {
         ULong at_name = get_ULEB128( c );
         ULong at_form = get_ULEB128( c );
         if (at_name == 0 && at_form == 0) break;
         //TRACE_D3("    %18s %s\n", 
         //         pp_DW_AT(at_name), pp_DW_FORM(at_form));
      }
   }

   if (acode == 0) {
      /* Not found.  This is fatal. */
      cc->barf("set_abbv_Cursor: abbv_code not found");
   }

   /* Otherwise, 'c' is now set correctly to parse the relevant entry,
      starting from the abbreviation entry's tag.  So just cache
      the result, and return. */
   for (i = N_ABBV_CACHE-1; i > N_ABBV_CACHE/2; i--) {
      cc->saC_cache[i] = cc->saC_cache[i-1];
   }
   if (0) VG_(printf)("XXXXXX update set_abbv_Cursor cache\n");
   cc->saC_cache[N_ABBV_CACHE/2].abbv_code = abbv_code;
   cc->saC_cache[N_ABBV_CACHE/2].posn = get_position_of_Cursor(c);
}


/* From 'c', get the Form data into the lowest 1/2/4/8 bytes of *cts.

   If *cts itself contains the entire result, then *ctsSzB is set to
   1,2,4 or 8 accordingly and *ctsMemSzB is set to zero.

   Alternatively, the result can be a block of data (in the
   transiently mapped-in object, so-called "image" space).  If so then
   the lowest sizeof(void*)/8 bytes of *cts hold a pointer to said
   image, *ctsSzB is zero, and *ctsMemSzB is the size of the block.

   Unfortunately this means it is impossible to represent a zero-size
   image block since that would have *ctsSzB == 0 and *ctsMemSzB == 0
   and so is ambiguous (which case it is?)

   Invariant on successful return: 
      (*ctsSzB > 0 && *ctsMemSzB == 0)
      || (*ctsSzB == 0 && *ctsMemSzB > 0)
*/
static
void get_Form_contents ( /*OUT*/ULong* cts,
                         /*OUT*/Int*   ctsSzB,
                         /*OUT*/UWord* ctsMemSzB,
                         CUConst* cc, Cursor* c,
                         Bool td3, DW_FORM form )
{
   *cts       = 0;
   *ctsSzB    = 0;
   *ctsMemSzB = 0;
   switch (form) {
      case DW_FORM_data1:
         *cts = (ULong)(UChar)get_UChar(c);
         *ctsSzB = 1;
         TRACE_D3("%u", (UInt)*cts);
         break;
      case DW_FORM_data2:
         *cts = (ULong)(UShort)get_UShort(c);
         *ctsSzB = 2;
         TRACE_D3("%u", (UInt)*cts);
         break;
      case DW_FORM_data4:
         *cts = (ULong)(UInt)get_UInt(c);
         *ctsSzB = 4;
         TRACE_D3("%u", (UInt)*cts);
         break;
      case DW_FORM_sdata:
         *cts = (ULong)(Long)get_SLEB128(c);
         *ctsSzB = 8;
         TRACE_D3("%lld", (Long)*cts);
         break;
      case DW_FORM_addr:
         /* note, this is a hack.  DW_FORM_addr is defined as getting
            a word the size of the target machine as defined by the
            address_size field in the CU Header.  However,
            parse_CU_Header() rejects all inputs except those for
            which address_size == sizeof(Word), hence we can just
            treat it as a (host) Word.  */
         *cts = (ULong)(UWord)get_UWord(c);
         *ctsSzB = sizeof(UWord);
         TRACE_D3("0x%lx", (UWord)*cts);
         break;
      case DW_FORM_strp: {
         /* this is an offset into .debug_str */
         UChar* str;
         UWord uw = (UWord)get_Dwarfish_UWord( c, cc->is_dw64 );
         if (cc->debug_str_img == NULL || uw >= cc->debug_str_sz)
            cc->barf("read_and_show_Form: DW_FORM_strp "
                     "points outside .debug_str");
         /* FIXME: check the entire string lies inside debug_str,
            not just the first byte of it. */
         str = (UChar*)cc->debug_str_img + uw;
         TRACE_D3("(indirect string, offset: 0x%lx): %s", uw, str);
         *cts = (ULong)(UWord)str;
         *ctsMemSzB = 1 + (ULong)VG_(strlen)(str);
         break;
      }
      case DW_FORM_string: {
         UInt u32;
         UChar* str = get_address_of_Cursor(c);
         do { u32 = get_UChar(c); } while (u32 != 0);
         TRACE_D3("%s", str);
         *cts = (ULong)(UWord)str;
         /* strlen is safe because get_UChar already 'vetted' the
            entire string */
         *ctsMemSzB = 1 + (ULong)VG_(strlen)(str);
         break;
      }
      case DW_FORM_ref4: {
         UInt  u32 = get_UInt(c);
         UWord res = cc->cu_start_offset + (UWord)u32;
         *cts = (ULong)res;
         *ctsSzB = sizeof(UWord);
         TRACE_D3("<%lx>", res);
         break;
      }
      case DW_FORM_flag: {
         UChar u8 = get_UChar(c);
         TRACE_D3("%u", (UInt)u8);
         *cts = (ULong)u8;
         *ctsSzB = 1;
         break;
      }
      case DW_FORM_block1: {
         ULong  u64b;
         ULong  u64 = (ULong)get_UChar(c);
         UChar* block = get_address_of_Cursor(c);
         TRACE_D3("%llu byte block: ", u64);
         for (u64b = u64; u64b > 0; u64b--) {
            UChar u8 = get_UChar(c);
            TRACE_D3("%x ", (UInt)u8);
         }
         *cts = (ULong)(UWord)block;
         *ctsMemSzB = (UWord)u64;
         break;
      }
      default:
         VG_(printf)("get_Form_contents: unhandled %lld (%s)\n",
                     form, pp_DW_FORM(form));
         c->barf("get_Form_contents: unhandled DW_FORM");
   }
}


/////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////
// Variable location parser

typedef
   struct _TempVar {
      struct _TempVar* next;
      UChar*  name; /* in AR_DINFO */
      Addr    pcMin;
      Addr    pcMax;
      Int     level;
      D3Type* typeR;
      GExpr*  gexpr; /* for this variable */
      GExpr*  fbGX;  /* to find the frame base of the enclosing fn, if
                        any */
   }
   TempVar;

#define N_D3_VAR_STACK 16

typedef
   struct {
      /* Contains the range stack: a stack of address ranges, one
         stack entry for each nested scope.  

         Some scope entries are created by function definitions
         (DW_AT_subprogram), and for those, we also note the GExpr
         derived from its DW_AT_frame_base attribute, if any.
         Consequently it should be possible to find, for any
         variable's DIE, the GExpr for the the containing function's
         DW_AT_frame_base by scanning back through the stack to find
         the nearest entry associated with a function.  This somewhat
         elaborate scheme is provided so as to make it possible to
         obtain the correct DW_AT_frame_base expression even in the
         presence of nested functions (or to be more precise, in the
         presence of nested DW_AT_subprogram DIEs). 
      */
      Int     sp; /* [sp] is innermost active entry; sp==-1 for empty
                     stack */
      XArray* ranges[N_D3_VAR_STACK]; /* XArray of AddrRange */
      Int     level[N_D3_VAR_STACK];  /* D3 DIE levels */
      Bool    isFunc[N_D3_VAR_STACK]; /* from DW_AT_subprogram? */
      GExpr*  fbGX[N_D3_VAR_STACK];   /* if isFunc, contains the FB
                                         expr, else NULL */
   }
   D3VarParser;

static void varstack_show ( D3VarParser* parser, HChar* str ) {
   Word i, j;
   VG_(printf)("  varstack (%s) {\n", str);
   for (i = 0; i <= parser->sp; i++) {
      XArray* xa = parser->ranges[i];
      vg_assert(xa);
      VG_(printf)("    [%ld] (level %d)", i, parser->level[i]);
      if (parser->isFunc[i]) {
         VG_(printf)(" (fbGX=%p)", parser->fbGX[i]);
      } else {
         vg_assert(parser->fbGX[i] == NULL);
      }
      VG_(printf)(": ");
      for (j = 0; j < VG_(sizeXA)( xa ); j++) {
         AddrRange* range = (AddrRange*) VG_(indexXA)( xa, j );
         vg_assert(range);
         VG_(printf)("[%p,%p] ", range->aMin, range->aMax);
      }
      VG_(printf)("\n");
   }
   VG_(printf)("  }\n");
}

/* Remove from the stack, all entries with .level > 'level' */
static 
void varstack_preen ( D3VarParser* parser, Bool td3, Int level )
{
   Bool changed = False;
   vg_assert(parser->sp < N_D3_VAR_STACK);
   while (True) {
      vg_assert(parser->sp >= -1);
      if (parser->sp == -1) break;
      if (parser->level[parser->sp] <= level) break;
      if (0) 
         TRACE_D3("BBBBAAAA varstack_pop [newsp=%d]\n", parser->sp-1);
      vg_assert(parser->ranges[parser->sp]);
      /* Who allocated this xa?  get_range_list() or
         unitary_range_list(). */
      VG_(deleteXA)( parser->ranges[parser->sp] );
      parser->ranges[parser->sp] = NULL;
      parser->level[parser->sp]  = 0;
      parser->isFunc[parser->sp] = False;
      parser->fbGX[parser->sp]   = NULL;
      parser->sp--;
      changed = True;
   }
   if (changed && td3)
      varstack_show( parser, "after preen" );
}

static void varstack_push ( CUConst* cc,
                            D3VarParser* parser,
                            Bool td3,
                            XArray* ranges, Int level,
                            Bool    isFunc, GExpr* fbGX ) {
   if (0)
   TRACE_D3("BBBBAAAA varstack_push[newsp=%d]: %d  %p\n",
            parser->sp+1, level, ranges);

   /* First we need to zap everything >= 'level', as we are about to
      replace any previous entry at 'level', so .. */
   varstack_preen(parser, /*td3*/False, level-1);

   vg_assert(parser->sp >= -1);
   vg_assert(parser->sp < N_D3_VAR_STACK);
   if (parser->sp == N_D3_VAR_STACK-1)
      cc->barf("varstack_push: N_D3_VAR_STACK is too low; "
               "increase and recompile");
   if (parser->sp >= 0)
      vg_assert(parser->level[parser->sp] < level);
   parser->sp++;
   vg_assert(parser->ranges[parser->sp] == NULL);
   vg_assert(parser->level[parser->sp]  == 0);
   vg_assert(parser->isFunc[parser->sp] == False);
   vg_assert(parser->fbGX[parser->sp]   == NULL);
   vg_assert(ranges != NULL);
   if (!isFunc) vg_assert(fbGX == NULL);
   parser->ranges[parser->sp] = ranges;
   parser->level[parser->sp]  = level;
   parser->isFunc[parser->sp] = isFunc;
   parser->fbGX[parser->sp]   = fbGX;
   if (td3)
      varstack_show( parser, "after push" );
}


/* cts, ctsSzB, ctsMemSzB are derived from a DW_AT_location and so
   refer either to a location expression or to a location list.
   Figure out which, and in both cases bundle the expression or
   location list into a so-called GExpr (guarded expression. */
__attribute__((noinline))
static GExpr* get_GX ( CUConst* cc, Bool td3, 
                       ULong cts, Int ctsSzB, UWord ctsMemSzB )
{
   GExpr* gexpr = NULL;
   if (ctsMemSzB > 0 && ctsSzB == 0) {
      /* represents an in-line location expression, and cts points
         right at it */
      gexpr = make_singleton_GX( (UChar*)(UWord)cts, ctsMemSzB );
   }
   else 
   if (ctsMemSzB == 0 && ctsSzB > 0) {
      /* represents location list.  cts is the offset of it in
         .debug_loc. */
      if (!cc->cu_svma_known)
         cc->barf("get_GX: location list, but CU svma is unknown");
      gexpr = make_general_GX( cc, td3, (UWord)cts, cc->cu_svma );
   }
   else {
      vg_assert(0); /* else caller is bogus */
   }
   return gexpr;
}

__attribute__((noinline))
static void parse_var_DIE ( /*OUT*/TempVar** tempvars,
                            /*OUT*/GExpr** gexprs,
                            /*MOD*/D3VarParser* parser,
                            DW_TAG dtag,
                            UWord posn,
                            Int level,
                            Cursor* c_die,
                            Cursor* c_abbv,
                            CUConst* cc,
                            Bool td3 )
{
   ULong       cts;
   Int         ctsSzB;
   UWord       ctsMemSzB;

   Word saved_die_c_offset  = get_position_of_Cursor( c_die );
   Word saved_abbv_c_offset = get_position_of_Cursor( c_abbv );

   varstack_preen( parser, td3, level );

   if (dtag == DW_TAG_compile_unit) {
      Bool have_lo    = False;
      Bool have_hi1   = False;
      Bool have_range = False;
      Addr ip_lo    = 0;
      Addr ip_hi1   = 0;
      Addr rangeoff = 0;
      while (True) {
         DW_AT   attr = (DW_AT)  get_ULEB128( c_abbv );
         DW_FORM form = (DW_FORM)get_ULEB128( c_abbv );
         if (attr == 0 && form == 0) break;
         get_Form_contents( &cts, &ctsSzB, &ctsMemSzB,
                            cc, c_die, False/*td3*/, form );
         if (attr == DW_AT_low_pc && ctsSzB > 0) {
            ip_lo   = cts;
            have_lo = True;
         }
         if (attr == DW_AT_high_pc && ctsSzB > 0) {
            ip_hi1   = cts;
            have_hi1 = True;
         }
         if (attr == DW_AT_ranges && ctsSzB > 0) {
            rangeoff = cts;
            have_range = True;
         }
      }
      /* Now, does this give us an opportunity to find this
         CU's svma? */
#if 0
      if (level == 0 && have_lo) {
         vg_assert(!cc->cu_svma_known); /* if this fails, it must be
         because we've already seen a DW_TAG_compile_unit DIE at level
         0.  But that can't happen, because DWARF3 only allows exactly
         one top level DIE per CU. */
         cc->cu_svma_known = True;
         cc->cu_svma = ip_lo;
         if (1)
            TRACE_D3("BBBBAAAA acquire CU_SVMA of %p\n", cc->cu_svma);
         /* Now, it may be that this DIE doesn't tell us the CU's
            SVMA, by way of not having a DW_AT_low_pc.  That's OK --
            the CU doesn't *have* to have its SVMA specified.

            But as per last para D3 spec sec 3.1.1 ("Normal and
            Partial Compilation Unit Entries", "If the base address
            (viz, the SVMA) is undefined, then any DWARF entry of
            structure defined interms of the base address of that
            compilation unit is not valid.".  So that means, if whilst
            processing the children of this top level DIE (or their
            children, etc) we see a DW_AT_range, and cu_svma_known is
            False, then the DIE that contains it is (per the spec)
            invalid, and we can legitimately stop and complain. */
      }
#else
      if (level == 0) {
         vg_assert(!cc->cu_svma_known);
         cc->cu_svma_known = True;
         if (have_lo)
            cc->cu_svma = ip_lo;
         else
            cc->cu_svma = 0;
      }
#endif
      /* Do we have something that looks sane? */
      if (have_lo && have_hi1 && (!have_range)) {
         if (ip_lo < ip_hi1)
            varstack_push( cc, parser, td3, 
                           unitary_range_list(ip_lo, ip_hi1 - 1),
                           level,
                           False/*isFunc*/, NULL/*fbGX*/ );
      } else
      if ((!have_lo) && (!have_hi1) && have_range) {
         varstack_push( cc, parser, td3, 
                        get_range_list( cc, td3,
                                        rangeoff, cc->cu_svma ),
                        level,
                        False/*isFunc*/, NULL/*fbGX*/ );
      } else
      if ((!have_lo) && (!have_hi1) && (!have_range)) {
         /* CU has no code, presumably? */
         varstack_push( cc, parser, td3, 
                        empty_range_list(),
                        level,
                        False/*isFunc*/, NULL/*fbGX*/ );
      } else
         goto bad_DIE;
   }

   if (dtag == DW_TAG_lexical_block || dtag == DW_TAG_subprogram) {
      Bool   have_lo    = False;
      Bool   have_hi1   = False;
      Bool   have_range = False;
      Addr   ip_lo      = 0;
      Addr   ip_hi1     = 0;
      Addr   rangeoff   = 0;
      Bool   isFunc     = dtag == DW_TAG_subprogram;
      GExpr* fbGX       = NULL;
      while (True) {
         DW_AT   attr = (DW_AT)  get_ULEB128( c_abbv );
         DW_FORM form = (DW_FORM)get_ULEB128( c_abbv );
         if (attr == 0 && form == 0) break;
         get_Form_contents( &cts, &ctsSzB, &ctsMemSzB,
                            cc, c_die, False/*td3*/, form );
         if (attr == DW_AT_low_pc && ctsSzB > 0) {
            ip_lo   = cts;
            have_lo = True;
         }
         if (attr == DW_AT_high_pc && ctsSzB > 0) {
            ip_hi1   = cts;
            have_hi1 = True;
         }
         if (attr == DW_AT_ranges && ctsSzB > 0) {
            rangeoff = cts;
            have_range = True;
         }
         if (isFunc
             && attr == DW_AT_frame_base
             && ((ctsMemSzB > 0 && ctsSzB == 0)
                 || (ctsMemSzB == 0 && ctsSzB > 0))) {
            fbGX = get_GX( cc, False/*td3*/, cts, ctsSzB, ctsMemSzB );
            vg_assert(fbGX);
            vg_assert(!fbGX->next);
            fbGX->next = *gexprs;
            *gexprs = fbGX;
         }
      }
      /* Do we have something that looks sane? */
      if (dtag == DW_TAG_subprogram 
          && (!have_lo) && (!have_hi1) && (!have_range)) {
         /* This is legit - ignore it. Sec 3.3.3: "A subroutine entry
            representing a subroutine declaration that is not also a
            definition does not have code address or range
            attributes." */
      } else
      if (dtag == DW_TAG_lexical_block
          && (!have_lo) && (!have_hi1) && (!have_range)) {
         /* I believe this is legit, and means the lexical block
            contains no insns (whatever that might mean).  Ignore. */
      } else
      if (have_lo && have_hi1 && (!have_range)) {
         /* This scope supplies just a single address range. */
         if (ip_lo < ip_hi1)
            varstack_push( cc, parser, td3, 
                           unitary_range_list(ip_lo, ip_hi1 - 1),
                           level, isFunc, fbGX );
      } else
      if ((!have_lo) && (!have_hi1) && have_range) {
         /* This scope supplies multiple address ranges via the use of
            a range list. */
         varstack_push( cc, parser, td3, 
                        get_range_list( cc, td3,
                                        rangeoff, cc->cu_svma ),
                        level, isFunc, fbGX );
      } else
         goto bad_DIE;
   }

   if (dtag == DW_TAG_variable || dtag == DW_TAG_formal_parameter) {
      UChar*  name        = NULL;
      D3Type* typeR       = D3_INVALID_CUOFF;
      Bool    external    = False;
      GExpr*  gexpr       = NULL;
      Int     n_attrs     = 0;
      Bool    has_abs_ori = False;
      Bool    declaration = False;
      while (True) {
         DW_AT   attr = (DW_AT)  get_ULEB128( c_abbv );
         DW_FORM form = (DW_FORM)get_ULEB128( c_abbv );
         if (attr == 0 && form == 0) break;
         get_Form_contents( &cts, &ctsSzB, &ctsMemSzB,
                            cc, c_die, False/*td3*/, form );
         n_attrs++;
         if (attr == DW_AT_name && ctsMemSzB > 0) {
            name = dinfo_strdup( (UChar*)(UWord)cts );
         }
         if (attr == DW_AT_location
             && ((ctsMemSzB > 0 && ctsSzB == 0)
                 || (ctsMemSzB == 0 && ctsSzB > 0))) {
            gexpr = get_GX( cc, False/*td3*/, cts, ctsSzB, ctsMemSzB );
            vg_assert(gexpr);
            vg_assert(!gexpr->next);
            gexpr->next = *gexprs;
            *gexprs = gexpr;
         }
         if (attr == DW_AT_type && ctsSzB > 0) {
            typeR = (D3Type*)(UWord)cts;
         }
         if (attr == DW_AT_external && ctsSzB > 0 && cts > 0) {
            external = True;
         }
         if (attr == DW_AT_abstract_origin && ctsSzB > 0) {
            has_abs_ori = True;
         }
         if (attr == DW_AT_declaration && ctsSzB > 0 && cts > 0) {
            declaration = True;
         }
      }
      /* We'll collect it if it has a type and a location.  Doesn't
         even have to have a name. */
      if (gexpr && typeR != D3_INVALID_CUOFF) {
         /* Add this variable to the set of variables associated with
            each address range at the top of the stack. */
         GExpr*  fbGX = NULL;
         Word    i;
         XArray* /* of AddrRange */ xa;
         /* Stack can't be empty; we put a dummy entry on it for the
            entire address range before starting with the DIEs for
            this CU. */
         vg_assert(parser->sp >= 0);

         if (!name)
            name = dinfo_strdup( dtag == DW_TAG_variable 
                                 ? "<anon_variable>" : "<anon_formal>" );

	 /* If this is a local variable (non-external), try to find
            the GExpr for the DW_AT_frame_base of the containing
            function.  It should have been pushed on the stack at the
            time we encountered its DW_TAG_subprogram DIE, so the way
            to find it is to scan back down the stack looking for it.
            If there isn't an enclosing stack entry marked 'isFunc'
            then we must be seeing variable or formal param DIEs
            outside of a function, so we deem the Dwarf to be
            malformed if that happens.  Note that the fbGX may be NULL
            if the containing DT_TAG_subprogram didn't supply a
            DW_AT_frame_base -- that's OK, but there must actually be
            a containing DW_TAG_subprogram. */
         if (!external) {
            Bool found = False;
            for (i = parser->sp; i >= 0; i--) {
               if (parser->isFunc[i]) {
                  fbGX = parser->fbGX[i];
                  found = True;
                  break;
               }
            }
            if (!found) {
               VG_(printf)(
                  "parse_var_DIE: found non-external variable "
                  "outside DW_TAG_subprogram\n");
	       // FIXME             goto bad_DIE;
            }
         }

         /* re "external ? 0 : parser->sp" (twice), if the var is
            marked 'external' then we must put it at the global scope,
            as only the global scope (level 0) covers the entire PC
            address space.  It is asserted elsewhere that level 0 
            always covers the entire address space. */
         xa = parser->ranges[external ? 0 : parser->sp];
         for (i = 0; i < VG_(sizeXA)( xa ); i++) {
            AddrRange* r = (AddrRange*) VG_(indexXA)( xa, i );
            TempVar* tv = dinfo_zalloc( sizeof(TempVar) );
            tv->name  = name;
            tv->pcMin = r->aMin;
            tv->pcMax = r->aMax;
            tv->level = external ? 0 : parser->sp;
            tv->typeR = typeR;
            tv->gexpr = gexpr;
            tv->fbGX  = fbGX;
            tv->next  = *tempvars;
            *tempvars = tv;
         }
         TRACE_D3("  Recording this variable, with %ld PC range(s)\n",
                  VG_(sizeXA)(xa) );
      }
#if 0
      else
      if ((dtag == DW_TAG_variable || dtag == DW_TAG_formal_parameter)
          && name && typeR != D3_INVALID_CUOFF && !gexpr) {
         /* We have a variable with a name and a type, but no
            location.  I guess that's a sign that it has been
            optimised away.  Ignore it.  Here's an example:

            static Int lc_compar(void* n1, void* n2) {
               MC_Chunk* mc1 = *(MC_Chunk**)n1;
               MC_Chunk* mc2 = *(MC_Chunk**)n2;
               return (mc1->data < mc2->data ? -1 : 1);
            }

            Both mc1 and mc2 are like this
            <2><5bc>: Abbrev Number: 21 (DW_TAG_variable)
                DW_AT_name        : mc1
                DW_AT_decl_file   : 1
                DW_AT_decl_line   : 216
                DW_AT_type        : <5d3>

            whereas n1 and n2 do have locations specified.
         */
         /* ignore */
      }
      else 
      if (dtag == DW_TAG_formal_parameter
          && typeR != D3_INVALID_CUOFF && !name && !gexpr) {
         /* We see a DW_TAG_formal_parameter with a type, but
            no name and no location.  It's probably part of a function type
            construction, thusly, hence ignore it:
         <1><2b4>: Abbrev Number: 12 (DW_TAG_subroutine_type)
             DW_AT_sibling     : <2c9>
             DW_AT_prototyped  : 1
             DW_AT_type        : <114>
         <2><2be>: Abbrev Number: 13 (DW_TAG_formal_parameter)
             DW_AT_type        : <13e>
         <2><2c3>: Abbrev Number: 13 (DW_TAG_formal_parameter)
             DW_AT_type        : <133>
	*/
        /* ignore */
      }
      else
      if ((dtag == DW_TAG_variable || dtag == DW_TAG_formal_parameter)
          && has_abs_ori && n_attrs == 1) {
         /* Is very minimal, like this:
            <4><81d>: Abbrev Number: 44 (DW_TAG_variable)
                DW_AT_abstract_origin: <7ba>
            What that signifies I have no idea.  Ignore. */
         /* ignore */
      }
      else
      if ((dtag == DW_TAG_variable || dtag == DW_TAG_formal_parameter)
          && has_abs_ori && gexpr && n_attrs == 2) {
         /* Is very minimal, like this:
            <200f>: DW_TAG_formal_parameter
                DW_AT_abstract_ori: <1f4c>
                DW_AT_location    : 13440
            What that signifies I have no idea.  Ignore. 
            It might be significant, though: the variable at least
            has a location and so might exist somewhere.
            Maybe we should handle this.*/
         /* ignore */
      }
      else
      if (dtag == DW_TAG_variable && declaration && !gexpr) {
         /* <22407>: DW_TAG_variable
              DW_AT_name        : (indirect string, offset: 0x6579):
                                  vgPlain_trampoline_stuff_start
              DW_AT_decl_file   : 29
              DW_AT_decl_line   : 56
              DW_AT_external    : 1
              DW_AT_declaration : 1
         */
         /* ignore */
      }
      else
      if (dtag == DW_TAG_variable && gexpr && n_attrs == 1) {
         /* Nameless and typeless variable that has a location?  Who
            knows.  Not me.
            <2><3d178>: Abbrev Number: 22 (DW_TAG_variable)
                 DW_AT_location    : 9 byte block: 3 c0 c7 13 38 0 0 0 0
                                     (DW_OP_addr: 3813c7c0)
         */
         /* ignore */
      }
      else
      if (dtag == DW_TAG_variable && n_attrs == 0) {
         /* No, really.  Check it out.  gcc is quite simply borked.
            <3><168cc>: Abbrev Number: 141 (DW_TAG_variable)
            // followed by no attributes, and the next DIE is a sibling,
            // not a child
         */
         /* ignore */
      }
      else
         goto bad_DIE;
#endif
   }

   return;

  bad_DIE:
   set_position_of_Cursor( c_die,  saved_die_c_offset );
   set_position_of_Cursor( c_abbv, saved_abbv_c_offset );
   VG_(printf)("\nparse_var_DIE: confused by:\n");
   VG_(printf)(" <%d><%lx>: %s\n", level, posn, pp_DW_TAG( dtag ) );
   while (True) {
      DW_AT   attr = (DW_AT)  get_ULEB128( c_abbv );
      DW_FORM form = (DW_FORM)get_ULEB128( c_abbv );
      if (attr == 0 && form == 0) break;
      VG_(printf)("     %18s: ", pp_DW_AT(attr));
      /* Get the form contents, so as to print them */
      get_Form_contents( &cts, &ctsSzB, &ctsMemSzB,
                         cc, c_die, True, form );
      VG_(printf)("\t\n");
   }
   VG_(printf)("\n");
   cc->barf("parse_var_DIE: confused by the above DIE");
   /*NOTREACHED*/
}


/////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////
// Type parser.  Sometimes maintains a pointer to a type
// currently under construction.

#define N_D3_TYPE_STACK 16

typedef
   struct {
      /* What source language?  'C'=C/C++, 'F'=Fortran, '?'=other
	 Established once per compilation unit. */
      UChar language;
      /* A stack of types which are currently under construction */
      Int     sp; /* [sp] is innermost active entry; sp==-1 for empty
                     stack */
      D3Type* qparent[N_D3_TYPE_STACK];
      Int     qlevel[N_D3_TYPE_STACK];

   }
   D3TypeParser;

static void typestack_show ( D3TypeParser* parser, HChar* str ) {
   Word i;
   VG_(printf)("  typestack (%s) {\n", str);
   for (i = 0; i <= parser->sp; i++) {
      VG_(printf)("    [%ld] (level %d): ", i, parser->qlevel[i]);
      pp_D3Type( parser->qparent[i] );
      VG_(printf)("\n");
   }
   VG_(printf)("  }\n");
}

/* Remove from the stack, all entries with .level > 'level' */
static 
void typestack_preen ( D3TypeParser* parser, Bool td3, Int level )
{
   Bool changed = False;
   vg_assert(parser->sp < N_D3_TYPE_STACK);
   while (True) {
      vg_assert(parser->sp >= -1);
      if (parser->sp == -1) break;
      if (parser->qlevel[parser->sp] <= level) break;
      if (0) 
         TRACE_D3("BBBBAAAA typestack_pop [newsp=%d]\n", parser->sp-1);
      vg_assert(parser->qparent[parser->sp]);
      parser->qparent[parser->sp] = NULL;
      parser->qlevel[parser->sp]  = 0;
      parser->sp--;
      changed = True;
   }
   if (changed && td3)
      typestack_show( parser, "after preen" );
}

static Bool typestack_is_empty ( D3TypeParser* parser ) {
   vg_assert(parser->sp >= -1 && parser->sp < N_D3_TYPE_STACK);
   return parser->sp == -1;
}

static void typestack_push ( CUConst* cc,
                             D3TypeParser* parser,
                             Bool td3,
                             D3Type* parent, Int level ) {
   if (0)
   TRACE_D3("BBBBAAAA typestack_push[newsp=%d]: %d  %p\n",
            parser->sp+1, level, parent);

   /* First we need to zap everything >= 'level', as we are about to
      replace any previous entry at 'level', so .. */
   typestack_preen(parser, /*td3*/False, level-1);

   vg_assert(parser->sp >= -1);
   vg_assert(parser->sp < N_D3_TYPE_STACK);
   if (parser->sp == N_D3_TYPE_STACK-1)
      cc->barf("typestack_push: N_D3_TYPE_STACK is too low; "
               "increase and recompile");
   if (parser->sp >= 0)
      vg_assert(parser->qlevel[parser->sp] < level);
   parser->sp++;
   vg_assert(parser->qparent[parser->sp] == NULL);
   vg_assert(parser->qlevel[parser->sp]  == 0);
   vg_assert(parent != NULL);
   parser->qparent[parser->sp] = parent;
   parser->qlevel[parser->sp]  = level;
   if (td3)
      typestack_show( parser, "after push" );
}



/* Parse a type-related DIE.  'parser' holds the current parser state.
   'admin' is where the completed types are dumped.  'dtag' is the tag
   for this DIE.  'c_die' points to the start of the data fields (FORM
   stuff) for the DIE.  c_abbv points to the start of the (name,form)
   pairs which describe the DIE.

   We may find the DIE uninteresting, in which case we should ignore
   it.
*/
__attribute__((noinline))
static void parse_type_DIE ( /*OUT*/D3TyAdmin** admin,
                             /*MOD*/D3TypeParser* parser,
                             DW_TAG dtag,
                             UWord posn,
                             Int level,
                             Cursor* c_die,
                             Cursor* c_abbv,
                             CUConst* cc,
                             Bool td3 )
{
   ULong       cts;
   Int         ctsSzB;
   UWord       ctsMemSzB;
   D3Type*     type   = NULL;
   D3TyAtom*   atom   = NULL;
   D3TyField*  field  = NULL;
   D3Expr*     expr   = NULL;
   D3TyBounds* bounds = NULL;

   Word saved_die_c_offset  = get_position_of_Cursor( c_die );
   Word saved_abbv_c_offset = get_position_of_Cursor( c_abbv );

   /* If we've returned to a level at or above any previously noted
      parent, un-note it, so we don't believe we're still collecting
      its children. */
   typestack_preen( parser, td3, level-1 );

   if (dtag == DW_TAG_base_type
       || dtag == DW_TAG_pointer_type
       || dtag == DW_TAG_reference_type
       || dtag == DW_TAG_typedef
       || dtag == DW_TAG_array_type
       || dtag == DW_TAG_subrange_type
       || dtag == DW_TAG_enumeration_type
       || dtag == DW_TAG_structure_type
       || dtag == DW_TAG_union_type) {
      if (0) 
         TRACE_D3("YYYYXXXX offset=%ld %s\n", posn, pp_DW_TAG(dtag));
   }

   if (dtag == DW_TAG_compile_unit) {
      /* See if we can find DW_AT_language, since it is important for
         establishing array bounds (see DW_TAG_subrange_type below in
         this fn) */
      while (True) {
         DW_AT   attr = (DW_AT)  get_ULEB128( c_abbv );
         DW_FORM form = (DW_FORM)get_ULEB128( c_abbv );
         if (attr == 0 && form == 0) break;
         get_Form_contents( &cts, &ctsSzB, &ctsMemSzB,
                            cc, c_die, False/*td3*/, form );
         if (attr != DW_AT_language)
            continue;
         if (ctsSzB == 0)
           goto bad_DIE;
         switch (cts) {
            case DW_LANG_C89: case DW_LANG_C:
            case DW_LANG_C_plus_plus: case DW_LANG_ObjC:
            case DW_LANG_ObjC_plus_plus: case DW_LANG_UPC:
            case DW_LANG_Upc:
               parser->language = 'C'; break;
            case DW_LANG_Fortran77: case DW_LANG_Fortran90:
            case DW_LANG_Fortran95:
               parser->language = 'F'; break;
            case DW_LANG_Ada83: case DW_LANG_Cobol74:
            case DW_LANG_Cobol85: case DW_LANG_Pascal83:
            case DW_LANG_Modula2: case DW_LANG_Java:
            case DW_LANG_C99: case DW_LANG_Ada95:
            case DW_LANG_PLI: case DW_LANG_D:
            case DW_LANG_Mips_Assembler:
               parser->language = '?'; break;
            default:
               goto bad_DIE;
         }
      }
   }

   if (dtag == DW_TAG_base_type) {
      /* We can pick up a new base type any time. */
      type = new_D3Type();
      type->tag = D3Ty_Base;
      while (True) {
         DW_AT   attr = (DW_AT)  get_ULEB128( c_abbv );
         DW_FORM form = (DW_FORM)get_ULEB128( c_abbv );
         if (attr == 0 && form == 0) break;
         get_Form_contents( &cts, &ctsSzB, &ctsMemSzB,
                            cc, c_die, False/*td3*/, form );
         if (attr == DW_AT_name && ctsMemSzB > 0) {
            type->D3Ty.Base.name = dinfo_strdup( (UChar*)(UWord)cts );
         }
         if (attr == DW_AT_byte_size && ctsSzB > 0) {
            type->D3Ty.Base.szB = cts;
         }
         if (attr == DW_AT_encoding && ctsSzB > 0) {
            switch (cts) {
               case DW_ATE_unsigned: case DW_ATE_unsigned_char:
               case DW_ATE_boolean:/* FIXME - is this correct? */
                  type->D3Ty.Base.enc = 'U'; break;
               case DW_ATE_signed: case DW_ATE_signed_char:
                  type->D3Ty.Base.enc = 'S'; break;
               case DW_ATE_float:
                  type->D3Ty.Base.enc = 'F'; break;
               default:
                  goto bad_DIE;
            }
         }
      }
      /* Do we have something that looks sane? */
      if (/* must have a name */
          type->D3Ty.Base.name == NULL
          /* and a plausible size */
          || type->D3Ty.Base.szB < 1 || type->D3Ty.Base.szB > 16
          /* and a plausible encoding */
          || (type->D3Ty.Base.enc != 'U'
              && type->D3Ty.Base.enc != 'S' 
              && type->D3Ty.Base.enc != 'F'))
         goto bad_DIE;
      else
         goto acquire_Type;
   }

   if (dtag == DW_TAG_pointer_type || dtag == DW_TAG_reference_type) {
      type = new_D3Type();
      type->tag = D3Ty_PorR;
      /* target type defaults to void */
      type->D3Ty.PorR.typeR = D3_FAKEVOID_CUOFF;
      type->D3Ty.PorR.isPtr = dtag == DW_TAG_pointer_type;
      while (True) {
         DW_AT   attr = (DW_AT)  get_ULEB128( c_abbv );
         DW_FORM form = (DW_FORM)get_ULEB128( c_abbv );
         if (attr == 0 && form == 0) break;
         get_Form_contents( &cts, &ctsSzB, &ctsMemSzB,
                            cc, c_die, False/*td3*/, form );
         if (attr == DW_AT_byte_size && ctsSzB > 0) {
            type->D3Ty.PorR.szB = cts;
         }
         if (attr == DW_AT_type && ctsSzB > 0) {
            type->D3Ty.PorR.typeR = (D3Type*)(UWord)cts;
         }
      }
      /* Do we have something that looks sane? */
      if (type->D3Ty.PorR.szB != sizeof(Word))
         goto bad_DIE;
      else
         goto acquire_Type;
   }

   if (dtag == DW_TAG_enumeration_type) {
      /* Create a new D3Type to hold the results. */
      type = new_D3Type();
      type->tag = D3Ty_Enum;
      type->D3Ty.Enum.name = NULL;
      type->D3Ty.Enum.atomRs
         = VG_(newXA)( dinfo_zalloc, dinfo_free, sizeof(D3TyAtom*) );
      while (True) {
         DW_AT   attr = (DW_AT)  get_ULEB128( c_abbv );
         DW_FORM form = (DW_FORM)get_ULEB128( c_abbv );
         if (attr == 0 && form == 0) break;
         get_Form_contents( &cts, &ctsSzB, &ctsMemSzB,
                            cc, c_die, False/*td3*/, form );
         if (attr == DW_AT_name && ctsMemSzB > 0) {
            type->D3Ty.Enum.name = dinfo_strdup( (UChar*)(UWord)cts );
         }
         if (attr == DW_AT_byte_size && ctsSzB > 0) {
            type->D3Ty.Enum.szB = cts;
         }
      }
      /* Do we have something that looks sane? */
      if (type->D3Ty.Enum.szB == 0 /* we must know the size */
          /* But the name can be present, or not */)
         goto bad_DIE;
      /* On't stack! */
      typestack_push( cc, parser, td3, type, level );
      goto acquire_Type;
   }

   if (dtag == DW_TAG_enumerator) {
      Bool have_value = False;
      atom = new_D3TyAtom( NULL, 0 );
      while (True) {
         DW_AT   attr = (DW_AT)  get_ULEB128( c_abbv );
         DW_FORM form = (DW_FORM)get_ULEB128( c_abbv );
         if (attr == 0 && form == 0) break;
         get_Form_contents( &cts, &ctsSzB, &ctsMemSzB,
                            cc, c_die, False/*td3*/, form );
         if (attr == DW_AT_name && ctsMemSzB > 0) {
            atom->name = dinfo_strdup( (UChar*)(UWord)cts );
         }
         if (attr == DW_AT_const_value && ctsSzB > 0) {
            atom->value = cts;
            have_value = True;
         }
      }
      /* Do we have something that looks sane? */
      if ((!have_value) || atom->name == NULL)
         goto bad_DIE;
      /* Do we have a plausible parent? */
      if (typestack_is_empty(parser)) goto bad_DIE;
      vg_assert(parser->qparent[parser->sp]);
      if (level != parser->qlevel[parser->sp]+1) goto bad_DIE;
      if (parser->qparent[parser->sp]->tag != D3Ty_Enum) goto bad_DIE;
      /* Record this child in the parent */
      vg_assert(parser->qparent[parser->sp]->D3Ty.Enum.atomRs);
      VG_(addToXA)( parser->qparent[parser->sp]->D3Ty.Enum.atomRs, &atom );
      /* And record the child itself */
      goto acquire_Atom;
   }

   if (dtag == DW_TAG_structure_type || dtag == DW_TAG_union_type) {
      Bool have_szB = False;
      Bool is_decl  = False;
      Bool is_spec  = False;
      /* Create a new D3Type to hold the results. */
      type = new_D3Type();
      type->tag = D3Ty_StOrUn;
      type->D3Ty.StOrUn.name = NULL;
      type->D3Ty.StOrUn.fields
         = VG_(newXA)( dinfo_zalloc, dinfo_free, sizeof(D3TyAtom*) );
      type->D3Ty.StOrUn.complete = True;
      type->D3Ty.StOrUn.isStruct = dtag == DW_TAG_structure_type;
      while (True) {
         DW_AT   attr = (DW_AT)  get_ULEB128( c_abbv );
         DW_FORM form = (DW_FORM)get_ULEB128( c_abbv );
         if (attr == 0 && form == 0) break;
         get_Form_contents( &cts, &ctsSzB, &ctsMemSzB,
                            cc, c_die, False/*td3*/, form );
         if (attr == DW_AT_name && ctsMemSzB > 0) {
            type->D3Ty.StOrUn.name = dinfo_strdup( (UChar*)(UWord)cts );
         }
         if (attr == DW_AT_byte_size && ctsSzB >= 0) {
            type->D3Ty.StOrUn.szB = cts;
            have_szB = True;
         }
         if (attr == DW_AT_declaration && ctsSzB > 0 && cts > 0) {
            is_decl = True;
         }
         if (attr == DW_AT_specification && ctsSzB > 0 && cts > 0) {
            is_spec = True;
         }
      }
      /* Do we have something that looks sane? */
      if (is_decl && (!is_spec)) {
         /* It's a DW_AT_declaration.  We require the name but
            nothing else. */
         if (type->D3Ty.StOrUn.name == NULL)
            goto bad_DIE;
         type->D3Ty.StOrUn.complete = False;
         goto acquire_Type;
      }
      if ((!is_decl) /* && (!is_spec) */) {
         /* this is the common, ordinary case */
         if ((!have_szB) /* we must know the size */
             /* But the name can be present, or not */)
            goto bad_DIE;
         /* On't stack! */
         typestack_push( cc, parser, td3, type, level );
         goto acquire_Type;
      }
      else {
         /* don't know how to handle any other variants just now */
         goto bad_DIE;
      }
   }

   if (dtag == DW_TAG_member) {
      /* Acquire member entries for both DW_TAG_structure_type and
         DW_TAG_union_type.  They differ minorly, in that struct
         members must have a DW_AT_data_member_location expression
         whereas union members must not. */
      Bool parent_is_struct;
      field = new_D3TyField( NULL, NULL, NULL );
      field->typeR = D3_INVALID_CUOFF;
      expr  = NULL;
      while (True) {
         DW_AT   attr = (DW_AT)  get_ULEB128( c_abbv );
         DW_FORM form = (DW_FORM)get_ULEB128( c_abbv );
         if (attr == 0 && form == 0) break;
         get_Form_contents( &cts, &ctsSzB, &ctsMemSzB,
                            cc, c_die, False/*td3*/, form );
         if (attr == DW_AT_name && ctsMemSzB > 0) {
            field->name = dinfo_strdup( (UChar*)(UWord)cts );
         }
         if (attr == DW_AT_type && ctsSzB > 0) {
            field->typeR = (D3Type*)(UWord)cts;
         }
         if (attr == DW_AT_data_member_location && ctsMemSzB > 0) {
            expr = new_D3Expr( (UChar*)(UWord)cts, (UWord)ctsMemSzB );
         }
      }
      /* Do we have a plausible parent? */
      if (typestack_is_empty(parser)) goto bad_DIE;
      vg_assert(parser->qparent[parser->sp]);
      if (level != parser->qlevel[parser->sp]+1) goto bad_DIE;
      if (parser->qparent[parser->sp]->tag != D3Ty_StOrUn) goto bad_DIE;
      /* Do we have something that looks sane?  If this a member of a
         struct, we must have a location expression; but if a member
         of a union that is irrelevant and so we reject it. */
      parent_is_struct = parser->qparent[parser->sp]->D3Ty.StOrUn.isStruct;
      if (!field->name)
         field->name = dinfo_strdup("<anon_field>");
      if ((!field->name) || (field->typeR == D3_INVALID_CUOFF))
         goto bad_DIE;
      if (parent_is_struct && (!expr))
         goto bad_DIE;
      if ((!parent_is_struct) && expr)
         goto bad_DIE;
      /* Record this child in the parent */
      field->isStruct = parent_is_struct;
      if (expr)
         field->loc = expr;
      vg_assert(parser->qparent[parser->sp]->D3Ty.StOrUn.fields);
      VG_(addToXA)( parser->qparent[parser->sp]->D3Ty.StOrUn.fields, &field );
      /* And record the child itself */
      goto acquire_Field_and_Expr;
   }

   if (dtag == DW_TAG_array_type) {
      type = new_D3Type();
      type->tag = D3Ty_Array;
      type->D3Ty.Array.typeR = D3_INVALID_CUOFF;
      type->D3Ty.Array.bounds
         = VG_(newXA)( dinfo_zalloc, dinfo_free, sizeof(D3TyBounds*) );
      while (True) {
         DW_AT   attr = (DW_AT)  get_ULEB128( c_abbv );
         DW_FORM form = (DW_FORM)get_ULEB128( c_abbv );
         if (attr == 0 && form == 0) break;
         get_Form_contents( &cts, &ctsSzB, &ctsMemSzB,
                            cc, c_die, False/*td3*/, form );
         if (attr == DW_AT_type && ctsSzB > 0) {
            type->D3Ty.Array.typeR = (D3Type*)(UWord)cts;
         }
      }
      if (type->D3Ty.Array.typeR == D3_INVALID_CUOFF)
         goto bad_DIE;
      /* On't stack! */
      typestack_push( cc, parser, td3, type, level );
      goto acquire_Type;
   }

   if (dtag == DW_TAG_subrange_type) {
      Bool have_lower = False;
      Bool have_upper = False;
      Bool have_count = False;
      Long lower = 0;
      Long upper = 0;
      Long count = 0;

      switch (parser->language) {
         case 'C': have_lower = True;  lower = 0; break;
         case 'F': have_lower = True;  lower = 1; break;
         case '?': have_lower = False; break;
         default:  vg_assert(0); /* assured us by handling of
                                    DW_TAG_compile_unit in this fn */
      }
      bounds = new_D3TyBounds();
      while (True) {
         DW_AT   attr = (DW_AT)  get_ULEB128( c_abbv );
         DW_FORM form = (DW_FORM)get_ULEB128( c_abbv );
         if (attr == 0 && form == 0) break;
         get_Form_contents( &cts, &ctsSzB, &ctsMemSzB,
                            cc, c_die, False/*td3*/, form );
         if (attr == DW_AT_lower_bound && ctsSzB > 0) {
            lower      = (Long)cts;
            have_lower = True;
         }
         if (attr == DW_AT_upper_bound && ctsSzB > 0) {
            upper      = (Long)cts;
            have_upper = True;
         }
         if (attr == DW_AT_count && ctsSzB > 0) {
            count      = cts;
            have_count = True;
         }
      }
      /* FIXME: potentially skip the rest if no parent present, since
         it could be the case that this subrange type is free-standing
         (not being used to describe the bounds of a containing array
         type) */
      /* Do we have a plausible parent? */
      if (typestack_is_empty(parser)) goto bad_DIE;
      vg_assert(parser->qparent[parser->sp]);
      if (level != parser->qlevel[parser->sp]+1) goto bad_DIE;
      if (parser->qparent[parser->sp]->tag != D3Ty_Array) goto bad_DIE;

      /* Figure out if we have a definite range or not */
      if (have_lower && have_upper && (!have_count)) {
         bounds->knownL = True;
         bounds->knownU = True;
         bounds->boundL = lower;
         bounds->boundU = upper;
      } 
      else if (have_lower && (!have_upper) && (!have_count)) {
         bounds->knownL = True;
         bounds->knownU = False;
         bounds->boundL = lower;
         bounds->boundU = 0;
      } else {
         /* FIXME: handle more cases */
         goto bad_DIE;
      }

      /* Record this bound in the parent */
      vg_assert(parser->qparent[parser->sp]->D3Ty.Array.bounds);
      VG_(addToXA)( parser->qparent[parser->sp]->D3Ty.Array.bounds, &bounds );
      /* And record the child itself */
      goto acquire_Bounds;
   }

   if (dtag == DW_TAG_typedef) {
      /* We can pick up a new base type any time. */
      type = new_D3Type();
      type->tag = D3Ty_TyDef;
      type->D3Ty.TyDef.name = NULL;
      type->D3Ty.TyDef.typeR = D3_INVALID_CUOFF;
      while (True) {
         DW_AT   attr = (DW_AT)  get_ULEB128( c_abbv );
         DW_FORM form = (DW_FORM)get_ULEB128( c_abbv );
         if (attr == 0 && form == 0) break;
         get_Form_contents( &cts, &ctsSzB, &ctsMemSzB,
                            cc, c_die, False/*td3*/, form );
         if (attr == DW_AT_name && ctsMemSzB > 0) {
            type->D3Ty.TyDef.name = dinfo_strdup( (UChar*)(UWord)cts );
         }
         if (attr == DW_AT_type && ctsSzB > 0) {
            type->D3Ty.TyDef.typeR = (D3Type*)(UWord)cts;
         }
      }
      /* Do we have something that looks sane? */
      if (/* must have a name */
          type->D3Ty.TyDef.name == NULL
          /* but the referred-to type can be absent */)
         goto bad_DIE;
      else
         goto acquire_Type;
   }

   if (dtag == DW_TAG_subroutine_type) {
      /* function type? just record that one fact and ask no
         further questions. */
      type = new_D3Type();
      type->tag = D3Ty_Fn;
      goto acquire_Type;
   }

   if (dtag == DW_TAG_volatile_type || dtag == DW_TAG_const_type) {
      Int have_ty = 0;
      type = new_D3Type();
      type->tag = D3Ty_Qual;
      type->D3Ty.Qual.qual
         = dtag == DW_TAG_volatile_type ? 'V' : 'C';
      /* target type defaults to 'void' */
      type->D3Ty.Qual.typeR = D3_FAKEVOID_CUOFF;
      while (True) {
         DW_AT   attr = (DW_AT)  get_ULEB128( c_abbv );
         DW_FORM form = (DW_FORM)get_ULEB128( c_abbv );
         if (attr == 0 && form == 0) break;
         get_Form_contents( &cts, &ctsSzB, &ctsMemSzB,
                            cc, c_die, False/*td3*/, form );
         if (attr == DW_AT_type && ctsSzB > 0) {
            type->D3Ty.Qual.typeR = (D3Type*)(UWord)cts;
            have_ty++;
         }
      }
      /* gcc sometimes generates DW_TAG_const/volatile_type without
         DW_AT_type and GDB appears to interpret the type as 'const
         void' (resp. 'volatile void').  So just allow it .. */
      if (have_ty == 1 || have_ty == 0)
         goto acquire_Type;
      else
         goto bad_DIE;
   }

   /* else ignore this DIE */
   return;
   /*NOTREACHED*/

  acquire_Type:
   if (0) VG_(printf)("YYYY Acquire Type\n");
   vg_assert(type); vg_assert(!atom); vg_assert(!field);
   vg_assert(!expr); vg_assert(!bounds);
   *admin            = new_D3TyAdmin( posn, *admin );
   (*admin)->payload = type;
   (*admin)->tag     = D3TyA_Type;
   return;
   /*NOTREACHED*/

  acquire_Atom:
   if (0) VG_(printf)("YYYY Acquire Atom\n");
   vg_assert(!type); vg_assert(atom); vg_assert(!field);
   vg_assert(!expr); vg_assert(!bounds);
   *admin            = new_D3TyAdmin( posn, *admin );
   (*admin)->payload = atom;
   (*admin)->tag     = D3TyA_Atom;
   return;
   /*NOTREACHED*/

  acquire_Field_and_Expr:
   /* For union members, Expr should be absent */
   if (0) VG_(printf)("YYYY Acquire Field and Expr\n");
   vg_assert(!type); vg_assert(!atom); vg_assert(field); 
   /*vg_assert(expr);*/ vg_assert(!bounds);
   if (expr) {
      *admin            = new_D3TyAdmin( (UWord)D3_INVALID_CUOFF,
                                          *admin );
      (*admin)->payload = expr;
      (*admin)->tag     = D3TyA_Expr;
   }
   *admin            = new_D3TyAdmin( posn, *admin );
   (*admin)->payload = field;
   (*admin)->tag     = D3TyA_Field;
   return;
   /*NOTREACHED*/

  acquire_Bounds:
   if (0) VG_(printf)("YYYY Acquire Bounds\n");
   vg_assert(!type); vg_assert(!atom); vg_assert(!field);
   vg_assert(!expr); vg_assert(bounds);
   *admin            = new_D3TyAdmin( posn, *admin );
   (*admin)->payload = bounds;
   (*admin)->tag     = D3TyA_Bounds;
   return;
   /*NOTREACHED*/

  bad_DIE:
   set_position_of_Cursor( c_die,  saved_die_c_offset );
   set_position_of_Cursor( c_abbv, saved_abbv_c_offset );
   VG_(printf)("\nparse_type_DIE: confused by:\n");
   VG_(printf)(" <%d><%lx>: %s\n", level, posn, pp_DW_TAG( dtag ) );
   while (True) {
      DW_AT   attr = (DW_AT)  get_ULEB128( c_abbv );
      DW_FORM form = (DW_FORM)get_ULEB128( c_abbv );
      if (attr == 0 && form == 0) break;
      VG_(printf)("     %18s: ", pp_DW_AT(attr));
      /* Get the form contents, so as to print them */
      get_Form_contents( &cts, &ctsSzB, &ctsMemSzB,
                         cc, c_die, True, form );
      VG_(printf)("\t\n");
   }
   VG_(printf)("\n");
   cc->barf("parse_type_DIE: confused by the above DIE");
   /*NOTREACHED*/
}

/////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////
// Type Resolver

static Int cmp_D3TyAdmin_by_cuOff ( void* v1, void* v2 ) {
   D3TyAdmin* a1 = *(D3TyAdmin**)v1;
   D3TyAdmin* a2 = *(D3TyAdmin**)v2;
   if (a1->cuOff < a2->cuOff) return -1;
   if (a1->cuOff > a2->cuOff) return 1;
   return 0;
}

/* Look up 'cuOff' in 'map', to find the associated D3TyAdmin*.  Check
   that the found D3TyAdmin has tag 'adtag'.  Sets *payload to be the
   resulting payload pointer and returns True on success.

   Also, if 'allow_invalid' is True, then if cuOff is
   D3_INVALID_CUOFF, return NULL in *payload.

   Otherwise (conceptually fails) and returns False. */
static Bool resolve_binding ( /*OUT*/void** payload,
                              XArray* map, void* cuOff,
                              D3TyAdminTag tag, 
                              Bool allow_invalid ) {
   Bool      found;
   Word      ixLo, ixHi;
   D3TyAdmin dummy, *dummyP, *admin;

   if (cuOff == D3_INVALID_CUOFF && allow_invalid) {
      *payload = NULL;
      return True;
   }

   VG_(memset)(&dummy, 0, sizeof(dummy));
   dummy.cuOff = (UWord)cuOff;
   dummyP = &dummy;
   found = VG_(lookupXA)( map, &dummyP, &ixLo, &ixHi );
   if (!found)
      return False;
   /* If this doesn't hold, we must have seen more than one DIE with
      the same cuOff(set).  Which isn't possible. */
   vg_assert(ixLo == ixHi);
   admin = *(D3TyAdmin**)VG_(indexXA)( map, ixLo );
   /* All payload pointers should be non-NULL.  Ensured by assertion in
      loop in resolve_type_entities that creates 'map'.  Hence it is
      safe to return NULL to indicate 'not found'. */
   vg_assert(admin->payload);
   vg_assert(admin->cuOff == (UWord)cuOff); /* stay sane */

   if (admin->tag != tag)
      return False;

   *payload = admin->payload;
   return True;
}

static void resolve_type_entities ( /*MOD*/D3TyAdmin* admin,
                                    /*MOD*/TempVar* vars )
{
   Bool  ok;
   void* payload;
   D3TyAdmin* adp;
   XArray* /* of D3TyAdmin* */ map;

   map = VG_(newXA)( dinfo_zalloc, dinfo_free, sizeof(D3TyAdmin*) );
   for (adp = admin; adp; adp = adp->next) {
      vg_assert(adp);
      vg_assert(adp->payload != NULL);
      if (adp->cuOff != (UWord)D3_INVALID_CUOFF) {
         VG_(addToXA)( map, &adp );
      }
   }

   VG_(setCmpFnXA)( map, cmp_D3TyAdmin_by_cuOff );
   VG_(sortXA)( map );

   for (adp = admin; adp; adp = adp->next) {
      vg_assert(adp->payload);
      switch (adp->tag) {
      case D3TyA_Bounds: {
         D3TyBounds* bounds = (D3TyBounds*)adp->payload;
         if (bounds->knownL && bounds->knownU 
             && bounds->knownL > bounds->knownU) goto baaad;
         break;
      }
      case D3TyA_Atom: {
         D3TyAtom* atom = (D3TyAtom*)adp->payload;
         if (!atom->name) goto baaad;
         break;
      }
      case D3TyA_Expr: {
         D3Expr* expr = (D3Expr*)adp->payload;
         if (!expr->bytes) goto baaad;
         break;
      }
      case D3TyA_Field: {
         D3TyField* field = (D3TyField*)adp->payload;
         if (!field->name) goto baaad;
         if ( (field->isStruct && (!field->loc)) 
              || ((!field->isStruct) && field->loc))
            goto baaad;
         ok = resolve_binding( &payload, map, field->typeR,
                               D3TyA_Type, False/*!allow_invalid*/ );
         if (!ok) goto baaad;
         field->typeR = payload;
         break;
      }
      case D3TyA_Type: {
         UChar   enc;
#if 0
         Word    i;
#endif
         XArray* xa;
         D3Type* ty = (D3Type*)adp->payload;
         switch (ty->tag) {
            case D3Ty_Base:
               enc = ty->D3Ty.Base.enc;
               if ((!ty->D3Ty.Base.name) 
                   || ty->D3Ty.Base.szB < 1 || ty->D3Ty.Base.szB > 16
                   || (enc != 'S' && enc != 'U' && enc != 'F'))
                  goto baaad;
               break;
            case D3Ty_TyDef:
               if (!ty->D3Ty.TyDef.name) goto baaad;
               ok = resolve_binding( &payload, map,
                                     ty->D3Ty.TyDef.typeR, 
                                     D3TyA_Type,
                                     True/*allow_invalid*/ );
               if (!ok) goto baaad;
               ty->D3Ty.TyDef.typeR = payload;
               break;
            case D3Ty_PorR:
               if (ty->D3Ty.PorR.szB != sizeof(Word)) goto baaad;
               ok = resolve_binding( &payload, map,
                                     ty->D3Ty.PorR.typeR, 
                                     D3TyA_Type,
                                     False/*!allow_invalid*/ );
               if (!ok) goto baaad;
               ty->D3Ty.PorR.typeR = payload;
               break;
            case D3Ty_Array:
               if (!ty->D3Ty.Array.bounds) goto baaad;
               ok = resolve_binding( &payload, map,
                                     ty->D3Ty.Array.typeR, 
                                     D3TyA_Type,
                                     False/*!allow_invalid*/ );
               if (!ok) goto baaad;
               ty->D3Ty.Array.typeR = payload;
               break;
            case D3Ty_Enum:
               if ((!ty->D3Ty.Enum.atomRs)
                   || ty->D3Ty.Enum.szB < 1 
                   || ty->D3Ty.Enum.szB > 8) goto baaad;
               xa = ty->D3Ty.Enum.atomRs;
#if 0
               for (i = 0; i < VG_(sizeXA)(xa); i++) {
                  void** ppAtom = VG_(indexXA)(xa,i);
                  ok = resolve_binding( &payload, map,
                                        *ppAtom, D3TyA_Atom,
                                        False/*!allow_invalid*/ );
                  if (!ok) goto baaad;
                  *ppAtom = payload;
               }
#endif
               break;
            case D3Ty_StOrUn:
               xa = ty->D3Ty.StOrUn.fields;
               if (!xa) goto baaad;
#if 0
               for (i = 0; i < VG_(sizeXA)(xa); i++) {
                  void** ppField = VG_(indexXA)(xa,i);
                  ok = resolve_binding( &payload, map,
                                        *ppField, D3TyA_Field,
                                        False/*!allow_invalid*/ );
                  if (!ok) goto baaad;
                  *ppField = payload;
               }
#endif
               break;
            case D3Ty_Fn:
               break;
            case D3Ty_Qual:
               if (ty->D3Ty.Qual.qual != 'C' 
                   && ty->D3Ty.Qual.qual != 'V') goto baaad;
               ok = resolve_binding( &payload, map,
                                     ty->D3Ty.Qual.typeR, 
                                     D3TyA_Type,
                                     False/*!allow_invalid*/ );
               if (!ok) goto baaad;
               ty->D3Ty.Qual.typeR = payload;
               break;
            case D3Ty_Void:
               if (ty->D3Ty.Void.isFake != False 
                   && ty->D3Ty.Void.isFake != True) goto baaad;
               break;
            default:
               goto baaad;
         }
         break;
      }
      baaad:
      default:
         VG_(printf)("valgrind: bad D3TyAdmin: ");
         pp_D3TyAdmin(adp);
         VG_(printf)("\n");
      }
   }

   /* Now resolve the variables list */
   for (; vars; vars = vars->next) {
      payload = NULL;
      ok = resolve_binding( &payload, map, vars->typeR,
                            D3TyA_Type, True/*allow_invalid*/ );
//if (!ok) VG_(printf)("Can't resolve type reference 0x%lx\n", (UWord)vars->typeR);
//vg_assert(ok);
      vars->typeR = payload;
   }

   VG_(deleteXA)( map );
}


/////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////

static void read_DIE ( /*OUT*/D3TyAdmin** admin,
                       /*OUT*/TempVar** tempvars,
                       /*OUT*/GExpr** gexprs,
                       /*MOD*/D3TypeParser* typarser,
                       /*MOD*/D3VarParser* varparser,
                       Cursor* c, Bool td3, CUConst* cc, Int level )
{
   Cursor abbv;
   ULong  atag, abbv_code;
   UWord  posn;
   UInt   has_children;
   Word   start_die_c_offset, start_abbv_c_offset;
   Word   after_die_c_offset, after_abbv_c_offset;

   /* --- Deal with this DIE --- */
   posn      = get_position_of_Cursor( c );
   abbv_code = get_ULEB128( c );
   set_abbv_Cursor( &abbv, td3, cc, abbv_code );
   atag      = get_ULEB128( &abbv );
   TRACE_D3("\n");
   TRACE_D3(" <%d><%lx>: Abbrev Number: %llu (%s)\n",
            level, posn, abbv_code, pp_DW_TAG( atag ) );

   if (atag == 0)
      cc->barf("read_DIE: invalid zero tag on DIE");

   has_children = get_UChar( &abbv );
   if (has_children != DW_children_no && has_children != DW_children_yes)
      cc->barf("read_DIE: invalid has_children value");

   /* We're set up to look at the fields of this DIE.  Hand it off to
      any parser(s) that want to see it.  Since they will in general
      advance both the DIE and abbrev cursors, remember where their
      current settings so that we can then back up and do one final
      pass over the DIE, to print out its contents. */

   start_die_c_offset  = get_position_of_Cursor( c );
   start_abbv_c_offset = get_position_of_Cursor( &abbv );

   while (True) {
      ULong cts;
      Int   ctsSzB;
      UWord ctsMemSzB;
      ULong at_name = get_ULEB128( &abbv );
      ULong at_form = get_ULEB128( &abbv );
      if (at_name == 0 && at_form == 0) break;
      TRACE_D3("     %18s: ", pp_DW_AT(at_name));
      /* Get the form contents, but ignore them; the only purpose is
         to print them, if td3 is True */
      get_Form_contents( &cts, &ctsSzB, &ctsMemSzB,
                         cc, c, td3, (DW_FORM)at_form );
      TRACE_D3("\t");
      TRACE_D3("\n");
   }

   after_die_c_offset  = get_position_of_Cursor( c );
   after_abbv_c_offset = get_position_of_Cursor( &abbv );

   set_position_of_Cursor( c,     start_die_c_offset );
   set_position_of_Cursor( &abbv, start_abbv_c_offset );

   parse_type_DIE( admin,
                   typarser,
                   (DW_TAG)atag,
                   posn,
                   level,
                   c,     /* DIE cursor */
                   &abbv, /* abbrev cursor */
                   cc,
                   td3 );

   set_position_of_Cursor( c,     start_die_c_offset );
   set_position_of_Cursor( &abbv, start_abbv_c_offset );

   parse_var_DIE( tempvars,
                  gexprs,
                  varparser,
                  (DW_TAG)atag,
                  posn,
                  level,
                  c,     /* DIE cursor */
                  &abbv, /* abbrev cursor */
                  cc,
                  td3 );

   set_position_of_Cursor( c,     after_die_c_offset );
   set_position_of_Cursor( &abbv, after_abbv_c_offset );

   /* --- Now recurse into its children, if any --- */
   if (has_children == DW_children_yes) {
      if (0) TRACE_D3("BEGIN children of level %d\n", level);
      while (True) {
         atag = peek_ULEB128( c );
         if (atag == 0) break;
         read_DIE( admin, tempvars, gexprs, typarser, varparser,
                   c, td3, cc, level+1 );
      }
      /* Now we need to eat the terminating zero */
      atag = get_ULEB128( c );
      vg_assert(atag == 0);
      if (0) TRACE_D3("END children of level %d\n", level);
   }

}


static
void new_dwarf3_reader_wrk ( 
   struct _DebugInfo* di,
   __attribute__((noreturn))
   void (*barf)( HChar* ),
   UChar* debug_info_img,   SizeT debug_info_sz,
   UChar* debug_abbv_img,   SizeT debug_abbv_sz,
   UChar* debug_line_img,   SizeT debug_line_sz,
   UChar* debug_str_img,    SizeT debug_str_sz,
   UChar* debug_ranges_img, SizeT debug_ranges_sz,
   UChar* debug_loc_img,    SizeT debug_loc_sz
)
{
   D3TyAdmin *admin, *adminp;
   TempVar *tempvars, *varp, *varp2;
   GExpr *gexprs, *gexpr;
   Cursor abbv; /* for showing .debug_abbrev */
   Cursor info; /* primary cursor for parsing .debug_info */
   Cursor ranges; /* for showing .debug_ranges */
   Cursor loc; /* for showing .debug_loc */
   D3TypeParser typarser;
   D3VarParser varparser;
   Addr  dr_base, dl_base;
   UWord dr_offset, dl_offset;
   Bool td3 = di->trace_symtab;

#if 0
   /* Display .debug_loc */
   TRACE_SYMTAB("\n");
   TRACE_SYMTAB("\n------ The contents of .debug_loc ------\n");
   TRACE_SYMTAB("    Offset   Begin    End      Expression\n");
   init_Cursor( &loc, debug_loc_img, 
                debug_loc_sz, 0, barf, 
                "Overrun whilst reading .debug_loc section(1)" );
   dl_base = 0;
   dl_offset = 0;
   while (True) {
      UWord  w1, w2;
      UWord  len;
      if (is_at_end_Cursor( &loc ))
         break;

      /* Read a (host-)word pair.  This is something of a hack since
         the word size to read is really dictated by the ELF file;
         however, we assume we're reading a file with the same
         word-sizeness as the host.  Reasonably enough. */
      w1 = get_UWord( &loc );
      w2 = get_UWord( &loc );

      if (w1 == 0 && w2 == 0) {
         /* end of list.  reset 'base' */
         TRACE_D3("    %08lx <End of list>\n", dl_offset);
         dl_base = 0;
         dl_offset = get_position_of_Cursor( &loc );
         continue;
      }

      if (w1 == -1UL) {
         /* new value for 'base' */
         TRACE_D3("    %08lx %16lx %08lx (base address)\n",
                  dl_offset, w1, w2);
         dl_base = w2;
         continue;
      }

      /* else a location expression follows */
      TRACE_D3("    %08lx %08lx %08lx ",
               dl_offset, w1 + dl_base, w2 + dl_base);
      len = (UWord)get_UShort( &loc );
      while (len > 0) {
         UChar byte = get_UChar( &loc );
         TRACE_D3("%02x", (UInt)byte);
         len--;
      }
      TRACE_SYMTAB("\n");
   }
#endif

   /* Display .debug_ranges */
   TRACE_SYMTAB("\n");
   TRACE_SYMTAB("\n------ The contents of .debug_ranges ------\n");
   TRACE_SYMTAB("    Offset   Begin    End\n");
   init_Cursor( &ranges, debug_ranges_img, 
                debug_ranges_sz, 0, barf, 
                "Overrun whilst reading .debug_ranges section(1)" );
   dr_base = 0;
   dr_offset = 0;
   while (True) {
      UWord  w1, w2;

      if (is_at_end_Cursor( &ranges ))
         break;

      /* Read a (host-)word pair.  This is something of a hack since
         the word size to read is really dictated by the ELF file;
         however, we assume we're reading a file with the same
         word-sizeness as the host.  Reasonably enough. */
      w1 = get_UWord( &ranges );
      w2 = get_UWord( &ranges );

      if (w1 == 0 && w2 == 0) {
         /* end of list.  reset 'base' */
         TRACE_D3("    %08lx <End of list>\n", dr_offset);
         dr_base = 0;
         dr_offset = get_position_of_Cursor( &ranges );
         continue;
      }

      if (w1 == -1UL) {
         /* new value for 'base' */
         TRACE_D3("    %08lx %16lx %08lx (base address)\n",
                  dr_offset, w1, w2);
         dr_base = w2;
         continue;
      }

      /* else a range [w1+base, w2+base) is denoted */
      TRACE_D3("    %08lx %08lx %08lx\n",
               dr_offset, w1 + dr_base, w2 + dr_base);
   }


   /* Display .debug_abbrev */
   init_Cursor( &abbv, debug_abbv_img, debug_abbv_sz, 0, barf, 
                "Overrun whilst reading .debug_abbrev section" );
   TRACE_SYMTAB("\n");
   TRACE_SYMTAB("\n------ The contents of .debug_abbrev ------\n");
   while (True) {
      if (is_at_end_Cursor( &abbv ))
         break;
      /* Read one abbreviation table */
      TRACE_D3("  Number TAG\n");
      while (True) {
         ULong atag;
         UInt  has_children;
         ULong acode = get_ULEB128( &abbv );
         if (acode == 0) break; /* end of the table */
         atag = get_ULEB128( &abbv );
         has_children = get_UChar( &abbv );
         TRACE_D3("   %llu      %s    [%s]\n", 
                  acode, pp_DW_TAG(atag), pp_DW_children(has_children));
         while (True) {
            ULong at_name = get_ULEB128( &abbv );
            ULong at_form = get_ULEB128( &abbv );
            if (at_name == 0 && at_form == 0) break;
            TRACE_D3("    %18s %s\n", 
                     pp_DW_AT(at_name), pp_DW_FORM(at_form));
         }
      }
   }
   TRACE_SYMTAB("\n");

   /* Now loop over the Compilation Units listed in the .debug_info
      section (see D3SPEC sec 7.5) paras 1 and 2.  Each compilation
      unit contains a Compilation Unit Header followed by precisely
      one DW_TAG_compile_unit or DW_TAG_partial_unit DIE. */
   init_Cursor( &info, debug_info_img, debug_info_sz, 0, barf,
                "Overrun whilst reading .debug_info section" );

   /* We'll park the harvested type information in here.  Also create
      a fake "void" entry with offset D3_FAKEVOID_CUOFF, so we always
      have at least one type entry to refer to.  D3_FAKEVOID_CUOFF is
      huge and presumably will not occur in any valid DWARF3 file --
      it would need to have a .debug_info section 4GB long for that to
      happen. */
   admin = NULL;
   { D3Type* tVoid = new_D3Type();
     tVoid->tag = D3Ty_Void;
     tVoid->D3Ty.Void.isFake = True;
     admin = new_D3TyAdmin( (UWord)D3_FAKEVOID_CUOFF, admin );
     admin->payload = tVoid;
     admin->tag     = D3TyA_Type;
   }

   tempvars = NULL;
   gexprs = NULL;

   /* We need a D3TypeParser to keep track of partially constructed
      types.  It'll be discarded as soon as we've completed the CU,
      since the resulting information is tipped in to 'admin' as it is
      generated. */
   VG_(memset)( &typarser, 0, sizeof(typarser) );
   typarser.sp = -1;
   typarser.language = '?';

   VG_(memset)( &varparser, 0, sizeof(varparser) );
   varparser.sp = -1;

   TRACE_D3("\n------ Parsing .debug_info section ------\n");
   while (True) {
      Word    cu_start_offset, cu_offset_now;
      CUConst cc;
      if (is_at_end_Cursor( &info ))
         break;

      /* Check the varparser's stack is in a sane state. */
      { Int i;
        vg_assert(varparser.sp == -1);
        for (i = 0; i < N_D3_VAR_STACK; i++) {
           vg_assert(varparser.ranges[i] == NULL);
           vg_assert(varparser.level[i] == 0);
        }
        for (i = 0; i < N_D3_TYPE_STACK; i++) {
           vg_assert(typarser.qparent[i] == NULL);
           vg_assert(typarser.qlevel[i] == 0);
        }
      }

      cu_start_offset = get_position_of_Cursor( &info );
      TRACE_D3("\n");
      TRACE_D3("  Compilation Unit @ offset 0x%lx:\n", cu_start_offset);
      parse_CU_Header( &cc, td3, &info,
                       (UChar*)debug_abbv_img, debug_abbv_sz );
      cc.debug_str_img    = debug_str_img;
      cc.debug_str_sz     = debug_str_sz;
      cc.debug_ranges_img = debug_ranges_img;
      cc.debug_ranges_sz  = debug_ranges_sz;
      cc.debug_loc_img    = debug_loc_img;
      cc.debug_loc_sz     = debug_loc_sz;
      cc.cu_start_offset  = cu_start_offset;
      /* The CU's svma can be deduced by looking at the AT_low_pc
         value in the top level TAG_compile_unit, which is the topmost
         DIE.  We'll leave it for the 'varparser' to acquire that info
         and fill it in -- since it is the only party to want to know
         it. */
      cc.cu_svma_known = False;
      cc.cu_svma       = 0;

      /* Create a fake outermost-level range covering the entire
         address range.  So we always have *something* to catch all
         variable declarations. */
      varstack_push( &cc, &varparser, td3, 
                     unitary_range_list(0UL, ~0UL),
                     -1, False/*isFunc*/, NULL/*fbGX*/ );

      /* Now read the one-and-only top-level DIE for this CU. */
      vg_assert(varparser.sp == 0);
      read_DIE( &admin, &tempvars, &gexprs, &typarser, &varparser,
                &info, td3, &cc, 0 );

      cu_offset_now = get_position_of_Cursor( &info );
      if (0) TRACE_D3("offset now %ld, d-i-size %ld\n",
                      cu_offset_now, debug_info_sz);
      if (cu_offset_now > debug_info_sz)
         barf("toplevel DIEs beyond end of CU");
      if (cu_offset_now == debug_info_sz)
         break;

      /* Preen to level -2.  DIEs have level >= 0 so -2 cannot occur
         anywhere else at all.  Our fake the-entire-address-space
         range is at level -1, so preening to -2 should completely
         empty the stack out. */
      TRACE_D3("\n");
      varstack_preen( &varparser, td3, -2 );
      /* Similarly, empty the type stack out. */
      typestack_preen( &typarser, td3, -2 );
      /* else keep going */

      TRACE_D3("set_abbv_Cursor cache: %lu queries, %lu misses\n",
               cc.saC_cache_queries, cc.saC_cache_misses);
   }

   /* Put the type entry list the right way round.  Not strictly
      necessary, but makes it easier to read. */
   vg_assert(admin);
   if (admin) { 
      D3TyAdmin *next, *prev = NULL;
      for (adminp = admin; adminp; adminp = next) {
         next = adminp->next;
         adminp->next = prev;
         prev = adminp;
      }
      admin = prev;
   }

   /* Put the variable list the right way round.  Not strictly
      necessary, but makes it easier to read. */
   if (tempvars) { 
      TempVar *next, *prev = NULL;
      for (varp = tempvars; varp; varp = next) {
         next = varp->next;
         varp->next = prev;
         prev = varp;
      }
      tempvars = prev;
   }

   TRACE_D3("\n");
   TRACE_D3("------ Acquired the following type entities: ------\n");
   for (adminp = admin; adminp; adminp = adminp->next) {
      TRACE_D3("   ");
      if (td3) pp_D3TyAdmin( adminp );
      TRACE_D3("\n");
   }
   TRACE_D3("\n");
   TRACE_D3("------ Resolving type entries ------\n");

   resolve_type_entities( admin, tempvars );
   for (gexpr = gexprs; gexpr; gexpr = gexpr->next) {
      bias_GX( gexpr, di->text_bias );
   }

   TRACE_D3("\n");
   TRACE_D3("------ Acquired the following variables: ------\n");
   for (varp = tempvars; varp; varp = varp2) {
      varp2 = varp->next;

      /* Possibly show .. */
      if (td3) {
         VG_(printf)("  addVar: level %d  %p-%p  %s :: ",
                     varp->level, varp->pcMin, varp->pcMax, varp->name );
         if (varp->typeR) {
            ML_(pp_D3Type_C_ishly)( varp->typeR );
         } else {
            VG_(printf)("!!type=NULL!!");
         }
         VG_(printf)("\n  Var=");
         ML_(pp_GX)(varp->gexpr);
         VG_(printf)("\n");
         if (varp->fbGX) {
            VG_(printf)("  FrB=");
            ML_(pp_GX)( varp->fbGX );
            VG_(printf)("\n");
         } else {
            VG_(printf)("  FrB=none\n");
         }
         VG_(printf)("\n");
      }

      /* Level 0 is the global address range.  So at level 0 we don't
         want to bias pcMin/pcMax; but at all other levels we do since
         those are derived from svmas in the Dwarf we're reading.  Be
         paranoid ... */
      vg_assert(varp->level >= 0);
      vg_assert(varp->pcMin <= varp->pcMax);
      if (varp->level == 0) {
         vg_assert(varp->pcMin == (Addr)0);
         vg_assert(varp->pcMax == ~(Addr)0);
      } else {
        /* vg_assert(varp->pcMin > (Addr)0);
           No .. we can legitmately expect to see ranges like 
           0x0-0x11D (pre-biasing, of course). */
         vg_assert(varp->pcMax < ~(Addr)0);
      }
      /* NOTE: re "if": this is a hack.  Really, if the type didn't
         get resolved, something's broken earlier on. */
      if (varp->typeR)
         ML_(addVar)(
            di, varp->level, 
                varp->pcMin + (varp->level==0 ? 0 : di->text_bias),
                varp->pcMax + (varp->level==0 ? 0 : di->text_bias), 
                varp->name, (void*)varp->typeR,
                varp->gexpr, varp->fbGX, td3 
         );
      dinfo_free(varp);
   }
   tempvars = NULL;

   /* FIXME: record adminp in di so it can be freed later */
}


/*------------------------------------------------------------*/
/*--- The "new" DWARF3 reader -- top level control logic   ---*/
/*------------------------------------------------------------*/

/* --- !!! --- EXTERNAL HEADERS start --- !!! --- */
#include <setjmp.h>   /* For jmp_buf */
/* --- !!! --- EXTERNAL HEADERS end --- !!! --- */

static Bool    d3rd_jmpbuf_valid  = False;
static HChar*  d3rd_jmpbuf_reason = NULL;
static jmp_buf d3rd_jmpbuf;

static __attribute__((noreturn)) void barf ( HChar* reason ) {
   vg_assert(d3rd_jmpbuf_valid);
   d3rd_jmpbuf_reason = reason;
   __builtin_longjmp(&d3rd_jmpbuf, 1);
   /*NOTREACHED*/
   vg_assert(0);
}


void 
ML_(new_dwarf3_reader) (
   struct _DebugInfo* di,
   UChar* debug_info_img,   SizeT debug_info_sz,
   UChar* debug_abbv_img,   SizeT debug_abbv_sz,
   UChar* debug_line_img,   SizeT debug_line_sz,
   UChar* debug_str_img,    SizeT debug_str_sz,
   UChar* debug_ranges_img, SizeT debug_ranges_sz,
   UChar* debug_loc_img,    SizeT debug_loc_sz
)
{
   volatile Int  jumped;
   volatile Bool td3 = di->trace_symtab;

   /* Run the _wrk function to read the dwarf3.  If it succeeds, it
      just returns normally.  If there is any failure, it longjmp's
      back here, having first set d3rd_jmpbuf_reason to something
      useful. */
   vg_assert(d3rd_jmpbuf_valid  == False);
   vg_assert(d3rd_jmpbuf_reason == NULL);

   d3rd_jmpbuf_valid = True;
   jumped = __builtin_setjmp(&d3rd_jmpbuf);
   if (jumped == 0) {
      /* try this ... */
      new_dwarf3_reader_wrk( di, barf,
                             debug_info_img,   debug_info_sz,
                             debug_abbv_img,   debug_abbv_sz,
                             debug_line_img,   debug_line_sz,
                             debug_str_img,    debug_str_sz,
                             debug_ranges_img, debug_ranges_sz,
                             debug_loc_img,    debug_loc_sz );
      d3rd_jmpbuf_valid = False;
      TRACE_D3("\n------ .debug_info reading was successful ------\n");
   } else {
      /* It longjmp'd. */
      d3rd_jmpbuf_valid = False;
      /* Can't longjump without giving some sort of reason. */
      vg_assert(d3rd_jmpbuf_reason != NULL);

      TRACE_D3("\n------ .debug_info reading failed ------\n");

      ML_(symerr)(di, True, d3rd_jmpbuf_reason);
   }

   d3rd_jmpbuf_valid  = False;
   d3rd_jmpbuf_reason = NULL;
}



/* --- Unused code fragments which might be useful one day. --- */

#if 0
   /* Read the arange tables */
   TRACE_SYMTAB("\n");
   TRACE_SYMTAB("\n------ The contents of .debug_arange ------\n");
   init_Cursor( &aranges, debug_aranges_img, 
                debug_aranges_sz, 0, barf, 
                "Overrun whilst reading .debug_aranges section" );
   while (True) {
      ULong  len, d_i_offset;
      Bool   is64;
      UShort version;
      UChar  asize, segsize;

      if (is_at_end_Cursor( &aranges ))
         break;
      /* Read one arange thingy */
      /* initial_length field */
      len = get_Initial_Length( &is64, &aranges, 
               "in .debug_aranges: invalid initial-length field" );
      version    = get_UShort( &aranges );
      d_i_offset = get_Dwarfish_UWord( &aranges, is64 );
      asize      = get_UChar( &aranges );
      segsize    = get_UChar( &aranges );
      TRACE_D3("  Length:                   %llu\n", len);
      TRACE_D3("  Version:                  %d\n", (Int)version);
      TRACE_D3("  Offset into .debug_info:  %llx\n", d_i_offset);
      TRACE_D3("  Pointer Size:             %d\n", (Int)asize);
      TRACE_D3("  Segment Size:             %d\n", (Int)segsize);
      TRACE_D3("\n");
      TRACE_D3("    Address            Length\n");

      while ((get_position_of_Cursor( &aranges ) % (2 * asize)) > 0) {
         (void)get_UChar( & aranges );
      }
      while (True) {
         ULong address = get_Dwarfish_UWord( &aranges, asize==8 );
         ULong length = get_Dwarfish_UWord( &aranges, asize==8 );
         TRACE_D3("    0x%016llx 0x%llx\n", address, length);
         if (address == 0 && length == 0) break;
      }
   }
   TRACE_SYMTAB("\n");
#endif

/*--------------------------------------------------------------------*/
/*--- end                                             readdwarf3.c ---*/
/*--------------------------------------------------------------------*/
