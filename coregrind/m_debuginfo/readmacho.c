
/*--------------------------------------------------------------------*/
/*--- Reading of syms & debug info from Mach-O files.              ---*/
/*---                                                  readmacho.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2005-2008 Apple Inc.
      Greg Parker gparker@apple.com

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
#include "pub_core_vki.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcprint.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcfile.h"
#include "pub_core_libcproc.h"
#include "pub_core_aspacemgr.h"    /* for mmaping debuginfo files */
#include "pub_core_machine.h"      /* VG_ELF_CLASS */
#include "pub_core_mallocfree.h"
#include "pub_core_options.h"
#include "pub_core_oset.h"
#include "pub_core_tooliface.h"    /* VG_(needs) */
#include "pub_core_xarray.h"
#include "pub_core_clientstate.h"
#include "pub_core_debuginfo.h"

#include "priv_d3basics.h"
#include "priv_misc.h"
#include "priv_tytypes.h"
#include "priv_storage.h"
#include "priv_readmacho.h"
#include "priv_readdwarf.h"
#include "priv_readdwarf3.h"
#include "priv_readstabs.h"

/* --- !!! --- EXTERNAL HEADERS start --- !!! --- */
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/fat.h>
/* --- !!! --- EXTERNAL HEADERS end --- !!! --- */

#if VG_WORDSIZE == 4
#define MAGIC MH_MAGIC
#define MACH_HEADER mach_header
#define LC_SEGMENT_CMD LC_SEGMENT
#define SEGMENT_COMMAND segment_command
#define SECTION section
#define NLIST nlist
#else
#define MAGIC MH_MAGIC_64
#define MACH_HEADER mach_header_64
#define LC_SEGMENT_CMD LC_SEGMENT_64
#define SEGMENT_COMMAND segment_command_64
#define SECTION section_64
#define NLIST nlist_64
#endif


Bool ML_(is_macho_object_file)( const void *buf, SizeT size )
{
   // GrP fixme Mach-O headers might not be in this mapped data
   // Assume it's Mach-O and let ML_(read_macho_debug_info) sort it out.
   return True;
}


/* Read a symbol table (nlist) */
static
void read_symtab( struct _DebugInfo* di, 
                  struct NLIST* o_symtab, UInt o_symtab_count,
                  UChar*     o_strtab, UInt o_strtab_sz )
{
   Int   i;
   Addr  sym_addr;
   DiSym risym;

   for (i = 0; i < o_symtab_count; i++) {
      struct NLIST *nl = o_symtab+i;
      if ((nl->n_type & N_TYPE) == N_SECT) {
         sym_addr = di->text_bias + nl->n_value;
    /*} else if ((nl->n_type & N_TYPE) == N_ABS) {
         GrP fixme don't ignore absolute symbols?
         sym_addr = nl->n_value; */
      } else {
         continue;
      }
      
      /* If no part of the symbol falls within the mapped range,
         ignore it. */
      if (sym_addr <= di->text_avma
          || sym_addr >= di->text_avma+di->text_size) {
         continue;
      }

      risym.tocptr = 0;
      risym.addr = sym_addr;
      risym.size = di->text_avma+di->text_size - sym_addr; // let canonicalize fix it
      risym.name = ML_(addStr)(di, o_strtab + nl->n_un.n_strx, -1);
      risym.isText = True;
      // Lots of user function names get prepended with an underscore.  Eg. the
      // function 'f' becomes the symbol '_f'.  And the "below main"
      // function is called "start".  So we skip the leading underscore, and
      // if we see 'start' and --show-below-main=no, we rename it as
      // "start_according_to_valgrind", which makes it easy to spot later
      // and display as "(below main)".
      if (risym.name[0] == '_') {
         risym.name++;
      } else if (!VG_(clo_show_below_main) && VG_STREQ(risym.name, "start")) {
         risym.name = "start_according_to_valgrind";
      }
      ML_(addSym)(di, &risym);
   }
}


#if ! defined (APPLE_DSYM_EXT_AND_SUBDIRECTORY)
#define APPLE_DSYM_EXT_AND_SUBDIRECTORY ".dSYM/Contents/Resources/DWARF/"
#endif


static Bool file_exists_p(const Char *path)
{
   struct vg_stat sbuf;
   SysRes res = VG_(stat)(path, &sbuf);
   return res.isError ? False : True;
}


/* Search for an existing dSYM file as a possible separate debug file.  
   Adapted from gdb. */
static Char *
find_separate_debug_file (const Char *executable_name)
{
   Char *basename_str;
   Char *dot_ptr;
   Char *slash_ptr;
   Char *dsymfile;
    
   /* Make sure the object file name itself doesn't contain ".dSYM" in it or we
      will end up with an infinite loop where after we add a dSYM symbol file,
      it will then enter this function asking if there is a debug file for the
      dSYM file itself.  */
   if (VG_(strcasestr) (executable_name, ".dSYM") == NULL)
   {
        /* Check for the existence of a .dSYM file for a given executable.  */
      basename_str = VG_(basename) (executable_name);
      dsymfile = VG_(malloc)("di.readmacho.dsymfile", 
                             VG_(strlen) (executable_name)
                             + VG_(strlen) (APPLE_DSYM_EXT_AND_SUBDIRECTORY)
                             + VG_(strlen) (basename_str)
                             + 1);
        
      /* First try for the dSYM in the same directory as the original file.  */
      VG_(strcpy) (dsymfile, executable_name);
      VG_(strcat) (dsymfile, APPLE_DSYM_EXT_AND_SUBDIRECTORY);
      VG_(strcat) (dsymfile, basename_str);
        
      if (file_exists_p (dsymfile))
         return dsymfile;
        
      /* Now search for any parent directory that has a '.' in it so we can find
         Mac OS X applications, bundles, plugins, and any other kinds of files. 
         Mac OS X application bundles wil have their program in
         "/some/path/MyApp.app/Contents/MacOS/MyApp" (or replace ".app" with
         ".bundle" or ".plugin" for other types of bundles).  So we look for any
         prior '.' character and try appending the apple dSYM extension and
         subdirectory and see if we find an existing dSYM file (in the above
         MyApp example the dSYM would be at either:
         "/some/path/MyApp.app.dSYM/Contents/Resources/DWARF/MyApp" or
         "/some/path/MyApp.dSYM/Contents/Resources/DWARF/MyApp".  */
      VG_(strcpy) (dsymfile, VG_(dirname) (executable_name));
      while ((dot_ptr = VG_(strrchr) (dsymfile, '.')))
      {
         /* Find the directory delimiter that follows the '.' character since
            we now look for a .dSYM that follows any bundle extension.  */
         slash_ptr = VG_(strchr) (dot_ptr, '/');
         if (slash_ptr)
         {
             /* NULL terminate the string at the '/' character and append
                the path down to the dSYM file.  */
            *slash_ptr = '\0';
            VG_(strcat) (slash_ptr, APPLE_DSYM_EXT_AND_SUBDIRECTORY);
            VG_(strcat) (slash_ptr, basename_str);
            if (file_exists_p (dsymfile))
               return dsymfile;
         }
         
         /* NULL terminate the string at the '.' character and append
            the path down to the dSYM file.  */
         *dot_ptr = '\0';
         VG_(strcat) (dot_ptr, APPLE_DSYM_EXT_AND_SUBDIRECTORY);
         VG_(strcat) (dot_ptr, basename_str);
         if (file_exists_p (dsymfile))
            return dsymfile;
         
         /* NULL terminate the string at the '.' locatated by the strrchr()
            function again.  */
         *dot_ptr = '\0';
         
         /* We found a previous extension '.' character and did not find a
            dSYM file so now find previous directory delimiter so we don't
            try multiple times on a file name that may have a version number
            in it such as "/some/path/MyApp.6.0.4.app".  */
         slash_ptr = VG_(strrchr) (dsymfile, '/');
         if (!slash_ptr)
            break;
         /* NULL terminate the string at the previous directory character
            and search again.  */
         *slash_ptr = '\0';
      }
   }

   return NULL;
}


static Addr map_file(Char *filename, UInt *size)
{
   SysRes fd, sres;
   struct vg_stat stat_buf;

   fd = VG_(stat)(filename, &stat_buf);
   if (fd.isError) {
      ML_(symerr)(NULL, False, "Can't stat image (to determine its size)?!");
      return 0;
   }
   *size = stat_buf.size;

   fd = VG_(open)(filename, VKI_O_RDONLY, 0);
   if (fd.isError) {
      ML_(symerr)(NULL, False, "Can't open image to read symbols?!");
      return 0;
   }

   sres = VG_(am_mmap_file_float_valgrind)
             ( *size, VKI_PROT_READ, fd.res, 0 );

   VG_(close)(fd.res);

   if (sres.isError) return 0;
   else return sres.res;
}


static Addr make_thin(Addr fat, UInt fat_size, UInt *thin_size)
{
   struct fat_header *fh_be;
   struct fat_header fh;
   struct MACH_HEADER *mh;
   Addr result = fat;

   // Check for fat header.
   if (fat_size < sizeof(struct fat_header)) {
      ML_(symerr)(NULL, False, "Invalid Mach-O file (0 too small).");
      return 0;
   }

   // Fat header is always BIG-ENDIAN
   fh_be = (struct fat_header *)fat;
   fh.magic = VG_(ntohl)(fh_be->magic);
   fh.nfat_arch = VG_(ntohl)(fh_be->nfat_arch);
   if (fh.magic == FAT_MAGIC) {
      // Look for a good architecture.
      struct fat_arch *arch_be;
      struct fat_arch arch;
      int f;
      if (fat_size < sizeof(struct fat_header) + fh.nfat_arch * sizeof(struct fat_arch)) {
         ML_(symerr)(NULL, False, "Invalid Mach-O file (1 too small).");
         return 0;
      }
      for (f = 0, arch_be = (struct fat_arch *)(fh_be+1); 
           f < fh.nfat_arch;
           f++, arch_be++)
      {
         Int cputype;
#       if defined(VGA_ppc)
         cputype = CPU_TYPE_POWERPC;
#       elif defined(VGA_ppc64)
         cputype = CPU_TYPE_POWERPC64;
#       elif defined(VGA_x86)
         cputype = CPU_TYPE_X86;
#       elif defined(VGA_amd64)
         cputype = CPU_TYPE_X86_64;
#       else
#        error unknown architecture
#       endif
         arch.cputype = VG_(ntohl)(arch_be->cputype);
         arch.cpusubtype = VG_(ntohl)(arch_be->cpusubtype);
         arch.offset = VG_(ntohl)(arch_be->offset);
         arch.size = VG_(ntohl)(arch_be->size);
         if (arch.cputype == cputype) {
            if (fat_size < arch.offset + arch.size) {
               ML_(symerr)(NULL, False, "Invalid Mach-O file (2 too small).");
               return 0;
            }
            result = fat + arch.offset;
            *thin_size = arch.size;
            break;
         }
      }
      if (f == fh.nfat_arch) {
         ML_(symerr)(NULL, True, "No acceptable architecture found in fat file.");
         return 0;
      }
   } else {
       // Not fat.
       *thin_size = fat_size;
   }

   if (*thin_size < sizeof(struct MACH_HEADER)) {
      ML_(symerr)(NULL, False, "Invalid Mach-O file (3 too small).");
      VG_(printf)("%d %lu\n", *thin_size, sizeof(struct MACH_HEADER));
      return 0;
   }

   mh = (struct MACH_HEADER *)result;
   if (mh->magic != MAGIC) {
      ML_(symerr)(NULL, False, "Invalid Mach-O file (bad magic).");
      return 0;
   }

   if (*thin_size < sizeof(struct MACH_HEADER) + mh->sizeofcmds) {
      ML_(symerr)(NULL, False, "Invalid Mach-O file (4 too small).");
      return 0;
   }

   return result;
}


static UChar *getsectdata(Addr base, Int size, 
                          Char *segname, Char *sectname, Int *sect_size)
{
   struct MACH_HEADER *mh = (struct MACH_HEADER *)base;
   struct load_command *cmd;          
   int c;

   for (c = 0, cmd = (struct load_command *)(mh+1);
        c < mh->ncmds;
        c++, cmd = (struct load_command *)(cmd->cmdsize + (Addr)cmd))
   {
      if (cmd->cmd == LC_SEGMENT_CMD) {
         struct SEGMENT_COMMAND *seg = (struct SEGMENT_COMMAND *)cmd;
         if (0 == VG_(strncmp(seg->segname, segname, sizeof(seg->segname)))) {
            struct SECTION *sects = (struct SECTION *)(seg+1);
            int s;
            for (s = 0; s < seg->nsects; s++) {
               if (0 == VG_(strncmp(sects[s].sectname, sectname, 
                                    sizeof(sects[s].sectname)))) 
               {
                  if (sect_size) *sect_size = sects[s].size;
                  return (UChar *)(base + sects[s].offset);
               }
            }
         }
      }
   }

   if (sect_size) *sect_size = 0;
   return 0;
}


Bool ML_(read_macho_debug_info)( struct _DebugInfo* di )
{
   SysRes m_res;
   Addr ob_map_base = 0, ob_oimage = 0;
   UInt ob_map_size, ob_n_oimage;
   struct symtab_command *symcmd = NULL;
   struct dysymtab_command *dysymcmd = NULL;
   Addr dw_map_base = 0, dw_oimage = 0;
   UInt dw_map_size, dw_n_oimage;
   Char *dsymfile = NULL;
   Bool got_nlist = False;
   Bool got_dwarf = False;
   Bool got_uuid = False;
   unsigned char uuid[16];

   /* mmap the object file to look for di->soname and di->text_bias 
      and uuid and nlist and STABS */

   if (VG_(clo_verbosity) > 1)
      VG_(message)(Vg_DebugMsg, "Looking for debug info in %s ...",
                   di->filename);

   di->text_bias = 0;
   ob_map_base = map_file(di->filename, &ob_map_size);
   if (ob_map_base) {
      ob_oimage = make_thin(ob_map_base, ob_map_size, &ob_n_oimage);
      if (ob_oimage) {
         // Find LC_SYMTAB and LC_DYSYMTAB, if present.
         // Read di->soname from LC_ID_DYLIB if present, 
         //    or from LC_ID_DYLINKER if present, 
         //    or use "NONE".
         // Get di->text_bias (aka slide) based on the corresponding LC_SEGMENT
         // Get uuid for later dsym search
         struct MACH_HEADER *mh = (struct MACH_HEADER *)ob_oimage;
         struct load_command *cmd;
         int c;

         for (c = 0, cmd = (struct load_command *)(mh+1);
              c < mh->ncmds;
              c++, cmd = (struct load_command *)(cmd->cmdsize + (unsigned long)cmd))
         {
            if (cmd->cmd == LC_SYMTAB) {
               symcmd = (struct symtab_command *)cmd;
            } 
            else if (cmd->cmd == LC_DYSYMTAB) {
               dysymcmd = (struct dysymtab_command *)cmd;
            } 
            else if (cmd->cmd == LC_ID_DYLIB  &&  mh->filetype == MH_DYLIB) {
               // GrP fixme bundle?
               struct dylib_command *dcmd = (struct dylib_command *)cmd;
               UChar *dylibname = dcmd->dylib.name.offset + (UChar *)dcmd;
               UChar *soname = VG_(strrchr)(dylibname, '/');
               if (!soname) soname = dylibname;
               else soname++;
               di->soname = VG_(arena_strdup)(VG_AR_DINFO, "di.readmacho.dylibname", soname);
            }
            else if (cmd->cmd==LC_ID_DYLINKER  &&  mh->filetype==MH_DYLINKER) {
               struct dylinker_command *dcmd = (struct dylinker_command *)cmd;
               UChar *dylinkername = dcmd->name.offset + (UChar *)dcmd;
               UChar *soname = VG_(strrchr)(dylinkername, '/');
               if (!soname) soname = dylinkername;
               else soname++;
               di->soname = VG_(arena_strdup)(VG_AR_DINFO, "di.readmacho.dylinkername", soname);
            }
            else if (cmd->cmd == LC_SEGMENT_CMD) {
               struct SEGMENT_COMMAND *seg = (struct SEGMENT_COMMAND *)cmd;
               if (!di->text_present  &&  seg->fileoff == 0  &&  
                   seg->filesize != 0) 
               {
                  di->text_present = True;
                  di->text_svma = (Addr)seg->vmaddr;
                  di->text_avma = di->rx_map_avma;
                  di->text_size = seg->vmsize;
                  di->text_bias = di->text_avma - (Addr)seg->vmaddr;
               }
            }
            else if (cmd->cmd == LC_UUID) {
                struct uuid_command *uuid_cmd = (struct uuid_command *)cmd;
                VG_(memcpy)(uuid, uuid_cmd->uuid, sizeof(uuid));
                got_uuid = True;
            }
         }
      }

      ; /* Don't unmap object yet; we'll read nlist and STABS after DWARF. */
   }

   if (!di->soname) {
      di->soname = VG_(arena_strdup)(VG_AR_DINFO, "di.readmacho.noname", "NONE");
   }


   /* mmap the dSYM file to look for DWARF debug info */

   dsymfile = find_separate_debug_file(di->filename);
   // fixme verify dsymfile matches uuid

   if (dsymfile) {
      if (VG_(clo_verbosity) > 1)
         VG_(message)(Vg_DebugMsg, "Looking for debug info in %s ...",
                      dsymfile);
      dw_map_base = map_file(dsymfile, &dw_map_size);
      if (dw_map_base) {
          dw_oimage = make_thin(dw_map_base, dw_map_size, &dw_n_oimage);
      }
   }
   if (dw_oimage) {
      UChar *debug_info_img = NULL;
      Int debug_info_sz;
      UChar *debug_abbv_img;
      Int debug_abbv_sz;
      UChar *debug_line_img;
      Int debug_line_sz;
      UChar *debug_str_img;
      Int debug_str_sz;
      UChar *debug_ranges_img;
      Int debug_ranges_sz;
      UChar *debug_loc_img;
      Int debug_loc_sz;
      UChar *debug_name_img;
      Int debug_name_sz;
      
      debug_info_img = 
          getsectdata(dw_oimage, dw_n_oimage, 
                      "__DWARF", "__debug_info", &debug_info_sz);
      debug_abbv_img = 
          getsectdata(dw_oimage, dw_n_oimage, 
                      "__DWARF", "__debug_abbrev", &debug_abbv_sz);
      debug_line_img = 
          getsectdata(dw_oimage, dw_n_oimage, 
                      "__DWARF", "__debug_line", &debug_line_sz);
      debug_str_img = 
          getsectdata(dw_oimage, dw_n_oimage, 
                      "__DWARF", "__debug_str", &debug_str_sz);
      debug_ranges_img = 
          getsectdata(dw_oimage, dw_n_oimage, 
                      "__DWARF", "__debug_aranges", &debug_ranges_sz);
      debug_loc_img = 
          getsectdata(dw_oimage, dw_n_oimage, 
                      "__DWARF", "__debug_loc", &debug_loc_sz);
      debug_name_img = 
          getsectdata(dw_oimage, dw_n_oimage, 
                      "__DWARF", "__debug_pubnames", &debug_name_sz);
   
      if (debug_info_img) {
         if (VG_(clo_verbosity) > 1)
            VG_(message)(Vg_DebugMsg,
                         "Reading DWARF debuginfo for %s (%#lx) from %s"
                         " (%d %d %d %d %d %d)",
                         di->filename, di->text_avma, dsymfile, 
                         debug_info_sz, debug_abbv_sz, debug_line_sz, 
                         debug_str_sz, debug_ranges_sz, debug_loc_sz
                         );
         /* The old reader: line numbers and unwind info only */
         ML_(read_debuginfo_dwarf3) ( di,
                                      debug_info_img, debug_info_sz,
                                      debug_abbv_img, debug_abbv_sz,
                                      debug_line_img, debug_line_sz,
                                      debug_str_img,  debug_str_sz );
         /* Function names and ranges from debug_pubnames */
         ML_(read_fnnames_dwarf3) ( di,
                                    debug_info_img,   debug_info_sz,
                                    debug_abbv_img,   debug_abbv_sz,
                                    debug_line_img,   debug_line_sz,
                                    debug_str_img,    debug_str_sz,
                                    debug_ranges_img, debug_ranges_sz,
                                    debug_loc_img,    debug_loc_sz,
                                    debug_name_img,   debug_name_sz);

         /* The new reader: read the DIEs in .debug_info to acquire
            information on variable types and locations.  But only if
            the tool asks for it, or the user requests it on the
            command line. */
         if (VG_(needs).var_info /* the tool requires it */
             || VG_(clo_read_var_info) /* the user asked for it */) {
            ML_(new_dwarf3_reader)(
               di, debug_info_img,   debug_info_sz,
                   debug_abbv_img,   debug_abbv_sz,
                   debug_line_img,   debug_line_sz,
                   debug_str_img,    debug_str_sz,
                   debug_ranges_img, debug_ranges_sz,
                   debug_loc_img,    debug_loc_sz
            );
         }
         got_dwarf = True;
      }
   }

   if (dw_map_base) {
      m_res = VG_(am_munmap_valgrind) ( dw_map_base, dw_map_size );
      vg_assert(!m_res.isError);
   }

   if (dsymfile) VG_(free)(dsymfile);


   /* Read nlist symbol tables and (if no DWARF) STABS debuginfo. 
      In particular, hand-written assembly often has an nlist entry 
      but no DWARF debuginfo. Prefer the DWARF version.
   */

   if (ob_oimage  &&  symcmd  &&  dysymcmd) {
      /* Read nlist symbol table and STABS debug info */
      struct NLIST *syms;
      UChar *strs;
      
      if (ob_n_oimage < symcmd->stroff + symcmd->strsize  ||  
          ob_n_oimage < symcmd->symoff + symcmd->nsyms*sizeof(struct NLIST))
      {
         ML_(symerr)(NULL, False, "Invalid Mach-O file (5 too small).");
         goto bad_nlist;
      }   
      if (dysymcmd->ilocalsym + dysymcmd->nlocalsym > symcmd->nsyms  ||  
          dysymcmd->iextdefsym + dysymcmd->nextdefsym > symcmd->nsyms)
      {
         ML_(symerr)(NULL, False, "Invalid Mach-O file (bad symbol table).");
         goto bad_nlist;
      }
      
      syms = (struct NLIST *)(ob_oimage + symcmd->symoff);
      strs = (UChar *)(ob_oimage + symcmd->stroff);
      
      if (VG_(clo_verbosity) > 1)
         VG_(message)(Vg_DebugMsg, "Reading nlist symbols and STABS debuginfo for %s (%#lx) (%d %d)",
                      di->filename, di->text_avma, 
                      dysymcmd->nextdefsym, dysymcmd->nlocalsym );
      // extern symbols
      read_symtab(di, 
                  syms + dysymcmd->iextdefsym, dysymcmd->nextdefsym, 
                  strs, symcmd->strsize);
      // static and private_extern symbols
      read_symtab(di, 
                  syms + dysymcmd->ilocalsym, dysymcmd->nlocalsym, 
                  strs, symcmd->strsize);
      if (!got_dwarf) {
         // debug info
         ML_(read_debuginfo_stabs) ( di, di->text_bias, 
                                     (UChar *)syms, 
                                     symcmd->nsyms * sizeof(struct NLIST), 
                                     strs, symcmd->strsize);
      }
      
      got_nlist = True;
   }
   
 bad_nlist: 
   ;
   
   ML_(shrinkSym)(di);
   ML_(shrinkLineInfo)(di);

   if (ob_map_base) {
      m_res = VG_(am_munmap_valgrind) ( ob_map_base, ob_map_size );
      vg_assert(!m_res.isError);
   }

   if (got_dwarf  ||  got_nlist) {
      return True;
   }

   ML_(symerr)(NULL, True, "No symbol table found.");
   return False;
}


