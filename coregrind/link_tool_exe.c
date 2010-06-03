
/* This program handles linking the tool executables, statically and
   at an alternative load address.  Linking them statically sidesteps
   all sorts of complications to do with having two copies of the
   dynamic linker (valgrind's and the client's) coexisting in the same
   process.  The alternative load address is needed because Valgrind
   itself will load the client at whatever address it specifies, which
   is almost invariably the default load address.  Hence we can't
   allow Valgrind itself (viz, the tool executable) to be loaded at
   that address.

   Unfortunately there's no standard way to do 'static link at
   alternative address', so this program handles the per-platform
   hoop-jumping.
*/

/* What we get passed here is:
   first arg
      the alternative load address
   all the rest of the args
      the gcc invokation to do the final link, that
      the build system would have done, left to itself

   We just let assertions fail rather than do proper error reporting.
   We don't expect the users to run this directly.  It is only run
   from as part of the build process, with carefully constrained
   inputs.
*/

/* ------------------------- LINUX ------------------------- */

#if defined(VGO_linux)

/* Scheme is simple: pass the specified command to the linker as-is,
   except, add "-static" and "-Ttext=<argv[1]>" to it.

   Also apparently we need --build-id=none.  For older ld's (2.18
   vintage) the first two flags are fine.  For newer ones (2.20), a
   .note.gnu.build-id is nevertheless created at the default text
   segment address, which of course means the resulting executable is
   unusable.  So we have to tell ld not to generate that, with
   --build-id=none.

   As to "how far back is this flag supported", it's available at
   least in ld 2.18 and 2.20 and gold 2.20.
*/

// Don't NDEBUG this; the asserts are necesary for
// safety checks.
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>  /* WEXITSTATUS */

int main ( int argc, char** argv )
{
   int         i;
   int/*bool*/ failed = 0;
   size_t      reqd = 0;

   // expect at least: alt-load-address gcc -o foo bar.o
   assert(argc > 5);

   // check for plausible-ish alt load address
   char* ala = argv[1];
   assert(ala[0] == '0');
   assert(ala[1] == 'x');

   // We'll need to invoke this to do the linking
   char* gcc = argv[2];

   // and the 'restargs' are argv[3 ..]

   // so, build up the complete command here:
   // 'gcc' -static -Ttext='ala' 'restargs'

   // first, do length safety checks
   reqd += 1+ strlen(gcc);
   reqd += 1+ 100/*let's say*/ + strlen(ala);
   for (i = 3; i < argc; i++)
      reqd += 1+ strlen(argv[i]);

   reqd += 1;
   char* cmd = calloc(reqd,1);
   assert(cmd);

   char ttext[100];
   assert(strlen(ala) < 30);
   memset(ttext, 0, sizeof(ttext));
   sprintf(ttext, " -static -Wl,-Ttext=%s -Wl,--build-id=none", ala);

   strcpy(cmd, gcc);
   strcat(cmd, ttext);
   for (i = 3; i < argc; i++) {
     strcat(cmd, " ");
     strcat(cmd, argv[i]);
   }

   assert(cmd[reqd-1] == 0);

   if (0) printf("\n");
   printf("link_tool_exe: %s\n", cmd);
   if (0) printf("\n");

   int r = system(cmd);
   if (r == -1 || WEXITSTATUS(r) != 0)
      failed = 1;

   free(cmd);

   // return the result of system.
   return failed ? 1 : 0;
}

/* ------------------------- DARWIN ------------------------ */

#elif defined(VGO_darwin)

/* Plan is: look at the specified gcc invokation.  Ignore all parts of
   it except the *.a, *.o and -o outfile parts.  Wrap them up in a new
   command which looks (eg) as follows:

   (64-bit):

   /usr/bin/ld -static -arch x86_64 -macosx_version_min 10.5 \
      -o memcheck-amd64-darwin -u __start -e __start \
      -image_base 0x138000000 -stack_addr 0x13c000000 \
      -stack_size 0x800000 \
      memcheck_amd*.o \
      ../coregrind/libcoregrind-amd64-darwin.a \
      ../VEX/libvex-amd64-darwin.a

   (32-bit)

   /usr/bin/ld -static -arch i386 -macosx_version_min 10.5 \
      -o memcheck-x86-darwin -u __start -e __start \
      -image_base 0x38000000 -stack_addr 0x3c000000 \
      -stack_size 0x800000 \
      memcheck_x86*.o \
      ../coregrind/libcoregrind-x86-darwin.a \
      ../VEX/libvex-x86-darwin.a

   The addresses shown above will actually work, although "for real" we
   of course need to take it from argv[1].  In these examples the stack
   is placed 64M after the executable start.  It is probably safer to
   place it 64M before the executable's start point, so the executable
   + data + bss can grow arbitrarily in future without colliding with
   the stack.

   There's one more twist: this executable (for the program in this
   file) could be compiled as either 32- or 64-bit.  That has no
   bearing at all on the word size of the executable for which we are
   linking.  We need to know the latter since we need to hand to the
   linker, "-arch x86_64" or "-arch i386".  Fortunately we can figure
   this out by scanning the gcc invokation, which itself must contain
   either "-arch x86_64" or "-arch i386".
*/

/* user configurable constants: how far before the exe should we
   place the stack? */
#define TX_STACK_OFFSET_BEFORE_TEXT (64 * 1024 * 1024)
/* and how big should the stack be */
#define TX_STACK_SIZE (8 * 1024 * 1024)


// Don't NDEBUG this; the asserts are necesary for
// safety checks.
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static void add_to ( char** str, size_t* str_sz, char* to_add )
{
   size_t needed = strlen(to_add) +2/*paranoia*/;
   size_t currlen = strlen(*str);
   assert(currlen < *str_sz);

   while (needed >= *str_sz - currlen) {
      *str = realloc(*str, 2 * *str_sz);
      assert(*str);
      (*str_sz) *= 2;
   }

   assert(currlen < *str_sz);
   assert(needed < *str_sz - currlen);
   strcat(*str, to_add);
}

static int/*bool*/ is_dota_or_doto ( char* str )
{
   assert(str);
   size_t n = strlen(str);
   if (n < 2) return 0;
   if (str[n-2] == '.' && (str[n-1] == 'a' || str[n-1] == 'o'))
       return 1;
   return 0;
}

/* Run the specified command as-is; ignore the specified load address
   (argv[1]). */

int main ( int argc, char** argv )
{
   int         i;
   int/*bool*/ failed = 0;
   size_t      reqd = 0;

   // expect at least: alt-load-address gcc -o foo bar.o
   assert(argc > 5);

   // check for plausible-ish alt load address, and get hold
   // of it
   char* ala_str = argv[1];
   unsigned long long int ala = 0;

   assert(ala_str[0] == '0');
   assert(ala_str[1] == 'x');

   int r = sscanf(ala_str, "0x%llx", &ala);
   assert(r == 1);

   // get hold of the outfile name
   char* outfile_name = NULL;
   for (i = 1; i < argc-1; i++) {
      if (0 == strcmp(argv[i], "-o")) {
         outfile_name = argv[i+1];
         break;
      }
   }
   assert(outfile_name);

   // get hold of the string following -arch
   char* arch_str = NULL;
   for (i = 1; i < argc-1; i++) {
      if (0 == strcmp(argv[i], "-arch")) {
         arch_str = argv[i+1];
         break;
      }
   }
   assert(arch_str);

   // build the command line
   size_t cmd_sz = 1;
   char*  cmd    = calloc(cmd_sz, 1);
   assert(cmd);

   add_to(&cmd, &cmd_sz,  "/usr/bin/ld");
   add_to(&cmd, &cmd_sz,  " -static");
   add_to(&cmd, &cmd_sz,  " -arch ");
   add_to(&cmd, &cmd_sz,  arch_str);
   add_to(&cmd, &cmd_sz,  " -macosx_version_min 10.5");
   add_to(&cmd, &cmd_sz,  " -o ");
   add_to(&cmd, &cmd_sz,  outfile_name);
   add_to(&cmd, &cmd_sz,  " -u __start -e __start");

   char buf[40];
   sprintf(buf, "0x%llx", ala);
   add_to(&cmd, &cmd_sz,  " -image_base ");
   add_to(&cmd, &cmd_sz,  buf);

   sprintf(buf, "0x%llx", ala - TX_STACK_OFFSET_BEFORE_TEXT);
   add_to(&cmd, &cmd_sz,  " -stack_addr ");
   add_to(&cmd, &cmd_sz,  buf);

   sprintf(buf, "0x%llx", (unsigned long long int)TX_STACK_SIZE);
   add_to(&cmd, &cmd_sz,  " -stack_size ");
   add_to(&cmd, &cmd_sz,  buf);

   for (i = 3; i < argc; i++) {
      if (is_dota_or_doto(argv[i])) {
         add_to(&cmd, &cmd_sz,  " ");
         add_to(&cmd, &cmd_sz,  argv[i]);
      }
   }

   if (1) printf("\n");
   printf("link_tool_exe: %s\n", cmd);
   if (1) printf("\n");

   r = system(cmd);
   if (r == -1 || WEXITSTATUS(r) != 0)
      failed = 1;

   free(cmd);

   // return the result of system.
   return failed ? 1 : 0;
}


#else
#  error "Unsupported OS"
#endif
