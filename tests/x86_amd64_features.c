
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// This file determines x86/AMD64 features a processor supports.
//
// We return:
// - 0 if the machine matches the asked-for feature.
// - 1 if the machine does not.
// - 2 if the asked-for feature isn't recognised (this will be the case for
//     any feature if run on a non-x86/AMD64 machine).
// - 3 if there was a usage error (it also prints an error message).

#define False  0
#define True   1
typedef int    Bool;

//---------------------------------------------------------------------------
// {x86,amd64}-linux (part 1 of 2)
//---------------------------------------------------------------------------
#if defined(VGP_x86_linux) || defined(VGP_amd64_linux) || \
                              defined(VGP_amd64_darwin)
static void cpuid ( unsigned int n,
                    unsigned int* a, unsigned int* b,
                    unsigned int* c, unsigned int* d )
{
   __asm__ __volatile__ (
      "cpuid"
      : "=a" (*a), "=b" (*b), "=c" (*c), "=d" (*d)      /* output */
      : "0" (n)         /* input */
   );
}
#endif   // VGP_x86_linux || VGP_amd64_linux || VGP_amd64_darwin

//---------------------------------------------------------------------------
// x86-darwin (part 1 of 2)
//---------------------------------------------------------------------------
// We can't use the one above for x86-darwin, because we get this:
//
//   arch_test.c:88: error: can't find a register in class ‘BREG’ while
//   reloading ‘asm’
//
// because %ebx is reserved for PIC.  This version preserves %ebx.
#if defined(VGP_x86_darwin)
static void cpuid ( unsigned int n,
                    unsigned int* a, unsigned int* b,
                    unsigned int* c, unsigned int* d )
{
   unsigned int abcd[4] = { n, 0, 0, 0 };

   __asm__ __volatile__ (
      "\tmovl %%ebx,%%esi\n"
      "\tmovl 0(%0),%%eax\n"
      "\tcpuid\n"
      "\tmovl %%eax,0(%0)\n"
      "\tmovl %%ebx,4(%0)\n"
      "\tmovl %%ecx,8(%0)\n"
      "\tmovl %%edx,12(%0)\n"
      "\tmovl %%esi,%%ebx\n"
      : /*out*/
      : /*in*/ "r"(abcd)
      : /*clobber*/ "eax", "esi", "ecx", "edx", "memory", "cc"
      );

   *a = abcd[0];
   *b = abcd[1];
   *c = abcd[2];
   *d = abcd[3];
}
#endif   // VGP_x86_darwin

//---------------------------------------------------------------------------
// {x86,amd64}-{linux,darwin} (part 2 of 2)
//---------------------------------------------------------------------------
#if defined(VGA_x86)  || defined(VGA_amd64)
static Bool go(char* cpu)
{ 
   unsigned int level = 0, cmask = 0, dmask = 0, a, b, c, d;

   if        ( strcmp( cpu, "x86-fpu" ) == 0 ) {
     level = 1;
     dmask = 1 << 0;
   } else if ( strcmp( cpu, "x86-cmov" ) == 0 ) {
     level = 1;
     dmask = 1 << 15;
   } else if ( strcmp( cpu, "x86-mmx" ) == 0 ) {
     level = 1;
     dmask = 1 << 23;
   } else if ( strcmp( cpu, "x86-mmxext" ) == 0 ) {
     level = 0x80000001;
     dmask = 1 << 22;
   } else if ( strcmp( cpu, "x86-sse" ) == 0 ) {
     level = 1;
     dmask = 1 << 25;
   } else if ( strcmp( cpu, "x86-sse2" ) == 0 ) {
     level = 1;
     dmask = 1 << 26;
   } else if ( strcmp( cpu, "x86-sse3" ) == 0 ) {
     level = 1;
     cmask = 1 << 0;
   } else if ( strcmp( cpu, "x86-ssse3" ) == 0 ) {
     level = 1;
     cmask = 1 << 9;
#if defined(VGA_amd64)
   } else if ( strcmp( cpu, "amd64-sse3" ) == 0 ) {
     level = 1;
     cmask = 1 << 0;
   } else if ( strcmp( cpu, "amd64-ssse3" ) == 0 ) {
     level = 1;
     cmask = 1 << 9;
#endif
   } else {
     return 2;          // Unrecognised feature.
   }

   assert( !(cmask != 0 && dmask != 0) );
   assert( !(cmask == 0 && dmask == 0) );

   cpuid( level & 0x80000000, &a, &b, &c, &d );

   if ( a >= level ) {
      cpuid( level, &a, &b, &c, &d );

      if (dmask > 0 && (d & dmask) != 0) return 0;    // Feature present.
      if (cmask > 0 && (c & cmask) != 0) return 0;    // Feature present.
   }
   return 1;                                          // Feature not present.
}

#else

static Bool go(char* cpu)
{
   return 2;      // Feature not recognised (non-x86/AMD64 machine!)
}

#endif   // defined(VGA_x86)  || defined(VGA_amd64)


//---------------------------------------------------------------------------
// main
//---------------------------------------------------------------------------
int main(int argc, char **argv)
{
   if ( argc != 2 ) {
      fprintf( stderr, "usage: x86_amd64_features <feature>\n" );
      exit(3);                // Usage error.
   }
   return go(argv[1]);
}
