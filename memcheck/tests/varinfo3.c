
/* Check for correct handling of static vs non-static, local vs
   non-local variables in a zero-biased executable. */

/* Relevant compile flags are:

   -Wall -g -I$prefix/include/valgrind

   eg -Wall -g -I`pwd`/Inst/include/valgrind
*/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "memcheck/memcheck.h"

/* Cause memcheck to complain about the address "a" and so to print
   its best guess as to what "a" actually is.  a must be
   addressible. */

void croak ( void* a )
{
  volatile char undef;
  *(char*)a = undef;
  VALGRIND_CHECK_MEM_IS_DEFINED(a, 1);
}

#include <stdio.h>

static char static_global_def[10]    = {0,0,0,0,0, 0,0,0,0,0};
       char nonstatic_global_def[10] = {0,0,0,0,0, 0,0,0,0,0};
static char static_global_undef[10];
       char nonstatic_global_undef[10];

void bar ( char* p1, char* p2, char* p3, char* p4 )
{
   croak(p1);
   croak(p2);
   croak(p3);
   croak(p4);
}

void foo ( void )
{
   static char static_local_def[10]    = {0,0,0,0,0, 0,0,0,0,0};
          char nonstatic_local_def[10] = {0,0,0,0,0, 0,0,0,0,0};
   static char static_local_undef[10];
          char nonstatic_local_undef[10];
   croak ( 1 + (char*)&static_global_def );
   croak ( 2 + (char*)&nonstatic_global_def );
   croak ( 3 + (char*)&static_global_undef );
   croak ( 4 + (char*)&nonstatic_global_undef );
   bar( 5 + (char*)&static_local_def,
        6 + (char*)&nonstatic_local_def,
        7 + (char*)&static_local_undef,
        8 + (char*)&nonstatic_local_undef );
}

int main ( void )
{
  foo();
  return 0;
}
