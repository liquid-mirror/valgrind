
#include <stdio.h>
#include "valgrind.h"

/* The simplest possible wrapping test: just call a wrapped function
   and check we run the wrapper instead. */

/* The "original" function */
void actual ( void )
{
   printf("in actual\n");
}

/* The wrapper.  Since this executable won't have a soname, we have to
   use "NONE", since V treats any executable/.so which lacks a soname
   as if its soname was "NONE". */
void I_REPLACE_SONAME_FNNAME_ZU(NONE,actual) ( void )
{
   printf("wrapper-pre\n");

   CALL_ORIG_VOIDFN_0(actual);

   printf("wrapper-post\n");
}

/* --------------- */

int main ( void )
{
   printf("starting\n");
   actual();
   return 0;
}
