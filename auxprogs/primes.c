
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <assert.h>

int isprime ( int n )
{
   int m;
   int sqrt_n = sqrt(n);
   for (m = 2; m <= sqrt_n+1; m++)  // +1 in case of obscure rounding error
      if ((n % m) == 0) return 0;
   return 1;
}

int main ( int argc, char** argv )
{
  int i, start;
   if (argc != 2) {
      fprintf(stderr, "usage: %s <number>\n", argv[0]);
      return 1;
   }
   start = atoi(argv[1]);
   assert(start >= 2);
   for (i = start; i < start+2000; i++)
     if (isprime(i)) { printf ( "%d ", i ); fflush(stdout); }
   return 0;
}
