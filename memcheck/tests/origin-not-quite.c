// This test demonstrates more cases we cannot handle, but conceivably
// might.

#include <assert.h>
#include <stdlib.h>

int x = 0;

typedef long long Long;

int main(void)
{
   assert(4 == sizeof(int));
   assert(8 == sizeof(Long));

   // 64-bit undefined double.
   {
      double* ptr_to_undef_double = malloc(sizeof(double));
      double  undef_double = *ptr_to_undef_double;
      x += (undef_double == (double)123.45 ? 12 : 23);
   }

   // 32-bit undefined float.
   {
      float* ptr_to_undef_float = malloc(sizeof(float));
      float undef_float = *ptr_to_undef_float;
      x += (undef_float == (float)234.56  ? 13 : 24);
   }

   // Stack, 32-bit, recently modified.
   // Problem here is that we don't chase backwards through loads and
   // stores.  Ie. the variable is stored after it's been modified, then
   // loaded again, so we don't see the unmodified version.
   {
      int modified_undef_stack_int;
      modified_undef_stack_int++;
      x += (modified_undef_stack_int == 0x1234 ? 11 : 22);
   }
   
   return x;
}
