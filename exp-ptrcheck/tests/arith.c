
#include <stdlib.h>

typedef unsigned int Uint;

int main(void)
{
   int* x = malloc(sizeof(int) * 10);
   int* y = malloc(sizeof(int) * 10);
   int* y2 = y + 3;

   // ok -- same segment
   int  w = y2 - y;

   // ok -- different heap segments (result can only be used to index off
   // 'x', but glibc's strcpy() does this...)
   int* z = (int*)((int)x - (int)y);

   w = (int)y2 + (int)y;            // bad (same segment)

   w = (int)x  & (int)y;            // bad (different segments)

   w = (int)y2 / (int)4;            // bad, but indistinguishable from
                                    // acceptable '%' cases...

   w = (int)y2 % (int)4;            // ok
   w = (int)y2 % (int)y;            // bad -- modulor(?) is a pointer
   w = (int)0xffffffff % (int)y;    // bad -- modulend(?) is a non-pointer

   w = (Uint)y2 % (Uint)4;          // ok
   w = (Uint)y2 % (Uint)y;          // bad -- modulor(?) is a pointer
   w = (Uint)0xffffffff % (Uint)y;  // bad -- modulend(?) is a non-pointer

   w = (int)y * (int)y2;            // bad

   w = (int)y >> (int)2;            // ok
   w = (int)y << (int)2;            // ok

   w = (int)y &  0xffff;            // ok
   w = (int)y |  0xffff;            // ok
   w = (int)y ^  (int)y2;           // ok

   w = ~((int)y);                   // ok

   w = -((int)y);                   // bad -- operand is a non-pointer

   w = (int)x ^ (int)x;             // xor(ptr,ptr) --> constant (0)
   z = x + w;                       // ok, because xor result was zero

   w = (int)x ^ ((int)x+1);         // xor(ptr,ptr') --> constant (small)
   z = x + w;                       // ok, because xor result was constant

   w = (int)x ^ (int)y;             // xor(ptr,ptr') --> constant (small)
   z = x + w;                       // ok, because xor result was constant

   return (int)z;
}
