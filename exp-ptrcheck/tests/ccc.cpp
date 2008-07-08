#include <assert.h>
#include <stdlib.h>
#include <malloc.h> // for memalign()

int main(void)
{
   int  y1, y2, y3, y4, y5, y6;
   int* x1 = (int*)malloc(sizeof(int));
   int* x2 = new int;
   int* x3 = new int[10];
   int* x4 = (int*)calloc(1, sizeof(int));
   int* x5 = (int*)memalign(8, sizeof(int));
   int* x6;  
   int res = posix_memalign((void**)&x6, 8, sizeof(int));

   assert(NULL != x1 && NULL != x2 && NULL != x3 && NULL != x4 &&
          NULL != x5 && 0 == res);

   // all underruns
   y1 = x1[-1];
   y2 = x2[-1];
   y3 = x3[-1];
   y4 = x4[-1];
   y5 = x5[-1];
   y6 = x6[-1];

   return y1+y2+y3+y4+y5+y6;
}
