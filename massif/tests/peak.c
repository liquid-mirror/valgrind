#include <stdlib.h>

int main(void)
{
   int i;
   for (i = 0; i < 20; i++) {
      int* p;
      p = malloc(100);
      p = malloc(100);
      free(p);
   }
   return 0;
}
