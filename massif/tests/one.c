#include <stdlib.h>

// Allocate some memory and then deallocate it, to get a nice up-then-down
// graph.

int main(void)
{
   malloc(1);
   return 0;
}
