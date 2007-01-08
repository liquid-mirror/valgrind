// This one tests loads and stores through undefined pointers.

#include <stdlib.h>

typedef long Word;

int main(void)
{
   Word a;
   Word* ptr_to_undef_word = malloc(sizeof(Word));
   Word  undef_word = *ptr_to_undef_word;

   a = *(Word*)undef_word;    // read through undefined pointer

   return 0;
}
