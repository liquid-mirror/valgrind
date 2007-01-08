
#include <stdlib.h>

typedef long Word;

int main(void)
{
   int(*f)(void);
   Word* ptr_to_undef_word = malloc(sizeof(Word));
   Word  undef_word = *ptr_to_undef_word;

   f = (void*)undef_word;
   return f();                      // jump to undefined target
}
