
#include <stdio.h>

int main ( int argc, char** argv, char** envp )
{
  int i = 0;
  while (*envp) {
    i++;
    printf("%d  %s\n", i, *envp);
    envp++;
  }
  return 0;
}
