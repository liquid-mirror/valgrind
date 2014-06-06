
#include <stdio.h>

typedef unsigned long int UWord;

int main ( int argc, char** argv, char** envp )
{
  //fprintf(stderr, "bye\n"); return 0;

  //fprintf(stderr, "argc %d  argv %p  envp %p\n", argc, argv, envp);

  int i;
  for (i = 0; argv[i]; i++) {
    fprintf(stderr, "%s %s\n", i == 0 ? " exe" : "carg", argv[i]);
  }
  //fprintf(stderr, "#argv %d\n", i);

  if (0) {
  for (i = 0; envp[i]; i++) {
    fprintf(stderr, "envp %d %s\n", i, envp[i]);
  }
  fprintf(stderr, "#envp %d\n", i);
  }

  if (0) {
  UWord* p = (UWord*)&envp[i+1];
  i = 0;
  while (1) {
    if (*p == 0) break;
    fprintf(stderr, "%016lx %016lx\n", p[0], p[1]);
    p += 2;
    i += 1;
    if (i == 1000) break;
  }

  fprintf(stderr, "%d auxv entries\n", i);
  }

  return 0;
}
