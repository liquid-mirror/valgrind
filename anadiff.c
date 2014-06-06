
#define _GNU_SOURCE
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define FILENAME  "./diffs"

int main ( void )
{
  FILE* f = fopen(FILENAME, "r");
  assert(f);

  int nLines = 0;
  int nDiffs = 0;

  while (1) {
    if (feof(f)) break;

    char* line = NULL;
    size_t len_ign = 0;
    ssize_t n = getline(&line, &len_ign, f);
    if (n == -1) break;
    assert(n >= 0);
    assert(line);

    char* bar = strchr(line, '|');
    if (bar) nDiffs++;

    nLines++;

    const int step = 100000;
    if ((nLines % step) == 0) {
      printf("Lines %d-%d  diffs %d\n", nLines-step+1, nLines, nDiffs);
      nDiffs = 0;
    }

    free(line);

  }

  fclose(f);

  printf("Saw %d lines\n", nLines);

  return 0;
}
