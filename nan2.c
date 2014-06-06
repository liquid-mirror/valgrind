
#include <stdio.h>
#include <math.h>
#include <stdlib.h>

int main ( void )
{
  const int N = 4096;
  double x = sqrt(-1.0);
  double* a = malloc(N * sizeof(double));
  int i;
  for (i = 0; i < N; i++) a[i] = x;
  free(a);
  return 0;
}
