#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <assert.h>

#define COUNT 10

static int race;
static __thread int local;
__thread int global;

/* deliberate failure */
static int *test_race(void)
{
  return &race;
}

static int *test_local(void)
{
  return &local;
}

static int *test_global(void)
{
  return &global;
}

static const struct timespec awhile = { 0, 50000000 };

typedef int *(*func_t)(void);
struct testcase {
  const char *name;
  func_t func;
};

static void *tls_ptr(void *p)
{
  struct testcase *test = (struct testcase *)p;
  int *ip = (*test->func)();
  int here = 0;
  int i;

  for(i = 0; i < COUNT; i++) {
    int a = (*ip)++;
    int b = here++;
    if (a != b)
      printf("tls_ptr: case \"%s\" has mismatch: *ip=%d here=%d\n",
             test->name, a, b);
    nanosleep(&awhile, 0);
  }

  return 0;
}

static const struct testcase tests[] = {
#define T(t)   { #t, test_##t }
  T(race),
  T(local),
  T(global),
#undef T
};

#define NTESTS   (sizeof(tests)/sizeof(*tests))

int main(int argc, char** argv)
{
  if (argc != 2) {
    fprintf(stderr, "usage: %s <number_threads_per_test>\n", argv[0]);
    return 1;
  }

  int nThr = atoi(argv[1]);
  assert(nThr >= 1  && nThr < 10);
  fprintf(stderr, "nThr = %d\n", nThr);

  pthread_t threads[NTESTS*nThr];
  int curthread = 0;
  int i, j;

   for (i = 0; i < NTESTS; i++) {
     for (j = 0; j < nThr; j++) {
        pthread_create(&threads[curthread++], NULL, tls_ptr, 
                       (void *)&tests[i]);
     }
   }

   assert(curthread == NTESTS*nThr);

   for (i = 0; i < curthread; i++)
     pthread_join(threads[i], NULL);

   return 0;
}
