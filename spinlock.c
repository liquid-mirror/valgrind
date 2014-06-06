#include <stdio.h>
#include <pthread.h>
#include <assert.h>

#define NEVENTS 100

#define PRINT 0

typedef  struct { volatile int w; }  Loc;

Loc loc_send;
Loc loc_ack;


void* t_consumer ( void* v )
{
  int i;
  for (i = 1; i < NEVENTS; i++) {
    while (loc_send.w != i) ;  // spin
    if (PRINT) fprintf(stderr, "consumer: got %d\n", i);
    loc_ack.w = i;
    __sync_synchronize();
  }
  return NULL;
}

void* t_producer ( void* v )
{
  int i;
  for (i = 1; i < NEVENTS; i++) {
    loc_send.w = i;
    __sync_synchronize();
    while (loc_ack.w != i) ; // spin;
    if (PRINT) fprintf(stderr, "producer: did %d\n", i);
  }
  return NULL;
}

int main ( void )
{
  int r;
  pthread_t thr_p, thr_c;
  loc_send.w = loc_ack.w = 0;

  r= pthread_create(&thr_p, NULL, t_producer, NULL); assert(!r);
  r= pthread_create(&thr_c, NULL, t_consumer, NULL); assert(!r);

  r= pthread_join(thr_p, NULL); assert(!r);
  r= pthread_join(thr_c, NULL); assert(!r);

  assert(loc_send.w == NEVENTS-1);
  assert(loc_ack.w == NEVENTS-1);

  return 0;
}
