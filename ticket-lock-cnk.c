
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/futex.h>
#include <errno.h>

// for syscall()
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>


typedef unsigned long int UWord;
typedef unsigned char Bool;
#define True  ((Bool)1)
#define False ((Bool)0)

#if 0
static Bool s_debug;
#else
static Bool s_debug = True;
#endif

#define TL_FUTEX_COUNT_LOG2 0
#define TL_FUTEX_COUNT (1U << TL_FUTEX_COUNT_LOG2)
#define TL_FUTEX_MASK (TL_FUTEX_COUNT - 1)

struct sched_lock {
  volatile unsigned head;
  volatile unsigned tail;
  volatile unsigned fx[TL_FUTEX_COUNT];
  int owner;
};

static struct sched_lock *create_sched_lock(void)
{
  struct sched_lock *p;

  p = malloc(sizeof(*p));
  if (p) {
    // The futex syscall requires that a futex takes four bytes.
    assert(sizeof(p->fx[0]) == 4);

    p->head = 0;
    p->tail = 0;
    memset((void*)p->fx, 0, sizeof(p->fx));
    p->owner = 0;
  }
  //INNER_REQUEST(ANNOTATE_RWLOCK_CREATE(p));
  //INNER_REQUEST(ANNOTATE_BENIGN_RACE_SIZED(&p->fx, sizeof(p->fx), ""));
  return p;
}

static void destroy_sched_lock(struct sched_lock *p)
{
  //INNER_REQUEST(ANNOTATE_RWLOCK_DESTROY(p));
  free(p);
}

static pid_t my_gettid(void)
{
  return syscall(SYS_gettid);
}
/*
 * Acquire ticket lock. Increment the tail of the queue and use the original
 * value as the ticket value. Wait until the head of the queue equals the
 * ticket value. The futex used to wait depends on the ticket value in order
 * to avoid that all threads get woken up every time a ticket lock is
 * released. That last effect is sometimes called the "thundering herd"
 * effect.
 *
 * See also Nick Piggin, x86: FIFO ticket spinlocks, Linux kernel mailing list
 * (http://lkml.org/lkml/2007/11/1/125) for more info.
 */

// Wait, using waitrsv, for *addr to have the value |val|
__attribute__((noinline))
static void wait_using_waitrsv(volatile unsigned int* addr, unsigned int val)
{
  __asm__ __volatile__(
    "Lxyzzy1:"           "\n\t"
    "   li    6, 0"      "\n\t"
    "   lwarx 5, %0, 6"  "\n\t"   // r5 = *addr, and set resvn
    "   cmpw  5, %1"     "\n\t"   // is it what we're after?
    "   beq   Lxyzzy2"   "\n\t"   // yes -- exit the loop
    "   waitrsv"         "\n\t"   // no -- snooze till resvn is cleared
    "   b Lxyzzy1"       "\n\t"   // try again
    "Lxyzzy2:"
    : : "b"(addr), "b"(val) : "cc","memory","r6","r5"
  );
}

static void acquire_sched_lock(struct sched_lock *p)
{
  unsigned ticket;

  ticket = __sync_fetch_and_add(&p->tail, 1);
  if (s_debug)
    fprintf(stderr, "[%d] acquire: ticket %d\n",
            my_gettid(), ticket);
  while (1) {
    __sync_synchronize();
    if (ticket == p->head)
      break;
    if (s_debug)
      fprintf(stderr, "[%d] acquire: ticket %d - waiting\n",
              my_gettid(), ticket);

    // Spin wait for p->head to catch up
    if (0) {
      while (ticket != p->head) {
        //__asm__ __volatile__("rep; nop");
        __sync_synchronize();
      }
    } else {
      assert(sizeof(ticket) == 4);
      assert(sizeof(p->head) == 4);
      assert(sizeof(unsigned) == 4);
      wait_using_waitrsv(&p->head, ticket);
    }

    break;
  }
  __sync_synchronize();
  //INNER_REQUEST(ANNOTATE_RWLOCK_ACQUIRED(p, /*is_w*/1));
  assert(p->owner == 0);
  p->owner = my_gettid();
}
/*
 * Release a ticket lock by incrementing the head of the queue. Only generate
 * a thread wakeup signal if at least one thread is waiting. If the queue tail
 * matches the wakeup_ticket value, no threads have to be woken up.
 *
 * Note: tail will only be read after head has been incremented since both are
 * declared as volatile and since the __sync...() functions imply a memory
 * barrier.
 */
static void release_sched_lock(struct sched_lock *p)
{
  unsigned wakeup_ticket;
  assert(p->owner != 0);
  p->owner = 0;
  //INNER_REQUEST(ANNOTATE_RWLOCK_RELEASED(p, /*is_w*/1));
  wakeup_ticket = __sync_fetch_and_add(&p->head, 1) + 1;
  (void)wakeup_ticket;
  __sync_synchronize();
}

/////////////////////////////////////////////////////////////////

#include <pthread.h>

#define NTHR     4
#define N_EVENTS 100

struct sched_lock* fair_lk   = NULL;
pthread_mutex_t*   unfair_lk = NULL;

unsigned char arr[N_EVENTS];
unsigned int  arr_used = 0;

void* child ( void* arg )
{
  Bool fair = True;
  int myid = (int)(long)arg;

  while (1) {
    if (fair) acquire_sched_lock(fair_lk);
    else pthread_mutex_lock(unfair_lk);

    if (arr_used >= N_EVENTS) {
      if (fair) release_sched_lock(fair_lk);
      else pthread_mutex_unlock(unfair_lk);
      break;
    }
    arr[arr_used++] = (unsigned char)myid;

    if (1) {
      volatile int q;
      for (q = 0; q < 10000; q++) 
        __asm__ __volatile__("":::"cc","memory");
    }

    if (fair) release_sched_lock(fair_lk);
    else pthread_mutex_unlock(unfair_lk);
  }
  return NULL;
}

int main ( void )
{
  int i, r;
  pthread_t thr[NTHR];

  fprintf(stderr, "main: starting children\n");

  fair_lk = create_sched_lock();

  unfair_lk = malloc(sizeof(pthread_mutex_t));
  pthread_mutex_init(unfair_lk, NULL);

  for (i = 0; i < NTHR; i++) {
    r= pthread_create(&thr[i], NULL, child, (void*)(long)i);  assert(!r);
  }

  for (i = 0; i < NTHR; i++) {
    r= pthread_join(thr[i], NULL);  assert(!r);
  }

  destroy_sched_lock(fair_lk);
  pthread_mutex_destroy(unfair_lk);
  free(unfair_lk);

  fprintf(stderr, "main: checking\n");

  assert(arr_used == N_EVENTS);

  unsigned int count[NTHR];
  memset(&count, 0, sizeof(count));
  for (i = 0; i < N_EVENTS; i++) {
    unsigned int x = arr[i];
    assert(x >= 0 && x < NTHR);
    count[x]++;
  }

  for (i = 0; i < NTHR; i++) {
    fprintf(stderr, "[%2d] %u\n", i, count[i]);
  }

  return 0;
}
