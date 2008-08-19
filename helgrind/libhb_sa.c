
/////////////////////////////////////////////////////////////////
//                                                             //
// BEGIN Standalone test driver for libhb_core.c.              //
//                                                             //
/////////////////////////////////////////////////////////////////

typedef  unsigned int   UInt;
typedef    signed int   Int;

typedef  unsigned long  UWord;
typedef  unsigned long  Addr;
typedef  unsigned long  SizeT;
typedef    signed long  SSizeT;

typedef    signed long  Word;

typedef  unsigned short  UShort;

typedef    signed char  Char;
typedef  unsigned char  UChar;
typedef           char  HChar;

typedef  unsigned long long int  ULong;

typedef  unsigned char  Bool;
#define False ((Bool)0)
#define True  ((Bool)1)

#include <assert.h>
#define vg_assert(__xx) assert(__xx)
#define tl_assert(__xx) assert(__xx)

#include <stdlib.h>  /* for NULL */

#include <string.h>  /* for memset et al */

static void* libhbPlainVG_memset ( void *s, Int c, SizeT sz ) {
   return memset(s,c,sz);
}

static void* libhbPlainVG_memcpy ( void *d, const void *s, SizeT sz ) {
   return memcpy(d,s,sz);
}

static void libhbPlainVG_ssort ( void* base, SizeT nmemb, SizeT size,
                                 Int (*compar)(void*, void*) ) {
   qsort(base,nmemb,size,
         (int(*)(const void*,const void*))compar);
}

static SizeT libhbPlainVG_strlen ( const char* s ) {
   return strlen(s);
}

static char* libhbPlainVG_strcat (char *dest, const char *src) {
   return strcat(dest,src);
}

#define libhbPlainVG_printf(_format, _args...) \
   printf(_format, _args)

#define libhbPlainVG_sprintf(_str, _format, _args...) \
   sprintf(_str, _format, _args)

#include <stdio.h>

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect((x), 0)


//////////////////////////////////////
#include "libhb_core.c"
//////////////////////////////////////


#include <malloc.h>

static void* zalloc_nofail ( SizeT n ) {
  return malloc(n); //calloc(n,1);
}

static void dealloc ( void* v ) {
   free(v);
}

static void* shadow_alloc_nofail ( SizeT n ) {
   return memalign(16,n);
}

static struct EC_* get_EC ( Thr* thr ) {
   return NULL;
}


//////////////////////////////

static void wr ( Thr* t, Addr a, SizeT sz )
{
   RaceInfo ri;
   Bool r = libhb_write( &ri, t, a, sz );
   if (r) {
      printf("race, W %ld, thr %p\n", sz, t);
   }
}

static void rd ( Thr* t, Addr a, SizeT sz )
{
   RaceInfo ri;
   Bool r = libhb_read( &ri, t, a, sz );
   if (r) {
      printf("race, R %ld, thr %p\n", sz, t);
   }
}

static void wrlock ( Thr* t, SO* so ) {
   libhb_so_recv(t, so, True/*strong*/);
}

static void rdlock ( Thr* t, SO* so ) {
   libhb_so_recv(t, so, False/*weak*/);
}

static void unlock ( Thr* t, SO* so ) {
   libhb_so_send(t, so);
}

int main ( void )
{
  //  Addr a;
  printf("\ndriver, blah\n");

  Thr* t1
     = libhb_init( zalloc_nofail, dealloc, shadow_alloc_nofail, get_EC );
  SO* lk = libhb_so_alloc();

  libhb_range_new( t1, 100, 8 );

  Thr* t2 = libhb_create( t1 );

  Int do_test_RW1 = 1;
  Int do_test_RW2 = 1;
  Int do_test_RW3 = 0;
  Int do_test0 = 1;
  Int do_test1 = 1;
  Int do_test2 = 1;
  Int do_test3 = 1;
  Int do_test4 = 1;
  Int do_test5 = 1;

  if (do_test_RW1) {
     /* At this point, t1 has created t2, and 100 is 'new' */     

     rdlock(t1, lk);
                       rdlock(t2, lk);
     rd(t1, 100, 4);
                       rd(t2, 100, 4);
     unlock(t1, lk);
                       unlock(t2, lk);

                       wrlock(t2, lk);
                       wr(t2, 100, 4);
                       unlock(t2, lk);
  }

  if (do_test_RW2) {
     /* At this point, t1 has created t2, and 100 is 'new' */     

     rdlock(t1, lk);
                       rdlock(t2, lk);
     rd(t1, 100, 4);
                       rd(t2, 100, 4);
     unlock(t1, lk);
                       unlock(t2, lk);

     wrlock(t1, lk);
     wr(t1, 100, 4);
     unlock(t1, lk);
  }

  if (do_test0) {
     Thr* t3;
     /* At this point, t1 has created t2, and 100 is 'new' */     

                  rd(t2, 100, 4);
                  wr(t2, 100, 4);
     t3 = libhb_create(t1);
             rd(t3, 100, 4);
             wr(t3, 100, 4);
  }

  // no race
  if (do_test1)
  {
     wr(t1, 100, 4);

     wrlock(t1, lk);
     wr(t1, 100, 4);
     unlock(t1, lk);
                      wrlock(t2, lk);
                      wr(t2, 100, 4);
                      unlock(t2, lk);
  }

  if (do_test2)
  {
     wr(t1, 100, 4);

     wrlock(t1, lk);
     wr(t1, 100, 4);
     unlock(t1, lk);
                   // wrlock(t2, lk);
                      wr(t2, 100, 4); // race
                   // unlock(t2, lk);
  }

  if (do_test3)
  {
     wr(t1, 100, 4);

     wrlock(t1, lk);
     wr(t1, 100, 4);
     unlock(t1, lk);
                   // wrlock(t2, lk);
                   rd(t2, 100, 4); // race
                   // unlock(t2, lk);
  }

  // no race
  if (do_test4)
  {
     rd(t1, 100, 4);
                      rd(t2, 100, 4);
     rd(t1, 100, 4);
                      rd(t2, 100, 4);
                      rd(t2, 100, 4);
  }

  // no race, checks for resource leaks
  if (do_test5)
  {
     Int i;
     wr(t1, 100, 4);
     for (i = 0; i < 1000; i++) {
     wrlock(t1, lk);
     wr(t1, 100, 4);
     unlock(t1, lk);
                      wrlock(t2, lk);
                      wr(t2, 100, 4);
                      unlock(t2, lk);
     }
  }

  libhb_maybe_GC();
  libhb_so_dealloc(lk);

  printf("\n");
  return 0;
}


/////////////////////////////////////////////////////////////////
//                                                             //
// END Standalone test driver for libhb_core.c.                //
//                                                             //
/////////////////////////////////////////////////////////////////

