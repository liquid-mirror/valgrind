
#include <stdio.h>
#include <sys/mman.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>


/* x86 linux specifics */
#define __NR_mremap          163
#define VKI_MREMAP_MAYMOVE        1
#define VKI_MREMAP_FIXED  2



#define PAGE 4096

void mapanon_fixed ( void* start, size_t length )
{
  void* r = mmap(start, length, PROT_NONE, 
                 MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, 0,0);
  assert(r != MAP_FAILED);
  assert(r == start);
}

void unmap_and_check ( void* start, size_t length )
{
   int r = munmap( start, length );
   assert(r == 0);
}

char* workingarea = NULL;
char* try_dst     = NULL;

// set up working area so expansion limit is 20*PAGE
//
//   |   10   |   20   |   10   |   60   |
//   |  pre   |  src   |  FREE  |  post  |
//
//  A suitable attempted fixed dst is workingarea + 150*PAGE.

char* setup ( void* other_stuff, int other_len )
{
  if (!workingarea) {
     workingarea = mmap(0, 200*PAGE, PROT_NONE, 
                           MAP_ANONYMOUS|MAP_PRIVATE, 0,0);
     assert(workingarea);
     try_dst = workingarea + 150*PAGE;
     unmap_and_check(workingarea, 200*PAGE);
  }

  if (other_stuff) {
    unmap_and_check(other_stuff, other_len);
  }

  // get rid of the old working area
  unmap_and_check( workingarea, 200*PAGE);

  // pre block
  mapanon_fixed( workingarea + 0*PAGE, 9*PAGE);

  // the area
  mapanon_fixed( workingarea + 10*PAGE, 20*PAGE );

  // upper half
  mapanon_fixed( workingarea + 40*PAGE, 60*PAGE );

  return workingarea + 10*PAGE;
}

/* show the working area */
void show ( void )
{
  int i,r;
  for (i = 0; i < 200; i++) {
    r = mprotect( workingarea + i * PAGE, PAGE, PROT_NONE );
    printf("%c", r == 0 ? 'X' : '.');
    if (i == 49 || i == 99 || i == 149) printf("\n");
  }
  printf("\n");
}


int is_kerror(int r) 
{
  return r >= -4096 && r <= -1;
}

typedef unsigned int UWord;
extern UWord do_syscall_WRK (
          UWord syscall_no,
          UWord a1, UWord a2, UWord a3,
          UWord a4, UWord a5, UWord a6
       );
asm(
"do_syscall_WRK:\n"
"       push    %esi\n"
"       push    %edi\n"
"       push    %ebx\n"
"       push    %ebp\n"
"       movl    16+ 4(%esp),%eax\n"
"       movl    16+ 8(%esp),%ebx\n"
"       movl    16+12(%esp),%ecx\n"
"       movl    16+16(%esp),%edx\n"
"       movl    16+20(%esp),%esi\n"
"       movl    16+24(%esp),%edi\n"
"       movl    16+28(%esp),%ebp\n"
"       int     $0x80\n"
"       popl    %ebp\n"
"       popl    %ebx\n"
"       popl    %edi\n"
"       popl    %esi\n"
"       ret\n"
);



char* dst = NULL;
char* src = NULL;
char* dst_impossible = NULL;


char* identify ( char* p )
{
  if (p == dst)            return "dst";
  if (p == src)            return "src";
  if (p == dst_impossible) return "dst_imp!";
  if (p == try_dst)        return "dst_poss";
  return "other";
}

int main ( void )
{
  int alocal, maymove, fixed, nsi, dstpossible;
  dst_impossible = (char*)(&alocal) + 500 * 1000 * 1000;
  int newsizes[6] = { 19, 20, 21, 29, 30, 31 };

  char* tidythis = NULL;
  int  tidylen = 0;
  int firsttime = 1;
  char buf[100];

  for (maymove = 0; maymove <= 1 ; maymove++) {
  for (fixed = 0; fixed <= 1; fixed++) {
    printf("\n");
  for (nsi = 0; nsi < 6; nsi++) {
  for (dstpossible = 0; dstpossible <= 1; dstpossible++) {

    int newsize = newsizes[nsi] * PAGE;
    int flags = (maymove ? VKI_MREMAP_MAYMOVE : 0)  |
                (fixed ? VKI_MREMAP_FIXED : 0);
    dst = dstpossible ? try_dst : dst_impossible;
    src = setup( tidythis, tidylen );

    char* r;

    if (firsttime) {
       printf("dst_possible   = %p\n", try_dst );
       printf("dst_impossible = %p\n", dst_impossible );
       printf("           src = %p\n", src);
       printf("\n");
       sprintf(buf, "cat /proc/%d/maps", getpid());
       if (0) system(buf);
       firsttime = 0;
    }

    printf("maymv %d   fixed %d   newsz %2d   dstpo %d  dst 0x%08x ->  ",
	   maymove, fixed, newsizes[nsi], dstpossible, (UWord)dst );
    r = (char*)
        do_syscall_WRK(__NR_mremap, (UWord)src, 
                       20*PAGE, newsize, flags, (UWord)dst, 0 );
    if (is_kerror((int)r))
      printf("error %d\n", -(int)r);
    else
      printf("0x%08x (== %s)\n", (int)r, identify(r));

    if (1) {
       show();
       printf("\n");
    }

    if (!is_kerror((int)r)) {
      if (r != src && r != try_dst && r != dst_impossible) {
	tidythis = r;
	tidylen = newsize;
      }
    }

  }
  }
  }
  }
  return 0;
}
