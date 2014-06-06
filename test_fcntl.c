
#include <stdio.h>
#include <sys/resource.h>
#include <assert.h>
#include <fcntl.h>

int main ( void )
{
   struct rlimit rl;
   rl.rlim_cur = rl.rlim_max = 0x55555555;

   /* Get the current file descriptor limits. */
   int r = getrlimit(RLIMIT_NOFILE, &rl);
   assert(r == 0);

   printf("limits: cur %d  max %d\n", (int)rl.rlim_cur, (int)rl.rlim_max);

   int oldfd, newfd;

   // Try to move fd 2 to >= 500
   oldfd = 2;
   newfd = fcntl(oldfd, F_DUPFD, 500);
   printf("f_dupfd: %d --> %d\n", oldfd, newfd);

   // and again
   oldfd = 2;
   newfd = fcntl(oldfd, F_DUPFD, 500);
   printf("f_dupfd: %d --> %d\n", oldfd, newfd);

   return 0;
}
