
#include "vg_include.h"
#include "vg_unsafe.h"
#include "vg_memcheck_include.h"

static
void must_be_writable ( ThreadState* tst, 
                        Char* syscall_name, UInt base, UInt size )
{
   Bool ok;
   Addr bad_addr;
   /* VG_(message)(Vg_DebugMsg,"must be writable: %x .. %x",
                               base,base+size-1); */
   if (Vg_MemCheck != VG_(clo_skin)) 
      return;
   ok = SKN_(check_writable) ( base, size, &bad_addr );
   if (!ok)
      SK_(record_param_err) ( tst, bad_addr, True, syscall_name );
}

static
void must_be_readable ( ThreadState* tst, 
                        Char* syscall_name, UInt base, UInt size )
{
   Bool ok;
   Addr bad_addr;
   /* VG_(message)(Vg_DebugMsg,"must be readable: %x .. %x",
                               base,base+size-1); */
   if (Vg_MemCheck != VG_(clo_skin)) 
      return;
   ok = SKN_(check_readable) ( base, size, &bad_addr );
   if (!ok)
      SK_(record_param_err) ( tst, bad_addr, False, syscall_name );
}

static
void must_be_readable_asciiz ( ThreadState* tst, 
                               Char* syscall_name, UInt str )
{
   Bool ok = True;
   Addr bad_addr;
   /* VG_(message)(Vg_DebugMsg,"must be readable asciiz: 0x%x",str); */
   if (Vg_MemCheck != VG_(clo_skin)) 
      return;
   ok = SKN_(check_readable_asciiz) ( (Addr)str, &bad_addr );
   if (!ok)
      SK_(record_param_err) ( tst, bad_addr, False, syscall_name );
}

/* Dereference a pointer, but only after checking that it's
   safe to do so.  If not, return the default.
*/
static
UInt safe_dereference ( Addr aa, UInt defawlt )
{
   if (Vg_MemCheck != VG_(clo_skin)) 
      return * (UInt*)aa;
   if (SKN_(check_readable)(aa,4,NULL))
      return * (UInt*)aa;
   else
      return defawlt;
}


static
Char *strdupcat ( const Char *s1, const Char *s2, ArenaId aid )
{
   UInt len = VG_(strlen) ( s1 ) + VG_(strlen) ( s2 ) + 1;
   Char *result = VG_(malloc) ( aid, len );
   VG_(strcpy) ( result, s1 );
   VG_(strcat) ( result, s2 );
   return result;
}

static 
void must_be_readable_sendmsg ( ThreadState* tst, 
                                Char *msg, UInt base, UInt size )
{
   Char *outmsg = strdupcat ( "socketcall.sendmsg", msg, VG_AR_TRANSIENT );
   must_be_readable ( tst, outmsg, base, size );
   VG_(free) ( VG_AR_TRANSIENT, outmsg );
}

static 
void must_be_writable_recvmsg ( ThreadState* tst, 
                                Char *msg, UInt base, UInt size )
{
   Char *outmsg = strdupcat ( "socketcall.recvmsg", msg, VG_AR_TRANSIENT );
   must_be_writable ( tst, outmsg, base, size );
   VG_(free) ( VG_AR_TRANSIENT, outmsg );
}


// SSS: duplicated this from pre.c, bleurgh
static void VG_(msghdr_foreachfield) ( 
        ThreadState* tst, 
        struct msghdr *msg, 
        void (*foreach_func)( ThreadState*, Char *, UInt, UInt ) 
     )
{
   if ( !msg )
      return;

   foreach_func ( tst, "(msg)", (Addr)msg, sizeof( struct msghdr ) );

   if ( msg->msg_name )
      foreach_func ( tst, 
                     "(msg.msg_name)", 
                     (Addr)msg->msg_name, msg->msg_namelen );

   if ( msg->msg_iov ) {
      struct iovec *iov = msg->msg_iov;
      UInt i;

      foreach_func ( tst, 
                     "(msg.msg_iov)", 
                     (Addr)iov, msg->msg_iovlen * sizeof( struct iovec ) );

      for ( i = 0; i < msg->msg_iovlen; ++i, ++iov )
         foreach_func ( tst, 
                        "(msg.msg_iov[i]", 
                        (Addr)iov->iov_base, iov->iov_len );
   }

   if ( msg->msg_control )
      foreach_func ( tst, 
                     "(msg.msg_control)", 
                     (Addr)msg->msg_control, msg->msg_controllen );
}

static
void must_be_readable_sockaddr ( ThreadState* tst,
                                 Char *description,
                                 struct sockaddr *sa, UInt salen )
{
   Char *outmsg = VG_(malloc) ( VG_AR_TRANSIENT, strlen( description ) + 30 );

   VG_(sprintf) ( outmsg, description, ".sa_family" );
   must_be_readable( tst, outmsg, (UInt) &sa->sa_family, sizeof (sa_family_t));
               
   switch (sa->sa_family) {
                  
      case AF_UNIX:
         VG_(sprintf) ( outmsg, description, ".sun_path" );
         must_be_readable_asciiz( tst, outmsg,
            (UInt) ((struct sockaddr_un *) sa)->sun_path);
         break;
                     
      case AF_INET:
         VG_(sprintf) ( outmsg, description, ".sin_port" );
         must_be_readable( tst, outmsg,
            (UInt) &((struct sockaddr_in *) sa)->sin_port,
            sizeof (((struct sockaddr_in *) sa)->sin_port));
         VG_(sprintf) ( outmsg, description, ".sin_addr" );
         must_be_readable( tst, outmsg,
            (UInt) &((struct sockaddr_in *) sa)->sin_addr,
            sizeof (struct in_addr));
         break;
                           
      case AF_INET6:
         VG_(sprintf) ( outmsg, description, ".sin6_port" );
         must_be_readable( tst, outmsg,
            (UInt) &((struct sockaddr_in6 *) sa)->sin6_port,
            sizeof (((struct sockaddr_in6 *) sa)->sin6_port));
         VG_(sprintf) ( outmsg, description, ".sin6_flowinfo" );
         must_be_readable( tst, outmsg,
            (UInt) &((struct sockaddr_in6 *) sa)->sin6_flowinfo,
            sizeof (uint32_t));
         VG_(sprintf) ( outmsg, description, ".sin6_addr" );
         must_be_readable( tst, outmsg,
            (UInt) &((struct sockaddr_in6 *) sa)->sin6_addr,
            sizeof (struct in6_addr));
#        ifndef GLIBC_2_1
         VG_(sprintf) ( outmsg, description, ".sin6_scope_id" );
         must_be_readable( tst, outmsg,
            (UInt) &((struct sockaddr_in6 *) sa)->sin6_scope_id,
            sizeof (uint32_t));
#        endif
         break;
               
      default:
         VG_(sprintf) ( outmsg, description, "" );
         must_be_readable( tst, outmsg, (UInt) sa, salen );
         break;
   }
   
   VG_(free) ( VG_AR_TRANSIENT, outmsg );
}

/* The Main Entertainment ... */

void* SKN_(pre_syscall) ( ThreadId tid )
{
   ThreadState* tst;
   Int          sane_before_call;
   UInt         syscallno, arg1, arg2, arg3, arg4, arg5;

   VGP_PUSHCC(VgpSyscall);

   vg_assert(VG_(is_valid_tid)(tid));
   tst              = & VG_(threads)[tid];
   syscallno        = tst->m_eax;
   arg1             = tst->m_ebx;
   arg2             = tst->m_ecx;
   arg3             = tst->m_edx;
   arg4             = tst->m_esi;
   arg5             = tst->m_edi;

   /* Since buggy syscall wrappers sometimes break this, we may as well 
      check ourselves. */
   sane_before_call = SKN_(cheap_sanity_check)();

   /* See vg_syscalls_mem.c:VG_(perform_assumed_nonblocking_syscall)()
    * for details on arguments and return values.
   */

   switch (syscallno) {

      case __NR_exit:
         VG_(panic)("syscall exit() not caught by the scheduler?!");
         break;

      case __NR_clone:
         VG_(unimplemented)
            ("clone(): not supported by Valgrind.\n   "
             "We do now support programs linked against\n   "
             "libpthread.so, though.  Re-run with -v and ensure that\n   "
             "you are picking up Valgrind's implementation of libpthread.so.");
         break;

#     if defined(__NR_modify_ldt)
      case __NR_modify_ldt:
         VG_(nvidia_moan)();
         VG_(unimplemented)
            ("modify_ldt(): I (JRS) haven't investigated this yet; sorry.");
         break;
#     endif


      /* These are all the ones that don't need any checking */
#     if defined(__NR_fdatasync)
      case __NR_fdatasync: /* syscall 148 */
         /* int fdatasync(int fd); */
#     endif
      case __NR_personality: /* syscall 136 */
         /* int personality(unsigned long persona); */
      case __NR_nice: /* syscall 34 */
         /* int nice(int inc); */
      /* !!!!!!!!!! New, untested syscalls, 14 Mar 02 !!!!!!!!!! */
#     if defined(__NR_setresgid32)
      case __NR_setresgid32: /* syscall 210 */
         /* int setresgid(gid_t rgid, gid_t egid, gid_t sgid); */
#     endif
#     if defined(__NR_setfsuid32)
      case __NR_setfsuid32: /* syscall 215 */
         /* int setfsuid(uid_t fsuid); */
#     endif
#     if defined(__NR_sched_getscheduler)
      case __NR_sched_getscheduler:
         /* int sched_getscheduler(pid_t pid); */
         break;
#     endif
#     if defined(__NR_mlock)
      case __NR_mlock:
         /* int mlock(const void * addr, size_t len) */
#     endif
#     if defined(__NR_mlockall)
      case __NR_mlockall:
         /* int mlockall(int flags); */
#     endif
#     if defined(__NR_munlockall)
      case __NR_munlockall:
         /* int munlockall(void); */
#     endif
#if   defined(__NR_sched_get_priority_max)
      case __NR_sched_get_priority_max:
         /* int sched_get_priority_max(int policy); */
#     endif
#if   defined(__NR_sched_get_priority_min)
      case __NR_sched_get_priority_min: /* syscall 160 */
         /* int sched_get_priority_min(int policy); */
#     endif
#if   defined(__NR_setpriority)
      case __NR_setpriority: /* syscall 97 */
         /* int setpriority(int which, int who, int prio); */
#     endif
#if   defined(__NR_getpriority)
      case __NR_getpriority: /* syscall 96 */
         /* int getpriority(int which, int who); */
#     endif
#     if defined(__NR_setfsgid)
      case __NR_setfsgid: /* syscall 139 */
         /* int setfsgid(gid_t gid); */
#     endif
#     if defined(__NR_setregid)
      case __NR_setregid: /* syscall 71 */
         /* int setregid(gid_t rgid, gid_t egid); */
#     endif
#     if defined(__NR_setresuid)
      case __NR_setresuid: /* syscall 164 */
         /* int setresuid(uid_t ruid, uid_t euid, uid_t suid); */
#     endif
#     if defined(__NR_setfsuid)
      case __NR_setfsuid: /* syscall 138 */
         /* int setfsuid(uid_t uid); */
#     endif
      /* !!!!!!!!!! New, untested syscalls, 6 Mar 02 !!!!!!!!!!! */
      case __NR_sync: /* syscall 36 */
         /* int sync(); */
      /* !!!!!!!!!! New, untested syscalls, 4 Mar 02 !!!!!!!!!!! */
      case __NR_pause: /* syscall 29 */
         /* int pause(void); */
      case __NR_getsid: /* syscall 147 */
         /* pid_t getsid(pid_t pid); */
      case __NR_flock: /* syscall 143 */
         /* int flock(int fd, int operation); */
      case __NR_ioperm: /* syscall 101 */
         /* int ioperm(unsigned long from, unsigned long num, int turn_on); */
      case __NR_alarm: /* syscall 27 */
         /* unsigned int alarm(unsigned int seconds); */
         break;
      case __NR_brk: /* syscall 45 */
         /* int brk(void *end_data_segment); */
      case __NR_close: /* syscall 6 */
         /* int close(int fd); */
      case __NR_dup: /* syscall 41 */
         /* int dup(int oldfd); */
      case __NR_dup2: /* syscall 63 */
         /* int dup2(int oldfd, int newfd); */
      case __NR_fcntl: /* syscall 55 */
         /* int fcntl(int fd, int cmd, int arg); */
      case __NR_fchdir: /* syscall 133 */
         /* int fchdir(int fd); */
#     if defined(__NR_fchown32)
      case __NR_fchown32: /* syscall 207 */
#     endif
      case __NR_fchown: /* syscall 95 */
         /* int fchown(int filedes, uid_t owner, gid_t group); */
      case __NR_fchmod: /* syscall 94 */
         /* int fchmod(int fildes, mode_t mode); */
#     if defined(__NR_fcntl64)
      case __NR_fcntl64: /* syscall 221 */
         /* I don't know what the prototype for this is supposed to be. */
         /* ??? int fcntl(int fd, int cmd); */
#     endif
      case __NR_vfork: /* syscall 190 */
         /* pid_t vfork(void); */
         /* KLUDGE: we prefer to do a fork rather than vfork. 
            vfork gives a SIGSEGV, and the stated semantics looks
            pretty much impossible for us. */
         /* fall through ... */
      case __NR_fork: /* syscall 2 */
         /* pid_t fork(void); */
      case __NR_fsync: /* syscall 118 */
         /* int fsync(int fd); */
      case __NR_ftruncate: /* syscall 93 */
         /* int ftruncate(int fd, size_t length); */
#     if defined(__NR_ftruncate64)
      case __NR_ftruncate64: /* syscall 194 */
         /* int ftruncate64(int fd, off64_t length); */
#     endif
      case __NR_geteuid: /* syscall 49 */
         /* uid_t geteuid(void); */
#     if defined(__NR_geteuid32)
      case __NR_geteuid32: /* syscall 201 */
         /* ?? uid_t geteuid32(void); */
#     endif
      case __NR_getegid: /* syscall 50 */
         /* gid_t getegid(void); */
#     if defined(__NR_getegid32)
      case __NR_getegid32: /* syscall 202 */
         /* gid_t getegid32(void); */
#     endif
      case __NR_getgid: /* syscall 47 */
         /* gid_t getgid(void); */
#     if defined(__NR_getgid32)
      case __NR_getgid32: /* syscall 200 */
         /* gid_t getgid32(void); */
#     endif
      case __NR_getpid: /* syscall 20 */
         /* pid_t getpid(void); */
      case __NR_getpgid: /* syscall 132 */
         /* pid_t getpgid(pid_t pid); */
      case __NR_getpgrp: /* syscall 65 */
         /* pid_t getpprp(void); */
      case __NR_getppid: /* syscall 64 */
         /* pid_t getppid(void); */
      case __NR_getuid: /* syscall 24 */
         /* uid_t getuid(void); */
#     if defined(__NR_getuid32)
      case __NR_getuid32: /* syscall 199 */
         /* ???uid_t getuid32(void); */
#     endif
      case __NR_kill: /* syscall 37 */
         /* int kill(pid_t pid, int sig); */
      case __NR_lseek: /* syscall 19 */
         /* off_t lseek(int fildes, off_t offset, int whence); */
#     if defined(__NR_mmap2)
      case __NR_mmap2: /* syscall 192 */
         /* My impression is that this is exactly like __NR_mmap 
            except that all 6 args are passed in regs, rather than in 
            a memory-block. */
         /* void* mmap(void *start, size_t length, int prot, 
                       int flags, int fd, off_t offset); */
#     endif
      case __NR_mprotect: /* syscall 125 */
         /* int mprotect(const void *addr, size_t len, int prot); */
         /* should addr .. addr+len-1 be checked before the call? */
      case __NR_munmap: /* syscall 91 */
         /* int munmap(void *start, size_t length); */
         /* should start .. start+length-1 be checked before the call? */
      case __NR_sched_yield: /* syscall 158 */
         /* int sched_yield(void); */
         break;
#     if defined(__NR_setfsgid32)
      case __NR_setfsgid32: /* syscall 216 */
         /* int setfsgid(uid_t fsgid); */
#     endif
#     if defined(__NR_setgid32)
      case __NR_setgid32: /* syscall 214 */
#     endif
      case __NR_setgid: /* syscall 46 */
         /* int setgid(gid_t gid); */
      case __NR_setsid: /* syscall 66 */
         /* pid_t setsid(void); */
      case __NR_setpgid: /* syscall 57 */
         /* int setpgid(pid_t pid, pid_t pgid); */
#     if defined(__NR_setregid32)
      case __NR_setregid32: /* syscall 204 */
         /* int setregid(gid_t rgid, gid_t egid); */
#     endif
#     if defined(__NR_setresuid32)
      case __NR_setresuid32: /* syscall 208 */
         /* int setresuid(uid_t ruid, uid_t euid, uid_t suid); */
#     endif
#     if defined(__NR_setreuid32)
      case __NR_setreuid32: /* syscall 203 */
#     endif
      case __NR_setreuid: /* syscall 70 */
         /* int setreuid(uid_t ruid, uid_t euid); */
#     if defined(__NR_setuid32)
      case __NR_setuid32: /* syscall 213 */
#     endif
      case __NR_setuid: /* syscall 23 */
         /* int setuid(uid_t uid); */
      case __NR_umask: /* syscall 60 */
         /* mode_t umask(mode_t mask); */

         /* All fall through to here */
         break;




      /* !!!!!!!!!! New, untested syscalls !!!!!!!!!!!!!!!!!!!!! */

#     if defined(__NR_getxattr)
      case __NR_getxattr: /* syscall 229 */
         /* ssize_t getxattr (const char *path, const char* name,
                              void* value, size_t size); */
         must_be_readable_asciiz( tst, "getxattr(path)", arg1 );
         must_be_readable_asciiz( tst, "getxattr(name)", arg2 );
         must_be_writable( tst, "getxattr(value)", arg3, arg4 );
         break;
#     endif
      
#     if defined(__NR_quotactl)
      case __NR_quotactl: /* syscall 131 */
         /* int quotactl(int cmd, char *special, int uid, caddr_t addr); */
         must_be_readable_asciiz( tst, "quotactl(special)", arg2 );
         break;
#     endif

#     if defined(__NR_truncate64)
      case __NR_truncate64: /* syscall 193 */
         /* int truncate64(const char *path, off64_t length); */
         must_be_readable_asciiz( tst, "truncate64(path)", arg1 );
         break;
#     endif

#     if defined(__NR_msync) /* syscall 144 */
      case __NR_msync:
         /* int msync(const void *start, size_t length, int flags); */
         must_be_readable( tst, "msync(start)", arg1, arg2 );
         break;
#     endif

#     if defined(__NR_getpmsg) /* syscall 188 */
      case __NR_getpmsg: 
      {
      /* LiS getpmsg from http://www.gcom.com/home/linux/lis/ */
      /* int getpmsg(int fd, struct strbuf *ctrl, struct strbuf *data, 
                             int *bandp, int *flagsp); */
      struct strbuf {
         int     maxlen;         /* no. of bytes in buffer */
         int     len;            /* no. of bytes returned */
         caddr_t buf;            /* pointer to data */
      };
      struct strbuf *ctrl;
      struct strbuf *data;
      ctrl = (struct strbuf *)arg2;
      data = (struct strbuf *)arg3;
      if (ctrl && ctrl->maxlen > 0)
          must_be_writable(tst, "getpmsg(ctrl)", 
                                (UInt)ctrl->buf, ctrl->maxlen);
      if (data && data->maxlen > 0)
          must_be_writable(tst, "getpmsg(data)", 
                                 (UInt)data->buf, data->maxlen);
      if (arg4)
          must_be_writable(tst, "getpmsg(bandp)", 
                                (UInt)arg4, sizeof(int));
      if (arg5)
          must_be_writable(tst, "getpmsg(flagsp)", 
                                (UInt)arg5, sizeof(int));
      }
      break;
#     endif


#     if defined(__NR_putpmsg) /* syscall 189 */
      case __NR_putpmsg: 
      {
      /* LiS putpmsg from http://www.gcom.com/home/linux/lis/ */
      /* int putpmsg(int fd, struct strbuf *ctrl, struct strbuf *data, 
                             int band, int flags); */
      struct strbuf {
         int     maxlen;         /* no. of bytes in buffer */
         int     len;            /* no. of bytes returned */
         caddr_t buf;            /* pointer to data */
      };
      struct strbuf *ctrl;
      struct strbuf *data;
      ctrl = (struct strbuf *)arg2;
      data = (struct strbuf *)arg3;
      if (ctrl && ctrl->len > 0)
          must_be_readable(tst, "putpmsg(ctrl)",
                                (UInt)ctrl->buf, ctrl->len);
      if (data && data->len > 0)
          must_be_readable(tst, "putpmsg(data)",
                                (UInt)data->buf, data->len);
      }
      break;
#     endif

      case __NR_getitimer: /* syscall 105 */
         /* int getitimer(int which, struct itimerval *value); */
         must_be_writable( tst, "getitimer(timer)", arg2, 
                           sizeof(struct itimerval) );
         break;

#     if defined(__NR_syslog)
      case __NR_syslog: /* syscall 103 */
         /* int syslog(int type, char *bufp, int len); */
         switch(arg1) {
            case 2: case 3: case 4:
               must_be_writable( tst, "syslog(buf)", arg2, arg3);
	       break;
            default: 
               break;
         }
         break;
#     endif

      case __NR_chroot: /* syscall 61 */
         /* int chroot(const char *path); */
         must_be_readable_asciiz( tst, "chroot(path)", arg1 );
         break;

#     if defined(__NR_madvise)
      case __NR_madvise: /* syscall 219 */
         /* int madvise(void *start, size_t length, int advice ); */
         break;
#     endif

#     if defined(__NR_mremap)
      /* Is this really right?  Perhaps it should copy the permissions
         from the old area into the new.  Unclear from the Linux man
         pages what this really does.  Also, the flags don't look like
         they mean the same as the standard mmap flags, so that's
         probably wrong too. */
      case __NR_mremap: /* syscall 163 */
         /* void* mremap(void * old_address, size_t old_size, 
                         size_t new_size, unsigned long flags); */
         must_be_writable ( tst, "mremap(old_address)", arg1, arg2 );
         break;         
#     endif

#     if defined(__NR__sysctl)
      case __NR__sysctl:
      /* int _sysctl(struct __sysctl_args *args); */
         must_be_writable ( tst, "_sysctl(args)", arg1, 
                            sizeof(struct __sysctl_args) );
         break;
#     endif

#     if defined(__NR_sched_setscheduler)
      case __NR_sched_setscheduler:
         /* int sched_setscheduler(pid_t pid, int policy, 
                const struct sched_param *p); */
         if (arg3 != (UInt)NULL)
            must_be_readable( tst,
                              "sched_setscheduler(struct sched_param *p)", 
                              arg3, sizeof(struct sched_param));
         break;
#     endif

      /* !!!!!!!!!! New, untested syscalls, 8 Mar 02 !!!!!!!!!!! */

#     if defined(__NR_sendfile)
      case __NR_sendfile: /* syscall 187 */
         /* ssize_t sendfile(int out_fd, int in_fd, off_t *offset, 
                             size_t count) */
         if (arg3 != (UInt)NULL)
            must_be_writable( tst, "sendfile(offset)", arg3, sizeof(off_t) );
         break;
#     endif

      /* !!!!!!!!!! New, untested syscalls, 7 Mar 02 !!!!!!!!!!! */

#     if defined(__NR_pwrite)
      case __NR_pwrite: /* syscall 181 */
         /* ssize_t pwrite (int fd, const void *buf, size_t nbytes,
                            off_t offset); */
         must_be_readable( tst, "pwrite(buf)", arg2, arg3 );
         break;
#     endif

      case __NR_fstatfs: /* syscall 100 */
         /* int fstatfs(int fd, struct statfs *buf); */
         must_be_writable( tst, "stat(buf)", arg2, sizeof(struct statfs) );
         break;

#     if defined(__NR_pread)
      case __NR_pread: /* syscall 180 */
         /* ssize_t pread(int fd, void *buf, size_t count, off_t offset); */
         must_be_writable( tst, "pread(buf)", arg2, arg3 );
         break;
#     endif

      /* !!!!!!!!!! New, untested syscalls, 27 Feb 02 !!!!!!!!!! */

      case __NR_mknod: /* syscall 14 */
         /* int mknod(const char *pathname, mode_t mode, dev_t dev); */
         must_be_readable_asciiz( tst, "mknod(pathname)", arg1 );
         break;

#     if defined(__NR_rt_sigsuspend)
      /* Viewed with great suspicion by me, but, hey, let's do it
         anyway ... */
      case __NR_rt_sigsuspend: /* syscall 179 */
         /* int sigsuspend(const sigset_t *mask); */
         if (arg1 != (Addr)NULL) {
            /* above NULL test is paranoia */
            must_be_readable( tst, "sigsuspend(mask)", arg1, 
                              sizeof(vki_ksigset_t) );
         }
         break;
#     endif

      case __NR_init_module: /* syscall 128 */
         /* int init_module(const char *name, struct module *image); */
         must_be_readable_asciiz( tst, "init_module(name)", arg1 );
         must_be_readable( tst, "init_module(image)", arg2, 
                           VKI_SIZEOF_STRUCT_MODULE );
         break;

      case __NR_capget: /* syscall 184 */
         /* int capget(cap_user_header_t header, cap_user_data_t data); */
         must_be_readable( tst, "capget(header)", arg1, 
                                             sizeof(vki_cap_user_header_t) );
         must_be_writable( tst, "capget(data)", arg2, 
                                           sizeof( vki_cap_user_data_t) );
         break;

      /* !!!!!!!!!!!!!!!!!!!!! mutant ones !!!!!!!!!!!!!!!!!!!!! */

      case __NR_execve:
         /* int execve (const char *filename, 
                        char *const argv [], 
                        char *const envp[]); */
         break;

      /* !!!!!!!!!!!!!!!!!!!!!     end     !!!!!!!!!!!!!!!!!!!!! */

      case __NR_access: /* syscall 33 */
         /* int access(const char *pathname, int mode); */
         must_be_readable_asciiz( tst, "access(pathname)", arg1 );
         break;

      case __NR_chdir: /* syscall 12 */
         /* int chdir(const char *path); */
         must_be_readable_asciiz( tst, "chdir(path)", arg1 );
         break;

      case __NR_chmod: /* syscall 15 */
         /* int chmod(const char *path, mode_t mode); */
         must_be_readable_asciiz( tst, "chmod(path)", arg1 );
         break;

#     if defined(__NR_chown32)
      case __NR_chown32: /* syscall 212 */
#     endif
#     if defined(__NR_lchown32)
      case __NR_lchown32: /* syscall 198 */
#     endif
      case __NR_chown: /* syscall 16 */
         /* int chown(const char *path, uid_t owner, gid_t group); */
         must_be_readable_asciiz( tst, "chown(path)", arg1 );
         break;

      case __NR_fstat: /* syscall 108 */
         /* int fstat(int filedes, struct stat *buf); */
         must_be_writable( tst, "fstat", arg2, sizeof(struct stat) );
         break;

      case __NR_getdents: /* syscall 141 */
         /* int getdents(unsigned int fd, struct dirent *dirp, 
                         unsigned int count); */
         must_be_writable( tst, "getdents(dirp)", arg2, arg3 );
         break;

#     if defined(__NR_getdents64)
      case __NR_getdents64: /* syscall 220 */
         /* int getdents(unsigned int fd, struct dirent64 *dirp, 
                         unsigned int count); */
         must_be_writable( tst, "getdents64(dirp)", arg2, arg3 );
         break;
#     endif

#     if defined(__NR_getgroups32)
      case __NR_getgroups32: /* syscall 205 */
#     endif
      case __NR_getgroups: /* syscall 80 */
         /* int getgroups(int size, gid_t list[]); */
         if (arg1 > 0)
            must_be_writable ( tst, "getgroups(list)", arg2, 
                               arg1 * sizeof(gid_t) );
         break;

      case __NR_getcwd: /* syscall 183 */
         /* char *getcwd(char *buf, size_t size); */
         must_be_writable( tst, "getcwd(buf)", arg1, arg2 );
         break;

      case __NR_getresgid: /* syscall 171 */
         /* int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid); */
         must_be_writable ( tst, "getresgid(rgid)", arg1, sizeof(gid_t) );
         must_be_writable ( tst, "getresgid(egid)", arg2, sizeof(gid_t) );
         must_be_writable ( tst, "getresgid(sgid)", arg3, sizeof(gid_t) );
         break;

#     if defined(__NR_getresgid32)
      case __NR_getresgid32: /* syscall 211 */
         /* int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid); */
         must_be_writable ( tst, "getresgid32(rgid)", arg1, sizeof(gid_t) );
         must_be_writable ( tst, "getresgid32(egid)", arg2, sizeof(gid_t) );
         must_be_writable ( tst, "getresgid32(sgid)", arg3, sizeof(gid_t) );
         break;
#     endif

      case __NR_getresuid: /* syscall 165 */
         /* int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid); */
         must_be_writable ( tst, "getresuid(ruid)", arg1, sizeof(uid_t) );
         must_be_writable ( tst, "getresuid(euid)", arg2, sizeof(uid_t) );
         must_be_writable ( tst, "getresuid(suid)", arg3, sizeof(uid_t) );
         break;

#     if defined(__NR_getresuid32)
      case __NR_getresuid32: /* syscall 209 */
         /* int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid); */
         must_be_writable ( tst, "getresuid32(ruid)", arg1, sizeof(uid_t) );
         must_be_writable ( tst, "getresuid32(euid)", arg2, sizeof(uid_t) );
         must_be_writable ( tst, "getresuid32(suid)", arg3, sizeof(uid_t) );
         break;
#     endif

#     if defined(__NR_ugetrlimit)
      case __NR_ugetrlimit: /* syscall 191 */
#     endif
      case __NR_getrlimit: /* syscall 76 */
         /* int getrlimit (int resource, struct rlimit *rlim); */
         must_be_writable( tst, "getrlimit(rlim)", arg2, 
                           sizeof(struct rlimit) );
         break;

      case __NR_getrusage: /* syscall 77 */
         /* int getrusage (int who, struct rusage *usage); */
         must_be_writable( tst, "getrusage(usage)", arg2, 
                           sizeof(struct rusage) );
         break;

      case __NR_gettimeofday: /* syscall 78 */
         /* int gettimeofday(struct timeval *tv, struct timezone *tz); */
         must_be_writable( tst, "gettimeofday(tv)", arg1, 
                           sizeof(struct timeval) );
         if (arg2 != 0)
            must_be_writable( tst, "gettimeofday(tz)", arg2, 
                              sizeof(struct timezone) );
         break;

      case __NR_ipc: /* syscall 117 */
         /* int ipc ( unsigned int call, int first, int second, 
                      int third, void *ptr, long fifth); */
         switch (arg1 /* call */) {
            case 1: /* IPCOP_semop */
               must_be_readable ( tst, "semop(sops)", arg5, 
                                  arg3 * sizeof(struct sembuf) );
               break;
            case 2: /* IPCOP_semget */
            case 3: /* IPCOP_semctl */
               break;
            case 11: /* IPCOP_msgsnd */
               {
                  struct msgbuf *msgp = (struct msgbuf *)arg5;
                  Int msgsz = arg3;

                  must_be_readable ( tst, "msgsnd(msgp->mtype)", 
                                     (UInt)&msgp->mtype, sizeof(msgp->mtype) );
                  must_be_readable ( tst, "msgsnd(msgp->mtext)", 
                                     (UInt)msgp->mtext, msgsz );
                  break;
               }
            case 12: /* IPCOP_msgrcv */
               {
                  struct msgbuf *msgp;
                  Int msgsz = arg3;
 
                  msgp = (struct msgbuf *)safe_dereference( 
                            (Addr) (&((struct ipc_kludge *)arg5)->msgp), 0 );

                  must_be_writable ( tst, "msgrcv(msgp->mtype)", 
                                     (UInt)&msgp->mtype, sizeof(msgp->mtype) );
                  must_be_writable ( tst, "msgrcv(msgp->mtext)", 
                                     (UInt)msgp->mtext, msgsz );
                  break;
               }
            case 13: /* IPCOP_msgget */
               break;
            case 14: /* IPCOP_msgctl */
               {
                  switch (arg3 /* cmd */) {
                     case IPC_STAT:
                        must_be_writable ( tst, "msgctl(buf)", arg5, 
                                           sizeof(struct msqid_ds) );
                        break;
                     case IPC_SET:
                        must_be_readable ( tst, "msgctl(buf)", arg5, 
                                           sizeof(struct msqid_ds) );
                        break;
#                    if defined(IPC_64)
                     case IPC_STAT|IPC_64:
                        must_be_writable ( tst, "msgctl(buf)", arg5, 
                                           sizeof(struct msqid64_ds) );
                        break;
#                    endif
#                    if defined(IPC_64)
                     case IPC_SET|IPC_64:
                        must_be_readable ( tst, "msgctl(buf)", arg5, 
                                           sizeof(struct msqid64_ds) );
                        break;
#                    endif
                     default:
                        break;
                  }
                  break;
               }
            case 21: /* IPCOP_shmat */
               break;
            case 22: /* IPCOP_shmdt */
               break;
            case 23: /* IPCOP_shmget */
                break;
            case 24: /* IPCOP_shmctl */
	      /* Subject: shmctl: The True Story
                    Date: Thu, 9 May 2002 18:07:23 +0100 (BST)
                    From: Reuben Thomas <rrt@mupsych.org>
                      To: Julian Seward <jseward@acm.org>

                 1. As you suggested, the syscall subop is in arg1.

                 2. There are a couple more twists, so the arg order
                    is actually:

                 arg1 syscall subop
                 arg2 file desc
                 arg3 shm operation code (can have IPC_64 set)
                 arg4 0 ??? is arg3-arg4 a 64-bit quantity when IPC_64
                        is defined?
                 arg5 pointer to buffer

                 3. With this in mind, I've amended the case as below:
	      */
               {
                  UInt cmd = arg3;
                  Bool out_arg = False;
                  if ( arg5 ) {
#                    if defined(IPC_64)
                     cmd = cmd & (~IPC_64);
#                    endif
                     out_arg = cmd == SHM_STAT || cmd == IPC_STAT;
                     if ( out_arg )
                        must_be_writable( tst, 
                           "shmctl(SHM_STAT or IPC_STAT,buf)", 
                           arg5, sizeof(struct shmid_ds) );
                     else
                        must_be_readable( tst, 
                           "shmctl(SHM_XXXX,buf)", 
                           arg5, sizeof(struct shmid_ds) );
                  }
               }
               break;
            default:
               VG_(message)(Vg_DebugMsg,
                            "FATAL: unhandled syscall(ipc) %d",
                            arg1 );
               VG_(panic)("... bye!\n");
               break; /*NOTREACHED*/
         }
         break;

      case __NR_ioctl: /* syscall 54 */
         /* int ioctl(int d, int request, ...)
            [The  "third"  argument  is traditionally char *argp, 
             and will be so named for this discussion.]
         */
         switch (arg2 /* request */) {
            case TCSETS:
            case TCSETSW:
            case TCSETSF:
               must_be_readable( tst, "ioctl(TCSET{S,SW,SF})", arg3, 
                                 VKI_SIZEOF_STRUCT_TERMIOS );
               break; 
            case TCGETS:
               must_be_writable( tst, "ioctl(TCGETS)", arg3, 
                                 VKI_SIZEOF_STRUCT_TERMIOS );
               break;
            case TCSETA:
            case TCSETAW:
            case TCSETAF:
               must_be_readable( tst, "ioctl(TCSET{A,AW,AF})", arg3,
                                 VKI_SIZEOF_STRUCT_TERMIO );
               break;
            case TCGETA:
               must_be_writable( tst, "ioctl(TCGETA)", arg3,
                                 VKI_SIZEOF_STRUCT_TERMIO );
               break;
            case TCSBRK:
            case TCXONC:
            case TCSBRKP:
            case TCFLSH:
               /* These just take an int by value */
               break;
            case TIOCGWINSZ:
               must_be_writable( tst, "ioctl(TIOCGWINSZ)", arg3, 
                                 sizeof(struct winsize) );
               break;
            case TIOCSWINSZ:
               must_be_readable( tst, "ioctl(TIOCSWINSZ)", arg3, 
                                 sizeof(struct winsize) );
               break;
            case TIOCGPGRP:
               /* Get process group ID for foreground processing group. */
               must_be_writable( tst, "ioctl(TIOCGPGRP)", arg3,
                                 sizeof(pid_t) );
               break;
            case TIOCSPGRP:
               /* Set a process group ID? */
               must_be_writable( tst, "ioctl(TIOCSPGRP)", arg3,
                                 sizeof(pid_t) );
               break;
            case TIOCGPTN: /* Get Pty Number (of pty-mux device) */
               must_be_writable(tst, "ioctl(TIOCGPTN)", arg3, sizeof(int) );
               break;
            case TIOCSCTTY:
               /* Just takes an int value.  */
               break;
            case TIOCSPTLCK: /* Lock/unlock Pty */
               must_be_readable( tst, "ioctl(TIOCSPTLCK)", arg3, sizeof(int) );
               break;
            case FIONBIO:
               must_be_readable( tst, "ioctl(FIONBIO)", arg3, sizeof(int) );
               break;
            case FIOASYNC:
               must_be_readable( tst, "ioctl(FIOASYNC)", arg3, sizeof(int) );
               break;
            case FIONREAD:
               must_be_writable( tst, "ioctl(FIONREAD)", arg3, sizeof(int) );
               break;

            /* If you get compilation problems here, change the #if
               1 to #if 0 and get rid of <scsi/sg.h> in
               vg_unsafe.h. */
#       if 1
            case SG_SET_COMMAND_Q:
               must_be_readable( tst, "ioctl(SG_SET_COMMAND_Q)", 
                                 arg3, sizeof(int) );
               break;
#           if defined(SG_IO)
            case SG_IO:
               must_be_writable( tst, "ioctl(SG_IO)", arg3, 
                                 sizeof(struct sg_io_hdr) );
               break;
#           endif /* SG_IO */
            case SG_GET_SCSI_ID:
               /* Note: sometimes sg_scsi_id is called sg_scsi_id_t */
               must_be_writable( tst, "ioctl(SG_GET_SCSI_ID)", arg3, 
                                 sizeof(struct sg_scsi_id) );
               break;
            case SG_SET_RESERVED_SIZE:
               must_be_readable( tst, "ioctl(SG_SET_RESERVED_SIZE)", 
                                 arg3, sizeof(int) );
               break;
            case SG_SET_TIMEOUT:
               must_be_readable( tst, "ioctl(SG_SET_TIMEOUT)", arg3, 
                                 sizeof(int) );
               break;
            case SG_GET_RESERVED_SIZE:
               must_be_writable( tst, "ioctl(SG_GET_RESERVED_SIZE)", arg3, 
                                 sizeof(int) );
               break;
            case SG_GET_TIMEOUT:
               must_be_writable( tst, "ioctl(SG_GET_TIMEOUT)", arg3, 
                                 sizeof(int) );
               break;
            case SG_GET_VERSION_NUM:
               must_be_readable( tst, "ioctl(SG_GET_VERSION_NUM)", 
                                 arg3, sizeof(int) );
               break;
#       endif

            case IIOCGETCPS:
               /* In early 2.4 kernels, ISDN_MAX_CHANNELS was only defined
                * when KERNEL was. I never saw a larger value than 64 though */
#              ifndef ISDN_MAX_CHANNELS
#              define ISDN_MAX_CHANNELS 64
#              endif
               must_be_writable( tst, "ioctl(IIOCGETCPS)", arg3,
                                 ISDN_MAX_CHANNELS 
                                 * 2 * sizeof(unsigned long) );
               break;
            case IIOCNETGPN:
               must_be_readable( tst, "ioctl(IIOCNETGPN)",
                                 (UInt)&((isdn_net_ioctl_phone *)arg3)->name,
                                 sizeof(((isdn_net_ioctl_phone *)arg3)->name) );
               must_be_writable( tst, "ioctl(IIOCNETGPN)", arg3,
                                 sizeof(isdn_net_ioctl_phone) );
               break;

            /* These all use struct ifreq AFAIK */
            case SIOCGIFINDEX:
            case SIOCGIFFLAGS:        /* get flags                    */
            case SIOCGIFHWADDR:       /* Get hardware address         */
            case SIOCGIFMTU:          /* get MTU size                 */
            case SIOCGIFADDR:         /* get PA address               */
            case SIOCGIFNETMASK:      /* get network PA mask          */
            case SIOCGIFMETRIC:       /* get metric                   */
            case SIOCGIFMAP:          /* Get device parameters        */
            case SIOCGIFTXQLEN:       /* Get the tx queue length      */
            case SIOCGIFDSTADDR:      /* get remote PA address        */
            case SIOCGIFBRDADDR:      /* get broadcast PA address     */
            case SIOCGIFNAME:         /* get iface name               */
               must_be_writable(tst, "ioctl(SIOCGIFINDEX)", arg3, 
                                sizeof(struct ifreq));
               break;
            case SIOCGIFCONF:         /* get iface list               */
               /* WAS:
               must_be_writable("ioctl(SIOCGIFCONF)", arg3, 
                                sizeof(struct ifconf));
               */
               must_be_readable(tst, "ioctl(SIOCGIFCONF)", arg3, 
                                sizeof(struct ifconf));
               if ( arg3 ) {
                  // TODO len must be readable and writable
                  // buf pointer only needs to be readable
                  struct ifconf *ifc = (struct ifconf *) arg3;
                  must_be_writable(tst, "ioctl(SIOCGIFCONF).ifc_buf",
                                   (Addr)(ifc->ifc_buf), (UInt)(ifc->ifc_len) );
               }
               break;
            case SIOCGSTAMP:
               must_be_writable(tst, "ioctl(SIOCGSTAMP)", arg3, 
                                sizeof(struct timeval));
               break;
            case SIOCGRARP:           /* get RARP table entry         */
            case SIOCGARP:            /* get ARP table entry          */
               must_be_writable(tst, "ioctl(SIOCGARP)", arg3, 
                                sizeof(struct arpreq));
               break;
                    
            case SIOCSIFFLAGS:        /* set flags                    */
            case SIOCSIFMAP:          /* Set device parameters        */
            case SIOCSIFTXQLEN:       /* Set the tx queue length      */
            case SIOCSIFDSTADDR:      /* set remote PA address        */
            case SIOCSIFBRDADDR:      /* set broadcast PA address     */
            case SIOCSIFNETMASK:      /* set network PA mask          */
            case SIOCSIFMETRIC:       /* set metric                   */
            case SIOCSIFADDR:         /* set PA address               */
            case SIOCSIFMTU:          /* set MTU size                 */
            case SIOCSIFHWADDR:       /* set hardware address         */
               must_be_readable(tst,"ioctl(SIOCSIFFLAGS)", arg3, 
                                sizeof(struct ifreq));
               break;
            /* Routing table calls.  */
            case SIOCADDRT:           /* add routing table entry      */
            case SIOCDELRT:           /* delete routing table entry   */
               must_be_readable(tst,"ioctl(SIOCADDRT/DELRT)", arg3, 
                                sizeof(struct rtentry));
               break;

            /* RARP cache control calls. */
            case SIOCDRARP:           /* delete RARP table entry      */
            case SIOCSRARP:           /* set RARP table entry         */
            /* ARP cache control calls. */
            case SIOCSARP:            /* set ARP table entry          */
            case SIOCDARP:            /* delete ARP table entry       */
               must_be_readable(tst, "ioctl(SIOCSIFFLAGS)", arg3, 
                                sizeof(struct ifreq));
               break;

            case SIOCSPGRP:
               must_be_readable( tst, "ioctl(SIOCSPGRP)", arg3, sizeof(int) );
               break;

            /* linux/soundcard interface (OSS) */
            case SNDCTL_SEQ_GETOUTCOUNT:
            case SNDCTL_SEQ_GETINCOUNT:
            case SNDCTL_SEQ_PERCMODE:
            case SNDCTL_SEQ_TESTMIDI:
            case SNDCTL_SEQ_RESETSAMPLES:
            case SNDCTL_SEQ_NRSYNTHS:
            case SNDCTL_SEQ_NRMIDIS:
            case SNDCTL_SEQ_GETTIME:
            case SNDCTL_DSP_GETFMTS:
            case SNDCTL_DSP_GETTRIGGER:
            case SNDCTL_DSP_GETODELAY:
#           if defined(SNDCTL_DSP_GETSPDIF)
            case SNDCTL_DSP_GETSPDIF:
#           endif
            case SNDCTL_DSP_GETCAPS:
            case SOUND_PCM_READ_RATE:
            case SOUND_PCM_READ_CHANNELS:
            case SOUND_PCM_READ_BITS:
            case (SOUND_PCM_READ_BITS|0x40000000): /* what the fuck ? */
            case SOUND_PCM_READ_FILTER:
               must_be_writable(tst,"ioctl(SNDCTL_XXX|SOUND_XXX (SIOR, int))", 
                                arg3,
                                sizeof(int));
               break;
            case SNDCTL_SEQ_CTRLRATE:
            case SNDCTL_DSP_SPEED:
            case SNDCTL_DSP_STEREO:
            case SNDCTL_DSP_GETBLKSIZE: 
            case SNDCTL_DSP_CHANNELS:
            case SOUND_PCM_WRITE_FILTER:
            case SNDCTL_DSP_SUBDIVIDE:
            case SNDCTL_DSP_SETFRAGMENT:
#           if defined(SNDCTL_DSP_GETCHANNELMASK)
            case SNDCTL_DSP_GETCHANNELMASK:
#           endif
#           if defined(SNDCTL_DSP_BIND_CHANNEL)
            case SNDCTL_DSP_BIND_CHANNEL:
#           endif
            case SNDCTL_TMR_TIMEBASE:
            case SNDCTL_TMR_TEMPO:
            case SNDCTL_TMR_SOURCE:
            case SNDCTL_MIDI_PRETIME:
            case SNDCTL_MIDI_MPUMODE:
               must_be_readable(tst, "ioctl(SNDCTL_XXX|SOUND_XXX "
                                     "(SIOWR, int))", 
                                arg3, sizeof(int));
               must_be_writable(tst, "ioctl(SNDCTL_XXX|SOUND_XXX "
                                     "(SIOWR, int))", 
                                arg3, sizeof(int));
               break;
            case SNDCTL_DSP_GETOSPACE:
            case SNDCTL_DSP_GETISPACE:
               must_be_writable(tst, 
                                "ioctl(SNDCTL_XXX|SOUND_XXX "
                                "(SIOR, audio_buf_info))", arg3,
                                sizeof(audio_buf_info));
            case SNDCTL_DSP_SETTRIGGER:
               must_be_readable(tst, "ioctl(SNDCTL_XXX|SOUND_XXX (SIOW, int))", 
                                arg3, sizeof(int));
               break;

            /* Real Time Clock (/dev/rtc) ioctls */
#           ifndef GLIBC_2_1
            case RTC_UIE_ON:
            case RTC_UIE_OFF:
            case RTC_AIE_ON:
            case RTC_AIE_OFF:
            case RTC_PIE_ON:
            case RTC_PIE_OFF:
            case RTC_IRQP_SET:
               break;
            case RTC_RD_TIME:
            case RTC_ALM_READ:
               must_be_writable(tst, "ioctl(RTC_RD_TIME/ALM_READ)", arg3,
                                sizeof(struct rtc_time));
               break;
            case RTC_ALM_SET:
               must_be_readable(tst, "ioctl(RTC_ALM_SET)", arg3,
                                sizeof(struct rtc_time));
               break;
            case RTC_IRQP_READ:
               must_be_writable(tst, "ioctl(RTC_IRQP_READ)", arg3,
                                sizeof(unsigned long));
               break;
#           endif /* GLIBC_2_1 */

#           ifdef BLKGETSIZE
            case BLKGETSIZE:
               must_be_writable(tst, "ioctl(BLKGETSIZE)", arg3,
                                sizeof(unsigned long));
               break;
#           endif /* BLKGETSIZE */

            /* CD ROM stuff (??)  */
            case CDROMSUBCHNL:
                must_be_readable(tst, "ioctl(CDROMSUBCHNL (cdsc_format, char))",
                   (int) &(((struct cdrom_subchnl *) arg3)->cdsc_format), 
                   sizeof(((struct cdrom_subchnl *) arg3)->cdsc_format));
                must_be_writable(tst, "ioctl(CDROMSUBCHNL)", arg3, 
                   sizeof(struct cdrom_subchnl));
                break;
            case CDROMREADTOCHDR:
                must_be_writable(tst, "ioctl(CDROMREADTOCHDR)", arg3, 
                   sizeof(struct cdrom_tochdr));
                break;
            case CDROMREADTOCENTRY:
                 must_be_readable(tst, "ioctl(CDROMREADTOCENTRY (cdte_format, char))",
                    (int) &(((struct cdrom_tocentry *) arg3)->cdte_format), 
                    sizeof(((struct cdrom_tocentry *) arg3)->cdte_format));
                 must_be_readable(tst, "ioctl(CDROMREADTOCENTRY (cdte_track, char))",
                    (int) &(((struct cdrom_tocentry *) arg3)->cdte_track), 
                    sizeof(((struct cdrom_tocentry *) arg3)->cdte_track));
                 must_be_writable(tst, "ioctl(CDROMREADTOCENTRY)", arg3, 
                    sizeof(struct cdrom_tocentry));
                 break;
            case CDROMPLAYMSF:
                 must_be_readable(tst, "ioctl(CDROMPLAYMSF)", arg3, 
                    sizeof(struct cdrom_msf));
                 break;
            /* We don't have any specific information on it, so
               try to do something reasonable based on direction and
               size bits.  The encoding scheme is described in
               /usr/include/asm/ioctl.h.  

               According to Simon Hausmann, _IOC_READ means the kernel
               writes a value to the ioctl value passed from the user
               space and the other way around with _IOC_WRITE. */
            default: {
               // SSS: some repeated vars
               UInt dir  = _IOC_DIR(arg2);
               UInt size = _IOC_SIZE(arg2);
               if (/* size == 0 || */ dir == _IOC_NONE) {
                  VG_(message)(Vg_UserMsg, 
                     "Warning: noted but unhandled ioctl 0x%x"
                     " with no size/direction hints",
                     arg2); 
                  VG_(message)(Vg_UserMsg, 
                     "   This could cause spurious value errors"
                     " to appear.");
                  VG_(message)(Vg_UserMsg, 
                     "   See README_MISSING_SYSCALL_OR_IOCTL for guidance on"
                     " writing a proper wrapper." );
               } else {
                  if ((dir & _IOC_WRITE) && size > 0)
                     must_be_readable(tst, "ioctl(generic)", arg3, size);
                  if ((dir & _IOC_READ) && size > 0)
                     must_be_writable(tst, "ioctl(generic)", arg3, size);
               }
               break;
            }
         }
         break;

      case __NR_link: /* syscall 9 */
         /* int link(const char *oldpath, const char *newpath); */
         must_be_readable_asciiz( tst, "link(oldpath)", arg1);
         must_be_readable_asciiz( tst, "link(newpath)", arg2);
         break;

      case __NR__llseek: /* syscall 140 */
         /* int _llseek(unsigned int fd, unsigned long offset_high,       
                        unsigned long  offset_low, 
                        loff_t * result, unsigned int whence); */
         must_be_writable( tst, "llseek(result)", arg4, sizeof(loff_t));
         break;

      case __NR_lstat: /* syscall 107 */
         /* int lstat(const char *file_name, struct stat *buf); */
         must_be_readable_asciiz( tst, "lstat(file_name)", arg1 );
         must_be_writable( tst, "lstat(buf)", arg2, sizeof(struct stat) );
         break;

#     if defined(__NR_lstat64)
      case __NR_lstat64: /* syscall 196 */
         /* int lstat64(const char *file_name, struct stat64 *buf); */
         must_be_readable_asciiz( tst, "lstat64(file_name)", arg1 );
         must_be_writable( tst, "lstat64(buf)", arg2, sizeof(struct stat64) );
         break;
#     endif

      case __NR_mkdir: /* syscall 39 */
         /* int mkdir(const char *pathname, mode_t mode); */
         must_be_readable_asciiz( tst, "mkdir(pathname)", arg1 );
         break;

      case __NR_mmap: /* syscall 90 */
         /* void* mmap(void *start, size_t length, int prot, 
                       int flags, int fd, off_t offset); 
         */
         must_be_readable( tst, "mmap(args)", arg1, 6*sizeof(UInt) );
         //must_be_readable( tst, "mmap(args)", arg1, 6*sizeof(UInt) );
         break;

      case __NR_nanosleep: /* syscall 162 */
         /* int nanosleep(const struct timespec *req, struct timespec *rem); */
         must_be_readable ( tst, "nanosleep(req)", arg1, 
                                              sizeof(struct timespec) );
         if (arg2 != (UInt)NULL)
            must_be_writable ( tst, "nanosleep(rem)", arg2, 
                               sizeof(struct timespec) );
         break;

      case __NR__newselect: /* syscall 142 */
         /* int select(int n,  
                       fd_set *readfds, fd_set *writefds, fd_set *exceptfds, 
                       struct timeval *timeout);
         */
         if (arg2 != 0)
            must_be_readable( tst, "newselect(readfds)",   
                              arg2, arg1/8 /* __FD_SETSIZE/8 */ );
         if (arg3 != 0)
            must_be_readable( tst, "newselect(writefds)",  
                              arg3, arg1/8 /* __FD_SETSIZE/8 */ );
         if (arg4 != 0)
            must_be_readable( tst, "newselect(exceptfds)", 
                              arg4, arg1/8 /* __FD_SETSIZE/8 */ );
         if (arg5 != 0)
            must_be_readable( tst, "newselect(timeout)", arg5, 
                              sizeof(struct timeval) );
         break;
         
      case __NR_open: /* syscall 5 */
         /* int open(const char *pathname, int flags); */
         must_be_readable_asciiz( tst, "open(pathname)", arg1 );
         break;

      case __NR_pipe: /* syscall 42 */
         /* int pipe(int filedes[2]); */
         must_be_writable( tst, "pipe(filedes)", arg1, 2*sizeof(int) );
         break;

      case __NR_poll: /* syscall 168 */
         /* struct pollfd {
               int fd;           -- file descriptor
               short events;     -- requested events
               short revents;    -- returned events
            };
           int poll(struct pollfd *ufds, unsigned int nfds, 
                                         int timeout) 
         */
         /* In fact some parts of this struct should be readable too.
            This should be fixed properly. */
         must_be_writable( tst, "poll(ufds)", 
                           arg1, arg2 * sizeof(struct pollfd) );
         break;
 
      case __NR_readlink: /* syscall 85 */
         /* int readlink(const char *path, char *buf, size_t bufsiz); */
         must_be_readable_asciiz( tst, "readlink(path)", arg1 );
         must_be_writable ( tst, "readlink(buf)", arg2,arg3 );
         break;

         // SSS: not sure about vec...
      case __NR_readv: { /* syscall 145 */
         /* int readv(int fd, const struct iovec * vector, size_t count); */
         UInt i;
         struct iovec * vec;
         must_be_readable( tst, "readv(vector)", 
                           arg2, arg3 * sizeof(struct iovec) );
         /* ToDo: don't do any of the following if the vector is invalid */
         vec = (struct iovec *)arg2;
         for (i = 0; i < arg3; i++)
            must_be_writable( tst, "readv(vector[...])",
                              (UInt)vec[i].iov_base,vec[i].iov_len );
         break;
      }

      case __NR_rename: /* syscall 38 */
         /* int rename(const char *oldpath, const char *newpath); */
         must_be_readable_asciiz( tst, "rename(oldpath)", arg1 );
         must_be_readable_asciiz( tst, "rename(newpath)", arg2 );
         break;

      case __NR_rmdir: /* syscall 40 */
         /* int rmdir(const char *pathname); */
         must_be_readable_asciiz( tst, "rmdir(pathname)", arg1 );
         break;

      case __NR_sched_setparam: /* syscall 154 */
         /* int sched_setparam(pid_t pid, const struct sched_param *p); */
         must_be_readable( tst, "sched_setparam(ptr)",
                           arg2, sizeof(struct sched_param) );
         break;

      case __NR_sched_getparam: /* syscall 155 */
         /* int sched_getparam(pid_t pid, struct sched_param *p); */
         must_be_writable( tst, "sched_getparam(ptr)",
                           arg2, sizeof(struct sched_param) );
         break;

      case __NR_select: /* syscall 82 */
         /* struct sel_arg_struct {
              unsigned long n;
              fd_set *inp, *outp, *exp;
              struct timeval *tvp;
            };
            int old_select(struct sel_arg_struct *arg);
         */
         {
         Bool arg_block_readable
                 = Vg_MemCheck==VG_(clo_skin)
                 ? SKN_(check_readable)(arg1, 5*sizeof(UInt), NULL)
                 : True;
         must_be_readable ( tst, "select(args)", arg1, 5*sizeof(UInt) );
         if (arg_block_readable) {
            UInt* arg_struct = (UInt*)arg1;
            arg1 = arg_struct[0];
            arg2 = arg_struct[1];
            arg3 = arg_struct[2];
            arg4 = arg_struct[3];
            arg5 = arg_struct[4];

            if (arg2 != (Addr)NULL)
               must_be_readable(tst, "select(readfds)", arg2, 
                                arg1/8 /* __FD_SETSIZE/8 */ );
            if (arg3 != (Addr)NULL)
               must_be_readable(tst, "select(writefds)", arg3, 
                                arg1/8 /* __FD_SETSIZE/8 */ );
            if (arg4 != (Addr)NULL)
               must_be_readable(tst, "select(exceptfds)", arg4, 
                                arg1/8 /* __FD_SETSIZE/8 */ );
            if (arg5 != (Addr)NULL)
               must_be_readable(tst, "select(timeout)", arg5, 
                                sizeof(struct timeval) );
         }
         }
         break;

      case __NR_setitimer: /* syscall 104 */
         /* setitimer(int which, const struct itimerval *value,
                                 struct itimerval *ovalue); */
         if (arg2 != (Addr)NULL)
            must_be_readable(tst, "setitimer(value)", 
                             arg2, sizeof(struct itimerval) );
         if (arg3 != (Addr)NULL)
            must_be_writable(tst, "setitimer(ovalue)", 
                             arg3, sizeof(struct itimerval));
         break;

#     if defined(__NR_setgroups32)
      case __NR_setgroups32: /* syscall 206 */
#     endif
      case __NR_setgroups: /* syscall 81 */
         /* int setgroups(size_t size, const gid_t *list); */
         if (arg1 > 0)
            must_be_readable ( tst, "setgroups(list)", arg2, 
                               arg1 * sizeof(gid_t) );
         break;

      case __NR_setrlimit: /* syscall 75 */
         /* int setrlimit (int resource, const struct rlimit *rlim); */
         must_be_readable( tst, "setrlimit(rlim)", arg2, sizeof(struct rlimit) );
         break;

      case __NR_socketcall: /* syscall 102 */
         /* int socketcall(int call, unsigned long *args); */
         switch (arg1 /* request */) {

            case SYS_SOCKETPAIR:
               /* int socketpair(int d, int type, int protocol, int sv[2]); */
               must_be_readable( tst, "socketcall.socketpair(args)", 
                                 arg2, 4*sizeof(Addr) );
               must_be_writable( tst, "socketcall.socketpair(sv)", 
                                 ((UInt*)arg2)[3], 2*sizeof(int) );
               break;

            case SYS_SOCKET:
               /* int socket(int domain, int type, int protocol); */
               must_be_readable( tst, "socketcall.socket(args)", 
                                 arg2, 3*sizeof(Addr) );
               break;

            case SYS_BIND:
               /* int bind(int sockfd, struct sockaddr *my_addr, 
                           int addrlen); */
               must_be_readable( tst, "socketcall.bind(args)", 
                                 arg2, 3*sizeof(Addr) );
               must_be_readable_sockaddr( tst, "socketcall.bind(my_addr.%s)",
                  (struct sockaddr *) (((UInt*)arg2)[1]), ((UInt*)arg2)[2]);
               break;
               
            case SYS_LISTEN:
               /* int listen(int s, int backlog); */
               must_be_readable( tst, "socketcall.listen(args)", 
                                 arg2, 2*sizeof(Addr) );
               break;

            case SYS_ACCEPT: {
               /* int accept(int s, struct sockaddr *addr, int *p_addrlen); */
               Addr addr;
               Addr p_addrlen;
               UInt addrlen_in;
               must_be_readable( tst, "socketcall.accept(args)", 
                                 arg2, 3*sizeof(Addr) );
               addr      = ((UInt*)arg2)[1];
               p_addrlen = ((UInt*)arg2)[2];
               if (p_addrlen != (Addr)NULL) {
                  must_be_readable ( tst, "socketcall.accept(addrlen)", 
                                     p_addrlen, sizeof(int) );
                  addrlen_in = safe_dereference( p_addrlen, 0 );
                  must_be_writable ( tst, "socketcall.accept(addr)", 
                                     addr, addrlen_in );
               }
               break;
            }

            case SYS_SENDTO:
               /* int sendto(int s, const void *msg, int len, 
                             unsigned int flags, 
                             const struct sockaddr *to, int tolen); */
               must_be_readable( tst, "socketcall.sendto(args)", arg2, 
                                 6*sizeof(Addr) );
               must_be_readable( tst, "socketcall.sendto(msg)",
                                 ((UInt*)arg2)[1], /* msg */
                                 ((UInt*)arg2)[2]  /* len */ );
               must_be_readable_sockaddr( tst, "socketcall.sendto(to.%s)",
                  (struct sockaddr *) (((UInt*)arg2)[4]), ((UInt*)arg2)[5]);
               break;

            case SYS_SEND:
               /* int send(int s, const void *msg, size_t len, int flags); */
               must_be_readable( tst, "socketcall.send(args)", arg2,
                                 4*sizeof(Addr) );
               must_be_readable( tst, "socketcall.send(msg)",
                                 ((UInt*)arg2)[1], /* msg */
                                  ((UInt*)arg2)[2]  /* len */ );
               break;

            case SYS_RECVFROM:
               /* int recvfrom(int s, void *buf, int len, unsigned int flags,
                               struct sockaddr *from, int *fromlen); */
               must_be_readable( tst, "socketcall.recvfrom(args)", 
                                 arg2, 6*sizeof(Addr) );
               if ( ((UInt*)arg2)[4] /* from */ != 0) {
                  must_be_readable( tst, "socketcall.recvfrom(fromlen)",
                                    ((UInt*)arg2)[5] /* fromlen */, 
                                    sizeof(int) );
                  must_be_writable( tst, "socketcall.recvfrom(from)",
                                    ((UInt*)arg2)[4], /*from*/
                                    safe_dereference( (Addr)
                                                      ((UInt*)arg2)[5], 0 ) );
               }
               must_be_writable( tst, "socketcall.recvfrom(buf)", 
                                 ((UInt*)arg2)[1], /* buf */
                                 ((UInt*)arg2)[2]  /* len */ );
               /* phew! */
               break;

            case SYS_RECV:
               /* int recv(int s, void *buf, int len, unsigned int flags); */
               /* man 2 recv says:
               The  recv call is normally used only on a connected socket
               (see connect(2)) and is identical to recvfrom with a  NULL
               from parameter.
               */
               must_be_readable( tst, "socketcall.recv(args)", 
                                 arg2, 4*sizeof(Addr) );
               must_be_writable( tst, "socketcall.recv(buf)", 
                                 ((UInt*)arg2)[1], /* buf */
                                 ((UInt*)arg2)[2]  /* len */ );
               break;

            case SYS_CONNECT:
               /* int connect(int sockfd, 
                              struct sockaddr *serv_addr, int addrlen ); */
               must_be_readable( tst, "socketcall.connect(args)", 
                                 arg2, 3*sizeof(Addr) );
               must_be_readable( tst, "socketcall.connect(serv_addr.sa_family)",
                                 ((UInt*)arg2)[1], /* serv_addr */
                                 sizeof (sa_family_t));
               must_be_readable_sockaddr( tst,
                  "socketcall.connect(serv_addr.%s)",
                  (struct sockaddr *) (((UInt*)arg2)[1]), ((UInt*)arg2)[2]);
               break;

            case SYS_SETSOCKOPT:
               /* int setsockopt(int s, int level, int optname, 
                                 const void *optval, int optlen); */
               must_be_readable( tst, "socketcall.setsockopt(args)", 
                                 arg2, 5*sizeof(Addr) );
               must_be_readable( tst, "socketcall.setsockopt(optval)",
                                 ((UInt*)arg2)[3], /* optval */
                                 ((UInt*)arg2)[4]  /* optlen */ );
               break;

            case SYS_GETSOCKOPT:
               /* int setsockopt(int s, int level, int optname, 
                                 void *optval, socklen_t *optlen); */
               must_be_readable( tst, "socketcall.getsockopt(args)", 
                                 arg2, 5*sizeof(Addr) );
               {
               Addr optval_p = ((UInt*)arg2)[3];
               Addr optlen_p = ((UInt*)arg2)[4];
               /* vg_assert(sizeof(socklen_t) == sizeof(UInt)); */
               UInt optlen = safe_dereference ( optlen_p, 0 );
               if (optlen > 0) 
                  must_be_writable( tst, "socketcall.getsockopt(optval)", 
                                    optval_p, optlen );
               }
               break;

            case SYS_GETSOCKNAME:
               /* int getsockname(int s, struct sockaddr* name, 
                                  int* namelen) */
               must_be_readable( tst, "socketcall.getsockname(args)", 
                                 arg2, 3*sizeof(Addr) );
               {
               UInt namelen = safe_dereference( (Addr) ((UInt*)arg2)[2], 0);
               if (namelen > 0)
                  must_be_writable( tst, "socketcall.getsockname(name)", 
                                    ((UInt*)arg2)[1], namelen );
               }
               break;

            case SYS_GETPEERNAME:
               /* int getpeername(int s, struct sockaddr* name, 
                                  int* namelen) */
               must_be_readable( tst, "socketcall.getpeername(args)", 
                                 arg2, 3*sizeof(Addr) );
               {
               UInt namelen = safe_dereference( (Addr) ((UInt*)arg2)[2], 0);
               if (namelen > 0)
                  must_be_writable( tst, "socketcall.getpeername(name)", 
                                    ((UInt*)arg2)[1], namelen );
               }
               break;

            case SYS_SHUTDOWN:
               /* int shutdown(int s, int how); */
               must_be_readable( tst, "socketcall.shutdown(args)", 
                                 arg2, 2*sizeof(Addr) );
               break;

            case SYS_SENDMSG:
               {
                  /* int sendmsg(int s, const struct msghdr *msg, int flags); */

                  /* this causes warnings, and I don't get why. glibc bug?
                   * (after all it's glibc providing the arguments array)
                  must_be_readable( "socketcall.sendmsg(args)", 
                                     arg2, 3*sizeof(Addr) );
                  */

                  struct msghdr *msg = (struct msghdr *)((UInt *)arg2)[ 1 ];
                  VG_(msghdr_foreachfield) ( tst, msg, must_be_readable_sendmsg );
                  break;
               }

            case SYS_RECVMSG:
               {
                  /* int recvmsg(int s, struct msghdr *msg, int flags); */

                  /* this causes warnings, and I don't get why. glibc bug?
                   * (after all it's glibc providing the arguments array)
                  must_be_readable( "socketcall.recvmsg(args)", 
                                     arg2, 3*sizeof(Addr) );
                  */

                  struct msghdr *msg = (struct msghdr *)((UInt *)arg2)[ 1 ];
                  VG_(msghdr_foreachfield) ( tst, msg, must_be_writable_recvmsg );
                  break;
               }

            default:
               VG_(message)(Vg_DebugMsg,"FATAL: unhandled socketcall 0x%x",arg1);
               VG_(panic)("... bye!\n");
               break; /*NOTREACHED*/
         }
         break;

      case __NR_stat: /* syscall 106 */
         /* int stat(const char *file_name, struct stat *buf); */
         must_be_readable_asciiz( tst, "stat(file_name)", arg1 );
         must_be_writable( tst, "stat(buf)", arg2, sizeof(struct stat) );
         break;

      case __NR_statfs: /* syscall 99 */
         /* int statfs(const char *path, struct statfs *buf); */
         must_be_readable_asciiz( tst, "statfs(path)", arg1 );
         must_be_writable( tst, "stat(buf)", arg2, sizeof(struct statfs) );
         break;

      case __NR_symlink: /* syscall 83 */
         /* int symlink(const char *oldpath, const char *newpath); */
         must_be_readable_asciiz( tst, "symlink(oldpath)", arg1 );
         must_be_readable_asciiz( tst, "symlink(newpath)", arg2 );
         break; 

#     if defined(__NR_stat64)
      case __NR_stat64: /* syscall 195 */
         /* int stat64(const char *file_name, struct stat64 *buf); */
         must_be_readable_asciiz( tst, "stat64(file_name)", arg1 );
         must_be_writable( tst, "stat64(buf)", arg2, sizeof(struct stat64) );
         break;
#     endif

#     if defined(__NR_fstat64)
      case __NR_fstat64: /* syscall 197 */
         /* int fstat64(int filedes, struct stat64 *buf); */
         must_be_writable( tst, "fstat64(buf)", arg2, sizeof(struct stat64) );
         break;
#     endif

      case __NR_sysinfo: /* syscall 116 */
         /* int sysinfo(struct sysinfo *info); */
         must_be_writable( tst, "sysinfo(info)", arg1, sizeof(struct sysinfo) );
         break;

      case __NR_time: /* syscall 13 */
         /* time_t time(time_t *t); */
         if (arg1 != (UInt)NULL) {
            must_be_writable( tst, "time", arg1, sizeof(time_t) );
         }
         break;

      case __NR_times: /* syscall 43 */
         /* clock_t times(struct tms *buf); */
         must_be_writable( tst, "times(buf)", arg1, sizeof(struct tms) );
         break;

      case __NR_truncate: /* syscall 92 */
         /* int truncate(const char *path, size_t length); */
         must_be_readable_asciiz( tst, "truncate(path)", arg1 );
         break;

      case __NR_unlink: /* syscall 10 */
         /* int unlink(const char *pathname) */
         must_be_readable_asciiz( tst, "unlink(pathname)", arg1 );
         break;

      case __NR_uname: /* syscall 122 */
         /* int uname(struct utsname *buf); */
         must_be_writable( tst, "uname(buf)", arg1, sizeof(struct utsname) );
         break;

      case __NR_utime: /* syscall 30 */
         /* int utime(const char *filename, struct utimbuf *buf); */
         must_be_readable_asciiz( tst, "utime(filename)", arg1 );
         if (arg2 != (UInt)NULL)
            must_be_readable( tst, "utime(buf)", arg2, 
                                                 sizeof(struct utimbuf) );
         break;

      case __NR_wait4: /* syscall 114 */
         /* pid_t wait4(pid_t pid, int *status, int options,
                        struct rusage *rusage) */
         if (arg2 != (Addr)NULL)
            must_be_writable( tst, "wait4(status)", arg2, sizeof(int) );
         if (arg4 != (Addr)NULL)
            must_be_writable( tst, "wait4(rusage)", arg4, 
                              sizeof(struct rusage) );
         break;

      case __NR_writev: { /* syscall 146 */
         /* int writev(int fd, const struct iovec * vector, size_t count); */
         UInt i;
         struct iovec * vec;
         must_be_readable( tst, "writev(vector)", 
                           arg2, arg3 * sizeof(struct iovec) );
         /* ToDo: don't do any of the following if the vector is invalid */
         vec = (struct iovec *)arg2;
         for (i = 0; i < arg3; i++)
            must_be_readable( tst, "writev(vector[...])",
                              (UInt)vec[i].iov_base,vec[i].iov_len );
         break;
      }

      /*-------------------------- SIGNALS --------------------------*/

      /* Normally set to 1, so that Valgrind's signal-simulation machinery
         is engaged.  Sometimes useful to disable (set to 0), for
         debugging purposes, to make clients more deterministic. */
#     define SIGNAL_SIMULATION 1

      case __NR_sigaltstack: /* syscall 186 */
         /* int sigaltstack(const stack_t *ss, stack_t *oss); */
         if (arg1 != (UInt)NULL) {
            must_be_readable( tst, "sigaltstack(ss)", 
                              arg1, sizeof(vki_kstack_t) );
         }
         if (arg2 != (UInt)NULL) {
            must_be_writable( tst, "sigaltstack(ss)", 
                              arg1, sizeof(vki_kstack_t) );
         }
         break;

      case __NR_rt_sigaction:
      case __NR_sigaction:
         /* int sigaction(int signum, struct k_sigaction *act, 
                                      struct k_sigaction *oldact); */
         if (arg2 != (UInt)NULL)
            must_be_readable( tst, "sigaction(act)", 
                              arg2, sizeof(vki_ksigaction));
         if (arg3 != (UInt)NULL)
            must_be_writable( tst, "sigaction(oldact)", 
                              arg3, sizeof(vki_ksigaction));
         break;

      case __NR_rt_sigprocmask:
      case __NR_sigprocmask:
         /* int sigprocmask(int how, k_sigset_t *set, 
                                     k_sigset_t *oldset); */
         if (arg2 != (UInt)NULL)
            must_be_readable( tst, "sigprocmask(set)", 
                              arg2, sizeof(vki_ksigset_t));
         if (arg3 != (UInt)NULL)
            must_be_writable( tst, "sigprocmask(oldset)", 
                              arg3, sizeof(vki_ksigset_t));
         break;

      case __NR_sigpending: /* syscall 73 */
#     if defined(__NR_rt_sigpending)
      case __NR_rt_sigpending: /* syscall 176 */
#     endif
         /* int sigpending( sigset_t *set ) ; */
         must_be_writable( tst, "sigpending(set)", 
                           arg1, sizeof(vki_ksigset_t));
         break ;

      default:
         VG_(message)
            (Vg_DebugMsg,"FATAL: unhandled (pre)syscall: %d",syscallno);
         VG_(message)
            (Vg_DebugMsg,"Do not panic.  You may be able to fix this easily.");
         VG_(message)
            (Vg_DebugMsg,"Read the file README_MISSING_SYSCALL_OR_IOCTL.");
         VG_(unimplemented)("no wrapper for the above system call");
         vg_assert(3+3 == 7);
         break; /*NOTREACHED*/
   }

   /* { void zzzmemscan(void); zzzmemscan(); } */

   VGP_POPCC;

   return (void*)sane_before_call;
}



/* Perform pre- and post- actions for a blocking syscall, but do not
   do the syscall itself.  If res is NULL, the pre-syscall actions are
   to be performed.  If res is non-NULL, the post-syscall actions are
   to be performed, and *res is assumed to hold the result of the
   syscall.  This slightly strange scheme makes it impossible to
   mistakenly use the value of *res in the pre-syscall actions.  

   This doesn't actually do the syscall itself, it is important to
   observe.  

   Because %eax is used both for the syscall number before the call
   and the result value afterwards, we can't reliably use it to get
   the syscall number.  So the caller has to pass it explicitly.  
*/
void* SKN_(pre_blocking_syscall_check) ( ThreadId tid,
                                         Int syscallno,
                                         Int* /*IN*/ res )
{
   ThreadState* tst;
   Int          sane_before_post;
   UInt         arg1, arg2, arg3;

   VGP_PUSHCC(VgpSyscall);

   vg_assert(VG_(is_valid_tid)(tid));
   tst              = & VG_(threads)[tid];
   arg1             = tst->m_ebx;
   arg2             = tst->m_ecx;
   arg3             = tst->m_edx;
   /*
   arg4             = tst->m_esi;
   arg5             = tst->m_edi;
   */

   sane_before_post = SKN_(cheap_sanity_check)();

   switch (syscallno) {

      case __NR_read: /* syscall 3 */
         /* size_t read(int fd, void *buf, size_t count); */
         if (res == NULL) { 
            /* PRE */
            must_be_writable( tst, "read(buf)", arg2, arg3 );
         } else {
            /* POST */
	 }
         break;

      case __NR_write: /* syscall 4 */
         /* size_t write(int fd, const void *buf, size_t count); */
         if (res == NULL) {
            /* PRE */
            must_be_readable( tst, "write(buf)", arg2, arg3 );
	 } else {
            /* POST */
	 }
         break;

      default:
         VG_(printf)("check_known_blocking_syscall: unexpected %d\n", 
                     syscallno);
         VG_(panic)("check_known_blocking_syscall");
         /*NOTREACHED*/
         break;
   }

   VGP_POPCC;

   return (void*)sane_before_post;
}

