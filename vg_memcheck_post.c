
#include "vg_include.h"
#include "vg_unsafe.h"

// SSS: duplicating this from pre.c, bleurgh
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






static void make_noaccess ( Addr a, UInt len )
{
   if (VG_(needs).shadow_memory)
      SKN_(make_noaccess) ( a, len );
}

static void make_writable ( Addr a, UInt len )
{
   if (VG_(needs).shadow_memory)   
      SKN_(make_writable) ( a, len );
}

static void make_readable ( Addr a, UInt len )
{
   if (VG_(needs).shadow_memory)   
      SKN_(make_readable) ( a, len );
}

static void make_readwritable ( Addr a, UInt len )
{
   if (VG_(needs).shadow_memory)   
      SKN_(make_readwritable) ( a, len );
}

/* Set memory permissions, based on PROT_* values for mmap/mprotect,
   into the permissions our scheme understands.  Dunno if this is
   really correct.  */

// SSS: not correct for eraser -- make_segment_access??
static void approximate_mmap_permissions ( Addr a, UInt len, UInt prot )
{
   /* PROT_READ and PROT_WRITE --> readable
      PROT_READ only           --> readable
      PROT_WRITE only          --> writable
      NEITHER                  --> noaccess
   */
   if (prot & PROT_READ)
      make_readable(a,len);
   else
   if (prot & PROT_WRITE)
      make_writable(a,len);
   else
      make_noaccess(a,len);
}


// SSS: hmm...
/* Dereference a pointer.  Not really safe, would require
 * memchecking for that which we don't necessarily have...
*/
static __inline__
UInt safe_dereference ( Addr aa, UInt defawlt )
{
   return * (UInt*)aa;
}

static
UInt get_shm_size ( Int shmid )
{
   struct shmid_ds buf;
   long __res;
    __asm__ volatile ( "int $0x80"
                       : "=a" (__res)
                       : "0" (__NR_ipc),
                         "b" ((long)(24) /*IPCOP_shmctl*/),
                         "c" ((long)(shmid)),
                         "d" ((long)(IPC_STAT)),
                         "S" ((long)(0)),
                         "D" ((long)(&buf)) );
    if ( VG_(is_kerror) ( __res ) )
       return 0;
 
   return buf.shm_segsz;
}
 

static
void make_readable_recvmsg ( ThreadState* tst,
                             Char *fieldName, UInt base, UInt size )
{
   make_readable( base, size );
}
 

/* Records the current end of the data segment so we can make sense of
   calls to brk().  Initial value set by VGM_(init_memory_audit)(). */
Addr SK_(curr_dataseg_end);


/* The Main Entertainment ... */

void SKN_(post_syscall) ( ThreadId tid, UInt syscallno,
                          void* sane_before_call, Int res )
{
   ThreadState* tst;
   Bool         sane_after_call;
   UInt         arg1, arg2, arg3, arg4, arg5;

   VGP_PUSHCC(VgpSyscall);

   vg_assert(VG_(is_valid_tid)(tid));
   sane_after_call  = True;
   tst              = & VG_(threads)[tid];

   /* Don't look in tid->m_eax for the syscallno, it will have been trashed
      by now, which is why we passed it in.  But the other regs should still
      be intact. */
   arg1      = tst->m_ebx;
   arg2      = tst->m_ecx;
   arg3      = tst->m_edx;
   arg4      = tst->m_esi;
   arg5      = tst->m_edi;

   /* the syscall no is in %eax.  For syscalls with <= 5 args,
      args 1 .. 5 to the syscall are in %ebx %ecx %edx %esi %edi.
      For calls with > 5 args, %ebx points to a lump of memory
      containing the args.

      The result is returned in %eax.  If this value >= 0, the call
      succeeded, and this is the return value.  If < 0, it failed, and
      the negation of this value is errno.  To be more specific, 
      if res is in the range -EMEDIUMTYPE (-124) .. -EPERM (-1)
      (kernel 2.4.9 sources, include/asm-i386/errno.h)
      then it indicates an error.  Otherwise it doesn't.

      Dirk Mueller (mueller@kde.org) says that values -4095 .. -1
      (inclusive?) indicate error returns.  Not sure where the -4095
      comes from.
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


      /* All the ones that don't require any marking */
#     if defined(__NR_quotactl)
      case __NR_quotactl: /* syscall 131 */
         /* int quotactl(int cmd, char *special, int uid, caddr_t addr); */
#     endif
#     if defined(__NR_truncate64)
      case __NR_truncate64: /* syscall 193 */
         /* int truncate64(const char *path, off64_t length); */
#     endif
#     if defined(__NR_fdatasync)
      case __NR_fdatasync: /* syscall 148 */
         /* int fdatasync(int fd); */
#     endif
#     if defined(__NR_msync) /* syscall 144 */
      case __NR_msync:
         /* int msync(const void *start, size_t length, int flags); */
#     endif
#     if defined(__NR_putpmsg) /* syscall 189 */
      case __NR_putpmsg: 
      /* LiS putpmsg from http://www.gcom.com/home/linux/lis/ */
      /* int putpmsg(int fd, struct strbuf *ctrl, struct strbuf *data, 
                             int band, int flags); */
      break;
#     endif
      case __NR_personality: /* syscall 136 */
         /* int personality(unsigned long persona); */
      case __NR_chroot: /* syscall 61 */
         /* int chroot(const char *path); */
#     if defined(__NR_madvise)
      case __NR_madvise: /* syscall 219 */
         /* int madvise(void *start, size_t length, int advice ); */
#     endif
      case __NR_nice: /* syscall 34 */
         /* int nice(int inc); */
         break;
#     if defined(__NR_setresgid32)
      case __NR_setresgid32: /* syscall 210 */
         /* int setresgid(gid_t rgid, gid_t egid, gid_t sgid); */
         break;
#     endif
#     if defined(__NR_setfsuid32)
      case __NR_setfsuid32: /* syscall 215 */
         /* int setfsuid(uid_t fsuid); */
          break;
#     endif
#     if defined(__NR_sched_getscheduler)
      case __NR_sched_getscheduler:
         /* int sched_getscheduler(pid_t pid); */
#     endif
#     if defined(__NR_sched_setscheduler)
      case __NR_sched_setscheduler:
         /* int sched_setscheduler(pid_t pid, int policy, 
                const struct sched_param *p); */
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
#     if defined(__NR_pwrite)
      case __NR_pwrite: /* syscall 181 */
         /* ssize_t pwrite (int fd, const void *buf, size_t nbytes,
                            off_t offset); */
#     endif
      case __NR_sync: /* syscall 36 */
         /* int sync(); */
      case __NR_pause: /* syscall 29 */
         /* int pause(void); */
      case __NR_getsid: /* syscall 147 */
         /* pid_t getsid(pid_t pid); */
      case __NR_mknod: /* syscall 14 */
         /* int mknod(const char *pathname, mode_t mode, dev_t dev); */
      case __NR_flock: /* syscall 143 */
         /* int flock(int fd, int operation); */
#     if defined(__NR_rt_sigsuspend)
      /* Viewed with great suspicion by me, but, hey, let's do it
         anyway ... */
      case __NR_rt_sigsuspend: /* syscall 179 */
         /* int sigsuspend(const sigset_t *mask); */
#     endif
      case __NR_init_module: /* syscall 128 */
         /* int init_module(const char *name, struct module *image); */
      case __NR_ioperm: /* syscall 101 */
         /* int ioperm(unsigned long from, unsigned long num, int turn_on); */
      case __NR_execve:
         /* int execve (const char *filename, 
                        char *const argv [], 
                        char *const envp[]); */
      case __NR_access: /* syscall 33 */
         /* int access(const char *pathname, int mode); */
      case __NR_alarm: /* syscall 27 */
         /* unsigned int alarm(unsigned int seconds); */
      case __NR_chdir: /* syscall 12 */
         /* int chdir(const char *path); */
      case __NR_chmod: /* syscall 15 */
         /* int chmod(const char *path, mode_t mode); */
#     if defined(__NR_chown32)
      case __NR_chown32: /* syscall 212 */
#     endif
#     if defined(__NR_lchown32)
      case __NR_lchown32: /* syscall 198 */
#     endif
      case __NR_chown: /* syscall 16 */
         /* int chown(const char *path, uid_t owner, gid_t group); */
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
      case __NR_link: /* syscall 9 */
         /* int link(const char *oldpath, const char *newpath); */
      case __NR_lseek: /* syscall 19 */
         /* off_t lseek(int fildes, off_t offset, int whence); */
      case __NR_mkdir: /* syscall 39 */
         /* int mkdir(const char *pathname, mode_t mode); */
      case __NR__newselect: /* syscall 142 */
         /* int select(int n,  
                       fd_set *readfds, fd_set *writefds, fd_set *exceptfds, 
                       struct timeval *timeout);
         */
      case __NR_open: /* syscall 5 */
         /* int open(const char *pathname, int flags); */
      case __NR_rename: /* syscall 38 */
         /* int rename(const char *oldpath, const char *newpath); */
      case __NR_rmdir: /* syscall 40 */
         /* int rmdir(const char *pathname); */
      case __NR_sched_yield: /* syscall 158 */
         /* int sched_yield(void); */
      case __NR_select: /* syscall 82 */
         /* struct sel_arg_struct {
              unsigned long n;
              fd_set *inp, *outp, *exp;
              struct timeval *tvp;
            };
            int old_select(struct sel_arg_struct *arg);
         */
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
#     if defined(__NR_setgroups32)
      case __NR_setgroups32: /* syscall 206 */
#     endif
      case __NR_setgroups: /* syscall 81 */
         /* int setgroups(size_t size, const gid_t *list); */
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
      case __NR_setrlimit: /* syscall 75 */
         /* int setrlimit (int resource, const struct rlimit *rlim); */
#     if defined(__NR_setuid32)
      case __NR_setuid32: /* syscall 213 */
#     endif
      case __NR_setuid: /* syscall 23 */
         /* int setuid(uid_t uid); */
      case __NR_symlink: /* syscall 83 */
         /* int symlink(const char *oldpath, const char *newpath); */
      case __NR_truncate: /* syscall 92 */
         /* int truncate(const char *path, size_t length); */
      case __NR_umask: /* syscall 60 */
         /* mode_t umask(mode_t mask); */
      case __NR_unlink: /* syscall 10 */
         /* int unlink(const char *pathname) */
      case __NR_utime: /* syscall 30 */
         /* int utime(const char *filename, struct utimbuf *buf); */
      case __NR_writev: { /* syscall 146 */
         /* int writev(int fd, const struct iovec * vector, size_t count); */

         /* All fall through to here */
         break;



      /* !!!!!!!!!! New, untested syscalls !!!!!!!!!!!!!!!!!!!!! */

#     if defined(__NR_getxattr)
      case __NR_getxattr: /* syscall 229 */
         /* ssize_t getxattr (const char *path, const char* name,
                              void* value, size_t size); */
         if (!VG_(is_kerror)(res) && res > 0 
                                  && arg3 != (Addr)NULL) {
            make_readable( arg3, res );
         }
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
      if (!VG_(is_kerror)(res) && res == 0 && ctrl && ctrl->len > 0) {
         make_readable( (UInt)ctrl->buf, ctrl->len);
      }
      if (!VG_(is_kerror)(res) && res == 0 && data && data->len > 0) {
         make_readable( (UInt)data->buf, data->len);
      }
      }
      break;
#     endif

      case __NR_getitimer: /* syscall 105 */
         /* int getitimer(int which, struct itimerval *value); */
         if (!VG_(is_kerror)(res) && arg2 != (Addr)NULL) {
            make_readable(arg2, sizeof(struct itimerval));
         }
         break;

#     if defined(__NR_syslog)
      case __NR_syslog: /* syscall 103 */
         /* int syslog(int type, char *bufp, int len); */
         if (!VG_(is_kerror)(res)) {
            switch (arg1) {
               case 2: case 3: case 4:
                  make_readable( arg2, arg3 );
                  break;
               default:
                  break;
            }
         }
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
         if (!VG_(is_kerror)(res)) {
            /* Copied from munmap() wrapper. */
            //Bool munmap_exe;
            Addr start  = arg1;
            Addr length = arg2;
            while ((start % VKI_BYTES_PER_PAGE) > 0) { start--; length++; }
            while (((start+length) % VKI_BYTES_PER_PAGE) > 0) { length++; }
            make_noaccess( start, length );
            //munmap_exe = VG_(symtab_notify_munmap) ( start, length );
            //if (munmap_exe)
            //   VG_(invalidate_translations) ( start, length );
            approximate_mmap_permissions( (Addr)res, arg3, arg4 );
         }
         break;         
#     endif

#     if defined(__NR__sysctl)
      case __NR__sysctl:
      /* int _sysctl(struct __sysctl_args *args); */
         if (!VG_(is_kerror)(res))
            make_readable ( arg1, sizeof(struct __sysctl_args) );
         break;
#     endif

      /* !!!!!!!!!! New, untested syscalls, 8 Mar 02 !!!!!!!!!!! */

#     if defined(__NR_sendfile)
      case __NR_sendfile: /* syscall 187 */
         /* ssize_t sendfile(int out_fd, int in_fd, off_t *offset, 
                             size_t count) */
         if (!VG_(is_kerror)(res) && arg3 != (UInt)NULL) {
            make_readable( arg3, sizeof( off_t ) );
         }
         break;
#     endif

      case __NR_fstatfs: /* syscall 100 */
         /* int fstatfs(int fd, struct statfs *buf); */
         if (!VG_(is_kerror)(res))
            make_readable( arg2, sizeof(struct statfs) );
         break;

#     if defined(__NR_pread)
      case __NR_pread: /* syscall 180 */
         /* ssize_t pread(int fd, void *buf, size_t count, off_t offset); */
         if (!VG_(is_kerror)(res) && res > 0) {
            make_readable( arg2, res );
         }
         break;
#     endif

      case __NR_capget: /* syscall 184 */
         /* int capget(cap_user_header_t header, cap_user_data_t data); */
         if (!VG_(is_kerror)(res) && arg2 != (Addr)NULL)
            make_readable ( arg2, sizeof( vki_cap_user_data_t) );
         break;

      case __NR_brk: /* syscall 45 */
         /* Haven't a clue if this is really right. */
         /* int brk(void *end_data_segment); */
         if (!VG_(is_kerror)(res)) {
            if (arg1 == 0) {
               /* Just asking where the current end is. (???) */
               SK_(curr_dataseg_end) = res;
            } else
            if (arg1 < SK_(curr_dataseg_end)) {
               /* shrinking the data segment. */
               make_noaccess( (Addr)arg1, 
                              SK_(curr_dataseg_end)-arg1 );
               SK_(curr_dataseg_end) = arg1;
            } else
            if (arg1 > SK_(curr_dataseg_end) && res != 0) {
               /* asked for more memory, and got it */
               /* 
               VG_(printf)("BRK: new area %x .. %x\n", 
                           SK_(curr_dataseg_end, arg1-1 );
               */
               make_writable ( (Addr)SK_(curr_dataseg_end), 
                               arg1-SK_(curr_dataseg_end) );

               SK_(curr_dataseg_end) = arg1;         
            }
         }
         break;

      case __NR_fstat: /* syscall 108 */
         /* int fstat(int filedes, struct stat *buf); */
         if (!VG_(is_kerror)(res))
            make_readable( arg2, sizeof(struct stat) );
         break;

      case __NR_getdents: /* syscall 141 */
         /* int getdents(unsigned int fd, struct dirent *dirp, 
                         unsigned int count); */
         if (!VG_(is_kerror)(res) && res > 0)
            make_readable( arg2, res );
         break;

#     if defined(__NR_getdents64)
      case __NR_getdents64: /* syscall 220 */
         /* int getdents(unsigned int fd, struct dirent64 *dirp, 
                         unsigned int count); */
         if (!VG_(is_kerror)(res) && res > 0)
            make_readable( arg2, res );
         break;
#     endif

#     if defined(__NR_getgroups32)
      case __NR_getgroups32: /* syscall 205 */
#     endif
      case __NR_getgroups: /* syscall 80 */
         /* int getgroups(int size, gid_t list[]); */
         if (arg1 > 0 && !VG_(is_kerror)(res) && res > 0)
            make_readable ( arg2, res * sizeof(gid_t) );
         break;

      case __NR_getcwd: /* syscall 183 */
         /* char *getcwd(char *buf, size_t size); */
         if (!VG_(is_kerror)(res) && res != (Addr)NULL)
            make_readable ( arg1, arg2 );
         /* Not really right -- really we should have the asciiz
            string starting at arg1 readable, or up to arg2 bytes,
            whichever finishes first. */
         break;

      case __NR_getresgid: /* syscall 171 */
         /* int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid); */
         if (!VG_(is_kerror)(res) && res == 0) {
            make_readable ( arg1, sizeof(gid_t) );
            make_readable ( arg2, sizeof(gid_t) );
            make_readable ( arg3, sizeof(gid_t) );
         }
         break;

#     if defined(__NR_getresgid32)
      case __NR_getresgid32: /* syscall 211 */
         /* int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid); */
         if (!VG_(is_kerror)(res) && res == 0) {
            make_readable ( arg1, sizeof(gid_t) );
            make_readable ( arg2, sizeof(gid_t) );
            make_readable ( arg3, sizeof(gid_t) );
         }
         break;
#     endif

      case __NR_getresuid: /* syscall 165 */
         /* int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid); */
         if (!VG_(is_kerror)(res) && res == 0) {
            make_readable ( arg1, sizeof(uid_t) );
            make_readable ( arg2, sizeof(uid_t) );
            make_readable ( arg3, sizeof(uid_t) );
         }
         break;

#     if defined(__NR_getresuid32)
      case __NR_getresuid32: /* syscall 209 */
         /* int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid); */
         if (!VG_(is_kerror)(res) && res == 0) {
            make_readable ( arg1, sizeof(uid_t) );
            make_readable ( arg2, sizeof(uid_t) );
            make_readable ( arg3, sizeof(uid_t) );
         }
         break;
#     endif

#     if defined(__NR_ugetrlimit)
      case __NR_ugetrlimit: /* syscall 191 */
#     endif
      case __NR_getrlimit: /* syscall 76 */
         /* int getrlimit (int resource, struct rlimit *rlim); */
         if (!VG_(is_kerror)(res) && res == 0)
            make_readable( arg2, sizeof(struct rlimit) );
         break;

      case __NR_getrusage: /* syscall 77 */
         /* int getrusage (int who, struct rusage *usage); */
         if (!VG_(is_kerror)(res) && res == 0)
            make_readable(arg2, sizeof(struct rusage) );
         break;

      case __NR_gettimeofday: /* syscall 78 */
         /* int gettimeofday(struct timeval *tv, struct timezone *tz); */
         if (!VG_(is_kerror)(res) && res == 0) {
            make_readable( arg1, sizeof(struct timeval) );
            if (arg2 != 0)
               make_readable( arg2, sizeof(struct timezone) );
         }
         break;

      case __NR_ipc: /* syscall 117 */
         /* int ipc ( unsigned int call, int first, int second, 
                      int third, void *ptr, long fifth); */
         switch (arg1 /* call */) {
            case 1: /* IPCOP_semop */
            case 2: /* IPCOP_semget */
            case 3: /* IPCOP_semctl */
            case 11: /* IPCOP_msgsnd */
               break;
            case 12: /* IPCOP_msgrcv */
               // SSS: some overlap
               {
                  struct msgbuf *msgp;
                  msgp = (struct msgbuf *)safe_dereference( 
                            (Addr) (&((struct ipc_kludge *)arg5)->msgp), 0 );

                  if ( !VG_(is_kerror)(res) && res > 0 ) {
                     make_readable ( (UInt)&msgp->mtype, sizeof(msgp->mtype) );
                     make_readable ( (UInt)msgp->mtext, res );
                  }
                  break;
               }
            case 13: /* IPCOP_msgget */
               break;
            case 14: /* IPCOP_msgctl */
               {
                  switch (arg3 /* cmd */) {
                     case IPC_STAT:
                        if ( !VG_(is_kerror)(res) && res > 0 ) {
                           make_readable ( arg5, sizeof(struct msqid_ds) );
                        }
                        break;
                     case IPC_SET:
                        break;
#                    if defined(IPC_64)
                     case IPC_STAT|IPC_64:
                        if ( !VG_(is_kerror)(res) && res > 0 ) {
                           make_readable ( arg5, sizeof(struct msqid64_ds) );
                        }
                        break;
#                    endif
#                    if defined(IPC_64)
                     case IPC_SET|IPC_64:
                        break;
#                    endif
                     default:
                        break;
                  }
                  break;
               }
            case 21: /* IPCOP_shmat */
               {
                  Int shmid = arg2;
                  Int shmflag = arg3;
                  UInt addr;

                  if ( VG_(is_kerror) ( res ) )
                     break;
                  
                  /* force readability. before the syscall it is
                   * indeed uninitialized, as can be seen in
                   * glibc/sysdeps/unix/sysv/linux/shmat.c */
                  make_readable ( arg4, sizeof( ULong ) );

                  addr = safe_dereference ( arg4, 0 );
                  if ( addr > 0 ) { 
                     UInt segmentSize = get_shm_size ( shmid );
                     if ( segmentSize > 0 ) {
                        if ( shmflag & SHM_RDONLY )
                           make_readable ( addr, segmentSize );
                        else
                           make_readwritable ( addr, segmentSize );
                     }
                  }
                  break;
               }
            case 22: /* IPCOP_shmdt */
                  /* ### FIXME: this should call make_noaccess on the
                   * area passed to shmdt. But there's no way to
                   * figure out the size of the shared memory segment
                   * just from the address...  Maybe we want to keep a
                   * copy of the exiting mappings inside valgrind? */
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
                  }
                  if ( arg5 && !VG_(is_kerror)(res) && res == 0 && out_arg )
                          make_readable( arg5, sizeof(struct shmid_ds) );
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
               break; 
            case TCGETS:
               if (!VG_(is_kerror)(res) && res == 0)
                  make_readable ( arg3, VKI_SIZEOF_STRUCT_TERMIOS );
               break;
            case TCSETA:
            case TCSETAW:
            case TCSETAF:
               break;
            case TCGETA:
               if (!VG_(is_kerror)(res) && res == 0)
                  make_readable ( arg3, VKI_SIZEOF_STRUCT_TERMIO );
               break;
            case TCSBRK:
            case TCXONC:
            case TCSBRKP:
            case TCFLSH:
               /* These just take an int by value */
               break;
            case TIOCGWINSZ:
               if (!VG_(is_kerror)(res) && res == 0)
                  make_readable ( arg3, sizeof(struct winsize) );
               break;
            case TIOCSWINSZ:
               break;
            case TIOCGPGRP:
               /* Get process group ID for foreground processing group. */
               if (!VG_(is_kerror)(res) && res == 0)
                  make_readable ( arg3, sizeof(pid_t) );
               break;
            case TIOCSPGRP:
               /* Set a process group ID? */
               if (!VG_(is_kerror)(res) && res == 0)
                  make_readable ( arg3, sizeof(pid_t) );
               break;
            case TIOCGPTN: /* Get Pty Number (of pty-mux device) */
               if (!VG_(is_kerror)(res) && res == 0)
                   make_readable ( arg3, sizeof(int));
               break;
            case TIOCSCTTY:
               /* Just takes an int value.  */
            case TIOCSPTLCK: /* Lock/unlock Pty */
            case FIONBIO:
            case FIOASYNC:
               break;
            case FIONREAD:
               if (!VG_(is_kerror)(res) && res == 0)
                  make_readable( arg3, sizeof(int) );
               break;

            /* If you get compilation problems here, change the #if
               1 to #if 0 and get rid of <scsi/sg.h> in
               vg_unsafe.h. */
#       if 1
            case SG_SET_COMMAND_Q:
               break;
#           if defined(SG_IO)
            case SG_IO:
               if (!VG_(is_kerror)(res) && res == 0)
                  make_readable (arg3, sizeof(struct sg_io_hdr));
               break;
#           endif /* SG_IO */
            case SG_GET_SCSI_ID:
               /* Note: sometimes sg_scsi_id is called sg_scsi_id_t */
               if (!VG_(is_kerror)(res) && res == 0)
                  make_readable (arg3, sizeof(struct sg_scsi_id));
               break;
            case SG_SET_RESERVED_SIZE:
            case SG_SET_TIMEOUT:
               break;
            case SG_GET_RESERVED_SIZE: /* fall thru */
            case SG_GET_TIMEOUT:
               if (!VG_(is_kerror)(res) && res == 0)
                  make_readable (arg3, sizeof(int));
               break;
            case SG_GET_VERSION_NUM:
               break;
#       endif

            case IIOCGETCPS:
               /* In early 2.4 kernels, ISDN_MAX_CHANNELS was only defined
                * when KERNEL was. I never saw a larger value than 64 though */
#              ifndef ISDN_MAX_CHANNELS
#              define ISDN_MAX_CHANNELS 64
#              endif
               if (!VG_(is_kerror)(res) && res == 0)
                  make_readable ( arg3, ISDN_MAX_CHANNELS 
                                        * 2 * sizeof(unsigned long) );
               break;
            case IIOCNETGPN:
               if (!VG_(is_kerror)(res) && res == 0)
                  make_readable ( arg3, sizeof(isdn_net_ioctl_phone) );
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
               if (!VG_(is_kerror)(res) && res == 0)
                  make_readable (arg3, sizeof(struct ifreq));
               break;
            case SIOCGIFCONF:         /* get iface list               */
               /* WAS:
               if (!VG_(is_kerror)(res) && res == 0)
                  make_readable (arg3, sizeof(struct ifconf));
               */
               if (!VG_(is_kerror)(res) && res == 0 && arg3 ) {
                  struct ifconf *ifc = (struct ifconf *) arg3;
                  if (ifc->ifc_buf != NULL)
                     make_readable ( (Addr)(ifc->ifc_buf), 
                                     (UInt)(ifc->ifc_len) );
               }
               break;
            case SIOCGSTAMP:
               if (!VG_(is_kerror)(res) && res == 0)
                  make_readable (arg3, sizeof(struct timeval));
               break;
            case SIOCGRARP:           /* get RARP table entry         */
            case SIOCGARP:            /* get ARP table entry          */
               if (!VG_(is_kerror)(res) && res == 0)
                  make_readable (arg3, sizeof(struct arpreq));
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
            /* Routing table calls.  */
            case SIOCADDRT:           /* add routing table entry      */
            case SIOCDELRT:           /* delete routing table entry   */
               break;

            /* RARP cache control calls. */
            case SIOCDRARP:           /* delete RARP table entry      */
            case SIOCSRARP:           /* set RARP table entry         */
            /* ARP cache control calls. */
            case SIOCSARP:            /* set ARP table entry          */
            case SIOCDARP:            /* delete ARP table entry       */
               break;

            case SIOCSPGRP:
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
               if (!VG_(is_kerror)(res) && res == 0)
                  make_readable (arg3, sizeof(int));
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
               break;
            case SNDCTL_DSP_GETOSPACE:
            case SNDCTL_DSP_GETISPACE:
               if (!VG_(is_kerror)(res) && res == 0)
                  make_readable (arg3, sizeof(audio_buf_info));
               break;
            case SNDCTL_DSP_SETTRIGGER:
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
               if (!VG_(is_kerror) && res == 0)
                  make_readable(arg3, sizeof(struct rtc_time));
               break;
            case RTC_ALM_SET:
               break;
            case RTC_IRQP_READ:
               if(!VG_(is_kerror) && res == 0)
                   make_readable(arg3, sizeof(unsigned long));
               break;
#           endif /* GLIBC_2_1 */

#           ifdef BLKGETSIZE
            case BLKGETSIZE:
               if (!VG_(is_kerror)(res) && res == 0)
                  make_readable (arg3, sizeof(unsigned long));
               break;
#           endif /* BLKGETSIZE */

            /* CD ROM stuff (??)  */
            case CDROMSUBCHNL:
                if (!VG_(is_kerror)(res) && res == 0)
                   make_readable (arg3, sizeof(struct cdrom_subchnl));
                break;
            case CDROMREADTOCHDR:
                if (!VG_(is_kerror)(res) && res == 0)
                   make_readable (arg3, sizeof(struct cdrom_tochdr));
                break;
            case CDROMREADTOCENTRY:
                 if (!VG_(is_kerror)(res) && res == 0)
                    make_readable (arg3, sizeof(struct cdrom_tochdr));
                 break;
            case CDROMPLAYMSF:
                 break;
            /* We don't have any specific information on it, so
               try to do something reasonable based on direction and
               size bits.  The encoding scheme is described in
               /usr/include/asm/ioctl.h.  

               According to Simon Hausmann, _IOC_READ means the kernel
               writes a value to the ioctl value passed from the user
               space and the other way around with _IOC_WRITE. */
            // SSS: some repeated vars
            default: {
               UInt dir  = _IOC_DIR(arg2);
               UInt size = _IOC_SIZE(arg2);
               if (size > 0 && (dir & _IOC_READ)
                   && !VG_(is_kerror)(res) && res == 0
                   && arg3 != (Addr)NULL)
                  make_readable (arg3, size);
               break;
            }
         }
         break;

      case __NR__llseek: /* syscall 140 */
         /* int _llseek(unsigned int fd, unsigned long offset_high,       
                        unsigned long  offset_low, 
                        loff_t * result, unsigned int whence); */
         if (!VG_(is_kerror)(res) && res == 0)
            make_readable( arg4, sizeof(loff_t) );
         break;

      case __NR_lstat: /* syscall 107 */
         /* int lstat(const char *file_name, struct stat *buf); */
         if (!VG_(is_kerror)(res) && res == 0) {
            make_readable( arg2, sizeof(struct stat) );
         }
         break;

#     if defined(__NR_lstat64)
      case __NR_lstat64: /* syscall 196 */
         /* int lstat64(const char *file_name, struct stat64 *buf); */
         if (!VG_(is_kerror)(res) && res == 0) {
            make_readable( arg2, sizeof(struct stat64) );
         }
         break;
#     endif

#     if defined(__NR_mmap2)
      case __NR_mmap2: /* syscall 192 */
         /* My impression is that this is exactly like __NR_mmap 
            except that all 6 args are passed in regs, rather than in 
            a memory-block. */
         /* void* mmap(void *start, size_t length, int prot, 
                       int flags, int fd, off_t offset); */
         if (!VG_(is_kerror)(res))
            approximate_mmap_permissions( (Addr)res, arg2, arg3 );
         break;
#     endif

      case __NR_mmap: /* syscall 90 */
         /* void* mmap(void *start, size_t length, int prot, 
                       int flags, int fd, off_t offset); 
         */
         {
         UInt* arg_block = (UInt*)arg1;
         arg2 = arg_block[1];
         arg3 = arg_block[2];
         if (!VG_(is_kerror)(res))
            approximate_mmap_permissions( (Addr)res, arg2, arg3 );
         }
         break;

      case __NR_mprotect: /* syscall 125 */
         /* int mprotect(const void *addr, size_t len, int prot); */
         if (!VG_(is_kerror)(res))
            approximate_mmap_permissions ( arg1, arg2, arg3 );
         break;

      case __NR_munmap: /* syscall 91 */
         /* int munmap(void *start, size_t length); */
         if (!VG_(is_kerror)(res)) {
            /* Mash around start and length so that the area passed to
               make_noaccess() exactly covers an integral number of
               pages.  If we don't do that, our idea of addressible
               memory diverges from that of the kernel's, which causes
               the leak detector to crash. */
            Addr start = arg1;
            Addr length = arg2;
            while ((start % VKI_BYTES_PER_PAGE) > 0) { start--; length++; }
            while (((start+length) % VKI_BYTES_PER_PAGE) > 0) { length++; }
            make_noaccess( start, length );
         }
         break;

      case __NR_nanosleep: /* syscall 162 */
         /* int nanosleep(const struct timespec *req, struct timespec *rem); */
         /* Somewhat bogus ... is only written by the kernel if
            res == -1 && errno == EINTR. */
         if (!VG_(is_kerror)(res) && arg2 != (UInt)NULL)
            make_readable ( arg2, sizeof(struct timespec) );
         break;

      case __NR_pipe: /* syscall 42 */
         /* int pipe(int filedes[2]); */
         if (!VG_(is_kerror)(res))
            make_readable ( arg1, 2*sizeof(int) );
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
         if (!VG_(is_kerror)(res) && res > 0) {
            Int i;
            struct pollfd * arr = (struct pollfd *)arg1;
            for (i = 0; i < arg2; i++)
               make_readable( (Addr)(&arr[i].revents), sizeof(Short) );
         }
         break;
 
      case __NR_readlink: /* syscall 85 */
         /* int readlink(const char *path, char *buf, size_t bufsiz); */
         if (!VG_(is_kerror)(res) && res > 0) {
            make_readable ( arg2, res );
         }
         break;

      case __NR_readv: { /* syscall 145 */
         /* int readv(int fd, const struct iovec * vector, size_t count); */
         UInt i;
         struct iovec * vec;
         /* ToDo: don't do any of the following if the vector is invalid */
         vec = (struct iovec *)arg2;
         if (!VG_(is_kerror)(res) && res > 0) {
            /* res holds the number of bytes read. */
            for (i = 0; i < arg3; i++) {
               Int nReadThisBuf = vec[i].iov_len;
               if (nReadThisBuf > res) nReadThisBuf = res;
               make_readable( (UInt)vec[i].iov_base, nReadThisBuf );
               res -= nReadThisBuf;
               if (res < 0) VG_(panic)("vg_wrap_syscall: readv: res < 0");
            }
         }
         break;
      }

      case __NR_sched_setparam: /* syscall 154 */
         /* int sched_setparam(pid_t pid, const struct sched_param *p); */
         if (!VG_(is_kerror)(res))
            make_readable( arg2, sizeof(struct sched_param) );
         break;

      case __NR_sched_getparam: /* syscall 155 */
         /* int sched_getparam(pid_t pid, struct sched_param *p); */
         if (!VG_(is_kerror)(res))
            make_readable( arg2, sizeof(struct sched_param) );
         break;

      case __NR_setitimer: /* syscall 104 */
         /* setitimer(int which, const struct itimerval *value,
                                 struct itimerval *ovalue); */
         if (!VG_(is_kerror)(res) && arg3 != (Addr)NULL) {
            make_readable(arg3, sizeof(struct itimerval));
         }
         break;

      case __NR_socketcall: /* syscall 102 */
         /* int socketcall(int call, unsigned long *args); */
         switch (arg1 /* request */) {

            /* All these ones don't need any marking */
            case SYS_SOCKET:
               /* int socket(int domain, int type, int protocol); */
            case SYS_BIND:
               /* int bind(int sockfd, struct sockaddr *my_addr, 
                           int addrlen); */
            case SYS_LISTEN:
               /* int listen(int s, int backlog); */
            case SYS_SENDTO:
               /* int sendto(int s, const void *msg, int len, 
                             unsigned int flags, 
                             const struct sockaddr *to, int tolen); */
            case SYS_SEND:
               /* int send(int s, const void *msg, size_t len, int flags); */
            case SYS_CONNECT:
               /* int connect(int sockfd, 
                              struct sockaddr *serv_addr, int addrlen ); */
            case SYS_SETSOCKOPT:
               /* int setsockopt(int s, int level, int optname, 
                                 const void *optval, int optlen); */
            case SYS_SHUTDOWN:
               /* int shutdown(int s, int how); */
            case SYS_SENDMSG:
               /* int sendmsg(int s, const struct msghdr *msg, int flags); */

               /* all fall through to here */
               break;


            case SYS_SOCKETPAIR:
               /* int socketpair(int d, int type, int protocol, int sv[2]); */
               if (!VG_(is_kerror)(res))
                  make_readable ( ((UInt*)arg2)[3], 2*sizeof(int) );
               break;

            case SYS_ACCEPT: {
               /* int accept(int s, struct sockaddr *addr, int *p_addrlen); */
               Addr addr;
               Addr p_addrlen;
               UInt addrlen_out;
               addr      = ((UInt*)arg2)[1];
               p_addrlen = ((UInt*)arg2)[2];
               if (!VG_(is_kerror)(res) && res >= 0 && p_addrlen != (Addr)NULL) {
                  addrlen_out = safe_dereference( p_addrlen, 0 );
                  if (addrlen_out > 0)
                     make_readable( addr, addrlen_out );
               }
               break;
            }

            case SYS_RECVFROM:
               /* int recvfrom(int s, void *buf, int len, unsigned int flags,
                               struct sockaddr *from, int *fromlen); */
               if (!VG_(is_kerror)(res) && res >= 0) {
                  make_readable( ((UInt*)arg2)[1], /* buf */
                                 ((UInt*)arg2)[2]  /* len */ );
                  if ( ((UInt*)arg2)[4] /* from */ != 0) {
                     make_readable( 
                        ((UInt*)arg2)[4], /*from*/
                        safe_dereference( (Addr) ((UInt*)arg2)[5], 0 ) );
                  }
               }
               /* phew! */
               break;

            case SYS_RECV:
               /* int recv(int s, void *buf, int len, unsigned int flags); */
               /* man 2 recv says:
               The  recv call is normally used only on a connected socket
               (see connect(2)) and is identical to recvfrom with a  NULL
               from parameter.
               */
               if (!VG_(is_kerror)(res) && res >= 0 
                                   && ((UInt*)arg2)[1] != (UInt)NULL) {
                  make_readable( ((UInt*)arg2)[1], /* buf */
                                 ((UInt*)arg2)[2]  /* len */ );
               }
               break;

               // SSS: reusing values from before the call...
            case SYS_GETSOCKOPT:
               /* int setsockopt(int s, int level, int optname, 
                                 void *optval, socklen_t *optlen); */
               {
               Addr optval_p = ((UInt*)arg2)[3];
               Addr optlen_p = ((UInt*)arg2)[4];
               UInt optlen_after;
               UInt optlen = safe_dereference ( optlen_p, 0 );
               optlen_after = safe_dereference ( optlen_p, 0 );
               if (!VG_(is_kerror)(res) && optlen > 0 && optlen_after > 0) 
                  make_readable( optval_p, optlen_after );
               }
               break;

            case SYS_GETSOCKNAME:
               /* int getsockname(int s, struct sockaddr* name, 
                                  int* namelen) */
               if (!VG_(is_kerror)(res)) {
                  UInt namelen = safe_dereference( (Addr) ((UInt*)arg2)[2], 0);
                  if (namelen > 0 
                      && ((UInt*)arg2)[1] != (UInt)NULL)
                     make_readable( ((UInt*)arg2)[1], namelen );
               }
               break;

            case SYS_GETPEERNAME:
               /* int getpeername(int s, struct sockaddr* name, 
                                  int* namelen) */
               if (!VG_(is_kerror)(res)) {
                  UInt namelen = safe_dereference( (Addr) ((UInt*)arg2)[2], 0);
                  if (namelen > 0 
                      && ((UInt*)arg2)[1] != (UInt)NULL)
                     make_readable( ((UInt*)arg2)[1], namelen );
               }
               break;

            case SYS_RECVMSG:
               /* int recvmsg(int s, struct msghdr *msg, int flags); */
               {
               struct msghdr *msg = (struct msghdr *)((UInt *)arg2)[ 1 ];
               if ( !VG_(is_kerror)( res ) )
                  VG_(msghdr_foreachfield)( tst, msg, make_readable_recvmsg );
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
         if (!VG_(is_kerror)(res))
            make_readable( arg2, sizeof(struct stat) );
         break;

      case __NR_statfs: /* syscall 99 */
         /* int statfs(const char *path, struct statfs *buf); */
         if (!VG_(is_kerror)(res))
            make_readable( arg2, sizeof(struct statfs) );
         break;

#     if defined(__NR_stat64)
      case __NR_stat64: /* syscall 195 */
         /* int stat64(const char *file_name, struct stat64 *buf); */
         if (!VG_(is_kerror)(res))
            make_readable( arg2, sizeof(struct stat64) );
         break;
#     endif

#     if defined(__NR_fstat64)
      case __NR_fstat64: /* syscall 197 */
         /* int fstat64(int filedes, struct stat64 *buf); */
         if (!VG_(is_kerror)(res))
            make_readable( arg2, sizeof(struct stat64) );
         break;
#     endif

      case __NR_sysinfo: /* syscall 116 */
         /* int sysinfo(struct sysinfo *info); */
         if (!VG_(is_kerror)(res))
            make_readable( arg1, sizeof(struct sysinfo) );
         break;

      case __NR_time: /* syscall 13 */
         /* time_t time(time_t *t); */
         if (!VG_(is_kerror)(res) && arg1 != (UInt)NULL) {
            make_readable( arg1, sizeof(time_t) );
         }
         break;

      case __NR_times: /* syscall 43 */
         /* clock_t times(struct tms *buf); */
         if (!VG_(is_kerror)(res) && arg1 != (UInt)NULL) {
            make_readable( arg1, sizeof(struct tms) );
         }
         break;

      case __NR_uname: /* syscall 122 */
         /* int uname(struct utsname *buf); */
         if (!VG_(is_kerror)(res) && arg1 != (UInt)NULL) {
            make_readable( arg1, sizeof(struct utsname) );
         }
         break;

      case __NR_wait4: /* syscall 114 */
         /* pid_t wait4(pid_t pid, int *status, int options,
                        struct rusage *rusage) */
         if (!VG_(is_kerror)(res)) {
            if (arg2 != (Addr)NULL)
               make_readable( arg2, sizeof(int) );
            if (arg4 != (Addr)NULL)
               make_readable( arg4, sizeof(struct rusage) );
         }
         break;
      }

      /*-------------------------- SIGNALS --------------------------*/

      /* Normally set to 1, so that Valgrind's signal-simulation machinery
         is engaged.  Sometimes useful to disable (set to 0), for
         debugging purposes, to make clients more deterministic. */
#     define SIGNAL_SIMULATION 1

      case __NR_sigaltstack: /* syscall 186 */
         /* int sigaltstack(const stack_t *ss, stack_t *oss); */
         if (!VG_(is_kerror)(res) && res == 0 && arg2 != (UInt)NULL)
            make_readable( arg2, sizeof(vki_kstack_t));
         break;

      case __NR_rt_sigaction:
      case __NR_sigaction:
         /* int sigaction(int signum, struct k_sigaction *act, 
                                      struct k_sigaction *oldact); */
         if (!VG_(is_kerror)(res) && res == 0 && arg3 != (UInt)NULL)
            make_readable( arg3, sizeof(vki_ksigaction));
         break;

      case __NR_rt_sigprocmask:
      case __NR_sigprocmask:
         /* int sigprocmask(int how, k_sigset_t *set, 
                                     k_sigset_t *oldset); */
         if (!VG_(is_kerror)(res) && res == 0 && arg3 != (UInt)NULL)
            make_readable( arg3, sizeof(vki_ksigset_t));
         break;

      case __NR_sigpending: /* syscall 73 */
#     if defined(__NR_rt_sigpending)
      case __NR_rt_sigpending: /* syscall 176 */
#     endif
         /* int sigpending( sigset_t *set ) ; */
         if ( !VG_( is_kerror )( res ) && res == 0 )
            make_readable( arg1, sizeof( vki_ksigset_t ) ) ;
         break ;

      default:
         VG_(message)
            (Vg_DebugMsg,"FATAL: unhandled (post)syscall: %d",syscallno);
         VG_(message)
            (Vg_DebugMsg,"Do not panic.  You may be able to fix this easily.");
         VG_(message)
            (Vg_DebugMsg,"Read the file README_MISSING_SYSCALL_OR_IOCTL.");
         VG_(unimplemented)("no wrapper for the above system call");
         vg_assert(3+3 == 7);
         break; /*NOTREACHED*/
   }

   /* { void zzzmemscan(void); zzzmemscan(); } */

   sane_after_call = SKN_(cheap_sanity_check)();

   if ((Int)sane_before_call && (!sane_after_call)) {
      VG_(message)(Vg_DebugMsg, "post_syscall: ");
      VG_(message)(Vg_DebugMsg,
                   "probable sanity check failure for syscall number %d\n", 
                   syscallno );
      VG_(panic)("aborting due to the above ... bye!"); 
   }
   VGP_POPCC;
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
void SKN_(post_blocking_syscall_check) ( ThreadId tid,
                                        Int syscallno,
                                        Int* /*IN*/ res,
                                        void* sane_before_post )
{
   ThreadState* tst;
   Bool         sane_after_post;
   UInt         arg1, arg2, arg3;

   VGP_PUSHCC(VgpSyscall);

   vg_assert(VG_(is_valid_tid)(tid));
   sane_after_post  = True;
   tst              = & VG_(threads)[tid];
   arg1             = tst->m_ebx;
   arg2             = tst->m_ecx;
   arg3             = tst->m_edx;
   /*
   arg4             = tst->m_esi;
   arg5             = tst->m_edi;
   */

   /* See vg_syscalls_mem.c:VG_(perform_assumed_nonblocking_syscall)()
    * for details on arguments and return values.
   */

   switch (syscallno) {

      case __NR_read: /* syscall 3 */
         /* size_t read(int fd, void *buf, size_t count); */
         if (res == NULL) { 
            /* PRE */
         } else {
            /* POST */
            if (!VG_(is_kerror)(*res) && *res > 0) {
               make_readable( arg2, *res );
            }
	 }
         break;

      case __NR_write: /* syscall 4 */
         /* size_t write(int fd, const void *buf, size_t count); */
         if (res == NULL) {
            /* PRE */
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

   if (res != NULL) { /* only check after syscall */
      if (! SKN_(cheap_sanity_check)())
         sane_after_post = False;

      if ((Int)sane_before_post && (!sane_after_post)) {
         VG_(message)(Vg_DebugMsg, "post_blocking_syscall_check: ");
         VG_(message)(Vg_DebugMsg,
                      "probable sanity check failure for syscall number %d\n", 
                      syscallno );
         VG_(panic)("aborting due to the above ... bye!"); 
      }
   }

   VGP_POPCC;
}

