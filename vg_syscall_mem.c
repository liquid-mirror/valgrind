
/*--------------------------------------------------------------------*/
/*--- Update the byte permission maps following a system call.     ---*/
/*---                                             vg_syscall_mem.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, an x86 protected-mode emulator 
   designed for debugging and profiling binaries on x86-Unixes.

   Copyright (C) 2000-2002 Julian Seward 
      jseward@acm.org

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file LICENSE.
*/

#include "vg_include.h"

/* vg_unsafe.h should NOT be included into any file except this
   one. */
#include "vg_unsafe.h"


// SSS: update this comment
/* All system calls are channelled through vg_wrap_syscall.  It does
   three things:

   * optionally, checks the permissions for the args to the call

   * perform the syscall, usually by passing it along to the kernel
     unmodified.  However, because we simulate signals ourselves,
     signal-related syscalls are routed to vg_signal.c, and are not
     delivered to the kernel.

   * Update the permission maps following the syscall.

   A magical piece of assembly code, vg_do_syscall(), in vg_syscall.S
   does the tricky bit of passing a syscall to the kernel, whilst
   having the simulator retain control.
*/

/* Is this a Linux kernel error return value? */
/* From:
   http://sources.redhat.com/cgi-bin/cvsweb.cgi/libc/sysdeps/unix/sysv/
   linux/i386/sysdep.h?
   rev=1.28&content-type=text/x-cvsweb-markup&cvsroot=glibc

   QUOTE:

   Linux uses a negative return value to indicate syscall errors,
   unlike most Unices, which use the condition codes' carry flag.

   Since version 2.1 the return value of a system call might be
   negative even if the call succeeded.  E.g., the `lseek' system call
   might return a large offset.  Therefore we must not anymore test
   for < 0, but test for a real error by making sure the value in %eax
   is a real error number.  Linus said he will make sure the no syscall
   returns a value in -1 .. -4095 as a valid result so we can savely
   test with -4095.  

   END QUOTE
*/
Bool VG_(is_kerror) ( Int res )
{
   if (res >= -4095 && res <= -1)
      return True;
   else
      return False;
}


/* The Main Entertainment ... */

void VG_(perform_assumed_nonblocking_syscall) ( ThreadId tid )
{
   ThreadState* tst;
   UInt         syscallno, arg1, arg2, arg3, arg4, arg5;
   /* Do not make this unsigned! */
   Int res        = 0;  // shut gcc up
   Int pre_result = 0;  // shut gcc up

   VGP_PUSHCC(VgpSyscall);

   vg_assert(VG_(is_valid_tid)(tid));
   tst       = & VG_(threads)[tid];
   syscallno = tst->m_eax;
   arg1      = tst->m_ebx;
   arg2      = tst->m_ecx;
   arg3      = tst->m_edx;
   arg4      = tst->m_esi;
   arg5      = tst->m_edi;

   /* Do any pre-syscall checking */
   if (VG_(needs).wrap_syscalls) {
      pre_result = (Int)SKN_(pre_syscall)(tid);
   }

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

/* Use GNU macro varargs... the ## handles the case where there are no args */
#define MAYBE_PRINTF(format, args...)  \
   if (VG_(clo_trace_syscalls))        \
      VG_(printf)(format, ## args)

#define M_PRINTF_CALL_BREAK(format, args...)  \
   MAYBE_PRINTF(format, ## args);             \
   KERNEL_DO_SYSCALL(tid,res);                \
   break

   MAYBE_PRINTF("SYSCALL[%d,%d](%3d): ", VG_(getpid)(), tid, syscallno);

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

      /* !!!!!!!!!! New, untested syscalls !!!!!!!!!!!!!!!!!!!!! */

#     if defined(__NR_getxattr)
      case __NR_getxattr: /* syscall 229 */
         /* ssize_t getxattr (const char *path, const char* name,
                              void* value, size_t size); */
         M_PRINTF_CALL_BREAK("getxattr ( %p, %p, %p, %d )\n", 
                             arg1,arg2,arg3, arg4);
#     endif
      
#     if defined(__NR_quotactl)
      case __NR_quotactl: /* syscall 131 */
         /* int quotactl(int cmd, char *special, int uid, caddr_t addr); */
         M_PRINTF_CALL_BREAK("quotactl (0x%x, %p, 0x%x, 0x%x )\n", 
                             arg1,arg2,arg3, arg4);
#     endif

#     if defined(__NR_truncate64)
      case __NR_truncate64: /* syscall 193 */
         /* int truncate64(const char *path, off64_t length); */
         M_PRINTF_CALL_BREAK("truncate64 ( %p, %lld )\n",
                             arg1, ((ULong)arg2) | (((ULong) arg3) << 32));
#     endif

#     if defined(__NR_fdatasync)
      case __NR_fdatasync: /* syscall 148 */
         /* int fdatasync(int fd); */
         M_PRINTF_CALL_BREAK("fdatasync ( %d )\n", arg1);
#     endif

#     if defined(__NR_msync) /* syscall 144 */
      case __NR_msync:
         /* int msync(const void *start, size_t length, int flags); */
         M_PRINTF_CALL_BREAK("msync ( %p, %d, %d )\n", arg1,arg2,arg3);
#     endif

         // SSS: are the args trashed across the call?
#     if defined(__NR_getpmsg) /* syscall 188 */
      case __NR_getpmsg: 
         /* LiS getpmsg from http://www.gcom.com/home/linux/lis/ */
         /* int getpmsg(int fd, struct strbuf *ctrl, struct strbuf *data, 
                                int *bandp, int *flagsp); */
         M_PRINTF_CALL_BREAK("getpmsg ( %d, %p, %p, %p, %p )\n",
                             arg1,arg2,arg3,arg4,arg5);
#     endif


#     if defined(__NR_putpmsg) /* syscall 189 */
      case __NR_putpmsg: 
         /* LiS putpmsg from http://www.gcom.com/home/linux/lis/ */
         /* int putpmsg(int fd, struct strbuf *ctrl, struct strbuf *data, 
                                int band, int flags); */
         M_PRINTF_CALL_BREAK("putpmsg ( %d, %p, %p, %d, %d )\n",
                             arg1,arg2,arg3,arg4,arg5);
#     endif

      case __NR_getitimer: /* syscall 105 */
         /* int getitimer(int which, struct itimerval *value); */
         M_PRINTF_CALL_BREAK("getitimer ( %d, %p )\n", arg1, arg2);

#     if defined(__NR_syslog)
      case __NR_syslog: /* syscall 103 */
         /* int syslog(int type, char *bufp, int len); */
         M_PRINTF_CALL_BREAK("syslog (%d, %p, %d)\n",arg1,arg2,arg3);
#     endif

      case __NR_personality: /* syscall 136 */
         /* int personality(unsigned long persona); */
         M_PRINTF_CALL_BREAK("personality ( %d )\n", arg1);

      case __NR_chroot: /* syscall 61 */
         /* int chroot(const char *path); */
         M_PRINTF_CALL_BREAK("chroot ( %p )\n", arg1);

#     if defined(__NR_madvise)
      case __NR_madvise: /* syscall 219 */
         /* int madvise(void *start, size_t length, int advice ); */
         M_PRINTF_CALL_BREAK("madvise ( %p, %d, %d )\n", arg1,arg2,arg3);
#     endif

#     if defined(__NR_mremap)
      // SSS: shared code...
      /* Is this really right?  Perhaps it should copy the permissions
         from the old area into the new.  Unclear from the Linux man
         pages what this really does.  Also, the flags don't look like
         they mean the same as the standard mmap flags, so that's
         probably wrong too. */
      case __NR_mremap: /* syscall 163 */
         /* void* mremap(void * old_address, size_t old_size, 
                         size_t new_size, unsigned long flags); */
         MAYBE_PRINTF("mremap ( %p, %d, %d, 0x%x )\n", 
                        arg1, arg2, arg3, arg4);
         KERNEL_DO_SYSCALL(tid,res);
         if (!VG_(is_kerror)(res)) {
            /* Copied from munmap() wrapper. */
            Bool munmap_exe;
            Addr start  = arg1;
            Addr length = arg2;
            while ((start % VKI_BYTES_PER_PAGE) > 0) { start--; length++; }
            while (((start+length) % VKI_BYTES_PER_PAGE) > 0) { length++; }
            munmap_exe = VG_(symtab_notify_munmap) ( start, length );
            if (munmap_exe)
               VG_(invalidate_translations) ( start, length );
         }
         break;         
#     endif

      case __NR_nice: /* syscall 34 */
         /* int nice(int inc); */
         M_PRINTF_CALL_BREAK("nice ( %d )\n", arg1);

      /* !!!!!!!!!! New, untested syscalls, 14 Mar 02 !!!!!!!!!! */

#     if defined(__NR_setresgid32)
      case __NR_setresgid32: /* syscall 210 */
         /* int setresgid(gid_t rgid, gid_t egid, gid_t sgid); */
         M_PRINTF_CALL_BREAK("setresgid32 ( %d, %d, %d )\n", arg1, arg2, arg3);
#     endif

#     if defined(__NR_setfsuid32)
      case __NR_setfsuid32: /* syscall 215 */
         /* int setfsuid(uid_t fsuid); */
          M_PRINTF_CALL_BREAK("setfsuid ( %d )\n", arg1);
#     endif

#     if defined(__NR__sysctl)
      case __NR__sysctl:
      /* int _sysctl(struct __sysctl_args *args); */
         M_PRINTF_CALL_BREAK("_sysctl ( %p )\n", arg1 );
#     endif

#     if defined(__NR_sched_getscheduler)
      case __NR_sched_getscheduler:
         /* int sched_getscheduler(pid_t pid); */
         M_PRINTF_CALL_BREAK("sched_getscheduler ( %d )\n", arg1);
#     endif

#     if defined(__NR_sched_setscheduler)
      case __NR_sched_setscheduler:
         /* int sched_setscheduler(pid_t pid, int policy, 
                const struct sched_param *p); */
         M_PRINTF_CALL_BREAK("sched_setscheduler ( %d, %d, %p )\n",
                             arg1,arg2,arg3);
#     endif

#     if defined(__NR_mlock)
      case __NR_mlock:
         /* int mlock(const void * addr, size_t len) */
         M_PRINTF_CALL_BREAK("mlock ( %p, %d )\n", arg1, arg2);
#     endif

#     if defined(__NR_mlockall)
      case __NR_mlockall:
         /* int mlockall(int flags); */
         M_PRINTF_CALL_BREAK("mlockall ( %x )\n", arg1);
#     endif

#     if defined(__NR_munlockall)
      case __NR_munlockall:
         /* int munlockall(void); */
         M_PRINTF_CALL_BREAK("munlockall ( )\n");
#     endif

#if   defined(__NR_sched_get_priority_max)
      case __NR_sched_get_priority_max:
         /* int sched_get_priority_max(int policy); */
         M_PRINTF_CALL_BREAK("sched_get_priority_max ( %d )\n", arg1);
#     endif

#if   defined(__NR_sched_get_priority_min)
      case __NR_sched_get_priority_min: /* syscall 160 */
         /* int sched_get_priority_min(int policy); */
         M_PRINTF_CALL_BREAK("sched_get_priority_min ( %d )\n", arg1);
#     endif

#if   defined(__NR_setpriority)
      case __NR_setpriority: /* syscall 97 */
         /* int setpriority(int which, int who, int prio); */
         M_PRINTF_CALL_BREAK("setpriority ( %d, %d, %d )\n", arg1, arg2, arg3);
#     endif

#if   defined(__NR_getpriority)
      case __NR_getpriority: /* syscall 96 */
         /* int getpriority(int which, int who); */
         M_PRINTF_CALL_BREAK("getpriority ( %d, %d )\n", arg1, arg2);
#     endif

#     if defined(__NR_setfsgid)
      case __NR_setfsgid: /* syscall 139 */
         /* int setfsgid(gid_t gid); */
         M_PRINTF_CALL_BREAK("setfsgid ( %d )\n", arg1);
#     endif

#     if defined(__NR_setregid)
      case __NR_setregid: /* syscall 71 */
         /* int setregid(gid_t rgid, gid_t egid); */
         M_PRINTF_CALL_BREAK("setregid ( %d, %d )\n", arg1, arg2);
#     endif

#     if defined(__NR_setresuid)
      case __NR_setresuid: /* syscall 164 */
         /* int setresuid(uid_t ruid, uid_t euid, uid_t suid); */
         M_PRINTF_CALL_BREAK("setresuid ( %d, %d, %d )\n", arg1, arg2, arg3);
#     endif

#     if defined(__NR_setfsuid)
      case __NR_setfsuid: /* syscall 138 */
         /* int setfsuid(uid_t uid); */
         M_PRINTF_CALL_BREAK("setfsuid ( %d )\n", arg1);
#     endif

      /* !!!!!!!!!! New, untested syscalls, 8 Mar 02 !!!!!!!!!!! */

#     if defined(__NR_sendfile)
      case __NR_sendfile: /* syscall 187 */
         /* ssize_t sendfile(int out_fd, int in_fd, off_t *offset, 
                             size_t count) */
         M_PRINTF_CALL_BREAK("sendfile ( %d, %d, %p, %d )\n",
                             arg1,arg2,arg3,arg4);
#     endif

      /* !!!!!!!!!! New, untested syscalls, 7 Mar 02 !!!!!!!!!!! */

#     if defined(__NR_pwrite)
      case __NR_pwrite: /* syscall 181 */
         /* ssize_t pwrite (int fd, const void *buf, size_t nbytes,
                            off_t offset); */
         M_PRINTF_CALL_BREAK("pwrite ( %d, %p, %d, %d )\n",
                             arg1,arg2,arg3,arg4);
#     endif

      /* !!!!!!!!!! New, untested syscalls, 6 Mar 02 !!!!!!!!!!! */

      case __NR_sync: /* syscall 36 */
         /* int sync(); */
         M_PRINTF_CALL_BREAK("sync ( )\n");
 
      case __NR_fstatfs: /* syscall 100 */
         /* int fstatfs(int fd, struct statfs *buf); */
         M_PRINTF_CALL_BREAK("fstatfs ( %d, %p )\n",arg1,arg2);

      /* !!!!!!!!!! New, untested syscalls, 4 Mar 02 !!!!!!!!!!! */

      case __NR_pause: /* syscall 29 */
         /* int pause(void); */
         M_PRINTF_CALL_BREAK("pause ( )\n");

      case __NR_getsid: /* syscall 147 */
         /* pid_t getsid(pid_t pid); */
         M_PRINTF_CALL_BREAK("getsid ( %d )\n", arg1);

#     if defined(__NR_pread)
      case __NR_pread: /* syscall 180 */
         /* ssize_t pread(int fd, void *buf, size_t count, off_t offset); */
         MAYBE_PRINTF("pread ( %d, %p, %d, %d ) ...\n",arg1,arg2,arg3,arg4);
         KERNEL_DO_SYSCALL(tid,res);
         MAYBE_PRINTF("SYSCALL[%d]       pread ( %d, %p, %d, %d ) --> %d\n",
                        VG_(getpid)(),
                        arg1, arg2, arg3, arg4, res);
         break;
#     endif

      /* !!!!!!!!!! New, untested syscalls, 27 Feb 02 !!!!!!!!!! */

      case __NR_mknod: /* syscall 14 */
         /* int mknod(const char *pathname, mode_t mode, dev_t dev); */
         M_PRINTF_CALL_BREAK("mknod ( %p, 0x%x, 0x%x )\n", arg1, arg2, arg3 );

      case __NR_flock: /* syscall 143 */
         /* int flock(int fd, int operation); */
         M_PRINTF_CALL_BREAK("flock ( %d, %d )\n", arg1, arg2 );

#     if defined(__NR_rt_sigsuspend)
      /* Viewed with great suspicion by me, but, hey, let's do it
         anyway ... */
      case __NR_rt_sigsuspend: /* syscall 179 */
         /* int sigsuspend(const sigset_t *mask); */
         M_PRINTF_CALL_BREAK("sigsuspend ( %p )\n", arg1 );
#     endif

      case __NR_init_module: /* syscall 128 */
         /* int init_module(const char *name, struct module *image); */
         M_PRINTF_CALL_BREAK("init_module ( %p, %p )\n", arg1, arg2 );

      case __NR_ioperm: /* syscall 101 */
         /* int ioperm(unsigned long from, unsigned long num, int turn_on); */
         M_PRINTF_CALL_BREAK("ioperm ( %d, %d, %d )\n", arg1, arg2, arg3 );

      case __NR_capget: /* syscall 184 */
         /* int capget(cap_user_header_t header, cap_user_data_t data); */
         M_PRINTF_CALL_BREAK("capget ( %p, %p )\n", arg1, arg2 );

      /* !!!!!!!!!!!!!!!!!!!!! mutant ones !!!!!!!!!!!!!!!!!!!!! */

      case __NR_execve:
         /* int execve (const char *filename, 
                        char *const argv [], 
                        char *const envp[]); */
         MAYBE_PRINTF("execve ( %p(%s), %p, %p ) --- NOT CHECKED\n", 
                        arg1, arg1, arg2, arg3);
         /* Resistance is futile.  Nuke all other threads.  POSIX
            mandates this. */
            VG_(nuke_all_threads_except)( tid );
         /* Make any binding for LD_PRELOAD disappear, so that child
            processes don't get traced into. */
         if (!VG_(clo_trace_children)) {
            Int i;
            Char** envp = (Char**)arg3;
            Char*  ld_preload_str = NULL;
            Char*  ld_library_path_str = NULL;
            for (i = 0; envp[i] != NULL; i++) {
               if (VG_(strncmp)(envp[i], "LD_PRELOAD=", 11) == 0)
                  ld_preload_str = &envp[i][11];
               if (VG_(strncmp)(envp[i], "LD_LIBRARY_PATH=", 16) == 0)
                  ld_library_path_str = &envp[i][16];
            }
            VG_(mash_LD_PRELOAD_and_LD_LIBRARY_PATH)(
	       ld_preload_str, ld_library_path_str );
         }
         KERNEL_DO_SYSCALL(tid,res);
         /* Should we still be alive here?  Don't think so. */
         /* Actually, above comment is wrong.  execve can fail, just
            like any other syscall -- typically the file to exec does
            not exist.  Hence: */
         vg_assert(VG_(is_kerror)(res));
         break;

      /* !!!!!!!!!!!!!!!!!!!!!     end     !!!!!!!!!!!!!!!!!!!!! */

      case __NR_access: /* syscall 33 */
         /* int access(const char *pathname, int mode); */
         M_PRINTF_CALL_BREAK("access ( %p, %d )\n", arg1,arg2);

      case __NR_alarm: /* syscall 27 */
         /* unsigned int alarm(unsigned int seconds); */
         M_PRINTF_CALL_BREAK("alarm ( %d )\n", arg1);

         // SSS: not completely certain about this...
      case __NR_brk: /* syscall 45 */
         /* Haven't a clue if this is really right. */
         /* int brk(void *end_data_segment); */
         MAYBE_PRINTF("brk ( %p ) --> ",arg1);
         KERNEL_DO_SYSCALL(tid,res);
         MAYBE_PRINTF("0x%x\n", res);
         break;

      case __NR_chdir: /* syscall 12 */
         /* int chdir(const char *path); */
         M_PRINTF_CALL_BREAK("chdir ( %p )\n", arg1);

      case __NR_chmod: /* syscall 15 */
         /* int chmod(const char *path, mode_t mode); */
         M_PRINTF_CALL_BREAK("chmod ( %p, %d )\n", arg1,arg2);

#     if defined(__NR_chown32)
      case __NR_chown32: /* syscall 212 */
#     endif
#     if defined(__NR_lchown32)
      case __NR_lchown32: /* syscall 198 */
#     endif
      case __NR_chown: /* syscall 16 */
         /* int chown(const char *path, uid_t owner, gid_t group); */
         M_PRINTF_CALL_BREAK("chown ( %p, 0x%x, 0x%x )\n", arg1,arg2,arg3);

      case __NR_close: /* syscall 6 */
         /* int close(int fd); */
         MAYBE_PRINTF("close ( %d )\n",arg1);
         /* Detect and negate attempts by the client to close Valgrind's
            logfile fd ... */
         if (arg1 == VG_(clo_logfile_fd)) {
            VG_(message)(Vg_UserMsg, 
              "Warning: client attempted to close "
               "Valgrind's logfile fd (%d).", 
               VG_(clo_logfile_fd));
            VG_(message)(Vg_UserMsg, 
              "   Use --logfile-fd=<number> to select an "
              "alternative logfile fd." );
         } else {
            KERNEL_DO_SYSCALL(tid,res);
         }
         break;

      case __NR_dup: /* syscall 41 */
         /* int dup(int oldfd); */
         MAYBE_PRINTF("dup ( %d ) --> ", arg1);
         KERNEL_DO_SYSCALL(tid,res);
         MAYBE_PRINTF("%d\n", res);
         break;

      case __NR_dup2: /* syscall 63 */
         /* int dup2(int oldfd, int newfd); */
         MAYBE_PRINTF("dup2 ( %d, %d ) ...\n", arg1,arg2);
         KERNEL_DO_SYSCALL(tid,res);
         MAYBE_PRINTF("SYSCALL[%d]       dup2 ( %d, %d ) = %d\n", 
                        VG_(getpid)(), 
                        arg1, arg2, res);
         break;

      case __NR_fcntl: /* syscall 55 */
         /* int fcntl(int fd, int cmd, int arg); */
         M_PRINTF_CALL_BREAK("fcntl ( %d, %d, %d )\n",arg1,arg2,arg3);

      case __NR_fchdir: /* syscall 133 */
         /* int fchdir(int fd); */
         M_PRINTF_CALL_BREAK("fchdir ( %d )\n", arg1);

#     if defined(__NR_fchown32)
      case __NR_fchown32: /* syscall 207 */
#     endif
      case __NR_fchown: /* syscall 95 */
         /* int fchown(int filedes, uid_t owner, gid_t group); */
         M_PRINTF_CALL_BREAK("fchown ( %d, %d, %d )\n", arg1,arg2,arg3);

      case __NR_fchmod: /* syscall 94 */
         /* int fchmod(int fildes, mode_t mode); */
         M_PRINTF_CALL_BREAK("fchmod ( %d, %d )\n", arg1,arg2);

#     if defined(__NR_fcntl64)
      case __NR_fcntl64: /* syscall 221 */
         /* I don't know what the prototype for this is supposed to be. */
         /* ??? int fcntl(int fd, int cmd); */
         M_PRINTF_CALL_BREAK("fcntl64 (?!) ( %d, %d )\n", arg1,arg2);
#     endif

      case __NR_fstat: /* syscall 108 */
         /* int fstat(int filedes, struct stat *buf); */
         M_PRINTF_CALL_BREAK("fstat ( %d, %p )\n",arg1,arg2);

      case __NR_vfork: /* syscall 190 */
         /* pid_t vfork(void); */
         MAYBE_PRINTF("vfork ( ) ... becomes ... ");
         /* KLUDGE: we prefer to do a fork rather than vfork. 
            vfork gives a SIGSEGV, and the stated semantics looks
            pretty much impossible for us. */
         tst->m_eax = __NR_fork;
         /* fall through ... */
      case __NR_fork: /* syscall 2 */
         /* pid_t fork(void); */
         MAYBE_PRINTF("fork ()\n");
         KERNEL_DO_SYSCALL(tid,res);
         if (res == 0) {
            /* I am the child.  Nuke all other threads which I might
               have inherited from my parent.  POSIX mandates this. */
            VG_(nuke_all_threads_except)( tid );
         }
         break;

      case __NR_fsync: /* syscall 118 */
         /* int fsync(int fd); */
         M_PRINTF_CALL_BREAK("fsync ( %d )\n", arg1);

      case __NR_ftruncate: /* syscall 93 */
         /* int ftruncate(int fd, size_t length); */
         M_PRINTF_CALL_BREAK("ftruncate ( %d, %d )\n", arg1,arg2);

#     if defined(__NR_ftruncate64)
      case __NR_ftruncate64: /* syscall 194 */
         /* int ftruncate64(int fd, off64_t length); */
         M_PRINTF_CALL_BREAK("ftruncate64 ( %d, %lld )\n", 
                             arg1,arg2|((long long) arg3 << 32));
#     endif

      case __NR_getdents: /* syscall 141 */
         /* int getdents(unsigned int fd, struct dirent *dirp, 
                         unsigned int count); */
         M_PRINTF_CALL_BREAK("getdents ( %d, %p, %d )\n",arg1,arg2,arg3);

#     if defined(__NR_getdents64)
      case __NR_getdents64: /* syscall 220 */
         /* int getdents(unsigned int fd, struct dirent64 *dirp, 
                         unsigned int count); */
         M_PRINTF_CALL_BREAK("getdents64 ( %d, %p, %d )\n",arg1,arg2,arg3);
#     endif

#     if defined(__NR_getgroups32)
      case __NR_getgroups32: /* syscall 205 */
#     endif
      case __NR_getgroups: /* syscall 80 */
         /* int getgroups(int size, gid_t list[]); */
         M_PRINTF_CALL_BREAK("getgroups ( %d, %p )\n", arg1, arg2);

      case __NR_getcwd: /* syscall 183 */
         /* char *getcwd(char *buf, size_t size); */
         M_PRINTF_CALL_BREAK("getcwd ( %p, %d )\n",arg1,arg2);

      case __NR_geteuid: /* syscall 49 */
         /* uid_t geteuid(void); */
         M_PRINTF_CALL_BREAK("geteuid ( )\n");

#     if defined(__NR_geteuid32)
      case __NR_geteuid32: /* syscall 201 */
         /* ?? uid_t geteuid32(void); */
         M_PRINTF_CALL_BREAK("geteuid32(?) ( )\n");
#     endif

      case __NR_getegid: /* syscall 50 */
         /* gid_t getegid(void); */
         M_PRINTF_CALL_BREAK("getegid ()\n");

#     if defined(__NR_getegid32)
      case __NR_getegid32: /* syscall 202 */
         /* gid_t getegid32(void); */
         M_PRINTF_CALL_BREAK("getegid32 ()\n");
#     endif

      case __NR_getgid: /* syscall 47 */
         /* gid_t getgid(void); */
         M_PRINTF_CALL_BREAK("getgid ()\n");

#     if defined(__NR_getgid32)
      case __NR_getgid32: /* syscall 200 */
         /* gid_t getgid32(void); */
         M_PRINTF_CALL_BREAK("getgid32 ()\n");
#     endif

      case __NR_getpid: /* syscall 20 */
         /* pid_t getpid(void); */
         M_PRINTF_CALL_BREAK("getpid ()\n");

      case __NR_getpgid: /* syscall 132 */
         /* pid_t getpgid(pid_t pid); */
         M_PRINTF_CALL_BREAK("getpgid ( %d )\n", arg1);

      case __NR_getpgrp: /* syscall 65 */
         /* pid_t getpprp(void); */
         M_PRINTF_CALL_BREAK("getpgrp ()\n");

      case __NR_getppid: /* syscall 64 */
         /* pid_t getppid(void); */
         M_PRINTF_CALL_BREAK("getppid ()\n");

      case __NR_getresgid: /* syscall 171 */
         /* int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid); */
         M_PRINTF_CALL_BREAK("getresgid ( %p, %p, %p )\n", arg1,arg2,arg3);

#     if defined(__NR_getresgid32)
      case __NR_getresgid32: /* syscall 211 */
         /* int getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid); */
         M_PRINTF_CALL_BREAK("getresgid32 ( %p, %p, %p )\n", arg1,arg2,arg3);
#     endif

      case __NR_getresuid: /* syscall 165 */
         /* int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid); */
         M_PRINTF_CALL_BREAK("getresuid ( %p, %p, %p )\n", arg1,arg2,arg3);

#     if defined(__NR_getresuid32)
      case __NR_getresuid32: /* syscall 209 */
         /* int getresuid(uid_t *ruid, uid_t *euid, uid_t *suid); */
         M_PRINTF_CALL_BREAK("getresuid32 ( %p, %p, %p )\n", arg1,arg2,arg3);
#     endif

#     if defined(__NR_ugetrlimit)
      case __NR_ugetrlimit: /* syscall 191 */
#     endif
      case __NR_getrlimit: /* syscall 76 */
         /* int getrlimit (int resource, struct rlimit *rlim); */
         M_PRINTF_CALL_BREAK("getrlimit ( %d, %p )\n", arg1,arg2);

      case __NR_getrusage: /* syscall 77 */
         /* int getrusage (int who, struct rusage *usage); */
         M_PRINTF_CALL_BREAK("getrusage ( %d, %p )\n", arg1,arg2);

      case __NR_gettimeofday: /* syscall 78 */
         /* int gettimeofday(struct timeval *tv, struct timezone *tz); */
         M_PRINTF_CALL_BREAK("gettimeofday ( %p, %p )\n",arg1,arg2);

      case __NR_getuid: /* syscall 24 */
         /* uid_t getuid(void); */
         M_PRINTF_CALL_BREAK("getuid ( )\n");

#     if defined(__NR_getuid32)
      case __NR_getuid32: /* syscall 199 */
         /* ???uid_t getuid32(void); */
         M_PRINTF_CALL_BREAK("getuid32 ( )\n");
#     endif

      case __NR_ipc: /* syscall 117 */
         /* int ipc ( unsigned int call, int first, int second, 
                      int third, void *ptr, long fifth); */
         {
         UInt arg6 = tst->m_ebp;

         MAYBE_PRINTF("ipc ( %d, %d, %d, %d, %p, %d )\n",
                        arg1,arg2,arg3,arg4,arg5,arg6);
         switch (arg1 /* call */) {
            case 1:  /* IPCOP_semop  */
            case 2:  /* IPCOP_semget */
            case 3:  /* IPCOP_semctl */
            case 11: /* IPCOP_msgsnd */
            case 12: /* IPCOP_msgrcv */
            case 13: /* IPCOP_msgget */
            case 14: /* IPCOP_msgctl */
            case 21: /* IPCOP_shmat  */
            case 22: /* IPCOP_shmdt  */
            case 23: /* IPCOP_shmget */
            case 24: /* IPCOP_shmctl */
               KERNEL_DO_SYSCALL(tid,res);
               break;
               // SSS: distinguish the three error messages
            default:
               VG_(message)(Vg_DebugMsg,
                            "FATAL: unhandled syscall(ipc) %d",
                            arg1 );
               VG_(panic)("... bye!\n");
               break; /*NOTREACHED*/
         }
         }
         break;

      case __NR_ioctl: /* syscall 54 */
         /* int ioctl(int d, int request, ...)
            [The  "third"  argument  is traditionally char *argp, 
             and will be so named for this discussion.]
         */
         /*
         VG_(message)(
            Vg_DebugMsg, 
            "is an IOCTL,  request = 0x%x,   d = %d,   argp = 0x%x", 
            arg2,arg1,arg3);
         */
         /* We don't care what type it was here... just do it. */
         M_PRINTF_CALL_BREAK("ioctl ( %d, 0x%x, %p )\n",arg1,arg2,arg3);

      case __NR_kill: /* syscall 37 */
         /* int kill(pid_t pid, int sig); */
         M_PRINTF_CALL_BREAK("kill ( %d, %d )\n", arg1,arg2);

      case __NR_link: /* syscall 9 */
         /* int link(const char *oldpath, const char *newpath); */
         M_PRINTF_CALL_BREAK("link ( %p, %p)\n", arg1, arg2);

      case __NR_lseek: /* syscall 19 */
         /* off_t lseek(int fildes, off_t offset, int whence); */
         M_PRINTF_CALL_BREAK("lseek ( %d, %d, %d )\n",arg1,arg2,arg3);

      case __NR__llseek: /* syscall 140 */
         /* int _llseek(unsigned int fd, unsigned long offset_high,       
                        unsigned long  offset_low, 
                        loff_t * result, unsigned int whence); */
         M_PRINTF_CALL_BREAK("llseek ( %d, 0x%x, 0x%x, %p, %d )\n",
                        arg1,arg2,arg3,arg4,arg5);

      case __NR_lstat: /* syscall 107 */
         /* int lstat(const char *file_name, struct stat *buf); */
         M_PRINTF_CALL_BREAK("lstat ( %p, %p )\n",arg1,arg2);

#     if defined(__NR_lstat64)
      case __NR_lstat64: /* syscall 196 */
         /* int lstat64(const char *file_name, struct stat64 *buf); */
         M_PRINTF_CALL_BREAK("lstat64 ( %p, %p )\n",arg1,arg2);
#     endif

      case __NR_mkdir: /* syscall 39 */
         /* int mkdir(const char *pathname, mode_t mode); */
         M_PRINTF_CALL_BREAK("mkdir ( %p, %d )\n", arg1,arg2);

#     if defined(__NR_mmap2)
      case __NR_mmap2: /* syscall 192 */
         /* My impression is that this is exactly like __NR_mmap 
            except that all 6 args are passed in regs, rather than in 
            a memory-block. */
         /* void* mmap(void *start, size_t length, int prot, 
                       int flags, int fd, off_t offset); 
         */
         {
         UInt arg6 = tst->m_ebp;
         MAYBE_PRINTF("mmap2 ( %p, %d, %d, %d, %d, %d )\n",
                        arg1, arg2, arg3, arg4, arg5, arg6 );
         KERNEL_DO_SYSCALL(tid,res);
         // SSS: need to do this if VG_(needs).debug_info not set?
         if (!VG_(is_kerror)(res)
             && (arg3 & PROT_EXEC)) {
            /* The client mmap'ed a segment with executable
               permissions.  Tell the symbol-table loader, so that it
               has an opportunity to pick up more symbols if this mmap
               was caused by the client loading a new .so via
               dlopen().  This is important for debugging KDE. */
            VG_(read_symbols)();
         }
         }
         break;
#     endif

         // SSS: ditched arg_block_readable... maybe need a way of passing
         // args between the pre/call/post syscall handlers...
      case __NR_mmap: /* syscall 90 */
         /* void* mmap(void *start, size_t length, int prot, 
                       int flags, int fd, off_t offset); */
         if (VG_(clo_trace_syscalls)) {
            UInt* arg_block = (UInt*)arg1;
            UInt arg6;
            arg1 = arg_block[0];
            arg2 = arg_block[1];
            arg3 = arg_block[2];
            arg4 = arg_block[3];
            arg5 = arg_block[4];
            arg6 = arg_block[5];
            VG_(printf)("mmap ( %p, %d, %d, %d, %d, %d )\n",
                        arg1, arg2, arg3, arg4, arg5, arg6 );
         }
         KERNEL_DO_SYSCALL(tid,res);
         // SSS: as for mmap2
         if (!VG_(is_kerror)(res) && (arg3 & PROT_EXEC)) {
            /* The client mmap'ed a segment with executable
               permissions.  Tell the symbol-table loader, so that it
               has an opportunity to pick up more symbols if this mmap
               was caused by the client loading a new .so via
               dlopen().  This is important for debugging KDE. */
            VG_(read_symbols)();
         }
         break;

      case __NR_mprotect: /* syscall 125 */
         /* int mprotect(const void *addr, size_t len, int prot); */
         M_PRINTF_CALL_BREAK("mprotect ( %p, %d, %d )\n", arg1,arg2,arg3);

      case __NR_munmap: /* syscall 91 */
         /* int munmap(void *start, size_t length); */
         MAYBE_PRINTF("munmap ( %p, %d )\n", arg1,arg2);
         KERNEL_DO_SYSCALL(tid,res);
         if (!VG_(is_kerror)(res)) {
            /* Mash around start and length so that the area passed to
               make_noaccess() exactly covers an integral number of
               pages.  If we don't do that, our idea of addressible
               memory diverges from that of the kernel's, which causes
               the leak detector to crash. */
            Bool munmap_exe;
            Addr start = arg1;
            Addr length = arg2;
            while ((start % VKI_BYTES_PER_PAGE) > 0) { start--; length++; }
            while (((start+length) % VKI_BYTES_PER_PAGE) > 0) { length++; }
            /*
            VG_(printf)("MUNMAP: correct (%p for %d) to (%p for %d) %s\n", 
               arg1, arg2, start, length, (arg1!=start || arg2!=length) 
                                             ? "CHANGE" : "");
            */
            /* Tell our symbol table machinery about this, so that if
               this happens to be a .so being unloaded, the relevant
               symbols are removed too. */
            munmap_exe = VG_(symtab_notify_munmap) ( start, length );
            if (munmap_exe)
               VG_(invalidate_translations) ( start, length );
         }
         break;

      case __NR_nanosleep: /* syscall 162 */
         /* int nanosleep(const struct timespec *req, struct timespec *rem); */
         M_PRINTF_CALL_BREAK("nanosleep ( %p, %p )\n", arg1,arg2);

      case __NR__newselect: /* syscall 142 */
         /* int select(int n,  
                       fd_set *readfds, fd_set *writefds, fd_set *exceptfds, 
                       struct timeval *timeout);
         */
         M_PRINTF_CALL_BREAK("newselect ( %d, %p, %p, %p, %p )\n",
                        arg1,arg2,arg3,arg4,arg5);
         
      case __NR_open: /* syscall 5 */
         /* int open(const char *pathname, int flags); */
         M_PRINTF_CALL_BREAK("open ( %p(%s), %d ) --> ",arg1,arg1,arg2);

      case __NR_pipe: /* syscall 42 */
         /* int pipe(int filedes[2]); */
         MAYBE_PRINTF("pipe ( %p ) ...\n", arg1);
         KERNEL_DO_SYSCALL(tid,res);
         if (!VG_(is_kerror)(res))
            MAYBE_PRINTF("SYSCALL[%d]       pipe --> (rd %d, wr %d)\n", 
                        VG_(getpid)(), 
                        ((UInt*)arg1)[0], ((UInt*)arg1)[1] );
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
         M_PRINTF_CALL_BREAK("poll ( %p, %d, %d )\n",arg1,arg2,arg3);
 
      case __NR_readlink: /* syscall 85 */
         /* int readlink(const char *path, char *buf, size_t bufsiz); */
         M_PRINTF_CALL_BREAK("readlink ( %p, %p, %d )\n", arg1,arg2,arg3);

      case __NR_readv: { /* syscall 145 */
         /* int readv(int fd, const struct iovec * vector, size_t count); */
         M_PRINTF_CALL_BREAK("readv ( %d, %p, %d )\n",arg1,arg2,arg3);
      }

      case __NR_rename: /* syscall 38 */
         /* int rename(const char *oldpath, const char *newpath); */
         M_PRINTF_CALL_BREAK("rename ( %p, %p )\n", arg1, arg2 );

      case __NR_rmdir: /* syscall 40 */
         /* int rmdir(const char *pathname); */
         M_PRINTF_CALL_BREAK("rmdir ( %p )\n", arg1);

      case __NR_sched_setparam: /* syscall 154 */
         /* int sched_setparam(pid_t pid, const struct sched_param *p); */
         M_PRINTF_CALL_BREAK("sched_setparam ( %d, %p )\n", arg1, arg2 );

      case __NR_sched_getparam: /* syscall 155 */
         /* int sched_getparam(pid_t pid, struct sched_param *p); */
         M_PRINTF_CALL_BREAK("sched_getparam ( %d, %p )\n", arg1, arg2 );

      case __NR_sched_yield: /* syscall 158 */
         /* int sched_yield(void); */
         M_PRINTF_CALL_BREAK("sched_yield ()\n" );

         // SSS: ditched arg_block_readable
      case __NR_select: /* syscall 82 */
         /* struct sel_arg_struct {
              unsigned long n;
              fd_set *inp, *outp, *exp;
              struct timeval *tvp;
            };
            int old_select(struct sel_arg_struct *arg);
         */
         if (VG_(clo_trace_syscalls)) {
            UInt* arg_struct = (UInt*)arg1;
            arg1 = arg_struct[0];
            arg2 = arg_struct[1];
            arg3 = arg_struct[2];
            arg4 = arg_struct[3];
            arg5 = arg_struct[4];
            VG_(printf)("select ( %d, %p, %p, %p, %p )\n", 
                        arg1,arg2,arg3,arg4,arg5);
         }
         KERNEL_DO_SYSCALL(tid,res);
         break;

      case __NR_setitimer: /* syscall 104 */
         /* setitimer(int which, const struct itimerval *value,
                                 struct itimerval *ovalue); */
         M_PRINTF_CALL_BREAK("setitimer ( %d, %p, %p )\n", arg1,arg2,arg3);

#     if defined(__NR_setfsgid32)
      case __NR_setfsgid32: /* syscall 216 */
         /* int setfsgid(uid_t fsgid); */
         M_PRINTF_CALL_BREAK("setfsgid ( %d )\n", arg1);
#     endif

#     if defined(__NR_setgid32)
      case __NR_setgid32: /* syscall 214 */
#     endif
      case __NR_setgid: /* syscall 46 */
         /* int setgid(gid_t gid); */
         M_PRINTF_CALL_BREAK("setgid ( %d )\n", arg1);

      case __NR_setsid: /* syscall 66 */
         /* pid_t setsid(void); */
         M_PRINTF_CALL_BREAK("setsid ()\n");

#     if defined(__NR_setgroups32)
      case __NR_setgroups32: /* syscall 206 */
#     endif
      case __NR_setgroups: /* syscall 81 */
         /* int setgroups(size_t size, const gid_t *list); */
         M_PRINTF_CALL_BREAK("setgroups ( %d, %p )\n", arg1, arg2);

      case __NR_setpgid: /* syscall 57 */
         /* int setpgid(pid_t pid, pid_t pgid); */
         M_PRINTF_CALL_BREAK("setpgid ( %d, %d )\n", arg1, arg2);

#     if defined(__NR_setregid32)
      case __NR_setregid32: /* syscall 204 */
         /* int setregid(gid_t rgid, gid_t egid); */
         M_PRINTF_CALL_BREAK("setregid32(?) ( %d, %d )\n", arg1, arg2);
#     endif

#     if defined(__NR_setresuid32)
      case __NR_setresuid32: /* syscall 208 */
         /* int setresuid(uid_t ruid, uid_t euid, uid_t suid); */
         M_PRINTF_CALL_BREAK("setresuid32(?) ( %d, %d, %d )\n", 
                             arg1, arg2, arg3);
#     endif

#     if defined(__NR_setreuid32)
      case __NR_setreuid32: /* syscall 203 */
#     endif
      case __NR_setreuid: /* syscall 70 */
         /* int setreuid(uid_t ruid, uid_t euid); */
         M_PRINTF_CALL_BREAK("setreuid ( 0x%x, 0x%x )\n", arg1, arg2);

      case __NR_setrlimit: /* syscall 75 */
         /* int setrlimit (int resource, const struct rlimit *rlim); */
         M_PRINTF_CALL_BREAK("setrlimit ( %d, %p )\n", arg1,arg2);

#     if defined(__NR_setuid32)
      case __NR_setuid32: /* syscall 213 */
#     endif
      case __NR_setuid: /* syscall 23 */
         /* int setuid(uid_t uid); */
         M_PRINTF_CALL_BREAK("setuid ( %d )\n", arg1);

      case __NR_socketcall: /* syscall 102 */
         /* int socketcall(int call, unsigned long *args); */
         MAYBE_PRINTF("socketcall ( %d, %p )\n",arg1,arg2);
         switch (arg1 /* request */) {

            case SYS_SOCKETPAIR:
            case SYS_SOCKET:
            case SYS_BIND:
            case SYS_LISTEN:
            case SYS_ACCEPT:
            case SYS_SENDTO:
            case SYS_SEND:
            case SYS_RECVFROM:
            case SYS_RECV:
            case SYS_CONNECT:
            case SYS_SETSOCKOPT:
            case SYS_GETSOCKOPT:
            case SYS_GETSOCKNAME:
            case SYS_GETPEERNAME:
            case SYS_SHUTDOWN:
            case SYS_SENDMSG:
            case SYS_RECVMSG:
               KERNEL_DO_SYSCALL(tid,res);
               break;

               // SSS: distinguish the three error messages
            default:
               VG_(message)(Vg_DebugMsg,"FATAL: unhandled socketcall 0x%x",arg1);
               VG_(panic)("... bye!\n");
               break; /*NOTREACHED*/
         }
         break;

      case __NR_stat: /* syscall 106 */
         /* int stat(const char *file_name, struct stat *buf); */
         M_PRINTF_CALL_BREAK("stat ( %p, %p )\n",arg1,arg2);

      case __NR_statfs: /* syscall 99 */
         /* int statfs(const char *path, struct statfs *buf); */
         M_PRINTF_CALL_BREAK("statfs ( %p, %p )\n",arg1,arg2);

      case __NR_symlink: /* syscall 83 */
         /* int symlink(const char *oldpath, const char *newpath); */
         M_PRINTF_CALL_BREAK("symlink ( %p, %p )\n",arg1,arg2);

#     if defined(__NR_stat64)
      case __NR_stat64: /* syscall 195 */
         /* int stat64(const char *file_name, struct stat64 *buf); */
         M_PRINTF_CALL_BREAK("stat64 ( %p, %p )\n",arg1,arg2);
#     endif

#     if defined(__NR_fstat64)
      case __NR_fstat64: /* syscall 197 */
         /* int fstat64(int filedes, struct stat64 *buf); */
         M_PRINTF_CALL_BREAK("fstat64 ( %d, %p )\n",arg1,arg2);
#     endif

      case __NR_sysinfo: /* syscall 116 */
         /* int sysinfo(struct sysinfo *info); */
         M_PRINTF_CALL_BREAK("sysinfo ( %p )\n",arg1);

      case __NR_time: /* syscall 13 */
         /* time_t time(time_t *t); */
         M_PRINTF_CALL_BREAK("time ( %p )\n",arg1);

      case __NR_times: /* syscall 43 */
         /* clock_t times(struct tms *buf); */
         M_PRINTF_CALL_BREAK("times ( %p )\n",arg1);

      case __NR_truncate: /* syscall 92 */
         /* int truncate(const char *path, size_t length); */
         M_PRINTF_CALL_BREAK("truncate ( %p, %d )\n", arg1,arg2);

      case __NR_umask: /* syscall 60 */
         /* mode_t umask(mode_t mask); */
         M_PRINTF_CALL_BREAK("umask ( %d )\n", arg1);

      case __NR_unlink: /* syscall 10 */
         /* int unlink(const char *pathname) */
         M_PRINTF_CALL_BREAK("ulink ( %p )\n",arg1);

      case __NR_uname: /* syscall 122 */
         /* int uname(struct utsname *buf); */
         M_PRINTF_CALL_BREAK("uname ( %p )\n",arg1);

      case __NR_utime: /* syscall 30 */
         /* int utime(const char *filename, struct utimbuf *buf); */
         M_PRINTF_CALL_BREAK("utime ( %p, %p )\n", arg1,arg2);

      case __NR_wait4: /* syscall 114 */
         /* pid_t wait4(pid_t pid, int *status, int options,
                        struct rusage *rusage) */
         M_PRINTF_CALL_BREAK("wait4 ( %d, %p, %d, %p )\n",
                      arg1,arg2,arg3,arg4);

      case __NR_writev: { /* syscall 146 */
         /* int writev(int fd, const struct iovec * vector, size_t count); */
         M_PRINTF_CALL_BREAK("writev ( %d, %p, %d )\n",arg1,arg2,arg3);
      }

      /*-------------------------- SIGNALS --------------------------*/

      /* Normally set to 1, so that Valgrind's signal-simulation machinery
         is engaged.  Sometimes useful to disable (set to 0), for
         debugging purposes, to make clients more deterministic. */
#     define SIGNAL_SIMULATION 1

      case __NR_sigaltstack: /* syscall 186 */
         /* int sigaltstack(const stack_t *ss, stack_t *oss); */
         MAYBE_PRINTF("sigaltstack ( %p, %p )\n",arg1,arg2);
#        if SIGNAL_SIMULATION
         VG_(do__NR_sigaltstack) (tid);
         res = tst->m_eax;
#        else
         KERNEL_DO_SYSCALL(tid,res);
#        endif
         break;

      case __NR_rt_sigaction:
      case __NR_sigaction:
         /* int sigaction(int signum, struct k_sigaction *act, 
                                      struct k_sigaction *oldact); */
         MAYBE_PRINTF("sigaction ( %d, %p, %p )\n",arg1,arg2,arg3);
         /* We do this one ourselves! */
#        if SIGNAL_SIMULATION
         VG_(do__NR_sigaction)(tid);
         res = tst->m_eax;
#        else
         /* debugging signals; when we don't handle them. */
         KERNEL_DO_SYSCALL(tid,res);
#        endif
         break;

      case __NR_rt_sigprocmask:
      case __NR_sigprocmask:
         /* int sigprocmask(int how, k_sigset_t *set, 
                                     k_sigset_t *oldset); */
         MAYBE_PRINTF("sigprocmask ( %d, %p, %p )\n",arg1,arg2,arg3);
#        if SIGNAL_SIMULATION
         VG_(do__NR_sigprocmask) ( tid, 
                                   arg1 /*how*/, 
                                   (vki_ksigset_t*) arg2,
                                   (vki_ksigset_t*) arg3 );
         res = tst->m_eax;
#        else
         KERNEL_DO_SYSCALL(tid,res);
#        endif
         break;

      case __NR_sigpending: /* syscall 73 */
#     if defined(__NR_rt_sigpending)
      case __NR_rt_sigpending: /* syscall 176 */
#     endif
         /* int sigpending( sigset_t *set ) ; */
         MAYBE_PRINTF( "sigpending ( %p )\n", arg1 );
#        if SIGNAL_SIMULATION
         VG_(do_sigpending)( tid, (vki_ksigset_t*)arg1 );
         res = 0;
	 SET_EAX(tid, res);
#        else
         KERNEL_DO_SYSCALL(tid,res);
#        endif
         break ;

         // SSS: need to distinguish the three error messages, pre/call/post!
      default:
         VG_(message)
            (Vg_DebugMsg,"FATAL: unhandled syscall: %d",syscallno);
         VG_(message)
            (Vg_DebugMsg,"Do not panic.  You may be able to fix this easily.");
         VG_(message)
            (Vg_DebugMsg,"Read the file README_MISSING_SYSCALL_OR_IOCTL.");
         VG_(unimplemented)("no wrapper for the above system call");
         vg_assert(3+3 == 7);
         break; /*NOTREACHED*/
   }

   /* { void zzzmemscan(void); zzzmemscan(); } */

   // SSS: must free pre_result if it was malloc'd by pre_syscall()!!
   /* Do any post-syscall checking or updating */
   if (VG_(needs).wrap_syscalls) {
      SKN_(post_syscall)(tid, syscallno, (void*)pre_result, res);
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
void VG_(check_known_blocking_syscall) ( ThreadId tid,
                                         Int syscallno,
                                         Int* /*IN*/ res )
{
   ThreadState* tst;
   Bool         sane_before_post, sane_after_post;
   UInt         arg1, arg2, arg3;
   Int          pre_result = 0;  /* shut gcc up */

   VGP_PUSHCC(VgpSyscall);

   vg_assert(VG_(is_valid_tid)(tid));
   sane_before_post = True;
   sane_after_post  = True;
   tst              = & VG_(threads)[tid];
   arg1             = tst->m_ebx;
   arg2             = tst->m_ecx;
   arg3             = tst->m_edx;
   /*
   arg4             = tst->m_esi;
   arg5             = tst->m_edi;
   */

   if (VG_(needs).wrap_syscalls) {
      pre_result = (Int)SKN_(pre_blocking_syscall_check)(tid, syscallno, res);
   }

   switch (syscallno) {

      case __NR_read: /* syscall 3 */
         /* size_t read(int fd, void *buf, size_t count); */
         if (res == NULL) { 
            /* PRE */
            MAYBE_PRINTF(
                  "SYSCALL--PRE[%d,%d]       read ( %d, %p, %d )\n", 
                  VG_(getpid)(), tid,
                  arg1, arg2, arg3);
         } else {
            /* POST */
            MAYBE_PRINTF(
                  "SYSCALL-POST[%d,%d]       read ( %d, %p, %d ) --> %d\n", 
                  VG_(getpid)(), tid,
                  arg1, arg2, arg3, *res);
	 }
         break;

      case __NR_write: /* syscall 4 */
         /* size_t write(int fd, const void *buf, size_t count); */
         if (res == NULL) {
            /* PRE */
            MAYBE_PRINTF(
                  "SYSCALL--PRE[%d,%d]       write ( %d, %p, %d )\n", 
                  VG_(getpid)(), tid,
                  arg1, arg2, arg3);
	 } else {
            /* POST */
            MAYBE_PRINTF(
                  "SYSCALL-POST[%d,%d]       write ( %d, %p, %d ) --> %d\n", 
                  VG_(getpid)(), tid,
                  arg1, arg2, arg3, *res);
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

   if (VG_(needs).wrap_syscalls) {
      SKN_(post_blocking_syscall_check)(tid, syscallno, 
                                        res, (void*)pre_result);
   }
}

#undef MAYBE_PRINTF

/*--------------------------------------------------------------------*/
/*--- end                                         vg_syscall_mem.c ---*/
/*--------------------------------------------------------------------*/
