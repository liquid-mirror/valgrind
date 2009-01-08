
/*--------------------------------------------------------------------*/
/*--- System call numbers for Darwin.          vki-scnums-darwin.h ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2007-2008 Apple Inc.
      Greg Parker  gparker@apple.com

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

   The GNU General Public License is contained in the file COPYING.
*/

#ifndef __VKI_SCNUMS_DARWIN_H
#define __VKI_SCNUMS_DARWIN_H


// osfmk/mach/i386/syscall_sw.h

// x86_64's syscall numbering system is used for all architectures. 
// Don't pass __NR_something directly to any syscall instruction.
// Hack: x86 `int $0x80` (unix, 64-bit result) are special.

#define SYSCALL_CLASS_SHIFT     24
#define SYSCALL_CLASS_MASK      (0xFF << SYSCALL_CLASS_SHIFT)
#define SYSCALL_NUMBER_MASK     (~SYSCALL_CLASS_MASK)

#define SYSCALL_CLASS_NONE      0       /* Invalid */
#define SYSCALL_CLASS_MACH      1       /* Mach */      
#define SYSCALL_CLASS_UNIX      2       /* Unix/BSD */
#define SYSCALL_CLASS_MDEP      3       /* Machine-dependent */
#define SYSCALL_CLASS_DIAG      4       /* Diagnostics */
#define SYSCALL_CLASS_UX64      99      /* hack: x86 `int $0x80` */

#define SYSCALL_CONSTRUCT_MACH(syscall_number) \
    ((SYSCALL_CLASS_MACH << SYSCALL_CLASS_SHIFT) | \
     (SYSCALL_NUMBER_MASK & (syscall_number)))
#define SYSCALL_CONSTRUCT_UNIX(syscall_number) \
    ((SYSCALL_CLASS_UNIX << SYSCALL_CLASS_SHIFT) | \
     (SYSCALL_NUMBER_MASK & (syscall_number)))
#define SYSCALL_CONSTRUCT_MDEP(syscall_number) \
    ((SYSCALL_CLASS_MDEP << SYSCALL_CLASS_SHIFT) | \
     (SYSCALL_NUMBER_MASK & (syscall_number)))
#define SYSCALL_CONSTRUCT_DIAG(syscall_number) \
    ((SYSCALL_CLASS_DIAG << SYSCALL_CLASS_SHIFT) | \
     (SYSCALL_NUMBER_MASK & (syscall_number)))

#if defined(VGA_x86)
#define SYSCALL_CONSTRUCT_UX64(syscall_number) \
    ((SYSCALL_CLASS_UX64 << SYSCALL_CLASS_SHIFT) | \
     (SYSCALL_NUMBER_MASK & (syscall_number)))
#else
#define SYSCALL_CONSTRUCT_UX64(syscall_number) \
    ((SYSCALL_CLASS_UNIX/*not a typo*/ << SYSCALL_CLASS_SHIFT) | \
     (SYSCALL_NUMBER_MASK & (syscall_number)))
#endif

#define sysno_index(sysno) ((sysno) & SYSCALL_NUMBER_MASK)
#define sysno_class(sysno) ((sysno) >> SYSCALL_CLASS_SHIFT)

#define sysno_print(sysno) \
    ((sysno_class(sysno) == SYSCALL_CLASS_MACH) ? -sysno_index(sysno) : sysno_index(sysno))

#if defined(VGA_x86)
#define sysno_num(sysno) sysno_print(sysno)
#elif defined(VGA_amd64)
#define sysno_num(sysno) (sysno)
#else
#error unknown arch
#endif


// mdep syscalls

#if defined(VGA_x86)

// osfmk/i386/machdep_call.c
// #  define __NR_thread_get_cthread_self SYSCALL_CONSTRUCT_MDEP(0)
// #  define __NR_thread_set_cthread_self SYSCALL_CONSTRUCT_MDEP(1)
// #  define __NR_2 SYSCALL_CONSTRUCT_MDEP(2)
#  define __NR_pthread_set_self SYSCALL_CONSTRUCT_MDEP(3)
// #  define __NR_thread_set_user_ldt SYSCALL_CONSTRUCT_MDEP(4)
// #  define __NR_i386_set_ldt SYSCALL_CONSTRUCT_MDEP(5)
// #  define __NR_i386_get_ldt SYSCALL_CONSTRUCT_MDEP(6)

#elif defined(VGA_amd64)

// osfmk/i386/machdep_call.c
#  define __NR_pthread_set_self SYSCALL_CONSTRUCT_MDEP(3)

#else
#  error unknown architecture
#endif


// osfmk/mach/syscall_sw.h

#define __NR_mach_reply_port                  SYSCALL_CONSTRUCT_MACH(26)
#define __NR_thread_self_trap                 SYSCALL_CONSTRUCT_MACH(27)
#define __NR_task_self_trap                   SYSCALL_CONSTRUCT_MACH(28)
#define __NR_host_self_trap                   SYSCALL_CONSTRUCT_MACH(29)

#define __NR_mach_msg_trap                    SYSCALL_CONSTRUCT_MACH(31)
#define __NR_mach_msg_overwrite_trap          SYSCALL_CONSTRUCT_MACH(32)
#define __NR_semaphore_signal_trap            SYSCALL_CONSTRUCT_MACH(33)
#define __NR_semaphore_signal_all_trap        SYSCALL_CONSTRUCT_MACH(34)
#define __NR_semaphore_signal_thread_trap     SYSCALL_CONSTRUCT_MACH(35)
#define __NR_semaphore_wait_trap              SYSCALL_CONSTRUCT_MACH(36)
#define __NR_semaphore_wait_signal_trap       SYSCALL_CONSTRUCT_MACH(37)
#define __NR_semaphore_timedwait_trap         SYSCALL_CONSTRUCT_MACH(38)
#define __NR_semaphore_timedwait_signal_trap  SYSCALL_CONSTRUCT_MACH(39)

#if defined(VGA_x86)
#define __NR_init_process                     SYSCALL_CONSTRUCT_MACH(41)
#define __NR_map_fd                           SYSCALL_CONSTRUCT_MACH(43)
#endif

#define __NR_task_name_for_pid                SYSCALL_CONSTRUCT_MACH(44)
#define __NR_task_for_pid                     SYSCALL_CONSTRUCT_MACH(45)
#define __NR_pid_for_task                     SYSCALL_CONSTRUCT_MACH(46)

#if defined(VGA_x86)
#define __NR_macx_swapon                      SYSCALL_CONSTRUCT_MACH(48)
#define __NR_macx_swapoff                     SYSCALL_CONSTRUCT_MACH(49)
#define __NR_macx_triggers                    SYSCALL_CONSTRUCT_MACH(51)
#define __NR_macx_backing_store_suspend       SYSCALL_CONSTRUCT_MACH(52)
#define __NR_macx_backing_store_recovery      SYSCALL_CONSTRUCT_MACH(53)
#endif

#define __NR_swtch_pri                        SYSCALL_CONSTRUCT_MACH(59)
#define __NR_swtch                            SYSCALL_CONSTRUCT_MACH(60)
#define __NR_sched_yield  __NR_swtch  /* linux-alike name */
#define __NR_syscall_thread_switch            SYSCALL_CONSTRUCT_MACH(61)
#define __NR_clock_sleep_trap                 SYSCALL_CONSTRUCT_MACH(62)

#define __NR_mach_timebase_info               SYSCALL_CONSTRUCT_MACH(89)
#define __NR_mach_wait_until                  SYSCALL_CONSTRUCT_MACH(90)
#define __NR_mk_timer_create                  SYSCALL_CONSTRUCT_MACH(91)
#define __NR_mk_timer_destroy                 SYSCALL_CONSTRUCT_MACH(92)
#define __NR_mk_timer_arm                     SYSCALL_CONSTRUCT_MACH(93)
#define __NR_mk_timer_cancel                  SYSCALL_CONSTRUCT_MACH(94)

#define __NR_iokit_user_client_trap           SYSCALL_CONSTRUCT_MACH(100)


// bsd/sys/syscall.h
 
#define	__NR_syscall        SYSCALL_CONSTRUCT_UNIX(0)
#define	__NR_exit           SYSCALL_CONSTRUCT_UNIX(1)
#define	__NR_fork           SYSCALL_CONSTRUCT_UX64(2)
#define	__NR_read           SYSCALL_CONSTRUCT_UNIX(3)
#define	__NR_write          SYSCALL_CONSTRUCT_UNIX(4)
#define	__NR_open           SYSCALL_CONSTRUCT_UNIX(5)
#define	__NR_close          SYSCALL_CONSTRUCT_UNIX(6)
#define	__NR_wait4          SYSCALL_CONSTRUCT_UNIX(7)
			/* 8  old creat */
#define	__NR_link           SYSCALL_CONSTRUCT_UNIX(9)
#define	__NR_unlink         SYSCALL_CONSTRUCT_UNIX(10)
			/* 11  old execv */
#define	__NR_chdir          SYSCALL_CONSTRUCT_UNIX(12)
#define	__NR_fchdir         SYSCALL_CONSTRUCT_UNIX(13)
#define	__NR_mknod          SYSCALL_CONSTRUCT_UNIX(14)
#define	__NR_chmod          SYSCALL_CONSTRUCT_UNIX(15)
#define	__NR_chown          SYSCALL_CONSTRUCT_UNIX(16)
			/* 17  old break */
#define	__NR_getfsstat      SYSCALL_CONSTRUCT_UNIX(18)
			/* 19  old lseek */
#define	__NR_getpid         SYSCALL_CONSTRUCT_UNIX(20)
			/* 21  old mount */
			/* 22  old umount */
#define	__NR_setuid         SYSCALL_CONSTRUCT_UNIX(23)
#define	__NR_getuid         SYSCALL_CONSTRUCT_UNIX(24)
#define	__NR_geteuid        SYSCALL_CONSTRUCT_UNIX(25)
#define	__NR_ptrace         SYSCALL_CONSTRUCT_UNIX(26)
#define	__NR_recvmsg        SYSCALL_CONSTRUCT_UNIX(27)
#define	__NR_sendmsg        SYSCALL_CONSTRUCT_UNIX(28)
#define	__NR_recvfrom       SYSCALL_CONSTRUCT_UNIX(29)
#define	__NR_accept         SYSCALL_CONSTRUCT_UNIX(30)
#define	__NR_getpeername    SYSCALL_CONSTRUCT_UNIX(31)
#define	__NR_getsockname    SYSCALL_CONSTRUCT_UNIX(32)
#define	__NR_access         SYSCALL_CONSTRUCT_UNIX(33)
#define	__NR_chflags        SYSCALL_CONSTRUCT_UNIX(34)
#define	__NR_fchflags       SYSCALL_CONSTRUCT_UNIX(35)
#define	__NR_sync           SYSCALL_CONSTRUCT_UNIX(36)
#define	__NR_kill           SYSCALL_CONSTRUCT_UNIX(37)
			/* 38  old stat */
#define	__NR_getppid        SYSCALL_CONSTRUCT_UNIX(39)
			/* 40  old lstat */
#define	__NR_dup            SYSCALL_CONSTRUCT_UNIX(41)
#define	__NR_pipe           SYSCALL_CONSTRUCT_UX64(42)
#define	__NR_getegid        SYSCALL_CONSTRUCT_UNIX(43)
#define	__NR_profil         SYSCALL_CONSTRUCT_UNIX(44)
			/* 45  old ktrace */
#define	__NR_sigaction      SYSCALL_CONSTRUCT_UNIX(46)
#define	__NR_getgid         SYSCALL_CONSTRUCT_UNIX(47)
#define	__NR_sigprocmask    SYSCALL_CONSTRUCT_UNIX(48)
#define	__NR_getlogin       SYSCALL_CONSTRUCT_UNIX(49)
#define	__NR_setlogin       SYSCALL_CONSTRUCT_UNIX(50)
#define	__NR_acct           SYSCALL_CONSTRUCT_UNIX(51)
#define	__NR_sigpending     SYSCALL_CONSTRUCT_UNIX(52)
#define	__NR_sigaltstack    SYSCALL_CONSTRUCT_UNIX(53)
#define	__NR_ioctl          SYSCALL_CONSTRUCT_UNIX(54)
#define	__NR_reboot         SYSCALL_CONSTRUCT_UNIX(55)
#define	__NR_revoke         SYSCALL_CONSTRUCT_UNIX(56)
#define	__NR_symlink        SYSCALL_CONSTRUCT_UNIX(57)
#define	__NR_readlink       SYSCALL_CONSTRUCT_UNIX(58)
#define	__NR_execve         SYSCALL_CONSTRUCT_UNIX(59)
#define	__NR_umask          SYSCALL_CONSTRUCT_UNIX(60)
#define	__NR_chroot         SYSCALL_CONSTRUCT_UNIX(61)
			/* 62  old fstat */
			/* 63  used internally , reserved */
			/* 64  old getpagesize */
#define	__NR_msync          SYSCALL_CONSTRUCT_UNIX(65)
#define	__NR_vfork          SYSCALL_CONSTRUCT_UNIX(66)
			/* 67  old vread */
			/* 68  old vwrite */
			/* 69  old sbrk */
			/* 70  old sstk */
			/* 71  old mmap */
			/* 72  old vadvise */
#define	__NR_munmap         SYSCALL_CONSTRUCT_UNIX(73)
#define	__NR_mprotect       SYSCALL_CONSTRUCT_UNIX(74)
#define	__NR_madvise        SYSCALL_CONSTRUCT_UNIX(75)
			/* 76  old vhangup */
			/* 77  old vlimit */
#define	__NR_mincore        SYSCALL_CONSTRUCT_UNIX(78)
#define	__NR_getgroups      SYSCALL_CONSTRUCT_UNIX(79)
#define	__NR_setgroups      SYSCALL_CONSTRUCT_UNIX(80)
#define	__NR_getpgrp        SYSCALL_CONSTRUCT_UNIX(81)
#define	__NR_setpgid        SYSCALL_CONSTRUCT_UNIX(82)
#define	__NR_setitimer      SYSCALL_CONSTRUCT_UNIX(83)
			/* 84  old wait */
#define	__NR_swapon         SYSCALL_CONSTRUCT_UNIX(85)
#define	__NR_getitimer      SYSCALL_CONSTRUCT_UNIX(86)
			/* 87  old gethostname */
			/* 88  old sethostname */
#define	__NR_getdtablesize  SYSCALL_CONSTRUCT_UNIX(89)
#define	__NR_dup2           SYSCALL_CONSTRUCT_UNIX(90)
			/* 91  old getdopt */
#define	__NR_fcntl          SYSCALL_CONSTRUCT_UNIX(92)
#define	__NR_select         SYSCALL_CONSTRUCT_UNIX(93)
			/* 94  old setdopt */
#define	__NR_fsync          SYSCALL_CONSTRUCT_UNIX(95)
#define	__NR_setpriority    SYSCALL_CONSTRUCT_UNIX(96)
#define	__NR_socket         SYSCALL_CONSTRUCT_UNIX(97)
#define	__NR_connect        SYSCALL_CONSTRUCT_UNIX(98)
			/* 99  old accept */
#define	__NR_getpriority    SYSCALL_CONSTRUCT_UNIX(100)
			/* 101  old send */
			/* 102  old recv */
			/* 103  old sigreturn */
#define	__NR_bind           SYSCALL_CONSTRUCT_UNIX(104)
#define	__NR_setsockopt     SYSCALL_CONSTRUCT_UNIX(105)
#define	__NR_listen         SYSCALL_CONSTRUCT_UNIX(106)
			/* 107  old vtimes */
			/* 108  old sigvec */
			/* 109  old sigblock */
			/* 110  old sigsetmask */
#define	__NR_sigsuspend     SYSCALL_CONSTRUCT_UNIX(111)
			/* 112  old sigstack */
			/* 113  old recvmsg */
			/* 114  old sendmsg */
			/* 115  old vtrace */
#define	__NR_gettimeofday   SYSCALL_CONSTRUCT_UNIX(116)
#define	__NR_getrusage      SYSCALL_CONSTRUCT_UNIX(117)
#define	__NR_getsockopt     SYSCALL_CONSTRUCT_UNIX(118)
			/* 119  old resuba */
#define	__NR_readv          SYSCALL_CONSTRUCT_UNIX(120)
#define	__NR_writev         SYSCALL_CONSTRUCT_UNIX(121)
#define	__NR_settimeofday   SYSCALL_CONSTRUCT_UNIX(122)
#define	__NR_fchown         SYSCALL_CONSTRUCT_UNIX(123)
#define	__NR_fchmod         SYSCALL_CONSTRUCT_UNIX(124)
			/* 125  old recvfrom */
#define	__NR_setreuid       SYSCALL_CONSTRUCT_UNIX(126)
#define	__NR_setregid       SYSCALL_CONSTRUCT_UNIX(127)
#define	__NR_rename         SYSCALL_CONSTRUCT_UNIX(128)
			/* 129  old truncate */
			/* 130  old ftruncate */
#define	__NR_flock          SYSCALL_CONSTRUCT_UNIX(131)
#define	__NR_mkfifo         SYSCALL_CONSTRUCT_UNIX(132)
#define	__NR_sendto         SYSCALL_CONSTRUCT_UNIX(133)
#define	__NR_shutdown       SYSCALL_CONSTRUCT_UNIX(134)
#define	__NR_socketpair     SYSCALL_CONSTRUCT_UNIX(135)
#define	__NR_mkdir          SYSCALL_CONSTRUCT_UNIX(136)
#define	__NR_rmdir          SYSCALL_CONSTRUCT_UNIX(137)
#define	__NR_utimes         SYSCALL_CONSTRUCT_UNIX(138)
#define	__NR_futimes        SYSCALL_CONSTRUCT_UNIX(139)
#define	__NR_adjtime        SYSCALL_CONSTRUCT_UNIX(140)
			/* 141  old getpeername */
#define __NR_gethostuuid    SYSCALL_CONSTRUCT_UNIX(142)
			/* 142  old gethostid */
			/* 143  old sethostid */
			/* 144  old getrlimit */
			/* 145  old setrlimit */
			/* 146  old killpg */
#define	__NR_setsid         SYSCALL_CONSTRUCT_UNIX(147)
			/* 148  old setquota */
			/* 149  old qquota */
			/* 150  old getsockname */
#define	__NR_getpgid        SYSCALL_CONSTRUCT_UNIX(151)
#define	__NR_setprivexec    SYSCALL_CONSTRUCT_UNIX(152)
#define	__NR_pread          SYSCALL_CONSTRUCT_UNIX(153)
#define	__NR_pwrite         SYSCALL_CONSTRUCT_UNIX(154)
#define __NR_nfssvc         SYSCALL_CONSTRUCT_UNIX(155)
			/* 156  old getdirentries */
#define	__NR_statfs         SYSCALL_CONSTRUCT_UNIX(157)
#define	__NR_fstatfs        SYSCALL_CONSTRUCT_UNIX(158)
#define	__NR_unmount        SYSCALL_CONSTRUCT_UNIX(159)
			/* 160  old async_daemon */
#define __NR_getfh          SYSCALL_CONSTRUCT_UNIX(161)
			/* 162  old getdomainname */
			/* 163  old setdomainname */
			/* 164  */
#define	__NR_quotactl       SYSCALL_CONSTRUCT_UNIX(165)
			/* 166  old exportfs */
#define	__NR_mount          SYSCALL_CONSTRUCT_UNIX(167)
			/* 168  old ustat */
#define __NR_csops          SYSCALL_CONSTRUCT_UNIX(169)
			/* 170  old table */
			/* 171  old wait3 */
			/* 172  old rpause */
#define	__NR_waitid         SYSCALL_CONSTRUCT_UNIX(173)
			/* 174  old getdents */
			/* 175  old gc_control */
#define	__NR_add_profil     SYSCALL_CONSTRUCT_UNIX(176)
			/* 177  */
			/* 178  */
			/* 179  */
#define	__NR_kdebug_trace   SYSCALL_CONSTRUCT_UNIX(180)
#define	__NR_setgid         SYSCALL_CONSTRUCT_UNIX(181)
#define	__NR_setegid        SYSCALL_CONSTRUCT_UNIX(182)
#define	__NR_seteuid        SYSCALL_CONSTRUCT_UNIX(183)
#define __NR_sigreturn      SYSCALL_CONSTRUCT_UNIX(184)
#define __NR_chud           SYSCALL_CONSTRUCT_UNIX(185)
			/* 186  */
			/* 187  */
#define	__NR_stat           SYSCALL_CONSTRUCT_UNIX(188)
#define	__NR_fstat          SYSCALL_CONSTRUCT_UNIX(189)
#define	__NR_lstat          SYSCALL_CONSTRUCT_UNIX(190)
#define	__NR_pathconf       SYSCALL_CONSTRUCT_UNIX(191)
#define	__NR_fpathconf      SYSCALL_CONSTRUCT_UNIX(192)
			/* 193 */
#define	__NR_getrlimit      SYSCALL_CONSTRUCT_UNIX(194)
#define	__NR_setrlimit      SYSCALL_CONSTRUCT_UNIX(195)
#define	__NR_getdirentries  SYSCALL_CONSTRUCT_UNIX(196)
#define	__NR_mmap           SYSCALL_CONSTRUCT_UNIX(197)
			/* 198  __syscall */
#define	__NR_lseek          SYSCALL_CONSTRUCT_UX64(199)
#define	__NR_truncate       SYSCALL_CONSTRUCT_UNIX(200)
#define	__NR_ftruncate      SYSCALL_CONSTRUCT_UNIX(201)
#define	__NR___sysctl       SYSCALL_CONSTRUCT_UNIX(202)
#define	__NR_mlock          SYSCALL_CONSTRUCT_UNIX(203)
#define	__NR_munlock        SYSCALL_CONSTRUCT_UNIX(204)
#define	__NR_undelete       SYSCALL_CONSTRUCT_UNIX(205)
#define	__NR_ATsocket       SYSCALL_CONSTRUCT_UNIX(206)
#define	__NR_ATgetmsg       SYSCALL_CONSTRUCT_UNIX(207)
#define	__NR_ATputmsg       SYSCALL_CONSTRUCT_UNIX(208)
#define	__NR_ATPsndreq      SYSCALL_CONSTRUCT_UNIX(209)
#define	__NR_ATPsndrsp      SYSCALL_CONSTRUCT_UNIX(210)
#define	__NR_ATPgetreq      SYSCALL_CONSTRUCT_UNIX(211)
#define	__NR_ATPgetrsp      SYSCALL_CONSTRUCT_UNIX(212)
			/* 213  Reserved for AppleTalk */
#define	__NR_kqueue_from_portset_np SYSCALL_CONSTRUCT_UNIX(214)
#define	__NR_kqueue_portset_np SYSCALL_CONSTRUCT_UNIX(215)
#define	__NR_mkcomplex      SYSCALL_CONSTRUCT_UNIX(216)
#define	__NR_statv          SYSCALL_CONSTRUCT_UNIX(217)
#define	__NR_lstatv         SYSCALL_CONSTRUCT_UNIX(218)
#define	__NR_fstatv         SYSCALL_CONSTRUCT_UNIX(219)
#define	__NR_getattrlist    SYSCALL_CONSTRUCT_UNIX(220)
#define	__NR_setattrlist    SYSCALL_CONSTRUCT_UNIX(221)
#define	__NR_getdirentriesattr SYSCALL_CONSTRUCT_UNIX(222)
#define	__NR_exchangedata   SYSCALL_CONSTRUCT_UNIX(223)
			/* 224  checkuseraccess */
#define	__NR_searchfs       SYSCALL_CONSTRUCT_UNIX(225)
#define	__NR_delete         SYSCALL_CONSTRUCT_UNIX(226)
#define	__NR_copyfile       SYSCALL_CONSTRUCT_UNIX(227)
			/* 228  */
			/* 229  */
#define	__NR_poll           SYSCALL_CONSTRUCT_UNIX(230)
#define	__NR_watchevent     SYSCALL_CONSTRUCT_UNIX(231)
#define	__NR_waitevent      SYSCALL_CONSTRUCT_UNIX(232)
#define	__NR_modwatch       SYSCALL_CONSTRUCT_UNIX(233)
#define	__NR_getxattr       SYSCALL_CONSTRUCT_UNIX(234)
#define	__NR_fgetxattr      SYSCALL_CONSTRUCT_UNIX(235)
#define	__NR_setxattr       SYSCALL_CONSTRUCT_UNIX(236)
#define	__NR_fsetxattr      SYSCALL_CONSTRUCT_UNIX(237)
#define	__NR_removexattr    SYSCALL_CONSTRUCT_UNIX(238)
#define	__NR_fremovexattr   SYSCALL_CONSTRUCT_UNIX(239)
#define	__NR_listxattr      SYSCALL_CONSTRUCT_UNIX(240)
#define	__NR_flistxattr     SYSCALL_CONSTRUCT_UNIX(241)
#define	__NR_fsctl          SYSCALL_CONSTRUCT_UNIX(242)
#define	__NR_initgroups     SYSCALL_CONSTRUCT_UNIX(243)
#define __NR_posix_spawn    SYSCALL_CONSTRUCT_UNIX(244)
			/* 245  */
			/* 246  */
#define __NR_nfsclnt        SYSCALL_CONSTRUCT_UNIX(247)
#define __NR_fhopen         SYSCALL_CONSTRUCT_UNIX(248)
			/* 249  */
#define	__NR_minherit       SYSCALL_CONSTRUCT_UNIX(250)
#define	__NR_semsys         SYSCALL_CONSTRUCT_UNIX(251)
#define	__NR_msgsys         SYSCALL_CONSTRUCT_UNIX(252)
#define	__NR_shmsys         SYSCALL_CONSTRUCT_UNIX(253)
#define	__NR_semctl         SYSCALL_CONSTRUCT_UNIX(254)
#define	__NR_semget         SYSCALL_CONSTRUCT_UNIX(255)
#define	__NR_semop          SYSCALL_CONSTRUCT_UNIX(256)
			/* 257  */
#define	__NR_msgctl         SYSCALL_CONSTRUCT_UNIX(258)
#define	__NR_msgget         SYSCALL_CONSTRUCT_UNIX(259)
#define	__NR_msgsnd         SYSCALL_CONSTRUCT_UNIX(260)
#define	__NR_msgrcv         SYSCALL_CONSTRUCT_UNIX(261)
#define	__NR_shmat          SYSCALL_CONSTRUCT_UNIX(262)
#define	__NR_shmctl         SYSCALL_CONSTRUCT_UNIX(263)
#define	__NR_shmdt          SYSCALL_CONSTRUCT_UNIX(264)
#define	__NR_shmget         SYSCALL_CONSTRUCT_UNIX(265)
#define	__NR_shm_open       SYSCALL_CONSTRUCT_UNIX(266)
#define	__NR_shm_unlink     SYSCALL_CONSTRUCT_UNIX(267)
#define	__NR_sem_open       SYSCALL_CONSTRUCT_UNIX(268)
#define	__NR_sem_close      SYSCALL_CONSTRUCT_UNIX(269)
#define	__NR_sem_unlink     SYSCALL_CONSTRUCT_UNIX(270)
#define	__NR_sem_wait       SYSCALL_CONSTRUCT_UNIX(271)
#define	__NR_sem_trywait    SYSCALL_CONSTRUCT_UNIX(272)
#define	__NR_sem_post       SYSCALL_CONSTRUCT_UNIX(273)
#define	__NR_sem_getvalue   SYSCALL_CONSTRUCT_UNIX(274)
#define	__NR_sem_init       SYSCALL_CONSTRUCT_UNIX(275)
#define	__NR_sem_destroy    SYSCALL_CONSTRUCT_UNIX(276)
#define	__NR_open_extended  SYSCALL_CONSTRUCT_UNIX(277)
#define	__NR_umask_extended SYSCALL_CONSTRUCT_UNIX(278)
#define	__NR_stat_extended  SYSCALL_CONSTRUCT_UNIX(279)
#define	__NR_lstat_extended SYSCALL_CONSTRUCT_UNIX(280)
#define	__NR_fstat_extended SYSCALL_CONSTRUCT_UNIX(281)
#define	__NR_chmod_extended SYSCALL_CONSTRUCT_UNIX(282)
#define	__NR_fchmod_extended SYSCALL_CONSTRUCT_UNIX(283)
#define	__NR_access_extended SYSCALL_CONSTRUCT_UNIX(284)
#define	__NR_settid         SYSCALL_CONSTRUCT_UNIX(285)
#define	__NR_gettid         SYSCALL_CONSTRUCT_UNIX(286)
#define	__NR_setsgroups     SYSCALL_CONSTRUCT_UNIX(287)
#define	__NR_getsgroups     SYSCALL_CONSTRUCT_UNIX(288)
#define	__NR_setwgroups     SYSCALL_CONSTRUCT_UNIX(289)
#define	__NR_getwgroups     SYSCALL_CONSTRUCT_UNIX(290)
#define	__NR_mkfifo_extended SYSCALL_CONSTRUCT_UNIX(291)
#define	__NR_mkdir_extended SYSCALL_CONSTRUCT_UNIX(292)
#define	__NR_identitysvc    SYSCALL_CONSTRUCT_UNIX(293)
#define	__NR_shared_region_check_np SYSCALL_CONSTRUCT_UNIX(294)
#define	__NR_shared_region_map_np   SYSCALL_CONSTRUCT_UNIX(295)
			/* 296  old load_shared_file */
			/* 297  old reset_shared_file */
			/* 298  old new_system_shared_regions */
			/* 299  old shared_region_map_file_np */
			/* 300  old shared_region_make_private_np */
#define __NR___pthread_mutex_destroy SYSCALL_CONSTRUCT_UNIX(301)
#define __NR___pthread_mutex_init SYSCALL_CONSTRUCT_UNIX(302)
#define __NR___pthread_mutex_lock SYSCALL_CONSTRUCT_UNIX(303)
#define __NR___pthread_mutex_trylock SYSCALL_CONSTRUCT_UNIX(304)
#define __NR___pthread_mutex_unlock SYSCALL_CONSTRUCT_UNIX(305)
#define __NR___pthread_cond_init SYSCALL_CONSTRUCT_UNIX(306)
#define __NR___pthread_cond_destroy SYSCALL_CONSTRUCT_UNIX(307)
#define __NR___pthread_cond_broadcast SYSCALL_CONSTRUCT_UNIX(308)
#define __NR___pthread_cond_signal SYSCALL_CONSTRUCT_UNIX(309)
#define	__NR_getsid         SYSCALL_CONSTRUCT_UNIX(310)
#define	__NR_settid_with_pid SYSCALL_CONSTRUCT_UNIX(311)
#define __NR___pthread_cond_timedwait SYSCALL_CONSTRUCT_UNIX(312)
#define	__NR_aio_fsync      SYSCALL_CONSTRUCT_UNIX(313)
#define	__NR_aio_return     SYSCALL_CONSTRUCT_UNIX(314)
#define	__NR_aio_suspend    SYSCALL_CONSTRUCT_UNIX(315)
#define	__NR_aio_cancel     SYSCALL_CONSTRUCT_UNIX(316)
#define	__NR_aio_error      SYSCALL_CONSTRUCT_UNIX(317)
#define	__NR_aio_read       SYSCALL_CONSTRUCT_UNIX(318)
#define	__NR_aio_write      SYSCALL_CONSTRUCT_UNIX(319)
#define	__NR_lio_listio     SYSCALL_CONSTRUCT_UNIX(320)
#define __NR___pthread_cond_wait SYSCALL_CONSTRUCT_UNIX(321)
#define __NR_iopolicysys    SYSCALL_CONSTRUCT_UNIX(322)
			/* 323  */
#define	__NR_mlockall       SYSCALL_CONSTRUCT_UNIX(324)
#define	__NR_munlockall     SYSCALL_CONSTRUCT_UNIX(325)
			/* 326  */
#define	__NR_issetugid      SYSCALL_CONSTRUCT_UNIX(327)
#define	__NR___pthread_kill SYSCALL_CONSTRUCT_UNIX(328)
#define	__NR___pthread_sigmask SYSCALL_CONSTRUCT_UNIX(329)
#define	__NR___sigwait        SYSCALL_CONSTRUCT_UNIX(330)
#define	__NR_sigwait        SYSCALL_CONSTRUCT_UNIX(330) // GrP fixme hack
#define	__NR___disable_threadsignal SYSCALL_CONSTRUCT_UNIX(331)
#define	__NR___pthread_markcancel SYSCALL_CONSTRUCT_UNIX(332)
#define	__NR___pthread_canceled SYSCALL_CONSTRUCT_UNIX(333)
#define	__NR___semwait_signal SYSCALL_CONSTRUCT_UNIX(334)
			/* 335  old utrace */
#define __NR_proc_info      SYSCALL_CONSTRUCT_UNIX(336)
#define __NR_sendfile       SYSCALL_CONSTRUCT_UNIX(337)
#define __NR_stat64         SYSCALL_CONSTRUCT_UNIX(338)
#define __NR_fstat64        SYSCALL_CONSTRUCT_UNIX(339)
#define __NR_lstat64        SYSCALL_CONSTRUCT_UNIX(340)
#define __NR_stat64_extended SYSCALL_CONSTRUCT_UNIX(341)
#define __NR_lstat64_extended SYSCALL_CONSTRUCT_UNIX(342)
#define __NR_fstat64_extended SYSCALL_CONSTRUCT_UNIX(343)
#define __NR_getdirentries64 SYSCALL_CONSTRUCT_UNIX(344)
#define __NR_statfs64       SYSCALL_CONSTRUCT_UNIX(345)
#define __NR_fstatfs64      SYSCALL_CONSTRUCT_UNIX(346)
#define __NR_getfsstat64    SYSCALL_CONSTRUCT_UNIX(347)
#define __NR___pthread_chdir SYSCALL_CONSTRUCT_UNIX(348)
#define __NR___pthread_fchdir SYSCALL_CONSTRUCT_UNIX(349)

#define	__NR_audit          SYSCALL_CONSTRUCT_UNIX(350)
#define	__NR_auditon        SYSCALL_CONSTRUCT_UNIX(351)
			/* 352  */
#define	__NR_getauid        SYSCALL_CONSTRUCT_UNIX(353)
#define	__NR_setauid        SYSCALL_CONSTRUCT_UNIX(354)
#define	__NR_getaudit       SYSCALL_CONSTRUCT_UNIX(355)
#define	__NR_setaudit       SYSCALL_CONSTRUCT_UNIX(356)
#define	__NR_getaudit_addr  SYSCALL_CONSTRUCT_UNIX(357)
#define	__NR_setaudit_addr  SYSCALL_CONSTRUCT_UNIX(358)
#define	__NR_auditctl       SYSCALL_CONSTRUCT_UNIX(359)
#define	__NR_bsdthread_create SYSCALL_CONSTRUCT_UNIX(360)
#define	__NR_bsdthread_terminate SYSCALL_CONSTRUCT_UNIX(361)
#define	__NR_kqueue         SYSCALL_CONSTRUCT_UNIX(362)
#define	__NR_kevent         SYSCALL_CONSTRUCT_UNIX(363)
#define	__NR_lchown         SYSCALL_CONSTRUCT_UNIX(364)
#define __NR_stack_snapshot SYSCALL_CONSTRUCT_UNIX(365)
#define __NR_bsdthread_register SYSCALL_CONSTRUCT_UNIX(366)
#define __NR_workq_open     SYSCALL_CONSTRUCT_UNIX(367)
#define __NR_workq_ops      SYSCALL_CONSTRUCT_UNIX(368)
			/* 369  */
			/* 370  */
			/* 371  */
			/* 372  */
			/* 373  */
			/* 374  */
			/* 375  */
			/* 376  */
			/* 377  */
			/* 378  */
			/* 379  */
#define __NR___mac_execve   SYSCALL_CONSTRUCT_UNIX(380)
#define __NR___mac_syscall  SYSCALL_CONSTRUCT_UNIX(381)
#define __NR___mac_get_file SYSCALL_CONSTRUCT_UNIX(382)
#define __NR___mac_set_file SYSCALL_CONSTRUCT_UNIX(383)
#define __NR___mac_get_link SYSCALL_CONSTRUCT_UNIX(384)
#define __NR___mac_set_link SYSCALL_CONSTRUCT_UNIX(385)
#define __NR___mac_get_proc SYSCALL_CONSTRUCT_UNIX(386)
#define __NR___mac_set_proc SYSCALL_CONSTRUCT_UNIX(387)
#define __NR___mac_get_fd   SYSCALL_CONSTRUCT_UNIX(388)
#define __NR___mac_set_fd   SYSCALL_CONSTRUCT_UNIX(389)
#define __NR___mac_get_pid  SYSCALL_CONSTRUCT_UNIX(390)
#define __NR___mac_get_lcid SYSCALL_CONSTRUCT_UNIX(391)
#define __NR___mac_get_lctx SYSCALL_CONSTRUCT_UNIX(392)
#define __NR___mac_set_lctx SYSCALL_CONSTRUCT_UNIX(393)
#define __NR_setlcid        SYSCALL_CONSTRUCT_UNIX(394)
#define __NR_getlcid        SYSCALL_CONSTRUCT_UNIX(395)
#define __NR_read_nocancel  SYSCALL_CONSTRUCT_UNIX(396)
#define __NR_write_nocancel SYSCALL_CONSTRUCT_UNIX(397)
#define __NR_open_nocancel  SYSCALL_CONSTRUCT_UNIX(398)
#define __NR_close_nocancel SYSCALL_CONSTRUCT_UNIX(399)
#define __NR_wait4_nocancel SYSCALL_CONSTRUCT_UNIX(400)
#define __NR_recvmsg_nocancel SYSCALL_CONSTRUCT_UNIX(401)
#define __NR_sendmsg_nocancel SYSCALL_CONSTRUCT_UNIX(402)
#define __NR_recvfrom_nocancel SYSCALL_CONSTRUCT_UNIX(403)
#define __NR_accept_nocancel SYSCALL_CONSTRUCT_UNIX(404)
#define __NR_msync_nocancel SYSCALL_CONSTRUCT_UNIX(405)
#define __NR_fcntl_nocancel SYSCALL_CONSTRUCT_UNIX(406)
#define __NR_select_nocancel SYSCALL_CONSTRUCT_UNIX(407)
#define __NR_fsync_nocancel SYSCALL_CONSTRUCT_UNIX(408)
#define __NR_connect_nocancel SYSCALL_CONSTRUCT_UNIX(409)
#define __NR_sigsuspend_nocancel SYSCALL_CONSTRUCT_UNIX(410)
#define __NR_readv_nocancel SYSCALL_CONSTRUCT_UNIX(411)
#define __NR_writev_nocancel SYSCALL_CONSTRUCT_UNIX(412)
#define __NR_sendto_nocancel SYSCALL_CONSTRUCT_UNIX(413)
#define __NR_pread_nocancel SYSCALL_CONSTRUCT_UNIX(414)
#define __NR_pwrite_nocancel SYSCALL_CONSTRUCT_UNIX(415)
#define __NR_waitid_nocancel SYSCALL_CONSTRUCT_UNIX(416)
#define __NR_poll_nocancel  SYSCALL_CONSTRUCT_UNIX(417)
#define __NR_msgsnd_nocancel SYSCALL_CONSTRUCT_UNIX(418)
#define __NR_msgrcv_nocancel SYSCALL_CONSTRUCT_UNIX(419)
#define __NR_sem_wait_nocancel SYSCALL_CONSTRUCT_UNIX(420)
#define __NR_aio_suspend_nocancel SYSCALL_CONSTRUCT_UNIX(421)
#define __NR___sigwait_nocancel SYSCALL_CONSTRUCT_UNIX(422)
#define __NR___semwait_signal_nocancel SYSCALL_CONSTRUCT_UNIX(423)
#define __NR___mac_mount    SYSCALL_CONSTRUCT_UNIX(424)
#define __NR___mac_get_mount SYSCALL_CONSTRUCT_UNIX(425)
#define __NR___mac_getfsstat SYSCALL_CONSTRUCT_UNIX(426)
#define	__NR_MAXSYSCALL     SYSCALL_CONSTRUCT_UNIX(427)

#endif
