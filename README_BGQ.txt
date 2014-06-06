
Valgrind 3_8_BRANCH, port for BG/Q, 21 May 2014
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Contents: 
1. Limitations
2. How to build and run
3. BGQ-specific suppressions, and XML output hints
4. Hardwired command line arguments


1. Limitations
~~~~~~~~~~~~~~

This is work in progress.

The tarball can successfully run, with Memcheck, at least small MPI
apps (eg, as below, prestacom), with little or no noise, and with the
MPI wrapper library.  Also QMcBeaver.  There are some limitations:

* non-hanging: the MPI library has similar spin/hang problems 
  to the OpenMP library.  I think I have worked around this by
  disabling some optimisations in the JIT, but I am not sure.

* System call wrappers for the circa 40 CNK-specific system calls
  are missing.  Hence there may be Memcheck false positives as a
  result.

* QPX instruction set support is complete and is mostly bit-exact with
  the hardware.  See QPX_LIMITATIONS.txt for further details.

* At least one MPI application (QMcBeaver) works when compiled with
  xlc (mpixlcxx) at -O3.

* Signal handling is flaky at best.  Whether address space management
  is really correct is also unclear.  That might have consequences when
  running processes that use hundreds of megabytes of heap, or more.

* No support for transactional memory.  You need to run OpenMP
  applications with TM_MAX_NUM_ROLLBACK=0.  It may be safe to omit
  this for non-OpenMP applications.  If you mistakenly omit it, you
  are likely to get segfaulting and other strange behaviour when the
  application tries to do a transaction.

* Some minimal testing with a simple OpenMP program failed to show any
  sign of spin/hang problems.  This requires more testing, though.


2. How to build and run
~~~~~~~~~~~~~~~~~~~~~~~

# You'll need to adjust paths accordingly.

cd branch38bgq-2014May21

export AR=/bgsys/drivers/toolchain/V1R2M1/gnu-linux/powerpc64-bgq-linux/bin/ar
export LD=/bgsys/drivers/toolchain/V1R2M1/gnu-linux/powerpc64-bgq-linux/bin/ld
export CC=/bgsys/drivers/toolchain/V1R2M1/gnu-linux/powerpc64-bgq-linux/bin/gcc

./autogen.sh

./configure --prefix=/g/g92/seward3/BGQ2014/branch38bgq-2014May21/Inst \
            --host=ppc64-bgq-linux

# You need to see this at the end of the configure run.  If you don't
# see it, something is wrong.
#
#       Primary -DVGPV string: -DVGPV_ppc64_linux_bgq=1


###### Build/install ######

make --quiet -j4 
make install

# Set up to use.

# Baseline path
export BGQ_VALGRIND=/g/g92/seward3/BGQ2014/branch38bgq-2014May21

# For using --tool=none
export BGQ_NL="$BGQ_VALGRIND/none/none-ppc64-linux -Wl,-e,_start_valgrind"

# For using --tool=memcheck
export BGQ_MC="$BGQ_VALGRIND/memcheck/memcheck-ppc64-linux $BGQ_VALGRIND/memcheck/vgpreload_memcheck_ppc64_linux_so-mc_replace_strmem.o $BGQ_VALGRIND/coregrind/libreplacemalloc_toolpreload_ppc64_linux_a-vg_replace_malloc.o $BGQ_VALGRIND/mpi/libmpiwrap_ppc64_linux_so-libmpiwrap.o -Wl,-e,_start_valgrind"


###### Try an MPI program: ######

/bgsys/drivers/ppcfloor/comm/gcc/bin/mpicc -g -O -o 05prestacom-mc \
   ../../MPI/05prestacom/prestacom.c ../../MPI/05prestacom/util.c $BGQ_MC

srun -N4 -ppdebug \
   ./05prestacom-mc \
   --ignore-ranges=0x4000000000000-0x4063000000000,0x003fdc0000000-0x003fe00000000 \
   -- -o 2


3. BGQ-specific suppressions, and XML output hints
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is how I test with QMcBeaver.  Set BGQ_IR to the desired
ignore-ranges:

export BGQ_IR="--ignore-ranges=0x4000000000000-0x4063000000000,0x003fdc0000000-0x003fe00000000"

Then:

MPIWRAP_DEBUG=quiet \
   srun -n4 -ppdebug \
   ./objdir-xlc/QMcBeaver $BGQ_IR \
   --xml=yes --xml-file=qmcOut%r.xml "--xml-user-comment=<rank>%r</rank>" \
   --suppressions=/g/g92/seward3/BGQ2014/branch38bgq/cnk-baseline.supp \
   -- smallish.ckmf

Note:

(1) --xml-file= has been enhanced so that "%r" in it is replaced by
    the MPI Rank, as obtained by calling Kernel_GetRank.  Also, "%b"
    is allowed, and is replaced by the executable's basename.  These
    facilitates naming output files by rank and basename.

(2) --xml-user-comment= has been enhanced to also replace "%r" by
    the MPI Rank.  This facilitates adding rank indications to the
    output XML files, for the benefit of Memcheckview.


Suppressions: an initial suppression file "cnk-baseline.supp" is
included.  It contains suppressions for leaks observed when running a
simple MPI hello-world program.  Don't take it to be either definitive
or correct.  It is a starting point, though.


4. Hardwired command line arguments
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Applications linked against any of the Valgrind tool binaries, as
described above, will interpret all command line arguments before
the first "--" as directed to Valgrind itself.  Hence if there is
a native run

  srun -N 16 ./myapp --args --for --my --app

then when linked against (eg) the Memcheck tool, you can do

  srun -N 16 ./myapp --args --for --valgrind -- --args --for --my --app

That is to say, they are split at the first "--".  Your app of course
"sees" only the arguments directed to it.


You can optionally choose to hardwire arguments for Valgrind, in which
case all of the arguments specified on the command line are handed to
the application.  To do this, edit coregrind/m_commandline.c around
line 43.  What to do is explained in comments.
