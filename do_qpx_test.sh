#!/bin/sh

rm -f out-R out-V out-V-mc
make --quiet -j4
mpicc -g -Wall -o test_qpx-nl test_qpx.c $BGQ_NL
mpicc -g -Wall -o test_qpx-mc test_qpx.c $BGQ_MC
mpicc -g -Wall -o test_qpx-nat test_qpx.c
ls -l test_qpx-nat test_qpx-nl test_qpx-mc

echo "Running native"
TM_MAX_NUM_ROLLBACK=0 TMPDIR=/g/g92/seward3/BGQ2014/TmpDir \
   srun -n1 -ppdebug ./test_qpx-nat > out-R

echo "Running mc"
TM_MAX_NUM_ROLLBACK=0 TMPDIR=/g/g92/seward3/BGQ2014/TmpDir \
   srun -n1 -ppdebug ./test_qpx-mc \
   --ignore-ranges=0x4000000000000-0x4063000000000,0x003fdc0000000-0x003fe00000000 \
   > out-V-mc

ls -l out-R out-V-mc
md5sum out-R out-V-mc

diff out-R out-V-mc
