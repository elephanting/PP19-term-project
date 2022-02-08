#!/bin/bash
/home/PP-f19/MPI/bin/mpicc md5_mpi.c -o md5_mpi
# time /home/PP-f19/MPI/bin/mpiexec -npernode 1 --hostfile hostfile md5_mpi 0

for ((n=2;n<=3;n++)); do 
    echo -e "===== npernode: $n ======="
    for ((i=0;i<=9;i++)); do 
        /home/PP-f19/MPI/bin/mpiexec -npernode $n --hostfile hostfile md5_mpi $i
    done
done