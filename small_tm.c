#include <stdio.h>
#include <stdlib.h>
#include <omp.h>
#include <spi/include/kernel/spec.h>
#include <speculation.h>

int array_len = 100;
int num_arrays = 64;
int num_times = 9;

void update_array(double *array, double incoming_deposit)
{
    double deposit;
    long count;

    for (count=0; count < array_len; count++)
    {
	deposit = incoming_deposit * 0.01;
	incoming_deposit -= deposit;
	
#pragma omp atomic
	    array[count] += deposit;
    }
}

int main(int argc, char** argv, char** envp)
{
  int nenv;
  for (nenv = 0; envp[nenv]; nenv++)
    ;
  int aargc;
  for (aargc = 0; argv[aargc]; aargc++)
    ;
  //fprintf(stderr, "QQQQQQQQ APP: %d env vars, argc=%d, actualargc=%d\n", 
  //        nenv, argc, aargc);
    double *array;
    int iter, id;

    array = (double *)calloc (array_len * num_arrays, sizeof(double));
    
    for (iter = 0; iter < num_times; iter++)
    {
	
#pragma omp parallel for private (id) schedule (static)
	for (id=0; id < num_arrays; id++)
	{
	    /* Total conflicts, mostly overlaps */
	    update_array (&array[id], 1.0);
	}
    }

    printf ("Done! array[%i] is %g\n", num_arrays, array[num_arrays]);

    free(array);
    
    return (0);
}
