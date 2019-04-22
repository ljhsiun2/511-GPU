#include <stdio.h>
#include <stdint.h>
#include <assert.h>

// CUDA runtime
#include <cuda_runtime.h>

// helper functions and utilities to work with CUDA
// #include <helper_functions.h>
// #include <helper_cuda.h>

// #define STRIDE 4 // stide to access new line



__global__ void measure_hit(const int* mem, const int stride, int* results){
    // int index = indices[threadIdx.x];
    int time = clock();
    results[threadIdx.x] = mem[threadIdx.x * stride];
    int time2 = clock() - time;
    printf("time for %d is %d\n", threadIdx.x, time2);
};

// __global__ void find_indices(const int numLines, int* indices){

// 	int curCacheIdx = 0;
// 	// printf("num lines is %d\n", numLines);
// 	for(int i = 0; i < 32; i++)
// 	{
// 		indices[i] = curCacheIdx * STRIDE;
// 		printf("index[%d] is %d\n", i, indices[i]);
// 		if(curCacheIdx < numLines -1)
// 			curCacheIdx += 1;
// 	}

// }



int main(int argc, char** argv){

	// int numCacheLine = atoi(argv[1]);

	int* indices;
	int* mem;
	int* results;

	cudaMalloc((void**) &indices, sizeof(int)*32);
	cudaMalloc((void**) &mem, 49152*32);
	cudaMalloc((void**) &results, sizeof(int)*32);

	dim3 threads(32, 1, 1);
	dim3 grid(1, 1, 1);
	// printf("numCacheLine is %d\n", numCacheLine);
	// find_indices <<< grid, threads >>> (numCacheLine, indices);
	

	
	measure_hit <<<grid, threads>>> (mem, atoi(argv[1]), results);


	cudaFree(indices);
	cudaFree(mem);
	cudaFree(results);
	return 0;
}