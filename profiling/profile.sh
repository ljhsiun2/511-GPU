#!/bin/bash
# runs 100 trials of binary and returns avg cycle latency in measure_hit
# with memory accesses in a warp with #define STRIDE

nvcc attack.cu
rm out.txt
for j in 1 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192
do
	rm out.txt
	for i in {1..100}
	do
		./a.out $j | awk '{print $5}' >> out.txt
		#echo $i      
		#python profile.py 
	done
	python profile.py $j
	sleep 1
done
