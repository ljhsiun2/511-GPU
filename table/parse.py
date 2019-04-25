import numpy

cache_array = []
cycle_array = []

with open('trial2.txt', 'r') as file:
	while True:
		line1 = file.readline().strip()
		line2 = file.readline().strip()
		if not line2: break

		cache_cnt = line1.split(' ')[4]
		cycle_time = line2.split(' ')[4]

		cache_array.append(int(cache_cnt))
		cycle_array.append(int(cycle_time))

print numpy.corrcoef(cache_array, cycle_array)[0, 1]