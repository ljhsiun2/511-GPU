import numpy as np
import sys
import matplotlib.pyplot as plt
from matplotlib.ticker import FormatStrFormatter

cache_array = []
cycle_array = []

with open(sys.argv[1], 'r') as file:
	while True:
		line1 = file.readline().strip()
		line2 = file.readline().strip()
		if not line2: break

		cache_cnt = line1.split(' ')[4]
		cycle_time = line2.split(' ')[4]

		cache_array.append(int(cache_cnt))
		cycle_array.append(int(cycle_time))

print set(cache_array)
slope = np.corrcoef(cache_array, cycle_array)[0, 1]
print slope

plt.plot(cache_array, cycle_array, 'co')
plt.ylabel('cycle times')
plt.xlabel('number unique line accesses')
plt.show()

def abline(slope, intercept):
    """Plot a line from slope and intercept"""
    axes = plt.gca()
    x_vals = np.array(axes.get_xlim())
    y_vals = intercept + slope * x_vals
    plt.plot(x_vals, y_vals, '--')

abline(slope, 0)

plt.ylabel('correlation')
plt.show()