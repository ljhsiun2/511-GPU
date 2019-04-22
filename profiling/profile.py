import sys

arr = []
init_sum = 0

with open('out.txt', 'r') as file:
    for line in file:
        number = int(line.strip())
        init_sum += number
        arr.append(number)

print "sum is {} for stride {}".format(float(init_sum/len(arr)), sys.argv[1])
