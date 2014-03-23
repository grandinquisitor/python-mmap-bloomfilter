pybloom-mmap is a module that includes a Bloom Filter data structure using mmap.

Bloom filters are great if you understand what amount of bits you need to set
aside early to store your entire set.

The mmap implemenation allows very large bloom filters to be shared by
multiple processes without using additional memory.

A filter is "full" when at capacity: M * ((ln 2 ^ 2) / abs(ln p)), where M
is the number of bits and p is the false positive probability. When capacity
is reached a new filter is then created exponentially larger than the last
with a tighter probability of false positives and a larger number of hash
functions.

>>> from pybloom import BloomFilter
>>> f = BloomFilter(None, capacity=1000, error_rate=0.001)
>>> [f.add(x) for x in range(10)]
[False, False, False, False, False, False, False, False, False, False]
>>> all([(x in f) for x in range(10)])
True
>>> 10 in f
False
>>> 5 in f
True
>>> f = BloomFilter(None, capacity=1000, error_rate=0.001)
>>> for i in xrange(0, f.capacity):
...     _ = f.add(i)
>>> (1.0 - (len(f) / float(f.capacity))) <= f.error_rate + 2e-18
True

