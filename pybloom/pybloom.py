# -*- encoding: utf-8 -*-
"""This module implements a bloom filter probabilistic data structure,
backed by mmap.

This is useful for large readonly bloom filters needed by multiple processes.

While multiple processes writing to the same bloom filter is possible, the
resulting filter may possibly have *false negatives* if there are collisions
at byte offsets, although improbable.

  >>> from pybloom import BloomFilter
  >>> f = BloomFilter(BloomFilter.TEMPORARY, capacity=10000, error_rate=0.001)
  >>> for i in xrange(0, f.capacity):
  ...   _ = f.add(i)
  ...
  >>> 0 in f
  True
  >>> f.capacity in f
  False
  >>> len(f) <= f.capacity
  True
  >>> (1.0 - (len(f) / float(f.capacity))) <= f.error_rate + 2e-18
  True

"""


from collections import deque, namedtuple
import hashlib
import math
import mmap
import os
import tempfile
from struct import unpack, pack, calcsize
import zlib


__version__ = '2.0-mmap'
__author__  = "Jay Baird <jay.baird@me.com>, Bob Ippolito <bob@redivi.com>,\
         Marius Eriksen <marius@monkey.org>,\
         Alex Brasetvik <alex@brasetvik.com>"


def make_hashfuncs(num_slices, num_bits):
  if num_bits >= (1 << 31):
    fmt_code = 'Q'
  elif num_bits >= (1 << 15):
    fmt_code = 'I'
  else:
    fmt_code = 'H'
  chunk_size = calcsize(fmt_code)
  total_hash_bits = 8 * num_slices * chunk_size
  if total_hash_bits > 384:
    hashfn = hashlib.sha512
  elif total_hash_bits > 256:
    hashfn = hashlib.sha384
  elif total_hash_bits > 160:
    hashfn = hashlib.sha256
  elif total_hash_bits > 128:
    hashfn = hashlib.sha1
  else:
    hashfn = hashlib.md5
  fmt = fmt_code * (hashfn().digest_size // chunk_size)
  num_salts, extra = divmod(num_slices, len(fmt))
  if extra:
    num_salts += 1
  salts = tuple(
      hashfn(hashfn(pack('I', i)).digest())
      for i in xrange(num_salts))

  def _make_hashfuncs(key):
    if isinstance(key, unicode):
      key = key.encode('utf-8')
    else:
      key = str(key)

    i = 0
    for salt in salts:
      h = salt.copy()
      h.update(key)
      for uint in unpack(fmt, h.digest()):
        yield uint % num_bits
        i += 1
        if i >= num_slices:
          return

  return _make_hashfuncs


class BloomFilter(object):
  _HEADER_FMT = '<dQQQQ'
  _HEADER_FMT_LEN = calcsize(_HEADER_FMT)
  _HEADER = namedtuple(
      'BloomFilterHeader',
      'error_rate '
      'num_slices '
      'bits_per_slice '
      'capacity '
      'count')

  # Count will be rewritten at flush(). All other header values remain constant.
  _COUNT_FMT = '<Q'
  _COUNT_FMT_LEN = calcsize(_COUNT_FMT)

  # Flag to specify an in-memory only temporary file.
  # This is useful for testing but has no benefits over a non-mmap implementation.
  TEMPORARY = object()

  def __init__(self,
               file_path,
               capacity=None,
               readonly=False,
               error_rate=0.001):
    """Implements a space-efficient probabilistic data structure

    file_path
      path to mmap, or BloomFilter.TEMPORARY. If TEMPORARY, a
      temporary file object will be created that will not persist beyond the
      life of this object. If path does not exist, it will be created.
    readonly
      if True, optimize for readonly acccess.
    capacity
      this BloomFilter must be able to store at least *capacity* elements
      while maintaining no more than *error_rate* chance of false
      positives
    error_rate
      the error_rate of the filter returning false positives. This
      determines the filters capacity. Inserting more than capacity
      elements greatly increases the chance of false positives.

    >>> b = BloomFilter(None, capacity=100000, error_rate=0.001)
    >>> b.add("test")
    False
    >>> "test" in b
    True

    """
    if file_path is None:
      file_path = self.TEMPORARY

    if file_path is self.TEMPORARY:
      exists_already = False
      self.file_path = None
    else:
      exists_already = os.path.exists(file_path)
      self.file_path = file_path

    self.readonly = readonly

    if readonly and not exists_already:
      raise ValueError("can't be readonly without existing data")

    elif not exists_already:
      self._initialize(**self._gen_header(error_rate, capacity)._asdict())

    self._open_file(file_path, exists_already, self.readonly)

    if exists_already:
      self._initialize(**self._read_header()._asdict())

    # Post-initialization sanity checks.
    if capacity is not None and self.capacity != capacity:
      raise ValueError(
          "unexpected capacity %s vs %s"
          % (self.capacity, capacity))

    elif error_rate is not None and self.error_rate != error_rate:
      raise ValueError(
          "unexpected error_rate %s vs %s"
          % (self.error_rate, error_rate))

    elif self.mm.size() != self.num_bytes + self._HEADER_FMT_LEN:
      raise ValueError(
          "unexpected mmap size %s vs %s"
          % (self.mm.size(), self.num_bytes))


  def _init_fileno(self):
    """Initialize an empty file.
    """
    startpos = self.fileno.tell()
    self.fileno.write(pack(self._HEADER_FMT, *self._get_header()))

    chunk_size = 1024
    chunks, extra = divmod(self.num_bytes, chunk_size)
    for _ in xrange(chunks):
      self.fileno.write(chr(0) * chunk_size)
    self.fileno.write(chr(0) * extra)

    self.fileno.seek(startpos)


  @classmethod
  def _gen_header(cls, error_rate, capacity):
    """Generate a new header based on the input parameters.
    """

    if error_rate is None or not (0 < error_rate < 1):
      raise ValueError("Error_Rate must be between 0 and 1.")
    if capacity is None or capacity <= 0:
      raise ValueError("Capacity must be > 0")

    # given M = num_bits, k = num_slices, P = error_rate, n = capacity
    #     k = log2(1/P)
    # solving for m = bits_per_slice
    # n ~= M * ((ln(2) ** 2) / abs(ln(P)))
    # n ~= (k * m) * ((ln(2) ** 2) / abs(ln(P)))
    # m ~= n * abs(ln(P)) / (k * (ln(2) ** 2))
    num_slices = int(math.ceil(math.log(1.0 / error_rate, 2)))
    bits_per_slice = int(math.ceil(
      (capacity * abs(math.log(error_rate))) /
      (num_slices * (math.log(2) ** 2))))

    header = cls._HEADER(
        error_rate=error_rate,
        num_slices=num_slices,
        bits_per_slice=bits_per_slice,
        capacity=capacity,
        count=0)

    return header


  def _initialize(self, error_rate, num_slices, bits_per_slice, capacity, count):
    """Initialize instance variables.
    """
    self.error_rate = error_rate
    self.num_slices = num_slices
    self.bits_per_slice = bits_per_slice
    self.capacity = capacity
    self.num_bits = num_slices * bits_per_slice
    self.num_bytes = int(math.ceil(self.num_bits / 8.))
    self.count = count
    self._make_hashes = make_hashfuncs(self.num_slices, self.bits_per_slice)


  def _get_header(self):
    """Generate a header based on the current state of the object.
    """
    return self._HEADER(
        error_rate=self.error_rate,
        num_slices=self.num_slices,
        bits_per_slice=self.bits_per_slice,
        capacity=self.capacity,
        count=self.count)


  def _read_header(self):
    """Read header out of the currently open mmap.
    """
    return self._HEADER(
        *unpack(self._HEADER_FMT, self.mm[0:self._HEADER_FMT_LEN]))


  def _open_file(self, file_path, exists_already, readonly):
    """Open file handle and corresponding mmap.
    """
    if readonly:
      fmode = 'rb'
      mmprot = mmap.PROT_READ
      mmaccess = mmap.ACCESS_READ
    else:
      if exists_already:
        fmode = 'r+b'
      else:
        fmode = 'w+b'
      mmprot = mmap.PROT_READ | mmap.PROT_WRITE
      mmaccess = mmap.ACCESS_WRITE

    if file_path is self.TEMPORARY:
      self.fileno = os.tmpfile()
      self._init_fileno()
    else:
      self.fileno = open(file_path, fmode)
      if not exists_already:
        self._init_fileno()

    self.mm = mmap.mmap(
        self.fileno.fileno(), 0, prot=mmprot, access=mmaccess)


  def __contains__(self, value):
    """Tests a value's membership in this bloom filter.

    value will be passed through str() before hashing.

    >>> b = BloomFilter(None, capacity=100)
    >>> b.add("hello")
    False
    >>> "hello" in b
    True

    """
    if self.readonly:
      raise TypeError
    mm = self.mm
    hashes = self._make_hashes(value)
    for byte_addr, bit_addr in self._get_offset(hashes)
      if not ord(mm[byte_addr]) & bit_addr:
        return False
    return True


  def __len__(self):
    """Return the number of keys stored by this bloom filter."""
    return self.count


  def toolarge(self):
    """Return True if this filter is over capacity.
    """
    return self.count > self.capacity


  def add(self, value, check_existing=True, check_capacity=True):
    """Adds a value to this bloom filter. If the value already exists in this
    filter it will return True. Otherwise False.

    value will be passed through str() before hashing.

    check_existing
      safer if accessed in write mode from multiple processes, otherwise
      faster.
    check_capacity
      if False, don't raise an error if the bloom filter is over capacity.

    >>> b = BloomFilter(None, capacity=100)
    >>> b.add("hello")
    False
    >>> b.add("hello")
    True

    """

    if check_capacity and self.toolarge():
      raise IndexError("BloomFilter is at capacity")

    hashes = self._make_hashes(value)
    bits_per_slice = self.bits_per_slice
    offset = 0
    mm = self.mm
    seen_all_bits = True

    # If this mmap is open by multiple processes, you could get collisions
    # if hashes set the same byte.

    for byte_addr, bit_addr in self._get_offset(hashes):
      if check_existing and seen_all_bits:
        # increased latency between read and write, increasing odds of collision
        # but odds of write decreased.
        val = ord(mm[byte_addr])
        if not val & bit_addr:
          seen_all_bits = False
          mm[byte_addr] = chr(val | bit_addr)
      else:
        # less latency between read and write, but always writes.
        mm[byte_addr] = chr(ord(mm[byte_addr]) | bit_addr)
    self.count += 1

    if check_existing:
      return seen_all_bits
    else:
      return None


  def _get_offset(self, hashes):
    """Translate bit offsets into byte offsets.

    Since we're using mmap which only has byte resolution and not bits.
    """
    bits_per_slice = self.bits_per_slice
    offset = 0
    byte_offset = self._HEADER_FMT_LEN

    for k in hashes:
      byte_addr, bit_addr = divmod(offset + k, 8)
      yield byte_addr + byte_offset, 1 << bit_addr
      offset += bits_per_slice


  def flush(self):
    """Flush data to file.
    """
    if not self.readonly:
      i, j = self._HEADER_FMT_LEN - self._COUNT_FMT_LEN, self._HEADER_FMT_LEN
      self.mm[i:j] = pack(self._COUNT_FMT, self.count)
      self.mm.flush()


  def close(self):
    """Close handles. Assumes flush() has been called.
    """
    self.mm.close()
    self.fileno.close()


  def __enter__(self):
    """Open context, for use with 'with'.
    """
    return self


  def __exit__(self, typ, val, tb):
    """Close context, for use with 'with'.
    """
    self.flush()
    self.close()


  def _bits_set(self):
    return sum(
        bin(ord(c)).count('1')
        for c in self.mm)

  def _bits_unset(self):
    return self.num_bits - self._bits_set()


if __name__ == "__main__":
  import doctest
  doctest.testmod()
