import doctest
import os
import random
import tempfile
import unittest
from unittest import TestSuite

from pybloom import BloomFilter

def additional_tests():
    proj_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    readme_fn = os.path.join(proj_dir, 'README.txt')
    suite = TestSuite([doctest.DocTestSuite('pybloom')])
    if os.path.exists(readme_fn):
        suite.addTest(doctest.DocFileSuite(readme_fn, module_relative=False))
    return suite

if __name__ == '__main__':
  runner = unittest.TextTestRunner()
  test_suite = additional_tests()
  runner.run(test_suite)
