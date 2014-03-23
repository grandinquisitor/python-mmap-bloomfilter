#!/usr/bin/env python
from ez_setup import use_setuptools
use_setuptools()

import os

from setuptools import setup, find_packages, Extension

VERSION = '2.0.0'
DESCRIPTION = "pybloom-mmap"
LONG_DESCRIPTION = """
pybloom-mmap is a Python implementation of the bloom filter probabilistic data
structure using mmap."""

CLASSIFIERS = filter(None, map(str.strip,
"""
Intended Audience :: Developers
License :: OSI Approved :: MIT License
Programming Language :: Python
Operating System :: OS Independent
Topic :: Utilities
Topic :: Database :: Database Engines/Servers
Topic :: Software Development :: Libraries :: Python Modules
""".splitlines()))

setup(
    name="pybloom-mmap",
    version=VERSION,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    classifiers=CLASSIFIERS,
    keywords=('data structures', 'bloom filter', 'bloom', 'filter',
              'probabilistic', 'set', 'mmap'),
    author="AUTHOR",
    author_email="AUTHOR_EMAIL",
    url="http://yahoo.com",
    license="MIT License",
    packages=find_packages(exclude=['ez_setup']),
    platforms=['any'],
    test_suite="pybloom.tests",
    zip_safe=True
)
