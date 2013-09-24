#!/usr/bin/env python3.3
from distutils.core import setup

setup(
    name='syndie',
    version='0.0.1',
    description='Python implementation of the high latency network agnostic distributed forum syndie',
    author='Jeff',
    author_email='ampernand@gmail.com',
    packages=['syndie'],
    package_dir={'syndie':'src'}
    )
