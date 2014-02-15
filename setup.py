#!/usr/bin/env python3.3

''' Handles packaging and setup '''

from distutils.core import setup
from setuptools import find_packages

setup(

	# Basic package information.
    name = 'syndie',
    version = '0.0.1',
    packages = ['syndie'],

    # Packaging options.
    zip_safe = False,
    include_package_data = True,

    # Package dependencies to be added later.
    install_requires = [''],
    tests_require = [''],

    # Metadata for PyPI.
    author = 'Jeff',
    author_email = 'ampernand@gmail.com',
    license = '',
    url = '',
    keywords = '',
    description = 'Python implementation of the high latency network agnostic' \
    	' distributed forum syndie.',
    package_dir= {'syndie':'src'}

    )
