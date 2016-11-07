#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import codecs
from setuptools import setup


def read(fname):
    file_path = os.path.join(os.path.dirname(__file__), fname)
    return codecs.open(file_path, encoding='utf-8').read()


setup(
    name='mrglog',
    version='0.1.1',
    author='Luboš Tříletý',
    author_email='ltrilety@redhat.com',
    license='Apache 2.0',
    url='https://github.com/ltrilety/mrglog',
    description='MRG log module',
    long_description=read('README.rst'),
    py_modules=['mrglog'],
    classifiers=[
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Testing',
        'Topic :: System :: Logging',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
    ],
    scripts=['mrglog_demo.py'],
    )
