#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages


with open('README.md') as readme_file:
    readme = readme_file.read()
                
requirements = ['Click>=6.0', ]

setup(
    author="Alastair Irvine",
    description="Prompt for a password and prints the hash",
    install_requires=requirements,
    long_description=readme, ## + '\n\n' + history,
    entry_points={
        'console_scripts': [
            'hashpw=hashpw:main',
        ],
    },
    install_requires=requirements,
    keywords="password hash cli",
    name="hashpw",
    packages=find_packages(".", exclude=['tests']),
    url='https://github.com/unixnut/hashpw',
    version="2.1.0",
    zip_safe=False,
)



